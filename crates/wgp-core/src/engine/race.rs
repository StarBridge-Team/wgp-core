//! 竞速执行器（00 D4）：UDP 三波 ∥ TCP 多端口并行，先通先用。
//! 预算闸门共享（Arc<tokio::Mutex<BudgetScheduler>>）：两路径原子扣减，H6 全局不破。
//!
//! UDP 侧：发一包前非阻塞查收一次（150ms 时序压缩窗内回包不延迟到波后，
//! 03 §3.5.6/§3.3.5 的边发边收简化形态）。

use crate::transport::{TcpProbeCarrier, UdpProbeCarrier};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use wgp_proto::consts::WAVE_TIMEOUT_MS;
use wgp_punch::{plan_waves, BudgetScheduler, PortStepModel, ProbeCarrier};

/// 竞速结果
pub enum RaceOutcome {
    Udp {
        peer_addr: SocketAddr,
        packets_sent: u32,
    },
    Tcp {
        stream: TcpStream,
        packets_sent: u32,
    },
    Failed {
        packets_sent: u32,
    },
}

/// UDP 三波（边发边收）：返回 (命中地址, 发包数)，未命中地址为 None
async fn run_udp_waves(
    carrier: &UdpProbeCarrier,
    model: Option<&PortStepModel>,
    peer_ip: IpAddr,
    seed: u64,
    budget: &Mutex<BudgetScheduler>,
) -> (Option<SocketAddr>, u32) {
    let window = Duration::from_millis(WAVE_TIMEOUT_MS);
    let mut packets = 0u32;
    let self_addr = carrier.local_addr().ok();

    let is_hit = |src: &SocketAddr| src.ip() == peer_ip && Some(*src) != self_addr;

    let plan = {
        let guard = budget.lock().await;
        plan_waves(model, seed, guard.remaining().0)
    };
    let waves = [plan.wave1, plan.wave2, plan.wave3];

    for wave in waves.iter() {
        if wave.is_empty() {
            continue;
        }
        let mut sent_this_wave = 0u32;
        for &port in wave.iter() {
            // ① 发一包前非阻塞查收（150ms 窗口内对端回包即时命中）
            if let Ok(Some((_p, src))) = timeout(Duration::ZERO, carrier.recv_verified()).await {
                if is_hit(&src) {
                    return (Some(src), packets);
                }
            }
            // ② 发射（预算闸门）
            if budget.lock().await.try_acquire(1).is_err() {
                break;
            }
            let probe = carrier.craft();
            let dst = SocketAddr::new(peer_ip, port);
            if carrier.send_probe(dst, &probe).await.is_err() {
                continue;
            }
            packets += 1;
            sent_this_wave += 1;
        }
        if sent_this_wave == 0 {
            break;
        }
        // ③ 波尾收紧窗口：真等一个波周期吸收迟到回包
        let deadline = timeout(window, async {
            loop {
                match carrier.recv_verified().await {
                    Some((_p, src)) if is_hit(&src) => return Some(src),
                    _ => continue,
                }
            }
        });
        if let Ok(Some(src)) = deadline.await {
            return (Some(src), packets);
        }
    }
    (None, packets)
}

/// TCP 多端口并行：每波所有端口同时尝试（预算门控），首个成功即返回。
/// 返回 (流, 发包数)。
async fn run_tcp_waves(
    carrier: &TcpProbeCarrier,
    model: Option<&PortStepModel>,
    peer_ip: IpAddr,
    seed: u64,
    budget: &Mutex<BudgetScheduler>,
) -> (Option<TcpStream>, u32) {
    let window = Duration::from_millis(WAVE_TIMEOUT_MS);
    let mut packets = 0u32;

    let plan = {
        let guard = budget.lock().await;
        plan_waves(model, seed, guard.remaining().0)
    };
    let waves = [plan.wave1, plan.wave2, plan.wave3];

    for wave in waves.iter() {
        if wave.is_empty() {
            continue;
        }
        let (hit_tx, mut hit_rx) = mpsc::unbounded_channel();
        let mut handles = Vec::new();
        let mut sent_this_wave = 0u32;
        for &port in wave.iter() {
            if budget.lock().await.try_acquire(1).is_err() {
                break;
            }
            packets += 1;
            sent_this_wave += 1;
            let carrier = carrier.clone();
            let hit_tx = hit_tx.clone();
            handles.push(tokio::spawn(async move {
                let peer = SocketAddr::new(peer_ip, port);
                if let Some(stream) = carrier.punch_port(peer).await {
                    let _ = hit_tx.send(stream);
                }
            }));
        }
        if sent_this_wave == 0 {
            break;
        }
        // 等本波首个成功；超时进入下一波
        if let Ok(Some(stream)) = timeout(window, hit_rx.recv()).await {
            for h in handles {
                h.abort();
            }
            return (Some(stream), packets);
        }
        for h in handles {
            h.abort();
        }
    }
    (None, packets)
}

/// 竞速入口：UDP 与 TCP 同时跑，先命中者胜；一方先失败不影响另一路。
/// udp_on=false（T1 命中）时跳过 UDP 路径，纯 TCP。
pub async fn race_punch(
    udp: &UdpProbeCarrier,
    tcp: Option<&TcpProbeCarrier>,
    model: Option<&PortStepModel>,
    peer_ip: IpAddr,
    seed: u64,
    budget: Arc<Mutex<BudgetScheduler>>,
    udp_on: bool,
) -> RaceOutcome {
    let udp_fut = async {
        if udp_on {
            run_udp_waves(udp, model, peer_ip, seed, &budget).await
        } else {
            (None, 0u32)
        }
    };
    tokio::pin!(udp_fut);
    // 统一类型（None → 立即返回无命中，由 done 标志消化）
    let tcp_fut = async {
        match tcp {
            Some(t) => run_tcp_waves(t, model, peer_ip, seed, &budget).await,
            None => (None, 0u32),
        }
    };
    tokio::pin!(tcp_fut);

    let mut udp_done = !udp_on;
    let mut tcp_done = false;
    let mut packets = 0u32;

    loop {
        if udp_done && tcp_done {
            return RaceOutcome::Failed {
                packets_sent: packets,
            };
        }
        tokio::select! {
            r = &mut udp_fut, if !udp_done => {
                udp_done = true;
                let (hit, n) = r;
                packets += n;
                if let Some(addr) = hit {
                    return RaceOutcome::Udp { peer_addr: addr, packets_sent: packets };
                }
            }
            r = &mut tcp_fut, if !tcp_done => {
                tcp_done = true;
                let (hit, n) = r;
                packets += n;
                if let Some(stream) = hit {
                    return RaceOutcome::Tcp { stream, packets_sent: packets };
                }
            }
        }
    }
}