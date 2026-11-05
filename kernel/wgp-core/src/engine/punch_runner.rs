//! 竞速执行器：三波计划 → 预算闸门（唯一发包点）→ 载体发包 → 监听验签 → 命中判定。
//! 这是"打洞成功"的最小闭环（15 全链路 Phase 5-6 的执行核心）。
//!
//! 注意：当前为"发一批 → 短监听"的串行简化；生产实现应改为发包/收包并发
//! （时序压缩 150ms 窗口，见 03 §3.5.6），由引擎实现阶段切换。

use crate::transport::UdpProbeCarrier;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;
use wgp_proto::consts::WAVE_TIMEOUT_MS;
use wgp_punch::{plan_waves, BudgetScheduler, PortStepModel, ProbeCarrier};

/// 一轮竞速的结果
#[derive(Debug, Clone)]
pub struct PunchOutcome {
    /// 验证过的对端实际地址（收到对端探针且 HMAC 通过）
    pub peer_addr: Option<SocketAddr>,
    /// 命中的对端探针数
    pub hits: u32,
    /// 实际发送的探针数（受预算裁剪）
    pub packets_sent: u32,
    /// 剩余轮预算
    pub budget_left: u16,
}

impl PunchOutcome {
    pub fn is_hit(&self) -> bool {
        self.peer_addr.is_some()
    }
}

pub struct PunchRunner<'a> {
    carrier: &'a UdpProbeCarrier,
    budget: &'a mut BudgetScheduler,
}

impl<'a> PunchRunner<'a> {
    pub fn new(carrier: &'a UdpProbeCarrier, budget: &'a mut BudgetScheduler) -> Self {
        Self { carrier, budget }
    }

    /// 执行一轮三波探测（对 peer_ip 的预测端口窗口）。
    /// `model`：端口步长模型（None = 无数据 36 包撒网）。
    /// `seed`：计划的确定性种子（由会话 nonce 派生）。
    pub async fn run_waves(
        &mut self,
        model: Option<&PortStepModel>,
        peer_ip: IpAddr,
        seed: u64,
    ) -> PunchOutcome {
        let window_ms = Duration::from_millis(WAVE_TIMEOUT_MS);
        let mut hits = 0u32;
        let mut packets_sent = 0u32;
        let mut peer_addr: Option<SocketAddr> = None;

        let plan = {
            let round_remain = self.budget.remaining().0;
            plan_waves(model, seed, round_remain)
        };
        let waves = [
            plan.wave1.clone(),
            plan.wave2.clone(),
            plan.wave3.clone(),
        ];

        for wave in waves.iter() {
            if wave.is_empty() {
                continue;
            }
            // ① 预算门控发包（每包先扣预算，扣不出即停）
            let mut sent_this_wave = 0u32;
            for &port in wave.iter() {
                if self.budget.try_acquire(1).is_err() {
                    break;
                }
                let probe = self.carrier.craft();
                let dst = SocketAddr::new(peer_ip, port);
                if let Err(_e) = self.carrier.send_probe(dst, &probe).await {
                    // 发送失败不致命；继续（预算已扣——严格口径下由引擎层统一处理）
                    continue;
                }
                packets_sent += 1;
                sent_this_wave += 1;
            }
            if sent_this_wave == 0 {
                break;
            }

            // ② 本波监听窗口：等对端探针（验签由 recv_verified 内建）
            let deadline = timeout(window_ms, async {
                loop {
                    match self.carrier.recv_verified().await {
                        Some((_p, src)) => return Some(src),
                        None => continue, // malformed/伪造包——静默丢弃
                    }
                }
            });

            if let Ok(Some(src)) = deadline.await {
                // 自包头排除：loopback/异常路由下自己发出的探针折返不得计命中
                let self_addr = self.carrier.local_addr().ok();
                if src.ip() == peer_ip && Some(src) != self_addr {
                    hits += 1;
                    peer_addr = Some(src);
                    // 命中即停（先通先用；同档更优链路不重复交付，14 §10 条款 1）
                    break;
                }
                // 源 IP 不匹配或自折返：忽略（乱包/其他会话）
            }
        }

        PunchOutcome {
            peer_addr,
            hits,
            packets_sent,
            budget_left: self.budget.remaining().0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED_KEY: [u8; 32] = [0x51; 32];

    fn probe_bytes_is_valid(carrier: &UdpProbeCarrier, buf: &[u8]) -> bool {
        carrier.on_probe("0.0.0.0:0".parse().unwrap(), buf)
    }

    #[tokio::test]
    async fn wave_exec_hits_peer_reply() {
        let a = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [1, 2, 3, 4])
            .await
            .unwrap();
        let b = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [5, 6, 7, 8])
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let peer_ip = b.local_addr().unwrap().ip();

        // 对端 B：100ms 后向 A 回发验签探针（模拟窗口内命中并双向确认）
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let probe = b.craft();
            b.socket().send_to(&probe, a_addr).await.unwrap();
        });

        let mut budget = BudgetScheduler::new();
        let mut runner = PunchRunner::new(&a, &mut budget);
        let outcome = runner.run_waves(None, peer_ip, 42).await;

        assert!(outcome.is_hit(), "应收到对端探针并判定命中");
        assert_eq!(outcome.hits, 1, "对端回发的验签探针计 1 次命中");
        assert!(outcome.peer_addr.unwrap().ip() == peer_ip);
        assert!(outcome.packets_sent > 0 && outcome.packets_sent <= 36);
    }

    #[tokio::test]
    async fn budget_cap_limits_packets() {
        let a = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [1, 2, 3, 4])
            .await
            .unwrap();
        let peer_ip = "127.0.0.1".parse::<IpAddr>().unwrap();

        let mut budget = BudgetScheduler::new();
        // 手动消耗至仅剩 7
        for _ in 0..40 {
            budget.try_acquire(1).unwrap();
        }
        let mut runner = PunchRunner::new(&a, &mut budget);
        let outcome = runner.run_waves(None, peer_ip, 42).await;
        assert_eq!(outcome.packets_sent, 7, "轮预算仅剩 7，发包必须被裁剪");
        assert!(!outcome.is_hit());
    }

    #[tokio::test]
    async fn forged_probe_never_counts_as_hit() {
        let a = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [1, 2, 3, 4])
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let peer_ip = a_addr.ip();
        // 伪造源：同 IP、错误密钥 → recv_verified 必拒
        let evil = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), [0xEE; 32], [9, 9, 9, 9])
            .await
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let probe = evil.craft();
            evil.socket().send_to(&probe, a_addr).await.unwrap();
        });

        let mut budget = BudgetScheduler::new();
        let mut runner = PunchRunner::new(&a, &mut budget);
        // 单波超时后结束：不会有命中
        let outcome = runner.run_waves(None, peer_ip, 7).await;
        assert!(!outcome.is_hit(), "伪造探针（错密钥）不得判定命中");
        // 探针自身格式与签名仍可被外部验证工具确认（载体 A 视角应拒绝）
        let evil_probe = {
            let e = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), [0xEE; 32], [9, 9, 9, 9])
                .await
                .unwrap();
            let p = e.craft();
            assert!(probe_bytes_is_valid(&e, &p));
            p
        };
        assert!(!probe_bytes_is_valid(&a, &evil_probe));
    }
}