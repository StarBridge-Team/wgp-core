//! NAT 保活哨兵（14 §10 条款 4：内核唯一负责保活，外围零心跳）。
//!
//! 节奏决策复用 wgp-punch 的 HeartbeatLoop（滑窗自适应/恢复三连发/
//! 步长扩展节拍）；发送侧复用 31B 验签探针（探针即等价 NAT 保活流量，
//! 避免双包型）。每发 1 包同样过全局预算闸门（H6 不破）。

use crate::transport::probe::now_ms;
use crate::transport::UdpProbeCarrier;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use wgp_punch::{BudgetScheduler, HbAction, HeartbeatLoop, ProbeCarrier};

/// 保活主循环：100ms 步进轮询 HeartbeatLoop 节拍（低功耗优化
/// ——生产改为按 next_interval 精确 sleep；CPU 影响在 v1 可忽略）
pub async fn keepalive_loop(
    carrier: Arc<UdpProbeCarrier>,
    peer_addr: SocketAddr,
    budget: Arc<Mutex<BudgetScheduler>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut hb = HeartbeatLoop::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        let now = now_ms();
        match hb.tick(now, true) {
            Some(HbAction::Send { seq: _, with_ext: _ }) | Some(HbAction::FastSend { seq: _ }) => {
                // 预算闸门：保活包同受全局调度（失败仅本轮跳过）
                if budget.lock().await.try_acquire(1).is_ok() {
                    let probe = carrier.craft();
                    let _ = carrier.send_probe(peer_addr, &probe).await;
                }
            }
            None => {}
        }
    }
}