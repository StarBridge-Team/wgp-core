//! NAT 保活哨兵（14 §10 条款 4：内核唯一负责保活，外围零心跳）。
//!
//! 节奏决策复用 wgp-punch 的 HeartbeatLoop（滑窗自适应/恢复三连发/
//! 步长扩展节拍）；发送侧复用 31B 验签探针（探针即等价 NAT 保活流量，
//! 避免双包型）。每发 1 包同样过全局预算闸门（H6 不破）。
//!
//! 预算口径：保活只过 10 分钟窗口闸门（`try_acquire_keepalive`）——轮预算属于
//! 「一次打洞竞速」，稳态保活若也扣轮预算，打洞用剩的余量耗尽后保活即永久停摆。
//! 多链路公平节拍：同一引擎上的 n 条链路共享窗口预算，按
//! [`fair_share_interval_ms`] 均摊发包间隔，避免「前半窗口发光、后半窗口全哑」。

use crate::transport::probe::now_ms;
use crate::transport::UdpProbeCarrier;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use wgp_proto::consts::{PROBE_BUDGET_PER_10MIN, PROBE_BUDGET_PER_ROUND};
use wgp_punch::{BudgetScheduler, HbAction, HeartbeatLoop, ProbeCarrier};

/// 窗口预算的时间跨度（H6：≤500 包/10 分钟）
pub const BUDGET_WINDOW_MS: u64 = 600_000;

/// n 条链路共享窗口预算时，单链路保活的最小发包间隔（毫秒）。
///
/// 窗口预算先给打洞竞速留出两轮余量（2×47），其余平摊给各链路的保活。
/// 单链路时约 1.5s，低于心跳基础间隔 2s，不改变既有节奏；链路越多间隔越长
/// （2 条 ≈3s、5 条 ≈7.4s、10 条 ≈14.8s），保活总量恒不超其份额。
pub fn fair_share_interval_ms(active_links: usize) -> u64 {
    let share = u64::from(PROBE_BUDGET_PER_10MIN - 2 * PROBE_BUDGET_PER_ROUND);
    let n = active_links.max(1) as u64;
    (n * BUDGET_WINDOW_MS).div_ceil(share)
}

/// 保活主循环：100ms 步进轮询 HeartbeatLoop 节拍（低功耗优化
/// ——生产改为按 next_interval 精确 sleep；CPU 影响在 v1 可忽略）。
/// `active_links`：本引擎当前在跑的保活链路数（含自身），用于公平节拍。
pub async fn keepalive_loop(
    carrier: Arc<UdpProbeCarrier>,
    peer_addr: SocketAddr,
    budget: Arc<Mutex<BudgetScheduler>>,
    mut stop: watch::Receiver<bool>,
    active_links: Arc<AtomicUsize>,
) {
    let mut hb = HeartbeatLoop::new();
    let mut last_sent_ms: Option<u64> = None;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        let now = now_ms();
        // 公平节拍未到 = 视同预算暂不可用：HeartbeatLoop 不推进计时，下个 tick 重试
        let pace_ok = match last_sent_ms {
            None => true,
            Some(last) => {
                now.saturating_sub(last)
                    >= fair_share_interval_ms(active_links.load(Ordering::Relaxed))
            }
        };
        match hb.tick(now, pace_ok) {
            Some(HbAction::Send { seq: _, with_ext: _ }) | Some(HbAction::FastSend { seq: _ }) => {
                // 预算闸门：保活包同受全局调度（失败仅本轮跳过）
                if budget.lock().await.try_acquire_keepalive(1).is_ok() {
                    let probe = carrier.craft();
                    let _ = carrier.send_probe(peer_addr, &probe).await;
                    last_sent_ms = Some(now);
                }
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_link_keeps_base_cadence() {
        // 单链路均摊间隔 < 心跳基础间隔 2s：不改变既有节奏
        assert!(fair_share_interval_ms(1) < 2_000);
        assert_eq!(fair_share_interval_ms(0), fair_share_interval_ms(1));
    }

    #[test]
    fn fair_share_grows_with_links_and_stays_within_share() {
        let share = u64::from(PROBE_BUDGET_PER_10MIN - 2 * PROBE_BUDGET_PER_ROUND);
        let mut prev = 0u64;
        for n in 1..=64usize {
            let interval = fair_share_interval_ms(n);
            assert!(interval >= prev, "链路越多间隔不得变短");
            prev = interval;
            // 一个窗口内 n 条链路的保活总量不超保活份额
            assert!(n as u64 * (BUDGET_WINDOW_MS / interval) <= share, "n={n}");
        }
    }

    /// 回归：轮预算被打洞竞速耗尽后，保活仍须持续送达
    /// （修复前保活与竞速共用轮预算：余量用尽即永久停摆，NAT 映射随之过期）。
    #[tokio::test]
    async fn keepalive_survives_exhausted_round_budget() {
        let key = [0x5Au8; 32];
        let a = Arc::new(
            UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), key, [1, 2, 3, 4])
                .await
                .unwrap(),
        );
        let b = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), key, [5, 6, 7, 8])
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();

        let mut sched = BudgetScheduler::new();
        while sched.try_acquire(1).is_ok() {}
        assert_eq!(sched.remaining().0, 0);
        let window_before = sched.remaining().1;
        let budget = Arc::new(Mutex::new(sched));

        let (stop_tx, stop_rx) = watch::channel(false);
        let links = Arc::new(AtomicUsize::new(1));
        let task = tokio::spawn(keepalive_loop(a, b_addr, budget.clone(), stop_rx, links));

        let got = tokio::time::timeout(Duration::from_secs(2), b.recv_verified()).await;
        assert!(matches!(got, Ok(Some(_))), "轮预算耗尽后保活仍须送达对端");

        let _ = stop_tx.send(true);
        let _ = task.await;
        assert!(
            budget.lock().await.remaining().1 < window_before,
            "保活包须计入窗口预算（H6）"
        );
    }
}
