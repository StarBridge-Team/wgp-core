//! 动态心跳控制器与保活循环（03 §3.7/§3.8 代码化）。
//! HeartbeatController：成功率滑窗动态调间隔。
//! HeartbeatLoop：tick 驱动纯逻辑（无定时器依赖，可单测），与预算闸门联动。

use std::collections::VecDeque;
use std::time::Duration;

/// NAT 保活心跳控制器（保活唯一权在内核，00 §4；外围零心跳）
pub struct HeartbeatController {
    min_interval: Duration,
    max_interval: Duration,
    next_interval: Duration,
    /// 最近 20 次心跳成功率滑窗
    success_window: VecDeque<bool>,
}

impl HeartbeatController {
    pub fn new() -> Self {
        Self {
            min_interval: Duration::from_millis(500),
            max_interval: Duration::from_secs(15),
            next_interval: Duration::from_secs(2),
            success_window: VecDeque::with_capacity(20),
        }
    }

    /// 心跳结果反馈：成功率 <0.8 加频（步长 500ms）；>0.95 减频（步长 1s）
    pub fn on_result(&mut self, success: bool) {
        self.success_window.push_back(success);
        if self.success_window.len() > 20 {
            self.success_window.pop_front();
        }
        let rate = self
            .success_window
            .iter()
            .filter(|&&s| s)
            .count() as f64
            / self.success_window.len() as f64;

        if rate < 0.8 {
            self.next_interval = self
                .next_interval
                .saturating_sub(Duration::from_millis(500))
                .max(self.min_interval);
        } else if rate > 0.95 {
            self.next_interval = (self.next_interval + Duration::from_secs(1))
                .min(self.max_interval);
        }
    }

    /// 休眠/挂起恢复：连续 3 次快速心跳（100ms 间隔）
    pub fn fast_recovery_interval(&self) -> Duration {
        Duration::from_millis(100)
    }

    pub fn next_interval(&self) -> Duration {
        self.next_interval
    }
}

impl Default for HeartbeatController {
    fn default() -> Self {
        Self::new()
    }
}

/// 保活循环（tick 驱动：外层每 ~100ms 调一次 tick(now_ms, budget_ok)）。
/// 输出动作由引擎执行发包；预算拒绝时不推进计时，避免 NAT 表超时口径失真。
pub struct HeartbeatLoop {
    ctrl: HeartbeatController,
    last_send_ms: Option<u64>,
    seq: u32,
    /// 步长校准扩展节奏：每 10 次带 1 次（03 §3.7.4）
    ext_every: u32,
    /// 检测到端口突变后连续 3 次都带扩展
    anomaly_extra_ext: u8,
    /// 设备恢复快速心跳剩余次数（100ms 间隔 ×3）
    fast_recovery_left: u8,
}

/// 心跳动作
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HbAction {
    /// 常规发送：seq + 是否携带步长扩展（cur/prev port 由引擎填入）
    Send { seq: u32, with_ext: bool },
    /// 恢复期快速发送（100ms 间隔，不参与滑窗计数）
    FastSend { seq: u32 },
}

impl HeartbeatLoop {
    pub fn new() -> Self {
        Self {
            ctrl: HeartbeatController::new(),
            last_send_ms: None,
            seq: 0,
            ext_every: 10,
            anomaly_extra_ext: 0,
            fast_recovery_left: 0,
        }
    }

    /// 是否该发心跳（外层驱动入口）
    pub fn tick(&mut self, now_ms: u64, budget_ok: bool) -> Option<HbAction> {
        // ① 恢复期快速心跳优先（100ms 间隔，发送 3 次）
        if self.fast_recovery_left > 0 {
            let due = match self.last_send_ms {
                None => true,
                Some(last) => now_ms.saturating_sub(last) >= 100,
            };
            if due {
                self.seq = self.seq.wrapping_add(1);
                self.last_send_ms = Some(now_ms);
                self.fast_recovery_left -= 1;
                return Some(HbAction::FastSend { seq: self.seq });
            }
            return None;
        }

        // ② 常规心跳：间隔由滑窗控制器给定
        let interval_ms = self.ctrl.next_interval().as_millis() as u64;
        let due = match self.last_send_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= interval_ms,
        };
        if !due {
            return None;
        }
        // ③ 预算闸门（H6：心跳与探测共用调度器配额）
        if !budget_ok {
            // 不推进 last_send：下次 tick 重试；引擎侧会收到 BudgetExhausted
            return None;
        }
        self.seq = self.seq.wrapping_add(1);
        self.last_send_ms = Some(now_ms);

        // ④ 扩展节奏：每 ext_every 次 1 次；异常后连续 3 次
        let with_ext = if self.anomaly_extra_ext > 0 {
            self.anomaly_extra_ext -= 1;
            true
        } else {
            self.seq % self.ext_every == 0
        };
        Some(HbAction::Send {
            seq: self.seq,
            with_ext,
        })
    }

    /// 心跳结果反馈（透传滑窗）
    pub fn on_result(&mut self, success: bool) {
        self.ctrl.on_result(success);
    }

    /// 引擎检测到端口突变（03 §3.7.5）：连续 3 次扩展格式
    pub fn on_anomaly(&mut self) {
        self.anomaly_extra_ext = 3;
    }

    /// 设备休眠/网络切换恢复：3 次 100ms 快速心跳重建映射
    pub fn on_resume(&mut self) {
        self.fast_recovery_left = 3;
    }

    /// 当前常规间隔（毫秒）
    pub fn current_interval_ms(&self) -> u64 {
        self.ctrl.next_interval().as_millis() as u64
    }

    /// 连接断开/释放：状态复位，seq 从 0 起
    pub fn reset(&mut self) {
        self.last_send_ms = None;
        self.seq = 0;
        self.anomaly_extra_ext = 0;
        self.fast_recovery_left = 0;
    }
}

impl Default for HeartbeatLoop {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_interval_2s() {
        let mut hb = HeartbeatLoop::new();
        assert_eq!(hb.current_interval_ms(), 2000);
        // t=0 首发
        assert!(matches!(hb.tick(0, true), Some(HbAction::Send { seq: 1, .. })));
        // 2s 内不再发
        assert!(hb.tick(1999, true).is_none());
        // 2s 到点再发
        assert!(matches!(hb.tick(2000, true), Some(HbAction::Send { seq: 2, .. })));
    }

    #[test]
    fn seq_10_carries_ext_normal_rhythm() {
        let mut hb = HeartbeatLoop::new();
        let mut ext_at = Vec::new();
        let mut t = 0u64;
        for _ in 0..10 {
            let a = hb.tick(t, true).expect("due");
            t += 2000;
            if let HbAction::Send { seq, with_ext: true } = a {
                ext_at.push(seq);
            }
        }
        assert_eq!(ext_at, vec![10]); // 每 10 次恰 1 次扩展
    }

    #[test]
    fn budget_reject_defers_not_sends() {
        let mut hb = HeartbeatLoop::new();
        let mut t = 0u64;
        let _ = hb.tick(t, true); // seq=1
        t += 2000;
        // 预算拒绝：不发且不推进
        assert!(hb.tick(t, false).is_none());
        // 下个 tick 预算恢复：seq 应为 2（不是跳号）
        let a = hb.tick(t, true).expect("recovered");
        assert!(matches!(a, HbAction::Send { seq: 2, .. }));
    }

    #[test]
    fn fast_recovery_three_at_100ms() {
        let mut hb = HeartbeatLoop::new();
        hb.on_resume();
        let mut t = 0u64;
        let mut seqs = Vec::new();
        for _ in 0..3 {
            // 恢复期不被常规间隔限制
            let a = hb.tick(t, true).expect("fast");
            if let HbAction::FastSend { seq } = a {
                seqs.push(seq);
            }
            t += 100;
        }
        assert_eq!(seqs.len(), 3);
        // 恢复完毕，回常规节奏（2s）
        assert!(hb.tick(t, true).is_none());
    }

    #[test]
    fn high_success_low_freq_adapts_up() {
        let mut ctrl = HeartbeatController::new();
        for _ in 0..20 {
            ctrl.on_result(true);
        }
        // 20 次全成：rate=1.0 → 逐次 +1s 直至上限 15s
        assert_eq!(ctrl.next_interval(), Duration::from_secs(15));
        // 反压：连续失败逐步拉回 500ms 底（15s→500ms 需 29 次 -500ms；
        // 前 4 次 rate 仍 ≥0.8 不触发，用 40 次保证触底）
        for _ in 0..40 {
            ctrl.on_result(false);
        }
        assert_eq!(ctrl.next_interval(), Duration::from_millis(500));
    }
}