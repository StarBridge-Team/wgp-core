//! 双模定时器（03 §3.3.5）。
//!
//!  - Normal：常规调度，tokio 默认精度即可（心跳/保活/超时）
//!  - Precision：打洞窗口期高精度（探测波形启用），内核强制小数 ms 抖动收紧
//!
//! v1 边界如实标注：本模块管理"何时点火"的语义与时序纪律（deadline 判定、
//! 模式切换、对齐辅助）；真实时钟精度由 tokio 提供——Windows 基础定时器
//! 分辨率 15.6ms 的问题在生产阶段以 timeBeginPeriod/Priority 提升解决
//! （列入部署清单真机验证前置项）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    Normal,
    Precision,
}

impl Default for TimerMode {
    fn default() -> Self {
        Self::Normal
    }
}

/// 相对时刻毫秒（引擎单调时钟锚点换算后）
pub struct DualModeTimer {
    mode: TimerMode,
    /// 校准偏移：Precision 模式核 align_shift 前的提前量回补
    shift_ms: i64,
}

impl DualModeTimer {
    pub fn new() -> Self {
        Self {
            mode: TimerMode::Normal,
            shift_ms: 0,
        }
    }

    /// 模式切换（Precision 仅限打洞窗口，窗口结束必须回落）
    pub fn set_mode(&mut self, mode: TimerMode) {
        self.mode = mode;
    }

    pub fn mode(&self) -> TimerMode {
        self.mode
    }

    /// 校准：双端测得的单向漂移注入（引擎换算后调用）
    pub fn apply_shift(&mut self, shift_ms: i64) {
        self.shift_ms = shift_ms;
    }

    /// 判定：无偏 deadline 已到？
    /// deadline_ms 为约定发射时刻（相对锚点），now_ms 为当前相对时刻。
    pub fn fired(&self, deadline_ms: i64, now_ms: i64) -> bool {
        // Precision 允许提前 ≤2ms 视为已到（内核级抖动收紧）
        let slack = if self.mode == TimerMode::Precision { 2 } else { 0 };
        now_ms >= deadline_ms + self.shift_ms - slack
    }

    /// 距下一次点火剩余毫秒（<=0 = 已到）
    pub fn remaining(&self, deadline_ms: i64, now_ms: i64) -> i64 {
        deadline_ms + self.shift_ms - now_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_fires_on_or_after_deadline() {
        let t = DualModeTimer::new();
        assert!(!t.fired(1000, 999), "未到不点火");
        assert!(t.fired(1000, 1000), "恰好到即点火");
        assert!(t.fired(1000, 1001), "过了更要点");
    }

    #[test]
    fn precision_allows_2ms_lead() {
        let mut t = DualModeTimer::new();
        t.set_mode(TimerMode::Precision);
        assert!(!t.fired(1000, 997), "提前 3ms 仍不点");
        assert!(t.fired(1000, 998), "提前 2ms 视为已到");
        assert!(t.fired(1000, 1005));
    }

    #[test]
    fn shift_is_applied() {
        let mut t = DualModeTimer::new();
        t.apply_shift(-50);
        assert!(!t.fired(1000, 949));
        assert!(t.fired(1000, 950), "shift 后的 deadline 提前");
    }

    #[test]
    fn remaining_respects_shift() {
        let mut t = DualModeTimer::new();
        t.apply_shift(30);
        assert_eq!(t.remaining(1000, 950), 80);
        assert_eq!(t.remaining(1000, 1050), -20);
    }
}