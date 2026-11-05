//! 包预算调度器（H6，00 §3：内核唯一发包点）。
//! 双闸门：轮预算 ≤47、滑动 10 分钟预算 ≤500；耗尽即触发 BudgetExhausted 事件。

use wgp_proto::consts::{PROBE_BUDGET_PER_10MIN, PROBE_BUDGET_PER_ROUND};

#[derive(Debug, Clone)]
pub struct BudgetScheduler {
    /// 本轮剩余（打洞竞速一轮）
    per_round_remaining: u16,
    /// 10 分钟滑动窗口剩余
    per_window_remaining: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    RoundExhausted,
    WindowExhausted,
}

impl BudgetScheduler {
    pub fn new() -> Self {
        Self {
            per_round_remaining: PROBE_BUDGET_PER_ROUND,
            per_window_remaining: PROBE_BUDGET_PER_10MIN,
        }
    }

    /// 申请 n 包发射预算；两闸门任一不足即拒绝。
    /// 这是全内核唯一的探针预算入口。
    pub fn try_acquire(&mut self, n: u16) -> Result<(), BudgetError> {
        if n > self.per_round_remaining {
            return Err(BudgetError::RoundExhausted);
        }
        if n > self.per_window_remaining {
            return Err(BudgetError::WindowExhausted);
        }
        self.per_round_remaining -= n;
        self.per_window_remaining -= n;
        Ok(())
    }

    /// 新一轮开始（重打洞/升级探测）：轮预算复位（窗口预算不回滚——H6 滑动语义）
    pub fn begin_round(&mut self) {
        self.per_round_remaining = PROBE_BUDGET_PER_ROUND;
    }

    /// 窗口闸门恢复（由时间驱动；实现阶段接入引擎定时器，每 10 分钟滑动回填）
    pub fn refill_window(&mut self) {
        self.per_window_remaining = PROBE_BUDGET_PER_10MIN;
    }

    pub fn remaining(&self) -> (u16, u16) {
        (self.per_round_remaining, self.per_window_remaining)
    }
}

impl Default for BudgetScheduler {
    fn default() -> Self {
        Self::new()
    }
}