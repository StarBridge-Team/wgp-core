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

    /// 为一次打洞会话预留一轮配额（H6：单侧 ≤47 包/轮）。
    ///
    /// 从 10 分钟窗口预算中**预扣** `min(47, 窗口剩余)`，返回只供该会话使用的
    /// 会话级调度器（其轮/窗口两闸门都等于预扣额）。会话结束后必须调用
    /// [`BudgetScheduler::refund_round`] 归还未用部分。
    ///
    /// 预扣而非事后结算：多个会话并发打洞时，各自配额之和永远不会超出窗口预算；
    /// 每个会话独立的轮闸门则保证 mesh 多边互不挤占、也互不放大。
    pub fn reserve_round(&mut self) -> BudgetScheduler {
        let grant = self.per_window_remaining.min(PROBE_BUDGET_PER_ROUND);
        self.per_window_remaining -= grant;
        BudgetScheduler {
            per_round_remaining: grant,
            per_window_remaining: grant,
        }
    }

    /// 归还会话未用配额（与 [`BudgetScheduler::reserve_round`] 配对）。
    /// 封顶于窗口上限：会话期间若恰逢窗口回填，归还不得令预算超发。
    pub fn refund_round(&mut self, session: &BudgetScheduler) {
        let unused = session
            .per_round_remaining
            .min(session.per_window_remaining);
        self.per_window_remaining = self
            .per_window_remaining
            .saturating_add(unused)
            .min(PROBE_BUDGET_PER_10MIN);
    }

    /// 保活专用入口：只过 10 分钟窗口闸门。
    ///
    /// 轮预算是「一次打洞竞速」的配额；稳态保活跨越任意多轮，若也扣轮预算，
    /// 打洞用剩的那点余量几十秒内就会耗尽，此后保活永久停摆（NAT 映射随之过期）。
    pub fn try_acquire_keepalive(&mut self, n: u16) -> Result<(), BudgetError> {
        if n > self.per_window_remaining {
            return Err(BudgetError::WindowExhausted);
        }
        self.per_window_remaining -= n;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_round_grants_full_round_and_prededucts_window() {
        let mut shared = BudgetScheduler::new();
        let session = shared.reserve_round();
        assert_eq!(session.remaining(), (PROBE_BUDGET_PER_ROUND, PROBE_BUDGET_PER_ROUND));
        assert_eq!(
            shared.remaining().1,
            PROBE_BUDGET_PER_10MIN - PROBE_BUDGET_PER_ROUND,
            "预留即从窗口预扣"
        );
    }

    #[test]
    fn refund_returns_only_unused_part() {
        let mut shared = BudgetScheduler::new();
        let mut session = shared.reserve_round();
        for _ in 0..30 {
            session.try_acquire(1).unwrap();
        }
        shared.refund_round(&session);
        assert_eq!(shared.remaining().1, PROBE_BUDGET_PER_10MIN - 30);
    }

    #[test]
    fn each_session_capped_at_round_budget() {
        let mut shared = BudgetScheduler::new();
        let mut session = shared.reserve_round();
        for _ in 0..PROBE_BUDGET_PER_ROUND {
            session.try_acquire(1).unwrap();
        }
        assert!(session.try_acquire(1).is_err(), "单会话不得超过 47 包");
        // 第二个会话拿到的是全新的一轮，与前一会话互不影响
        let second = shared.reserve_round();
        assert_eq!(second.remaining().0, PROBE_BUDGET_PER_ROUND);
    }

    #[test]
    fn concurrent_reservations_never_exceed_window() {
        let mut shared = BudgetScheduler::new();
        let mut granted = 0u16;
        let mut sessions = Vec::new();
        // 远超窗口容量的并发会话数：配额之和必须封顶于 500
        for _ in 0..20 {
            let s = shared.reserve_round();
            granted += s.remaining().0;
            sessions.push(s);
        }
        assert_eq!(granted, PROBE_BUDGET_PER_10MIN);
        assert_eq!(shared.remaining().1, 0);
        // 窗口耗尽后的会话拿到 0 配额
        assert_eq!(shared.reserve_round().remaining(), (0, 0));
        // 全部未用归还 → 恢复满额且不超发
        for s in &sessions {
            shared.refund_round(s);
        }
        assert_eq!(shared.remaining().1, PROBE_BUDGET_PER_10MIN);
    }

    #[test]
    fn refund_after_refill_is_capped() {
        let mut shared = BudgetScheduler::new();
        let session = shared.reserve_round();
        shared.refill_window(); // 会话期间恰逢窗口回填
        shared.refund_round(&session);
        assert_eq!(shared.remaining().1, PROBE_BUDGET_PER_10MIN, "归还不得令窗口超发");
    }

    #[test]
    fn keepalive_ignores_round_gate_but_obeys_window() {
        let mut b = BudgetScheduler::new();
        // 轮预算耗尽
        for _ in 0..PROBE_BUDGET_PER_ROUND {
            b.try_acquire(1).unwrap();
        }
        assert_eq!(b.try_acquire(1), Err(BudgetError::RoundExhausted));
        // 保活不受轮闸门影响
        assert!(b.try_acquire_keepalive(1).is_ok());
        // 但窗口闸门照旧生效
        let left = b.remaining().1;
        for _ in 0..left {
            b.try_acquire_keepalive(1).unwrap();
        }
        assert_eq!(b.try_acquire_keepalive(1), Err(BudgetError::WindowExhausted));
        b.refill_window();
        assert!(b.try_acquire_keepalive(1).is_ok());
    }
}
