//! 入站 UDP 的限速闸门（审计 M6：观察者与 DHT socket 共用一套机制）。
//!
//! 为什么要有它：本项目的 UDP 入站面（观察者 / DHT socket 上的 STUN）对任何源地址都应答，
//! 而 UDP 源地址可伪造。只按单源限速挡不住分布式洪流，只按全局限速又会让一台主机把整个
//! 节点刷死（同 NAT 后面的正常用户一起遭殃）。所以闸门同时管三层：
//!
//! 1. **单源额度**（按 IP 归一，换源端口不重置）；
//! 2. **全局限速**（每秒应答数上限，挡住总量洪流）；
//! 3. **状态表上限**（源 IP 表有硬上限，超出整表清空——用短期宽松换内存确定性）。
//!
//! 超限一律**静默丢弃**：回一个错误包反而替攻击者放大了流量。

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 限速策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatePolicy {
    /// 单源 IP 每个窗口允许的应答数
    pub per_ip: u32,
    /// 窗口长度
    pub window: Duration,
    /// 全局限速（每秒应答数；0 = 不限）
    pub global_per_sec: u32,
    /// 参与计数的源 IP 表上限
    pub max_sources: usize,
}

impl RatePolicy {
    /// 单源每窗口 `per_ip` 条，窗口 `window`，全局按 25 倍单源额度/秒兜底
    pub fn per_source(per_ip: u32, window: Duration) -> Self {
        Self {
            per_ip: per_ip.max(1),
            window,
            ..Self::default()
        }
    }
}

impl Default for RatePolicy {
    /// 观察者默认值（审计简单项「观察者用量与限频对齐」）：
    ///
    /// 一次协商里每端要向观察者发 4 次探测（观测 + 步长三连测），同一公网 IP 后面可能
    /// 同时坐着一整个网吧/家庭的多台机器。旧的 12 次 / 10s 在 4 人并发时就到顶了，
    /// 现在给到 60 次 / 10s（≈ 15 个成员并发协商），全局 600 次 / 秒。
    fn default() -> Self {
        Self {
            per_ip: 60,
            window: Duration::from_secs(10),
            global_per_sec: 600,
            max_sources: 65_536,
        }
    }
}

struct Bucket {
    window_start: Instant,
    count: u32,
}

/// 单源 + 全局限速闸门
pub struct RateGate {
    policy: RatePolicy,
    buckets: HashMap<IpAddr, Bucket>,
    global_window: Instant,
    global_count: u32,
    last_sweep: Instant,
}

impl RateGate {
    pub fn new(policy: RatePolicy) -> Self {
        let now = Instant::now();
        Self {
            policy,
            buckets: HashMap::new(),
            global_window: now,
            global_count: 0,
            last_sweep: now,
        }
    }

    pub fn policy(&self) -> RatePolicy {
        self.policy
    }

    /// 替换策略（运维配置热更新；已有计数保留，只影响后续判定）
    pub fn set_policy(&mut self, policy: RatePolicy) {
        self.policy = policy;
    }

    /// 判定并计数：true = 额度内（本次计数）；false = 超限，调用方应静默丢弃
    pub fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        let policy = self.policy;
        // 全局限速：按 1 秒窗口
        if policy.global_per_sec > 0 {
            if now.duration_since(self.global_window) >= Duration::from_secs(1) {
                self.global_window = now;
                self.global_count = 0;
            }
            if self.global_count >= policy.global_per_sec {
                return false;
            }
        }
        // 周期性清扫过期窗口（间隔一个窗口即可，防长期闲置条目堆积）
        if now.duration_since(self.last_sweep) > policy.window {
            self.buckets
                .retain(|_, b| now.duration_since(b.window_start) <= policy.window);
            self.last_sweep = now;
        }
        // 清扫后仍逼近硬上限（海量源 IP 洪流）→ 整表清空
        if self.buckets.len() >= policy.max_sources {
            self.buckets.clear();
        }
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            window_start: now,
            count: 0,
        });
        if now.duration_since(bucket.window_start) > policy.window {
            bucket.window_start = now;
            bucket.count = 0;
        }
        if bucket.count >= policy.per_ip {
            return false;
        }
        bucket.count += 1;
        if policy.global_per_sec > 0 {
            self.global_count += 1;
        }
        true
    }

    /// 当前表里的源 IP 数（诊断 / 测试）
    pub fn tracked_sources(&self) -> usize {
        self.buckets.len()
    }
}

/// 放大应答的字节预算（审计 M3 的可落地部分）。
///
/// FIND_NODE / FIND_VALUE / FIND_SEEDS 的应答可以远大于请求（最多约 20 倍），UDP 源地址
/// 可伪造，于是它们天然是反射放大器。彻底解法是给请求加源地址 cookie（要改协议），
/// 这里先做**不改变报文格式**的缓解：按源 IP 与全局分别限制「放大应答的字节速率」。
/// 合法查询（一次完整迭代查找约 3KB）远低于额度；反射攻击的带宽被压到可忽略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudgetPolicy {
    /// 单源 IP 每秒允许的放大应答字节
    pub per_ip_per_sec: u32,
    /// 全局每秒允许的放大应答字节
    pub global_per_sec: u32,
    /// 参与计数的源 IP 表上限
    pub max_sources: usize,
}

impl Default for ByteBudgetPolicy {
    /// 单源 32 KiB/s（够 10 次完整查找）、全局 1 MiB/s
    fn default() -> Self {
        Self {
            per_ip_per_sec: 32 * 1024,
            global_per_sec: 1024 * 1024,
            max_sources: 65_536,
        }
    }
}

struct ByteBucket {
    window_start: Instant,
    bytes: u32,
}

/// 字节预算表
pub struct ByteBudget {
    policy: ByteBudgetPolicy,
    buckets: HashMap<IpAddr, ByteBucket>,
    global_window: Instant,
    global_bytes: u32,
}

impl ByteBudget {
    pub fn new(policy: ByteBudgetPolicy) -> Self {
        Self {
            policy,
            buckets: HashMap::new(),
            global_window: Instant::now(),
            global_bytes: 0,
        }
    }

    pub fn policy(&self) -> ByteBudgetPolicy {
        self.policy
    }

    /// 判定并记账：true = 这笔放大应答可以发；false = 超预算，丢弃（请求方超时重试）
    pub fn admit(&mut self, ip: IpAddr, bytes: usize, now: Instant) -> bool {
        let policy = self.policy;
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        if now.duration_since(self.global_window) >= Duration::from_secs(1) {
            self.global_window = now;
            self.global_bytes = 0;
        }
        if self.global_bytes.saturating_add(bytes) > policy.global_per_sec {
            return false;
        }
        if self.buckets.len() >= policy.max_sources {
            let now_window = now;
            self.buckets
                .retain(|_, b| now_window.duration_since(b.window_start) < Duration::from_secs(1));
            if self.buckets.len() >= policy.max_sources {
                return false; // 表满：拒绝新源（内存优先）
            }
        }
        let bucket = self.buckets.entry(ip).or_insert(ByteBucket {
            window_start: now,
            bytes: 0,
        });
        if now.duration_since(bucket.window_start) >= Duration::from_secs(1) {
            bucket.window_start = now;
            bucket.bytes = 0;
        }
        if bucket.bytes.saturating_add(bytes) > policy.per_ip_per_sec {
            return false;
        }
        bucket.bytes += bytes;
        self.global_bytes += bytes;
        true
    }

    /// 当前记账的源 IP 数（诊断 / 测试）
    pub fn tracked_sources(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, n])
    }

    #[test]
    fn per_ip_quota_is_independent_of_source_port() {
        let mut gate = RateGate::new(RatePolicy::per_source(3, Duration::from_secs(10)));
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(gate.admit(ip(1), t0));
        }
        assert!(!gate.admit(ip(1), t0), "超额即拒");
        // 别的源不受影响
        assert!(gate.admit(ip(2), t0));
        // 窗口滚动后恢复
        assert!(gate.admit(ip(1), t0 + Duration::from_secs(11)));
    }

    #[test]
    fn global_limit_caps_total_even_with_many_sources() {
        let mut gate = RateGate::new(RatePolicy {
            per_ip: 100,
            window: Duration::from_secs(10),
            global_per_sec: 5,
            max_sources: 1024,
        });
        let t0 = Instant::now();
        let admitted = (0..50u8).filter(|n| gate.admit(ip(*n), t0)).count();
        assert_eq!(admitted, 5, "分布式源也不能把全局额度撑破");
        // 下一秒恢复
        assert!(gate.admit(ip(99), t0 + Duration::from_secs(1)));
    }

    #[test]
    fn source_table_has_hard_cap() {
        let mut gate = RateGate::new(RatePolicy {
            per_ip: 10,
            window: Duration::from_secs(10),
            global_per_sec: 0, // 关掉全局限制，单看表
            max_sources: 4,
        });
        let t0 = Instant::now();
        for n in 0..8u8 {
            let _ = gate.admit(ip(n), t0);
        }
        assert!(gate.tracked_sources() <= 4, "表不得无界增长");
    }

    #[test]
    fn byte_budget_limits_amplification_per_source_and_globally() {
        let mut budget = ByteBudget::new(ByteBudgetPolicy {
            per_ip_per_sec: 1000,
            global_per_sec: 2500,
            max_sources: 16,
        });
        let t0 = Instant::now();
        // 单源：每次 400B，第三次会超出 1000
        assert!(budget.admit(ip(1), 400, t0));
        assert!(budget.admit(ip(1), 400, t0));
        assert!(!budget.admit(ip(1), 400, t0), "单源预算挡住放大");
        // 其它源仍可用，直到全局额度
        assert!(budget.admit(ip(2), 400, t0));
        assert!(budget.admit(ip(3), 400, t0)); // 累计 1200
        assert!(budget.admit(ip(4), 400, t0)); // 1600
        assert!(budget.admit(ip(5), 400, t0)); // 2000
        assert!(!budget.admit(ip(6), 400, t0), "全局预算 2500 挡住第 7 笔");
        // 窗口滚动后恢复
        assert!(budget.admit(ip(1), 400, t0 + Duration::from_secs(1)));
    }
}
