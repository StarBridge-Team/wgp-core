//! 链路档位（00 §4 链路优先级：LAN > QUIC > TCP > ICMP）。
//! 独立成模块：node 裁剪面的事件系统也需要引用（不依赖 link/crypto）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkRank {
    /// 主档：UDP（跑 QUIC）/ LAN 直连
    Primary,
    /// 降级档：TCP + TLS-PSK
    Degraded,
    /// 逃生档：ICMP（仅信令级流量）
    Escape,
}