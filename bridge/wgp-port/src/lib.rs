//! 折跃门数据面（外围，不属内核）：把内核交付的 `PunchedLink` 变成能传业务数据的隧道。
//!
//! 内核的职责终点是「打通一条链路并保活」（00 §4）；本 crate 从那里接手：
//!
//! ```text
//!   本地应用 ⇄ 端口转发(forward) ⇄ 多路复用(mux) ⇄ 链路(link) ⇄ PunchedLink
//!                                                   ├─ UDP：AEAD 数据报 + 可靠层(arq)
//!                                                   └─ TCP：AEAD 记录流
//! ```
//!
//! 硬约束的落点：
//!  - H1 零中继：业务数据只在打洞得到的直连 socket 上走，不经任何第三方。
//!  - H2 端到端加密：每个报文/记录都用会话密钥派生的方向密钥做 AES-256-GCM
//!    （`wgp_crypto::tunnel`），防篡改、防重放。
//!  - 保活唯一权在内核（14 §10 条款 4）：本 crate 不发任何周期性心跳；内核的保活探针
//!    与隧道报文共用同一个 UDP socket，收包侧按类型字节分流。
//!
//! 取舍说明（登记于 docs/14 §12）：00 D3 规划的「QUIC + TLS-PSK」依赖 rustls 支持外部
//! PSK，而 rustls 0.23 无此能力；v1 数据面因此采用 01 §1.3 的 AES-GCM 帧 + 自带的轻量
//! 可靠层，零新增第三方依赖。可靠层与复用层之间只有「可靠字节流」这一个接缝，
//! 日后换成 QUIC 不动上层。

mod arq;
pub mod forward;
mod frame;
mod link;
pub mod mux;
mod ranges;

pub use forward::{ExposeRule, ForwardRule, PortConfig, PortEvent, PortHub, Proto};
pub use frame::MUX_VERSION;
pub use mux::{
    Carrier, InboundDgram, IncomingStream, PeerHello, StreamReader, StreamWriter, Tunnel,
    TunnelConfig, TunnelError, TunnelHandle, TunnelStream, STREAM_WINDOW,
};

/// 隧道（链路）关闭原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// 本端主动关闭
    Local,
    /// 对端主动关闭（附对端给出的原因码，见 [`close_code`]）
    Peer(u8),
    /// 有数据在途但对端长时间无任何应答：链路已死
    Timeout,
    /// 对端长时间完全静默（既无隧道报文、也无内核保活探针）
    PeerSilent,
    /// 对端违反协议（帧畸形 / 越过流量额度 / 认证失败的记录流）
    Protocol,
    /// 底层 IO 错误（TCP 载体断开等）
    Io,
}

/// CLOSE 帧携带的原因码
pub mod close_code {
    /// 正常关闭（退出 / 离开房间）
    pub const NORMAL: u8 = 0;
    /// 检测到对端协议违规
    pub const PROTOCOL: u8 = 1;
    /// 同一对端的新链路已就绪，旧隧道让位
    pub const REPLACED: u8 = 2;
}
