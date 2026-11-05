//! 链路交付物（14 §2）：PunchedLink 及承载类型。

use crate::PeerId;
use crate::rank::LinkRank;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// 链路质量（内核实测）
#[derive(Debug, Clone, Copy)]
pub struct LinkQuality {
    pub rtt: Duration,
    pub loss: f32,
    pub measured_mtu: u16,
    pub obeys_budget: bool,
}

/// 承载载体（14 §2）——所有权随 PunchedLink 一并移交外围
pub enum LinkTransport {
    /// 打洞验证的 UDP socket（外围跑 QUIC；Arc 共享：载体保活与 QUIC 同 socket）
    Udp { socket: Arc<UdpSocket> },
    /// simultaneous-open 成功的 TCP 流（外围跑 TLS-PSK + 帧流）
    Tcp { stream: TcpStream },
    /// ICMP 逃生通道句柄（平台实现待接；仅信令级）
    Icmp { chan: IcmpChan },
    /// LAN 组播发现直连
    Lan { socket: Arc<UdpSocket> },
}

/// ICMP 逃生通道句柄骨架（实现阶段接平台原生 API）
pub struct IcmpChan {
    pub identifier: u16,
}

/// 内核交付物（14 §2）：一次打击 = 一条可用链路
pub struct PunchedLink {
    pub peer_id: PeerId,
    pub transport: LinkTransport,
    pub session_key: wgp_crypto::SecretBox,
    pub quality: LinkQuality,
    pub rank: LinkRank,
}