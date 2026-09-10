//! 折跃门内核门面（00 §4 + 14 文档的代码落点）。
//! 内核契约：职责终点 = 产出一条已打通的链路（PunchedLink）；
//! 保活唯一权在内核；调度器是唯一发包点。

pub mod engine;
pub mod event;
pub mod exporter;
pub mod link;
pub mod transport;
pub mod types;

pub use engine::{Engine, LinkStream, NodeConfig, NodeHandle, NodeRole, PunchInput, RoomHandle};
pub use event::{
    AnchorChangeReason, DeadEndReport, EngineEvent, LinkLossCause, RePunchReason,
    RoomJoinFailReason,
};
pub use exporter::{KeyExporter, PskBundle};
pub use link::{LinkQuality, LinkRank, LinkTransport, PunchedLink};
pub use transport::UdpProbeCarrier;
pub use types::{
    JoinHandle, LinkControl, LinkIntent, LinkSink, MemberInfo, RoomApi, RoomCode, RoomId, RoomKey,
    RoomRole, TransportCapabilitySet,
};
pub use wgp_crypto::{CryptoProfile, SecretBox};
pub use wgp_dht::id::peer_id_from_node;
pub use wgp_punch::{ProbeCarrier, PunchState};

/// Peer 短标识 = DHT 节点身份公钥哈希截断
pub type PeerId = [u8; 16];