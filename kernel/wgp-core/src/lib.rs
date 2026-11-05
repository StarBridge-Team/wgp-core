//! 折跃门内核门面（00 §4 + 14 文档的代码落点）。
//! 内核契约：职责终点 = 产出一条已打通的链路（PunchedLink）；
//! 保活唯一权在内核；调度器是唯一发包点。
//!
//! feature 裁剪（00 ADR D1）：
//!  - `client`（默认）：打洞/信令/载体/密钥导出全量
//!  - `node`：仅服务端四职（DHT 种子/观察者/STUN/承诺转发兜底），
//!    编译产物不含打洞引擎与密钥协商逻辑

pub mod engine;
pub mod event;
#[cfg(feature = "client")]
pub mod exporter;
#[cfg(feature = "client")]
pub mod link;
#[cfg(feature = "client")]
pub mod orchestrator;
pub mod rank;
#[cfg(feature = "client")]
pub mod servers;
#[cfg(feature = "client")]
pub mod transport;
#[cfg(feature = "client")]
pub mod types;

pub use engine::{Engine, LinkStream, NodeConfig, NodeHandle, NodeRole};
#[cfg(feature = "client")]
pub use engine::{PunchInput, RoomHandle};
pub use event::{
    AnchorChangeReason, DeadEndReport, EngineEvent, LinkLossCause, RePunchReason,
    RoomJoinFailReason,
};
#[cfg(feature = "client")]
pub use exporter::{KeyExporter, PskBundle};
#[cfg(feature = "client")]
pub use link::{LinkQuality, LinkTransport, PunchedLink};
#[cfg(feature = "client")]
pub use orchestrator::{OrchestratorError, SessionOrchestrator};
pub use rank::LinkRank;
#[cfg(feature = "client")]
pub use servers::{measure_seeds, pick_fastest_seed, resolve_endpoint, SeedPick};
#[cfg(feature = "client")]
pub use transport::{LanProbeCarrier, TcpProbeCarrier, UdpProbeCarrier};
#[cfg(feature = "client")]
pub use types::{
    JoinHandle, LinkControl, LinkIntent, LinkSink, MemberInfo, RoomApi, RoomCode, RoomId, RoomKey,
    RoomRole, TransportCapabilitySet,
};
#[cfg(feature = "client")]
pub use wgp_crypto::{CryptoProfile, SecretBox};
pub use wgp_dht::id::peer_id_from_node;
#[cfg(feature = "client")]
pub use wgp_punch::{ProbeCarrier, PunchState};

/// Peer 短标识 = DHT 节点身份公钥哈希截断
pub type PeerId = [u8; 16];