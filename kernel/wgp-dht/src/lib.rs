//! 折跃门去中心化信令面（07 文档的代码化）。
//! 自研 Kademlia 变种；唯一基础设施是公网 wgp-node 种子（地址由外围配置注入）。

pub mod advertise;
pub mod id;
pub mod kbucket;
#[cfg(test)]
mod net_test;
pub mod node;
pub mod observe;
pub mod room;
pub mod runtime;

pub use advertise::{sign_advertise, verify_advertise};
pub use id::{NodeId, NodeIdentity};
pub use kbucket::RoutingTable;
pub use node::{DhtNode, PongInfo, RelayPolicy, RpcError};
pub use observe::{
    try_answer_stun, ObserverPolicy, ObserverServer, OBSERVER_RATE_LIMIT, OBSERVER_RATE_WINDOW,
};
pub use room::{room_key, sign_room, succession_line, verify_room, Lease, RoomRecord};
pub use runtime::{RoomError, RoomRuntime};