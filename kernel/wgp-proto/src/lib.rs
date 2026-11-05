//! 折跃门协议层：纯数据 crate。
//! 纪律（00 §3）：无 IO、无 async、零依赖；所有包格式与常量以此为准。

pub mod consts;
pub mod dht;
pub mod endpoint;
pub mod packet;
pub mod punycode;
pub mod room_code;
pub mod sig;
pub mod stun;

pub use endpoint::{ParseError, SeedEndpoint, SeedScheme};
pub use room_code::derive_room_code;