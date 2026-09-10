//! 协议常量（00 §1 H 约束、15 全链路流程的数字化）

/// 协议版本（每包头部携带，未来线与能力协商依据；00 §11 版本化纪律）
pub const PROTO_VERSION: u8 = 0x01;

/// 探针/心跳魔数前缀（会话级魔数由 session_key 派生，见 wgp-crypto）
pub const MAGIC_PREFIX: &[u8; 3] = b"wgp";

// —— 端口（07 §6 wgp-node 部署规格） ——
pub const DHT_PORT: u16 = 3841;
pub const STUN_PORT: u16 = 3478;

// —— 打洞预算（H6，00 §1） ——
pub const PROBE_BUDGET_PER_ROUND: u16 = 47;
pub const PROBE_BUDGET_PER_10MIN: u16 = 500;

// —— 三波探测（03 §3.5） ——
pub const WAVE1_PACKETS: u16 = 21;
pub const WAVE2_PACKETS: u16 = 15;
pub const WAVE3_PACKETS: u16 = 11;
pub const WAVE_TIMEOUT_MS: u64 = 800;

// —— 超时约定（15 全链路） ——
pub const COMMIT_TIMEOUT_S: u64 = 3;
pub const QUIC_HANDSHAKE_TIMEOUT_S: u64 = 3;
pub const DEGRADED_UDP_PROBE_S: u64 = 30;
pub const OLD_LINK_GRACE_S: u64 = 30;

// —— 房间/锚点（07 §4） ——
pub const LEASE_INTERVAL_S: u64 = 30;
pub const LEASE_TIMEOUT_S: u64 = 75;
pub const ROOM_KEY_DOMAIN: &[u8] = b"wgp/room/v1";