//! 协议常量（00 §1 H 约束、15 全链路流程的数字化）

/// 协议版本（每包头部携带，未来线与能力协商依据；00 §11 版本化纪律）
pub const PROTO_VERSION: u8 = 0x01;

/// 探针/心跳魔数前缀（会话级魔数由 session_key 派生，见 wgp-crypto）
pub const MAGIC_PREFIX: &[u8; 3] = b"wgp";

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

// —— 种子发现（07 §5 第③层 / 17 P0） ——
/// 种子广告 V2 的签名域分隔前缀（同一把身份密钥还要签房间记录与报道请求，前缀防跨用途挪用）
pub const SEED_ADV_DOMAIN: &[u8] = b"wgp/seed-adv/v2";

// —— 探活身份证明（17 §11） ——
/// 挑战响应证明的签名域分隔前缀。长度是线格式的一部分（见 [`AUTH_SIGNING_MESSAGE_LEN`]）：
/// 改字符串等于换协议，必须同时换类型号或提 version。
pub const AUTH_DOMAIN: &[u8] = b"wgp/dht-auth/v1";
/// 身份证明协议的当前版本（写在 AUTH_CHALLENGE / AUTH_PROOF 的 version 字节，且被签名覆盖）
pub const AUTH_VERSION: u8 = 1;
/// 一次性挑战 / 证明方自选 nonce 的长度
pub const AUTH_NONCE_LEN: usize = 16;