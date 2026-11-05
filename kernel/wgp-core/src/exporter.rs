//! KeyExporter（14 §4）：TLS-PSK 一次取出 + PQ 可选 API 落点。

use crate::PeerId;
use wgp_crypto::{CryptoProfile, SecretBox};

/// PSK 束（quinn/rustls 各自经适配器注入）
pub struct PskBundle {
    /// identity：room 扰动 + Peer 对序 + epoch，两端推导一致（0-RTT 查表键）
    pub identity: Vec<u8>,
    /// 32B TLS-PSK 密钥（一次性取出）
    pub key: SecretBox,
    /// 0-RTT early-data 上限
    pub max_early_data: u32,
}

/// 密钥导出（14 §4；PQ 可选入口：crypto_profile 恒可查询）
pub trait KeyExporter: Send + Sync {
    /// 一次性取出 PSK；再次调用返回 None（14 §10 条款 3）
    fn take_tls_psk(&self, peer: PeerId) -> Option<PskBundle>;
    /// 当前密码学档位（D6；PQ 开启后返回 HybridPqMlKem768）
    fn crypto_profile(&self) -> CryptoProfile;
}