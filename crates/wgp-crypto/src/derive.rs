//! 会话密钥族派生（01 §1.2.3 HKDF + 02 心跳合并 + 探针签名）。
//! 一次展开产出全会话密钥：session / PSK / 探针 HMAC / 心跳 / 逃生。

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 固定且公开的盐（01 §1.2.3）
pub const SALT_DOMAIN: &[u8] = b"zheyuemen/v1/ecdh-salt";

/// 全会话密钥族（14 §2/§4 对应字段的来源）
pub struct SessionSecrets {
    /// TLS-PSK 主密钥（QUIC/TCP 路径注入，方案 a）
    pub session_key: [u8; 32],
    /// PSK identity 派生种子（两端推导一致）
    pub psk_identity: [u8; 16],
    /// 探针 HMAC 密钥（打洞验证前防伪造）
    pub probe_key: [u8; 32],
    /// 心跳 HMAC 密钥（03 §3.7.4）
    pub hb_key: [u8; 32],
    /// 逃生通道 AES-GCM 密钥（ICMP 单向，01 §1.3 修订后仅此用途）
    pub escape_key: [u8; 32],
}

/// 由 ECDH 共享密钥一次性派生全会话密钥族。
/// `info_ctx` 应包含：双方公钥、nonce_A/B、ServerTime、协议域名（01 §1.2.3）。
pub fn derive_all(shared: &[u8; 32], info_ctx: &[u8]) -> SessionSecrets {
    let hk = Hkdf::<Sha256>::new(Some(SALT_DOMAIN), shared);
    let mut okm = [0u8; 144];
    hk.expand(info_ctx, &mut okm)
        .expect("HKDF-SHA256 输出 144B 合法");

    let mut session_key = [0u8; 32];
    let mut psk_identity = [0u8; 16];
    let mut probe_key = [0u8; 32];
    let mut hb_key = [0u8; 32];
    let mut escape_key = [0u8; 32];
    session_key.copy_from_slice(&okm[0..32]);
    psk_identity.copy_from_slice(&okm[32..48]);
    probe_key.copy_from_slice(&okm[48..80]);
    hb_key.copy_from_slice(&okm[80..112]);
    escape_key.copy_from_slice(&okm[112..144]);

    SessionSecrets {
        session_key,
        psk_identity,
        probe_key,
        hb_key,
        escape_key,
    }
}

/// 探针 HMAC 截断 12B（03 §3.5.5 AuthTag）；失败返回全零 → 调用方静默丢弃
pub fn probe_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    truncated_hmac(key, data)
}

/// 心跳 HMAC 截断 12B（03 §3.7.4）
pub fn hb_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    truncated_hmac(key, data)
}

/// 逃生帧 HMAC 截断 12B（00 §4 ICMP 逃生档）
pub fn escape_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    truncated_hmac(key, data)
}

/// LAN 组播 beacon HMAC 截断 12B（00 §4 局域网快速路径）
pub fn lan_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    truncated_hmac(key, data)
}

fn truncated_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 密钥长度合法");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}