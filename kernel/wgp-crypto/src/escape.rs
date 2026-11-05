//! 逃生通道加密（01 §1.3 修订：AES-256-GCM 帧仅用于 ICMP 逃生链路）。
//! QUIC/TCP 主链路不走本节（TLS-PSK 承担）；此处密钥来自 SessionSecrets::escape_key。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

/// 逃生帧编解码器（每个 Peer 对一份，密钥由 escape_key 提供）
pub struct EscapeCodec {
    cipher: Aes256Gcm,
}

impl EscapeCodec {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)),
        }
    }

    /// 加密（密文含 16B GCM Tag）
    pub fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Option<Vec<u8>> {
        self.cipher
            .encrypt(Nonce::from_slice(nonce), plain)
            .ok()
    }

    /// 解密验证；任何失败（篡改/非本密钥/重放位的上层检测）返回 None → 静默丢弃
    pub fn open(&self, nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), sealed)
            .ok()
    }
}