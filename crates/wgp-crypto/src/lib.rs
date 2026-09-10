//! 折跃门密码层（01 文档的代码化 + 14 §4 的 PQ 可插拔 API）。
//! 纪律：无 IO、无 async；密钥材料全生命周期 zeroize。

pub mod commit;
pub mod derive;
pub mod escape;
pub mod ka;
#[cfg(test)]
mod handshake_test;

use zeroize::Zeroize;

/// 一次性秘密容器：取出即销毁（14 §10 条款 3）
pub struct SecretBox(pub [u8; 32]);

impl SecretBox {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    /// 一次性取出；此后本容器归零
    pub fn take(&mut self) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        if self.0.iter().all(|&b| b == 0) {
            return None;
        }
        out.copy_from_slice(&self.0);
        self.0.zeroize();
        Some(out)
    }
}

impl Drop for SecretBox {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 当前密码学档位（00 D6：现役 X25519；PQ 为可选，留 API 不实现）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoProfile {
    X25519Aes128Gcm,
    HybridPqMlKem768,
}