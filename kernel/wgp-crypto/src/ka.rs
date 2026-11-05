//! KeyAgreement：密钥协商可插拔（14 §4，00 D6/D9）。
//! 现役实现 X25519；Hybrid(PQ) 预留算法位 0x02，随 rustls 生态随时接入，
//! 调用方（承诺-揭示/会话密钥派生）无感。

use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// 密钥协商原语。任何实现的成果（共享密钥）语义一致：双方推导相同字节。
/// 约定：PrivKey 为一次性临时密钥（每次协商全新生成）；
/// drop 时清零由后端自保证（x25519-dalek 内部使用 `Zeroizing`，PQ 后端亦须同语义）。
pub trait KeyAgreement: Send + Sync {
    type PrivKey;

    /// 生成临时私钥
    fn keygen(&self, rng: &mut impl CryptoRngCore) -> Self::PrivKey;
    /// 导出公钥字节（承诺-揭示的承诺输入）
    fn pubkey_raw(&self, sk: &Self::PrivKey) -> Vec<u8>;
    /// 计算共享密钥；失败（长度非法/低熵全零）返回 None
    fn agree(&self, sk: &Self::PrivKey, peer_pk: &[u8]) -> Option<Vec<u8>>;
    /// 算法标识（承诺/揭示包的 algo_tag；协议版本协商依据）
    fn algo_id(&self) -> u8;
}

/// 现役：X25519（algo_id = 0x01）
pub struct X25519Agreement;

impl KeyAgreement for X25519Agreement {
    type PrivKey = StaticSecret;

    fn keygen(&self, rng: &mut impl CryptoRngCore) -> Self::PrivKey {
        StaticSecret::random_from_rng(rng)
    }

    fn pubkey_raw(&self, sk: &Self::PrivKey) -> Vec<u8> {
        PublicKey::from(sk).as_bytes().to_vec()
    }

    fn agree(&self, sk: &Self::PrivKey, peer_pk: &[u8]) -> Option<Vec<u8>> {
        if peer_pk.len() != 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(peer_pk);
        let pk = PublicKey::from(buf);
        let shared = sk.diffie_hellman(&pk);
        // 01 §1.2.4：全零共享密钥立即终止（不自动重协商，避免死循环）
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return None;
        }
        Some(shared.as_bytes().to_vec())
    }

    fn algo_id(&self) -> u8 {
        0x01
    }
}

/// 未来线：Hybrid PQ（X25519 + ML-KEM-768，algo_id = 0x02）。
/// 未实现——接入点：实现 KeyAgreement 并在承诺-揭示中带 algo_tag=0x02，
/// 同时挂接 rustls 的 X25519MLKEM768（rustls ≥0.23 默认支持）。
pub struct HybridPqAgreement;

/// 协商器工厂（enum 形态替代 dyn，保持零成本抽象；PQ 接入时在此增臂）。
/// 未知算法标识 → None（协议版本协商失败路径：断连而非降级）。
pub enum AnyAgreement {
    X25519(X25519Agreement),
    // 未来：Hybrid(HybridPqAgreement),
}

impl AnyAgreement {
    pub fn for_algo(algo_id: u8) -> Option<Self> {
        match algo_id {
            0x01 => Some(Self::X25519(X25519Agreement)),
            _ => None,
        }
    }

    pub fn algo_id(&self) -> u8 {
        match self {
            Self::X25519(_) => 0x01,
        }
    }
}