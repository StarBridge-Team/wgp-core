//! DHT 节点身份（07 §8：ed25519 身份持久化，防日蚀/防冒充）。

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

/// 节点 ID：公钥的 SHA-256（Kademlia 距离度量基）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Kademlia XOR 距离
    pub fn xor_distance(&self, other: &NodeId) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.0[i] ^ other.0[i];
        }
        out
    }
}

pub fn node_id_from_verifying(vk: &VerifyingKey) -> NodeId {
    NodeId(Sha256::digest(vk.as_bytes()).into())
}

/// 节点长期身份（生成一次持久化；PeerId 派生自本公钥哈希）
pub struct NodeIdentity {
    signing: SigningKey,
    node_id: NodeId,
}

impl NodeIdentity {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let signing = SigningKey::generate(rng);
        let node_id = node_id_from_verifying(&signing.verifying_key());
        Self { signing, node_id }
    }

    /// 从持久化种子恢复（32B ed25519 种子；文件读满即用）
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let node_id = node_id_from_verifying(&signing.verifying_key());
        Self { signing, node_id }
    }

    /// 持久化种子导出（写入 node_identity.key；权限 600）
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// 签名（锚点租约续期、成员表、SeedAdvertise 均须签名）
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing.sign(data)
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> bool {
        self.signing.verify(data, sig).is_ok()
    }
}

/// PeerId = 节点公钥哈希截断 16B（对外短标识；防冲突校验在 12 §5）
pub fn peer_id_from_node(node_id: &NodeId) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&node_id.0[..16]);
    out
}