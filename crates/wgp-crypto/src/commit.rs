//! 承诺-揭示（01 §1.2.2）：让不可信转发者无法替换公钥而不被发现。

use sha2::{Digest, Sha256};

/// SHA-256 承诺值
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);

/// 计算承诺：SHA256(pubkey || nonce)
pub fn commit(pubkey: &[u8], nonce: &[u8; 32]) -> Commitment {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.update(nonce);
    Commitment(h.finalize().into())
}

/// 验证揭示；不匹配 = MITM 检测 → 调用方断连 + 黑名单（01 §1.2.2 表）
pub fn verify(c: &Commitment, pubkey: &[u8], nonce: &[u8; 32]) -> bool {
    let expect = commit(pubkey, nonce);
    expect.0 == c.0
}

/// 双方承诺相同（碰撞，概率 2^-256）→ 重生成 nonce 重试（最多 1 次）
pub fn is_collision(a: &Commitment, b: &Commitment) -> bool {
    a.0 == b.0
}