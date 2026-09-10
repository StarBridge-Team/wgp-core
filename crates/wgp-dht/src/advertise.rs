//! 种子广告的真实签名/验证（07 §5 第③层：DHT 内交换种子，
//! 发送方长期 ed25519 身份签名；篡改即无效）。

use crate::id::NodeIdentity;
use ed25519_dalek::Signature;
use wgp_proto::packet::{seed_advertise, SeedAdvertise};

/// 用节点身份对种子广告载荷签名，产出完整 90B 报文
pub fn sign_advertise(
    id: &NodeIdentity,
    addr_v4: [u8; 4],
    dht_port: u16,
    stun_port: u16,
    priority: u8,
    flags: u8,
) -> [u8; seed_advertise::LEN] {
    let payload = seed_advertise::payload_for_sign(addr_v4, dht_port, stun_port, priority, flags);
    let sig: Signature = id.sign(&payload);
    let mut out = [0u8; seed_advertise::LEN];
    seed_advertise::encode_signed(
        addr_v4,
        dht_port,
        stun_port,
        priority,
        flags,
        sig.to_bytes(),
        &mut out,
    );
    out
}

/// 验证入站种子广告：提取载荷 + 用广告内公钥验签。
pub fn verify_advertise(id: &NodeIdentity, buf: &[u8]) -> Option<SeedAdvertise> {
    let adv = seed_advertise::extract(buf)?;
    let payload = seed_advertise::signed_payload(buf)?;
    let sig = Signature::from_bytes(&adv.signature);
    if id.verify(payload, &sig) {
        Some(adv)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::node_id_from_verifying;
    use rand_core::OsRng;

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = OsRng;
        let a = NodeIdentity::generate(&mut rng);
        let bytes = sign_advertise(&a, [203, 0, 113, 1], 3841, 3478, 5, 1);
        assert_eq!(bytes.len(), seed_advertise::LEN);

        let adv = verify_advertise(&a, &bytes).expect("签名应通过");
        assert_eq!(adv.dht_port, 3841);
        assert_eq!(adv.stun_port, 3478);
        assert_eq!(adv.priority, 5);
        assert_eq!(adv.flags, 1);
    }

    #[test]
    fn tampered_advertise_rejected() {
        let mut rng = OsRng;
        let a = NodeIdentity::generate(&mut rng);
        let mut bytes = sign_advertise(&a, [203, 0, 113, 1], 3841, 3478, 5, 1);
        // 篡改端口字段（签名载荷内）→ 验签失败
        bytes[9] ^= 0x01;
        assert!(verify_advertise(&a, &bytes).is_none());
    }

    #[test]
    fn wrong_signer_rejected() {
        let mut rng = OsRng;
        let a = NodeIdentity::generate(&mut rng);
        let b = NodeIdentity::generate(&mut rng);
        let bytes = sign_advertise(&a, [203, 0, 113, 1], 3841, 3478, 5, 1);
        // 用错误身份验签 → 拒绝（防谎报种子）
        assert!(verify_advertise(&b, &bytes).is_none());
    }

    #[test]
    fn node_id_stable_derivation() {
        let mut rng = OsRng;
        let a = NodeIdentity::generate(&mut rng);
        let id1 = node_id_from_verifying(&a.verifying_key());
        let id2 = a.node_id();
        assert_eq!(id1, id2);
    }
}