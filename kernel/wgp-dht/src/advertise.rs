//! 种子广告的真实签名/验证（07 §5 第③层：DHT 内交换种子，
//! 发送方长期 ed25519 身份签名；篡改即无效）。

use crate::id::{node_id_from_verifying, NodeId, NodeIdentity};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use wgp_proto::packet::{seed_advertise, seed_advertise_v2, SeedAdvertise, SeedAdvertiseV2};

/// 用节点身份对种子广告载荷签名，产出完整 91B 报文
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

/// 验证入站种子广告：提取载荷 + 用**广告主公钥**验签。
///
/// SeedAdvertise 报文不携带公钥（91B 定长装不下 32B 密钥），因此验证方必须
/// 从可信信道取得广告主的 VerifyingKey——即身份绑定校验（node_id=SHA256(pubkey)）
/// 通过的 PING/PONG 对端公钥。用本地身份验他人广告是必然失败的（历史缺陷已修）。
pub fn verify_advertise(advertiser: &VerifyingKey, buf: &[u8]) -> Option<SeedAdvertise> {
    let adv = seed_advertise::extract(buf)?;
    let payload = seed_advertise::signed_payload(buf)?;
    let sig = Signature::from_bytes(&adv.signature);
    advertiser.verify(payload, &sig).ok()?;
    Some(adv)
}

// —— V2（17 §5）：报文自带公钥，转述后仍可独立验签 ——————————————————————————

/// 本节点对外宣告的内容（签名之前）。地址与端口由部署层给出——内核不猜测自己的公网地址。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvertiseSpec {
    pub addr_v4: [u8; 4],
    pub dht_port: u16,
    /// 观察者（STUN）端口；0 = 不提供
    pub stun_port: u16,
    /// TCP 信令端口；0 = 不提供
    pub tcp_port: u16,
    /// 自称优先级。P0 仅透传、不参与任何选择：自称的东西不可信，等 17 P1 的信任评分接手
    pub priority: u8,
    /// 见 `seed_advertise_v2::FLAG_*`
    pub flags: u8,
    /// SHA256(名字) 前 4B；未命名全 0（17 P2 名字锚定用）
    pub name_hash: [u8; 4],
}

/// 签发种子广告 V2（123B）。`epoch` 对同一身份必须只增不减（接收端只认更大的）。
pub fn sign_advertise_v2(
    id: &NodeIdentity,
    spec: &AdvertiseSpec,
    epoch: u64,
) -> [u8; seed_advertise_v2::LEN] {
    let unsigned = SeedAdvertiseV2 {
        addr_v4: spec.addr_v4,
        dht_port: spec.dht_port,
        stun_port: spec.stun_port,
        tcp_port: spec.tcp_port,
        priority: spec.priority,
        flags: spec.flags,
        epoch,
        name_hash: spec.name_hash,
        pubkey: id.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    let mut out = [0u8; seed_advertise_v2::LEN];
    seed_advertise_v2::encode(&unsigned, &mut out);
    let sig = id.sign(&seed_advertise_v2::signing_message(&out));
    out[seed_advertise_v2::SIGNED_LEN..].copy_from_slice(&sig.to_bytes());
    out
}

/// 验证种子广告 V2：结构 → 公钥合法 → 签名（严格模式：拒绝弱公钥与非规范签名）。
/// 通过后返回广告内容与广告主的 NodeId（= SHA256(公钥)）。
///
/// 验签只证明「持有该私钥的人说过这句话」，不证明地址属实、更不证明可信——入表前还要在所报
/// 地址上探活（node.rs），信任评分是 17 P1 的事。
pub fn verify_advertise_v2(buf: &[u8]) -> Option<(SeedAdvertiseV2, NodeId)> {
    let adv = seed_advertise_v2::decode(buf)?;
    let advertiser = VerifyingKey::from_bytes(&adv.pubkey).ok()?;
    let mut packet = [0u8; seed_advertise_v2::LEN];
    packet.copy_from_slice(buf);
    let sig = Signature::from_bytes(&adv.signature);
    advertiser
        .verify_strict(&seed_advertise_v2::signing_message(&packet), &sig)
        .ok()?;
    Some((adv, node_id_from_verifying(&advertiser)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn spec() -> AdvertiseSpec {
        AdvertiseSpec {
            addr_v4: [203, 0, 113, 9],
            dht_port: 11010,
            stun_port: 3478,
            tcp_port: 3481,
            priority: 0,
            flags: seed_advertise_v2::FLAG_RELAY,
            name_hash: [0; 4],
        }
    }

    #[test]
    fn v2_sign_and_verify_without_out_of_band_key() {
        let a = NodeIdentity::generate(&mut OsRng);
        let bytes = sign_advertise_v2(&a, &spec(), 42);
        // 验签方手里只有报文本身
        let (adv, advertiser) = verify_advertise_v2(&bytes).expect("签名应通过");
        assert_eq!(advertiser, a.node_id(), "广告主身份 = SHA256(报文内公钥)");
        assert_eq!(adv.addr_v4, [203, 0, 113, 9]);
        assert_eq!(adv.dht_port, 11010);
        assert_eq!(adv.stun_port, 3478);
        assert_eq!(adv.tcp_port, 3481);
        assert_eq!(adv.epoch, 42);
        assert_eq!(adv.flags, seed_advertise_v2::FLAG_RELAY);
    }

    #[test]
    fn v2_any_tampering_is_rejected() {
        let a = NodeIdentity::generate(&mut OsRng);
        let bytes = sign_advertise_v2(&a, &spec(), 7);
        // 签名覆盖范围内逐字节翻转（地址、端口、epoch、公钥……）与签名本身：全部拒绝
        for offset in 0..seed_advertise_v2::LEN {
            let mut bad = bytes;
            bad[offset] ^= 0x01;
            assert!(
                verify_advertise_v2(&bad).is_none(),
                "偏移 {offset} 被篡改后仍通过验签"
            );
        }
        assert!(verify_advertise_v2(&bytes[..seed_advertise_v2::LEN - 1]).is_none());
    }

    #[test]
    fn v2_pubkey_substitution_is_rejected() {
        // 攻击者拿到 A 的广告，把公钥换成自己的（想把「这个地址」认领到自己名下）→ 签名对不上
        let a = NodeIdentity::generate(&mut OsRng);
        let mallory = NodeIdentity::generate(&mut OsRng);
        let mut bytes = sign_advertise_v2(&a, &spec(), 7);
        bytes[27..59].copy_from_slice(&mallory.verifying_key().to_bytes());
        assert!(verify_advertise_v2(&bytes).is_none());
    }

    #[test]
    fn v2_signature_is_domain_separated() {
        // 同一把密钥对「报文前缀本身」（不带域前缀）的签名不能冒充广告签名
        let a = NodeIdentity::generate(&mut OsRng);
        let mut bytes = sign_advertise_v2(&a, &spec(), 7);
        let raw_sig = a.sign(&bytes[..seed_advertise_v2::SIGNED_LEN]);
        bytes[seed_advertise_v2::SIGNED_LEN..].copy_from_slice(&raw_sig.to_bytes());
        assert!(verify_advertise_v2(&bytes).is_none());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = OsRng;
        let a = NodeIdentity::generate(&mut rng);
        let bytes = sign_advertise(&a, [203, 0, 113, 1], 3841, 3478, 5, 1);
        assert_eq!(bytes.len(), seed_advertise::LEN);

        let adv = verify_advertise(&a.verifying_key(), &bytes).expect("签名应通过");
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
        assert!(verify_advertise(&a.verifying_key(), &bytes).is_none());
    }

    #[test]
    fn wrong_signer_rejected() {
        let mut rng = OsRng;
        let a = NodeIdentity::generate(&mut rng);
        let b = NodeIdentity::generate(&mut rng);
        let bytes = sign_advertise(&a, [203, 0, 113, 1], 3841, 3478, 5, 1);
        // 用错误公钥验签 → 拒绝（防谎报种子）；用正确广告主公钥 → 通过
        assert!(verify_advertise(&b.verifying_key(), &bytes).is_none());
        assert!(verify_advertise(&a.verifying_key(), &bytes).is_some());
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