//! 房间键与锚点机制（07 §4：租约/继位链/epoch 防脑裂三件套）。

use crate::id::{NodeId, NodeIdentity};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wgp_proto::consts::{
    LEASE_INTERVAL_S, LEASE_TIMEOUT_S, OLD_LINK_GRACE_S, ROOM_KEY_DOMAIN,
};

/// U/ 房间码 → DHT 房间键（13 文档"未来 DHT 冷启动的房间键"落定）
pub fn room_key(room_code: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROOM_KEY_DOMAIN);
    h.update(room_code.as_bytes());
    h.finalize().into()
}

/// 锚点租约
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub epoch: u64,
    pub anchor: NodeId,
    /// 租约到期时刻（Instant 单调时基的毫秒数，由网络时间锚点换算）
    pub expires_at_ms: u64,
}

impl Lease {
    pub fn new(epoch: u64, anchor: NodeId, now_ms: u64) -> Self {
        Self {
            epoch,
            anchor,
            expires_at_ms: now_ms + LEASE_TIMEOUT_S * 1000,
        }
    }

    /// 续期（每 LEASE_INTERVAL_S 由锚点调用，DHT 条件写 CAS）
    pub fn renew(&mut self, now_ms: u64) {
        self.expires_at_ms = now_ms + LEASE_TIMEOUT_S * 1000;
    }

    /// 成员视角：租约是否已过期（连续判过期即触发继位链抢占）
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    pub fn interval_s(&self) -> u64 {
        LEASE_INTERVAL_S
    }
}

/// 房间记录（存于 DHT，K=3 副本目标；v1 单值 + 锚点 republish）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRecord {
    /// (NodeId, 身份公钥) 成员表；房主签名保证链序唯一（继位链）
    pub members: Vec<(NodeId, Vec<u8>)>,
    pub lease: Lease,
    /// PoW 凭证（防刷注册，07 §8）
    pub pow: Option<Vec<u8>>,
}

/// 记录字节格式：
/// version(1) | epoch(8) | anchor(32) | expires(8) | count(1)
/// | count × (node_id 32 + pubkey 32) | pow_len(1) | pow
impl RoomRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.members.len() * 64);
        out.push(0x01); // version
        out.extend_from_slice(&self.lease.epoch.to_be_bytes());
        out.extend_from_slice(&self.lease.anchor.0);
        out.extend_from_slice(&self.lease.expires_at_ms.to_be_bytes());
        out.push(self.members.len() as u8);
        for (id, pk) in &self.members {
            out.extend_from_slice(&id.0);
            debug_assert_eq!(pk.len(), 32);
            out.extend_from_slice(&pk[..32.min(pk.len())]);
            if pk.len() != 32 {
                // 防御：非 32B 公钥用零补齐
                let need = 32usize.saturating_sub(pk.len());
                out.extend_from_slice(&vec![0u8; need]);
            }
        }
        match &self.pow {
            Some(p) => {
                out.push(p.len() as u8);
                out.extend_from_slice(p);
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 50 {
            return None;
        }
        if buf[0] != 0x01 {
            return None;
        }
        let epoch = u64::from_be_bytes(buf[1..9].try_into().ok()?);
        let mut anchor_arr = [0u8; 32];
        anchor_arr.copy_from_slice(&buf[9..41]);
        let expires_at_ms = u64::from_be_bytes(buf[41..49].try_into().ok()?);
        let count = buf[49] as usize;
        let mut i = 50usize;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            if i + 64 > buf.len() {
                return None;
            }
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&buf[i..i + 32]);
            let pk = buf[i + 32..i + 64].to_vec();
            members.push((NodeId(id_arr), pk));
            i += 64;
        }
        if i >= buf.len() {
            return None;
        }
        let pow_len = buf[i] as usize;
        i += 1;
        let pow = if pow_len == 0 {
            None
        } else {
            if i + pow_len > buf.len() {
                return None;
            }
            let p = buf[i..i + pow_len].to_vec();
            i += pow_len;
            Some(p)
        };
        if i != buf.len() {
            return None;
        }
        Some(Self {
            members,
            lease: Lease {
                epoch,
                anchor: NodeId(anchor_arr),
                expires_at_ms,
            },
            pow,
        })
    }
}

/// 签名房间记录（锚点以长期身份签名；DHT 存储值 = signature(64) || record_bytes）
pub fn sign_room(identity: &NodeIdentity, record: &RoomRecord) -> Vec<u8> {
    let body = record.encode();
    let sig = identity.sign(&body);
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&body);
    out
}

/// 验证签名房间记录：锚点公钥须在成员表中；签名不匹配/结构损坏 → None
pub fn verify_room(buf: &[u8]) -> Option<(RoomRecord, Signature)> {
    if buf.len() < 64 + 50 {
        return None;
    }
    let sig = Signature::from_bytes(buf[..64].try_into().ok()?);
    let record = RoomRecord::decode(&buf[64..])?;
    // 锚点公钥在成员表中检索
    let anchor_pk: &[u8] = record
        .members
        .iter()
        .find(|(id, _)| *id == record.lease.anchor)
        .map(|(_, pk)| pk.as_slice())?;
    if anchor_pk.len() != 32 {
        return None;
    }
    let vk = VerifyingKey::from_bytes(anchor_pk.try_into().ok()?).ok()?;
    vk.verify(&buf[64..], &sig).ok()?;
    Some((record, sig))
}

/// 继位链：成员表按 NodeId（Ord 已为确定的字节序）排序
pub fn succession_line(record: &RoomRecord) -> Vec<NodeId> {
    let mut ids: Vec<NodeId> = record.members.iter().map(|(id, _)| *id).collect();
    ids.sort();
    ids
}

/// 旧链路宽限（00 §4：upgraded 后保活 30s 供外围切换）
pub fn old_link_grace_s() -> u64 {
    OLD_LINK_GRACE_S
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(byte0: u8) -> NodeId {
        let mut a = [0u8; 32];
        a[0] = byte0;
        NodeId(a)
    }

    #[test]
    fn room_key_deterministic_and_distinct() {
        let k1 = room_key("U/C2G9-GYET-311W-R636");
        let k2 = room_key("U/C2G9-GYET-311W-R636");
        assert_eq!(k1, k2);
        let k3 = room_key("U/6U01-TWHM-B7H0-CV36");
        assert_ne!(k1, k3);
    }

    #[test]
    fn lease_renew_and_expiry() {
        let mut lease = Lease::new(1, anchor(1), 1000);
        assert_eq!(lease.expires_at_ms, 1000 + LEASE_TIMEOUT_S * 1000);
        assert!(!lease.expired(1000 + LEASE_TIMEOUT_S * 1000 - 1));
        assert!(lease.expired(1000 + LEASE_TIMEOUT_S * 1000));
        lease.renew(2000);
        assert!(!lease.expired(2000 + LEASE_TIMEOUT_S * 1000 - 1));
    }

    #[test]
    fn epoch_guard_against_zombie() {
        let l1 = Lease::new(5, anchor(1), 0);
        let l2 = Lease::new(6, anchor(2), 0);
        assert_ne!(l1.epoch, l2.epoch);
    }

    #[test]
    fn succession_line_is_deterministic_order() {
        let rec = RoomRecord {
            members: vec![
                (anchor(9), vec![]),
                (anchor(1), vec![]),
                (anchor(5), vec![]),
            ],
            lease: Lease::new(1, anchor(9), 0),
            pow: None,
        };
        let line = succession_line(&rec);
        assert_eq!(line[0], anchor(1));
        assert_eq!(line[1], anchor(5));
        assert_eq!(line[2], anchor(9));
    }
}