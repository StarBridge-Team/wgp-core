//! 房间键与锚点机制（07 §4：租约/继位链/epoch 防脑裂三件套）。

use crate::id::{NodeId, NodeIdentity};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wgp_proto::consts::{
    LEASE_INTERVAL_S, LEASE_TIMEOUT_S, OLD_LINK_GRACE_S, ROOM_KEY_DOMAIN,
};
use wgp_proto::dht::STORE_VALUE_MAX;

/// 房间成员上限（审计 M5）。
///
/// 记录要整块塞进一次 STORE（值上限 [`STORE_VALUE_MAX`] = 1024B）：
/// `64B 签名 + 50B 记录头 + N×64B 成员 + 1B pow 长度 + pow`。
/// N=12 时固定部分是 `64 + 50 + 12×64 + 1 = 883B`，留给 PoW 凭证 141B——够用且不越界。
///
/// 定这个上限的真正目的不是「够不够用」，而是**让越界显式失败**：旧实现在
/// `encode()` 里写 `members.len() as u8`（超过 255 会静默回绕），超长记录又会被
/// `StoreBody::encode` 静默截断到 1024B——两种都是「签名看着有效、成员表其实已被改」
/// 的静默数据损坏。现在编码走 [`RoomRecord::try_encode`]，越界返回 `None`，
/// 锚点侧直接报 [`RoomError::RoomFull`]，绝不落一份坏记录。
pub const MAX_ROOM_MEMBERS: usize = 12;

/// 房间记录（含签名）能安全编码出的最大字节数
pub const ROOM_RECORD_MAX: usize = STORE_VALUE_MAX;

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
    /// 租约到期时刻：**锚点进程**单调时钟的毫秒读数。
    /// 不同进程的单调时基互不可比，成员不能拿它和自己的时钟比大小——对成员而言它只是
    /// 一个「每次续期都会变」的值，掉线判定见 [`LeaseWatch`]。
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

    /// 租约是否已过期。`now_ms` 必须与写入 `expires_at_ms` 的是同一个时基（即锚点自己，
    /// 或共用注入时钟的测试）；跨进程的成员侧判定不要用它，用 [`LeaseWatch`]。
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    pub fn interval_s(&self) -> u64 {
        LEASE_INTERVAL_S
    }
}

/// 成员侧的租约观测器。
///
/// 租约里的到期时刻是锚点进程单调时钟的读数（内核禁读系统时钟，H5），而不同进程的单调时基
/// 互不可比：成员进程比锚点老，会把健康的租约判成早已过期；比锚点新，则锚点死了很久都判不出来。
/// 成员能可靠观测的只有一件事——**租约在本地时钟下已经多久没变过**。锚点每 LEASE_INTERVAL_S
/// 续期一次（到期时刻随之改变），超过 LEASE_TIMEOUT_S 没变即视为掉线。
#[derive(Debug, Default)]
pub struct LeaseWatch {
    /// (最近一次看到的租约, 本地首次看到它的时刻)
    last: Option<(Lease, u64)>,
}

impl LeaseWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入刚读到的租约，返回它在本地已保持不变的毫秒数（首次看到或刚发生变化时为 0）。
    /// `now_ms` 取本地单调时钟。
    pub fn observe(&mut self, lease: &Lease, now_ms: u64) -> u64 {
        match &self.last {
            Some((seen, since)) if seen == lease => now_ms.saturating_sub(*since),
            _ => {
                self.last = Some((lease.clone(), now_ms));
                0
            }
        }
    }

    /// 不变时长是否已达掉线判定阈值
    pub fn is_stale(unchanged_ms: u64) -> bool {
        unchanged_ms >= LEASE_TIMEOUT_S * 1000
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
    /// 成员数是否已到上限（锚点侧据此显式拒绝新成员）
    pub fn is_full(&self) -> bool {
        self.members.len() >= MAX_ROOM_MEMBERS
    }

    /// 结构化记录编码。**成员表越界或总长超 STORE 值上限时返回 `None`**——绝不静默截断。
    pub fn try_encode(&self) -> Option<Vec<u8>> {
        if self.members.len() > MAX_ROOM_MEMBERS {
            return None;
        }
        let mut out = Vec::with_capacity(64 + self.members.len() * 64);
        out.push(0x01); // version
        out.extend_from_slice(&self.lease.epoch.to_be_bytes());
        out.extend_from_slice(&self.lease.anchor.0);
        out.extend_from_slice(&self.lease.expires_at_ms.to_be_bytes());
        out.push(self.members.len() as u8); // <= MAX_ROOM_MEMBERS，不会回绕
        for (id, pk) in &self.members {
            out.extend_from_slice(&id.0);
            if pk.len() != 32 {
                // 防御：非 32B 公钥用零补齐（成员表本身已由签名与身份绑定校验守住）
                let mut padded = [0u8; 32];
                let n = pk.len().min(32);
                padded[..n].copy_from_slice(&pk[..n]);
                out.extend_from_slice(&padded);
                continue;
            }
            out.extend_from_slice(pk);
        }
        match &self.pow {
            Some(p) => {
                if p.len() > u8::MAX as usize {
                    return None;
                }
                out.push(p.len() as u8);
                out.extend_from_slice(p);
            }
            None => out.push(0),
        }
        // 整块（签名 + 记录）必须落在 STORE 值上限内，否则会被 StoreBody 截断
        if out.len() + 64 > ROOM_RECORD_MAX {
            return None;
        }
        Some(out)
    }

    /// 同 [`Self::try_encode`]，越界视为程序错误（只用于已校验容量的内部路径与测试）
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode()
            .expect("房间记录超出容量上限：调用方必须先检查 try_encode")
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
        if count > MAX_ROOM_MEMBERS {
            return None; // 超出本实现的容量上限：既不接受也不转述
        }
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

/// 签名房间记录（锚点以长期身份签名；DHT 存储值 = signature(64) || record_bytes）。
///
/// 记录超出容量上限（成员过多 / PoW 凭证过长）时返回 `None`——签名一份会被 STORE 截断的
/// 记录等于自欺：读回来验签必然失败，别人看到的是「房间坏了」。调用方应把 `None` 转成
/// 明确的错误（见 `RoomError::RoomFull` / `RoomError::RecordTooLarge`）。
pub fn sign_room(identity: &NodeIdentity, record: &RoomRecord) -> Option<Vec<u8>> {
    let body = record.try_encode()?;
    let sig = identity.sign(&body);
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&body);
    Some(out)
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
    fn lease_watch_measures_local_silence_not_remote_clock() {
        let timeout = LEASE_TIMEOUT_S * 1000;
        let mut watch = LeaseWatch::new();

        // 锚点进程刚启动：它写下的到期时刻很小；成员进程已运行一小时（本地时钟 3_600_000）。
        // 拿两者直接比大小会得出「早已过期」，观测器只看本地流逝：刚看到 = 0
        let young_anchor = Lease::new(0, anchor(1), 5_000);
        assert!(young_anchor.expired(3_600_000), "跨时基直接比较的确会误判——所以不能用");
        assert_eq!(watch.observe(&young_anchor, 3_600_000), 0);
        assert_eq!(watch.observe(&young_anchor, 3_600_000 + 40_000), 40_000);
        assert!(!LeaseWatch::is_stale(40_000));

        // 锚点续期（到期时刻变了）：计时归零
        let mut renewed = young_anchor.clone();
        renewed.renew(35_000);
        assert_eq!(watch.observe(&renewed, 3_600_000 + 41_000), 0);

        // 此后锚点沉默：本地满 LEASE_TIMEOUT_S 才判掉线
        let silent_for = watch.observe(&renewed, 3_600_000 + 41_000 + timeout - 1);
        assert!(!LeaseWatch::is_stale(silent_for));
        let silent_for = watch.observe(&renewed, 3_600_000 + 41_000 + timeout);
        assert!(LeaseWatch::is_stale(silent_for));

        // 反方向：锚点进程很老（到期时刻极大），成员很新——同样只看本地沉默时长
        let mut watch = LeaseWatch::new();
        let old_anchor = Lease::new(3, anchor(2), 86_400_000);
        assert!(!old_anchor.expired(timeout * 10), "直接比较则永远判不出掉线");
        assert_eq!(watch.observe(&old_anchor, 1_000), 0);
        assert!(LeaseWatch::is_stale(watch.observe(&old_anchor, 1_000 + timeout)));

        // 换锚点（epoch+1）也是变化
        let taken_over = Lease::new(4, anchor(3), 0);
        assert_eq!(watch.observe(&taken_over, 1_000 + timeout + 5), 0);
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

    fn full_record() -> RoomRecord {
        RoomRecord {
            members: (0..MAX_ROOM_MEMBERS)
                .map(|i| (anchor(i as u8), vec![1u8; 32]))
                .collect(),
            lease: Lease::new(1, anchor(0), 0),
            pow: None,
        }
    }

    /// 审计 M5：记录编码绝不静默截断（成员数回绕 / 整块超 STORE 值上限）
    #[test]
    fn record_encoding_refuses_to_truncate() {
        // 上限内：成员数如实写出，解码回得来
        let rec = full_record();
        let body = rec.try_encode().expect("上限内应可编码");
        assert_eq!(body.len(), 50 + MAX_ROOM_MEMBERS * 64 + 1);
        assert_eq!(body[49] as usize, MAX_ROOM_MEMBERS, "成员数必须如实写出");
        assert_eq!(RoomRecord::decode(&body).unwrap().members.len(), MAX_ROOM_MEMBERS);
        // 含 64B 签名在内必须落在一次 STORE 的值上限里
        assert!(body.len() + 64 <= ROOM_RECORD_MAX);

        // 多一个成员：显式 None（旧实现会把 13 写进 1 字节……超过 255 时静默回绕）
        let mut over = rec.clone();
        over.members.push((anchor(99), vec![2u8; 32]));
        assert!(over.is_full(), "13 个成员已满");
        assert!(over.try_encode().is_none(), "超出成员上限必须显式失败");
        assert!(sign_room(&NodeIdentity::generate(&mut rand_core::OsRng), &over).is_none());

        // PoW 凭证长度超过 u8 能表达的范围：显式 None
        let mut big_pow = rec.clone();
        big_pow.pow = Some(vec![0u8; 256]);
        assert!(big_pow.try_encode().is_none(), "PoW 凭证过长必须显式失败");

        // 解码侧同样守住上限：把 count 改大 → 拒绝
        let mut tampered = body.clone();
        tampered[49] = (MAX_ROOM_MEMBERS + 1) as u8;
        assert!(RoomRecord::decode(&tampered).is_none());
    }
}