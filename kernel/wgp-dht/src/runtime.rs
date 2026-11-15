//! 房间生命周期运行时（07 §4 三件套的落地：租约、继位链、epoch）。
//! v1 简化语义（在未来版本向标准 Kademlia 键值复制演进）：
//!  - 房间键值存于"存储节点"（创建/加入双方共同 bootstrap 的种子），
//!    锚点负责 republish；成员经 find_value 读取。
//!  - 抢占裁决：候选按继位链序退避出手，写后回读验证（epoch/锚点一致性）。
//!  - 加入报道：JoinRequest 经存储节点 Forward 路由至锚点（存储节点已学习
//!    写入者身份），锚点验签后 add_member 重签重存。

use crate::id::{node_id_from_verifying, NodeId, NodeIdentity};
use crate::node::DhtNode;
use crate::room::{
    room_key, sign_room, succession_line, verify_room, Lease, LeaseWatch, RoomRecord,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use wgp_proto::consts::LEASE_INTERVAL_S;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    NotFound,
    InvalidSignature,
    StoreFailed,
    NotExpired,
    PreemptedByOther,
}

/// 选点时最多向多少个候选（离房间键最近的）发起查询
const LOCATE_MAX_QUERIES: usize = 8;

/// 房间存储节点的候选（v1：房间记录只放在公网可达的种子上）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCandidate {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    /// 是否允许 Forward 中转；None = 不知道（没有广告的手工配置种子）
    pub relays: Option<bool>,
}

/// 选点结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoragePick {
    pub candidate: StorageCandidate,
    /// true = 该节点上已有本房间的合法记录（跟随既有房间）
    pub existing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageProbe {
    HasRoom,
    Empty,
    Unreachable,
}

/// 房间运行时：把房间语义绑定在具体 DHT 节点 + 存储节点上
pub struct RoomRuntime {
    node: Arc<DhtNode>,
    identity: Arc<NodeIdentity>,
    /// 房间键存储节点（v1：双方共同认识的种子）
    storage: SocketAddr,
}

impl RoomRuntime {
    pub fn new(node: Arc<DhtNode>, storage: SocketAddr) -> Self {
        let identity = node.identity();
        Self {
            node,
            identity,
            storage,
        }
    }

    /// 在候选种子里为房间选定存储节点（v1 仍是单存储点，仲裁语义不变）。
    ///
    /// 两个客户端只有选中同一个存储节点才能在同一个房间里相遇，所以选点必须是**确定**的，
    /// 不能用「各自测速最快」这种因人而异的标准：
    /// 1. 向离房间键最近的若干候选并发查询，**已有合法房间记录**的优先（取其中最近者）——
    ///    双方认识的种子不完全一样时，宁可跟随既有房间，也不另起一个造成分裂；
    /// 2. 都没有 → 取最近的可达候选，明确不中转的（贡献模式）排在后面：报道与协商消息要靠
    ///    存储节点中转，选一个不中转的，房间里就永远只有自己。
    ///
    /// 全部候选不可达（或没有候选）返回 None。
    pub async fn locate(
        node: &Arc<DhtNode>,
        code: &str,
        candidates: &[StorageCandidate],
    ) -> Option<StoragePick> {
        let key = room_key(code);
        let target = NodeId(key);
        let mut ordered: Vec<StorageCandidate> = candidates.to_vec();
        ordered.sort_by_key(|c| c.node_id.xor_distance(&target));
        let mut seen = HashSet::new();
        ordered.retain(|c| seen.insert(c.addr));
        ordered.truncate(LOCATE_MAX_QUERIES);

        let mut queries = JoinSet::new();
        for (rank, candidate) in ordered.iter().enumerate() {
            let node = node.clone();
            let addr = candidate.addr;
            queries.spawn(async move {
                let state = match node.find_value(addr, key).await {
                    Ok(v) if !v.value.is_empty() && verify_room(&v.value).is_some() => {
                        StorageProbe::HasRoom
                    }
                    Ok(_) => StorageProbe::Empty,
                    Err(_) => StorageProbe::Unreachable,
                };
                (rank, state)
            });
        }
        let mut states = vec![StorageProbe::Unreachable; ordered.len()];
        while let Some(done) = queries.join_next().await {
            if let Ok((rank, state)) = done {
                states[rank] = state;
            }
        }

        let first = |want: &dyn Fn(&StorageCandidate, StorageProbe) -> bool| {
            ordered
                .iter()
                .zip(&states)
                .find(|(c, s)| want(c, **s))
                .map(|(c, _)| *c)
        };
        if let Some(candidate) = first(&|_, s| s == StorageProbe::HasRoom) {
            return Some(StoragePick {
                candidate,
                existing: true,
            });
        }
        let candidate = first(&|c, s| s == StorageProbe::Empty && c.relays != Some(false))
            .or_else(|| first(&|_, s| s == StorageProbe::Empty))?;
        Some(StoragePick {
            candidate,
            existing: false,
        })
    }

    fn my_id(&self) -> NodeId {
        self.identity.node_id()
    }

    fn my_pk(&self) -> Vec<u8> {
        self.identity.verifying_key().to_bytes().to_vec()
    }

    /// 创建房间：自己 = 房主 + 锚点，epoch=0
    pub async fn create(&self, code: &str, now_ms: u64) -> Result<RoomRecord, RoomError> {
        let record = RoomRecord {
            members: vec![(self.my_id(), self.my_pk())],
            lease: Lease::new(0, self.my_id(), now_ms),
            pow: None,
        };
        self.publish(code, &record).await?;
        // 回读自证
        let got = self.fetch(code).await?;
        if got.lease.anchor != self.my_id() {
            return Err(RoomError::PreemptedByOther);
        }
        Ok(got)
    }

    /// 读取房间（加入者入口）
    pub async fn fetch(&self, code: &str) -> Result<RoomRecord, RoomError> {
        let key = room_key(code);
        let value = self
            .node
            .find_value(self.storage, key)
            .await
            .map_err(|_| RoomError::StoreFailed)?;
        if value.value.is_empty() {
            return Err(RoomError::NotFound);
        }
        let (record, _sig) = verify_room(&value.value).ok_or(RoomError::InvalidSignature)?;
        Ok(record)
    }

    /// 签名并存储记录
    pub async fn publish(&self, code: &str, record: &RoomRecord) -> Result<(), RoomError> {
        let signed = sign_room(&self.identity, record);
        self.node
            .store(self.storage, room_key(code), signed)
            .await
            .map_err(|_| RoomError::StoreFailed)
    }

    /// 锚点续期：推进 expires 并 republish（epoch 不变）
    pub async fn renew(&self, code: &str, record: &RoomRecord, now_ms: u64) -> Result<RoomRecord, RoomError> {
        let mut next = record.clone();
        next.lease.renew(now_ms);
        self.publish(code, &next).await?;
        Ok(next)
    }

    /// 成员注册（仅锚点执行）：成员表追加后重签重存
    pub async fn add_member(
        &self,
        code: &str,
        record: &RoomRecord,
        member_id: NodeId,
        member_pk: Vec<u8>,
        now_ms: u64,
    ) -> Result<RoomRecord, RoomError> {
        if record.lease.anchor != self.my_id() {
            // 只有当前锚点能改成员表（07 §4 权限语义）
            return Err(RoomError::PreemptedByOther);
        }
        if record.members.iter().any(|(id, _)| *id == member_id) {
            return Ok(record.clone());
        }
        let mut next = record.clone();
        next.members.push((member_id, member_pk));
        next.lease.renew(now_ms);
        self.publish(code, &next).await?;
        Ok(next)
    }

    /// 继位尝试。前提由调用方在本地观测得出：`current` 的租约已连续 `unchanged_ms` 毫秒没有变化
    /// （见 [`LeaseWatch`]——不同进程的时钟不可比，掉线只能这样判）。
    /// 按继位链序出手（退避 = 链内序号 × 300ms）；出手前复核存储节点上仍是观测到的那份租约，
    /// 期间有人续期或接任即放弃；写后回读裁决——被抢先即认输。
    pub async fn try_takeover(
        &self,
        code: &str,
        current: &RoomRecord,
        unchanged_ms: u64,
        now_ms: u64,
    ) -> Result<RoomRecord, RoomError> {
        if !LeaseWatch::is_stale(unchanged_ms) {
            return Err(RoomError::NotExpired);
        }
        let line = succession_line(current);
        let my_pos = line
            .iter()
            .position(|id| *id == self.my_id())
            .ok_or(RoomError::PreemptedByOther)?;
        // 退避去重：链上排前面的先动手
        if my_pos > 0 {
            tokio::time::sleep(Duration::from_millis(300 * my_pos as u64)).await;
        }
        // 提防等待期间已易主：租约只要动过（续期或换锚点），就不再是我们观测到的那份
        let latest = self.fetch(code).await?;
        if latest.lease != current.lease {
            return Err(RoomError::NotExpired);
        }
        let mut next = latest.clone();
        next.lease = Lease::new(current.lease.epoch + 1, self.my_id(), now_ms);
        self.publish(code, &next).await?;
        // 写后回读裁决
        let back = self.fetch(code).await?;
        if back.lease.anchor == self.my_id() {
            Ok(back)
        } else {
            Err(RoomError::PreemptedByOther)
        }
    }

    /// 加入报道：向锚点发送签名 JoinRequest（经存储节点 Forward 路由）。
    /// v1 无 ACK：请求方轮询 fetch 直至自己入表（upkeep 内实现）。
    pub async fn request_join(&self, code: &str, record: &RoomRecord) -> Result<(), RoomError> {
        let payload = JoinRequest::sign(&self.identity, code);
        self.node
            .forward_to(self.storage, record.lease.anchor, payload)
            .await
            .map_err(|_| RoomError::StoreFailed)
    }

    /// 锚点侧：处理入站 JoinRequest（upkeep 轮询 inbox 调用）。
    /// 验签 → add_member（仅当前锚点有效）→ 重签重存。
    async fn handle_join_request(&self, code: &str, payload: &[u8], now_ms: u64) -> bool {
        let Some((member_id, member_pk)) = JoinRequest::verify(code, payload)
        else {
            return false; // 伪造报道：静默丢弃
        };
        let Ok(current) = self.fetch(code).await else {
            return false;
        };
        if current.lease.anchor != self.my_id() {
            return false; // 我已不是锚点：忽略（新锚点会处理重发）
        }
        if current.members.iter().any(|(id, _)| *id == member_id) {
            return true; // 已在表（重复报道幂等）
        }
        self.add_member(code, &current, member_id, member_pk, now_ms)
            .await
            .is_ok()
    }

    /// upkeep 长任务（三合一循环，锚点与成员共用同一逻辑）：
    /// ① 锚点：处理入站报道 + 租约续期
    /// ② 成员：监控租约过期 → 继位尝试
    /// ③ 全员：向锚点补报道（若自己尚未入表）
    pub async fn upkeep(
        &self,
        code: String,
        interval_ms: u64,
        mut stop: watch::Receiver<bool>,
        now_fn: impl Fn() -> u64,
    ) {
        // 续期节流：报道处理每轮执行；republish 仅当距上次 ≥ 租约周期。首拍立即续期——
        // 锚点进程重启后要尽快让成员看到租约在动，否则会被当成掉线
        let mut last_renew_ms: Option<u64> = None;
        // 成员侧掉线判定：本地观测租约多久没变（跨进程的时钟不可比）
        let mut lease_watch = LeaseWatch::new();
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = tokio::time::sleep(Duration::from_millis(interval_ms)) => {}
            }

            // ① 锚点职责：处理报道队列
            while let Some(fwd) = self.node.try_recv_forward().await {
                if fwd.target == self.my_id().0 {
                    let _ = self.handle_join_request(&code, &fwd.payload, now_fn()).await;
                }
            }

            let now = now_fn();
            let Ok(record) = self.fetch(&code).await else {
                continue; // 存储节点暂不可达：下轮重试
            };

            if record.lease.anchor == self.my_id() {
                // ② 我是锚点：续期（按 LEASE_INTERVAL_S 节流）
                let due = last_renew_ms
                    .map_or(true, |at| now.saturating_sub(at) >= LEASE_INTERVAL_S * 1000);
                if due && self.renew(&code, &record, now).await.is_ok() {
                    last_renew_ms = Some(now);
                }
            } else {
                // ③ 我是成员：监控 + 补报道
                last_renew_ms = None;
                if !record.members.iter().any(|(id, _)| *id == self.my_id()) {
                    let _ = self.request_join(&code, &record).await;
                }
                let unchanged_ms = lease_watch.observe(&record.lease, now);
                if LeaseWatch::is_stale(unchanged_ms) {
                    let _ = self
                        .try_takeover(&code, &record, unchanged_ms, now)
                        .await;
                }
            }
        }
    }
}

/// 加入报道载荷（v2，定长 163B）：
///   magic(2 "WJ") | ver(1)=2 | room_key(32) | member_id(32) | pubkey(32) | sig(64)
/// sig = ed25519_sign(前 99B)，由请求者的长期身份签发。
///
/// 载荷要经存储节点 Forward 中转，而中转者不可信。**房间码绝不能出现在这里**：它是混入会话
/// 密钥派生的口令（装配线的 info_ctx），中转者一旦得知，就能对协商做中间人。v1 载荷带的正是
/// 明文房间码；v2 改带 `room_key = SHA256(域 ‖ 房间码)`——存储节点本来就以它为键存取房间记录，
/// 不增加任何信息。
pub struct JoinRequest;

impl JoinRequest {
    pub const VERSION: u8 = 2;
    pub const LEN: usize = 163;
    const SIGNED_LEN: usize = 99;

    /// 以 `identity` 的名义签发「加入 `code` 所指房间」的报道
    pub fn sign(identity: &NodeIdentity, code: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(b"WJ");
        out.push(Self::VERSION);
        out.extend_from_slice(&room_key(code));
        out.extend_from_slice(&identity.node_id().0);
        out.extend_from_slice(&identity.verifying_key().to_bytes());
        let sig = identity.sign(&out);
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    /// 校验报道：格式与版本 → 房间键属于本房间 → member_id 与公钥绑定 → 签名。
    /// 通过后返回 (成员 NodeId, 成员公钥)。
    pub fn verify(code: &str, payload: &[u8]) -> Option<(NodeId, Vec<u8>)> {
        if payload.len() != Self::LEN || &payload[0..2] != b"WJ" || payload[2] != Self::VERSION {
            return None;
        }
        if payload[3..35] != room_key(code) {
            return None; // 报错房间：拒绝
        }
        let member_id = NodeId(payload[35..67].try_into().ok()?);
        let member_pk: [u8; 32] = payload[67..99].try_into().ok()?;
        let vk = VerifyingKey::from_bytes(&member_pk).ok()?;
        // 身份绑定：不校验的话，任何人都能拿自己的密钥把「别人的 NodeId」塞进成员表
        if node_id_from_verifying(&vk) != member_id {
            return None;
        }
        let sig = Signature::from_bytes(payload[Self::SIGNED_LEN..].try_into().ok()?);
        vk.verify(&payload[..Self::SIGNED_LEN], &sig).ok()?;
        Some((member_id, member_pk.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    async fn spawn_node() -> Arc<DhtNode> {
        let mut rng = OsRng;
        let id = NodeIdentity::generate(&mut rng);
        DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
    }

    async fn setup() -> (RoomRuntime, Arc<DhtNode>, RoomRuntime, Arc<DhtNode>, RoomRuntime) {
        let owner = spawn_node().await;
        let bob = spawn_node().await;
        let carol = spawn_node().await;
        let storage = owner.local_addr().unwrap();
        // bob/carol 都与 owner（存储节点）互认（模拟共同 bootstrap 的种子）
        let _ = bob.ping(storage).await.unwrap();
        let _ = carol.ping(storage).await.unwrap();
        let _ = owner.ping(bob.local_addr().unwrap()).await.unwrap();
        let _ = owner.ping(carol.local_addr().unwrap()).await.unwrap();
        let rt_owner = RoomRuntime::new(owner.clone(), storage);
        let rt_bob = RoomRuntime::new(bob.clone(), storage);
        let rt_carol = RoomRuntime::new(carol, storage);
        (rt_owner, owner, rt_bob, bob, rt_carol)
    }

    fn node_id_of(node: &Arc<DhtNode>) -> NodeId {
        node.node_id()
    }

    fn pk_of(node: &Arc<DhtNode>) -> Vec<u8> {
        node.identity().verifying_key().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn create_and_fetch_valid_signed_record() {
        let (owner_rt, owner_node, _, _, _) = setup().await;
        let created = owner_rt.create("U/TEST-ROOM-0001-AB12", 0).await.unwrap();
        assert_eq!(created.lease.anchor, node_id_of(&owner_node));
        assert_eq!(created.lease.epoch, 0);
        assert_eq!(created.members.len(), 1);
        // 存储值可被证书链验证（fetch 内部已 verify_room）
        let fetched = owner_rt.fetch("U/TEST-ROOM-0001-AB12").await.unwrap();
        assert_eq!(fetched, created);
    }

    #[tokio::test]
    async fn tampered_record_rejected() {
        let (owner_rt, owner_node, _, bob_node, _) = setup().await;
        let mut record = owner_rt
            .create("U/TEST-ROOM-0002-CD34", 0)
            .await
            .unwrap();
        // 篡改：把 Bob 塞进成员表但不重签 → 直接 publish 伪造
        record.members.push((node_id_of(&bob_node), pk_of(&bob_node)));
        let forged = sign_room(&owner_node.identity(), &record); // 用另一个身份签（Bob 不当锚点）
        let _ = forged;
        // 直接存储"未签名伪造体"：篡改成员表的字节流
        let body = record.encode();
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&[0xEEu8; 64]); // 假签名
        tampered.extend_from_slice(&body);
        owner_node
            .store(
                owner_node.local_addr().unwrap(),
                room_key("U/TEST-ROOM-0002-CD34"),
                tampered,
            )
            .await
            .unwrap();
        // fetch → 签名无效 → InvalidSignature
        let r = owner_rt.fetch("U/TEST-ROOM-0002-CD34").await;
        assert_eq!(r, Err(RoomError::InvalidSignature));
    }

    #[tokio::test]
    async fn renew_advances_expiry_no_epoch_bump() {
        let (owner_rt, _, _, _, _) = setup().await;
        owner_rt.create("U/TEST-ROOM-0003-EF56", 0).await.unwrap();
        let r1 = owner_rt.fetch("U/TEST-ROOM-0003-EF56").await.unwrap();
        let r2 = owner_rt.renew("U/TEST-ROOM-0003-EF56", &r1, 29_000).await.unwrap();
        assert_eq!(r2.lease.epoch, r1.lease.epoch, "续期不改 epoch");
        assert!(r2.lease.expires_at_ms > r1.lease.expires_at_ms);
    }

    #[tokio::test]
    async fn add_member_updates_membership() {
        let (owner_rt, _, _, bob_node, carol_rt) = setup().await;
        let rec = owner_rt.create("U/TEST-ROOM-0004-AB78", 0).await.unwrap();
        let bumped = owner_rt
            .add_member(
                "U/TEST-ROOM-0004-AB78",
                &rec,
                node_id_of(&bob_node),
                pk_of(&bob_node),
                0,
            )
            .await
            .unwrap();
        assert_eq!(bumped.members.len(), 2);
        // Carol 侧可读到新成员表
        let seen = carol_rt.fetch("U/TEST-ROOM-0004-AB78").await.unwrap();
        assert_eq!(seen.members.len(), 2);
        assert!(seen.members.iter().any(|(id, _)| *id == node_id_of(&bob_node)));
    }

    #[tokio::test]
    async fn takeover_when_owner_silent() {
        const CODE: &str = "U/TEST-ROOM-0005-CD90";
        let timeout_ms = wgp_proto::consts::LEASE_TIMEOUT_S * 1000;
        let (owner_rt, owner_node, bob_rt, bob_node, carol_rt) = setup().await;
        let rec = owner_rt.create(CODE, 0).await.unwrap();
        let rec = owner_rt
            .add_member(CODE, &rec, node_id_of(&bob_node), pk_of(&bob_node), 0)
            .await
            .unwrap();
        owner_rt
            .add_member(CODE, &rec, carol_rt.my_id(), carol_rt.my_pk(), 0)
            .await
            .unwrap();

        // 房主"掉线"：此后不再续期。Bob 在本地观测到租约 40s 没变——还不到 75s，不许抢
        let stale = bob_rt.fetch(CODE).await.unwrap();
        let too_early = bob_rt.try_takeover(CODE, &stale, 40_000, 40_000).await;
        assert_eq!(too_early, Err(RoomError::NotExpired));

        // 观测满 75s：Bob 抢占成功——epoch+1、锚点=Bob、成员表原样继承
        let after = bob_rt
            .try_takeover(CODE, &stale, timeout_ms, 80_000)
            .await
            .unwrap();
        assert_eq!(after.lease.anchor, node_id_of(&bob_node));
        assert_eq!(after.lease.epoch, stale.lease.epoch + 1);
        assert_eq!(after.members, stale.members);

        // Carol 手里还是那份旧快照，也观测满了 75s：出手前复核发现租约已变 → 放弃
        let late = carol_rt
            .try_takeover(CODE, &stale, timeout_ms, 80_000)
            .await;
        assert_eq!(late, Err(RoomError::NotExpired));
        // Carol 看到新租约后重新计时：刚看到 = 0 → 不许抢
        let fresh = carol_rt.try_takeover(CODE, &after, 0, 80_000).await;
        assert_eq!(fresh, Err(RoomError::NotExpired));
        assert_eq!(owner_rt.fetch(CODE).await.unwrap(), after, "记录未被 Carol 改动");

        // 不在成员表里的人没有继位资格
        let outsider = RoomRuntime::new(spawn_node().await, owner_node.local_addr().unwrap());
        let denied = outsider
            .try_takeover(CODE, &after, timeout_ms, 200_000)
            .await;
        assert_eq!(denied, Err(RoomError::PreemptedByOther));
    }

    /// 回归：成员进程与锚点进程的单调时基不同（这里成员比锚点"老"一小时）。
    /// 旧实现拿记录里的到期时刻与本地时钟直接比较，成员一上来就把健康的锚点判成过期并夺位；
    /// 现在只看本地观测到的「多久没续期」：锚点在续期就不动，锚点沉默满 75s 才接任。
    #[tokio::test]
    async fn member_with_different_clock_base_takes_over_only_after_real_silence() {
        use std::sync::atomic::{AtomicU64, Ordering};
        const CODE: &str = "U/SKEW-TEST-0001-EE55";
        const MEMBER_CLOCK_AHEAD_MS: u64 = 3_600_000;

        let (owner_rt, owner_node, bob_rt, bob_node, _) = setup().await;
        let owner_rt = Arc::new(owner_rt);
        let bob_rt = Arc::new(bob_rt);
        let clock = Arc::new(AtomicU64::new(1_000));

        let rec = owner_rt.create(CODE, 1_000).await.unwrap();
        owner_rt
            .add_member(CODE, &rec, node_id_of(&bob_node), pk_of(&bob_node), 1_000)
            .await
            .unwrap();

        let (owner_stop, owner_stop_rx) = watch::channel(false);
        let (bob_stop, bob_stop_rx) = watch::channel(false);
        let owner_task = {
            let (rt, clock) = (owner_rt.clone(), clock.clone());
            tokio::spawn(async move {
                rt.upkeep(CODE.to_string(), 40, owner_stop_rx, move || {
                    clock.load(Ordering::Relaxed)
                })
                .await;
            })
        };
        let bob_task = {
            let (rt, clock) = (bob_rt.clone(), clock.clone());
            tokio::spawn(async move {
                rt.upkeep(CODE.to_string(), 40, bob_stop_rx, move || {
                    clock.load(Ordering::Relaxed) + MEMBER_CLOCK_AHEAD_MS
                })
                .await;
            })
        };

        // 锚点健在：时间推进 4 × 31s（远超 75s 租约），每步锚点都会续期——成员不得夺位
        let mut last_expiry = owner_rt.fetch(CODE).await.unwrap().lease.expires_at_ms;
        for step in 1..=4 {
            clock.fetch_add(31_000, Ordering::Relaxed);
            // 等锚点的这次续期落到存储节点，再留几拍让成员看到
            let mut renewed = false;
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let lease = owner_rt.fetch(CODE).await.unwrap().lease;
                if lease.expires_at_ms != last_expiry {
                    last_expiry = lease.expires_at_ms;
                    renewed = true;
                    break;
                }
            }
            assert!(renewed, "第 {step} 步：锚点应已续期");
            tokio::time::sleep(Duration::from_millis(200)).await;
            let record = owner_rt.fetch(CODE).await.unwrap();
            assert_eq!(
                record.lease.anchor,
                node_id_of(&owner_node),
                "第 {step} 步：锚点健在时成员不得夺位"
            );
            assert_eq!(record.lease.epoch, 0);
        }

        // 锚点掉线：停止续期。沉默 40s——还不到 75s，成员继续等
        owner_stop.send(true).unwrap();
        owner_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await; // 让成员先看到最后一次续期
        clock.fetch_add(40_000, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let record = bob_rt.fetch(CODE).await.unwrap();
        assert_eq!(record.lease.anchor, node_id_of(&owner_node), "沉默未满 75s 不得接任");

        // 再沉默 40s（累计 80s）：成员接任，epoch+1
        clock.fetch_add(40_000, Ordering::Relaxed);
        let mut taken = None;
        for _ in 0..150 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let record = bob_rt.fetch(CODE).await.unwrap();
            if record.lease.anchor == node_id_of(&bob_node) {
                taken = Some(record);
                break;
            }
        }
        let taken = taken.expect("锚点沉默满 75s 后成员应接任");
        assert_eq!(taken.lease.epoch, 1);
        assert_eq!(taken.members.len(), 2, "成员表随接任继承");

        bob_stop.send(true).unwrap();
        bob_task.await.unwrap();
    }

    /// 起 n 个节点充当存储候选（种子）
    async fn storage_candidates(n: usize) -> Vec<(Arc<DhtNode>, StorageCandidate)> {
        let mut out = Vec::new();
        for _ in 0..n {
            let node = spawn_node().await;
            let candidate = StorageCandidate {
                node_id: node.node_id(),
                addr: node.local_addr().unwrap(),
                relays: None,
            };
            out.push((node, candidate));
        }
        out
    }

    #[tokio::test]
    async fn locate_is_deterministic_and_follows_existing_room() {
        const CODE: &str = "U/LOCATE-TEST-0001-AA11";
        let seeds = storage_candidates(4).await;
        let candidates: Vec<StorageCandidate> = seeds.iter().map(|(_, c)| *c).collect();
        let key = NodeId(room_key(CODE));
        let closest = *candidates
            .iter()
            .min_by_key(|c| c.node_id.xor_distance(&key))
            .unwrap();

        let alice = spawn_node().await;
        let bob = spawn_node().await;
        // 还没有房间：两端各自选点，候选顺序不同也必须选中同一个（离房间键最近者）
        let pick_a = RoomRuntime::locate(&alice, CODE, &candidates).await.unwrap();
        let mut reversed = candidates.clone();
        reversed.reverse();
        let pick_b = RoomRuntime::locate(&bob, CODE, &reversed).await.unwrap();
        assert_eq!(pick_a.candidate, closest);
        assert_eq!(pick_b.candidate, closest);
        assert!(!pick_a.existing && !pick_b.existing);

        // 房间已经建在「不是最近」的节点上（建房者当时只认识它）：后来者跟随既有房间
        let elsewhere = *candidates.iter().find(|c| **c != closest).unwrap();
        RoomRuntime::new(alice.clone(), elsewhere.addr)
            .create(CODE, 0)
            .await
            .unwrap();
        let pick = RoomRuntime::locate(&bob, CODE, &candidates).await.unwrap();
        assert_eq!(pick.candidate, elsewhere);
        assert!(pick.existing);
    }

    #[tokio::test]
    async fn locate_skips_unreachable_and_prefers_relaying_seed() {
        const CODE: &str = "U/LOCATE-TEST-0002-BB22";
        let seeds = storage_candidates(3).await;
        let key = NodeId(room_key(CODE));
        let mut ordered: Vec<StorageCandidate> = seeds.iter().map(|(_, c)| *c).collect();
        ordered.sort_by_key(|c| c.node_id.xor_distance(&key));
        let client = spawn_node().await;

        // 最近的候选连不上 → 跳过，取下一个
        let mut dead_first = ordered.clone();
        dead_first[0].addr = "127.0.0.1:1".parse().unwrap();
        let pick = RoomRuntime::locate(&client, CODE, &dead_first).await.unwrap();
        assert_eq!(pick.candidate, ordered[1]);

        // 最近的候选明确不中转（贡献模式）→ 建房时让位给能中转的
        let mut hobby_first = ordered.clone();
        hobby_first[0].relays = Some(false);
        let pick = RoomRuntime::locate(&client, CODE, &hobby_first).await.unwrap();
        assert_eq!(pick.candidate, hobby_first[1]);

        // 全都不中转：仍取最近的（至少房主自己能入表，由外围给出明确提示）
        let all_hobby: Vec<StorageCandidate> = ordered
            .iter()
            .map(|c| StorageCandidate {
                relays: Some(false),
                ..*c
            })
            .collect();
        let pick = RoomRuntime::locate(&client, CODE, &all_hobby).await.unwrap();
        assert_eq!(pick.candidate, all_hobby[0]);

        // 全部不可达 / 没有候选 → None
        let dead: Vec<StorageCandidate> = (1..=2u16)
            .map(|port| StorageCandidate {
                node_id: ordered[0].node_id,
                addr: SocketAddr::from(([127, 0, 0, 1], port)),
                relays: None,
            })
            .collect();
        assert!(RoomRuntime::locate(&client, CODE, &dead).await.is_none());
        assert!(RoomRuntime::locate(&client, CODE, &[]).await.is_none());
    }

    #[tokio::test]
    async fn fetch_uncreated_room_not_found() {
        let (owner_rt, _, _, _, _) = setup().await;
        let r = owner_rt.fetch("U/NO-SUCH-ROOM-0000-0000").await;
        assert_eq!(r, Err(RoomError::NotFound));
    }

    #[test]
    fn join_request_sign_verify_and_forgery_rejected() {
        const CODE: &str = "U/JOIN-TEST-0001-AA22";
        let bob = NodeIdentity::generate(&mut OsRng);
        let payload = JoinRequest::sign(&bob, CODE);
        assert_eq!(payload.len(), JoinRequest::LEN);

        // 合法自证：验签通过
        let (got_id, got_pk) = JoinRequest::verify(CODE, &payload).expect("合法报道应通过");
        assert_eq!(got_id, bob.node_id());
        assert_eq!(got_pk, bob.verifying_key().to_bytes().to_vec());

        // 报错房间 → 拒
        assert!(JoinRequest::verify("U/JOIN-TEST-0002-BB33", &payload).is_none());

        // 任一字节被篡改（魔数、版本、房间键、身份、公钥、签名）→ 拒
        for offset in 0..payload.len() {
            let mut tampered = payload.clone();
            tampered[offset] ^= 0x01;
            assert!(
                JoinRequest::verify(CODE, &tampered).is_none(),
                "偏移 {offset} 被篡改后仍通过"
            );
        }
        // 长度不对 → 拒（含 v1 那种变长载荷）
        assert!(JoinRequest::verify(CODE, &payload[..payload.len() - 1]).is_none());
        let mut longer = payload.clone();
        longer.push(0);
        assert!(JoinRequest::verify(CODE, &longer).is_none());

        // 冒名：Mallory 用自己的密钥签，却把 member_id 写成 Bob 的（签名本身有效）→ 身份绑定拒绝
        let mallory = NodeIdentity::generate(&mut OsRng);
        let mut forged = JoinRequest::sign(&mallory, CODE);
        forged[35..67].copy_from_slice(&bob.node_id().0);
        let resigned = mallory.sign(&forged[..99]);
        forged[99..].copy_from_slice(&resigned.to_bytes());
        assert!(
            JoinRequest::verify(CODE, &forged).is_none(),
            "member_id 必须等于 SHA256(公钥)"
        );
    }

    /// 房间码是混入会话密钥派生的口令，绝不能出现在经第三方中转的报道载荷里
    #[test]
    fn join_request_never_carries_the_room_code() {
        const CODE: &str = "U/C2G9-GYET-311W-R636";
        let payload = JoinRequest::sign(&NodeIdentity::generate(&mut OsRng), CODE);
        let contains = |needle: &[u8]| payload.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(CODE.as_bytes()), "载荷里出现了明文房间码");
        assert!(!contains(&CODE.as_bytes()[2..]), "载荷里出现了房间码主体");
        assert!(!contains(b"C2G9"), "载荷里出现了房间码片段");
        // 只带房间键（存储节点本来就知道的那个哈希）
        assert_eq!(&payload[3..35], &room_key(CODE));
    }

    /// upkeep 全生命周期：A 建房 → A、B 各跑 upkeep（100ms 周期）→
    /// B 自动报道入表 → 租约被 A 持续续期。
    #[tokio::test]
    async fn upkeep_auto_report_and_renew() {
        let (owner_rt, owner_node, bob_rt, bob_node, _) = setup().await;
        let owner_rt = Arc::new(owner_rt);
        let bob_rt = Arc::new(bob_rt);
        let code = "U/UPKEEP-TEST-0002-BB33".to_string();

        // 建房
        let rec = owner_rt.create(&code, 0).await.unwrap();
        assert!(rec.members.iter().any(|(id, _)| *id == node_id_of(&owner_node)));

        let now = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // 双方启动 upkeep（100ms 周期短跑）
        let (stop_tx, stop_rx) = watch::channel(false);
        let a_code = code.clone();
        let a_now = {
            let now = now.clone();
            move || now.load(std::sync::atomic::Ordering::Relaxed)
        };
        let a_rt = owner_rt.clone();
        let a_task = tokio::spawn(async move {
            a_rt.upkeep(a_code, 100, stop_rx, a_now).await;
        });
        let b_code = code.clone();
        let b_now = {
            let now = now.clone();
            move || now.load(std::sync::atomic::Ordering::Relaxed)
        };
        let (b_stop_tx, b_stop_rx) = watch::channel(false);
        let b_rt = bob_rt.clone();
        let b_task = tokio::spawn(async move {
            b_rt.upkeep(b_code, 100, b_stop_rx, b_now).await;
        });

        // B 从未在成员表；upkeep 数轮后应自动补报道入表
        tokio::time::sleep(Duration::from_millis(1600)).await;
        let record = bob_rt.fetch(&code).await.unwrap();
        assert!(
            record.members.iter().any(|(id, _)| *id == node_id_of(&bob_node)),
            "B 应已自动报道入表（{}/{} 成员）",
            record.members.len(),
            record.members.iter().map(|(id, _)| format!("{:?}", &id.0[..2])).collect::<Vec<_>>().join(",")
        );

        let _ = stop_tx.send(true);
        let _ = b_stop_tx.send(true);
        let _ = a_task.await;
        let _ = b_task.await;
    }
}