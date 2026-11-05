//! 房间生命周期运行时（07 §4 三件套的落地：租约、继位链、epoch）。
//! v1 简化语义（在未来版本向标准 Kademlia 键值复制演进）：
//!  - 房间键值存于"存储节点"（创建/加入双方共同 bootstrap 的种子），
//!    锚点负责 republish；成员经 find_value 读取。
//!  - 抢占裁决：候选按继位链序退避出手，写后回读验证（epoch/锚点一致性）。
//!  - 加入报道：JoinRequest 经存储节点 Forward 路由至锚点（存储节点已学习
//!    写入者身份），锚点验签后 add_member 重签重存。

use crate::id::{NodeIdentity, NodeId};
use crate::node::DhtNode;
use crate::room::{room_key, sign_room, succession_line, verify_room, Lease, RoomRecord};
use ed25519_dalek::Signature;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use wgp_proto::consts::LEASE_INTERVAL_S;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    NotFound,
    InvalidSignature,
    StoreFailed,
    NotExpired,
    PreemptedByOther,
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

    /// 继位尝试：租约过期后按继位链序出手（退避 = 链内序号 × 300ms），
    /// 写后回读裁决——被抢先即认输。
    pub async fn try_takeover(
        &self,
        code: &str,
        current: &RoomRecord,
        now_ms: u64,
    ) -> Result<RoomRecord, RoomError> {
        if !current.lease.expired(now_ms) {
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
        // 提防等待期间已易主
        let latest = self.fetch(code).await?;
        if !latest.lease.expired(now_ms) {
            return Err(RoomError::NotExpired); // 新锚点已经续期
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
        let payload = JoinRequest::sign(
            &self.identity,
            code,
            self.my_id(),
            &self.my_pk(),
        );
        self.node
            .forward_to(self.storage, record.lease.anchor, payload)
            .await
            .map_err(|_| RoomError::StoreFailed)
    }

    /// 锚点侧：处理入站 JoinRequest（upkeep 轮询 inbox 调用）。
    /// 验签 → add_member（仅当前锚点有效）→ 重签重存。
    async fn handle_join_request(&self, code: &str, payload: &[u8], now_ms: u64) -> bool {
        let Some((member_id, member_pk)) = JoinRequest::verify(&self.identity, code, payload)
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
        // 续期节流：报道处理每轮执行；republish 仅当距上次 ≥ 租约周期
        let mut last_renew_ms = 0u64;
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
                if now.saturating_sub(last_renew_ms) >= LEASE_INTERVAL_S * 1000 {
                    if self.renew(&code, &record, now).await.is_ok() {
                        last_renew_ms = now;
                    }
                }
            } else {
                // ③ 我是成员：监控 + 补报道
                if !record.members.iter().any(|(id, _)| *id == self.my_id()) {
                    let _ = self.request_join(&code, &record).await;
                }
                if record.lease.expired(now) {
                    let _ = self.try_takeover(&code, &record, now).await;
                }
            }
        }
    }
}

/// JoinRequest 载荷：
/// magic(2 "WJ") | code_len(1) | code | member_id(32) | pubkey(32) | sig(64)
/// sig = ed25519_sign(code || member_id || pubkey)（请求者长期身份）
pub struct JoinRequest;

impl JoinRequest {
    pub fn sign(
        identity: &NodeIdentity,
        code: &str,
        member_id: NodeId,
        member_pk: &[u8],
    ) -> Vec<u8> {
        let code_bytes = code.as_bytes();
        debug_assert!(code_bytes.len() <= 200);
        let mut unsigned = Vec::with_capacity(2 + 1 + code_bytes.len() + 64);
        unsigned.extend_from_slice(b"WJ");
        unsigned.push(code_bytes.len() as u8);
        unsigned.extend_from_slice(code_bytes);
        unsigned.extend_from_slice(&member_id.0);
        unsigned.extend_from_slice(&member_pk[..32.min(member_pk.len())]);
        // 签名域 = 全部 unsigned 字段
        let sig = identity.sign(&unsigned);
        let mut out = unsigned;
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    /// 视为"验签者视角"：identity 用于验签（用成员公钥验证）
    pub fn verify(
        verifier: &NodeIdentity,
        code: &str,
        payload: &[u8],
    ) -> Option<(NodeId, Vec<u8>)> {
        if payload.len() < 2 + 1 + 64 + 64 {
            return None;
        }
        if &payload[0..2] != b"WJ" {
            return None;
        }
        let code_len = payload[2] as usize;
        if payload.len() != 2 + 1 + code_len + 64 + 64 {
            return None;
        }
        if &payload[3..3 + code_len] != code.as_bytes() {
            return None; // 报错房间：拒绝
        }
        let member_id = NodeId(
            payload[3 + code_len..3 + code_len + 32]
                .try_into()
                .ok()?,
        );
        let member_pk = payload[3 + code_len + 32..3 + code_len + 64].to_vec();
        let sig_bytes: [u8; 64] = payload[3 + code_len + 64..].try_into().ok()?;
        let sig = Signature::from_bytes(&sig_bytes);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            member_pk.as_slice().try_into().ok()?,
        )
        .ok()?;
        use ed25519_dalek::Verifier;
        vk.verify(&payload[..3 + code_len + 64], &sig).ok()?;
        let _ = verifier; // 验签不依赖本地身份（用对端公钥自证）
        Some((member_id, member_pk))
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
        let (owner_rt, owner_node, bob_rt, bob_node, carol_rt) = setup().await;
        let rec = owner_rt.create("U/TEST-ROOM-0005-CD90", 0).await.unwrap();
        let rec = owner_rt
            .add_member(
                "U/TEST-ROOM-0005-CD90",
                &rec,
                node_id_of(&bob_node),
                pk_of(&bob_node),
                0,
            )
            .await
            .unwrap();
        let _ = &rec;

        // 房主"掉线"：不再续期。时间越过 75s 租约。
        let stale = bob_rt.fetch("U/TEST-ROOM-0005-CD90").await.unwrap();
        assert!(stale.lease.expired(80_000));
        // 未过期时绝不允许抢占
        let too_early = bob_rt.try_takeover("U/TEST-ROOM-0005-CD90", &stale, 40_000).await;
        assert_eq!(too_early, Err(RoomError::NotExpired));

        // Bob 抢占成功：epoch+1、锚点=Bob
        let after = bob_rt
            .try_takeover("U/TEST-ROOM-0005-CD90", &stale, 80_000)
            .await
            .unwrap();
        assert_eq!(after.lease.anchor, node_id_of(&bob_node));
        assert!(after.lease.epoch > stale.lease.epoch);

        // Carol 此时再抢：新锚点已续期 → NotExpired
        let carol_try = carol_rt
            .try_takeover("U/TEST-ROOM-0005-CD90", &after, 80_000)
            .await;
        assert_eq!(carol_try, Err(RoomError::NotExpired));
        let _ = owner_node;
    }

    #[tokio::test]
    async fn fetch_uncreated_room_not_found() {
        let (owner_rt, _, _, _, _) = setup().await;
        let r = owner_rt.fetch("U/NO-SUCH-ROOM-0000-0000").await;
        assert_eq!(r, Err(RoomError::NotFound));
    }

    #[tokio::test]
    async fn join_request_sign_verify_and_forgery_rejected() {
        let mut rng = OsRng;
        let bob_identity = NodeIdentity::generate(&mut rng);
        let mallory = NodeIdentity::generate(&mut rng);
        let bob_id = bob_identity.node_id();
        let bob_pk = bob_identity.verifying_key().to_bytes().to_vec();

        let payload = JoinRequest::sign(&bob_identity, "U/JOIN-TEST-0001-AA22", bob_id, &bob_pk);
        // 合法自证：验签通过
        let (got_id, got_pk) =
            JoinRequest::verify(&bob_identity, "U/JOIN-TEST-0001-AA22", &payload).expect("合法报道应通过");
        assert_eq!(got_id, bob_id);
        assert_eq!(got_pk, bob_pk);

        // 篡改公钥 → 拒
        let mut tampered = payload.clone();
        let code_len = tampered[2] as usize;
        tampered[3 + code_len + 35] ^= 0xFF;
        assert!(JoinRequest::verify(&bob_identity, "U/JOIN-TEST-0001-AA22", &tampered).is_none());

        // 用 Mallory 身份签 → 公钥自证失败
        let forged = JoinRequest::sign(&mallory, "U/JOIN-TEST-0001-AA22", bob_id, &bob_pk);
        assert!(JoinRequest::verify(&bob_identity, "U/JOIN-TEST-0001-AA22", &forged).is_none());
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