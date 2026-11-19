//! 装配线（SessionOrchestrator）：把内核零件组装成全自动打洞流水线。
//!
//! 输入：房间码 + 对端 NodeId；输出：经 Engine 交付的 PunchedLink（sink 回调）。
//! 阶段（15 全链路 Phase 3→5 的自动编排，两端对等对称运行）：
//!   ① 承诺-揭示密钥协商（经 DHT Forward，session_tag 分派）
//!   ② 本端观察者探测 + 步长学习（NatProbe）
//!   ③ Endpoints 交换（公网端点/能力位/步长模型/完整承诺复验）
//!   ④ T1-T4 判定 + 密钥族派生 + PunchInput 组装
//!   ⑤ Engine::new_link 竞速交付（保活自动挂载）
//! 安全说明：sig 包的 Commit 字段仅 16B（协议定长限制），MITM 复验强度不足；
//! 故 Endpoints 帧追加 32B 完整承诺，揭示后重算比对 → 128bit 抗 MITM（01 §1.2）。

use crate::engine::circuit::{decide_race, CircuitInput};
use crate::engine::nat_probe::NatProbe;
use crate::engine::Engine;
use crate::engine::PunchInput;
use crate::transport::{TcpProbeCarrier, UdpProbeCarrier};
use crate::types::LinkSink;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use wgp_crypto::commit::{commit as make_commit, verify as verify_commit, Commitment};
use wgp_crypto::derive::derive_all;
use wgp_crypto::ka::{KeyAgreement, X25519Agreement};
use wgp_crypto::SecretBox;
use wgp_dht::id::peer_id_from_node;
use wgp_dht::verify_identity_signature;
use wgp_dht::{room_key, DhtNode, NodeId, RoomRuntime};
use wgp_proto::dht::ForwardBody;
use wgp_proto::sig::{CommitBody, RevealBody, SigBody, SigPacket};
use wgp_punch::PortStepModel;

/// 装配线错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorError {
    /// 对端无响应（重传耗尽）
    PeerGone,
    /// 承诺不匹配（信令 MITM 嫌疑，24h 黑名单由上层处理）
    Mitm,
    /// 算法不支持
    AlgoMismatch,
    /// 观察者全灭（无法获得端点报告）
    ObserverDead,
    /// 无可用路径（UDP 双亡且无 TCP 同意）
    NoRoute,
}

/// 协商消息：tag(4B 由 DHT 分派层消费) | kind(1B) | body
mod frame {
    pub const KIND_SIG: u8 = 0x01; // SigPacket 字节（COMMIT/REVEAL）
    pub const KIND_EP: u8 = 0x02; // 端点报告（含完整承诺复验）

    /// 端点字段 + 完整承诺 + 身份签名。
    pub const EP_BODY_LEN: usize = 15 + 32 + 64;

    /// Endpoints 报告体（47B = 15B 端点 + 32B 完整承诺）
    #[derive(Debug, Clone, Copy)]
    pub struct Endpoints {
        pub ipv4: [u8; 4],
        pub port: u16,
        pub udp_ok: bool,
        pub tcp_ok: bool,
        pub has_model: bool,
        pub last_port: u16,
        /// 步长（×64 定点，防浮点传输）
        pub mean_delta_q: i16,
        /// 置信度 0-100
        pub confidence: u8,
        /// 完整 32B 承诺，用于确认完整 SHA-256 承诺。
        pub full_commit: [u8; 32],
        /// 身份密钥对房间、双方身份和全部端点字段的签名。
        pub identity_signature: [u8; 64],
    }

    pub fn encode_endpoints(e: &Endpoints) -> [u8; EP_BODY_LEN] {
        let mut out = [0u8; EP_BODY_LEN];
        out[0..4].copy_from_slice(&e.ipv4);
        out[4..6].copy_from_slice(&e.port.to_be_bytes());
        out[6] = e.udp_ok as u8;
        out[7] = e.tcp_ok as u8;
        out[8] = e.has_model as u8;
        out[9..11].copy_from_slice(&e.last_port.to_be_bytes());
        out[11..13].copy_from_slice(&e.mean_delta_q.to_be_bytes());
        out[13] = e.confidence;
        out[14] = 0;
        out[15..47].copy_from_slice(&e.full_commit);
        out[47..].copy_from_slice(&e.identity_signature);
        out
    }

    pub fn decode_endpoints(buf: &[u8]) -> Option<Endpoints> {
        if buf.len() != EP_BODY_LEN || buf[14] != 0 {
            return None;
        }
        let mut ipv4 = [0u8; 4];
        ipv4.copy_from_slice(&buf[0..4]);
        let mut full_commit = [0u8; 32];
        full_commit.copy_from_slice(&buf[15..47]);
        let mut identity_signature = [0u8; 64];
        identity_signature.copy_from_slice(&buf[47..111]);
        Some(Endpoints {
            ipv4,
            port: u16::from_be_bytes([buf[4], buf[5]]),
            udp_ok: buf[6] != 0,
            tcp_ok: buf[7] != 0,
            has_model: buf[8] != 0,
            last_port: u16::from_be_bytes([buf[9], buf[10]]),
            mean_delta_q: i16::from_be_bytes([buf[11], buf[12]]),
            confidence: buf[13],
            full_commit,
            identity_signature,
        })
    }

    /// 解析端点帧体（kind 字节 + 47B 报告）；kind 不符或长度不对返回 None。
    /// 帧体可能来自任何算得出会话 tag 的人，必须先验再切——直接 `&body[1..]`
    /// 会被一个只含 tag 的 4 字节载荷打崩（切片越界 panic）。
    pub fn parse_endpoints_frame(body: &[u8]) -> Option<Endpoints> {
        let (&kind, rest) = body.split_first()?;
        if kind != KIND_EP {
            return None;
        }
        decode_endpoints(rest)
    }
}

/// 对端只报告了实测映射端口、没有步长模型时，兜底模型取的置信度（中档：±400 窗口）
const OBSERVED_PORT_CONFIDENCE: f64 = 0.5;

/// 由对端的端点报告重建它的端口模型（供三波规划预测对端端口）。
///
/// 对端学出了步长模型就照搬；没学出（观察者丢包或限频导致三连测不全）但报告了实测映射
/// 端口时，以该端口为中心、零步长兜底——锥形 NAT 下这个端口就是打洞目标，首包直打它，
/// 其余在窗口内撒。旧实现在此情形下完全无视实测端口、全范围盲撒，最好打的锥形 NAT
/// 反而打不通。只有连映射端口都没有（UDP 不通）才返回 None。
fn peer_model_from(ep: &frame::Endpoints) -> Option<PortStepModel> {
    if ep.has_model {
        return Some(PortStepModel {
            last_port: ep.last_port,
            mean_delta: ep.mean_delta_q as f64 / 64.0,
            delta_range: (0, 0),
            trend: wgp_punch::Trend::Oscillating,
            confidence: (ep.confidence as f64 / 100.0).clamp(0.0, 1.0),
        });
    }
    if ep.udp_ok && ep.port != 0 {
        return Some(PortStepModel {
            last_port: ep.port,
            mean_delta: 0.0,
            delta_range: (0, 0),
            trend: wgp_punch::Trend::Oscillating,
            confidence: OBSERVED_PORT_CONFIDENCE,
        });
    }
    None
}

/// 解析承诺/揭示帧体（kind 字节 + SigPacket）；非 SIG 帧或畸形返回 None
fn parse_sig(body: &[u8]) -> Option<SigBody> {
    let (&kind, rest) = body.split_first()?;
    if kind != frame::KIND_SIG {
        return None;
    }
    SigPacket::decode(rest).map(|pkt| pkt.body)
}

/// 确定性会话分派 tag（两端推导一致；按 NodeId 排序免疫方向性）
fn session_tag(room: &str, a: NodeId, b: NodeId) -> u32 {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(room.as_bytes());
    h.update(&lo.0);
    h.update(&hi.0);
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) | 1
}

/// 打洞种子（三波计划参数，两端一致）
fn punch_seed(room: &str, a: NodeId, b: NodeId) -> u64 {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(b"wgp-seed");
    h.update(room.as_bytes());
    h.update(&lo.0);
    h.update(&hi.0);
    let d = h.finalize();
    u64::from_be_bytes(d[0..8].try_into().unwrap())
}

/// 密钥族信息上下文（01 §1.2.3：两端相同即一致）
fn info_ctx(room: &str, a: NodeId, b: NodeId) -> Vec<u8> {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut ctx = Vec::new();
    ctx.extend_from_slice(b"wgp-session");
    ctx.extend_from_slice(room.as_bytes());
    ctx.extend_from_slice(&lo.0);
    ctx.extend_from_slice(&hi.0);
    ctx
}

fn handshake_transcript(
    room: &str,
    tag: u32,
    sender: NodeId,
    receiver: NodeId,
    commitment: &[u8; 16],
    pubkey: &[u8],
    nonce: &[u8; 32],
    sender_session_nonce: &[u8; 16],
    receiver_session_nonce: &[u8; 16],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128 + pubkey.len());
    transcript.extend_from_slice(b"wgp-handshake-transcript-v1\0");
    transcript.push(wgp_proto::sig::SIG_VERSION);
    transcript.extend_from_slice(&room_key(room));
    transcript.extend_from_slice(&tag.to_be_bytes());
    transcript.extend_from_slice(&sender.0);
    transcript.extend_from_slice(&receiver.0);
    transcript.extend_from_slice(commitment);
    transcript.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    transcript.extend_from_slice(pubkey);
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(sender_session_nonce);
    transcript.extend_from_slice(receiver_session_nonce);
    transcript
}

fn endpoint_signing_message(
    room: &str,
    tag: u32,
    sender: NodeId,
    receiver: NodeId,
    endpoints: &frame::Endpoints,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128 + frame::EP_BODY_LEN);
    message.extend_from_slice(b"wgp-endpoints-v1\0");
    message.push(wgp_proto::sig::SIG_VERSION);
    message.extend_from_slice(&(room.len() as u32).to_be_bytes());
    message.extend_from_slice(room.as_bytes());
    message.extend_from_slice(&tag.to_be_bytes());
    message.extend_from_slice(&sender.0);
    message.extend_from_slice(&receiver.0);
    message.extend_from_slice(&endpoints.ipv4);
    message.extend_from_slice(&endpoints.port.to_be_bytes());
    message.push(endpoints.udp_ok as u8);
    message.push(endpoints.tcp_ok as u8);
    message.push(endpoints.has_model as u8);
    message.extend_from_slice(&endpoints.last_port.to_be_bytes());
    message.extend_from_slice(&endpoints.mean_delta_q.to_be_bytes());
    message.push(endpoints.confidence);
    message.extend_from_slice(&endpoints.full_commit);
    message
}

fn reveal_is_authentic(
    room: &str,
    tag: u32,
    sender: NodeId,
    receiver: NodeId,
    expected_peer_id: &[u8; 16],
    expected_identity_key: &[u8; 32],
    reveal: &RevealBody,
    expected_commit: Option<&CommitBody>,
    receiver_session_nonce: &[u8; 16],
) -> bool {
    let computed_commit = make_commit(&reveal.pubkey, &reveal.nonce);
    if &reveal.peer_id != expected_peer_id
        || expected_commit.is_some_and(|commit| {
            commit.commit != reveal.commitment || commit.session_nonce != reveal.session_nonce
        })
        || reveal.peer_session_nonce != *receiver_session_nonce
        || computed_commit.0[..16] != reveal.commitment
    {
        return false;
    }
    let transcript = handshake_transcript(
        room,
        tag,
        sender,
        receiver,
        &reveal.commitment,
        &reveal.pubkey,
        &reveal.nonce,
        &reveal.session_nonce,
        &reveal.peer_session_nonce,
    );
    verify_identity_signature(
        sender,
        expected_identity_key,
        &transcript,
        &reveal.identity_signature,
    )
}

/// 装配线：房间内成员间的全自动会话工厂
pub struct SessionOrchestrator {
    node: Arc<DhtNode>,
    engine: Engine,
    storage: SocketAddr,
    /// 种子的 TCP 信令兜底地址（UDP 被封/受限时同发一份；None = 无 TCP 通道）
    storage_tcp: Option<SocketAddr>,
    observers: Vec<SocketAddr>,
}

impl SessionOrchestrator {
    pub fn new(
        node: Arc<DhtNode>,
        engine: Engine,
        storage: SocketAddr,
        observers: Vec<SocketAddr>,
    ) -> Self {
        Self {
            node,
            engine,
            storage,
            storage_tcp: None,
            observers,
        }
    }

    /// 配置种子的 TCP 信令兜底地址（07 §5：UDP 打不通时的信令降级通道）。
    /// 设置后，信令每次重传同时经 UDP 与 TCP 各投一份（Fire-and-forget + 幂等 accept）。
    pub fn with_tcp_fallback(mut self, storage_tcp: Option<SocketAddr>) -> Self {
        self.storage_tcp = storage_tcp;
        self
    }

    /// 与指定成员建立 mesh 链路（两端对等运行本方法即可）
    pub async fn connect_peer(
        &self,
        room_code: &str,
        peer_node_id: NodeId,
        peer_identity_key: [u8; 32],
        sink: Arc<dyn LinkSink>,
    ) -> Result<(), OrchestratorError> {
        let room_runtime = RoomRuntime::with_transport(
            self.node.clone(),
            self.storage,
            self.node.signaling_transport(),
        );
        let record = room_runtime
            .fetch(room_code)
            .await
            .map_err(|_| OrchestratorError::PeerGone)?;
        let my_node_id = self.node.node_id();
        let local_key = self.node.identity().verifying_key().to_bytes();
        if !record.members.iter().any(|(id, key)| {
            *id == peer_node_id && key.as_slice() == peer_identity_key.as_slice()
        }) || !record.members.iter().any(|(id, key)| {
            *id == my_node_id && key.as_slice() == local_key
        }) {
            return Err(OrchestratorError::Mitm);
        }
        let my_peer_id = peer_id_from_node(&my_node_id);
        let _peer_peer_id = peer_id_from_node(&peer_node_id);
        let tag = session_tag(room_code, my_node_id, peer_node_id);
        let mut rx = self.node.register_session(tag).await;
        // 会话锚点：两端连接起点近似同步（真实部署由 T_offset 对齐代替）
        let session_start = tokio::time::Instant::now();
        /// 双方约定开火时刻（自会话起点起）
        const FIRE_AT_MS: u64 = 3000;

        // —— ① 承诺-揭示 ——
        let ka = X25519Agreement;
        let sk = {
            let mut rng = OsRng;
            ka.keygen(&mut rng)
        };
        let pubkey = ka.pubkey_raw(&sk);
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let my_commit = make_commit(&pubkey, &nonce);
        let mut my_session_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut my_session_nonce);

        let mut commit16 = [0u8; 16];
        commit16.copy_from_slice(&my_commit.0[..16]);
        let my_commit_body = CommitBody {
            peer_id: my_peer_id,
            commit: commit16,
            session_nonce: my_session_nonce,
        };
        let commit_pkt = SigPacket::commit(my_commit_body, ka.algo_id(), 0);
        let expected_peer_id = peer_id_from_node(&peer_node_id);
        let mut peer_commit: Option<CommitBody> = None;
        let mut early_reveal: Option<RevealBody> = None;
        let mut invalid_peer_frame = false;
        if !self
            .exchange(
                &peer_node_id,
                tag,
                &mut rx,
                frame::KIND_SIG,
                &commit_pkt.encode(),
                None,
                |body| match parse_sig(body) {
                    Some(SigBody::Commit(commit)) if commit.peer_id == expected_peer_id => {
                        peer_commit = Some(commit);
                        true
                    }
                    Some(SigBody::Reveal(reveal))
                        if reveal_is_authentic(
                            room_code,
                            tag,
                            peer_node_id,
                            my_node_id,
                            &expected_peer_id,
                            &peer_identity_key,
                            &reveal,
                            None,
                            &my_session_nonce,
                        ) =>
                    {
                        early_reveal = Some(reveal);
                        true
                    }
                    Some(SigBody::Commit(_)) | Some(SigBody::Reveal(_)) => {
                        invalid_peer_frame = true;
                        false
                    }
                    _ => false,
                },
            )
            .await
        {
            return Err(OrchestratorError::PeerGone);
        }
        if invalid_peer_frame {
            return Err(OrchestratorError::Mitm);
        }
        let peer_commit = peer_commit
            .or_else(|| {
                early_reveal.as_ref().map(|reveal| CommitBody {
                    peer_id: reveal.peer_id,
                    commit: reveal.commitment,
                    session_nonce: reveal.session_nonce,
                })
            })
            .ok_or(OrchestratorError::PeerGone)?;

        let transcript = handshake_transcript(
            room_code,
            tag,
            my_node_id,
            peer_node_id,
            &commit16,
            &pubkey,
            &nonce,
            &my_session_nonce,
            &peer_commit.session_nonce,
        );
        let reveal_signature = self.node.identity().sign(&transcript).to_bytes();
        let reveal_pkt = SigPacket::reveal(
            RevealBody {
                peer_id: my_peer_id,
                pubkey: pubkey.clone(),
                nonce,
                session_nonce: my_session_nonce,
                peer_session_nonce: peer_commit.session_nonce,
                commitment: commit16,
                identity_signature: reveal_signature,
            },
            ka.algo_id(),
            0,
        );
        let reveal_bytes = reveal_pkt.encode();
        let peer_reveal = if let Some(reveal) = early_reveal {
            self.send_frame(&peer_node_id, tag, frame::KIND_SIG, &reveal_bytes)
                .await;
            reveal
        } else {
            let mut accepted = None;
            if !self
                .exchange(
                    &peer_node_id,
                    tag,
                    &mut rx,
                    frame::KIND_SIG,
                    &reveal_bytes,
                    None,
                    |body| match parse_sig(body) {
                        Some(SigBody::Reveal(reveal)) => {
                            accepted = Some(reveal);
                            true
                        }
                        _ => false,
                    },
                )
                .await
            {
                return Err(OrchestratorError::PeerGone);
            }
            accepted.ok_or(OrchestratorError::PeerGone)?
        };
        if !reveal_is_authentic(
            room_code,
            tag,
            peer_node_id,
            my_node_id,
            &expected_peer_id,
            &peer_identity_key,
            &peer_reveal,
            Some(&peer_commit),
            &my_session_nonce,
        ) {
            return Err(OrchestratorError::Mitm);
        }
        let peer_pk_raw = peer_reveal.pubkey;
        let peer_nonce = peer_reveal.nonce;

        // 共享密钥
        let shared_bytes = ka.agree(&sk, &peer_pk_raw).ok_or(OrchestratorError::Mitm)?;
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&shared_bytes);

        // —— ② 密钥族派生 + 打洞 socket（学习与打洞同源端口，03 §3.4）——
        let secrets = derive_all(&shared, &info_ctx(room_code, my_node_id, peer_node_id));
        let tag4 = tag.to_be_bytes();
        let carrier = UdpProbeCarrier::bind("0.0.0.0:0".parse().unwrap(), secrets.probe_key, tag4)
            .await
            .map_err(|_| OrchestratorError::NoRoute)?;

        // —— ③ 观察者探测 + 步长学习（复用打洞 socket）——
        let probe = NatProbe::from_socket(carrier.socket());
        let mut my_mapped: Option<([u8; 4], u16)> = None;
        let mut model: Option<PortStepModel> = None;
        let mut first_ok: Option<SocketAddr> = None;
        for &obs in self.observers.iter() {
            // 每次探测用独立随机 txid（审计 M1）：可预测的 txid 让攻击者能提前拼出应答
            let (txid, _nonce) = crate::engine::nat_probe::fresh_probe_ids();
            if let Some(r) = probe.probe_observer(obs, txid, None).await {
                my_mapped = Some((r.ipv4, r.port));
                first_ok = Some(obs);
                break;
            }
        }
        let udp_ok = my_mapped.is_some();
        if let Some(obs) = first_ok {
            model = probe.learn_step(obs, || [0u8; 8]).await;
        }

        // —— ④ 交换端点（含完整承诺复验）——
        let mut my_ep = frame::Endpoints {
            ipv4: my_mapped.map(|(ip, _)| ip).unwrap_or([0u8; 4]),
            port: my_mapped.map(|(_, p)| p).unwrap_or(0),
            udp_ok,
            tcp_ok: true,
            has_model: model.is_some(),
            last_port: model.as_ref().map(|m| m.last_port).unwrap_or(0),
            mean_delta_q: {
                let d = model.as_ref().map(|m| m.mean_delta).unwrap_or(0.0);
                (d * 64.0).round().clamp(-32768.0, 32767.0) as i16
            },
            confidence: model
                .as_ref()
                .map(|m| (m.confidence * 100.0) as u8)
                .unwrap_or(0),
            full_commit: my_commit.0,
            identity_signature: [0; 64],
        };
        let endpoint_transcript =
            endpoint_signing_message(room_code, tag, my_node_id, peer_node_id, &my_ep);
        my_ep.identity_signature = self.node.identity().sign(&endpoint_transcript).to_bytes();
        let ep_bytes = frame::encode_endpoints(&my_ep);

        let mut peer_ep: Option<frame::Endpoints> = None;
        if !self
            .exchange(
                &peer_node_id,
                tag,
                &mut rx,
                frame::KIND_EP,
                &ep_bytes,
                // 对端若还在重发 SIG 帧，说明它没收到我方揭示：补发，否则它永远走不到本阶段
                Some((frame::KIND_SIG, reveal_bytes.as_slice())),
                |body| match frame::parse_endpoints_frame(body) {
                    Some(ep) => {
                        let message =
                            endpoint_signing_message(room_code, tag, peer_node_id, my_node_id, &ep);
                        if verify_identity_signature(
                            peer_node_id,
                            &peer_identity_key,
                            &message,
                            &ep.identity_signature,
                        ) {
                            peer_ep = Some(ep);
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                },
            )
            .await
        {
            return Err(OrchestratorError::PeerGone);
        }
        let peer_ep = peer_ep.ok_or(OrchestratorError::PeerGone)?;

        // 完整承诺复验（128bit 抗 MITM；不匹配 = 有人在中间）
        if !verify_commit(&Commitment(peer_ep.full_commit), &peer_pk_raw, &peer_nonce) {
            return Err(OrchestratorError::Mitm);
        }

        // —— ⑤ 判定 + 组装 ——
        let circuit = CircuitInput {
            udp_egress_ok: Some(udp_ok),
            peer_udp_ok: Some(peer_ep.udp_ok),
            udp_waves_failed: false,
            quic_handshake_timed_out: false,
            carrier_profile_bad: false,
            peer_agrees_tcp: peer_ep.tcp_ok,
        };
        let race_cfg = decide_race(&circuit, true);
        if !race_cfg.udp_on && !race_cfg.tcp_on {
            return Err(OrchestratorError::NoRoute);
        }

        // 撒网预测用「对端模型」（对端测的是它自己 NAT 的映射规律，
        // 由 EP 报告给我方；03 §3.4/§3.5 语义）
        let peer_model = peer_model_from(&peer_ep);

        // TCP 载体（竞速并行；绑定一个保留端口 = punch 源端口）
        let tcp = if race_cfg.tcp_on {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| OrchestratorError::NoRoute)?;
            let local = listener
                .local_addr()
                .map_err(|_| OrchestratorError::NoRoute)?;
            drop(listener);
            let bind: SocketAddr = SocketAddr::new("0.0.0.0".parse().unwrap(), local.port());
            Some(TcpProbeCarrier::new(bind, secrets.probe_key, tag4))
        } else {
            None
        };

        let input = PunchInput {
            peer: peer_id_from_node(&peer_node_id),
            peer_ip: std::net::IpAddr::V4(Ipv4Addr::from(peer_ep.ipv4)),
            carrier,
            tcp,
            udp_enabled: race_cfg.udp_on,
            session_key: SecretBox::new(secrets.session_key),
            model: peer_model,
            seed: punch_seed(room_code, my_node_id, peer_node_id),
        };

        // —— ⑥ 同步开火（相对锚点对齐；双向偏差压缩到会话建立噪声级）——
        let elapsed = session_start.elapsed();
        if elapsed < Duration::from_millis(FIRE_AT_MS) {
            tokio::time::sleep(Duration::from_millis(FIRE_AT_MS) - elapsed).await;
        }
        let _stream = self.engine.new_link(input, sink);

        // —— ⑦ 清理 ——
        self.node.unregister_session(tag).await;
        Ok(())
    }

    /// 被动应答：等待对端向本端发起（或重新发起）协商，收到对端的承诺帧即返回 true。
    ///
    /// `connect_peer` 要求两端在约 4 秒的重传窗口内都在跑；两类情形会错过这个窗口：
    ///  ① 入表时序错位——本端已超时放弃，对端才开始；
    ///  ② 链路断了——先察觉的一端重新发起，另一端还以为链路健在（14 §10 条款 5 重连幂等）。
    /// 外围在没有 `connect_peer` 在跑时挂上本方法，返回 true 就立刻调用 `connect_peer`：
    /// 触发用的那一帧被本方法消费，但对端每 300ms 重传一次，后续帧会被接住。
    ///
    /// `settle`：挂上后的静默期，期间到达的帧一律忽略——刚结束的那轮协商可能还有迟到的
    /// 重传帧在路上，不能把它们误判成新一轮发起（真正的发起会持续重传数秒，不怕错过开头）。
    ///
    /// 返回 false = 本会话的注册已被新的 `connect_peer` 顶替（调用方无需再做什么）。
    /// 注意：本方法会注册会话 tag，**不得**与同一对端的 `connect_peer` 并发调用。
    pub async fn wait_incoming(
        &self,
        room_code: &str,
        peer_node_id: NodeId,
        settle: Duration,
    ) -> bool {
        let tag = session_tag(room_code, self.node.node_id(), peer_node_id);
        let mut rx = self.node.register_session(tag).await;
        let armed_at = tokio::time::Instant::now();
        loop {
            let Some(msg) = rx.recv().await else {
                return false;
            };
            if armed_at.elapsed() < settle {
                continue;
            }
            let Some(body) = msg.payload.get(4..) else {
                continue;
            };
            if matches!(parse_sig(body), Some(SigBody::Commit(_))) {
                return true;
            }
        }
    }

    /// 通用交换：重传本端帧（300ms ×14 ≈ 4.2s），直到对端帧通过 `accept`。
    ///
    /// `stale_reply` = (帧类型, 应答帧体)：本阶段收到对端该类型的帧，说明对端还停在
    /// 更早的阶段（没收到我方对应的帧），就地补发应答，避免对端永远等不到。
    #[allow(clippy::too_many_arguments)]
    async fn exchange(
        &self,
        peer: &NodeId,
        tag: u32,
        rx: &mut mpsc::UnboundedReceiver<ForwardBody>,
        kind: u8,
        body: &[u8],
        stale_reply: Option<(u8, &[u8])>,
        mut accept: impl FnMut(&[u8]) -> bool,
    ) -> bool {
        for _ in 0..14 {
            self.send_frame(peer, tag, kind, body).await;
            // 一个重传周期内逐帧判定：收到无关帧不提前进入下一次重传（否则对端的重传会
            // 成倍消耗本端的重试次数，等待窗口被压缩）
            let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
            while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
                let Some(frame_body) = msg.payload.get(4..) else {
                    continue; // 前 4B 为分派 tag
                };
                if accept(frame_body) {
                    return true;
                }
                if let Some((stale_kind, reply)) = stale_reply {
                    if frame_body.first() == Some(&stale_kind) {
                        self.send_frame(peer, tag, stale_kind, reply).await;
                    }
                }
            }
        }
        false
    }

    /// 发送一帧协商消息：tag(4B，由 DHT 分派层消费) | kind(1B) | body
    async fn send_frame(&self, peer: &NodeId, tag: u32, kind: u8, body: &[u8]) {
        let mut payload = Vec::with_capacity(5 + body.len());
        payload.extend_from_slice(&tag.to_be_bytes());
        payload.push(kind);
        payload.extend_from_slice(body);
        self.send_forward(*peer, &payload).await;
    }

    /// 向种子投递一条"致 peer"的载荷：UDP 为主；配置了 TCP 兜底时同发一份。
    /// 两条通道语义一致（种子按地址簿转发 / 长度前缀帧），上层 accept 幂等，重投无副作用。
    async fn send_forward(&self, peer: NodeId, payload: &[u8]) {
        let _ = self
            .node
            .forward_to(self.storage, peer, payload.to_vec())
            .await;
        if let Some(tcp) = self.storage_tcp {
            let _ = self.node.forward_tcp(tcp, peer, payload.to_vec()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rank::LinkRank;
    use crate::types::{LinkSink, RoomCode};
    use rand_core::OsRng;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use wgp_dht::{DhtNode, NodeIdentity, ObserverServer};

    /// 收集交付（计数 + 记录 rank）
    struct CountSink {
        count: AtomicUsize,
        ranks: Mutex<Vec<LinkRank>>,
    }

    impl LinkSink for CountSink {
        fn on_link_yielded(&self, _peer: crate::PeerId, link: crate::link::PunchedLink) {
            self.count.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut r) = self.ranks.try_lock() {
                r.push(link.rank);
            }
        }
        fn on_link_upgraded(&self, _peer: crate::PeerId, _link: crate::link::PunchedLink) {}
        fn on_link_lost(&self, _peer: crate::PeerId, _cause: crate::LinkLossCause) {}
    }

    struct TestClient {
        node: Arc<DhtNode>,
        engine: Engine,
        orchestrator: SessionOrchestrator,
    }

    async fn spawn_client(seed_addr: SocketAddr, observers: Vec<SocketAddr>) -> TestClient {
        let mut rng = OsRng;
        let id = NodeIdentity::generate(&mut rng);
        let node = DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        node.ping(seed_addr).await.expect("认识种子");
        let (engine, _ev) = Engine::new();
        engine.attach_dht(node.clone(), seed_addr).await;
        let orchestrator =
            SessionOrchestrator::new(node.clone(), engine.clone(), seed_addr, observers);
        TestClient {
            node,
            engine,
            orchestrator,
        }
    }

    /// 端到端：种子(观察者) + 双客户端全自动装配——从空房间到双边 PunchedLink。
    #[tokio::test]
    async fn two_clients_auto_punch_full_pipeline() {
        // —— 种子进程（wgp-node 同构：DHT + 观察者一面）——
        let seed = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap()
        };
        let seed_addr = seed.local_addr().unwrap();
        let observer = ObserverServer::bind(0).await.expect("观察者启动");
        let observer_addr: SocketAddr =
            format!("127.0.0.1:{}", observer.local_addr().unwrap().port())
                .parse()
                .unwrap();

        // —— 客户端 A（房主）——
        let a = spawn_client(seed_addr, vec![observer_addr]).await;
        // —— 客户端 B ——
        let b = spawn_client(seed_addr, vec![observer_addr]).await;

        const ROOM: &str = "U/E2E-FULL-0001-DD55";

        // A 建房 → B 入表
        let _ha = a
            .engine
            .join_room(RoomCode(ROOM.to_string()), None)
            .await
            .expect("A 建房");
        // 让 B 在成员表就绪
        let mut joined = false;
        for _ in 0..20 {
            if let Ok(h) = b.engine.join_room(RoomCode(ROOM.to_string()), None).await {
                joined = true;
                let _ = h;
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        assert!(joined, "B 应加入房间");

        // —— 双方同时启动装配（对等对称）——
        let sink_a = Arc::new(CountSink {
            count: AtomicUsize::new(0),
            ranks: Mutex::new(Vec::new()),
        });
        let sink_b = Arc::new(CountSink {
            count: AtomicUsize::new(0),
            ranks: Mutex::new(Vec::new()),
        });

        let (a_node_id, b_node_id) = (a.node.node_id(), b.node.node_id());
        let (a_identity_key, b_identity_key) = (
            a.node.identity().verifying_key().to_bytes(),
            b.node.identity().verifying_key().to_bytes(),
        );
        let oa = {
            let orch = a.orchestrator;
            let sink = sink_a.clone();
            tokio::spawn(async move {
                orch.connect_peer(ROOM, b_node_id, b_identity_key, sink)
                    .await
            })
        };
        let ob = {
            let orch = b.orchestrator;
            let sink = sink_b.clone();
            tokio::spawn(async move {
                orch.connect_peer(ROOM, a_node_id, a_identity_key, sink)
                    .await
            })
        };

        let (ra, rb) = tokio::join!(oa, ob);
        assert!(matches!(&ra, Ok(Ok(()))), "A 侧装配应成功, got={ra:?}");
        assert!(matches!(&rb, Ok(Ok(()))), "B 侧装配应成功, got={rb:?}");

        // —— 双边交付断言（竞速 ≤ 5s 内）——
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if sink_a.count.load(Ordering::SeqCst) >= 1 && sink_b.count.load(Ordering::SeqCst) >= 1
            {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(sink_a.count.load(Ordering::SeqCst) >= 1, "A 应收到链路交付");
        assert!(sink_b.count.load(Ordering::SeqCst) >= 1, "B 应收到链路交付");

        // rank 断言：loopback 双栈全通 → Primary（UDP 命中）
        let ra_ranks = sink_a.ranks.lock().await;
        assert!(
            ra_ranks.iter().all(|r| *r == LinkRank::Primary),
            "loopback 无障碍应 UDP 主档直连"
        );
        drop(ra_ranks);

        let _ = observer;
    }

    /// 被动应答：A 先发起并超时放弃之前，B 并没有在跑 connect_peer——B 只挂着
    /// wait_incoming。B 被 A 的承诺帧触发后再调用 connect_peer，双方仍能完成装配并各自收到交付。
    #[tokio::test]
    async fn passive_side_is_woken_by_peer_commit() {
        let seed = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap()
        };
        let seed_addr = seed.local_addr().unwrap();
        let observer = ObserverServer::bind(0).await.expect("观察者启动");
        let observer_addr: SocketAddr =
            format!("127.0.0.1:{}", observer.local_addr().unwrap().port())
                .parse()
                .unwrap();
        let a = spawn_client(seed_addr, vec![observer_addr]).await;
        let b = spawn_client(seed_addr, vec![observer_addr]).await;
        const ROOM: &str = "U/PASSIVE-0001-EE66";
        let _a_room = a
            .engine
            .join_room(RoomCode(ROOM.to_string()), None)
            .await
            .expect("A 建房");
        let mut b_joined = false;
        for _ in 0..20 {
            if b
                .engine
                .join_room(RoomCode(ROOM.to_string()), None)
                .await
                .is_ok()
            {
                b_joined = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(b_joined, "B 应入房间成员表");
        let (a_node_id, b_node_id) = (a.node.node_id(), b.node.node_id());
        let (a_identity_key, b_identity_key) = (
            a.node.identity().verifying_key().to_bytes(),
            b.node.identity().verifying_key().to_bytes(),
        );

        let sink_a = Arc::new(CountSink {
            count: AtomicUsize::new(0),
            ranks: Mutex::new(Vec::new()),
        });
        let sink_b = Arc::new(CountSink {
            count: AtomicUsize::new(0),
            ranks: Mutex::new(Vec::new()),
        });

        // B：先只监听；被触发后才进入正式协商
        let b_task = {
            let orch = b.orchestrator;
            let sink = sink_b.clone();
            tokio::spawn(async move {
                let woken = orch
                    .wait_incoming(ROOM, a_node_id, Duration::from_millis(0))
                    .await;
                assert!(woken, "B 应被 A 的承诺帧唤醒");
                orch.connect_peer(ROOM, a_node_id, a_identity_key, sink)
                    .await
            })
        };
        // 让 B 先挂上监听，再由 A 发起
        tokio::time::sleep(Duration::from_millis(200)).await;
        let a_result = a
            .orchestrator
            .connect_peer(ROOM, b_node_id, b_identity_key, sink_a.clone())
            .await;
        assert!(a_result.is_ok(), "A 侧装配应成功, got={a_result:?}");
        let b_result = b_task.await.unwrap();
        assert!(b_result.is_ok(), "B 侧装配应成功, got={b_result:?}");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline
            && (sink_a.count.load(Ordering::SeqCst) == 0
                || sink_b.count.load(Ordering::SeqCst) == 0)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(sink_a.count.load(Ordering::SeqCst) >= 1, "A 应收到链路交付");
        assert!(sink_b.count.load(Ordering::SeqCst) >= 1, "B 应收到链路交付");
        let _ = observer;
    }

    #[test]
    fn transcript_signatures_reject_relay_tampering() {
        let signer = NodeIdentity::from_seed([0x41; 32]);
        let expected_peer = signer.node_id();
        let receiver = NodeIdentity::from_seed([0x42; 32]);
        let tag = session_tag("room-key", expected_peer, receiver.node_id());
        let public_key = signer.verifying_key().to_bytes();
        let sender_nonce = [0x55; 16];
        let receiver_nonce = [0x66; 16];
        let ephemeral_key = vec![0x77; 32];
        let reveal_nonce = [0x88; 32];
        let full_commit = make_commit(&ephemeral_key, &reveal_nonce);
        let mut commit_hash = [0u8; 16];
        commit_hash.copy_from_slice(&full_commit.0[..16]);
        let transcript = handshake_transcript(
            "room-key",
            tag,
            expected_peer,
            receiver.node_id(),
            &commit_hash,
            &ephemeral_key,
            &reveal_nonce,
            &sender_nonce,
            &receiver_nonce,
        );
        let signature = signer.sign(&transcript).to_bytes();
        let reveal = RevealBody {
            peer_id: peer_id_from_node(&expected_peer),
            pubkey: ephemeral_key.clone(),
            nonce: reveal_nonce,
            session_nonce: sender_nonce,
            peer_session_nonce: receiver_nonce,
            commitment: commit_hash,
            identity_signature: signature,
        };
        let commit = CommitBody {
            peer_id: reveal.peer_id,
            commit: commit_hash,
            session_nonce: sender_nonce,
        };
        assert!(reveal_is_authentic(
            "room-key",
            tag,
            expected_peer,
            receiver.node_id(),
            &peer_id_from_node(&expected_peer),
            &public_key,
            &reveal,
            Some(&commit),
            &receiver_nonce,
        ));
        assert!(!reveal_is_authentic(
            "other-room",
            tag,
            expected_peer,
            receiver.node_id(),
            &peer_id_from_node(&expected_peer),
            &public_key,
            &reveal,
            Some(&commit),
            &receiver_nonce,
        ));

        let mut tampered_key = reveal.clone();
        tampered_key.pubkey[0] ^= 1;
        assert!(!reveal_is_authentic(
            "room-key",
            tag,
            expected_peer,
            receiver.node_id(),
            &peer_id_from_node(&expected_peer),
            &public_key,
            &tampered_key,
            Some(&commit),
            &receiver_nonce,
        ));
        let mut tampered_nonce = reveal.clone();
        tampered_nonce.peer_session_nonce[0] ^= 1;
        assert!(!reveal_is_authentic(
            "room-key",
            tag,
            expected_peer,
            receiver.node_id(),
            &peer_id_from_node(&expected_peer),
            &public_key,
            &tampered_nonce,
            Some(&commit),
            &receiver_nonce,
        ));
        let mut wrong_key = public_key;
        wrong_key[0] ^= 1;
        assert!(!reveal_is_authentic(
            "room-key",
            tag,
            expected_peer,
            receiver.node_id(),
            &peer_id_from_node(&expected_peer),
            &wrong_key,
            &reveal,
            Some(&commit),
            &receiver_nonce,
        ));

        let mut endpoints = frame::Endpoints {
            ipv4: [1, 2, 3, 4],
            port: 12345,
            udp_ok: true,
            tcp_ok: false,
            has_model: false,
            last_port: 0,
            mean_delta_q: 0,
            confidence: 0,
            full_commit: [0x99; 32],
            identity_signature: [0; 64],
        };
        let endpoint_message = endpoint_signing_message(
            "room-key",
            tag,
            expected_peer,
            receiver.node_id(),
            &endpoints,
        );
        endpoints.identity_signature = signer.sign(&endpoint_message).to_bytes();
        assert!(verify_identity_signature(
            expected_peer,
            &public_key,
            &endpoint_signing_message(
                "room-key",
                tag,
                expected_peer,
                receiver.node_id(),
                &endpoints,
            ),
            &endpoints.identity_signature,
        ));
        endpoints.port ^= 1;
        assert!(!verify_identity_signature(
            expected_peer,
            &public_key,
            &endpoint_signing_message(
                "room-key",
                tag,
                expected_peer,
                receiver.node_id(),
                &endpoints,
            ),
            &endpoints.identity_signature,
        ));
    }

    #[test]
    fn peer_model_falls_back_to_observed_port() {
        let base = frame::Endpoints {
            ipv4: [1, 2, 3, 4],
            port: 40123,
            udp_ok: true,
            tcp_ok: true,
            has_model: false,
            last_port: 0,
            mean_delta_q: 0,
            confidence: 0,
            full_commit: [0; 32],
            identity_signature: [0; 64],
        };
        // 无模型但有实测端口 → 以实测端口为中心建模，三波首包直打该端口
        let model = peer_model_from(&base).expect("应兜底建模");
        assert_eq!(model.last_port, 40123);
        let plan = wgp_punch::plan_waves(Some(&model), 7, 47);
        assert_eq!(plan.wave1.first(), Some(&40123));

        // 有模型：照搬对端报告
        let learned = frame::Endpoints {
            has_model: true,
            last_port: 50_000,
            mean_delta_q: 3 * 64,
            confidence: 90,
            ..base
        };
        let model = peer_model_from(&learned).unwrap();
        assert_eq!(model.last_port, 50_000);
        assert!((model.mean_delta - 3.0).abs() < 1e-9);
        assert!((model.confidence - 0.9).abs() < 1e-9);

        // UDP 不通 / 没有端口：无从预测
        assert!(peer_model_from(&frame::Endpoints {
            udp_ok: false,
            ..base
        })
        .is_none());
        assert!(peer_model_from(&frame::Endpoints { port: 0, ..base }).is_none());
    }

    /// 端点帧/承诺帧体来自网络，任何长度都必须安全解析（回归：空帧体曾触发切片越界 panic）
    #[test]
    fn frame_parsers_never_panic_on_short_input() {
        assert!(frame::parse_endpoints_frame(&[]).is_none());
        assert!(frame::parse_endpoints_frame(&[frame::KIND_EP]).is_none());
        assert!(frame::parse_endpoints_frame(&[frame::KIND_EP, 1, 2, 3]).is_none());
        // kind 不符：即使长度恰好也不当作端点帧
        let mut wrong_kind = vec![frame::KIND_SIG];
        wrong_kind.extend_from_slice(&[0u8; frame::EP_BODY_LEN]);
        assert!(frame::parse_endpoints_frame(&wrong_kind).is_none());
        let mut ok = vec![frame::KIND_EP];
        ok.extend_from_slice(&[0u8; frame::EP_BODY_LEN]);
        assert!(frame::parse_endpoints_frame(&ok).is_some());

        assert!(parse_sig(&[]).is_none());
        assert!(parse_sig(&[frame::KIND_SIG]).is_none());
        assert!(parse_sig(&[frame::KIND_EP, 0, 0]).is_none());
    }

    /// 静默期内到达的帧（上一轮协商的迟到重传）不得触发；非承诺帧任何时候都不触发。
    #[tokio::test]
    async fn wait_incoming_ignores_stale_and_non_commit_frames() {
        let seed = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap()
        };
        let seed_addr = seed.local_addr().unwrap();
        let a = spawn_client(seed_addr, vec![]).await;
        let b = spawn_client(seed_addr, vec![]).await;
        const ROOM: &str = "U/PASSIVE-0002-FF77";
        let (a_node_id, b_node_id) = (a.node.node_id(), b.node.node_id());
        let tag = session_tag(ROOM, a_node_id, b_node_id);

        let commit_payload = {
            let pkt = SigPacket::commit(
                CommitBody {
                    peer_id: peer_id_from_node(&a_node_id),
                    commit: [0x11; 16],
                    session_nonce: [0x22; 16],
                },
                X25519Agreement.algo_id(),
                0,
            );
            let mut p = tag.to_be_bytes().to_vec();
            p.push(frame::KIND_SIG);
            p.extend_from_slice(&pkt.encode());
            p
        };
        let endpoint_payload = {
            let mut p = tag.to_be_bytes().to_vec();
            p.push(frame::KIND_EP);
            p.extend_from_slice(&[0u8; frame::EP_BODY_LEN]);
            p
        };

        let b_orch = b.orchestrator;
        let waiter = tokio::spawn(async move {
            b_orch
                .wait_incoming(ROOM, a_node_id, Duration::from_millis(600))
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 静默期内的承诺帧 + 任意时刻的端点帧：都不应触发
        a.orchestrator
            .send_forward(b_node_id, &commit_payload)
            .await;
        tokio::time::sleep(Duration::from_millis(700)).await;
        a.orchestrator
            .send_forward(b_node_id, &endpoint_payload)
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!waiter.is_finished(), "静默期内的帧与非承诺帧不得触发");

        // 静默期过后的承诺帧：触发
        a.orchestrator
            .send_forward(b_node_id, &commit_payload)
            .await;
        let woken = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("应被触发")
            .unwrap();
        assert!(woken);
    }

    /// TCP 信令兜底：UDP 种子地址不可达（黑洞端口）时，
    /// 装配线仍能经 TCP 种子把信令送达对端（种子→目标腿走 UDP）。
    #[tokio::test]
    async fn tcp_fallback_signaling_route() {
        // 种子：UDP + TCP 双面
        let seed = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap()
        };
        let seed_tcp = seed
            .listen_tcp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // 目标端 B：与种子经 UDP 互认（地址簿才有 B 的 UDP 端点）
        let b = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap()
        };
        b.ping(seed.local_addr().unwrap()).await.unwrap();

        // 发送端 A：storage（UDP）指向黑洞；TCP 兜底指向种子
        let a = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap()
        };
        let (engine, _ev) = Engine::new();
        let dead_udp: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let orch = SessionOrchestrator::new(a.clone(), engine, dead_udp, vec![])
            .with_tcp_fallback(Some(seed_tcp));

        let payload = vec![0x42u8; 16];
        orch.send_forward(b.node_id(), &payload).await;

        let got = tokio::time::timeout(Duration::from_millis(1500), b.recv_forward())
            .await
            .expect("TCP 兜底应送达")
            .expect("载荷非空");
        assert_eq!(got.payload, payload);
    }
}
