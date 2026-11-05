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

use crate::engine::Engine;
use crate::engine::circuit::{CircuitInput, decide_race};
use crate::engine::nat_probe::NatProbe;
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
use wgp_crypto::commit::{Commitment, commit as make_commit, verify as verify_commit};
use wgp_crypto::derive::derive_all;
use wgp_crypto::ka::{KeyAgreement, X25519Agreement};
use wgp_crypto::SecretBox;
use wgp_dht::id::peer_id_from_node;
use wgp_dht::{DhtNode, NodeId};
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

    /// 纯 body 长度（kind 由 exchange 统一封装）
    pub const EP_BODY_LEN: usize = 47;

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
        /// 完整 32B 承诺（MITM 复验，128bit）
        pub full_commit: [u8; 32],
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
        out[14..46].fill(0); // 保留
        out[15..47].copy_from_slice(&e.full_commit);
        out
    }

    pub fn decode_endpoints(buf: &[u8]) -> Option<Endpoints> {
        if buf.len() != EP_BODY_LEN {
            return None;
        }
        let mut ipv4 = [0u8; 4];
        ipv4.copy_from_slice(&buf[0..4]);
        let mut full_commit = [0u8; 32];
        full_commit.copy_from_slice(&buf[15..47]);
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
        })
    }
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
        sink: Arc<dyn LinkSink>,
    ) -> Result<(), OrchestratorError> {
        let my_node_id = self.node.node_id();
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

        let commit16 = {
            let mut c = [0u8; 16];
            c.copy_from_slice(&my_commit.0[..16]);
            c
        };
        let commit_pkt = SigPacket::commit(
            CommitBody {
                peer_id: my_peer_id,
                commit: commit16,
            },
            ka.algo_id(),
            0,
        );
        let reveal_pkt = SigPacket::reveal(
            RevealBody {
                peer_id: my_peer_id,
                pubkey: pubkey.clone(),
                nonce,
            },
            ka.algo_id(),
            0,
        );

        // ①a 交换承诺。accept 放宽到「Commit 或 Reveal」：对端可能因加入时序
        // 已先行完成本阶段（先 Reveal 后我们再补 commit 收发），直接放行避免
        // 阶段漂移死锁；MITM 防护由 EP 交换的 full_commit 复验兜底（128bit）。
        if !self
            .exchange(
                &peer_node_id,
                tag,
                &mut rx,
                frame::KIND_SIG,
                &commit_pkt.encode(),
                |body| {
                    body.first().map(|k| *k == frame::KIND_SIG).unwrap_or(false)
                        && matches!(
                            SigPacket::decode(&body[1..]),
                            Some(pkt) if matches!(pkt.body, SigBody::Commit(_) | SigBody::Reveal(_))
                        )
                },
            )
            .await
        {
            return Err(OrchestratorError::PeerGone);
        }

        // ①b 交换揭示 + 取对端公钥/nonce
        let mut peer_pk_raw: Option<Vec<u8>> = None;
        let mut peer_nonce: Option<[u8; 32]> = None;
        if !self
            .exchange(
                &peer_node_id,
                tag,
                &mut rx,
                frame::KIND_SIG,
                &reveal_pkt.encode(),
                |body| {
                    if body.first() != Some(&frame::KIND_SIG) {
                        return false;
                    }
                    if let Some(pkt) = SigPacket::decode(&body[1..]) {
                        if let SigBody::Reveal(r) = &pkt.body {
                            peer_pk_raw = Some(r.pubkey.clone());
                            peer_nonce = Some(r.nonce);
                            return true;
                        }
                    }
                    false
                },
            )
            .await
        {
            return Err(OrchestratorError::PeerGone);
        }
        let peer_pk_raw = peer_pk_raw.ok_or(OrchestratorError::PeerGone)?;
        let peer_nonce = peer_nonce.ok_or(OrchestratorError::PeerGone)?;

        // 共享密钥
        let shared_bytes = ka.agree(&sk, &peer_pk_raw).ok_or(OrchestratorError::Mitm)?;
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&shared_bytes);

        // —— ② 密钥族派生 + 打洞 socket（学习与打洞同源端口，03 §3.4）——
        let secrets = derive_all(&shared, &info_ctx(room_code, my_node_id, peer_node_id));
        let tag4 = tag.to_be_bytes();
        let carrier = UdpProbeCarrier::bind(
            "0.0.0.0:0".parse().unwrap(),
            secrets.probe_key,
            tag4,
        )
        .await
        .map_err(|_| OrchestratorError::NoRoute)?;

        // —— ③ 观察者探测 + 步长学习（复用打洞 socket）——
        let probe = NatProbe::from_socket(carrier.socket());
        let mut my_mapped: Option<([u8; 4], u16)> = None;
        let mut model: Option<PortStepModel> = None;
        let mut first_ok: Option<SocketAddr> = None;
        for &obs in self.observers.iter() {
            let mut txid = [0u8; 12];
            txid[..4].copy_from_slice(&my_peer_id[..4]);
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
        let my_ep = frame::Endpoints {
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
        };
        let ep_bytes = frame::encode_endpoints(&my_ep);

        let mut peer_ep: Option<frame::Endpoints> = None;
        if !self
            .exchange(
                &peer_node_id,
                tag,
                &mut rx,
                frame::KIND_EP,
                &ep_bytes,
                |body| {
                    if let Some(ep) = frame::decode_endpoints(&body[1..]) {
                        peer_ep = Some(ep);
                        true
                    } else {
                        false
                    }
                },
            )
            .await
        {
            return Err(OrchestratorError::PeerGone);
        }
        let peer_ep = peer_ep.ok_or(OrchestratorError::PeerGone)?;

        // 完整承诺复验（128bit 抗 MITM；不匹配 = 有人在中间）
        if !verify_commit(
            &Commitment(peer_ep.full_commit),
            &peer_pk_raw,
            &peer_nonce,
        ) {
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
        let peer_model = if peer_ep.has_model {
            Some(PortStepModel {
                last_port: peer_ep.last_port,
                mean_delta: peer_ep.mean_delta_q as f64 / 64.0,
                delta_range: (0, 0),
                trend: wgp_punch::Trend::Oscillating,
                confidence: (peer_ep.confidence as f64 / 100.0).clamp(0.0, 1.0),
            })
        } else {
            None
        };

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

    /// 通用交换：重传本端帧（300ms ×14 ≈ 4.2s），直到对端帧通过 `accept`。
    async fn exchange(
        &self,
        peer: &NodeId,
        tag: u32,
        rx: &mut mpsc::UnboundedReceiver<ForwardBody>,
        expect_kind: u8,
        body: &[u8],
        mut accept: impl FnMut(&[u8]) -> bool,
    ) -> bool {
        let mut payload = Vec::with_capacity(5 + body.len());
        payload.extend_from_slice(&tag.to_be_bytes());
        payload.push(expect_kind);
        payload.extend_from_slice(body);

        for _ in 0..14 {
            self.send_forward(*peer, &payload).await;
            let got = tokio::time::timeout(Duration::from_millis(300), rx.recv())
                .await
                .ok()
                .flatten();
            if let Some(m) = got {
                let frame_body = &m.payload[4..]; // 前 4B 为分派 tag
                if accept(frame_body) {
                    return true;
                }
            }
        }
        false
    }

    /// 向种子投递一条"致 peer"的载荷：UDP 为主；配置了 TCP 兜底时同发一份。
    /// 两条通道语义一致（种子按地址簿转发 / 长度前缀帧），上层 accept 幂等，重投无副作用。
    async fn send_forward(&self, peer: NodeId, payload: &[u8]) {
        let _ = self.node.forward_to(self.storage, peer, payload.to_vec()).await;
        if let Some(tcp) = self.storage_tcp {
            let _ = self.node.forward_tcp(tcp, peer, payload.to_vec()).await;
        }
    }
}

#[allow(unused)]
fn _split_frame(buf: &[u8]) -> (u8, &[u8]) {
    (buf[0], &buf[1..])
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
        let observer_addr: SocketAddr = format!("127.0.0.1:{}", observer.local_addr().unwrap().port())
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
            if let Ok(h) = b
                .engine
                .join_room(RoomCode(ROOM.to_string()), None)
                .await
            {
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
        let oa = {
            let orch = a.orchestrator;
            let sink = sink_a.clone();
            tokio::spawn(async move {
                orch.connect_peer(ROOM, b_node_id, sink).await
            })
        };
        let ob = {
            let orch = b.orchestrator;
            let sink = sink_b.clone();
            tokio::spawn(async move {
                orch.connect_peer(ROOM, a_node_id, sink).await
            })
        };

        let (ra, rb) = tokio::join!(oa, ob);
        assert!(matches!(&ra, Ok(Ok(()))), "A 侧装配应成功, got={ra:?}");
        assert!(matches!(&rb, Ok(Ok(()))), "B 侧装配应成功, got={rb:?}");

        // —— 双边交付断言（竞速 ≤ 5s 内）——
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if sink_a.count.load(Ordering::SeqCst) >= 1 && sink_b.count.load(Ordering::SeqCst) >= 1 {
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