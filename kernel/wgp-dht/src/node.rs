//! Kademlia 网络栈（07 文档自研 DHT 的运行时）。
//!
//! 学习语义：仅 PING/PONG 双向学习（sender_id ↔ src 入地址簿）；
//! Forward 不做身份学习（防垃圾投递毒化地址簿），fire-and-forget 邮件语义，
//! 上层信令自持超时重发（sig::Commit REQUIRE_ACK / 3s 超时）。
//!
//! 种子发现（07 §5 第③层 / 17 P0）：公网节点把自己的签名广告周期推给已知种子；任何节点都可以
//! 向别人索取它已知的种子广告（FIND_SEEDS）。一条广告要进种子目录，必须验签通过，并且广告主
//! 确实在所报地址上应答 PING。P0 不做信任评分：目录里的种子只代表「存在且可达」，不代表可信。

use crate::advertise::{sign_advertise_v2, verify_advertise_v2, AdvertiseSpec};
use crate::directory::{advert_addr, RawAdvert, SeedDirectory, SeedInfo, Verdict};
use crate::id::{node_id_from_verifying, NodeId, NodeIdentity};
use crate::kbucket::RoutingTable;
use ed25519_dalek::VerifyingKey;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Semaphore};
use tokio::task::JoinSet;
use wgp_proto::dht::{
    FindNodeBody, FindSeedsBody, FindValueBody, ForwardBody, NeighborsBody, NodeEntry, PingBody, RpcBody,
    RpcPacket, SeedsBody, StoreBody, ValueBody, SEEDS_MAX,
};
use wgp_proto::packet::{classify, seed_advertise_v2, SeedAdvertiseV2};

/// RPC 超时/失败
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    Timeout,
    NoRoute,
    PayloadTooLarge,
}

/// PONG 应答信息（ping 的返回值：对方身份 + 返回地址）
#[derive(Debug, Clone, Copy)]
pub struct PongInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
}

/// 单帧上限（DHT 包最大 ~1080B：STORE_VALUE_MAX 1024 + 头部开销）
const MAX_TCP_FRAME: usize = 4096;
/// TCP 信令并发连接上限（家庭带宽/公网单机都能扛；超限直接拒连）
const MAX_TCP_CONN: usize = 512;
/// TCP 连接空闲超时（防慢连接长期占用名额）
const TCP_IDLE_TIMEOUT_S: u64 = 30;
/// TCP RPC 单次往返超时（与 UDP RPC 一致）
const TCP_RPC_TIMEOUT_MS: u64 = 1500;
/// UDP 读缓冲上限（RPC 最大 ~1130B：StoreBody 前缀 98 + 值 1024 + 头 7）
const MAX_UDP_DATAGRAM: usize = 2048;
/// 地址簿条目上限（防伪造身份洪流撑爆内存；超限触发过期清扫）
const ADDR_BOOK_MAX: usize = 4096;
/// 地址簿条目静默过期（远超正常重 PING 周期；被清者下次 PING 即复原）
const ADDR_BOOK_TTL: Duration = Duration::from_secs(1800);
/// KV 存储条目上限（房间记录宿主；超限先清最旧腾位）
const KV_MAX_ENTRIES: usize = 4096;
/// KV 条目写入时间戳（用于 TTL 清扫与最旧淘汰）
type KvEntry = (Vec<u8>, Instant);

// —— 种子发现（17 P0） ——
/// 存活复验的并发上限（每条新广告触发一次 PING；超出即丢弃，等广告主下一轮重发）
const VERIFY_CONCURRENCY: usize = 8;
/// 主动推送来的广告每秒最多验签多少条（挡住用广告洪流消耗 CPU；超出静默丢弃）
const ADVERT_VERIFY_PER_SEC: u32 = 64;
/// 用户配置的入口端点数上限
const PINNED_MAX: usize = 16;
/// 维护节拍：探活已知种子（也是本端到种子的 NAT 映射保活周期）
const MAINTAIN_TICK: Duration = Duration::from_secs(20);
/// 每多少拍推送一次自己的广告（60s）
const ADVERTISE_EVERY_TICKS: u32 = 3;
/// 每多少拍向已知种子重新索取一次目录（5min），学到后来加入的节点
const PULL_EVERY_TICKS: u32 = 15;
/// 一次引导 / 补全最多向多少个节点索取种子广告
const DISCOVER_MAX_ASKS: usize = 8;
/// 迭代节点查找：每轮并发数 / 最多轮数 / 最多接触的节点数
const LOOKUP_ALPHA: usize = 3;
const LOOKUP_MAX_ROUNDS: usize = 4;
const LOOKUP_MAX_CONTACTS: usize = 12;

/// 应答投递出口：UDP 回源地址 / TCP 连接的写端。
///
/// 关键：TCP 连接携带的源 IP:port 与 UDP NAT 映射**无关**（TCP 源端口 ≠ UDP 源端口），
/// 若把 TCP 源地址写进地址簿，会把 Forward 中转指向错误的 UDP 端口。
/// 因此 TCP 入站只入路由表（身份存在性），绝不写地址簿。
#[derive(Clone)]
enum Sink {
    Udp(SocketAddr),
    Tcp(mpsc::UnboundedSender<Vec<u8>>),
}

impl Sink {
    fn udp_addr(&self) -> Option<SocketAddr> {
        match self {
            Sink::Udp(a) => Some(*a),
            Sink::Tcp(_) => None,
        }
    }
}

enum Pending {
    Pong(oneshot::Sender<PongInfo>),
    Neighbors(oneshot::Sender<Vec<NodeEntry>>),
    Value(oneshot::Sender<ValueBody>),
    StoreAck(oneshot::Sender<()>),
    Seeds(oneshot::Sender<Vec<RawAdvert>>),
}

/// 中继策略（07 §6 贡献模式：家庭带宽节点拒绝 Forward 中转——
/// 中转是唯一可能产生持续流量进而被运营商判 PCDN 的路径）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicy {
    /// 完整节点：允许中转
    Allow,
    /// 贡献模式：只收发自己的消息，不做中转
    Deny,
}

/// DHT 节点：路由表 + 地址簿 + KV 存储 + RPC 收发（bind 即启动读循环）
pub struct DhtNode {
    socket: Arc<UdpSocket>,
    identity: Arc<NodeIdentity>,
    routing: Mutex<RoutingTable>,
    /// 已知 UDP 端点（带最后见时刻；容量上限 + 过期清扫，防伪造洪流撑爆）
    addr_book: Mutex<HashMap<NodeId, (SocketAddr, Instant)>>,
    /// KV 存储（带写入时刻；条目数上限 + 最旧淘汰，防无界内存增长）
    kv: Mutex<HashMap<[u8; 32], KvEntry>>,
    txid: AtomicU32,
    pending: Mutex<HashMap<u32, Pending>>,
    /// 会话分派表：payload 首 4B session_tag → 会话处理队列
    /// （装配线协商消息按 tag 分流；tag=0 / 未注册 → 默认队列，房间管理用）
    sessions: Mutex<HashMap<u32, mpsc::UnboundedSender<ForwardBody>>>,
    /// 默认收件队列（有界：forward 洪流在队满时静默丢弃，符合邮件语义）
    inbox_tx: mpsc::Sender<ForwardBody>,
    inbox_rx: Mutex<mpsc::Receiver<ForwardBody>>,
    /// 中继开关（默认 Allow；贡献模式置 Deny）
    relay_allow: AtomicBool,
    /// 种子目录（17 P0：验签 + 存活复验后入表）
    seeds: Mutex<SeedDirectory>,
    /// 目录变更通知（值 = 变更代数）
    seeds_gen: watch::Sender<u64>,
    /// 正在做存活复验的广告主（去重：同一广告主同时只探一次）
    verifying: Mutex<HashSet<NodeId>>,
    verify_slots: Arc<Semaphore>,
    /// 推送广告的验签限速（窗口起点, 窗口内已验条数）
    advert_gate: Mutex<(Instant, u32)>,
    /// 用户显式配置的入口端点（--seed / --peers）
    pinned: Mutex<HashSet<SocketAddr>>,
    /// 本节点的广告原文（None = 不宣告：NAT 后的客户端）
    own_advert: Mutex<Option<RawAdvert>>,
    /// 维护循环是否已启动
    maintaining: AtomicBool,
}

/// 默认收件队列容量
const INBOX_CAP: usize = 512;

impl DhtNode {
    pub async fn bind(identity: NodeIdentity, local: SocketAddr) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(local).await?);
        let identity = Arc::new(identity);
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX_CAP);

        let node = Arc::new(Self {
            socket: socket.clone(),
            routing: Mutex::new(RoutingTable::new(identity.node_id())),
            identity: identity.clone(),
            addr_book: Mutex::new(HashMap::new()),
            kv: Mutex::new(HashMap::new()),
            txid: AtomicU32::new(0),
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            inbox_tx,
            inbox_rx: Mutex::new(inbox_rx),
            relay_allow: AtomicBool::new(true),
            seeds: Mutex::new(SeedDirectory::new()),
            seeds_gen: watch::channel(0u64).0,
            verifying: Mutex::new(HashSet::new()),
            verify_slots: Arc::new(Semaphore::new(VERIFY_CONCURRENCY)),
            advert_gate: Mutex::new((Instant::now(), 0)),
            pinned: Mutex::new(HashSet::new()),
            own_advert: Mutex::new(None),
            maintaining: AtomicBool::new(false),
        });

        // 读循环：RPC 为主；非 RPC 且为 Binding Request → 观察者应答（同 socket 3478 场景）
        let loop_node = node.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            loop {
                let (n, src) = match loop_node.socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(pkt) = RpcPacket::decode(&buf[..n]) {
                    loop_node.dispatch(pkt, Sink::Udp(src)).await;
                } else if n == seed_advertise_v2::LEN
                    && classify(&buf[..n]) == Some(seed_advertise_v2::TYPE)
                {
                    // 别的节点推送来的种子广告（非 RPC：定长报文，无应答）
                    loop_node.on_pushed_advert(&buf[..n]).await;
                } else if let Some(resp) = crate::observe::try_answer_stun(&buf[..n], src) {
                    let _ = loop_node.socket.send_to(&resp, src).await;
                }
            }
        });

        Ok(node)
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn identity(&self) -> Arc<NodeIdentity> {
        self.identity.clone()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn next_txid(&self) -> u32 {
        self.txid.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 测试用：模拟进程重启——丢掉全部只存在于内存里的状态（KV、地址簿），身份不变
    #[cfg(test)]
    pub(crate) async fn forget_volatile_state(&self) {
        self.kv.lock().await.clear();
        self.addr_book.lock().await.clear();
    }

    /// 学习（身份 ↔ 地址）：仅经身份绑定校验的 ping/pong/store 路径调用。
    /// UDP 入站：路由表 + 地址簿（可被 Forward 中转寻址）。
    /// TCP 入站：只入路由表——TCP 源地址不是可达的 UDP 端点，写地址簿会毒化转发路由。
    async fn learn_incoming(&self, id: NodeId, sink: &Sink) {
        self.routing.lock().await.insert(id);
        if let Some(addr) = sink.udp_addr() {
            let mut book = self.addr_book.lock().await;
            learn_addr(&mut book, id, addr);
        }
    }

    /// Ping：bootstrap 与路由维护基础原语
    pub async fn ping(&self, dest: SocketAddr) -> Result<PongInfo, RpcError> {
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(txid, Pending::Pong(tx));

        let body = PingBody {
            node_id: self.node_id().0,
            pubkey: self.identity.verifying_key().to_bytes(),
        };
        let pkt = RpcPacket::ping(txid, body);
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }

        match tokio::time::timeout(Duration::from_millis(1500), rx).await {
            Ok(Ok(info)) => Ok(info),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// FindNode：查目标邻近节点（本地路由表作答方视角）
    pub async fn find_node(
        &self,
        dest: SocketAddr,
        target: NodeId,
    ) -> Result<Vec<NodeEntry>, RpcError> {
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(txid, Pending::Neighbors(tx));

        let pkt = RpcPacket::find_node(txid, FindNodeBody { target: target.0 });
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }

        match tokio::time::timeout(Duration::from_millis(1500), rx).await {
            Ok(Ok(nodes)) => Ok(nodes),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// Forward：向认识的节点（如种子）投递"致 target"的透明载荷。
    /// fire-and-forget；上层信令自持超时重发。
    pub async fn forward_to(
        &self,
        route: SocketAddr,
        target: NodeId,
        payload: Vec<u8>,
    ) -> Result<(), RpcError> {
        if payload.len() > wgp_proto::dht::FORWARD_PAYLOAD_MAX {
            return Err(RpcError::PayloadTooLarge);
        }
        let pkt = RpcPacket::forward(
            self.next_txid(),
            ForwardBody {
                target: target.0,
                payload,
            },
        );
        self.socket
            .send_to(&pkt.encode(), route)
            .await
            .map_err(|_| RpcError::NoRoute)?;
        Ok(())
    }

    /// 收取以本节点为目标的 forward 载荷
    pub async fn recv_forward(&self) -> Option<ForwardBody> {
        self.inbox_rx.lock().await.recv().await
    }

    /// 非阻塞收取（upkeep 循环轮询用）
    pub async fn try_recv_forward(&self) -> Option<ForwardBody> {
        self.inbox_rx.lock().await.try_recv().ok()
    }

    /// 注册协商会话（payload 首 4B = session_tag 的 forward 将被投递至此）；
    /// tag=0 保留给房间管理默认队列
    pub async fn register_session(&self, tag: u32) -> mpsc::UnboundedReceiver<ForwardBody> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.sessions.lock().await.insert(tag, tx);
        rx
    }

    /// 注销会话（会话结束时调用，防 tag 泄漏）
    pub async fn unregister_session(&self, tag: u32) {
        self.sessions.lock().await.remove(&tag);
    }

    /// 中继策略（贡献模式家庭带宽节点：Deny 后不再为他人中转）
    pub async fn set_relay_policy(&self, policy: RelayPolicy) {
        self.relay_allow
            .store(policy == RelayPolicy::Allow, Ordering::Relaxed);
    }

    pub fn relay_policy(&self) -> RelayPolicy {
        if self.relay_allow.load(Ordering::Relaxed) {
            RelayPolicy::Allow
        } else {
            RelayPolicy::Deny
        }
    }

    /// KV 存储（房间记录宿主；sender 学习使存储节点可回路由锚点）
    pub async fn store(&self, dest: SocketAddr, key: [u8; 32], value: Vec<u8>) -> Result<(), RpcError> {
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(txid, Pending::StoreAck(tx));
        let pkt = RpcPacket::store(
            txid,
            StoreBody {
                sender: self.node_id().0,
                pubkey: self.identity.verifying_key().to_bytes(),
                key,
                value,
            },
        );
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }
        match tokio::time::timeout(Duration::from_millis(1500), rx).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// KV 读取；空值 = 未命中
    pub async fn find_value(
        &self,
        dest: SocketAddr,
        key: [u8; 32],
    ) -> Result<ValueBody, RpcError> {
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(txid, Pending::Value(tx));
        let pkt = RpcPacket::find_value(txid, FindValueBody { key });
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }
        match tokio::time::timeout(Duration::from_millis(1500), rx).await {
            Ok(Ok(v)) => Ok(v),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// 地址簿视图（供测试与诊断）
    pub async fn known_nodes(&self) -> Vec<(NodeId, SocketAddr)> {
        let book = self.addr_book.lock().await;
        book.iter().map(|(id, (addr, _))| (*id, *addr)).collect()
    }

    /// 应答 Neighbors：本路由表 k-closest 与地址簿交集
    async fn answer_neighbors(&self, target: NodeId, sink: &Sink, txid: u32) {
        let closest: Vec<NodeId> = {
            let rt = self.routing.lock().await;
            rt.closest_to(&target)
        };
        let book = self.addr_book.lock().await;
        let entries: Vec<NodeEntry> = closest
            .iter()
            .take(20)
            .filter_map(|id| {
                book.get(id).and_then(|(addr, _)| match addr.ip() {
                    std::net::IpAddr::V4(v4) => Some(NodeEntry {
                        id: id.0,
                        ipv4: v4.octets(),
                        port: addr.port(),
                    }),
                    _ => None, // v1 仅 IPv4 条目；IPv6 未来线
                })
            })
            .collect();
        drop(book);
        let pkt = RpcPacket::neighbors(txid, NeighborsBody { nodes: entries });
        self.sink_send(sink, pkt.encode()).await;
    }

    /// 按出口类型投递应答字节（UDP 回源 / TCP 写连接）
    async fn sink_send(&self, sink: &Sink, bytes: Vec<u8>) {
        match sink {
            Sink::Udp(addr) => {
                let _ = self.socket.send_to(&bytes, *addr).await;
            }
            Sink::Tcp(tx) => {
                let _ = tx.send(bytes);
            }
        }
    }

    /// 报文分发（UDP 读循环与 TCP 连接读端共用同一逻辑）
    async fn dispatch(&self, pkt: RpcPacket, sink: Sink) {
        match pkt.body {
            RpcBody::Ping(body) => {
                // 身份绑定校验：node_id 必须等于 SHA-256(pubkey)，否则拒绝——
                // 这是地址簿/路由表防毒化的唯一闸门（伪造 node_id 无法占位）
                let Some(sender) = verified_identity(body.node_id, body.pubkey) else {
                    return;
                };
                // 双向学习：入站 ping 即认识发送者
                self.learn_incoming(sender, &sink).await;
                let my = PingBody {
                    node_id: self.node_id().0,
                    pubkey: self.identity.verifying_key().to_bytes(),
                };
                let resp = RpcPacket::pong(pkt.header.txid, my);
                self.sink_send(&sink, resp.encode()).await;
            }
            RpcBody::Pong(body) => {
                let Some(peer) = verified_identity(body.node_id, body.pubkey) else {
                    return;
                };
                self.learn_incoming(peer, &sink).await;
                if let Some(Pending::Pong(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    // TCP 路径不产生 Pong（客户端直读应答），此处仅 UDP 命中；
                    // 兜底用未指定地址，避免 unwrap 崩溃。
                    let addr = sink
                        .udp_addr()
                        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
                    let _ = tx.send(PongInfo { node_id: peer, addr });
                }
            }
            RpcBody::FindNode(body) => {
                self.answer_neighbors(NodeId(body.target), &sink, pkt.header.txid)
                    .await;
            }
            RpcBody::Neighbors(body) => {
                if let Some(Pending::Neighbors(tx)) =
                    self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body.nodes);
                }
            }
            RpcBody::Forward(body) => {
                if body.target == self.node_id().0 {
                    // 本节点即收件人：按 session_tag 分流
                    let tag = if body.payload.len() >= 4 {
                        u32::from_be_bytes(body.payload[..4].try_into().unwrap())
                    } else {
                        0
                    };
                    let dispatched = if tag != 0 {
                        let sessions = self.sessions.lock().await;
                        match sessions.get(&tag) {
                            Some(tx) => tx.send(body.clone()).is_ok(),
                            None => false,
                        }
                    } else {
                        false
                    };
                    if !dispatched {
                        // 默认队列（房间管理/未注册降级）；队满静默丢弃=邮件语义
                        let _ = self.inbox_tx.try_send(body);
                    }
                } else {
                    // 中转：地址簿命中则转发（保留 txid，确保端到端匹配）
                    if self.relay_allow.load(Ordering::Relaxed) {
                        let book = self.addr_book.lock().await;
                        if let Some(&(dest, _)) = book.get(&NodeId(body.target)) {
                            drop(book);
                            let fwd = RpcPacket::forward(pkt.header.txid, body);
                            let _ = self.socket.send_to(&fwd.encode(), dest).await;
                        }
                    }
                    // 未命中或贡献模式拒绝：静默丢弃（fire-and-forget 语义）
                }
            }
            RpcBody::Store(body) => {
                // 存储同样过身份绑定：否则任何人可伪造 sender 抢占 KV 空间
                let Some(sender) = verified_identity(body.sender, body.pubkey) else {
                    return;
                };
                // 存储 + ACK；学习写入者身份（锚点报道回路由依赖此条目）
                self.learn_incoming(sender, &sink).await;
                let mut kv = self.kv.lock().await;
                kv_admit(&mut kv, body.key, body.value);
                drop(kv);
                let resp = RpcPacket::stored_ack(pkt.header.txid);
                self.sink_send(&sink, resp.encode()).await;
            }
            RpcBody::StoredAck => {
                if let Some(Pending::StoreAck(tx)) =
                    self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(());
                }
            }
            RpcBody::FindValue(body) => {
                let value = self
                    .kv
                    .lock()
                    .await
                    .get(&body.key)
                    .map(|entry| entry.0.clone())
                    .unwrap_or_default(); // 空值 = 未命中
                let resp = RpcPacket::value(
                    pkt.header.txid,
                    ValueBody { key: body.key, value },
                );
                self.sink_send(&sink, resp.encode()).await;
            }
            RpcBody::Value(body) => {
                if let Some(Pending::Value(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body);
                }
            }
            RpcBody::FindSeeds(body) => {
                self.answer_seeds(body, &sink, pkt.header.txid).await;
            }
            RpcBody::Seeds(body) => {
                if let Some(Pending::Seeds(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body.adverts);
                }
            }
        }
    }

    // —————————————— TCP 信令面（长度前缀帧，复用同一 dispatch/路由/KV） ——————————————

    /// 启动 TCP 信令监听（与 UDP 同 socket 语义以外的独立端口，如 3481）。
    /// 帧格式：`[u16 BE 长度][RpcPacket 字节]`，一连接多帧。
    /// 返回实际绑定地址（传端口 0 时由内核分配，供测试用）。
    pub async fn listen_tcp(self: &Arc<Self>, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let node = self.clone();
        tokio::spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONN));
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // 并发连接超限：直接拒绝（家庭宽带防连接耗尽）
                let permit = match limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let node = node.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    node.serve_tcp_conn(stream).await;
                });
            }
        });
        Ok(local)
    }

    /// 单条 TCP 信令连接：读端解帧 → dispatch(Sink::Tcp)；写端将应答帧回灌。
    /// 空闲超时关闭（防慢连接长期占用名额）。
    async fn serve_tcp_conn(&self, stream: TcpStream) {
        let (mut rd, mut wr) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if write_frame(&mut wr, &frame).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        loop {
            let frame = match tokio::time::timeout(
                Duration::from_secs(TCP_IDLE_TIMEOUT_S),
                read_frame(&mut rd),
            )
            .await
            {
                Ok(Ok(f)) => f,
                _ => break, // 空闲超时 / 对端关闭 / 帧非法
            };
            if let Some(pkt) = RpcPacket::decode(&frame) {
                self.dispatch(pkt, Sink::Tcp(tx.clone())).await;
            }
        }
        drop(tx);
        let _ = writer.await;
    }

    /// TCP 单次往返（v1：一请求一连接，低频信令足够；后续可升级长连接池）
    async fn tcp_roundtrip(&self, dest: SocketAddr, req: RpcPacket) -> Result<RpcPacket, RpcError> {
        let txid = req.header.txid;
        let fut = async {
            let mut stream = TcpStream::connect(dest)
                .await
                .map_err(|_| RpcError::NoRoute)?;
            write_frame(&mut stream, &req.encode())
                .await
                .map_err(|_| RpcError::NoRoute)?;
            let resp = read_frame(&mut stream).await.map_err(|_| RpcError::Timeout)?;
            let pkt = RpcPacket::decode(&resp).ok_or(RpcError::Timeout)?;
            if pkt.header.txid != txid {
                return Err(RpcError::Timeout);
            }
            Ok(pkt)
        };
        match tokio::time::timeout(Duration::from_millis(TCP_RPC_TIMEOUT_MS), fut).await {
            Ok(r) => r,
            Err(_) => Err(RpcError::Timeout),
        }
    }

    /// TCP Ping（UDP 被封/受限时的信令兜底）
    pub async fn ping_tcp(&self, dest: SocketAddr) -> Result<PongInfo, RpcError> {
        let body = PingBody {
            node_id: self.node_id().0,
            pubkey: self.identity.verifying_key().to_bytes(),
        };
        let req = RpcPacket::ping(self.next_txid(), body);
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::Pong(b) => Ok(PongInfo {
                node_id: NodeId(b.node_id),
                addr: dest,
            }),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP FindNode
    pub async fn find_node_tcp(
        &self,
        dest: SocketAddr,
        target: NodeId,
    ) -> Result<Vec<NodeEntry>, RpcError> {
        let req = RpcPacket::find_node(
            self.next_txid(),
            FindNodeBody { target: target.0 },
        );
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::Neighbors(b) => Ok(b.nodes),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP Store（KV 写入，等 StoredAck）
    pub async fn store_tcp(
        &self,
        dest: SocketAddr,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<(), RpcError> {
        let req = RpcPacket::store(
            self.next_txid(),
            StoreBody {
                sender: self.node_id().0,
                pubkey: self.identity.verifying_key().to_bytes(),
                key,
                value,
            },
        );
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::StoredAck => Ok(()),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP FindValue
    pub async fn find_value_tcp(
        &self,
        dest: SocketAddr,
        key: [u8; 32],
    ) -> Result<ValueBody, RpcError> {
        let req = RpcPacket::find_value(self.next_txid(), FindValueBody { key });
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::Value(b) => Ok(b),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP Forward 投递（fire-and-forget：只发不等，符合 Forward 邮件语义）。
    /// 种子收到后按地址簿以 UDP 转发给 target（种子→目标腿仍是 UDP）。
    pub async fn forward_tcp(
        &self,
        dest: SocketAddr,
        target: NodeId,
        payload: Vec<u8>,
    ) -> Result<(), RpcError> {
        if payload.len() > wgp_proto::dht::FORWARD_PAYLOAD_MAX {
            return Err(RpcError::PayloadTooLarge);
        }
        let req = RpcPacket::forward(
            self.next_txid(),
            ForwardBody {
                target: target.0,
                payload,
            },
        );
        let fut = async {
            let mut stream = TcpStream::connect(dest)
                .await
                .map_err(|_| RpcError::NoRoute)?;
            write_frame(&mut stream, &req.encode())
                .await
                .map_err(|_| RpcError::NoRoute)?;
            Ok(())
        };
        match tokio::time::timeout(Duration::from_millis(TCP_RPC_TIMEOUT_MS), fut).await {
            Ok(r) => r,
            Err(_) => Err(RpcError::Timeout),
        }
    }
}

// —————————————— 种子发现（07 §5 第③层 / 17 P0） ——————————————

/// 一条入站广告验签之后的去向
enum AdvertStep {
    /// 无效：验签失败 / 是自己的广告 / 所报地址不可用
    Rejected,
    /// 广告主已在目录中（重放、迟到，或已就地刷新）
    Known,
    /// 新广告主，或换了端点：要先探活
    Probe(Candidate),
}

/// 等待存活复验的广告
struct Candidate {
    id: NodeId,
    adv: SeedAdvertiseV2,
    raw: RawAdvert,
    addr: SocketAddr,
}

/// 广告所报端点是否可用作目的地址（只做格式层面的排除；是否可达由探活回答）
fn is_usable_endpoint(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            addr.port() != 0 && !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()
        }
        IpAddr::V6(_) => false,
    }
}

/// 固定窗口限速：`gate` = (窗口起点, 窗口内已放行数)；每秒至多放行 ADVERT_VERIFY_PER_SEC 次
fn gate_admit(gate: &mut (Instant, u32), now: Instant) -> bool {
    if now.duration_since(gate.0) >= Duration::from_secs(1) {
        *gate = (now, 0);
    }
    if gate.1 >= ADVERT_VERIFY_PER_SEC {
        return false;
    }
    gate.1 += 1;
    true
}

fn rtt_millis(rtt: Duration) -> u32 {
    u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)
}

impl DhtNode {
    /// 种子目录快照（按探活往返耗时升序）
    pub async fn seeds(&self) -> Vec<SeedInfo> {
        self.seeds.lock().await.list()
    }

    /// 订阅目录变更。值只是变更代数，含义仅为「有变化了，请重新读一次 seeds()」
    pub fn watch_seeds(&self) -> watch::Receiver<u64> {
        self.seeds_gen.subscribe()
    }

    /// 本节点当前的广告原文（未宣告为 None）
    pub async fn own_advert(&self) -> Option<RawAdvert> {
        *self.own_advert.lock().await
    }

    /// 登记用户显式配置的入口端点（--seed / --peers）。它们在目录满员时不被挤出；即使尚未
    /// 宣告自己，维护循环也会周期探活它们（保住到它们的 NAT 映射）并询问其种子目录。
    pub async fn pin_seeds(&self, addrs: &[SocketAddr]) {
        let mut pinned = self.pinned.lock().await;
        for addr in addrs {
            if pinned.len() >= PINNED_MAX {
                break;
            }
            pinned.insert(*addr);
        }
    }

    /// 开始对外宣告本节点（仅公网可达的节点调用；地址与端口由部署层给出）。
    ///
    /// `epoch`：广告纪元。接收端只采纳比已有的更大的纪元，所以同一身份每次重启（或广告内容
    /// 变化）都要传入更大的值。内核既不读系统时钟（H5）也不落盘：由外围持久化一个启动计数后
    /// 注入（wgp-node 的做法见 server.rs）。纪元回退的后果只是：已经认识本节点的人继续沿用
    /// 旧广告，直到旧端点探活失败被逐出后才重新采纳。
    ///
    /// 广告由维护循环周期推给已知种子与入口端点；调用后立即推送一轮。
    pub async fn start_advertising(&self, spec: AdvertiseSpec, epoch: u64) {
        let raw = sign_advertise_v2(&self.identity, &spec, epoch.max(1));
        *self.own_advert.lock().await = Some(raw);
        self.push_advert().await;
    }

    /// 向 `dest` 索取它已知的、离 `target` 最近的种子广告，把通过验签与存活复验的写入目录。
    /// 返回对方给出的广告中、此刻已在本地目录里的条数（全部探活有结果后才返回）。
    pub async fn find_seeds(
        self: &Arc<Self>,
        dest: SocketAddr,
        target: NodeId,
    ) -> Result<usize, RpcError> {
        let adverts = self.request_seeds(dest, target, SEEDS_MAX).await?;
        Ok(self.absorb_adverts(adverts).await)
    }

    /// 入网引导（07 §5）：以 `entry`（用户配置的入口端点）为起点建立种子目录。
    /// 入口端点登记为 pinned；向每个入口索取种子广告，再向新学到的种子问一层（让目录不局限于
    /// 入口自己认识的那几个）；更远的由周期维护慢慢补。正在宣告的节点最后把自己的广告推给
    /// 已知种子。返回目录内的种子数。
    pub async fn discover(self: &Arc<Self>, entry: &[SocketAddr]) -> usize {
        self.pin_seeds(entry).await;
        let me = self.node_id();
        let mut asked: HashSet<SocketAddr> = HashSet::new();
        let mut frontier: Vec<SocketAddr> = entry.to_vec();
        for _ in 0..2 {
            frontier.retain(|addr| asked.len() < DISCOVER_MAX_ASKS && asked.insert(*addr));
            if frontier.is_empty() {
                break;
            }
            self.ask_many(std::mem::take(&mut frontier), me).await;
            frontier = self.seeds().await.into_iter().map(|s| s.addr).collect();
        }
        // 正在宣告的节点顺手把自己的广告推给刚认识的种子：启动时那一轮推送可能发生在对方上线之前，
        // 不补这一下，对方要等到下一个推送周期（60s）才知道我们（未宣告则无事发生）
        self.push_advert().await;
        self.seeds.lock().await.len()
    }

    /// 为某个键（如房间键）补全它附近的种子：向已知种子各问一次「离 `target` 最近的有哪些」。
    /// 种子很少时与 discover 的结果相同；种子多到一次问不全时，这一步让各客户端对「谁离这个键
    /// 最近」的看法收敛。返回目录内的种子数。
    pub async fn seek_seeds(self: &Arc<Self>, target: NodeId) -> usize {
        let mut addrs = self.known_seed_addrs().await;
        addrs.truncate(DISCOVER_MAX_ASKS);
        self.ask_many(addrs, target).await;
        self.seeds.lock().await.len()
    }

    /// 迭代节点查找（Kademlia FIND_NODE 扩散）：从 `entry` 出发，逐轮向离 `target` 最近的未访问
    /// 候选发 FIND_NODE，用应答里的节点扩充候选，直到候选耗尽或触及轮数 / 接触数上限。
    ///
    /// 每个候选先 PING：应答者的身份过了绑定校验才算数（转述来的身份与实际应答者不符即丢弃），
    /// 同时也让对方认识我们。应答里常常夹着 NAT 后的客户端——它们多半连不上，所以规模刻意压得
    /// 很小，也不做「没有更近的候选就停」的提前终止。返回已验证的节点，按与 target 的距离升序。
    pub async fn lookup_node(
        self: &Arc<Self>,
        target: NodeId,
        entry: &[SocketAddr],
    ) -> Vec<(NodeId, SocketAddr)> {
        let me = self.node_id();
        let mut seen: HashSet<SocketAddr> = entry.iter().copied().collect();
        // (转述者声称的身份, 地址)；入口端点的身份未知（None），排序时排最前
        let mut pending: Vec<(Option<NodeId>, SocketAddr)> =
            seen.iter().map(|addr| (None, *addr)).collect();
        let mut verified: Vec<(NodeId, SocketAddr)> = Vec::new();
        let mut contacts = 0usize;

        for _ in 0..LOOKUP_MAX_ROUNDS {
            pending.sort_by_key(|(id, _)| id.map(|id| id.xor_distance(&target)));
            let take = LOOKUP_ALPHA
                .min(pending.len())
                .min(LOOKUP_MAX_CONTACTS - contacts);
            if take == 0 {
                break;
            }
            contacts += take;
            let mut asks = JoinSet::new();
            for (claimed, addr) in pending.drain(..take) {
                let node = self.clone();
                asks.spawn(async move {
                    let pong = node.ping(addr).await.ok()?;
                    if claimed.is_some_and(|id| id != pong.node_id) {
                        return None;
                    }
                    let neighbors = node.find_node(addr, target).await.unwrap_or_default();
                    Some((pong.node_id, addr, neighbors))
                });
            }
            while let Some(done) = asks.join_next().await {
                let Ok(Some((id, addr, neighbors))) = done else {
                    continue;
                };
                if !verified.iter().any(|(known, _)| *known == id) {
                    verified.push((id, addr));
                }
                for entry in neighbors {
                    let addr = SocketAddr::from((entry.ipv4, entry.port));
                    if entry.id != me.0 && is_usable_endpoint(addr) && seen.insert(addr) {
                        pending.push((Some(NodeId(entry.id)), addr));
                    }
                }
            }
        }
        verified.sort_by_key(|(id, _)| id.xor_distance(&target));
        verified
    }

    /// 扩散：以自身 ID 为目标做一次迭代查找，把沿途可达的节点认识一遍，再向其中还不在种子目录里的
    /// 节点索取种子广告——入口种子不认识、但路由上够得着的宣告者，靠这一步进入目录。
    /// 返回沿途验证过的节点数。耗时取决于不可达候选的超时，适合放在后台跑。
    pub async fn spread(self: &Arc<Self>, entry: &[SocketAddr]) -> usize {
        let me = self.node_id();
        let reached = self.lookup_node(me, entry).await;
        let listed: HashSet<SocketAddr> = self.seeds().await.into_iter().map(|s| s.addr).collect();
        let fresh: Vec<SocketAddr> = reached
            .iter()
            .map(|(_, addr)| *addr)
            .filter(|addr| !listed.contains(addr) && !entry.contains(addr))
            .collect();
        self.ask_many(fresh, me).await;
        reached.len()
    }

    /// 启动后台维护（幂等）：
    /// - 每 20s 探活目录里的种子与用户配置的入口端点——顺带保住本端到它们的 NAT 映射
    ///   （种子要靠这条映射把别人的 Forward 投递过来）；连续 3 次不应答的种子逐出目录；
    /// - 正在宣告的节点每 60s 把自己的广告推给已知种子与入口端点；
    /// - 每 5 分钟向已知种子重新索取目录，学到后来加入的节点。
    ///
    /// 这些都是低频信令，与打洞探针无关，不占用打洞发包预算（H6）。
    pub fn spawn_maintenance(self: &Arc<Self>) {
        if self.maintaining.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick: u32 = 0;
            loop {
                tokio::time::sleep(MAINTAIN_TICK).await;
                let Some(node) = weak.upgrade() else {
                    break;
                };
                tick = tick.wrapping_add(1);
                node.probe_known_seeds().await;
                if tick % ADVERTISE_EVERY_TICKS == 0 {
                    node.push_advert().await;
                }
                if tick % PULL_EVERY_TICKS == 0 {
                    let mut addrs = node.known_seed_addrs().await;
                    addrs.truncate(DISCOVER_MAX_ASKS);
                    let me = node.node_id();
                    node.ask_many(addrs, me).await;
                }
            }
        });
    }

    fn bump_seeds(&self) {
        self.seeds_gen.send_modify(|gen| *gen = gen.wrapping_add(1));
    }

    async fn ping_timed(&self, dest: SocketAddr) -> Result<(PongInfo, Duration), RpcError> {
        let start = Instant::now();
        let pong = self.ping(dest).await?;
        Ok((pong, start.elapsed()))
    }

    /// 已知种子的地址：目录条目（往返耗时升序）在前，尚未进目录的入口端点在后
    async fn known_seed_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self.seeds().await.into_iter().map(|s| s.addr).collect();
        let mut extra: Vec<SocketAddr> = self
            .pinned
            .lock()
            .await
            .iter()
            .copied()
            .filter(|addr| !addrs.contains(addr))
            .collect();
        extra.sort();
        addrs.extend(extra);
        addrs
    }

    /// 发 FIND_SEEDS 并等应答。请求按想要的条数填充（防反射放大，见 FindSeedsBody）
    async fn request_seeds(
        &self,
        dest: SocketAddr,
        target: NodeId,
        count: usize,
    ) -> Result<Vec<RawAdvert>, RpcError> {
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(txid, Pending::Seeds(tx));
        let pkt = RpcPacket::find_seeds(txid, FindSeedsBody::for_count(target.0, count));
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }
        match tokio::time::timeout(Duration::from_millis(1500), rx).await {
            Ok(Ok(adverts)) => Ok(adverts),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// 应答 FIND_SEEDS：自己的广告（若在宣告）与目录条目一起按与 target 的距离排序，
    /// 条数不超过请求的填充所允许的额度——应答永远不长于请求
    async fn answer_seeds(&self, req: FindSeedsBody, sink: &Sink, txid: u32) {
        let own = self.own_advert().await.map(|raw| (self.node_id(), raw));
        let adverts = self
            .seeds
            .lock()
            .await
            .closest_raw(&NodeId(req.target), req.quota(), own);
        let pkt = RpcPacket::seeds(txid, SeedsBody { adverts });
        self.sink_send(sink, pkt.encode()).await;
    }

    /// 验签一条入站广告，并按目录现状决定去向（同端点的更新广告在这里就地刷新）
    async fn examine_advert(&self, raw: &[u8]) -> AdvertStep {
        let Some((adv, id)) = verify_advertise_v2(raw) else {
            return AdvertStep::Rejected;
        };
        let addr = advert_addr(&adv);
        if id == self.node_id() || !is_usable_endpoint(addr) {
            return AdvertStep::Rejected;
        }
        let mut packet: RawAdvert = [0u8; seed_advertise_v2::LEN];
        packet.copy_from_slice(raw);

        let mut seeds = self.seeds.lock().await;
        match seeds.judge(&id, &adv) {
            Verdict::Stale => AdvertStep::Known,
            Verdict::Refresh => {
                seeds.refresh(&id, &adv, packet);
                drop(seeds);
                self.bump_seeds();
                AdvertStep::Known
            }
            Verdict::Probe => AdvertStep::Probe(Candidate {
                id,
                adv,
                raw: packet,
                addr,
            }),
        }
    }

    /// 存活复验：在广告所报端点上 PING，应答必须来自该端点且身份就是广告主，通过即入目录。
    /// 同一广告主同时只探一次；并发满额时直接放弃（广告主会重发，不值得排队）。
    async fn probe_and_admit(&self, candidate: Candidate) -> bool {
        if !self.verifying.lock().await.insert(candidate.id) {
            return false;
        }
        let admitted = match self.verify_slots.clone().try_acquire_owned() {
            Ok(_slot) => self.probe_candidate(&candidate).await,
            Err(_) => false,
        };
        self.verifying.lock().await.remove(&candidate.id);
        admitted
    }

    async fn probe_candidate(&self, candidate: &Candidate) -> bool {
        let Ok((pong, rtt)) = self.ping_timed(candidate.addr).await else {
            return false;
        };
        if pong.node_id != candidate.id || pong.addr != candidate.addr {
            return false;
        }
        let pinned = self.pinned.lock().await.contains(&candidate.addr);
        let admitted = self.seeds.lock().await.admit(
            candidate.id,
            &candidate.adv,
            candidate.raw,
            Some(rtt_millis(rtt)),
            pinned,
        );
        if admitted {
            self.bump_seeds();
        }
        admitted
    }

    /// 处置一批应我方请求而来的广告：需要探活的并发探，全部有结果后返回「已在目录中」的条数
    async fn absorb_adverts(self: &Arc<Self>, adverts: Vec<RawAdvert>) -> usize {
        let mut known = 0usize;
        let mut probes = JoinSet::new();
        for raw in adverts {
            match self.examine_advert(&raw).await {
                AdvertStep::Known => known += 1,
                AdvertStep::Probe(candidate) => {
                    let node = self.clone();
                    probes.spawn(async move { node.probe_and_admit(candidate).await });
                }
                AdvertStep::Rejected => {}
            }
        }
        while let Some(done) = probes.join_next().await {
            if matches!(done, Ok(true)) {
                known += 1;
            }
        }
        known
    }

    /// 向一组节点并发索取「离 target 最近的种子」，全部有结果后返回
    async fn ask_many(self: &Arc<Self>, addrs: Vec<SocketAddr>, target: NodeId) {
        let mut asks = JoinSet::new();
        for addr in addrs {
            let node = self.clone();
            asks.spawn(async move {
                let _ = node.find_seeds(addr, target).await;
            });
        }
        while asks.join_next().await.is_some() {}
    }

    /// 别的节点主动推来的广告：先过限速再验签；需要探活的放到后台，绝不阻塞读循环
    async fn on_pushed_advert(self: &Arc<Self>, raw: &[u8]) {
        if !self.advert_gate_admit().await {
            return;
        }
        if let AdvertStep::Probe(candidate) = self.examine_advert(raw).await {
            let node = self.clone();
            tokio::spawn(async move {
                node.probe_and_admit(candidate).await;
            });
        }
    }

    /// 推送广告的验签限速：每秒至多 ADVERT_VERIFY_PER_SEC 条
    async fn advert_gate_admit(&self) -> bool {
        let mut gate = self.advert_gate.lock().await;
        gate_admit(&mut gate, Instant::now())
    }

    /// 把自己的广告推给已知种子与入口端点（未宣告则无事发生）
    async fn push_advert(&self) {
        let Some(raw) = self.own_advert().await else {
            return;
        };
        for addr in self.known_seed_addrs().await {
            let _ = self.socket.send_to(&raw, addr).await;
        }
    }

    /// 探活一轮：目录里的种子记账（往返耗时 / 连续失败逐出）；尚未进目录的入口端点只要应答了，
    /// 就顺手问它要它自己的广告（它可能刚开始宣告，或者我们启动时它还没上线）
    pub(crate) async fn probe_known_seeds(self: &Arc<Self>) {
        let listed: Vec<(NodeId, SocketAddr)> = self
            .seeds()
            .await
            .into_iter()
            .map(|s| (s.node_id, s.addr))
            .collect();
        let unlisted: Vec<SocketAddr> = self
            .pinned
            .lock()
            .await
            .iter()
            .copied()
            .filter(|addr| !listed.iter().any(|(_, known)| known == addr))
            .collect();

        let mut probes = JoinSet::new();
        for (id, addr) in listed {
            let node = self.clone();
            probes.spawn(async move { (Some(id), addr, node.ping_timed(addr).await) });
        }
        for addr in unlisted {
            let node = self.clone();
            probes.spawn(async move { (None, addr, node.ping_timed(addr).await) });
        }

        let mut changed = false;
        let mut newcomers: Vec<(SocketAddr, NodeId)> = Vec::new();
        while let Some(done) = probes.join_next().await {
            let Ok((listed_as, addr, result)) = done else {
                continue;
            };
            match (listed_as, result) {
                (Some(id), Ok((pong, rtt))) if pong.node_id == id => {
                    self.seeds.lock().await.mark_alive(&id, rtt_millis(rtt));
                }
                // 不应答，或该端点上已经换了别的身份：都算这个种子失联
                (Some(id), _) => {
                    if self.seeds.lock().await.mark_failed(&id) {
                        self.forget(id).await;
                        changed = true;
                    }
                }
                (None, Ok((pong, _))) => newcomers.push((addr, pong.node_id)),
                (None, Err(_)) => {}
            }
        }
        if changed {
            self.bump_seeds();
        }
        for (addr, id) in newcomers {
            // 以对方自己的 ID 为目标、只要 1 条：它若在宣告，排最前的就是它自己的广告
            if let Ok(adverts) = self.request_seeds(addr, id, 1).await {
                self.absorb_adverts(adverts).await;
            }
        }
    }

    /// 忘掉一个失联的节点（路由表 + 地址簿）；它恢复后的下一次 PING / 广告会把它带回来
    async fn forget(&self, id: NodeId) {
        self.routing.lock().await.remove(&id);
        self.addr_book.lock().await.remove(&id);
    }
}

/// 写一帧：`[u16 BE 长度][payload]`
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u16;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

/// 读一帧（长度前缀）；帧长越界/为 0 视为非法，返回错误以断连
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_TCP_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tcp frame size out of range",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// 身份绑定校验：claims 的 node_id 必须等于 SHA-256(pubkey)。
/// 伪造 node_id（不等于自身公钥哈希）或非法公钥字节一律拒绝；
/// 冒充他人则需要为其 node_id 找一个 SHA-256 原像——计算上不可行。
fn verified_identity(node_id: [u8; 32], pubkey: [u8; 32]) -> Option<NodeId> {
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let claimed = NodeId(node_id);
    (node_id_from_verifying(&vk) == claimed).then_some(claimed)
}

/// 地址簿学习（含容量治理）：写入/刷新最后见时刻；满员先清扫静默过期条目，
/// 仍满则逐出"最久未见"的一条——攻击者必须持续在线才能保住席位，成本对等。
fn learn_addr(book: &mut HashMap<NodeId, (SocketAddr, Instant)>, id: NodeId, addr: SocketAddr) {
    let now = Instant::now();
    if !book.contains_key(&id) && book.len() >= ADDR_BOOK_MAX {
        book.retain(|_, (_, seen)| now.duration_since(*seen) < ADDR_BOOK_TTL);
        if book.len() >= ADDR_BOOK_MAX {
            let oldest = book
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(id, _)| *id);
            if let Some(dead) = oldest {
                book.remove(&dead);
            }
        }
    }
    book.insert(id, (addr, now));
}

/// KV 写入（含容量治理）：同 key 覆盖不计新；新 key 满员时逐出最旧写入的一条。
fn kv_admit(store: &mut HashMap<[u8; 32], KvEntry>, key: [u8; 32], value: Vec<u8>) {
    let now = Instant::now();
    if !store.contains_key(&key) && store.len() >= KV_MAX_ENTRIES {
        let oldest = store
            .iter()
            .min_by_key(|(_, (_, written))| *written)
            .map(|(k, _)| *k);
        if let Some(dead) = oldest {
            store.remove(&dead);
        }
    }
    store.insert(key, (value, now));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32])
    }

    fn fake_id(n: u32) -> NodeId {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&n.to_be_bytes());
        NodeId(a)
    }

    fn addr(n: u32) -> SocketAddr {
        ([127, 0, 0, 1], (n as u16) + 1024).into()
    }

    #[test]
    fn pushed_advert_verification_is_rate_limited() {
        let start = Instant::now();
        let mut gate = (start, 0u32);
        // 同一秒内：前 ADVERT_VERIFY_PER_SEC 条放行，其余丢弃
        let admitted = (0..ADVERT_VERIFY_PER_SEC + 40)
            .filter(|_| gate_admit(&mut gate, start + Duration::from_millis(500)))
            .count();
        assert_eq!(admitted as u32, ADVERT_VERIFY_PER_SEC);
        assert!(!gate_admit(&mut gate, start + Duration::from_millis(999)));
        // 窗口滚动后恢复
        assert!(gate_admit(&mut gate, start + Duration::from_millis(1000)));
    }

    #[test]
    fn endpoint_usability_filter() {
        let ok = |s: &str| is_usable_endpoint(s.parse().unwrap());
        assert!(ok("203.0.113.7:11010"));
        assert!(ok("127.0.0.1:11010"), "回环地址不在格式层排除（本机联调要用；远程一侧探活自然失败）");
        assert!(!ok("0.0.0.0:11010"));
        assert!(!ok("255.255.255.255:11010"));
        assert!(!ok("224.0.0.1:11010"));
        assert!(!ok("203.0.113.7:0"));
        assert!(!ok("[::1]:11010"));
    }

    #[test]
    fn identity_binding_accepts_true_and_rejects_spoof() {
        let a = ident(1);
        let b = ident(2);
        // 真实绑定通过
        assert_eq!(
            verified_identity(a.node_id().0, a.verifying_key().to_bytes()),
            Some(a.node_id())
        );
        // 拿自己的公钥冒充别人的 node_id：拒绝
        assert_eq!(
            verified_identity(b.node_id().0, a.verifying_key().to_bytes()),
            None
        );
        // 拿别人的公钥冒充其身份（等价重放）：通过的是该身份本身，非伪造
        assert_eq!(
            verified_identity(b.node_id().0, b.verifying_key().to_bytes()),
            Some(b.node_id())
        );
        // 全零公钥字节（ed25519 非典范点）：from_bytes 直接失败
        assert_eq!(verified_identity(a.node_id().0, [0u8; 32]), None);
    }

    #[test]
    fn learn_addr_sweeps_expired_before_evicting() {
        let mut book: HashMap<NodeId, (SocketAddr, Instant)> = HashMap::new();
        let stale = Instant::now() - ADDR_BOOK_TTL - Duration::from_secs(1);
        for i in 0..ADDR_BOOK_MAX as u32 {
            book.insert(fake_id(i), (addr(i), stale));
        }
        let fresh = fake_id(9_999);
        learn_addr(&mut book, fresh, addr(9_999));
        // 过期条目被整体清扫，新条目存活且远小于上限
        assert!(book.len() < ADDR_BOOK_MAX / 2, "len={}", book.len());
        assert!(book.contains_key(&fresh));
    }

    #[test]
    fn learn_addr_evicts_oldest_when_all_fresh() {
        let mut book: HashMap<NodeId, (SocketAddr, Instant)> = HashMap::new();
        let now = Instant::now();
        // 全员在线（间隔 < TTL，清扫不掉任何条目）：i 越大越久未见
        for i in 0..ADDR_BOOK_MAX as u32 {
            book.insert(
                fake_id(i),
                (addr(i), now - Duration::from_millis(u64::from(i) * 10)),
            );
        }
        let fresh = fake_id(9_999);
        learn_addr(&mut book, fresh, addr(9_999));
        assert_eq!(book.len(), ADDR_BOOK_MAX);
        assert!(
            !book.contains_key(&fake_id((ADDR_BOOK_MAX - 1) as u32)),
            "最久未见的应被逐出"
        );
        assert!(book.contains_key(&fresh));
        // 已存在条目的刷新不受容量限制影响
        learn_addr(&mut book, fresh, addr(9));
        assert_eq!(book.get(&fresh).unwrap().0, addr(9));
    }

    #[test]
    fn kv_admit_overwrites_and_evicts_oldest() {
        let mut store: HashMap<[u8; 32], KvEntry> = HashMap::new();
        let now = Instant::now();
        for i in 0..KV_MAX_ENTRIES {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            key[1] = (i >> 8) as u8;
            // 用 checked_sub：开机不足 10000s 时 Instant 相减会 panic（time.rs 溢出），此时退化为 now
            let old = now
                .checked_sub(Duration::from_secs(10_000 - i as u64))
                .unwrap_or(now);
            store.insert(key, (vec![i as u8], old));
        }
        // 覆盖旧 key 不逐出
        let k0 = [0u8; 32];
        kv_admit(&mut store, k0, vec![0xAA]);
        assert_eq!(store.len(), KV_MAX_ENTRIES);
        assert_eq!(store[&k0].0, vec![0xAA]);
        // 新 key 满员：逐出写入时刻最旧的（key[0]=0 刚被刷新，最旧是次旧者）
        let mut new_key = [0u8; 32];
        new_key[31] = 0xFF;
        kv_admit(&mut store, new_key, vec![1]);
        assert_eq!(store.len(), KV_MAX_ENTRIES);
        assert!(store.contains_key(&new_key));
    }
}