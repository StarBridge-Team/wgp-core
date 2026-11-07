//! Kademlia 网络栈（07 文档自研 DHT 的运行时）。
//!
//! 学习语义：仅 PING/PONG 双向学习（sender_id ↔ src 入地址簿）；
//! Forward 不做身份学习（防垃圾投递毒化地址簿），fire-and-forget 邮件语义，
//! 上层信令自持超时重发（sig::Commit REQUIRE_ACK / 3s 超时）。

use crate::id::{node_id_from_verifying, NodeId, NodeIdentity};
use crate::kbucket::RoutingTable;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Mutex};
use wgp_proto::dht::{
    FindNodeBody, FindValueBody, ForwardBody, NeighborsBody, NodeEntry, PingBody, RpcBody,
    RpcPacket, StoreBody, ValueBody,
};

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