//! Kademlia 网络栈（07 文档自研 DHT 的运行时）。
//!
//! 学习语义：仅 PING/PONG 双向学习（sender_id ↔ src 入地址簿）；
//! Forward 不做身份学习（防垃圾投递毒化地址簿），fire-and-forget 邮件语义，
//! 上层信令自持超时重发（sig::Commit REQUIRE_ACK / 3s 超时）。

use crate::id::{NodeId, NodeIdentity};
use crate::kbucket::RoutingTable;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
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

enum Pending {
    Pong(oneshot::Sender<PongInfo>),
    Neighbors(oneshot::Sender<Vec<NodeEntry>>),
    Value(oneshot::Sender<ValueBody>),
    StoreAck(oneshot::Sender<()>),
}

/// DHT 节点：路由表 + 地址簿 + KV 存储 + RPC 收发（bind 即启动读循环）
pub struct DhtNode {
    socket: Arc<UdpSocket>,
    identity: Arc<NodeIdentity>,
    routing: Mutex<RoutingTable>,
    addr_book: Mutex<HashMap<NodeId, SocketAddr>>,
    kv: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    txid: AtomicU32,
    pending: Mutex<HashMap<u32, Pending>>,
    inbox_tx: mpsc::UnboundedSender<ForwardBody>,
    inbox_rx: Mutex<mpsc::UnboundedReceiver<ForwardBody>>,
}

impl DhtNode {
    pub async fn bind(identity: NodeIdentity, local: SocketAddr) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(local).await?);
        let identity = Arc::new(identity);
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();

        let node = Arc::new(Self {
            socket: socket.clone(),
            routing: Mutex::new(RoutingTable::new(identity.node_id())),
            identity: identity.clone(),
            addr_book: Mutex::new(HashMap::new()),
            kv: Mutex::new(HashMap::new()),
            txid: AtomicU32::new(0),
            pending: Mutex::new(HashMap::new()),
            inbox_tx,
            inbox_rx: Mutex::new(inbox_rx),
        });

        // 读循环：RPC 为主；非 RPC 且为 Binding Request → 观察者应答（同 socket 3478 场景）
        let loop_node = node.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                let (n, src) = match loop_node.socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(pkt) = RpcPacket::decode(&buf[..n]) {
                    loop_node.dispatch(pkt, src).await;
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

    /// 学习（身份 ↔ 地址）：仅 ping/pong 路径调用
    async fn learn(&self, id: NodeId, addr: SocketAddr) {
        self.routing.lock().await.insert(id);
        self.addr_book.lock().await.insert(id, addr);
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
        book.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// 应答 Neighbors：本路由表 k-closest 与地址簿交集
    async fn answer_neighbors(&self, target: NodeId, dest: SocketAddr, txid: u32) {
        let closest: Vec<NodeId> = {
            let rt = self.routing.lock().await;
            rt.closest_to(&target)
        };
        let book = self.addr_book.lock().await;
        let entries: Vec<NodeEntry> = closest
            .iter()
            .take(20)
            .filter_map(|id| {
                book.get(id).and_then(|addr| match addr.ip() {
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
        let _ = self.socket.send_to(&pkt.encode(), dest).await;
    }

    /// 报文分发（读循环调用）
    async fn dispatch(&self, pkt: RpcPacket, src: SocketAddr) {
        match pkt.body {
            RpcBody::Ping(body) => {
                let sender = NodeId(body.node_id);
                // 双向学习：入站 ping 即认识发送者
                self.learn(sender, src).await;
                let my = PingBody {
                    node_id: self.node_id().0,
                    pubkey: self.identity.verifying_key().to_bytes(),
                };
                let resp = RpcPacket::pong(pkt.header.txid, my);
                let _ = self.socket.send_to(&resp.encode(), src).await;
            }
            RpcBody::Pong(body) => {
                self.learn(NodeId(body.node_id), src).await;
                if let Some(Pending::Pong(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(PongInfo {
                        node_id: NodeId(body.node_id),
                        addr: src,
                    });
                }
            }
            RpcBody::FindNode(body) => {
                self.answer_neighbors(NodeId(body.target), src, pkt.header.txid)
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
                    // 本节点即收件人：投递上层
                    let _ = self.inbox_tx.send(body);
                } else {
                    // 中转：地址簿命中则转发（保留 txid，确保端到端匹配）
                    let book = self.addr_book.lock().await;
                    if let Some(&dest) = book.get(&NodeId(body.target)) {
                        drop(book);
                        let fwd = RpcPacket::forward(pkt.header.txid, body);
                        let _ = self.socket.send_to(&fwd.encode(), dest).await;
                    }
                    // 未命中：静默丢弃（fire-and-forget 语义）
                }
            }
            RpcBody::Store(body) => {
                // 存储 + ACK；学习写入者身份（锚点报道回路由依赖此条目）
                self.learn(NodeId(body.sender), src).await;
                self.kv.lock().await.insert(body.key, body.value);
                let resp = RpcPacket::stored_ack(pkt.header.txid);
                let _ = self.socket.send_to(&resp.encode(), src).await;
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
                    .cloned()
                    .unwrap_or_default(); // 空值 = 未命中
                let resp = RpcPacket::value(
                    pkt.header.txid,
                    ValueBody { key: body.key, value },
                );
                let _ = self.socket.send_to(&resp.encode(), src).await;
            }
            RpcBody::Value(body) => {
                if let Some(Pending::Value(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body);
                }
            }
        }
    }
}