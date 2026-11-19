//! ET 桥接（路线图 M3）：把 EasyTier 协议兼容层（mesh-tun-proto）跑在折跃门的加密隧道上。
//!
//! 为什么是「ET 帧跑在隧道上」，而不是把打通的 UDP socket 直接交给 ET：
//! - mesh-tun-proto 的 `ExternalHolePunchBridge` 目前是占位接口——返回值里只有地址、没有 socket，
//!   `MeshUdpPlug::new` 会自己另开一个 socket，接不上我们打通的那条洞；
//! - 打通的 UDP socket 上混着内核的保活探针，直接交出去就得停保活、再自己做一遍分流；
//! - 走隧道则这些都不用管：分流、加密、可靠传输、多路复用隧道已经做了，ET 帧只是其中一条流上的字节。
//!
//! 一条隧道上有两条 ET 通道：
//!
//! ```text
//! wgp 隧道 ─┬─ 逻辑端口 11010 的流：ET 控制帧（握手 / RPC / Ping / Pong），可靠、有序
//!           └─ 逻辑端口 11010 的数据报：ET 数据帧（IP 包 / 用户 payload），不保证送达
//! ```
//!
//! 数据帧改走数据报是为了避免「TCP over TCP」的队头阻塞：一条 IP 包丢了不该拖住后面的控制帧。
//! 数据报放不下（超长）或队列满时，[`TunnelFrameTransport::send_frame`] 会退回可靠流——接收端两条
//! 通道都读，所以回退不会丢帧，只是那一帧又变成有序传输。
//!
//! 接缝只有一个：[`TunnelFrameTransport`] 实现 mesh-tun-proto 的 `MeshFrameTransport`，经
//! `P2pNode::add_custom_transport` 接入。该库是「同步 + 手动 tick」模型，[`EtNode`] 用一个独立线程
//! 承载它，对外只有命令与事件两条通道。
//!
//! 本 crate 仍然**不含 TUN 设备**：IP 包以 [`EtEvent::Node`] 里的 `InboundIpPacket` 交给上层，
//! 由上层决定写哪儿。

use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use mesh_tun_proto::{
    MeshFrameTransport, PacketType, P2pEvent, P2pNode, PeerManagerHeader,
    PEER_MANAGER_HEADER_SIZE,
};
use std::sync::mpsc as std_mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tokio_mpsc;
use wgp_port::{InboundDgram, StreamReader, Tunnel, TunnelHandle, TunnelStream};

/// ET 流在隧道里占用的逻辑端口（取 ET 的默认监听端口号，便于辨认）。
/// 接受连接的一侧要在 `TunnelConfig::expose_tcp` 里列出它。
pub const ET_STREAM_PORT: u16 = 11010;
/// 兼容旧名字：ET 控制帧走的流端口
pub const ET_TUNNEL_PORT: u16 = ET_STREAM_PORT;
/// ET 数据帧走的数据报端口（与流端口同号，但两者是不同的命名空间）
pub const ET_DGRAM_PORT: u16 = 11010;
/// ET 数据帧统一用 flow 0（不需要多路区分）
const ET_DGRAM_FLOW: u32 = 0;

/// 单帧上限（与 mesh-tun-proto 的流式帧一致：16MiB）
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// ET 节点线程的 tick 间隔（该库要求不超过 50ms）
const TICK_INTERVAL: Duration = Duration::from_millis(40);
/// 每次 tick 每条连接最多处理的帧数，也限制单轮命令队列处理量
const TICK_FRAMES: usize = 64;
/// 等待 ET 同步轮询的帧数。单帧最大 16MiB，因此每方向最多多保留一帧。
const TRANSPORT_QUEUE_FRAMES: usize = 1;
/// 待处理命令上限，避免调用方持续提交造成无界内存增长
const COMMAND_QUEUE_CAPACITY: usize = 128;
/// 事件队列上限，避免无人消费事件时持续占用内存
const EVENT_QUEUE_CAPACITY: usize = 16;
/// 用户数据命令上限，128 个槽位合计最多暂存 8MiB
const MAX_COMMAND_DATA: usize = 64 * 1024;
/// 单个 IP 包上限（IPv4 总长字段是 16 位）
const MAX_IP_PACKET: usize = 65_535;
/// 重新宣告自身信息的间隔（官方 relay 会让路由老化，定期重发；版本号由库维护）
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(10);
/// 等对端隧道 HELLO 的上限
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// 一对 WGP 节点之间谁来发起 ET 流：**PeerId 字节序较小的一方发起**。
///
/// 两端各自只知道「我」和「对端」的 PeerId，算出来的结果必然相反，所以不会双方同时开流，
/// 也不会双方都等着对方——这个规则不需要协商。选「小的发起」与隧道 mux 的流号奇偶同向
/// （`local_is_lo` 用奇数号），排障时一条链路的流号含义固定。
///
/// `my_peer` / `remote_peer` 是 wgp 的 `PeerId`（16 字节）。
pub fn should_open_et_stream(my_peer: &[u8; 16], remote_peer: &[u8; 16]) -> bool {
    my_peer < remote_peer
}

/// 按 [`should_open_et_stream`] 的结果建立一条 ET 隧道流。
///
/// 发起方 `open_stream`，接受方等 `Tunnel::incoming`；两端并发调用即可（测试与示例都这么用）。
/// 返回的 [`EtStreamSide`] 说明本方是发起方还是接受方，便于日志与断言。
pub async fn establish_et_stream(
    tunnel: &mut Tunnel,
    my_peer: &[u8; 16],
    remote_peer: &[u8; 16],
) -> anyhow::Result<(TunnelStream, EtStreamSide)> {
    if should_open_et_stream(my_peer, remote_peer) {
        // 开流前先等对端 HELLO：确认 mux 已起来（也免得在 Hello 之前开流被对端当成未知端口）
        if tokio::time::timeout(HELLO_TIMEOUT, tunnel.handle.peer_hello())
            .await
            .map_err(|_| anyhow!("waiting for peer hello timed out"))?
            .is_none()
        {
            return Err(anyhow!("tunnel closed before peer hello"));
        }
        let stream = tunnel.handle.open_stream(ET_STREAM_PORT)?;
        Ok((stream, EtStreamSide::Opened))
    } else {
        loop {
            let incoming = tokio::time::timeout(HELLO_TIMEOUT, tunnel.incoming.recv())
                .await
                .map_err(|_| anyhow!("waiting for inbound ET stream timed out"))?
                .ok_or_else(|| anyhow!("tunnel closed while waiting for the ET stream"))?;
            if incoming.port == ET_STREAM_PORT {
                return Ok((incoming.stream, EtStreamSide::Accepted));
            }
            // 别的端口的入站流不归 ET 桥接管：丢掉（tunnel 的 expose_tcp 应只列出 ET 端口）
        }
    }
}

/// 本方在建立 ET 流时是哪一侧
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtStreamSide {
    /// 本方发起（PeerId 较小）
    Opened,
    /// 本方接受
    Accepted,
}

/// 把一帧编码成流上的字节：4B LE 长度（头 + 载荷）| 16B PeerManagerHeader | 载荷。
/// 与 mesh-tun-proto / EasyTier 的 TCP 帧格式相同。
fn encode_frame(hdr: &PeerManagerHeader, payload: &[u8]) -> Vec<u8> {
    let total = PEER_MANAGER_HEADER_SIZE + payload.len();
    let mut buf = BytesMut::with_capacity(4 + total);
    buf.put_u32_le(total as u32);
    hdr.encode(&mut buf);
    buf.put_slice(payload);
    buf.to_vec()
}

/// 数据报里的一帧：没有 4 字节长度前缀（数据报自带边界），只有 16B 头 + 载荷。
fn encode_dgram_frame(hdr: &PeerManagerHeader, payload: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(PEER_MANAGER_HEADER_SIZE + payload.len());
    hdr.encode(&mut buf);
    buf.put_slice(payload);
    buf.to_vec()
}

/// 数据报 → (头, 载荷)。长度字段对不上就当非法帧丢掉。
fn decode_dgram_frame(bytes: &[u8]) -> Option<(PeerManagerHeader, Vec<u8>)> {
    if bytes.len() < PEER_MANAGER_HEADER_SIZE {
        return None;
    }
    let hdr = PeerManagerHeader::decode(bytes);
    let payload = &bytes[PEER_MANAGER_HEADER_SIZE..];
    (hdr.len as usize == payload.len()).then(|| (hdr, payload.to_vec()))
}

/// 帧格式非法（长度字段越界）
#[derive(Debug, PartialEq, Eq)]
struct BadFrame;

/// 从缓冲区头部取出一帧：`Ok(None)` = 数据还不够；`Ok(Some((头, 载荷, 消耗字节数)))`。
fn take_frame(buf: &[u8]) -> Result<Option<(PeerManagerHeader, Vec<u8>, usize)>, BadFrame> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let total = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if !(PEER_MANAGER_HEADER_SIZE..=MAX_FRAME).contains(&total) {
        return Err(BadFrame);
    }
    let Some(body) = buf.get(4..4 + total) else {
        return Ok(None);
    };
    let hdr = PeerManagerHeader::decode(body);
    let payload = body[PEER_MANAGER_HEADER_SIZE..].to_vec();
    if hdr.len as usize != payload.len() {
        return Err(BadFrame);
    }
    Ok(Some((hdr, payload, 4 + total)))
}

/// 帧在隧道里的去向：数据帧走数据报，其余走可靠流
fn goes_over_dgram(pt: PacketType) -> bool {
    matches!(pt, PacketType::Data)
}

/// 数据报通道的发送侧
struct DgramPath {
    handle: TunnelHandle,
    max_payload: usize,
}

/// 跑在一条 wgp 隧道上的 ET 帧传输。
///
/// 隧道是异步的，ET 库是同步轮询的：中间用通道隔开——读任务把流里的字节切成帧、数据报任务把
/// 数据报解成帧，都送进同一个同步队列（`recv_frame` 非阻塞地取）；`send_frame` 按帧类型决定
/// 交给写任务还是数据报通道。
pub struct TunnelFrameTransport {
    /// 控制帧的流写任务队列
    outbound: tokio_mpsc::Sender<Vec<u8>>,
    /// 数据帧的数据报通道（`None` = 没有接管数据报，全部走流）
    dgram: Option<DgramPath>,
    inbound: tokio_mpsc::Receiver<(PeerManagerHeader, Vec<u8>)>,
    /// 自己留一份发送端：接管数据报时也要往同一个队列里塞帧
    inbound_tx: tokio_mpsc::Sender<(PeerManagerHeader, Vec<u8>)>,
    /// 流那一侧已经结束（读到 EOF / 非法帧 / 写失败）
    ///
    /// 不能只靠「入站通道断开」来判断对端下线：结构体自己留着 `inbound_tx`，通道永远不会断开。
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    label: String,
}

impl TunnelFrameTransport {
    /// 接管一条隧道流：ET 的所有帧都走这条可靠流（控制与数据混在一起）。
    ///
    /// 必须在 tokio 运行时内调用（会起读、写两个任务）。
    /// 流断开或收到非法帧时，下一次 `recv_frame` 返回错误，ET 节点据此判定对端下线。
    pub fn spawn(stream: TunnelStream, label: impl Into<String>) -> Self {
        let (reader, writer) = stream.split();
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (outbound, mut outbound_rx) = tokio_mpsc::channel::<Vec<u8>>(TRANSPORT_QUEUE_FRAMES);
        let (inbound_tx, inbound) = tokio_mpsc::channel(TRANSPORT_QUEUE_FRAMES);

        let write_closed = closed.clone();
        tokio::spawn(async move {
            let mut writer = writer;
            while let Some(frame) = outbound_rx.recv().await {
                if writer.write(&frame).await.is_err() {
                    write_closed.store(true, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            }
            writer.finish().await;
        });
        tokio::spawn(pump_stream(reader, inbound_tx.clone(), closed.clone()));

        Self {
            outbound,
            dgram: None,
            inbound,
            inbound_tx,
            closed,
            label: label.into(),
        }
    }

    /// 接管一条隧道流，并让 ET 的**数据帧走数据报通道**（控制帧仍走这条流）。
    ///
    /// 会取走隧道的入站数据报接收端（见 `Tunnel::take_dgrams`）：此后该隧道的数据报只由这个
    /// 传输消费，所以同一个 `Tunnel` 上只能有一个 ET 传输用数据报；第二条 ET 流请用
    /// [`Self::spawn`]（全部走流）。
    pub fn spawn_with_dgram(
        stream: TunnelStream,
        tunnel: &mut Tunnel,
        label: impl Into<String>,
    ) -> Self {
        let mut transport = Self::spawn(stream, label);
        let dgrams = tunnel.take_dgrams();
        let handle = tunnel.handle.clone();
        transport.dgram = Some(DgramPath {
            max_payload: handle.max_dgram_payload(),
            handle,
        });

        let inbound_tx = transport.inbound_tx.clone();
        tokio::spawn(async move {
            let mut dgrams: tokio_mpsc::Receiver<InboundDgram> = dgrams;
            while let Some(dgram) = dgrams.recv().await {
                if dgram.port != ET_DGRAM_PORT {
                    continue; // 不属于 ET 的数据报（别的服务在用这条隧道）
                }
                let Some(frame) = decode_dgram_frame(&dgram.data) else {
                    continue; // 非法帧直接丢：数据报本来就不保证送达
                };
                if inbound_tx.send(frame).await.is_err() {
                    return;
                }
            }
        });
        transport
    }

    /// 这条传输是否把数据帧放进数据报通道
    pub fn uses_dgram(&self) -> bool {
        self.dgram.is_some()
    }

    /// 单个数据报能装下的 ET 帧上限（`uses_dgram()` 为 false 时是流的上限）
    pub fn max_dgram_frame(&self) -> usize {
        self.dgram
            .as_ref()
            .map_or(MAX_FRAME, |d| d.max_payload)
    }
}

/// 读任务：把流里的字节按 4B 长度前缀切成帧
async fn pump_stream(
    mut reader: StreamReader,
    inbound_tx: tokio_mpsc::Sender<(PeerManagerHeader, Vec<u8>)>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut buf: Vec<u8> = Vec::new();
    while let Ok(Some(chunk)) = reader.read().await {
        let mut remaining: &[u8] = chunk.as_ref();
        while !remaining.is_empty() {
            let capacity = (MAX_FRAME + 4).saturating_sub(buf.len());
            if capacity == 0 {
                closed.store(true, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            let take = capacity.min(remaining.len());
            buf.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            loop {
                match take_frame(&buf) {
                    Ok(Some((hdr, payload, used))) => {
                        buf.drain(..used);
                        if inbound_tx.send((hdr, payload)).await.is_err() {
                            closed.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(BadFrame) => {
                        closed.store(true, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
    // EOF：对端关了这条流
    closed.store(true, std::sync::atomic::Ordering::Relaxed);
}

impl MeshFrameTransport for TunnelFrameTransport {
    fn send_frame(&mut self, hdr: &PeerManagerHeader, payload: &[u8]) -> anyhow::Result<()> {
        if hdr.len as usize != payload.len() {
            return Err(anyhow!("ET frame header length does not match payload"));
        }
        if payload.len() + PEER_MANAGER_HEADER_SIZE > MAX_FRAME {
            return Err(anyhow!("ET frame exceeds {MAX_FRAME} byte limit"));
        }
        if goes_over_dgram(hdr.packet_type) {
            if let Some(dgram) = &self.dgram {
                let frame = encode_dgram_frame(hdr, payload);
                // 超长（IP 包大于单报上限）或队列满都退回可靠流：接收端两条通道都读，不会丢
                if frame.len() <= dgram.max_payload
                    && dgram
                        .handle
                        .send_dgram(false, ET_DGRAM_PORT, ET_DGRAM_FLOW, &frame)
                {
                    return Ok(());
                }
            }
        }
        self.outbound
            .try_send(encode_frame(hdr, payload))
            .map_err(|err| anyhow!("wgp tunnel outbound queue unavailable: {err}"))
    }

    fn recv_frame(&mut self) -> anyhow::Result<Option<(PeerManagerHeader, Vec<u8>)>> {
        match self.inbound.try_recv() {
            Ok(frame) => Ok(Some(frame)),
            Err(tokio_mpsc::error::TryRecvError::Empty) => {
                // 流已经结束（对端关闭 / 非法帧）：报错让 ET 节点把这条连接判为下线
                if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                    Err(anyhow!("wgp tunnel stream closed"))
                } else {
                    Ok(None)
                }
            }
            Err(tokio_mpsc::error::TryRecvError::Disconnected) => {
                Err(anyhow!("wgp tunnel stream closed"))
            }
        }
    }

    fn remote_peer_id(&self) -> u32 {
        0
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

/// 路由表里的一条（给上层看「现在网络里有哪些节点、虚拟 IP 是什么」）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtRoute {
    pub peer_id: u32,
    pub ipv4: Option<u32>,
    pub hostname: Option<String>,
}

/// [`EtNode`] 对外的事件
#[derive(Debug, Clone)]
pub enum EtEvent {
    /// 一条传输完成了 ET 握手；`peer_id` 是对端的 ET 节点号
    Connected { peer_id: u32 },
    /// 握手失败：网络名 / 密钥不一致、超时或流已断开
    ConnectFailed { reason: String },
    /// 发送失败（没有到该节点的连接等）
    SendFailed { to: u32, reason: String },
    /// 发 IP 包失败：路由里没有这个地址、或通往它的下一跳没连上
    Ipv4SendFailed { reason: String },
    /// ET 库自身的事件：收到 IP 包 / 用户数据、对端断开、解密失败等
    Node(P2pEvent),
    /// 路由表快照：每次 `RouteChanged` 之后紧跟一条，上层不用再自己查库
    Routes { routes: Vec<EtRoute> },
}

enum Command {
    Attach(TunnelFrameTransport),
    Send { to: u32, data: Vec<u8> },
    SendIpv4 { packet: Vec<u8> },
    Announce { hostname: String, ipv4: Option<u32> },
    Stop,
}

/// 跑在独立线程里的 ET 节点。
///
/// 已知简化：握手在节点线程里同步进行（该库最长等 30s），期间其他连接不会被 tick。
/// 产品化时应把握手挪出主循环。
pub struct EtNode {
    peer_id: u32,
    commands: std_mpsc::SyncSender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl EtNode {
    /// 启动一个 ET 节点（网络名 + 密钥决定它属于哪个 ET 网络），返回句柄与事件接收端。
    ///
    /// 桥接自己就是「TUN 那一层」：IP 包以事件交给上层，所以节点按「已接 TUN」配置
    /// （发 IP 包时清 `NOT_SEND_TO_TUN`，对端才会当 IP 包处理）。
    pub fn start(
        network: &str,
        secret: &str,
    ) -> std::io::Result<(Self, tokio_mpsc::Receiver<EtEvent>)> {
        let (commands, command_rx) = std_mpsc::sync_channel::<Command>(COMMAND_QUEUE_CAPACITY);
        let (events, event_rx) = tokio_mpsc::channel::<EtEvent>(EVENT_QUEUE_CAPACITY);
        let (id_tx, id_rx) = std_mpsc::channel::<u32>();
        let (network, secret) = (network.to_string(), secret.to_string());

        let thread = std::thread::Builder::new()
            .name("wgp-et-node".to_string())
            .spawn(move || {
                // 节点在本线程内创建，不跨线程移动
                let mut node = P2pNode::new(network, secret, None);
                node.set_my_tun_enabled(true);
                if id_tx.send(node.identity.my_peer_id).is_err() {
                    return;
                }
                // 最近一次要求宣告的自身信息（每 ANNOUNCE_INTERVAL 重发一次）
                let mut announce: Option<(String, Option<u32>)> = None;
                let mut last_announce: Option<Instant> = None;
                loop {
                    let first = match command_rx.recv_timeout(TICK_INTERVAL) {
                        Ok(command) => Some(command),
                        Err(std_mpsc::RecvTimeoutError::Timeout) => None,
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
                    };
                    let mut command = first;
                    let mut handled = 0;
                    while let Some(current) = command {
                        handled += 1;
                        let event = match current {
                            Command::Attach(transport) => {
                                Some(match node.add_custom_transport(Box::new(transport)) {
                                    Ok(peer_id) => EtEvent::Connected { peer_id },
                                    Err(e) => EtEvent::ConnectFailed {
                                        reason: e.to_string(),
                                    },
                                })
                            }
                            Command::Send { to, data } => {
                                node.send_data_to(to, &data)
                                    .err()
                                    .map(|e| EtEvent::SendFailed {
                                        to,
                                        reason: e.to_string(),
                                    })
                            }
                            Command::SendIpv4 { packet } => node
                                .send_ipv4(&packet)
                                .err()
                                .map(|e| EtEvent::Ipv4SendFailed {
                                    reason: e.to_string(),
                                }),
                            Command::Announce { hostname, ipv4 } => {
                                if ipv4.is_some() {
                                    node.set_my_ipv4(ipv4);
                                }
                                node.announce_self_to_all(&hostname, ipv4);
                                announce = Some((hostname, ipv4));
                                last_announce = Some(Instant::now());
                                None
                            }
                            Command::Stop => return,
                        };
                        if let Some(event) = event {
                            if events.try_send(event).is_err() {
                                return;
                            }
                        }
                        if handled >= TICK_FRAMES {
                            break;
                        }
                        command = match command_rx.try_recv() {
                            Ok(command) => Some(command),
                            Err(std_mpsc::TryRecvError::Empty) => None,
                            Err(std_mpsc::TryRecvError::Disconnected) => return,
                        };
                    }
                    // 定期重新宣告（官方 relay 会让路由老化；库内部保证版本号递增）
                    if let Some((hostname, ipv4)) = &announce {
                        if last_announce
                            .map(|t| t.elapsed() >= ANNOUNCE_INTERVAL)
                            .unwrap_or(true)
                        {
                            node.announce_self_to_all(hostname, *ipv4);
                            last_announce = Some(Instant::now());
                        }
                    }
                    for event in node.tick(TICK_FRAMES) {
                        let route_changed = matches!(event, P2pEvent::RouteChanged { .. });
                        if events.try_send(EtEvent::Node(event)).is_err() {
                            return;
                        }
                        if route_changed {
                            let routes = node
                                .routes()
                                .peers
                                .iter()
                                .map(|p| EtRoute {
                                    peer_id: p.peer_id,
                                    ipv4: p.ipv4_addr,
                                    hostname: p.hostname.clone(),
                                })
                                .collect();
                            if events.try_send(EtEvent::Routes { routes }).is_err() {
                                return;
                            }
                        }
                    }
                }
            })?;

        let peer_id = id_rx.recv().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "ET node thread exited at startup",
            )
        })?;
        Ok((
            Self {
                peer_id,
                commands,
                thread: Some(thread),
            },
            event_rx,
        ))
    }

    /// 本节点的 ET 节点号
    pub fn peer_id(&self) -> u32 {
        self.peer_id
    }

    /// 接入一条传输并做 ET 握手；队列满时返回错误，不阻塞调用线程。
    pub fn attach(&self, transport: TunnelFrameTransport) -> anyhow::Result<()> {
        self.commands
            .try_send(Command::Attach(transport))
            .map_err(|err| anyhow!("ET command queue unavailable: {err}"))
    }

    /// 向指定 ET 节点发一段用户数据（对端收到 `P2pEvent::InboundUserData`）。
    /// 队列满时返回错误，不阻塞调用线程。
    pub fn send_data(&self, to: u32, data: Vec<u8>) -> anyhow::Result<()> {
        if data.len() > MAX_COMMAND_DATA {
            return Err(anyhow!(
                "ET user payload exceeds {MAX_COMMAND_DATA} byte limit"
            ));
        }
        self.commands
            .try_send(Command::Send { to, data })
            .map_err(|err| anyhow!("ET command queue unavailable: {err}"))
    }

    /// 发一个 IPv4 包（目标由包头的目的地址决定，按路由表选下一跳）。
    ///
    /// 对端会收到 `InboundIpPacket`——桥接把它交给上层，真接 TUN 时就是写进网卡的那个包。
    pub fn send_ipv4(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        if packet.len() > MAX_IP_PACKET {
            return Err(anyhow!("IPv4 packet exceeds {MAX_IP_PACKET} byte limit"));
        }
        self.commands
            .try_send(Command::SendIpv4 { packet })
            .map_err(|err| anyhow!("ET command queue unavailable: {err}"))
    }

    /// 宣告自己的主机名与虚拟 IPv4，并每 10 秒自动重发（库保证版本号递增）。
    pub fn announce(&self, hostname: &str, ipv4: Option<u32>) -> anyhow::Result<()> {
        self.commands
            .try_send(Command::Announce {
                hostname: hostname.to_string(),
                ipv4,
            })
            .map_err(|err| anyhow!("ET command queue unavailable: {err}"))
    }

    /// 停止节点并等线程退出
    pub fn stop(mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for EtNode {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Stop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(len: usize) -> PeerManagerHeader {
        PeerManagerHeader::new(0x1111_2222, 0x3333_4444, PacketType::Data, len as u32)
    }

    #[test]
    fn frame_roundtrip_and_reassembly_across_chunks() {
        let first = encode_frame(&header(5), b"hello");
        let second = encode_frame(&header(0), b"");
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&first);
        stream.extend_from_slice(&second);

        // 流上的字节可能在任意位置被切开：逐字节喂入，帧边界仍然正确
        let mut buf: Vec<u8> = Vec::new();
        let mut got = Vec::new();
        for byte in stream {
            buf.push(byte);
            while let Some((hdr, payload, used)) = take_frame(&buf).unwrap() {
                buf.drain(..used);
                got.push((hdr.from_peer_id, hdr.to_peer_id, payload));
            }
        }
        assert!(buf.is_empty());
        assert_eq!(
            got,
            vec![
                (0x1111_2222, 0x3333_4444, b"hello".to_vec()),
                (0x1111_2222, 0x3333_4444, Vec::new()),
            ]
        );
    }

    #[test]
    fn frame_layout_matches_the_et_stream_format() {
        let bytes = encode_frame(&header(3), b"abc");
        // 4B LE 长度 = 16B 头 + 3B 载荷
        assert_eq!(&bytes[..4], &19u32.to_le_bytes());
        assert_eq!(bytes.len(), 4 + 16 + 3);
        assert_eq!(&bytes[20..], b"abc");
    }

    #[test]
    fn dgram_frame_has_no_length_prefix_and_roundtrips() {
        let bytes = encode_dgram_frame(&header(3), b"abc");
        // 数据报自带边界：16B 头 + 3B 载荷
        assert_eq!(bytes.len(), 16 + 3);
        assert_eq!(&bytes[..4], &0x1111_2222u32.to_le_bytes());
        let (hdr, payload) = decode_dgram_frame(&bytes).expect("应能解出");
        assert_eq!((hdr.to_peer_id, hdr.len), (0x3333_4444, 3));
        assert_eq!(payload, b"abc");

        // 长度字段与载荷对不上 → 丢掉
        let mut bad = bytes.clone();
        bad[12..16].copy_from_slice(&9u32.to_le_bytes());
        assert!(decode_dgram_frame(&bad).is_none());
        assert!(decode_dgram_frame(&bytes[..15]).is_none());
    }

    #[test]
    fn malformed_length_is_rejected() {
        // 长度小于头部
        assert_eq!(take_frame(&15u32.to_le_bytes()).unwrap_err(), BadFrame);
        // 长度超过上限（防止恶意长度让接收端无限攒缓冲）
        let huge = (MAX_FRAME as u32 + 1).to_le_bytes();
        assert_eq!(take_frame(&huge).unwrap_err(), BadFrame);
        // 数据不足不是错误
        assert!(take_frame(&[1, 0]).unwrap().is_none());
        let partial = &encode_frame(&header(5), b"hello")[..10];
        assert!(take_frame(partial).unwrap().is_none());
    }

    #[test]
    fn data_frames_go_over_the_datagram_channel_and_the_rest_over_the_stream() {
        assert!(goes_over_dgram(PacketType::Data));
        for pt in [
            PacketType::HandShake,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::RpcReq,
            PacketType::RpcResp,
        ] {
            assert!(!goes_over_dgram(pt), "{pt:?} 应该走可靠流");
        }
    }

    #[test]
    fn the_opener_rule_is_symmetric_and_picks_exactly_one_side() {
        let low = [0u8; 16];
        let high = [0xFF; 16];
        // 节点号小的一方发起；两端算出来的结果必然相反
        assert!(should_open_et_stream(&low, &high));
        assert!(!should_open_et_stream(&high, &low));
        assert_ne!(
            should_open_et_stream(&low, &high),
            should_open_et_stream(&high, &low)
        );

        // 不同字节位置都能比较（PeerId 是 16 字节数组，按字节序比）
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        b[15] = 1;
        assert!(should_open_et_stream(&a, &b));
        a[0] = 1;
        assert!(!should_open_et_stream(&a, &b), "高位字节更有分量");
    }
}
