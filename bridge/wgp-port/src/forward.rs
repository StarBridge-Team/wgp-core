//! 端口转发：本地端口 ⇄ 隧道流（wgp-port 的用户可见面）。
//!
//! 两个角色，同一进程可同时担任：
//!  - 暴露（expose）：允许对端经隧道连到本机的某个服务（如房主的 25565）。
//!    只有显式列出的端口可达——对端无法借隧道连本机的其他端口。
//!  - 转发（forward）：在本机开一个监听口，连进来的流量经隧道送到对端暴露的端口。
//!
//! TCP 一条连接对应一条隧道流；UDP（基岩版等）走隧道的数据报旁路，按来源地址分配流号。
//! [`PortHub`] 同时就是内核的 `LinkSink`：打洞成功的链路交付到这里即成为隧道。

use crate::mux::{
    Carrier, InboundDgram, IncomingStream, PeerHello, Tunnel, TunnelConfig, TunnelError,
    TunnelHandle, TunnelStream,
};
use crate::{close_code, CloseReason};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use wgp_core::{LinkLossCause, LinkSink, PeerId, PunchedLink};

/// 连接本机被暴露服务的超时
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 双向拷贝缓冲
const COPY_BUF: usize = 16 * 1024;
/// UDP 流空闲回收时间（02 §2.1.1：GameUdp 空闲超时 60s）
const UDP_FLOW_IDLE: Duration = Duration::from_secs(60);
const MAX_UDP_FLOWS: usize = 512;
const UDP_FLOW_QUEUE: usize = 64;
/// 「无可用对端」事件的最小间隔（毫秒）：客户端反复重连时不刷屏
const NO_PROVIDER_EVENT_GAP_MS: u64 = 2_000;

/// 暴露规则：对端请求 `port` 时，连到本机的 `target`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposeRule {
    pub port: u16,
    pub target: SocketAddr,
}

/// 转发规则：监听本机 `listen`，流量送往对端暴露的 `remote_port`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardRule {
    pub listen: SocketAddr,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct PortConfig {
    pub expose_tcp: Vec<ExposeRule>,
    pub forward_tcp: Vec<ForwardRule>,
    pub expose_udp: Vec<ExposeRule>,
    pub forward_udp: Vec<ForwardRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// 数据面事件（供外围呈现；不含任何业务数据）
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PortEvent {
    /// 本地转发口已开始监听
    Listening {
        proto: Proto,
        listen: SocketAddr,
        remote_port: u16,
    },
    /// 链路已接管、隧道已启动（尚未收到对端应答）
    TunnelUp {
        peer: PeerId,
        carrier: Carrier,
        peer_addr: SocketAddr,
    },
    /// 收到对端 HELLO：隧道双向可用，并得知对端暴露了哪些端口
    TunnelReady {
        peer: PeerId,
        tcp: Vec<u16>,
        udp: Vec<u16>,
    },
    TunnelDown {
        peer: PeerId,
        reason: CloseReason,
    },
    /// 交付的链路无法建成隧道
    TunnelFailed {
        peer: PeerId,
        error: TunnelError,
    },
    /// 一条 TCP 转发连接开始（`inbound` = 对端连入本机暴露的服务）
    StreamOpened {
        peer: PeerId,
        port: u16,
        inbound: bool,
    },
    /// 本地有连接进来，但当前没有任何对端暴露该端口
    NoProvider {
        proto: Proto,
        remote_port: u16,
    },
    /// 对端请求的暴露端口在本机连不上（服务没开）
    TargetUnreachable {
        port: u16,
        target: SocketAddr,
    },
    /// 内核报告打洞失败
    LinkLost {
        peer: PeerId,
        cause: LinkLossCause,
    },
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // 临界区内只有简单的表操作；即便持锁线程曾 panic，表本身仍可用
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct PeerSlot {
    handle: TunnelHandle,
    hello: Option<PeerHello>,
    /// 同一对端重新打洞时新旧隧道交替：用代号区分，旧隧道收尾时不误删新槽位
    generation: u64,
}

#[derive(Default)]
struct FlowTable {
    by_addr: HashMap<SocketAddr, (u32, Instant)>,
    by_flow: HashMap<u32, SocketAddr>,
    next_flow: u32,
}

/// 一个 UDP 转发口：本地客户端地址 ⇄ 流号
struct UdpForward {
    socket: UdpSocket,
    remote_port: u16,
    flows: Mutex<FlowTable>,
}

impl UdpForward {
    fn flow_for(&self, from: SocketAddr, now: Instant) -> u32 {
        let mut table = lock(&self.flows);
        if let Some((flow, seen)) = table.by_addr.get_mut(&from) {
            *seen = now;
            return *flow;
        }
        if table.by_addr.len() >= MAX_UDP_FLOWS {
            let stale: Vec<SocketAddr> = table
                .by_addr
                .iter()
                .filter(|(_, (_, seen))| now.saturating_duration_since(*seen) > UDP_FLOW_IDLE)
                .map(|(addr, _)| *addr)
                .collect();
            for addr in stale {
                if let Some((flow, _)) = table.by_addr.remove(&addr) {
                    table.by_flow.remove(&flow);
                }
            }
        }
        table.next_flow = table.next_flow.wrapping_add(1);
        let flow = table.next_flow;
        table.by_addr.insert(from, (flow, now));
        table.by_flow.insert(flow, from);
        flow
    }

    fn deliver_reply(&self, flow: u32, data: &[u8]) {
        let addr = lock(&self.flows).by_flow.get(&flow).copied();
        if let Some(addr) = addr {
            let _ = self.socket.try_send_to(data, addr);
        }
    }
}

struct HubInner {
    local: PeerId,
    cfg: PortConfig,
    events: mpsc::UnboundedSender<PortEvent>,
    peers: Mutex<HashMap<PeerId, PeerSlot>>,
    generation: AtomicU64,
    udp_forwards: Vec<Arc<UdpForward>>,
    /// 暴露侧的 UDP 流：(对端, 端口, 流号) → 该流任务的投递口
    udp_flows: Mutex<HashMap<(PeerId, u16, u32), mpsc::Sender<Vec<u8>>>>,
    started: Instant,
    last_no_provider_ms: AtomicU64,
}

impl HubInner {
    fn emit(&self, event: PortEvent) {
        let _ = self.events.send(event);
    }

    fn emit_no_provider(&self, proto: Proto, remote_port: u16) {
        let now_ms = self.started.elapsed().as_millis() as u64 + NO_PROVIDER_EVENT_GAP_MS;
        let last = self.last_no_provider_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= NO_PROVIDER_EVENT_GAP_MS {
            self.last_no_provider_ms.store(now_ms, Ordering::Relaxed);
            self.emit(PortEvent::NoProvider { proto, remote_port });
        }
    }

    /// 找一个暴露了 `port` 且隧道仍在的对端（多个时取最新建立的）
    fn provider(&self, proto: Proto, port: u16) -> Option<(PeerId, TunnelHandle)> {
        lock(&self.peers)
            .iter()
            .filter(|(_, slot)| slot.handle.close_reason().is_none())
            .filter(|(_, slot)| {
                slot.hello.as_ref().is_some_and(|hello| match proto {
                    Proto::Tcp => hello.tcp.contains(&port),
                    Proto::Udp => hello.udp.contains(&port),
                })
            })
            .max_by_key(|(_, slot)| slot.generation)
            .map(|(peer, slot)| (*peer, slot.handle.clone()))
    }

    fn on_dgram(&self, peer: PeerId, handle: &TunnelHandle, dgram: InboundDgram) {
        if dgram.reply {
            // 对端服务的回包 → 送回对应转发口的本地客户端
            if let Some(fwd) = self
                .udp_forwards
                .iter()
                .find(|fwd| fwd.remote_port == dgram.port)
            {
                fwd.deliver_reply(dgram.flow, &dgram.data);
            }
            return;
        }
        // 对端发往本机暴露服务的数据报
        let Some(rule) = self.cfg.expose_udp.iter().find(|r| r.port == dgram.port) else {
            return;
        };
        let key = (peer, dgram.port, dgram.flow);
        let mut flows = lock(&self.udp_flows);
        let data = match flows.get(&key) {
            Some(tx) => match tx.try_send(dgram.data) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => return,
                // 该流的任务已因空闲退出：重建
                Err(mpsc::error::TrySendError::Closed(data)) => data,
            },
            None => dgram.data,
        };
        if flows.len() >= MAX_UDP_FLOWS {
            flows.retain(|_, tx| !tx.is_closed());
            if flows.len() >= MAX_UDP_FLOWS {
                return;
            }
        }
        let (tx, rx) = mpsc::channel(UDP_FLOW_QUEUE);
        let _ = tx.try_send(data);
        flows.insert(key, tx);
        drop(flows);
        tokio::spawn(udp_expose_flow(
            rule.target,
            rx,
            handle.clone(),
            dgram.port,
            dgram.flow,
        ));
    }
}

/// 端口转发中枢：持有本地监听口与各对端的隧道。可克隆（共享同一中枢）。
#[derive(Clone)]
pub struct PortHub {
    inner: Arc<HubInner>,
}

impl PortHub {
    /// 绑定全部转发口并启动。任一端口绑定失败即整体失败（启动时就暴露问题，
    /// 而不是等打洞成功后才发现端口被占）。`local` 为本端 PeerId。
    pub async fn start(
        local: PeerId,
        cfg: PortConfig,
    ) -> io::Result<(PortHub, mpsc::UnboundedReceiver<PortEvent>)> {
        let (events, events_rx) = mpsc::unbounded_channel();

        let mut listeners = Vec::new();
        for rule in &cfg.forward_tcp {
            let listener = TcpListener::bind(rule.listen).await.map_err(|e| {
                io::Error::new(e.kind(), format!("绑定 TCP 转发口 {} 失败：{e}", rule.listen))
            })?;
            let _ = events.send(PortEvent::Listening {
                proto: Proto::Tcp,
                listen: listener.local_addr()?,
                remote_port: rule.remote_port,
            });
            listeners.push((listener, rule.remote_port));
        }
        let mut udp_forwards = Vec::new();
        for rule in &cfg.forward_udp {
            let socket = UdpSocket::bind(rule.listen).await.map_err(|e| {
                io::Error::new(e.kind(), format!("绑定 UDP 转发口 {} 失败：{e}", rule.listen))
            })?;
            let _ = events.send(PortEvent::Listening {
                proto: Proto::Udp,
                listen: socket.local_addr()?,
                remote_port: rule.remote_port,
            });
            udp_forwards.push(Arc::new(UdpForward {
                socket,
                remote_port: rule.remote_port,
                flows: Mutex::new(FlowTable::default()),
            }));
        }

        let inner = Arc::new(HubInner {
            local,
            cfg,
            events,
            peers: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            udp_forwards,
            udp_flows: Mutex::new(HashMap::new()),
            started: Instant::now(),
            last_no_provider_ms: AtomicU64::new(0),
        });
        for (listener, remote_port) in listeners {
            tokio::spawn(accept_loop(inner.clone(), listener, remote_port));
        }
        for fwd in &inner.udp_forwards {
            tokio::spawn(udp_forward_loop(inner.clone(), fwd.clone()));
        }
        Ok((PortHub { inner }, events_rx))
    }

    /// 接管一条打通的链路并建成隧道；该对端已有隧道时以新代旧（14 §10 条款 5）。
    /// 必须在 tokio 运行时内调用。
    pub fn attach_link(&self, peer: PeerId, link: PunchedLink) {
        let inner = &self.inner;
        let peer_addr = link.peer_addr;
        let cfg = TunnelConfig {
            expose_tcp: inner.cfg.expose_tcp.iter().map(|r| r.port).collect(),
            expose_udp: inner.cfg.expose_udp.iter().map(|r| r.port).collect(),
        };
        let tunnel = match Tunnel::from_link(inner.local, link, cfg) {
            Ok(tunnel) => tunnel,
            Err(error) => {
                inner.emit(PortEvent::TunnelFailed { peer, error });
                return;
            }
        };
        let generation = inner.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let replaced = lock(&inner.peers).insert(
            peer,
            PeerSlot {
                handle: tunnel.handle.clone(),
                hello: None,
                generation,
            },
        );
        if let Some(old) = replaced {
            old.handle.close(close_code::REPLACED);
        }
        inner.emit(PortEvent::TunnelUp {
            peer,
            carrier: tunnel.carrier,
            peer_addr,
        });
        tokio::spawn(serve_tunnel(inner.clone(), peer, tunnel, generation));
    }

    /// 该对端当前是否有未关闭的隧道
    pub fn has_tunnel(&self, peer: &PeerId) -> bool {
        lock(&self.inner.peers)
            .get(peer)
            .is_some_and(|slot| slot.handle.close_reason().is_none())
    }

    /// 关闭与某个对端的隧道（若有）
    pub fn close_peer(&self, peer: &PeerId, code: u8) {
        if let Some(slot) = lock(&self.inner.peers).get(peer) {
            slot.handle.close(code);
        }
    }

    /// 关闭全部隧道（退出前调用：对端可立即得知，而不必等到超时）
    pub fn shutdown(&self) {
        for slot in lock(&self.inner.peers).values() {
            slot.handle.close(close_code::NORMAL);
        }
    }
}

impl LinkSink for PortHub {
    fn on_link_yielded(&self, peer: PeerId, link: PunchedLink) {
        self.attach_link(peer, link);
    }

    fn on_link_upgraded(&self, peer: PeerId, link: PunchedLink) {
        self.attach_link(peer, link);
    }

    fn on_link_lost(&self, peer: PeerId, cause: LinkLossCause) {
        self.inner.emit(PortEvent::LinkLost { peer, cause });
    }
}

/// 一条隧道的伴生任务：记录对端 HELLO、接入对端发起的流与数据报、收尾
async fn serve_tunnel(inner: Arc<HubInner>, peer: PeerId, tunnel: Tunnel, generation: u64) {
    let Tunnel {
        handle,
        mut incoming,
        mut dgrams,
        ..
    } = tunnel;
    let mut hello_pending = true;
    let reason = loop {
        tokio::select! {
            reason = handle.closed() => break reason,
            hello = handle.peer_hello(), if hello_pending => {
                hello_pending = false;
                if let Some(hello) = hello {
                    {
                        let mut peers = lock(&inner.peers);
                        if let Some(slot) = peers.get_mut(&peer) {
                            if slot.generation == generation {
                                slot.hello = Some(hello.clone());
                            }
                        }
                    }
                    inner.emit(PortEvent::TunnelReady {
                        peer,
                        tcp: hello.tcp,
                        udp: hello.udp,
                    });
                }
            }
            Some(stream) = incoming.recv() => {
                tokio::spawn(serve_incoming(inner.clone(), peer, stream));
            }
            Some(dgram) = dgrams.recv() => inner.on_dgram(peer, &handle, dgram),
        }
    };
    {
        let mut peers = lock(&inner.peers);
        if peers
            .get(&peer)
            .is_some_and(|slot| slot.generation == generation)
        {
            peers.remove(&peer);
        }
    }
    inner.emit(PortEvent::TunnelDown { peer, reason });
}

/// 转发口：接受本地连接，经隧道连向对端暴露的端口
async fn accept_loop(inner: Arc<HubInner>, listener: TcpListener, remote_port: u16) {
    loop {
        let conn = match listener.accept().await {
            Ok((conn, _)) => conn,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some((peer, handle)) = inner.provider(Proto::Tcp, remote_port) else {
            // 没有对端可送：直接关闭本地连接（应用侧看到的是连接被关闭）
            inner.emit_no_provider(Proto::Tcp, remote_port);
            continue;
        };
        if let Ok(stream) = handle.open_stream(remote_port) {
            inner.emit(PortEvent::StreamOpened {
                peer,
                port: remote_port,
                inbound: false,
            });
            tokio::spawn(bridge(conn, stream));
        }
    }
}

/// 暴露侧：对端开流 → 连本机服务 → 双向拷贝
async fn serve_incoming(inner: Arc<HubInner>, peer: PeerId, incoming: IncomingStream) {
    let IncomingStream { port, stream } = incoming;
    let Some(rule) = inner.cfg.expose_tcp.iter().find(|r| r.port == port).copied() else {
        return; // stream 在此丢弃 → 对端收到重置
    };
    let conn = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(rule.target)).await {
        Ok(Ok(conn)) => conn,
        _ => {
            inner.emit(PortEvent::TargetUnreachable {
                port,
                target: rule.target,
            });
            return;
        }
    };
    inner.emit(PortEvent::StreamOpened {
        peer,
        port,
        inbound: true,
    });
    bridge(conn, stream).await;
}

/// 本地 TCP 连接 ⇄ 隧道流，双向拷贝，保留半关闭语义。
/// 任一方向出错即整体中止：未正常结束的那一半在丢弃时向对端发 RST。
async fn bridge(conn: TcpStream, stream: TunnelStream) {
    let _ = conn.set_nodelay(true); // 02 §2.2：小包即发
    let (mut local_rd, mut local_wr) = conn.into_split();
    let (mut reader, mut writer) = stream.split();

    let upstream = async {
        let mut buf = vec![0u8; COPY_BUF];
        loop {
            let n = local_rd.read(&mut buf).await?;
            if n == 0 {
                writer.finish().await;
                return Ok::<(), io::Error>(());
            }
            writer.write(&buf[..n]).await?;
        }
    };
    let downstream = async {
        loop {
            match reader.read().await? {
                Some(chunk) => local_wr.write_all(&chunk).await?,
                None => {
                    let _ = local_wr.shutdown().await;
                    return Ok::<(), io::Error>(());
                }
            }
        }
    };
    tokio::pin!(upstream, downstream);
    let (mut up_done, mut down_done) = (false, false);
    while !(up_done && down_done) {
        tokio::select! {
            result = &mut upstream, if !up_done => {
                up_done = true;
                if result.is_err() {
                    break;
                }
            }
            result = &mut downstream, if !down_done => {
                down_done = true;
                if result.is_err() {
                    break;
                }
            }
        }
    }
}

/// UDP 转发口：本地客户端发来的数据报 → 隧道数据报（按来源地址分流号）
async fn udp_forward_loop(inner: Arc<HubInner>, fwd: Arc<UdpForward>) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, from) = match fwd.socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(_) => {
                // Windows 上目的端口不可达会以 recv 错误冒出：稍等再读，避免空转
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };
        let flow = fwd.flow_for(from, Instant::now());
        match inner.provider(Proto::Udp, fwd.remote_port) {
            // 超长或隧道拥塞时返回 false：数据报直接丢弃（上层协议自有重传/探测）
            Some((_, handle)) => {
                let _ = handle.send_dgram(false, fwd.remote_port, flow, &buf[..n]);
            }
            None => inner.emit_no_provider(Proto::Udp, fwd.remote_port),
        }
    }
}

/// 暴露侧的一条 UDP 流：专用 socket 连向本机服务，回包经隧道送回；空闲即回收
async fn udp_expose_flow(
    target: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    handle: TunnelHandle,
    port: u16,
    flow: u32,
) {
    let bind: SocketAddr = if target.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return;
    };
    if socket.connect(target).await.is_err() {
        return;
    }
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            outbound = rx.recv() => match outbound {
                Some(data) => {
                    let _ = socket.send(&data).await;
                }
                None => break,
            },
            received = socket.recv(&mut buf) => match received {
                Ok(n) => {
                    let _ = handle.send_dgram(true, port, flow, &buf[..n]);
                }
                // 服务未启动时 Windows 会报连接重置：稍等再读，等空闲超时自然回收
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            },
            _ = tokio::time::sleep(UDP_FLOW_IDLE) => break,
            _ = handle.closed() => break,
        }
    }
}
