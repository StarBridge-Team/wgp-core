//! ET 回退通道：没有 wgp 种子时，借 EasyTier 公共节点组一张临时网络，把本机的
//! 固定端口（DHT / 观察者 / 打洞）透明地送到对端。
//!
//! 为什么是「固定端口的 UDP 代理」而不是 ET 的 Port Forward：mesh-tun-proto 里的
//! `MeshPortForwarder` / `MeshTcpSocket` 还是占位实现（伪 TCP 会丢载荷），而
//! `send_data_to` / `P2pEvent::InboundUserData` 已经是可用的、能经公共中继多跳路由的
//! 自定义帧通道（见 `reports/et-fallback-seed-feasibility-2026-11-19.md`）。
//!
//! ## 拓扑
//!
//! ```text
//! 房主                                                  公共 ET 节点                    加入方
//! wgp 种子 127.0.0.1:11010/3478                            (relay)                     wgp 客户端
//!      ▲                                                                                  ▲
//!      │ 本机 UDP                                                                          │ 本机 UDP
//! 桥 127.0.0.2:{11010,3478,421xx} ── ET 自定义帧 ──► relay ──► 桥 127.0.0.2:{11010,3478,421xx}
//! ```
//!
//! - 每侧都在 `bind_ip`（默认 `127.0.0.2`，与 `127.0.0.1` 分开以免和本体进程抢端口）上
//!   监听三个固定服务端口，把收到的 UDP 报文封成 `[u16 端口][载荷]` 发给对端；
//! - 对端的同名端口收到后再写回本机应用：房主侧固定转发到 `127.0.0.1:<端口>`（本机的种子），
//!   加入方侧回给「最近一次从这个端口发出去的本地地址」——端口保持不变，所以 wgp 看到的
//!   对端地址始终是 `bind_ip:<端口>`，与它发出的目标一致（观察者应答的来源校验也就能过）；
//! - 打洞端口按 ET 节点号派生（`punch_base + peer_id % span`），双方都能算出对端的端口，
//!   因此不需要额外的协商：房主向 `bind_ip:punch(加入方)` 发包，加入方的桥正好在听那个端口。
//!
//! ## 已知边界
//!
//! - 一条桥上只支持**一个对端**参与数据面（fallback 里就是「房主 ⇄ 一个加入方」）。
//!   多个加入方要真正的 ET relay（官方 Core），轻量客户端不替别人转发，见桥接 README。
//! - 自建 relay 的可用性、限速与计费都不受本项目控制；日志里会明确写出「经公共 ET 中继」。

use anyhow::{anyhow, bail};
use mesh_tun_proto::{P2pEvent, P2pNode};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket as TokioUdp;
use tokio::sync::mpsc as tokio_mpsc;

/// 服务端口：DHT 信令与观察者（STUN）。两者都必须透传，否则加入方连 PING 都发不出去。
pub const SERVICE_PORT_DHT: u16 = 11010;
pub const SERVICE_PORT_STUN: u16 = 3478;
/// 打洞端口的派生基址与跨度：`punch_base + peer_id % span`
pub const PUNCH_BASE: u16 = 42_100;
pub const PUNCH_SPAN: u32 = 900;
/// 桥默认监听的地址：与 127.0.0.1 分开，本体进程照常用 127.0.0.1，不会抢端口
pub const DEFAULT_BIND_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// ET 节点线程的 tick 间隔（该库要求 ≤ 50ms）
const TICK: Duration = Duration::from_millis(40);
/// 每条连接每轮最多处理的帧数
const TICK_FRAMES: usize = 64;
/// 重连间隔
const RECONNECT: Duration = Duration::from_secs(3);
/// 接收缓冲：ET 帧上限按 UDP 报文来（65KB 够一个 IP 包）
const RECV_BUF: usize = 65_536;

/// `WGP_ET_DEBUG=1` 时把每一枚报文的去向打到 stderr（排障用）
fn debug_enabled() -> bool {
    std::env::var("WGP_ET_DEBUG").map(|v| v != "0").unwrap_or(false)
}

macro_rules! trace {
    ($($arg:tt)*) => {
        if debug_enabled() {
            eprintln!("[et-fallback] {}", format!($($arg)*));
        }
    };
}

/// `punch_base + peer_id % span`
pub fn punch_port(peer_id: u32) -> u16 {
    PUNCH_BASE + (peer_id % PUNCH_SPAN) as u16
}

/// 一条代理配置
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// 本侧监听的地址（默认 `127.0.0.2`）
    pub bind_ip: Ipv4Addr,
    /// 本侧应用（房主的种子 / 加入方的客户端）地址：房主侧固定 `127.0.0.1`；
    /// 加入方侧留 `None`——从它自己发出来的报文里学。
    pub local_app_ip: Option<Ipv4Addr>,
    /// 透传的固定服务端口
    pub service_ports: Vec<u16>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_ip: DEFAULT_BIND_IP,
            local_app_ip: None,
            service_ports: vec![SERVICE_PORT_DHT, SERVICE_PORT_STUN],
        }
    }
}

/// 把 `(端口, 载荷)` 编成一帧
pub fn encode_frame(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 解析一帧；长度不足或端口为 0 视为非法（静默丢弃，别让坏帧打断通道）
pub fn decode_frame(buf: &[u8]) -> Option<(u16, &[u8])> {
    if buf.len() < 3 {
        return None;
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    if port == 0 {
        return None;
    }
    Some((port, &buf[2..]))
}

/// ET 节点线程的命令
enum Command {
    Send { to: u32, frame: Vec<u8> },
    Stop,
}

/// 桥的事件（给命令行与日志用）
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    Ready { peer_id: u32, punch_port: u16 },
    PeerUp { peer_id: u32 },
    PeerDown { peer_id: u32 },
    /// 收到又送不出去的帧（没有对端 / 应用地址未知）
    Dropped { reason: String },
}

/// ET 节点线程：连 relay、握手、tick、收发自定义帧
struct EtLink {
    peer_id: u32,
    commands: std_mpsc::SyncSender<Command>,
    events: tokio_mpsc::UnboundedReceiver<P2pEvent>,
    thread: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    /// 当前到 relay 的流：`Drop` 时 `shutdown` 它，好让卡在握手/读上的线程立刻退出
    stream: Arc<Mutex<Option<TcpStream>>>,
}

impl EtLink {
    /// 连接一个 ET relay（`tcp://host:port` 里的 host:port），加入 `network/secret` 网络。
    ///
    /// 该库是「同步 + 手动 tick」模型，所以整条链路放在独立线程里：
    /// 命令用同步通道送进去，事件用异步通道送出来。
    fn connect(
        network: String,
        secret: String,
        relay: SocketAddr,
    ) -> anyhow::Result<Self> {
        let (cmd_tx, cmd_rx) = std_mpsc::sync_channel::<Command>(256);
        let (ev_tx, ev_rx) = tokio_mpsc::unbounded_channel::<P2pEvent>();
        let (id_tx, id_rx) = std_mpsc::channel::<u32>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let stream_slot: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        let stream_thread = stream_slot.clone();

        let thread = std::thread::Builder::new()
            .name("wgp-et-fallback".to_string())
            .spawn(move || {
                let mut node = P2pNode::new(network, secret, None);
                // no-tun：我们只在用户态搬 UDP 报文，不碰网卡
                node.set_my_tun_enabled(false);
                let my_id = node.identity.my_peer_id;
                if id_tx.send(my_id).is_err() {
                    return;
                }
                let mut connected = false;
                let mut last_connect: Option<Instant> = None;
                let mut last_announce: Option<Instant> = None;
                loop {
                    if stop_thread.load(Ordering::Relaxed) {
                        break;
                    }
                    // ① 保持一条到 relay 的连接（断了就重连）
                    if !connected && last_connect.map_or(true, |at| at.elapsed() >= RECONNECT) {
                        last_connect = Some(Instant::now());
                        if let Ok(stream) = TcpStream::connect_timeout(&relay, Duration::from_secs(5))
                        {
                            let _ = stream.set_nodelay(true);
                            // **必须设读超时**：该库的流式传输用阻塞 read，没有超时的话
                            // `tick()` 会一直卡在 read 里，命令与事件都轮不到（库的 examples/poc.rs
                            // 同样设了 100ms）。
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                            if let Ok(clone) = stream.try_clone() {
                                *stream_thread.lock().expect("stream 锁中毒") = Some(clone);
                            }
                            match node.add_stream_conn(stream) {
                                Ok(peer) => {
                                    connected = true;
                                    // 该库只在 tick 里发 PeerDown，不发 PeerUp：这里补一条，
                                    // 桥才知道「可以开始转发了」。
                                    let _ = ev_tx.send(P2pEvent::PeerUp {
                                        peer_id: peer,
                                        label: "relay".to_string(),
                                    });
                                }
                                Err(_) => {}
                            }
                            *stream_thread.lock().expect("stream 锁中毒") = None;
                        }
                        let _ = node.announce_self_to_all("wgp-fallback", None);
                        last_announce = Some(Instant::now());
                    }
                    // ② 周期重宣告：relay 侧的路由会老化
                    if last_announce.map_or(true, |at| at.elapsed() >= Duration::from_secs(10)) {
                        let _ = node.announce_self_to_all("wgp-fallback", None);
                        last_announce = Some(Instant::now());
                    }
                    // ③ 处理命令
                    while let Ok(cmd) = cmd_rx.try_recv() {
                        match cmd {
                            Command::Send { to, frame } => {
                                if let Err(e) = node.send_data_to(to, &frame) {
                                    trace!("send_data_to({to}) 失败：{e}；peers={:?}", node.connected_peers());
                                }
                            }
                            Command::Stop => return,
                        }
                    }
                    // ④ tick：驱动收发与保活
                    let events = node.tick(TICK_FRAMES);
                    for event in events {
                        if debug_enabled() {
                            trace!("ET 事件：{event:?}");
                        }
                        if ev_tx.send(event).is_err() {
                            return;
                        }
                    }
                    if node.connected_peers().is_empty() {
                        connected = false;
                    }
                    std::thread::sleep(TICK);
                }
            })
            .map_err(|e| anyhow!("启动 ET 线程失败：{e}"))?;

        let peer_id = id_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| anyhow!("ET 线程没有启动"))?;
        Ok(Self {
            peer_id,
            commands: cmd_tx,
            events: ev_rx,
            thread: Some(thread),
            stop,
            stream: stream_slot,
        })
    }

    fn send(&self, to: u32, frame: Vec<u8>) -> anyhow::Result<()> {
        self.commands
            .send(Command::Send { to, frame })
            .map_err(|_| anyhow!("ET 线程已退出"))
    }
}

impl Drop for EtLink {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.commands.try_send(Command::Stop);
        // 先把流打断：线程可能正卡在阻塞的握手/读上，不打断就要等 30 秒
        if let Some(stream) = self.stream.lock().expect("stream 锁中毒").take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// 桥本体：固定端口 ⇄ ET 自定义帧
pub struct FallbackBridge {
    config: ProxyConfig,
    link: EtLink,
    /// 每个绑定的端口一个 UDP socket（tokio）
    sockets: HashMap<u16, Arc<TokioUdp>>,
    /// `(对端, 端口) → 本机应用地址`：加入方侧从它自己发出的报文里学；房主侧固定为
    /// `127.0.0.1:<端口>`
    app_addr: Arc<Mutex<HashMap<(u32, u16), SocketAddr>>>,
    /// 已知对端（取第一个作为数据面的对端）
    peers: Arc<Mutex<Vec<u32>>>,
    event_tx: tokio_mpsc::UnboundedSender<BridgeEvent>,
}

impl FallbackBridge {
    /// 建桥：先在 `bind_ip` 上绑好固定端口，再连 relay。
    /// 返回桥本身与事件接收端（命令行用来打日志）。
    pub async fn start(
        config: ProxyConfig,
        network: String,
        secret: String,
        relay: SocketAddr,
    ) -> anyhow::Result<(Self, tokio_mpsc::UnboundedReceiver<BridgeEvent>)> {
        let mut sockets = HashMap::new();
        for port in &config.service_ports {
            let addr = SocketAddr::new(IpAddr::V4(config.bind_ip), *port);
            let sock = TokioUdp::bind(addr)
                .await
                .map_err(|e| anyhow!("绑定 {addr} 失败（{e}）"))?;
            sockets.insert(*port, Arc::new(sock));
        }
        let link = EtLink::connect(network, secret, relay)?;
        let (event_tx, events) = tokio_mpsc::unbounded_channel();
        Ok((
            Self {
                config,
                link,
                sockets,
                app_addr: Arc::new(Mutex::new(HashMap::new())),
                peers: Arc::new(Mutex::new(Vec::new())),
                event_tx,
            },
            events,
        ))
    }

    /// 本侧 ET 节点号与它对应的打洞端口（要写进 wgp 的端点宣告里）
    pub fn punch_port(&self) -> u16 {
        punch_port(self.link.peer_id)
    }

    pub fn peer_id(&self) -> u32 {
        self.link.peer_id
    }

    /// 本侧监听地址（wgp 应把它当作「种子 / 观察者 / 对端」的地址）
    pub fn bind_ip(&self) -> Ipv4Addr {
        self.config.bind_ip
    }

    /// 已连接的对端（取第一个当数据面对端）
    fn single_peer(&self) -> Option<u32> {
        let peers = self.peers.lock().expect("peers 锁中毒");
        match peers.len() {
            0 => None,
            1 => Some(peers[0]),
            _ => {
                // 多个对端时数据面只支持一个：仍然取第一个，并把这件事记在日志里
                Some(peers[0])
            }
        }
    }

    /// 为某个对端补一个打洞端口监听（`bind_ip:punch_port(peer)`）
    async fn ensure_punch_socket(&mut self, peer: u32) -> anyhow::Result<()> {
        let port = punch_port(peer);
        if self.sockets.contains_key(&port) {
            return Ok(());
        }
        let addr = SocketAddr::new(IpAddr::V4(self.config.bind_ip), port);
        let sock = TokioUdp::bind(addr)
            .await
            .map_err(|e| anyhow!("绑定打洞端口 {addr} 失败（{e}）"))?;
        self.sockets.insert(port, Arc::new(sock));
        Ok(())
    }

    /// 跑起来：转发两侧的报文，直到 `shutdown` 被触发或通道断开。
    pub async fn run(mut self, mut shutdown: tokio_mpsc::UnboundedReceiver<()>) {
        let _ = self.event_tx.send(BridgeEvent::Ready {
            peer_id: self.link.peer_id,
            punch_port: self.punch_port(),
        });
        let mut buf = vec![0u8; RECV_BUF];
        // ET 事件与 UDP 接收并行：用一个 select 轮询所有 socket
        loop {
            // ① 收 ET 帧（非阻塞）
            while let Ok(event) = self.link.events.try_recv() {
                match event {
                    P2pEvent::PeerUp { peer_id, .. } => {
                        self.peers.lock().expect("peers 锁中毒").push(peer_id);
                        if let Err(e) = self.ensure_punch_socket(peer_id).await {
                            let _ = self.event_tx.send(BridgeEvent::Dropped {
                                reason: e.to_string(),
                            });
                        }
                        let _ = self.event_tx.send(BridgeEvent::PeerUp { peer_id });
                    }
                    P2pEvent::PeerDown { peer_id, .. } => {
                        self.peers
                            .lock()
                            .expect("peers 锁中毒")
                            .retain(|p| *p != peer_id);
                        let _ = self.event_tx.send(BridgeEvent::PeerDown { peer_id });
                    }
                    P2pEvent::InboundUserData { from_peer_id, data } => {
                        self.on_frame(from_peer_id, &data).await;
                    }
                    _ => {}
                }
            }

            // ② 收本机应用的报文：任一 socket 有数据就转发
            let mut received: Option<(u16, SocketAddr, usize)> = None;
            for (port, sock) in self.sockets.iter() {
                match sock.try_recv_from(&mut buf) {
                    Ok((n, src)) => {
                        received = Some((*port, src, n));
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => continue,
                }
            }
            if let Some((port, src, n)) = received {
                self.on_local_datagram(port, src, &buf[..n]).await;
                continue; // 先把这枚处理完，再继续轮询（避免 buffer 被下一个覆盖）
            }

            if shutdown.try_recv().is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// 本机应用发来一枚报文：记下它的地址，转发给对端
    async fn on_local_datagram(&mut self, port: u16, src: SocketAddr, payload: &[u8]) {
        trace!("本地 -> 端口 {port}：来自 {src} 的 {} 字节", payload.len());
        let Some(peer) = self.single_peer() else {
            let _ = self.event_tx.send(BridgeEvent::Dropped {
                reason: format!("端口 {port} 收到报文，但还没有连上任何 ET 对端"),
            });
            return;
        };
        self.app_addr
            .lock()
            .expect("app_addr 锁中毒")
            .insert((peer, port), src);
        let frame = encode_frame(port, payload);
        trace!("转发给对端 {peer}：端口 {port}，{} 字节", payload.len());
        if let Err(e) = self.link.send(peer, frame) {
            let _ = self.event_tx.send(BridgeEvent::Dropped {
                reason: e.to_string(),
            });
        }
    }

    /// ET 帧到达：写回本机应用
    async fn on_frame(&mut self, from: u32, data: &[u8]) {
        let Some((port, payload)) = decode_frame(data) else {
            return;
        };
        let Some(sock) = self.sockets.get(&port).cloned() else {
            let _ = self.event_tx.send(BridgeEvent::Dropped {
                reason: format!("没有监听端口 {port}（对端帧的目标端口不认识）"),
            });
            return;
        };
        // 目标地址：房主侧固定 `local_app_ip:port`；加入方侧用「最近一次从该端口发出去的地址」
        let dst = match self.config.local_app_ip {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), port),
            None => match self
                .app_addr
                .lock()
                .expect("app_addr 锁中毒")
                .get(&(from, port))
                .copied()
            {
                Some(addr) => addr,
                None => {
                    let _ = self.event_tx.send(BridgeEvent::Dropped {
                        reason: format!("端口 {port}：还不知道本机应用地址，丢弃 {from} 的帧"),
                    });
                    return;
                }
            },
        };
        trace!("对端 {from} -> 端口 {port}：写回 {dst}（{} 字节）", payload.len());
        if let Err(e) = sock.send_to(payload, dst).await {
            trace!("写回 {dst} 失败：{e}");
        }
    }
}

/// `tcp://host:port` / `host:port` → SocketAddr（只解析字面 IPv4 或域名，用系统解析）
pub fn parse_relay(spec: &str) -> anyhow::Result<SocketAddr> {
    let spec = spec.trim();
    let spec = spec.strip_prefix("tcp://").unwrap_or(spec);
    if spec.is_empty() {
        bail!("relay 不能为空（应为 tcp://主机:端口）");
    }
    use std::net::ToSocketAddrs;
    let mut addrs = spec
        .to_socket_addrs()
        .map_err(|e| anyhow!("relay 解析失败（{spec}）：{e}"))?;
    addrs
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow!("relay {spec} 没有 IPv4 地址"))
}

/// 从房间码派生的临时网络名与密钥（两侧算法必须一致）。
///
/// 网络名带房间键前 4 字节、密钥用房间键中段：**只有拿到房间码的人能加入这张网**，
/// 不同房间天然隔离。ET 侧只按「网络名 + 密钥摘要」做准入，所以这里不需要更强的 KDF。
pub fn derive_network(room_key: &[u8; 32]) -> (String, String) {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    (
        format!("wgp-{}", hex(&room_key[..4])),
        hex(&room_key[8..24]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_rejects_bad_input() {
        let frame = encode_frame(11_010, b"hello");
        let (port, payload) = decode_frame(&frame).expect("应能解出");
        assert_eq!(port, 11_010);
        assert_eq!(payload, b"hello");
        assert!(decode_frame(&[]).is_none());
        assert!(decode_frame(&[0, 1]).is_none(), "不足 3 字节");
        assert!(decode_frame(&[0, 0, 9]).is_none(), "端口 0 非法");
    }

    #[test]
    fn punch_port_is_derived_and_in_range() {
        for peer in [0u32, 1, 12_345, u32::MAX] {
            let port = punch_port(peer);
            assert!((PUNCH_BASE..PUNCH_BASE + PUNCH_SPAN as u16).contains(&port));
        }
        assert_eq!(punch_port(0), PUNCH_BASE);
        assert_eq!(punch_port(PUNCH_SPAN + 7), PUNCH_BASE + 7, "按跨度回绕");
    }

    #[test]
    fn network_is_derived_from_the_room_key() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (name, secret) = derive_network(&key);
        assert!(name.starts_with("wgp-"));
        assert_eq!(name.len(), 4 + 8, "名字带 4 字节房间键前缀");
        assert_eq!(secret.len(), 32, "密钥是 16 字节的十六进制");
        // 不同房间 → 不同网络
        let mut other = key;
        other[0] ^= 0xff;
        assert_ne!(derive_network(&other), (name, secret));
        // 同一房间 → 完全一致（两侧必须算出同一张网）
        assert_eq!(derive_network(&key), derive_network(&key));
    }

    #[test]
    fn relay_parsing_accepts_both_forms() {
        let a = parse_relay("tcp://127.0.0.1:11010").expect("带 scheme");
        let b = parse_relay("127.0.0.1:11010").expect("裸地址");
        assert_eq!(a, b);
        assert!(parse_relay("").is_err());
        assert!(parse_relay("tcp://127.0.0.1").is_err(), "缺端口");
    }
}
