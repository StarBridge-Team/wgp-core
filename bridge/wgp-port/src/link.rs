//! 链路驱动：把 `PunchedLink` 的原始载体变成统一的「可靠字节流 + 数据报旁路」接口。
//!
//!  - UDP（主档 / LAN）：收包按类型字节分流（内核保活探针 vs 隧道报文）→ 重放窗口 →
//!    AEAD 开封 → 可靠层（arq）；发包反之。
//!  - TCP（降级档）：AEAD 记录流（长度前缀），计数器隐式递增——TCP 自身保序，
//!    任何一条记录认证失败都意味着流已被破坏，直接断开。
//!
//! 与内核的边界：打洞成功后内核的保活哨兵继续在同一个 UDP socket 上**只发不收**，
//! 收方向完全归本层。对端内核发来的 31B 探针在这里被识别并吞掉（本层没有探针密钥，
//! 不验签，只把它当作「对端进程还在」的弱信号）。

use crate::arq::Arq;
use crate::{close_code, CloseReason};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use wgp_crypto::tunnel::{ReplayWindow, TunnelOpener, TunnelSealer, TAG_LEN};
use wgp_proto::packet::{classify, probe, tunnel};

/// UDP 载体上单个隧道报文（UDP 载荷）的最大长度。
/// 加 28B IP/UDP 头后为 1328B，低于内核报告的 1400 路径 MTU，也低于常见 PPPoE/隧道路径。
pub(crate) const MAX_UDP_DATAGRAM: usize = 1300;
/// 单报文明文预算
pub(crate) const UDP_MAX_PAYLOAD: usize = MAX_UDP_DATAGRAM - tunnel::HEADER_LEN - TAG_LEN;
/// 对端完全静默（无隧道报文、无内核保活探针）达到此时长即判定链路已死。
/// 内核保活间隔 2s（多链路时均摊，10 条链路约 15s），留足余量。
const PEER_SILENCE_TIMEOUT: Duration = Duration::from_secs(90);
/// 无定时器时的巡检周期（只为检查对端静默，不发包）
const IDLE_TICK: Duration = Duration::from_secs(5);
const STREAM_CHANNEL_CAP: usize = 64;
const DGRAM_CHANNEL_CAP: usize = 256;
/// 一次唤醒最多连续收取的报文数（避免收包狂潮饿死发送与定时器）
const RECV_BATCH: usize = 64;
/// 收发缓冲：系统默认（Windows 64KB）在突发下会溢出丢包
const SOCKET_BUFFER_BYTES: usize = 2 * 1024 * 1024;
/// 连续收包错误达到此数视为 socket 已不可用
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 1000;

/// TCP 记录明文上限（含 1B 类型）
const TCP_MAX_RECORD: usize = 32 * 1024;
/// TCP 载体上数据报载荷上限
pub(crate) const TCP_MAX_DGRAM: usize = 16 * 1024;
/// TCP 记录 AAD 头部的 flags（与 UDP 报文的 0 区分）
const TCP_RECORD_FLAG: u8 = 0x01;
const REC_STREAM: u8 = 0;
const REC_DGRAM: u8 = 1;
const REC_CLOSE: u8 = 2;

/// 上层 → 链路
pub(crate) enum LinkCmd {
    /// 可靠字节流数据
    Bytes(Vec<u8>),
    /// 关闭链路并把原因码告知对端
    Close(u8),
}

/// 链路 → 上层
pub(crate) enum LinkEvent {
    /// 按序到达的可靠字节流数据
    Bytes(Vec<u8>),
    /// 数据报（不保证送达、不保序）
    Dgram(Vec<u8>),
    /// 链路已关闭（最后一个事件）
    Closed(CloseReason),
}

/// 链路的上层句柄。丢弃 `stream_tx` 等价于 `LinkCmd::Close(NORMAL)`。
pub(crate) struct LinkIo {
    pub stream_tx: mpsc::Sender<LinkCmd>,
    /// 数据报发送口：满则丢（调用方用 try_send）
    pub dgram_tx: mpsc::Sender<Vec<u8>>,
    pub events: mpsc::UnboundedReceiver<LinkEvent>,
    /// 单个数据报载荷上限
    pub max_dgram: usize,
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

struct UdpLink {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    sealer: TunnelSealer,
    opener: TunnelOpener,
    replay: ReplayWindow,
    arq: Arq,
    /// 最近一次见到对端迹象（认证通过的隧道报文，或对端内核的保活探针）的时刻
    last_peer_sign: Instant,
    /// 对端发来过畸形的（但认证通过的）报文
    violated: bool,
}

impl UdpLink {
    fn on_datagram(&mut self, pkt: &[u8], src: SocketAddr, now: Instant) {
        match classify(pkt) {
            Some(probe::TYPE) => {
                if pkt.len() == probe::LEN && src.ip() == self.peer.ip() {
                    self.last_peer_sign = now;
                }
            }
            Some(tunnel::TYPE) => {
                let Some((_flags, pn)) = tunnel::decode_header(pkt) else {
                    return;
                };
                // 先查重放窗口（省掉对重放包的 AEAD），验签通过后才登记——伪造包推不动窗口
                if !self.replay.check(pn) {
                    return;
                }
                let (header, body) = pkt.split_at(tunnel::HEADER_LEN);
                let Some(plain) = self.opener.open(pn, header, body) else {
                    return;
                };
                if !self.replay.commit(pn) {
                    return;
                }
                self.last_peer_sign = now;
                // 对端地址漂移（NAT 重绑定）：认证通过的新报文从哪来，回程就发往哪
                if src != self.peer {
                    self.peer = src;
                }
                if self.arq.on_packet(pn, &plain, now).is_err() {
                    self.violated = true;
                    self.arq.close(close_code::PROTOCOL);
                }
            }
            _ => {} // 既非探针也非隧道报文：杂包，静默丢弃
        }
    }

    async fn flush(&mut self, now: Instant) {
        while let Some((pn, payload)) = self.arq.poll_transmit(now) {
            let mut header = [0u8; tunnel::HEADER_LEN];
            tunnel::encode_header(0, pn, &mut header);
            let Some(sealed) = self.sealer.seal(pn, &header, &payload) else {
                continue;
            };
            let mut pkt = Vec::with_capacity(header.len() + sealed.len());
            pkt.extend_from_slice(&header);
            pkt.extend_from_slice(&sealed);
            // 发送失败等同丢包：由可靠层重传兜底
            let _ = self.socket.send_to(&pkt, self.peer).await;
        }
    }
}

fn tune_udp_buffers(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(SOCKET_BUFFER_BYTES);
    let _ = sock.set_send_buffer_size(SOCKET_BUFFER_BYTES);
}

/// 接管一条打通的 UDP 链路（必须在 tokio 运行时内调用）
pub(crate) fn spawn_udp(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    sealer: TunnelSealer,
    opener: TunnelOpener,
) -> LinkIo {
    tune_udp_buffers(&socket);
    let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_CAP);
    let (dgram_tx, dgram_rx) = mpsc::channel(DGRAM_CHANNEL_CAP);
    let (ev_tx, events) = mpsc::unbounded_channel();
    let now = Instant::now();
    let arq = Arq::new(UDP_MAX_PAYLOAD, now);
    let max_dgram = arq.max_dgram();
    let link = UdpLink {
        socket,
        peer,
        sealer,
        opener,
        replay: ReplayWindow::new(),
        arq,
        last_peer_sign: now,
        violated: false,
    };
    tokio::spawn(udp_task(link, stream_rx, dgram_rx, ev_tx));
    LinkIo {
        stream_tx,
        dgram_tx,
        events,
        max_dgram,
    }
}

async fn udp_task(
    mut link: UdpLink,
    mut stream_rx: mpsc::Receiver<LinkCmd>,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    ev_tx: mpsc::UnboundedSender<LinkEvent>,
) {
    let mut buf = vec![0u8; 2048];
    let mut stream_open = true;
    let mut dgram_open = true;
    let mut recv_errors = 0u32;
    loop {
        let now = Instant::now();
        link.flush(now).await;
        while let Some(bytes) = link.arq.take_stream() {
            if ev_tx.send(LinkEvent::Bytes(bytes)).is_err() {
                return; // 上层已不在
            }
        }
        while let Some(dgram) = link.arq.take_dgram() {
            let _ = ev_tx.send(LinkEvent::Dgram(dgram));
        }
        if let Some(reason) = link.arq.closed() {
            let reason = if link.violated {
                CloseReason::Protocol
            } else {
                reason
            };
            let _ = ev_tx.send(LinkEvent::Closed(reason));
            return;
        }
        if now.saturating_duration_since(link.last_peer_sign) >= PEER_SILENCE_TIMEOUT {
            let _ = ev_tx.send(LinkEvent::Closed(CloseReason::PeerSilent));
            return;
        }

        let idle_tick = now + IDLE_TICK;
        let deadline = link.arq.next_timeout().map_or(idle_tick, |t| t.min(idle_tick));
        let want_stream = stream_open && link.arq.send_capacity() > 0;
        tokio::select! {
            received = link.socket.recv_from(&mut buf) => {
                let now = Instant::now();
                match received {
                    Ok((n, src)) => {
                        recv_errors = 0;
                        link.on_datagram(&buf[..n], src, now);
                    }
                    // Windows 上对端端口不可达的 ICMP 会以 recv 错误的形式冒出来：忽略即可，
                    // 对端是否真的没了由可靠层超时与静默检测判断
                    Err(_) => {
                        recv_errors += 1;
                        if recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                            let _ = ev_tx.send(LinkEvent::Closed(CloseReason::Io));
                            return;
                        }
                    }
                }
                for _ in 0..RECV_BATCH {
                    match link.socket.try_recv_from(&mut buf) {
                        Ok((n, src)) => link.on_datagram(&buf[..n], src, now),
                        Err(_) => break,
                    }
                }
            }
            cmd = stream_rx.recv(), if want_stream => match cmd {
                Some(LinkCmd::Bytes(bytes)) => link.arq.push_stream(&bytes, Instant::now()),
                Some(LinkCmd::Close(code)) => {
                    stream_open = false;
                    link.arq.close(code);
                }
                None => {
                    stream_open = false;
                    link.arq.close(close_code::NORMAL);
                }
            },
            dgram = dgram_rx.recv(), if dgram_open => match dgram {
                Some(dgram) => {
                    let _ = link.arq.push_dgram(dgram);
                }
                None => dgram_open = false,
            },
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                link.arq.on_timeout(Instant::now());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// 接管一条打通的 TCP 链路（必须在 tokio 运行时内调用）
pub(crate) fn spawn_tcp(stream: TcpStream, sealer: TunnelSealer, opener: TunnelOpener) -> LinkIo {
    let _ = stream.set_nodelay(true);
    let (rd, wr) = stream.into_split();
    let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_CAP);
    let (dgram_tx, dgram_rx) = mpsc::channel(DGRAM_CHANNEL_CAP);
    let (ev_tx, events) = mpsc::unbounded_channel();
    tokio::spawn(tcp_reader(rd, opener, ev_tx.clone()));
    tokio::spawn(tcp_writer(wr, sealer, stream_rx, dgram_rx, ev_tx));
    LinkIo {
        stream_tx,
        dgram_tx,
        events,
        max_dgram: TCP_MAX_DGRAM,
    }
}

fn record_aad(counter: u64) -> [u8; tunnel::HEADER_LEN] {
    let mut header = [0u8; tunnel::HEADER_LEN];
    tunnel::encode_header(TCP_RECORD_FLAG, counter, &mut header);
    header
}

/// 读一条记录并解密；返回明文（首字节为记录类型）
async fn read_record(
    rd: &mut OwnedReadHalf,
    opener: &TunnelOpener,
    counter: &mut u64,
) -> Result<Vec<u8>, CloseReason> {
    let mut len_buf = [0u8; 2];
    rd.read_exact(&mut len_buf)
        .await
        .map_err(|_| CloseReason::Io)?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len < TAG_LEN + 1 || len > TCP_MAX_RECORD + TAG_LEN {
        return Err(CloseReason::Protocol);
    }
    let mut sealed = vec![0u8; len];
    rd.read_exact(&mut sealed)
        .await
        .map_err(|_| CloseReason::Io)?;
    let plain = opener
        .open(*counter, &record_aad(*counter), &sealed)
        .ok_or(CloseReason::Protocol)?;
    *counter += 1;
    Ok(plain)
}

async fn tcp_reader(
    mut rd: OwnedReadHalf,
    opener: TunnelOpener,
    ev_tx: mpsc::UnboundedSender<LinkEvent>,
) {
    let mut counter = 0u64;
    let reason = loop {
        let plain = tokio::select! {
            // 上层已不在：不必再读
            _ = ev_tx.closed() => return,
            record = read_record(&mut rd, &opener, &mut counter) => match record {
                Ok(plain) => plain,
                Err(reason) => break reason,
            },
        };
        match plain.split_first() {
            Some((&REC_STREAM, body)) => {
                if ev_tx.send(LinkEvent::Bytes(body.to_vec())).is_err() {
                    return;
                }
            }
            Some((&REC_DGRAM, body)) => {
                let _ = ev_tx.send(LinkEvent::Dgram(body.to_vec()));
            }
            Some((&REC_CLOSE, body)) => {
                break CloseReason::Peer(body.first().copied().unwrap_or(close_code::NORMAL));
            }
            _ => break CloseReason::Protocol,
        }
    };
    let _ = ev_tx.send(LinkEvent::Closed(reason));
}

async fn write_record(
    wr: &mut OwnedWriteHalf,
    sealer: &TunnelSealer,
    counter: &mut u64,
    kind: u8,
    body: &[u8],
) -> std::io::Result<()> {
    let mut plain = Vec::with_capacity(1 + body.len());
    plain.push(kind);
    plain.extend_from_slice(body);
    let sealed = sealer
        .seal(*counter, &record_aad(*counter), &plain)
        .ok_or_else(|| std::io::Error::other("seal failed"))?;
    *counter += 1;
    let mut wire = Vec::with_capacity(2 + sealed.len());
    wire.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    wire.extend_from_slice(&sealed);
    wr.write_all(&wire).await
}

async fn tcp_writer(
    mut wr: OwnedWriteHalf,
    sealer: TunnelSealer,
    mut stream_rx: mpsc::Receiver<LinkCmd>,
    mut dgram_rx: mpsc::Receiver<Vec<u8>>,
    ev_tx: mpsc::UnboundedSender<LinkEvent>,
) {
    let mut counter = 0u64;
    let mut dgram_open = true;
    loop {
        let (kind, payload) = tokio::select! {
            biased;
            cmd = stream_rx.recv() => match cmd {
                Some(LinkCmd::Bytes(bytes)) => (REC_STREAM, bytes),
                closing => {
                    let code = match closing {
                        Some(LinkCmd::Close(code)) => code,
                        _ => close_code::NORMAL,
                    };
                    let _ = write_record(&mut wr, &sealer, &mut counter, REC_CLOSE, &[code]).await;
                    let _ = wr.shutdown().await;
                    let _ = ev_tx.send(LinkEvent::Closed(CloseReason::Local));
                    return;
                }
            },
            dgram = dgram_rx.recv(), if dgram_open => match dgram {
                Some(dgram) if dgram.len() <= TCP_MAX_DGRAM => (REC_DGRAM, dgram),
                Some(_) => continue, // 超长数据报：丢弃
                None => {
                    dgram_open = false;
                    continue;
                }
            },
        };
        // 字节流可任意切分；数据报已保证不超过单记录上限
        for chunk in payload.chunks(TCP_MAX_RECORD - 1) {
            if write_record(&mut wr, &sealer, &mut counter, kind, chunk)
                .await
                .is_err()
            {
                let _ = ev_tx.send(LinkEvent::Closed(CloseReason::Io));
                return;
            }
        }
    }
}
