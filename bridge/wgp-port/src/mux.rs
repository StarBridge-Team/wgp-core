//! 复用层：一条隧道（可靠字节流 + 数据报旁路）上承载多条双向流，带逐流流量控制。
//!
//! 并发模型：每条隧道一个复用任务，独占流表；`TunnelHandle` / `TunnelStream` 经通道与之通信。
//!  - 控制通道（无界、优先处理）：开流 / 重置 / 额度发放 / 关闭。
//!  - 数据通道（有界）：流数据与 FIN——FIN 与数据同道，保证排在该流已写数据之后。
//!  - 入站投递永不阻塞：对端能发多少由本端发放的额度决定（逐流窗口），所以链路层可以
//!    无条件把收到的字节交上来，不存在「某个应用读得慢 → 整条隧道卡死」。
//!
//! 流的生命周期与 TCP 一致：两个方向各自 FIN（半关闭），双向 FIN 后流结束；RST 立即双向中止。

use crate::frame::{
    decode_dgram, encode_dgram, MuxDecoder, MuxFrame, DGRAM_HEADER, DGRAM_REPLY, DGRAM_REQUEST,
    MAX_DATA_FRAME, MUX_VERSION,
};
use crate::link::{self, LinkCmd, LinkEvent, LinkIo};
use crate::{close_code, CloseReason};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Semaphore};
use wgp_core::{LinkTransport, PeerId, PunchedLink};
use wgp_crypto::tunnel::derive_tunnel;
use zeroize::Zeroize;

/// 逐流接收窗口：对端在获得新额度前最多可发的字节数（也是单流在本端的缓冲上限）
pub const STREAM_WINDOW: u32 = 256 * 1024;
/// 应用读走这么多字节后向对端补发额度
const WINDOW_UPDATE_THRESHOLD: u32 = STREAM_WINDOW / 2;
/// 单流发送额度上限（防对端用巨额 WINDOW 帧撑爆信号量计数）
const MAX_SEND_CREDIT: usize = 1 << 30;
const INCOMING_QUEUE: usize = 64;
const DATA_QUEUE: usize = 32;
const DGRAM_IN_QUEUE: usize = 1024;
/// 单条隧道上对端可同时打开的流数上限
const MAX_STREAMS: usize = 1024;

/// RST 帧携带的原因码
pub mod rst_code {
    /// 请求的端口未被对端暴露
    pub const REFUSED: u8 = 1;
    /// 对端流数已满
    pub const BUSY: u8 = 2;
    /// 一端异常中止（本地连接出错 / 流被丢弃）
    pub const ABORT: u8 = 3;
    /// 越过流量额度，或 FIN 之后仍发数据
    pub const FLOW: u8 = 4;
}

/// 隧道所用的载体
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// UDP 打洞链路（主档 / LAN）：AEAD 数据报 + 可靠层
    Udp,
    /// TCP 同时打开链路（降级档）：AEAD 记录流
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelError {
    /// 会话密钥已被取走（14 §10 条款 3：一次性转移）
    KeyUnavailable,
    /// 对端 PeerId 与本端相同：收发方向无法区分
    SelfPairing,
    /// 该载体不承载数据面（ICMP 逃生通道仅信令级）
    UnsupportedTransport,
}

/// 本端暴露给对端的服务端口（写进 HELLO；对端只能向这些 TCP 端口开流）
#[derive(Debug, Clone, Default)]
pub struct TunnelConfig {
    pub expose_tcp: Vec<u16>,
    pub expose_udp: Vec<u16>,
}

/// 对端在 HELLO 里声明的版本与暴露端口
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    pub version: u8,
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

/// 对端发起的一条流（目标是本端暴露的 `port`）
pub struct IncomingStream {
    pub port: u16,
    pub stream: TunnelStream,
}

/// 收到的数据报
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundDgram {
    /// false = 对端发往本端暴露的服务；true = 对端服务给本端转发口的回包
    pub reply: bool,
    pub port: u16,
    pub flow: u32,
    pub data: Vec<u8>,
}

enum StreamIn {
    Data(Vec<u8>),
    Fin,
    Reset,
}

struct StreamEntry {
    in_tx: mpsc::UnboundedSender<StreamIn>,
    /// 本端向该流写数据的额度（对端经 WINDOW 帧补发）
    credit: Arc<Semaphore>,
    /// 对端还可以发来的字节数（本端发放的额度余量）
    recv_allow: u32,
    local_fin: bool,
    remote_fin: bool,
}

enum Ctrl {
    Open {
        id: u32,
        port: u16,
        entry: StreamEntry,
    },
    Rst {
        id: u32,
        code: u8,
    },
    Credit {
        id: u32,
        n: u32,
    },
    Close {
        code: u8,
    },
}

enum DataCmd {
    Data { id: u32, bytes: Vec<u8> },
    Fin { id: u32 },
}

fn make_stream(
    id: u32,
    ctrl_tx: &mpsc::UnboundedSender<Ctrl>,
    data_tx: &mpsc::Sender<DataCmd>,
) -> (TunnelStream, StreamEntry) {
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let credit = Arc::new(Semaphore::new(STREAM_WINDOW as usize));
    let stream = TunnelStream {
        reader: StreamReader {
            id,
            rx: in_rx,
            ctrl_tx: ctrl_tx.clone(),
            pending_credit: 0,
            done: false,
        },
        writer: StreamWriter {
            id,
            data_tx: data_tx.clone(),
            ctrl_tx: ctrl_tx.clone(),
            credit: credit.clone(),
            finished: false,
        },
    };
    let entry = StreamEntry {
        in_tx,
        credit,
        recv_allow: STREAM_WINDOW,
        local_fin: false,
        remote_fin: false,
    };
    (stream, entry)
}

fn reset_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "tunnel stream reset")
}

// ---------------------------------------------------------------------------
// 流
// ---------------------------------------------------------------------------

/// 隧道上的一条双向流
pub struct TunnelStream {
    reader: StreamReader,
    writer: StreamWriter,
}

impl TunnelStream {
    pub fn id(&self) -> u32 {
        self.reader.id
    }

    /// 拆成读、写两半，可分属两个任务
    pub fn split(self) -> (StreamReader, StreamWriter) {
        (self.reader, self.writer)
    }

    pub async fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.reader.read().await
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write(data).await
    }

    pub async fn finish(&mut self) {
        self.writer.finish().await
    }
}

/// 流的读半部。未读到结束就被丢弃 = 中止整条流（向对端发 RST）。
pub struct StreamReader {
    id: u32,
    rx: mpsc::UnboundedReceiver<StreamIn>,
    ctrl_tx: mpsc::UnboundedSender<Ctrl>,
    /// 已读走但尚未折算成额度发还给对端的字节数
    pending_credit: u32,
    done: bool,
}

impl StreamReader {
    /// 读下一段数据。`Ok(None)` = 对端已正常结束发送（FIN）；
    /// `Err` = 流被重置或隧道已关闭。
    pub async fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        match self.rx.recv().await {
            Some(StreamIn::Data(bytes)) => {
                self.pending_credit = self.pending_credit.saturating_add(bytes.len() as u32);
                if self.pending_credit >= WINDOW_UPDATE_THRESHOLD {
                    let n = std::mem::take(&mut self.pending_credit);
                    let _ = self.ctrl_tx.send(Ctrl::Credit { id: self.id, n });
                }
                Ok(Some(bytes))
            }
            Some(StreamIn::Fin) => {
                self.done = true;
                Ok(None)
            }
            Some(StreamIn::Reset) | None => {
                self.done = true;
                Err(reset_error())
            }
        }
    }
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.ctrl_tx.send(Ctrl::Rst {
                id: self.id,
                code: rst_code::ABORT,
            });
        }
    }
}

/// 流的写半部。未 `finish` 就被丢弃 = 中止整条流（向对端发 RST）。
pub struct StreamWriter {
    id: u32,
    data_tx: mpsc::Sender<DataCmd>,
    ctrl_tx: mpsc::UnboundedSender<Ctrl>,
    credit: Arc<Semaphore>,
    finished: bool,
}

impl StreamWriter {
    /// 写入数据；受对端发放的额度与隧道拥塞双重反压，必要时挂起等待
    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel stream already finished",
            ));
        }
        for chunk in data.chunks(MAX_DATA_FRAME) {
            let permit = self
                .credit
                .acquire_many(chunk.len() as u32)
                .await
                .map_err(|_| reset_error())?;
            permit.forget();
            self.data_tx
                .send(DataCmd::Data {
                    id: self.id,
                    bytes: chunk.to_vec(),
                })
                .await
                .map_err(|_| reset_error())?;
        }
        Ok(())
    }

    /// 正常结束发送方向（FIN）；读方向不受影响
    pub async fn finish(&mut self) {
        if !self.finished {
            self.finished = true;
            let _ = self.data_tx.send(DataCmd::Fin { id: self.id }).await;
        }
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.ctrl_tx.send(Ctrl::Rst {
                id: self.id,
                code: rst_code::ABORT,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// 隧道句柄
// ---------------------------------------------------------------------------

struct HandleInner {
    ctrl_tx: mpsc::UnboundedSender<Ctrl>,
    data_tx: mpsc::Sender<DataCmd>,
    dgram_tx: mpsc::Sender<Vec<u8>>,
    next_id: AtomicU32,
    closed: watch::Receiver<Option<CloseReason>>,
    hello: watch::Receiver<Option<PeerHello>>,
    max_dgram: usize,
}

/// 隧道的可克隆句柄：开流、发数据报、关闭、查询状态
#[derive(Clone)]
pub struct TunnelHandle {
    inner: Arc<HandleInner>,
}

impl TunnelHandle {
    /// 向对端暴露的 `port` 打开一条流。不等对端确认：对端拒绝时流会收到重置。
    pub fn open_stream(&self, port: u16) -> io::Result<TunnelStream> {
        if self.close_reason().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tunnel closed",
            ));
        }
        let id = self.inner.next_id.fetch_add(2, Ordering::Relaxed);
        let (stream, entry) = make_stream(id, &self.inner.ctrl_tx, &self.inner.data_tx);
        // 发送失败时 entry 连同其中的接收端一起被丢弃，stream 随后的读写自然报错
        self.inner
            .ctrl_tx
            .send(Ctrl::Open { id, port, entry })
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "tunnel closed"))?;
        Ok(stream)
    }

    /// 发一个数据报（不保证送达）。超长、队列已满或隧道已关闭时返回 false。
    pub fn send_dgram(&self, reply: bool, port: u16, flow: u32, data: &[u8]) -> bool {
        let kind = if reply { DGRAM_REPLY } else { DGRAM_REQUEST };
        let wire = encode_dgram(kind, port, flow, data);
        wire.len() <= self.inner.max_dgram && self.inner.dgram_tx.try_send(wire).is_ok()
    }

    /// 单个数据报可承载的应用数据上限
    pub fn max_dgram_payload(&self) -> usize {
        self.inner.max_dgram.saturating_sub(DGRAM_HEADER)
    }

    /// 关闭隧道，并把原因码（见 [`crate::close_code`]）告知对端
    pub fn close(&self, code: u8) {
        let _ = self.inner.ctrl_tx.send(Ctrl::Close { code });
    }

    /// 已关闭则返回原因
    pub fn close_reason(&self) -> Option<CloseReason> {
        *self.inner.closed.borrow()
    }

    /// 等到隧道关闭
    pub async fn closed(&self) -> CloseReason {
        let mut rx = self.inner.closed.clone();
        loop {
            if let Some(reason) = *rx.borrow_and_update() {
                return reason;
            }
            if rx.changed().await.is_err() {
                let last = *rx.borrow();
                return last.unwrap_or(CloseReason::Io);
            }
        }
    }

    /// 对端 HELLO（若已收到）
    pub fn peer_hello_now(&self) -> Option<PeerHello> {
        self.inner.hello.borrow().clone()
    }

    /// 等对端 HELLO；隧道先关闭则返回 None
    pub async fn peer_hello(&self) -> Option<PeerHello> {
        let mut rx = self.inner.hello.clone();
        loop {
            let current = rx.borrow_and_update().clone();
            if current.is_some() {
                return current;
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// 一条已启动的隧道：句柄 + 入站流队列 + 入站数据报队列
pub struct Tunnel {
    pub handle: TunnelHandle,
    /// 对端发起、目标端口已在本端暴露的流
    pub incoming: mpsc::Receiver<IncomingStream>,
    pub dgrams: mpsc::Receiver<InboundDgram>,
    pub carrier: Carrier,
}

impl Tunnel {
    /// 接管内核交付物，启动隧道（必须在 tokio 运行时内调用）。
    ///
    /// `local`：本端 PeerId。收发密钥方向与流号奇偶都由双方 PeerId 的字节序决定，
    /// 两端无需协商。会话密钥在此一次性取出、派生后立即清零。
    pub fn from_link(
        local: PeerId,
        link: PunchedLink,
        cfg: TunnelConfig,
    ) -> Result<Tunnel, TunnelError> {
        let PunchedLink {
            peer_id,
            transport,
            peer_addr,
            mut session_key,
            ..
        } = link;
        let mut key = session_key.take().ok_or(TunnelError::KeyUnavailable)?;
        let pair = derive_tunnel(&key, &local, &peer_id);
        key.zeroize();
        let (sealer, opener) = pair.ok_or(TunnelError::SelfPairing)?;
        let (io, carrier) = match transport {
            LinkTransport::Udp { socket } | LinkTransport::Lan { socket } => (
                link::spawn_udp(socket, peer_addr, sealer, opener),
                Carrier::Udp,
            ),
            LinkTransport::Tcp { stream } => {
                (link::spawn_tcp(stream, sealer, opener), Carrier::Tcp)
            }
            LinkTransport::Icmp { .. } => return Err(TunnelError::UnsupportedTransport),
        };
        Ok(Tunnel::start(io, local < peer_id, cfg, carrier))
    }

    pub(crate) fn start(
        io: LinkIo,
        local_is_lo: bool,
        cfg: TunnelConfig,
        carrier: Carrier,
    ) -> Tunnel {
        let LinkIo {
            stream_tx,
            dgram_tx,
            events,
            max_dgram,
        } = io;
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE);
        let (incoming_tx, incoming) = mpsc::channel(INCOMING_QUEUE);
        let (dgram_in_tx, dgrams) = mpsc::channel(DGRAM_IN_QUEUE);
        let (closed_tx, closed_rx) = watch::channel(None);
        let (hello_tx, hello_rx) = watch::channel(None);
        // 流号奇偶：PeerId 较小的一方用奇数，另一方用偶数——双方可同时开流而不撞号
        let local_parity: u32 = if local_is_lo { 1 } else { 0 };
        let mux = Mux {
            link_tx: stream_tx,
            streams: HashMap::new(),
            expose_tcp: cfg.expose_tcp.clone(),
            incoming_tx,
            dgram_in_tx,
            hello_tx,
            out: Vec::new(),
            ctrl_tx: ctrl_tx.clone(),
            data_tx: data_tx.clone(),
            remote_parity: 1 - local_parity,
        };
        let hello = MuxFrame::Hello {
            version: MUX_VERSION,
            tcp: cfg.expose_tcp,
            udp: cfg.expose_udp,
        };
        tokio::spawn(mux.run(hello, events, ctrl_rx, data_rx, closed_tx));
        Tunnel {
            handle: TunnelHandle {
                inner: Arc::new(HandleInner {
                    ctrl_tx,
                    data_tx,
                    dgram_tx,
                    next_id: AtomicU32::new(local_parity),
                    closed: closed_rx,
                    hello: hello_rx,
                    max_dgram,
                }),
            },
            incoming,
            dgrams,
            carrier,
        }
    }
}

// ---------------------------------------------------------------------------
// 复用任务
// ---------------------------------------------------------------------------

struct Mux {
    link_tx: mpsc::Sender<LinkCmd>,
    streams: HashMap<u32, StreamEntry>,
    expose_tcp: Vec<u16>,
    incoming_tx: mpsc::Sender<IncomingStream>,
    dgram_in_tx: mpsc::Sender<InboundDgram>,
    hello_tx: watch::Sender<Option<PeerHello>>,
    /// 已编码、待交给链路的帧字节
    out: Vec<u8>,
    /// 为对端发起的流构造句柄时使用
    ctrl_tx: mpsc::UnboundedSender<Ctrl>,
    data_tx: mpsc::Sender<DataCmd>,
    /// 对端发起的流号必须具有的奇偶
    remote_parity: u32,
}

/// 链路任务已退出时，从残留事件里找出它给的关闭原因
fn pending_close(events: &mut mpsc::UnboundedReceiver<LinkEvent>) -> CloseReason {
    while let Ok(event) = events.try_recv() {
        if let LinkEvent::Closed(reason) = event {
            return reason;
        }
    }
    CloseReason::Io
}

impl Mux {
    fn push(&mut self, frame: MuxFrame) {
        frame.encode(&mut self.out);
    }

    /// 本地拆除一条流：唤醒读、写两半（读到重置；写等额度者报错）
    fn drop_stream(&mut self, id: u32) {
        if let Some(entry) = self.streams.remove(&id) {
            entry.credit.close();
            let _ = entry.in_tx.send(StreamIn::Reset);
        }
    }

    /// 处理对端发来的一帧；`Err` = 对端违反协议，整条隧道关闭
    fn on_frame(&mut self, frame: MuxFrame) -> Result<(), CloseReason> {
        match frame {
            MuxFrame::Hello { version, tcp, udp } => {
                self.hello_tx
                    .send_replace(Some(PeerHello { version, tcp, udp }));
            }
            MuxFrame::Open { id, port } => {
                if id % 2 != self.remote_parity || self.streams.contains_key(&id) {
                    return Err(CloseReason::Protocol);
                }
                if !self.expose_tcp.contains(&port) {
                    self.push(MuxFrame::Rst {
                        id,
                        code: rst_code::REFUSED,
                    });
                } else if self.streams.len() >= MAX_STREAMS {
                    self.push(MuxFrame::Rst {
                        id,
                        code: rst_code::BUSY,
                    });
                } else {
                    let (stream, entry) = make_stream(id, &self.ctrl_tx, &self.data_tx);
                    // 先登记再投递：投递失败（队列满）时 stream 被丢弃，其 Drop 会发来 Rst
                    // 控制消息，由 on_ctrl 统一拆除并通知对端
                    self.streams.insert(id, entry);
                    let _ = self.incoming_tx.try_send(IncomingStream { port, stream });
                }
            }
            MuxFrame::Data { id, data } => {
                let Some(entry) = self.streams.get_mut(&id) else {
                    return Ok(()); // 已关闭流的迟到数据
                };
                let len = data.len() as u32;
                if entry.remote_fin || len > entry.recv_allow {
                    // FIN 之后还发数据 / 越过本端发放的额度：只重置这条流，不牵连整条隧道
                    self.drop_stream(id);
                    self.push(MuxFrame::Rst {
                        id,
                        code: rst_code::FLOW,
                    });
                } else {
                    entry.recv_allow -= len;
                    let _ = entry.in_tx.send(StreamIn::Data(data));
                }
            }
            MuxFrame::Fin { id } => {
                if let Some(entry) = self.streams.get_mut(&id) {
                    if !entry.remote_fin {
                        entry.remote_fin = true;
                        let _ = entry.in_tx.send(StreamIn::Fin);
                        if entry.local_fin {
                            self.streams.remove(&id);
                        }
                    }
                }
            }
            MuxFrame::Rst { id, .. } => self.drop_stream(id),
            MuxFrame::Window { id, credit } => {
                if let Some(entry) = self.streams.get(&id) {
                    let room = MAX_SEND_CREDIT.saturating_sub(entry.credit.available_permits());
                    entry.credit.add_permits((credit as usize).min(room));
                }
            }
        }
        Ok(())
    }

    /// 处理本地控制消息；返回 `Some(code)` = 请求关闭隧道
    fn on_ctrl(&mut self, ctrl: Ctrl) -> Option<u8> {
        match ctrl {
            Ctrl::Open { id, port, entry } => {
                self.streams.insert(id, entry);
                self.push(MuxFrame::Open { id, port });
            }
            Ctrl::Rst { id, code } => {
                if self.streams.contains_key(&id) {
                    self.drop_stream(id);
                    self.push(MuxFrame::Rst { id, code });
                }
            }
            Ctrl::Credit { id, n } => {
                if let Some(entry) = self.streams.get_mut(&id) {
                    entry.recv_allow = entry.recv_allow.saturating_add(n);
                    self.push(MuxFrame::Window { id, credit: n });
                }
            }
            Ctrl::Close { code } => return Some(code),
        }
        None
    }

    fn on_data(&mut self, cmd: DataCmd) {
        match cmd {
            DataCmd::Data { id, bytes } => {
                if self.streams.get(&id).is_some_and(|e| !e.local_fin) {
                    self.push(MuxFrame::Data { id, data: bytes });
                }
            }
            DataCmd::Fin { id } => {
                let Some(entry) = self.streams.get_mut(&id) else {
                    return;
                };
                if entry.local_fin {
                    return;
                }
                entry.local_fin = true;
                let both_done = entry.remote_fin;
                self.push(MuxFrame::Fin { id });
                if both_done {
                    self.streams.remove(&id);
                }
            }
        }
    }

    fn on_dgram(&mut self, bytes: Vec<u8>) {
        if let Some((kind, port, flow, data)) = decode_dgram(&bytes) {
            // 队列满即丢：数据报本就不保证送达
            let _ = self.dgram_in_tx.try_send(InboundDgram {
                reply: kind == DGRAM_REPLY,
                port,
                flow,
                data: data.to_vec(),
            });
        }
    }

    async fn run(
        mut self,
        hello: MuxFrame,
        mut events: mpsc::UnboundedReceiver<LinkEvent>,
        mut ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,
        mut data_rx: mpsc::Receiver<DataCmd>,
        closed_tx: watch::Sender<Option<CloseReason>>,
    ) {
        let mut decoder = MuxDecoder::new();
        self.push(hello);
        // (关闭原因, 需要告知对端的原因码)
        let (reason, notify) = loop {
            if !self.out.is_empty() {
                let bytes = std::mem::take(&mut self.out);
                if self.link_tx.send(LinkCmd::Bytes(bytes)).await.is_err() {
                    break (pending_close(&mut events), None);
                }
            }
            tokio::select! {
                biased;
                event = events.recv() => match event {
                    Some(LinkEvent::Bytes(bytes)) => {
                        decoder.push(&bytes);
                        let mut violation = false;
                        loop {
                            match decoder.next() {
                                Ok(Some(frame)) => {
                                    if self.on_frame(frame).is_err() {
                                        violation = true;
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    violation = true;
                                    break;
                                }
                            }
                        }
                        if violation {
                            break (CloseReason::Protocol, Some(close_code::PROTOCOL));
                        }
                    }
                    Some(LinkEvent::Dgram(bytes)) => self.on_dgram(bytes),
                    Some(LinkEvent::Closed(reason)) => break (reason, None),
                    None => break (CloseReason::Io, None),
                },
                Some(ctrl) = ctrl_rx.recv() => {
                    if let Some(code) = self.on_ctrl(ctrl) {
                        break (CloseReason::Local, Some(code));
                    }
                }
                Some(cmd) = data_rx.recv() => self.on_data(cmd),
            }
        };
        if let Some(code) = notify {
            let _ = self.link_tx.send(LinkCmd::Close(code)).await;
        }
        for (_, entry) in self.streams.drain() {
            entry.credit.close();
            let _ = entry.in_tx.send(StreamIn::Reset);
        }
        let _ = closed_tx.send(Some(reason));
    }
}
