//! ET 桥接 PoC（路线图 M3）：把 EasyTier 协议兼容层（mesh-tun-proto）跑在折跃门的加密隧道上。
//!
//! 为什么是「ET 帧跑在隧道流上」，而不是把打通的 UDP socket 直接交给 ET：
//! - mesh-tun-proto 的 `ExternalHolePunchBridge` 目前是占位接口——返回值里只有地址、没有 socket，
//!   `MeshUdpPlug::new` 会自己另开一个 socket，接不上我们打通的那条洞；
//! - 打通的 UDP socket 上混着内核的保活探针，直接交出去就得停保活、再自己做一遍分流；
//! - 走隧道流则这些都不用管：分流、加密、可靠传输、多路复用隧道已经做了，ET 帧只是其中一条流上的
//!   字节。代价是 ET 的 IP 包也走了可靠流（队头阻塞）；正式接 TUN 时应把数据帧改走隧道的数据报通道。
//!
//! 接缝只有一个：[`TunnelFrameTransport`] 实现 mesh-tun-proto 的 `MeshFrameTransport`，经
//! `P2pNode::add_custom_transport` 接入。该库是「同步 + 手动 tick」模型，[`EtNode`] 用一个独立线程
//! 承载它，对外只有命令与事件两条通道。
//!
//! 这是 PoC，不是产品代码：只覆盖「握手 + 互发用户数据」，没有接 TUN / 虚拟 IP / 路由。

use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use mesh_tun_proto::{
    MeshFrameTransport, P2pEvent, P2pNode, PeerManagerHeader, PEER_MANAGER_HEADER_SIZE,
};
use std::sync::mpsc as std_mpsc;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc as tokio_mpsc;
use wgp_port::TunnelStream;

/// ET 流在隧道里占用的逻辑端口（取 ET 的默认监听端口号，便于辨认）。
/// 接受连接的一侧要在 `TunnelConfig::expose_tcp` 里列出它。
pub const ET_TUNNEL_PORT: u16 = 11010;

/// 单帧上限（与 mesh-tun-proto 的流式帧一致：16MiB）
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// ET 节点线程的 tick 间隔（该库要求不超过 50ms）
const TICK_INTERVAL: Duration = Duration::from_millis(10);
/// 每次 tick 每条连接最多处理的帧数
const TICK_FRAMES: usize = 64;

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
    Ok(Some((hdr, payload, 4 + total)))
}

/// 跑在一条 wgp 隧道流上的 ET 帧传输。
///
/// 隧道流是异步的，ET 库是同步轮询的：中间用两条通道隔开——读任务把流里的字节切成帧送进
/// 同步队列（`recv_frame` 非阻塞地取），`send_frame` 把编码好的帧交给写任务。
pub struct TunnelFrameTransport {
    outbound: tokio_mpsc::UnboundedSender<Vec<u8>>,
    inbound: std_mpsc::Receiver<(PeerManagerHeader, Vec<u8>)>,
    label: String,
}

impl TunnelFrameTransport {
    /// 接管一条隧道流。必须在 tokio 运行时内调用（会起读、写两个任务）。
    /// 流断开或收到非法帧时，下一次 `recv_frame` 返回错误，ET 节点据此判定对端下线。
    pub fn spawn(stream: TunnelStream, label: impl Into<String>) -> Self {
        let (mut reader, mut writer) = stream.split();
        let (outbound, mut outbound_rx) = tokio_mpsc::unbounded_channel::<Vec<u8>>();
        let (inbound_tx, inbound) = std_mpsc::channel();

        tokio::spawn(async move {
            while let Some(frame) = outbound_rx.recv().await {
                if writer.write(&frame).await.is_err() {
                    return;
                }
            }
            writer.finish().await;
        });

        tokio::spawn(async move {
            let mut buf: Vec<u8> = Vec::new();
            while let Ok(Some(chunk)) = reader.read().await {
                buf.extend_from_slice(&chunk);
                loop {
                    match take_frame(&buf) {
                        Ok(Some((hdr, payload, used))) => {
                            buf.drain(..used);
                            if inbound_tx.send((hdr, payload)).is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(BadFrame) => return,
                    }
                }
            }
        });

        Self {
            outbound,
            inbound,
            label: label.into(),
        }
    }
}

impl MeshFrameTransport for TunnelFrameTransport {
    fn send_frame(&mut self, hdr: &PeerManagerHeader, payload: &[u8]) -> anyhow::Result<()> {
        self.outbound
            .send(encode_frame(hdr, payload))
            .map_err(|_| anyhow!("wgp tunnel stream closed"))
    }

    fn recv_frame(&mut self) -> anyhow::Result<Option<(PeerManagerHeader, Vec<u8>)>> {
        match self.inbound.try_recv() {
            Ok(frame) => Ok(Some(frame)),
            Err(std_mpsc::TryRecvError::Empty) => Ok(None),
            Err(std_mpsc::TryRecvError::Disconnected) => Err(anyhow!("wgp tunnel stream closed")),
        }
    }

    fn remote_peer_id(&self) -> u32 {
        0
    }

    fn label(&self) -> String {
        self.label.clone()
    }
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
    /// ET 库自身的事件：收到用户数据、对端断开、路由变化等
    Node(P2pEvent),
}

enum Command {
    Attach(TunnelFrameTransport),
    Send { to: u32, data: Vec<u8> },
    Stop,
}

/// 跑在独立线程里的 ET 节点。
///
/// PoC 的已知简化：握手在节点线程里同步进行（该库最长等 30s），期间其他连接不会被 tick。
/// 产品化时应把握手挪出主循环。
pub struct EtNode {
    peer_id: u32,
    commands: std_mpsc::Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl EtNode {
    /// 启动一个 ET 节点（网络名 + 密钥决定它属于哪个 ET 网络），返回句柄与事件接收端。
    pub fn start(
        network: &str,
        secret: &str,
    ) -> std::io::Result<(Self, tokio_mpsc::UnboundedReceiver<EtEvent>)> {
        let (commands, command_rx) = std_mpsc::channel::<Command>();
        let (events, event_rx) = tokio_mpsc::unbounded_channel::<EtEvent>();
        let (id_tx, id_rx) = std_mpsc::channel::<u32>();
        let (network, secret) = (network.to_string(), secret.to_string());

        let thread = std::thread::Builder::new()
            .name("wgp-et-node".to_string())
            .spawn(move || {
                // 节点在本线程内创建，不跨线程移动
                let mut node = P2pNode::new(network, secret, None);
                if id_tx.send(node.identity.my_peer_id).is_err() {
                    return;
                }
                loop {
                    loop {
                        let event = match command_rx.try_recv() {
                            Ok(Command::Attach(transport)) => {
                                match node.add_custom_transport(Box::new(transport)) {
                                    Ok(peer_id) => EtEvent::Connected { peer_id },
                                    Err(e) => EtEvent::ConnectFailed {
                                        reason: e.to_string(),
                                    },
                                }
                            }
                            Ok(Command::Send { to, data }) => match node.send_data_to(to, &data) {
                                Ok(()) => continue,
                                Err(e) => EtEvent::SendFailed {
                                    to,
                                    reason: e.to_string(),
                                },
                            },
                            Ok(Command::Stop) | Err(std_mpsc::TryRecvError::Disconnected) => return,
                            Err(std_mpsc::TryRecvError::Empty) => break,
                        };
                        if events.send(event).is_err() {
                            return;
                        }
                    }
                    for event in node.tick(TICK_FRAMES) {
                        if events.send(EtEvent::Node(event)).is_err() {
                            return;
                        }
                    }
                    std::thread::sleep(TICK_INTERVAL);
                }
            })?;

        let peer_id = id_rx.recv().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "ET node thread exited at startup")
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

    /// 接入一条传输并做 ET 握手；结果经事件通道给出（Connected / ConnectFailed）
    pub fn attach(&self, transport: TunnelFrameTransport) {
        let _ = self.commands.send(Command::Attach(transport));
    }

    /// 向指定 ET 节点发一段用户数据（对端收到 `P2pEvent::InboundUserData`）
    pub fn send_data(&self, to: u32, data: Vec<u8>) {
        let _ = self.commands.send(Command::Send { to, data });
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
        let _ = self.commands.send(Command::Stop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_tun_proto::PacketType;

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
}
