//! 集成测试公共辅助：用 loopback socket 构造「打洞成功后两端各自拿到的交付物」。
#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use wgp_core::{LinkQuality, LinkRank, LinkTransport, PeerId, PunchedLink, SecretBox};

pub const ALICE: PeerId = [0xA1; 16];
pub const BOB: PeerId = [0xB2; 16];
pub const KEY: [u8; 32] = [0x5C; 32];

pub fn quality() -> LinkQuality {
    LinkQuality {
        rtt: Duration::ZERO,
        loss: 0.0,
        measured_mtu: 1400,
        obeys_budget: true,
    }
}

pub fn udp_link(
    peer_id: PeerId,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    key: [u8; 32],
) -> PunchedLink {
    PunchedLink {
        peer_id,
        transport: LinkTransport::Udp { socket },
        peer_addr,
        session_key: SecretBox::new(key),
        quality: quality(),
        rank: LinkRank::Primary,
    }
}

pub fn tcp_link(peer_id: PeerId, stream: TcpStream, key: [u8; 32]) -> PunchedLink {
    let peer_addr = stream.peer_addr().unwrap();
    PunchedLink {
        peer_id,
        transport: LinkTransport::Tcp { stream },
        peer_addr,
        session_key: SecretBox::new(key),
        quality: quality(),
        rank: LinkRank::Degraded,
    }
}

pub async fn udp_socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
}

/// 一对互指的 UDP 链路：(Alice 拿到的, Bob 拿到的, Alice 的 socket, Bob 的 socket)
pub async fn udp_link_pair() -> (PunchedLink, PunchedLink, Arc<UdpSocket>, Arc<UdpSocket>) {
    let sa = udp_socket().await;
    let sb = udp_socket().await;
    let a_addr = sa.local_addr().unwrap();
    let b_addr = sb.local_addr().unwrap();
    (
        udp_link(BOB, sa.clone(), b_addr, KEY),
        udp_link(ALICE, sb.clone(), a_addr, KEY),
        sa,
        sb,
    )
}

/// 一对已连通的 TCP 链路：(Alice 拿到的, Bob 拿到的)
pub async fn tcp_link_pair() -> (PunchedLink, PunchedLink) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (a, b) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let a = a.unwrap();
    let (b, _) = b.unwrap();
    (tcp_link(BOB, a, KEY), tcp_link(ALICE, b, KEY))
}

pub struct XorShift(pub u64);

impl XorShift {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// 确定性伪随机字节串（内容与位置相关，错位/丢段/重复都能被比对发现）
pub fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift(seed | 1);
    (0..len).map(|_| rng.next() as u8).collect()
}

/// 给测试体加总时限：数据面的 bug 往往表现为「永远等下去」，超时即失败
pub async fn within<T>(secs: u64, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(secs), fut)
        .await
        .expect("测试超时")
}

/// 双向 UDP 代理：按千分比丢包 + 随机延迟（制造乱序）。
/// 返回 (Alice 应发往的地址, Bob 应发往的地址)。
pub async fn lossy_proxy(
    alice: SocketAddr,
    bob: SocketAddr,
    loss_permille: u64,
    max_delay_ms: u64,
) -> (SocketAddr, SocketAddr) {
    let pa = udp_socket().await; // Alice → pa；发往 Alice 的包也从 pa 出
    let pb = udp_socket().await; // Bob → pb；发往 Bob 的包也从 pb 出
    let pa_addr = pa.local_addr().unwrap();
    let pb_addr = pb.local_addr().unwrap();

    async fn pump(
        inbound: Arc<UdpSocket>,
        outbound: Arc<UdpSocket>,
        dest: SocketAddr,
        loss_permille: u64,
        max_delay_ms: u64,
        seed: u64,
    ) {
        let mut rng = XorShift(seed);
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, _)) = inbound.recv_from(&mut buf).await else {
                continue;
            };
            if rng.next() % 1000 < loss_permille {
                continue;
            }
            let delay = if max_delay_ms == 0 {
                0
            } else {
                rng.next() % (max_delay_ms + 1)
            };
            let pkt = buf[..n].to_vec();
            let outbound = outbound.clone();
            tokio::spawn(async move {
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let _ = outbound.send_to(&pkt, dest).await;
            });
        }
    }

    tokio::spawn(pump(
        pa.clone(),
        pb.clone(),
        bob,
        loss_permille,
        max_delay_ms,
        0x1111_2222_3333_4445,
    ));
    tokio::spawn(pump(pb, pa, alice, loss_permille, max_delay_ms, 0x5555_6666_7777_8889));
    (pa_addr, pb_addr)
}
