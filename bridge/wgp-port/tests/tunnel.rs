//! 隧道层集成测试：真实 loopback socket 上跑完整的 链路驱动 + 可靠层 + 复用层。

mod common;

use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use wgp_core::SecretBox;
use wgp_port::{
    close_code, Carrier, CloseReason, InboundDgram, Tunnel, TunnelConfig, TunnelError,
    TunnelHandle, STREAM_WINDOW,
};

const PORT: u16 = 7000;

fn exposing(ports: &[u16]) -> TunnelConfig {
    TunnelConfig {
        expose_tcp: ports.to_vec(),
        expose_udp: Vec::new(),
    }
}

async fn udp_tunnels() -> (Tunnel, Tunnel, Arc<UdpSocket>, Arc<UdpSocket>) {
    let (la, lb, sa, sb) = udp_link_pair().await;
    let a = Tunnel::from_link(ALICE, la, TunnelConfig::default()).unwrap();
    let b = Tunnel::from_link(BOB, lb, exposing(&[PORT])).unwrap();
    (a, b, sa, sb)
}

async fn tcp_tunnels() -> (Tunnel, Tunnel) {
    let (la, lb) = tcp_link_pair().await;
    let a = Tunnel::from_link(ALICE, la, TunnelConfig::default()).unwrap();
    let b = Tunnel::from_link(BOB, lb, exposing(&[PORT])).unwrap();
    (a, b)
}

/// 把每条入站流原样回显，读到 FIN 后结束发送
fn spawn_echo(mut tunnel: Tunnel) -> TunnelHandle {
    let handle = tunnel.handle.clone();
    tokio::spawn(async move {
        while let Some(incoming) = tunnel.incoming.recv().await {
            tokio::spawn(async move {
                let mut stream = incoming.stream;
                while let Ok(Some(chunk)) = stream.read().await {
                    if stream.write(&chunk).await.is_err() {
                        return;
                    }
                }
                stream.finish().await;
            });
        }
    });
    handle
}

/// 经一条新流发送 `data` 并收回回显（读写并发，避免回显死锁），返回收到的全部字节
async fn echo_roundtrip(handle: &TunnelHandle, data: Vec<u8>, chunk: usize) -> Vec<u8> {
    let (mut rd, mut wr) = handle.open_stream(PORT).unwrap().split();
    let writer = tokio::spawn(async move {
        for piece in data.chunks(chunk) {
            wr.write(piece).await.unwrap();
        }
        wr.finish().await;
    });
    let mut got = Vec::new();
    while let Some(piece) = rd.read().await.unwrap() {
        got.extend_from_slice(&piece);
    }
    writer.await.unwrap();
    // FIN 之后继续读恒为 None
    assert!(rd.read().await.unwrap().is_none());
    got
}

#[tokio::test]
async fn udp_stream_echo_with_half_close() {
    within(30, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        assert_eq!(a.carrier, Carrier::Udp);
        let _b = spawn_echo(b);
        let data = pattern(300_000, 1);
        assert_eq!(echo_roundtrip(&a.handle, data.clone(), 7_777).await, data);
    })
    .await;
}

#[tokio::test]
async fn tcp_stream_echo_with_half_close() {
    within(30, async {
        let (a, b) = tcp_tunnels().await;
        assert_eq!(a.carrier, Carrier::Tcp);
        let _b = spawn_echo(b);
        let data = pattern(300_000, 2);
        assert_eq!(echo_roundtrip(&a.handle, data.clone(), 7_777).await, data);
    })
    .await;
}

#[tokio::test]
async fn both_ends_learn_peer_hello() {
    within(10, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        let hello_from_b = a.handle.peer_hello().await.expect("A 应收到 B 的 HELLO");
        assert_eq!(hello_from_b.tcp, vec![PORT]);
        assert_eq!(hello_from_b.version, wgp_port::MUX_VERSION);
        let hello_from_a = b.handle.peer_hello().await.expect("B 应收到 A 的 HELLO");
        assert!(hello_from_a.tcp.is_empty());
    })
    .await;
}

/// 打洞成功后内核保活探针与隧道报文共用同一个 socket；再加上第三方的垃圾包与伪造隧道报文，
/// 业务数据必须不受影响（分流 + 认证 + 「验签通过才推进重放窗口」）。
#[tokio::test]
async fn udp_link_shrugs_off_probes_garbage_and_forgeries() {
    within(60, async {
        let (a, b, sa, sb) = udp_tunnels().await;
        let _b = spawn_echo(b);
        let a_addr = sa.local_addr().unwrap();
        let b_addr = sb.local_addr().unwrap();

        let noise = tokio::spawn(async move {
            let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            // 内核探针：magic "WG" + 类型 0x10，定长 31B（本层不验签，只需正确分流）
            let mut probe = [0u8; 31];
            probe[..3].copy_from_slice(&[0x57, 0x47, 0x10]);
            // 伪造隧道报文：头部合法（counter 逐个覆盖真实报文会用到的号段），密文乱填
            let mut forged = vec![0x99u8; 200];
            forged[..4].copy_from_slice(&[0x57, 0x47, 0x40, 0x00]);
            for counter in 0..600u64 {
                // 探针经对端自己的 socket 发出，与真实情形（对端内核保活）一致
                let _ = sb.send_to(&probe, a_addr).await;
                let _ = sa.send_to(&probe, b_addr).await;
                forged[4..12].copy_from_slice(&counter.to_be_bytes());
                let _ = stranger.send_to(&forged, a_addr).await;
                let _ = stranger.send_to(&forged, b_addr).await;
                let _ = stranger.send_to(&[0xEE; 64], a_addr).await;
                let _ = stranger.send_to(&[0x57, 0x47], b_addr).await;
                if counter % 8 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        });

        let data = pattern(400_000, 3);
        assert_eq!(echo_roundtrip(&a.handle, data.clone(), 9_000).await, data);
        noise.await.unwrap();
        // 干扰结束后隧道仍然健康
        assert_eq!(a.handle.close_reason(), None);
        let data = pattern(50_000, 4);
        assert_eq!(echo_roundtrip(&a.handle, data.clone(), 4_096).await, data);
    })
    .await;
}

#[tokio::test]
async fn opening_unexposed_port_is_reset_without_hurting_the_tunnel() {
    within(20, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        let _b = spawn_echo(b);
        let mut refused = a.handle.open_stream(PORT + 1).unwrap();
        assert!(refused.read().await.is_err(), "未暴露的端口必须被重置");
        // 写端同样应报错（额度信号量已关闭）
        let big = vec![0u8; 2 * STREAM_WINDOW as usize];
        assert!(refused.write(&big).await.is_err());

        let data = pattern(10_000, 5);
        assert_eq!(echo_roundtrip(&a.handle, data.clone(), 1_000).await, data);
    })
    .await;
}

#[tokio::test]
async fn udp_bulk_transfer_is_intact() {
    within(120, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        let _b = spawn_echo(b);
        let data = pattern(8 * 1024 * 1024, 6);
        let started = Instant::now();
        let got = echo_roundtrip(&a.handle, data.clone(), 64 * 1024).await;
        let secs = started.elapsed().as_secs_f64();
        assert!(got == data, "8MiB 往返内容必须逐字节一致");
        eprintln!(
            "[udp bulk] 8MiB 往返耗时 {secs:.2}s，单向约 {:.1} MiB/s",
            8.0 / secs
        );
    })
    .await;
}

#[tokio::test]
async fn tcp_bulk_transfer_is_intact() {
    within(120, async {
        let (a, b) = tcp_tunnels().await;
        let _b = spawn_echo(b);
        let data = pattern(8 * 1024 * 1024, 7);
        let started = Instant::now();
        let got = echo_roundtrip(&a.handle, data.clone(), 64 * 1024).await;
        let secs = started.elapsed().as_secs_f64();
        assert!(got == data, "8MiB 往返内容必须逐字节一致");
        eprintln!(
            "[tcp bulk] 8MiB 往返耗时 {secs:.2}s，单向约 {:.1} MiB/s",
            8.0 / secs
        );
    })
    .await;
}

/// 经丢包代理建一对隧道并往返 1MiB，校验内容、返回耗时（秒）
async fn lossy_roundtrip(loss_permille: u64, max_delay_ms: u64, seed: u64) -> f64 {
    let sa = udp_socket().await;
    let sb = udp_socket().await;
    let (to_bob, to_alice) = lossy_proxy(
        sa.local_addr().unwrap(),
        sb.local_addr().unwrap(),
        loss_permille,
        max_delay_ms,
    )
    .await;
    let a = Tunnel::from_link(ALICE, udp_link(BOB, sa, to_bob, KEY), TunnelConfig::default())
        .unwrap();
    let b =
        Tunnel::from_link(BOB, udp_link(ALICE, sb, to_alice, KEY), exposing(&[PORT])).unwrap();
    let _b = spawn_echo(b);

    let data = pattern(1024 * 1024, seed);
    let started = Instant::now();
    let got = echo_roundtrip(&a.handle, data.clone(), 32 * 1024).await;
    assert!(got == data, "丢包路径下内容必须逐字节一致");
    started.elapsed().as_secs_f64()
}

/// 路径丢包 5%（不乱序）：可靠层必须把数据完整送达
#[tokio::test]
async fn udp_transfer_survives_lossy_path() {
    within(120, async {
        let secs = lossy_roundtrip(50, 0, 8).await;
        eprintln!("[udp lossy] 5% 丢包下 1MiB 往返耗时 {secs:.2}s");
    })
    .await;
}

/// 路径丢包 5% + 逐包随机延迟 0-12ms（重度乱序，远超真实网络）：仍须完整送达
#[tokio::test]
async fn udp_transfer_survives_lossy_reordering_path() {
    within(120, async {
        let secs = lossy_roundtrip(50, 12, 9).await;
        eprintln!("[udp lossy+reorder] 5% 丢包 + 重度乱序下 1MiB 往返耗时 {secs:.2}s");
    })
    .await;
}

/// 读端不读时，写端必须在一个流窗口处停住（而不是无界缓冲）；读端恢复后继续直到写完
#[tokio::test]
async fn slow_reader_backpressures_writer() {
    within(60, async {
        let (a, mut b, _sa, _sb) = udp_tunnels().await;
        const TOTAL: usize = 4 * 1024 * 1024;
        let (_rd, mut wr) = a.handle.open_stream(PORT).unwrap().split();
        let incoming = b.incoming.recv().await.expect("B 应收到入站流");

        let written = Arc::new(AtomicUsize::new(0));
        let counter = written.clone();
        let writer = tokio::spawn(async move {
            let chunk = vec![0x77u8; 16 * 1024];
            while counter.load(Ordering::SeqCst) < TOTAL {
                wr.write(&chunk).await.unwrap();
                counter.fetch_add(chunk.len(), Ordering::SeqCst);
            }
            wr.finish().await;
        });

        tokio::time::sleep(Duration::from_millis(600)).await;
        let stalled_at = written.load(Ordering::SeqCst);
        assert_eq!(
            stalled_at, STREAM_WINDOW as usize,
            "写端应恰好停在一个流窗口处"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(written.load(Ordering::SeqCst), stalled_at, "读端不读时写端必须停住");

        let mut stream = incoming.stream;
        let mut total = 0usize;
        while let Some(chunk) = stream.read().await.unwrap() {
            assert!(chunk.iter().all(|&b| b == 0x77));
            total += chunk.len();
        }
        assert_eq!(total, TOTAL);
        writer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn many_concurrent_streams_do_not_interfere() {
    within(60, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        let _b = spawn_echo(b);
        let mut tasks = Vec::new();
        for i in 0..64u64 {
            let handle = a.handle.clone();
            tasks.push(tokio::spawn(async move {
                let data = pattern(20_000 + i as usize * 97, 100 + i);
                let got = echo_roundtrip(&handle, data.clone(), 1_500).await;
                assert!(got == data, "流 {i} 内容不一致");
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await;
}

async fn assert_close_propagates(a: Tunnel, b: Tunnel) {
    let b_handle = spawn_echo(b);
    let mut stream = a.handle.open_stream(PORT).unwrap();
    stream.write(b"x").await.unwrap();
    assert_eq!(stream.read().await.unwrap().unwrap(), b"x");

    a.handle.close(close_code::NORMAL);
    assert_eq!(a.handle.closed().await, CloseReason::Local);
    assert_eq!(
        b_handle.closed().await,
        CloseReason::Peer(close_code::NORMAL),
        "对端应立即得知关闭及原因码，而不是等超时"
    );
    assert!(stream.read().await.is_err(), "隧道关闭后存量流必须报错");
    assert!(a.handle.open_stream(PORT).is_err(), "隧道关闭后不能再开流");
}

#[tokio::test]
async fn close_propagates_over_udp() {
    within(20, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        assert_close_propagates(a, b).await;
    })
    .await;
}

#[tokio::test]
async fn close_propagates_over_tcp() {
    within(20, async {
        let (a, b) = tcp_tunnels().await;
        assert_close_propagates(a, b).await;
    })
    .await;
}

async fn assert_datagrams(a: Tunnel, mut b: Tunnel, min_payload: usize) {
    assert!(a.handle.send_dgram(false, 19132, 7, b"hello-dgram"));
    assert_eq!(
        b.dgrams.recv().await.unwrap(),
        InboundDgram {
            reply: false,
            port: 19132,
            flow: 7,
            data: b"hello-dgram".to_vec(),
        }
    );
    assert!(b.handle.send_dgram(true, 19132, 7, b"pong"));
    let mut a = a;
    let reply = a.dgrams.recv().await.unwrap();
    assert!(reply.reply && reply.flow == 7 && reply.data == b"pong");

    // 上限：恰好放得下的可发，超 1 字节即拒绝（不静默截断）
    let max = a.handle.max_dgram_payload();
    assert!(max >= min_payload, "max={max}");
    let big = pattern(max, 9);
    assert!(a.handle.send_dgram(false, 1, 2, &big));
    assert_eq!(b.dgrams.recv().await.unwrap().data, big);
    assert!(!a.handle.send_dgram(false, 1, 2, &vec![0u8; max + 1]));
}

#[tokio::test]
async fn datagrams_over_udp_fit_raknet_mtu_probe() {
    within(20, async {
        let (a, b, _sa, _sb) = udp_tunnels().await;
        // 基岩版 RakNet 的 1200 MTU 探测包载荷为 1172B，必须放得下
        assert_datagrams(a, b, 1172).await;
    })
    .await;
}

#[tokio::test]
async fn datagrams_over_tcp() {
    within(20, async {
        let (a, b) = tcp_tunnels().await;
        assert_datagrams(a, b, 1172).await;
    })
    .await;
}

/// 会话密钥不一致（不是同一次承诺-揭示的产物）：双方互相一个字节都解不开，隧道永远就绪不了
#[tokio::test]
async fn mismatched_session_keys_never_become_ready() {
    within(20, async {
        let sa = udp_socket().await;
        let sb = udp_socket().await;
        let (a_addr, b_addr) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        let a = Tunnel::from_link(ALICE, udp_link(BOB, sa, b_addr, KEY), TunnelConfig::default())
            .unwrap();
        let other_key = [0x5D; 32];
        let b = Tunnel::from_link(BOB, udp_link(ALICE, sb, a_addr, other_key), exposing(&[PORT]))
            .unwrap();
        let waited =
            tokio::time::timeout(Duration::from_millis(1500), a.handle.peer_hello()).await;
        assert!(waited.is_err(), "密钥不一致时不应收到对端 HELLO");
        assert!(b.handle.peer_hello_now().is_none());
    })
    .await;
}

#[tokio::test]
async fn link_preconditions_are_checked() {
    // 会话密钥已被取走（全零 = SecretBox 的「已取空」状态）
    let sa = udp_socket().await;
    let addr = sa.local_addr().unwrap();
    let mut link = udp_link(BOB, sa.clone(), addr, KEY);
    link.session_key = SecretBox::new([0u8; 32]);
    assert_eq!(
        Tunnel::from_link(ALICE, link, TunnelConfig::default()).err(),
        Some(TunnelError::KeyUnavailable)
    );
    // 对端 PeerId 与本端相同：收发方向无法区分，拒绝建隧道
    let link = udp_link(ALICE, sa, addr, KEY);
    assert_eq!(
        Tunnel::from_link(ALICE, link, TunnelConfig::default()).err(),
        Some(TunnelError::SelfPairing)
    );
}
