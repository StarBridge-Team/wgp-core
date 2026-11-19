//! S1 验收：两座桥经一条 ET 链路互发 UDP 报文。
//!
//! 拓扑（全程回环）：
//!
//! ```text
//! 测试客户端 127.0.0.1:X ──► 加入方桥 127.0.0.3:11010 ── ET 自定义帧 ──► 房主桥 127.0.0.2:11010 ──► 回显 127.0.0.1:11010
//! ```
//!
//! 中间没有 `wgp-node`，也没有 relay：两个 ET 节点经一个「TCP 字节管道」直接握手（ET 的
//! 流式帧本来就是点到点的，一个转发字节的监听器就够当测试用 relay）。

use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::{Duration, Instant};
use wgp_et_bridge::fallback::{
    derive_network, FallbackBridge, ProxyConfig, SERVICE_PORT_DHT, SERVICE_PORT_STUN,
};

/// 一个只会转发字节的 TCP 监听器：把前两个连接对接起来，充当「测试用 relay」。
fn byte_pipe_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("relay 绑定");
    let addr = listener.local_addr().expect("relay 地址");
    std::thread::spawn(move || {
        let (a, _) = listener.accept().expect("relay 接受第一个连接");
        let (b, _) = listener.accept().expect("relay 接受第二个连接");
        let (mut ar, mut aw) = (a.try_clone().expect("clone"), a);
        let (mut br, mut bw) = (b.try_clone().expect("clone"), b);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut ar, &mut bw);
        });
        let _ = std::io::copy(&mut br, &mut aw);
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_datagram_crosses_the_et_link_both_ways() {
    eprintln!("[t] 起回显与客户端");
    // 回显服务（房主侧的本机应用）与测试客户端
    let echo = UdpSocket::bind("127.0.0.1:11010").expect("回显服务绑定 11010");
    echo.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").expect("测试客户端绑定");
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    let relay = byte_pipe_relay();
    eprintln!("[t] relay 在 {relay}");
    let (name, secret) = derive_network(&[7u8; 32]);

    // 房主侧桥：监听 127.0.0.2，把报文交给本机 127.0.0.1
    let host_cfg = ProxyConfig {
        bind_ip: Ipv4Addr::new(127, 0, 0, 2),
        local_app_ip: Some(Ipv4Addr::LOCALHOST),
        service_ports: vec![SERVICE_PORT_DHT, SERVICE_PORT_STUN],
    };
    let (host_bridge, mut host_events) = FallbackBridge::start(
        host_cfg,
        name.clone(),
        secret.clone(),
        relay,
    )
    .await
    .expect("房主桥启动");
    let host_punch = host_bridge.punch_port();
    eprintln!("[t] 房主桥 peer={} punch={host_punch}", host_bridge.peer_id());
    let (host_stop, host_stop_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(host_bridge.run(host_stop_rx));

    // 加入方侧桥：监听 127.0.0.3，本机应用地址从它自己的报文里学
    let joiner_cfg = ProxyConfig {
        bind_ip: Ipv4Addr::new(127, 0, 0, 3),
        local_app_ip: None,
        service_ports: vec![SERVICE_PORT_DHT, SERVICE_PORT_STUN],
    };
    let (joiner_bridge, mut joiner_events) = FallbackBridge::start(
        joiner_cfg,
        name,
        secret,
        relay,
    )
    .await
    .expect("加入方桥启动");
    let joiner_punch = joiner_bridge.punch_port();
    eprintln!("[t] 加入方桥 peer={} punch={joiner_punch}", joiner_bridge.peer_id());
    let (joiner_stop, joiner_stop_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(joiner_bridge.run(joiner_stop_rx));

    // 两侧都看到对端（PeerUp）之后才开始发报文：桥只有知道对端才转发
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut host_up = false;
    let mut joiner_up = false;
    while Instant::now() < deadline && !(host_up && joiner_up) {
        tokio::select! {
            Some(ev) = host_events.recv() => {
                eprintln!("[t] 房主桥事件 {ev:?}");
                if let wgp_et_bridge::fallback::BridgeEvent::PeerUp { .. } = ev { host_up = true; }
            }
            Some(ev) = joiner_events.recv() => {
                eprintln!("[t] 加入方桥事件 {ev:?}");
                if let wgp_et_bridge::fallback::BridgeEvent::PeerUp { .. } = ev { joiner_up = true; }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    eprintln!("[t] host_up={host_up} joiner_up={joiner_up}");
    assert!(host_up, "房主桥应看到 ET 对端");
    assert!(joiner_up, "加入方桥应看到 ET 对端");
    assert_ne!(host_punch, joiner_punch, "两侧打洞端口按节点号派生，不应相同");

    // 客户端 → 加入方桥 → ET → 房主桥 → 回显服务；回程原路返回
    let responder = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 256];
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        while Instant::now() < deadline {
            // 回显服务：收一枚就原样送回
            if let Ok((n, src)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], src);
                seen.push(buf[..n].to_vec());
            }
            // 测试客户端：等回程
            if let Ok((n, _src)) = client.recv_from(&mut buf) {
                return Some(buf[..n].to_vec());
            }
            let _ = client.send_to(b"ping-through-et", SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), SERVICE_PORT_DHT));
        }
        let _ = seen;
        None
    });

    let got = responder.await.expect("回程任务不应 panic");
    let _ = host_stop.send(());
    let _ = joiner_stop.send(());
    assert_eq!(
        got.as_deref(),
        Some(&b"ping-through-et"[..]),
        "报文必须经 ET 链路往返（含房主侧应用与回程地址映射）"
    );
}

/// 打洞端口：两侧应用各自绑在自己的 `punch` 端口上，通过桥互相打洞。
///
/// 这是 S4（数据面）的桥接层前提：对端会按「我的 ET 节点号」算出端口并把打洞报文发到
/// `bind_ip:punch(me)`，所以桥必须真的在那个端口上听，并把报文交给本机绑定在同号端口的应用。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_ports_reach_the_peer_application() {
    let relay = byte_pipe_relay();
    let (name, secret) = derive_network(&[5u8; 32]);

    let host_cfg = ProxyConfig {
        bind_ip: Ipv4Addr::new(127, 0, 0, 5),
        local_app_ip: Some(Ipv4Addr::LOCALHOST),
        service_ports: vec![SERVICE_PORT_DHT],
    };
    let (host_bridge, mut host_events) = FallbackBridge::start(
        host_cfg,
        name.clone(),
        secret.clone(),
        relay,
    )
    .await
    .expect("房主桥");
    let host_punch = host_bridge.punch_port();
    let (host_stop, host_stop_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(host_bridge.run(host_stop_rx));

    let joiner_cfg = ProxyConfig {
        bind_ip: Ipv4Addr::new(127, 0, 0, 6),
        local_app_ip: None,
        service_ports: vec![SERVICE_PORT_DHT],
    };
    let (joiner_bridge, mut joiner_events) = FallbackBridge::start(
        joiner_cfg,
        name,
        secret,
        relay,
    )
    .await
    .expect("加入方桥");
    let joiner_punch = joiner_bridge.punch_port();
    let (joiner_stop, joiner_stop_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(joiner_bridge.run(joiner_stop_rx));

    // 两侧应用：绑在自己的打洞端口上（回退形态里 wgp 的打洞载体就是这个端口）
    assert_ne!(host_punch, joiner_punch, "两个节点号派生的端口不应相同");
    let host_app = UdpSocket::bind((Ipv4Addr::LOCALHOST, host_punch)).expect("房主应用绑定打洞端口");
    host_app.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let joiner_app =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, joiner_punch)).expect("加入方应用绑定打洞端口");
    joiner_app.set_read_timeout(Some(Duration::from_millis(200))).unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    let (mut host_up, mut joiner_up) = (false, false);
    while Instant::now() < deadline && !(host_up && joiner_up) {
        tokio::select! {
            Some(ev) = host_events.recv() => {
                if matches!(ev, wgp_et_bridge::fallback::BridgeEvent::PeerUp { .. }) { host_up = true; }
            }
            Some(ev) = joiner_events.recv() => {
                if matches!(ev, wgp_et_bridge::fallback::BridgeEvent::PeerUp { .. }) { joiner_up = true; }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(host_up && joiner_up, "两侧都要看到对端");

    // 加入方按「对端的打洞端口」发包。注意：同一台机器上两侧桥绑在不同回环地址（.5/.6），
    // 所以每侧都往**自己那边**的 bind_ip 发——真实部署里两侧的 bind_ip 都是 127.0.0.2，
    // 这两个写法就合并成同一个地址。
    let host_punch_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 6).into(), host_punch);
    let joiner = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 64];
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut got = None;
        while Instant::now() < deadline {
            let _ = joiner_app.send_to(b"punch", host_punch_addr);
            if let Ok((n, src)) = joiner_app.recv_from(&mut buf) {
                // 房主应用回显的 pong
                let _ = src;
                got = Some(buf[..n].to_vec());
                break;
            }
        }
        got
    });

    // 房主应用：收到就回 pong（它看到的来源就是桥给它的对端地址）
    let host_reply = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 64];
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok((n, src)) = host_app.recv_from(&mut buf) {
                let _ = host_app.send_to(b"pong", src);
                let _ = n;
                return true;
            }
        }
        false
    });

    let (got, replied) = (joiner.await.unwrap(), host_reply.await.unwrap());
    let _ = host_stop.send(());
    let _ = joiner_stop.send(());
    assert!(replied, "房主应用应收到打洞报文");
    assert_eq!(got.as_deref(), Some(&b"pong"[..]), "加入方应收到回程打洞报文");
}
