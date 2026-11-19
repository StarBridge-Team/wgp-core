//! 探针：库的「流式传输 + 自定义 payload」到底怎么用。
//!
//! 这不是产品代码，只回答一个问题：两个 `P2pNode` 通过 `add_stream_conn`（TCP 流）握手之后，
//! `send_data_to` 的载荷会不会以 `P2pEvent::InboundUserData` 送到对端。桥接（`fallback`）
//! 依赖这条通道，所以这里先把它钉成可复现的最小用例。

use mesh_tun_proto::{P2pEvent, P2pNode};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// 只转发字节的监听器：把前两个连接对接起来
fn byte_pipe_relay() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("relay 绑定");
    let addr = listener.local_addr().expect("地址");
    std::thread::spawn(move || {
        let (a, _) = listener.accept().expect("第一个连接");
        let (b, _) = listener.accept().expect("第二个连接");
        let (mut ar, mut aw) = (a.try_clone().expect("clone"), a);
        let (mut br, mut bw) = (b.try_clone().expect("clone"), b);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut ar, &mut bw);
        });
        let _ = std::io::copy(&mut br, &mut aw);
    });
    addr
}

#[test]
fn user_data_over_stream_transport_reaches_the_peer() {    let relay = byte_pipe_relay();
    let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>();
    let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>();

    let spawn = |tx: mpsc::Sender<Vec<u8>>| {
        std::thread::spawn(move || {
            let mut node = P2pNode::new("probe-net", "probe-secret", None);
            node.set_my_tun_enabled(false);
            let stream = TcpStream::connect(relay).expect("连 relay");
            // 与库自带 examples/poc.rs 一致：给流设读超时，tick 才不会卡在 read 上
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("设读超时");
            let stream2 = stream.try_clone().expect("clone");
            let _keep = stream2;
            let peer = node.add_stream_conn(stream).expect("握手");
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut sent = false;
            while Instant::now() < deadline {
                if !sent {
                    match node.send_data_to(peer, b"probe-payload") {
                        Ok(()) => eprintln!("[probe] send_data_to ok"),
                        Err(e) => eprintln!("[probe] send_data_to 失败：{e}"),
                    }
                    sent = true;
                }
                for event in node.tick(64) {
                    eprintln!("[probe] 事件 {event:?}");
                    if let P2pEvent::InboundUserData { data, .. } = event {
                        let _ = tx.send(data);
                        return;
                    }
                }
                let _ = node.announce_self_to_all("probe", None);
                std::thread::sleep(Duration::from_millis(30));
                let _ = &mut buf;
            }
        });
    };

    spawn(tx_a);
    spawn(tx_b);
    let got_a = rx_a.recv_timeout(Duration::from_secs(15));
    let got_b = rx_b.recv_timeout(Duration::from_secs(15));
    assert_eq!(
        got_a.expect("A 应收到 B 的载荷").as_slice(),
        b"probe-payload",
        "A 收到的载荷必须一致"
    );
    assert_eq!(
        got_b.expect("B 应收到 A 的载荷").as_slice(),
        b"probe-payload",
        "B 收到的载荷必须一致"
    );
    let _ = std::io::empty().read(&mut [0u8; 1]);
    let _ = std::io::sink().write_all(b"");
}
