//! 端口转发集成测试：本地应用 ⇄ PortHub ⇄ 隧道 ⇄ PortHub ⇄ 本地服务。
//! 最后一个用例走完整链路：种子 + 观察者 + 双引擎自动打洞 → 内核交付 → 转发可用。

mod common;

use common::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::UnboundedReceiver;
use wgp_core::PunchedLink;
use wgp_port::{
    close_code, Carrier, CloseReason, ExposeRule, ForwardRule, PortConfig, PortEvent, PortHub,
    Proto,
};

/// 房主暴露给对端的「服务端口」编号（与本机实际目标地址解耦）
const SERVICE: u16 = 25565;
const UDP_SERVICE: u16 = 19132;

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// TCP 回显服务：读到 EOF 后关闭写方向（用来检验半关闭能否穿过隧道）
async fn tcp_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = conn.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

async fn udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn next_event(
    rx: &mut UnboundedReceiver<PortEvent>,
    what: &str,
    pred: impl Fn(&PortEvent) -> bool,
) -> PortEvent {
    within(30, async {
        loop {
            let event = rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("事件流结束，未等到：{what}"));
            if pred(&event) {
                return event;
            }
        }
    })
    .await
}

struct Rig {
    host: PortHub,
    joiner: PortHub,
    host_events: UnboundedReceiver<PortEvent>,
    joiner_events: UnboundedReceiver<PortEvent>,
    /// 加入方本地的 TCP 转发口
    tcp_forward: SocketAddr,
    /// 加入方本地的 UDP 转发口
    udp_forward: SocketAddr,
}

/// 房主（ALICE）暴露 TCP/UDP 回显服务；加入方（BOB）各开一个本地转发口
async fn rig(tcp_target: SocketAddr, udp_target: SocketAddr) -> Rig {
    let (host, host_events) = PortHub::start(
        ALICE,
        PortConfig {
            expose_tcp: vec![ExposeRule {
                port: SERVICE,
                target: tcp_target,
            }],
            expose_udp: vec![ExposeRule {
                port: UDP_SERVICE,
                target: udp_target,
            }],
            ..PortConfig::default()
        },
    )
    .await
    .unwrap();
    let (joiner, mut joiner_events) = PortHub::start(
        BOB,
        PortConfig {
            forward_tcp: vec![ForwardRule {
                listen: loopback(0),
                remote_port: SERVICE,
            }],
            forward_udp: vec![ForwardRule {
                listen: loopback(0),
                remote_port: UDP_SERVICE,
            }],
            ..PortConfig::default()
        },
    )
    .await
    .unwrap();
    let mut tcp_forward = None;
    let mut udp_forward = None;
    for _ in 0..2 {
        match joiner_events.recv().await.unwrap() {
            PortEvent::Listening {
                proto: Proto::Tcp,
                listen,
                remote_port,
            } => {
                assert_eq!(remote_port, SERVICE);
                tcp_forward = Some(listen);
            }
            PortEvent::Listening {
                proto: Proto::Udp,
                listen,
                remote_port,
            } => {
                assert_eq!(remote_port, UDP_SERVICE);
                udp_forward = Some(listen);
            }
            other => panic!("启动阶段只应有监听事件，得到 {other:?}"),
        }
    }
    Rig {
        host,
        joiner,
        host_events,
        joiner_events,
        tcp_forward: tcp_forward.unwrap(),
        udp_forward: udp_forward.unwrap(),
    }
}

impl Rig {
    /// 把一对链路交付给两端，并等加入方看到「隧道就绪且对端暴露了服务端口」
    async fn link_up(&mut self, for_host: PunchedLink, for_joiner: PunchedLink) {
        self.host.attach_link(BOB, for_host);
        self.joiner.attach_link(ALICE, for_joiner);
        let ready = next_event(&mut self.joiner_events, "加入方隧道就绪", |e| {
            matches!(e, PortEvent::TunnelReady { .. })
        })
        .await;
        match ready {
            PortEvent::TunnelReady { peer, tcp, udp } => {
                assert_eq!(peer, ALICE);
                assert_eq!(tcp, vec![SERVICE]);
                assert_eq!(udp, vec![UDP_SERVICE]);
            }
            _ => unreachable!(),
        }
        assert!(self.joiner.has_tunnel(&ALICE));
    }
}

/// 经转发口发送 `data`，读回全部回显；写完后关闭写方向，读到 EOF 为止
async fn tcp_roundtrip(addr: SocketAddr, data: Vec<u8>) -> Vec<u8> {
    let conn = TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = conn.into_split();
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    got
}

#[tokio::test]
async fn tcp_forward_over_udp_link() {
    within(60, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner, _sa, _sb) = udp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        match next_event(&mut rig.host_events, "房主隧道启动", |e| {
            matches!(e, PortEvent::TunnelUp { .. })
        })
        .await
        {
            PortEvent::TunnelUp { peer, carrier, .. } => {
                assert_eq!(peer, BOB);
                assert_eq!(carrier, Carrier::Udp);
            }
            _ => unreachable!(),
        }

        // 小包交互（游戏流量的典型形态）
        let mut conn = TcpStream::connect(rig.tcp_forward).await.unwrap();
        for i in 0..50u8 {
            let msg = [i; 37];
            conn.write_all(&msg).await.unwrap();
            let mut back = [0u8; 37];
            conn.read_exact(&mut back).await.unwrap();
            assert_eq!(back, msg);
        }
        drop(conn);

        // 大块数据 + 半关闭
        let data = pattern(2 * 1024 * 1024, 11);
        assert!(tcp_roundtrip(rig.tcp_forward, data.clone()).await == data);

        // 房主侧能看到对端连入
        next_event(&mut rig.host_events, "房主侧入站流", |e| {
            matches!(
                e,
                PortEvent::StreamOpened {
                    port: SERVICE,
                    inbound: true,
                    ..
                }
            )
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn tcp_forward_over_tcp_link() {
    within(60, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner) = tcp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        let data = pattern(2 * 1024 * 1024, 12);
        assert!(tcp_roundtrip(rig.tcp_forward, data.clone()).await == data);
    })
    .await;
}

#[tokio::test]
async fn concurrent_connections_share_one_tunnel() {
    within(60, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner, _sa, _sb) = udp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        let mut tasks = Vec::new();
        for i in 0..16u64 {
            let addr = rig.tcp_forward;
            tasks.push(tokio::spawn(async move {
                let data = pattern(100_000 + i as usize * 1_000, 200 + i);
                assert!(tcp_roundtrip(addr, data.clone()).await == data, "连接 {i}");
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn forward_without_any_peer_closes_the_connection() {
    within(20, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        // 还没有任何隧道：连接被接受后立即关闭，应用侧读到 EOF 或复位
        let mut conn = TcpStream::connect(rig.tcp_forward).await.unwrap();
        let mut buf = [0u8; 16];
        let closed = match conn.read(&mut buf).await {
            Ok(0) | Err(_) => true,
            Ok(_) => false,
        };
        assert!(closed, "没有对端时转发口不应吞下连接不放");
        next_event(&mut rig.joiner_events, "无可用对端", |e| {
            matches!(
                e,
                PortEvent::NoProvider {
                    proto: Proto::Tcp,
                    remote_port: SERVICE
                }
            )
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn dead_local_service_is_reported_and_connection_closed() {
    within(30, async {
        // 目标端口无人监听（先占后放）
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let mut rig = rig(dead, udp_echo_server().await).await;
        let (for_host, for_joiner, _sa, _sb) = udp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;

        let mut conn = TcpStream::connect(rig.tcp_forward).await.unwrap();
        let _ = conn.write_all(b"anyone?").await;
        let mut buf = [0u8; 16];
        let closed = match conn.read(&mut buf).await {
            Ok(0) | Err(_) => true,
            Ok(_) => false,
        };
        assert!(closed, "房主侧服务没开时，加入方的连接应被关闭而不是悬挂");
        match next_event(&mut rig.host_events, "目标不可达", |e| {
            matches!(e, PortEvent::TargetUnreachable { .. })
        })
        .await
        {
            PortEvent::TargetUnreachable { port, target } => {
                assert_eq!(port, SERVICE);
                assert_eq!(target, dead);
            }
            _ => unreachable!(),
        }
        // 隧道本身不受影响
        assert!(rig.joiner.has_tunnel(&ALICE));
    })
    .await;
}

async fn assert_udp_forward(rig: &Rig) {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(rig.udp_forward).await.unwrap();
    let mut buf = vec![0u8; 2048];
    // 含基岩版 RakNet 的 1200 MTU 探测包尺寸（载荷 1172B）
    for (i, len) in [1usize, 17, 500, 1172]
        .into_iter()
        .cycle()
        .take(40)
        .enumerate()
    {
        let msg = pattern(len, 300 + i as u64);
        // 数据报不保证送达：允许重发，但收到的回显必须与发出的完全一致
        let mut echoed = false;
        for _ in 0..5 {
            client.send(&msg).await.unwrap();
            match tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    assert_eq!(&buf[..n], &msg[..], "第 {i} 个数据报回显不一致");
                    echoed = true;
                    break;
                }
                _ => continue,
            }
        }
        assert!(echoed, "第 {i} 个数据报（{len}B）始终没有回显");
    }
}

#[tokio::test]
async fn udp_forward_over_udp_link() {
    within(60, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner, _sa, _sb) = udp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        assert_udp_forward(&rig).await;
    })
    .await;
}

#[tokio::test]
async fn udp_forward_over_tcp_link() {
    within(60, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner) = tcp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        assert_udp_forward(&rig).await;
    })
    .await;
}

/// 同一对端重新打洞（新链路、新会话密钥）：以新代旧，旧隧道让位，转发恢复可用
#[tokio::test]
async fn relink_replaces_old_tunnel() {
    within(60, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner, _sa, _sb) = udp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        let data = pattern(50_000, 13);
        assert!(tcp_roundtrip(rig.tcp_forward, data.clone()).await == data);

        // 新一轮打洞的交付物：全新 socket + 全新会话密钥（14 §10 条款 5）
        let new_key = [0x6E; 32];
        let sa = udp_socket().await;
        let sb = udp_socket().await;
        let (a_addr, b_addr) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
        rig.host
            .attach_link(BOB, udp_link(BOB, sa, b_addr, new_key));
        rig.joiner
            .attach_link(ALICE, udp_link(ALICE, sb, a_addr, new_key));

        // 加入方应看到：旧隧道收尾（对端以 REPLACED 关闭，或本端先一步主动让位）+ 新隧道就绪。
        // 两个事件的先后取决于调度，不作假设。
        let (mut down, mut ready) = (None, false);
        while down.is_none() || !ready {
            match next_event(&mut rig.joiner_events, "换链事件", |_| true).await {
                PortEvent::TunnelDown { peer, reason } => {
                    assert_eq!(peer, ALICE);
                    down = Some(reason);
                }
                PortEvent::TunnelReady { peer, .. } => {
                    assert_eq!(peer, ALICE);
                    ready = true;
                }
                _ => {}
            }
        }
        let reason = down.unwrap();
        assert!(
            matches!(
                reason,
                CloseReason::Peer(close_code::REPLACED) | CloseReason::Local
            ),
            "reason={reason:?}"
        );
        // 旧隧道收尾不得误删新隧道
        assert!(rig.joiner.has_tunnel(&ALICE));
        assert!(rig.host.has_tunnel(&BOB));
        let data = pattern(200_000, 14);
        assert!(tcp_roundtrip(rig.tcp_forward, data.clone()).await == data);
    })
    .await;
}

#[tokio::test]
async fn shutdown_notifies_peer_immediately() {
    within(30, async {
        let mut rig = rig(tcp_echo_server().await, udp_echo_server().await).await;
        let (for_host, for_joiner, _sa, _sb) = udp_link_pair().await;
        rig.link_up(for_host, for_joiner).await;
        rig.host.shutdown();
        match next_event(&mut rig.joiner_events, "对端退出", |e| {
            matches!(e, PortEvent::TunnelDown { .. })
        })
        .await
        {
            PortEvent::TunnelDown { reason, .. } => {
                assert_eq!(reason, CloseReason::Peer(close_code::NORMAL));
            }
            _ => unreachable!(),
        }
        assert!(!rig.joiner.has_tunnel(&ALICE));
    })
    .await;
}

#[tokio::test]
async fn occupied_forward_port_fails_fast() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let result = PortHub::start(
        BOB,
        PortConfig {
            forward_tcp: vec![ForwardRule {
                listen: occupied.local_addr().unwrap(),
                remote_port: SERVICE,
            }],
            ..PortConfig::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "转发口被占用必须在启动时报错，而不是等到打洞成功之后"
    );
}

/// 全链路：种子（DHT）+ 观察者 + 两个引擎自动装配打洞 → 内核把链路交付给 PortHub
/// → 经转发口访问对端暴露的服务。内核保活哨兵全程在同一 socket 上发探针。
#[tokio::test]
async fn full_pipeline_punch_then_forward() {
    use rand_core::OsRng;
    use wgp_core::{peer_id_from_node, Engine, LinkSink, RoomCode, SessionOrchestrator};
    use wgp_dht::{DhtNode, NodeIdentity, ObserverServer};

    within(90, async {
        // —— 种子进程（wgp-node 同构：DHT + 观察者）——
        let seed = DhtNode::bind(
            NodeIdentity::generate(&mut OsRng),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let seed_addr = seed.local_addr().unwrap();
        let observer = ObserverServer::bind(0).await.unwrap();
        let observer_addr = loopback(observer.local_addr().unwrap().port());

        struct Client {
            node: Arc<DhtNode>,
            engine: Engine,
            orchestrator: SessionOrchestrator,
        }
        async fn client(seed_addr: SocketAddr, observer: SocketAddr) -> Client {
            let node = DhtNode::bind(
                NodeIdentity::generate(&mut OsRng),
                "127.0.0.1:0".parse().unwrap(),
            )
            .await
            .unwrap();
            node.ping(seed_addr).await.expect("认识种子");
            let (engine, _events) = Engine::new();
            engine.attach_dht(node.clone(), seed_addr).await;
            let orchestrator =
                SessionOrchestrator::new(node.clone(), engine.clone(), seed_addr, vec![observer]);
            Client {
                node,
                engine,
                orchestrator,
            }
        }
        let host = client(seed_addr, observer_addr).await;
        let joiner = client(seed_addr, observer_addr).await;
        let host_peer = peer_id_from_node(&host.node.node_id());
        let joiner_peer = peer_id_from_node(&joiner.node.node_id());

        // —— 数据面：房主暴露回显服务，加入方开本地转发口 ——
        let echo = tcp_echo_server().await;
        let (host_hub, _host_events) = PortHub::start(
            host_peer,
            PortConfig {
                expose_tcp: vec![ExposeRule {
                    port: SERVICE,
                    target: echo,
                }],
                ..PortConfig::default()
            },
        )
        .await
        .unwrap();
        let (joiner_hub, mut joiner_events) = PortHub::start(
            joiner_peer,
            PortConfig {
                forward_tcp: vec![ForwardRule {
                    listen: loopback(0),
                    remote_port: SERVICE,
                }],
                ..PortConfig::default()
            },
        )
        .await
        .unwrap();
        let forward = match joiner_events.recv().await.unwrap() {
            PortEvent::Listening { listen, .. } => listen,
            other => panic!("期望监听事件，得到 {other:?}"),
        };

        // —— 房间：房主建房，加入方入表 ——
        const ROOM: &str = "U/PORT-E2E0-0001-AB12";
        let _host_room = host
            .engine
            .join_room(RoomCode(ROOM.to_string()), None)
            .await
            .expect("房主建房");
        let mut joined = None;
        for _ in 0..20 {
            if let Ok(handle) = joiner
                .engine
                .join_room(RoomCode(ROOM.to_string()), None)
                .await
            {
                joined = Some(handle);
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let _joiner_room = joined.expect("加入方入表");

        // —— 双方对等装配：链路交付物直接落到各自的 PortHub ——
        let host_sink: Arc<dyn LinkSink> = Arc::new(host_hub.clone());
        let joiner_sink: Arc<dyn LinkSink> = Arc::new(joiner_hub.clone());
        let (host_id, joiner_id) = (host.node.node_id(), joiner.node.node_id());
        let (host_identity_key, joiner_identity_key) = (
            host.node.identity().verifying_key().to_bytes(),
            joiner.node.identity().verifying_key().to_bytes(),
        );
        let (r1, r2) = tokio::join!(
            host.orchestrator
                .connect_peer(ROOM, joiner_id, joiner_identity_key, host_sink,),
            joiner
                .orchestrator
                .connect_peer(ROOM, host_id, host_identity_key, joiner_sink,),
        );
        assert!(r1.is_ok() && r2.is_ok(), "装配应成功：{r1:?} / {r2:?}");

        match next_event(&mut joiner_events, "加入方隧道就绪", |e| {
            matches!(e, PortEvent::TunnelReady { .. })
        })
        .await
        {
            PortEvent::TunnelReady { peer, tcp, .. } => {
                assert_eq!(peer, host_peer);
                assert_eq!(tcp, vec![SERVICE]);
            }
            _ => unreachable!(),
        }

        // —— 业务数据经打洞链路往返 ——
        let data = pattern(1024 * 1024, 15);
        assert!(tcp_roundtrip(forward, data.clone()).await == data);

        // 跨过若干个内核保活周期（2s）后隧道仍然可用：探针与业务数据共用 socket 互不干扰
        tokio::time::sleep(Duration::from_millis(4_500)).await;
        let data = pattern(100_000, 16);
        assert!(tcp_roundtrip(forward, data.clone()).await == data);
        assert!(joiner_hub.has_tunnel(&host_peer));
        assert!(host_hub.has_tunnel(&joiner_peer));

        // 主动释放：停内核保活 + 关隧道
        host.engine.release(joiner_peer).await;
        host_hub.shutdown();
        next_event(&mut joiner_events, "对端退出", |e| {
            matches!(e, PortEvent::TunnelDown { .. })
        })
        .await;
    })
    .await;
}
