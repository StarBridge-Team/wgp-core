//! PoC 验收（路线图 M3）：两个 WGP 节点经种子自动打洞 → 在打通的加密隧道上跑 ET 协议 → 互发一条消息。
//! 全程回环，不依赖真实网络。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mesh_tun_proto::P2pEvent;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::time::timeout;
use wgp_core::{
    peer_id_from_node, Engine, LinkLossCause, LinkSink, PeerId, PunchedLink, RoomCode, RoomHandle,
    SessionOrchestrator,
};
use wgp_dht::{DhtNode, NodeIdentity, ObserverServer};
use wgp_et_bridge::{EtEvent, EtNode, TunnelFrameTransport, ET_TUNNEL_PORT};
use wgp_port::{Tunnel, TunnelConfig, TunnelStream};

const ROOM: &str = "U/ET-POC-0001-AB12";
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// 内核的交付口：把打通的链路送进通道
struct ChannelSink(mpsc::UnboundedSender<PunchedLink>);

impl LinkSink for ChannelSink {
    fn on_link_yielded(&self, _peer: PeerId, link: PunchedLink) {
        let _ = self.0.send(link);
    }
    fn on_link_upgraded(&self, _peer: PeerId, _link: PunchedLink) {}
    fn on_link_lost(&self, _peer: PeerId, _cause: LinkLossCause) {}
}

struct Client {
    node: Arc<DhtNode>,
    engine: Engine,
    orchestrator: SessionOrchestrator,
}

async fn client(seed: SocketAddr, observer: SocketAddr) -> Client {
    let node = DhtNode::bind(
        NodeIdentity::generate(&mut OsRng),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    node.ping(seed).await.expect("认识种子");
    let (engine, _events) = Engine::new();
    engine.attach_dht(node.clone(), seed).await;
    let orchestrator = SessionOrchestrator::new(node.clone(), engine.clone(), seed, vec![observer]);
    Client {
        node,
        engine,
        orchestrator,
    }
}

/// 打洞完成、两端各自建好隧道之后的现场（其余字段只为保活）
struct Rig {
    host_tunnel: Tunnel,
    joiner_tunnel: Tunnel,
    _seed: Arc<DhtNode>,
    _observer: Arc<ObserverServer>,
    _clients: (Client, Client),
    _rooms: (RoomHandle, RoomHandle),
}

/// 种子（DHT）+ 观察者 + 两个引擎自动装配打洞 → 内核交付 PunchedLink → 各自建成加密隧道
async fn punch() -> Rig {
    let seed = DhtNode::bind(
        NodeIdentity::generate(&mut OsRng),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let seed_addr = seed.local_addr().unwrap();
    let observer = ObserverServer::bind(0).await.unwrap();
    let observer_addr = SocketAddr::from(([127, 0, 0, 1], observer.local_addr().unwrap().port()));

    let host = client(seed_addr, observer_addr).await;
    let joiner = client(seed_addr, observer_addr).await;
    let host_peer = peer_id_from_node(&host.node.node_id());
    let joiner_peer = peer_id_from_node(&joiner.node.node_id());

    let host_room = host
        .engine
        .join_room(RoomCode(ROOM.to_string()), None)
        .await
        .expect("房主建房");
    let joiner_room = joiner
        .engine
        .join_room(RoomCode(ROOM.to_string()), None)
        .await
        .expect("加入方入表");

    let (host_tx, mut host_links) = mpsc::unbounded_channel();
    let (joiner_tx, mut joiner_links) = mpsc::unbounded_channel();
    let host_sink: Arc<dyn LinkSink> = Arc::new(ChannelSink(host_tx));
    let joiner_sink: Arc<dyn LinkSink> = Arc::new(ChannelSink(joiner_tx));
    let (host_id, joiner_id) = (host.node.node_id(), joiner.node.node_id());
    let (r1, r2) = tokio::join!(
        host.orchestrator.connect_peer(ROOM, joiner_id, host_sink),
        joiner.orchestrator.connect_peer(ROOM, host_id, joiner_sink),
    );
    assert!(r1.is_ok() && r2.is_ok(), "装配应成功：{r1:?} / {r2:?}");

    let host_link = timeout(STEP_TIMEOUT, host_links.recv())
        .await
        .expect("房主侧应收到打通的链路")
        .expect("交付通道关闭");
    let joiner_link = timeout(STEP_TIMEOUT, joiner_links.recv())
        .await
        .expect("加入方应收到打通的链路")
        .expect("交付通道关闭");

    // 两端都声明愿意在 ET 端口上接受流
    let config = || TunnelConfig {
        expose_tcp: vec![ET_TUNNEL_PORT],
        expose_udp: Vec::new(),
    };
    let host_tunnel = Tunnel::from_link(host_peer, host_link, config()).expect("房主侧建隧道");
    let joiner_tunnel =
        Tunnel::from_link(joiner_peer, joiner_link, config()).expect("加入方建隧道");

    Rig {
        host_tunnel,
        joiner_tunnel,
        _seed: seed,
        _observer: observer,
        _clients: (host, joiner),
        _rooms: (host_room, joiner_room),
    }
}

/// 在一对隧道上开一条 ET 流：`opener` 发起，`acceptor` 接受
async fn et_stream_pair(opener: &mut Tunnel, acceptor: &mut Tunnel) -> (TunnelStream, TunnelStream) {
    let hello = timeout(STEP_TIMEOUT, opener.handle.peer_hello())
        .await
        .expect("应收到对端的隧道 HELLO")
        .expect("隧道在 HELLO 之前关闭");
    assert!(hello.tcp.contains(&ET_TUNNEL_PORT), "对端应声明接受 ET 端口");
    let opened = opener.handle.open_stream(ET_TUNNEL_PORT).expect("开流");
    let incoming = timeout(STEP_TIMEOUT, acceptor.incoming.recv())
        .await
        .expect("对端应收到入站流")
        .expect("隧道已关闭");
    assert_eq!(incoming.port, ET_TUNNEL_PORT);
    (opened, incoming.stream)
}

/// 等一个满足条件的 ET 事件（其余事件跳过）
async fn expect_event<T>(
    events: &mut mpsc::UnboundedReceiver<EtEvent>,
    what: &str,
    mut pick: impl FnMut(EtEvent) -> Option<T>,
) -> T {
    let wait = async {
        loop {
            let event = events
                .recv()
                .await
                .unwrap_or_else(|| panic!("ET 事件通道在等到「{what}」之前关闭"));
            if let Some(found) = pick(event) {
                return found;
            }
        }
    };
    timeout(STEP_TIMEOUT, wait)
        .await
        .unwrap_or_else(|_| panic!("等待「{what}」超时"))
}

fn connected(event: EtEvent) -> Option<u32> {
    match event {
        EtEvent::Connected { peer_id } => Some(peer_id),
        EtEvent::ConnectFailed { reason } => panic!("ET 握手失败：{reason}"),
        _ => None,
    }
}

fn user_data(event: EtEvent) -> Option<(u32, Vec<u8>)> {
    match event {
        EtEvent::Node(P2pEvent::InboundUserData { from_peer_id, data }) => {
            Some((from_peer_id, data))
        }
        EtEvent::SendFailed { to, reason } => panic!("发往 {to:#x} 失败：{reason}"),
        _ => None,
    }
}

fn rejected(event: EtEvent) -> Option<String> {
    match event {
        EtEvent::ConnectFailed { reason } => Some(reason),
        EtEvent::Connected { peer_id } => panic!("密钥不同却与 {peer_id:#x} 握手成功"),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_wgp_nodes_punch_then_talk_et_over_the_tunnel() {
    let run = async {
        let mut rig = punch().await;

        // —— ET 协议跑在隧道流上：两端各起一个 ET 节点（同一网络名与密钥），把流接进去握手 ——
        let (host_stream, joiner_stream) =
            et_stream_pair(&mut rig.host_tunnel, &mut rig.joiner_tunnel).await;
        let (et_host, mut host_events) = EtNode::start("wgp-et-poc", "poc-secret").unwrap();
        let (et_joiner, mut joiner_events) = EtNode::start("wgp-et-poc", "poc-secret").unwrap();
        et_host.attach(TunnelFrameTransport::spawn(host_stream, "wgp-tunnel/host"));
        et_joiner.attach(TunnelFrameTransport::spawn(joiner_stream, "wgp-tunnel/joiner"));

        let seen_by_host = expect_event(&mut host_events, "房主侧 ET 握手完成", connected).await;
        let seen_by_joiner =
            expect_event(&mut joiner_events, "加入方 ET 握手完成", connected).await;
        assert_eq!(seen_by_host, et_joiner.peer_id(), "房主认出的对端 = 加入方的 ET 节点号");
        assert_eq!(seen_by_joiner, et_host.peer_id(), "加入方认出的对端 = 房主的 ET 节点号");

        // —— 互发一条消息 ——
        et_host.send_data(et_joiner.peer_id(), b"hello from host".to_vec());
        et_joiner.send_data(et_host.peer_id(), "加入方向房主问好".as_bytes().to_vec());

        let (from, data) = expect_event(&mut joiner_events, "加入方收到消息", user_data).await;
        assert_eq!(from, et_host.peer_id());
        assert_eq!(data, b"hello from host");
        let (from, data) = expect_event(&mut host_events, "房主收到消息", user_data).await;
        assert_eq!(from, et_joiner.peer_id());
        assert_eq!(String::from_utf8(data).unwrap(), "加入方向房主问好");

        // —— 同一条隧道上再开一条流（反方向发起），接一个密钥不同的 ET 节点：握手必须失败。
        //    这说明桥接没有绕过 ET 自己的网络隔离，也顺带验证了一条隧道能承载多条 ET 流 ——
        let (stranger_stream, host_stream_2) =
            et_stream_pair(&mut rig.joiner_tunnel, &mut rig.host_tunnel).await;
        let (stranger, mut stranger_events) =
            EtNode::start("wgp-et-poc", "another-secret").unwrap();
        stranger.attach(TunnelFrameTransport::spawn(stranger_stream, "wgp-tunnel/stranger"));
        et_host.attach(TunnelFrameTransport::spawn(host_stream_2, "wgp-tunnel/host-2"));

        let reason = expect_event(&mut stranger_events, "陌生节点被拒", rejected).await;
        assert!(reason.contains("mismatch"), "拒绝原因应为身份不符，得到：{reason}");
        let reason = expect_event(&mut host_events, "房主拒绝陌生节点", rejected).await;
        assert!(reason.contains("mismatch"), "拒绝原因应为身份不符，得到：{reason}");

        // 已建立的那条 ET 连接不受影响
        et_joiner.send_data(et_host.peer_id(), b"still here".to_vec());
        let (from, data) = expect_event(&mut host_events, "旧连接仍可用", user_data).await;
        assert_eq!((from, data.as_slice()), (et_joiner.peer_id(), &b"still here"[..]));

        et_host.stop();
        et_joiner.stop();
        stranger.stop();
    };
    timeout(Duration::from_secs(120), run)
        .await
        .expect("PoC 全流程应在 120s 内完成");
}
