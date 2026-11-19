//! ET 桥接验收（路线图 M3）：两个 WGP 节点经种子自动打洞 → 在打通的加密隧道上跑 ET 协议。
//! 全程回环，不依赖真实网络，也不与官方 EasyTier 节点对测。
//!
//! 覆盖：
//! 1. 握手（含密钥不同必须被拒）；
//! 2. 路由同步与虚拟 IP：两端各自宣告，各自在路由表里看到对方那条；
//! 3. IP 帧双向：A 发给 B 的虚拟 IP，B 收到 `InboundIpPacket`（数据帧走隧道数据报通道）；
//! 4. 新节点加入：第三条 ET 流上来后，已在网的节点能看到它的路由条目；
//! 5. 节点离开：停掉新节点，已在网的节点收到 `PeerDown`，路由表里不再有它。

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
use wgp_et_bridge::{
    establish_et_stream, EtEvent, EtNode, EtRoute, EtStreamSide, TunnelFrameTransport,
    ET_DGRAM_PORT, ET_STREAM_PORT,
};
use wgp_port::{Tunnel, TunnelConfig, TunnelStream};

const ROOM: &str = "U/ET-POC-0001-AB12";
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// ET 网络名与密钥（两端必须一致）
const NET: &str = "wgp-et-poc";
const SECRET: &str = "poc-secret";

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
    host_peer: PeerId,
    joiner_peer: PeerId,
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
    let (host_identity_key, joiner_identity_key) = (
        host.node.identity().verifying_key().to_bytes(),
        joiner.node.identity().verifying_key().to_bytes(),
    );
    let (r1, r2) = tokio::join!(
        host.orchestrator
            .connect_peer(ROOM, joiner_id, joiner_identity_key, host_sink),
        joiner
            .orchestrator
            .connect_peer(ROOM, host_id, host_identity_key, joiner_sink),
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
        expose_tcp: vec![ET_STREAM_PORT],
        expose_udp: Vec::new(),
    };
    let host_tunnel = Tunnel::from_link(host_peer, host_link, config()).expect("房主侧建隧道");
    let joiner_tunnel =
        Tunnel::from_link(joiner_peer, joiner_link, config()).expect("加入方建隧道");

    Rig {
        host_tunnel,
        joiner_tunnel,
        host_peer,
        joiner_peer,
        _seed: seed,
        _observer: observer,
        _clients: (host, joiner),
        _rooms: (host_room, joiner_room),
    }
}

/// 在既有隧道上再开一对 ET 流：按桥接的确定性规则决定谁发起（PeerId 小的一方）。
async fn et_stream_pair(
    rig: &mut Rig,
    what: &str,
) -> (TunnelStream, TunnelStream, EtStreamSide, EtStreamSide) {
    let Rig {
        host_tunnel,
        joiner_tunnel,
        host_peer,
        joiner_peer,
        ..
    } = rig;
    let (host, joiner) = tokio::join!(
        establish_et_stream(host_tunnel, host_peer, joiner_peer),
        establish_et_stream(joiner_tunnel, joiner_peer, host_peer),
    );
    let (host_stream, host_side) = host.unwrap_or_else(|e| panic!("{what}：房主侧建流失败：{e}"));
    let (joiner_stream, joiner_side) =
        joiner.unwrap_or_else(|e| panic!("{what}：加入方建流失败：{e}"));
    assert_ne!(
        host_side, joiner_side,
        "{what}：必须只有一方发起，否则会开出两条流"
    );
    (host_stream, joiner_stream, host_side, joiner_side)
}

/// 等一个满足条件的 ET 事件（其余事件跳过）
async fn expect_event<T>(
    events: &mut mpsc::Receiver<EtEvent>,
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
        EtEvent::Ipv4SendFailed { reason } => panic!("IP 包发送失败：{reason}"),
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

/// 路由快照里是否已经有 `peer_id` 那条、且虚拟 IP 对得上
fn route_of(routes: &[EtRoute], peer_id: u32, ipv4: u32) -> bool {
    routes
        .iter()
        .any(|r| r.peer_id == peer_id && r.ipv4 == Some(ipv4))
}

/// 等到路由表里能看到「某个节点 + 它的虚拟 IP」
async fn expect_route(
    events: &mut mpsc::Receiver<EtEvent>,
    what: &str,
    peer_id: u32,
    ipv4: u32,
) -> Vec<EtRoute> {
    expect_event(events, what, |event| match event {
        EtEvent::Routes { routes } if route_of(&routes, peer_id, ipv4) => Some(routes),
        EtEvent::Node(P2pEvent::Ipv4Conflict { ipv4, peer_ids }) => {
            panic!("虚拟 IP 冲突：{ipv4:#x} 被 {peer_ids:x?} 同时宣告")
        }
        _ => None,
    })
    .await
}

/// 一个最小的 IPv4 包（20 字节头 + 8 字节 ICMP Echo），`dst` 是点分十进制四段
fn ipv4_echo(dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45; // IPv4 + IHL=5
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&[10, 144, 0, 1]);
    p[16..20].copy_from_slice(&dst);
    p[20] = 8; // Echo Request
    p[24..26].copy_from_slice(&1u16.to_be_bytes()); // id
    p[26..28].copy_from_slice(&1u16.to_be_bytes()); // seq
    p
}

fn vip(last: u8) -> u32 {
    u32::from_be_bytes([10, 144, 0, last])
}

fn inbound_ip(event: EtEvent) -> Option<Vec<u8>> {
    match event {
        EtEvent::Node(P2pEvent::InboundIpPacket(pkt)) => Some(pkt),
        EtEvent::Ipv4SendFailed { reason } => panic!("IP 包发送失败：{reason}"),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_wgp_nodes_punch_then_talk_et_over_the_tunnel() {
    let run = async {
        let mut rig = punch().await;

        // —— ET 协议跑在隧道上：两端各起一个 ET 节点（同一网络名与密钥），把流接进去握手 ——
        let (host_stream, joiner_stream, host_side, _) = et_stream_pair(&mut rig, "第一条流").await;
        let (et_host, mut host_events) = EtNode::start(NET, SECRET).unwrap();
        let (et_joiner, mut joiner_events) = EtNode::start(NET, SECRET).unwrap();
        let host_transport =
            TunnelFrameTransport::spawn_with_dgram(host_stream, &mut rig.host_tunnel, "tunnel/host");
        assert!(host_transport.uses_dgram(), "第一条流应带数据报通道");
        assert_eq!(
            host_side == EtStreamSide::Opened,
            rig.host_peer < rig.joiner_peer,
            "PeerId 小的一方发起（房主侧）"
        );
        et_host.attach(host_transport).expect("队列应有空位接入房主流");
        let joiner_transport =
            TunnelFrameTransport::spawn_with_dgram(joiner_stream, &mut rig.joiner_tunnel, "tunnel/joiner");
        assert!(joiner_transport.uses_dgram(), "数据帧要走数据报通道");
        et_joiner
            .attach(joiner_transport)
            .expect("队列应有空位接入加入流");

        let seen_by_host = expect_event(&mut host_events, "房主侧 ET 握手完成", connected).await;
        let seen_by_joiner =
            expect_event(&mut joiner_events, "加入方 ET 握手完成", connected).await;
        assert_eq!(
            seen_by_host,
            et_joiner.peer_id(),
            "房主认出的对端 = 加入方的 ET 节点号"
        );
        assert_eq!(
            seen_by_joiner,
            et_host.peer_id(),
            "加入方认出的对端 = 房主的 ET 节点号"
        );

        // —— 互发一条消息（自定义 payload，走数据报通道）——
        et_host
            .send_data(et_joiner.peer_id(), b"hello from host".to_vec())
            .expect("发送命令应入队");
        et_joiner
            .send_data(et_host.peer_id(), "加入方向房主问好".as_bytes().to_vec())
            .expect("发送命令应入队");

        let (from, data) = expect_event(&mut joiner_events, "加入方收到消息", user_data).await;
        assert_eq!(from, et_host.peer_id());
        assert_eq!(data, b"hello from host");
        let (from, data) = expect_event(&mut host_events, "房主收到消息", user_data).await;
        assert_eq!(from, et_joiner.peer_id());
        assert_eq!(String::from_utf8(data).unwrap(), "加入方向房主问好");

        // —— 同一条隧道上再开一条流（按同一规则发起），接一个密钥不同的 ET 节点：握手必须失败。
        //    这说明桥接没有绕过 ET 自己的网络隔离，也顺带验证了一条隧道能承载多条 ET 流 ——
        let (stranger_stream, host_stream_2, stranger_side, _) =
            et_stream_pair(&mut rig, "第二条流").await;
        assert_eq!(
            stranger_side, host_side,
            "同一对 PeerId 的规则不变：还是同一方发起"
        );
        let (stranger, mut stranger_events) = EtNode::start(NET, "another-secret").unwrap();
        stranger
            .attach(TunnelFrameTransport::spawn(
                stranger_stream,
                "tunnel/stranger",
            ))
            .expect("队列应有空位接入陌生节点流");
        et_host
            .attach(TunnelFrameTransport::spawn(
                host_stream_2,
                "tunnel/host-2",
            ))
            .expect("队列应有空位接入第二条流");

        let reason = expect_event(&mut stranger_events, "陌生节点被拒", rejected).await;
        assert!(
            reason.contains("mismatch"),
            "拒绝原因应为身份不符，得到：{reason}"
        );
        let reason = expect_event(&mut host_events, "房主拒绝陌生节点", rejected).await;
        assert!(
            reason.contains("mismatch"),
            "拒绝原因应为身份不符，得到：{reason}"
        );

        // 已建立的那条 ET 连接不受影响
        et_joiner
            .send_data(et_host.peer_id(), b"still here".to_vec())
            .expect("发送命令应入队");
        let (from, data) = expect_event(&mut host_events, "旧连接仍可用", user_data).await;
        assert_eq!(
            (from, data.as_slice()),
            (et_joiner.peer_id(), &b"still here"[..])
        );

        et_host.stop();
        et_joiner.stop();
        stranger.stop();
    };
    timeout(Duration::from_secs(120), run)
        .await
        .expect("PoC 全流程应在 120s 内完成");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_sync_virtual_ip_and_ip_frames_go_over_the_tunnel() {
    let run = async {
        let mut rig = punch().await;
        let (host_stream, joiner_stream, _, _) = et_stream_pair(&mut rig, "ET 流").await;

        let (et_host, mut host_events) = EtNode::start(NET, SECRET).unwrap();
        let (et_joiner, mut joiner_events) = EtNode::start(NET, SECRET).unwrap();
        et_host
            .attach(TunnelFrameTransport::spawn_with_dgram(
                host_stream,
                &mut rig.host_tunnel,
                "tunnel/host",
            ))
            .expect("接入房主流");
        et_joiner
            .attach(TunnelFrameTransport::spawn_with_dgram(
                joiner_stream,
                &mut rig.joiner_tunnel,
                "tunnel/joiner",
            ))
            .expect("接入加入流");
        expect_event(&mut host_events, "房主侧握手", connected).await;
        expect_event(&mut joiner_events, "加入方握手", connected).await;

        // —— 各自宣告虚拟 IP ——
        let (host_vip, joiner_vip) = (vip(10), vip(20));
        et_host.announce("host", Some(host_vip)).unwrap();
        et_joiner.announce("joiner", Some(joiner_vip)).unwrap();

        // 双方的路由表里都应出现对方的虚拟 IP（这是「第二轮同步」也能看到的结果：
        // 宣告之后增量同步带过来的就是新节点的条目）
        expect_route(
            &mut host_events,
            "房主看到加入方的虚拟 IP",
            et_joiner.peer_id(),
            joiner_vip,
        )
        .await;
        expect_route(
            &mut joiner_events,
            "加入方看到房主的虚拟 IP",
            et_host.peer_id(),
            host_vip,
        )
        .await;

        // —— 双向 IP 帧：A 发给 B 的虚拟 IP，B 收到原始 IP 包；反过来也一样 ——
        let to_joiner = ipv4_echo([10, 144, 0, 20]);
        et_host.send_ipv4(to_joiner.clone()).expect("发送命令入队");
        let got = expect_event(&mut joiner_events, "加入方收到 IP 包", inbound_ip).await;
        assert_eq!(got, to_joiner, "IP 包必须原样到达");

        let to_host = ipv4_echo([10, 144, 0, 10]);
        et_joiner.send_ipv4(to_host.clone()).expect("发送命令入队");
        let got = expect_event(&mut host_events, "房主收到 IP 包", inbound_ip).await;
        assert_eq!(got, to_host);

        // —— 新节点加入：第三条 ET 流上来，已在网的房主要能看到它的路由条目 ——
        let (late_stream, late_host_stream, late_side, _) =
            et_stream_pair(&mut rig, "第三条流").await;
        // 发起方那一侧的流交给新节点；另一侧的流接给已在网的房主
        let (late_transport, host_transport_2) = if late_side == EtStreamSide::Opened {
            (
                TunnelFrameTransport::spawn(late_stream, "tunnel/late"),
                TunnelFrameTransport::spawn(late_host_stream, "tunnel/host-late"),
            )
        } else {
            (
                TunnelFrameTransport::spawn(late_host_stream, "tunnel/late"),
                TunnelFrameTransport::spawn(late_stream, "tunnel/host-late"),
            )
        };
        let (late, mut late_events) = EtNode::start(NET, SECRET).unwrap();
        late.attach(late_transport).expect("接入新节点流");
        et_host
            .attach(host_transport_2)
            .expect("房主接入新节点那一侧");
        expect_event(&mut host_events, "房主与 新节点 握手", connected).await;
        expect_event(&mut late_events, "新节点握手", connected).await;

        let late_vip = vip(30);
        late.announce("late", Some(late_vip)).unwrap();
        let routes = expect_route(
            &mut host_events,
            "房主看到新节点的虚拟 IP",
            late.peer_id(),
            late_vip,
        )
        .await;
        assert!(
            route_of(&routes, et_joiner.peer_id(), joiner_vip),
            "先前的节点不能被后来的同步冲掉：{routes:?}"
        );

        // 新节点也能看到房主的虚拟 IP
        expect_route(
            &mut late_events,
            "新节点看到房主的虚拟 IP",
            et_host.peer_id(),
            host_vip,
        )
        .await;

        // —— 节点离开：停掉新节点后，房主收到 PeerDown，路由表里不再有它 ——
        let late_et_id = late.peer_id();
        late.stop();
        expect_event(&mut host_events, "房主看到新节点掉线", |event| match event {
            EtEvent::Node(P2pEvent::PeerDown { peer_id, .. }) if peer_id == late_et_id => {
                Some(peer_id)
            }
            _ => None,
        })
        .await;
        let gone = expect_event(&mut host_events, "路由表里新节点消失", |event| match event {
            EtEvent::Routes { routes } if !routes.iter().any(|r| r.peer_id == late_et_id) => {
                Some(routes)
            }
            _ => None,
        })
        .await;
        assert!(!gone.iter().any(|r| r.peer_id == late_et_id));

        // 现有的那条 ET 连接不受影响：房主仍能收到加入方的 IP 包
        et_joiner
            .send_ipv4(ipv4_echo([10, 144, 0, 10]))
            .expect("发送命令入队");
        expect_event(&mut host_events, "旧连接的 IP 包仍能到达", inbound_ip).await;

        et_host.stop();
        et_joiner.stop();
    };
    timeout(Duration::from_secs(180), run)
        .await
        .expect("路由 / 虚拟 IP / IP 帧全流程应在 180s 内完成");
    // 端口常量留个守卫：数据报端口与流端口同号，但含义不同
    assert_eq!(ET_DGRAM_PORT, ET_STREAM_PORT);
}
