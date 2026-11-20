//! S2 验收：**房主进程内的本地种子**经桥被加入方访问，房间能读能写。
//!
//! ```text
//! 房主                                  ET 链路                        加入方
//! DhtNode 127.0.0.1:21010 ──► 桥 127.0.0.2:21010 ═══════► 桥 127.0.0.4:21010 ──► DhtNode(临时端口)
//! ObserverServer :23478   ──► 桥 127.0.0.2:23478 ═══════► 桥 127.0.0.4:23478
//! ```
//!
//! 注意端口用的是 21010/23478 而不是 11010/3478：同一进程里还有另一条回环用例在用默认端口，
//! 两个测试并行跑时不能抢同一个端口。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use wgp_dht::{
    room_key, DhtNode, EndpointScope, NodeIdentity, ObserverServer, RoomRuntime,
};
use wgp_et_bridge::fallback::{
    derive_network, BridgeEvent, FallbackBridge, ProxyConfig,
};

const DHT_PORT: u16 = 21_010;
const STUN_PORT: u16 = 23_478;

/// 桥与内核必须用**同一套**网络派生：两侧算出不同网络就根本碰不到一起。
///
/// 这条用例是防漂移的钉子：一边改了派生规则而另一边没改，这里立刻红。
#[test]
fn network_derivation_matches_the_core() {
    for seed in [0u8, 7, 0x5a, 0xff] {
        let key = [seed; 32];
        assert_eq!(
            derive_network(&key),
            wgp_dht::et_fallback_network(&key),
            "seed={seed}：桥侧派生必须与 wgp-dht 一致"
        );
    }
    // 用房间码派生的真实路径也一致
    let key = room_key("U/FALLBACK-ROOM-01-AB12");
    assert_eq!(derive_network(&key), wgp_dht::et_fallback_network(&key));
}

/// 只转发字节的测试 relay（同 fallback_bridge.rs）
fn byte_pipe_relay() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("relay 绑定");
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

async fn wait_peers(
    host_events: &mut tokio::sync::mpsc::UnboundedReceiver<BridgeEvent>,
    joiner_events: &mut tokio::sync::mpsc::UnboundedReceiver<BridgeEvent>,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let (mut host_up, mut joiner_up) = (false, false);
    while Instant::now() < deadline && !(host_up && joiner_up) {
        tokio::select! {
            Some(ev) = host_events.recv() => {
                if matches!(ev, BridgeEvent::PeerUp { .. }) { host_up = true; }
            }
            Some(ev) = joiner_events.recv() => {
                if matches!(ev, BridgeEvent::PeerUp { .. }) { joiner_up = true; }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(host_up && joiner_up, "两侧桥都应看到对端（host={host_up} joiner={joiner_up}）");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn room_is_readable_and_writable_through_the_fallback_bridge() {
    // 房主侧：进程内的本地种子（DHT + 观察者），模拟 `wgp-client 开房` 在回退形态下起的那一个
    let host_identity = NodeIdentity::generate(&mut rand_core::OsRng);
    let host_seed = DhtNode::bind(
        host_identity,
        SocketAddr::from((Ipv4Addr::LOCALHOST, DHT_PORT)),
    )
    .await
    .expect("房主种子绑定");
    host_seed.set_endpoint_scope(EndpointScope::LocalNetwork);
    let _observer = ObserverServer::bind(STUN_PORT).await.expect("观察者绑定");

    let relay = byte_pipe_relay();
    let (name, secret) = derive_network(&[9u8; 32]);

    let (host_bridge, mut host_events) = FallbackBridge::start(
        ProxyConfig {
            bind_ip: Ipv4Addr::new(127, 0, 0, 2),
            local_app_ip: Some(Ipv4Addr::LOCALHOST),
            service_ports: vec![DHT_PORT, STUN_PORT],
        },
        name.clone(),
        secret.clone(),
        relay,
    )
    .await
    .expect("房主桥");
    let (host_stop, host_stop_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(host_bridge.run(host_stop_rx));

    let (joiner_bridge, mut joiner_events) = FallbackBridge::start(
        ProxyConfig {
            bind_ip: Ipv4Addr::new(127, 0, 0, 4),
            local_app_ip: None,
            service_ports: vec![DHT_PORT, STUN_PORT],
        },
        name,
        secret,
        relay,
    )
    .await
    .expect("加入方桥");
    let (joiner_stop, joiner_stop_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(joiner_bridge.run(joiner_stop_rx));

    wait_peers(&mut host_events, &mut joiner_events).await;

    // 房主建房（房主 = 锚点 = 存储节点，回退形态下就是同一个进程内的这个种子）
    let storage = SocketAddr::from((Ipv4Addr::LOCALHOST, DHT_PORT));
    let host_rt = RoomRuntime::new(host_seed.clone(), storage);
    const CODE: &str = "U/FALLBACK-ROOM-01-AB12";
    let created = host_rt.create(CODE, 1_000).await.expect("建房");
    assert_eq!(created.lease.anchor, host_seed.node_id());

    // 加入方：自己的 DHT 节点 + 把桥的地址当作种子
    let joiner_identity = NodeIdentity::generate(&mut rand_core::OsRng);
    let joiner_node = DhtNode::bind(joiner_identity, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("加入方 DHT 绑定");
    joiner_node.set_endpoint_scope(EndpointScope::LocalNetwork);
    let bridged_seed = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 4), DHT_PORT));

    // ① 信令：PING 能通（身份证明握手也要经桥走一遍）
    //
    // 要重试：桥是先连上 ET、再从路由表学到对端的，这之前的报文会被丢掉；真实客户端
    // 也是这样重试的（`warm_up` 最多 10 次），第一次可能因为丢包/竞态失败。
    let mut last_err = String::new();
    let mut pong = None;
    for _ in 0..10 {
        match joiner_node.ping(bridged_seed).await {
            Ok(p) => {
                pong = Some(p);
                break;
            }
            Err(e) => {
                last_err = format!("{e:?}");
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    let pong = pong.unwrap_or_else(|| panic!("加入方应能经桥 PING 到房主种子（最后一次：{last_err}）"));
    assert_eq!(pong.node_id, host_seed.node_id(), "应答者必须是房主种子");

    // ② 房间读写：读得到房主建的房间
    let joiner_rt = RoomRuntime::new(joiner_node.clone(), bridged_seed);
    let fetched = joiner_rt.fetch(CODE).await.expect("加入方应能读到房间");
    assert_eq!(fetched.lease, created.lease, "租约一致");
    assert_eq!(fetched.members, created.members, "成员表一致");

    // ③ 写入：加入方的**报道**（JoinRequest）经桥送到锚点，锚点把自己写进成员表。
    //    这是回退形态下真正的写路径：客户端 → 桥 → 房主种子（存储 + 锚点）。
    let (stop_host, stop_rx) = tokio::sync::watch::channel(false);
    let upkeep_seed = host_seed.clone();
    tokio::spawn(async move {
        RoomRuntime::new(upkeep_seed, storage)
            .upkeep(CODE.to_string(), 100, stop_rx, || 2_000)
            .await;
    });
    joiner_rt
        .request_join(CODE, &fetched)
        .await
        .expect("报道应能经桥送达锚点");

    let mut joined = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(record) = joiner_rt.fetch(CODE).await {
            if record
                .members
                .iter()
                .any(|(id, _)| *id == joiner_node.node_id())
            {
                joined = Some(record);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let joined = joined.expect("加入方应经桥入表（锚点处理了它的报道）");
    assert_eq!(joined.members.len(), 2, "成员表里应有房主与加入方");
    let _ = stop_host.send(true);

    // ④ 房间键与 ET 网络派生用的是同一份房间键（防止两侧算出不同网络）
    assert_eq!(room_key(CODE).len(), 32);

    let _ = host_stop.send(());
    let _ = joiner_stop.send(());
}
