//! DhtNode 网络层集成测试（loopback 三节点拓扑：A、B、种子 S）

#[cfg(test)]
mod tests {
    use crate::id::NodeIdentity;
    use crate::node::DhtNode;
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use wgp_crypto::commit::commit;
    use wgp_crypto::ka::KeyAgreement;
    use wgp_crypto::ka::X25519Agreement;
    use wgp_proto::sig::{algo, sig_type, CommitBody, RevealBody, SigBody, SigPacket};

    async fn spawn_node() -> Arc<DhtNode> {
        let mut rng = OsRng;
        let id = NodeIdentity::generate(&mut rng);
        DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn dropping_node_releases_udp_socket_and_receive_task() {
        let node = spawn_node().await;
        let addr = node.local_addr().unwrap();
        drop(node);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                tokio::task::yield_now().await;
                let mut rng = OsRng;
                match DhtNode::bind(NodeIdentity::generate(&mut rng), addr).await {
                    Ok(rebound) => break drop(rebound),
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                    Err(error) => panic!("rebind failed unexpectedly: {error}"),
                }
            }
        })
        .await
        .expect("dropping the last Arc should release the UDP socket");
    }

    #[tokio::test]
    async fn maintenance_evicts_dead_non_seed_routes() {
        let node = spawn_node().await;
        let peer = spawn_node().await;
        let peer_id = peer.node_id();
        let peer_addr = peer.local_addr().unwrap();
        node.ping(peer_addr).await.unwrap();
        assert!(node
            .known_nodes()
            .await
            .iter()
            .any(|(id, _)| *id == peer_id));
        drop(peer);

        for _ in 0..crate::node::ROUTE_FAILURE_LIMIT {
            node.probe_routing_batch(&HashSet::new()).await;
        }
        assert!(!node
            .known_nodes()
            .await
            .iter()
            .any(|(id, _)| *id == peer_id));
    }

    /// 中继策略：贡献模式（Deny）下种子不再中转他人消息；恢复 Allow 即通。
    #[tokio::test]
    async fn relay_policy_deny_blocks_transit() {
        use crate::node::RelayPolicy;

        let a = spawn_node().await;
        let b = spawn_node().await;
        let c = spawn_node().await;

        // 三节点互认（C 将作为中转）
        a.ping(addr(&c)).await.unwrap();
        c.ping(addr(&b)).await.unwrap();
        c.ping(addr(&a)).await.unwrap();
        b.ping(addr(&c)).await.unwrap();

        let payload = vec![0x5Au8; 20];

        // ① Deny：中转静默拒绝
        c.set_relay_policy(RelayPolicy::Deny).await;
        a.forward_to(addr(&c), b.node_id(), payload.clone())
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(600), b.recv_forward()).await;
        assert!(got.is_err(), "贡献模式不得为中转（B 不应收到）");

        // ② Allow：恢复中转即通
        c.set_relay_policy(RelayPolicy::Allow).await;
        a.forward_to(addr(&c), b.node_id(), payload.clone())
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(1500), b.recv_forward())
            .await
            .expect("恢复后应送达")
            .expect("载荷非空");
        assert_eq!(got.payload, payload);
    }

    /// 会话分派：B 注册 tag 后，发往 B 的 forward 载荷按 tag 分流；
    /// 未注册 tag 落默认队列（房间管理路径）。
    #[tokio::test]
    async fn forward_session_dispatch_by_tag() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let c = spawn_node().await;
        // 三节点互认（C 作中转：A→C 转发至 B）
        a.ping(addr(&c)).await.unwrap();
        c.ping(addr(&b)).await.unwrap();
        c.ping(addr(&a)).await.unwrap();
        b.ping(addr(&c)).await.unwrap();

        let mut session_rx = b.register_session(0x1234u32).await;

        // ① 已注册 tag：载荷进会话队列（经 C 中转）
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234u32.to_be_bytes());
        payload.extend_from_slice(b"nego-data");
        a.forward_to(addr(&c), b.node_id(), payload.clone())
            .await
            .expect("转达（经 C 中转）");

        let got = tokio::time::timeout(Duration::from_millis(1500), session_rx.recv())
            .await
            .expect("会话队列应投递")
            .expect("载荷非空");
        assert_eq!(got.payload, payload, "会话载荷原样投递");

        // ② 未注册 tag：落默认队列（房间管理路径）
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x9999u32.to_be_bytes());
        raw.extend_from_slice(b"fallback");
        a.forward_to(addr(&c), b.node_id(), raw.clone())
            .await
            .unwrap();
        let default_got = tokio::time::timeout(Duration::from_millis(1500), b.recv_forward())
            .await
            .expect("未注册 tag 应落默认队列")
            .expect("默认队列有货");
        assert_eq!(default_got.payload, raw);

        // ③ 注销后同 tag 落默认队列
        b.unregister_session(0x1234u32).await;
        let _ = a.forward_to(addr(&c), b.node_id(), payload).await;
        let fallback2 = tokio::time::timeout(Duration::from_millis(1500), b.recv_forward())
            .await
            .expect("注销后转默认")
            .expect("默认队列有货");
        assert_eq!(&fallback2.payload[4..], b"nego-data");
    }

    fn addr(node: &DhtNode) -> SocketAddr {
        node.local_addr().unwrap()
    }

    #[tokio::test]
    async fn ping_roundtrip_bidirectional_learn() {
        let a = spawn_node().await;
        let b = spawn_node().await;

        let pong = a.ping(addr(&b)).await.expect("ping 应成功");
        assert_eq!(pong.node_id, b.node_id());
        assert_eq!(pong.addr, addr(&b));

        // 双向学习：A 认识 B（验证明即学），B 认识 A（回证，fire-and-forget）
        assert!(a
            .known_nodes()
            .await
            .iter()
            .any(|(id, _)| *id == b.node_id()));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let learned = b
                .known_nodes()
                .await
                .iter()
                .any(|(id, _)| *id == a.node_id());
            if learned {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "回证后 B 应认识 A（地址簿 + 路由表）"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn ping_timeout_to_dead_node() {
        let a = spawn_node().await;
        // 0.0.0.0:1 无人监听 → 1.5s 超时
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let start = tokio::time::Instant::now();
        let r = a.ping(dead).await;
        assert!(r.is_err(), "死节点必须超时");
        assert!(start.elapsed() >= Duration::from_millis(1400));
    }

    #[tokio::test]
    async fn find_node_returns_known_neighbors() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let c = spawn_node().await;

        // 拓扑：B、C 先 ping A → A 认识 B、C
        let _ = b.ping(addr(&a)).await.unwrap();
        let _ = c.ping(addr(&a)).await.unwrap();

        // C 向 A 查"离某目标最近节点"→ 应答应含 A 的已知节点
        let neighbors = c.find_node(addr(&a), a.node_id()).await.unwrap();
        let ids: Vec<_> = neighbors.iter().map(|n| n.id).collect();
        assert!(!ids.is_empty(), "应答应含已知节点");
        // 应答里不应包含 A 自己（closest 含 home? RoutingTable 不含自身）
        assert!(neighbors.iter().all(|n| n.id != a.node_id().0));
    }

    #[tokio::test]
    async fn forward_delivery_via_seed() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let seed = spawn_node().await;

        // 双方 bootstrap：与种子互 ping（互相认识）
        let _ = a.ping(addr(&seed)).await.unwrap();
        let _ = b.ping(addr(&seed)).await.unwrap();

        // A 经种子向 B 投递透明载荷（承诺包的原型）
        let payload = vec![0xC0, 0xFF, 0xEE, 0x01, 0x02, 0x03];
        a.forward_to(addr(&seed), b.node_id(), payload.clone())
            .await
            .expect("forward_to 成功");

        // B 收到载荷：字节级完整
        let got = tokio::time::timeout(Duration::from_millis(1000), b.recv_forward())
            .await
            .expect("投递超时")
            .expect("载荷丢失");
        assert_eq!(got.payload, payload);
    }

    #[tokio::test]
    async fn forward_unknown_target_silently_dropped() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let seed = spawn_node().await;
        let stranger = spawn_node().await; // 与任何人都素不相识

        let _ = a.ping(addr(&seed)).await.unwrap();
        let _ = b.ping(addr(&seed)).await.unwrap();

        // A 投递给"种子不认识的人"→ 静默丢弃，B 收不到任何东西
        a.forward_to(addr(&seed), stranger.node_id(), vec![1, 2, 3])
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(400), b.recv_forward()).await;
        assert!(got.is_err(), "未知目标必须被静默丢弃且无响应");
    }

    #[tokio::test]
    async fn garbage_burst_does_not_kill_node() {
        let a = spawn_node().await;
        let b = spawn_node().await;

        // 垃圾/恶意包洪流：节点必须存活且后续 RPC 正常
        let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for i in 0..32u8 {
            let junk = vec![i; 64];
            attacker.send_to(&junk, addr(&b)).await.unwrap();
        }
        // 延迟极短后，正常 ping 仍应成功
        tokio::time::sleep(Duration::from_millis(50)).await;
        let pong = a.ping(addr(&b)).await.expect("垃圾洪流后 ping 必须仍可用");
        assert_eq!(pong.node_id, b.node_id());
    }

    /// 信令接线实测：承诺-揭示完整信令经 DHT Forward 投递（A → 种子 → B），
    /// B 侧解出并完成密码学验证——证明"不可信转发者"通道成立（07 §2）。
    #[tokio::test]
    async fn commit_reveal_over_dht_forward() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let seed = spawn_node().await;

        // 双方都与种子互认
        let _ = a.ping(addr(&seed)).await.unwrap();
        let _ = b.ping(addr(&seed)).await.unwrap();

        // A 侧：生成临时密钥对 + nonce + 承诺
        let mut rng = OsRng;
        let ka = X25519Agreement;
        let sk = ka.keygen(&mut rng);
        let pk = ka.pubkey_raw(&sk);
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut nonce);
        let full_commit = commit(&pk, &nonce);
        let mut commit16 = [0u8; 16];
        commit16.copy_from_slice(&full_commit.0[..16]);

        let peer_a: [u8; 16] = [0xA1; 16];
        let peer_b: [u8; 16] = [0xB2; 16];

        // ① 承诺包经种子投递
        let commit_pkt = SigPacket::commit(
            CommitBody {
                peer_id: peer_a,
                commit: commit16,
            },
            algo::X25519,
            0,
        );
        a.forward_to(addr(&seed), b.node_id(), commit_pkt.encode())
            .await
            .unwrap();

        // ② 揭示包经种子投递（透明载荷含 32B 公钥 + 32B nonce）
        let reveal_pkt = SigPacket::reveal(
            RevealBody {
                peer_id: peer_a,
                pubkey: pk.clone(),
                nonce,
            },
            algo::X25519,
            0,
        );
        a.forward_to(addr(&seed), b.node_id(), reveal_pkt.encode())
            .await
            .unwrap();

        // B 侧：按序收取两个载荷并做端到端验证
        let got_commit = tokio::time::timeout(Duration::from_millis(1000), b.recv_forward())
            .await
            .unwrap()
            .expect("承诺包丢失");
        let got_reveal = tokio::time::timeout(Duration::from_millis(1000), b.recv_forward())
            .await
            .unwrap()
            .expect("揭示包丢失");

        let dec_commit = SigPacket::decode(&got_commit.payload).expect("承诺包解码");
        let dec_reveal = SigPacket::decode(&got_reveal.payload).expect("揭示包解码");

        let (their_peer, their_commit16) = match dec_commit.body {
            SigBody::Commit(c) => (c.peer_id, c.commit),
            _ => panic!("期望 Commit"),
        };
        assert_eq!(their_peer, peer_a);
        assert_eq!(their_commit16, commit16, "承诺载荷字节级一致");

        let (their_pk, their_nonce) = match dec_reveal.body {
            SigBody::Reveal(r) => (r.pubkey, r.nonce),
            _ => panic!("期望 Reveal"),
        };
        assert_eq!(their_pk, pk);
        assert_eq!(their_nonce, nonce);

        // ③ 密码学验证：SHA256(pk||nonce)[..16] == 承诺（MITM 检测闭环）
        let mut h = Sha256::new();
        h.update(&their_pk);
        h.update(&their_nonce);
        let digest: [u8; 32] = h.finalize().into();
        assert_eq!(
            &digest[..16],
            &their_commit16[..],
            "承诺-揭示经转发后验签一致"
        );

        let _ = (sig_type::COMMIT, peer_b);
    }

    // —————————————— TCP 信令面测试 ——————————————

    /// 启一条 TCP 信令监听，返回其监听地址
    async fn spawn_tcp(node: &Arc<DhtNode>) -> SocketAddr {
        node.listen_tcp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
    }

    /// TCP ping 单次往返：应答身份正确；且 TCP 入站**不得**毒化地址簿
    /// （TCP 源端口 ≠ UDP NAT 映射，写入地址簿会把 Forward 中转指向错误端口）。
    #[tokio::test]
    async fn tcp_ping_roundtrip_and_no_addr_book_pollution() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let b_tcp = spawn_tcp(&b).await;

        let pong = a.ping_tcp(b_tcp).await.expect("TCP ping 应成功");
        assert_eq!(pong.node_id, b.node_id());
        assert_eq!(pong.addr, b_tcp);

        // 核心断言：B 经 TCP 收到 A 的 ping，但地址簿必须为空（只入路由表）
        assert!(
            b.known_nodes().await.is_empty(),
            "TCP 入站不得把源地址写入地址簿（会毒化 UDP 中转路由）"
        );
    }

    /// TCP KV：写入 → 读回字节一致；未命中返回空值。
    #[tokio::test]
    async fn tcp_store_and_find_value() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let b_tcp = spawn_tcp(&b).await;

        let key = [0x11u8; 32];
        let value = vec![0xABu8; 300];
        a.store_tcp(b_tcp, key, value.clone())
            .await
            .expect("TCP store 应收到 StoredAck");

        let got = a.find_value_tcp(b_tcp, key).await.expect("TCP find_value");
        assert_eq!(got.key, key);
        assert_eq!(got.value, value, "KV 值字节级一致");

        // 未命中：空值（非错误）
        let miss = a
            .find_value_tcp(b_tcp, [0x22u8; 32])
            .await
            .expect("未命中应返回空值而非错误");
        assert!(miss.value.is_empty());

        // store 的 sender 学习同样只入路由表
        assert!(b.known_nodes().await.is_empty(), "TCP store 不得毒化地址簿");
    }

    /// TCP Forward 投递：客户端经 TCP 把"致 B"的载荷交给种子，
    /// 种子按地址簿以 UDP 转给 B（种子→目标腿仍是 UDP，符合拓扑假设）。
    #[tokio::test]
    async fn tcp_forward_relayed_by_seed_over_udp() {
        let a = spawn_node().await;
        let b = spawn_node().await;
        let seed = spawn_node().await;

        // 种子先经 UDP 认识 B（这样地址簿里才有 B 的 UDP 端点）
        let _ = b.ping(addr(&seed)).await.unwrap();
        let seed_tcp = spawn_tcp(&seed).await;

        let payload = vec![0x7Eu8; 12];
        a.forward_tcp(seed_tcp, b.node_id(), payload.clone())
            .await
            .expect("TCP forward 投递");

        let got = tokio::time::timeout(Duration::from_millis(1500), b.recv_forward())
            .await
            .expect("经 TCP→种子→UDP 应送达 B")
            .expect("载荷非空");
        assert_eq!(got.payload, payload);
    }

    /// TCP 帧长越界：写一个超大长度前缀 → 服务端应断连，节点存活且后续仍可服务。
    #[tokio::test]
    async fn tcp_oversize_frame_rejected_and_node_survives() {
        use tokio::io::AsyncWriteExt;

        let a = spawn_node().await;
        let b = spawn_node().await;
        let b_tcp = spawn_tcp(&b).await;

        // 帧长 > MAX_TCP_FRAME(4096)：仅写 2B 长度头（声明 0xFFFF）
        let mut evil = tokio::net::TcpStream::connect(b_tcp).await.unwrap();
        evil.write_all(&0xFFFFu16.to_be_bytes()).await.unwrap();
        evil.flush().await.unwrap();
        drop(evil);

        // 节点必须存活：正常 TCP ping 仍可用
        tokio::time::sleep(Duration::from_millis(50)).await;
        let pong = a.ping_tcp(b_tcp).await.expect("非法帧后节点须存活");
        assert_eq!(pong.node_id, b.node_id());
    }

    // —————————————— 种子发现（07 §5 第③层 / 17 P0） ——————————————

    mod seed_discovery {
        use super::*;
        use crate::advertise::{sign_advertise_v2, AdvertiseSpec};
        use crate::id::NodeId;
        use tokio::net::UdpSocket;
        use wgp_proto::dht::{FindSeedsBody, RpcBody, RpcPacket, SEEDS_MAX};
        use wgp_proto::packet::seed_advertise_v2::FLAG_RELAY;

        /// 以节点的真实回环端点生成广告内容
        fn spec_of(node: &DhtNode, stun_port: u16, flags: u8) -> AdvertiseSpec {
            let at = addr(node);
            let std::net::IpAddr::V4(ip) = at.ip() else {
                panic!("测试节点应为 IPv4");
            };
            AdvertiseSpec {
                addr_v4: ip.octets(),
                dht_port: at.port(),
                stun_port,
                tcp_port: 0,
                priority: 0,
                flags,
                name_hash: [0; 4],
            }
        }

        /// 起一个正在宣告的种子
        async fn spawn_seed(stun_port: u16) -> Arc<DhtNode> {
            let node = spawn_node().await;
            node.start_advertising(spec_of(&node, stun_port, FLAG_RELAY), 1)
                .await;
            node
        }

        async fn has_seed(node: &Arc<DhtNode>, id: NodeId) -> bool {
            node.seeds().await.iter().any(|s| s.node_id == id)
        }

        /// 轮询等待目录里出现指定种子
        async fn wait_seed(node: &Arc<DhtNode>, id: NodeId, within_ms: u64) -> bool {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(within_ms);
            loop {
                if has_seed(node, id).await {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        async fn knows(node: &Arc<DhtNode>, id: NodeId) -> bool {
            node.known_nodes()
                .await
                .iter()
                .any(|(known, _)| *known == id)
        }

        /// 轮询等待「认识」成立：回证是 fire-and-forget，学习比分发晚一个包
        async fn wait_knows(node: &Arc<DhtNode>, id: NodeId, within_ms: u64) -> bool {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(within_ms);
            loop {
                if knows(node, id).await {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// 以裸 UDP 报文的形式把一条广告推给目标节点（模拟任意第三方转述 / 攻击者注入）
        async fn push_raw(to: &DhtNode, raw: &[u8]) {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sock.send_to(raw, addr(to)).await.unwrap();
        }

        /// 宣告者把广告推给它配置的入口 → 入口验签、探活、入目录；反方向不会凭空出现条目
        #[tokio::test]
        async fn pushed_advert_is_verified_probed_and_admitted() {
            let hub = spawn_node().await; // 不宣告的老式种子
            let newcomer = spawn_node().await;
            newcomer.pin_seeds(&[addr(&hub)]).await;
            newcomer
                .start_advertising(spec_of(&newcomer, 3478, FLAG_RELAY), 1)
                .await;

            assert!(
                wait_seed(&hub, newcomer.node_id(), 2000).await,
                "入口应收录宣告者"
            );
            let seeds = hub.seeds().await;
            assert_eq!(seeds.len(), 1);
            assert_eq!(seeds[0].addr, addr(&newcomer));
            assert_eq!(
                seeds[0].observer_addr(),
                Some(SocketAddr::from(([127, 0, 0, 1], 3478)))
            );
            assert_eq!(seeds[0].tcp_addr(), None);
            assert!(seeds[0].relays());
            assert!(seeds[0].rtt_ms.is_some(), "入表时已测得往返耗时");
            // 探活用的 PING/PONG 顺带完成了双向认识（地址簿）
            assert!(knows(&hub, newcomer.node_id()).await);
            assert!(knows(&newcomer, hub.node_id()).await);
            // 入口自己没有宣告：宣告者的目录里不会有它
            assert!(newcomer.seeds().await.is_empty());
        }

        /// 客户端向一个种子索取，得到该种子自己的广告与它认识的其他种子
        #[tokio::test]
        async fn find_seeds_returns_own_and_known_adverts() {
            let s1 = spawn_seed(3478).await;
            let s2 = spawn_node().await;
            s2.pin_seeds(&[addr(&s1)]).await;
            s2.start_advertising(spec_of(&s2, 0, 0), 1).await; // 贡献模式：不中转、无观察者
            assert!(wait_seed(&s1, s2.node_id(), 2000).await);

            let client = spawn_node().await;
            let got = client.find_seeds(addr(&s1), client.node_id()).await;
            assert_eq!(got, Ok(2), "应收录 s1 自己与它认识的 s2");

            let seeds = client.seeds().await;
            let of = |id: NodeId| seeds.iter().find(|s| s.node_id == id).unwrap();
            assert!(of(s1.node_id()).relays());
            assert!(of(s1.node_id()).observer_addr().is_some());
            assert!(!of(s2.node_id()).relays(), "贡献模式种子必须可辨认");
            assert_eq!(of(s2.node_id()).observer_addr(), None);
            // 客户端不宣告：种子的目录里不会出现它
            assert!(!has_seed(&s1, client.node_id()).await);

            // 再问一次（含按任意键补全）：全是已知条目，数量不变
            assert_eq!(client.find_seeds(addr(&s1), client.node_id()).await, Ok(2));
            assert_eq!(client.seek_seeds(NodeId([0x77; 32])).await, 2);
        }

        /// 三种不该入表的广告：冒领别人的地址、报一个没人的地址、内容被篡改
        #[tokio::test]
        async fn forged_or_misaddressed_adverts_are_not_admitted() {
            let victim = spawn_seed(3478).await;
            let client = spawn_node().await;

            // ① 攻击者用自己的身份签一条广告，地址却填受害种子的：签名有效，但那个地址上应答的不是它
            let mallory = NodeIdentity::generate(&mut OsRng);
            let hijack = sign_advertise_v2(&mallory, &spec_of(&victim, 3478, FLAG_RELAY), 9);
            push_raw(&client, &hijack).await;

            // ② 地址上根本没人
            let ghost = NodeIdentity::generate(&mut OsRng);
            let mut nowhere = spec_of(&victim, 0, 0);
            nowhere.dht_port = 1;
            push_raw(&client, &sign_advertise_v2(&ghost, &nowhere, 1)).await;

            // ③ 真广告被改了一位（观察者端口）：验签即拒，连探活都不会发生
            let mut tampered = victim.own_advert().await.unwrap();
            tampered[10] ^= 0x01;
            push_raw(&client, &tampered).await;

            // ① 的探活确实发生过（客户端因此认识了受害种子），但谁也没进目录
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while !knows(&client, victim.node_id()).await {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "冒领广告应触发一次探活"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // 等 ② 的探活超时（1.5s）过去
            tokio::time::sleep(Duration::from_millis(1800)).await;
            assert!(
                client.seeds().await.is_empty(),
                "伪造 / 谎报地址 / 被篡改的广告都不得入表"
            );
        }

        /// 重放旧广告不回退；同端点的更新广告即时生效；换端点必须重新探活
        #[tokio::test]
        async fn replay_is_ignored_refresh_applies_and_moves_need_probe() {
            let seed = spawn_node().await;
            let identity = seed.identity();
            seed.start_advertising(spec_of(&seed, 3478, FLAG_RELAY), 5)
                .await;
            let client = spawn_node().await;
            assert_eq!(
                client.find_seeds(addr(&seed), client.node_id()).await,
                Ok(1)
            );
            let entry = || async { client.seeds().await.into_iter().next().unwrap() };
            assert_eq!(entry().await.epoch, 5);

            // 重放一条更旧的广告（观察者端口不同）：目录不变
            let older = sign_advertise_v2(&identity, &spec_of(&seed, 9999, 0), 3);
            push_raw(&client, &older).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let now = entry().await;
            assert_eq!(
                (now.epoch, now.stun_port),
                (5, 3478),
                "旧广告不得覆盖新广告"
            );

            // 同一端点、更大的纪元：直接生效
            let newer = sign_advertise_v2(&identity, &spec_of(&seed, 4000, 0), 6);
            push_raw(&client, &newer).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while entry().await.epoch != 6 {
                assert!(tokio::time::Instant::now() < deadline, "更新广告应被采纳");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let now = entry().await;
            assert_eq!(now.stun_port, 4000);
            assert!(!now.relays());

            // 纪元更大但端点换到了一个没人应答的地方：探活失败，条目保持原样
            let mut moved_spec = spec_of(&seed, 4000, 0);
            moved_spec.dht_port = 1;
            push_raw(&client, &sign_advertise_v2(&identity, &moved_spec, 7)).await;
            tokio::time::sleep(Duration::from_millis(1800)).await;
            let now = entry().await;
            assert_eq!(
                (now.epoch, now.addr),
                (6, addr(&seed)),
                "未经探活的端点变更不得生效"
            );
        }

        /// 引导能跨两跳：入口只认识 s2，s2 才认识 s3
        #[tokio::test]
        async fn discover_reaches_seeds_two_hops_away() {
            let s1 = spawn_seed(3478).await;
            let s2 = spawn_node().await;
            s2.pin_seeds(&[addr(&s1)]).await;
            s2.start_advertising(spec_of(&s2, 3479, FLAG_RELAY), 1)
                .await;
            assert!(wait_seed(&s1, s2.node_id(), 2000).await);

            let s3 = spawn_node().await;
            s3.pin_seeds(&[addr(&s2)]).await;
            s3.start_advertising(spec_of(&s3, 3480, FLAG_RELAY), 1)
                .await;
            assert!(wait_seed(&s2, s3.node_id(), 2000).await);
            assert!(
                !has_seed(&s1, s3.node_id()).await,
                "前提：入口 s1 并不认识 s3"
            );

            let client = spawn_node().await;
            assert_eq!(client.discover(&[addr(&s1)]).await, 3);
            for seed in [&s1, &s2, &s3] {
                assert!(has_seed(&client, seed.node_id()).await);
                // 探活（挑战响应）让每个种子都认识客户端：回证是 fire-and-forget，
                // 之后它们才能把 Forward 投递给它
                assert!(
                    wait_knows(seed, client.node_id(), 2000).await,
                    "探活后种子应通过回证认识客户端"
                );
            }
        }

        /// 防反射放大：应答永远不长于请求；不填充的请求一条广告也换不到
        #[tokio::test]
        async fn find_seeds_reply_never_exceeds_request_size() {
            let seed = spawn_seed(3478).await;
            for port in [3479u16, 3480, 3481] {
                let other = spawn_node().await;
                other.pin_seeds(&[addr(&seed)]).await;
                other.start_advertising(spec_of(&other, port, 0), 1).await;
                assert!(wait_seed(&seed, other.node_id(), 2000).await);
            }
            let known = 4; // 自己 + 3 个

            let asker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut buf = [0u8; 2048];
            for (txid, count) in [0usize, 1, 2, SEEDS_MAX].into_iter().enumerate() {
                let req = RpcPacket::find_seeds(
                    txid as u32 + 1,
                    FindSeedsBody::for_count([0x33; 32], count),
                )
                .encode();
                asker.send_to(&req, addr(&seed)).await.unwrap();
                let (n, _) =
                    tokio::time::timeout(Duration::from_secs(1), asker.recv_from(&mut buf))
                        .await
                        .expect("应有应答")
                        .unwrap();
                assert!(
                    n <= req.len(),
                    "count={count}: 应答 {n}B > 请求 {}B",
                    req.len()
                );
                let RpcBody::Seeds(body) = RpcPacket::decode(&buf[..n]).unwrap().body else {
                    panic!("期望 Seeds");
                };
                assert_eq!(body.adverts.len(), count.min(known));
            }
        }

        /// 失联的种子：连续三轮探活不应答才逐出（偏发丢包不踢人），并从地址簿遗忘
        #[tokio::test]
        async fn dead_seed_is_evicted_after_three_failed_probes() {
            // 把「将死」的种子起在独立的运行时里：关掉运行时 = 它的读循环停摆，不再应答任何报文
            let doomed_rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            let doomed = doomed_rt.spawn(spawn_seed(3478)).await.unwrap();
            let doomed_id = doomed.node_id();

            let client = spawn_node().await;
            assert_eq!(
                client.find_seeds(addr(&doomed), client.node_id()).await,
                Ok(1)
            );
            assert!(knows(&client, doomed_id).await);

            doomed_rt.shutdown_background();
            tokio::time::sleep(Duration::from_millis(300)).await;

            client.probe_known_seeds().await;
            client.probe_known_seeds().await;
            assert!(has_seed(&client, doomed_id).await, "两次失败还不逐出");
            client.probe_known_seeds().await;
            assert!(client.seeds().await.is_empty(), "连续三次失败即逐出");
            assert!(!knows(&client, doomed_id).await, "失联种子应从地址簿遗忘");
        }

        /// 健在的种子：探活轮只更新往返耗时，不动目录
        #[tokio::test]
        async fn live_seed_survives_probe_rounds() {
            let seed = spawn_seed(3478).await;
            let client = spawn_node().await;
            assert_eq!(client.discover(&[addr(&seed)]).await, 1);
            for _ in 0..4 {
                client.probe_known_seeds().await;
            }
            let seeds = client.seeds().await;
            assert_eq!(seeds.len(), 1);
            assert!(seeds[0].rtt_ms.is_some());
        }

        /// 入口端点起初没有宣告（老式种子 / 启动顺序问题），之后开始宣告：下一轮探活就把它收录
        #[tokio::test]
        async fn pinned_entry_is_adopted_once_it_starts_advertising() {
            let entry = spawn_node().await;
            let client = spawn_node().await;
            assert_eq!(
                client.discover(&[addr(&entry)]).await,
                0,
                "入口没有广告：目录为空"
            );
            client.probe_known_seeds().await;
            assert!(client.seeds().await.is_empty());

            entry.start_advertising(spec_of(&entry, 3478, 0), 1).await;
            client.probe_known_seeds().await;
            let seeds = client.seeds().await;
            assert_eq!(seeds.len(), 1);
            assert_eq!(seeds[0].node_id, entry.node_id());
            assert!(seeds[0].observer_addr().is_some());
            assert!(!seeds[0].relays());
        }

        /// 迭代查找能走出入口：入口 → a → b（入口不认识 b）
        #[tokio::test]
        async fn lookup_node_walks_beyond_the_entry() {
            let entry = spawn_node().await;
            let a = spawn_node().await;
            let b = spawn_node().await;
            a.ping(addr(&entry)).await.unwrap(); // 入口认识 a
            b.ping(addr(&a)).await.unwrap(); // a 认识 b；入口不认识 b
            assert!(!knows(&entry, b.node_id()).await);

            let client = spawn_node().await;
            let reached = client.lookup_node(b.node_id(), &[addr(&entry)]).await;
            let ids: Vec<NodeId> = reached.iter().map(|(id, _)| *id).collect();
            assert_eq!(
                ids.first(),
                Some(&b.node_id()),
                "结果按距离升序：目标本身排第一"
            );
            assert!(ids.contains(&entry.node_id()) && ids.contains(&a.node_id()));
            assert_eq!(ids.len(), 3, "不含自己，不重复");
            // 沿途每个节点都经 PING 验证并双向认识
            assert!(knows(&client, b.node_id()).await);
            assert!(knows(&b, client.node_id()).await);
        }

        /// 迭代查找对死候选与身份不符的候选有界、不中毒
        #[tokio::test]
        async fn lookup_node_tolerates_dead_entries() {
            let entry = spawn_node().await;
            let client = spawn_node().await;
            let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
            let reached = client
                .lookup_node(client.node_id(), &[dead, addr(&entry)])
                .await;
            assert_eq!(reached, vec![(entry.node_id(), addr(&entry))]);
            assert!(client.lookup_node(client.node_id(), &[]).await.is_empty());
        }

        /// 扩散：入口的种子目录里没有 x，但路由上够得着——沿 FIND_NODE 找到它，再拿到它的广告
        #[tokio::test]
        async fn spread_adopts_advertiser_missing_from_entry_directory() {
            let entry = spawn_seed(3478).await;
            let x = spawn_seed(3999).await; // 在宣告，但没有把广告推给任何人
            x.ping(addr(&entry)).await.unwrap(); // 只是普通地认识了一下入口
            assert!(!has_seed(&entry, x.node_id()).await);

            let client = spawn_node().await;
            assert_eq!(
                client.discover(&[addr(&entry)]).await,
                1,
                "引导只能学到入口自己"
            );
            let reached = client.spread(&[addr(&entry)]).await;
            assert!(reached >= 2, "扩散应触达入口与 x（实际 {reached}）");
            assert!(
                has_seed(&client, x.node_id()).await,
                "x 的广告应经扩散进入目录"
            );
        }
    }
}
