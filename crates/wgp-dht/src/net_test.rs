//! DhtNode 网络层集成测试（loopback 三节点拓扑：A、B、种子 S）

#[cfg(test)]
mod tests {
    use crate::id::NodeIdentity;
    use crate::node::DhtNode;
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use wgp_crypto::commit::commit;
    use wgp_crypto::ka::X25519Agreement;
    use wgp_crypto::ka::KeyAgreement;
    use wgp_proto::sig::{algo, sig_type, CommitBody, RevealBody, SigBody, SigPacket};

    async fn spawn_node() -> Arc<DhtNode> {
        let mut rng = OsRng;
        let id = NodeIdentity::generate(&mut rng);
        DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
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

        // 双向学习：A 认识 B（pong），B 认识 A（ping）
        assert!(a.known_nodes().await.iter().any(|(id, _)| *id == b.node_id()));
        assert!(b.known_nodes().await.iter().any(|(id, _)| *id == a.node_id()));
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
            CommitBody { peer_id: peer_a, commit: commit16 },
            algo::X25519,
            0,
        );
        a.forward_to(addr(&seed), b.node_id(), commit_pkt.encode())
            .await
            .unwrap();

        // ② 揭示包经种子投递（透明载荷含 32B 公钥 + 32B nonce）
        let reveal_pkt = SigPacket::reveal(
            RevealBody { peer_id: peer_a, pubkey: pk.clone(), nonce },
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
        assert_eq!(&digest[..16], &their_commit16[..], "承诺-揭示经转发后验签一致");

        let _ = (sig_type::COMMIT, peer_b);
    }
}