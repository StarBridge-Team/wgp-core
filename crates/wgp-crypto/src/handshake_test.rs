//! 端到端承诺-揭示交换测试（01 §1.2.2 全流程代码化自验证）。
//! 不依赖网络，纯逻辑验证：MITM 检测、共享密钥一致、全套会话密钥族派生。

#[cfg(test)]
mod tests {
    use crate::commit::{commit, verify, Commitment};
    use crate::derive::{derive_all, hb_auth, probe_auth};
    use crate::ka::{AnyAgreement, KeyAgreement};
    use rand_core::OsRng;
    use wgp_proto::consts::PROTO_VERSION;
    use wgp_proto::sig::{
        algo, sig_type, CommitBody, RevealBody, SigBody, SigPacket, SIG_MAGIC,
    };

    /// 模拟两端各自走完"承诺-揭示-X25519-agree"全流程
    fn run_handshake(peer_a: [u8; 16], peer_b: [u8; 16]) -> (Commitment, Commitment) {
        use crate::ka::X25519Agreement;
        let mut rng = OsRng;

        // ① 各生成临时密钥对
        let ka = X25519Agreement;
        let sk_a = ka.keygen(&mut rng);
        let sk_b = ka.keygen(&mut rng);
        let pk_a = ka.pubkey_raw(&sk_a);
        let pk_b = ka.pubkey_raw(&sk_b);

        // ② 各生成 32B nonce
        let mut nonce_a = [0u8; 32];
        let mut nonce_b = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut nonce_a);
        rand_core::RngCore::fill_bytes(&mut rng, &mut nonce_b);

        // ③ 互发承诺
        let commit_a = commit(&pk_a, &nonce_a);
        let commit_b = commit(&pk_b, &nonce_b);

        // ④ 经 DHT 互发承诺包
        let c_pkt_a = SigPacket::commit(
            CommitBody { peer_id: peer_a, commit: {
                let mut c16 = [0u8; 16];
                c16.copy_from_slice(&commit_a.0[..16]);
                c16
            }},
            algo::X25519,
            0,
        );
        let c_pkt_b = SigPacket::commit(
            CommitBody { peer_id: peer_b, commit: {
                let mut c16 = [0u8; 16];
                c16.copy_from_slice(&commit_b.0[..16]);
                c16
            }},
            algo::X25519,
            0,
        );
        let _bytes_a = c_pkt_a.encode();
        let _bytes_b = c_pkt_b.encode();

        // ⑤ 互发揭示
        let r_pkt_a = SigPacket::reveal(
            RevealBody { peer_id: peer_a, pubkey: pk_a.clone(), nonce: nonce_a },
            algo::X25519,
            0,
        );
        let r_pkt_b = SigPacket::reveal(
            RevealBody { peer_id: peer_b, pubkey: pk_b.clone(), nonce: nonce_b },
            algo::X25519,
            0,
        );

        // ⑥ 对端解码 + 验证
        let dec_a = SigPacket::decode(&r_pkt_b.encode()).unwrap();
        let dec_b = SigPacket::decode(&r_pkt_a.encode()).unwrap();
        let reveal_a = match dec_a.body {
            SigBody::Reveal(r) => r,
            _ => panic!("解码失败"),
        };
        let reveal_b = match dec_b.body {
            SigBody::Reveal(r) => r,
            _ => panic!("解码失败"),
        };
        let expect_a = commit(&reveal_a.pubkey, &reveal_a.nonce);
        let expect_b = commit(&reveal_b.pubkey, &reveal_b.nonce);
        assert!(verify(&commit_b, &reveal_a.pubkey, &reveal_a.nonce), "MITM 检测 A");
        assert!(verify(&commit_a, &reveal_b.pubkey, &reveal_b.nonce), "MITM 检测 B");

        // ⑦ ECDH 双方共享密钥必须一致
        let shared_a = ka.agree(&sk_a, &reveal_a.pubkey).expect("agree A");
        let shared_b = ka.agree(&sk_b, &reveal_b.pubkey).expect("agree B");
        assert_eq!(shared_a, shared_b, "共享密钥必须一致");

        // ⑧ 派生全套会话密钥族（两端输入相同 → 输出必须相同）
        let mut info = Vec::new();
        info.extend_from_slice(&pk_a);
        info.extend_from_slice(&pk_b);
        info.extend_from_slice(&reveal_a.nonce);
        info.extend_from_slice(&reveal_b.nonce);
        info.push(PROTO_VERSION);
        info.extend_from_slice(&SIG_MAGIC[..]);

        let secrets_a = derive_all(
            shared_a.as_slice().try_into().unwrap(),
            &info,
        );
        let secrets_b = derive_all(
            shared_b.as_slice().try_into().unwrap(),
            &info,
        );
        assert_eq!(secrets_a.session_key, secrets_b.session_key);
        assert_eq!(secrets_a.psk_identity, secrets_b.psk_identity);
        assert_eq!(secrets_a.probe_key, secrets_b.probe_key);
        assert_eq!(secrets_a.hb_key, secrets_b.hb_key);
        assert_eq!(secrets_a.escape_key, secrets_b.escape_key);

        // ⑨ 探针/心跳 HMAC 一致性（两端用同一 key 签名同 data 必须等）
        let data = b"punch-verify-data-v1";
        let at_a = probe_auth(&secrets_a.probe_key, data);
        let at_b = probe_auth(&secrets_b.probe_key, data);
        assert_eq!(at_a, at_b);
        let hb_a = hb_auth(&secrets_a.hb_key, data);
        let hb_b = hb_auth(&secrets_b.hb_key, data);
        assert_eq!(hb_a, hb_b);

        (expect_a, expect_b)
    }

    #[test]
    fn happy_path_two_peers() {
        let peer_a = [0x11u8; 16];
        let peer_b = [0x22u8; 16];
        let _ = run_handshake(peer_a, peer_b);
    }

    #[test]
    fn mitm_detected_on_commit_swap() {
        use rand_core::OsRng;
        use crate::ka::X25519Agreement;
        let mut rng = OsRng;
        let ka = X25519Agreement;
        let sk = ka.keygen(&mut rng);
        let pk = ka.pubkey_raw(&sk);
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut nonce);

        let original = commit(&pk, &nonce);
        // 攻击者：替换公钥（不知 nonce，强行重试会改变 nonce，承诺即变）
        let mut malicious_pk = pk.clone();
        malicious_pk[0] ^= 0x01;
        let mut malicious_nonce = nonce;
        malicious_nonce[0] ^= 0xAA;
        let attack = commit(&malicious_pk, &malicious_nonce);
        // 攻击者无法找到第二原像（SHA-256 抗性），承诺必然不同 → 检测成功
        assert_ne!(original.0, attack.0);
    }

    #[test]
    fn algo_mismatch_handled() {
        // 双方都仅支持 X25519 时，对端发 algo=0x02 Hybrid → 协商失败分支
        assert!(AnyAgreement::for_algo(0x02).is_none());
        assert!(AnyAgreement::for_algo(0xFF).is_none());
        // 工厂返回的具体协商器可直接用
        if let Some(crate::ka::AnyAgreement::X25519(ka)) = AnyAgreement::for_algo(algo::X25519) {
            let _ = ka.algo_id();
        } else {
            panic!("X25519 协商器应存在");
        }
    }

    #[test]
    fn sig_type_routing() {
        let c = SigPacket::commit(
            CommitBody { peer_id: [0; 16], commit: [0; 16] },
            algo::X25519,
            0,
        );
        let bytes = c.encode();
        assert_eq!(bytes[0..2], SIG_MAGIC);
        assert_eq!(bytes[2], sig_type::COMMIT);
    }
}