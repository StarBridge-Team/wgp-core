//! 探活身份证明（17 §11）：一次一密挑战响应。
//!
//! 解决的问题：PING/PONG 只能证明「这个地址上有人自称是这个 NodeId」——录下一条旧报文在别的地址上
//! 重放，就能把已知节点的地址簿条目指向攻击者。要证明「此刻持有私钥」，必须让对端对**本次专用的
//! 随机数**签名；要防「跨用途挪用」，签名要带域分隔前缀；要防「挪到别的事务里」，签名还要覆盖
//! 双方 NodeId 与 RPC 头部 txid。
//!
//! 本模块只做**密码学部分**（签发 / 校验一条证明），状态机在 [`crate::node`]：
//! - 谁发挑战谁学对方；应答方**不因收到挑战而学习**（否则伪造挑战即可毒化路由表）；
//! - 证明里带 `prover_nonce` 让应答方回证，1.5 RTT 双向认证（种子/存储节点靠这一点认识 NAT 后的客户端）。

use crate::id::{node_id_from_verifying, NodeId, NodeIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::CryptoRngCore;
use wgp_proto::consts::{AUTH_NONCE_LEN, AUTH_VERSION};
use wgp_proto::dht::{AuthChallengeBody, AuthProofBody, AuthRejectBody};

/// 生成一次性挑战 / 回证 nonce
pub fn fresh_nonce(rng: &mut impl CryptoRngCore) -> [u8; AUTH_NONCE_LEN] {
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// 身份绑定校验：`node_id == SHA256(pubkey)`。这是所有学习路径的前置闸门，
/// 也是「伪造 node_id 抢占路由位」在计算上不可行的原因。
pub fn bound_identity(node_id: [u8; 32], pubkey: [u8; 32]) -> Option<NodeId> {
    let vk = VerifyingKey::from_bytes(&pubkey).ok()?;
    let claimed = NodeId(node_id);
    (node_id_from_verifying(&vk) == claimed).then_some(claimed)
}

/// 校验挑战方的身份自洽（挑战本身不签名，但 verifier 的公钥必须绑定其 NodeId）
pub fn verify_challenge(challenge: &AuthChallengeBody) -> Option<NodeId> {
    if challenge.version != AUTH_VERSION {
        return None;
    }
    bound_identity(challenge.verifier_id, challenge.verifier_pubkey)
}

/// 构造一条挑战报文（发起方调用）
pub fn make_challenge(identity: &NodeIdentity, nonce: [u8; AUTH_NONCE_LEN]) -> AuthChallengeBody {
    AuthChallengeBody {
        verifier_id: identity.node_id().0,
        verifier_pubkey: identity.verifying_key().to_bytes(),
        nonce,
        version: AUTH_VERSION,
    }
}

/// 以 `identity` 的名义，对「证明给 `verifier`、挑战 nonce 为 `nonce_echo`、txid 为 `txid`」的一次
/// 询问签名，并可选地带上自己的挑战 nonce（`prover_nonce`，全 0 = 不要求回证）。
pub fn sign_proof(
    identity: &NodeIdentity,
    verifier: NodeId,
    nonce_echo: &[u8; AUTH_NONCE_LEN],
    prover_nonce: [u8; AUTH_NONCE_LEN],
    txid: u32,
) -> AuthProofBody {
    let mut proof = AuthProofBody {
        prover_id: identity.node_id().0,
        prover_pubkey: identity.verifying_key().to_bytes(),
        nonce_echo: *nonce_echo,
        prover_nonce,
        version: AUTH_VERSION,
        signature: [0u8; 64],
    };
    let msg = proof.signing_message(&verifier.0, txid);
    proof.signature = identity.sign(&msg).to_bytes();
    proof
}

/// 校验一条证明：版本 → 身份绑定 → 签名（`verify_strict` 拒掉非典范编码/小阶公钥）。
///
/// **不**在这里校验 nonce 与来源地址——那需要状态（本次挑战发给了谁、nonce 是否新鲜），
/// 属于 [`crate::node`] 的职责；把密码学校验与状态校验分开，便于各自单测。
pub fn verify_proof(proof: &AuthProofBody, verifier: NodeId, txid: u32) -> Option<NodeId> {
    if proof.version != AUTH_VERSION {
        return None;
    }
    let prover = bound_identity(proof.prover_id, proof.prover_pubkey)?;
    let vk = VerifyingKey::from_bytes(&proof.prover_pubkey).ok()?;
    let sig = Signature::from_bytes(&proof.signature);
    let msg = proof.signing_message(&verifier.0, txid);
    vk.verify_strict(&msg, &sig).ok()?;
    Some(prover)
}

/// 版本不支持时的拒绝报文
pub fn reject_unsupported_version() -> AuthRejectBody {
    AuthRejectBody {
        reason: wgp_proto::dht::auth_reject_reason::UNSUPPORTED_VERSION,
        supported_version: AUTH_VERSION,
    }
}

/// 拒绝原因 → 给调用方看的错误（`AUTH_REJECT` 的语义映射）
pub fn error_for_reject(reject: &AuthRejectBody) -> crate::node::RpcError {
    match reject.reason {
        wgp_proto::dht::auth_reject_reason::UNSUPPORTED_VERSION => {
            crate::node::RpcError::UnsupportedVersion
        }
        _ => crate::node::RpcError::Unverified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn ident(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32])
    }

    #[test]
    fn legitimate_proof_verifies() {
        let prover = ident(1);
        let verifier = ident(2);
        let nonce = [0x5A; AUTH_NONCE_LEN];
        let proof = sign_proof(&prover, verifier.node_id(), &nonce, [0x00; 16], 0x1234_5678);
        assert_eq!(
            verify_proof(&proof, verifier.node_id(), 0x1234_5678),
            Some(prover.node_id())
        );
    }

    #[test]
    fn forged_proof_is_rejected() {
        let prover = ident(1);
        let attacker = ident(3);
        let verifier = ident(2);
        let nonce = [0x5A; AUTH_NONCE_LEN];

        // 冒用别人的 node_id：拿自己的公钥填进去，绑定校验立刻失败
        let mut forged = sign_proof(&attacker, verifier.node_id(), &nonce, [0; 16], 7);
        forged.prover_id = prover.node_id().0;
        assert_eq!(verify_proof(&forged, verifier.node_id(), 7), None);

        // 冒用别人的公钥但用自己的密钥签名：绑定通过、验签失败
        let mut forged2 = sign_proof(&attacker, verifier.node_id(), &nonce, [0; 16], 7);
        forged2.prover_pubkey = prover.verifying_key().to_bytes();
        assert_eq!(verify_proof(&forged2, verifier.node_id(), 7), None);

        // 改 nonce：签名不再覆盖同一消息
        let mut tampered = sign_proof(&prover, verifier.node_id(), &nonce, [0; 16], 7);
        tampered.nonce_echo[0] ^= 0xFF;
        assert_eq!(verify_proof(&tampered, verifier.node_id(), 7), None);
    }

    #[test]
    fn proof_is_bound_to_verifier_and_txid() {
        let prover = ident(1);
        let verifier = ident(2);
        let other = ident(4);
        let nonce = [0x5A; AUTH_NONCE_LEN];
        let proof = sign_proof(&prover, verifier.node_id(), &nonce, [0; 16], 7);
        // 换验证方 / 换 txid / 换版本都不再有效
        assert_eq!(verify_proof(&proof, other.node_id(), 7), None);
        assert_eq!(verify_proof(&proof, verifier.node_id(), 8), None);
        let mut bumped = proof;
        bumped.version = AUTH_VERSION.wrapping_add(1);
        assert_eq!(verify_proof(&bumped, verifier.node_id(), 7), None);
    }

    #[test]
    fn challenge_requires_bound_identity_and_supported_version() {
        let mut rng = OsRng;
        let verifier = ident(2);
        let challenge = make_challenge(&verifier, fresh_nonce(&mut rng));
        assert_eq!(verify_challenge(&challenge), Some(verifier.node_id()));

        let mut spoof = challenge;
        spoof.verifier_id = ident(9).node_id().0;
        assert_eq!(verify_challenge(&spoof), None);

        let mut version = challenge;
        version.version = AUTH_VERSION + 1;
        assert_eq!(verify_challenge(&version), None);
    }

    #[test]
    fn fresh_nonce_differs_between_calls() {
        let mut rng = OsRng;
        let a = fresh_nonce(&mut rng);
        let b = fresh_nonce(&mut rng);
        assert_ne!(a, b, "挑战 nonce 必须每次不同，否则重放窗口重新打开");
        assert_ne!(a, [0u8; AUTH_NONCE_LEN]);
    }

    #[test]
    fn reject_maps_to_readable_error() {
        use crate::node::RpcError;
        let reject = reject_unsupported_version();
        assert_eq!(reject.reason, wgp_proto::dht::auth_reject_reason::UNSUPPORTED_VERSION);
        assert_eq!(reject.supported_version, AUTH_VERSION);
        assert_eq!(error_for_reject(&reject), RpcError::UnsupportedVersion);
        assert_eq!(
            error_for_reject(&AuthRejectBody {
                reason: wgp_proto::dht::auth_reject_reason::RATE_LIMITED,
                supported_version: 0,
            }),
            RpcError::Unverified
        );
    }
}
