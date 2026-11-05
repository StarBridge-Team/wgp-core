//! 探针组帧/验签共用逻辑（UDP/TCP 双载体复用）。
//! 帧格式沿用 packet::probe 31B 定长：UDP 上按包、TCP 上按流首帧。

use wgp_crypto::derive::probe_auth;
use wgp_proto::packet::{probe, Probe};

/// 进程级单调毫秒锚点（禁止读系统时钟，03 §3.3.2 硬约束）。
/// 绝对网络时间由引擎侧 net_time_anchor 二次换算。
pub fn now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    let anchor = *ANCHOR.get_or_init(Instant::now);
    Instant::now().duration_since(anchor).as_millis() as u64
}

/// 组一枚验签探针（31B；nonce 自增由调用方维护）
pub fn craft_probe(
    probe_key: &[u8; 32],
    session_tag: [u8; 4],
    nonce: u32,
    timestamp_ms: u64,
) -> [u8; probe::LEN] {
    let p = Probe {
        session_tag,
        nonce: nonce.to_be_bytes(),
        timestamp: timestamp_ms.to_be_bytes(),
        auth_tag: [0u8; 12],
    };
    let mut buf = [0u8; probe::LEN];
    probe::encode(&p, &mut buf);
    let tag = probe_auth(probe_key, &buf[..probe::AUTH_OFFSET]);
    buf[probe::AUTH_OFFSET..].copy_from_slice(&tag);
    buf
}

/// 验签（长度/魔数/类型 + HMAC）——伪造/错密钥静默拒绝
pub fn verify_probe(probe_key: &[u8; 32], buf: &[u8]) -> Option<Probe> {
    let p = probe::decode(buf)?;
    let recomputed = probe_auth(probe_key, &buf[..probe::AUTH_OFFSET]);
    if recomputed != p.auth_tag {
        return None;
    }
    Some(p)
}