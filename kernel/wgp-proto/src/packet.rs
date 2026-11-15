//! 打洞与 DHT 报文（与 sig:: 信令包并列；用单一字节 type 区分场景）。
//! 纪律（00 §3）：定长二进制 + 手写编解码；禁止引入 serde/protobuf。

use crate::sig::SIG_MAGIC;

// ============== 探针（03 §3.5.5） ==============

/// 探针包（31B）：
///   magic(2) | type=0x10 | session_tag(4) | nonce(4) | timestamp(8) | auth_tag(12)
///
/// AuthTag = HMAC-SHA256(punch_key, 前 19B) 截断 12B
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub session_tag: [u8; 4],
    pub nonce: [u8; 4],
    pub timestamp: [u8; 8],
    pub auth_tag: [u8; 12],
}

pub mod probe {
    use super::Probe;
    pub const TYPE: u8 = 0x10;
    pub const LEN: usize = 31;
    pub const AUTH_OFFSET: usize = 19;
    pub const AUTH_LEN: usize = 12;

    pub fn encode(p: &Probe, out: &mut [u8; LEN]) {
        out[0..2].copy_from_slice(&super::SIG_MAGIC);
        out[2] = TYPE;
        out[3..7].copy_from_slice(&p.session_tag);
        out[7..11].copy_from_slice(&p.nonce);
        out[11..19].copy_from_slice(&p.timestamp);
        out[19..31].copy_from_slice(&p.auth_tag);
    }

    pub fn decode(buf: &[u8]) -> Option<Probe> {
        if buf.len() != LEN {
            return None;
        }
        if &buf[0..2] != &super::SIG_MAGIC {
            return None;
        }
        if buf[2] != TYPE {
            return None;
        }
        let mut p = Probe {
            session_tag: [0u8; 4],
            nonce: [0u8; 4],
            timestamp: [0u8; 8],
            auth_tag: [0u8; 12],
        };
        p.session_tag.copy_from_slice(&buf[3..7]);
        p.nonce.copy_from_slice(&buf[7..11]);
        p.timestamp.copy_from_slice(&buf[11..19]);
        p.auth_tag.copy_from_slice(&buf[19..31]);
        Some(p)
    }
}

// ============== 心跳（03 §3.7.4） ==============

/// 基础 19B + 可选步长扩展 4B
pub mod heartbeat {
    pub const TYPE: u8 = 0x11;
    pub const LEN_BASE: usize = 19;
    pub const LEN_EXT: usize = 23;
    pub const AUTH_LEN: usize = 12;

    pub fn encode_base(seq: u32, auth_tag: [u8; 12], out: &mut [u8; LEN_BASE]) {
        out[0..2].copy_from_slice(&super::SIG_MAGIC);
        out[2] = TYPE;
        out[3..7].copy_from_slice(&seq.to_be_bytes());
        out[7..19].copy_from_slice(&auth_tag);
    }

    pub fn encode_ext(
        seq: u32,
        auth_tag: [u8; 12],
        cur_port: u16,
        prev_port: u16,
        out: &mut [u8; LEN_EXT],
    ) {
        out[0..2].copy_from_slice(&super::SIG_MAGIC);
        out[2] = TYPE;
        out[3..7].copy_from_slice(&seq.to_be_bytes());
        out[7..19].copy_from_slice(&auth_tag);
        out[19..21].copy_from_slice(&cur_port.to_be_bytes());
        out[21..23].copy_from_slice(&prev_port.to_be_bytes());
    }
}

// ============== 种子广告（07 §5 DHT 内交换） ==============

/// 90B：
///   magic(2) | type=0x20 | addr_v4(4) | dht_port(2) | stun_port(2) |
///   priority(1) | flags(1) | reserved(14) | signature(64)
#[derive(Debug, Clone)]
pub struct SeedAdvertise {
    pub addr_v4: [u8; 4],
    pub dht_port: u16,
    pub stun_port: u16,
    pub priority: u8,
    pub flags: u8,
    pub signature: [u8; 64],
}

pub mod seed_advertise {
    use super::SeedAdvertise;
    pub const TYPE: u8 = 0x20;
    pub const SIGNED_LEN: usize = 4 + 2 + 2 + 1 + 1;
    pub const LEN: usize = 2 + 1 + SIGNED_LEN + 14 + 64;

    pub fn encode_signed(
        addr_v4: [u8; 4],
        dht_port: u16,
        stun_port: u16,
        priority: u8,
        flags: u8,
        signature: [u8; 64],
        out: &mut [u8; LEN],
    ) {
        out[0..2].copy_from_slice(&super::SIG_MAGIC);
        out[2] = TYPE;
        out[3..7].copy_from_slice(&addr_v4);
        out[7..9].copy_from_slice(&dht_port.to_be_bytes());
        out[9..11].copy_from_slice(&stun_port.to_be_bytes());
        out[11] = priority;
        out[12] = flags;
        for i in 0..14 {
            out[13 + i] = 0;
        }
        out[27..91].copy_from_slice(&signature);
    }

    /// 提取待签名字段（供 ed25519-dalek 验证签名）
    pub fn signed_payload(buf: &[u8]) -> Option<&[u8]> {
        if buf.len() != LEN {
            return None;
        }
        if &buf[0..2] != &super::SIG_MAGIC {
            return None;
        }
        if buf[2] != TYPE {
            return None;
        }
        Some(&buf[3..3 + SIGNED_LEN])
    }

    pub fn extract(buf: &[u8]) -> Option<SeedAdvertise> {
        let payload = signed_payload(buf)?;
        let mut addr_v4 = [0u8; 4];
        let mut sig = [0u8; 64];
        addr_v4.copy_from_slice(&buf[3..7]);
        let dht_port = u16::from_be_bytes([buf[7], buf[8]]);
        let stun_port = u16::from_be_bytes([buf[9], buf[10]]);
        let priority = buf[11];
        let flags = buf[12];
        sig.copy_from_slice(&buf[27..91]);
        let _ = payload;
        Some(SeedAdvertise {
            addr_v4,
            dht_port,
            stun_port,
            priority,
            flags,
            signature: sig,
        })
    }

    /// 构造待签名载荷（与 encode/extract 的字节布局严格一致：
    /// addr_v4[0..4] || dht_port[4..6] || stun_port[6..8] || priority[8] || flags[9]）
    pub fn payload_for_sign(
        addr_v4: [u8; 4],
        dht_port: u16,
        stun_port: u16,
        priority: u8,
        flags: u8,
    ) -> [u8; SIGNED_LEN] {
        let mut out = [0u8; SIGNED_LEN];
        out[0..4].copy_from_slice(&addr_v4);
        out[4..6].copy_from_slice(&dht_port.to_be_bytes());
        out[6..8].copy_from_slice(&stun_port.to_be_bytes());
        out[8] = priority;
        out[9] = flags;
        out
    }
}

// ============== 数据面隧道报文（外围 bridge/wgp-port） ==============

/// 数据面隧道报文的外层头部（12B，明文，整体作 AEAD 的 AAD）：
///   magic(2) | type=0x40 | flags(1) | counter(8, BE)
///
/// 内核只登记类型号与外层头部布局——打洞成功后保活探针（0x10）与业务数据共用同一
/// UDP socket，收包侧靠 [`classify`] 的类型字节分流；头部之后的密文及其帧语义属于外围
/// 数据面（R1：内核不碰业务数据）。
/// counter 同时是 AEAD nonce 的低 8 字节：同一密钥下严格递增、永不复用。
pub mod tunnel {
    pub const TYPE: u8 = 0x40;
    pub const HEADER_LEN: usize = 12;

    pub fn encode_header(flags: u8, counter: u64, out: &mut [u8; HEADER_LEN]) {
        out[0..2].copy_from_slice(&super::SIG_MAGIC);
        out[2] = TYPE;
        out[3] = flags;
        out[4..12].copy_from_slice(&counter.to_be_bytes());
    }

    /// 解出 (flags, counter)；长度不足、魔数或类型不符返回 None
    pub fn decode_header(buf: &[u8]) -> Option<(u8, u64)> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        if buf[0..2] != super::SIG_MAGIC || buf[2] != TYPE {
            return None;
        }
        let counter = u64::from_be_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        Some((buf[3], counter))
    }
}

/// 任意数据面报文的统一判定入口（用于 UDP 接收分流）
pub fn classify(buf: &[u8]) -> Option<u8> {
    if buf.len() < 3 {
        return None;
    }
    if buf[0..2] != SIG_MAGIC {
        return None;
    }
    Some(buf[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_roundtrip() {
        let p = Probe {
            session_tag: [0xAA; 4],
            nonce: [0xBB; 4],
            timestamp: [0xCC; 8],
            auth_tag: [0xDD; 12],
        };
        let mut buf = [0u8; probe::LEN];
        probe::encode(&p, &mut buf);
        let p2 = probe::decode(&buf).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn heartbeat_base_len() {
        let mut buf = [0u8; heartbeat::LEN_BASE];
        heartbeat::encode_base(0x01020304, [0xEE; 12], &mut buf);
        assert_eq!(buf.len(), heartbeat::LEN_BASE);
    }

    #[test]
    fn seed_advertise_payload_isolation() {
        let payload = seed_advertise::payload_for_sign([1, 2, 3, 4], 3841, 3478, 0x05, 0x01);
        assert_eq!(payload.len(), seed_advertise::SIGNED_LEN);
    }

    #[test]
    fn tunnel_header_roundtrip_and_classify() {
        let mut hdr = [0u8; tunnel::HEADER_LEN];
        tunnel::encode_header(0x03, 0x0102_0304_0506_0708, &mut hdr);
        assert_eq!(tunnel::decode_header(&hdr), Some((0x03, 0x0102_0304_0506_0708)));
        // 分流：隧道报文与探针共用魔数、靠类型字节区分
        assert_eq!(classify(&hdr), Some(tunnel::TYPE));
        let mut probe_buf = [0u8; probe::LEN];
        probe::encode(
            &Probe {
                session_tag: [0; 4],
                nonce: [0; 4],
                timestamp: [0; 8],
                auth_tag: [0; 12],
            },
            &mut probe_buf,
        );
        assert_eq!(classify(&probe_buf), Some(probe::TYPE));
        assert_ne!(probe::TYPE, tunnel::TYPE);
    }

    #[test]
    fn tunnel_header_rejects_short_and_foreign() {
        let mut hdr = [0u8; tunnel::HEADER_LEN];
        tunnel::encode_header(0, 7, &mut hdr);
        assert!(tunnel::decode_header(&hdr[..tunnel::HEADER_LEN - 1]).is_none());
        let mut wrong_type = hdr;
        wrong_type[2] = probe::TYPE;
        assert!(tunnel::decode_header(&wrong_type).is_none());
        let mut wrong_magic = hdr;
        wrong_magic[0] ^= 0xFF;
        assert!(tunnel::decode_header(&wrong_magic).is_none());
    }
}
