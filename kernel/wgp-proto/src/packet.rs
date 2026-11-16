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

/// V1（从未上线：报文不带公钥，验签方必须从别的信道拿到广告主公钥）。线上一律用
/// [`SeedAdvertiseV2`]；此结构仅保留作对照。
///
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

// ============== 种子广告 V2（17 §5：自带公钥，可转述） ==============

/// 种子广告 V2（type=0x21，定长 123B）。报文自带广告主公钥，任何节点转述后都能独立验签——
/// 这是它能在 DHT 里互相交换的前提（V1 做不到）。
///
/// ```text
/// [0..2]    magic "WG"          [2]      type = 0x21
/// [3..7]    addr_v4             [7..9]   dht_port（非 0）
/// [9..11]   stun_port（0 = 不提供观察者）
/// [11..13]  tcp_port （0 = 不提供 TCP 信令）
/// [13]      priority            [14]     flags
/// [15..23]  epoch（u64 BE；同一广告主严格递增，接收端只认更大的——抗重放）
/// [23..27]  name_hash（SHA256(名字) 前 4B；未命名全 0。17 P2 名字锚定用，P0 不解释）
/// [27..59]  pubkey（ed25519；node_id = SHA256(pubkey)）
/// [59..123] signature = ed25519(SEED_ADV_DOMAIN ‖ [0..59])
/// ```
///
/// 签名覆盖签名之前的全部字节（含魔数与类型），并加域分隔前缀：节点的长期身份密钥还要签房间记录
/// 与报道请求，前缀保证这几类签名互不可挪用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedAdvertiseV2 {
    pub addr_v4: [u8; 4],
    pub dht_port: u16,
    pub stun_port: u16,
    pub tcp_port: u16,
    pub priority: u8,
    pub flags: u8,
    pub epoch: u64,
    pub name_hash: [u8; 4],
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}

pub mod seed_advertise_v2 {
    use super::SeedAdvertiseV2;
    use crate::consts::SEED_ADV_DOMAIN;

    pub const TYPE: u8 = 0x21;
    pub const LEN: usize = 123;
    /// 签名覆盖的报文前缀长度（含魔数与类型，到公钥为止）
    pub const SIGNED_LEN: usize = 59;
    /// 待签名消息长度 = 域分隔前缀 + 报文前缀
    pub const SIGNING_MESSAGE_LEN: usize = SEED_ADV_DOMAIN.len() + SIGNED_LEN;

    /// flags bit0：允许 Forward 中转（完整版节点）。贡献模式不置位——客户端据此得知
    /// 「这个种子能不能帮忙投递报道与协商消息」。其余位保留：发送置 0，接收忽略。
    pub const FLAG_RELAY: u8 = 0x01;

    /// flags bit1：支持挑战响应身份证明（17 §11）。老版本不置位；新版本恒置位。
    /// 客户端据此在探活之前就知道「这个种子能不能被采信」，也能区分「老版本」与「不可达」。
    pub const FLAG_AUTH_V1: u8 = 0x02;

    /// 编码整包（含 `adv.signature`；尚未签名时该字段可为全 0，见 [`signing_message`]）
    pub fn encode(adv: &SeedAdvertiseV2, out: &mut [u8; LEN]) {
        out[0..2].copy_from_slice(&super::SIG_MAGIC);
        out[2] = TYPE;
        out[3..7].copy_from_slice(&adv.addr_v4);
        out[7..9].copy_from_slice(&adv.dht_port.to_be_bytes());
        out[9..11].copy_from_slice(&adv.stun_port.to_be_bytes());
        out[11..13].copy_from_slice(&adv.tcp_port.to_be_bytes());
        out[13] = adv.priority;
        out[14] = adv.flags;
        out[15..23].copy_from_slice(&adv.epoch.to_be_bytes());
        out[23..27].copy_from_slice(&adv.name_hash);
        out[27..59].copy_from_slice(&adv.pubkey);
        out[59..123].copy_from_slice(&adv.signature);
    }

    /// 结构解码（不验签）：长度、魔数、类型不符，或 DHT 端口为 0，返回 None
    pub fn decode(buf: &[u8]) -> Option<SeedAdvertiseV2> {
        if buf.len() != LEN || buf[0..2] != super::SIG_MAGIC || buf[2] != TYPE {
            return None;
        }
        let dht_port = u16::from_be_bytes([buf[7], buf[8]]);
        if dht_port == 0 {
            return None;
        }
        let mut adv = SeedAdvertiseV2 {
            addr_v4: [0u8; 4],
            dht_port,
            stun_port: u16::from_be_bytes([buf[9], buf[10]]),
            tcp_port: u16::from_be_bytes([buf[11], buf[12]]),
            priority: buf[13],
            flags: buf[14],
            epoch: u64::from_be_bytes([
                buf[15], buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22],
            ]),
            name_hash: [0u8; 4],
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        adv.addr_v4.copy_from_slice(&buf[3..7]);
        adv.name_hash.copy_from_slice(&buf[23..27]);
        adv.pubkey.copy_from_slice(&buf[27..59]);
        adv.signature.copy_from_slice(&buf[59..123]);
        Some(adv)
    }

    /// 待签名 / 待验签消息：域分隔前缀 ‖ 报文前 59B。签名方与验签方都从报文字节取，
    /// 不存在「两边各自拼装字段」的歧义。
    pub fn signing_message(packet: &[u8; LEN]) -> [u8; SIGNING_MESSAGE_LEN] {
        let mut msg = [0u8; SIGNING_MESSAGE_LEN];
        msg[..SEED_ADV_DOMAIN.len()].copy_from_slice(SEED_ADV_DOMAIN);
        msg[SEED_ADV_DOMAIN.len()..].copy_from_slice(&packet[..SIGNED_LEN]);
        msg
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

    fn sample_advert_v2() -> SeedAdvertiseV2 {
        SeedAdvertiseV2 {
            addr_v4: [203, 0, 113, 7],
            dht_port: 11010,
            stun_port: 3478,
            tcp_port: 3481,
            priority: 5,
            flags: seed_advertise_v2::FLAG_RELAY,
            epoch: 0x0102_0304_0506_0708,
            name_hash: [0xA1, 0xA2, 0xA3, 0xA4],
            pubkey: [0x5C; 32],
            signature: [0x7E; 64],
        }
    }

    #[test]
    fn seed_advertise_v2_roundtrip_and_layout() {
        let adv = sample_advert_v2();
        let mut buf = [0u8; seed_advertise_v2::LEN];
        seed_advertise_v2::encode(&adv, &mut buf);
        assert_eq!(seed_advertise_v2::decode(&buf), Some(adv));
        assert_eq!(classify(&buf), Some(seed_advertise_v2::TYPE));
        // 布局锁定：字段偏移是线格式的一部分，改动即不兼容
        assert_eq!(&buf[3..7], &[203, 0, 113, 7]);
        assert_eq!(&buf[7..9], &11010u16.to_be_bytes());
        assert_eq!(&buf[9..11], &3478u16.to_be_bytes());
        assert_eq!(&buf[11..13], &3481u16.to_be_bytes());
        assert_eq!(buf[13], 5);
        assert_eq!(buf[14], seed_advertise_v2::FLAG_RELAY);
        assert_eq!(&buf[15..23], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&buf[27..59], &[0x5C; 32]);
        assert_eq!(&buf[59..], &[0x7E; 64]);
    }

    #[test]
    fn seed_advertise_v2_rejects_malformed() {
        let mut buf = [0u8; seed_advertise_v2::LEN];
        seed_advertise_v2::encode(&sample_advert_v2(), &mut buf);
        assert!(seed_advertise_v2::decode(&buf[..seed_advertise_v2::LEN - 1]).is_none());
        let mut longer = buf.to_vec();
        longer.push(0);
        assert!(seed_advertise_v2::decode(&longer).is_none());
        let mut v1_type = buf;
        v1_type[2] = seed_advertise::TYPE;
        assert!(seed_advertise_v2::decode(&v1_type).is_none(), "V1 类型号不得被当作 V2");
        let mut bad_magic = buf;
        bad_magic[1] ^= 0xFF;
        assert!(seed_advertise_v2::decode(&bad_magic).is_none());
        let mut no_port = buf;
        no_port[7] = 0;
        no_port[8] = 0;
        assert!(seed_advertise_v2::decode(&no_port).is_none(), "DHT 端口为 0 的广告无意义");
    }

    #[test]
    fn seed_advertise_v2_signing_message_covers_everything_but_signature() {
        let adv = sample_advert_v2();
        let mut buf = [0u8; seed_advertise_v2::LEN];
        seed_advertise_v2::encode(&adv, &mut buf);
        let base = seed_advertise_v2::signing_message(&buf);
        assert!(base.starts_with(crate::consts::SEED_ADV_DOMAIN));

        // 签名字段本身不在待签消息里
        let mut other_sig = buf;
        other_sig[seed_advertise_v2::LEN - 1] ^= 0xFF;
        assert_eq!(seed_advertise_v2::signing_message(&other_sig), base);

        // 签名之前的任何一个字节变化都会改变待签消息（含类型字节与公钥）
        for offset in 0..seed_advertise_v2::SIGNED_LEN {
            let mut changed = buf;
            changed[offset] ^= 0x01;
            assert_ne!(
                seed_advertise_v2::signing_message(&changed),
                base,
                "偏移 {offset} 未被签名覆盖"
            );
        }
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
