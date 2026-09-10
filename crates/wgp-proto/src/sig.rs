//! 信令包定长编解码（14 §11 协议版本化；00 §3 "禁止引入 serde/protobuf"）。
//! 全部手写零分配解析；BodyLen 上限 200B 防恶意膨胀。

use crate::consts::PROTO_VERSION;

/// 信令魔数 "WG"（与 03 §3.2.3 思路一致）
pub const SIG_MAGIC: [u8; 2] = [0x57, 0x47];

/// 包类型
pub mod sig_type {
    pub const COMMIT: u8 = 0x01;
    pub const REVEAL: u8 = 0x02;
    pub const COMMIT_ACK: u8 = 0x03;
    pub const ERROR: u8 = 0x04;
}

/// 算法标识（与 wgp_crypto::AnyAgreement 对齐）
pub mod algo {
    pub const X25519: u8 = 0x01;
    pub const HYBRID_PQ: u8 = 0x02; // 未来线
}

/// Flags 位
pub mod flag {
    /// 对端应在 3s 内 ACK，否则重发（应对 DHT 丢包）
    pub const REQUIRE_ACK: u8 = 0x01;
    /// 逃生通道能力位
    pub const CAP_ESCAPE: u8 = 0x02;
    /// LAN 组播能力位
    pub const CAP_LAN: u8 = 0x04;
}

pub const HEADER_LEN: usize = 8;
pub const BODY_MAX: usize = 200;
/// 完整包最大尺寸（含 header）
pub const PACKET_MAX: usize = HEADER_LEN + BODY_MAX;

// —— 包类型 ——————————————————————————————————————————————————————

/// 承诺包（33B body）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitBody {
    pub peer_id: [u8; 16],
    /// SHA256(pubkey||nonce) 截断 16B
    pub commit: [u8; 16],
}

impl CommitBody {
    pub const BODY_LEN: u8 = 48;

    pub fn encode(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[0..16].copy_from_slice(&self.peer_id);
        out[16..32].copy_from_slice(&self.commit);
        // 16B 保留位（未来算法标识扩展位，先置零）
        out
    }

    pub fn decode(buf: &[u8; 48]) -> Self {
        let mut peer_id = [0u8; 16];
        let mut commit = [0u8; 16];
        peer_id.copy_from_slice(&buf[0..16]);
        commit.copy_from_slice(&buf[16..32]);
        Self { peer_id, commit }
    }
}

/// 揭示包（X25519 模式 80B；Hybrid 模式长度由算法决定）
#[derive(Debug, Clone)]
pub struct RevealBody {
    pub peer_id: [u8; 16],
    pub pubkey: Vec<u8>, // X25519=32B；Hybrid=变长（由 algo 决定）
    pub nonce: [u8; 32],
}

impl RevealBody {
    pub const BODY_LEN_X25519: u8 = 80;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.pubkey.len() + 32);
        out.extend_from_slice(&self.peer_id);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.nonce);
        out
    }

    pub fn decode(buf: &[u8], expected_pubkey_len: usize) -> Option<Self> {
        if buf.len() != 16 + expected_pubkey_len + 32 {
            return None;
        }
        let mut peer_id = [0u8; 16];
        let mut nonce = [0u8; 32];
        peer_id.copy_from_slice(&buf[0..16]);
        nonce.copy_from_slice(&buf[16 + expected_pubkey_len..]);
        let pubkey = buf[16..16 + expected_pubkey_len].to_vec();
        Some(Self {
            peer_id,
            pubkey,
            nonce,
        })
    }
}

/// 错误包（≤200B 人类可读 + 1B 错误码）
#[derive(Debug, Clone)]
pub struct ErrorBody {
    pub code: u8,
    pub reason: Vec<u8>, // 限制 199B
}

pub mod err {
    pub const COMMIT_TIMEOUT: u8 = 0x01;
    pub const REVEAL_MISMATCH: u8 = 0x02; // 承诺不匹配 = MITM
    pub const ALGO_UNSUPPORTED: u8 = 0x03;
    pub const BAD_NONCE: u8 = 0x04;
    pub const PEER_BLACKLISTED: u8 = 0x05;
}

// —— 统一信封 ——————————————————————————————————————————————

/// 信令包头部（8B 定长）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigHeader {
    pub version: u8,
    pub kind: u8, // sig_type
    pub algo: u8,
    pub flags: u8,
    pub body_len: u8,
}

impl SigHeader {
    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        out[0..2].copy_from_slice(&SIG_MAGIC);
        out[2] = self.version;
        out[3] = self.kind;
        out[4] = self.algo;
        out[5] = self.flags;
        out[6] = self.body_len;
        out[7] = 0; // 保留
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        if buf[0..2] != SIG_MAGIC {
            return None;
        }
        let kind = buf[3];
        if kind != sig_type::COMMIT
            && kind != sig_type::REVEAL
            && kind != sig_type::COMMIT_ACK
            && kind != sig_type::ERROR
        {
            return None;
        }
        Some(Self {
            version: buf[2],
            kind,
            algo: buf[4],
            flags: buf[5],
            body_len: buf[6],
        })
    }
}

/// 完整信令包（用于 send/recv）
#[derive(Debug, Clone)]
pub struct SigPacket {
    pub header: SigHeader,
    pub body: SigBody,
}

#[derive(Debug, Clone)]
pub enum SigBody {
    Commit(CommitBody),
    Reveal(RevealBody),
    CommitAck,
    Error(ErrorBody),
}

impl SigPacket {
    /// 构造便捷方法
    pub fn commit(body: CommitBody, algo: u8, flags: u8) -> Self {
        Self {
            header: SigHeader {
                version: PROTO_VERSION,
                kind: sig_type::COMMIT,
                algo,
                flags,
                body_len: CommitBody::BODY_LEN,
            },
            body: SigBody::Commit(body),
        }
    }

    pub fn reveal(body: RevealBody, algo: u8, flags: u8) -> Self {
        let body_len = (16 + body.pubkey.len() + 32) as u8;
        Self {
            header: SigHeader {
                version: PROTO_VERSION,
                kind: sig_type::REVEAL,
                algo,
                flags,
                body_len,
            },
            body: SigBody::Reveal(body),
        }
    }

    pub fn commit_ack(algo: u8) -> Self {
        Self {
            header: SigHeader {
                version: PROTO_VERSION,
                kind: sig_type::COMMIT_ACK,
                algo,
                flags: 0,
                body_len: 0,
            },
            body: SigBody::CommitAck,
        }
    }

    pub fn error(code: u8, reason: impl Into<Vec<u8>>) -> Self {
        let mut reason = reason.into();
        reason.truncate(BODY_MAX - 1);
        Self {
            header: SigHeader {
                version: PROTO_VERSION,
                kind: sig_type::ERROR,
                algo: 0,
                flags: 0,
                body_len: (1 + reason.len()) as u8,
            },
            body: SigBody::Error(ErrorBody { code, reason }),
        }
    }

    /// 编码为完整包字节
    pub fn encode(&self) -> Vec<u8> {
        let body_bytes = match &self.body {
            SigBody::Commit(c) => c.encode().to_vec(),
            SigBody::Reveal(r) => r.encode(),
            SigBody::CommitAck => Vec::new(),
            SigBody::Error(e) => {
                let mut out = Vec::with_capacity(1 + e.reason.len());
                out.push(e.code);
                out.extend_from_slice(&e.reason);
                out
            }
        };
        let mut out = Vec::with_capacity(HEADER_LEN + body_bytes.len());
        let mut hdr = [0u8; HEADER_LEN];
        self.header.encode(&mut hdr);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&body_bytes);
        out
    }

    /// 解析入包；malformed 返 None
    pub fn decode(buf: &[u8]) -> Option<Self> {
        let header = SigHeader::decode(buf)?;
        if buf.len() != HEADER_LEN + header.body_len as usize {
            return None;
        }
        let body_buf = &buf[HEADER_LEN..];
        let body = match header.kind {
            sig_type::COMMIT => {
                if body_buf.len() != CommitBody::BODY_LEN as usize {
                    return None;
                }
                let mut b = [0u8; 48];
                b.copy_from_slice(body_buf);
                SigBody::Commit(CommitBody::decode(&b))
            }
            sig_type::REVEAL => {
                let pubkey_len = match header.algo {
                    algo::X25519 => 32,
                    // 未来线：Hybrid PQ 长度由算法决定；当前未实现
                    _ => return None,
                };
                SigBody::Reveal(RevealBody::decode(body_buf, pubkey_len)?)
            }
            sig_type::COMMIT_ACK => SigBody::CommitAck,
            sig_type::ERROR => {
                if body_buf.is_empty() {
                    return None;
                }
                let code = body_buf[0];
                let reason = body_buf[1..].to_vec();
                SigBody::Error(ErrorBody { code, reason })
            }
            _ => return None,
        };
        Some(Self { header, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = SigHeader {
            version: 1,
            kind: sig_type::COMMIT,
            algo: algo::X25519,
            flags: flag::REQUIRE_ACK,
            body_len: 48,
        };
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf);
        let h2 = SigHeader::decode(&buf).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn commit_packet_roundtrip() {
        let body = CommitBody {
            peer_id: [0xAB; 16],
            commit: [0xCD; 16],
        };
        let pkt = SigPacket::commit(body, algo::X25519, 0);
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 48);
        let pkt2 = SigPacket::decode(&bytes).unwrap();
        if let SigBody::Commit(c) = pkt2.body {
            assert_eq!(c, body);
        } else {
            panic!("expected Commit");
        }
    }

    #[test]
    fn reveal_packet_x25519_roundtrip() {
        let body = RevealBody {
            peer_id: [0x12; 16],
            pubkey: [0x99; 32].to_vec(),
            nonce: [0x33; 32],
        };
        let pkt = SigPacket::reveal(body.clone(), algo::X25519, 0);
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 80);
        let pkt2 = SigPacket::decode(&bytes).unwrap();
        if let SigBody::Reveal(r) = pkt2.body {
            assert_eq!(r.peer_id, body.peer_id);
            assert_eq!(r.nonce, body.nonce);
            assert_eq!(r.pubkey, body.pubkey);
        } else {
            panic!("expected Reveal");
        }
    }

    #[test]
    fn reject_bad_magic() {
        let bytes = vec![0x00, 0x00, 0x01, sig_type::COMMIT, 0x01, 0x00, 48, 0x00];
        assert!(SigHeader::decode(&bytes).is_none());
    }

    #[test]
    fn reject_truncated() {
        let bytes = vec![0x57, 0x47, 0x01, sig_type::COMMIT, 0x01, 0x00, 48];
        assert!(SigHeader::decode(&bytes).is_none());
    }
}