//! STUN 最小子集（RFC 8489）：Binding + XOR-MAPPED-ADDRESS + 观察者扩展属性。
//! 客户端/服务端同源（07 §3：一套编解码，两级能力）。

use crate::consts::STUN_PORT;

/// RFC 8489 magic cookie
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// 消息类型
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;

/// 标准属性
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

/// 观察者协议扩展属性（07 §3，0x80F0-0x80F2 未注册区）
pub mod wgp_attr {
    /// (4B PeerId | 8B Nonce | 8B Timestamp | 4B Flags)
    pub const WGP_PEER: u16 = 0x80F0;
    /// (2B Proto | 2B MTU | 4B RTT 预算提示)
    pub const WGP_LINK: u16 = 0x80F1;
    /// (打洞协调参数：对端 IP:Port、T_offset、窗口参数)
    pub const WGP_PUNCH: u16 = 0x80F2;
}

/// STUN 报文头（20 字节，大端）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunHeader {
    pub msg_type: u16,
    pub len: u16,
    pub cookie: u32,
    pub tx_id: [u8; 12],
}

impl StunHeader {
    /// 编码为 20 字节头（手写定长，无堆分配）
    pub fn encode(&self, out: &mut [u8; 20]) {
        out[0..2].copy_from_slice(&self.msg_type.to_be_bytes());
        out[2..4].copy_from_slice(&self.len.to_be_bytes());
        out[4..8].copy_from_slice(&self.cookie.to_be_bytes());
        out[8..20].copy_from_slice(&self.tx_id);
    }

    /// 从字节解码；cookie 不匹配直接拒绝（快速过滤非法包）
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 20 {
            return None;
        }
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC_COOKIE {
            return None;
        }
        let mut tx_id = [0u8; 12];
        tx_id.copy_from_slice(&buf[8..20]);
        Some(Self {
            msg_type: u16::from_be_bytes([buf[0], buf[1]]),
            len: u16::from_be_bytes([buf[2], buf[3]]),
            cookie,
            tx_id,
        })
    }

    pub fn is_binding_request(&self) -> bool {
        self.msg_type == BINDING_REQUEST
    }
}

/// 一次"绑定探测"的抽象——步长学习（3 连测）、NAT 判定（双异 IP）、
/// UDP 出站预判、观察者报告全部经由本类型（00 §5 / 15 Phase 0、4）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingProbe {
    pub tx_id: [u8; 12],
    /// 目标观察者地址（含端口，通常 STUN_PORT）
    pub observer: (std::net::IpAddr, u16),
}

impl BindingProbe {
    pub fn new(tx_id: [u8; 12], observer_ip: std::net::IpAddr, port: Option<u16>) -> Self {
        Self {
            tx_id,
            observer: (observer_ip, port.unwrap_or(STUN_PORT)),
        }
    }
}

// —— 属性编解码（RFC 8489 子集） ——————————————————————————

/// 观察者扩展属性 WGP-PEER 载荷（24B）：
/// 4B PeerId 短前缀 | 8B Nonce | 8B Timestamp | 4B Flags
/// （07 §3；观察者原样回显，客户端据 Nonce 关联请求并测量往返）
pub const WGP_PEER_PAYLOAD_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WgpPeerAttr {
    pub peer_prefix: [u8; 4],
    pub nonce: [u8; 8],
    pub timestamp: [u8; 8],
    pub flags: [u8; 4],
}

impl WgpPeerAttr {
    pub fn encode(&self, out: &mut [u8; WGP_PEER_PAYLOAD_LEN]) {
        out[0..4].copy_from_slice(&self.peer_prefix);
        out[4..12].copy_from_slice(&self.nonce);
        out[12..20].copy_from_slice(&self.timestamp);
        out[20..24].copy_from_slice(&self.flags);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != WGP_PEER_PAYLOAD_LEN {
            return None;
        }
        let mut peer_prefix = [0u8; 4];
        let mut nonce = [0u8; 8];
        let mut timestamp = [0u8; 8];
        let mut flags = [0u8; 4];
        peer_prefix.copy_from_slice(&buf[0..4]);
        nonce.copy_from_slice(&buf[4..12]);
        timestamp.copy_from_slice(&buf[12..20]);
        flags.copy_from_slice(&buf[20..24]);
        Some(Self {
            peer_prefix,
            nonce,
            timestamp,
            flags,
        })
    }
}

/// 编码一个 STUN 属性（type 2B + len 2B + value）
pub fn encode_attr(attr_type: u16, value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    // 属性 4B 对齐（填充 0）
    let pad = (4 - value.len() % 4) % 4;
    out.extend_from_slice(&vec![0u8; pad]);
}

/// 解码属性序列；返回 (type, value)。Bogus 属性直接终止（RFC 8489 合规）
pub fn decode_attrs(buf: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        if i + 4 + len > buf.len() {
            return None;
        }
        out.push((attr_type, buf[i + 4..i + 4 + len].to_vec()));
        i += 4 + len + (4 - len % 4) % 4;
    }
    if i != buf.len() {
        return None;
    }
    Some(out)
}

/// 编码 XOR-MAPPED-ADDRESS 的 value（RFC 8489：reserved(1) | family(1) | xport(2) | xaddr(4)）
pub fn xor_mapped_value(ipv4: [u8; 4], port: u16) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = 0x00;
    out[1] = 0x01; // IPv4
    let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
    out[2..4].copy_from_slice(&xport.to_be_bytes());
    for i in 0..4 {
        out[4 + i] = ipv4[i] ^ (MAGIC_COOKIE >> (24 - i * 8)) as u8;
    }
    out
}

/// 解码 XOR-MAPPED-ADDRESS value → (ipv4, port)
pub fn decode_xor_mapped(value: &[u8]) -> Option<([u8; 4], u16)> {
    if value.len() != 8 || value[1] != 0x01 {
        return None;
    }
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
    let mut ipv4 = [0u8; 4];
    for i in 0..4 {
        ipv4[i] = value[4 + i] ^ (MAGIC_COOKIE >> (24 - i * 8)) as u8;
    }
    Some((ipv4, port))
}

/// 构造 Binding Request（客户端侧：可选携带 WGP-PEER 扩展，观察者回显）
pub fn binding_request(tx_id: &[u8; 12], echo_peer: Option<&WgpPeerAttr>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // len 后补
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(tx_id);
    if let Some(peer) = echo_peer {
        let mut payload = [0u8; WGP_PEER_PAYLOAD_LEN];
        peer.encode(&mut payload);
        encode_attr(wgp_attr::WGP_PEER, &payload, &mut out);
    }
    let body_len = (out.len() - 20) as u16;
    out[2..4].copy_from_slice(&body_len.to_be_bytes());
    out
}

/// 构造 Binding Success Response：响应头 + XOR-MAPPED-ADDRESS + 回显 WGP-PEER（若有）
pub fn binding_response(
    req_tx_id: &[u8; 12],
    src_ipv4: [u8; 4],
    src_port: u16,
    echo_peer: Option<&WgpPeerAttr>,
) -> Vec<u8> {
    let mut out = Vec::new();
    // 头：msg_type=BINDING_RESPONSE, len 后补
    out.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(req_tx_id);

    let mapped = xor_mapped_value(src_ipv4, src_port);
    encode_attr(ATTR_XOR_MAPPED_ADDRESS, &mapped, &mut out);
    if let Some(peer) = echo_peer {
        let mut payload = [0u8; WGP_PEER_PAYLOAD_LEN];
        peer.encode(&mut payload);
        encode_attr(wgp_attr::WGP_PEER, &payload, &mut out);
    }

    let body_len = (out.len() - 20) as u16;
    out[2..4].copy_from_slice(&body_len.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mapped_roundtrip() {
        let (ip, port) = ([203, 0, 113, 9], 41107);
        let value = xor_mapped_value(ip, port);
        let (d_ip, d_port) = decode_xor_mapped(&value).unwrap();
        assert_eq!(d_ip, ip);
        assert_eq!(d_port, port);
        // XOR 后的值不得等于明文（防中间盒识别）
        assert_ne!(&value[4..8], &ip);
    }

    #[test]
    fn wgp_peer_attr_roundtrip() {
        let attr = WgpPeerAttr {
            peer_prefix: [1, 2, 3, 4],
            nonce: [9; 8],
            timestamp: [7; 8],
            flags: [0, 0, 0, 1],
        };
        let mut buf = [0u8; WGP_PEER_PAYLOAD_LEN];
        attr.encode(&mut buf);
        let dec = WgpPeerAttr::decode(&buf).unwrap();
        assert_eq!(dec, attr);
    }

    #[test]
    fn binding_response_parses_back() {
        let txid = [0x5A; 12];
        let echo = WgpPeerAttr {
            peer_prefix: [9, 9, 9, 9],
            nonce: [1; 8],
            timestamp: [2; 8],
            flags: [0; 4],
        };
        let resp = binding_response(&txid, [127, 0, 0, 1], 4567, Some(&echo));

        // 解析响应头
        let header = StunHeader::decode(&resp).unwrap();
        assert_eq!(header.msg_type, BINDING_RESPONSE);
        assert_eq!(header.tx_id, txid);

        // 解析属性：XOR-MAPPED 还原 + WGP-PEER 回显
        let attrs = decode_attrs(&resp[20..]).unwrap();
        let mut mapped = None;
        let mut echoed = None;
        for (t, v) in attrs {
            match t {
                ATTR_XOR_MAPPED_ADDRESS => mapped = Some(decode_xor_mapped(&v).unwrap()),
                wgp_attr::WGP_PEER => echoed = Some(WgpPeerAttr::decode(&v).unwrap()),
                _ => {}
            }
        }
        assert_eq!(mapped, Some(([127, 0, 0, 1], 4567)));
        assert_eq!(echoed, Some(echo));
    }

    #[test]
    fn attr_padding_handled() {
        let mut out = Vec::new();
        // 5B value → pad 到 8B（len 字段仍写真实 5）
        encode_attr(0x1234, &[1, 2, 3, 4, 5], &mut out);
        assert_eq!(out.len(), 12); // 4 头 + 5 值 + 3 填充？ 错误：5%4=1 pad=3 → 4+5+3=12 ✓
        let attrs = decode_attrs(&out).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, 0x1234);
        assert_eq!(attrs[0].1, vec![1, 2, 3, 4, 5]);
    }
}