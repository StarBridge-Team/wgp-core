//! DHT RPC 报文（Kademlia 变种，07 文档网络层格式）。
//! 头（7B）：magic(2)="WG" | type(1) | txid(4B)。
//! 全部手写编解码；Neighbors 上限 K=20。

use crate::sig::SIG_MAGIC;

pub const RPC_HEADER_LEN: usize = 7;

pub mod rpc_type {
    pub const PING: u8 = 0x30;
    pub const PONG: u8 = 0x31;
    pub const FIND_NODE: u8 = 0x32;
    pub const NEIGHBORS: u8 = 0x33;
    /// 致某 NodeId 的投递（承诺-揭示/打洞参数/协调消息；不可信转发语义）
    pub const FORWARD: u8 = 0x34;
    /// 键值存储（房间记录/打洞会话宿主，07 §4 K=1 简化）
    pub const STORE: u8 = 0x35;
    pub const STORED_ACK: u8 = 0x36;
    pub const FIND_VALUE: u8 = 0x37;
    pub const VALUE: u8 = 0x38;
}

/// Kademlia 常量
pub const K: usize = 20;

/// 存储值上限（房间记录 4 成员 ≈ 300B；1KB 足够 v1）
pub const STORE_VALUE_MAX: usize = 1024;

/// 节点地址条目（NodeId 32B + IPv4 4B + port 2B = 38B）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEntry {
    pub id: [u8; 32],
    pub ipv4: [u8; 4],
    pub port: u16,
}

impl NodeEntry {
    pub const LEN: usize = 38;

    pub fn encode(&self, out: &mut [u8; Self::LEN]) {
        out[0..32].copy_from_slice(&self.id);
        out[32..36].copy_from_slice(&self.ipv4);
        out[36..38].copy_from_slice(&self.port.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LEN {
            return None;
        }
        let mut id = [0u8; 32];
        let mut ipv4 = [0u8; 4];
        id.copy_from_slice(&buf[0..32]);
        ipv4.copy_from_slice(&buf[32..36]);
        Some(Self {
            id,
            ipv4,
            port: u16::from_be_bytes([buf[36], buf[37]]),
        })
    }
}

// —— 具体报文 ————————————————————————————————

/// Ping / Pong：携带发送方 NodeId + 长期公钥（身份发布）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingBody {
    pub node_id: [u8; 32],
    pub pubkey: [u8; 32],
}

impl PingBody {
    pub const BODY_LEN: usize = 64;

    pub fn encode(&self, out: &mut [u8; Self::BODY_LEN]) {
        out[0..32].copy_from_slice(&self.node_id);
        out[32..64].copy_from_slice(&self.pubkey);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::BODY_LEN {
            return None;
        }
        let mut node_id = [0u8; 32];
        let mut pubkey = [0u8; 32];
        node_id.copy_from_slice(&buf[0..32]);
        pubkey.copy_from_slice(&buf[32..64]);
        Some(Self { node_id, pubkey })
    }
}

/// FindNode：请求目标邻近节点
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindNodeBody {
    pub target: [u8; 32],
}

impl FindNodeBody {
    pub const BODY_LEN: usize = 32;

    pub fn encode(&self, out: &mut [u8; Self::BODY_LEN]) {
        out.copy_from_slice(&self.target);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::BODY_LEN {
            return None;
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(buf);
        Some(Self { target })
    }
}

/// Neighbors：count(1B) + count×NodeEntry
#[derive(Debug, Clone)]
pub struct NeighborsBody {
    pub nodes: Vec<NodeEntry>,
}

impl NeighborsBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.nodes.len() * NodeEntry::LEN);
        out.push(self.nodes.len() as u8);
        for n in &self.nodes {
            let mut e = [0u8; NodeEntry::LEN];
            n.encode(&mut e);
            out.extend_from_slice(&e);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        let count = buf[0] as usize;
        if count > K || buf.len() != 1 + count * NodeEntry::LEN {
            return None;
        }
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            let entry = NodeEntry::decode(&buf[1 + i * NodeEntry::LEN..1 + (i + 1) * NodeEntry::LEN])?;
            nodes.push(entry);
        }
        Some(Self { nodes })
    }
}

/// Forward：len(2B) + 投递目标 NodeId(32B) + 透明载荷（≤600B，即上层信令包）
#[derive(Debug, Clone)]
pub struct ForwardBody {
    pub target: [u8; 32],
    pub payload: Vec<u8>,
}

pub const FORWARD_PAYLOAD_MAX: usize = 600;

impl ForwardBody {
    /// 超限载荷静默截断（防御性写端语义；读端见 decode 拒绝逻辑）
    pub fn encode(&self) -> Vec<u8> {
        let payload = &self.payload[..self.payload.len().min(FORWARD_PAYLOAD_MAX)];
        let mut out = Vec::with_capacity(34 + payload.len());
        out.extend_from_slice(&self.target);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 34 {
            return None;
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&buf[0..32]);
        let len = u16::from_be_bytes([buf[32], buf[33]]) as usize;
        if len > FORWARD_PAYLOAD_MAX || buf.len() != 34 + len {
            return None;
        }
        Some(Self {
            target,
            payload: buf[34..].to_vec(),
        })
    }
}

// —— 键值存储（K=1 简化，07 §4 v1 单值） ——————————————————

/// Store：sender(32B) + key(32B) + 值（≤1KB）。
/// sender 让存储节点学习写入者身份 → 后续 Forward 可路由回锚点（07 §4 报道路径）。
#[derive(Debug, Clone)]
pub struct StoreBody {
    pub sender: [u8; 32],
    pub key: [u8; 32],
    pub value: Vec<u8>,
}

impl StoreBody {
    pub fn encode(&self) -> Vec<u8> {
        let value = &self.value[..self.value.len().min(STORE_VALUE_MAX)];
        let mut out = Vec::with_capacity(66 + value.len());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 66 {
            return None;
        }
        let mut sender = [0u8; 32];
        let mut key = [0u8; 32];
        sender.copy_from_slice(&buf[0..32]);
        key.copy_from_slice(&buf[32..64]);
        let len = u16::from_be_bytes([buf[64], buf[65]]) as usize;
        if len > STORE_VALUE_MAX || buf.len() != 66 + len {
            return None;
        }
        Some(Self {
            sender,
            key,
            value: buf[66..].to_vec(),
        })
    }
}

/// FindValue：key(32B)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindValueBody {
    pub key: [u8; 32],
}

impl FindValueBody {
    pub const BODY_LEN: usize = 32;

    pub fn encode(&self, out: &mut [u8; Self::BODY_LEN]) {
        out.copy_from_slice(&self.key);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::BODY_LEN {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(buf);
        Some(Self { key })
    }
}

/// Value：key(32B) + 值；空值 = 未命中（v1 简化单跳存储语义）
#[derive(Debug, Clone)]
pub struct ValueBody {
    pub key: [u8; 32],
    pub value: Vec<u8>,
}

impl ValueBody {
    pub fn encode(&self) -> Vec<u8> {
        let value = &self.value[..self.value.len().min(STORE_VALUE_MAX)];
        let mut out = Vec::with_capacity(34 + value.len());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 34 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&buf[0..32]);
        let len = u16::from_be_bytes([buf[32], buf[33]]) as usize;
        if len > STORE_VALUE_MAX || buf.len() != 34 + len {
            return None;
        }
        Some(Self {
            key,
            value: buf[34..].to_vec(),
        })
    }
}

// —— 统一信封 ————————————————————————————————

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcHeader {
    pub kind: u8,
    pub txid: u32,
}

impl RpcHeader {
    pub fn encode(&self, out: &mut [u8; RPC_HEADER_LEN]) {
        out[0..2].copy_from_slice(&SIG_MAGIC);
        out[2] = self.kind;
        out[3..7].copy_from_slice(&self.txid.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < RPC_HEADER_LEN {
            return None;
        }
        if buf[0..2] != SIG_MAGIC {
            return None;
        }
        let kind = buf[2];
        match kind {
            rpc_type::PING
            | rpc_type::PONG
            | rpc_type::FIND_NODE
            | rpc_type::NEIGHBORS
            | rpc_type::FORWARD
            | rpc_type::STORE
            | rpc_type::STORED_ACK
            | rpc_type::FIND_VALUE
            | rpc_type::VALUE => Some(Self {
                kind,
                txid: u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RpcBody {
    Ping(PingBody),
    Pong(PingBody),
    FindNode(FindNodeBody),
    Neighbors(NeighborsBody),
    Forward(ForwardBody),
    Store(StoreBody),
    StoredAck,
    FindValue(FindValueBody),
    Value(ValueBody),
}

#[derive(Debug, Clone)]
pub struct RpcPacket {
    pub header: RpcHeader,
    pub body: RpcBody,
}

impl RpcPacket {
    pub fn ping(txid: u32, body: PingBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::PING, txid },
            body: RpcBody::Ping(body),
        }
    }

    pub fn pong(txid: u32, body: PingBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::PONG, txid },
            body: RpcBody::Pong(body),
        }
    }

    pub fn find_node(txid: u32, body: FindNodeBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::FIND_NODE, txid },
            body: RpcBody::FindNode(body),
        }
    }

    pub fn neighbors(txid: u32, body: NeighborsBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::NEIGHBORS, txid },
            body: RpcBody::Neighbors(body),
        }
    }

    pub fn forward(txid: u32, body: ForwardBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::FORWARD, txid },
            body: RpcBody::Forward(body),
        }
    }

    pub fn store(txid: u32, body: StoreBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::STORE, txid },
            body: RpcBody::Store(body),
        }
    }

    pub fn stored_ack(txid: u32) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::STORED_ACK, txid },
            body: RpcBody::StoredAck,
        }
    }

    pub fn find_value(txid: u32, body: FindValueBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::FIND_VALUE, txid },
            body: RpcBody::FindValue(body),
        }
    }

    pub fn value(txid: u32, body: ValueBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::VALUE, txid },
            body: RpcBody::Value(body),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let body_bytes = match &self.body {
            RpcBody::Ping(b) | RpcBody::Pong(b) => {
                let mut out = [0u8; PingBody::BODY_LEN];
                b.encode(&mut out);
                out.to_vec()
            }
            RpcBody::FindNode(b) => {
                let mut out = [0u8; FindNodeBody::BODY_LEN];
                b.encode(&mut out);
                out.to_vec()
            }
            RpcBody::Neighbors(b) => b.encode(),
            RpcBody::Forward(b) => b.encode(),
            RpcBody::Store(b) => b.encode(),
            RpcBody::StoredAck => Vec::new(),
            RpcBody::FindValue(b) => {
                let mut out = [0u8; FindValueBody::BODY_LEN];
                b.encode(&mut out);
                out.to_vec()
            }
            RpcBody::Value(b) => b.encode(),
        };
        let mut out = Vec::with_capacity(RPC_HEADER_LEN + body_bytes.len());
        let mut hdr = [0u8; RPC_HEADER_LEN];
        self.header.encode(&mut hdr);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&body_bytes);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        let header = RpcHeader::decode(buf)?;
        let body_bytes = &buf[RPC_HEADER_LEN..];
        let body = match header.kind {
            rpc_type::PING => RpcBody::Ping(PingBody::decode(body_bytes)?),
            rpc_type::PONG => RpcBody::Pong(PingBody::decode(body_bytes)?),
            rpc_type::FIND_NODE => RpcBody::FindNode(FindNodeBody::decode(body_bytes)?),
            rpc_type::NEIGHBORS => RpcBody::Neighbors(NeighborsBody::decode(body_bytes)?),
            rpc_type::FORWARD => RpcBody::Forward(ForwardBody::decode(body_bytes)?),
            rpc_type::STORE => RpcBody::Store(StoreBody::decode(body_bytes)?),
            rpc_type::STORED_ACK => RpcBody::StoredAck,
            rpc_type::FIND_VALUE => RpcBody::FindValue(FindValueBody::decode(body_bytes)?),
            rpc_type::VALUE => RpcBody::Value(ValueBody::decode(body_bytes)?),
            _ => return None,
        };
        Some(Self { header, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let body = PingBody {
            node_id: [0xA1; 32],
            pubkey: [0xB2; 32],
        };
        let pkt = RpcPacket::ping(0x0102_0304, body);
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), RPC_HEADER_LEN + PingBody::BODY_LEN);
        let dec = RpcPacket::decode(&bytes).unwrap();
        assert_eq!(dec.header.txid, 0x0102_0304);
        match dec.body {
            RpcBody::Ping(b) => assert_eq!(b, body),
            _ => panic!("期望 Ping"),
        }
    }

    #[test]
    fn neighbors_roundtrip() {
        let body = NeighborsBody {
            nodes: vec![
                NodeEntry { id: [0x11; 32], ipv4: [127, 0, 0, 1], port: 3841 },
                NodeEntry { id: [0x22; 32], ipv4: [10, 0, 0, 2], port: 9999 },
            ],
        };
        let pkt = RpcPacket::neighbors(7, body);
        let dec = RpcPacket::decode(&pkt.encode()).unwrap();
        match dec.body {
            RpcBody::Neighbors(b) => {
                assert_eq!(b.nodes.len(), 2);
                assert_eq!(b.nodes[0].port, 3841);
            }
            _ => panic!("期望 Neighbors"),
        }
    }

    #[test]
    fn forward_payload_integrity() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let body = ForwardBody {
            target: [0x99; 32],
            payload: payload.clone(),
        };
        let pkt = RpcPacket::forward(42, body);
        let dec = RpcPacket::decode(&pkt.encode()).unwrap();
        match dec.body {
            RpcBody::Forward(b) => {
                assert_eq!(b.target, [0x99; 32]);
                assert_eq!(b.payload, payload); // 透明载荷字节级完整
            }
            _ => panic!("期望 Forward"),
        }
    }

    #[test]
    fn oversize_forward_rejected_decode() {
        // 绕过 encode，手工构造超限字节流：target(32B) + len=601 + 601B
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&(601u16).to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; 601]);
        // 前缀 RPC 头
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&SIG_MAGIC);
        pkt.push(rpc_type::FORWARD);
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&bytes);
        assert!(RpcPacket::decode(&pkt).is_none(), "超限载荷必须拒绝");
    }

    #[test]
    fn unknown_type_rejected() {
        let mut buf = [0u8; RPC_HEADER_LEN];
        buf[0..2].copy_from_slice(&SIG_MAGIC);
        buf[2] = 0xFF;
        assert!(RpcHeader::decode(&buf).is_none());
    }

    #[test]
    fn bad_magic_rejected() {
        let buf = [0u8; RPC_HEADER_LEN];
        assert!(RpcHeader::decode(&buf).is_none());
    }
}