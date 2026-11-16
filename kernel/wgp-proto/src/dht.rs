//! DHT RPC 报文（Kademlia 变种，07 文档网络层格式）。
//! 头（7B）：magic(2)="WG" | type(1) | txid(4B)。
//! 全部手写编解码；Neighbors 上限 K=20。

use crate::consts::AUTH_NONCE_LEN;
use crate::packet::seed_advertise_v2;
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
    /// 索取对方已知的种子广告（07 §5 第③层 / 17 P0）
    pub const FIND_SEEDS: u8 = 0x39;
    pub const SEEDS: u8 = 0x3A;
    // —— 探活身份证明（17 §11）：一次一密挑战响应，验证通过前不写路由表/地址簿 ——
    /// 发起方 → 应答方：带上一次性 nonce，要求对端证明私钥持有权
    pub const AUTH_CHALLENGE: u8 = 0x3B;
    /// 应答方 → 发起方：对挑战签名；体内 `prover_nonce` 供发起方回证（1.5 RTT 双向）
    pub const AUTH_PROOF: u8 = 0x3C;
    /// 明确拒绝（版本不支持 / 格式非法 / 限速），让对端拿到可读原因而不是超时
    pub const AUTH_REJECT: u8 = 0x3D;
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

/// Store：sender(32B) + pubkey(32B) + key(32B) + 值（≤1KB）。
/// sender 让存储节点学习写入者身份 → 后续 Forward 可路由回锚点（07 §4 报道路径）。
/// pubkey 与 sender 必须通过 SHA-256 绑定校验（防冒充写入者毒化地址簿/冒占 KV 配额）。
#[derive(Debug, Clone)]
pub struct StoreBody {
    pub sender: [u8; 32],
    pub pubkey: [u8; 32],
    pub key: [u8; 32],
    pub value: Vec<u8>,
}

impl StoreBody {
    /// 定长前缀：sender + pubkey + key + 值长 2B
    pub const PREFIX_LEN: usize = 98;

    pub fn encode(&self) -> Vec<u8> {
        let value = &self.value[..self.value.len().min(STORE_VALUE_MAX)];
        let mut out = Vec::with_capacity(Self::PREFIX_LEN + value.len());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::PREFIX_LEN {
            return None;
        }
        let mut sender = [0u8; 32];
        let mut pubkey = [0u8; 32];
        let mut key = [0u8; 32];
        sender.copy_from_slice(&buf[0..32]);
        pubkey.copy_from_slice(&buf[32..64]);
        key.copy_from_slice(&buf[64..96]);
        let len = u16::from_be_bytes([buf[96], buf[97]]) as usize;
        if len > STORE_VALUE_MAX || buf.len() != Self::PREFIX_LEN + len {
            return None;
        }
        Some(Self {
            sender,
            pubkey,
            key,
            value: buf[Self::PREFIX_LEN..].to_vec(),
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

// —— 种子目录交换（07 §5 第③层 / 17 P0） ——

/// 单个 Seeds 应答最多携带的广告数（8 × 123B + 头 = 992B，不触发 IP 分片）
pub const SEEDS_MAX: usize = 8;

/// FindSeeds：target(32B) + 填充。应答为「对方已知的、离 target 最近的若干条种子广告」。
///
/// **防反射放大**：应答（最多 8 条 123B 广告）远大于一个 32B 的请求，而 UDP 源地址可以伪造——
/// 不设防的话本 RPC 就是一个 20 多倍的流量放大器。因此规定**应答不得长于请求**：请求方想要
/// 几条广告，就把请求填充到装得下几条广告的长度（[`FindSeedsBody::for_count`]），应答方按
/// [`FindSeedsBody::quota`] 截断。填充内容不被解释。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindSeedsBody {
    pub target: [u8; 32],
    /// 填充字节数
    pub padding: u16,
}

impl FindSeedsBody {
    pub const TARGET_LEN: usize = 32;
    /// 请求体上限：恰好换回 SEEDS_MAX 条广告所需的长度
    pub const BODY_MAX: usize = 1 + SEEDS_MAX * seed_advertise_v2::LEN;

    /// 构造一个「想要 `count` 条广告」的请求（count 超过 SEEDS_MAX 按上限算）
    pub fn for_count(target: [u8; 32], count: usize) -> Self {
        let wanted = 1 + count.min(SEEDS_MAX) * seed_advertise_v2::LEN;
        let body_len = wanted.max(Self::TARGET_LEN);
        Self {
            target,
            padding: (body_len - Self::TARGET_LEN) as u16,
        }
    }

    pub fn body_len(&self) -> usize {
        Self::TARGET_LEN + self.padding as usize
    }

    /// 本请求允许换回的广告条数：保证「count(1B) + 条数 × 123B」不超过请求体长度
    pub fn quota(&self) -> usize {
        ((self.body_len() - 1) / seed_advertise_v2::LEN).min(SEEDS_MAX)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.body_len().min(Self::BODY_MAX)];
        out[..Self::TARGET_LEN].copy_from_slice(&self.target);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::TARGET_LEN || buf.len() > Self::BODY_MAX {
            return None;
        }
        let mut target = [0u8; 32];
        target.copy_from_slice(&buf[..Self::TARGET_LEN]);
        Some(Self {
            target,
            padding: (buf.len() - Self::TARGET_LEN) as u16,
        })
    }
}

/// Seeds：count(1B) + count × 种子广告 V2 原文（123B）。
/// 广告以原始字节转述——签名覆盖的就是这些字节，转述者改动任何一位都会被验签拒绝。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedsBody {
    pub adverts: Vec<[u8; seed_advertise_v2::LEN]>,
}

impl SeedsBody {
    /// 超过 SEEDS_MAX 的部分静默截断（写端防御；读端见 decode 的拒绝逻辑）
    pub fn encode(&self) -> Vec<u8> {
        let count = self.adverts.len().min(SEEDS_MAX);
        let mut out = Vec::with_capacity(1 + count * seed_advertise_v2::LEN);
        out.push(count as u8);
        for adv in &self.adverts[..count] {
            out.extend_from_slice(adv);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        let (&count, rest) = buf.split_first()?;
        let count = count as usize;
        if count > SEEDS_MAX || rest.len() != count * seed_advertise_v2::LEN {
            return None;
        }
        let adverts = rest
            .chunks_exact(seed_advertise_v2::LEN)
            .map(|chunk| {
                let mut adv = [0u8; seed_advertise_v2::LEN];
                adv.copy_from_slice(chunk);
                adv
            })
            .collect();
        Some(Self { adverts })
    }
}

// —— 探活身份证明（17 §11） ——————————————————————

pub mod auth_reject_reason {
    /// 对端发来的 version 不是本端支持的（supported_version 里告诉它本端支持什么）
    pub const UNSUPPORTED_VERSION: u8 = 1;
    /// 报文结构非法（长度/绑定校验失败等）
    pub const MALFORMED: u8 = 2;
    /// 超过入站配额（防 CPU 与放大滥用）
    pub const RATE_LIMITED: u8 = 3;
}

/// AuthChallenge：挑战方提出一次性问题，要求对端证明身份私钥持有权。
///
/// ```text
/// [0..32]   verifier_id       挑战方 NodeId（= SHA256(verifier_pubkey)）
/// [32..64]  verifier_pubkey   挑战方长期公钥
/// [64..80]  nonce             一次性挑战（16B，密码学随机；同一 nonce 只应答一次）
/// [80]      version           = AUTH_VERSION
/// ```
///
/// 挑战本身不携带证明方的任何信息——收到挑战不等于认识对方，应答方**不因收到挑战而学习发送者**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthChallengeBody {
    pub verifier_id: [u8; 32],
    pub verifier_pubkey: [u8; 32],
    pub nonce: [u8; AUTH_NONCE_LEN],
    pub version: u8,
}

impl AuthChallengeBody {
    pub const LEN: usize = 32 + 32 + AUTH_NONCE_LEN + 1;

    pub fn encode(&self, out: &mut [u8; Self::LEN]) {
        out[0..32].copy_from_slice(&self.verifier_id);
        out[32..64].copy_from_slice(&self.verifier_pubkey);
        out[64..80].copy_from_slice(&self.nonce);
        out[80] = self.version;
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LEN {
            return None;
        }
        let mut verifier_id = [0u8; 32];
        let mut verifier_pubkey = [0u8; 32];
        let mut nonce = [0u8; AUTH_NONCE_LEN];
        verifier_id.copy_from_slice(&buf[0..32]);
        verifier_pubkey.copy_from_slice(&buf[32..64]);
        nonce.copy_from_slice(&buf[64..80]);
        Some(Self {
            verifier_id,
            verifier_pubkey,
            nonce,
            version: buf[80],
        })
    }
}

/// AuthProof：对端对「本次挑战」的签名证明；同时可携带自己的挑战（`prover_nonce`）要求回证。
///
/// ```text
/// [0..32]   prover_id         证明方 NodeId
/// [32..64]  prover_pubkey     证明方长期公钥
/// [64..80]  nonce_echo        原样回抄收到的挑战 nonce
/// [80..96]  prover_nonce      证明方自选的 16B（要求对方回证时用；全 0 = 不要求回证）
/// [96]      version           = AUTH_VERSION
/// [97..161] signature         对 [`auth_signing_message`] 的 ed25519 签名
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthProofBody {
    pub prover_id: [u8; 32],
    pub prover_pubkey: [u8; 32],
    pub nonce_echo: [u8; AUTH_NONCE_LEN],
    pub prover_nonce: [u8; AUTH_NONCE_LEN],
    pub version: u8,
    pub signature: [u8; 64],
}

impl AuthProofBody {
    pub const LEN: usize = 32 + 32 + AUTH_NONCE_LEN + AUTH_NONCE_LEN + 1 + 64;
    /// 签名之前的字节数（待签消息由这些字段 + 头部 txid 拼成，不看这个偏移）
    pub const SIGNED_PREFIX_LEN: usize = Self::LEN - 64;

    pub fn encode(&self, out: &mut [u8; Self::LEN]) {
        out[0..32].copy_from_slice(&self.prover_id);
        out[32..64].copy_from_slice(&self.prover_pubkey);
        out[64..80].copy_from_slice(&self.nonce_echo);
        out[80..96].copy_from_slice(&self.prover_nonce);
        out[96] = self.version;
        out[97..161].copy_from_slice(&self.signature);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LEN {
            return None;
        }
        let mut prover_id = [0u8; 32];
        let mut prover_pubkey = [0u8; 32];
        let mut nonce_echo = [0u8; AUTH_NONCE_LEN];
        let mut prover_nonce = [0u8; AUTH_NONCE_LEN];
        let mut signature = [0u8; 64];
        prover_id.copy_from_slice(&buf[0..32]);
        prover_pubkey.copy_from_slice(&buf[32..64]);
        nonce_echo.copy_from_slice(&buf[64..80]);
        prover_nonce.copy_from_slice(&buf[80..96]);
        signature.copy_from_slice(&buf[97..161]);
        Some(Self {
            prover_id,
            prover_pubkey,
            nonce_echo,
            prover_nonce,
            version: buf[96],
            signature,
        })
    }

    /// 本证明的待签消息（`verifier_id` 与 `txid` 来自上下文，不在体内）
    pub fn signing_message(&self, verifier_id: &[u8; 32], txid: u32) -> [u8; AUTH_SIGNING_MESSAGE_LEN] {
        auth_signing_message(
            self.version,
            &self.prover_id,
            verifier_id,
            &self.nonce_echo,
            &self.prover_nonce,
            txid,
        )
    }
}

/// AuthReject：明确拒绝。收到它的一方不必等超时，能直接给出可读原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRejectBody {
    pub reason: u8,
    /// reason = UNSUPPORTED_VERSION 时填本端支持的版本，其余情况填 0
    pub supported_version: u8,
}

impl AuthRejectBody {
    pub const LEN: usize = 2;

    pub fn encode(&self, out: &mut [u8; Self::LEN]) {
        out[0] = self.reason;
        out[1] = self.supported_version;
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != Self::LEN {
            return None;
        }
        Some(Self {
            reason: buf[0],
            supported_version: buf[1],
        })
    }
}

/// 待签 / 待验消息长度：域前缀 + version + 双方 NodeId + 两个 nonce + txid
pub const AUTH_SIGNING_MESSAGE_LEN: usize =
    crate::consts::AUTH_DOMAIN.len() + 1 + 32 + 32 + AUTH_NONCE_LEN + AUTH_NONCE_LEN + 4;

/// 挑战响应的待签消息（117B，两个方向同一套）：
/// `AUTH_DOMAIN ‖ version ‖ prover_id ‖ verifier_id ‖ nonce_echo ‖ prover_nonce ‖ txid`
///
/// 约定：
/// - `prover_id` / `verifier_id` 必须过 `node_id == SHA256(pubkey)` 才谈得上签名有效；
/// - `version` 被签名覆盖，将来 v2 的证明不会被当成 v1 用；
/// - `txid` 取自 RPC 头部，签名覆盖它 → 证明不能被挪到别的事务里。
pub fn auth_signing_message(
    version: u8,
    prover_id: &[u8; 32],
    verifier_id: &[u8; 32],
    nonce_echo: &[u8; AUTH_NONCE_LEN],
    prover_nonce: &[u8; AUTH_NONCE_LEN],
    txid: u32,
) -> [u8; AUTH_SIGNING_MESSAGE_LEN] {
    let domain = crate::consts::AUTH_DOMAIN;
    let mut msg = [0u8; AUTH_SIGNING_MESSAGE_LEN];
    let mut at = 0usize;
    msg[at..at + domain.len()].copy_from_slice(domain);
    at += domain.len();
    msg[at] = version;
    at += 1;
    msg[at..at + 32].copy_from_slice(prover_id);
    at += 32;
    msg[at..at + 32].copy_from_slice(verifier_id);
    at += 32;
    msg[at..at + AUTH_NONCE_LEN].copy_from_slice(nonce_echo);
    at += AUTH_NONCE_LEN;
    msg[at..at + AUTH_NONCE_LEN].copy_from_slice(prover_nonce);
    at += AUTH_NONCE_LEN;
    msg[at..at + 4].copy_from_slice(&txid.to_be_bytes());
    msg
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
            | rpc_type::VALUE
            | rpc_type::FIND_SEEDS
            | rpc_type::SEEDS
            | rpc_type::AUTH_CHALLENGE
            | rpc_type::AUTH_PROOF
            | rpc_type::AUTH_REJECT => Some(Self {
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
    FindSeeds(FindSeedsBody),
    Seeds(SeedsBody),
    AuthChallenge(AuthChallengeBody),
    AuthProof(AuthProofBody),
    AuthReject(AuthRejectBody),
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

    pub fn find_seeds(txid: u32, body: FindSeedsBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::FIND_SEEDS, txid },
            body: RpcBody::FindSeeds(body),
        }
    }

    pub fn seeds(txid: u32, body: SeedsBody) -> Self {
        Self {
            header: RpcHeader { kind: rpc_type::SEEDS, txid },
            body: RpcBody::Seeds(body),
        }
    }

    pub fn auth_challenge(txid: u32, body: AuthChallengeBody) -> Self {
        Self {
            header: RpcHeader {
                kind: rpc_type::AUTH_CHALLENGE,
                txid,
            },
            body: RpcBody::AuthChallenge(body),
        }
    }

    pub fn auth_proof(txid: u32, body: AuthProofBody) -> Self {
        Self {
            header: RpcHeader {
                kind: rpc_type::AUTH_PROOF,
                txid,
            },
            body: RpcBody::AuthProof(body),
        }
    }

    pub fn auth_reject(txid: u32, body: AuthRejectBody) -> Self {
        Self {
            header: RpcHeader {
                kind: rpc_type::AUTH_REJECT,
                txid,
            },
            body: RpcBody::AuthReject(body),
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
            RpcBody::FindSeeds(b) => b.encode(),
            RpcBody::Seeds(b) => b.encode(),
            RpcBody::AuthChallenge(b) => {
                let mut out = [0u8; AuthChallengeBody::LEN];
                b.encode(&mut out);
                out.to_vec()
            }
            RpcBody::AuthProof(b) => {
                let mut out = [0u8; AuthProofBody::LEN];
                b.encode(&mut out);
                out.to_vec()
            }
            RpcBody::AuthReject(b) => {
                let mut out = [0u8; AuthRejectBody::LEN];
                b.encode(&mut out);
                out.to_vec()
            }
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
            rpc_type::FIND_SEEDS => RpcBody::FindSeeds(FindSeedsBody::decode(body_bytes)?),
            rpc_type::SEEDS => RpcBody::Seeds(SeedsBody::decode(body_bytes)?),
            rpc_type::AUTH_CHALLENGE => {
                RpcBody::AuthChallenge(AuthChallengeBody::decode(body_bytes)?)
            }
            rpc_type::AUTH_PROOF => RpcBody::AuthProof(AuthProofBody::decode(body_bytes)?),
            rpc_type::AUTH_REJECT => RpcBody::AuthReject(AuthRejectBody::decode(body_bytes)?),
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
    fn store_roundtrip_with_pubkey() {
        let body = StoreBody {
            sender: [0xA1; 32],
            pubkey: [0xB2; 32],
            key: [0xC3; 32],
            value: vec![0x42; 300],
        };
        let pkt = RpcPacket::store(9, body);
        let dec = RpcPacket::decode(&pkt.encode()).unwrap();
        match dec.body {
            RpcBody::Store(b) => {
                assert_eq!(b.sender, [0xA1; 32]);
                assert_eq!(b.pubkey, [0xB2; 32]);
                assert_eq!(b.key, [0xC3; 32]);
                assert_eq!(b.value.len(), 300);
            }
            _ => panic!("期望 Store"),
        }
    }

    #[test]
    fn store_truncated_rejected() {
        // 旧格式（无 pubkey 的 66B 前缀）必须解码失败——协议代际隔离
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 64]);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&SIG_MAGIC);
        pkt.push(rpc_type::STORE);
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&bytes);
        assert!(RpcPacket::decode(&pkt).is_none(), "缺 pubkey 的旧帧必须拒绝");
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
    fn find_seeds_reply_never_longer_than_request() {
        // 防放大的核心不变量：任意合法请求，按 quota 构造的最大应答都不长于请求
        for count in 0..=SEEDS_MAX + 3 {
            let req = FindSeedsBody::for_count([0x42; 32], count);
            let req_bytes = RpcPacket::find_seeds(1, req).encode();
            let reply = SeedsBody {
                adverts: vec![[0u8; seed_advertise_v2::LEN]; req.quota()],
            };
            let reply_bytes = RpcPacket::seeds(1, reply).encode();
            assert!(
                reply_bytes.len() <= req_bytes.len(),
                "count={count}: 应答 {} > 请求 {}",
                reply_bytes.len(),
                req_bytes.len()
            );
            assert_eq!(req.quota(), count.min(SEEDS_MAX));
        }
        // 不填充的最小请求一条也换不到
        let bare = FindSeedsBody { target: [0; 32], padding: 0 };
        assert_eq!(bare.quota(), 0);
    }

    #[test]
    fn find_seeds_roundtrip_and_bounds() {
        let req = FindSeedsBody::for_count([0x17; 32], SEEDS_MAX);
        assert_eq!(req.body_len(), FindSeedsBody::BODY_MAX);
        let pkt = RpcPacket::find_seeds(77, req);
        let dec = RpcPacket::decode(&pkt.encode()).unwrap();
        assert_eq!(dec.header.txid, 77);
        match dec.body {
            RpcBody::FindSeeds(b) => assert_eq!(b, req),
            _ => panic!("期望 FindSeeds"),
        }
        // 短于 target / 超过上限：拒绝
        assert!(FindSeedsBody::decode(&[0u8; 31]).is_none());
        assert!(FindSeedsBody::decode(&vec![0u8; FindSeedsBody::BODY_MAX + 1]).is_none());
    }

    #[test]
    fn seeds_roundtrip_and_malformed_rejected() {
        let mut a = [0u8; seed_advertise_v2::LEN];
        let mut b = [0u8; seed_advertise_v2::LEN];
        a[5] = 0xAA;
        b[100] = 0xBB;
        let body = SeedsBody { adverts: vec![a, b] };
        let pkt = RpcPacket::seeds(9, body.clone());
        match RpcPacket::decode(&pkt.encode()).unwrap().body {
            RpcBody::Seeds(got) => assert_eq!(got, body, "广告原文必须逐字节保留"),
            _ => panic!("期望 Seeds"),
        }
        // 空应答合法
        assert_eq!(SeedsBody::decode(&[0]), Some(SeedsBody { adverts: vec![] }));
        // 条数与长度不符 / 条数越限 / 空体：拒绝
        assert!(SeedsBody::decode(&[]).is_none());
        assert!(SeedsBody::decode(&[1]).is_none());
        let mut short = vec![2u8];
        short.extend_from_slice(&a);
        assert!(SeedsBody::decode(&short).is_none());
        let mut over = vec![(SEEDS_MAX + 1) as u8];
        over.extend_from_slice(&vec![0u8; (SEEDS_MAX + 1) * seed_advertise_v2::LEN]);
        assert!(SeedsBody::decode(&over).is_none());
        // 写端超限截断
        let many = SeedsBody { adverts: vec![a; SEEDS_MAX + 4] };
        assert_eq!(SeedsBody::decode(&many.encode()).unwrap().adverts.len(), SEEDS_MAX);
    }

    #[test]
    fn bad_magic_rejected() {
        let buf = [0u8; RPC_HEADER_LEN];
        assert!(RpcHeader::decode(&buf).is_none());
    }

    // —— 探活身份证明（17 §11） ——

    fn sample_challenge() -> AuthChallengeBody {
        AuthChallengeBody {
            verifier_id: [0x11; 32],
            verifier_pubkey: [0x22; 32],
            nonce: [0x33; AUTH_NONCE_LEN],
            version: crate::consts::AUTH_VERSION,
        }
    }

    fn sample_proof() -> AuthProofBody {
        AuthProofBody {
            prover_id: [0x44; 32],
            prover_pubkey: [0x55; 32],
            nonce_echo: [0x66; AUTH_NONCE_LEN],
            prover_nonce: [0x77; AUTH_NONCE_LEN],
            version: crate::consts::AUTH_VERSION,
            signature: [0x88; 64],
        }
    }

    #[test]
    fn auth_challenge_roundtrip_and_layout() {
        let body = sample_challenge();
        assert_eq!(AuthChallengeBody::LEN, 81);
        let pkt = RpcPacket::auth_challenge(0x0102_0304, body);
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), RPC_HEADER_LEN + AuthChallengeBody::LEN);
        // 布局锁定：字段偏移是线格式的一部分
        assert_eq!(&bytes[RPC_HEADER_LEN..RPC_HEADER_LEN + 32], &[0x11; 32]);
        assert_eq!(&bytes[RPC_HEADER_LEN + 32..RPC_HEADER_LEN + 64], &[0x22; 32]);
        assert_eq!(&bytes[RPC_HEADER_LEN + 64..RPC_HEADER_LEN + 80], &[0x33; 16]);
        assert_eq!(bytes[RPC_HEADER_LEN + 80], crate::consts::AUTH_VERSION);
        let dec = RpcPacket::decode(&bytes).unwrap();
        assert_eq!(dec.header.txid, 0x0102_0304);
        match dec.body {
            RpcBody::AuthChallenge(b) => assert_eq!(b, body),
            _ => panic!("期望 AuthChallenge"),
        }
        // 长度不对一律拒绝（不接受「多几个字节」的宽容解析）
        assert!(AuthChallengeBody::decode(&[0u8; AuthChallengeBody::LEN - 1]).is_none());
        assert!(AuthChallengeBody::decode(&[0u8; AuthChallengeBody::LEN + 1]).is_none());
    }

    #[test]
    fn auth_proof_roundtrip_and_layout() {
        let body = sample_proof();
        assert_eq!(AuthProofBody::LEN, 161);
        assert_eq!(AuthProofBody::SIGNED_PREFIX_LEN, 97);
        let pkt = RpcPacket::auth_proof(9, body);
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), RPC_HEADER_LEN + AuthProofBody::LEN);
        assert_eq!(&bytes[RPC_HEADER_LEN..RPC_HEADER_LEN + 32], &[0x44; 32]);
        assert_eq!(&bytes[RPC_HEADER_LEN + 32..RPC_HEADER_LEN + 64], &[0x55; 32]);
        assert_eq!(&bytes[RPC_HEADER_LEN + 64..RPC_HEADER_LEN + 80], &[0x66; 16]);
        assert_eq!(&bytes[RPC_HEADER_LEN + 80..RPC_HEADER_LEN + 96], &[0x77; 16]);
        assert_eq!(bytes[RPC_HEADER_LEN + 96], crate::consts::AUTH_VERSION);
        assert_eq!(&bytes[RPC_HEADER_LEN + 97..], &[0x88; 64]);
        match RpcPacket::decode(&bytes).unwrap().body {
            RpcBody::AuthProof(b) => assert_eq!(b, body),
            _ => panic!("期望 AuthProof"),
        }
        assert!(AuthProofBody::decode(&[0u8; AuthProofBody::LEN - 1]).is_none());
        assert!(AuthProofBody::decode(&[0u8; AuthProofBody::LEN + 1]).is_none());
    }

    #[test]
    fn auth_reject_roundtrip_and_layout() {
        let body = AuthRejectBody {
            reason: auth_reject_reason::UNSUPPORTED_VERSION,
            supported_version: crate::consts::AUTH_VERSION,
        };
        let bytes = RpcPacket::auth_reject(3, body).encode();
        assert_eq!(bytes.len(), RPC_HEADER_LEN + AuthRejectBody::LEN);
        match RpcPacket::decode(&bytes).unwrap().body {
            RpcBody::AuthReject(b) => assert_eq!(b, body),
            _ => panic!("期望 AuthReject"),
        }
        assert!(AuthRejectBody::decode(&[0u8]).is_none());
        assert!(AuthRejectBody::decode(&[0u8; 3]).is_none());
        // 三个原因码互不相同，且都不为 0（0 留给「无原因」）
        for reason in [
            auth_reject_reason::UNSUPPORTED_VERSION,
            auth_reject_reason::MALFORMED,
            auth_reject_reason::RATE_LIMITED,
        ] {
            assert_ne!(reason, 0);
        }
        assert_ne!(
            auth_reject_reason::UNSUPPORTED_VERSION,
            auth_reject_reason::MALFORMED
        );
        assert_ne!(
            auth_reject_reason::MALFORMED,
            auth_reject_reason::RATE_LIMITED
        );
    }

    #[test]
    fn auth_types_do_not_collide_with_existing_rpc() {
        let known = [
            rpc_type::PING,
            rpc_type::PONG,
            rpc_type::FIND_NODE,
            rpc_type::NEIGHBORS,
            rpc_type::FORWARD,
            rpc_type::STORE,
            rpc_type::STORED_ACK,
            rpc_type::FIND_VALUE,
            rpc_type::VALUE,
            rpc_type::FIND_SEEDS,
            rpc_type::SEEDS,
        ];
        for t in [
            rpc_type::AUTH_CHALLENGE,
            rpc_type::AUTH_PROOF,
            rpc_type::AUTH_REJECT,
        ] {
            assert!(!known.contains(&t), "类型号 {t:#04x} 与既有 RPC 冲突");
        }
        assert_ne!(rpc_type::AUTH_CHALLENGE, rpc_type::AUTH_PROOF);
        assert_ne!(rpc_type::AUTH_PROOF, rpc_type::AUTH_REJECT);
    }

    #[test]
    fn auth_signing_message_covers_every_field() {
        let body = sample_proof();
        let verifier = [0x99u8; 32];
        let txid = 0xAABB_CCDDu32;
        let base = body.signing_message(&verifier, txid);

        // 域分隔前缀在最前，长度等于声明的常量
        assert!(base.starts_with(crate::consts::AUTH_DOMAIN));
        assert_eq!(base.len(), AUTH_SIGNING_MESSAGE_LEN);
        assert_eq!(
            AUTH_SIGNING_MESSAGE_LEN,
            crate::consts::AUTH_DOMAIN.len() + 1 + 32 + 32 + 16 + 16 + 4
        );

        // 签名之后的字节（signature 本身）不在待签消息里
        let mut other_sig = body;
        other_sig.signature = [0x00; 64];
        assert_eq!(other_sig.signing_message(&verifier, txid), base);

        // 版本、双方身份、两个 nonce、txid：任一字节变化都必须反映到待签消息
        let mutations: [(&str, AuthProofBody); 2] = [
            (
                "version",
                AuthProofBody {
                    version: body.version.wrapping_add(1),
                    ..body
                },
            ),
            (
                "prover_id",
                AuthProofBody {
                    prover_id: [0x01; 32],
                    ..body
                },
            ),
        ];
        for (what, mutated) in mutations {
            assert_ne!(
                mutated.signing_message(&verifier, txid),
                base,
                "{what} 未被签名覆盖"
            );
        }
        // 公钥不进待签消息，但被 node_id 间接绑定（node_id == SHA256(pubkey) 是验签前置条件）：
        // 换公钥而不换 node_id 会先在校验绑定那一步失败，所以这里断言「消息不变」是设计意图。
        let other_pubkey = AuthProofBody {
            prover_pubkey: [0x02; 32],
            ..body
        };
        assert_eq!(other_pubkey.signing_message(&verifier, txid), base);
        let mut flipped_nonce_echo = body;
        flipped_nonce_echo.nonce_echo[0] ^= 0xFF;
        assert_ne!(flipped_nonce_echo.signing_message(&verifier, txid), base);
        let mut flipped_prover_nonce = body;
        flipped_prover_nonce.prover_nonce[15] ^= 0x01;
        assert_ne!(flipped_prover_nonce.signing_message(&verifier, txid), base);
        assert_ne!(body.signing_message(&verifier, txid + 1), base, "txid 未被签名覆盖");
        let mut other_verifier = verifier;
        other_verifier[31] ^= 0x80;
        assert_ne!(body.signing_message(&other_verifier, txid), base, "verifier_id 未被签名覆盖");
    }

    #[test]
    fn auth_proof_old_header_length_is_not_accepted() {
        // 代际隔离：把 64B 的 PingBody 当作 AUTH_PROOF 体，必须解码失败
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&SIG_MAGIC);
        pkt.push(rpc_type::AUTH_PROOF);
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&[0u8; PingBody::BODY_LEN]);
        assert!(RpcPacket::decode(&pkt).is_none());
    }
}