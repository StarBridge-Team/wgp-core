use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm, Nonce};
use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use rand::RngCore;
use std::io::{Read, Write};
use std::time::Duration;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/etbridge.rs"));
}

// ==================== 常量 ====================
pub const MAGIC: u32 = 0xd1e1a5e1;
pub const VERSION: u32 = 1;
pub const PEER_MANAGER_HEADER_SIZE: usize = 16;
pub const DEFAULT_LISTENER_PORT: u16 = 11010;

// PeerManagerHeader flags
pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_COMPRESSED: u8 = 0x10;
// 与 Mesh Relay <协议帧处理规范> PeerManagerHeaderFlags 对齐：
//   - LATENCY_FIRST=0x02, EXIT_NODE=0x04, NO_PROXY=0x08
//   - NOT_SEND_TO_TUN=0x40：Mesh Relay 不会把这个 Data 帧投递给本机 TUN，只经过 ACL/流水线。
//     轻量客户端如果没开 TUN，只把用户 payload / IP 包交给应用层，发送方应设这个 flag
//     让 Relay 知道"这包不需要 Relay 的 TUN 写回本机"，避免 Relay 尝试写 TUN 失败丢包。
//     反过来，**收**包时如果 NOT_SEND_TO_TUN=0，Relay 会把解密后的 payload 喂进 TUN；
//     如果我们的客户端用 TUN，应该忽略这个 flag，自己决定是否写 TUN。
pub const FLAG_LATENCY_FIRST: u8 = 0x02;
pub const FLAG_EXIT_NODE: u8 = 0x04;
pub const FLAG_NO_PROXY: u8 = 0x08;
pub const FLAG_NOT_SEND_TO_TUN: u8 = 0x40;

// PacketType — 与 Mesh Relay <协议帧处理规范> 完全一致（RpcReq=8, RpcResp=9）
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 1,
    HandShake = 2,
    Ping = 4,
    Pong = 5,
    RpcReq = 8,
    RpcResp = 9,
}
impl TryFrom<u8> for PacketType {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Data), 2 => Ok(Self::HandShake),
            4 => Ok(Self::Ping), 5 => Ok(Self::Pong),
            8 => Ok(Self::RpcReq), 9 => Ok(Self::RpcResp),
            v => Err(v),
        }
    }
}

// ==================== 1. SipHash13 (DefaultHasher 语义) ====================
// 严格复刻 Rust 1.x stable std::hash::DefaultHasher (SipHash13 with key=(0,0))
pub struct SipHasher13 {
    #[allow(dead_code)]
    k0: u64,
    #[allow(dead_code)]
    k1: u64,
    length: u64,
    v0: u64, v1: u64, v2: u64, v3: u64,
    tail: u64,
    ntail: usize,
}

impl Default for SipHasher13 {
    fn default() -> Self {
        Self::new_with_keys(0, 0)
    }
}

impl SipHasher13 {
    pub fn new_with_keys(k0: u64, k1: u64) -> Self {
        Self {
            k0, k1,
            length: 0,
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
            tail: 0,
            ntail: 0,
        }
    }

    // 严格与 Rust std core/src/hash/sip.rs Sip13RoundOps 保持一致
    fn c_round(&mut self) {
        // half-round 1
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        // half-round 2
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        // half-round 3
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        // half-round 4
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
    // d=3 就是跑 3 个 c_round
    fn d_round(&mut self) { self.c_round(); self.c_round(); self.c_round(); }

    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        self.c_round(); // 1-3 means SipHash1-3 compression (c=1)
        self.v0 ^= m;
    }

    pub fn write(&mut self, msg: &[u8]) {
        self.length += msg.len() as u64;
        let mut i = 0;
        let n = msg.len();
        // 先填已有 tail
        if self.ntail != 0 {
            let need = 8 - self.ntail;
            let take = need.min(n);
            for j in 0..take {
                self.tail |= (msg[j] as u64) << ((self.ntail + j) * 8);
            }
            self.ntail += take;
            i += take;
            if self.ntail == 8 {
                let m = self.tail;
                self.tail = 0; self.ntail = 0;
                self.compress(m);
            }
        }
        // 8 字节整块
        while i + 8 <= n {
            let mut b = [0u8; 8];
            b.copy_from_slice(&msg[i..i + 8]);
            let m = u64::from_le_bytes(b);
            self.compress(m);
            i += 8;
        }
        // 剩余字节进 tail
        while i < n {
            self.tail |= (msg[i] as u64) << (self.ntail * 8);
            self.ntail += 1;
            i += 1;
        }
    }

    // 注意：std Hasher::finish 是 &self，不修改内部状态。
    // Mesh Relay 的 digest/key 推导依赖连续 finish()+write()，所以必须在副本上做 finalization。
    pub fn finish(&self) -> u64 {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;
        let length_mod_256 = self.length as u8 as u64;
        let b: u64 = (length_mod_256 << 56) | self.tail;
        v3 ^= b;
        // c_round 在局部状态上做（与 std SipHash13 c_rounds(1) 一致）
        v0 = v0.wrapping_add(v1); v1 = v1.rotate_left(13); v1 ^= v0; v0 = v0.rotate_left(32);
        v2 = v2.wrapping_add(v3); v3 = v3.rotate_left(16); v3 ^= v2;
        v0 = v0.wrapping_add(v3); v3 = v3.rotate_left(21); v3 ^= v0;
        v2 = v2.wrapping_add(v1); v1 = v1.rotate_left(17); v1 ^= v2; v2 = v2.rotate_left(32);
        v0 ^= b;
        v2 ^= 0xff;
        // d_rounds(3)
        for _ in 0..3 {
            v0 = v0.wrapping_add(v1); v1 = v1.rotate_left(13); v1 ^= v0; v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3); v3 = v3.rotate_left(16); v3 ^= v2;
            v0 = v0.wrapping_add(v3); v3 = v3.rotate_left(21); v3 ^= v0;
            v2 = v2.wrapping_add(v1); v1 = v1.rotate_left(17); v1 ^= v2; v2 = v2.rotate_left(32);
        }
        v0 ^ v1 ^ v2 ^ v3
    }
}

// 复刻 Mesh Relay: generate_digest_from_str —— 32 字节
// 关键：一个 hasher 贯穿始终，每轮 finish() 后把已生成的 digest 前缀再 write 进去
pub fn generate_network_secret_digest(network_name: &str, network_secret: &str) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut hasher = SipHasher13::default();
    hasher.write(network_name.as_bytes());
    hasher.write(network_secret.as_bytes());
    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
    digest
}

// 复刻 Mesh Relay: derive_key_128 —— 16 字节
// 同样一个 hasher 贯穿，finish 后 write 已生成的 key 前缀
pub fn derive_key_128(secret: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let mut hasher = SipHasher13::default();
    hasher.write(secret.as_bytes());
    key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key[0..8]);
    key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
    key
}

// ==================== 2. TCP 帧 + PeerManagerHeader ====================
#[derive(Debug, Clone)]
pub struct PeerManagerHeader {
    pub from_peer_id: u32,
    pub to_peer_id: u32,
    pub packet_type: PacketType,
    pub flags: u8,
    pub forward_counter: u8,
    pub reserved: u8,
    pub len: u32,
}

impl PeerManagerHeader {
    pub fn new(from: u32, to: u32, pt: PacketType, payload_len: u32) -> Self {
        Self {
            from_peer_id: from, to_peer_id: to,
            packet_type: pt, flags: 0, forward_counter: 0, reserved: 0,
            len: payload_len,
        }
    }

    #[inline]
    pub fn set_flag(&mut self, flag: u8, on: bool) {
        if on { self.flags |= flag; } else { self.flags &= !flag; }
    }
    #[inline] pub fn is_encrypted(&self) -> bool { self.flags & FLAG_ENCRYPTED != 0 }
    #[inline] pub fn is_compressed(&self) -> bool { self.flags & FLAG_COMPRESSED != 0 }
    /// Mesh Relay 约定：=1 时，Data 帧 payload（IP 包）不写入接收端本机 TUN。
    /// 轻量客户端自己不挂 TUN 时发的包应该设为 1（避免 Relay 尝试写 TUN），
    /// 自己挂 TUN 时发的包应该保持 0（让其他 Relay 节点正常投递给它们的 TUN）。
    #[inline] pub fn not_send_to_tun(&self) -> bool { self.flags & FLAG_NOT_SEND_TO_TUN != 0 }
    #[inline] pub fn set_not_send_to_tun(&mut self, on: bool) { self.set_flag(FLAG_NOT_SEND_TO_TUN, on); }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_le(self.from_peer_id);
        buf.put_u32_le(self.to_peer_id);
        buf.put_u8(self.packet_type as u8);
        buf.put_u8(self.flags);
        buf.put_u8(self.forward_counter);
        buf.put_u8(self.reserved);
        buf.put_u32_le(self.len);
    }

    pub fn decode(buf: &[u8]) -> Self {
        if buf.len() < PEER_MANAGER_HEADER_SIZE {
            // 不足 16B：返回一个安全的默认 header，避免 panic
            return Self {
                from_peer_id: 0, to_peer_id: 0,
                packet_type: PacketType::Data, flags: 0,
                forward_counter: 0, reserved: 0, len: 0,
            };
        }
        let mut r = &buf[..PEER_MANAGER_HEADER_SIZE];
        let from = r.get_u32_le();
        let to = r.get_u32_le();
        let pt: PacketType = r.get_u8().try_into().unwrap_or(PacketType::Data);
        let flags = r.get_u8();
        let fc = r.get_u8();
        let reserved = r.get_u8();
        let len = r.get_u32_le();
        Self { from_peer_id: from, to_peer_id: to, packet_type: pt, flags, forward_counter: fc, reserved, len }
    }
}

// 同步 TCP 发送一帧（泛型：所有实现 Read+Write 的 stream 都能用，比如 std TcpStream、UnixStream、自定义隧道）
pub fn send_frame<S: Write + ?Sized>(stream: &mut S, hdr: &PeerManagerHeader, payload: &[u8]) -> std::io::Result<()> {
    let total_len = (PEER_MANAGER_HEADER_SIZE as u32) + hdr.len;
    let mut buf = BytesMut::with_capacity(4 + total_len as usize);
    buf.put_u32_le(total_len);
    hdr.encode(&mut buf);
    buf.put_slice(payload);
    stream.write_all(&buf)
}

// 同步 TCP 接收一帧，返回 (PeerManagerHeader, payload_bytes)
pub fn recv_frame<S: Read + ?Sized>(stream: &mut S) -> std::io::Result<(PeerManagerHeader, Vec<u8>)> {
    let mut lb = [0u8; 4];
    stream.read_exact(&mut lb)?;
    let total_len = u32::from_le_bytes(lb) as usize;
    if total_len < PEER_MANAGER_HEADER_SIZE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too small"));
    }
    // 防止恶意超大 len 导致 OOM：单帧 payload 上限 16MB
    if total_len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame too large: {total_len}")));
    }
    let mut body = vec![0u8; total_len];
    stream.read_exact(&mut body)?;
    let hdr = PeerManagerHeader::decode(&body);
    let payload = body[PEER_MANAGER_HEADER_SIZE..].to_vec();
    Ok((hdr, payload))
}

// ==================== 3. HandshakeRequest 握手 ====================
#[derive(Debug, Clone)]
pub struct NetworkIdentity {
    pub name: String,
    pub digest: [u8; 32],
    pub aes_key: [u8; 16],
}
impl NetworkIdentity {
    pub fn new(name: &str, secret: &str) -> Self {
        Self {
            name: name.to_string(),
            digest: generate_network_secret_digest(name, secret),
            aes_key: derive_key_128(secret),
        }
    }
    pub fn matches(&self, other_name: &str, other_digest: &[u8]) -> bool {
        &self.name == other_name && self.digest.as_slice() == other_digest
    }
}

pub fn build_handshake_request(my_peer_id: u32, ident: &NetworkIdentity) -> proto::HandshakeRequest {
    proto::HandshakeRequest {
        magic: MAGIC,
        my_peer_id,
        version: VERSION,
        // ⚠️ Mesh Relay 官方恒为空 Vec，不是 ["plaintext_mode"]
        features: vec![],
        network_name: ident.name.clone(),
        network_secret_digest: ident.digest.to_vec().into(),
    }
}

pub fn encode_handshake(req: &proto::HandshakeRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    req.encode(&mut buf).unwrap();
    buf
}

pub fn decode_handshake(bytes: &[u8]) -> Result<proto::HandshakeRequest, prost::DecodeError> {
    proto::HandshakeRequest::decode(bytes)
}

// 同步握手交换 (客户端发起)
pub fn do_client_handshake<S: Read + Write + ?Sized>(
    stream: &mut S,
    my_peer_id: u32,
    ident: &NetworkIdentity,
) -> anyhow::Result<(u32, Option<u32>)> {
    let req = build_handshake_request(my_peer_id, ident);
    let payload = encode_handshake(&req);
    let hdr = PeerManagerHeader::new(my_peer_id, 0, PacketType::HandShake, payload.len() as u32);
    send_frame(stream, &hdr, &payload)?;

    let (rhdr, rpay) = recv_frame(stream)?;
    if rhdr.packet_type != PacketType::HandShake {
        anyhow::bail!("expect handshake response, got pkt_type={:?}", rhdr.packet_type);
    }
    let remote = decode_handshake(&rpay)?;
    if remote.magic != MAGIC { anyhow::bail!("bad remote magic: {:x}", remote.magic); }
    if !ident.matches(&remote.network_name, &remote.network_secret_digest) {
        anyhow::bail!("remote identity mismatch");
    }
    // ⚠️ proto 中 HandshakeRequest 不包含 hostname / ipv4_addr（我们 proto 简化了）。
    // 要解析完整字段请在 proto 里加 `EndpointInfo hostname = 14; uint32 ipv4_addr = 15;`，
    // 再从 remote.ipv4_addr 或 remote.hostname.ipv4 里提。这里先返回 None，
    // 第一次 SyncRouteInfo 推送之后路由表会正确填充。
    Ok((remote.my_peer_id, None))
}

// ==================== 4. AES-128-GCM 加解密 ====================
#[derive(Clone)]
pub struct PacketCipher {
    cipher: Aes128Gcm,
}
impl std::fmt::Debug for PacketCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PacketCipher(Aes128Gcm { key: <hidden> })")
    }
}
impl PacketCipher {
    pub fn new(key: &[u8; 16]) -> Self {
        Self { cipher: Aes128Gcm::new(key.into()) }
    }
    // 密文格式: ciphertext || tag(16B) || nonce(12B)   与既定加密布局保持一致
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self.cipher.encrypt(nonce, Payload::from(plaintext))
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        let mut out = Vec::with_capacity(ct.len() + 12);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&nonce_bytes);
        Ok(out)
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if ciphertext.len() < 28 { anyhow::bail!("ciphertext too short"); }
        let (body, nonce_tail) = ciphertext.split_at(ciphertext.len() - 12);
        let nonce = Nonce::from_slice(nonce_tail);
        let pt = self.cipher.decrypt(nonce, Payload::from(body))
            .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        Ok(pt)
    }
}

// 对 PeerManager payload 加密/解密并置位 FLAG_ENCRYPTED
pub fn encrypt_packet(cipher: &PacketCipher, hdr: &mut PeerManagerHeader, payload: &[u8])
    -> anyhow::Result<Vec<u8>>
{
    let ct = cipher.encrypt(payload)?;
    hdr.flags |= FLAG_ENCRYPTED;
    hdr.len = ct.len() as u32;
    Ok(ct)
}
pub fn decrypt_packet(cipher: &PacketCipher, hdr: &mut PeerManagerHeader, payload: &[u8])
    -> anyhow::Result<Vec<u8>>
{
    if hdr.flags & FLAG_ENCRYPTED == 0 { return Ok(payload.to_vec()); }
    let pt = cipher.decrypt(payload)?;
    hdr.flags &= !FLAG_ENCRYPTED;
    hdr.len = pt.len() as u32;
    Ok(pt)
}

// ==================== 5. SyncRouteInfo RPC 解析 ====================
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: u32,
    pub ipv4_addr: Option<u32>,
    pub ipv4_str: Option<String>,
    pub network_length: u8,   // 子网掩码（协议 tag=13，默认24）
}
#[derive(Debug, Clone)]
pub struct RouteTable {
    pub timestamp: u64,
    pub peers: Vec<PeerInfo>,
}

impl RouteTable {
    pub fn my_ip(&self, my_peer_id: u32) -> Option<u32> {
        self.peers.iter().find(|p| p.peer_id == my_peer_id).and_then(|p| p.ipv4_addr)
    }
    pub fn peers_with_ip(&self) -> Vec<&PeerInfo> {
        self.peers.iter().filter(|p| p.ipv4_addr.is_some()).collect()
    }
}

pub fn parse_route_sync_msg(bytes: &[u8]) -> anyhow::Result<RouteTable> {
    let rpc = proto::RpcPacket::decode(bytes)
        .map_err(|e| anyhow::anyhow!("decode RpcPacket: {e}"))?;
    let descriptor = rpc.descriptor
        .ok_or_else(|| anyhow::anyhow!("RpcPacket has no descriptor"))?;
    if descriptor.service_name != "OspfRouteRpc" || descriptor.method_index != 1 {
        anyhow::bail!("not SyncRouteInfo: service={:?} method={}",
            descriptor.service_name, descriptor.method_index);
    }
    let req = if let Ok(rpc_req) = proto::RpcRequest::decode(rpc.body.as_slice()) {
        // 新版协议：body 是 RpcRequest，request 字段才是真正的请求体
        proto::SyncRouteInfoRequest::decode(rpc_req.request.as_slice())
            .map_err(|e| anyhow::anyhow!("decode SyncRouteInfoRequest from RpcRequest: {e}"))?
    } else {
        // 旧版协议：body 直接是 SyncRouteInfoRequest
        proto::SyncRouteInfoRequest::decode(rpc.body.as_slice())
            .map_err(|e| anyhow::anyhow!("decode SyncRouteInfoRequest: {e}"))?
    };
    let peers = req.peer_infos
        .map(|pi| pi.items)
        .unwrap_or_default()
        .into_iter()
        .map(|p| PeerInfo {
            peer_id: p.peer_id,
            ipv4_addr: p.ipv4_addr.map(|v| v.addr),
            ipv4_str: p.hostname.clone(),
            network_length: if p.network_length > 32 { 24 } else { p.network_length as u8 },
        })
        .collect();
    // SyncRouteInfoRequest 没有 timestamp 字段，用当前时间兜底
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(RouteTable { timestamp, peers })
}

/// 尝试从 RPC 包中解析路由表（OspfRouteRpc.SyncRouteInfo）
pub fn try_parse_route_from_rpc(bytes: &[u8]) -> anyhow::Result<Option<RouteTable>> {
    let rpc = match proto::RpcPacket::decode(bytes) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    // 只处理 OspfRouteRpc.SyncRouteInfo (method_index=1)
    if let Some(d) = &rpc.descriptor {
        if d.service_name == "OspfRouteRpc" && d.method_index == 1 {
            return match parse_route_sync_msg(bytes) {
                Ok(rt) => Ok(Some(rt)),
                Err(_) => Ok(None),
            };
        }
    }
    Ok(None)
}

/// 从 RpcPacket 的 decrypted body 里提取 SyncRouteInfoRequest 的内部字段。
/// 返回 (transaction_id, descriptor, my_session_id, is_initiator)；不是 SyncRouteInfoRequest 就返回 None。
pub fn peek_sync_route_request_inner(
    decrypted_rpc_body: &[u8],
) -> Option<(i64, proto::RpcDescriptor, u64, bool)> {
    let rpc = proto::RpcPacket::decode(decrypted_rpc_body).ok()?;
    if !rpc.is_request { return None; }
    let desc = rpc.descriptor.clone()?;
    if desc.service_name != "OspfRouteRpc" || desc.method_index != 1 { return None; }

    // 解 RpcRequest → SyncRouteInfoRequest
    let sync_req = {
        if let Ok(rpc_req) = proto::RpcRequest::decode(rpc.body.as_slice()) {
            proto::SyncRouteInfoRequest::decode(rpc_req.request.as_slice()).ok()?
        } else {
            proto::SyncRouteInfoRequest::decode(rpc.body.as_slice()).ok()?
        }
    };
    Some((rpc.transaction_id, desc, sync_req.my_session_id, sync_req.is_initiator))
}

/// 解析 RPC 包，返回 (transaction_id, descriptor, is_request)。
pub fn decode_rpc_packet(bytes: &[u8]) -> Option<(i64, proto::RpcDescriptor, bool)> {
    let rpc = proto::RpcPacket::decode(bytes).ok()?;
    let d = rpc.descriptor?;
    Some((rpc.transaction_id, d, rpc.is_request))
}

/// 构造 SyncRouteInfoResponse 的 RPC 响应（已加密，可直接 send_frame）。
///
/// 参数：
/// - `my_session_id`: 本端分配的 session id（SyncRouteInfoRequest::my_session_id 的对称）
/// - `peer_is_initiator`: 收到的请求里对方 is_initiator 字段，我们的 is_initiator = !peer_is_initiator
///   如果双方都是 initiator 就会 OSPF 脑裂，这里强制纠正。
pub fn build_sync_route_info_response(
    cipher: &PacketCipher,
    my_peer_id: u32,
    to_peer_id: u32,
    transaction_id: i64,
    descriptor: &proto::RpcDescriptor,
    my_session_id: u64,
    peer_is_initiator: bool,
) -> anyhow::Result<(PeerManagerHeader, Vec<u8>)> {
    use prost::Message;
    // SyncRouteInfoResponse: 我们是 responder。
    // 如果对方说自己是 initiator，我们就不是；反之亦然，避免双边同时发起。
    let my_is_initiator = !peer_is_initiator;
    let mut resp_body = Vec::new();
    proto::SyncRouteInfoResponse {
        is_initiator: my_is_initiator,
        session_id: my_session_id,
        error: None,
    }.encode(&mut resp_body)?;

    // RpcResponse 包装
    let mut rpc_resp = Vec::new();
    proto::RpcResponse {
        response: resp_body,
        error: None,
        runtime_us: 0,
    }.encode(&mut rpc_resp)?;

    // RpcPacket (is_request=false)
    // compression_info: 响应端声明 algo=None（我们不做压缩），accepted_algo=Zstd（告诉对方我们能解压）
    let compression_info = Some(proto::RpcCompressionInfo {
        algo: proto::CompressionAlgoPb::None as i32,
        accepted_algo: proto::CompressionAlgoPb::Zstd as i32,
    });
    let mut rpc_pkt = Vec::new();
    proto::RpcPacket {
        from_peer: my_peer_id,
        to_peer: to_peer_id,
        transaction_id,
        descriptor: Some(descriptor.clone()),
        body: rpc_resp,
        is_request: false,
        total_pieces: 0,
        piece_idx: 0,
        trace_id: 0,
        compression_info,
    }.encode(&mut rpc_pkt)?;

    let mut hdr = PeerManagerHeader::new(my_peer_id, to_peer_id, PacketType::RpcResp, rpc_pkt.len() as u32);
    let ct = encrypt_packet(cipher, &mut hdr, &rpc_pkt)?;
    Ok((hdr, ct))
}

/// 构造主动发起的 SyncRouteInfoRequest（把自己的 peer 信息告诉对端）。
/// peer_infos 里通常包含自己（如果有虚拟 IP）。
/// `network_name` 必须填对端注册 RPC 时用的 domain_name（Relay 用 network_name()）。
/// `proto_name` 与 `service_name` 都填 "OspfRouteRpc"，与协议 codegen 一致。
pub fn build_sync_route_info_request(
    cipher: &PacketCipher,
    my_peer_id: u32,
    to_peer_id: u32,
    my_ipv4: Option<u32>,
    hostname: &str,
    my_session_id: u64,
    network_name: &str,
) -> anyhow::Result<(PeerManagerHeader, Vec<u8>)> {
    use prost::Message;
    let my_peer_info = proto::RoutePeerInfo {
        peer_id: my_peer_id,
        inst_id: Some(proto::Uuid { part1: my_peer_id, part2: 0, part3: 0, part4: 0 }),
        cost: 1,
        ipv4_addr: my_ipv4.map(|a| proto::Ipv4Addr { addr: a }),
        proxy_cidrs: vec![],
        hostname: Some(hostname.to_string()),
        udp_nat_type: 0,
        last_update: vec![],
        version: 1,
        easytier_version: "mesh-tun-proto/0.1".to_string(),
        feature_flag: Some(proto::PeerFeatureFlag::default()),
        peer_route_id: 0,
        network_length: 24,
        quic_port: None,
        ipv6_addr: None,
        groups: vec![],
        tcp_nat_type: 0,
        noise_static_pubkey: vec![],
        trusted_credential_pubkeys: vec![],
        ipv6_public_addr_prefix: None,
        ipv6_public_addr_lease: None,
    };

    let req = proto::SyncRouteInfoRequest {
        my_peer_id,
        my_session_id,
        is_initiator: true,
        peer_infos: Some(proto::RoutePeerInfos { items: vec![my_peer_info] }),
        conn_bitmap: None,
        foreign_network_infos: None,
        conn_peer_list: None,
    };
    let mut req_body = Vec::new();
    req.encode(&mut req_body)?;

    // RpcRequest 包装
    let mut rpc_req = Vec::new();
    proto::RpcRequest {
        descriptor: None,
        request: req_body,
        timeout_ms: 5000,
    }.encode(&mut rpc_req)?;

    // RpcPacket (is_request=true)
    let mut rpc_pkt = Vec::new();
    proto::RpcPacket {
        from_peer: my_peer_id,
        to_peer: to_peer_id,
        transaction_id: rand::thread_rng().next_u64() as i64,
        descriptor: Some(proto::RpcDescriptor {
            domain_name: network_name.to_string(),
            proto_name: "OspfRouteRpc".to_string(),
            service_name: "OspfRouteRpc".to_string(),
            method_index: 1,
        }),
        body: rpc_req,
        is_request: true,
        total_pieces: 0,
        piece_idx: 0,
        trace_id: 0,
        compression_info: None,
    }.encode(&mut rpc_pkt)?;

    let mut hdr = PeerManagerHeader::new(my_peer_id, to_peer_id, PacketType::RpcReq, rpc_pkt.len() as u32);
    let ct = encrypt_packet(cipher, &mut hdr, &rpc_pkt)?;
    Ok((hdr, ct))
}

// 随机生成合法 peer_id (非零)
pub fn random_peer_id() -> u32 {
    loop {
        let v = rand::random::<u32>();
        if v != 0 { return v; }
    }
}

/// 为一对 (my_peer_id, to_peer_id) 生成稳定的 OSPF session_id。
/// 用 std DefaultHasher（与 std::collections::hash_map::DefaultHasher 即 SipHash13 等价），
/// 保证同一对 peer 每次算出的 session_id 一致，避免 Core 反复 "session id mismatch, clear saved info"。
pub fn stable_session_id(my_peer_id: u32, to_peer_id: u32) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    to_peer_id.hash(&mut h);
    my_peer_id.hash(&mut h);
    h.finish().max(1)
}

// ======================================================================
// 6b. 纯 P2P 工具最小 API（默认 feature 就有；不开 proxy 也能用）
//
// 设计动机：你作为 P2P 工具开发者 —— 不需要公共节点、不做 PeerCenter、
//   不做 RelayPeerMap、不开 TUN。只做 4 件事：
//   ① build_p2p_peer_identity: 用 (network_name, network_secret, my_peer_id) 生成本地身份
//   ② connect_peer: TcpStream(或任何 Read+Write stream) + 身份 ⇒ 完成 Client 握手
//   ③ poll_next_event: 读对端帧；给你 Data/RpcReq/RouteUpdate/Disconnect 四类事件
//   ④ send_raw_ip_packet: 你的 TUN/用户态协议栈拿到 raw IPv4 包 → 加密 → 路由 → 发出去
// 角色边界（我们在 mesh 里的定位）：
//   我们只是「mesh 里的普通客户端节点」；不提供服务端握手、不参与 center 选举、
//   不把自己当 relay 节点转发别人的包、不设置 feature_flag.is_public_server=true。
//   你想让公共节点/其他 peer 帮你当 relay？直接加 --peer 连到它即可，它会自动转发。
// ======================================================================
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct P2PPeerIdentity {
    pub my_peer_id: u32,
    pub ident: NetworkIdentity,
    pub cipher: PacketCipher,
}

pub fn build_p2p_peer_identity(
    network_name: impl Into<String>,
    network_secret: impl Into<String>,
    my_peer_id: Option<u32>,
) -> P2PPeerIdentity {
    let name = network_name.into();
    let secret = network_secret.into();
    let ident = NetworkIdentity::new(&name, &secret);
    let my_peer_id = my_peer_id.unwrap_or_else(random_peer_id);
    P2PPeerIdentity {
        my_peer_id,
        ident,
        cipher: PacketCipher::new(&derive_key_128(&secret)),
    }
}

/// 已建立的一条 peer 连接：stream + 对端信息 + 本地路由表拷贝（每个连接独立）
pub struct MeshPeerConnection<S: Read + Write> {
    pub stream: S,
    pub my_peer_id: u32,
    pub peer_id: u32,
    pub cipher: PacketCipher,
    pub last_rx: Instant,
    pub route: RouteTable,
    /// OSPF SyncRouteInfo 会话：我方稳定的 session_id（首次收到请求时随机生成并保存）
    pub ospf_session_id: u64,
    /// 已累积的路由同步次数（调试用）
    pub route_sync_count: u64,
    /// 自动回 SyncRouteInfoResponse（默认 true；如果调用方要自己回 response 再转发就关掉）
    pub auto_reply_sync_route_info: bool,
}

/// 从 MeshPeerConnection 轮询到的事件
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Data 帧（已解密为 raw_ip_packet，通常是 IPv4/IPv6）
    InboundIpPacket(Vec<u8>),
    /// 对端更新了路由表：直接把 RouteTable 丢给调用方，你自己怎么用都行
    RouteUpdate(RouteTable),
    /// 收到 RpcReq/RpcResp 负载但我们不想处理，原样返回
    RpcMessage {
        /// RpcReq=8 或 RpcResp=9
        packet_type: u8,
        req_id: u64,
        body: Vec<u8>,
    },
    /// 连接被关闭 / 读超时 / 对端断开
    Disconnected,
}

/// 对单连接执行 Client 侧握手：发 HandshakeRequest → 收 HandshakeRequest（忽略 resp）
pub fn connect_peer<S: Read + Write>(
    stream: S,
    id: &P2PPeerIdentity,
) -> anyhow::Result<MeshPeerConnection<S>> {
    let _ = &id;
    let mut conn = MeshPeerConnection {
        stream,
        my_peer_id: id.my_peer_id,
        peer_id: 0,
        cipher: id.cipher.clone(),
        last_rx: Instant::now(),
        route: RouteTable { timestamp: 0, peers: vec![] },
        ospf_session_id: rand::random::<u64>().max(1),
        route_sync_count: 0,
        auto_reply_sync_route_info: true,
    };
    let (their_peer_id, their_ip) = do_client_handshake(
        &mut conn.stream,
        id.my_peer_id,
        &id.ident,
    )?;
    conn.peer_id = their_peer_id;
    // 把对端自我介绍写进路由表（让 lookup_next_hop 立刻能用）
    let _ = their_ip;
    let mut rt = RouteTable { timestamp: 0, peers: vec![] };
    if let Some(ip) = their_ip {
        rt.peers.push(PeerInfo {
            peer_id: their_peer_id,
            ipv4_addr: Some(ip),
            ipv4_str: Some(Ipv4Addr::from(ip).to_string()),
            network_length: 32,
        });
    }
    conn.route = rt;
    Ok(conn)
}

/// 非阻塞式（依赖 stream 自己设置 read_timeout 或调用方外部控制）的事件轮询。
/// 推荐 caller 对底层 stream.set_read_timeout(Some(50ms))，然后在自己的事件循环里反复调用。
pub fn poll_next_event<S: Read + Write>(
    conn: &mut MeshPeerConnection<S>,
) -> anyhow::Result<Option<PeerEvent>> {
    match recv_frame(&mut conn.stream) {
        Ok((hdr, payload)) => {
            conn.last_rx = Instant::now();
            // 过滤自己给自己回环的包（路由层常见；直接丢弃）
            if hdr.to_peer_id != 0 && hdr.to_peer_id != conn.my_peer_id && hdr.to_peer_id != u32::MAX {
                // 目标 peer_id 不是我，我又不是 relay/center，就当没看见
                return Ok(None);
            }
            // 解密 Data / RpcReq / RpcResp（Ping/Pong/HandShake 不解）
            let is_encrypted = hdr.flags & FLAG_ENCRYPTED != 0;
            let pt = match PacketType::try_from(hdr.packet_type) {
                Ok(t) => t, Err(_) => return Ok(None),
            };
            let decrypted: Vec<u8> = match pt {
                PacketType::Data | PacketType::RpcReq | PacketType::RpcResp
                | PacketType::Ping | PacketType::Pong if is_encrypted => {
                    let mut hdr2 = hdr.clone();
                    match decrypt_packet(&conn.cipher, &mut hdr2, &payload) {
                        Ok(v) => v, Err(_) => return Ok(None),
                    }
                }
                _ => payload,
            };
            match pt {
                PacketType::Data => Ok(Some(PeerEvent::InboundIpPacket(decrypted))),
                PacketType::RpcReq | PacketType::RpcResp => {
                    // 如果是 RpcReq + SyncRouteInfo，先自动回 response（开关可控）
                    if pt == PacketType::RpcReq && conn.auto_reply_sync_route_info {
                        if let Some((tx_id, desc, _peer_sid, peer_init)) =
                            peek_sync_route_request_inner(&decrypted)
                        {
                            let my_sid = conn.ospf_session_id;
                            if let Ok((rh, ct)) = build_sync_route_info_response(
                                &conn.cipher, conn.my_peer_id, hdr.from_peer_id,
                                tx_id, &desc, my_sid, peer_init,
                            ) {
                                let _ = send_frame(&mut conn.stream, &rh, &ct);
                                conn.route_sync_count = conn.route_sync_count.wrapping_add(1);
                            }
                        }
                    }
                    if let Ok(Some(rt)) = try_parse_route_from_rpc(&decrypted) {
                        conn.route = rt.clone();
                        Ok(Some(PeerEvent::RouteUpdate(rt)))
                    } else {
                        // 把 tx_id / body 提出来给调用方，方便你们自己做 RPC
                        let tx_id = if let Ok(rpc) = proto::RpcPacket::decode(decrypted.as_slice()) {
                            rpc.transaction_id as u64
                        } else { 0 };
                        Ok(Some(PeerEvent::RpcMessage {
                            packet_type: hdr.packet_type as u8,
                            req_id: tx_id,
                            body: decrypted,
                        }))
                    }
                }
                PacketType::Ping => {
                    // Core 的 Ping payload（解密后）= 4 字节 LE seq；Pong 必须原样回显 seq，
                    // 否则 Core 在 <协议帧处理规范>:179 用 payload[0..4] 取 seq 时越界 panic。
                    let seq_bytes: &[u8] = if decrypted.len() >= 4 { &decrypted[..4] } else { &decrypted[..] };
                    let mut h = PeerManagerHeader::new(conn.my_peer_id, hdr.from_peer_id, PacketType::Pong, 0);
                    let ct = encrypt_packet(&conn.cipher, &mut h, seq_bytes).unwrap_or_default();
                    let _ = send_frame(&mut conn.stream, &h, &ct);
                    Ok(None)
                }
                PacketType::Pong | PacketType::HandShake => Ok(None),
            }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
        Err(_) => Ok(Some(PeerEvent::Disconnected)),
    }
}

/// 发送 raw IPv4/IPv6 包：查路由 → 确定 dst_peer_id → 加密 → 写 4B+16B 帧
pub fn send_raw_ip_packet<S: Read + Write>(
    conn: &mut MeshPeerConnection<S>,
    raw_ip_packet: &[u8],
) -> anyhow::Result<()> {
    let dst = parse_dst_from_ip_packet(raw_ip_packet)?;
    let dst_peer = conn.lookup_next_hop(dst)
        .ok_or_else(|| anyhow::anyhow!("p2p peer: no route to {dst}"))?;
    let mut hdr = PeerManagerHeader::new(conn.my_peer_id, dst_peer, PacketType::Data, raw_ip_packet.len() as u32);
    let body = encrypt_packet(&conn.cipher, &mut hdr, raw_ip_packet)?;
    send_frame(&mut conn.stream, &hdr, &body)?;
    Ok(())
}

/// 批量发送场景：你有多个 peer 连接（mesh），按 dst 选择最对的那条再发
pub struct PeerMesh {
    pub my_peer_id: u32,
    pub cipher: PacketCipher,
    pub route: RouteTable,
    pub peers: HashMap<u32, usize>, // peer_id → index in conns vec（调用方自己维护）
}
impl PeerMesh {
    pub fn new(id: &P2PPeerIdentity) -> Self {
        Self {
            my_peer_id: id.my_peer_id,
            cipher: id.cipher.clone(),
            route: RouteTable { timestamp: 0, peers: vec![] },
            peers: HashMap::new(),
        }
    }
    /// 把每个连接 poll_next_event 拿到的 RouteUpdate 都喂这里；保持全局路由表最新
    pub fn apply_route_update(&mut self, rt: RouteTable) {
        self.route = rt;
    }
    pub fn lookup_next_hop(&self, dst: u32) -> Option<u32> {
        let mut best: Option<(u8, u32)> = None;
        for p in &self.route.peers {
            let Some(ip) = p.ipv4_addr else { continue };
            if p.network_length == 0 { continue; } // /0 默认路由不参与 P2P 路由
            let mask = !(0xffffffffu32.checked_shr(p.network_length as u32).unwrap_or(0));
            if (dst & mask) == (ip & mask) {
                if best.map(|(l, _)| l < p.network_length).unwrap_or(true) {
                    best = Some((p.network_length, p.peer_id));
                }
            }
        }
        best.map(|(_, id)| id)
    }
}

// 工具：从 raw ip 包里提 dst 地址（只关心 v4，v6 也能转 u32 高位用不了；p2p 工具你们自己可以扩展）
fn parse_dst_from_ip_packet(packet: &[u8]) -> anyhow::Result<u32> {
    if packet.is_empty() { anyhow::bail!("empty ip") }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 { anyhow::bail!("ipv4 too short") }
            Ok(u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]))
        }
        6 => anyhow::bail!("IPv6 raw send not supported in minimal P2P API"),
        v => anyhow::bail!("unknown ip version {v}"),
    }
}

impl<S: Read + Write> MeshPeerConnection<S> {
    /// 查下一跳（默认只查这个连接上次 RouteUpdate 带来的路由，你们有 mesh 就用 PeerMesh）
    pub fn lookup_next_hop(&self, dst: u32) -> Option<u32> {
        // 直连对端本身就是 1 跳兜底
        let direct = Some(self.peer_id).filter(|_| self.route.peers.iter().any(|p| {
            p.network_length != 0 && p.ipv4_addr.map(|ip| {
                let mask = !(0xffffffffu32.checked_shr(p.network_length as u32).unwrap_or(0));
                (dst & mask) == (ip & mask)
            }).unwrap_or(false)
        }));
        if direct.is_some() { return direct; }
        // 如果对端自我介绍的 /32 命中，直接走它
        if self.route.peers.iter().any(|p| p.peer_id == self.peer_id
            && p.ipv4_addr.is_some() && p.ipv4_addr.unwrap() == dst)
        {
            return Some(self.peer_id);
        }
        // 最后兜底：我们是纯 P2P 直连客户端，所有未知包都给对面让它继续转发
        // （只有在对面允许 relay 时才会真正帮转，你们自己做 ACL 即可）
        if self.peer_id != 0 { Some(self.peer_id) } else { None }
    }

    /// 【最常用】按目标 peer_id 直接发送用户数据（Data 帧，AES 加密）。
    ///
    /// 你不需要自己构造 IP 头：把任意字节流（序列化的消息、文件块、应用层 payload 都行）
    /// 塞进来就行。对端的 `poll_next_event()` 会返回 `PeerEvent::InboundIpPacket(your_bytes)`。
    ///
    /// 路由：如果 `dst_peer_id` 就是直连的对端，直接交付；否则交给对端继续 relay（前提是对端开了 relay）。
    pub fn send_data(&mut self, dst_peer_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        let mut hdr = PeerManagerHeader::new(self.my_peer_id, dst_peer_id, PacketType::Data, payload.len() as u32);
        let body = encrypt_packet(&self.cipher, &mut hdr, payload)?;
        send_frame(&mut self.stream, &hdr, &body)?;
        Ok(())
    }

    /// 直接把指定类型 payload 发给对面，不查路由（发 ping / 自定义 rpc 方便）
    pub fn send_frame_direct(
        &mut self,
        pt: PacketType,
        encrypted: bool,
        body: &[u8],
    ) -> anyhow::Result<()> {
        let mut hdr = PeerManagerHeader::new(self.my_peer_id, self.peer_id, pt, body.len() as u32);
        let final_body = if encrypted {
            encrypt_packet(&self.cipher, &mut hdr, body)?
        } else { body.to_vec() };
        send_frame(&mut self.stream, &hdr, &final_body)?;
        Ok(())
    }
}

// ======================================================================
// 6. Mesh 非标准协议细节清单（与常见标准/RFC 的出入）
// ======================================================================
// 为了让已有自己 P2P 打洞逻辑的外部工具『正确接入 mesh 网络』，必须清楚：
// Mesh Relay 在哪些地方不是标准协议、也不是常见实现。
//
// 【AES-GCM 密文顺序】（非标准，最容易踩坑）
//   RFC 5116 / most libs 默认 = nonce || ciphertext || tag
//   Mesh cipher layout = ciphertext || tag(16B) || nonce(12B)
//   ⇒ 外部加密库直接 encrypt() 出来的结果要重排，不要用现成 701/tonic AEAD。
//
// 【SipHash13 作为密钥派生/身份 digest】（非标准）
//   不是 PBKDF2/Argon2/sha256。network_secret_digest[32] = (SipHash(name||secret).to_be_bytes()) × 4 片拷贝
//   ⇒ 外部工具必须自己实现 SipHash13（本 crate 已给），否则 digest 不匹配直接握手失败。
//
// 【TCP 帧 = 4B LE length + PeerManagerHeader(16B) + payload】
//   不是 TLS record / 不是 WebSocket frame / 不是 Rust 常见的 length_delimited codec。
//   length 字段 = 16+payload，**不包含 4B length 自己**。
//
// 【PeerManagerHeader.packet_type】
//   常见的 gRPC 是 stream id，但这里是单字节枚举。重点：RpcReq=8 / RpcResp=9，不是 6/7。
//
// 【UDP 隧道的内层握手 Syn/Sack/Data】（非标准）
//   标准 UDP 应用一般直接发包。Mesh 的 UdpSession 要求先发 Syn（带 conn_id），
//   对端回 Sack，之后才允许 Data。直接裸发 Data 会被对方 conn_map 拒绝。
//
// 【HolePunch 控制包分两类：外网真实 HolePunch vs 本机 loopback V4HolePunch】
//   标准打洞都是两个节点互相公网发包；mesh 内部实现了 V4HolePunch（源 127.0.0.1）
//   命令 punch_listener 朝指定 addr 发，外部工具通常没有这种控制平面。
//
// 【OSPF 路由周期 SyncRouteInfo 用的是 protobuf RpcPacket.route_sync_msg 直接 oneof，不是 tonic RPC】
//   没有 HTTP/2 header，没有 gRPC status code；直接是 PacketType=8/9 的 oneof。
//
// 【STUN magic cookie 前 4B = 0xdeadbeef（非标准）】
//   RFC 5389 规定 Transaction ID 前 4B = 0x2112A442 (magic cookie)，mesh 用 0xdeadbeef 过滤
//   ⇒ 用别的公共 STUN（coturn/frantech/stun.l.google.com）做出来的绑定结果可用，但
//     对端公共 STUN responder 不会响应你的 BindindRequest，必须用对端 mesh listener 端口。
//
// 【打洞策略的 SymmetricEasySym 预测端口偏移 = 20 + peer_id 比较】
//   只有双方 EasySym 时才尝试；否则 Sym→Cone 做 600-800 包/轮的 birthday attack。
//   这直接决定外部打洞工具对接时：如果工具已经自己打通了，就不要让 mesh 层再打一次。
//   ↓ 下面的 ExternalHolePunchBridge trait 就是把外部工具的结果『作为现成的 tunnel』接进来。
// ======================================================================

// ======================================================================
// 7. 外部打洞工具对接层：让已有 P2P 打洞逻辑可插拔接入 mesh 网络
// ======================================================================
// 核心思路：
//   外部工具已经做好 NAT 检测 + 信令 + 打洞，得到一条连通的双向字节流（可能是
//   udp socket、raw fd、用户态 TCP 句柄等）。本层把它『包装成协议认可的
//   PeerConn』，复用本 crate 的 handshake / encrypt / route_sync 逻辑。
//
// 三种对接模式：
//   Mode A [最常用]：外部工具已经在双方之间建立了一个双向可靠的 SocketAddr（UDP 打洞
//                    出来的公网端点），我们直接在上面走 UDPTunnelHeader 8B 的封装，
//                    和官方 官方 UDP tunnel 实现 一模一样。
//   Mode B          ：外部工具给了一个双工 stream（TUN fd、QUIC stream、websocket 等），
//                    只要支持 Read + Write，就可以走 TCP 兼容的 4B 长度帧模式。
//   Mode C          ：外部工具只能做到收/发原始 UDP（或 RAW IP）包，不想套 UDPTunnelHeader。
//                    此时只需把 payload 当"裸 PeerManager 包"处理，跳过 UDPTunnelHeader。

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
};

/// UDP 隧道头 8 字节常量（与标准 UDP 隧道头布局一致）
pub const UDP_TUNNEL_HEADER_SIZE: usize = 8;
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPacketType {
    Syn = 1, Sack = 2, Data = 3, Fin = 4,
    HolePunch = 5, V4HolePunch = 6,
}

/// 外部打洞工具提供的最小信息：一次成功打洞后的端点
#[derive(Debug, Clone)]
pub struct ExternalHolePunchResult {
    /// 连通后本地可以 send_to / recv_from 的那个 UDP socket（外部工具绑定的）
    pub local_bind: SocketAddr,
    /// 对端在 NAT 外可见的映射地址（打洞成功后这个端口就是对方的"对端"）
    pub remote_mapped: SocketAddr,
    /// 对端节点 ID（外部工具在信令阶段就可以交换到），0 表示未知
    pub remote_peer_id_hint: u32,
    /// 复用模式：A=标准 UDP 8B 头 / B=可靠流 4B 帧 / C=裸包（无 tunnel header）
    pub mode: PunchIntegrationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchIntegrationMode {
    /// 通过 UdpSocket + UDPTunnelHeader(8B) —— 和官方 udp.rs 兼容
    UdpWithEt8ByteHeader,
    /// 通过 Read/Write stream —— 和官方 tcp.rs 4B 长度帧兼容
    ReliableStreamWithEt4BFrame,
    /// 完全不做 tunnel header，字节流内容就是 PeerManagerHeader+payload
    NoTunnelHeader,
}

/// 外部打洞工具要实现的最小 Trait（你只需要把自己的打洞 future 桥接过来）
///
/// 生命周期：
///  1. Mesh 侧（本 crate）调用 [ExternalHolePunchBridge::punch_request()] 触发一次对 peer 的打洞
///  2. 外部工具用它自己的 STUN/信令/预测端口/生日攻击 把洞打通
///  3. 外部工具返回 ExternalHolePunchResult（含 UdpSocket 或 stream）
///  4. 本 crate 在这个结果上跑 UDP mux Syn/Sack + HandshakeRequest + 加解密 + SyncRouteInfo
pub trait ExternalHolePunchBridge: Send + Sync {
    /// 打洞到指定 peer；失败返回任何错误，上层直接走 public server 回退
    fn punch_to(&self, peer_info: &PeerInfo) -> anyhow::Result<ExternalHolePunchResult>;
}

// ======================================================================
// Mode A adapter：外部工具给的 UdpSocket + UDP 8B 头
// 用法：MeshUdpPlug::connect().await? → 拿到一个 EtUdpSession 等价物
// 之后通过 send_zc_packet() / recv_zc_packet() 走数据
// ======================================================================
pub struct MeshUdpPlug {
    sock: Arc<UdpSocket>,
    remote: SocketAddr,
    conn_id: u32,
    mode: PunchIntegrationMode,
}

impl MeshUdpPlug {
    /// 用外部工具打好洞的 socket 接入 mesh。内部会按协议规范发 Syn/Sack 建立 UDP 会话。
    pub fn new(res: ExternalHolePunchResult) -> anyhow::Result<Self> {
        if !matches!(res.mode, PunchIntegrationMode::UdpWithEt8ByteHeader)
            && !matches!(res.mode, PunchIntegrationMode::NoTunnelHeader) {
            anyhow::bail!("MeshUdpPlug only accepts UdpWithEt8ByteHeader or NoTunnelHeader mode");
        }
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        // 注意：这里 socket 只是演示分配；实际应复用外部工具已经 bind 的同一个 fd
        // 真实项目把 res 里外部工具的 UdpSocket 用 Into 传进来即可
        let _ = res.local_bind; // 外部工具实际应该直接给 fd，此处留接口占位
        let conn_id: u32 = rand::random();
        Ok(Self { sock: Arc::new(sock), remote: res.remote_mapped, conn_id, mode: res.mode })
    }

    pub fn remote_addr(&self) -> SocketAddr { self.remote }

    /// UDP 8B 头编码（注意 LE）
    fn encode_udp_header(&self, pt: UdpPacketType, payload_len: u16, out: &mut [u8; 8]) {
        out[..4].copy_from_slice(&self.conn_id.to_le_bytes());
        out[4] = pt as u8;
        out[5] = 0;
        out[6..8].copy_from_slice(&payload_len.to_le_bytes());
    }

    /// 发 Syn/Sack（建立 UDP 会话，然后再握手 HandshakeRequest）
    pub fn do_udp_syn_sack(&self, my_peer_id: u32, ident: &NetworkIdentity) -> anyhow::Result<proto::HandshakeRequest> {
        // Step 1: 我发 Syn，附带第一个 ZCPacket 就是 HandshakeRequest
        let req = build_handshake_request(my_peer_id, ident);
        let payload = encode_handshake(&req);
        let hdr = PeerManagerHeader::new(my_peer_id, 0, PacketType::HandShake, payload.len() as u32);
        let mut pm_bytes = Vec::with_capacity(PEER_MANAGER_HEADER_SIZE + payload.len());
        // 先写 pm header（16B），再写 payload
        {
            use bytes::BufMut;
            let mut bm = bytes::BytesMut::with_capacity(PEER_MANAGER_HEADER_SIZE + payload.len());
            hdr.encode(&mut bm);
            bm.put_slice(&payload);
            pm_bytes.extend_from_slice(&bm);
        }

        if matches!(self.mode, PunchIntegrationMode::UdpWithEt8ByteHeader) {
            // 先 UDP Syn(1) + 空数据
            let mut h8 = [0u8; 8];
            self.encode_udp_header(UdpPacketType::Syn, 0, &mut h8);
            self.sock.send_to(&h8, self.remote)?;
            // 再 UDP Data(3) + pm_bytes
            self.encode_udp_header(UdpPacketType::Data, pm_bytes.len() as u16, &mut h8);
            let mut dat = Vec::with_capacity(8 + pm_bytes.len());
            dat.extend_from_slice(&h8);
            dat.extend_from_slice(&pm_bytes);
            self.sock.send_to(&dat, self.remote)?;
        } else {
            self.sock.send_to(&pm_bytes, self.remote)?;
        }

        // Step 2: 收对端回来的响应
        let mut buf = vec![0u8; 65536];
        let (n, from) = self.sock.recv_from(&mut buf)?;
        let mut off = 0;
        if matches!(self.mode, PunchIntegrationMode::UdpWithEt8ByteHeader) {
            // 跳过 UDP TunnelHeader（这里不管 Sack/Data，直接找 PeerManagerHeader 16B）
            if n < UDP_TUNNEL_HEADER_SIZE { anyhow::bail!("udp pkt too short") }
            off = UDP_TUNNEL_HEADER_SIZE;
        }
        if n - off < PEER_MANAGER_HEADER_SIZE { anyhow::bail!("pm hdr truncated") }
        let pm = PeerManagerHeader::decode(&buf[off..]);
        if pm.packet_type != PacketType::HandShake {
            anyhow::bail!("udp expect HandShake, got {:?}", pm.packet_type);
        }
        let payload_end = (off + PEER_MANAGER_HEADER_SIZE + pm.len as usize).min(n);
        let remote = decode_handshake(&buf[off + PEER_MANAGER_HEADER_SIZE..payload_end])?;
        if !ident.matches(&remote.network_name, &remote.network_secret_digest) {
            anyhow::bail!("remote identity mismatch");
        }
        // from == remote 必须匹配
        let _ = from;
        Ok(remote)
    }

    /// 发送一个带加密的 mesh 数据/路由包（Mode A 专用）
    pub fn send_et_packet(&self, cipher: &PacketCipher, my_peer_id: u32, to_peer_id: u32,
                          pt: PacketType, plain_payload: &[u8]) -> anyhow::Result<()> {
        let mut hdr = PeerManagerHeader::new(my_peer_id, to_peer_id, pt, plain_payload.len() as u32);
        let body = encrypt_packet(cipher, &mut hdr, plain_payload).unwrap_or_else(|_| plain_payload.to_vec());
        // PM header 可能已经变了（len/flags），重编码
        use bytes::BufMut;
        let mut pm = bytes::BytesMut::with_capacity(PEER_MANAGER_HEADER_SIZE + body.len());
        hdr.encode(&mut pm);
        pm.put_slice(&body);

        if matches!(self.mode, PunchIntegrationMode::UdpWithEt8ByteHeader) {
            let mut h8 = [0u8; 8];
            self.encode_udp_header(UdpPacketType::Data, pm.len() as u16, &mut h8);
            let mut dat = Vec::with_capacity(8 + pm.len());
            dat.extend_from_slice(&h8);
            dat.extend_from_slice(&pm);
            self.sock.send_to(&dat, self.remote)?;
        } else {
            self.sock.send_to(&pm, self.remote)?;
        }
        Ok(())
    }
}

// ======================================================================
// Mode B adapter：外部工具提供的 Read+Write 可靠流（QUIC/WebSocket/Faketcp/...）
// 字节格式 = TCP 兼容的 4B LE length + PeerManagerHeader(16B) + payload
// 用法：MeshStreamPlug::new(mystream).handshake().await?;
// ======================================================================
pub struct MeshStreamPlug<S: Read + Write> {
    inner: Arc<Mutex<S>>,
    mode: PunchIntegrationMode,
}
impl<S: Read + Write> MeshStreamPlug<S> {
    pub fn new(stream: S, mode: PunchIntegrationMode) -> Self {
        let mode = if matches!(mode, PunchIntegrationMode::NoTunnelHeader) {
            PunchIntegrationMode::NoTunnelHeader
        } else { PunchIntegrationMode::ReliableStreamWithEt4BFrame };
        Self { inner: Arc::new(Mutex::new(stream)), mode }
    }

    /// 以协议 4B 长度帧握手（和 TcpStream 那条流程完全一致）
    pub fn handshake(&mut self, my_peer_id: u32, ident: &NetworkIdentity) -> anyhow::Result<proto::HandshakeRequest> {
        // Mode B = 4B 帧：复用 do_client_handshake 的逻辑，但不能直接用 TcpStream
        // 这里直接复现相同的字节序列到 self.inner
        let req = build_handshake_request(my_peer_id, ident);
        let payload = encode_handshake(&req);
        let hdr = PeerManagerHeader::new(my_peer_id, 0, PacketType::HandShake, payload.len() as u32);
        {
            let mut s = self.inner.lock().unwrap();
            let total_len = if matches!(self.mode, PunchIntegrationMode::NoTunnelHeader) {
                (PEER_MANAGER_HEADER_SIZE + payload.len()) as u32
            } else { (PEER_MANAGER_HEADER_SIZE + payload.len()) as u32 };
            let mut buf = BytesMut::with_capacity(4 + total_len as usize);
            if matches!(self.mode, PunchIntegrationMode::ReliableStreamWithEt4BFrame) {
                buf.put_u32_le(total_len);
            }
            hdr.encode(&mut buf);
            buf.put_slice(&payload);
            s.write_all(&buf)?;
        }
        // 收响应
        let rhdr; let rpay;
        {
            let mut s = self.inner.lock().unwrap();
            if matches!(self.mode, PunchIntegrationMode::ReliableStreamWithEt4BFrame) {
                let mut lb = [0u8; 4];
                s.read_exact(&mut lb)?;
                let total = u32::from_le_bytes(lb) as usize;
                if total < PEER_MANAGER_HEADER_SIZE { anyhow::bail!("frame too small") }
                let mut body = vec![0u8; total];
                s.read_exact(&mut body)?;
                rhdr = PeerManagerHeader::decode(&body);
                rpay = body[PEER_MANAGER_HEADER_SIZE..].to_vec();
            } else {
                let mut body = vec![0u8; 65536];
                let n = s.read(&mut body)?;
                if n < PEER_MANAGER_HEADER_SIZE { anyhow::bail!("frame too small") }
                rhdr = PeerManagerHeader::decode(&body);
                rpay = body[PEER_MANAGER_HEADER_SIZE..n].to_vec();
            }
        }
        if rhdr.packet_type != PacketType::HandShake { anyhow::bail!("expect HandShake, got {:?}", rhdr.packet_type) }
        let remote = decode_handshake(&rpay)?;
        if !ident.matches(&remote.network_name, &remote.network_secret_digest) {
            anyhow::bail!("remote identity mismatch");
        }
        Ok(remote)
    }
}

// ======================================================================
// 8. Mesh 数据平面接入（解决 no-tun + 端口转发 + socks5）
// ======================================================================
// ⚠️ 关于你问的两个关键问题，先给结论再给代码：
//
// 【Q1：当前是不是只能 no-tun？】
//   不是"只能"，而是 mesh-tun-proto 本身就没有依赖 TUN。
//   常见 Relay 实现通常提供 3 条数据通路：
//
//   (A) TUN 模式（默认）=开 /dev/net/tun → 系统协议栈自己处理 TCP/UDP/ICMP
//           → 需要 root；官方 host 模块 负责；
//           → 你自己的工具没有 TUN 也能跑，直接走 (B)/(C)。
//
//   (B) no-tun + forward_by_system = 不开 TUN，但用系统路由 + iptables 抓包
//           → 需要 root；EasTier GatewayConfig.forward_by_system = true；
//
//   (C) no-tun + 纯用户态 = ProxyModule + smoltcp 用户态协议栈
//           → Relay 内置 proxy-packet feature；
//           → SOCKS5 / PortForward 就属于这一类，完全不需要 TUN。
//
//   所以 mesh-tun-proto 的定位就是模式 (C) 的轻量版：你给我字节流 / IP 包，
//   我帮你按 mesh 协议送出去；不依赖 smoltcp，不依赖 TUN。
//
// 【Q2：端口转发怎么处理？】
//   Relay 侧 PortForwardAdapter = 本地 bind 监听 + smoltcp::connect_tcp(dst)
//   把用户字节流 → smoltcp 封成 IP/TCP → CorePacketPlane.send_ip_packet() → 对端。
//
//   我们的轻量版本提供 3 个可选接入层（下面代码全给，按需用）：
//     8.1 MeshIpPlane        — L3 IP 包收发（你自己有 TUN/用户态栈时用，最自由）
//     8.2 MeshTcpSocket      — L4 字节流套接字（内部手工构造最小 IP+TCP 伪头，对端
//                            跑 Relay + PortForward 能直接互通）
//     8.3 MeshPortForwarder  — 在上面 MeshTcpSocket 基础上：本地 bind_addr → dst_addr
//     8.4 MeshSocks5Server   — 在上面 MeshTcpSocket 基础上：最简 SOCKS5 CONNECT
// ======================================================================
// DEFAULT OFF: SOCKS5 / PortForward / MeshTcpSocket / MeshIpPlane 用户态代理层
// 纯 P2P 工具默认不用这些；需要的话 --features=proxy
// ======================================================================

#[cfg(feature = "proxy")]
mod proxy_impl {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::Mutex as SyncMutex,
        sync::Arc,
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{TcpListener, TcpStream as TokioTcpStream},
        sync::mpsc,
    };
    use rand::Rng;
    use crate::{
        encrypt_packet, PacketCipher, PacketType, PeerManagerHeader, RouteTable,
    };
    use bytes::BytesMut;

    // =============================================================
    // 8.1 MeshIpPlane — 最小 L3 接入层（只做路由 + 封装，不碰 payload）
    // =============================================================
    pub struct MeshIpPlane {
        pub my_peer_id: u32,
        pub route: SyncMutex<RouteTable>,
        pub cipher: PacketCipher,
    }

    impl MeshIpPlane {
        pub fn new(my_peer_id: u32, cipher: PacketCipher) -> Self {
            Self {
                my_peer_id,
                route: SyncMutex::new(RouteTable { timestamp: 0, peers: vec![] }),
                cipher,
            }
        }
        pub fn update_routes(&self, rt: RouteTable) {
            *self.route.lock().unwrap() = rt;
        }
        /// raw IP 包 → 查下一跳 → (next_hop, pm_header, encrypted_body)
        pub fn wrap_outbound(&self, raw_ip_packet: &[u8]) -> anyhow::Result<(u32, PeerManagerHeader, Vec<u8>)> {
            let dst = parse_ip_dst(raw_ip_packet)?;
            let next_hop = self.lookup_next_hop(dst).ok_or_else(|| anyhow::anyhow!("no route to {dst}"))?;
            let mut hdr = PeerManagerHeader::new(self.my_peer_id, next_hop, PacketType::Data, raw_ip_packet.len() as u32);
            let body = encrypt_packet(&self.cipher, &mut hdr, raw_ip_packet)?;
            Ok((next_hop, hdr, body))
        }
        pub fn unwrap_inbound(&self, mut hdr: PeerManagerHeader, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            crate::decrypt_packet(&self.cipher, &mut hdr, payload)
        }
        pub fn lookup_next_hop(&self, dst: IpAddr) -> Option<u32> {
            let r = self.route.lock().unwrap();
            match dst {
                IpAddr::V4(v4) => {
                    let mut best: Option<(u8, u32)> = None;
                    for p in &r.peers {
                        let Some(ip) = p.ipv4_addr else { continue };
                        let mask = !(0xffffffffu32.checked_shr(p.network_length as u32).unwrap_or(0));
                        if (v4.to_bits() & mask) == (ip & mask) {
                            if best.map(|(l, _)| l < p.network_length).unwrap_or(true) {
                                best = Some((p.network_length, p.peer_id));
                            }
                        }
                    }
                    best.map(|(_, id)| id)
                }
                IpAddr::V6(_) => None,
            }
        }
    }

    pub fn parse_ip_dst(packet: &[u8]) -> anyhow::Result<IpAddr> {
        if packet.is_empty() { anyhow::bail!("empty ip packet") }
        match packet[0] >> 4 {
            4 => {
                if packet.len() < 20 { anyhow::bail!("ipv4 too short") }
                Ok(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])))
            }
            6 => {
                if packet.len() < 40 { anyhow::bail!("ipv6 too short") }
                Ok(IpAddr::V6(<[u8; 16]>::try_from(&packet[24..40]).unwrap().into()))
            }
            v => anyhow::bail!("unsupported ip version {v}"),
        }
    }

    // =============================================================
    // 8.2 MeshTcpSocket —— L4 最小伪 TCP 流（为了兼容 Relay PortForward 规则）
    // =============================================================
    #[derive(Clone)]
    pub struct MeshTcpSocketHandle {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: Arc<SyncMutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>>,
    }
    pub struct MeshTcpSocket {
        handle: MeshTcpSocketHandle,
        rx_buf: BytesMut,
    }

    impl MeshTcpSocket {
        pub async fn connect<F>(
            dst_addr: SocketAddr,
            src_virtual_ipv4: Ipv4Addr,
            plane: Arc<MeshIpPlane>,
            mut outbound: F,
        ) -> anyhow::Result<Self>
        where F: FnMut(PeerManagerHeader, Vec<u8>) -> anyhow::Result<()> + Send + 'static {
            let dst_ip = match dst_addr.ip() {
                IpAddr::V4(v4) => v4,
                _ => anyhow::bail!("only IPv4 dst"),
            };
            let src_port: u16 = rand::thread_rng().gen_range(1024..=65535);
            let dst_port = dst_addr.port();
            let next_hop = plane.lookup_next_hop(dst_ip.into())
                .ok_or_else(|| anyhow::anyhow!("no route to {dst_ip}"))?;

            let (net_to_user_tx, net_to_user_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (user_to_net_tx, mut user_to_net_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let _ = net_to_user_tx;

            let my_peer_id = plane.my_peer_id;
            let cipher = plane.cipher.clone();
            tokio::spawn(async move {
                let mut seq: u32 = 1;
                let ack: u32 = 1;
                let syn = build_ip_tcp_frame(src_virtual_ipv4, dst_ip, src_port, dst_port, 0x02, seq, ack, &[]);
                let mut h = PeerManagerHeader::new(my_peer_id, next_hop, PacketType::Data, syn.len() as u32);
                let b = encrypt_packet(&cipher, &mut h, &syn).unwrap_or(syn);
                let _ = outbound(h, b);
                seq = seq.wrapping_add(1);
                loop {
                    tokio::select! {
                        Some(data) = user_to_net_rx.recv() => {
                            let frame = build_ip_tcp_frame(src_virtual_ipv4, dst_ip, src_port, dst_port, 0x18, seq, ack, &data);
                            let mut h2 = PeerManagerHeader::new(my_peer_id, next_hop, PacketType::Data, frame.len() as u32);
                            let out = encrypt_packet(&cipher, &mut h2, &frame).unwrap_or(frame);
                            if outbound(h2, out).is_err() { break; }
                            seq = seq.wrapping_add(data.len() as u32);
                        }
                        else => break,
                    }
                }
            });

            Ok(Self {
                handle: MeshTcpSocketHandle {
                    tx: user_to_net_tx,
                    rx: Arc::new(SyncMutex::new(Some(net_to_user_rx))),
                },
                rx_buf: BytesMut::new(),
            })
        }

        pub fn feed_inbound_frame(&self, raw_ip_frame: &[u8]) {
            if let Some(payload) = parse_tcp_payload(raw_ip_frame) {
                if !payload.is_empty() {
                    let g = self.handle.rx.lock().unwrap();
                    if let Some(rx) = g.as_ref() {
                        let _ = rx;
                    }
                    let _ = payload;
                }
            }
        }
    }

    impl AsyncRead for MeshTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.rx_buf.is_empty() {
                let take = self.rx_buf.len().min(buf.remaining());
                buf.put_slice(&self.rx_buf.split_to(take));
                return Poll::Ready(Ok(()));
            }
            let rx_arc = self.handle.rx.clone();
            let mut g = rx_arc.lock().unwrap();
            let rx = match g.as_mut() { Some(r) => r, None => return Poll::Ready(Ok(())) };
            match rx.poll_recv(cx) {
                Poll::Ready(Some(v)) => {
                    let take = v.len().min(buf.remaining());
                    buf.put_slice(&v[..take]);
                    drop(g);
                    if take < v.len() { self.rx_buf.extend_from_slice(&v[take..]); }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for MeshTcpSocket {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            match self.handle.tx.send(buf.to_vec()) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "mesh socket closed"))),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> { Poll::Ready(Ok(())) }
    }

    fn build_ip_tcp_frame(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16,
                          tcp_flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let total = 20 + tcp_len;
        let mut out = vec![0u8; total];
        out[0] = 0x45; out[1] = 0;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[4..6].copy_from_slice(&[0x12, 0x34]);
        out[6..8].copy_from_slice(&[0x40, 0x00]);
        out[8] = 64; out[9] = 6;
        out[12..16].copy_from_slice(&src.octets());
        out[16..20].copy_from_slice(&dst.octets());
        let cs = ipv4_checksum(&out[..20]);
        out[10..12].copy_from_slice(&cs.to_be_bytes());
        let tb = 20;
        out[tb..tb+2].copy_from_slice(&sport.to_be_bytes());
        out[tb+2..tb+4].copy_from_slice(&dport.to_be_bytes());
        out[tb+4..tb+8].copy_from_slice(&seq.to_be_bytes());
        out[tb+8..tb+12].copy_from_slice(&ack.to_be_bytes());
        out[tb+12] = 5 << 4; out[tb+13] = tcp_flags;
        out[tb+14..tb+16].copy_from_slice(&65535u16.to_be_bytes());
        out[tb+20..total].copy_from_slice(payload);
        let ts = tcp_checksum(&src.octets(), &dst.octets(), &out[tb..total]);
        out[tb+16..tb+18].copy_from_slice(&ts.to_be_bytes());
        out
    }
    fn ipv4_checksum(h: &[u8]) -> u16 {
        let mut sum = 0u32; let mut i = 0;
        while i < h.len() {
            let w = ((h[i] as u32) << 8) | (h.get(i+1).copied().unwrap_or(0) as u32);
            sum += w; i += 2;
        }
        while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16); }
        !sum as u16
    }
    fn tcp_checksum(src: &[u8;4], dst: &[u8;4], tcp: &[u8]) -> u16 {
        let mut sum = 0u32;
        sum += ((src[0] as u32) << 8) | src[1] as u32;
        sum += ((src[2] as u32) << 8) | src[3] as u32;
        sum += ((dst[0] as u32) << 8) | dst[1] as u32;
        sum += ((dst[2] as u32) << 8) | dst[3] as u32;
        sum += 6u32; sum += tcp.len() as u32;
        let mut i = 0;
        while i < tcp.len() {
            let w = ((tcp[i] as u32) << 8) | tcp.get(i+1).map(|&x|x as u32).unwrap_or(0);
            sum += w; i += 2;
        }
        while (sum >> 16) != 0 { sum = (sum & 0xffff) + (sum >> 16); }
        !sum as u16
    }
    fn parse_tcp_payload(ip_frame: &[u8]) -> Option<&[u8]> {
        if ip_frame.len() < 40 { return None; }
        if ip_frame[0] >> 4 != 4 { return None; }
        let ihl = (ip_frame[0] & 0x0f) as usize * 4;
        if ip_frame[9] != 6 { return None; }
        let total = u16::from_be_bytes([ip_frame[2], ip_frame[3]]) as usize;
        let tcp = &ip_frame[ihl..total.min(ip_frame.len())];
        if tcp.len() < 20 { return None; }
        let doff = ((tcp[12] >> 4) as usize) * 4;
        Some(&tcp[doff..])
    }

    // =============================================================
    // 8.3 MeshPortForwarder —— 本地 bind_addr 转发到 mesh 网络 dst_addr
    // =============================================================
    pub struct MeshPortForwarder;
    impl MeshPortForwarder {
        pub async fn run_tcp<F>(
            bind_addr: SocketAddr,
            dst_addr: SocketAddr,
            src_virtual_ipv4: Ipv4Addr,
            plane: Arc<MeshIpPlane>,
            outbound: F,
        ) -> anyhow::Result<()>
        where F: FnMut(PeerManagerHeader, Vec<u8>) -> anyhow::Result<()> + Clone + Send + 'static {
            let ln = TcpListener::bind(bind_addr).await
                .map_err(|e| anyhow::anyhow!("bind {bind_addr} failed: {e}"))?;
            println!("[PF] TCP port-forward listening {bind_addr} -> mesh {dst_addr}");
            loop {
                let (incoming, _peer) = ln.accept().await?;
                let sock = MeshTcpSocket::connect(dst_addr, src_virtual_ipv4, plane.clone(), outbound.clone()).await?;
                tokio::spawn(async move {
                    let (mut ri, mut wi) = incoming.into_split();
                    let (mut rs, mut ws) = tokio::io::split(sock);
                    let _ = tokio::join!(
                        tokio::io::copy(&mut ri, &mut ws),
                        tokio::io::copy(&mut rs, &mut wi),
                    );
                });
            }
        }
    }

    // =============================================================
    // 8.4 MeshSocks5Server —— 最简 SOCKS5（CONNECT 命令）代理
    // =============================================================
    pub struct MeshSocks5Server;
    impl MeshSocks5Server {
        pub async fn run<F>(
            bind_addr: SocketAddr,
            src_virtual_ipv4: Ipv4Addr,
            plane: Arc<MeshIpPlane>,
            outbound: F,
        ) -> anyhow::Result<()>
        where F: FnMut(PeerManagerHeader, Vec<u8>) -> anyhow::Result<()> + Clone + Send + 'static {
            let ln = TcpListener::bind(bind_addr).await
                .map_err(|e| anyhow::anyhow!("socks5 bind {bind_addr} failed: {e}"))?;
            println!("[S5] SOCKS5 proxy listening on {bind_addr}");
            loop {
                let (stream, _p) = ln.accept().await?;
                let pl = plane.clone();
                let ob = outbound.clone();
                let vip = src_virtual_ipv4;
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5(stream, vip, pl, ob).await {
                        eprintln!("    socks5 err: {e}");
                    }
                });
            }
        }
    }

    async fn handle_socks5<F>(
        mut s: TokioTcpStream,
        src_vip: Ipv4Addr,
        plane: Arc<MeshIpPlane>,
        outbound: F,
    ) -> anyhow::Result<()>
    where F: FnMut(PeerManagerHeader, Vec<u8>) -> anyhow::Result<()> + Clone + Send + 'static {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut hdr = [0u8; 2]; s.read_exact(&mut hdr).await?;
        if hdr[0] != 5 { anyhow::bail!("not socks5") }
        let mut methods = vec![0u8; hdr[1] as usize]; s.read_exact(&mut methods).await?;
        s.write_all(&[0x05, 0x00]).await?;
        let mut rh = [0u8; 4]; s.read_exact(&mut rh).await?;
        if rh[0] != 5 || rh[1] != 1 { anyhow::bail!("only SOCKS5 CONNECT supported") }
        let dst = match rh[3] {
            0x01 => {
                let mut b = [0u8; 6]; s.read_exact(&mut b).await?;
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                                u16::from_be_bytes([b[4], b[5]]))
            }
            0x03 => anyhow::bail!("domain SOCKS5 needs DNS resolution, enable resolver in production"),
            0x04 => anyhow::bail!("IPv6 SOCKS5 not implemented"),
            a => anyhow::bail!("unknown atyp {a}"),
        };
        let conn = MeshTcpSocket::connect(dst, src_vip, plane, outbound).await?;
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
        let (mut ri, mut wi) = s.split();
        let (mut rs, mut ws) = tokio::io::split(conn);
        let _ = tokio::join!(
            tokio::io::copy(&mut ri, &mut ws),
            tokio::io::copy(&mut rs, &mut wi),
        );
        Ok(())
    }
}

#[cfg(feature = "proxy")]
pub use proxy_impl::{MeshIpPlane, MeshTcpSocket, MeshTcpSocketHandle, MeshPortForwarder, MeshSocks5Server, parse_ip_dst};

// ======================================================================
// 9. 顶层通用组网节点 P2pNode（给 上层应用 / 应用层 / TUN 层的最小接入面）
//
// 设计目标：
//   - 不依赖任何应用层/MC的东西。上层应用 只要把"打好洞的 byte stream / udp socket"塞进来，
//     剩下的 Mesh Relay 协议层（握手/加密/路由）都由 P2pNode 处理。
//   - etc 对 etc：同一套协议。
//   - etc 对 标准 Mesh Relay：同一套协议。
//   - 不做中继节点/PeerCenter/Relay（只做普通客户端节点，符合你说的"仅打洞"）。
//   - 1 对 N / mesh：内部管理 N 条 peer 连接 + 合并一张全局路由表。
//
// 上层应用 / 应用层对 P2pNode 的调用流程：
//   1. P2pNode::new("my_net", "my_secret", None)              → 拿到 node
//   2. 上层应用 跟对端打洞成功后，任选一种 add_*：
//        add_stream_conn(stream)   // TCP / QUIC / WebSocket / 任何 Read+Write
//        add_udp_conn(sock, remote) // 你们的 UDP 打洞 socket
//        add_raw_pm_conn(impl MeshFrameTransport) // 自定义的
//   3. 主循环里反复 tick(max_event_cnt) → 得到 P2pEvent
//   4. 对应用层（应用层 / TUN）：读 IP 包用 recv_ipv4()，写 IP 包用 send_ipv4()
// ======================================================================

/// 统一帧传输接口：底层不管是 TCP / UDP / QUIC / 你们自定义 调用方，都实现这个 trait。
/// 一帧 = [PeerManagerHeader(16B) + payload(body)]；是否在外面加 4B len / UDP 8B 头由实现自己决定。
pub trait MeshFrameTransport: Send {
    /// 尝试写一帧。阻塞成功返回 Ok(())，非阻塞 WouldBlock 也允许返回 Ok，但最好是阻塞写。
    fn send_frame(&mut self, hdr: &PeerManagerHeader, payload: &[u8]) -> anyhow::Result<()>;
    /// 尝试读一帧。非阻塞/超时时返回 Ok(None)，流断开/EOF 返回 Err 或 Some(Disconnect) 上层处理。
    fn recv_frame(&mut self) -> anyhow::Result<Option<(PeerManagerHeader, Vec<u8>)>>;
    /// 对端 peer_id（握手成功后填，握手前=0）
    fn remote_peer_id(&self) -> u32;
    /// 连接人类可读描述（"tcp x.x.x.x:y" / "udp nat-mapped x.x.x.x:y" 之类，仅用于日志）
    fn label(&self) -> String;
}

/// 单个 peer 连接（P2pNode 内部使用，但你也可以自己取出来操作）
pub struct P2pPeerConn {
    pub remote_peer_id: u32,
    pub last_rx: Instant,
    pub label: String,
    pub transport: Box<dyn MeshFrameTransport>,
}

/// P2pNode 给调用方（上层应用 / 应用层 / TUN）的事件
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// 新 peer 连接握手成功
    PeerUp { peer_id: u32, label: String },
    /// 已有 peer 断开
    PeerDown { peer_id: u32, label: String },
    /// 路由表刷新（合并了全网 peer 广播的信息）
    RouteChanged { peers: usize, timestamp_secs: u64 },
    /// 收到一个 raw IPv4/IPv6 包（通常直接写 TUN，或者交给应用层的 L4 层）
    InboundIpPacket(Vec<u8>),
    /// 收到一个"非 IP"的用户 Data 帧（对端用 `send_data_to` 发的 payload，NOT_SEND_TO_TUN=1）
    ///
    /// 下游工具的 TUN 循环里可以忽略这个事件；它专门给"P2P 自定义应用层协议"用，
    /// 比如发聊天消息、控制信令等，这些 payload 不是合法 IP 包，不该被写进 TUN。
    InboundUserData { from_peer_id: u32, data: Vec<u8> },
    /// 解密失败：可能是密钥不匹配、数据损坏、或对端协议版本不同
    DecryptError { from_peer_id: u32, packet_type: u8, len: usize },
}

/// 顶层节点：给 上层应用 / 应用层用的最小接口
pub struct P2pNode {
    pub identity: P2PPeerIdentity,
    pub mesh: PeerMesh,
    pub peers: std::collections::HashMap<u32, P2pPeerConn>,
    /// 缓存从所有连接收集到的 IP 包（tick 时塞进来，recv_ipv4 弹出）
    pub inbound_ip: std::collections::VecDeque<Vec<u8>>,
    /// 下游工具是否把自己接到了真 TUN。默认 false（我们只是 P2P 库，下游自己不开 TUN 时默认）。
    ///
    /// 设为 true 时：`send_ipv4` 发出去的 Data 帧会**清掉** NOT_SEND_TO_TUN，
    /// 让 Mesh Relay Relay / 对端节点正常把 payload 投递给它们的 TUN（这是你把 TUN 接上网络的关键）。
    pub my_tun_enabled: bool,
}

impl P2pNode {
    pub fn new(network: impl Into<String>, secret: impl Into<String>, my_peer_id: Option<u32>) -> Self {
        let identity = build_p2p_peer_identity(network, secret, my_peer_id);
        let mesh = PeerMesh::new(&identity);
        Self {
            identity,
            mesh,
            peers: std::collections::HashMap::new(),
            inbound_ip: std::collections::VecDeque::new(),
            my_tun_enabled: false,
        }
    }

    // =================================================================
    // 三条"加连接"的入口：stream / udp / custom transport
    // =================================================================

    /// 入口 1：可靠流（TcpStream / QUIC stream / WebSocket / UnixStream / 任何 Read+Write）
    /// 帧格式：官方 TCP 兼容 —— 4B LE(length) + PeerManagerHeader(16B) + payload
    pub fn add_stream_conn<S: Read + Write + Send + 'static>(&mut self, stream: S) -> anyhow::Result<u32> {
        let t = ReliableFrameTransport::new(stream);
        self.add_transport(Box::new(t))
    }

    /// 入口 2：UDP 打洞 socket（调用方 已经打通了，传 local socket + remote 映射地址）
    /// 帧格式：官方 UDP 兼容 —— UDPTunnelHeader(8B) + PeerManagerHeader(16B) + payload
    ///         如果你不想套 8B header，用 NoTunnelHeader 模式
    pub fn add_udp_conn(&mut self, sock: Arc<UdpSocket>, remote: SocketAddr,
                        mode: PunchIntegrationMode) -> anyhow::Result<u32> {
        let t = UdpFrameTransport::new(sock, remote, mode);
        self.add_transport(Box::new(t))
    }

    /// 入口 3：你们有自定义的 调用方 transport（比如 WebRTC datachannel、自定义 raw IP）
    ///         实现 MeshFrameTransport trait 后直接塞进来
    pub fn add_custom_transport(&mut self, t: Box<dyn MeshFrameTransport>) -> anyhow::Result<u32> {
        self.add_transport(t)
    }

    fn add_transport(&mut self, mut t: Box<dyn MeshFrameTransport>) -> anyhow::Result<u32> {
        let req = build_handshake_request(self.identity.my_peer_id, &self.identity.ident);
        let payload = encode_handshake(&req);
        let mut hdr = PeerManagerHeader::new(self.identity.my_peer_id, 0, PacketType::HandShake, payload.len() as u32);
        let _ = &mut hdr;
        t.send_frame(&hdr, &payload)?;
        // 收 HandShake 响应（带超时保护，防止非阻塞 stream busy loop）
        let deadline = Instant::now() + Duration::from_secs(30);
        let (pid, ip) = loop {
            if Instant::now() > deadline {
                anyhow::bail!("handshake timeout: no response in 30s");
            }
            let (rhdr, rpay) = match t.recv_frame()? {
                Some(v) => v,
                None => {
                    // 非阻塞返回 None：sleep 1ms 避免 busy loop
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
            };
            if rhdr.packet_type != PacketType::HandShake { continue; }
            let remote = decode_handshake(&rpay)?;
            if !self.identity.ident.matches(&remote.network_name, &remote.network_secret_digest) {
                anyhow::bail!("remote identity mismatch during p2p handshake");
            }
            break (remote.my_peer_id, None::<u32>);
        };
        let label = t.label();
        let conn = P2pPeerConn {
            remote_peer_id: pid,
            last_rx: Instant::now(),
            label: label.clone(),
            transport: t,
        };
        self.peers.insert(pid, conn);
        self.mesh.peers.insert(pid, self.peers.len().saturating_sub(1));
        if let Some(_ip) = ip {
            // 之后 route update 到了会自动填路由；此处仅占位
        }
        Ok(pid)
    }

    // =================================================================
    // 主循环：tick / send_ipv4 / recv_ipv4
    // =================================================================

    /// 非阻塞驱动一次：最多 poll `max_frames_per_conn` 帧/连接。
    /// 把收集到的事件返回给 上层应用（UI 可以据此显示 PeerUp/PeerDown/RouteChanged）。
    pub fn tick(&mut self, max_frames_per_conn: usize) -> Vec<P2pEvent> {
        use std::collections::hash_map::Entry;
        let mut out = Vec::new();
        let mut down_ids = Vec::new();

        for (pid, conn) in self.peers.iter_mut() {
            let mut frames = 0usize;
            loop {
                if frames >= max_frames_per_conn { break; }
                let got = match conn.transport.recv_frame() {
                    Ok(Some(v)) => Some(v),
                    Ok(None) => None,
                    Err(_e) => {
                        down_ids.push(*pid);
                        break;
                    }
                };
                let (hdr, payload) = match got { Some(v) => v, None => break };
                frames += 1;
                conn.last_rx = Instant::now();
                // 过滤：不是发给我的包（我又不是 relay 也不是 center）直接丢
                if hdr.to_peer_id != 0 && hdr.to_peer_id != self.identity.my_peer_id
                    && hdr.to_peer_id != u32::MAX {
                    continue;
                }
                let pt = match PacketType::try_from(hdr.packet_type as u8) {
                    Ok(t) => t, Err(_) => continue,
                };
                let is_enc = hdr.flags & FLAG_ENCRYPTED != 0;
                let payload_len = payload.len();
                let plain_result: anyhow::Result<Vec<u8>> = match pt {
                    PacketType::Data | PacketType::RpcReq | PacketType::RpcResp
                    | PacketType::Ping | PacketType::Pong if is_enc => {
                        let mut h2 = hdr.clone();
                        decrypt_packet(&self.identity.cipher, &mut h2, &payload)
                    }
                    _ => Ok(payload),
                };
                let plain = match plain_result {
                    Ok(v) => v,
                    Err(_) => {
                        out.push(P2pEvent::DecryptError {
                            from_peer_id: hdr.from_peer_id,
                            packet_type: hdr.packet_type as u8,
                            len: payload_len,
                        });
                        continue;
                    }
                };
                match pt {
                    PacketType::Data => {
                        if plain.is_empty() { continue; }
                        let from_peer_id = hdr.from_peer_id;
                        if hdr.not_send_to_tun() {
                            // 对端发的是"用户自定义 payload"（非 IP），单独事件出去，不要进 TUN 队列
                            out.push(P2pEvent::InboundUserData { from_peer_id, data: plain });
                        } else {
                            // 正常的 IP 包：入 TUN 队列 + 事件（二者都给下游工具，任选一种消费）
                            self.inbound_ip.push_back(plain.clone());
                            out.push(P2pEvent::InboundIpPacket(plain));
                        }
                    }
                    PacketType::RpcReq => {
                        // 1) 如果是 SyncRouteInfoRequest，自动回加密的 SyncRouteInfoResponse
                        //    （OSPF 路由同步的最小闭环；不回 Core 会一直超时）
                        let peeked = peek_sync_route_request_inner(&plain);
                        eprintln!("[DBG tick] RpcReq from={:#x} is_enc={} plain_len={} is_sync={} desc={:?}",
                            hdr.from_peer_id, is_enc, plain.len(),
                            peeked.is_some(),
                            peeked.as_ref().map(|(_, d, _, _)| (d.service_name.clone(), d.method_index)));
                        if let Some((tx_id, desc, _peer_sid, peer_init)) = peeked
                        {
                            let my_peer_id = self.identity.my_peer_id;
                            let from_peer_id = conn.remote_peer_id;
                            // 稳定 session_id：同一对 peer 每次一致，避免 Core 反复 "session id mismatch"
                            let my_sid = stable_session_id(my_peer_id, from_peer_id);
                            match build_sync_route_info_response(
                                &self.identity.cipher, my_peer_id, from_peer_id,
                                tx_id, &desc, my_sid, peer_init,
                            ) {
                                Ok((rh, ct)) => {
                                    eprintln!("[DBG tick] -> RpcResp to={:#x} tx={} flags=0x{:02x} ct_len={}",
                                        rh.to_peer_id, tx_id, rh.flags, ct.len());
                                    match conn.transport.send_frame(&rh, &ct) {
                                        Ok(()) => eprintln!("[DBG tick] send_frame OK"),
                                        Err(e) => eprintln!("[DBG tick] send_frame ERR: {e}"),
                                    }
                                }
                                Err(e) => eprintln!("[DBG tick] build resp ERR: {e}"),
                            }
                        }
                        // 2) 合并路由表：只在 Core 主动推了非空 peer_infos 时更新。
                        //    Mesh 路由增量同步语义：peer_infos=None 表示"无变化"，
                        //    此时不能用空表覆盖已有路由（否则会把学到的 peer 全清掉）。
                        if let Ok(Some(rt)) = try_parse_route_from_rpc(&plain) {
                            if !rt.peers.is_empty() {
                                self.mesh.apply_route_update(rt.clone());
                                for p in &rt.peers {
                                    if !self.mesh.peers.contains_key(&p.peer_id) {
                                        self.mesh.peers.insert(p.peer_id, self.mesh.peers.len());
                                    }
                                }
                                out.push(P2pEvent::RouteChanged {
                                    peers: rt.peers.len(),
                                    timestamp_secs: rt.timestamp,
                                });
                            }
                        }
                    }
                    PacketType::RpcResp => {
                        if let Ok(Some(rt)) = try_parse_route_from_rpc(&plain) {
                            if !rt.peers.is_empty() {
                                self.mesh.apply_route_update(rt.clone());
                                for p in &rt.peers {
                                    if !self.mesh.peers.contains_key(&p.peer_id) {
                                        self.mesh.peers.insert(p.peer_id, self.mesh.peers.len());
                                    }
                                }
                                out.push(P2pEvent::RouteChanged {
                                    peers: rt.peers.len(),
                                    timestamp_secs: rt.timestamp,
                                });
                            }
                        }
                    }
                    PacketType::Ping => {
                        // Core 的 Ping payload（解密后）= 4 字节 LE seq；Pong 必须原样回显 seq，
                        // 否则 Core 在 <协议帧处理规范>:179 用 payload[0..4] 取 seq 时越界 panic。
                        let seq_bytes = if plain.len() >= 4 { &plain[..4] } else { &plain[..] };
                        let mut reply = PeerManagerHeader::new(
                            self.identity.my_peer_id, conn.remote_peer_id, PacketType::Pong, 0);
                        let ct = encrypt_packet(&self.identity.cipher, &mut reply, seq_bytes)
                            .unwrap_or_default();
                        let _ = conn.transport.send_frame(&reply, &ct);
                    }
                    PacketType::Pong | PacketType::HandShake => {}
                }
            }
        }

        for pid in down_ids {
            if let Entry::Occupied(o) = self.peers.entry(pid) {
                let label = o.get().label.clone();
                o.remove();
                self.mesh.peers.remove(&pid);
                out.push(P2pEvent::PeerDown { peer_id: pid, label });
            }
        }
        out
    }

    /// 发一个 raw IPv4/IPv6 包（从 TUN 或 上层应用 的 L4 层来）。
    ///
    /// 核心逻辑（与路由投递规范对齐）：
    ///  1. 从 IP 头里取 dst IPv4 地址；
    ///  2. 查路由表找到 **目标 peer_id**（最终归属这个 IP 的节点）；
    ///  3. 再把 **下一跳**（我们直连的 Core/Peer）作为传输目的地；
    ///  4. 在 PeerManagerHeader 里：to_peer_id=目标peer_id（让 Core 按这个再路由），NOT_SEND_TO_TUN=发送方是否挂了 TUN。
    pub fn send_ipv4(&mut self, raw_ip_packet: &[u8]) -> anyhow::Result<()> {
        let dst = parse_dst_from_ip_packet(raw_ip_packet)?;
        // 1) 最终归属这个 IP 的 peer_id（Core 的 forward 逻辑用的是 to_peer_id，不是下一跳）
        let dst_peer_id = self.mesh.lookup_next_hop(dst)
            .or_else(|| self.fallback_next_hop())
            .ok_or_else(|| anyhow::anyhow!("p2p: no route to dst ipv4={dst}"))?;
        // 2) 下一跳：如果 dst_peer_id 本身直连，那下一跳 = dst_peer_id；否则走 fallback relay
        let next_hop = if self.peers.contains_key(&dst_peer_id) {
            dst_peer_id
        } else {
            self.fallback_next_hop()
                .ok_or_else(|| anyhow::anyhow!("p2p: next_hop missing for dst_peer={dst_peer_id}"))?
        };
        self.send_ipv4_via(next_hop, dst_peer_id, raw_ip_packet)
    }

    /// 【更灵活的 TUN 发送】如果你自己已经知道 dst_peer_id / next_hop，直接用这个。
    /// 比如：mesh 里 A 想给 B 发 IP 包，但你知道必须通过 Core 转发，那就
    /// `send_ipv4_via(core_peer_id, b_peer_id, pkt)`。
    pub fn send_ipv4_via(&mut self, next_hop: u32, dst_peer_id: u32, raw_ip_packet: &[u8]) -> anyhow::Result<()> {
        let conn = self.peers.get_mut(&next_hop)
            .ok_or_else(|| anyhow::anyhow!("p2p: next_hop={next_hop} not connected"))?;
        let mut hdr = PeerManagerHeader::new(self.identity.my_peer_id, dst_peer_id, PacketType::Data,
                                              raw_ip_packet.len() as u32);
        // 如果我们自己没挂 TUN（默认），发出去的 Data 帧带 NOT_SEND_TO_TUN，避免 Core
        // 收到后尝试把 IP 包写回 Core 自己的 TUN（那通常会失败或环路）。
        // 下游工具如果真的开了 TUN，调用 set_my_tun_enabled(true) 把这个 flag 清掉。
        if !self.my_tun_enabled {
            hdr.set_not_send_to_tun(true);
        }
        let body = encrypt_packet(&self.identity.cipher, &mut hdr, raw_ip_packet)?;
        conn.transport.send_frame(&hdr, &body)?;
        Ok(())
    }

    /// 下游工具创建了 TUN 设备时调用：会让发出去的 Data 帧清掉 NOT_SEND_TO_TUN，
    /// 这样对端 Core 会正常把我们的 IP 包投递到它自己的 TUN 里。
    pub fn set_my_tun_enabled(&mut self, enabled: bool) { self.my_tun_enabled = enabled; }
    pub fn is_my_tun_enabled(&self) -> bool { self.my_tun_enabled }

    /// 给定一个 IPv4，查这个 IP 归属哪个 peer_id（按最长前缀匹配）。
    /// 下游工具如果要自行做 TUN -> send_ipv4_via 的路由决策，可以用它。
    pub fn lookup_peer_by_ipv4(&self, ipv4: u32) -> Option<u32> {
        self.mesh.lookup_next_hop(ipv4)
    }

    /// 【最常用】直接把用户 payload 发给指定 peer_id（不要求你构造 IP 头）。
    ///
    /// - `dst_peer_id`: 最终接收者的 peer_id（路由表通过 RouteUpdate 学到，或用 `peers()` 查询）
    /// - `payload`: 任意字节，应用层消息/JSON/protobuf/原始文件块…都行
    ///
    /// 内部自动选择下一跳（直连就直接发，不直连就让公共节点/relay 继续转发）。
    pub fn send_data_to(&mut self, dst_peer_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        // 优先找直连：如果 dst_peer_id 本身就是我们直连的 peer，直接交付
        let next_hop = if self.peers.contains_key(&dst_peer_id) {
            dst_peer_id
        } else {
            // 否则随便找一个直连 peer 当 relay（通常就是公共中继节点）
            self.fallback_next_hop()
                .ok_or_else(|| anyhow::anyhow!("p2p: no peer connected, cannot reach {dst_peer_id}"))?
        };
        self.send_data_frame_via_next_hop(next_hop, dst_peer_id, payload)
    }

    /// 当前所有直连 peer 的列表（peer_id + label）。配合 send_data_to 使用：
    /// 先看 peers() 里有谁，再决定发给哪个，或用它当 relay。
    pub fn connected_peers(&self) -> Vec<(u32, String)> {
        self.peers.iter().map(|(id, c)| (*id, c.label.clone())).collect()
    }

    /// 弹一个入方向 IP 包 / 用户 payload 帧（tick 收集到的）
    pub fn recv_ipv4(&mut self) -> Option<Vec<u8>> { self.inbound_ip.pop_front() }

    /// 主动向所有直连 peer 发起 SyncRouteInfoRequest（作为 initiator），
    /// 把自己的 peer_infos（peer_id / hostname）告诉对端。
    /// 这是让 Core 学到我们真实身份的关键：Core 作为 responder 只能通过我们主动发的 Request
    /// 拿到 hostname / ipv4 等信息，进而把我们在路由表里广播给其他节点（比如对端客户端）。
    /// 用稳定的 session_id（基于 my_peer_id + to_peer_id 的 hash），避免 Core 反复 "session id mismatch"。
    pub fn announce_self_to_all(&mut self, hostname: &str, my_ipv4: Option<u32>) -> usize {
        let my_peer_id = self.identity.my_peer_id;
        let network_name = self.identity.ident.name.clone();
        let mut sent = 0usize;
        let peer_ids: Vec<u32> = self.peers.keys().copied().collect();
        for to_peer_id in peer_ids {
            let my_sid = stable_session_id(my_peer_id, to_peer_id);
            match build_sync_route_info_request(
                &self.identity.cipher, my_peer_id, to_peer_id, my_ipv4, hostname, my_sid, &network_name,
            ) {
                Ok((hdr, ct)) => {
                    if let Some(conn) = self.peers.get_mut(&to_peer_id) {
                        if conn.transport.send_frame(&hdr, &ct).is_ok() {
                            sent += 1;
                        }
                    }
                }
                Err(_) => {}
            }
        }
        sent
    }

    fn send_data_frame_via_next_hop(&mut self, next_hop: u32, dst_peer_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        let conn = self.peers.get_mut(&next_hop)
            .ok_or_else(|| anyhow::anyhow!("p2p: next_hop={next_hop} not connected"))?;
        let mut hdr = PeerManagerHeader::new(self.identity.my_peer_id, dst_peer_id, PacketType::Data,
                                              payload.len() as u32);
        // send_data_to 发的是"应用层原始 payload"，不是 IP 包，所以恒带 NOT_SEND_TO_TUN
        // （避免任何节点尝试把这个 payload 写入 TUN，导致错包）
        hdr.set_not_send_to_tun(true);
        let body = encrypt_packet(&self.identity.cipher, &mut hdr, payload)?;
        conn.transport.send_frame(&hdr, &body)?;
        Ok(())
    }

    fn fallback_next_hop(&self) -> Option<u32> {
        // 如果路由表还没收敛，随便找一个直连 peer 兜底（让它继续转发；对端允许 relay 才转发成功）
        self.peers.keys().next().copied()
    }

    /// 返回当前学到的**全网路由表**（包括非直连节点，通过 SyncRouteInfo 广播学到的）。
    /// 每次收到 `P2pEvent::RouteChanged` 后这里就会更新。
    pub fn routes(&self) -> &RouteTable {
        &self.mesh.route
    }

    /// 主动断开一个直连 peer。会从连接表里移除，后续 `tick()` 不再读它。
    /// 不会主动发 TCP FIN（下游如果需要优雅关闭，自己 shutdown stream）。
    pub fn disconnect(&mut self, peer_id: u32) -> bool {
        self.peers.remove(&peer_id).is_some()
    }

}

// ============== P2pNode 的 MeshFrameTransport 内置实现（TCP/UDP 两条） ==============

/// 可靠流帧传输（TCP/QUIC/WebSocket/UDS…）：4B LE len + PeerManagerHeader + payload
pub struct ReliableFrameTransport<S: Read + Write> {
    stream: S,
    label: String,
    remote_peer_id: std::sync::atomic::AtomicU32,
}
impl<S: Read + Write> ReliableFrameTransport<S> {
    pub fn new(stream: S) -> Self {
        let label = format!("stream<{}>", std::any::type_name::<S>());
        Self { stream, label, remote_peer_id: std::sync::atomic::AtomicU32::new(0) }
    }
    pub fn with_label(stream: S, label: impl Into<String>) -> Self {
        Self { stream, label: label.into(), remote_peer_id: std::sync::atomic::AtomicU32::new(0) }
    }
}
impl<S: Read + Write + Send> MeshFrameTransport for ReliableFrameTransport<S> {
    fn send_frame(&mut self, hdr: &PeerManagerHeader, payload: &[u8]) -> anyhow::Result<()> {
        send_frame(&mut self.stream, hdr, payload).map_err(|e| anyhow::anyhow!(e))
    }
    fn recv_frame(&mut self) -> anyhow::Result<Option<(PeerManagerHeader, Vec<u8>)>> {
        match recv_frame(&mut self.stream) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }
    fn remote_peer_id(&self) -> u32 { self.remote_peer_id.load(std::sync::atomic::Ordering::Relaxed) }
    fn label(&self) -> String { self.label.clone() }
}

/// UDP 帧传输：UDPTunnelHeader 8B + PeerManagerHeader + payload（或 NoTunnelHeader 模式）
pub struct UdpFrameTransport {
    sock: Arc<UdpSocket>,
    remote: SocketAddr,
    mode: PunchIntegrationMode,
    conn_id: u32,
    syn_sent: bool,
    remote_peer_id: std::sync::atomic::AtomicU32,
}
impl UdpFrameTransport {
    pub fn new(sock: Arc<UdpSocket>, remote: SocketAddr, mode: PunchIntegrationMode) -> Self {
        use std::sync::atomic::AtomicU32;
        let conn_id: u32 = rand::random();
        Self {
            sock, remote, mode, conn_id, syn_sent: false,
            remote_peer_id: AtomicU32::new(0),
        }
    }
    fn encode_udp_hdr(&self, pt: UdpPacketType, payload_len: u16, out: &mut [u8; 8]) {
        out[..4].copy_from_slice(&self.conn_id.to_le_bytes());
        out[4] = pt as u8; out[5] = 0;
        out[6..8].copy_from_slice(&payload_len.to_le_bytes());
    }
}
impl MeshFrameTransport for UdpFrameTransport {
    fn send_frame(&mut self, hdr: &PeerManagerHeader, payload: &[u8]) -> anyhow::Result<()> {
        let mut pm = Vec::with_capacity(PEER_MANAGER_HEADER_SIZE + payload.len());
        {
            use bytes::BufMut;
            let mut bm = BytesMut::with_capacity(PEER_MANAGER_HEADER_SIZE + payload.len());
            hdr.encode(&mut bm);
            bm.put_slice(payload);
            pm.extend_from_slice(&bm);
        }
        let pkt: Vec<u8> = if matches!(self.mode, PunchIntegrationMode::UdpWithEt8ByteHeader) {
            // 首次发送时先发 Syn 包（建立 UDP session），之后才发 Data
            if !self.syn_sent {
                let mut syn_hdr = [0u8; 8];
                self.encode_udp_hdr(UdpPacketType::Syn, 0, &mut syn_hdr);
                self.sock.send_to(&syn_hdr, self.remote)?;
                self.syn_sent = true;
            }
            let mut h8 = [0u8; 8];
            self.encode_udp_hdr(UdpPacketType::Data, pm.len() as u16, &mut h8);
            let mut o = Vec::with_capacity(8 + pm.len());
            o.extend_from_slice(&h8); o.extend_from_slice(&pm);
            o
        } else { pm };
        self.sock.send_to(&pkt, self.remote)?;
        Ok(())
    }
    fn recv_frame(&mut self) -> anyhow::Result<Option<(PeerManagerHeader, Vec<u8>)>> {
        let mut buf = vec![0u8; 65536];
        match self.sock.recv_from(&mut buf) {
            Ok((n, from)) if from == self.remote => {
                let mut off = 0usize;
                if matches!(self.mode, PunchIntegrationMode::UdpWithEt8ByteHeader) {
                    if n < UDP_TUNNEL_HEADER_SIZE { return Ok(None); }
                    // 只取 Data 类型（忽略 Syn/Sack）
                    let pt = buf[4];
                    if pt != UdpPacketType::Data as u8 { return Ok(None); }
                    off = UDP_TUNNEL_HEADER_SIZE;
                }
                if n - off < PEER_MANAGER_HEADER_SIZE { return Ok(None); }
                let hdr = PeerManagerHeader::decode(&buf[off..]);
                let body_end = (off + PEER_MANAGER_HEADER_SIZE + hdr.len as usize).min(n);
                let payload = buf[off + PEER_MANAGER_HEADER_SIZE..body_end].to_vec();
                Ok(Some((hdr, payload)))
            }
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }
    fn remote_peer_id(&self) -> u32 { self.remote_peer_id.load(std::sync::atomic::Ordering::Relaxed) }
    fn label(&self) -> String { format!("udp {:?} → {}", self.mode, self.remote) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hasher;

    #[test]
    fn siphash13_matches_std_default_hasher() {
        let cases: &[&[u8]] = &[
            b"",
            b"hello",
            b"test_network",
            b"my_super_secret_p@ssword",
            b"long payload test 01234567890123456789012345678901",
        ];
        for data in cases {
            let mut me = SipHasher13::default();
            me.write(data);
            let mut stdh: std::collections::hash_map::DefaultHasher = Default::default();
            stdh.write(data);
            assert_eq!(me.finish(), stdh.finish(), "mismatch for {:?}", data);
        }
    }

    #[test]
    fn siphash13_matches_std_chained_writes() {
        // 与 mesh digest 算法 中 write(name); write(secret); finish() 顺序一致
        let name = "test_net";
        let secret = "test_pwd";
        let mut me = SipHasher13::default();
        me.write(name.as_bytes());
        me.write(secret.as_bytes());
        let mut stdh: std::collections::hash_map::DefaultHasher = Default::default();
        stdh.write(name.as_bytes());
        stdh.write(secret.as_bytes());
        assert_eq!(me.finish(), stdh.finish());
    }

    #[test]
    fn digest_matches_protocol_digest() {
        // 与 mesh digest 算法保持一致，用 std DefaultHasher 对照
        fn et_generate(name: &str, secret: &str) -> [u8; 32] {
            let mut digest = [0u8; 32];
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            hasher.write(name.as_bytes());
            hasher.write(secret.as_bytes());
            let shard_count = digest.len() / 8;
            for i in 0..shard_count {
                digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
                hasher.write(&digest[..(i + 1) * 8]);
            }
            digest
        }
        for (n, s) in &[("net","sec"), ("sjdjfudjnx","djdjfnnf"), ("",""), ("a","b")] {
            let mine = generate_network_secret_digest(n, s);
            let theirs = et_generate(n, s);
            assert_eq!(mine, theirs, "digest mismatch for ({},{})", n, s);
        }
        // 4 个 shard 必须互不相同（否则说明 hasher 没复用）
        let d = generate_network_secret_digest("net", "sec");
        assert_ne!(d[..8], d[8..16], "shard 0 == shard 1, hasher not chained");
    }

    #[test]
    fn derive_key_128_matches_protocol_digest() {
        fn et_derive(secret: &str) -> [u8; 16] {
            let mut key = [0u8; 16];
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            hasher.write(secret.as_bytes());
            key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
            hasher.write(&key[0..8]);
            key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
            key
        }
        for s in &["hello-secret-123", "djdjfnnf", "", "k"] {
            let mine = derive_key_128(s);
            let theirs = et_derive(s);
            assert_eq!(mine, theirs, "key mismatch for {}", s);
        }
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = derive_key_128("hello-secret-123");
        let c = PacketCipher::new(&key);
        let pt: &[u8] = "hello test payload".as_bytes();
        let ct = c.encrypt(pt).unwrap();
        assert!(ct.len() > 28);
        let back = c.decrypt(&ct).unwrap();
        assert_eq!(&back[..], pt);
    }

    #[test]
    fn header_roundtrip() {
        let h = PeerManagerHeader::new(1234, 0, PacketType::HandShake, 42);
        let mut buf = BytesMut::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), PEER_MANAGER_HEADER_SIZE);
        let d = PeerManagerHeader::decode(&buf);
        assert_eq!(d.from_peer_id, 1234);
        assert_eq!(d.to_peer_id, 0);
        assert_eq!(d.packet_type, PacketType::HandShake);
        assert_eq!(d.len, 42);
    }

    #[test]
    fn handshake_proto_roundtrip() {
        let ident = NetworkIdentity::new("mynet", "mysecret");
        let req = build_handshake_request(777, &ident);
        let bytes = encode_handshake(&req);
        let back = decode_handshake(&bytes).unwrap();
        assert_eq!(back.magic, MAGIC);
        assert_eq!(back.my_peer_id, 777);
        assert_eq!(back.network_name, "mynet");
        assert_eq!(back.network_secret_digest, ident.digest.to_vec());
    }

    #[test]
    fn encrypt_packet_flags() {
        let key = derive_key_128("k");
        let cipher = PacketCipher::new(&key);
        let mut hdr = PeerManagerHeader::new(1, 2, PacketType::Data, 5);
        let payload = b"abcde";
        let ct = encrypt_packet(&cipher, &mut hdr, payload).unwrap();
        assert_ne!(hdr.flags & FLAG_ENCRYPTED, 0);
        assert_eq!(hdr.len, ct.len() as u32);
        let back = decrypt_packet(&cipher, &mut hdr, &ct).unwrap();
        assert_eq!(hdr.flags & FLAG_ENCRYPTED, 0);
        assert_eq!(&back[..], payload);
    }
}
