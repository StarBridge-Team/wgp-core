//! LAN 组播发现载体（00 §4 第一档：同网段直连，跳过 STUN/打洞）。
//!
//! beacon 定长 22B：magic(2 "LN") | session_tag(4) | nonce(4) | auth(12)
//!  - auth = HMAC(lan_key, 前 10B)（LAN 内仍验签：防蹭网者伪造发现）
//!  - 组播包 src 即对端单播地址 → 收到验签 beacon 即直接交付 Lan 链路
//!  - 组地址默认 239.255.42.42:3842（站点本地范围，不进公网路由）
//!
//! 平台注意：Windows 上同端口多实例需要 SO_REUSEADDR（socket2 提供）。
//! 组播真实收发依赖网卡路径，loopback 行为不稳定 → 网络收发不在单测内
//! （部署清单列为真机验证项）。

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use wgp_crypto::derive::lan_auth;

pub mod beacon {
    use super::lan_auth;

    pub const LEN: usize = 22;
    pub const MAGIC: [u8; 2] = *b"LN";

    /// 组一帧 beacon（前 10B 签名）
    pub fn craft(key: &[u8; 32], session_tag: [u8; 4], nonce: u32) -> [u8; LEN] {
        let mut buf = [0u8; LEN];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2..6].copy_from_slice(&session_tag);
        buf[6..10].copy_from_slice(&nonce.to_be_bytes());
        let tag = lan_auth(key, &buf[..10]);
        buf[10..].copy_from_slice(&tag);
        buf
    }

    /// 解并验签：返回 (tag, nonce)；伪造/错键 → None
    pub fn decode(key: &[u8; 32], buf: &[u8]) -> Option<([u8; 4], u32)> {
        if buf.len() != LEN || buf[0..2] != MAGIC {
            return None;
        }
        let recomputed = lan_auth(key, &buf[..10]);
        if recomputed != buf[10..] {
            return None;
        }
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&buf[2..6]);
        let nonce = u32::from_be_bytes(buf[6..10].try_into().ok()?);
        Some((tag, nonce))
    }
}

/// 默认组频道（站点本地：239.255.0.0/16 的保留使用段）
pub const DEFAULT_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 42, 42), 3842);

pub struct LanProbeCarrier {
    socket: Arc<UdpSocket>,
    group: SocketAddrV4,
    lan_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: AtomicU32,
}

impl LanProbeCarrier {
    /// 绑定组播组（SO_REUSEADDR 允许多实例同端口——同一台机器上多客户端共存）
    pub fn bind(
        group: SocketAddrV4,
        lan_key: [u8; 32],
        session_tag: [u8; 4],
    ) -> std::io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::from(([0u8; 4], group.port())).into())?;
        socket.join_multicast_v4(group.ip(), &Ipv4Addr::UNSPECIFIED)?;
        socket.set_nonblocking(true)?;
        let std_udp: std::net::UdpSocket = socket.into();
        Ok(Self {
            socket: Arc::new(UdpSocket::from_std(std_udp)?),
            group,
            lan_key,
            session_tag,
            nonce_seed: AtomicU32::new(0),
        })
    }

    pub fn group(&self) -> SocketAddrV4 {
        self.group
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// 发一帧 beacon
    pub async fn send_beacon(&self) -> std::io::Result<usize> {
        let nonce = self.nonce_seed.fetch_add(1, Ordering::Relaxed) + 1;
        let buf = beacon::craft(&self.lan_key, self.session_tag, nonce);
        self.socket.send_to(&buf, SocketAddr::V4(self.group)).await
    }

    /// 收一帧并验签：返回对端单播地址（组播包 src）
    pub async fn recv_beacon(&self) -> Option<(SocketAddr, [u8; 4], u32)> {
        let mut buf = [0u8; beacon::LEN];
        let (n, src) = self.socket.recv_from(&mut buf).await.ok()?;
        if n != beacon::LEN {
            return None;
        }
        let (tag, nonce) = beacon::decode(&self.lan_key, &buf)?;
        Some((src, tag, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::beacon;

    #[test]
    fn beacon_roundtrip() {
        let key = [0x67u8; 32];
        let buf = beacon::craft(&key, [3, 2, 1, 0], 42);
        let (tag, nonce) = beacon::decode(&key, &buf).expect("合法 beacon");
        assert_eq!(tag, [3, 2, 1, 0]);
        assert_eq!(nonce, 42);
    }

    #[test]
    fn beacon_tamper_and_wrong_key_rejected() {
        let key = [0x67u8; 32];
        let mut buf = beacon::craft(&key, [1; 4], 1);
        buf[8] ^= 1;
        assert!(beacon::decode(&key, &buf).is_none());

        let buf = beacon::craft(&key, [1; 4], 1);
        assert!(beacon::decode(&[0x68u8; 32], &buf).is_none());
    }

    #[test]
    fn beacon_bad_magic_rejected() {
        let mut buf = beacon::craft(&[0x67u8; 32], [1; 4], 1);
        buf[0] = b'X';
        assert!(beacon::decode(&[0x67u8; 32], &buf).is_none());
    }
}