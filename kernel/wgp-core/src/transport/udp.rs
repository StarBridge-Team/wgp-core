//! 载体实现（wgp-core 侧）：UDP 探针载体。
//! 探针定长 31B（packet::probe），HMAC 由 probe_key 签名（03 §3.5.5）。
//! 保活与三波共用同一 socket；打洞成功后该 socket 移交 QUIC 作链路载体。

use super::probe::{craft_probe, now_ms, verify_probe};
use crate::ProbeCarrier;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use wgp_proto::packet::{probe, Probe};
use wgp_punch::{CarrierError, MappingSemantics, TransportCapability};

/// UDP 探针载体
pub struct UdpProbeCarrier {
    socket: Arc<UdpSocket>,
    probe_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: AtomicU32,
    timestamp_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl UdpProbeCarrier {
    pub async fn bind(
        local: SocketAddr,
        probe_key: [u8; 32],
        session_tag: [u8; 4],
    ) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(local).await?);
        Ok(Self {
            socket,
            probe_key,
            session_tag,
            nonce_seed: AtomicU32::new(0),
            timestamp_fn: Arc::new(now_ms),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 打洞成功后取出底层 socket（Arc 共享；QUIC 端复用同一 socket 握手）
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// 时间源替换（引擎注入网络时间锚点换算函数；默认为单调相对毫秒）
    pub fn set_timestamp_fn(&mut self, f: impl Fn() -> u64 + Send + Sync + 'static) {
        self.timestamp_fn = Arc::new(f);
    }

    /// 组一枚探针（31B 定长，前 19B 签名；&self 并发安全，nonce 原子递增）
    pub fn craft(&self) -> [u8; probe::LEN] {
        let n = self.nonce_seed.fetch_add(1, Ordering::Relaxed) + 1;
        craft_probe(&self.probe_key, self.session_tag, n, (self.timestamp_fn)())
    }

    /// 异步收一枚探针并验证（长度/魔数/类型 + HMAC）；失败静默丢弃
    pub async fn recv_verified(&self) -> Option<(Probe, SocketAddr)> {
        let mut buf = [0u8; probe::LEN];
        let (n, src) = self.socket.recv_from(&mut buf).await.ok()?;
        if n != probe::LEN {
            return None;
        }
        let p = verify_probe(&self.probe_key, &buf)?;
        Some((p, src))
    }
}

impl ProbeCarrier for UdpProbeCarrier {
    async fn send_probe(&self, dst: SocketAddr, payload: &[u8]) -> Result<(), CarrierError> {
        if payload.len() != probe::LEN {
            return Err(CarrierError("探针载荷必须 31B"));
        }
        self.socket
            .send_to(payload, dst)
            .await
            .map(|_| ())
            .map_err(|_| CarrierError("UDP 探针发送失败"))
    }

    fn on_probe(&self, _src: SocketAddr, payload: &[u8]) -> bool {
        verify_probe(&self.probe_key, payload).is_some()
    }

    fn mapping_semantics(&self) -> MappingSemantics {
        MappingSemantics::PortTagged {
            port: self.local_addr().map(|a| a.port()).unwrap_or(0),
        }
    }

    fn capability(&self) -> TransportCapability {
        TransportCapability::Udp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[tokio::test]
    async fn hmac_verify_and_tamper_rejection() {
        let key = [0xA1u8; 32];
        let carrier = UdpProbeCarrier::bind(addr(), key, [0x11u8; 4]).await.unwrap();
        let probe_buf = carrier.craft();
        assert_eq!(probe_buf.len(), probe::LEN);

        let peer = UdpProbeCarrier::bind(addr(), key, [0x22u8; 4]).await.unwrap();
        // 同 key（交换会话后的对端）验签通过
        assert!(peer.on_probe(addr(), &probe_buf));

        // 篡改一字节 → 拒绝
        let mut tampered = probe_buf;
        tampered[11] ^= 0xFF;
        assert!(!peer.on_probe(addr(), &tampered));

        // 错误密钥 → 拒绝
        let wrong = UdpProbeCarrier::bind(addr(), [0xB2u8; 32], [0x22u8; 4])
            .await
            .unwrap();
        assert!(!wrong.on_probe(addr(), &probe_buf));
    }

    #[tokio::test]
    async fn send_recv_roundtrip_across_two_carriers() {
        let key = [0xC3u8; 32];
        let a = UdpProbeCarrier::bind(addr(), key, [0x11u8; 4]).await.unwrap();
        let b = UdpProbeCarrier::bind(addr(), key, [0x22u8; 4]).await.unwrap();

        // host 场景：本地一个"公网"不可达载体；验证同机 A→B 直连可验签
        let a_addr = a.local_addr().unwrap();
        let probe_buf = a.craft();
        // 由 A 的 socket 直接 send_to B（同 key 对端收验）
        a.socket()
            .send_to(&probe_buf, b.local_addr().unwrap())
            .await
            .expect("send_ok");

        let got = b.recv_verified().await;
        assert!(got.is_some(), "对端收到并验签通过");
        let (p, src) = got.unwrap();
        assert_eq!(p.session_tag, [0x11u8; 4]);
        assert_eq!(src, a_addr);
    }
}