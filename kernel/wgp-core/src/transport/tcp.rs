//! TCP 探针载体：simultaneous open 打洞（T1-T4 兜底路径）。
//!
//! 语义（00 §4 / 03 §5.5 TCP 探测）：
//!  - 本地绑定固定源端口（TCP 打洞要求双方源端口可预测）
//!  - 向对端预测端口发起 connect；双方同时打开时 SYN 交叉 → 连接建立
//!  - 连接建立后首帧互发 31B 验签探针（复用 UDP 帧格式，流上定长读取）

use super::probe::{craft_probe, now_ms, verify_probe};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// 单端口 TCP 打洞尝试超时（SYN 交叉窗口；retry 后总时长 < 800ms 波窗口）
pub const TCP_PORT_PUNCH_TIMEOUT_MS: u64 = 250;

/// 单端口重试次数（SYN 错位在真实 NAT 与 loopback 均会发生；03 §3.5.6 重试语义）
const PUNCH_RETRIES: u32 = 2;
const PUNCH_RETRY_GAP_MS: u64 = 80;

/// TCP 载体（Arc 内聚：多端口并行 spawn 可 Clone）
#[derive(Clone)]
pub struct TcpProbeCarrier {
    inner: Arc<TcpInner>,
}

struct TcpInner {
    /// 本地固定绑定地址（打洞源端口）
    bind_addr: SocketAddr,
    probe_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: AtomicU32,
}

impl TcpProbeCarrier {
    pub fn new(bind_addr: SocketAddr, probe_key: [u8; 32], session_tag: [u8; 4]) -> Self {
        Self {
            inner: Arc::new(TcpInner {
                bind_addr,
                probe_key,
                session_tag,
                nonce_seed: AtomicU32::new(0),
            }),
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.inner.bind_addr
    }

    fn next_nonce(&self) -> u32 {
        self.inner.nonce_seed.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 单端口打洞：simultaneous open + 双向探针验证（内置重试抗 SYN 错位）。
    /// 成功返回已验证的流量（对端探针 HMAC 通过）。
    pub async fn punch_port(&self, peer: SocketAddr) -> Option<TcpStream> {
        for _ in 0..=PUNCH_RETRIES {
            if let Some(stream) = self.try_punch_once(peer).await {
                return Some(stream);
            }
            tokio::time::sleep(Duration::from_millis(PUNCH_RETRY_GAP_MS)).await;
        }
        None
    }

    async fn try_punch_once(&self, peer: SocketAddr) -> Option<TcpStream> {
        // ① 固定源端口发起连接（交叉即建立）
        let socket = TcpSocket::new_v4().ok()?;
        socket.bind(self.inner.bind_addr).ok()?;
        let mut stream = tokio::time::timeout(
            Duration::from_millis(TCP_PORT_PUNCH_TIMEOUT_MS),
            socket.connect(peer),
        )
        .await
        .ok()?
        .ok()?;
        stream.set_nodelay(true).ok(); // 02 §2.2：立即禁用 Nagle

        // ② 互发验签探针首帧
        let probe = craft_probe(
            &self.inner.probe_key,
            self.inner.session_tag,
            self.next_nonce(),
            now_ms(),
        );
        if stream.write_all(&probe).await.is_err() {
            return None;
        }
        // ③ 读对端探针并验签（超时即视为未通过）
        let mut buf = [0u8; 31];
        let read = tokio::time::timeout(
            Duration::from_millis(TCP_PORT_PUNCH_TIMEOUT_MS),
            stream.read_exact(&mut buf),
        )
        .await
        .ok()?;
        if read.is_err() {
            return None;
        }
        verify_probe(&self.inner.probe_key, &buf)?;
        Some(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// 占坑取一个空闲端口（drop 后立即复用，本地测试竞态可忽略）
    async fn reserve_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    #[tokio::test]
    async fn simultaneous_open_both_sides_verified() {
        let key = [0x77u8; 32];
        let a_addr: SocketAddr = format!("127.0.0.1:{}", reserve_port().await)
            .parse()
            .unwrap();
        let b_addr: SocketAddr = format!("127.0.0.1:{}", reserve_port().await)
            .parse()
            .unwrap();

        let a = TcpProbeCarrier::new(a_addr, key, [1, 2, 3, 4]);
        let b = TcpProbeCarrier::new(b_addr, key, [5, 6, 7, 8]);

        // 双方同时打开（SYN 交叉；loopback 下等价于真实 NAT 的 simultaneous open）
        let (a2, b2) = (a.clone(), b.clone());
        let (ra, rb) = tokio::join!(a2.punch_port(b_addr), b2.punch_port(a_addr));
        assert!(ra.is_some(), "A 侧应建立连接并完成探针互验");
        assert!(rb.is_some(), "B 侧应建立连接并完成探针互验");
    }

    #[tokio::test]
    async fn mismatched_keys_reject_each_other() {
        let a_addr: SocketAddr = format!("127.0.0.1:{}", reserve_port().await)
            .parse()
            .unwrap();
        let b_addr: SocketAddr = format!("127.0.0.1:{}", reserve_port().await)
            .parse()
            .unwrap();

        // 密钥不同 = 未完成承诺-揭示的"陌生人"：连接可能建立但探针必须互拒
        let a = TcpProbeCarrier::new(a_addr, [0x11u8; 32], [1, 1, 1, 1]);
        let b = TcpProbeCarrier::new(b_addr, [0x22u8; 32], [2, 2, 2, 2]);

        let (a2, b2) = (a.clone(), b.clone());
        let (ra, rb) = tokio::join!(a2.punch_port(b_addr), b2.punch_port(a_addr));
        assert!(ra.is_none(), "错密钥探针必须被拒");
        assert!(rb.is_none(), "错密钥探针必须被拒");
    }
}