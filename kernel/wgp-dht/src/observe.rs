//! 观察者 / STUN 响应器（07 §3："一套编解码，两级能力"的第二级）。
//! 公共 STUN 仅回 MAPPED（一级）；本观察者额外回显 WGP-PEER 扩展（二级）。
//! wgp-node 四职之一；可独立 socket（配置的观察者端口）或与 DhtNode 同 socket。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use wgp_proto::stun::{binding_response, decode_attrs, wgp_attr, StunHeader, WgpPeerAttr};

use crate::ratelimit::{RateGate, RatePolicy};

/// 观察者响应限频默认值（07 §7 贡献模式防滥用）。
///
/// **额度与真实用量对齐**（审计简单项）：一次协商里每端向观察者发 4 次探测
/// （观测 + 步长三连测），而同一个公网 IP 后面可能坐着多台机器（家庭 / 网吧 / 运营商 NAT）。
/// 旧值 12 次 / 10s 在 4 个成员并发协商时就会打满，被限的是正常用户。现在 60 次 / 10s
/// 约等于 15 个成员并发；再叠加全局 600 次 / 秒与「按 IP 归一」两道，滥用仍然被挡。
/// 超出即视为滥用（刷子/洪流），静默丢弃。运维可用 `--observer-rate-limit` 覆盖。
pub const OBSERVER_RATE_LIMIT: u32 = 60;
pub const OBSERVER_RATE_WINDOW: Duration = Duration::from_secs(10);

/// 观察者限频策略（每 IP / 窗口允许的响应数）。
///
/// 具体数值属运维策略：内核只提供机制与安全默认值，
/// 实际取值由后端配置注入（`ObserverServer::bind_with_policy`）。
#[derive(Debug, Clone, Copy)]
pub struct ObserverPolicy {
    pub rate_limit: u32,
    pub rate_window: Duration,
    /// 前置代理会注入 PROXY protocol v2 时置 true：用头里的**真实**客户端地址做
    /// 映射报告与限速，而不是代理自己的地址。默认 false（直接把来源当客户端）。
    ///
    /// 只能在「本端口只可能被可信代理访问」时打开，否则任何人都能伪造来源。
    pub proxy_protocol: bool,
}

impl Default for ObserverPolicy {
    fn default() -> Self {
        Self {
            rate_limit: OBSERVER_RATE_LIMIT,
            rate_window: OBSERVER_RATE_WINDOW,
            proxy_protocol: false,
        }
    }
}

impl ObserverPolicy {
    /// 转成通用闸门策略：保留运维给出的单源额度与窗口，全局额度用默认值
    pub fn rate_policy(&self) -> RatePolicy {
        RatePolicy {
            per_ip: self.rate_limit.max(1),
            window: self.rate_window,
            ..RatePolicy::default()
        }
    }
}

/// 对入站报文判定是否为 Binding Request，是则构造响应（None = 非 STUN 业务）
pub fn try_answer_stun(buf: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    try_answer_stun_ex(buf, src, false).map(|(_, resp)| resp)
}

/// 同 [`try_answer_stun`]，但可以识别前置代理注入的 PROXY protocol v2。
///
/// 返回 `(声称的客户端地址, 响应字节)`：
/// - `proxy_v2` 为 true 且报文以 v2 头开头时，映射报告与限速都用头里的真实来源；
/// - 否则用 `src`（UDP 看到的来源）。
///
/// **响应永远回给 `src`**（也就是代理），绝不回给头里声明的地址——那个地址在隧道外面，
/// 直接发过去既到不了，也会成为反射放大器。
pub fn try_answer_stun_ex(
    buf: &[u8],
    src: SocketAddr,
    proxy_v2: bool,
) -> Option<(SocketAddr, Vec<u8>)> {
    let (claimed, body) = if proxy_v2 {
        match crate::proxy_protocol::strip_v2(buf) {
            Some((info, rest)) => (info.source.unwrap_or(src), rest),
            None => (src, buf),
        }
    } else {
        (src, buf)
    };
    let header = StunHeader::decode(body)?;
    if !header.is_binding_request() {
        return None;
    }
    // 客户端的 WGP-PEER 扩展（若有）→ 原样回显（Nonce 关联 + 往返测量）
    let echo = decode_attrs(body.get(20..)?).and_then(|attrs| {
        for (t, v) in attrs {
            if t == wgp_attr::WGP_PEER {
                return WgpPeerAttr::decode(&v);
            }
        }
        None
    });

    // 仅支持 IPv4 源（v1 观察者；IPv6 未来线）
    let ipv4 = match claimed.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return None,
    };
    Some((
        claimed,
        binding_response(&header.tx_id, ipv4, claimed.port(), echo.as_ref()),
    ))
}

/// 独立观察者服务（专用端口；内置每 IP 限频）
pub struct ObserverServer {
    socket: Arc<UdpSocket>,
    /// 限频闸门（IP 归一 + 清扫 + 硬上限）
    gate: Mutex<RateGate>,
    /// 限频策略（由部署配置注入；默认见 `ObserverPolicy::default`）
    policy: ObserverPolicy,
}

impl ObserverServer {
    /// 以默认限频策略绑定（端到端测试/内置装配入口）
    pub async fn bind(port: u16) -> std::io::Result<Arc<Self>> {
        Self::bind_with_policy(port, ObserverPolicy::default()).await
    }

    /// 以显式限频策略绑定（wgp-node 由后端配置注入）
    pub async fn bind_with_policy(
        port: u16,
        policy: ObserverPolicy,
    ) -> std::io::Result<Arc<Self>> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let server = Arc::new(Self {
            socket: socket.clone(),
            gate: Mutex::new(RateGate::new(policy.rate_policy())),
            policy,
        });
        let loop_socket = socket.clone();
        let loop_server = server.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let (n, src) = match loop_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some((claimed, resp)) =
                    try_answer_stun_ex(&buf[..n], src, loop_server.policy.proxy_protocol)
                {
                    // 限频闸门：按**真实来源**计数（PROXY v2 打开时就是头里的客户端地址）。
                    // 超限静默丢弃（防刷观察者/贡献节点保带宽特征）。
                    let admitted = {
                        let mut g = loop_server.gate.lock().await;
                        g.admit(claimed.ip(), Instant::now())
                    };
                    if !admitted {
                        continue;
                    }
                    // 回给代理（src），不是头里声明的地址
                    let _ = loop_socket.send_to(&resp, src).await;
                }
            }
        });
        Ok(server)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 当前生效的限频策略（运维诊断 / 日志用）
    pub fn policy(&self) -> ObserverPolicy {
        self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wgp_proto::stun::{
        decode_xor_mapped, wgp_attr::WGP_PEER, ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST,
        MAGIC_COOKIE,
    };

    fn client_binding_with_echo(txid: [u8; 12], nonce: [u8; 8]) -> Vec<u8> {
        // 构造带 WGP-PEER 扩展的 Binding Request
        let mut out = Vec::new();
        out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // len 后补
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&txid);
        let echo = WgpPeerAttr {
            peer_prefix: [7, 7, 7, 7],
            nonce,
            timestamp: [3; 8],
            flags: [0, 0, 0, 0],
        };
        let mut payload = [0u8; wgp_proto::stun::WGP_PEER_PAYLOAD_LEN];
        echo.encode(&mut payload);
        wgp_proto::stun::encode_attr(WGP_PEER, &payload, &mut out);
        let len = (out.len() - 20) as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    #[tokio::test]
    async fn observer_reports_mapped_and_echoes() {
        let server = ObserverServer::bind(0).await.unwrap();
        // 0.0.0.0 不可直拨：测试环境以 127.0.0.1 同端口访问
        let server_addr: SocketAddr = format!(
            "127.0.0.1:{}",
            server.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let txid = [0x42; 12];
        let nonce = [9, 8, 7, 6, 5, 4, 3, 2];
        let req = client_binding_with_echo(txid, nonce);
        client.send_to(&req, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, src) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(src, server_addr, "响应必须来自观察者");

        let header = StunHeader::decode(&buf[..n]).unwrap();
        assert_eq!(header.tx_id, txid, "txid 回显关联请求");

        let attrs = decode_attrs(&buf[20..n]).unwrap();
        let mut mapped = None;
        let mut echoed_nonce = None;
        for (t, v) in attrs {
            match t {
                ATTR_XOR_MAPPED_ADDRESS => {
                    let (ip, port) = decode_xor_mapped(&v).unwrap();
                    mapped = Some((ip, port));
                }
                WGP_PEER => {
                    let echo = WgpPeerAttr::decode(&v).unwrap();
                    echoed_nonce = Some(echo.nonce);
                }
                _ => {}
            }
        }
        // 观察者视角的"我的公网端点" = 客户端源地址（loopback 测试中即真实地址）
        let expect_ip = match client_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => panic!("期望 IPv4"),
        };
        assert_eq!(mapped, Some((expect_ip, client_addr.port())));
        assert_eq!(echoed_nonce, Some(nonce), "WGP-PEER 扩展必须回显");
    }

    #[tokio::test]
    async fn observer_ignores_non_stun() {
        let server = ObserverServer::bind(0).await.unwrap();
        let server_addr: SocketAddr = format!(
            "127.0.0.1:{}",
            server.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 发送垃圾载荷（非 STUN）→ 观察者不应答
        client
            .send_to(&[0x00u8; 32], server_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(res.is_err(), "非 STUN 报文必须被静默忽略");
    }

    /// 限频：单 IP 30 连发，仅前 12 有响应，剩余静默丢弃
    #[tokio::test]
    async fn observer_rate_limit_drops_flood() {
        let server = ObserverServer::bind(0).await.unwrap();
        let server_addr: SocketAddr = format!(
            "127.0.0.1:{}",
            server.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let req = client_binding_with_echo([0x55; 12], [0; 8]);
        for _ in 0..(OBSERVER_RATE_LIMIT + 8) {
            client.send_to(&req, server_addr).await.unwrap();
        }

        // 读窗口期内全部响应
        let mut buf = [0u8; 512];
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(900);
        let mut received = 0usize;
        while std::time::Instant::now() < deadline {
            match tokio::time::timeout(
                std::time::Duration::from_millis(120),
                client.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }
        assert!(
            received <= OBSERVER_RATE_LIMIT as usize,
            "洪流必须被截断：收 {received}（上限 {OBSERVER_RATE_LIMIT}）"
        );
        assert!(
            received >= OBSERVER_RATE_LIMIT as usize,
            "正常额度内应全部响应：收 {received}"
        );
    }

    /// 绕过回归：同一 IP、不同源端口轮流向观察者发请求——    /// 限频必须按 IP 归一，总额度依然是 12（旧实现按 IP:port 计数可无限刷）
    #[tokio::test]
    async fn observer_rate_limit_keys_by_ip_not_port() {
        let server = ObserverServer::bind(0).await.unwrap();
        let server_addr: SocketAddr = format!(
            "127.0.0.1:{}",
            server.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();

        // 全部源端口各只发 1 请求，端口数超过单 IP 额度——额度必须按 IP 归一
        let mut clients = Vec::new();
        for i in 0..(OBSERVER_RATE_LIMIT + 6) as u16 {
            let client = UdpSocket::bind(format!("127.0.0.1:{}", 20_000 + i))
                .await
                .unwrap();
            let req = client_binding_with_echo([0x66; 12], [i as u8; 8]);
            client.send_to(&req, server_addr).await.unwrap();
            clients.push(client);
        }

        // 等待响应落地后逐 socket 清点
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let mut received = 0usize;
        let mut buf = [0u8; 512];
        for client in &clients {
            while let Ok((_, _)) = client.try_recv_from(&mut buf) {
                received += 1;
            }
        }
        assert!(
            received <= OBSERVER_RATE_LIMIT as usize,
            "端口轮换不得放大总额度：收 {received}（上限 {OBSERVER_RATE_LIMIT}）"
        );
    }

    /// 组一个 PROXY v2 UDP/IPv4 头（测试用）
    fn proxy_v2_udp_header(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut out = crate::proxy_protocol::SIGNATURE.to_vec();
        out.push(0x21); // version 2, PROXY
        out.push(0x12); // UDP over IPv4
        out.extend_from_slice(&12u16.to_be_bytes());
        out.extend_from_slice(&src);
        out.extend_from_slice(&dst);
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out
    }

    /// 前置代理（FRP / nginx stream）注入 PROXY v2 时：
    /// 映射报告必须用**头里的真实客户端地址**，应答仍然回给代理。
    #[tokio::test]
    async fn observer_with_proxy_v2_reports_the_real_client_address() {
        let policy = ObserverPolicy {
            rate_limit: OBSERVER_RATE_LIMIT,
            rate_window: OBSERVER_RATE_WINDOW,
            proxy_protocol: true,
        };
        let server = ObserverServer::bind_with_policy(0, policy).await.unwrap();
        let server_addr: SocketAddr = format!(
            "127.0.0.1:{}",
            server.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let txid = [0x7Bu8; 12];
        let nonce = [1u8; 8];

        // 头里声称：真实客户端是 203.0.113.9:41107
        let mut datagram = proxy_v2_udp_header([203, 0, 113, 9], 41107, [198, 51, 100, 2], 3478);
        datagram.extend_from_slice(&client_binding_with_echo(txid, nonce));
        client.send_to(&datagram, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, src) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("应有应答")
        .unwrap();
        // 应答必须回到代理（也就是发送方），不能发往头里声称的地址
        assert_eq!(src, server_addr, "应答必须回到代理地址");

        let attrs = decode_attrs(&buf[20..n]).unwrap();
        let mut mapped = None;
        for (t, v) in attrs {
            if t == ATTR_XOR_MAPPED_ADDRESS {
                mapped = Some(decode_xor_mapped(&v).unwrap());
            }
        }
        assert_eq!(
            mapped,
            Some(([203, 0, 113, 9], 41107)),
            "映射报告必须使用 PROXY v2 头里的真实来源"
        );
    }

    /// 没开 PROXY v2 时，带头的报文不该被当成 STUN（否则报告会指向伪造地址）
    #[tokio::test]
    async fn observer_without_proxy_v2_ignores_prefixed_datagrams() {
        let server = ObserverServer::bind(0).await.unwrap();
        let server_addr: SocketAddr = format!(
            "127.0.0.1:{}",
            server.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = proxy_v2_udp_header([203, 0, 113, 9], 41107, [198, 51, 100, 2], 3478);
        datagram.extend_from_slice(&client_binding_with_echo([0x7C; 12], [2u8; 8]));
        client.send_to(&datagram, server_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(res.is_err(), "默认关闭时必须把它当坏包忽略");
    }
}