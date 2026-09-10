//! 观察者 / STUN 响应器（07 §3："一套编解码，两级能力"的第二级）。
//! 公共 STUN 仅回 MAPPED（一级）；本观察者额外回显 WGP-PEER 扩展（二级）。
//! 长沙 wgp-node 四职之一；可独立 socket（3478）或与 DhtNode 同 socket。

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use wgp_proto::stun::{binding_response, decode_attrs, wgp_attr, StunHeader, WgpPeerAttr};

/// 对入站报文判定是否为 Binding Request，是则构造响应（None = 非 STUN 业务）
pub fn try_answer_stun(buf: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    let header = StunHeader::decode(buf)?;
    if !header.is_binding_request() {
        return None;
    }
    // 客户端的 WGP-PEER 扩展（若有）→ 原样回显（Nonce 关联 + 往返测量）
    let echo = decode_attrs(buf.get(20..)?).and_then(|attrs| {
        for (t, v) in attrs {
            if t == wgp_attr::WGP_PEER {
                return WgpPeerAttr::decode(&v);
            }
        }
        None
    });

    // 仅支持 IPv4 源（v1 观察者；IPv6 未来线）
    let ipv4 = match src.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => return None,
    };
    Some(binding_response(&header.tx_id, ipv4, src.port(), echo.as_ref()))
}

/// 独立观察者服务（专用端口）
pub struct ObserverServer {
    socket: Arc<UdpSocket>,
}

impl ObserverServer {
    pub async fn bind(port: u16) -> std::io::Result<Arc<Self>> {
        let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let server = Arc::new(Self {
            socket: socket.clone(),
        });
        let loop_socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let (n, src) = match loop_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(resp) = try_answer_stun(&buf[..n], src) {
                    let _ = loop_socket.send_to(&resp, src).await;
                }
            }
        });
        Ok(server)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
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
}