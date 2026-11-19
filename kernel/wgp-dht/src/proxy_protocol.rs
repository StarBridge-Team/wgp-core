//! PROXY protocol v2（HAProxy 规范）解析。
//!
//! **为什么需要**：种子挂在 FRP / nginx stream / 云负载均衡这类前置代理后面时，我们看到的
//! 源地址是那个代理的地址。观察者若拿它当「客户端公网端点」，NAT 判定会得出错误结论，
//! 打洞也会指向代理而不是客户端；限速同样会把所有用户算成同一个 IP。
//! 支持该协议的代理会在连接或数据报最前面加一段二进制头，携带**真实**源/目的地址：
//!
//! ```text
//! \r\n\r\n\0\r\nQUIT\n | ver/cmd(1) | fam/proto(1) | len(2, BE) | 地址块(len 字节)
//! ```
//!
//! **安全前提**：只能在「这个端口只可能被可信前置代理访问」时启用（服务商隧道、本机 nginx）。
//! 直接暴露在公网时启用它，等于把「我是谁」交给客户端自称——任何人都能伪造来源，
//! 从而污染观察者报告、地址簿与限速。默认关闭。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 固定的 12 字节签名
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// 固定部分长度（签名 12 + 版本命令 1 + 族协议 1 + 长度 2）
pub const FIXED_LEN: usize = 16;
/// 头部总长度上限（规范允许地址块带 TLVs，这里给一个防御性上界）
pub const MAX_HEADER: usize = 16 + 65_535;

/// 传输层类型（v2 的族/协议字节里带）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyTransport {
    Tcp,
    Udp,
}

/// 解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyV2 {
    /// 头部总长度：有效载荷从 `buf[header_len..]` 开始
    pub header_len: usize,
    /// 真实源地址；`LOCAL` 命令或 UNSPEC 族时为 None
    pub source: Option<SocketAddr>,
    /// 真实目的地址（诊断用）
    pub destination: Option<SocketAddr>,
    /// 传输层类型；UNSPEC 时为 None
    pub transport: Option<ProxyTransport>,
}

/// 这段字节看起来是不是 PROXY v2（只比对签名，不做完整校验）
pub fn looks_like_v2(buf: &[u8]) -> bool {
    buf.len() >= SIGNATURE.len() && buf[..SIGNATURE.len()] == SIGNATURE
}

/// 解析 PROXY v2 头。
///
/// 返回 None = 不是 v2（签名/版本不符）或长度不足（数据报被截断）。
/// `LOCAL` 命令（健康检查）返回 `source: None`，调用方应视为「没有真实来源」。
pub fn parse_v2(buf: &[u8]) -> Option<ProxyV2> {
    if !looks_like_v2(buf) || buf.len() < FIXED_LEN {
        return None;
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 2 {
        return None; // 只支持 v2
    }
    let command = ver_cmd & 0x0F; // 0 = LOCAL, 1 = PROXY
    let fam_proto = buf[13];
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let header_len = FIXED_LEN + addr_len;
    if header_len > MAX_HEADER || buf.len() < header_len {
        return None;
    }
    let block = &buf[FIXED_LEN..header_len];

    let mut out = ProxyV2 {
        header_len,
        source: None,
        destination: None,
        transport: None,
    };
    if command == 0 {
        return Some(out); // LOCAL：没有地址信息
    }
    if command != 1 {
        return None;
    }

    match fam_proto {
        // TCP over IPv4
        0x11 | 0x12 => {
            if block.len() < 12 {
                return None;
            }
            let src = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let dst = Ipv4Addr::new(block[4], block[5], block[6], block[7]);
            let sport = u16::from_be_bytes([block[8], block[9]]);
            let dport = u16::from_be_bytes([block[10], block[11]]);
            out.source = Some(SocketAddr::new(IpAddr::V4(src), sport));
            out.destination = Some(SocketAddr::new(IpAddr::V4(dst), dport));
            out.transport = Some(if fam_proto == 0x11 {
                ProxyTransport::Tcp
            } else {
                ProxyTransport::Udp
            });
            Some(out)
        }
        // TCP/UDP over IPv6
        0x21 | 0x22 => {
            if block.len() < 36 {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&block[0..16]);
            dst.copy_from_slice(&block[16..32]);
            let sport = u16::from_be_bytes([block[32], block[33]]);
            let dport = u16::from_be_bytes([block[34], block[35]]);
            out.source = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), sport));
            out.destination = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(dst)), dport));
            out.transport = Some(if fam_proto == 0x21 {
                ProxyTransport::Tcp
            } else {
                ProxyTransport::Udp
            });
            Some(out)
        }
        // UNSPEC / 其它：有头，但没有地址
        _ => Some(out),
    }
}

/// 剥掉 v2 头：`Some((解析结果, 载荷))`；不是 v2 时返回 None（调用方按原样处理）
pub fn strip_v2(buf: &[u8]) -> Option<(ProxyV2, &[u8])> {
    let info = parse_v2(buf)?;
    Some((info, &buf[info.header_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(fam_proto: u8, block: &[u8]) -> Vec<u8> {
        let mut out = SIGNATURE.to_vec();
        out.push(0x21); // version 2, PROXY
        out.push(fam_proto);
        out.extend_from_slice(&(block.len() as u16).to_be_bytes());
        out.extend_from_slice(block);
        out
    }

    #[test]
    fn ipv4_tcp_and_udp_sources_are_parsed() {
        // 203.0.113.9:41107 -> 198.51.100.2:11010
        let mut block = Vec::new();
        block.extend_from_slice(&[203, 0, 113, 9]);
        block.extend_from_slice(&[198, 51, 100, 2]);
        block.extend_from_slice(&41107u16.to_be_bytes());
        block.extend_from_slice(&11010u16.to_be_bytes());

        for (fam, want) in [(0x11u8, ProxyTransport::Tcp), (0x12, ProxyTransport::Udp)] {
            let buf = header(fam, &block);
            let info = parse_v2(&buf).expect("应能解析");
            assert_eq!(info.header_len, FIXED_LEN + 12);
            assert_eq!(
                info.source,
                Some("203.0.113.9:41107".parse().unwrap()),
                "源地址必须是头里声明的那个"
            );
            assert_eq!(info.destination, Some("198.51.100.2:11010".parse().unwrap()));
            assert_eq!(info.transport, Some(want));

            // 载荷从 header_len 开始
            let mut with_payload = buf.clone();
            with_payload.extend_from_slice(b"payload");
            let (info, payload) = strip_v2(&with_payload).expect("应能剥离");
            assert_eq!(info.source, info.source);
            assert_eq!(payload, b"payload");
        }
    }

    #[test]
    fn ipv6_source_is_parsed() {
        let mut block = vec![0u8; 36];
        block[15] = 0x01; // ::1
        block[31] = 0x02; // ::2
        block[32..34].copy_from_slice(&5000u16.to_be_bytes());
        block[34..36].copy_from_slice(&3478u16.to_be_bytes());
        let buf = header(0x22, &block);
        let info = parse_v2(&buf).expect("IPv6 应能解析");
        assert_eq!(info.source, Some("[::1]:5000".parse().unwrap()));
        assert_eq!(info.transport, Some(ProxyTransport::Udp));
    }

    #[test]
    fn local_command_has_no_source() {
        let mut buf = SIGNATURE.to_vec();
        buf.push(0x20); // LOCAL
        buf.push(0x00); // UNSPEC
        buf.extend_from_slice(&0u16.to_be_bytes());
        let info = parse_v2(&buf).expect("LOCAL 也要认出头部长度");
        assert_eq!(info.header_len, FIXED_LEN);
        assert!(info.source.is_none());
        assert!(info.transport.is_none());
    }

    #[test]
    fn garbage_truncated_and_v1_are_rejected() {
        assert!(!looks_like_v2(b"GET / HTTP/1.1\r\n"));
        assert!(parse_v2(b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse_v2(&[]).is_none());
        // 只有签名没有固定部分
        assert!(parse_v2(&SIGNATURE).is_none());
        // 声明长度超过实际数据（数据报被截断）
        let mut buf = header(0x11, &[0u8; 12]);
        buf.truncate(buf.len() - 1);
        assert!(parse_v2(&buf).is_none(), "截断的头必须拒绝");
        // 版本 1
        let mut v1 = SIGNATURE.to_vec();
        v1.push(0x11);
        v1.push(0x11);
        v1.extend_from_slice(&12u16.to_be_bytes());
        v1.extend_from_slice(&[0u8; 12]);
        assert!(parse_v2(&v1).is_none(), "只支持 v2");
    }
}
