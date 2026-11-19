//! 端点地址准入（审计 M2）。
//!
//! 种子目录与路由表只该收「别人真的可能连上」的地址。不设准入时，任何人都能把
//! `127.0.0.1:11010`、`10.0.0.5:11010`、`100.64.x.x`、`169.254.x.x` 或保留网段写进自己的
//! 签名广告，再把它转述出去——所有收到的人都去做一次注定失败的探活/打洞，白花流量与超时预算。
//!
//! 默认策略只收**公网可路由**的 IPv4。局域网与本机联调（开发、FRP 落在内网、单机多进程
//! 端到端）用显式策略 [`EndpointScope::LocalNetwork`]——必须是显式选择，不能是默认值，
//! 否则公共目录会被内网地址污染。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// 端点地址准入策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScope {
    /// 只接受公网可路由的 IPv4（默认）
    Public,
    /// 公网 + 回环 / RFC1918 / 链路本地（本机与局域网联调）
    LocalNetwork,
}

impl EndpointScope {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::LocalNetwork => 1,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        if v == 1 {
            Self::LocalNetwork
        } else {
            Self::Public
        }
    }

    /// 依**绑定地址**推断初始策略。
    ///
    /// 绑在回环 / 私网地址上的节点，本来就只能和本机或同一局域网通信——它也永远收不到
    /// 公网发来的包。这类节点默认放宽到 [`Self::LocalNetwork`]，让本机联调与单元测试
    /// 不必逐个显式设置；绑 `0.0.0.0` 或公网地址的节点保持严格默认。
    pub fn from_local_bind(bind: SocketAddr) -> Self {
        match bind.ip() {
            IpAddr::V4(ip) if ip.is_loopback() || ip.is_private() || ip.is_link_local() => {
                Self::LocalNetwork
            }
            _ => Self::Public,
        }
    }

    /// 该端点能否作为目的地址（只做地址层面的排除；是否可达由探活回答）
    pub fn allows(self, addr: SocketAddr) -> bool {
        let ip = match addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return false, // v1 仅 IPv4（IPv6 未来线）
        };
        if addr.port() == 0 || ip.is_unspecified() {
            return false;
        }
        match self {
            Self::Public => is_public_ipv4(ip),
            // 局域网策略：回环/私有/链路本地都放行（本机多进程与同交换机联调），
            // CGNAT、组播、保留段仍然拒——这些地址在局域网内也不可达。
            Self::LocalNetwork => {
                !ip.is_multicast() && !is_cgnat(ip) && !is_reserved(ip) && ip != Ipv4Addr::BROADCAST
            }
        }
    }
}

/// 该 IPv4 是否公网可路由（审计列出的特殊网段全部排除）
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
    {
        return false;
    }
    if is_cgnat(ip) || is_reserved(ip) {
        return false;
    }
    let [a, b, c, _] = ip.octets();
    // IETF 协议分配段（192.0.0.0/24）与三个文档/示例网段（TEST-NET-1/2/3）
    if a == 192 && b == 0 && c == 0 {
        return false;
    }
    if a == 192 && b == 0 && c == 2 {
        return false;
    }
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    // 198.18.0.0/15：基准测试保留
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 0.0.0.0/8（本网络）与 240.0.0.0/4（保留）
    if a == 0 {
        return false;
    }
    true
}

/// 100.64.0.0/10（运营商级 NAT，RFC 6598）：别人在公网上连不上
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

/// 依一组**用户显式给出的**端点推断该用哪种策略。
///
/// 用途：`wgp-node` 与客户端在启动时按「本机/局域网形态」自动选策略——只要配置里出现
/// 回环或私网地址（本机联调、同一交换机、FRP 落在内网），就说明这不是公网部署，
/// 放宽到 [`EndpointScope::LocalNetwork`]；全是公网地址则保持默认的严格策略。
///
/// 这**不是**让远端广告自己决定策略：只有用户自己写进配置的地址参与推断，
/// 别人的广告地址再特殊也改变不了本端的准入规则。
pub fn scope_for_endpoints(addrs: impl IntoIterator<Item = SocketAddr>) -> EndpointScope {
    for addr in addrs {
        if let IpAddr::V4(ip) = addr.ip() {
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                return EndpointScope::LocalNetwork;
            }
        }
    }
    EndpointScope::Public
}

/// 240.0.0.0/4（保留，含 255.255.255.255 广播）
fn is_reserved(ip: Ipv4Addr) -> bool {
    let [a, _, _, _] = ip.octets();
    a >= 240
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_scope_rejects_every_special_range_in_the_audit() {
        for bad in [
            "127.0.0.1:11010",       // 回环
            "10.1.2.3:11010",        // RFC1918
            "172.16.0.9:11010",      // RFC1918
            "172.31.255.1:11010",    // RFC1918 上界
            "192.168.1.2:11010",     // RFC1918
            "100.64.0.1:11010",      // CGNAT 下界
            "100.127.255.254:11010", // CGNAT 上界
            "169.254.1.1:11010",     // 链路本地
            "0.0.0.0:11010",         // 未指定
            "0.1.2.3:11010",         // 0/8
            "192.0.0.8:11010",       // IETF 协议分配
            "192.0.2.1:11010",       // TEST-NET-1
            "198.51.100.7:11010",    // TEST-NET-2
            "203.0.113.7:11010",     // TEST-NET-3（示例地址，不可路由）
            "198.18.0.1:11010",      // 基准测试
            "198.19.255.255:11010",  // 基准测试上界
            "224.0.0.1:11010",       // 组播
            "240.0.0.1:11010",       // 保留
            "255.255.255.255:11010", // 广播
            "[::1]:11010",           // IPv6（v1 不支持）
            "1.1.1.1:0",             // 端口 0
        ] {
            assert!(
                !EndpointScope::Public.allows(ep(bad)),
                "{bad} 不该被公共策略接受"
            );
        }
        for good in ["1.1.1.1:11010", "8.8.4.4:3478", "203.119.1.1:11010"] {
            assert!(
                EndpointScope::Public.allows(ep(good)),
                "{good} 是公网地址，应被接受"
            );
        }
    }

    #[test]
    fn local_scope_admits_loopback_and_private_but_not_cgnat_or_reserved() {
        let local = EndpointScope::LocalNetwork;
        for good in [
            "127.0.0.1:11010",
            "10.0.0.5:11010",
            "192.168.1.2:11010",
            "172.20.0.1:11010",
            "169.254.10.10:3478",
            "1.1.1.1:11010",
        ] {
            assert!(local.allows(ep(good)), "{good} 在局域网策略下应被接受");
        }
        for bad in [
            "100.64.0.1:11010",
            "224.0.0.1:11010",
            "255.255.255.255:11010",
            "0.0.0.0:11010",
            "127.0.0.1:0",
            "[::1]:11010",
        ] {
            assert!(!local.allows(ep(bad)), "{bad} 在任何策略下都不可用");
        }
    }

    #[test]
    fn scope_roundtrips_through_u8() {
        for scope in [EndpointScope::Public, EndpointScope::LocalNetwork] {
            assert_eq!(EndpointScope::from_u8(scope.as_u8()), scope);
        }
        assert_eq!(EndpointScope::from_u8(99), EndpointScope::Public);
    }
}
