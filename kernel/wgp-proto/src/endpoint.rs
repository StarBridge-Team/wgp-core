//! 种子/服务器端点（07 §5 种子发现第 1 层的可配置形态）。
//! 支持：`udp://host:port`、`tcp://host:port`、裸 `ip:port`、裸 `host:port`（默认 udp）。
//! host 允许 IDN 中文域名，解析前经 `punycode::domain_to_ascii` 归一化。

/// 端点 scheme（udp=信令主通道；tcp=UDP 被封/受限时的信令兜底）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedScheme {
    Udp,
    Tcp,
}

/// 服务器端点 = scheme + host（域名或 IPv4）+ 端口
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedEndpoint {
    pub scheme: SeedScheme,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    BadScheme,     // 不认识的 scheme（如 http://）
    BadPort,       // 端口缺失/非数字/越界
    BadHost,       // 主机为空
    TooLong,       // 超长主机名
}

impl SeedEndpoint {
    /// 解析：udp://host:port | tcp://host:port | host:port | ipv4:port
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ParseError::Empty);
        }
        let (scheme_str, rest) = match s.split_once("://") {
            Some((sch, rest)) => (Some(sch), rest),
            None => (None, s),
        };
        let scheme = match scheme_str {
            None | Some("udp") | Some("UDP") => SeedScheme::Udp,
            Some("tcp") | Some("TCP") => SeedScheme::Tcp,
            Some(_) => return Err(ParseError::BadScheme),
        };
        // IPv4 直连带冒号端口：host:port；域名同上
        let (host, port_str) = match rest.rfind(':') {
            Some(idx) if rest[..idx].find(':').is_none() => (&rest[..idx], &rest[idx + 1..]),
            _ => {
                // 没有端口（裸 IPv4 或裸域名）→ 非法（端点必须指定端口）
                return Err(ParseError::BadPort);
            }
        };
        if host.is_empty() {
            return Err(ParseError::BadHost);
        }
        if host.len() > 253 {
            return Err(ParseError::TooLong);
        }
        let port: u16 = port_str.parse().map_err(|_| ParseError::BadPort)?;
        if port == 0 {
            return Err(ParseError::BadPort);
        }
        Ok(Self {
            scheme,
            host: host.to_string(),
            port,
        })
    }

    /// 回显（规范化字符串，配置展示用；保留原始 host 便于人读）
    pub fn display(&self) -> String {
        match self.scheme {
            SeedScheme::Udp => format!("udp://{}:{}", self.host, self.port),
            SeedScheme::Tcp => format!("tcp://{}:{}", self.host, self.port),
        }
    }

    /// 批量解析种子端点串（配置层用：逗号/分号/空白/换行分隔，忽略空项）。
    /// 返回 (成功列表, 失败项) —— 由调用方决定"容忍部分失败"还是"启动即报错"。
    pub fn parse_list(input: &str) -> (Vec<SeedEndpoint>, Vec<String>) {
        let mut ok = Vec::new();
        let mut bad = Vec::new();
        for raw in input.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            match SeedEndpoint::parse(item) {
                Ok(ep) => ok.push(ep),
                Err(_) => bad.push(item.to_string()),
            }
        }
        (ok, bad)
    }

    /// 用于 DNS 解析的 ASCII 主机名（IDN 中文域名 → punycode；纯 ASCII/IPv4 原样）。
    pub fn host_ascii(&self) -> String {
        crate::punycode::domain_to_ascii(&self.host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp_scheme_with_domain() {
        let e = SeedEndpoint::parse("udp://seed.example.com:3841").unwrap();
        assert_eq!(e.scheme, SeedScheme::Udp);
        assert_eq!(e.host, "seed.example.com");
        assert_eq!(e.port, 3841);
        assert_eq!(e.display(), "udp://seed.example.com:3841");
    }

    #[test]
    fn parse_bare_ip_port() {
        let e = SeedEndpoint::parse("120.53.11.77:3841").unwrap();
        assert_eq!(e.scheme, SeedScheme::Udp);
        assert_eq!(e.host, "120.53.11.77");
        assert_eq!(e.port, 3841);
    }

    #[test]
    fn parse_bare_domain_port() {
        let e = SeedEndpoint::parse("seed.wgp.dev:3478").unwrap();
        assert_eq!(e.host, "seed.wgp.dev");
        assert_eq!(e.port, 3478);
    }

    #[test]
    fn reject_bad_inputs() {
        assert_eq!(SeedEndpoint::parse(""), Err(ParseError::Empty));
        assert_eq!(
            SeedEndpoint::parse("http://x.com:11010"),
            Err(ParseError::BadScheme)
        );
        assert_eq!(SeedEndpoint::parse("udp://:3841"), Err(ParseError::BadHost));
        assert_eq!(SeedEndpoint::parse("udp://x.com"), Err(ParseError::BadPort));
        assert_eq!(SeedEndpoint::parse("udp://x.com:0"), Err(ParseError::BadPort));
        assert_eq!(
            SeedEndpoint::parse("udp://x.com:abc"),
            Err(ParseError::BadPort)
        );
        assert_eq!(SeedEndpoint::parse("udp://x.com:99999"), Err(ParseError::BadPort));
    }

    #[test]
    fn parse_tcp_scheme() {
        let e = SeedEndpoint::parse("tcp://seed.example.com:3841").unwrap();
        assert_eq!(e.scheme, SeedScheme::Tcp);
        assert_eq!(e.host, "seed.example.com");
        assert_eq!(e.port, 3841);
        assert_eq!(e.display(), "tcp://seed.example.com:3841");
    }

    #[test]
    fn parse_udp_idn_host_ascii() {
        // IDN 主机名：非 ASCII 域名解析前必须归一化为 punycode ASCII
        let e = SeedEndpoint::parse("udp://münchen.example:3841").unwrap();
        assert_eq!(e.scheme, SeedScheme::Udp);
        assert_eq!(e.host, "münchen.example");
        assert_eq!(e.host_ascii(), "xn--mnchen-3ya.example");
    }

    #[test]
    fn parse_list_splits_and_reports_bad() {
        let (ok, bad) =
            SeedEndpoint::parse_list("udp://a.example:1, tcp://b.example:2\n http://c.example:3");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].scheme, SeedScheme::Udp);
        assert_eq!(ok[1].scheme, SeedScheme::Tcp);
        assert_eq!(bad, vec!["http://c.example:3".to_string()]);
    }

    #[test]
    fn uppercase_scheme_ok() {
        let e = SeedEndpoint::parse("UDP://x.com:3841").unwrap();
        assert_eq!(e.scheme, SeedScheme::Udp);
        let t = SeedEndpoint::parse("TCP://x.com:3481").unwrap();
        assert_eq!(t.scheme, SeedScheme::Tcp);
    }
}