//! 房间请求的执行：种子解析、承载选择、存储选点、端口转发配置。
//!
//! 这里的逻辑与 `wgp-client` 的同名流程保持一致（两端必须对「同一个房间用哪个存储节点」
//! 有相同的答案，否则各自建一个房间）。差异只有一处：agent 的入参来自 IPC 的
//! [`RoomRequest`]，不是命令行字符串。

use std::net::SocketAddr;
use std::sync::Arc;

use wgp_core::servers::{measure_seeds, resolve_endpoint};
use wgp_dht::{DhtNode, RoomRuntime, SeedInfo, StorageCandidate, Transport};
use wgp_ipc::RoomRequest;
use wgp_port::{ExposeRule, ForwardRule, PortConfig};
use wgp_proto::{SeedEndpoint, SeedScheme};

/// 选点结果：存储节点 + 承载 + 该房间此刻是否已存在
#[derive(Debug, Clone, Copy)]
pub struct StoragePickOut {
    pub storage: SocketAddr,
    pub transport: Transport,
    pub existed: Option<bool>,
}

/// 把 IPC 里的种子串解析成端点（一次解析失败即整体报错，不静默跳过）
pub fn parse_seeds(specs: &[String]) -> Result<Vec<SeedEndpoint>, String> {
    if specs.is_empty() {
        return Err("房间请求没有给种子端点（seeds 为空）".to_string());
    }
    let joined = specs.join(",");
    let (eps, bad) = SeedEndpoint::parse_list(&joined);
    if let Some(b) = bad.first() {
        return Err(format!("种子端点非法（应为 udp://主机:端口 或 tcp://主机:端口）：{b}"));
    }
    if eps.is_empty() {
        return Err("种子端点解析结果为空".to_string());
    }
    Ok(eps)
}

/// 承载选择：全给 tcp:// 才走 TCP（与客户端一致）
pub fn choose_transport(eps: &[SeedEndpoint]) -> Transport {
    if !eps.is_empty() && eps.iter().all(|ep| ep.scheme == SeedScheme::Tcp) {
        Transport::Tcp
    } else {
        Transport::Udp
    }
}

/// 测速 + 发现 + 选点。返回 (存储节点, 承载, 房间此前是否存在)。
///
/// 失败一律返回可读原因：IPC 的 `ResponsePayload::Error` 会原样送到 UI。
pub async fn resolve_storage(
    node: &Arc<DhtNode>,
    eps: &[SeedEndpoint],
    transport: Transport,
    code: &str,
    explicit: Option<&str>,
) -> Result<StoragePickOut, String> {
    node.set_signaling_transport(transport);

    if let Some(spec) = explicit {
        let ep = SeedEndpoint::parse(spec).map_err(|e| format!("storage 解析失败：{e:?}"))?;
        let addr = resolve_endpoint(&ep)
            .await
            .ok_or_else(|| format!("storage 无法解析为地址：{spec}"))?;
        // 端点准入（审计 M2）：显式存储节点若是回环/私网地址，说明这是本机或局域网形态
        node.set_endpoint_scope(wgp_dht::scope_for_endpoints([addr]));
        let explicit_transport = match ep.scheme {
            SeedScheme::Tcp => Transport::Tcp,
            SeedScheme::Udp => Transport::Udp,
        };
        return Ok(StoragePickOut {
            storage: addr,
            transport: explicit_transport,
            existed: None,
        });
    }

    let picks = measure_seeds(node, eps).await;
    if picks.is_empty() {
        return Err(format!(
            "全部种子端点不可达（{}）。请检查种子是否在线、协议与端口是否填对",
            eps.iter()
                .map(|e| e.display())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let entries: Vec<SocketAddr> = picks
        .iter()
        .filter(|p| (transport == Transport::Tcp) == (p.endpoint.scheme == SeedScheme::Tcp))
        .map(|p| p.addr)
        .collect();
    if entries.is_empty() {
        return Err(format!(
            "没有可用的 {} 种子端点；UDP 被封时请用 tcp://<主机>:<TCP 信令端口>",
            transport.scheme()
        ));
    }
    // 端点准入（审计 M2）：与客户端同一规则——入口里出现回环/私网地址就放宽，
    // 否则只收公网地址（避免公共目录被内网地址污染，也让本机联调无需额外开关）
    node.set_endpoint_scope(wgp_dht::scope_for_endpoints(entries.iter().copied()));
    node.discover(&entries).await;
    node.seek_seeds(wgp_dht::NodeId(wgp_dht::room_key(code)))
        .await;

    let seeds: Vec<SeedInfo> = node.seeds().await;
    let candidates = storage_candidates(&seeds, &entries, transport);
    if candidates.is_empty() {
        return Err("没有可用的存储候选：种子既不宣告自己也不应答，无法读写房间记录".to_string());
    }
    let pick = RoomRuntime::locate(node, code, &candidates)
        .await
        .ok_or_else(|| "已知种子全部不可达，无法读写房间记录".to_string())?;
    Ok(StoragePickOut {
        storage: pick.candidate.addr,
        transport: pick.candidate.transport,
        existed: Some(pick.existing),
    })
}

fn storage_candidates(
    seeds: &[SeedInfo],
    entries: &[SocketAddr],
    transport: Transport,
) -> Vec<StorageCandidate> {
    let mut out: Vec<StorageCandidate> = seeds
        .iter()
        .filter_map(|s| {
            let addr = match transport {
                Transport::Udp => Some(s.addr),
                Transport::Tcp => s.tcp_addr(),
            };
            addr.map(|addr| StorageCandidate {
                node_id: s.node_id,
                addr,
                relays: Some(s.relays()),
                transport,
            })
        })
        .collect();
    // 手工入口端点：身份未知（测速只证明「有人应答」，没有 NodeId）→ 不参与选点。
    // 客户端用的是「测速时学到的 NodeId」，agent 这一层没有那个信息，宁可少一个候选，
    // 也不要猜一个 NodeId 去算距离（猜错会让两端选出不同的存储节点）。
    let _ = entries;
    out.retain(|c| c.relays != Some(false) || true);
    out
}

/// 观察者端点（`ip:port`，可逗号分隔）。解析不了的条目直接丢弃——
/// 观察者只影响 NAT 探测质量，不该让整个请求失败。
pub fn parse_observers(specs: &[String]) -> Vec<SocketAddr> {
    specs
        .iter()
        .flat_map(|s| s.split(','))
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}

/// 端口转发配置（语法与 `wgp-client --expose/--forward` 一致）
pub fn build_port_config(req: &RoomRequest) -> Result<PortConfig, String> {
    let mut cfg = PortConfig::default();
    for spec in &req.expose {
        cfg.expose_tcp.push(parse_expose(spec)?);
    }
    for spec in &req.forward {
        cfg.forward_tcp.push(parse_forward(spec)?);
    }
    for spec in &req.expose_udp {
        cfg.expose_udp.push(parse_expose(spec)?);
    }
    for spec in &req.forward_udp {
        cfg.forward_udp.push(parse_forward(spec)?);
    }
    Ok(cfg)
}

fn parse_expose(spec: &str) -> Result<ExposeRule, String> {
    let (port, target) = match spec.split_once('=') {
        Some((p, target)) => {
            let target: SocketAddr = target
                .trim()
                .parse()
                .map_err(|_| format!("暴露目标 `{target}` 不是合法的 ip:port"))?;
            (parse_port(p)?, target)
        }
        None => {
            let port = parse_port(spec)?;
            (
                port,
                SocketAddr::from(([127, 0, 0, 1], port)),
            )
        }
    };
    Ok(ExposeRule { port, target })
}

fn parse_forward(spec: &str) -> Result<ForwardRule, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (ip, local, remote) = match parts.as_slice() {
        [remote] => ("127.0.0.1", parse_port(remote)?, parse_port(remote)?),
        [local, remote] => ("127.0.0.1", parse_port(local)?, parse_port(remote)?),
        [ip, local, remote] => (ip.trim(), parse_port(local)?, parse_port(remote)?),
        _ => return Err(format!("转发规则 `{spec}` 非法")),
    };
    let ip: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| format!("监听地址 `{ip}` 不是合法 IPv4"))?;
    Ok(ForwardRule {
        listen: SocketAddr::from((ip, local)),
        remote_port: remote,
    })
}

fn parse_port(s: &str) -> Result<u16, String> {
    match s.trim().parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(format!("端口 `{s}` 非法（应为 1-65535）")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_and_transport_selection() {
        let udp = parse_seeds(&["udp://127.0.0.1:11010".to_string()]).unwrap();
        assert_eq!(choose_transport(&udp), Transport::Udp);
        let tcp = parse_seeds(&["tcp://127.0.0.1:3481".to_string()]).unwrap();
        assert_eq!(choose_transport(&tcp), Transport::Tcp);
        // 混着给：按 UDP 走（客户端同一规则），并在后续用 UDP picks
        let mixed = parse_seeds(&[
            "udp://127.0.0.1:11010".to_string(),
            "tcp://127.0.0.1:3481".to_string(),
        ])
        .unwrap();
        assert_eq!(choose_transport(&mixed), Transport::Udp);
        assert!(parse_seeds(&[]).is_err());
        assert!(parse_seeds(&["nonsense".to_string()]).is_err());
    }

    #[test]
    fn port_rules_match_client_syntax() {
        let req = RoomRequest {
            room_code: "U/C2G9-GYET-311W-R636".to_string(),
            seeds: vec!["udp://127.0.0.1:11010".to_string()],
            expose: vec!["25565".to_string(), "25566=127.0.0.1:25567".to_string()],
            forward: vec![
                "25565".to_string(),
                "25566:25565".to_string(),
                "0.0.0.0:25568:25565".to_string(),
            ],
            ..Default::default()
        };
        let cfg = build_port_config(&req).unwrap();
        assert_eq!(cfg.expose_tcp.len(), 2);
        assert_eq!(cfg.expose_tcp[0].target.port(), 25565);
        assert_eq!(cfg.expose_tcp[1].target.port(), 25567);
        assert_eq!(cfg.forward_tcp.len(), 3);
        assert_eq!(cfg.forward_tcp[0].listen.port(), 25565);
        assert_eq!(cfg.forward_tcp[0].remote_port, 25565);
        assert_eq!(cfg.forward_tcp[1].listen.port(), 25566);
        assert_eq!(cfg.forward_tcp[2].listen.ip().to_string(), "0.0.0.0");
        assert!(build_port_config(&RoomRequest {
            expose: vec!["0".to_string()],
            ..Default::default()
        })
        .is_err());
    }
}
