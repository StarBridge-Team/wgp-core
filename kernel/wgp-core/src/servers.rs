//! 服务器选择器（07 §5 种子发现第 1 层 + 就近低延迟选路）。
//! 多端点并发探测，按 RTT 排序；全灭返回 None（上层可退到内置列表）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use wgp_dht::DhtNode;
use wgp_proto::{SeedEndpoint, SeedScheme};

/// 测速结果：端点 + 解析地址 + RTT
#[derive(Debug, Clone)]
pub struct SeedPick {
    pub endpoint: SeedEndpoint,
    pub addr: SocketAddr,
    pub rtt: Duration,
}

/// 解析端点至 SocketAddr（DNS 解析；host 先经 IDN punycode 归一化）。
/// scheme 不影响解析（udp/tcp 共用同一主机名），仅决定后续探测/通信走哪条 RPC。
pub async fn resolve_endpoint(ep: &SeedEndpoint) -> Option<SocketAddr> {
    let host = ep.host_ascii();
    let addrs = tokio::net::lookup_host((host.as_str(), ep.port))
        .await
        .ok()?;
    for a in addrs {
        // 优先 IPv4（当前打洞面 v4 聚焦；未来线 IPv6 时扩展）
        if a.is_ipv4() {
            return Some(a);
        }
    }
    None
}

/// 探测单个端点（按 scheme 选 UDP/TCP 的 PING），返回 RTT。
async fn probe_endpoint(node: &Arc<DhtNode>, ep: &SeedEndpoint, addr: SocketAddr) -> Option<Duration> {
    let start = Instant::now();
    let ok = match ep.scheme {
        SeedScheme::Udp => node.ping(addr).await.is_ok(),
        SeedScheme::Tcp => node.ping_tcp(addr).await.is_ok(),
    };
    ok.then(|| start.elapsed())
}

/// 并发探测全部端点，返回按 RTT 升序的可用列表（不可达被剔除）。
/// 每端点超时 1.5s（与 DHT RPC 超时一致）。
pub async fn measure_seeds(
    node: &Arc<DhtNode>,
    endpoints: &[SeedEndpoint],
) -> Vec<SeedPick> {
    let mut tasks = Vec::new();
    for ep in endpoints {
        let ep = ep.clone();
        let node = node.clone();
        tasks.push(tokio::spawn(async move {
            let addr = resolve_endpoint(&ep).await?;
            let rtt = probe_endpoint(&node, &ep, addr).await?;
            Some(SeedPick { endpoint: ep, addr, rtt })
        }));
    }
    let mut picks: Vec<SeedPick> = Vec::new();
    for t in tasks {
        if let Ok(Some(p)) = t.await {
            picks.push(p);
        }
    }
    picks.sort_by_key(|p| p.rtt);
    picks
}

/// 内置种子列表已移至外围配置层（后端/客户端启动时注入）。
/// 内核只保留"给定端点列表 → 测速/选路"的机制，不持有任何部署地址。

/// 选最快一个（无可用 → None）
pub async fn pick_fastest_seed(
    node: &Arc<DhtNode>,
    endpoints: &[SeedEndpoint],
) -> Option<SeedPick> {
    measure_seeds(node, endpoints).await.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use wgp_dht::{DhtNode, NodeIdentity};

    async fn spawn_node() -> Arc<DhtNode> {
        let mut rng = OsRng;
        let id = NodeIdentity::generate(&mut rng);
        DhtNode::bind(id, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn measure_picks_live_and_skips_dead() {
        let client = spawn_node().await;
        let live = spawn_node().await;
        let live_addr = live.local_addr().unwrap();
        let live_ep = SeedEndpoint::parse(&format!("udp://127.0.0.1:{}", live_addr.port())).unwrap();
        // 死端点：本机一个无人监听端口
        let dead_ep = SeedEndpoint::parse("udp://127.0.0.1:1").unwrap();

        // 预热：client 与 live 互认
        client.ping(live_addr).await.unwrap();

        let picks = measure_seeds(&client, &[dead_ep.clone(), live_ep.clone()]).await;
        assert_eq!(picks.len(), 1, "死端点被剔除，仅剩活端点");
        assert_eq!(picks[0].endpoint, live_ep);
        assert_eq!(picks[0].addr.ip().to_string(), "127.0.0.1");
        assert!(picks[0].rtt < Duration::from_millis(1500));
        let _ = dead_ep;
    }

    #[tokio::test]
    async fn all_dead_returns_empty() {
        let client = spawn_node().await;
        let eps = vec![
            SeedEndpoint::parse("udp://127.0.0.1:1").unwrap(),
            SeedEndpoint::parse("udp://127.0.0.1:2").unwrap(),
        ];
        let picks = measure_seeds(&client, &eps).await;
        assert!(picks.is_empty());
        assert!(pick_fastest_seed(&client, &eps).await.is_none());
    }

    #[tokio::test]
    async fn resolve_domain_and_ipv4() {
        // 本地主机名不应解析（无 DNS 依赖测试）；用 IP 形式测解析路径
        let ep = SeedEndpoint::parse("udp://127.0.0.1:11010").unwrap();
        let addr = resolve_endpoint(&ep).await.unwrap();
        assert_eq!(addr, "127.0.0.1:11010".parse().unwrap());
    }

    /// TCP 种子探测：走 ping_tcp（UDP 被封时的兜底信令）也能被选中。
    #[tokio::test]
    async fn measure_picks_tcp_seed() {
        let client = spawn_node().await;
        let live = spawn_node().await;
        let live_tcp = live
            .listen_tcp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let live_ep = SeedEndpoint::parse(&format!("tcp://127.0.0.1:{}", live_tcp.port())).unwrap();

        let picks = measure_seeds(&client, &[live_ep.clone()]).await;
        assert_eq!(picks.len(), 1, "TCP 种子应探测成功");
        assert_eq!(picks[0].endpoint, live_ep);
        assert_eq!(picks[0].endpoint.scheme, SeedScheme::Tcp);
        assert_eq!(picks[0].addr, live_tcp);
    }
}