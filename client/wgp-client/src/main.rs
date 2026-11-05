//! 折跃门客户端命令行前端（14 文档的"参考外围"）。
//!
//! 职责边界（00 §3 内核纯粹性）：外围只做两件事——参数装配 + 事件呈现；
//! 一切网络语义（信令/入表/打洞/保活）都在内核，本进程不含任何协议实现。
//! 内核不持有任何部署地址：种子端点必须由本外围经 `--seed` 或 `WGP_SEED` 注入。
//!
//! 命令：
//!   code <房间名> <房间密钥>                 离线派生房间码（13 文档）
//!   开房 [--name N] [--key K] [--seed ...]   创建房间（第一人 = 房主 + 锚点）
//!   join <U/房间码> [--seed ...]             加入房间（报道至锚点）
//!
//! 通用选项：
//!   --seed <list>      种子端点（逗号/分号/空白分隔；udp://host:port | tcp://host:port）
//!   --storage <ep>     显式指定房间键存储节点（默认取最快 UDP 种子）
//!   --identity <path>  身份文件（默认 {DEFAULT_IDENTITY_FILE}；首启生成）
//!   --once             入表后立即退出（默认驻留并打印链路/房间事件，Ctrl+C 退出）
//!   -h, --help         帮助；  -V, --version   版本

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use wgp_core::{
    measure_seeds, peer_id_from_node, resolve_endpoint, types::LinkSink, Engine, EngineEvent,
    LinkLossCause, PeerId, PunchedLink, RoomCode, SessionOrchestrator, SeedPick,
};
use wgp_dht::{DhtNode, NodeId, NodeIdentity, RoomRuntime};
use wgp_proto::room_code::derive_room_code;
use wgp_proto::{SeedEndpoint, SeedScheme};

const DEFAULT_IDENTITY_FILE: &str = "wgp-client.key";
const IDENTITY_LEN: usize = 32;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("错误：{msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    match cmd {
        "-h" | "--help" | "help" | "帮助" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" | "version" | "版本" => {
            println!("wgp-client {VERSION}");
            Ok(())
        }
        "code" | "码" => cmd_code(&args[1..]),
        "开房" | "host" | "create" => cmd_host(&args[1..]),
        "join" | "加入" => cmd_join(&args[1..]),
        other => Err(format!("未知命令 `{other}`（用 `--help` 查看用法）")),
    }
}

// ---------------------------------------------------------------------------
// 参数解析（零依赖：与 wgp-node 后端同一套 `--flag` 约定）
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Opts {
    name: Option<String>,
    key: Option<String>,
    seed: Option<String>,
    storage: Option<String>,
    observer: Option<String>,
    identity: Option<PathBuf>,
    once: bool,
    positional: Vec<String>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0usize;
    while i < args.len() {
        let flag = args[i].clone();
        // 取值型选项：消费下一个 token（越界即报错，避免静默吞参数）
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("选项 {flag} 需要一个值"))
        };
        match flag.as_str() {
            "--name" | "-n" => o.name = Some(take(&mut i)?),
            "--key" | "-k" => o.key = Some(take(&mut i)?),
            "--seed" | "-s" => o.seed = Some(take(&mut i)?),
            "--storage" => o.storage = Some(take(&mut i)?),
            "--observer" => o.observer = Some(take(&mut i)?),
            "--identity" | "-i" => o.identity = Some(PathBuf::from(take(&mut i)?)),
            "--once" => o.once = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with("--") => {
                return Err(format!("未知选项 `{other}`"));
            }
            positional => o.positional.push(positional.to_string()),
        }
        i += 1;
    }
    Ok(o)
}

// ---------------------------------------------------------------------------
// 子命令
// ---------------------------------------------------------------------------

/// 离线派生房间码（无网络；13 文档唯一权威实现）
fn cmd_code(args: &[String]) -> Result<(), String> {
    let opts = parse_opts(args)?;
    let name = opts
        .name
        .clone()
        .or_else(|| opts.positional.first().cloned())
        .ok_or("缺少房间名：code <房间名> <房间密钥>")?;
    let key = opts
        .key
        .clone()
        .or_else(|| opts.positional.get(1).cloned())
        .ok_or("缺少房间密钥：code <房间名> <房间密钥>")?;
    println!("{}", derive_room_code(&name, &key));
    Ok(())
}

/// 开房：派生房间码 → 以第一人身份建房（房主 = 锚点）
fn cmd_host(args: &[String]) -> Result<(), String> {
    let opts = parse_opts(args)?;
    let name = opts
        .name
        .clone()
        .or_else(|| opts.positional.first().cloned())
        .unwrap_or_else(|| "wgp".to_string());
    let key = opts
        .key
        .clone()
        .or_else(|| opts.positional.get(1).cloned())
        .unwrap_or_else(random_hex16);

    let code = derive_room_code(&name, &key);
    println!("房间名  : {name}");
    println!("房间密钥: {key}");
    println!("房间码  : {code}");
    println!("—— 把「房间码」分享给同伴，对方执行 `wgp-client join {code}` 即可加入 ——");
    run_room(&code, opts)
}

/// 加入房间
fn cmd_join(args: &[String]) -> Result<(), String> {
    let opts = parse_opts(args)?;
    let code = opts
        .positional
        .first()
        .cloned()
        .ok_or("缺少房间码：join <U/房间码>")?;
    println!("房间码  : {code}");
    run_room(&code, opts)
}

// ---------------------------------------------------------------------------
// 房间会话（装配内核 + 呈现事件）
// ---------------------------------------------------------------------------

fn run_room(code: &str, opts: Opts) -> Result<(), String> {
    let seed_str = opts
        .seed
        .clone()
        .or_else(|| std::env::var("WGP_SEED").ok())
        .unwrap_or_default();
    let (endpoints, bad) = SeedEndpoint::parse_list(&seed_str);
    for b in &bad {
        eprintln!("[warn] 忽略非法种子端点：{b}");
    }
    if endpoints.is_empty() && opts.storage.is_none() {
        return Err(
            "未提供可用种子端点。请用 `--seed udp://host:port[,tcp://host:port]` \
             或环境变量 WGP_SEED 注入（内核不内置任何部署地址）"
                .to_string(),
        );
    }

    let identity_path = opts
        .identity
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_FILE));
    let identity = load_or_create_identity(&identity_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("运行时启动失败：{e}"))?;
    rt.block_on(async_move(code.to_string(), identity, endpoints, opts))
}

async fn async_move(
    code: String,
    identity: NodeIdentity,
    endpoints: Vec<SeedEndpoint>,
    opts: Opts,
) -> Result<(), String> {
    // ① 本进程 DHT 节点（绑定随机端口）
    let node = DhtNode::bind(identity, "0.0.0.0:0".parse().unwrap())
        .await
        .map_err(|e| format!("DHT 绑定失败：{e}"))?;

    // ② 选路：测速全部种子（顺带打印观测 RTT）
    let picks: Vec<SeedPick> = if endpoints.is_empty() {
        Vec::new()
    } else {
        measure_seeds(&node, &endpoints).await
    };
    for p in &picks {
        println!("[种子] {} → {}  往返 {:?}", p.endpoint.display(), p.addr, p.rtt);
    }
    if !endpoints.is_empty() && picks.is_empty() {
        eprintln!("[warn] 全部种子端点不可达（继续尝试显式 --storage）");
    }

    // ③ 房间键存储节点：显式优先，否则取最快 UDP 种子（v1 房间 RPC 走 UDP）
    let storage = resolve_storage(&node, &picks, opts.storage.as_deref()).await?;
    println!("[存储] 房间键存储节点 = {storage}");

    // 预热：让存储节点学习本端身份（失败不致命）
    let _ = node.ping(storage).await;

    // ④ 装配内核
    let (engine, _rx) = Engine::new();
    engine.attach_dht(node.clone(), storage).await;

    let handle = engine
        .join_room(RoomCode(code.clone()), None)
        .await
        .map_err(|e| format!("加入房间失败：{e:?}"))?;
    println!("[房间] 已入表，当前成员数 = {}", handle.members);

    // ⑤ 装配线：成员感知 + 自动打洞（mesh 每对端一次协商竞速）。
    // 观察者(src) 由 `--observer` 显式注入；缺省为空则跳过 NAT 探测，
    // 由引擎按 T1-T4 判定自动降级到 TCP 兜底——不让用户为打洞必须配齐 STUN。
    let observers = parse_observers(opts.observer.as_deref());
    let tcp_seed = picks
        .iter()
        .find(|p| p.endpoint.scheme == SeedScheme::Tcp)
        .map(|p| p.addr);
    let orch = Arc::new(
        SessionOrchestrator::new(node.clone(), engine.clone(), storage, observers)
            .with_tcp_fallback(tcp_seed),
    );
    let my_id = node.node_id();
    tokio::spawn(member_watch(
        node.clone(),
        storage,
        code.clone(),
        my_id,
        orch,
    ));

    if opts.once {
        let _ = handle.leave();
        return Ok(());
    }

    println!("[房间] 驻留中——打印链路/房间事件；按 Ctrl+C 退出");
    let mut events = engine.subscribe();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n[房间] 收到退出信号，正在清理…");
                break;
            }
            ev = events.recv() => match ev {
                Ok(e) => render(&e),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("[warn] 事件处理滞后，丢弃 {n} 条");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    let _ = handle.leave();
    Ok(())
}

/// 解析房间键存储节点地址（显式 > 最快 UDP 种子）
async fn resolve_storage(
    _node: &Arc<DhtNode>,
    picks: &[SeedPick],
    explicit: Option<&str>,
) -> Result<SocketAddr, String> {
    if let Some(s) = explicit {
        let ep = SeedEndpoint::parse(s).map_err(|e| format!("--storage 解析失败：{e:?}"))?;
        return resolve_endpoint(&ep)
            .await
            .ok_or_else(|| format!("--storage 无法解析为地址：{s}"));
    }
    if let Some(p) = picks.iter().find(|p| p.endpoint.scheme == SeedScheme::Udp) {
        return Ok(p.addr);
    }
    Err("无可用 UDP 种子端点：v1 房间键存储走 UDP RPC，请提供 `--seed udp://host:port`".to_string())
}

fn parse_observers(list: Option<&str>) -> Vec<SocketAddr> {
    let Some(s) = list else {
        return Vec::new()
    };
    s.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}

/// 成员感知 + 自动打洞：每 2s 读取房间记录，对新增成员发起一次协商竞速。
/// 失败仅记录不重试（遵守预算纪律）；链路丢/挂后的重打由引擎自持。
async fn member_watch(
    node: Arc<DhtNode>,
    storage: SocketAddr,
    code: String,
    my_id: NodeId,
    orch: Arc<SessionOrchestrator>,
) {
    let rt = RoomRuntime::new(node, storage);
    let mut launched: HashSet<NodeId> = HashSet::new();
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(rec) = rt.fetch(&code).await else {
            continue;
        };
        for (id, _pk) in &rec.members {
            let id = *id;
            if id == my_id || launched.contains(&id) {
                continue;
            }
            launched.insert(id);
            let orch = orch.clone();
            let code = code.clone();
            let sink: Arc<dyn LinkSink> = Arc::new(SilentSink);
            tokio::spawn(async move {
                match orch.connect_peer(&code, id, sink).await {
                    Ok(()) => println!(
                        "[链路] 协商完成，竞速已启动 peer={}",
                        hex(&peer_id_from_node(&id))
                    ),
                    Err(e) => eprintln!(
                        "[链路] peer={} 协商失败：{e:?}（链路重试由引擎自持）",
                        hex(&peer_id_from_node(&id))
                    ),
                }
            });
        }
    }
}

/// 链路交付 sink：链路事件已由引擎广播（render 打印），此处静默防重复。
struct SilentSink;

impl LinkSink for SilentSink {
    fn on_link_yielded(&self, _peer: PeerId, _link: PunchedLink) {}
    fn on_link_upgraded(&self, _peer: PeerId, _link: PunchedLink) {}
    fn on_link_lost(&self, _peer: PeerId, _cause: LinkLossCause) {}
}

fn render(ev: &EngineEvent) {
    match ev {
        EngineEvent::PunchingStarted { peer } => println!("[链路] 开始打洞 peer={}", hex(peer)),
        EngineEvent::LinkYielded { peer, rank } => {
            println!("[链路] 已打通 peer={} 档位={rank:?}", hex(peer))
        }
        EngineEvent::LinkUpgraded { peer, from, to } => {
            println!("[链路] 升级 peer={} {from:?} → {to:?}", hex(peer))
        }
        EngineEvent::LinkLost { peer, cause } => {
            println!("[链路] 丢失 peer={} 原因={cause:?}", hex(peer))
        }
        EngineEvent::RePunching { peer, reason } => {
            println!("[链路] 重打洞 peer={} 原因={reason:?}", hex(peer))
        }
        EngineEvent::DeadEnd { peer, diagnosis } => println!(
            "[链路] 判死局 peer={} 评分={} NAT={} 防火墙={} UDP封禁={} CGNAT={}",
            hex(peer),
            diagnosis.score,
            diagnosis.nat_type,
            diagnosis.firewalled,
            diagnosis.udp_blocked,
            diagnosis.cgnat
        ),
        EngineEvent::RoomAnchorChanged { epoch, anchor, reason } => println!(
            "[房间] 锚点变更 epoch={epoch} 新锚点={} 原因={reason:?}",
            hex(anchor)
        ),
        EngineEvent::RoomJoined { members, .. } => println!("[房间] 成员表就绪，成员数={members}"),
        EngineEvent::RoomJoinFailed { reason, .. } => println!("[房间] 入表失败 原因={reason:?}"),
        EngineEvent::BudgetExhausted { .. } => println!("[预算] 发包窗口耗尽，等待下一窗口"),
        EngineEvent::KeepaliveSuspended { peer } => println!("[保活] 自动降频 peer={}", hex(peer)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 生成 16 位十六进制随机房间密钥（仅当用户未指定 `--key`）
fn random_hex16() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    hex(&buf)
}

/// 载入或生成节点身份（07 §8：身份漂移 = DHT 键散乱 + 日蚀风险）。
/// 文件存在但长度非法时拒绝（宁可人工确认，也不静默换身份）。
fn load_or_create_identity(path: &Path) -> Result<NodeIdentity, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != IDENTITY_LEN {
                return Err(format!(
                    "身份文件 {} 长度非法（期望 32B，实得 {}B）",
                    path.display(),
                    bytes.len()
                ));
            }
            let mut seed = [0u8; IDENTITY_LEN];
            seed.copy_from_slice(&bytes);
            Ok(NodeIdentity::from_seed(seed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use rand_core::OsRng;
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            std::fs::write(path, id.to_seed())
                .map_err(|e| format!("写入身份文件 {} 失败：{e}", path.display()))?;
            println!("[身份] 已生成新身份并持久化于 {}", path.display());
            Ok(id)
        }
        Err(e) => Err(format!("读取身份文件 {} 失败：{e}", path.display())),
    }
}

fn print_help() {
    println!(
        "折跃门客户端 v{VERSION}（14 文档的参考外围：仅装配 + 呈现，无协议实现）\n\
         \n\
         用法：\n\
           wgp-client code <房间名> <房间密钥>              离线派生房间码\n\
           wgp-client 开房 [--name N] [--key K] [选项]      创建房间（房主 + 锚点）\n\
           wgp-client join <U/房间码> [选项]                加入房间\n\
         \n\
         选项：\n\
           -s, --seed <list>      种子端点（逗号/分号/空白分隔）\n\
                                  udp://host:port 或 tcp://host:port\n\
           --storage <ep>         显式房间键存储节点（默认取最快 UDP 种子）\n\
           --observer <list>      观察者/STUN 端点，逗号分隔 ip:port（缺省跳过 NAT 探测，自动降级 TCP 兜底）\n\
           -i, --identity <path>  身份文件（默认 {DEFAULT_IDENTITY_FILE}）\n\
           --once                 入表后立即退出（默认驻留并打印事件）\n\
           -h, --help             显示本帮助\n\
           -V, --version          显示版本\n\
         \n\
         环境变量：\n\
           WGP_SEED               种子端点列表（等价 --seed；内核不内置任何地址）\n\
         \n\
         示例：\n\
           wgp-client code 示例房间 123456\n\
           wgp-client 开房 --name 示例房间 --key 123456 --seed udp://轻松.躺进.icu:11010\n\
           wgp-client join U/C2G9-GYET-311W-R636 --seed udp://轻松.躺进.icu:11010"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_opts_collects_flags_and_positionals() {
        let args = v(&["--name", "房间", "位置1", "--once"]);
        let o = parse_opts(&args).unwrap();
        assert_eq!(o.name.as_deref(), Some("房间"));
        assert!(o.once);
        assert_eq!(o.positional, vec!["位置1".to_string()]);
    }

    #[test]
    fn unknown_flag_rejected() {
        assert!(parse_opts(&v(&["--nope"])).is_err());
    }

    #[test]
    fn missing_value_rejected() {
        assert!(parse_opts(&v(&["--seed"])).is_err());
    }

    #[test]
    fn code_subcommand_matches_doc13_vector() {
        // 13 文档测试向量
        let code = derive_room_code("示例房间", "123456");
        assert_eq!(code, "U/C2G9-GYET-311W-R636");
    }
}
