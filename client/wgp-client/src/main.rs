//! 折跃门客户端命令行前端（14 文档的"参考外围"）。
//!
//! 职责边界（00 §3 内核纯粹性）：外围只做三件事——参数装配、事件呈现、把内核交付的链路
//! 交给数据面。一切网络语义（信令/入表/打洞/保活）都在内核；隧道与端口转发在 wgp-port；
//! 本进程不含任何协议实现。
//! 内核不持有任何部署地址：种子端点必须由本外围经 `--seed` 或 `WGP_SEED` 注入。
//!
//! 命令：
//!   code <房间名> <房间密钥>                 离线派生房间码（13 文档）
//!   开房 [--name N] [--key K] [--seed ...]   创建房间（第一人 = 房主 + 锚点）
//!   join <U/房间码> [--seed ...]             加入房间（报道至锚点）
//!
//! 通用选项：
//!   --seed <list>      种子端点（逗号/分号/空白分隔；udp://host:port | tcp://host:port）
//!   --storage <ep>     显式指定房间键存储节点（默认在已知种子里按房间键确定性选点）
//!   --observer <list>  观察者端点（默认用发现到的种子自带的观察者）
//!   --identity <path>  身份文件（默认 {DEFAULT_IDENTITY_FILE}；首启生成）
//!   --expose <spec>    暴露本机 TCP 服务给房间成员（如房主的 25565）
//!   --forward <spec>   本地监听并转发到对端暴露的端口（游戏直连 localhost）
//!   --once             入表后立即退出（默认驻留并打印链路/房间事件，Ctrl+C 退出）
//!   -h, --help         帮助；  -V, --version   版本

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use wgp_core::{
    measure_seeds, peer_id_from_node, resolve_endpoint, types::LinkSink, Engine, EngineEvent,
    PeerId, RoomCode, SeedPick, SessionOrchestrator,
};
use wgp_dht::{
    room_key, DhtNode, NodeId, NodeIdentity, RoomError, RoomRuntime, SeedInfo, StorageCandidate,
};
use wgp_port::{
    close_code, Carrier, CloseReason, ExposeRule, ForwardRule, PortConfig, PortEvent, PortHub,
    Proto,
};
use wgp_proto::room_code::derive_room_code;
use wgp_proto::{SeedEndpoint, SeedScheme};

const DEFAULT_IDENTITY_FILE: &str = "wgp-client.key";
const IDENTITY_LEN: usize = 32;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 被动监听挂上后的静默期：忽略上一轮协商还在路上的迟到重传帧
const INCOMING_SETTLE: Duration = Duration::from_secs(2);
/// 链路失败后的主动重试退避（秒）。用尽后只做被动应答——遵守预算纪律，不无限催促重连
const RETRY_BACKOFF_SECS: [u64; 3] = [3, 10, 30];
/// 退出前留给「关闭通知」发出去的时间
const SHUTDOWN_FLUSH: Duration = Duration::from_millis(300);
/// 「加入」时在已知种子上没找到房间：程序会照常建房等人，但用户多半以为自己已经进了别人的房间
const NO_ROOM_NOTICE: &str = "[提示] 没有找到这个房间，现在房间里只有你自己。\
     如果是要加入别人开的房间：请核对房间码（或房间名与密钥），确认对方已经在线、\
     并且双方填的种子互相认识。保持运行即可，对方上线后会自动连上";

/// 未指定 --observer 时，最多自动选用几个发现到的观察者
const MAX_AUTO_OBSERVERS: usize = 3;

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
    /// 兼容旧节点：身份证明失败时回退到旧 PING/PONG 学习（默认关闭）
    allow_legacy_identity: bool,
    /// 接受回环/私网端点（本机与局域网联调；默认只收公网地址，见审计 M2）
    allow_local_endpoints: bool,
    /// 端口转发规则（原始字符串，可重复给出；解析见 build_port_config）
    expose: Vec<String>,
    forward: Vec<String>,
    expose_udp: Vec<String>,
    forward_udp: Vec<String>,
    positional: Vec<String>,
}

/// 把一个选项值按逗号拆开追加（选项本身也可重复给出）
fn push_list(dst: &mut Vec<String>, value: &str) {
    dst.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
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
            // 网络身份：`--name/--key` 与 EasyTier 习惯的
            // `--network-name/--network-secret` 是同一组语义，全部接受
            "--name" | "-n" | "--network-name" => o.name = Some(take(&mut i)?),
            "--key" | "-k" | "--network-secret" | "--secret" => o.key = Some(take(&mut i)?),
            // 种子端点：`--seed/-s` 与 EasyTier 习惯的 `--peers/-p` 等价；
            // 可重复给多次（也支持单个值内逗号/分号/空白分隔）
            "--seed" | "-s" | "--peers" | "-p" => {
                let one = take(&mut i)?;
                o.seed = Some(match o.seed.take() {
                    Some(prev) => format!("{prev},{one}"),
                    None => one,
                });
            }
            "--storage" => o.storage = Some(take(&mut i)?),
            "--observer" => o.observer = Some(take(&mut i)?),
            "--identity" | "-i" => o.identity = Some(PathBuf::from(take(&mut i)?)),
            "--expose" | "-e" => push_list(&mut o.expose, &take(&mut i)?),
            "--forward" | "-f" => push_list(&mut o.forward, &take(&mut i)?),
            "--expose-udp" => push_list(&mut o.expose_udp, &take(&mut i)?),
            "--forward-udp" => push_list(&mut o.forward_udp, &take(&mut i)?),
            "--once" => o.once = true,
            "--allow-legacy-identity" => o.allow_legacy_identity = true,
            "--allow-local-endpoints" => o.allow_local_endpoints = true,
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
// 端口转发规则
// ---------------------------------------------------------------------------

fn parse_port_number(s: &str) -> Result<u16, String> {
    match s.trim().parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(format!("端口 `{s}` 非法（应为 1-65535）")),
    }
}

/// 暴露规则：`<端口>`（目标 127.0.0.1:<端口>）或 `<端口>=<ip:port>`（目标任意地址，
/// 如局域网里另一台机器上的服务器）。对端只看得到端口号，看不到目标地址。
fn parse_expose(spec: &str) -> Result<ExposeRule, String> {
    match spec.split_once('=') {
        Some((port, target)) => Ok(ExposeRule {
            port: parse_port_number(port)?,
            target: target
                .trim()
                .parse::<SocketAddr>()
                .map_err(|_| format!("暴露目标 `{target}` 不是合法的 ip:port"))?,
        }),
        None => {
            let port = parse_port_number(spec)?;
            Ok(ExposeRule {
                port,
                target: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            })
        }
    }
}

/// 转发规则：`<远端端口>` | `<本地端口>:<远端端口>` | `<监听IPv4>:<本地端口>:<远端端口>`。
/// 默认只监听 127.0.0.1；给出监听地址（如 0.0.0.0）才对局域网开放。
fn parse_forward(spec: &str) -> Result<ForwardRule, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (ip, local, remote) = match parts.as_slice() {
        [remote] => (Ipv4Addr::LOCALHOST, *remote, *remote),
        [local, remote] => (Ipv4Addr::LOCALHOST, *local, *remote),
        [ip, local, remote] => (
            ip.trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("转发监听地址 `{ip}` 不是合法的 IPv4 地址"))?,
            *local,
            *remote,
        ),
        _ => {
            return Err(format!(
                "转发规则 `{spec}` 格式不对（应为 [监听IP:][本地端口:]远端端口）"
            ))
        }
    };
    Ok(ForwardRule {
        listen: SocketAddr::new(IpAddr::V4(ip), parse_port_number(local)?),
        remote_port: parse_port_number(remote)?,
    })
}

fn check_unique(what: &str, items: impl Iterator<Item = String>) -> Result<(), String> {
    let mut seen = HashSet::new();
    for item in items {
        if !seen.insert(item.clone()) {
            return Err(format!("{what} 重复：{item}"));
        }
    }
    Ok(())
}

fn build_port_config(opts: &Opts) -> Result<PortConfig, String> {
    let mut cfg = PortConfig::default();
    for spec in &opts.expose {
        cfg.expose_tcp.push(parse_expose(spec)?);
    }
    for spec in &opts.expose_udp {
        cfg.expose_udp.push(parse_expose(spec)?);
    }
    for spec in &opts.forward {
        cfg.forward_tcp.push(parse_forward(spec)?);
    }
    for spec in &opts.forward_udp {
        cfg.forward_udp.push(parse_forward(spec)?);
    }
    check_unique(
        "暴露的 TCP 端口",
        cfg.expose_tcp.iter().map(|r| r.port.to_string()),
    )?;
    check_unique(
        "暴露的 UDP 端口",
        cfg.expose_udp.iter().map(|r| r.port.to_string()),
    )?;
    check_unique(
        "TCP 转发监听地址",
        cfg.forward_tcp.iter().map(|r| r.listen.to_string()),
    )?;
    check_unique(
        "UDP 转发监听地址",
        cfg.forward_udp.iter().map(|r| r.listen.to_string()),
    )?;
    Ok(cfg)
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
    // 转发规则写错了在这里就报，不等到打印完加入命令之后
    let port_cfg = build_port_config(&opts)?;
    println!("房间名  : {name}");
    println!("房间密钥: {key}");
    println!("房间码  : {code}");
    println!("—— 把下面这一行发给同伴，对方原样执行即可加入 ——");
    println!(
        "{}",
        join_command(
            &code,
            &seed_string(&opts),
            opts.observer.as_deref(),
            &port_cfg
        )
    );
    run_room(&code, opts, false)
}

/// 种子端点串：命令行优先，其次环境变量 WGP_SEED
fn seed_string(opts: &Opts) -> String {
    opts.seed
        .clone()
        .or_else(|| std::env::var("WGP_SEED").ok())
        .unwrap_or_default()
}

/// 给同伴的加入命令：把房主这边已经确定的东西都带上——种子、手工指定的观察者、与暴露端口对应的
/// 转发规则。只给一个房间码的话，同伴还得自己知道种子地址、知道该转发哪个端口。
fn join_command(code: &str, seeds: &str, observer: Option<&str>, cfg: &PortConfig) -> String {
    let mut cmd = format!("wgp-client join {code}");
    let (endpoints, _) = SeedEndpoint::parse_list(seeds);
    if !endpoints.is_empty() {
        let list: Vec<String> = endpoints.iter().map(SeedEndpoint::display).collect();
        cmd.push_str(&format!(" -p {}", list.join(",")));
    }
    let observers = parse_observers(observer);
    if !observers.is_empty() {
        let list: Vec<String> = observers.iter().map(SocketAddr::to_string).collect();
        cmd.push_str(&format!(" --observer {}", list.join(",")));
    }
    for rule in &cfg.expose_tcp {
        cmd.push_str(&format!(" --forward {}", rule.port));
    }
    for rule in &cfg.expose_udp {
        cmd.push_str(&format!(" --forward-udp {}", rule.port));
    }
    cmd
}

/// 加入房间
///
/// 两种写法等价：
///   join <U/房间码>                                    —— 房主把码发给你
///   join --network-name N --network-secret S           —— 双方各自持有网络名+密钥，本地派生
fn cmd_join(args: &[String]) -> Result<(), String> {
    let opts = parse_opts(args)?;
    let code = resolve_join_code(&opts)?;
    println!("房间码  : {code}");
    run_room(&code, opts, true)
}

/// 解析加入目标：显式房间码优先，否则由「网络名 + 网络密钥」在本地派生
fn resolve_join_code(opts: &Opts) -> Result<String, String> {
    if let Some(code) = opts.positional.first() {
        return Ok(code.clone());
    }
    match (&opts.name, &opts.key) {
        (Some(name), Some(key)) => {
            let code = derive_room_code(name, key);
            println!("网络    : {name}");
            println!("派生房间码: {code}");
            Ok(code)
        }
        _ => Err("缺少加入目标：给 `join <U/房间码>`，或改用 \
             `join --network-name <网络名> --network-secret <网络密钥>` 在本地派生"
            .to_string()),
    }
}

// ---------------------------------------------------------------------------
// 房间会话（装配内核 + 数据面 + 呈现事件）
// ---------------------------------------------------------------------------

/// `joining`：本次是「加入」而不是「开房」——加入时没找到房间要提醒用户（见 async_move）
fn runtime_worker_threads() -> usize {
    runtime_worker_threads_for(
        std::env::var("WGP_RUNTIME_WORKERS").ok().as_deref(),
        std::thread::available_parallelism().map_or(2, |n| n.get()),
    )
}

fn runtime_worker_threads_for(configured: Option<&str>, available: usize) -> usize {
    configured
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|workers| (1..=64).contains(workers))
        .unwrap_or_else(|| available.max(1).min(4))
}

fn run_room(code: &str, opts: Opts, joining: bool) -> Result<(), String> {
    let seed_str = seed_string(&opts);
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
    // 转发规则在联网之前校验：写错了立刻报，而不是等入表、打洞之后
    let port_cfg = build_port_config(&opts)?;

    let identity_path = opts
        .identity
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_FILE));
    let identity = load_or_create_identity(&identity_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(runtime_worker_threads())
        .enable_all()
        .build()
        .map_err(|e| format!("运行时启动失败：{e}"))?;
    rt.block_on(async_move(
        code.to_string(),
        identity,
        endpoints,
        opts,
        port_cfg,
        joining,
    ))
}

async fn async_move(
    code: String,
    identity: NodeIdentity,
    endpoints: Vec<SeedEndpoint>,
    opts: Opts,
    port_cfg: PortConfig,
    joining: bool,
) -> Result<(), String> {
    // ① 本进程 DHT 节点（绑定随机端口）
    let node = DhtNode::bind(identity, "0.0.0.0:0".parse().unwrap())
        .await
        .map_err(|e| format!("DHT 绑定失败：{e}"))?;
    // 身份证明策略（17 §11.6）：默认严格；--allow-legacy-identity 才回退旧 PING/PONG
    node.set_identity_policy(if opts.allow_legacy_identity {
        wgp_dht::IdentityPolicy::LegacyAllowed
    } else {
        wgp_dht::IdentityPolicy::Strict
    });

    // ② 选路：测速全部种子（顺带打印观测 RTT）
    //
    // 承载选择：用户给的全是 tcp:// → 走 TCP 信令（UDP 被封时的兜底）。TCP 只能承担信令，
    // 打洞与数据面仍然需要 UDP，所以这里先把话说清楚，而不是等到入表阶段才超时。
    let tcp_signaling =
        !endpoints.is_empty() && endpoints.iter().all(|ep| ep.scheme == SeedScheme::Tcp);
    let transport = if tcp_signaling {
        wgp_dht::Transport::Tcp
    } else {
        wgp_dht::Transport::Udp
    };
    node.set_signaling_transport(transport);
    if tcp_signaling {
        println!("[信令] 使用 TCP 种子（UDP 被封时的兜底）：入表、选点、房间读写与报道中转走 TCP");
        eprintln!(
            "[warn] 打洞与数据面仍然需要 UDP：两端之间 UDP 完全不通时隧道不会建立，\
             本端只能停在「已入表」"
        );
    }

    let picks: Vec<SeedPick> = if endpoints.is_empty() {
        Vec::new()
    } else {
        measure_seeds(&node, &endpoints).await
    };
    for p in &picks {
        println!(
            "[种子] {} → {}  往返 {:?}",
            p.endpoint.display(),
            p.addr,
            p.rtt
        );
    }
    if !endpoints.is_empty() && picks.is_empty() {
        eprintln!(
            "[warn] 全部种子端点不可达（对端未启动、UDP 被封，或对端是旧版本不支持身份证明）。\
             继续尝试显式 --storage"
        );
        if tcp_signaling {
            eprintln!(
                "[hint] TCP 种子也不可达：确认种子的 TCP 信令端口（wgp-node --tcp）已开放且端口填对"
            );
        } else {
            eprintln!(
                "[hint] UDP 被封时可以改用 TCP 种子：-p tcp://<主机>:<TCP 信令端口>（如 3481）"
            );
        }
        if !opts.allow_legacy_identity {
            eprintln!("[hint] 若确认种子在线且是旧版本，加 --allow-legacy-identity 显式兼容旧协议");
        }
    }

    // ②b 种子发现（07 §5 第③层）：以配置的种子为入口，学到它们认识的其他种子，并启动
    // 后台维护（探活 + 保住到各种子的 NAT 映射）。入口种子没有宣告自己时目录为空，一切照旧——
    // 只认手工配置的那几个。
    let entries: Vec<SocketAddr> = picks
        .iter()
        .filter(|p| {
            (transport == wgp_dht::Transport::Tcp) == (p.endpoint.scheme == SeedScheme::Tcp)
        })
        .map(|p| p.addr)
        .collect();
    if entries.is_empty() && !endpoints.is_empty() {
        return Err(format!(
            "没有可用的 {} 种子端点：房间读写至少要一个能连上的种子。\
             请检查 -p 的协议与端口，或改用 --storage 显式指定存储节点",
            transport.scheme()
        ));
    }
    // 端点准入（审计 M2）：用户配置的种子里出现回环/私网地址，说明这是本机或局域网形态，
    // 放宽到接受这类广告；否则保持默认（只收公网地址）。
    let endpoint_scope = if opts.allow_local_endpoints {
        wgp_dht::EndpointScope::LocalNetwork
    } else {
        wgp_dht::scope_for_endpoints(entries.iter().copied())
    };
    node.set_endpoint_scope(endpoint_scope);
    if !entries.is_empty() {
        node.discover(&entries).await;
        // 再问一遍「离这个房间最近的种子」：种子很多时，让各端对选点的看法一致
        node.seek_seeds(NodeId(room_key(&code))).await;
    }
    node.spawn_maintenance();
    let seeds = node.seeds().await;
    for seed in &seeds {
        println!("[发现] {}", describe_seed(seed));
    }
    if !opts.allow_legacy_identity && seeds.iter().any(|s| !s.supports_auth()) {
        eprintln!(
            "[warn] 有种子没有宣告身份证明能力（旧版本）。严格模式下它们不会被采信：\
             升级种子，或加 --allow-legacy-identity 显式兼容旧协议"
        );
    }

    // ③ 房间键存储节点：显式优先；否则在已知种子里按房间键确定性选点
    let (storage, room_exists, storage_transport) = resolve_storage(
        &node,
        &code,
        &entries,
        &seeds,
        opts.storage.as_deref(),
        transport,
    )
    .await?;

    // 预热：让存储节点学习本端身份（失败不致命，但要给出可读原因）
    if let Err(e) = node.ping(storage).await {
        eprintln!("[warn] 与存储节点 {storage} 互认失败：{}", e.explain());
    }

    // ④ 数据面：端口转发中枢。先于入表启动——转发口被占用等问题立刻暴露
    let my_id = node.node_id();
    let my_peer = peer_id_from_node(&my_id);
    for rule in &port_cfg.expose_tcp {
        println!("[转发] 暴露 TCP 端口 {} → 本机 {}", rule.port, rule.target);
    }
    for rule in &port_cfg.expose_udp {
        println!("[转发] 暴露 UDP 端口 {} → 本机 {}", rule.port, rule.target);
    }
    // 本端转发了对端的哪些端口：隧道就绪时用来提示「对端暴露了、本端却没转发」的端口
    let forwarded = Forwarded {
        tcp: port_cfg.forward_tcp.iter().map(|r| r.remote_port).collect(),
        udp: port_cfg.forward_udp.iter().map(|r| r.remote_port).collect(),
    };
    let mut hinted: HashSet<(bool, u16)> = HashSet::new();
    let (hub, mut port_events) = PortHub::start(my_peer, port_cfg)
        .await
        .map_err(|e| format!("端口转发启动失败：{e}"))?;

    // ⑤ 装配内核
    let (engine, _rx) = Engine::new();
    engine
        .attach_dht_with_transport(node.clone(), storage, storage_transport)
        .await;

    let handle = engine
        .join_room(RoomCode(code.clone()), None)
        .await
        .map_err(|e| describe_join_error(&e, storage))?;
    println!("[房间] 已入表，当前成员数 = {}", handle.members);
    if joining && room_exists == Some(false) {
        println!("{NO_ROOM_NOTICE}");
    }

    if opts.once {
        let _ = handle.leave();
        return Ok(());
    }

    // ⑥ 装配线：成员感知 + 自动打洞（mesh 每对端一个监管任务），打通的链路交付给端口转发中枢。
    // 观察者由 `--observer` 显式注入；缺省为空则跳过 NAT 探测，
    // 由引擎按 T1-T4 判定自动降级到 TCP 兜底——不让用户为打洞必须配齐 STUN。
    let explicit_observers = parse_observers(opts.observer.as_deref());
    let auto = explicit_observers.is_empty();
    let observers = choose_observers(explicit_observers, &seeds);
    if auto {
        if observers.is_empty() {
            println!(
                "[观察者] 未指定，也没有发现带观察者的种子：将跳过 NAT 探测、只能尝试 TCP 兜底\
                 （可用 --observer <IP:端口> 指定）"
            );
        } else {
            let list: Vec<String> = observers.iter().map(|a| a.to_string()).collect();
            println!("[观察者] 自动选用 {}", list.join(", "));
        }
    }
    let tcp_seed = picks
        .iter()
        .find(|p| p.endpoint.scheme == SeedScheme::Tcp)
        .map(|p| p.addr);
    let session = Arc::new(Session {
        code: code.clone(),
        orch: SessionOrchestrator::new(node.clone(), engine.clone(), storage, observers)
            .with_tcp_fallback(tcp_seed),
        engine: engine.clone(),
        sink: Arc::new(hub.clone()),
        states: PeerStates::default(),
    });
    tokio::spawn(member_watch(node.clone(), storage, my_id, session.clone()));

    // 后台扩散：沿 FIND_NODE 再认识一圈节点，把入口种子不认识的宣告者也纳入种子目录
    if !entries.is_empty() {
        let (node, entries) = (node.clone(), entries.clone());
        tokio::spawn(async move {
            node.spread(&entries).await;
        });
    }
    let mut seed_changes = node.watch_seeds();
    let mut shown_seeds = seed_addrs(&seeds);

    println!("[房间] 驻留中——打印链路/房间/转发事件；按 Ctrl+C 退出");
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
            Some(ev) = port_events.recv() => {
                render_port(&ev);
                if let Some(hint) = unforwarded_hint(&ev, &forwarded, &mut hinted) {
                    println!("{hint}");
                }
                session.states.apply(&ev, &hub);
            }
            Ok(()) = seed_changes.changed() => {
                // 目录的变更通知也包括「同一种子换了新广告」：只在成员确实变了时才提示
                let now = seed_addrs(&node.seeds().await);
                if now != shown_seeds {
                    let list: Vec<String> = now.iter().map(|a| a.to_string()).collect();
                    println!("[发现] 种子目录更新：{} 个（{}）", now.len(), list.join(", "));
                    shown_seeds = now;
                }
            }
        }
    }
    // 先关隧道：对端立刻得知本端退出，而不必等到超时才发现
    hub.shutdown();
    tokio::time::sleep(SHUTDOWN_FLUSH).await;
    let _ = handle.leave();
    Ok(())
}

/// 入表失败的原因说明（给人看的：指出最可能的原因，而不是只报一个内部错误名）
fn describe_join_error(error: &RoomError, storage: SocketAddr) -> String {
    match error {
        // 房间记录读到了、报道也发了，但等到超时都没有被写进成员表
        RoomError::NotFound => format!(
            "加入房间失败：报道没有得到房主的处理（等待入表超时）。\
             可能的原因：房主已经离线；或者存放房间的种子 {storage} 不中转信令（贡献节点）"
        ),
        RoomError::StoreFailed => format!(
            "加入房间失败：存储节点 {storage} 没有应答——种子不可达，或本机到它的 UDP 被拦截"
        ),
        RoomError::PreemptedByOther => {
            "加入房间失败：建房时被别人抢先（同名房间刚刚被创建），请重试".to_string()
        }
        other => format!("加入房间失败：{other:?}"),
    }
}

/// 本端转发了对端的哪些端口
struct Forwarded {
    tcp: HashSet<u16>,
    udp: HashSet<u16>,
}

/// 隧道就绪时，对端暴露了端口而本端没有转发它：给出一次用法提示。
/// 不提示的话，隧道通了用户也不知道下一步——对端的服务在本机上并没有入口。
fn unforwarded_hint(
    ev: &PortEvent,
    forwarded: &Forwarded,
    hinted: &mut HashSet<(bool, u16)>,
) -> Option<String> {
    let PortEvent::TunnelReady { tcp, udp, .. } = ev else {
        return None;
    };
    let mut flags: Vec<String> = Vec::new();
    for port in tcp {
        if !forwarded.tcp.contains(port) && hinted.insert((false, *port)) {
            flags.push(format!("--forward {port}"));
        }
    }
    for port in udp {
        if !forwarded.udp.contains(port) && hinted.insert((true, *port)) {
            flags.push(format!("--forward-udp {port}"));
        }
    }
    if flags.is_empty() {
        return None;
    }
    Some(format!(
        "[提示] 对端暴露了端口，但本端没有转发它，现在还用不了。加上 `{}` 重新运行，\
         就能在本机用 127.0.0.1:<端口> 访问对端的服务",
        flags.join(" ")
    ))
}

/// 确定房间键存储节点：显式 `--storage` 优先；否则在已知种子（手工配置的 + 发现的）里由内核
/// 按房间键选点——已有本房间的跟随之；没有则在可达种子里先看中转能力（明确可中转 > 不知道 >
/// 明确不中转），同一档内取离房间键最近者。
/// 两端只要认识的种子一样，选中的就是同一个（不再取决于各自测速谁最快）。
///
/// `preferred` 是本次信令的承载：UDP 模式下候选是广告里的 DHT 地址，TCP 模式下是 TCP 信令端口
/// （没有宣告 TCP 端口的种子在 TCP 模式下不可用，会被跳过并给出说明）。
/// 返回 (存储节点, 房间此刻是否已经在它上面 / None=没查, 访问它的承载)。
async fn resolve_storage(
    node: &Arc<DhtNode>,
    code: &str,
    entries: &[SocketAddr],
    seeds: &[SeedInfo],
    explicit: Option<&str>,
    preferred: wgp_dht::Transport,
) -> Result<(SocketAddr, Option<bool>, wgp_dht::Transport), String> {
    if let Some(s) = explicit {
        let ep = SeedEndpoint::parse(s).map_err(|e| format!("--storage 解析失败：{e:?}"))?;
        let addr = resolve_endpoint(&ep)
            .await
            .ok_or_else(|| format!("--storage 无法解析为地址：{s}"))?;
        let transport = match ep.scheme {
            SeedScheme::Tcp => wgp_dht::Transport::Tcp,
            SeedScheme::Udp => wgp_dht::Transport::Udp,
        };
        println!(
            "[存储] 房间键存储节点 = {addr}（--storage 指定，{}）",
            transport.scheme()
        );
        // 没有查过房间在不在
        return Ok((addr, None, transport));
    }
    let candidates = storage_candidates(&node.known_nodes().await, entries, seeds, preferred);
    if candidates.is_empty() {
        return Err(match preferred {
            wgp_dht::Transport::Udp => {
                "无可用 UDP 种子端点：房间键存储走 UDP RPC，\
                 请提供 `--seed udp://host:port`（UDP 被封时改用 `--seed tcp://host:<TCP 信令端口>`）"
                    .to_string()
            }
            wgp_dht::Transport::Tcp => {
                "无可用 TCP 种子端点：UDP 被封时房间读写需要种子的 TCP 信令端口。\
                 请按 `--seed tcp://host:3481` 给出（端口见 wgp-node 的 --tcp），\
                 或确认该种子有宣告 tcp_port"
                    .to_string()
            }
        });
    }
    let pick = RoomRuntime::locate(node, code, &candidates)
        .await
        .ok_or("已知种子全部不可达，无法读写房间记录")?;
    println!(
        "[存储] 房间键存储节点 = {}（{}，{}）",
        pick.candidate.addr,
        if pick.existing {
            "房间已在该节点上，跟随"
        } else {
            "房间尚不存在，按房间键选定"
        },
        pick.candidate.transport.scheme()
    );
    if pick.candidate.relays == Some(false) {
        eprintln!(
            "[warn] 该存储节点是贡献模式（不中转信令）：其他成员的报道与协商消息送不到，\
             房间里只会有你自己。请至少配置一个完整版种子（wgp-node）"
        );
    }
    Ok((
        pick.candidate.addr,
        Some(pick.existing),
        pick.candidate.transport,
    ))
}

/// 汇集存储候选：发现的种子（广告里带中转能力）+ 手工配置但没有宣告自己的入口种子
/// （身份取自测速时的应答，中转能力未知）。同一地址以广告为准。
///
/// `preferred` 决定每个候选的访问地址与承载：TCP 模式下用广告里的 TCP 信令端口，
/// 没有宣告 TCP 端口的种子直接跳过（它在这条路径上不可达）。
fn storage_candidates(
    known: &[(NodeId, SocketAddr)],
    entries: &[SocketAddr],
    seeds: &[SeedInfo],
    preferred: wgp_dht::Transport,
) -> Vec<StorageCandidate> {
    let addr_of = |s: &SeedInfo| match preferred {
        wgp_dht::Transport::Udp => Some(s.addr),
        wgp_dht::Transport::Tcp => s.tcp_addr(),
    };
    let mut out: Vec<StorageCandidate> = seeds
        .iter()
        .filter_map(|s| {
            addr_of(s).map(|addr| StorageCandidate {
                node_id: s.node_id,
                addr,
                relays: Some(s.relays()),
                transport: preferred,
            })
        })
        .collect();
    for addr in entries {
        if out.iter().any(|c| c.addr == *addr) {
            continue;
        }
        // 手工入口端点的身份来自测速时的应答；TCP 模式下 entries 本身就是 TCP 端点
        if let Some((id, _)) = known.iter().find(|(_, at)| at == addr) {
            out.push(StorageCandidate {
                node_id: *id,
                addr: *addr,
                relays: None,
                transport: preferred,
            });
        }
    }
    out
}

/// 观察者：显式 `--observer` 优先；否则用发现到的种子自带的观察者（目录已按往返耗时排序，取前几个）
fn choose_observers(explicit: Vec<SocketAddr>, seeds: &[SeedInfo]) -> Vec<SocketAddr> {
    if !explicit.is_empty() {
        return explicit;
    }
    seeds
        .iter()
        .filter_map(SeedInfo::observer_addr)
        .take(MAX_AUTO_OBSERVERS)
        .collect()
}

/// 目录成员的地址集合（排序后便于比较「成员有没有变」）
fn seed_addrs(seeds: &[SeedInfo]) -> Vec<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = seeds.iter().map(|s| s.addr).collect();
    addrs.sort();
    addrs
}

fn describe_seed(seed: &SeedInfo) -> String {
    let observer = match seed.observer_addr() {
        Some(addr) => format!("观察者 :{}", addr.port()),
        None => "无观察者".to_string(),
    };
    let rtt = match seed.rtt_ms {
        Some(ms) => format!("，往返 {ms}ms"),
        None => String::new(),
    };
    format!(
        "种子 {}（{observer}，{}{rtt}）",
        seed.addr,
        if seed.relays() {
            "可中转"
        } else {
            "不中转"
        }
    )
}

fn parse_observers(list: Option<&str>) -> Vec<SocketAddr> {
    let Some(s) = list else { return Vec::new() };
    s.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}

// ---------------------------------------------------------------------------
// 逐对端链路监管
// ---------------------------------------------------------------------------

/// 某个对端的链路状态（由数据面事件驱动）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    /// 尚无结果
    Idle,
    /// 隧道已建立
    Up,
    /// 打洞失败 / 链路无法建成隧道
    Lost,
    /// 隧道已关闭
    Down(CloseReason),
}

#[derive(Default)]
struct PeerStates {
    map: Mutex<HashMap<PeerId, watch::Sender<LinkState>>>,
}

impl PeerStates {
    fn with_sender<T>(&self, peer: PeerId, f: impl FnOnce(&watch::Sender<LinkState>) -> T) -> T {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let sender = map
            .entry(peer)
            .or_insert_with(|| watch::channel(LinkState::Idle).0);
        f(sender)
    }

    fn subscribe(&self, peer: PeerId) -> watch::Receiver<LinkState> {
        self.with_sender(peer, |sender| sender.subscribe())
    }

    fn set(&self, peer: PeerId, state: LinkState) {
        self.with_sender(peer, |sender| {
            sender.send_replace(state);
        });
    }

    /// 把数据面事件折算成链路状态
    fn apply(&self, event: &PortEvent, hub: &PortHub) {
        match event {
            PortEvent::TunnelUp { peer, .. } => self.set(*peer, LinkState::Up),
            PortEvent::TunnelDown { peer, reason } => {
                // 旧隧道被新链路顶替时也会收尾：只要该对端还有隧道在，就不算断开
                if !hub.has_tunnel(peer) {
                    self.set(*peer, LinkState::Down(*reason));
                }
            }
            PortEvent::LinkLost { peer, .. } | PortEvent::TunnelFailed { peer, .. } => {
                self.set(*peer, LinkState::Lost)
            }
            _ => {}
        }
    }
}

struct Session {
    code: String,
    orch: SessionOrchestrator,
    engine: Engine,
    /// 链路交付口 = 端口转发中枢
    sink: Arc<dyn LinkSink>,
    states: PeerStates,
}

/// 成员感知：每 2s 读取房间记录，为新增成员启动一个链路监管任务
async fn member_watch(
    node: Arc<DhtNode>,
    storage: SocketAddr,
    my_id: NodeId,
    session: Arc<Session>,
) {
    let rt = RoomRuntime::new(node, storage);
    let mut supervised: HashSet<NodeId> = HashSet::new();
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(rec) = rt.fetch(&session.code).await else {
            continue;
        };
        for (id, pk) in &rec.members {
            let id = *id;
            let Ok(peer_identity_key) = <[u8; 32]>::try_from(pk.as_slice()) else {
                continue;
            };
            if id == my_id || !supervised.insert(id) {
                continue;
            }
            tokio::spawn(supervise_peer(session.clone(), id, peer_identity_key));
        }
    }
}

/// 为什么要（重新）协商
enum Trigger {
    /// 对端发起了新一轮协商（它认为链路已断，或刚上线）
    PeerInitiated,
    /// 本端按退避主动重试
    Retry,
}

fn is_graceful(reason: CloseReason) -> bool {
    matches!(
        reason,
        CloseReason::Local
            | CloseReason::Peer(close_code::NORMAL)
            | CloseReason::Peer(close_code::REPLACED)
    )
}

/// 安排下一次主动重试；退避表用尽返回 None（此后只等对端发起）
fn schedule_retry(retries: &mut usize, peer: &str) -> Option<tokio::time::Instant> {
    match RETRY_BACKOFF_SECS.get(*retries) {
        Some(&secs) => {
            *retries += 1;
            println!(
                "[链路] peer={peer} 将在 {secs}s 后重试（{}/{}）",
                *retries,
                RETRY_BACKOFF_SECS.len()
            );
            Some(tokio::time::Instant::now() + Duration::from_secs(secs))
        }
        None => {
            println!("[链路] peer={peer} 主动重试已用尽，改为等待对端发起");
            None
        }
    }
}

async fn sleep_until_some(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// 一个对端的链路监管：主动协商 → 等结果 → 失败/断开时按退避重试；全程挂着被动监听，
/// 对端先发起（或重新发起）时立即响应——两端无需恰好同时动手。
async fn supervise_peer(session: Arc<Session>, id: NodeId, peer_identity_key: [u8; 32]) {
    let peer = peer_id_from_node(&id);
    let name = hex(&peer);
    let mut state = session.states.subscribe(peer);
    let mut retries = 0usize;
    loop {
        let mut retry_at = match session
            .orch
            .connect_peer(&session.code, id, peer_identity_key, session.sink.clone())
            .await
        {
            Ok(()) => {
                println!("[链路] 协商完成，竞速已启动 peer={name}");
                None
            }
            Err(e) => {
                eprintln!("[链路] peer={name} 协商失败：{e:?}");
                schedule_retry(&mut retries, &name)
            }
        };

        let trigger = {
            let incoming = session
                .orch
                .wait_incoming(&session.code, id, INCOMING_SETTLE);
            tokio::pin!(incoming);
            loop {
                tokio::select! {
                    woken = &mut incoming => {
                        if woken {
                            break Trigger::PeerInitiated;
                        }
                        // 监听被顶替（正常流程不会出现）：重新挂上
                        incoming.set(session.orch.wait_incoming(&session.code, id, INCOMING_SETTLE));
                    }
                    changed = state.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        let current = *state.borrow_and_update();
                        match current {
                            LinkState::Idle => {}
                            LinkState::Up => {
                                retries = 0;
                                retry_at = None;
                            }
                            LinkState::Lost => retry_at = schedule_retry(&mut retries, &name),
                            LinkState::Down(reason) => {
                                // 死链路上的内核保活已无意义：停掉，不再占用发包预算
                                session.engine.release(peer).await;
                                retry_at = if is_graceful(reason) {
                                    None
                                } else {
                                    schedule_retry(&mut retries, &name)
                                };
                            }
                        }
                    }
                    _ = sleep_until_some(retry_at), if retry_at.is_some() => break Trigger::Retry,
                }
            }
        };
        match trigger {
            Trigger::PeerInitiated => println!("[链路] peer={name} 发起了新一轮协商，本端响应"),
            Trigger::Retry => println!("[链路] 重新发起协商 peer={name}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 事件呈现
// ---------------------------------------------------------------------------

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
        EngineEvent::RoomAnchorChanged {
            epoch,
            anchor,
            reason,
        } => println!(
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

fn proto_name(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    }
}

fn describe_close(reason: &CloseReason) -> String {
    match reason {
        CloseReason::Local => "本端关闭".to_string(),
        CloseReason::Peer(code) if *code == close_code::NORMAL => "对端已退出".to_string(),
        CloseReason::Peer(code) if *code == close_code::REPLACED => "对端已换用新链路".to_string(),
        CloseReason::Peer(code) => format!("对端关闭（原因码 {code}）"),
        CloseReason::Timeout => "对端无应答，链路已断".to_string(),
        CloseReason::PeerSilent => "对端长时间静默".to_string(),
        CloseReason::Protocol => "协议错误".to_string(),
        CloseReason::Io => "底层连接断开".to_string(),
        other => format!("{other:?}"),
    }
}

fn render_port(ev: &PortEvent) {
    match ev {
        PortEvent::Listening {
            proto,
            listen,
            remote_port,
        } => println!(
            "[转发] 本地 {} {listen} → 对端端口 {remote_port}（隧道就绪后可用）",
            proto_name(*proto)
        ),
        PortEvent::TunnelUp {
            peer,
            carrier,
            peer_addr,
        } => println!(
            "[隧道] 已接管链路 peer={} 载体={} 对端地址={peer_addr}",
            hex(peer),
            match carrier {
                Carrier::Udp => "UDP",
                Carrier::Tcp => "TCP",
            }
        ),
        PortEvent::TunnelReady { peer, tcp, udp } => println!(
            "[隧道] 就绪 peer={} 对端暴露 TCP={tcp:?} UDP={udp:?}",
            hex(peer)
        ),
        PortEvent::TunnelDown { peer, reason } => println!(
            "[隧道] 关闭 peer={} 原因={}",
            hex(peer),
            describe_close(reason)
        ),
        PortEvent::TunnelFailed { peer, error } => {
            println!("[隧道] 无法建立 peer={} 原因={error:?}", hex(peer))
        }
        PortEvent::StreamOpened {
            peer,
            port,
            inbound,
        } => println!(
            "[转发] {} peer={} 端口={port}",
            if *inbound {
                "对端连入"
            } else {
                "本地连出"
            },
            hex(peer)
        ),
        PortEvent::NoProvider { proto, remote_port } => println!(
            "[转发] 暂无对端暴露 {} 端口 {remote_port}，本地连接已拒绝",
            proto_name(*proto)
        ),
        PortEvent::TargetUnreachable { port, target } => {
            println!("[转发] 本机服务 {target} 连不上（对端请求端口 {port}）——服务启动了吗？")
        }
        // 打洞失败已由引擎事件（LinkLost）打印，此处不重复
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
        "折跃门客户端 v{VERSION}（14 文档的参考外围：装配 + 呈现 + 端口转发，无协议实现）\n\
         \n\
         用法：\n\
           wgp-client code <网络名> <网络密钥>                离线派生房间码\n\
           wgp-client 开房 <选项>                            创建房间（房主 + 锚点）\n\
           wgp-client join <U/房间码> <选项>                  按房间码加入\n\
           wgp-client join --network-name N --network-secret S <选项>\n\
                                                             按网络名+密钥加入（本地派生，无需交换码）\n\
         \n\
         网络身份（两种写法等价，后者为 EasyTier 习惯）：\n\
           -n, --name <名字>              等价 --network-name\n\
           -k, --key <密钥>               等价 --network-secret / --secret\n\
         \n\
         端口转发（打洞成功后经加密隧道传输；均可重复给出或逗号分隔）：\n\
           -e, --expose <端口>            把本机 127.0.0.1:<端口> 的 TCP 服务暴露给房间成员\n\
               --expose <端口>=<ip:port>  同上，但服务在指定地址（如局域网内另一台机器）\n\
           -f, --forward <端口>           监听本机 127.0.0.1:<端口>，转发到对端暴露的同号端口\n\
               --forward <本地>:<远端>    本地端口与对端端口不同时使用\n\
               --forward <IP>:<本地>:<远端>  指定监听地址（如 0.0.0.0 让局域网其他设备也能连）\n\
               --expose-udp / --forward-udp  同上，UDP（如基岩版 19132）\n\
         \n\
         选项：\n\
           -s, --seed <list>      种子端点（可重复；也支持逗号/分号/空白分隔）\n\
                                  udp://host:port 或 tcp://host:port\n\
                                  ◦ tcp:// 只兜底信令（bootstrap / 选点 / 房间 KV / 报道中转）；\n\
                                    打洞与业务隧道仍要 UDP，两端 UDP 全不通时隧道建不起来\n\
           -p, --peers <list>     等价 --seed（EasyTier 习惯）\n\
           --storage <ep>         显式房间键存储节点（默认在已知种子里按房间键选定，两端结果一致）\n\
           --observer <list>      观察者/STUN 端点，逗号分隔 ip:port\n\
                                  （缺省用发现到的种子自带的观察者；一个也没有则跳过 NAT 探测、只试 TCP 兜底）\n\
           -i, --identity <path>  身份文件（默认 {DEFAULT_IDENTITY_FILE}）\n\
           --once                 入表后立即退出（默认驻留并打印事件）\n\
           --allow-legacy-identity  兼容旧节点：身份证明失败时回退到旧 PING/PONG 学习\n\
                                   （默认关闭；严格模式只把旧协议用于存活诊断）\n\
           --allow-local-endpoints  接受回环/私网种子端点（本机多进程联调、局域网或 FRP 内网部署；\n\
                                   默认只收公网地址，回环/内网地址的种子广告会被丢弃）\n\
           -h, --help             显示本帮助\n\
           -V, --version          显示版本\n\
         \n\
         环境变量：\n\
           WGP_SEED               种子端点列表（等价 --seed；内核不内置任何地址）\n\
         \n\
         示例：\n\
           wgp-client code 示例房间 123456\n\
           wgp-client 开房 --network-name 示例房间 --network-secret 123456 -p udp://轻松.躺进.icu:11010\n\
           wgp-client join --network-name 示例房间 --network-secret 123456 -p udp://轻松.躺进.icu:11010\n\
           wgp-client join U/C2G9-GYET-311W-R636 -p udp://轻松.躺进.icu:11010\n\
         \n\
         联机示例（Minecraft Java 版，服务器在房主本机 25565）：\n\
           房主：wgp-client 开房 -n 我的房间 -k 密钥 -p udp://<种子>:11010 --expose 25565\n\
           朋友：wgp-client join -n 我的房间 -k 密钥 -p udp://<种子>:11010 --forward 25565\n\
           朋友在游戏里连接 localhost:25565 即可\n\
           （种子没有用 --advertise 宣告自己时，两端都要加 --observer <种子IP>:3478）"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_worker_threads_are_capped_and_configurable() {
        assert_eq!(runtime_worker_threads_for(None, 1), 1);
        assert_eq!(runtime_worker_threads_for(None, 32), 4);
        assert_eq!(runtime_worker_threads_for(Some("2"), 32), 2);
        assert_eq!(runtime_worker_threads_for(Some("64"), 1), 64);
        assert_eq!(runtime_worker_threads_for(Some("0"), 8), 4);
        assert_eq!(runtime_worker_threads_for(Some("bad"), 8), 4);
    }

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

    #[test]
    fn join_accepts_easytier_style_network_flags() {
        // --network-name / --network-secret 与 --name / --key 同义
        let o = parse_opts(&v(&[
            "--network-name",
            "示例房间",
            "--network-secret",
            "123456",
        ]))
        .unwrap();
        assert_eq!(o.name.as_deref(), Some("示例房间"));
        assert_eq!(o.key.as_deref(), Some("123456"));
        // 无位置参数时由网络身份本地派生，结果与 code 子命令一致
        assert_eq!(resolve_join_code(&o).unwrap(), "U/C2G9-GYET-311W-R636");
    }

    #[test]
    fn join_prefers_explicit_room_code_over_network_flags() {
        let o = parse_opts(&v(&[
            "U/8SRU-FM1Q-XTDQ-LL36",
            "--network-name",
            "示例房间",
            "--network-secret",
            "123456",
        ]))
        .unwrap();
        assert_eq!(resolve_join_code(&o).unwrap(), "U/8SRU-FM1Q-XTDQ-LL36");
    }

    #[test]
    fn join_without_code_or_network_identity_errors() {
        let o = parse_opts(&v(&["--peers", "udp://127.0.0.1:11010"])).unwrap();
        assert!(resolve_join_code(&o).is_err());
    }

    #[test]
    fn peers_alias_accumulates_like_easytier() {
        // 可重复给多次，内部合并成一个列表
        let o = parse_opts(&v(&[
            "-p",
            "udp://a:1",
            "--peers",
            "tcp://b:2",
            "--seed",
            "c:3",
        ]))
        .unwrap();
        assert_eq!(o.seed.as_deref(), Some("udp://a:1,tcp://b:2,c:3"));
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn expose_spec_forms() {
        assert_eq!(
            parse_expose("25565").unwrap(),
            ExposeRule {
                port: 25565,
                target: addr("127.0.0.1:25565"),
            }
        );
        // 服务在局域网另一台机器上：对端仍然只看到端口号 25565
        assert_eq!(
            parse_expose("25565=192.168.1.20:25570").unwrap(),
            ExposeRule {
                port: 25565,
                target: addr("192.168.1.20:25570"),
            }
        );
        for bad in [
            "",
            "0",
            "70000",
            "abc",
            "25565=",
            "25565=localhost",
            "=1.2.3.4:5",
        ] {
            assert!(parse_expose(bad).is_err(), "`{bad}` 应被拒绝");
        }
    }

    #[test]
    fn forward_spec_forms() {
        assert_eq!(
            parse_forward("25565").unwrap(),
            ForwardRule {
                listen: addr("127.0.0.1:25565"),
                remote_port: 25565,
            }
        );
        assert_eq!(
            parse_forward("25566:25565").unwrap(),
            ForwardRule {
                listen: addr("127.0.0.1:25566"),
                remote_port: 25565,
            }
        );
        assert_eq!(
            parse_forward("0.0.0.0:25566:25565").unwrap(),
            ForwardRule {
                listen: addr("0.0.0.0:25566"),
                remote_port: 25565,
            }
        );
        for bad in [
            "",
            "0",
            "1:2:3:4",
            "x:25565",
            "25565:0",
            "nope:1:2",
            "1.2.3:1:2",
        ] {
            assert!(parse_forward(bad).is_err(), "`{bad}` 应被拒绝");
        }
    }

    #[test]
    fn port_options_accumulate_and_build_config() {
        let o = parse_opts(&v(&[
            "--expose",
            "25565,8080",
            "-e",
            "9000=10.0.0.5:9001",
            "--forward",
            "25566:25565",
            "-f",
            "8080",
            "--expose-udp",
            "19132",
            "--forward-udp",
            "19133:19132",
        ]))
        .unwrap();
        let cfg = build_port_config(&o).unwrap();
        assert_eq!(
            cfg.expose_tcp.iter().map(|r| r.port).collect::<Vec<_>>(),
            vec![25565, 8080, 9000]
        );
        assert_eq!(cfg.expose_tcp[2].target, addr("10.0.0.5:9001"));
        assert_eq!(cfg.forward_tcp.len(), 2);
        assert_eq!(cfg.forward_tcp[0].listen, addr("127.0.0.1:25566"));
        assert_eq!(cfg.expose_udp[0].port, 19132);
        assert_eq!(cfg.forward_udp[0].remote_port, 19132);
    }

    #[test]
    fn duplicate_or_malformed_port_rules_rejected_before_networking() {
        let dup = parse_opts(&v(&["--expose", "25565", "--expose", "25565=10.0.0.1:1"])).unwrap();
        assert!(build_port_config(&dup).unwrap_err().contains("重复"));
        let dup = parse_opts(&v(&["--forward", "25565", "--forward", "25565:25570"])).unwrap();
        assert!(build_port_config(&dup).unwrap_err().contains("重复"));
        let bad = parse_opts(&v(&["--forward", "notaport"])).unwrap();
        assert!(build_port_config(&bad).is_err());
        // 没有任何转发规则也是合法配置（纯打洞演示）
        let none = parse_opts(&v(&[])).unwrap();
        let cfg = build_port_config(&none).unwrap();
        assert!(cfg.expose_tcp.is_empty() && cfg.forward_tcp.is_empty());
    }

    fn seed_info(byte: u8, port: u16, stun_port: u16, relays: bool) -> SeedInfo {
        SeedInfo {
            node_id: NodeId([byte; 32]),
            pubkey: [byte; 32],
            addr: addr(&format!("203.0.113.{byte}:{port}")),
            stun_port,
            tcp_port: 0,
            priority: 0,
            flags: if relays { 0x01 } else { 0 },
            epoch: 1,
            rtt_ms: Some(u32::from(byte)),
        }
    }

    #[test]
    fn storage_candidates_merge_discovered_and_configured_seeds() {
        let discovered = [
            seed_info(1, 11010, 3478, true),
            seed_info(2, 11010, 0, false),
        ];
        // 配置了三个入口：一个就是已发现的 1 号；一个没有宣告但测速时应答过；一个没应答过
        let silent_seed = addr("198.51.100.9:11010");
        let dead_seed = addr("198.51.100.10:11010");
        let entries = [discovered[0].addr, silent_seed, dead_seed];
        let known = [
            (NodeId([9; 32]), silent_seed),
            (NodeId([1; 32]), discovered[0].addr),
        ];

        let got = storage_candidates(&known, &entries, &discovered, wgp_dht::Transport::Udp);
        assert_eq!(
            got.len(),
            3,
            "已发现的不重复计入；没应答过的（身份未知）不计入"
        );
        // 广告里的中转能力如实带上；手工配置而未宣告的种子能力未知
        assert_eq!(got[0].relays, Some(true));
        assert_eq!(got[1].relays, Some(false));
        assert_eq!(
            got[2],
            StorageCandidate {
                node_id: NodeId([9; 32]),
                addr: silent_seed,
                relays: None,
                transport: wgp_dht::Transport::Udp,
            }
        );
        // 没有任何已知种子：候选为空（调用方报错，而不是猜一个）
        assert!(storage_candidates(&[], &[dead_seed], &[], wgp_dht::Transport::Udp).is_empty());
    }

    #[test]
    fn storage_candidates_in_tcp_mode_use_tcp_endpoints() {
        // 广告宣告了 TCP 信令端口的种子：TCP 模式用 tcp_addr()
        let mut with_tcp = seed_info(1, 11010, 3478, true);
        with_tcp.tcp_port = 3481;
        // 没有宣告 TCP 端口的种子在 TCP 模式下不可用，必须被跳过
        let no_tcp = seed_info(2, 11010, 3478, true);
        let seeds = [with_tcp, no_tcp];
        let got = storage_candidates(&[], &[], &seeds, wgp_dht::Transport::Tcp);
        assert_eq!(got.len(), 1, "没有 TCP 信令端口的种子应被跳过");
        assert_eq!(got[0].transport, wgp_dht::Transport::Tcp);
        assert_eq!(got[0].addr.port(), 3481);
        assert_eq!(got[0].addr.ip(), seeds[0].addr.ip());
    }

    #[test]
    fn observers_explicit_wins_else_taken_from_discovered_seeds() {
        let seeds = [
            seed_info(1, 11010, 3478, true),
            seed_info(2, 11010, 0, true), // 这个种子不提供观察者
            seed_info(3, 11010, 3479, false),
            seed_info(4, 11010, 3480, true),
            seed_info(5, 11010, 3481, true),
        ];
        // 显式指定：原样使用，不掺入发现的
        let explicit = vec![addr("192.0.2.1:3478")];
        assert_eq!(choose_observers(explicit.clone(), &seeds), explicit);
        // 未指定：取发现的种子里带观察者的前 MAX_AUTO_OBSERVERS 个（端口来自广告，IP 同种子）
        assert_eq!(
            choose_observers(Vec::new(), &seeds),
            vec![
                addr("203.0.113.1:3478"),
                addr("203.0.113.3:3479"),
                addr("203.0.113.4:3480"),
            ]
        );
        assert!(choose_observers(Vec::new(), &[]).is_empty());
        assert!(describe_seed(&seeds[1]).contains("无观察者"));
        assert!(describe_seed(&seeds[2]).contains("不中转"));
    }

    #[test]
    fn graceful_close_reasons_do_not_trigger_active_retry() {
        assert!(is_graceful(CloseReason::Local));
        assert!(is_graceful(CloseReason::Peer(close_code::NORMAL)));
        assert!(is_graceful(CloseReason::Peer(close_code::REPLACED)));
        assert!(!is_graceful(CloseReason::Timeout));
        assert!(!is_graceful(CloseReason::PeerSilent));
        assert!(!is_graceful(CloseReason::Io));
        assert!(!is_graceful(CloseReason::Peer(close_code::PROTOCOL)));
    }

    #[test]
    fn retry_backoff_is_bounded() {
        let mut retries = 0usize;
        let mut granted = 0usize;
        while schedule_retry(&mut retries, "test").is_some() {
            granted += 1;
            assert!(granted <= RETRY_BACKOFF_SECS.len(), "重试次数必须有界");
        }
        assert_eq!(granted, RETRY_BACKOFF_SECS.len());
        // 用尽后继续询问仍是 None（不回绕）
        assert!(schedule_retry(&mut retries, "test").is_none());
    }

    #[test]
    fn join_command_carries_seeds_observer_and_ports() {
        let o = parse_opts(&v(&[
            "-p",
            "udp://seed.example:11010",
            "--peers",
            "tcp://seed.example:3481",
            "--observer",
            "192.0.2.7:3478",
            "--expose",
            "25565",
            "--expose",
            "8080=192.168.1.20:80",
            "--expose-udp",
            "19132",
        ]))
        .unwrap();
        let cfg = build_port_config(&o).unwrap();
        let cmd = join_command(
            "U/C2G9-GYET-311W-R636",
            o.seed.as_deref().unwrap(),
            o.observer.as_deref(),
            &cfg,
        );
        assert_eq!(
            cmd,
            "wgp-client join U/C2G9-GYET-311W-R636 \
             -p udp://seed.example:11010,tcp://seed.example:3481 \
             --observer 192.0.2.7:3478 --forward 25565 --forward 8080 --forward-udp 19132"
        );
        // 生成的命令行能被本程序自己解析回去，且转发规则合法
        let args: Vec<String> = cmd.split(' ').skip(2).map(str::to_string).collect();
        let parsed = parse_opts(&args).unwrap();
        assert_eq!(resolve_join_code(&parsed).unwrap(), "U/C2G9-GYET-311W-R636");
        let joiner_cfg = build_port_config(&parsed).unwrap();
        assert_eq!(joiner_cfg.forward_tcp.len(), 2);
        assert_eq!(joiner_cfg.forward_udp.len(), 1);
    }

    #[test]
    fn join_command_without_extras_is_just_the_code() {
        let cmd = join_command("U/C2G9-GYET-311W-R636", "", None, &PortConfig::default());
        assert_eq!(cmd, "wgp-client join U/C2G9-GYET-311W-R636");
    }

    #[test]
    fn unforwarded_hint_names_missing_ports_once() {
        let forwarded = Forwarded {
            tcp: [25565u16].into_iter().collect(),
            udp: HashSet::new(),
        };
        let mut hinted = HashSet::new();
        let ready = PortEvent::TunnelReady {
            peer: [7u8; 16],
            tcp: vec![25565, 8080],
            udp: vec![19132],
        };
        let hint = unforwarded_hint(&ready, &forwarded, &mut hinted).expect("有没转发的端口应提示");
        assert!(hint.contains("--forward 8080"), "{hint}");
        assert!(hint.contains("--forward-udp 19132"), "{hint}");
        assert!(
            !hint.contains("--forward 25565"),
            "已经转发的端口不该出现：{hint}"
        );
        // 重连后同样的端口不再重复提示
        assert!(unforwarded_hint(&ready, &forwarded, &mut hinted).is_none());
        // 全都转发了：不提示
        let all = Forwarded {
            tcp: [25565u16, 8080].into_iter().collect(),
            udp: [19132u16].into_iter().collect(),
        };
        assert!(unforwarded_hint(&ready, &all, &mut HashSet::new()).is_none());
    }

    #[test]
    fn join_errors_are_explained() {
        let storage: SocketAddr = "192.0.2.1:11010".parse().unwrap();
        let timeout = describe_join_error(&RoomError::NotFound, storage);
        assert!(
            timeout.contains("入表超时") && timeout.contains("192.0.2.1:11010"),
            "{timeout}"
        );
        let unreachable = describe_join_error(&RoomError::StoreFailed, storage);
        assert!(unreachable.contains("没有应答"), "{unreachable}");
    }
}
