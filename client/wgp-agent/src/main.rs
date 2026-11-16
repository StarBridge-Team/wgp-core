//! `wgp-agent`：本机唯一的客户端 agent 进程（20 文档阶段 1）。
//!
//! 它持有客户端侧的 DHT 身份、UDP socket、`Engine` 与 `PortHub`，通过**仅本机可访问**的
//! IPC 端点接受 UI/CLI 控制。密钥与 socket 不出这个进程：IPC 里既没有导出私钥的命令，
//! 也没有「任意执行/任意路径」这类口子。
//!
//! 用法：
//! ```text
//!   wgp-agent [--identity <path>] [--socket <endpoint>] [--allow-legacy-identity]
//!   wgp-agent ping [--socket <endpoint>]        # 冒烟：GetVersion + GetSnapshot + ShutdownAgent
//! ```
//!
//! 退出码：0 = 正常；2 = 参数/入口错误；3 = IPC 绑定失败（多半是已有 agent 在跑）。

mod agent;
mod room;

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use tokio::sync::watch;
use wgp_core::Engine;
use wgp_dht::{DhtNode, NodeIdentity};
use wgp_ipc::{
    serve_connection, Client, Command, Endpoint, Inbound, Limits, Request, RoomRequest,
};

const DEFAULT_IDENTITY: &str = "wgp-agent.key";

struct Opts {
    identity: PathBuf,
    socket: Option<String>,
    allow_legacy_identity: bool,
    ping: bool,
}

fn usage() -> &'static str {
    "wgp-agent —— 折跃门客户端 agent（本机 IPC 控制面）\n\
     \n\
     用法：\n\
       wgp-agent [选项]                 启动 agent（前台运行）\n\
       wgp-agent ping [选项]            冒烟自检：GetVersion + GetSnapshot + ShutdownAgent\n\
     \n\
     选项：\n\
       --identity <path>            身份文件（默认 wgp-agent.key；不存在则生成）\n\
       --socket <endpoint>          IPC 端点（默认当前用户端点：Unix socket 或命名管道）\n\
       --allow-legacy-identity      兼容旧节点：身份证明失败时回退到旧 PING/PONG 学习\n\
       -h, --help                   显示本帮助"
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        identity: PathBuf::from(DEFAULT_IDENTITY),
        socket: None,
        allow_legacy_identity: false,
        ping: false,
    };
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "ping" => opts.ping = true,
            "--identity" | "-i" => {
                i += 1;
                opts.identity = PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "选项 --identity 需要一个值".to_string())?,
                );
            }
            "--socket" => {
                i += 1;
                opts.socket = Some(
                    args.get(i)
                        .ok_or_else(|| "选项 --socket 需要一个值".to_string())?
                        .clone(),
                );
            }
            "--allow-legacy-identity" => opts.allow_legacy_identity = true,
            "-V" | "--version" => {
                println!("wgp-agent {}", wgp_ipc::VERSION);
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => return Err(format!("未知选项：{other}")),
        }
        i += 1;
    }
    Ok(opts)
}

fn endpoint(opts: &Opts) -> Result<Endpoint, String> {
    match &opts.socket {
        Some(spec) => Endpoint::parse(spec).map_err(|e| format!("IPC 端点 `{spec}` 非法：{e}")),
        None => Endpoint::for_current_user().map_err(|e| format!("无法确定默认 IPC 端点：{e}")),
    }
}

/// 读取或生成身份文件。权限：Unix 0600；Windows 由用户目录的 ACL 兜底（见 README 残余风险）。
fn load_identity(path: &PathBuf) -> Result<NodeIdentity, String> {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(NodeIdentity::from_seed(seed));
        }
        return Err(format!(
            "身份文件 {} 长度不对（{} 字节，应为 32）",
            path.display(),
            bytes.len()
        ));
    }
    let identity = NodeIdentity::generate(&mut OsRng);
    let seed = identity.to_seed();
    let mut file = std::fs::File::create(path)
        .map_err(|e| format!("创建身份文件 {} 失败：{e}", path.display()))?;
    file.write_all(&seed)
        .map_err(|e| format!("写入身份文件失败：{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(identity)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_opts(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[wgp-agent] {e}\n\n{}", usage());
            std::process::exit(2);
        }
    };
    let ep = match endpoint(&opts) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("[wgp-agent] {e}");
            std::process::exit(2);
        }
    };
    if opts.ping {
        std::process::exit(run_ping(&ep).await);
    }
    std::process::exit(run_agent(opts, ep).await);
}

async fn run_agent(opts: Opts, ep: Endpoint) -> i32 {
    let identity = match load_identity(&opts.identity) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("[wgp-agent] {e}");
            return 2;
        }
    };
    let node = match DhtNode::bind(identity, "0.0.0.0:0".parse().unwrap()).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[wgp-agent] DHT 绑定失败：{e}");
            return 2;
        }
    };
    node.set_identity_policy(agent::identity_policy(opts.allow_legacy_identity));
    node.spawn_maintenance();

    let (engine, _events) = Engine::new();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let mut listener = match wgp_ipc::transport::bind(&ep).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[wgp-agent] IPC 端点 {} 绑定失败：{e}（已有 agent 在跑？）",
                ep.display()
            );
            return 3;
        }
    };

    println!("[wgp-agent] ready — 已就绪");
    println!("  身份节点 = {}", node.node_id().0.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("  IPC 端点 = {}", ep.display());
    println!(
        "  IPC 协议 = {}.{}",
        wgp_ipc::PROTOCOL_MAJOR,
        wgp_ipc::PROTOCOL_MINOR
    );
    println!("  ACL      = {}", ep.acl_summary());

    let agent = agent::Agent::new(node.clone(), engine, shutdown_tx.clone());
    agent.announce_started().await;
    let handler: Arc<dyn wgp_ipc::Handler> = agent.clone();
    let limits = Limits::default();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok(accepted) => {
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            let _ = serve_connection(accepted.stream, accepted.peer, handler, limits).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("[wgp-agent] accept 失败：{e}");
                        break;
                    }
                }
            }
        }
    }
    node.shutdown().await;
    println!("[wgp-agent] exited — 已退出");
    0
}

/// 冒烟自检：连上 agent，取版本与快照，再让它优雅退出。
async fn run_ping(ep: &Endpoint) -> i32 {
    let mut client = match Client::connect(ep).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[wgp-agent] 连接 {} 失败：{e}", ep.display());
            return 3;
        }
    };
    let mut id = 1u64;
    let call = |command: Command, id: u64| Request {
        request_id: id,
        session_id: 0,
        deadline_ms: Some(5_000),
        command,
    };
    let request = call(Command::GetVersion, id);
    match tokio::time::timeout(Duration::from_secs(6), client.call(&request)).await {
        Ok(Ok(resp)) => match &resp.payload {
            wgp_ipc::ResponsePayload::Version(v) => {
                // 第一行保持纯 ASCII：冒烟脚本（scripts/agent-smoke.*）按它断言
                println!(
                    "version: {} (ipc {}.{}, pid {}, uptime {} ms)",
                    v.agent, v.protocol_major, v.protocol_minor, v.pid, v.uptime_ms
                );
                println!(
                    "版本 {}（IPC {}.{}，pid {}，已运行 {} ms）",
                    v.agent, v.protocol_major, v.protocol_minor, v.pid, v.uptime_ms
                );
            }
            other => {
                eprintln!("[wgp-agent] 版本应答形状不对：{other:?}");
                return 1;
            }
        },
        other => {
            eprintln!("[wgp-agent] GetVersion 失败：{other:?}");
            return 1;
        }
    }
    id += 1;
    let request = call(Command::GetSnapshot, id);
    match tokio::time::timeout(Duration::from_secs(6), client.call(&request)).await {
        Ok(Ok(resp)) => match &resp.payload {
            wgp_ipc::ResponsePayload::Snapshot(s) => {
                println!(
                    "snapshot: {} rooms, {} subscribers, {} dropped events",
                    s.rooms.len(),
                    s.subscribers,
                    s.dropped_events
                );
                println!(
                    "快照：{} 个房间、{} 个订阅者（丢弃事件 {}）",
                    s.rooms.len(),
                    s.subscribers,
                    s.dropped_events
                );
                for room in &s.rooms {
                    println!("  房间 {} 成员 {} 存储 {}", room.room, room.members, room.storage);
                }
            }
            other => {
                eprintln!("[wgp-agent] 快照应答形状不对：{other:?}");
                return 1;
            }
        },
        other => {
            eprintln!("[wgp-agent] GetSnapshot 失败：{other:?}");
            return 1;
        }
    }
    // 冒烟脚本需要 agent 退出；真实 UI 不会这样用（它只是发一条 ShutdownAgent）
    id += 1;
    let request = call(Command::ShutdownAgent, id);
    let _ = tokio::time::timeout(Duration::from_secs(2), client.call(&request)).await;
    0
}

/// 事件流的最小演示（预留给将来的 GUI/CLI 复用；当前不参与编译期路径）
#[allow(dead_code)]
async fn watch_events(client: &mut Client) -> std::io::Result<()> {
    let request = Request {
        request_id: 9,
        session_id: 0,
        deadline_ms: None,
        command: Command::WatchEvents(wgp_ipc::Watch { since_seq: 0 }),
    };
    client.send(&request).await?;
    while let Inbound::Event(event) = client.recv().await? {
        println!("事件 {} {:?}", event.event_seq, event.kind);
    }
    Ok(())
}

/// 供将来 IPC 客户端的房间请求构造（当前由 `wgp-client` 侧的 IPC 客户端负责）
#[allow(dead_code)]
fn sample_room_request(code: &str, seed: &str) -> RoomRequest {
    RoomRequest {
        room_code: code.to_string(),
        seeds: vec![seed.to_string()],
        ..Default::default()
    }
}
