//! `wgp-et-fallback`：没有 wgp 种子时，把本机固定端口经 EasyTier 公共节点送到对端。
//!
//! 由 `wgp-client` 在「一个真种子都连不上、但用户给了 `et://` 入口」时拉起：
//!
//! ```text
//! wgp-et-fallback --network-name wgp-xxxxxxxx --network-secret <hex32> \
//!                 --relay tcp://relay.example.com:11010 --mode host
//! ```
//!
//! 启动成功后 stdout 打一行机器可读的 READY（父进程据此知道打洞端口）：
//!
//! ```text
//! WGP-ET-FALLBACK READY peer=<u32> bind=127.0.0.2 punch=<u16>
//! ```
//!
//! 之后把事件与错误打到 stderr（父进程可以直接透传给用户）。
//!
//! 这个程序**不碰 TUN**：它只是在用户态搬 UDP 报文。TUN 设备、与官方 ET 节点互通
//! 都不在它的范围里（见 `bridge/wgp-et-bridge/README.md`）。

use std::net::Ipv4Addr;
use std::process::ExitCode;
use wgp_et_bridge::fallback::{
    derive_network, parse_relay, BridgeEvent, FallbackBridge, ProxyConfig, DEFAULT_BIND_IP,
    SERVICE_PORT_DHT, SERVICE_PORT_STUN,
};

fn usage(program: &str) -> String {
    format!(
        "wgp-et-fallback {version}\n\
用法：{program} --relay tcp://主机:端口 [选项]\n\n\
选项：\n\
  --relay <list>              ET 公共节点（tcp://主机:端口），逗号分隔；连上第一个可用的即可\n\
  --network-name <名字>        临时 ET 网络名（父进程按房间派生）\n\
  --network-secret <密钥>      临时 ET 网络密钥（父进程按房间派生）\n\
  --room-key <64 位十六进制>    房间键：给了它就自己派生网络名与密钥，代替上面两项\n\
  --mode <host|joiner>        host = 本机有种子，转发给 127.0.0.1；joiner = 本机是客户端\n\
  --bind <IPv4>               本侧监听地址（默认 {bind}，与 127.0.0.1 分开以免抢端口）\n\
  --local-app <IPv4>          host 模式下把报文写回的本机地址（默认 127.0.0.1）\n\
  --services <端口,端口>       透传的固定服务端口（默认 {dht},{stun}）\n\
  -h, --help                  显示本帮助\n\n\
说明：\n\
  · 本程序不使用 TUN，也不实现 ET 的端口转发；它只把 UDP 报文封进 ET 自定义帧。\n\
  · 一条桥只支持一个对端参与数据面（房主 ⇄ 一个加入方）。\n\
  · 流量经公共 ET 中继：带宽与稳定性不受本项目控制。",
        version = env!("CARGO_PKG_VERSION"),
        bind = DEFAULT_BIND_IP,
        dht = SERVICE_PORT_DHT,
        stun = SERVICE_PORT_STUN,
    )
}

struct Args {
    relays: Vec<String>,
    network_name: Option<String>,
    network_secret: Option<String>,
    room_key: Option<String>,
    mode: String,
    bind: Ipv4Addr,
    local_app: Ipv4Addr,
    services: Vec<u16>,
}

fn parse_args(argv: &[String]) -> Result<Option<Args>, String> {
    let mut args = Args {
        relays: Vec::new(),
        network_name: None,
        network_secret: None,
        room_key: None,
        mode: "joiner".to_string(),
        bind: DEFAULT_BIND_IP,
        local_app: Ipv4Addr::LOCALHOST,
        services: vec![SERVICE_PORT_DHT, SERVICE_PORT_STUN],
    };
    let mut i = 0usize;
    while i < argv.len() {
        let flag = argv[i].clone();
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("选项 {flag} 需要一个值"))
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "--relay" => {
                let v = take(&mut i)?;
                args.relays
                    .extend(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
            }
            "--network-name" => args.network_name = Some(take(&mut i)?),
            "--network-secret" => args.network_secret = Some(take(&mut i)?),
            "--room-key" => args.room_key = Some(take(&mut i)?),
            "--mode" => args.mode = take(&mut i)?,
            "--bind" => {
                let v = take(&mut i)?;
                args.bind = v
                    .parse()
                    .map_err(|_| format!("--bind 需要 IPv4 地址，得到：{v}"))?;
            }
            "--local-app" => {
                let v = take(&mut i)?;
                args.local_app = v
                    .parse()
                    .map_err(|_| format!("--local-app 需要 IPv4 地址，得到：{v}"))?;
            }
            "--services" => {
                let v = take(&mut i)?;
                args.services = v
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .parse::<u16>()
                            .map_err(|_| format!("--services 里有非法端口：{s}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            other => return Err(format!("未知选项：{other}")),
        }
        i += 1;
    }
    Ok(Some(args))
}

fn room_key_from_hex(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!("--room-key 需要 64 位十六进制，得到 {} 位", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "--room-key 不是合法十六进制".to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| format!("--room-key 含非法字符：{s}"))?;
    }
    Ok(out)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let program = std::env::args().next().unwrap_or_else(|| "wgp-et-fallback".into());
    let args = match parse_args(&argv) {
        Ok(Some(a)) => a,
        Ok(None) => {
            println!("{}", usage(&program));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("[et-fallback] 配置错误：{e}");
            eprintln!("[et-fallback] 运行 `{program} --help` 查看用法。");
            return ExitCode::from(2);
        }
    };

    // 网络名/密钥：优先 --room-key 派生，否则要求显式给出
    let (network, secret) = match (&args.room_key, &args.network_name, &args.network_secret) {
        (Some(hex), _, _) => match room_key_from_hex(hex) {
            Ok(key) => derive_network(&key),
            Err(e) => {
                eprintln!("[et-fallback] {e}");
                return ExitCode::from(2);
            }
        },
        (None, Some(name), Some(secret)) => (name.clone(), secret.clone()),
        _ => {
            eprintln!("[et-fallback] 需要 --room-key，或同时给出 --network-name 与 --network-secret");
            return ExitCode::from(2);
        }
    };

    let Some(relay_spec) = args.relays.first() else {
        eprintln!("[et-fallback] 需要至少一个 --relay（tcp://主机:端口）");
        return ExitCode::from(2);
    };
    let relay = match parse_relay(relay_spec) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("[et-fallback] {e}");
            return ExitCode::from(2);
        }
    };

    let config = ProxyConfig {
        bind_ip: args.bind,
        local_app_ip: if args.mode == "host" {
            Some(args.local_app)
        } else {
            None
        },
        service_ports: args.services.clone(),
    };

    let (bridge, mut events) = match FallbackBridge::start(config, network, secret, relay).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[et-fallback] 启动失败：{e}");
            return ExitCode::from(3);
        }
    };

    // 父进程读这一行拿打洞端口；格式固定，改之前先看 wgp-client 的解析
    println!(
        "WGP-ET-FALLBACK READY peer={} bind={} punch={}",
        bridge.peer_id(),
        bridge.bind_ip(),
        bridge.punch_port()
    );
    eprintln!(
        "[et-fallback] 已加入临时 ET 网络（经公共中继 {relay_spec}）：本侧 {bind}:{ports}，打洞端口 {punch}",
        bind = bridge.bind_ip(),
        ports = args
            .services
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("/"),
        punch = bridge.punch_port(),
    );
    eprintln!("[et-fallback] 流量经公共 EasyTier 中继：带宽与稳定性不受本项目控制");

    let (stop_tx, stop_rx) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                BridgeEvent::PeerUp { peer_id } => {
                    eprintln!("[et-fallback] 对端上线：{peer_id}");
                }
                BridgeEvent::PeerDown { peer_id } => {
                    eprintln!("[et-fallback] 对端断开：{peer_id}");
                }
                BridgeEvent::Ready { .. } => {}
                BridgeEvent::Dropped { reason } => {
                    eprintln!("[et-fallback] 丢弃：{reason}");
                }
            }
        }
    });

    let run = tokio::spawn(bridge.run(stop_rx));
    // 等 Ctrl-C；父进程退出时 stdin/stdout 断开，这里也靠信号收尾
    let _ = tokio::signal::ctrl_c().await;
    let _ = stop_tx.send(());
    let _ = run.await;
    pump.abort();
    eprintln!("[et-fallback] 已停止");
    ExitCode::SUCCESS
}
