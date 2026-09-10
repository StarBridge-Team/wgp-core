//! wgp-node：折跃门服务端节点（07 §6 部署规格）。
//! 单进程四职：DHT 种子 / 观察者 / STUN 响应器 / 承诺转发兜底。
//! 无状态、无数据库；日志仅记录节点数与观察请求（不记会话内容）。
//!
//! 用法：
//!   wgp-node [bind] [stun_port|none]
//!   示例：wgp-node 0.0.0.0:3841 3478
//!        wgp-node 0.0.0.0:3841 none   （关 STUN/观察者面）
//! 身份持久化于 ./node_identity.key（首启生成，重启复用；防身份漂移 07 §8）

use std::env;
use std::fs;
use std::path::Path;
use wgp_core::{Engine, NodeConfig, NodeRole};
use wgp_dht::NodeIdentity;

const DEFAULT_BIND: &str = "0.0.0.0:3841";
const DEFAULT_STUN_PORT: u16 = 3478;
const IDENTITY_FILE: &str = "node_identity.key";

/// 载入或生成节点身份（07 §8：身份漂移 = DHT 键散乱 + 日蚀风险）
fn load_or_create_identity() -> NodeIdentity {
    if let Ok(bytes) = fs::read(IDENTITY_FILE) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return NodeIdentity::from_seed(seed);
        }
    }
    let identity = {
        use rand_core::OsRng;
        NodeIdentity::generate(&mut OsRng)
    };
    // 尽力持久化（权限由部署侧 chmod 600；写失败不阻塞启动）
    if let Ok(path) = std::env::current_dir() {
        let _ = fs::write(path.join(Path::new(IDENTITY_FILE)), identity.to_seed());
    }
    identity
}

fn parse_args() -> (String, Option<u16>) {
    let args: Vec<String> = env::args().collect();
    let bind = args
        .get(1)
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    let stun = match args.get(2).map(|s| s.as_str()) {
        Some("none") | Some("off") => None,
        Some(v) => Some(v.parse::<u16>().unwrap_or(DEFAULT_STUN_PORT)),
        None => Some(DEFAULT_STUN_PORT),
    };
    (bind, stun)
}

#[tokio::main]
async fn main() {
    let (bind, stun) = parse_args();
    let identity = load_or_create_identity();

    let (engine, _events) = Engine::new();
    let cfg = NodeConfig {
        role: NodeRole::Seed,
        bind: bind.clone(),
        stun,
    };

    // 四职中的两个网络面：DHT（含承诺转发兜底）+ 观察者（STUN）
    let node = engine.run_node(cfg, identity).await;

    let dht_text = match &node.dht {
        Some(n) => format!("DHT bind={bind} node_id={:02x?}", &n.node_id().0[..4]),
        None => "DHT 启动失败".to_string(),
    };
    match &node.observer {
        Some(o) => println!(
            "wgp-node 已启动（种子+观察者+承诺兜底）| {dht_text} | STUN=:{}",
            o.local_addr().map(|a| a.port()).unwrap_or(0)
        ),
        None => println!("wgp-node 已启动（种子+承诺兜底）| {dht_text} | STUN=off"),
    }

    // 常驻至 ctrl_c（SIGINT）优雅退出
    let _ = tokio::signal::ctrl_c().await;
    println!("wgp-node 收到退出信号，关闭中。");
}