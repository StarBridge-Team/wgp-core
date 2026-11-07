//! 端到端示例：两个轻量客户端通过同一个 Mesh Network 节点（Core/Public Server）互发用户自定义 payload。
//!
//! 设计目标：
//!   - 不依赖任何官方 Mesh Relay Relay 二进制运行时（只用到本 crate 的协议层）；
//!   - 不做 NAT 穿透，只要求双方都能连上同一个 relay（任何 Mesh Relay 节点都行）；
//!   - 直接发「应用层消息」，不需要构造 IP 头 / 开 TUN / 用 SOCKS5。
//!
//! 用法（两个终端分别跑）：
//!   Terminal A: cargo run --example p2p_chat -- --role a --peer 127.0.0.1:11010 --net testnet --sec testpass
//!   Terminal B: cargo run --example p2p_chat -- --role b --peer 127.0.0.1:11010 --net testnet --sec testpass
//!
//! 如果需要通过代理连中继节点：
//!   --proxy http://127.0.0.1:18080
//!
//! 工作流程：
//!   1. 两边都连到同一个 relay，完成握手 → 拿到 relay peer_id；
//!   2. 两边都给 relay 推 SyncRouteInfoRequest（声明自己 peer_id + hostname）；
//!   3. 两边通过 RouteUpdate 学习全网路由表，从 hostname 里识别出"对方"的 peer_id；
//!   4. P2pNode::send_data_to(dst_peer_id, msg_bytes) → relay 转发 → 对方通过 P2pEvent::InboundIpPacket 收到；
//!   5. A 每 2 秒发一个 hello-xxx，B 收到后立刻回 pong-xxx。

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use mesh_tun_proto::{P2pEvent, P2pNode};

struct Args {
    role: String,        // "a" 或 "b"
    peer_addr: String,   // relay/中继节点 ip:port
    net: String,
    sec: String,
    proxy: Option<String>,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut role = "a".to_string();
    let mut peer_addr = String::new();
    let mut net = String::new();
    let mut sec = String::new();
    let mut proxy: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--role" => { i += 1; role = args[i].clone(); }
            "--peer" => { i += 1; peer_addr = args[i].clone(); }
            "--net"  => { i += 1; net = args[i].clone(); }
            "--sec"  => { i += 1; sec = args[i].clone(); }
            "--proxy"=> { i += 1; proxy = Some(args[i].clone()); }
            _ => {}
        }
        i += 1;
    }
    if peer_addr.is_empty() || net.is_empty() || sec.is_empty() {
        eprintln!(
            "usage: {} --role <a|b> --peer <ip:port> --net <name> --sec <secret> [--proxy http://...]",
            args[0]
        );
        std::process::exit(1);
    }
    Args { role, peer_addr, net, sec, proxy }
}

fn connect_tcp(addr: &str, proxy: &Option<String>, read_timeout_ms: u64) -> anyhow::Result<TcpStream> {
    let s = if let Some(p) = proxy {
        let p = p.strip_prefix("http://").or_else(|| p.strip_prefix("https://")).unwrap_or(p);
        let (phost, pport) = p.rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad proxy: {p}"))?;
        let pport: u16 = pport.parse()?;
        let mut s = TcpStream::connect((phost, pport))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let req = format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        s.write_all(req.as_bytes())?;
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf)?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
            anyhow::bail!("proxy CONNECT failed: {}", resp.lines().next().unwrap_or(""));
        }
        s
    } else {
        let sa: std::net::SocketAddr = addr.parse()?;
        TcpStream::connect_timeout(&sa, Duration::from_secs(15))?
    };
    s.set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(s)
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    let my_hostname = format!("mesh-client-{}", args.role);
    // 客户端 A 用奇数 peer_id，B 用偶数 peer_id，方便肉眼区分
    let my_peer_id_seed: u32 = if args.role == "a" { 0xA000_0001 } else { 0xB000_0001 };

    // -------- 1. 创建本地身份 + 顶层 P2pNode --------
    let mut node = P2pNode::new(args.net.clone(), args.sec.clone(), Some(my_peer_id_seed));
    let my_peer_id = node.identity.my_peer_id;
    eprintln!("[Init] my_peer_id={my_peer_id:#x} hostname={my_hostname} role={}", args.role);

    // -------- 2. 连到 relay --------
    let stream = connect_tcp(&args.peer_addr, &args.proxy, 50)?;
    eprintln!("[Conn] TCP 已连接到 relay={}, local={:?}",
        args.peer_addr, stream.local_addr().unwrap());
    let relay_pid = node.add_stream_conn(stream)?;
    eprintln!("[HS OK] relay peer_id={relay_pid:#x}");

    // -------- 3. 在主连接上主动发 SyncRouteInfoRequest，让 relay 学到我们的 hostname/peer_id --------
    // 这是关键：Relay 作为 responder 只能通过我们主动发的 Request 拿到 hostname 等信息，
    // 进而把我们在路由表里广播给对端客户端。用主连接发，避免临时连接关闭导致信息丢失。
    let announced = node.announce_self_to_all(&my_hostname, None);
    eprintln!("[Announce] SyncRouteInfoRequest sent to {announced} peer(s)");

    // -------- 4. 主循环：tick → 找对方 peer_id → 收发消息 --------
    let mut other_peer_id: Option<u32> = None;
    let mut seen: HashSet<u32> = HashSet::new();
    let mut seq: u64 = 0;
    let mut sent: u64 = 0;
    let mut recv: u64 = 0;
    let mut last_send = Instant::now() - Duration::from_secs(9999); // 立刻触发一次发送
    let mut last_announce = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(120);
    let role_is_a = args.role == "a";

    eprintln!("\n[MainLoop] 2 分钟，等待路由学习并互发消息...\n");

    while Instant::now() < deadline {
        // 每 16ms 驱一次 tick，最多 poll 16 帧/连接
        let events = node.tick(16);
        for ev in events {
            match ev {
                P2pEvent::RouteChanged { peers, timestamp_secs: _ } => {
                    // 从路由表里找"不是我、不是 relay"的那个，就是对方客户端
                    let candidates: Vec<_> = node.mesh.route.peers.iter()
                        .filter(|p| p.peer_id != my_peer_id && p.peer_id != relay_pid)
                        .collect();
                    for p in &candidates {
                        let is_new = seen.insert(p.peer_id);
                        let host = p.ipv4_str.as_deref().unwrap_or("-");
                        if is_new {
                            eprintln!("[NEW PEER] peer_id={:#x} hostname={}", p.peer_id, host);
                        }
                        // hostname 里有 "client-b" 就认定是 B，反之亦然
                        let want = if role_is_a { "client-b" } else { "client-a" };
                        if host.contains(want) && other_peer_id != Some(p.peer_id) {
                            other_peer_id = Some(p.peer_id);
                            eprintln!("[Found {}] peer_id={:#x}", if role_is_a { "B" } else { "A" }, p.peer_id);
                        }
                    }
                    eprintln!("[Route] total={} candidates={} my_routes={}",
                        peers, candidates.len(), node.mesh.route.peers.len());
                }
                P2pEvent::InboundIpPacket(bytes) => {
                    // 正常的 IP 包（NOT_SEND_TO_TUN=0）：如果下游接 TUN 就写 TUN；这里我们只做演示
                    let txt = String::from_utf8_lossy(&bytes);
                    recv += 1;
                    eprintln!("[RECV-IP #{}] {} bytes: {}", recv, bytes.len(), txt);
                }
                P2pEvent::InboundUserData { from_peer_id, data } => {
                    // 用户自定义 payload（NOT_SEND_TO_TUN=1）：对端 send_data_to 发的聊天消息
                    let txt = String::from_utf8_lossy(&data);
                    recv += 1;
                    eprintln!("[RECV-DATA #{}] from={:#x} {} bytes: {}", recv, from_peer_id, data.len(), txt);
                    // B 角色：收到 A 的 hello 就回 pong
                    if !role_is_a {
                        let reply = format!("pong-from-B echo=[{}]", txt);
                        if let Err(e) = node.send_data_to(from_peer_id, reply.as_bytes()) {
                            eprintln!("    B reply failed: {e}");
                        } else {
                            eprintln!("    B -> A (to={:#x}): {}", from_peer_id, reply);
                            sent += 1;
                        }
                    }
                }
                P2pEvent::PeerUp { peer_id, label } => {
                    eprintln!("[PeerUp] {peer_id:#x} via {label}");
                }
                P2pEvent::PeerDown { peer_id, label } => {
                    eprintln!("[PeerDown] {peer_id:#x} via {label}");
                }
                P2pEvent::DecryptError { from_peer_id, packet_type, len } => {
                    eprintln!("[DecryptErr] from={from_peer_id:#x} type={packet_type} len={len}");
                }
            }
        }

        // A 角色：每 2 秒发一个 hello
        if role_is_a && last_send.elapsed() >= Duration::from_secs(2) {
            if let Some(pid) = other_peer_id {
                seq += 1;
                let msg = format!("hello-from-A seq={seq} ts={:?}", Instant::now().elapsed());
                match node.send_data_to(pid, msg.as_bytes()) {
                    Ok(()) => {
                        eprintln!("[SEND #{}] A -> B: {}", seq, msg);
                        sent += 1;
                    }
                    Err(e) => eprintln!("[SEND FAIL] {e}"),
                }
                last_send = Instant::now();
            } else if seq == 0 {
                // 只打印一次"还没找到对方"
                eprintln!("[WAIT] 尚未发现对方客户端，等 OSPF 路由同步...");
                seq = 1; // 防重复打印
            }
        }

        // 顺便把 recv_ipv4 队列里的也打出来（tick 已经在 InboundIpPacket 里给过一次了，这里是空操作，保险）
        while let Some(pkt) = node.recv_ipv4() {
            eprintln!("[recv_ipv4 drain] {} bytes", pkt.len());
        }

        // 每 10 秒重发一次 SyncRouteInfoRequest，让 Relay 持续学到我们的 hostname
        if last_announce.elapsed() >= Duration::from_secs(10) {
            let n = node.announce_self_to_all(&my_hostname, None);
            if n > 0 {
                eprintln!("[Announce] re-announce to {n} peer(s)");
            }
            last_announce = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(16));
    }

    eprintln!("\n========== 结束统计 ==========");
    eprintln!("my_peer_id  = {my_peer_id:#x}");
    eprintln!("relay       = {relay_pid:#x}");
    eprintln!("other_peer  = {:?}", other_peer_id.map(|v| format!("{v:#x}")).unwrap_or_else(|| "N/A".to_string()));
    eprintln!("发送包数    = {sent}");
    eprintln!("接收包数    = {recv}");
    eprintln!("全网见过peer = {:?}", seen.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>());
    Ok(())
}
