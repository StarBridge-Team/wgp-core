//! 模拟 TUN 集成示例：两个轻量客户端（各自代表一个"加了 TUN 的应用"）通过同一个
//! Mesh Network relay（Relay）交换真实 IPv4 包（ICMP Echo/Reply）。
//!
//! 关键差异（和 p2p_chat.rs 比）：
//!   - 双方 announce_self_to_all 时**带上自己的虚拟 IPv4**（A=10.144.0.10, B=10.144.0.20）
//!   - 调用 node.set_my_tun_enabled(true) → send_ipv4 发的 Data 帧自动带 NOT_SEND_TO_TUN=0
//!   - A 构造 ICMP Echo (src=10.144.0.10 → dst=10.144.0.20) → node.send_ipv4()
//!   - Relay 按 OSPF 学到的 peer_infos（有/32 路由）把 Data 帧投递给 B
//!   - B 通过 P2pEvent::InboundIpPacket 拿到 ICMP Echo，构造 Echo Reply → send_ipv4()
//!   - A 收到 P2pEvent::InboundIpPacket 的 Reply，统计 RTT
//!
//! 用法（两个终端分别跑，假设 Relay 跑在 127.0.0.1:11010）：
//!   A: cargo run --example tun_ipv4 -- --role a --peer 127.0.0.1:11010 --net testnet --sec testpass
//!   B: cargo run --example tun_ipv4 -- --role b --peer 127.0.0.1:11010 --net testnet --sec testpass

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::{Duration, Instant};

use mesh_tun_proto::{P2pEvent, P2pNode};

struct Args {
    role: String,        // "a" 或 "b"
    peer_addr: String,   // relay ip:port
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
        let (phost, pport) = p.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("bad proxy"))?;
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
        TcpStream::connect(addr)?
    };
    s.set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))?;
    s.set_write_timeout(Some(Duration::from_millis(read_timeout_ms)))?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// 每个角色的虚拟 IPv4（严格对应 announce_self_to_all 里的 my_ipv4 参数）
fn my_virtual_ip(role: &str) -> u32 {
    match role {
        "b" => u32::from_be_bytes([10, 144, 0, 20]),
        _   => u32::from_be_bytes([10, 144, 0, 10]),
    }
}
fn peer_virtual_ip(role: &str) -> u32 {
    match role {
        "b" => u32::from_be_bytes([10, 144, 0, 10]),
        _   => u32::from_be_bytes([10, 144, 0, 20]),
    }
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    let role_is_a = args.role != "b";
    let my_hostname = if role_is_a { "tun-client-a".to_string() } else { "tun-client-b".to_string() };
    let my_ip = my_virtual_ip(&args.role);
    let peer_ip = peer_virtual_ip(&args.role);
    eprintln!("[TUN] role={} vip={}", if role_is_a { "A" } else { "B" }, Ipv4Addr::from(my_ip));

    // ---- 1. 建连接 + 加 P2pNode（注意：set_my_tun_enabled(true) 是 TUN 集成关键）
    let stream = connect_tcp(&args.peer_addr, &args.proxy, 200)?;
    let mut node = P2pNode::new(args.net.clone(), args.sec.clone(), None);
    node.set_my_tun_enabled(true); // <<< 告诉 crate："我已经接了真 TUN"，NOT_SEND_TO_TUN 清零
    let my_peer_id = node.identity.my_peer_id;
    eprintln!("[TUN] my_peer_id={:#x}", my_peer_id);
    let relay_pid = node.add_stream_conn(stream)?;
    eprintln!("[TUN] connected relay peer_id={:#x}", relay_pid);

    // ---- 2. 周期性主动 announce 自己（带 IPv4），让 relay/Core 学到我们的路由并广播给对方
    let mut last_announce = Instant::now() - Duration::from_secs(999);
    let _ = node.announce_self_to_all(&my_hostname, Some(my_ip));

    let deadline = Instant::now() + Duration::from_secs(60);
    let _seen: HashSet<u32> = HashSet::new();
    let mut ping_sent = 0usize;
    let mut pong_recv = 0usize;
    let mut last_ping_at: Option<Instant> = None;
    let mut last_send = Instant::now() - Duration::from_secs(999);

    while Instant::now() < deadline {
        let events = node.tick(32);
        for ev in events {
            match ev {
                P2pEvent::RouteChanged { peers, timestamp_secs: _ } => {
                    // 打印学习到的 IPv4 路由
                    let routes: Vec<_> = node.mesh.route.peers.iter()
                        .filter(|p| p.ipv4_addr.is_some())
                        .map(|p| (p.peer_id, p.ipv4_addr.unwrap(), p.network_length))
                        .collect();
                    eprintln!("[Route] total={} vip-routes={:?}", peers, routes.iter()
                        .map(|(pid, ip, n)| format!("{:#x}->{}/{}", pid, Ipv4Addr::from(*ip), n))
                        .collect::<Vec<_>>());
                }
                P2pEvent::InboundIpPacket(pkt) => {
                    // 这就是 TUN 要读的东西！下游工具把 pkt 直接写进 /dev/net/tun 即可
                    if pkt.len() < 28 { continue; }
                    let ver = pkt[0] >> 4;
                    if ver != 4 { continue; }
                    let proto = pkt[9];
                    if proto != 1 { continue; } // ICMP only
                    let icmp_type = pkt[20];
                    match icmp_type {
                        8 => {
                            // Echo Request → 我们模拟 TUN 上的 ping daemon，发 Echo Reply
                            let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
                            let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
                            eprintln!("[IP-RECV] ICMP Echo Request {} -> {}", Ipv4Addr::from(src), Ipv4Addr::from(dst));
                            let reply = build_icmp_echo_reply_from_request(&pkt);
                            match node.send_ipv4(&reply) {
                                Ok(_) => eprintln!("[IP-SEND] ICMP Echo Reply sent (via send_ipv4)"),
                                Err(e) => eprintln!("[IP-SEND] send_ipv4 failed: {e}"),
                            }
                        }
                        0 => {
                            // Echo Reply → 统计 RTT
                            pong_recv += 1;
                            let rtt = last_ping_at.map(|t| t.elapsed()).unwrap_or_default();
                            eprintln!("[IP-RECV] ICMP Echo Reply #{pong_recv} rtt={:?}", rtt);
                        }
                        _ => {}
                    }
                }
                P2pEvent::InboundUserData { from_peer_id, data } => {
                    eprintln!("[DATA] from={:#x} {} bytes (ignored; only IPv4 here)", from_peer_id, data.len());
                }
                P2pEvent::PeerUp { peer_id, label } => eprintln!("[PeerUp] {peer_id:#x} via {label}"),
                P2pEvent::PeerDown { peer_id, label } => eprintln!("[PeerDown] {peer_id:#x} via {label}"),
                P2pEvent::DecryptError { from_peer_id, packet_type, len } =>
                    eprintln!("[DecryptErr] from={from_peer_id:#x} t={packet_type} l={len}"),
            }
        }

        // 重发 announce（每 10s）
        if last_announce.elapsed() >= Duration::from_secs(10) {
            let n = node.announce_self_to_all(&my_hostname, Some(my_ip));
            if n > 0 { eprintln!("[Announce] re-announce vip={} to {n} peer(s)", Ipv4Addr::from(my_ip)); }
            last_announce = Instant::now();
        }

        // A 每 3s 造一个 ICMP Echo 发过去
        if role_is_a && last_send.elapsed() >= Duration::from_secs(3) {
            match node.lookup_peer_by_ipv4(peer_ip) {
                Some(pid) => eprintln!("[Lookup] peer_ip={} -> peer_id={:#x}", Ipv4Addr::from(peer_ip), pid),
                None => eprintln!("[Lookup] no route to {} (will fall back to relay)", Ipv4Addr::from(peer_ip)),
            }
            let echo = build_icmp_echo_request(my_ip, peer_ip, (ping_sent + 1) as u16, (ping_sent + 1) as u16);
            match node.send_ipv4(&echo) {
                Ok(_) => {
                    ping_sent += 1;
                    last_ping_at = Some(Instant::now());
                    eprintln!("[IP-SEND #{}] ICMP Echo {} -> {}", ping_sent, Ipv4Addr::from(my_ip), Ipv4Addr::from(peer_ip));
                }
                Err(e) => eprintln!("[IP-SEND-ERR] {e}"),
            }
            last_send = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    eprintln!("\n[Done] role={} ping_sent={ping_sent} pong_recv={pong_recv}", if role_is_a { "A" } else { "B" });
    Ok(())
}

// ====================== ICMP helpers ======================

fn build_icmp_echo_request(src_ip: u32, dst_ip: u32, id: u16, seq: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&src_ip.to_be_bytes());
    pkt[16..20].copy_from_slice(&dst_ip.to_be_bytes());
    let cs = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&cs.to_be_bytes());

    pkt[20] = 8;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&id.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    let ic = icmp_checksum(&pkt[20..28]);
    pkt[22..24].copy_from_slice(&ic.to_be_bytes());
    pkt
}

/// 把 Echo Request 的 IP/ICMP 整包倒转 src/dst，type=0 变成 Echo Reply。
fn build_icmp_echo_reply_from_request(req: &[u8]) -> Vec<u8> {
    if req.len() < 28 { return Vec::new(); }
    let mut pkt = req.to_vec();
    let src = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst = [pkt[16], pkt[17], pkt[18], pkt[19]];
    pkt[12..16].copy_from_slice(&dst);
    pkt[16..20].copy_from_slice(&src);
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes());
    let cs = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&cs.to_be_bytes());

    pkt[20] = 0; // Echo Reply
    pkt[22..24].copy_from_slice(&0u16.to_be_bytes());
    let ic = icmp_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&ic.to_be_bytes());
    pkt
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }
    while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}
fn icmp_checksum(data: &[u8]) -> u16 { ipv4_checksum(data) }
