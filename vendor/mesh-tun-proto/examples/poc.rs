//! PoC 验证 demo：用 STUN 探测公网地址 + 连官方 Mesh Relay 中继节点
//! 
//! 用法：
//!   cargo run --example poc --features=proxy -- <中继节点IP:端口> <网络名> <密码>
//!   例：cargo run --example poc --features=proxy -- 1.2.3.4:11010 testnet pass123

use mesh_tun_proto::*;
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("用法: {} <公共节点IP:端口> <网络名> <密码>", args[0]);
        eprintln!("例: {} 1.2.3.4:11010 testnet pass123", args[0]);
        std::process::exit(1);
    }
    let public_server = &args[1];
    let network_name = &args[2];
    let network_secret = &args[3];

    println!("=== Mesh Proto PoC 验证 ===");
    println!("目标公共节点: {}", public_server);
    println!("网络名: {}", network_name);

    // ① 用 STUN 探测公网地址（失败就跳过，不影响后续测试）
    println!("\n[1/4] 探测公网地址（用 STUN 协议）...");
    match detect_public_addr() {
        Ok(addr) => println!("✓ 我的公网地址: {}", addr),
        Err(e) => println!("⚠ STUN 探测失败（{}），跳过，不影响协议测试", e),
    }

    // ② 建 P2pNode
    println!("\n[2/4] 建 P2pNode...");
    let mut node = P2pNode::new(network_name, network_secret, None);
    println!("✓ 我的 peer_id: {}", node.identity.my_peer_id);

    // ③ TCP 连中继节点
    println!("\n[3/4] TCP 连公共节点 {}...", public_server);
    let stream = TcpStream::connect(public_server)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let peer_id = node.add_stream_conn(stream)?;
    println!("✓ 握手成功，对端 peer_id: {}", peer_id);

    // ④ 主循环：tick + 主动 Ping + 等 RouteUpdate
    println!("\n[4/4] 进入主循环（每 10s 发 Ping，等 RouteUpdate）...\n");
    let start = Instant::now();
    let mut last_ping = Instant::now();
    let mut got_route = false;

    loop {
        // 每 10s 主动发 Ping
        if last_ping.elapsed() > Duration::from_secs(10) {
            if let Some(conn) = node.peers.get_mut(&peer_id) {
                let ping_hdr = PeerManagerHeader::new(
                    node.identity.my_peer_id,
                    peer_id,
                    PacketType::Ping,
                    0,
                );
                conn.transport.send_frame(&ping_hdr, &[])?;
                println!("[Ping] 发送心跳到 peer_id={}", peer_id);
                last_ping = Instant::now();
            }
        }

        // tick 一次
        let events = node.tick(10);
        for ev in events {
            match ev {
                P2pEvent::PeerUp { peer_id, label } => {
                    println!("[事件] PeerUp: peer_id={}, label={}", peer_id, label);
                }
                P2pEvent::PeerDown { peer_id, label } => {
                    println!("[事件] PeerDown: peer_id={}, label={}", peer_id, label);
                    println!("\n❌ 连接断开，退出");
                    return Ok(());
                }
                P2pEvent::RouteChanged { peers, timestamp_secs } => {
                    println!("[事件] RouteChanged: {} 个节点 @ {}", peers, timestamp_secs);
                    got_route = true;
                    // 打印路由表
                    for p in &node.mesh.route.peers {
                        if let Some(ip) = p.ipv4_addr {
                            let ip_str = std::net::Ipv4Addr::from(ip);
                            println!("  - peer_id={}, ip={}/{}", p.peer_id, ip_str, p.network_length);
                        }
                    }
                }
                P2pEvent::InboundIpPacket(pkt) => {
                    println!("[事件] InboundIpPacket: {} 字节", pkt.len());
                    if pkt.len() >= 20 {
                        let ip_version = pkt[0] >> 4;
                        println!("  IP 版本: {}", ip_version);
                        if ip_version == 4 && pkt.len() >= 20 {
                            let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                            let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                            println!("  {} → {}", src, dst);
                        }
                    }
                }
                P2pEvent::InboundUserData { from_peer_id, data } => {
                    println!("[事件] InboundUserData: from={:#x} {} 字节", from_peer_id, data.len());
                }
                P2pEvent::DecryptError { from_peer_id, packet_type, len } => {
                    println!("[错误] DecryptError: from={}, type={}, len={}", from_peer_id, packet_type, len);
                }
            }
        }

        // 如果已经拿到路由表，尝试发一个 ICMP Echo（可选）
        if got_route && start.elapsed() > Duration::from_secs(5) {
            // 找路由表里第一个有 IP 的 peer
            if let Some(target_peer) = node.mesh.route.peers.iter().find(|p| p.ipv4_addr.is_some()) {
                let target_ip = target_peer.ipv4_addr.unwrap();
                let target_ip_str = std::net::Ipv4Addr::from(target_ip);
                
                // 构造一个最小的 ICMP Echo Request（IPv4 + ICMP）
                let icmp_pkt = build_icmp_echo_request(target_ip);
                println!("\n[测试] 发送 ICMP Echo 到 {}...", target_ip_str);
                match node.send_ipv4(&icmp_pkt) {
                    Ok(_) => println!("✓ ICMP Echo 已发送"),
                    Err(e) => println!("✗ 发送失败: {}", e),
                }
                // 发完就退出（PoC 验证完成）
                println!("\n=== PoC 验证完成 ===");
                println!("✓ 成功连上公共节点");
                println!("✓ 成功拿到路由表");
                println!("✓ 成功发送 ICMP Echo");
                println!("\n如果收到 InboundIpPacket 里的 ICMP Reply，说明整条链路通了！");
                return Ok(());
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 用 STUN 协议探测公网地址（RFC 5389）
fn detect_public_addr() -> anyhow::Result<String> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    
    // 用 Google 的公共 STUN 服务器
    let stun_server = "stun.l.google.com:19302";
    
    // 构造 STUN Binding Request（20 字节）
    // Message Type: 0x0001 (Binding Request)
    // Message Length: 0x0000 (无属性)
    // Magic Cookie: 0x2112A442
    // Transaction ID: 12 字节随机
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&[0x00, 0x01]); // Binding Request
    request[2..4].copy_from_slice(&[0x00, 0x00]); // Length = 0
    request[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
    // Transaction ID (12 bytes random)
    for i in 8..20 {
        request[i] = rand::random();
    }
    
    sock.send_to(&request, stun_server)?;
    
    let mut buf = [0u8; 1500];
    let (n, _) = sock.recv_from(&mut buf)?;
    
    // 解析 STUN 响应
    if n < 20 {
        anyhow::bail!("STUN 响应太短");
    }
    
    // 检查 Magic Cookie
    if buf[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        anyhow::bail!("STUN 响应 Magic Cookie 不对");
    }
    
    // 解析属性，找 XOR-MAPPED-ADDRESS (0x0020)
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let mut offset = 20;
    while offset < 20 + msg_len {
        if offset + 4 > n {
            break;
        }
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        
        if attr_type == 0x0020 && attr_len >= 8 {
            // XOR-MAPPED-ADDRESS
            // Family: 1 byte (0x01 = IPv4)
            // X-Port: 2 bytes
            // X-Address: 4 bytes
            let family = buf[offset];
            if family == 0x01 {
                let x_port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
                let port = x_port ^ 0x2112; // XOR with magic cookie first 2 bytes
                
                let x_addr = u32::from_be_bytes([
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                ]);
                let addr = x_addr ^ 0x2112A442; // XOR with magic cookie
                
                let ip = std::net::Ipv4Addr::from(addr);
                return Ok(format!("{}:{}", ip, port));
            }
        }
        
        // 属性长度要 4 字节对齐
        offset += (attr_len + 3) & !3;
    }
    
    anyhow::bail!("STUN 响应里没有 XOR-MAPPED-ADDRESS")
}

/// 构造一个最小的 ICMP Echo Request（IPv4 + ICMP）
fn build_icmp_echo_request(dst_ip: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 28]; // 20B IPv4 + 8B ICMP
    
    // IPv4 Header
    pkt[0] = 0x45; // Version=4, IHL=5
    pkt[1] = 0x00; // DSCP/ECN
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes()); // Total Length
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identification
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // Flags + Fragment Offset
    pkt[8] = 64; // TTL
    pkt[9] = 1; // Protocol = ICMP
    pkt[10..12].copy_from_slice(&0u16.to_be_bytes()); // Header Checksum (先填 0)
    pkt[12..16].copy_from_slice(&10u32.to_be_bytes()); // Source IP (随便填个 10.x.x.x)
    pkt[16..20].copy_from_slice(&dst_ip.to_be_bytes()); // Destination IP
    
    // 计算 IPv4 Header Checksum
    let checksum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
    
    // ICMP Header (Echo Request)
    pkt[20] = 8; // Type = Echo Request
    pkt[21] = 0; // Code = 0
    pkt[22..24].copy_from_slice(&0u16.to_be_bytes()); // Checksum (先填 0)
    pkt[24..26].copy_from_slice(&1u16.to_be_bytes()); // Identifier
    pkt[26..28].copy_from_slice(&1u16.to_be_bytes()); // Sequence Number
    
    // 计算 ICMP Checksum
    let icmp_checksum = icmp_checksum(&pkt[20..28]);
    pkt[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    
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
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmp_checksum(data: &[u8]) -> u16 {
    ipv4_checksum(data) // 同样的算法
}
