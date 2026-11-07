//! 轻量 Mesh Relay 协议兼容客户端 —— 演示版（含 no-tun / port-forward / socks5 模式）
//!
//! 用法:
//!   普通握手 + 路由监听:
//!     cargo run -- <peer_addr:port> <network_name> <network_secret>
//!
//!   开启端口转发（no-tun，不需要 root/TUN）：
//!     cargo run -- <peer> <name> <secret> --port-forward 0.0.0.0:8080=10.0.0.5:80
//!
//!   开启 SOCKS5 代理（no-tun，不需要 root/TUN）：
//!     cargo run -- <peer> <name> <secret> --socks5 127.0.0.1:1080
//!
//!   同时开：
//!     cargo run -- <peer> <name> <secret> --no-tun --port-forward :8080=10.0.0.5:80 --socks5 :1080
//!
//! 例:   cargo run -- 1.2.3.4:11010 my_net my_secret_pwd --socks5 127.0.0.1:1080

use std::{
    net::{Ipv4Addr, SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};
use mesh_tun_proto::*;

fn u32_to_ip(ip: u32) -> String {
    format!("{}.{}.{}.{}",
        (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff)
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut positional = vec![];
    let mut port_forward = vec![];
    let mut socks5: Option<SocketAddr> = None;
    let mut no_tun = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-tun" => { no_tun = true; }
            "--port-forward" => {
                i += 1;
                if i < args.len() {
                    if let Some((b, d)) = args[i].split_once('=') {
                        port_forward.push((
                            b.parse::<SocketAddr>().expect("bad bind addr"),
                            d.parse::<SocketAddr>().expect("bad dst addr"),
                        ));
                    }
                }
            }
            "--socks5" => {
                i += 1;
                if i < args.len() {
                    socks5 = Some(args[i].parse().expect("bad socks5 addr"));
                }
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    if positional.len() < 3 {
        eprintln!("Usage: {} <peer_addr:port> <network_name> <network_secret> \
                   [--no-tun] [--port-forward bind=dst]* [--socks5 addr]", args[0]);
        std::process::exit(1);
    }
    Args {
        peer_addr: positional.remove(0),
        network_name: positional.remove(0),
        network_secret: positional.remove(0),
        no_tun, port_forward, socks5,
    }
}
struct Args {
    peer_addr: String,
    network_name: String,
    network_secret: String,
    no_tun: bool,
    port_forward: Vec<(SocketAddr, SocketAddr)>,
    socks5: Option<SocketAddr>,
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let ident = NetworkIdentity::new(&args.network_name, &args.network_secret);
    let cipher = PacketCipher::new(&ident.aes_key);

    println!("[1] 计算 digest & AES key …");
    println!("    network_name      = {}", args.network_name);
    println!("    secret_digest[16] = {}", hex::encode(&ident.digest[..16]));
    println!("    aes-128-gcm key   = {}", hex::encode(&ident.aes_key));

    let my_id = random_peer_id();
    println!("\n[2] 连接到 {}，我的 peer_id={my_id}", args.peer_addr);
    let mut stream = TcpStream::connect_timeout(
        &args.peer_addr.parse()?, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    println!("\n[3] 发起 HandshakeRequest …");
    let (remote_peer_id, remote_ip) = do_client_handshake(&mut stream, my_id, &ident)?;
    println!("    ✅ 握手通过: remote_peer_id={remote_peer_id}  remote_ip={}",
        remote_ip.map(u32_to_ip).unwrap_or_else(|| "(none)".to_string()));

    // 初始化 MeshIpPlane（L3 路由 + 加解密）
    let plane = Arc::new(MeshIpPlane::new(my_id, cipher.clone()));

    // outbound 闭包：把 (PeerManagerHeader, body) 发到对端
    let stream_lock = Arc::new(Mutex::new(stream.try_clone().unwrap()));
    let outbound = {
        let s = stream_lock.clone();
        move |hdr: PeerManagerHeader, body: Vec<u8>| -> anyhow::Result<()> {
            let mut guard = s.lock().unwrap();
            send_frame(&mut *guard, &hdr, &body)
                .map_err(|e| anyhow::anyhow!(e))
        }
    };

    // 启动端口转发 / SOCKS5 (需要在 tokio runtime 内)
    if !args.port_forward.is_empty() || args.socks5.is_some() {
        let pf = args.port_forward.clone();
        let s5 = args.socks5;
        let pl = plane.clone();
        let ob = outbound.clone();
        rt.spawn(async move {
            // 先等路由表
            let start = std::time::Instant::now();
            while pl.route.lock().unwrap().peers.is_empty()
                && start.elapsed() < Duration::from_secs(15)
            { tokio::time::sleep(Duration::from_millis(200)).await; }
            let my_vip = pl.route.lock().unwrap().my_ip(my_id)
                .map(|u| Ipv4Addr::from(u.to_be_bytes()))
                .unwrap_or_else(|| Ipv4Addr::new(10, 0, 0, 2));
            println!("\n[*] 我的虚拟 IPv4 = {}", my_vip);

            for (b, d) in pf {
                let pl = pl.clone(); let ob = ob.clone();
                tokio::spawn(async move {
                    if let Err(e) = MeshPortForwarder::run_tcp(b, d, my_vip, pl, ob).await {
                        eprintln!("    port-forward [{b}->{d}] err: {e}");
                    }
                });
            }
            if let Some(addr) = s5 {
                if let Err(e) = MeshSocks5Server::run(addr, my_vip, pl, ob).await {
                    eprintln!("    socks5 err: {e}");
                }
            }
        });
    }

    println!("\n[4] 监听路由表、回包、Ping。监听 60s 后退出。");
    println!("    data-plane mode = {}", if args.no_tun || !args.port_forward.is_empty() || args.socks5.is_some() {
        "no-tun / user-space proxy" } else { "monitor-only（没有代理/TUN）" });
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        let (mut hdr, payload) = match recv_frame(&mut stream) {
            Ok(v) => v,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => { eprintln!("    recv err: {e}"); break; }
        };
        let decrypted = match decrypt_packet(&cipher, &mut hdr, &payload) {
            Ok(b) => b,
            Err(e) => { eprintln!("    decrypt skip: {e}"); continue; }
        };

        match hdr.packet_type {
            PacketType::RpcReq | PacketType::RpcResp => {
                if let Ok(Some(rt)) = try_parse_route_from_rpc(&decrypted) {
                    let newer = plane.route.lock().unwrap().timestamp < rt.timestamp;
                    if newer {
                        println!("    路由表更新 ts={}, peers={}", rt.timestamp, rt.peers.len());
                        for p in &rt.peers {
                            println!("      peer_id={:<10}  ipv4={:<15}  /{}  str={}",
                                p.peer_id,
                                p.ipv4_addr.map(u32_to_ip).unwrap_or_default(),
                                p.network_length,
                                p.ipv4_str.as_deref().unwrap_or("-"));
                        }
                        plane.update_routes(rt);
                    }
                }
            }
            PacketType::Ping => {
                let mut ph = PeerManagerHeader::new(my_id, hdr.from_peer_id, PacketType::Pong, 0);
                let resp = encrypt_packet(&cipher, &mut ph, &[])
                    .unwrap_or_default();
                let _ = send_frame(&mut stream, &ph, &resp);
            }
            PacketType::Data => {
                // 解出的 raw IP 包：
                //  * 如果有 MeshIpPlane 上连接着 TUN 或用户态栈，就喂进去
                //  * 如果有 MeshTcpSocket feed_inbound 通道，就解析 TCP payload
                // 这里演示版只打印长度
                if decrypted.len() > 0 && hdr.to_peer_id == my_id {
                    let _d = parse_ip_dst(&decrypted).ok();
                }
            }
            other => {
                if !decrypted.is_empty() {
                    println!("    pkt={:?} len={} encrypted={} from={} to={}",
                        other, hdr.len, (hdr.flags & FLAG_ENCRYPTED) != 0,
                        hdr.from_peer_id, hdr.to_peer_id);
                }
            }
        }
    }

    let _ = stream.shutdown(std::net::Shutdown::Both);
    println!("\n[5] 演示结束。");
    Ok(())
}
