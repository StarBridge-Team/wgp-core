//! 完整链路验证 v2：握手 + 回送 SyncRouteInfoResponse + 主动发起 SyncRouteInfoRequest
//! 长时间运行，观察网络内是否出现别的节点，以及是否能收到 Data 包。
//!
//! 用法：
//!   cargo run --example dbg_hs -- <中继节点IP:端口> <网络名> <密码> [代理URL]
//!   例：cargo run --example dbg_hs -- 39.108.52.138:11010 sjdjfudjnx djdjfnnf http://127.0.0.1:18080

use bytes::BufMut;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn connect_via_proxy(dst: &str, proxy: &str) -> anyhow::Result<TcpStream> {
    let proxy = proxy.strip_prefix("http://").or_else(|| proxy.strip_prefix("https://")).unwrap_or(proxy);
    let (phost, pport) = proxy.rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("bad proxy url"))?;
    let pport: u16 = pport.parse()?;
    let mut s = TcpStream::connect((phost, pport))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let req = format!("CONNECT {dst} HTTP/1.1\r\nHost: {dst}\r\n\r\n");
    s.write_all(req.as_bytes())?;
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
        anyhow::bail!("proxy CONNECT failed: {}", resp.lines().next().unwrap_or(""));
    }
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(s)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} <ip:port> <net> <secret> [proxy_url]", args[0]);
        std::process::exit(1);
    }
    let addr = &args[1];
    let net = &args[2];
    let secret = &args[3];
    let proxy = args.get(4).cloned();

    let ident = mesh_tun_proto::NetworkIdentity::new(net, secret);
    let cipher = mesh_tun_proto::PacketCipher::new(&ident.aes_key);
    let my_id = mesh_tun_proto::random_peer_id();
    let my_ospf_sid: u64 = rand::random::<u64>().max(1);

    // 构造握手帧
    let req = mesh_tun_proto::build_handshake_request(my_id, &ident);
    let payload = mesh_tun_proto::encode_handshake(&req);
    let hdr = mesh_tun_proto::PeerManagerHeader::new(my_id, 0, mesh_tun_proto::PacketType::HandShake, payload.len() as u32);
    let mut buf = bytes::BytesMut::new();
    buf.put_u32_le((mesh_tun_proto::PEER_MANAGER_HEADER_SIZE as u32) + payload.len() as u32);
    hdr.encode(&mut buf);
    buf.extend_from_slice(&payload);

    eprintln!("[1] 连接 {} (proxy={})", addr, proxy.as_deref().unwrap_or("(none)"));
    let mut s = match &proxy {
        Some(p) => connect_via_proxy(addr, p)?,
        None => {
            let sa: std::net::SocketAddr = addr.parse()?;
            let s = TcpStream::connect_timeout(&sa, Duration::from_secs(15))?;
            s
        }
    };
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    eprintln!("    local={:?}", s.local_addr());

    s.write_all(&buf)?;
    eprintln!("[2] 已发送握手包");

    // 读握手响应
    let mut rbuf = Vec::new();
    let server_peer_id;
    loop {
        let mut tmp = [0u8; 4096];
        match s.read(&mut tmp) {
            Ok(0) => anyhow::bail!("连接关闭（握手阶段）"),
            Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        if rbuf.len() >= 4 {
            let want = u32::from_le_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]) as usize;
            if rbuf.len() >= 4 + want {
                let body = &rbuf[4..4 + want];
                let rhdr = mesh_tun_proto::PeerManagerHeader::decode(body);
                let rpay = &body[mesh_tun_proto::PEER_MANAGER_HEADER_SIZE..];
                let rreq = mesh_tun_proto::decode_handshake(rpay)?;
                eprintln!("[3] 握手通过: server peer_id={} version={}", rreq.my_peer_id, rreq.version);
                server_peer_id = rreq.my_peer_id;
                rbuf = rbuf[4 + want..].to_vec();
                break;
            }
        }
    }

    // 主动发 SyncRouteInfoRequest，告诉 server 我们的存在
    let my_sid = mesh_tun_proto::stable_session_id(my_id, server_peer_id);
    if let Ok((phdr, pct)) = mesh_tun_proto::build_sync_route_info_request(
        &cipher, my_id, server_peer_id, None, "mesh-proto-poc", my_sid, "default") {
        let mut f = bytes::BytesMut::new();
        f.put_u32_le((mesh_tun_proto::PEER_MANAGER_HEADER_SIZE as u32) + pct.len() as u32);
        phdr.encode(&mut f);
        f.extend_from_slice(&pct);
        let _ = s.write_all(&f);
        eprintln!("[4] 主动发送 SyncRouteInfoRequest");
    }

    // 主循环
    eprintln!("\n[5] 主循环 90s：回送响应 + 观察路由 + 统计收发包\n");
    let start = Instant::now();
    let mut last_ping = Instant::now();
    let mut seen_peers: HashSet<u32> = HashSet::new();
    let mut data_in = 0usize;
    let mut data_out = 0usize;
    let mut rpc_in = 0usize;
    let mut rpc_out = 0usize;

    while start.elapsed() < Duration::from_secs(90) {
        if last_ping.elapsed() > Duration::from_secs(15) {
            let ping_hdr = mesh_tun_proto::PeerManagerHeader::new(my_id, server_peer_id, mesh_tun_proto::PacketType::Ping, 0);
            let mut f = bytes::BytesMut::new();
            f.put_u32_le(mesh_tun_proto::PEER_MANAGER_HEADER_SIZE as u32);
            ping_hdr.encode(&mut f);
            let _ = s.write_all(&f);
            last_ping = Instant::now();
        }

        let mut tmp = [0u8; 8192];
        match s.read(&mut tmp) {
            Ok(0) => { eprintln!("[!] 连接关闭 @ {:?}s", start.elapsed().as_secs()); break; }
            Ok(n) => {
                rbuf.extend_from_slice(&tmp[..n]);
                loop {
                    if rbuf.len() < 4 { break; }
                    let want = u32::from_le_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]) as usize;
                    if want > 16 * 1024 * 1024 { rbuf.clear(); break; }
                    if rbuf.len() < 4 + want { break; }
                    let body = &rbuf[4..4 + want];
                    let mut ph = mesh_tun_proto::PeerManagerHeader::decode(body);
                    let payload = body[mesh_tun_proto::PEER_MANAGER_HEADER_SIZE..].to_vec();
                    rbuf = rbuf[4 + want..].to_vec();

                    let decrypted = match mesh_tun_proto::decrypt_packet(&cipher, &mut ph, &payload) {
                        Ok(b) => b,
                        Err(_) => payload.clone(),
                    };

                    match ph.packet_type {
                        mesh_tun_proto::PacketType::RpcReq => {
                            rpc_in += 1;
                            eprintln!("[RPC REQ IN] @ {:?}s  hdr.from={} hdr.to={} flags=0x{:02x} len={} body_len={}",
                                start.elapsed().as_secs(), ph.from_peer_id, ph.to_peer_id, ph.flags, ph.len, payload.len());
                            let mut route_handled = false;
                            if let Some((tx_id, desc, peer_sid, peer_init)) =
                                mesh_tun_proto::peek_sync_route_request_inner(&decrypted)
                            {
                                if desc.service_name == "OspfRouteRpc" && desc.method_index == 1 {
                                    route_handled = true;
                                    if let Ok(Some(rt)) = mesh_tun_proto::try_parse_route_from_rpc(&decrypted) {
                                        let new_count = rt.peers.iter()
                                            .filter(|p| seen_peers.insert(p.peer_id)).count();
                                        eprintln!("[Route @ {:?}s] peers={} (新增 {})  peer_sid={} peer_init={}",
                                            start.elapsed().as_secs(), rt.peers.len(), new_count,
                                            peer_sid, peer_init);
                                        for p in &rt.peers {
                                            let ip_str = p.ipv4_addr
                                                .map(|u| std::net::Ipv4Addr::from(u).to_string())
                                                .unwrap_or_else(|| "(无IP)".to_string());
                                            eprintln!("    peer_id={:<12} ipv4={:<15} /{}  host={}",
                                                p.peer_id, ip_str, p.network_length,
                                                p.ipv4_str.as_deref().unwrap_or("-"));
                                        }
                                    }
                                    // 回送 SyncRouteInfoResponse — 先试明文（Relay 发来的 RpcReq 也是明文 flags=0x00）
                                    {
                                        use prost::Message as _;
                                        let my_is_initiator = !peer_init;
                                        let mut resp_body = Vec::new();
                                        mesh_tun_proto::proto::SyncRouteInfoResponse {
                                            is_initiator: my_is_initiator,
                                            session_id: my_ospf_sid,
                                            error: None,
                                        }.encode(&mut resp_body).unwrap();
                                        let mut rpc_resp = Vec::new();
                                        mesh_tun_proto::proto::RpcResponse {
                                            response: resp_body,
                                            error: None,
                                            runtime_us: 0,
                                        }.encode(&mut rpc_resp).unwrap();
                                        let compression_info = Some(mesh_tun_proto::proto::RpcCompressionInfo {
                                            algo: mesh_tun_proto::proto::CompressionAlgoPb::None as i32,
                                            accepted_algo: mesh_tun_proto::proto::CompressionAlgoPb::Zstd as i32,
                                        });
                                        let mut rpc_pkt = Vec::new();
                                        mesh_tun_proto::proto::RpcPacket {
                                            from_peer: my_id,
                                            to_peer: ph.from_peer_id,
                                            transaction_id: tx_id,
                                            descriptor: Some(desc.clone()),
                                            body: rpc_resp,
                                            is_request: false,
                                            total_pieces: 0,
                                            piece_idx: 0,
                                            trace_id: 0,
                                            compression_info,
                                        }.encode(&mut rpc_pkt).unwrap();
                                        // 明文 PeerManagerHeader（FLAG_ENCRYPTED=0），和 Relay 的 RpcReq 一致
                                        let pkt_len = rpc_pkt.len() as u32;
                                        let mut rh = mesh_tun_proto::PeerManagerHeader::new(
                                            my_id, ph.from_peer_id, mesh_tun_proto::PacketType::RpcResp, pkt_len);
                                        rh.flags &= !mesh_tun_proto::FLAG_ENCRYPTED; // 明文
                                        let total_frame = (mesh_tun_proto::PEER_MANAGER_HEADER_SIZE as u32) + pkt_len;
                                        let mut f = bytes::BytesMut::new();
                                        f.put_u32_le(total_frame);
                                        rh.encode(&mut f);
                                        f.extend_from_slice(&rpc_pkt);
                                        eprintln!("[RPC RESP PLAIN] @ {:?}s  from={} to={} tx={} flags=0x{:02x} pkt_len={} frame={}",
                                            start.elapsed().as_secs(),
                                            rh.from_peer_id, rh.to_peer_id, tx_id, rh.flags, pkt_len, f.len());
                                        match s.write_all(&f) {
                                            Ok(()) => { rpc_out += 1; eprintln!("[RPC RESP PLAIN] write OK"); }
                                            Err(e) => eprintln!("[RPC RESP PLAIN] write FAILED: {e}"),
                                        }
                                    }
                                }
                            }
                            if !route_handled {
                                if let Some((tx_id, desc, _is_req)) = mesh_tun_proto::decode_rpc_packet(&decrypted) {
                                    eprintln!("[Unhandled RpcReq @ {:?}s] svc={} method={} tx={}",
                                        start.elapsed().as_secs(), desc.service_name, desc.method_index, tx_id);
                                }
                            }
                        }
                        mesh_tun_proto::PacketType::RpcResp => {
                            rpc_in += 1;
                        }
                        mesh_tun_proto::PacketType::Ping => {
                            let mut ph2 = mesh_tun_proto::PeerManagerHeader::new(my_id, ph.from_peer_id, mesh_tun_proto::PacketType::Pong, 0);
                            let ct = mesh_tun_proto::encrypt_packet(&cipher, &mut ph2, &[]).unwrap_or_default();
                            let mut f = bytes::BytesMut::new();
                            f.put_u32_le((mesh_tun_proto::PEER_MANAGER_HEADER_SIZE as u32) + ct.len() as u32);
                            ph2.encode(&mut f);
                            f.extend_from_slice(&ct);
                            let _ = s.write_all(&f);
                        }
                        mesh_tun_proto::PacketType::Pong => {}
                        mesh_tun_proto::PacketType::Data => {
                            data_in += 1;
                            let src = if decrypted.len() >= 20 {
                                format!("{}.{}.{}.{}", decrypted[12], decrypted[13], decrypted[14], decrypted[15])
                            } else { "?".to_string() };
                            let dst = if decrypted.len() >= 20 {
                                format!("{}.{}.{}.{}", decrypted[16], decrypted[17], decrypted[18], decrypted[19])
                            } else { "?".to_string() };
                            let proto = decrypted.get(9).copied().unwrap_or(0);
                            eprintln!("[Data IN @ {:?}s] {}B  {} -> {}  proto={}",
                                start.elapsed().as_secs(), decrypted.len(), src, dst, proto);
                        }
                        _ => {}
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => { eprintln!("[!] read err: {}", e); break; }
        }
    }

    eprintln!("\n========== 统计 ==========");
    eprintln!("运行时长: {:?}", start.elapsed());
    eprintln!("发现的不同节点数: {} (含公共节点)", seen_peers.len());
    eprintln!("收到的 RPC 包: {}", rpc_in);
    eprintln!("发出的 RPC 包: {}", rpc_out);
    eprintln!("收到的 Data 包: {}", data_in);
    eprintln!("发出的 Data 包: {}", data_out);
    if !seen_peers.is_empty() {
        eprintln!("\n节点列表:");
        for p in &seen_peers {
            eprintln!("  - peer_id={}", p);
        }
    }
    Ok(())
}
