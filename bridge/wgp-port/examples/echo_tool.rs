//! 本机联调小工具：给端口转发做端到端验证用（不依赖任何外部程序）。
//!
//! 用法：
//!   echo_tool serve-tcp <端口>              在 127.0.0.1:<端口> 起 TCP 回显服务（扮演「房主的游戏服务器」）
//!   echo_tool serve-udp <端口>              在 127.0.0.1:<端口> 起 UDP 回显服务
//!   echo_tool check-tcp <ip:port> [字节数]   连接并收发指定字节数，逐字节校验回显（扮演「朋友的游戏客户端」）
//!   echo_tool check-udp <ip:port> [个数]     发指定个数的数据报并校验回显
//!
//! 典型流程（三个终端 + 一个种子）：
//!   wgp-node --bind 127.0.0.1:11010 --stun 3478 --tcp 3481
//!   echo_tool serve-tcp 25565
//!   wgp-client 开房 -n t -k k -p udp://127.0.0.1:11010 --observer 127.0.0.1:3478 -i a.key --expose 25565
//!   wgp-client join -n t -k k -p udp://127.0.0.1:11010 --observer 127.0.0.1:3478 -i b.key --forward 25566:25565
//!   echo_tool check-tcp 127.0.0.1:25566 4194304
//!
//! `check-*` 校验通过退出码 0，否则非 0。

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// 与位置相关的伪随机字节：错位、丢段、重复都会被比对发现
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

async fn serve_tcp(port: u16) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("绑定 TCP {port} 失败：{e}"))?;
    println!("TCP 回显服务已启动：127.0.0.1:{port}");
    loop {
        let (mut conn, from) = listener.accept().await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.set_nodelay(true);
            let (mut rd, mut wr) = conn.split();
            let copied = tokio::io::copy(&mut rd, &mut wr).await.unwrap_or(0);
            let _ = wr.shutdown().await;
            println!("连接 {from} 结束，回显 {copied} 字节");
        });
    }
}

async fn serve_udp(port: u16) -> Result<(), String> {
    let socket = UdpSocket::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("绑定 UDP {port} 失败：{e}"))?;
    println!("UDP 回显服务已启动：127.0.0.1:{port}");
    let mut buf = vec![0u8; 65_535];
    loop {
        // Windows 上对端端口不可达会以 recv 错误冒出：忽略后继续
        if let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    }
}

async fn check_tcp(addr: SocketAddr, total: usize) -> Result<(), String> {
    let conn = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| format!("连接 {addr} 超时"))?
        .map_err(|e| format!("连接 {addr} 失败：{e}"))?;
    let _ = conn.set_nodelay(true);
    let (mut rd, mut wr) = conn.into_split();
    let data = pattern(total, 0x5EED);
    let expect = data.clone();
    let started = Instant::now();

    // 先做一组小包往返（游戏流量的典型形态），统计单次往返延迟
    let mut worst = Duration::ZERO;
    for i in 0..50u8 {
        let msg = [i; 64];
        let t = Instant::now();
        wr.write_all(&msg).await.map_err(|e| format!("小包写失败：{e}"))?;
        let mut back = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(30), rd.read_exact(&mut back))
            .await
            .map_err(|_| "小包回显超时".to_string())?
            .map_err(|e| format!("小包读失败：{e}"))?;
        if back != msg {
            return Err(format!("第 {i} 个小包回显内容不一致"));
        }
        worst = worst.max(t.elapsed());
    }
    println!("小包往返 50 次全部一致，最慢一次 {worst:?}");

    // 再做大块数据：边写边读，写完关闭写方向，读到 EOF 为止（检验半关闭穿过隧道）
    let writer = tokio::spawn(async move {
        wr.write_all(&data).await?;
        wr.shutdown().await
    });
    let mut got = Vec::with_capacity(total);
    tokio::time::timeout(Duration::from_secs(300), rd.read_to_end(&mut got))
        .await
        .map_err(|_| format!("大块数据回显超时（已收 {} / {total}）", got.len()))?
        .map_err(|e| format!("读失败：{e}"))?;
    writer
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("写失败：{e}"))?;
    if got.len() != expect.len() {
        return Err(format!("回显长度不符：发 {} 收 {}", expect.len(), got.len()));
    }
    if let Some(pos) = got.iter().zip(&expect).position(|(a, b)| a != b) {
        return Err(format!("回显内容在偏移 {pos} 处不一致"));
    }
    let secs = started.elapsed().as_secs_f64();
    println!(
        "TCP 校验通过：{total} 字节往返逐字节一致，总耗时 {secs:.2}s（单向约 {:.2} MiB/s）",
        total as f64 / 1_048_576.0 / secs
    );
    Ok(())
}

async fn check_udp(addr: SocketAddr, count: usize) -> Result<(), String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    socket.connect(addr).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65_535];
    let mut resent = 0usize;
    // 含基岩版 RakNet 的 1200 MTU 探测包尺寸（载荷 1172B）
    for (i, len) in [1usize, 32, 500, 1172].into_iter().cycle().take(count).enumerate() {
        let msg = pattern(len, 0xD06 + i as u64);
        let mut echoed = false;
        for attempt in 0..10 {
            socket.send(&msg).await.map_err(|e| e.to_string())?;
            match tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await {
                Ok(Ok(n)) if buf[..n] == msg[..] => {
                    echoed = true;
                    resent += attempt;
                    break;
                }
                Ok(Ok(_)) => return Err(format!("第 {i} 个数据报回显内容不一致")),
                _ => continue,
            }
        }
        if !echoed {
            return Err(format!("第 {i} 个数据报（{len}B）始终没有回显"));
        }
    }
    println!("UDP 校验通过：{count} 个数据报回显一致（重发 {resent} 次）");
    Ok(())
}

fn usage() -> String {
    "用法：echo_tool <serve-tcp|serve-udp> <端口> | <check-tcp|check-udp> <ip:port> [数量]".to_string()
}

async fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().ok_or_else(usage)?;
    let target = args.get(1).ok_or_else(usage)?;
    match cmd.as_str() {
        "serve-tcp" | "serve-udp" => {
            let port: u16 = target.parse().map_err(|_| format!("端口非法：{target}"))?;
            if cmd == "serve-tcp" {
                serve_tcp(port).await
            } else {
                serve_udp(port).await
            }
        }
        "check-tcp" | "check-udp" => {
            let addr: SocketAddr = target
                .parse()
                .map_err(|_| format!("地址非法（应为 ip:port）：{target}"))?;
            let default = if cmd == "check-tcp" { 1_048_576 } else { 40 };
            let amount: usize = match args.get(2) {
                Some(s) => s.parse().map_err(|_| format!("数量非法：{s}"))?,
                None => default,
            };
            if cmd == "check-tcp" {
                check_tcp(addr, amount).await
            } else {
                check_udp(addr, amount).await
            }
        }
        _ => Err(usage()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("失败：{msg}");
            ExitCode::FAILURE
        }
    }
}
