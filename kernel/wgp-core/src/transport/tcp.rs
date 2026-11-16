//! TCP 探针载体：同端口「监听 + 主动连接」打洞（T1-T4 兜底路径）。
//!
//! 语义（00 §4 / 03 §5.5 TCP 探测）：
//!  - 本地绑定固定源端口（TCP 打洞要求双方源端口可预测）
//!  - 向对端预测端口发起 connect；双方同时打开时 SYN 交叉 → 连接建立（simultaneous open）
//!  - 同一个端口上同时开着监听：SYN 没有交叉、或对端的实际源端口与预测不符时，
//!    对端打进来的连接由监听口接受——否则本机协议栈会回 RST，对端立刻失败
//!    （Windows 收到 RST 会自行重发 SYN，掩盖了这个问题；Linux 不会）
//!  - 连接建立后互验 31B 验签探针（复用 UDP 帧格式，流上定长读取）：
//!    主动方先发后收；被动方先验后发——没通过验签的入站连接得不到我们的任何数据

use super::probe::{craft_probe, now_ms, verify_probe};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

/// 单端口 TCP 打洞尝试超时（SYN 交叉窗口；retry 后总时长 < 800ms 波窗口）
pub const TCP_PORT_PUNCH_TIMEOUT_MS: u64 = 250;

/// 降级档 TCP keepalive 的空闲探测起始时间（秒）
pub const TCP_KEEPALIVE_IDLE_S: u64 = 30;

/// 单端口重试次数（SYN 错位在真实 NAT 与 loopback 均会发生；03 §3.5.6 重试语义）
const PUNCH_RETRIES: u32 = 2;
const PUNCH_RETRY_GAP_MS: u64 = 80;

/// 一次 `punch_port` 的总时限：主动连接提前用完重试次数后，余下的时间继续等入站连接
const PUNCH_WINDOW_MS: u64 =
    (TCP_PORT_PUNCH_TIMEOUT_MS + PUNCH_RETRY_GAP_MS) * (PUNCH_RETRIES as u64 + 1);

/// 监听口同时在验签的入站连接上限（超出的直接丢弃：打洞端口不为陌生人排队）
const INBOUND_VERIFY_MAX: usize = 8;
/// 监听队列长度
const LISTEN_BACKLOG: u32 = 16;

/// TCP 载体（Arc 内聚：多端口并行 spawn 可 Clone）
#[derive(Clone)]
pub struct TcpProbeCarrier {
    inner: Arc<TcpInner>,
}

struct TcpInner {
    /// 本地固定绑定地址（打洞源端口）
    bind_addr: SocketAddr,
    probe_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: Arc<AtomicU32>,
    inbound: Arc<Inbound>,
    acceptor: Mutex<Acceptor>,
}

/// 同端口监听的状态：首次打洞时启动，载体销毁时终止（监听口随之关闭）
enum Acceptor {
    NotStarted,
    Running(JoinHandle<()>),
    /// 监听口起不来（端口被不共用的 socket 占着等）：退回只靠主动连接
    Unavailable,
}

/// 监听口收到且验签通过的入站流：只留最先到的一条，等某个 `punch_port` 取走
struct Inbound {
    slot: Mutex<Option<TcpStream>>,
    ready: Notify,
}

impl Inbound {
    fn offer(&self, stream: TcpStream) {
        let mut slot = lock(&self.slot);
        if slot.is_none() {
            *slot = Some(stream);
            drop(slot);
            self.ready.notify_one();
        }
    }

    fn take(&self) -> Option<TcpStream> {
        lock(&self.slot).take()
    }

    /// 等到一条验签通过的入站流
    async fn wait(&self) -> TcpStream {
        loop {
            if let Some(stream) = self.take() {
                return stream;
            }
            // notify_one 会为「还没人等」的情况存一个许可，这里不会错过 offer
            self.ready.notified().await;
        }
    }
}

impl Drop for TcpInner {
    fn drop(&mut self) {
        if let Acceptor::Running(task) = &*lock(&self.acceptor) {
            task.abort();
        }
    }
}

/// 生产路径零 panic：锁中毒时照常取出数据（这里的临界区都不会让数据处于半更新状态）
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 建一个绑在 `bind` 上、允许同端口共用的 socket。
/// 监听口与各个主动连接的 socket 都绑同一个端口（靠四元组区分），所以两边都要开共用。
fn shared_port_socket(bind: SocketAddr) -> Option<TcpSocket> {
    let socket = if bind.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .ok()?;
    socket.set_reuseaddr(true).ok()?;
    // Unix 上已有监听口时，光有 SO_REUSEADDR 绑不了同一个端口，还需要 SO_REUSEPORT
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    socket.set_reuseport(true).ok()?;
    socket.bind(bind).ok()?;
    Some(socket)
}

/// 交付前的流设置
fn tune(stream: &TcpStream) {
    stream.set_nodelay(true).ok(); // 02 §2.2：立即禁用 Nagle
    // 降级档保活由 TCP keepalive 承担（14 §12）：必须显式开启——系统默认关闭，
    // 空闲流在 NAT 上的映射到期后会被静默丢弃，外围却无从得知。
    let keepalive =
        socket2::TcpKeepalive::new().with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_S));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// 读对端探针并验签（超时即视为未通过）
async fn read_peer_probe(stream: &mut TcpStream, probe_key: &[u8; 32]) -> Option<()> {
    let mut buf = [0u8; 31];
    tokio::time::timeout(
        Duration::from_millis(TCP_PORT_PUNCH_TIMEOUT_MS),
        stream.read_exact(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    verify_probe(probe_key, &buf)?;
    Some(())
}

/// 监听循环：接受入站连接 → 先验对端探针 → 通过后才回我方探针 → 交给等待中的 `punch_port`
async fn accept_loop(
    listener: TcpListener,
    probe_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: Arc<AtomicU32>,
    inbound: Arc<Inbound>,
) {
    let verifying = Arc::new(Semaphore::new(INBOUND_VERIFY_MAX));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            // 瞬时错误（描述符用尽等）：稍等再试，监听不因此退出
            tokio::time::sleep(Duration::from_millis(PUNCH_RETRY_GAP_MS)).await;
            continue;
        };
        let Ok(permit) = verifying.clone().try_acquire_owned() else {
            continue;
        };
        let (nonce_seed, inbound) = (nonce_seed.clone(), inbound.clone());
        tokio::spawn(async move {
            let _permit = permit;
            tune(&stream);
            if read_peer_probe(&mut stream, &probe_key).await.is_none() {
                return;
            }
            let nonce = nonce_seed.fetch_add(1, Ordering::Relaxed) + 1;
            let probe = craft_probe(&probe_key, session_tag, nonce, now_ms());
            if stream.write_all(&probe).await.is_ok() {
                inbound.offer(stream);
            }
        });
    }
}

impl TcpProbeCarrier {
    pub fn new(bind_addr: SocketAddr, probe_key: [u8; 32], session_tag: [u8; 4]) -> Self {
        Self {
            inner: Arc::new(TcpInner {
                bind_addr,
                probe_key,
                session_tag,
                nonce_seed: Arc::new(AtomicU32::new(0)),
                inbound: Arc::new(Inbound {
                    slot: Mutex::new(None),
                    ready: Notify::new(),
                }),
                acceptor: Mutex::new(Acceptor::NotStarted),
            }),
        }
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.inner.bind_addr
    }

    fn next_nonce(&self) -> u32 {
        self.inner.nonce_seed.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 首次打洞时在源端口上开监听（需在 tokio 运行时内调用）
    fn ensure_acceptor(&self) {
        let mut state = lock(&self.inner.acceptor);
        if !matches!(*state, Acceptor::NotStarted) {
            return;
        }
        let listener = shared_port_socket(self.inner.bind_addr)
            .and_then(|socket| socket.listen(LISTEN_BACKLOG).ok());
        *state = match listener {
            Some(listener) => Acceptor::Running(tokio::spawn(accept_loop(
                listener,
                self.inner.probe_key,
                self.inner.session_tag,
                self.inner.nonce_seed.clone(),
                self.inner.inbound.clone(),
            ))),
            None => Acceptor::Unavailable,
        };
    }

    /// 单端口打洞：主动连接（内置重试抗 SYN 错位）与同端口监听并行，先通先用。
    /// 成功返回已验证的流（对端探针 HMAC 通过）；流的对端地址以 `peer_addr()` 为准——
    /// 经监听口进来的连接，对端端口不一定是 `peer` 里预测的那个。
    pub async fn punch_port(&self, peer: SocketAddr) -> Option<TcpStream> {
        self.ensure_acceptor();
        let connect = async {
            for _ in 0..=PUNCH_RETRIES {
                if let Some(stream) = self.try_punch_once(peer).await {
                    return stream;
                }
                tokio::time::sleep(Duration::from_millis(PUNCH_RETRY_GAP_MS)).await;
            }
            // 主动连接用完了重试次数（被 RST 拒绝时很快）：余下的时间只等入站连接
            std::future::pending().await
        };
        let first = async {
            tokio::select! {
                biased;
                stream = self.inner.inbound.wait() => stream,
                stream = connect => stream,
            }
        };
        tokio::time::timeout(Duration::from_millis(PUNCH_WINDOW_MS), first)
            .await
            .ok()
    }

    async fn try_punch_once(&self, peer: SocketAddr) -> Option<TcpStream> {
        // ① 固定源端口发起连接（交叉即建立；不交叉则由对端的监听口接受）
        let socket = shared_port_socket(self.inner.bind_addr)?;
        let mut stream = tokio::time::timeout(
            Duration::from_millis(TCP_PORT_PUNCH_TIMEOUT_MS),
            socket.connect(peer),
        )
        .await
        .ok()?
        .ok()?;
        tune(&stream);

        // ② 先发我方探针，③ 再读对端探针并验签
        let probe = craft_probe(
            &self.inner.probe_key,
            self.inner.session_tag,
            self.next_nonce(),
            now_ms(),
        );
        stream.write_all(&probe).await.ok()?;
        read_peer_probe(&mut stream, &self.inner.probe_key).await?;
        Some(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::test_ports::unique_loopback_addr;

    #[tokio::test]
    async fn simultaneous_open_both_sides_verified() {
        let key = [0x77u8; 32];
        let a_addr = unique_loopback_addr();
        let b_addr = unique_loopback_addr();

        let a = TcpProbeCarrier::new(a_addr, key, [1, 2, 3, 4]);
        let b = TcpProbeCarrier::new(b_addr, key, [5, 6, 7, 8]);

        // 双方同时打开（SYN 交叉；loopback 下等价于真实 NAT 的 simultaneous open）
        let (a2, b2) = (a.clone(), b.clone());
        let (ra, rb) = tokio::join!(a2.punch_port(b_addr), b2.punch_port(a_addr));
        let ra = ra.expect("A 侧应建立连接并完成探针互验");
        let rb = rb.expect("B 侧应建立连接并完成探针互验");
        // 两侧拿到的是同一条连接的两端
        assert_eq!(ra.peer_addr().unwrap(), b_addr);
        assert_eq!(rb.peer_addr().unwrap(), a_addr);
        assert_eq!(ra.local_addr().unwrap(), a_addr);
    }

    #[tokio::test]
    async fn mismatched_keys_reject_each_other() {
        let a_addr = unique_loopback_addr();
        let b_addr = unique_loopback_addr();

        // 密钥不同 = 未完成承诺-揭示的"陌生人"：连接可能建立但探针必须互拒
        let a = TcpProbeCarrier::new(a_addr, [0x11u8; 32], [1, 1, 1, 1]);
        let b = TcpProbeCarrier::new(b_addr, [0x22u8; 32], [2, 2, 2, 2]);

        let (a2, b2) = (a.clone(), b.clone());
        let (ra, rb) = tokio::join!(a2.punch_port(b_addr), b2.punch_port(a_addr));
        assert!(ra.is_none(), "错密钥探针必须被拒");
        assert!(rb.is_none(), "错密钥探针必须被拒");
    }

    /// SYN 没有交叉、对端也没有瞄准我们的端口：对端打进来的连接由监听口接受。
    /// （对应真实场景：对端的源端口与我方预测不符，但我方 NAT 放行了它的 SYN。）
    #[tokio::test]
    async fn inbound_connection_is_accepted_when_syns_do_not_cross() {
        let key = [0x55u8; 32];
        let a_addr = unique_loopback_addr();
        let b_addr = unique_loopback_addr();
        let nowhere = unique_loopback_addr();

        let a = TcpProbeCarrier::new(a_addr, key, [1, 2, 3, 4]);
        let b = TcpProbeCarrier::new(b_addr, key, [5, 6, 7, 8]);

        // B 先开始，瞄的是一个没人的端口：它自己的主动连接不可能成功
        let b_task = {
            let b = b.clone();
            tokio::spawn(async move { b.punch_port(nowhere).await })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        // A 后到，连 B 的真实端口：此时不存在 SYN 交叉
        let ra = a.punch_port(b_addr).await.expect("A 的连接应被 B 的监听口接受");
        let rb = b_task
            .await
            .unwrap()
            .expect("B 应从监听口拿到 A 打进来的连接");
        assert_eq!(ra.peer_addr().unwrap(), b_addr);
        assert_eq!(rb.peer_addr().unwrap(), a_addr, "流的对端以实际连接为准");
    }

    /// 一波里的多个端口并行尝试，共用同一个本地源端口：不能因为「端口已被自己占用」而互相挤掉。
    #[tokio::test]
    async fn parallel_ports_share_the_local_port() {
        let key = [0x66u8; 32];
        let a_addr = unique_loopback_addr();
        let b_addr = unique_loopback_addr();
        let mut targets = Vec::new();
        for _ in 0..4 {
            targets.push(unique_loopback_addr()); // 没人的端口
        }
        targets.push(b_addr); // 对端真正的端口排在最后

        let a = TcpProbeCarrier::new(a_addr, key, [1, 2, 3, 4]);
        let b = TcpProbeCarrier::new(b_addr, key, [5, 6, 7, 8]);
        let b_task = {
            let b = b.clone();
            tokio::spawn(async move { b.punch_port(a_addr).await })
        };

        let mut attempts = tokio::task::JoinSet::new();
        for target in targets {
            let a = a.clone();
            attempts.spawn(async move { a.punch_port(target).await });
        }
        let mut hit = None;
        while let Some(done) = attempts.join_next().await {
            if let Some(stream) = done.unwrap() {
                hit = Some(stream);
                break;
            }
        }
        let hit = hit.expect("并行尝试里应有一路打通");
        assert_eq!(hit.peer_addr().unwrap(), b_addr);
        assert!(b_task.await.unwrap().is_some(), "B 侧同样应拿到已验证的流");
    }

    /// 陌生连接（不发探针 / 发错探针）得不到我方的任何字节，也不妨碍随后到来的真对端。
    #[tokio::test]
    async fn strangers_get_nothing_and_do_not_block_the_real_peer() {
        let key = [0x44u8; 32];
        let a_addr = unique_loopback_addr();
        let b_addr = unique_loopback_addr();
        let nowhere = unique_loopback_addr();

        let a = TcpProbeCarrier::new(a_addr, key, [1, 2, 3, 4]);
        let a_task = {
            let a = a.clone();
            tokio::spawn(async move { a.punch_port(nowhere).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 陌生人：连上后发 31 字节垃圾
        let mut stranger = TcpStream::connect(a_addr).await.expect("监听口应已就绪");
        stranger.write_all(&[0xEEu8; 31]).await.unwrap();
        let mut got = Vec::new();
        let read = tokio::time::timeout(
            Duration::from_millis(TCP_PORT_PUNCH_TIMEOUT_MS * 2),
            stranger.read_to_end(&mut got),
        )
        .await;
        assert!(read.is_ok(), "验签不过的连接应被关闭");
        assert!(got.is_empty(), "验签不过的连接不应收到我方探针");

        // 真对端随后到来，照常打通
        let b = TcpProbeCarrier::new(b_addr, key, [5, 6, 7, 8]);
        let rb = b.punch_port(a_addr).await.expect("真对端应打通");
        let ra = a_task.await.unwrap().expect("A 应拿到真对端的流");
        assert_eq!(ra.peer_addr().unwrap(), b_addr);
        assert_eq!(rb.peer_addr().unwrap(), a_addr);
    }
}
