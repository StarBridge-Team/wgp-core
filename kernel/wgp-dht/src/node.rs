//! Kademlia 网络栈（07 文档自研 DHT 的运行时）。
//!
//! 学习语义：**只有验过身份证明的路径能写路由表与地址簿**（17 §11）。一次一密挑战响应
//! （`AUTH_CHALLENGE` / `AUTH_PROOF`）取代了「PING/PONG 顺带学习」——旧路径仍应答（存活与兼容），
//! 但不再产生任何学习：否则录下一条旧报文在别的地址上重放，就能把已知节点指向攻击者。
//! Forward 不做身份学习（防垃圾投递毒化地址簿），fire-and-forget 邮件语义，
//! 上层信令自持超时重发（sig::Commit REQUIRE_ACK / 3s 超时）。
//!
//! 种子发现（07 §5 第③层 / 17 P0）：公网节点把自己的签名广告周期推给已知种子；任何节点都可以
//! 向别人索取它已知的种子广告（FIND_SEEDS）。一条广告要进种子目录，必须验签通过，并且广告主
//! 确实在所报地址上**证明持有该身份私钥**（挑战响应）。P0 不做信任评分：目录里的种子只代表
//! 「存在且持有该身份」，不代表可信。

use crate::addr::EndpointScope;
use crate::advertise::{sign_advertise_v2, verify_advertise_v2, AdvertiseSpec};
use crate::auth::{self, bound_identity};
use crate::directory::{advert_addr, RawAdvert, SeedDirectory, SeedInfo, Verdict};
use crate::id::{NodeId, NodeIdentity};
use crate::kbucket::RoutingTable;
use crate::ratelimit::{ByteBudget, ByteBudgetPolicy, RateGate, RatePolicy};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Semaphore};
use tokio::task::JoinSet;
use wgp_proto::consts::{AUTH_NONCE_LEN, AUTH_VERSION};
use wgp_proto::dht::{
    AuthChallengeBody, AuthProofBody, FindNodeBody, FindSeedsBody, FindValueBody, ForwardBody,
    NeighborsBody, NodeEntry, PingBody, RpcBody, RpcPacket, SeedsBody, StoreBody, ValueBody, SEEDS_MAX,
};
use wgp_proto::packet::{classify, seed_advertise_v2, SeedAdvertiseV2};

/// RPC 超时/失败
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    Timeout,
    NoRoute,
    PayloadTooLarge,
    /// 对端不支持身份证明（严格模式下不采信：既有的 PING/PONG 只证明「有人自称」，不证明持钥）
    Unverified,
    /// 对端明确拒绝：身份证明协议版本不受支持
    UnsupportedVersion,
    /// 本地待应答挑战表已满（调用方退避重试，不要无限 spawn）
    Busy,
}

impl RpcError {
    /// 给用户看的一句话（客户端/服务端日志、命令行报错共用）
    pub fn explain(&self) -> &'static str {
        match self {
            RpcError::Timeout => "对端无应答（超时）",
            RpcError::NoRoute => "没有可用路由（发送失败）",
            RpcError::PayloadTooLarge => "载荷超过单帧上限",
            RpcError::Unverified => {
                "对端不支持身份证明（旧版本）：严格模式不采信；需要兼容请显式启用旧协议兼容"
            }
            RpcError::UnsupportedVersion => "对端只支持另一个身份证明协议版本",
            RpcError::Busy => "本地待应答挑战已满，稍后重试",
        }
    }
}

/// 信令承载方式（UDP 被封时的兜底）。
///
/// 两种承载共用同一套 RPC 报文与长度前缀帧格式：TCP 只是把「一次请求一次应答」换成一条短连接，
/// 包体语义完全一致。注意：**打洞与数据面仍然需要 UDP**，TCP 只能承担信令
/// （入表、选点、房间读写、报道中转）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn scheme(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Transport::Udp => 0,
            Transport::Tcp => 1,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Transport::Tcp,
            _ => Transport::Udp,
        }
    }
}

/// 身份证明策略（17 §11.6）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPolicy {
    /// 只采信挑战响应；旧 PING/PONG 只用于存活与诊断，不产生学习（默认）
    Strict,
    /// 迁移期兼容：握手超时后回退到旧 PING/PONG 并学习（与旧行为等价，可观测计数会 +1）
    LegacyAllowed,
}

impl IdentityPolicy {
    fn as_u8(self) -> u8 {
        match self {
            IdentityPolicy::Strict => 0,
            IdentityPolicy::LegacyAllowed => 1,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => IdentityPolicy::LegacyAllowed,
            _ => IdentityPolicy::Strict,
        }
    }
}

/// PONG 应答信息（ping 的返回值：对方身份 + 返回地址）
#[derive(Debug, Clone, Copy)]
pub struct PongInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
}

/// 单帧上限（DHT 包最大 ~1080B：STORE_VALUE_MAX 1024 + 头部开销）
const MAX_TCP_FRAME: usize = 4096;
/// TCP 信令并发连接上限（家庭带宽/公网单机都能扛；超限直接拒连）
const MAX_TCP_CONN: usize = 512;
/// TCP 连接空闲超时（防慢连接长期占用名额）
const TCP_IDLE_TIMEOUT_S: u64 = 30;
/// TCP RPC 单次往返超时（与 UDP RPC 一致）
const TCP_RPC_TIMEOUT_MS: u64 = 1500;
/// UDP 读缓冲上限（RPC 最大 ~1130B：StoreBody 前缀 98 + 值 1024 + 头 7）
const MAX_UDP_DATAGRAM: usize = 2048;

// —— 探活身份证明（17 §11） ——
/// UDP RPC 单次往返超时（挑战响应也用它）
const RPC_TIMEOUT_MS: u64 = 1500;
/// 严格模式下握手超时后，用旧 PING 判定「对端是老版本」而不是「不可达」的等待时间
const LEGACY_DIAGNOSTIC_TIMEOUT_MS: u64 = 800;
/// 发起方同时等待应答的挑战数上限（满则返回 Busy，由调用方退避）
const MAX_PENDING_AUTH: usize = 64;
/// 应答方记住的「已发出回证挑战」上限与寿命（一次性，用完即删）
const MAX_ISSUED: usize = 512;
const ISSUED_TTL: Duration = Duration::from_secs(30);
/// 入站挑战应答配额：全局每秒条数 / 单源 IP 每秒条数 / 参与限速的 IP 表上限
const AUTH_REPLIES_PER_SEC: u32 = 128;
const AUTH_REPLIES_PER_IP_PER_SEC: u32 = 16;
const AUTH_GATE_IPS_MAX: usize = 1024;
/// 地址簿条目上限（防伪造身份洪流撑爆内存；超限触发过期清扫）
const ADDR_BOOK_MAX: usize = 4096;
/// 地址簿条目静默过期（远超正常重 PING 周期；被清者下次 PING 即复原）
const ADDR_BOOK_TTL: Duration = Duration::from_secs(1800);
/// KV 存储条目上限（房间记录宿主；超限先清最旧腾位）
const KV_MAX_ENTRIES: usize = 4096;
/// KV 条目写入时间戳（用于 TTL 清扫与最旧淘汰）
type KvEntry = (Vec<u8>, Instant);

// —— 种子发现（17 P0） ——
/// 存活复验的并发上限（每条新广告触发一次 PING；超出即丢弃，等广告主下一轮重发）
const VERIFY_CONCURRENCY: usize = 8;
/// 主动推送来的广告每秒最多验签多少条（挡住用广告洪流消耗 CPU；超出静默丢弃）
const ADVERT_VERIFY_PER_SEC: u32 = 64;
/// 用户配置的入口端点数上限
const PINNED_MAX: usize = 16;
/// 维护节拍：探活已知种子（也是本端到种子的 NAT 映射保活周期）
const MAINTAIN_TICK: Duration = Duration::from_secs(20);
/// 每多少拍推送一次自己的广告（60s）
const ADVERTISE_EVERY_TICKS: u32 = 3;
/// 每多少拍向已知种子重新索取一次目录（5min），学到后来加入的节点
const PULL_EVERY_TICKS: u32 = 15;
/// 普通路由节点每 5 个维护拍做一轮有限探活
const ROUTE_PROBE_EVERY_TICKS: u32 = 1;
/// 单次最多探活的普通路由节点数，避免大桶表上的突发流量
const ROUTE_PROBE_BATCH: usize = 8;
/// 普通路由节点连续探活失败次数，超过后释放桶位
pub(crate) const ROUTE_FAILURE_LIMIT: u8 = 3;
/// 一次引导 / 补全最多向多少个节点索取种子广告
const DISCOVER_MAX_ASKS: usize = 8;
/// 迭代节点查找：每轮并发数 / 最多轮数 / 最多接触的节点数
const LOOKUP_ALPHA: usize = 3;
const LOOKUP_MAX_ROUNDS: usize = 4;
const LOOKUP_MAX_CONTACTS: usize = 12;

/// 应答投递出口：UDP 回源地址 / TCP 连接的写端。
///
/// 关键：TCP 连接携带的源 IP:port 与 UDP NAT 映射**无关**（TCP 源端口 ≠ UDP 源端口），
/// 若把 TCP 源地址写进地址簿，会把 Forward 中转指向错误的 UDP 端口。
/// 因此 TCP 入站只入路由表（身份存在性），绝不写地址簿。
#[derive(Clone)]
enum Sink {
    Udp(SocketAddr),
    Tcp(mpsc::UnboundedSender<Vec<u8>>),
}

impl Sink {
    fn udp_addr(&self) -> Option<SocketAddr> {
        match self {
            Sink::Udp(a) => Some(*a),
            Sink::Tcp(_) => None,
        }
    }
}

enum Pending {
    /// 等我方挑战的应答（发起方）：目标地址 + 本次一次性 nonce
    Auth {
        addr: SocketAddr,
        nonce: [u8; AUTH_NONCE_LEN],
        tx: oneshot::Sender<Result<PongInfo, RpcError>>,
    },
    /// 旧协议 PING 等 PONG。`learn` 只有在兼容模式/诊断路径才会是 true——
    /// 严格模式下不存在能学习的 Pong 等待项（保证「验证前不写表」）
    Pong {
        addr: SocketAddr,
        learn: bool,
        tx: oneshot::Sender<PongInfo>,
    },
    Neighbors(oneshot::Sender<Vec<NodeEntry>>),
    Value(oneshot::Sender<ValueBody>),
    StoreAck(oneshot::Sender<()>),
    Seeds(oneshot::Sender<Vec<RawAdvert>>),
}

/// 入站挑战应答的固定窗口限速（全局 + 单源 IP）。
///
/// 不设限的话，`AUTH_CHALLENGE`(88B) → `AUTH_PROOF`(168B) 就是约 1.9 倍的放大器和一次 ed25519 签名的
/// CPU 消耗入口。超限**静默丢弃**：回一个 `AUTH_REJECT` 反而替攻击者放大了流量。
struct AuthGate {
    window: Instant,
    total: u32,
    per_ip: HashMap<IpAddr, (Instant, u32)>,
}

impl AuthGate {
    fn new() -> Self {
        Self {
            window: Instant::now(),
            total: 0,
            per_ip: HashMap::new(),
        }
    }

    fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.total = 0;
        }
        if self.total >= AUTH_REPLIES_PER_SEC {
            return false;
        }
        let new_window = match self.per_ip.get(&ip) {
            Some((start, _)) => now.duration_since(*start) >= Duration::from_secs(1),
            None => true,
        };
        if new_window {
            if !self.per_ip.contains_key(&ip) && self.per_ip.len() >= AUTH_GATE_IPS_MAX {
                // 先清扫过期项；仍然满就拒绝新 IP（不让内存被伪造源地址撑大）
                self.per_ip
                    .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(1));
                if self.per_ip.len() >= AUTH_GATE_IPS_MAX {
                    return false;
                }
            }
            self.per_ip.insert(ip, (now, 0));
        }
        let count = &mut self.per_ip.get_mut(&ip).expect("刚插入或已存在").1;
        if *count >= AUTH_REPLIES_PER_IP_PER_SEC {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}

/// 中继策略（07 §6 贡献模式：家庭带宽节点拒绝 Forward 中转——
/// 中转是唯一可能产生持续流量进而被运营商判 PCDN 的路径）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicy {
    /// 完整节点：允许中转
    Allow,
    /// 贡献模式：只收发自己的消息，不做中转
    Deny,
}

/// DHT 节点：路由表 + 地址簿 + KV 存储 + RPC 收发（bind 即启动读循环）
pub struct DhtNode {
    socket: Arc<UdpSocket>,
    identity: Arc<NodeIdentity>,
    routing: Mutex<RoutingTable>,
    /// 已知 UDP 端点（带最后见时刻；容量上限 + 过期清扫，防伪造洪流撑爆）
    addr_book: Mutex<HashMap<NodeId, (SocketAddr, Instant)>>,
    /// KV 存储（带写入时刻；条目数上限 + 最旧淘汰，防无界内存增长）
    kv: Mutex<HashMap<[u8; 32], KvEntry>>,
    txid: AtomicU32,
    pending: Mutex<HashMap<u32, Pending>>,
    /// 会话分派表：payload 首 4B session_tag → 会话处理队列
    /// （装配线协商消息按 tag 分流；tag=0 / 未注册 → 默认队列，房间管理用）
    sessions: Mutex<HashMap<u32, mpsc::UnboundedSender<ForwardBody>>>,
    /// 默认收件队列（有界：forward 洪流在队满时静默丢弃，符合邮件语义）
    inbox_tx: mpsc::Sender<ForwardBody>,
    inbox_rx: Mutex<mpsc::Receiver<ForwardBody>>,
    /// 中继开关（默认 Allow；贡献模式置 Deny）
    relay_allow: AtomicBool,
    /// 种子目录（17 P0：验签 + 存活复验后入表）
    seeds: Mutex<SeedDirectory>,
    /// 目录变更通知（值 = 变更代数）
    seeds_gen: watch::Sender<u64>,
    /// 正在做存活复验的广告主（去重：同一广告主同时只探一次）
    verifying: Mutex<HashSet<NodeId>>,
    verify_slots: Arc<Semaphore>,
    /// 推送广告的验签限速（窗口起点, 窗口内已验条数）
    advert_gate: Mutex<(Instant, u32)>,
    /// 用户显式配置的入口端点（--seed / --peers）
    pinned: Mutex<HashSet<SocketAddr>>,
    /// 本节点的广告原文（None = 不宣告：NAT 后的客户端）
    own_advert: Mutex<Option<RawAdvert>>,
    /// 维护循环是否已启动
    maintaining: AtomicBool,
    /// 普通路由节点连续探活失败次数
    route_failures: Mutex<HashMap<NodeId, u8>>,
    /// 普通路由探活轮转游标
    route_probe_cursor: Mutex<usize>,
    /// 已发出的回证挑战（应答方）：prover_nonce → (来源地址, 发出时刻)
    issued: Mutex<HashMap<[u8; AUTH_NONCE_LEN], (SocketAddr, Instant)>>,
    /// 入站挑战应答的限速状态
    auth_gate: Mutex<AuthGate>,
    /// DHT socket 上直接应答 STUN 时的限速闸门（审计 M6：与观察者共用一套机制）。
    /// 同一个 socket 既收 DHT RPC 又当观察者用，不设闸门就是一条无成本的上行放大面。
    stun_gate: Mutex<RateGate>,
    /// 放大应答（NEIGHBORS / VALUE / SEEDS）的字节预算（审计 M3 的缓解部分）
    response_budget: Mutex<ByteBudget>,
    /// 端点地址准入策略（审计 M2）：默认只收公网地址
    endpoint_scope: AtomicU8,
    /// 是否识别前置代理注入的 PROXY protocol v2（默认关闭；见 proxy_protocol 模块文档）
    proxy_protocol: AtomicBool,
    /// 身份证明策略（严格 / 兼容旧 PING-PONG）
    identity_policy: AtomicU8,
    /// 对外信令的承载方式（UDP / TCP 兜底）。切换后所有出站 RPC 都按它分派，
    /// 调用方传入的地址必须是该承载的端点（TCP 模式下是 TCP 信令端口）。
    signaling: AtomicU8,
    /// 退回旧协议学习的次数（严格模式恒为 0；可观测性）
    legacy_fallbacks: AtomicU64,
    /// 被拒绝的入站证明数（伪造/重放/来源不符/版本不符，诊断用）
    rejected_proofs: AtomicU64,
    /// 让 UDP 接收任务随节点释放，不在外部 Arc 消失后泄漏 socket 和 task
    shutdown_tx: watch::Sender<bool>,
}

/// 默认收件队列容量
const INBOX_CAP: usize = 512;

impl DhtNode {
    pub async fn bind(identity: NodeIdentity, local: SocketAddr) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(local).await?);
        let identity = Arc::new(identity);
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX_CAP);
        // 端点准入的初始策略取自实际绑定地址：绑回环/私网就是本机或局域网节点
        let scope = EndpointScope::from_local_bind(socket.local_addr()?);

        let node = Arc::new(Self {
            socket: socket.clone(),
            routing: Mutex::new(RoutingTable::new(identity.node_id())),
            identity: identity.clone(),
            addr_book: Mutex::new(HashMap::new()),
            kv: Mutex::new(HashMap::new()),
            txid: AtomicU32::new(0),
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            inbox_tx,
            inbox_rx: Mutex::new(inbox_rx),
            relay_allow: AtomicBool::new(true),
            seeds: Mutex::new(SeedDirectory::new()),
            seeds_gen: watch::channel(0u64).0,
            verifying: Mutex::new(HashSet::new()),
            verify_slots: Arc::new(Semaphore::new(VERIFY_CONCURRENCY)),
            advert_gate: Mutex::new((Instant::now(), 0)),
            pinned: Mutex::new(HashSet::new()),
            own_advert: Mutex::new(None),
            maintaining: AtomicBool::new(false),
            route_failures: Mutex::new(HashMap::new()),
            route_probe_cursor: Mutex::new(0),
            issued: Mutex::new(HashMap::new()),
            auth_gate: Mutex::new(AuthGate::new()),
            stun_gate: Mutex::new(RateGate::new(RatePolicy::default())),
            response_budget: Mutex::new(ByteBudget::new(ByteBudgetPolicy::default())),
            endpoint_scope: AtomicU8::new(scope.as_u8()),
            proxy_protocol: AtomicBool::new(false),
            identity_policy: AtomicU8::new(IdentityPolicy::Strict.as_u8()),
            signaling: AtomicU8::new(Transport::Udp.as_u8()),
            legacy_fallbacks: AtomicU64::new(0),
            rejected_proofs: AtomicU64::new(0),
            shutdown_tx: watch::channel(false).0,
        });

        // 读循环只持 Weak：最后一个外部 Arc 释放后，watch sender 关闭并结束任务。
        let loop_node = Arc::downgrade(&node);
        let socket = node.socket.clone();
        let mut shutdown = node.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            loop {
                let received = tokio::select! {
                    _ = shutdown.changed() => break,
                    result = socket.recv_from(&mut buf) => result,
                };
                let (n, src) = match received {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let Some(node) = loop_node.upgrade() else {
                    break;
                };
                // 前置代理（FRP / nginx stream 等）注入 PROXY v2 时先剥掉头：
                // STUN 用头里的真实来源出报告，RPC 只用剩下的载荷解帧。
                let proxy_v2 = node.proxy_protocol();
                let (claimed, body): (SocketAddr, &[u8]) = if proxy_v2 {
                    match crate::proxy_protocol::strip_v2(&buf[..n]) {
                        Some((info, rest)) => (info.source.unwrap_or(src), rest),
                        None => (src, &buf[..n]),
                    }
                } else {
                    (src, &buf[..n])
                };
                if let Some(pkt) = RpcPacket::decode(body) {
                    node.dispatch(pkt, Sink::Udp(src)).await;
                } else if body.len() == seed_advertise_v2::LEN
                    && classify(body) == Some(seed_advertise_v2::TYPE)
                {
                    // 别的节点推送来的种子广告（非 RPC：定长报文，无应答）
                    node.on_pushed_advert(body).await;
                } else if let Some((_who, resp)) =
                    crate::observe::try_answer_stun_ex(body, claimed, proxy_v2)
                {
                    // STUN 应答与观察者服务共用限速机制（审计 M6）：没人能从 DHT socket
                    // 上无成本地刷出上行流量。限速按**声称的真实来源**计数（代理后面就是客户端）。
                    let admitted = {
                        let mut gate = node.stun_gate.lock().await;
                        gate.admit(claimed.ip(), Instant::now())
                    };
                    if admitted {
                        let _ = node.socket.send_to(&resp, src).await;
                    }
                }
            }
        });

        Ok(node)
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn identity(&self) -> Arc<NodeIdentity> {
        self.identity.clone()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// 停止 UDP 接收任务。正常路径靠最后一个 `Arc` 释放（读循环持 `Weak`），
    /// 但需要「先停网络再落盘/退出」的场景（agent 退出、固定端口重绑）要能显式收尾。
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        // 给读循环一次被调度的机会（它在下一次 select 里看到变更就退出）
        tokio::task::yield_now().await;
    }

    fn next_txid(&self) -> u32 {
        self.txid.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 测试用：模拟进程重启——丢掉全部只存在于内存里的状态（KV、地址簿），身份不变
    #[cfg(test)]
    pub(crate) async fn forget_volatile_state(&self) {
        self.kv.lock().await.clear();
        self.addr_book.lock().await.clear();
    }

    /// 学习（身份 ↔ 地址）：**只有验过身份证明的路径**可以调用（17 §11）。
    /// 严格模式下这是唯一能写路由表与地址簿的入口。
    async fn learn_verified(&self, id: NodeId, addr: SocketAddr) {
        self.route_failures.lock().await.remove(&id);
        self.routing.lock().await.insert(id);
        let mut book = self.addr_book.lock().await;
        learn_addr(&mut book, id, addr);
    }

    /// 身份证明策略（默认严格；迁移期可显式放宽）
    pub fn set_identity_policy(&self, policy: IdentityPolicy) {
        self.identity_policy.store(policy.as_u8(), Ordering::Relaxed);
    }

    /// 切换对外信令的承载（UDP 被封时设 [`Transport::Tcp`]）。
    ///
    /// 切换后所有出站 RPC（`ping` / `find_node` / `store` / `find_value` / `forward_to` /
    /// `find_seeds`）都改走 TCP，长度前缀帧格式不变；调用方传入的地址必须是 TCP 信令端点。
    /// 入站两个方向始终同时可用（UDP 读循环 + TCP 监听都在跑），所以切换只影响「我怎么出去」。
    pub fn set_signaling_transport(&self, transport: Transport) {
        self.signaling.store(transport.as_u8(), Ordering::Relaxed);
    }

    pub fn signaling_transport(&self) -> Transport {
        Transport::from_u8(self.signaling.load(Ordering::Relaxed))
    }

    /// 设置端点地址准入策略（审计 M2）。默认 [`EndpointScope::Public`]：只收公网地址。
    ///
    /// 本机多进程联调、局域网部署（含 FRP 落在内网）要显式切到
    /// [`EndpointScope::LocalNetwork`]，否则回环/私网地址的广告会被当作无效广告丢弃。
    pub fn set_endpoint_scope(&self, scope: EndpointScope) {
        self.endpoint_scope.store(scope.as_u8(), Ordering::Relaxed);
    }

    pub fn endpoint_scope(&self) -> EndpointScope {
        EndpointScope::from_u8(self.endpoint_scope.load(Ordering::Relaxed))
    }

    /// 该端点是否可作为目的地址（按当前策略）
    fn endpoint_ok(&self, addr: SocketAddr) -> bool {
        is_usable_endpoint(addr, self.endpoint_scope())
    }

    /// 是否识别前置代理注入的 PROXY protocol v2（默认关闭）。
    ///
    /// 打开后：UDP 端口上的 STUN 应答会用头里的**真实客户端地址**做映射报告（观察者口径），
    /// TCP 信令会在连接开头先吃掉这段头再解帧。**只能在「本端口只可能被可信代理访问」时打开**，
    /// 否则任何人都能自称任意来源（污染映射报告、地址簿与限速）。
    pub fn set_proxy_protocol(&self, enabled: bool) {
        self.proxy_protocol.store(enabled, Ordering::Relaxed);
    }

    pub fn proxy_protocol(&self) -> bool {
        self.proxy_protocol.load(Ordering::Relaxed)
    }

    /// 覆盖 DHT socket 上直接应答 STUN 的限速策略（运维配置注入；默认见 `RatePolicy`）
    pub async fn set_stun_rate_policy(&self, policy: RatePolicy) {
        self.stun_gate.lock().await.set_policy(policy);
    }

    /// 某个种子在当前承载下的可探测端点：UDP 模式用广告里的 DHT 地址，
    /// TCP 模式用广告里的 TCP 信令端口（没有宣告 TCP 端口的种子在 TCP 模式下不可用）。
    fn seed_endpoint(&self, info: &SeedInfo) -> Option<SocketAddr> {
        match self.signaling_transport() {
            Transport::Udp => Some(info.addr),
            Transport::Tcp => info.tcp_addr(),
        }
    }

    pub fn identity_policy(&self) -> IdentityPolicy {
        IdentityPolicy::from_u8(self.identity_policy.load(Ordering::Relaxed))
    }

    /// 退回旧协议学习的次数（严格模式恒为 0）
    pub fn legacy_fallback_count(&self) -> u64 {
        self.legacy_fallbacks.load(Ordering::Relaxed)
    }

    /// 被拒绝的入站证明数（伪造/重放/来源不符/版本不符，诊断用）
    pub fn rejected_proof_count(&self) -> u64 {
        self.rejected_proofs.load(Ordering::Relaxed)
    }

    /// 测试用：某个路由节点当前的连续探活失败次数
    #[cfg(test)]
    pub(crate) async fn route_failure_count(&self, id: NodeId) -> u8 {
        *self.route_failures.lock().await.get(&id).unwrap_or(&0)
    }

    /// 探活（bootstrap / 路由维护的唯一原语）：一次一密挑战响应，验过才学习。
    ///
    /// 严格模式下，握手超时后会用旧 PING 做一次**只读诊断**（不学习）：能收到 PONG 说明对端
    /// 只讲旧协议，返回 [`RpcError::Unverified`] 并附可读原因，而不是让调用方以为「对端挂了」。
    /// 兼容模式（[`IdentityPolicy::LegacyAllowed`]）下超时后直接回退到旧的 PING/PONG 学习。
    pub async fn ping(&self, dest: SocketAddr) -> Result<PongInfo, RpcError> {
        if self.signaling_transport() == Transport::Tcp {
            return self.ping_tcp(dest).await;
        }
        match self.authenticate(dest).await {
            Ok(info) => Ok(info),
            Err(RpcError::Timeout) => match self.identity_policy() {
                IdentityPolicy::LegacyAllowed => match self.ping_legacy(dest, true).await {
                    Ok(info) => {
                        self.legacy_fallbacks.fetch_add(1, Ordering::Relaxed);
                        Ok(info)
                    }
                    Err(e) => Err(e),
                },
                IdentityPolicy::Strict => {
                    if self.ping_legacy(dest, false).await.is_ok() {
                        self.legacy_fallbacks.fetch_add(1, Ordering::Relaxed);
                        Err(RpcError::Unverified)
                    } else {
                        Err(RpcError::Timeout)
                    }
                }
            },
            Err(other) => Err(other),
        }
    }

    /// 挑战响应握手（发起方）：发挑战 → 验证明 → 回证，双向各学一次
    async fn authenticate(&self, dest: SocketAddr) -> Result<PongInfo, RpcError> {
        let nonce = auth::fresh_nonce(&mut OsRng);
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            let waiting = pending
                .values()
                .filter(|p| matches!(p, Pending::Auth { .. }))
                .count();
            if waiting >= MAX_PENDING_AUTH {
                return Err(RpcError::Busy);
            }
            pending.insert(
                txid,
                Pending::Auth {
                    addr: dest,
                    nonce,
                    tx,
                },
            );
        }

        let pkt = RpcPacket::auth_challenge(txid, auth::make_challenge(&self.identity, nonce));
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }

        match tokio::time::timeout(Duration::from_millis(RPC_TIMEOUT_MS), rx).await {
            Ok(Ok(result)) => result,
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// 旧协议 PING/PONG（仅兼容模式或诊断用）。`learn = false` 时只取应答、不写任何表。
    async fn ping_legacy(&self, dest: SocketAddr, learn: bool) -> Result<PongInfo, RpcError> {
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(
            txid,
            Pending::Pong {
                addr: dest,
                learn,
                tx,
            },
        );

        let body = PingBody {
            node_id: self.node_id().0,
            pubkey: self.identity.verifying_key().to_bytes(),
        };
        let pkt = RpcPacket::ping(txid, body);
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }

        let wait = if learn {
            RPC_TIMEOUT_MS
        } else {
            LEGACY_DIAGNOSTIC_TIMEOUT_MS
        };
        match tokio::time::timeout(Duration::from_millis(wait), rx).await {
            Ok(Ok(info)) => Ok(info),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// FindNode：查目标邻近节点（本地路由表作答方视角）
    pub async fn find_node(
        &self,
        dest: SocketAddr,
        target: NodeId,
    ) -> Result<Vec<NodeEntry>, RpcError> {
        if self.signaling_transport() == Transport::Tcp {
            return self.find_node_tcp(dest, target).await;
        }
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(txid, Pending::Neighbors(tx));

        let pkt = RpcPacket::find_node(txid, FindNodeBody { target: target.0 });
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }

        match tokio::time::timeout(Duration::from_millis(RPC_TIMEOUT_MS), rx).await {
            Ok(Ok(nodes)) => Ok(nodes),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// Forward：向认识的节点（如种子）投递"致 target"的透明载荷。
    /// fire-and-forget；上层信令自持超时重发。
    pub async fn forward_to(
        &self,
        route: SocketAddr,
        target: NodeId,
        payload: Vec<u8>,
    ) -> Result<(), RpcError> {
        if self.signaling_transport() == Transport::Tcp {
            return self.forward_tcp(route, target, payload).await;
        }
        if payload.len() > wgp_proto::dht::FORWARD_PAYLOAD_MAX {
            return Err(RpcError::PayloadTooLarge);
        }
        let pkt = RpcPacket::forward(
            self.next_txid(),
            ForwardBody {
                target: target.0,
                payload,
            },
        );
        self.socket
            .send_to(&pkt.encode(), route)
            .await
            .map_err(|_| RpcError::NoRoute)?;
        Ok(())
    }

    /// 收取以本节点为目标的 forward 载荷
    pub async fn recv_forward(&self) -> Option<ForwardBody> {
        self.inbox_rx.lock().await.recv().await
    }

    /// 非阻塞收取（upkeep 循环轮询用）
    pub async fn try_recv_forward(&self) -> Option<ForwardBody> {
        self.inbox_rx.lock().await.try_recv().ok()
    }

    /// 注册协商会话（payload 首 4B = session_tag 的 forward 将被投递至此）；
    /// tag=0 保留给房间管理默认队列
    pub async fn register_session(&self, tag: u32) -> mpsc::UnboundedReceiver<ForwardBody> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.sessions.lock().await.insert(tag, tx);
        rx
    }

    /// 注销会话（会话结束时调用，防 tag 泄漏）
    pub async fn unregister_session(&self, tag: u32) {
        self.sessions.lock().await.remove(&tag);
    }

    /// 中继策略（贡献模式家庭带宽节点：Deny 后不再为他人中转）
    pub async fn set_relay_policy(&self, policy: RelayPolicy) {
        self.relay_allow
            .store(policy == RelayPolicy::Allow, Ordering::Relaxed);
    }

    pub fn relay_policy(&self) -> RelayPolicy {
        if self.relay_allow.load(Ordering::Relaxed) {
            RelayPolicy::Allow
        } else {
            RelayPolicy::Deny
        }
    }

    /// KV 存储（房间记录宿主；sender 学习使存储节点可回路由锚点）
    pub async fn store(&self, dest: SocketAddr, key: [u8; 32], value: Vec<u8>) -> Result<(), RpcError> {
        if self.signaling_transport() == Transport::Tcp {
            return self.store_tcp(dest, key, value).await;
        }
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(txid, Pending::StoreAck(tx));
        let pkt = RpcPacket::store(
            txid,
            StoreBody {
                sender: self.node_id().0,
                pubkey: self.identity.verifying_key().to_bytes(),
                key,
                value,
            },
        );
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }
        match tokio::time::timeout(Duration::from_millis(RPC_TIMEOUT_MS), rx).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// KV 读取；空值 = 未命中
    pub async fn find_value(
        &self,
        dest: SocketAddr,
        key: [u8; 32],
    ) -> Result<ValueBody, RpcError> {
        if self.signaling_transport() == Transport::Tcp {
            return self.find_value_tcp(dest, key).await;
        }
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(txid, Pending::Value(tx));
        let pkt = RpcPacket::find_value(txid, FindValueBody { key });
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }
        match tokio::time::timeout(Duration::from_millis(RPC_TIMEOUT_MS), rx).await {
            Ok(Ok(v)) => Ok(v),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// 地址簿视图（供测试与诊断）
    pub async fn known_nodes(&self) -> Vec<(NodeId, SocketAddr)> {
        let book = self.addr_book.lock().await;
        book.iter().map(|(id, (addr, _))| (*id, *addr)).collect()
    }

    /// 应答 Neighbors：本路由表 k-closest 与地址簿交集
    async fn answer_neighbors(&self, target: NodeId, sink: &Sink, txid: u32) {
        let closest: Vec<NodeId> = {
            let rt = self.routing.lock().await;
            rt.closest_to(&target)
        };
        let book = self.addr_book.lock().await;
        let entries: Vec<NodeEntry> = closest
            .iter()
            .take(20)
            .filter_map(|id| {
                book.get(id).and_then(|(addr, _)| match addr.ip() {
                    std::net::IpAddr::V4(v4) => Some(NodeEntry {
                        id: id.0,
                        ipv4: v4.octets(),
                        port: addr.port(),
                    }),
                    _ => None, // v1 仅 IPv4 条目；IPv6 未来线
                })
            })
            .collect();
        drop(book);
        let pkt = RpcPacket::neighbors(txid, NeighborsBody { nodes: entries });
        self.sink_send_amplified(sink, pkt.encode()).await;
    }

    /// 按出口类型投递应答字节（UDP 回源 / TCP 写连接）
    async fn sink_send(&self, sink: &Sink, bytes: Vec<u8>) {
        match sink {
            Sink::Udp(addr) => {
                let _ = self.socket.send_to(&bytes, *addr).await;
            }
            Sink::Tcp(tx) => {
                let _ = tx.send(bytes);
            }
        }
    }

    /// 投递**放大应答**（NEIGHBORS / VALUE / SEEDS）：UDP 出口先按源 IP 记账字节预算。
    ///
    /// 这三类应答可以远大于请求（最多约 20 倍），而 UDP 源地址可伪造——不设预算就是
    /// 现成的反射放大器（审计 M3 的缓解部分，真正的 cookie 方案要改协议）。超预算静默
    /// 丢弃：请求方超时重试，攻击者拿不到放大倍数。TCP 出口是已完成三次握手的连接，
    /// 不存在伪造源，不记账。
    async fn sink_send_amplified(&self, sink: &Sink, bytes: Vec<u8>) {
        if let Sink::Udp(addr) = sink {
            let admitted = {
                let mut budget = self.response_budget.lock().await;
                budget.admit(addr.ip(), bytes.len(), Instant::now())
            };
            if !admitted {
                return;
            }
        }
        self.sink_send(sink, bytes).await;
    }

    /// 报文分发（UDP 读循环与 TCP 连接读端共用同一逻辑）
    async fn dispatch(&self, pkt: RpcPacket, sink: Sink) {
        match pkt.body {
            RpcBody::Ping(body) => {
                // 只为存活与兼容而应答。**不学习**：身份绑定只能证明「公钥与 node_id 自洽」，
                // 证明不了「发送者持有私钥」，更证明不了「它在这个地址上」——录下别人的报文
                // 在另一个地址上重放即可毒化地址簿（17 §11.1）。
                let Some(_sender) = bound_identity(body.node_id, body.pubkey) else {
                    return;
                };
                let my = PingBody {
                    node_id: self.node_id().0,
                    pubkey: self.identity.verifying_key().to_bytes(),
                };
                let resp = RpcPacket::pong(pkt.header.txid, my);
                self.sink_send(&sink, resp.encode()).await;
            }
            RpcBody::Pong(body) => {
                // 旧协议应答：只有在兼容模式的 Pending::Pong{learn:true} 才学习（默认代码路径
                // 根本不会创建这样的等待项）
                let Some(peer) = bound_identity(body.node_id, body.pubkey) else {
                    return;
                };
                let Some(addr) = sink.udp_addr() else {
                    return;
                };
                let matched = {
                    let mut pending = self.pending.lock().await;
                    match pending.remove(&pkt.header.txid) {
                        Some(Pending::Pong {
                            addr: expected,
                            learn,
                            tx,
                        }) if expected == addr => Some((learn, tx)),
                        Some(other) => {
                            pending.insert(pkt.header.txid, other);
                            None
                        }
                        None => None,
                    }
                };
                if let Some((learn, tx)) = matched {
                    if learn {
                        self.learn_verified(peer, addr).await;
                    }
                    let _ = tx.send(PongInfo {
                        node_id: peer,
                        addr,
                    });
                }
            }
            RpcBody::FindNode(body) => {
                self.answer_neighbors(NodeId(body.target), &sink, pkt.header.txid)
                    .await;
            }
            RpcBody::Neighbors(body) => {
                if let Some(Pending::Neighbors(tx)) =
                    self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body.nodes);
                }
            }
            RpcBody::Forward(body) => {
                if body.target == self.node_id().0 {
                    // 本节点即收件人：按 session_tag 分流
                    let tag = if body.payload.len() >= 4 {
                        u32::from_be_bytes(body.payload[..4].try_into().unwrap())
                    } else {
                        0
                    };
                    let dispatched = if tag != 0 {
                        let sessions = self.sessions.lock().await;
                        match sessions.get(&tag) {
                            Some(tx) => tx.send(body.clone()).is_ok(),
                            None => false,
                        }
                    } else {
                        false
                    };
                    if !dispatched {
                        // 默认队列（房间管理/未注册降级）；队满静默丢弃=邮件语义
                        let _ = self.inbox_tx.try_send(body);
                    }
                } else {
                    // 中转：地址簿命中则转发（保留 txid，确保端到端匹配）
                    if self.relay_allow.load(Ordering::Relaxed) {
                        let book = self.addr_book.lock().await;
                        if let Some(&(dest, _)) = book.get(&NodeId(body.target)) {
                            drop(book);
                            let fwd = RpcPacket::forward(pkt.header.txid, body);
                            let _ = self.socket.send_to(&fwd.encode(), dest).await;
                        }
                    }
                    // 未命中或贡献模式拒绝：静默丢弃（fire-and-forget 语义）
                }
            }
            RpcBody::Store(body) => {
                // 存储同样过身份绑定：否则任何人可伪造 sender 抢占 KV 空间。
                // 但**不学习地址**：绑定只证明公钥自洽，写入者要进地址簿必须另走挑战响应
                // （服务端的 upkeep ping 会促成那次握手）。
                let Some(_sender) = bound_identity(body.sender, body.pubkey) else {
                    return;
                };
                let mut kv = self.kv.lock().await;
                kv_admit(&mut kv, body.key, body.value);
                drop(kv);
                let resp = RpcPacket::stored_ack(pkt.header.txid);
                self.sink_send(&sink, resp.encode()).await;
            }
            RpcBody::StoredAck => {
                if let Some(Pending::StoreAck(tx)) =
                    self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(());
                }
            }
            RpcBody::FindValue(body) => {
                let value = self
                    .kv
                    .lock()
                    .await
                    .get(&body.key)
                    .map(|entry| entry.0.clone())
                    .unwrap_or_default(); // 空值 = 未命中
                let resp = RpcPacket::value(
                    pkt.header.txid,
                    ValueBody { key: body.key, value },
                );
                self.sink_send_amplified(&sink, resp.encode()).await;
            }
            RpcBody::Value(body) => {
                if let Some(Pending::Value(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body);
                }
            }
            RpcBody::FindSeeds(body) => {
                self.answer_seeds(body, &sink, pkt.header.txid).await;
            }
            RpcBody::Seeds(body) => {
                if let Some(Pending::Seeds(tx)) = self.pending.lock().await.remove(&pkt.header.txid)
                {
                    let _ = tx.send(body.adverts);
                }
            }
            RpcBody::AuthChallenge(body) => {
                self.answer_challenge(body, &sink, pkt.header.txid).await;
            }
            RpcBody::AuthProof(body) => {
                self.accept_proof(body, &sink, pkt.header.txid).await;
            }
            RpcBody::AuthReject(body) => {
                // 对端明确拒绝：让等待方立刻拿到可读原因，而不是等满 1.5s 超时
                let waiting = {
                    let mut pending = self.pending.lock().await;
                    match pending.remove(&pkt.header.txid) {
                        Some(Pending::Auth { tx, .. }) => Some(tx),
                        Some(other) => {
                            pending.insert(pkt.header.txid, other);
                            None
                        }
                        None => None,
                    }
                };
                if let Some(tx) = waiting {
                    let _ = tx.send(Err(auth::error_for_reject(&body)));
                }
            }
        }
    }

    // —————————————— 身份证明（17 §11）：先验后写 ——————————————

    /// 回应一条挑战：校验挑战方身份 → 回签 → （UDP 下）登记回证 nonce 等对方回证。
    /// 注意：**应答方不因收到挑战而学习**，否则伪造挑战即可毒化我们的表。
    async fn answer_challenge(&self, body: AuthChallengeBody, sink: &Sink, txid: u32) {
        if body.version != AUTH_VERSION {
            let reject = RpcPacket::auth_reject(txid, auth::reject_unsupported_version());
            self.sink_send(sink, reject.encode()).await;
            return;
        }
        if auth::verify_challenge(&body).is_none() {
            // 挑战方身份不自洽：静默丢弃（回包只会成为放大器）
            self.rejected_proofs.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let verifier = NodeId(body.verifier_id);
        // 只有 UDP 入站值得要求回证：TCP 源地址不是可达的 UDP 端点。
        let callback = match sink.udp_addr() {
            Some(src) => {
                if !self.auth_gate.lock().await.admit(src.ip(), Instant::now()) {
                    // 限速：静默丢弃。回 AUTH_REJECT 会替攻击者放大流量。
                    return;
                }
                let nonce = auth::fresh_nonce(&mut OsRng);
                self.remember_issued(nonce, src).await;
                Some(nonce)
            }
            None => None,
        };
        let proof = auth::sign_proof(
            &self.identity,
            verifier,
            &body.nonce,
            callback.unwrap_or([0u8; AUTH_NONCE_LEN]),
            txid,
        );
        self.sink_send(sink, RpcPacket::auth_proof(txid, proof).encode())
            .await;
    }

    /// 校验一条证明：签名 + 一次性 nonce + 来源地址，全部通过才写表。
    async fn accept_proof(&self, body: AuthProofBody, sink: &Sink, txid: u32) {
        let Some(prover) = auth::verify_proof(&body, self.node_id(), txid) else {
            self.rejected_proofs.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(src) = sink.udp_addr() else {
            // TCP 入站：证明有效，但 TCP 源地址不能作为可达的 UDP 端点写进地址簿；
            // 而只入路由表的条目没有可探活的地址，会成为永不淘汰的死条目。故不写任何表。
            return;
        };

        // ① 这是对我方挑战的应答：命中 pending，且来源与 nonce 都要对得上
        let matched = {
            let mut pending = self.pending.lock().await;
            match pending.remove(&txid) {
                Some(Pending::Auth {
                    addr,
                    nonce,
                    tx,
                }) if addr == src && body.nonce_echo == nonce => Some(tx),
                Some(Pending::Auth {
                    addr,
                    nonce,
                    tx,
                }) => {
                    // 来源或 nonce 不符：可能 attacker 抢答，保住等待项让合法应答还能进来
                    pending.insert(txid, Pending::Auth { addr, nonce, tx });
                    None
                }
                Some(other) => {
                    pending.insert(txid, other);
                    None
                }
                None => None,
            }
        };
        if let Some(tx) = matched {
            self.learn_verified(prover, src).await;
            // 回证：让对方也能学到我们（种子/存储节点认识 NAT 后的客户端全靠这一步）
            if body.prover_nonce != [0u8; AUTH_NONCE_LEN] {
                let cb_txid = self.next_txid();
                let proof = auth::sign_proof(
                    &self.identity,
                    prover,
                    &body.prover_nonce,
                    [0u8; AUTH_NONCE_LEN],
                    cb_txid,
                );
                let _ = self
                    .socket
                    .send_to(&RpcPacket::auth_proof(cb_txid, proof).encode(), src)
                    .await;
            }
            let _ = tx.send(Ok(PongInfo {
                node_id: prover,
                addr: src,
            }));
            return;
        }

        // ② 这是我方回证请求的应答：nonce 必须是本端刚发出、未过期、未用过的那一个，
        //    而且必须来自当初发挑战的目标地址（否则谁都能把别人的回证挪到自己的地址上）
        if self.claim_issued(&body.nonce_echo, src).await {
            self.learn_verified(prover, src).await;
            return;
        }
        self.rejected_proofs.fetch_add(1, Ordering::Relaxed);
    }

    /// 记下「已向 addr 发出回证挑战」，等对方回证时核对（一次性，30s 过期）
    async fn remember_issued(&self, nonce: [u8; AUTH_NONCE_LEN], addr: SocketAddr) {
        let now = Instant::now();
        let mut issued = self.issued.lock().await;
        issued.retain(|_, (_, at)| now.duration_since(*at) < ISSUED_TTL);
        if issued.len() >= MAX_ISSUED {
            let oldest = issued
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(nonce, _)| *nonce);
            if let Some(oldest) = oldest {
                issued.remove(&oldest);
            }
        }
        issued.insert(nonce, (addr, now));
    }

    /// 认领一个回证挑战（一次性）：地址与期限都对得上才返回 true 并删除。
    /// 地址不符时不删——否则知道 nonce 的人可以抢先「烧掉」合法回证。
    async fn claim_issued(&self, nonce: &[u8; AUTH_NONCE_LEN], from: SocketAddr) -> bool {
        let now = Instant::now();
        let mut issued = self.issued.lock().await;
        match issued.get(nonce) {
            Some((addr, at)) if *addr == from && now.duration_since(*at) < ISSUED_TTL => {
                issued.remove(nonce);
                true
            }
            _ => false,
        }
    }

    // —————————————— TCP 信令面（长度前缀帧，复用同一 dispatch/路由/KV） ——————————————

    /// 启动 TCP 信令监听（与 UDP 同 socket 语义以外的独立端口，如 3481）。
    /// 帧格式：`[u16 BE 长度][RpcPacket 字节]`，一连接多帧。
    /// 返回实际绑定地址（传端口 0 时由内核分配，供测试用）。
    pub async fn listen_tcp(self: &Arc<Self>, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let node = self.clone();
        tokio::spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONN));
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // 并发连接超限：直接拒绝（家庭宽带防连接耗尽）
                let permit = match limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let node = node.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    node.serve_tcp_conn(stream).await;
                });
            }
        });
        Ok(local)
    }

    /// 单条 TCP 信令连接：读端解帧 → dispatch(Sink::Tcp)；写端将应答帧回灌。
    /// 空闲超时关闭（防慢连接长期占用名额）。
    async fn serve_tcp_conn(&self, mut stream: TcpStream) {
        // 前置代理注入 PROXY v2 时先把头吃掉（只用 peek 确认签名，不消费正常流量）
        if self.proxy_protocol() {
            let _ = read_proxy_v2(&mut stream).await;
        }
        let (mut rd, mut wr) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if write_frame(&mut wr, &frame).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });
        loop {
            let frame = match tokio::time::timeout(
                Duration::from_secs(TCP_IDLE_TIMEOUT_S),
                read_frame(&mut rd),
            )
            .await
            {
                Ok(Ok(f)) => f,
                _ => break, // 空闲超时 / 对端关闭 / 帧非法
            };
            if let Some(pkt) = RpcPacket::decode(&frame) {
                self.dispatch(pkt, Sink::Tcp(tx.clone())).await;
            }
        }
        drop(tx);
        let _ = writer.await;
    }

    /// TCP 单次往返（v1：一请求一连接，低频信令足够；后续可升级长连接池）
    async fn tcp_roundtrip(&self, dest: SocketAddr, req: RpcPacket) -> Result<RpcPacket, RpcError> {
        let txid = req.header.txid;
        let fut = async {
            let mut stream = TcpStream::connect(dest)
                .await
                .map_err(|_| RpcError::NoRoute)?;
            write_frame(&mut stream, &req.encode())
                .await
                .map_err(|_| RpcError::NoRoute)?;
            let resp = read_frame(&mut stream).await.map_err(|_| RpcError::Timeout)?;
            let pkt = RpcPacket::decode(&resp).ok_or(RpcError::Timeout)?;
            if pkt.header.txid != txid {
                return Err(RpcError::Timeout);
            }
            Ok(pkt)
        };
        match tokio::time::timeout(Duration::from_millis(TCP_RPC_TIMEOUT_MS), fut).await {
            Ok(r) => r,
            Err(_) => Err(RpcError::Timeout),
        }
    }

    /// TCP Ping（UDP 被封/受限时的信令兜底）：同样走挑战响应，身份必须可验证。
    ///
    /// TCP 上不做回证、也不写任何表：连接的对端端口是临时的，不能当地址簿条目；
    /// 调用方拿到的是「这个地址上的对端此刻持有该身份私钥」这一事实。
    pub async fn ping_tcp(&self, dest: SocketAddr) -> Result<PongInfo, RpcError> {
        let nonce = auth::fresh_nonce(&mut OsRng);
        let txid = self.next_txid();
        let req = RpcPacket::auth_challenge(txid, auth::make_challenge(&self.identity, nonce));
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::AuthProof(b) => {
                if b.nonce_echo != nonce {
                    self.rejected_proofs.fetch_add(1, Ordering::Relaxed);
                    return Err(RpcError::Unverified);
                }
                let peer = auth::verify_proof(&b, self.node_id(), txid).ok_or_else(|| {
                    self.rejected_proofs.fetch_add(1, Ordering::Relaxed);
                    RpcError::Unverified
                })?;
                Ok(PongInfo {
                    node_id: peer,
                    addr: dest,
                })
            }
            RpcBody::AuthReject(b) => Err(auth::error_for_reject(&b)),
            // 旧版本对未知类型静默丢弃 → 这里只会超时；兼容模式的旧 PING 回退由 caller 决定
            _ => Err(RpcError::Timeout),
        }
    }

    /// 旧协议 TCP Ping（仅兼容模式用：不回证、不写表）
    pub async fn ping_tcp_legacy(&self, dest: SocketAddr) -> Result<PongInfo, RpcError> {
        let body = PingBody {
            node_id: self.node_id().0,
            pubkey: self.identity.verifying_key().to_bytes(),
        };
        let txid = self.next_txid();
        let req = RpcPacket::ping(txid, body);
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::Pong(b) => bound_identity(b.node_id, b.pubkey)
                .map(|node_id| PongInfo { node_id, addr: dest })
                .ok_or(RpcError::Unverified),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP FindNode
    pub async fn find_node_tcp(
        &self,
        dest: SocketAddr,
        target: NodeId,
    ) -> Result<Vec<NodeEntry>, RpcError> {
        let req = RpcPacket::find_node(
            self.next_txid(),
            FindNodeBody { target: target.0 },
        );
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::Neighbors(b) => Ok(b.nodes),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP Store（KV 写入，等 StoredAck）
    pub async fn store_tcp(
        &self,
        dest: SocketAddr,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<(), RpcError> {
        let req = RpcPacket::store(
            self.next_txid(),
            StoreBody {
                sender: self.node_id().0,
                pubkey: self.identity.verifying_key().to_bytes(),
                key,
                value,
            },
        );
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::StoredAck => Ok(()),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP FindValue
    pub async fn find_value_tcp(
        &self,
        dest: SocketAddr,
        key: [u8; 32],
    ) -> Result<ValueBody, RpcError> {
        let req = RpcPacket::find_value(self.next_txid(), FindValueBody { key });
        let resp = self.tcp_roundtrip(dest, req).await?;
        match resp.body {
            RpcBody::Value(b) => Ok(b),
            _ => Err(RpcError::Timeout),
        }
    }

    /// TCP Forward 投递（fire-and-forget：只发不等，符合 Forward 邮件语义）。
    /// 种子收到后按地址簿以 UDP 转发给 target（种子→目标腿仍是 UDP）。
    pub async fn forward_tcp(
        &self,
        dest: SocketAddr,
        target: NodeId,
        payload: Vec<u8>,
    ) -> Result<(), RpcError> {
        if payload.len() > wgp_proto::dht::FORWARD_PAYLOAD_MAX {
            return Err(RpcError::PayloadTooLarge);
        }
        let req = RpcPacket::forward(
            self.next_txid(),
            ForwardBody {
                target: target.0,
                payload,
            },
        );
        let fut = async {
            let mut stream = TcpStream::connect(dest)
                .await
                .map_err(|_| RpcError::NoRoute)?;
            write_frame(&mut stream, &req.encode())
                .await
                .map_err(|_| RpcError::NoRoute)?;
            Ok(())
        };
        match tokio::time::timeout(Duration::from_millis(TCP_RPC_TIMEOUT_MS), fut).await {
            Ok(r) => r,
            Err(_) => Err(RpcError::Timeout),
        }
    }
}

// —————————————— 种子发现（07 §5 第③层 / 17 P0） ——————————————

/// 一条入站广告验签之后的去向
enum AdvertStep {
    /// 无效：验签失败 / 是自己的广告 / 所报地址不可用
    Rejected,
    /// 广告主已在目录中（重放、迟到，或已就地刷新）
    Known,
    /// 新广告主，或换了端点：要先探活
    Probe(Candidate),
}

/// 等待存活复验的广告
struct Candidate {
    id: NodeId,
    adv: SeedAdvertiseV2,
    raw: RawAdvert,
    addr: SocketAddr,
}

/// 广告所报端点是否可用作目的地址（只做格式层面的排除；是否可达由探活回答）
///
/// 具体规则见 [`EndpointScope`]：默认只收公网地址，本机/局域网联调要显式切换策略。
fn is_usable_endpoint(addr: SocketAddr, scope: EndpointScope) -> bool {
    scope.allows(addr)
}

/// 固定窗口限速：`gate` = (窗口起点, 窗口内已放行数)；每秒至多放行 ADVERT_VERIFY_PER_SEC 次
fn gate_admit(gate: &mut (Instant, u32), now: Instant) -> bool {
    if now.duration_since(gate.0) >= Duration::from_secs(1) {
        *gate = (now, 0);
    }
    if gate.1 >= ADVERT_VERIFY_PER_SEC {
        return false;
    }
    gate.1 += 1;
    true
}

fn rtt_millis(rtt: Duration) -> u32 {
    u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX)
}

impl DhtNode {
    /// 种子目录快照（按探活往返耗时升序）
    pub async fn seeds(&self) -> Vec<SeedInfo> {
        self.seeds.lock().await.list()
    }

    /// 订阅目录变更。值只是变更代数，含义仅为「有变化了，请重新读一次 seeds()」
    pub fn watch_seeds(&self) -> watch::Receiver<u64> {
        self.seeds_gen.subscribe()
    }

    /// 本节点当前的广告原文（未宣告为 None）
    pub async fn own_advert(&self) -> Option<RawAdvert> {
        *self.own_advert.lock().await
    }

    /// 登记用户显式配置的入口端点（--seed / --peers）。它们在目录满员时不被挤出；即使尚未
    /// 宣告自己，维护循环也会周期探活它们（保住到它们的 NAT 映射）并询问其种子目录。
    pub async fn pin_seeds(&self, addrs: &[SocketAddr]) {
        let mut pinned = self.pinned.lock().await;
        for addr in addrs {
            if pinned.len() >= PINNED_MAX {
                break;
            }
            pinned.insert(*addr);
        }
    }

    /// 开始对外宣告本节点（仅公网可达的节点调用；地址与端口由部署层给出）。
    ///
    /// `epoch`：广告纪元。接收端只采纳比已有的更大的纪元，所以同一身份每次重启（或广告内容
    /// 变化）都要传入更大的值。内核既不读系统时钟（H5）也不落盘：由外围持久化一个启动计数后
    /// 注入（wgp-node 的做法见 server.rs）。纪元回退的后果只是：已经认识本节点的人继续沿用
    /// 旧广告，直到旧端点探活失败被逐出后才重新采纳。
    ///
    /// 广告由维护循环周期推给已知种子与入口端点；调用后立即推送一轮。
    pub async fn start_advertising(&self, spec: AdvertiseSpec, epoch: u64) {
        let raw = sign_advertise_v2(&self.identity, &spec, epoch.max(1));
        *self.own_advert.lock().await = Some(raw);
        self.push_advert().await;
    }

    /// 向 `dest` 索取它已知的、离 `target` 最近的种子广告，把通过验签与存活复验的写入目录。
    /// 返回对方给出的广告中、此刻已在本地目录里的条数（全部探活有结果后才返回）。
    pub async fn find_seeds(
        self: &Arc<Self>,
        dest: SocketAddr,
        target: NodeId,
    ) -> Result<usize, RpcError> {
        let adverts = self.request_seeds(dest, target, SEEDS_MAX).await?;
        Ok(self.absorb_adverts(adverts).await)
    }

    /// 入网引导（07 §5）：以 `entry`（用户配置的入口端点）为起点建立种子目录。
    /// 入口端点登记为 pinned；向每个入口索取种子广告，再向新学到的种子问一层（让目录不局限于
    /// 入口自己认识的那几个）；更远的由周期维护慢慢补。正在宣告的节点最后把自己的广告推给
    /// 已知种子。返回目录内的种子数。
    pub async fn discover(self: &Arc<Self>, entry: &[SocketAddr]) -> usize {
        self.pin_seeds(entry).await;
        let me = self.node_id();
        let mut asked: HashSet<SocketAddr> = HashSet::new();
        let mut frontier: Vec<SocketAddr> = entry.to_vec();
        for _ in 0..2 {
            frontier.retain(|addr| asked.len() < DISCOVER_MAX_ASKS && asked.insert(*addr));
            if frontier.is_empty() {
                break;
            }
            self.ask_many(std::mem::take(&mut frontier), me).await;
            frontier = self.known_seed_addrs().await;
        }
        // 正在宣告的节点顺手把自己的广告推给刚认识的种子：启动时那一轮推送可能发生在对方上线之前，
        // 不补这一下，对方要等到下一个推送周期（60s）才知道我们（未宣告则无事发生）
        self.push_advert().await;
        self.seeds.lock().await.len()
    }

    /// 为某个键（如房间键）补全它附近的种子：向已知种子各问一次「离 `target` 最近的有哪些」。
    /// 种子很少时与 discover 的结果相同；种子多到一次问不全时，这一步让各客户端对「谁离这个键
    /// 最近」的看法收敛。返回目录内的种子数。
    pub async fn seek_seeds(self: &Arc<Self>, target: NodeId) -> usize {
        let mut addrs = self.known_seed_addrs().await;
        addrs.truncate(DISCOVER_MAX_ASKS);
        self.ask_many(addrs, target).await;
        self.seeds.lock().await.len()
    }

    /// 迭代节点查找（Kademlia FIND_NODE 扩散）：从 `entry` 出发，逐轮向离 `target` 最近的未访问
    /// 候选发 FIND_NODE，用应答里的节点扩充候选，直到候选耗尽或触及轮数 / 接触数上限。
    ///
    /// 每个候选先 PING：应答者的身份过了绑定校验才算数（转述来的身份与实际应答者不符即丢弃），
    /// 同时也让对方认识我们。应答里常常夹着 NAT 后的客户端——它们多半连不上，所以规模刻意压得
    /// 很小，也不做「没有更近的候选就停」的提前终止。返回已验证的节点，按与 target 的距离升序。
    pub async fn lookup_node(
        self: &Arc<Self>,
        target: NodeId,
        entry: &[SocketAddr],
    ) -> Vec<(NodeId, SocketAddr)> {
        let me = self.node_id();
        let scope = self.endpoint_scope();
        let mut seen: HashSet<SocketAddr> = entry.iter().copied().collect();
        // (转述者声称的身份, 地址)；入口端点的身份未知（None），排序时排最前
        let mut pending: Vec<(Option<NodeId>, SocketAddr)> =
            seen.iter().map(|addr| (None, *addr)).collect();
        let mut verified: Vec<(NodeId, SocketAddr)> = Vec::new();
        let mut contacts = 0usize;

        for _ in 0..LOOKUP_MAX_ROUNDS {
            pending.sort_by_key(|(id, _)| id.map(|id| id.xor_distance(&target)));
            let take = LOOKUP_ALPHA
                .min(pending.len())
                .min(LOOKUP_MAX_CONTACTS - contacts);
            if take == 0 {
                break;
            }
            contacts += take;
            let mut asks = JoinSet::new();
            for (claimed, addr) in pending.drain(..take) {
                let node = self.clone();
                asks.spawn(async move {
                    let pong = node.ping(addr).await.ok()?;
                    if claimed.is_some_and(|id| id != pong.node_id) {
                        return None;
                    }
                    let neighbors = node.find_node(addr, target).await.unwrap_or_default();
                    Some((pong.node_id, addr, neighbors))
                });
            }
            while let Some(done) = asks.join_next().await {
                let Ok(Some((id, addr, neighbors))) = done else {
                    continue;
                };
                if !verified.iter().any(|(known, _)| *known == id) {
                    verified.push((id, addr));
                }
                for entry in neighbors {
                    let addr = SocketAddr::from((entry.ipv4, entry.port));
                    if entry.id != me.0 && is_usable_endpoint(addr, scope) && seen.insert(addr) {
                        pending.push((Some(NodeId(entry.id)), addr));
                    }
                }
            }
        }
        verified.sort_by_key(|(id, _)| id.xor_distance(&target));
        verified
    }

    /// 扩散：以自身 ID 为目标做一次迭代查找，把沿途可达的节点认识一遍，再向其中还不在种子目录里的
    /// 节点索取种子广告——入口种子不认识、但路由上够得着的宣告者，靠这一步进入目录。
    /// 返回沿途验证过的节点数。耗时取决于不可达候选的超时，适合放在后台跑。
    pub async fn spread(self: &Arc<Self>, entry: &[SocketAddr]) -> usize {
        let me = self.node_id();
        let reached = self.lookup_node(me, entry).await;
        let listed: HashSet<SocketAddr> = self.seeds().await.into_iter().map(|s| s.addr).collect();
        let fresh: Vec<SocketAddr> = reached
            .iter()
            .map(|(_, addr)| *addr)
            .filter(|addr| !listed.contains(addr) && !entry.contains(addr))
            .collect();
        self.ask_many(fresh, me).await;
        reached.len()
    }

    /// 启动后台维护（幂等）：
    /// - 每 20s 探活目录里的种子与用户配置的入口端点——顺带保住本端到它们的 NAT 映射
    ///   （种子要靠这条映射把别人的 Forward 投递过来）；连续 3 次不应答的种子逐出目录；
    /// - 同一拍里再轮转探活若干普通路由节点（默认 8 个），连续 3 次失败释放桶位；
    ///   刚被种子探活覆盖过的身份跳过，不重复发一轮握手；
    /// - 正在宣告的节点每 60s 把自己的广告推给已知种子与入口端点；
    /// - 每 5 分钟向已知种子重新索取目录，学到后来加入的节点。
    ///
    /// 这些都是低频信令，与打洞探针无关，不占用打洞发包预算（H6）。
    pub fn spawn_maintenance(self: &Arc<Self>) {
        if self.maintaining.swap(true, Ordering::SeqCst) {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick: u32 = 0;
            loop {
                tokio::time::sleep(MAINTAIN_TICK).await;
                let Some(node) = weak.upgrade() else {
                    break;
                };
                tick = tick.wrapping_add(1);
                let just_probed = node.probe_known_seeds().await;
                if tick % ROUTE_PROBE_EVERY_TICKS == 0 {
                    node.probe_routing_batch(&just_probed).await;
                }
                if tick % ADVERTISE_EVERY_TICKS == 0 {
                    node.push_advert().await;
                }
                if tick % PULL_EVERY_TICKS == 0 {
                    let mut addrs = node.known_seed_addrs().await;
                    addrs.truncate(DISCOVER_MAX_ASKS);
                    let me = node.node_id();
                    node.ask_many(addrs, me).await;
                }
            }
        });
    }

    fn bump_seeds(&self) {
        self.seeds_gen.send_modify(|gen| *gen = gen.wrapping_add(1));
    }

    /// 轮转探活一批普通路由节点。`skip` 是本拍刚被种子探活覆盖过的身份——
    /// 普通人参与种子常常是同一批节点，重复握手既费流量也费 CPU。
    pub(crate) async fn probe_routing_batch(self: &Arc<Self>, skip: &HashSet<NodeId>) {
        let mut candidates = Vec::new();
        {
            let routing = self.routing.lock().await;
            let addr_book = self.addr_book.lock().await;
            candidates.extend(
                routing
                    .all_nodes()
                    .into_iter()
                    .filter_map(|id| addr_book.get(&id).map(|(addr, _)| (id, *addr))),
            );
        }
        if candidates.is_empty() {
            return;
        }
        candidates.sort_unstable_by_key(|(id, _)| *id);
        // 窗口按**全量**候选推进：跳过若干身份不改变轮转节奏，下一拍接着往下扫
        let window = {
            let mut cursor = self.route_probe_cursor.lock().await;
            probe_window(&mut cursor, candidates.len(), ROUTE_PROBE_BATCH)
        };
        let selected: Vec<(NodeId, SocketAddr)> = window
            .into_iter()
            .map(|i| candidates[i])
            .filter(|(id, _)| !skip.contains(id))
            .collect();
        if selected.is_empty() {
            return;
        }
        let mut probes = JoinSet::new();
        for (id, addr) in selected {
            let node = self.clone();
            probes.spawn(async move { (id, addr, node.ping(addr).await) });
        }
        while let Some(done) = probes.join_next().await {
            self.process_route_probe(done).await;
        }
    }

    async fn process_route_probe(
        &self,
        result: Result<(NodeId, SocketAddr, Result<PongInfo, RpcError>), tokio::task::JoinError>,
    ) {
        let Ok((id, addr, result)) = result else {
            return;
        };
        let alive = matches!(result, Ok(pong) if pong.node_id == id && pong.addr == addr);
        if alive {
            // 活着就刷新地址簿的最后见时刻：否则长期在线但很少被别的路径学到的条目
            // 会在容量清扫时被当成「静默过期」
            self.route_failures.lock().await.remove(&id);
            let mut book = self.addr_book.lock().await;
            learn_addr(&mut book, id, addr);
            return;
        }
        let failures = {
            let mut map = self.route_failures.lock().await;
            let failures = map.entry(id).or_insert(0);
            *failures = failures.saturating_add(1);
            *failures
        };
        if failures >= ROUTE_FAILURE_LIMIT {
            self.routing.lock().await.remove(&id);
            self.addr_book.lock().await.remove(&id);
            self.route_failures.lock().await.remove(&id);
        }
    }

    async fn ping_timed(&self, dest: SocketAddr) -> Result<(PongInfo, Duration), RpcError> {
        let start = Instant::now();
        let pong = self.ping(dest).await?;
        Ok((pong, start.elapsed()))
    }

    /// 已知种子的地址：目录条目（往返耗时升序）在前，尚未进目录的入口端点在后。
    /// 地址按当前承载换算（TCP 模式下取广告里的 TCP 信令端口）。
    async fn known_seed_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self
            .seeds()
            .await
            .iter()
            .filter_map(|s| self.seed_endpoint(s))
            .collect();
        let mut extra: Vec<SocketAddr> = self
            .pinned
            .lock()
            .await
            .iter()
            .copied()
            .filter(|addr| !addrs.contains(addr))
            .collect();
        extra.sort();
        addrs.extend(extra);
        addrs
    }

    /// 发 FIND_SEEDS 并等应答。请求按想要的条数填充（防反射放大，见 FindSeedsBody）
    async fn request_seeds(
        &self,
        dest: SocketAddr,
        target: NodeId,
        count: usize,
    ) -> Result<Vec<RawAdvert>, RpcError> {
        let filled = FindSeedsBody::for_count(target.0, count);
        if self.signaling_transport() == Transport::Tcp {
            let req = RpcPacket::find_seeds(self.next_txid(), filled);
            let resp = self.tcp_roundtrip(dest, req).await?;
            return match resp.body {
                RpcBody::Seeds(b) => Ok(b.adverts),
                _ => Err(RpcError::Timeout),
            };
        }
        let txid = self.next_txid();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(txid, Pending::Seeds(tx));
        let pkt = RpcPacket::find_seeds(txid, filled);
        if self.socket.send_to(&pkt.encode(), dest).await.is_err() {
            self.pending.lock().await.remove(&txid);
            return Err(RpcError::NoRoute);
        }
        match tokio::time::timeout(Duration::from_millis(RPC_TIMEOUT_MS), rx).await {
            Ok(Ok(adverts)) => Ok(adverts),
            _ => {
                self.pending.lock().await.remove(&txid);
                Err(RpcError::Timeout)
            }
        }
    }

    /// 应答 FIND_SEEDS：自己的广告（若在宣告）与目录条目一起按与 target 的距离排序，
    /// 条数不超过请求的填充所允许的额度——应答永远不长于请求
    async fn answer_seeds(&self, req: FindSeedsBody, sink: &Sink, txid: u32) {
        let own = self.own_advert().await.map(|raw| (self.node_id(), raw));
        let adverts = self
            .seeds
            .lock()
            .await
            .closest_raw(&NodeId(req.target), req.quota(), own);
        let pkt = RpcPacket::seeds(txid, SeedsBody { adverts });
        self.sink_send_amplified(sink, pkt.encode()).await;
    }

    /// 验签一条入站广告，并按目录现状决定去向（同端点的更新广告在这里就地刷新）
    async fn examine_advert(&self, raw: &[u8]) -> AdvertStep {
        let Some((adv, id)) = verify_advertise_v2(raw) else {
            return AdvertStep::Rejected;
        };
        let addr = advert_addr(&adv);
        if id == self.node_id() || !self.endpoint_ok(addr) {
            return AdvertStep::Rejected;
        }
        let mut packet: RawAdvert = [0u8; seed_advertise_v2::LEN];
        packet.copy_from_slice(raw);

        let mut seeds = self.seeds.lock().await;
        match seeds.judge(&id, &adv) {
            Verdict::Stale => AdvertStep::Known,
            Verdict::Refresh => {
                seeds.refresh(&id, &adv, packet);
                drop(seeds);
                self.bump_seeds();
                AdvertStep::Known
            }
            Verdict::Probe => AdvertStep::Probe(Candidate {
                id,
                adv,
                raw: packet,
                addr,
            }),
        }
    }

    /// 存活复验：在广告所报端点上 PING，应答必须来自该端点且身份就是广告主，通过即入目录。
    /// 同一广告主同时只探一次；并发满额时直接放弃（广告主会重发，不值得排队）。
    async fn probe_and_admit(&self, candidate: Candidate) -> bool {
        if !self.verifying.lock().await.insert(candidate.id) {
            return false;
        }
        let admitted = match self.verify_slots.clone().try_acquire_owned() {
            Ok(_slot) => self.probe_candidate(&candidate).await,
            Err(_) => false,
        };
        self.verifying.lock().await.remove(&candidate.id);
        admitted
    }

    async fn probe_candidate(&self, candidate: &Candidate) -> bool {
        // 探活端点按当前承载换算：UDP 用广告里的 DHT 地址，TCP 用广告里的 TCP 信令端口
        let target = match self.signaling_transport() {
            Transport::Udp => candidate.addr,
            Transport::Tcp => {
                if candidate.adv.tcp_port == 0 {
                    return false; // 该种子没有宣告 TCP 信令端口：TCP 模式下无法验证
                }
                SocketAddr::new(candidate.addr.ip(), candidate.adv.tcp_port)
            }
        };
        let Ok((pong, rtt)) = self.ping_timed(target).await else {
            return false;
        };
        if pong.node_id != candidate.id || pong.addr != target {
            return false;
        }
        let pinned = self.pinned.lock().await.contains(&target)
            || self.pinned.lock().await.contains(&candidate.addr);
        let admitted = self.seeds.lock().await.admit(
            candidate.id,
            &candidate.adv,
            candidate.raw,
            Some(rtt_millis(rtt)),
            pinned,
        );
        if admitted {
            self.bump_seeds();
        }
        admitted
    }

    /// 处置一批应我方请求而来的广告：需要探活的并发探，全部有结果后返回「已在目录中」的条数
    async fn absorb_adverts(self: &Arc<Self>, adverts: Vec<RawAdvert>) -> usize {
        let mut known = 0usize;
        let mut probes = JoinSet::new();
        for raw in adverts {
            match self.examine_advert(&raw).await {
                AdvertStep::Known => known += 1,
                AdvertStep::Probe(candidate) => {
                    let node = self.clone();
                    probes.spawn(async move { node.probe_and_admit(candidate).await });
                }
                AdvertStep::Rejected => {}
            }
        }
        while let Some(done) = probes.join_next().await {
            if matches!(done, Ok(true)) {
                known += 1;
            }
        }
        known
    }

    /// 向一组节点并发索取「离 target 最近的种子」，全部有结果后返回
    async fn ask_many(self: &Arc<Self>, addrs: Vec<SocketAddr>, target: NodeId) {
        let mut asks = JoinSet::new();
        for addr in addrs {
            let node = self.clone();
            asks.spawn(async move {
                let _ = node.find_seeds(addr, target).await;
            });
        }
        while asks.join_next().await.is_some() {}
    }

    /// 别的节点主动推来的广告：先过限速再验签；需要探活的放到后台，绝不阻塞读循环
    async fn on_pushed_advert(self: &Arc<Self>, raw: &[u8]) {
        if !self.advert_gate_admit().await {
            return;
        }
        if let AdvertStep::Probe(candidate) = self.examine_advert(raw).await {
            let node = self.clone();
            tokio::spawn(async move {
                node.probe_and_admit(candidate).await;
            });
        }
    }

    /// 推送广告的验签限速：每秒至多 ADVERT_VERIFY_PER_SEC 条
    async fn advert_gate_admit(&self) -> bool {
        let mut gate = self.advert_gate.lock().await;
        gate_admit(&mut gate, Instant::now())
    }

    /// 把自己的广告推给已知种子与入口端点（未宣告则无事发生）
    async fn push_advert(&self) {
        // 广告是「非 RPC 的定长数据报」，TCP 信令面只承载 RPC 帧，没有对应的推送通道；
        // TCP 模式（UDP 被封）下无法宣告自己——客户端本来也不宣告，种子则总是走 UDP。
        if self.signaling_transport() == Transport::Tcp {
            return;
        }
        let Some(raw) = self.own_advert().await else {
            return;
        };
        for addr in self.known_seed_addrs().await {
            let _ = self.socket.send_to(&raw, addr).await;
        }
    }

    /// 探活一轮：目录里的种子记账（往返耗时 / 连续失败逐出）；尚未进目录的入口端点只要应答了，
    /// 就顺手问它要它自己的广告（它可能刚开始宣告，或者我们启动时它还没上线）。
    ///
    /// 返回本拍实际探过的身份集合：同一拍的普通路由探活跳过它们（同一批公网节点往往既是种子
    /// 又在路由表里，重复握手纯属浪费）。
    pub(crate) async fn probe_known_seeds(self: &Arc<Self>) -> HashSet<NodeId> {
        let listed: Vec<(NodeId, SocketAddr)> = self
            .seeds()
            .await
            .iter()
            .filter_map(|s| self.seed_endpoint(s).map(|addr| (s.node_id, addr)))
            .collect();
        let unlisted: Vec<SocketAddr> = self
            .pinned
            .lock()
            .await
            .iter()
            .copied()
            .filter(|addr| !listed.iter().any(|(_, known)| known == addr))
            .collect();

        let mut probed: HashSet<NodeId> = listed.iter().map(|(id, _)| *id).collect();
        let mut probes = JoinSet::new();
        for (id, addr) in listed {
            let node = self.clone();
            probes.spawn(async move { (Some(id), addr, node.ping_timed(addr).await) });
        }
        for addr in unlisted {
            let node = self.clone();
            probes.spawn(async move { (None, addr, node.ping_timed(addr).await) });
        }

        let mut changed = false;
        let mut newcomers: Vec<(SocketAddr, NodeId)> = Vec::new();
        while let Some(done) = probes.join_next().await {
            let Ok((listed_as, addr, result)) = done else {
                continue;
            };
            match (listed_as, result) {
                (Some(id), Ok((pong, rtt))) if pong.node_id == id => {
                    self.seeds.lock().await.mark_alive(&id, rtt_millis(rtt));
                }
                // 不应答，或该端点上已经换了别的身份：都算这个种子失联
                (Some(id), _) => {
                    if self.seeds.lock().await.mark_failed(&id) {
                        self.forget(id).await;
                        changed = true;
                    }
                }
                (None, Ok((pong, _))) => {
                    probed.insert(pong.node_id);
                    newcomers.push((addr, pong.node_id));
                }
                (None, Err(_)) => {}
            }
        }
        if changed {
            self.bump_seeds();
        }
        for (addr, id) in newcomers {
            // 以对方自己的 ID 为目标、只要 1 条：它若在宣告，排最前的就是它自己的广告
            if let Ok(adverts) = self.request_seeds(addr, id, 1).await {
                self.absorb_adverts(adverts).await;
            }
        }
        probed
    }

    /// 忘掉一个失联的节点（路由表 + 地址簿）；它恢复后的下一次 PING / 广告会把它带回来
    async fn forget(&self, id: NodeId) {
        self.routing.lock().await.remove(&id);
        self.addr_book.lock().await.remove(&id);
    }
}

/// 若连接以 PROXY protocol v2 头开头，读掉它并返回头里声明的真实源地址。
///
/// 用 `peek` 先确认签名：不是 v2 就一个字节都不消费——同一个端口上「配了代理」和
/// 「没配代理」的客户端可以共存，不会把正常帧当成头。
async fn read_proxy_v2(stream: &mut TcpStream) -> Option<SocketAddr> {
    use crate::proxy_protocol;
    // 等头到达（代理连接建立后会立刻发头；正常客户端则永远不会发这 12 字节）
    let mut sig = [0u8; 12];
    let mut rounds = 0;
    while rounds < 40 {
        match stream.peek(&mut sig).await {
            Ok(n) if n >= sig.len() => break,
            Ok(_) => {}
            Err(_) => return None,
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        rounds += 1;
    }
    if !proxy_protocol::looks_like_v2(&sig) {
        return None;
    }
    let mut head = [0u8; proxy_protocol::FIXED_LEN];
    stream.read_exact(&mut head).await.ok()?;
    let addr_len = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut full = vec![0u8; proxy_protocol::FIXED_LEN + addr_len];
    full[..proxy_protocol::FIXED_LEN].copy_from_slice(&head);
    stream.read_exact(&mut full[proxy_protocol::FIXED_LEN..]).await.ok()?;
    proxy_protocol::parse_v2(&full).and_then(|info| info.source)
}

/// 写一帧：`[u16 BE 长度][payload]`
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u16;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

/// 读一帧（长度前缀）；帧长越界/为 0 视为非法，返回错误以断连
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_TCP_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tcp frame size out of range",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// 轮转窗口：从 `cursor` 起取至多 `batch` 个下标（环形），并把游标推进到下一轮起点。
///
/// 抽成纯函数是为了能用组合测试证明「节点数 × 批次大小」的长期公平性：只要每轮窗口连续、
/// 步长等于窗口长度，`ceil(len/batch)` 轮就能覆盖全部下标——不存在某些桶位长期漏测。
fn probe_window(cursor: &mut usize, len: usize, batch: usize) -> Vec<usize> {
    if len == 0 || batch == 0 {
        return Vec::new();
    }
    let start = *cursor % len;
    *cursor = (*cursor + batch) % len;
    let count = batch.min(len);
    (0..count).map(|i| (start + i) % len).collect()
}

/// 地址簿学习（含容量治理）：写入/刷新最后见时刻；满员先清扫静默过期条目，
/// 仍满则逐出"最久未见"的一条——攻击者必须持续在线才能保住席位，成本对等。
fn learn_addr(book: &mut HashMap<NodeId, (SocketAddr, Instant)>, id: NodeId, addr: SocketAddr) {
    learn_addr_at(book, id, addr, Instant::now());
}

fn learn_addr_at(
    book: &mut HashMap<NodeId, (SocketAddr, Instant)>,
    id: NodeId,
    addr: SocketAddr,
    now: Instant,
) {
    if !book.contains_key(&id) && book.len() >= ADDR_BOOK_MAX {
        book.retain(|_, (_, seen)| now.duration_since(*seen) < ADDR_BOOK_TTL);
        if book.len() >= ADDR_BOOK_MAX {
            let oldest = book
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(id, _)| *id);
            if let Some(dead) = oldest {
                book.remove(&dead);
            }
        }
    }
    book.insert(id, (addr, now));
}

/// KV 写入（含容量治理）：同 key 覆盖不计新；新 key 满员时逐出最旧写入的一条。
fn kv_admit(store: &mut HashMap<[u8; 32], KvEntry>, key: [u8; 32], value: Vec<u8>) {
    let now = Instant::now();
    if !store.contains_key(&key) && store.len() >= KV_MAX_ENTRIES {
        let oldest = store
            .iter()
            .min_by_key(|(_, (_, written))| *written)
            .map(|(k, _)| *k);
        if let Some(dead) = oldest {
            store.remove(&dead);
        }
    }
    store.insert(key, (value, now));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(seed: u8) -> NodeIdentity {
        NodeIdentity::from_seed([seed; 32])
    }

    fn fake_id(n: u32) -> NodeId {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&n.to_be_bytes());
        NodeId(a)
    }

    fn addr(n: u32) -> SocketAddr {
        ([127, 0, 0, 1], (n as u16) + 1024).into()
    }

    // —— 探活身份证明（17 §11.7 的验证矩阵） ——

    /// 测试辅助：手工登记一个待应答挑战（等价于 `authenticate()` 已经发出的那一半）
    async fn arm_challenge(
        node: &DhtNode,
        txid: u32,
        dest: SocketAddr,
        nonce: [u8; AUTH_NONCE_LEN],
    ) -> oneshot::Receiver<Result<PongInfo, RpcError>> {
        let (tx, rx) = oneshot::channel();
        node.pending
            .lock()
            .await
            .insert(txid, Pending::Auth { addr: dest, nonce, tx });
        rx
    }

    async fn recv_packet(sock: &UdpSocket) -> RpcPacket {
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("等待报文超时")
            .unwrap();
        RpcPacket::decode(&buf[..n]).expect("回包必须是合法 RPC")
    }

    #[tokio::test]
    async fn legitimate_handshake_teaches_both_sides() {
        let a = DhtNode::bind(ident(80), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = DhtNode::bind(ident(81), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (a_addr, b_addr) = (a.local_addr().unwrap(), b.local_addr().unwrap());

        let info = a.ping(b_addr).await.expect("合法握手应成功");
        assert_eq!(info.node_id, b.node_id());
        assert_eq!(info.addr, b_addr);

        // 发起方学到了应答方
        assert_eq!(
            a.known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == b.node_id())
                .map(|(_, addr)| addr),
            Some(b_addr)
        );
        // 回证是 fire-and-forget：给它一点时间落到 b 的地址簿
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if b.known_nodes()
                .await
                .into_iter()
                .any(|(id, addr)| id == a.node_id() && addr == a_addr)
            {
                break;
            }
            assert!(Instant::now() < deadline, "回证后 b 应学到 a");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(a.rejected_proof_count(), 0);
        assert_eq!(b.rejected_proof_count(), 0);
    }

    #[tokio::test]
    async fn forged_proof_cannot_learn_or_poison() {
        let node = DhtNode::bind(ident(82), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let node_addr = node.local_addr().unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker_addr = attacker.local_addr().unwrap();
        let victim = ident(83);
        let nonce = [0x11; AUTH_NONCE_LEN];
        let txid = 401;
        let _rx = arm_challenge(&node, txid, attacker_addr, nonce).await;

        // ① 声称是受害者，但用自己的密钥签名：身份绑定失败
        let mut forged = auth::sign_proof(&ident(84), node.node_id(), &nonce, [0; 16], txid);
        forged.prover_id = victim.node_id().0;
        attacker
            .send_to(&RpcPacket::auth_proof(txid, forged).encode(), node_addr)
            .await
            .unwrap();
        // ② 用受害者的公钥，但签名是别人的：验签失败
        let mut forged2 = auth::sign_proof(&ident(85), node.node_id(), &nonce, [0; 16], txid);
        forged2.prover_pubkey = victim.verifying_key().to_bytes();
        attacker
            .send_to(&RpcPacket::auth_proof(txid, forged2).encode(), node_addr)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            node.known_nodes().await.is_empty(),
            "伪造证明不得写地址簿"
        );
        assert!(
            node.pending.lock().await.contains_key(&txid),
            "伪造证明不得消费等待项"
        );
        assert!(node.rejected_proof_count() >= 2);
    }

    #[tokio::test]
    async fn proof_from_other_source_is_rejected_then_legit_source_recovers() {
        let node = DhtNode::bind(ident(86), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let node_addr = node.local_addr().unwrap();
        let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let right_addr = right.local_addr().unwrap();
        let peer = ident(87);
        let nonce = [0x22; AUTH_NONCE_LEN];
        let txid = 402;
        let rx = arm_challenge(&node, txid, right_addr, nonce).await;

        // 从错误来源发一条合法签名：来源不符 → 拒绝，且等待项保住
        let proof = auth::sign_proof(&peer, node.node_id(), &nonce, [0; 16], txid);
        wrong
            .send_to(&RpcPacket::auth_proof(txid, proof).encode(), node_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(node.known_nodes().await.is_empty(), "来源不符不得学习");
        assert!(node.pending.lock().await.contains_key(&txid));
        assert_eq!(node.rejected_proof_count(), 1);

        // 正确来源重发同一条：学习成功（合法恢复，不需要重新握手）
        right
            .send_to(&RpcPacket::auth_proof(txid, proof).encode(), node_addr)
            .await
            .unwrap();
        let info = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("等待学习结果超时")
            .expect("通道应被应答");
        assert_eq!(info.expect("合法证明应通过").node_id, peer.node_id());
        assert_eq!(
            node.known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == peer.node_id())
                .map(|(_, addr)| addr),
            Some(right_addr)
        );
    }

    #[tokio::test]
    async fn replayed_proof_is_rejected() {
        let node = DhtNode::bind(ident(88), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let node_addr = node.local_addr().unwrap();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let peer = ident(89);

        // 第一次合法握手：录下这条证明
        let nonce = [0x33; AUTH_NONCE_LEN];
        let txid = 403;
        let rx = arm_challenge(&node, txid, peer_addr, nonce).await;
        let recorded = RpcPacket::auth_proof(
            txid,
            auth::sign_proof(&peer, node.node_id(), &nonce, [0; 16], txid),
        )
        .encode();
        peer_sock.send_to(&recorded, node_addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("等待学习结果超时")
            .expect("通道应被应答")
            .expect("第一次应通过");

        // 重放同一条：等待项已消费、issued 里也没有这个 nonce → 拒绝
        let rejected_before = node.rejected_proof_count();
        peer_sock.send_to(&recorded, node_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(node.rejected_proof_count(), rejected_before + 1);

        // 换一个新挑战，再把旧证明塞进去：txid 与 nonce 都对不上 → 仍然拒绝
        let nonce2 = [0x44; AUTH_NONCE_LEN];
        let txid2 = 404;
        let rx2 = arm_challenge(&node, txid2, peer_addr, nonce2).await;
        // 旧证明的 txid 是 403，本来就不会命中 404；再构造一条「txid 对、nonce 错」的
        let wrong_nonce = RpcPacket::auth_proof(
            txid2,
            auth::sign_proof(&peer, node.node_id(), &nonce, [0; 16], txid2),
        )
        .encode();
        peer_sock.send_to(&wrong_nonce, node_addr).await.unwrap();
        peer_sock.send_to(&recorded, node_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            node.pending.lock().await.contains_key(&txid2),
            "nonce 不符不得消费等待项"
        );
        drop(rx2);
    }

    #[tokio::test]
    async fn callback_proof_replay_from_another_address_is_rejected() {
        let node = DhtNode::bind(ident(92), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let node_addr = node.local_addr().unwrap();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_sock.local_addr().unwrap();
        let thief = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = ident(93);

        // 正常一来一回：对方要求回证（prover_nonce 非 0），我们发出回证
        let nonce = [0x55; AUTH_NONCE_LEN];
        let callback_nonce = [0x66; AUTH_NONCE_LEN];
        let txid = 405;
        let rx = arm_challenge(&node, txid, peer_addr, nonce).await;
        peer_sock
            .send_to(
                &RpcPacket::auth_proof(
                    txid,
                    auth::sign_proof(&peer, node.node_id(), &nonce, callback_nonce, txid),
                )
                .encode(),
                node_addr,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("等待学习结果超时")
            .expect("通道应被应答")
            .expect("应通过");
        // 回证发给了 peer_sock
        let callback = recv_packet(&peer_sock).await;
        assert_eq!(callback.header.kind, wgp_proto::dht::rpc_type::AUTH_PROOF);

        // 小偷把这条回证从自己的地址发出去：issued 里记的是 peer 的地址 → 拒绝
        thief
            .send_to(&callback.encode(), node_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(node.rejected_proof_count(), 1);
        assert_eq!(
            node.known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == peer.node_id())
                .map(|(_, addr)| addr),
            Some(peer_addr),
            "地址簿里仍是正主，没被小偷改掉"
        );

        // 正主从原地址发同一条回证：应当被采信（nonce 没有被小偷烧掉）
        peer_sock.send_to(&callback.encode(), node_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            node.known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == peer.node_id())
                .map(|(_, addr)| addr),
            Some(peer_addr)
        );
        assert!(node.issued.lock().await.is_empty(), "回证是一次性的");
    }

    #[tokio::test]
    async fn unsupported_version_gets_explicit_reject() {
        let node = DhtNode::bind(ident(94), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let node_addr = node.local_addr().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let me = ident(95);
        let challenge = wgp_proto::dht::AuthChallengeBody {
            verifier_id: me.node_id().0,
            verifier_pubkey: me.verifying_key().to_bytes(),
            nonce: [0x77; AUTH_NONCE_LEN],
            version: wgp_proto::consts::AUTH_VERSION + 1,
        };
        probe
            .send_to(&RpcPacket::auth_challenge(1, challenge).encode(), node_addr)
            .await
            .unwrap();
        let reply = recv_packet(&probe).await;
        match reply.body {
            RpcBody::AuthReject(b) => {
                assert_eq!(
                    b.reason,
                    wgp_proto::dht::auth_reject_reason::UNSUPPORTED_VERSION
                );
                assert_eq!(b.supported_version, wgp_proto::consts::AUTH_VERSION);
            }
            other => panic!("期望 AUTH_REJECT，收到 {other:?}"),
        }
    }

    #[tokio::test]
    async fn challenge_flood_is_rate_limited_per_source() {
        let node = DhtNode::bind(ident(96), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let node_addr = node.local_addr().unwrap();
        let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let me = ident(97);
        let total = AUTH_REPLIES_PER_IP_PER_SEC * 3;
        for i in 0..total {
            let challenge = wgp_proto::dht::AuthChallengeBody {
                verifier_id: me.node_id().0,
                verifier_pubkey: me.verifying_key().to_bytes(),
                nonce: [i as u8; AUTH_NONCE_LEN],
                version: wgp_proto::consts::AUTH_VERSION,
            };
            flood
                .send_to(
                    &RpcPacket::auth_challenge(i + 1, challenge).encode(),
                    node_addr,
                )
                .await
                .unwrap();
        }
        let mut answered = 0usize;
        let mut buf = [0u8; 2048];
        while let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(300), flood.recv_from(&mut buf)).await
        {
            if RpcPacket::decode(&buf[..n])
                .is_some_and(|p| p.header.kind == wgp_proto::dht::rpc_type::AUTH_PROOF)
            {
                answered += 1;
            }
        }
        assert!(
            answered <= AUTH_REPLIES_PER_IP_PER_SEC as usize,
            "单源应答数 {answered} 应被限速在 {} 以内",
            AUTH_REPLIES_PER_IP_PER_SEC
        );
        // 限速只影响应答数量：窗口滚过之后（回环上所有测试共用 127.0.0.1）握手必须恢复
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let peer = DhtNode::bind(ident(98), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(peer.ping(node_addr).await.is_ok(), "限速窗口滚过后握手应恢复");
    }

    #[tokio::test]
    async fn strict_mode_does_not_learn_from_legacy_pong() {
        let node = DhtNode::bind(ident(99), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let legacy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let legacy_addr = legacy.local_addr().unwrap();
        let legacy_id = ident(100);
        let legacy_node_id = legacy_id.node_id();
        let legacy_pk = legacy_id.verifying_key().to_bytes();
        // 只讲旧协议的对端：收到 PING 回 PONG，忽略 AUTH_CHALLENGE
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok(Ok((n, src))) =
                    tokio::time::timeout(Duration::from_secs(4), legacy.recv_from(&mut buf)).await
                else {
                    break;
                };
                let Some(pkt) = RpcPacket::decode(&buf[..n]) else {
                    continue;
                };
                if pkt.header.kind == wgp_proto::dht::rpc_type::PING {
                    let pong = RpcPacket::pong(
                        pkt.header.txid,
                        PingBody {
                            node_id: legacy_node_id.0,
                            pubkey: legacy_pk,
                        },
                    )
                    .encode();
                    let _ = legacy.send_to(&pong, src).await;
                }
            }
        });

        let started = Instant::now();
        let err = node.ping(legacy_addr).await.unwrap_err();
        assert_eq!(err, RpcError::Unverified, "严格模式应报告「对端不支持身份证明」");
        assert!(started.elapsed() >= Duration::from_millis(RPC_TIMEOUT_MS));
        assert!(node.known_nodes().await.is_empty(), "旧协议不得写地址簿");
        assert_eq!(node.legacy_fallback_count(), 1, "诊断路径会计数");
        responder.abort();
    }

    #[tokio::test]
    async fn legacy_mode_still_learns_from_pong() {
        let node = DhtNode::bind(ident(101), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        node.set_identity_policy(IdentityPolicy::LegacyAllowed);
        let legacy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let legacy_addr = legacy.local_addr().unwrap();
        let legacy_id = ident(102);
        let legacy_node_id = legacy_id.node_id();
        let legacy_pk = legacy_id.verifying_key().to_bytes();
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok(Ok((n, src))) =
                    tokio::time::timeout(Duration::from_secs(6), legacy.recv_from(&mut buf)).await
                else {
                    break;
                };
                let Some(pkt) = RpcPacket::decode(&buf[..n]) else {
                    continue;
                };
                if pkt.header.kind == wgp_proto::dht::rpc_type::PING {
                    let pong = RpcPacket::pong(
                        pkt.header.txid,
                        PingBody {
                            node_id: legacy_node_id.0,
                            pubkey: legacy_pk,
                        },
                    )
                    .encode();
                    let _ = legacy.send_to(&pong, src).await;
                }
            }
        });

        let info = node.ping(legacy_addr).await.expect("兼容模式应回退成功");
        assert_eq!(info.node_id, legacy_node_id);
        assert_eq!(node.legacy_fallback_count(), 1);
        assert_eq!(
            node.known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == legacy_node_id)
                .map(|(_, addr)| addr),
            Some(legacy_addr),
            "兼容模式保留旧行为：PONG 学习"
        );
        responder.abort();
    }

    #[tokio::test]
    async fn new_endpoint_of_same_identity_replaces_book_entry() {
        let watcher = DhtNode::bind(ident(103), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let moving_id = ident(104);
        let at_first = DhtNode::bind(NodeIdentity::from_seed(moving_id.to_seed()), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let first_addr = at_first.local_addr().unwrap();
        watcher.ping(first_addr).await.expect("第一次握手");
        assert_eq!(
            watcher
                .known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == moving_id.node_id())
                .map(|(_, addr)| addr),
            Some(first_addr)
        );

        // 「重启」到新端口（同一身份）：新握手的地址必须覆盖旧条目
        let at_second = DhtNode::bind(NodeIdentity::from_seed(moving_id.to_seed()), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let second_addr = at_second.local_addr().unwrap();
        watcher.ping(second_addr).await.expect("换端点后仍应握手成功");
        assert_eq!(
            watcher
                .known_nodes()
                .await
                .into_iter()
                .find(|(id, _)| *id == moving_id.node_id())
                .map(|(_, addr)| addr),
            Some(second_addr),
            "地址簿应更新到新端点"
        );
    }

    // —— 路由维护：轮转公平性与去重（17 §3.2 第 14 项） ——

    #[test]
    fn probe_window_covers_every_route_for_any_size_and_batch() {
        for len in 1..=40usize {
            for batch in 1..=12usize {
                let mut cursor = 0usize;
                let mut seen = vec![false; len];
                for _ in 0..len.div_ceil(batch) {
                    let window = probe_window(&mut cursor, len, batch);
                    assert_eq!(window.len(), batch.min(len), "len={len} batch={batch}");
                    for i in window {
                        assert!(i < len, "窗口下标越界");
                        seen[i] = true;
                    }
                }
                assert!(
                    seen.iter().all(|v| *v),
                    "len={len} batch={batch}：{} 轮后仍有桶位没被探到",
                    len.div_ceil(batch)
                );
                // 长跑不 panic、游标始终在界内
                for _ in 0..50 {
                    let _ = probe_window(&mut cursor, len, batch);
                    assert!(cursor < len);
                }
            }
        }
    }

    #[test]
    fn probe_window_handles_empty_and_shrinking_tables() {
        let mut cursor = 5usize;
        assert!(probe_window(&mut cursor, 0, 8).is_empty(), "空表不出窗口");
        assert_eq!(cursor, 5, "空表不推进游标");
        // 候选表缩小到比游标还小：窗口仍然覆盖全表，不越界
        let window = probe_window(&mut cursor, 3, 8);
        let mut covered = window.clone();
        covered.sort_unstable();
        assert_eq!(covered, vec![0, 1, 2]);
        assert!(cursor < 3);
    }

    #[tokio::test]
    async fn routing_probe_skips_ids_just_probed_as_seeds() {
        let watcher = DhtNode::bind(ident(110), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer = DhtNode::bind(ident(111), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer_id = peer.node_id();
        let peer_addr = peer.local_addr().unwrap();
        watcher.ping(peer_addr).await.expect("先认识对端");
        assert_eq!(watcher.route_failure_count(peer_id).await, 0);

        // 对端消失（socket 释放，端口无人应答）
        drop(peer);

        // 本拍已作为种子探过 → 不再重复探，失败计数保持 0
        let mut skip = HashSet::new();
        skip.insert(peer_id);
        watcher.probe_routing_batch(&skip).await;
        assert_eq!(
            watcher.route_failure_count(peer_id).await,
            0,
            "刚被种子探活覆盖过的身份不应再发一轮握手"
        );

        // 不跳过 → 探活失败计数 +1
        watcher.probe_routing_batch(&HashSet::new()).await;
        assert_eq!(watcher.route_failure_count(peer_id).await, 1);
    }

    #[test]
    fn auth_gate_limits_per_ip_and_window() {
        let start = Instant::now();
        let mut gate = AuthGate::new();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let admitted = (0..AUTH_REPLIES_PER_IP_PER_SEC + 10)
            .filter(|_| gate.admit(ip, start + Duration::from_millis(100)))
            .count();
        assert_eq!(admitted as u32, AUTH_REPLIES_PER_IP_PER_SEC);
        // 窗口滚动后恢复
        assert!(gate.admit(ip, start + Duration::from_millis(1200)));
        // 另一个源 IP 不受影响
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(gate.admit(other, start + Duration::from_millis(1200)));
    }

    #[test]
    fn pushed_advert_verification_is_rate_limited() {
        let start = Instant::now();
        let mut gate = (start, 0u32);
        // 同一秒内：前 ADVERT_VERIFY_PER_SEC 条放行，其余丢弃
        let admitted = (0..ADVERT_VERIFY_PER_SEC + 40)
            .filter(|_| gate_admit(&mut gate, start + Duration::from_millis(500)))
            .count();
        assert_eq!(admitted as u32, ADVERT_VERIFY_PER_SEC);
        assert!(!gate_admit(&mut gate, start + Duration::from_millis(999)));
        // 窗口滚动后恢复
        assert!(gate_admit(&mut gate, start + Duration::from_millis(1000)));
    }

    #[test]
    fn endpoint_usability_filter() {
        let ok = |s: &str| is_usable_endpoint(s.parse().unwrap(), EndpointScope::Public);
        let local = |s: &str| is_usable_endpoint(s.parse().unwrap(), EndpointScope::LocalNetwork);
        assert!(ok("1.1.1.1:11010"));
        assert!(ok("8.8.8.8:3478"));
        // 公网策略下回环/私网/文档网段一律不准入（审计 M2）
        assert!(!ok("127.0.0.1:11010"), "回环地址不是公网端点");
        assert!(!ok("10.0.0.5:11010"), "RFC1918 不是公网端点");
        assert!(!ok("203.0.113.7:11010"), "TEST-NET-3 是文档地址，不可路由");
        // 局域网策略显式放宽：本机多进程联调才用
        assert!(local("127.0.0.1:11010"));
        assert!(local("10.0.0.5:11010"));
        // 两种策略都不接受这些
        assert!(!ok("0.0.0.0:11010"));
        assert!(!ok("255.255.255.255:11010"));
        assert!(!ok("224.0.0.1:11010"));
        assert!(!ok("100.64.0.1:11010"));
        assert!(!ok("203.0.113.7:0"));
        assert!(!ok("[::1]:11010"));
        assert!(!local("0.0.0.0:11010"));
        assert!(!local("100.64.0.1:11010"));
    }

    #[test]
    fn identity_binding_accepts_true_and_rejects_spoof() {
        let a = ident(1);
        let b = ident(2);
        // 真实绑定通过
        assert_eq!(
            bound_identity(a.node_id().0, a.verifying_key().to_bytes()),
            Some(a.node_id())
        );
        // 拿自己的公钥冒充别人的 node_id：拒绝
        assert_eq!(
            bound_identity(b.node_id().0, a.verifying_key().to_bytes()),
            None
        );
        // 拿别人的公钥冒充其身份（等价重放）：通过的是该身份本身，非伪造
        assert_eq!(
            bound_identity(b.node_id().0, b.verifying_key().to_bytes()),
            Some(b.node_id())
        );
        // 全零公钥字节（ed25519 非典范点）：from_bytes 直接失败
        assert_eq!(bound_identity(a.node_id().0, [0u8; 32]), None);
    }

    #[test]
    fn learn_addr_sweeps_expired_before_evicting() {
        let mut book: HashMap<NodeId, (SocketAddr, Instant)> = HashMap::new();
        let stale = Instant::now();
        let now = stale + ADDR_BOOK_TTL + Duration::from_secs(1);
        for i in 0..ADDR_BOOK_MAX as u32 {
            book.insert(fake_id(i), (addr(i), stale));
        }
        let fresh = fake_id(9_999);
        learn_addr_at(&mut book, fresh, addr(9_999), now);
        // 过期条目被整体清扫，新条目存活且远小于上限
        assert!(book.len() < ADDR_BOOK_MAX / 2, "len={}", book.len());
        assert!(book.contains_key(&fresh));
    }

    #[test]
    fn learn_addr_evicts_oldest_when_all_fresh() {
        let mut book: HashMap<NodeId, (SocketAddr, Instant)> = HashMap::new();
        let start = Instant::now();
        // 所有条目都在 TTL 内；最小编号最久未见，避免对 Instant 做减法。
        for i in 0..ADDR_BOOK_MAX as u32 {
            book.insert(
                fake_id(i),
                (addr(i), start + Duration::from_millis(u64::from(i) * 10)),
            );
        }
        let now = start + Duration::from_secs(60);
        let fresh = fake_id(9_999);
        learn_addr_at(&mut book, fresh, addr(9_999), now);
        assert_eq!(book.len(), ADDR_BOOK_MAX);
        assert!(!book.contains_key(&fake_id(0)), "最久未见的应被逐出");
        assert!(book.contains_key(&fresh));
        // 已存在条目的刷新不受容量限制影响
        learn_addr(&mut book, fresh, addr(9));
        assert_eq!(book.get(&fresh).unwrap().0, addr(9));
    }

    #[test]
    fn kv_admit_overwrites_and_evicts_oldest() {
        let mut store: HashMap<[u8; 32], KvEntry> = HashMap::new();
        let now = Instant::now();
        for i in 0..KV_MAX_ENTRIES {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            key[1] = (i >> 8) as u8;
            // 用 checked_sub：开机不足 10000s 时 Instant 相减会 panic（time.rs 溢出），此时退化为 now
            let old = now
                .checked_sub(Duration::from_secs(10_000 - i as u64))
                .unwrap_or(now);
            store.insert(key, (vec![i as u8], old));
        }
        // 覆盖旧 key 不逐出
        let k0 = [0u8; 32];
        kv_admit(&mut store, k0, vec![0xAA]);
        assert_eq!(store.len(), KV_MAX_ENTRIES);
        assert_eq!(store[&k0].0, vec![0xAA]);
        // 新 key 满员：逐出写入时刻最旧的（key[0]=0 刚被刷新，最旧是次旧者）
        let mut new_key = [0u8; 32];
        new_key[31] = 0xFF;
        kv_admit(&mut store, new_key, vec![1]);
        assert_eq!(store.len(), KV_MAX_ENTRIES);
        assert!(store.contains_key(&new_key));
    }
}