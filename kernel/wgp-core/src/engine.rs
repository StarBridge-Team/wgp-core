//! Engine 门面（14 §9）：内核唯一入口。
//! 三条路径：new_link（客户端打洞）/ join_room（多人房间）/ run_node（wgp-node 服务端）。

#[cfg(feature = "client")]
pub mod circuit;
#[cfg(feature = "client")]
pub mod keepalive;
#[cfg(feature = "client")]
pub mod nat_probe;
#[cfg(feature = "client")]
pub mod punch_runner;
#[cfg(feature = "client")]
pub mod race;

#[cfg(feature = "client")]
pub use circuit::{decide_race, CircuitInput, RaceConfig, TcpTrigger};
#[cfg(feature = "client")]
pub use keepalive::keepalive_loop;
#[cfg(feature = "client")]
pub use nat_probe::{classify_reports, NatClass, NatProbe, ObserverReport};
#[cfg(feature = "client")]
pub use punch_runner::{PunchOutcome, PunchRunner};
#[cfg(feature = "client")]
pub use race::{race_punch, RaceOutcome};

use crate::event::EngineEvent;
#[cfg(feature = "client")]
use crate::event::{LinkLossCause, RoomJoinFailReason};
#[cfg(feature = "client")]
use crate::link::{LinkQuality, LinkTransport, PunchedLink};
#[cfg(feature = "client")]
use crate::rank::LinkRank;
#[cfg(feature = "client")]
use crate::types::{JoinHandle, LinkControl, LinkSink, RoomCode, TransportCapabilitySet};
#[cfg(feature = "client")]
use crate::transport::{TcpProbeCarrier, UdpProbeCarrier};
#[cfg(feature = "client")]
use crate::PeerId;
#[cfg(feature = "client")]
use crate::RoomKey;
#[cfg(feature = "client")]
use std::collections::HashMap;
#[cfg(feature = "client")]
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
#[cfg(feature = "client")]
use std::time::Duration;
use tokio::sync::broadcast;
#[cfg(feature = "client")]
use tokio::sync::watch;
#[cfg(feature = "client")]
use wgp_crypto::SecretBox;
use wgp_dht::{DhtNode, NodeIdentity, ObserverPolicy, ObserverServer};
#[cfg(feature = "client")]
use wgp_dht::{RoomError, RoomRuntime, room_key as room_key_of};
#[cfg(feature = "client")]
use wgp_punch::{BudgetScheduler, PortStepModel};

/// Engine 可克隆（装配线/多人会话共享同一内核实例）
impl Clone for Engine {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            #[cfg(feature = "client")]
            budget: self.budget.clone(),
            #[cfg(feature = "client")]
            dht: self.dht.clone(),
            #[cfg(feature = "client")]
            storage: self.storage.clone(),
            #[cfg(feature = "client")]
            links: self.links.clone(),
        }
    }
}

#[cfg(feature = "client")]
const ROOM_UPKEEP_INTERVAL_MS: u64 = 2_000;

/// 进程级单调毫秒（禁止读系统时钟；03 §3.3.2 硬约束）
#[cfg(feature = "client")]
fn engine_now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    let anchor = *ANCHOR.get_or_init(Instant::now);
    Instant::now().duration_since(anchor).as_millis() as u64
}

/// 节点角色（07 §1/§6：公网固定地址节点 = Seed）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Seed,
    Observer,
}

/// wgp-node 配置（07 §6 部署规格的代码化；具体地址/端口由后端配置注入）
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub role: NodeRole,
    /// "0.0.0.0:11010"（示例形态；实际值来自后端配置）
    pub bind: String,
    /// 同进程 STUN/观察者端口（None = 关闭）
    pub stun: Option<u16>,
    /// 同进程 TCP 信令兜底端口（None = 关闭；UDP 被封/受限时客户端可经此接入）
    pub tcp_signal: Option<u16>,
    /// 贡献模式（家庭带宽节点）：拒绝 Forward 中转（唯一持续流量源）
    pub hobby: bool,
    /// 观察者限频策略（运维参数；默认 `ObserverPolicy::default`）
    pub observer_policy: ObserverPolicy,
}

/// 打洞输入：已协商完成的会话上下文（承诺-揭示产物 + 对端观察报告）。
/// 真实网络中这些参数由装配线（orchestrator）自动产出；本结构亦可供底层直接注入。
#[cfg(feature = "client")]
pub struct PunchInput {
    pub peer: PeerId,
    /// 对端公网 IP（观察者报告的地址）
    pub peer_ip: IpAddr,
    /// 本端打洞载体（承诺-揭示产出的 probe_key 已注入）
    pub carrier: UdpProbeCarrier,
    /// TCP 兜底载体（T1-T4 竞速路径；None = 仅 UDP）
    pub tcp: Option<TcpProbeCarrier>,
    /// UDP 路径开关（T1 预判命中时置 false → 纯 TCP 竞速）
    pub udp_enabled: bool,
    /// 会话密钥（所有权随交付转移）
    pub session_key: SecretBox,
    /// 端口步长模型（None = 无数据撒网）
    pub model: Option<PortStepModel>,
    /// 三波计划种子（由会话 nonce 派生，两端一致→同步探测）
    pub seed: u64,
}

/// 内核门面；事件总线为 broadcast（多外围订阅互不阻塞）。
/// client：预算闸门为房间维度共享（00 §3：调度器是唯一发包点）；
/// node：仅 tx（服务端四职不需要打洞状态）。
pub struct Engine {
    tx: broadcast::Sender<EngineEvent>,
    #[cfg(feature = "client")]
    budget: Arc<tokio::sync::Mutex<BudgetScheduler>>,
    /// 信令上下文（attach_dht 注入：本进程的 DHT 节点 + 房间存储节点）
    #[cfg(feature = "client")]
    dht: Arc<tokio::sync::Mutex<Option<Arc<DhtNode>>>>,
    #[cfg(feature = "client")]
    storage: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,
    /// 活跃链路保活停止开关（release 时拉闸；14 §10 条款 4）
    #[cfg(feature = "client")]
    links: Arc<tokio::sync::Mutex<HashMap<PeerId, watch::Sender<bool>>>>,
}

/// 打洞会话事件流
pub struct LinkStream {
    pub(crate) rx: broadcast::Receiver<EngineEvent>,
}

impl LinkStream {
    /// 等待下一事件（会话级过滤在实现阶段接入）
    pub async fn next(&mut self) -> Option<EngineEvent> {
        self.rx.recv().await.ok()
    }
}

/// 房间句柄：持有停止开关（leave = 停 upkeep）与入表时成员数
#[cfg(feature = "client")]
pub struct RoomHandle {
    pub(crate) room: [u8; 32],
    pub(crate) stop: watch::Sender<bool>,
    pub members: usize,
}

/// 节点运行句柄：DHT 节点与观察者服务（wgp-node 四职中的两个网络面）
pub struct NodeHandle {
    pub dht: Option<Arc<DhtNode>>,
    pub observer: Option<Arc<ObserverServer>>,
    /// TCP 信令监听地址（None = 未启用）
    pub tcp: Option<std::net::SocketAddr>,
}

impl Engine {
    pub fn new() -> (Self, broadcast::Receiver<EngineEvent>) {
        let (tx, rx) = broadcast::channel(256);
        (
            Self {
                tx,
                #[cfg(feature = "client")]
                budget: Arc::new(tokio::sync::Mutex::new(BudgetScheduler::new())),
                #[cfg(feature = "client")]
                dht: Arc::new(tokio::sync::Mutex::new(None)),
                #[cfg(feature = "client")]
                storage: Arc::new(tokio::sync::Mutex::new(None)),
                #[cfg(feature = "client")]
                links: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            },
            rx,
        )
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.tx.subscribe()
    }

    /// 注入信令上下文（客户端启动时调用：本进程 DHT 节点 + 已知存储节点）
    #[cfg(feature = "client")]
    pub async fn attach_dht(&self, node: Arc<DhtNode>, storage: SocketAddr) {
        *self.dht.lock().await = Some(node);
        *self.storage.lock().await = Some(storage);
    }

    /// 客户端路径：接收已协商完成的打洞输入，执行竞速（UDP 三波 ∥ TCP），
    /// 结果经事件总线广播 + LinkSink 回调交付（14 §3 交付语义）。
    /// 交付 UDP 链路后自动挂 NAT 保活哨兵（内核唯一负责保活）。
    #[cfg(feature = "client")]
    pub fn new_link(&self, input: PunchInput, sink: Arc<dyn LinkSink>) -> LinkStream {
        let tx = self.tx.clone();
        let budget = self.budget.clone();
        let links = self.links.clone();
        let peer = input.peer;
        let carrier = Arc::new(input.carrier);
        tokio::spawn(async move {
            let _ = tx.send(EngineEvent::PunchingStarted { peer });

            let outcome = race_punch(
                &carrier,
                input.tcp.as_ref(),
                input.model.as_ref(),
                input.peer_ip,
                input.seed,
                budget.clone(),
                input.udp_enabled,
            )
            .await;

            match outcome {
                RaceOutcome::Udp { peer_addr, .. } => {
                    let rank = LinkRank::Primary;
                    // 实现阶段：命中后接 QUIC 握手（3s 超时，T3 触发 TCP 兜底）；
                    // 本迭代以"打洞成功"为交付点（15 Phase 6 前半）
                    let _ = tx.send(EngineEvent::LinkYielded { peer, rank });
                    let link = PunchedLink {
                        peer_id: peer,
                        transport: LinkTransport::Udp {
                            socket: carrier.socket(),
                        },
                        session_key: input.session_key,
                        quality: LinkQuality {
                            rtt: Duration::from_millis(0),
                            loss: 0.0,
                            measured_mtu: 1400,
                            obeys_budget: true,
                        },
                        rank,
                    };
                    sink.on_link_yielded(peer, link);

                    // ④ 保活哨兵起跑（release 拉闸）
                    let (stop_tx, stop_rx) = watch::channel(false);
                    links.lock().await.insert(peer, stop_tx);
                    let c2 = carrier.clone();
                    let budget2 = budget.clone();
                    tokio::spawn(async move {
                        keepalive_loop(c2, peer_addr, budget2, stop_rx).await;
                    });
                }
                RaceOutcome::Tcp { stream, .. } => {
                    // TCP 路径 = 降级档（00 §4 链路优先级：LAN > QUIC > TCP > ICMP）
                    // 保活由 TCP keepalive/流活性承担，内核不另发探针
                    let rank = LinkRank::Degraded;
                    let _ = tx.send(EngineEvent::LinkYielded { peer, rank });
                    let link = PunchedLink {
                        peer_id: peer,
                        transport: LinkTransport::Tcp { stream },
                        session_key: input.session_key,
                        quality: LinkQuality {
                            rtt: Duration::from_millis(0),
                            loss: 0.0,
                            measured_mtu: 1400,
                            obeys_budget: true,
                        },
                        rank,
                    };
                    sink.on_link_yielded(peer, link);
                }
                RaceOutcome::Failed { .. } => {
                    let cause = LinkLossCause::PeerGone;
                    let _ = tx.send(EngineEvent::LinkLost { peer, cause });
                    sink.on_link_lost(peer, cause);
                }
            }
        });
        LinkStream {
            rx: self.tx.subscribe(),
        }
    }

    /// 释放链路：停保活、清注册（LinkControl::release 的引擎实现）
    #[cfg(feature = "client")]
    pub async fn release(&self, peer: PeerId) {
        if let Some(stop) = self.links.lock().await.remove(&peer) {
            let _ = stop.send(true);
        }
    }

    /// 房间路径（D7 mesh）：加入房间（第一个加入者自动建房）。
    /// 流程：fetch → 已在表 → 直接入；未在表 → 签名报道至锚点并轮询；
    /// NotFound → 创建（房主+锚点）。入表后 spawn upkeep（续期/监控/继位三合一）。
    #[cfg(feature = "client")]
    pub async fn join_room(
        &self,
        code: RoomCode,
        _auth: Option<RoomKey>,
    ) -> Result<RoomHandle, RoomError> {
        let code_str = code.0.clone();
        let room = room_key_of(&code_str);

        let node = {
            let guard = self.dht.lock().await;
            match &*guard {
                Some(n) => n.clone(),
                None => {
                    let _ = self.tx.send(EngineEvent::RoomJoinFailed {
                        room,
                        reason: RoomJoinFailReason::NoDhtAttached,
                    });
                    return Err(RoomError::NotFound);
                }
            }
        };
        let storage = {
            let guard = self.storage.lock().await;
            match *guard {
                Some(s) => s,
                None => {
                    let _ = self.tx.send(EngineEvent::RoomJoinFailed {
                        room,
                        reason: RoomJoinFailReason::NoDhtAttached,
                    });
                    return Err(RoomError::NotFound);
                }
            }
        };

        let rt = RoomRuntime::new(node.clone(), storage);
        let my_id = node.node_id();

        // ① 入表判定（建房/已在表/需报道）
        let joined = match rt.fetch(&code_str).await {
            Ok(rec) if rec.members.iter().any(|(id, _)| *id == my_id) => rec,
            Ok(rec) => {
                // 未入表：签名报道 + 轮询等锚点处理
                let _ = rt.request_join(&code_str, &rec).await;
                let mut last = rec;
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    match rt.fetch(&code_str).await {
                        Ok(r) if r.members.iter().any(|(id, _)| *id == my_id) => {
                            last = r;
                            break;
                        }
                        Ok(r) => last = r,
                        Err(_) => continue,
                    }
                }
                if !last.members.iter().any(|(id, _)| *id == my_id) {
                    let _ = self.tx.send(EngineEvent::RoomJoinFailed {
                        room,
                        reason: RoomJoinFailReason::ReportTimeout,
                    });
                    return Err(RoomError::NotFound);
                }
                last
            }
            Err(RoomError::NotFound) => {
                // 第一人：建房（房主 = 锚点）
                rt.create(&code_str, engine_now_ms()).await?
            }
            Err(e) => {
                let _ = self.tx.send(EngineEvent::RoomJoinFailed {
                    room,
                    reason: RoomJoinFailReason::NotFound,
                });
                return Err(e);
            }
        };

        // ② spawn upkeep（三合一循环；cancel 经 RoomHandle::cancel 停止）
        let (stop_tx, stop_rx) = watch::channel(false);
        let upkeep_code = code_str.clone();
        let upkeep_rt = RoomRuntime::new(node.clone(), storage);
        tokio::spawn(async move {
            upkeep_rt
                .upkeep(upkeep_code, ROOM_UPKEEP_INTERVAL_MS, stop_rx, engine_now_ms)
                .await;
        });

        let _ = self.tx.send(EngineEvent::RoomJoined {
            room,
            members: joined.members.len(),
        });
        Ok(RoomHandle {
            room,
            stop: stop_tx,
            members: joined.members.len(),
        })
    }

    /// 节点路径：种子/观察者模式——wgp-node 的完整逻辑入口（07 §6 四职）。
    /// 承载：DHT 节点（RPC/转发/种子）+ 观察者（STUN 响应，独立端口）
    ///      + TCP 信令面（UDP 被封/受限时的长度前缀帧兜底）。
    pub async fn run_node(&self, cfg: NodeConfig, identity: NodeIdentity) -> NodeHandle {
        let bind_addr: Option<std::net::SocketAddr> = cfg.bind.parse().ok();
        let dht = match bind_addr {
            Some(addr) => match DhtNode::bind(identity, addr).await {
                Ok(n) => {
                    // 贡献模式：拒绝中转（PCDN 防护，07 §7）
                    if cfg.hobby {
                        n.set_relay_policy(wgp_dht::RelayPolicy::Deny).await;
                    }
                    Some(n)
                }
                Err(e) => {
                    eprintln!("[wgp-node] DHT 绑定失败: {e}");
                    None
                }
            },
            None => {
                eprintln!("[wgp-node] 无效绑定地址: {}", cfg.bind);
                None
            }
        };
        // TCP 信令面：复用同一 DHT 节点（同一 dispatch/路由/KV），仅多一条接入通道
        let tcp = match (cfg.tcp_signal, bind_addr, dht.as_ref()) {
            (Some(port), Some(base), Some(node)) => {
                let tcp_addr = std::net::SocketAddr::new(base.ip(), port);
                match node.listen_tcp(tcp_addr).await {
                    Ok(a) => Some(a),
                    Err(e) => {
                        eprintln!("[wgp-node] TCP 信令绑定失败: {e}");
                        None
                    }
                }
            }
            _ => None,
        };
        let observer = match cfg.stun {
            Some(port) => match ObserverServer::bind_with_policy(port, cfg.observer_policy).await {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("[wgp-node] 观察者绑定失败: {e}");
                    None
                }
            },
            None => None,
        };
        NodeHandle { dht, observer, tcp }
    }
}

#[cfg(feature = "client")]
impl LinkControl for Engine {
    /// 主动断开：停保活 + 清注册（异步执行，同步签名适配外围阻塞调用方）
    fn release(&self, peer: PeerId) {
        let links = self.links.clone();
        tokio::spawn(async move {
            if let Some(stop) = links.lock().await.remove(&peer) {
                let _ = stop.send(true);
            }
        });
    }

    /// 升级探测（30s 周期探测的即时触发）——升级链路在后续迭代接入
    fn request_upgrade(&self, _peer: PeerId) {}

    /// 挂起/恢复保活——NAT 学习否决权在后续迭代接入
    fn suspend_keepalive(&self, _peer: PeerId) {}
    fn resume_keepalive(&self, _peer: PeerId) {}

    fn advertise_transports(&self, _supported: TransportCapabilitySet) {}
}

#[cfg(feature = "client")]
impl RoomHandle {
    /// 离开房间（100ms 清理保证，14 §10 条款 6）：停 upkeep
    pub fn leave(self) -> JoinHandle {
        let _ = self.stop.send(true);
        JoinHandle { room: self.room }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EngineEvent;
    use tokio::sync::mpsc;

    const SHARED_KEY: [u8; 32] = [0x71; 32];

    struct CollectSink {
        yielded: mpsc::UnboundedSender<PunchedLink>,
        lost: mpsc::UnboundedSender<PeerId>,
    }

    impl LinkSink for CollectSink {
        fn on_link_yielded(&self, _peer: PeerId, link: PunchedLink) {
            self.yielded.send(link).ok();
        }
        fn on_link_upgraded(&self, _peer: PeerId, _link: PunchedLink) {}
        fn on_link_lost(&self, peer: PeerId, _cause: LinkLossCause) {
            self.lost.send(peer).ok();
        }
    }

    /// 端到端：协商产物（探针密钥共享）→ Engine 竞速 → 事件 + 交付
    #[tokio::test]
    async fn engine_yields_link_on_hit() {
        let (engine, _events) = Engine::new();
        let peer_id: PeerId = [7u8; 16];

        let a = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [1, 2, 3, 4])
            .await
            .unwrap();
        let b = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [5, 6, 7, 8])
            .await
            .unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_ip = b.local_addr().unwrap().ip();

        // 对端回发（同 key：模拟承诺-揭示后的共享探针密钥）
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let probe = b.craft();
            b.socket().send_to(&probe, a_addr).await.unwrap();
        });

        let (yielded_tx, mut yielded_rx) = mpsc::unbounded_channel();
        let (lost_tx, _lost_rx) = mpsc::unbounded_channel();
        let sink = Arc::new(CollectSink {
            yielded: yielded_tx,
            lost: lost_tx,
        });

        let mut stream = engine.new_link(
            PunchInput {
                peer: peer_id,
                peer_ip: b_ip,
                carrier: a,
                tcp: None,
                udp_enabled: true,
                session_key: SecretBox::new([0xAB; 32]),
                model: None,
                seed: 99,
            },
            sink,
        );

        // 事件序：PunchingStarted → LinkYielded
        let e1 = stream.next().await.unwrap();
        assert!(matches!(e1, EngineEvent::PunchingStarted { peer } if peer == peer_id));
        let e2 = stream.next().await.unwrap();
        assert!(matches!(e2, EngineEvent::LinkYielded { peer, rank: LinkRank::Primary } if peer == peer_id));

        // 交付链路抵达外围 sink
        let link = yielded_rx.recv().await.expect("交付链路");
        assert_eq!(link.peer_id, peer_id);
        assert!(matches!(link.transport, LinkTransport::Udp { .. }));
    }

    /// 无对端 → 链路丢失事件 + 外围收到 lost 回调
    #[tokio::test]
    async fn engine_reports_lost_when_no_peer() {
        let (engine, _events) = Engine::new();
        let peer_id: PeerId = [8u8; 16];
        let a = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), SHARED_KEY, [1, 1, 1, 1])
            .await
            .unwrap();

        let (yielded_tx, _yielded_rx) = mpsc::unbounded_channel();
        let (lost_tx, mut lost_rx) = mpsc::unbounded_channel();
        let sink = Arc::new(CollectSink { yielded: yielded_tx, lost: lost_tx });

        let mut stream = engine.new_link(
            PunchInput {
                peer: peer_id,
                peer_ip: "127.0.0.1".parse().unwrap(),
                carrier: a,
                tcp: None,
                udp_enabled: true,
                session_key: SecretBox::new([0xCD; 32]),
                model: None,
                seed: 3,
            },
            sink,
        );

        // 三波发完无回包（每波 800ms 监听——实际约 2.4s）
        let e1 = stream.next().await.unwrap();
        assert!(matches!(e1, EngineEvent::PunchingStarted { .. }));
        let e2 = stream.next().await.unwrap();
        assert!(matches!(e2, EngineEvent::LinkLost { peer, cause: LinkLossCause::PeerGone } if peer == peer_id));

        let lost = lost_rx.recv().await.expect("lost 回调");
        assert_eq!(lost, peer_id);
    }

    /// 多客户端联调：两台 Engine（各自 DHT 节点 + 共同存储节点）加入同一房间。
    /// A 建房 → B 经签名报道入表 → 双方成员表一致 + 事件流含 RoomJoined。
    #[tokio::test]
    async fn two_engines_join_same_room() {
        use rand_core::OsRng;
        use wgp_dht::{NodeIdentity, RoomRuntime};

        // 存储节点（真实部署中即一个公网 wgp-node 种子）
        let storage_node = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap()).await.unwrap()
        };
        let storage_addr = match storage_node.local_addr().unwrap().ip() {
            std::net::IpAddr::V4(_) => storage_node.local_addr().unwrap(),
            _ => panic!("期望 IPv4"),
        };

        // 客户端 A（建房者）
        let (engine_a, mut ev_a) = Engine::new();
        let node_a = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap()).await.unwrap()
        };
        node_a.ping(storage_addr).await.unwrap();
        engine_a.attach_dht(node_a.clone(), storage_addr).await;

        // 客户端 B（加入者）
        let (engine_b, mut ev_b) = Engine::new();
        let node_b = {
            let mut rng = OsRng;
            let id = NodeIdentity::generate(&mut rng);
            DhtNode::bind(id, "127.0.0.1:0".parse().unwrap()).await.unwrap()
        };
        node_b.ping(storage_addr).await.unwrap();
        engine_b.attach_dht(node_b.clone(), storage_addr).await;

        const CODE: &str = "U/ENG-ROOM-0001-CC44";

        // A 建房（第一人 = 房主 + 锚点）
        let a_handle = engine_a
            .join_room(crate::RoomCode(CODE.to_string()), None)
            .await
            .expect("A 建房成功");
        assert_eq!(a_handle.members, 1);

        // B 加入（签名报道 → 锚点入表；upkeep 2s 周期处理）
        let b_handle = engine_b
            .join_room(crate::RoomCode(CODE.to_string()), None)
            .await
            .expect("B 加入成功");
        assert!(b_handle.members >= 2, "B 入表时成员数应至少为 2");

        // 事件断言：双方都收到 RoomJoined
        let mut a_joined = false;
        for _ in 0..8 {
            match ev_a.recv().await {
                Ok(crate::EngineEvent::RoomJoined { room, members }) => {
                    assert_eq!(room, wgp_dht::room_key(CODE));
                    a_joined = members >= 1;
                    if members >= 2 || a_joined {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(a_joined);
        let mut b_joined = false;
        for _ in 0..8 {
            match ev_b.recv().await {
                Ok(crate::EngineEvent::RoomJoined { members, .. }) => {
                    b_joined = members >= 2;
                    break;
                }
                _ => {}
            }
        }
        assert!(b_joined);

        // 存储侧终态：成员表含 A、B 且签名有效（fetch 内建验签）
        let rt = RoomRuntime::new(node_b.clone(), storage_addr);
        let rec = rt.fetch(CODE).await.expect("成员表可读");
        assert!(rec.members.iter().any(|(id, _)| *id == node_a.node_id()));
        assert!(rec.members.iter().any(|(id, _)| *id == node_b.node_id()));
        assert_eq!(rec.lease.anchor, node_a.node_id(), "锚点应为房主 A");

        let _ = a_handle.leave();
        let _ = b_handle.leave();
    }

    /// 竞速交付：UDP 无对端（死路）→ TCP 兜底路径命中 → 交付 Tcp 链路（Degraded 档）。
    /// 确定性构造：B 绑定"波内第一个端口"（同 seed 生成计划），A 侧 TCP 波首个尝试即命中。
    #[tokio::test]
    async fn engine_delivers_tcp_link_when_udp_dead() {
        use crate::transport::TcpProbeCarrier;
        use tokio::net::TcpListener;
        use wgp_punch::plan_waves;

        let key: [u8; 32] = [0x31; 32];
        let seed = 7u64;
        let plan = plan_waves(None, seed, 47);
        // 无数据模式：撒网在 wave3（wave1/2 为空），取第一个端口作确定性命中
        let b_port = plan.wave3[0];

        async fn reserve_port() -> u16 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        }

        let a_tcp_bind: std::net::SocketAddr =
            format!("127.0.0.1:{}", reserve_port().await).parse().unwrap();
        let b_tcp_bind: std::net::SocketAddr =
            format!("127.0.0.1:{b_port}").parse().unwrap();

        let tcp_a = TcpProbeCarrier::new(a_tcp_bind, key, [1, 1, 1, 1]);
        let tcp_b = TcpProbeCarrier::new(b_tcp_bind, key, [2, 2, 2, 2]);

        // 对端 B：循环向 A 的固定 TCP 源端口发起同时打开（覆盖 A 波内尝试窗口）
        {
            let tcp_b = tcp_b.clone();
            tokio::spawn(async move {
                for _ in 0..6 {
                    if tcp_b.punch_port(a_tcp_bind).await.is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            });
        }

        let (engine, _ev) = Engine::new();
        let udp = UdpProbeCarrier::bind("127.0.0.1:0".parse().unwrap(), key, [3, 3, 3, 3])
            .await
            .unwrap();
        let (yielded_tx, mut yielded_rx) = mpsc::unbounded_channel();
        let (lost_tx, mut lost_rx) = mpsc::unbounded_channel();
        let sink = Arc::new(CollectSink {
            yielded: yielded_tx,
            lost: lost_tx,
        });

        let mut stream = engine.new_link(
            PunchInput {
                peer: [0x55; 16],
                peer_ip: "127.0.0.1".parse().unwrap(),
                carrier: udp,
                tcp: Some(tcp_a.clone()),
                udp_enabled: true,
                session_key: SecretBox::new([0x66; 32]),
                model: None,
                seed,
            },
            sink,
        );

        // 等待交付：必须 LinkYielded(rank=Degraded) 而非 Primary/lost
        let mut degraded_seen = false;
        for _ in 0..12 {
            match stream.next().await.unwrap() {
                EngineEvent::LinkYielded { rank: LinkRank::Degraded, .. } => {
                    degraded_seen = true;
                    break;
                }
                EngineEvent::LinkLost { .. } => break,
                _ => {}
            }
        }
        assert!(degraded_seen, "应经 TCP 兜底交付（Degraded 档）");

        let link = yielded_rx.recv().await.expect("TCP 链路交付");
        assert_eq!(link.rank, LinkRank::Degraded);
        assert!(matches!(link.transport, LinkTransport::Tcp { .. }));
        assert!(lost_rx.try_recv().is_err(), "不应有 lost 回调");
    }
}