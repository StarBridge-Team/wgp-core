//! agent 的业务层：持有 DHT 身份 / socket / `Engine` / `PortHub`，把 IPC 命令翻译成内核调用。
//!
//! 阶段 1 的范围（20 文档 §7 第 2 条）刻意不含 GUI、TUN helper 与 ET 子进程；这里保证：
//!
//! - 身份私钥、socket、会话密钥只在本进程里（UI 通过 IPC 拿不到它们，也没有导出路径）；
//! - 控制命令经有界队列串行执行（`wgp-ipc::server`），慢命令不会把读循环堵死；
//! - 事件按订阅者有界推送，慢订阅者被丢弃并计数（绝不无界堆积）；
//! - 每个房间的 `PortHub` 与 `Engine` 句柄由本进程独占；`LeaveRoom` 停止 upkeep 并关闭隧道。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Mutex};
use wgp_core::{peer_id_from_node, Engine, EngineEvent, RoomCode, RoomHandle, SessionOrchestrator};
use wgp_dht::{DhtNode, IdentityPolicy, NodeId, RoomRuntime};
use wgp_ipc::message::{local_protocol, ExposeSnapshot, ForwardSnapshot, RoomSummary};
use wgp_ipc::{
    caps, link_state, proto, Capabilities, Command, ConnCtx, Event, EventKind, Handler, Request,
    Response, ResponseFuture, ResponsePayload, RoomSnapshot, Snapshot, Status, VersionInfo,
};
use wgp_port::{PortConfig, PortEvent, PortHub};

use crate::room;

/// 单进程同时开房上限（阶段 1 每房间一个 `PortHub`，不做资源池）
const MAX_ROOMS: usize = 4;
/// 成员轮询间隔：房间记录由锚点每 30s 续期，成员表变化远慢于这个节拍
const MEMBER_POLL: Duration = Duration::from_secs(2);
/// 同一对端两次打洞尝试之间的最小间隔（失败后不要打成风暴）
const REPUNCH_BACKOFF: Duration = Duration::from_secs(5);

/// 一个已加入的房间
struct RoomEntry {
    members: u32,
    created: bool,
    /// 存储节点地址（带上承载，便于排障：`1.2.3.4:11010 (udp)`）
    storage: String,
    handle: RoomHandle,
    hub: PortHub,
    cfg: PortConfig,
    room_id: [u8; 32],
}

/// 订阅者：每人的有界出口就是它的队列
struct Subscriber {
    out: mpsc::Sender<Arc<Vec<u8>>>,
}

pub struct Agent {
    node: Arc<DhtNode>,
    engine: Engine,
    started: Instant,
    rooms: Mutex<HashMap<String, RoomEntry>>,
    /// 内核事件里的房间 id → 房间码（给事件贴上可读名字）
    room_codes: Mutex<HashMap<[u8; 32], String>>,
    subscribers: Mutex<Vec<Subscriber>>,
    seq: AtomicU64,
    dropped: AtomicU64,
    shutdown: watch::Sender<bool>,
    /// `Arc<Self>` 的自引用：打洞驱动任务需要持有 agent（读房间成员、推事件）
    self_ref: OnceLock<Weak<Agent>>,
}

impl Agent {
    pub fn new(
        node: Arc<DhtNode>,
        engine: Engine,
        shutdown: watch::Sender<bool>,
    ) -> Arc<Self> {
        let agent = Arc::new(Self {
            node,
            engine,
            started: Instant::now(),
            rooms: Mutex::new(HashMap::new()),
            room_codes: Mutex::new(HashMap::new()),
            subscribers: Mutex::new(Vec::new()),
            seq: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            shutdown,
            self_ref: OnceLock::new(),
        });
        let _ = agent.self_ref.set(Arc::downgrade(&agent));
        let me = agent.clone();
        let mut events = agent.engine.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => me.on_engine_event(event).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        agent
    }

    fn arc(&self) -> Option<Arc<Self>> {
        self.self_ref.get().and_then(Weak::upgrade)
    }

    /// 启动时广播一次 `AgentStarted`（重连的 UI 据此发现进程换了）
    pub async fn announce_started(&self) {
        self.emit(EventKind::AgentStarted {
            pid: std::process::id(),
            agent: agent_name(),
        })
        .await;
    }

    fn uptime_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// 向所有订阅者推一条事件。出口满 = 该订阅者太慢：丢弃并计数，绝不等它。
    async fn emit(&self, kind: EventKind) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let Ok(body) = (Event {
            event_seq: seq,
            kind,
        })
        .encode() else {
            return;
        };
        let body = Arc::new(body);
        let mut subs = self.subscribers.lock().await;
        subs.retain(|sub| {
            if sub.out.try_send(body.clone()).is_ok() {
                true
            } else {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                // 连接已断（出口关闭）时顺手清掉订阅；否则只是这条丢了
                !sub.out.is_closed()
            }
        });
    }

    async fn on_engine_event(&self, event: EngineEvent) {
        match event {
            EngineEvent::PunchingStarted { peer } => {
                self.emit(EventKind::Link {
                    peer,
                    state: link_state::PUNCHING,
                    detail: "打洞开始".to_string(),
                })
                .await;
            }
            EngineEvent::LinkYielded { peer, .. } => {
                self.emit(EventKind::Link {
                    peer,
                    state: link_state::UP,
                    detail: "链路已交付".to_string(),
                })
                .await;
            }
            EngineEvent::LinkLost { peer, cause } => {
                self.emit(EventKind::Link {
                    peer,
                    state: link_state::LOST,
                    detail: format!("链路丢失（{cause:?}）"),
                })
                .await;
            }
            EngineEvent::RoomJoined { room, members } => {
                let code = self.room_codes.lock().await.get(&room).cloned();
                if let Some(room) = code {
                    self.emit(EventKind::RoomMembers {
                        room,
                        members: members as u32,
                    })
                    .await;
                }
            }
            // 其余（预算/锚点换人/死局诊断）阶段 1 不透出：UI 还没有对应展示位，
            // 硬塞进现有 EventKind 会让协议形状先于需求固化（见 README「未实现」）。
            _ => {}
        }
    }

    async fn join_room(&self, req: wgp_ipc::RoomRequest) -> Result<RoomSummary, (Status, String)> {
        let code = req.room_code.trim().to_string();
        if code.is_empty() {
            return Err((Status::BadRequest, "room_code 为空".to_string()));
        }
        if self.rooms.lock().await.len() >= MAX_ROOMS {
            return Err((Status::Busy, format!("同时最多 {MAX_ROOMS} 个房间")));
        }
        let eps = room::parse_seeds(&req.seeds).map_err(|e| (Status::BadRequest, e))?;
        let transport = room::choose_transport(&eps);
        let pick = room::resolve_storage(
            &self.node,
            &eps,
            transport,
            &code,
            req.storage.as_deref(),
        )
        .await
        .map_err(|e| (Status::Internal, e))?;
        let cfg = room::build_port_config(&req).map_err(|e| (Status::BadRequest, e))?;

        // 选点之后，房间读写的承载以选中的候选为准（显式 storage 可能换了一条路）
        self.node.set_signaling_transport(pick.transport);
        self.engine
            .attach_dht_with_transport(self.node.clone(), pick.storage, pick.transport)
            .await;

        let my_peer = peer_id_from_node(&self.node.node_id());
        let (hub, port_events) = PortHub::start(my_peer, cfg.clone())
            .await
            .map_err(|e| (Status::Internal, format!("端口转发启动失败：{e}")))?;
        let handle = self
            .engine
            .join_room(RoomCode(code.clone()), None)
            .await
            .map_err(|e| (Status::Internal, format!("加入房间失败：{e:?}")))?;
        let members = handle.members as u32;
        let created = pick.existed == Some(false);
        let room_id = wgp_dht::room_key(&code);
        self.room_codes
            .lock()
            .await
            .insert(room_id, code.clone());
        self.rooms.lock().await.insert(
            code.clone(),
            RoomEntry {
                members,
                created,
                storage: format!("{} ({})", pick.storage, pick.transport.scheme()),
                handle,
                hub: hub.clone(),
                cfg,
                room_id,
            },
        );

        let me = self
            .arc()
            .ok_or_else(|| (Status::Internal, "agent 自引用丢失".to_string()))?;
        let pump = me.clone();
        tokio::spawn(async move { pump.pump_port_events(port_events).await });
        let observers: Vec<SocketAddr> = if req.observers.is_empty() {
            // 没有显式观察者时，用发现到的种子自带的（与客户端同一策略）
            self.node
                .seeds()
                .await
                .iter()
                .filter_map(|s| s.observer_addr())
                .collect()
        } else {
            room::parse_observers(&req.observers)
        };
        let tcp_seed = match eps
            .iter()
            .find(|e| e.scheme == wgp_proto::SeedScheme::Tcp)
        {
            Some(ep) => wgp_core::resolve_endpoint(ep).await,
            None => None,
        };
        let rt = RoomRuntime::with_transport(self.node.clone(), pick.storage, pick.transport);
        let orch = Arc::new(
            SessionOrchestrator::new(
                self.node.clone(),
                self.engine.clone(),
                pick.storage,
                observers,
            )
            .with_tcp_fallback(tcp_seed),
        );
        tokio::spawn(punch_driver(
            me.clone(),
            code.clone(),
            rt,
            orch,
            hub,
            self.node.node_id(),
        ));

        self.emit(EventKind::RoomJoined {
            room: code.clone(),
            members,
        })
        .await;
        Ok(RoomSummary {
            room: code,
            members,
            created,
            storage: pick.storage.to_string(),
        })
    }

    async fn leave_room(&self, code: &str) -> Response {
        let entry = self.rooms.lock().await.remove(code);
        match entry {
            Some(entry) => {
                // 先关隧道：对端立刻得知本端退出，而不必等到超时
                entry.hub.shutdown();
                entry.handle.leave();
                self.room_codes.lock().await.remove(&entry.room_id);
                self.emit(EventKind::RoomLeft {
                    room: code.to_string(),
                })
                .await;
                Response::ok(0, ResponsePayload::Empty)
            }
            None => Response::error(0, Status::NotFound, format!("没有这个房间：{code}")),
        }
    }

    async fn snapshot(&self) -> Snapshot {
        let rooms = self.rooms.lock().await;
        let mut out: Vec<RoomSnapshot> = Vec::with_capacity(rooms.len());
        for (code, entry) in rooms.iter() {
            out.push(RoomSnapshot {
                room: code.clone(),
                members: entry.members,
                created: entry.created,
                storage: entry.storage.clone(),
                // 链路明细靠事件增量补齐（阶段 1 的已知缺口，见 README）
                links: Vec::new(),
                forward: entry
                    .cfg
                    .forward_tcp
                    .iter()
                    .map(|r| ForwardSnapshot {
                        proto: proto::TCP,
                        listen: r.listen.to_string(),
                        remote_port: r.remote_port,
                    })
                    .chain(entry.cfg.forward_udp.iter().map(|r| ForwardSnapshot {
                        proto: proto::UDP,
                        listen: r.listen.to_string(),
                        remote_port: r.remote_port,
                    }))
                    .collect(),
                expose: entry
                    .cfg
                    .expose_tcp
                    .iter()
                    .map(|r| ExposeSnapshot {
                        proto: proto::TCP,
                        port: r.port,
                        target: r.target.to_string(),
                    })
                    .chain(entry.cfg.expose_udp.iter().map(|r| ExposeSnapshot {
                        proto: proto::UDP,
                        port: r.port,
                        target: r.target.to_string(),
                    }))
                    .collect(),
            });
        }
        let (major, minor) = local_protocol();
        Snapshot {
            protocol_major: major,
            protocol_minor: minor,
            agent: agent_name(),
            uptime_ms: self.uptime_ms(),
            subscribers: self.subscribers.lock().await.len() as u32,
            dropped_events: self.dropped.load(Ordering::Relaxed),
            rooms: out,
        }
    }

    async fn refresh_members(&self, code: &str, members: u32) {
        let mut rooms = self.rooms.lock().await;
        if let Some(entry) = rooms.get_mut(code) {
            if entry.members != members {
                entry.members = members;
                drop(rooms);
                self.emit(EventKind::RoomMembers {
                    room: code.to_string(),
                    members,
                })
                .await;
            }
        }
    }

    async fn watch(&self, ctx: &ConnCtx) {
        self.subscribers
            .lock()
            .await
            .push(Subscriber { out: ctx.out() });
    }

    async fn pump_port_events(self: Arc<Self>, mut events: mpsc::UnboundedReceiver<PortEvent>) {
        while let Some(event) = events.recv().await {
            match event {
                PortEvent::Listening {
                    proto,
                    listen,
                    remote_port,
                } => {
                    let proto = match proto {
                        wgp_port::Proto::Tcp => proto::TCP,
                        wgp_port::Proto::Udp => proto::UDP,
                    };
                    self.emit(EventKind::Forward {
                        proto,
                        listen: listen.to_string(),
                        remote_port,
                    })
                    .await;
                }
                PortEvent::TunnelReady { peer, tcp, udp } => {
                    self.emit(EventKind::TunnelReady { peer, tcp, udp }).await;
                }
                PortEvent::TunnelDown { peer, reason } => {
                    self.emit(EventKind::Link {
                        peer,
                        state: link_state::DOWN,
                        detail: format!("隧道关闭：{reason:?}"),
                    })
                    .await;
                }
                PortEvent::TunnelFailed { peer, error } => {
                    self.emit(EventKind::Link {
                        peer,
                        state: link_state::DOWN,
                        detail: format!("隧道建立失败：{error:?}"),
                    })
                    .await;
                }
                // TunnelUp / StreamOpened / StreamClosed：阶段 1 不透出
                _ => {}
            }
        }
    }
}

/// 每个房间一个打洞驱动：轮询成员表，为每个已知成员发起一次协商，链路交给 `PortHub`。
///
/// 为什么是轮询而不是订阅：成员表在 DHT 里，只有拉取（`fetch`）一条路；锚点每 30s 续期，
/// 2s 的轮询足够快又不会把种子打满。`connect_peer` 会等完整个协商，所以同一对端同时只有
/// 一个在跑（`in_flight` 去重），失败后按 `REPUNCH_BACKOFF` 退避。
async fn punch_driver(
    agent: Arc<Agent>,
    code: String,
    rt: RoomRuntime,
    orch: Arc<SessionOrchestrator>,
    hub: PortHub,
    my_id: NodeId,
) {
    let sink: Arc<dyn wgp_core::LinkSink> = Arc::new(hub);
    let in_flight: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(HashSet::new()));
    let last_attempt: Arc<Mutex<HashMap<NodeId, Instant>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut ticker = tokio::time::interval(MEMBER_POLL);
    loop {
        ticker.tick().await;
        let Ok(record) = rt.fetch(&code).await else {
            if !agent.has_room(&code).await {
                return;
            }
            continue;
        };
        agent.refresh_members(&code, record.members.len() as u32).await;
        let now = Instant::now();
        for (member, _pk) in &record.members {
            if *member == my_id {
                continue;
            }
            {
                let mut set = in_flight.lock().await;
                if !set.insert(*member) {
                    continue;
                }
            }
            {
                let attempts = last_attempt.lock().await;
                if attempts
                    .get(member)
                    .is_some_and(|at| now.duration_since(*at) < REPUNCH_BACKOFF)
                {
                    in_flight.lock().await.remove(member);
                    continue;
                }
            }
            let orch = orch.clone();
            let sink = sink.clone();
            let in_flight = in_flight.clone();
            let last_attempt = last_attempt.clone();
            let room = code.clone();
            let member = *member;
            tokio::spawn(async move {
                let _ = orch.connect_peer(&room, member, sink).await;
                last_attempt.lock().await.insert(member, Instant::now());
                in_flight.lock().await.remove(&member);
            });
        }
        // 房间已经从 agent 里移除（LeaveRoom）→ 结束驱动
        if !agent.has_room(&code).await {
            return;
        }
    }
}

impl Agent {
    async fn has_room(&self, code: &str) -> bool {
        self.rooms.lock().await.contains_key(code)
    }
}

impl Handler for Agent {
    fn handle<'a>(&'a self, request: Request, ctx: ConnCtx) -> ResponseFuture<'a> {
        Box::pin(async move {
            let id = request.request_id;
            let mut response = match request.command {
                Command::GetVersion => {
                    let (major, minor) = local_protocol();
                    Response::ok(
                        id,
                        ResponsePayload::Version(VersionInfo {
                            agent: agent_name(),
                            protocol_major: major,
                            protocol_minor: minor,
                            pid: std::process::id(),
                            uptime_ms: self.uptime_ms(),
                        }),
                    )
                }
                Command::GetCapabilities => {
                    let limits = wgp_ipc::server::Limits::default();
                    Response::ok(
                        id,
                        ResponsePayload::Capabilities(Capabilities {
                            bits: caps::STAGE1,
                            max_rooms: MAX_ROOMS as u16,
                            control_queue: limits.control_queue as u16,
                            event_queue: limits.out_queue as u16,
                        }),
                    )
                }
                Command::GetSnapshot => {
                    Response::ok(id, ResponsePayload::Snapshot(self.snapshot().await))
                }
                Command::StartRoom(req) | Command::JoinRoom(req) => {
                    match self.join_room(req).await {
                        Ok(summary) => Response::ok(id, ResponsePayload::Room(summary)),
                        Err((status, message)) => Response::error(id, status, message),
                    }
                }
                Command::LeaveRoom(leave) => {
                    let mut r = self.leave_room(&leave.room_code).await;
                    r.request_id = id;
                    r
                }
                Command::WatchEvents(_) => {
                    self.watch(&ctx).await;
                    Response::ok(id, ResponsePayload::Empty)
                }
                Command::ShutdownAgent => {
                    let _ = self.shutdown.send(true);
                    Response::ok(id, ResponsePayload::Empty)
                }
                // 未知命令（更新的 UI 发来的）：明确 Unsupported，绝不猜语义执行（20 §4）
                _ => Response::error(id, Status::Unsupported, "本版本不支持该命令"),
            };
            response.request_id = id;
            response
        })
    }
}

fn agent_name() -> String {
    format!("wgp-agent {}", wgp_ipc::VERSION)
}

/// 身份策略（agent 启动时注入）
pub fn identity_policy(legacy: bool) -> IdentityPolicy {
    if legacy {
        IdentityPolicy::LegacyAllowed
    } else {
        IdentityPolicy::Strict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_policy_mapping_is_explicit() {
        assert_eq!(identity_policy(false), IdentityPolicy::Strict);
        assert_eq!(identity_policy(true), IdentityPolicy::LegacyAllowed);
    }
}
