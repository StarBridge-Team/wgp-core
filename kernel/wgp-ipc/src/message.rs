//! IPC v1 消息：请求信封、命令、响应与事件（20 文档 §4）。
//!
//! 设计要点：
//! - 所有命令都是**显式枚举**。不存在 `RunCommand`、任意路径、任意 shell、任意 bind 之类的
//!   通用通道——本 crate 的枚举里没有的东西，IPC 上就不可能发出来。
//! - `request_id` 由调用方给出，响应原样回带；`session_id` 是调用方自选的关联号（0 = 不用）。
//!   `deadline_ms` 是**相对本次请求送达时刻**的毫秒数（不是绝对时间戳）：本机 IPC 两端共享
//!   同一条时间线没必要，用相对值可避免时钟跳变带来的误判。
//! - 事件带独立的 `event_seq`（单调递增，从 1 起）。事件不重放：UI 重连后按 `GetSnapshot`
//!   重建状态（20 §5）。
//! - 房间/种子/端口规则全部沿用 CLI 的字符串写法（`udp://host:port`、`25565`、`25566:25565`），
//!   agent 用与 `wgp-client` 相同的解析规则处理。这样 IPC 里不出现第二套「端口规则」结构，
//!   也就不存在两套语义漂移。

use crate::frame::{PROTOCOL_MAJOR, PROTOCOL_MINOR};
use crate::wire::{DecodeError, EncodeError, Reader, Writer};

/// 消息主体 tag：请求
pub const TAG_REQUEST: u8 = 1;
/// 消息主体 tag：响应
pub const TAG_RESPONSE: u8 = 2;
/// 消息主体 tag：事件（只在订阅后由 agent 单向推送）
pub const TAG_EVENT: u8 = 3;

/// 命令 tag（20 §4 的初始命令集，阶段 1 只实现前八个）
pub mod cmd {
    pub const GET_VERSION: u8 = 1;
    pub const GET_CAPABILITIES: u8 = 2;
    pub const GET_SNAPSHOT: u8 = 3;
    pub const START_ROOM: u8 = 4;
    pub const JOIN_ROOM: u8 = 5;
    pub const LEAVE_ROOM: u8 = 6;
    pub const WATCH_EVENTS: u8 = 7;
    pub const SHUTDOWN_AGENT: u8 = 8;

    /// 以下是 20 §4 里已规划、**阶段 1 明确不做**的命令。保留 tag 只是为了让「版本对得上但功能
    /// 没有」的调用方拿到明确的 `Unsupported`，而不是被当成畸形帧或（更糟）静默降级。
    pub const LIST_SESSIONS: u8 = 9;
    pub const SET_PORT_FORWARD: u8 = 10;
    pub const REMOVE_PORT_FORWARD: u8 = 11;
    pub const CANCEL_REQUEST: u8 = 12;

    /// 命令是否改变 agent 状态（未知次版本时这些命令一律拒绝，见 [`crate::server`]）
    pub fn is_state_changing(tag: u8) -> bool {
        matches!(
            tag,
            START_ROOM | JOIN_ROOM | LEAVE_ROOM | SHUTDOWN_AGENT
        )
    }
}

/// 响应状态码
pub mod status {
    pub const OK: u8 = 0;
    pub const UNSUPPORTED: u8 = 1;
    pub const BUSY: u8 = 2;
    pub const DEADLINE_EXCEEDED: u8 = 3;
    pub const BAD_REQUEST: u8 = 4;
    pub const NOT_FOUND: u8 = 5;
    pub const INTERNAL: u8 = 6;
    pub const UNAUTHORIZED: u8 = 7;
}

/// 响应状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// 命令/次版本/字段不认识，或属于保留但未实现的命令
    Unsupported,
    /// 单连接控制队列已满（容量 128）：调用者应退避重试，而不是重连轰炸
    Busy,
    /// 请求的 deadline 已过（或执行超时）
    DeadlineExceeded,
    /// 帧能读、字段能读，但语义不合法（例如房间码为空）
    BadRequest,
    /// 目标房间/会话不存在
    NotFound,
    /// agent 内部错误（含端口绑定失败等）
    Internal,
    /// 调用者没有权限（当前只用于传输层 ACL，方法级鉴权尚未实现）
    Unauthorized,
}

impl Status {
    pub fn as_u8(self) -> u8 {
        match self {
            Status::Ok => status::OK,
            Status::Unsupported => status::UNSUPPORTED,
            Status::Busy => status::BUSY,
            Status::DeadlineExceeded => status::DEADLINE_EXCEEDED,
            Status::BadRequest => status::BAD_REQUEST,
            Status::NotFound => status::NOT_FOUND,
            Status::Internal => status::INTERNAL,
            Status::Unauthorized => status::UNAUTHORIZED,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            status::OK => Status::Ok,
            status::UNSUPPORTED => Status::Unsupported,
            status::BUSY => Status::Busy,
            status::DEADLINE_EXCEEDED => Status::DeadlineExceeded,
            status::BAD_REQUEST => Status::BadRequest,
            status::NOT_FOUND => Status::NotFound,
            status::INTERNAL => Status::Internal,
            status::UNAUTHORIZED => Status::Unauthorized,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Unsupported => "unsupported",
            Status::Busy => "busy",
            Status::DeadlineExceeded => "deadline-exceeded",
            Status::BadRequest => "bad-request",
            Status::NotFound => "not-found",
            Status::Internal => "internal",
            Status::Unauthorized => "unauthorized",
        }
    }
}

/// 响应载荷 tag
mod payload_tag {
    pub const EMPTY: u8 = 0;
    pub const VERSION: u8 = 1;
    pub const CAPABILITIES: u8 = 2;
    pub const SNAPSHOT: u8 = 3;
    pub const ROOM: u8 = 4;
    pub const ERROR: u8 = 5;
}

/// 能力位。UI 据此决定要不要显示某个开关，agent 据此声明「我能做什么」。
pub mod caps {
    /// 支持同时开多个房间（每房间独立 Engine/PortHub）
    pub const MULTI_ROOM: u64 = 1 << 0;
    /// 支持端口转发规则（expose/forward）
    pub const PORT_FORWARD: u64 = 1 << 1;
    /// 支持事件订阅（WatchEvents）
    pub const EVENTS: u64 = 1 << 2;
    /// 支持快照重建（GetSnapshot）
    pub const SNAPSHOT: u64 = 1 << 3;
    /// 接入种子发现（discover/seek/spread）
    pub const SEED_DISCOVERY: u64 = 1 << 4;
    /// 支持 UDP 端口转发
    pub const UDP_FORWARD: u64 = 1 << 5;
    /// 支持 --allow-legacy-identity（身份证明回退策略可切换）
    pub const LEGACY_IDENTITY: u64 = 1 << 6;

    pub const STAGE1: u64 =
        MULTI_ROOM | PORT_FORWARD | EVENTS | SNAPSHOT | SEED_DISCOVERY | UDP_FORWARD | LEGACY_IDENTITY;
}

// ---------------------------------------------------------------------------
// 请求
// ---------------------------------------------------------------------------

/// 一次请求：公共信封 + 命令
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub request_id: u64,
    pub session_id: u64,
    /// 相对送达时刻的毫秒数；`None` = 不设截止
    pub deadline_ms: Option<u64>,
    pub command: Command,
}

/// 阶段 1 的全部命令（与 [`cmd`] 的 tag 一一对应）
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    GetVersion,
    GetCapabilities,
    GetSnapshot,
    /// 创建房间（第一人 = 房主 + 锚点）。房间已存在时行为与 JoinRoom 相同（内核语义）
    StartRoom(RoomRequest),
    /// 加入房间；房间不存在时内核会建房，响应里的 `created` 会让 UI 提示这一点
    JoinRoom(RoomRequest),
    LeaveRoom(LeaveRoom),
    /// 订阅事件流。本版本不支持按 `since_seq` 重放，客户端应先用 `GetSnapshot` 对齐
    WatchEvents(Watch),
    /// 关闭 agent（仅限本用户，传输层 ACL 已经保证这一点）
    ShutdownAgent,
}

impl Command {
    pub fn tag(&self) -> u8 {
        match self {
            Command::GetVersion => cmd::GET_VERSION,
            Command::GetCapabilities => cmd::GET_CAPABILITIES,
            Command::GetSnapshot => cmd::GET_SNAPSHOT,
            Command::StartRoom(_) => cmd::START_ROOM,
            Command::JoinRoom(_) => cmd::JOIN_ROOM,
            Command::LeaveRoom(_) => cmd::LEAVE_ROOM,
            Command::WatchEvents(_) => cmd::WATCH_EVENTS,
            Command::ShutdownAgent => cmd::SHUTDOWN_AGENT,
        }
    }

    /// 是否改变 agent 状态。未知次版本时这类命令一律拒绝（20 §4「不能静默降级」）。
    pub fn is_state_changing(&self) -> bool {
        cmd::is_state_changing(self.tag())
    }

    fn encode_payload(&self, w: &mut Writer) {
        match self {
            Command::StartRoom(r) | Command::JoinRoom(r) => r.encode(w),
            Command::LeaveRoom(l) => {
                w.string(&l.room_code);
            }
            Command::WatchEvents(v) => {
                w.u64(v.since_seq);
            }
            _ => {}
        }
    }
}

/// 开房/加入的参数。字段语义与 `wgp-client` 的同名 CLI 选项完全一致。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomRequest {
    /// 房间码（`U/XXXX-XXXX-XXXX-XXXX`）
    pub room_code: String,
    /// 种子端点串（`udp://host:port` / `tcp://host:port`）
    pub seeds: Vec<String>,
    /// 观察者/STUN 端点（`ip:port`）；空 = 用发现到的种子自带的观察者
    pub observers: Vec<String>,
    /// 显式房间键存储节点（`udp://...`）；None = 在已知种子里按房间键选点
    pub storage: Option<String>,
    /// 暴露给房间成员的 TCP 服务（CLI `--expose` 语法）
    pub expose: Vec<String>,
    /// 本地监听并转发到对端暴露端口（CLI `--forward` 语法）
    pub forward: Vec<String>,
    /// 同上，UDP
    pub expose_udp: Vec<String>,
    pub forward_udp: Vec<String>,
}

impl RoomRequest {
    fn encode(&self, w: &mut Writer) {
        w.string(&self.room_code);
        w.strings(&self.seeds);
        w.strings(&self.observers);
        w.opt_string(self.storage.as_deref());
        w.strings(&self.expose);
        w.strings(&self.forward);
        w.strings(&self.expose_udp);
        w.strings(&self.forward_udp);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            room_code: r.string()?,
            seeds: r.strings()?,
            observers: r.strings()?,
            storage: r.opt_string()?,
            expose: r.strings()?,
            forward: r.strings()?,
            expose_udp: r.strings()?,
            forward_udp: r.strings()?,
        })
    }
}

/// 离开房间
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveRoom {
    pub room_code: String,
}

/// 订阅事件
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    /// 期望从哪一条事件之后开始。本版本无重放缓冲：`0` 与任意值都表示「从现在起」。
    pub since_seq: u64,
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new(TAG_REQUEST);
        w.u64(self.request_id);
        w.u64(self.session_id);
        match self.deadline_ms {
            Some(ms) => {
                w.u8(1);
                w.u64(ms);
            }
            None => w.u8(0),
        }
        w.u8(self.command.tag());
        self.command.encode_payload(&mut w);
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        if r.u8()? != TAG_REQUEST {
            return Err(DecodeError::UnknownTag(body.first().copied().unwrap_or(0)));
        }
        let request_id = r.u64()?;
        let session_id = r.u64()?;
        let deadline_ms = match r.u8()? {
            0 => None,
            1 => Some(r.u64()?),
            _ => return Err(DecodeError::Truncated),
        };
        let tag = r.u8()?;
        let command = match tag {
            cmd::GET_VERSION => Command::GetVersion,
            cmd::GET_CAPABILITIES => Command::GetCapabilities,
            cmd::GET_SNAPSHOT => Command::GetSnapshot,
            cmd::START_ROOM => Command::StartRoom(RoomRequest::decode(&mut r)?),
            cmd::JOIN_ROOM => Command::JoinRoom(RoomRequest::decode(&mut r)?),
            cmd::LEAVE_ROOM => Command::LeaveRoom(LeaveRoom {
                room_code: r.string()?,
            }),
            cmd::WATCH_EVENTS => Command::WatchEvents(Watch {
                since_seq: r.u64()?,
            }),
            cmd::SHUTDOWN_AGENT => Command::ShutdownAgent,
            other => return Err(DecodeError::UnknownCommand(other)),
        };
        r.finish()?;
        Ok(Self {
            request_id,
            session_id,
            deadline_ms,
            command,
        })
    }

    /// 尽力从任意（可能畸形的）body 里捞出 `request_id`。
    /// 解不出命令时仍然要回一个带 `request_id` 的 `Unsupported`/`BadRequest`，
    /// 否则调用方只能等到自己的超时，看不出是协议错还是 agent 卡住。
    pub fn peek_request_id(body: &[u8]) -> Option<u64> {
        if body.len() < 9 || body[0] != TAG_REQUEST {
            return None;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&body[1..9]);
        Some(u64::from_le_bytes(b))
    }
}

// ---------------------------------------------------------------------------
// 响应
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub status: Status,
    pub payload: ResponsePayload,
}

/// 响应载荷。形状由命令决定；`Status::Ok` 之外通常带 `Error` 文案。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponsePayload {
    Empty,
    Version(VersionInfo),
    Capabilities(Capabilities),
    Snapshot(Snapshot),
    Room(RoomSummary),
    /// 人类可读的失败原因。**不得**包含私钥、房间密钥、ET secret（20 §5）。
    Error(String),
}

/// `GetVersion` 的应答：版本 + 协议主/次版本（握手第一步）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub agent: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub pid: u32,
    pub uptime_ms: u64,
}

/// `GetCapabilities` 的应答
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub bits: u64,
    /// 同时可开的房间上限（0 = 不限）
    pub max_rooms: u16,
    /// 单连接控制队列容量（当前 128）
    pub control_queue: u16,
    /// 单连接事件队列容量
    pub event_queue: u16,
}

/// 开房/加入的应答
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSummary {
    pub room: String,
    pub members: u32,
    /// true = 本端就是建房者（房间此前不存在）。JoinRoom 时它意味着「房间里其实只有你」
    pub created: bool,
    /// 选中的房间键存储节点（`ip:port`）。不含任何密钥。
    pub storage: String,
}

/// `GetSnapshot` 的应答：UI 重连后据此重建全部状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub agent: String,
    pub uptime_ms: u64,
    pub subscribers: u32,
    /// 因为订阅者太慢而被丢弃的事件总数（agent 级）
    pub dropped_events: u64,
    pub rooms: Vec<RoomSnapshot>,
}

/// 单个房间的可观测状态。**不含**会话密钥、房间密钥、身份私钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSnapshot {
    pub room: String,
    pub members: u32,
    pub created: bool,
    pub storage: String,
    pub links: Vec<LinkSnapshot>,
    pub forward: Vec<ForwardSnapshot>,
    pub expose: Vec<ExposeSnapshot>,
}

/// 一条到对端的链路
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSnapshot {
    pub peer: [u8; 16],
    /// 见 [`link_state`]
    pub state: u8,
    pub detail: String,
}

/// 链路状态码
pub mod link_state {
    pub const IDLE: u8 = 0;
    pub const PUNCHING: u8 = 1;
    pub const UP: u8 = 2;
    pub const LOST: u8 = 3;
    pub const DOWN: u8 = 4;
}

/// 本地转发口（对端暴露的端口 → 本地监听）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSnapshot {
    /// 见 [`proto`]
    pub proto: u8,
    pub listen: String,
    pub remote_port: u16,
}

/// 本端暴露给房间成员的服务
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeSnapshot {
    pub proto: u8,
    pub port: u16,
    pub target: String,
}

/// 承载协议码
pub mod proto {
    pub const TCP: u8 = 0;
    pub const UDP: u8 = 1;
}

impl Response {
    pub fn ok(request_id: u64, payload: ResponsePayload) -> Self {
        Self {
            request_id,
            status: Status::Ok,
            payload,
        }
    }

    pub fn status(request_id: u64, status: Status) -> Self {
        Self {
            request_id,
            status,
            payload: ResponsePayload::Empty,
        }
    }

    pub fn error(request_id: u64, status: Status, message: impl Into<String>) -> Self {
        Self {
            request_id,
            status,
            payload: ResponsePayload::Error(message.into()),
        }
    }

    /// 失败时的人类可读文案（`Ok` 返回空串）
    pub fn error_text(&self) -> &str {
        match &self.payload {
            ResponsePayload::Error(s) => s,
            _ => "",
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new(TAG_RESPONSE);
        w.u64(self.request_id);
        w.u8(self.status.as_u8());
        match &self.payload {
            ResponsePayload::Empty => w.u8(payload_tag::EMPTY),
            ResponsePayload::Version(v) => {
                w.u8(payload_tag::VERSION);
                w.string(&v.agent);
                w.u16(v.protocol_major);
                w.u16(v.protocol_minor);
                w.u32(v.pid);
                w.u64(v.uptime_ms);
            }
            ResponsePayload::Capabilities(c) => {
                w.u8(payload_tag::CAPABILITIES);
                w.u64(c.bits);
                w.u16(c.max_rooms);
                w.u16(c.control_queue);
                w.u16(c.event_queue);
            }
            ResponsePayload::Snapshot(s) => {
                w.u8(payload_tag::SNAPSHOT);
                w.u16(s.protocol_major);
                w.u16(s.protocol_minor);
                w.string(&s.agent);
                w.u64(s.uptime_ms);
                w.u32(s.subscribers);
                w.u64(s.dropped_events);
                w.u16(s.rooms.len().min(u16::MAX as usize) as u16);
                for room in &s.rooms {
                    room.encode(&mut w);
                }
            }
            ResponsePayload::Room(r) => {
                w.u8(payload_tag::ROOM);
                w.string(&r.room);
                w.u32(r.members);
                w.u8(u8::from(r.created));
                w.string(&r.storage);
            }
            ResponsePayload::Error(text) => {
                w.u8(payload_tag::ERROR);
                w.string(text);
            }
        }
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        if r.u8()? != TAG_RESPONSE {
            return Err(DecodeError::UnknownTag(body.first().copied().unwrap_or(0)));
        }
        let request_id = r.u64()?;
        let status = Status::from_u8(r.u8()?).ok_or(DecodeError::Truncated)?;
        let tag = r.u8()?;
        let payload = match tag {
            payload_tag::EMPTY => ResponsePayload::Empty,
            payload_tag::VERSION => ResponsePayload::Version(VersionInfo {
                agent: r.string()?,
                protocol_major: r.u16()?,
                protocol_minor: r.u16()?,
                pid: r.u32()?,
                uptime_ms: r.u64()?,
            }),
            payload_tag::CAPABILITIES => ResponsePayload::Capabilities(Capabilities {
                bits: r.u64()?,
                max_rooms: r.u16()?,
                control_queue: r.u16()?,
                event_queue: r.u16()?,
            }),
            payload_tag::SNAPSHOT => {
                let protocol_major = r.u16()?;
                let protocol_minor = r.u16()?;
                let agent = r.string()?;
                let uptime_ms = r.u64()?;
                let subscribers = r.u32()?;
                let dropped_events = r.u64()?;
                let n = r.u16()? as usize;
                if n > crate::wire::MAX_ITEMS {
                    return Err(DecodeError::TooManyItems);
                }
                let mut rooms = Vec::with_capacity(n.min(16));
                for _ in 0..n {
                    rooms.push(RoomSnapshot::decode(&mut r)?);
                }
                ResponsePayload::Snapshot(Snapshot {
                    protocol_major,
                    protocol_minor,
                    agent,
                    uptime_ms,
                    subscribers,
                    dropped_events,
                    rooms,
                })
            }
            payload_tag::ROOM => ResponsePayload::Room(RoomSummary {
                room: r.string()?,
                members: r.u32()?,
                created: r.u8()? != 0,
                storage: r.string()?,
            }),
            payload_tag::ERROR => ResponsePayload::Error(r.string()?),
            other => return Err(DecodeError::UnknownPayload(other)),
        };
        r.finish()?;
        Ok(Self {
            request_id,
            status,
            payload,
        })
    }
}

impl RoomSnapshot {
    fn encode(&self, w: &mut Writer) {
        w.string(&self.room);
        w.u32(self.members);
        w.u8(u8::from(self.created));
        w.string(&self.storage);
        w.u16(self.links.len().min(u16::MAX as usize) as u16);
        for l in &self.links {
            w.peer(&l.peer);
            w.u8(l.state);
            w.string(&l.detail);
        }
        w.u16(self.forward.len().min(u16::MAX as usize) as u16);
        for f in &self.forward {
            w.u8(f.proto);
            w.string(&f.listen);
            w.u16(f.remote_port);
        }
        w.u16(self.expose.len().min(u16::MAX as usize) as u16);
        for e in &self.expose {
            w.u8(e.proto);
            w.u16(e.port);
            w.string(&e.target);
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let room = r.string()?;
        let members = r.u32()?;
        let created = r.u8()? != 0;
        let storage = r.string()?;
        let n = r.u16()? as usize;
        if n > crate::wire::MAX_ITEMS {
            return Err(DecodeError::TooManyItems);
        }
        let mut links = Vec::with_capacity(n.min(16));
        for _ in 0..n {
            links.push(LinkSnapshot {
                peer: r.peer()?,
                state: r.u8()?,
                detail: r.string()?,
            });
        }
        let n = r.u16()? as usize;
        if n > crate::wire::MAX_ITEMS {
            return Err(DecodeError::TooManyItems);
        }
        let mut forward = Vec::with_capacity(n.min(16));
        for _ in 0..n {
            forward.push(ForwardSnapshot {
                proto: r.u8()?,
                listen: r.string()?,
                remote_port: r.u16()?,
            });
        }
        let n = r.u16()? as usize;
        if n > crate::wire::MAX_ITEMS {
            return Err(DecodeError::TooManyItems);
        }
        let mut expose = Vec::with_capacity(n.min(16));
        for _ in 0..n {
            expose.push(ExposeSnapshot {
                proto: r.u8()?,
                port: r.u16()?,
                target: r.string()?,
            });
        }
        Ok(Self {
            room,
            members,
            created,
            storage,
            links,
            forward,
            expose,
        })
    }
}

// ---------------------------------------------------------------------------
// 事件
// ---------------------------------------------------------------------------

/// 一条异步事件。`event_seq` 由 agent 单调分配（从 1 起）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub event_seq: u64,
    pub kind: EventKind,
}

/// 事件种类。**不含**业务数据与任何密钥；UI 只做展示与状态对齐。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
    /// agent 启动（重连的 UI 可据此发现进程换了）
    AgentStarted { pid: u32, agent: String },
    RoomJoined { room: String, members: u32 },
    RoomLeft { room: String },
    /// 成员数变化（轮询房间记录得到）
    RoomMembers { room: String, members: u32 },
    /// 链路状态变化（打洞开始/打通/丢失/断开）
    Link {
        peer: [u8; 16],
        state: u8,
        detail: String,
    },
    /// 隧道双向就绪，并告知对端暴露了哪些端口
    TunnelReady {
        peer: [u8; 16],
        tcp: Vec<u16>,
        udp: Vec<u16>,
    },
    /// 本地转发口开始监听
    Forward {
        proto: u8,
        listen: String,
        remote_port: u16,
    },
    /// 本订阅者太慢，之前的 `count` 条事件已被丢弃（绝不无界堆积）
    EventsDropped { count: u64 },
}

mod event_tag {
    pub const AGENT_STARTED: u8 = 1;
    pub const ROOM_JOINED: u8 = 2;
    pub const ROOM_LEFT: u8 = 3;
    pub const ROOM_MEMBERS: u8 = 4;
    pub const LINK: u8 = 5;
    pub const TUNNEL_READY: u8 = 6;
    pub const FORWARD: u8 = 7;
    pub const EVENTS_DROPPED: u8 = 8;
}

impl Event {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new(TAG_EVENT);
        w.u64(self.event_seq);
        match &self.kind {
            EventKind::AgentStarted { pid, agent } => {
                w.u8(event_tag::AGENT_STARTED);
                w.u32(*pid);
                w.string(agent);
            }
            EventKind::RoomJoined { room, members } => {
                w.u8(event_tag::ROOM_JOINED);
                w.string(room);
                w.u32(*members);
            }
            EventKind::RoomLeft { room } => {
                w.u8(event_tag::ROOM_LEFT);
                w.string(room);
            }
            EventKind::RoomMembers { room, members } => {
                w.u8(event_tag::ROOM_MEMBERS);
                w.string(room);
                w.u32(*members);
            }
            EventKind::Link {
                peer,
                state,
                detail,
            } => {
                w.u8(event_tag::LINK);
                w.peer(peer);
                w.u8(*state);
                w.string(detail);
            }
            EventKind::TunnelReady { peer, tcp, udp } => {
                w.u8(event_tag::TUNNEL_READY);
                w.peer(peer);
                w.ports(tcp);
                w.ports(udp);
            }
            EventKind::Forward {
                proto,
                listen,
                remote_port,
            } => {
                w.u8(event_tag::FORWARD);
                w.u8(*proto);
                w.string(listen);
                w.u16(*remote_port);
            }
            EventKind::EventsDropped { count } => {
                w.u8(event_tag::EVENTS_DROPPED);
                w.u64(*count);
            }
        }
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        if r.u8()? != TAG_EVENT {
            return Err(DecodeError::UnknownTag(body.first().copied().unwrap_or(0)));
        }
        let event_seq = r.u64()?;
        let tag = r.u8()?;
        let kind = match tag {
            event_tag::AGENT_STARTED => EventKind::AgentStarted {
                pid: r.u32()?,
                agent: r.string()?,
            },
            event_tag::ROOM_JOINED => EventKind::RoomJoined {
                room: r.string()?,
                members: r.u32()?,
            },
            event_tag::ROOM_LEFT => EventKind::RoomLeft { room: r.string()? },
            event_tag::ROOM_MEMBERS => EventKind::RoomMembers {
                room: r.string()?,
                members: r.u32()?,
            },
            event_tag::LINK => EventKind::Link {
                peer: r.peer()?,
                state: r.u8()?,
                detail: r.string()?,
            },
            event_tag::TUNNEL_READY => EventKind::TunnelReady {
                peer: r.peer()?,
                tcp: r.ports()?,
                udp: r.ports()?,
            },
            event_tag::FORWARD => EventKind::Forward {
                proto: r.u8()?,
                listen: r.string()?,
                remote_port: r.u16()?,
            },
            event_tag::EVENTS_DROPPED => EventKind::EventsDropped { count: r.u64()? },
            other => return Err(DecodeError::UnknownEvent(other)),
        };
        r.finish()?;
        Ok(Self { event_seq, kind })
    }
}

/// 本端协议版本（`GetVersion` 与启动横幅共用）
pub fn local_protocol() -> (u16, u16) {
    (PROTOCOL_MAJOR, PROTOCOL_MINOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room_req() -> RoomRequest {
        RoomRequest {
            room_code: "U/C2G9-GYET-311W-R636".into(),
            seeds: vec!["udp://127.0.0.1:11010".into()],
            observers: vec!["127.0.0.1:3478".into()],
            storage: Some("udp://127.0.0.1:11010".into()),
            expose: vec!["25565".into(), "8080=10.0.0.5:9001".into()],
            forward: vec!["25566:25565".into()],
            expose_udp: vec!["19132".into()],
            forward_udp: vec!["19133:19132".into()],
        }
    }

    #[test]
    fn every_command_roundtrips() {
        let requests = vec![
            Command::GetVersion,
            Command::GetCapabilities,
            Command::GetSnapshot,
            Command::StartRoom(room_req()),
            Command::JoinRoom(RoomRequest::default()),
            Command::LeaveRoom(LeaveRoom {
                room_code: "U/AAAA-BBBB".into(),
            }),
            Command::WatchEvents(Watch { since_seq: 42 }),
            Command::ShutdownAgent,
        ];
        for (i, command) in requests.into_iter().enumerate() {
            let req = Request {
                request_id: 1000 + i as u64,
                session_id: 7,
                deadline_ms: if i % 2 == 0 { Some(5000) } else { None },
                command,
            };
            let body = req.encode().unwrap();
            let got = Request::decode(&body).unwrap();
            assert_eq!(got, req);
        }
    }

    #[test]
    fn unknown_command_is_unsupported_not_garbage() {
        // 命令 tag 99 不存在：解码必须明确报 UnknownCommand(99)，而不是当作合法请求
        let mut body = Request {
            request_id: 9,
            session_id: 0,
            deadline_ms: None,
            command: Command::GetVersion,
        }
        .encode()
        .unwrap();
        // tag(1) + request_id(8) + session_id(8) + deadline flag(1) = 18，命令 tag 在 18
        body[18] = 99;
        assert_eq!(Request::decode(&body), Err(DecodeError::UnknownCommand(99)));
        // 即便解不出命令，也能捞回 request_id 以便回一条带 id 的 Unsupported
        assert_eq!(Request::peek_request_id(&body), Some(9));
    }

    #[test]
    fn reserved_command_tags_are_rejected() {
        for tag in [
            cmd::LIST_SESSIONS,
            cmd::SET_PORT_FORWARD,
            cmd::REMOVE_PORT_FORWARD,
            cmd::CANCEL_REQUEST,
        ] {
            let mut body = Request {
                request_id: 1,
                session_id: 0,
                deadline_ms: None,
                command: Command::GetVersion,
            }
            .encode()
            .unwrap();
            body[18] = tag;
            assert_eq!(Request::decode(&body), Err(DecodeError::UnknownCommand(tag)));
        }
    }

    #[test]
    fn truncated_request_rejected() {
        let body = Request {
            request_id: 1,
            session_id: 2,
            deadline_ms: Some(3),
            command: Command::GetSnapshot,
        }
        .encode()
        .unwrap();
        for cut in 0..body.len() {
            assert!(
                Request::decode(&body[..cut]).is_err(),
                "截断到 {cut} 字节必须被拒绝"
            );
        }
    }

    #[test]
    fn response_roundtrips_every_payload() {
        let snapshot = Snapshot {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            agent: "0.1.0".into(),
            uptime_ms: 12,
            subscribers: 1,
            dropped_events: 3,
            rooms: vec![RoomSnapshot {
                room: "U/C2G9-GYET-311W-R636".into(),
                members: 2,
                created: true,
                storage: "127.0.0.1:11010".into(),
                links: vec![LinkSnapshot {
                    peer: [7u8; 16],
                    state: link_state::UP,
                    detail: "carrier=udp".into(),
                }],
                forward: vec![ForwardSnapshot {
                    proto: proto::TCP,
                    listen: "127.0.0.1:25566".into(),
                    remote_port: 25565,
                }],
                expose: vec![ExposeSnapshot {
                    proto: proto::UDP,
                    port: 19132,
                    target: "127.0.0.1:19132".into(),
                }],
            }],
        };
        let payloads = vec![
            ResponsePayload::Empty,
            ResponsePayload::Version(VersionInfo {
                agent: "0.1.0".into(),
                protocol_major: 1,
                protocol_minor: 0,
                pid: 4242,
                uptime_ms: 9,
            }),
            ResponsePayload::Capabilities(Capabilities {
                bits: caps::STAGE1,
                max_rooms: 4,
                control_queue: 128,
                event_queue: 256,
            }),
            ResponsePayload::Snapshot(snapshot),
            ResponsePayload::Room(RoomSummary {
                room: "U/C2G9-GYET-311W-R636".into(),
                members: 1,
                created: false,
                storage: "127.0.0.1:11010".into(),
            }),
            ResponsePayload::Error("房间码为空".into()),
        ];
        for (i, payload) in payloads.into_iter().enumerate() {
            let resp = Response {
                request_id: 10 + i as u64,
                status: Status::Ok,
                payload,
            };
            let body = resp.encode().unwrap();
            assert_eq!(Response::decode(&body).unwrap(), resp);
        }
    }

    #[test]
    fn every_event_roundtrips() {
        let kinds = vec![
            EventKind::AgentStarted {
                pid: 1,
                agent: "0.1.0".into(),
            },
            EventKind::RoomJoined {
                room: "U/A".into(),
                members: 2,
            },
            EventKind::RoomLeft {
                room: "U/A".into(),
            },
            EventKind::RoomMembers {
                room: "U/A".into(),
                members: 3,
            },
            EventKind::Link {
                peer: [1u8; 16],
                state: link_state::LOST,
                detail: "timeout".into(),
            },
            EventKind::TunnelReady {
                peer: [2u8; 16],
                tcp: vec![25565],
                udp: vec![19132, 19133],
            },
            EventKind::Forward {
                proto: proto::TCP,
                listen: "127.0.0.1:25566".into(),
                remote_port: 25565,
            },
            EventKind::EventsDropped { count: 17 },
        ];
        for (i, kind) in kinds.into_iter().enumerate() {
            let ev = Event {
                event_seq: i as u64 + 1,
                kind,
            };
            let body = ev.encode().unwrap();
            assert_eq!(Event::decode(&body).unwrap(), ev);
        }
    }

    #[test]
    fn unknown_event_tag_rejected() {
        let mut body = Event {
            event_seq: 1,
            kind: EventKind::EventsDropped { count: 1 },
        }
        .encode()
        .unwrap();
        body[9] = 200; // tag(1) + seq(8) 之后是事件 tag
        assert_eq!(Event::decode(&body), Err(DecodeError::UnknownEvent(200)));
    }

    #[test]
    fn state_changing_classification_matches_design() {
        assert!(!Command::GetVersion.is_state_changing());
        assert!(!Command::GetSnapshot.is_state_changing());
        assert!(!Command::WatchEvents(Watch { since_seq: 0 }).is_state_changing());
        assert!(Command::StartRoom(RoomRequest::default()).is_state_changing());
        assert!(Command::JoinRoom(RoomRequest::default()).is_state_changing());
        assert!(Command::LeaveRoom(LeaveRoom {
            room_code: "U/A".into()
        })
        .is_state_changing());
        assert!(Command::ShutdownAgent.is_state_changing());
    }
}
