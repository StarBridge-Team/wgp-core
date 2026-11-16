//! 折跃门本机控制面 IPC（IPC v1）。
//!
//! 这是 20 文档（多进程运行与跨进程通信方案）阶段 1 的协议与传输层：**只给本机同一用户的
//! 进程之间**用，承载 UI/CLI ↔ `wgp-agent` 的控制面。数据面（TUN、ET 隧道）不在本 crate。
//!
//! ```text
//!   帧：magic "WGPI" | major(u16 LE) | minor(u16 LE) | flags(u16 LE) | body_len(u32 LE) | body
//!   body：Request(TAG=1) | Response(TAG=2) | Event(TAG=3)
//! ```
//!
//! ## 模块划分
//!
//! - [`frame`]：定长头 + 1 MiB body 上限；未知主版本直接拒连。
//! - [`wire`]：显式小端编解码原语（无 serde/protobuf；所有读函数返回 `Result`）。
//! - [`message`]：版本化消息（请求信封 / 命令 / 响应 / 事件）。
//! - [`transport`]：本机端点与 ACL（UDS peer-cred / 命名管道受限 DACL）。
//! - [`server`]：连接驱动，有界队列（控制 128 / 出口 256）、`Busy`、deadline。
//! - [`client`]：最小客户端（`wgp-agent ping` 与集成测试用）。
//!
//! ## 本版本明确**不做**的事
//!
//! - 没有方法级鉴权（只有传输层的「同一用户」）；没有启动时一次性 token；没有 IPC 重放保护。
//! - 没有事件重放缓冲：重连后靠 `GetSnapshot` 重建（20 §5 的要求就是这样）。
//! - 没有跨主机/容器场景的 TLS（20 §6 要求那属于另一套机制，默认关闭）。
//!
//! 这些都在 `client/wgp-agent/README.md` 的「残余风险」里写明，避免被误当成已交付能力。

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod client;
pub mod frame;
pub mod message;
pub mod server;
pub mod transport;
pub mod wire;

pub use client::{Client, Inbound};
pub use frame::{
    FrameError, FrameHeader, HEADER_LEN, MAGIC, MAX_BODY, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
pub use message::{
    caps, cmd, link_state, proto, status, Capabilities, Command, Event, EventKind, LeaveRoom,
    Request, Response, ResponsePayload, RoomRequest, RoomSnapshot, Snapshot, Status, VersionInfo,
    Watch,
};
pub use server::{serve_connection, ConnCtx, ConnStats, Handler, Limits, ResponseFuture};
pub use transport::Endpoint;
pub use wire::{DecodeError, EncodeError};

/// 本 crate 的版本（`GetVersion` 里报告的 agent 版本用得上）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
