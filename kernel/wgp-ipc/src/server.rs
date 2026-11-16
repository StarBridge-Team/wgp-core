//! 连接驱动：一条 IPC 连接的生命周期（读 → 有界控制队列 → 串行执行 → 有界出口）。
//!
//! ## 为什么是这个形状
//!
//! - **读写分三个任务**：读任务只做「拆帧 + 入队」，绝不执行命令。命令可能很慢（`JoinRoom`
//!   要等打洞），如果读任务顺手执行，队列就形同虚设，`Busy` 永远不会出现，调用方只能干等。
//! - **控制队列有界（128）**：满了立刻回 `Busy`，让调用方退避重试；绝不 `spawn` 一个任务去
//!   消化积压（那等于无界并发，20 §5 明令禁止）。
//! - **出口有界（256）**：事件与响应共用一条出口。对端不读，我们就不无限攒内存。
//! - **deadline**：入队前判一次（`0` 毫秒即过期），执行时套 `timeout`。超时**不会**回滚已经
//!   发生的事——状态改变类命令按房间名幂等，调用方再发一次即可收敛（见 agent README 残余风险）。
//! - **未知次版本**：只读命令照常服务，**状态改变类命令一律 `Unsupported`**。新版本对端应该先
//!   读 `GetVersion` 再决定，而不是被老 agent 用旧语义执行一遍危险命令（20 §4「不能静默降级」）。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::frame::{self, FrameHeader, MAX_BODY, PROTOCOL_MINOR};
use crate::message::{Request, Response, Status};
use crate::wire::DecodeError;

/// 单连接控制队列容量（20 §5 建议值）
pub const CONTROL_QUEUE: usize = 128;
/// 单连接出口（响应 + 事件）容量
pub const OUT_QUEUE: usize = 256;
/// 单个请求的 deadline 上限：再长就没有意义了（调用方早就该重试）
const DEADLINE_CAP_MS: u64 = 24 * 60 * 60 * 1000;
/// 收尾时等出口写完的时间上限
const FLUSH_WAIT: Duration = Duration::from_secs(1);

/// 队列容量。测试用小值验证 `Busy`，agent 用默认值。
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub control_queue: usize,
    pub out_queue: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            control_queue: CONTROL_QUEUE,
            out_queue: OUT_QUEUE,
        }
    }
}

/// 一条连接的计数（结构化日志用；不含任何 payload）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// 成功解码并入队的请求数
    pub requests: u64,
    /// 因控制队列满而回的 `Busy` 数
    pub busy: u64,
    /// 被拒绝的帧/消息数（oversize、未知命令、字段畸形……）
    pub rejected_frames: u64,
    /// 其中因「未知命令/未知次版本」被记 `Unsupported` 的数
    pub unsupported: u64,
    /// deadline 过期数
    pub deadline_exceeded: u64,
    /// 出口拥塞导致丢弃的帧数（响应或事件）
    pub dropped_out: u64,
}

impl ConnStats {
    fn merge(&mut self, other: ConnStats) {
        self.requests += other.requests;
        self.busy += other.busy;
        self.rejected_frames += other.rejected_frames;
        self.unsupported += other.unsupported;
        self.deadline_exceeded += other.deadline_exceeded;
        self.dropped_out += other.dropped_out;
    }
}

/// 交给业务层（agent）的连接句柄。
///
/// 它唯一的额外能力是「往这条连接上再推一帧」——事件订阅就是把这个句柄的出口登记到事件总线上。
/// 业务层拿不到 socket，也就无法绕过有界队列。
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// 连接序号（进程内自增，日志与订阅登记用）
    pub id: u64,
    /// 对端人类可读描述（`uid=1000,pid=4242` / `pid=4242`）
    pub peer: String,
    out: mpsc::Sender<Arc<Vec<u8>>>,
}

impl ConnCtx {
    /// 出口的发送端（事件总线保存它 = 这个订阅者的有界事件队列）
    pub fn out(&self) -> mpsc::Sender<Arc<Vec<u8>>> {
        self.out.clone()
    }

    /// 非阻塞推一帧。返回 `false` 表示出口已满：**调用方必须丢弃并计数**，不得重试到无界。
    pub fn try_emit(&self, body: Arc<Vec<u8>>) -> bool {
        self.out.try_send(body).is_ok()
    }
}

/// 业务层要实现的唯一接口。
pub type ResponseFuture<'a> = Pin<Box<dyn Future<Output = Response> + Send + 'a>>;

pub trait Handler: Send + Sync + 'static {
    fn handle<'a>(&'a self, request: Request, ctx: ConnCtx) -> ResponseFuture<'a>;
}

/// 已解码、待执行的一条请求（连同它的帧头，用来判次版本）
pub struct Incoming {
    pub header: FrameHeader,
    pub request: Request,
}

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// 驱动一条连接直到对端关闭。正常关闭返回 `Ok(stats)`；致命错误返回 `Err`。
pub async fn serve_connection<S>(
    stream: S,
    peer: String,
    handler: Arc<dyn Handler>,
    limits: Limits,
) -> io::Result<ConnStats>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Incoming>(limits.control_queue.max(1));
    let (out_tx, mut out_rx) = mpsc::channel::<Arc<Vec<u8>>>(limits.out_queue.max(1));

    // 写任务：只负责把出口里的帧按序写出
    let mut write_task = tokio::spawn(async move {
        while let Some(body) = out_rx.recv().await {
            frame::write_frame(&mut writer, &body).await?;
        }
        writer.flush().await
    });

    // 读任务：拆帧 → 解码 → 入控制队列（满则 Busy）
    let reader_out = out_tx.clone();
    let read_task = tokio::spawn(async move {
        let mut stats = ConnStats::default();
        loop {
            let (header, body) = match frame::read_frame(&mut reader, MAX_BODY).await {
                Ok(v) => v,
                Err(e) => {
                    if e.is_fatal() {
                        stats.rejected_frames += 1;
                    }
                    // 致命（魔数/主版本/oversize）与对端正常关闭都结束这条连接的读侧
                    break;
                }
            };
            let request = match Request::decode(&body) {
                Ok(request) => request,
                Err(error) => {
                    stats.rejected_frames += 1;
                    let status = match error {
                        DecodeError::UnknownCommand(_) => Status::Unsupported,
                        _ => Status::BadRequest,
                    };
                    if status == Status::Unsupported {
                        stats.unsupported += 1;
                    }
                    // 命令不认识 ≠ 要断连接：对端可能只是版本更新。回一条带 request_id 的
                    // 应答后继续读（body 已完整读出，不破坏帧边界）。
                    let request_id = Request::peek_request_id(&body).unwrap_or(0);
                    let response = Response::error(request_id, status, error.to_string());
                    if let Ok(encoded) = response.encode() {
                        if reader_out.try_send(Arc::new(encoded)).is_err() {
                            stats.dropped_out += 1;
                        }
                    }
                    continue;
                }
            };
            match ctrl_tx.try_send(Incoming { header, request }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(incoming)) => {
                    // 控制队列满：明确告诉调用方退避，而不是把他排在无界队列里
                    stats.busy += 1;
                    let response = Response::error(
                        incoming.request.request_id,
                        Status::Busy,
                        format!("控制队列已满（容量 {}）：请退避后重试", limits.control_queue),
                    );
                    if let Ok(encoded) = response.encode() {
                        if reader_out.try_send(Arc::new(encoded)).is_err() {
                            stats.dropped_out += 1;
                        }
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
        stats
    });

    // 执行任务（当前任务）：一条连接上的命令串行执行，避免状态改变类命令互相踩
    let ctx = ConnCtx {
        id,
        peer,
        out: out_tx.clone(),
    };
    drop(out_tx);
    let mut stats = ConnStats::default();
    while let Some(incoming) = ctrl_rx.recv().await {
        stats.requests += 1;
        let response = dispatch(&handler, incoming, &ctx, &mut stats).await;
        let Ok(encoded) = response.encode() else {
            stats.rejected_frames += 1;
            continue;
        };
        // 这里 await 是**故意**的：出口满了就该让执行侧停下来（背压），
        // 而不是继续跑下一个命令、把结果丢掉。
        if ctx.out.send(Arc::new(encoded)).await.is_err() {
            break;
        }
    }

    let read_stats = read_task.await.unwrap_or_default();
    stats.merge(read_stats);
    // 给出口一点时间把已排队的帧写完，然后收工（否则断开时最后一条响应会丢）
    if tokio::time::timeout(FLUSH_WAIT, &mut write_task).await.is_err() {
        write_task.abort();
    }
    Ok(stats)
}

async fn dispatch(
    handler: &Arc<dyn Handler>,
    incoming: Incoming,
    ctx: &ConnCtx,
    stats: &mut ConnStats,
) -> Response {
    let Incoming { header, request } = incoming;
    let request_id = request.request_id;

    // 未知次版本：只读命令可以继续，状态改变类命令一律拒绝（绝不静默降级）
    if header.minor > PROTOCOL_MINOR && request.command.is_state_changing() {
        stats.unsupported += 1;
        return Response::error(
            request_id,
            Status::Unsupported,
            format!(
                "对端协议次版本 {} 高于本端 {}：状态改变类命令拒绝执行（先读 GetVersion 再决定）",
                header.minor, PROTOCOL_MINOR
            ),
        );
    }

    let limit = match request.deadline_ms {
        None => return handler.handle(request, ctx.clone()).await,
        Some(0) => {
            stats.deadline_exceeded += 1;
            return Response::error(
                request_id,
                Status::DeadlineExceeded,
                "deadline_ms=0：请求在入队时已过期，未执行",
            );
        }
        Some(ms) => Duration::from_millis(ms.min(DEADLINE_CAP_MS)),
    };

    let future = handler.handle(request, ctx.clone());
    match tokio::time::timeout(limit, future).await {
        Ok(response) => response,
        Err(_) => {
            stats.deadline_exceeded += 1;
            Response::error(
                request_id,
                Status::DeadlineExceeded,
                "请求超时：命令可能仍在后台继续（状态改变类命令按房间名幂等，可重发）",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_match_design_doc() {
        let l = Limits::default();
        assert_eq!(l.control_queue, 128);
        assert_eq!(l.out_queue, 256);
    }

    #[test]
    fn stats_merge_adds_every_counter() {
        let mut a = ConnStats {
            requests: 1,
            busy: 2,
            ..Default::default()
        };
        a.merge(ConnStats {
            requests: 10,
            busy: 20,
            dropped_out: 3,
            ..Default::default()
        });
        assert_eq!(a.requests, 11);
        assert_eq!(a.busy, 22);
        assert_eq!(a.dropped_out, 3);
    }
}
