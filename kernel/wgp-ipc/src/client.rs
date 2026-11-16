//! 极小的 IPC 客户端（agent 的 `ping` 子命令与集成测试共用）。
//!
//! 这里**不做**连接池、重连、请求多路复用：阶段 1 的调用方（CLI/GUI）自己决定重连策略，
//! 重连后用 `GetSnapshot` 重建状态（20 §5）。库只保证「一问一答」与「按帧读」两件事清楚。

use std::io;

use tokio::io::{ReadHalf, WriteHalf};

use crate::frame::{self, MAX_BODY};
use crate::message::{Event, Request, Response, TAG_EVENT, TAG_RESPONSE};
use crate::transport::{self, BoxStream, Endpoint};
use crate::wire::DecodeError;

/// 从 agent 收到的一帧（响应或事件）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Response(Response),
    Event(Event),
}

/// IPC 客户端
pub struct Client {
    reader: ReadHalf<BoxStream>,
    writer: WriteHalf<BoxStream>,
}

impl Client {
    /// 连接本机端点。失败说明 agent 没在跑（或 ACL 把你挡在外面）。
    pub async fn connect(endpoint: &Endpoint) -> io::Result<Self> {
        let stream = transport::connect(endpoint).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self { reader, writer })
    }

    /// 发一条请求（不等待应答）
    pub async fn send(&mut self, request: &Request) -> io::Result<()> {
        let body = request
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        frame::write_frame(&mut self.writer, &body)
            .await
            .map_err(|e| io::Error::new(e.kind(), e.to_string()))
    }

    /// 读下一帧
    pub async fn recv(&mut self) -> io::Result<Inbound> {
        let (_header, body) = frame::read_frame(&mut self.reader, MAX_BODY)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        match body.first().copied() {
            Some(TAG_RESPONSE) => Response::decode(&body)
                .map(Inbound::Response)
                .map_err(decode_error),
            Some(TAG_EVENT) => Event::decode(&body).map(Inbound::Event).map_err(decode_error),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("收到了未知消息 tag {other:?}"),
            )),
        }
    }

    /// 一问一答。中途收到的事件会被丢弃——需要事件的调用方应当自己 `send` + `recv`。
    pub async fn call(&mut self, request: &Request) -> io::Result<Response> {
        self.send(request).await?;
        loop {
            match self.recv().await? {
                Inbound::Response(response) if response.request_id == request.request_id => {
                    return Ok(response)
                }
                // 旧请求的迟到响应 / 本连接订阅的事件：跳过（事件不该阻塞一问一答）
                Inbound::Response(_) | Inbound::Event(_) => continue,
            }
        }
    }

    /// 关闭写侧（让 agent 看到 EOF）
    pub async fn shutdown(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.writer.shutdown().await
    }
}

fn decode_error(e: DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
