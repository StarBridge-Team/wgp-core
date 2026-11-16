//! 帧层：`magic(4) = "WGPI" | major(u16 LE) | minor(u16 LE) | flags(u16 LE) | body_len(u32 LE) | body`。
//!
//! 为什么固定头而不是自描述格式：控制面要在最便宜的路径上拒绝垃圾输入。14 字节定长头让「这不是
//! 我们的流」「这个版本我不认识」「这个 body 太大」三类致命错误在任何一次分配之前就能判定
//! （20 文档 §3/§4）。手写编解码是本项目的硬约束（自有线格式不用 serde/protobuf），所以这里
//! 的全部长度都是显式的、带上下界的。
//!
//! 校验顺序按 20 §4：**先长度，后 magic/version**。两者都是致命错误，先判长度可以避免拿着
//! 一个来自别的协议的 body_len 去做任何分配。

use std::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 帧魔数。`WGPI` = WGP IPC。不是这个字节序列的流直接断开，不做任何兼容尝试。
pub const MAGIC: [u8; 4] = *b"WGPI";
/// 协议主版本。不兼容的语义变更才动它；不认识的主版本拒绝连接（绝不猜测）。
pub const PROTOCOL_MAJOR: u16 = 1;
/// 协议次版本。只增可选字段/新命令时加一；未知次版本见 [`crate::server`] 的严格策略。
pub const PROTOCOL_MINOR: u16 = 0;
/// 单个帧 body 的上限（20 §3：一次 frame 最大 1 MiB）。控制面没有任何合法消息需要更大。
pub const MAX_BODY: usize = 1024 * 1024;
/// 定长头长度：4 + 2 + 2 + 2 + 4
pub const HEADER_LEN: usize = 14;
/// 保留位：当前必须为 0，接收方忽略（未知可选字段不改变语义）。
pub const FLAG_NONE: u16 = 0;

/// 帧头。`body_len` 是 body 的字节数，不含头自身。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub major: u16,
    pub minor: u16,
    pub flags: u16,
    pub body_len: u32,
}

impl FrameHeader {
    /// 用本端版本构造头部；body 超限返回 None（调用方应编码更小的消息，而不是截断）。
    pub fn for_body(body_len: usize) -> Option<Self> {
        if body_len > MAX_BODY {
            return None;
        }
        Some(Self {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            flags: FLAG_NONE,
            body_len: body_len as u32,
        })
    }

    /// 与本端主版本是否兼容（次版本不参与这个判断，见 [`crate::server`]）。
    pub fn is_compatible_major(&self) -> bool {
        self.major == PROTOCOL_MAJOR
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.major.to_le_bytes());
        out[6..8].copy_from_slice(&self.minor.to_le_bytes());
        out[8..10].copy_from_slice(&self.flags.to_le_bytes());
        out[10..14].copy_from_slice(&self.body_len.to_le_bytes());
        out
    }

    /// 解析定长头。顺序：长度上限 → magic → 主版本。
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::Short(bytes.len()));
        }
        let body_len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        // ① 先判长度：来自别的协议的 4 字节「长度」可能是个天文数字
        if body_len as usize > MAX_BODY {
            return Err(FrameError::Oversize {
                len: body_len,
                max: MAX_BODY,
            });
        }
        // ② 再确认这确实是 WGPI 流
        if bytes[0..4] != MAGIC {
            let mut got = [0u8; 4];
            got.copy_from_slice(&bytes[0..4]);
            return Err(FrameError::BadMagic(got));
        }
        // ③ 最后判版本：未知主版本拒绝（连接就此关闭，不做降级尝试）
        let major = u16::from_le_bytes([bytes[4], bytes[5]]);
        if major != PROTOCOL_MAJOR {
            return Err(FrameError::UnsupportedMajor(major));
        }
        Ok(Self {
            major,
            minor: u16::from_le_bytes([bytes[6], bytes[7]]),
            flags: u16::from_le_bytes([bytes[8], bytes[9]]),
            body_len,
        })
    }
}

/// 帧层错误。除 [`FrameError::Io`] 之外都是致命的：对端要么不是本协议，要么版本/尺寸不可接受。
#[derive(Debug)]
pub enum FrameError {
    /// 底层 IO 失败（含对端正常关闭导致的 UnexpectedEof）
    Io(io::Error),
    /// 头部不足 14 字节就断了
    Short(usize),
    /// body 超过 [`MAX_BODY`]
    Oversize { len: u32, max: usize },
    /// 魔数不对：这不是 WGPI 流
    BadMagic([u8; 4]),
    /// 主版本不认识：拒绝连接（20 §4）
    UnsupportedMajor(u16),
}

impl FrameError {
    /// 是否意味着「必须立刻断开」——除 IO/Eof 之外全部是。
    pub fn is_fatal(&self) -> bool {
        !matches!(self, FrameError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof)
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "帧 IO 错误：{e}"),
            FrameError::Short(n) => write!(f, "帧头不足：只有 {n} 字节（需要 {HEADER_LEN}）"),
            FrameError::Oversize { len, max } => write!(f, "帧 body 过大：{len} 字节（上限 {max}）"),
            FrameError::BadMagic(got) => {
                write!(f, "魔数不对：{got:02x?}（期望 {MAGIC:02x?}）")
            }
            FrameError::UnsupportedMajor(m) => {
                write!(f, "不支持的协议主版本 {m}（本端只支持 {PROTOCOL_MAJOR}）")
            }
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// 读一个完整帧（头 + body）。超限的帧**不会被读进来**：先判头，直接报错。
pub async fn read_frame<R>(
    reader: &mut R,
    max_body: usize,
) -> Result<(FrameHeader, Vec<u8>), FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; HEADER_LEN];
    reader.read_exact(&mut head).await?;
    let header = FrameHeader::decode(&head)?;
    if header.body_len as usize > max_body {
        return Err(FrameError::Oversize {
            len: header.body_len,
            max: max_body,
        });
    }
    let mut body = vec![0u8; header.body_len as usize];
    reader.read_exact(&mut body).await?;
    Ok((header, body))
}

/// 用本端版本写一个帧。
pub async fn write_frame<W>(writer: &mut W, body: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let header = FrameHeader::for_body(body.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "待写帧体超过 1 MiB 上限"))?;
    write_frame_with(writer, header, body).await
}

/// 写一个指定头的帧（测试与未来握手需要显式指定 minor）。
pub async fn write_frame_with<W>(writer: &mut W, header: FrameHeader, body: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if body.len() != header.body_len as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "帧头 body_len 与实际 body 长度不一致",
        ));
    }
    writer.write_all(&header.encode()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn header_roundtrip() {
        let h = FrameHeader::for_body(1234).expect("1 KiB 以内必须能构造头");
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..4], b"WGPI");
        assert_eq!(FrameHeader::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn oversize_header_rejected_before_body() {
        let h = FrameHeader {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            flags: 0,
            body_len: (MAX_BODY as u32) + 1,
        };
        match FrameHeader::decode(&h.encode()) {
            Err(FrameError::Oversize { len, max }) => {
                assert_eq!(len as usize, MAX_BODY + 1);
                assert_eq!(max, MAX_BODY);
            }
            other => panic!("应报 Oversize，实得 {other:?}"),
        }
        // 恰好 1 MiB 是允许的（边界不误杀）
        let ok = FrameHeader {
            body_len: MAX_BODY as u32,
            ..h
        };
        assert!(FrameHeader::decode(&ok.encode()).is_ok());
    }

    #[test]
    fn unknown_major_rejected() {
        let h = FrameHeader {
            major: 2,
            minor: 0,
            flags: 0,
            body_len: 0,
        };
        match FrameHeader::decode(&h.encode()) {
            Err(FrameError::UnsupportedMajor(2)) => {}
            other => panic!("应报 UnsupportedMajor(2)，实得 {other:?}"),
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = FrameHeader::for_body(0).unwrap().encode();
        bytes[0..4].copy_from_slice(b"HTTP");
        match FrameHeader::decode(&bytes) {
            Err(FrameError::BadMagic(got)) => assert_eq!(&got, b"HTTP"),
            other => panic!("应报 BadMagic，实得 {other:?}"),
        }
    }

    #[test]
    fn short_header_rejected() {
        assert!(matches!(
            FrameHeader::decode(&[0u8; 5]),
            Err(FrameError::Short(5))
        ));
    }

    #[tokio::test]
    async fn frame_roundtrip_over_stream() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let body = b"\x01\x02\x03hello".to_vec();
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &body).await.unwrap();
        });
        let (header, got) = read_frame(&mut b, MAX_BODY).await.unwrap();
        writer.await.unwrap();
        assert_eq!(header.major, PROTOCOL_MAJOR);
        assert_eq!(header.minor, PROTOCOL_MINOR);
        assert_eq!(got, b"\x01\x02\x03hello");
    }

    #[tokio::test]
    async fn oversize_body_is_not_read() {
        // 头声明 2 MiB：读端必须立刻报错，不能尝试分配/读取 2 MiB
        let (mut a, mut b) = tokio::io::duplex(64);
        let h = FrameHeader {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            flags: 0,
            body_len: (2 * MAX_BODY) as u32,
        };
        tokio::spawn(async move {
            let _ = a.write_all(&h.encode()).await;
        });
        match read_frame(&mut b, MAX_BODY).await {
            Err(FrameError::Oversize { len, .. }) => assert_eq!(len as usize, 2 * MAX_BODY),
            other => panic!("应报 Oversize，实得 {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_body_is_io_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let h = FrameHeader::for_body(8).unwrap();
        tokio::spawn(async move {
            let _ = a.write_all(&h.encode()).await;
            let _ = a.write_all(b"short").await;
            drop(a);
        });
        match read_frame(&mut b, MAX_BODY).await {
            Err(FrameError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("应报 Io(UnexpectedEof)，实得 {other:?}"),
        }
    }
}
