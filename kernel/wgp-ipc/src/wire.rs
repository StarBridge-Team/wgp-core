//! 极小的显式编解码原语：小端定宽整数 + `u16` 长度前缀的字符串/向量。
//!
//! 只用这一组原语拼消息，是为了让「读多少字节」在代码里一眼可数：本项目不用 serde/protobuf
//! 描述自有线格式，任何一处隐式长度都可能在对端被当成内存炸弹。所有读函数返回 `Option` 语义的
//! `Result<_, DecodeError>`，越界即失败，绝不读越界、绝不 panic。

use std::fmt;

/// 单段字符串/字节块的上限（`u16` 长度前缀）
pub const MAX_FIELD: usize = u16::MAX as usize;
/// 单个向量的元素个数上限。对端可以用几十字节声明 65535 个元素，这里直接挡掉。
pub const MAX_ITEMS: usize = 4096;

/// 编码错误：只在「我们自己的数据超出线格式上界」时出现（正常路径不可达）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// 单段字节/字符串超过 65535 字节
    FieldTooLong,
    /// 向量元素过多
    TooManyItems,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::FieldTooLong => write!(f, "字段超过 {MAX_FIELD} 字节上限"),
            EncodeError::TooManyItems => write!(f, "向量元素超过 {MAX_ITEMS} 个上限"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// 解码错误：对端数据不可信，全部走这个枚举，不 panic。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 声明的长度超出了剩余字节
    Truncated,
    /// 字符串不是合法 UTF-8（本协议全部字符串都是 UTF-8）
    BadUtf8,
    /// 消息主体 tag 不认识（非 Request/Response/Event）
    UnknownTag(u8),
    /// 命令 tag 不认识（或属于阶段 1 未实现的保留命令）
    UnknownCommand(u8),
    /// 响应载荷 tag 不认识
    UnknownPayload(u8),
    /// 事件 tag 不认识
    UnknownEvent(u8),
    /// 向量元素个数超过上限
    TooManyItems,
    /// 字段解完了但还有剩余字节（本实现要求自洽，见 crate 文档）
    Trailing,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "字段声明长度超过剩余字节"),
            DecodeError::BadUtf8 => write!(f, "字符串不是合法 UTF-8"),
            DecodeError::UnknownTag(t) => write!(f, "未知消息 tag {t}"),
            DecodeError::UnknownCommand(t) => write!(f, "未知命令 tag {t}"),
            DecodeError::UnknownPayload(t) => write!(f, "未知响应载荷 tag {t}"),
            DecodeError::UnknownEvent(t) => write!(f, "未知事件 tag {t}"),
            DecodeError::TooManyItems => write!(f, "向量元素个数超过上限"),
            DecodeError::Trailing => write!(f, "消息尾部有多余字节"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// 追加式写端。错误被记在内部（`finish` 统一报），这样每个字段写入点不必都套 `?`，
/// 但也不会静默截断——一旦越界，整条消息作废。
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
    err: Option<EncodeError>,
}

impl Writer {
    pub fn new(tag: u8) -> Self {
        let mut me = Self {
            buf: Vec::with_capacity(64),
            err: None,
        };
        me.u8(tag);
        me
    }

    fn fail(&mut self, e: EncodeError) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// 定长 16 字节（PeerId）
    pub fn peer(&mut self, v: &[u8; 16]) {
        self.raw(v);
    }

    /// `u16` 长度前缀的 UTF-8 字符串
    pub fn string(&mut self, v: &str) {
        if v.len() > MAX_FIELD {
            self.fail(EncodeError::FieldTooLong);
            self.u16(0);
            return;
        }
        self.u16(v.len() as u16);
        self.raw(v.as_bytes());
    }

    pub fn opt_string(&mut self, v: Option<&str>) {
        match v {
            Some(s) => {
                self.u8(1);
                self.string(s);
            }
            None => self.u8(0),
        }
    }

    /// `u16` 元素个数 + 逐个 `u16` 长度前缀的字符串
    pub fn strings(&mut self, v: &[String]) {
        if v.len() > MAX_ITEMS {
            self.fail(EncodeError::TooManyItems);
            self.u16(0);
            return;
        }
        self.u16(v.len() as u16);
        for s in v {
            self.string(s);
        }
    }

    /// `u16` 元素个数 + 逐个 `u16` 值
    pub fn ports(&mut self, v: &[u16]) {
        if v.len() > MAX_ITEMS {
            self.fail(EncodeError::TooManyItems);
            self.u16(0);
            return;
        }
        self.u16(v.len() as u16);
        for p in v {
            self.u16(*p);
        }
    }

    pub fn finish(self) -> Result<Vec<u8>, EncodeError> {
        match self.err {
            Some(e) => Err(e),
            None => Ok(self.buf),
        }
    }
}

/// 读端。每个读函数都自己判边界。
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }

    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.raw(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.raw(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.raw(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.raw(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn peer(&mut self) -> Result<[u8; 16], DecodeError> {
        let b = self.raw(16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn string(&mut self) -> Result<String, DecodeError> {
        let n = self.u16()? as usize;
        let bytes = self.raw(n)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| DecodeError::BadUtf8)
    }

    pub fn opt_string(&mut self) -> Result<Option<String>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            _ => Err(DecodeError::Truncated),
        }
    }

    pub fn strings(&mut self) -> Result<Vec<String>, DecodeError> {
        let n = self.u16()? as usize;
        if n > MAX_ITEMS {
            return Err(DecodeError::TooManyItems);
        }
        let mut out = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            out.push(self.string()?);
        }
        Ok(out)
    }

    pub fn ports(&mut self) -> Result<Vec<u16>, DecodeError> {
        let n = self.u16()? as usize;
        if n > MAX_ITEMS {
            return Err(DecodeError::TooManyItems);
        }
        let mut out = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            out.push(self.u16()?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_roundtrip() {
        let mut w = Writer::new(7);
        w.u8(0xab);
        w.u16(0x1234);
        w.u32(0xdead_beef);
        w.u64(u64::MAX);
        w.string("房间码");
        w.opt_string(None);
        w.opt_string(Some("ip:port"));
        w.strings(&["a".into(), "b".into()]);
        w.ports(&[1, 65535]);
        let buf = w.finish().unwrap();

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u8().unwrap(), 0xab);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.string().unwrap(), "房间码");
        assert_eq!(r.opt_string().unwrap(), None);
        assert_eq!(r.opt_string().unwrap().as_deref(), Some("ip:port"));
        assert_eq!(r.strings().unwrap(), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(r.ports().unwrap(), vec![1, 65535]);
        assert!(r.finish().is_ok());
    }

    #[test]
    fn truncated_length_prefix_is_error() {
        // 声明 8 字节字符串但只给 3 字节
        let buf = [6u8, 0x08, 0x00, b'a', b'b', b'c'];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 6);
        assert_eq!(r.string(), Err(DecodeError::Truncated));
    }

    #[test]
    fn bad_utf8_is_error() {
        // 长度声明 2 字节、内容非法 UTF-8：先验长度再验编码
        let buf = [0x02, 0x00, 0xff, 0xfe];
        let mut r = Reader::new(&buf);
        assert_eq!(r.string(), Err(DecodeError::BadUtf8));
        // 长度超出剩余字节：先报 Truncated（不做越界读）
        let buf = [0xff, 0xfe];
        let mut r = Reader::new(&buf);
        assert_eq!(r.string(), Err(DecodeError::Truncated));
    }

    #[test]
    fn vector_count_bomb_rejected() {
        // 声明 5000 个元素：立刻 TooManyItems，不做 5000 次尝试
        let buf = [0x88, 0x13];
        let mut r = Reader::new(&buf);
        assert_eq!(r.strings(), Err(DecodeError::TooManyItems));
        let mut r = Reader::new(&buf);
        assert_eq!(r.ports(), Err(DecodeError::TooManyItems));
    }

    #[test]
    fn trailing_bytes_reported() {
        let mut w = Writer::new(1);
        w.u8(2);
        let mut buf = w.finish().unwrap();
        buf.push(0);
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u8().unwrap(), 2);
        assert_eq!(r.finish(), Err(DecodeError::Trailing));
    }
}
