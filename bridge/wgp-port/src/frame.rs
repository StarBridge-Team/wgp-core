//! 帧编解码：链路层帧（可靠层报文内）与复用层帧（可靠字节流内）。
//!
//! 纪律同 wgp-proto：定长手写、多字节大端、解码失败返回 None/Err、绝不 panic。
//!
//! 分层：
//!  - 链路层帧：一个隧道报文（AEAD 明文）内的若干帧——ACK / STREAM / DGRAM / CLOSE，
//!    只在 UDP 载体上使用（TCP 载体本身可靠有序，不需要）。
//!  - 复用层帧：两种载体上完全一致的可靠字节流里的帧序列——
//!    `type(1) | body_len(2) | body`。未知类型按长度跳过（前向兼容）。
//!  - 数据报与关闭不属复用层帧：它们由链路层承载（UDP 上是 DGRAM/CLOSE 链路帧，
//!    TCP 上是对应类型的记录），数据报因此不受可靠流的队头阻塞影响。

/// 链路层帧类型
pub(crate) mod link_type {
    pub const ACK: u8 = 0x01;
    pub const STREAM: u8 = 0x02;
    pub const DGRAM: u8 = 0x03;
    pub const CLOSE: u8 = 0x04;
}

/// 一个 ACK 帧最多携带的区间数（含首区间）
pub(crate) const MAX_ACK_RANGES: usize = 16;
/// ACK 帧最大编码长度：type + largest + delay + first + n + (n-1)×4
pub(crate) const ACK_FRAME_MAX: usize = 1 + 8 + 2 + 2 + 1 + (MAX_ACK_RANGES - 1) * 4;
/// STREAM 帧头：type + offset + len
pub(crate) const STREAM_OVERHEAD: usize = 1 + 8 + 2;
/// DGRAM 帧头：type + len
pub(crate) const DGRAM_OVERHEAD: usize = 1 + 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkFrame<'a> {
    /// 确认：`ranges` 为闭区间 (low, high)，自高向低排列
    Ack {
        largest: u64,
        delay_ms: u16,
        ranges: Vec<(u64, u64)>,
    },
    /// 可靠字节流片段
    Stream { offset: u64, data: &'a [u8] },
    /// 不可靠数据报（不重传）
    Dgram(&'a [u8]),
    /// 链路关闭
    Close(u8),
}

/// 编码 ACK 帧。`ranges` 为闭区间 (low, high)，必须自高向低、互不相邻；空列表不产出帧。
///
/// 线格式：`0x01 | largest(8) | delay_ms(2) | first(2) | n(1) | n × (gap(2), len(2))`
///  - 首区间 = `[largest - first, largest]`
///  - 其后每段：`high = 上一段 low - gap - 1`，`low = high - len`（gap = 两段间未确认的报文数）
///
/// 超出 u16 表达范围的部分被截断（更早的确认早已在先前的 ACK 里送达，丢弃无害）。
pub(crate) fn put_ack(out: &mut Vec<u8>, ranges: &[(u64, u64)], delay_ms: u16) {
    let Some(&(first_low, largest)) = ranges.first() else {
        return;
    };
    let first = (largest - first_low).min(u64::from(u16::MAX));
    out.push(link_type::ACK);
    out.extend_from_slice(&largest.to_be_bytes());
    out.extend_from_slice(&delay_ms.to_be_bytes());
    out.extend_from_slice(&(first as u16).to_be_bytes());
    let count_at = out.len();
    out.push(0);

    let mut count = 0u8;
    // 首区间被截断时，后续区间已无法正确表达（gap 会误覆盖已确认部分），就此打住
    if largest - first_low <= u64::from(u16::MAX) {
        let mut prev_low = first_low;
        for &(low, high) in ranges.iter().skip(1).take(MAX_ACK_RANGES - 1) {
            // 调用方保证 high + 1 < prev_low；违反则停止编码而不是产出坏帧
            let Some(gap) = prev_low.checked_sub(high).and_then(|d| d.checked_sub(1)) else {
                break;
            };
            if gap == 0 || gap > u64::from(u16::MAX) || high < low {
                break;
            }
            let len = (high - low).min(u64::from(u16::MAX));
            out.extend_from_slice(&(gap as u16).to_be_bytes());
            out.extend_from_slice(&(len as u16).to_be_bytes());
            count += 1;
            if high - low > u64::from(u16::MAX) {
                break;
            }
            prev_low = low;
        }
    }
    out[count_at] = count;
}

/// 编码 STREAM 帧：`0x02 | offset(8) | len(2) | data`
pub(crate) fn put_stream(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    debug_assert!(data.len() <= usize::from(u16::MAX));
    out.push(link_type::STREAM);
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// 编码 DGRAM 帧：`0x03 | len(2) | data`
pub(crate) fn put_dgram(out: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= usize::from(u16::MAX));
    out.push(link_type::DGRAM);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// 编码 CLOSE 帧：`0x04 | code(1)`
pub(crate) fn put_close(out: &mut Vec<u8>, code: u8) {
    out.push(link_type::CLOSE);
    out.push(code);
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if buf.len() < n {
        return None;
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Some(head)
}

fn take_u8(buf: &mut &[u8]) -> Option<u8> {
    take(buf, 1).map(|b| b[0])
}

fn take_u16(buf: &mut &[u8]) -> Option<u16> {
    take(buf, 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn take_u32(buf: &mut &[u8]) -> Option<u32> {
    take(buf, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn take_u64(buf: &mut &[u8]) -> Option<u64> {
    take(buf, 8).map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// 解析一个报文内的全部链路层帧；任何畸形（截断/未知类型/区间下溢）返回 None。
/// 报文已过 AEAD 认证，畸形只可能来自对端实现错误，调用方据此关闭链路。
pub(crate) fn parse_link_frames(mut buf: &[u8]) -> Option<Vec<LinkFrame<'_>>> {
    let mut frames = Vec::new();
    while !buf.is_empty() {
        match take_u8(&mut buf)? {
            link_type::ACK => {
                let largest = take_u64(&mut buf)?;
                let delay_ms = take_u16(&mut buf)?;
                let first = u64::from(take_u16(&mut buf)?);
                let count = usize::from(take_u8(&mut buf)?);
                if count > MAX_ACK_RANGES - 1 {
                    return None;
                }
                let mut ranges = Vec::with_capacity(count + 1);
                let mut low = largest.checked_sub(first)?;
                ranges.push((low, largest));
                for _ in 0..count {
                    let gap = u64::from(take_u16(&mut buf)?);
                    let len = u64::from(take_u16(&mut buf)?);
                    let high = low.checked_sub(gap)?.checked_sub(1)?;
                    low = high.checked_sub(len)?;
                    ranges.push((low, high));
                }
                frames.push(LinkFrame::Ack {
                    largest,
                    delay_ms,
                    ranges,
                });
            }
            link_type::STREAM => {
                let offset = take_u64(&mut buf)?;
                let len = usize::from(take_u16(&mut buf)?);
                let data = take(&mut buf, len)?;
                offset.checked_add(len as u64)?;
                frames.push(LinkFrame::Stream { offset, data });
            }
            link_type::DGRAM => {
                let len = usize::from(take_u16(&mut buf)?);
                frames.push(LinkFrame::Dgram(take(&mut buf, len)?));
            }
            link_type::CLOSE => frames.push(LinkFrame::Close(take_u8(&mut buf)?)),
            _ => return None,
        }
    }
    Some(frames)
}

// ---------------------------------------------------------------------------
// 复用层帧
// ---------------------------------------------------------------------------

/// 复用层协议版本（HELLO 携带；不兼容变更时递增）
pub const MUX_VERSION: u8 = 1;

/// 单个 DATA 帧最大数据长度
pub(crate) const MAX_DATA_FRAME: usize = 16 * 1024;
/// 复用层帧头：type + body_len
const MUX_HEADER: usize = 3;
/// HELLO 里每类端口列表的上限
pub(crate) const MAX_HELLO_PORTS: usize = 64;

mod mux_type {
    pub const HELLO: u8 = 0x01;
    pub const OPEN: u8 = 0x02;
    pub const DATA: u8 = 0x03;
    pub const FIN: u8 = 0x04;
    pub const RST: u8 = 0x05;
    pub const WINDOW: u8 = 0x06;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MuxFrame {
    /// 隧道建立后双方各发一次：版本 + 本端暴露的服务端口
    Hello {
        version: u8,
        tcp: Vec<u16>,
        udp: Vec<u16>,
    },
    /// 请求打开一条流，连向对端暴露的 `port`
    Open { id: u32, port: u16 },
    Data { id: u32, data: Vec<u8> },
    /// 发送方向结束（半关闭）
    Fin { id: u32 },
    /// 双向中止
    Rst { id: u32, code: u8 },
    /// 流量控制：再授予对端 `credit` 字节的发送额度
    Window { id: u32, credit: u32 },
}

fn put_ports(out: &mut Vec<u8>, ports: &[u16]) {
    let n = ports.len().min(MAX_HELLO_PORTS);
    out.push(n as u8);
    for p in &ports[..n] {
        out.extend_from_slice(&p.to_be_bytes());
    }
}

fn take_ports(buf: &mut &[u8]) -> Option<Vec<u16>> {
    let n = usize::from(take_u8(buf)?);
    if n > MAX_HELLO_PORTS {
        return None;
    }
    let mut ports = Vec::with_capacity(n);
    for _ in 0..n {
        ports.push(take_u16(buf)?);
    }
    Some(ports)
}

impl MuxFrame {
    /// 编码追加到 `out`。DATA 的载荷超长时截断（写端防御；调用方本就按上限切片）。
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&[0, 0, 0]);
        let kind = match self {
            MuxFrame::Hello { version, tcp, udp } => {
                out.push(*version);
                put_ports(out, tcp);
                put_ports(out, udp);
                mux_type::HELLO
            }
            MuxFrame::Open { id, port } => {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                mux_type::OPEN
            }
            MuxFrame::Data { id, data } => {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&data[..data.len().min(MAX_DATA_FRAME)]);
                mux_type::DATA
            }
            MuxFrame::Fin { id } => {
                out.extend_from_slice(&id.to_be_bytes());
                mux_type::FIN
            }
            MuxFrame::Rst { id, code } => {
                out.extend_from_slice(&id.to_be_bytes());
                out.push(*code);
                mux_type::RST
            }
            MuxFrame::Window { id, credit } => {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&credit.to_be_bytes());
                mux_type::WINDOW
            }
        };
        let body_len = (out.len() - start - MUX_HEADER) as u16;
        out[start] = kind;
        out[start + 1..start + 3].copy_from_slice(&body_len.to_be_bytes());
    }

    /// 解析一个帧体；None = 已知类型但帧体畸形
    fn parse(kind: u8, mut body: &[u8]) -> Option<Option<MuxFrame>> {
        let frame = match kind {
            mux_type::HELLO => {
                let version = take_u8(&mut body)?;
                let tcp = take_ports(&mut body)?;
                let udp = take_ports(&mut body)?;
                // 尾部允许有未来版本追加的字段：忽略
                MuxFrame::Hello { version, tcp, udp }
            }
            mux_type::OPEN => {
                let id = take_u32(&mut body)?;
                let port = take_u16(&mut body)?;
                MuxFrame::Open { id, port }
            }
            mux_type::DATA => {
                let id = take_u32(&mut body)?;
                if body.len() > MAX_DATA_FRAME {
                    return None;
                }
                MuxFrame::Data {
                    id,
                    data: body.to_vec(),
                }
            }
            mux_type::FIN => MuxFrame::Fin {
                id: take_u32(&mut body)?,
            },
            mux_type::RST => {
                let id = take_u32(&mut body)?;
                let code = take_u8(&mut body)?;
                MuxFrame::Rst { id, code }
            }
            mux_type::WINDOW => {
                let id = take_u32(&mut body)?;
                let credit = take_u32(&mut body)?;
                MuxFrame::Window { id, credit }
            }
            // 未知类型：按长度跳过（前向兼容）
            _ => return Some(None),
        };
        Some(Some(frame))
    }
}

/// 复用层帧解码错误（帧体畸形 → 协议违规，调用方关闭隧道）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MuxDecodeError;

/// 增量解码器：喂入任意切分的字节流，逐帧取出
#[derive(Default)]
pub(crate) struct MuxDecoder {
    buf: Vec<u8>,
    pos: usize,
}

impl MuxDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        // 已消费前缀过半即压缩，避免缓冲无界增长
        if self.pos > 0 && self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// 取下一帧；`Ok(None)` = 数据还不够一整帧
    pub fn next(&mut self) -> Result<Option<MuxFrame>, MuxDecodeError> {
        loop {
            let avail = &self.buf[self.pos..];
            if avail.len() < MUX_HEADER {
                return Ok(None);
            }
            let kind = avail[0];
            let body_len = usize::from(u16::from_be_bytes([avail[1], avail[2]]));
            if avail.len() < MUX_HEADER + body_len {
                return Ok(None);
            }
            let body = &avail[MUX_HEADER..MUX_HEADER + body_len];
            let parsed = MuxFrame::parse(kind, body);
            self.pos += MUX_HEADER + body_len;
            match parsed {
                Some(Some(frame)) => return Ok(Some(frame)),
                Some(None) => continue, // 未知类型已跳过
                None => return Err(MuxDecodeError),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 数据报载荷（UDP 端口转发）
// ---------------------------------------------------------------------------

/// 数据报方向：发往对端暴露的服务 / 服务回给转发口
pub(crate) const DGRAM_REQUEST: u8 = 0;
pub(crate) const DGRAM_REPLY: u8 = 1;
/// 数据报载荷头：kind(1) | port(2) | flow(4)
pub(crate) const DGRAM_HEADER: usize = 7;

pub(crate) fn encode_dgram(kind: u8, port: u16, flow: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DGRAM_HEADER + data.len());
    out.push(kind);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&flow.to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// 解出 (kind, port, flow, data)
pub(crate) fn decode_dgram(buf: &[u8]) -> Option<(u8, u16, u32, &[u8])> {
    if buf.len() < DGRAM_HEADER {
        return None;
    }
    let kind = buf[0];
    if kind != DGRAM_REQUEST && kind != DGRAM_REPLY {
        return None;
    }
    let port = u16::from_be_bytes([buf[1], buf[2]]);
    let flow = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
    Some((kind, port, flow, &buf[DGRAM_HEADER..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack_roundtrip(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        put_ack(&mut out, ranges, 7);
        assert!(out.len() <= ACK_FRAME_MAX);
        match parse_link_frames(&out).unwrap().as_slice() {
            [LinkFrame::Ack {
                largest,
                delay_ms,
                ranges: got,
            }] => {
                assert_eq!(*largest, ranges[0].1);
                assert_eq!(*delay_ms, 7);
                got.clone()
            }
            other => panic!("期望单个 ACK 帧，得到 {other:?}"),
        }
    }

    #[test]
    fn ack_single_and_multi_range_roundtrip() {
        assert_eq!(ack_roundtrip(&[(0, 0)]), vec![(0, 0)]);
        assert_eq!(ack_roundtrip(&[(5, 9)]), vec![(5, 9)]);
        let ranges = [(90, 100), (80, 85), (10, 10), (0, 3)];
        assert_eq!(ack_roundtrip(&ranges), ranges.to_vec());
    }

    #[test]
    fn ack_caps_range_count() {
        // 40 个单点区间：只编码最高的 MAX_ACK_RANGES 个
        let ranges: Vec<(u64, u64)> = (0..40u64).rev().map(|i| (i * 3, i * 3)).collect();
        let got = ack_roundtrip(&ranges);
        assert_eq!(got.len(), MAX_ACK_RANGES);
        assert_eq!(got, ranges[..MAX_ACK_RANGES].to_vec());
    }

    #[test]
    fn ack_truncates_oversized_ranges_safely() {
        // 首区间超过 u16：只保留靠近 largest 的 65536 个报文，且不再编码后续区间
        let got = ack_roundtrip(&[(0, 100_000), (0, 0)]);
        assert_eq!(got, vec![(100_000 - 65_535, 100_000)]);
        // 间隔超过 u16：后续区间被丢弃
        let got = ack_roundtrip(&[(200_000, 200_010), (5, 9)]);
        assert_eq!(got, vec![(200_000, 200_010)]);
    }

    #[test]
    fn ack_empty_ranges_emit_nothing() {
        let mut out = Vec::new();
        put_ack(&mut out, &[], 0);
        assert!(out.is_empty());
    }

    #[test]
    fn mixed_link_frames_roundtrip() {
        let mut out = Vec::new();
        put_ack(&mut out, &[(3, 4), (0, 1)], 12);
        put_stream(&mut out, 0x1_0000_0000, b"stream-bytes");
        put_dgram(&mut out, b"dgram");
        put_close(&mut out, 9);
        let frames = parse_link_frames(&out).unwrap();
        assert_eq!(
            frames,
            vec![
                LinkFrame::Ack {
                    largest: 4,
                    delay_ms: 12,
                    ranges: vec![(3, 4), (0, 1)],
                },
                LinkFrame::Stream {
                    offset: 0x1_0000_0000,
                    data: b"stream-bytes",
                },
                LinkFrame::Dgram(b"dgram"),
                LinkFrame::Close(9),
            ]
        );
    }

    #[test]
    fn malformed_link_frames_rejected() {
        // 未知类型
        assert!(parse_link_frames(&[0xEE]).is_none());
        // 截断的 STREAM
        let mut out = Vec::new();
        put_stream(&mut out, 5, b"abcdef");
        assert!(parse_link_frames(&out[..out.len() - 1]).is_none());
        // ACK 区间下溢：largest=1 却声称首区间长 5
        let mut bad = vec![link_type::ACK];
        bad.extend_from_slice(&1u64.to_be_bytes());
        bad.extend_from_slice(&0u16.to_be_bytes());
        bad.extend_from_slice(&5u16.to_be_bytes());
        bad.push(0);
        assert!(parse_link_frames(&bad).is_none());
        // 偏移 + 长度溢出 u64
        let mut bad = Vec::new();
        put_stream(&mut bad, u64::MAX, b"x");
        assert!(parse_link_frames(&bad).is_none());
        // 空报文 = 零帧（合法）
        assert_eq!(parse_link_frames(&[]).unwrap(), vec![]);
    }

    fn sample_frames() -> Vec<MuxFrame> {
        vec![
            MuxFrame::Hello {
                version: MUX_VERSION,
                tcp: vec![25565, 8080],
                udp: vec![19132],
            },
            MuxFrame::Open { id: 1, port: 25565 },
            MuxFrame::Data {
                id: 1,
                data: vec![0xAB; 3000],
            },
            MuxFrame::Window {
                id: 1,
                credit: 65536,
            },
            MuxFrame::Fin { id: 1 },
            MuxFrame::Rst { id: 3, code: 2 },
        ]
    }

    #[test]
    fn mux_frames_roundtrip_whole() {
        let frames = sample_frames();
        let mut wire = Vec::new();
        for f in &frames {
            f.encode(&mut wire);
        }
        let mut dec = MuxDecoder::new();
        dec.push(&wire);
        let mut got = Vec::new();
        while let Some(f) = dec.next().unwrap() {
            got.push(f);
        }
        assert_eq!(got, frames);
    }

    #[test]
    fn mux_decoder_handles_arbitrary_fragmentation() {
        let frames = sample_frames();
        let mut wire = Vec::new();
        for f in &frames {
            f.encode(&mut wire);
        }
        // 逐字节喂入 + 几种固定步长：结果必须与整块喂入一致
        for step in [1usize, 2, 3, 7, 100, 4097] {
            let mut dec = MuxDecoder::new();
            let mut got = Vec::new();
            for chunk in wire.chunks(step) {
                dec.push(chunk);
                while let Some(f) = dec.next().unwrap() {
                    got.push(f);
                }
            }
            assert_eq!(got, frames, "step={step}");
        }
    }

    #[test]
    fn mux_unknown_type_skipped_and_malformed_rejected() {
        let mut wire = vec![0x7F, 0, 2, 0xAA, 0xBB]; // 未知类型，2 字节帧体
        MuxFrame::Fin { id: 9 }.encode(&mut wire);
        let mut dec = MuxDecoder::new();
        dec.push(&wire);
        assert_eq!(dec.next().unwrap(), Some(MuxFrame::Fin { id: 9 }));
        assert_eq!(dec.next().unwrap(), None);

        // OPEN 帧体过短 → 协议违规
        let mut dec = MuxDecoder::new();
        dec.push(&[mux_type::OPEN, 0, 2, 0, 0]);
        assert_eq!(dec.next(), Err(MuxDecodeError));
    }

    #[test]
    fn dgram_payload_roundtrip() {
        let wire = encode_dgram(DGRAM_REPLY, 19132, 0xDEAD_BEEF, b"payload");
        assert_eq!(
            decode_dgram(&wire),
            Some((DGRAM_REPLY, 19132, 0xDEAD_BEEF, &b"payload"[..]))
        );
        assert!(decode_dgram(&wire[..DGRAM_HEADER - 1]).is_none());
        let mut bad = wire.clone();
        bad[0] = 9;
        assert!(decode_dgram(&bad).is_none());
    }
}
