//! 可靠层（仅 UDP 载体）：在「已认证、可丢、可乱序」的数据报之上提供一条可靠有序字节流，
//! 外加一条不重传的数据报旁路（UDP 端口转发用）。
//!
//! 纯状态机：不做 IO、不读时钟（时刻由调用方传入），可在模拟网络下做确定性测试。
//! 丢包恢复取 QUIC（RFC 9002）的思路并简化：
//!  - 报文号（pn）单调递增、永不复用——重传的数据装进新报文，ACK 确认的是报文号，
//!    RTT 采样无歧义；pn 同时就是外层 AEAD 的 counter。
//!  - 丢包判定：报文数阈值（落后已确认的最大 pn ≥3）或时间阈值（9/8·RTT）；
//!    尾部丢失靠超时探测（PTO，指数退避）兜底——超时只补发一个探测报文，本身不判丢，
//!    等探测被确认后再由上述阈值判定真正丢了哪些。
//!  - 拥塞控制：NewReno（慢启动 / 拥塞避免 / 每次拥塞事件窗口减半）。
//!  - 流量控制不在本层：复用层按流发放额度，本层只管把收到的字节按序交上去。
//!
//! 不发任何周期性心跳（保活唯一权在内核，14 §10 条款 4）：没有数据要传时本层完全静默。

use crate::frame::{
    parse_link_frames, put_ack, put_close, put_dgram, put_stream, LinkFrame, ACK_FRAME_MAX,
    DGRAM_OVERHEAD, MAX_ACK_RANGES, STREAM_OVERHEAD,
};
use crate::ranges::RangeSet;
use crate::CloseReason;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// 尚无 RTT 样本时的初始估计
pub(crate) const INITIAL_RTT: Duration = Duration::from_millis(200);
/// 接收方最多把 ACK 延迟这么久（等第二个报文合并确认）
pub(crate) const MAX_ACK_DELAY: Duration = Duration::from_millis(20);
/// 定时器粒度下限
const TIMER_GRANULARITY: Duration = Duration::from_millis(5);
/// 报文数阈值：落后已确认最大 pn 达到此数即判丢
const PACKET_THRESHOLD: u64 = 3;
/// PTO 退避后的单次等待上限
const MAX_PTO_INTERVAL: Duration = Duration::from_secs(4);
/// 有数据在途却这么久收不到对端任何报文 → 判定链路已死
pub(crate) const DEAD_TIMEOUT: Duration = Duration::from_secs(30);
const INITIAL_CWND_PACKETS: usize = 10;
const MIN_CWND_PACKETS: usize = 2;
const MAX_CWND: usize = 4 * 1024 * 1024;
/// 发送缓冲软上限（未确认 + 未发送）：超过后不再向上层索要数据
pub(crate) const SEND_BUF_SOFT: usize = 1024 * 1024;
/// 乱序重组缓冲上限：超出的片段直接丢弃（对端会重传）
const MAX_OOO_BYTES: usize = 8 * 1024 * 1024;
/// 数据报队列上限（收、发各一）：满则丢弃——数据报本就不保证送达
const MAX_DGRAM_QUEUE: usize = 256;
/// CLOSE 重复发送次数（尽力而为，不等确认）
const CLOSE_REPEAT: u8 = 3;
/// 外层开销（12B 头 + 16B 标签），计入拥塞窗口的报文尺寸
const PACKET_OVERHEAD: usize = 28;

/// 对端违反链路层协议（帧畸形）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtocolViolation;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ArqStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    /// 判定丢失（含超时探测）的报文数
    pub lost_packets: u64,
    pub tx_stream_bytes: u64,
    pub rx_stream_bytes: u64,
}

struct Sent {
    time: Instant,
    size: usize,
    /// 本报文携带的字节流区间 [start, end)
    chunk: (u64, u64),
}

pub(crate) struct Arq {
    /// 单报文最多携带的字节流数据
    mss: usize,
    /// 单个数据报载荷上限
    max_dgram: usize,
    /// 满载报文尺寸（拥塞窗口的计量单位）
    max_packet: usize,

    // —— 发送侧 ——
    next_pn: u64,
    /// 字节流中自 `base` 起的数据（未确认 + 未发送）
    buf: VecDeque<u8>,
    /// 最低的未确认偏移（其下全部已确认）
    base: u64,
    /// 下一个从未发送过的偏移
    next: u64,
    /// `base` 之上已被确认的区间（乱序确认）
    acked: RangeSet,
    /// 待重传区间。不变式：⊆ [base, next)，且与 `acked` 不相交
    retx: RangeSet,
    /// 在途的携数据报文：pn → 记录
    sent: BTreeMap<u64, Sent>,
    in_flight: usize,
    cwnd: usize,
    ssthresh: usize,
    /// 最近一次拥塞事件的时刻：此前发出的报文再丢不重复减窗，其确认也不增窗
    recovery_start: Option<Instant>,
    largest_acked: Option<u64>,
    loss_time: Option<Instant>,
    last_eliciting_sent: Option<Instant>,
    pto_count: u32,
    /// 超时后允许越过拥塞窗口发一个探测报文
    probe_pending: bool,
    srtt: Duration,
    rttvar: Duration,
    latest_rtt: Duration,
    min_rtt: Duration,
    has_rtt: bool,
    /// 对端首次确认我方数据的时刻（此前发出的报文丢失不计拥塞，见 on_packet_lost）
    first_ack_at: Option<Instant>,
    /// 最近一次「有进展」的时刻：收到对端报文，或从空闲转入有数据待发
    progress_at: Instant,
    dgram_q: VecDeque<Vec<u8>>,
    close_code: Option<u8>,
    close_left: u8,

    // —— 接收侧 ——
    /// 收到过的报文号（只保留最高的若干段，供生成 ACK）
    recv_pns: RangeSet,
    largest_recv: Option<u64>,
    largest_recv_at: Instant,
    /// 自上次发 ACK 以来收到的「需确认」报文数
    ack_eliciting_pending: u32,
    ack_deadline: Option<Instant>,
    ack_now: bool,
    /// 下一个待按序交付的偏移
    recv_next: u64,
    /// 乱序到达的片段：偏移 → 数据
    ooo: BTreeMap<u64, Vec<u8>>,
    ooo_bytes: usize,
    stream_out: VecDeque<Vec<u8>>,
    dgram_out: VecDeque<Vec<u8>>,

    closed: Option<CloseReason>,
    pub stats: ArqStats,
}

impl Arq {
    /// `max_payload`：单个报文的明文预算（外层头与标签之外）
    pub fn new(max_payload: usize, now: Instant) -> Self {
        // 每个报文都给一个满配 ACK 帧留位，省去动态排布
        let mss = max_payload
            .saturating_sub(STREAM_OVERHEAD + ACK_FRAME_MAX)
            .max(1);
        let max_dgram = max_payload.saturating_sub(DGRAM_OVERHEAD + ACK_FRAME_MAX);
        let max_packet = max_payload + PACKET_OVERHEAD;
        Self {
            mss,
            max_dgram,
            max_packet,
            next_pn: 0,
            buf: VecDeque::new(),
            base: 0,
            next: 0,
            acked: RangeSet::new(),
            retx: RangeSet::new(),
            sent: BTreeMap::new(),
            in_flight: 0,
            cwnd: INITIAL_CWND_PACKETS * max_packet,
            ssthresh: usize::MAX,
            recovery_start: None,
            largest_acked: None,
            loss_time: None,
            last_eliciting_sent: None,
            pto_count: 0,
            probe_pending: false,
            srtt: INITIAL_RTT,
            rttvar: INITIAL_RTT / 2,
            latest_rtt: Duration::ZERO,
            min_rtt: Duration::ZERO,
            has_rtt: false,
            first_ack_at: None,
            progress_at: now,
            dgram_q: VecDeque::new(),
            close_code: None,
            close_left: 0,
            recv_pns: RangeSet::new(),
            largest_recv: None,
            largest_recv_at: now,
            ack_eliciting_pending: 0,
            ack_deadline: None,
            ack_now: false,
            recv_next: 0,
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            stream_out: VecDeque::new(),
            dgram_out: VecDeque::new(),
            closed: None,
            stats: ArqStats::default(),
        }
    }

    fn min_cwnd(&self) -> usize {
        MIN_CWND_PACKETS * self.max_packet
    }

    // —————————————— 上层接口 ——————————————

    /// 发送缓冲还能接纳的字节数（软上限；为 0 时上层应暂停喂数据）
    pub fn send_capacity(&self) -> usize {
        SEND_BUF_SOFT.saturating_sub(self.buf.len())
    }

    /// 追加待发送的字节流数据
    pub fn push_stream(&mut self, data: &[u8], now: Instant) {
        if self.closed.is_some() || self.close_code.is_some() || data.is_empty() {
            return;
        }
        if self.buf.is_empty() {
            // 从空闲转入有数据待发：死链判定从此刻起算，而不是从很久以前的最后一次收包
            self.progress_at = now;
        }
        self.buf.extend(data);
    }

    /// 排队一个数据报（不重传）；超长或队列已满返回 false
    pub fn push_dgram(&mut self, data: Vec<u8>) -> bool {
        if self.closed.is_some()
            || data.len() > self.max_dgram
            || self.dgram_q.len() >= MAX_DGRAM_QUEUE
        {
            return false;
        }
        self.dgram_q.push_back(data);
        true
    }

    pub fn max_dgram(&self) -> usize {
        self.max_dgram
    }

    /// 主动关闭：随后的 `poll_transmit` 会发出 CLOSE，发完即进入已关闭状态
    pub fn close(&mut self, code: u8) {
        if self.closed.is_none() && self.close_code.is_none() {
            self.close_code = Some(code);
            self.close_left = CLOSE_REPEAT;
        }
    }

    pub fn closed(&self) -> Option<CloseReason> {
        self.closed
    }

    /// 取走一段已按序到达的字节流数据
    pub fn take_stream(&mut self) -> Option<Vec<u8>> {
        self.stream_out.pop_front()
    }

    /// 取走一个收到的数据报
    pub fn take_dgram(&mut self) -> Option<Vec<u8>> {
        self.dgram_out.pop_front()
    }

    /// 发送侧是否完全空闲（没有未确认也没有未发送的数据）
    #[cfg(test)]
    pub fn send_idle(&self) -> bool {
        self.buf.is_empty() && self.sent.is_empty() && self.dgram_q.is_empty()
    }

    // —————————————— 发包 ——————————————

    fn alloc_pn(&mut self) -> u64 {
        let pn = self.next_pn;
        self.next_pn += 1;
        self.stats.tx_packets += 1;
        pn
    }

    /// 下一个待发的字节流区间：重传优先，其次新数据
    fn next_chunk(&self) -> Option<(u64, u64)> {
        let mss = self.mss as u64;
        if let Some((s, e)) = self.retx.first() {
            return Some((s, e.min(s + mss)));
        }
        let end = self.base + self.buf.len() as u64;
        if self.next < end {
            return Some((self.next, end.min(self.next + mss)));
        }
        None
    }

    fn put_pending_ack(&mut self, out: &mut Vec<u8>, now: Instant) {
        if self.ack_eliciting_pending == 0 && !self.ack_now {
            return;
        }
        let ranges: Vec<(u64, u64)> = self
            .recv_pns
            .iter_desc()
            .take(MAX_ACK_RANGES)
            .map(|(s, e)| (s, e - 1))
            .collect();
        let delay = now
            .saturating_duration_since(self.largest_recv_at)
            .as_millis()
            .min(u128::from(u16::MAX)) as u16;
        put_ack(out, &ranges, delay);
        self.ack_eliciting_pending = 0;
        self.ack_deadline = None;
        self.ack_now = false;
    }

    /// 取下一个要发出的报文：(报文号, 明文载荷)。返回 None = 当前无可发（或受拥塞窗口所限）。
    /// 调用方必须用返回的报文号作外层 AEAD counter，且每个返回值只发一次。
    pub fn poll_transmit(&mut self, now: Instant) -> Option<(u64, Vec<u8>)> {
        if self.closed.is_some() {
            return None;
        }
        if let Some(code) = self.close_code {
            let mut out = Vec::with_capacity(2);
            put_close(&mut out, code);
            self.close_left = self.close_left.saturating_sub(1);
            let pn = self.alloc_pn();
            if self.close_left == 0 {
                self.closed = Some(CloseReason::Local);
            }
            return Some((pn, out));
        }

        let chunk = self.next_chunk().filter(|&(s, e)| {
            let size = (e - s) as usize + STREAM_OVERHEAD + ACK_FRAME_MAX + PACKET_OVERHEAD;
            self.probe_pending || self.in_flight + size <= self.cwnd
        });
        let dgram = if chunk.is_none() {
            self.dgram_q.pop_front()
        } else {
            None
        };
        if chunk.is_none() && dgram.is_none() && !self.ack_now {
            return None;
        }

        let mut out = Vec::with_capacity(self.max_packet);
        self.put_pending_ack(&mut out, now);

        if let Some((s, e)) = chunk {
            let from = (s - self.base) as usize;
            let to = (e - self.base) as usize;
            let data: Vec<u8> = self.buf.range(from..to).copied().collect();
            put_stream(&mut out, s, &data);
            self.retx.remove(s, e);
            if e > self.next {
                self.stats.tx_stream_bytes += e - self.next.max(s);
                self.next = e;
            }
            let pn = self.alloc_pn();
            let size = out.len() + PACKET_OVERHEAD;
            self.sent.insert(
                pn,
                Sent {
                    time: now,
                    size,
                    chunk: (s, e),
                },
            );
            self.in_flight += size;
            self.last_eliciting_sent = Some(now);
            self.probe_pending = false;
            return Some((pn, out));
        }

        if let Some(d) = dgram {
            put_dgram(&mut out, &d);
        }
        if out.is_empty() {
            return None;
        }
        Some((self.alloc_pn(), out))
    }

    // —————————————— 收包 ——————————————

    /// 处理一个已通过 AEAD 认证与重放检查的报文（同一报文号不会出现两次）
    pub fn on_packet(
        &mut self,
        pn: u64,
        payload: &[u8],
        now: Instant,
    ) -> Result<(), ProtocolViolation> {
        if self.closed.is_some() {
            return Ok(());
        }
        let frames = parse_link_frames(payload).ok_or(ProtocolViolation)?;
        self.progress_at = now;
        self.stats.rx_packets += 1;

        let mut eliciting = false;
        for frame in frames {
            match frame {
                LinkFrame::Ack {
                    largest,
                    delay_ms,
                    ranges,
                } => self.on_ack(largest, delay_ms, &ranges, now),
                LinkFrame::Stream { offset, data } => {
                    eliciting = true;
                    self.on_stream(offset, data);
                }
                LinkFrame::Dgram(data) => {
                    if self.dgram_out.len() < MAX_DGRAM_QUEUE {
                        self.dgram_out.push_back(data.to_vec());
                    }
                }
                LinkFrame::Close(code) => {
                    self.closed = Some(CloseReason::Peer(code));
                    return Ok(());
                }
            }
        }

        let expected = self.largest_recv.map_or(0, |l| l + 1);
        let out_of_order = pn != expected;
        self.recv_pns.insert(pn, pn + 1);
        while self.recv_pns.len() > MAX_ACK_RANGES {
            self.recv_pns.pop_first();
        }
        if self.largest_recv.map_or(true, |l| pn > l) {
            self.largest_recv = Some(pn);
            self.largest_recv_at = now;
        }
        if eliciting {
            self.ack_eliciting_pending += 1;
            // 乱序/空洞立即确认（让对端尽快判丢）；否则每两个报文确认一次或到期确认
            if out_of_order || self.ack_eliciting_pending >= 2 {
                self.ack_now = true;
            } else if self.ack_deadline.is_none() {
                self.ack_deadline = Some(now + MAX_ACK_DELAY);
            }
        }
        Ok(())
    }

    fn on_stream(&mut self, offset: u64, data: &[u8]) {
        let end = offset + data.len() as u64;
        if data.is_empty() || end <= self.recv_next {
            return; // 空片段或完全重复
        }
        if offset > self.recv_next {
            // 乱序：缓存等空洞补齐（容量有限；超限丢弃，对端会重传）
            let replaced = match self.ooo.get(&offset) {
                Some(existing) if existing.len() >= data.len() => return,
                Some(existing) => existing.len(),
                None => 0,
            };
            if self.ooo_bytes - replaced + data.len() > MAX_OOO_BYTES {
                return;
            }
            self.ooo_bytes = self.ooo_bytes - replaced + data.len();
            self.ooo.insert(offset, data.to_vec());
            return;
        }
        self.deliver(offset, data.to_vec());
        // 空洞补齐后，把能接上的乱序片段一并交付（片段边界可能与重传时不同，按重叠裁剪）
        while let Some((&off, _)) = self.ooo.iter().next() {
            if off > self.recv_next {
                break;
            }
            if let Some(chunk) = self.ooo.remove(&off) {
                self.ooo_bytes -= chunk.len();
                self.deliver(off, chunk);
            }
        }
    }

    /// 交付 `[offset, offset+len)` 中尚未交付的尾部；调用方保证 offset ≤ recv_next
    fn deliver(&mut self, offset: u64, mut chunk: Vec<u8>) {
        let end = offset + chunk.len() as u64;
        if end <= self.recv_next {
            return;
        }
        let skip = (self.recv_next - offset) as usize;
        if skip > 0 {
            chunk.drain(..skip);
        }
        self.stats.rx_stream_bytes += chunk.len() as u64;
        self.recv_next = end;
        self.stream_out.push_back(chunk);
    }

    fn on_ack(&mut self, largest: u64, delay_ms: u16, ranges: &[(u64, u64)], now: Instant) {
        if largest >= self.next_pn {
            return; // 确认了我们从未发过的报文号：忽略整帧
        }
        let mut newly: Vec<(u64, Sent)> = Vec::new();
        for &(lo, hi) in ranges {
            let pns: Vec<u64> = self.sent.range(lo..=hi).map(|(&pn, _)| pn).collect();
            for pn in pns {
                if let Some(sp) = self.sent.remove(&pn) {
                    newly.push((pn, sp));
                }
            }
        }
        self.largest_acked = Some(self.largest_acked.map_or(largest, |l| l.max(largest)));

        // RTT 只在「本帧最大报文号是新确认的携数据报文」时采样
        if let Some((_, sp)) = newly.iter().find(|(pn, _)| *pn == largest) {
            let sample = now.saturating_duration_since(sp.time);
            self.update_rtt(sample, Duration::from_millis(u64::from(delay_ms)));
        }
        for (_, sp) in &newly {
            self.in_flight = self.in_flight.saturating_sub(sp.size);
            let (s, e) = sp.chunk;
            self.acked.insert(s, e);
            self.retx.remove(s, e);
            if self.recovery_start.map_or(true, |r| sp.time > r) {
                self.grow_cwnd(sp.size);
            }
        }
        if !newly.is_empty() {
            self.pto_count = 0;
            if self.first_ack_at.is_none() {
                self.first_ack_at = Some(now);
            }
        }
        self.advance_base();
        self.detect_losses(now);
    }

    fn advance_base(&mut self) {
        while let Some((s, e)) = self.acked.first() {
            if s > self.base {
                break;
            }
            if e > self.base {
                let n = ((e - self.base) as usize).min(self.buf.len());
                self.buf.drain(..n);
                self.base += n as u64;
            }
            self.acked.pop_first();
        }
        if self.next < self.base {
            self.next = self.base;
        }
        self.retx.remove_below(self.base);
    }

    fn update_rtt(&mut self, sample: Duration, ack_delay: Duration) {
        self.latest_rtt = sample;
        if !self.has_rtt {
            self.has_rtt = true;
            self.min_rtt = sample;
            self.srtt = sample;
            self.rttvar = sample / 2;
            return;
        }
        self.min_rtt = self.min_rtt.min(sample);
        let delay = ack_delay.min(MAX_ACK_DELAY);
        let adjusted = if sample >= self.min_rtt + delay {
            sample - delay
        } else {
            sample
        };
        let diff = if self.srtt > adjusted {
            self.srtt - adjusted
        } else {
            adjusted - self.srtt
        };
        self.rttvar = (self.rttvar * 3 + diff) / 4;
        self.srtt = (self.srtt * 7 + adjusted) / 8;
    }

    fn grow_cwnd(&mut self, acked_bytes: usize) {
        if self.cwnd < self.ssthresh {
            self.cwnd += acked_bytes; // 慢启动
        } else {
            self.cwnd += (self.max_packet * acked_bytes / self.cwnd).max(1); // 拥塞避免
        }
        self.cwnd = self.cwnd.min(MAX_CWND);
    }

    /// 把报文携带的区间中「仍未确认」的部分排入重传；返回 false = 已全部被确认、无需重传
    fn requeue(&mut self, chunk: (u64, u64)) -> bool {
        let start = chunk.0.max(self.base);
        let gaps = self.acked.gaps_within(start, chunk.1);
        for &(s, e) in &gaps {
            self.retx.insert(s, e);
        }
        !gaps.is_empty()
    }

    fn on_packet_lost(&mut self, sp: Sent, now: Instant) {
        self.in_flight = self.in_flight.saturating_sub(sp.size);
        if !self.requeue(sp.chunk) {
            // 同一区间的另一份副本（重传/探测）已被确认：这份只是多余，不是丢包事件
            return;
        }
        self.stats.lost_packets += 1;
        // 对端首次应答之前发出的报文丢失不算拥塞信号：那时对端多半还在打洞、尚未接管 socket，
        // 报文是被对端内核当杂包丢掉的，与路径容量无关——否则连接一建立窗口就先折半。
        let before_first_ack = self.first_ack_at.map_or(true, |t| sp.time < t);
        // 一次拥塞事件只减一次窗：恢复期开始之后发出的报文再丢才算新事件
        if !before_first_ack && self.recovery_start.map_or(true, |r| sp.time > r) {
            self.recovery_start = Some(now);
            self.ssthresh = (self.cwnd / 2).max(self.min_cwnd());
            self.cwnd = self.ssthresh;
        }
    }

    fn detect_losses(&mut self, now: Instant) {
        self.loss_time = None;
        let Some(largest_acked) = self.largest_acked else {
            return;
        };
        let loss_delay = (self.srtt.max(self.latest_rtt) * 9 / 8).max(TIMER_GRANULARITY);
        let mut lost: Vec<u64> = Vec::new();
        for (&pn, sp) in self.sent.range(..largest_acked) {
            if largest_acked - pn >= PACKET_THRESHOLD
                || now.saturating_duration_since(sp.time) >= loss_delay
            {
                lost.push(pn);
            } else {
                let at = sp.time + loss_delay;
                self.loss_time = Some(self.loss_time.map_or(at, |cur| cur.min(at)));
            }
        }
        for pn in lost {
            if let Some(sp) = self.sent.remove(&pn) {
                self.on_packet_lost(sp, now);
            }
        }
    }

    // —————————————— 定时器 ——————————————

    fn pto_deadline(&self) -> Option<Instant> {
        if self.sent.is_empty() {
            return None;
        }
        let last = self.last_eliciting_sent?;
        let base = self.srtt + (self.rttvar * 4).max(TIMER_GRANULARITY) + MAX_ACK_DELAY;
        let wait = (base * 2u32.pow(self.pto_count.min(6))).min(MAX_PTO_INTERVAL);
        Some(last + wait)
    }

    /// 最近的定时器到期时刻（None = 无定时器：没有在途数据，也没有待发的延迟确认）
    pub fn next_timeout(&self) -> Option<Instant> {
        if self.closed.is_some() {
            return None;
        }
        [self.ack_deadline, self.loss_time, self.pto_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    pub fn on_timeout(&mut self, now: Instant) {
        if self.closed.is_some() {
            return;
        }
        if self.ack_deadline.is_some_and(|t| now >= t) {
            self.ack_deadline = None;
            self.ack_now = true;
        }
        if self.loss_time.is_some_and(|t| now >= t) {
            self.detect_losses(now);
        }
        if self.pto_deadline().is_some_and(|t| now >= t) {
            if now.saturating_duration_since(self.progress_at) >= DEAD_TIMEOUT {
                self.closed = Some(CloseReason::Timeout);
                return;
            }
            self.pto_count += 1;
            // 尾部丢失兜底：把最老的在途报文所带的数据再发一份作探测（允许越过拥塞窗口）。
            // 原报文的记录保留：超时本身不判丢、不改窗口——可能只是确认来得晚；
            // 真正丢了哪些，等探测被确认后由报文数/时间阈值判定。
            loop {
                let Some((pn, chunk)) = self.sent.iter().next().map(|(&pn, sp)| (pn, sp.chunk))
                else {
                    break;
                };
                if self.requeue(chunk) {
                    break;
                }
                // 该报文的数据已被其他副本确认：记录多余，清掉后看下一个
                if let Some(sp) = self.sent.remove(&pn) {
                    self.in_flight = self.in_flight.saturating_sub(sp.size);
                }
            }
            self.probe_pending = !self.sent.is_empty();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 明文预算取与生产一致的量级
    const MAX_PAYLOAD: usize = 1272;

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        /// [0, n)
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[derive(Clone, Copy)]
    struct NetCfg {
        /// 丢包率（千分比）
        loss_permille: u64,
        /// 单向时延范围（毫秒）：随机时延即带来乱序
        delay_ms: (u64, u64),
    }

    struct Wire {
        /// (到达时刻毫秒, pn, 载荷)
        queue: Vec<(u64, u64, Vec<u8>)>,
    }

    /// 双端 + 模拟网络；虚拟时钟以 1ms 步进
    struct Sim {
        t0: Instant,
        now_ms: u64,
        a: Arq,
        b: Arq,
        a_to_b: Wire,
        b_to_a: Wire,
        cfg: NetCfg,
        rng: XorShift,
        /// 此时刻之前 A 发出的报文全部被吞（模拟对端尚未就绪）
        a_blackhole_until_ms: u64,
        /// B 永不应答（模拟对端消失）
        b_dead: bool,
        a_recv: Vec<u8>,
        b_recv: Vec<u8>,
        a_dgrams: Vec<Vec<u8>>,
        b_dgrams: Vec<Vec<u8>>,
        packets_on_wire: u64,
    }

    impl Sim {
        fn new(cfg: NetCfg, seed: u64) -> Self {
            let t0 = Instant::now();
            Self {
                t0,
                now_ms: 0,
                a: Arq::new(MAX_PAYLOAD, t0),
                b: Arq::new(MAX_PAYLOAD, t0),
                a_to_b: Wire { queue: Vec::new() },
                b_to_a: Wire { queue: Vec::new() },
                cfg,
                rng: XorShift(seed | 1),
                a_blackhole_until_ms: 0,
                b_dead: false,
                a_recv: Vec::new(),
                b_recv: Vec::new(),
                a_dgrams: Vec::new(),
                b_dgrams: Vec::new(),
                packets_on_wire: 0,
            }
        }

        fn now(&self) -> Instant {
            self.t0 + Duration::from_millis(self.now_ms)
        }

        fn step(&mut self) {
            let now = self.now();
            // ① 到期报文投递
            let due: Vec<(u64, u64, Vec<u8>)> = {
                let (due, rest) = std::mem::take(&mut self.a_to_b.queue)
                    .into_iter()
                    .partition(|(at, _, _)| *at <= self.now_ms);
                self.a_to_b.queue = rest;
                due
            };
            for (_, pn, payload) in due {
                if !self.b_dead {
                    self.b.on_packet(pn, &payload, now).expect("B 收包");
                }
            }
            let due: Vec<(u64, u64, Vec<u8>)> = {
                let (due, rest) = std::mem::take(&mut self.b_to_a.queue)
                    .into_iter()
                    .partition(|(at, _, _)| *at <= self.now_ms);
                self.b_to_a.queue = rest;
                due
            };
            for (_, pn, payload) in due {
                self.a.on_packet(pn, &payload, now).expect("A 收包");
            }
            // ② 定时器
            if self.a.next_timeout().is_some_and(|t| t <= now) {
                self.a.on_timeout(now);
            }
            if self.b.next_timeout().is_some_and(|t| t <= now) {
                self.b.on_timeout(now);
            }
            // ③ 发包（随机丢弃 + 随机时延）
            while let Some((pn, payload)) = self.a.poll_transmit(now) {
                self.packets_on_wire += 1;
                let dropped = self.now_ms < self.a_blackhole_until_ms
                    || self.rng.below(1000) < self.cfg.loss_permille;
                if !dropped {
                    let (lo, hi) = self.cfg.delay_ms;
                    let at = self.now_ms + lo + self.rng.below(hi - lo + 1);
                    self.a_to_b.queue.push((at, pn, payload));
                }
            }
            if !self.b_dead {
                while let Some((pn, payload)) = self.b.poll_transmit(now) {
                    self.packets_on_wire += 1;
                    if self.rng.below(1000) >= self.cfg.loss_permille {
                        let (lo, hi) = self.cfg.delay_ms;
                        let at = self.now_ms + lo + self.rng.below(hi - lo + 1);
                        self.b_to_a.queue.push((at, pn, payload));
                    }
                }
            }
            // ④ 上层取数
            while let Some(c) = self.a.take_stream() {
                self.a_recv.extend_from_slice(&c);
            }
            while let Some(c) = self.b.take_stream() {
                self.b_recv.extend_from_slice(&c);
            }
            while let Some(d) = self.a.take_dgram() {
                self.a_dgrams.push(d);
            }
            while let Some(d) = self.b.take_dgram() {
                self.b_dgrams.push(d);
            }
            self.now_ms += 1;
        }

        /// 单向/双向传输直到两侧都收齐，返回耗时（虚拟毫秒）；超时即失败
        fn transfer(&mut self, a_data: &[u8], b_data: &[u8], limit_ms: u64) -> u64 {
            let start = self.now_ms;
            let (mut a_off, mut b_off) = (0usize, 0usize);
            let a_base = self.b_recv.len();
            let b_base = self.a_recv.len();
            loop {
                let now = self.now();
                let room = self.a.send_capacity().min(a_data.len() - a_off);
                if room > 0 {
                    self.a.push_stream(&a_data[a_off..a_off + room], now);
                    a_off += room;
                }
                let room = self.b.send_capacity().min(b_data.len() - b_off);
                if room > 0 {
                    self.b.push_stream(&b_data[b_off..b_off + room], now);
                    b_off += room;
                }
                self.step();
                let done = self.b_recv.len() - a_base == a_data.len()
                    && self.a_recv.len() - b_base == b_data.len();
                if done {
                    assert_eq!(&self.b_recv[a_base..], a_data, "A→B 内容必须逐字节一致");
                    assert_eq!(&self.a_recv[b_base..], b_data, "B→A 内容必须逐字节一致");
                    return self.now_ms - start;
                }
                assert!(
                    self.now_ms - start < limit_ms,
                    "传输超时：A→B {}/{}，B→A {}/{}，cwnd={} in_flight={} lost={}",
                    self.b_recv.len() - a_base,
                    a_data.len(),
                    self.a_recv.len() - b_base,
                    b_data.len(),
                    self.a.cwnd,
                    self.a.in_flight,
                    self.a.stats.lost_packets,
                );
                assert_eq!(self.a.closed(), None);
                assert_eq!(self.b.closed(), None);
            }
        }
    }

    fn pattern(len: usize, seed: u64) -> Vec<u8> {
        let mut rng = XorShift(seed | 1);
        (0..len).map(|_| rng.next() as u8).collect()
    }

    const CLEAN: NetCfg = NetCfg {
        loss_permille: 0,
        delay_ms: (10, 10),
    };

    #[test]
    fn lossless_transfer_has_no_retransmits() {
        let mut sim = Sim::new(CLEAN, 1);
        let data = pattern(1024 * 1024, 11);
        let took = sim.transfer(&data, &[], 20_000);
        assert_eq!(sim.a.stats.lost_packets, 0, "无丢包网络不应有任何重传");
        assert!(took < 5_000, "1MiB 在 20ms RTT 下应在数秒内传完，实际 {took}ms");
        assert!(sim.a.has_rtt);
        // RTT 估计应接近真实往返（20ms + 延迟确认）
        assert!(sim.a.srtt >= Duration::from_millis(15) && sim.a.srtt <= Duration::from_millis(60));
    }

    #[test]
    fn bidirectional_transfer_under_loss_and_reordering() {
        let cfg = NetCfg {
            loss_permille: 50,
            delay_ms: (5, 40),
        };
        let mut sim = Sim::new(cfg, 2);
        let a_data = pattern(400_000, 21);
        let b_data = pattern(250_000, 22);
        sim.transfer(&a_data, &b_data, 120_000);
        assert!(sim.a.stats.lost_packets > 0, "5% 丢包下必然触发过重传");
    }

    #[test]
    fn survives_heavy_loss() {
        let cfg = NetCfg {
            loss_permille: 300,
            delay_ms: (5, 30),
        };
        let mut sim = Sim::new(cfg, 3);
        let data = pattern(60_000, 31);
        sim.transfer(&data, &pattern(5_000, 32), 300_000);
    }

    #[test]
    fn many_seeds_small_transfers_stay_intact() {
        // 多组随机种子：覆盖不同的丢包/乱序组合（含重传片段边界与原片段不一致的重叠情形）
        for seed in 100..140u64 {
            let cfg = NetCfg {
                loss_permille: 120,
                delay_ms: (1, 60),
            };
            let mut sim = Sim::new(cfg, seed);
            let data = pattern(30_000 + (seed as usize % 7) * 1111, seed);
            sim.transfer(&data, &pattern(3_000, seed + 1), 200_000);
        }
    }

    #[test]
    fn peer_not_ready_at_start_then_recovers_without_cwnd_penalty() {
        let mut sim = Sim::new(CLEAN, 4);
        // 前 3 秒对端还没接管 socket（打洞竞速未结束）：A 的报文全部石沉大海
        sim.a_blackhole_until_ms = 3_000;
        let data = pattern(300_000, 41);
        let took = sim.transfer(&data, &[], 20_000);
        assert!(took >= 3_000);
        assert!(took < 8_000, "对端就绪后应迅速传完，实际 {took}ms");
        assert_eq!(sim.a.closed(), None);
    }

    #[test]
    fn dead_peer_is_detected_by_timeout_only_when_data_pending() {
        let mut sim = Sim::new(CLEAN, 5);
        sim.b_dead = true;
        // 空闲 60 秒：没有数据要发就不发包、也不判死（不自发心跳）
        for _ in 0..60_000 {
            sim.step();
        }
        assert_eq!(sim.packets_on_wire, 0, "空闲链路不得有任何发包");
        assert_eq!(sim.a.closed(), None);

        // 有数据在途而对端始终无应答 → DEAD_TIMEOUT 后判死（从开始等待算起，而非从上次收包算起）
        let now = sim.now();
        sim.a.push_stream(b"hello?", now);
        let started = sim.now_ms;
        while sim.a.closed().is_none() {
            sim.step();
            assert!(sim.now_ms - started < 60_000, "必须在有限时间内判死");
        }
        assert_eq!(sim.a.closed(), Some(CloseReason::Timeout));
        let waited = sim.now_ms - started;
        assert!(
            waited >= DEAD_TIMEOUT.as_millis() as u64,
            "不得早于 DEAD_TIMEOUT 判死，实际 {waited}ms"
        );
        // 退避生效：30 秒里的探测包数量很少
        assert!(sim.packets_on_wire < 30, "探测必须指数退避，实际发包 {}", sim.packets_on_wire);
    }

    #[test]
    fn goes_silent_after_transfer_completes() {
        let mut sim = Sim::new(CLEAN, 6);
        sim.transfer(&pattern(50_000, 61), &pattern(50_000, 62), 20_000);
        // 等尾部确认收敛
        for _ in 0..1_000 {
            sim.step();
        }
        assert!(sim.a.send_idle() && sim.b.send_idle());
        let before = sim.packets_on_wire;
        for _ in 0..30_000 {
            sim.step();
        }
        assert_eq!(
            sim.packets_on_wire, before,
            "传输结束后必须彻底静默：不得有心跳，也不得有确认的确认"
        );
        assert_eq!(sim.a.next_timeout(), None);
        assert_eq!(sim.b.next_timeout(), None);
    }

    #[test]
    fn datagrams_are_delivered_but_never_retransmitted() {
        let mut sim = Sim::new(CLEAN, 7);
        for i in 0..20u8 {
            assert!(sim.a.push_dgram(vec![i; 100]));
        }
        // 超长数据报直接拒绝
        let too_big = vec![0u8; sim.a.max_dgram() + 1];
        assert!(!sim.a.push_dgram(too_big));
        assert!(sim.a.push_dgram(vec![9u8; sim.a.max_dgram()]));
        for _ in 0..200 {
            sim.step();
        }
        assert_eq!(sim.b_dgrams.len(), 21);
        for (i, d) in sim.b_dgrams.iter().take(20).enumerate() {
            assert_eq!(d, &vec![i as u8; 100]);
        }

        // 全丢的网络：数据报发一次就算完，不重传、不计在途
        let mut lossy = Sim::new(
            NetCfg {
                loss_permille: 1000,
                delay_ms: (1, 1),
            },
            8,
        );
        assert!(lossy.a.push_dgram(vec![1, 2, 3]));
        for _ in 0..5_000 {
            lossy.step();
        }
        assert_eq!(lossy.packets_on_wire, 1);
        assert!(lossy.b_dgrams.is_empty());
        assert_eq!(lossy.a.closed(), None);
    }

    #[test]
    fn close_is_propagated_to_peer() {
        let mut sim = Sim::new(CLEAN, 9);
        sim.transfer(b"before close", &[], 5_000);
        sim.a.close(7);
        for _ in 0..100 {
            sim.step();
        }
        assert_eq!(sim.a.closed(), Some(CloseReason::Local));
        assert_eq!(sim.b.closed(), Some(CloseReason::Peer(7)));
        // 关闭后不再产生任何报文
        let before = sim.packets_on_wire;
        let now = sim.now();
        sim.a.push_stream(b"ignored", now);
        for _ in 0..1_000 {
            sim.step();
        }
        assert_eq!(sim.packets_on_wire, before);
    }

    #[test]
    fn malformed_payload_is_a_protocol_violation() {
        let now = Instant::now();
        let mut arq = Arq::new(MAX_PAYLOAD, now);
        assert_eq!(arq.on_packet(0, &[0xEE, 1, 2], now), Err(ProtocolViolation));
    }

    #[test]
    fn bogus_ack_for_unsent_packets_is_ignored() {
        let now = Instant::now();
        let mut arq = Arq::new(MAX_PAYLOAD, now);
        arq.push_stream(&[1u8; 5000], now);
        let mut sent = Vec::new();
        while let Some((pn, _)) = arq.poll_transmit(now) {
            sent.push(pn);
        }
        assert!(!sent.is_empty());
        // 对端声称确认了一个我们从未发过的报文号：整帧忽略，在途记账不变
        let mut payload = Vec::new();
        put_ack(&mut payload, &[(0, 10_000)], 0);
        let in_flight = arq.in_flight;
        arq.on_packet(0, &payload, now).unwrap();
        assert_eq!(arq.in_flight, in_flight);
        assert_eq!(arq.base, 0);
    }

    #[test]
    fn congestion_window_limits_initial_burst() {
        let now = Instant::now();
        let mut arq = Arq::new(MAX_PAYLOAD, now);
        arq.push_stream(&vec![7u8; 500_000], now);
        let mut burst = 0usize;
        while arq.poll_transmit(now).is_some() {
            burst += 1;
        }
        assert!(
            burst <= INITIAL_CWND_PACKETS,
            "未收到任何确认前，首波发包不得超过初始窗口（{INITIAL_CWND_PACKETS} 包），实际 {burst}"
        );
        assert!(burst >= INITIAL_CWND_PACKETS - 1);
    }
}
