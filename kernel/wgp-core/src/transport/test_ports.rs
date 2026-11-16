//! 测试专用：发放本进程内不重复的回环端口（TCP 为主，UDP 同理）。
//!
//! 不用「绑 0 号端口、取到端口号再释放」的办法占坑：那样拿到的端口落在系统的动态端口范围里，
//! 释放之后系统可以把它发给别人，包括并行运行的另一个测试（Linux 的动态端口是随机发的）。
//! 打洞载体绑定时又开了端口共用（见 `tcp.rs`），在 Windows 上撞到别人正在用的端口不会报错，
//! 两个测试的连接会串到一起。
//!
//! 这里在系统动态端口范围之下（Windows 49152 起，Linux 32768 起）**随机**取端口，
//! 本进程内不重复，并用一次不开共用的试绑跳过正被占用的端口。
//! 不按顺序发放，是因为打洞用固定源端口去连固定目的端口：相邻两次测试进程如果发出同一对端口，
//! 后一次的 connect 会撞上前一次连接留下的 TIME_WAIT 而失败（Windows 报 10048）。

use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

/// 随机发放区（避开本仓端到端脚本使用的 21xxx / 23xxx / 45xxx）
const RANDOM_RANGE: Range<u16> = 24_000..32_000;
/// 指定端口区：留给「端口号由别的规则决定」的测试（如按种子生成的撒网计划），与随机发放区不相交
pub(crate) const PINNED_RANGE: Range<u16> = 32_000..32_700;

/// 最多抽多少次（远大于一次测试运行用得到的端口数；抽不到说明环境有问题，直接报错）
const MAX_DRAWS: u32 = 100_000;

/// 该端口此刻是否空闲（不开端口共用的试绑）
pub(crate) fn is_free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// 取一个本进程内不会再发第二次的回环地址（TCP）
pub(crate) fn unique_loopback_addr() -> SocketAddr {
    draw_unique(is_free)
}

/// 同上，给 UDP 用：返回时该端口此刻没有被任何 UDP socket 占用
pub(crate) fn unique_loopback_udp_addr() -> SocketAddr {
    draw_unique(|port| UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok())
}

fn draw_unique(free: impl Fn(u16) -> bool) -> SocketAddr {
    // 每个进程一组随机密钥：各次测试进程抽到的端口序列互不相同
    static KEYS: OnceLock<RandomState> = OnceLock::new();
    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    static DRAWS: AtomicU32 = AtomicU32::new(0);

    let keys = KEYS.get_or_init(RandomState::new);
    let issued = ISSUED.get_or_init(Default::default);
    let span = u64::from(RANDOM_RANGE.end - RANDOM_RANGE.start);
    loop {
        let draw = DRAWS.fetch_add(1, Ordering::Relaxed);
        assert!(draw < MAX_DRAWS, "抽了 {MAX_DRAWS} 次仍找不到空闲的测试端口");
        let port = RANDOM_RANGE.start + (keys.hash_one(draw) % span) as u16;
        let fresh = issued
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(port);
        if fresh && free(port) {
            return SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        }
    }
}
