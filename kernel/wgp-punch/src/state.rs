//! 引擎主状态机（00 §4：Idle → … → Connected；失败 → ICMP 逃生 → 死局）。

/// 每 Peer 一会话实例（15 全链路 Phase 3-8 的状态化）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PunchState {
    /// 入口：收到连接意图
    Idle,
    /// 后台预探测：时间锚点 / NAT 类型 / UDP 可用 / 步长模型
    Preprobe,
    /// DHT 房间键查找（U/ 码 → 房间 → 锚点）
    RoomLookup,
    /// 承诺-揭示 + 观察者报告交叉验证 + 能力位交换
    Negotiating,
    /// 竞速打洞：LAN ∥ UDP 三波 ∥ TCP simultaneous-open
    Punching,
    /// 链路已打通（链路档位见 LinkRank，在 wgp-core）
    Connected,
    /// 全灭 + ICMP 逃生失败：死局判定（04 D5），附诊断报告告知用户
    DeadEnd,
}

/// TCP 兜底触发条件（00 §4：T1-T4，任一满足即启动 TCP simultaneous open）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFallbackTrigger {
    /// T1：预判 UDP 出站不可达
    UdpPrecheckBlocked,
    /// T2：UDP 三波全灭
    UdpThreeWavesFailed,
    /// T3：UDP 打通但 QUIC 握手超时（疑 DPI 拦 QUIC）
    QuicHandshakeTimeout,
    /// T4：运营商画像差 + 对端同意
    CarrierProfileBad,
}

/// 状态转移中枢（实现阶段补全：由引擎任务驱动，双模定时器内嵌）
impl PunchState {
    /// 是否允许进入 Punching
    pub fn can_punch(&self) -> bool {
        matches!(
            self,
            PunchState::Negotiating | PunchState::Preprobe | PunchState::RoomLookup
        )
    }

    /// 链路失效后应回到的状态（重打洞环：lost → Punching → yield）
    pub fn on_link_lost() -> PunchState {
        PunchState::Punching
    }

    /// 死局判定入口（04 D5 评分 ≥70）
    pub fn on_all_failed() -> PunchState {
        PunchState::DeadEnd
    }
}