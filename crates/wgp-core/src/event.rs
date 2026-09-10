//! 事件流（14 §5：tokio broadcast，多外围订阅互不阻塞）。

use crate::link::LinkRank;
use crate::PeerId;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EngineEvent {
    PunchingStarted { peer: PeerId },
    LinkYielded { peer: PeerId, rank: LinkRank },
    LinkUpgraded {
        peer: PeerId,
        from: LinkRank,
        to: LinkRank,
    },
    LinkLost { peer: PeerId, cause: LinkLossCause },
    RePunching {
        peer: PeerId,
        reason: RePunchReason,
    },
    /// 死局判定（04 D5 评分），附诊断报告，外围据此向用户完整呈现
    DeadEnd {
        peer: PeerId,
        diagnosis: DeadEndReport,
    },
    /// 房间锚点接替/房主回归（epoch 增加即发生）
    RoomAnchorChanged {
        epoch: u64,
        anchor: PeerId,
        reason: AnchorChangeReason,
    },
    /// 已成功加入房间（成员表就绪）
    RoomJoined {
        room: [u8; 32],
        members: usize,
    },
    /// 加入房间失败（存储不可达/报道超时）
    RoomJoinFailed {
        room: [u8; 32],
        reason: RoomJoinFailReason,
    },
    /// 预算闸门触发：外围须停止催促重连，等待下个窗口
    BudgetExhausted { room_id: [u8; 32] },
    /// 内核学习到长超时、自动降频时告知
    KeepaliveSuspended { peer: PeerId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLossCause {
    NatExpired,
    NetworkChanged,
    PeerGone,
    BudgetExhausted,
    ReleasedByPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RePunchReason {
    /// 降级档 30s 探测发现 UDP 恢复
    UdpRecovered,
    /// NAT 重绑定（多数被 QUIC 连接迁移吸收）
    NatRebound,
    /// 外围请求（LinkControl::request_upgrade）
    UpgradeRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorChangeReason {
    OwnerLeft,
    AnchorTimeout,
    OwnerReturned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomJoinFailReason {
    NoDhtAttached,
    NotFound,
    ReportTimeout,
}

/// 死局诊断报告（04 §4.6.4 诊断日志的代码形态）
#[derive(Debug, Clone)]
pub struct DeadEndReport {
    /// 04 D5 评分（≥70 判死局；65-75 区间为"极难"警告）
    pub score: u8,
    pub nat_type: &'static str,
    pub firewalled: bool,
    pub udp_blocked: bool,
    pub cgnat: bool,
}