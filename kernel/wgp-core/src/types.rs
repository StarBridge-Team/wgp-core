//! LinkSink / RoomApi / LinkControl / 意图类型（14 §3/§6/§7）。
//! 三原则：内核被动交付；所有权一次转移；保活唯一权在内核。

use crate::link::PunchedLink;
use crate::rank::LinkRank;
use crate::PeerId;
use wgp_punch::TransportCapability;

/// 房间码（"U/XXXX-XXXX-XXXX-XXXX"，13 文档）
pub struct RoomCode(pub String);

/// 房间密钥（不参与会话密钥派生，13 §6）
pub struct RoomKey(pub Vec<u8>);

/// 房间 ID（DHT 键，07 §4 派生）
pub type RoomId = [u8; 32];

/// 链路生命周期时序：
/// yield(至多一次) → [upgraded × N] → lost → [重打洞成功 → yield] → …
pub trait LinkSink: Send + Sync {
    fn on_link_yielded(&self, peer: PeerId, link: PunchedLink);
    /// 更优链路（升级）；旧链路按 00 §4 宽限 30s 供外围切换
    fn on_link_upgraded(&self, peer: PeerId, link: PunchedLink);
    fn on_link_lost(&self, peer: PeerId, cause: crate::event::LinkLossCause);
}

/// 外围 → 内核的控制回向（14 §6）
pub trait LinkControl: Send + Sync {
    /// 主动断开（应用退出/被踢/用户取消）→ 停保活 + 清密钥
    fn release(&self, peer: PeerId);
    /// 请求立即升级探测（不等 30s 周期）
    fn request_upgrade(&self, peer: PeerId);
    /// 挂起保活（可能被内核否决：超出该 Peer 的 NAT 学习超时值）
    fn suspend_keepalive(&self, peer: PeerId);
    fn resume_keepalive(&self, peer: PeerId);
    /// 本端可用载体集（实验区协议在此挂线，00 D9）
    fn advertise_transports(&self, supported: TransportCapabilitySet);
}

/// 能力集（能力位交换的集合形态）
pub struct TransportCapabilitySet(pub Vec<TransportCapability>);

/// 连接意图（new_link 入参）
pub struct LinkIntent {
    pub peer: PeerId,
    pub transport_hint: Option<TransportCapability>,
}

/// 可取消句柄：取消后 100ms 内核完成清理（保活停/密钥清/预算归还）
pub struct JoinHandle {
    pub room: RoomId,
}

/// 多人房间角色（07 §1：房主/锚点分离）
pub enum RoomRole {
    Owner,
    Anchor,
    Member,
}

pub struct MemberInfo {
    pub peer_id: PeerId,
    pub role: RoomRole,
    pub link_rank: Option<LinkRank>,
}

/// 房间 API（14 §7，D7 mesh）
pub trait RoomApi: Send + Sync {
    fn join(&self, code: &RoomCode, auth: Option<RoomKey>) -> JoinHandle;
    fn leave(&self, room: RoomId);
    fn members(&self, room: RoomId) -> Vec<MemberInfo>;
    /// 房主专有；锚点转手不改变房主权限语义
    fn kick(&self, peer: PeerId);
}