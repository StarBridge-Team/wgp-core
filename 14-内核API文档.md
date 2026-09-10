# 14-内核 API 文档（wgp-core 对外接口定版）

**状态**：v1.0（2026-09-10）
**定位**：wgp-core 对外接口的权威定义。所有签名以本文件为准，实现（wgp-core/wgp-*）与文档漂移即 bug。

---

## 0. 三个设计原则

1. **内核被动交付、外围主动消费**：内核产出链路与事件，外围决定消费时序。
2. **所有权只转移一次**：密钥与链路 socket 交付即归外围，内核侧副本一律 zeroize。
3. **保活唯一权在内核**：外围唯一入口是 `suspend/resume_keepalive`，且受内核否决权约束；外围不得自行发心跳/PING。

---

## 1. 基础类型

```rust
pub type PeerId = [u8; 16];                      // ed25519 公钥哈希截断
pub type RoomId = [u8; 32];                      // SHA256("wgp/room/v1" || U/房码)
pub struct RoomCode(String);                     // "U/XXXX-XXXX-XXXX-XXXX"
pub struct RoomKey(Vec<u8>);                     // 房间密钥（不参与会话密钥派生，13 §6）
pub struct SecretBox<T: Zeroize>(T);             // 取出即销毁的一次性容器
```

---

## 2. 交付物 PunchedLink

```rust
pub struct PunchedLink {
    pub peer_id: PeerId,
    pub transport: LinkTransport,
    pub peer_addr: SocketAddr,                   // 验证过的对端地址
    pub session_key: SecretBox<[u8; 32]>,        // 所有权随结构转移
    pub quality: LinkQuality,
    pub rank: LinkRank,
}

pub enum LinkTransport {
    Udp  { socket: UdpSocket },                  // 外部跑 QUIC
    Tcp  { stream: TcpStream },                  // 外部跑 TLS-PSK + 帧流
    Icmp { chan: IcmpChan },                     // 逃生（仅信令级）
    Lan  { socket: UdpSocket, addr: SocketAddr },
}

pub enum LinkRank { Primary, Degraded, Escape }

pub struct LinkQuality {
    pub rtt: Duration,
    pub loss: f32,
    pub measured_mtu: u16,
    pub obeys_budget: bool,
}
```

---

## 3. LinkSink（内核 → 外围）

```rust
pub trait LinkSink: Send + Sync {
    fn on_link_yielded(&self, peer: PeerId, link: PunchedLink);
    fn on_link_upgraded(&self, peer: PeerId, link: PunchedLink);
    fn on_link_lost(&self, peer: PeerId, cause: LinkLossCause);
}

pub enum LinkLossCause {
    NatExpired, NetworkChanged, PeerGone,
    BudgetExhausted, ReleasedByPeer,
}

// 生命周期时序：
// yield(至多一次) → [upgraded × N] → lost → [重打洞成功 → yield] → …
```

---

## 4. KeyExporter 与 PQ 可选 API（D6）

```rust
pub trait KeyExporter {
    /// 一次性取出 TLS-PSK 材料（取出后内核不持明文；再次调用返回 None）
    fn take_tls_psk(&self, peer: PeerId) -> Option<PskBundle>;
    /// 当前密钥协商档位（D6：现役 X25519；PQ 开启后为 Hybrid）
    fn crypto_profile(&self) -> CryptoProfile;
}

pub struct PskBundle {
    pub identity: Vec<u8>,       // room 扰动 + Peer 对序 + epoch，两端推导一致
    pub key: SecretVec<u8>,      // 32B
    pub max_early_data: u32,     // 0-RTT 上限
}

/// 未来线：后量子可选。现役仅 X25519 实现；
/// Hybrid 实现 = 承诺字段类型标签 0x02 + rustls 的 X25519MLKEM768 挂接。
/// 开启点：wgp-crypto 的 KeyAgreement 实现 + 协议版本号递增，调用方无感。
pub trait KeyAgreement: Send + Sync {
    fn keygen(&self, rng: &mut impl CryptoRngCore) -> Self::PrivKey;
    fn pubkey(&self, sk: &Self::PrivKey) -> Vec<u8>;
    fn agree(&self, sk: &Self::PrivKey, peer_pk: &[u8]) -> Option<Vec<u8>>;
    type PrivKey: ZeroizeOnDrop;
    fn algo_id(&self) -> u8;     // 0x01=X25519, 0x02=Hybrid(PQ), 扩展位
}

#[non_exhaustive]
pub enum CryptoProfile { X25519Aes128Gcm, HybridPqMlKem768 }
```

---

## 5. SignalingBus（事件流，tokio broadcast）

```rust
#[non_exhaustive]
pub enum EngineEvent {
    PunchingStarted   { peer: PeerId },
    LinkYielded       { peer: PeerId, rank: LinkRank },
    LinkUpgraded      { peer: PeerId, from: LinkRank, to: LinkRank },
    LinkLost          { peer: PeerId, cause: LinkLossCause },
    RePunching        { peer: PeerId, reason: RePunchReason },
    DeadEnd           { peer: PeerId, diagnosis: DeadEndReport },
    RoomAnchorChanged { epoch: u64, anchor: PeerId, reason: AnchorChangeReason },
    BudgetExhausted   { room_id: RoomId },
    KeepaliveSuspended{ peer: PeerId },
}

pub enum RePunchReason {
    UdpRecovered,     // 降级档 30s 探测发现 UDP 恢复
    NatRebound,       // NAT 重绑定（多数被 QUIC 连接迁移吸收）
    UpgradeRequested, // 外围请求（LinkControl）
}
```

---

## 6. LinkControl（外围 → 内核）

```rust
pub trait LinkControl {
    fn release(&self, peer: PeerId);
    fn request_upgrade(&self, peer: PeerId);
    fn suspend_keepalive(&self, peer: PeerId);   // 可能被内核否决（超 NAT 学习值）
    fn resume_keepalive(&self, peer: PeerId);
    /// 未来线 transport 可插拔：本端可用载体集（实验区协议在此挂线）
    fn advertise_transports(&self, supported: TransportCapabilitySet);
}
```

---

## 7. RoomApi（多人房间，D7）

```rust
pub trait RoomApi {
    fn join(&self, code: &RoomCode, auth: Option<RoomKey>) -> JoinHandle;
    fn leave(&self, room: RoomId);
    fn members(&self, room: RoomId) -> Vec<MemberInfo>;
    fn kick(&self, peer: PeerId);                 // 房主专有
}

pub struct MemberInfo {
    pub peer_id: PeerId,
    pub role: RoomRole,                           // Owner / Anchor / Member
    pub link_rank: Option<LinkRank>,
}

pub struct JoinHandle { /* 可取消；取消后 100ms 内完成清理（保活停/密钥清/预算归还） */ }
```

---

## 8. ProbeCarrier（底层多协议，D9）

```rust
/// 只要能"向目标发小包 + 收对端小包"，就能当打洞载体。
/// 引擎只面向本 trait 编程，不认识具体协议。
pub trait ProbeCarrier: Send + Sync {
    fn send_probe(&self, dst: SocketAddr, payload: ProbePayload) -> Result<(), CarrierError>;
    fn on_probe(&self, src: SocketAddr, payload: ProbePayload) -> bool;
    /// 关键：每种协议的 NAT 映射语义（UDP 打端口/ICMP 打 identifier/…）
    fn mapping_semantics(&self) -> MappingSemantics;
    fn capability(&self) -> TransportCapability;  // 用于能力位交换与广告
}

pub enum MappingSemantics {
    PortTagged { port: u16 },        // UDP/TCP
    IdentifierTagged { id: u16 },    // ICMP Echo query identifier
    AddrOnly,                        // LAN 组播
}
```

---

## 9. Engine 门面（内核唯一入口）

```rust
pub struct Engine;

impl Engine {
    /// 客户端路径：发起/接受一次打洞会话 → 事件流
    pub fn new_link(&self, intent: LinkIntent) -> LinkStream;   // feature="client"

    /// 房间路径：加入房间，内部为每个成员驱动一条 mesh 边
    pub fn join_room(&self, code: RoomCode, auth: Option<RoomKey>) -> RoomHandle;

    /// 节点路径：以种子/观察者身份运行（长沙服务器用）          // feature="node"
    pub fn run_node(&self, cfg: NodeConfig) -> NodeHandle;

    /// 订阅事件（LinkSink 的流式形态）
    pub fn subscribe(&self) -> EventStream;
}
```

---

## 10. 生命周期六条款（实现必须遵守）

1. **yield 一次语义**：竞速先通先用；yield 后同档更优链路不再重复交付；跨档升级走 `upgraded`。
2. **旧链路宽限 30s**：`upgraded` 后内核继续保活旧链路 30s 供外围切换；到期停止保活并清 socket。
3. **密钥单次转移**：`take_tls_psk` 与 `session_key` 一次性取出；内核任何路径不得缓存明文副本（zeroize 审计点）。
4. **保活唯一权**：外围唯一入口 `suspend_keepalive`，受否决权约束；双发心跳即缺陷。
5. **重连幂等**：lost → re-punch → yield 环上，新旧 session_key 必然不同（全新 ECDH），外围必须以新代旧。
6. **取消语义**：JoinHandle 取消后 100ms 完成清理，无悬挂流量。

---

## 11. 版本与扩展性

- 所有 `pub enum` 一律 `#[non_exhaustive]`；所有 trait 方法新增一律走默认实现或版本协商位。
- 协议版本号在每包头部（wgp-proto）；`crypto_profile`/`advertise_transports` 完成能力协商。
- 新增载体 = 新写一个 `ProbeCarrier` 实现（引擎零改动）；新增密码学 = 新写一个 `KeyAgreement` 实现（调用方零改动）—— 两条未来线接口已在本文档落地。

---

## 12. 实现演进记录（内核 v0.2，2026-09）

本文档为设计契约；实现过程中经实测调整的签名漂移在此登记（代码为最终权威）：

| 条款 | 文档初版 | 实现定版 | 原因 |
|------|---------|---------|------|
| new_link 输入 | `LinkIntent` | `PunchInput`（含 `carrier/tcp/udp_enabled/session_key/model/seed`） | 信令面与引擎解耦：参数由 DHT 协商层注入 |
| join_room | 同步 `→ RoomHandle` | `async → Result<RoomHandle, RoomError>`；**第一人加入自动建房**（房主=锚点） | DHT 读写天然异步；自动建房消除"建房与加入"双入口竞态 |
| RoomHandle | `cancel()` | `leave()` | 语义更准（停 upkeep + 注销） |
| 信令上下文 | 隐含 | 显式 `attach_dht(node, storage)` | 内核无隐式网络假设 |
| 竞速 | 未定义 | `race_punch` + `RaceOutcome`（UDP∥TCP 先通先用、一方先败不阻另一方）；T1 命中可跳过 UDP（`udp_enabled=false`） | 00 ADR D10 |
| T1-T4 判定 | 文本 | `CircuitInput::tcp_triggered()` / `decide_race()` 纯函数 | 可单测的触发层 |
| 载体集 | UDP/TCP | + ICMP 逃生（`IcEscape`，Win iphlpapi / Unix ping-socket 双后端）+ LAN 组播（`LanProbeCarrier`） | 00 ADR D11；Unix ICMP 后端待服务器首日编译验证 |
| 保活 | 条款 4 契约 | UDP 链路交付后自动挂 `keepalive_loop`（HeartbeatLoop 节奏 + 探针包 + 预算闸门）；`LinkControl::release` 已实现 | 内核唯一负责保活 |
| LinkTransport::Tcp | — | TCP 命中交付 rank=`Degraded`；其保活由 TCP keepalive 承担，内核不另发探针 | 00 §4 链路优先级 |
| UDP 波次 | 发一批→短监听 | 边发边收（发一包前非阻塞查收 + 波尾收紧窗） | 150ms 时序压缩窗（03 §3.5.6） |
| 双模定时器 | 03 §3.3.5 | `DualModeTimer`（Normal/Precision + 校准偏移；Windows 15.6ms 定时器分辨率提升列真机前置项） | 对齐 03 |

**已验证边界（诚实声明）**：全部 92 测试为 Windows loopback；跨平台性由"零平台依赖代码 + tokio 抽象"保证，Linux 侧以 [deploy/DEPLOY.md](deploy/DEPLOY.md) 第 0 步"编译测试先行"为验证门。

*文档结束*