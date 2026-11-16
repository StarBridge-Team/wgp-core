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

    /// 房间路径：加入房间（入表；mesh 打洞边由外围 SessionOrchestrator 驱动）
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
| mesh 边驱动 | join_room 内部驱动 | 外围 `SessionOrchestrator::connect_peer(room, peer, sink)`（client 的 member_watch 每 2s 感知新成员触发） | 打洞是对外部可见的副作用，归属编排层；join_room 仅保证入表；`connect_peer` commit 阶段 accept 放宽（Commit|Reveal），防成员加入时序错位导致的阶段漂移死锁 |
| 竞速 | 未定义 | `race_punch` + `RaceOutcome`（UDP∥TCP 先通先用、一方先败不阻另一方）；T1 命中可跳过 UDP（`udp_enabled=false`） | 00 ADR D10 |
| T1-T4 判定 | 文本 | `CircuitInput::tcp_triggered()` / `decide_race()` 纯函数 | 可单测的触发层 |
| 载体集 | UDP/TCP | + ICMP 逃生（`IcEscape`，Win iphlpapi / Unix ping-socket 双后端）+ LAN 组播（`LanProbeCarrier`） | 00 ADR D11；Unix ICMP 后端待服务器首日编译验证 |
| 保活 | 条款 4 契约 | UDP 链路交付后自动挂 `keepalive_loop`（HeartbeatLoop 节奏 + 探针包 + 预算闸门）；`LinkControl::release` 已实现 | 内核唯一负责保活 |
| LinkTransport::Tcp | — | TCP 命中交付 rank=`Degraded`；其保活由 TCP keepalive 承担，内核不另发探针 | 00 §4 链路优先级 |
| UDP 波次 | 发一批→短监听 | 边发边收（发一包前非阻塞查收 + 波尾收紧窗） | 150ms 时序压缩窗（03 §3.5.6） |
| 双模定时器 | 03 §3.3.5 | `DualModeTimer`（Normal/Precision + 校准偏移；Windows 15.6ms 定时器分辨率提升列真机前置项） | 对齐 03 |

### 12.1 追加登记（2026-11：M2 数据面 / M4 DHT 接线 / 缺陷修复）

| 条款 | 此前 | 实现定版 | 原因 |
|------|------|---------|------|
| `PunchedLink` | 实现里没有对端地址（本文 §2 其实写了） | 新增 `peer_addr: SocketAddr`（UDP = 命中探针的来源；TCP = 流的对端） | 外围拿到链路必须知道往哪发 |
| 预算口径（H6） | 全进程共用一「轮」47 包，且从不复位 | `BudgetScheduler::reserve_round / refund_round`：每次打洞会话从 10 分钟窗口预扣一轮、结束归还；保活走 `try_acquire_keepalive`（只过窗口闸门）；窗口按 10 分钟回填 | 第二次打洞起配额为 0、保活永久停摆 |
| `keepalive_loop` | 固定节拍 | 新增 `active_links` 参数 + `fair_share_interval_ms`：多条链路按份额分摊窗口预算 | 多 Peer 时不互相饿死 |
| `SessionOrchestrator` | 只有 `connect_peer` | 新增 `wait_incoming(room, peer, settle)`（被动应答：对端发起新一轮协商时返回）；`connect_peer` 能消化提前到达的 Reveal；端点帧先验长度；对端无步长模型时用其实测端口兜底建模 | 重连需要被动端；修阶段漂移死锁与越界 panic |
| 数据面（§4、00 D3） | UDP → QUIC-TLS-PSK；TCP → TLS-PSK 帧流 | `bridge/wgp-port`：AES-256-GCM（会话密钥经 HKDF 派生双向密钥，`wgp_crypto::tunnel`）；UDP 上自带可靠层，TCP 上记录流；隧道报文类型 `0x40` 登记于 `wgp_proto::packet::tunnel`。`KeyExporter::take_tls_psk` 未被使用 | rustls 0.23 没有外部 PSK 接口；01 §1.3 早有 AES-GCM 帧设计；零新增第三方依赖。可靠层与复用层只有一个接缝，日后可换 QUIC |
| `JoinRequest` | `"WJ"‖len‖房间码‖id‖pk‖sig`（变长） | v2：`"WJ"‖0x02‖room_key‖id‖pk‖sig`（163B）；`sign(identity, code)` / `verify(code, payload)`；校验 `id == SHA256(pk)` | 房间码是会话密钥派生的口令，不得经第三方中转。**与旧版不兼容** |
| `RoomRuntime::try_takeover` | `(code, current, now_ms)`，按 `lease.expired(now)` 判定 | `(code, current, unchanged_ms, now_ms)`；新增 `LeaseWatch`：成员只看「本地观测到租约多久没变」 | 不同进程的单调时钟不可比（H5 禁读系统时钟） |
| `join_room` 入表 | 报道发一次，轮询 3s | 轮询 6s，每 1.5s 补发报道 | 报道无应答，丢一个包即失败 |
| 种子广告 | V1（91B，无公钥），从未发送 | V2（type `0x21`，123B，自带公钥，布局见 17 §10）；RPC `FIND_SEEDS(0x39)` / `SEEDS(0x3A)`（应答不长于请求）；`SeedDirectory`；`DhtNode::{start_advertising, find_seeds, discover, seek_seeds, lookup_node, spread, spawn_maintenance, seeds, watch_seeds}` | 17 P0：让节点互相发现 |
| `NodeConfig` | 6 个字段 | 新增 `advertise / advertise_epoch / peers` | 同上；纪元由外围持久化（启动计数）后注入 |
| `TcpProbeCarrier` | 只主动连接，靠 SYN 交叉（simultaneous open）建立；一波里的多个端口并行尝试时绑同一个源端口，却没开端口共用 | 同端口「监听 + 主动连接」，先通先用；监听口先验对端探针、通过后才回我方探针；socket 开 SO_REUSEADDR（Unix 另加 SO_REUSEPORT）；一次 `punch_port` 总时限 990ms；返回流的对端以 `peer_addr()` 为准 | Linux 上 SYN 不交叉就被本机 RST 拒绝，回环与公网直连主机上必然失败（Windows 会自行重发 SYN，掩盖了问题）；并行尝试互相挤占端口，实际只有第一个端口在试 |
| `PunchRunner::run_waves` | 收到第一枚验签通过的包就结束本波监听，再判断它算不算命中 | 不算数的包（自己的探针折返、源 IP 不是对端）丢弃后继续等到窗口结束 | 撒网端口撞上自己的端口时，自己的探针折返会让随后到达的真对端探针被错过。引擎实际使用的竞速执行器（`race.rs`）本来就是这样处理的 |
| 节点入网引导（`run_node` / `DhtNode::discover`） | 引导只做一次；自己的广告只在启动时与每 60s 推送 | 一个引导端点都没问到时按 0 / 0.3 / 0.7 / 1.5 / 3 / 6 秒重试，之后交给周期维护；`discover` 结束时把自己的广告推给已知种子 | 几个种子同时启动、对方端口还没开时，要 20～60 秒才互相认识；这期间两个只认识不同种子的客户端会把同一个房间建到两个存储节点上 |
| `RoomRuntime::upkeep` | 读不到房间记录就跳过本轮；成员平时只读记录，不向存储节点登记地址 | 记录不存在时，锚点凭上一次读到的记录原样恢复（成员表保留，epoch 不变）；全员每 3 轮（约 6 秒）向存储节点 PING 一次 | 存储节点的房间记录与地址簿都只在内存里：它重启后房间「不存在」，经它中转给老成员的消息被丢弃 |
| 房间存储节点 | 外围取「测速最快的 UDP 种子」 | `RoomRuntime::locate(node, code, candidates)`：已有该房间记录的优先；否则可达候选按中转能力分档（明确可中转 > 不知道 > 明确不中转），同档取离房间键最近者。仍是单存储点 | 两端必须选中同一个才能相遇 |

### 12.2 追加登记（2026-11-16：身份证明 / TCP 兜底 / 路由维护 / 多进程）

| 条款 | 此前 | 实现定版 | 原因 |
|------|------|---------|------|
| 身份学习闸门 | PING/PONG/STORE 里「`node_id == SHA256(pk)`」即入路由表与地址簿 | `DhtNode` 只在 `accept_proof` 通过（签名 + 一次性 nonce + 来源地址 + 期限）后调 `learn_verified`；PING/PONG/STORE 不再写表。新增 `auth` 模块（`bound_identity` / `sign_proof` / `verify_proof` / `make_challenge` / `fresh_nonce`）与 RPC `AUTH_CHALLENGE(0x3B)` / `AUTH_PROOF(0x3C)` / `AUTH_REJECT(0x3D)`（17 §11） | 绑定校验只证明「公钥与 node_id 自洽」，录下旧报文换地址重放即可把已知节点指向攻击者 |
| `RpcError` | `Timeout / NoRoute / PayloadTooLarge` | 新增 `Unverified`（对端不支持身份证明）/ `UnsupportedVersion` / `Busy`（本地待应答挑战满）；`explain()` 给用户可读文案 | 严格模式下必须把「旧版本」与「不可达」分开报，否则排障只能猜 |
| `PingBody` / `PONG` 语义 | 双向学习原语 | `PING` 只为存活与兼容而应答；`PONG` 只在 `IdentityPolicy::LegacyAllowed` 的等待项上学习。`DhtNode::set_identity_policy / identity_policy / legacy_fallback_count / rejected_proof_count` | 安全降级必须是运营者的显式决定 |
| 信令承载 | 房间 RPC 只有 UDP | `Transport::{Udp,Tcp}`；`DhtNode::set_signaling_transport` 让 `ping/find_node/store/find_value/forward_to/find_seeds` 统一分派到 TCP 版本（复用同一 RPC 与 u16 长度前缀）；`RoomRuntime::with_transport` + `StorageCandidate.transport`；`ping_tcp` 也改成挑战响应，新增 `ping_tcp_legacy` | UDP 被封时 bootstrap / 选点 / `fetch`·`store`·`renew` 仍可用。TCP 不能完成「报道→锚点」这一跳（Forward 要地址簿里的 UDP 目标），已在 12 §6.5 记录 |
| 广告能力位 | `flags` bit0 = 可中转 | 新增 `FLAG_AUTH_V1 = 0x02`；`SeedInfo::supports_auth()`；`NodeConfig::allow_legacy_identity`；`wgp-node --allow-legacy-identity`（配置键 / `WGP_ALLOW_LEGACY_IDENTITY`），客户端同名校验参数 | 让客户端在探活之前就能判断种子是否会讲身份证明，并给出可操作的提示 |
| 路由维护 | 无主动淘汰；每拍只探种子 | `probe_window`（纯函数）+ `probe_routing_batch(&skip)`：每拍至多 8 个普通路由节点、连续 3 次失败释放桶位；本拍已被种子探活覆盖的身份跳过；探活成功刷新地址簿最后见时刻 | 死路由占桶位不下线；同一批公网节点既是种子又在路由表里，重复握手纯属浪费 |
| 多进程（阶段 1） | 单进程 `wgp-client` | 新增 `wgp-ipc`（本机 UDS / Windows 命名管道、长度前缀帧、ACL、有界队列）与 `wgp-agent`（持有 DHT 身份、socket、Engine、PortHub；IPC 命令 `GetVersion/GetCapabilities/GetSnapshot/StartRoom/JoinRoom/LeaveRoom/WatchEvents/ShutdownAgent`）。GUI 仍是后续工作 | UI 崩溃不该带走网络；私钥与 socket 只能有一个所有者 |

**已验证边界（诚实声明）**：截至 2026-11-16，全部自动化测试与端到端脚本仍跑在回环上（Windows、WSL2 里的 Linux）；TCP 兜底、身份证明、路由维护都有回环测试，但**没有任何一次真实 NAT 下的双端联调**。跨平台性由「零平台依赖代码 + tokio 抽象」保证，Linux 侧以 [部署清单](../server/deploy/DEPLOY.md) 第 0 步「编译测试先行」为验证门。

*文档结束*