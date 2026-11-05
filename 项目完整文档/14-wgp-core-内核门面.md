# wgp-core 内核门面详细文档

> **源目录**：`kernel/wgp-core/src/`（20 个源文件）
> **生成日期**：2026-11-05
> **对应设计文档**：`docs/14-内核API文档.md`（对外接口定版）、`docs/00-架构总览.md` §4（内核设计）、`docs/15-全链路流程.md`（端到端时序）
> **文档性质**：本文档由通读 crate 全部源文件后撰写，只记录代码中真实存在的内容；关键签名照抄源码；与设计文档不一致处（实现漂移）在第 5 章逐条登记。

---

## 1. Crate 概览

### 1.1 定位

`wgp-core` 是折跃门（wgp）Rust workspace 的最上层 crate，即**内核门面**。它是全部对外 API 的唯一出口（00 §3 依赖纪律：`proto ← crypto ← punch ← dht ← core`，core 在依赖链顶端）。

lib.rs 顶部注释声明的**内核契约**三条（00 §4 的代码化）：

1. **职责终点 = 产出一条已打通的链路（`PunchedLink`）**；起点 = 收到连接意图。内核不解析应用协议、不建 QUIC 连接、不做数据面（00 §4"不做清单"）。
2. **保活唯一权在内核**：外围零心跳。链路交付后内核自动挂 `keepalive_loop` 哨兵；外围唯一入口是 `LinkControl::suspend/resume_keepalive`（14 §10 条款 4）。
3. **调度器是唯一发包点**：所有探针/保活包均经 `BudgetScheduler`（来自 wgp-punch）的 `try_acquire(1)` 扣减，房间维度共享（00 §3 / H6：≤47 包/轮、≤500 包/10 分钟）。

三条用户可见路径（engine.rs 头注释）：

- `Engine::new_link`（feature `client`）：客户端打洞路径，输入已协商完成的 `PunchInput`，输出经事件总线 + `LinkSink` 回调双通道交付。
- `Engine::join_room`（feature `client`）：多人房间路径（D7 mesh），入表 + upkeep 三合一循环。
- `Engine::run_node`（无 feature 门控）：wgp-node 服务端路径，DHT 种子 / 观察者 / TCP 信令兜底三面。

### 1.2 feature 裁剪（00 ADR D1 的编译期落点）

`Cargo.toml` 原文：

```toml
[features]
default = ["client"]
client = ["dep:wgp-punch", "dep:wgp-crypto", "dep:rand_core", "dep:sha2"]
node = []
```

| feature | 含义 | 编译产物 |
|---------|------|---------|
| `client`（默认） | 打洞/信令/载体/密钥导出全量 | 含 engine 五子模块（circuit/keepalive/nat_probe/punch_runner/race）、orchestrator、exporter、link、servers、transport、types 全部模块；引入 wgp-punch、wgp-crypto、rand_core、sha2 依赖 |
| `node` | 仅服务端四职（DHT 种子/观察者/STUN/承诺转发兜底） | 只留 `engine`（裸 Engine + `run_node`）、`event`、`rank` 三模块；**不含打洞引擎与密钥协商逻辑**；wgp-punch/wgp-crypto 不参与编译 |

注意：`node` feature 本身是**空 feature**（`node = []`），裁剪效果完全由 `#[cfg(feature = "client")]` 属性反向实现——即"默认全量，非 client 构建自动收敛为 node 面"。`default = ["client"]` 意味着不加参数构建即客户端全量面。

### 1.3 依赖（Cargo.toml）

| 依赖 | 可选性 | 用途 |
|------|--------|------|
| `wgp-proto`（path） | 必选 | 包格式/常量（`WAVE_TIMEOUT_MS`、`packet::probe` 31B 帧、STUN 子集）、`SeedEndpoint/SeedScheme`、DHT 帧 |
| `wgp-dht`（path） | 必选 | `DhtNode`、`NodeIdentity`、`ObserverServer`、`ObserverPolicy`、`RoomRuntime`、`room_key`、`NodeId`、`peer_id_from_node`、`RelayPolicy`、`RoomError` |
| `wgp-punch`（path） | optional（client） | `BudgetScheduler`、`PortStepModel`、`plan_waves`、`HeartbeatLoop`/`HbAction`、`ProbeCarrier`/`CarrierError`/`MappingSemantics`/`TransportCapability`、`PunchState` |
| `wgp-crypto`（path） | optional（client） | `SecretBox`、`CryptoProfile`、承诺-揭示（`commit`/`verify`/`Commitment`）、`derive_all`/`probe_auth`/`lan_auth`/`escape_auth`、`X25519Agreement`/`KeyAgreement` |
| `rand_core`（workspace） | optional（client，dev 亦依赖） | `OsRng`/`RngCore`（orchestrator 与测试） |
| `sha2`（workspace） | optional（client） | `Sha256`（orchestrator 的 session_tag/punch_seed/info_ctx 派生） |
| `tokio`（workspace） | 必选 | 全部异步运行时、`broadcast`/`watch`/`Mutex`/`mpsc`、`TcpStream`/`UdpSocket` |
| `socket2`（workspace） | 必选 | LAN 组播载体（SO_REUSEADDR + join_multicast_v4）、Unix ICMP ping socket |

**纪律符合性**：00 §3 要求"proto/crypto 禁止依赖 tokio"——wgp-core 直接依赖 tokio/socket2 但不破坏该条（它自身就是 async 面）；内核不引入 quinn/rustls（00 §8：quinn 属客户端数据面任务）。

---

## 2. 模块结构总表

| 文件 | 职责 | 关键导出 |
|------|------|---------|
| `src/lib.rs` | crate 根：模块声明 + 全量 re-export + `PeerId` 类型别名 | `PeerId`；全部 pub use（见第 4 章） |
| `src/engine.rs` | Engine 门面（内核唯一入口）：new_link / join_room / run_node 三路径 + `LinkControl for Engine` 实现 | `Engine`、`LinkStream`、`NodeConfig`、`NodeHandle`、`NodeRole`、`PunchInput`(c)、`RoomHandle`(c) |
| `src/engine/punch_runner.rs` | 三波执行器（串行简化版）：计划→预算闸门→发包→监听验签→命中判定 | `PunchOutcome`、`PunchRunner` |
| `src/engine/circuit.rs` | T1-T4 TCP 兜底触发判定（纯函数层） | `TcpTrigger`、`CircuitInput`、`RaceConfig`、`decide_race` |
| `src/engine/keepalive.rs` | NAT 保活哨兵主循环（内核唯一保活权） | `keepalive_loop` |
| `src/engine/nat_probe.rs` | 观察者探测（STUN binding + XOR-MAPPED）、NAT 粗判、步长学习 | `NatProbe`、`ObserverReport`、`NatClass`、`classify_reports` |
| `src/engine/race.rs` | 竞速执行器（00 D10）：UDP 三波 ∥ TCP simultaneous open，先通先用 | `race_punch`、`RaceOutcome` |
| `src/orchestrator.rs` | 装配线：承诺-揭示→观察者探测→端点交换→T1-T4 判定→PunchInput 组装→同步开火 | `SessionOrchestrator`、`OrchestratorError` |
| `src/rank.rs` | 链路档位（00 §4 优先级） | `LinkRank` |
| `src/event.rs` | 事件总线载荷（14 §5 tokio broadcast） | `EngineEvent`、`LinkLossCause`、`RePunchReason`、`AnchorChangeReason`、`RoomJoinFailReason`、`DeadEndReport` |
| `src/types.rs` | 外围↔内核契约 trait 与意图类型（14 §3/§6/§7） | `LinkSink`、`LinkControl`、`RoomApi`、`RoomCode`、`RoomKey`、`RoomId`、`RoomRole`、`MemberInfo`、`LinkIntent`、`JoinHandle`、`TransportCapabilitySet` |
| `src/link.rs` | 交付物：一次打击 = 一条可用链路 | `PunchedLink`、`LinkTransport`、`LinkQuality`、`IcmpChan` |
| `src/exporter.rs` | TLS-PSK 一次取出 + PQ 档位查询 API 落点 | `KeyExporter`、`PskBundle` |
| `src/servers.rs` | 种子发现第 1 层：端点解析 + 并发测速选路 | `measure_seeds`、`pick_fastest_seed`、`resolve_endpoint`、`SeedPick` |
| `src/transport/mod.rs` | 载体集合门面（00 §4 四档链路） | re-export 四载体 |
| `src/transport/probe.rs` | 探针组帧/验签共用逻辑（UDP/TCP 复用） | `now_ms`、`craft_probe`、`verify_probe` |
| `src/transport/udp.rs` | UDP 探针载体（主档） | `UdpProbeCarrier` |
| `src/transport/tcp.rs` | TCP simultaneous-open 载体（兜底档） | `TcpProbeCarrier`、`TCP_PORT_PUNCH_TIMEOUT_MS` |
| `src/transport/lan.rs` | LAN 组播发现载体（第一档） | `LanProbeCarrier`、`DEFAULT_GROUP`、`beacon` 子模块 |
| `src/transport/escape.rs` | ICMP 逃生载体（第四档，Win/Unix 双后端） | `IcEscape`、`escape_frame` 子模块 |

（表中 `(c)` = 仅 `feature = "client"` 编译。）

---

## 3. 逐文件详细文档

### 3.1 `src/lib.rs`

**一句话职责**：crate 根——模块声明、feature 门控、全量对外 re-export、`PeerId` 定义。

**模块声明与门控**（照抄）：

```rust
pub mod engine;
pub mod event;
#[cfg(feature = "client")] pub mod exporter;
#[cfg(feature = "client")] pub mod link;
#[cfg(feature = "client")] pub mod orchestrator;
pub mod rank;
#[cfg(feature = "client")] pub mod servers;
#[cfg(feature = "client")] pub mod transport;
#[cfg(feature = "client")] pub mod types;
```

即：`engine`/`event`/`rank` 两个 feature 都编译；其余五个模块仅 client。

**类型别名**：

```rust
/// Peer 短标识 = DHT 节点身份公钥哈希截断
pub type PeerId = [u8; 16];
```

**re-export 全量清单**见第 4 章。三处跨 crate 转发值得注意：

- `pub use wgp_crypto::{CryptoProfile, SecretBox};`（client）——密码学档位与一次性密钥容器经内核转出，外围无需直接依赖 wgp-crypto。
- `pub use wgp_dht::id::peer_id_from_node;`（无门控）——NodeId → PeerId 转换函数经内核转出。
- `pub use wgp_punch::{ProbeCarrier, PunchState};`（client）——D9 载体 trait 经内核转出，外围实现新载体（实验区协议）时面向它编程。

**测试**：无。

---

### 3.2 `src/engine.rs`（786 行，本 crate 最大文件）

**一句话职责**：Engine 门面——内核唯一入口，三条路径（new_link / join_room / run_node）+ LinkControl 实现 + 测试。

#### 3.2.1 常量与自由函数

```rust
#[cfg(feature = "client")]
const ROOM_UPKEEP_INTERVAL_MS: u64 = 2_000;   // room upkeep 周期（续期/监控/继位三合一）

/// 进程级单调毫秒（禁止读系统时钟；03 §3.3.2 硬约束）
#[cfg(feature = "client")]
fn engine_now_ms() -> u64 { /* OnceLock<Instant> 锚点 + duration_of_since */ }
```

注意：`engine_now_ms`（engine.rs:81）与 `transport::probe::now_ms`（probe.rs:9）是**两个独立的 OnceLock 锚点**，同一进程内单调毫秒存在两套起点（代码如此，用途不同：前者供 DHT 房间 upkeep 时钟，后者供探针时间戳；意图待确认是否需要统一）。

#### 3.2.2 核心类型

```rust
/// 节点角色（07 §1/§6：公网固定地址节点 = Seed）
pub enum NodeRole { Seed, Observer }                    // Debug/Clone/Copy/PartialEq/Eq

/// wgp-node 配置（07 §6 部署规格的代码化）
pub struct NodeConfig {
    pub role: NodeRole,
    pub bind: String,                    // "0.0.0.0:11010"（示例形态；实际值来自后端配置）
    pub stun: Option<u16>,               // 同进程 STUN/观察者端口（None = 关闭）
    pub tcp_signal: Option<u16>,         // 同进程 TCP 信令兜底端口（None = 关闭）
    pub hobby: bool,                     // 贡献模式：拒绝 Forward 中转（唯一持续流量源）
    pub observer_policy: ObserverPolicy, // 观察者限频策略（默认 ObserverPolicy::default）
}
```

`NodeConfig.role` 字段在当前 `run_node` 实现中**未被读取**（run_node 不按 role 分流行为——Seed/Observer 由实际绑定哪个面隐式决定；代码如此，意图待确认）。

```rust
/// 打洞输入：已协商完成的会话上下文（承诺-揭示产物 + 对端观察报告）。
#[cfg(feature = "client")]
pub struct PunchInput {
    pub peer: PeerId,                  // 对端短标识
    pub peer_ip: IpAddr,               // 对端公网 IP（观察者报告的地址）
    pub carrier: UdpProbeCarrier,      // 本端打洞载体（承诺-揭示产出的 probe_key 已注入）
    pub tcp: Option<TcpProbeCarrier>,  // TCP 兜底载体（T1-T4 竞速路径；None = 仅 UDP）
    pub udp_enabled: bool,             // UDP 路径开关（T1 预判命中时置 false → 纯 TCP 竞速）
    pub session_key: SecretBox,        // 会话密钥（所有权随交付转移）
    pub model: Option<PortStepModel>,  // 端口步长模型（None = 无数据撒网）
    pub seed: u64,                     // 三波计划种子（由会话 nonce 派生，两端一致→同步探测）
}
```

`PunchInput` 即 14 §12 漂移表登记的"new_link 输入由 `LinkIntent` 改为 `PunchInput`"的落点：信令面与引擎解耦，全部协商产物由 orchestrator 注入。

```rust
pub struct Engine {
    tx: broadcast::Sender<EngineEvent>,                              // 事件总线（多外围订阅互不阻塞）
    #[cfg(feature = "client")]
    budget: Arc<tokio::sync::Mutex<BudgetScheduler>>,               // 房间维度共享的预算闸门（唯一发包点）
    #[cfg(feature = "client")]
    dht: Arc<tokio::sync::Mutex<Option<Arc<DhtNode>>>>,             // 信令上下文（attach_dht 注入）
    #[cfg(feature = "client")]
    storage: Arc<tokio::sync::Mutex<Option<SocketAddr>>>,           // 房间存储节点地址
    #[cfg(feature = "client")]
    links: Arc<tokio::sync::Mutex<HashMap<PeerId, watch::Sender<bool>>>>, // 活跃链路保活停止开关表
}

pub struct LinkStream { pub(crate) rx: broadcast::Receiver<EngineEvent> }
impl LinkStream {
    pub async fn next(&mut self) -> Option<EngineEvent> { self.rx.recv().await.ok() }
}

#[cfg(feature = "client")]
pub struct RoomHandle {
    pub(crate) room: [u8; 32],
    pub(crate) stop: watch::Sender<bool>,
    pub members: usize,          // 入表时成员数
}

pub struct NodeHandle {
    pub dht: Option<Arc<DhtNode>>,
    pub observer: Option<Arc<ObserverServer>>,
    pub tcp: Option<std::net::SocketAddr>,   // TCP 信令监听地址（None = 未启用）
}
```

`Engine` 的 `Clone` 为**手写实现**（engine.rs:60，所有字段 Arc 克隆，含 client 字段的门控克隆）——装配线/多人会话共享同一内核实例（含同一预算闸门与 links 表）。

#### 3.2.3 Engine 方法

```rust
impl Engine {
    pub fn new() -> (Self, broadcast::Receiver<EngineEvent>);   // broadcast::channel(256)
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent>;

    #[cfg(feature = "client")]
    pub async fn attach_dht(&self, node: Arc<DhtNode>, storage: SocketAddr);

    #[cfg(feature = "client")]
    pub fn new_link(&self, input: PunchInput, sink: Arc<dyn LinkSink>) -> LinkStream;

    #[cfg(feature = "client")]
    pub async fn release(&self, peer: PeerId);

    #[cfg(feature = "client")]
    pub async fn join_room(&self, code: RoomCode, _auth: Option<RoomKey>)
        -> Result<RoomHandle, RoomError>;

    pub async fn run_node(&self, cfg: NodeConfig, identity: NodeIdentity) -> NodeHandle;
}
```

**`new_link`（engine.rs:212-292）执行流**（14 §3 交付语义的落点）：

1. spawn 任务，先广播 `EngineEvent::PunchingStarted { peer }`。
2. 调 `race_punch(&carrier, input.tcp.as_ref(), input.model.as_ref(), input.peer_ip, input.seed, budget.clone(), input.udp_enabled)`（§3.7 race）。
3. 三分支：
   - `RaceOutcome::Udp { peer_addr, .. }` → `rank = LinkRank::Primary`；广播 `LinkYielded`；构造 `PunchedLink { transport: LinkTransport::Udp { socket: carrier.socket() }, session_key, quality: LinkQuality { rtt: 0ms, loss: 0.0, measured_mtu: 1400, obeys_budget: true }, rank }`；`sink.on_link_yielded(peer, link)`；**起保活哨兵**：`watch::channel(false)` → `links` 表插入 `stop_tx` → spawn `keepalive_loop(carrier, peer_addr, budget, stop_rx)`。注释明示：命中后接 QUIC 握手（3s 超时，T3 触发 TCP 兜底）属实现阶段，本迭代以"打洞成功"为交付点（15 Phase 6 前半）。
   - `RaceOutcome::Tcp { stream, .. }` → `rank = LinkRank::Degraded`（00 §4：LAN > QUIC > TCP > ICMP）；同样广播+交付；**不挂保活**（注释：TCP 路径保活由 TCP keepalive/流活性承担，内核不另发探针）。
   - `RaceOutcome::Failed { .. }` → `cause = LinkLossCause::PeerGone`；广播 `LinkLost` + `sink.on_link_lost`。
4. 返回 `LinkStream { rx: self.tx.subscribe() }`（订阅点设在 spawn 之后，事件不丢失——broadcast 保证订阅后收到）。

**`join_room`（engine.rs:306-403）执行流**（14 §12 漂移落点：async + Result + 第一人自动建房）：

1. `room = room_key_of(&code.0)`（wgp-dht 的房间键派生，07 §4）。
2. 取 `dht`/`storage`：任一未 attach → 广播 `RoomJoinFailed { reason: NoDhtAttached }` 并 `Err(RoomError::NotFound)`。
3. `RoomRuntime::new(node, storage)`；`rt.fetch(&code_str)` 三分支：
   - 已在成员表 → 直接用该记录；
   - 未在表 → `rt.request_join`（签名报道）→ 最多 10 轮 × 300ms 轮询 fetch → 仍未入表则 `RoomJoinFailed { ReportTimeout }` + `Err(NotFound)`；
   - `Err(RoomError::NotFound)` → 第一人：`rt.create(&code_str, engine_now_ms())`（房主 = 锚点）；
   - 其他 Err → `RoomJoinFailed { NotFound }` + 原错误上抛。
4. spawn upkeep：`upkeep_rt.upkeep(code, ROOM_UPKEEP_INTERVAL_MS, stop_rx, engine_now_ms)`（续期/监控/继位三合一，wgp-dht 侧实现）。
5. 广播 `RoomJoined { room, members: joined.members.len() }`；返回 `RoomHandle { room, stop: stop_tx, members }`。

**`run_node`（engine.rs:408-454）**：解析 `cfg.bind`（失败仅 `eprintln!` + None）；`DhtNode::bind(identity, addr)`；`cfg.hobby` → `n.set_relay_policy(wgp_dht::RelayPolicy::Deny)`（07 §7 PCDN 防护）；`cfg.tcp_signal` → `node.listen_tcp(SocketAddr::new(base.ip(), port))`（复用同一 DHT 节点的 dispatch/路由/KV，仅多一条接入通道）；`cfg.stun` → `ObserverServer::bind_with_policy(port, cfg.observer_policy)`。返回 `NodeHandle { dht, observer, tcp }`。三个面各自独立失败降级，互不阻塞。

#### 3.2.4 `LinkControl for Engine`（engine.rs:458-477，14 §6 的引擎侧实现）

```rust
fn release(&self, peer: PeerId);              // spawn：links 表摘除 + stop.send(true)（停保活+清注册）
fn request_upgrade(&self, _peer: PeerId) {}   // 空：升级链路在后续迭代接入
fn suspend_keepalive(&self, _peer: PeerId) {} // 空：NAT 学习否决权在后续迭代接入
fn resume_keepalive(&self, _peer: PeerId) {}  // 空
fn advertise_transports(&self, _supported: TransportCapabilitySet) {} // 空（D9 实验区挂线）
```

注意两个 `release` 并存：`Engine::release`（async，engine.rs:296）与 `LinkControl::release`（同步签名，内部 spawn，engine.rs:460）——后者为适配外围阻塞调用方（源码注释）。

#### 3.2.5 `RoomHandle::leave`（engine.rs:482-485）

```rust
pub fn leave(self) -> JoinHandle {   // 14 §12：cancel() → leave()
    let _ = self.stop.send(true);    // 停 upkeep（14 §10 条款 6 的 100ms 清理保证）
    JoinHandle { room: self.room }
}
```

#### 3.2.6 测试（4 个）

| 测试 | 验证点 |
|------|--------|
| `engine_yields_link_on_hit` | 端到端：双 UdpProbeCarrier（同 SHARED_KEY 模拟承诺-揭示后共享探针密钥）→ new_link → 事件序 `PunchingStarted → LinkYielded(Primary)` → sink 收到 `LinkTransport::Udp` |
| `engine_reports_lost_when_no_peer` | 无对端：三波发完（约 2.4s）→ `LinkLost { PeerGone }` + sink lost 回调 |
| `two_engines_join_same_room` | 多客户端联调：A 建房 → B 签名报道入表 → 双方成员表一致（fetch 内建验签）→ 锚点=房主 A → 双方均收 `RoomJoined` |
| `engine_delivers_tcp_link_when_udp_dead` | UDP 死路 → TCP 兜底命中 → `LinkYielded(Degraded)` + `LinkTransport::Tcp` 交付，且无 lost 回调（确定性构造：B 绑定 plan_waves 无数据模式 wave3 首端口） |

---

### 3.3 `src/engine/punch_runner.rs`

**一句话职责**：竞速执行器——三波计划 → 预算闸门（唯一发包点）→ 载体发包 → 监听验签 → 命中判定；"打洞成功"的最小闭环（15 Phase 5-6 执行核心）。

**重要限定**（文件头注释）：当前为"**发一批 → 短监听**"的**串行简化**；生产实现应改为发包/收包并发（150ms 时序压缩窗，03 §3.5.6），由引擎实现阶段切换。`Engine::new_link` 实际调用的是 race.rs 的 `race_punch`（已含边发边收），`PunchRunner` 是独立可测的执行器（二者功能重叠，PunchRunner 当前无生产调用点）。

```rust
#[derive(Debug, Clone)]
pub struct PunchOutcome {
    pub peer_addr: Option<SocketAddr>,   // 验证过的对端实际地址（HMAC 通过）
    pub hits: u32,                      // 命中的对端探针数
    pub packets_sent: u32,              // 实际发送的探针数（受预算裁剪）
    pub budget_left: u16,               // 剩余轮预算
}
impl PunchOutcome { pub fn is_hit(&self) -> bool { self.peer_addr.is_some() } }

pub struct PunchRunner<'a> {
    carrier: &'a UdpProbeCarrier,
    budget: &'a mut BudgetScheduler,
}
impl<'a> PunchRunner<'a> {
    pub fn new(carrier: &'a UdpProbeCarrier, budget: &'a mut BudgetScheduler) -> Self;
    pub async fn run_waves(&mut self, model: Option<&PortStepModel>, peer_ip: IpAddr, seed: u64) -> PunchOutcome;
}
```

`run_waves` 流程：`plan_waves(model, seed, budget.remaining().0)` → 三波串行；每波内逐端口 `budget.try_acquire(1)`（扣不出即 break）→ `carrier.craft()` → `send_probe`（发送失败不致命，预算已扣）；本波发出 ≥1 包后 `timeout(WAVE_TIMEOUT_MS, recv_verified 循环)`；命中判定 `src.ip() == peer_ip && Some(src) != self_addr`（自折返排除）；**命中即停**（14 §10 条款 1：先通先用）。

**测试（3 个）**：`wave_exec_hits_peer_reply`（对端 100ms 后回发验签探针 → hits==1、packets_sent ≤36）；`budget_cap_limits_packets`（预算仅剩 7 → packets_sent==7 且不命中）；`forged_probe_never_counts_as_hit`（错密钥伪造探针 → recv_verified 必拒，不得计命中）。

---

### 3.4 `src/engine/circuit.rs`

**一句话职责**：T1-T4 TCP 兜底触发判定（00 §4 触发条件表的可单测纯函数层；00 ADR D10）。

```rust
#[non_exhaustive]
pub enum TcpTrigger {
    UdpBlocked,             // T1：任一侧确认 UDP 出站不可用（预判层）
    UdpWavesFailed,         // T2：UDP 三波全灭（竞速兜底层，事后判定）
    QuicHandshakeTimeout,   // T3：UDP 打通但 QUIC 握手超时（疑 DPI 拦 QUIC）
    CarrierProfile,         // T4：运营商画像显示 UDP 高丢包 + 对端同意切换
}

#[derive(Debug, Clone, Copy)]
pub struct CircuitInput {
    pub udp_egress_ok: Option<bool>,        // 本端 UDP 出站可用性（None = 未测）
    pub peer_udp_ok: Option<bool>,          // 对端宣告（承诺-揭示阶段能力位）
    pub udp_waves_failed: bool,             // UDP 三波已全灭（竞速结果回填）
    pub quic_handshake_timed_out: bool,     // Phase 6 后半启用
    pub carrier_profile_bad: bool,          // D2 运营商画像：UDP 信道质量差
    pub peer_agrees_tcp: bool,              // 能力位协商：对端同意走 TCP
}
impl Default for CircuitInput { /* 全 None/false */ }

impl CircuitInput {
    /// 判定当前是否已命中任一 TCP 触发条件（优先级 T1 > T2 > T3 > T4）
    pub fn tcp_triggered(&self) -> Option<TcpTrigger> {
        if self.udp_egress_ok == Some(false) || self.peer_udp_ok == Some(false) { return Some(TcpTrigger::UdpBlocked); }
        if self.udp_waves_failed { return Some(TcpTrigger::UdpWavesFailed); }
        if self.quic_handshake_timed_out { return Some(TcpTrigger::QuicHandshakeTimeout); }
        if self.carrier_profile_bad && self.peer_agrees_tcp { return Some(TcpTrigger::CarrierProfile); }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaceConfig { pub udp_on: bool, pub tcp_on: bool }

pub fn decide_race(circuit: &CircuitInput, tcp_available: bool) -> RaceConfig {
    let udp_blocked = circuit.udp_egress_ok == Some(false) || circuit.peer_udp_ok == Some(false);
    RaceConfig {
        udp_on: !udp_blocked,
        tcp_on: tcp_available && (udp_blocked || circuit.carrier_profile_bad && circuit.peer_agrees_tcp),
    }
}
```

**语义要点**：

- `tcp_triggered` 是**纯查询**（不改变状态），供事件/诊断层读取当前命中的触发条件；`decide_race` 是**纯决策**，产出竞速路径开关。
- T1 判定覆盖两侧（本端 `udp_egress_ok` 或对端宣告 `peer_udp_ok` 任一为 `Some(false)`）。
- T4 需**双条件**（画像差 + 对端同意），单条件不触发（测试 `t2_then_t3_then_t4_order` 断言）。
- 文件头注释：竞速模型下 **T2/T3 天然由并行兜底覆盖**（TCP 同步在跑），本模块只负责"预判类"决策——T1 命中 → 跳过 UDP 路径（`decide_race` 的 `udp_on=false` → `PunchInput.udp_enabled=false` → `race_punch` 纯 TCP）；T3 在 QUIC 接入阶段启用。

**测试（5 个，全为同步 `#[test]`）**：`t1_udp_blocked_wins_priority`（T1 与 T2 同时置位 → 返回 T1）；`t1_via_peer_declaration`（仅对端宣告 UDP 不可用 → T1）；`t2_then_t3_then_t4_order`（T2→T3→T4 顺序断言 + T4 双条件）；`race_config_skips_udp_on_t1`（T1 → `!udp_on && tcp_on`）；`race_config_full_race_when_no_trigger`（默认输入 → `udp_on=true, tcp_on=false`，TCP 由竞速层自带）。

---

### 3.5 `src/engine/keepalive.rs`

**一句话职责**：NAT 保活哨兵——内核唯一负责保活（14 §10 条款 4），外围零心跳。

```rust
pub async fn keepalive_loop(
    carrier: Arc<UdpProbeCarrier>,
    peer_addr: SocketAddr,
    budget: Arc<Mutex<BudgetScheduler>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut hb = HeartbeatLoop::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        let now = now_ms();
        match hb.tick(now, true) {
            Some(HbAction::Send { seq: _, with_ext: _ }) | Some(HbAction::FastSend { seq: _ }) => {
                if budget.lock().await.try_acquire(1).is_ok() {   // 保活包同受全局调度（H6 不破）
                    let probe = carrier.craft();
                    let _ = carrier.send_probe(peer_addr, &probe).await;
                }
            }
            None => {}
        }
    }
}
```

**设计要点**：

- 节奏决策复用 wgp-punch 的 `HeartbeatLoop`（滑窗自适应/恢复三连发/步长扩展节拍）；发送侧复用 **31B 验签探针**（探针即等价 NAT 保活流量，避免双包型）。
- 每发 1 包同样过全局预算闸门（失败仅本轮跳过）。
- 100ms 步进轮询为低功耗简化（源码注释：生产改为按 `next_interval` 精确 sleep）。
- 停止机制：`watch` 通道，`Engine::release`/`LinkControl::release` 拉闸（14 §10 条款 4 的代码落点）。
- `now_ms` 来自 `crate::transport::probe`（独立 OnceLock 锚点，见 §3.2.1）。

**测试**：无。

---

### 3.6 `src/engine/nat_probe.rs`

**一句话职责**：观察者探测与 NAT 判定（15 Phase 0②/④ 的客户端侧）——STUN binding 取公网端点、双观察者交叉粗判 NAT、同观察者三连测学步长。

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverReport {
    pub ipv4: [u8; 4],                    // 观察者报告的"我的公网端点"
    pub port: u16,
    pub echoed_nonce: Option<[u8; 8]>,    // 观察者回显的 nonce（防错勘/测量往返）
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClass {
    ConeLike,        // 两报告一致：锥形类（NAT1/2/3，或直连公网）
    SymmetricLike,   // 端口不同：疑似对称（NAT4）
    MultiEgress,     // IP 出口不同：多出口/多层环境
}

pub struct NatProbe { socket: Arc<UdpSocket> }

impl NatProbe {
    pub async fn bind() -> std::io::Result<Self>;                          // 0.0.0.0:0
    pub fn from_socket(socket: Arc<UdpSocket>) -> Self;                    // 复用打洞 socket（03 §3.4）
    pub fn socket(&self) -> Arc<UdpSocket>;

    pub async fn probe_observer(
        &self, observer: SocketAddr, tx_id: [u8; 12], echo: Option<&WgpPeerAttr>,
    ) -> Option<ObserverReport>;

    pub async fn learn_step(&self, observer: SocketAddr, now_fn: impl Fn() -> [u8; 8]) -> Option<PortStepModel>;
}

pub fn classify_reports(a: &ObserverReport, b: &ObserverReport) -> NatClass;
```

**`probe_observer` 细节**：`binding_request(&tx_id, echo)`（wgp-proto STUN 子集）→ 1500ms 超时等响应 → `StunHeader::decode` + tx_id 校验（非本请求响应视为乱包）→ `decode_attrs` → 解析 `ATTR_XOR_MAPPED_ADDRESS`（`decode_xor_mapped`）与 `WGP_PEER` 扩展（取 nonce）→ 无 mapped 返回 None。`echo = None` 即纯公共 STUN 档。

**`from_socket` 的意义**（03 §3.4 核心纪律）：**学习与打洞同源端口**——NAT 映射规律才适用于打洞本身。orchestrator 即先 bind UdpProbeCarrier、再 `NatProbe::from_socket(carrier.socket())`。

**`learn_step`**：同观察者三连测（tx_id[0]=i；`WgpPeerAttr { peer_prefix: [0x77;4], nonce[0]=i, timestamp: now_fn(), flags: [0;4] }`）→ 3 个端口样本 → `PortStepModel::learn(&samples)`（样本不足返回 None）。

**`classify_reports`**：IP 不同 → MultiEgress；端口相同 → ConeLike；否则 SymmetricLike。

**测试（4 个）**：`cone_like_on_loopback_dual_observers`（loopback 无 NAT，双观察者端口一致 → ConeLike）；`echo_roundtrip_nonce_match`（WGP-PEER nonce 回显一致）；`step_learning_three_probes`（loopback 步长恒 0 → confidence > 0.9、mean_delta == 0.0）；`dead_observer_times_out`（127.0.0.1:1 → None）。

---

### 3.7 `src/engine/race.rs`

**一句话职责**：竞速执行器（00 ADR D4/D10）——UDP 三波 ∥ TCP 多端口并行，先通先用；预算闸门共享，两路径原子扣减。

```rust
pub enum RaceOutcome {
    Udp   { peer_addr: SocketAddr, packets_sent: u32 },
    Tcp   { stream: TcpStream, packets_sent: u32 },
    Failed{ packets_sent: u32 },
}

pub async fn race_punch(
    udp: &UdpProbeCarrier,
    tcp: Option<&TcpProbeCarrier>,
    model: Option<&PortStepModel>,
    peer_ip: IpAddr,
    seed: u64,
    budget: Arc<Mutex<BudgetScheduler>>,
    udp_on: bool,
) -> RaceOutcome;
```

**`run_udp_waves`（私有，race.rs:33-96）——UDP 三波边发边收**：

- 滚动 3 轮（`round in 0..3`），每轮**重播种** `seed.wrapping_add(round)` 重采样（覆盖两端开火残差；真实 T_offset 对齐后单轮即中）。
- 每轮持预算锁 `plan_waves(model, seed', guard.remaining().0)`。
- 波内逐端口：① 发一包前 `timeout(Duration::ZERO, carrier.recv_verified())` **非阻塞查收**（150ms 窗口内对端回包即时命中，不等波后——03 §3.5.6/§3.3.5 边发边收简化形态）；② `budget.try_acquire(1)` → `craft()` → `send_probe`。
- 波尾收紧窗：`timeout(WAVE_TIMEOUT_MS, recv_verified 循环)` 吸收迟到回包。
- 命中判定 `src.ip() == peer_ip && Some(*src) != self_addr`（自折返排除）。

**`run_tcp_waves`（私有，race.rs:100-153）——TCP 多端口并行**：

- 单次 `plan_waves`（无滚动轮）；每波**所有端口同时尝试**：预算门控后 spawn `carrier.punch_port(peer)`，流经 `mpsc::unbounded_channel` 汇合；`timeout(window, hit_rx.recv())` 等本波首个成功 → abort 全部 handles 返回；超时进下一波。

**`race_punch` 主循环（race.rs:166-212）**：

- `udp_fut`/`tcp_fut` 均 `tokio::pin!`；`udp_done = !udp_on`（T1 命中时 UDP 侧立即视为完成且无命中）。
- `tokio::select!` 循环带完成标志：一方先失败仅置 done 标志，**不影响另一路**；任一方命中立即返回对应 `RaceOutcome`（先通先用，14 §10 条款 1）；双方都无命中 → `Failed { packets_sent }`（两路发包数累计）。

**测试**：无（竞速行为由 engine.rs 与 orchestrator.rs 的集成测试覆盖）。

---

### 3.8 `src/orchestrator.rs`

**一句话职责**：装配线（SessionOrchestrator）——把内核零件组装成全自动打洞流水线（15 Phase 3→5 的自动编排，两端对等对称运行）。

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorError {
    PeerGone,      // 对端无响应（重传耗尽）
    Mitm,          // 承诺不匹配（信令 MITM 嫌疑，24h 黑名单由上层处理）
    AlgoMismatch,  // 算法不支持
    ObserverDead,  // 观察者全灭（无法获得端点报告）
    NoRoute,       // 无可用路径（UDP 双亡且无 TCP 同意）
}

pub struct SessionOrchestrator {
    node: Arc<DhtNode>,
    engine: Engine,
    storage: SocketAddr,
    storage_tcp: Option<SocketAddr>,   // 种子的 TCP 信令兜底地址（None = 无 TCP 通道）
    observers: Vec<SocketAddr>,
}

impl SessionOrchestrator {
    pub fn new(node: Arc<DhtNode>, engine: Engine, storage: SocketAddr, observers: Vec<SocketAddr>) -> Self;
    pub fn with_tcp_fallback(mut self, storage_tcp: Option<SocketAddr>) -> Self;
    pub async fn connect_peer(&self, room_code: &str, peer_node_id: NodeId, sink: Arc<dyn LinkSink>)
        -> Result<(), OrchestratorError>;
    async fn exchange(&self, peer: &NodeId, tag: u32, rx: &mut mpsc::UnboundedReceiver<ForwardBody>,
        expect_kind: u8, body: &[u8], mut accept: impl FnMut(&[u8]) -> bool) -> bool;
    async fn send_forward(&self, peer: NodeId, payload: &[u8]);
}
```

#### 3.8.1 帧与派生函数（模块私有）

```rust
mod frame {
    pub const KIND_SIG: u8 = 0x01;      // SigPacket 字节（COMMIT/REVEAL）
    pub const KIND_EP: u8  = 0x02;      // 端点报告（含完整承诺复验）
    pub const EP_BODY_LEN: usize = 47;  // 纯 body 长度

    pub struct Endpoints {              // 47B = 15B 端点 + 32B 完整承诺
        pub ipv4: [u8; 4], pub port: u16,
        pub udp_ok: bool, pub tcp_ok: bool, pub has_model: bool,
        pub last_port: u16,
        pub mean_delta_q: i16,          // 步长（×64 定点，防浮点传输）
        pub confidence: u8,             // 置信度 0-100
        pub full_commit: [u8; 32],      // 完整 32B 承诺（MITM 复验，128bit）
    }
    pub fn encode_endpoints(e: &Endpoints) -> [u8; EP_BODY_LEN];
    pub fn decode_endpoints(buf: &[u8]) -> Option<Endpoints>;
}

fn session_tag(room: &str, a: NodeId, b: NodeId) -> u32;  // Sha256(room||lo.0||hi.0) 前4B BE | 1（按 NodeId 排序免疫方向性）
fn punch_seed(room: &str, a: NodeId, b: NodeId) -> u64;   // Sha256("wgp-seed"||room||lo||hi) 前8B
fn info_ctx(room: &str, a: NodeId, b: NodeId) -> Vec<u8>; // "wgp-session"||room||lo||hi（01 §1.2.3）
```

`encode_endpoints` 布局：`0..4` ipv4、`4..6` port(BE)、`6` udp_ok、`7` tcp_ok、`8` has_model、`9..11` last_port(BE)、`11..13` mean_delta_q(BE)、`13` confidence、`14` 保留、`15..47` full_commit（32B）。注意 `out[14..46].fill(0)` 与 `out[15..47].copy_from_slice(&full_commit)` 有 1 字节重叠写（14..15），功能上等价于"14 保留、15..47 承诺"（代码如此，无实际影响）。

#### 3.8.2 `connect_peer` 七阶段执行流（15 Phase 3→5 编排）

| 阶段 | 代码要点 |
|------|---------|
| 准备 | `tag = session_tag(...)`；`node.register_session(tag)` → `rx: mpsc::UnboundedReceiver<ForwardBody>`；`session_start = Instant::now()`；`const FIRE_AT_MS: u64 = 3000`（双方约定开火时刻，自会话起点起；注释：真实部署由 T_offset 对齐代替） |
| ① 承诺-揭示 | `X25519Agreement` keygen；`nonce = [0u8;32]` OsRng 填；`my_commit = make_commit(&pubkey, &nonce)`；COMMIT 帧只带前 16B（`commit16`，协议定长限制）；REVEAL 帧带完整 pubkey+nonce。**①a accept 放宽到 `Commit \| Reveal`**（对端可能因加入时序已先行完成本阶段，直接放行避免阶段漂移死锁；MITM 防护由 EP 交换的 full_commit 复验兜底——14 §12 漂移表登记项）。①b 捕获 `peer_pk_raw`/`peer_nonce`；`ka.agree` 失败 → `Mitm` |
| ② 密钥族派生 + 打洞 socket | `secrets = derive_all(&shared, &info_ctx(room, my, peer))`（session_key/probe_key 等）；`UdpProbeCarrier::bind("0.0.0.0:0", secrets.probe_key, tag.to_be_bytes())`——**学习与打洞同源端口**（03 §3.4） |
| ③ 观察者探测 + 步长学习 | `NatProbe::from_socket(carrier.socket())`；遍历 `self.observers` `probe_observer`（tx_id 前 4B = my_peer_id 前 4B），首个成功即止（`udp_ok = my_mapped.is_some()`）；`first_ok` → `learn_step(obs, \|\| [0u8; 8])`（时间戳恒零——代码如此，真实部署应传网络时间换算） |
| ④ 交换端点 | 组 47B `Endpoints`（mean_delta_q = `(d*64).round().clamp(-32768,32767) as i16`；confidence = `(conf*100) as u8`；**full_commit = my_commit.0 完整 32B**）→ exchange KIND_EP → 对端 `peer_ep`；`verify_commit(&Commitment(peer_ep.full_commit), &peer_pk_raw, &peer_nonce)` 失败 → `Mitm`（128bit 抗 MITM，01 §1.2） |
| ⑤ 判定 + 组装 | `CircuitInput { udp_egress_ok: Some(udp_ok), peer_udp_ok: Some(peer_ep.udp_ok), carrier_profile_bad: false, peer_agrees_tcp: peer_ep.tcp_ok, .. }` → `decide_race(&circuit, true)`；`!udp_on && !tcp_on` → `NoRoute`；**peer_model 用对端模型**（对端测的是它自己 NAT 的映射规律，由 EP 报告给我方；重建时 `trend` 恒 `Oscillating`、`delta_range (0,0)`）；`race_cfg.tcp_on` 时保留一个 TCP 源端口（`TcpListener::bind("127.0.0.1:0")` 占位 → drop → `0.0.0.0:port` 重绑 → `TcpProbeCarrier::new`）；组装 `PunchInput { peer: peer_id_from_node(&peer_node_id), peer_ip: V4(peer_ep.ipv4), carrier, tcp, udp_enabled: race_cfg.udp_on, session_key: SecretBox::new(secrets.session_key), model: peer_model, seed: punch_seed(...) }` |
| ⑥ 同步开火 | `elapsed < FIRE_AT_MS` → sleep 补齐（双向偏差压缩到会话建立噪声级）→ `engine.new_link(input, sink)` |
| ⑦ 清理 | `node.unregister_session(tag)`；`Ok(())` |

#### 3.8.3 `exchange` 与 `send_forward`

- `exchange`：payload = `tag(4B BE) + kind(1B) + body`；**14 轮循环**（`send_forward` + 300ms 超时 `rx.recv()`，总重传窗 ≈4.2s）；收到的 `ForwardBody` 剥前 4B 分派 tag 后交 `accept` 闭包判定。
- `send_forward`：`node.forward_to(self.storage, peer, payload)` 为主；配置了 `storage_tcp` 时同发一份 `node.forward_tcp(...)`（07 §5：UDP 打不通时的信令降级通道；两条通道语义一致、上层 accept 幂等、重投无副作用）。
- `_split_frame`（`#[allow(unused)]`，orchestrator.rs:480）：遗留辅助函数，未被调用。

#### 3.8.4 测试（2 个）

| 测试 | 验证点 |
|------|--------|
| `two_clients_auto_punch_full_pipeline` | 端到端：种子（DHT+观察者）+ 双客户端全自动装配——A 建房 → B 入表 → 双方对等 `connect_peer` → 双边 `PunchedLink` 交付（8s 内）→ loopback 双栈全通 → rank 全 `Primary` |
| `tcp_fallback_signaling_route` | UDP 种子地址指向黑洞端口时，经 `with_tcp_fallback` 的 TCP 种子仍能把信令送达对端（`b.recv_forward()` 收到载荷） |

---

### 3.9 `src/rank.rs`

**一句话职责**：链路档位（00 §4 链路优先级：LAN > QUIC > TCP > ICMP）；独立成模块使 node 裁剪面的事件系统也能引用（不依赖 link/crypto）。

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkRank {
    Primary,   // 主档：UDP（跑 QUIC）/ LAN 直连
    Degraded,  // 降级档：TCP + TLS-PSK
    Escape,    // 逃生档：ICMP（仅信令级流量）
}
```

当前代码中 `Primary`/`Degraded` 有产出点（engine.rs 的 new_link 两分支）；**`Escape` 无产出点**（ICMP 逃生载体未接入 Engine 流程，见第 6 章）。**测试**：无。

---

### 3.10 `src/event.rs`

**一句话职责**：事件流（14 §5：tokio broadcast，多外围订阅互不阻塞）。

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EngineEvent {
    PunchingStarted { peer: PeerId },
    LinkYielded { peer: PeerId, rank: LinkRank },
    LinkUpgraded { peer: PeerId, from: LinkRank, to: LinkRank },
    LinkLost { peer: PeerId, cause: LinkLossCause },
    RePunching { peer: PeerId, reason: RePunchReason },
    DeadEnd { peer: PeerId, diagnosis: DeadEndReport },        // 04 D5 评分，附诊断报告
    RoomAnchorChanged { epoch: u64, anchor: PeerId, reason: AnchorChangeReason },
    RoomJoined { room: [u8; 32], members: usize },
    RoomJoinFailed { room: [u8; 32], reason: RoomJoinFailReason },
    BudgetExhausted { room_id: [u8; 32] },                     // 外围须停止催促重连
    KeepaliveSuspended { peer: PeerId },                      // 内核学习到长超时自动降频
}

pub enum LinkLossCause { NatExpired, NetworkChanged, PeerGone, BudgetExhausted, ReleasedByPeer }
pub enum RePunchReason { UdpRecovered, NatRebound, UpgradeRequested }
pub enum AnchorChangeReason { OwnerLeft, AnchorTimeout, OwnerReturned }
pub enum RoomJoinFailReason { NoDhtAttached, NotFound, ReportTimeout }

pub struct DeadEndReport {          // 04 §4.6.4 诊断日志的代码形态
    pub score: u8,                  // 04 D5 评分（≥70 判死局；65-75 为"极难"警告）
    pub nat_type: &'static str,
    pub firewalled: bool,
    pub udp_blocked: bool,
    pub cgnat: bool,
}
```

**当前发送点**：`PunchingStarted`/`LinkYielded`/`LinkLost`（engine.rs new_link 三分支）、`RoomJoined`/`RoomJoinFailed`（join_room）。**未发送的变体**：`LinkUpgraded`、`RePunching`、`DeadEnd`、`RoomAnchorChanged`、`BudgetExhausted`、`KeepaliveSuspended`（升级/重打洞/死局判定/锚点变更广播/预算事件/降频通知均未接线，见第 6 章）。

**测试**：无。

---

### 3.11 `src/types.rs`

**一句话职责**：LinkSink / RoomApi / LinkControl / 意图类型（14 §3/§6/§7）——三原则：内核被动交付；所有权一次转移；保活唯一权在内核。

```rust
pub struct RoomCode(pub String);                 // "U/XXXX-XXXX-XXXX-XXXX"（13 文档）
pub struct RoomKey(pub Vec<u8>);                 // 房间密钥（不参与会话密钥派生，13 §6）
pub type RoomId = [u8; 32];                      // DHT 键（07 §4 派生）

/// 链路生命周期时序：yield(至多一次) → [upgraded × N] → lost → [重打洞成功 → yield] → …
pub trait LinkSink: Send + Sync {
    fn on_link_yielded(&self, peer: PeerId, link: PunchedLink);
    fn on_link_upgraded(&self, peer: PeerId, link: PunchedLink);   // 旧链路按 00 §4 宽限 30s 供外围切换
    fn on_link_lost(&self, peer: PeerId, cause: crate::event::LinkLossCause);
}

pub trait LinkControl: Send + Sync {             // 外围 → 内核控制回向（14 §6）
    fn release(&self, peer: PeerId);             // 主动断开 → 停保活 + 清密钥
    fn request_upgrade(&self, peer: PeerId);     // 不等 30s 周期的即时升级探测
    fn suspend_keepalive(&self, peer: PeerId);   // 可能被内核否决（超 NAT 学习值）
    fn resume_keepalive(&self, peer: PeerId);
    fn advertise_transports(&self, supported: TransportCapabilitySet);  // D9 实验区挂线
}

pub struct TransportCapabilitySet(pub Vec<TransportCapability>);   // wgp_punch::TransportCapability

pub struct LinkIntent { pub peer: PeerId, pub transport_hint: Option<TransportCapability> }  // 14 §9 原 new_link 入参

pub struct JoinHandle { pub room: RoomId };      // 可取消句柄；取消后 100ms 内核完成清理

pub enum RoomRole { Owner, Anchor, Member }      // 07 §1：房主/锚点分离

pub struct MemberInfo { pub peer_id: PeerId, pub role: RoomRole, pub link_rank: Option<LinkRank> }

pub trait RoomApi: Send + Sync {                 // 14 §7，D7 mesh
    fn join(&self, code: &RoomCode, auth: Option<RoomKey>) -> JoinHandle;
    fn leave(&self, room: RoomId);
    fn members(&self, room: RoomId) -> Vec<MemberInfo>;
    fn kick(&self, peer: PeerId);                // 房主专有；锚点转手不改变房主权限语义
}
```

**漂移与现状**：

- `LinkIntent` 按 14 §12 已被 `PunchInput` 取代，**当前无任何生产消费者**（仅类型保留）。
- `RoomApi` trait **无实现者**（Engine 只实现了 `LinkControl`；房间操作走 `Engine::join_room` 具体方法而非该 trait）。
- `JoinHandle` 只持有 `room: RoomId` 一个字段，**无 cancel 方法**（14 §7"取消后 100ms 清理"的取消动作无 API 入口；`RoomHandle::leave` 返回它仅作占位）。

**测试**：无。

---

### 3.12 `src/link.rs`

**一句话职责**：链路交付物（14 §2）——PunchedLink 及承载类型；所有权随结构移交外围。

```rust
#[derive(Debug, Clone, Copy)]
pub struct LinkQuality {
    pub rtt: Duration,
    pub loss: f32,
    pub measured_mtu: u16,
    pub obeys_budget: bool,
}

/// 承载载体（14 §2）——所有权随 PunchedLink 一并移交外围
pub enum LinkTransport {
    Udp { socket: Arc<UdpSocket> },   // 打洞验证的 UDP socket（外围跑 QUIC；Arc 共享：载体保活与 QUIC 同 socket）
    Tcp { stream: TcpStream },        // simultaneous-open 成功的 TCP 流（外围跑 TLS-PSK + 帧流）
    Icmp { chan: IcmpChan },          // ICMP 逃生通道句柄（平台实现待接；仅信令级）
    Lan { socket: Arc<UdpSocket> },   // LAN 组播发现直连
}

pub struct IcmpChan { pub identifier: u16 }     // 骨架（实现阶段接平台原生 API）

pub struct PunchedLink {
    pub peer_id: PeerId,
    pub transport: LinkTransport,
    pub session_key: wgp_crypto::SecretBox,     // 所有权随结构转移
    pub quality: LinkQuality,
    pub rank: LinkRank,
}
```

**与 14 §2 的漂移**（代码为最终权威）：

| 14 §2 文档初版 | 代码定版 |
|---------------|---------|
| `PunchedLink.peer_addr: SocketAddr` | **无该字段**（对端地址内化于 transport/竞速结果） |
| `LinkTransport::Udp { socket: UdpSocket }` | `socket: Arc<UdpSocket>`（保活哨兵与 QUIC 共享同一 socket） |
| `LinkTransport::Lan { socket, addr }` | 无 `addr` 字段 |
| `session_key: SecretBox<[u8;32]>` | `wgp_crypto::SecretBox`（泛型参数默认由 wgp-crypto 定） |

当前产出点仅 `Udp`/`Tcp` 两个变体（engine.rs new_link）；`Icmp`/`Lan` 无产出点。quality 为**硬编码占位**（rtt 0ms、loss 0.0、mtu 1400、obeys_budget true）。

**测试**：无。

---

### 3.13 `src/exporter.rs`

**一句话职责**：KeyExporter（14 §4）——TLS-PSK 一次取出 + PQ 可选 API 落点。

```rust
pub struct PskBundle {
    pub identity: Vec<u8>,        // room 扰动 + Peer 对序 + epoch，两端推导一致（0-RTT 查表键）
    pub key: SecretBox,           // 32B TLS-PSK 密钥（一次性取出）
    pub max_early_data: u32,      // 0-RTT early-data 上限
}

pub trait KeyExporter: Send + Sync {
    /// 一次性取出 PSK；再次调用返回 None（14 §10 条款 3）
    fn take_tls_psk(&self, peer: PeerId) -> Option<PskBundle>;
    /// 当前密码学档位（D6；PQ 开启后返回 HybridPqMlKem768）
    fn crypto_profile(&self) -> CryptoProfile;
}
```

**漂移**：14 §4 文档 `PskBundle.key: SecretVec<u8>`，代码为 `SecretBox`（wgp-crypto 的一次性容器类型）。**该 trait 当前无实现者**（ trait 定义即 API 落点；PSK 实际经 `PunchedLink.session_key` 交付，QUIC/TLS-PSK 注入属客户端任务）。

**测试**：无。

---

### 3.14 `src/servers.rs`

**一句话职责**：服务器选择器（07 §5 种子发现第 1 层 + 就近低延迟选路）——多端点并发探测、按 RTT 排序；全灭返回 None。

```rust
#[derive(Debug, Clone)]
pub struct SeedPick {
    pub endpoint: SeedEndpoint,   // wgp_proto 的端点描述（scheme + host + port）
    pub addr: SocketAddr,         // 解析地址
    pub rtt: Duration,            // 实测 RTT
}

pub async fn resolve_endpoint(ep: &SeedEndpoint) -> Option<SocketAddr>;   // host_ascii + lookup_host，优先 IPv4

async fn probe_endpoint(node: &Arc<DhtNode>, ep: &SeedEndpoint, addr: SocketAddr) -> Option<Duration>;  // 私有
// Udp → node.ping(addr)；Tcp → node.ping_tcp(addr)

pub async fn measure_seeds(node: &Arc<DhtNode>, endpoints: &[SeedEndpoint]) -> Vec<SeedPick>;  // 并发 spawn，rtt 升序
pub async fn pick_fastest_seed(node: &Arc<DhtNode>, endpoints: &[SeedEndpoint]) -> Option<SeedPick>;
```

**要点**：

- 注释明示：**内置种子列表已移至外围配置层**——内核只保留"给定端点列表 → 测速/选路"机制，不持有任何部署地址（00 §5：内核零内置部署地址）。
- `resolve_endpoint` 优先 IPv4（当前打洞面 v4 聚焦；未来 IPv6 时扩展——注释）；host 先经 `host_ascii()` IDN punycode 归一化；scheme 不影响解析（udp/tcp 共用主机名），仅决定探测走哪条 RPC。
- 每端点超时 1.5s（与 DHT RPC 超时一致）。

**测试（4 个）**：`measure_picks_live_and_skips_dead`（死端点剔除、仅剩活端点、rtt < 1500ms）；`all_dead_returns_empty`（全灭 → 空 + pick_fastest_seed None）；`resolve_domain_and_ipv4`（IP 形式解析路径）；`measure_picks_tcp_seed`（TCP 种子经 ping_tcp 也能被选中）。

---

### 3.15 `src/transport/mod.rs`

**一句话职责**：载体实现集合门面（00 §4 四档链路：UDP / TCP / ICMP / LAN）；内核只通过这些载体建立链路，数据面协议由外围决定。

```rust
pub mod escape;
pub mod lan;
pub mod probe;
pub mod tcp;
pub mod udp;

pub use escape::IcEscape;
pub use lan::LanProbeCarrier;
pub use tcp::TcpProbeCarrier;
pub use udp::UdpProbeCarrier;
```

注意：`probe` 模块（craft_probe/verify_probe/now_ms）**未**在 mod.rs re-export，需经 `wgp_core::transport::probe::*` 访问；`IcEscape` 亦未在 lib.rs 顶层 re-export（`wgp_core::transport::IcEscape` 可达）。

**测试**：无。

---

### 3.16 `src/transport/probe.rs`

**一句话职责**：探针组帧/验签共用逻辑（UDP/TCP 双载体复用）——31B 定长帧（packet::probe），UDP 上按包、TCP 上按流首帧。

```rust
/// 进程级单调毫秒锚点（禁止读系统时钟，03 §3.3.2 硬约束）。
/// 绝对网络时间由引擎侧 net_time_anchor 二次换算。
pub fn now_ms() -> u64;

pub fn craft_probe(probe_key: &[u8; 32], session_tag: [u8; 4], nonce: u32, timestamp_ms: u64) -> [u8; probe::LEN];
// Probe { session_tag, nonce: BE, timestamp: BE, auth_tag: [0;12] } → probe::encode → probe_auth(前 AUTH_OFFSET 字节) → 回填 12B

pub fn verify_probe(probe_key: &[u8; 32], buf: &[u8]) -> Option<Probe>;
// probe::decode（长度/魔数/类型）→ 重算 probe_auth 比对 auth_tag → 伪造/错密钥静默拒绝
```

**帧结构**（31B = 19B 签名域 + 12B HMAC，`probe::AUTH_OFFSET` 之前部分签名；03 §3.5.5）。

**测试**：无（由 udp/tcp 载体测试间接覆盖）。

---

### 3.17 `src/transport/udp.rs`

**一句话职责**：UDP 探针载体（主档）——31B HMAC 探针；保活与三波共用同一 socket；打洞成功后该 socket 移交 QUIC 作链路载体。

```rust
pub struct UdpProbeCarrier {
    socket: Arc<UdpSocket>,
    probe_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: AtomicU32,
    timestamp_fn: Arc<dyn Fn() -> u64 + Send + Sync>,   // 时间源可替换（引擎注入网络时间锚点换算）
}

impl UdpProbeCarrier {
    pub async fn bind(local: SocketAddr, probe_key: [u8; 32], session_tag: [u8; 4]) -> std::io::Result<Self>;
    pub fn local_addr(&self) -> std::io::Result<SocketAddr>;
    pub fn socket(&self) -> Arc<UdpSocket>;                                  // 打洞成功后取出底层 socket
    pub fn set_timestamp_fn(&mut self, f: impl Fn() -> u64 + Send + Sync + 'static);
    pub fn craft(&self) -> [u8; probe::LEN];                                 // nonce 原子自增（fetch_add+1）
    pub async fn recv_verified(&self) -> Option<(Probe, SocketAddr)>;        // 长度校验 + HMAC；失败静默丢弃
}

impl ProbeCarrier for UdpProbeCarrier {   // wgp_punch::ProbeCarrier（D9）
    async fn send_probe(&self, dst: SocketAddr, payload: &[u8]) -> Result<(), CarrierError>;  // 31B 定长校验
    fn on_probe(&self, _src: SocketAddr, payload: &[u8]) -> bool;
    fn mapping_semantics(&self) -> MappingSemantics;   // PortTagged { port: 本地端口 }
    fn capability(&self) -> TransportCapability;       // TransportCapability::Udp
}
```

**测试（2 个）**：`hmac_verify_and_tamper_rejection`（同 key 验过 / 篡改一字节拒 / 错密钥拒）；`send_recv_roundtrip_across_two_carriers`（A→B 直发，B `recv_verified` 收到且 session_tag/src 正确）。

---

### 3.18 `src/transport/tcp.rs`

**一句话职责**：TCP 探针载体——simultaneous open 打洞（T1-T4 兜底路径）；固定源端口 + SYN 交叉 + 首帧 31B 验签探针互验。

```rust
pub const TCP_PORT_PUNCH_TIMEOUT_MS: u64 = 250;   // 单端口尝试超时（SYN 交叉窗口；retry 后总时长 < 800ms 波窗口）
const PUNCH_RETRIES: u32 = 2;                     // 单端口重试次数（抗 SYN 错位；03 §3.5.6 重试语义）
const PUNCH_RETRY_GAP_MS: u64 = 80;

#[derive(Clone)]
pub struct TcpProbeCarrier { inner: Arc<TcpInner> }   // Arc 内聚：多端口并行 spawn 可 Clone

struct TcpInner {
    bind_addr: SocketAddr,       // 本地固定绑定地址（打洞源端口）
    probe_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: AtomicU32,
}

impl TcpProbeCarrier {
    pub fn new(bind_addr: SocketAddr, probe_key: [u8; 32], session_tag: [u8; 4]) -> Self;
    pub fn bind_addr(&self) -> SocketAddr;
    pub async fn punch_port(&self, peer: SocketAddr) -> Option<TcpStream>;   // 内置重试；成功返回已验证流
}

async fn try_punch_once(&self, peer: SocketAddr) -> Option<TcpStream> {   // 私有
    // ① TcpSocket::new_v4 + bind(bind_addr) + timeout(250ms) connect
    // ② set_nodelay(true)（02 §2.2：立即禁用 Nagle）
    // ③ write_all(31B 探针首帧) → timeout(250ms) read_exact(31B) → verify_probe
}
```

**语义要点**（文件头）：TCP 打洞要求双方源端口可预测（本地绑定固定源端口）；连接建立后**首帧互发 31B 验签探针**（复用 UDP 帧格式，流上定长读取）——连接建立 ≠ 打通，探针 HMAC 过才算（15 Phase 6 验证语义）。

**测试（2 个）**：`simultaneous_open_both_sides_verified`（双方同时打开，loopback 下等价真实 NAT simultaneous open，双向探针互验通过）；`mismatched_keys_reject_each_other`（错密钥 = 未完成承诺-揭示的"陌生人"：连接可能建立但探针必须互拒）。

---

### 3.19 `src/transport/lan.rs`

**一句话职责**：LAN 组播发现载体（00 §4 第一档：同网段直连，跳过 STUN/打洞）。

```rust
pub mod beacon {
    pub const LEN: usize = 22;
    pub const MAGIC: [u8; 2] = *b"LN";
    pub fn craft(key: &[u8; 32], session_tag: [u8; 4], nonce: u32) -> [u8; LEN];
    pub fn decode(key: &[u8; 32], buf: &[u8]) -> Option<([u8; 4], u32)>;   // 伪造/错键 → None
}

/// 默认组频道（站点本地：239.255.0.0/16 的保留使用段）
pub const DEFAULT_GROUP: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 42, 42), 3842);

pub struct LanProbeCarrier {
    socket: Arc<UdpSocket>,
    group: SocketAddrV4,
    lan_key: [u8; 32],
    session_tag: [u8; 4],
    nonce_seed: AtomicU32,
}

impl LanProbeCarrier {
    pub fn bind(group: SocketAddrV4, lan_key: [u8; 32], session_tag: [u8; 4]) -> std::io::Result<Self>;
    pub fn group(&self) -> SocketAddrV4;
    pub fn socket(&self) -> Arc<UdpSocket>;
    pub async fn send_beacon(&self) -> std::io::Result<usize>;
    pub async fn recv_beacon(&self) -> Option<(SocketAddr, [u8; 4], u32)>;  // 返回对端单播地址（组播包 src）
}
```

**帧格式**（22B）：`magic(2 "LN") | session_tag(4) | nonce(4) | auth(12)`，`auth = HMAC(lan_key, 前 10B)`（`wgp_crypto::derive::lan_auth`）——LAN 内仍验签：防蹭网者伪造发现。

**绑定细节**：socket2 建 socket → `set_reuse_address(true)`（Windows 同端口多实例；同一台机器多客户端共存）→ bind `0.0.0.0:group.port()` → `join_multicast_v4(group.ip(), UNSPECIFIED)` → nonblocking → `UdpSocket::from_std`。

**发现语义**：组播包 src 即对端单播地址 → 收到验签 beacon 即直接交付 Lan 链路。**平台注意**（文件头）：组播真实收发依赖网卡路径，loopback 行为不稳定 → 网络收发不在单测内（部署清单列为真机验证项）。

**测试（3 个，全同步）**：`beacon_roundtrip`（craft/decode 一致）；`beacon_tamper_and_wrong_key_rejected`（篡改 + 错键拒）；`beacon_bad_magic_rejected`（魔数错误拒）。

---

### 3.20 `src/transport/escape.rs`

**一句话职责**：ICMP 逃生载体（00 §4 第四档：最后一搏，仅信令级流量）——Win iphlpapi / Unix ping-socket 双后端。

```rust
pub mod escape_frame {
    pub const MAGIC: [u8; 2] = *b"EE";
    pub const HEAD_LEN: usize = 2 + 4 + 4 + 1;      // = 11（magic + tag + seq + len）
    pub const PAYLOAD_MAX: usize = 40;              // 保证 ≤ 63B
    pub const TOTAL_MAX: usize = HEAD_LEN + PAYLOAD_MAX + 12;   // = 63

    pub struct EscapeFrame { pub session_tag: [u8; 4], pub seq: u32, pub payload: Vec<u8>, pub auth: [u8; 12] }

    pub fn craft(key: &[u8; 32], session_tag: [u8; 4], seq: u32, payload: &[u8]) -> Vec<u8>;
    // magic | tag | seq(BE) | payload_len(1) | payload(≤40，超长截断) | auth(12)
    // auth = HMAC(probe_key, 前 11B + payload)（auth 域置零后对全帧签名——escape_auth）

    pub fn decode(key: &[u8; 32], buf: &[u8]) -> Option<EscapeFrame>;
    // 长度界 [HEAD_LEN+12, TOTAL_MAX] + magic + len 字段自洽 + 全帧验签
}

#[cfg(windows)] mod backend { /* ... */ }
#[cfg(unix)]    mod backend { /* ... */ }
#[cfg(any(windows, unix))]
pub use backend::IcEscape;
```

**帧布局**：`magic(2 "EE") | session_tag(4) | seq(4) | payload_len(1) | payload(≤40) | auth(12)`，总长 ≤63B（装入 ICMP Echo data 区）；`escape_auth` 签名。

**Windows 后端**（`#[cfg(windows)]`，escape.rs:85-166）：

- iphlpapi FFI 直连（零额外依赖）：`#[link(name = "iphlpapi")] extern "system" { IcmpCreateFile / IcmpCloseHandle / IcmpSendEcho }`。
- `IcEscape { key: [u8;32], tag: [u8;4] }`；`new(key, tag)`。
- `round_trip(&self, dst: Ipv4Addr, seq: u32, payload: &[u8]) -> Option<EscapeFrame>`：组帧 → `spawn_blocking`（IcmpSendEcho 阻塞；句柄生命周期收进阻塞域避免跨 await 持句柄）→ 800ms 超时 → 回显 data 位于 `reply[REPLY_HEAD..]`（`REPLY_HEAD = 8`，ICMP_ECHO_REPLY 头尺寸）→ `escape_frame::decode` 验签。
- 语义降级说明（文件头）：IcmpSendEcho 自带 identifier 管理，Windows 逃生降级为"**ping 轮询信道**"（本端发帧、回包中提取对端帧）。

**Unix 后端**（`#[cfg(unix)]`，escape.rs:168-222）：

- `SOCK_DGRAM + IPPROTO_ICMP` ping socket（socket2 `Protocol::ICMPV4`；系统 `ping_group_range` 允许时免 root）→ `send_to` 直发帧 → 同步 `read` 单帧 → decode。
- 文件头注释：**本分支在当前 Windows 开发机上无法编译验证，服务器首日先 cargo build 验证**（部署清单 1 号步骤）。
- 代码注释自承：简化同步读（阻塞模式下 recv 单帧；**生产应挂 async 适配**）。

**使用约束**（文件头）：两个后端均较 UDP 低效且不可靠，仅供 UDP/TCP 全灭时交换保活/重连协调等极小流量；**业务数据永不进入**。

**测试（5 个）**：`escape_frame_roundtrip`（帧字段完整解出）；`escape_frame_tamper_rejected`（篡改载荷拒）；`escape_frame_wrong_key_rejected`；`escape_frame_overlong_payload_truncated`（64B 载荷截断至 40B，总长 ≤ TOTAL_MAX）；`icmp_loopback_echo_carrier_alive`（`#[cfg(windows)]` + tokio：ping loopback 回显闭环证明 iphlpapi 后端可用；**软断言**——本机防火墙可能静默丢 ICMP，仅 eprintln 打印结果不断言）。

---

## 4. 对外 API 汇总（lib.rs 的 pub use 全量清单）

| 导出项 | 来源 | feature 门控 |
|--------|------|-------------|
| `pub type PeerId = [u8; 16]` | lib.rs 定义 | 无（两 feature 均导出） |
| `Engine`、`LinkStream`、`NodeConfig`、`NodeHandle`、`NodeRole` | `engine` | 无 |
| `PunchInput`、`RoomHandle` | `engine` | `client` |
| `AnchorChangeReason`、`DeadEndReport`、`EngineEvent`、`LinkLossCause`、`RePunchReason`、`RoomJoinFailReason` | `event` | 无 |
| `KeyExporter`、`PskBundle` | `exporter` | `client` |
| `LinkQuality`、`LinkTransport`、`PunchedLink` | `link` | `client` |
| `OrchestratorError`、`SessionOrchestrator` | `orchestrator` | `client` |
| `LinkRank` | `rank` | 无 |
| `measure_seeds`、`pick_fastest_seed`、`resolve_endpoint`、`SeedPick` | `servers` | `client` |
| `LanProbeCarrier`、`TcpProbeCarrier`、`UdpProbeCarrier` | `transport` | `client` |
| `JoinHandle`、`LinkControl`、`LinkIntent`、`LinkSink`、`MemberInfo`、`RoomApi`、`RoomCode`、`RoomId`、`RoomKey`、`RoomRole`、`TransportCapabilitySet` | `types` | `client` |
| `CryptoProfile`、`SecretBox` | 转发 `wgp_crypto` | `client` |
| `peer_id_from_node` | 转发 `wgp_dht::id` | 无 |
| `ProbeCarrier`、`PunchState` | 转发 `wgp_punch` | `client` |

**未在 lib.rs 顶层 re-export 但 pub 可达的项**（经模块路径）：

- `wgp_core::engine::decide_race` / `CircuitInput` / `RaceConfig` / `TcpTrigger` / `keepalive_loop` / `NatClass` / `NatProbe` / `ObserverReport` / `classify_reports` / `PunchOutcome` / `PunchRunner` / `race_punch` / `RaceOutcome`（engine.rs 内 `pub use`，`client`）——注意 `engine::circuit` 等子模块本身是 `#[cfg(feature="client")] pub mod`，路径 `wgp_core::engine::circuit::*` 亦可达。
- `wgp_core::link::IcmpChan`（`client`）。
- `wgp_core::transport::IcEscape`、`wgp_core::transport::probe::{now_ms, craft_probe, verify_probe}`、`wgp_core::transport::lan::{DEFAULT_GROUP, beacon}`、`wgp_core::transport::tcp::TCP_PORT_PUNCH_TIMEOUT_MS`（`client`）。
- `wgp_core::transport::escape::escape_frame::*`（`client`）。

---

## 5. 与设计文档（14/00/15）的对应关系

### 5.1 14 §12 实现漂移表在代码中的落点（逐条）

| 14 §12 条款 | 漂移内容 | 代码落点 |
|------------|---------|---------|
| new_link 输入 | `LinkIntent` → `PunchInput` | `engine.rs:115`（结构定义）、`engine.rs:212`（`new_link(&self, input: PunchInput, sink)`）；`LinkIntent` 保留无消费者（`types.rs:44`） |
| join_room | 同步 → `async → Result<RoomHandle, RoomError>`；第一人自动建房 | `engine.rs:306-403`（`Err(RoomError::NotFound)` 分支 → `rt.create(...)`，房主=锚点） |
| RoomHandle | `cancel()` → `leave()` | `engine.rs:482`（`leave(self) -> JoinHandle`，停 upkeep） |
| 信令上下文 | 隐含 → 显式 `attach_dht` | `engine.rs:203`；未 attach 时 join_room 报 `NoDhtAttached` |
| mesh 边驱动 | join_room 内部 → 外围 `SessionOrchestrator::connect_peer`；commit accept 放宽 Commit\|Reveal | `orchestrator.rs:181`（connect_peer）、`orchestrator.rs:234-252`（①a accept 闭包放宽 + 注释说明防阶段漂移死锁） |
| 竞速 | `race_punch` + `RaceOutcome`；T1 命中跳过 UDP | `race.rs:157`（race_punch）、`race.rs:18-30`（RaceOutcome）；`engine.rs:124`（`PunchInput.udp_enabled` 注释）、`race.rs:183`（`udp_done = !udp_on`） |
| T1-T4 判定 | `CircuitInput::tcp_triggered()` / `decide_race()` 纯函数 | `circuit.rs:51`、`circuit.rs:75` |
| 载体集 | + ICMP 逃生（双后端）+ LAN 组播 | `transport/escape.rs`（windows backend / unix backend）、`transport/lan.rs`；Unix ICMP 后端"服务器首日编译验证"注释在 `escape.rs:171-172` |
| 保活 | UDP 交付后自动挂 `keepalive_loop`；`LinkControl::release` 已实现 | `engine.rs:254-261`（哨兵起跑）；`engine.rs:458-467`（LinkControl impl） |
| TCP 命中 | rank=Degraded，保活由 TCP keepalive 承担 | `engine.rs:263-281`（分支 + 注释） |
| UDP 波次 | 发一批→短监听 → 边发边收 | `race.rs:60-65`（发前非阻塞查收）、`race.rs:81-92`（波尾收紧窗） |
| 双模定时器 | `DualModeTimer`（Normal/Precision + 校准偏移） | **wgp-core 内无落点**（属 wgp-punch 职责；代码如此，意图待确认是否需在内核侧留钩子） |

### 5.2 生命周期六条款（14 §10）在代码中的落点

| 条款 | 契约 | 代码落点与现状 |
|------|------|--------------|
| 1. yield 一次语义 | 竞速先通先用；同档更优不重复交付 | `engine.rs` new_link 三分支各至多一次 `on_link_yielded`；`punch_runner.rs:107`、`race.rs` 命中即返回（先通先用）。跨档升级 `upgraded` 路径未实现 |
| 2. 旧链路宽限 30s | upgraded 后旧链路保活 30s | **未实现**（无 `LinkUpgraded` 产出点）；`types.rs:23` 注释保留语义 |
| 3. 密钥单次转移 | take_tls_psk/session_key 一次取出 | `exporter.rs:19`（take_tls_psk 返回 Option 语义）；`link.rs:39`（`session_key: SecretBox` 所有权随 PunchedLink 转移）；`PunchInput.session_key` 注释"所有权随交付转移"（engine.rs:126） |
| 4. 保活唯一权 | 外围唯一入口 suspend/resume，内核可否决 | `keepalive.rs`（唯一保活实现）+ `engine.rs:254-261`（自动挂载）；`LinkControl::suspend/resume_keepalive` 为空实现（否决权未接，engine.rs:473-474） |
| 5. 重连幂等 | lost→re-punch→yield 环上新旧密钥必然不同 | **未实现**（无重打洞路径；每次 connect_peer 全新 X25519 + nonce + derive_all，orchestrator.rs:198-291） |
| 6. 取消语义 | JoinHandle 取消后 100ms 清理 | `RoomHandle::leave` → `JoinHandle`（engine.rs:482）；**100ms 保证为注释宣称，JoinHandle 无取消方法**（types.rs:50） |

### 5.3 00 §4 内核要素对照

| 00 §4 要素 | 代码落点 |
|-----------|---------|
| 契约：产出 PunchedLink；保活唯一权 | `link.rs:36`（PunchedLink）；`keepalive.rs:17` |
| 链路优先级 LAN > QUIC > TCP > ICMP | `rank.rs`（Primary/Degraded/Escape 三档，LAN 与 QUIC 同归 Primary）；engine.rs 中 UDP→Primary、TCP→Degraded 赋值 |
| 状态机 Idle→…→Punched→Connected | **代码无显式状态机**——控制流隐式分布于 connect_peer 七阶段 + race_punch + keepalive_loop（与 14 §12"竞速/漂移"登记一致：引擎以编排取代显式 FSM） |
| TCP 兜底触发 T1-T4 | `circuit.rs`（TcpTrigger 四变体 + tcp_triggered 优先级 T1>T2>T3>T4） |
| 调度器唯一发包点（H6） | `BudgetScheduler` 贯穿：`race.rs:67`（UDP 发包前）、`race.rs:124`（TCP 发包前）、`keepalive.rs:33`（保活包）、`punch_runner.rs:74` |
| 对外交付物八件套 | PunchedLink（link.rs）、LinkSink/KeyExporter/SignalingBus(EngineEvent)/LinkControl/RoomApi/ProbeCarrier/KeyAgreement：前五项 + ProbeCarrier 转发在 lib.rs；KeyAgreement 由 orchestrator 经 wgp-crypto 使用（orchestrator.rs:28） |
| 不做清单（不建 QUIC/不解析应用协议/无流控） | engine.rs:235-236 注释（QUIC 握手属实现阶段）；内核无任何应用协议代码 |

### 5.4 15 全链路 Phase 对照

| 15 Phase | 代码落点 |
|---------|---------|
| Phase 0② NAT 判定（双观察者 STUN） | `nat_probe.rs`（probe_observer + classify_reports；orchestrator 只用首个成功观察者的单报告，未做双报告交叉——见第 6 章） |
| Phase 0③ 出站预判 / LAN beacon 监听 | `udp_ok = my_mapped.is_some()`（orchestrator.rs:315，间接预判）；`LanProbeCarrier` 存在但未接入流程 |
| Phase 1/2 建房/加入 | `Engine::join_room`（建房 + 签名报道 + upkeep） |
| Phase 3 承诺-揭示 | `orchestrator.rs:197-288`（X25519 commit/reveal、shared、derive_all 密钥族） |
| Phase 4 观察与测量 | `orchestrator.rs:301-318`（NatProbe + learn_step；**未做 net_offset 时间对齐交换**——FIRE_AT_MS 为近似锚点，orchestrator.rs:192-195 注释自承） |
| Phase 5 竞速打洞 | `race.rs`（UDP 三波 ∥ TCP simultaneous open；LAN 路径①与 ICMP 反推辅助未接入） |
| Phase 6 验证与握手 | `race.rs` 探针 HMAC 验证即"打通"；QUIC 握手未接（engine.rs:235 注释）；ICMP 逃生/死局评分未接 |
| Phase 7 稳态保活 | `keepalive.rs`（HeartbeatLoop 节奏 + 31B 探针 + 预算闸门）；降级档 30s 升级探测、NAT 重绑定重打洞未接 |
| Phase 8 清理 | `RoomHandle::leave`（停 upkeep）；成员表除名/密钥 zeroize/预算归还由 wgp-dht upkeep 与 SecretBox 所有权转移承担 |

---

## 6. 已知限制或未实现项

以下均为代码中可核实的状态（2026-11-05 通读确认）：

**引擎/流程缺口**

1. **QUIC 握手未接**：UDP 命中后以"打洞成功"为交付点（engine.rs:235-236 注释），15 Phase 6 后半（TLS-PSK 注入、3s 超时 → T3 触发）未实现；`CircuitInput.quic_handshake_timed_out` 恒 false。
2. **ICMP 逃生与 LAN 未接入竞速**：`IcEscape`/`LanProbeCarrier` 载体已实现，但 `race_punch` 只跑 UDP∥TCP；`LinkRank::Escape`、`LinkTransport::{Icmp, Lan}` 无产出点；`PunchInput` 无对应输入字段。
3. **LAN 路径①**（15 Phase 5：beacon 互见 → 跳过②③）未编排进 connect_peer。
4. **双观察者交叉判定未用**：`classify_reports` 已实现且被测试覆盖，但 orchestrator 只用首个成功观察者的单报告（orchestrator.rs:306-314），未执行 15 Phase 4 的"K=2 报告取多数"。
5. **网络时间对齐未做**：无 net_offset 交换；`FIRE_AT_MS = 3000` 为近似会话锚点（orchestrator.rs:192-195 注释自承"真实部署由 T_offset 对齐代替"）；`learn_step` 的 `now_fn` 传 `|| [0u8; 8]`（时间戳恒零）。
6. **T4 运营商画像未接**：`CircuitInput.carrier_profile_bad` 在 orchestrator 中恒 false（orchestrator.rs:376）；D2 画像无数据来源。
7. **降级档升级探测 / NAT 重绑定重打洞 / 死局判定**：`LinkControl::request_upgrade` 空实现；`EngineEvent::{LinkUpgraded, RePunching, DeadEnd, BudgetExhausted, KeepaliveSuspended, RoomAnchorChanged}` 从未发送；`DeadEndReport`（04 D5 评分）无产出点。
8. **`PunchRunner` 无生产调用点**：`Engine::new_link` 走 `race_punch`；`PunchRunner`（串行简化版）仅测试在用，与 `race.rs::run_udp_waves` 功能重叠（文件头注释说明生产应改并发）。
9. **`PunchedLink.quality` 硬编码**：rtt 0ms、loss 0.0、mtu 1400、obeys_budget true（engine.rs:244-249、273-278）——内核实测值未填。
10. **`OrchestratorError::AlgoMismatch`/`ObserverDead` 无产出点**：connect_peer 不产这两种错误（ObserverDead 场景下 udp_ok=false 继续走 EP 交换，不报 ObserverDead）。
11. **peer_model 重建信息损失**：对端步长模型经 EP 传输后 `trend` 恒 `Oscillating`、`delta_range (0,0)`（orchestrator.rs:388-398），仅 last_port/mean_delta/confidence 有效。
12. **TCP 源端口保留技巧**：orchestrator 先 `TcpListener::bind("127.0.0.1:0")` 占端口、drop、再以 `0.0.0.0:port` 重绑（orchestrator.rs:401-413）——占位与重绑之间存在竞态窗口（测试注释承认本地竞态可忽略）。

**API 契约缺口**

13. **`KeyExporter` trait 无实现者**（PSK 经 `PunchedLink.session_key` 交付；quinn/rustls 注入属客户端任务）。
14. **`RoomApi` trait 无实现者**（房间操作走 `Engine::join_room` 具体方法）。
15. **`JoinHandle` 无取消方法**：仅持 `room` 字段；14 §7"取消后 100ms 清理"无 API 入口。
16. **`LinkControl` 五方法中四个为空实现**（仅 release 落地）：request_upgrade / suspend_keepalive / resume_keepalive / advertise_transports（engine.rs:470-476）。
17. **`LinkIntent` 无消费者**（14 §12 漂移后保留的类型）。
18. **`NodeConfig.role` 字段未被 run_node 读取**（Seed/Observer 角色由实际绑定面隐式决定）。

**平台/工程项**

19. **Unix ICMP 后端未编译验证**：当前 Windows 开发机无法验证，服务器首日 cargo build 为验证门（escape.rs:171-172 注释 + 14 §12 登记）。
20. **Unix ICMP 后端为同步阻塞读**：未挂 async 适配（escape.rs:210 注释自承"生产应挂 async 适配"）。
21. **Windows ICMP 逃生为无状态 ping 轮询**：IcmpSendEcho 每帧一次调用，identifier 不自主管理（降级语义，文件头注释）。
22. **LAN 组播网络收发无单测**：loopback 行为不稳定，真机验证项（lan.rs:8-10 注释）。
23. **两个独立单调时钟锚点**：`engine_now_ms`（engine.rs:81）与 `probe::now_ms`（probe.rs:9）各自 OnceLock，同进程两套毫秒起点（用途不同，统一与否意图待确认）。
24. **测试环境边界**：wgp-core 全部 34 个测试（engine 4 / punch_runner 3 / circuit 5 / nat_probe 4 / orchestrator 2 / servers 4 / udp 2 / tcp 2 / lan 3 / escape 5，其中 escape 的 `icmp_loopback_echo_carrier_alive` 为 Windows 软断言）均运行于 Windows loopback；跨平台性依赖"零平台依赖代码 + tokio 抽象"声明（14 §12 诚实声明；Linux 侧以部署清单"编译测试先行"为门）。
25. **`run_node` 失败仅 eprintln**：DHT/TCP/STUN 三面绑定失败不向调用方传播错误（NodeHandle 字段为 None 即降级）。
26. **orchestrator `encode_endpoints` 1 字节重叠写**：`out[14..46].fill(0)` 后 `out[15..47]` 拷贝承诺，14..15 重叠（功能无影响，代码如此）。

---

*本文档结束。所有签名、常量、流程描述均照抄自 `kernel/wgp-core/src/` 源码（2026-11-05 通读）；标注"代码如此，意图待确认"处为文档纪律要求的下不确定项。*
