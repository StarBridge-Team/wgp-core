# wgp-punch 打洞引擎详细文档

> - 源目录：`H:\mclink core\kernel\wgp-punch\src\`
> - 生成日期：2026-11-05
> - 对应设计文档：`docs/03-核心打洞与穿透算法`、`docs/04-边缘辅助与容错算法`（另涉及 `docs/00` 约束总则、`docs/14` 载体分层、`docs/15` 全链路流程）
> - 分析范围：crate 全部 8 个源文件（含测试模块），另核对 `wgp-proto/src/consts.rs` 中被引用常量的真实数值

---

## 1. Crate 概览

### 1.1 定位

wgp-punch 是折跃门（wgp）NAT 打洞引擎的**纯算法层**，是 `docs/03`（核心打洞与穿透算法）与 `docs/04`（边缘辅助与容错算法）的代码化实现。其纪律见 `lib.rs` 头注释：

- **调度器是唯一发包点（H6，00 §3）**：crate 内所有模块只做决策与计划（"何时发、发哪些端口、发多少"），不持有 socket、不执行任何真实 IO；发包动作与预算扣减由外层调度器 / `UdpProbeCarrier` / 引擎完成。
- **内核只产链路、不跑数据**：本 crate 的产出是"探测计划 + 心跳节奏 + 预算闸门 + 状态机语义"，链路打通后的数据面归 wgp-core。
- 各子模块均为**零依赖或仅依赖 wgp-proto 常量**的纯逻辑，可独立单测。

### 1.2 依赖

仅一个内部依赖：`wgp-proto`（取其 `consts` 模块的常量）：

| 引用常量 | 数值 | 定义位置 | 使用者 |
|---|---|---|---|
| `PROBE_BUDGET_PER_ROUND` | `u16 = 47` | wgp-proto/src/consts.rs:10 | budget.rs |
| `PROBE_BUDGET_PER_10MIN` | `u16 = 500` | wgp-proto/src/consts.rs:11 | budget.rs |
| `WAVE1_PACKETS` | `u16 = 21` | wgp-proto/src/consts.rs:14 | wave.rs |
| `WAVE2_PACKETS` | `u16 = 15` | wgp-proto/src/consts.rs:15 | wave.rs |
| `WAVE3_PACKETS` | `u16 = 11` | wgp-proto/src/consts.rs:16 | wave.rs |

无任何第三方 crate 依赖（随机数为自带 xorshift64 实现，注释明示"避免引入第三方 RNG"）。

---

## 2. 模块结构总表

| 文件 | 职责 | 关键导出 |
|---|---|---|
| `lib.rs` | crate 根：声明 7 个 pub 模块并再导出核心类型 | `BudgetScheduler`、`ProbeCarrier`、`HeartbeatController`、`HeartbeatLoop`、`PunchState`、`PortStepModel`、`DualModeTimer`、`plan_waves` 等 15 项 |
| `budget.rs` | 包预算调度器（H6 双闸门：轮 ≤47、10 分钟滑窗 ≤500） | `BudgetScheduler`、`BudgetError` |
| `carrier.rs` | 底层多协议载体抽象（引擎只面向 trait 编程） | `ProbeCarrier`、`TransportCapability`、`MappingSemantics`、`CarrierError` |
| `heartbeat.rs` | 动态心跳控制器（成功率滑窗调间隔）+ tick 驱动保活循环 | `HeartbeatController`、`HeartbeatLoop`、`HbAction` |
| `state.rs` | 引擎主状态机（Idle→…→Connected / DeadEnd）与 TCP 兜底触发条件 | `PunchState`、`TcpFallbackTrigger` |
| `stepmodel.rs` | 端口步长学习模型（3 次 STUN 观测建立预测窗口） | `PortStepModel`、`Trend`、`PredictWindow` |
| `timer.rs` | 双模定时器（Normal / Precision 切换、deadline 判定、漂移校准） | `DualModeTimer`、`TimerMode` |
| `wave.rs` | 三波探测计划生成器（21+15+11，纯逻辑零 IO） | `plan_waves`、`WavePlan`、`Confidence`、`XorShift64`、`BROAD_NET_PACKETS` |

---

## 3. 逐文件详细文档

### 3.1 `lib.rs`

**文件路径**：`kernel/wgp-punch/src/lib.rs`
**一句话职责**：crate 根模块，声明全部子模块并统一再导出对外 API。

**内容**（`lib.rs:1-18`）：

模块声明（7 个，均 `pub`）：
```rust
pub mod budget;
pub mod carrier;
pub mod heartbeat;
pub mod state;
pub mod stepmodel;
pub mod timer;
pub mod wave;
```

再导出（15 项）：
```rust
pub use budget::BudgetScheduler;
pub use carrier::{CarrierError, MappingSemantics, ProbeCarrier, TransportCapability};
pub use heartbeat::{HbAction, HeartbeatController, HeartbeatLoop};
pub use state::PunchState;
pub use stepmodel::{PortStepModel, Trend};
pub use timer::{DualModeTimer, TimerMode};
pub use wave::{plan_waves, Confidence, WavePlan, XorShift64};
```

头注释声明了两条纪律（H6 唯一发包点；内核只产链路不跑数据），并注明本 crate 是"03/04 文档的代码化"。

**测试**：无（lib.rs 不含测试模块）。

---

### 3.2 `budget.rs` — 包预算调度器

**文件路径**：`kernel/wgp-punch/src/budget.rs`
**一句话职责**：实现 H6 双闸门预算——每轮打洞竞速 ≤47 包、10 分钟滑动窗口 ≤500 包，是全内核唯一的探针预算入口。

#### 类型与函数

```rust
pub struct BudgetScheduler {
    per_round_remaining: u16,   // 本轮剩余（打洞竞速一轮）
    per_window_remaining: u16,  // 10 分钟滑动窗口剩余
}
```
（`#[derive(Debug, Clone)]`，budget.rs:6-12；两个字段均私有，仅能经方法访问）

```rust
pub enum BudgetError {
    RoundExhausted,     // 轮预算耗尽
    WindowExhausted,    // 10 分钟窗口预算耗尽
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，budget.rs:14-18）

| 方法 | 签名（照抄） | 含义 |
|---|---|---|
| 构造 | `pub fn new() -> Self` | 两闸门分别初始化为 47 / 500 |
| 申请 | `pub fn try_acquire(&mut self, n: u16) -> Result<(), BudgetError>` | 申请 n 包；**任一闸门不足即整体拒绝，不部分扣减**；通过则两闸门同时扣 n |
| 新一轮 | `pub fn begin_round(&mut self)` | 轮预算复位为 47；**窗口预算不回滚**（H6 滑动语义） |
| 窗口恢复 | `pub fn refill_window(&mut self)` | 窗口闸门回填为 500（注释注明由时间驱动，实现阶段接入引擎定时器） |
| 查询 | `pub fn remaining(&self) -> (u16, u16)` | 返回 `(轮剩余, 窗口剩余)` |

另实现 `Default`（委托 `new()`）。

#### 算法细节

- **双闸门检查顺序**（budget.rs:30-40）：先查 `n > per_round_remaining` → `RoundExhausted`；再查 `n > per_window_remaining` → `WindowExhausted`。即轮闸门优先级高于窗口闸门。
- **滑动语义**：`begin_round()` 只复位轮闸门，10 分钟窗口跨轮累积消耗；`refill_window()` 一次性回填（注释说明"每 10 分钟滑动回填"由引擎定时器驱动，本 crate 不含定时器接线）。
- 头注释："耗尽即触发 BudgetExhausted 事件"——事件在引擎侧消费，本 crate 只返回 `BudgetError`。

#### 常量数值

| 常量 | 数值 | 来源 |
|---|---|---|
| 轮预算 | 47 包/轮 | `PROBE_BUDGET_PER_ROUND`（wgp-proto） |
| 窗口预算 | 500 包/10min | `PROBE_BUDGET_PER_10MIN`（wgp-proto） |

#### 测试用例

无（budget.rs 不含 `#[cfg(test)]` 模块）。

---

### 3.3 `carrier.rs` — ProbeCarrier 多协议载体抽象

**文件路径**：`kernel/wgp-punch/src/carrier.rs`
**一句话职责**：定义底层多协议打洞载体的 trait 与配套值类型；引擎只面向 trait 编程，新增载体 = 新写一个实现，引擎零改动（00 D9，14 §8）。

#### 类型与函数

```rust
pub enum TransportCapability {
    Udp,
    Tcp,
    Icmp,
    Lan,
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]`，carrier.rs:7-13；用于能力位交换 + `LinkControl::advertise_transports` 的单元）

```rust
pub enum MappingSemantics {
    PortTagged { port: u16 },       // UDP/TCP：打端口
    IdentifierTagged { id: u16 },   // ICMP Echo：打 query identifier（NAT 以 identifier 做映射）
    AddrOnly,                       // LAN 组播：无端口语义，地址即身份
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，carrier.rs:16-24；表示"每种协议的 NAT 映射语义（打洞预测的对象）"）

```rust
pub struct CarrierError(pub &'static str);
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，carrier.rs:27；载体错误，携带静态字符串）

```rust
#[allow(async_fn_in_trait)]
pub trait ProbeCarrier: Send + Sync {
    async fn send_probe(&self, dst: SocketAddr, payload: &[u8]) -> Result<(), CarrierError>;
    fn on_probe(&self, src: SocketAddr, payload: &[u8]) -> bool;
    fn mapping_semantics(&self) -> MappingSemantics;
    fn capability(&self) -> TransportCapability;
}
```
（carrier.rs:34-48）

四个方法的语义（注释原文要义）：

| 方法 | 含义 |
|---|---|
| `send_probe` | 发送一枚探针；**预算由 BudgetScheduler 预扣，本方法不做预算判断**。为原生 async fn（快速路径复用调用方 executor；不进对象指针，实现方为具体类型，由引擎泛型持有）。lint 豁免理由：本 trait 不打对象指针，auto trait 边界无意义 |
| `on_probe` | 收到可能是探针的包时交给引擎裁决，**返回 true 表示已消费**；同步方法（读循环单包即可判定，无需悬挂） |
| `mapping_semantics` | NAT 映射语义，决定引擎如何预测/撒网 |
| `capability` | 本载体能力标识（能力位交换用） |

设计约束："只要能'向目标发小包 + 收对端小包'，就能当打洞载体（14 §8）"。

#### 算法细节

trait 本身不含算法，是引擎与具体载体（如外层 `UdpProbeCarrier`）之间的解耦面。引擎据 `mapping_semantics()` 的三种形态选择不同的预测撒网策略；`MappingSemantics` 与 stepmodel/wave 的端口规划配合覆盖 `PortTagged`/`IdentifierTagged` 两种可预测形态。

#### 常量数值

无（无关联常量）。

#### 测试用例

无（carrier.rs 不含测试模块）。

---

### 3.4 `heartbeat.rs` — 动态心跳控制器与保活循环

**文件路径**：`kernel/wgp-punch/src/heartbeat.rs`
**一句话职责**：03 §3.7/§3.8 的代码化——`HeartbeatController` 用成功率滑窗动态调心跳间隔；`HeartbeatLoop` 是 tick 驱动纯逻辑（无定时器依赖，可单测），与预算闸门联动。

#### 3.4.1 HeartbeatController（成功率滑窗控制器）

```rust
pub struct HeartbeatController {
    min_interval: Duration,
    max_interval: Duration,
    next_interval: Duration,
    success_window: VecDeque<bool>,   // 最近 20 次心跳成功率滑窗
}
```
（heartbeat.rs:9-15；字段均私有）

| 方法 | 签名（照抄） | 含义 |
|---|---|---|
| 构造 | `pub fn new() -> Self` | `min=500ms`、`max=15s`、`next=2s`、滑窗容量 20 |
| 结果反馈 | `pub fn on_result(&mut self, success: bool)` | 推入滑窗（保持最近 20 条）→ 计算成功率 → 调间隔 |
| 恢复间隔 | `pub fn fast_recovery_interval(&self) -> Duration` | 固定返回 `100ms`（休眠/挂起恢复用） |
| 查询 | `pub fn next_interval(&self) -> Duration` | 当前常规心跳间隔 |

**调频算法**（heartbeat.rs:40-48）：
- 成功率 = 滑窗内 `true` 计数 / 滑窗长度；
- `rate < 0.8` → 间隔 **−500ms**（saturating_sub，下限 `min_interval=500ms`）；
- `rate > 0.95` → 间隔 **+1s**（上限 `max_interval=15s`）；
- `[0.8, 0.95]` 区间不变（死区）。
- 注意：`fast_recovery_interval()` 是 `HeartbeatController` 的方法，但 `HeartbeatLoop::tick` 内部恢复期间隔硬编码为 `100ms`（heartbeat.rs:108），两者数值一致但无代码关联。代码如此，意图待确认。

#### 3.4.2 HeartbeatLoop（tick 驱动保活循环）

```rust
pub struct HeartbeatLoop {
    ctrl: HeartbeatController,
    last_send_ms: Option<u64>,
    seq: u32,
    ext_every: u32,            // 步长校准扩展节奏：每 10 次带 1 次（03 §3.7.4）
    anomaly_extra_ext: u8,     // 检测到端口突变后连续 3 次都带扩展
    fast_recovery_left: u8,    // 设备恢复快速心跳剩余次数（100ms 间隔 ×3）
}
```
（heartbeat.rs:69-79；字段均私有）

```rust
pub enum HbAction {
    Send { seq: u32, with_ext: bool },   // 常规发送：seq + 是否携带步长扩展（cur/prev port 由引擎填入）
    FastSend { seq: u32 },               // 恢复期快速发送（100ms 间隔，不参与滑窗计数）
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，heartbeat.rs:82-88）

| 方法 | 签名（照抄） | 含义 |
|---|---|---|
| 构造 | `pub fn new() -> Self` | `ext_every=10`，其余计数清零 |
| 主入口 | `pub fn tick(&mut self, now_ms: u64, budget_ok: bool) -> Option<HbAction>` | 外层每 ~100ms 调一次；返回待执行动作 |
| 反馈 | `pub fn on_result(&mut self, success: bool)` | 透传给内部控制器滑窗 |
| 异常 | `pub fn on_anomaly(&mut self)` | 引擎检测到端口突变（03 §3.7.5）→ `anomaly_extra_ext = 3`，连续 3 次扩展格式 |
| 恢复 | `pub fn on_resume(&mut self)` | 设备休眠/网络切换恢复 → `fast_recovery_left = 3`，3 次 100ms 快速心跳重建映射 |
| 查询 | `pub fn current_interval_ms(&self) -> u64` | 当前常规间隔（毫秒） |
| 复位 | `pub fn reset(&mut self)` | 连接断开/释放：清 last_send/seq/anomaly/fast_recovery，seq 从 0 起 |

**`tick` 的四段逻辑**（heartbeat.rs:103-147）：
1. **恢复期优先**：`fast_recovery_left > 0` 时按 100ms 间隔发 `HbAction::FastSend`，递减计数，`return None` 不让位常规逻辑；
2. **到点判定**：`now_ms.saturating_sub(last) >= ctrl.next_interval()`；首次（`last_send_ms=None`）立即发；
3. **预算闸门（H6）**：`budget_ok=false` 时 **不推进 `last_send_ms`**，直接返回 None，下次 tick 重试——注释说明这是为了"避免 NAT 表超时口径失真"，引擎侧会收到 `BudgetExhausted`；
4. **扩展节奏**：`anomaly_extra_ext > 0` 时消耗之并带扩展；否则 `seq % ext_every == 0`（即每第 10、20… 次）带扩展。

`seq` 使用 `wrapping_add(1)` 递增（heartbeat.rs:111,133）。

#### 3.4.3 常量数值（heartbeat.rs 全部硬编码数值）

| 常量 | 数值 | 位置 | 含义 |
|---|---|---|---|
| 最小间隔 `min_interval` | 500 ms | heartbeat.rs:20 | 调频下限 |
| 最大间隔 `max_interval` | 15 s | heartbeat.rs:21 | 调频上限 |
| 初始间隔 `next_interval` | 2 s | heartbeat.rs:22 | 控制器初始节奏 |
| 滑窗长度 | 20 | heartbeat.rs:23,30 | 成功率统计窗口 |
| 加频阈值 | `< 0.8` | heartbeat.rs:40 | 低于此降间隔 |
| 加频步长 | 500 ms | heartbeat.rs:43 | 每次 −500ms |
| 减频阈值 | `> 0.95` | heartbeat.rs:45 | 高于此升间隔 |
| 减频步长 | 1 s | heartbeat.rs:46 | 每次 +1s |
| 快速恢复间隔 | 100 ms | heartbeat.rs:53,108 | 恢复期心跳间隔 |
| 快速恢复次数 | 3 | heartbeat.rs:161,98 语义 | `fast_recovery_left` 初值 |
| 扩展节奏 | 每 10 次带 1 次 | heartbeat.rs:96 | `ext_every = 10` |
| 突变后连续扩展 | 3 次 | heartbeat.rs:156 | `anomaly_extra_ext = 3` |
| 常规 tick 驱动周期 | ~100 ms | heartbeat.rs:67 注释 | 外层建议节奏 |

#### 3.4.4 测试用例（heartbeat.rs:184-262，共 5 个）

| # | 测试名 | 验证点 |
|---|---|---|
| 1 | `initial_interval_2s` | 初始间隔 2000ms；t=0 首发（seq=1）；1999ms 不发；2000ms 到点再发（seq=2） |
| 2 | `seq_10_carries_ext_normal_rhythm` | 10 次心跳中恰第 10 次携带扩展（`ext_at == vec![10]`） |
| 3 | `budget_reject_defers_not_sends` | 预算拒绝时不发且不推进；预算恢复后 seq=2（不跳号） |
| 4 | `fast_recovery_three_at_100ms` | `on_resume` 后连发 3 次 FastSend（100ms 间隔，不受常规间隔限制）；恢复完毕回 2s 常规节奏 |
| 5 | `high_success_low_freq_adapts_up` | 20 次全成功（rate=1.0）→ 间隔逐次 +1s 直至上限 15s；随后 40 次失败 → 逐步拉回 500ms 底 |

---

### 3.5 `state.rs` — 引擎主状态机

**文件路径**：`kernel/wgp-punch/src/state.rs`
**一句话职责**：定义每 Peer 一会话实例的状态机（00 §4：Idle → … → Connected；失败 → ICMP 逃生 → 死局）与 TCP 兜底触发条件。

#### 类型与函数

```rust
#[non_exhaustive]
pub enum PunchState {
    Idle,         // 入口：收到连接意图
    Preprobe,     // 后台预探测：时间锚点 / NAT 类型 / UDP 可用 / 步长模型
    RoomLookup,   // DHT 房间键查找（U/ 码 → 房间 → 锚点）
    Negotiating,  // 承诺-揭示 + 观察者报告交叉验证 + 能力位交换
    Punching,     // 竞速打洞：LAN ∥ UDP 三波 ∥ TCP simultaneous-open
    Connected,    // 链路已打通（链路档位见 LinkRank，在 wgp-core）
    DeadEnd,      // 全灭 + ICMP 逃生失败：死局判定（04 D5），附诊断报告告知用户
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，state.rs:4-21；7 个状态，注释即 15 全链路 Phase 3-8 的状态化说明）

```rust
pub enum TcpFallbackTrigger {
    UdpPrecheckBlocked,    // T1：预判 UDP 出站不可达
    UdpThreeWavesFailed,   // T2：UDP 三波全灭
    QuicHandshakeTimeout,  // T3：UDP 打通但 QUIC 握手超时（疑 DPI 拦 QUIC）
    CarrierProfileBad,     // T4：运营商画像差 + 对端同意
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，state.rs:24-34；00 §4：T1-T4，任一满足即启动 TCP simultaneous open）

| 方法 | 签名（照抄） | 含义 |
|---|---|---|
| 允许打洞 | `pub fn can_punch(&self) -> bool` | `Negotiating \| Preprobe \| RoomLookup` 三态返回 true |
| 链路丢失 | `pub fn on_link_lost() -> PunchState` | 关联函数（无 self），恒返回 `Punching`（重打洞环：lost → Punching → yield） |
| 全失败 | `pub fn on_all_failed() -> PunchState` | 关联函数（无 self），恒返回 `DeadEnd`（04 D5 评分 ≥70） |

#### 算法细节

- 状态机转移中枢尚未在 crate 内闭环：`impl PunchState` 块头注释明示"实现阶段补全：由引擎任务驱动，双模定时器内嵌"（state.rs:36）。
- `on_link_lost` / `on_all_failed` 是**无 self 的关联函数**（不接受当前状态、恒返回固定值），调用方需自行匹配当前状态后调用；这与典型状态机 `fn(self) -> Self` 签名不同。代码如此，意图待确认。
- `#[non_exhaustive]`：允许未来增补状态而不破坏下游匹配。

#### 常量数值

无（无关联常量；T1–T4 为枚举变体而非数值）。

#### 测试用例

无（state.rs 不含测试模块）。

---

### 3.6 `stepmodel.rs` — 端口步长学习模型

**文件路径**：`kernel/wgp-punch/src/stepmodel.rs`
**一句话职责**：03 §3.4 的代码化——由 3 次 STUN 观测学习 NAT 端口分配步长，建立预测窗口；实测依据为"电信/移动 CGNAT 均为按目标分区 + 区内顺序推步"（nat/ 报告）。

#### 类型与函数

```rust
pub enum Trend {
    Increasing,   // 全部 delta > 0
    Decreasing,   // 全部 delta < 0
    Oscillating,  // 有正有负
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，stepmodel.rs:5-10）

```rust
pub struct PortStepModel {
    pub last_port: u16,        // 最近一次公网端口
    pub mean_delta: f64,       // 平均步长
    pub delta_range: (i32, i32),// (最小 delta, 最大 delta)
    pub trend: Trend,
    pub confidence: f64,       // 0.0 – 1.0
}
```
（`#[derive(Debug, Clone)]`，stepmodel.rs:13-20；字段全 pub）

```rust
pub struct PredictWindow {
    pub center: u16,        // 预测中心端口
    pub half_width: u16,    // 半窗宽
    pub confidence: f64,
}
```
（`#[derive(Debug, Clone, Copy)]`，stepmodel.rs:23-28）

| 方法 | 签名（照抄） | 含义 |
|---|---|---|
| 学习 | `pub fn learn(probes: &[(u16, u16)]) -> Option<Self>` | 从有序观测 `(local_port, public_port)` 建立模型；**少于 3 个观测返回 None**（退化为宽泛探测 ±3000 大撒网） |
| 预测 | `pub fn predict_window(&self, rounds_ahead: f64) -> PredictWindow` | 预测 rounds_ahead 轮后的端口窗口 |
| 可靠性 | `pub fn is_reliable(&self) -> bool` | `confidence >= 0.5` |
| 心跳校准 | `pub fn update_with_heartbeat(&mut self, cur_port: u16, prev_port: Option<u16>) -> bool` | 用心跳观测的 `cur_port - prev_port` 持续校准；返回 true 表示检测到端口突变 |

#### 算法细节

**`learn`（stepmodel.rs:32-69）**：
1. 观测数 `< 3` → `None`；
2. `deltas[i] = probes[i+1].1 - probes[i].1`（相邻公网端口差，`windows(2)`）；
3. `mean_delta = deltas 均值`；`delta_range = (min, max)`；
4. **trend 判定**：`min_delta > 0` → `Increasing`；`max_delta < 0` → `Decreasing`；否则 `Oscillating`；
5. **置信度公式**：`confidence = 1.0 / (1.0 + variance / 100.0)`，其中 `variance = deltas 的总体方差（除以 n）`。方差 0 → confidence 1.0；方差 100 → 0.5；方差 900 → 0.1。（除数 100 的标定依据代码未注明——代码如此，意图待确认）
6. `last_port = 最后一个观测的 public_port`。

**`predict_window`（stepmodel.rs:72-83）**：
- `span = |delta_range.1 - delta_range.0|`；
- `safety = 1.0 + span / 1000.0`（步长波动越大安全系数越大）；
- `center = round(last_port + mean_delta × rounds_ahead × safety)`，clamp 到 `[1024, 65535]`；
- `half_width = (50.0 × safety) as u16`；
- `confidence` 透传模型置信度。
- 注释指明这是"00/03 §3.4.4 分层策略"：步长波动越大窗口越宽。
- 注意：wave.rs 的 `plan_waves` 只用了 `predict_window(1.0).center`，`half_width` 未被子模块消费（窗口宽度由 plan_waves 按置信度分档硬编码，见 3.8）。代码如此，意图待确认。

**`update_with_heartbeat`（stepmodel.rs:91-107）**：
1. `prev_port = None`（首次）→ 仅更新 `last_port`，返回 false；
2. `delta = cur_port - prev_port`；`expected_max = max(|delta_range.0|, |delta_range.1|) × 3`；
3. `|delta| > expected_max` → **端口突变：`confidence = 0.0`，返回 true**（注释：连续 3 次 → confidence 归零 → 触发 STUN 重新学习；"连续 3 次"的计数由引擎侧/`HeartbeatLoop::on_anomaly` 配合完成，本函数单次即置零）；
4. 否则更新 `last_port = cur_port`，并扩张 `delta_range = (min(mn, delta), max(mx, delta))`，返回 false。

#### 常量数值（stepmodel.rs 硬编码）

| 常量 | 数值 | 位置 | 含义 |
|---|---|---|---|
| 最少观测数 | 3 | stepmodel.rs:33 | 少于 3 个观测不建模型 |
| 置信度除数 | 100.0 | stepmodel.rs:60 | `1/(1+variance/100)` |
| 可靠阈值 | 0.5 | stepmodel.rs:87 | `is_reliable` 下限 |
| 安全系数基数 | 1.0 + span/1000 | stepmodel.rs:74 | 窗口随波动展宽 |
| 基础半窗 | 50 | stepmodel.rs:80 | `50 × safety` |
| 端口 clamp 范围 | 1024 – 65535 | stepmodel.rs:77 | 预测中心钳制 |
| 突变阈值 | 3 × max\|delta_range\| | stepmodel.rs:97 | 心跳 delta 超限判突变 |

#### 测试用例

无（stepmodel.rs 不含测试模块；`PortStepModel` 的构造由 wave.rs 测试的 `model()` 辅助函数以字面量方式覆盖）。

---

### 3.7 `timer.rs` — 双模定时器

**文件路径**：`kernel/wgp-punch/src/timer.rs`
**一句话职责**：03 §3.3.5 的代码化——管理"何时点火"的语义与时序纪律（deadline 判定、模式切换、漂移校准），不负责真实时钟精度。

#### 类型与函数

```rust
pub enum TimerMode {
    Normal,     // 常规调度（心跳/保活/超时），tokio 默认精度即可
    Precision,  // 打洞窗口期高精度（探测波形启用），内核强制小数 ms 抖动收紧
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，timer.rs:11-15；`Default = Normal`，timer.rs:17-21）

```rust
pub struct DualModeTimer {
    mode: TimerMode,
    shift_ms: i64,   // 校准偏移：Precision 模式核 align_shift 前的提前量回补
}
```
（timer.rs:24-28；字段私有）

| 方法 | 签名（照抄） | 含义 |
|---|---|---|
| 构造 | `pub fn new() -> Self` | 初始 `Normal`、`shift_ms = 0` |
| 切模 | `pub fn set_mode(&mut self, mode: TimerMode)` | 模式切换（Precision 仅限打洞窗口，窗口结束必须回落） |
| 查询模式 | `pub fn mode(&self) -> TimerMode` | 当前模式 |
| 漂移校准 | `pub fn apply_shift(&mut self, shift_ms: i64)` | 注入双端测得的单向漂移（引擎换算后调用） |
| 到点判定 | `pub fn fired(&self, deadline_ms: i64, now_ms: i64) -> bool` | 无偏 deadline 已到？ |
| 剩余时间 | `pub fn remaining(&self, deadline_ms: i64, now_ms: i64) -> i64` | 距下次点火毫秒数（≤0 = 已到） |

#### 算法细节

**`fired`（timer.rs:54-58）**：
```
now_ms >= deadline_ms + shift_ms - slack
```
- `slack = if mode == Precision { 2 } else { 0 }`——Precision 模式允许提前 ≤2ms 视为已到（内核级抖动收紧）；Normal 模式严格不提前。
- 时间均为"相对时刻毫秒（引擎单调时钟锚点换算后）"。

**`remaining`（timer.rs:61-63）**：`deadline_ms + shift_ms - now_ms`，可为负（已过期）。注意 `remaining` 不像 `fired` 那样考虑 Precision 的 2ms slack——代码如此，意图待确认。

**v1 边界（模块头注释 timer.rs:5-9，如实转录）**：本模块只管"何时点火"的语义与时序纪律；真实时钟精度由 tokio 提供；Windows 基础定时器分辨率 15.6ms 的问题在生产阶段以 `timeBeginPeriod`/Priority 提升解决（列入部署清单真机验证前置项）。

#### 常量数值

| 常量 | 数值 | 位置 | 含义 |
|---|---|---|---|
| Precision 提前 slack | 2 ms | timer.rs:56 | Precision 模式允许的提前点火量 |

#### 测试用例（timer.rs:66-101，共 4 个）

| # | 测试名 | 验证点 |
|---|---|---|
| 1 | `normal_fires_on_or_after_deadline` | Normal 模式：999 不点、1000 恰好即点、1001 更点 |
| 2 | `precision_allows_2ms_lead` | Precision 模式：提前 3ms（997）不点；提前 2ms（998）视为已到；1005 点 |
| 3 | `shift_is_applied` | `apply_shift(-50)` 后 deadline 提前 50ms：949 不点、950 点 |
| 4 | `remaining_respects_shift` | `apply_shift(30)`：`remaining(1000,950)==80`、`remaining(1000,1050)==-20` |

---

### 3.8 `wave.rs` — 三波探测计划生成器

**文件路径**：`kernel/wgp-punch/src/wave.rs`
**一句话职责**：03 §3.5 的代码化——按模型置信度生成 21+15+11 三波探测计划；纯逻辑、无 IO、零第三方依赖，由调度器调用，发包执行与预算扣减在外层。

#### 类型与函数

```rust
pub const BROAD_NET_PACKETS: u16 = WAVE1_PACKETS + WAVE2_PACKETS; // 21+15=36
```
（wave.rs:8；"无数据"模式的撒网包数）

```rust
pub enum Confidence {
    High,    // 高置信（≥0.85）：±50 精准窗口，21+15，无第三波
    Medium,  // 中置信（0.5-0.85）：±400，21+15+11
    Low,     // 低置信（<0.5 有模型）/无数据：±3000 或全撒网
}
```
（`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`，wave.rs:11-19）

```rust
impl From<Option<&PortStepModel>> for Confidence {
    fn from(model: Option<&PortStepModel>) -> Self {
        match model {
            None => Confidence::Low,
            Some(m) if m.confidence >= 0.85 => Confidence::High,
            Some(m) if m.confidence >= 0.5 => Confidence::Medium,
            Some(_) => Confidence::Low,
        }
    }
}
```
（wave.rs:21-30）

```rust
pub struct WavePlan {
    pub wave1: Vec<u16>,
    pub wave2: Vec<u16>,
    pub wave3: Vec<u16>,
}
```
（`#[derive(Debug, Clone)]`，wave.rs:33-38；发送顺序 wave1 → wave2 → wave3，波内按序）

```rust
pub struct XorShift64(pub u64);
```
（wave.rs:47；xorshift64 确定性伪随机，避免引入第三方 RNG）

| 方法 / 函数 | 签名（照抄） | 含义 |
|---|---|---|
| `WavePlan::total` | `pub fn total(&self) -> u16` | 三波包数合计 |
| `XorShift64::next` | `pub fn next(&mut self) -> u64` | 一步 xorshift64（`x^=x<<13; x^=x>>7; x^=x<<17`），wave.rs:50-57 |
| `XorShift64::range_u16` | `pub fn range_u16(&mut self, lo: u16, hi: u16) -> u16` | `[lo, hi]` 内均匀整数（取模法），wave.rs:60-63 |
| 计划生成 | `pub fn plan_waves(model: Option<&PortStepModel>, seed: u64, packet_cap: u16) -> WavePlan` | 主入口：按置信度生成三波端口列表 |

私有辅助（wave.rs:66-83, 166-176）：
```rust
fn clamp_port(p: i64) -> u16 { p.clamp(1024, 65535) as u16 }
fn sample_window(rng: &mut XorShift64, center: i64, half: i64, n: u16) -> Vec<u16>
fn sample_window_trunc(rng: &mut XorShift64, center: i64, negative_half: i64, n: u16) -> Vec<u16>
```
- `sample_window`：在 `[center-half, center+half]` 内均匀取 n 个端口（lo 下限 1024、hi 上限 65535；`lo >= hi` 退化返回 clamp 后的 center）。注释：确定性伪随机，"避开外层包序聚簇"。
- `sample_window_trunc`：half 传负值即向 center 以下覆盖（`lo = center + negative_half`，`hi = center`，同样 clamp 1024）；`lo >= hi` 时全部返回 hi。
- 两者均**不保证去重**（独立随机采样，可能重复端口）。代码如此，意图待确认。

#### 算法细节

**`plan_waves` 主流程**（wave.rs:88-163）：
1. `conf = Confidence::from(model)`；
2. `max_total = min(packet_cap, 21+15+11=47)`——**预算裁剪在此发生，顺序裁剪 wave1 → wave2 → wave3，先保精准波**；
3. `rng = XorShift64(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))`（黄金比例常数混种）；
4. `center = model.predict_window(1.0).center`（无模型时为 0，仅 Low(None) 分支不使用它）。

**四个分支与窗口宽度表**：

| 分支 | wave1 | wave2 | wave3 | 合计 |
|---|---|---|---|---|
| **High**（conf ≥0.85） | 21 包：**首包必打预测中心**（`vec![clamp_port(center)]`，最大似然端口）+ 其余在 **±50** 内随机采样 | 15 包：`sample_window_trunc(center, -500)`（center 以下 500 覆盖） | 空 | 36 |
| **Medium**（0.5 ≤ conf <0.85） | 21 包：±400 内采样 | 15 包：-500 覆盖 | 11 包：±3000 内采样 | 47 |
| **Low 有模型**（conf <0.5） | 21 包：±3000 内采样 | 15 包：-500 覆盖 | 剩余全部：±3000 内采样（cap=47 时为 11） | 47 |
| **Low 无模型**（model=None） | 空 | 空 | **36 包**：`sample_window(rng, 32768, 31744)` | 36 |

各分支细节：
- High 分支 wave2 数量为 `WAVE2_PACKETS.min(remaining)`，`remaining = max_total - wave1.len()`；cap=47 时 wave1=21、wave2=15。
- Medium 分支 wave3：`if remaining >= WAVE3_PACKETS { 11 } else { remaining }`（等价 `min(11, remaining)`）。
- **无数据模式**（wave.rs:151-158）：注释称"36 包全范围撒网（03 §3.5.2'无数据'行：无一二波）"；实际窗口 `lo = max(1024, 32768-31744) = 1024`、`hi = min(65535, 32768+31744) = 64512`，即实际撒网范围为 **[1024, 64512]**，并非完整 [1024, 65535]。代码如此，意图待确认。
- 当 `packet_cap` 很小（如 10）时：High 分支 `n = min(21, 10) = 10`，wave1 = 1 + 9 = 10 包，其后全空（测试 `budget_cap_truncates_in_order` 验证）。
- **边界情况**：`packet_cap = 0` 时 High 分支 `n=0`，`n.saturating_sub(1)=0`，wave1 仍含 `vec![clamp_port(center)]` 共 1 包，超过 cap=0。代码如此，意图待确认。

#### 常量数值（wave.rs 及被引用者）

| 常量 | 数值 | 含义 |
|---|---|---|
| `BROAD_NET_PACKETS` | 36 (=21+15) | 无数据模式撒网包数 |
| `WAVE1_PACKETS` | 21 | 第一波包数 |
| `WAVE2_PACKETS` | 15 | 第二波包数 |
| `WAVE3_PACKETS` | 11 | 第三波包数 |
| 三波总计上限 | 47 | `max_total = min(cap, 47)` |
| High 窗口半宽 | ±50 | 精准窗口 |
| Medium/Low 波1窗口 | ±400 / ±3000 | 分档窗口 |
| 波2 负向窗口 | -500 | center 以下 500 |
| 波3 窗口 | ±3000 | 大撒网 |
| 无数据中心 / 半宽 | 32768 / 31744 | 全范围撒网中心与半宽 |
| 种子混种常数 | `0x9E37_79B9_7F4A_7C15` | 黄金比例（wrapping_add） |
| 端口 clamp 范围 | 1024 – 65535 | 所有窗口边界 |

#### 测试用例（wave.rs:178-237，共 5 个）

| # | 测试名 | 验证点 |
|---|---|---|
| 1 | `high_confidence_two_waves_36` | conf=0.92：wave1=21、wave2=15、wave3 空、total=36；所有端口 ∈ [1024, 65535] |
| 2 | `medium_confidence_three_waves_47` | conf=0.7：total=47、wave3=11 |
| 3 | `no_model_broad_net_36` | model=None：total=36，全部端口合法 |
| 4 | `budget_cap_truncates_in_order` | cap=10：wave1 被裁到 10，wave2/wave3 空（先保精准波） |
| 5 | `determinism_same_seed` | 同 seed（12345）两次生成三波完全一致（确定性伪随机） |

测试辅助 `fn model(conf: f64, last: u16) -> PortStepModel`（wave.rs:183-191）：以 `mean_delta=5.0, delta_range=(2,12), trend=Increasing` 构造模型，仅调 `confidence` 与 `last_port`。

---

## 4. 对外 API 汇总

### 4.1 crate 根再导出（`wgp_punch::…`，共 15 项）

| 导出名 | 类型 | 来源模块 |
|---|---|---|
| `BudgetScheduler` | struct | budget |
| `CarrierError` | struct | carrier |
| `MappingSemantics` | enum | carrier |
| `ProbeCarrier` | trait | carrier |
| `TransportCapability` | enum | carrier |
| `HbAction` | enum | heartbeat |
| `HeartbeatController` | struct | heartbeat |
| `HeartbeatLoop` | struct | heartbeat |
| `PunchState` | enum | state |
| `PortStepModel` | struct | stepmodel |
| `Trend` | enum | stepmodel |
| `DualModeTimer` | struct | timer |
| `TimerMode` | enum | timer |
| `plan_waves` | fn | wave |
| `Confidence` | enum | wave |
| `WavePlan` | struct | wave |
| `XorShift64` | struct | wave |

（注：`budget::BudgetError`、`stepmodel::PredictWindow`、`wave::BROAD_NET_PACKETS` **未**在 lib.rs 再导出，需经模块路径 `wgp_punch::budget::BudgetError` 等访问。）

### 4.2 关键签名速查

```rust
// budget
impl BudgetScheduler {
    pub fn new() -> Self;
    pub fn try_acquire(&mut self, n: u16) -> Result<(), BudgetError>;
    pub fn begin_round(&mut self);
    pub fn refill_window(&mut self);
    pub fn remaining(&self) -> (u16, u16);
}

// carrier
pub trait ProbeCarrier: Send + Sync {
    async fn send_probe(&self, dst: SocketAddr, payload: &[u8]) -> Result<(), CarrierError>;
    fn on_probe(&self, src: SocketAddr, payload: &[u8]) -> bool;
    fn mapping_semantics(&self) -> MappingSemantics;
    fn capability(&self) -> TransportCapability;
}

// heartbeat
impl HeartbeatController {
    pub fn new() -> Self;
    pub fn on_result(&mut self, success: bool);
    pub fn fast_recovery_interval(&self) -> Duration;
    pub fn next_interval(&self) -> Duration;
}
impl HeartbeatLoop {
    pub fn new() -> Self;
    pub fn tick(&mut self, now_ms: u64, budget_ok: bool) -> Option<HbAction>;
    pub fn on_result(&mut self, success: bool);
    pub fn on_anomaly(&mut self);
    pub fn on_resume(&mut self);
    pub fn current_interval_ms(&self) -> u64;
    pub fn reset(&mut self);
}

// state
impl PunchState {
    pub fn can_punch(&self) -> bool;
    pub fn on_link_lost() -> PunchState;
    pub fn on_all_failed() -> PunchState;
}

// stepmodel
impl PortStepModel {
    pub fn learn(probes: &[(u16, u16)]) -> Option<Self>;
    pub fn predict_window(&self, rounds_ahead: f64) -> PredictWindow;
    pub fn is_reliable(&self) -> bool;
    pub fn update_with_heartbeat(&mut self, cur_port: u16, prev_port: Option<u16>) -> bool;
}

// timer
impl DualModeTimer {
    pub fn new() -> Self;
    pub fn set_mode(&mut self, mode: TimerMode);
    pub fn mode(&self) -> TimerMode;
    pub fn apply_shift(&mut self, shift_ms: i64);
    pub fn fired(&self, deadline_ms: i64, now_ms: i64) -> bool;
    pub fn remaining(&self, deadline_ms: i64, now_ms: i64) -> i64;
}

// wave
pub fn plan_waves(model: Option<&PortStepModel>, seed: u64, packet_cap: u16) -> WavePlan;
impl WavePlan { pub fn total(&self) -> u16; }
impl XorShift64 {
    pub fn next(&mut self) -> u64;
    pub fn range_u16(&mut self, lo: u16, hi: u16) -> u16;
}
impl From<Option<&PortStepModel>> for Confidence { /* conf ≥0.85 High；≥0.5 Medium；其余 Low */ }
```

---

## 5. 与设计文档（03/04）的对应关系

下表按源码注释中的章节引用逐条对应（引用均来自各文件头注释或行内注释）：

| 代码元素 | 设计文档对应 | 对应内容 |
|---|---|---|
| 整个 crate 定位（lib.rs:1-2） | 03、04 文档总纲 | "折跃门打洞引擎（03/04 文档的代码化）" |
| H6 / 00 §3（lib.rs:2、budget.rs:1-2、heartbeat.rs:128） | docs/00 §3 | 调度器是内核唯一发包点；心跳与探测共用调度器配额 |
| 双闸门预算（budget.rs） | 03/00 §1 H6 | 轮预算 ≤47、滑动 10 分钟预算 ≤500；耗尽即触发 BudgetExhausted 事件 |
| `ProbeCarrier`（carrier.rs:1） | 00 D9、14 §8 | 底层多协议抽象；新增载体 = 新写实现，引擎零改动 |
| `TransportCapability`（carrier.rs:6） | 14 §8（能力位交换） | 能力位交换 + `LinkControl::advertise_transports` 的单元 |
| 保活唯一权在内核、外围零心跳（heartbeat.rs:8） | 00 §4 | NAT 保活心跳由内核负责 |
| `HeartbeatController` / `HeartbeatLoop`（heartbeat.rs:1-3） | 03 §3.7 / §3.8 | 成功率滑窗动态调间隔；tick 驱动纯逻辑可单测 |
| 扩展节奏每 10 次 1 次（heartbeat.rs:73） | 03 §3.7.4 | 步长校准扩展节奏 |
| 端口突变连续 3 次扩展（heartbeat.rs:75、154-157） | 03 §3.7.5 | 检测到端口突变的响应 |
| `update_with_heartbeat`（stepmodel.rs:90） | 03 §3.7.3 | cur_port − prev_port 持续校准步长模型 |
| 休眠恢复 3×100ms 快速心跳（heartbeat.rs:51、159-162） | 03 §3.8（注释"03 §3.7/§3.8 代码化"） | 设备休眠/网络切换恢复重建映射 |
| `PortStepModel`（stepmodel.rs:1-2） | 03 §3.4 | 3 次 STUN 学习建立预测窗口 |
| 置信度公式 / trend 判定（stepmodel.rs） | 03 §3.4（nat/ 实测报告） | 电信/移动 CGNAT"按目标分区 + 区内顺序推步" |
| 分层策略 `predict_window`（stepmodel.rs:71） | 00/03 §3.4.4 | 步长波动越大窗口越宽 |
| 三波 21+15+11（wave.rs:1） | 03 §3.5 | 三波探测计划，纯逻辑无 IO，由调度器调用 |
| 置信度分档表（wave.rs:10、High/Medium/Low） | 03 §3.5.2 | ≥0.85：±50，21+15 无第三波；0.5–0.85：±400，21+15+11；<0.5/无数据：±3000 或全撒网 |
| "无数据"行 36 包撒网（wave.rs:7、151） | 03 §3.5.2 | 无模型时无一二波，36 包全范围撒网 |
| `DualModeTimer`（timer.rs:1） | 03 §3.3.5 | 双模定时器：Normal 常规 / Precision 打洞窗口期高精度 |
| Precision 2ms 抖动收紧（timer.rs:55-56） | 03 §3.3.5（"内核强制小数 ms 抖动收紧"） | Precision 允许提前 ≤2ms |
| Windows 15.6ms 定时器精度（timer.rs:6-9） | 部署清单（生产阶段） | timeBeginPeriod/Priority 提升，真机验证前置项 |
| `PunchState` 状态机（state.rs:1） | 00 §4 | Idle → … → Connected；失败 → ICMP 逃生 → 死局 |
| 15 全链路 Phase 3-8 状态化（state.rs:3、各状态注释） | docs/15 全链路流程 | Preprobe/RoomLookup/Negotiating/Punching/Connected 各阶段 |
| `DeadEnd` + 04 D5 评分 ≥70（state.rs:19、52） | docs/04 D5 | 全灭 + ICMP 逃生失败死局判定，附诊断报告 |
| `TcpFallbackTrigger` T1–T4（state.rs:23-24） | 00 §4 | 任一满足即启动 TCP simultaneous open（UDP 预检失败 / 三波全灭 / QUIC 握手超时 / 运营商画像差+对端同意） |
| `WAVE_TIMEOUT_MS=800`（wgp-proto consts.rs:17） | 03 §3.5 | 波间超时约定；**本 crate 未引用**（应在引擎/调度器层消费），见 §6 |

---

## 6. 已知限制或未实现项

以下均为源码中如实存在的未闭环点（按代码注释或代码结构归纳，不含推测性内容）：

1. **窗口预算回填未接定时器**：`BudgetScheduler::refill_window()` 注释明示"由时间驱动；实现阶段接入引擎定时器，每 10 分钟滑动回填"（budget.rs:47）。当前 crate 内无任何时间驱动调用点。
2. **状态机转移中枢未闭环**：state.rs:36 注释"实现阶段补全：由引擎任务驱动，双模定时器内嵌"；`PunchState` 仅有 `can_punch` / `on_link_lost` / `on_all_failed` 三个辅助方法，且 `on_link_lost` / `on_all_failed` 是无 self 的关联函数（不接受当前状态、恒返回固定值），不能独立构成完整状态转移函数。
3. **定时器精度依赖外部**：timer.rs:5-9 自述 v1 边界——只管"何时点火"语义，真实时钟精度由 tokio 提供；Windows 基础定时器 15.6ms 分辨率问题需在生产阶段以 timeBeginPeriod/Priority 解决，且列入"部署清单真机验证前置项"。
4. **无具体载体实现**：carrier.rs 只定义 trait；`UdpProbeCarrier` 等实现位于外层（wave.rs:1-2 注释提及"发包执行与预算扣减在外层 UdpProbeCarrier/引擎"），本 crate 内不存在任何 `impl ProbeCarrier`。
5. **`WAVE_TIMEOUT_MS`（800ms）未被本 crate 使用**：定义于 wgp-proto/src/consts.rs:17（03 §3.5 波间超时），wgp-punch 无引用；波间等待逻辑应在引擎/调度器层。
6. **`fast_recovery_interval()` 与 tick 内硬编码脱节**：`HeartbeatController::fast_recovery_interval()` 返回 100ms，但 `HeartbeatLoop::tick` 恢复期间隔是硬编码字面量 `100`（heartbeat.rs:108），两者无数值关联。代码如此，意图待确认。
7. **`PredictWindow.half_width` 无消费者**：`predict_window` 计算了 `half_width`，但 wave.rs 的 `plan_waves` 仅取 `.center`，窗口宽度按置信度分档硬编码（50/400/3000）。代码如此，意图待确认。
8. **端口采样不保证去重**：`sample_window` / `sample_window_trunc` 为独立随机采样，同一波内可能产生重复端口（无 dedup 逻辑）。代码如此，意图待确认。
9. **无数据模式窗口非完整端口域**：注释称"全范围撒网"，实际窗口为 [1024, 64512]（center=32768、half=31744，上界 64512 < 65535）。代码如此，意图待确认。
10. **`packet_cap = 0` 边界**：High 分支仍会产出含 1 包（预测中心）的 wave1，超出 cap=0 的预算裁剪预期。代码如此，意图待确认。
11. **置信度公式标定依据缺失**：`confidence = 1.0 / (1.0 + variance / 100.0)`（stepmodel.rs:60）中除数 100.0 无注释说明标定来源。代码如此，意图待确认。
12. **budget/state/stepmodel/carrier 四个模块无单元测试**：仅 heartbeat（5 个）、timer（4 个）、wave（5 个）含测试，共 14 个测试用例。
13. **突变置零的计数口径**：`update_with_heartbeat` 单次超限即 `confidence = 0.0`，注释描述为"连续 3 次 → confidence 归零"；"连续 3 次"的计数由调用方（引擎/`HeartbeatLoop::on_anomaly`）负责，函数本身不判断连续性。代码如此，意图待确认。

---

*本文档由通读全部 8 个源文件（含 `#[cfg(test)]` 测试模块）后编写；所有签名、常量数值均与源码逐一核对，其中 wgp-proto 常量（47/500/21/15/11/800）经 `wgp-proto/src/consts.rs` 原文确认。*
