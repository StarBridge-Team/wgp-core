# wgp-dht 信令面详细文档

> **源目录**：`kernel/wgp-dht/`（9 个源文件：lib.rs / id.rs / kbucket.rs / node.rs / observe.rs / room.rs / runtime.rs / advertise.rs / net_test.rs）
> **生成日期**：2026-11-05
> **对应设计文档**：`docs/07-信令面与观察者协议.md`
> **crate 描述**（Cargo.toml）：折跃门去中心化信令面：Kademlia 变种、房间键、租约/继位链、观察者协议

---

## 1. Crate 概览

### 1.1 定位

wgp-dht 是折跃门（wgp）纯 P2P 零中继 NAT 打洞组网架构中的**信令面**实现，对应分层 `wgp-proto → wgp-crypto → wgp-punch / wgp-dht（信令面）→ wgp-core` 中的第三层。

- **自研 Kademlia 变种**：`NodeId = SHA-256(ed25519 公钥)`，XOR 距离度量，256 个 k-bucket（K=20）。
- **零中继定位**：Forward 走"不可信即可用"的邮件语义（fire-and-forget），转发者只按地址簿中转 UDP 字节，不做身份学习、不做 ACK。
- **唯一基础设施**：公网 wgp-node 种子（地址由外围配置注入，协议层不持有默认种子）。
- 库首页注释（lib.rs:1-2）：

  ```rust
  //! 折跃门去中心化信令面（07 文档的代码化）。
  //! 自研 Kademlia 变种；唯一基础设施是公网 wgp-node 种子（地址由外围配置注入）。
  ```

### 1.2 依赖（Cargo.toml）

| 依赖 | 用途 |
|------|------|
| `wgp-proto`（path） | 协议常量（LEASE_*/ROOM_KEY_DOMAIN）、DHT RPC 报文编解码、STUN 最小子集、SeedAdvertise 线格式 |
| `ed25519-dalek`（workspace） | 节点长期身份签名/验签、NodeId 身份绑定校验 |
| `rand_core`（workspace） | `CryptoRngCore`（身份生成的 RNG 抽象）、测试用 `OsRng` |
| `sha2`（workspace） | NodeId = SHA256(pubkey)、room_key = SHA256(domain||房码) |
| `tokio`（workspace） | UDP/TCP 异步 IO、Mutex/watch/mpsc/oneshot、超时与任务派生 |

dev-dependencies：`wgp-crypto`（net_test.rs 中做承诺-揭示端到端密码学验证用）。

> 代码如此：Cargo.toml 未列 `thiserror` 等，错误类型全部手写 enum；未引入 serde/protobuf（与 00 §3 定长二进制纪律一致）。

---

## 2. 模块结构总表

| 文件 | 职责 | 关键导出 |
|------|------|----------|
| `lib.rs` | crate 根：模块声明 + 对外再导出 | 见 §4 全量清单 |
| `id.rs` | 节点身份：ed25519 长期身份、NodeId 派生、PeerId 截断 | `NodeId`、`NodeIdentity`、`node_id_from_verifying`、`peer_id_from_node` |
| `kbucket.rs` | Kademlia 路由表骨架：256 桶、XOR 分桶、K 上限 | `RoutingTable`、`KBucket`、`K` |
| `node.rs` | DHT 网络栈运行时：UDP/TCP RPC、地址簿、KV、会话分派、中继策略 | `DhtNode`、`RpcError`、`PongInfo`、`RelayPolicy` |
| `observe.rs` | 观察者 / STUN 响应器：Binding 应答 + WGP-PEER 回显 + IP 键控限频 | `ObserverServer`、`ObserverPolicy`、`try_answer_stun`、`OBSERVER_RATE_LIMIT`、`OBSERVER_RATE_WINDOW` |
| `room.rs` | 房间键、锚点租约、房间记录签名/继位链 | `room_key`、`Lease`、`RoomRecord`、`sign_room`、`verify_room`、`succession_line`、`old_link_grace_s` |
| `runtime.rs` | 房间生命周期运行时：创建/加入/续期/继位/upkeep | `RoomRuntime`、`RoomError`、`JoinRequest` |
| `advertise.rs` | SeedAdvertise 种子广告签名/验签 | `sign_advertise`、`verify_advertise` |
| `net_test.rs` | DhtNode 网络层集成测试（loopback 三节点拓扑） | 仅 `#[cfg(test)]`，无对外导出 |

---

## 3. 逐文件详细文档

### 3.1 `kernel/wgp-dht/src/lib.rs`

**一句话职责**：crate 根，声明 8 个公开模块 + 1 个测试模块，并把核心类型再导出到 crate 根。

**模块声明**（照抄）：

```rust
pub mod advertise;
pub mod id;
pub mod kbucket;
#[cfg(test)]
mod net_test;
pub mod node;
pub mod observe;
pub mod room;
pub mod runtime;
```

**pub use 全量清单**（见 §4）。

无测试。

---

### 3.2 `kernel/wgp-dht/src/id.rs`

**一句话职责**：DHT 节点身份层——ed25519 长期身份生成/持久化，NodeId = SHA256(pubkey) 身份绑定，PeerId 短标识截断（07 §8：防日蚀/防冒充）。

#### 常量

无模块级常量。

#### 类型

**`pub struct NodeId(pub [u8; 32])`** —— 节点 ID，公钥的 SHA-256（Kademlia 距离度量基）。

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);
```

> `Ord` 派生（确定字节序）是继位链排序（room.rs `succession_line`）的基础。

方法：

```rust
pub fn xor_distance(&self, other: &NodeId) -> [u8; 32]
```

- Kademlia XOR 距离：逐字节异或，32B 大端距离值。

**`pub struct NodeIdentity`** —— 节点长期身份（生成一次持久化；PeerId 派生自本公钥哈希）。

```rust
pub struct NodeIdentity {
    signing: SigningKey,
    node_id: NodeId,
}
```

方法（签名照抄）：

```rust
pub fn generate(rng: &mut impl CryptoRngCore) -> Self
pub fn from_seed(seed: [u8; 32]) -> Self
pub fn to_seed(&self) -> [u8; 32]
pub fn node_id(&self) -> NodeId
pub fn verifying_key(&self) -> VerifyingKey
pub fn sign(&self, data: &[u8]) -> Signature
pub fn verify(&self, data: &[u8], sig: &Signature) -> bool
```

- `generate`：`SigningKey::generate(rng)` 后立即派生 node_id。
- `from_seed`：从持久化种子恢复（32B ed25519 种子；注释"文件读满即用"）。
- `to_seed`：导出种子（注释说明写入 `node_identity.key`，权限 600——文件落盘由外围负责，本 crate 不含文件 IO）。
- `sign`/`verify`：ed25519 原语直通。注释明确"锚点租约续期、成员表、SeedAdvertise 均须签名"。

#### 自由函数

```rust
pub fn node_id_from_verifying(vk: &VerifyingKey) -> NodeId
pub fn peer_id_from_node(node_id: &NodeId) -> [u8; 16]
```

- `node_id_from_verifying`：`NodeId(Sha256::digest(vk.as_bytes()).into())`——身份绑定的核心定义。
- `peer_id_from_node`：截断 NodeId 前 16B 作为对外短标识（注释："防冲突校验在 12 §5"）。

#### 关键机制

- **身份绑定**：NodeId 不是随机数，而是公钥哈希。任何声称 node_id 的消息必须同时出示公钥，且 node_id == SHA256(pubkey)，否则伪造者需为任意 node_id 找 SHA-256 原像（计算上不可行）。校验入口在 node.rs `verified_identity`（见 3.4）。

#### 测试用例

无（本文件无 `#[cfg(test)]` 模块；相关测试分布在 node.rs / advertise.rs）。

---

### 3.3 `kernel/wgp-dht/src/kbucket.rs`

**一句话职责**：Kademlia 路由表骨架——以本节点 ID 为原点按 XOR 距离分 256 桶，桶容量 K=20，满桶拒入。

> 文件头注释自述："实现阶段补全：k-bucket 分裂、维护、SeedAdvertise 交换"——即当前为骨架版，无桶分裂/刷新/逐出逻辑。

#### 常量

```rust
pub const K: usize = 20;
```

注释："Kademlia 桶容量（标准 K=20；全表上限 256*K，杜绝无界内存增长）"。

#### 类型

**`pub struct KBucket`** —— 单桶，仅保留节点 ID 列表：

```rust
pub struct KBucket {
    pub nodes: Vec<NodeId>,
}

impl KBucket {
    pub fn new() -> Self { Self { nodes: Vec::new() } }
}
```

**`pub struct RoutingTable`** —— 路由表：

```rust
pub struct RoutingTable {
    home: NodeId,
    buckets: Vec<KBucket>,
}
```

方法（签名照抄）：

```rust
pub fn new(home: NodeId) -> Self
pub fn bucket_index(&self, id: &NodeId) -> usize
pub fn insert(&mut self, id: NodeId)
pub fn closest_to(&self, target: &NodeId) -> Vec<NodeId>
```

- `new`：建表即分配 256 个空桶（`(0..256).map(|_| KBucket::new()).collect()`）。
- `bucket_index`：`home` 与 `id` 的 XOR 距离中**最高不同位的位序**（0 = 最高位）。逐字节找第一个非零字节，`i * 8 + leading_zeros`；全零（即 id == home）返回 0。
- `insert`：三条规则——
  1. 本节点不入自己路由表（`id == home` 直接 return）；
  2. 重复身份忽略（已认识者不重新占位）；
  3. **桶满拒入新客**：`len() >= K` 时直接 return。注释明确 v1 不做旧节点逐出："攻击者无法用洪流挤掉诚实节点；节点失联由上层 PING 超时清理路径兜底"。
- `closest_to`：全表摊平、按 XOR 距离排序、截断 K=20（注释："实现阶段：全表排序截断"）。

#### 线格式

无独立线格式（仅内存结构）。

#### 测试用例（5 个）

| 测试 | 验证点 |
|------|--------|
| `bucket_index_by_leading_bit` | home=全零：自身→0；0x01→桶 7；0x80→桶 0；第二字节 0x01→桶 15 |
| `closest_to_sorted_by_xor_distance` | 3 节点按 XOR 距离升序返回 |
| `closest_to_truncates_to_20` | 40 个已知节点截断为 20 |
| `insert_caps_bucket_at_k` | 40 个同桶节点只保留 K=20 |
| `insert_skips_self_and_duplicates` | 自身与重复身份不占位 |

---

### 3.4 `kernel/wgp-dht/src/node.rs`（核心文件，876 行）

**一句话职责**：Kademlia 网络栈运行时——UDP/TCP 双传输的 RPC 收发、地址簿与 KV 容量治理、会话分派、Forward 中转、身份绑定校验闸门。

文件头注释定义学习语义：

```rust
//! 学习语义：仅 PING/PONG 双向学习（sender_id ↔ src 入地址簿）；
//! Forward 不做身份学习（防垃圾投递毒化地址簿），fire-and-forget 邮件语义，
//! 上层信令自持超时重发（sig::Commit REQUIRE_ACK / 3s 超时）。
```

#### 3.4.1 常量（全部照抄）

| 常量 | 值 | 注释含义 |
|------|-----|----------|
| `MAX_TCP_FRAME` | `4096` | 单帧上限（DHT 包最大 ~1080B：STORE_VALUE_MAX 1024 + 头部开销） |
| `MAX_TCP_CONN` | `512` | TCP 信令并发连接上限（超限直接拒连） |
| `TCP_IDLE_TIMEOUT_S` | `30` | TCP 连接空闲超时（防慢连接长期占用名额） |
| `TCP_RPC_TIMEOUT_MS` | `1500` | TCP RPC 单次往返超时（与 UDP RPC 一致） |
| `MAX_UDP_DATAGRAM` | `2048` | UDP 读缓冲上限（RPC 最大 ~1130B：StoreBody 前缀 98 + 值 1024 + 头 7） |
| `ADDR_BOOK_MAX` | `4096` | 地址簿条目上限（防伪造身份洪流撑爆内存；超限触发过期清扫） |
| `ADDR_BOOK_TTL` | `Duration::from_secs(1800)` | 地址簿条目静默过期 30min（远超正常重 PING 周期；被清者下次 PING 即复原） |
| `KV_MAX_ENTRIES` | `4096` | KV 存储条目上限（房间记录宿主；超限先清最旧腾位） |
| `INBOX_CAP` | `512` | 默认收件队列容量 |

另：UDP RPC 超时在代码内联为 `Duration::from_millis(1500)`（ping/find_node/store/find_value 一致）；`type KvEntry = (Vec<u8>, Instant);`（KV 条目写入时间戳）。

#### 3.4.2 公开类型

**`pub enum RpcError`** —— RPC 超时/失败：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    Timeout,
    NoRoute,
    PayloadTooLarge,
}
```

**`pub struct PongInfo`** —— PONG 应答信息（ping 的返回值：对方身份 + 返回地址）：

```rust
#[derive(Debug, Clone, Copy)]
pub struct PongInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
}
```

**`pub enum RelayPolicy`** —— 中继策略（07 §6 贡献模式：家庭带宽节点拒绝 Forward 中转——注释："中转是唯一可能产生持续流量进而被运营商判 PCDN 的路径"）：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicy {
    /// 完整节点：允许中转
    Allow,
    /// 贡献模式：只收发自己的消息，不做中转
    Deny,
}
```

**私有类型**（记录以完整理解状态机）：

```rust
enum Sink {
    Udp(SocketAddr),
    Tcp(mpsc::UnboundedSender<Vec<u8>>),
}

enum Pending {
    Pong(oneshot::Sender<PongInfo>),
    Neighbors(oneshot::Sender<Vec<NodeEntry>>),
    Value(oneshot::Sender<ValueBody>),
    StoreAck(oneshot::Sender<()>),
}
```

`Sink` 注释是关键设计说明："TCP 连接携带的源 IP:port 与 UDP NAT 映射**无关**（TCP 源端口 ≠ UDP 源端口），若把 TCP 源地址写进地址簿，会把 Forward 中转指向错误的 UDP 端口。因此 TCP 入站只入路由表（身份存在性），绝不写地址簿。"

#### 3.4.3 `pub struct DhtNode`（字段全列）

```rust
pub struct DhtNode {
    socket: Arc<UdpSocket>,
    identity: Arc<NodeIdentity>,
    routing: Mutex<RoutingTable>,
    /// 已知 UDP 端点（带最后见时刻；容量上限 + 过期清扫，防伪造洪流撑爆）
    addr_book: Mutex<HashMap<NodeId, (SocketAddr, Instant)>>,
    /// KV 存储（带写入时刻；条目数上限 + 最旧淘汰，防无界内存增长）
    kv: Mutex<HashMap<[u8; 32], KvEntry>>,
    txid: AtomicU32,
    pending: Mutex<HashMap<u32, Pending>>,
    /// 会话分派表：payload 首 4B session_tag → 会话处理队列
    /// （装配线协商消息按 tag 分流；tag=0 / 未注册 → 默认队列，房间管理用）
    sessions: Mutex<HashMap<u32, mpsc::UnboundedSender<ForwardBody>>>,
    /// 默认收件队列（有界：forward 洪流在队满时静默丢弃，符合邮件语义）
    inbox_tx: mpsc::Sender<ForwardBody>,
    inbox_rx: Mutex<mpsc::Receiver<ForwardBody>>,
    /// 中继开关（默认 Allow；贡献模式置 Deny）
    relay_allow: AtomicBool,
}
```

#### 3.4.4 方法（签名照抄）

构造与基础访问：

```rust
pub async fn bind(identity: NodeIdentity, local: SocketAddr) -> std::io::Result<Arc<Self>>
pub fn node_id(&self) -> NodeId
pub fn identity(&self) -> Arc<NodeIdentity>
pub fn local_addr(&self) -> std::io::Result<SocketAddr>
```

- `bind`：绑 UDP socket，初始化路由表（home = 自身 node_id）/地址簿/KV/会话表，**随即派生读循环任务**（`tokio::spawn`）：每包先试 `RpcPacket::decode`，是 RPC 则 `dispatch(pkt, Sink::Udp(src))`；否则试 `observe::try_answer_stun`，命中则以同 socket 回包（"同 socket 3478 场景"）。

UDP RPC 客户端原语（全部 1500ms 超时 + txid 匹配 + 超时后清理 pending）：

```rust
pub async fn ping(&self, dest: SocketAddr) -> Result<PongInfo, RpcError>
pub async fn find_node(&self, dest: SocketAddr, target: NodeId) -> Result<Vec<NodeEntry>, RpcError>
pub async fn forward_to(&self, route: SocketAddr, target: NodeId, payload: Vec<u8>) -> Result<(), RpcError>
pub async fn recv_forward(&self) -> Option<ForwardBody>
pub async fn try_recv_forward(&self) -> Option<ForwardBody>
pub async fn register_session(&self, tag: u32) -> mpsc::UnboundedReceiver<ForwardBody>
pub async fn unregister_session(&self, tag: u32)
pub async fn set_relay_policy(&self, policy: RelayPolicy)
pub fn relay_policy(&self) -> RelayPolicy
pub async fn store(&self, dest: SocketAddr, key: [u8; 32], value: Vec<u8>) -> Result<(), RpcError>
pub async fn find_value(&self, dest: SocketAddr, key: [u8; 32]) -> Result<ValueBody, RpcError>
pub async fn known_nodes(&self) -> Vec<(NodeId, SocketAddr)>
```

- `ping`：发送 `PingBody { node_id, pubkey }`（身份发布），等 `Pending::Pong`。
- `forward_to`：payload > `FORWARD_PAYLOAD_MAX`(600) 直接 `PayloadTooLarge`；fire-and-forget 只发不等（注释："上层信令自持超时重发"）。
- `register_session(tag)`：注册后 payload 首 4B == tag 的 forward 投递至该会话队列；注释"tag=0 保留给房间管理默认队列"。
- `try_recv_forward`：非阻塞收取（upkeep 循环轮询用）。

私有内部方法：

```rust
fn next_txid(&self) -> u32                                    // fetch_add(1, Relaxed) + 1，从 1 起
async fn learn_incoming(&self, id: NodeId, sink: &Sink)       // 学习：路由表必入；地址簿仅 UDP
async fn answer_neighbors(&self, target: NodeId, sink: &Sink, txid: u32)
async fn sink_send(&self, sink: &Sink, bytes: Vec<u8>)
async fn dispatch(&self, pkt: RpcPacket, sink: Sink)
```

- `answer_neighbors`：本路由表 `closest_to(target)`（最多取 20）**与地址簿交集**，仅输出 IPv4 条目（v1 仅 IPv4；IPv6 注释"未来线"），组 `NeighborsBody` 回包。

TCP 信令面（帧格式 `[u16 BE 长度][RpcPacket 字节]`，一连接多帧；独立端口如 3481）：

```rust
pub async fn listen_tcp(self: &Arc<Self>, addr: SocketAddr) -> std::io::Result<SocketAddr>
pub async fn ping_tcp(&self, dest: SocketAddr) -> Result<PongInfo, RpcError>
pub async fn find_node_tcp(&self, dest: SocketAddr, target: NodeId) -> Result<Vec<NodeEntry>, RpcError>
pub async fn store_tcp(&self, dest: SocketAddr, key: [u8; 32], value: Vec<u8>) -> Result<(), RpcError>
pub async fn find_value_tcp(&self, dest: SocketAddr, key: [u8; 32]) -> Result<ValueBody, RpcError>
pub async fn forward_tcp(&self, dest: SocketAddr, target: NodeId, payload: Vec<u8>) -> Result<(), RpcError>
```

私有 TCP 辅助：

```rust
async fn serve_tcp_conn(&self, stream: TcpStream)
async fn tcp_roundtrip(&self, dest: SocketAddr, req: RpcPacket) -> Result<RpcPacket, RpcError>
```

- `listen_tcp`：Semaphore(512) 限并发，超限 `try_acquire_owned` 失败即拒连；返回实际绑定地址（端口 0 时内核分配，供测试）。
- `serve_tcp_conn`：读写分离；读端 30s 空闲超时解帧 → `dispatch(Sink::Tcp)`；写端把应答帧回灌。
- `tcp_roundtrip`：v1"一请求一连接"（注释："低频信令足够；后续可升级长连接池"），校验应答 txid 一致。
- `forward_tcp`：只发不等（fire-and-forget，符合 Forward 邮件语义）；注释："种子收到后按地址簿以 UDP 转发给 target（种子→目标腿仍是 UDP）"。

模块级私有函数：

```rust
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()>
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>>
fn verified_identity(node_id: [u8; 32], pubkey: [u8; 32]) -> Option<NodeId>
fn learn_addr(book: &mut HashMap<NodeId, (SocketAddr, Instant)>, id: NodeId, addr: SocketAddr)
fn kv_admit(store: &mut HashMap<[u8; 32], KvEntry>, key: [u8; 32], value: Vec<u8>)
```

- `read_frame`：长度 0 或 > MAX_TCP_FRAME(4096) 视为非法，返回 `InvalidData` 错误以断连。
- `verified_identity`：**身份绑定校验闸门**——`node_id` 必须等于 `SHA-256(pubkey)`，且公钥字节必须是合法 ed25519 点；否则拒绝。注释："伪造 node_id（不等于自身公钥哈希）或非法公钥字节一律拒绝；冒充他人则需要为其 node_id 找一个 SHA-256 原像——计算上不可行。"
- `learn_addr`：**地址簿容量治理**——写入/刷新最后见时刻；满员（4096）先 `retain` 清扫静默过期（30min）条目，仍满则逐出"最久未见"一条。注释："攻击者必须持续在线才能保住席位，成本对等。"
- `kv_admit`：**KV 容量治理**——同 key 覆盖不计新；新 key 满员（4096）时逐出最旧写入一条。

#### 3.4.5 dispatch 状态机（RPC 消息处理全表）

`dispatch(&self, pkt: RpcPacket, sink: Sink)` 是 UDP 读循环与 TCP 连接读端共用的同一逻辑：

| RpcBody | 处理 |
|---------|------|
| `Ping(body)` | ① `verified_identity` 校验 node_id==SHA256(pubkey)，失败即 return（"地址簿/路由表防毒化的唯一闸门"）；② `learn_incoming` 双向学习；③ 回 Pong（携带自身 node_id + pubkey） |
| `Pong(body)` | ① 身份绑定校验；② 学习；③ 命中 `Pending::Pong` 则投递 `PongInfo`（TCP 路径不产生 Pong，兜底地址 `0.0.0.0:0`） |
| `FindNode(body)` | `answer_neighbors`：本地路由表 k-closest ∩ 地址簿 → Neighbors 回包 |
| `Neighbors(body)` | 命中 `Pending::Neighbors` 则投递节点列表 |
| `Forward(body)` | target == 自身：payload 首 4B 为 session_tag，已注册 tag 走会话队列（`tx.send(body).is_ok()` 判定），tag=0 或未注册落默认 inbox（`try_send`，队满静默丢弃 = 邮件语义）。target != 自身：`relay_allow` 开启时查地址簿，命中则以**保留 txid** 的 Forward 包 UDP 转发给目标；未命中或贡献模式静默丢弃 |
| `Store(body)` | ① `verified_identity(body.sender, body.pubkey)` 校验（"否则任何人可伪造 sender 抢占 KV 空间"）；② 学习写入者身份（"锚点报道回路由依赖此条目"）；③ `kv_admit` 落库；④ 回 StoredAck |
| `StoredAck` | 命中 `Pending::StoreAck` 则投递 `()` |
| `FindValue(body)` | 查 KV，未命中返回空值；回 Value 包 |
| `Value(body)` | 命中 `Pending::Value` 则投递 |

#### 3.4.6 线格式

**TCP 帧**（listen_tcp 注释 + write_frame/read_frame）：

```
[u16 BE 长度][RpcPacket 字节]
长度 == 0 或 > 4096 → 非法帧，断连
```

**RPC 报文**（定义在 wgp-proto `dht.rs`，node.rs 直接使用）：

```
头部 7B（RPC_HEADER_LEN）：
┌──────────┬──────────┬─────────────────┐
│ magic(2) │ type(1)  │ txid(4B BE)     │
│ "WG"     │ rpc_type │ 事务 id          │
│ 0x57 0x47│          │                 │
└──────────┴──────────┴─────────────────┘

rpc_type 常量：
PING=0x30 | PONG=0x31 | FIND_NODE=0x32 | NEIGHBORS=0x33 | FORWARD=0x34
STORE=0x35 | STORED_ACK=0x36 | FIND_VALUE=0x37 | VALUE=0x38
```

各 Body 布局：

| 报文 | 线格式 |
|------|--------|
| Ping / Pong（`PingBody`，64B） | `node_id(32) \| pubkey(32)` |
| FindNode（`FindNodeBody`，32B） | `target(32)` |
| Neighbors（`NeighborsBody`） | `count(1) \| count × NodeEntry(38B)`，count ≤ K=20 |
| NodeEntry（38B，`NodeEntry::LEN`） | `id(32) \| ipv4(4) \| port(2 BE)` |
| Forward（`ForwardBody`） | `target(32) \| payload_len(2 BE) \| payload(≤600)`，`FORWARD_PAYLOAD_MAX=600` |
| Store（`StoreBody`） | `sender(32) \| pubkey(32) \| key(32) \| value_len(2 BE) \| value(≤1024)`，`PREFIX_LEN=98`，`STORE_VALUE_MAX=1024` |
| StoredAck | 空 body |
| FindValue（`FindValueBody`，32B） | `key(32)` |
| Value（`ValueBody`） | `key(32) \| value_len(2 BE) \| value(≤1024)`，空值 = 未命中 |

估算最大包：Store ≈ 7 + 98 + 1024 = 1129B（与 `MAX_UDP_DATAGRAM=2048` 注释"~1130B"吻合）；TCP 帧上限 4096 覆盖之。

#### 3.4.7 测试用例（node.rs 内联 4 个）

| 测试 | 验证点 |
|------|--------|
| `identity_binding_accepts_true_and_rejects_spoof` | 真实绑定通过；拿自己公钥冒充别人 node_id 拒绝；全零公钥（非典范点）拒绝 |
| `learn_addr_sweeps_expired_before_evicting` | 全员过期时先整体清扫再写入，新条目存活 |
| `learn_addr_evicts_oldest_when_all_fresh` | 全员在线时逐出最久未见；已存在条目刷新不受容量限制 |
| `kv_admit_overwrites_and_evicts_oldest` | 同 key 覆盖不逐出；新 key 满员逐出最旧写入 |

---

### 3.5 `kernel/wgp-dht/src/observe.rs`

**一句话职责**：观察者 / STUN 响应器——对 Binding Request 回 MAPPED 端点并原样回显 WGP-PEER 扩展（07 §3"一套编解码，两级能力"的第二级）；可独立 socket 或与 DhtNode 同 socket。

文件头注释：

```rust
//! 观察者 / STUN 响应器（07 §3："一套编解码，两级能力"的第二级）。
//! 公共 STUN 仅回 MAPPED（一级）；本观察者额外回显 WGP-PEER 扩展（二级）。
//! wgp-node 四职之一；可独立 socket（配置的观察者端口）或与 DhtNode 同 socket。
```

#### 常量（完整照录）

```rust
pub const OBSERVER_RATE_LIMIT: u32 = 12;
pub const OBSERVER_RATE_WINDOW: Duration = Duration::from_secs(10);
```

注释："观察者响应限频默认值（07 §7 贡献模式防滥用）：每 IP 12 次 / 10s——正常打洞信令（探测+步长三连测）远低于此，超出即视为滥用（刷子/洪流），静默丢弃。"

私有常量：

```rust
const GATE_MAX_IPS: usize = 65_536;
```

注释："限频表追踪的源 IP 数上限（按 IP 归一后单主机只占一格；超限说明是分布式源洪流——整表清空重新计数：用短期宽松换内存确定性）"。

#### 公开类型

**`pub struct ObserverPolicy`** —— 观察者限频策略：

```rust
#[derive(Debug, Clone, Copy)]
pub struct ObserverPolicy {
    pub rate_limit: u32,
    pub rate_window: Duration,
}

impl Default for ObserverPolicy {
    fn default() -> Self {
        Self {
            rate_limit: OBSERVER_RATE_LIMIT,
            rate_window: OBSERVER_RATE_WINDOW,
        }
    }
}
```

注释："具体数值属运维策略：内核只提供机制与安全默认值，实际取值由后端配置注入（`ObserverServer::bind_with_policy`）。"

**`pub struct ObserverServer`**：

```rust
pub struct ObserverServer {
    socket: Arc<UdpSocket>,
    /// 限频闸门（IP 归一 + 清扫 + 硬上限）
    gate: Mutex<RateGate>,
    /// 限频策略（由部署配置注入；默认见 `ObserverPolicy::default`）
    policy: ObserverPolicy,
}
```

方法：

```rust
pub async fn bind(port: u16) -> std::io::Result<Arc<Self>>
pub async fn bind_with_policy(port: u16, policy: ObserverPolicy) -> std::io::Result<Arc<Self>>
pub fn local_addr(&self) -> std::io::Result<SocketAddr>
```

- `bind` = 默认策略的 `bind_with_policy`（"端到端测试/内置装配入口"）。
- `bind_with_policy`：绑 `0.0.0.0:{port}`，派生读循环（512B 缓冲）：`try_answer_stun` 命中 → `gate.admit(src.ip(), ...)` 限频判定 → 通过才回包，超限静默丢弃。

#### 私有类型

```rust
struct IpBucket {
    window_start: Instant,
    count: u32,
}

struct RateGate {
    buckets: HashMap<std::net::IpAddr, IpBucket>,
    last_sweep: Instant,
}

impl RateGate {
    fn admit(&mut self, ip: std::net::IpAddr, policy: &ObserverPolicy, now: Instant) -> bool
}
```

`admit` 逻辑（注释照录要点）：
1. **惰性窗口清扫**：距上次清扫 > 一个窗口时，`retain` 掉过期桶；
2. **硬上限**：桶数 ≥ 65536 整表清空重建；
3. **IP 键控**：按 `src.ip()` 归一（注释："换源端口不再重置额度，堵住端口轮换绕过"）；
4. 桶内窗口过期重置计数；`count >= rate_limit` 返回 false（静默丢弃），否则计数 +1。

#### 自由函数

```rust
pub fn try_answer_stun(buf: &[u8], src: SocketAddr) -> Option<Vec<u8>>
```

流程：
1. `StunHeader::decode(buf)`，非 Binding Request → None；
2. `decode_attrs(buf[20..])` 找 WGP-PEER 属性并 `WgpPeerAttr::decode`（回显用：Nonce 关联 + 往返测量）；
3. **仅支持 IPv4 源**（v1 观察者；IPv6 注释"未来线"）；
4. `binding_response(tx_id, ipv4, src.port(), echo)`。

#### 线格式（STUN，定义在 wgp-proto `stun.rs`，RFC 8489 最小子集）

```
STUN 头 20B：
┌──────────────┬──────────┬───────────────┬──────────────────┐
│ msg_type(2)  │ len(2)   │ cookie(4)     │ tx_id(12)        │
│ 0x0001 请求  │ 属性长度  │ 0x2112A442    │ 事务 id          │
│ 0x0101 响应  │          │ (MAGIC_COOKIE)│                  │
└──────────────┴──────────┴───────────────┴──────────────────┘

属性（4B 对齐）：
┌──────────────┬──────────┬─────────────────────┐
│ attr_type(2) │ len(2)   │ value + 0 填充至 4B  │
└──────────────┴──────────┴─────────────────────┘

XOR-MAPPED-ADDRESS（0x0020，value 8B）：
  reserved(1)=0x00 | family(1)=0x01(IPv4) | xport(2) | xaddr(4)
  xport = port ^ (MAGIC_COOKIE>>16)；xaddr 逐字节异或 MAGIC_COOKIE（防中间盒识别）

观察者扩展属性（0x80F0-0x80F2 未注册区）：
  WGP_PEER = 0x80F0，value 24B：
    4B PeerId 短前缀 | 8B Nonce | 8B Timestamp | 4B Flags
    （观察者原样回显，客户端据 Nonce 关联请求并测量往返）
  WGP_LINK = 0x80F1，(2B Proto | 2B MTU | 4B RTT 预算提示)
  WGP_PUNCH = 0x80F2，(打洞协调参数：对端 IP:Port、T_offset、窗口参数)
```

本 crate 只实现/回显 WGP_PEER（0x80F0）；WGP_LINK/WGP_PUNCH 仅常量定义在 wgp-proto，本 crate 无处理代码。

#### 测试用例（4 个）

| 测试 | 验证点 |
|------|--------|
| `observer_reports_mapped_and_echoes` | 响应回显 txid；XOR-MAPPED = 客户端源地址；WGP-PEER nonce 原样回显 |
| `observer_ignores_non_stun` | 垃圾载荷（非 STUN）静默忽略，300ms 内无响应 |
| `observer_rate_limit_drops_flood` | 单 IP 30 连发，响应数恰为 12（≤ 且 ≥ OBSERVER_RATE_LIMIT） |
| `observer_rate_limit_keys_by_ip_not_port` | 30 个同 IP 不同源端口各发 1 请求，总额度仍 12（端口轮换不得放大额度；回归测试，注释："旧实现按 IP:port 计数可无限刷"） |

---

### 3.6 `kernel/wgp-dht/src/room.rs`

**一句话职责**：房间键与锚点机制——room_key 派生、租约（30s 续期/75s 过期）、房间记录编解码与签名、继位链排序、旧链路宽限（07 §4 防脑裂三件套）。

文件头注释："房间键与锚点机制（07 §4：租约/继位链/epoch 防脑裂三件套）。"

#### 引用常量（来自 wgp-proto consts.rs，完整照录）

```rust
pub const LEASE_INTERVAL_S: u64 = 30;
pub const LEASE_TIMEOUT_S: u64 = 75;
pub const OLD_LINK_GRACE_S: u64 = 30;
pub const ROOM_KEY_DOMAIN: &[u8] = b"wgp/room/v1";
```

#### 自由函数

```rust
pub fn room_key(room_code: &str) -> [u8; 32]
```

- U/ 房间码 → DHT 房间键：`SHA256(ROOM_KEY_DOMAIN || room_code.as_bytes())`，即 `SHA256("wgp/room/v1" || 房码)`。注释："13 文档'未来 DHT 冷启动的房间键'落定"。

```rust
pub fn sign_room(identity: &NodeIdentity, record: &RoomRecord) -> Vec<u8>
```

- 锚点以长期身份签名；DHT 存储值 = `signature(64) || record_bytes`。

```rust
pub fn verify_room(buf: &[u8]) -> Option<(RoomRecord, Signature)>
```

- 验证签名房间记录：取前 64B 签名 → `RoomRecord::decode(rest)` → **锚点公钥必须在成员表中检索**（按 anchor NodeId 找）→ ed25519 验签。任一环节失败 None。

```rust
pub fn succession_line(record: &RoomRecord) -> Vec<NodeId>
```

- 继位链：成员表按 NodeId 排序（`Ord` 已为确定字节序）→ 确定性继位顺序。

```rust
pub fn old_link_grace_s() -> u64
```

- 旧链路宽限（注释："00 §4：upgraded 后保活 30s 供外围切换"）→ `OLD_LINK_GRACE_S`。

#### 类型

**`pub struct Lease`** —— 锚点租约：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub epoch: u64,
    pub anchor: NodeId,
    /// 租约到期时刻（Instant 单调时基的毫秒数，由网络时间锚点换算）
    pub expires_at_ms: u64,
}

impl Lease {
    pub fn new(epoch: u64, anchor: NodeId, now_ms: u64) -> Self
    pub fn renew(&mut self, now_ms: u64)
    pub fn expired(&self, now_ms: u64) -> bool
    pub fn interval_s(&self) -> u64
}
```

- `new`/`renew`：`expires_at_ms = now_ms + LEASE_TIMEOUT_S * 1000`（75s）。
- `expired`：`now_ms >= expires_at_ms`（"成员视角：租约是否已过期（连续判过期即触发继位链抢占）"）。
- `interval_s`：返回 `LEASE_INTERVAL_S`（30）。
- `renew` 注释："每 LEASE_INTERVAL_S 由锚点调用，DHT 条件写 CAS"。

**`pub struct RoomRecord`** —— 房间记录（存于 DHT，注释："K=3 副本目标；v1 单值 + 锚点 republish"）：

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRecord {
    /// (NodeId, 身份公钥) 成员表；房主签名保证链序唯一（继位链）
    pub members: Vec<(NodeId, Vec<u8>)>,
    pub lease: Lease,
    /// PoW 凭证（防刷注册，07 §8）
    pub pow: Option<Vec<u8>>,
}
```

`encode`/`decode` 的字节格式（代码注释照录 + 实现核对）：

```
version(1) | epoch(8) | anchor(32) | expires(8) | count(1)
| count × (node_id 32 + pubkey 32) | pow_len(1) | pow
```

- `encode`：`version = 0x01`；各定长字段大端；成员 pubkey 非 32B 时零补齐（防御分支，`debug_assert_eq!(pk.len(), 32)`）；pow 为 None 时 pow_len=0。
- `decode`：总长 < 50 拒绝（头部 1+8+32+8+1=50）；version != 0x01 拒绝；成员段每轮检查 `i + 64 > buf.len()`；结尾必须 `i == buf.len()`（无尾部垃圾）。

#### 测试用例（4 个）

| 测试 | 验证点 |
|------|--------|
| `room_key_deterministic_and_distinct` | 同房码确定性；不同房码（U/C2G9-GYET-311W-R636 vs U/6U01-TWHM-B7H0-CV36）相异 |
| `lease_renew_and_expiry` | expires = now + 75s；边界 now-1 未过期 / now 过期；renew 后同规则 |
| `epoch_guard_against_zombie` | 不同 epoch 的租约可区分（防旧锚点诈尸的语义单元） |
| `succession_line_is_deterministic_order` | 成员表按 NodeId 升序 = 确定性继位顺序 |

---

### 3.7 `kernel/wgp-dht/src/runtime.rs`

**一句话职责**：房间生命周期运行时——创建/读取/续期/成员注册/继位抢占/加入报道/upkeep 三合一循环，把 07 §4 三件套（租约、继位链、epoch）落地。

文件头注释（v1 简化语义）：

```rust
//! v1 简化语义（在未来版本向标准 Kademlia 键值复制演进）：
//!  - 房间键值存于"存储节点"（创建/加入双方共同 bootstrap 的种子），
//!    锚点负责 republish；成员经 find_value 读取。
//!  - 抢占裁决：候选按继位链序退避出手，写后回读验证（epoch/锚点一致性）。
//!  - 加入报道：JoinRequest 经存储节点 Forward 路由至锚点（存储节点已学习
//!    写入者身份），锚点验签后 add_member 重签重存。
```

#### 类型

**`pub enum RoomError`**：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    NotFound,
    InvalidSignature,
    StoreFailed,
    NotExpired,
    PreemptedByOther,
}
```

**`pub struct RoomRuntime`** —— 房间语义绑定在具体 DHT 节点 + 存储节点上：

```rust
pub struct RoomRuntime {
    node: Arc<DhtNode>,
    identity: Arc<NodeIdentity>,
    /// 房间键存储节点（v1：双方共同认识的种子）
    storage: SocketAddr,
}
```

#### 方法（签名照抄）

```rust
pub fn new(node: Arc<DhtNode>, storage: SocketAddr) -> Self
pub async fn create(&self, code: &str, now_ms: u64) -> Result<RoomRecord, RoomError>
pub async fn fetch(&self, code: &str) -> Result<RoomRecord, RoomError>
pub async fn publish(&self, code: &str, record: &RoomRecord) -> Result<(), RoomError>
pub async fn renew(&self, code: &str, record: &RoomRecord, now_ms: u64) -> Result<RoomRecord, RoomError>
pub async fn add_member(&self, code: &str, record: &RoomRecord, member_id: NodeId, member_pk: Vec<u8>, now_ms: u64) -> Result<RoomRecord, RoomError>
pub async fn try_takeover(&self, code: &str, current: &RoomRecord, now_ms: u64) -> Result<RoomRecord, RoomError>
pub async fn request_join(&self, code: &str, record: &RoomRecord) -> Result<(), RoomError>
async fn handle_join_request(&self, code: &str, payload: &[u8], now_ms: u64) -> bool   // 私有
pub async fn upkeep(&self, code: String, interval_ms: u64, mut stop: watch::Receiver<bool>, now_fn: impl Fn() -> u64)
```

逐方法语义：

- **`create`**：自己 = 房主 + 锚点，`Lease::new(0, my_id, now_ms)`（epoch=0），`pow: None`；publish 后**回读自证**——若回读 anchor != 自己 → `PreemptedByOther`。
- **`fetch`**：`room_key(code)` → `find_value(storage, key)`；空值 → `NotFound`；`verify_room` 失败 → `InvalidSignature`。
- **`publish`**：`sign_room` 后 `store(storage, room_key, signed)`；RPC 失败 → `StoreFailed`。
- **`renew`**：克隆记录 → `lease.renew(now_ms)`（**epoch 不变**）→ republish。
- **`add_member`**（仅锚点执行）：`record.lease.anchor != self.my_id()` → `PreemptedByOther`（"只有当前锚点能改成员表（07 §4 权限语义）"）；成员已在表 → 幂等返回原记录；否则追加成员 + renew + 重签重存。
- **`try_takeover`**：① 未过期 → `NotExpired`；② 不在继位链 → `PreemptedByOther`；③ **退避**：`my_pos > 0` 时 `sleep(300ms × my_pos)`（"链上排前面的先动手"）；④ 重读最新记录，已被新锚点续期 → `NotExpired`；⑤ 以 `Lease::new(current.epoch + 1, my_id, now_ms)` 写入（epoch+1）；⑥ **写后回读裁决**：anchor == 自己 → 成功，否则 `PreemptedByOther`。
- **`request_join`**：构造签名 JoinRequest → `forward_to(storage, record.lease.anchor, payload)`（经存储节点 Forward 路由至锚点）。注释："v1 无 ACK：请求方轮询 fetch 直至自己入表（upkeep 内实现）。"
- **`handle_join_request`**（锚点侧，upkeep 轮询 inbox 调用）：`JoinRequest::verify` 失败 → false（伪造报道静默丢弃）；`fetch` 失败 → false；自己已非锚点 → false（"新锚点会处理重发"）；成员已在表 → true（幂等）；否则 `add_member`。
- **`upkeep`**（长任务，锚点与成员共用同一逻辑）：`watch` 停止信号 + 定时循环：
  1. ① **锚点职责**：`try_recv_forward` 排空 inbox，target == 自身的 payload 交 `handle_join_request`；
  2. `fetch` 房间记录（存储节点暂不可达则下轮重试）；
  3. ② 自己是锚点：`now - last_renew_ms >= LEASE_INTERVAL_S * 1000`（30s 节流）时续期；
  4. ③ 自己是成员：自己未入表 → `request_join` 补报道；租约过期 → `try_takeover`。

#### `JoinRequest`（pub struct，无字段的命名空间类型）

```rust
pub struct JoinRequest;

impl JoinRequest {
    pub fn sign(identity: &NodeIdentity, code: &str, member_id: NodeId, member_pk: &[u8]) -> Vec<u8>
    pub fn verify(verifier: &NodeIdentity, code: &str, payload: &[u8]) -> Option<(NodeId, Vec<u8>)>
}
```

线格式（代码注释照录）：

```
magic(2 "WJ") | code_len(1) | code | member_id(32) | pubkey(32) | sig(64)
```

- `sign`：`debug_assert!(code_bytes.len() <= 200)`；签名域 = 全部 unsigned 字段（"WJ" + code_len + code + member_id + pubkey）。
  > 代码如此，意图待确认：结构体上方注释写 "sig = ed25519_sign(code || member_id || pubkey)"，但实际 `identity.sign(&unsigned)` 覆盖含 magic 与长度字节的全部前缀，`verify` 亦对应校验 `payload[..3 + code_len + 64]`。以代码为准。
- `verify`：长度必须严格等于 `2 + 1 + code_len + 64 + 64`；magic 与 code 必须匹配（"报错房间：拒绝"）；用**载荷自带的成员公钥**验签（`let _ = verifier;`——"验签不依赖本地身份（用对端公钥自证）"）。

#### 测试用例（8 个，loopback 三节点拓扑 owner/bob/carol + owner 兼任存储节点）

| 测试 | 验证点 |
|------|--------|
| `create_and_fetch_valid_signed_record` | 建房：anchor=自己、epoch=0、1 成员；fetch 回读一致且验签通过 |
| `tampered_record_rejected` | 篡改成员表 + 假签名直接 store → fetch 得 `InvalidSignature` |
| `renew_advances_expiry_no_epoch_bump` | 续期推后 expires、epoch 不变 |
| `add_member_updates_membership` | 成员表 1→2；第三方（Carol）可读到新成员表 |
| `takeover_when_owner_silent` | 房主不续期：40s 时抢占 → `NotExpired`；80s（越过 75s 租约）Bob 抢占成功（epoch+1、anchor=Bob）；Carol 再抢 → `NotExpired`（新锚点已续期） |
| `fetch_uncreated_room_not_found` | 未建房 → `NotFound` |
| `join_request_sign_verify_and_forgery_rejected` | 合法自证通过；篡改公钥字节拒绝；Mallory 身份签拒绝 |
| `upkeep_auto_report_and_renew` | A 建房后 A、B 各跑 upkeep（100ms 周期）：B 自动补报道入表；租约被 A 持续续期 |

---

### 3.8 `kernel/wgp-dht/src/advertise.rs`

**一句话职责**：种子广告 SeedAdvertise 的真实签名/验证（07 §5 第③层：DHT 内交换种子，发送方长期 ed25519 身份签名；篡改即无效）。

#### 自由函数（签名照抄）

```rust
pub fn sign_advertise(
    id: &NodeIdentity,
    addr_v4: [u8; 4],
    dht_port: u16,
    stun_port: u16,
    priority: u8,
    flags: u8,
) -> [u8; seed_advertise::LEN]
```

- `seed_advertise::payload_for_sign(...)` 构 10B 载荷 → `id.sign` → `encode_signed` 填 91B 定长报文。注释："产出完整 91B 报文"。

```rust
pub fn verify_advertise(advertiser: &VerifyingKey, buf: &[u8]) -> Option<SeedAdvertise>
```

- `seed_advertise::extract` + `signed_payload` + 用**广告主公钥**验签。
- 注释（重要设计说明）："SeedAdvertise 报文不携带公钥（91B 定长装不下 32B 密钥），因此验证方必须从可信信道取得广告主的 VerifyingKey——即身份绑定校验（node_id=SHA256(pubkey)）通过的 PING/PONG 对端公钥。用本地身份验他人广告是必然失败的（历史缺陷已修）。"

#### 线格式（SeedAdvertise，定义在 wgp-proto `packet.rs`，91B）

```
magic(2) | type(1)=0x20 | addr_v4(4) | dht_port(2) | stun_port(2)
| priority(1) | flags(1) | reserved(14) | signature(64)
```

- `SIGNED_LEN = 4 + 2 + 2 + 1 + 1 = 10`；`LEN = 2 + 1 + 10 + 14 + 64 = 91`。
- 签名字节域 = `buf[3..13]`（addr_v4 || dht_port || stun_port || priority || flags），与 `payload_for_sign` 严格一致；reserved 14B 不签名。
- magic 为 SIG_MAGIC = `[0x57, 0x47]`（"WG"）。
> 代码如此：wgp-proto 中 `SeedAdvertise` 结构体上方注释写 "90B"，但常量 `LEN` 计算值为 91（advertise.rs 注释亦为 91B）。以常量 `LEN = 91` 为准。

#### 测试用例（4 个）

| 测试 | 验证点 |
|------|--------|
| `sign_and_verify_roundtrip` | 91B 长度；dht_port=3841/stun_port=3478/priority=5/flags=1 往返一致 |
| `tampered_advertise_rejected` | 篡改端口字段（签名载荷内 `bytes[9] ^= 0x01`）→ 验签失败 |
| `wrong_signer_rejected` | 错误公钥验签拒绝；正确广告主公钥通过（防谎报种子） |
| `node_id_stable_derivation` | `node_id_from_verifying(vk) == identity.node_id()`（身份绑定派生稳定） |

---

### 3.9 `kernel/wgp-dht/src/net_test.rs`（测试文件）

**一句话职责**：DhtNode 网络层集成测试——loopback 三节点拓扑（A、B、种子 S）覆盖中继策略、会话分派、RPC 往返、Forward 投递、抗垃圾洪流、承诺-揭示端到端、TCP 信令面。

#### 测试辅助

```rust
async fn spawn_node() -> Arc<DhtNode>      // 随机身份 + 127.0.0.1:0
async fn spawn_tcp(node: &Arc<DhtNode>) -> SocketAddr   // listen_tcp 127.0.0.1:0
fn addr(node: &DhtNode) -> SocketAddr
```

dev-dependencies 使用：`wgp_crypto::commit::commit`、`wgp_crypto::ka::{X25519Agreement, KeyAgreement}`、`wgp_proto::sig::{algo, sig_type, CommitBody, RevealBody, SigBody, SigPacket}`。

#### 测试用例（13 个）

| # | 测试 | 验证点 |
|---|------|--------|
| 1 | `relay_policy_deny_blocks_transit` | 贡献模式 Deny：种子不中转（B 600ms 内收不到）；恢复 Allow 即通（载荷字节级一致） |
| 2 | `forward_session_dispatch_by_tag` | 已注册 tag(0x1234) → 会话队列；未注册 tag(0x9999) → 默认队列；注销后同 tag 落默认队列 |
| 3 | `ping_roundtrip_bidirectional_learn` | ping 返回对方 node_id + 地址；**双向学习**：A 认识 B（pong），B 认识 A（ping） |
| 4 | `ping_timeout_to_dead_node` | 127.0.0.1:1 无人监听 → 1.5s 超时（断言 elapsed ≥ 1400ms） |
| 5 | `find_node_returns_known_neighbors` | B、C 先 ping A → C 向 A find_node 应答非空且不含 A 自身 |
| 6 | `forward_delivery_via_seed` | A 经种子向 B 投递 6B 载荷，字节级完整 |
| 7 | `forward_unknown_target_silently_dropped` | 投递给种子不认识的人 → 静默丢弃，B 无响应 |
| 8 | `garbage_burst_does_not_kill_node` | 32 个 64B 垃圾包洪流后节点存活，ping 仍成功 |
| 9 | `commit_reveal_over_dht_forward` | 承诺-揭示信令经 DHT Forward 完整投递；B 侧验 `SHA256(pk‖nonce)[..16] == commit`（MITM 检测闭环；"不可信转发者"通道成立，07 §2） |
| 10 | `tcp_ping_roundtrip_and_no_addr_book_pollution` | TCP ping 往返正确；**核心断言**：B 经 TCP 收到 ping 后地址簿必须为空（只入路由表，防毒化 UDP 中转路由） |
| 11 | `tcp_store_and_find_value` | TCP KV 写入读回一致；未命中返回空值（非错误）；TCP store 的 sender 学习同样只入路由表 |
| 12 | `tcp_forward_relayed_by_seed_over_udp` | 客户端经 TCP 把"致 B"载荷交给种子，种子按地址簿以 UDP 转给 B（种子→目标腿仍是 UDP） |
| 13 | `tcp_oversize_frame_rejected_and_node_survives` | 声明 0xFFFF 超长帧 → 服务端断连；节点存活，后续 TCP ping 可用 |

---

## 4. 对外 API 汇总（lib.rs `pub use` 全量清单）

```rust
pub use advertise::{sign_advertise, verify_advertise};
pub use id::{NodeId, NodeIdentity};
pub use kbucket::RoutingTable;
pub use node::{DhtNode, PongInfo, RelayPolicy, RpcError};
pub use observe::{
    try_answer_stun, ObserverPolicy, ObserverServer, OBSERVER_RATE_LIMIT, OBSERVER_RATE_WINDOW,
};
pub use room::{room_key, sign_room, succession_line, verify_room, Lease, RoomRecord};
pub use runtime::{RoomError, RoomRuntime};
```

共 **20 个** crate 根再导出项。

**注意：以下 pub 项未在 crate 根再导出**（需经模块路径访问）：

| 项 | 路径 |
|----|------|
| `node_id_from_verifying`、`peer_id_from_node` | `wgp_dht::id::*` |
| `KBucket`、`K` | `wgp_dht::kbucket::*` |
| `old_link_grace_s` | `wgp_dht::room::*` |
| `JoinRequest` | `wgp_dht::runtime::*` |

（模块本身 `pub mod`，故上述均对外可见，只是没有根路径快捷方式。）

---

## 5. 与设计文档（07）的对应关系

| 07 文档条目 | 代码落点 | 对应情况 |
|--------------|----------|----------|
| §1 角色（种子/观察者/转发者/锚点） | observe.rs `ObserverServer`；node.rs Forward 中转分支；runtime.rs `RoomRuntime` | 已实现（角色由部署组合，非独立类型） |
| §3 观察者协议：RFC 8489 复用 + WGP-PEER/LINK/PUNCH 三扩展属性 | observe.rs `try_answer_stun`；wgp-proto stun.rs 常量 | 部分：仅 WGP_PEER(0x80F0) 有编解码与回显；WGP_LINK/WGP_PUNCH 仅常量，无处理代码 |
| §3 "一套编解码，两级能力" | try_answer_stun 与 DhtNode 读循环同 socket 应答（node.rs:149） | 已实现 |
| §3 元素过程（K 个观察者/交叉比对） | 本 crate 无（属上层引擎） | 未实现于本 crate |
| §3 限频门控：按源 IP 令牌桶、周期清扫、桶上限 65536、默认 10s/12 次可配 | observe.rs `RateGate`/`GATE_MAX_IPS`/`OBSERVER_RATE_LIMIT`/`ObserverPolicy` | 已实现 |
| §4 room_key = SHA256("wgp/room/v1" \|\| U/房码) | room.rs `room_key` + wgp-proto `ROOM_KEY_DOMAIN = b"wgp/room/v1"` | 已实现 |
| §4 存储对象（成员表/锚点/epoch/租约/PoW） | room.rs `RoomRecord`（含 `pow: Option<Vec<u8>>` 字段） | 已实现（PoW 仅字段，无生成/校验逻辑） |
| §4 副本 K=3 | runtime.rs 注释"v1 单值 + 锚点 republish" | v1 简化为单存储节点，K=3 未实现 |
| §4 租约：锚点每 30s 续期、75s 判掉线 | consts `LEASE_INTERVAL_S=30`/`LEASE_TIMEOUT_S=75`；room.rs `Lease`；runtime.rs `renew`/`expired`/upkeep 30s 节流 | 已实现 |
| §4 继位链：成员表排序 = 确定性顺序，候补按序抢占 | room.rs `succession_line`（NodeId Ord 排序）；runtime.rs `try_takeover`（300ms×位次退避 + 写后回读） | 已实现 |
| §4 epoch：转移 +1、续期带 epoch、旧锚点回归降级 | room.rs `Lease::new(epoch+1, ...)`；`epoch_guard_against_zombie` 测试 | 已实现 |
| §4 新成员加入（读房间键→找锚点→报道） | runtime.rs `request_join`/`handle_join_request`/`JoinRequest` | 已实现（v1 无 ACK，轮询 fetch） |
| §4 存储线格式与容量治理：98B 前缀 + 公钥绑定校验；KV 4096 逐出最旧；地址簿 4096/30min 过期/先清扫后逐最久未见 | wgp-proto dht.rs `StoreBody::PREFIX_LEN=98`；node.rs `verified_identity`/`kv_admit`/`learn_addr`/`ADDR_BOOK_MAX`/`ADDR_BOOK_TTL`/`KV_MAX_ENTRIES` | 已实现 |
| §5 种子发现四层（静态/DNS/DHT/排序） | advertise.rs `sign_advertise`/`verify_advertise`（第③层 DHT 内交换） | 部分：仅第③层签名/验签原语；①②④ 属外围（wgp-node/应用配置） |
| §6 wgp-node 部署（UDP 11010 / TCP 3481 / UDP 3478、四职、贡献版拒中转） | node.rs `listen_tcp`/`RelayPolicy::Deny`；observe.rs `ObserverServer` | 机制已实现；端口由配置注入，协议层无默认端口 |
| §7 公共 STUN 池 | 本 crate 无（外围探测） | 不适用 |
| §8 威胁表：身份绑定防冒充/毒化、IP 键控限频、PoW、epoch 防诈尸 | node.rs `verified_identity`；observe.rs `RateGate`；room.rs `pow` 字段；Lease epoch | 已实现（PoW 仅字段） |
| §2 承诺-揭示中转（不可信转发语义） | node.rs Forward 分支（fire-and-forget、不学习）；net_test.rs `commit_reveal_over_dht_forward` | 已实现并有端到端测试 |

---

## 6. 已知限制或未实现项

以下均为代码注释/结构可证的现状，非推测：

1. **k-bucket 为骨架**：kbucket.rs 无桶分裂、无定时刷新、无旧节点逐出（满桶拒入）；`closest_to` 为全表排序截断（非桶内索引）。文件头自述"实现阶段补全：k-bucket 分裂、维护、SeedAdvertise 交换"。
2. **路由查询未递归**：`find_node` 仅单跳问答（本地 closest ∩ 地址簿），无 Kademlia 迭代式多跳查找。
3. **KV 单点存储**：v1 房间记录存于单一"存储节点"（双方共同 bootstrap 的种子），无 K=3 副本、无复制/再平衡（runtime.rs 头注释明示"在未来版本向标准 Kademlia 键值复制演进"）。
4. **条件写 CAS 未实现**：renew/takeover 的并发互斥靠"写后回读裁决"（try_takeover 的 epoch+1 竞争），非 DHT 原子 CAS。
5. **IPv6 全线未实现**：Neighbors 应答仅 IPv4 条目（node.rs `answer_neighbors` 注释"v1 仅 IPv4 条目；IPv6 未来线"）；观察者仅 IPv4 源（observe.rs `try_answer_stun`）。
6. **TCP 一请求一连接**：`tcp_roundtrip` 注释"v1：一请求一连接，低频信令足够；后续可升级长连接池"。
7. **PoW 仅有字段无逻辑**：`RoomRecord::pow` 存在于编解码与签名域，但本 crate 无 PoW 生成/难度校验代码（07 §8 防刷注册）。
8. **WGP-LINK / WGP_PUNCH 无处理代码**：常量定义在 wgp-proto，本 crate 只回显 WGP_PEER。
9. **无 RPC 重试/退避**：UDP RPC 1500ms 超时即失败返回，重发由上层负责（lib 注释"上层信令自持超时重发"）。
10. **Pong 兜底地址**：TCP 路径到达 Pong 分支时（当前 dispatch 下实际不触发）使用 `0.0.0.0:0` 占位（node.rs:426 注释"避免 unwrap 崩溃"）。
11. **address book 与路由表无主动清理**：节点失联清理依赖上层 PING 超时后不再 insert（kbucket.rs insert 注释兜底说明）；无后台清扫任务。
12. **JoinRequest 头注释与签名域表述不一致**：注释写 `code || member_id || pubkey`，代码实际签名域含 "WJ" magic 与长度字节（runtime.rs:250-251 vs :269）。以代码为准，意图待确认。
13. **SeedAdvertise 长度注释不一致**：wgp-proto 结构体注释"90B"与常量 `LEN=91` 不符（本 crate advertise.rs 注释为 91B）。以 `LEN=91` 为准。
14. **身份持久化文件 IO 不在本 crate**：`to_seed`/`from_seed` 只处理 32B 种子字节；`node_identity.key`（600 权限）的读写由外围负责（id.rs 注释）。
15. **观察者策略数值可配但 CLI 接线在外围**：`ObserverPolicy` 由 `bind_with_policy` 注入；07 §6 所述 `--observer-rate-limit/--observer-rate-window` 参数解析不在本 crate。

---

*文档结束*
