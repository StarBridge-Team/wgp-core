# wgp-proto 协议层详细文档

> - 源目录：`H:\mclink core\kernel\wgp-proto\src\`（共 9 个文件，2099 行）
> - 生成日期：2026-11-05
> - 对应设计文档：docs/00（总纲与 crate 纪律）、docs/08（包格式）、docs/07（观察者协议 / DHT 网络层 / 房间与锚点）、docs/13（房间码）；代码内注释另引用 docs/03（打洞）、docs/14（协议版本化）、docs/15（全链路流程）
> - 本文档所有签名、常量、测试向量均逐字照抄源码，未做任何虚构；注释与代码不一致处以代码为准并标注"代码如此，意图待确认"。

---

## 1. Crate 概览

### 1.1 定位

wgp-proto 是折跃门（wgp）项目的**协议层 crate**：纯数据、零行为。它是全部线上报文格式、协议常量、标识符派生算法的**唯一权威实现**——信令包（承诺-揭示）、数据面报文（探针/心跳/种子广告）、DHT RPC 报文、STUN 最小子集与观察者扩展属性、种子端点解析、IDN 域名归一化、U/ 房间码派生，全部集中于此。

### 1.2 零依赖纪律（00 §3）

`lib.rs` 第 1-2 行原文：

```rust
//! 折跃门协议层：纯数据 crate。
//! 纪律（00 §3）：无 IO、无 async、零依赖；所有包格式与常量以此为准。
```

具体表现为：

- **无 IO、无 async**：没有任何 `std::net` 之外的系统调用式操作；唯一的 `std` 使用是 `std::net::IpAddr`（stun.rs 的观察者地址）与字符串/集合。
- **零第三方依赖**：连 serde/protobuf 都明令禁止（sig.rs 第 1 行、packet.rs 第 2 行注释），全部手写定长二进制编解码。
- **算法也自实现**：MD5（room_code.rs，RFC 1321，约 70 行手写）与 Punycode（punycode.rs，RFC 3492 编码方向）都不引 crate，以维持零依赖。
- **加密切签外置**：本 crate 只定义"哪些字节待签/待认证"及其布局，HMAC / SHA-256 / ed25519 的实际计算在 wgp-crypto 或上层完成。

### 1.3 在设计中的位置

crate 分层（用户给定）：`wgp-proto`（协议层，纯数据、无 IO 无 async 零依赖）→ `wgp-crypto` → `wgp-punch` / `wgp-dht` → `wgp-core`。

wgp-proto 处于**最底层**：wgp-crypto 为其提供哈希/签名/HMAC 原语（本 crate 的 `md5` 是纪律例外，仅服务于房间码派生），wgp-punch / wgp-dht / wgp-core 消费其类型与常量。下游不允许自行定义包格式——"所有包格式与常量以此为准"。

### 1.4 全局编码约定

| 约定 | 值 | 出处 |
|---|---|---|
| 字节序 | 全部多字节整数**大端（BE）** | 各 encode 函数 |
| 数据面魔数 | `SIG_MAGIC = [0x57, 0x47]`（ASCII "WG"） | sig.rs:7，被 sig/dht/packet 三模块共用 |
| 协议版本 | `PROTO_VERSION = 0x01` | consts.rs:4，写入 SigHeader.version |
| 编解码风格 | 定长走 `&mut [u8; N]` 出参；变长走 `Vec<u8>`；解码失败一律 `Option::None` | 全文 |

---

## 2. 模块结构总表

| 文件（行数） | 职责 | 关键导出 |
|---|---|---|
| `lib.rs`（14） | crate 根：声明 8 个 pub 模块 + 4 项再导出 | `pub mod` × 8；`pub use endpoint::{ParseError, SeedEndpoint, SeedScheme}`；`pub use room_code::derive_room_code` |
| `consts.rs`（28） | 全局协议常量：版本、魔数前缀、打洞预算、三波探测、超时约定、房间/锚点租约 | `PROTO_VERSION`、`MAGIC_PREFIX`、`PROBE_BUDGET_*`、`WAVE*_PACKETS`、`WAVE_TIMEOUT_MS`、`COMMIT_TIMEOUT_S`、`QUIC_HANDSHAKE_TIMEOUT_S`、`DEGRADED_UDP_PROBE_S`、`OLD_LINK_GRACE_S`、`LEASE_INTERVAL_S`、`LEASE_TIMEOUT_S`、`ROOM_KEY_DOMAIN` |
| `sig.rs`（366） | 信令包（承诺-揭示）定长编解码 | `SIG_MAGIC`、`sig_type`、`algo`、`flag`、`err`、`HEADER_LEN`、`BODY_MAX`、`PACKET_MAX`、`CommitBody`、`RevealBody`、`ErrorBody`、`SigHeader`、`SigPacket`、`SigBody` |
| `packet.rs`（230） | 数据面报文：探针、心跳、种子广告 + UDP 分流判定 | `Probe`、`probe`、`heartbeat`、`SeedAdvertise`、`seed_advertise`、`classify` |
| `dht.rs`（590） | DHT RPC 报文（Kademlia 变种）与 KV 存储体 | `rpc_type`、`RPC_HEADER_LEN`、`K`、`STORE_VALUE_MAX`、`FORWARD_PAYLOAD_MAX`、`NodeEntry`、`PingBody`、`FindNodeBody`、`NeighborsBody`、`ForwardBody`、`StoreBody`、`FindValueBody`、`ValueBody`、`RpcHeader`、`RpcBody`、`RpcPacket` |
| `stun.rs`（302） | STUN 最小子集（RFC 8489）+ 观察者扩展属性 | `MAGIC_COOKIE`、`BINDING_REQUEST`、`BINDING_RESPONSE`、`ATTR_*`、`wgp_attr`、`StunHeader`、`BindingProbe`、`WgpPeerAttr`、`WGP_PEER_PAYLOAD_LEN`、`encode_attr`、`decode_attrs`、`xor_mapped_value`、`decode_xor_mapped`、`binding_request`、`binding_response` |
| `endpoint.rs`（182） | 种子/服务器端点解析（scheme + host + port，IDN 归一化） | `SeedScheme`、`SeedEndpoint`、`ParseError` |
| `punycode.rs`（144） | RFC 3492 Punycode 编码（仅 Unicode → ACE 方向） | `label_to_ascii`、`domain_to_ascii` |
| `room_code.rs`（243） | U/ 房间码确定性派生 + 自实现 MD5 | `derive_room_code`、`md5`、`ROOM_CODE_LEN` |

---

## 3. 逐文件详细文档

### 3.1 `src/lib.rs`（14 行）

**一句话职责**：crate 根，声明全部 8 个公共模块并做最小面再导出。

**内容**：

```rust
pub mod consts;
pub mod dht;
pub mod endpoint;
pub mod packet;
pub mod punycode;
pub mod room_code;
pub mod sig;
pub mod stun;

pub use endpoint::{ParseError, SeedEndpoint, SeedScheme};
pub use room_code::derive_room_code;
```

**设计要点**：再导出只挑"门面级"API（端点解析三件套 + 房间码派生），其余一律经模块路径访问（如 `wgp_proto::sig::SigPacket`），避免命名冲突（如 `classify`、`md5` 这类通用名）。

**测试**：无。

---

### 3.2 `src/consts.rs`（28 行）

**一句话职责**：全项目协议常量的唯一定义处（00 §1 H 约束、15 全链路流程的数字化）。

**常量清单（照抄）**：

```rust
pub const PROTO_VERSION: u8 = 0x01;
pub const MAGIC_PREFIX: &[u8; 3] = b"wgp";
pub const PROBE_BUDGET_PER_ROUND: u16 = 47;
pub const PROBE_BUDGET_PER_10MIN: u16 = 500;
pub const WAVE1_PACKETS: u16 = 21;
pub const WAVE2_PACKETS: u16 = 15;
pub const WAVE3_PACKETS: u16 = 11;
pub const WAVE_TIMEOUT_MS: u64 = 800;
pub const COMMIT_TIMEOUT_S: u64 = 3;
pub const QUIC_HANDSHAKE_TIMEOUT_S: u64 = 3;
pub const DEGRADED_UDP_PROBE_S: u64 = 30;
pub const OLD_LINK_GRACE_S: u64 = 30;
pub const LEASE_INTERVAL_S: u64 = 30;
pub const LEASE_TIMEOUT_S: u64 = 75;
pub const ROOM_KEY_DOMAIN: &[u8] = b"wgp/room/v1";
```

| 常量 | 值 | 含义（据注释） |
|---|---|---|
| `PROTO_VERSION` | `0x01` | 协议版本，每包头部携带，未来线与能力协商依据（00 §11 版本化纪律） |
| `MAGIC_PREFIX` | `b"wgp"`（3B） | 注释称"探针/心跳魔数前缀（会话级魔数由 session_key 派生，见 wgp-crypto）" |
| `PROBE_BUDGET_PER_ROUND` | 47 | 单轮打洞探针预算（H6，00 §1） |
| `PROBE_BUDGET_PER_10MIN` | 500 | 10 分钟窗口探针预算 |
| `WAVE1_PACKETS` / `WAVE2_PACKETS` / `WAVE3_PACKETS` | 21 / 15 / 11 | 三波探测各波包数（03 §3.5）；三者之和恰为 47，与单轮预算自洽 |
| `WAVE_TIMEOUT_MS` | 800 | 波间超时（ms） |
| `COMMIT_TIMEOUT_S` | 3 | 承诺-揭示的 commit 超时（15 全链路） |
| `QUIC_HANDSHAKE_TIMEOUT_S` | 3 | QUIC 握手超时 |
| `DEGRADED_UDP_PROBE_S` | 30 | 降级 UDP 探测窗口 |
| `OLD_LINK_GRACE_S` | 30 | 旧链路宽限期（迁移期间双链路并存时长） |
| `LEASE_INTERVAL_S` | 30 | 房间/锚点租约续期间隔（07 §4） |
| `LEASE_TIMEOUT_S` | 75 | 租约超时（> 2× 续期间隔） |
| `ROOM_KEY_DOMAIN` | `b"wgp/room/v1"` | 房间密钥派生域分隔串 |

**设计要点与约束**：
- 本文件**零函数、零类型**，纯 `pub const`；编译期内联，无运行时成本。
- 超时组（3s/3s/30s/30s/30s/75s）体现了"3 秒承诺、3 秒握手、30 秒探测/宽限/续租、75 秒租约死亡"的全链路时间轴（15）。
- ⚠️ **注释与代码不一致（代码如此，意图待确认）**：`MAGIC_PREFIX = b"wgp"` 的注释称其为"探针/心跳魔数前缀"，但 `packet.rs` 的探针（`probe::encode`）与心跳（`heartbeat::encode_base`）实际使用的都是 `sig::SIG_MAGIC`（"WG"）；且 `MAGIC_PREFIX` 在本 crate 内**无任何引用**（可能供 wgp-crypto 派生会话级魔数或其他 crate 使用）。

**测试**：无（纯常量文件）。

---

### 3.3 `src/sig.rs`（366 行）

**一句话职责**：信令包（承诺-揭示握手）的定长编解码，含 8B 统一头与 4 种包体（14 §11 协议版本化；00 §3 禁止 serde/protobuf，全部手写零分配解析，BodyLen 上限 200B 防恶意膨胀）。

#### 常量

```rust
pub const SIG_MAGIC: [u8; 2] = [0x57, 0x47];   // ASCII "WG"（与 03 §3.2.3 思路一致）
pub const HEADER_LEN: usize = 8;
pub const BODY_MAX: usize = 200;
pub const PACKET_MAX: usize = HEADER_LEN + BODY_MAX;   // = 208
```

```rust
pub mod sig_type {
    pub const COMMIT: u8 = 0x01;
    pub const REVEAL: u8 = 0x02;
    pub const COMMIT_ACK: u8 = 0x03;
    pub const ERROR: u8 = 0x04;
}
pub mod algo {
    pub const X25519: u8 = 0x01;
    pub const HYBRID_PQ: u8 = 0x02; // 未来线
}
pub mod flag {
    pub const REQUIRE_ACK: u8 = 0x01;  // 对端应在 3s 内 ACK，否则重发（应对 DHT 丢包）
    pub const CAP_ESCAPE: u8 = 0x02;   // 逃生通道能力位
    pub const CAP_LAN: u8 = 0x04;      // LAN 组播能力位
}
pub mod err {
    pub const COMMIT_TIMEOUT: u8 = 0x01;
    pub const REVEAL_MISMATCH: u8 = 0x02; // 承诺不匹配 = MITM
    pub const ALGO_UNSUPPORTED: u8 = 0x03;
    pub const BAD_NONCE: u8 = 0x04;
    pub const PEER_BLACKLISTED: u8 = 0x05;
}
```

#### 信令包头（8B 定长，`SigHeader`）

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigHeader {
    pub version: u8,
    pub kind: u8,    // sig_type
    pub algo: u8,
    pub flags: u8,
    pub body_len: u8,
}

impl SigHeader {
    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) { /* ... */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* ... */ }
}
```

字节布局（大端）：

```
偏移  0    1    2        3      4      5      6        7
      ┌────┬────┬────────┬──────┬──────┬──────┬────────┬─────────┐
      │ 'W'│ 'G'│version │ kind │ algo │flags │body_len│reserved │
      │    │    │        │      │      │      │        │ (恒 0)  │
      └────┴────┴────────┴──────┴──────┴──────┴────────┴─────────┘
```

- `decode` 校验：长度 ≥ 8、魔数匹配、`kind ∈ {COMMIT, REVEAL, COMMIT_ACK, ERROR}`；**不校验 version**（读到但不禁用任何版本号）。
- `body_len` 为 u8，与 `BODY_MAX = 200` 共同封顶包体。

#### 包体类型

**`CommitBody`（承诺包）**：

```rust
pub struct CommitBody {
    pub peer_id: [u8; 16],
    /// SHA256(pubkey||nonce) 截断 16B
    pub commit: [u8; 16],
}
impl CommitBody {
    pub const BODY_LEN: u8 = 48;
    pub fn encode(&self) -> [u8; 48] { /* ... */ }
    pub fn decode(buf: &[u8; 48]) -> Self { /* ... */ }
}
```

```
peer_id(16B) │ commit(16B) │ reserved(16B，先置零，未来算法标识扩展位)
```

- ⚠️ 源码注释写"承诺包（33B body）"，实际 `BODY_LEN = 48`（含 16B 保留位），`encode` 返回 `[u8; 48]`——**代码如此，意图待确认**（保留位为未来扩展预留）。
- `commit` 的 SHA-256 计算在本 crate 之外（零依赖无哈希原语），由上层填充。

**`RevealBody`（揭示包）**：

```rust
pub struct RevealBody {
    pub peer_id: [u8; 16],
    pub pubkey: Vec<u8>, // X25519=32B；Hybrid=变长（由 algo 决定）
    pub nonce: [u8; 32],
}
impl RevealBody {
    pub const BODY_LEN_X25519: u8 = 80;
    pub fn encode(&self) -> Vec<u8> { /* ... */ }
    pub fn decode(buf: &[u8], expected_pubkey_len: usize) -> Option<Self> { /* ... */ }
}
```

```
peer_id(16B) │ pubkey(expected_pubkey_len B) │ nonce(32B)
```

- `decode` 要求 `buf.len() == 16 + expected_pubkey_len + 32`，长度由调用方按 algo 推断。
- X25519 模式定长 80B；Hybrid 模式长度由算法决定（当前 `SigPacket::decode` 对非 X25519 一律拒识，见 §6）。

**`ErrorBody`（错误包）**：

```rust
pub struct ErrorBody {
    pub code: u8,
    pub reason: Vec<u8>, // 限制 199B
}
```

```
code(1B) │ reason(≤199B 人类可读)
```

- `SigPacket::error(code, reason)` 构造时将 reason 截断至 `BODY_MAX - 1 = 199` B。

#### 统一信封

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigPacket { pub header: SigHeader, pub body: SigBody }

pub enum SigBody {
    Commit(CommitBody),
    Reveal(RevealBody),
    CommitAck,
    Error(ErrorBody),
}

impl SigPacket {
    pub fn commit(body: CommitBody, algo: u8, flags: u8) -> Self
    pub fn reveal(body: RevealBody, algo: u8, flags: u8) -> Self
    pub fn commit_ack(algo: u8) -> Self
    pub fn error(code: u8, reason: impl Into<Vec<u8>>) -> Self
    pub fn encode(&self) -> Vec<u8>
    pub fn decode(buf: &[u8]) -> Option<Self>
}
```

- `commit` / `reveal` / `commit_ack` / `error` 四个便捷构造器自动填 `version = PROTO_VERSION`；`reveal` 的 `body_len = (16 + pubkey.len() + 32) as u8`。
- `decode` 校验链：头合法 → 总长 `== HEADER_LEN + body_len` → COMMIT 要求 body 恰 48B → REVEAL 按 algo 推 pubkey 长度（仅 X25519=32 放行）→ ERROR 要求 body 非空（至少含 1B code）。
- `CommitAck` 无 body（`body_len = 0`）。

#### 测试用例（5 个）

| 测试名 | 测什么 | 测试向量/断言 |
|---|---|---|
| `header_roundtrip` | 8B 头编解码往返一致 | `version=1, kind=COMMIT, algo=X25519, flags=REQUIRE_ACK, body_len=48`；`assert_eq!(h, h2)` |
| `commit_packet_roundtrip` | Commit 整包往返，总长 8+48=56B | `peer_id=[0xAB;16], commit=[0xCD;16]` |
| `reveal_packet_x25519_roundtrip` | X25519 Reveal 整包往返，总长 8+80=88B | `peer_id=[0x12;16], pubkey=[0x99;32], nonce=[0x33;32]` |
| `reject_bad_magic` | 魔数错误拒绝 | `[0x00,0x00,0x01,COMMIT,0x01,0x00,48,0x00]` → `decode` 为 `None` |
| `reject_truncated` | 不足 8B 的截断头拒绝 | 7B 缓冲 → `None` |

---

### 3.4 `src/packet.rs`（230 行）

**一句话职责**：数据面报文——打洞探针、心跳、种子广告的定长编解码，以及 UDP 收包的统一类型判定入口（与 `sig::` 信令包并列，用单一字节 type 区分场景；定长二进制 + 手写编解码，禁止 serde/protobuf）。

#### 探针（`Probe`，31B）

```rust
pub struct Probe {
    pub session_tag: [u8; 4],
    pub nonce: [u8; 4],
    pub timestamp: [u8; 8],
    pub auth_tag: [u8; 12],
}

pub mod probe {
    pub const TYPE: u8 = 0x10;
    pub const LEN: usize = 31;
    pub const AUTH_OFFSET: usize = 19;
    pub const AUTH_LEN: usize = 12;
    pub fn encode(p: &Probe, out: &mut [u8; LEN]) { /* ... */ }
    pub fn decode(buf: &[u8]) -> Option<Probe> { /* ... */ }
}
```

字节布局（31B，03 §3.5.5）：

```
偏移  0..2      2       3..7          7..11        11..19         19..31
      ┌─────────┬───────┬─────────────┬─────────────┬──────────────┬──────────────┐
      │magic"WG"│type   │session_tag  │nonce        │timestamp     │auth_tag      │
      │         │=0x10  │(4B)         │(4B)         │(8B)          │(12B)         │
      └─────────┴───────┴─────────────┴─────────────┴──────────────┴──────────────┘
      └──────────────── 前 19B 为 HMAC 输入（AUTH_OFFSET=19）────────────────┘
```

- 源码注释：`AuthTag = HMAC-SHA256(punch_key, 前 19B) 截断 12B`——HMAC 计算不在本 crate，上层填 `auth_tag` 字段；本 crate 只固定"认证覆盖范围 = 前 19B"。
- `decode` 校验：长度恰 31、魔数匹配、type == 0x10。

#### 心跳（`heartbeat`，无结构体，纯函数模块）

```rust
pub mod heartbeat {
    pub const TYPE: u8 = 0x11;
    pub const LEN_BASE: usize = 19;
    pub const LEN_EXT: usize = 23;
    pub const AUTH_LEN: usize = 12;
    pub fn encode_base(seq: u32, auth_tag: [u8; 12], out: &mut [u8; LEN_BASE]) { /* ... */ }
    pub fn encode_ext(
        seq: u32,
        auth_tag: [u8; 12],
        cur_port: u16,
        prev_port: u16,
        out: &mut [u8; LEN_EXT],
    ) { /* ... */ }
}
```

基础形态（19B，03 §3.7.4）：

```
magic(2) │ type=0x11 │ seq(4B BE) │ auth_tag(12B)
```

步长扩展形态（23B）= 基础 19B +：

```
cur_port(2B BE) │ prev_port(2B BE)
```

- 扩展形态用于端口迁移时通告"当前端口 / 前一端口"，配合对端步长学习。
- ⚠️ 本模块**只有 encode，没有 decode**：收包侧按 UDP 报文长度（19 vs 23）分流的逻辑需上层实现（见 §6）。

#### 种子广告（`SeedAdvertise`，91B）

```rust
pub struct SeedAdvertise {
    pub addr_v4: [u8; 4],
    pub dht_port: u16,
    pub stun_port: u16,
    pub priority: u8,
    pub flags: u8,
    pub signature: [u8; 64],
}

pub mod seed_advertise {
    pub const TYPE: u8 = 0x20;
    pub const SIGNED_LEN: usize = 4 + 2 + 2 + 1 + 1;        // = 10
    pub const LEN: usize = 2 + 1 + SIGNED_LEN + 14 + 64;    // = 91
    pub fn encode_signed(
        addr_v4: [u8; 4], dht_port: u16, stun_port: u16,
        priority: u8, flags: u8, signature: [u8; 64],
        out: &mut [u8; LEN],
    ) { /* ... */ }
    pub fn signed_payload(buf: &[u8]) -> Option<&[u8]> { /* ... */ }
    pub fn extract(buf: &[u8]) -> Option<SeedAdvertise> { /* ... */ }
    pub fn payload_for_sign(
        addr_v4: [u8; 4], dht_port: u16, stun_port: u16,
        priority: u8, flags: u8,
    ) -> [u8; SIGNED_LEN] { /* ... */ }
}
```

字节布局（07 §5，DHT 内交换）：

```
偏移  0..2    2       3..7        7..9        9..11       11       12       13..27        27..91
      ┌───────┬───────┬───────────┬───────────┬───────────┬────────┬────────┬──────────────┬───────────┐
      │magic  │type   │addr_v4    │dht_port   │stun_port  │priority│flags   │reserved      │signature  │
      │"WG"   │=0x20  │(4B)       │(2B BE)    │(2B BE)    │(1B)    │(1B)    │(14B，置零)   │(64B)      │
      └───────┴───────┴───────────┴───────────┴───────────┴────────┴────────┴───────┬──────┴───────────┘
                                                                              │
      待签名字节 = buf[3..13]（SIGNED_LEN=10B）：addr_v4(4) ‖ dht_port(2) ‖ stun_port(2) ‖ priority(1) ‖ flags(1)
```

- `payload_for_sign` 构造的待签载荷与 `encode_signed`/`signed_payload` 提取的字节布局**严格一致**（源码注释明示）。
- `extract` 解析全部字段；ed25519 验签由上层用 `signed_payload` 拿到的 10B + `signature` 完成。
- ⚠️ 源码模块注释写"90B"，实际 `LEN = 91`（2+1+10+14+64）——**代码如此，意图待确认**（疑为注释笔误）。

#### 统一判定入口

```rust
/// 任意数据面报文的统一判定入口（用于 UDP 接收分流）
pub fn classify(buf: &[u8]) -> Option<u8> {
    if buf.len() < 3 { return None; }
    if buf[0..2] != SIG_MAGIC { return None; }
    Some(buf[2])
}
```

- 长度 ≥ 3 且魔数为 "WG" 时返回 type 字节，否则 `None`。
- ⚠️ 由于信令（`sig_type` 0x01-0x04）、数据面（0x10/0x11/0x20）、DHT RPC（`rpc_type` 0x30-0x38）共用同一魔数，`classify` **只返回 type 值、不区分协议族**；场景判定由调用方按值域完成（见 §6）。

#### 测试用例（3 个）

| 测试名 | 测什么 | 测试向量/断言 |
|---|---|---|
| `probe_roundtrip` | 31B 探针编解码往返 | `session_tag=[0xAA;4], nonce=[0xBB;4], timestamp=[0xCC;8], auth_tag=[0xDD;12]`；`assert_eq!(p, p2)` |
| `heartbeat_base_len` | 基础心跳编码后长度恒为 19 | `encode_base(0x01020304, [0xEE;12], &mut buf)`；`buf.len() == LEN_BASE` |
| `seed_advertise_payload_isolation` | 待签载荷长度恰为 SIGNED_LEN=10 | `payload_for_sign([1,2,3,4], 3841, 3478, 0x05, 0x01)` |

---

### 3.5 `src/dht.rs`（590 行）

**一句话职责**：DHT RPC 报文（Kademlia 变种，07 文档网络层格式）的全部包体与统一信封编解码——头 7B：magic(2)="WG" | type(1) | txid(4B)，全部手写编解码，Neighbors 上限 K=20。

#### 常量

```rust
pub const RPC_HEADER_LEN: usize = 7;

pub mod rpc_type {
    pub const PING: u8 = 0x30;
    pub const PONG: u8 = 0x31;
    pub const FIND_NODE: u8 = 0x32;
    pub const NEIGHBORS: u8 = 0x33;
    /// 致某 NodeId 的投递（承诺-揭示/打洞参数/协调消息；不可信转发语义）
    pub const FORWARD: u8 = 0x34;
    /// 键值存储（房间记录/打洞会话宿主，07 §4 K=1 简化）
    pub const STORE: u8 = 0x35;
    pub const STORED_ACK: u8 = 0x36;
    pub const FIND_VALUE: u8 = 0x37;
    pub const VALUE: u8 = 0x38;
}

pub const K: usize = 20;                  // Kademlia 常量
pub const STORE_VALUE_MAX: usize = 1024;  // 存储值上限（房间记录 4 成员 ≈ 300B；1KB 足够 v1）
pub const FORWARD_PAYLOAD_MAX: usize = 600;
```

#### 节点地址条目 `NodeEntry`（38B）

```rust
pub struct NodeEntry {
    pub id: [u8; 32],
    pub ipv4: [u8; 4],
    pub port: u16,
}
impl NodeEntry {
    pub const LEN: usize = 38;
    pub fn encode(&self, out: &mut [u8; Self::LEN]) { /* ... */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* ... */ }
}
```

```
id(32B) │ ipv4(4B) │ port(2B BE)
```

`decode` 要求 `buf.len() == 38`。

#### 各报文包体

| 类型 | 结构 | 体长 | 字节布局 |
|---|---|---|---|
| `PingBody`（PING/PONG 共用） | `node_id: [u8;32], pubkey: [u8;32]`，`BODY_LEN=64` | 64B | `node_id(32) ‖ pubkey(32)`——携带发送方 NodeId + 长期公钥（身份发布） |
| `FindNodeBody` | `target: [u8;32]`，`BODY_LEN=32` | 32B | `target(32)` |
| `NeighborsBody` | `nodes: Vec<NodeEntry>` | 1 + n×38 | `count(1B) ‖ count×NodeEntry`；decode 拒 `count > K(20)` 与长度不符 |
| `ForwardBody` | `target: [u8;32], payload: Vec<u8>` | 34 + n | `target(32) ‖ len(2B BE) ‖ payload(≤600B)` |
| `StoreBody` | `sender:[u8;32], pubkey:[u8;32], key:[u8;32], value: Vec<u8>`，`PREFIX_LEN=98` | 98 + n | `sender(32) ‖ pubkey(32) ‖ key(32) ‖ len(2B BE) ‖ value(≤1024B)` |
| `FindValueBody` | `key: [u8;32]`，`BODY_LEN=32` | 32B | `key(32)` |
| `ValueBody` | `key: [u8;32], value: Vec<u8>` | 34 + n | `key(32) ‖ len(2B BE) ‖ value(≤1024B)`；**空值 = 未命中**（v1 简化单跳存储语义） |

签名照抄（各体 encode/decode 模式一致，摘其要）：

```rust
impl NeighborsBody {
    pub fn encode(&self) -> Vec<u8> { /* count(1B) + count×NodeEntry */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* 拒 count>K、拒长度不符 */ }
}
impl ForwardBody {
    /// 超限载荷静默截断（防御性写端语义；读端见 decode 拒绝逻辑）
    pub fn encode(&self) -> Vec<u8> { /* payload 截断至 FORWARD_PAYLOAD_MAX=600 */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* buf.len()<34 拒；len>600 拒；总长必须恰 34+len */ }
}
impl StoreBody {
    /// 定长前缀：sender + pubkey + key + 值长 2B
    pub const PREFIX_LEN: usize = 98;
    pub fn encode(&self) -> Vec<u8> { /* value 截断至 STORE_VALUE_MAX=1024 */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* len>1024 拒；总长必须恰 98+len */ }
}
```

`StoreBody` 源码注释的安全语义（v1 K=1 简化）：
- `sender` 让存储节点学习写入者身份 → 后续 Forward 可路由回锚点（07 §4 报道路由）。
- `pubkey` 与 `sender` **必须通过 SHA-256 绑定校验**（防冒充写入者毒化地址簿/冒占 KV 配额）——该校验不在本 crate（零依赖），由上层执行。

⚠️ `ForwardBody` 源码注释的字段描述为"len(2B) + 投递目标 NodeId(32B) + 透明载荷"，但 `encode` 实际写入顺序是 `target(32) ‖ len(2) ‖ payload`——**以代码为准，注释顺序描述有误（代码如此）**。

#### 统一信封

```rust
pub struct RpcHeader { pub kind: u8, pub txid: u32 }
impl RpcHeader {
    pub fn encode(&self, out: &mut [u8; RPC_HEADER_LEN]) { /* magic+kind+txid(BE) */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* 校验魔数 + kind ∈ 0x30..=0x38 白名单 */ }
}

pub enum RpcBody {
    Ping(PingBody), Pong(PingBody),
    FindNode(FindNodeBody), Neighbors(NeighborsBody),
    Forward(ForwardBody), Store(StoreBody),
    StoredAck,
    FindValue(FindValueBody), Value(ValueBody),
}

pub struct RpcPacket { pub header: RpcHeader, pub body: RpcBody }
impl RpcPacket {
    pub fn ping(txid: u32, body: PingBody) -> Self
    pub fn pong(txid: u32, body: PingBody) -> Self
    pub fn find_node(txid: u32, body: FindNodeBody) -> Self
    pub fn neighbors(txid: u32, body: NeighborsBody) -> Self
    pub fn forward(txid: u32, body: ForwardBody) -> Self
    pub fn store(txid: u32, body: StoreBody) -> Self
    pub fn stored_ack(txid: u32) -> Self
    pub fn find_value(txid: u32, body: FindValueBody) -> Self
    pub fn value(txid: u32, body: ValueBody) -> Self
    pub fn encode(&self) -> Vec<u8>   // 7B 头 + 各体编码；StoredAck 无体
    pub fn decode(buf: &[u8]) -> Option<Self>
}
```

RPC 头字节布局（7B）：

```
偏移  0..2      2        3..7
      ┌─────────┬─────────┬──────────────────┐
      │magic    │kind     │txid              │
      │"WG"     │rpc_type │(4B BE)           │
      └─────────┴─────────┴──────────────────┘
```

- `RpcHeader::decode` 的 kind 白名单 = `rpc_type` 全部 9 个值（0x30-0x38），其余拒绝。
- `RpcPacket::decode` 先解头，剩余字节按 kind 分发到对应 body 的 decode；任一失败整体 `None`。
- FORWARD 的设计语义（源码注释）："致某 NodeId 的投递（承诺-揭示/打洞参数/协调消息；**不可信转发语义**）"——中间节点只按 target 转发，不解析载荷。

#### 测试用例（8 个）

| 测试名 | 测什么 | 测试向量/断言 |
|---|---|---|
| `ping_roundtrip` | Ping 整包往返，总长 7+64=71B | `node_id=[0xA1;32], pubkey=[0xB2;32]`，`txid=0x0102_0304` |
| `neighbors_roundtrip` | 2 节点 Neighbors 往返 | 条目1 `id=[0x11;32], ip=[127,0,0,1], port=3841`；条目2 `id=[0x22;32], ip=[10,0,0,2], port=9999`；`txid=7` |
| `store_roundtrip_with_pubkey` | Store 带 pubkey 往返 | `sender=[0xA1;32], pubkey=[0xB2;32], key=[0xC3;32], value=300×0x42`，`txid=9` |
| `store_truncated_rejected` | 旧格式（无 pubkey 的 66B 前缀）必须解码失败——协议代际隔离 | 手工构造 64B 零 + `0u16` 长度 + STORE 头 → `decode` 为 `None` |
| `forward_payload_integrity` | Forward 透明载荷字节级完整 | `payload=[0xDE,0xAD,0xBE,0xEF]`，`target=[0x99;32]`，`txid=42`；解出 payload 逐字节相等 |
| `oversize_forward_rejected_decode` | 超限载荷（601B）必须拒绝 | 手工构造 `target(32B 零) ‖ len=601 ‖ 601B 零` + FORWARD 头 → `None` |
| `unknown_type_rejected` | 未知类型拒绝 | 头 kind=0xFF → `RpcHeader::decode` 为 `None` |
| `bad_magic_rejected` | 魔数错误拒绝 | 7B 全零 → `None` |

---

### 3.6 `src/stun.rs`（302 行）

**一句话职责**：STUN 最小子集（RFC 8489：Binding + XOR-MAPPED-ADDRESS + 观察者扩展属性），客户端/服务端同源一套编解码、两级能力（07 §3）。

#### 常量

```rust
pub const MAGIC_COOKIE: u32 = 0x2112_A442;   // RFC 8489 magic cookie
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

pub mod wgp_attr {
    /// (4B PeerId | 8B Nonce | 8B Timestamp | 4B Flags)
    pub const WGP_PEER: u16 = 0x80F0;
    /// (2B Proto | 2B MTU | 4B RTT 预算提示)
    pub const WGP_LINK: u16 = 0x80F1;
    /// (打洞协调参数：对端 IP:Port、T_offset、窗口参数)
    pub const WGP_PUNCH: u16 = 0x80F2;
}
```

- `wgp_attr` 三属性取自 0x80F0-0x80F2（RFC 8489 未注册区），为折跃门观察者协议专用（07 §3）。
- ⚠️ `WGP_LINK` / `WGP_PUNCH` 目前**只有常量与注释中的布局，没有编解码函数**（见 §6）。

#### STUN 报文头 `StunHeader`（20B）

```rust
pub struct StunHeader {
    pub msg_type: u16,
    pub len: u16,
    pub cookie: u32,
    pub tx_id: [u8; 12],
}
impl StunHeader {
    pub fn encode(&self, out: &mut [u8; 20]) { /* ... */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* cookie 不匹配直接拒绝 */ }
    pub fn is_binding_request(&self) -> bool { self.msg_type == BINDING_REQUEST }
}
```

```
偏移  0..2        2..4      4..8                8..20
      ┌───────────┬─────────┬────────────────────┬──────────────┐
      │msg_type   │len      │cookie              │tx_id         │
      │(2B BE)    │(2B BE)  │0x2112A442          │(12B)         │
      └───────────┴─────────┴────────────────────┴──────────────┘
```

- `decode` 要求 ≥ 20B 且 `cookie == MAGIC_COOKIE`（快速过滤非法包）；`len` 为消息体长度（不含 20B 头）。
- `is_binding_request` 是头结构上唯一的语义判定 helper。

#### 观察者扩展属性 `WgpPeerAttr`（24B 载荷）

```rust
pub const WGP_PEER_PAYLOAD_LEN: usize = 24;

pub struct WgpPeerAttr {
    pub peer_prefix: [u8; 4],
    pub nonce: [u8; 8],
    pub timestamp: [u8; 8],
    pub flags: [u8; 4],
}
impl WgpPeerAttr {
    pub fn encode(&self, out: &mut [u8; WGP_PEER_PAYLOAD_LEN]) { /* ... */ }
    pub fn decode(buf: &[u8]) -> Option<Self> { /* 要求恰 24B */ }
}
```

```
peer_prefix(4B) │ nonce(8B) │ timestamp(8B) │ flags(4B)
```

- 语义（源码注释，07 §3）：观察者**原样回显**，客户端据 Nonce 关联请求并测量往返。

#### "绑定探测"抽象 `BindingProbe`

```rust
pub struct BindingProbe {
    pub tx_id: [u8; 12],
    /// 目标观察者地址（含端口，由部署配置注入，协议层不设默认端口）
    pub observer: (std::net::IpAddr, u16),
}
impl BindingProbe {
    pub fn new(tx_id: [u8; 12], observer_ip: std::net::IpAddr, port: u16) -> Self { /* ... */ }
}
```

- 源码注释：步长学习（3 连测）、NAT 判定（双异 IP）、UDP 出站预判、观察者报告全部经由本类型（00 §5 / 15 Phase 0、4）。
- **协议层不持有部署端口**：观察者 IP:port 由引擎/应用配置显式经 `new` 注入。

#### 属性序列编解码

```rust
/// 编码一个 STUN 属性（type 2B + len 2B + value）
pub fn encode_attr(attr_type: u16, value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    // 属性 4B 对齐（填充 0）
    let pad = (4 - value.len() % 4) % 4;
    out.extend_from_slice(&vec![0u8; pad]);
}

/// 解码属性序列；返回 (type, value)。Bogus 属性直接终止（RFC 8489 合规）
pub fn decode_attrs(buf: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> { /* ... */ }
```

STUN 属性 TLV 布局（RFC 8489）：

```
type(2B BE) │ len(2B BE，真实值长) │ value(len B) │ pad(0..3B，补至 4B 对齐)
```

- `decode_attrs` 循环解析至恰耗尽 buffer；任一属性越界（`i+4+len > buf.len()`）或收尾不齐（`i != buf.len()`）整体 `None`。
- 注意 `len` 字段写真实长度、不含 pad；读侧按 `len` 取值、按 `len+pad` 步进。

#### XOR-MAPPED-ADDRESS

```rust
/// 编码 XOR-MAPPED-ADDRESS 的 value（RFC 8489：reserved(1) | family(1) | xport(2) | xaddr(4)）
pub fn xor_mapped_value(ipv4: [u8; 4], port: u16) -> [u8; 8] {
    out[0] = 0x00;
    out[1] = 0x01; // IPv4
    let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
    out[2..4].copy_from_slice(&xport.to_be_bytes());
    for i in 0..4 {
        out[4 + i] = ipv4[i] ^ (MAGIC_COOKIE >> (24 - i * 8)) as u8;
    }
    out
}

/// 解码 XOR-MAPPED-ADDRESS value → (ipv4, port)
pub fn decode_xor_mapped(value: &[u8]) -> Option<([u8; 4], u16)> { /* 要求 len==8 且 family==0x01 */ }
```

```
0x00 │ 0x01(IPv4) │ xport(2B BE) │ xaddr(4B)
```

- `xport = port ^ (MAGIC_COOKIE >> 16)`（即 XOR cookie 高 16 位）；`xaddr[i] = ipv4[i] ^ cookie 第 i 字节`。
- **仅支持 IPv4**（family 硬编码 0x01）；IPv6 不在实现内（见 §6）。

#### Binding 报文构造

```rust
/// 构造 Binding Request（客户端侧：可选携带 WGP-PEER 扩展，观察者回显）
pub fn binding_request(tx_id: &[u8; 12], echo_peer: Option<&WgpPeerAttr>) -> Vec<u8> { /* ... */ }

/// 构造 Binding Success Response：响应头 + XOR-MAPPED-ADDRESS + 回显 WGP-PEER（若有）
pub fn binding_response(
    req_tx_id: &[u8; 12],
    src_ipv4: [u8; 4],
    src_port: u16,
    echo_peer: Option<&WgpPeerAttr>,
) -> Vec<u8> { /* ... */ }
```

- 两者都采用"先写头（len 占位 0）→ 写属性 → 回填 `len = out.len() - 20`"的两遍式构造。
- `binding_request`：BINDING_REQUEST 头 + 可选 WGP-PEER 属性（请求观察者回显）。
- `binding_response`：BINDING_RESPONSE 头 + XOR-MAPPED-ADDRESS（报告对方看到的 IP:port）+ 可选 WGP-PEER 回显。

#### 测试用例（4 个）

| 测试名 | 测什么 | 测试向量/断言 |
|---|---|---|
| `xor_mapped_roundtrip` | XOR 映射往返一致 + 异或值不得等于明文（防中间盒识别） | `([203,0,113,9], 41107)`；`assert_ne!(&value[4..8], &ip)` |
| `wgp_peer_attr_roundtrip` | 24B 观察者属性往返 | `peer_prefix=[1,2,3,4], nonce=[9;8], timestamp=[7;8], flags=[0,0,0,1]` |
| `binding_response_parses_back` | 构造的响应可被自产解码器完整还原 | `txid=[0x5A;12], src=127.0.0.1:4567, echo={peer_prefix=[9,9,9,9], nonce=[1;8], timestamp=[2;8], flags=[0;4]}`；断言头 msg_type、tx_id、映射地址、回显属性全部相等 |
| `attr_padding_handled` | 5B value 的 4B 对齐 pad | `encode_attr(0x1234, &[1,2,3,4,5])` → 总长 12B（4 头 + 5 值 + 3 pad）；解出 len 字段语义正确（值为 `[1,2,3,4,5]`） |

---

### 3.7 `src/endpoint.rs`（182 行）

**一句话职责**：种子/服务器端点解析（07 §5 种子发现第 1 层的可配置形态）——支持 `udp://host:port`、`tcp://host:port`、裸 `ip:port`、裸 `host:port`（默认 udp），host 允许 IDN 中文域名，解析前经 `punycode::domain_to_ascii` 归一化。

#### 类型

```rust
/// 端点 scheme（udp=信令主通道；tcp=UDP 被封/受限时的信令兜底）
pub enum SeedScheme { Udp, Tcp }

/// 服务器端点 = scheme + host（域名或 IPv4）+ 端口
pub struct SeedEndpoint {
    pub scheme: SeedScheme,
    pub host: String,
    pub port: u16,
}

pub enum ParseError {
    Empty,      // 输入为空
    BadScheme,  // 不认识的 scheme（如 http://）
    BadPort,    // 端口缺失/非数字/越界
    BadHost,    // 主机为空
    TooLong,    // 超长主机名
}
```

#### 函数

```rust
impl SeedEndpoint {
    /// 解析：udp://host:port | tcp://host:port | host:port | ipv4:port
    pub fn parse(input: &str) -> Result<Self, ParseError> { /* ... */ }

    /// 回显（规范化字符串，配置展示用；保留原始 host 便于人读）
    pub fn display(&self) -> String { /* "udp://host:port" / "tcp://host:port" */ }

    /// 批量解析种子端点串（配置层用：逗号/分号/空白/换行分隔，忽略空项）。
    /// 返回 (成功列表, 失败项) —— 由调用方决定"容忍部分失败"还是"启动即报错"。
    pub fn parse_list(input: &str) -> (Vec<SeedEndpoint>, Vec<String>) { /* ... */ }

    /// 用于 DNS 解析的 ASCII 主机名（IDN 中文域名 → punycode；纯 ASCII/IPv4 原样）。
    pub fn host_ascii(&self) -> String {
        crate::punycode::domain_to_ascii(&self.host)
    }
}
```

`parse` 的处理链（照代码顺序）：
1. `trim()`；空 → `Empty`。
2. `split_once("://")` 拆 scheme；无 scheme 或 `udp`/`UDP` → `Udp`；`tcp`/`TCP` → `Tcp`；其他 → `BadScheme`。
3. `rfind(':')` 找最后一个冒号，且**要求冒号前的 host 部分不再含冒号**（即不支持 IPv6 字面量；含多个冒号 → `BadPort`）；找不到冒号（裸域名/IP 无端口）→ `BadPort`（端点必须指定端口）。
4. host 空 → `BadHost`；`host.len() > 253` → `TooLong`。
5. 端口 `parse::<u16>()`，失败 → `BadPort`；`port == 0` → `BadPort`。

**设计要点与约束**：
- scheme 大小写不敏感（`UDP://`、`TCP://` 均接受）；无 scheme 时默认 udp（udp 是信令主通道，tcp 是 UDP 被封时的兜底）。
- `display()` 输出规范化串但保留原始（可能含 Unicode 的）host；`host_ascii()` 才做 punycode 归一化——"人读用原样、机读用 ACE"的分工。
- `parse_list` 按 `,` `;` 及任意空白切分，返回 `(成功, 失败原文)` 二元组，把"部分失败容忍策略"上抛给调用方。
- host 只校验非空与 ≤253 字节，不做 DNS 语法强校验（如连续点号、以 `-` 开头等不拦）。

#### 测试用例（8 个）

| 测试名 | 测什么 | 测试向量/断言 |
|---|---|---|
| `parse_udp_scheme_with_domain` | udp scheme + 域名正常解析与回显 | `udp://seed.example.com:3841` → `(Udp, "seed.example.com", 3841)`；`display()` 往返一致 |
| `parse_bare_ip_port` | 裸 IPv4:port 默认 udp | `120.53.11.77:3841` → `(Udp, "120.53.11.77", 3841)` |
| `parse_bare_domain_port` | 裸域名:port 默认 udp | `seed.wgp.dev:3478` → host/port 正确 |
| `reject_bad_inputs` | 6 类非法输入逐一拒绝 | `""`→Empty；`http://x.com:11010`→BadScheme；`udp://:3841`→BadHost；`udp://x.com`→BadPort；`udp://x.com:0`→BadPort；`udp://x.com:abc`→BadPort；`udp://x.com:99999`→BadPort |
| `parse_tcp_scheme` | tcp scheme 解析与回显 | `tcp://seed.example.com:3841` → `(Tcp, ..., 3841)` |
| `parse_udp_idn_host_ascii` | IDN 主机名归一化 | `udp://münchen.example:3841` → `host == "münchen.example"`（原样保留），`host_ascii() == "xn--mnchen-3ya.example"` |
| `parse_list_splits_and_reports_bad` | 批量解析切分 + 失败项上报 | `"udp://a.example:1, tcp://b.example:2\n http://c.example:3"` → ok=2（Udp/Tcp 各一），bad=`["http://c.example:3"]` |
| `uppercase_scheme_ok` | scheme 大写接受 | `UDP://x.com:3841`→Udp；`TCP://x.com:3481`→Tcp |

---

### 3.8 `src/punycode.rs`（144 行）

**一句话职责**：极简 IDN 处理——RFC 3492 Punycode **仅"Unicode → ASCII(xn--)"编码方向**；动机是非 ASCII 域名（münchen.de、中文域名）在 Linux/glibc 上 getaddrinfo 无法解析且 Rust 标准库不做 IDN 归一化，内核在解析前统一转成 ACE 形态。纪律：零依赖、纯函数、无 IO、无 Unicode 表。

#### 私有常量与函数（RFC 3492 参数）

```rust
const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;

fn encode_digit(d: u32) -> char { /* d<26 → 'a'+d；否则 → '0'+(d-26) */ }
fn adapt(mut delta: u32, numpoints: u32, first_time: bool) -> u32 { /* RFC 3492 §6.3 bias 自适应 */ }
fn encode_label(input: &[char]) -> String { /* 基本码点前置 + '-' 分隔 + 差值编码主循环 */ }
```

#### 公开函数

```rust
/// 单标签 → ACE 标签（先按 IDNA 规则小写；非 ASCII 加 `xn--` 前缀；纯 ASCII 原样返回）。
pub fn label_to_ascii(label: &str) -> String {
    let lower = label.to_lowercase();
    if lower.is_ascii() { return lower; }
    let chars: Vec<char> = lower.chars().collect();
    format!("xn--{}", encode_label(&chars))
}

/// 域名 → ASCII（punycode）域名，逐标签处理，`.` 分隔。
/// 已是 ASCII 的域名原样返回（幂等）。
pub fn domain_to_ascii(domain: &str) -> String {
    domain.split('.').map(label_to_ascii).collect::<Vec<_>>().join(".")
}
```

**设计要点与约束**：
- 只做编码不做解码（xn-- → Unicode 的解码不需要：机读只用 ACE）。
- IDNA 小写归一化在 `label_to_ascii` 内完成（`to_lowercase()`），因此 `München` → `mnchen-3ya`。
- 对纯 ASCII 输入幂等（`xn--fiqs8s` 原样返回），可安全重复调用。
- 无 Unicode 属性表：大小写映射委托 `str::to_lowercase()`（std 内部实现），其余全靠 RFC 3492 算术。

#### 测试用例（3 个，测试向量完整抄录）

| 测试名 | 测什么 | 测试向量（源码注明：RFC 3492 算法 + 与 Python `str.encode('punycode')` 逐字交叉验证） |
|---|---|---|
| `known_vectors` | 中文标签与 IDNA 小写归一化 | `label_to_ascii("中国") == "xn--fiqs8s"`；`"北京" → "xn--1lq90i"`；`"上海" → "xn--fhqz97e"`；`"测试" → "xn--0zwm56d"`；`"我爱你" → "xn--6qq986b3xl"`；`"München" → "xn--mnchen-3ya"` |
| `ascii_passthrough_idempotent` | ASCII 直通 + 幂等 | `"example"→"example"`；`"xn--fiqs8s"→"xn--fiqs8s"`；`domain_to_ascii("seed.example.com")` 原样；`domain_to_ascii("xn--fiqs8s.com")` 原样 |
| `mixed_domain` | 混合中英文域名逐标签处理 | `domain_to_ascii("münchen.de") == "xn--mnchen-3ya.de"`；`domain_to_ascii("münchen.example") == "xn--mnchen-3ya.example"` |

---

### 3.9 `src/room_code.rs`（243 行）

**一句话职责**：U/ 房间码派生（13 文档的唯一权威实现）——从 (房间名称, 房间密钥) **确定性**派生 16 字符房间码：`U/` + 4×4 字符（连字符分组），末 2 位 = 命中时的进制（10..=36）。

安全边界（13 §6，源码注释）：MD5 仅作**标识符派生**，非认证、非加密、非签名；房间密钥不参与任何密钥材料派生，泄漏 U/ 码不影响会话加密。本模块自实现 MD5 以维持零依赖纪律（00 §3）。

#### 常量

```rust
/// MD5 输出长度（字节）
pub const ROOM_CODE_LEN: usize = 16;

// 以下为私有：
const BASE_MIN: u32 = 11;        // 单轮扫掠的进制下界（index 从 36 递减到 11，index < 11 触发降级）
const BASE_RESET: u32 = 37;      // 单轮扫掠的进制上界（index 复位值，首轮 -1 得 36）
const IF_INDEX_START: usize = 14;// 命中截取长度（14 → 13 → 12 降级；<=0 兜底）
const BODY_LEN: usize = 14;      // 房间码主体长度（不含末 2 位进制）
```

#### 主函数

```rust
/// 从 (房间名称, 房间密钥) 确定性派生 U/ 房间码（13 §2 算法规范）。
///
/// 同输入恒同输出，跨语言/跨平台一致。末 2 位为命中时的进制。
pub fn derive_room_code(name: &str, key: &str) -> String { /* ... */ }
```

算法流程（照代码）：

```
loop:
    index -= 1                                  # 首轮 37-1 = 36（36 进制）
    raw    = format!("{name}{index}{key}")      # 名称 + 进制数 + 密钥 拼接
    num    = u128::from_be_bytes(md5(raw))      # MD5 当 128 位大整数
    result = to_base(num, index)                # 转 index 进制字符串（0-9A-Z）
    trimmed = result.trim_end_matches('0')      # 去末尾 '0'
    candidate = trimmed.chars().take(ifindex)   # 截前 ifindex 位
    candidate = candidate.map('I'→'1', 'O'→'0') # 消歧补丁（1:1 替换，长度不变）
    if candidate.len() == ifindex: break candidate   # 命中
    if index < BASE_MIN(11):                    # 整轮扫掠无命中 → 降级
        index = BASE_RESET(37)
        if ifindex == 0: break "A".repeat(14)   # 极端兜底
        ifindex -= 1                            # 14 → 13 → 12 …
body = candidate 补 'A' 至 14 字符
full = body + format!("{index:02}")             # 末 2 位 = 命中进制（十进制）
返回 "U/" + full 按 4 字符分组 '-' 连接
```

#### 辅助函数

```rust
/// u128 → 任意进制字符串（字符表 `0-9A-Z`，大写）
fn to_base(mut num: u128, base: u32) -> String {
    const DIGITS: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /* num==0 → "0"；否则反复取模反序输出 */
}

/// 自实现 MD5（RFC 1321）。仅用于标识符派生，不作任何安全承诺（13 §6）。
pub fn md5(input: &[u8]) -> [u8; 16] { /* ... */ }
```

`md5` 实现要点：标准 S[64] 移位表与 K[64] 常量表（`0xd76aa478` 起，与 RFC 1321 逐字一致）；初始向量 `a0=0x67452301, b0=0xefcdab89, c0=0x98badcfe, d0=0x10325476`；填充规则为 `0x80` 后补零至 `≡ 56 (mod 64)`、末尾 8 字节**小端**位长；四轮非线性函数 F/G 选择与 RFC 一致（`0..=15` 用 `(b&c)|(!b&d)`，`16..=31` 用 `(d&b)|(!d&c)`，`32..=47` 用 `b^c^d`，其余用 `c^(b|!d)`）；全部运算 `wrapping_*`。

**设计要点与约束**：
- 输出格式：`U/XXXX-XXXX-XXXX-XXXX`，共 16 字符主体（`ROOM_CODE_LEN`）+ 3 个连字符 + `U/` 前缀。
- 末 2 位是**十进制的命中进制**（10..=36，`{:02}` 定宽），解码方可知该码由几进制生成。
- 消歧补丁：`'I'→'1'`、`'O'→'0'`，消除人眼易混字符（1:1 替换不改变长度，故命中判定不受影响）。
- 确定性：同一 (name, key) 恒得同一码；密钥参与拼接串，换密钥即换码。
- 命中条件 `candidate.chars().count() == ifindex`：去尾零后再截取，可能不足长，不足则降级重扫。

#### 测试用例（5 个，**4 组标准向量完整抄录**）

| 测试名 | 测什么 | 测试向量/断言 |
|---|---|---|
| `md5_rfc1321_vectors` | 自实现 MD5 与 RFC 1321 标准向量一致 | `md5(b"") == d41d8cd98f00b204e9800998ecf8427e`；`md5(b"a") == 0cc175b9c0f1b6a831c399e269772661`；`md5(b"abc") == 900150983cd24fb0d6963f7d28e17f72`；`md5(b"message digest") == f96b697d7cb7938d525a2f31aaf161d0`；`md5(b"abcdefghijklmnopqrstuvwxyz") == c3fcd3d76192e4007dfb496cca67e13b` |
| `standard_vectors_match_doc13` | 与设计文档 13 的 4 组标准向量一致 | `derive_room_code("示例房间", "123456") == "U/C2G9-GYET-311W-R636"`；`derive_room_code("test-room", "abc123") == "U/6U01-TWHM-B7H0-CV36"`；`derive_room_code("MC联机", "9999") == "U/48WY-WMLN-8XDA-FA36"`；`derive_room_code("a", "b") == "U/8SRU-FM1Q-XTDQ-LL36"` |
| `format_is_stable` | 输出格式恒定：`U/` 前缀 + 4 组 × 4 字符 + 末 2 位进制 ∈ [10,36] | 输入 `("任意房间", "任意密钥")`；断言分组数 4、每组 4 字符、展平 16 字符、`flat[14..16].parse::<u32>() ∈ 10..=36` |
| `derivation_is_deterministic_and_sensitive` | 确定性与密钥敏感性 | `derive("room","key") == derive("room","key")`；`derive("room","key") != derive("room","key2")` |
| `disambiguation_patch_applied` | 消歧补丁在全空间生效（输出不含 I/O） | 对 `n ∈ 0..2000`，`derive_room_code(&format!("n{n}"), &format!("k{n}"))` 的主体均不含 `'I'` 与 `'O'` |

---

## 4. 对外 API 汇总（lib.rs 的 `pub use` 全量清单）

`lib.rs` 的全部再导出仅 4 项（其余 API 一律经模块路径访问，如 `wgp_proto::sig::SigPacket`、`wgp_proto::dht::RpcPacket`）：

```rust
pub use endpoint::{ParseError, SeedEndpoint, SeedScheme};
pub use room_code::derive_room_code;
```

| 再导出项 | 类型 | 用途 |
|---|---|---|
| `SeedEndpoint` | struct | 种子端点（scheme + host + port），含 `parse` / `display` / `parse_list` / `host_ascii` |
| `SeedScheme` | enum（Udp/Tcp） | 端点传输 scheme |
| `ParseError` | enum | 端点解析错误分类（Empty/BadScheme/BadPort/BadHost/TooLong） |
| `derive_room_code` | fn(&str, &str) -> String | U/ 房间码派生 |

> 说明：`SIG_MAGIC`、`SigPacket`、`RpcPacket`、`StunHeader`、`classify`、`md5` 等虽为各模块 `pub`，但未在 crate 根再导出，使用方需写全模块路径。

---

## 5. 与设计文档的对应关系

| 设计文档 | 代码内引用的章节 | 在本 crate 的落地 |
|---|---|---|
| docs/00 总纲 | §1 H 约束、§3 纪律、§5、§11 版本化纪律 | `consts.rs` 全部常量（H6 打洞预算 47/500）；lib.rs 模块划分与"无 IO/async/零依赖/禁 serde"纪律（sig.rs、packet.rs 注释明示）；`PROTO_VERSION` |
| docs/08 包格式 | —（包格式权威） | `sig.rs`（信令包 8B 头 + 4 体）、`packet.rs`（探针 31B/心跳 19/23B/种子广告 91B）、`dht.rs`（RPC 7B 头 + 9 体）、`stun.rs`（STUN 20B 头 + TLV 属性） |
| docs/07 观察者协议/网络层/房间 | §3（STUN 扩展，客户端/服务端同源两级能力）、§4（房间/锚点、K=1 简化 KV、报道路由）、§5（种子发现） | `stun.rs` 的 `wgp_attr`（WGP_PEER/LINK/PUNCH，0x80F0-0x80F2）、`BindingProbe`；`consts.rs` 的 `LEASE_INTERVAL_S`/`LEASE_TIMEOUT_S`/`ROOM_KEY_DOMAIN`；`dht.rs` 的 STORE/FORWARD/ValueBody（空值=未命中）；`endpoint.rs` 种子端点第 1 层 |
| docs/13 房间码 | §2 算法规范、§6 安全边界 | `room_code.rs` 全部（`derive_room_code` + 自实现 `md5` + 消歧补丁；"MD5 仅标识符派生、房间密钥不参与密钥材料派生"注释） |
| docs/03 打洞 | §3.2.3（魔数思路）、§3.5（三波探测）、§3.5.5（探针包）、§3.7.4（心跳） | `packet.rs` 的 `probe`/`heartbeat`；`consts.rs` 的 `WAVE1/2/3_PACKETS`、`WAVE_TIMEOUT_MS`、`PROBE_BUDGET_*`；`sig::SIG_MAGIC` 注释"与 03 §3.2.3 思路一致" |
| docs/14 协议版本化 | §11 | `consts.rs` 的 `PROTO_VERSION`；`sig.rs` 头部 version 字段（lib/sig 注释明示 14 §11） |
| docs/15 全链路流程 | Phase 0、4；各超时数字化 | `consts.rs` 超时组（COMMIT/QUIC/DEGRADED/OLD_LINK_GRACE）；`stun.rs` 的 `BindingProbe` 注释（步长学习/NAT 判定/出站预判/观察者报告） |

---

## 6. 已知限制或未实现项

以下均为通读源码确认的事实；标注"代码如此，意图待确认"的为注释与代码不一致或需向上游确认的点。

### 6.1 功能未实现 / 半成品

1. **Hybrid PQ 未实现**：`algo::HYBRID_PQ = 0x02` 常量已定义（注释"未来线"），但 `SigPacket::decode` 对 `header.algo != X25519` 一律返回 `None`——Hybrid 揭示包当前不可解析。
2. **心跳无解码器**：`heartbeat` 模块只有 `encode_base`/`encode_ext`，没有 decode；收包侧按长度（19B vs 23B）分流的逻辑需上层自行实现。
3. **WGP_LINK / WGP_PUNCH 只有常量**：`wgp_attr::WGP_LINK(0x80F1)`、`WGP_PUNCH(0x80F2)` 仅注释了布局（2B Proto|2B MTU|4B RTT 预算提示；对端 IP:Port、T_offset、窗口参数），无任何编解码函数。
4. **STUN 仅 IPv4**：`xor_mapped_value`/`decode_xor_mapped` 硬编码 family=0x01，无 IPv6 路径；`ATTR_MAPPED_ADDRESS`、`ATTR_FINGERPRINT` 常量已定义但无编解码函数，`binding_request`/`binding_response` 也不生成 FINGERPRINT。
5. **端点不支持 IPv6**：`SeedEndpoint::parse` 的冒号切分逻辑（`rest[..idx].find(':').is_none()`）使含多个冒号的 IPv6 字面量直接落入 `BadPort`。

### 6.2 安全计算外置（本 crate 只定布局）

6. **认证/签名计算均不在本 crate**：Probe/Heartbeat 的 `auth_tag`（HMAC-SHA256 截断 12B，覆盖前 19B）、Commit 的 `commit`（SHA-256 截断 16B）、StoreBody 的 `sender ↔ pubkey` SHA-256 绑定校验、SeedAdvertise 的 ed25519 签名/验签——本 crate 仅提供字段布局与 `signed_payload`/`payload_for_sign` 待签字节提取，实际密码学运算在 wgp-crypto 或上层。`md5` 是唯一例外（零依赖纪律下的自实现，且仅用于房间码标识符派生，13 §6 明确不作安全承诺）。
7. **SigHeader::decode 不校验 version**：任何 version 字节都被接受（只校验魔数与 kind）；协议版本协商/拒绝逻辑需上层实现。

### 6.3 注释与代码不一致（代码如此，意图待确认）

8. `consts.rs` 的 `MAGIC_PREFIX = b"wgp"` 注释称"探针/心跳魔数前缀"，但 packet.rs 探针/心跳实际使用 `sig::SIG_MAGIC`（"WG"）；且 `MAGIC_PREFIX` 在本 crate 内无任何引用。
9. `sig.rs` `CommitBody` 注释"承诺包（33B body）"，实际 `BODY_LEN = 48`（含 16B 保留位）。
10. `packet.rs` `seed_advertise` 注释"90B"，实际 `LEN = 91`（2+1+10+14+64）。
11. `dht.rs` `ForwardBody` 注释字段顺序"len(2B) + 目标 NodeId(32B) + 载荷"与 `encode` 实际顺序 `target(32) ‖ len(2) ‖ payload` 不符。

### 6.4 其他边界行为

12. **classify 不分协议族**：`classify` 只返回 type 字节；信令（0x01-0x04）、数据面（0x10/0x11/0x20）、DHT RPC（0x30-0x38）共用 "WG" 魔数，场景区分由调用方按值域判断。
13. **room_code 极端兜底**：整轮扫掠无命中且 `ifindex` 降为 0 时返回 `"AAAAAAAAAAAAAA" + "37"`，末 2 位 37 超出 [10,36] 约定（正常输入不可达；`format_is_stable` 仅覆盖常规输入）。
14. **读写端语义不对称（有意设计）**：`ForwardBody`/`StoreBody`/`ValueBody` 的 `encode` 对超限载荷**静默截断**（600B/1024B），`decode` 对超限**严格拒绝**；`NeighborsBody::encode` 的 `nodes.len() as u8` 在 >255 时会截断（无意义输入，decode 端 `count > K=20` 即拒）。
15. **ValueBody 空值二义**：空值表示"未命中"，无法区分"键不存在"与"存储了空值"（v1 简化语义，源码注释明示）。

---

*（完）本文档基于 2026-11-05 对 `kernel/wgp-proto/src` 全部 9 个文件、共 2099 行的逐行通读编写；所有签名、常量值、字节布局与测试向量均与源码逐字核对。*
