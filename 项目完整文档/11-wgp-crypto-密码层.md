# wgp-crypto 密码层详细文档

> - 源目录：`H:\mclink core\kernel\wgp-crypto`
> - 生成日期：2026-11-05
> - 对应设计文档：`docs/01-安全与加密算法`（§1.2.2 承诺-揭示、§1.2.3 HKDF、§1.2.4 全零共享密钥、§1.3 ICMP 逃生）、`docs/14`（§2 会话密钥族、§4 PQ 可插拔、§10 条款 3 SecretBox、§11 协议版本化）
> - 文档基于源码逐行阅读编写，关键签名照抄源码；凡源码与设计文档表述不一致或意图不明处，均标注"代码如此，意图待确认"。

---

## 1. Crate 概览

### 1.1 定位

`wgp-crypto` 是折跃门（wgp）workspace 的密码层 crate，是 `docs/01-安全与加密算法` 的代码化实现，并提供 `docs/14 §4` 规定的后量子（PQ）可插拔密钥协商 API。它位于依赖分层中的第二层：

```
wgp-proto（协议层，纯数据） → wgp-crypto（密码层，本 crate） → wgp-punch / wgp-dht → wgp-core
```

crate 自述（`Cargo.toml` description）：

> 折跃门密码层：承诺-揭示、HKDF、探针 HMAC、逃生 AEAD、KeyAgreement（PQ 可插拔，无 IO 无 async）

### 1.2 依赖

来自 `kernel/wgp-crypto/Cargo.toml`（全部为 workspace 统一版本）：

| 依赖 | 用途 |
|---|---|
| `x25519-dalek` | X25519 密钥协商（`StaticSecret` / `PublicKey`） |
| `rand_core` | 仅取 `CryptoRngCore` trait（密钥生成的 RNG 抽象，不绑定具体 RNG 实现） |
| `sha2` | SHA-256（承诺值计算） |
| `hkdf` | HKDF-SHA256（会话密钥族派生） |
| `hmac` | HMAC-SHA256（探针/心跳/逃生/LAN 认证标签） |
| `aes-gcm` | AES-256-GCM（ICMP 逃生帧加密） |
| `zeroize` | 密钥材料内存清零 |

dev-dependencies：`wgp-proto`（path = `../wgp-proto`），仅供 `handshake_test.rs` 集成测试使用。

### 1.3 纪律

`lib.rs` 头部注释声明的两条核心纪律：

1. **无 IO、无 async**：本 crate 不做任何网络/文件/时钟访问，所有函数均为纯计算；异步与传输完全由上层（wgp-punch / wgp-dht / wgp-core）负责。
2. **密钥材料全生命周期 zeroize**：秘密容器在取出后、析构时清零（见 `SecretBox`）。

### 1.4 零化原则的落地与边界

- 已落地：`SecretBox` 在 `take()` 成功后立即 `zeroize()` 自身，并实现 `Drop` 兜底清零；`x25519-dalek` 的 `StaticSecret` 由库自身保证 drop 清零（`ka.rs` 注释声称其内部使用 `Zeroizing`）。
- 未落地（详见第 6 节）：`SessionSecrets` 未实现 `Drop`/`ZeroizeOnDrop`，其 5 个密钥字段在结构体丢弃时不会主动清零；HKDF 中间输出 `okm: [u8; 144]` 为栈上临时数组，派生后未清零；`KeyAgreement::agree` 返回的 `Vec<u8>` 共享密钥亦无零化包装。

---

## 2. 模块结构总表

| 文件 | 职责 | 关键导出 |
|---|---|---|
| `src/lib.rs` | crate 根：模块声明 + 一次性秘密容器 + 密码学档位枚举 | `SecretBox`、`CryptoProfile` |
| `src/commit.rs` | 承诺-揭示（Commit-Reveal），防不可信转发者替换公钥 | `Commitment`、`commit`、`verify`、`is_collision` |
| `src/derive.rs` | HKDF 会话密钥族派生 + 各用途 HMAC 截断标签 | `SALT_DOMAIN`、`SessionSecrets`、`derive_all`、`probe_auth`、`hb_auth`、`escape_auth`、`lan_auth` |
| `src/escape.rs` | ICMP 逃生通道 AES-256-GCM 帧编解码 | `EscapeCodec` |
| `src/ka.rs` | 可插拔密钥协商 trait 与 X25519 现役实现（PQ 预留） | `KeyAgreement`、`X25519Agreement`、`HybridPqAgreement`（占位）、`AnyAgreement` |
| `src/handshake_test.rs` | 端到端承诺-揭示交换集成测试（`#[cfg(test)]`，不依赖网络） | 4 个 `#[test]`（crate 外不可见） |

模块声明（`lib.rs:4-9`）：

```rust
pub mod commit;
pub mod derive;
pub mod escape;
pub mod ka;
#[cfg(test)]
mod handshake_test;
```

---

## 3. 逐文件详细文档

### 3.1 `src/lib.rs`

**文件路径**：`H:\mclink core\kernel\wgp-crypto\src\lib.rs`（44 行）

**一句话职责**：crate 入口，声明四个公开模块，并定义全局共享的"一次性秘密容器"与"密码学档位"两个基础类型。

#### 3.1.1 定义的类型

**`SecretBox`** —— 一次性秘密容器（`lib.rs:13-36`）：

```rust
pub struct SecretBox(pub [u8; 32]);
```

元组结构体，内部 32 字节秘密，字段为 `pub`。注释注明用途：*"一次性秘密容器：取出即销毁（14 §10 条款 3）"*。

方法与实现：

```rust
impl SecretBox {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
    /// 一次性取出；此后本容器归零
    pub fn take(&mut self) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        if self.0.iter().all(|&b| b == 0) {
            return None;
        }
        out.copy_from_slice(&self.0);
        self.0.zeroize();
        Some(out)
    }
}

impl Drop for SecretBox {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
```

安全语义：

- `take()` 先把内容拷出到局部 `out`，再对自身 `zeroize()`，返回 `Some(out)`；即"取出即销毁"，同一容器无法二次取出。
- 若内部已全零（从未装入有效密钥，或已 `take` 过），返回 `None`。注意此判定是"全零即空"，一把恰好全为零的合法密钥（概率 2^-256）会被误判为空——代码如此，风险可忽略，意图待确认（设计上应以独立标志位区分更严谨）。
- `Drop` 兜底：未调用 `take` 就丢弃容器时，同样清零。

**`CryptoProfile`** —— 当前密码学档位（`lib.rs:38-44`）：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoProfile {
    X25519Aes128Gcm,
    HybridPqMlKem768,
}
```

注释：*"当前密码学档位（00 D6：现役 X25519；PQ 为可选，留 API 不实现）"*。

- `X25519Aes128Gcm`：现役档位（X25519 协商）。
- `HybridPqMlKem768`：后量子混合档位占位（X25519 + ML-KEM-768），当前未接线。
- `#[non_exhaustive]`：允许未来新增档位而不破坏调用方匹配。
- **注意（代码如此，意图待确认）**：变体名写作 `X25519Aes128Gcm`（AES-**128**），但本 crate 逃生通道实际使用 **AES-256-GCM**（见 `escape.rs`），命名与实现不一致，疑为笔误或历史命名。

#### 3.1.2 本 crate 内使用情况

`SecretBox` 与 `CryptoProfile` 在 `wgp-crypto` 内部均无使用点（无函数签名引用它们），是面向 wgp-core 等上层的公共 API。

---

### 3.2 `src/commit.rs`

**文件路径**：`H:\mclink core\kernel\wgp-crypto\src\commit.rs`（26 行）

**一句话职责**：实现承诺-揭示机制（`01 §1.2.2`）——对端先发出公钥承诺、后揭示公钥+nonce，使不可信转发者（DHT 中继）无法替换公钥而不被发现。

#### 3.2.1 定义

```rust
/// SHA-256 承诺值
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);

/// 计算承诺：SHA256(pubkey || nonce)
pub fn commit(pubkey: &[u8], nonce: &[u8; 32]) -> Commitment {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.update(nonce);
    Commitment(h.finalize().into())
}

/// 验证揭示；不匹配 = MITM 检测 → 调用方断连 + 黑名单（01 §1.2.2 表）
pub fn verify(c: &Commitment, pubkey: &[u8], nonce: &[u8; 32]) -> bool {
    let expect = commit(pubkey, nonce);
    expect.0 == c.0
}

/// 双方承诺相同（碰撞，概率 2^-256）→ 重生成 nonce 重试（最多 1 次）
pub fn is_collision(a: &Commitment, b: &Commitment) -> bool {
    a.0 == b.0
}
```

#### 3.2.2 密码学细节

- **承诺计算**：`commit = SHA-256(pubkey || nonce)`。
  - `pubkey`：变长字节切片（`&[u8]`），不限定算法与长度——X25519 模式下为 32B，为未来 Hybrid PQ 变长公钥预留。
  - `nonce`：定长 32B（`&[u8; 32]`），每次握手随机生成。
  - 拼接顺序固定为公钥在前、nonce 在后；无其他域分隔前缀。
- **承诺值长度**：`Commitment` 为完整 32B SHA-256 输出。注意传输层会截断：`wgp-proto` 的 `CommitBody.commit` 字段仅 16B（`sig.rs` 注释"SHA256(pubkey||nonce) 截断 16B"），截断动作发生在协议层，本 crate 始终按 32B 计算与比较。
- **`verify` 的比较方式**：`expect.0 == c.0` 为普通数组相等比较（`[u8; 32]` 的 `PartialEq`），非恒定时间比较。承诺值是公开传输的非秘密数据，时序侧信道风险低；代码如此，记录备查。
- **`is_collision`**：双方承诺值相等的碰撞检测（概率 2^-256），注释规定处理策略为"重生成 nonce 重试（最多 1 次）"；但**重试逻辑不在本 crate**——`is_collision` 在 wgp-crypto 内无调用方，由上层（握手状态机）负责（详见第 6 节）。

#### 3.2.3 安全语义

- 抗替换：攻击者在中继侧换公钥，由于不知道 nonce 与承诺的绑定关系（SHA-256 抗第二原像），替换后揭示阶段 `verify` 必然失败。
- 失败处置约定（写在 `verify` 文档注释中）：不匹配 = MITM 检测 → 调用方断连 + 黑名单；具体断连与黑名单动作同样由上层执行。

---

### 3.3 `src/derive.rs`

**文件路径**：`H:\mclink core\kernel\wgp-crypto\src\derive.rs`（80 行）

**一句话职责**：从 ECDH 共享密钥经 HKDF-SHA256 **一次性展开**派生出全会话密钥族（session / PSK / 探针 / 心跳 / 逃生），并提供四个用途的 HMAC-SHA256 截断 12B 认证函数。

#### 3.3.1 常量

```rust
/// 固定且公开的盐（01 §1.2.3）
pub const SALT_DOMAIN: &[u8] = b"zheyuemen/v1/ecdh-salt";
```

- 完整字符串照录：`zheyuemen/v1/ecdh-salt`（22 字节，ASCII）。
- 作为 HKDF 提取阶段的 salt（`Some(SALT_DOMAIN)`），固定且公开——即所有会话共享同一盐，会话间区分完全依赖 IKM（ECDH 共享密钥）与 info（上下文）。

#### 3.3.2 定义的类型

```rust
/// 全会话密钥族（14 §2/§4 对应字段的来源）
pub struct SessionSecrets {
    /// TLS-PSK 主密钥（QUIC/TCP 路径注入，方案 a）
    pub session_key: [u8; 32],
    /// PSK identity 派生种子（两端推导一致）
    pub psk_identity: [u8; 16],
    /// 探针 HMAC 密钥（打洞验证前防伪造）
    pub probe_key: [u8; 32],
    /// 心跳 HMAC 密钥（03 §3.7.4）
    pub hb_key: [u8; 32],
    /// 逃生通道 AES-GCM 密钥（ICMP 单向，01 §1.3 修订后仅此用途）
    pub escape_key: [u8; 32],
}
```

五个字段全部 `pub`，总长 144 字节。`SessionSecrets` 未 derive 任何 trait，也未实现 `Drop`/`ZeroizeOnDrop`（见第 6 节）。

#### 3.3.3 定义的函数

```rust
pub fn derive_all(shared: &[u8; 32], info_ctx: &[u8]) -> SessionSecrets
```

由 ECDH 共享密钥一次性派生全会话密钥族。文档注释要求 `info_ctx` 应包含：双方公钥、nonce_A/B、ServerTime、协议域名（01 §1.2.3）。

实现（`derive.rs:27-51`）：

```rust
let hk = Hkdf::<Sha256>::new(Some(SALT_DOMAIN), shared);
let mut okm = [0u8; 144];
hk.expand(info_ctx, &mut okm)
    .expect("HKDF-SHA256 输出 144B 合法");
```

随后按固定偏移从 `okm` 顺序切分：

| 字段 | 字节区间 | 长度 |
|---|---|---|
| `session_key` | `okm[0..32]` | 32B |
| `psk_identity` | `okm[32..48]` | 16B |
| `probe_key` | `okm[48..80]` | 32B |
| `hb_key` | `okm[80..112]` | 32B |
| `escape_key` | `okm[112..144]` | 32B |

```rust
/// 探针 HMAC 截断 12B（03 §3.5.5 AuthTag）；失败返回全零 → 调用方静默丢弃
pub fn probe_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12]

/// 心跳 HMAC 截断 12B（03 §3.7.4）
pub fn hb_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12]

/// 逃生帧 HMAC 截断 12B（00 §4 ICMP 逃生档）
pub fn escape_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12]

/// LAN 组播 beacon HMAC 截断 12B（00 §4 局域网快速路径）
pub fn lan_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12]
```

四个函数签名与行为完全一致，均委托私有函数：

```rust
fn truncated_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 密钥长度合法");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}
```

#### 3.3.4 密码学细节

- **算法**：HKDF-SHA256（RFC 5869），两阶段：
  - Extract：`PRK = HMAC-SHA256(salt = SALT_DOMAIN, IKM = shared)`，其中 `shared` 为 32B ECDH 共享密钥。
  - Expand：`OKM(144B) = HKDF-Expand(PRK, info = info_ctx, L = 144)`。
- **`expect` 不会触发**：HKDF-SHA256 的 Expand 上限 L ≤ 255 × HashLen = 255 × 32 = 8160 字节，144B 合法，`expect("HKDF-SHA256 输出 144B 合法")` 为不变式断言。
- **输出总长**：144B（= 0x90）。注意与设计文档的关系：本实现展开 144B 覆盖全部 5 个字段；若设计文档侧仅描述"48B 输出"（session_key 32B + psk_identity 16B），则只覆盖前两字段——代码实际为 144B，此处以代码为准，差异见第 5 节。
- **无 per-key 标签分离**：Expand 只用一个统一 `info_ctx`，五个密钥仅靠 OKM 内的顺序位置区分，没有为每个密钥追加独立 label/info（如 "session" || 0x01）。这在 HKDF 实践中属于弱化做法（位置即分离），代码如此。
- **HMAC 认证标签**：四个 `*_auth` 函数均为 HMAC-SHA256(key, data) 取**前 12 字节**截断；无域分隔前缀（不同用途仅靠密钥不同区分）。注释中 `probe_auth` 提及"失败返回全零 → 调用方静默丢弃"——指验证方比对失败时调用方的处置约定，函数本身不返回 Option。
- **HMAC 密钥长度**：`new_from_slice(key)` 接受任意长度，32B 为规范用法，`expect` 不会触发。

#### 3.3.5 与测试的呼应

`handshake_test.rs` 中 `info` 的构造顺序为：`pk_a || pk_b || nonce_a || nonce_b || PROTO_VERSION || SIG_MAGIC`（共 32+32+32+32+1+2 = 131B），两端相同 → 派生输出逐字段断言相等。

---

### 3.4 `src/escape.rs`

**文件路径**：`H:\mclink core\kernel\wgp-crypto\src\escape.rs`（32 行）

**一句话职责**：ICMP 逃生链路的 AES-256-GCM 帧编解码器（`01 §1.3` 修订后：逃生帧加密仅此用途；QUIC/TCP 主链路不走本节，由 TLS-PSK 承担）。

#### 3.4.1 定义

```rust
/// 逃生帧编解码器（每个 Peer 对一份，密钥由 escape_key 提供）
pub struct EscapeCodec {
    cipher: Aes256Gcm,
}

impl EscapeCodec {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)),
        }
    }

    /// 加密（密文含 16B GCM Tag）
    pub fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Option<Vec<u8>> {
        self.cipher
            .encrypt(Nonce::from_slice(nonce), plain)
            .ok()
    }

    /// 解密验证；任何失败（篡改/非本密钥/重放位的上层检测）返回 None → 静默丢弃
    pub fn open(&self, nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), sealed)
            .ok()
    }
}
```

#### 3.4.2 密码学细节

- **算法**：AES-256-GCM（`aes_gcm::Aes256Gcm`，即 AES-GCM with 256-bit key）。
- **密钥**：32B，来自 `SessionSecrets::escape_key`（`derive.rs` 派生），每个 Peer 对一份 `EscapeCodec`。
- **Nonce**：12B（`&[u8; 12]`，GCM 标准 IV 长度），**完全由调用方传入**，本 crate 不生成、不管理 nonce。
  - **注意（代码如此，意图待确认）**：`EscapeCodec` 内**没有** nonce 前缀/方向隔离逻辑（如为 A→B、B→A 分配不同 nonce 前缀位），也没有序列号计数器或重放窗口——注释中"重放位的上层检测"表明重放检测被推给上层。若设计上存在 nonce 前缀方向隔离，其实现不在本文件，应在 wgp-punch / wgp-core 的调用方。
- **AAD**：`encrypt`/`decrypt` 均未使用附加认证数据（两参数形式，无 `aad`），即仅密文本身受完整性保护，帧头等元数据不在 GCM 认证范围内。
- **Tag**：GCM 16B 认证标签包含在密文尾部（`seal` 输出 = ciphertext || tag）。
- **失败语义**：`seal`/`open` 把 `aes-gcm` 的 `Result` 用 `.ok()` 转为 `Option`；任何失败（篡改、密钥不符、nonce 不符、长度不足 16B 等）返回 `None`，调用方静默丢弃，不区分错误类型。
- **重密钥开销**：`EscapeCodec::new` 每次调用都重新执行 AES 密钥扩展，无缓存/池化。

#### 3.4.3 安全语义与边界

- `EscapeCodec` 持有 `Aes256Gcm` 实例（内含展开后的密钥调度），结构体**未实现 `Drop`/zeroize**，丢弃时不清零（见第 6 节）。
- 逃生通道为 ICMP 单向（注释："ICMP 单向"），双向需两端各自持有对端方向的编解码器（由上层用相同 `escape_key` + 不同 nonce 策略构造；具体策略不在本 crate）。

---

### 3.5 `src/ka.rs`

**文件路径**：`H:\mclink core\kernel\wgp-crypto\src\ka.rs`（83 行）

**一句话职责**：定义可插拔的 `KeyAgreement` 密钥协商 trait（`14 §4`、`00 D6/D9`），提供 X25519 现役实现，并为 Hybrid PQ（X25519 + ML-KEM-768）预留算法位 0x02。

#### 3.5.1 trait 定义

```rust
/// 密钥协商原语。任何实现的成果（共享密钥）语义一致：双方推导相同字节。
/// 约定：PrivKey 为一次性临时密钥（每次协商全新生成）；
/// drop 时清零由后端自保证（x25519-dalek 内部使用 `Zeroizing`，PQ 后端亦须同语义）。
pub trait KeyAgreement: Send + Sync {
    type PrivKey;

    /// 生成临时私钥
    fn keygen(&self, rng: &mut impl CryptoRngCore) -> Self::PrivKey;
    /// 导出公钥字节（承诺-揭示的承诺输入）
    fn pubkey_raw(&self, sk: &Self::PrivKey) -> Vec<u8>;
    /// 计算共享密钥；失败（长度非法/低熵全零）返回 None
    fn agree(&self, sk: &Self::PrivKey, peer_pk: &[u8]) -> Option<Vec<u8>>;
    /// 算法标识（承诺/揭示包的 algo_tag；协议版本协商依据）
    fn algo_id(&self) -> u8;
}
```

trait 约定（照录注释）：

- 任何实现的成果语义一致：双方推导相同字节。
- `PrivKey` 为**一次性临时密钥**，每次协商全新生成（无长期静态密钥）。
- drop 时清零由后端自保证：注释声称 x25519-dalek 内部使用 `Zeroizing`，要求未来 PQ 后端同语义。（此为注释声明；本 crate 代码无法直接验证 dalek 内部实现，记录备查。）
- `Send + Sync`：协商器可在线程间共享与转移（上层并发握手需要）。
- `algo_id` 的返回值即协议层 `wgp_proto::sig::algo` 的 `algo_tag`，是协议版本协商依据。

#### 3.5.2 X25519 现役实现

```rust
/// 现役：X25519（algo_id = 0x01）
pub struct X25519Agreement;

impl KeyAgreement for X25519Agreement {
    type PrivKey = StaticSecret;

    fn keygen(&self, rng: &mut impl CryptoRngCore) -> Self::PrivKey {
        StaticSecret::random_from_rng(rng)
    }

    fn pubkey_raw(&self, sk: &Self::PrivKey) -> Vec<u8> {
        PublicKey::from(sk).as_bytes().to_vec()
    }

    fn agree(&self, sk: &Self::PrivKey, peer_pk: &[u8]) -> Option<Vec<u8>> {
        if peer_pk.len() != 32 {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(peer_pk);
        let pk = PublicKey::from(buf);
        let shared = sk.diffie_hellman(&pk);
        // 01 §1.2.4：全零共享密钥立即终止（不自动重协商，避免死循环）
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return None;
        }
        Some(shared.as_bytes().to_vec())
    }

    fn algo_id(&self) -> u8 {
        0x01
    }
}
```

行为细节：

- `keygen`：`StaticSecret::random_from_rng(rng)`，RNG 由调用方以 `&mut impl CryptoRngCore` 注入（测试用 `OsRng`），crate 不绑定具体熵源。
- `pubkey_raw`：`PublicKey::from(sk).as_bytes().to_vec()`，输出 32B 原始公钥（X25519 u 坐标，未经域分隔编码）。
- `agree`：
  1. 对端公钥长度必须为 32B，否则 `None`（长度非法）。
  2. `PublicKey::from(buf)` 构造对端公钥；`sk.diffie_hellman(&pk)` 计算共享密钥。
  3. **全零检查**（`01 §1.2.4`）：共享密钥任一端为低熵点（对端公钥为小阶点）时 X25519 输出全零，此时立即返回 `None` 终止——注释明确"不自动重协商，避免死循环"。
  4. 成功返回 32B 共享密钥 `Vec<u8>`（堆分配，无 zeroize 包装，见第 6 节）。
- `algo_id` = `0x01`（与 `wgp_proto::sig::algo::X25519 = 0x01` 对齐）。

#### 3.5.3 PQ 预留与协商器工厂

```rust
/// 未来线：Hybrid PQ（X25519 + ML-KEM-768，algo_id = 0x02）。
/// 未实现——接入点：实现 KeyAgreement 并在承诺-揭示中带 algo_tag=0x02，
/// 同时挂接 rustls 的 X25519MLKem768（rustls ≥0.23 默认支持）。
pub struct HybridPqAgreement;

/// 协商器工厂（enum 形态替代 dyn，保持零成本抽象；PQ 接入时在此增臂）。
/// 未知算法标识 → None（协议版本协商失败路径：断连而非降级）。
pub enum AnyAgreement {
    X25519(X25519Agreement),
    // 未来：Hybrid(HybridPqAgreement),
}

impl AnyAgreement {
    pub fn for_algo(algo_id: u8) -> Option<Self> {
        match algo_id {
            0x01 => Some(Self::X25519(X25519Agreement)),
            _ => None,
        }
    }

    pub fn algo_id(&self) -> u8 {
        match self {
            Self::X25519(_) => 0x01,
        }
    }
}
```

- `HybridPqAgreement`：**空结构体占位**，未实现 `KeyAgreement`，无任何方法——即 PQ Hybrid 当前只是 enum/struct 占位，不可用。
- `AnyAgreement`：enum 形态的协商器工厂（替代 `dyn KeyAgreement`，保持零成本抽象）；未来臂 `Hybrid(HybridPqAgreement)` 以注释形式预留。
- `for_algo(algo_id)`：仅 `0x01` 返回 `Some(Self::X25519(..))`，其余一切标识（含 `0x02`、`0xFF`）返回 `None`。注释规定失败路径为"断连而非降级"（协议版本协商失败）。
- `algo_id()`：反射当前协商器的算法标识，X25519 臂返回 `0x01`。

---

### 3.6 `src/handshake_test.rs`（测试文件）

**文件路径**：`H:\mclink core\kernel\wgp-crypto\src\handshake_test.rs`（180 行）

**一句话职责**：端到端"承诺-揭示交换"全流程的代码化自验证（`01 §1.2.2`），不依赖网络，纯逻辑验证 MITM 检测、共享密钥一致性、全套会话密钥族派生。

模块条件编译：`#[cfg(test)] mod handshake_test;`（`lib.rs:8-9`），测试内再嵌套 `#[cfg(test)] mod tests`。

#### 3.6.1 依赖的跨 crate 符号（来自 dev-dependency `wgp-proto`）

| 符号 | 定义处 | 值/语义 |
|---|---|---|
| `wgp_proto::consts::PROTO_VERSION` | `wgp-proto/src/consts.rs:4` | `u8 = 0x01` |
| `wgp_proto::sig::SIG_MAGIC` | `wgp-proto/src/sig.rs:7` | `[u8; 2] = [0x57, 0x47]`（"WG"） |
| `wgp_proto::sig::algo::X25519` | `wgp-proto/src/sig.rs:19` | `u8 = 0x01` |
| `wgp_proto::sig::sig_type::COMMIT` | `wgp-proto/src/sig.rs:11` | `u8 = 0x01` |
| `SigPacket::commit / reveal / encode / decode` | `wgp-proto/src/sig.rs` | 信令包构造与编解码 |
| `CommitBody { peer_id: [u8; 16], commit: [u8; 16] }` | `wgp-proto/src/sig.rs:42` | 承诺包 body（48B 定长） |
| `RevealBody { peer_id: [u8; 16], pubkey: Vec<u8>, nonce: [u8; 32] }` | `wgp-proto/src/sig.rs:70` | 揭示包 body（X25519 模式 80B） |
| `SigBody::Reveal` | `wgp-proto/src/sig.rs:175` | body 枚举变体 |

#### 3.6.2 核心辅助函数

```rust
fn run_handshake(peer_a: [u8; 16], peer_b: [u8; 16]) -> (Commitment, Commitment)
```

模拟两端走完"承诺-揭示-X25519-agree"全流程，共 9 步：

1. **① 各生成临时密钥对**：`X25519Agreement` + `OsRng`，`keygen` → `sk_a`/`sk_b`，`pubkey_raw` → `pk_a`/`pk_b`。
2. **② 各生成 32B nonce**：`RngCore::fill_bytes` 填 `nonce_a`/`nonce_b`。
3. **③ 互发承诺**：`commit(&pk_a, &nonce_a)` / `commit(&pk_b, &nonce_b)`。
4. **④ 经 DHT 互发承诺包**：承诺值 32B **截断为 16B**（`commit_a.0[..16]`）填入 `CommitBody.commit`，`SigPacket::commit(.., algo::X25519, 0)` 构造后 `encode()`（仅编码，未解码验证）。
5. **⑤ 互发揭示**：`SigPacket::reveal(RevealBody { peer_id, pubkey, nonce }, algo::X25519, 0)`。
6. **⑥ 对端解码 + 验证**：`SigPacket::decode(&r_pkt_b.encode())` 取 `SigBody::Reveal`，重算承诺并双向 `verify(&commit_b, &reveal_a.pubkey, &reveal_a.nonce)` / `verify(&commit_a, &reveal_b.pubkey, &reveal_b.nonce)`，断言消息分别为 `"MITM 检测 A"` / `"MITM 检测 B"`。
7. **⑦ ECDH 双方共享密钥一致**：`ka.agree(&sk_a, &reveal_a.pubkey)` 与 `ka.agree(&sk_b, &reveal_b.pubkey)` 结果 `assert_eq!`（`"共享密钥必须一致"`）。
8. **⑧ 派生全套会话密钥族**：`info = pk_a || pk_b || nonce_a || nonce_b || PROTO_VERSION || SIG_MAGIC`（131B），两端 `derive_all` 后**五个字段逐一 `assert_eq!`**（`session_key`/`psk_identity`/`probe_key`/`hb_key`/`escape_key`）。
9. **⑨ 探针/心跳 HMAC 一致性**：数据 `b"punch-verify-data-v1"`，`probe_auth` 与 `hb_auth` 两端结果相等。

#### 3.6.3 测试用例列表与测试向量

| 测试 | 向量/输入 | 断言 |
|---|---|---|
| `happy_path_two_peers` | `peer_a = [0x11u8; 16]`，`peer_b = [0x22u8; 16]`，`OsRng` 随机密钥/nonce | 走通 `run_handshake` 全 9 步无 panic（含 MITM 双向验证、共享密钥一致、5 字段派生一致、HMAC 一致） |
| `mitm_detected_on_commit_swap` | 合法 `(pk, nonce)`；攻击者 `malicious_pk = pk` 且 `malicious_pk[0] ^= 0x01`，`malicious_nonce = nonce` 且 `malicious_nonce[0] ^= 0xAA` | `assert_ne!(original.0, attack.0)`——攻击者不知 nonce，替换公钥+nonce 后承诺必然不同（SHA-256 抗第二原像） |
| `algo_mismatch_handled` | `AnyAgreement::for_algo(0x02)`、`for_algo(0xFF)`、`for_algo(algo::X25519)` | 前两者 `is_none()`；`for_algo(algo::X25519)` 解出 `AnyAgreement::X25519(ka)` 且 `ka.algo_id()` 可调用，否则 `panic!("X25519 协商器应存在")` |
| `sig_type_routing` | `SigPacket::commit(CommitBody { peer_id: [0; 16], commit: [0; 16] }, algo::X25519, 0)` | `bytes[0..2] == SIG_MAGIC`（`[0x57, 0x47]`）；`bytes[2] == sig_type::COMMIT` |

关于 `sig_type_routing` 第二条断言的说明（代码如此，意图待确认）：按 `wgp-proto` 的 `SigHeader::encode`，包字节布局为 `[0..2]=MAGIC, [2]=version, [3]=kind`，因此 `bytes[2]` 实为 **version** 字段（值 `PROTO_VERSION = 0x01`），而 `sig_type::COMMIT` 同为 `0x01`——该断言因两常量巧合相等而恒真，并未真正校验 kind 字节（kind 在 `bytes[3]`）。疑为测试笔误，但不影响测试通过。

#### 3.6.4 测试覆盖边界

- 未覆盖：`is_collision`、`escape_auth`、`lan_auth`、`escape::EscapeCodec`、`SecretBox`、`CryptoProfile`、`agree` 的长度非法分支与全零共享密钥分支（`ka.rs` 内的检查无直接单测）。
- 全零共享密钥路径仅在注释（`01 §1.2.4`）中约定，无测试构造小阶点公钥触发。

---

## 4. 对外 API 汇总

以下为 `wgp-crypto` 的全部公开 API（`pub` 项），按模块列出；签名照抄源码。

### 4.1 crate 根（`lib.rs`）

```rust
pub struct SecretBox(pub [u8; 32]);
impl SecretBox {
    pub fn new(key: [u8; 32]) -> Self;
    pub fn take(&mut self) -> Option<[u8; 32]>;
}

#[non_exhaustive]
pub enum CryptoProfile {
    X25519Aes128Gcm,
    HybridPqMlKem768,
}
```

### 4.2 `commit` 模块

```rust
pub struct Commitment(pub [u8; 32]);
pub fn commit(pubkey: &[u8], nonce: &[u8; 32]) -> Commitment;
pub fn verify(c: &Commitment, pubkey: &[u8], nonce: &[u8; 32]) -> bool;
pub fn is_collision(a: &Commitment, b: &Commitment) -> bool;
```

### 4.3 `derive` 模块

```rust
pub const SALT_DOMAIN: &[u8] = b"zheyuemen/v1/ecdh-salt";

pub struct SessionSecrets {
    pub session_key: [u8; 32],
    pub psk_identity: [u8; 16],
    pub probe_key: [u8; 32],
    pub hb_key: [u8; 32],
    pub escape_key: [u8; 32],
}

pub fn derive_all(shared: &[u8; 32], info_ctx: &[u8]) -> SessionSecrets;
pub fn probe_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12];
pub fn hb_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12];
pub fn escape_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12];
pub fn lan_auth(key: &[u8; 32], data: &[u8]) -> [u8; 12];
```

### 4.4 `escape` 模块

```rust
pub struct EscapeCodec {
    cipher: Aes256Gcm, // 私有字段
}
impl EscapeCodec {
    pub fn new(key: &[u8; 32]) -> Self;
    pub fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Option<Vec<u8>>;
    pub fn open(&self, nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>>;
}
```

### 4.5 `ka` 模块

```rust
pub trait KeyAgreement: Send + Sync {
    type PrivKey;
    fn keygen(&self, rng: &mut impl CryptoRngCore) -> Self::PrivKey;
    fn pubkey_raw(&self, sk: &Self::PrivKey) -> Vec<u8>;
    fn agree(&self, sk: &Self::PrivKey, peer_pk: &[u8]) -> Option<Vec<u8>>;
    fn algo_id(&self) -> u8;
}

pub struct X25519Agreement;                      // PrivKey = x25519_dalek::StaticSecret
pub struct HybridPqAgreement;                    // 空占位，未实现 trait

pub enum AnyAgreement {
    X25519(X25519Agreement),
}
impl AnyAgreement {
    pub fn for_algo(algo_id: u8) -> Option<Self>;
    pub fn algo_id(&self) -> u8;
}
```

### 4.6 算法参数速查

| 项目 | 值 |
|---|---|
| 承诺算法 | SHA-256(pubkey \|\| nonce)，输出 32B（协议层截断 16B 传输） |
| nonce（承诺用） | 32B 随机 |
| HKDF | HKDF-SHA256；salt = `zheyuemen/v1/ecdh-salt`；IKM = 32B ECDH 共享密钥；OKM = 144B |
| OKM 布局 | `[0..32]` session_key / `[32..48]` psk_identity / `[48..80]` probe_key / `[80..112]` hb_key / `[112..144]` escape_key |
| HMAC | HMAC-SHA256，截断前 12B（probe/hb/escape/lan 四种用途，密钥各不相同） |
| 逃生 AEAD | AES-256-GCM，key 32B、nonce 12B、tag 16B、无 AAD |
| 密钥协商 | X25519，`algo_id = 0x01`；PQ Hybrid 预留 `0x02`（未实现） |

---

## 5. 与设计文档（01/14）的对应关系

| 设计条款 | 设计内容 | 代码实现 | 对应情况 |
|---|---|---|---|
| `01 §1.2.2` 承诺-揭示 | 先承诺后揭示，防转发者替换公钥 | `commit.rs`：`commit = SHA256(pubkey\|\|nonce)`（32B）、`verify` 双向校验、`is_collision` 碰撞检测 | 完全对应；MITM 检测的断连+黑名单动作约定在注释中，由上层执行 |
| `01 §1.2.3` HKDF 会话密钥派生 | 固定公开盐 + info 上下文派生 | `derive.rs`：`SALT_DOMAIN = b"zheyuemen/v1/ecdh-salt"`，`Hkdf::<Sha256>::new(Some(SALT_DOMAIN), shared)` + `expand(info_ctx, 144B)` | 对应；但 **OKM 长度以代码为准为 144B**（5 个字段）。若设计文档按 48B（session_key 32B + psk_identity 16B）描述，则仅覆盖前两字段，后三个字段（probe/hb/escape）为代码超出设计描述的部分——代码如此，差异待确认 |
| `01 §1.2.4` 全零共享密钥 | 全零立即终止，不自动重协商 | `ka.rs` `X25519Agreement::agree`：`shared.as_bytes().iter().all(\|&b\| b == 0)` → `None`，注释照录该条款 | 完全对应 |
| `01 §1.3`（修订）ICMP 逃生 | AES-GCM 帧仅用于 ICMP 逃生链路；QUIC/TCP 主链路由 TLS-PSK 承担 | `escape.rs`：`EscapeCodec` = AES-256-GCM，密钥来自 `SessionSecrets::escape_key`；`derive.rs` 注释"修订后仅此用途" | 完全对应 |
| `14 §2` 会话密钥族 | 全会话密钥族字段来源 | `derive.rs::SessionSecrets` 五字段（session_key/psk_identity/probe_key/hb_key/escape_key），注释标注"14 §2/§4 对应字段的来源" | 对应 |
| `14 §4` PQ 可插拔 KeyAgreement | 协商算法可插拔、调用方无感 | `ka.rs`：`KeyAgreement` trait + `AnyAgreement::for_algo` 工厂；`X25519Agreement`（0x01）现役，`HybridPqAgreement`（0x02）占位 | 机制对应；**PQ 本体未实现**（见第 6 节） |
| `14 §10` 条款 3 SecretBox | 一次性秘密容器，取出即销毁 | `lib.rs::SecretBox`：`take()` 后 zeroize + `Drop` 兜底 | 完全对应 |
| `14 §11` / `00 §3` 协议版本化 | algo_tag 作为版本协商依据；未知算法断连不降级 | `ka.rs::algo_id()` 与 `AnyAgreement::for_algo`（未知 → `None`，注释"断连而非降级"）；协议层 `wgp_proto::sig::algo::{X25519=0x01, HYBRID_PQ=0x02}` | 对应 |
| `03 §3.5.5 / §3.7.4` 探针/心跳 AuthTag | 12B 截断 HMAC | `derive.rs::probe_auth` / `hb_auth`（HMAC-SHA256 截断 12B） | 对应 |
| `00 §4` ICMP 逃生档 / LAN 快速路径 | 逃生帧与 LAN beacon 的 HMAC | `derive.rs::escape_auth` / `lan_auth` | 函数存在且注释对应；**调用方与密钥来源未在本 crate 体现**（见第 6 节） |
| `00 D6` 密码学档位 | 现役 X25519；PQ 可选、留 API 不实现 | `lib.rs::CryptoProfile`（`X25519Aes128Gcm` / `HybridPqMlKem768`，`#[non_exhaustive]`） | 对应；enum 在本 crate 内无使用点 |

---

## 6. 已知限制或未实现项

以下均为源码中可核实的状态，按严重程度/明确程度排序：

1. **PQ Hybrid 仅占位，未实现**：`HybridPqAgreement` 是空结构体（无任何 impl），`AnyAgreement` 的 `Hybrid(HybridPqAgreement)` 臂被注释掉，`for_algo` 对 `0x02` 返回 `None`。接入路径（注释原文）：实现 `KeyAgreement` 并在承诺-揭示中带 `algo_tag=0x02`，同时挂接 rustls 的 `X25519MLKem768`（rustls ≥0.23 默认支持）。`CryptoProfile::HybridPqMlKem768` 同理为留 API 不实现的枚举占位。

2. **`SessionSecrets` 无 zeroize**：五个密钥字段为普通数组，结构体丢弃时不清零，也未实现 `Drop`/`ZeroizeOnDrop`——与 crate 层注释宣称的"密钥材料全生命周期 zeroize"存在差距（`SecretBox` 与 dalek 私钥已覆盖，派生结果未覆盖）。

3. **HKDF 中间输出未清零**：`derive_all` 中 `okm: [u8; 144]` 为栈上临时数组，切片拷贝进 `SessionSecrets` 后未 `zeroize` 即离开作用域。

4. **`agree` 返回的共享密钥无零化包装**：`Option<Vec<u8>>` 为堆分配普通 Vec，调用方持有期间与丢弃后均无清零保证（trait 签名如此，更换后端亦然）。

5. **nonce 无前缀/方向隔离、无重放防护**：`EscapeCodec::seal/open` 的 12B nonce 完全由调用方提供，crate 内无 nonce 生成、无方向前缀位、无序列号/重放窗口；`open` 注释将"重放位的上层检测"推给上层。方向上若两端同钥同 noncetext 碰撞，风险由调用方的 nonce 策略决定——代码如此，具体上层策略待确认。

6. **逃生 AEAD 无 AAD**：帧头等元数据不在 GCM 认证范围内。

7. **`EscapeCodec` 无 `Drop`/zeroize**：内含 AES 密钥调度，丢弃不清零。

8. **`is_collision` 无 crate 内调用方**：注释规定的"重生成 nonce 重试（最多 1 次）"逻辑未实现于本 crate，由上层握手状态机负责；即碰撞重试路径当前不可用。

9. **`escape_auth` / `lan_auth` 的调用方与密钥来源未定义**：两函数已导出，但 `SessionSecrets` 中没有对应的 LAN/逃生 HMAC 密钥字段（逃生路径实际使用 `escape_key` 走 AES-GCM，`escape_auth` 疑为冗余或历史层）；LAN beacon HMAC 用哪把密钥无代码依据——代码如此，意图待确认。

10. **HKDF 无 per-key 标签分离**：五个会话密钥仅靠单一 `info_ctx` 下 OKM 的位置切分区分，未使用独立 label/info（如 `info || label || index`）做密码学域分离，属弱化做法。

11. **`verify` 非恒定时间比较**：`expect.0 == c.0` 为普通数组比较；承诺值为公开数据，风险评估为低，记录备查。

12. **`SecretBox` 以"全零"判空**：恰好全零的合法密钥会被 `take` 误判为已取出（概率 2^-256），语义上应以独立标志位区分。

13. **`CryptoProfile` 命名疑云**：`X25519Aes128Gcm` 含 "Aes128" 字样，但逃生通道实际为 AES-**256**-GCM——代码如此，意图待确认（疑为笔误或历史命名）。

14. **`sig_type_routing` 测试断言恒真**：`bytes[2] == sig_type::COMMIT` 实际比较的是 version 字段（与 COMMIT 同为 `0x01` 而恒真），kind 位于 `bytes[3]`——疑为测试笔误，不影响通过，见 §3.6.3。

15. **测试覆盖缺口**：`EscapeCodec`、`SecretBox`、`CryptoProfile`、`is_collision`、`escape_auth`、`lan_auth` 及 `agree` 的异常分支（长度非法、全零共享密钥）均无测试用例；`happy_path` 中的承诺包只编码不解码（步骤 ④ 的 `_bytes_a`/`_bytes_b` 未参与断言）。

---

*本文档由逐行通读 `kernel/wgp-crypto` 全部 6 个源文件生成；所有函数签名、常量字符串、字节区间均照抄源码，未作推测性补全。*
