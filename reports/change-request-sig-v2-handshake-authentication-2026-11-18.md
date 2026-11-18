# 变更请求：SIG v2 握手身份认证（修复会话中间人缺陷）

| 字段 | 内容 |
|---|---|
| CR 编号 | CR-2026-11-18-01 |
| 标题 | 承诺-揭示握手升级为成员身份签名的 SIG v2 |
| 类型 | 安全修复 + **破坏性协议变更** |
| 状态 | 待评审（本地编译与测试已通过，未做真实公网验证） |
| 源分支 | `dsh-85b6d55e-9ace`（基准 `ae4e18d`） |
| 目标分支 | `main`（当前 `b54099e`） |
| 来源 | [`network-security-and-vps-audit-2026-11-17.md`](network-security-and-vps-audit-2026-11-17.md) 的 P0 发现 |
| 影响 crate | `wgp-proto`、`wgp-dht`、`wgp-core`、`wgp-client`、`wgp-agent`，以及桥接集成测试 |

## 1. 摘要

修复审计 P0：原实现只用不可信 Forward 通道上的承诺-揭示保护临时 X25519 公钥，恶意种子/中继可以分别与两端协商，各自建立一条「看起来正常」的会话。本 CR 把临时密钥与端点报告绑定到**房间成员的长期 Ed25519 身份**，并在协商前强制校验签名房间记录中的成员身份。

- 信令握手版本升为 `SIG_VERSION = 0x02`；v1 与未知版本在协议解析层即被拒绝。
- Commit 的 16B 保留区改为每轮 CSPRNG 随机挑战（帧长仍 48B，不变）。
- Reveal 增加双方挑战回显、Commit 前缀与 64B 身份签名（X25519 body 80B → 192B）。
- 端点报告增加 64B 身份签名（47B → 111B），在接受报告前验签。
- `connect_peer` 新增成员身份公钥参数，并自行读取、验证房间签名记录，要求本端与对端都在成员表中且公钥一致。

## 2. 问题与根因

### 2.1 攻击路径

1. 两端经种子 Forward 交换 Commit/Reveal；Forward 者可以丢弃、替换任意帧。
2. 旧实现接受任意 `RevealBody`，只校验「收到的值是 Commit 或 Reveal」，未比较此前收到的 Commit，也未验证 Reveal 的 `peer_id` 是预期成员。
3. `full_commit` 仍由同一条不可信通道传送，因此中继可分别替换两侧公钥与完整承诺。
4. 结果：AEAD 只保护两端各自与攻击者建立的**不同**会话，不能阻止中继读取业务数据。

### 2.2 根因

- 握手 transcript 没有绑定长期身份，临时公钥是匿名的。
- 端点报告同样没有认证，可在身份认证之后被替换为攻击者地址。
- 协商入口没有验证调用方提供的成员身份是否真的登记在房主签名的房间记录中。

## 3. 方案

### 3.1 信任根

信任根是**房主 Ed25519 签名的房间记录**（`RoomRecord.members` 中的 `(NodeId, pubkey)`）。`connect_peer` 在开始协商前：

1. 通过 `RoomRuntime` 拉取并验签房间记录；
2. 要求 `(peer_node_id, peer_identity_key)` 与 `(my_node_id, my_key)` 都精确匹配成员项；
3. 任一不匹配返回 `OrchestratorError::Mitm`，不发送任何协商帧。

（实现位置：`kernel/wgp-core/src/orchestrator.rs:333` 起。）

### 3.2 线格式变更

| 结构 | 旧 | 新 | 说明 |
|---|---|---|---|
| `CommitBody` | 48B（16B 保留置零） | 48B | 末 16B 改为 `session_nonce`，帧长不变 |
| `RevealBody`（X25519） | 80B | **192B** | + `session_nonce`16 + `peer_session_nonce`16 + `commitment`16 + `identity_signature`64 |
| `SigHeader.version` | `PROTO_VERSION`(1) | `SIG_VERSION`(2) | 解析入口拒绝非 2 |
| 端点报告 `EP_BODY_LEN` | 47B | **111B** | + `identity_signature`64；保留字节必须为 0 |

`PROTO_VERSION`（数据面/其他报文）不变，只有信令包版本号独立升级。

### 3.3 握手 transcript

签名消息以域分隔前缀开始，依次绑定：

```
"wgp-handshake-transcript-v1\0"
SIG_VERSION(1)
room_key(room) 32B          # 房间键派生值，不含明文房间码
session_tag(4)
sender NodeId(32)
receiver NodeId(32)
commitment 前缀(16)
len(pubkey)(2) + pubkey
nonce(32)
sender session_nonce(16)
receiver session_nonce(16)
```

验签使用**房间记录中的成员公钥**，不使用 Reveal 自报公钥：`verify_identity_signature` 同时校验 `NodeId == SHA256(pubkey)` 与 Ed25519 签名（`verify_strict`）。

### 3.4 状态机

- 阶段一：发送本端 Commit，只接受 `peer_id` 匹配的 Commit。
- 收到 Commit 后生成 Reveal，签名覆盖本端承诺与**对端挑战**。
- Reveal 接受条件（任一失败即 `Mitm`）：`peer_id` 匹配、与已收 Commit 的承诺前缀一致、`session_nonce` 一致、`peer_session_nonce` 等于本端本轮挑战、`SHA256(pubkey‖nonce)` 前缀一致、身份签名有效。
- `wait_incoming` 可能先消费对端 Commit。若之后先到 Reveal，仅当它已通过上述全部校验（含对本端挑战的回显）才允许从 Reveal 恢复对端 Commit 状态；未认证的提前 Reveal 不被接受。
- 只有认证通过的 Reveal 才进入 ECDH 与密钥派生。

### 3.5 端点报告认证

端点签名消息绑定同样的域、版本、房间键、tag、双方 NodeId，外加全部端点字段（ipv4/port/能力位/端口模型/置信度/完整 Commit）。接收端在 `exchange` 的 accept 回调里先验签，通过后才把报告交给后续判定。

### 3.6 调用方接线

- CLI：`member_watch` 从房间记录取成员公钥传给 `supervise_peer`，再传入 `connect_peer`。
- agent：`punch_driver` 从记录成员项取公钥，长度不符则跳过该成员。
- 集成测试与桥接测试改用节点真实身份公钥。

## 4. 兼容性与升级

**不兼容变更。**

- 旧客户端发送的 v1 信令包会被 `SigHeader::decode` 直接拒绝（不会降级解析）。
- 房间内所有成员必须升级到同一 v2 构建；只升一侧会导致握手失败（表现为协商失败/`PeerGone`）。
- 没有提供 v1 兼容开关；如需过渡期，需另行设计双版本协商，本 CR 未包含。
- DHT RPC、种子广告、数据面报文的线格式与版本不变。

## 5. 安全影响评估

**本 CR 阻止：** 中继替换临时公钥、替换端点映射/端口模型、跨房间或跨对端重放 Reveal、把未登记身份伪装成成员。

**本 CR 不阻止：** 恶意中继丢包/延迟/审查（可用性攻击）；房间记录信任根被房主自身作恶；全局名称认证；Sybil/身份准入成本；STUN 映射伪造；DHT 反射放大；队列内存 DoS。这些仍列在分级报告中。

## 6. 变更文件

| 文件 | 变更 |
|---|---|
| `kernel/wgp-proto/src/sig.rs` | `SIG_VERSION`、新字段与长度、版本拒绝、测试 |
| `kernel/wgp-core/src/orchestrator.rs` | transcript、验签、成员授权、签名端点、状态机、回归测试 |
| `kernel/wgp-dht/src/id.rs` | `verify_identity_signature` 与单元测试 |
| `kernel/wgp-dht/src/lib.rs` | 导出校验函数 |
| `kernel/wgp-crypto/src/handshake_test.rs` | fixture 适配、修正 `bytes[3]` kind 断言 |
| `kernel/wgp-dht/src/net_test.rs` | fixture 适配 |
| `client/wgp-client/src/main.rs` | 成员公钥贯穿到协商 |
| `client/wgp-agent/src/agent.rs` | 同上 |
| `bridge/wgp-port/tests/forward.rs`、`bridge/wgp-et-bridge/tests/et_over_wgp.rs` | 调用点适配 |
| `项目完整文档/01、10、14`、`HANDOFF.md` | 协议、API、威胁模型与交接更新 |
| `reports/` | 审计原文与任务分级报告 |

## 7. 验证记录

环境：Windows，回环；测试临时目录设为工作区 `target/test-temp`（系统 `%TEMP%` 的 linker 临时文件权限受限）。

| 命令 | 结果 |
|---|---|
| `cargo check --workspace --all-targets --locked` | 通过 |
| `cargo test -j 1 --workspace --locked` | **366 passed，0 failed**（退出码 0） |
| `cargo test -j 1 -p wgp-proto -p wgp-dht -p wgp-core` | 通过（proto 51 / dht 102 / core 49） |
| `cargo fmt --all -- --check` | 失败：仓库既有未格式化文件；本 CR 未做无关格式化 |

新增回归测试：

- `sig::tests::rejects_legacy_unbound_handshake_version`：v1 头被拒绝。
- `id::identity_signature_tests::signature_binds_node_id_key_and_message`：消息/NodeId/公钥任一改变即失败。
- `orchestrator::tests::transcript_signatures_reject_relay_tampering`：篡改临时公钥、挑战回显、错误身份公钥、签名后改端口、换房间均失败。

未验证：真实公网 NAT、真实中继攻击、VPS 部署、真实丢包/切网。

## 8. 风险与回滚

- 风险：协议不兼容导致混版本房间无法联机 → 发布说明必须写明「全房间统一升级」。
- 风险：额外的房间记录读取在每次协商前发生，可能增加一次 DHT 往返；失败会直接放弃协商（快速失败，不降级）。
- 回滚：回退本 CR 提交即可；不涉及数据迁移或磁盘格式变更。

## 9. 评审清单

- [ ] transcript 字段顺序与文档一致，且与 `SIG_VERSION` 绑定。
- [ ] 确认 `commitment` 只传输 16B 前缀，完整 32B 仍在端点帧中复验。
- [ ] 确认房间成员公钥来源是签名记录，而非 Reveal 自报。
- [ ] 确认端点验签发生在任何地址/模型被使用之前。
- [ ] 确认发布说明包含 v1/v2 不互通与统一升级要求。

## 10. 后续工作（不在本 CR 范围）

见 [`network-security-vps-task-triage-2026-11-18.md`](network-security-vps-task-triage-2026-11-18.md)：STUN 绑定、公共端点过滤、DHT 放大、队列预算、探针新鲜度、K>1 存储、真实 NAT 联调与发布。
