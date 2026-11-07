# wgp v2 现状盘点（2026-11-07）

> 面向读者：9 月接手、需要在一小时内搞清楚「这套东西做到哪了」的人。
> 依据：逐文件通读 57 个 `.rs` + 实际运行 `cargo test` / `cargo build` / 二进制冒烟。
> 结论口径：**只算能跑起来的**，不以文档承诺为准。

---

## 1. 一句话

**协议内核、密码层、信令面、打洞引擎、服务端都已经写完并能跑通单机测试；
但"打通之后怎么传数据"这一层完全没有——内核把 socket 交出去，客户端收下就丢掉了。**

---

## 2. 基线数字

| 项 | 值 |
|---|---|
| 源文件 | 57 个 `.rs`，10,290 行（另有 GUI 无、文档 27 篇） |
| crate | 7 个：proto / crypto / punch / dht / core / wgp-node / wgp-client |
| 编译 | `cargo check` 0 warning（release LTO 39s） |
| 测试 | **148 个，全绿**（proto 36 / dht 42 / core 34 / punch 14 / node 14 / crypto 4 / client 4） |
| 依赖 | 11 个，全部是密码学与网络基础设施（无 libp2p / 无 quinn / 无 serde） |
| 产物 | `wgp-node.exe`、`wgp-node-hobby.exe`、`wgp-client.exe` |

测试全部是**单机 loopback**：`wgp-dht/net_test.rs` 用三节点（A、B、种子 S）在本地端口互发 UDP/TCP 验证路由与转发；其余是纯函数与编码往返。**没有任何一条测试跨过真实网络。**

---

## 3. 分层完成度

### 3.1 `wgp-proto` — 协议层：**完成**

9 个文件全部手写定长编解码，无 serde/protobuf。包含信令包（承诺-揭示）、打洞探针（31B）、DHT RPC（Ping/FindNode/FindValue/Store/Forward）、STUN 最小子集（RFC 8489 + 观察者扩展 0x80F0–0x80F2）、种子端点解析（含 `udp://`/`tcp://`/裸地址）、Punycode（RFC 3492，中文域名归一化）、U/ 房间码派生（自实现 MD5，文档 13 的 4 个标准向量实测命中）。

### 3.2 `wgp-crypto` — 密码层：**完成（PQ 只留接口）**

承诺-揭示（commit = SHA256(pk‖nonce)）、HKDF 一次展开产全会话密钥族（session / PSK / probe_key / heartbeat / escape）、探针 HMAC、逃生通道 AES-256-GCM 帧、`KeyAgreement` trait（现役 X25519）。`handshake_test.rs` 有端到端握手对拍（含 MITM 检出）。混合后量子（ML-KEM）明确未实现，只留 `algo_id = 0x02` 的位置。

### 3.3 `wgp-punch` — 打洞引擎：**完成**

预算调度器（H6：≤47 包/轮、≤500 包/10min，唯一发包点）、三波规划（21+15+11）、步长模型（3 次 STUN 学习预测窗口）、心跳控制器 + 保活循环、双模定时器、状态机。纯逻辑，无 IO，好测。

### 3.4 `wgp-dht` — 信令面：**可用，但有 4 处 v1 简化**

已实现：ed25519 身份持久化、XOR 距离路由表（K=20 封顶）、UDP+TCP 双栈 RPC、地址簿（防投递毒化）、观察者限频（每 IP 12 次/10s）、房间键 + 租约 + 继位链 + epoch、SeedAdvertise 签名交换、Forward 透明投递（fire-and-forget 邮件语义）。

简化（代码注释自认）：

| 位置 | 简化 |
|---|---|
| `kbucket.rs:1` | 路由表桶**不分裂、不逐出**（满即拒入新节点） |
| `dht.rs:16` | KV 存储 **K=1 单值**，非标准 Kademlia 多副本 |
| `node.rs:376` | 仅 IPv4 条目，IPv6 未来线 |
| `runtime.rs:2` | 房间"锚点 republish + 候选按继位链退避抢写 + 写后回读校验"，非完整 DHT 复制 |

### 3.5 `wgp-core` — 内核门面：**装配完成，交付点卡在 socket**

- `Engine`：三条路径 `new_link`（单点打洞）/ `join_room`（多人群）/ `run_node`（服务端面）
- `SessionOrchestrator`（635 行）：承诺-揭示 → 观察者探测 + 步长学习 → 端点交换（含 32B 完整承诺复验抗 MITM）→ T1–T4 判定 → 竞速
- 竞速：UDP 三波 ∥ TCP simultaneous-open，共享预算闸门，先通先用
- 四载体：UDP（主）、TCP（兜底）、LAN 组播发现、ICMP 逃生
- 保活：`engine/keepalive.rs` 复用 `HeartbeatLoop`，每包过预算闸门，`release()` 拉闸停

**交付物 = `PunchedLink { Udp{socket} | Tcp{stream}, session_key, quality, rank }`**——内核到此为止，数据面由外围负责（这是设计，不是缺陷）。

### 3.6 `server/wgp-node` — 服务端：**完成，Linux 未验证**

单进程四职（DHT 种子 / 观察者+STUN 响应器 / TCP 信令兜底 / Forward 承诺兜底）、双形态（完整版允许 Forward，`hobby` 版强制拒中转防 PCDN）、配置三源优先级（CLI > 环境变量 > 文件 > 默认）、身份 `node_identity.key` 32B 首启生成。冒烟通过：`--help`、非法配置 exit 2、就绪日志、三端口。

部署件 11 个齐（systemd ×2、nftables、一键脚本、Windows 一键包）——**包括 Linux 分支在内全部未在真机跑过**。

### 3.7 `client/wgp-client` — 客户端：**参考外围，不是产品**

`code` / 开房 / join 三个子命令；身份文件、种子测速选路、成员感知、11 种事件打印。**打通后 `SilentSink` 把 `PunchedLink` 直接丢弃**（`main.rs:371`）。

---

## 4. 端到端：今天实际能走到哪

```
[能做] 算房间码 → DHT 入表（建房/加入） → 承诺-揭示密钥协商 → 观察者探测 + 步长学习
      → 端点交换（抗 MITM 复验） → T1-T4 → UDP 三波 ∥ TCP 同时打开 → 交付 socket + 挂保活
[断了] socket 交给谁？ —— 没人接手，客户端直接丢弃
[没有] QUIC/TLS-PSK 数据面、端口转发、虚拟网卡、图形界面、多客户端 mesh 调试
```

对着 `docs/15-全链路流程.md` 的 Phase 0–8：**Phase 0→6 有代码，Phase 7（数据面）为 0，Phase 8（验收）无数据。**

---

## 5. 代码里明确写着的"还没做"

| 文件:行 | 原文 |
|---|---|
| `core/engine.rs:235` | "实现阶段：命中后接 QUIC 握手（3s 超时，T3 触发 TCP 兜底）；本迭代以'打洞成功'为交付点" |
| `core/engine/punch_runner.rs:4` | "当前为'发一批 → 短监听'的串行简化；生产实现应改为发包/收包并发（150ms 窗口）" |
| `core/link.rs:24` | "ICMP 逃生通道句柄（平台实现待接；仅信令级）" |
| `core/transport/escape.rs:171` | "本分支在当前 Windows 开发机上无法编译验证，服务器首日先 cargo build 验证" |
| `dht/kbucket.rs:1` | "Kademlia 路由表骨架（实现阶段补全：k-bucket 分裂、维护）" |
| `crypto/ka.rs:58` | "Hybrid PQ……未实现——接入点已留" |

---

## 6. 最容易被高估的部分：**全部验证都是单机的**

这是接手时最该警惕的一点：

1. **没有一次真实双端打洞**。所有"打洞成功"的断言来自单测里的 loopback、或代码推理。NAT 穿透的本质是跨网络行为，单机测不出来。
2. **NAT 实测数据是 6–8 月采的**（`nat/` 11 份），采集时用的工具很可能是 v1（mc-link 时代）的探测器，不是现在这套 `NatProbe`。用它推出来的"胜算评估"（docs/00 §7：NAT1/2/3 >95%、电信 NAT4 40–70%…）在 v2 上**未经复测**。
3. **Linux 完全没跑过**：ICMP 逃生 Unix 分支、systemd 单元、nftables 规则、一键脚本，一条都没执行过。
4. **服务端对外可达性未验证**：`wgp-node` 的三端口在公网上能不能被穿透/被限制，未知。

---

## 7. 换算成"还有多远"

以**"两台电脑在异 NAT 下真的玩上 Minecraft Java"** 为 100%：

| 段落 | 状态 | 大致占比 |
|---|---|---|
| 协议 / 密码 / 打洞引擎 / 信令面 | 代码完成、单机测试全绿 | ~40% |
| 服务端部署 + 真机可运行 | 代码完成、未验证 | ~10%（完成一半） |
| 真实网络下的打洞成功率 | **零数据** | 0 / 15% |
| 数据面（TLS-PSK 帧流 + 端口转发） | **零代码** | 0 / 25% |
| 客户端产品化（配置/托盘/打包/更新） | 只有 CLI | 0 / 10% |

**粗估：55% 左右。** 前半段（最难的技术内核）已经落地，后半段（验证 + 数据面 + 产品化）几乎没动。
好消息是剩下的部分技术难度低、路径清晰；坏消息是**没有一项经过真实环境检验**，实际返工风险集中在这里。

---

## 8. 建议的三个里程碑

### M1 · 真实环境打通（1–2 天，最高优先级）
两台异 NAT 机器 + 一台公网 `wgp-node`，跑 `wgp-client 开房` × `join --observer`，把事件流和耗时记下来。
目的不是"成功"，是**拿到第一份真实数据**：哪些阶段超时、NAT 类型判对没、三波打完多久、TCP 兜底是否触发。
产物回填 `nat/` 与 docs/18。

### M2 · 数据面 `wgp-port`（3–7 天，解锁"能联机"）
`PunchedLink` + `KeyExporter` 的 `PskBundle` → TLS-PSK 帧流 → 本地 `TcpListener` ⇄ 隧道。
即：房主把本地 25565 暴露到隧道，加入方在本地起一个端口，Minecraft 直连 `localhost`。
v1（`E:\Work Files\Code\Rust\mc-link-core`）里的 `reliable.rs`（seq/ack/50ms 重传/分帧）可以直接搬来做骨架，能省两天。

### M3 · 产品化（之后）
Bedrock（UDP/RakNet，`app_adapter` 已有识别逻辑可搬）、图形界面、打包分发、多客户端 mesh 调试。

---

## 9. 五分钟自己验一遍

```bash
cargo test --workspace          # 148 绿
cargo build --release

# 起服务端（本机即可）
target/release/wgp-node --bind 127.0.0.1:11010 --stun 3478 --tcp 3481

# 算房间码（离线，命中文档 13 向量）
target/release/wgp-client code 示例房间 123456     # U/C2G9-GYET-311W-R636

# 两个终端分别开房/加入（同一台机器需要两个 --identity）
target/release/wgp-client 开房 --name t --key k --seed udp://127.0.0.1:11010 -i a.key
target/release/wgp-client join U/xxxx-xxxx-xxxx-xxxx --seed udp://127.0.0.1:11010 -i b.key
```

打通后会看到 `LinkYielded` 事件，然后……什么也不会发生——这就是第 4 节说的那一步。
