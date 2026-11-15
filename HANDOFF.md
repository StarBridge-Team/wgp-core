# 交接文档（HANDOFF）

> 首次生成于 2026-11-07；**2026-11-15 更新**：路线图 M2 / M3（PoC）/ M4 / M5（可本机验证部分）已完成。
> 配套阅读：[`PROGRESS.md`](PROGRESS.md)（11-07 的代码盘点快照）、[`STATUS.md`](STATUS.md)（拼装与验证记录）。
> 本文回答三个问题：**做了什么 → 现在在哪 → 接下来怎么走。**

---

## 1. 一句话状态

**「能联机」的整条链路已经在回环上走通：种子互相发现 → 入表 → 打洞 → 加密隧道 → 端口转发，
Windows 与 Linux 都用真实二进制跑过。但仍然没有任何一次真实 NAT 下的双端联调（M1）——
所有「打洞成功」都发生在 127.0.0.1 上。**

---

## 2. 做了什么

### 2.1 第一轮（2026-11-07）：拼装与建仓

- 分清两个工程：`mc-link-core` 是 v1 存档，文档描述的是 v2「折跃门 wgp」。
- 把散落的 v2 源码拼成可构建的 workspace（补根 `Cargo.toml`），152 个测试全绿；补齐 `nat/` 11 份数据。
- 三个仓库与许可证链：EasyTier (LGPL) → mesh-tun-proto (LGPL) → **wgp (GPL)** → mc-link (GPL)。
- 客户端支持 `join --network-name N --network-secret S`；写了 [`docs/17`](docs/17-DHT节点身份与信任方案.md)。

细节见 [`STATUS.md`](STATUS.md)。

### 2.2 第二轮（2026-11-15）：按路线图补完剩余部分

| 里程碑 | 结果 | 代码落点 |
|---|---|---|
| **M1 真机联调** | **未做**（按要求搁置） | — |
| **M2 数据面** | 完成 | `bridge/wgp-port`，`client/wgp-client` |
| **M3 ET 桥接** | PoC 完成（互发消息）；TUN / 虚拟 IP / 路由未做 | `bridge/wgp-et-bridge`（独立 workspace） |
| **M4 DHT 接线** | 完成（P0：不校验信任） | `kernel/wgp-proto`、`wgp-dht`、`wgp-core`，`server/wgp-node`，`client/wgp-client` |
| **M5 产品化** | 基岩版 UDP 转发、打包脚本、Linux 运行验证、CI 与多平台发版已做；**GUI 未做** | `scripts/`、`.github/workflows/` |

**M2 数据面**：打通的链路不再被丢弃，而是建成加密隧道做端口转发。

```
本地应用 ⇄ forward ⇄ mux ⇄ link ⇄ PunchedLink
                             ├─ UDP：AES-256-GCM 数据报 + 自带可靠层
                             └─ TCP：AES-256-GCM 记录流
```

路线图写的是 TLS-PSK，但 rustls 0.23 没有外部 PSK 接口（翻源码确认），改用 `docs/01` §1.3 已设计的 AES-GCM 帧，
UDP 上自带一个轻量可靠层，**零新增第三方依赖**。可靠层与复用层之间只有一个接缝，日后可换 QUIC。

**M4 DHT 接线**：节点周期宣告自己（签名广告 V2），互相验签 + 探活后收进种子目录；客户端从任一入口种子
学到其余种子与观察者，并按房间键**确定性**选存储节点（不再是「各自测速最快的」）。结果：
`--observer` 不必手填；两个人填的种子不一样也能进同一个房间；hobby 节点配一个完整版种子即可用。

**M3 ET 桥接 PoC**：把 ET 帧跑在我们的加密隧道流上（`add_custom_transport`），两个 WGP 节点打洞后完成 ET
握手并互发消息。没有按「实现 `ExternalHolePunchBridge`」去做——那个接口的返回值只有地址、没有 socket，
接不上我们打通的洞；理由与后续见 [`bridge/wgp-et-bridge/README.md`](bridge/wgp-et-bridge/README.md)。
mesh-tun-proto 一行未改。

### 2.3 顺带修掉的缺陷（都有回归测试）

| # | 缺陷 | 后果 |
|---|---|---|
| 1 | 打洞预算的「轮」从不复位 | 进程内第二次打洞起配额为 0；保活用完余量后永久停摆 |
| 2 | `PunchedLink` 没有对端地址 | 外围拿到链路却不知道往哪发 |
| 3 | 装配线阶段漂移死锁 | 两端不是同时起步就可能双双超时 |
| 4 | 端点帧解析越界 | 一个 4 字节载荷就能让客户端 panic |
| 5 | 对端没学出步长模型时无视其实测端口 | 全范围盲撒，最好打的锥形 NAT 反而打不通 |
| 6 | **报道请求明文携带房间码** | 房间码是会话密钥派生的口令，经种子中转等于交给种子；读代码推断可据此做中间人，未写攻击实测 |
| 7 | 租约过期判定跨进程比较单调时钟 | 成员进程比锚点老会误夺锚点；比锚点新则锚点掉线后很久判不出 |
| 8 | 加入房间时报道只发一次 | 丢一个包就「入表超时」 |

第 6 项改了报文格式（JoinRequest v2），**新旧客户端不能混用**。API 漂移全部登记在
[`docs/14`](docs/14-内核API文档.md) §12.1。

### 2.4 验证范围（全部在本机，全部是回环）

| 验证项 | 结果 |
|---|---|
| `cargo test --workspace` | **286 passed / 0 failed**（另有 `bridge/wgp-et-bridge` 4 个） |
| `cargo check --workspace --all-targets` | 0 warning；`x86_64-unknown-linux-gnu` 目标同样 0 warning |
| Windows 端到端（`scripts\e2e-local.ps1`） | 单种子 / `-Discovery` / `-Discovery -Hobby` 全部 PASS |
| Linux 端到端（`scripts/e2e-local.sh`，WSL2 Ubuntu 24.04，musl 静态二进制） | 三种模式全部 PASS——这是项目第一次在 Linux 上运行 |
| 吞吐（release，回环，经转发口） | Windows 单向约 33 MiB/s；WSL 约 18 MiB/s |
| 仅 hobby 种子 | **复现失败**：第二个成员始终进不了房间（见 §3.2） |

端到端脚本的流程：种子 → 房主开房并暴露回显服务 → 加入方入表、打洞、建隧道 → 经本地转发口校验 TCP
（4MiB 逐字节）与 UDP → 杀掉加入方再重启，校验重新打洞后转发恢复。

---

## 3. 现在卡在哪

### 3.1 最大的未知：真实网络

所有验证都在回环上。NAT 类型判定、端口预测、三波时序、保活间隔、可靠层在真实丢包与乱序下的表现——
**一项都没有真实数据**。M1 仍是最高优先级。

### 3.2 已知问题（未修，按影响排序）

| # | 问题 | 说明 |
|---|---|---|
| 1 | **只有 hobby 种子时无法多人联机** | 报道与密钥协商都靠种子 Forward 中转，hobby 拒绝一切中转。文档称线上种子正是 hobby。客户端现在会给出明确告警；策略怎么改是待决项（§5 第 5 条） |
| 2 | UDP 被封的网络连不上 | 房间 RPC 只走 UDP；TCP 兜底拿不到本端公网 IP；T2（UDP 三波全灭 → TCP）在装配线里没有接线 |
| 3 | PING / PONG 不带签名 | 身份可被人拿到别的地址上冒用，种子的地址簿会被改写（信令 DoS）；种子目录的「探活」证明的只是该地址上有人自称是这个身份 |
| 4 | FIND_NODE / FIND_VALUE 应答远大于请求 | UDP 源地址可伪造，这两个既有 RPC 是约 20 倍的反射放大器。新增的 FIND_SEEDS 已按「应答不长于请求」设计，旧的没动（改了就是协议变更） |
| 5 | 观察者限频与用量不匹配 | 默认每 IP 12 次 / 10s，而每次协商每端要 4 次：同一公网 IP 下多人或多对端并发协商会被限 |
| 6 | 弱房间名 / 密钥可被离线猜解 | 存储节点知道 room_key（房间码的哈希），可对弱口令做字典攻击。「开房」不给密钥时默认随机生成 |
| 7 | 房间记录仍是单存储点（K=1） | 存储节点掉线则房间不可达；两端认识的种子不一样时靠「跟随既有房间」缓解，不能根除分裂 |
| 8 | 协商最后一帧丢失 | 「两将军」问题：一端以为完成、另一端超时；靠客户端的重试兜底 |
| 9 | Unix 的 ICMP 逃生后端收不到包 | socket 设了非阻塞又立即同步读；该载体本来也没有接线 |
| 10 | 重度乱序下可靠层吞吐低 | 标准阈值把乱序判成丢包；调优要等真实数据 |
| 11 | `--advertise` 只支持固定 IPv4 | 家宽动态 IP 的节点换了地址要重启；外部端口必须与本机端口一致 |
| 12 | P0 不校验信任 | 任何人都能宣告自己是种子并可能被选为存储节点；目录只代表「存在且连得上」 |

### 3.3 没做的

- GUI、虚拟网卡（`docs/12`）、托盘 / 自动更新。
- ET 桥接的下游：接进客户端、TUN / 虚拟 IP / 路由、与真正的 EasyTier 节点互通。
- 17 文档的 P1 / P2：背书、信任评分、域名锚、PoW、/24 限入。

---

## 4. 路线图

### M1 · 真机联调（最高优先级，仍未做）

- [ ] 两台异 NAT 机器 + 一台公网 `wgp-node --advertise <IP>`
- [ ] 跑 `wgp-client 开房 --expose` × `join --forward`，留下两端终端输出
- [ ] 记录：哪一步超时、NAT 类型判对没、三波打多久、TCP 兜底触发没、隧道吞吐与重传率
- [ ] 结果回填 `nat/` 与 `docs/18`

### M2 · 数据面 `wgp-port`（完成）

- [x] `bridge/wgp-port`：加密隧道（UDP 可靠层 / TCP 记录流）、多路复用、端口转发（TCP 与 UDP）
- [x] UDP socket 分流：按类型字节区分保活探针与隧道报文
- [x] 客户端 `--expose / --forward / --expose-udp / --forward-udp`，逐对端链路监管与重连
- [x] 本机双客户端验证

### M3 · ET 桥接（PoC 完成，目标未达成）

**目标（2026-11-15 确认）**：不使用官方 ET 客户端，由本项目建立连接，作为节点加入 EasyTier 网络，
并支持基础的 ET 节点特性。

- [x] PoC：两个 WGP 节点打洞成功 → 跑 ET 协议 → 互发一条消息（两端都是本项目的节点）
- [x] tick 线程包装 `P2pNode`，事件转出
- [ ] ~~实现 `ExternalHolePunchBridge`~~：按现有接口走不通，改走 `add_custom_transport`（理由见该目录 README）
- [ ] **与真正的 EasyTier 节点互通**：官方节点不认识我们的打洞信令，和它们只能走标准的 ET TCP / UDP 连接
  （mesh-tun-proto 已有这两种传输），打洞直连只发生在两个都跑本项目的节点之间。需要一个官方节点来对测，未做
- [ ] 路由同步、虚拟 IP 宣告、IP 帧在隧道传输上跑通（库里有实现，PoC 只覆盖了握手与用户数据）
- [ ] TUN 虚拟网卡（Windows 需要 Wintun 驱动与管理员权限）
- [ ] 做成可用的程序：「加入 ET 网络」的命令；一对节点谁来开流的确定性规则；数据帧改走隧道的数据报通道

### M4 · DHT 接线（完成，P0）

- [x] 启动后周期广播种子广告，入站验签 + 探活后入表（`wgp-node --advertise / --peers`）
- [x] 客户端用 FIND_SEEDS / FIND_NODE 扩散，而不是只认一个种子
- [x] P0 不校验信任
- [ ] 17 文档 P1 / P2（等 §5 的决策）

### M5 · 产品化

- [x] 基岩版 UDP 转发（`--expose-udp / --forward-udp`）
- [x] 打包：本机 `scripts\package.ps1`；GitHub Actions 多平台预览版发版（见 §6）
- [x] Linux 运行验证（WSL）；真机 systemd / nftables 部署件仍未执行过
- [ ] GUI

---

## 5. 待决策（需要团队拍板）

| # | 问题 | 影响 | 现状 |
|---|---|---|---|
| 1 | 「DHT 节点」= 每个客户端也宣告自己，还是只有公网节点宣告？ | 发现层的规模与攻击面 | 只实现了机制；目前只有配了 `--advertise` 的节点宣告，客户端不宣告 |
| 2 | 官方根用 DNS 锚还是纯背书锚？ | 信任模型强度 | 未动 |
| 3 | PoW 取 16 / 18 / 20 bit？ | 抗 sybil vs 启动耗时 | 未动 |
| 4 | ET 桥是独立进程还是同进程？ | 部署复杂度 | PoC 是同进程的库 + 独立线程，两种形态都还能选 |
| 5 | **hobby 节点是否允许少量信令中转？** | 只有 hobby 种子时能否多人联机 | 未动默认行为。可选：限速中转 / 只中转报道与协商帧 / 维持现状并要求至少一个完整版种子 |

---

## 6. 发版与 CI

- **CI**（`.github/workflows/ci.yml`）：推送到 main 与每个 PR，在 Windows / Linux 上跑全量测试与回环端到端，
  并对其余发版目标做编译检查。
- **发版**（`.github/workflows/release.yml`）：推送 `v*` 标签即构建 8 个目标并发布为 **pre-release**：

  ```
  git tag v0.1.0-preview.1 && git push origin v0.1.0-preview.1
  ```

  Windows：x86_64 / i686 / ARM64；Linux（musl 静态）：x86_64 / i686 / ARM64 / ARMv7 / 龙架构 64。
  龙架构 32 位与 Windows 32 位 ARM 没有带标准库的 Rust 目标，编不了。
  转正时把工作流里的 `PRERELEASE` 改为 `'false'`。
- 本机只编 Windows x86_64：`powershell -ExecutionPolicy Bypass -File scripts\package.ps1`，产物在 `dist\`。

---

## 7. 五分钟自己验一遍

```powershell
cd 'E:\Work Files\Code\Rust\wgp'
cargo test --workspace                                                    # 286 绿
powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1            # 单种子全流程
powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1 -Discovery # 双种子发现
```

手工走一遍（三个终端；同一台机器要用不同的 `-i` 身份文件）：

```powershell
target\release\wgp-node --bind 127.0.0.1:11010 --advertise 127.0.0.1
target\release\wgp-client 开房 -n t -k k -p udp://127.0.0.1:11010 -i a.key --expose 25565
target\release\wgp-client join -n t -k k -p udp://127.0.0.1:11010 -i b.key --forward 25566:25565
```

加入方打印 `[隧道] 就绪` 之后，连 `127.0.0.1:25566` 就是连到房主本机的 25565。
