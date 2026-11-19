# 交接文档（HANDOFF）

> 首次生成于 2026-11-07；**2026-11-16 更新**：路线图 M2 / M3（PoC）/ M4 / M5（可本机验证部分）已完成；
> 本轮补上「探活身份证明」「UDP 被封时的 TCP 信令」「路由维护」「多进程阶段 1」，并发出版本标签。
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
- 客户端支持 `join --network-name N --network-secret S`；写了 [`项目完整文档/17-DHT节点身份与信任方案`](项目完整文档/17-DHT节点身份与信任方案.md)。

细节见 [`STATUS.md`](STATUS.md)。

### 2.2 第二轮（2026-11-15）：按路线图补完剩余部分

| 里程碑 | 结果 | 代码落点 |
|---|---|---|
| **M1 真机联调** | **未做**（按要求搁置） | — |
| **M2 数据面** | 完成 | `bridge/wgp-port`，`client/wgp-client` |
| **M3 ET 桥接** | PoC 完成（互发消息）；TUN / 虚拟 IP / 路由未做 | `bridge/wgp-et-bridge`（独立 workspace） |
| **M4 DHT 接线** | 完成（P0：不校验信任） | `kernel/wgp-proto`、`wgp-dht`、`wgp-core`，`server/wgp-node`，`client/wgp-client` |
| **M5 产品化** | 基岩版 UDP 转发、打包脚本、Linux 运行验证、CI 与多平台发版工作流已实现；**远端尚未执行发布**（本轮检查：`main` 无 release.yml、Actions runs / tags / Releases 均为 0）；GUI 未做 | `scripts/`、`.github/workflows/` |

**M2 数据面**：打通的链路不再被丢弃，而是建成加密隧道做端口转发。

```
本地应用 ⇄ forward ⇄ mux ⇄ link ⇄ PunchedLink
                             ├─ UDP：AES-256-GCM 数据报 + 自带可靠层
                             └─ TCP：AES-256-GCM 记录流
```

路线图写的是 TLS-PSK，但 rustls 0.23 没有外部 PSK 接口（翻源码确认），改用 [`项目完整文档/01-安全与加密算法`](项目完整文档/01-安全与加密算法.md) §1.3 已设计的 AES-GCM 帧，
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
| 9 | 没宣告自己的贡献节点被当成可中转 | 房间可能建在它上面（看房间键离谁近），第二个成员进不来，且没有告警 |
| 10 | TCP 兜底只做主动连接；一波里的多个端口并行尝试却没开端口共用 | Linux 上 SYN 不交叉就被 RST，回环与公网直连主机上打不通（Windows 会自行重发 SYN，掩盖了问题）；并行尝试实际只有第一个端口在试 |
| 11 | 串行探测执行器收到第一枚验签通过的包就结束监听 | 自己的探针折返回来时，随后到达的真对端探针被错过（该执行器目前只有测试在用） |
| 12 | 节点入网引导只做一次 | 几个种子同时启动时 20～60 秒内互不认识；这期间两个只认识不同种子的客户端会把同一个房间建到两个存储节点上 |
| 13 | 存储节点重启后房间不恢复 | 房间记录与地址簿都只在种子的内存里：重启后记录没人重建，新来的人另起一个房间；老成员的地址要 20 秒后才重新登记，期间协商反复失败 |

第 10～13 项是第一次在 Linux 上跑全套测试、端到端与场景测试时查出来的（此前只在 Windows 上跑过）。

**客户端易用性**（同一轮）：房主启动后直接打印一行完整的加入命令（含种子与转发端口），同伴原样执行即可；
隧道通了但没转发对端暴露的端口、用「加入」却没找到房间、入表失败，这三种情况现在都有明确的说明。

第 6 项改了报文格式（JoinRequest v2），**新旧客户端不能混用**。API 漂移全部登记在
[`项目完整文档/14-内核API文档`](项目完整文档/14-内核API文档.md) §12.1。

### 2.4 验证范围（全部是回环；Windows 与 WSL 在开发机，原生 Linux 在一台云端虚拟机）

| 验证项 | 结果 |
|---|---|
| `cargo test --workspace` | **Windows 363，0 failed**（含 `wgp-ipc` 30 个、`wgp-agent` 3 个、`wgp-dht` 101 个；`bridge/wgp-et-bridge` 4 个不在该 workspace 内） |
| wgp-core 整套测试并行重复运行 | Windows 30 遍、Linux 150 遍，0 失败（修复第 11 项之前：Linux 150 遍里失败 2 遍） |
| `cargo check --workspace --all-targets` | 0 warning |
| Windows 端到端（`scripts\e2e-local.ps1`） | 单种子 / `-Discovery` / `-Discovery -Hobby` 全部 PASS；本轮重跑单种子 PASS |
| agent IPC 冒烟（`scripts\agent-smoke.ps1`） | PASS：就绪、同端点二次绑定被拒（退出码 3）、`ping` 取到版本与快照、`ShutdownAgent` 走优雅退出、端点清理 |
| Linux 端到端（`scripts/e2e-local.sh`） | 上一轮：WSL2 Ubuntu 24.04 与云端原生 Linux 三种模式全部 PASS；本轮未重跑（`wgp-ipc` 的 Unix 分支由 CI 覆盖） |
| 种子重启场景 | 上一轮：新成员在种子恢复 0～3 秒后加入，7 次全部连上房主 |
| 吞吐（release，回环，经转发口） | Windows 单向约 33 MiB/s；WSL 约 18 MiB/s |
| 仅 hobby 种子 | **复现失败**：第二个成员始终进不了房间（见 §3.2） |
| 真实 NAT 双端联调 | **仍未做**：没有可达的公网种子（既有配置里的两台 VPS 均已不可达），见 §3.1 |

端到端脚本的流程：种子 → 房主开房并暴露回显服务 → 加入方入表、打洞、建隧道 → 经本地转发口校验 TCP
（4MiB 逐字节）与 UDP → 杀掉加入方再重启，校验重新打洞后转发恢复。

### 2.5 第三轮（2026-11-16）：安全与进程边界

按「先安全、再兜底、最后进程边界」的顺序做了四件事，细节见 [`项目完整文档/20-变更追补-2026-11.md`](项目完整文档/20-变更追补-2026-11.md) §11-16：

| 主题 | 结果 | 代码落点 |
|---|---|---|
| **探活身份证明** | 一次一密挑战响应（`AUTH_CHALLENGE/PROOF/REJECT`），签名绑定域、双方 NodeId、txid 与新鲜 nonce；**验证通过前不写路由表与地址簿**；广告加 `FLAG_AUTH_V1`；严格模式默认，`--allow-legacy-identity` 显式兼容旧节点 | `wgp-proto::dht`、`wgp-dht::auth`（新）、`wgp-dht::node` |
| **UDP 被封时的入房** | `Transport::{Udp,Tcp}` 贯穿 DHT 与房间运行时；bootstrap / 选点 / `fetch`·`store`·`renew` 可走 TCP（复用同一 RPC 与长度前缀帧）；不支持的拓扑在开始阶段就给可读报错 | `wgp-dht::{node,runtime}`、`wgp-core::{engine,servers}`、`wgp-client` |
| **路由维护** | 轮转窗口抽成纯函数 + 组合覆盖测试；种子探过的不再重复探；探活成功刷新地址簿 | `wgp-dht::node` |
| **多进程阶段 1** | 新增 `wgp-ipc`（本机端点 + ACL + 有界队列 + 版本化帧）与 `wgp-agent`（持有身份/socket/Engine/PortHub，经 IPC 接受 8 条命令） | `kernel/wgp-ipc`（新）、`client/wgp-agent`（新） |

同时修掉三个新问题：恢复工作区时的编码/备份教训（记入项目记忆）、客户端「种子不可达」的三种原因不再混为一谈、
`wgp-client` 与 agent 的存储选点规则必须一致（已各自带测试，真正合并等 client 抽成库）。

---

## 本轮补记（2026-11-18）：SIG v2 握手身份认证

网络安全审计中的高危会话 MITM 已在当前代码中修复：协商 transcript 由房间成员长期身份签名，绑定双方 NodeId、房间键派生值、临时密钥/nonce、Commit 与每轮随机挑战；端点报告也签名，`connect_peer` 会重新验证房间签名记录并确认本端和对端成员身份。信令版本升为 v2，旧版客户端不兼容。回归测试与 Windows workspace 测试通过，但真实公网/NAT 测试仍未做。分类和后续任务见 [`reports/network-security-vps-task-triage-2026-11-18.md`](reports/network-security-vps-task-triage-2026-11-18.md)。

## 本轮补记（2026-11-19）：审计中低难度项 + FRP/DDNS 部署 + ET 推进

按交接报告里「中等难度 M1/M2/M5/M6 + 全部简单项」收口，并新增两条产品能力：

| 主题 | 结果 | 落点 |
|---|---|---|
| STUN 响应绑定 | 类型/txid/nonce/映射地址四道校验 + 来源地址绑定 + CSPRNG txid | `wgp-core::engine::nat_probe`（5 个新用例） |
| 端点地址准入 | 默认只收公网地址（回环/RFC1918/链路本地/CGNAT/保留/文档网段/IPv6 全拒），局域网形态显式放宽 | `wgp-dht::addr`（新）、`--allow-local-endpoints`（node / client） |
| 房间容量 | `MAX_ROOM_MEMBERS=12`；`try_encode` 不再静默截断；满员 `RoomFull` 且不改写旧记录 | `wgp-dht::room`、`runtime` |
| 入站限速 | 单源窗口 + 全局每秒 + 源表上限的统一闸门；DHT socket 上的 STUN 也纳入；放大应答加字节预算 | `wgp-dht::ratelimit`（新）、`observe`、`node` |
| 种子部署 | `--advertise` 支持 DDNS 域名并自动重宣告；外部端口可独立（FRP / 端口映射）；`--allow-local-endpoints` | `wgp-core::AdvertiseTarget`、`wgp-node`、`server/deploy/frp/*`、`install-seed-frp.sh` |
| 简单项 | 观察者默认额度 12→60 次/10s（另加全局）；TCP-only 文案；测试临时目录不再互相删除；格式整治仍单独立项 | 见 [`20-变更追补-2026-11.md`](项目完整文档/20-变更追补-2026-11.md) §22 |

验证：`cargo check --workspace --all-targets` 0 warning；`cargo test --workspace` 全绿（22 个测试目标，0 failed）。
**仍然没有真实 NAT / 真实 FRP / 真实 DDNS 验证**——脚本与参数解析有测试，拓扑可用性只有检查表。

M3 只做了「不改变报文格式」的缓解（放大应答字节预算），**源地址 cookie 仍待协议决策**；
M4/M7-M12 未动（都需要先有 M12 的基线与多机环境）。

## 3. 现在卡在哪

### 3.1 最大的未知：真实网络

所有验证都在回环上。NAT 类型判定、端口预测、三波时序、保活间隔、可靠层在真实丢包与乱序下的表现——
**一项都没有真实数据**。M1 仍是最高优先级。

本轮试图补上这一环时发现：既有配置里指向的两台 VPS 都已不可达（`103.236.84.213:48772` 连接被拒、
`70.39.201.151:22` 只接受密码且无凭据），本机也没有可用的公网出口映射。因此**真实 NAT 联调仍缺一台可达的
公网种子**。需要的东西很少：一台有公网 IP 的 Linux（1 核 / 512MB 足够），放行 UDP 11010 + UDP 3478 + TCP 3481，
跑 `wgp-node --bind 0.0.0.0:11010 --advertise <公网IPv4>`；随后按 [`项目完整文档/18-NAT实测数据.md`](项目完整文档/18-NAT实测数据.md)
的表格记录两端的入网时间、NAT 类型、打洞轮次、TCP 兜底是否触发、丢包与失败阶段。

### 3.2 已知问题（未修，按影响排序）

| # | 问题 | 说明 |
|---|---|---|
| 1 | **只有 hobby 种子时无法多人联机** | 报道与密钥协商都靠种子 Forward 中转，hobby 拒绝一切中转。文档称线上种子正是 hobby。客户端现在会给出明确告警；策略怎么改是待决项（§5 第 5 条）。另：没有宣告自己的 hobby 节点（家宽无固定地址）客户端认不出来，身边没有「明确可中转」的种子时仍会被选为存储节点，且没有告警 |
| 2 | UDP 被封时只能「入表 + 读写房间」 | 信令可以走 TCP 种子了（`-p tcp://<种子>:3481`），但**报道 → 锚点**这一跳仍依赖存储节点地址簿里的 UDP 地址，T2（UDP 三波全灭 → TCP 数据面）也没有接线。两端之间 UDP 全灭时隧道建不起来——命令会明确说明这一点 |
| 3 | ~~入站 PING 不证明私钥持有权~~ **已修（2026-11-16）** | 一次一密挑战响应（`AUTH_CHALLENGE/PROOF/REJECT`），签名绑定域、双方 NodeId、txid 与新鲜 nonce，验证通过前不写路由表/地址簿。旧节点需 `--allow-legacy-identity` 才被采信。残留风险见 17 §11.8 第 1 条：在线中继仍可把「别人的身份」证明到自己的地址上（可用性问题，探活连续失败即淘汰） |
| 14 | 普通 DHT 路由桶死项不主动淘汰 | 本轮已加每 20s 最多 8 项的轮转探活，连续 3 次失败后删除路由及地址簿；需要多机/真实网络压测确认间隔与误删率 |
| 15 | DHT 节点释放不能停止 UDP 接收任务 | 本轮读任务改持 `Weak` 并监听 sender 关闭；固定端口丢弃后重绑回归测试通过 |
| 4 | FIND_NODE / FIND_VALUE 应答远大于请求 | UDP 源地址可伪造，这两个既有 RPC 是约 20 倍的反射放大器。FIND_SEEDS 已按「应答不长于请求」设计。**2026-11-19**：三类放大应答（NEIGHBORS/VALUE/SEEDS）加了按源 IP 的字节预算（单源 32 KiB/s、全局 1 MiB/s），但彻底的源地址 cookie 要改线协议，仍待决策 |
| 5 | ~~观察者限频与用量不匹配~~ **已修（2026-11-19）** | 默认从 12 次/10s 提到 60 次/10s（≈15 个成员并发协商），并加全局 600 次/秒兜底；`--observer-rate-limit` 仍可覆盖 |
| 6 | 弱房间名 / 密钥可被离线猜解 | 存储节点知道 room_key（房间码的哈希），可对弱口令做字典攻击。「开房」不给密钥时默认随机生成 |
| 7 | 房间记录仍是单存储点（K=1） | 存储节点掉线则房间不可达；两端认识的种子不一样时靠「跟随既有房间」缓解，不能根除分裂。一旦同一个房间被建到了两个种子上，之后即使种子目录补全也不会自愈 |
| 8 | 协商最后一帧丢失 | 「两将军」问题：一端以为完成、另一端超时；靠客户端的重试兜底 |
| 9 | Unix 的 ICMP 逃生后端收不到包 | socket 设了非阻塞又立即同步读；该载体本来也没有接线 |
| 10 | 重度乱序下可靠层吞吐低 | 标准阈值把乱序判成丢包；调优要等真实数据 |
| 11 | ~~`--advertise` 只支持固定 IPv4~~ **已修（2026-11-19）** | 现在接受 `ipv4 / DDNS 域名 / none`；域名按 `--ddns-refresh`（默认 300s）重解析，地址变化自动换纪元重宣告。外部端口可用 `--advertise-{dht,stun,tcp}-port` 独立指定（FRP / 端口映射）。仍未做 UPnP/NAT-PMP 自动映射与 IPv6 广告 |
| 12 | P0 不校验信任 | 任何人都能宣告自己是种子并可能被选为存储节点；目录只代表「存在且连得上」 |
| 13 | `rust-version = "1.75"` 与锁文件不符 | 锁定的 `zeroize_derive 1.5.0` 要求 Rust 1.85 以上（用 1.83 构建会在解析依赖时失败）。基线就是如此；CI 用最新稳定版，不受影响 |
| 16 | 多进程阶段 1 的已知缺口 | `GetSnapshot.links` 恒为空；`LeaveRoom` 不释放转发端口（`PortHub` 没有关监听的 API）；多房间共用一份 `Engine`，暂定只开一个；IPC 只有「同一用户」这一层鉴权，没有方法级授权与重放保护。逐条写在 `client/wgp-agent/README.md` |
| 17 | 升级顺序有要求 | 老版本种子不置 `FLAG_AUTH_V1`，严格模式下会被探活拒绝：先升种子，再升客户端；过渡期两端都加 `--allow-legacy-identity` |
| 18 | TCP 模式下的邻居扩散退化 | `Neighbors` 应答里是 UDP 端口，TCP 模式下按 TCP 语义去连会失败，`lookup_node` 只能覆盖手工入口（12 §6.3） |

### 3.3 没做的

- GUI、虚拟网卡（[`项目完整文档/12-虚拟网卡设计`](项目完整文档/12-虚拟网卡设计.md)）、托盘 / 自动更新。
- ET 桥接的下游：接进客户端、TUN / 虚拟 IP / 路由、与真正的 EasyTier 节点互通。
- 17 文档的 P1 / P2：背书、信任评分、域名锚、PoW、/24 限入。

---

## 4. 路线图

### M1 · 真机联调（最高优先级，仍未做）

- [ ] 两台异 NAT 机器 + 一台公网 `wgp-node --advertise <IP>`
- [ ] 跑 `wgp-client 开房 --expose` × `join --forward`，留下两端终端输出
- [ ] 记录：哪一步超时、NAT 类型判对没、三波打多久、TCP 兜底触发没、隧道吞吐与重传率
- [ ] 结果回填 `nat/` 与 `项目完整文档/18-NAT实测数据.md`

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
- [x] UDP 被封时的信令兜底：TCP 种子（bootstrap / 选点 / 房间读写）
- [x] 多进程阶段 1：`wgp-agent` + `wgp-ipc`（GUI 仍是下一步）
- [ ] GUI
- [ ] 把 `wgp-client` 改成 agent 的 IPC 客户端（需要先把它的装配线抽成库）

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
- **发版工作流配置**（`.github/workflows/release.yml`）：代码已实现，推送 `v*` 标签时构建 8 个目标并发布为 **pre-release**；但截至 2026-11-16 检查，当前远端分支有 workflow 文件，`main` 尚无此文件，Actions run / pushed tag / Release 均为 0，因此还没有发生自动发版：

  ```
  git tag v0.1.2 && git push origin v0.1.2
  ```

  Windows：x86_64 / i686 / ARM64；Linux（musl 静态）：x86_64 / i686 / ARM64 / ARMv7 / 龙架构 64。
  龙架构 32 位与 Windows 32 位 ARM 没有带标准库的 Rust 目标，编不了。
  Linux 的交叉链接用 **cargo-zigbuild**（Zig 自带 musl 与 compiler-rt，不需要各架构的 gcc 工具链，也不再自行拼 CRT）；
  本机同样一条命令：`cargo zigbuild --release --target <target>`（需要 `pip install ziglang cargo-zigbuild`）。
  转正时把工作流里的 `PRERELEASE` 改为 `'false'`。
  改到发版流程本身的 PR 会自动做一次不发布的全矩阵演练（构建 + 验证 + 打包，产物挂在该次运行上）。
- **Windows 产物静态链接 C 运行时**（`.cargo/config.toml`）：不依赖目标机器上的 VC++ 运行库。
  此前的构建（含 11-15 早些时候打的 `c85c207` 包）是动态链接，没装运行库的机器上会报找不到 `vcruntime140.dll`。
- 本机只编 Windows x86_64：`powershell -ExecutionPolicy Bypass -File scripts\package.ps1`，产物在 `dist\`。
  脚本在独立的 `target\package` 里构建，并把构建者的用户目录路径从程序里改写掉（否则本机用户名会跟着包发出去）。

---

## 7. 五分钟自己验一遍

```powershell
cd 'E:\Work Files\Code\Rust\wgp'
cargo test --workspace                                                    # Windows 363 绿
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


---

## 8. 下次开工先做这几件事（2026-11-16 收工时的状态）

**当前状态**：main 已合入（PR #1，merge commit 4489a9d）；CI（Windows/Linux 测试 + agent IPC 冒烟 + 交叉编译检查）
与发版全矩阵演练（workflow_dispatch，run 43882937807：8 个目标全部 success、8 份产物 + 每目标 sha256 已上传）都是绿的。
**标签还没打**——公开预览版发布是刻意留到下次的：

`ash
git tag v0.1.2 && git push origin v0.1.2     # 会真的发布公开 pre-release
`

打完标签要核对：Release 页面 8 个资产 + SHA256SUMS.txt + 每目标 .sha256；把 run/Release 链接补进本文 §6。

之后按这个顺序：

1. **真实 NAT 联调**（唯一还缺证据的一环）。需要一台可达的公网 Linux：放行 UDP 11010 / UDP 3478 / TCP 3481，
   跑 wgp-node --bind 0.0.0.0:11010 --advertise <公网IP>。流程与要填的表见 scripts/nat-field-test.md
   与 项目完整文档/18-NAT实测数据.md §7。之前配置的两台 VPS 都不可达（一台端口拒绝、一台只接受密码）。
2. **把 wgp-client 改成 agent 的 IPC 客户端**：需要先把它里面的装配线（member_watch、PeerStates、事件渲染）
   抽成库，否则 agent 与 CLI 会各维护一份。抽完之后 GUI 才有意义。
3. 多进程阶段 2 / 3：TUN 特权 helper、ET 独立 worker（见 [项目完整文档/20-多进程运行与跨进程通信方案.md](项目完整文档/20-多进程运行与跨进程通信方案.md)）。
4. 待决策项（§5）里最影响体验的是第 5 条：hobby 节点是否允许少量信令中转——它决定「只有 hobby 种子时能不能多人联机」。
5. 小尾巴：GetSnapshot.links 恒空、LeaveRoom 不释放转发端口、多房间共用一份 Engine（见 §3.2 第 16 项）。
