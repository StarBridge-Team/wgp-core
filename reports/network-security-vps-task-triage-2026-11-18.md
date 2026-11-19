# wgp 网络安全与 VPS 审计任务筛选及交付报告

- 日期：2026-11-18（Asia/Shanghai）
- 输入：[`network-security-and-vps-audit-2026-11-17.md`](network-security-and-vps-audit-2026-11-17.md)、当前 `HANDOFF.md` 和 `scripts/nat-field-test.md`
- 范围：完成最高难度且可在仓库内闭环的缺陷；筛选其余中低难度和需真实环境/人类决策的工作。
- 未将回环结果、静态审查或模拟攻击描述成真实公网验证。

## 交付结论

原审计 P0 成立：仅依赖不可信 Forward 上的承诺-揭示，未认证的临时 X25519 公钥与端点报告可被恶意转发者替换。已实现 SIG v2 身份认证握手，并要求调用方提供房间成员身份公钥；`connect_peer` 自身再从存储节点读取并验证房间签名记录，确认本端与目标成员 NodeId/公钥都已登记。

- Commit 的 16B 保留区现携带每轮 CSPRNG 随机挑战；Reveal 回显发送方与接收方挑战，并携带 Commit 前缀。
- Reveal 的 Ed25519 transcript 签名绑定域、SIG 版本、房间键派生值（不发送明文房间码）、会话 tag、双方完整 NodeId、临时 X25519 公钥/nonce、Commit 和双方挑战；验签、NodeId/公钥绑定或 Commit 校验任一失败均拒绝进入 ECDH。
- 被动等待阶段可能消费 Commit。若之后先到 Reveal，仅当其签名、承诺及本端新鲜挑战回显已验证时，才允许从 Reveal 恢复对端 Commit 状态；未经认证的提前 Reveal 不会被接受。
- 端点报告签名绑定完整映射地址、能力、端口模型、完整 Commit、房间与双方身份；收包时在接受报告前验签，阻止中继替换地址或模型。
- 信令版本单独升级为 `SIG_VERSION = 0x02`，并在解析入口拒绝 v1/未知版本；旧客户端不能参与 v2 握手，必须整体升级。
- CLI、agent 与集成测试均将成员身份公钥传入协商；协商 API 自身还校验签名房间记录中的本端与对端成员项。

安全边界：认证不能阻止恶意中继丢包、延迟、审查或拒绝服务；成员身份公钥仍以房主签名的房间记录为信任来源。此修复不提供用户可读名称认证、全局身份准入或 Sybil 防护。

## 验证结果

- `cargo check --workspace --all-targets`：通过，0 编译错误。
- `cargo test -j 1 -p wgp-proto -p wgp-dht -p wgp-core`：协议、DHT、核心定向测试均通过（核心 49、DHT 102、协议 51）。
- `cargo test -j 1 --workspace --locked`：所有 workspace 单元、集成、文档测试通过，退出码 0；覆盖 `wgp-port` 完整回环转发、TCP/UDP、丢包/乱序测试与 ET 桥接测试。
- 新增攻击回归覆盖：错误成员公钥/NodeId、篡改临时公钥、挑战回显篡改、端点映射端口签名后篡改、旧 SIG v1 解析拒绝。
- 测试在 Windows 回环环境执行。公网 NAT、真实中继攻击、VPS 部署、真实丢包与切网仍未测。

## 中等难度：仓库内可推进

| 优先级 | 任务 | 工作内容 | 验收条件 | 建议归属 |
|---|---|---|---|---|
| M1 | STUN 响应绑定与投毒防护 | 每次 observer 请求使用随机 txid/nonce；验证响应来源、Binding Success 类型、txid 和 nonce；拒绝并发注入伪造响应 | 错误来源/类型/txid/nonce 均不能生成 ObserverReport，正常 observer 互通测试通过 | 开发 |
| M2 | 公共 DHT 端点地址准入 | 拒绝 loopback、RFC1918、link-local、CGNAT、保留地址及特殊 IPv6；LAN 发现采用显式独立策略 | 覆盖审计列出的特殊网段边界，广告和 FIND_NODE 转述路径均不向特殊地址发探测 | 开发 |
| M3 | DHT 反射放大缓解 | 为 FIND_NODE/FIND_VALUE 增加源地址 cookie/挑战，或约束未验证响应尺寸；加按源限速 | 逐字节测试最大请求/应答比例；源地址未验证时不发送大响应 | 开发，涉及协议升级评估 |
| M4 | 远端可驱动队列和字节预算 | 会话/TCP 响应/mux 接收队列有界；增加每 peer 与全局字节预算、TCP RPC 速率限制 | 慢读、session flood、最大流与慢应用测试保持 RSS 上限且其他 peer 可服务 | 开发 |
| M5 | 房间成员容量边界 | `add_member` 超限显式失败；禁止 STORE 编码对结构化记录静默截断 | 成员数边界测试；失败不覆盖旧记录 | 开发 |
| M6 | STUN DHT socket 限速 | DHT socket 直接响应 STUN 时共享每 IP/全局限速和有界状态表 | 多源 flood、单源 flood 下速率/响应字节受限 | 开发 |
| M7 | UDP datagram pacing 与公平性 | 将 datagram 纳入共享 pacing/带宽预算；可丢弃队列并避免可靠控制帧饥饿 | 同链路 stream+datagram、多 peer 在 RTT/丢包矩阵下测 RTT、goodput、公平性、队列上限 | 开发；需先有统一基准 |
| M8 | 网络切换后持续恢复 | 有抖动和全局预算的持续低频重试；接口变化后重建 socket、重测 NAT、重协商 | 两端同时切网/恢复、空闲及有流量断网都达到明确恢复 SLO，不出现重试风暴 | 开发 + 多机测试 |
| M9 | K>1 房间副本与写入授权 | 副本、epoch 比较、读修复、锚点授权、租户配额 | 单 seed 故障/恢复、冲突、表满、分裂收敛场景可重复测试 | 开发，需先确定一致性设计 |
| M10 | 探针新鲜度与地址迁移验证 | 对探针校验 session tag、时间窗、去重 nonce 和预测端口范围；把候选地址交付延后到新鲜 AEAD/path challenge 成功 | 旧探针重放、同 IP 异端口、错误 tag、网络切换后旧映射均不能抢占链路；新路径 challenge 成功后才迁移 | 开发 + 多机/网络仿真 |
| M11 | TCP 信令与 Forward 地址簿解耦 | 设计经身份认证的 TCP 长连接双向转发或明确可选 relay 数据面；当前 TCP bootstrap/KV 成功不代表 Forward 到目标可达 | 目标无 UDP 地址登记或映射失效时，按产品策略可报告不可用或通过已授权 TCP 通道送达；不得误报 UDP 全封锁可联机 | 需产品决策 + 开发 |
| M12 | 网络基线与热路径 profiling | 固定 release 构建、硬件、流量与 RTT/丢包/并发矩阵；profile AEAD、分配、RangeSet/ACK、Tokio wake 和 socket syscall 后再优化 | 提供可复现脚本与基线，记录 goodput、P95、重传、CPU/RSS、分配数；优化前后在同矩阵比较 | 开发；依赖 VPS/基准环境 |

## 简单难度：可排期的小项

| 任务 | 工作内容 | 完成标准 |
|---|---|---|
| 观察者用量与限频对齐 | 按一次协商的请求数、同公网 IP 并发成员数重设默认限额，增加配置说明 | 默认策略允许预期并发；超限日志/指标可区分 |
| 端点广告配置说明 | 明确 `--advertise` 目前只支持固定 IPv4，外部端口须和监听端口一致；动态 IP 需重启更新 | CLI 帮助、部署文档和错误信息一致 |
| TCP-only 文案复核 | 明确 TCP 只覆盖 bootstrap/选点/房间 KV 等阶段，不保证 Forward 与隧道在 UDP 完全封锁时可达 | 帮助、Runbook、部署文档无“全链路兜底”暗示 |
| 测试临时目录错误处理 | 文件测试中不忽略 `create_dir_all` 失败，给出路径及系统错误 | 无权限时测试立即失败且错误可读 |
| 格式基线 | 记录当前仓库未格式化文件，按目录或 PR 逐步规范，而非全库机械格式化 | 格式检查与此次安全更改通过，格式整治独立提交 |

## 需人类或外部环境完成

| 事项 | 人类/环境前置 | 需要执行的工作与证据 |
|---|---|---|
| 真实 NAT 双端联调（最高优先级的外部验证） | 一台可登录且有公网 IPv4 的 Linux seed、两台不同运营商/NAT 的客户端、云安全组与主机防火墙权限 | 按 [`scripts/nat-field-test.md`](../scripts/nat-field-test.md) 运行 UDP 正常、TCP-only 信令、旧版本拒绝、单侧/双侧切网、seed 重启；把完整脱敏日志和测量填入 NAT 实测数据 §7 |
| 发布 SIG v2 客户端 | 发布负责人和预览版渠道确认 | v1/v2 握手不互通；所有参与房间的客户端需升级到同一 v2 构建，再发布并注明最低客户端版本；不可只升级单侧 |
| VPS 凭据与部署授权 | 合法账号/密钥、实例所有权确认、可配置安全组；不得复用或复制别的节点身份私钥 | 部署独立持久 identity 的 seed；开 UDP 11010/3478、TCP 3481；验证日志、外部可达性、备份和回滚 |
| hobby 转发策略 | 产品/运营方决策与滥用责任人确认 | 决定保持拒绝、有限中继或拆分消息白名单；明确带宽配额、滥用监控、服务条款及 PCDN 风险后才实现 |
| Sybil/路由准入策略 | 团队决定信任根/背书、PoW 或其他准入成本，并确认隐私及误伤原则 | 再实现 ASN/前缀多样性与准入；至少需多 VPS/共享 NAT 对测，不能把观测指标当作 Sybil 防线 |
| 正式预览版发布 | 发布负责人确认版本、资产、校验和及兼容性声明 | 在 SIG v2 实现合并后打新 preview 标签；核对多平台产物和 SHA256，不复用旧二进制 |

当前环境未提供可确认的 VPS 登录凭据、云安全组权限或两台真实客户端，因此本轮未尝试登录、未部署远端主机，也未执行真实 NAT 测试。

## 本轮完成情况（2026-11-19）

同一轮还完成两条产品线要求：**种子节点支持 FRP / NAT 后 / DDNS 部署**，以及**把 ET 支持推进到 TUN 之外尽量落在 mesh-tun-proto 库侧**
（含该仓库的源码管理）。逐项证据见 [`20-变更追补-2026-11.md`](../项目完整文档/20-变更追补-2026-11.md) §17-§23。

### 中等难度

| 项 | 状态 | 落点与验收证据 |
|---|---|---|
| **M1** STUN 响应绑定与投毒防护 | **完成** | `wgp-core::engine::nat_probe`：类型/txid/nonce/映射地址四道校验 + 来源地址绑定 + CSPRNG txid；5 个新用例含「另一源持续伪造应答仍不采信」「未回显 nonce 被拒」「反射请求被拒」 |
| **M2** 公共 DHT 端点地址准入 | **完成** | `wgp-dht::addr::EndpointScope`：默认公网白名单式排除（回环/RFC1918/链路本地/CGNAT/0-8/协议分配/TEST-NET×3/198.18-15/组播/240-4/IPv6），局域网形态显式 `--allow-local-endpoints`；广告与 `NEIGHBORS` 转述两条路径都过闸 |
| **M3** DHT 反射放大缓解 | **部分完成（缓解）** | 放大应答（NEIGHBORS/VALUE/SEEDS）按源 IP 与全局限字节速率（`ratelimit::ByteBudget`）；**源地址 cookie 需改线协议，仍待决策**，单元测试只覆盖闸门本身 |
| **M4** 远端可驱动队列与字节预算 | **未做** | 需要先有统一基准（M12）。现有 `inbox` 512 的有界队列、`Forward` 邮件语义保持不变；会话表/`wgp-port` mux 接收队列仍未定量化预算 |
| **M5** 房间成员容量边界 | **完成** | `MAX_ROOM_MEMBERS=12` + `try_encode` 不再静默截断（原 `as u8` 回绕与 STORE 1024B 截断两条都堵住）；`RoomError::{RoomFull, RecordTooLarge}`；满员失败不改写旧记录 |
| **M6** STUN DHT socket 限速 | **完成** | 统一 `RateGate`（单源窗口 + 全局每秒 + 源表硬上限），DHT 读循环与观察者服务共用；`set_stun_rate_policy()` 可覆盖 |
| **M7** UDP datagram pacing 与公平性 | **未做** | 依赖 M12 基准与真实丢包矩阵 |
| **M8** 网络切换后持续恢复 | **未做** | 依赖多机/真实网络；代码未改 |
| **M9** K>1 房间副本 | **未做** | 需先定一致性设计 |
| **M10** 探针新鲜度与地址迁移验证 | **未做** | 需多机/网络仿真；本轮只做到观察者应答来源绑定 |
| **M11** TCP 信令与 Forward 地址簿解耦 | **未做** | 需产品决策（可选 relay 数据面） |
| **M12** 网络基线与热路径 profiling | **未做** | 依赖 VPS/基准环境；`DEPLOY.md` §10.4 给了首轮真机检查表 |

### 简单项

| 项 | 状态 |
|---|---|
| 观察者用量与限频对齐 | 完成：默认 12 → **60 次/10s**，另加全局 600 次/秒，文档写明换算 |
| 端点广告配置说明 | 完成：`--advertise` 现支持 IPv4 **与 DDNS 域名**，外部端口可独立配置，动地址自动重宣告；`DEPLOY.md` §7.2/§10、`17-部署与运维.md` §7 与 `--help` 三处一致 |
| TCP-only 文案复核 | 完成：`wgp-node --help`、`wgp-client --help` 明确只兜底信令 |
| 测试临时目录错误处理 | 完成：改用 `target/test-tmp/<用例>`，不忽略 `create_dir_all` 失败，并修掉两个用例共用同一临时目录的相互删除 |
| 格式基线 | 记录在案：本轮不做全库机械格式化（见 HANDOFF §3.3），只保证新增/修改文件风格一致 |

### 部署形态（新增能力）

- 内核 `AdvertiseTarget`：对外地址与三个外部端口分开，端口 0 = 沿用本机。
- `wgp-node`：`--advertise <ipv4|域名|none>`、`--advertise-{dht,stun,tcp}-port`、`--ddns-refresh`、`--allow-local-endpoints`。
- 资产：`server/deploy/frp/{frps,frpc}.toml.example`、`server/deploy/install-seed-frp.sh`。
- 文档：`server/deploy/DEPLOY.md` §10（四种拓扑、FRP 限制、验证清单）、`项目完整文档/17-部署与运维.md` §7。
- **未验证**：真实 FRP 中继 + 真实 NAT + 真实 DDNS 都没有跑过（没有中继机/域名/第二台客户端）。

回环端到端（真实二进制、Windows）单种子与 `-Discovery` 两种模式本轮均 **PASS**；
`cargo test --workspace` 22 个目标 0 failed；`cargo check --workspace --all-targets` 0 warning。
（沙箱内跑端到端要把 `TEMP`/`TMP` 指到仓库 `target\` 目录：受限沙箱不允许写系统临时目录。）

### ET（TUN 之外）

见 `bridge/wgp-et-bridge/README.md` 与 mesh-tun-proto 仓库的 `CHANGELOG.md`；本轮把路由同步合并、RPC 分片重组、
数据帧走隧道数据报通道、确定性开流规则等落在库侧，并把 mesh-tun-proto 的提交/CI/文档补齐。
**TUN 设备、与官方 EasyTier 节点互通仍未做**（前者需要 Wintun 驱动与管理员权限，后者需要一台真实官方节点对测）。

### 仍然只能由人/外部环境完成

1. 真实 NAT 双端联调（最高优先级）——一台可达公网种子 + 两台异 NAT 客户端。
2. FRP 拓扑首次上线验证（中继机安全组、`allowPorts`、端口映射一致性）。
3. 发布 SIG v2 客户端（协议不兼容，必须全体升级）。
4. hobby 中转策略、Sybil 准入、K>1 存储三个待决策项。


## 推荐执行顺序

1. 合并/评审 SIG v2 P0 修复和协议/API 文档，明确 v1/v2 不互通，随后制作所有参与者统一升级的预览构建。
2. 由具备 VPS 与客户端条件的人按 NAT Runbook 执行真实 M1，建立 NAT、丢包、建连时延、吞吐、CPU/RSS 基线。
3. 先处理 STUN 响应伪造和公共端点过滤，再做 DHT 放大/队列预算及房间容量；这些直接暴露在公网输入面。
4. 有基线后做 datagram 公平、切网恢复、profiling 与固定网络基准。
5. 需要产品决策的 hobby 中继、身份准入、K>1 存储分别立项；不要用性能优化替代威胁模型决策。

## 项目定位交接摘要

wgp 是 Rust 实现的纯 P2P 穿透工具；两端直连承载业务数据，seed 负责发现、信令和 NAT 观测，不作为业务流量中继。协议、密码、DHT、打洞、加密数据面、节点/客户端、IPC agent 和 CI/多平台构建均已有实现。回环 E2E 通过不代表真实 NAT 已验证。M1 真实异 NAT 测试仍是主要产品风险；ET 当前只到本项目节点间 PoC，GUI、TUN/虚拟 IP、官方 EasyTier 节点互通均未完成。版本 v0.1.0-preview.1 是否已发布应以当前远端/tag/Release 实际状态重新核对，不沿用旧快照结论。
