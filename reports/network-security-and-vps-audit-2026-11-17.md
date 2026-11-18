# wgp 网络安全与 VPS 联调探查报告

- 日期：2026-11-17（Asia/Shanghai）
- 范围：打洞与 NAT/STUN、会话密钥协商、DHT 身份/路由/存储、隧道重放与地址迁移、UDP 可靠层、TCP 信令、端口转发及资源边界。
- 结论口径：代码审查 + Windows workspace 测试；没有把回环测试视为真实 NAT 证据。

## 执行摘要

当前代码有可靠的隧道 AES-256-GCM、方向隔离密钥和 1024 位 replay window；DHT 探活也已从自报 PING 升级到一次一密签名挑战。但这并不覆盖整条路径：会话协商没有把临时 X25519 密钥认证绑定到已知成员身份，STUN 响应没有绑定来源地址，DHT 的部分 RPC 仍可被伪造源地址放大，数条网络输入路径会进入无界队列。DHT 的身份自证也没有身份准入成本，因此不能抑制持钥者创建大量新身份。

**预览版安全门槛：P0 会话中间人缺陷必须先修并加攻击回归测试。预览版发布后，第一项技术工作按要求应立即做 VPS 异 NAT 联调，而不是先扩展功能。** 联调期间同步收集真实丢包、NAT 映射、CPU/内存和重连数据。当前本轮没有可用凭据或可确认的公网 seed，故没有实施公网部署或声称完成联调。

## 优先级与发现

### P0：承诺-揭示没有认证临时密钥，Forward 中继可实施中间人

`connect_peer` 发出 Commit 后，接收端只判断收到的是 Commit 或 Reveal；没有保存/比较 Commit 内容，也没有验证 Reveal 的 `peer_id` 是预期对端。之后完整承诺 `full_commit` 仍通过同一条不可信 Forward 通道传送。中继可分别向两端替换 Reveal 与端点报告中的完整承诺，令双方分别与中继协商密钥并把数据面端点指向中继。这里不是“端到端加密可阻止中继读取”：AEAD 保护的是各自与攻击者建立的两条不同会话。

证据：[orchestrator.rs](../kernel/wgp-core/src/orchestrator.rs#L282-L341)、[orchestrator.rs](../kernel/wgp-core/src/orchestrator.rs#L423-L429)、[sig.rs](../kernel/wgp-proto/src/sig.rs#L40-L100)。现有密码测试只检验手动替换 Commit 值会导致摘要不同，并未驱动线上状态机验证已收 Commit；因此该测试不覆盖此攻击：[handshake_test.rs](../kernel/wgp-crypto/src/handshake_test.rs#L127-L154)。

**修复与验收：**将协商 transcript 以域分隔方式绑定协议版本、房间键/会话 tag、双方 NodeId、角色、完整临时公钥与 nonce，并由各自长期身份密钥签名；接收方从已签名房间成员记录取得预期公钥并验证 NodeId-公钥绑定。承诺必须被保存并在 Reveal 到达时校验，拒绝重放/跨房间/跨对端消息。加入一个可修改 Forward 的恶意中继端到端测试，必须证明它无法取得两侧会话密钥、替换端点或使双方误报安全链路。未完成之前不应把预览版描述为可抵御恶意种子/中继的端到端安全连接。

### P1：STUN 映射可被伪造，造成端点/端口模型投毒

`NatProbe::probe_observer` 忽略 `recv_from` 返回的来源地址，只校验 STUN cookie、txid 和 mapped 属性；没有要求消息类型为 Binding Success Response，也没有验证 WGP 扩展 nonce。当前协商的初始 txid 由本端 PeerId 前缀和零填充组成，可预测。能向客户端注入 UDP 的同网段主机可抢先伪造映射 IP/端口，让打洞对端把包发到攻击者控制地址，造成 DoS/错误 NAT 判断。

证据：[nat_probe.rs](../kernel/wgp-core/src/engine/nat_probe.rs#L56-L94)、[orchestrator.rs](../kernel/wgp-core/src/orchestrator.rs#L360-L373)、[stun.rs](../kernel/wgp-proto/src/stun.rs#L44-L65)。

**修复与验收：**每次探测生成 CSPRNG txid/nonce；要求响应来源严格等于配置的 observer、消息类型正确、txid 与本次请求匹配；扩展模式必须验证 nonce 回显。加入错误来源、错误类型、旧 txid、错误 nonce 的并发注入测试，均不得产生 `ObserverReport`。

### P1：公网 DHT 接受私网/回环广告，可成为内网 UDP 探测器

端点过滤只排除 unspecified、broadcast、multicast 与 IPv6，未排除 RFC1918、loopback、link-local 等特殊网段。收到种子广告后会向广告端点发认证探活；FIND_NODE 转述地址也会进入探测流程。恶意公网节点可诱使客户端向局域网地址发 UDP 包，导致内网探测、噪声或命中不安全服务。

证据：[node.rs](../kernel/wgp-dht/src/node.rs#L1369-L1376)、[node.rs](../kernel/wgp-dht/src/node.rs#L1787-L1802)、[node.rs](../kernel/wgp-dht/src/node.rs#L1528-L1532)。

**修复与验收：**在公共 DHT 准入层拒绝私有、回环、链路本地、保留和 IPv4 映射的特殊 IPv6 地址；LAN 发现另走显式本地策略，不复用公共广告准入。覆盖 `10/8`、`172.16/12`、`192.168/16`、`127/8`、`169.254/16`、CGNAT `100.64/10`、IPv6 ULA/link-local 等边界用例。

### P1：FIND_NODE / FIND_VALUE 是未认证 UDP 反射放大器

`FIND_NODE` 请求为 39B（RPC 头 7 + target 32），最大 20 条 Neighbors 响应为 768B，约 **19.7 倍**。`FIND_VALUE` 请求同为 39B，最大 1KiB 值响应为 1065B，约 **27.3 倍**。服务端按收到请求的源地址直接回包，没有 cookie/挑战或应答不超过请求的限制。攻击者可伪造受害者源 IP 反射流量。FIND_SEEDS 已采用填充 quota 保证响应不大于请求，但旧 RPC 未修。

证据：大小来自 [dht.rs](../kernel/wgp-proto/src/dht.rs#L9-L39)、[dht.rs](../kernel/wgp-proto/src/dht.rs#L126-L158)、[dht.rs](../kernel/wgp-proto/src/dht.rs#L249-L269)；响应路径在 [node.rs](../kernel/wgp-dht/src/node.rs#L868-L870)、[node.rs](../kernel/wgp-dht/src/node.rs#L933-L945)。

**修复与验收：**先做反射安全设计：未验证源地址前应答不大于请求，或先发小型 cookie challenge，验证后再允许大响应；对 FindNode 返回数、FindValue 未认证读取和每源速率设上限。测试需逐字节计算最大应答/请求比，并在伪造源测试中确认验证前不会发送大包。

### P1：会话队列与 TCP 应答队列无界，存在远程内存 DoS 面

DHT 对已注册 session tag 使用 `mpsc::unbounded_channel`；tag 是确定性 32 位哈希，目标 NodeId 和房间标识可被知道后，直接 Forward 洪流可持续进入协商队列。TCP 信令每条连接也把响应送入 unbounded channel；慢读客户端可持续请求并停止读取。TCP 并发连接虽然封顶 512、空闲超时 30 秒，但单连接请求速率和响应队列字节数没有硬上限。`wgp-port` 的每流接收 channel 同样无界；上限虽有 1024 条流 × 256KiB 初始额度，理论上仍允许单隧道约 256MiB 的未读接收数据，且缺全局内存额度。

证据：[node.rs](../kernel/wgp-dht/src/node.rs#L305-L309)、[node.rs](../kernel/wgp-dht/src/node.rs#L687-L693)、[node.rs](../kernel/wgp-dht/src/node.rs#L879-L899)、[node.rs](../kernel/wgp-dht/src/node.rs#L1134-L1188)、[mux.rs](../bridge/wgp-port/src/mux.rs#L26-L36)、[mux.rs](../bridge/wgp-port/src/mux.rs#L101-L115)。

**修复与验收：**将所有远端可驱动队列改成有界队列或带字节额度的队列；队满时丢弃/关闭并计数，避免接收循环阻塞；加入全局与每 peer 的内存预算、TCP RPC 限速/应答排队上限。压力测试应模拟不读 TCP 响应的慢客户端、session flood、最大流数和慢应用读者，断言 RSS 有确定上界且其他 peer 仍可服务。

### P1：合法密钥不限制 Sybil；固定桶满后可排斥诚实节点

身份挑战仅证明“对方持有对应私钥”，而任何人都能本地生成任意多把合法密钥。路由表 256 个桶各最多 20 个节点，满桶直接拒绝新节点且不分裂；没有 PoW、信任根、/24/ASN 入表限额或多样性准入。攻击者可批量制造身份填充桶或影响最近节点查询，配合控制种子目录可形成 eclipse/记录拒绝服务。按同一 `/24` 或 ASN 统计占比是必要的部署观测，但仅观测不能阻止攻击。

证据：[kbucket.rs](../kernel/wgp-dht/src/kbucket.rs#L5-L7)、[kbucket.rs](../kernel/wgp-dht/src/kbucket.rs#L45-L60)、[auth.rs](../kernel/wgp-dht/src/auth.rs#L25-L30)、[17-DHT节点身份与信任方案.md](../项目完整文档/17-DHT节点身份与信任方案.md#L185-L222)。

**修复与验收：**先实现每桶地址前缀/AS 多样性软硬配额、桶刷新与健康节点替换策略；对路由准入引入可配置成本（PoW 或可审计信任根/背书），不把 PoW 单独当作充分防护。VPS/多节点实验记录路由表 `/24`、ASN 分布、拒绝准入数、桶满率、节点 churn 和目标查找成功率；需包含集中在单一 AS、共享 NAT 的诚实节点情形，测量误伤。

### P1：探针没有新鲜度/重放窗；假命中可占用链路状态

31B 探针有 nonce、timestamp 与 HMAC，但 `verify_probe` 仅校验格式和 HMAC，未校验时间戳、nonce 重放或会话 tag；打洞器按 `src.ip() == peer_ip` 接受任意来源端口。捕获到的有效会话探针可被同一目标 IP 下重放，引发假命中/地址抢占和打洞 DoS。探针密钥未知时不能凭空伪造 HMAC；因此该问题不是“同网段任何主机都能立即解密隧道”。数据面 AEAD 与 ReplayWindow 仍会阻止伪造/重复业务帧。

证据：[probe.rs](../kernel/wgp-core/src/transport/probe.rs#L17-L45)、[udp.rs](../kernel/wgp-core/src/transport/udp.rs#L59-L68)、[race.rs](../kernel/wgp-core/src/engine/race.rs#L40-L45)、[punch_runner.rs](../kernel/wgp-core/src/engine/punch_runner.rs#L90-L100)。

**修复与验收：**探针接收按 session 校验 tag、时间窗和去重 nonce；允许打洞端口预测窗口时，对端口范围做显式约束；把探针命中视为候选地址，只有后续带新鲜随机 challenge 的 AEAD 握手通过才交付可用链路。加旧探针重放、异端口同 IP、错误 tag、时间回拨和并发竞速测试。

### P1：链路切换/双方同时失联后不会持续恢复

客户端重试退避只有 3/10/30 秒，耗尽后进入被动 `wait_incoming`。如果两端同时网络切换并都耗尽主动重试，它们会同时只监听，没有后续定时器发起新协商。UDP 数据面静默判死还需 90 秒；可靠层仅在有数据待发时以 30 秒检测死链，空闲断网可能更晚暴露。因而“网络回来后自动恢复”不是当前保证。

证据：[main.rs](../client/wgp-client/src/main.rs#L49-L52)、[main.rs](../client/wgp-client/src/main.rs#L1010-L1113)、[link.rs](../bridge/wgp-port/src/link.rs#L29-L33)、[arq.rs](../bridge/wgp-port/src/arq.rs#L35-L36)。

**修复与验收：**引入有抖动、上限与全局预算控制的持续低频重试；网络接口/本地地址变化时主动重建 UDP socket、重新做 STUN/认证和打洞。测试两端同时断网/换 Wi-Fi/恢复、NAT 映射重建、空闲与有流量两种情况，设恢复 SLO 并确保不会无限高频重试。

### P1：UDP 数据报绕过 NewReno 与字节级公平控制

可靠字节流有 NewReno cwnd，但数据报在没有可发送 stream chunk 时直接从队列发出，不计入 in-flight；接收 `Dgram` 也不会触发 ACK。持续或突发的 UDP 转发数据可绕过拥塞窗口，和同隧道可靠流争抢带宽，形成队列膨胀、丢包和对其他链路的不公平。

证据：[arq.rs](../bridge/wgp-port/src/arq.rs#L303-L369)、[arq.rs](../bridge/wgp-port/src/arq.rs#L387-L429)、[arq.rs](../bridge/wgp-port/src/arq.rs#L562-L569)。

**修复与验收：**对不可靠数据报也实施统一 pacing/带宽预算，至少纳入共享的链路 token bucket/拥塞估计；给实时数据报设置可丢弃队列与优先级，不能无限排队，也不能令可靠控制帧饥饿。测量同链路 TCP stream + UDP 满载、多个 peer 并发时的 RTT、丢包、吞吐公平性和队列长度。

### P1：房间记录超过 14 名成员后会被静默截断

房间值包括 64B 签名与记录头；每个成员额外 64B。无 PoW 时总长度为 `115 + 64 × 成员数`，`STORE_VALUE_MAX=1024`，所以最多 14 个成员条目（含锚点）可完整存储。第 15 个成员时 `StoreBody::encode` 静默截断到 1024B，存储节点仍 ACK；后续读取记录签名/结构失败。`add_member` 没有容量预检查，调用者可能看到加入流程成功但其他成员无法读取房间。

证据：[room.rs](../kernel/wgp-dht/src/room.rs#L89-L127)、[dht.rs](../kernel/wgp-proto/src/dht.rs#L38-L39)、[dht.rs](../kernel/wgp-proto/src/dht.rs#L211-L245)、[runtime.rs](../kernel/wgp-dht/src/runtime.rs#L257-L277)。

**修复与验收：**在加入前以明确错误拒绝容量超限，禁止编码层静默截断结构化持久数据；长期改为分片/按成员键存储或提高经 MTU/资源论证的容量。覆盖 14/15 成员边界，并确认失败不会覆盖原有效房间记录。

### P2：K=1 单点存储与任意写入造成可用性/扩展瓶颈

房间只写到一个确定的存储节点；DHT KV 只有 4096 项、满时淘汰最旧值，`STORE` 只校验公钥与 NodeId 自洽，不校验键所有权/授权，写入可覆盖任意 key。客户端会验证房间锚点签名，故无私钥者伪造不了有效房间状态，但仍可覆盖合法值造成拒绝服务；存储节点掉线/被压满会令 K=1 房间不可达。该问题与前述 14 成员上限叠加。

证据：[runtime.rs](../kernel/wgp-dht/src/runtime.rs#L1-L7)、[node.rs](../kernel/wgp-dht/src/node.rs#L913-L925)、[node.rs](../kernel/wgp-dht/src/node.rs#L2027-L2040)。

**修复与验收：**迁移到 K>1 副本、版本/epoch 单调比较与读修复；为 key 写入加房间锚点授权及速率/租户配额，避免任意写入逐出热点房间。测量单种子失效、恢复、一致性冲突、全表压力和分裂后收敛。

### P2：TCP 信令与 UDP 地址簿仍耦合，不是完整 UDP 被封兜底

TCP 模式能做 bootstrap、选点和房间 KV 读写，但 TCP 入站身份验证不写 UDP 地址簿；Forward 中继最终仍从地址簿取目标 UDP 地址并经 UDP 投递。若目标端从未完成 UDP 探活，或网络切换令其映射失效，TCP 到种子成功也不能保证报道/协商送到对端。客户端打洞和 UDP 数据面仍需要 UDP。

证据：[node.rs](../kernel/wgp-dht/src/node.rs#L192-L196)、[node.rs](../kernel/wgp-dht/src/node.rs#L1034-L1037)、[node.rs](../kernel/wgp-dht/src/node.rs#L879-L910)、[HANDOFF.md](../HANDOFF.md#L132-L153)。

**处理：**产品文案明确限定“TCP 只覆盖信令部分阶段”；后续要么建立可认证的 TCP 长连接转发/双向地址会话，要么将完整 relay 数据面作为明确的可选服务，不要把 TCP 种子标成全链路 UDP 失效后的等价替代。

### P2：DHT socket 上的 STUN 响应无速率闸门

独立 `ObserverServer` 对每 IP 限频，但 DHT UDP 读循环也直接调用 `try_answer_stun` 并回包，没有经过同一限速器。最小 STUN 请求 20B 会得到约 32B 响应（约 1.6 倍，扩展请求约 1.25 倍），不如 DHT 查询的放大严重，但可被伪造源地址滥用。

证据：[node.rs](../kernel/wgp-dht/src/node.rs#L407-L416)、[observe.rs](../kernel/wgp-dht/src/observe.rs#L13-L35)、[observe.rs](../kernel/wgp-dht/src/observe.rs#L143-L160)。

**修复：**将 DHT socket 的 STUN 响应也纳入共享的每 IP/全局限速，监控响应字节量；限速表有硬容量与过期策略。

## 对提出问题的逐项判断

| 主题 | 代码审查结论 |
|---|---|
| 打洞劫持/别名混淆、家庭私网 | 公共端点过滤不排私网，且 STUN 映射可伪造；探针还接受同 IP 任意端口。成立为端点投毒/打洞 DoS 风险；不等于任意邻居可以伪造 HMAC 或直接解密 AES-GCM。 |
| DHT 日食/投毒/Sybil | 合法密钥可无限生成，桶无分裂并满即拒新；没有 PoW、/24、AS 或信任准入。FindValue 可被写入任意 key，K=1 又放大单点可用性风险。 |
| 隧道帧重放 | AEAD + 方向独立密钥 + replay window 已实现并有测试；该保护本身未发现直接绕过。首个合法密文若被抢先从新源地址送达，当前 NAT rebinding 会改写 peer 地址，缺少 path challenge，存在可用性风险。 |
| 未认证地址 DoS 放大 | FIND_NODE/FIND_VALUE 最大约 19.7x/27.3x；STUN 同 socket 未限速；Auth challenge 约 1.9x 但已有全局/每 IP 限制。 |
| 中间人不可防御与定位张力 | 不是“理论上不可防御”：当前临时密钥 transcript 未认证，是可修复的 P0 实现缺陷。即使修复，恶意中继仍可丢包/审查/拒绝服务；去中心化也不能自动提供名字归属和运营信任。 |
| UDP 可靠层拥塞与公平 | Stream 有 NewReno；datagram 旁路不在 cwnd/in-flight/ACK 之内，且多条链路各自竞争。不能概括为“完全没有拥塞控制”，但 UDP 数据报确实可绕过拥塞控制。 |
| Rust 热路径隐性开销 | 代码存在每包多个 Vec 分配/复制、同步逐包 AEAD 和连续 send_to；是否是瓶颈需 profile。不能仅由代码推定 CPU 热点。 |
| 单种子/K=1 扩展性 | K=1 房间单点与 4096 条目淘汰已确认；此外房间成员容量仅 14 条。需副本与恢复设计。 |
| TCP 信令依赖 UDP | 已确认：TCP KV/发现可用不代表 Forward 可达，Forward 目标路由最终依赖已登记的 UDP 地址。 |
| 网络切换后无恢复性 | 有限主动重试耗尽后双方可能同时被动等待；接收端的认证数据包迁移地址不能解决 socket/NAT 映射失效与双方静默。 |

## VPS 联调状态与首轮计划

本轮只做了 TCP 端口探测：`103.236.84.213:48772` 仍超时/拒绝；`70.39.201.151:22` TCP 可达。交接记录称后者只接受密码且本地无凭据；本轮未尝试登录，也未部署或修改任何远端主机。请见 [NAT 实测记录](../项目完整文档/18-NAT实测数据.md#L86-L118) 与 [field-test runbook](../scripts/nat-field-test.md#L7-L61)。因此公网 seed 和异 NAT 双客户端仍未测。

预览版发布后首项技术实现：

1. 准备一台有公网 IPv4 的 Linux seed（建议 1 vCPU/512MiB 起），独立持久身份，放行 UDP 11010、UDP 3478、TCP 3481；保留 systemd 日志与资源采样。不要复制已有 seed 私钥。
2. 使用两台真实客户端、不同运营商/NAT，另加手机热点/CGNAT 变体。每轮使用同一预览版构建与独立身份文件。先做 UDP 正常路径，再做一侧切网、双侧同时切网、UDP 封锁、种子重启。
3. 每轮记录 seed RTT、入表时间、观察者响应来源/txid、NAT 映射、打洞波次/端口/发包数、隧道 ready 时间、载体、重传/丢包、TCP/UDP 吞吐、CPU/RSS 和失败阶段；抓包需脱敏并保留时钟/版本标记。
4. 在真实多节点网络统计路由表按 `/24`、ASN 的占比、桶满率、节点 churn 与 FIND_NODE/FIND_VALUE 成功率。ASN 数据源、隐私与 NAT 误伤阈值应在采集前确定；指标是观察，不是 Sybil 防线。
5. 对网络切换、5% 丢包、随机时延/乱序、慢读端与 100+ 并发流做重复试验；从原始日志计算 P50/P95/P99 建连时延、goodput、重传率、CPU/RSS 和公平性。

远端准入凭据、云安全组和两台真实客户端是缺失条件；具备条件后可直接按 runbook 执行并将结果填入 [18 §7](../项目完整文档/18-NAT实测数据.md#L96-L118)。

## 性能与健壮性落地顺序

1. **安全先决：**修 P0 transcript 认证、STUN 响应校验、私网广告过滤、队列上限、DHT 放大；攻击回归测试纳入 CI。
2. **预览后立即 VPS M1：**不先扩展 GUI/功能；拿到真实 NAT、MTU、丢包、切网的基线后再调三波参数与超时。
3. **拥塞与公平：**为 datagram 增加 pacing 和共享字节预算；按可靠流/实时数据报分别设限，避免实时流排队，也保护可靠控制数据。
4. **内存与背压：**给 DHT session、TCP response、mux stream 和事件队列增加总字节预算；512 TCP 连接上限需要与每连接 RPC 频率、响应队列共同评估。
5. **热路径 profiling：**先用相同硬件/版本/流量脚本建立 release baseline；用 samply/flamegraph 或 Linux `perf` 看 AEAD、Vec 分配、RangeSet/ACK、Tokio wake 和 socket syscall 占比。再针对性复用缓冲、减少复制、批量收发/批量加密，改动后复跑丢包与重排用例。
6. **固定可复现基准：**TCP/UDP 各测 64KiB、1MiB、16MiB、持续 60 秒；RTT 10/50/150ms，丢包 0/1/5%，并发 1/10/100；报告 goodput、P95 延迟、重传、CPU 核时、RSS、分配数与 datagram 丢弃。历史记录中的 Windows 吞吐约 33MiB/s 与约 1.6MiB/s 来源于不同日期/脚本，不能直接比较，需统一脚本重测：[STATUS.md](../STATUS.md#L63-L95)、[HANDOFF.md](../HANDOFF.md#L85-L101)。

## 本轮验证

- `cargo test --workspace --locked`：首次运行有 2 个 `wgp-node` 文件测试在系统 `%TEMP%` 下报权限/路径错误；将 `TEMP/TMP` 指向工作区 `target/test-temp` 后全 workspace **363 passed，0 failed**。这是当前执行环境的临时目录限制；测试对 `create_dir_all` 忽略错误也应改进，让错误更早更清楚。
- `cargo check --workspace --all-targets --locked`：通过，0 warning。
- `cargo fmt --all -- --check`：失败，rustfmt 在多个现有 Rust 源文件中报告格式差异；差异不涉及本报告（Markdown），本轮未对不相关源码做整仓格式重写。
- 工作区审查开始时无未提交改动；本报告是本轮新增文件。真实 NAT、VPS 部署、多机 Sybil/放大压力与真实网络切换尚未测试。
