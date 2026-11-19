# wgp-et-bridge · ET 桥接（路线图 M3）

把 EasyTier 协议兼容层（[`mesh-tun-proto`](https://github.com/StarBridge-Team/mesh-tun-proto)）跑在折跃门打通的加密隧道上。

**最终目标**：不使用官方 ET 客户端，由本项目建立连接，作为节点加入 EasyTier 网络，并支持基础的 ET 节点特性。

**状态：PoC（进行中）。** 已在**本机回环**上跑通：打洞 → ET 握手 → 路由同步 + 虚拟 IP → 双向 IP 帧
→ 新节点加入/离开。**没有**接 TUN 设备，**没有**和官方 EasyTier 节点对测过，所以还谈不上「加入真实的 ET 网络」。

## 依赖的 mesh-tun-proto 版本

| 项 | 值 |
|---|---|
| 期望版本 | `mesh-tun-proto 0.2.x`（用到 `PeerInfo.hostname`、`P2pEvent::Ipv4Conflict`、`DataFlags`、`set_keepalive`、分片 RPC 重组与链路状态路由） |
| 本桥接验证时的 checkout | commit `120f3bc`（分支 `fix/official-interop`，2026-11-19） |
| 检出位置 | 与本仓库**同级目录**：`…/wgp` 与 `…/mesh-tun-proto` 并排；`Cargo.toml` 里是 `path = "../../../mesh-tun-proto"` |
| 校验方式 | `git -C ../mesh-tun-proto log --oneline -1` 应能看到上面的短哈希（或更新的、仍属 0.2.x 的提交） |

## 差距（如实记录）

| 差距 | 说明 |
|---|---|
| 与真正的 EasyTier 节点互通 | 官方节点不认识我们的打洞信令，和它们只能走标准的 ET TCP / UDP 连接（mesh-tun-proto 已有这两种传输）；打洞直连只发生在两个都跑本项目的节点之间。**没有**用官方节点对测过 |
| TUN 虚拟网卡 | 未做。Windows 需要 Wintun 驱动与管理员权限。桥接只把 IP 包以事件交出来（`P2pEvent::InboundIpPacket`），写不写网卡是上层的事 |
| 可用的程序 | 仍是库 + 测试，没有「加入 ET 网络」的主 CLI；`examples/` 也还没加 |
| 不转发别人的包 | mesh-tun-proto 是轻量客户端：`to_peer_id` 不是自己的帧直接丢。所以两个叶子节点之间要互通，中间必须有真正的 ET relay（官方 Core）——本项目节点目前只能当叶子 |
| 一条隧道只有一个数据报消费者 | `Tunnel::take_dgrams` 只能取一次，所以同一对节点上**第一条** ET 流吃数据报，后续 ET 流全部走可靠流（控制与数据混在一起） |

## 两条相反方向，别搞混

| 方向 | 用途 | 入口 |
|---|---|---|
| **ET 跑在 wgp 隧道上** | 两个 wgp 节点打洞成功后，把它当一条 ET 链路，加入 ET 网络 | `EtNode` / `TunnelFrameTransport`（本 README 的 §怎么接的） |
| **wgp 跑在 ET 上（回退通道）** | 一个 wgp 种子都没有时，借 ET 公共节点组临时网络，把本机固定端口透明送到对端 | `fallback` 模块 + `wgp-et-fallback` 可执行文件（下面的 §回退通道） |

### 回退通道（`fallback` 模块 / `wgp-et-fallback`）

没有 wgp 种子、只有 ET 公共节点时，`wgp-client` 会拉起这个程序：

```text
wgp-et-fallback --relay tcp://relay.example.com:11010 --room-key <64位hex> --mode host|joiner
```

- 启动后 stdout 打一行 `WGP-ET-FALLBACK READY peer=<u32> bind=<ip> punch=<u16>`，父进程据此接线；
- 在 `127.0.0.2`（与本体进程的 `127.0.0.1` 分开，不抢端口）上监听 `11010`/`3478`，把 UDP 报文封成
  ET 自定义帧（`send_data_to` / `InboundUserData`）发给对端；`host` 模式写回 `127.0.0.1:<同名端口>`
  的本地种子，`joiner` 模式回给「最近一次从该端口发出去的本地地址」；
- 打洞端口按 ET 节点号派生：`42100 + peer_id % 900`，两侧各自算得出对方的端口，不需要协商；
- 网络名/密钥由房间键派生（`wgp-<room_key[..4] hex>` / `room_key[8..24] hex`），只有拿到房间码的人能加入。

**实现要点（踩过的坑）**：`add_stream_conn` 的流式传输用阻塞 `read` 实现 `recv_frame`，
**必须先设读超时**（`set_read_timeout(100ms)`，与库自带 `examples/poc.rs` 一致），否则 `tick()`
会一直卡在 read 里——握手成功、数据永远收不到，看起来像「库不支持自定义 payload」。

**限制**：一条桥只支持一个对端参与数据面（房主 ⇄ 一个加入方）；流量经公共中继，带宽与稳定性
不受本项目控制；不碰 TUN。

验收用例：`tests/fallback_bridge.rs`（两座桥经一条 ET 链路互发 UDP 报文，回环，1–2 秒）、
`tests/stream_user_data_probe.rs`（钉住「流式传输 + 自定义 payload」这条库能力）。

## 职责边界

| 仓库 | 管什么 |
|---|---|
| wgp-core（本仓） | 打洞、加密隧道、端口转发；以及本目录这层「接缝」 |
| mesh-tun-proto | ET 协议：握手、加解密、路由、TUN 帧、保活 |

本目录只做适配，不实现任何 ET 协议逻辑。它是一个**独立的 workspace**，不在主构建和 GitHub CI 里：
编译它需要 mesh-tun-proto 的检出（私有仓）和 protoc，不该让主构建依赖这两样东西。

## 怎么接的

```
内核打洞 → PunchedLink → wgp-port 隧道（加密 / 可靠 / 多路复用）
                              ├─ 隧道流（逻辑端口 11010）      ← ET 控制帧（握手 / RPC / Ping / Pong）
                              └─ 隧道数据报（端口 11010，flow 0）← ET 数据帧（IP 包 / 用户 payload）
                                   └─ TunnelFrameTransport：字节流 / 数据报 ⇄ ET 帧
                                        └─ P2pNode::add_custom_transport → ET 握手 / 收发 / 路由
```

- `TunnelFrameTransport` 实现 mesh-tun-proto 的 `MeshFrameTransport`：
  - **控制帧**走可靠流，帧格式与 ET 的 TCP 帧一致：4 字节小端长度 + 16 字节 `PeerManagerHeader` + 载荷；
  - **数据帧**（`PacketType::Data`）走 `TunnelHandle::send_dgram`，一个数据报就是「16B 头 + 载荷」，
    没有长度前缀（数据报自带边界）。超长或队列满时自动退回可靠流——接收端两条通道都读，回退不会丢帧。
    这样避免「TCP over TCP」：丢一个 IP 包不该拖住后面的控制帧。
- `EtNode` 用一个独立线程承载 `P2pNode`（该库是同步 + 手动 tick 的模型），对外只有命令与事件两条通道。
  IP 包用命令发出去、以 `EtEvent::Node(P2pEvent::InboundIpPacket)` 事件收上来，这就是「TUN 交接面」。

### 谁开流：确定性规则

一条隧道上开几条 ET 流由**双方 PeerId 的字节序**决定：**PeerId 较小的一方发起**
（`should_open_et_stream`，与隧道 mux 的流号奇偶同向）。两端各自只知道「我」和「对端」，
算出来的结果必然相反，所以不可能双方同时开流、也不会都等着对方——不需要协商。
`establish_et_stream` 就是按这条规则封装的一步到位入口（发起方 `open_stream`，接受方等 `incoming`）。

### 为什么不按路线图写的「实现 ExternalHolePunchBridge」

mesh-tun-proto 的 `ExternalHolePunchBridge::punch_to` 返回的 `ExternalHolePunchResult` 只有地址、没有 socket，
`MeshUdpPlug::new` 会自己另绑一个 socket（库里的注释也写明这是占位）——另开的 socket 不在我们打通的那条洞上，
包发不过去。而把打通的 UDP socket 直接交给 ET（`add_udp_conn`）还有两个麻烦：这个 socket 上混着内核的
保活探针，要停保活并自己分流；链路的端到端加密也就只剩 ET 自己那一层（密钥由网络密钥派生）。

走隧道的两条通道则都不用管：分流、加密、可靠传输、多路复用隧道已经做了。

## 构建与运行

前提：

1. `mesh-tun-proto` 检出在本仓库的**同级目录**（`…/wgp` 与 `…/mesh-tun-proto` 并排，版本见上表）。
2. 有 protoc（mesh-tun-proto 的构建脚本要用）。没有的话从 protobuf 官方 Release 下载，解压到本目录的
   `.tools/`（已在 .gitignore 里），构建时用 `PROTOC` 指过去，不必改系统 PATH：

```powershell
# 在仓库根目录
$tools = "bridge\wgp-et-bridge\.tools"
New-Item -ItemType Directory -Force $tools | Out-Null
# 直连慢的话，可在地址前加镜像前缀，例如 https://v4.gh-proxy.org/
Invoke-WebRequest -OutFile "$tools\protoc.zip" `
  https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-win64.zip
# 校验（SHA256）：57ea59e9f551ad8d71ffaa9b5cfbe0ca1f4e720972a1db7ec2d12ab44bff9383
(Get-FileHash "$tools\protoc.zip").Hash
Expand-Archive "$tools\protoc.zip" "$tools\protoc"

$env:PROTOC = (Resolve-Path "$tools\protoc\bin\protoc.exe").Path
cargo test --manifest-path bridge\wgp-et-bridge\Cargo.toml
```

> 受限沙箱（build 脚本不允许写系统临时目录）里构建会看到 prost-build 的 `PermissionDenied`：
> 把 `TMP`/`TEMP` 指到仓库内的目录即可，例如
> `$env:TMP = (Resolve-Path .).Path + "\.tmp"`（该目录不要入库）。

验收用例 `tests/et_over_wgp.rs`（全程回环，两条用例）：

1. `two_wgp_nodes_punch_then_talk_et_over_the_tunnel`：种子 + 观察者 + 两个引擎自动装配打洞 →
   两端各自建成加密隧道 → 按 PeerId 规则开一条 ET 流 → 双向用户数据 → 同一条隧道上再开一条流、
   接一个密钥不同的 ET 节点，握手被两端拒绝且已建立的连接不受影响。
2. `route_sync_virtual_ip_and_ip_frames_go_over_the_tunnel`：握手 → 两端各自宣告虚拟 IP →
   各自路由表里看到对方那条（`EtEvent::Routes`）→ 双向 IP 帧（A 的包从 B 的 `InboundIpPacket` 原样出来）
   → 第三个 ET 节点加入，房主看到它的路由条目 → 停掉它，房主收到 `PeerDown` 且路由表里不再有它。

## 已知简化与后续

- ET 握手在节点线程里同步进行（库最长等 30 秒），期间其他连接不会被 tick。
- 重新宣告是固定 10 秒一次（`ANNOUNCE_INTERVAL`），刻意比官方 Core 的老化时间短。
- 下一步：接进 `wgp-client`；接 TUN（把 `InboundIpPacket` 写进网卡）；与真正的 EasyTier 节点互通测试；
  「独立进程还是同进程」仍是待决项（HANDOFF §5 第 4 条）。
- 若要让 `ExternalHolePunchBridge` 这条路能用，需要 mesh-tun-proto 那边把返回值改成能携带 socket 或传输对象——
  那是该库自己的接口设计，本桥接没有动它。
