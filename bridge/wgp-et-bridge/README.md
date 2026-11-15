# wgp-et-bridge · ET 桥接 PoC（路线图 M3）

把 EasyTier 协议兼容层（[`mesh-tun-proto`](https://github.com/StarBridge-Team/mesh-tun-proto)）跑在折跃门打通的加密隧道上。

**最终目标**：不使用官方 ET 客户端，由本项目建立连接，作为节点加入 EasyTier 网络，并支持基础的 ET 节点特性。

**状态：PoC，目标尚未达成。** 只验证了路线图里的第一步——两个 WGP 节点打洞成功 → 跑 ET 协议 →
互发一条消息（本机回环，两端都是本项目的节点）。离目标还差：

| 差距 | 说明 |
|---|---|
| 与真正的 EasyTier 节点互通 | 官方节点不认识我们的打洞信令，和它们只能走标准的 ET TCP / UDP 连接（mesh-tun-proto 已有这两种传输）；打洞直连只发生在两个都跑本项目的节点之间。没有用官方节点对测过 |
| 路由同步 / 虚拟 IP / IP 帧 | 库里有实现，PoC 只覆盖了握手与用户数据，没有在隧道传输上跑过 |
| TUN 虚拟网卡 | 未做。Windows 需要 Wintun 驱动与管理员权限 |
| 可用的程序 | PoC 是库 + 测试，还没有「加入 ET 网络」的命令 |

## 职责边界

| 仓库 | 管什么 |
|---|---|
| wgp-core（本仓） | 打洞、加密隧道、端口转发；以及本目录这层「接缝」 |
| mesh-tun-proto | ET 协议：握手、加解密、路由、TUN 帧 |

本目录只做适配，不实现任何 ET 协议逻辑，也没有改动 mesh-tun-proto。它是一个**独立的 workspace**，不在主构建
和 GitHub CI 里：编译它需要 mesh-tun-proto 的检出（私有仓）和 protoc，不该让主构建依赖这两样东西。

## 怎么接的

```
内核打洞 → PunchedLink → wgp-port 隧道（加密 / 可靠 / 多路复用）
                              └─ 一条隧道流（逻辑端口 11010）
                                   └─ TunnelFrameTransport：字节流 ⇄ ET 帧
                                        └─ P2pNode::add_custom_transport → ET 握手 / 收发
```

- `TunnelFrameTransport` 实现 mesh-tun-proto 的 `MeshFrameTransport`。帧格式与 ET 的 TCP 帧一致：
  4 字节小端长度 + 16 字节 `PeerManagerHeader` + 载荷。
- `EtNode` 用一个独立线程承载 `P2pNode`（该库是同步 + 手动 tick 的模型），对外只有命令与事件两条通道。

### 为什么不按路线图写的「实现 ExternalHolePunchBridge」

mesh-tun-proto 的 `ExternalHolePunchBridge::punch_to` 返回的 `ExternalHolePunchResult` 只有地址、没有 socket，
`MeshUdpPlug::new` 会自己另绑一个 socket（库里的注释也写明这是占位）——另开的 socket 不在我们打通的那条洞上，
包发不过去。而把打通的 UDP socket 直接交给 ET（`add_udp_conn`）还有两个麻烦：这个 socket 上混着内核的
保活探针，要停保活并自己分流；链路的端到端加密也就只剩 ET 自己那一层（密钥由网络密钥派生）。

走隧道流则都不用管：分流、加密、可靠传输、多路复用隧道已经做了。

**代价**：ET 的 IP 包也走了可靠流，会有队头阻塞（「TCP over TCP」）。正式接 TUN 时，应让 ET 的数据帧改走
隧道的数据报通道（`TunnelHandle::send_dgram`），控制帧留在流上。

## 构建与运行

前提：

1. `mesh-tun-proto` 检出在本仓库的**同级目录**（`…/wgp` 与 `…/mesh-tun-proto` 并排）。
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

验收用例 `tests/et_over_wgp.rs`（全程回环）：

1. 种子 + 观察者 + 两个引擎自动装配打洞，内核交付 `PunchedLink`，两端各自建成加密隧道；
2. 在隧道上开一条流，两端各起一个 ET 节点（同一网络名与密钥）完成 ET 握手，互相认出对方的 ET 节点号；
3. 双向各发一条消息，对端以 `InboundUserData` 收到，内容一致；
4. 同一条隧道上再开一条流、接一个密钥不同的 ET 节点：握手被两端拒绝，已建立的连接不受影响。

## 已知简化与后续

- ET 握手在节点线程里同步进行（库最长等 30 秒），期间其他连接不会被 tick。
- 一对节点谁来开流还没有约定（测试里由用例指定）；接入客户端时需要一个确定性规则（如 PeerId 小的一方发起）。
- 下一步（都还没做）：接进 `wgp-client`；数据帧改走数据报通道；接 TUN / 虚拟 IP / 路由；与真正的 EasyTier
  节点互通测试；「独立进程还是同进程」仍是待决项（HANDOFF §5 第 4 条）。
- 若要让 `ExternalHolePunchBridge` 这条路能用，需要 mesh-tun-proto 那边把返回值改成能携带 socket 或传输对象——
  那是该库自己的接口设计，本 PoC 没有动它。
