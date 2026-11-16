# 折跃门（wgp）· 纯 P2P 零中继 NAT 打洞组网

两端业务数据端到端直连，种子节点只承担信令与端点观测，永不转发业务流量。

> **预览阶段**：种子发现 → 打洞 → 加密隧道 → 端口转发的全流程已用真实二进制在回环上走通（Windows 与 Linux），
> 但**还没有做过真实 NAT 下的双端联调**。现状、已知问题与下一步见 [`HANDOFF.md`](HANDOFF.md)。

许可证：**GPL-3.0-or-later**（上游链条：EasyTier LGPL → mesh-tun-proto LGPL → **wgp GPL** → mc-link GPL）。

## 跑起来

```bash
# 1. 一台公网机器跑种子（放行 UDP 11010 信令 / UDP 3478 观察者 / TCP 3481 信令兜底）
wgp-node --bind 0.0.0.0:11010 --advertise <本机公网IPv4>

# 2. 房主（游戏服务器所在的机器，以 Minecraft Java 版 25565 为例）
wgp-client 开房 -n <房间名> -k <口令> -p udp://<种子>:11010 --expose 25565

# 3. 朋友
wgp-client join -n <房间名> -k <口令> -p udp://<种子>:11010 --forward 25565
#    看到「[隧道] 就绪」后，游戏里连 localhost:25565
```

- 房间名 + 口令在本地派生成房间码，**两端不需要交换任何码**（等价于 EasyTier 的 `--network-name / --network-secret`）。
- 种子用 `--advertise` 宣告自己后，客户端自动找到观察者与其他种子；种子没有宣告时，两端都要加
  `--observer <种子IP>:3478`。多个种子之间用 `--peers udp://<另一个种子>:11010` 互相认识。
- 基岩版等 UDP 服务用 `--expose-udp / --forward-udp`。更多写法见 `wgp-client --help`。
- 种子里至少要有一个完整版 `wgp-node`：只有 `wgp-node-hobby`（拒绝信令中转）时第二个成员进不了房间。

## 目录

```
kernel/               内核五层（依赖单向 proto ← crypto ← punch ← dht ← core）
  wgp-proto           协议：包格式/常量/编解码 + STUN 最小子集（零依赖、无 async）
  wgp-crypto          密码：承诺-揭示、HKDF、探针 HMAC、隧道 AEAD、KeyAgreement（PQ 可插拔）
  wgp-punch           打洞：状态机、预算调度器（唯一发包点）、步长学习、三波、保活
  wgp-dht             信令：Kademlia 变种、房间键、租约/继位链、观察者协议、种子发现
  wgp-core            门面：Engine + PunchedLink 交付物 + 全部对外 API（feature: client/node）
bridge/
  wgp-port            数据面：加密隧道（UDP 可靠层 / TCP 记录流）、多路复用、端口转发
  wgp-et-bridge       ET 桥接 PoC（独立 workspace：依赖 mesh-tun-proto 与 protoc，见其 README）
server/wgp-node       服务端：种子 / 观察者 / TCP 信令兜底（双形态 wgp-node + wgp-node-hobby）
client/wgp-client     客户端：code / 开房 / join + 端口转发
scripts/              端到端验证（e2e-local.ps1 / .sh）与本机打包（package.ps1）
.github/workflows/    持续集成（ci.yml）与多平台预览版发版（release.yml）
项目完整文档/          设计文档（00–17 编号）+ 按代码现状撰写的全量文档（20 号为 2026-11 的变更追补与多进程方案）
nat/                  NAT 实测数据
```

## 构建与测试

```bash
cargo test --workspace        # Windows 297 个 / Linux 296 个测试，全部跑在回环上
cargo build --release         # LTO release，产出 wgp-node / wgp-node-hobby / wgp-client
```

用真实二进制在回环上走一遍完整流程（种子 → 开房 → 加入 → 打洞 → 隧道 → TCP/UDP 转发 → 崩溃重连）：

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1             # 单种子
powershell -ExecutionPolicy Bypass -File scripts\e2e-local.ps1 -Discovery  # 双种子发现
```

```bash
# Linux
cargo build --release --bins --examples
bash scripts/e2e-local.sh target/release --discovery
```

## 发版

推送 `v*` 标签，GitHub Actions 为 8 个目标构建、验证、打包并发布为 **pre-release**：

```bash
git tag v0.1.0-preview.1 && git push origin v0.1.0-preview.1
```

| 系统 | 64 位 | 32 位 |
|---|---|---|
| Windows | x86_64、ARM64 | x86（i686） |
| Linux（musl 静态） | x86_64、ARM64、龙架构 | x86（i686）、ARMv7 |

龙架构 32 位与 Windows 32 位 ARM 没有带标准库的 Rust 目标，编不了。本机只打 Windows x86_64 的包：
`powershell -ExecutionPolicy Bypass -File scripts\package.ps1`（产物在 `dist\`）。

## 文档

- **接手先读**：[`HANDOFF.md`](HANDOFF.md)（做了什么 / 现在在哪 / 已知问题 / 下一步）
- 拼装与验证记录：[`STATUS.md`](STATUS.md)；11-07 的代码盘点快照：[`PROGRESS.md`](PROGRESS.md)
- 设计文档：先读 [`项目完整文档/00-项目总览.md`](项目完整文档/00-项目总览.md)，再按文末路线深入
- 写代码前必读 [`项目完整文档/03-代码编写硬规矩与规范.md`](项目完整文档/03-代码编写硬规矩与规范.md)
- 接口与协议的变更登记：[`项目完整文档/14-内核API文档.md`](项目完整文档/14-内核API文档.md) §12
- DHT 身份与信任方案（含 P0 实现记录）：[`项目完整文档/17-DHT节点身份与信任方案.md`](项目完整文档/17-DHT节点身份与信任方案.md)

## EasyTier 兼容

上游 EasyTier 是 **LGPL-3.0**，且 ET 协议层依赖 protobuf（本仓内核明令禁止），所以 ET 协议兼容层
`mesh-tun-proto` 单独建仓（StarBridge-Team/mesh-tun-proto）。本仓已选 GPL-3.0-or-later，可以直接链接该 LGPL 库。

目标：不使用官方 ET 客户端，由本项目建立连接，作为节点（no-tun 模式）加入 EasyTier 网络。
现状：[`bridge/wgp-et-bridge`](bridge/wgp-et-bridge/README.md) 是 PoC——两个本项目的节点打洞后在加密隧道上完成 ET 握手并互发消息；
与官方 EasyTier 节点的互通尚未验证。两个仓库各管各的：本仓只做适配，不实现 ET 协议逻辑。
