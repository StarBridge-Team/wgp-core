# wgp-node 部署清单（Linux · 双形态）

> 用途：登录服务器后按顺序执行。每步前面的 `[验证]` 是完成后必须确认的事项。
>
> 本仓库提供两个可执行形态，同一份代码、同一份配置：
> - **`wgp-node`（静态 IP 完整版）**——自有固定公网 IP 的服务器，启用全部职责（种子 + 观察者 + STUN + 承诺转发）。
> - **`wgp-node-hobby`（家庭宽带贡献版）**——社区贡献者的家宽机器，**强制拒绝中转**（PCDN 自保），只承担种子 + 观察者 + STUN + KV。
>
> 当前线上种子：`udp://轻松.躺进.icu:11010` + `tcp://轻松.躺进.icu:3481`（服务端为贡献服务器）。

## 0. 首次登录顺序（重要）

1. **[验证] Linux 编译与测试**——本清单 1-3 步必须在动任何生产配置之前完成。
   开发机为 Windows。`cfg(unix)` 分支（ICMP ping-socket 后端）已用
   `cargo check --workspace --target x86_64-unknown-linux-gnu` 交叉编译验证通过，
   但**尚未在真实 Linux 上跑过测试**——登录后务必 `cargo test --workspace` 补一次。
2. **[验证] 身份文件已生成且重启不变**（第 5 步查 node_id 两次一致）。
3. **IP 保密**：本服务器 IP 不进 README/文档/公告/群消息。只进客户端内置种子列表。

## 1. 构建与测试

```bash
sudo apt update && sudo apt install -y build-essential pkg-config   # Debian/Ubuntu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
git clone <仓库地址> && cd <仓库目录>
cargo test --workspace          # [验证] 全绿；含 cfg(unix) ICMP 分支编译
cargo build --release           # 产出 target/release/wgp-node 与 wgp-node-hobby 两个可执行
```

## 2. 防火墙（nftables）

```bash
sudo apt install -y nftables || sudo dnf install -y nftables
sudo nft -f server/deploy/wgp-node.nft   # [验证] nft list ruleset 显示 wgp 表
sudo systemctl enable --now nftables
```

规则要点（`server/deploy/wgp-node.nft`）：默认 DROP；只放 UDP 11010/3478 + TCP 3481；
ICMP 全静默；单 IP UDP 限速 40 包/10s、TCP 新建限速 20/秒（协议正常流量远低于此）。

## 3. 服务安装（systemd）

**静态 IP 完整版**：
```bash
sudo mkdir -p /opt/wgp-node
sudo cp target/release/wgp-node /opt/wgp-node/
sudo useradd -r -s /usr/sbin/nologin wgp 2>/dev/null || true
sudo cp server/deploy/wgp-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wgp-node
sudo systemctl status wgp-node
```

**家庭宽带贡献版**（把第 3 步的 unit 换成 hobby 单元，二进制换成 `wgp-node-hobby`）：
```bash
sudo cp target/release/wgp-node-hobby /opt/wgp-node/
sudo cp server/deploy/wgp-node-hobby.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wgp-node-hobby
```

> 两个单元都可保留，但**同一台机器同时只应启用一个**（端口 11010/3478/3481 冲突）。

## 4. 启动自检

```bash
ls -l /opt/wgp-node/node_identity.key    # [验证] 身份文件已生成（属主 wgp）
sudo systemctl restart wgp-node
sudo journalctl -u wgp-node -n 20        # [验证] 重启后日志 node_id 前 4 字节与上次一致
```

## 5. 客户端侧手工验证（本机即可）

```bash
sudo apt install -y netcat-openbsd
# STUN 面：构造 Binding 请求（cargo test 的 stun 用例可改出小工具）——或
# 等客户端联调一步到位（见下）。
```

## 6. 真机验证清单（服务器 + 两台异 NAT 设备）

| 项 | 操作 | 通过标准 |
|----|------|---------|
| 种子连通 | 客户端 attach 本种子 → ping | 1.5s 内 Pong |
| 观察者报告 | 客户端带 WGP-PEER 扩展探测 | 回显 nonce 一致 + XOR-MAPPED 正确 |
| 双端打洞 | 两端各掛异 NAT（电信家宽 × 移动热点）跑 new_link | 按 15 文档账本：UDP 高置信 ≤3.05s |
| TCP 兜底 | 一端屏蔽 UDP 出站（T1） | TCP 交付（Degraded） |
| LAN 组播 | 同一局域网两客户端 | <1s 组播发现直连 |
| ICMP 逃生 | 两端仅放 ICMP（防火墙模拟） | EscapePayload 往返（Linux ping-socket 后端首测） |

## 7. 贡献者模式（家庭带宽 · 防运营商误判 PCDN）

> 面向社区贡献者：用自己的家庭宽带跑 wgp-node。PCDN 判定的核心特征是
> **持续高上行带宽**——折跃门信令本就是小包低频，只要锁死两条放大路径，
> 特征上就不会被误判。

**必须做的三件事**：

```bash
# ① 直接用贡献版二进制启动：内部已强制 hobby，拒绝 Forward 中转
#    （中转是唯一可能产生持续流量的路径）
wgp-node-hobby --bind 0.0.0.0:11010 --stun 3478 --tcp 3481

# ② systemd 用贡献版单元：server/deploy/wgp-node-hobby.service
#    （ExecStart 不带参数：默认值即 07 §6 规格 11010/3478/3481；
#      改端口/限频用环境文件覆盖，见 §7.2，不写死在单元里）
# ③ 沿用 server/deploy/wgp-node.nft：默认 DROP + ICMP 静默 + 单 IP UDP 限速
```

> CLI 以 `--flag value` 为准（`--bind/--stun/--tcp/--identity/--observer-rate-limit/
> --observer-rate-window/--log-level/--config/--advertise/--peers`）；配置优先级：命令行 > WGP_* 环境变量 >
> `wgp-node.conf` > 默认值。旧的纯位置参数（`wgp-node 0.0.0.0:11010 3478 3481`）仅首位
> bind 向后兼容，stun/tcp 位置值已不生效（取默认 3478/3481）。

**软件内置的防护（本版已落地）**：
- 拒绝中转：hobby 模式节点不替他人转发任何消息（只收发自己参与的）
- 观察者限频：每 IP 12 次 / 10 秒，超限静默丢弃（合法打洞信令远低于此）
- 身份持久化：node_identity.key 固定节点身份

**贡献者须知**：
- 家庭宽带的可用价值 = 观察者 + 种子 + KV，完全不需要"中转"能力
- 正常流量量级：一天的信令总量低于几 MB；如果你的网被运营商警告，
  先查是不是 hobby 没开
- IP 保密仍适用：贡献节点 IP 不进公告，只进客户端种子列表

## 7.1 Windows 本机一键部署包（可选备用，免编译）

> 仅面向 Windows 本机试跑的贡献者；**服务器部署请走上文 systemd 流程或 §7.2 脚本**。

成品在 `server/deploy/hobby-windows/`：

| 文件 | 说明 |
|------|------|
| `wgp-node-hobby.exe` | 贡献版二进制（release 构建；内部强制 hobby，拒绝 Forward 中转） |
| `wgp-node.conf` | 配置文件（启动自动加载；键与 `server.rs::resolve_opts()` 一一对应） |
| `start-hobby.bat` | 启动脚本（双击运行；Ctrl+C/关窗即停止；不写死端口） |
| `firewall-hobby.bat` | 防火墙放行（**右键管理员运行**；端口自动读 `wgp-node.conf`，与后端同源） |

步骤：`firewall-hobby.bat`（管理员）→ 光猫/路由器端口映射（以 `wgp-node.conf` 中的端口为准，映射到本机内网 IP）→ 双击 `start-hobby.bat` → 日志出现 `已就绪（种子+观察者+承诺兜底）` 即成功。细节（自启、公网 IP 变动、卸载）见包内 `README.md`。

> 服务端代码有改动后，记得重新构建并把新的 `wgp-node-hobby.exe` 拷入本目录，保持包内二进制与源码一致。
> 请用 `scripts\package.ps1` 构建、取 `target\package\release\wgp-node-hobby.exe`：这样编出来的程序不依赖 VC++ 运行库，
> 也不会把构建者本机的用户目录路径带进仓库（直接 `cargo build --release` 的产物里有）。

## 7.2 Linux 一键部署（参数化，不写死端口）

```bash
cargo build --release                    # 交叉编译见 00 §8 / 14 文档
sudo bash server/deploy/install-hobby.sh # 创建用户+装二进制+装单元+enable --now
```

部署参数的来源与优先级（与 `server.rs` 同一套解析）：

| 来源 | 位置 | 说明 |
|------|------|------|
| 二进制默认值 | 内置 | `0.0.0.0:11010` + STUN 3478 + TCP 3481（07 §6 规格），单元 `ExecStart` 不带任何 `--flag` |
| 环境文件 | `/etc/wgp-node/env` | 安装脚本首装从 `wgp-node.env.example` 模板创建（全注释=全默认）；**已存在则绝不覆盖**。改键后 `systemctl restart wgp-node-hobby` |
| `wgp-node.conf` | 工作目录 | 二进制自动加载；键同 env（去 `WGP_` 前缀） |

键名与 `server.rs::collect_env()` 一一对应：`WGP_BIND` / `WGP_STUN` / `WGP_TCP` / `WGP_HOBBY`（贡献版恒 true 无需设） / `WGP_OBSERVER_RATE_LIMIT` / `WGP_OBSERVER_RATE_WINDOW` / `WGP_IDENTITY` / `WGP_LOG_LEVEL` / `WGP_CONFIG` / `WGP_ADVERTISE` / `WGP_ADVERTISE_DHT_PORT` / `WGP_ADVERTISE_STUN_PORT` / `WGP_ADVERTISE_TCP_PORT` / `WGP_DDNS_REFRESH` / `WGP_ALLOW_LOCAL_ENDPOINTS` / `WGP_PEERS`。

`WGP_ADVERTISE=<地址>`（或 `--advertise`）让节点对外宣告自己：其他节点与客户端可以自动发现它，客户端也不必再手填观察者。地址可以是：

- **固定公网 IPv4**（`203.0.113.7`）：VPS / 固定 IP 机器，外部端口与本机一致时无需其他参数；
- **域名**（`seed.example.com`，DDNS）：启动时解析，之后每 `WGP_DDNS_REFRESH` 秒（默认 300）重解析；**解析结果变了会自动换纪元重新宣告**，不再需要「改配置 + 重启」；
- **`none`**：不宣告（NAT 后面的 hobby 节点、只做客户端的节点）。

外部端口与本机不同（FRP / 端口映射）时，必须显式给出 `WGP_ADVERTISE_DHT_PORT` / `WGP_ADVERTISE_STUN_PORT` / `WGP_ADVERTISE_TCP_PORT`，否则别人连的是错的端口。宣告后身份文件旁会多一个 `node_identity.epoch`（启动计数，请和身份文件一起保留）。`WGP_PEERS=udp://另一个种子:11010,...`（或 `--peers`）指定入网引导的其他种子。两者都不设时节点不参与发现，行为与以前一致。

脚本可调安装位置（均有默认，不需要就不设）：`WGP_INSTALL_DIR` / `WGP_RUN_USER` / `WGP_ENV_FILE` / `WGP_BIN`。防火墙仍按 §2 手工执行 `wgp-node.nft`（该文件首行 `flush ruleset` 会清空宿主机全部规则，故脚本不代劳）。

## 8. 低资源调度配置

WGP 的节点与客户端以网络 I/O 为主；节点宣告/探活由 DHT 每 20 秒维护一次，房间维护及成员发现当前约每 2 秒轮询。默认 Tokio 多线程运行时会创建与 CPU 可见核数接近的 worker；新版本将默认封顶为 4 个，可通过 `WGP_RUNTIME_WORKERS` 设为 1–64。低流量种子可先设 1，普通 VPS 建议 2，只有测得 Tokio 任务积压后再增加。

### systemd 资源预算（可直接配置）

创建 `/etc/systemd/system/wgp-node-hobby.service.d/resources.conf`：

```ini
[Service]
# 家宽/1C VPS：CPU 配额按实际贡献能力调整，超限会延后工作但不丢状态
CPUQuota=50%
CPUWeight=50
# 当前目录簿 / KV / 转发队列均有界；给日志、运行时和峰值留余量
MemoryHigh=160M
MemoryMax=256M
TasksMax=32
# 低优先级后台运行，正常网络服务不受影响
Nice=5
IOWeight=50
Environment=WGP_RUNTIME_WORKERS=1
# 只在确实有公网 IPv4 且路由映射已通时配置静态地址
# Environment=WGP_ADVERTISE=203.0.113.7
# Environment=WGP_PEERS=udp://seed1.example:11010,udp://seed2.example:11010
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart wgp-node-hobby
sudo systemctl show wgp-node-hobby -p CPUQuotaPerSecUSec -p MemoryHigh -p MemoryMax -p TasksMax
sudo systemctl status wgp-node-hobby --no-pager
```

静态 IP 完整版同样可用该 drop-in，文件名改为 `wgp-node.service.d/resources.conf`，但公网转发种子不建议设置过低 CPUQuota；资源限制是宿主机预算，不替代 DHT 自身限流。避免对生产机直接应用 `server/deploy/wgp-node.nft`：该规则文件会 `flush ruleset`，先合并到现有防火墙策略。

资源监控：

```bash
systemctl show wgp-node-hobby -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent
journalctl -u wgp-node-hobby --since today --no-pager
ss -lunpt | grep -E ':(11010|3478|3481)\\b'
```

### 种子维护节奏与节点角色

- VPS 主种子：固定公网 IPv4，开放 UDP 11010、UDP 3478、TCP 3481；设置 `WGP_ADVERTISE`，并用 `WGP_PEERS` 配置至少一个独立备用 VPS。完整 `wgp-node` 提供信令 Forward 兜底。
- 家宽贡献节点：使用 `wgp-node-hobby`，保持 `WGP_HOBBY` 不可关闭；需映射 UDP 11010/3478、TCP 3481。配置一个 VPS 完整节点为 `WGP_PEERS`，家宽节点只承担发现、观察者与 KV，不中转 Forward。
- 房间快速入网：客户端优先配置稳定 VPS 的 UDP seed，第一次运行执行发现；入口 seed 必须互相认识并持续对外宣告。仅 TCP seed 目前只能作为后续协商兜底，房间 DHT RPC 仍要求至少一个 UDP seed。
- 客户端开房/加入命令须长期驻留；节点服务用 `systemctl enable --now` 开机自启。首次开机后检查日志中 `已就绪`、`node_id`、广告地址和入网引导端点。

### VPS 部署检查表

1. 优先选择有固定公网 IPv4 的 1 vCPU / 512 MiB 或以上 Linux VPS；完整节点建议 2 Tokio workers，极小实例用 1。
2. 安装完整版：按 §3 放置 `wgp-node` 与 `wgp-node.service`。将 `--advertise` 设置为固定公网 IPv4，并用 `--peers udp://<备用VPS>:11010`（或配置 `WGP_PEERS`）形成至少双入口。
3. 云厂商安全组和主机防火墙都开放 UDP 11010、UDP 3478、TCP 3481；TCP 3481 不能替代 UDP DHT 房间读写。
4. 执行 `systemctl enable --now wgp-node`，用另一条网络运行 `wgp-client --seed udp://<VPS_IP>:11010` 做连通实测，再查看目录是否互相发现。
5. 备用 VPS 使用不同可用区/供应商；不要复制同一份 `node_identity.key`，身份必须独立且持久化。

### 家庭宽带节点细分

- **公网 IPv4 / 光猫桥接**：在路由器 DHCP 保留节点主机 LAN IP；映射 UDP 11010、UDP 3478、TCP 3481 到本机相同端口；配置 `WGP_ADVERTISE=<当前公网 IPv4>`、`WGP_PEERS=udp://<VPS_IP>:11010`；选用 hobby 版并设 `WGP_RUNTIME_WORKERS=1`。WAN 地址变化时按下一节更新宣告。
- **双层 NAT**：光猫路由模式时，光猫与下游路由器都要映射；任一层没有管理权限或不支持映射，外部节点无法主动探测此节点。仍可运行 hobby 版作为出站发现客户端，但不要发布不可达地址。
- **CGNAT / 无公网 IPv4**：端口映射无效，`--advertise` 不能填写私网或 CGNAT 地址并期待公网入站；不要做 UPnP/DMZ 暴露。节点可以作为出站客户端连 VPS seed，但目前不是可被其他节点直连的公共 seed。若运营商提供公网 IPv6，可在另行实现并验证 IPv6 广告前作为实验性目标，不要宣称当前 IPv4 DHT 路径已支持 IPv6。
- **纯 Windows 家庭电脑**：运行 `server/deploy/hobby-windows/` 包，防火墙脚本需管理员运行；用任务计划程序创建“登录时启动”任务，程序指向 `wgp-node-hobby.exe`，起始目录设为包目录以固定身份文件位置。关机启动且无人登录的服务场景优先使用 Linux/systemd 或受控 Windows Service 包装器，不要依赖用户 Startup 文件夹。

### 动态 IPv4 更新（DDNS 内置 / 外部 timer）

**首选：让节点自己盯着 DDNS。** `WGP_ADVERTISE` 直接写域名，节点按 `WGP_DDNS_REFRESH`（默认 300 秒）重解析，地址一变就换纪元重新宣告——不需要重启，也不需要外部脚本：

```bash
# /etc/wgp-node/env
WGP_ADVERTISE=seed.example.com
WGP_DDNS_REFRESH=300
```

前提是这台机器的公网地址确实被那个域名跟踪（DDNS 客户端或路由器自带的 DDNS 功能负责更新 A 记录）。节点侧的日志会打印每次解析结果与重宣告。

**备选：没有域名、只有「查公网 IP」的条件。** 仓库仍保留外部刷新脚本：它定时查公网地址，只在变化时替换 `WGP_ADVERTISE` 行并重启节点（先确认公网 IP 查询服务可信且允许自动请求）：

仓库提供脚本与 systemd 单元模板；脚本会校验全球可路由 IPv4、使用文件锁防并发、仅地址变化时重启，并在重启失败时回滚环境文件。安装步骤：

```bash
sudo install -m 0755 server/deploy/wgp-refresh-advertise.sh /usr/local/libexec/wgp-refresh-advertise
sudo install -m 0644 server/deploy/wgp-refresh-advertise.service /etc/systemd/system/
sudo install -m 0644 server/deploy/wgp-refresh-advertise.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wgp-refresh-advertise.timer
sudo systemctl start wgp-refresh-advertise.service
sudo systemctl list-timers wgp-refresh-advertise.timer
sudo journalctl -u wgp-refresh-advertise.service -n 30 --no-pager
```

service 默认维护 `/etc/wgp-node/env` 并重启 `wgp-node-hobby`；完整版 VPS 不需要动态刷新。脚本依赖 `curl`、`python3`、`flock`。可在 service drop-in 覆盖 `WGP_IP_CHECK_URL` 使用自有可信地址回显服务。
该脚本不负责 DDNS 提供商 API、路由器端口映射或 CGNAT 穿透。端口外部映射与本机不一致时，用 `WGP_ADVERTISE_DHT_PORT` 等三个键显式给出外部端口（见 §10）。若更新配置失败，先恢复 `/etc/wgp-node/env` 备份并重启服务。不要把 seed 私钥复制给更新任务。

### 客户端开机运行

Linux 图形桌面可用用户 systemd unit；身份文件用绝对路径固定保存位置，命令中的房间码、口令请限制本地文件权限：

```ini
# ~/.config/systemd/user/wgp-client.service
[Unit]
Description=WGP room client
After=network-online.target
Wants=network-online.target
[Service]
Environment=WGP_RUNTIME_WORKERS=2
Environment=WGP_SEED=udp://seed.example:11010
ExecStart=/opt/wgp/wgp-client join U/替换为房间码 --identity %h/.local/share/wgp/client.key --forward 25565
Restart=on-failure
RestartSec=5
[Install]
WantedBy=default.target
```

```bash
mkdir -p ~/.config/systemd/user ~/.local/share/wgp
chmod 700 ~/.local/share/wgp
systemctl --user daemon-reload
systemctl --user enable --now wgp-client
loginctl enable-linger "$USER"  # 仅需在无交互登录也要运行时开启
```

客户端是会话进程，不要作为 seed 节点运行；在 Windows 用任务计划程序配置开机触发、失败重启，并把 `wgp-client.key`/工作目录固定到用户数据目录。

## 9. 运维要点

- 升级 = `cargo build --release && cp` 覆盖二进制 + `systemctl restart`（无数据迁移，无状态）
- 身份文件即服务器全部状态：备份 `node_identity.key`，丢失 = 节点身份重生成（被已入网路由表视为新节点，无害但不优雅）
- 被打（DDoS）预案：架构级冗余兜底（社区种子顶替/公共 STUN 顶替观察者）；
  P2P mesh 已建立的业务流零影响——不需要为此买高防

## 10. 五种部署方式（VPS / NAT 手动映射 / DDNS / FRP / 局域网）

按「这台机器怎么把端口暴露给外部」选方式。五种方式跑的是同一个二进制，差别只在
`--advertise` 怎么写、端口怎么来。**DDNS 不是一个独立形态**：它是 A/C/B 任意一种里
「地址会变」时的写法（§10.4），与 FRP 同级——两者都是正式支持的方式，不是兜底。

| 方式 | 入站路径 | 关键参数 | 适用 |
|---|---|---|---|
| **A. 公网 VPS** | 直连本机公网 IPv4 | `--advertise <公网IPv4>` | 有固定公网 IP 的云主机（首选） |
| **B. NAT 机（手动端口映射）** | 路由器/光猫把外部端口映射到本机 | `--advertise <公网IPv4 或 DDNS 域名>`；外部端口与本机不同时再加三个 `--advertise-*-port` | 有公网 IP 的家宽 / 办公网（需要手动加端口映射的形态） |
| **C. FRP 穿透** | 公网中继机 `frps` → `frpc` → 本机 | `--advertise <frps 公网地址> --advertise-dht-port … --advertise-stun-port … --advertise-tcp-port …` | 没有公网 IPv4（CGNAT / 公司网 / 宿舍网） |
| **D. 局域网 / 本机联调** | 同一网段内直连 | `--allow-local-endpoints` | 开发、单机多进程、内网小规模试用 |
| **E. DDNS（跨形态）** | 同所在形态 | `--advertise <域名>` + `--ddns-refresh <秒>` | 公网地址会变（家宽重播、弹性 IP） |

> **不支持的形态**：CGNAT（`100.64.0.0/10`）后面既没有公网 IPv4 也没有中继机时，`--advertise`
> 写什么都不会让外部节点连进来；DHCPv6/IPv6 广告未实现（协议面 v1 只有 IPv4）——这一种走 C（FRP）。

### 10.1 NAT 机：手工端口映射（拓扑 C，主线）

这台机器在 NAT 后面，但 NAT 设备（路由器 / 光猫）能手工加映射。做法：

1. **先固定本机内网地址**：在路由器 DHCP 里给这台机器保留一个固定租约（否则重启换了内网 IP，
   映射就指错地方）。
2. **在本机确认监听端口**：默认 `0.0.0.0:11010`（DHT UDP）、`3478`（STUN UDP）、`3481`（TCP 信令）。
   改了端口就以实际值为准。
3. **在路由器/光猫上加三条端口映射**（外部端口 → 内网 IP:端口）：

   | 外部端口 | 协议 | 内网目标 | 用途 |
   |---|---|---|---|
   | 11010 | UDP | `<内网IP>:11010` | DHT 信令（房间读写、发现、Forward 中转） |
   | 3478 | UDP | `<内网IP>:3478` | 观察者 / STUN（NAT 判定与打洞） |
   | 3481 | TCP | `<内网IP>:3481` | TCP 信令兜底（可选但强烈建议） |

   **首选「外部端口 = 内网端口」**：这样 `--advertise` 只写地址，不需要额外参数。
   路由器只允许换号时，才用 `--advertise-dht-port/-stun-port/-tcp-port` 写出外部端口。
4. **启动参数**：

   ```bash
   wgp-node --bind 0.0.0.0:11010 --stun 3478 --tcp 3481 \
            --advertise <公网IPv4 或 DDNS 域名>
   ```

   公网 IP 会变就写 DDNS 域名（见 §7.2），节点自己重解析并重宣告，不用重启。
5. **验证**：从另一条网络（手机热点即可）跑
   `wgp-client join U/.... -p udp://<公网地址>:11010`，看到 `[种子] … 往返` 即外部可达。
   只见到「全部种子端点不可达」时依次查：云/运营商是否封 UDP、路由器映射是否真的生效
   （部分光猫需要「虚拟服务器/DMZ」而不是「端口触发」）、主机防火墙是否放行。

**常见坑**：

- **双层 NAT**（光猫路由模式 + 下游路由器）：两层都要映射，缺一层外部就连不进来。
- **hairpin / NAT 回环**：从内网用公网地址访问自己往往不通，这不代表映射错了——请从外网验证。
- **运营商级 NAT（CGNAT）**：路由器 WAN 口拿到的是 `100.64.x.x` 或 `10.x` 而不是公网地址，
  说明没有公网 IPv4，端口映射无论如何都不会生效 → 走 §10.2 的 FRP。
- **映射了 UDP 却没映射 TCP**：房间读写能用，UDP 被封时没有兜底。

### 10.2 FRP 穿透（方式 C，没有公网 IPv4 时）

一台机器（`frps`）有公网 IPv4，另一台（`frpc` + `wgp-node`）在 NAT 后面、且拿不到公网 IPv4
（CGNAT、公司网、宿舍网）。仓库给了三份东西：

- `server/deploy/frp/frps.toml.example`：中继端配置（含 `allowPorts` 白名单与 token 鉴权）
- `server/deploy/frp/frpc.toml.example`：NAT 端配置（三个 proxy：DHT UDP / STUN UDP / TCP 信令）
- `server/deploy/install-seed-frp.sh`：NAT 端一键安装（装 frpc + wgp-node、写单元、起服务、自检）

中继端手工三步：

```bash
sudo install -d /etc/frp
sudo cp server/deploy/frp/frps.toml.example /etc/frp/frps.toml   # 改 auth.token
sudo systemctl enable --now frps                                 # 或用 frps -c /etc/frp/frps.toml
# 放行 TCP 7000（frps 控制口）与 allowPorts 里的三个端口（云安全组 + 主机防火墙都要）
```

NAT 端一条命令：

```bash
FRPS_ADDR=relay.example.com FRP_TOKEN='<与 frps 一致的长随机串>' \
  sudo -E bash server/deploy/install-seed-frp.sh
```

脚本最终会写出这样的启动参数（外部端口 ≠ 本机端口，这是本拓扑的关键）：

```ini
ExecStart=/opt/wgp-node/wgp-node --bind 0.0.0.0:11010 --stun 3478 --tcp 3481 \
  --advertise relay.example.com \
  --advertise-dht-port 21010 --advertise-stun-port 23478 --advertise-tcp-port 23481
```

客户端侧只需 `-p udp://relay.example.com:21010`（TCP 兜底 `tcp://relay.example.com:23481`）。

**限制（必须知道）**：FRP 的 UDP 代理按「访客」跟踪。种子主动推给别人的广告，在还没有任何
访客之前会被丢弃；一旦有节点来 PING / FIND_SEEDS / FIND_VALUE，双向就通了。所以 FRP 形态的
种子**更适合被查询，不适合做主动推送源**——它的价值（发现、观察者、房间 KV）不受影响，
但它自己不擅长「先去告诉别人我在这儿」。需要主动推送时，配置 `WGP_PEERS` 指向至少一个
能主动连到的种子（例如一台公网 VPS），由对方向它索取。

### 10.3 局域网 / 本机联调（方式 D）

端点准入默认**只收公网地址**（审计 M2：挡住「把 127.0.0.1 / 10.x / CGNAT 地址写进公共目录，
让所有人去探一个注定连不上的地址」）。本机多进程或同一交换机上的部署要显式放宽：

```bash
wgp-node --bind 0.0.0.0:11010 --advertise 192.168.1.10 --allow-local-endpoints
wgp-client join U/XXXX-XXXX-XXXX-XXXX -p udp://192.168.1.10:11010 --allow-local-endpoints
```

`wgp-node` / `wgp-client` 也会按**你自己配置的地址**自动判断：入口里出现回环/私网地址时自动
放宽（本机联调、`scripts/e2e-local.*` 都属于这种）；公共部署仍然严格。别人的广告地址再特殊
也改变不了本端的准入规则。

### 10.4 DDNS（方式 E，地址会变时套在 A/B/C 上）

DDNS 不是独立形态，而是「地址会变」时 `--advertise` 的写法：域名由 DDNS 服务商（或路由器
自带的 DDNS 功能）跟踪 A 记录，节点按域名宣告，并在解析结果变化时**自动换纪元重新宣告**。

**前提**：你有一个域名，且它的 A 记录确实被更新（云厂商 API / DDNS 客户端 / 路由器内置功能，
任选其一）。本项目不负责更新 DNS 记录，只负责「解析 → 宣告 → 变了再宣告」。

配置只有两行：

```ini
# /etc/wgp-node/env（或 wgp-node.conf 里的 advertise / ddns_refresh）
WGP_ADVERTISE=seed.example.com      # 写域名，不写 IP
WGP_DDNS_REFRESH=300               # 重解析周期（秒）；0 = 只在启动时解析一次
```

启动日志会显示：

```
[INFO] DDNS：seed.example.com → 203.0.113.7
[INFO] 对外宣告 seed.example.com:11010（DHT）/ 3478（STUN）/ 3481（TCP）| 第 12 次启动 | 声明可中转
```

地址变化时（例如家宽重播）会再打一条：

```
[INFO] DDNS：seed.example.com → 198.51.100.9（原 Some(203.0.113.7)），已用纪元 12 重新宣告
```

纪元机制保证「认识你的人会换到新地址」：接收端只采纳更大的纪元，旧地址的广告自动作废。

**踩坑清单**：

1. **首选 TTL 短一点**（60–300 秒）。TTL 太长时，即使节点换了宣告，别人的 DNS 缓存还是旧地址。
2. **不要在 DDNS 后面再套一层 CDN/代理**：A 记录必须是这台机器（或 FRP 中继）的真实公网地址。
3. **解析不出 IPv4 不阻止启动**：日志会给 `暂时解析不出 IPv4，先以「不宣告」启动`，后台继续重试；
   常见原因是网络还没起来（systemd 的 `After=network-online.target` 已经加了，但云主机早期仍可能抢跑）。
4. **IPv6 未支持**：协议面 v1 只有 IPv4 广告，只给 AAAA 记录不会有帮助。
5. **FRP + DDNS**：`--advertise` 写的是 **frps 的地址**；frps 主机如果也可能换 IP，就把 frps 的域名
   写进 `--advertise`（节点会解析它），同时 `frpc.toml` 的 `serverAddr` 也用同一个域名。

### 10.5 验证清单（针对方式 B / C）

| 检查 | 命令 | 期望 |
|---|---|---|
| 本机端口在听 | `ss -lunpt \| grep -E ':(11010\|3478\|3481)\b'` | 三个都在 |
| 中继隧道已建立（C） | `journalctl -u frpc -n 30 \| grep -i 'login to server success'` | 有 |
| 广告内容正确 | `journalctl -u wgp-node -n 30 \| grep '对外宣告'` | 地址是**中继/公网地址**，端口是**外部端口** |
| DDNS 生效 | `journalctl -u wgp-node \| grep DDNS` | 有解析结果；地址变化时有「已用纪元 … 重新宣告」 |
| 外部可达 | 另找一台不同网络的机器跑 `wgp-client join … -p udp://<地址>:<外部DHT端口>` | 1.5 秒内出现 `[种子] … 往返` |
| 观察者可用 | 客户端启动后看 NAT 探测输出 | 有公网端点（不是 `0.0.0.0:0`） |

> 诚实声明：本仓库此前的验证全部在回环与单机多进程上；方式 C（FRP）、手动端口映射与 DDNS 的
> 参数解析、广告组装、重宣告逻辑都有单元测试，但**没有在真实 FRP 中继 + 真实 NAT + 真实 DDNS
> 域名上跑过**。第一次上线请按上表逐项确认，并把结果填进 `项目完整文档/18-NAT实测数据.md` §7。

