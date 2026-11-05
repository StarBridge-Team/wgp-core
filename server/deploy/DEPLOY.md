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
> --observer-rate-window/--log-level/--config`）；配置优先级：命令行 > WGP_* 环境变量 >
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

> 每次重新 `cargo build --release` 后，记得把新的 `target/release/wgp-node-hobby.exe` 拷入本目录，保持包内二进制与源码一致。

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

键名与 `server.rs::collect_env()` 一一对应：`WGP_BIND` / `WGP_STUN` / `WGP_TCP` / `WGP_HOBBY`（贡献版恒 true 无需设） / `WGP_OBSERVER_RATE_LIMIT` / `WGP_OBSERVER_RATE_WINDOW` / `WGP_IDENTITY` / `WGP_LOG_LEVEL` / `WGP_CONFIG`。

脚本可调安装位置（均有默认，不需要就不设）：`WGP_INSTALL_DIR` / `WGP_RUN_USER` / `WGP_ENV_FILE` / `WGP_BIN`。防火墙仍按 §2 手工执行 `wgp-node.nft`（该文件首行 `flush ruleset` 会清空宿主机全部规则，故脚本不代劳）。

## 8. 运维要点

- 升级 = `cargo build --release && cp` 覆盖二进制 + `systemctl restart`（无数据迁移，无状态）
- 身份文件即服务器全部状态：备份 `node_identity.key`，丢失 = 节点身份重生成（被已入网路由表视为新节点，无害但不优雅）
- 被打（DDoS）预案：架构级冗余兜底（社区种子顶替/公共 STUN 顶替观察者）；
  P2P mesh 已建立的业务流零影响——不需要为此买高防