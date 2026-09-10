# wgp-node 部署清单（长沙种子 · Linux）

> 用途：登录服务器后按顺序执行。每步前面的 `[验证]` 是完成后必须确认的事项。

## 0. 首次登录顺序（重要）

1. **[验证] Linux 编译与测试**——本清单 1-3 步必须在动任何生产配置之前完成。
   开发机为 Windows，`cfg(unix)` 分支（ICMP ping-socket 后端）从未在 Linux 编译过。
2. **[验证] 身份文件已生成且重启不变**（第 5 步查 node_id 两次一致）。
3. **IP 保密**：本服务器 IP 不进 README/文档/公告/群消息。只进客户端内置种子列表。

## 1. 构建与测试

```bash
sudo apt update && sudo apt install -y build-essential pkg-config   # Debian/Ubuntu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
git clone <仓库地址> && cd <仓库目录>
cargo test --workspace          # [验证] 全绿；含 cfg(unix) ICMP 分支编译
cargo build --release
```

## 2. 防火墙（nftables）

```bash
sudo apt install -y nftables || sudo dnf install -y nftables
sudo nft -f deploy/wgp-node.nft    # [验证] nft list ruleset 显示三条链
sudo systemctl enable --now nftables
```

规则要点（`deploy/wgp-node.nft`）：默认 DROP；只放 UDP 3841/3478；
ICMP 全静默；单 IP UDP 限速 40 包/10s（协议正常流量远低于此）。

## 3. 服务安装（systemd）

```bash
sudo mkdir -p /opt/wgp-node
sudo cp target/release/wgp-node /opt/wgp-node/
sudo useradd -r -s /usr/sbin/nologin wgp 2>/dev/null || true
sudo cp deploy/wgp-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wgp-node
sudo systemctl status wgp-node
```

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

## 7. 运维要点

- 升级 = `cargo build --release && cp` 覆盖二进制 + `systemctl restart`（无数据迁移，无状态）
- 身份文件即服务器全部状态：备份 `node_identity.key`，丢失 = 节点身份重生成（被已入网路由表视为新节点，无害但不优雅）
- 被打（DDoS）预案：架构级冗余兜底（社区种子顶替/公共 STUN 顶替观察者）；
  P2P mesh 已建立的业务流零影响——不需要为此买高防