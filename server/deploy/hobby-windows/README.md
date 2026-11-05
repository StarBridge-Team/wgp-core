# wgp-node-hobby 家庭宽带部署包（Windows）

家庭宽带贡献节点 = 折跃门的种子/观察者/STUN/TCP 信令兜底四职，但**强制拒绝 Forward 中转**（避免持续流量触发运营商 PCDN 风控，见 `docs/07-信令面与观察者协议.md` §7）。

## 包内容

| 文件 | 说明 |
|------|------|
| `wgp-node-hobby.exe` | 贡献版服务端（内部恒定贡献模式，`--no-hobby` 无效） |
| `wgp-node.conf` | 配置文件（启动时自动加载；键与后端 `server.rs::resolve_opts()` 一一对应） |
| `start-hobby.bat` | 启动脚本（双击运行；Ctrl+C 或关窗即停止） |
| `firewall-hobby.bat` | 防火墙放行脚本（**需右键“以管理员身份运行”，仅需执行一次**） |

## 部署步骤

1. **放行防火墙**：右键 `firewall-hobby.bat` → 以管理员身份运行（端口自动读 `wgp-node.conf`，conf 改端口后重跑即可原位更新规则）。
2. **端口映射**：登录光猫/路由器，把 `wgp-node.conf` 中启用的端口转发到本机内网 IP（改为“静态/映射”而非 DMZ）。默认配置对应下表：

   | 协议 | 外部端口 | 内部端口 | 用途 |
   |------|---------|---------|------|
   | UDP  | 11010   | 11010   | DHT 信令 |
   | UDP  | 3478    | 3478    | STUN/观察者 |
   | TCP  | 3481    | 3481    | TCP 信令兜底（UDP 被限速/封禁时客户端由此接入） |

   端口在 `wgp-node.conf` 改过时，以 conf 为准同步映射；conf 写 `none` 的面不用映射。
   光猫为桥接、路由器拨号时只在路由器上映射；光猫路由模式需两层都映射。
3. **启动**：双击 `start-hobby.bat`。看到 `已就绪（种子+观察者+承诺兜底）` 且三个端口在日志中列出即为成功。
4. （可选）**设为开机自启**：`Win+R` → `shell:startup` → 把 `start-hobby.bat` 的快捷方式放进去。

## 验证

- 本机：日志出现 `node_id=xx:xx:xx:xx` 与三个端口；
- 局域网外验证（用手机流量）：`wgp-client --seed udp://你的公网IP:11010` 能 Ping 通即入网成功；
- 查看公网出口 IP：浏览器访问任意 IP 查询页，客户端 `--seed` 填该 IP。

## 注意事项

- **`node_identity.key` 勿删**：删除即更换节点身份（node_id 变化）；
- 修改端口后需同步更新防火墙规则与路由器映射；
- 家宽多无固定公网 IPv4：IP 变化后需更新客户端 `--seed`（DDNS 域名可缓解）；有公网 IPv6 时客户端也可直连（防火墙规则已放行 any profile）；
- 贡献版不会中转业务流量，仅承担信令与观察，带宽占用可忽略；
- 卸载 = 删除本目录 + 删除防火墙规则（`控制面板 → 防火墙 → 高级设置 → 入站规则` 搜 "wgp-node"）。

## 配置速查（wgp-node.conf）

| 键 | 默认 | 说明 |
|----|------|------|
| `bind` | `0.0.0.0:11010` | DHT UDP 绑定地址 |
| `stun` | `3478` | 观察者/STUN 端口，`none` 关闭 |
| `tcp` | `3481` | TCP 信令端口，`none` 关闭 |
| `hobby` | `true` | 贡献模式（本二进制恒为 true） |
| `observer_rate_limit` / `observer_rate_window` | `12` / `10` | 观察者每 IP 限频 |
| `identity` | `node_identity.key` | 身份文件路径 |
| `log_level` | `info` | `error`/`warn`/`info`/`debug` |

优先级：命令行 > `WGP_*` 环境变量 > 本文件 > 内置默认值。完整选项见 `wgp-node-hobby.exe --help`。
