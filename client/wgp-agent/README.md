# wgp-agent（多进程阶段 1）

> 配套设计：[项目完整文档/20-多进程运行与跨进程通信方案.md](../../项目完整文档/20-多进程运行与跨进程通信方案.md)。
> 本文只写**已经做了什么、没做什么、怎么跑、还剩哪些风险**，避免把阶段 1 当成完整的多进程交付。

## 1. 现在是什么

`wgp-agent` 是客户端侧唯一的特权持有者：

```
wgp-ui / CLI ──(本机 IPC，ACL + 有界队列)──> wgp-agent ──UDP/TCP──> seeds & peers
                                              ├─ DhtNode（身份、socket、路由、KV）
                                              ├─ Engine（打洞内核）
                                              └─ PortHub（端口转发、隧道）
```

- 身份私钥、UDP socket、会话密钥都只在 agent 进程里。IPC 命令集里没有「导出私钥」「打开任意 socket」「执行命令」这类口子。
- IPC 端点只在本机：Unix 用 `$XDG_RUNTIME_DIR/wgp/agent.sock`（目录 0700 / socket 0600，accept 后校验 `SO_PEERCRED` 的 UID），
  Windows 用命名管道 `\\.\pipe\wgp-agent-<用户名>`，创建时用受限安全描述符 `D:P(A;;GA;;;OW)`（仅属主）并拒绝远程客户端，
  连接建立后比对登录会话（`TokenStatistics.AuthenticationId`）。
- 每条连接的控制队列 128、出口队列 256。满了回 `Busy`；慢订阅者的事件被丢弃并计数（`Snapshot.dropped_events`）。
- 状态改变类命令在「未知次版本」下**一律拒绝**（`Unsupported`），不会用旧语义执行一遍危险命令。

### 命令集（IPC v1）

| 命令 | 说明 |
|---|---|
| `GetVersion` | agent 版本 + IPC 主/次版本 + pid + 运行时长 |
| `GetCapabilities` | 能力位、最大房间数、队列容量 |
| `GetSnapshot` | UI 重连后重建状态：房间、成员数、存储节点、转发/暴露规则、丢弃事件数 |
| `StartRoom` / `JoinRoom` | 开房/加入（同一内核语义：房间不存在就建）。参数与 `wgp-client` 的同名命令行选项一一对应 |
| `LeaveRoom` | 关隧道 + 停 upkeep |
| `WatchEvents` | 订阅事件流（本版本无重放：重连后先 `GetSnapshot`） |
| `ShutdownAgent` | 优雅退出（仅属主可发，传输层已保证） |

事件：`AgentStarted` / `RoomJoined` / `RoomLeft` / `RoomMembers` / `Link` / `TunnelReady` / `Forward` / `EventsDropped`。

## 2. 怎么跑

```bash
cargo build -p wgp-agent

# 前台启动（默认身份文件 wgp-agent.key，默认本机端点）
./target/debug/wgp-agent

# 指定身份与端点
./target/debug/wgp-agent --identity /tmp/agent.key --socket /tmp/agent.sock

# 冒烟：GetVersion + GetSnapshot + ShutdownAgent
./target/debug/wgp-agent ping --socket /tmp/agent.sock
```

Windows：

```powershell
cargo build -p wgp-agent
target\debug\wgp-agent.exe --identity agent.key --socket wgp-agent-demo
target\debug\wgp-agent.exe ping --socket wgp-agent-demo
powershell -ExecutionPolicy Bypass -File scripts\agent-smoke.ps1
```

`scripts/agent-smoke.ps1` / `scripts/agent-smoke.sh` 会验证：启动就绪、第二个 agent 拒绝同一端点（退出码 3）、
`ping` 拿到版本与快照、`ShutdownAgent` 走优雅退出路径、端点被清理。

## 3. 与 `wgp-client` 的关系

`wgp-client` 仍是**单进程**命令行前端（开房/加入/端口转发都能用），它没有改成 IPC 客户端。阶段 1 先落地
「agent 能通过 IPC 做同样的事」，把两者合并成「CLI 只是 IPC 客户端」是下一步——那需要把 `wgp-client`
里的呈现/装配线代码抽成库，本次刻意没动，避免一边改协议一边改前端。

## 4. 没做的（重要）

1. **GUI**：没有。IPC 只是给它留好了入口。
2. **TUN 特权 helper**（阶段 2）：没有。虚拟网卡仍属未开工项。
3. **ET 独立 worker**（阶段 3）：没有。ET 桥接仍是同进程线程。
4. **方法级鉴权**：只做「同一用户」（UDS peer-cred / 管道 DACL + 登录会话）。同一用户的另一个进程可以控制 agent——这是阶段 1 的
   有意取舍（同用户本来就能读写对方的进程内存）。
5. **IPC 重放/防重放**：没有 token、没有 nonce。防护全部依赖 OS 权限边界。
6. **事件重放**：没有缓冲，重连必须靠 `GetSnapshot` 重建。
7. **`GetSnapshot.links` 恒为空**：链路明细只通过 `Link`/`TunnelReady` 事件增量给出。
8. **多房间共用一份 `Engine`**：`Engine::attach_dht` 是进程级的，阶段 1 每开一个房间就覆盖一次存储节点与承载。
   同时开两个房间时，第二个房间会改变第一个房间后续 RPC 的目标。**暂定只开一个房间**（`max_rooms` 报 4 只是上限，
   真正的限制是这条）。
9. **`LeaveRoom` 不释放转发端口**：`PortHub` 没有「关监听」的 API，监听任务随进程存活；关房后端口仍被占用，
   要重开同一个端口必须重启 agent。
10. **`--allow-legacy-identity`**：只在启动时生效（身份策略不随命令切换）。

## 5. 残余风险

- 命名管道的安全描述符由 `windows-sys` 构造，SDDL 字符串是常量 `D:P(A;;GA;;;OW)`。如果将来改成按 SID 精确授权，
  必须重跑 `sddl_parses_to_a_valid_descriptor` 与真实两用户测试。
- Unix 侧只校验 UID，不校验可执行文件/签名：同 UID 的进程都可信（与 ssh-agent 同一模型）。
- IPC 帧上限 1 MiB；超限在**读 body 之前**就拒绝，避免被一个大长度前缀拖住内存。
- agent 崩溃后由手动/服务管理器重启；正在进行的打洞靠内核既有重试恢复，房间身份文件路径不变。

## 6. 测试

- `cargo test -p wgp-ipc`：帧编解码、未知主/次版本、未知命令、队列容量、UDS 同 UID 校验、SDDL 解析等。
- `cargo test -p wgp-agent`：入参解析、端口规则语法（与 `wgp-client` 同语法）、身份策略映射。
- `scripts/agent-smoke.ps1`（Windows）/ `scripts/agent-smoke.sh`（Linux）：真实进程 + 真实端点，端到端验证 IPC 与优雅退出。
