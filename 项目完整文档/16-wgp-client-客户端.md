# wgp-client 客户端详细文档

> 源目录：`client/wgp-client/`（crate 名 `wgp-client`，workspace 成员）
> 生成日期：2026-11-05
> 定位：**参考外围，非产品**（14 文档的"参考外围"：仅参数装配 + 事件呈现，不含任何协议实现）

## 1. 概览

- 单文件 CLI：全部逻辑在 `src/main.rs`（524 行，含 4 个单元测试）；`Cargo.toml` 显式声明唯一二进制 `wgp-client`（path = `src/main.rs`）。
- 职责边界（main.rs:3-5，00 §3 内核纯粹性）：外围只做两件事——**参数装配 + 事件呈现**；一切网络语义（信令/入表/打洞/保活）都在内核，本进程不含任何协议实现。
- 内核不持有任何部署地址：种子端点必须由本外围经 `--seed` 或 `WGP_SEED` 注入（main.rs:5、481）。
- 依赖（Cargo.toml:13-17）：`wgp-core`（默认特性，即 `client` 全量：打洞/信令/密钥导出/载体，`kernel/wgp-core/Cargo.toml:10-11`）、`wgp-dht`、`wgp-proto`、`rand_core`、`tokio`。
- 直接调用的内核 API：`measure_seeds`、`peer_id_from_node`、`resolve_endpoint`、`LinkSink`、`Engine`、`EngineEvent`、`LinkLossCause`、`PeerId`、`PunchedLink`、`RoomCode`、`SessionOrchestrator`、`SeedPick`（wgp-core）；`DhtNode`、`NodeId`、`NodeIdentity`、`RoomRuntime`（wgp-dht）；`derive_room_code`（wgp-proto）；`SeedEndpoint`、`SeedScheme`（wgp-proto）。
- 异步运行时：不走 `#[tokio::main]`，而是在 `run_room` 内手动 `Builder::new_multi_thread().enable_all().build()` 后 `block_on`（main.rs:203-207）。

### 1.1 子命令总表（run，main.rs:49-68）

| 命令 | 别名 | 参数 | 行为 |
| --- | --- | --- | --- |
| `code` | `码` | `<房间名> <房间密钥>`（或 `--name`/`--key`） | 离线派生房间码（无网络），打印结果 |
| `开房` | `host`、`create` | 位置1=房间名（缺省 `"wgp"`）、位置2=密钥（缺省随机 16 位hex） | 创建房间（第一人 = 房主 + 锚点） |
| `join` | `加入` | 位置1=`U/房间码` | 加入房间（报道至锚点） |
| `help` | `-h`、`--help`、`帮助` | — | 打印帮助 |
| `version` | `-V`、`--version`、`版本` | — | 打印 `wgp-client {VERSION}`（`CARGO_PKG_VERSION`） |
| 其他 | — | — | 报错 `未知命令 \`{other}\`（用 \`--help\` 查看用法）`，退出码 1 |

无参数时打印帮助并正常退出（main.rs:50-53）。全局错误出口：`eprintln!("错误：{msg}")` + `ExitCode::FAILURE`（main.rs:41-45）。

## 2. `main.rs` 逐段详细文档

### 2.1 常量（main.rs:34-36）

| 常量 | 值 | 用途 |
| --- | --- | --- |
| `DEFAULT_IDENTITY_FILE` | `"wgp-client.key"` | 默认身份文件 |
| `IDENTITY_LEN` | `32` | 身份种子字节数 |
| `VERSION` | `env!("CARGO_PKG_VERSION")` | 版本串 |

### 2.2 参数解析（零依赖手写，parse_opts，main.rs:86-118）

与 wgp-node 后端同一套 `--flag` 约定（main.rs:71 注释）。选项表：

| 选项 | 短选项 | 取值 | 默认 | 说明 |
| --- | --- | --- | --- | --- |
| `--name` | `-n` | String | 无 | 房间名 |
| `--key` | `-k` | String | 无 | 房间密钥 |
| `--seed` | `-s` | String | 无（回落 `WGP_SEED`） | 种子端点列表 |
| `--storage` | — | String | 无 | 显式房间键存储节点 |
| `--observer` | — | String | 无 | 观察者/STUN 端点列表 |
| `--identity` | `-i` | PathBuf | `wgp-client.key` | 身份文件路径 |
| `--once` | — | flag | false | 入表后立即退出 |

解析规则：

- 取值型选项消费下一个 token；越界报错 `选项 {flag} 需要一个值`（main.rs:92-97，测试 `missing_value_rejected`）。
- `-h`/`--help` 在解析层直接打印帮助并 `exit(0)`（main.rs:106-109）。
- 以 `--` 开头且不在表中的选项报错 `未知选项 \`{other}\``（main.rs:110-112，测试 `unknown_flag_rejected`）。
- 其余 token 一律进入 `positional`（main.rs:113）。
- **不支持 `--flag=value` 形式**（与 wgp-node 不同；`--seed=x` 会落入"未知选项"报错；代码如此）。
- 短选项只识别 `-n/-k/-s/-i/-h`；其他单横杠 token 落入 positional（代码如此）。
- 测试 `parse_opts_collects_flags_and_positionals` 覆盖 flag 与位置参数混合收集。

### 2.3 `code` 子命令（cmd_code，main.rs:125-139）

房间名/密钥优先取 `--name`/`--key`，缺省取 positional[0]/[1]；再缺则分别报错 `缺少房间名：code <房间名> <房间密钥>` / `缺少房间密钥：code <房间名> <房间密钥>`。输出只有一行：`derive_room_code(&name, &key)` 的结果（wgp-proto 的 13 文档唯一权威实现）。测试向量（main.rs:518-522）：`derive_room_code("示例房间", "123456") == "U/C2G9-GYET-311W-R636"`。

### 2.4 `开房` 子命令（cmd_host，main.rs:142-161）

- 房间名：`--name` > positional[0] > 缺省 `"wgp"`（main.rs:147-148）。
- 房间密钥：`--key` > positional[1] > `random_hex16()`（OsRng 生成 8 字节转 16 位十六进制，main.rs:153、425-430）。
- 依次打印四行（main.rs:156-159）：

```
房间名  : {name}
房间密钥: {key}
房间码  : {code}
—— 把「房间码」分享给同伴，对方执行 `wgp-client join {code}` 即可加入 ——
```

随后进入 `run_room(&code, opts)`。

### 2.5 `join` 子命令（cmd_join，main.rs:164-173）

房间码取 positional[0]，缺省报错 `缺少房间码：join <U/房间码>`；打印 `房间码  : {code}` 后进入 `run_room`。

### 2.6 种子配置（run_room，main.rs:179-208）

- 种子串优先级：`--seed` > 环境变量 `WGP_SEED` > 空串（main.rs:180-184）。
- `SeedEndpoint::parse_list(&seed_str)` 解析列表：逗号/分号/空白分隔；形如 `udp://host:port` 或 `tcp://host:port`（main.rs:13-14、185）。
- 非法端点逐条警告到 stderr：`[warn] 忽略非法种子端点：{b}`（main.rs:186-188）。
- **种子为空且未指定 `--storage` 时拒绝启动**（main.rs:189-195）：
  `未提供可用种子端点。请用 \`--seed udp://host:port[,tcp://host:port]\` 或环境变量 WGP_SEED 注入（内核不内置任何部署地址）`
- 身份文件加载（见 2.9）后构建 tokio 多线程运行时并 `block_on(async_move(...))`。

### 2.7 房间会话装配（async_move，main.rs:210-296）

按代码顺序：

1. **本进程 DHT 节点**：`DhtNode::bind(identity, "0.0.0.0:0")` 绑定随机端口（main.rs:217-219）；失败报错 `DHT 绑定失败：{e}`。
2. **种子测速**：`measure_seeds(&node, &endpoints)`（endpoints 为空则跳过，main.rs:222-226）。每个结果打印（main.rs:227-229）：
   `[种子] {endpoint.display()} → {addr}  往返 {rtt:?}`
   全部不可达时 stderr 警告（main.rs:230-232）：`[warn] 全部种子端点不可达（继续尝试显式 --storage）`。
3. **房间键存储节点**（resolve_storage，main.rs:299-314）：
   - 显式 `--storage` 优先：`SeedEndpoint::parse` 失败报 `--storage 解析失败：{e:?}`；`resolve_endpoint` 失败报 `--storage 无法解析为地址：{s}`。
   - 否则取第一个 `SeedScheme::Udp` 种子的 addr（v1 房间 RPC 走 UDP，main.rs:234 注释）。
   - 两者皆无报错：`无可用 UDP 种子端点：v1 房间键存储走 UDP RPC，请提供 \`--seed udp://host:port\``。
   - 打印 `[存储] 房间键存储节点 = {storage}`。
   - 预热：`node.ping(storage)`，失败不致命（`let _ =`，main.rs:238-239）。
4. **装配内核**：`Engine::new()` → `(engine, _rx)`（事件接收端丢弃，后文用 `engine.subscribe()`）；`engine.attach_dht(node.clone(), storage).await`（main.rs:242-243）。
5. **入表**：`engine.join_room(RoomCode(code.clone()), None).await`（main.rs:245-248；第二参数固定传 `None`，代码如此，语义待确认）；失败报 `加入房间失败：{e:?}`。成功打印：
   `[房间] 已入表，当前成员数 = {handle.members}`
6. **观察者装配**（main.rs:254）：`parse_observers(opts.observer)`——按 `,`/`;`/空白分割，逐项 `parse::<SocketAddr>()`，**非法项被静默丢弃**（filter_map，main.rs:316-324）。注释说明（main.rs:252-253）：观察者缺省为空则跳过 NAT 探测，由引擎按 T1-T4 判定自动降级到 TCP 兜底——不让用户为打洞必须配齐 STUN。
7. **TCP 兜底种子**：`picks` 中第一个 `SeedScheme::Tcp` 种子的 addr（main.rs:255-258）。
8. **会话编排器**：`SessionOrchestrator::new(node, engine, storage, observers).with_tcp_fallback(tcp_seed)`，包 `Arc`（main.rs:259-262）。
9. **成员感知 + 自动打洞**：spawn `member_watch(node, storage, code, my_id, orch)`（main.rs:264-270；mesh 每对端一次协商竞速，main.rs:251 注释）。
10. **`--once`**：`handle.leave()` 后立即返回（main.rs:272-275）。
11. **驻留事件循环**（main.rs:277-295）：先打印
    `[房间] 驻留中——打印链路/房间事件；按 Ctrl+C 退出`
    然后 `engine.subscribe()`，`tokio::select!` 两路：
    - `ctrl_c()` → 打印 `\n[房间] 收到退出信号，正在清理…` 并 break；
    - `events.recv()` → `Ok(e)` 交 `render` 打印；`Lagged(n)` → stderr `[warn] 事件处理滞后，丢弃 {n} 条`；`Closed` → break。
    循环结束后 `handle.leave()`。

### 2.8 成员感知 + 自动打洞（member_watch，main.rs:328-365）

- 每 **2 秒**（`Duration::from_secs(2)`）循环：`RoomRuntime::new(node, storage).fetch(&code)`，失败 `continue`。
- 对房间记录中每个成员：跳过自己（`id == my_id`）与已发起过的（`launched` 集合）；否则标记后 spawn `orch.connect_peer(&code, id, sink)`，sink 为 `SilentSink`。
- 结果打印（main.rs:352-361）：
  - 成功：`[链路] 协商完成，竞速已启动 peer={hex(peer_id_from_node(&id))}`
  - 失败：stderr `[链路] peer={hex} 协商失败：{e:?}（链路重试由引擎自持）`
- 注释纪律（main.rs:326-327）：失败仅记录不重试（遵守预算纪律）；链路丢/挂后的重打由引擎自持。

### 2.9 身份文件（load_or_create_identity，main.rs:434-459）

- 默认路径 `wgp-client.key`，可用 `--identity/-i` 覆盖（main.rs:197-200）。
- 文件存在：长度必须为 32 字节，否则拒绝：`身份文件 {path} 长度非法（期望 32B，实得 {n}B）`（宁可人工确认，也不静默换身份；07 §8 身份漂移 = DHT 键散乱 + 日蚀风险）。
- 文件不存在：`NodeIdentity::generate(&mut OsRng)` 生成并 `fs::write(path, id.to_seed())`，打印：
  `[身份] 已生成新身份并持久化于 {path}`
- 其他读取错误：`读取身份文件 {path} 失败：{e}`。
- 注意：客户端是直接 `fs::write` 落盘，**无** wgp-node 那样的"临时文件 + rename + chmod 600"原子写（与 server.rs:447-463 不同；代码如此）。

### 2.10 事件订阅与打印（render，main.rs:376-410）

`render(&EngineEvent)` 全量映射（`hex()` 为小写十六进制，main.rs:416-422）：

| EngineEvent | 输出（stdout） |
| --- | --- |
| `PunchingStarted { peer }` | `[链路] 开始打洞 peer={hex}` |
| `LinkYielded { peer, rank }` | `[链路] 已打通 peer={hex} 档位={rank:?}` |
| `LinkUpgraded { peer, from, to }` | `[链路] 升级 peer={hex} {from:?} → {to:?}` |
| `LinkLost { peer, cause }` | `[链路] 丢失 peer={hex} 原因={cause:?}` |
| `RePunching { peer, reason }` | `[链路] 重打洞 peer={hex} 原因={reason:?}` |
| `DeadEnd { peer, diagnosis }` | `[链路] 判死局 peer={hex} 评分={score} NAT={nat_type} 防火墙={firewalled} UDP封禁={udp_blocked} CGNAT={cgnat}` |
| `RoomAnchorChanged { epoch, anchor, reason }` | `[房间] 锚点变更 epoch={epoch} 新锚点={hex} 原因={reason:?}` |
| `RoomJoined { members, .. }` | `[房间] 成员表就绪，成员数={members}` |
| `RoomJoinFailed { reason, .. }` | `[房间] 入表失败 原因={reason:?}` |
| `BudgetExhausted { .. }` | `[预算] 发包窗口耗尽，等待下一窗口` |
| `KeepaliveSuspended { peer }` | `[保活] 自动降频 peer={hex}` |
| 其他事件 | 静默（`_ => {}`） |

`SilentSink`（main.rs:368-374）：`LinkSink` 三回调（`on_link_yielded`/`on_link_upgraded`/`on_link_lost`）全部空实现——链路事件已由引擎广播经 render 打印，静默防重复（main.rs:367 注释）。

### 2.11 帮助文本（print_help，main.rs:461-488，原文）

```
折跃门客户端 v{VERSION}（14 文档的参考外围：仅装配 + 呈现，无协议实现）

用法：
  wgp-client code <房间名> <房间密钥>              离线派生房间码
  wgp-client 开房 [--name N] [--key K] [选项]      创建房间（房主 + 锚点）
  wgp-client join <U/房间码> [选项]                加入房间

选项：
  -s, --seed <list>      种子端点（逗号/分号/空白分隔）
                         udp://host:port 或 tcp://host:port
  --storage <ep>         显式房间键存储节点（默认取最快 UDP 种子）
  --observer <list>      观察者/STUN 端点，逗号分隔 ip:port（缺省跳过 NAT 探测，自动降级 TCP 兜底）
  -i, --identity <path>  身份文件（默认 wgp-client.key）
  --once                 入表后立即退出（默认驻留并打印事件）
  -h, --help             显示本帮助
  -V, --version          显示版本

环境变量：
  WGP_SEED               种子端点列表（等价 --seed；内核不内置任何地址）

示例：
  wgp-client code 示例房间 123456
  wgp-client 开房 --name 示例房间 --key 123456 --seed udp://轻松.躺进.icu:11010
  wgp-client join U/C2G9-GYET-311W-R636 --seed udp://轻松.躺进.icu:11010
```

（示例中的域名 `轻松.躺进.icu:11010` 为源码帮助文本原样，非本文档虚构。）

### 2.12 测试用例列表（main.rs:490-523，共 4 个）

| 测试名 | 断言要点 |
| --- | --- |
| `parse_opts_collects_flags_and_positionals` | flag 与位置参数混合解析 |
| `unknown_flag_rejected` | `--nope` 报错 |
| `missing_value_rejected` | `--seed` 越界报错 |
| `code_subcommand_matches_doc13_vector` | `derive_room_code("示例房间","123456") == "U/C2G9-GYET-311W-R636"`（13 文档测试向量） |

## 3. 使用示例（均由代码推导，真实可用）

```bash
# 离线派生房间码（无网络；输出 U/C2G9-GYET-311W-R636）
wgp-client code 示例房间 123456

# 开房：显式种子（帮助文本原文示例）
wgp-client 开房 --name 示例房间 --key 123456 --seed udp://轻松.躺进.icu:11010

# 加入：拿房主分享的房间码（帮助文本原文示例）
wgp-client join U/C2G9-GYET-311W-R636 --seed udp://轻松.躺进.icu:11010

# 种子走环境变量（等价 --seed）
WGP_SEED=udp://host:11010,tcp://host:3481 wgp-client 开房

# 开房但不指定密钥（自动生成 16 位随机 hex）
wgp-client 开房 --name 我的房间 --seed udp://host:11010

# 一次性模式：入表后立即退出
wgp-client 开房 --name R --key K --seed udp://host:11010 --once

# 无任何种子、仅显式存储节点 + 观察者
wgp-client 开房 --name R --key K --storage udp://host:11010 --observer 1.2.3.4:3478,5.6.7.8:3478

# 自定义身份文件
wgp-client join U/XXXX-XXXX-XXXX-XXXX --seed udp://host:11010 -i my.key
```

## 4. 与设计文档对应关系

| 设计文档 | 对应代码 |
| --- | --- |
| `docs/14-内核API文档.md` | "参考外围"定位（main.rs:1-5、463）；Engine / EngineEvent / SessionOrchestrator / measure_seeds / resolve_endpoint / LinkSink 等 API 装配（main.rs:26-29、242-262） |
| `docs/13-房间码派生协议.md` | `code` 子命令 = `wgp_proto::room_code::derive_room_code`（main.rs:31、124、137）；测试向量 `U/C2G9-GYET-311W-R636`（main.rs:518-522） |
| `docs/15-全链路流程.md` | 入表 → 成员感知 → 协商竞速 → 打洞/保活事件流（async_move、member_watch、render 全表） |
| `docs/16-怎么做与下一步.md` | 客户端启动命令与环境变量 `WGP_SEED`（main.rs:481） |
| `docs/00-架构总览.md` §3 | 外围只做参数装配 + 事件呈现，无协议实现（main.rs:3-5） |
| `docs/07` §8 | 身份文件 32B 校验、拒绝静默换身份（main.rs:432-433） |

## 5. 已知限制或未实现项

- **无 QUIC 数据面**：代码只到"入表 + 链路协商/竞速 + 事件打印"，没有任何数据隧道、TUN 网卡或报文转发逻辑；`SilentSink` 直接丢弃链路交付物（main.rs:368-374）。打通链路后如何传数据不在本进程内。
- **无界面**：纯 CLI 文本输出，无 TUI/GUI。
- 不支持 `--flag=value` 形式（与 wgp-node 的解析器不同；`--seed=x` 报"未知选项"；代码如此）。
- `--observer` 列表中的非法端点被静默丢弃，无警告（与 `--seed` 的 `[warn]` 提示不同；代码如此）。
- 身份文件写入为非原子 `fs::write`，无临时文件 + rename、无 chmod 600（server 端有；代码如此）。
- 广播事件通道 `Lagged` 时丢弃事件并打 warn（main.rs:287-289），不补放。
- `member_watch` 对每个远端成员只发起**一次**协商，失败不重试；重打洞由引擎自持（main.rs:326-327）。
- `engine.join_room(RoomCode(code), None)` 第二参数恒为 `None`（代码如此，语义待确认）。
- 无配置文件支持（与 wgp-node 的 `wgp-node.conf` 机制不同）；唯一环境变量是 `WGP_SEED`。
- 种子为空时唯一豁免是显式 `--storage`；且 `--storage` 也要求最终能解析出地址（main.rs:189-195、299-314）。
- 帮助/版本拦截只在 `run()` 顶层；`parse_opts` 内仅识别 `-n/-k/-s/-i/-h`，其余单横杠参数落入 positional（代码如此）。
