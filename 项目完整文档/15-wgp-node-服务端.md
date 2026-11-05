# wgp-node 服务端详细文档

> 源目录：`server/wgp-node/`（crate 名 `wgp-node`，workspace 成员）
> 生成日期：2026-11-05
> 对应设计文档：`docs/07-信令面与观察者协议.md` §6/§7（部署规格）、`server/deploy/DEPLOY.md`（部署手册）

## 1. 概览

- 同一套服务端逻辑编译出**两个二进制**（lib.rs:3-7）：
  - `wgp-node`：静态 IP 完整版，部署于公网固定地址，**允许** Forward 中转（承担最坏情况下的承诺投递兜底）。
  - `wgp-node-hobby`：家庭宽带贡献版，**强制拒绝** Forward 中转（PCDN 防护，07 §7）。
- 二者共享 `src/server.rs` 的全部启动/身份/参数解析逻辑，仅入口传给 `server::run()` 的 `force_hobby` 实参不同：完整版 `false`（main.rs:21），贡献版恒 `true`（bin/wgp-node-hobby.rs:21）。
- 单进程四职（lib.rs:3、server.rs:3）：**DHT 种子 / 观察者 / STUN 响应器 / 承诺转发兜底**。
- 无状态、无数据库；日志仅记录生命周期与错误，不记会话内容（server.rs:4）。
- 身份持久化于 `node_identity.key`（首启生成，重启复用；防身份漂移 07 §8）。
- feature 裁剪（Cargo.toml:9）：`wgp-core = { default-features = false, features = ["node"] }`，即只编译服务端四职（DHT/观察者/STUN/兜底转发），剔除 client 全量引入的打洞/加密可选依赖（`kernel/wgp-core/Cargo.toml:10-12`：`client = ["dep:wgp-punch", "dep:wgp-crypto", "dep:rand_core", "dep:sha2"]`，`node = []`）。
- 部署数据（bind/stun/tcp 等）一律由本层注入内核，内核不持有任何部署常量（00 §3，server.rs:10）。

## 2. 模块结构总表

| 文件 | 行数 | 职责 |
| --- | --- | --- |
| `src/lib.rs` | 10 | crate 门面：`pub mod server;` + 模块文档（双形态说明） |
| `src/main.rs` | 22 | `wgp-node` 完整版入口：`#[tokio::main]` → `server::run("wgp-node", false)` |
| `src/server.rs` | 756 | 共享启动逻辑：零依赖日志、四层配置解析、身份持久化、运行与退出信号；含 14 个单元测试 |
| `src/bin/wgp-node-hobby.rs` | 22 | `wgp-node-hobby` 贡献版入口：`server::run("wgp-node-hobby", true)` |
| `Cargo.toml` | 12 | 依赖：`wgp-core`（node 特性）、`wgp-dht`、`rand_core`、`tokio` |

二进制名由 Cargo 自动发现：`src/main.rs` → `wgp-node`；`src/bin/wgp-node-hobby.rs` → `wgp-node-hobby`（Cargo.toml 未显式声明 `[[bin]]`）。

## 3. 逐文件详细文档

### 3.1 `src/lib.rs`（10 行）

仅一行代码 `pub mod server;`（lib.rs:9），其余为模块文档：说明同一套四职逻辑编译出两个二进制、二者仅默认姿态不同（lib.rs:7）。

### 3.2 `src/main.rs`（22 行）

`wgp-node`（静态 IP 完整版）入口。文档注释给出用法摘要与三条示例（main.rs:8-14）：

```
wgp-node                                   （默认 0.0.0.0:11010 + 3478 + 3481）
wgp-node --tcp none                        （关闭 TCP 信令面）
wgp-node --stun none --tcp none            （仅 DHT 种子）
```

代码本体仅 `#[tokio::main] async fn main() { server::run("wgp-node", false).await; }`（main.rs:19-22）。

### 3.3 `src/server.rs`（756 行，核心文件）

#### 3.3.1 内置常量（server.rs:22-33）

| 常量 | 值 | 用途 |
| --- | --- | --- |
| `DEFAULT_BIND` | `"0.0.0.0:11010"` | 默认 DHT 信令 UDP 绑定地址 |
| `DEFAULT_STUN_PORT` | `3478` | 默认 STUN/观察者端口 |
| `DEFAULT_TCP_PORT` | `3481` | 默认 TCP 信令兜底端口 |
| `IDENTITY_FILE` | `"node_identity.key"` | 默认身份持久化文件名 |
| `DEFAULT_CONFIG_FILE` | `"wgp-node.conf"` | 默认配置文件（存在即自动加载） |
| `ENV_PREFIX` | `"WGP_"` | 环境变量前缀 |

#### 3.3.2 日志（零依赖，server.rs:39-100）

- 级别枚举 `LogLevel`：`Error=0 / Warn=1 / Info=2 / Debug=3`（数值越大越详细），全局默认 `Info`（server.rs:69）。
- `LogLevel::parse` 接受的写法（server.rs:50-56）：`error`/`err`、`warn`/`warning`、`info`、`debug`/`trace`；其余报错。
- 输出格式：`[ERROR] msg` / `[WARN] msg` / `[INFO] msg` / `[DEBUG] msg`（server.rs:79）。
- 分流：warn/error 走 stderr（无缓冲）；info/debug 走 stdout 并立即 flush（server.rs:81-86）。
- 设计注释：systemd/journald 负责采集，时间戳由采集端补全（server.rs:36）。

#### 3.3.3 CLI 参数全表（server.rs:391-414 usage 文本 + resolve_opts 实现）

| 参数 | 取值 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--bind <addr>` | `IP:端口` | `0.0.0.0:11010` | DHT UDP 绑定地址；非法的报错 `bind 非法（应为 IP:端口，如 0.0.0.0:11010）：{bind}` |
| `--stun <port\|none>` | 1-65535 或 `none` | `3478` | 观察者/STUN 端口；`none` 关闭 |
| `--tcp <port\|none>` | 1-65535 或 `none` | `3481` | TCP 信令兜底端口；`none` 关闭 |
| `--hobby` / `--no-hobby` | 布尔 flag（无需取值） | `false` | 贡献模式：拒绝 Forward 中转（PCDN 防护） |
| `--observer-rate-limit <n>` | u32，≥1 | `12`（取 `wgp_dht::OBSERVER_RATE_LIMIT`） | 观察者每 IP 每窗口响应上限；0 报错 |
| `--observer-rate-window <secs>` | u64 秒，≥1 | `10`（取 `wgp_dht::OBSERVER_RATE_WINDOW.as_secs()`） | 观察者限频窗口秒数；0 报错 |
| `--identity <path>` | 文件路径 | `node_identity.key` | 节点身份文件 |
| `--config <path>` | 文件路径 | 存在即自动加载 `wgp-node.conf` | 配置文件（`key = value`） |
| `--log-level <level>` | `error`/`warn`/`info`/`debug`（含 err/warning/trace 别名） | `info` | 日志级别 |
| `-h` / `--help` / `help` | — | — | 打印 usage 后正常返回（退出码 0） |
| `-V` / `--version` | — | — | 打印 `{profile} {CARGO_PKG_VERSION}` |

解析细则（resolve_opts，server.rs:204-319）：

- 支持 `--flag=value` 形式（`split_once('=')`，server.rs:217），如 `--bind=0.0.0.0:12000`、`--stun=none`。
- 布尔 flag 集合 `BOOL_FLAGS = ["hobby", "no_hobby", "help", "version"]`（server.rs:201）：出现时不消费下一个 token，值记 `true`。
- `--no-hobby` 归一为 `hobby=false`（server.rs:234-237）。
- 键名统一归一：小写 + `-`→`_`（server.rs:232），故 `--observer-rate-limit` 与 `--observer_rate_limit` 等价。
- 端口关闭词（parse_port，server.rs:178-187）：空串、`none`、`off`、`disable`、`disabled` 均解析为 `None`。
- 位置参数向后兼容（server.rs:249-252）：第一个不以 `-` 开头的参数，在 `bind` 尚未被任何来源设置时视作 bind；之后的位置参数因 `m.entry().or_insert()` 语义被静默忽略（有测试 `positional_bind_is_backward_compatible`）。
- 未知短选项（`-h`/`-V` 之外）报错 `未知选项：{arg}`（server.rs:247）。
- `run()` 层先行拦截 help/version 并返回（server.rs:500-507），因此 `resolve_opts` 内的 help/version 布尔分支实际只被单元测试与直接调用触及（代码如此）。
- 取值型选项越界报错 `--{k} 缺少参数值`（server.rs:226）。

#### 3.3.4 配置键全表（配置文件 / 环境变量 / 命令行共用同一套键）

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `bind` | SocketAddr 字符串 | `0.0.0.0:11010` | DHT UDP 绑定地址 |
| `stun` | 端口或 none | `3478` | 观察者/STUN 端口 |
| `tcp` | 端口或 none | `3481` | TCP 信令端口 |
| `hobby` | 布尔 | `false` | 贡献模式（贡献版二进制恒 true） |
| `observer_rate_limit` | u32 | `12` | 观察者每 IP 每窗口响应上限 |
| `observer_rate_window` | u64 秒 | `10` | 观察者限频窗口 |
| `identity` | 路径 | `node_identity.key` | 身份文件路径 |
| `log_level` | 枚举 | `info` | 日志级别 |

布尔值写法（parse_bool，server.rs:170-176）：`1`/`true`/`yes`/`on` 为真，`0`/`false`/`no`/`off` 为假，其余报错。

#### 3.3.5 环境变量全表（collect_env，server.rs:340-359；前缀 `WGP_`）

| 环境变量 | 对应键 | 说明 |
| --- | --- | --- |
| `WGP_BIND` | `bind` | 同 `--bind` |
| `WGP_STUN` | `stun` | 同 `--stun` |
| `WGP_TCP` | `tcp` | 同 `--tcp` |
| `WGP_HOBBY` | `hobby` | 布尔；贡献版恒 true 无需设置（DEPLOY.md:159） |
| `WGP_OBSERVER_RATE_LIMIT` | `observer_rate_limit` | u32 |
| `WGP_OBSERVER_RATE_WINDOW` | `observer_rate_window` | u64 秒 |
| `WGP_IDENTITY` | `identity` | 身份文件路径 |
| `WGP_LOG_LEVEL` | `log_level` | 日志级别 |
| `WGP_CONFIG` | `config` | 仅用于定位配置文件（find_config_path，server.rs:332）；该键不参与 resolve_opts 的合并 |

#### 3.3.6 优先级（server.rs:8-9、203-238）

**命令行 > 环境变量 > 配置文件 > 内置默认值**。`resolve_opts` 是纯函数：先把 `input.file` 全量 insert 进 `HashMap`，再 insert `input.env` 覆盖，最后逐条解析 argv 覆盖（server.rs:206-238）。有测试 `precedence_cli_over_env_over_file` 验证三层覆盖。

#### 3.3.7 配置文件格式（parse_config_text，server.rs:150-168）

- 每行 `key = value`；缺少 `=` 报错 `配置文件第 {n} 行缺少 '='：{原文}`；键名为空报错。
- `#` 和 `;` 均为注释符，行内注释亦可（`raw.split(['#',';']).next()`，server.rs:153）；空行跳过。
- 键名小写归一、`-`→`_`；值 `trim()`。
- 定位顺序（find_config_path，server.rs:322-338）：`--config <path>` 或 `--config=<path>` > `WGP_CONFIG` > 默认 `wgp-node.conf`（当前工作目录下存在才加载）。
- 配置文件读取/解析失败均为致命错误，向上冒泡为 `配置错误` 退出（exit 2）。

#### 3.3.8 身份加载/生成（server.rs:420-463）

- `load_or_create_identity(path)`：读取身份文件；长度必须为 **32 字节**。
- 文件存在但长度非法 → **拒绝启动**（Err：`身份文件 {path} 长度非法（{n} 字节，应为 32）。为避免身份漂移，请人工确认后删除该文件再重启`；`run()` 中以此 exit(3)）。理由（07 §8）：身份漂移 = DHT 键散乱 + 日蚀风险。
- 文件不存在 → `NodeIdentity::generate(&mut OsRng)` 生成，`persist_identity` 落盘。
- `persist_identity`（server.rs:447-463）：先写临时文件（`<name>.tmp` 或同名换扩展名 `.tmp`），Unix 下 `chmod 600`，再 `rename` 原子替换；rename 失败则清理临时文件并报错。

#### 3.3.9 启动流程（`server::run`，server.rs:497-597）

1. 收集 `argv`（跳过 argv[0]）。
2. 若含 `-h`/`--help`/`help` → 打印 `usage(profile)` 后返回；若含 `-V`/`--version` → 打印 `{profile} {版本}` 后返回。
3. `parse_args(force_hobby, &argv)`：失败时向 stderr 打两行——`[{profile}] 配置错误：{e}` 与 `[{profile}] 运行 \`{profile} --help\` 查看用法。`，随后 `exit(2)`。
4. `set_log_level(opts.log_level)`。
5. `load_or_create_identity(&opts.identity_file)`：失败打 `[{profile}] 身份初始化失败：{e}`，`exit(3)`；取 `node_id = identity.node_id()`。
6. 启动日志（INFO，server.rs:529-538）：
   `{profile} 启动中 | bind={} | stun={} | tcp={} | 模式={} | 观察者限频={}/{}s | 身份={}`
   （stun/tcp 为 None 时显示 `off`；模式为 `贡献(PCDN防护)` 或 `完整`）。
7. `Engine::new()` 得到 `(engine, _events)`（事件接收端丢弃）。
8. 装配 `NodeConfig { role: NodeRole::Seed, bind, stun, tcp_signal, hobby, observer_policy }`（server.rs:541-548）；`observer_policy()` 把 `observer_rate_limit` + `observer_rate_window_secs` 转成 `ObserverPolicy { rate_limit, rate_window: Duration::from_secs(..) }`（server.rs:129-134）。
9. `engine.run_node(cfg, identity).await` 启动网络面：DHT（含承诺转发兜底）+ 观察者（STUN）+ TCP 信令兜底（server.rs:550-551）。
10. **绑定失败 = 致命**（服务端不允许"假装在线"降级空转，server.rs:553-574）：
    - `node.dht.is_none()` → `[{profile}] 致命：DHT 绑定失败 {bind}（端口被占用或权限不足），进程退出`，exit(1)；
    - `stun.is_some() && node.observer.is_none()` → `致命：观察者绑定失败（端口 {:?}），进程退出`，exit(1)；
    - `tcp.is_some() && node.tcp.is_none()` → `致命：TCP 信令绑定失败（端口 {:?}），进程退出`，exit(1)。
11. 就绪日志（INFO，server.rs:590-593）：
    `{profile} 已就绪（种子+观察者+承诺兜底）| node_id={:02x?} | DHT bind={} | STUN=:{} | TCP=:{} | {}`
    - `node_id` 只打印前 4 字节（`&node_id.0[..4]`）；
    - `STUN=:{port}` / `TCP=:{port}`，关闭时显示 `STUN=off` / `TCP=off`；
    - 末段为 `贡献模式：拒绝 Forward 中转（PCDN 防护）` 或 `完整模式：允许 Forward 中转`。
12. `wait_for_shutdown().await`：Unix 下 `tokio::select!` 同时等 SIGTERM（systemd 默认）与 SIGINT；非 Unix 平台仅 Ctrl-C（server.rs:470-493）。
13. 收到退出信号后打 INFO 日志 `{profile} 收到退出信号，关闭中。`（server.rs:596），进程结束。

#### 3.3.10 hobby 模式强制拒绝 Forward 中转的实现点

服务端层共三处，语义落地均通过注入内核完成：

1. `resolve_opts` 的 `force_hobby` 分支（server.rs:273-280）：`if force_hobby { true }`——贡献版二进制传入 `true`，此时 `--no-hobby`、配置文件、环境变量一律无法覆盖（测试 `hobby_flag_and_force_hobby` 断言 `force_hobby=true` 时即使传 `--no-hobby` 仍为 true）。
2. `NodeConfig.hobby` 字段注入内核（server.rs:546）。
3. 日志文案区分（server.rs:585-589）：`贡献模式：拒绝 Forward 中转（PCDN 防护）` vs `完整模式：允许 Forward 中转`。

（实际的 Forward 拒绝执行逻辑位于内核 crate，不在本目录 5 个文件内。）

#### 3.3.11 观察者限频默认值

- **12 次 / 10 秒 / IP**：默认值不硬编码在 server.rs，而是引用内核常量 `wgp_dht::OBSERVER_RATE_LIMIT = 12` 与 `wgp_dht::OBSERVER_RATE_WINDOW = Duration::from_secs(10)`（`kernel/wgp-dht/src/observe.rs:16-17`；server.rs:284、291 引用）。
- usage 帮助文本动态打印这两个默认值（server.rs:400-401、411-412）。
- 取值校验：`observer_rate_limit == 0` 报错 `observer_rate_limit 必须 >= 1（0 会关闭观察者应答）`；`observer_rate_window_secs == 0` 报错 `observer_rate_window 必须 >= 1 秒`（server.rs:286-295）。
- 部署示例 `server/deploy/wgp-node.env.example:28-29` 亦为 `WGP_OBSERVER_RATE_LIMIT=12` / `WGP_OBSERVER_RATE_WINDOW=10`。

#### 3.3.12 测试用例列表（server.rs:599-755，共 14 个）

| 测试名 | 断言要点 |
| --- | --- |
| `defaults_are_seed_full_profile` | 默认即完整版：bind/stun/tcp/限频/身份文件/日志级别默认值 |
| `precedence_cli_over_env_over_file` | 命令行 > 环境变量 > 配置文件 |
| `flag_equals_form_and_none_ports` | `--flag=value` 形式；`--stun=none`、`--tcp off` 均关闭 |
| `hobby_flag_and_force_hobby` | `--hobby` 真、`--no-hobby` 假；force_hobby 恒真不可覆盖 |
| `invalid_bind_is_rejected` | 非法 bind 报错含 "bind 非法" |
| `invalid_port_is_rejected_not_silently_defaulted` | 端口非法（70000/abc）报错含 "端口非法"，不静默回落默认 |
| `zero_rate_limit_rejected` | 限频/窗口为 0 均报错 |
| `observer_policy_is_injected` | `observer_policy()` 正确转 `ObserverPolicy`（30 次/5s） |
| `bad_bool_and_log_level_rejected` | 非法布尔、非法日志级别报错；debug 可解析 |
| `unknown_short_option_rejected` | `-x` 报错 |
| `positional_bind_is_backward_compatible` | 首个位置参数视作 bind |
| `config_text_parsing` | 注释/空行/键名归一；缺 `=` 报错 |
| `identity_roundtrip_and_corruption_detected` | 重启复用同一 node_id；长度非法拒绝启动 |
| `usage_mentions_env_and_precedence` | usage 含 `WGP_BIND` 与 "优先级" |

（`lib.rs`、`main.rs`、`bin/wgp-node-hobby.rs` 无测试。）

### 3.4 `src/bin/wgp-node-hobby.rs`（22 行）

`wgp-node-hobby`（家庭宽带贡献版）入口。文档注释说明（bin/wgp-node-hobby.rs:3-6）：

- 拒绝 Forward 中转（中转是唯一可能产生持续流量、进而被运营商判 PCDN 的路径）；
- 面向家庭宽带：默认同开 UDP 11010 与 TCP 3481，观测限速由观察者侧兜底；
- 默认绑定 0.0.0.0，端口映射由家庭路由器/光猫转发；
- **本形态 hobby 恒为真，`--no-hobby` 无效**（bin/wgp-node-hobby.rs:12）。

代码本体：`#[tokio::main] async fn main() { server::run("wgp-node-hobby", true).await; }`（bin/wgp-node-hobby.rs:19-22）。CLI/配置/环境变量与完整版完全相同（共用 server.rs）。

## 4. 与设计文档对应关系

| 设计文档 | 对应代码 |
| --- | --- |
| `docs/07-信令面与观察者协议.md` §6（部署规格） | lib.rs:1、server.rs:1、bin/wgp-node-hobby.rs:1 的模块头注释；四职启动（server.rs:550-551） |
| `docs/07` §7（贡献版/PCDN 防护） | force_hobby 恒真逻辑（server.rs:273-280）、bin/wgp-node-hobby.rs 全文 |
| `docs/07` §8（身份漂移） | `load_or_create_identity` 长度校验与拒绝启动（server.rs:420-444）、main.rs:15、bin/wgp-node-hobby.rs:15 |
| `docs/00-架构总览.md` §3（内核纯粹性） | 部署数据由 server 层注入 `NodeConfig`（server.rs:10、541-548） |
| `server/deploy/DEPLOY.md` | 环境变量键名与 `collect_env()` 一一对应（DEPLOY.md:159）；`server/deploy/wgp-node.env.example` 示例值 |
| `docs/16-怎么做与下一步.md` | 服务端环境变量键清单（docs/16:147） |

## 5. 已知限制或未实现项

- 无状态、无数据库、无会话内容记录（server.rs:4）；重启不恢复任何运行时状态（身份除外）。
- 日志零依赖：无时间戳、无结构化字段，依赖 systemd/journald 采集端补全（server.rs:36）。
- 配置文件为极简 `key = value`，无 section/无嵌套/无类型声明；默认只从当前工作目录自动加载 `wgp-node.conf`。
- 位置参数兼容仅覆盖"首个位置参数 = bind"；多余位置参数被静默忽略（server.rs:251，`or_insert` 语义；代码如此，意图待确认）。
- 布尔 flag 不消费取值：`--hobby true` 中的 `true` 会落入位置参数逻辑，若 bind 未设置则使 bind 非法而启动失败（代码如此，意图待确认）。
- `WGP_CONFIG` 只参与配置文件定位，不出现在 resolve_opts 的合并表中（server.rs:332-336）。
- hobby 拒绝 Forward 的实际执行在内核 crate，本目录只能看到"恒真 + 注入 + 日志"三处服务端侧实现点。
- 非 Unix 平台（如 Windows）不响应 SIGTERM，仅 Ctrl-C 可退出（server.rs:489-492）。
- 观察者限频默认值（12/10s）定义在内核 `wgp-dht`，服务端只引用不持有；改默认值需动内核常量。
