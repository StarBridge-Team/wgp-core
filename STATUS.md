# 折跃门 wgp · 拼装与验证记录

> 生成于 2026-11-07，由本次会话把 `C:\Users\DogerWindows\Downloads\` 下的散落代码拼成完整 workspace。
> 原始文件未改动（Downloads 保持原样），此处为**拷贝 + 补齐缺件 + 实测**。

## 1. 来源与补齐

| 项 | 状态 |
|---|---|
| `kernel/`（wgp-proto、crypto、punch、dht、core） | 从 Downloads 原样拷贝 |
| `server/`（wgp-node 源码 + deploy 11 件） | 原样拷贝 |
| `client/`（wgp-client） | 原样拷贝 |
| `docs/`（设计文档，现已并入 项目完整文档/） | 原样拷贝 |
| `项目完整文档/`（15 篇） | 原样拷贝 |
| `release-prebuilt/`（3 个预编译 exe） | 原样拷贝，作对照 |
| **根 `Cargo.toml`** | **原本缺失 → 按 `项目完整文档/01-工作区与构建.md` §2/§4 重建** |
| `Cargo.lock` | 首次构建时由 cargo 生成 |
| `nat/`（NAT 实测数据） | **已 11/11 补齐**：首轮从 `mc-link-core/docs/nat` 拿到 8 份，2026-11-07 由源码归档 `wgp-src.tar.gz` 补齐余下 3 份（美国 VPN 代理、香港 VPN 非宽带、深圳 netstat 快照） |
| `node_identity.key`、`wgp-src.tar.gz` | **未找到**，非源码，不影响构建 |

Downloads 里另有两个目录 `libcxx等10项文件`、`build-web等7项文件`（含 `c.zig`/`compiler_rt.zig`/`zig.h`），是 Zig 标准库文件，对应文档里提到的 `.tools/zig` 本地工具链，与本项目无关，未纳入。

## 2. 验证结果（本机实测）

| 项 | 结果 |
|---|---|
| `cargo check --workspace --all-targets` | 通过，**0 warning** |
| `cargo build --release --workspace` | 通过（LTO），39s，产出 3 个 exe |
| `cargo test --workspace` | **148 passed / 0 failed**（proto 36、dht 42、core 34、punch 14、node 14、crypto 4、client 4） |
| `wgp-node --help` | 正常，与 15 号文档参数表一致 |
| `wgp-node --bind bogus` | 配置校验生效，退出码 2 |
| `wgp-node` 实跑 | 打印就绪日志、生成 32B 身份文件，三端口起监听 |
| `wgp-client --help` | 正常，三子命令齐备 |
| `wgp-client code` 文档 13 的 4 个标准向量 | **4/4 全部命中** |

### 2.1 改动记录（唯一一处）

`kernel/wgp-dht/src/node.rs::kv_admit_overwrites_and_evicts_oldest`：
原测试用 `Instant::now() - Duration::from_secs(10_000)`，在**开机不足 10000s 的机器上**必然 panic
（`time.rs:445 overflow when subtracting duration from instant`）。改为 `checked_sub(...).unwrap_or(now)`，
语义不变、不再依赖开机时长。

## 3. 结论

代码与 `项目完整文档/` 描述一致：57 个 `.rs`、10,290 行、7 个 crate、编译干净、测试全绿。
文档中"92 个测试"的数字已过时，实际 148 个。

尚缺（详见下节）：数据面（QUIC / TLS-PSK 帧流 / 端口转发 / TAP）、真机双端联调、Linux 部署验证。

## 4. 版本历史（重建说明）

本仓库的 git 历史是**按快照重建**的，不是从原 `.git` 恢复（原仓库从未提交过）。三个提交各自对应一份真实证据，
提交日期取自文件真实 mtime 或文档标注日期：

| 提交 | 日期 | 依据 |
|---|---|---|
| `761226c` 内核五层 + wgp-node 骨架 | 2026-09-10 | `wgp-src.tar.gz` 归档快照（crates+apps 布局，80 文件，mtime 9/6–9/10） |
| `875a87b` 重构为 kernel/server/client | 2026-11-05 | 现行目录树 + `项目完整文档/`（文档标注整理日期 2026-11-05） |
| `f31d592` 仓库化 | 2026-11-07 | 本次拼装：根 `Cargo.toml`、nat 补齐、README/STATUS/忽略规则、测试修复 |

两次快照之间：32 个源文件逐字节相同，19 个改过，新增 6 个模块（`rank`/`orchestrator`/`servers`/`endpoint`/`punycode`/`room_code`）。

## 5. 2026-11-15 追加：路线图 M2–M5 的验证记录

本节只记「实际跑过什么」。做了什么、还有哪些问题见 [`HANDOFF.md`](HANDOFF.md)。全部是回环；Windows 与 WSL 在同一台开发机上，
原生 Linux 在一台云端虚拟机上（rustc 1.100）。

| 项 | 结果 |
|---|---|
| `cargo check --workspace --all-targets --locked` | 通过，0 warning |
| `cargo test --workspace` | **Windows 297 / Linux 296，0 failed**（proto 44、crypto 13、punch 21、dht 77、core 48、port 55、node 19、client 20；Linux 上 core 为 47，少的一个只在 Windows 编译） |
| wgp-core 整套测试并行重复运行 | Windows 30 遍、Linux 150 遍，0 失败 |
| `bridge/wgp-et-bridge`（独立 workspace） | 4 passed；验收用例连续 4 次通过 |
| `cargo check` 交叉目标 | `x86_64-unknown-linux-gnu`（--all-targets）与 `x86_64-unknown-linux-musl`（--bins）均 0 warning |
| Windows 端到端 `scripts\e2e-local.ps1` | 单种子、`-Discovery`（5 轮）、`-Discovery -Hobby` 全部 PASS；仅 hobby 种子（`-Hobby`）按预期 FAIL |
| Linux 端到端 `scripts/e2e-local.sh` | WSL2 Ubuntu 24.04（内核 6.6），`x86_64-unknown-linux-musl` 静态二进制：单种子、`--discovery`、`--discovery --hobby` 全部 PASS。云端原生 Linux（release 构建）：三种模式 PASS，`--discovery` 连跑 25 遍 0 失败 |
| 种子重启场景（云端原生 Linux，临时脚本，未入库） | 房主 + 成员建好隧道 → 杀掉种子、2 秒后重启 → 新成员在种子恢复 0～3 秒后加入：7 次全部连上房主并通过转发校验；老隧道全程可用 |
| 发版流程 Linux 部分的本地演练（云端 Ubuntu 24.04，按工作流里的命令原样执行） | 5 个 musl 目标全部构建成功（静态链接）；x86_64 / i686 原生运行、aarch64 / armv7 / loongarch64 经 QEMU 用户态仿真，版本输出、房间码标准向量、双种子端到端全部通过 |
| release 吞吐（经转发口往返） | Windows：8MiB，单向约 33 MiB/s；WSL：4MiB，单向约 18 MiB/s |
| 本机打包 `scripts\package.ps1` | 三个程序版本输出正常、13 文档房间码标准向量命中 |

端到端脚本校验的内容：种子就绪（发现模式下两个种子互相收录）→ 房主建房 → 加入方入表 →（发现模式：两端都学到两个种子、
选中同一个存储节点、自动选到观察者）→ 隧道就绪 → TCP 4MiB 往返逐字节一致 → UDP 40 个数据报一致 → 杀掉加入方后重启，
隧道重新就绪且 TCP 转发恢复。

做过变异检验的回归测试（把修复临时改回旧逻辑，确认测试随之失败）：租约的跨进程时钟比较、入表只发一次报道、
存储选点的中转能力分档、TCP 载体的同端口监听与端口共用、探测执行器的监听窗口、节点入网引导的重试与补推广告、
存储节点重启后的房间恢复与地址重新登记。
装配线阶段漂移死锁的用例则是修复前失败、修复后通过。

中途查出的测试自身的问题（已修）：同一模块的测试共用探针密钥，并行时互相误命中；测试端口按顺序发放时，
Windows 上相邻两次测试进程会撞上前一次连接留下的 TIME_WAIT（40 遍里失败 4 遍，改成随机取端口后 50 遍 0 失败）。

**没有验证的**：真实 NAT、真实丢包与乱序、跨机器运行、Linux 的 systemd / nftables 部署件、除 x86 以外的架构在真实硬件上的运行
（ARM / 龙架构只在 QEMU 用户态仿真下跑过；Windows 的 i686 / ARM64 构建要等 GitHub Actions 的实际运行）。
