# 折跃门 wgp · 拼装与验证记录

> 生成于 2026-11-07，由本次会话把 `C:\Users\DogerWindows\Downloads\` 下的散落代码拼成完整 workspace。
> 原始文件未改动（Downloads 保持原样），此处为**拷贝 + 补齐缺件 + 实测**。

## 1. 来源与补齐

| 项 | 状态 |
|---|---|
| `kernel/`（wgp-proto、crypto、punch、dht、core） | 从 Downloads 原样拷贝 |
| `server/`（wgp-node 源码 + deploy 11 件） | 原样拷贝 |
| `client/`（wgp-client） | 原样拷贝 |
| `docs/`（12 篇设计文档） | 原样拷贝 |
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
