# 交接文档（HANDOFF）

> 生成于 2026-11-07，覆盖本轮接手后的全部工作、当前状态、下一步路线。
> 配套阅读：[`PROGRESS.md`](PROGRESS.md)（代码现状盘点）、[`STATUS.md`](STATUS.md)（拼装与验证记录）。
> 本文回答三个问题：**做了什么 → 现在在哪 → 接下来怎么走。**

---

## 1. 一句话状态

**v2 内核能编译、152 个测试全绿、三个仓库已建好并归档；但「打洞成功后传数据」这一层仍是零，
且没有任何一次真实双端联调。产品离「能联机」还差数据面 + 一次真机验证。**

---

## 2. 本轮完成的事

### 2.1 摸清家底：原来有两个工程

接手时 `E:\...\mc-link-core` 是 v1 原型（62 个文件，7 月停更），而 `docs/` 里那套文档描述的是另一个工程
「折跃门 wgp」（v2）。两者架构完全不同：v1 是单 crate + GUI + 集中式 TCP 信令；v2 是 5 层内核 + DHT + 服务端。
**结论：文档没错，只是指的是 v2；v1 是历史存档。**

### 2.2 把散落的 v2 源码拼成可构建的 workspace

Downloads 里只有 `kernel/ server/ client/ docs/ 项目完整文档/ release/`，缺根 `Cargo.toml`（所有 crate 都用
`workspace = true` 继承，没有它一行都编不了）。按 `项目完整文档/01-工作区与构建.md` §2/§4 重建后：

| 验证项 | 结果 |
|---|---|
| `cargo check --workspace --all-targets` | 通过，**0 warning** |
| `cargo build --release` | 通过（LTO 39s），产出 3 个 exe |
| `cargo test --workspace` | **152 passed / 0 failed** |
| `wgp-node --help` / 非法配置 | 参数表一致 / 退出码 2 |
| `wgp-node` 实跑 | 就绪日志 + 32B 身份文件 + 三端口监听 |
| `wgp-client code` 文档 13 的 4 个标准向量 | **4/4 命中** |

顺带修了一个**依赖开机时长**的脆弱测试（`Instant::now() - 10000s` 在刚开机的机器上必 panic）。

### 2.3 补齐数据

- `nat/` **11/11**：首轮从 `mc-link-core/docs/nat` 拿到 8 份，第二轮从 `wgp-src.tar.gz` 补上余下 3 份（美国 VPN、香港 VPN、深圳 netstat）。
- 交叉验证：9/10 快照与现行代码 **32 个文件逐字节相同、19 个改过、6 个模块新增**——确认是同一条演化线。

### 2.4 三个仓库

| 仓 | 远程 | 许可证 | 说明 |
|---|---|---|---|
| **wgp-core** | [GitHub](https://github.com/StarBridge-Team/wgp-core) | GPL-3.0-or-later | 主仓，122 文件，历史按 3 份真实快照重建（9/10 → 11/05 → 11/07） |
| **mesh-tun-proto** | [GitHub](https://github.com/StarBridge-Team/mesh-tun-proto) | LGPL-3.0-or-later | ET 协议兼容层，15 文件，从 `vendor/` 迁出独立建仓 |
| **mc-link-core** | *无远程* | GPL-3.0-or-later | v1 存档，本地 `main` 分支，已确认废弃 |

**许可证链已闭环**：

```
EasyTier (LGPL-3.0)
   └─ mesh-tun-proto (LGPL-3.0-or-later)
        └─ wgp (GPL-3.0-or-later)      ← 静态链接 LGPL 库不再产生额外义务
             └─ mc-link (GPL-3.0-or-later)
```

### 2.5 客户端加了一条命令就加入

原来 `join` 必须粘 `U/房间码`。现在两种写法都行：

```bash
wgp-client join --network-name <网络名> --network-secret <密钥> -p udp://<种子>:11010   # ET 习惯
wgp-client join U/C2G9-GYET-311W-R636 -p udp://<种子>:11010                          # 房间码
```

`-p/--peers` 是 `--seed` 别名，可重复给多次。新增 4 个单测。

### 2.6 写了两份方案文档

- [`docs/17-DHT节点身份与信任方案.md`](docs/17-DHT节点身份与信任方案.md)：回答「谁来宣告、凭什么信」——身份自证 + 三把锚（DNS TXT / 背书 / TOFU）+ 信任图 + PoW。
- [`PROGRESS.md`](PROGRESS.md)：逐层盘点代码完成度，标出「已写但没接线」的模块。

### 2.7 ET 兼容：路线已定，代码未动

`mesh-tun-proto` 内置 `ExternalHolePunchBridge` / `ExternalHolePunchResult` / `PunchIntegrationMode`，
明确为外部打洞器设计。接缝是 `add_udp_conn(sock, remote, mode)` 或 `add_stream_conn(stream)`。
**但库是同步 + 手动 tick（≤50ms）模型，且 `MeshUdpPlug::new()` 是占位实现**——集成时要自己传 socket 并开线程。

---

## 3. 当前卡在哪

### 3.1 唯一的硬断点：数据面

```
算房间码 → DHT 入表 → 密钥协商 → 观察者探测 → 端点交换 → 打洞 → ✅ 交付 socket + 保活
                                                                    ↓
                                                        ❌ 没人接手（SilentSink 直接丢弃）
```

`PunchedLink` 交出的是 `Udp{socket}` / `Tcp{stream}` + `session_key`，客户端收到就扔了。
所以今天能演示"打通"，但不能传一个字节。

### 3.2 所有验证都是单机的

152 个测试全在 loopback；`net_test.rs` 的三节点也是本机端口。**零真实双端、零真实 NAT、零 Linux 运行。**

### 3.3 DHT 只是"能当邮箱"

`SeedAdvertise` 写完从未发送，路由表桶不分裂，KV 是 K=1 单值。
节点不会宣告自己，别的节点也发现不了它——发现层实际是死的，用户仍要手工知道种子地址。

### 3.4 ET 桥接的三个坑

1. `MeshUdpPlug::new()` 自建 socket（占位），必须改用 `add_udp_conn()` 传我们打洞的 socket；
2. 我们的 UDP socket 上混着 31B 签名探针，交给 ET 前必须停保活 + 分流；
3. 库是阻塞模型，要单独线程或 `spawn_blocking`。

---

## 4. 下一步路线图

### M1 · 真机联调（最高优先级，1–2 天）

**目的不是"成功"，是拿到第一份真实数据。**

- [ ] 两台异 NAT 机器 + 一台公网 `wgp-node`（或直接用现有种子）
- [ ] 跑 `wgp-client 开房` × `join --observer`
- [ ] 记录：哪一步超时、NAT 类型判对没、三波打多久、TCP 兜底触发没
- [ ] 结果回填 `nat/` 与 `docs/18`

> 没有这一步，下面所有工作都是盲写。

### M2 · 数据面 `wgp-port`（解锁"能联机"，3–7 天）

- [ ] 新建 `bridge/wgp-port` crate：`PunchedLink` + `PskBundle` → TLS-PSK 帧流 → 本地 `TcpListener`
- [ ] **UDP socket 分流**：先验探针 HMAC（31B），否则当业务数据（参考 v1 `reliable.rs` 的 magic 方案）
- [ ] 端口转发：房主暴露本地 25565，加入方本地起端口，MC 直连 `localhost`
- [ ] 本机双客户端验证（不依赖 ET、不依赖真网络）

> 这一段与 ET 无关，做完立刻可用；也是 ET 桥接的基础。

### M3 · ET 桥接（陶瓦兼容，1–2 周）

- [ ] 实现 `ExternalHolePunchBridge`：内部调 `Engine::new_link`，返回 `ExternalHolePunchResult`
- [ ] tick 线程包装 `P2pNode`，`P2pEvent` 转 wgp 事件
- [ ] 先用 `examples/p2p_chat.rs` 做 PoC：两个 WGP 节点打洞成功 → 跑 ET 协议 → 互发一条消息
- [ ] 再接 TUN / 虚拟 IP / 路由（这些 ET 库已实现，是纯下游）

**形态选择**：独立进程（推荐，契合 ET 库的同步模型）还是同进程 crate（GPL 后法律无碍，但内核禁 protobuf 的纪律仍在）——见 [`mesh-tun-proto/LICENSING.md`](https://github.com/StarBridge-Team/mesh-tun-proto/blob/main/LICENSING.md)。

### M4 · DHT 接线（让节点真正互相发现，2–3 天）

- [ ] 启动后周期广播 `SeedAdvertise`，入站验签后入表
- [ ] 客户端用 `FIND_NODE` 扩散，而不是只认一个种子
- [ ] P0 阶段先不校验信任（`docs/17` §8 待拍板第 1 条）

### M5 · 产品化（之后）

Bedrock UDP、GUI、打包分发、Linux 部署验证。

---

## 5. 待决策（需要原开发者/团队拍板）

| # | 问题 | 影响 |
|---|---|---|
| 1 | 「DHT 节点」= 每个客户端宣告自己（自发现），还是任何人都能跑公共节点（生态）？ | M4 工作量差一倍 |
| 2 | 官方根用 DNS 锚（买域名）还是纯背书锚（零成本）？ | 信任模型强度 |
| 3 | PoW 取 16/18/20 bit？ | 抗 sybil vs 启动耗时 |
| 4 | ET 桥是独立进程还是同进程？ | 部署复杂度 |

---

## 6. 五分钟自己验一遍

```bash
cd 'E:\Work Files\Code\Rust\wgp'
cargo test --workspace          # 152 绿
cargo build --release

target/release/wgp-node --bind 127.0.0.1:11010 --stun 3478 --tcp 3481
target/release/wgp-client code 示例房间 123456    # U/C2G9-GYET-311W-R636
```

打通后会看到 `LinkYielded` 事件，然后**什么也不会发生**——这就是 §3.1 那个断点。
