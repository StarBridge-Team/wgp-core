# vendor/ — 外部代码安放区

本目录存放**不属于 wgp 内核、但需要随仓库一起管理**的外部代码。
与 `kernel/`、`server/`、`client/` 的区别：这里的代码**不参与本 workspace 构建**
（根 `Cargo.toml` 里 `exclude = ["vendor"]`），需要单独构建，也尽量不修改上游实现。

---

## mesh-tun-proto/ — EasyTier 协议兼容层

| 项 | 值 |
|---|---|
| 包名 | `mesh-tun-proto` v0.1.0（edition 2021） |
| 来源 | `E:\Sata Files\Download\mesh-tun-proto.tar.gz`（2026-11-07，原始目录名 `easytier-client/`） |
| 作者 | 项目内部私有库（非 crates.io 公开包） |
| 定位 | **EasyTier 网络协议的轻量客户端实现**：只做协议层（握手 / SipHash13 digest / AES-128-GCM / SyncRouteInfo 路由 / Data 帧），不做 NAT 穿透、不做 TUN、不做服务端 |
| 文档 | 同目录 [`ACCESS_GUIDE.md`](mesh-tun-proto/ACCESS_GUIDE.md)（638 行，含三步接入、路由原理、FAQ） |
| 示例 | `examples/poc.rs`、`examples/tun_ipv4.rs`、`examples/p2p_chat.rs`、`examples/dbg_hs.rs` |

### 为什么放在 vendor/ 而不是 kernel/

1. 它是**别人写的、会独立更新**的代码，改它会让后续同步变痛苦；
2. 它引入 `prost`（protobuf）——而 wgp 内核有"禁止 serde/protobuf"的硬规矩（00 §3）。
   放在 vendor/ 并排除出 workspace，这条规矩在**内核**范围内依然成立；
3. 它需要 `protoc` 才能构建，不该成为 `cargo test --workspace` 的前置条件。

### 构建

```bash
# 需要 protoc（build.rs 用 prost-build 编译 proto/mesh_proto.proto）
# 未安装时：
#   Windows: 下载 https://github.com/protocolbuffers/protobuf/releases 的 win64 zip
#   Linux:   apt install protobuf-compiler
export PROTOC=/path/to/protoc        # 若已在 PATH 可省略

cargo check --manifest-path vendor/mesh-tun-proto/Cargo.toml --all-targets
```

验证环境：protoc 27.3 + Rust（本仓库同款 toolchain），`--all-targets` 通过，
仅 `examples/dbg_hs.rs` 有 2 条 unused 警告（上游代码，未改）。

### 与 wgp 的接缝（关键）

这个库**天生为外部打洞器设计**，内置了三处接缝（`src/lib.rs`）：

```rust
// ① 外部打洞器要实现的最小 trait：给我一个 peer，还我一个已打通的 socket
pub trait ExternalHolePunchBridge: Send + Sync {
    fn punch_to(&self, peer_info: &PeerInfo) -> anyhow::Result<ExternalHolePunchResult>;
}

// ② 打洞结果：本地绑定 + 对端映射地址 + 传输模式
pub struct ExternalHolePunchResult {
    pub local_bind: SocketAddr,
    pub remote_mapped: SocketAddr,
    pub remote_peer_id_hint: u32,
    pub mode: PunchIntegrationMode,
}

// ③ 三种接入模式
pub enum PunchIntegrationMode {
    UdpWithEt8ByteHeader,        // UDP + ET 官方 8B 隧道头
    ReliableStreamWithEt4BFrame, // TCP 流 + 4B 长度帧（对应 wgp 的 TCP 兜底载体）
    NoTunnelHeader,              // 裸帧：字节流内容直接是 PeerManagerHeader + payload
}
```

对应的 wgp 侧接口：

| wgp 交付物 | 接法 |
|---|---|
| `PunchedLink::Udp { socket }` | `P2pNode::add_udp_conn(sock, remote, mode)`（`src/lib.rs:1794` 附近） |
| `PunchedLink::Tcp { stream }` | `P2pNode::add_stream_conn(stream)`（泛型 `Read + Write + Send`） |

`P2pNode` 是**同步阻塞 + 手动 tick** 模型：`tick()` 必须 ≤50ms 调用一次，内部驱动全部 TCP/UDP 读写。
集成时需要一个专门的线程或 `spawn_blocking` 循环，不能塞进 async 任务里干等。

### 已知待解（集成时才会遇到）

1. **socket 复用**：`MeshUdpPlug::new()` 是**占位实现**——它自己 bind 了个新 socket 并注释说明
   "实际应复用外部工具已经 bind 的同一个 fd"。真正可用的是 `add_udp_conn(sock, ...)`。
2. **探针混杂**：wgp 的打洞 socket 上同时跑自己的 31B 签名探针与 keepalive。
   交给 ET 之前必须先停掉 wgp 保活，否则 ET 会读到无法解析的包。
3. **只实现客户端**：需要一个 ET relay（官方 Core 或自建）才能组网；本库不做服务端。

### 维护策略

- **不修改上游源码**。确有必要的本地适配，写进 `wgp` 侧的新 crate（见下），不要改 `vendor/mesh-tun-proto/`。
- 上游更新时，整目录替换 + 重新跑 `cargo check --all-targets` 即可。
- 桥接逻辑将来放在 `bridge/`（例如 `bridge/wgp-et/`），它依赖 `wgp-core` 与 `vendor/mesh-tun-proto`。
