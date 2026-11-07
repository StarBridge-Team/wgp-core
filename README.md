# 折跃门（wgp）· 纯 P2P 零中继 NAT 打洞组网

两端业务数据端到端直连，种子节点只承担信令与端点观测，永不转发业务流量。

## 目录

```
kernel/           内核五层（依赖单向 proto ← crypto ← punch ← dht ← core）
  wgp-proto       协议：包格式/常量/编解码 + STUN 最小子集（零依赖、无 async）
  wgp-crypto      密码：承诺-揭示、HKDF、探针 HMAC、逃生 AEAD、KeyAgreement（PQ 可插拔）
  wgp-punch       打洞：状态机、预算调度器（唯一发包点）、步长学习、三波、保活
  wgp-dht         信令：Kademlia 变种、房间键、租约/继位链、观察者协议
  wgp-core        门面：Engine + PunchedLink 交付物 + 全部对外 API（feature: client/node）
server/wgp-node   服务端：种子 / 观察者（STUN 扩展）/ STUN / 承诺兜底（双形态 node + hobby）
client/wgp-client 客户端参考外围：code / 开房 / join
docs/             设计文档 12 篇（00-16 编号）
项目完整文档/      按代码现状撰写的全量文档 15 篇（逐个源文件）
nat/              NAT 实测数据
vendor/           外部代码：mesh-tun-proto（EasyTier 协议兼容层，独立构建）
```

## 构建与测试

```bash
cargo test --workspace        # 148 个测试，全部 Windows loopback
cargo build --release         # LTO release，产出 wgp-node / wgp-node-hobby / wgp-client
```

## 跑起来

```bash
# 种子 + 观察者（默认三端口：UDP 11010 信令 / UDP 3478 STUN / TCP 3481 信令兜底）
wgp-node --bind 0.0.0.0:11010 --stun 3478 --tcp 3481

# 加入一个网络：一条命令，不需要房间码、不需要配置文件
wgp-client join --network-name <网络名> --network-secret <网络密钥> -p udp://<种子>:11010

# 房主（同样可用 --network-name/--network-secret）
wgp-client 开房 --network-name <网络名> --network-secret <网络密钥> -p udp://<种子>:11010
```

网络名 + 网络密钥即 EasyTier 的 `network_name` / `network_secret`；两者由客户端本地派生成房间码，
所以**两端不需要交换任何码**。房主要分享时再执行 `wgp-client code <网络名> <网络密钥>` 把码发出去即可。

## 文档

- 先读 [`项目完整文档/00-项目总览.md`](项目完整文档/00-项目总览.md)，再按文末路线深入
- 写代码前必读 [`项目完整文档/03-代码编写硬规矩与规范.md`](项目完整文档/03-代码编写硬规矩与规范.md)
- 本次拼装与验证记录见 [`STATUS.md`](STATUS.md)

> 上线前须知：内核交付物是 `PunchedLink`（UDP socket / TCP 流 + 会话密钥），
> 数据面（QUIC-TLS / TLS-PSK 帧流 / 端口转发 / 虚拟网卡）属于外围任务，尚未实现。
