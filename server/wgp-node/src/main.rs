//! wgp-node（静态 IP 完整版）：折跃门服务端节点（07 §6 部署规格）。
//! 单进程四职：DHT 种子 / 观察者 / STUN 响应器 / 承诺转发兜底。
//! 部署于公网固定地址，**允许** Forward 中转（承担最坏情况下的承诺投递兜底）。
//!
//! 家庭宽带贡献节点请改用 `wgp-node-hobby`（强制拒绝中转，PCDN 防护）。
//!
//! 用法：
//!   wgp-node [--bind <addr>] [--stun <port|none>] [--tcp <port|none>]
//!            [--hobby] [--config <path>] [--log-level <level>]
//!   示例：wgp-node                                   （默认 0.0.0.0:11010 + 3478 + 3481）
//!        wgp-node --tcp none                        （关闭 TCP 信令面）
//!        wgp-node --stun none --tcp none            （仅 DHT 种子）
//! 配置优先级：命令行 > WGP_* 环境变量 > wgp-node.conf 配置文件 > 默认值
//! 运行 `wgp-node --help` 查看完整选项。
//! 身份持久化于 ./node_identity.key（首启生成，重启复用；防身份漂移 07 §8）

use wgp_node::server;

#[tokio::main]
async fn main() {
    server::run("wgp-node", false).await;
}
