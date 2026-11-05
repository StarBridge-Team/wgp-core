//! wgp-node-hobby（家庭宽带专用版）：折跃门贡献节点（07 §6/§7 部署规格）。
//!
//! 与静态 IP 完整版共用同一套四职逻辑，但**强制贡献模式**：
//! - 拒绝 Forward 中转（中转是唯一可能产生持续流量、进而被运营商判 PCDN 的路径）
//! - 面向家庭宽带：默认同开 UDP 11010 与 TCP 3481，观测限速由观察者侧兜底
//! - 默认绑定 0.0.0.0，端口映射由家庭路由器/光猫转发
//!
//! 用法：
//!   wgp-node-hobby [--bind <addr>] [--stun <port|none>] [--tcp <port|none>] [--config <path>]
//!   示例：wgp-node-hobby                            （默认 0.0.0.0:11010 + 3478 + 3481）
//!        wgp-node-hobby --bind 0.0.0.0:11010 --tcp none
//! 本形态 hobby 恒为真（--no-hobby 无效）。
//! 配置优先级：命令行 > WGP_* 环境变量 > wgp-node.conf 配置文件 > 默认值
//! 运行 `wgp-node-hobby --help` 查看完整选项。
//! 身份持久化于 ./node_identity.key（首启生成，重启复用；防身份漂移 07 §8）

use wgp_node::server;

#[tokio::main]
async fn main() {
    server::run("wgp-node-hobby", true).await;
}
