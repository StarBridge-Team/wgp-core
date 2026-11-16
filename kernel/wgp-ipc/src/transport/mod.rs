//! 传输层：**只**开本机端点，并真的做 ACL 检查。
//!
//! 两条铁律（20 文档 §3/§6）：
//! 1. 端点不映射到任何 TCP 监听口。跨主机管理另做显式 SSH 隧道或 TLS，默认关闭。
//! 2. 「路径/名字难猜」不算认证。Unix 用 `SO_PEERCRED` 校验同 UID；Windows 用命名管道的
//!    受限 DACL 挡在连接建立阶段，连上后再比对调用者与被调用者是否处于同一个登录会话。
//!
//! 平台差异只体现在本模块之下：两个平台各自给出 `Listener`/`connect`，上层（[`crate::server`]）
//! 只看见 `Box<dyn Stream>` 与一句「对端是谁」。

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{bind, connect, Listener};
#[cfg(windows)]
pub use windows::{bind, connect, Listener};

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

/// 已建立的字节流。控制面只需要「有序字节流」这一件事，无关承载是 UDS 还是命名管道。
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// 装箱的字节流（split 后交给读写两个任务）
pub type BoxStream = Box<dyn Stream>;

/// 一个已被接受、且**已通过 ACL 检查**的连接
pub struct Accepted {
    pub stream: BoxStream,
    /// 对端的人类可读描述（日志用；不含敏感信息）
    pub peer: String,
}

/// 本机端点。
///
/// - Unix：Unix domain socket 的文件路径（`$XDG_RUNTIME_DIR/wgp/agent.sock`，
///   退化到 `$HOME/.wgp/agent.sock`）
/// - Windows：命名管道全路径（`\\.\pipe\wgp-agent-<用户名>`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    #[cfg(windows)]
    Pipe(String),
}

impl Endpoint {
    /// 当前用户的默认端点
    pub fn for_current_user() -> io::Result<Self> {
        #[cfg(unix)]
        {
            unix::default_path().map(Endpoint::Unix)
        }
        #[cfg(windows)]
        {
            windows::default_pipe_name().map(Endpoint::Pipe)
        }
    }

    /// 解析 `--socket` 覆盖值。
    ///
    /// Unix 接受任意路径（也接受 `unix:` 前缀）；Windows 接受完整管道名、裸管道名
    /// （自动补 `\\.\pipe\` 前缀），以及 `unix:`/`pipe:` 显式前缀。
    pub fn parse(spec: &str) -> io::Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "端点为空"));
        }
        #[cfg(unix)]
        {
            let path = spec.strip_prefix("unix:").unwrap_or(spec);
            Ok(Endpoint::Unix(std::path::PathBuf::from(path)))
        }
        #[cfg(windows)]
        {
            let name = spec
                .strip_prefix("pipe:")
                .or_else(|| spec.strip_prefix("unix:"))
                .unwrap_or(spec);
            Ok(Endpoint::Pipe(windows::normalize_pipe_name(name)))
        }
    }

    /// 端点展示串（启动横幅、错误消息、快照）
    pub fn display(&self) -> String {
        match self {
            #[cfg(unix)]
            Endpoint::Unix(p) => p.display().to_string(),
            #[cfg(windows)]
            Endpoint::Pipe(n) => n.clone(),
        }
    }

    /// ACL 摘要（启动时打印给人看：我们究竟靠什么挡住别人）
    pub fn acl_summary(&self) -> &'static str {
        #[cfg(unix)]
        {
            "Unix socket：目录 0700 / socket 0600，accept 后校验 SO_PEERCRED 的 UID 必须与本进程相同"
        }
        #[cfg(windows)]
        {
            "命名管道：DACL = D:P(A;;GA;;;OW)（仅属主 GA），并置 PIPE_REJECT_REMOTE_CLIENTS；\
             连上后比对调用者与本进程的登录会话（TokenStatistics.AuthenticationId）"
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_endpoint_rejected() {
        assert!(Endpoint::parse("   ").is_err());
    }

    #[test]
    fn default_endpoint_is_local_only() {
        let ep = Endpoint::for_current_user().expect("默认端点必须能算出来");
        let text = ep.display();
        assert!(!text.is_empty());
        // 端点绝不能是 TCP 形式：控制面不开公网/回环 TCP 监听（20 §3）
        assert!(
            !text.starts_with("tcp://") && !text.contains("127.0.0.1:") && !text.contains("0.0.0.0"),
            "端点不应该是 TCP 地址：{text}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_endpoint_normalizes_pipe_prefix() {
        let ep = Endpoint::parse("wgp-agent-test").unwrap();
        assert_eq!(ep.display(), r"\\.\pipe\wgp-agent-test");
        let ep2 = Endpoint::parse(r"\\.\pipe\wgp-agent-test").unwrap();
        assert_eq!(ep, ep2);
        let ep3 = Endpoint::parse("pipe:wgp-agent-test").unwrap();
        assert_eq!(ep, ep3);
    }

    #[cfg(unix)]
    #[test]
    fn unix_endpoint_accepts_plain_path() {
        let ep = Endpoint::parse("/tmp/wgp-test.sock").unwrap();
        assert_eq!(ep, Endpoint::Unix("/tmp/wgp-test.sock".into()));
        assert_eq!(ep.display(), "/tmp/wgp-test.sock");
        assert_eq!(
            Endpoint::parse("unix:/tmp/x.sock").unwrap(),
            Endpoint::Unix("/tmp/x.sock".into())
        );
    }
}
