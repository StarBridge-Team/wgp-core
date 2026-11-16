//! Unix domain socket 传输。
//!
//! 三道门（20 §3/§6）：
//! 1. **路径**：`$XDG_RUNTIME_DIR/wgp/agent.sock`（每个用户自己的 runtime 目录），
//!    没有 `XDG_RUNTIME_DIR` 时退化到 `$HOME/.wgp/agent.sock`。
//! 2. **权限**：父目录 `0700`、socket 文件 `0600`。别人连 socket 都打不开。
//! 3. **凭据**：`accept` 之后立刻用 `SO_PEERCRED`（`UnixStream::peer_cred`）取对端 UID，
//!    必须与本进程 UID 相同，否则断开。权限位能被 `chmod`/`umask` 意外改坏，
//!    凭据校验不会——所以两者都要，不能只靠文件权限。
//!
//! 本模块只覆盖 Linux/Android 语义（`SO_PEERCRED`）。macOS 的 `LOCAL_PEERCRED` 语义不同，
//! 本项目未承诺支持 macOS。

use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener as TokioUnixListener, UnixStream};

use super::{Accepted, BoxStream, Endpoint};

/// 监听中的 UDS
pub struct Listener {
    inner: TokioUnixListener,
    path: PathBuf,
    our_uid: u32,
}

/// 默认路径：`$XDG_RUNTIME_DIR/wgp/agent.sock`，退化到 `$HOME/.wgp/agent.sock`
pub fn default_path() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        // XDG_RUNTIME_DIR 规定必须是本用户的私有目录；不存在就按退化路径处理
        if dir.is_dir() {
            return Ok(dir.join("wgp").join("agent.sock"));
        }
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::other("既没有 XDG_RUNTIME_DIR 也没有 HOME，无法确定端点路径"))?;
    Ok(PathBuf::from(home).join(".wgp").join("agent.sock"))
}

/// 建私有目录：已存在也要把权限收紧（可能是上次崩溃留下的宽松权限目录）
fn private_dir(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir)?;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

pub fn path_of(ep: &Endpoint) -> &Path {
    match ep {
        Endpoint::Unix(p) => p.as_path(),
    }
}

/// 绑定端点
pub async fn bind(ep: &Endpoint) -> io::Result<Listener> {
    let path = path_of(ep);
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            private_dir(dir)?;
        }
    }
    if path.exists() {
        // 已有活着的 agent 时**不要**抢 socket：unlink 掉别人的 socket 会让旧进程变成
        // 静默的孤儿（它还以为自己在服务），排查起来非常痛苦。
        match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("端点已被占用（另一个 agent 正在运行？）：{}", path.display()),
                ));
            }
            Err(_) => {
                // 连不上 = 上次崩溃残留的 socket 文件
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let inner = TokioUnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let our_uid = current_euid()?;
    Ok(Listener {
        inner,
        path: path.to_path_buf(),
        our_uid,
    })
}

impl Listener {
    /// 监听路径（横幅与日志用）
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 接受连接。凭据不符直接返回 `PermissionDenied`（调用方记一条拒绝后继续 accept）。
    pub async fn accept(&mut self) -> io::Result<Accepted> {
        let (stream, _addr) = self.inner.accept().await?;
        let cred = stream
            .peer_cred()
            .map_err(|e| io::Error::new(e.kind(), format!("读取对端凭据失败：{e}")))?;
        check_peer_uid(cred.uid(), self.our_uid)?;
        let peer = match cred.pid() {
            Some(pid) => format!("uid={},pid={pid}", cred.uid()),
            None => format!("uid={}", cred.uid()),
        };
        Ok(Accepted {
            stream: Box::new(stream),
            peer,
        })
    }
}

/// 客户端连接
pub async fn connect(ep: &Endpoint) -> io::Result<BoxStream> {
    let stream = UnixStream::connect(path_of(ep)).await?;
    Ok(Box::new(stream))
}

/// 同 UID 校验（本机控制面唯一的认证手段，纯函数便于单测）
pub fn check_peer_uid(peer_uid: u32, our_uid: u32) -> io::Result<()> {
    if peer_uid == our_uid {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "IPC 对端 UID {peer_uid} 与本进程 UID {our_uid} 不同：拒绝（控制面只服务同一用户，20 §6）"
        ),
    ))
}

/// 本进程的有效 UID。
///
/// 不引入 `libc`（本项目对新增第三方依赖很保守），所以：
/// ① 首选 `/proc/self/status` 的 `Uid:` 第二列（effective uid）；
/// ② 退化用 socketpair：对端就是本进程自己，`SO_PEERCRED` 给出本进程凭据。
/// 两条都不通时**拒绝启动**——宁可跑不起来，也不能在无法校验凭据的情况下开门。
pub fn current_euid() -> io::Result<u32> {
    if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let mut fields = rest.split_whitespace();
                let _real = fields.next();
                if let Some(eff) = fields.next() {
                    if let Ok(uid) = eff.parse::<u32>() {
                        return Ok(uid);
                    }
                }
            }
        }
    }
    if let Ok((mine, _other)) = UnixStream::pair() {
        if let Ok(cred) = mine.peer_cred() {
            return Ok(cred.uid());
        }
    }
    Err(io::Error::other(
        "无法确定本进程 UID：peer 凭据校验无法进行，拒绝启动控制面",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_uid_allowed_mismatch_rejected() {
        assert!(check_peer_uid(1000, 1000).is_ok());
        let err = check_peer_uid(1001, 1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let text = err.to_string();
        assert!(text.contains("1001") && text.contains("1000"), "{text}");
    }

    #[test]
    fn current_euid_is_deterministic() {
        // 同一个进程问两次必须一致（否则凭据校验会随机失败）
        let a = current_euid().expect("必须能确定本进程 UID");
        let b = current_euid().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn xdg_runtime_dir_wins_home() {
        // 不改进程环境（测试并行），只验证路径形状
        let p = default_path().expect("必须有默认路径");
        assert!(p.ends_with("wgp/agent.sock"), "{}", p.display());
    }
}
