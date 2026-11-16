//! Windows 命名管道传输。
//!
//! ## 我们到底做了什么（逐条对应「不得假装」的要求）
//!
//! 1. **受限 DACL**：管道用 SDDL `D:P(A;;GA;;;OW)` 创建。`P` = 受保护的 DACL（不继承父目录上
//!    任何宽松 ACE），唯一一条 ACE 是「Owner Rights 访问 GA（GENERIC_ALL）」。`OW`
//!    （S-1-3-4，OWNER RIGHTS）在访问检查时解析为**对象属主**——即创建管道的这个用户。
//!    效果：只有属主本人能 `CreateFile` 打开这条管道；`Everyone`、`Authenticated Users`
//!    都没有任何权限（20 §3「禁止 Everyone 写入」）。同时置 `PIPE_REJECT_REMOTE_CLIENTS`，
//!    远程（SMB）客户端直接连不上。
//! 2. **连上之后的身份校验**：`GetNamedPipeClientProcessId` 拿到客户端 PID，再取该进程令牌的
//!    `TokenStatistics.AuthenticationId`（登录会话 LUID），与本进程的同一个值比较。不同就断开。
//!    AuthenticationId 是「LSA 登录会话」标识：同一用户的不同登录会话（例如另开一个 `runas`
//!    会话）会被拒绝，这是**故意的**——控制面只服务本用户本会话。
//! 3. **残留风险**（见 `client/wgp-agent/README.md`）：DACL 只管「谁能连」。同一用户在同一登录
//!    会话里的任意进程（包括被注入的恶意程序）都能连进来并调用 `StartRoom`/`ShutdownAgent`。
//!    阶段 1 没有方法级鉴权，也没有启动时一次性 token（20 §6 允许的强认证手段）。
//!
//! 为什么用 `windows-sys`：构造安全描述符必须调 `ConvertStringSecurityDescriptorToSecurityDescriptorW`。
//! 本 crate 只在 Windows 目标上依赖它，feature 只开必需的五组（Foundation / Security /
//! Security_Authorization / System_Pipes / System_Threading），版本与 tokio 已依赖的
//! `windows-sys 0.61` 对齐，不引入新的依赖树。

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenStatistics, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_STATISTICS,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{Accepted, BoxStream, Endpoint};

/// 只有属主有权限的 DACL（受保护 + Owner Rights GA）
pub const OWNER_ONLY_SDDL: &str = "D:P(A;;GA;;;OW)";

/// 管道名默认形态：`\\.\pipe\wgp-agent-<用户名>`
pub fn default_pipe_name() -> io::Result<String> {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    // 用户名里可能有空格/反斜杠/域前缀：管道名只留安全字符，真正的门是 DACL 不是名字
    let mut safe: String = user
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        safe.push_str("user");
    }
    Ok(format!(r"\\.\pipe\wgp-agent-{safe}"))
}

/// 补全 `\\.\pipe\` 前缀
pub fn normalize_pipe_name(name: &str) -> String {
    if name.starts_with(r"\\.\pipe\") {
        name.to_string()
    } else {
        format!(r"\\.\pipe\{name}")
    }
}

/// 自持有安全描述符（Drop 时 `LocalFree`）
struct OwnerOnlySd(PSECURITY_DESCRIPTOR);

impl OwnerOnlySd {
    fn new() -> io::Result<Self> {
        let wide: Vec<u16> = OWNER_ONLY_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut size = 0u32;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!(
                    "构造安全描述符失败（SDDL `{OWNER_ONLY_SDDL}`）：{}",
                    io::Error::last_os_error()
                ),
            ));
        }
        Ok(Self(sd))
    }
}

impl Drop for OwnerOnlySd {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

/// 监听中的命名管道。
///
/// 始终保有一个「等待连接」的实例：tokio/Windows 的管道对象只在存在实例时才能被打开，
/// 若两次 `accept` 之间没有实例，客户端会拿到 `ERROR_FILE_NOT_FOUND`——表现为「agent 明明
/// 在跑却连不上」。所以每次 `accept` 取走当前实例后**先**补建下一个，再去等连接。
pub struct Listener {
    name: String,
    sd: OwnerOnlySd,
    pending: Option<NamedPipeServer>,
}

impl Listener {
    /// 管道名
    pub fn name(&self) -> &str {
        &self.name
    }

    fn create_instance(&self, first: bool) -> io::Result<NamedPipeServer> {
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: 0,
        };
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first).reject_remote_clients(true);
        // Safety: attrs 指向的 SD 由 self.sd 持有，活到 listener 被 drop；
        // attrs 本身只需在这次调用期间有效。
        let res = unsafe {
            opts.create_with_security_attributes_raw(
                &self.name,
                &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
        };
        if let Err(e) = &res {
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "无法创建命名管道 {}：已有实例存在或拒绝访问（另一个 agent 在运行？）",
                        self.name
                    ),
                ));
            }
        }
        res
    }

    /// 接受连接：DACL 已经挡掉了别的用户；这里再校验一次登录会话。
    pub async fn accept(&mut self) -> io::Result<Accepted> {
        let server = match self.pending.take() {
            Some(server) => server,
            None => self.create_instance(false)?,
        };
        // 先补建下一个实例，保证"等待中"始终有一个
        let next = self.create_instance(false)?;
        self.pending = Some(next);

        server.connect().await?;
        verify_same_logon(&server)?;
        let peer = match client_pid(&server) {
            Ok(pid) => format!("pid={pid}"),
            Err(_) => "pid=?".to_string(),
        };
        Ok(Accepted {
            stream: Box::new(server),
            peer,
        })
    }
}

pub async fn bind(ep: &Endpoint) -> io::Result<Listener> {
    let name = match ep {
        Endpoint::Pipe(n) => n.clone(),
    };
    let sd = OwnerOnlySd::new()?;
    let mut listener = Listener {
        name,
        sd,
        pending: None,
    };
    // 第一个实例用 first_pipe_instance(true)：同一台机器上第二个 agent 会直接失败，
    // 而不是悄悄共享一条管道（否则两个进程都会以为自己拥有 DHT 身份）。
    let first = listener.create_instance(true)?;
    listener.pending = Some(first);
    Ok(listener)
}

/// 客户端连接。`ERROR_PIPE_BUSY` 表示实例正忙（服务端在轮换实例），短暂退避后重试。
pub async fn connect(ep: &Endpoint) -> io::Result<BoxStream> {
    let name = match ep {
        Endpoint::Pipe(n) => n.clone(),
    };
    let mut last = None;
    for _ in 0..40 {
        match ClientOptions::new().open(&name) {
            Ok(client) => return Ok(Box::new(client)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("命名管道连接失败")))
}

/// 持有句柄的 RAII（避免错误路径漏 CloseHandle）
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn client_pid(server: &NamedPipeServer) -> io::Result<u32> {
    let mut pid = 0u32;
    let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

fn logon_session_of_pid(pid: u32) -> io::Result<(u32, i32)> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _guard = OwnedHandle(process);
    logon_session_of_process(process)
}

fn logon_session_of_process(process: HANDLE) -> io::Result<(u32, i32)> {
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = OwnedHandle(token);
    let mut stats = TOKEN_STATISTICS::default();
    let mut returned = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            &mut stats as *mut TOKEN_STATISTICS as *mut c_void,
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((stats.AuthenticationId.LowPart, stats.AuthenticationId.HighPart))
}

/// 本进程的登录会话 LUID
pub fn own_logon_session() -> io::Result<(u32, i32)> {
    // GetCurrentProcess 返回伪句柄（-1），不能 CloseHandle，也不该被 OwnedHandle 包住
    logon_session_of_process(unsafe { GetCurrentProcess() })
}

/// 校验客户端与本进程处于同一登录会话。**失败即拒绝**（不降级、不"仅记录警告"）。
pub fn verify_same_logon(server: &NamedPipeServer) -> io::Result<()> {
    let pid = client_pid(server)?;
    let client = logon_session_of_pid(pid)?;
    let ours = own_logon_session()?;
    if client == ours {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "拒绝 IPC 连接：客户端 PID {pid} 的登录会话 {:?} 与本进程 {:?} 不同（控制面只服务本用户本会话）",
            client, ours
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_parses_to_a_valid_descriptor() {
        // 只验证「这条 SDDL 能被系统接受」——真正的访问检查需要另一个用户账号才能验证
        let sd = OwnerOnlySd::new().expect("SDDL 必须能被解析");
        assert!(!sd.0.is_null());
    }

    #[test]
    fn pipe_name_normalization() {
        assert_eq!(normalize_pipe_name("wgp-agent-x"), r"\\.\pipe\wgp-agent-x");
        assert_eq!(
            normalize_pipe_name(r"\\.\pipe\wgp-agent-x"),
            r"\\.\pipe\wgp-agent-x"
        );
    }

    #[test]
    fn default_pipe_name_has_no_dangerous_chars() {
        let name = default_pipe_name().expect("必须能算出默认管道名");
        assert!(name.starts_with(r"\\.\pipe\wgp-agent-"), "{name}");
        // 名字里不能出现空格/反斜杠之外的路径分隔（用户名可能带域前缀）
        let tail = name.trim_start_matches(r"\\.\pipe\");
        assert!(
            tail.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "{tail}"
        );
    }

    #[test]
    fn own_logon_session_is_queryable() {
        let id = own_logon_session().expect("必须能查到本进程登录会话");
        assert_eq!(id, own_logon_session().unwrap());
    }
}
