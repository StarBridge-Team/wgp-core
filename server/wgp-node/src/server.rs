//! wgp-node 服务端共享启动逻辑（07 §6 部署规格）。
//!
//! 四职：DHT 种子 / 观察者 / STUN 响应器 / 承诺转发兜底。
//! 无状态、无数据库；日志仅记录生命周期与错误（不记会话内容）。
//!
//! 身份持久化于 `node_identity.key`（首启生成，重启复用；防身份漂移 07 §8）。
//!
//! 配置来源与优先级（高 → 低）：
//!   命令行 `--flag`  >  环境变量 `WGP_*`  >  配置文件（`key = value`）  >  内置默认值
//! 端口/地址等部署数据一律由本层注入内核，内核不持有任何部署常量（00 §3）。

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use wgp_core::{Engine, NodeConfig, NodeRole};
use wgp_dht::{NodeIdentity, ObserverPolicy};

/// 默认 DHT 信令 UDP 绑定地址
pub const DEFAULT_BIND: &str = "0.0.0.0:11010";
/// 默认 STUN/观察者端口
pub const DEFAULT_STUN_PORT: u16 = 3478;
/// 默认 TCP 信令兜底端口
pub const DEFAULT_TCP_PORT: u16 = 3481;
/// 默认身份持久化文件名
pub const IDENTITY_FILE: &str = "node_identity.key";
/// 默认配置文件（存在即自动加载）
pub const DEFAULT_CONFIG_FILE: &str = "wgp-node.conf";
/// 环境变量前缀
pub const ENV_PREFIX: &str = "WGP_";

// ————————————————————————————————————————————————————————————
// 日志（零依赖；systemd/journald 负责采集，时间戳由采集端补全）
// ————————————————————————————————————————————————————————————

/// 日志级别（数值越大越详细）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "trace" => Some(Self::Debug),
            _ => None,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

fn emit(level: LogLevel, msg: &str) {
    if level as u8 > LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let line = format!("[{}] {}", level.tag(), msg);
    // warn/error 走 stderr（无缓冲、随 systemd 立即采集）；其余走 stdout 并立即 flush
    if level <= LogLevel::Warn {
        eprintln!("{line}");
    } else {
        println!("{line}");
        let _ = std::io::stdout().flush();
    }
}

pub fn log_error(msg: impl AsRef<str>) {
    emit(LogLevel::Error, msg.as_ref());
}
pub fn log_warn(msg: impl AsRef<str>) {
    emit(LogLevel::Warn, msg.as_ref());
}
pub fn log_info(msg: impl AsRef<str>) {
    emit(LogLevel::Info, msg.as_ref());
}
pub fn log_debug(msg: impl AsRef<str>) {
    emit(LogLevel::Debug, msg.as_ref());
}

// ————————————————————————————————————————————————————————————
// 配置
// ————————————————————————————————————————————————————————————

/// 解析后的启动配置
#[derive(Debug, Clone)]
pub struct ServerOpts {
    /// DHT UDP 绑定地址（`SocketAddr` 形态，如 `0.0.0.0:11010`）
    pub bind: String,
    /// STUN/观察者端口（None = 关闭）
    pub stun: Option<u16>,
    /// TCP 信令端口（None = 关闭）
    pub tcp: Option<u16>,
    /// 贡献模式（家庭带宽）：拒绝 Forward 中转
    pub hobby: bool,
    /// 观察者每 IP 每窗口响应上限
    pub observer_rate_limit: u32,
    /// 观察者限频窗口（秒）
    pub observer_rate_window_secs: u64,
    /// 身份文件路径
    pub identity_file: PathBuf,
    /// 日志级别
    pub log_level: LogLevel,
}

impl ServerOpts {
    /// 观察者限频策略（注入内核）
    pub fn observer_policy(&self) -> ObserverPolicy {
        ObserverPolicy {
            rate_limit: self.observer_rate_limit,
            rate_window: Duration::from_secs(self.observer_rate_window_secs),
        }
    }
}

/// 原始输入（配置来源分层；便于纯函数测试）
#[derive(Debug, Default, Clone)]
pub struct RawInput {
    /// 配置文件键值（已小写归一，`-`→`_`）
    pub file: Vec<(String, String)>,
    /// 环境变量键值（已去掉 `WGP_` 前缀并小写归一）
    pub env: Vec<(String, String)>,
    /// 命令行参数（不含 argv[0]）
    pub argv: Vec<String>,
}

/// 解析极简 `key = value` 配置文本。
/// 支持 `#`/`;` 行内注释、空行、键名小写归一（`-`→`_`）。
pub fn parse_config_text(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let no_comment = raw.split(['#', ';']).next().unwrap_or("");
        let line = no_comment.trim();
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("配置文件第 {} 行缺少 '='：{}", i + 1, raw.trim()))?;
        let key = k.trim().to_ascii_lowercase().replace('-', "_");
        if key.is_empty() {
            return Err(format!("配置文件第 {} 行键名为空", i + 1));
        }
        out.push((key, v.trim().to_string()));
    }
    Ok(out)
}

fn parse_bool(key: &str, v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{key} 需要布尔值（true/false），得到：{v}")),
    }
}

fn parse_port(key: &str, v: &str) -> Result<Option<u16>, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "" | "none" | "off" | "disable" | "disabled" => Ok(None),
        _ => v
            .trim()
            .parse::<u16>()
            .map(Some)
            .map_err(|_| format!("{key} 端口非法（应为 1-65535 或 none）：{v}")),
    }
}

fn parse_u32(key: &str, v: &str) -> Result<u32, String> {
    v.trim()
        .parse::<u32>()
        .map_err(|_| format!("{key} 需要无符号整数，得到：{v}"))
}

fn parse_u64(key: &str, v: &str) -> Result<u64, String> {
    v.trim()
        .parse::<u64>()
        .map_err(|_| format!("{key} 需要无符号整数，得到：{v}"))
}

const BOOL_FLAGS: [&str; 4] = ["hobby", "no_hobby", "help", "version"];

/// 把各来源合并为最终配置。纯函数，不读进程环境（便于测试）。
pub fn resolve_opts(force_hobby: bool, input: &RawInput) -> Result<ServerOpts, String> {
    // 分层覆盖：文件 < 环境 < 命令行
    let mut m: HashMap<String, String> = HashMap::new();
    for (k, v) in &input.file {
        m.insert(k.clone(), v.clone());
    }
    for (k, v) in &input.env {
        m.insert(k.clone(), v.clone());
    }

    let mut it = input.argv.iter();
    while let Some(arg) = it.next() {
        if let Some(rest) = arg.strip_prefix("--") {
            let (raw_key, val) = match rest.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => {
                    let k = rest.to_string();
                    if BOOL_FLAGS.contains(&k.replace('-', "_").to_ascii_lowercase().as_str()) {
                        (k, "true".to_string())
                    } else {
                        let v = it
                            .next()
                            .ok_or_else(|| format!("--{k} 缺少参数值"))?
                            .clone();
                        (k, v)
                    }
                }
            };
            let mut key = raw_key.to_ascii_lowercase().replace('-', "_");
            let mut val = val;
            if key == "no_hobby" {
                key = "hobby".to_string();
                val = "false".to_string();
            }
            m.insert(key, val);
        } else if let Some(short) = arg.strip_prefix('-') {
            match short {
                "h" => {
                    m.insert("help".to_string(), "true".to_string());
                }
                "V" => {
                    m.insert("version".to_string(), "true".to_string());
                }
                _ => return Err(format!("未知选项：{arg}")),
            }
        } else {
            // 向后兼容旧的位置参数：首位视作 bind
            m.entry("bind".to_string()).or_insert_with(|| arg.clone());
        }
    }

    let bind = m
        .get("bind")
        .cloned()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    if bind.parse::<std::net::SocketAddr>().is_err() {
        return Err(format!("bind 非法（应为 IP:端口，如 {DEFAULT_BIND}）：{bind}"));
    }

    let stun = match m.get("stun") {
        Some(v) => parse_port("stun", v)?,
        None => Some(DEFAULT_STUN_PORT),
    };
    let tcp = match m.get("tcp") {
        Some(v) => parse_port("tcp", v)?,
        None => Some(DEFAULT_TCP_PORT),
    };

    let hobby = if force_hobby {
        true
    } else {
        match m.get("hobby") {
            Some(v) => parse_bool("hobby", v)?,
            None => false,
        }
    };

    let observer_rate_limit = match m.get("observer_rate_limit") {
        Some(v) => parse_u32("observer_rate_limit", v)?,
        None => wgp_dht::OBSERVER_RATE_LIMIT,
    };
    if observer_rate_limit == 0 {
        return Err("observer_rate_limit 必须 >= 1（0 会关闭观察者应答）".to_string());
    }
    let observer_rate_window_secs = match m.get("observer_rate_window") {
        Some(v) => parse_u64("observer_rate_window", v)?,
        None => wgp_dht::OBSERVER_RATE_WINDOW.as_secs(),
    };
    if observer_rate_window_secs == 0 {
        return Err("observer_rate_window 必须 >= 1 秒".to_string());
    }

    let identity_file = m
        .get("identity")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(IDENTITY_FILE));

    let log_level = match m.get("log_level") {
        Some(v) => LogLevel::parse(v)
            .ok_or_else(|| format!("log_level 非法（error/warn/info/debug）：{v}"))?,
        None => LogLevel::Info,
    };

    Ok(ServerOpts {
        bind,
        stun,
        tcp,
        hobby,
        observer_rate_limit,
        observer_rate_window_secs,
        identity_file,
        log_level,
    })
}

/// 从命令行/环境变量定位配置文件路径（不加载）
fn find_config_path(argv: &[String]) -> Option<PathBuf> {
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--config=") {
            return Some(PathBuf::from(v));
        }
        if a == "--config" {
            return it.next().map(PathBuf::from);
        }
    }
    if let Ok(v) = env::var(format!("{ENV_PREFIX}CONFIG")) {
        if !v.trim().is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    None
}

fn collect_env() -> Vec<(String, String)> {
    const KEYS: [&str; 9] = [
        "BIND",
        "STUN",
        "TCP",
        "HOBBY",
        "OBSERVER_RATE_LIMIT",
        "OBSERVER_RATE_WINDOW",
        "IDENTITY",
        "LOG_LEVEL",
        "CONFIG",
    ];
    KEYS.iter()
        .filter_map(|k| {
            env::var(format!("{ENV_PREFIX}{k}"))
                .ok()
                .map(|v| (k.to_ascii_lowercase(), v))
        })
        .collect()
}

/// 解析命令行 + 环境变量 + 配置文件（见模块文档的优先级）。
pub fn parse_args(force_hobby: bool, argv: &[String]) -> Result<ServerOpts, String> {
    let file = match find_config_path(argv) {
        Some(p) => {
            let text = fs::read_to_string(&p)
                .map_err(|e| format!("读取配置文件 {} 失败：{e}", p.display()))?;
            parse_config_text(&text)?
        }
        None => {
            let def = Path::new(DEFAULT_CONFIG_FILE);
            if def.exists() {
                let text = fs::read_to_string(def)
                    .map_err(|e| format!("读取默认配置 {} 失败：{e}", def.display()))?;
                parse_config_text(&text)?
            } else {
                Vec::new()
            }
        }
    };
    resolve_opts(
        force_hobby,
        &RawInput {
            file,
            env: collect_env(),
            argv: argv.to_vec(),
        },
    )
}

/// 用法说明
pub fn usage(profile: &str) -> String {
    format!(
        "折跃门服务端节点 {profile}\n\
用法：{profile} [选项]\n\n\
选项：\n\
  --bind <addr>                      DHT UDP 绑定地址（默认 {DEFAULT_BIND}）\n\
  --stun <port|none>                 观察者/STUN 端口（默认 {DEFAULT_STUN_PORT}；none 关闭）\n\
  --tcp <port|none>                  TCP 信令兜底端口（默认 {DEFAULT_TCP_PORT}；none 关闭）\n\
  --hobby / --no-hobby               贡献模式：拒绝 Forward 中转（PCDN 防护）\n\
  --observer-rate-limit <n>          观察者每 IP 每窗口响应上限（默认 {limit}）\n\
  --observer-rate-window <secs>      观察者限频窗口秒数（默认 {window}）\n\
  --identity <path>                  节点身份文件（默认 {IDENTITY_FILE}）\n\
  --config <path>                    配置文件（key = value，默认自动加载 {DEFAULT_CONFIG_FILE}）\n\
  --log-level <error|warn|info|debug>  日志级别（默认 info）\n\
  -h, --help                         显示本帮助\n\
  -V, --version                      显示版本\n\n\
环境变量：WGP_BIND / WGP_STUN / WGP_TCP / WGP_HOBBY /\n\
          WGP_OBSERVER_RATE_LIMIT / WGP_OBSERVER_RATE_WINDOW /\n\
          WGP_IDENTITY / WGP_LOG_LEVEL / WGP_CONFIG\n\
优先级：命令行 > 环境变量 > 配置文件 > 默认值",
        limit = wgp_dht::OBSERVER_RATE_LIMIT,
        window = wgp_dht::OBSERVER_RATE_WINDOW.as_secs(),
    )
}

// ————————————————————————————————————————————————————————————
// 身份
// ————————————————————————————————————————————————————————————

/// 载入或生成节点身份（07 §8：身份漂移 = DHT 键散乱 + 日蚀风险）。
/// 身份文件存在但长度非法时**拒绝启动**（宁可人工确认，也不静默换身份）。
pub fn load_or_create_identity(path: &Path) -> Result<NodeIdentity, String> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(format!(
                    "身份文件 {} 长度非法（{} 字节，应为 32）。为避免身份漂移，请人工确认后删除该文件再重启",
                    path.display(),
                    bytes.len()
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(NodeIdentity::from_seed(seed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use rand_core::OsRng;
            let identity = NodeIdentity::generate(&mut OsRng);
            persist_identity(path, &identity.to_seed())?;
            Ok(identity)
        }
        Err(e) => Err(format!("读取身份文件 {} 失败：{e}", path.display())),
    }
}

/// 原子落盘身份（临时文件 + rename；Unix 下 chmod 600）
fn persist_identity(path: &Path, seed: &[u8; 32]) -> Result<(), String> {
    let tmp: PathBuf = match path.extension() {
        Some(_) => path.with_extension("tmp"),
        None => PathBuf::from(format!("{}.tmp", path.display())),
    };
    fs::write(&tmp, seed).map_err(|e| format!("写入身份临时文件 {} 失败：{e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("落盘身份文件 {} 失败：{e}", path.display()));
    }
    Ok(())
}

// ————————————————————————————————————————————————————————————
// 运行
// ————————————————————————————————————————————————————————————

/// 等待退出信号：Unix 下同时响应 SIGTERM（systemd 默认）与 SIGINT；其他平台仅 Ctrl-C。
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut intr)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = intr.recv() => {}
                }
            }
            _ => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// 启动服务端并常驻至退出信号。
/// `profile` 仅用于日志标识；`force_hobby` 决定是否强制贡献模式（家庭宽带版）。
pub async fn run(profile: &str, force_hobby: bool) {
    let argv: Vec<String> = env::args().skip(1).collect();

    if argv.iter().any(|a| a == "-h" || a == "--help" || a == "help") {
        println!("{}", usage(profile));
        return;
    }
    if argv.iter().any(|a| a == "-V" || a == "--version") {
        println!("{profile} {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let opts = match parse_args(force_hobby, &argv) {
        Ok(o) => o,
        Err(e) => {
            // stderr 无缓冲：即便随后 exit 也不会丢日志
            eprintln!("[{profile}] 配置错误：{e}");
            eprintln!("[{profile}] 运行 `{profile} --help` 查看用法。");
            std::process::exit(2);
        }
    };
    set_log_level(opts.log_level);

    let identity = match load_or_create_identity(&opts.identity_file) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("[{profile}] 身份初始化失败：{e}");
            std::process::exit(3);
        }
    };
    let node_id = identity.node_id();

    log_info(format!(
        "{profile} 启动中 | bind={} | stun={} | tcp={} | 模式={} | 观察者限频={}/{}s | 身份={}",
        opts.bind,
        opts.stun.map(|p| p.to_string()).unwrap_or_else(|| "off".into()),
        opts.tcp.map(|p| p.to_string()).unwrap_or_else(|| "off".into()),
        if opts.hobby { "贡献(PCDN防护)" } else { "完整" },
        opts.observer_rate_limit,
        opts.observer_rate_window_secs,
        opts.identity_file.display(),
    ));

    let (engine, _events) = Engine::new();
    let cfg = NodeConfig {
        role: NodeRole::Seed,
        bind: opts.bind.clone(),
        stun: opts.stun,
        tcp_signal: opts.tcp,
        hobby: opts.hobby,
        observer_policy: opts.observer_policy(),
    };

    // 四职中的网络面：DHT（含承诺转发兜底）+ 观察者（STUN）+ TCP 信令兜底
    let node = engine.run_node(cfg, identity).await;

    // 绑定失败 = 致命：服务端不允许"假装在线"地降级空转（否则运维误判为健康）
    if node.dht.is_none() {
        eprintln!(
            "[{profile}] 致命：DHT 绑定失败 {}（端口被占用或权限不足），进程退出",
            opts.bind
        );
        std::process::exit(1);
    }
    if opts.stun.is_some() && node.observer.is_none() {
        eprintln!(
            "[{profile}] 致命：观察者绑定失败（端口 {:?}），进程退出",
            opts.stun
        );
        std::process::exit(1);
    }
    if opts.tcp.is_some() && node.tcp.is_none() {
        eprintln!(
            "[{profile}] 致命：TCP 信令绑定失败（端口 {:?}），进程退出",
            opts.tcp
        );
        std::process::exit(1);
    }

    let dht_text = format!("DHT bind={}", opts.bind);
    let stun_text = match &node.observer {
        Some(o) => format!("STUN=:{}", o.local_addr().map(|a| a.port()).unwrap_or(0)),
        None => "STUN=off".to_string(),
    };
    let tcp_text = match node.tcp {
        Some(a) => format!("TCP=:{}", a.port()),
        None => "TCP=off".to_string(),
    };
    let relay_text = if opts.hobby {
        "贡献模式：拒绝 Forward 中转（PCDN 防护）"
    } else {
        "完整模式：允许 Forward 中转"
    };
    log_info(format!(
        "{profile} 已就绪（种子+观察者+承诺兜底）| node_id={:02x?} | {dht_text} | {stun_text} | {tcp_text} | {relay_text}",
        &node_id.0[..4]
    ));

    wait_for_shutdown().await;
    log_info(format!("{profile} 收到退出信号，关闭中。"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(file: &[(&str, &str)], env: &[(&str, &str)], argv: &[&str]) -> RawInput {
        RawInput {
            file: file.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn defaults_are_seed_full_profile() {
        let o = resolve_opts(false, &raw(&[], &[], &[])).unwrap();
        assert_eq!(o.bind, DEFAULT_BIND);
        assert_eq!(o.stun, Some(DEFAULT_STUN_PORT));
        assert_eq!(o.tcp, Some(DEFAULT_TCP_PORT));
        assert!(!o.hobby);
        assert_eq!(o.observer_rate_limit, wgp_dht::OBSERVER_RATE_LIMIT);
        assert_eq!(
            o.observer_rate_window_secs,
            wgp_dht::OBSERVER_RATE_WINDOW.as_secs()
        );
        assert_eq!(o.identity_file, PathBuf::from(IDENTITY_FILE));
        assert_eq!(o.log_level, LogLevel::Info);
    }

    #[test]
    fn precedence_cli_over_env_over_file() {
        let input = raw(
            &[("bind", "10.0.0.1:11010"), ("stun", "5000")],
            &[("bind", "10.0.0.2:11010"), ("tcp", "6000")],
            &["--bind", "10.0.0.3:11010"],
        );
        let o = resolve_opts(false, &input).unwrap();
        assert_eq!(o.bind, "10.0.0.3:11010"); // CLI 胜出
        assert_eq!(o.stun, Some(5000)); // 仅文件提供
        assert_eq!(o.tcp, Some(6000)); // 环境变量提供
    }

    #[test]
    fn flag_equals_form_and_none_ports() {
        let o = resolve_opts(
            false,
            &raw(&[], &[], &["--bind=0.0.0.0:12000", "--stun=none", "--tcp", "off"]),
        )
        .unwrap();
        assert_eq!(o.bind, "0.0.0.0:12000");
        assert_eq!(o.stun, None);
        assert_eq!(o.tcp, None);
    }

    #[test]
    fn hobby_flag_and_force_hobby() {
        assert!(resolve_opts(false, &raw(&[], &[], &["--hobby"])).unwrap().hobby);
        assert!(!resolve_opts(false, &raw(&[], &[], &["--no-hobby"])).unwrap().hobby);
        // force_hobby（家庭宽带版）恒为真，且不被 --no-hobby 覆盖
        assert!(resolve_opts(true, &raw(&[], &[], &["--no-hobby"])).unwrap().hobby);
        assert!(resolve_opts(true, &raw(&[], &[], &[])).unwrap().hobby);
    }

    #[test]
    fn invalid_bind_is_rejected() {
        let e = resolve_opts(false, &raw(&[], &[], &["--bind", "not-an-addr"])).unwrap_err();
        assert!(e.contains("bind 非法"), "{e}");
    }

    #[test]
    fn invalid_port_is_rejected_not_silently_defaulted() {
        let e = resolve_opts(false, &raw(&[], &[], &["--stun", "70000"])).unwrap_err();
        assert!(e.contains("端口非法"), "{e}");
        let e2 = resolve_opts(false, &raw(&[], &[], &["--tcp", "abc"])).unwrap_err();
        assert!(e2.contains("端口非法"), "{e2}");
    }

    #[test]
    fn zero_rate_limit_rejected() {
        assert!(resolve_opts(false, &raw(&[], &[], &["--observer-rate-limit", "0"])).is_err());
        assert!(resolve_opts(false, &raw(&[], &[], &["--observer-rate-window", "0"])).is_err());
    }

    #[test]
    fn observer_policy_is_injected() {
        let o = resolve_opts(
            false,
            &raw(&[], &[], &["--observer-rate-limit", "30", "--observer-rate-window", "5"]),
        )
        .unwrap();
        let p = o.observer_policy();
        assert_eq!(p.rate_limit, 30);
        assert_eq!(p.rate_window, Duration::from_secs(5));
    }

    #[test]
    fn bad_bool_and_log_level_rejected() {
        assert!(resolve_opts(false, &raw(&[], &[], &["--hobby", "maybe"])).is_err());
        assert!(resolve_opts(false, &raw(&[], &[], &["--log-level", "loud"])).is_err());
        let o = resolve_opts(false, &raw(&[], &[], &["--log-level", "debug"])).unwrap();
        assert_eq!(o.log_level, LogLevel::Debug);
    }

    #[test]
    fn unknown_short_option_rejected() {
        assert!(resolve_opts(false, &raw(&[], &[], &["-x"])).is_err());
    }

    #[test]
    fn positional_bind_is_backward_compatible() {
        let o = resolve_opts(false, &raw(&[], &[], &["0.0.0.0:9999"])).unwrap();
        assert_eq!(o.bind, "0.0.0.0:9999");
    }

    #[test]
    fn config_text_parsing() {
        let kv = parse_config_text(
            "# 注释行\nbind = 0.0.0.0:11010  # 行内注释\n\nstun=3478 ; 也是注释\ntcp = none\n",
        )
        .unwrap();
        assert_eq!(
            kv,
            vec![
                ("bind".to_string(), "0.0.0.0:11010".to_string()),
                ("stun".to_string(), "3478".to_string()),
                ("tcp".to_string(), "none".to_string()),
            ]
        );
        assert!(parse_config_text("bind 0.0.0.0:1").is_err());
    }

    #[test]
    fn identity_roundtrip_and_corruption_detected() {
        let dir = std::env::temp_dir().join(format!("wgp-node-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("node_identity.key");
        let _ = fs::remove_file(&path);

        let a = load_or_create_identity(&path).unwrap();
        let b = load_or_create_identity(&path).unwrap();
        assert_eq!(a.node_id(), b.node_id(), "重启必须复用同一身份");

        fs::write(&path, [0u8; 8]).unwrap();
        assert!(
            load_or_create_identity(&path).is_err(),
            "长度非法必须拒绝启动"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_mentions_env_and_precedence() {
        let u = usage("wgp-node");
        assert!(u.contains("WGP_BIND"));
        assert!(u.contains("优先级"));
    }
}
