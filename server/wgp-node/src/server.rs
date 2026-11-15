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
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use wgp_core::{Engine, NodeConfig, NodeRole};
use wgp_dht::{NodeIdentity, ObserverPolicy};
use wgp_proto::{SeedEndpoint, SeedScheme};

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
/// 入网引导端点数上限（与内核的入口端点上限一致）
pub const MAX_PEERS: usize = 16;

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
    /// 对外宣告的公网 IPv4（None = 不宣告）
    pub advertise: Option<Ipv4Addr>,
    /// 入网引导端点（其他种子的 UDP 信令地址；域名在启动时解析）
    pub peers: Vec<SeedEndpoint>,
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

    let mut cli_peers: Vec<String> = Vec::new();
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
            if key == "peer" || key == "peers" {
                // 可重复给出：命令行上的多次 --peers 累加（整体仍覆盖环境变量 / 配置文件）
                cli_peers.push(val);
                continue;
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
    if !cli_peers.is_empty() {
        m.insert("peers".to_string(), cli_peers.join(","));
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

    let advertise = match m.get("advertise").map(|v| v.trim()) {
        None | Some("") => None,
        Some(v) if matches!(v.to_ascii_lowercase().as_str(), "none" | "off") => None,
        Some(v) => {
            let ip = v.parse::<Ipv4Addr>().map_err(|_| {
                format!("advertise 非法（应为本节点的公网 IPv4 地址，如 203.0.113.7；不支持域名）：{v}")
            })?;
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                return Err(format!("advertise 不能是 {ip}：别的节点无法用它连到本节点"));
            }
            Some(ip)
        }
    };

    let peers = match m.get("peers") {
        Some(v) => {
            let (peers, bad) = SeedEndpoint::parse_list(v);
            if let Some(b) = bad.first() {
                return Err(format!("peers 含非法端点（应为 udp://主机:端口）：{b}"));
            }
            if let Some(tcp) = peers.iter().find(|ep| ep.scheme != SeedScheme::Udp) {
                return Err(format!(
                    "peers 只支持 UDP 端点（种子之间走 UDP 信令）：{}",
                    tcp.display()
                ));
            }
            if peers.len() > MAX_PEERS {
                return Err(format!("peers 最多 {MAX_PEERS} 个，得到 {} 个", peers.len()));
            }
            peers
        }
        None => Vec::new(),
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
        advertise,
        peers,
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
    const KEYS: [&str; 11] = [
        "BIND",
        "STUN",
        "TCP",
        "HOBBY",
        "OBSERVER_RATE_LIMIT",
        "OBSERVER_RATE_WINDOW",
        "IDENTITY",
        "LOG_LEVEL",
        "CONFIG",
        "ADVERTISE",
        "PEERS",
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
  --advertise <ipv4|none>            对外宣告的公网 IPv4（默认不宣告）：宣告后其他节点与客户端可自动发现本节点\n\
  --peers <list>                     入网引导：其他种子的 udp://主机:端口，逗号分隔，可重复给出\n\
  --observer-rate-limit <n>          观察者每 IP 每窗口响应上限（默认 {limit}）\n\
  --observer-rate-window <secs>      观察者限频窗口秒数（默认 {window}）\n\
  --identity <path>                  节点身份文件（默认 {IDENTITY_FILE}）\n\
  --config <path>                    配置文件（key = value，默认自动加载 {DEFAULT_CONFIG_FILE}）\n\
  --log-level <error|warn|info|debug>  日志级别（默认 info）\n\
  -h, --help                         显示本帮助\n\
  -V, --version                      显示版本\n\n\
环境变量：WGP_BIND / WGP_STUN / WGP_TCP / WGP_HOBBY /\n\
          WGP_OBSERVER_RATE_LIMIT / WGP_OBSERVER_RATE_WINDOW /\n\
          WGP_IDENTITY / WGP_LOG_LEVEL / WGP_CONFIG /\n\
          WGP_ADVERTISE / WGP_PEERS\n\
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

/// 广告纪元文件：与身份文件同目录、同名，扩展名为 .epoch（如 node_identity.epoch）
pub fn epoch_file_for(identity_file: &Path) -> PathBuf {
    identity_file.with_extension("epoch")
}

/// 取本次启动的广告纪元并落盘（17 §5）。
///
/// 别的节点只采纳纪元更大的广告（挡重放），所以同一身份每次启动都要比上次大。项目禁读系统
/// 时钟（H5），这里用「启动计数」代替时间：文件里存上次的计数（十进制文本），本次 +1；
/// 纪元 = 启动计数 << 32，低 32 位留给进程内的广告修订。
///
/// 返回 (纪元, 可选的告警)。读不出或写不进都不阻止启动——后果只是已经认识本节点的人在一段时间内
/// 沿用旧广告，而不是节点不可用。
pub fn next_advertise_epoch(path: &Path) -> (u64, Option<String>) {
    let mut warning = None;
    let previous: u32 = match fs::read_to_string(path) {
        Ok(text) => text.trim().parse::<u32>().unwrap_or_else(|_| {
            warning = Some(format!(
                "广告纪元文件 {} 内容无法识别，已从头计数；其他节点可能在一段时间内沿用本节点的旧广告",
                path.display()
            ));
            0
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            warning = Some(format!(
                "读取广告纪元文件 {} 失败（{e}），已从头计数",
                path.display()
            ));
            0
        }
    };
    let boot = previous.saturating_add(1);

    let tmp = path.with_extension("epoch.tmp");
    let persisted = fs::write(&tmp, format!("{boot}\n")).and_then(|_| fs::rename(&tmp, path));
    if let Err(e) = persisted {
        let _ = fs::remove_file(&tmp);
        warning = Some(format!(
            "广告纪元无法写入 {}（{e}）：下次重启后，其他节点可能在一段时间内沿用本节点的旧广告",
            path.display()
        ));
    }
    (u64::from(boot) << 32, warning)
}

/// 解析一个引导端点（域名先经 IDN 归一化；只取 IPv4）
async fn resolve_peer(ep: &SeedEndpoint) -> Option<SocketAddr> {
    let host = ep.host_ascii();
    let mut addrs = tokio::net::lookup_host((host.as_str(), ep.port)).await.ok()?;
    addrs.find(|a| a.is_ipv4())
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

    // 入网引导端点：解析不了的跳过并告警（对端的域名暂时解析不出，不该拦住本节点启动）
    let mut peers: Vec<SocketAddr> = Vec::new();
    for ep in &opts.peers {
        match resolve_peer(ep).await {
            Some(addr) => peers.push(addr),
            None => log_warn(format!("引导端点 {} 无法解析，已跳过", ep.display())),
        }
    }
    let advertise_epoch = match opts.advertise {
        Some(_) => {
            let (epoch, warning) = next_advertise_epoch(&epoch_file_for(&opts.identity_file));
            if let Some(w) = warning {
                log_warn(w);
            }
            epoch
        }
        None => 0,
    };

    let (engine, _events) = Engine::new();
    let cfg = NodeConfig {
        role: NodeRole::Seed,
        bind: opts.bind.clone(),
        stun: opts.stun,
        tcp_signal: opts.tcp,
        hobby: opts.hobby,
        observer_policy: opts.observer_policy(),
        advertise: opts.advertise,
        advertise_epoch,
        peers: peers.clone(),
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
    match opts.advertise {
        Some(ip) => {
            log_info(format!(
                "对外宣告 {ip}（第 {} 次启动；{}）：其他节点与客户端可自动发现本节点",
                advertise_epoch >> 32,
                if opts.hobby { "声明不中转" } else { "声明可中转" },
            ));
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                log_warn(format!(
                    "宣告地址 {ip} 不是公网地址：只有本机 / 同一局域网内的节点能据此连到本节点"
                ));
            }
        }
        None => log_info("未配置 --advertise：本节点不对外宣告，只能靠手工填写地址找到"),
    }
    if !peers.is_empty() {
        let list: Vec<String> = peers.iter().map(|a| a.to_string()).collect();
        log_info(format!("入网引导端点：{}", list.join(", ")));
    }

    // 种子目录有变化就记一笔（运维可见性：谁被发现了、谁失联了）
    if let Some(dht) = node.dht.clone() {
        tokio::spawn(async move {
            let mut changes = dht.watch_seeds();
            let mut logged: Vec<String> = Vec::new();
            loop {
                // 先读后等：订阅之前已经发生的变化也不会漏；只在成员确实变了时才记
                let mut list: Vec<String> = dht
                    .seeds()
                    .await
                    .iter()
                    .map(|s| format!("{}{}", s.addr, if s.relays() { "" } else { "(不中转)" }))
                    .collect();
                list.sort();
                if list != logged {
                    log_info(format!("种子目录：{} 个 [{}]", list.len(), list.join(", ")));
                    logged = list;
                }
                if changes.changed().await.is_err() {
                    break;
                }
            }
        });
    }

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
    fn advertise_and_peers_default_to_off() {
        let o = resolve_opts(false, &raw(&[], &[], &[])).unwrap();
        assert_eq!(o.advertise, None);
        assert!(o.peers.is_empty());
    }

    #[test]
    fn advertise_is_parsed_and_validated() {
        let o = resolve_opts(false, &raw(&[], &[], &["--advertise", "203.0.113.7"])).unwrap();
        assert_eq!(o.advertise, Some(Ipv4Addr::new(203, 0, 113, 7)));
        // 关闭写法：命令行的 none 覆盖配置文件里的地址
        let o = resolve_opts(
            false,
            &raw(&[("advertise", "203.0.113.7")], &[], &["--advertise=none"]),
        )
        .unwrap();
        assert_eq!(o.advertise, None);
        // 域名、越界、不可用地址：启动即报错，而不是带着一个谁也连不上的地址去宣告
        for bad in ["seed.example.com", "999.1.1.1", "0.0.0.0", "255.255.255.255", "224.0.0.1"] {
            let e = resolve_opts(false, &raw(&[], &[], &["--advertise", bad])).unwrap_err();
            assert!(e.contains("advertise"), "{bad}: {e}");
        }
    }

    #[test]
    fn peers_accumulate_on_cli_and_override_lower_layers() {
        // 配置文件 / 环境变量：单个值内用逗号分隔
        let o = resolve_opts(
            false,
            &raw(&[("peers", "udp://a.example:11010, b.example:11011")], &[], &[]),
        )
        .unwrap();
        let shown: Vec<String> = o.peers.iter().map(|p| p.display()).collect();
        assert_eq!(shown, vec!["udp://a.example:11010", "udp://b.example:11011"]);

        // 命令行：--peers / --peer 可重复给出并累加；整体覆盖环境变量与配置文件
        let o = resolve_opts(
            false,
            &raw(
                &[("peers", "udp://file.example:1")],
                &[("peers", "udp://env.example:2")],
                &["--peers", "udp://x.example:3", "--peer=198.51.100.4:4"],
            ),
        )
        .unwrap();
        let shown: Vec<String> = o.peers.iter().map(|p| p.display()).collect();
        assert_eq!(shown, vec!["udp://x.example:3", "udp://198.51.100.4:4"]);
    }

    #[test]
    fn bad_peers_are_rejected() {
        let err = |v: &str| resolve_opts(false, &raw(&[], &[], &["--peers", v])).unwrap_err();
        assert!(err("http://x.example:1").contains("非法端点"));
        assert!(err("udp://x.example").contains("非法端点"), "缺端口");
        assert!(err("tcp://x.example:3481").contains("UDP"), "种子间信令只走 UDP");
        let many: Vec<String> = (0..=MAX_PEERS).map(|i| format!("udp://198.51.100.1:{}", 1000 + i)).collect();
        assert!(err(&many.join(",")).contains("最多"));
    }

    #[test]
    fn advertise_epoch_strictly_increases_across_restarts() {
        let dir = std::env::temp_dir().join(format!("wgp-node-epoch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = epoch_file_for(&dir.join("node_identity.key"));
        assert_eq!(path.file_name().unwrap(), "node_identity.epoch");

        // 连续三次「启动」：纪元严格递增，且低 32 位留空
        let (first, w1) = next_advertise_epoch(&path);
        let (second, w2) = next_advertise_epoch(&path);
        let (third, w3) = next_advertise_epoch(&path);
        assert!(w1.is_none() && w2.is_none() && w3.is_none());
        assert_eq!((first >> 32, second >> 32, third >> 32), (1, 2, 3));
        assert_eq!(first & 0xFFFF_FFFF, 0);
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "3");

        // 文件损坏：给出告警并从头计数，不阻止启动
        fs::write(&path, "not-a-number").unwrap();
        let (reset, warning) = next_advertise_epoch(&path);
        assert_eq!(reset >> 32, 1);
        assert!(warning.unwrap().contains("无法识别"));

        // 写不进去（目录不存在）：仍返回可用的纪元，并告警
        let (epoch, warning) = next_advertise_epoch(&dir.join("missing").join("x.epoch"));
        assert_eq!(epoch >> 32, 1);
        assert!(warning.unwrap().contains("无法写入"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_mentions_env_and_precedence() {
        let u = usage("wgp-node");
        assert!(u.contains("WGP_BIND"));
        assert!(u.contains("优先级"));
    }
}
