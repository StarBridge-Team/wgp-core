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
use wgp_core::{AdvertisePorts, AdvertiseTarget, Engine, NodeConfig, NodeRole};
use wgp_dht::{EndpointScope, NodeIdentity, ObserverPolicy};
use wgp_proto::{SeedEndpoint, SeedScheme};

/// Tokio worker cap for mostly-I/O node runtimes. Set WGP_RUNTIME_WORKERS to override.
pub fn runtime_worker_threads() -> usize {
    runtime_worker_threads_for(
        env::var("WGP_RUNTIME_WORKERS").ok().as_deref(),
        std::thread::available_parallelism().map_or(2, |n| n.get()),
    )
}

fn runtime_worker_threads_for(configured: Option<&str>, available: usize) -> usize {
    configured
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|workers| (1..=64).contains(workers))
        .unwrap_or_else(|| available.max(1).min(4))
}

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

/// 对外宣告的来源。
///
/// 三种部署形态各有各的写法（见 `项目完整文档/21-种子节点部署（VPS-FRP-NAT-DDNS）.md`）：
/// - [`AdvertiseSource::Fixed`]：VPS / 有固定公网 IPv4 的机器，直接写字面地址；
/// - [`AdvertiseSource::Dns`]：DDNS（家宽动态 IP、云主机弹性 IP）。启动时解析，之后按
///   `--ddns-refresh` 周期重解析，**解析结果变了就换纪元重新宣告**——否则已经认识本节点的
///   人会在老地址上探活到失败为止；
/// - [`AdvertiseSource::Off`]：不宣告（NAT 后面的 hobby 节点、只做客户端的节点）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertiseSource {
    Off,
    /// 固定 IPv4
    Fixed(Ipv4Addr),
    /// 域名（DDNS）：内核不解析域名，解析在本层完成
    Dns(String),
}

impl AdvertiseSource {
    pub fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }

    /// 运维展示用
    pub fn display(&self) -> String {
        match self {
            Self::Off => "off".to_string(),
            Self::Fixed(ip) => ip.to_string(),
            Self::Dns(host) => format!("{host}（DDNS）"),
        }
    }
}

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
    /// 身份证明兼容策略（17 §11.6）：true = 允许回退到旧 PING/PONG 学习。
    /// 默认 false（严格）——旧协议只用于存活诊断，绝不写路由表/地址簿。
    pub allow_legacy_identity: bool,
    /// 观察者每 IP 每窗口响应上限
    pub observer_rate_limit: u32,
    /// 观察者限频窗口（秒）
    pub observer_rate_window_secs: u64,
    /// 身份文件路径
    pub identity_file: PathBuf,
    /// 日志级别
    pub log_level: LogLevel,
    /// 对外宣告来源（Off / 固定 IPv4 / DDNS 域名）
    pub advertise: AdvertiseSource,
    /// 对外端口（0 = 沿用本机实际绑定端口）；FRP / 端口映射部署用
    pub advertise_ports: AdvertisePorts,
    /// DDNS 域名的重解析周期（秒；0 = 只在启动时解析一次）
    pub ddns_refresh_secs: u64,
    /// 是否接受回环/私网端点（本机与局域网联调、FRP 落在内网）
    pub allow_local_endpoints: bool,
    /// 是否识别前置代理注入的 PROXY protocol v2（FRP / nginx stream / 云 LB 后面）
    pub proxy_protocol: bool,
    /// 入网引导端点（其他种子的 UDP 信令地址；域名在启动时解析）
    pub peers: Vec<SeedEndpoint>,
}

impl ServerOpts {
    /// 观察者限频策略（注入内核）
    pub fn observer_policy(&self) -> ObserverPolicy {
        ObserverPolicy {
            rate_limit: self.observer_rate_limit,
            rate_window: Duration::from_secs(self.observer_rate_window_secs),
            proxy_protocol: self.proxy_protocol,
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

const BOOL_FLAGS: [&str; 6] = [
    "hobby",
    "no_hobby",
    "allow_legacy_identity",
    "allow_local_endpoints",
    "help",
    "version",
];

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
        return Err(format!(
            "bind 非法（应为 IP:端口，如 {DEFAULT_BIND}）：{bind}"
        ));
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

    // 身份证明兼容策略（17 §11.6）：默认严格，旧 PING/PONG 只用于存活诊断
    let allow_legacy_identity = match m.get("allow_legacy_identity") {
        Some(v) => parse_bool("allow_legacy_identity", v)?,
        None => false,
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
        None | Some("") => AdvertiseSource::Off,
        Some(v) if matches!(v.to_ascii_lowercase().as_str(), "none" | "off") => AdvertiseSource::Off,
        Some(v) => match v.parse::<Ipv4Addr>() {
            Ok(ip) => {
                if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                    return Err(format!("advertise 不能是 {ip}：别的节点无法用它连到本节点"));
                }
                AdvertiseSource::Fixed(ip)
            }
            Err(_) => {
                // 域名（DDNS）：只做格式校验，解析在启动时进行（此刻可能还没解析出来）
                if !is_plausible_hostname(v) {
                    return Err(format!(
                        "advertise 非法：既不是 IPv4 地址也不是合法域名（如 203.0.113.7 / seed.example.com）：{v}"
                    ));
                }
                AdvertiseSource::Dns(v.to_ascii_lowercase())
            }
        },
    };

    // 对外端口（FRP / 端口映射）：0 = 沿用本机实际端口
    let ext_port = |key: &str| -> Result<u16, String> {
        match m.get(key) {
            Some(v) => v
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("{key} 端口非法（应为 0-65535，0 = 沿用本机端口）：{v}")),
            None => Ok(0),
        }
    };
    let advertise_ports = AdvertisePorts {
        dht: ext_port("advertise_dht_port")?,
        stun: ext_port("advertise_stun_port")?,
        tcp: ext_port("advertise_tcp_port")?,
    };
    if advertise.is_off()
        && (advertise_ports.dht != 0 || advertise_ports.stun != 0 || advertise_ports.tcp != 0)
    {
        return Err(
            "配置了对外端口（advertise_*_port）但没有 --advertise：这些端口不会写进任何广告"
                .to_string(),
        );
    }
    // 本机没开的能力，对外端口写了也没意义——直接拒绝，避免广告里出现「指向空端口」的端点
    if advertise_ports.stun != 0 && stun.is_none() {
        return Err("advertise_stun_port 已配置但本机 --stun 已关闭".to_string());
    }
    if advertise_ports.tcp != 0 && tcp.is_none() {
        return Err("advertise_tcp_port 已配置但本机 --tcp 已关闭".to_string());
    }

    let ddns_refresh_secs = match m.get("ddns_refresh") {
        Some(v) => parse_u64("ddns_refresh", v)?,
        // 默认 5 分钟：家宽 IP 变动通常以小时计，5 分钟足够快，也远低于 DDNS 服务商限频
        None => 300,
    };

    let allow_local_endpoints = match m.get("allow_local_endpoints") {
        Some(v) => parse_bool("allow_local_endpoints", v)?,
        None => false,
    };

    // 前置代理（FRP / nginx stream / 云 LB）注入 PROXY protocol v2 时打开：
    // 观察者与 TCP 信令会先剥掉这段头，用头里的真实客户端地址出映射报告。
    // 只支持 v2；v1 是文本协议、这里不解析。
    let proxy_protocol = match m.get("proxy_protocol").map(|v| v.trim().to_ascii_lowercase()) {
        None => false,
        Some(v) if matches!(v.as_str(), "" | "off" | "none" | "false" | "0") => false,
        Some(v) if matches!(v.as_str(), "v2" | "2" | "on" | "true" | "1") => true,
        Some(v) if v == "v1" => {
            return Err(
                "proxy_protocol 只支持 v2（v1 是文本协议，本实现不解析）：请在前置代理侧改用 v2"
                    .to_string(),
            )
        }
        Some(v) => {
            return Err(format!(
                "proxy_protocol 非法（off | v2）：{v}"
            ))
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
                return Err(format!(
                    "peers 最多 {MAX_PEERS} 个，得到 {} 个",
                    peers.len()
                ));
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
        allow_legacy_identity,
        observer_rate_limit,
        observer_rate_window_secs,
        identity_file,
        log_level,
        advertise,
        advertise_ports,
        ddns_refresh_secs,
        allow_local_endpoints,
        proxy_protocol,
        peers,
    })
}

/// 域名的**格式**校验（不做解析）：标签 1-63 字符、字母数字与连字符、首尾不为连字符，
/// 至少两段且顶级域至少两个字母。IDN 由调用方先转 punycode（本层只管 ASCII）。
fn is_plausible_hostname(host: &str) -> bool {
    const MAX_HOST: usize = 253;
    if host.is_empty() || host.len() > MAX_HOST {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
    }
    let tld = labels.last().unwrap();
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
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
    const KEYS: [&str; 18] = [
        "BIND",
        "STUN",
        "TCP",
        "HOBBY",
        "ALLOW_LEGACY_IDENTITY",
        "OBSERVER_RATE_LIMIT",
        "OBSERVER_RATE_WINDOW",
        "IDENTITY",
        "LOG_LEVEL",
        "CONFIG",
        "ADVERTISE",
        "ADVERTISE_DHT_PORT",
        "ADVERTISE_STUN_PORT",
        "ADVERTISE_TCP_PORT",
        "DDNS_REFRESH",
        "ALLOW_LOCAL_ENDPOINTS",
        "PROXY_PROTOCOL",
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
                                     ◦ 注意：TCP 只承载 bootstrap / 选点 / 房间 KV 等信令阶段，\n\
                                       不保证 Forward 与业务隧道在 UDP 完全被封时可达\n\
  --hobby / --no-hobby               贡献模式：拒绝 Forward 中转（PCDN 防护）\n\
  --allow-legacy-identity            兼容旧节点：身份证明失败时回退到旧 PING/PONG 学习\n\
                                     （默认关闭；严格模式只把旧协议用于存活诊断）\n\
  --advertise <ipv4|域名|none>       对外宣告的地址（默认不宣告）。可以是固定公网 IPv4，\n\
                                     也可以是 DDNS 域名（启动时解析、周期重解析，变了就换纪元重宣告）\n\
  --advertise-dht-port <port>        对外 DHT UDP 端口（0 = 沿用本机，默认 0）\n\
  --advertise-stun-port <port>       对外 STUN 端口（0 = 沿用本机，默认 0）\n\
  --advertise-tcp-port <port>        对外 TCP 信令端口（0 = 沿用本机，默认 0）\n\
                                     ◦ 上面三个用于 FRP / 端口映射：外部端口与本机端口不同时\n\
                                       必须显式给出，否则别人连的是错的端口\n\
  --ddns-refresh <secs>              DDNS 域名重解析周期（默认 300；0 = 只在启动时解析一次）\n\
  --allow-local-endpoints            接受回环/私网端点（本机多进程联调、局域网或 FRP 内网部署；\n\
                                     默认只收公网地址）\n\
  --proxy-protocol <off|v2>          前置代理注入 PROXY protocol v2 时打开：观察者与 TCP 信令会用\n\
                                     头里的**真实客户端地址**（而不是中继地址）出映射报告与限速。\n\
                                     只能在「本端口只可能被可信代理访问」时打开，否则来源可伪造\n\
  --peers <list>                     入网引导：其他种子的 udp://主机:端口，逗号分隔，可重复给出\n\
  --observer-rate-limit <n>          观察者每 IP 每窗口响应上限（默认 {limit}）\n\
  --observer-rate-window <secs>      观察者限频窗口秒数（默认 {window}）\n\
  --identity <path>                  节点身份文件（默认 {IDENTITY_FILE}）\n\
  --config <path>                    配置文件（key = value，默认自动加载 {DEFAULT_CONFIG_FILE}）\n\
  --log-level <error|warn|info|debug>  日志级别（默认 info）\n\
  -h, --help                         显示本帮助\n\
  -V, --version                      显示版本\n\n\
环境变量：WGP_BIND / WGP_STUN / WGP_TCP / WGP_HOBBY /\n\
          WGP_ALLOW_LEGACY_IDENTITY /\n\
          WGP_OBSERVER_RATE_LIMIT / WGP_OBSERVER_RATE_WINDOW /\n\
          WGP_IDENTITY / WGP_LOG_LEVEL / WGP_CONFIG /\n\
          WGP_ADVERTISE / WGP_ADVERTISE_DHT_PORT / WGP_ADVERTISE_STUN_PORT /\n\
          WGP_ADVERTISE_TCP_PORT / WGP_DDNS_REFRESH / WGP_ALLOW_LOCAL_ENDPOINTS /\n\
          WGP_PROXY_PROTOCOL / WGP_PEERS\n\
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
    let mut addrs = tokio::net::lookup_host((host.as_str(), ep.port))
        .await
        .ok()?;
    addrs.find(|a| a.is_ipv4())
}

/// 把一个域名解析成 IPv4（DDNS 用；本协议面只支持 IPv4）。
///
/// 端口传 1 只是 `lookup_host` 的接口要求：这里只关心地址，不看端口。
async fn resolve_ipv4(host: &str) -> Option<Ipv4Addr> {
    let addrs = tokio::net::lookup_host((host, 1)).await.ok()?;
    addrs
        .filter_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .next()
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

    if argv
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
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
        opts.stun
            .map(|p| p.to_string())
            .unwrap_or_else(|| "off".into()),
        opts.tcp
            .map(|p| p.to_string())
            .unwrap_or_else(|| "off".into()),
        if opts.hobby {
            "贡献(PCDN防护)"
        } else {
            "完整"
        },
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
    // 对外宣告：固定 IPv4 直接可用；DDNS 域名要在这里解析出 IPv4（内核不解析域名）。
    // 解析不出来不阻止启动——DDNS 记录可能刚好在更新，后台会继续重试。
    let advertise_ip: Option<Ipv4Addr> = match &opts.advertise {
        AdvertiseSource::Off => None,
        AdvertiseSource::Fixed(ip) => Some(*ip),
        AdvertiseSource::Dns(host) => match resolve_ipv4(host).await {
            Some(ip) => {
                log_info(format!("DDNS：{host} → {ip}"));
                Some(ip)
            }
            None => {
                log_warn(format!(
                    "DDNS：{} 暂时解析不出 IPv4，先以「不宣告」启动；后台每 {} 秒重试",
                    host,
                    opts.ddns_refresh_secs.max(30)
                ));
                None
            }
        },
    };
    // 纪元：高 32 位 = 启动计数（落盘、跨重启单调），低 32 位 = 本进程内的广告修订号
    // （DDNS 解析结果变化时 +1）。接收端只采纳更大的纪元，所以修订号必须随每次重宣告递增。
    let advertise_epoch_base = if opts.advertise.is_off() {
        0
    } else {
        let (epoch, warning) = next_advertise_epoch(&epoch_file_for(&opts.identity_file));
        if let Some(w) = warning {
            log_warn(w);
        }
        epoch
    };

    // 端点准入策略（审计 M2）：显式放宽，或按「配置里出现的地址」自动判断本机/局域网形态
    let endpoint_scope = if opts.allow_local_endpoints {
        EndpointScope::LocalNetwork
    } else {
        let mut scope_addrs: Vec<SocketAddr> = peers.clone();
        if let Ok(bind) = opts.bind.parse::<SocketAddr>() {
            scope_addrs.push(bind);
        }
        if let Some(ip) = advertise_ip {
            scope_addrs.push(SocketAddr::from((ip, 1)));
        }
        wgp_dht::scope_for_endpoints(scope_addrs)
    };

    let (engine, _events) = Engine::new();
    let cfg = NodeConfig {
        role: NodeRole::Seed,
        bind: opts.bind.clone(),
        stun: opts.stun,
        tcp_signal: opts.tcp,
        hobby: opts.hobby,
        observer_policy: opts.observer_policy(),
        advertise: advertise_ip.map(|ip| AdvertiseTarget {
            addr_v4: ip.octets(),
            ports: opts.advertise_ports,
        }),
        advertise_epoch: advertise_epoch_base,
        endpoint_scope,
        proxy_protocol: opts.proxy_protocol,
        peers: peers.clone(),
        allow_legacy_identity: opts.allow_legacy_identity,
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
    match advertise_ip {
        Some(ip) => {
            let ports = node.ports;
            let ext = |wanted: u16, local: u16| if wanted != 0 { wanted } else { local };
            log_info(format!(
                "对外宣告 {}:{}（DHT）/ {}（STUN）/ {}（TCP）| 第 {} 次启动 | {}",
                opts.advertise.display(),
                ext(opts.advertise_ports.dht, ports.dht),
                if ports.stun == 0 {
                    "off".to_string()
                } else {
                    ext(opts.advertise_ports.stun, ports.stun).to_string()
                },
                if ports.tcp == 0 {
                    "off".to_string()
                } else {
                    ext(opts.advertise_ports.tcp, ports.tcp).to_string()
                },
                advertise_epoch_base >> 32,
                if opts.hobby {
                    "声明不中转"
                } else {
                    "声明可中转"
                },
            ));
            if opts.advertise_ports.dht != 0
                || opts.advertise_ports.stun != 0
                || opts.advertise_ports.tcp != 0
            {
                log_info(
                    "外部端口与本机不同（FRP / 端口映射形态）：请确认中继端确实把这些端口转发到了本机",
                );
            }
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                log_warn(format!(
                    "宣告地址 {ip} 不是公网地址：只有本机 / 同一局域网内的节点能据此连到本节点；\
                     对端也要用 --allow-local-endpoints 才会采纳这类广告"
                ));
            }
        }
        None if opts.advertise.is_off() => {
            log_info("未配置 --advertise：本节点不对外宣告，只能靠手工填写地址找到")
        }
        None => log_warn("对外宣告尚未生效：DDNS 解析出 IPv4 后会自动开始宣告"),
    }
    log_info(format!(
        "端点准入策略：{}",
        match endpoint_scope {
            EndpointScope::Public => "只收公网地址",
            EndpointScope::LocalNetwork => "接受回环/私网地址（本机或局域网部署）",
        }
    ));
    if opts.proxy_protocol {
        log_info(
            "PROXY protocol v2：已启用（观察者/信令使用前置代理声明的真实客户端地址）\
             —— 只能用于「本端口仅可信代理可访问」的部署",
        );
    }
    if !peers.is_empty() {
        let list: Vec<String> = peers.iter().map(|a| a.to_string()).collect();
        log_info(format!("入网引导端点：{}", list.join(", ")));
    }

    // DDNS 守夜：周期重解析，结果变了就换纪元重宣告（审计简单项「--advertise 只支持固定 IPv4」）
    if let (AdvertiseSource::Dns(host), Some(dht)) = (&opts.advertise, node.dht.clone()) {
        if opts.ddns_refresh_secs > 0 {
            let host = host.clone();
            let period = opts.ddns_refresh_secs;
            let ports = node.ports;
            let target_ports = opts.advertise_ports;
            let hobby = opts.hobby;
            let mut revision: u32 = 0;
            let mut current = advertise_ip;
            tokio::spawn(async move {
                let host_label = host.clone();
                loop {
                    tokio::time::sleep(Duration::from_secs(period.max(30))).await;
                    let Some(ip) = resolve_ipv4(&host).await else {
                        log_warn(format!("DDNS：{host_label} 暂时解析不出 IPv4，保持现有宣告"));
                        continue;
                    };
                    if current == Some(ip) {
                        continue;
                    }
                    revision = revision.saturating_add(1);
                    let target = AdvertiseTarget {
                        addr_v4: ip.octets(),
                        ports: target_ports,
                    };
                    let spec = target.spec(ports, hobby);
                    dht.start_advertising(spec, advertise_epoch_base | u64::from(revision))
                        .await;
                    log_info(format!(
                        "DDNS：{host_label} → {ip}（原 {:?}），已用纪元 {} 重新宣告",
                        current,
                        advertise_epoch_base >> 32
                    ));
                    current = Some(ip);
                }
            });
        }
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

    #[test]
    fn runtime_worker_count_is_capped_and_configurable() {
        assert_eq!(runtime_worker_threads_for(None, 1), 1);
        assert_eq!(runtime_worker_threads_for(None, 32), 4);
        assert_eq!(runtime_worker_threads_for(Some("2"), 32), 2);
        assert_eq!(runtime_worker_threads_for(Some("64"), 4), 64);
        assert_eq!(runtime_worker_threads_for(Some("0"), 8), 4);
        assert_eq!(runtime_worker_threads_for(Some("oops"), 8), 4);
    }

    fn raw(file: &[(&str, &str)], env: &[(&str, &str)], argv: &[&str]) -> RawInput {
        RawInput {
            file: file
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
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
            &raw(
                &[],
                &[],
                &["--bind=0.0.0.0:12000", "--stun=none", "--tcp", "off"],
            ),
        )
        .unwrap();
        assert_eq!(o.bind, "0.0.0.0:12000");
        assert_eq!(o.stun, None);
        assert_eq!(o.tcp, None);
    }

    #[test]
    fn hobby_flag_and_force_hobby() {
        assert!(
            resolve_opts(false, &raw(&[], &[], &["--hobby"]))
                .unwrap()
                .hobby
        );
        assert!(
            !resolve_opts(false, &raw(&[], &[], &["--no-hobby"]))
                .unwrap()
                .hobby
        );
        // force_hobby（家庭宽带版）恒为真，且不被 --no-hobby 覆盖
        assert!(
            resolve_opts(true, &raw(&[], &[], &["--no-hobby"]))
                .unwrap()
                .hobby
        );
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
            &raw(
                &[],
                &[],
                &["--observer-rate-limit", "30", "--observer-rate-window", "5"],
            ),
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

    /// 测试用临时目录：**每个用例一个**，创建失败要立刻带着路径与系统错误失败。
    ///
    /// 位置选在仓库的 `target/test-tmp/` 而不是系统临时目录：后者在受限环境（只读沙箱、
    /// 某些 CI 容器）里可能不可写。旧实现还让同一进程的多个用例共用
    /// `wgp-node-test-{pid}` 一条路径，一个 `remove_dir_all` 会删掉另一个正在用的目录，
    /// 报出「拒绝访问 / 找不到路径」，看起来像产品缺陷（审计简单项）。
    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("wgp-node-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("创建测试临时目录 {} 失败：{e}", dir.display()));
        dir
    }

    #[test]
    fn identity_roundtrip_and_corruption_detected() {
        let dir = test_dir("identity");
        let path = dir.join("node_identity.key");

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
        assert!(o.advertise.is_off());
        assert!(o.peers.is_empty());
        assert_eq!(o.advertise_ports, AdvertisePorts::default());
        assert_eq!(o.ddns_refresh_secs, 300);
        assert!(!o.allow_local_endpoints);
    }

    #[test]
    fn advertise_is_parsed_and_validated() {
        let o = resolve_opts(false, &raw(&[], &[], &["--advertise", "203.0.113.7"])).unwrap();
        assert_eq!(
            o.advertise,
            AdvertiseSource::Fixed(Ipv4Addr::new(203, 0, 113, 7))
        );
        // 关闭写法：命令行的 none 覆盖配置文件里的地址
        let o = resolve_opts(
            false,
            &raw(&[("advertise", "203.0.113.7")], &[], &["--advertise=none"]),
        )
        .unwrap();
        assert!(o.advertise.is_off());
        // 越界、不可用地址：启动即报错，而不是带着一个谁也连不上的地址去宣告
        for bad in [
            "999.1.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "not a host",
            "localhost",
            "-bad.example",
            "a..b",
        ] {
            let e = resolve_opts(false, &raw(&[], &[], &["--advertise", bad])).unwrap_err();
            assert!(e.contains("advertise"), "{bad}: {e}");
        }
    }

    /// DDNS：域名形态的 --advertise 是合法输入（解析在启动时进行）
    #[test]
    fn advertise_accepts_ddns_hostname() {
        let o = resolve_opts(
            false,
            &raw(&[], &[], &["--advertise", "Seed.Example.COM"]),
        )
        .unwrap();
        assert_eq!(o.advertise, AdvertiseSource::Dns("seed.example.com".into()));
        assert_eq!(o.advertise.display(), "seed.example.com（DDNS）");
        // 重解析周期可配
        let o = resolve_opts(false, &raw(&[], &[], &["--advertise", "a.example", "--ddns-refresh", "60"]))
            .unwrap();
        assert_eq!(o.ddns_refresh_secs, 60);
        // 0 = 只在启动时解析一次
        let o = resolve_opts(false, &raw(&[], &[], &["--advertise", "a.example", "--ddns-refresh", "0"]))
            .unwrap();
        assert_eq!(o.ddns_refresh_secs, 0);
    }

    /// FRP / 端口映射：外部端口可独立配置，且配置了就必须有 --advertise
    #[test]
    fn advertise_external_ports_require_advertise_and_matching_local_service() {
        let o = resolve_opts(
            false,
            &raw(
                &[],
                &[],
                &[
                    "--advertise",
                    "203.0.113.7",
                    "--advertise-dht-port",
                    "20010",
                    "--advertise-stun-port",
                    "23478",
                    "--advertise-tcp-port",
                    "23481",
                ],
            ),
        )
        .unwrap();
        assert_eq!(
            o.advertise_ports,
            AdvertisePorts {
                dht: 20010,
                stun: 23478,
                tcp: 23481
            }
        );

        // 没写 --advertise 却配了外部端口：报错（那些端口不会进入任何广告）
        let e = resolve_opts(
            false,
            &raw(&[], &[], &["--advertise-dht-port", "20010"]),
        )
        .unwrap_err();
        assert!(e.contains("advertise"), "{e}");

        // 本机没开 STUN / TCP，却写了对外端口：报错，避免广告里出现指向空端口
        let e = resolve_opts(
            false,
            &raw(
                &[],
                &[],
                &["--advertise", "203.0.113.7", "--stun", "none", "--advertise-stun-port", "23478"],
            ),
        )
        .unwrap_err();
        assert!(e.contains("stun"), "{e}");
        let e = resolve_opts(
            false,
            &raw(
                &[],
                &[],
                &["--advertise", "203.0.113.7", "--tcp", "none", "--advertise-tcp-port", "23481"],
            ),
        )
        .unwrap_err();
        assert!(e.contains("tcp"), "{e}");
    }

    /// 局域网 / 本机部署：显式放宽端点准入（审计 M2）
    #[test]
    fn allow_local_endpoints_flag() {        let o = resolve_opts(false, &raw(&[], &[], &["--allow-local-endpoints"])).unwrap();
        assert!(o.allow_local_endpoints);
        // 配置文件里写连字符也认（parse_config_text 负责 - → _ 归一）
        let kv = parse_config_text("allow-local-endpoints = true\n").unwrap();
        let o = resolve_opts(
            false,
            &RawInput {
                file: kv,
                env: Vec::new(),
                argv: Vec::new(),
            },
        )
        .unwrap();
        assert!(o.allow_local_endpoints, "配置文件里的键名做 - → _ 归一");
    }

    #[test]
    fn peers_accumulate_on_cli_and_override_lower_layers() {
        // 配置文件 / 环境变量：单个值内用逗号分隔
        let o = resolve_opts(
            false,
            &raw(
                &[("peers", "udp://a.example:11010, b.example:11011")],
                &[],
                &[],
            ),
        )
        .unwrap();
        let shown: Vec<String> = o.peers.iter().map(|p| p.display()).collect();
        assert_eq!(
            shown,
            vec!["udp://a.example:11010", "udp://b.example:11011"]
        );

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
        assert!(
            err("tcp://x.example:3481").contains("UDP"),
            "种子间信令只走 UDP"
        );
        let many: Vec<String> = (0..=MAX_PEERS)
            .map(|i| format!("udp://198.51.100.1:{}", 1000 + i))
            .collect();
        assert!(err(&many.join(",")).contains("最多"));
    }

    #[test]
    fn advertise_epoch_strictly_increases_across_restarts() {
        let dir = test_dir("epoch");
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

    /// 前置代理的 PROXY protocol v2 开关：默认关，只认 v2
    #[test]
    fn proxy_protocol_flag_accepts_only_v2() {
        let o = resolve_opts(false, &raw(&[], &[], &[])).unwrap();
        assert!(!o.proxy_protocol, "默认关闭");

        for on in ["v2", "2", "on", "true"] {
            let o = resolve_opts(false, &raw(&[], &[], &["--proxy-protocol", on])).unwrap();
            assert!(o.proxy_protocol, "{on} 应开启");
        }
        for off in ["off", "none", "0", "false"] {
            let o = resolve_opts(false, &raw(&[], &[], &["--proxy-protocol", off])).unwrap();
            assert!(!o.proxy_protocol, "{off} 应关闭");
        }
        // v1 是文本协议：明确拒绝，而不是「悄悄当 off」（运维会以为开了）
        let e = resolve_opts(false, &raw(&[], &[], &["--proxy-protocol", "v1"])).unwrap_err();
        assert!(e.contains("只支持 v2"), "{e}");
        let e = resolve_opts(false, &raw(&[], &[], &["--proxy-protocol", "maybe"])).unwrap_err();
        assert!(e.contains("proxy_protocol 非法"), "{e}");

        // 打开后观察者策略与节点配置都要跟着变
        let o = resolve_opts(false, &raw(&[], &[], &["--proxy-protocol", "v2"])).unwrap();
        assert!(o.observer_policy().proxy_protocol);
    }
}
