use std::{
    collections::HashSet,
    fmt, fs,
    io::Write as _,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::SystemTime,
};

use anyhow::{Context as _, Result, bail};
use ebpf_forward_common::{CT_DEFAULT_ENTRIES, PROTO_TCP, PROTO_UDP};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const DEFAULT_CONFIG: &str = "/etc/ebpf-forward/config.toml";
pub const DEFAULT_RUN_DIR: &str = "/run/ebpf-forward";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Proto {
    Tcp,
    Udp,
    #[default]
    Both,
}

impl Proto {
    pub fn numbers(self) -> &'static [u8] {
        match self {
            Self::Tcp => &[PROTO_TCP],
            Self::Udp => &[PROTO_UDP],
            Self::Both => &[PROTO_TCP, PROTO_UDP],
        }
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.numbers().iter().any(|p| other.numbers().contains(p))
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Both => "tcp+udp",
        })
    }
}

impl FromStr for Proto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "tcp+udp" | "udp+tcp" | "all" | "both" | "" => Ok(Self::Both),
            other => Err(format!("未知协议 `{other}`，可选: tcp / udp / tcp+udp")),
        }
    }
}

impl Serialize for Proto {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Proto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub listen_port: u16,
    /// IPv4 / IPv6 地址或域名。
    pub target: String,
    pub target_port: u16,
    #[serde(default)]
    pub proto: Proto,
    /// 手动指定 SNAT 源地址；默认自动使用本机去往目标的出口地址。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snat_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl Rule {
    pub fn target_ip(&self) -> Option<IpAddr> {
        normalize_target(&self.target).parse().ok()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub resolve_interval: u64,
    pub interfaces: Vec<String>,
    pub snat_port_min: u16,
    pub snat_port_max: u16,
    pub mss_clamp: bool,
    pub ct_max: u32,
    pub tcp_timeout: u64,
    pub udp_timeout: u64,
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            resolve_interval: 300,
            interfaces: Vec::new(),
            snat_port_min: 10000,
            snat_port_max: 32767,
            mss_clamp: true,
            ct_max: CT_DEFAULT_ENTRIES,
            tcp_timeout: 86400,
            udp_timeout: 120,
            rules: Vec::new(),
        }
    }
}

const HEADER: &str = "\
# ebpf-forward 配置文件（由 ebpf-forward 维护，手动修改后约 2 秒内自动生效）
#
# resolve_interval   域名重新解析间隔（秒）
# interfaces         挂载 eBPF 的网卡，留空 = 自动（所有已启用且有 IP 地址的网卡）
# snat_port_min/max  SNAT 源端口范围，应避开 net.ipv4.ip_local_port_range
# mss_clamp          对 SYN 做 MSS 钳制，出口 MTU 较小（如 WireGuard）时避免大包被丢弃
# ct_max             连接跟踪表容量（每条连接占 2 项，修改后需重启服务）
# tcp_timeout        TCP 连接空闲超时（秒）
# udp_timeout        UDP 会话空闲超时（秒）
#
# 规则示例：
# [[rule]]
# listen_port = 8080         # 本机端口（同时接受 IPv4 与 IPv6 连入）
# target = \"example.com\"     # 目标 IPv4、IPv6 或域名
# target_port = 80           # 目标端口
# proto = \"tcp+udp\"          # tcp / udp / tcp+udp
# snat_ip = \"1.2.3.4\"        # 可选：手动指定 SNAT 源地址（需与目标同为 IPv4 或 IPv6）
# comment = \"备注\"           # 可选

";

impl Config {
    /// 读取配置；文件不存在时返回默认配置。
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(e).with_context(|| format!("读取配置文件 {} 失败", path.display()));
            }
        };
        let cfg: Self = toml::from_str(&text)
            .with_context(|| format!("解析配置文件 {} 失败", path.display()))?;
        cfg.validate()
            .with_context(|| format!("配置文件 {} 有误", path.display()))?;
        Ok(cfg)
    }

    /// 先写临时文件再原子替换，避免写到一半导致配置损坏。
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("创建目录 {} 失败", dir.display()))?;
        }
        let body = toml::to_string(self).context("序列化配置失败")?;
        let tmp: PathBuf = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("写入 {} 失败", tmp.display()))?;
            f.write_all(HEADER.as_bytes())?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path).with_context(|| format!("写入 {} 失败", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.resolve_interval < 5 {
            bail!("resolve_interval 不能小于 5 秒");
        }
        if self.snat_port_min < 1024 || self.snat_port_max < self.snat_port_min {
            bail!(
                "SNAT 端口范围 {}-{} 无效（需 1024 <= min <= max <= 65535）",
                self.snat_port_min,
                self.snat_port_max
            );
        }
        if !(1024..=16 * 1024 * 1024).contains(&self.ct_max) {
            bail!("ct_max 需在 1024 ~ 16777216 之间");
        }
        if self.tcp_timeout < 60 || self.udp_timeout < 10 {
            bail!("tcp_timeout 不能小于 60 秒，udp_timeout 不能小于 10 秒");
        }
        let mut seen = HashSet::new();
        for r in &self.rules {
            validate_rule(r)?;
            for p in r.proto.numbers() {
                if !seen.insert((r.listen_port, *p)) {
                    bail!("本机端口 {} 存在重复规则", r.listen_port);
                }
            }
        }
        Ok(())
    }

    /// 需要解析的域名（去重）。
    pub fn domains(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.target_ip().is_none())
            .map(|r| r.target.to_ascii_lowercase())
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

pub fn normalize_target(t: &str) -> &str {
    let t = t.trim();
    t.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(t)
}

pub fn validate_rule(r: &Rule) -> Result<()> {
    if r.listen_port == 0 || r.target_port == 0 {
        bail!("端口必须在 1-65535 之间");
    }
    validate_target(&r.target)?;
    if let (Some(tip), Some(sip)) = (r.target_ip(), r.snat_ip)
        && tip.is_ipv4() != sip.is_ipv4()
    {
        bail!("snat_ip {sip} 与目标 {tip} 协议族不一致（需同为 IPv4 或同为 IPv6）");
    }
    Ok(())
}

pub fn validate_target(t: &str) -> Result<()> {
    let t = normalize_target(t);
    if t.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if t.contains(':') {
        bail!("目标 `{t}` 不是合法的 IPv6 地址");
    }
    let looks_like_ip = t
        .split('.')
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if looks_like_ip {
        bail!("目标 `{t}` 不是合法的 IPv4 地址");
    }
    let host = t.strip_suffix('.').unwrap_or(t);
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid {
        bail!("目标 `{t}` 既不是合法 IP（IPv4/IPv6）也不是合法域名");
    }
    Ok(())
}

pub fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

pub fn mtime_nanos(path: &Path) -> u64 {
    mtime(path)
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut cfg = Config::default();
        cfg.rules.push(Rule {
            listen_port: 8080,
            target: "example.com".into(),
            target_port: 80,
            proto: Proto::Both,
            snat_ip: None,
            comment: "web".into(),
        });
        cfg.rules.push(Rule {
            listen_port: 53,
            target: "1.1.1.1".into(),
            target_port: 53,
            proto: Proto::Udp,
            snat_ip: Some("10.0.0.1".parse().unwrap()),
            comment: String::new(),
        });
        let text = format!("{HEADER}{}", toml::to_string(&cfg).unwrap());
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(cfg, back);
        assert_eq!(back.domains(), vec!["example.com".to_string()]);
    }

    #[test]
    fn duplicate_ports() {
        let mut cfg = Config::default();
        let r = Rule {
            listen_port: 1000,
            target: "1.2.3.4".into(),
            target_port: 1,
            proto: Proto::Tcp,
            snat_ip: None,
            comment: String::new(),
        };
        cfg.rules.push(r.clone());
        cfg.rules.push(Rule {
            proto: Proto::Udp,
            ..r.clone()
        });
        assert!(cfg.validate().is_ok());
        cfg.rules.push(Rule {
            proto: Proto::Both,
            ..r
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn targets() {
        assert!(validate_target("1.2.3.4").is_ok());
        assert!(validate_target("2001:db8::1").is_ok());
        assert!(validate_target("[2001:db8::1]").is_ok());
        assert!(validate_target("::1").is_ok());
        assert!(validate_target("a-b.example.com").is_ok());
        assert!(validate_target("example.com.").is_ok());
        assert!(validate_target("1.2.3").is_err());
        assert!(validate_target("999.1.1.1").is_err());
        assert!(validate_target("2001:db8::gggg").is_err());
        assert!(validate_target("bad host").is_err());
        assert_eq!("all".parse::<Proto>().unwrap(), Proto::Both);
    }
}
