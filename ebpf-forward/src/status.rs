use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

pub struct Paths {
    pub config: PathBuf,
    pub run_dir: PathBuf,
}

impl Paths {
    pub fn status_file(&self) -> PathBuf {
        self.run_dir.join("status.toml")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.run_dir.join("ebpf-forward.pid")
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleStatus {
    pub listen_port: u16,
    pub proto: String,
    pub target: String,
    pub target_port: u16,
    /// ok / pending / error
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<u64>,
    pub conns: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IfaceStatus {
    pub name: String,
    pub ifindex: u32,
    pub program: String,
}

/// 守护进程定期写出的运行状态（TOML 要求普通字段在表数组之前）。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub pid: u32,
    pub version: String,
    pub started: u64,
    pub updated: u64,
    pub config_mtime: u64,
    pub kernel: String,
    pub ct_map_id: u32,
    pub stats_map_id: u32,
    pub ct_max: u32,
    pub conns: u64,
    pub warnings: Vec<String>,
    pub interfaces: Vec<IfaceStatus>,
    #[serde(rename = "rule")]
    pub rules: Vec<RuleStatus>,
}

impl Status {
    pub fn load(path: &Path) -> Option<Self> {
        let text = fs::read_to_string(path).ok()?;
        toml::from_str(&text).ok()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, toml::to_string(self).context("序列化状态失败")?)
            .with_context(|| format!("写入 {} 失败", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("写入 {} 失败", path.display()))?;
        Ok(())
    }

    pub fn rule(&self, port: u16, proto: &str) -> Option<&RuleStatus> {
        self.rules
            .iter()
            .find(|r| r.listen_port == port && r.proto == proto)
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// 守护进程是否在运行（读取 pid 文件并探测进程；普通用户探测 root 进程会得到 EPERM）。
pub fn daemon_pid(paths: &Paths) -> Option<i32> {
    let pid: i32 = fs::read_to_string(paths.pid_file())
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if pid <= 0 {
        return None;
    }
    let alive = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    alive.then_some(pid)
}

pub fn fmt_ago(ts: u64) -> String {
    fmt_duration(unix_now().saturating_sub(ts))
}

pub fn fmt_duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}秒"),
        60..3600 => format!("{}分{}秒", secs / 60, secs % 60),
        3600..86400 => format!("{}时{}分", secs / 3600, secs % 3600 / 60),
        _ => format!("{}天{}时", secs / 86400, secs % 86400 / 3600),
    }
}

pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}
