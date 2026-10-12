use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use ebpf_forward_common::*;
use log::{error, info, warn};

use crate::{
    config::{self, Config},
    datapath::{Datapath, GcStats, Timeouts},
    netinfo::{self, IfKind, Iface, ip_to_be},
    status::{IfaceStatus, Paths, RuleStatus, Status, unix_now},
};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::SeqCst);
    } else {
        STOP.store(true, Ordering::SeqCst);
    }
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// 用 flock 保证同一运行目录只有一个守护进程。
struct PidLock {
    _file: fs::File,
    path: PathBuf,
}

impl PidLock {
    fn acquire(path: PathBuf) -> Result<Self> {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("打开 {} 失败", path.display()))?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("已有 ebpf-forward 守护进程在运行（{}）", path.display());
        }
        f.set_len(0)?;
        writeln!(f, "{}", std::process::id())?;
        Ok(Self { _file: f, path })
    }
}

impl Drop for PidLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn bump_memlock_rlimit() {
    // 5.11 之前的内核按 RLIMIT_MEMLOCK 计算 BPF map 内存
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        warn!("无法解除 RLIMIT_MEMLOCK 限制，旧内核上创建大 map 可能失败");
    }
}

pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

type ResolveBatch = Vec<(String, Result<Vec<Ipv4Addr>, String>)>;

fn resolve(host: &str) -> Result<Vec<Ipv4Addr>, String> {
    let addrs = (host, 0u16).to_socket_addrs().map_err(|e| e.to_string())?;
    let mut v: Vec<Ipv4Addr> = Vec::new();
    for a in addrs {
        if let SocketAddr::V4(a) = a
            && !v.contains(a.ip())
        {
            v.push(*a.ip());
        }
    }
    if v.is_empty() {
        Err("没有 IPv4 (A) 记录".into())
    } else {
        Ok(v)
    }
}

/// 在后台线程解析，避免 DNS 卡顿影响信号响应和连接回收。
fn spawn_resolver(domains: Vec<String>) -> mpsc::Receiver<ResolveBatch> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let batch = domains
            .into_iter()
            .map(|d| {
                let r = resolve(&d);
                (d, r)
            })
            .collect();
        let _ = tx.send(batch);
    });
    rx
}

struct Resolved {
    ip: Option<Ipv4Addr>,
    error: Option<String>,
    at: u64,
}

struct Daemon {
    paths: Paths,
    cfg: Config,
    cfg_mtime: u64,
    dp: Datapath,
    resolved: HashMap<String, Resolved>,
    resolver: Option<mpsc::Receiver<ResolveBatch>>,
    next_resolve: Instant,
    statuses: Vec<RuleStatus>,
    warnings: Vec<String>,
    gc: GcStats,
    started: u64,
}

pub fn run(paths: Paths) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("需要 root 权限运行");
    }
    bump_memlock_rlimit();
    fs::create_dir_all(&paths.run_dir)
        .with_context(|| format!("创建运行目录 {} 失败", paths.run_dir.display()))?;
    let _lock = PidLock::acquire(paths.pid_file())?;
    install_signal_handlers();

    let cfg = Config::load(&paths.config)?;
    let cfg_mtime = config::mtime_nanos(&paths.config);
    match netinfo::enable_ip_forward() {
        Ok(true) => info!("已开启 net.ipv4.ip_forward（bpf_fib_lookup 要求入口网卡允许转发）"),
        Ok(false) => {}
        Err(e) => warn!("开启 net.ipv4.ip_forward 失败: {e}，转发将无法工作"),
    }

    let dp = Datapath::load(cfg.ct_max)?;
    info!(
        "eBPF 已加载（内核 {}，连接跟踪表 {} 项），共 {} 条规则",
        kernel_release(),
        cfg.ct_max,
        cfg.rules.len()
    );

    let mut d = Daemon {
        paths,
        cfg,
        cfg_mtime,
        dp,
        resolved: HashMap::new(),
        resolver: None,
        next_resolve: Instant::now(),
        statuses: Vec::new(),
        warnings: Vec::new(),
        gc: GcStats::default(),
        started: unix_now(),
    };
    d.apply();
    let result = d.main_loop();
    d.dp.detach_all();
    let _ = fs::remove_file(d.paths.status_file());
    info!("已退出，eBPF 程序已卸载");
    result
}

impl Daemon {
    fn main_loop(&mut self) -> Result<()> {
        let mut last_cfg_check = Instant::now();
        let mut last_tick = Instant::now();
        while !STOP.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(250));

            let reload = RELOAD.swap(false, Ordering::SeqCst);
            if reload || last_cfg_check.elapsed() >= Duration::from_secs(2) {
                last_cfg_check = Instant::now();
                let mtime = config::mtime_nanos(&self.paths.config);
                if reload || mtime != self.cfg_mtime {
                    self.cfg_mtime = mtime;
                    self.reload();
                }
            }

            if self.resolver.is_none() && Instant::now() >= self.next_resolve {
                self.start_resolve();
            }
            if let Some(rx) = &self.resolver {
                match rx.try_recv() {
                    Ok(batch) => {
                        self.resolver = None;
                        self.on_resolved(batch);
                        self.apply();
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => self.resolver = None,
                }
            }

            if last_tick.elapsed() >= Duration::from_secs(10) {
                last_tick = Instant::now();
                self.run_gc();
                self.apply();
            }
        }
        Ok(())
    }

    fn reload(&mut self) {
        match Config::load(&self.paths.config) {
            Ok(mut cfg) => {
                if cfg.ct_max != self.cfg.ct_max {
                    warn!("ct_max 的修改需要重启服务才能生效");
                    cfg.ct_max = self.cfg.ct_max;
                }
                if cfg != self.cfg {
                    info!("配置已重新加载，共 {} 条规则", cfg.rules.len());
                }
                self.cfg = cfg;
                self.next_resolve = Instant::now();
                self.apply();
            }
            Err(e) => error!("重新加载配置失败，继续使用旧配置: {e:#}"),
        }
    }

    fn start_resolve(&mut self) {
        let domains = self.cfg.domains();
        self.resolved.retain(|d, _| domains.contains(d));
        self.next_resolve = Instant::now() + Duration::from_secs(self.cfg.resolve_interval);
        if !domains.is_empty() {
            self.resolver = Some(spawn_resolver(domains));
        }
    }

    fn on_resolved(&mut self, batch: ResolveBatch) {
        let now = unix_now();
        for (domain, res) in batch {
            let ent = self.resolved.entry(domain.clone()).or_insert(Resolved {
                ip: None,
                error: None,
                at: 0,
            });
            match res {
                Ok(ips) => {
                    // 当前 IP 仍在结果里就不切换，避免轮询 DNS 导致目标来回变化
                    let new = match ent.ip {
                        Some(cur) if ips.contains(&cur) => cur,
                        _ => ips[0],
                    };
                    match ent.ip {
                        None => info!("域名 {domain} 解析为 {new}"),
                        Some(old) if old != new => info!("域名 {domain} 解析变化: {old} -> {new}"),
                        _ => {}
                    }
                    ent.ip = Some(new);
                    ent.error = None;
                    ent.at = now;
                }
                Err(e) => {
                    if let Some(ip) = ent.ip {
                        warn!("解析域名 {domain} 失败: {e}，继续使用上次结果 {ip}");
                    } else {
                        warn!("解析域名 {domain} 失败: {e}");
                    }
                    ent.error = Some(e);
                }
            }
        }
    }

    fn run_gc(&mut self) {
        let live: HashSet<(u8, u16)> = self
            .cfg
            .rules
            .iter()
            .flat_map(|r| r.proto.numbers().iter().map(move |p| (*p, r.listen_port)))
            .collect();
        let t = Timeouts {
            tcp: self.cfg.tcp_timeout,
            udp: self.cfg.udp_timeout,
        };
        self.gc = self.dp.gc(monotonic_ns(), &t, &live);
        if self.gc.removed > 0 {
            log::debug!(
                "回收 {} 个连接跟踪项，活动连接 {}",
                self.gc.removed,
                self.gc.conns
            );
        }
    }

    /// 根据配置、解析结果和当前网络状态，同步 eBPF map 与网卡挂载。
    fn apply(&mut self) {
        let ifaces = match netinfo::interfaces() {
            Ok(v) => v,
            Err(e) => {
                error!("读取网卡信息失败: {e}");
                return;
            }
        };
        let local: HashSet<Ipv4Addr> = ifaces
            .iter()
            .flat_map(|i| i.addrs.iter().copied())
            .collect();
        let mut warnings = Vec::new();
        if !netinfo::ip_forward_enabled() {
            warnings.push(
                "net.ipv4.ip_forward 已被关闭，转发无法工作（sysctl -w net.ipv4.ip_forward=1）"
                    .into(),
            );
        }

        let mut want: HashMap<RuleKey, RuleValue> = HashMap::new();
        let mut statuses = Vec::new();
        let mut via_ifaces: HashSet<String> = HashSet::new();
        for rule in &self.cfg.rules {
            let mut st = RuleStatus {
                listen_port: rule.listen_port,
                proto: rule.proto.to_string(),
                target: rule.target.clone(),
                target_port: rule.target_port,
                state: "pending".into(),
                conns: rule
                    .proto
                    .numbers()
                    .iter()
                    .map(|p| {
                        self.gc
                            .per_rule
                            .get(&(*p, rule.listen_port))
                            .copied()
                            .unwrap_or(0)
                    })
                    .sum(),
                ..Default::default()
            };
            let ip = match rule.target_ip() {
                Some(ip) => Some(ip),
                None => match self.resolved.get(&rule.target.to_ascii_lowercase()) {
                    Some(r) => {
                        st.resolved_at = (r.at > 0).then_some(r.at);
                        st.error = r.error.clone();
                        if r.ip.is_none() {
                            st.state = "error".into();
                        }
                        r.ip
                    }
                    None => None,
                },
            };
            let Some(ip) = ip else {
                statuses.push(st);
                continue;
            };
            st.ip = Some(ip.to_string());

            if local.contains(&ip)
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
            {
                st.state = "error".into();
                st.error = Some("目标是本机或特殊地址，eBPF 转发不支持".into());
                statuses.push(st);
                continue;
            }
            let snat = match rule.snat_ip {
                Some(s) if !local.contains(&s) => Err(format!("snat_ip {s} 不是本机地址")),
                Some(s) => Ok(s),
                None => {
                    netinfo::source_addr_for(ip).map_err(|e| format!("没有去往 {ip} 的路由: {e}"))
                }
            };
            let snat = match snat {
                Ok(s) => s,
                Err(e) => {
                    st.state = "error".into();
                    st.error = Some(e);
                    statuses.push(st);
                    continue;
                }
            };
            st.snat = Some(snat.to_string());
            if let Some(i) = ifaces.iter().find(|i| i.addrs.contains(&snat)) {
                st.via = Some(i.name.clone());
                via_ifaces.insert(i.name.clone());
            }
            st.state = "ok".into();
            let value = RuleValue {
                target_addr: ip_to_be(ip),
                snat_addr: ip_to_be(snat),
                target_port: rule.target_port.to_be(),
                _pad: 0,
            };
            for p in rule.proto.numbers() {
                want.insert(
                    RuleKey {
                        port: rule.listen_port.to_be(),
                        proto: *p,
                        _pad: 0,
                    },
                    value,
                );
            }
            statuses.push(st);
        }

        let global = GlobalConfig {
            snat_port_min: self.cfg.snat_port_min,
            snat_port_max: self.cfg.snat_port_max,
            flags: if self.cfg.mss_clamp {
                CFG_F_MSS_CLAMP
            } else {
                0
            },
        };
        if let Some((lo, hi)) = netinfo::local_port_range()
            && self.cfg.snat_port_min <= hi
            && self.cfg.snat_port_max >= lo
        {
            warnings.push(format!(
                "SNAT 端口范围 {}-{} 与 ip_local_port_range {lo}-{hi} 重叠，本机主动连接目标时可能与转发连接冲突",
                self.cfg.snat_port_min, self.cfg.snat_port_max
            ));
        }

        let results = [
            self.dp.set_global(&global),
            self.dp.set_rules(&want),
            self.dp.set_local_addrs(&local),
            self.dp.set_if_mtu(&ifaces),
        ];
        for r in results {
            if let Err(e) = r {
                error!("更新 eBPF map 失败: {e:#}");
            }
        }

        let selected = select_ifaces(&self.cfg, &ifaces, &via_ifaces, &mut warnings);
        self.dp.sync_interfaces(&selected);

        for w in &warnings {
            if !self.warnings.contains(w) {
                warn!("{w}");
            }
        }
        for st in &statuses {
            let prev = self
                .statuses
                .iter()
                .find(|p| p.listen_port == st.listen_port && p.proto == st.proto);
            let changed =
                prev.is_none_or(|p| p.state != st.state || p.ip != st.ip || p.snat != st.snat);
            if changed && st.state != "pending" {
                match &st.error {
                    Some(e) if st.state == "error" => warn!(
                        "规则 {}/{} -> {}:{} 未生效: {e}",
                        st.listen_port, st.proto, st.target, st.target_port
                    ),
                    _ => info!(
                        "规则 {}/{} -> {}:{} 生效: 目标 {}，SNAT {}{}",
                        st.listen_port,
                        st.proto,
                        st.target,
                        st.target_port,
                        st.ip.as_deref().unwrap_or("?"),
                        st.snat.as_deref().unwrap_or("?"),
                        st.via
                            .as_deref()
                            .map(|v| format!("（出口 {v}）"))
                            .unwrap_or_default(),
                    ),
                }
            }
        }
        self.statuses = statuses;
        self.warnings = warnings;
        self.write_status();
    }

    fn write_status(&self) {
        let st = Status {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            started: self.started,
            updated: unix_now(),
            config_mtime: self.cfg_mtime,
            kernel: kernel_release(),
            ct_map_id: self.dp.ct_map_id,
            stats_map_id: self.dp.stats_map_id,
            ct_max: self.cfg.ct_max,
            conns: self.gc.conns,
            warnings: self.warnings.clone(),
            interfaces: self
                .dp
                .attached()
                .map(|(name, ifindex, prog)| IfaceStatus {
                    name: name.into(),
                    ifindex,
                    program: prog.into(),
                })
                .collect(),
            rules: self.statuses.clone(),
        };
        if let Err(e) = st.save(&self.paths.status_file()) {
            warn!("写状态文件失败: {e:#}");
        }
    }
}

/// 未指定网卡时：所有已启用、有 IPv4 地址的以太网/L3 网卡，加上去往各目标的出口网卡。
fn select_ifaces<'a>(
    cfg: &Config,
    ifaces: &'a [Iface],
    via: &HashSet<String>,
    warnings: &mut Vec<String>,
) -> Vec<&'a Iface> {
    let supported = |i: &Iface| matches!(i.kind, IfKind::Ether | IfKind::L3);
    if !cfg.interfaces.is_empty() {
        let mut v = Vec::new();
        for name in &cfg.interfaces {
            match ifaces.iter().find(|i| &i.name == name) {
                Some(i) if supported(i) => v.push(i),
                Some(i) => warnings.push(format!("网卡 {name} 类型 {:?} 不受支持", i.kind)),
                None => warnings.push(format!("配置的网卡 {name} 不存在")),
            }
        }
        for name in via {
            if !cfg.interfaces.contains(name) {
                warnings.push(format!(
                    "去往目标的出口网卡 {name} 不在 interfaces 列表中，目标的回包将无法转换"
                ));
            }
        }
        return v;
    }
    let defaults = netinfo::default_route_ifaces();
    ifaces
        .iter()
        .filter(|i| {
            supported(i)
                && i.up
                && (!i.addrs.is_empty() || via.contains(&i.name) || defaults.contains(&i.name))
        })
        .collect()
}
