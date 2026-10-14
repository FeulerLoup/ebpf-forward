use std::{
    collections::HashMap,
    io::{self, BufRead as _, IsTerminal as _, Write as _},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use aya::programs::{TcAttachType, tc};
use ebpf_forward_common::*;

use crate::{
    config::{self, Config, Proto, Rule},
    daemon::monotonic_ns,
    datapath::{self, PROG_ETH, PROG_L3, Timeouts, conn_timeout},
    netinfo::{self, fmt_addr_port, fmt_host_port, raw_to_ip},
    status::{self, Paths, Status, fmt_ago, fmt_bytes, fmt_duration},
};

pub fn info(msg: &str) {
    println!("\x1b[32m[信息]\x1b[0m {msg}");
}

pub fn warn(msg: &str) {
    println!("\x1b[33m[警告]\x1b[0m {msg}");
}

pub fn err(msg: &str) {
    println!("\x1b[31m[错误]\x1b[0m {msg}");
}

pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("此操作需要 root 权限，请使用 sudo 或 root 用户执行");
    }
    Ok(())
}

/// 读取一行输入；EOF 时返回 None。
pub fn prompt(msg: &str) -> Option<String> {
    print!("{msg}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_owned()),
    }
}

pub fn confirm(msg: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    match prompt(&format!("{msg} {hint}: ")) {
        Some(a) if a.is_empty() => default_yes,
        Some(a) => matches!(a.as_str(), "y" | "Y" | "yes" | "YES"),
        None => false,
    }
}

/// 按终端显示宽度补齐（中文字符占 2 列）。
pub fn pad(s: &str, width: usize) -> String {
    let w: usize = s
        .chars()
        .map(|c| if (c as u32) >= 0x2e80 { 2 } else { 1 })
        .sum();
    format!("{s}{}", " ".repeat(width.saturating_sub(w)))
}

/// 新增规则。`confirmed` 为 true 时跳过端口占用确认（交互菜单里已经问过）。
pub fn add(paths: &Paths, mut rule: Rule, confirmed: bool) -> Result<()> {
    require_root()?;
    rule.target = config::normalize_target(&rule.target).to_owned();
    config::validate_rule(&rule)?;
    let mut cfg = Config::load(&paths.config)?;
    if let Some(r) = cfg
        .rules
        .iter()
        .find(|r| r.listen_port == rule.listen_port && r.proto.overlaps(rule.proto))
    {
        bail!(
            "本机端口 {} ({}) 已存在转发规则 -> {}，请先删除后再添加",
            r.listen_port,
            r.proto,
            fmt_host_port(&r.target, r.target_port)
        );
    }
    if !confirmed && !check_port_conflict(rule.listen_port, rule.proto) {
        info("已取消。");
        return Ok(());
    }
    let summary = format!(
        "{} ({}) -> {}",
        rule.listen_port,
        rule.proto,
        fmt_host_port(&rule.target, rule.target_port)
    );
    cfg.rules.push(rule);
    cfg.save(&paths.config)?;
    info(&format!("已写入配置 {}: {summary}", paths.config.display()));
    notify_and_wait(paths);
    list(paths)
}

/// 端口被本地服务占用时提示，返回是否继续。
pub fn check_port_conflict(port: u16, proto: Proto) -> bool {
    let busy: Vec<&str> = netinfo::local_listeners(port)
        .into_iter()
        .filter(|p| proto.to_string().contains(p))
        .collect();
    if busy.is_empty() {
        return true;
    }
    warn(&format!(
        "本机端口 {port} 已被本地服务占用（{}）。添加后外部访问该端口的流量会被转发，本地服务将无法从外部访问（本机访问不受影响）。",
        busy.join("+")
    ));
    if !io::stdin().is_terminal() {
        return true;
    }
    confirm("是否仍要继续添加转发规则？", false)
}

pub fn del(paths: &Paths, port: u16, proto: Option<Proto>) -> Result<()> {
    require_root()?;
    let mut cfg = Config::load(&paths.config)?;
    let before = cfg.rules.len();
    cfg.rules
        .retain(|r| !(r.listen_port == port && proto.is_none_or(|p| p.overlaps(r.proto))));
    if cfg.rules.len() == before {
        bail!("没有本机端口 {port} 的转发规则");
    }
    cfg.save(&paths.config)?;
    info(&format!(
        "已删除本机端口 {port} 的转发规则（已有连接会在 10 秒内断开）"
    ));
    notify_and_wait(paths);
    Ok(())
}

pub fn clear(paths: &Paths, yes: bool) -> Result<()> {
    require_root()?;
    let mut cfg = Config::load(&paths.config)?;
    if cfg.rules.is_empty() {
        info("当前没有端口转发规则，无需清空。");
        return Ok(());
    }
    if !yes
        && !confirm(
            &format!("即将清空全部 {} 条转发规则，确认？", cfg.rules.len()),
            false,
        )
    {
        info("已取消。");
        return Ok(());
    }
    cfg.rules.clear();
    cfg.save(&paths.config)?;
    info("所有转发规则已清空。");
    notify_and_wait(paths);
    Ok(())
}

/// 通知守护进程重新加载，并等待其应用完配置（含域名解析）。
fn notify_and_wait(paths: &Paths) {
    let Some(pid) = status::daemon_pid(paths) else {
        warn(
            "守护进程未运行，配置将在服务启动后生效（ebpf-forward install 安装服务，或 systemctl start ebpf-forward）。",
        );
        return;
    };
    unsafe { libc::kill(pid, libc::SIGHUP) };
    let want = config::mtime_nanos(&paths.config);
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
        if let Some(st) = Status::load(&paths.status_file())
            && st.config_mtime == want
            && st.rules.iter().all(|r| r.state != "pending")
        {
            return;
        }
    }
    warn("等待守护进程应用配置超时，可稍后执行 ebpf-forward list 查看。");
}

fn running_status(paths: &Paths) -> Option<Status> {
    status::daemon_pid(paths)?;
    Status::load(&paths.status_file())
}

pub fn list(paths: &Paths) -> Result<()> {
    let cfg = Config::load(&paths.config)?;
    if cfg.rules.is_empty() {
        info("当前没有端口转发规则。");
        return Ok(());
    }
    let st = running_status(paths);
    println!();
    println!(
        "\x1b[1m{}{}{}{}状态\x1b[0m",
        pad("序号", 6),
        pad("协议", 9),
        pad("本机端口", 10),
        pad("目标", 34),
    );
    println!("{}", "─".repeat(96));
    for (i, r) in cfg.rules.iter().enumerate() {
        let target = fmt_host_port(&r.target, r.target_port);
        let rs = st
            .as_ref()
            .and_then(|s| s.rule(r.listen_port, &r.proto.to_string()));
        let state = match (st.is_some(), rs) {
            (false, _) => "\x1b[33m服务未运行\x1b[0m".to_owned(),
            (true, None) => "\x1b[33m等待生效\x1b[0m".to_owned(),
            (true, Some(rs)) => match rs.state.as_str() {
                "ok" => {
                    let mut s = String::from("\x1b[32m正常\x1b[0m");
                    if r.target_ip().is_none() {
                        s += &format!(" 解析={}", rs.ip.as_deref().unwrap_or("?"));
                    }
                    s += &format!(" SNAT={}", rs.snat.as_deref().unwrap_or("?"));
                    if let Some(v) = &rs.via {
                        s += &format!(" 出口={v}");
                    }
                    s += &format!(" 连接={}", rs.conns);
                    if let Some(e) = &rs.error {
                        s += &format!(" \x1b[33m(最近一次解析失败: {e})\x1b[0m");
                    }
                    s
                }
                "pending" => "\x1b[33m解析中\x1b[0m".to_owned(),
                _ => format!(
                    "\x1b[31m未生效: {}\x1b[0m",
                    rs.error.as_deref().unwrap_or("未知原因")
                ),
            },
        };
        println!(
            "{}{}{}{}{state}",
            pad(&(i + 1).to_string(), 6),
            pad(&r.proto.to_string(), 9),
            pad(&r.listen_port.to_string(), 10),
            pad(&target, 34),
        );
        if !r.comment.is_empty() {
            println!("{}备注: {}", " ".repeat(25), r.comment);
        }
    }
    println!();
    Ok(())
}

pub fn conns(paths: &Paths) -> Result<()> {
    require_root()?;
    let st = running_status(paths).context("守护进程未运行")?;
    let ct = datapath::open_ct(st.ct_map_id)?;
    let entries: HashMap<CtKey, CtValue> = ct.iter().filter_map(Result::ok).collect();
    let now = monotonic_ns();
    let cfg = Config::load(&paths.config).unwrap_or_default();
    let t = Timeouts {
        tcp: cfg.tcp_timeout,
        udp: cfg.udp_timeout,
    };

    let mut rows: Vec<(u64, String)> = Vec::new();
    for (k, v) in &entries {
        if v.flags & CT_F_REPLY != 0 {
            continue;
        }
        let r = entries.get(&v.pair_key(k.proto)).copied();
        let rflags = r.map_or(0, |r| r.flags);
        let last = r.map_or(v.last_seen, |r| r.last_seen.max(v.last_seen));
        let state = match (k.proto, r) {
            (_, None) => "无回程项",
            (PROTO_TCP, _) if (v.flags | rflags) & CT_F_RST != 0 => "已重置",
            (PROTO_TCP, _) if v.flags & rflags & CT_F_FIN != 0 => "已关闭",
            (PROTO_TCP, _) if (v.flags | rflags) & CT_F_FIN != 0 => "关闭中",
            (PROTO_TCP, _) if rflags & CT_F_SEEN == 0 => "SYN已发送",
            (PROTO_TCP, _) => "已建立",
            (_, _) if rflags & CT_F_SEEN == 0 => "单向",
            _ => "双向",
        };
        let idle = now.saturating_sub(last) / 1_000_000_000;
        let age = now.saturating_sub(v.created) / 1_000_000_000;
        let timeout = conn_timeout(k.proto, v.flags, rflags, &t);
        let proto = if k.proto == PROTO_TCP { "tcp" } else { "udp" };
        let client = fmt_addr_port(raw_to_ip(k.saddr, k.family), u16::from_be(k.sport));
        let local = fmt_addr_port(raw_to_ip(k.daddr, k.family), u16::from_be(k.dport));
        let nat = format!(
            "{} -> {}",
            fmt_addr_port(raw_to_ip(v.saddr, v.family), u16::from_be(v.sport)),
            fmt_addr_port(raw_to_ip(v.daddr, v.family), u16::from_be(v.dport))
        );
        rows.push((
            v.created,
            format!(
                "{}{}{}{}{}空闲 {} / 超时 {}，已持续 {}",
                pad(proto, 5),
                pad(&client, 22),
                pad(&local, 22),
                pad(&nat, 44),
                pad(state, 10),
                fmt_duration(idle),
                fmt_duration(timeout),
                fmt_duration(age)
            ),
        ));
    }
    if rows.is_empty() {
        info("当前没有活动连接。");
        return Ok(());
    }
    rows.sort_by_key(|(c, _)| *c);
    println!(
        "\x1b[1m{}{}{}{}状态\x1b[0m",
        pad("协议", 5),
        pad("客户端", 22),
        pad("本机入口", 22),
        pad("转发为 (SNAT -> 目标)", 44),
    );
    for (_, row) in &rows {
        println!("{row}");
    }
    println!(
        "共 {} 个连接（连接跟踪表已用 {} / {} 项）",
        rows.len(),
        entries.len(),
        st.ct_max
    );
    Ok(())
}

pub fn status(paths: &Paths) -> Result<()> {
    let Some(st) = running_status(paths) else {
        warn("守护进程未运行。");
        if let Some(svc) = systemctl_state() {
            println!("  systemd 服务状态: {svc}（journalctl -u ebpf-forward 查看日志）");
        }
        return Ok(());
    };
    println!();
    info(&format!(
        "守护进程运行中: pid {}，已运行 {}，版本 {}，内核 {}",
        st.pid,
        fmt_ago(st.started),
        st.version,
        st.kernel
    ));
    let ifs: Vec<String> = st
        .interfaces
        .iter()
        .map(|i| format!("{}({})", i.name, i.program))
        .collect();
    println!(
        "  挂载网卡: {}",
        if ifs.is_empty() {
            "无".into()
        } else {
            ifs.join(", ")
        }
    );
    let ok = st.rules.iter().filter(|r| r.state == "ok").count();
    println!(
        "  规则: {} 条，生效 {} 条；活动连接 {}",
        st.rules.len(),
        ok,
        st.conns
    );
    for w in &st.warnings {
        warn(w);
    }

    if unsafe { libc::geteuid() } == 0 {
        match datapath::open_stats(st.stats_map_id) {
            Ok(m) => {
                let s = datapath::read_stats(&m);
                println!("  转发统计（自启动以来）:");
                println!(
                    "    客户端 -> 目标: {} 包 / {}",
                    s[STAT_ORIG_PKTS as usize],
                    fmt_bytes(s[STAT_ORIG_BYTES as usize])
                );
                println!(
                    "    目标 -> 客户端: {} 包 / {}",
                    s[STAT_REPLY_PKTS as usize],
                    fmt_bytes(s[STAT_REPLY_BYTES as usize])
                );
                println!(
                    "    新建连接 {}，ICMP 差错转换 {}，MSS 钳制 {}，邻居解析重定向 {}",
                    s[STAT_NEW_CONN as usize],
                    s[STAT_ICMP_XLATE as usize],
                    s[STAT_MSS_CLAMPED as usize],
                    s[STAT_REDIRECT_NEIGH as usize]
                );
                let drops = [
                    (STAT_PORT_EXHAUSTED, "SNAT 端口耗尽"),
                    (STAT_CT_INSERT_FAIL, "连接表写入失败"),
                    (STAT_FIB_DROP, "无路由/未开启转发"),
                    (STAT_FRAG_NEEDED, "超过出口 MTU"),
                    (STAT_TTL_EXCEEDED, "TTL 耗尽"),
                    (STAT_REDIRECT_FAIL, "重定向失败"),
                ];
                let d: Vec<String> = drops
                    .iter()
                    .filter(|(i, _)| s[*i as usize] > 0)
                    .map(|(i, n)| format!("{n} {}", s[*i as usize]))
                    .collect();
                if !d.is_empty() {
                    warn(&format!("丢弃: {}", d.join("，")));
                }
            }
            Err(e) => warn(&format!("读取统计失败: {e:#}")),
        }
    }
    println!();
    Ok(())
}

pub fn systemctl_state() -> Option<String> {
    let out = std::process::Command::new("systemctl")
        .args(["is-active", "ebpf-forward"])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// 卸载所有网卡上残留的本程序 TC 过滤器（netlink 方式挂载时异常退出可能残留）。
pub fn cleanup(paths: &Paths, force: bool) -> Result<()> {
    require_root()?;
    if status::daemon_pid(paths).is_some() && !force {
        bail!("守护进程正在运行，请先停止服务（systemctl stop ebpf-forward），或加 --force");
    }
    let mut n = 0;
    for iface in netinfo::interfaces()? {
        for prog in [PROG_ETH, PROG_L3] {
            if tc::qdisc_detach_program(&iface.name, TcAttachType::Ingress, prog).is_ok() {
                info(&format!("已从 {} 卸载 {prog}", iface.name));
                n += 1;
            }
        }
    }
    if n == 0 {
        info("没有发现残留的 eBPF 挂载。");
    }
    Ok(())
}
