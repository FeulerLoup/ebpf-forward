use std::{
    collections::HashMap,
    fs,
    io::IsTerminal as _,
    net::{SocketAddr, TcpStream},
    path::Path,
    process::Command,
    time::Duration,
};

use anyhow::Result;

use crate::{
    config::Config,
    daemon::{bump_memlock_rlimit, kernel_release},
    datapath,
    manage::{confirm, err, info, systemctl_state, warn},
    netinfo,
    status::{self, Paths, Status},
};

/// 最低要求 5.10（bpf_redirect_neigh），MSS 钳制等在 5.12+ 上效果最好。
pub const MIN_KERNEL: (u32, u32) = (5, 10);

pub fn parse_version(release: &str) -> Option<(u32, u32, u32)> {
    let mut it = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next().flatten().unwrap_or(0)))
}

fn kernel_config(release: &str) -> Option<HashMap<String, String>> {
    let text = fs::read_to_string(format!("/boot/config-{release}"))
        .ok()
        .or_else(|| {
            let out = Command::new("zcat").arg("/proc/config.gz").output().ok()?;
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
        })?;
    Some(
        text.lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    )
}

/// WSL2 的 PID 1 也带 container=wsl，但它是有独立内核的虚拟机，不算容器。
/// nftables 规则集中 DNAT 规则匹配的目的端口（闭区间）；没有 nft 或无权限时为空。
fn nft_dnat_ports() -> Vec<(u16, u16)> {
    let Ok(out) = Command::new("nft").args(["list", "ruleset"]).output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_dnat_ports(&String::from_utf8_lossy(&out.stdout))
}

/// 解析 `tcp dport 8080 dnat to ...`、`dport 1000-2000`、`dport { 80, 443 }` 等写法。
/// 只认 DNAT / redirect 动作；`ct status dnat snat to` 这类回源 SNAT 规则里的 dport 是目标端口，不算。
fn parse_dnat_ports(ruleset: &str) -> Vec<(u16, u16)> {
    let is_dnat = |l: &&str| {
        ["dnat to", "dnat ip to", "dnat ip6 to", "redirect to"]
            .iter()
            .any(|a| l.contains(a))
    };
    let mut ports = Vec::new();
    for line in ruleset.lines().filter(is_dnat) {
        let mut tokens = line
            .split_whitespace()
            .skip_while(|t| *t != "dport")
            .skip(1);
        let Some(first) = tokens.next() else {
            continue;
        };
        let values: Vec<&str> = if first == "{" {
            tokens.take_while(|t| *t != "}").collect()
        } else {
            vec![first]
        };
        for v in values {
            let v = v.trim_end_matches(',');
            let range = match v.split_once('-') {
                Some((a, b)) => a.parse().ok().zip(b.parse().ok()),
                None => v.parse().ok().map(|p| (p, p)),
            };
            ports.extend(range);
        }
    }
    ports
}

fn container_kind() -> Option<String> {
    if Path::new("/proc/vz").exists() && !Path::new("/proc/bc").exists() {
        return Some("OpenVZ".into());
    }
    let is_container = |v: &str| !v.is_empty() && v != "none" && v != "wsl";
    if let Ok(env) = fs::read("/proc/1/environ")
        && let Some(v) = env
            .split(|b| *b == 0)
            .filter_map(|kv| std::str::from_utf8(kv).ok())
            .find_map(|kv| kv.strip_prefix("container="))
    {
        return is_container(v).then(|| v.to_owned());
    }
    let out = Command::new("systemd-detect-virt")
        .arg("-c")
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && is_container(&v)).then_some(v)
}

pub const UPGRADE_GUIDE: &str = "\
内核升级参考（要求 >= 5.10，推荐 >= 5.15；升级后重启，uname -r 确认，再运行 ebpf-forward check）:
  Debian 11 (5.10)  已满足要求；也可升级到 Debian 12/13 获得 6.1/6.12 内核
  Debian 10 及更早  建议直接升级/重装为 Debian 12 或 13（apt full-upgrade 逐个大版本升级）
  Ubuntu 18.04/20.04  apt update && apt install --install-recommends linux-generic-hwe-20.04（5.15，18.04 需先升级到 20.04）
  Ubuntu 22.04+     已满足要求（5.15 / 6.x）
  CentOS 7 / RHEL 7 (3.10)  已停止维护，建议重装为 Debian 12 / Rocky 9；
                    若必须保留：通过 ELRepo 安装 kernel-ml 后 grub2-set-default 0 && reboot
  Rocky/Alma 8 (4.18)  dnf install https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
                    dnf --enablerepo=elrepo-kernel install kernel-ml && grubby --set-default-index=0 && reboot
  Rocky/Alma 9 (5.14 + 大量 BPF 回移)  一般可直接使用；若 check 失败同样可装 ELRepo kernel-ml
  WSL2              Windows PowerShell 中执行: wsl --update；然后 wsl --shutdown 重新打开（新版 WSL 内核为 6.6）
                    或在 %UserProfile%\\.wslconfig 的 [wsl2] 中用 kernel= 指定自编译内核
  OpenVZ / LXC 容器  共享宿主机内核且无权加载 eBPF，无法升级，请换用 KVM/Xen/独立服务器";

fn print_guide() {
    println!();
    println!("{UPGRADE_GUIDE}");
}

pub fn check(paths: &Paths) -> Result<bool> {
    let mut supported = true;
    println!();
    println!("========================================");
    println!("           内核支持检查");
    println!("========================================");

    let release = kernel_release();
    match parse_version(&release) {
        Some((a, b, _)) if (a, b) >= MIN_KERNEL => {
            info(&format!(
                "内核版本: {release}（满足 >= {}.{}）",
                MIN_KERNEL.0, MIN_KERNEL.1
            ));
            if (a, b) >= (6, 6) {
                println!("  挂载方式: TCX（内核 >= 6.6，进程退出时自动卸载）");
            } else {
                println!("  挂载方式: netlink clsact（内核 < 6.6）");
            }
        }
        Some(_) => {
            err(&format!(
                "内核版本: {release}，低于最低要求 {}.{}",
                MIN_KERNEL.0, MIN_KERNEL.1
            ));
            supported = false;
        }
        None => warn(&format!("无法识别内核版本: {release}")),
    }

    let container = container_kind();
    if let Some(c) = &container {
        warn(&format!(
            "检测到运行在容器中（{c}）：容器共享宿主机内核，通常无权加载 eBPF 程序"
        ));
    }

    match kernel_config(&release) {
        Some(cfg) => {
            let required = [
                ("CONFIG_BPF_SYSCALL", "bpf() 系统调用"),
                ("CONFIG_NET_CLS_BPF", "TC eBPF 分类器"),
                ("CONFIG_NET_SCH_INGRESS", "clsact/ingress qdisc"),
                ("CONFIG_NET_CLS_ACT", "TC 动作（重定向）"),
            ];
            for (k, desc) in required {
                match cfg.get(k).map(String::as_str) {
                    Some("y" | "m") => info(&format!("{k}={}（{desc}）", cfg[k])),
                    _ => {
                        err(&format!("{k} 未开启（{desc}）"));
                        supported = false;
                    }
                }
            }
            match cfg.get("CONFIG_BPF_JIT").map(String::as_str) {
                Some("y") => info("CONFIG_BPF_JIT=y（JIT 编译，性能更好）"),
                _ => warn("CONFIG_BPF_JIT 未开启：可以运行但性能较差"),
            }
        }
        None => {
            warn("无法读取内核配置（/boot/config-* 或 /proc/config.gz），以下面的试加载结果为准")
        }
    }

    if unsafe { libc::geteuid() } == 0 {
        bump_memlock_rlimit();
        match datapath::load_object(4096) {
            Ok(_) => info("试加载 eBPF 程序: 成功（内核 verifier 校验通过）"),
            Err(e) => {
                err(&format!("试加载 eBPF 程序失败: {e:#}"));
                supported = false;
            }
        }
    } else {
        warn("非 root 运行，跳过 eBPF 试加载（sudo ebpf-forward check 可做完整检查）");
        if container.is_some() {
            supported = false;
        }
    }

    if supported {
        info("结论: 当前内核支持 eBPF 端口转发。");
    } else {
        err("结论: 当前内核/环境不支持，请参考下面的方法升级。");
        print_guide();
    }

    diagnose(paths);
    Ok(supported)
}

fn diagnose(paths: &Paths) {
    println!();
    println!("========================================");
    println!("           运行环境诊断");
    println!("========================================");

    if netinfo::ip_forward_enabled() {
        info("IPv4 转发: 已开启");
    } else {
        warn("IPv4 转发: 未开启（守护进程启动时会自动开启；install 会写入 /etc/sysctl.d 持久化）");
    }
    if netinfo::ipv6_forward_enabled() {
        info("IPv6 转发: 已开启");
    } else {
        warn("IPv6 转发: 未开启（守护进程启动时会自动开启；install 会写入 /etc/sysctl.d 持久化）");
    }

    match systemctl_state() {
        Some(s) if s == "active" => info("systemd 服务: 运行中"),
        Some(s) => warn(&format!(
            "systemd 服务: {s}（ebpf-forward install 安装，journalctl -u ebpf-forward 查看日志）"
        )),
        None => warn("未检测到 systemd，需要自行保证 `ebpf-forward run` 常驻"),
    }

    let st = status::daemon_pid(paths).and_then(|_| Status::load(&paths.status_file()));
    match &st {
        Some(st) => {
            let ifs: Vec<&str> = st.interfaces.iter().map(|i| i.name.as_str()).collect();
            info(&format!(
                "守护进程: pid {}，挂载网卡 [{}]，规则 {} 条，活动连接 {}",
                st.pid,
                ifs.join(", "),
                st.rules.len(),
                st.conns
            ));
            for r in st.rules.iter().filter(|r| r.state != "ok") {
                warn(&format!(
                    "规则 {}/{} -> {} 未生效: {}",
                    r.listen_port,
                    r.proto,
                    netinfo::fmt_host_port(&r.target, r.target_port),
                    r.error.as_deref().unwrap_or(&r.state)
                ));
            }
            for w in &st.warnings {
                warn(w);
            }
        }
        None => warn("守护进程未运行"),
    }

    let cfg = Config::load(&paths.config).unwrap_or_default();
    let dnat = nft_dnat_ports();
    let mut conflicts: Vec<u16> = cfg
        .rules
        .iter()
        .map(|r| r.listen_port)
        .filter(|p| dnat.iter().any(|(lo, hi)| (*lo..=*hi).contains(p)))
        .collect();
    conflicts.sort_unstable();
    conflicts.dedup();
    if !conflicts.is_empty() {
        let list: Vec<String> = conflicts.iter().map(u16::to_string).collect();
        warn(&format!(
            "本机端口 {} 在 nftables 中也有 DNAT 规则：这些端口由 eBPF 优先处理，对应的 nftables 规则不会生效，建议删除",
            list.join(", ")
        ));
    }
    println!(
        "  提示: eBPF 在 TC 入口完成转发，绕过 netfilter；firewalld/UFW/iptables 的 INPUT/FORWARD 规则不影响也不保护转发流量，云厂商安全组仍需放行端口。"
    );

    if let Some((lo, hi)) = netinfo::local_port_range()
        && cfg.snat_port_min <= hi
        && cfg.snat_port_max >= lo
    {
        warn(&format!(
            "SNAT 端口范围 {}-{} 与本机临时端口范围 {lo}-{hi} 重叠，建议修改 snat_port_min/max",
            cfg.snat_port_min, cfg.snat_port_max
        ));
    }

    if let Some(st) = st {
        let targets: Vec<(String, u16)> = st
            .rules
            .iter()
            .filter(|r| r.state == "ok" && r.proto != "udp")
            .filter_map(|r| r.ip.clone().map(|ip| (ip, r.target_port)))
            .collect();
        if !targets.is_empty()
            && std::io::stdin().is_terminal()
            && confirm("是否测试目标连通性（本机直连目标 TCP 端口）？", false)
        {
            for (ip, port) in targets {
                let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
                    continue;
                };
                let addr = SocketAddr::new(ip, port);
                match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                    Ok(_) => println!("  测试 {addr} (TCP) ... \x1b[32m通\x1b[0m"),
                    Err(e) => println!("  测试 {addr} (TCP) ... \x1b[31m不通 ({e})\x1b[0m"),
                }
            }
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::{parse_dnat_ports, parse_version};

    #[test]
    fn dnat_ports() {
        let ruleset = r#"
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 8080 dnat to 10.0.0.2:80
        udp dport 8080 dnat to 10.0.0.2:80
        iifname != "docker0" meta l4proto tcp tcp dport 2222 counter packets 0 bytes 0 dnat to 172.17.0.2:22
        tcp dport 10000-10100 dnat to 10.0.0.3
        tcp dport { 80, 443 } dnat to 10.0.0.4
        meta nfproto ipv4 tcp dport 3000 dnat ip to 10.0.0.5:3000
        tcp dport 81 redirect to :8081
        tcp dport 9999 accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip daddr 10.0.0.2 tcp dport 53 ct status dnat snat to 192.168.1.10
    }
}"#;
        assert_eq!(
            parse_dnat_ports(ruleset),
            vec![
                (8080, 8080),
                (8080, 8080),
                (2222, 2222),
                (10000, 10100),
                (80, 80),
                (443, 443),
                (3000, 3000),
                (81, 81),
            ]
        );
    }

    #[test]
    fn versions() {
        assert_eq!(
            parse_version("5.15.146.1-microsoft-standard-WSL2"),
            Some((5, 15, 146))
        );
        assert_eq!(parse_version("6.1.0-27-amd64"), Some((6, 1, 0)));
        assert_eq!(parse_version("3.10.0-1160.el7.x86_64"), Some((3, 10, 0)));
        assert_eq!(parse_version("6.12"), Some((6, 12, 0)));
    }
}
