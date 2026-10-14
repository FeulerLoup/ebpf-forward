use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

use anyhow::{Context as _, Result, bail};

use crate::{
    check::UPGRADE_GUIDE,
    config::{Config, DEFAULT_CONFIG},
    daemon::bump_memlock_rlimit,
    datapath,
    manage::{self, info, require_root, warn},
    netinfo,
    status::Paths,
};

pub const BIN_PATH: &str = "/usr/local/bin/ebpf-forward";
const UNIT_PATH: &str = "/etc/systemd/system/ebpf-forward.service";
const SYSCTL_CONF: &str = "/etc/sysctl.d/99-ebpf-forward.conf";

fn has_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

fn unit_file(paths: &Paths) -> String {
    let mut exec = format!("{BIN_PATH} run");
    if paths.config != Path::new(DEFAULT_CONFIG) {
        exec += &format!(" --config {}", paths.config.display());
    }
    format!(
        "\
[Unit]
Description=eBPF port forwarding (DNAT/SNAT)
Documentation=man:tc-bpf(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
LimitMEMLOCK=infinity
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
"
    )
}

pub fn install(paths: &Paths) -> Result<()> {
    require_root()?;
    println!();

    bump_memlock_rlimit();
    if let Err(e) = datapath::load_object(4096) {
        manage::err(&format!("当前内核无法加载 eBPF 程序: {e:#}"));
        println!("\n{UPGRADE_GUIDE}");
        bail!("内核不支持，已中止安装");
    }
    info("内核支持检查通过（eBPF 程序已通过 verifier 校验）。");

    let exe = std::env::current_exe().context("获取当前程序路径失败")?;
    let dst = Path::new(BIN_PATH);
    if fs::canonicalize(&exe).ok() != fs::canonicalize(dst).ok() {
        let tmp = dst.with_extension("new");
        fs::copy(&exe, &tmp).with_context(|| format!("复制程序到 {} 失败", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
        fs::rename(&tmp, dst)?;
        info(&format!("已安装程序到 {BIN_PATH}"));
    }

    if paths.config.exists() {
        Config::load(&paths.config)?;
        info(&format!("保留现有配置 {}", paths.config.display()));
    } else {
        Config::default().save(&paths.config)?;
        info(&format!("已创建配置文件 {}", paths.config.display()));
    }

    fs::write(
        SYSCTL_CONF,
        "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n",
    )
    .with_context(|| format!("写入 {SYSCTL_CONF} 失败"))?;
    if netinfo::enable_ip_forward().unwrap_or(false) {
        info("已开启 IPv4 转发");
    }
    if netinfo::enable_ipv6_forward().unwrap_or(false) {
        info("已开启 IPv6 转发");
    }
    info(&format!("已持久化 IPv4/IPv6 转发配置到 {SYSCTL_CONF}"));

    if !has_systemd() {
        warn("未检测到 systemd：请自行配置开机启动，例如在 /etc/rc.local 中加入:");
        println!("  nohup {BIN_PATH} run >/var/log/ebpf-forward.log 2>&1 &");
        return Ok(());
    }
    fs::write(UNIT_PATH, unit_file(paths)).with_context(|| format!("写入 {UNIT_PATH} 失败"))?;
    systemctl(&["daemon-reload"]);
    if systemctl(&["enable", "ebpf-forward"]) && systemctl(&["restart", "ebpf-forward"]) {
        info("已启用并启动 ebpf-forward 服务（开机自启）。");
        std::thread::sleep(std::time::Duration::from_secs(2));
        manage::status(paths)?;
    } else {
        warn("服务启动失败，请查看: journalctl -u ebpf-forward -e");
    }
    Ok(())
}

pub fn uninstall(paths: &Paths, purge: bool) -> Result<()> {
    require_root()?;
    if has_systemd() && Path::new(UNIT_PATH).exists() {
        systemctl(&["disable", "--now", "ebpf-forward"]);
        fs::remove_file(UNIT_PATH).ok();
        systemctl(&["daemon-reload"]);
        info("已停止并移除 systemd 服务。");
    }
    let _ = manage::cleanup(paths, true);
    fs::remove_file(SYSCTL_CONF).ok();
    if purge {
        if let Some(dir) = paths.config.parent() {
            fs::remove_dir_all(dir).ok();
        }
        fs::remove_file(BIN_PATH).ok();
        info("已删除配置和程序文件。");
    } else {
        info(&format!(
            "配置文件 {} 已保留（--purge 可一并删除）。",
            paths.config.display()
        ));
    }
    info("提示: net.ipv4.ip_forward 未改回，如不需要可执行 sysctl -w net.ipv4.ip_forward=0");
    Ok(())
}
