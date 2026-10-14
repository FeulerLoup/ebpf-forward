use anyhow::Result;

use crate::{
    check,
    config::{self, Config, Proto, Rule},
    install,
    manage::{self, confirm, err, info, prompt},
    netinfo::fmt_host_port,
    status::Paths,
};

fn read_port(msg: &str, default: Option<u16>) -> Option<u16> {
    loop {
        let input = prompt(msg)?;
        if input.is_empty()
            && let Some(d) = default
        {
            return Some(d);
        }
        match input.parse::<u16>() {
            Ok(p) if p > 0 && !input.starts_with('0') => return Some(p),
            _ => err("端口无效，请输入 1-65535 之间的数字。"),
        }
    }
}

fn add(paths: &Paths) -> Result<()> {
    let cfg = Config::load(&paths.config)?;
    let Some(lport) = read_port("请输入本机监听端口 (1-65535): ", None) else {
        return Ok(());
    };
    if let Some(r) = cfg.rules.iter().find(|r| r.listen_port == lport) {
        err(&format!(
            "本机端口 {lport} 已存在转发规则 -> {}，请先删除后再添加。",
            fmt_host_port(&r.target, r.target_port)
        ));
        return Ok(());
    }
    let target = loop {
        let Some(t) = prompt("请输入目标地址（IPv4 / IPv6 或域名）: ") else {
            return Ok(());
        };
        match config::validate_target(&t) {
            Ok(()) => break config::normalize_target(&t).to_owned(),
            Err(e) => err(&e.to_string()),
        }
    };
    let Some(tport) = read_port(
        &format!("请输入目标端口 (1-65535) [默认: {lport}]: "),
        Some(lport),
    ) else {
        return Ok(());
    };
    let proto = match prompt("协议: 1) tcp+udp  2) tcp  3) udp [默认 1]: ").as_deref() {
        Some("2") => Proto::Tcp,
        Some("3") => Proto::Udp,
        _ => Proto::Both,
    };
    if !manage::check_port_conflict(lport, proto) {
        info("已取消。");
        return Ok(());
    }
    let comment = prompt("备注（可留空）: ").unwrap_or_default();

    println!();
    println!("即将添加转发规则:");
    println!(
        "  本机端口 {lport} ({proto}) -> {}",
        fmt_host_port(&target, tport)
    );
    if target.parse::<std::net::IpAddr>().is_err() {
        println!("  目标为域名，每隔 resolve_interval（默认 300 秒）重新解析一次");
    }
    if !confirm("确认添加？", true) {
        info("已取消。");
        return Ok(());
    }
    manage::add(
        paths,
        Rule {
            listen_port: lport,
            target,
            target_port: tport,
            proto,
            snat_ip: None,
            comment,
        },
        true,
    )
}

fn delete(paths: &Paths) -> Result<()> {
    let cfg = Config::load(&paths.config)?;
    if cfg.rules.is_empty() {
        info("当前没有端口转发规则，无需删除。");
        return Ok(());
    }
    manage::list(paths)?;
    let Some(choice) = prompt("请输入要删除的序号 (0 取消): ") else {
        return Ok(());
    };
    if choice.is_empty() || choice == "0" {
        info("已取消。");
        return Ok(());
    }
    let idx: usize = match choice.parse() {
        Ok(n) if (1..=cfg.rules.len()).contains(&n) => n,
        _ => {
            err("无效的序号。");
            return Ok(());
        }
    };
    let r = &cfg.rules[idx - 1];
    println!("即将删除转发规则:");
    println!(
        "  本机端口 {} ({}) -> {}",
        r.listen_port,
        r.proto,
        fmt_host_port(&r.target, r.target_port)
    );
    if !confirm("确认删除？", true) {
        info("已取消。");
        return Ok(());
    }
    manage::del(paths, r.listen_port, Some(r.proto))
}

pub fn run(paths: &Paths) -> Result<()> {
    if let Err(e) = manage::require_root() {
        err(&e.to_string());
        return Ok(());
    }
    loop {
        println!();
        println!("========================================");
        println!("   eBPF 端口转发管理工具 v{}", env!("CARGO_PKG_VERSION"));
        println!("========================================");
        println!("  1) 安装 / 更新服务（开机自启）");
        println!("  2) 查看现有端口转发");
        println!("  3) 新增端口转发");
        println!("  4) 删除端口转发");
        println!("  5) 一键清空所有转发");
        println!("  6) 查看活动连接");
        println!("  7) 运行状态与统计");
        println!("  8) 诊断 / 自检（含内核支持检查）");
        println!("  9) 卸载");
        println!("  0) 退出");
        println!("========================================");
        let Some(choice) = prompt("请选择操作 [0-9]: ") else {
            return Ok(());
        };
        let res = match choice.as_str() {
            "1" => install::install(paths),
            "2" => manage::list(paths),
            "3" => add(paths),
            "4" => delete(paths),
            "5" => manage::clear(paths, false),
            "6" => manage::conns(paths),
            "7" => manage::status(paths),
            "8" => check::check(paths).map(|_| ()),
            "9" => {
                if confirm("确认卸载服务？（配置文件会保留）", false) {
                    install::uninstall(paths, false)
                } else {
                    Ok(())
                }
            }
            "0" | "q" => {
                info("再见！");
                return Ok(());
            }
            _ => {
                err("无效选择，请输入 0-9。");
                Ok(())
            }
        };
        if let Err(e) = res {
            err(&format!("{e:#}"));
        }
    }
}
