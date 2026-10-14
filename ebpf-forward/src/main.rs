mod check;
mod config;
mod daemon;
mod datapath;
mod install;
mod manage;
mod menu;
mod netinfo;
mod status;

use std::{io::IsTerminal as _, path::PathBuf, process::ExitCode};

use clap::{CommandFactory as _, Parser, Subcommand};

use crate::{
    config::{DEFAULT_CONFIG, DEFAULT_RUN_DIR, Proto, Rule},
    status::Paths,
};

/// 基于 eBPF (TC ingress) 的端口转发：DNAT + SNAT，支持域名目标（定时重新解析）。
///
/// 不带子命令运行时进入交互式菜单。
#[derive(Parser)]
#[command(name = "ebpf-forward", version)]
struct Cli {
    /// 配置文件
    #[arg(short, long, global = true, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// 运行目录（pid 与状态文件）
    #[arg(long, global = true, default_value = DEFAULT_RUN_DIR)]
    run_dir: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 前台运行转发守护进程（systemd 服务即执行此命令）
    Run,
    /// 新增转发规则，例如: add 8080 example.com 80
    Add {
        /// 本机监听端口
        listen_port: u16,
        /// 目标 IPv4 / IPv6 地址或域名
        target: String,
        /// 目标端口（默认与本机端口相同）
        target_port: Option<u16>,
        /// 协议: tcp / udp / tcp+udp
        #[arg(short, long, default_value = "tcp+udp")]
        proto: Proto,
        /// 手动指定 SNAT 源地址（默认自动取去往目标的出口地址）
        #[arg(long)]
        snat_ip: Option<std::net::IpAddr>,
        /// 备注
        #[arg(long, default_value = "")]
        comment: String,
        /// 端口已被本地服务占用时不再询问
        #[arg(short, long)]
        yes: bool,
    },
    /// 删除本机端口的转发规则
    #[command(alias = "rm")]
    Del {
        listen_port: u16,
        /// 只删除指定协议（默认全部）
        #[arg(short, long)]
        proto: Option<Proto>,
    },
    /// 查看转发规则与生效状态
    #[command(alias = "ls")]
    List,
    /// 清空全部规则
    Clear {
        #[arg(short, long)]
        yes: bool,
    },
    /// 查看活动连接（连接跟踪表）
    Conns,
    /// 运行状态与转发统计
    Status,
    /// 检查内核是否支持并诊断运行环境
    Check,
    /// 安装为 systemd 服务并开机自启
    Install,
    /// 卸载 systemd 服务
    Uninstall {
        /// 同时删除配置文件和程序
        #[arg(long)]
        purge: bool,
    },
    /// 卸载网卡上残留的 eBPF 挂载（守护进程异常退出后使用）
    Cleanup {
        #[arg(long)]
        force: bool,
    },
    /// 交互式菜单
    Menu,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let paths = Paths {
        config: cli.config,
        run_dir: cli.run_dir,
    };
    let is_daemon = matches!(cli.cmd, Some(Cmd::Run));
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_target(false)
        .init();

    let res = match cli.cmd {
        Some(Cmd::Run) => daemon::run(paths),
        Some(Cmd::Add {
            listen_port,
            target,
            target_port,
            proto,
            snat_ip,
            comment,
            yes,
        }) => manage::add(
            &paths,
            Rule {
                listen_port,
                target,
                target_port: target_port.unwrap_or(listen_port),
                proto,
                snat_ip,
                comment,
            },
            yes,
        ),
        Some(Cmd::Del { listen_port, proto }) => manage::del(&paths, listen_port, proto),
        Some(Cmd::List) => manage::list(&paths),
        Some(Cmd::Clear { yes }) => manage::clear(&paths, yes),
        Some(Cmd::Conns) => manage::conns(&paths),
        Some(Cmd::Status) => manage::status(&paths),
        Some(Cmd::Check) => match check::check(&paths) {
            Ok(true) => Ok(()),
            Ok(false) => return ExitCode::from(2),
            Err(e) => Err(e),
        },
        Some(Cmd::Install) => install::install(&paths),
        Some(Cmd::Uninstall { purge }) => install::uninstall(&paths, purge),
        Some(Cmd::Cleanup { force }) => manage::cleanup(&paths, force),
        Some(Cmd::Menu) => menu::run(&paths),
        None if std::io::stdin().is_terminal() => menu::run(&paths),
        None => {
            let _ = Cli::command().print_help();
            return ExitCode::from(2);
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if is_daemon {
                log::error!("{e:#}");
            } else {
                manage::err(&format!("{e:#}"));
            }
            ExitCode::FAILURE
        }
    }
}
