# ebpf-forward

[![Build & Release](https://github.com/FeulerLoup/ebpf-forward/actions/workflows/release.yml/badge.svg)](https://github.com/FeulerLoup/ebpf-forward/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/FeulerLoup/ebpf-forward)](https://github.com/FeulerLoup/ebpf-forward/releases/latest)

基于 eBPF 的 Linux 端口转发工具，使用 Rust + [aya](https://aya-rs.dev) 编写。效果等同于 nftables 的 DNAT + SNAT 端口转发：把本机端口收到的 TCP/UDP 流量转发到目标 IP 或**域名**，同时把源地址改写成本机，让回包经本机原路返回。

转发在网卡的 TC 入口完成：eBPF 程序改写报文后查路由表，直接从出口网卡发出，不经过内核协议栈和 netfilter / conntrack。

## 特性

- DNAT + SNAT，自带连接跟踪；可转发 TCP、UDP 或两者
- 支持 IPv4 / IPv6 任意进任意出（v4→v4、v6→v6、v4→v6、v6→v4），同一本机监听端口同时接受 IPv4 与 IPv6 客户端连入
- 目标支持域名（A / AAAA），定时重新解析（默认 300 秒），解析失败时沿用上次结果
- ICMP / ICMPv6 差错（端口不可达、需要分片 / Packet Too Big、TTL 超时）会转换回连接的另一端（含跨协议族 ICMPv4↔ICMPv6 转换），PMTU 发现正常工作
- 对 SYN / SYN-ACK 做 MSS 钳制，出口是 WireGuard 等小 MTU 网卡或跨 v4↔v6 转发时连接不会卡住
- 支持以太网网卡，以及 WireGuard、tun 等没有二层头的网卡
- 交互式菜单 + 命令行；systemd 服务；修改配置自动生效
- 单个静态二进制（musl），提供 x86_64 与 aarch64 版本

## 工作原理

```
客户端 C:cp ──▶ 本机 L:lp ══ DNAT + SNAT ══▶ 本机 S:np ──▶ 目标 T:tp
客户端 C:cp ◀── 本机 L:lp ◀═════ 还原 ═════ 本机 S:np ◀── 目标 T:tp
```

- **L**：客户端访问的本机地址；**S**：本机去往目标时的出口地址（自动获取，相当于 nftables 规则里 `snat to` 后面的本机 IP）
- **np**：从 SNAT 端口范围中分配，优先沿用客户端的源端口
- 每条连接在连接跟踪表里占两项（原方向、回复方向），守护进程按 TCP 状态和空闲时间回收

## 系统要求

| 项目 | 要求 |
|---|---|
| 内核 | ≥ 5.10，推荐 ≥ 5.15。内核 < 6.6 通过 netlink clsact 挂载，≥ 6.6 使用 TCX |
| 内核配置 | `CONFIG_BPF_SYSCALL`、`CONFIG_NET_CLS_BPF`、`CONFIG_NET_SCH_INGRESS`、`CONFIG_NET_CLS_ACT`（主流发行版默认开启） |
| CPU 架构 | x86_64、aarch64 |
| 运行环境 | root 权限；KVM / Xen / 独立服务器 / WSL2。OpenVZ、LXC 等容器无法加载 eBPF |

安装前可以先运行 `sudo ebpf-forward check`。它会读取内核配置，并把 eBPF 程序交给内核 verifier 试加载（不挂载，不影响网络）；不支持时会给出升级方法。

### 内核升级参考

| 系统 | 方法 |
|---|---|
| Debian 11（5.10） | 已满足要求；也可以升级到 Debian 12 / 13 |
| Debian 10 及更早 | 逐个大版本 `apt full-upgrade` 升级，或重装为 Debian 12 / 13 |
| Ubuntu 18.04 / 20.04 | `apt install --install-recommends linux-generic-hwe-20.04`（5.15；18.04 需先升级到 20.04） |
| Ubuntu 22.04 及以上 | 已满足要求 |
| CentOS 7 / RHEL 7（3.10） | 已停止维护，建议重装为 Debian 12 / Rocky 9；必须保留时可通过 ELRepo 安装 `kernel-ml` |
| Rocky / Alma 8（4.18） | `dnf install https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm`<br>`dnf --enablerepo=elrepo-kernel install kernel-ml && grubby --set-default-index=0 && reboot` |
| Rocky / Alma 9（5.14） | 带有大量 BPF 回移，一般可直接使用；`check` 不通过时同样可装 ELRepo `kernel-ml` |
| WSL2 | 自带的 5.15 内核即可。也可以在 PowerShell 中执行 `wsl --update`，再 `wsl --shutdown` 重开，升级到 6.6 |
| OpenVZ / LXC 容器 | 共享宿主机内核且无权加载 eBPF，无法使用，请换用 KVM 架构的 VPS |

升级后重启，用 `uname -r` 确认，再运行 `ebpf-forward check`。

## 安装

### 一键安装 / 升级（推荐）

```bash
curl -fsSL https://github.com/FeulerLoup/ebpf-forward/releases/latest/download/install.sh | sudo bash
```

脚本按 CPU 架构下载 Release 里的静态二进制，校验 sha256 后放到 `/usr/local/bin/ebpf-forward`，再执行 `ebpf-forward install`。`install` 会依次完成：检查内核支持、创建默认配置、开启并持久化 `net.ipv4.ip_forward`、安装并启动 systemd 服务。重复执行即为升级，配置文件会保留。

可选环境变量（写在 `sudo` 与 `bash` 之间，例如 `curl -fsSL ... | sudo VERSION=v0.1.0 bash`）：

| 变量 | 说明 |
|---|---|
| `VERSION=v0.1.0` | 安装指定版本，默认最新版 |
| `DOWNLOAD_BASE=<URL>` | 直接指定存放二进制和 `sha256sums.txt` 的目录，例如 GitHub 镜像地址，适合访问 GitHub 较慢的机器 |

### 手动下载

从 [Releases](https://github.com/FeulerLoup/ebpf-forward/releases) 下载对应架构的二进制：

```bash
curl -fL -o ebpf-forward \
  https://github.com/FeulerLoup/ebpf-forward/releases/latest/download/ebpf-forward-x86_64-unknown-linux-musl
chmod +x ebpf-forward
sudo ./ebpf-forward install      # 会把自己复制到 /usr/local/bin
```

ARM64 机器把文件名换成 `ebpf-forward-aarch64-unknown-linux-musl`。

### 从源码编译

需要 rustup（stable ≥ 1.91）、nightly 的 `rust-src` 和 [bpf-linker](https://github.com/aya-rs/bpf-linker)。`scripts/build.sh` 会按 `scripts/toolchain.env` 中锁定的版本自动安装 nightly；本机没有对应版本的 bpf-linker 时，会下载官方预编译版到 `target/tools/`：

```bash
scripts/build.sh                                     # 编译本机架构
TARGET=aarch64-unknown-linux-musl scripts/build.sh   # 在 x86_64 上交叉编译 aarch64
```

产物位于 `target/<target>/release/ebpf-forward`，复制到目标机器即可运行。

## 使用

### 交互式菜单

```bash
sudo ebpf-forward
```

菜单包括：安装/更新服务、查看转发、新增转发、删除转发、一键清空、查看活动连接、运行状态、诊断/自检、卸载。

### 命令行

```bash
sudo ebpf-forward add 8080 example.com 80              # 本机 8080 (tcp+udp) -> example.com:80
sudo ebpf-forward add 5353 1.1.1.1 53 -p udp           # 只转发 UDP
sudo ebpf-forward add 2222 10.0.0.5 22 -p tcp --comment "内网 SSH"
sudo ebpf-forward add 443 10.0.0.5                     # 目标端口省略时与本机端口相同
ebpf-forward list                                      # 规则与状态：解析结果、SNAT 地址、出口网卡、连接数
sudo ebpf-forward conns                                # 活动连接（类似 conntrack -L）
sudo ebpf-forward status                               # 运行状态与转发统计
sudo ebpf-forward del 8080                             # 删除（-p tcp 只删除 TCP）
sudo ebpf-forward clear                                # 清空全部规则
sudo ebpf-forward check                                # 内核支持检查 + 环境诊断
```

| 子命令 | 说明 |
|---|---|
| `run` | 前台运行守护进程（systemd 服务执行的就是它） |
| `add <本机端口> <目标> [目标端口]` | 新增规则。`-p tcp\|udp\|tcp+udp`（默认 tcp+udp）、`--snat-ip` 手动指定 SNAT 源地址、`--comment` 备注、`-y` 端口被本地服务占用时不再询问 |
| `del <本机端口>` | 删除规则，`-p` 只删除指定协议 |
| `list` | 查看规则与生效状态 |
| `clear` | 清空规则（`-y` 跳过确认） |
| `conns` | 查看连接跟踪表 |
| `status` | 守护进程状态、挂载的网卡、转发与丢包统计 |
| `check` | 内核支持检查与运行环境诊断 |
| `install` / `uninstall [--purge]` | 安装 / 卸载 systemd 服务（`--purge` 同时删除配置和程序） |
| `cleanup` | 卸载网卡上残留的 eBPF 挂载 |
| `menu` | 交互式菜单（不带子命令运行时默认进入） |

全局参数：`-c, --config <文件>`（默认 `/etc/ebpf-forward/config.toml`）、`--run-dir <目录>`（默认 `/run/ebpf-forward`）。

通过命令行增删规则后，程序会通知守护进程立即重新加载，等它应用完成（包括域名解析）再显示结果。

## 配置文件

默认路径为 `/etc/ebpf-forward/config.toml`。也可以手动编辑，保存后约 2 秒内自动生效（或执行 `systemctl reload ebpf-forward`）；配置有误时守护进程会记录错误并继续使用旧配置。

```toml
resolve_interval = 300
interfaces = []
snat_port_min = 10000
snat_port_max = 32767
mss_clamp = true
ct_max = 131072
tcp_timeout = 86400
udp_timeout = 120

[[rule]]
listen_port = 8080
target = "example.com"
target_port = 80
proto = "tcp+udp"
comment = "网站"

[[rule]]
listen_port = 5353
target = "1.1.1.1"
target_port = 53
proto = "udp"
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `resolve_interval` | 300 | 域名重新解析间隔（秒） |
| `interfaces` | `[]` | 挂载 eBPF 的网卡。留空时自动选择：所有已启用且有 IP 地址的网卡，加上去往各目标的出口网卡；网卡增删后自动重新挂载 |
| `snat_port_min` / `snat_port_max` | 10000 / 32767 | SNAT 源端口范围，应避开 `net.ipv4.ip_local_port_range`（默认 32768-60999） |
| `mss_clamp` | true | 把 SYN / SYN-ACK 的 MSS 钳制到 min(入口 MTU, 出口 MTU) - (纯 v4 为 40，含 v6 为 60) |
| `ct_max` | 131072 | 连接跟踪表容量，每条连接占 2 项（默认约 6.5 万条连接，满了按 LRU 淘汰）。修改后需重启服务 |
| `tcp_timeout` | 86400 | TCP 已建立连接的空闲超时（秒） |
| `udp_timeout` | 120 | 有回包的 UDP 会话空闲超时（秒）；没有回包的 30 秒回收 |

| 规则字段 | 说明 |
|---|---|
| `listen_port` | 本机端口（同时接受 IPv4 与 IPv6 连入） |
| `target` | 目标 IPv4 / IPv6 地址或域名 |
| `target_port` | 目标端口 |
| `proto` | `tcp` / `udp` / `tcp+udp`（默认） |
| `snat_ip` | 可选，手动指定 SNAT 源地址（必须是本机地址且与目标同协议族），默认自动使用去往目标的出口地址 |
| `comment` | 可选，备注 |

TCP 的其余超时参照 Linux conntrack：收到 RST 后 10 秒，双方都发出 FIN 后 60 秒，单方 FIN 后 120 秒，SYN 无应答 60 秒。

## 域名解析

- 使用系统解析器（`/etc/hosts` + `/etc/resolv.conf`），支持 IPv4（A）与 IPv6（AAAA），自动优选本机有去往路由的地址
- 每隔 `resolve_interval` 秒在后台重新解析；配置变化时立即解析
- 新结果里仍包含当前使用的 IP（且路由可达）时不切换，避免轮询 DNS 导致目标来回变化；否则切换到首个可达地址，并在日志中记录“解析变化”
- 解析失败时继续使用上次的结果；从未解析成功的规则暂不生效
- 已建立的连接不受解析变化影响，继续连接旧 IP；新连接使用新 IP

## 与 nftables 端口转发的区别与注意事项

- **防火墙**：转发在 netfilter 之前完成并直接发出，firewalld / UFW / iptables 的 INPUT、FORWARD 规则既不会拦截、也无法保护转发流量，所以不需要为转发端口放行。云厂商的安全组仍需放行端口
- 同一端口如果在 nftables 里也有 DNAT 规则，由 eBPF 优先处理，nftables 的规则不再生效；`ebpf-forward check` 会列出冲突的端口
- 支持 IPv4 / IPv6 任意组合转发（v4→v4、v6→v6、v4→v6、v6→v4）；只支持单个端口，不支持端口段
- 不转发 IP 分片报文：超过 MTU 的大 UDP 包会受影响，TCP 不受影响
- 目标不能是本机地址或链路本地地址（`fe80::/10`）
- 只转发发往本机地址的报文，不会影响路过本机（路由转发）的流量；本机自己访问 `127.0.0.1:端口` / `[::1]:端口` 也不会被转发（与 nftables 的 prerouting DNAT 一致）
- 删除规则后，该规则已有的连接会在 10 秒内断开

## 排错

- 日志：`journalctl -u ebpf-forward -f`
- `ebpf-forward list` 会显示每条规则未生效的原因，例如域名解析失败、没有去往目标的路由、目标是本机地址
- `ebpf-forward status` 中的丢包计数：
  - **无路由/未开启转发**：检查 `sysctl net.ipv4.ip_forward`（应为 1）以及去往目标的路由
  - **超过出口 MTU**：非 TCP 的大包超过出口网卡 MTU；TCP 由 MSS 钳制处理
  - **SNAT 端口耗尽**：同一目标的并发连接过多，可扩大 SNAT 端口范围
- 内核 < 6.6 时，守护进程如果被 `kill -9`，网卡上会残留 eBPF 挂载（继续按旧规则转发）。重启服务会自动替换残留，也可以停止服务后执行 `ebpf-forward cleanup`
- 也可以直接查看内核里的对象：`bpftool net show`、`tc filter show dev eth0 ingress`

## 开发

### 目录结构

```
ebpf-forward/          用户态：命令行、守护进程、配置、map 管理
ebpf-forward-ebpf/     eBPF 程序（TC classifier：fwd_eth / fwd_l3）
ebpf-forward-common/   内核态与用户态共享的 map 结构
scripts/build.sh       编译静态二进制
scripts/toolchain.env  锁定的 nightly / bpf-linker 版本（build.sh 与 CI 共用）
scripts/release.sh     一键改版本、打标签并推送，触发自动发布
scripts/install.sh     一键安装脚本（随 Release 发布）
scripts/netns-test.sh  端到端测试
.github/workflows/     CI 与自动发布
```

### 测试

```bash
cargo test --release           # 单元测试

BIN=target/x86_64-unknown-linux-musl/release/ebpf-forward
sudo scripts/netns-test.sh $BIN partial
sudo scripts/netns-test.sh $BIN full
sudo LONG=1 scripts/netns-test.sh $BIN partial   # 额外验证超时回收（多等 75 秒）
```

端到端测试在新建的 network namespace 中搭建“客户端 / 转发机 / 路由器 / 目标机 / WireGuard 对端”，覆盖以下场景：

- TCP / UDP 转发，SNAT 是否生效
- 域名目标，以及解析变化后的切换
- ICMP 端口不可达与 PMTU 发现
- MSS 钳制
- WireGuard 等 L3 网卡
- 同网卡回环、源端口复用
- 删除规则、连接回收、退出卸载与异常退出后的恢复

两种模式分别验证 CHECKSUM_PARTIAL（GSO）报文和完整校验和报文，并用 tcpdump 独立重新计算校验和。测试只操作新建的 namespace，不影响本机网络。

依赖：iproute2、ethtool、curl、iperf3、python3、tcpdump，wireguard-tools 可选（缺少时跳过 L3 网卡测试）。

### CI 与发布

`.github/workflows/release.yml` 的行为：

- **push / PR**：编译 x86_64 与 aarch64 静态二进制（aarch64 在 x86_64 上用 rust-lld 交叉编译），检查 `cargo fmt`，跑单元测试，并在 GitHub runner 的真实内核上跑两种模式的端到端测试。二进制作为 artifact 保留
- **推送 `v*` 标签**：以上全部通过后创建 GitHub Release，附件包括：
  - `ebpf-forward-x86_64-unknown-linux-musl`
  - `ebpf-forward-aarch64-unknown-linux-musl`
  - `install.sh`（已写入本仓库地址）
  - `sha256sums.txt`

  标签里带 `-` 时（如 `v0.2.0-rc.1`）发布为预发布版本；重新运行工作流会覆盖已上传的附件

#### 发布新版本

标签必须与 Cargo.toml 中的版本一致（工作流会校验）。`scripts/release.sh` 一条命令完成全部步骤：修改根目录 Cargo.toml 的版本 → 刷新 Cargo.lock（只更新本项目的包，不升级依赖）→ 提交 → 创建标签 → 推送。

```bash
scripts/release.sh patch --push         # 0.1.0 -> 0.1.1，提交、打标签 v0.1.1 并推送
scripts/release.sh minor --push         # 0.1.0 -> 0.2.0（major -> 1.0.0）
scripts/release.sh 1.0.0-rc.1 --push    # 指定版本；带 - 的版本发布为预发布
scripts/release.sh 0.1.0 --push         # 传入当前版本：不改版本、只打标签（首次发布用这个）
scripts/release.sh minor --dry-run      # 只显示将要做的事
```

- 不加 `--push` 时，脚本会在终端里询问是否推送；非交互环境下只打本地标签，并打印推送命令
- 执行前会检查：工作区没有未提交的改动、当前在分支上、本地和远端都还没有这个标签、代码通过 `cargo fmt --check`
- 进度在 [Actions](https://github.com/FeulerLoup/ebpf-forward/actions) 页面查看，全部通过后 Release 出现在 [Releases](https://github.com/FeulerLoup/ebpf-forward/releases) 页面
- CI 失败需要重新发布时：先删除标签 `git tag -d v0.1.1 && git push origin :refs/tags/v0.1.1`，修复并提交后执行 `scripts/release.sh 0.1.1 --push`（版本已改好，只会重新打标签）

编译 eBPF 使用的 nightly（`EBPF_TOOLCHAIN`）和 bpf-linker（`BPF_LINKER_VERSION`）锁定在 `scripts/toolchain.env` 中，CI 与 `scripts/build.sh` 都从这里读取。两者必须使用相同的 LLVM 大版本：升级 nightly 后如果出现 LLVM / bitcode 相关的链接错误，要同时把 bpf-linker 升到对应版本。直接用 `cargo build` 编译时不受这个文件约束：设置了 `EBPF_TOOLCHAIN` 环境变量就用它，否则使用最新 nightly。

## 许可证

Cargo.toml 中声明为 MIT OR Apache-2.0；eBPF 程序以 `Dual MIT/GPL` 许可证加载（`bpf_fib_lookup` 等内核 helper 要求 GPL 兼容许可证）。
