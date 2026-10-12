#!/usr/bin/env bash
#
# ebpf-forward 一键安装 / 升级：下载对应架构的静态二进制，校验后安装为 systemd 服务。
#
#   curl -fsSL https://github.com/FeulerLoup/ebpf-forward/releases/latest/download/install.sh | sudo bash
#
# 可选环境变量:
#   VERSION=v0.1.0         安装指定版本（默认最新版）
#   REPO=owner/repo        从其他仓库下载（发布时会替换为发布所在的仓库）
#   DOWNLOAD_BASE=<URL>    直接指定下载目录（如 GitHub 镜像），优先于 REPO / VERSION
#
set -euo pipefail

REPO=${REPO:-FeulerLoup/ebpf-forward}
BIN=/usr/local/bin/ebpf-forward

info() { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
die()  { printf '\033[31m[错误]\033[0m %s\n' "$1" >&2; exit 1; }

[[ -n $REPO || -n ${DOWNLOAD_BASE:-} ]] || die "未设置仓库，请这样运行: REPO=owner/repo bash install.sh"
[[ $EUID -eq 0 ]] || die "需要 root 权限，请使用 sudo 运行"
command -v curl >/dev/null || die "缺少 curl"

case $(uname -m) in
    x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
    *) die "不支持的 CPU 架构: $(uname -m)（仅提供 x86_64 / aarch64）" ;;
esac

if [[ -n ${DOWNLOAD_BASE:-} ]]; then
    base=${DOWNLOAD_BASE%/}
elif [[ -n ${VERSION:-} ]]; then
    base="https://github.com/$REPO/releases/download/$VERSION"
else
    base="https://github.com/$REPO/releases/latest/download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
asset="ebpf-forward-$target"
info "下载 $base/$asset"
curl -fSL --retry 3 -o "$tmp/$asset" "$base/$asset" || die "下载失败"
if curl -fsSL --retry 3 -o "$tmp/sha256sums.txt" "$base/sha256sums.txt" && command -v sha256sum >/dev/null; then
    (cd "$tmp" && grep " $asset\$" sha256sums.txt | sha256sum -c --quiet -) || die "sha256 校验失败"
    info "sha256 校验通过"
fi

# install 会先删除旧文件再写入，服务运行中也能直接覆盖升级
install -m 755 "$tmp/$asset" "$BIN"
info "已安装 $("$BIN" --version)"
# 检查内核支持、写默认配置、开启 ip_forward、安装并（重新）启动 systemd 服务
"$BIN" install </dev/null
echo
info "新增转发: ebpf-forward add 8080 example.com 80    交互菜单: ebpf-forward"
