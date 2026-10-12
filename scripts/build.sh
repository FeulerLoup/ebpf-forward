#!/usr/bin/env bash
#
# 编译静态链接的 ebpf-forward（musl），产物可直接复制到同架构的任意 Linux 上运行。
#
#   scripts/build.sh                                     # 本机架构
#   TARGET=aarch64-unknown-linux-musl scripts/build.sh   # 在 x86_64 上交叉编译 aarch64
#
# 依赖：rustup、curl；需要下载 bpf-linker 时还需要 tar + zstd。
#
set -euo pipefail
cd "$(dirname "$0")/.."

# 锁定的 nightly / bpf-linker 版本（与 CI 共用），已设置的同名环境变量优先
while IFS='=' read -r key value; do
    if [[ $key =~ ^[A-Z_]+$ && -z ${!key:-} ]]; then
        export "$key=$value"
    fi
done <scripts/toolchain.env

TARGET=${TARGET:-$(uname -m)-unknown-linux-musl}

command -v rustup >/dev/null || {
    echo "请先安装 Rust: curl --proto '=https' -sSf https://sh.rustup.rs | sh"
    exit 1
}
rustup toolchain install "$EBPF_TOOLCHAIN" --profile minimal --component rust-src
rustup target add "$TARGET"

# cargo install bpf-linker 需要系统 LLVM，这里用官方预编译的静态版本，放在 target/tools 下
linker_version=${BPF_LINKER_VERSION#v}
if ! bpf-linker --version 2>/dev/null | grep -qF "$linker_version"; then
    tools="$PWD/target/tools/bpf-linker-$linker_version"
    if [[ ! -x $tools/bpf-linker ]]; then
        url="https://github.com/aya-rs/bpf-linker/releases/download/$BPF_LINKER_VERSION/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst"
        echo "下载 bpf-linker: $url"
        tmp=$(mktemp -d)
        curl -fsSL --retry 3 "$url" | tar --zstd -x -C "$tmp"
        mkdir -p "$tools"
        install -m 755 "$(find "$tmp" -type f -name bpf-linker | head -n1)" "$tools/bpf-linker"
        rm -rf "$tmp"
    fi
    export PATH="$tools:$PATH"
fi

cargo build --release --target "$TARGET"
echo
echo "产物: $PWD/target/$TARGET/release/ebpf-forward"
