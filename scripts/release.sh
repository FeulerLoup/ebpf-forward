#!/usr/bin/env bash
#
# 一键改版本并打标签：修改 Cargo.toml 版本 -> 刷新 Cargo.lock -> 提交 -> 创建 vX.Y.Z 标签 -> 推送。
# 推送标签后 GitHub Actions 自动构建、测试并发布 Release。
#
#   scripts/release.sh patch            0.1.0 -> 0.1.1（minor -> 0.2.0，major -> 1.0.0）
#   scripts/release.sh 0.2.0            指定版本（也可写 v0.2.0；带 - 的如 1.0.0-rc.1 发布为预发布）
#   scripts/release.sh 0.1.0            传入当前版本：不改版本，只打标签（首次发布或重新打标签）
#
#   -p, --push      完成后直接推送分支和标签（默认询问）
#   -n, --dry-run   只显示将要做的事，不做任何修改
#
set -euo pipefail
cd "$(dirname "$0")/.."

info() { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
die()  { printf '\033[31m[错误]\033[0m %s\n' "$1" >&2; exit 1; }
usage() { sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-1}"; }

arg="" push=0 dry=0
for a in "$@"; do
    case $a in
        -p | --push) push=1 ;;
        -n | --dry-run) dry=1 ;;
        -h | --help) usage 0 ;;
        -*) die "未知参数 $a" ;;
        *)
            [[ -z $arg ]] || die "只能指定一个版本"
            arg=$a ;;
    esac
done
[[ -n $arg ]] || usage

# 版本号只在根 Cargo.toml 的 [workspace.package] 里，各 crate 通过 version.workspace 继承
current=$(sed -n '/^\[workspace\.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
[[ -n $current ]] || die "无法从 Cargo.toml 的 [workspace.package] 读取版本"

case $arg in
    major | minor | patch)
        IFS=. read -r major minor patch <<<"${current%%-*}"
        case $arg in
            major) new="$((major + 1)).0.0" ;;
            minor) new="$major.$((minor + 1)).0" ;;
            patch) new="$major.$minor.$((patch + 1))" ;;
        esac ;;
    *) new=${arg#v} ;;
esac
[[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "版本号 $new 不合法，格式应为 X.Y.Z 或 X.Y.Z-rc.1"
tag="v$new"

git rev-parse --git-dir >/dev/null 2>&1 || die "当前目录不是 git 仓库"
git rev-parse -q --verify HEAD >/dev/null || die "仓库还没有任何提交，请先提交代码"
branch=$(git symbolic-ref --short -q HEAD) || die "当前不在任何分支上（detached HEAD）"
[[ -z $(git status --porcelain) ]] || die "工作区有未提交的改动，请先提交（git status 查看）"
! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "本地已存在标签 $tag"
if git remote get-url origin >/dev/null 2>&1 &&
    GIT_TERMINAL_PROMPT=0 timeout 20 git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    die "远程仓库已存在标签 $tag"
fi
# CI 会检查格式，提前发现可以避免推送后构建失败
if cargo fmt --version >/dev/null 2>&1 && ! cargo fmt --all --check >/dev/null 2>&1; then
    die "代码未通过 cargo fmt --check（CI 会失败），请先执行 cargo fmt --all 并提交"
fi

if [[ $new == "$current" ]]; then
    info "版本保持 $current，只创建标签 $tag（分支 $branch）"
else
    info "版本 $current -> $new，提交后创建标签 $tag（分支 $branch）"
fi
if ((dry)); then
    info "dry-run：未做任何修改"
    exit 0
fi

if [[ $new != "$current" ]]; then
    sed -i "/^\[workspace\.package\]/,/^\[/ s/^version = \".*\"/version = \"$new\"/" Cargo.toml
    # 只刷新 Cargo.lock 里本工作区的包，不升级任何依赖
    cargo update --workspace --offline --quiet 2>/dev/null || cargo update --workspace --quiet
    git add Cargo.toml Cargo.lock
    git commit -q -m "release $tag"
    info "已提交: $(git log -1 --format='%h %s')"
fi
git tag -a "$tag" -m "$tag"
info "已创建标签 $tag"

if ((push)); then
    answer=y
elif [[ -t 0 ]]; then
    read -rp "是否立即推送 $branch 和 $tag 到 origin？[y/N]: " answer || answer=n
else
    answer=n
fi
if [[ $answer =~ ^[Yy]$ ]]; then
    git push --atomic origin "$branch" "$tag"
    info "已推送，GitHub Actions 会自动构建并发布 Release"
else
    echo "稍后推送: git push --atomic origin $branch $tag"
    echo "放弃本次发布: git tag -d $tag$([[ $new != "$current" ]] && echo " && git reset --hard HEAD~1")"
fi
