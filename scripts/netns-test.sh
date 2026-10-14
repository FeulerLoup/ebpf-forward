#!/usr/bin/env bash
#
# ebpf-forward 端到端测试（需要 root，只操作独立的 network namespace，不影响本机网络）
#
#   efw-cli ──veth── efw-relay ──veth── efw-rt ──veth── efw-srv
#  10.10.1.2     10.10.1.1 | 10.10.2.1   10.10.2.254 | 10.10.3.254   10.10.3.2 / 10.10.3.3
#                          |             （去往 10.10.3.0/24 的路由 MTU 1400）
#                          |
#                    wg0 10.20.0.1 ══ WireGuard ══ efw-wg 10.20.0.2
#
# 目标机只有去往 10.10.2.0/24 的回程路由，没有到客户端的路由：能通即说明 SNAT 生效。
#
# 用法: sudo [LONG=1] [NO_WG=1] scripts/netns-test.sh [ebpf-forward 路径] [partial|full]
#   LONG=1   额外等待 75 秒验证超时回收；NO_WG=1 跳过 WireGuard（L3 网卡）测试
#   partial  客户端/目标机发出 TSO/GSO 报文（CHECKSUM_PARTIAL），转发机出口关闭校验和卸载，
#            由出口软件计算最终校验和并交给对端校验 —— 验证伪首部增量更新
#   full     客户端/目标机关闭校验和卸载（报文带完整校验和）—— 验证完整的增量校验和
#
set -u

BIN=$(readlink -f "${1:-$(dirname "$0")/../target/release/ebpf-forward}")
MODE=${2:-partial}
W=/tmp/efw-test
ST=$W/run/status.toml
C=efw-cli R=efw-relay T=efw-rt S=efw-srv G=efw-wg
PASS=0 FAIL=0
DAEMON_PID=
CAPS=()

ok()   { printf '\033[32m[PASS]\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '\033[31m[FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
nsx()  { local ns=$1; shift; ip netns exec "$ns" "$@"; }
efw()  { ip netns exec $R "$BIN" -c $W/config.toml --run-dir $W/run "$@"; }
# 后台运行测试用服务；disown 后，结束时被 kill -9 不会再打印 “Killed”
svc()  { local log=$1; shift; nsx "$@" >"$log" 2>&1 & disown; }

# wait_until 秒数 命令...：反复执行命令直到成功，超时返回失败（慢机器上不依赖固定的 sleep）
wait_until() {
    local end=$((SECONDS + $1)); shift
    until "$@"; do
        ((SECONDS < end)) || return 1
        sleep 0.2
    done
}
listening() { nsx "$1" ss -Hln"$2" src "$3" | grep -q .; }
no_conns()  { ! efw conns | grep -q "10.10.1.1:$1 "; }
status_changed() { [[ $(stat -c '%i %.9Y' $ST 2>/dev/null) != "$1" ]]; }
# 状态文件是当前这个守护进程写的，并且没有还在等待解析的域名规则
daemon_ready() { grep -qx "pid = $DAEMON_PID" $ST 2>/dev/null && ! grep -q '^state = "pending"' $ST; }

start_daemon() {
    # kill -9 留下的旧状态文件会让等待提前结束
    rm -f $ST
    ip netns exec $R env RUST_LOG=info "$BIN" -c $W/config.toml --run-dir $W/run run >>$W/daemon.log 2>&1 &
    DAEMON_PID=$!
    wait_until 15 daemon_ready
}

# SIGHUP 让守护进程立即重新读取网卡信息并同步 map，状态文件被重写即同步完成
resync() {
    local before
    before=$(stat -c '%i %.9Y' $ST)
    kill -HUP "$DAEMON_PID"
    wait_until 5 status_changed "$before"
}

# 抓包：抓满指定个数即退出，并等 tcpdump 就绪后才返回。
# 输出（含 stderr 的统计信息）经管道写文件：Ubuntu 上 tcpdump 受 AppArmor 限制且会降权，
# 不一定能写 /tmp 下的文件
capture() {  # 命名空间 网卡 过滤条件 报文数 输出文件
    nsx "$1" timeout 20 tcpdump -l -c "$4" -i "$2" -Q in -nn -vv "$3" 2>&1 | cat >"$5" &
    CAPS+=($!)
    wait_until 10 grep -qs 'listening on' "$5"
}
capture_wait() { wait "${CAPS[@]}"; CAPS=(); }

# 客户端跑 iperf3；服务端上一轮测试还没收尾时会回 “the server is busy”，稍等重试
iperf_c() {
    local dst=10.10.1.1 out
    if [[ ${1:-} == -dst ]]; then dst=$2; shift 2; fi
    for _ in 1 2 3 4 5; do
        out=$(nsx $C timeout 30 iperf3 -c "$dst" -t 3 -f m "$@" 2>&1) && { echo "$out"; return 0; }
        grep -q 'server is busy' <<<"$out" || break
        sleep 1
    done
    echo "$out"
    return 1
}

stop_daemon() {
    [[ -n $DAEMON_PID ]] || return 0
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    DAEMON_PID=
}

cleanup() {
    stop_daemon
    for ns in $C $R $T $S $G; do
        ip netns pids $ns 2>/dev/null | xargs -r kill -9 2>/dev/null
        ip netns del $ns 2>/dev/null
    done
    rm -rf /etc/netns/$R
}

[[ $EUID -eq 0 ]] || { echo "需要 root"; exit 1; }
[[ -x $BIN ]] || { echo "找不到 $BIN"; exit 1; }
for c in ip tc ethtool curl iperf3 python3 tcpdump; do
    command -v $c >/dev/null || { echo "缺少命令 $c"; exit 1; }
done
trap cleanup EXIT
cleanup
rm -rf $W && mkdir -p $W/run $W/a $W/b $W/g $W/c

step "搭建拓扑（模式: $MODE）"
for ns in $C $R $T $S $G; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add cli0 netns $C type veth peer name r-cli netns $R
ip link add r-up netns $R type veth peer name rt-a netns $T
ip link add rt-b netns $T type veth peer name srv0 netns $S
ip link add r-wg netns $R type veth peer name g-r netns $G
ip -n $C addr add 10.10.1.2/24 dev cli0
ip -n $R addr add 10.10.1.1/24 dev r-cli
ip -n $R addr add 10.10.2.1/24 dev r-up
ip -n $R addr add 10.30.0.1/24 dev r-wg
ip -n $T addr add 10.10.2.254/24 dev rt-a
ip -n $T addr add 10.10.3.254/24 dev rt-b
ip -n $S addr add 10.10.3.2/24 dev srv0
ip -n $S addr add 10.10.3.3/24 dev srv0
ip -n $G addr add 10.30.0.2/24 dev g-r
ip -n $C -6 addr add fd00:1::2/64 dev cli0 nodad
ip -n $R -6 addr add fd00:1::1/64 dev r-cli nodad
ip -n $R -6 addr add fd00:2::1/64 dev r-up nodad
ip -n $T -6 addr add fd00:2::fe/64 dev rt-a nodad
ip -n $T -6 addr add fd00:3::fe/64 dev rt-b nodad
ip -n $S -6 addr add fd00:3::2/64 dev srv0 nodad
ip -n $S -6 addr add fd00:3::3/64 dev srv0 nodad
for p in "$C cli0" "$R r-cli" "$R r-up" "$R r-wg" "$T rt-a" "$T rt-b" "$S srv0" "$G g-r"; do
    set -- $p
    ip -n "$1" link set "$2" up
    # 部分内核的 veth 会做 GRO：tcpdump 抓到合并后的大包时校验和检查会误报
    nsx "$1" ethtool -K "$2" gro off >/dev/null 2>&1 || true
done
ip -n $R route add 10.10.3.0/24 via 10.10.2.254
ip -n $S route add 10.10.2.0/24 via 10.10.3.254
ip -n $R -6 route add fd00:3::/64 via fd00:2::fe
ip -n $S -6 route add fd00:2::/64 via fd00:3::fe
# 两端网卡都是 1500，只有路由器转发时受 1400 限制：客户端上传的大包会触发路由器回 ICMP “需要分片 / Packet Too Big”
ip -n $T route replace 10.10.3.0/24 dev rt-b mtu lock 1400
ip -n $T -6 route replace fd00:3::/64 dev rt-b metric 256 mtu lock 1400
nsx $T sysctl -qw net.ipv4.ip_forward=1
nsx $T sysctl -qw net.ipv6.conf.all.forwarding=1

WG=0
if [[ ${NO_WG:-0} != 1 ]] && command -v wg >/dev/null && ip -n $R link add wg0 type wireguard 2>/dev/null; then
    WG=1
    (umask 077; wg genkey >$W/kr; wg genkey >$W/kg)
    PR=$(wg pubkey <$W/kr); PG=$(wg pubkey <$W/kg)
    ip -n $G link add wg0 type wireguard
    nsx $R wg set wg0 private-key $W/kr listen-port 51820 peer "$PG" allowed-ips 10.20.0.2/32,fd00:20::2/128 endpoint 10.30.0.2:51820
    nsx $G wg set wg0 private-key $W/kg listen-port 51820 peer "$PR" allowed-ips 10.20.0.1/32,fd00:20::1/128 endpoint 10.30.0.1:51820
    ip -n $R addr add 10.20.0.1/24 dev wg0
    ip -n $G addr add 10.20.0.2/24 dev wg0
    ip -n $R -6 addr add fd00:20::1/64 dev wg0 nodad
    ip -n $G -6 addr add fd00:20::2/64 dev wg0 nodad
    ip -n $R link set wg0 up
    ip -n $G link set wg0 up
else
    echo "（缺少 wireguard-tools 或内核 WireGuard 模块，跳过 L3 网卡相关测试）"
fi

case $MODE in
    partial)
        nsx $R ethtool -K r-cli tx off >/dev/null
        nsx $R ethtool -K r-up tx off >/dev/null ;;
    full)
        nsx $C ethtool -K cli0 tx off >/dev/null
        nsx $S ethtool -K srv0 tx off >/dev/null ;;
esac

cat >$W/udp_echo.py <<'EOF'
import socket, sys
af = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(af, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d + b" from %s:%d" % (a[0].encode(), a[1]), a)
EOF
cat >$W/udp_client.py <<'EOF'
import socket, sys
af = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(af, socket.SOCK_DGRAM)
s.settimeout(3)
s.connect((sys.argv[1], int(sys.argv[2])))
s.send(b"ping")
try:
    print(s.recv(65535).decode())
except ConnectionRefusedError:
    print("REFUSED")
except socket.timeout:
    print("TIMEOUT")
EOF
cat >$W/peer_echo.py <<'EOF'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
while True:
    c, a = s.accept()
    c.sendall(b"%s:%d" % (a[0].encode(), a[1]))
    c.close()
EOF
cat >$W/tcp_reuse.py <<'EOF'
import socket, sys, time
out = []
for _ in range(2):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(5)
    s.bind(("10.10.1.2", int(sys.argv[2])))
    s.connect((sys.argv[1], int(sys.argv[3])))
    data = b""
    while True:
        d = s.recv(100)
        if not d:
            break
        data += d
    s.close()
    out.append(data.decode() or "EMPTY")
    time.sleep(0.3)
print(" ".join(out))
EOF
echo srv-A >$W/a/who; echo srv-B >$W/b/who; echo srv-WG >$W/g/who; echo client-self >$W/c/who
head -c 4194304 /dev/urandom >$W/a/big; cp $W/a/big $W/g/big
head -c 262144 /dev/urandom >$W/a/mid
svc $W/http-a.log $S python3 -m http.server 80 --bind 10.10.3.2 --directory $W/a
svc $W/http-a6.log $S python3 -m http.server 80 --bind fd00:3::2 --directory $W/a
svc $W/http-b.log $S python3 -m http.server 80 --bind 10.10.3.3 --directory $W/b
svc $W/http-b6.log $S python3 -m http.server 80 --bind fd00:3::3 --directory $W/b
svc $W/http-c.log $C python3 -m http.server 80 --bind 10.10.1.2 --directory $W/c
svc $W/udp-echo.log $S python3 $W/udp_echo.py 10.10.3.2 5353
svc $W/udp-echo6.log $S python3 $W/udp_echo.py fd00:3::2 5353
svc $W/peer-echo.log $S python3 $W/peer_echo.py 10.10.3.2 81
nsx $S iperf3 -s -B 10.10.3.2 -D --logfile $W/iperf-s.log
nsx $S iperf3 -s -B fd00:3::2 -D --logfile $W/iperf-s6.log
READY=("$S t 10.10.3.2:80" "$S t [fd00:3::2]:80" "$S t 10.10.3.3:80" "$S t [fd00:3::3]:80" "$C t 10.10.1.2:80" "$S u 10.10.3.2:5353" "$S u [fd00:3::2]:5353" "$S t 10.10.3.2:81" "$S t 10.10.3.2:5201" "$S t [fd00:3::2]:5201")
if [[ $WG == 1 ]]; then
    svc $W/http-g.log $G python3 -m http.server 80 --bind 10.20.0.2 --directory $W/g
    svc $W/http-g6.log $G python3 -m http.server 80 --bind fd00:20::2 --directory $W/g
    nsx $G iperf3 -s -B 10.20.0.2 -D --logfile $W/iperf-g.log
    READY+=("$G t 10.20.0.2:80" "$G t [fd00:20::2]:80" "$G t 10.20.0.2:5201")
fi
mkdir -p /etc/netns/$R && echo "10.10.3.2 srv.test" >/etc/netns/$R/hosts
for s in "${READY[@]}"; do
    wait_until 10 listening $s || echo "（测试服务 $s 未就绪）"
done

step "启动守护进程并通过命令行添加规则"
echo 'resolve_interval = 5' >$W/config.toml
start_daemon && ok "守护进程已启动" || { bad "守护进程启动失败"; cat $W/daemon.log; exit 1; }
{
    efw add 8080 10.10.3.2 80 -p tcp -y
    efw add 8086 fd00:3::2 80 -p tcp -y
    efw add 9090 srv.test 80 -p tcp -y --comment "域名目标"
    efw add 5353 10.10.3.2 -p udp -y
    efw add 5356 fd00:3::2 5353 -p udp -y
    efw add 6000 10.10.3.2 -p udp -y
    efw add 6006 fd00:3::2 6000 -p udp -y
    efw add 5201 10.10.3.2 -p tcp -y
    efw add 5206 fd00:3::2 5201 -p tcp -y
    efw add 8181 10.10.1.2 80 -y
    efw add 8282 10.10.3.2 81 -p tcp -y
    if [[ $WG == 1 ]]; then
        efw add 7070 10.20.0.2 80 -p tcp -y
        efw add 7071 10.20.0.2 5201 -p tcp -y
        efw add 7076 fd00:20::2 80 -p tcp -y
    fi
} >$W/cli.log 2>&1
efw list
grep -A2 'name = "r-cli"' $ST | grep -q fwd_eth && grep -A2 'name = "r-up"' $ST | grep -q fwd_eth \
    && ok "自动挂载: r-cli/r-up 使用 fwd_eth" || bad "挂载网卡不符: $(grep -A2 name $ST | tr '\n' ' ')"
if [[ $WG == 1 ]]; then
    grep -A2 'name = "wg0"' $ST | grep -q fwd_l3 && ok "自动挂载: wg0 使用 fwd_l3" || bad "wg0 未挂载 fwd_l3"
fi

step "TCP DNAT + SNAT"
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:8080/who)
[[ $out == srv-A ]] && ok "8080/tcp -> 10.10.3.2:80 返回 $out" || bad "8080/tcp 返回 '$out'"
grep -q '^10.10.2.1 ' $W/http-a.log && ok "目标机看到的源地址为转发机 SNAT 地址 10.10.2.1" \
    || bad "SNAT 不符: $(tail -1 $W/http-a.log)"

step "线上报文校验和（tcpdump 独立重新计算）"
# 抓目标机与客户端“收到”的报文：转发机改写后的 TCP/UDP 校验和必须正确。
# 只抓少量报文：大流量会打满 tcpdump 的缓冲区，被内核丢弃的报文就无从检查
csum_check() {  # 抓包文件 说明 正确标记 错误标记
    local good wrong
    good=$(grep -c -- "$3" "$1"); wrong=$(grep -c -- "$4" "$1")
    if [[ $good -gt 0 && $wrong -eq 0 ]]; then
        ok "$2校验和全部正确（$good 个报文）"
    else
        bad "$2校验和: 正确 $good，错误 $wrong；$(grep -m1 -- "$4" "$1" || sed -n 2p "$1")；tcpdump: $(grep -E 'captured|dropped' "$1" | tr '\n' ' ')"
    fi
}
capture $S srv0 'tcp port 80' 10 $W/ck-srv-tcp.txt
capture $C cli0 'tcp port 8080' 100 $W/ck-cli-tcp.txt
nsx $C curl -s --max-time 10 -o /dev/null http://10.10.1.1:8080/mid
capture_wait
capture $S srv0 'udp port 5353' 1 $W/ck-srv-udp.txt
capture $C cli0 'udp port 5353' 1 $W/ck-cli-udp.txt
nsx $C python3 $W/udp_client.py 10.10.1.1 5353 >/dev/null
capture_wait
csum_check $W/ck-srv-tcp.txt "目标机收到的 TCP " '(correct)' 'incorrect'
csum_check $W/ck-cli-tcp.txt "客户端收到的 TCP " '(correct)' 'incorrect'
csum_check $W/ck-srv-udp.txt "目标机收到的 UDP " 'udp sum ok' 'bad udp cksum'
csum_check $W/ck-cli-udp.txt "客户端收到的 UDP " 'udp sum ok' 'bad udp cksum'

step "域名目标"
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:9090/who)
[[ $out == srv-A ]] && ok "9090 -> srv.test(10.10.3.2):80 返回 $out" || bad "域名目标返回 '$out'"

step "UDP 与 ICMP 差错转换"
out=$(nsx $C python3 $W/udp_client.py 10.10.1.1 5353)
[[ $out == "ping from 10.10.2.1:"* ]] && ok "UDP 5353 回显: $out" || bad "UDP 回显: '$out'"
out=$(nsx $C python3 $W/udp_client.py 10.10.1.1 6000)
[[ $out == REFUSED ]] && ok "目标端口不可达的 ICMP 被转换回客户端（ECONNREFUSED）" || bad "ICMP 端口不可达: '$out'"

step "大流量与 PMTU（路由器到目标的路由 MTU 1400）"
nsx $C curl -s --max-time 20 -o $W/big.dl http://10.10.1.1:8080/big
cmp -s $W/big.dl $W/a/big && ok "4 MiB 下载内容一致" || bad "4 MiB 下载内容不一致"
out=$(iperf_c -p 5201)
[[ $? -eq 0 ]] && ok "iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "iperf3 上传失败: $(tail -3 <<<"$out")"
nsx $C ip route get 10.10.1.1 | grep -q 'mtu 1400' \
    && ok "客户端学到 PMTU 1400（路由器的 ICMP 需要分片已被正确转换）" || bad "客户端没有学到 PMTU: $(nsx $C ip route get 10.10.1.1)"
out=$(iperf_c -p 5201 -R)
[[ $? -eq 0 ]] && ok "iperf3 下载: $(grep -m1 receiver <<<"$out" | awk '{print $7, $8}')" || bad "iperf3 下载失败: $(tail -3 <<<"$out")"

if [[ $WG == 1 ]]; then
    step "WireGuard 出口（L3 网卡，回包走 fwd_l3 + 补二层头）"
    out=$(nsx $C curl -s --max-time 8 http://10.10.1.1:7070/who)
    [[ $out == srv-WG ]] && ok "7070 -> 10.20.0.2:80 返回 $out" || bad "WireGuard 目标返回 '$out'"
    nsx $C curl -s --max-time 20 -o $W/big.wg http://10.10.1.1:7070/big
    cmp -s $W/big.wg $W/g/big && ok "经 WireGuard 下载 4 MiB 内容一致" || bad "经 WireGuard 下载内容不一致"
    out=$(iperf_c -p 7071)
    [[ $? -eq 0 ]] && ok "经 WireGuard iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "经 WireGuard 上传失败"
    out=$(iperf_c -p 7071 -R)
    [[ $? -eq 0 ]] && ok "经 WireGuard iperf3 下载: $(grep -m1 receiver <<<"$out" | awk '{print $7, $8}')" || bad "经 WireGuard 下载失败"
fi

step "源端口复用（目标先关闭连接、处于 TIME_WAIT）"
out=$(nsx $C python3 $W/tcp_reuse.py 10.10.1.1 20000 8282)
read -r first second <<<"$out"
[[ $first == 10.10.2.1:20000 ]] && ok "首次连接保留了客户端源端口: $first" || bad "首次连接: '$first'"
[[ $second == 10.10.2.1:* && $second != "$first" ]] && ok "旧连接关闭后同端口重连换用了新 SNAT 端口: $second" \
    || bad "重连: '$second'"

step "同网卡回环（目标与客户端在同一网卡侧）"
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:8181/who)
[[ $out == client-self ]] && ok "8181 -> 10.10.1.2:80 返回 $out" || bad "回环返回 '$out'"

step "MSS 钳制（转发机与路由器之间的链路 MTU 改为 1400）"
ip -n $R link set r-up mtu 1400
ip -n $T link set rt-a mtu 1400
ip -n $C route flush cache
resync || bad "守护进程没有在 SIGHUP 后重新同步"
capture $S srv0 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and dst port 80' 1 $W/syn.txt
nsx $C curl -s --max-time 5 http://10.10.1.1:8080/who >/dev/null
capture_wait
grep -q 'mss 1360' $W/syn.txt && ok "目标机收到的 SYN 中 MSS 被钳制为 1360" || bad "MSS 未钳制: $(grep -o 'mss [0-9]*' $W/syn.txt)"
nsx $C curl -s --max-time 20 -o $W/big.dl2 http://10.10.1.1:8080/big
cmp -s $W/big.dl2 $W/a/big && ok "链路 MTU 1400 时下载内容一致（SYN 方向钳制）" || bad "链路 MTU 1400 时下载失败"
nsx $C ip route get 10.10.1.1 | grep -q 'mtu' && bad "客户端 PMTU 缓存未清除，无法验证回复方向钳制"
out=$(iperf_c -p 5201)
[[ $? -eq 0 ]] && ok "链路 MTU 1400 时上传正常（SYN-ACK 方向钳制）: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" \
    || bad "链路 MTU 1400 时上传失败: $(tail -3 <<<"$out")"
ip -n $R link set r-up mtu 1500
ip -n $T link set rt-a mtu 1500
resync

step "IPv6 与跨协议族转发（v6->v6、v4->v6、v6->v4）"
out=$(nsx $C curl -s --max-time 5 http://[fd00:1::1]:8086/who)
[[ $out == srv-A ]] && ok "v6 进 v6 出 TCP (8086 -> [fd00:3::2]:80) 返回 $out" || bad "v6->v6 TCP 返回 '$out'"
grep -q '^fd00:2::1 ' $W/http-a6.log && ok "v6 目标看到的源地址为转发机 IPv6 SNAT 地址 fd00:2::1" \
    || bad "v6 SNAT 不符: $(tail -1 $W/http-a6.log)"

capture $S srv0 'ip6 and tcp port 80' 10 $W/ck-v46-srv.txt
capture $C cli0 'ip and tcp port 8086' 100 $W/ck-v46-cli.txt
out=$(nsx $C curl -s --max-time 10 http://10.10.1.1:8086/mid | wc -c)
capture_wait
[[ $out -eq 262144 ]] && ok "v4 进 v6 出 TCP (8086 -> [fd00:3::2]:80) 传输 256 KiB 成功" || bad "v4->v6 TCP 传输字节数 '$out'"
csum_check $W/ck-v46-srv.txt "v4->v6 目标机收到的 IPv6 TCP " '(correct)' 'incorrect'
csum_check $W/ck-v46-cli.txt "v4->v6 客户端收到的 IPv4 TCP " '(correct)' 'incorrect'

capture $S srv0 'ip and tcp port 80' 10 $W/ck-v64-srv.txt
capture $C cli0 'ip6 and tcp port 8080' 100 $W/ck-v64-cli.txt
out=$(nsx $C curl -s --max-time 10 http://[fd00:1::1]:8080/mid | wc -c)
capture_wait
[[ $out -eq 262144 ]] && ok "v6 进 v4 出 TCP ([fd00:1::1]:8080 -> 10.10.3.2:80) 传输 256 KiB 成功" || bad "v6->v4 TCP 传输字节数 '$out'"
csum_check $W/ck-v64-srv.txt "v6->v4 目标机收到的 IPv4 TCP " '(correct)' 'incorrect'
csum_check $W/ck-v64-cli.txt "v6->v4 客户端收到的 IPv6 TCP " '(correct)' 'incorrect'

out=$(nsx $C python3 $W/udp_client.py fd00:1::1 5356)
[[ $out == "ping from fd00:2::1:"* ]] && ok "v6 进 v6 出 UDP 回显: $out" || bad "v6->v6 UDP 回显: '$out'"
out=$(nsx $C python3 $W/udp_client.py 10.10.1.1 5356)
[[ $out == "ping from fd00:2::1:"* ]] && ok "v4 进 v6 出 UDP 回显: $out" || bad "v4->v6 UDP 回显: '$out'"
out=$(nsx $C python3 $W/udp_client.py fd00:1::1 5353)
[[ $out == "ping from 10.10.2.1:"* ]] && ok "v6 进 v4 出 UDP 回显: $out" || bad "v6->v4 UDP 回显: '$out'"

out=$(nsx $C python3 $W/udp_client.py fd00:1::1 6006)
[[ $out == REFUSED ]] && ok "v6->v6 ICMPv6 端口不可达转换成功（ECONNREFUSED）" || bad "v6->v6 ICMPv6 端口不可达: '$out'"
out=$(nsx $C python3 $W/udp_client.py 10.10.1.1 6006)
[[ $out == REFUSED ]] && ok "v4->v6 ICMPv6->ICMPv4 端口不可达转换成功（ECONNREFUSED）" || bad "v4->v6 端口不可达: '$out'"
out=$(nsx $C python3 $W/udp_client.py fd00:1::1 6000)
[[ $out == REFUSED ]] && ok "v6->v4 ICMPv4->ICMPv6 端口不可达转换成功（ECONNREFUSED）" || bad "v6->v4 端口不可达: '$out'"

ip -n $C route flush cache
out=$(iperf_c -p 5206)
[[ $? -eq 0 ]] && ok "v4->v6 iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "v4->v6 iperf3 上传失败: $(tail -3 <<<"$out")"
nsx $C ip route get 10.10.1.1 | grep -q 'mtu 1380' \
    && ok "v4->v6 客户端学到 PMTU 1380（ICMPv6 Packet Too Big 已转换为 ICMPv4 需要分片）" \
    || bad "v4->v6 客户端未学到 PMTU 1380: $(nsx $C ip route get 10.10.1.1)"

ip -n $C -6 route flush cache
out=$(iperf_c -dst fd00:1::1 -p 5201)
[[ $? -eq 0 ]] && ok "v6->v4 iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "v6->v4 iperf3 上传失败: $(tail -3 <<<"$out")"
nsx $C ip -6 route get fd00:1::1 | grep -q 'mtu 1400' \
    && ok "v6->v4 客户端学到 PMTU 1400（ICMPv4 需要分片已转换为 ICMPv6 Packet Too Big）" \
    || bad "v6->v4 客户端未学到 PMTU 1400: $(nsx $C ip -6 route get fd00:1::1)"

ip -n $C -6 route flush cache
out=$(iperf_c -dst fd00:1::1 -p 5206)
[[ $? -eq 0 ]] && ok "v6->v6 iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "v6->v6 iperf3 上传失败: $(tail -3 <<<"$out")"
nsx $C ip -6 route get fd00:1::1 | grep -q 'mtu 1400' \
    && ok "v6->v6 客户端学到 PMTU 1400（ICMPv6 Packet Too Big 转换成功）" \
    || bad "v6->v6 客户端未学到 PMTU 1400: $(nsx $C ip -6 route get fd00:1::1)"
ip -n $C route flush cache
ip -n $C -6 route flush cache

if [[ $WG == 1 ]]; then
    out=$(nsx $C curl -s --max-time 8 http://10.10.1.1:7076/who)
    [[ $out == srv-WG ]] && ok "v4->v6 经 WireGuard (L3) 返回 $out" || bad "v4->v6 WireGuard 返回 '$out'"
    out=$(nsx $C curl -s --max-time 8 http://[fd00:1::1]:7070/who)
    [[ $out == srv-WG ]] && ok "v6->v4 经 WireGuard (L3) 返回 $out" || bad "v6->v4 WireGuard 返回 '$out'"
    out=$(nsx $C curl -s --max-time 8 http://[fd00:1::1]:7076/who)
    [[ $out == srv-WG ]] && ok "v6->v6 经 WireGuard (L3) 返回 $out" || bad "v6->v6 WireGuard 返回 '$out'"
fi

step "域名解析变化（resolve_interval = 5 秒）"
echo "10.10.3.3 srv.test" >/etc/netns/$R/hosts
wait_until 15 grep -q 'ip = "10.10.3.3"' $ST
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:9090/who)
[[ $out == srv-B ]] && ok "域名改指 10.10.3.3 后新连接转发到 $out" || bad "解析变化后返回 '$out'"
grep -q '解析变化: 10.10.3.2 -> 10.10.3.3' $W/daemon.log && ok "日志记录了解析变化" || bad "日志中没有解析变化"
echo "fd00:3::3 srv.test" >/etc/netns/$R/hosts
wait_until 15 grep -q 'ip = "fd00:3::3"' $ST
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:9090/who)
[[ $out == srv-B ]] && ok "域名改指 AAAA (fd00:3::3) 后 v4 客户端转发到 $out" || bad "AAAA 解析变化后返回 '$out'"

step "连接表 / 状态"
efw conns | tail -4
efw status | sed -n '1,12p'
n=$(efw conns | grep -c ' tcp \|^tcp ')
[[ $n -gt 0 ]] && ok "conns 列出 $n 条 TCP 连接" || bad "conns 没有列出连接"

step "删除规则"
efw del 8080 >/dev/null
nsx $C curl -s --max-time 3 -o /dev/null http://10.10.1.1:8080/who
rc=$?
[[ $rc -eq 7 ]] && ok "删除后 8080 不再转发（连接被拒绝）" || bad "删除后 curl 返回码 $rc"
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:9090/who)
[[ $out == srv-B ]] && ok "其他规则不受影响" || bad "删除 8080 影响了其他规则: '$out'"
wait_until 15 no_conns 8080 && ok "被删除规则的连接已从连接跟踪表回收" \
    || bad "仍有 $(efw conns | grep -c '10.10.1.1:8080 ') 条 8080 的连接"

if [[ ${LONG:-0} == 1 ]]; then
    step "连接超时回收（等待 75 秒）"
    sleep 75
    n=$(efw conns | grep -c '^tcp ')
    [[ $n -eq 0 ]] && ok "已关闭的 TCP 连接在超时后全部回收" || { bad "仍有 $n 条 TCP 连接"; efw conns; }
    efw conns | grep -q '10.10.1.1:6000 ' && bad "未得到回应的 UDP 映射未在 30 秒后回收" || ok "未得到回应的 UDP 映射已回收"
fi

step "停止守护进程后自动卸载"
stop_daemon
nsx $R tc filter show dev r-cli ingress | grep -q fwd_ && bad "停止后仍有 eBPF 挂载残留" || ok "停止后 eBPF 已从网卡卸载"
[[ ! -f $W/run/status.toml && ! -f $W/run/ebpf-forward.pid ]] && ok "状态文件与 pid 文件已清理" || bad "状态文件/pid 文件残留"

step "异常退出（kill -9）后的恢复"
start_daemon || bad "守护进程启动失败"
kill -9 $DAEMON_PID; wait $DAEMON_PID 2>/dev/null; DAEMON_PID=
if nsx $R tc filter show dev r-cli ingress | grep -q fwd_eth; then
    ok "kill -9 后 netlink 挂载残留（内核 < 6.6 的预期行为）"
    rm -f $W/run/ebpf-forward.pid
    start_daemon || bad "重启后守护进程没有就绪"
    n=$(nsx $R tc filter show dev r-cli ingress | grep -c fwd_eth)
    [[ $n -eq 1 ]] && ok "重启后替换了残留挂载（r-cli 上只有 1 个 fwd_eth）" || bad "r-cli 上有 $n 个 fwd_eth"
    out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:9090/who)
    [[ $out == srv-B ]] && ok "重启后转发正常" || bad "重启后转发返回 '$out'"
    kill -9 $DAEMON_PID; wait $DAEMON_PID 2>/dev/null; DAEMON_PID=
    rm -f $W/run/ebpf-forward.pid
    efw cleanup >/dev/null
    nsx $R tc filter show dev r-cli ingress | grep -q fwd_ && bad "cleanup 后仍有残留" || ok "ebpf-forward cleanup 清除了残留挂载"
else
    ok "kill -9 后无残留（TCX 挂载随进程自动释放）"
fi

echo
grep -E 'WARN|ERROR' $W/daemon.log | grep -v 'ip_local_port_range' | head -5
printf '\n\033[1m结果（%s 模式）: %d 通过, %d 失败\033[0m\n' "$MODE" $PASS $FAIL
[[ $FAIL -eq 0 ]] || { echo "--- daemon.log (tail) ---"; tail -30 $W/daemon.log; }
[[ $FAIL -eq 0 ]]
