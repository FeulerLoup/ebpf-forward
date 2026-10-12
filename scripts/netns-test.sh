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
C=efw-cli R=efw-relay T=efw-rt S=efw-srv G=efw-wg
PASS=0 FAIL=0
DAEMON_PID=

ok()   { printf '\033[32m[PASS]\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '\033[31m[FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
nsx()  { local ns=$1; shift; ip netns exec "$ns" "$@"; }
efw()  { ip netns exec $R "$BIN" -c $W/config.toml --run-dir $W/run "$@"; }

start_daemon() {
    ip netns exec $R env RUST_LOG=info "$BIN" -c $W/config.toml --run-dir $W/run run >>$W/daemon.log 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 50); do
        [[ -f $W/run/status.toml ]] && return 0
        sleep 0.1
    done
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
for p in "$C cli0" "$R r-cli" "$R r-up" "$R r-wg" "$T rt-a" "$T rt-b" "$S srv0" "$G g-r"; do
    set -- $p
    ip -n "$1" link set "$2" up
    # 部分内核的 veth 会做 GRO：tcpdump 抓到合并后的大包时校验和检查会误报
    nsx "$1" ethtool -K "$2" gro off >/dev/null 2>&1 || true
done
ip -n $R route add 10.10.3.0/24 via 10.10.2.254
ip -n $S route add 10.10.2.0/24 via 10.10.3.254
# 两端网卡都是 1500，只有路由器转发时受 1400 限制：客户端上传的大包会触发路由器回 ICMP “需要分片”
ip -n $T route replace 10.10.3.0/24 dev rt-b mtu lock 1400
nsx $T sysctl -qw net.ipv4.ip_forward=1

WG=0
if [[ ${NO_WG:-0} != 1 ]] && command -v wg >/dev/null && ip -n $R link add wg0 type wireguard 2>/dev/null; then
    WG=1
    wg genkey >$W/kr; wg genkey >$W/kg
    PR=$(wg pubkey <$W/kr); PG=$(wg pubkey <$W/kg)
    ip -n $G link add wg0 type wireguard
    nsx $R wg set wg0 private-key $W/kr listen-port 51820 peer "$PG" allowed-ips 10.20.0.2/32 endpoint 10.30.0.2:51820
    nsx $G wg set wg0 private-key $W/kg listen-port 51820 peer "$PR" allowed-ips 10.20.0.1/32 endpoint 10.30.0.1:51820
    ip -n $R addr add 10.20.0.1/24 dev wg0
    ip -n $G addr add 10.20.0.2/24 dev wg0
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
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d + b" from %s:%d" % (a[0].encode(), a[1]), a)
EOF
cat >$W/udp_client.py <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
nsx $S python3 -m http.server 80 --bind 10.10.3.2 --directory $W/a >$W/http-a.log 2>&1 &
nsx $S python3 -m http.server 80 --bind 10.10.3.3 --directory $W/b >$W/http-b.log 2>&1 &
nsx $C python3 -m http.server 80 --bind 10.10.1.2 --directory $W/c >$W/http-c.log 2>&1 &
nsx $S python3 $W/udp_echo.py 10.10.3.2 5353 &
nsx $S python3 $W/peer_echo.py 10.10.3.2 81 &
nsx $S iperf3 -s -B 10.10.3.2 -D --logfile $W/iperf-s.log
if [[ $WG == 1 ]]; then
    nsx $G python3 -m http.server 80 --bind 10.20.0.2 --directory $W/g >$W/http-g.log 2>&1 &
    nsx $G iperf3 -s -B 10.20.0.2 -D --logfile $W/iperf-g.log
fi
mkdir -p /etc/netns/$R && echo "10.10.3.2 srv.test" >/etc/netns/$R/hosts
sleep 1

step "启动守护进程并通过命令行添加规则"
echo 'resolve_interval = 5' >$W/config.toml
start_daemon && ok "守护进程已启动" || { bad "守护进程启动失败"; cat $W/daemon.log; exit 1; }
{
    efw add 8080 10.10.3.2 80 -p tcp -y
    efw add 9090 srv.test 80 -p tcp -y --comment "域名目标"
    efw add 5353 10.10.3.2 -p udp -y
    efw add 6000 10.10.3.2 -p udp -y
    efw add 5201 10.10.3.2 -p tcp -y
    efw add 8181 10.10.1.2 80 -y
    efw add 8282 10.10.3.2 81 -p tcp -y
    if [[ $WG == 1 ]]; then
        efw add 7070 10.20.0.2 80 -p tcp -y
        efw add 7071 10.20.0.2 5201 -p tcp -y
    fi
} >$W/cli.log 2>&1
efw list
ST=$W/run/status.toml
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
# 抓目标机与客户端“收到”的报文：转发机改写后的 TCP/UDP 校验和必须正确
# 输出经管道写文件：Ubuntu 的 AppArmor 不允许 tcpdump 直接写 /tmp 下的普通文件
capture() { nsx "$1" timeout 5 tcpdump -l -i "$2" -Q in -nn -vv "$3" 2>/dev/null | cat >"$4"; }
capture $S srv0 'tcp port 80 or udp port 5353' $W/ck-srv.txt & P1=$!
capture $C cli0 'tcp port 8080 or udp port 5353' $W/ck-cli.txt & P2=$!
sleep 1
nsx $C curl -s --max-time 5 -o /dev/null http://10.10.1.1:8080/who
nsx $C curl -s --max-time 5 -o /dev/null -r 0-65535 http://10.10.1.1:8080/big
nsx $C python3 $W/udp_client.py 10.10.1.1 5353 >/dev/null
wait $P1 $P2
for f in srv cli; do
    t=$(grep -c '(correct)' $W/ck-$f.txt); u=$(grep -c 'udp sum ok' $W/ck-$f.txt)
    i=$(grep -cE 'incorrect|bad udp cksum' $W/ck-$f.txt)
    [[ $t -gt 0 && $u -gt 0 && $i -eq 0 ]] && ok "$f 侧收到的报文校验和全部正确（TCP $t 个，UDP $u 个）" \
        || bad "$f 侧校验和: TCP 正确 $t，UDP 正确 $u，错误 $i: $(grep -m1 -E 'incorrect|bad udp' $W/ck-$f.txt)"
done

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
out=$(nsx $C timeout 30 iperf3 -c 10.10.1.1 -p 5201 -t 3 -f m 2>&1)
[[ $? -eq 0 ]] && ok "iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "iperf3 上传失败: $(tail -3 <<<"$out")"
nsx $C ip route get 10.10.1.1 | grep -q 'mtu 1400' \
    && ok "客户端学到 PMTU 1400（路由器的 ICMP 需要分片已被正确转换）" || bad "客户端没有学到 PMTU: $(nsx $C ip route get 10.10.1.1)"
out=$(nsx $C timeout 30 iperf3 -c 10.10.1.1 -p 5201 -t 3 -R -f m 2>&1)
[[ $? -eq 0 ]] && ok "iperf3 下载: $(grep -m1 receiver <<<"$out" | awk '{print $7, $8}')" || bad "iperf3 下载失败: $(tail -3 <<<"$out")"

if [[ $WG == 1 ]]; then
    step "WireGuard 出口（L3 网卡，回包走 fwd_l3 + 补二层头）"
    out=$(nsx $C curl -s --max-time 8 http://10.10.1.1:7070/who)
    [[ $out == srv-WG ]] && ok "7070 -> 10.20.0.2:80 返回 $out" || bad "WireGuard 目标返回 '$out'"
    nsx $C curl -s --max-time 20 -o $W/big.wg http://10.10.1.1:7070/big
    cmp -s $W/big.wg $W/g/big && ok "经 WireGuard 下载 4 MiB 内容一致" || bad "经 WireGuard 下载内容不一致"
    out=$(nsx $C timeout 30 iperf3 -c 10.10.1.1 -p 7071 -t 3 -f m 2>&1)
    [[ $? -eq 0 ]] && ok "经 WireGuard iperf3 上传: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" || bad "经 WireGuard 上传失败"
    out=$(nsx $C timeout 30 iperf3 -c 10.10.1.1 -p 7071 -t 3 -R -f m 2>&1)
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
sleep 11
nsx $S timeout 10 tcpdump -l -i srv0 -nn -c 1 -v 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and dst port 80' 2>/dev/null | cat >$W/syn.txt &
TD=$!
sleep 1
nsx $C curl -s --max-time 5 http://10.10.1.1:8080/who >/dev/null
wait $TD
grep -q 'mss 1360' $W/syn.txt && ok "目标机收到的 SYN 中 MSS 被钳制为 1360" || bad "MSS 未钳制: $(grep -o 'mss [0-9]*' $W/syn.txt)"
nsx $C curl -s --max-time 20 -o $W/big.dl2 http://10.10.1.1:8080/big
cmp -s $W/big.dl2 $W/a/big && ok "链路 MTU 1400 时下载内容一致（SYN 方向钳制）" || bad "链路 MTU 1400 时下载失败"
nsx $C ip route get 10.10.1.1 | grep -q 'mtu' && bad "客户端 PMTU 缓存未清除，无法验证回复方向钳制"
out=$(nsx $C timeout 30 iperf3 -c 10.10.1.1 -p 5201 -t 3 -f m 2>&1)
[[ $? -eq 0 ]] && ok "链路 MTU 1400 时上传正常（SYN-ACK 方向钳制）: $(grep -m1 sender <<<"$out" | awk '{print $7, $8}')" \
    || bad "链路 MTU 1400 时上传失败: $(tail -3 <<<"$out")"
ip -n $R link set r-up mtu 1500
ip -n $T link set rt-a mtu 1500

step "域名解析变化（resolve_interval = 5 秒）"
echo "10.10.3.3 srv.test" >/etc/netns/$R/hosts
sleep 7
out=$(nsx $C curl -s --max-time 5 http://10.10.1.1:9090/who)
[[ $out == srv-B ]] && ok "域名改指 10.10.3.3 后新连接转发到 $out" || bad "解析变化后返回 '$out'"
grep -q '解析变化: 10.10.3.2 -> 10.10.3.3' $W/daemon.log && ok "日志记录了解析变化" || bad "日志中没有解析变化"

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
sleep 11
n=$(efw conns | grep -c '10.10.1.1:8080 ')
[[ $n -eq 0 ]] && ok "被删除规则的连接已从连接跟踪表回收" || bad "仍有 $n 条 8080 的连接"

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
start_daemon
sleep 1
kill -9 $DAEMON_PID; wait $DAEMON_PID 2>/dev/null; DAEMON_PID=
if nsx $R tc filter show dev r-cli ingress | grep -q fwd_eth; then
    ok "kill -9 后 netlink 挂载残留（内核 < 6.6 的预期行为）"
    rm -f $W/run/ebpf-forward.pid
    start_daemon
    sleep 1
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
