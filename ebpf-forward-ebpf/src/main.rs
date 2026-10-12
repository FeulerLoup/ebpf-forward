#![no_std]
#![no_main]

//! TC ingress 端口转发：DNAT + SNAT，自带连接跟踪。
//!
//! 原方向  客户端C:cp -> 本机L:lp   改写为  本机S:np -> 目标T:tp
//! 回复方向 目标T:tp  -> 本机S:np   改写为  本机L:lp -> 客户端C:cp
//!
//! 改写后用 bpf_fib_lookup 选路并直接 redirect 到出口网卡，报文不再经过内核协议栈
//! （因此也不经过 netfilter：防火墙的 INPUT/FORWARD 规则对转发流量不生效）。

use core::mem::{self, size_of};

use aya_ebpf::{
    EbpfContext,
    bindings::{
        BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR, BPF_NOEXIST, TC_ACT_SHOT, TC_ACT_UNSPEC,
        bpf_fib_lookup as FibParams, bpf_redir_neigh,
    },
    helpers::{
        bpf_fib_lookup, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh,
        bpf_skb_change_head,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use ebpf_forward_common::*;

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const AF_INET: u8 = 2;
const PROTO_ICMP: u8 = 1;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAMETERPROB: u8 = 12;

const FIB_SUCCESS: i64 = 0;
const FIB_NO_NEIGH: i64 = 7;
const FIB_FRAG_NEEDED: i64 = 8;

const PORT_TRIES: u32 = 16;
const NS_PER_SEC: u64 = 1_000_000_000;

/// 不归本程序处理：继续交给同一网卡上的其他 TC 程序 / 协议栈。
const PASS: i32 = TC_ACT_UNSPEC;
const SHOT: i32 = TC_ACT_SHOT as i32;

#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(MAX_RULES, 0);

#[map]
static CT: LruHashMap<CtKey, CtValue> = LruHashMap::with_max_entries(CT_DEFAULT_ENTRIES, 0);

#[map]
static LOCAL_ADDRS: HashMap<u32, u32> = HashMap::with_max_entries(MAX_LOCAL_ADDRS, 0);

#[map]
static IF_MTU: HashMap<u32, u32> = HashMap::with_max_entries(MAX_IFACES, 0);

#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_MAX, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv4Hdr {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ports {
    sport: u16,
    dport: u16,
}

/// 以太网网卡（eth0、veth、bridge 等）。
#[classifier]
pub fn fwd_eth(ctx: TcContext) -> i32 {
    process(&ctx, ETH_HLEN)
}

/// 无二层头的网卡（WireGuard、tun、ipip 等），报文从 IP 头开始。
#[classifier]
pub fn fwd_l3(ctx: TcContext) -> i32 {
    process(&ctx, 0)
}

#[inline(always)]
fn stat_add(idx: u32, v: u64) {
    if let Some(p) = STATS.get_ptr_mut(idx) {
        unsafe { *p += v };
    }
}

#[inline(always)]
fn process(ctx: &TcContext, l3_off: usize) -> i32 {
    if l3_off == ETH_HLEN {
        match ctx.load::<u16>(12) {
            Ok(p) if p == ETH_P_IP.to_be() => {}
            _ => return PASS,
        }
    } else if ctx.skb.protocol() != u32::from(ETH_P_IP.to_be()) {
        return PASS;
    }

    let Ok(ip) = ctx.load::<Ipv4Hdr>(l3_off) else {
        return PASS;
    };
    if ip.ver_ihl >> 4 != 4 {
        return PASS;
    }
    let ihl = ((ip.ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return PASS;
    }
    // 分片无法按端口转换（后续分片没有 L4 头），交给协议栈
    if u16::from_be(ip.frag_off) & 0x3fff != 0 {
        return PASS;
    }
    let l4_off = l3_off + ihl;

    match ip.proto {
        PROTO_TCP | PROTO_UDP => handle_l4(ctx, l3_off, l4_off, &ip),
        PROTO_ICMP => handle_icmp(ctx, l3_off, l4_off, &ip),
        _ => PASS,
    }
}

#[inline(always)]
fn handle_l4(ctx: &TcContext, l3_off: usize, l4_off: usize, ip: &Ipv4Hdr) -> i32 {
    let proto = ip.proto;
    let Ok(ports) = ctx.load::<Ports>(l4_off) else {
        return PASS;
    };
    let mut tcp_flags = 0u8;
    if proto == PROTO_TCP {
        match ctx.load::<u8>(l4_off + 13) {
            Ok(f) => tcp_flags = f,
            Err(_) => return PASS,
        }
    }
    let pure_syn = proto == PROTO_TCP && tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN;

    let key = CtKey {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: ports.sport,
        dport: ports.dport,
        proto,
        _pad: [0; 3],
    };
    let now = unsafe { bpf_ktime_get_ns() };

    let xlate = match ct_lookup(&key, tcp_flags, pure_syn, now) {
        Lookup::Hit(v) => v,
        miss => {
            let avoid = match miss {
                Lookup::Reopen(port) => port,
                _ => 0,
            };
            match ct_create(&key, pure_syn, now, avoid) {
                Ok(Some(v)) => v,
                Ok(None) => return PASS,
                Err(()) => return SHOT,
            }
        }
    };

    if ip.ttl <= 1 {
        stat_add(STAT_TTL_EXCEEDED, 1);
        return SHOT;
    }

    let ingress = ingress_ifindex(ctx);
    let (rc, fib) = fib_route(
        ctx,
        ingress,
        proto,
        ip.tos,
        xlate.saddr,
        xlate.daddr,
        xlate.sport,
        xlate.dport,
    );
    if rc != FIB_SUCCESS && rc != FIB_NO_NEIGH {
        stat_add(
            if rc == FIB_FRAG_NEEDED {
                STAT_FRAG_NEEDED
            } else {
                STAT_FIB_DROP
            },
            1,
        );
        return SHOT;
    }

    if rewrite_l4(ctx, l3_off, l4_off, ip, &ports, &xlate).is_err() {
        return SHOT;
    }

    if proto == PROTO_TCP && tcp_flags & TCP_SYN != 0 {
        mss_clamp(ctx, l4_off, ingress, fib.ifindex);
    }

    let len = u64::from(ctx.len());
    if xlate.flags & CT_F_REPLY != 0 {
        stat_add(STAT_REPLY_PKTS, 1);
        stat_add(STAT_REPLY_BYTES, len);
    } else {
        stat_add(STAT_ORIG_PKTS, 1);
        stat_add(STAT_ORIG_BYTES, len);
    }

    redirect(ctx, l3_off, rc, &fib)
}

enum Lookup {
    Hit(CtValue),
    Miss,
    /// 旧连接已关闭、映射已删除，重建时要避开的旧 SNAT 端口（网络字节序）。
    Reopen(u16),
}

/// 查连接跟踪表并刷新状态，返回需要套用的改写。
#[inline(always)]
fn ct_lookup(key: &CtKey, tcp_flags: u8, pure_syn: bool, now: u64) -> Lookup {
    let Some(p) = CT.get_ptr_mut(key) else {
        return Lookup::Miss;
    };
    let e = unsafe { &mut *p };

    if pure_syn && e.flags & CT_F_REPLY == 0 {
        // 客户端用同一五元组发起了新连接：若旧连接已关闭，丢弃旧映射并换一个 SNAT 端口重建，
        // 避免目标端仍处于 TIME_WAIT 的旧四元组被复用。SYN 重传（旧连接未关闭）则沿用映射。
        let pair = e.pair_key(key.proto);
        let mut closed = e.flags & (CT_F_FIN | CT_F_RST) != 0;
        match CT.get_ptr(&pair) {
            Some(r) => {
                if unsafe { (*r).flags } & (CT_F_FIN | CT_F_RST) != 0 {
                    closed = true;
                }
            }
            None => closed = true,
        }
        if closed {
            let old_port = e.sport;
            let _ = CT.remove(&pair);
            let _ = CT.remove(key);
            return Lookup::Reopen(old_port);
        }
    }

    let mut flags = e.flags;
    if tcp_flags & TCP_FIN != 0 {
        flags |= CT_F_FIN;
    }
    if tcp_flags & TCP_RST != 0 {
        flags |= CT_F_RST;
    }
    if flags & CT_F_REPLY != 0 {
        flags |= CT_F_SEEN;
    }
    if flags != e.flags {
        e.flags = flags;
    }
    // 降低多核同时写同一缓存行的频率，GC 的精度到秒即可
    if now.wrapping_sub(e.last_seen) > NS_PER_SEC {
        e.last_seen = now;
    }
    Lookup::Hit(*e)
}

/// 新连接：匹配规则、分配 SNAT 端口、写入双向映射。
/// Ok(None) 表示不归本程序处理（交给协议栈）。
#[inline(always)]
fn ct_create(key: &CtKey, pure_syn: bool, now: u64, avoid: u16) -> Result<Option<CtValue>, ()> {
    let rk = RuleKey {
        port: key.dport,
        proto: key.proto,
        _pad: 0,
    };
    let Some(rule) = (unsafe { RULES.get(&rk) }).copied() else {
        return Ok(None);
    };
    if rule.target_addr == 0 || rule.snat_addr == 0 {
        return Ok(None);
    }
    // TCP 只在 SYN 时建立映射；中途的报文（例如程序重启前的旧连接）交给协议栈回 RST
    if key.proto == PROTO_TCP && !pure_syn {
        return Ok(None);
    }
    // 只转发发往本机地址的报文，避免劫持路过本机（路由转发）的流量
    if unsafe { LOCAL_ADDRS.get(&key.daddr) }.is_none() {
        return Ok(None);
    }

    let (pmin, pmax) = match CONFIG.get(0) {
        Some(c) if c.snat_port_min != 0 && c.snat_port_max >= c.snat_port_min => {
            (u32::from(c.snat_port_min), u32::from(c.snat_port_max))
        }
        _ => (10000, 32767),
    };
    let span = pmax - pmin + 1;

    let reply = CtValue {
        saddr: key.daddr,
        daddr: key.saddr,
        sport: key.dport,
        dport: key.sport,
        flags: CT_F_REPLY,
        last_seen: now,
        created: now,
    };
    let mut rkey = CtKey {
        saddr: rule.target_addr,
        daddr: rule.snat_addr,
        sport: rule.target_port,
        dport: 0,
        proto: key.proto,
        _pad: [0; 3],
    };

    // 优先保留客户端源端口（与 Linux NAT 行为一致），冲突时随机选取
    let client_port = u32::from(u16::from_be(key.sport));
    let mut port = if client_port >= pmin && client_port <= pmax && key.sport != avoid {
        client_port
    } else {
        pmin + rand_below(span)
    };
    let mut allocated = false;
    for _ in 0..PORT_TRIES {
        rkey.dport = (port as u16).to_be();
        if CT.insert(&rkey, &reply, u64::from(BPF_NOEXIST)).is_ok() {
            allocated = true;
            break;
        }
        port = pmin + rand_below(span);
    }
    if !allocated {
        stat_add(STAT_PORT_EXHAUSTED, 1);
        return Err(());
    }

    let orig = CtValue {
        saddr: rule.snat_addr,
        daddr: rule.target_addr,
        sport: rkey.dport,
        dport: rule.target_port,
        flags: 0,
        last_seen: now,
        created: now,
    };
    if CT.insert(key, &orig, u64::from(BPF_NOEXIST)).is_err() {
        // 另一个 CPU 刚为同一条流建好了映射：撤销本次分配，沿用已有映射
        let _ = CT.remove(&rkey);
        return match unsafe { CT.get(key) } {
            Some(e) => Ok(Some(*e)),
            None => {
                stat_add(STAT_CT_INSERT_FAIL, 1);
                Err(())
            }
        };
    }
    stat_add(STAT_NEW_CONN, 1);
    Ok(Some(orig))
}

/// [0, n) 内的随机数，用乘法代替取模（避免除法与除零检查）。
#[inline(always)]
fn rand_below(n: u32) -> u32 {
    let r = u64::from(unsafe { bpf_get_prandom_u32() });
    ((r * u64::from(n)) >> 32) as u32
}

#[inline(always)]
fn ingress_ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ifindex }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn fib_route(
    ctx: &TcContext,
    ingress: u32,
    proto: u8,
    tos: u8,
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
) -> (i64, FibParams) {
    let mut fib: FibParams = unsafe { mem::zeroed() };
    fib.family = AF_INET;
    fib.l4_protocol = proto;
    fib.sport = sport;
    fib.dport = dport;
    // tot_len = 0：由内核按 skb 判断能否转发（GSO 报文也能正确处理）
    fib.ifindex = ingress;
    fib.__bindgen_anon_2.tos = tos;
    fib.__bindgen_anon_3.ipv4_src = saddr;
    fib.__bindgen_anon_4.ipv4_dst = daddr;
    let rc = unsafe { bpf_fib_lookup(ctx.as_ptr(), &mut fib, size_of::<FibParams>() as i32, 0) };
    (rc, fib)
}

/// 改写 IPv4 + TCP/UDP 头，并增量更新校验和。
///
/// 地址属于 L4 伪首部，必须带 BPF_F_PSEUDO_HDR：对 CHECKSUM_PARTIAL（GRO 合并包、veth）
/// 内核只修正伪首部部分，端口的变化则留给最终的校验和计算。
#[inline(always)]
fn rewrite_l4(
    ctx: &TcContext,
    l3_off: usize,
    l4_off: usize,
    ip: &Ipv4Hdr,
    ports: &Ports,
    new: &CtValue,
) -> Result<(), i64> {
    let ip_csum = l3_off + 10;
    let (l4_csum, mangled) = if ip.proto == PROTO_TCP {
        (l4_off + 16, 0u64)
    } else {
        // UDP 校验和为 0 表示未计算，必须保持为 0；结果恰为 0 时写成 0xffff
        (l4_off + 6, u64::from(BPF_F_MARK_MANGLED_0))
    };
    let pseudo = u64::from(BPF_F_PSEUDO_HDR);

    if new.saddr != ip.saddr {
        ctx.l4_csum_replace(
            l4_csum,
            u64::from(ip.saddr),
            u64::from(new.saddr),
            pseudo | mangled | 4,
        )?;
        ctx.l3_csum_replace(ip_csum, u64::from(ip.saddr), u64::from(new.saddr), 4)?;
        ctx.store(l3_off + 12, &new.saddr, 0)?;
    }
    if new.daddr != ip.daddr {
        ctx.l4_csum_replace(
            l4_csum,
            u64::from(ip.daddr),
            u64::from(new.daddr),
            pseudo | mangled | 4,
        )?;
        ctx.l3_csum_replace(ip_csum, u64::from(ip.daddr), u64::from(new.daddr), 4)?;
        ctx.store(l3_off + 16, &new.daddr, 0)?;
    }
    if new.sport != ports.sport {
        ctx.l4_csum_replace(
            l4_csum,
            u64::from(ports.sport),
            u64::from(new.sport),
            mangled | 2,
        )?;
        ctx.store(l4_off, &new.sport, 0)?;
    }
    if new.dport != ports.dport {
        ctx.l4_csum_replace(
            l4_csum,
            u64::from(ports.dport),
            u64::from(new.dport),
            mangled | 2,
        )?;
        ctx.store(l4_off + 2, &new.dport, 0)?;
    }
    dec_ttl(ctx, l3_off, ip)
}

/// TTL 减一：防止两台转发机互相转发时报文无限循环。
#[inline(always)]
fn dec_ttl(ctx: &TcContext, l3_off: usize, ip: &Ipv4Hdr) -> Result<(), i64> {
    let ttl = ip.ttl.wrapping_sub(1);
    let old = u16::from_ne_bytes([ip.ttl, ip.proto]);
    let new = u16::from_ne_bytes([ttl, ip.proto]);
    ctx.l3_csum_replace(l3_off + 10, u64::from(old), u64::from(new), 2)?;
    ctx.store(l3_off + 8, &ttl, 0)
}

/// 把 SYN / SYN-ACK 里的 MSS 钳制到 min(入口MTU, 出口MTU) - 40。
/// redirect 绕过了协议栈，超过出口 MTU 的报文不会有人回 ICMP “需要分片”，
/// 所以要在握手阶段就让两端用不超过路径 MTU 的报文段（例如出口是 WireGuard）。
#[inline(always)]
fn mss_clamp(ctx: &TcContext, l4_off: usize, ingress: u32, egress: u32) {
    match CONFIG.get(0) {
        Some(c) if c.flags & CFG_F_MSS_CLAMP != 0 => {}
        _ => return,
    }
    let in_mtu = unsafe { IF_MTU.get(&ingress) }.copied().unwrap_or(0);
    let out_mtu = unsafe { IF_MTU.get(&egress) }.copied().unwrap_or(0);
    let mtu = match (in_mtu, out_mtu) {
        (0, 0) => return,
        (0, m) | (m, 0) => m,
        (a, b) => a.min(b),
    };
    if !(576..=65535).contains(&mtu) {
        return;
    }
    let max_mss = (mtu - 40) as u16;

    let Ok(doff) = ctx.load::<u8>(l4_off + 12) else {
        return;
    };
    let end = l4_off + ((doff >> 4) as usize) * 4;
    let mut off = l4_off + 20;
    for _ in 0..10 {
        if off + 4 > end {
            return;
        }
        let Ok(kind) = ctx.load::<u8>(off) else {
            return;
        };
        match kind {
            0 => return,
            1 => {
                off += 1;
                continue;
            }
            _ => {}
        }
        let Ok(len) = ctx.load::<u8>(off + 1) else {
            return;
        };
        if kind == 2 {
            if len != 4 {
                return;
            }
            let Ok(mss) = ctx.load::<u16>(off + 2) else {
                return;
            };
            if u16::from_be(mss) > max_mss {
                let new = max_mss.to_be();
                if ctx
                    .l4_csum_replace(l4_off + 16, u64::from(mss), u64::from(new), 2)
                    .is_ok()
                    && ctx.store(off + 2, &new, 0).is_ok()
                {
                    stat_add(STAT_MSS_CLAMPED, 1);
                }
            }
            return;
        }
        if len < 2 {
            return;
        }
        off += len as usize;
    }
}

/// 按 FIB 结果填好二层头并重定向到出口网卡。
#[inline(always)]
fn redirect(ctx: &TcContext, l3_off: usize, rc: i64, fib: &FibParams) -> i32 {
    if l3_off == 0 {
        // 入口是 L3 网卡：补一个以太网头。出口若也是 L3 网卡，内核会自动剥掉它
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH_HLEN as u32, 0) } != 0 {
            stat_add(STAT_REDIRECT_FAIL, 1);
            return SHOT;
        }
        if ctx.store(12, &ETH_P_IP.to_be(), 0).is_err() {
            return SHOT;
        }
    }

    if rc == FIB_SUCCESS {
        if ctx.store(0, &fib.dmac, 0).is_err() || ctx.store(6, &fib.smac, 0).is_err() {
            return SHOT;
        }
        return unsafe { bpf_redirect(fib.ifindex, 0) } as i32;
    }

    // 邻居（ARP）尚未解析：交给内核做邻居解析后发出
    let mut nh: bpf_redir_neigh = unsafe { mem::zeroed() };
    nh.nh_family = u32::from(AF_INET);
    nh.__bindgen_anon_1.ipv4_nh = unsafe { fib.__bindgen_anon_4.ipv4_dst };
    stat_add(STAT_REDIRECT_NEIGH, 1);
    unsafe {
        bpf_redirect_neigh(fib.ifindex, &mut nh, size_of::<bpf_redir_neigh>() as i32, 0) as i32
    }
}

/// ICMP 差错（目标不可达 / 需要分片 / 超时）：内层是本机发出的、已转换过的报文，
/// 其反向五元组正是连接跟踪中的某一项。按该项把内外层都还原给连接的另一端，
/// 这样 PMTU 发现、端口不可达等都能像 nftables 一样正常工作。
#[inline(always)]
fn handle_icmp(ctx: &TcContext, l3_off: usize, l4_off: usize, ip: &Ipv4Hdr) -> i32 {
    let Ok(icmp_type) = ctx.load::<u8>(l4_off) else {
        return PASS;
    };
    if icmp_type != ICMP_DEST_UNREACH
        && icmp_type != ICMP_TIME_EXCEEDED
        && icmp_type != ICMP_PARAMETERPROB
    {
        return PASS;
    }
    let in_off = l4_off + 8;
    let Ok(inner) = ctx.load::<Ipv4Hdr>(in_off) else {
        return PASS;
    };
    if inner.ver_ihl >> 4 != 4 || (inner.proto != PROTO_TCP && inner.proto != PROTO_UDP) {
        return PASS;
    }
    let in_ihl = ((inner.ver_ihl & 0x0f) as usize) * 4;
    if in_ihl < 20 || inner.saddr != ip.daddr {
        return PASS;
    }
    let in_l4 = in_off + in_ihl;
    let Ok(in_ports) = ctx.load::<Ports>(in_l4) else {
        return PASS;
    };

    let key = CtKey {
        saddr: inner.daddr,
        daddr: inner.saddr,
        sport: in_ports.dport,
        dport: in_ports.sport,
        proto: inner.proto,
        _pad: [0; 3],
    };
    let Some(e) = (unsafe { CT.get(&key) }).copied() else {
        return PASS;
    };
    if ip.ttl <= 1 {
        return SHOT;
    }

    let ingress = ingress_ifindex(ctx);
    let (rc, fib) = fib_route(ctx, ingress, PROTO_ICMP, ip.tos, e.saddr, e.daddr, 0, 0);
    if rc != FIB_SUCCESS && rc != FIB_NO_NEIGH {
        stat_add(STAT_FIB_DROP, 1);
        return SHOT;
    }
    if icmp_rewrite(
        ctx, l3_off, l4_off, in_off, in_l4, ip, &inner, &in_ports, &e,
    )
    .is_err()
    {
        return SHOT;
    }
    stat_add(STAT_ICMP_XLATE, 1);
    redirect(ctx, l3_off, rc, &fib)
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn icmp_rewrite(
    ctx: &TcContext,
    l3_off: usize,
    l4_off: usize,
    in_off: usize,
    in_l4: usize,
    ip: &Ipv4Hdr,
    inner: &Ipv4Hdr,
    in_ports: &Ports,
    e: &CtValue,
) -> Result<(), i64> {
    let icmp_csum = l4_off + 2;
    let in_csum = in_off + 10;

    // 内层报文还原为“对端当初发出的那个报文”：e 的改写结果取反
    let (n_saddr, n_daddr, n_sport, n_dport) = (e.daddr, e.saddr, e.dport, e.sport);

    // ICMP 校验和覆盖整个内层数据，内层每个被改动的字段（含内层 IP 校验和）都要计入
    if n_saddr != inner.saddr {
        ctx.l3_csum_replace(in_csum, u64::from(inner.saddr), u64::from(n_saddr), 4)?;
        ctx.l4_csum_replace(icmp_csum, u64::from(inner.saddr), u64::from(n_saddr), 4)?;
        ctx.store(in_off + 12, &n_saddr, 0)?;
    }
    if n_daddr != inner.daddr {
        ctx.l3_csum_replace(in_csum, u64::from(inner.daddr), u64::from(n_daddr), 4)?;
        ctx.l4_csum_replace(icmp_csum, u64::from(inner.daddr), u64::from(n_daddr), 4)?;
        ctx.store(in_off + 16, &n_daddr, 0)?;
    }
    let new_in_check = ctx.load::<u16>(in_csum)?;
    if new_in_check != inner.check {
        ctx.l4_csum_replace(
            icmp_csum,
            u64::from(inner.check),
            u64::from(new_in_check),
            2,
        )?;
    }
    if n_sport != in_ports.sport {
        ctx.l4_csum_replace(icmp_csum, u64::from(in_ports.sport), u64::from(n_sport), 2)?;
        ctx.store(in_l4, &n_sport, 0)?;
    }
    if n_dport != in_ports.dport {
        ctx.l4_csum_replace(icmp_csum, u64::from(in_ports.dport), u64::from(n_dport), 2)?;
        ctx.store(in_l4 + 2, &n_dport, 0)?;
    }

    // 外层：本机 -> 连接的另一端（源地址用本机地址，避免被上游的源地址校验丢弃）
    if e.saddr != ip.saddr {
        ctx.l3_csum_replace(l3_off + 10, u64::from(ip.saddr), u64::from(e.saddr), 4)?;
        ctx.store(l3_off + 12, &e.saddr, 0)?;
    }
    if e.daddr != ip.daddr {
        ctx.l3_csum_replace(l3_off + 10, u64::from(ip.daddr), u64::from(e.daddr), 4)?;
        ctx.store(l3_off + 16, &e.daddr, 0)?;
    }
    dec_ttl(ctx, l3_off, ip)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
