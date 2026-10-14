#![no_std]
#![no_main]

//! TC ingress 端口转发：支持 IPv4 / IPv6 任意进任意出（v4->v4、v6->v6、v4->v6、v6->v4）的
//! DNAT + SNAT，自带连接跟踪。
//!
//! 原方向  客户端C:cp -> 本机L:lp   改写为  本机S:np -> 目标T:tp
//! 回复方向 目标T:tp  -> 本机S:np   改写为  本机L:lp -> 客户端C:cp
//!
//! 跨协议族转发时通过 `bpf_skb_change_proto` 转换 L3 报头（IPv4 <-> IPv6），
//! 改写后用 `bpf_fib_lookup` 选路并直接 redirect 到出口网卡，报文不再经过内核协议栈。

use core::mem::size_of;

use aya_ebpf::{
    EbpfContext,
    bindings::{
        BPF_F_MARK_MANGLED_0, BPF_F_PSEUDO_HDR, BPF_NOEXIST, TC_ACT_SHOT, TC_ACT_UNSPEC,
        bpf_fib_lookup as FibParams, bpf_redir_neigh,
    },
    helpers::{
        bpf_fib_lookup, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh,
        bpf_skb_change_head, bpf_skb_change_tail,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use ebpf_forward_common::*;

const ETH_HLEN: usize = 14;
const IPV4_HLEN: usize = 20;
const IPV6_HLEN: usize = 40;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAMETERPROB: u8 = 12;

const ICMPV6_DEST_UNREACH: u8 = 1;
const ICMPV6_PKT_TOOBIG: u8 = 2;
const ICMPV6_TIME_EXCEED: u8 = 3;
const ICMPV6_PARAMPROB: u8 = 4;

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
static LOCAL_ADDRS: HashMap<LocalAddrKey, u32> = HashMap::with_max_entries(MAX_LOCAL_ADDRS, 0);

#[map]
static IF_MTU: HashMap<u32, u32> = HashMap::with_max_entries(MAX_IFACES, 0);

#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_MAX, 0);

/// 每 CPU 工作区：避免 IPv6 头、CT 键值、FIB 参数同时在栈上分配导致超出 eBPF 512 字节栈限制。
#[repr(C)]
struct Scratch {
    l3: L3Meta,
    key: CtKey,
    rkey: CtKey,
    pair: CtKey,
    xlate: CtValue,
    reply: CtValue,
    lk: LocalAddrKey,
    fib: FibParams,
    nh: bpf_redir_neigh,
    ip4: Ipv4Hdr,
    inner4: Ipv4Hdr,
    ip6: Ipv6Hdr,
    inner6: Ipv6Hdr,
    icmp: IcmpHdr,
}

#[map]
static SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

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
struct Ipv6Hdr {
    ver_tc_flow: u32,
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IcmpHdr {
    ty: u8,
    code: u8,
    check: u16,
    rest: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ports {
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct L3Meta {
    saddr: [u32; 4],
    daddr: [u32; 4],
    /// L4 头 + 载荷长度（主机字节序）。
    l4_len: u16,
    ihl: u16,
    family: u8,
    proto: u8,
    ttl: u8,
    tos: u8,
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
    let Some(sp) = SCRATCH.get_ptr_mut(0) else {
        return PASS;
    };
    let s = unsafe { &mut *sp };

    let proto_be = if l3_off == ETH_HLEN {
        match ctx.load::<u16>(12) {
            Ok(p) => p,
            Err(_) => return PASS,
        }
    } else {
        ctx.skb.protocol() as u16
    };

    if proto_be == ETH_P_IP.to_be() {
        process_v4(ctx, s, l3_off)
    } else if proto_be == ETH_P_IPV6.to_be() {
        process_v6(ctx, s, l3_off)
    } else {
        PASS
    }
}

#[inline(always)]
fn process_v4(ctx: &TcContext, s: &mut Scratch, l3_off: usize) -> i32 {
    let Ok(ip) = ctx.load::<Ipv4Hdr>(l3_off) else {
        return PASS;
    };
    if ip.ver_ihl >> 4 != 4 {
        return PASS;
    }
    let ihl = ((ip.ver_ihl & 0x0f) as usize) * 4;
    if ihl < IPV4_HLEN {
        return PASS;
    }
    // 分片无法按端口转换（后续分片没有 L4 头），交给协议栈
    if u16::from_be(ip.frag_off) & 0x3fff != 0 {
        return PASS;
    }
    let l4_off = l3_off + ihl;

    match ip.proto {
        PROTO_TCP | PROTO_UDP => {
            s.l3 = L3Meta {
                saddr: [ip.saddr, 0, 0, 0],
                daddr: [ip.daddr, 0, 0, 0],
                l4_len: u16::from_be(ip.tot_len).saturating_sub(ihl as u16),
                ihl: ihl as u16,
                family: AF_INET,
                proto: ip.proto,
                ttl: ip.ttl,
                tos: ip.tos,
            };
            handle_l4(ctx, s, l3_off, l4_off)
        }
        PROTO_ICMP => {
            s.ip4 = ip;
            handle_icmp4(ctx, s, l3_off, l4_off)
        }
        _ => PASS,
    }
}

#[inline(always)]
fn process_v6(ctx: &TcContext, s: &mut Scratch, l3_off: usize) -> i32 {
    let Ok(ip6) = ctx.load::<Ipv6Hdr>(l3_off) else {
        return PASS;
    };
    let vcf = u32::from_be(ip6.ver_tc_flow);
    if vcf >> 28 != 6 {
        return PASS;
    }
    let tos = ((vcf >> 20) & 0xff) as u8;
    let l4_off = l3_off + IPV6_HLEN;

    match ip6.nexthdr {
        PROTO_TCP | PROTO_UDP => {
            s.l3 = L3Meta {
                saddr: ip6.saddr,
                daddr: ip6.daddr,
                l4_len: u16::from_be(ip6.payload_len),
                ihl: IPV6_HLEN as u16,
                family: AF_INET6,
                proto: ip6.nexthdr,
                ttl: ip6.hop_limit,
                tos,
            };
            handle_l4(ctx, s, l3_off, l4_off)
        }
        PROTO_ICMPV6 => {
            s.ip6 = ip6;
            handle_icmp6(ctx, s, l3_off, l4_off, tos)
        }
        _ => PASS,
    }
}

#[inline(always)]
fn handle_l4(ctx: &TcContext, s: &mut Scratch, l3_off: usize, l4_off: usize) -> i32 {
    let proto = s.l3.proto;
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

    s.key = CtKey {
        saddr: s.l3.saddr,
        daddr: s.l3.daddr,
        sport: ports.sport,
        dport: ports.dport,
        proto,
        family: s.l3.family,
        _pad: [0; 2],
    };
    let now = unsafe { bpf_ktime_get_ns() };

    match ct_lookup(s, tcp_flags, pure_syn, now) {
        Lookup::Hit => {}
        miss => {
            let avoid = match miss {
                Lookup::Reopen(port) => port,
                _ => 0,
            };
            match ct_create(s, pure_syn, now, avoid) {
                Ok(true) => {}
                Ok(false) => return PASS,
                Err(()) => return SHOT,
            }
        }
    }

    if s.l3.ttl <= 1 {
        stat_add(STAT_TTL_EXCEEDED, 1);
        return SHOT;
    }

    if ensure_eth_head(ctx, l3_off, s.l3.family).is_err() {
        return SHOT;
    }

    let Ok(new_l4_off) = rewrite_l4(ctx, s, &ports) else {
        return SHOT;
    };

    let ingress = ingress_ifindex(ctx);
    let rc = fib_route(
        ctx,
        &mut s.fib,
        ingress,
        s.xlate.family,
        proto,
        s.l3.tos,
        &s.xlate.saddr,
        &s.xlate.daddr,
        s.xlate.sport,
        s.xlate.dport,
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

    if proto == PROTO_TCP && tcp_flags & TCP_SYN != 0 {
        let any_v6 = s.l3.family == AF_INET6 || s.xlate.family == AF_INET6;
        mss_clamp(ctx, new_l4_off, ingress, s.fib.ifindex, any_v6);
    }

    let len = u64::from(ctx.len());
    if s.xlate.flags & CT_F_REPLY != 0 {
        stat_add(STAT_REPLY_PKTS, 1);
        stat_add(STAT_REPLY_BYTES, len);
    } else {
        stat_add(STAT_ORIG_PKTS, 1);
        stat_add(STAT_ORIG_BYTES, len);
    }

    redirect(ctx, &s.fib, &mut s.nh, rc, s.xlate.family)
}

enum Lookup {
    Hit,
    Miss,
    /// 旧连接已关闭、映射已删除，重建时要避开的旧 SNAT 端口（网络字节序）。
    Reopen(u16),
}

/// 查连接跟踪表并刷新状态，命中时把改写信息写入 `s.xlate`。
#[inline(always)]
fn ct_lookup(s: &mut Scratch, tcp_flags: u8, pure_syn: bool, now: u64) -> Lookup {
    let Some(p) = CT.get_ptr_mut(&s.key) else {
        return Lookup::Miss;
    };
    let e = unsafe { &mut *p };

    if pure_syn && e.flags & CT_F_REPLY == 0 {
        // 客户端用同一五元组发起了新连接：若旧连接已关闭，丢弃旧映射并换一个 SNAT 端口重建，
        // 避免目标端仍处于 TIME_WAIT 的旧四元组被复用。SYN 重传（旧连接未关闭）则沿用映射。
        s.pair = e.pair_key(s.key.proto);
        let mut closed = e.flags & (CT_F_FIN | CT_F_RST) != 0;
        match CT.get_ptr(&s.pair) {
            Some(r) => {
                if unsafe { (*r).flags } & (CT_F_FIN | CT_F_RST) != 0 {
                    closed = true;
                }
            }
            None => closed = true,
        }
        if closed {
            let old_port = e.sport;
            let _ = CT.remove(&s.pair);
            let _ = CT.remove(&s.key);
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
    s.xlate = *e;
    Lookup::Hit
}

/// 新连接：匹配规则、分配 SNAT 端口、写入双向映射（结果存入 `s.xlate`）。
/// `Ok(false)` 表示不归本程序处理（交给协议栈）。
#[inline(always)]
fn ct_create(s: &mut Scratch, pure_syn: bool, now: u64, avoid: u16) -> Result<bool, ()> {
    let rk = RuleKey {
        port: s.key.dport,
        proto: s.key.proto,
        _pad: 0,
    };
    let Some(rule) = (unsafe { RULES.get(&rk) }) else {
        return Ok(false);
    };
    if rule.family == 0 {
        return Ok(false);
    }
    // TCP 只在 SYN 时建立映射；中途的报文（例如程序重启前的旧连接）交给协议栈回 RST
    if s.key.proto == PROTO_TCP && !pure_syn {
        return Ok(false);
    }
    // 只转发发往本机地址的报文，避免劫持路过本机（路由转发）的流量
    s.lk = LocalAddrKey {
        addr: s.key.daddr,
        family: s.key.family,
        _pad: [0; 3],
    };
    if unsafe { LOCAL_ADDRS.get(&s.lk) }.is_none() {
        return Ok(false);
    }

    let (pmin, pmax) = match CONFIG.get(0) {
        Some(c) if c.snat_port_min != 0 && c.snat_port_max >= c.snat_port_min => {
            (u32::from(c.snat_port_min), u32::from(c.snat_port_max))
        }
        _ => (10000, 32767),
    };
    let span = pmax - pmin + 1;

    s.reply = CtValue {
        saddr: s.key.daddr,
        daddr: s.key.saddr,
        sport: s.key.dport,
        dport: s.key.sport,
        flags: CT_F_REPLY,
        family: s.key.family,
        _pad: 0,
        last_seen: now,
        created: now,
    };
    s.rkey = CtKey {
        saddr: rule.target_addr,
        daddr: rule.snat_addr,
        sport: rule.target_port,
        dport: 0,
        proto: s.key.proto,
        family: rule.family,
        _pad: [0; 2],
    };

    // 优先保留客户端源端口（与 Linux NAT 行为一致），冲突时随机选取
    let client_port = u32::from(u16::from_be(s.key.sport));
    let mut port = if client_port >= pmin && client_port <= pmax && s.key.sport != avoid {
        client_port
    } else {
        pmin + rand_below(span)
    };
    let mut allocated = false;
    for _ in 0..PORT_TRIES {
        s.rkey.dport = (port as u16).to_be();
        if CT.insert(&s.rkey, &s.reply, u64::from(BPF_NOEXIST)).is_ok() {
            allocated = true;
            break;
        }
        port = pmin + rand_below(span);
    }
    if !allocated {
        stat_add(STAT_PORT_EXHAUSTED, 1);
        return Err(());
    }

    s.xlate = CtValue {
        saddr: rule.snat_addr,
        daddr: rule.target_addr,
        sport: s.rkey.dport,
        dport: rule.target_port,
        flags: 0,
        family: rule.family,
        _pad: 0,
        last_seen: now,
        created: now,
    };
    if CT.insert(&s.key, &s.xlate, u64::from(BPF_NOEXIST)).is_err() {
        // 另一个 CPU 刚为同一条流建好了映射：撤销本次分配，沿用已有映射
        let _ = CT.remove(&s.rkey);
        return match unsafe { CT.get(&s.key) } {
            Some(e) => {
                s.xlate = *e;
                Ok(true)
            }
            None => {
                stat_add(STAT_CT_INSERT_FAIL, 1);
                Err(())
            }
        };
    }
    stat_add(STAT_NEW_CONN, 1);
    Ok(true)
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

/// 入口是 L3 网卡时补一个 14 字节以太网头，使后续 `bpf_skb_change_proto` 和二层地址写入
/// 统一从 `ETH_HLEN` 开始。出口若也是 L3 网卡，内核会在发送时自动剥掉二层头。
#[inline(always)]
fn ensure_eth_head(ctx: &TcContext, l3_off: usize, in_family: u8) -> Result<(), ()> {
    if l3_off == 0 {
        if unsafe { bpf_skb_change_head(ctx.skb.skb, ETH_HLEN as u32, 0) } != 0 {
            stat_add(STAT_REDIRECT_FAIL, 1);
            return Err(());
        }
        let eth_proto = if in_family == AF_INET6 {
            ETH_P_IPV6.to_be()
        } else {
            ETH_P_IP.to_be()
        };
        if ctx.store(12, &eth_proto, 0).is_err() {
            return Err(());
        }
    }
    Ok(())
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn fib_route(
    ctx: &TcContext,
    fib: &mut FibParams,
    ingress: u32,
    family: u8,
    proto: u8,
    tos: u8,
    saddr: &[u32; 4],
    daddr: &[u32; 4],
    sport: u16,
    dport: u16,
) -> i64 {
    *fib = unsafe { core::mem::zeroed() };
    fib.family = family;
    fib.l4_protocol = proto;
    fib.sport = sport;
    fib.dport = dport;
    // tot_len = 0：由内核按改写后的 skb 判断能否转发（GSO 报文也能正确处理）
    fib.ifindex = ingress;
    if family == AF_INET6 {
        fib.__bindgen_anon_2.flowinfo = (u32::from(tos) << 20).to_be();
    } else {
        fib.__bindgen_anon_2.tos = tos;
    }
    fib.__bindgen_anon_3.ipv6_src = *saddr;
    fib.__bindgen_anon_4.ipv6_dst = *daddr;
    unsafe { bpf_fib_lookup(ctx.as_ptr(), fib, size_of::<FibParams>() as i32, 0) }
}

/// 改写 L3（含跨协议族 v4<->v6 转换）+ TCP/UDP 头，并增量更新校验和。
/// 返回改写后的 L4 头偏移。
#[inline(always)]
fn rewrite_l4(ctx: &TcContext, s: &mut Scratch, ports: &Ports) -> Result<usize, i64> {
    let l3 = &s.l3;
    let new = &s.xlate;
    let l4_off = match (l3.family, new.family) {
        (AF_INET, AF_INET) => {
            let ip_csum = ETH_HLEN + 10;
            if new.saddr[0] != l3.saddr[0] {
                ctx.l3_csum_replace(ip_csum, u64::from(l3.saddr[0]), u64::from(new.saddr[0]), 4)?;
                ctx.store(ETH_HLEN + 12, &new.saddr[0], 0)?;
            }
            if new.daddr[0] != l3.daddr[0] {
                ctx.l3_csum_replace(ip_csum, u64::from(l3.daddr[0]), u64::from(new.daddr[0]), 4)?;
                ctx.store(ETH_HLEN + 16, &new.daddr[0], 0)?;
            }
            dec_ttl4(ctx, ETH_HLEN, l3.ttl, l3.proto)?;
            ETH_HLEN + l3.ihl as usize
        }
        (AF_INET6, AF_INET6) => {
            if new.saddr != l3.saddr {
                ctx.store(ETH_HLEN + 8, &new.saddr, 0)?;
            }
            if new.daddr != l3.daddr {
                ctx.store(ETH_HLEN + 24, &new.daddr, 0)?;
            }
            let hop = l3.ttl.wrapping_sub(1);
            ctx.store(ETH_HLEN + 7, &hop, 0)?;
            ETH_HLEN + IPV6_HLEN
        }
        (AF_INET, AF_INET6) => {
            if l3.ihl as usize != IPV4_HLEN {
                return Err(-1);
            }
            ctx.change_proto(ETH_P_IPV6.to_be(), 0)?;
            s.ip6 = Ipv6Hdr {
                ver_tc_flow: ((6u32 << 28) | (u32::from(l3.tos) << 20)).to_be(),
                payload_len: l3.l4_len.to_be(),
                nexthdr: l3.proto,
                hop_limit: l3.ttl.wrapping_sub(1),
                saddr: new.saddr,
                daddr: new.daddr,
            };
            ctx.store(ETH_HLEN, &s.ip6, 0)?;
            ETH_HLEN + IPV6_HLEN
        }
        (AF_INET6, AF_INET) => {
            ctx.change_proto(ETH_P_IP.to_be(), 0)?;
            s.ip4 = Ipv4Hdr {
                ver_ihl: 0x45,
                tos: l3.tos,
                tot_len: l3.l4_len.wrapping_add(IPV4_HLEN as u16).to_be(),
                id: 0,
                frag_off: 0x4000u16.to_be(),
                ttl: l3.ttl.wrapping_sub(1),
                proto: l3.proto,
                check: 0,
                saddr: new.saddr[0],
                daddr: new.daddr[0],
            };
            s.ip4.check = ipv4_csum(&s.ip4);
            ctx.store(ETH_HLEN, &s.ip4, 0)?;
            ETH_HLEN + IPV4_HLEN
        }
        _ => return Err(-1),
    };

    let l3 = &s.l3;
    let new = &s.xlate;
    let (l4_csum, mangled) = if l3.proto == PROTO_TCP {
        (l4_off + 16, 0u64)
    } else {
        (l4_off + 6, u64::from(BPF_F_MARK_MANGLED_0))
    };
    let pseudo = u64::from(BPF_F_PSEUDO_HDR);

    for i in 0..4 {
        if new.saddr[i] != l3.saddr[i] {
            ctx.l4_csum_replace(
                l4_csum,
                u64::from(l3.saddr[i]),
                u64::from(new.saddr[i]),
                pseudo | mangled | 4,
            )?;
        }
        if new.daddr[i] != l3.daddr[i] {
            ctx.l4_csum_replace(
                l4_csum,
                u64::from(l3.daddr[i]),
                u64::from(new.daddr[i]),
                pseudo | mangled | 4,
            )?;
        }
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
    Ok(l4_off)
}

/// IPv4 TTL 减一并增量修正首部校验和。
#[inline(always)]
fn dec_ttl4(ctx: &TcContext, l3_off: usize, ttl: u8, proto: u8) -> Result<(), i64> {
    let new_ttl = ttl.wrapping_sub(1);
    let old = u16::from_ne_bytes([ttl, proto]);
    let new = u16::from_ne_bytes([new_ttl, proto]);
    ctx.l3_csum_replace(l3_off + 10, u64::from(old), u64::from(new), 2)?;
    ctx.store(l3_off + 8, &new_ttl, 0)
}

/// 计算 20 字节标准 IPv4 首部的校验和（调用前 `h.check` 应为 0）。
#[inline(always)]
fn ipv4_csum(h: &Ipv4Hdr) -> u16 {
    let mut sum = u64::from(u16::from_ne_bytes([h.ver_ihl, h.tos]))
        + u64::from(h.tot_len)
        + u64::from(h.id)
        + u64::from(h.frag_off)
        + u64::from(u16::from_ne_bytes([h.ttl, h.proto]))
        + u64::from(h.saddr)
        + u64::from(h.daddr);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[inline(always)]
fn fold_wsum(mut sum: u64) -> u32 {
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    sum as u32
}

/// 把 SYN / SYN-ACK 里的 MSS 钳制到 min(入口MTU, 出口MTU) - (纯 v4 为 40，含 v6 为 60)。
#[inline(always)]
fn mss_clamp(ctx: &TcContext, l4_off: usize, ingress: u32, egress: u32, any_v6: bool) {
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
    let overhead = if any_v6 { 60 } else { 40 };
    if !(576..=65535).contains(&mtu) {
        return;
    }
    let max_mss = (mtu - overhead) as u16;

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

/// 按 FIB 结果填好二层头并重定向到出口网卡（调用前已通过 `ensure_eth_head` 保证含 14 字节二层头）。
#[inline(always)]
fn redirect(
    ctx: &TcContext,
    fib: &FibParams,
    nh: &mut bpf_redir_neigh,
    rc: i64,
    out_family: u8,
) -> i32 {
    let eth_proto = if out_family == AF_INET6 {
        ETH_P_IPV6.to_be()
    } else {
        ETH_P_IP.to_be()
    };
    if ctx.store(12, &eth_proto, 0).is_err() {
        return SHOT;
    }

    if rc == FIB_SUCCESS {
        if ctx.store(0, &fib.dmac, 0).is_err() || ctx.store(6, &fib.smac, 0).is_err() {
            return SHOT;
        }
        return unsafe { bpf_redirect(fib.ifindex, 0) } as i32;
    }

    // 邻居（ARP / NDP）尚未解析或出口为 L3 网卡：交给内核处理邻居后发出
    *nh = unsafe { core::mem::zeroed() };
    nh.nh_family = u32::from(out_family);
    nh.__bindgen_anon_1.ipv6_nh = unsafe { fib.__bindgen_anon_4.ipv6_dst };
    stat_add(STAT_REDIRECT_NEIGH, 1);
    unsafe { bpf_redirect_neigh(fib.ifindex, nh, size_of::<bpf_redir_neigh>() as i32, 0) as i32 }
}

/// IPv4 ICMP 差错：内层是本机发出的已转换报文，反向五元组对应 CT 中的某一项。
/// 若对端是 IPv4 则原地还原 ICMPv4，若对端是 IPv6 则转换为 ICMPv6 差错。
#[inline(always)]
fn handle_icmp4(ctx: &TcContext, s: &mut Scratch, l3_off: usize, l4_off: usize) -> i32 {
    let Ok(icmp) = ctx.load::<IcmpHdr>(l4_off) else {
        return PASS;
    };
    if icmp.ty != ICMP_DEST_UNREACH
        && icmp.ty != ICMP_TIME_EXCEEDED
        && icmp.ty != ICMP_PARAMETERPROB
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
    if in_ihl < IPV4_HLEN || inner.saddr != s.ip4.daddr {
        return PASS;
    }
    let in_l4 = in_off + in_ihl;
    let Ok(in_ports) = ctx.load::<Ports>(in_l4) else {
        return PASS;
    };

    s.key = CtKey {
        saddr: [inner.daddr, 0, 0, 0],
        daddr: [inner.saddr, 0, 0, 0],
        sport: in_ports.dport,
        dport: in_ports.sport,
        proto: inner.proto,
        family: AF_INET,
        _pad: [0; 2],
    };
    let Some(e) = (unsafe { CT.get(&s.key) }) else {
        return PASS;
    };
    s.xlate = *e;
    if s.ip4.ttl <= 1 {
        return SHOT;
    }

    let delta = if l3_off == 0 { ETH_HLEN } else { 0 };
    if ensure_eth_head(ctx, l3_off, AF_INET).is_err() {
        return SHOT;
    }
    let l4_off = l4_off + delta;
    let in_off = in_off + delta;
    let in_l4 = in_l4 + delta;

    s.icmp = icmp;
    s.inner4 = inner;
    let res = if s.xlate.family == AF_INET {
        icmp4_rewrite(ctx, s, l4_off, in_off, in_l4, &in_ports)
    } else {
        icmp4_to_icmp6(ctx, s, in_l4, in_ihl)
    };
    if res.is_err() {
        return SHOT;
    }

    let out_proto = if s.xlate.family == AF_INET6 {
        PROTO_ICMPV6
    } else {
        PROTO_ICMP
    };
    let ingress = ingress_ifindex(ctx);
    let rc = fib_route(
        ctx,
        &mut s.fib,
        ingress,
        s.xlate.family,
        out_proto,
        s.ip4.tos,
        &s.xlate.saddr,
        &s.xlate.daddr,
        0,
        0,
    );
    if rc != FIB_SUCCESS && rc != FIB_NO_NEIGH {
        stat_add(STAT_FIB_DROP, 1);
        return SHOT;
    }
    stat_add(STAT_ICMP_XLATE, 1);
    redirect(ctx, &s.fib, &mut s.nh, rc, s.xlate.family)
}

/// IPv6 ICMPv6 差错：若对端是 IPv6 则原地还原 ICMPv6，若对端是 IPv4 则转换为 ICMPv4 差错。
#[inline(always)]
fn handle_icmp6(ctx: &TcContext, s: &mut Scratch, l3_off: usize, l4_off: usize, tos: u8) -> i32 {
    let Ok(icmp) = ctx.load::<IcmpHdr>(l4_off) else {
        return PASS;
    };
    if icmp.ty != ICMPV6_DEST_UNREACH
        && icmp.ty != ICMPV6_PKT_TOOBIG
        && icmp.ty != ICMPV6_TIME_EXCEED
        && icmp.ty != ICMPV6_PARAMPROB
    {
        return PASS;
    }
    let in_off = l4_off + 8;
    let Ok(inner) = ctx.load::<Ipv6Hdr>(in_off) else {
        return PASS;
    };
    if (u32::from_be(inner.ver_tc_flow) >> 28) != 6
        || (inner.nexthdr != PROTO_TCP && inner.nexthdr != PROTO_UDP)
        || inner.saddr != s.ip6.daddr
    {
        return PASS;
    }
    let in_l4 = in_off + IPV6_HLEN;
    let Ok(in_ports) = ctx.load::<Ports>(in_l4) else {
        return PASS;
    };

    s.key = CtKey {
        saddr: inner.daddr,
        daddr: inner.saddr,
        sport: in_ports.dport,
        dport: in_ports.sport,
        proto: inner.nexthdr,
        family: AF_INET6,
        _pad: [0; 2],
    };
    let Some(e) = (unsafe { CT.get(&s.key) }) else {
        return PASS;
    };
    s.xlate = *e;
    if s.ip6.hop_limit <= 1 {
        return SHOT;
    }

    let delta = if l3_off == 0 { ETH_HLEN } else { 0 };
    if ensure_eth_head(ctx, l3_off, AF_INET6).is_err() {
        return SHOT;
    }
    let l4_off = l4_off + delta;
    let in_off = in_off + delta;
    let in_l4 = in_l4 + delta;

    s.icmp = icmp;
    s.inner6 = inner;
    let res = if s.xlate.family == AF_INET6 {
        icmp6_rewrite(ctx, s, l4_off, in_off, in_l4, &in_ports)
    } else {
        icmp6_to_icmp4(ctx, s, in_l4, tos)
    };
    if res.is_err() {
        return SHOT;
    }

    let out_proto = if s.xlate.family == AF_INET6 {
        PROTO_ICMPV6
    } else {
        PROTO_ICMP
    };
    let ingress = ingress_ifindex(ctx);
    let rc = fib_route(
        ctx,
        &mut s.fib,
        ingress,
        s.xlate.family,
        out_proto,
        tos,
        &s.xlate.saddr,
        &s.xlate.daddr,
        0,
        0,
    );
    if rc != FIB_SUCCESS && rc != FIB_NO_NEIGH {
        stat_add(STAT_FIB_DROP, 1);
        return SHOT;
    }
    stat_add(STAT_ICMP_XLATE, 1);
    redirect(ctx, &s.fib, &mut s.nh, rc, s.xlate.family)
}

#[inline(always)]
fn icmp4_rewrite(
    ctx: &TcContext,
    s: &Scratch,
    l4_off: usize,
    in_off: usize,
    in_l4: usize,
    in_ports: &Ports,
) -> Result<(), i64> {
    let ip = &s.ip4;
    let inner = &s.inner4;
    let e = &s.xlate;
    let icmp_csum = l4_off + 2;
    let in_csum = in_off + 10;

    // 内层报文还原为“对端当初发出的那个报文”：e 的改写结果取反
    let (n_saddr, n_daddr, n_sport, n_dport) = (e.daddr[0], e.saddr[0], e.dport, e.sport);

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
    if e.saddr[0] != ip.saddr {
        ctx.l3_csum_replace(ETH_HLEN + 10, u64::from(ip.saddr), u64::from(e.saddr[0]), 4)?;
        ctx.store(ETH_HLEN + 12, &e.saddr[0], 0)?;
    }
    if e.daddr[0] != ip.daddr {
        ctx.l3_csum_replace(ETH_HLEN + 10, u64::from(ip.daddr), u64::from(e.daddr[0]), 4)?;
        ctx.store(ETH_HLEN + 16, &e.daddr[0], 0)?;
    }
    dec_ttl4(ctx, ETH_HLEN, ip.ttl, ip.proto)
}

#[inline(always)]
fn icmp6_rewrite(
    ctx: &TcContext,
    s: &Scratch,
    l4_off: usize,
    in_off: usize,
    in_l4: usize,
    in_ports: &Ports,
) -> Result<(), i64> {
    let ip6 = &s.ip6;
    let inner = &s.inner6;
    let e = &s.xlate;
    let icmp_csum = l4_off + 2;
    let pseudo = u64::from(BPF_F_PSEUDO_HDR);
    let (n_saddr, n_daddr, n_sport, n_dport) = (e.daddr, e.saddr, e.dport, e.sport);

    for i in 0..4 {
        if n_saddr[i] != inner.saddr[i] {
            ctx.l4_csum_replace(
                icmp_csum,
                u64::from(inner.saddr[i]),
                u64::from(n_saddr[i]),
                4,
            )?;
        }
        if n_daddr[i] != inner.daddr[i] {
            ctx.l4_csum_replace(
                icmp_csum,
                u64::from(inner.daddr[i]),
                u64::from(n_daddr[i]),
                4,
            )?;
        }
    }
    ctx.store(in_off + 8, &n_saddr, 0)?;
    ctx.store(in_off + 24, &n_daddr, 0)?;

    if n_sport != in_ports.sport {
        ctx.l4_csum_replace(icmp_csum, u64::from(in_ports.sport), u64::from(n_sport), 2)?;
        ctx.store(in_l4, &n_sport, 0)?;
    }
    if n_dport != in_ports.dport {
        ctx.l4_csum_replace(icmp_csum, u64::from(in_ports.dport), u64::from(n_dport), 2)?;
        ctx.store(in_l4 + 2, &n_dport, 0)?;
    }

    for i in 0..4 {
        if e.saddr[i] != ip6.saddr[i] {
            ctx.l4_csum_replace(
                icmp_csum,
                u64::from(ip6.saddr[i]),
                u64::from(e.saddr[i]),
                pseudo | 4,
            )?;
        }
        if e.daddr[i] != ip6.daddr[i] {
            ctx.l4_csum_replace(
                icmp_csum,
                u64::from(ip6.daddr[i]),
                u64::from(e.daddr[i]),
                pseudo | 4,
            )?;
        }
    }
    ctx.store(ETH_HLEN + 8, &e.saddr, 0)?;
    ctx.store(ETH_HLEN + 24, &e.daddr, 0)?;
    let hop = ip6.hop_limit.wrapping_sub(1);
    ctx.store(ETH_HLEN + 7, &hop, 0)
}

/// ICMPv4 差错转换为 ICMPv6 差错（用于 v6 进 v4 出连接）。
#[inline(always)]
fn icmp4_to_icmp6(
    ctx: &TcContext,
    s: &mut Scratch,
    in_l4: usize,
    in_ihl: usize,
) -> Result<(), i64> {
    let l4_tail = ctx.load::<u32>(in_l4 + 4)?;
    let (ty6, code6, rest6) = match (s.icmp.ty, s.icmp.code) {
        (ICMP_DEST_UNREACH, 4) => {
            let mtu = (u32::from_be(s.icmp.rest) & 0xffff).max(1280);
            (ICMPV6_PKT_TOOBIG, 0, mtu.to_be())
        }
        (ICMP_DEST_UNREACH, 2 | 3) => (ICMPV6_DEST_UNREACH, 4, 0),
        (ICMP_DEST_UNREACH, 9 | 10 | 13) => (ICMPV6_DEST_UNREACH, 1, 0),
        (ICMP_DEST_UNREACH, _) => (ICMPV6_DEST_UNREACH, 0, 0),
        (ICMP_TIME_EXCEEDED, c) => (ICMPV6_TIME_EXCEED, c, 0),
        (ICMP_PARAMETERPROB, _) => (ICMPV6_PARAMPROB, 0, 0),
        _ => return Err(-1),
    };

    ctx.change_proto(ETH_P_IPV6.to_be(), 0)?;
    // 40(外层IPv6) + 8(ICMPv6) + 40(内层IPv6) + 8(内层L4前8字节) = 96 字节
    let new_len = (ETH_HLEN + IPV6_HLEN + 56) as u32;
    if unsafe { bpf_skb_change_tail(ctx.skb.skb, new_len, 0) } != 0 {
        return Err(-1);
    }

    s.ip6 = Ipv6Hdr {
        ver_tc_flow: ((6u32 << 28) | (u32::from(s.ip4.tos) << 20)).to_be(),
        payload_len: 56u16.to_be(),
        nexthdr: PROTO_ICMPV6,
        hop_limit: s.ip4.ttl.wrapping_sub(1),
        saddr: s.xlate.saddr,
        daddr: s.xlate.daddr,
    };
    let in_plen = u16::from_be(s.inner4.tot_len).saturating_sub(in_ihl as u16);
    s.inner6 = Ipv6Hdr {
        ver_tc_flow: ((6u32 << 28) | (u32::from(s.inner4.tos) << 20)).to_be(),
        payload_len: in_plen.to_be(),
        nexthdr: s.inner4.proto,
        hop_limit: s.inner4.ttl,
        saddr: s.xlate.daddr,
        daddr: s.xlate.saddr,
    };
    s.icmp = IcmpHdr {
        ty: ty6,
        code: code6,
        check: 0xffff,
        rest: rest6,
    };
    let new_ports = Ports {
        sport: s.xlate.dport,
        dport: s.xlate.sport,
    };

    let l4_off = ETH_HLEN + IPV6_HLEN;
    ctx.store(ETH_HLEN, &s.ip6, 0)?;
    ctx.store(l4_off, &s.icmp, 0)?;
    ctx.store(l4_off + 8, &s.inner6, 0)?;
    ctx.store(l4_off + 48, &new_ports, 0)?;
    ctx.store(l4_off + 52, &l4_tail, 0)?;

    let mut p_sum = u64::from(56u32.to_be()) + u64::from(u32::from(PROTO_ICMPV6).to_be());
    let mut b_sum = u64::from(u16::from_ne_bytes([ty6, code6]))
        + u64::from(rest6)
        + u64::from(s.inner6.ver_tc_flow)
        + u64::from(s.inner6.payload_len)
        + u64::from(u16::from_ne_bytes([s.inner6.nexthdr, s.inner6.hop_limit]))
        + u64::from(new_ports.sport)
        + u64::from(new_ports.dport)
        + u64::from(l4_tail);
    for i in 0..4 {
        p_sum += u64::from(s.xlate.saddr[i]) + u64::from(s.xlate.daddr[i]);
        b_sum += u64::from(s.inner6.saddr[i]) + u64::from(s.inner6.daddr[i]);
    }
    let csum_off = l4_off + 2;
    ctx.l4_csum_replace(
        csum_off,
        0,
        u64::from(fold_wsum(p_sum)),
        u64::from(BPF_F_PSEUDO_HDR),
    )?;
    ctx.l4_csum_replace(csum_off, 0, u64::from(fold_wsum(b_sum)), 0)
}

/// ICMPv6 差错转换为 ICMPv4 差错（用于 v4 进 v6 出连接）。
#[inline(always)]
fn icmp6_to_icmp4(ctx: &TcContext, s: &mut Scratch, in_l4: usize, tos: u8) -> Result<(), i64> {
    let l4_tail = ctx.load::<u32>(in_l4 + 4)?;
    let (ty4, code4, rest4) = match (s.icmp.ty, s.icmp.code) {
        (ICMPV6_DEST_UNREACH, 4) => (ICMP_DEST_UNREACH, 3, 0),
        (ICMPV6_DEST_UNREACH, 1) => (ICMP_DEST_UNREACH, 10, 0),
        (ICMPV6_DEST_UNREACH, _) => (ICMP_DEST_UNREACH, 1, 0),
        (ICMPV6_PKT_TOOBIG, _) => {
            let mtu = u32::from_be(s.icmp.rest)
                .saturating_sub(20)
                .clamp(576, 65535);
            (ICMP_DEST_UNREACH, 4, mtu.to_be())
        }
        (ICMPV6_TIME_EXCEED, c) => (ICMP_TIME_EXCEEDED, c, 0),
        (ICMPV6_PARAMPROB, _) => (ICMP_PARAMETERPROB, 0, 0),
        _ => return Err(-1),
    };

    ctx.change_proto(ETH_P_IP.to_be(), 0)?;
    // 20(外层IPv4) + 8(ICMPv4) + 20(内层IPv4) + 8(内层L4前8字节) = 56 字节
    let new_len = (ETH_HLEN + IPV4_HLEN + 36) as u32;
    if unsafe { bpf_skb_change_tail(ctx.skb.skb, new_len, 0) } != 0 {
        return Err(-1);
    }

    s.ip4 = Ipv4Hdr {
        ver_ihl: 0x45,
        tos,
        tot_len: 56u16.to_be(),
        id: 0,
        frag_off: 0,
        ttl: s.ip6.hop_limit.wrapping_sub(1),
        proto: PROTO_ICMP,
        check: 0,
        saddr: s.xlate.saddr[0],
        daddr: s.xlate.daddr[0],
    };
    s.ip4.check = ipv4_csum(&s.ip4);

    let in_tos = ((u32::from_be(s.inner6.ver_tc_flow) >> 20) & 0xff) as u8;
    s.inner4 = Ipv4Hdr {
        ver_ihl: 0x45,
        tos: in_tos,
        tot_len: u16::from_be(s.inner6.payload_len)
            .wrapping_add(IPV4_HLEN as u16)
            .to_be(),
        id: 0,
        frag_off: 0x4000u16.to_be(),
        ttl: s.inner6.hop_limit,
        proto: s.inner6.nexthdr,
        check: 0,
        saddr: s.xlate.daddr[0],
        daddr: s.xlate.saddr[0],
    };
    s.inner4.check = ipv4_csum(&s.inner4);

    s.icmp = IcmpHdr {
        ty: ty4,
        code: code4,
        check: 0xffff,
        rest: rest4,
    };
    let new_ports = Ports {
        sport: s.xlate.dport,
        dport: s.xlate.sport,
    };

    let l4_off = ETH_HLEN + IPV4_HLEN;
    ctx.store(ETH_HLEN, &s.ip4, 0)?;
    ctx.store(l4_off, &s.icmp, 0)?;
    ctx.store(l4_off + 8, &s.inner4, 0)?;
    ctx.store(l4_off + 28, &new_ports, 0)?;
    ctx.store(l4_off + 32, &l4_tail, 0)?;

    let b_sum = u64::from(u16::from_ne_bytes([ty4, code4]))
        + u64::from(rest4)
        + u64::from(u16::from_ne_bytes([s.inner4.ver_ihl, s.inner4.tos]))
        + u64::from(s.inner4.tot_len)
        + u64::from(s.inner4.id)
        + u64::from(s.inner4.frag_off)
        + u64::from(u16::from_ne_bytes([s.inner4.ttl, s.inner4.proto]))
        + u64::from(s.inner4.check)
        + u64::from(s.inner4.saddr)
        + u64::from(s.inner4.daddr)
        + u64::from(new_ports.sport)
        + u64::from(new_ports.dport)
        + u64::from(l4_tail);
    ctx.l4_csum_replace(l4_off + 2, 0, u64::from(fold_wsum(b_sum)), 0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
