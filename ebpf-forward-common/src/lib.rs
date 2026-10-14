#![no_std]

//! eBPF 程序与用户态共享的 map 键值结构。
//!
//! 约定：所有 IPv4/IPv6 地址和端口都按网络字节序存放（即与报文中的字节完全一致）。
//! 地址统一存为 `[u32; 4]`：IPv4 放在下标 0（其余 3 项为 0），IPv6 占满 4 项，由 `family`
//! （`AF_INET` / `AF_INET6`）区分协议族。
//! 所有结构体都显式补齐 padding：哈希 map 的 key 不允许含未初始化字节。

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const MAX_RULES: u32 = 4096;
pub const MAX_LOCAL_ADDRS: u32 = 1024;
pub const MAX_IFACES: u32 = 1024;
/// 默认连接跟踪表容量（每条连接占两项：原方向 + 回复方向）。
pub const CT_DEFAULT_ENTRIES: u32 = 131072;

/// RULES 的 key：协议 + 本机监听端口。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleKey {
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// RULES 的 value。`family == 0` 表示目标尚未解析成功，规则暂不生效。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleValue {
    pub target_addr: [u32; 4],
    /// SNAT 使用的源地址（本机去往目标时的出口地址，与 target_addr 同协议族）。
    pub snat_addr: [u32; 4],
    pub target_port: u16,
    pub family: u8,
    pub _pad: u8,
}

/// LOCAL_ADDRS 的 key：本机地址（含协议族）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalAddrKey {
    pub addr: [u32; 4],
    pub family: u8,
    pub _pad: [u8; 3],
}

/// 连接跟踪 key：报文的五元组（转换前）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CtKey {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub family: u8,
    pub _pad: [u8; 2],
}

/// 连接跟踪 value：命中该 key 的报文要被改写成的五元组（可跨协议族 v4<->v6），以及状态。
///
/// 每条连接有两项：原方向（客户端 -> 本机:监听端口）和回复方向（目标 -> 本机:SNAT端口）。
/// 任一项的“改写结果”取反，恰好就是另一项的 key。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtValue {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub flags: u16,
    pub family: u8,
    pub _pad: u8,
    /// bpf_ktime_get_ns()，即 CLOCK_MONOTONIC。
    pub last_seen: u64,
    pub created: u64,
}

impl CtValue {
    /// 与本项配对的另一方向的 key。
    pub const fn pair_key(&self, proto: u8) -> CtKey {
        CtKey {
            saddr: self.daddr,
            daddr: self.saddr,
            sport: self.dport,
            dport: self.sport,
            proto,
            family: self.family,
            _pad: [0; 2],
        }
    }
}

/// 回复方向的项（目标 -> 客户端）。
pub const CT_F_REPLY: u16 = 1 << 0;
/// 回复方向已经收到过报文（目标有回应）。
pub const CT_F_SEEN: u16 = 1 << 1;
/// 本方向出现过 FIN。
pub const CT_F_FIN: u16 = 1 << 2;
/// 本方向出现过 RST。
pub const CT_F_RST: u16 = 1 << 3;

/// CONFIG 数组（单元素）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalConfig {
    /// SNAT 端口范围（主机字节序，闭区间）。
    pub snat_port_min: u16,
    pub snat_port_max: u16,
    pub flags: u32,
}

/// 对经过的 SYN / SYN-ACK 做 MSS 钳制（按入/出网卡较小的 MTU）。
pub const CFG_F_MSS_CLAMP: u32 = 1 << 0;

/// STATS（per-CPU 数组）的下标。
pub const STAT_ORIG_PKTS: u32 = 0;
pub const STAT_ORIG_BYTES: u32 = 1;
pub const STAT_REPLY_PKTS: u32 = 2;
pub const STAT_REPLY_BYTES: u32 = 3;
pub const STAT_NEW_CONN: u32 = 4;
pub const STAT_PORT_EXHAUSTED: u32 = 5;
pub const STAT_CT_INSERT_FAIL: u32 = 6;
pub const STAT_FIB_DROP: u32 = 7;
pub const STAT_FRAG_NEEDED: u32 = 8;
pub const STAT_TTL_EXCEEDED: u32 = 9;
pub const STAT_ICMP_XLATE: u32 = 10;
pub const STAT_REDIRECT_NEIGH: u32 = 11;
pub const STAT_MSS_CLAMPED: u32 = 12;
pub const STAT_REDIRECT_FAIL: u32 = 13;
pub const STAT_MAX: u32 = 16;

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for RuleKey {}
    unsafe impl aya::Pod for RuleValue {}
    unsafe impl aya::Pod for LocalAddrKey {}
    unsafe impl aya::Pod for CtKey {}
    unsafe impl aya::Pod for CtValue {}
    unsafe impl aya::Pod for GlobalConfig {}
}
