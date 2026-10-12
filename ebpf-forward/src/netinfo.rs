use std::{
    collections::HashMap,
    ffi::CStr,
    fs, io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
};

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
/// 无二层头的网卡类型：ipip / sit / gre / rawip / none(tun、WireGuard)。
const ARPHRD_L3: &[u16] = &[768, 769, 776, 778, 519, 65534];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfKind {
    Ether,
    L3,
    Loopback,
    Other(u16),
}

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    pub mtu: u32,
    pub kind: IfKind,
    pub up: bool,
    pub addrs: Vec<Ipv4Addr>,
}

fn read_sys(name: &str, attr: &str) -> Option<String> {
    fs::read_to_string(Path::new("/sys/class/net").join(name).join(attr))
        .ok()
        .map(|s| s.trim().to_owned())
}

pub fn interfaces() -> io::Result<Vec<Iface>> {
    let addrs = ipv4_addrs()?;
    let mut out = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let Some(index) = read_sys(&name, "ifindex").and_then(|s| s.parse().ok()) else {
            continue;
        };
        let mtu = read_sys(&name, "mtu")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let ty: u16 = read_sys(&name, "type")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let flags = read_sys(&name, "flags")
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let kind = match ty {
            ARPHRD_ETHER => IfKind::Ether,
            ARPHRD_LOOPBACK => IfKind::Loopback,
            t if ARPHRD_L3.contains(&t) => IfKind::L3,
            t => IfKind::Other(t),
        };
        out.push(Iface {
            addrs: addrs.get(&name).cloned().unwrap_or_default(),
            name,
            index,
            mtu,
            kind,
            up: flags & libc::IFF_UP as u32 != 0,
        });
    }
    out.sort_by_key(|i| i.index);
    Ok(out)
}

/// 各网卡上的 IPv4 地址（别名 eth0:1 归入 eth0）。
fn ipv4_addrs() -> io::Result<HashMap<String, Vec<Ipv4Addr>>> {
    let mut map: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut p = ifap;
        while !p.is_null() {
            let ifa = &*p;
            if !ifa.ifa_addr.is_null() && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                let base = name.split(':').next().unwrap_or(&name).to_owned();
                let v = map.entry(base).or_default();
                if !v.contains(&ip) {
                    v.push(ip);
                }
            }
            p = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    Ok(map)
}

/// 默认路由所在网卡（/proc/net/route）。
pub fn default_route_ifaces() -> Vec<String> {
    let Ok(text) = fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    let mut v: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| f[0].to_owned())
        })
        .collect();
    v.dedup();
    v
}

/// 内核去往 `dst` 时选用的源地址：对 UDP socket 做 connect 即会完成路由查找，不发包。
pub fn source_addr_for(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect((dst, 9))?;
    match s.local_addr()? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Ok(*a.ip()),
        _ => Err(io::Error::other("无法确定源地址")),
    }
}

pub fn local_port_range() -> Option<(u16, u16)> {
    let s = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let mut it = s.split_whitespace().filter_map(|x| x.parse().ok());
    Some((it.next()?, it.next()?))
}

pub fn ip_forward_enabled() -> bool {
    fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|s| s.trim() == "1")
}

pub fn enable_ip_forward() -> io::Result<bool> {
    if ip_forward_enabled() {
        return Ok(false);
    }
    fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")?;
    Ok(true)
}

/// 本机是否有 socket 在监听该端口，返回 ("tcp"/"udp")。
pub fn local_listeners(port: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    let tcp = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .any(|f| proc_net_has_port(f, port, Some("0A")));
    let udp = ["/proc/net/udp", "/proc/net/udp6"]
        .iter()
        .any(|f| proc_net_has_port(f, port, None));
    if tcp {
        v.push("tcp");
    }
    if udp {
        v.push("udp");
    }
    v
}

fn proc_net_has_port(file: &str, port: u16, state: Option<&str>) -> bool {
    let Ok(text) = fs::read_to_string(file) else {
        return false;
    };
    let want = format!("{port:04X}");
    text.lines().skip(1).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() > 3
            && f[1].rsplit(':').next() == Some(want.as_str())
            && state.is_none_or(|s| f[3] == s)
    })
}

pub fn ip_to_be(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

pub fn be_to_ip(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v.to_ne_bytes())
}
