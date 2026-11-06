use std::{
    collections::{BTreeMap, HashMap as StdHashMap, HashSet},
    ffi::CString,
    fs,
    hash::Hash,
    mem::size_of,
    net::IpAddr,
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow, bail};
use aya::{
    Ebpf, EbpfLoader, Pod,
    maps::{Array, HashMap, Map, MapData, MapInfo, MapType, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, tc, tc::SchedClassifierLinkId},
};
use ebpf_forward_common::*;
use log::{debug, info, warn};

use crate::netinfo::{IfKind, Iface, ip_to_raw};

pub const PROG_ETH: &str = "fwd_eth";
pub const PROG_L3: &str = "fwd_l3";
/// 连接跟踪表在 pin 目录下的文件名。
pub const CT_PIN_NAME: &str = "CT";

pub fn ebpf_object() -> &'static [u8] {
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-forward"))
}

/// 加载 eBPF 对象并让内核 verifier 校验两个程序（不挂载）。
///
/// `ct_pin` 指定连接跟踪表在 bpffs 上的固定路径：已存在时直接复用（里面的连接得以保留），
/// 否则新建并固定；为 None 时连接跟踪表随进程销毁（`check` 试加载用这种方式，不碰守护进程的 pin）。
pub fn load_object(ct_max: u32, ct_pin: Option<&Path>) -> Result<Ebpf> {
    let mut loader = EbpfLoader::new();
    loader.map_max_entries("CT", ct_max);
    if let Some(p) = ct_pin {
        loader.map_pin_path("CT", p.to_path_buf());
    }
    let mut ebpf = loader.load(ebpf_object()).context("创建 eBPF map 失败")?;
    for name in [PROG_ETH, PROG_L3] {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("eBPF 对象中缺少程序 {name}"))?
            .try_into()?;
        prog.load().with_context(|| {
            format!("加载 eBPF 程序 {name} 失败（内核 verifier 拒绝或内核不支持）")
        })?;
    }
    Ok(ebpf)
}

fn is_bpffs(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0;
    ok && st.f_type as u64 == libc::BPF_FS_MAGIC as u64
}

/// 准备连接跟踪表的固定路径：创建 pin 目录，已有的 pin 与当前配置 / 程序版本不符时删掉重建。
/// bpffs 不可用时返回 None，连接跟踪表退回为随进程销毁。
fn prepare_ct_pin(pin_dir: &Path, ct_max: u32) -> Option<PathBuf> {
    if let Err(e) = fs::create_dir_all(pin_dir) {
        warn!(
            "无法创建 pin 目录 {}（{e}），连接跟踪表不会在重启后保留",
            pin_dir.display()
        );
        return None;
    }
    if !is_bpffs(pin_dir) {
        warn!(
            "{} 不在 bpffs 上（未挂载 /sys/fs/bpf？），连接跟踪表不会在重启后保留",
            pin_dir.display()
        );
        return None;
    }
    let path = pin_dir.join(CT_PIN_NAME);
    if !path.exists() {
        return Some(path);
    }
    match MapInfo::from_pin(&path) {
        Ok(info)
            if matches!(info.map_type(), Ok(MapType::LruHash))
                && info.key_size() == size_of::<CtKey>() as u32
                && info.value_size() == size_of::<CtValue>() as u32 =>
        {
            if info.max_entries() == ct_max {
                return Some(path);
            }
            info!(
                "连接跟踪表容量由 {} 改为 {ct_max}，重建连接跟踪表（已有连接会中断）",
                info.max_entries()
            );
        }
        Ok(_) => info!("已固定的连接跟踪表与当前程序版本不兼容，重建连接跟踪表（已有连接会中断）"),
        Err(e) => warn!("无法打开已固定的连接跟踪表 {}（{e}），重建", path.display()),
    }
    match fs::remove_file(&path) {
        Ok(()) => Some(path),
        Err(e) => {
            warn!(
                "删除旧的连接跟踪表 {} 失败（{e}），连接跟踪表不会在重启后保留",
                path.display()
            );
            None
        }
    }
}

/// 删除 pin 目录（固定的连接跟踪表随之销毁）；返回是否确实删除了东西。
pub fn remove_pins(pin_dir: &Path) -> Result<bool> {
    if !pin_dir.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(pin_dir).with_context(|| format!("删除 {} 失败", pin_dir.display()))?;
    Ok(true)
}

struct Attached {
    ifindex: u32,
    prog: &'static str,
    link: SchedClassifierLinkId,
}

pub struct Timeouts {
    pub tcp: u64,
    pub udp: u64,
}

#[derive(Default, Debug, Clone)]
pub struct GcStats {
    pub conns: u64,
    pub removed: u64,
    pub per_rule: StdHashMap<(u8, u16), u64>,
}

pub struct Datapath {
    ebpf: Ebpf,
    rules: HashMap<MapData, RuleKey, RuleValue>,
    ct: HashMap<MapData, CtKey, CtValue>,
    local_addrs: HashMap<MapData, LocalAddrKey, u32>,
    if_mtu: HashMap<MapData, u32, u32>,
    config: Array<MapData, GlobalConfig>,
    attached: BTreeMap<String, Attached>,
    pub ct_map_id: u32,
    pub stats_map_id: u32,
}

fn take<T>(ebpf: &mut Ebpf, name: &str) -> Result<(T, u32)>
where
    T: TryFrom<Map, Error = aya::maps::MapError>,
{
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| anyhow!("eBPF 对象中缺少 map {name}"))?;
    let id = match &map {
        Map::HashMap(d) | Map::LruHashMap(d) | Map::Array(d) | Map::PerCpuArray(d) => {
            d.info()?.id()
        }
        _ => 0,
    };
    let typed = T::try_from(map).with_context(|| format!("map {name} 类型不符"))?;
    Ok((typed, id))
}

impl Datapath {
    /// `pin_dir` 为 Some 时把连接跟踪表固定到 `pin_dir/CT`，重启守护进程时复用其中的连接。
    pub fn load(ct_max: u32, pin_dir: Option<&Path>) -> Result<Self> {
        let ct_pin = pin_dir.and_then(|d| prepare_ct_pin(d, ct_max));
        let restored = ct_pin.as_deref().is_some_and(Path::exists);
        let mut ebpf = load_object(ct_max, ct_pin.as_deref())?;
        let (ct, ct_map_id): (HashMap<MapData, CtKey, CtValue>, _) = take(&mut ebpf, "CT")?;
        if let Some(p) = &ct_pin {
            if restored {
                let n = ct.keys().filter_map(Result::ok).count();
                info!(
                    "复用已固定的连接跟踪表 {}（{n} 项），重启前的连接继续转发",
                    p.display()
                );
            } else {
                info!(
                    "连接跟踪表已固定到 {}，重启服务时会保留已有连接",
                    p.display()
                );
            }
        }
        let (_, stats_map_id): (PerCpuArray<MapData, u64>, _) = take(&mut ebpf, "STATS")?;
        Ok(Self {
            rules: take(&mut ebpf, "RULES")?.0,
            local_addrs: take(&mut ebpf, "LOCAL_ADDRS")?.0,
            if_mtu: take(&mut ebpf, "IF_MTU")?.0,
            config: take(&mut ebpf, "CONFIG")?.0,
            ct,
            ebpf,
            attached: BTreeMap::new(),
            ct_map_id,
            stats_map_id,
        })
    }

    pub fn set_global(&mut self, cfg: &GlobalConfig) -> Result<()> {
        if self.config.get(&0, 0).ok().as_ref() != Some(cfg) {
            self.config.set(0, cfg, 0).context("写入 CONFIG 失败")?;
        }
        Ok(())
    }

    pub fn set_rules(&mut self, want: &StdHashMap<RuleKey, RuleValue>) -> Result<()> {
        let stale: Vec<RuleKey> = self
            .rules
            .keys()
            .filter_map(Result::ok)
            .filter(|k| !want.contains_key(k))
            .collect();
        for k in stale {
            self.rules.remove(&k).context("删除规则失败")?;
        }
        for (k, v) in want {
            if self.rules.get(k, 0).ok().as_ref() != Some(v) {
                self.rules.insert(k, v, 0).context("写入规则失败")?;
            }
        }
        Ok(())
    }

    pub fn set_local_addrs(&mut self, addrs: &HashSet<IpAddr>) -> Result<()> {
        let want: StdHashMap<LocalAddrKey, u32> = addrs
            .iter()
            .map(|&a| {
                let (addr, family) = ip_to_raw(a);
                (
                    LocalAddrKey {
                        addr,
                        family,
                        _pad: [0; 3],
                    },
                    1,
                )
            })
            .collect();
        sync_set(&mut self.local_addrs, &want)
    }

    pub fn set_if_mtu(&mut self, ifaces: &[Iface]) -> Result<()> {
        let want: StdHashMap<u32, u32> = ifaces
            .iter()
            .filter(|i| i.mtu > 0)
            .map(|i| (i.index, i.mtu))
            .collect();
        sync_set(&mut self.if_mtu, &want)
    }

    pub fn attached(&self) -> impl Iterator<Item = (&str, u32, &'static str)> {
        self.attached
            .iter()
            .map(|(n, a)| (n.as_str(), a.ifindex, a.prog))
    }

    /// 让挂载的网卡集合与 `wanted` 一致（网卡被删除重建后 ifindex 会变，需要重新挂载）。
    pub fn sync_interfaces(&mut self, wanted: &[&Iface]) {
        let names: HashSet<&str> = wanted.iter().map(|i| i.name.as_str()).collect();
        let stale: Vec<String> = self
            .attached
            .iter()
            .filter(|(name, a)| {
                !names.contains(name.as_str())
                    || wanted.iter().any(|i| {
                        &i.name == *name
                            && (i.index != a.ifindex || prog_for(i.kind) != Some(a.prog))
                    })
            })
            .map(|(n, _)| n.clone())
            .collect();
        for name in stale {
            self.detach(&name);
        }
        for iface in wanted {
            if self.attached.contains_key(&iface.name) {
                continue;
            }
            match self.attach(iface) {
                Ok(prog) => info!(
                    "已在网卡 {} (ifindex {}) 挂载 {prog}",
                    iface.name, iface.index
                ),
                Err(e) => warn!("在网卡 {} 挂载 eBPF 失败: {e:#}", iface.name),
            }
        }
    }

    fn attach(&mut self, iface: &Iface) -> Result<&'static str> {
        let Some(prog_name) = prog_for(iface.kind) else {
            bail!("不支持的网卡类型 {:?}", iface.kind);
        };
        // 清理异常退出遗留的同名过滤器（netlink 方式挂载不会随进程退出自动卸载）
        for n in [PROG_ETH, PROG_L3] {
            let _ = tc::qdisc_detach_program(&iface.name, TcAttachType::Ingress, n);
        }
        let _ = tc::qdisc_add_clsact(&iface.name);
        let prog: &mut SchedClassifier = self
            .ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow!("缺少程序 {prog_name}"))?
            .try_into()?;
        let link = prog.attach(&iface.name, TcAttachType::Ingress)?;
        self.attached.insert(
            iface.name.clone(),
            Attached {
                ifindex: iface.index,
                prog: prog_name,
                link,
            },
        );
        Ok(prog_name)
    }

    pub fn detach(&mut self, name: &str) {
        let Some(a) = self.attached.remove(name) else {
            return;
        };
        if let Some(p) = self.ebpf.program_mut(a.prog) {
            let prog: Result<&mut SchedClassifier, _> = p.try_into();
            if let Ok(prog) = prog {
                match prog.detach(a.link) {
                    Ok(()) => info!("已从网卡 {name} 卸载 eBPF"),
                    Err(e) => debug!("卸载网卡 {name} 上的 eBPF: {e}"),
                }
            }
        }
    }

    pub fn detach_all(&mut self) {
        let names: Vec<String> = self.attached.keys().cloned().collect();
        for n in names {
            self.detach(&n);
        }
    }

    /// 回收超时 / 已关闭 / 规则已删除的连接，两个方向的项总是成对删除。
    pub fn gc(&mut self, now_ns: u64, t: &Timeouts, live_rules: &HashSet<(u8, u16)>) -> GcStats {
        let entries: StdHashMap<CtKey, CtValue> = self.ct.iter().filter_map(Result::ok).collect();
        let mut doomed: Vec<CtKey> = Vec::new();
        let mut st = GcStats::default();

        for (k, v) in &entries {
            let pair_key = v.pair_key(k.proto);
            let pair = entries
                .get(&pair_key)
                .copied()
                .or_else(|| self.ct.get(&pair_key, 0).ok());
            let idle = now_ns.saturating_sub(v.last_seen) / 1_000_000_000;

            if v.flags & CT_F_REPLY != 0 {
                if pair.is_none() && idle > ORPHAN_TIMEOUT {
                    doomed.push(*k);
                }
                continue;
            }
            let Some(r) = pair else {
                if idle > ORPHAN_TIMEOUT {
                    doomed.push(*k);
                }
                continue;
            };
            let last = v.last_seen.max(r.last_seen);
            let idle = now_ns.saturating_sub(last) / 1_000_000_000;
            let lport = u16::from_be(k.dport);
            let rule_gone = !live_rules.contains(&(k.proto, lport));
            if rule_gone || idle > conn_timeout(k.proto, v.flags, r.flags, t) {
                doomed.push(*k);
                doomed.push(pair_key);
            } else {
                st.conns += 1;
                *st.per_rule.entry((k.proto, lport)).or_default() += 1;
            }
        }
        for k in doomed {
            if self.ct.remove(&k).is_ok() {
                st.removed += 1;
            }
        }
        st
    }
}

impl Drop for Datapath {
    fn drop(&mut self) {
        self.detach_all();
    }
}

const ORPHAN_TIMEOUT: u64 = 30;

/// 超时规则参考 Linux conntrack 的默认值（秒）。
pub fn conn_timeout(proto: u8, orig: u16, reply: u16, t: &Timeouts) -> u64 {
    let any = orig | reply;
    if proto == PROTO_TCP {
        if any & CT_F_RST != 0 {
            10
        } else if orig & CT_F_FIN != 0 && reply & CT_F_FIN != 0 {
            60
        } else if any & CT_F_FIN != 0 {
            120
        } else if reply & CT_F_SEEN == 0 {
            60
        } else {
            t.tcp
        }
    } else if reply & CT_F_SEEN == 0 {
        30
    } else {
        t.udp
    }
}

fn prog_for(kind: IfKind) -> Option<&'static str> {
    match kind {
        IfKind::Ether => Some(PROG_ETH),
        IfKind::L3 => Some(PROG_L3),
        _ => None,
    }
}

fn sync_set<K: Copy + Eq + Hash + Pod>(
    map: &mut HashMap<MapData, K, u32>,
    want: &StdHashMap<K, u32>,
) -> Result<()> {
    let stale: Vec<K> = map
        .keys()
        .filter_map(Result::ok)
        .filter(|k| !want.contains_key(k))
        .collect();
    for k in stale {
        map.remove(&k)?;
    }
    for (k, v) in want {
        if map.get(k, 0).ok() != Some(*v) {
            map.insert(k, v, 0)?;
        }
    }
    Ok(())
}

pub fn read_stats(m: &PerCpuArray<MapData, u64>) -> [u64; STAT_MAX as usize] {
    let mut out = [0u64; STAT_MAX as usize];
    for (i, slot) in out.iter_mut().enumerate() {
        if let Ok(vals) = m.get(&(i as u32), 0) {
            *slot = vals.iter().sum();
        }
    }
    out
}

/// 供命令行读取守护进程的 map（按 ID 打开）。
pub fn open_ct(id: u32) -> Result<HashMap<MapData, CtKey, CtValue>> {
    let data = MapData::from_id(id).context("打开连接跟踪表失败")?;
    Ok(HashMap::try_from(Map::from_map_data(data)?)?)
}

pub fn open_stats(id: u32) -> Result<PerCpuArray<MapData, u64>> {
    let data = MapData::from_id(id).context("打开统计表失败")?;
    Ok(PerCpuArray::try_from(Map::from_map_data(data)?)?)
}
