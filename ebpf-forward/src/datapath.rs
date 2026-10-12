use std::{
    collections::{BTreeMap, HashMap as StdHashMap, HashSet},
    net::Ipv4Addr,
};

use anyhow::{Context as _, Result, anyhow, bail};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap, Map, MapData, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, tc, tc::SchedClassifierLinkId},
};
use ebpf_forward_common::*;
use log::{debug, info, warn};

use crate::netinfo::{IfKind, Iface, ip_to_be};

pub const PROG_ETH: &str = "fwd_eth";
pub const PROG_L3: &str = "fwd_l3";

pub fn ebpf_object() -> &'static [u8] {
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-forward"))
}

/// 加载 eBPF 对象并让内核 verifier 校验两个程序（不挂载）。
pub fn load_object(ct_max: u32) -> Result<Ebpf> {
    let mut ebpf = EbpfLoader::new()
        .map_max_entries("CT", ct_max)
        .load(ebpf_object())
        .context("创建 eBPF map 失败")?;
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
    local_addrs: HashMap<MapData, u32, u32>,
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
    pub fn load(ct_max: u32) -> Result<Self> {
        let mut ebpf = load_object(ct_max)?;
        let (ct, ct_map_id) = take(&mut ebpf, "CT")?;
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

    pub fn set_local_addrs(&mut self, addrs: &HashSet<Ipv4Addr>) -> Result<()> {
        let want: HashSet<u32> = addrs.iter().map(|a| ip_to_be(*a)).collect();
        sync_set(
            &mut self.local_addrs,
            &want.iter().map(|a| (*a, 1)).collect(),
        )
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
pub fn conn_timeout(proto: u8, orig: u32, reply: u32, t: &Timeouts) -> u64 {
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

fn sync_set(map: &mut HashMap<MapData, u32, u32>, want: &StdHashMap<u32, u32>) -> Result<()> {
    let stale: Vec<u32> = map
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
