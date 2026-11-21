use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::Mutex;

use crate::i18n::{self, Lang, pick};
use crate::model::{CheckCategory, CheckItem, CheckState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrListKind {
    Attack,
    Spam,
    Proxy,
    Tor,
    Datacenter,
    Vpn,
}

#[derive(Debug, Clone, Copy)]
pub struct CidrListSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: CidrListKind,
    /// Address-level threat list used for computing whole-ASN abuse density vs global baseline.
    pub density: bool,
    pub url: &'static str,
}

/// 17 public IPv4 threat, spam, proxy, Tor, datacenter & VPN CIDR lists (cached in memory per session).
pub const OPTIONAL_CIDR_LISTS: &[CidrListSpec] = &[
    CidrListSpec {
        id: "firehol1",
        name: "FireHOL Level 1",
        kind: CidrListKind::Attack,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    },
    CidrListSpec {
        id: "firehol2",
        name: "FireHOL Level 2",
        kind: CidrListKind::Attack,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
    },
    CidrListSpec {
        id: "firehol3",
        name: "FireHOL Level 3",
        kind: CidrListKind::Attack,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
    },
    CidrListSpec {
        id: "blocklistde",
        name: "blocklist.de",
        kind: CidrListKind::Attack,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
    },
    CidrListSpec {
        id: "greensnow",
        name: "GreenSnow",
        kind: CidrListKind::Attack,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/greensnow.ipset",
    },
    CidrListSpec {
        id: "cybercrime",
        name: "CyberCrime C&C",
        kind: CidrListKind::Attack,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset",
    },
    CidrListSpec {
        id: "sfs7d",
        name: "StopForumSpam 7d",
        kind: CidrListKind::Spam,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset",
    },
    CidrListSpec {
        id: "dshield",
        name: "DShield 7d",
        kind: CidrListKind::Attack,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_7d.netset",
    },
    CidrListSpec {
        id: "ipsum3",
        name: "IPsum >=3",
        kind: CidrListKind::Attack,
        density: false,
        url: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    },
    CidrListSpec {
        id: "et_compromised",
        name: "ET Compromised",
        kind: CidrListKind::Attack,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_compromised.ipset",
    },
    CidrListSpec {
        id: "ciarmy",
        name: "CINS Army",
        kind: CidrListKind::Attack,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ciarmy.ipset",
    },
    CidrListSpec {
        id: "botscout",
        name: "BotScout 7d",
        kind: CidrListKind::Spam,
        density: true,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_7d.ipset",
    },
    CidrListSpec {
        id: "socks_proxy",
        name: "Public SOCKS Proxy",
        kind: CidrListKind::Proxy,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset",
    },
    CidrListSpec {
        id: "ssl_proxy",
        name: "Public HTTPS Proxy",
        kind: CidrListKind::Proxy,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies_7d.ipset",
    },
    CidrListSpec {
        id: "tor_exits",
        name: "Tor Exits",
        kind: CidrListKind::Tor,
        density: false,
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset",
    },
    CidrListSpec {
        id: "x4b_dc",
        name: "X4BNet Datacenter",
        kind: CidrListKind::Datacenter,
        density: false,
        url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
    },
    CidrListSpec {
        id: "x4b_vpn",
        name: "X4BNet VPN",
        kind: CidrListKind::Vpn,
        density: false,
        url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    },
];

/// In-memory session cache of parsed sorted `(start, end)` inclusive IPv4 intervals.
static CIDR_CACHE: OnceLock<Mutex<HashMap<&'static str, Vec<(u32, u32)>>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<&'static str, Vec<(u32, u32)>>> {
    CIDR_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Parse an IPset / Netset plain-text file into sorted, merged `(start, end)` inclusive `u32` ranges.
pub fn parse_ipv4_cidr_ranges(body: &str) -> Vec<(u32, u32)> {
    let mut raw: Vec<(u32, u32)> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let token = trimmed.split_whitespace().next().unwrap_or("");
        let (addr_part, prefix_part) = match token.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (token, None),
        };
        let Ok(v4) = addr_part.parse::<Ipv4Addr>() else {
            continue;
        };
        let prefix: u32 = match prefix_part {
            Some(p) => match p.parse::<u32>() {
                Ok(n) if n <= 32 => n,
                _ => continue,
            },
            None => 32,
        };
        let ip_u32 = u32::from(v4);
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        let start = ip_u32 & mask;
        let end = start | !mask;
        raw.push((start, end));
    }
    merge_ranges(raw)
}

pub fn merge_ranges(mut raw: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if raw.is_empty() {
        return raw;
    }
    raw.sort_unstable_by_key(|&(s, _)| s);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(raw.len());
    for (s, e) in raw {
        if let Some(last) = merged.last_mut() {
            if s <= last.1.saturating_add(1) {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

/// Merge a list of IPv4 CIDR strings (e.g. an ASN's announced prefixes) into disjoint `u32` ranges.
pub fn merge_ipv4_cidrs(cidrs: &[String]) -> Vec<(u32, u32)> {
    let joined = cidrs.join("\n");
    parse_ipv4_cidr_ranges(&joined)
}

/// Two-pointer count of addresses from `ranges` that fall inside `space` (both sorted & disjoint).
pub fn count_overlap_u64(ranges: &[(u32, u32)], space: &[(u32, u32)]) -> u64 {
    let mut total = 0u64;
    let mut j = 0usize;
    for &(rs, re) in ranges {
        while j < space.len() && space[j].1 < rs {
            j += 1;
        }
        let mut k = j;
        while k < space.len() && space[k].0 <= re {
            let lo = rs.max(space[k].0) as u64;
            let hi = re.min(space[k].1) as u64;
            if hi >= lo {
                total += hi - lo + 1;
            }
            k += 1;
        }
    }
    total
}

/// Query merged sorted `u32` ranges for an exact IPv4 match and `/24` sibling overlap.
pub fn match_ip_and_subnet24(ranges: &[(u32, u32)], ip: Ipv4Addr) -> (bool, bool, Vec<Ipv4Addr>) {
    let target = u32::from(ip);
    let block_start = target & 0xffff_ff00;
    let block_end = block_start | 0x0000_00ff;

    let exact_hit = match ranges.binary_search_by_key(&target, |&(s, _)| s) {
        Ok(_) => true,
        Err(idx) => idx > 0 && ranges[idx - 1].1 >= target,
    };

    let mut idx = ranges.partition_point(|&(_, e)| e < block_start);
    let mut whole_block = false;
    let mut neighbors = Vec::new();
    while idx < ranges.len() && ranges[idx].0 <= block_end {
        let (s, e) = ranges[idx];
        if s <= block_start && e >= block_end {
            whole_block = true;
        } else {
            let lo = s.max(block_start);
            let hi = e.min(block_end);
            for addr in lo..=hi {
                if addr != target && neighbors.len() < 64 {
                    neighbors.push(Ipv4Addr::from(addr));
                }
            }
        }
        idx += 1;
    }

    (exact_hit, whole_block, neighbors)
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsnAbuseDensity {
    pub asn_v4_size: u64,
    pub listed_in_asn: u64,
    pub per_10k: f64,
    pub baseline_per_10k: f64,
    pub ratio: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CidrSummary {
    pub loaded: usize,
    pub failed: usize,
    pub attack_hits: Vec<String>,
    pub spam_hits: Vec<String>,
    pub proxy_hits: Vec<String>,
    pub tor_hit: bool,
    pub datacenter_hit: bool,
    pub vpn_hit: bool,
    pub whole_24_attack: bool,
    pub neighbor_24_count: usize,
    pub asn_density: Option<AsnAbuseDensity>,
}

async fn load_or_fetch_list(client: &Client, spec: CidrListSpec) -> Option<Vec<(u32, u32)>> {
    {
        let guard = cache().lock().await;
        if let Some(existing) = guard.get(spec.id) {
            return Some(existing.clone());
        }
    }
    let resp = client
        .get(spec.url)
        .timeout(Duration::from_secs(7))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    let parsed = parse_ipv4_cidr_ranges(&body);
    let mut guard = cache().lock().await;
    guard.insert(spec.id, parsed.clone());
    Some(parsed)
}

/// Compute whole-ASN abuse density from cached address-level threat lists vs ~3B routed IPv4 baseline.
pub async fn compute_asn_abuse_density_from_cache(
    announced_v4_cidrs: &[String],
) -> Option<AsnAbuseDensity> {
    let space = merge_ipv4_cidrs(announced_v4_cidrs);
    let asn_v4_size: u64 = space
        .iter()
        .map(|&(s, e)| (e as u64) - (s as u64) + 1)
        .sum();
    if asn_v4_size == 0 {
        return None;
    }

    let guard = cache().lock().await;
    let mut listed_in_asn = 0u64;
    let mut global_listed = 0u64;
    let mut density_lists_used = 0usize;

    for spec in OPTIONAL_CIDR_LISTS.iter().filter(|s| s.density) {
        if let Some(ranges) = guard.get(spec.id) {
            density_lists_used += 1;
            listed_in_asn += count_overlap_u64(ranges, &space);
            global_listed += ranges
                .iter()
                .map(|&(s, e)| (e as u64) - (s as u64) + 1)
                .sum::<u64>();
        }
    }
    if density_lists_used == 0 || global_listed == 0 {
        return None;
    }

    const ROUTED_IPV4: f64 = 3_000_000_000.0;
    let per_10k = (listed_in_asn as f64 / asn_v4_size as f64) * 10_000.0;
    let baseline_per_10k = (global_listed as f64 / ROUTED_IPV4) * 10_000.0;
    let ratio = if baseline_per_10k > 0.0 {
        per_10k / baseline_per_10k
    } else {
        0.0
    };

    Some(AsnAbuseDensity {
        asn_v4_size,
        listed_in_asn,
        per_10k,
        baseline_per_10k,
        ratio,
    })
}

/// Full 17-list CIDR threat/spam/proxy/datacenter/VPN & `/24` neighbor scan (IPv4 only).
pub async fn run_optional_cidr_scan(
    client: &Client,
    ip_str: Option<&str>,
    lang: Lang,
) -> (CidrSummary, CheckItem) {
    let start = Instant::now();
    let title =
        i18n::check_title("cidr-threat-lists", lang).unwrap_or("CIDR Threat & /24 Neighbors");

    let Some(v4) = ip_str
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .and_then(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
    else {
        let item = CheckItem::new(
            "cidr-threat-lists",
            CheckCategory::NetworkLeak,
            title,
            CheckState::Unknown,
            pick(
                lang,
                "公开 CIDR 威胁列表当前仅支持 IPv4 地址",
                "Public CIDR threat lists currently support IPv4 addresses only",
            ),
        );
        return (CidrSummary::default(), item);
    };

    let mut handles = Vec::with_capacity(OPTIONAL_CIDR_LISTS.len());
    for spec in OPTIONAL_CIDR_LISTS {
        let c = client.clone();
        let s = *spec;
        handles.push(tokio::spawn(async move {
            let loaded = load_or_fetch_list(&c, s).await;
            (s, loaded)
        }));
    }

    let mut summary = CidrSummary::default();
    let mut attack_neighbors: BTreeSet<Ipv4Addr> = BTreeSet::new();

    for h in handles {
        if let Ok((spec, opt_ranges)) = h.await {
            let Some(ranges) = opt_ranges else {
                summary.failed += 1;
                continue;
            };
            summary.loaded += 1;
            let (exact, whole, neighbors) = match_ip_and_subnet24(&ranges, v4);
            match spec.kind {
                CidrListKind::Attack => {
                    if exact {
                        summary.attack_hits.push(spec.name.to_owned());
                    }
                    if whole {
                        summary.whole_24_attack = true;
                    }
                    for n in neighbors {
                        attack_neighbors.insert(n);
                    }
                }
                CidrListKind::Spam => {
                    if exact {
                        summary.spam_hits.push(spec.name.to_owned());
                    }
                    for n in neighbors {
                        attack_neighbors.insert(n);
                    }
                }
                CidrListKind::Proxy => {
                    if exact {
                        summary.proxy_hits.push(spec.name.to_owned());
                    }
                }
                CidrListKind::Tor => {
                    if exact {
                        summary.tor_hit = true;
                    }
                }
                CidrListKind::Datacenter => {
                    if exact {
                        summary.datacenter_hit = true;
                    }
                }
                CidrListKind::Vpn => {
                    if exact {
                        summary.vpn_hit = true;
                    }
                }
            }
        }
    }

    summary.neighbor_24_count = attack_neighbors.len();
    let duration_ms = start.elapsed().as_millis() as u64;

    let mut details = vec![format!(
        "{}: {v4} · {} {}/{}",
        pick(lang, "检测 IPv4", "Checked IPv4"),
        pick(lang, "已加载列表", "Lists loaded"),
        summary.loaded,
        summary.loaded + summary.failed
    )];
    if !summary.attack_hits.is_empty() {
        details.push(format!(
            "[HIT] {}: {}",
            pick(lang, "攻击/滥用威胁列表", "Threat Lists"),
            summary.attack_hits.join(", ")
        ));
    }
    if !summary.spam_hits.is_empty() {
        details.push(format!(
            "[HIT] {}: {}",
            pick(lang, "垃圾注册列表", "Spam Lists"),
            summary.spam_hits.join(", ")
        ));
    }
    if !summary.proxy_hits.is_empty() {
        details.push(format!(
            "[HIT] {}: {}",
            pick(lang, "公开代理列表", "Public Proxy Lists"),
            summary.proxy_hits.join(", ")
        ));
    }
    if summary.tor_hit {
        details.push(
            pick(lang, "[HIT] 收录于 Tor 出口列表", "[HIT] Listed in Tor Exits").to_owned(),
        );
    }
    if summary.datacenter_hit {
        details.push(
            pick(lang, "[INFO] 命中 X4BNet 机房网段", "[INFO] Inside X4BNet Datacenter range")
                .to_owned(),
        );
    }
    if summary.vpn_hit {
        details.push(
            pick(lang, "[WARN] 命中 X4BNet VPN 网段", "[WARN] Inside X4BNet VPN range").to_owned(),
        );
    }
    details.push(format!(
        "{}: {} ({})",
        pick(lang, "同 /24 邻居威胁上榜数", "Same /24 listed neighbors"),
        summary.neighbor_24_count,
        if summary.whole_24_attack {
            pick(lang, "整个 /24 网段已被拉黑", "Entire /24 block listed")
        } else {
            pick(lang, "整段未拉黑", "Block not fully listed")
        }
    ));

    let state = if summary.loaded == 0 {
        CheckState::Unknown
    } else if !summary.attack_hits.is_empty()
        || !summary.proxy_hits.is_empty()
        || summary.tor_hit
        || summary.whole_24_attack
    {
        CheckState::Fail
    } else if summary.vpn_hit
        || !summary.spam_hits.is_empty()
        || summary.neighbor_24_count >= 3
        || summary.datacenter_hit
    {
        CheckState::Warn
    } else {
        CheckState::Ok
    };

    let msg = if summary.loaded == 0 {
        pick(
            lang,
            "GitHub CIDR 列表下载失败（请检查访问 GitHub 的网络连通性）",
            "Failed to download GitHub CIDR lists (check GitHub reachability)",
        )
        .to_owned()
    } else if state == CheckState::Ok {
        match lang {
            Lang::Zh => format!(
                "{} 个威胁/代理/机房列表均洁净，同 /24 邻居上榜 {} 个",
                summary.loaded, summary.neighbor_24_count
            ),
            Lang::En => format!(
                "Clean across {} threat/proxy/DC lists ({} listed /24 neighbors)",
                summary.loaded, summary.neighbor_24_count
            ),
        }
    } else {
        match lang {
            Lang::Zh => format!(
                "威胁 {} · 垃圾 {} · 代理 {} · /24 邻居 {} · 机房/VPN: {}/{}",
                summary.attack_hits.len(),
                summary.spam_hits.len(),
                summary.proxy_hits.len(),
                summary.neighbor_24_count,
                if summary.datacenter_hit { "是" } else { "否" },
                if summary.vpn_hit { "是" } else { "否" },
            ),
            Lang::En => format!(
                "Threats {} · Spam {} · Proxy {} · /24 Neighbors {} · DC/VPN: {}/{}",
                summary.attack_hits.len(),
                summary.spam_hits.len(),
                summary.proxy_hits.len(),
                summary.neighbor_24_count,
                if summary.datacenter_hit { "Yes" } else { "No" },
                if summary.vpn_hit { "Yes" } else { "No" },
            ),
        }
    };

    let mut item = CheckItem::new(
        "cidr-threat-lists",
        CheckCategory::NetworkLeak,
        title,
        state,
        msg,
    )
    .with_details(details)
    .with_duration(duration_ms);

    if matches!(state, CheckState::Warn | CheckState::Fail) {
        item = item.with_suggestion(pick(
            lang,
            "该 IP 或其同 /24 网段邻居存在威胁/代理/VPN 列表命中，AI 平台可能按网段连坐风控，建议更换干净段位。",
            "This IP or its /24 neighbors appear in threat/proxy/VPN lists. Consider switching to a cleaner subnet.",
        ));
    }

    (summary, item)
}
