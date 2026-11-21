use std::net::IpAddr;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

use crate::i18n::{self, Lang, pick};
use crate::model::{CheckCategory, CheckItem, CheckState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsblKind {
    Mail,
    Abuse,
    Tor,
}

#[derive(Debug, Clone, Copy)]
pub struct DnsblZone {
    pub name: &'static str,
    pub zone: &'static str,
    pub kind: DnsblKind,
    pub supports_ipv6: bool,
    pub proxy_last_octets: &'static [u8],
    pub ignore_codes: &'static [&'static str],
}

/// 16 public DNS-based blocklist zones queried via standard DoH (zero API keys required).
pub const PUBLIC_DNSBL_ZONES: &[DnsblZone] = &[
    DnsblZone {
        name: "SpamCop",
        zone: "bl.spamcop.net",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "Barracuda",
        zone: "b.barracudacentral.org",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "PSBL",
        zone: "psbl.surriel.com",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "Mailspike",
        zone: "bl.mailspike.net",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "UCEPROTECT L1",
        zone: "dnsbl-1.uceprotect.net",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "GBUdb Truncate",
        zone: "truncate.gbudb.net",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "NordSpam",
        zone: "bl.nordspam.com",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "JustSpam",
        zone: "dnsbl.justspam.org",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "SpamEatingMonkey",
        zone: "bl.spameatingmonkey.net",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "SPFBL",
        zone: "dnsbl.spfbl.net",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &["127.0.0.4"],
    },
    DnsblZone {
        name: "0spam",
        zone: "bl.0spam.org",
        kind: DnsblKind::Mail,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "InterServer",
        zone: "rbl.interserver.net",
        kind: DnsblKind::Abuse,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "blocklist.de",
        zone: "bl.blocklist.de",
        kind: DnsblKind::Abuse,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "S5H",
        zone: "all.s5h.net",
        kind: DnsblKind::Abuse,
        supports_ipv6: false,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
    // DroneBL codes 8-11, 14, 19 designate open proxies / socks / VPN relays.
    DnsblZone {
        name: "DroneBL",
        zone: "dnsbl.dronebl.org",
        kind: DnsblKind::Abuse,
        supports_ipv6: false,
        proxy_last_octets: &[8, 9, 10, 11, 14, 19],
        ignore_codes: &[],
    },
    DnsblZone {
        name: "dan.me.uk Tor",
        zone: "torexit.dan.me.uk",
        kind: DnsblKind::Tor,
        supports_ipv6: true,
        proxy_last_octets: &[],
        ignore_codes: &[],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsblHit {
    pub name: String,
    pub kind: DnsblKind,
    pub codes: Vec<String>,
    pub proxy_flagged: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsblSummary {
    pub checked: usize,
    pub errors: usize,
    pub hits: Vec<DnsblHit>,
}

impl DnsblSummary {
    pub fn mail_hits(&self) -> usize {
        self.hits.iter().filter(|h| h.kind == DnsblKind::Mail).count()
    }

    pub fn abuse_hits(&self) -> usize {
        self.hits
            .iter()
            .filter(|h| h.kind == DnsblKind::Abuse)
            .count()
    }

    pub fn tor_hit(&self) -> bool {
        self.hits.iter().any(|h| h.kind == DnsblKind::Tor)
    }

    pub fn proxy_hit(&self) -> bool {
        self.hits.iter().any(|h| h.proxy_flagged)
    }
}

/// Reverse an IPv4 address into `d.c.b.a` or IPv6 into dot-separated hex nibbles for DNSBL lookups.
pub fn reverse_ip_for_dnsbl(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}")
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0f));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            nibbles.join(".")
        }
    }
}

/// Filter raw A-record strings from a DNSBL lookup, discarding test/refusal markers (`127.0.0.1`, `127.255.x.x`).
pub fn filter_valid_dnsbl_codes(answers: &[String]) -> Vec<String> {
    answers
        .iter()
        .filter(|addr| {
            addr.starts_with("127.")
                && !addr.starts_with("127.255.")
                && addr.as_str() != "127.0.0.1"
        })
        .cloned()
        .collect()
}

async fn doh_resolve_a(client: &Client, qname: &str) -> Option<Vec<String>> {
    let urls = [
        format!("https://cloudflare-dns.com/dns-query?name={qname}&type=A"),
        format!("https://dns.google/resolve?name={qname}&type=A"),
    ];
    for url in &urls {
        let Ok(resp) = client
            .get(url)
            .header("Accept", "application/dns-json")
            .timeout(Duration::from_secs(3))
            .send()
            .await
        else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(v) = resp.json::<Value>().await else {
            continue;
        };
        let Some(status) = v.get("Status").and_then(|s| s.as_u64()) else {
            continue;
        };
        if status == 3 {
            // NXDOMAIN: cleanly not listed
            return Some(Vec::new());
        }
        if status != 0 {
            continue;
        }
        let answers = v
            .get("Answer")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|item| item.get("type").and_then(|t| t.as_u64()) == Some(1))
                    .filter_map(|item| item.get("data").and_then(|d| d.as_str()).map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        return Some(answers);
    }
    None
}

/// Build the user-facing `CheckItem` from a `DnsblSummary`.
pub fn evaluate_dnsbl_summary(
    ip: &str,
    summary: &DnsblSummary,
    lang: Lang,
    duration_ms: u64,
) -> CheckItem {
    let title =
        i18n::check_title("dnsbl-reputation", lang).unwrap_or("DNSBL Public Blocklists");
    let mut details = vec![format!(
        "{}: {ip} · {} {}/{}",
        pick(lang, "查询目标", "Target IP"),
        pick(lang, "成功检测", "Checked"),
        summary.checked,
        summary.checked + summary.errors
    )];

    if summary.checked == 0 {
        return CheckItem::new(
            "dnsbl-reputation",
            CheckCategory::NetworkLeak,
            title,
            CheckState::Unknown,
            pick(
                lang,
                "DoH 黑名单查询全部超时或失败",
                "All DoH DNSBL lookups failed or timed out",
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    for hit in &summary.hits {
        let kind_lbl = match (hit.kind, lang) {
            (DnsblKind::Tor, Lang::Zh) => "Tor 出口",
            (DnsblKind::Tor, Lang::En) => "Tor Exit",
            (DnsblKind::Abuse, Lang::Zh) => {
                if hit.proxy_flagged {
                    "代理 / 滥用"
                } else {
                    "攻击 / 滥用"
                }
            }
            (DnsblKind::Abuse, Lang::En) => {
                if hit.proxy_flagged {
                    "Proxy / Abuse"
                } else {
                    "Attack / Abuse"
                }
            }
            (DnsblKind::Mail, Lang::Zh) => "邮件垃圾",
            (DnsblKind::Mail, Lang::En) => "Spam / Mail",
        };
        details.push(format!(
            "[HIT] {} ({kind_lbl}): {}",
            hit.name,
            hit.codes.join(", ")
        ));
    }

    if summary.hits.is_empty() {
        details.push(
            pick(
                lang,
                "所有公开 DNSBL 黑名单均返回未收录 (NXDOMAIN)",
                "Clean across all queried public DNSBL zones (NXDOMAIN)",
            )
            .to_owned(),
        );
        return CheckItem::new(
            "dnsbl-reputation",
            CheckCategory::NetworkLeak,
            title,
            CheckState::Ok,
            match lang {
                Lang::Zh => format!("0/{} 个公开 DNSBL 黑名单命中（洁净）", summary.checked),
                Lang::En => format!("Clean: 0/{} public DNSBL zones listed", summary.checked),
            },
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    let state = if summary.tor_hit() || summary.abuse_hits() > 0 || summary.hits.len() >= 2 {
        CheckState::Fail
    } else {
        CheckState::Warn
    };

    let summary_text = match lang {
        Lang::Zh => format!(
            "命中 {}/{} 个 DNSBL 黑名单（滥用 {} · 邮件 {} · Tor {}）",
            summary.hits.len(),
            summary.checked,
            summary.abuse_hits(),
            summary.mail_hits(),
            if summary.tor_hit() { "是" } else { "否" }
        ),
        Lang::En => format!(
            "Listed on {}/{} DNSBL zones (Abuse {} · Mail {} · Tor {})",
            summary.hits.len(),
            summary.checked,
            summary.abuse_hits(),
            summary.mail_hits(),
            if summary.tor_hit() { "Yes" } else { "No" }
        ),
    };

    CheckItem::new(
        "dnsbl-reputation",
        CheckCategory::NetworkLeak,
        title,
        state,
        summary_text,
    )
    .with_details(details)
    .with_suggestion(pick(
        lang,
        "当前出口 IP 已被公开黑名单收录，极易触发 AI 服务风控或验证码拦截，建议更换更干净的出口节点。",
        "This IP is listed on public blocklists, increasing captcha and risk-control triggers. Consider switching to a cleaner exit node.",
    ))
    .with_duration(duration_ms)
}

/// Concurrently check public DNSBL blocklists over DoH for the given IP.
pub async fn run_dnsbl_check(
    client: &Client,
    ip_str: Option<&str>,
    lang: Lang,
) -> (DnsblSummary, CheckItem) {
    let start = Instant::now();
    let Some(raw) = ip_str.map(str::trim).filter(|s| !s.is_empty()) else {
        let item = CheckItem::new(
            "dnsbl-reputation",
            CheckCategory::NetworkLeak,
            i18n::check_title("dnsbl-reputation", lang).unwrap_or("DNSBL Public Blocklists"),
            CheckState::Unknown,
            pick(lang, "无可用出口 IP，跳过黑名单查询", "No exit IP; skipped DNSBL scan"),
        );
        return (DnsblSummary::default(), item);
    };

    let Ok(parsed_ip) = raw.parse::<IpAddr>() else {
        let item = CheckItem::new(
            "dnsbl-reputation",
            CheckCategory::NetworkLeak,
            i18n::check_title("dnsbl-reputation", lang).unwrap_or("DNSBL Public Blocklists"),
            CheckState::Unknown,
            pick(lang, "IP 格式无效，跳过黑名单查询", "Invalid IP format; skipped DNSBL scan"),
        );
        return (DnsblSummary::default(), item);
    };

    let reversed = reverse_ip_for_dnsbl(parsed_ip);
    let is_v6 = parsed_ip.is_ipv6();

    let mut handles = Vec::new();
    for zone in PUBLIC_DNSBL_ZONES {
        if is_v6 && !zone.supports_ipv6 {
            continue;
        }
        let c = client.clone();
        let qname = format!("{reversed}.{}", zone.zone);
        let zone_copy = *zone;
        handles.push(tokio::spawn(async move {
            let res = doh_resolve_a(&c, &qname).await;
            (zone_copy, res)
        }));
    }

    let mut summary = DnsblSummary::default();
    for h in handles {
        if let Ok((zone, res)) = h.await {
            match res {
                Some(raw_answers) => {
                    summary.checked += 1;
                    let codes: Vec<String> = filter_valid_dnsbl_codes(&raw_answers)
                        .into_iter()
                        .filter(|c| !zone.ignore_codes.contains(&c.as_str()))
                        .collect();
                    if !codes.is_empty() {
                        let proxy_flagged = !zone.proxy_last_octets.is_empty()
                            && codes.iter().any(|c| {
                                c.rsplit('.')
                                    .next()
                                    .and_then(|o| o.parse::<u8>().ok())
                                    .is_some_and(|last| zone.proxy_last_octets.contains(&last))
                            });
                        summary.hits.push(DnsblHit {
                            name: zone.name.to_owned(),
                            kind: zone.kind,
                            codes,
                            proxy_flagged,
                        });
                    }
                }
                None => summary.errors += 1,
            }
        }
    }

    let item = evaluate_dnsbl_summary(raw, &summary, lang, start.elapsed().as_millis() as u64);
    (summary, item)
}

/// Resolve reverse DNS (PTR) hostname for an IPv4/IPv6 via DoH.
pub async fn lookup_ptr_doh(client: &Client, ip_str: &str) -> Option<String> {
    let parsed: IpAddr = ip_str.trim().parse().ok()?;
    let rev = reverse_ip_for_dnsbl(parsed);
    let qname = match parsed {
        IpAddr::V4(_) => format!("{rev}.in-addr.arpa"),
        IpAddr::V6(_) => format!("{rev}.ip6.arpa"),
    };
    let url = format!("https://cloudflare-dns.com/dns-query?name={qname}&type=PTR");
    let resp = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    v.get("Answer")?
        .as_array()?
        .iter()
        .find(|a| a.get("type").and_then(|t| t.as_u64()) == Some(12))
        .and_then(|a| a.get("data").and_then(|d| d.as_str()))
        .map(|s| s.trim_end_matches('.').to_owned())
        .filter(|s| !s.is_empty())
}
