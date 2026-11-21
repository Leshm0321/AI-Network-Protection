use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rand::Rng;
use reqwest::Client;
use tokio::net::UdpSocket;

use crate::checks::exit::lookup_geo_info;
use crate::model::{CheckCategory, CheckItem, CheckState};
use crate::net::system::DnsServerEntry;

/// Known China public DNS servers (often indicate un-hijacked domestic DNS if seen on NIC or egress).
const CHINA_PUBLIC_DNS: &[&str] = &[
    "114.114.114.114",
    "114.114.115.115",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "182.254.116.116",
    "180.76.76.76",
    "1.2.4.8",
    "210.2.4.8",
];

pub fn is_tunnel_dns(addr: &str) -> bool {
    let a = addr.trim().to_ascii_lowercase();
    a == "198.18.0.2" || a == "fdfe:dcba:9876::2"
}

pub fn is_fake_ip(addr: &str) -> bool {
    let a = addr.trim().to_ascii_lowercase();
    if let Ok(IpAddr::V4(v4)) = a.parse::<IpAddr>() {
        // RFC 2544 / Mihomo fake-ip range 198.18.0.0/15
        let octets = v4.octets();
        return octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
    }
    a.starts_with("fdfe:dcba:9876:")
}

pub fn is_local_or_gateway_dns(addr: &str) -> bool {
    let a = addr.trim().to_ascii_lowercase();
    if a == "127.0.0.1" || a == "::1" || a.starts_with("fe80:") || a.starts_with("fc") || a.starts_with("fd") {
        return true;
    }
    if let Ok(IpAddr::V4(v4)) = a.parse::<IpAddr>() {
        let o = v4.octets();
        return o[0] == 10
            || (o[0] == 192 && o[1] == 168)
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 169 && o[1] == 254);
    }
    false
}

/// Build an RFC 1035 DNS query packet (qtype: 1 = A, 16 = TXT).
pub fn build_dns_query(tx_id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // Standard recursive query (RD=1)
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0x00); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    pkt
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswer {
    A(Ipv4Addr),
    Txt(Vec<String>),
}

/// Parse A / TXT answers from a raw DNS UDP response packet.
pub fn parse_dns_response(tx_id: u16, data: &[u8]) -> Option<Vec<DnsAnswer>> {
    if data.len() < 12 {
        return None;
    }
    let resp_id = u16::from_be_bytes([data[0], data[1]]);
    if resp_id != tx_id {
        return None;
    }
    let rcode = data[3] & 0x0f;
    if rcode != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        offset = offset.checked_add(4)?;
        if offset > data.len() {
            return None;
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(data, offset)?;
        if offset + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > data.len() {
            return None;
        }
        let rdata = &data[offset..offset + rdlen];
        match rtype {
            1 if rdlen == 4 => {
                answers.push(DnsAnswer::A(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            16 => {
                let mut pos = 0usize;
                let mut chunks = Vec::new();
                while pos < rdata.len() {
                    let len = rdata[pos] as usize;
                    pos += 1;
                    if pos + len > rdata.len() {
                        break;
                    }
                    chunks.push(String::from_utf8_lossy(&rdata[pos..pos + len]).into_owned());
                    pos += len;
                }
                if !chunks.is_empty() {
                    answers.push(DnsAnswer::Txt(chunks));
                }
            }
            _ => {}
        }
        offset += rdlen;
    }

    Some(answers)
}

fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if offset >= data.len() || jumps > 128 {
            return None;
        }
        let len = data[offset];
        if len == 0 {
            return Some(offset + 1);
        }
        if (len & 0xc0) == 0xc0 {
            return offset.checked_add(2).filter(|&end| end <= data.len());
        }
        offset = offset.checked_add(1 + len as usize)?;
        jumps += 1;
    }
}

async fn udp_dns_query(server: SocketAddr, domain: &str, qtype: u16, timeout_ms: u64) -> Option<Vec<DnsAnswer>> {
    let bind_addr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind_addr).await.ok()?;
    let tx_id: u16 = rand::random();
    let pkt = build_dns_query(tx_id, domain, qtype);
    sock.send_to(&pkt, server).await.ok()?;

    let mut buf = [0u8; 1500];
    let recv = tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_dns_response(tx_id, &buf[..recv.0])
}

#[derive(Debug, Clone, Default)]
pub struct DnsProbeFacts {
    pub nic_entries: Vec<DnsServerEntry>,
    pub system_claude_ips: Vec<String>,
    pub direct_114_claude_ips: Vec<String>,
    pub egress_resolver_ip: Option<String>,
    pub egress_resolver_country: Option<String>,
    pub egress_resolver_isp: Option<String>,
    pub exit_country: Option<String>,
    pub expected_country: Option<String>,
    /// EDNS resolver IP reported by `edns.ip-api.com`.
    pub edns_resolver_ip: Option<String>,
    /// EDNS resolver geo string (e.g. "United States - Cloudflare").
    pub edns_resolver_geo: Option<String>,
    /// Exposed EDNS Client Subnet (ECS) IP/prefix if forwarded to authoritative servers.
    pub ecs_subnet: Option<String>,
    /// Geo description of the exposed ECS subnet.
    pub ecs_geo: Option<String>,
    /// Domestic site observed IP (used to distinguish Wi-Fi soft-router split routing from leaks).
    pub domestic_exit_ip: Option<String>,
}

fn geo_text_is_cn(geo: Option<&str>) -> bool {
    let Some(g) = geo else {
        return false;
    };
    let lower = g.to_ascii_lowercase();
    lower.starts_with("china")
        || lower.starts_with("cn ")
        || lower.starts_with("cn-")
        || lower.contains(" - china")
        || lower.contains("chinatelecom")
        || lower.contains("china unicom")
        || lower.contains("china mobile")
}

/// Pure evaluator for universal DNS leak detection (handles TUN, WiFi soft-router, and direct setups).
pub fn evaluate_dns_leak(facts: &DnsProbeFacts, duration_ms: u64) -> CheckItem {
    let mut details = Vec::new();
    let mut public_nic_dns = Vec::new();
    let mut local_gateway_dns = Vec::new();
    let mut has_tunnel_dns = false;

    for e in &facts.nic_entries {
        if !e.servers.is_empty() {
            details.push(format!(
                "网卡 DNS ({} IPv{}): {}",
                e.iface,
                e.family,
                e.servers.join(", ")
            ));
        }
        for s in &e.servers {
            if is_tunnel_dns(s) {
                has_tunnel_dns = true;
            } else if is_local_or_gateway_dns(s) {
                local_gateway_dns.push(format!("{s} ({})", e.iface));
            } else {
                public_nic_dns.push(format!("{s} ({} IPv{})", e.iface, e.family));
            }
        }
    }

    let system_fake_ip = facts.system_claude_ips.iter().any(|ip| is_fake_ip(ip));
    let hijack_114_fake_ip = facts.direct_114_claude_ips.iter().any(|ip| is_fake_ip(ip));

    if !facts.system_claude_ips.is_empty() {
        details.push(format!(
            "系统解析 claude.ai: {}{}",
            facts.system_claude_ips.join(", "),
            if system_fake_ip { " (Fake-IP 透明接管)" } else { "" }
        ));
    }

    if !facts.direct_114_claude_ips.is_empty() {
        details.push(format!(
            "直查公网 DNS (114.114.114.114) claude.ai: {}{}",
            facts.direct_114_claude_ips.join(", "),
            if hijack_114_fake_ip {
                " (已被 53 端口透明劫持为 Fake-IP)"
            } else {
                " (未劫持，53 端口可直出公网 DNS)"
            }
        ));
    } else {
        details.push("直查公网 DNS (114.114.114.114:53): 无响应或被防火墙/路由拦截".to_owned());
    }

    if let Some(ref res_ip) = facts.egress_resolver_ip {
        details.push(format!(
            "权威 DNS 解析出口 (whoami.ds.akahelp.net): {} [{}{}]",
            res_ip,
            facts.egress_resolver_country.as_deref().unwrap_or("未知地区"),
            facts
                .egress_resolver_isp
                .as_deref()
                .map(|i| format!(" · {i}"))
                .unwrap_or_default()
        ));
    }

    if let Some(ref edns_ip) = facts.edns_resolver_ip {
        details.push(format!(
            "EDNS 探测解析器 (edns.ip-api.com): {} ({})",
            edns_ip,
            facts.edns_resolver_geo.as_deref().unwrap_or("-")
        ));
    }
    if let Some(ref ecs_ip) = facts.ecs_subnet {
        details.push(format!(
            "EDNS 客户端子网 (ECS) 透传: {} ({})",
            ecs_ip,
            facts.ecs_geo.as_deref().unwrap_or("-")
        ));
    } else if facts.edns_resolver_ip.is_some() {
        details.push("EDNS 客户端子网 (ECS): 未透传客户端真实网段（良好）".to_owned());
    }
    if let Some(ref dom_ip) = facts.domestic_exit_ip {
        details.push(format!(
            "国内站点观测出口 (myip.ipip.net): {dom_ip}（分流规则检测参考）"
        ));
    }

    let resolver_is_cn = facts
        .egress_resolver_country
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case("CN"));
    let exit_is_overseas = facts
        .exit_country
        .as_deref()
        .is_some_and(|c| !c.eq_ignore_ascii_case("CN"));
    let ecs_leaks_cn = facts.ecs_subnet.is_some()
        && exit_is_overseas
        && geo_text_is_cn(facts.ecs_geo.as_deref());

    // Priority check: EDNS Client Subnet explicitly leaking domestic/CN subnet while exit is overseas
    if ecs_leaks_cn {
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 与 EDNS 子网泄漏检测",
            CheckState::Warn,
            format!(
                "检测到 EDNS 客户端子网 (ECS) 暴露中国大陆网段 ({} · {})，权威 DNS 可直接识别真实地区",
                facts.ecs_subnet.as_deref().unwrap_or("-"),
                facts.ecs_geo.as_deref().unwrap_or("CN")
            ),
        )
        .with_details(details)
        .with_suggestion("请在软路由 / Mihomo / AdGuardHome / MosDNS 中关闭对海外域名的 EDNS Client Subnet (ECS) 透传，或改用不透传 ECS 的加密 DoH/DoT（如 Cloudflare 1.1.1.1）。")
        .with_duration(duration_ms);
    }

    // Case 1: Tunnel DNS or Fake-IP active on system DNS -> AI queries are captured
    if has_tunnel_dns && public_nic_dns.is_empty() {
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 泄漏检测",
            CheckState::Ok,
            "物理网卡 DNS 已全部接管至隧道地址 (198.18.0.2 / fdfe:dcba:9876::2)",
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    if hijack_114_fake_ip {
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 泄漏检测",
            CheckState::Ok,
            "检测到 53 端口透明 DNS 劫持生效（返回 Fake-IP），DNS 查询不会明文泄露给运营商",
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    // Case 2: Soft-router LAN gateway DNS + Fake-IP on AI domain
    if system_fake_ip {
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 泄漏检测",
            CheckState::Ok,
            "AI 域名通过软路由/内核 Fake-IP 接管解析（未走运营商明文解析）",
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    // Case 3: Authoritative DNS egress is in China while HTTP exit is overseas
    if resolver_is_cn && exit_is_overseas {
        let is_domestic_public = facts
            .egress_resolver_ip
            .as_deref()
            .is_some_and(|ip| CHINA_PUBLIC_DNS.contains(&ip));
        let msg = if is_domestic_public {
            format!(
                "默认 DNS 解析出口位于中国大陆（{}），若 AI 域名未单独走海外 DoH/Fake-IP 则存在 DNS 泄漏",
                facts.egress_resolver_ip.as_deref().unwrap_or("-")
            )
        } else {
            format!(
                "检测到 DNS 出口归属中国大陆（{} · {}），与海外出口 {} 不一致，存在 DNS 泄漏风险",
                facts.egress_resolver_ip.as_deref().unwrap_or("-"),
                facts.egress_resolver_isp.as_deref().unwrap_or("未知运营商"),
                facts.exit_country.as_deref().unwrap_or("-")
            )
        };
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 泄漏检测",
            if public_nic_dns.is_empty() {
                CheckState::Warn
            } else {
                CheckState::Fail
            },
            msg,
        )
        .with_details(details)
        .with_suggestion("软路由用户请确保 OpenClash/Mihomo/MosDNS 已对海外及 AI 域名启用 Fake-IP 或走代理链路的加密 DoH，并拦截局域网直出 53 端口。")
        .with_duration(duration_ms);
    }

    // Case 4: NIC explicitly configured with public ISP/China DNS and not hijacked
    if !public_nic_dns.is_empty() && !facts.direct_114_claude_ips.is_empty() {
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 泄漏检测",
            CheckState::Fail,
            format!(
                "网卡配置了公网 DNS ({}) 且未检测到 53 端口劫持，可能直接向运营商泄露解析",
                public_nic_dns.join("、")
            ),
        )
        .with_details(details)
        .with_suggestion("请将网卡 DNS 指向软路由网关或开启代理 TUN / 53 端口 DNS 劫持。")
        .with_duration(duration_ms);
    }

    // Case 5: Authoritative DNS egress is overseas and matches (or compatible with) exit
    if let (Some(res_ip), Some(res_cc)) = (
        facts.egress_resolver_ip.as_deref(),
        facts.egress_resolver_country.as_deref(),
    ) {
        if !res_cc.eq_ignore_ascii_case("CN") {
            let expected_mismatch = facts
                .expected_country
                .as_deref()
                .is_some_and(|exp| !exp.eq_ignore_ascii_case(res_cc));
            if expected_mismatch {
                return CheckItem::new(
                    "dns",
                    CheckCategory::NetworkLeak,
                    "DNS 泄漏检测",
                    CheckState::Warn,
                    format!(
                        "海外 DNS 出口位于 {res_cc} ({res_ip})，与预期国家 {} 不一致",
                        facts.expected_country.as_deref().unwrap_or("-")
                    ),
                )
                .with_details(details)
                .with_duration(duration_ms);
            }
            return CheckItem::new(
                "dns",
                CheckCategory::NetworkLeak,
                "DNS 泄漏检测",
                CheckState::Ok,
                format!("DNS 解析出口位于海外 {res_cc} ({res_ip})，未泄露本地运营商 DNS"),
            )
            .with_details(details)
            .with_duration(duration_ms);
        }
    }

    if !local_gateway_dns.is_empty() {
        return CheckItem::new(
            "dns",
            CheckCategory::NetworkLeak,
            "DNS 泄漏检测",
            CheckState::Unknown,
            format!(
                "网卡 DNS 指向局域网网关 ({})，但未能获取权威 DNS 出口，建议在浏览器复核 ipleak.net",
                local_gateway_dns.join("、")
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    CheckItem::new(
        "dns",
        CheckCategory::NetworkLeak,
        "DNS 泄漏检测",
        CheckState::Unknown,
        "未能读取网卡 DNS 且权威解析探测无结果，无法判断 DNS 泄漏",
    )
    .with_details(details)
    .with_duration(duration_ms)
}

pub async fn run_dns_leak_check(
    client: &Client,
    nic_entries: &[DnsServerEntry],
    exit_country: Option<&str>,
    expected_country: Option<&str>,
) -> CheckItem {
    let start = Instant::now();

    // Pick first available IPv4 system DNS server (e.g. soft router 192.168.x.1 or TUN 198.18.0.2)
    let primary_sys_dns: Option<SocketAddr> = nic_entries
        .iter()
        .filter(|e| e.family == 4)
        .flat_map(|e| e.servers.iter())
        .find_map(|s| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)));

    // 1. Query system DNS for claude.ai (detects Fake-IP on soft router / TUN)
    let sys_claude_fut = async {
        if let Some(srv) = primary_sys_dns {
            if let Some(ans) = udp_dns_query(srv, "claude.ai", 1, 2500).await {
                let ips: Vec<String> = ans
                    .into_iter()
                    .filter_map(|a| match a {
                        DnsAnswer::A(ip) => Some(ip.to_string()),
                        _ => None,
                    })
                    .collect();
                if !ips.is_empty() {
                    return ips;
                }
            }
        }
        // Fallback: OS resolver
        tokio::net::lookup_host(("claude.ai", 443))
            .await
            .map(|addrs| {
                addrs
                    .map(|a| a.ip().to_string())
                    .take(4)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    // 2. Direct UDP query to 114.114.114.114:53 (Layer 2 DNS hijack / interception probe)
    let direct_114_fut = async {
        let srv = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)), 53);
        udp_dns_query(srv, "claude.ai", 1, 2500)
            .await
            .map(|ans| {
                ans.into_iter()
                    .filter_map(|a| match a {
                        DnsAnswer::A(ip) => Some(ip.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    // 3. Authoritative DNS egress resolver identity via whoami.ds.akahelp.net TXT
    let egress_dns_fut = async {
        let target_srv = primary_sys_dns?;
        if let Some(ans) = udp_dns_query(target_srv, "whoami.ds.akahelp.net", 16, 4000).await {
            for a in ans {
                if let DnsAnswer::Txt(chunks) = a {
                    // Akamai returns ["ns", "1.2.3.4"] or ["ip", "1.2.3.4"]
                    if chunks.len() >= 2 && chunks[0] == "ns" && chunks[1].parse::<IpAddr>().is_ok()
                    {
                        return Some(chunks[1].clone());
                    }
                    if let Some(first) = chunks.first() {
                        if let Some(ip) = first.strip_prefix("ns ") {
                            if ip.trim().parse::<IpAddr>().is_ok() {
                                return Some(ip.trim().to_owned());
                            }
                        }
                    }
                }
            }
        }
        // Fallback: o-o.myaddr.l.google.com TXT
        if let Some(ans) = udp_dns_query(target_srv, "o-o.myaddr.l.google.com", 16, 3500).await {
            for a in ans {
                if let DnsAnswer::Txt(chunks) = a {
                    for chunk in chunks {
                        let c = chunk.trim().trim_matches('"');
                        if c.parse::<IpAddr>().is_ok() {
                            return Some(c.to_owned());
                        }
                    }
                }
            }
        }
        None
    };

    // 4. EDNS Client Subnet (ECS) probe via random subdomain on edns.ip-api.com
    let edns_fut = async {
        let rand_hex: String = {
            let mut rng = rand::thread_rng();
            (0..16)
                .map(|_| format!("{:02x}", rng.r#gen::<u8>()))
                .collect()
        };
        let url = format!("https://{rand_hex}.edns.ip-api.com/json");
        let resp = client
            .get(&url)
            .timeout(Duration::from_secs(4))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let dns_ip = v
            .get("dns")
            .and_then(|d| d.get("ip"))
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        let dns_geo = v
            .get("dns")
            .and_then(|d| d.get("geo"))
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        let ecs_ip = v
            .get("edns")
            .and_then(|e| e.get("ip"))
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        let ecs_geo = v
            .get("edns")
            .and_then(|e| e.get("geo"))
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        Some((dns_ip, dns_geo, ecs_ip, ecs_geo))
    };

    // 5. Domestic site exit check (myip.ipip.net) to detect split routing
    let domestic_fut = async {
        let resp = client
            .get("https://myip.ipip.net/json")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        v.get("data")
            .and_then(|d| d.get("ip"))
            .and_then(|s| s.as_str())
            .map(str::to_owned)
    };

    let (system_claude_ips, direct_114_claude_ips, egress_resolver_ip, edns_opt, domestic_exit_ip) =
        tokio::join!(
            sys_claude_fut,
            direct_114_fut,
            egress_dns_fut,
            edns_fut,
            domestic_fut
        );

    let (edns_resolver_ip, edns_resolver_geo, ecs_subnet, ecs_geo) = match edns_opt {
        Some((di, dg, ei, eg)) => (di, dg, ei, eg),
        None => (None, None, None, None),
    };

    let (egress_resolver_country, egress_resolver_isp) = if let Some(ref ip) = egress_resolver_ip {
        if let Some(geo) = lookup_geo_info(client, Some(ip)).await {
            (geo.country_code, geo.isp.or(geo.org))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let facts = DnsProbeFacts {
        nic_entries: nic_entries.to_vec(),
        system_claude_ips,
        direct_114_claude_ips,
        egress_resolver_ip,
        egress_resolver_country,
        egress_resolver_isp,
        exit_country: exit_country.map(str::to_owned),
        expected_country: expected_country.map(str::to_owned),
        edns_resolver_ip,
        edns_resolver_geo,
        ecs_subnet,
        ecs_geo,
        domestic_exit_ip,
    };

    evaluate_dns_leak(&facts, start.elapsed().as_millis() as u64)
}
