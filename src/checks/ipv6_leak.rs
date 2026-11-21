use std::time::Instant;

use crate::model::{CheckCategory, CheckItem, CheckState};
use crate::net::system::Ipv6Snapshot;
use crate::net::{TraceInfo, build_direct_ipv6_client, parse_cf_trace};

#[derive(Debug, Clone)]
pub struct Ipv6EvalInput {
    pub snapshot: Ipv6Snapshot,
    pub direct_v6_trace: Option<TraceInfo>,
    pub ipv4_exit_country: Option<String>,
    pub has_local_tun: bool,
}

/// Pure evaluator for IPv6 leak detection across TUN, WiFi soft-router, and direct setups.
pub fn evaluate_ipv6_leak(input: &Ipv6EvalInput, duration_ms: u64) -> CheckItem {
    let mut details = Vec::new();
    let has_phys_v6 = !input.snapshot.physical_public.is_empty();

    if has_phys_v6 {
        for p in &input.snapshot.physical_public {
            details.push(format!("物理网卡公网 IPv6 ({}): {}", p.iface, p.addr));
        }
    } else {
        details.push("物理网卡未分配公网 IPv6 地址".to_owned());
    }

    if !input.snapshot.tun_adapters.is_empty() {
        details.push(format!(
            "虚拟 TUN 网卡: {} (IPv6 接管: {})",
            input.snapshot.tun_adapters.join(", "),
            if input.snapshot.tun_has_ipv6 { "是" } else { "否" }
        ));
    }

    if !input.snapshot.ipv6_default_routes.is_empty() {
        details.push(format!(
            "IPv6 默认路由 (::/0): {}",
            input.snapshot.ipv6_default_routes.join(", ")
        ));
    }

    if let Some(ref tr) = input.direct_v6_trace {
        details.push(format!(
            "实测 IPv6 直出出口: {} [loc={} colo={}]",
            tr.ip,
            tr.loc.as_deref().unwrap_or("-"),
            tr.colo.as_deref().unwrap_or("-")
        ));
    } else {
        details.push("实测 IPv6 外网直出: 不可达 / 已被阻断".to_owned());
    }

    // 1. Active direct IPv6 egress observed
    if let Some(ref tr) = input.direct_v6_trace {
        let v6_loc = tr.loc.as_deref();
        let v4_loc = input.ipv4_exit_country.as_deref();

        // Classic WiFi soft-router / local-proxy leak: IPv4 is overseas (US/JP/SG), IPv6 leaks CN ISP!
        if let (Some(l6), Some(l4)) = (v6_loc, v4_loc) {
            if !l6.eq_ignore_ascii_case(l4) {
                return CheckItem::new(
                    "ipv6",
                    CheckCategory::NetworkLeak,
                    "IPv6 防泄漏",
                    CheckState::Fail,
                    format!(
                        "检测到 IPv6 绕过代理泄漏！IPv6 出口为 {} [{}]，而 IPv4 出口地区为 [{}]",
                        tr.ip, l6, l4
                    ),
                )
                .with_details(details)
                .with_suggestion(
                    "软路由或双栈网络常见问题：请在软路由关闭 IPv6 代理绕行（或禁用局域网 IPv6 分发/在代理核心开启 IPv6 接管与阻断）。",
                )
                .with_duration(duration_ms);
            }
        }

        // If local TUN is active but TUN has no IPv6 or ::/0 points to physical NIC, still a leak!
        if input.has_local_tun && !input.snapshot.tun_has_ipv6 {
            return CheckItem::new(
                "ipv6",
                CheckCategory::NetworkLeak,
                "IPv6 防泄漏",
                CheckState::Fail,
                format!(
                    "本机 TUN 未配置 IPv6 地址，IPv6 流量 ({}) 正绕过隧道直出",
                    tr.ip
                ),
            )
            .with_details(details)
            .with_suggestion("请在 TUN 客户端中开启 IPv6 接管或禁用物理网卡 IPv6。")
            .with_duration(duration_ms);
        }

        // IPv6 works and matches IPv4 country (e.g. soft router properly proxies IPv6 or overseas network)
        if v6_loc.is_some_and(|l| l.eq_ignore_ascii_case("CN")) {
            return CheckItem::new(
                "ipv6",
                CheckCategory::NetworkLeak,
                "IPv6 防泄漏",
                CheckState::Fail,
                format!("IPv6 出口位于中国大陆 ({})，访问双栈 AI 站点时会直接暴露真实归属地", tr.ip),
            )
            .with_details(details)
            .with_suggestion("请关闭本机或软路由 IPv6，或在代理规则中拦截/接管 IPv6 流量。")
            .with_duration(duration_ms);
        }

        return CheckItem::new(
            "ipv6",
            CheckCategory::NetworkLeak,
            "IPv6 防泄漏",
            CheckState::Ok,
            format!(
                "IPv6 出口 ({}) 地区 [{}] 与 IPv4 一致，未检测到跨区泄漏",
                tr.ip,
                v6_loc.unwrap_or("未知")
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    // 2. No direct IPv6 egress reachable
    if !has_phys_v6 {
        return CheckItem::new(
            "ipv6",
            CheckCategory::NetworkLeak,
            "IPv6 防泄漏",
            CheckState::Ok,
            "本机没有公网 IPv6，不会从 IPv6 泄漏",
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    // Has physical public IPv6, check TUN routing if local TUN is running
    if input.has_local_tun {
        let route_via_tun = input.snapshot.ipv6_default_routes.iter().any(|r| {
            input
                .snapshot
                .tun_adapters
                .iter()
                .any(|t| t.eq_ignore_ascii_case(r))
        });
        if !input.snapshot.tun_has_ipv6
            || (!input.snapshot.ipv6_default_routes.is_empty() && !route_via_tun)
        {
            return CheckItem::new(
                "ipv6",
                CheckCategory::NetworkLeak,
                "IPv6 防泄漏",
                CheckState::Warn,
                "本机存在公网 IPv6 且 TUN 未接管 ::/0 路由（当前 IPv6 外网探测未通，但存在潜在绕过风险）",
            )
            .with_details(details)
            .with_suggestion("建议在代理内核开启 IPv6 接管或禁用物理网卡 IPv6。")
            .with_duration(duration_ms);
        }
    }

    CheckItem::new(
        "ipv6",
        CheckCategory::NetworkLeak,
        "IPv6 防泄漏",
        CheckState::Ok,
        "本机虽有公网 IPv6，但 IPv6 外网已被接管或阻断，未检测到泄漏",
    )
    .with_details(details)
    .with_duration(duration_ms)
}

async fn probe_direct_ipv6_egress() -> Option<TraceInfo> {
    let client = build_direct_ipv6_client(4_000).ok()?;
    // Cloudflare IPv6 literal endpoint (works without DNS AAAA resolution issues)
    for url in [
        "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ] {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    if let Some(tr) = parse_cf_trace(&text) {
                        if tr.ip.contains(':') {
                            return Some(tr);
                        }
                    }
                }
            }
        }
    }
    None
}

pub async fn run_ipv6_leak_check(
    snapshot: &Ipv6Snapshot,
    ipv4_exit_country: Option<&str>,
) -> CheckItem {
    let start = Instant::now();
    let direct_v6_trace = if !snapshot.physical_public.is_empty() || snapshot.tun_has_ipv6 {
        probe_direct_ipv6_egress().await
    } else {
        // Still attempt a fast direct IPv6 probe on non-Windows where snapshot may be partial
        #[cfg(not(target_os = "windows"))]
        {
            probe_direct_ipv6_egress().await
        }
        #[cfg(target_os = "windows")]
        {
            None
        }
    };

    let input = Ipv6EvalInput {
        snapshot: snapshot.clone(),
        direct_v6_trace,
        ipv4_exit_country: ipv4_exit_country.map(str::to_owned),
        has_local_tun: !snapshot.tun_adapters.is_empty(),
    };
    evaluate_ipv6_leak(&input, start.elapsed().as_millis() as u64)
}
