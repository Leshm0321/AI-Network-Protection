use std::collections::HashSet;
use std::time::Instant;

use reqwest::Client;

use crate::model::{CheckCategory, CheckItem, CheckState, ExitGeoInfo};
use crate::net::{TraceInfo, normalize_ip, parse_cf_trace};

/// Neutral public Cloudflare trace endpoints for baseline exit-IP verification.
/// None of these carry user account credentials or touch AI login sessions.
pub const NEUTRAL_TRACE_TARGETS: &[(&str, &str)] = &[
    ("cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
    (
        "challenges",
        "https://challenges.cloudflare.com/cdn-cgi/trace",
    ),
    (
        "cloudflare-dns",
        "https://cloudflare-dns.com/cdn-cgi/trace",
    ),
];

#[derive(Debug, Clone)]
pub struct EndpointTrace {
    pub label: String,
    pub url: String,
    pub trace: Option<TraceInfo>,
    pub error: Option<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ExitCheckOutput {
    pub consistency_item: CheckItem,
    pub exclusive_item: Option<CheckItem>,
    pub primary_ip: Option<String>,
    pub primary_loc: Option<String>,
    pub network_ok: bool,
    pub geo: Option<ExitGeoInfo>,
}

pub async fn fetch_trace(client: &Client, label: &str, url: &str) -> EndpointTrace {
    let start = Instant::now();
    let res = client
        .get(url)
        .header("Cache-Control", "no-store")
        .send()
        .await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match res {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return EndpointTrace {
                    label: label.to_owned(),
                    url: url.to_owned(),
                    trace: None,
                    error: Some(format!("HTTP {}", status.as_u16())),
                    latency_ms,
                };
            }
            match resp.text().await {
                Ok(body) => match parse_cf_trace(&body) {
                    Some(info) => EndpointTrace {
                        label: label.to_owned(),
                        url: url.to_owned(),
                        trace: Some(info),
                        error: None,
                        latency_ms,
                    },
                    None => EndpointTrace {
                        label: label.to_owned(),
                        url: url.to_owned(),
                        trace: None,
                        error: Some("响应非有效 trace 文本".to_owned()),
                        latency_ms,
                    },
                },
                Err(e) => EndpointTrace {
                    label: label.to_owned(),
                    url: url.to_owned(),
                    trace: None,
                    error: Some(format!("读取响应失败: {e}")),
                    latency_ms,
                },
            }
        }
        Err(e) => EndpointTrace {
            label: label.to_owned(),
            url: url.to_owned(),
            trace: None,
            error: Some(compact_reqwest_err(&e)),
            latency_ms,
        },
    }
}

pub fn compact_reqwest_err(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "请求超时".to_owned()
    } else if e.is_connect() {
        format!("连接失败 ({e})")
    } else {
        e.to_string()
    }
}

/// Pure evaluator for exit IP consistency (unit-testable without network).
pub fn evaluate_exit_consistency(
    traces: &[EndpointTrace],
    expected_ip: Option<&str>,
    duration_ms: u64,
) -> (CheckItem, Option<String>, Option<String>) {
    let mut details = Vec::new();
    for t in traces {
        match &t.trace {
            Some(info) => {
                details.push(format!(
                    "{}: ip={} loc={} colo={} ({}ms)",
                    t.label,
                    info.ip,
                    info.loc.as_deref().unwrap_or("-"),
                    info.colo.as_deref().unwrap_or("-"),
                    t.latency_ms
                ));
            }
            None => {
                details.push(format!(
                    "{}: 失败 ({}) ({}ms)",
                    t.label,
                    t.error.as_deref().unwrap_or("无响应"),
                    t.latency_ms
                ));
            }
        }
    }

    let ok_traces: Vec<&EndpointTrace> = traces.iter().filter(|t| t.trace.is_some()).collect();
    if ok_traces.is_empty() {
        let item = CheckItem::new(
            "exit",
            CheckCategory::NetworkLeak,
            "出口 IP 一致性",
            CheckState::Unknown,
            "所有公共 Cloudflare 探测端点均无响应，无法判断出口 IP",
        )
        .with_details(details)
        .with_suggestion("请检查软路由/代理节点连通性，或通过 --proxy 指定本地代理端口。")
        .with_duration(duration_ms);
        return (item, None, None);
    }

    let distinct: HashSet<String> = ok_traces
        .iter()
        .filter_map(|t| t.trace.as_ref().and_then(|tr| normalize_ip(&tr.ip)))
        .collect();

    if distinct.len() > 1 {
        let desc = ok_traces
            .iter()
            .filter_map(|t| t.trace.as_ref().map(|tr| format!("{}={}", t.label, tr.ip)))
            .collect::<Vec<_>>()
            .join(", ");
        let item = CheckItem::new(
            "exit",
            CheckCategory::NetworkLeak,
            "出口 IP 一致性",
            CheckState::Fail,
            format!("出口 IP 发生跳变: {desc}"),
        )
        .with_details(details)
        .with_suggestion(
            "不同 Cloudflare 边缘端点看到不同出口 IP，属于典型 AI 风控高危特征。请将 cloudflare.com / cloudflare-dns.com 与 AI 域名固定在同一节点。",
        )
        .with_duration(duration_ms);
        return (item, None, None);
    }

    let primary_ip = ok_traces[0].trace.as_ref().map(|t| t.ip.clone());
    let primary_loc = ok_traces
        .iter()
        .find_map(|t| t.trace.as_ref().and_then(|tr| tr.loc.clone()));

    let ip_str = primary_ip.clone().unwrap_or_default();

    if let Some(exp_raw) = expected_ip.filter(|s| !s.trim().is_empty()) {
        if let (Some(exp_norm), Some(obs_norm)) = (normalize_ip(exp_raw), normalize_ip(&ip_str)) {
            if exp_norm != obs_norm {
                let item = CheckItem::new(
                    "exit",
                    CheckCategory::NetworkLeak,
                    "出口 IP 一致性",
                    CheckState::Fail,
                    format!("当前出口为 {ip_str}，但预期独享出口为 {exp_raw}"),
                )
                .with_details(details)
                .with_suggestion("流量可能已回落到备用/普通节点，请检查软路由或代理分流策略。")
                .with_duration(duration_ms);
                return (item, primary_ip, primary_loc);
            }
        }
    }

    let failed_labels: Vec<&str> = traces
        .iter()
        .filter(|t| t.trace.is_none())
        .map(|t| t.label.as_str())
        .collect();

    if !failed_labels.is_empty() {
        let item = CheckItem::new(
            "exit",
            CheckCategory::NetworkLeak,
            "出口 IP 一致性",
            CheckState::Warn,
            format!(
                "已响应端点一致 ({ip_str})，但 {} 未响应",
                failed_labels.join("、")
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
        return (item, primary_ip, primary_loc);
    }

    let loc_badge = primary_loc
        .as_deref()
        .map(|l| format!(" [{l}]"))
        .unwrap_or_default();
    let item = CheckItem::new(
        "exit",
        CheckCategory::NetworkLeak,
        "出口 IP 一致性",
        CheckState::Ok,
        format!("3/3 公共端点出口完全一致: {ip_str}{loc_badge}"),
    )
    .with_details(details)
    .with_duration(duration_ms);
    (item, primary_ip, primary_loc)
}

/// Evaluate exclusive IP check when user explicitly supplies `--expected-ip`.
pub fn evaluate_exclusive_ip(
    observed_ip: Option<&str>,
    expected_ip: Option<&str>,
) -> Option<CheckItem> {
    let expected = expected_ip?.trim();
    if expected.is_empty() {
        return None;
    }
    let Some(exp_norm) = normalize_ip(expected) else {
        return Some(CheckItem::new(
            "exclusive",
            CheckCategory::NetworkLeak,
            "独享 IP 核对",
            CheckState::Unknown,
            format!("预期值 `{expected}` 不是合法 IP 字面量，无法核对独享性"),
        ));
    };
    let Some(obs_raw) = observed_ip else {
        return Some(CheckItem::new(
            "exclusive",
            CheckCategory::NetworkLeak,
            "独享 IP 核对",
            CheckState::Unknown,
            "未能获取当前出口 IP，无法核对独享性",
        ));
    };
    let Some(obs_norm) = normalize_ip(obs_raw) else {
        return Some(CheckItem::new(
            "exclusive",
            CheckCategory::NetworkLeak,
            "独享 IP 核对",
            CheckState::Unknown,
            "观测到的出口 IP 格式无效",
        ));
    };
    if obs_norm != exp_norm {
        return Some(
            CheckItem::new(
                "exclusive",
                CheckCategory::NetworkLeak,
                "独享 IP 核对",
                CheckState::Fail,
                format!("出口是 {obs_raw}，与预期独享 IP {expected} 不一致"),
            )
            .with_suggestion("请确认软路由/代理节点未切换或发生故障回落。"),
        );
    }
    Some(CheckItem::new(
        "exclusive",
        CheckCategory::NetworkLeak,
        "独享 IP 核对",
        CheckState::Ok,
        format!("出口即预期独享 IP: {obs_raw}"),
    ))
}

/// Lookup geographic, ASN, ISP, and IANA timezone metadata for the current exit IP via `ipwho.is`.
pub async fn lookup_geo_info(client: &Client, ip: Option<&str>) -> Option<ExitGeoInfo> {
    let url = match ip {
        Some(addr) if !addr.is_empty() => format!("https://ipwho.is/{addr}"),
        _ => "https://ipwho.is/".to_owned(),
    };
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    if v.get("success").and_then(|b| b.as_bool()) != Some(true) {
        return None;
    }

    let resolved_ip = v.get("ip")?.as_str()?.to_owned();
    let country_code = v
        .get("country_code")
        .and_then(|s| s.as_str())
        .map(str::to_owned);
    let country = v.get("country").and_then(|s| s.as_str()).map(str::to_owned);
    let region = v.get("region").and_then(|s| s.as_str()).map(str::to_owned);
    let city = v.get("city").and_then(|s| s.as_str()).map(str::to_owned);

    let conn = v.get("connection");
    let asn = conn.and_then(|c| c.get("asn")).and_then(|a| a.as_u64());
    let org = conn
        .and_then(|c| c.get("org"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let isp = conn
        .and_then(|c| c.get("isp"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let tz = v.get("timezone");
    let timezone_iana = tz
        .and_then(|t| t.get("id"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let timezone_offset_secs = tz
        .and_then(|t| t.get("offset"))
        .and_then(|o| o.as_i64())
        .map(|o| o as i32);

    let ip_type_hint = classify_ip_type(org.as_deref(), isp.as_deref());

    Some(ExitGeoInfo {
        ip: resolved_ip,
        country_code,
        country,
        region,
        city,
        asn,
        org,
        isp,
        timezone_iana,
        timezone_offset_secs,
        ip_type_hint,
    })
}

/// Heuristic hint distinguishing hosting/datacenter vs residential ISP names.
pub fn classify_ip_type(org: Option<&str>, isp: Option<&str>) -> Option<String> {
    let combined = format!(
        "{} {}",
        org.unwrap_or_default().to_ascii_lowercase(),
        isp.unwrap_or_default().to_ascii_lowercase()
    );
    if combined.trim().is_empty() {
        return None;
    }
    let datacenter_keywords = [
        "amazon",
        "aws",
        "google cloud",
        "microsoft",
        "azure",
        "digitalocean",
        "linode",
        "akamai",
        "vultr",
        "hetzner",
        "ovh",
        "oracle",
        "alibaba",
        "tencent",
        "cloudflare",
        "datacamp",
        "m247",
        "choopa",
        "zenlayer",
        "racknerd",
        "bandwagon",
        "it7",
        "hosting",
        "cloud",
        "server",
        "vps",
        "datacenter",
    ];
    if datacenter_keywords.iter().any(|k| combined.contains(k)) {
        return Some("机房 / 云服务商 IP（Datacenter，风控风险偏高）".to_owned());
    }
    let residential_keywords = [
        "comcast",
        "xfinity",
        "verizon",
        "at&t",
        "charter",
        "spectrum",
        "cox",
        "t-mobile",
        "ntt",
        "kddi",
        "softbank",
        "singtel",
        "starhub",
        "bell",
        "rogers",
        "telus",
        "bt ",
        "virgin media",
        "deutsche telekom",
        "orange",
        "vodafone",
        "broadband",
        "fiber",
        "residential",
        "telecom",
        "communications",
    ];
    if residential_keywords.iter().any(|k| combined.contains(k)) {
        return Some("疑似宽带 / 住宅运营商 IP（ISP）".to_owned());
    }
    Some("常规网络运营商 IP（建议结合纯净度站复核）".to_owned())
}

/// Run the full exit consistency check (concurrent first round + serial retry on failures).
pub async fn run_exit_check(client: &Client, expected_ip: Option<&str>) -> ExitCheckOutput {
    let start = Instant::now();
    let futs: Vec<_> = NEUTRAL_TRACE_TARGETS
        .iter()
        .map(|&(label, url)| {
            let c = client.clone();
            async move { fetch_trace(&c, label, url).await }
        })
        .collect();
    let mut results = futures_join_all(futs).await;

    // Serial retry for any failed probe to avoid tunnel congestion false negatives
    for (idx, (label, url)) in NEUTRAL_TRACE_TARGETS.iter().enumerate() {
        if results[idx].trace.is_none() {
            results[idx] = fetch_trace(client, label, url).await;
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let (mut consistency_item, primary_ip, primary_loc) =
        evaluate_exit_consistency(&results, expected_ip, duration_ms);
    let network_ok = primary_ip.is_some();

    let geo = if let Some(ref ip) = primary_ip {
        lookup_geo_info(client, Some(ip)).await
    } else {
        None
    };

    if let Some(ref g) = geo {
        let mut extra = Vec::new();
        let location = [
            g.country.as_deref(),
            g.region.as_deref(),
            g.city.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" / ");
        if !location.is_empty() {
            extra.push(format!(
                "归属地: {location} ({})",
                g.country_code.as_deref().unwrap_or("-")
            ));
        }
        if let Some(asn) = g.asn {
            extra.push(format!(
                "ASN/ISP: AS{asn} · {}",
                g.isp
                    .as_deref()
                    .or(g.org.as_deref())
                    .unwrap_or("未知运营商")
            ));
        }
        if let Some(ref hint) = g.ip_type_hint {
            extra.push(format!("IP 类型参考: {hint}"));
        }
        consistency_item.details.extend(extra);
    }

    let exclusive_item = evaluate_exclusive_ip(primary_ip.as_deref(), expected_ip);

    ExitCheckOutput {
        consistency_item,
        exclusive_item,
        primary_ip,
        primary_loc,
        network_ok,
        geo,
    }
}

async fn futures_join_all<F, T>(futs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out
}
