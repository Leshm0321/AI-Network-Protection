use std::time::Instant;

use reqwest::Client;

use crate::model::{AiServiceProbe, CheckCategory, CheckItem, CheckState};
use crate::net::{normalize_ip, parse_cf_trace};

/// Run tiered unauthenticated probes for OpenAI, Anthropic, and Google AI services.
/// Never sends cookies, session tokens, or billing API requests.
pub async fn run_ai_services_checks(
    client: &Client,
    no_redirect_client: &Client,
    baseline_exit_ip: Option<&str>,
    neutral_only: bool,
) -> (Vec<CheckItem>, Vec<AiServiceProbe>) {
    if neutral_only {
        let item = CheckItem::new(
            "ai-services",
            CheckCategory::AiServices,
            "主流 AI 服务探测 (OpenAI / Anthropic / Google)",
            CheckState::Unknown,
            "已启用保守模式 (--neutral-only)，跳过向 AI 主站发探测请求",
        );
        return (vec![item], Vec::new());
    }

    let (openai_res, anthropic_res, google_res) = tokio::join!(
        check_openai(client, baseline_exit_ip),
        check_anthropic(client, baseline_exit_ip),
        check_google_ai(client, no_redirect_client),
    );

    let mut items = Vec::new();
    let mut probes = Vec::new();

    items.push(openai_res.0);
    probes.extend(openai_res.1);

    items.push(anthropic_res.0);
    probes.extend(anthropic_res.1);

    items.push(google_res.0);
    probes.extend(google_res.1);

    (items, probes)
}

async fn probe_cf_domain(client: &Client, provider: &str, url: &str) -> AiServiceProbe {
    let start = Instant::now();
    let res = client
        .get(url)
        .header("Cache-Control", "no-store")
        .send()
        .await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match res {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            if status >= 200 && status < 300 {
                if let Some(tr) = parse_cf_trace(&text) {
                    return AiServiceProbe {
                        provider: provider.to_owned(),
                        endpoint: url.to_owned(),
                        reachable: true,
                        status_code: Some(status),
                        observed_ip: Some(tr.ip),
                        cf_loc: tr.loc,
                        cf_colo: tr.colo,
                        latency_ms,
                        note: "Cloudflare 边缘 trace 正常".to_owned(),
                    };
                }
            }
            AiServiceProbe {
                provider: provider.to_owned(),
                endpoint: url.to_owned(),
                reachable: status < 500,
                status_code: Some(status),
                observed_ip: None,
                cf_loc: None,
                cf_colo: None,
                latency_ms,
                note: format!("返回 HTTP {status}（未返回 trace）"),
            }
        }
        Err(e) => AiServiceProbe {
            provider: provider.to_owned(),
            endpoint: url.to_owned(),
            reachable: false,
            status_code: None,
            observed_ip: None,
            cf_loc: None,
            cf_colo: None,
            latency_ms,
            note: if e.is_timeout() {
                "超时".to_owned()
            } else {
                format!("不可达: {e}")
            },
        },
    }
}

async fn check_openai(
    client: &Client,
    baseline_exit_ip: Option<&str>,
) -> (CheckItem, Vec<AiServiceProbe>) {
    let start = Instant::now();
    let trace_probe = probe_cf_domain(client, "OpenAI", "https://chatgpt.com/cdn-cgi/trace").await;

    let api_start = Instant::now();
    let api_probe = match client.get("https://api.openai.com/v1/models").send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let body_lower = body.to_ascii_lowercase();
            let geo_blocked = body_lower.contains("unsupported_country")
                || body_lower.contains("country, region, or territory not supported");
            let note = if geo_blocked {
                "区域受限 (unsupported_country_region_territory)".to_owned()
            } else if status == 401 {
                "API 端点正常可达 (无 Key 返回 401 属预期)".to_owned()
            } else if status == 403 {
                "返回 403（可能触发 Cloudflare 盾或区域限制）".to_owned()
            } else {
                format!("HTTP {status}")
            };
            AiServiceProbe {
                provider: "OpenAI".to_owned(),
                endpoint: "https://api.openai.com/v1/models".to_owned(),
                reachable: !geo_blocked && (status == 401 || status == 200),
                status_code: Some(status),
                observed_ip: None,
                cf_loc: None,
                cf_colo: None,
                latency_ms: api_start.elapsed().as_millis() as u64,
                note,
            }
        }
        Err(e) => AiServiceProbe {
            provider: "OpenAI".to_owned(),
            endpoint: "https://api.openai.com/v1/models".to_owned(),
            reachable: false,
            status_code: None,
            observed_ip: None,
            cf_loc: None,
            cf_colo: None,
            latency_ms: api_start.elapsed().as_millis() as u64,
            note: format!("不可达: {e}"),
        },
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let item = evaluate_cf_service_check(
        "ai-openai",
        "OpenAI / ChatGPT",
        &trace_probe,
        &api_probe,
        baseline_exit_ip,
        duration_ms,
    );

    (item, vec![trace_probe, api_probe])
}

async fn check_anthropic(
    client: &Client,
    baseline_exit_ip: Option<&str>,
) -> (CheckItem, Vec<AiServiceProbe>) {
    let start = Instant::now();
    let trace_probe = probe_cf_domain(client, "Anthropic", "https://claude.ai/cdn-cgi/trace").await;

    let api_start = Instant::now();
    let api_probe = match client
        .get("https://api.anthropic.com/v1/models")
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let lower = body.to_ascii_lowercase();
            let geo_blocked = lower.contains("not available in your")
                || lower.contains("region") && status == 403;
            let note = if geo_blocked {
                "区域受限（Anthropic 不支持当前出口地区）".to_owned()
            } else if status == 401 || status == 400 || status == 405 {
                format!("API 端点正常可达 (无 Key 返回 HTTP {status} 属预期)")
            } else if status == 403 {
                "返回 403（可能触发风控盾或地区限制）".to_owned()
            } else {
                format!("HTTP {status}")
            };
            AiServiceProbe {
                provider: "Anthropic".to_owned(),
                endpoint: "https://api.anthropic.com/v1/models".to_owned(),
                reachable: !geo_blocked && matches!(status, 200 | 400 | 401 | 405),
                status_code: Some(status),
                observed_ip: None,
                cf_loc: None,
                cf_colo: None,
                latency_ms: api_start.elapsed().as_millis() as u64,
                note,
            }
        }
        Err(e) => AiServiceProbe {
            provider: "Anthropic".to_owned(),
            endpoint: "https://api.anthropic.com/v1/models".to_owned(),
            reachable: false,
            status_code: None,
            observed_ip: None,
            cf_loc: None,
            cf_colo: None,
            latency_ms: api_start.elapsed().as_millis() as u64,
            note: format!("不可达: {e}"),
        },
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let item = evaluate_cf_service_check(
        "ai-anthropic",
        "Anthropic / Claude",
        &trace_probe,
        &api_probe,
        baseline_exit_ip,
        duration_ms,
    );

    (item, vec![trace_probe, api_probe])
}

async fn check_google_ai(
    client: &Client,
    no_redirect_client: &Client,
) -> (CheckItem, Vec<AiServiceProbe>) {
    let start = Instant::now();

    let (gemini_probe, studio_probe, api_probe) = tokio::join!(
        probe_google_web(no_redirect_client, "https://gemini.google.com/", "Gemini Web"),
        probe_google_web(no_redirect_client, "https://aistudio.google.com/", "AI Studio"),
        probe_google_api(client, "https://generativelanguage.googleapis.com/v1beta/models"),
    );

    let duration_ms = start.elapsed().as_millis() as u64;
    let details = vec![
        format!(
            "Gemini Web: {} ({}ms) - {}",
            gemini_probe
                .status_code
                .map(|c| format!("HTTP {c}"))
                .unwrap_or_else(|| "无响应".to_owned()),
            gemini_probe.latency_ms,
            gemini_probe.note
        ),
        format!(
            "AI Studio: {} ({}ms) - {}",
            studio_probe
                .status_code
                .map(|c| format!("HTTP {c}"))
                .unwrap_or_else(|| "无响应".to_owned()),
            studio_probe.latency_ms,
            studio_probe.note
        ),
        format!(
            "Gemini API: {} ({}ms) - {}",
            api_probe
                .status_code
                .map(|c| format!("HTTP {c}"))
                .unwrap_or_else(|| "无响应".to_owned()),
            api_probe.latency_ms,
            api_probe.note
        ),
    ];

    let all_probes = vec![gemini_probe, studio_probe, api_probe];
    let any_geo_blocked = all_probes.iter().any(|p| p.note.contains("区域受限"));
    let reachable_count = all_probes.iter().filter(|p| p.reachable).count();

    let item = if any_geo_blocked {
        CheckItem::new(
            "ai-google",
            CheckCategory::AiServices,
            "Google Gemini / AI Studio",
            CheckState::Fail,
            "检测到 Google AI 区域受限，当前出口地区不支持 Gemini / AI Studio",
        )
        .with_details(details)
        .with_suggestion("请将 gemini.google.com / aistudio.google.com / generativelanguage.googleapis.com 路由到支持的海外地区（如美国、日本、新加坡）。")
        .with_duration(duration_ms)
    } else if reachable_count == all_probes.len() {
        CheckItem::new(
            "ai-google",
            CheckCategory::AiServices,
            "Google Gemini / AI Studio",
            CheckState::Ok,
            "Gemini Web、AI Studio 与 API 端点均正常可达，未触发地区拦截",
        )
        .with_details(details)
        .with_duration(duration_ms)
    } else if reachable_count > 0 {
        CheckItem::new(
            "ai-google",
            CheckCategory::AiServices,
            "Google Gemini / AI Studio",
            CheckState::Warn,
            format!("部分 Google AI 端点可达 ({reachable_count}/3)"),
        )
        .with_details(details)
        .with_duration(duration_ms)
    } else {
        CheckItem::new(
            "ai-google",
            CheckCategory::AiServices,
            "Google Gemini / AI Studio",
            CheckState::Fail,
            "Google AI 全部端点不可达",
        )
        .with_details(details)
        .with_suggestion("请检查软路由或代理规则是否覆盖了 gemini.google.com 与 googleapis.com。")
        .with_duration(duration_ms)
    };

    (item, all_probes)
}

async fn probe_google_web(client: &Client, url: &str, label: &str) -> AiServiceProbe {
    let start = Instant::now();
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    let mut res = client.get(url).header("User-Agent", ua).send().await;
    if res.is_err() {
        res = client.get(url).header("User-Agent", ua).send().await;
    }
    let latency_ms = start.elapsed().as_millis() as u64;

    match res {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let loc_lower = loc.to_ascii_lowercase();
            let geo_blocked = loc_lower.contains("unsupported")
                || loc_lower.contains("faq")
                || loc_lower.contains("not-available")
                || loc_lower.contains("unavailable");
            let note = if geo_blocked {
                format!("区域受限（重定向至 {loc}）")
            } else if (200..400).contains(&status) {
                if loc.is_empty() {
                    format!("{label} 可达")
                } else {
                    format!("{label} 可达（跳转认证/入口）")
                }
            } else {
                format!("返回 HTTP {status}")
            };
            AiServiceProbe {
                provider: "Google".to_owned(),
                endpoint: url.to_owned(),
                reachable: !geo_blocked && (200..400).contains(&status),
                status_code: Some(status),
                observed_ip: None,
                cf_loc: None,
                cf_colo: None,
                latency_ms,
                note,
            }
        }
        Err(e) => AiServiceProbe {
            provider: "Google".to_owned(),
            endpoint: url.to_owned(),
            reachable: false,
            status_code: None,
            observed_ip: None,
            cf_loc: None,
            cf_colo: None,
            latency_ms,
            note: format!("不可达: {e}"),
        },
    }
}

async fn probe_google_api(client: &Client, url: &str) -> AiServiceProbe {
    let start = Instant::now();
    let res = client.get(url).send().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match res {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let lower = body.to_ascii_lowercase();
            let geo_blocked = lower.contains("user location is not supported")
                || lower.contains("not available in your country");
            let note = if geo_blocked {
                "区域受限 (User location is not supported)".to_owned()
            } else if status == 400 || status == 403 || status == 401 {
                format!("API 端点正常可达 (无 Key 返回 HTTP {status} 属预期)")
            } else {
                format!("HTTP {status}")
            };
            AiServiceProbe {
                provider: "Google".to_owned(),
                endpoint: url.to_owned(),
                reachable: !geo_blocked && matches!(status, 200 | 400 | 401 | 403),
                status_code: Some(status),
                observed_ip: None,
                cf_loc: None,
                cf_colo: None,
                latency_ms,
                note,
            }
        }
        Err(e) => AiServiceProbe {
            provider: "Google".to_owned(),
            endpoint: url.to_owned(),
            reachable: false,
            status_code: None,
            observed_ip: None,
            cf_loc: None,
            cf_colo: None,
            latency_ms,
            note: format!("不可达: {e}"),
        },
    }
}

/// Pure evaluator comparing an AI service's Cloudflare trace IP against the baseline exit IP.
pub fn evaluate_cf_service_check(
    key: &str,
    title: &str,
    trace_probe: &AiServiceProbe,
    api_probe: &AiServiceProbe,
    baseline_exit_ip: Option<&str>,
    duration_ms: u64,
) -> CheckItem {
    let mut details = vec![
        format!(
            "主站 Trace ({}): ip={} loc={} colo={} ({}ms) - {}",
            trace_probe.endpoint,
            trace_probe.observed_ip.as_deref().unwrap_or("-"),
            trace_probe.cf_loc.as_deref().unwrap_or("-"),
            trace_probe.cf_colo.as_deref().unwrap_or("-"),
            trace_probe.latency_ms,
            trace_probe.note
        ),
        format!(
            "API 端点 ({}): {} ({}ms) - {}",
            api_probe.endpoint,
            api_probe
                .status_code
                .map(|c| format!("HTTP {c}"))
                .unwrap_or_else(|| "无响应".to_owned()),
            api_probe.latency_ms,
            api_probe.note
        ),
    ];

    if api_probe.note.contains("区域受限") {
        return CheckItem::new(
            key,
            CheckCategory::AiServices,
            title,
            CheckState::Fail,
            format!("{} 拒绝当前出口地区访问（区域受限）", title),
        )
        .with_details(details)
        .with_suggestion("当前节点所在地区不受支持，请在软路由/代理中切换至受支持的海外节点。")
        .with_duration(duration_ms);
    }

    if let (Some(obs), Some(base)) = (trace_probe.observed_ip.as_deref(), baseline_exit_ip) {
        if normalize_ip(obs) != normalize_ip(base) {
            details.push(format!(
                "分流不一致警告: 基准 Cloudflare 出口={base}，但 {title} 看到={obs}"
            ));
            return CheckItem::new(
                key,
                CheckCategory::AiServices,
                title,
                CheckState::Fail,
                format!("{title} 看到的出口 IP ({obs}) 与基准出口 ({base}) 不一致！"),
            )
            .with_details(details)
            .with_suggestion("软路由或代理规则将主站与 Cloudflare 边缘/验证域名分到了不同节点，极易触发掉线或风控封号，请合并到同一出口策略组。")
            .with_duration(duration_ms);
        }
    }

    if let Some(ref obs) = trace_probe.observed_ip {
        if api_probe.reachable {
            let loc = trace_probe
                .cf_loc
                .as_deref()
                .map(|l| format!(" [{l}]"))
                .unwrap_or_default();
            return CheckItem::new(
                key,
                CheckCategory::AiServices,
                title,
                CheckState::Ok,
                format!("主站与 API 均可达，出口一致: {obs}{loc}"),
            )
            .with_details(details)
            .with_duration(duration_ms);
        }
        return CheckItem::new(
            key,
            CheckCategory::AiServices,
            title,
            CheckState::Warn,
            format!("主站出口一致 ({obs})，但 API 端点探测异常 ({})", api_probe.note),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    if api_probe.reachable {
        return CheckItem::new(
            key,
            CheckCategory::AiServices,
            title,
            CheckState::Warn,
            format!(
                "API 端点可达，但主站 /cdn-cgi/trace 未返回 IP（{}）",
                trace_probe.note
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    CheckItem::new(
        key,
        CheckCategory::AiServices,
        title,
        CheckState::Fail,
        format!("{title} 主站与 API 均不可达"),
    )
    .with_details(details)
    .with_suggestion("请检查软路由/代理节点连通性及域名规则覆盖。")
    .with_duration(duration_ms)
}
