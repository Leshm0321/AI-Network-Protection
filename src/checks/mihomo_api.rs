use std::time::Instant;

use serde_json::Value;

use crate::model::{CheckCategory, CheckItem, CheckState};
use crate::net::build_http_client;

/// Optional Clash / Mihomo External Controller checks (supports localhost OR WiFi soft-router LAN IP).
pub async fn run_mihomo_controller_checks(
    controller_url: Option<&str>,
    secret: Option<&str>,
) -> Vec<CheckItem> {
    let Some(raw_url) = controller_url.map(str::trim).filter(|s| !s.is_empty()) else {
        return vec![
            CheckItem::new(
                "controller-info",
                CheckCategory::Controller,
                "软路由 / Mihomo 内核检查（可选）",
                CheckState::Unknown,
                "未配置 Clash/Mihomo 控制 API（可选：通过 --controller 或设置页填入如 http://192.168.1.1:9090 解锁）",
            )
            .with_details(vec![
                "配置后可自动检查：".to_owned(),
                "1. STUN UDP (3478/5349/19302-19309) 阻断规则".to_owned(),
                "2. AI 域名 (claude.ai / anthropic.com / openai.com / chatgpt.com) 规则覆盖".to_owned(),
                "3. 实时活跃 AI 连接链是否走统一目标节点（无混跑/直连回落）".to_owned(),
                "4. 内核运行模式与断网保护 (Fallback + REJECT/阻断节点) 检查".to_owned(),
            ]),
        ];
    };

    let base = if raw_url.contains("://") {
        raw_url.trim_end_matches('/').to_owned()
    } else {
        format!("http://{}", raw_url.trim_end_matches('/'))
    };

    // Always talk directly to LAN/localhost controller without going through external proxy
    let Ok(client) = build_http_client(None, 5_000, true) else {
        return vec![CheckItem::new(
            "controller-info",
            CheckCategory::Controller,
            "软路由 / Mihomo 内核连接",
            CheckState::Unknown,
            "无法创建控制 API HTTP 客户端",
        )];
    };

    let start = Instant::now();
    let (configs, rules, proxies, connections) = tokio::join!(
        ctrl_get(&client, &base, secret, "/configs"),
        ctrl_get(&client, &base, secret, "/rules"),
        ctrl_get(&client, &base, secret, "/proxies"),
        ctrl_get(&client, &base, secret, "/connections"),
    );
    let dur = start.elapsed().as_millis() as u64;

    if configs.is_none() && rules.is_none() && proxies.is_none() {
        return vec![
            CheckItem::new(
                "controller-info",
                CheckCategory::Controller,
                "软路由 / Mihomo 内核连接",
                CheckState::Fail,
                format!("无法连接控制 API ({base})，请确认地址、端口与 Secret 是否正确"),
            )
            .with_details(vec![format!("尝试访问: {base}/configs")])
            .with_duration(dur),
        ];
    }

    let mut items = Vec::new();
    items.push(evaluate_controller_rules_and_mode(
        &base,
        configs.as_ref(),
        rules.as_ref(),
        dur,
    ));
    items.push(evaluate_controller_killswitch(proxies.as_ref(), dur));
    items.push(evaluate_controller_ai_connections(
        rules.as_ref(),
        connections.as_ref(),
        dur,
    ));
    items
}

async fn ctrl_get(
    client: &reqwest::Client,
    base: &str,
    secret: Option<&str>,
    path: &str,
) -> Option<Value> {
    let url = format!("{base}{path}");
    let mut req = client.get(&url);
    if let Some(sec) = secret.map(str::trim).filter(|s| !s.is_empty()) {
        req = req.header("Authorization", format!("Bearer {sec}"));
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

pub fn evaluate_controller_rules_and_mode(
    base: &str,
    configs: Option<&Value>,
    rules: Option<&Value>,
    duration_ms: u64,
) -> CheckItem {
    let mut details = vec![format!("控制器地址: {base}")];
    let mut warnings = Vec::new();

    if let Some(cfg) = configs {
        let mode = cfg.get("mode").and_then(|v| v.as_str()).unwrap_or("未知");
        let tun_enable = cfg
            .get("tun")
            .and_then(|t| t.get("enable"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let ipv6 = cfg.get("ipv6").and_then(|b| b.as_bool()).unwrap_or(false);
        details.push(format!(
            "内核模式: {mode} · TUN: {} · IPv6: {}",
            if tun_enable { "开启" } else { "关闭" },
            if ipv6 { "开启" } else { "关闭" }
        ));
        if mode.eq_ignore_ascii_case("direct") {
            warnings.push("内核当前处于 DIRECT 直连模式！".to_owned());
        }
    }

    let mut has_stun_reject = false;
    let mut covered_domains = Vec::new();
    let watch_domains = [
        "claude.ai",
        "anthropic.com",
        "openai.com",
        "chatgpt.com",
        "gemini.google.com",
    ];

    if let Some(rule_arr) = rules.and_then(|r| r.get("rules")).and_then(|v| v.as_array()) {
        details.push(format!("已加载规则总数: {}", rule_arr.len()));
        for r in rule_arr {
            let rtype = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let payload = r.get("payload").and_then(|v| v.as_str()).unwrap_or("");
            let proxy = r.get("proxy").and_then(|v| v.as_str()).unwrap_or("");
            let payload_lower = payload.to_ascii_lowercase();

            if proxy.eq_ignore_ascii_case("REJECT")
                && (payload_lower.contains("3478") || payload_lower.contains("19302"))
            {
                has_stun_reject = true;
            }
            for d in watch_domains {
                if payload_lower == d || payload_lower.ends_with(&format!(".{d}")) {
                    if !covered_domains.iter().any(|(dom, _)| dom == &d) {
                        covered_domains.push((d, format!("{rtype} -> {proxy}")));
                    }
                }
            }
        }
    }

    if has_stun_reject {
        details.push("STUN 阻断规则 (UDP 3478/19302): 已存在".to_owned());
    } else {
        warnings.push("未检测到 STUN 端口 (3478/19302) REJECT 规则".to_owned());
    }

    for (d, info) in &covered_domains {
        details.push(format!("显式规则 {d}: {info}"));
    }

    if !warnings.is_empty() {
        return CheckItem::new(
            "controller-rules",
            CheckCategory::Controller,
            "内核模式与核心规则",
            CheckState::Warn,
            warnings.join("；"),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    CheckItem::new(
        "controller-rules",
        CheckCategory::Controller,
        "内核模式与核心规则",
        CheckState::Ok,
        "内核运行模式正常，STUN 阻断与关键规则已就绪",
    )
    .with_details(details)
    .with_duration(duration_ms)
}

pub fn evaluate_controller_killswitch(proxies: Option<&Value>, duration_ms: u64) -> CheckItem {
    let Some(map) = proxies
        .and_then(|p| p.get("proxies"))
        .and_then(|v| v.as_object())
    else {
        return CheckItem::new(
            "controller-killswitch",
            CheckCategory::Controller,
            "断网保护 (Kill Switch)",
            CheckState::Unknown,
            "无法读取内核代理组列表",
        )
        .with_duration(duration_ms);
    };

    let mut fallback_with_reject = Vec::new();
    let mut ai_groups = Vec::new();

    for (name, val) in map {
        let gtype = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let all: Vec<&str> = val
            .get("all")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let now = val.get("now").and_then(|v| v.as_str()).unwrap_or("-");

        let lower = name.to_ascii_lowercase();
        if lower.contains("ai") || lower.contains("claude") || lower.contains("openai") || lower.contains("gpt") {
            ai_groups.push(format!("{name} ({gtype}, 当前={now})"));
        }

        if gtype.eq_ignore_ascii_case("Fallback") {
            let has_block = all.iter().any(|m| {
                let ml = m.to_ascii_lowercase();
                ml == "reject"
                    || ml == "reject-drop"
                    || ml.contains("阻断")
                    || ml.contains("block")
                    || ml.contains("kill")
            });
            if has_block {
                fallback_with_reject.push(format!("{name} (当前={now})"));
            }
        }
    }

    let mut details = Vec::new();
    if !ai_groups.is_empty() {
        details.push(format!("发现 AI 相关策略组: {}", ai_groups.join(" | ")));
    }
    if !fallback_with_reject.is_empty() {
        details.push(format!(
            "具备 fail-closed 阻断能力的 Fallback 组: {}",
            fallback_with_reject.join(", ")
        ));
        return CheckItem::new(
            "controller-killswitch",
            CheckCategory::Controller,
            "断网保护 (Kill Switch)",
            CheckState::Ok,
            format!(
                "已配置 Fallback + 阻断兜底组（{}），主节点失效时不回落直连",
                fallback_with_reject.join(", ")
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    details.push("未发现包含 REJECT/阻断节点的 Fallback 策略组".to_owned());
    CheckItem::new(
        "controller-killswitch",
        CheckCategory::Controller,
        "断网保护 (Kill Switch)",
        CheckState::Warn,
        "未检测到 fail-closed 断网保护策略组（主节点失效时可能回落其他节点或直连）",
    )
    .with_details(details)
    .with_suggestion("建议为 AI 专用策略组设置为 Fallback，并将 REJECT/丢弃节点放在住宅节点之后，避免主节点异常时回落直连。")
    .with_duration(duration_ms)
}

pub fn evaluate_controller_ai_connections(
    _rules: Option<&Value>,
    connections: Option<&Value>,
    duration_ms: u64,
) -> CheckItem {
    let Some(conns) = connections
        .and_then(|c| c.get("connections"))
        .and_then(|v| v.as_array())
    else {
        return CheckItem::new(
            "controller-ai-conns",
            CheckCategory::Controller,
            "AI 运行时连接链检查",
            CheckState::Unknown,
            "无法读取内核活跃连接快照",
        )
        .with_duration(duration_ms);
    };

    let ai_domains = [
        "claude.ai",
        "anthropic.com",
        "chatgpt.com",
        "openai.com",
        "gemini.google.com",
        "generativelanguage.googleapis.com",
    ];
    let mut matched = Vec::new();
    let mut direct_leaks = Vec::new();
    let mut egress_nodes = std::collections::HashSet::new();

    for c in conns {
        let host = c
            .get("metadata")
            .and_then(|m| m.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let proc = c
            .get("metadata")
            .and_then(|m| m.get("process"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let is_ai = ai_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
            || proc.eq_ignore_ascii_case("claude.exe")
            || proc.eq_ignore_ascii_case("claude");
        if !is_ai {
            continue;
        }
        let chains: Vec<&str> = c
            .get("chains")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let chain_text = chains.join(" → ");
        if let Some(egress) = chains.first() {
            egress_nodes.insert((*egress).to_owned());
            if egress.eq_ignore_ascii_case("DIRECT") {
                direct_leaks.push(format!("{host} ({proc}) -> DIRECT"));
            }
        }
        matched.push(format!("{host} [{proc}]: {chain_text}"));
    }

    if !direct_leaks.is_empty() {
        return CheckItem::new(
            "controller-ai-conns",
            CheckCategory::Controller,
            "AI 运行时连接链检查",
            CheckState::Fail,
            format!("检测到 {} 条 AI 活跃连接走 DIRECT 直连！", direct_leaks.len()),
        )
        .with_details(matched)
        .with_suggestion("存在 AI 流量直连泄露，请立即检查软路由/内核分流规则优先级。")
        .with_duration(duration_ms);
    }

    if matched.is_empty() {
        return CheckItem::new(
            "controller-ai-conns",
            CheckCategory::Controller,
            "AI 运行时连接链检查",
            CheckState::Ok,
            "当前无活跃 AI 连接（规则已就绪，发起 Claude/ChatGPT/Gemini 请求后可再次复检）",
        )
        .with_duration(duration_ms);
    }

    if egress_nodes.len() > 1 {
        let nodes: Vec<_> = egress_nodes.into_iter().collect();
        return CheckItem::new(
            "controller-ai-conns",
            CheckCategory::Controller,
            "AI 运行时连接链检查",
            CheckState::Warn,
            format!(
                "活跃 AI 连接分散在多个出口节点 ({})，存在 IP 不一致风险",
                nodes.join("、")
            ),
        )
        .with_details(matched)
        .with_duration(duration_ms);
    }

    let only_node = egress_nodes.into_iter().next().unwrap_or_default();
    CheckItem::new(
        "controller-ai-conns",
        CheckCategory::Controller,
        "AI 运行时连接链检查",
        CheckState::Ok,
        format!("{} 条活跃 AI 连接全部稳定经过单一节点: {only_node}", matched.len()),
    )
    .with_details(matched)
    .with_duration(duration_ms)
}
