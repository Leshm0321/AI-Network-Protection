use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use url::Url;

use crate::model::{CheckCategory, CheckItem, CheckState, NetworkPathInfo};
use crate::net::build_http_client;
use crate::net::system::SystemSnapshot;

/// Check local proxy clients, TUN adapters, system proxy / env proxy conflicts, dead proxy ports,
/// and bare network / Captive Portal readiness.
pub async fn run_proxy_env_checks(
    sys: &SystemSnapshot,
    net_path: &NetworkPathInfo,
) -> Vec<CheckItem> {
    let (proxy_item, portal_item) = tokio::join!(
        check_proxy_topology_and_conflicts(sys, net_path),
        check_captive_portal(),
    );
    vec![proxy_item, portal_item]
}

async fn tcp_port_alive(proxy_url: &str) -> Result<(), String> {
    let parsed = Url::parse(proxy_url).map_err(|e| format!("URL 解析失败: {e}"))?;
    let host = parsed.host_str().ok_or_else(|| "缺少主机".to_owned())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "缺少端口".to_owned())?;
    tokio::time::timeout(Duration::from_millis(800), TcpStream::connect((host, port)))
        .await
        .map_err(|_| format!("{host}:{port} 连接超时"))?
        .map(|_| ())
        .map_err(|e| format!("{host}:{port} 无法连通 ({e})"))
}

async fn check_proxy_topology_and_conflicts(
    sys: &SystemSnapshot,
    net_path: &NetworkPathInfo,
) -> CheckItem {
    let start = Instant::now();
    let mut details = Vec::new();
    let mut warnings = Vec::new();
    let mut failures = Vec::new();

    details.push(format!("当前生效路径: {}", net_path.mode_label));

    // 1. Check multi-TUN adapter conflicts
    if sys.ipv6.tun_adapters.len() > 1 {
        warnings.push(format!(
            "同时存在多个活跃 TUN/VPN 虚拟网卡 ({})，可能互相抢路由导致分流失效",
            sys.ipv6.tun_adapters.join("、")
        ));
    } else if !sys.ipv6.tun_adapters.is_empty() {
        details.push(format!("本机虚拟网卡: {}", sys.ipv6.tun_adapters.join(", ")));
    } else {
        details.push("本机虚拟网卡: 无（软路由/系统代理/直连环境）".to_owned());
    }

    if !net_path.proxy_processes.is_empty() {
        details.push(format!(
            "本机运行中的代理/VPN 进程: {}",
            net_path.proxy_processes.join(", ")
        ));
    } else {
        details.push("本机运行中的代理/VPN 进程: 无".to_owned());
    }

    // 2. Inspect HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY env vars for conflicts & dead ports
    let proxy_env_keys = [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ];
    let mut found_env = Vec::new();
    for k in proxy_env_keys {
        if let Ok(v) = std::env::var(k) {
            if !v.trim().is_empty() {
                found_env.push((k, v));
            }
        }
    }

    if found_env.is_empty() {
        details.push("代理环境变量 (HTTP_PROXY 等): 未设置".to_owned());
    } else {
        for (k, v) in &found_env {
            details.push(format!("环境变量 {k}={v}"));
        }
    }

    // Case-mismatch check (e.g. HTTP_PROXY vs http_proxy having different values)
    for (upper, lower) in [
        ("HTTP_PROXY", "http_proxy"),
        ("HTTPS_PROXY", "https_proxy"),
        ("ALL_PROXY", "all_proxy"),
        ("NO_PROXY", "no_proxy"),
    ] {
        if let (Ok(u), Ok(l)) = (std::env::var(upper), std::env::var(lower)) {
            if !u.trim().is_empty() && !l.trim().is_empty() && u.trim() != l.trim() {
                warnings.push(format!(
                    "环境变量大小写值冲突: {upper}={u} 与 {lower}={l} 不一致，不同 CLI 工具会走不同出口"
                ));
            }
        }
    }

    // Check NO_PROXY accidentally bypassing AI domains
    let no_proxy_val = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    if !no_proxy_val.trim().is_empty() {
        let lower = no_proxy_val.to_ascii_lowercase();
        let risky_tokens = [
            "*",
            "openai.com",
            "chatgpt.com",
            "anthropic.com",
            "claude.ai",
            "google.com",
            "googleapis.com",
            "cloudflare.com",
        ];
        for tok in risky_tokens {
            if lower.split(',').any(|p| p.trim() == tok) {
                warnings.push(format!(
                    "NO_PROXY 包含 `{tok}`，可能导致 AI CLI/SDK 绕过代理直连"
                ));
            }
        }
    }

    // 3. Check system proxy vs active port reachability
    if sys.system_proxy.enabled {
        details.push(format!(
            "系统代理已开启: {}",
            sys.system_proxy.server.as_deref().unwrap_or("(空)")
        ));
    } else {
        details.push("系统代理: 未开启".to_owned());
    }

    if let Some(ref active_proxy) = net_path.proxy_url {
        if let Err(err) = tcp_port_alive(active_proxy).await {
            failures.push(format!("当前代理地址 {active_proxy} 不可达: {err}"));
        } else {
            details.push(format!("代理端口连通性 ({active_proxy}): TCP 正常"));
        }
    }

    // Warn if system proxy is enabled on a dead port while env proxy isn't overriding it,
    // or if env proxy is set even though no local proxy process is running
    if let (Some(env_p), Some(sys_p)) = (&net_path.proxy_url, &net_path.system_proxy) {
        if env_p != sys_p {
            warnings.push(format!(
                "环境变量/指定代理 ({env_p}) 与系统代理 ({sys_p}) 不一致，浏览器与终端 CLI 可能走不同链路"
            ));
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    if !failures.is_empty() {
        details.extend(failures.clone());
        return CheckItem::new(
            "proxy-env",
            CheckCategory::LocalEnv,
            "代理拓扑与冲突检测",
            CheckState::Fail,
            failures.join("；"),
        )
        .with_details(details)
        .with_suggestion("若你已改用 WiFi 软路由，请清理失效的 HTTP_PROXY/HTTPS_PROXY 环境变量或关闭残留系统代理。")
        .with_duration(duration_ms);
    }

    if !warnings.is_empty() {
        details.extend(warnings.clone());
        return CheckItem::new(
            "proxy-env",
            CheckCategory::LocalEnv,
            "代理拓扑与冲突检测",
            CheckState::Warn,
            warnings.join("；"),
        )
        .with_details(details)
        .with_suggestion("请确保终端 CLI 与浏览器走同一出口路径，避免混用代理导致 IP 跳变。")
        .with_duration(duration_ms);
    }

    CheckItem::new(
        "proxy-env",
        CheckCategory::LocalEnv,
        "代理拓扑与冲突检测",
        CheckState::Ok,
        format!("代理环境清晰无冲突（{}）", net_path.mode_label),
    )
    .with_details(details)
    .with_duration(duration_ms)
}

/// Detect Captive Portal / unauthenticated Wi-Fi gateways before blaming AI endpoints.
async fn check_captive_portal() -> CheckItem {
    let start = Instant::now();
    let Ok(client) = build_http_client(None, 5_000, false) else {
        return CheckItem::new(
            "captive-portal",
            CheckCategory::NetworkLeak,
            "基础网络与门户认证",
            CheckState::Unknown,
            "无法创建基础网络探测客户端",
        );
    };

    let probes = [
        (
            "Windows NCSI",
            "http://www.msftconnecttest.com/connecttest.txt",
        ),
        ("MIUI 204", "http://connect.rom.miui.com/generate_204"),
    ];

    let mut details = Vec::new();
    let mut portal_url = None;
    let mut ok_count = 0usize;
    let mut unreachable_count = 0usize;

    for (name, url) in probes {
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let loc = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                if status == 204 || (status == 200 && name == "Windows NCSI") {
                    ok_count += 1;
                    details.push(format!("{name}: 正常 (HTTP {status})"));
                } else if (300..400).contains(&status) {
                    if portal_url.is_none() && loc.starts_with("http") {
                        portal_url = Some(loc.clone());
                    }
                    details.push(format!("{name}: 重定向到认证门户 ({loc})"));
                } else {
                    details.push(format!("{name}: 异常响应 (HTTP {status})"));
                }
            }
            Err(e) => {
                unreachable_count += 1;
                details.push(format!("{name}: 无响应 ({e})"));
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    if let Some(ref url) = portal_url {
        return CheckItem::new(
            "captive-portal",
            CheckCategory::NetworkLeak,
            "基础网络与门户认证",
            CheckState::Fail,
            format!("当前 Wi-Fi/网络需要网页认证 ({url})"),
        )
        .with_details(details)
        .with_suggestion("请先在浏览器完成校园网/酒店 Wi-Fi 认证后再进行 AI 访问。")
        .with_duration(duration_ms);
    }
    if unreachable_count == probes.len() {
        return CheckItem::new(
            "captive-portal",
            CheckCategory::NetworkLeak,
            "基础网络与门户认证",
            CheckState::Warn,
            "直连基础探测端点全部无响应（可能离线或处于纯代理隔离网络）",
        )
        .with_details(details)
        .with_duration(duration_ms);
    }
    if ok_count > 0 {
        return CheckItem::new(
            "captive-portal",
            CheckCategory::NetworkLeak,
            "基础网络与门户认证",
            CheckState::Ok,
            "基础网络连接正常，无门户劫持",
        )
        .with_details(details)
        .with_duration(duration_ms);
    }
    CheckItem::new(
        "captive-portal",
        CheckCategory::NetworkLeak,
        "基础网络与门户认证",
        CheckState::Unknown,
        "基础网络探测结果不一致，请查看详情",
    )
    .with_details(details)
    .with_duration(duration_ms)
}
