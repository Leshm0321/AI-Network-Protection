pub mod system;

use std::net::IpAddr;
use std::time::Duration;

use reqwest::Client;

use crate::config::CheckOptions;
use crate::model::NetworkPathInfo;
use crate::net::system::SystemSnapshot;

/// Parsed response from Cloudflare's `/cdn-cgi/trace` public endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceInfo {
    pub ip: String,
    pub loc: Option<String>,
    pub colo: Option<String>,
    pub warp: Option<String>,
}

/// Normalize proxy string (e.g. `127.0.0.1:7890` or `http=127.0.0.1:7890;https=127.0.0.1:7890`)
/// into a valid `http://` or `socks5h://` URL.
pub fn normalize_proxy_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Windows IE registry format may contain `http=host:port;https=host:port;socks=host:port`
    if trimmed.contains('=') && trimmed.contains(';') || trimmed.starts_with("http=") || trimmed.starts_with("https=") || trimmed.starts_with("socks=") {
        let mut https_val = None;
        let mut http_val = None;
        let mut socks_val = None;
        for part in trimmed.split(';') {
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim();
                if v.is_empty() {
                    continue;
                }
                match k.as_str() {
                    "https" => https_val = Some(format!("http://{v}")),
                    "http" => http_val = Some(format!("http://{v}")),
                    "socks" => socks_val = Some(format!("socks5h://{v}")),
                    _ => {}
                }
            }
        }
        return https_val.or(http_val).or(socks_val);
    }

    if trimmed.contains("://") {
        // Prefer socks5h so DNS is resolved through proxy when socks5 is given
        if let Some(rest) = trimmed.strip_prefix("socks5://") {
            return Some(format!("socks5h://{rest}"));
        }
        Some(trimmed.to_owned())
    } else {
        Some(format!("http://{trimmed}"))
    }
}

/// Read proxy URL from process environment variables in standard precedence order.
pub fn env_proxy_url() -> Option<(String, String)> {
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        if let Ok(val) = std::env::var(key) {
            if let Some(norm) = normalize_proxy_url(&val) {
                return Some((key.to_owned(), norm));
            }
        }
    }
    None
}

/// Resolve the effective proxy & human-readable network path description for this run.
pub fn resolve_network_path(opts: &CheckOptions, sys: &SystemSnapshot) -> NetworkPathInfo {
    let sys_proxy_url = if sys.system_proxy.enabled {
        sys.system_proxy
            .server
            .as_deref()
            .and_then(normalize_proxy_url)
    } else {
        None
    };

    let tun_adapters = sys.ipv6.tun_adapters.clone();
    let proxy_processes: Vec<String> = {
        let mut names: Vec<String> = sys
            .proxy_processes
            .iter()
            .map(|p| p.name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    };

    if opts.no_proxy {
        let label = if !tun_adapters.is_empty() {
            format!("强制直出 / 本机 TUN ({})", tun_adapters.join(", "))
        } else {
            "强制直出 / 软路由透明代理".to_owned()
        };
        return NetworkPathInfo {
            mode_label: label,
            proxy_url: None,
            system_proxy: sys_proxy_url,
            tun_adapters,
            proxy_processes,
        };
    }

    if let Some(explicit) = opts.proxy.as_deref().and_then(normalize_proxy_url) {
        return NetworkPathInfo {
            mode_label: format!("手动指定代理 ({explicit})"),
            proxy_url: Some(explicit),
            system_proxy: sys_proxy_url,
            tun_adapters,
            proxy_processes,
        };
    }

    if let Some((var, url)) = env_proxy_url() {
        return NetworkPathInfo {
            mode_label: format!("环境变量代理 {var} ({url})"),
            proxy_url: Some(url),
            system_proxy: sys_proxy_url,
            tun_adapters,
            proxy_processes,
        };
    }

    if let Some(ref sp) = sys_proxy_url {
        return NetworkPathInfo {
            mode_label: format!("系统代理 ({sp})"),
            proxy_url: Some(sp.clone()),
            system_proxy: sys_proxy_url,
            tun_adapters,
            proxy_processes,
        };
    }

    if !tun_adapters.is_empty() {
        return NetworkPathInfo {
            mode_label: format!("本机 TUN 接管 ({})", tun_adapters.join(", ")),
            proxy_url: None,
            system_proxy: None,
            tun_adapters,
            proxy_processes,
        };
    }

    NetworkPathInfo {
        mode_label: "直出 / WiFi 软路由透明代理".to_owned(),
        proxy_url: None,
        system_proxy: None,
        tun_adapters,
        proxy_processes,
    }
}

/// Build an HTTP client matching the resolved network path.
pub fn build_http_client(
    proxy_url: Option<&str>,
    timeout_ms: u64,
    follow_redirects: bool,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms.min(8_000)))
        .user_agent("AI-Network-Protection/0.1")
        .no_proxy();

    if !follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(proxy_str) = proxy_url {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_str) {
            builder = builder.proxy(proxy);
        }
    }

    builder.build()
}

/// Build a direct IPv6-only client (never uses proxy) to detect raw IPv6 leaks bypassing proxies/soft-routers.
pub fn build_direct_ipv6_client(timeout_ms: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms.min(4_000)))
        .user_agent("AI-Network-Protection/0.1")
        .local_address(Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)))
        .no_proxy()
        .build()
}

/// Parse Cloudflare `/cdn-cgi/trace` plain-text response.
/// Rejects HTML pages (e.g. WAF block or captive portal) and non-IP strings.
pub fn parse_cf_trace(body: &str) -> Option<TraceInfo> {
    let trimmed = body.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('<')
        || trimmed.contains("<html")
        || trimmed.contains("<!DOCTYPE")
    {
        return None;
    }

    let mut ip = None;
    let mut loc = None;
    let mut colo = None;
    let mut warp = None;

    for line in trimmed.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            match k.trim() {
                "ip" => {
                    if v.parse::<IpAddr>().is_ok() {
                        ip = Some(v.to_owned());
                    }
                }
                "loc" if !v.is_empty() => loc = Some(v.to_owned()),
                "colo" if !v.is_empty() => colo = Some(v.to_owned()),
                "warp" if !v.is_empty() => warp = Some(v.to_owned()),
                _ => {}
            }
        }
    }

    Some(TraceInfo {
        ip: ip?,
        loc,
        colo,
        warp,
    })
}

/// Normalize IPv4/IPv6 string into canonical form for equality comparisons.
pub fn normalize_ip(raw: &str) -> Option<String> {
    raw.trim().parse::<IpAddr>().ok().map(|ip| ip.to_string())
}
