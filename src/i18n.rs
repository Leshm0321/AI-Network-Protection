use serde::{Deserialize, Serialize};

use crate::model::{CheckCategory, CheckState, NetworkType, PurityBand, RiskBand};

/// UI and diagnostic output language (Chinese / English).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Zh,
    En,
}

impl Default for Lang {
    fn default() -> Self {
        Self::detect_system()
    }
}

impl Lang {
    /// Auto-detect default language from OS locale (`zh*` -> Chinese, otherwise English).
    pub fn detect_system() -> Self {
        let locale = sys_locale::get_locale().unwrap_or_default().to_ascii_lowercase();
        if locale.starts_with("zh") {
            Self::Zh
        } else {
            Self::En
        }
    }

    pub fn from_str_opt(raw: &str) -> Option<Self> {
        let s = raw.trim().to_ascii_lowercase();
        if s == "zh" || s.starts_with("zh-") || s.starts_with("zh_") || s == "cn" {
            Some(Self::Zh)
        } else if s == "en" || s.starts_with("en-") || s.starts_with("en_") {
            Some(Self::En)
        } else {
            None
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Zh => Self::En,
            Self::En => Self::Zh,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::Zh => "zh",
            Self::En => "en",
        }
    }
}

/// Ergonomic inline bilingual selector.
#[inline]
pub fn pick<'a>(lang: Lang, zh: &'a str, en: &'a str) -> &'a str {
    match lang {
        Lang::Zh => zh,
        Lang::En => en,
    }
}

pub fn state_label(state: CheckState, lang: Lang) -> &'static str {
    match (state, lang) {
        (CheckState::Ok, Lang::Zh) => "通过",
        (CheckState::Ok, Lang::En) => "Pass",
        (CheckState::Warn, Lang::Zh) => "警告",
        (CheckState::Warn, Lang::En) => "Warn",
        (CheckState::Unknown, Lang::Zh) => "未知",
        (CheckState::Unknown, Lang::En) => "Unknown",
        (CheckState::Fail, Lang::Zh) => "失败",
        (CheckState::Fail, Lang::En) => "Fail",
    }
}

pub fn category_label(cat: CheckCategory, lang: Lang) -> &'static str {
    match (cat, lang) {
        (CheckCategory::NetworkLeak, Lang::Zh) => "网络与泄漏",
        (CheckCategory::NetworkLeak, Lang::En) => "Network & Leaks",
        (CheckCategory::AiServices, Lang::Zh) => "AI 服务",
        (CheckCategory::AiServices, Lang::En) => "AI Services",
        (CheckCategory::LocalEnv, Lang::Zh) => "本地与配置",
        (CheckCategory::LocalEnv, Lang::En) => "Local & Config",
        (CheckCategory::Controller, Lang::Zh) => "软路由 / 内核",
        (CheckCategory::Controller, Lang::En) => "Router / Core",
    }
}

pub fn risk_band_label(band: RiskBand, lang: Lang) -> &'static str {
    match (band, lang) {
        (RiskBand::Low, Lang::Zh) => "低风险",
        (RiskBand::Low, Lang::En) => "Low Risk",
        (RiskBand::Medium, Lang::Zh) => "中风险",
        (RiskBand::Medium, Lang::En) => "Medium Risk",
        (RiskBand::High, Lang::Zh) => "高风险",
        (RiskBand::High, Lang::En) => "High Risk",
    }
}

pub fn purity_band_label(band: PurityBand, lang: Lang) -> &'static str {
    match (band, lang) {
        (PurityBand::High, Lang::Zh) => "高纯净",
        (PurityBand::High, Lang::En) => "High Purity",
        (PurityBand::Medium, Lang::Zh) => "中等",
        (PurityBand::Medium, Lang::En) => "Moderate",
        (PurityBand::Low, Lang::Zh) => "高风险",
        (PurityBand::Low, Lang::En) => "Risky",
    }
}

pub fn network_type_label(nt: NetworkType, lang: Lang) -> &'static str {
    match (nt, lang) {
        (NetworkType::Residential, Lang::Zh) => "住宅宽带",
        (NetworkType::Residential, Lang::En) => "Residential",
        (NetworkType::Business, Lang::Zh) => "商业网络",
        (NetworkType::Business, Lang::En) => "Business",
        (NetworkType::Datacenter, Lang::Zh) => "数据中心 / 机房",
        (NetworkType::Datacenter, Lang::En) => "Datacenter",
        (NetworkType::Unknown, Lang::Zh) => "未知类型",
        (NetworkType::Unknown, Lang::En) => "Unknown",
    }
}

/// Localized check title lookup by canonical check key (used for instant language toggle in UI).
pub fn check_title(key: &str, lang: Lang) -> Option<&'static str> {
    let pair = match key {
        "exit" => ("出口 IP 一致性", "Exit IP Consistency"),
        "exclusive-ip" => ("独享 IP 核对", "Dedicated IP Verification"),
        "ip-purity" => ("出口 IP 纯净度评分", "Exit IP Purity Score"),
        "dnsbl-reputation" => ("DNSBL 公开黑名单", "DNSBL Public Blocklists"),
        "ip-native-rpki" => ("原生 / 广播 IP 与 RPKI", "Native vs. Broadcast & RPKI"),
        "cidr-threat-lists" => ("威胁网段与 /24 邻居", "CIDR Threat & /24 Neighbors"),
        "dns" | "dns-leak" => ("DNS 与 EDNS 子网泄漏检测", "DNS & EDNS Subnet Leak"),
        "ipv6" | "ipv6-leak" => ("IPv6 防泄漏检测", "IPv6 Leak Detection"),
        "webrtc" | "webrtc-leak" => ("WebRTC / STUN 防泄漏", "WebRTC / STUN Leak"),
        "long-conn" | "long-connection" => ("长连接稳定性", "Long-Connection Stability"),
        "captive-portal" => ("基础网络与门户认证", "Network & Captive Portal"),
        "proxy-env" => ("本机代理与网络拓扑", "Local Proxy & Topology"),
        "ai-openai" => ("OpenAI / ChatGPT", "OpenAI / ChatGPT"),
        "ai-anthropic" => ("Anthropic / Claude", "Anthropic / Claude"),
        "ai-google" => ("Google / Gemini & AI Studio", "Google / Gemini & AI Studio"),
        "timezone-locale" => ("本机时区与语言一致性", "Timezone & Locale Consistency"),
        "env-fingerprint" => ("本机环境指纹风险评分", "OS Fingerprint Risk Score"),
        "claude-config" => ("Claude 配置完整性", "Claude Config Integrity"),
        "claude-env-sync" => ("Claude 环境变量一致性", "Claude Env Consistency"),
        "claude-endpoint-risk" => ("Claude 中转与隐写风险审计", "Claude Relay & Steganography Audit"),
        "ai-cli-extended" => ("扩展 AI CLI 环境检测", "Extended AI CLI Environment"),
        "claude-api-test" => ("Claude API 连通性测试", "Claude API Connectivity Test"),
        "controller-info" => ("软路由 / Mihomo 内核检查（可选）", "Router / Mihomo Core (Optional)"),
        "controller-mode-rules" => ("内核模式与分流规则", "Core Mode & Routing Rules"),
        "controller-killswitch" => ("断网保护 (Kill Switch)", "Kill Switch Protection"),
        "controller-ai-conns" => ("AI 实时连接链检查", "Live AI Connection Chains"),
        _ => return None,
    };
    Some(pick(lang, pair.0, pair.1))
}

/// Mask public IPv4 and IPv6 addresses in arbitrary text when Privacy / Hide-IP mode is enabled.
/// Preserves RFC-1918 private/loopback/Fake-IP addresses (127.*, 10.*, 192.168.*, 198.18.*) and non-IP tokens.
pub fn mask_ips_in_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        // Candidate IPv4 start
        if ch.is_ascii_digit()
            && (i == 0
                || !matches!(
                    bytes[i - 1] as char,
                    '0'..='9' | 'a'..='z' | 'A'..='Z' | '.' | '_' | '-'
                ))
        {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            let cand = &input[i..j];
            if let Ok(v4) = cand.parse::<std::net::Ipv4Addr>() {
                let oct = v4.octets();
                let is_private_or_special = v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19))
                    || (oct[0] == 100 && (64..=127).contains(&oct[1]));
                if !is_private_or_special {
                    out.push_str(&format!("{}.{}.*.*", oct[0], oct[1]));
                    i = j;
                    continue;
                }
            }
        }

        // Candidate IPv6 start (contains at least two ':' and valid hex/colon characters)
        if (ch.is_ascii_hexdigit() || ch == ':')
            && (i == 0
                || !matches!(
                    bytes[i - 1] as char,
                    '0'..='9' | 'a'..='z' | 'A'..='Z' | ':' | '_'
                ))
        {
            let mut j = i;
            let mut colons = 0usize;
            while j < bytes.len() && (bytes[j].is_ascii_hexdigit() || bytes[j] == b':') {
                if bytes[j] == b':' {
                    colons += 1;
                }
                j += 1;
            }
            if colons >= 2 && j - i >= 6 {
                let cand = &input[i..j];
                if let Ok(v6) = cand.parse::<std::net::Ipv6Addr>() {
                    let segs = v6.segments();
                    let is_local = v6.is_loopback()
                        || v6.is_unspecified()
                        || (segs[0] & 0xffc0) == 0xfe80
                        || (segs[0] & 0xfe00) == 0xfc00;
                    if !is_local {
                        out.push_str(&format!("{:x}:{:x}:****", segs[0], segs[1]));
                        i = j;
                        continue;
                    }
                }
            }
        }

        let next = input[i..].chars().next().unwrap();
        out.push(next);
        i += next.len_utf8();
    }

    out
}

/// Mask a single IP string directly (e.g. for KPI display or JSON export).
pub fn mask_ip_str(ip: &str) -> String {
    mask_ips_in_text(ip)
}
