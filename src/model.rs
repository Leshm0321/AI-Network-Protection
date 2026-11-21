use serde::{Deserialize, Serialize};

use crate::i18n::{self, Lang};

/// Severity/outcome state of a diagnostic check: ok < warn < unknown < fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    Ok,
    Warn,
    Unknown,
    Fail,
}

impl CheckState {
    pub fn severity(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Warn => 1,
            Self::Unknown => 2,
            Self::Fail => 3,
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Warn => "!",
            Self::Unknown => "?",
            Self::Fail => "✗",
        }
    }

    pub fn label(self, lang: Lang) -> &'static str {
        i18n::state_label(self, lang)
    }

    pub fn label_zh(self) -> &'static str {
        i18n::state_label(self, Lang::Zh)
    }
}

/// Functional category for grouping checks in desktop sidebar and CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckCategory {
    NetworkLeak,
    AiServices,
    LocalEnv,
    Controller,
}

impl CheckCategory {
    pub fn label(self, lang: Lang) -> &'static str {
        i18n::category_label(self, lang)
    }

    pub fn label_zh(self) -> &'static str {
        i18n::category_label(self, Lang::Zh)
    }
}

/// Risk band for the OS environment fingerprint score (0–100, lower is cleaner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskBand {
    Low,
    Medium,
    High,
}

impl RiskBand {
    pub fn from_score(score: u8) -> Self {
        if score <= 30 {
            Self::Low
        } else if score <= 60 {
            Self::Medium
        } else {
            Self::High
        }
    }
}

/// Single OS-level fingerprint signal contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintSignal {
    pub id: String,
    pub label_zh: String,
    pub label_en: String,
    pub weight: u8,
    /// Normalized 0..=100 intensity for this signal.
    pub intensity_pct: u8,
    /// Weighted points contributed to total score (`round(weight * intensity_pct / 100)`).
    pub contribution: u8,
    pub raw: String,
    pub hit: bool,
}

/// Standalone OS environment fingerprint risk summary (0–100; separate from IP purity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvFingerprintReport {
    pub score: u8,
    pub band: RiskBand,
    pub signals: Vec<FingerprintSignal>,
}

/// Exit IP purity band (0–100, higher is cleaner / more residential).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PurityBand {
    High,
    Medium,
    Low,
}

impl PurityBand {
    pub fn from_score(score: u8) -> Self {
        if score >= 75 {
            Self::High
        } else if score >= 45 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Classified network type for the exit IP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Residential,
    Business,
    Datacenter,
    #[default]
    Unknown,
}

/// Reputation boolean flags merged conservatively (worst-case wins).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpPurityFlags {
    pub proxy: Option<bool>,
    pub vpn: Option<bool>,
    pub tor: Option<bool>,
    pub datacenter: Option<bool>,
    pub abusive: Option<bool>,
}

/// Itemized deduction explaining why an IP purity score dropped from 100.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurityDeduction {
    pub code: String,
    pub label_zh: String,
    pub label_en: String,
    pub points: i16,
    pub source: String,
}

/// Standalone exit IP purity evaluation (never merged into OS fingerprint risk score).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpPurityReport {
    pub ip: Option<String>,
    /// `None` when no reputation provider answered (never fabricates a fake 100).
    pub purity: Option<u8>,
    pub band: Option<PurityBand>,
    pub network_type: NetworkType,
    pub flags: IpPurityFlags,
    pub deductions: Vec<PurityDeduction>,
    pub sources_configured: bool,
    pub proxycheck_status: String,
    pub abuseipdb_status: String,
}

/// A single diagnostic check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckItem {
    pub key: String,
    pub category: CheckCategory,
    pub title: String,
    pub state: CheckState,
    pub summary: String,
    pub details: Vec<String>,
    pub suggestion: Option<String>,
    pub duration_ms: u64,
}

impl CheckItem {
    pub fn new(
        key: impl Into<String>,
        category: CheckCategory,
        title: impl Into<String>,
        state: CheckState,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            category,
            title: title.into(),
            state,
            summary: summary.into(),
            details: Vec::new(),
            suggestion: None,
            duration_ms: 0,
        }
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

/// Geographic and ISP metadata for an observed public exit IP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitGeoInfo {
    pub ip: String,
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u64>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub timezone_iana: Option<String>,
    pub timezone_offset_secs: Option<i32>,
    pub ip_type_hint: Option<String>,
}

/// Detected effective network egress mode on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPathInfo {
    pub mode_label: String,
    pub proxy_url: Option<String>,
    pub system_proxy: Option<String>,
    pub tun_adapters: Vec<String>,
    pub proxy_processes: Vec<String>,
}

impl Default for NetworkPathInfo {
    fn default() -> Self {
        Self {
            mode_label: "检测中...".to_owned(),
            proxy_url: None,
            system_proxy: None,
            tun_adapters: Vec::new(),
            proxy_processes: Vec::new(),
        }
    }
}

/// Per-service AI endpoint probe snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiServiceProbe {
    pub provider: String,
    pub endpoint: String,
    pub reachable: bool,
    pub status_code: Option<u16>,
    pub observed_ip: Option<String>,
    pub cf_loc: Option<String>,
    pub cf_colo: Option<String>,
    pub latency_ms: u64,
    pub note: String,
}

/// Complete diagnostic report emitted by a full or quick run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub generated_at: String,
    pub overall: CheckState,
    pub total_duration_ms: u64,
    pub network_path: NetworkPathInfo,
    pub exit_geo: Option<ExitGeoInfo>,
    #[serde(default)]
    pub ip_purity: Option<IpPurityReport>,
    #[serde(default)]
    pub env_fingerprint: Option<EnvFingerprintReport>,
    pub ai_probes: Vec<AiServiceProbe>,
    pub items: Vec<CheckItem>,
}

impl DoctorReport {
    pub fn compute_overall(items: &[CheckItem]) -> CheckState {
        items
            .iter()
            // Do not let the optional unconfigured Clash/Mihomo controller placeholder
            // degrade overall health to `Unknown` when all active checks succeeded.
            .filter(|i| !(i.key == "controller-info" && i.state == CheckState::Unknown))
            .map(|i| i.state)
            .max_by_key(|s| s.severity())
            .unwrap_or(CheckState::Unknown)
    }

    pub fn count_by_state(&self, state: CheckState) -> usize {
        self.items.iter().filter(|i| i.state == state).count()
    }

    /// Return a deep-cloned copy with all public IPv4/IPv6 addresses redacted for privacy sharing.
    pub fn masked_for_privacy(&self) -> Self {
        let mut copy = self.clone();
        if let Some(ref mut geo) = copy.exit_geo {
            geo.ip = i18n::mask_ip_str(&geo.ip);
        }
        if let Some(ref mut purity) = copy.ip_purity {
            if let Some(ref mut ip) = purity.ip {
                *ip = i18n::mask_ip_str(ip);
            }
        }
        for p in &mut copy.ai_probes {
            if let Some(ref mut ip) = p.observed_ip {
                *ip = i18n::mask_ip_str(ip);
            }
            p.note = i18n::mask_ips_in_text(&p.note);
        }
        for item in &mut copy.items {
            item.summary = i18n::mask_ips_in_text(&item.summary);
            item.details = item
                .details
                .iter()
                .map(|d| i18n::mask_ips_in_text(d))
                .collect();
            if let Some(ref mut sug) = item.suggestion {
                *sug = i18n::mask_ips_in_text(sug);
            }
        }
        copy
    }
}
