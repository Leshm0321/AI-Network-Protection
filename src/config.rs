use serde::{Deserialize, Serialize};

use crate::i18n::Lang;

fn default_true() -> bool {
    true
}

/// Runtime options controlling how diagnostic checks are executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckOptions {
    /// UI and report language (`zh` / `en`). Defaults to OS locale.
    #[serde(default)]
    pub lang: Lang,
    /// Explicit proxy URL (e.g. `http://127.0.0.1:7890` or `socks5h://127.0.0.1:7891`).
    /// When `None` and `no_proxy` is false, automatically adapts to env/system proxy or direct/soft-router.
    pub proxy: Option<String>,
    /// Force direct OS routing (ignore HTTP_PROXY/HTTPS_PROXY/system proxy).
    pub no_proxy: bool,
    /// Optional expected exclusive/residential exit IPv4 or IPv6 address.
    pub expected_ip: Option<String>,
    /// Optional expected country ISO-2 code (e.g. "US", "JP", "SG").
    pub expected_country: Option<String>,
    /// Optional Clash / Mihomo External Controller URL (local or soft-router LAN, e.g. `http://192.168.1.1:9090`).
    pub controller_url: Option<String>,
    /// Optional Clash / Mihomo Controller Bearer secret.
    pub controller_secret: Option<String>,
    /// Optional custom Claude config directory override (auto-detected when `None`).
    pub claude_dir: Option<String>,
    /// Optional proxycheck.io API key for standalone IP purity scoring.
    #[serde(default)]
    pub proxycheck_api_key: Option<String>,
    /// Optional AbuseIPDB API key for standalone IP purity scoring.
    #[serde(default)]
    pub abuseipdb_api_key: Option<String>,
    /// Optional Cloudflare Radar API token (28-day ASN bot traffic ratio).
    #[serde(default)]
    pub cf_radar_token: Option<String>,
    /// Optional GreyNoise API key (internet scanner / benign RIOT classification).
    #[serde(default)]
    pub greynoise_api_key: Option<String>,
    /// Optional CrowdSec CTI API key (community threat intelligence).
    #[serde(default)]
    pub crowdsec_api_key: Option<String>,
    /// Optional VirusTotal API key (multi-engine IP maliciousness).
    #[serde(default)]
    pub virustotal_api_key: Option<String>,
    /// Optional IPRegistry API key (commercial IP security & company classification).
    #[serde(default)]
    pub ipregistry_api_key: Option<String>,
    /// Optional IPData API key (commercial threat & datacenter intel).
    #[serde(default)]
    pub ipdata_api_key: Option<String>,
    /// Download & scan 17 public CIDR threat/proxy/datacenter lists + /24 neighbor & ASN abuse density.
    /// Enabled by default (in-memory cached for 12h) for complete scoring confidence.
    #[serde(default = "default_true")]
    pub enable_cidr_lists: bool,
    /// Optional: inspect an arbitrary public IPv4/IPv6 instead of local egress + OS checks.
    #[serde(default)]
    pub target_ip: Option<String>,
    /// Long-connection keep-alive hold duration in seconds (default 15s; quick mode 8s).
    pub long_conn_secs: u64,
    /// Per-request HTTP timeout in milliseconds.
    pub timeout_ms: u64,
    /// Opt-in: execute active API connectivity test against configured Claude/OpenAI provider endpoint.
    /// Defaults to `false` so routine checks never spend tokens or send credentials.
    pub run_api_test: bool,
    /// Skip probing `claude.ai` / `chatgpt.com` / `gemini.google.com` if strict neutral-only mode is requested.
    pub neutral_only: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            lang: Lang::detect_system(),
            proxy: None,
            no_proxy: false,
            expected_ip: None,
            expected_country: None,
            controller_url: None,
            controller_secret: None,
            claude_dir: None,
            proxycheck_api_key: None,
            abuseipdb_api_key: None,
            cf_radar_token: None,
            greynoise_api_key: None,
            crowdsec_api_key: None,
            virustotal_api_key: None,
            ipregistry_api_key: None,
            ipdata_api_key: None,
            enable_cidr_lists: true,
            target_ip: None,
            long_conn_secs: 15,
            timeout_ms: 10_000,
            run_api_test: false,
            neutral_only: false,
        }
    }
}

impl CheckOptions {
    pub fn quick(mut self) -> Self {
        self.long_conn_secs = 8;
        self
    }

    pub fn from_env_defaults() -> Self {
        let mut opts = Self::default();
        if let Ok(raw_lang) = std::env::var("ANP_LANG") {
            if let Some(parsed) = Lang::from_str_opt(&raw_lang) {
                opts.lang = parsed;
            }
        }
        if let Ok(ip) = std::env::var("ANP_EXPECTED_IP") {
            let trimmed = ip.trim();
            if !trimmed.is_empty() {
                opts.expected_ip = Some(trimmed.to_owned());
            }
        }
        if let Ok(cc) = std::env::var("ANP_EXPECTED_COUNTRY") {
            let trimmed = cc.trim();
            if !trimmed.is_empty() {
                opts.expected_country = Some(trimmed.to_ascii_uppercase());
            }
        }
        if let Ok(ctrl) = std::env::var("ANP_CONTROLLER_URL") {
            let trimmed = ctrl.trim();
            if !trimmed.is_empty() {
                opts.controller_url = Some(trimmed.to_owned());
            }
        }
        if let Ok(secret) = std::env::var("ANP_CTRL_SECRET") {
            let trimmed = secret.trim();
            if !trimmed.is_empty() {
                opts.controller_secret = Some(trimmed.to_owned());
            }
        }
        if let Ok(key) = std::env::var("PROXYCHECK_API_KEY")
            .or_else(|_| std::env::var("ANP_PROXYCHECK_API_KEY"))
        {
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                opts.proxycheck_api_key = Some(trimmed.to_owned());
            }
        }
        if let Ok(key) =
            std::env::var("ABUSEIPDB_API_KEY").or_else(|_| std::env::var("ANP_ABUSEIPDB_API_KEY"))
        {
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                opts.abuseipdb_api_key = Some(trimmed.to_owned());
            }
        }
        if let Ok(tok) =
            std::env::var("CF_RADAR_TOKEN").or_else(|_| std::env::var("ANP_CF_RADAR_TOKEN"))
        {
            let trimmed = tok.trim();
            if !trimmed.is_empty() {
                opts.cf_radar_token = Some(trimmed.to_owned());
            }
        }
        for (env1, env2, slot) in [
            ("GREYNOISE_API_KEY", "ANP_GREYNOISE_API_KEY", &mut opts.greynoise_api_key),
            ("CROWDSEC_API_KEY", "ANP_CROWDSEC_API_KEY", &mut opts.crowdsec_api_key),
            ("VIRUSTOTAL_API_KEY", "ANP_VIRUSTOTAL_API_KEY", &mut opts.virustotal_api_key),
            ("IPREGISTRY_API_KEY", "ANP_IPREGISTRY_API_KEY", &mut opts.ipregistry_api_key),
            ("IPDATA_API_KEY", "ANP_IPDATA_API_KEY", &mut opts.ipdata_api_key),
        ] {
            if let Ok(val) = std::env::var(env1).or_else(|_| std::env::var(env2)) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    *slot = Some(trimmed.to_owned());
                }
            }
        }
        opts
    }
}
