use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

use crate::checks::cidr_lists::{self, CidrSummary};
use crate::checks::dnsbl::{self, DnsblSummary};
use crate::i18n::{self, Lang, pick};
use crate::model::{
    CheckCategory, CheckItem, CheckState, ExitGeoInfo, IpPurityFlags, IpPurityReport, NetworkType,
    PurityBand, PurityDeduction,
};

#[derive(Debug, Clone, Default)]
pub struct ReputationReading {
    pub source_name: String,
    pub weight: f64,
    pub status: String,
    pub ok: bool,
    pub asn: Option<u64>,
    pub asn_org: Option<String>,
    pub asn_type_hint: Option<AsnKind>,
    pub network_type: Option<NetworkType>,
    pub proxy: Option<bool>,
    pub vpn: Option<bool>,
    pub tor: Option<bool>,
    pub datacenter: Option<bool>,
    pub abusive: Option<bool>,
    pub abuse_confidence: Option<u8>,
    pub risk_score: Option<u8>,
    pub open_ports: Vec<u16>,
    pub cves: Vec<String>,
    pub otx_pulses: Option<u32>,
    pub extra_note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnKind {
    IspResidential,
    Mobile,
    Datacenter,
    Cdn,
    Backbone,
    Business,
    Education,
    Unknown,
}

impl AsnKind {
    pub fn label(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Self::IspResidential, Lang::Zh) => "运营商 / 住宅宽带",
            (Self::IspResidential, Lang::En) => "ISP / Residential",
            (Self::Mobile, Lang::Zh) => "移动网络",
            (Self::Mobile, Lang::En) => "Mobile Carrier",
            (Self::Datacenter, Lang::Zh) => "数据中心 / 云机房",
            (Self::Datacenter, Lang::En) => "Datacenter / Hosting",
            (Self::Cdn, Lang::Zh) => "CDN / 边缘网络",
            (Self::Cdn, Lang::En) => "CDN / Edge",
            (Self::Backbone, Lang::Zh) => "骨干网 / 传输",
            (Self::Backbone, Lang::En) => "Backbone / Transit",
            (Self::Business, Lang::Zh) => "企业 / 商业网络",
            (Self::Business, Lang::En) => "Enterprise / Business",
            (Self::Education, Lang::Zh) => "教育 / 科研 / 政务",
            (Self::Education, Lang::En) => "Education / Gov",
            (Self::Unknown, Lang::Zh) => "未知 ASN 类型",
            (Self::Unknown, Lang::En) => "Unknown ASN",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeeringDbInfo {
    pub found: bool,
    pub name: Option<String>,
    pub info_type: Option<String>,
    pub info_ratio: Option<String>,
    pub prefixes4: Option<u64>,
}

/// Single multi-source GeoIP consensus vote (country ISO-2 + optional city).
#[derive(Debug, Clone, Default)]
pub struct GeoConsensusVote {
    pub source: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
}

/// Optional API keys for commercial / rate-limited IP intelligence providers.
#[derive(Debug, Clone, Copy, Default)]
pub struct IntelApiKeys<'a> {
    pub proxycheck: Option<&'a str>,
    pub abuseipdb: Option<&'a str>,
    pub cf_radar: Option<&'a str>,
    pub greynoise: Option<&'a str>,
    pub crowdsec: Option<&'a str>,
    pub virustotal: Option<&'a str>,
    pub ipregistry: Option<&'a str>,
    pub ipdata: Option<&'a str>,
}

/// Authoritative BGP routing & registration context from ip.guide + RIPEstat + RDAP + DoH PTR + optional CF Radar + multi-source GeoIP consensus.
#[derive(Debug, Clone, Default)]
pub struct AsnRoutingInfo {
    pub bgp_asn: Option<u64>,
    pub bgp_org: Option<String>,
    pub bgp_prefix: Option<String>,
    pub bgp_rir: Option<String>,
    pub announced_v4_cidrs: Vec<String>,
    pub announced_v4_total: u64,
    pub asn_registered_date: Option<String>,
    pub asn_age_years: Option<f64>,
    pub ptr_hostname: Option<String>,
    pub cf_radar_bot_pct: Option<f64>,
    pub geo_votes: Vec<GeoConsensusVote>,
}

/// Bundle returned by `fetch_ip_purity_readings` (all concurrent zero-key + optional-key sources).
#[derive(Debug, Clone, Default)]
pub struct PurityIntelBundle {
    pub readings: Vec<ReputationReading>,
    pub peeringdb: Option<PeeringDbInfo>,
    pub routing: AsnRoutingInfo,
    pub keyed_configured: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AsnCrossCheck {
    pub asn: Option<u64>,
    pub org: Option<String>,
    pub inferred_kind: AsnKind,
    pub hosting_tendency: f64,
    pub peeringdb_type: Option<String>,
    pub peeringdb_ratio: Option<String>,
    pub is_clean_consumer_isp: bool,
}

impl Default for AsnCrossCheck {
    fn default() -> Self {
        Self {
            asn: None,
            org: None,
            inferred_kind: AsnKind::Unknown,
            hosting_tendency: 0.0,
            peeringdb_type: None,
            peeringdb_ratio: None,
            is_clean_consumer_isp: false,
        }
    }
}

/// Letter grade derived from 0–100 purity score.
pub fn purity_grade(score: u8) -> &'static str {
    if score >= 95 {
        "S"
    } else if score >= 85 {
        "A"
    } else if score >= 70 {
        "B"
    } else if score >= 55 {
        "C"
    } else if score >= 40 {
        "D"
    } else {
        "F"
    }
}

fn parse_asn_u64(raw: Option<&str>) -> Option<u64> {
    let s = raw?.trim();
    let digits: String = s
        .trim_start_matches("AS")
        .trim_start_matches("as")
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

fn map_network_type(raw: Option<&str>) -> Option<NetworkType> {
    let s = raw?.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    if s.contains("datacenter")
        || s.contains("data center")
        || s.contains("hosting")
        || s.contains("cdn")
        || s.contains("content delivery")
        || s.contains("search engine")
        || s.contains("spider")
    {
        return Some(NetworkType::Datacenter);
    }
    if s.contains("residential")
        || s.contains("wireless")
        || s.contains("mobile")
        || s.contains("fixed line")
        || s == "isp"
        || s.contains("isp")
    {
        return Some(NetworkType::Residential);
    }
    if s.contains("business")
        || s.contains("commercial")
        || s.contains("education")
        || s.contains("government")
        || s.contains("banking")
    {
        return Some(NetworkType::Business);
    }
    None
}

fn map_asn_kind_str(raw: Option<&str>) -> Option<AsnKind> {
    let s = raw?.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    if s.contains("hosting") || s.contains("datacenter") || s.contains("cloud") {
        Some(AsnKind::Datacenter)
    } else if s.contains("cdn") || s.contains("content") {
        Some(AsnKind::Cdn)
    } else if s.contains("mobile") || s.contains("wireless") {
        Some(AsnKind::Mobile)
    } else if s.contains("cable/dsl/isp") || s.contains("residential") || s == "isp" {
        Some(AsnKind::IspResidential)
    } else if s.contains("nsp") || s.contains("backbone") || s.contains("transit") {
        Some(AsnKind::Backbone)
    } else if s.contains("education") || s.contains("government") || s.contains("research") {
        Some(AsnKind::Education)
    } else if s.contains("enterprise") || s.contains("business") || s.contains("commercial") {
        Some(AsnKind::Business)
    } else {
        None
    }
}

fn heuristic_network_type_from_geo(geo: Option<&ExitGeoInfo>) -> NetworkType {
    let Some(g) = geo else {
        return NetworkType::Unknown;
    };
    let combined = format!(
        "{} {} {}",
        g.org.as_deref().unwrap_or_default(),
        g.isp.as_deref().unwrap_or_default(),
        g.ip_type_hint.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();
    if combined.trim().is_empty() {
        return NetworkType::Unknown;
    }
    let dc_keywords = [
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
        "choopa",
        "cloudflare",
        "oracle",
        "alibaba",
        "tencent",
        "bandwagon",
        "it7",
        "datacenter",
        "hosting",
        "vps",
        "cloud",
        "机房",
        "数据中心",
    ];
    if dc_keywords.iter().any(|k| combined.contains(k)) {
        return NetworkType::Datacenter;
    }
    let res_keywords = [
        "comcast",
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
        "bt ",
        "virgin media",
        "deutsche telekom",
        "residential",
        "broadband",
        "telecom",
        "fiber",
        "cable",
    ];
    if res_keywords.iter().any(|k| combined.contains(k)) {
        return NetworkType::Residential;
    }
    NetworkType::Unknown
}

/// Well-known cloud / datacenter / CDN ASNs for authoritative ASN classification.
const KNOWN_DC_ASNS: &[u64] = &[
    16509, 14618, 15169, 396982, 8075, 14061, 63949, 20473, 24940, 16276, 31898, 45102, 132203,
    25820, 46844, 53667, 60068, 9009, 212238, 36352, 40676, 62567,
];
const KNOWN_CDN_ASNS: &[u64] = &[13335, 20940, 54113, 16625, 22822];

/// Infer ASN profile by cross-checking live BGP ASN (`ip.guide`), PeeringDB, announced IPv4 size,
/// RDAP registration age, known lists, org keywords, and database ASN hints.
pub fn infer_asn_cross_check(
    geo: Option<&ExitGeoInfo>,
    readings: &[ReputationReading],
    peeringdb: Option<&PeeringDbInfo>,
    routing: Option<&AsnRoutingInfo>,
) -> AsnCrossCheck {
    let asn = routing
        .and_then(|rt| rt.bgp_asn)
        .or_else(|| geo.and_then(|g| g.asn))
        .or_else(|| readings.iter().find_map(|r| r.asn));
    let org = routing
        .and_then(|rt| rt.bgp_org.clone())
        .or_else(|| geo.and_then(|g| g.org.clone().or_else(|| g.isp.clone())))
        .or_else(|| readings.iter().find_map(|r| r.asn_org.clone()));

    let mut w_isp = 0.0_f64;
    let mut w_mobile = 0.0_f64;
    let mut w_dc = 0.0_f64;
    let mut w_cdn = 0.0_f64;
    let mut w_backbone = 0.0_f64;
    let mut w_biz = 0.0_f64;
    let mut w_edu = 0.0_f64;

    if let Some(num) = asn {
        if KNOWN_DC_ASNS.contains(&num) {
            w_dc += 3.0;
        } else if KNOWN_CDN_ASNS.contains(&num) {
            w_cdn += 3.0;
        }
    }

    // Database ASN hints
    for r in readings.iter().filter(|r| r.ok) {
        if let Some(k) = r.asn_type_hint {
            let w = r.weight.max(0.5);
            match k {
                AsnKind::IspResidential => w_isp += w * 1.4,
                AsnKind::Mobile => w_mobile += w * 1.4,
                AsnKind::Datacenter => w_dc += w * 1.4,
                AsnKind::Cdn => w_cdn += w * 1.4,
                AsnKind::Backbone => w_backbone += w * 1.2,
                AsnKind::Business => w_biz += w * 1.1,
                AsnKind::Education => w_edu += w * 1.1,
                AsnKind::Unknown => {}
            }
        }
    }

    // PeeringDB self-reported network type & traffic ratio
    let mut pdb_type = None;
    let mut pdb_ratio = None;
    let mut mostly_inbound = false;
    if let Some(pdb) = peeringdb.filter(|p| p.found) {
        pdb_type = pdb.info_type.clone();
        pdb_ratio = pdb.info_ratio.clone();
        if let Some(k) = map_asn_kind_str(pdb.info_type.as_deref()) {
            match k {
                AsnKind::IspResidential => w_isp += 1.8,
                AsnKind::Mobile => w_mobile += 1.8,
                AsnKind::Datacenter => w_dc += 1.8,
                AsnKind::Cdn => w_cdn += 1.8,
                AsnKind::Backbone => w_backbone += 1.6,
                AsnKind::Business => w_biz += 1.4,
                AsnKind::Education => w_edu += 1.4,
                AsnKind::Unknown => {}
            }
        }
        if let Some(ref ratio) = pdb.info_ratio {
            let rl = ratio.to_ascii_lowercase();
            if rl.contains("mostly inbound") || rl.contains("heavy inbound") {
                w_isp += 0.9;
                mostly_inbound = true;
            } else if rl.contains("mostly outbound") || rl.contains("heavy outbound") {
                w_dc += 0.7;
                w_cdn += 0.5;
            }
        }
    }

    // Org / ASN name keywords
    if let Some(ref name) = org {
        let lower = name.to_ascii_lowercase();
        if ["cloud", "hosting", "datacenter", "vps", "server", "dedicated", "colo", "digitalocean", "vultr", "hetzner", "ovh", "linode", "amazon", "azure"]
            .iter()
            .any(|k| lower.contains(k))
        {
            w_dc += 1.4;
        }
        if ["cdn", "cloudflare", "fastly", "akamai", "edgecast"]
            .iter()
            .any(|k| lower.contains(k))
        {
            w_cdn += 1.4;
        }
        if ["backbone", "transit", "cogent", "he.net", "hurricane", "telia", "arelion", "gtt", "sdn"]
            .iter()
            .any(|k| lower.contains(k))
        {
            w_backbone += 1.0;
        }
        if ["broadband", "telecom", "comcast", "verizon", "charter", "spectrum", "cox", "bell", "rogers", "telus", "ntt", "kddi", "singtel", "vodafone", "telekom", "orange", "telefonica"]
            .iter()
            .any(|k| lower.contains(k))
        {
            w_isp += 1.3;
        }
        if ["mobile", "wireless", "cellular", "t-mobile"]
            .iter()
            .any(|k| lower.contains(k))
        {
            w_mobile += 1.3;
        }
    }

    // Small announced IPv4 space & young ASN registration age are strong indicators of VPS / hosting / proxy ASNs
    if let Some(rt) = routing {
        if rt.announced_v4_total > 0 && rt.announced_v4_total <= 4096 {
            w_dc += 1.2;
        } else if rt.announced_v4_total >= 1_000_000 {
            w_isp += 0.6;
        }
        if let Some(age) = rt.asn_age_years {
            if age < 5.0 {
                w_dc += 0.9;
            }
        }
    }

    let total = w_isp + w_mobile + w_dc + w_cdn + w_backbone + w_biz + w_edu;
    let hosting_tendency = if total > 0.0 {
        ((w_dc + w_cdn + 0.3 * w_backbone) / total).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let candidates = [
        (AsnKind::IspResidential, w_isp),
        (AsnKind::Mobile, w_mobile),
        (AsnKind::Datacenter, w_dc),
        (AsnKind::Cdn, w_cdn),
        (AsnKind::Backbone, w_backbone),
        (AsnKind::Business, w_biz),
        (AsnKind::Education, w_edu),
    ];
    let inferred_kind = candidates
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .filter(|(_, w)| *w > 0.0)
        .map(|(k, _)| *k)
        .unwrap_or(AsnKind::Unknown);

    let is_clean_consumer_isp = matches!(inferred_kind, AsnKind::IspResidential | AsnKind::Mobile)
        && hosting_tendency < 0.25
        && (mostly_inbound || w_isp + w_mobile >= 2.5);

    AsnCrossCheck {
        asn,
        org,
        inferred_kind,
        hosting_tendency,
        peeringdb_type: pdb_type,
        peeringdb_ratio: pdb_ratio,
        is_clean_consumer_isp,
    }
}

pub fn parse_ipapi_is_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "ipapi.is".to_owned(),
        weight: 0.95,
        ..Default::default()
    };
    if json.get("error").is_some() || json.get("ip").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.datacenter = json.get("is_datacenter").and_then(|v| v.as_bool());
    r.vpn = json.get("is_vpn").and_then(|v| v.as_bool());
    r.proxy = json.get("is_proxy").and_then(|v| v.as_bool());
    r.tor = json.get("is_tor").and_then(|v| v.as_bool());
    r.abusive = json.get("is_abuser").and_then(|v| v.as_bool());

    // Handle BOTH object (`{"asn": 979, "type": "isp"}`) and compact string (`"AS979 NetLab Global"`) shapes!
    let comp_type = json
        .get("company")
        .and_then(|c| c.get("type"))
        .and_then(|v| v.as_str());
    let asn_type = json
        .get("asn")
        .and_then(|a| a.get("type"))
        .and_then(|v| v.as_str());
    r.asn = json
        .get("asn")
        .and_then(|a| a.get("asn").and_then(|n| n.as_u64()).or_else(|| parse_asn_u64(a.as_str())));
    r.asn_org = json
        .get("company")
        .and_then(|c| c.get("name").and_then(|v| v.as_str()).or_else(|| c.as_str()))
        .map(str::to_owned);
    r.asn_type_hint = map_asn_kind_str(asn_type).or_else(|| map_asn_kind_str(comp_type));

    r.network_type = if r.datacenter == Some(true) {
        Some(NetworkType::Datacenter)
    } else if json.get("is_mobile").and_then(|v| v.as_bool()) == Some(true) {
        Some(NetworkType::Residential)
    } else {
        map_network_type(comp_type).or_else(|| map_network_type(asn_type))
    };

    if let Some(abuser_str) = json
        .get("company")
        .and_then(|c| c.get("abuser_score"))
        .and_then(|v| v.as_str())
    {
        let lower = abuser_str.to_ascii_lowercase();
        r.risk_score = if lower.contains("very high") {
            Some(90)
        } else if lower.contains("high") {
            Some(70)
        } else if lower.contains("elevated") {
            Some(45)
        } else if lower.contains("very low") {
            Some(3)
        } else if lower.contains("low") {
            Some(10)
        } else {
            None
        };
    }
    r
}

pub fn parse_ipquery_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "ipquery.io".to_owned(),
        weight: 0.80,
        ..Default::default()
    };
    if json.get("ip").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.asn = parse_asn_u64(json.get("isp").and_then(|i| i.get("asn")).and_then(|v| v.as_str()));
    r.asn_org = json
        .get("isp")
        .and_then(|i| i.get("org").or_else(|| i.get("isp")))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if let Some(risk) = json.get("risk") {
        r.vpn = risk.get("is_vpn").and_then(|v| v.as_bool());
        r.proxy = risk.get("is_proxy").and_then(|v| v.as_bool());
        r.tor = risk.get("is_tor").and_then(|v| v.as_bool());
        r.datacenter = risk.get("is_datacenter").and_then(|v| v.as_bool());
        r.risk_score = risk
            .get("risk_score")
            .and_then(|v| v.as_u64())
            .map(|n| n.min(100) as u8);
        if r.datacenter == Some(true) {
            r.network_type = Some(NetworkType::Datacenter);
        } else if risk.get("is_mobile").and_then(|v| v.as_bool()) == Some(true) {
            r.network_type = Some(NetworkType::Residential);
        }
    }
    r
}

pub fn parse_blackbox_v3_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "blackbox-v3".to_owned(),
        weight: 0.85,
        ..Default::default()
    };
    if json.get("ip").is_none() || json.get("error").is_some_and(|e| !e.is_null()) {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.asn = json
        .get("asn")
        .and_then(|a| a.get("number"))
        .and_then(|v| v.as_u64());
    r.asn_org = json
        .get("asn")
        .and_then(|a| a.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let cls = json
        .get("classification")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let sig = json.get("signals");

    let hosting = sig.and_then(|s| s.get("hosting")).and_then(|v| v.as_bool());
    let cloud = sig.and_then(|s| s.get("cloud")).and_then(|v| v.as_bool());
    let proxy = sig.and_then(|s| s.get("proxy")).and_then(|v| v.as_bool());
    let tor = sig.and_then(|s| s.get("tor")).and_then(|v| v.as_bool());
    let vpnasn = sig.and_then(|s| s.get("vpnasn")).and_then(|v| v.as_bool());
    let goodvpn = sig.and_then(|s| s.get("goodvpn")).and_then(|v| v.as_bool());
    let sfs = sig.and_then(|s| s.get("sfs_listed")).and_then(|v| v.as_bool());
    let sfs_toxic = sig.and_then(|s| s.get("sfs_toxic")).and_then(|v| v.as_bool());

    if cls != "unknown" {
        r.datacenter = Some(hosting == Some(true) || cloud == Some(true) || cls == "hosting");
        r.proxy = proxy;
        r.tor = tor;
        r.vpn = Some(vpnasn == Some(true) || goodvpn == Some(true) || cls == "vpn");
        if sfs == Some(true) || sfs_toxic == Some(true) {
            r.abusive = Some(true);
        }
    } else {
        // When classification is unknown, only record explicit positive signals
        if hosting == Some(true) || cloud == Some(true) {
            r.datacenter = Some(true);
        }
        if proxy == Some(true) {
            r.proxy = Some(true);
        }
        if tor == Some(true) {
            r.tor = Some(true);
        }
        if vpnasn == Some(true) || goodvpn == Some(true) {
            r.vpn = Some(true);
        }
    }

    r.network_type = match cls.as_str() {
        "hosting" => Some(NetworkType::Datacenter),
        "residential" | "mobile" => Some(NetworkType::Residential),
        "business" => Some(NetworkType::Business),
        _ => None,
    };
    if sig.and_then(|s| s.get("residentialasn")).and_then(|v| v.as_bool()) == Some(true) {
        r.asn_type_hint = Some(AsnKind::IspResidential);
    } else if sig.and_then(|s| s.get("mobileasn")).and_then(|v| v.as_bool()) == Some(true) {
        r.asn_type_hint = Some(AsnKind::Mobile);
    } else if sig.and_then(|s| s.get("businessasn")).and_then(|v| v.as_bool()) == Some(true) {
        r.asn_type_hint = Some(AsnKind::Business);
    } else if hosting == Some(true) || cloud == Some(true) {
        r.asn_type_hint = Some(AsnKind::Datacenter);
    }
    r.extra_note = Some(format!("class={cls}"));
    r
}

pub fn parse_ip_api_com_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "ip-api.com".to_owned(),
        weight: 0.85,
        ..Default::default()
    };
    if json.get("status").and_then(|v| v.as_str()) != Some("success") {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.asn = parse_asn_u64(json.get("as").and_then(|v| v.as_str()));
    r.asn_org = json
        .get("org")
        .or_else(|| json.get("isp"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    r.datacenter = json.get("hosting").and_then(|v| v.as_bool());
    r.proxy = json.get("proxy").and_then(|v| v.as_bool());
    let mobile = json.get("mobile").and_then(|v| v.as_bool());
    r.network_type = if r.datacenter == Some(true) {
        Some(NetworkType::Datacenter)
    } else if mobile == Some(true) {
        Some(NetworkType::Residential)
    } else {
        None
    };
    if mobile == Some(true) {
        r.asn_type_hint = Some(AsnKind::Mobile);
    }
    r
}

pub fn parse_netcoffee_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "net.coffee".to_owned(),
        weight: 0.65,
        ..Default::default()
    };
    if json.get("ip").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.datacenter = json.get("is_datacenter").and_then(|v| v.as_bool());
    r.vpn = json.get("is_vpn").and_then(|v| v.as_bool());
    r.proxy = json.get("is_proxy").and_then(|v| v.as_bool());
    r.tor = json.get("is_tor").and_then(|v| v.as_bool());
    let is_res = json.get("isResidential").and_then(|v| v.as_bool());
    let is_mob = json.get("is_mobile").and_then(|v| v.as_bool());
    let comp = json.get("company_type").and_then(|v| v.as_str());
    r.asn_type_hint = map_asn_kind_str(comp);
    r.network_type = if r.datacenter == Some(true) {
        Some(NetworkType::Datacenter)
    } else if is_res == Some(true) || is_mob == Some(true) {
        Some(NetworkType::Residential)
    } else {
        map_network_type(comp)
    };
    r
}

pub fn parse_shodan_internetdb_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "shodan".to_owned(),
        weight: 0.60,
        ..Default::default()
    };
    if json.get("detail").is_some() && json.get("ip").is_none() {
        r.status = "ok (no open ports)".to_owned();
        r.ok = true;
        return r;
    }
    if json.get("ip").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.open_ports = json
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_u64().and_then(|n| u16::try_from(n).ok()))
                .collect()
        })
        .unwrap_or_default();
    r.cves = json
        .get("vulns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .take(8)
                .collect()
        })
        .unwrap_or_default();

    let tags: Vec<String> = json
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(|s| s.to_ascii_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    if tags.iter().any(|t| t == "tor") {
        r.tor = Some(true);
    }
    if tags.iter().any(|t| t == "vpn") {
        r.vpn = Some(true);
    }
    if tags.iter().any(|t| t == "proxy") {
        r.proxy = Some(true);
    }
    if tags.iter().any(|t| t == "compromised" || t == "malware") {
        r.abusive = Some(true);
    }
    if tags.iter().any(|t| t == "cloud" || t == "cdn") {
        r.datacenter = Some(true);
        r.network_type = Some(NetworkType::Datacenter);
    }
    if !r.open_ports.is_empty() || !tags.is_empty() {
        let port_preview: Vec<String> = r.open_ports.iter().take(6).map(u16::to_string).collect();
        r.extra_note = Some(format!(
            "ports=[{}] tags=[{}] vulns={}",
            port_preview.join(","),
            tags.join(","),
            r.cves.len()
        ));
    }
    r
}

pub fn parse_stopforumspam_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "stopforumspam".to_owned(),
        weight: 0.70,
        ..Default::default()
    };
    let Some(ip_obj) = json.get("ip").and_then(|v| v.as_object()) else {
        r.status = "error".to_owned();
        return r;
    };
    r.status = "ok".to_owned();
    r.ok = true;
    let appears = ip_obj.get("appears").and_then(|v| v.as_u64()).unwrap_or(0) > 0;
    let conf = ip_obj
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
        .clamp(0.0, 100.0) as u8;
    if appears && conf >= 25 {
        r.abusive = Some(true);
        r.abuse_confidence = Some(conf);
    } else if !appears {
        r.abusive = Some(false);
    }
    r
}

pub fn parse_proxycheck_json(json: &Value, ip: &str) -> ReputationReading {
    let mut reading = ReputationReading {
        source_name: "proxycheck".to_owned(),
        weight: 1.05,
        ..Default::default()
    };
    let Some(root) = json.as_object() else {
        reading.status = "error: invalid json".to_owned();
        return reading;
    };
    let status_str = root
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !status_str.is_empty() && status_str != "ok" && status_str != "warning" {
        reading.status = format!("error: {status_str}");
        return reading;
    }

    let row = root.get(ip).and_then(|v| v.as_object()).or_else(|| {
        root.iter()
            .find(|(k, v)| {
                !matches!(k.as_str(), "status" | "message" | "node" | "query time")
                    && v.is_object()
            })
            .and_then(|(_, v)| v.as_object())
    });
    let Some(row) = row else {
        reading.status = "error: missing ip row".to_owned();
        return reading;
    };

    reading.status = "ok".to_owned();
    reading.ok = true;
    reading.asn = parse_asn_u64(row.get("asn").and_then(|v| v.as_str()));

    if let Some(raw_type) = row.get("type").and_then(|v| v.as_str()) {
        for part in raw_type.split([',', '/', '|']) {
            let p = part.trim().to_ascii_lowercase();
            if p.is_empty() {
                continue;
            }
            if p.contains("tor") {
                reading.tor = Some(true);
            } else if p.contains("vpn") {
                reading.vpn = Some(true);
            } else if p.contains("socks")
                || p.contains("proxy")
                || p == "http"
                || p == "https"
                || p.contains("scraper")
            {
                reading.proxy = Some(true);
            } else if p.contains("compromised") {
                reading.proxy = Some(true);
                reading.abusive = Some(true);
            } else if p.contains("host")
                || p.contains("datacenter")
                || p.contains("data center")
                || p == "cdn"
            {
                reading.datacenter = Some(true);
                reading.network_type = Some(NetworkType::Datacenter);
            } else if p.contains("business") || p.contains("commercial") {
                if reading.network_type != Some(NetworkType::Datacenter) {
                    reading.network_type = Some(NetworkType::Business);
                }
            } else if p.contains("residential") || p.contains("wireless") || p.contains("mobile") {
                if !matches!(
                    reading.network_type,
                    Some(NetworkType::Datacenter | NetworkType::Business)
                ) {
                    reading.network_type = Some(NetworkType::Residential);
                }
            }
        }
    }

    if let Some(proxy_flag) = row.get("proxy").and_then(|v| v.as_str()) {
        if proxy_flag.eq_ignore_ascii_case("yes") {
            if reading.tor != Some(true) && reading.vpn != Some(true) {
                reading.proxy = Some(true);
            }
        } else if proxy_flag.eq_ignore_ascii_case("no") {
            if reading.proxy != Some(true) {
                reading.proxy = Some(false);
            }
            if reading.vpn != Some(true) {
                reading.vpn = Some(false);
            }
            if reading.tor != Some(true) {
                reading.tor = Some(false);
            }
        }
    }

    if let Some(risk) = row.get("risk").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    }) {
        reading.risk_score = Some(risk.min(100) as u8);
    }

    reading
}

pub fn parse_abuseipdb_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "abuseipdb".to_owned(),
        weight: 1.15,
        ..Default::default()
    };
    let Some(data) = json.get("data").and_then(|v| v.as_object()) else {
        r.status = "error: missing data".to_owned();
        return r;
    };
    let Some(confidence) = data
        .get("abuseConfidenceScore")
        .and_then(|v| v.as_u64())
        .map(|v| v.min(100) as u8)
    else {
        r.status = "error: missing score".to_owned();
        return r;
    };

    let usage_type = map_network_type(data.get("usageType").and_then(|v| v.as_str()));
    r.status = "ok".to_owned();
    r.ok = true;
    r.network_type = usage_type;
    r.tor = data.get("isTor").and_then(|v| v.as_bool());
    r.datacenter = if usage_type == Some(NetworkType::Datacenter) {
        Some(true)
    } else {
        None
    };
    r.abusive = if confidence >= 25 {
        Some(true)
    } else if confidence == 0 {
        Some(false)
    } else {
        None
    };
    r.abuse_confidence = Some(confidence);
    r
}

pub fn parse_peeringdb_json(json: &Value) -> PeeringDbInfo {
    let Some(row) = json
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|a| a.first())
    else {
        return PeeringDbInfo::default();
    };
    PeeringDbInfo {
        found: true,
        name: row
            .get("name_long")
            .or_else(|| row.get("name"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        info_type: row
            .get("info_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && *s != "Not Disclosed")
            .map(str::to_owned),
        info_ratio: row
            .get("info_ratio")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && *s != "Not Disclosed")
            .map(str::to_owned),
        prefixes4: row.get("info_prefixes4").and_then(|v| v.as_u64()),
    }
}

pub fn parse_iplocate_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "iplocate.io".to_owned(),
        weight: 0.85,
        ..Default::default()
    };
    if json.get("ip").is_none() || json.get("error").is_some() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    if let Some(asn_obj) = json.get("asn") {
        r.asn = parse_asn_u64(asn_obj.get("asn").and_then(|v| v.as_str()));
        r.asn_org = asn_obj
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let asn_type = asn_obj.get("type").and_then(|v| v.as_str());
        r.asn_type_hint = map_asn_kind_str(asn_type);
        r.network_type = map_network_type(asn_type);
    }
    if let Some(priv_obj) = json.get("privacy") {
        r.vpn = priv_obj.get("is_vpn").and_then(|v| v.as_bool());
        r.proxy = priv_obj.get("is_proxy").and_then(|v| v.as_bool());
        r.tor = priv_obj.get("is_tor").and_then(|v| v.as_bool());
        r.datacenter = priv_obj.get("is_hosting").and_then(|v| v.as_bool());
        r.abusive = priv_obj.get("is_abuser").and_then(|v| v.as_bool());
        if r.datacenter == Some(true) {
            r.network_type = Some(NetworkType::Datacenter);
        }
    }
    r
}

pub fn parse_geoiplookup_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "geoiplookup".to_owned(),
        weight: 0.55,
        ..Default::default()
    };
    if json.get("ip").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.asn = parse_asn_u64(json.get("asn").and_then(|v| v.as_str()));
    r.asn_org = json
        .get("asn_org")
        .or_else(|| json.get("isp"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let conn = json.get("connection_type").and_then(|v| v.as_str());
    r.network_type = map_network_type(conn);
    if let Some(c) = conn.filter(|s| !s.is_empty()) {
        r.extra_note = Some(format!("conn={c}"));
    }
    r
}

pub fn parse_freeipapi_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "freeipapi".to_owned(),
        weight: 0.70,
        ..Default::default()
    };
    if json.get("ipAddress").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    r.proxy = json.get("isProxy").and_then(|v| v.as_bool());
    r.asn = json
        .get("asn")
        .and_then(|v| v.as_u64().or_else(|| parse_asn_u64(v.as_str())));
    r.asn_org = json
        .get("asnOrganization")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    r
}

pub fn parse_onionoo_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "tor-onionoo".to_owned(),
        weight: 1.0,
        ..Default::default()
    };
    let relays = json.get("relays").and_then(|v| v.as_array());
    let bridges = json.get("bridges").and_then(|v| v.as_array());
    if relays.is_none() && bridges.is_none() {
        r.status = "error".to_owned();
        return r;
    }
    let relay_count = relays.map(|a| a.len()).unwrap_or(0);
    let bridge_count = bridges.map(|a| a.len()).unwrap_or(0);
    r.status = "ok".to_owned();
    r.ok = true;
    if relay_count > 0 || bridge_count > 0 {
        r.tor = Some(true);
        r.extra_note = Some(format!("relays={relay_count} bridges={bridge_count}"));
    } else {
        r.tor = Some(false);
    }
    r
}

pub fn parse_otx_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "otx".to_owned(),
        weight: 0.75,
        ..Default::default()
    };
    let Some(pulse_info) = json.get("pulse_info") else {
        r.status = "error".to_owned();
        return r;
    };
    let count = pulse_info
        .get("count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    r.status = "ok".to_owned();
    r.ok = true;
    r.otx_pulses = Some(count);
    r.asn = parse_asn_u64(json.get("asn").and_then(|v| v.as_str()));
    if count >= 3 {
        r.abusive = Some(true);
    } else if count == 0 {
        r.abusive = Some(false);
    }
    if count > 0 {
        r.extra_note = Some(format!("pulses={count}"));
    }
    r
}

/// Parse `https://ip.guide/{ip}` authoritative BGP routing info: `(asn, org, prefix, rir)`.
pub fn parse_ip_guide_json(json: &Value) -> (Option<u64>, Option<String>, Option<String>, Option<String>) {
    let Some(net) = json.get("network") else {
        return (None, None, None, None);
    };
    let prefix = net
        .get("cidr")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let as_obj = net.get("autonomous_system");
    let asn = as_obj.and_then(|a| a.get("asn")).and_then(|v| v.as_u64());
    let org = as_obj
        .and_then(|a| {
            a.get("organization")
                .or_else(|| a.get("name"))
                .and_then(|v| v.as_str())
        })
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let rir = as_obj
        .and_then(|a| a.get("rir"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    (asn, org, prefix, rir)
}

/// Parse RIPEstat `announced-prefixes` JSON -> `(ipv4_cidrs, deduplicated_ipv4_count)`.
pub fn parse_ripestat_announced_prefixes_json(json: &Value) -> (Vec<String>, u64) {
    let Some(arr) = json
        .get("data")
        .and_then(|d| d.get("prefixes"))
        .and_then(|p| p.as_array())
    else {
        return (Vec::new(), 0);
    };
    let cidrs: Vec<String> = arr
        .iter()
        .filter_map(|row| row.get("prefix").and_then(|v| v.as_str()))
        .filter(|p| !p.contains(':')) // IPv4 prefixes for density & size calc
        .map(str::to_owned)
        .collect();
    let merged = cidr_lists::merge_ipv4_cidrs(&cidrs);
    let total: u64 = merged
        .iter()
        .map(|&(s, e)| (e as u64 - s as u64) + 1)
        .sum();
    (cidrs, total)
}

/// Parse RDAP `autnum/{asn}` registration event date -> `(date_yyyy_mm_dd, age_years)`.
pub fn parse_rdap_asn_registration_json(json: &Value) -> (Option<String>, Option<f64>) {
    let Some(events) = json.get("events").and_then(|e| e.as_array()) else {
        return (None, None);
    };
    for ev in events {
        let action = ev
            .get("eventAction")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if action.eq_ignore_ascii_case("registration") {
            if let Some(raw_date) = ev.get("eventDate").and_then(|v| v.as_str()) {
                let date_part = raw_date.get(0..10).unwrap_or(raw_date).to_owned();
                if let Ok(dt) = chrono::NaiveDate::parse_from_str(&date_part, "%Y-%m-%d") {
                    let today = chrono::Utc::now().date_naive();
                    let days = (today - dt).num_days().max(0) as f64;
                    return (Some(date_part), Some(days / 365.25));
                }
                return (Some(date_part), None);
            }
        }
    }
    (None, None)
}

/// Parse Cloudflare Radar 28d `bot_class` summary -> bot traffic percentage (`0.0..=100.0`).
pub fn parse_cf_radar_bot_json(json: &Value) -> Option<f64> {
    let summary = json.get("result")?.get("summary_0")?;
    summary
        .get("bot")
        .or_else(|| summary.get("BOT"))
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
        .map(|v| v.clamp(0.0, 100.0))
}

pub fn parse_greynoise_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "greynoise".to_owned(),
        weight: 0.90,
        ..Default::default()
    };
    if json.get("ip").is_none() && json.get("noise").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    let noise = json.get("noise").and_then(|v| v.as_bool()).unwrap_or(false);
    let riot = json.get("riot").and_then(|v| v.as_bool()).unwrap_or(false);
    let cls = json
        .get("classification")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    if cls == "malicious" {
        r.abusive = Some(true);
        r.risk_score = Some(85);
    } else if noise && !riot {
        r.abusive = Some(true);
        r.risk_score = Some(55);
    } else {
        r.abusive = Some(false);
    }
    r.extra_note = Some(format!("noise={noise} riot={riot} class={cls}"));
    r
}

pub fn parse_crowdsec_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "crowdsec".to_owned(),
        weight: 0.95,
        ..Default::default()
    };
    if json.get("ip").is_none() && json.get("message").is_some() {
        r.status = "ok (not listed)".to_owned();
        r.ok = true;
        r.abusive = Some(false);
        return r;
    }
    if json.get("ip").is_none() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    let rep = json
        .get("reputation")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let score = json
        .get("ip_range_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if rep == "malicious" || score >= 4 {
        r.abusive = Some(true);
        r.risk_score = Some(85);
    } else if rep == "suspicious" || score >= 2 {
        r.abusive = Some(true);
        r.risk_score = Some(55);
    } else {
        r.abusive = Some(false);
    }
    r.extra_note = Some(format!("rep={rep} range_score={score}"));
    r
}

pub fn parse_virustotal_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "virustotal".to_owned(),
        weight: 0.95,
        ..Default::default()
    };
    let Some(stats) = json
        .get("data")
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("last_analysis_stats"))
    else {
        r.status = "error".to_owned();
        return r;
    };
    r.status = "ok".to_owned();
    r.ok = true;
    let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
    let suspicious = stats.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0);
    if malicious >= 2 {
        r.abusive = Some(true);
        r.risk_score = Some((40 + malicious * 12).min(100) as u8);
    } else if malicious == 1 || suspicious >= 2 {
        r.abusive = Some(true);
        r.risk_score = Some(45);
    } else {
        r.abusive = Some(false);
    }
    r.extra_note = Some(format!("mal={malicious} susp={suspicious}"));
    r
}

pub fn parse_ipregistry_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "ipregistry".to_owned(),
        weight: 1.05,
        ..Default::default()
    };
    if json.get("ip").is_none() || json.get("code").is_some() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    if let Some(conn) = json.get("connection") {
        r.asn = conn.get("asn").and_then(|v| v.as_u64());
        r.asn_org = conn
            .get("organization")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let ctype = conn.get("type").and_then(|v| v.as_str());
        r.asn_type_hint = map_asn_kind_str(ctype);
        r.network_type = map_network_type(ctype);
    }
    if let Some(sec) = json.get("security") {
        r.vpn = sec.get("is_vpn").and_then(|v| v.as_bool());
        r.proxy = sec.get("is_proxy").and_then(|v| v.as_bool());
        r.tor = sec
            .get("is_tor")
            .and_then(|v| v.as_bool())
            .or_else(|| sec.get("is_tor_exit").and_then(|v| v.as_bool()));
        r.datacenter = sec.get("is_cloud_provider").and_then(|v| v.as_bool());
        let abuser = sec.get("is_abuser").and_then(|v| v.as_bool()).unwrap_or(false);
        let attacker = sec
            .get("is_attacker")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        r.abusive = Some(abuser || attacker);
        if r.datacenter == Some(true) {
            r.network_type = Some(NetworkType::Datacenter);
        }
    }
    r
}

pub fn parse_ipdata_json(json: &Value) -> ReputationReading {
    let mut r = ReputationReading {
        source_name: "ipdata".to_owned(),
        weight: 1.05,
        ..Default::default()
    };
    if json.get("ip").is_none() || json.get("message").is_some() {
        r.status = "error".to_owned();
        return r;
    }
    r.status = "ok".to_owned();
    r.ok = true;
    if let Some(asn_obj) = json.get("asn") {
        r.asn = parse_asn_u64(asn_obj.get("asn").and_then(|v| v.as_str()));
        r.asn_org = asn_obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let atype = asn_obj.get("type").and_then(|v| v.as_str());
        r.asn_type_hint = map_asn_kind_str(atype);
        r.network_type = map_network_type(atype);
    }
    if let Some(th) = json.get("threat") {
        r.tor = th.get("is_tor").and_then(|v| v.as_bool());
        r.proxy = th.get("is_proxy").and_then(|v| v.as_bool());
        r.datacenter = th.get("is_datacenter").and_then(|v| v.as_bool());
        let abuser = th
            .get("is_known_abuser")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let attacker = th
            .get("is_known_attacker")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        r.abusive = Some(abuser || attacker);
        if r.datacenter == Some(true) {
            r.network_type = Some(NetworkType::Datacenter);
        }
    }
    r
}

pub fn is_public_ip(raw: &str) -> bool {
    match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_broadcast()
        }
        Ok(IpAddr::V6(v6)) => {
            let seg0 = v6.segments()[0];
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (seg0 & 0xffc0) != 0xfe80
                && (seg0 & 0xfe00) != 0xfc00
        }
        Err(_) => false,
    }
}

/// Weighted hit ratio `H / (H + N)` across responding sources that explicitly reported the field.
fn weighted_flag_ratio(
    readings: &[ReputationReading],
    extract: impl Fn(&ReputationReading) -> Option<bool>,
) -> (Option<f64>, Vec<String>, bool) {
    let mut hit_w = 0.0_f64;
    let mut miss_w = 0.0_f64;
    let mut hitters = Vec::new();
    let mut saw_true = false;
    let mut saw_false = false;

    for r in readings.iter().filter(|r| r.ok) {
        let w = if r.weight > 0.0 { r.weight } else { 1.0 };
        match extract(r) {
            Some(true) => {
                hit_w += w;
                saw_true = true;
                hitters.push(r.source_name.clone());
            }
            Some(false) => {
                miss_w += w;
                saw_false = true;
            }
            None => {}
        }
    }

    if hit_w + miss_w == 0.0 {
        (None, hitters, false)
    } else {
        (Some(hit_w / (hit_w + miss_w)), hitters, saw_true && saw_false)
    }
}

fn dominant_network_type(
    readings: &[ReputationReading],
    geo: Option<&ExitGeoInfo>,
    asn_check: &AsnCrossCheck,
) -> (NetworkType, f64) {
    let mut dc_w = 0.0;
    let mut biz_w = 0.0;
    let mut res_w = 0.0;
    for r in readings.iter().filter(|r| r.ok) {
        let w = if r.weight > 0.0 { r.weight } else { 1.0 };
        match r.network_type {
            Some(NetworkType::Datacenter) => dc_w += w,
            Some(NetworkType::Business) => biz_w += w,
            Some(NetworkType::Residential) => res_w += w,
            _ => {}
        }
    }
    let total = dc_w + biz_w + res_w;
    let res_share = if total > 0.0 { res_w / total } else { 0.0 };

    let chosen = if dc_w > 0.0 && dc_w >= biz_w && dc_w >= res_w {
        NetworkType::Datacenter
    } else if biz_w > 0.0 && biz_w >= res_w {
        NetworkType::Business
    } else if res_w > 0.0 {
        NetworkType::Residential
    } else {
        match asn_check.inferred_kind {
            AsnKind::Datacenter | AsnKind::Cdn => NetworkType::Datacenter,
            AsnKind::IspResidential | AsnKind::Mobile => NetworkType::Residential,
            AsnKind::Business | AsnKind::Education => NetworkType::Business,
            _ => heuristic_network_type_from_geo(geo),
        }
    };
    (chosen, res_share)
}

/// Multi-source weighted IP purity + ASN cross-check evaluator.
/// Calibrated around baseline 92 (+ up to 8 positive evidence bonus, capped at 100)
/// minus category-capped deductions so unverified/ambiguous IPs never inflate to 100/100.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_multi_source_purity(
    ip: Option<&str>,
    geo: Option<&ExitGeoInfo>,
    readings: &[ReputationReading],
    peeringdb: Option<&PeeringDbInfo>,
    routing: Option<&AsnRoutingInfo>,
    dnsbl: Option<&DnsblSummary>,
    cidr: Option<&CidrSummary>,
    keyed_configured: bool,
    lang: Lang,
    duration_ms: u64,
) -> (IpPurityReport, CheckItem) {
    let pc_status = readings
        .iter()
        .find(|r| r.source_name == "proxycheck")
        .map(|r| r.status.clone())
        .unwrap_or_else(|| "unconfigured".to_owned());
    let ab_status = readings
        .iter()
        .find(|r| r.source_name == "abuseipdb")
        .map(|r| r.status.clone())
        .unwrap_or_else(|| "unconfigured".to_owned());

    let title = i18n::check_title("ip-purity", lang).unwrap_or("Exit IP Purity Score");
    let Some(clean_ip) = ip.map(str::trim).filter(|s| !s.is_empty()) else {
        let rep = IpPurityReport {
            ip: None,
            purity: None,
            band: None,
            network_type: NetworkType::Unknown,
            flags: IpPurityFlags::default(),
            deductions: Vec::new(),
            sources_configured: keyed_configured,
            proxycheck_status: pc_status,
            abuseipdb_status: ab_status,
        };
        let item = CheckItem::new(
            "ip-purity",
            CheckCategory::NetworkLeak,
            title,
            CheckState::Unknown,
            pick(
                lang,
                "未获取到出口 IP，跳过纯净度评估",
                "No exit IP observed; skipped IP purity evaluation",
            ),
        )
        .with_duration(duration_ms);
        return (rep, item);
    };

    if !is_public_ip(clean_ip) {
        let rep = IpPurityReport {
            ip: Some(clean_ip.to_owned()),
            purity: None,
            band: None,
            network_type: NetworkType::Unknown,
            flags: IpPurityFlags::default(),
            deductions: Vec::new(),
            sources_configured: keyed_configured,
            proxycheck_status: "skipped (private IP)".to_owned(),
            abuseipdb_status: "skipped (private IP)".to_owned(),
        };
        let item = CheckItem::new(
            "ip-purity",
            CheckCategory::NetworkLeak,
            title,
            CheckState::Warn,
            pick(
                lang,
                "出口地址为内网/保留地址，无法评估公网纯净度",
                "Observed IP is private/reserved; cannot evaluate public purity",
            ),
        )
        .with_duration(duration_ms);
        return (rep, item);
    }

    let ok_sources: Vec<&ReputationReading> = readings.iter().filter(|r| r.ok).collect();
    let asn_check = infer_asn_cross_check(geo, readings, peeringdb, routing);

    let mut details = vec![format!(
        "{}: {clean_ip}",
        pick(lang, "检测目标 IP", "Evaluated IP")
    )];
    if let Some(g) = geo {
        let loc = [
            g.country_code.as_deref().unwrap_or("?"),
            g.city.as_deref().unwrap_or(""),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" / ");
        let isp = asn_check
            .org
            .as_deref()
            .or(g.isp.as_deref())
            .or(g.org.as_deref())
            .unwrap_or("-");
        let asn = asn_check
            .asn
            .map(|a| format!("AS{a}"))
            .unwrap_or_else(|| "-".to_owned());
        details.push(format!(
            "{}: {loc} · {asn} · {isp}",
            pick(lang, "地理与运营商", "Geo & ASN")
        ));
    } else if let Some(asn_num) = asn_check.asn {
        details.push(format!(
            "{}: AS{asn_num} · {}",
            pick(lang, "BGP 宣告 ASN", "Announcing ASN"),
            asn_check.org.as_deref().unwrap_or("-")
        ));
    }

    // BGP Routing & Registration details (ip.guide + RIPEstat + RDAP + PTR + CF Radar)
    if let Some(rt) = routing {
        let mut rt_parts = Vec::new();
        if let Some(ref pfx) = rt.bgp_prefix {
            rt_parts.push(format!("BGP {pfx}"));
        }
        if let Some(ref rir) = rt.bgp_rir {
            rt_parts.push(format!("RIR={rir}"));
        }
        if rt.announced_v4_total > 0 {
            rt_parts.push(format!(
                "{}={}",
                pick(lang, "宣告 IPv4 总量", "Announced IPv4"),
                rt.announced_v4_total
            ));
        }
        if let Some(ref dt) = rt.asn_registered_date {
            if let Some(age) = rt.asn_age_years {
                rt_parts.push(format!(
                    "{}={dt} ({age:.1}y)",
                    pick(lang, "ASN 注册", "ASN Reg")
                ));
            } else {
                rt_parts.push(format!("{}={dt}", pick(lang, "ASN 注册", "ASN Reg")));
            }
        }
        if let Some(ref ptr) = rt.ptr_hostname {
            rt_parts.push(format!("PTR={ptr}"));
        } else {
            rt_parts.push(format!("PTR={}", pick(lang, "无", "none")));
        }
        if let Some(bot_pct) = rt.cf_radar_bot_pct {
            rt_parts.push(format!("CF Radar Bot={bot_pct:.1}%"));
        }
        if !rt_parts.is_empty() {
            details.push(format!(
                "{}: {}",
                pick(lang, "注册与路由画像", "Routing & Registration"),
                rt_parts.join(" · ")
            ));
        }
        // Multi-source GeoIP consensus summary
        let valid_geo: Vec<&GeoConsensusVote> = rt
            .geo_votes
            .iter()
            .filter(|v| v.country_code.as_deref().is_some_and(|c| !c.is_empty()))
            .collect();
        if !valid_geo.is_empty() {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for v in &valid_geo {
                if let Some(ref cc) = v.country_code {
                    *counts.entry(cc.to_ascii_uppercase()).or_insert(0) += 1;
                }
            }
            let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            let tally: Vec<String> = sorted
                .iter()
                .map(|(cc, n)| format!("{cc} ×{n}"))
                .collect();
            let src_names: Vec<&str> = valid_geo.iter().map(|v| v.source.as_str()).collect();
            details.push(format!(
                "{} ({}/{}): {} [{}]",
                pick(lang, "多源地理共识", "Multi-Source Geo Consensus"),
                valid_geo.len(),
                rt.geo_votes.len(),
                tally.join(" · "),
                src_names.join(", ")
            ));
        }
    }

    // ASN Cross-Check summary line
    let pdb_note = match (&asn_check.peeringdb_type, &asn_check.peeringdb_ratio) {
        (Some(t), Some(r)) => format!(" · PeeringDB: {t} ({r})"),
        (Some(t), None) => format!(" · PeeringDB: {t}"),
        _ => String::new(),
    };
    details.push(format!(
        "{}: {} ({}: {:.0}%){pdb_note}",
        pick(lang, "ASN 交叉画像", "ASN Profile"),
        asn_check.inferred_kind.label(lang),
        pick(lang, "机房倾向", "Hosting tendency"),
        asn_check.hosting_tendency * 100.0
    ));

    let source_summary: Vec<String> = readings
        .iter()
        .map(|r| {
            if let Some(ref extra) = r.extra_note {
                format!("{}:{}({})", r.source_name, r.status, extra)
            } else {
                format!("{}:{}", r.source_name, r.status)
            }
        })
        .collect();
    if !source_summary.is_empty() {
        details.push(format!(
            "{} ({}/{}): {}",
            pick(lang, "多源数据库", "Intel Sources"),
            ok_sources.len(),
            readings.len(),
            source_summary.join(" · ")
        ));
    }

    if ok_sources.is_empty() {
        let h_type = heuristic_network_type_from_geo(geo);
        let rep = IpPurityReport {
            ip: Some(clean_ip.to_owned()),
            purity: None,
            band: None,
            network_type: h_type,
            flags: IpPurityFlags {
                datacenter: if h_type == NetworkType::Datacenter {
                    Some(true)
                } else {
                    None
                },
                ..Default::default()
            },
            deductions: Vec::new(),
            sources_configured: keyed_configured,
            proxycheck_status: pc_status,
            abuseipdb_status: ab_status,
        };
        let item = CheckItem::new(
            "ip-purity",
            CheckCategory::NetworkLeak,
            title,
            if h_type == NetworkType::Datacenter {
                CheckState::Warn
            } else {
                CheckState::Unknown
            },
            pick(
                lang,
                "所有公网 IP 情报源均暂不可达，已留空纯净度分（绝不虚构高分）",
                "All IP intelligence providers unreachable; purity withheld (never fabricated)",
            ),
        )
        .with_details(details)
        .with_duration(duration_ms);
        return (rep, item);
    }

    let (dc_ratio, dc_hitters, dc_conflict) = weighted_flag_ratio(readings, |r| r.datacenter);
    let (proxy_ratio, proxy_hitters, proxy_conflict) = weighted_flag_ratio(readings, |r| r.proxy);
    let (vpn_ratio, vpn_hitters, vpn_conflict) = weighted_flag_ratio(readings, |r| r.vpn);
    let (tor_ratio, tor_hitters, _) = weighted_flag_ratio(readings, |r| r.tor);
    let (abuse_ratio, abuse_hitters, _) = weighted_flag_ratio(readings, |r| r.abusive);

    let (mut network_type, res_share) = dominant_network_type(readings, geo, &asn_check);
    if dc_ratio.is_some_and(|e| e >= 0.5) || cidr.is_some_and(|c| c.datacenter_hit) {
        network_type = NetworkType::Datacenter;
    }

    let tor_confirmed = tor_ratio.is_some_and(|e| e > 0.0)
        || dnsbl.is_some_and(DnsblSummary::tor_hit)
        || cidr.is_some_and(|c| c.tor_hit);
    let proxy_flag = proxy_ratio.map(|e| e >= 0.30).or_else(|| {
        if dnsbl.is_some_and(DnsblSummary::proxy_hit)
            || cidr.is_some_and(|c| !c.proxy_hits.is_empty())
        {
            Some(true)
        } else {
            None
        }
    });
    let vpn_flag = vpn_ratio.map(|e| e >= 0.30).or_else(|| {
        if cidr.is_some_and(|c| c.vpn_hit) {
            Some(true)
        } else {
            None
        }
    });
    let dc_flag = dc_ratio.map(|e| e >= 0.25).or_else(|| {
        if network_type == NetworkType::Datacenter {
            Some(true)
        } else {
            None
        }
    });
    let abuse_flag = abuse_ratio.map(|e| e > 0.0);

    // Calibrated baseline 92: clean IP without strong positive evidence stays at A (92), not S (100)
    const BASELINE: i32 = 92;
    let mut deductions: Vec<PurityDeduction> = Vec::new();

    // Light ASN buffer (15%) ONLY for verified consumer ISPs on noisy single-database flags
    let asn_attenuation = if asn_check.is_clean_consumer_isp {
        0.85
    } else {
        1.0
    };

    // --- Category A: Anonymization (cap 50) ---
    let mut cat_anon = 0i32;
    if tor_confirmed {
        cat_anon += 50;
        let mut src = tor_hitters;
        if dnsbl.is_some_and(DnsblSummary::tor_hit) {
            src.push("dnsbl-tor".to_owned());
        }
        if cidr.is_some_and(|c| c.tor_hit) {
            src.push("cidr-tor".to_owned());
        }
        deductions.push(PurityDeduction {
            code: "tor".to_owned(),
            label_zh: "Tor 匿名出口节点".to_owned(),
            label_en: "Tor anonymous exit node".to_owned(),
            points: -50,
            source: src.join("+"),
        });
    } else {
        let p_e = proxy_ratio.unwrap_or(0.0).max(
            if dnsbl.is_some_and(DnsblSummary::proxy_hit)
                || cidr.is_some_and(|c| !c.proxy_hits.is_empty())
            {
                0.85
            } else {
                0.0
            },
        );
        let v_e = vpn_ratio
            .unwrap_or(0.0)
            .max(if cidr.is_some_and(|c| c.vpn_hit) { 0.65 } else { 0.0 });
        if p_e > 0.0 && v_e > 0.0 {
            let cut = ((30.0 * p_e.max(v_e) + 10.0 * p_e.min(v_e)) * asn_attenuation).round() as i32;
            if cut > 0 {
                cat_anon += cut;
                let mut src = proxy_hitters;
                for h in vpn_hitters {
                    if !src.contains(&h) {
                        src.push(h);
                    }
                }
                deductions.push(PurityDeduction {
                    code: "proxy_vpn".to_owned(),
                    label_zh: format!(
                        "代理 / VPN 匿名标记 (Proxy {:.0}% · VPN {:.0}%)",
                        p_e * 100.0,
                        v_e * 100.0
                    ),
                    label_en: format!(
                        "Proxy / VPN flagged (Proxy {:.0}% · VPN {:.0}%)",
                        p_e * 100.0,
                        v_e * 100.0
                    ),
                    points: -(cut as i16),
                    source: if src.is_empty() {
                        "dnsbl/cidr".to_owned()
                    } else {
                        src.join("+")
                    },
                });
            }
        } else if p_e > 0.0 {
            let cut = (28.0 * p_e * asn_attenuation).round() as i32;
            if cut > 0 {
                cat_anon += cut;
                deductions.push(PurityDeduction {
                    code: "proxy".to_owned(),
                    label_zh: format!("代理节点标记 (加权占比 {:.0}%)", p_e * 100.0),
                    label_en: format!("Proxy flagged ({:.0}% weighted)", p_e * 100.0),
                    points: -(cut as i16),
                    source: if proxy_hitters.is_empty() {
                        "dnsbl/cidr".to_owned()
                    } else {
                        proxy_hitters.join("+")
                    },
                });
            }
        } else if v_e > 0.0 {
            let cut = (26.0 * v_e * asn_attenuation).round() as i32;
            if cut > 0 {
                cat_anon += cut;
                deductions.push(PurityDeduction {
                    code: "vpn".to_owned(),
                    label_zh: format!("VPN 出口标记 (加权占比 {:.0}%)", v_e * 100.0),
                    label_en: format!("VPN exit flagged ({:.0}% weighted)", v_e * 100.0),
                    points: -(cut as i16),
                    source: if vpn_hitters.is_empty() {
                        "cidr".to_owned()
                    } else {
                        vpn_hitters.join("+")
                    },
                });
            }
        }
    }
    cat_anon = cat_anon.min(50);

    // --- Category B: Network Type & ASN Cross-Check (cap 25) ---
    let mut cat_net = 0i32;
    if let Some(e) = dc_ratio.filter(|&e| e > 0.0) {
        let cut = (22.0 * e * asn_attenuation).round().max(1.0) as i32;
        cat_net += cut;
        deductions.push(PurityDeduction {
            code: "datacenter".to_owned(),
            label_zh: format!("数据中心 / 机房标记 (加权占比 {:.0}%)", e * 100.0),
            label_en: format!("Datacenter / hosting flagged ({:.0}% weighted)", e * 100.0),
            points: -(cut as i16),
            source: dc_hitters.join("+"),
        });
    } else if matches!(asn_check.inferred_kind, AsnKind::Datacenter | AsnKind::Cdn) {
        let cut = (9.0 * asn_check.hosting_tendency).round().max(2.0) as i32;
        cat_net += cut;
        deductions.push(PurityDeduction {
            code: "asn_hosting".to_owned(),
            label_zh: format!("所属 ASN 推断为 {}", asn_check.inferred_kind.label(Lang::Zh)),
            label_en: format!("Announcing ASN inferred as {}", asn_check.inferred_kind.label(Lang::En)),
            points: -(cut as i16),
            source: "asn-crosscheck".to_owned(),
        });
    } else if network_type == NetworkType::Business {
        cat_net += 6;
        deductions.push(PurityDeduction {
            code: "business".to_owned(),
            label_zh: "商业 / 非住宅宽带线路".to_owned(),
            label_en: "Business / commercial network".to_owned(),
            points: -6,
            source: "multi-source".to_owned(),
        });
    }

    // ASN Cross-Check Mismatch: IP databases claim Residential, yet announcing ASN is Datacenter/CDN!
    if res_share >= 0.5 && matches!(asn_check.inferred_kind, AsnKind::Datacenter | AsnKind::Cdn) {
        let cut = (8.0 * asn_check.hosting_tendency).round().max(3.0) as i32;
        cat_net += cut;
        deductions.push(PurityDeduction {
            code: "asn_mismatch".to_owned(),
            label_zh: format!(
                "ASN 交叉核对异常：数据库标为住宅，但宣告 ASN 为 {}",
                asn_check.inferred_kind.label(Lang::Zh)
            ),
            label_en: format!(
                "ASN mismatch: IP labeled residential, but announcing ASN is {}",
                asn_check.inferred_kind.label(Lang::En)
            ),
            points: -(cut as i16),
            source: "asn-crosscheck".to_owned(),
        });
    }
    // Young ASN (< 5 years) & missing reverse PTR on non-consumer networks
    if let Some(rt) = routing {
        if let Some(age) = rt.asn_age_years.filter(|&a| a < 5.0) {
            cat_net += 2;
            deductions.push(PurityDeduction {
                code: "young_asn".to_owned(),
                label_zh: format!(
                    "所属 ASN 注册时间较新（{age:.1} 年，注册于 {}）",
                    rt.asn_registered_date.as_deref().unwrap_or("?")
                ),
                label_en: format!(
                    "Young announcing ASN ({age:.1} yrs, registered {})",
                    rt.asn_registered_date.as_deref().unwrap_or("?")
                ),
                points: -2,
                source: "rdap".to_owned(),
            });
        }
        if rt.ptr_hostname.is_none() && !asn_check.is_clean_consumer_isp {
            cat_net += 1;
            deductions.push(PurityDeduction {
                code: "no_ptr".to_owned(),
                label_zh: "未配置反向 DNS (PTR / rDNS) 记录".to_owned(),
                label_en: "No reverse DNS (PTR / rDNS) record".to_owned(),
                points: -1,
                source: "doh-ptr".to_owned(),
            });
        }
        // Geo-consensus split penalty (if >= 4 GeoIP sources respond and < 75% agree on one country)
        let valid_geo: Vec<&str> = rt
            .geo_votes
            .iter()
            .filter_map(|v| v.country_code.as_deref())
            .filter(|s| !s.is_empty())
            .collect();
        if valid_geo.len() >= 4 {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for cc in &valid_geo {
                *counts.entry(cc.to_ascii_uppercase()).or_insert(0) += 1;
            }
            let max_agree = counts.values().copied().max().unwrap_or(0);
            if counts.len() >= 2 && (max_agree as f64 / valid_geo.len() as f64) < 0.75 {
                cat_net += 2;
                deductions.push(PurityDeduction {
                    code: "geo_split".to_owned(),
                    label_zh: format!(
                        "多源 GeoIP 国家定位存在分歧（主共识仅 {}/{}）",
                        max_agree,
                        valid_geo.len()
                    ),
                    label_en: format!(
                        "Multi-source GeoIP country disagreement ({}/{} consensus)",
                        max_agree,
                        valid_geo.len()
                    ),
                    points: -2,
                    source: "geo-consensus".to_owned(),
                });
            }
        }
    }
    cat_net = cat_net.min(25);

    // --- Category C: Abuse, Risk Scores, DNSBL, Shodan CVEs & CIDR Threats (cap 40) ---
    let mut cat_abuse = 0i32;
    let max_abuse_conf = ok_sources
        .iter()
        .filter_map(|r| r.abuse_confidence)
        .max();
    if let Some(conf) = max_abuse_conf.filter(|&c| c > 0) {
        let cut = ((conf as f64) * 0.35).floor() as i32;
        if cut > 0 {
            cat_abuse += cut;
            deductions.push(PurityDeduction {
                code: "abuse_confidence".to_owned(),
                label_zh: format!("滥用举报置信度 {conf}%"),
                label_en: format!("Abuse report confidence {conf}%"),
                points: -(cut as i16),
                source: ok_sources
                    .iter()
                    .filter(|r| r.abuse_confidence.is_some_and(|c| c > 0))
                    .map(|r| r.source_name.as_str())
                    .collect::<Vec<_>>()
                    .join("+"),
            });
        }
    } else if let Some(ae) = abuse_ratio.filter(|&e| e > 0.0) {
        let cut = (16.0 * ae).round() as i32;
        if cut > 0 {
            cat_abuse += cut;
            deductions.push(PurityDeduction {
                code: "abuser".to_owned(),
                label_zh: format!("存在历史滥用标记 (占比 {:.0}%)", ae * 100.0),
                label_en: format!("Historical abuser flag ({:.0}% weighted)", ae * 100.0),
                points: -(cut as i16),
                source: abuse_hitters.join("+"),
            });
        }
    }

    let risk_vals: Vec<(u8, &str)> = ok_sources
        .iter()
        .filter_map(|r| r.risk_score.map(|s| (s, r.source_name.as_str())))
        .collect();
    if let Some(&(max_risk, max_src)) = risk_vals.iter().max_by_key(|(s, _)| *s) {
        if max_risk >= 75 {
            cat_abuse += 16;
            deductions.push(PurityDeduction {
                code: "risk_score".to_owned(),
                label_zh: format!("情报源高风险分 ({max_risk}/100)"),
                label_en: format!("High provider risk score ({max_risk}/100)"),
                points: -16,
                source: max_src.to_owned(),
            });
        } else if max_risk >= 45 {
            cat_abuse += 8;
            deductions.push(PurityDeduction {
                code: "risk_score".to_owned(),
                label_zh: format!("情报源中等风险分 ({max_risk}/100)"),
                label_en: format!("Moderate provider risk score ({max_risk}/100)"),
                points: -8,
                source: max_src.to_owned(),
            });
        }
    }

    if let Some(shodan) = ok_sources.iter().find(|r| r.source_name == "shodan") {
        if let Some(ref note) = shodan.extra_note {
            details.push(format!("Shodan InternetDB: {note}"));
        }
        if !shodan.cves.is_empty() {
            cat_abuse += 6;
            deductions.push(PurityDeduction {
                code: "shodan_cves".to_owned(),
                label_zh: format!("Shodan 观测到 {} 个开放端口关联 CVE", shodan.cves.len()),
                label_en: format!("Shodan observed {} open-port CVEs", shodan.cves.len()),
                points: -6,
                source: "shodan".to_owned(),
            });
        }
    }

    // AlienVault OTX threat intelligence pulses
    if let Some(otx) = ok_sources.iter().find(|r| r.source_name == "otx") {
        if let Some(pulses) = otx.otx_pulses.filter(|&p| p > 0) {
            let cut = if pulses >= 10 {
                10
            } else if pulses >= 3 {
                6
            } else {
                3
            };
            cat_abuse += cut;
            deductions.push(PurityDeduction {
                code: "otx_pulses".to_owned(),
                label_zh: format!("AlienVault OTX 威胁情报命中 {pulses} 个 Pulse"),
                label_en: format!("AlienVault OTX listed in {pulses} threat pulses"),
                points: -(cut as i16),
                source: "otx".to_owned(),
            });
        }
    }

    // Optional Cloudflare Radar 28-day ASN bot traffic ratio
    if let Some(bot_pct) = routing.and_then(|rt| rt.cf_radar_bot_pct) {
        let cut = if bot_pct >= 75.0 {
            6
        } else if bot_pct >= 50.0 {
            4
        } else if bot_pct >= 30.0 {
            2
        } else {
            0
        };
        if cut > 0 {
            cat_abuse += cut;
            deductions.push(PurityDeduction {
                code: "cf_radar_bot".to_owned(),
                label_zh: format!("Cloudflare Radar 28天观测该 ASN 自动化/Bot 流量占比 {bot_pct:.1}%"),
                label_en: format!("Cloudflare Radar 28d ASN bot traffic share {bot_pct:.1}%"),
                points: -(cut as i16),
                source: "cf-radar".to_owned(),
            });
        }
    }

    if let Some(bl) = dnsbl {
        let bl_cut = ((bl.abuse_hits() as i32 * 8) + (bl.mail_hits() as i32 * 4)).min(22);
        if bl_cut > 0 {
            cat_abuse += bl_cut;
            deductions.push(PurityDeduction {
                code: "dnsbl".to_owned(),
                label_zh: format!(
                    "DNSBL 黑名单命中（滥用 {} · 邮件 {}）",
                    bl.abuse_hits(),
                    bl.mail_hits()
                ),
                label_en: format!(
                    "DNSBL blocklist hits (Abuse {} · Mail {})",
                    bl.abuse_hits(),
                    bl.mail_hits()
                ),
                points: -(bl_cut as i16),
                source: "doh-dnsbl".to_owned(),
            });
        }
    }

    if let Some(c) = cidr {
        if !c.attack_hits.is_empty() {
            let cut = (14 + (c.attack_hits.len().saturating_sub(1) as i32 * 3)).min(22);
            cat_abuse += cut;
            deductions.push(PurityDeduction {
                code: "cidr_attack".to_owned(),
                label_zh: format!("命中公开攻击威胁列表: {}", c.attack_hits.join(", ")),
                label_en: format!("Listed in threat lists: {}", c.attack_hits.join(", ")),
                points: -(cut as i16),
                source: "cidr-lists".to_owned(),
            });
        }
        if c.whole_24_attack {
            cat_abuse += 12;
            deductions.push(PurityDeduction {
                code: "cidr_whole_24".to_owned(),
                label_zh: "所属整个 /24 网段被列入攻击黑名单".to_owned(),
                label_en: "Entire /24 subnet listed in threat blocklists".to_owned(),
                points: -12,
                source: "cidr-lists".to_owned(),
            });
        } else if c.neighbor_24_count >= 3 {
            let cut = if c.neighbor_24_count >= 10 { 8 } else { 4 };
            cat_abuse += cut;
            deductions.push(PurityDeduction {
                code: "cidr_neighbors".to_owned(),
                label_zh: format!("同 /24 网段存在 {} 个受污染邻居", c.neighbor_24_count),
                label_en: format!("{} listed threat neighbors in same /24", c.neighbor_24_count),
                points: -(cut as i16),
                source: "cidr-lists".to_owned(),
            });
        }
        if let Some(ref dens) = c.asn_density {
            details.push(format!(
                "{}: {}/{} IPv4 ({:.1} / 10k, {:.1}x {})",
                pick(lang, "整 ASN 滥用密度", "Whole-ASN Abuse Density"),
                dens.listed_in_asn,
                dens.asn_v4_size,
                dens.per_10k,
                dens.ratio,
                pick(lang, "全球均值", "global avg")
            ));
            let mut cut = if dens.ratio >= 50.0 {
                12
            } else if dens.ratio >= 15.0 {
                9
            } else if dens.ratio >= 5.0 {
                6
            } else if dens.ratio >= 2.0 {
                3
            } else {
                0
            };
            // Small-sample shrinkage: on a tiny ASN (< 1024 IPs), 1–2 single listed IPs shouldn't max out at -12
            if dens.asn_v4_size < 1024 && dens.listed_in_asn <= 2 {
                cut = cut.min(6);
            }
            if cut > 0 {
                cat_abuse += cut;
                deductions.push(PurityDeduction {
                    code: "asn_abuse_density".to_owned(),
                    label_zh: format!(
                        "所属 ASN 整网威胁密度偏高（{:.1}/万 IP，为全球均值 {:.1} 倍）",
                        dens.per_10k, dens.ratio
                    ),
                    label_en: format!(
                        "Elevated whole-ASN threat density ({:.1}/10k IPs, {:.1}x global avg)",
                        dens.per_10k, dens.ratio
                    ),
                    points: -(cut as i16),
                    source: "asn-density".to_owned(),
                });
            }
        }
    }
    cat_abuse = cat_abuse.min(40);

    // --- Positive Evidence Bonuses (max +8 total; strictly gated on zero anon/abuse/ASN-density threats) ---
    let mut bonus = 0i32;
    let asn_density_elevated = cidr
        .and_then(|c| c.asn_density.as_ref())
        .is_some_and(|d| d.ratio >= 2.0);
    let clean_of_threats = cat_anon == 0 && cat_abuse == 0 && !tor_confirmed && !asn_density_elevated;
    if clean_of_threats {
        // Multi-source clean consensus across >= 5 independent sources
        if ok_sources.len() >= 5 {
            bonus += 3;
            deductions.push(PurityDeduction {
                code: "bonus_multi_clean".to_owned(),
                label_zh: format!("{} 个独立情报源一致未见代理/VPN/滥用记录", ok_sources.len()),
                label_en: format!("{} independent sources agree clean on proxy/VPN/abuse", ok_sources.len()),
                points: 3,
                source: "multi-source".to_owned(),
            });
        }
        // Clean consumer ISP + residential alignment (no hosting flags!)
        if cat_net == 0
            && network_type == NetworkType::Residential
            && matches!(asn_check.inferred_kind, AsnKind::IspResidential | AsnKind::Mobile)
        {
            bonus += 3;
            deductions.push(PurityDeduction {
                code: "bonus_residential_isp".to_owned(),
                label_zh: "住宅 / 移动类型与所属运营商 ASN 交叉一致".to_owned(),
                label_en: "Residential / mobile label corroborated by ISP ASN".to_owned(),
                points: 3,
                source: "asn-crosscheck".to_owned(),
            });
        }
        // Clean DNSBL across >= 10 public zones
        if dnsbl.is_some_and(|b| b.checked >= 10 && b.hits.is_empty()) {
            bonus += 2;
            deductions.push(PurityDeduction {
                code: "bonus_dnsbl_clean".to_owned(),
                label_zh: "16 份公开 DNSBL 黑名单零命中".to_owned(),
                label_en: "Zero listings across public DNSBL zones".to_owned(),
                points: 2,
                source: "doh-dnsbl".to_owned(),
            });
        }
        // Clean /24 neighbor scan when CIDR lists are loaded
        if cidr.is_some_and(|c| c.loaded >= 5 && c.attack_hits.is_empty() && !c.whole_24_attack && c.neighbor_24_count == 0) {
            bonus += 2;
            deductions.push(PurityDeduction {
                code: "bonus_clean_subnet24".to_owned(),
                label_zh: "同 /24 网段未检出威胁邻居".to_owned(),
                label_en: "Clean /24 neighborhood (0 listed threat neighbors)".to_owned(),
                points: 2,
                source: "cidr-lists".to_owned(),
            });
        }
        // Low whole-ASN abuse density on a substantial ASN
        if cidr
            .and_then(|c| c.asn_density.as_ref())
            .is_some_and(|d| d.asn_v4_size >= 4096 && d.ratio <= 0.5)
        {
            bonus += 2;
            deductions.push(PurityDeduction {
                code: "bonus_low_asn_density".to_owned(),
                label_zh: "所属 ASN 整网威胁密度显著低于全球均值".to_owned(),
                label_en: "Whole-ASN threat density well below global average".to_owned(),
                points: 2,
                source: "asn-density".to_owned(),
            });
        }
    }
    bonus = bonus.min(8);

    if dc_conflict || proxy_conflict || vpn_conflict {
        deductions.push(PurityDeduction {
            code: "conflict".to_owned(),
            label_zh: "多来源数据库判定存在分歧，已按加权占比折算并保留全部明细".to_owned(),
            label_en: "Databases disagreed; weighted consensus ratio applied".to_owned(),
            points: 0,
            source: "aggregate".to_owned(),
        });
    }

    let mut score = BASELINE + bonus - cat_anon - cat_net - cat_abuse;
    if tor_confirmed && score > 25 {
        score = 25;
    }

    let final_score = score.clamp(0, 100) as u8;
    let band = PurityBand::from_score(final_score);
    let grade = purity_grade(final_score);

    details.push(format!(
        "{}: {final_score}/100 [{}] ({}) · {}: {} · {}: 92 (+{} / -{})",
        pick(lang, "IP 纯净度", "IP Purity"),
        grade,
        i18n::purity_band_label(band, lang),
        pick(lang, "网络类型", "Network Type"),
        i18n::network_type_label(network_type, lang),
        pick(lang, "基准分", "Baseline"),
        bonus,
        cat_anon + cat_net + cat_abuse
    ));
    for d in &deductions {
        let lbl = pick(lang, &d.label_zh, &d.label_en);
        details.push(format!("  [{:+}] {lbl} ({})", d.points, d.source));
    }

    let state = match band {
        PurityBand::High => CheckState::Ok,
        PurityBand::Medium => CheckState::Warn,
        PurityBand::Low => CheckState::Fail,
    };

    let summary = match lang {
        Lang::Zh => format!(
            "出口 IP 纯净度 {final_score}/100 [{grade}]（{} · {} · {} 源 + ASN 交叉）",
            i18n::purity_band_label(band, lang),
            i18n::network_type_label(network_type, lang),
            ok_sources.len()
        ),
        Lang::En => format!(
            "Exit IP Purity {final_score}/100 [{grade}] ({} · {} · {} sources + ASN)",
            i18n::purity_band_label(band, lang),
            i18n::network_type_label(network_type, lang),
            ok_sources.len()
        ),
    };

    let flags = IpPurityFlags {
        proxy: proxy_flag,
        vpn: vpn_flag,
        tor: if tor_confirmed {
            Some(true)
        } else {
            tor_ratio.map(|_| false)
        },
        datacenter: dc_flag,
        abusive: abuse_flag,
    };

    let rep = IpPurityReport {
        ip: Some(clean_ip.to_owned()),
        purity: Some(final_score),
        band: Some(band),
        network_type,
        flags,
        deductions,
        sources_configured: keyed_configured || !ok_sources.is_empty(),
        proxycheck_status: pc_status,
        abuseipdb_status: ab_status,
    };

    let mut item = CheckItem::new("ip-purity", CheckCategory::NetworkLeak, title, state, summary)
        .with_details(details)
        .with_duration(duration_ms);

    if band != PurityBand::High {
        item = item.with_suggestion(pick(
            lang,
            "当前出口 IP 存在机房/匿名/黑名单或 ASN 交叉扣分项，建议更换低滥用住宅或干净独立 ISP 出口节点。",
            "Exit IP received datacenter/proxy/blocklist/ASN deductions. Consider switching to a cleaner residential or dedicated ISP node.",
        ));
    }

    (rep, item)
}

/// Backward-compatible wrapper used by unit tests focusing specifically on proxycheck + AbuseIPDB.
pub fn evaluate_ip_purity(
    ip: Option<&str>,
    geo: Option<&ExitGeoInfo>,
    proxycheck: &ReputationReading,
    abuseipdb: &ReputationReading,
    sources_configured: bool,
    lang: Lang,
    duration_ms: u64,
) -> (IpPurityReport, CheckItem) {
    let mut pc = proxycheck.clone();
    if pc.source_name.is_empty() {
        pc.source_name = "proxycheck".to_owned();
        pc.weight = 1.05;
    }
    let mut ab = abuseipdb.clone();
    if ab.source_name.is_empty() {
        ab.source_name = "abuseipdb".to_owned();
        ab.weight = 1.15;
    }
    evaluate_multi_source_purity(
        ip,
        geo,
        &[pc, ab],
        None,
        None,
        None,
        None,
        sources_configured,
        lang,
        duration_ms,
    )
}

async fn query_ipapi_is(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://api.ipapi.is/?q={ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_ipapi_is_json(&v),
            Err(_) => ReputationReading {
                source_name: "ipapi.is".to_owned(),
                weight: 0.95,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "ipapi.is".to_owned(),
            weight: 0.95,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "ipapi.is".to_owned(),
            weight: 0.95,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_ipquery(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://api.ipquery.io/{ip}?format=json");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_ipquery_json(&v),
            Err(_) => ReputationReading {
                source_name: "ipquery.io".to_owned(),
                weight: 0.80,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "ipquery.io".to_owned(),
            weight: 0.80,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "ipquery.io".to_owned(),
            weight: 0.80,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_blackbox_v3(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://blackbox.ipinfo.app/api/v3beta/{ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_blackbox_v3_json(&v),
            Err(_) => ReputationReading {
                source_name: "blackbox-v3".to_owned(),
                weight: 0.85,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "blackbox-v3".to_owned(),
            weight: 0.85,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "blackbox-v3".to_owned(),
            weight: 0.85,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_ip_api_com(client: &Client, ip: &str) -> ReputationReading {
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org,as,asname,mobile,proxy,hosting,reverse"
    );
    if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(3)).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let parsed = parse_ip_api_com_json(&v);
                if parsed.ok {
                    return parsed;
                }
            }
        }
    }
    // Fallback to TechnikNews IPgeo (ip-api compatible schema) only when primary fails
    let fb_url = format!("https://api.techniknews.net/ipgeo/{ip}");
    if let Ok(resp) = client.get(&fb_url).timeout(Duration::from_secs(3)).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let mut parsed = parse_ip_api_com_json(&v);
                if parsed.ok {
                    parsed.source_name = "techniknews".to_owned();
                    parsed.weight = 0.60;
                    return parsed;
                }
            }
        }
    }
    ReputationReading {
        source_name: "ip-api.com".to_owned(),
        weight: 0.85,
        status: "unavailable".to_owned(),
        ..Default::default()
    }
}

async fn query_netcoffee(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://ip.net.coffee/api/ip/lookup/{ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_netcoffee_json(&v),
            Err(_) => ReputationReading {
                source_name: "net.coffee".to_owned(),
                weight: 0.65,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "net.coffee".to_owned(),
            weight: 0.65,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "net.coffee".to_owned(),
            weight: 0.65,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_shodan_internetdb(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://internetdb.shodan.io/{ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 404 => {
            match resp.json::<Value>().await {
                Ok(v) => parse_shodan_internetdb_json(&v),
                Err(_) => ReputationReading {
                    source_name: "shodan".to_owned(),
                    weight: 0.60,
                    status: "ok (clean)".to_owned(),
                    ok: true,
                    ..Default::default()
                },
            }
        }
        Ok(resp) => ReputationReading {
            source_name: "shodan".to_owned(),
            weight: 0.60,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "shodan".to_owned(),
            weight: 0.60,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_stopforumspam(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://api.stopforumspam.org/api?ip={ip}&json");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_stopforumspam_json(&v),
            Err(_) => ReputationReading {
                source_name: "stopforumspam".to_owned(),
                weight: 0.70,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "stopforumspam".to_owned(),
            weight: 0.70,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "stopforumspam".to_owned(),
            weight: 0.70,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_proxycheck(client: &Client, ip: &str, key: Option<&str>) -> ReputationReading {
    let url = match key {
        Some(k) => format!("https://proxycheck.io/v2/{ip}?key={k}&vpn=1&asn=1&risk=1"),
        None => format!("https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1"),
    };
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => {
                let mut r = parse_proxycheck_json(&v, ip);
                if key.is_none() && r.ok {
                    r.status = "ok (free)".to_owned();
                }
                r
            }
            Err(_) => ReputationReading {
                source_name: "proxycheck".to_owned(),
                weight: 1.05,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "proxycheck".to_owned(),
            weight: 1.05,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "proxycheck".to_owned(),
            weight: 1.05,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_abuseipdb(client: &Client, ip: &str, key: &str) -> ReputationReading {
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    match client
        .get(&url)
        .header("Key", key)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_abuseipdb_json(&v),
            Err(_) => ReputationReading {
                source_name: "abuseipdb".to_owned(),
                weight: 1.15,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "abuseipdb".to_owned(),
            weight: 1.15,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "abuseipdb".to_owned(),
            weight: 1.15,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_peeringdb(client: &Client, asn: u64) -> PeeringDbInfo {
    let url = format!("https://www.peeringdb.com/api/net?asn={asn}");
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(3)).send().await else {
        return PeeringDbInfo::default();
    };
    if !resp.status().is_success() {
        return PeeringDbInfo::default();
    }
    match resp.json::<Value>().await {
        Ok(v) => parse_peeringdb_json(&v),
        Err(_) => PeeringDbInfo::default(),
    }
}

async fn query_iplocate(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://iplocate.io/api/lookup/{ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_iplocate_json(&v),
            Err(_) => ReputationReading {
                source_name: "iplocate.io".to_owned(),
                weight: 0.85,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "iplocate.io".to_owned(),
            weight: 0.85,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "iplocate.io".to_owned(),
            weight: 0.85,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_geoiplookup(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://json.geoiplookup.io/{ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_geoiplookup_json(&v),
            Err(_) => ReputationReading {
                source_name: "geoiplookup".to_owned(),
                weight: 0.55,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "geoiplookup".to_owned(),
            weight: 0.55,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "geoiplookup".to_owned(),
            weight: 0.55,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_freeipapi(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://freeipapi.com/api/json/{ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_freeipapi_json(&v),
            Err(_) => ReputationReading {
                source_name: "freeipapi".to_owned(),
                weight: 0.70,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "freeipapi".to_owned(),
            weight: 0.70,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "freeipapi".to_owned(),
            weight: 0.70,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_onionoo(client: &Client, ip: &str) -> ReputationReading {
    let url = format!("https://onionoo.torproject.org/details?search={ip}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_onionoo_json(&v),
            Err(_) => ReputationReading {
                source_name: "tor-onionoo".to_owned(),
                weight: 1.0,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "tor-onionoo".to_owned(),
            weight: 1.0,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "tor-onionoo".to_owned(),
            weight: 1.0,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_otx(client: &Client, ip: &str) -> ReputationReading {
    let kind = if ip.contains(':') { "IPv6" } else { "IPv4" };
    let url = format!("https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/general");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_otx_json(&v),
            Err(_) => ReputationReading {
                source_name: "otx".to_owned(),
                weight: 0.75,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "otx".to_owned(),
            weight: 0.75,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "otx".to_owned(),
            weight: 0.75,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_ip_guide(
    client: &Client,
    ip: &str,
) -> (Option<u64>, Option<String>, Option<String>, Option<String>) {
    let url = format!("https://ip.guide/{ip}");
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(3)).send().await else {
        return (None, None, None, None);
    };
    if !resp.status().is_success() {
        return (None, None, None, None);
    }
    match resp.json::<Value>().await {
        Ok(v) => parse_ip_guide_json(&v),
        Err(_) => (None, None, None, None),
    }
}

async fn query_ripestat_announced_prefixes(client: &Client, asn: u64) -> (Vec<String>, u64) {
    let url = format!(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&sourceapp=ai-network-protection"
    );
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(4)).send().await else {
        return (Vec::new(), 0);
    };
    if !resp.status().is_success() {
        return (Vec::new(), 0);
    }
    match resp.json::<Value>().await {
        Ok(v) => parse_ripestat_announced_prefixes_json(&v),
        Err(_) => (Vec::new(), 0),
    }
}

async fn query_rdap_asn_registration(client: &Client, asn: u64) -> (Option<String>, Option<f64>) {
    let url = format!("https://rdap.org/autnum/{asn}");
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(4)).send().await else {
        return (None, None);
    };
    if !resp.status().is_success() {
        return (None, None);
    }
    match resp.json::<Value>().await {
        Ok(v) => parse_rdap_asn_registration_json(&v),
        Err(_) => (None, None),
    }
}

async fn query_cf_radar_bot(client: &Client, asn: u64, token: &str) -> Option<f64> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn={asn}&dateRange=28d"
    );
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(4))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v = resp.json::<Value>().await.ok()?;
    parse_cf_radar_bot_json(&v)
}

async fn query_greynoise(client: &Client, ip: &str, key: &str) -> ReputationReading {
    let url = format!("https://api.greynoise.io/v3/community/{ip}");
    match client
        .get(&url)
        .header("key", key)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(4))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 404 => {
            match resp.json::<Value>().await {
                Ok(v) => parse_greynoise_json(&v),
                Err(_) => ReputationReading {
                    source_name: "greynoise".to_owned(),
                    weight: 0.90,
                    status: "ok (clean)".to_owned(),
                    ok: true,
                    abusive: Some(false),
                    ..Default::default()
                },
            }
        }
        Ok(resp) => ReputationReading {
            source_name: "greynoise".to_owned(),
            weight: 0.90,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "greynoise".to_owned(),
            weight: 0.90,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_crowdsec(client: &Client, ip: &str, key: &str) -> ReputationReading {
    let url = format!("https://cti.api.crowdsec.net/v2/smoke/{ip}");
    match client
        .get(&url)
        .header("x-api-key", key)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(4))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 404 => {
            match resp.json::<Value>().await {
                Ok(v) => parse_crowdsec_json(&v),
                Err(_) => ReputationReading {
                    source_name: "crowdsec".to_owned(),
                    weight: 0.95,
                    status: "ok (not listed)".to_owned(),
                    ok: true,
                    abusive: Some(false),
                    ..Default::default()
                },
            }
        }
        Ok(resp) => ReputationReading {
            source_name: "crowdsec".to_owned(),
            weight: 0.95,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "crowdsec".to_owned(),
            weight: 0.95,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_virustotal(client: &Client, ip: &str, key: &str) -> ReputationReading {
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}");
    match client
        .get(&url)
        .header("x-apikey", key)
        .timeout(Duration::from_secs(4))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_virustotal_json(&v),
            Err(_) => ReputationReading {
                source_name: "virustotal".to_owned(),
                weight: 0.95,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "virustotal".to_owned(),
            weight: 0.95,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "virustotal".to_owned(),
            weight: 0.95,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_ipregistry(client: &Client, ip: &str, key: &str) -> ReputationReading {
    let url = format!("https://api.ipregistry.co/{ip}?key={key}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_ipregistry_json(&v),
            Err(_) => ReputationReading {
                source_name: "ipregistry".to_owned(),
                weight: 1.05,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "ipregistry".to_owned(),
            weight: 1.05,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "ipregistry".to_owned(),
            weight: 1.05,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_ipdata(client: &Client, ip: &str, key: &str) -> ReputationReading {
    let url = format!("https://api.ipdata.co/{ip}?api-key={key}");
    match client.get(&url).timeout(Duration::from_secs(4)).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => parse_ipdata_json(&v),
            Err(_) => ReputationReading {
                source_name: "ipdata".to_owned(),
                weight: 1.05,
                status: "parse error".to_owned(),
                ..Default::default()
            },
        },
        Ok(resp) => ReputationReading {
            source_name: "ipdata".to_owned(),
            weight: 1.05,
            status: format!("HTTP {}", resp.status().as_u16()),
            ..Default::default()
        },
        Err(_) => ReputationReading {
            source_name: "ipdata".to_owned(),
            weight: 1.05,
            status: "timeout".to_owned(),
            ..Default::default()
        },
    }
}

async fn query_geo_json(
    client: &Client,
    source: &str,
    url: String,
    cc_keys: &[&str],
    city_keys: &[&str],
) -> GeoConsensusVote {
    let mut vote = GeoConsensusVote {
        source: source.to_owned(),
        ..Default::default()
    };
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(3)).send().await else {
        return vote;
    };
    if !resp.status().is_success() {
        return vote;
    }
    let Ok(v) = resp.json::<Value>().await else {
        return vote;
    };
    for &k in cc_keys {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).map(str::trim) {
            if s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic()) {
                vote.country_code = Some(s.to_ascii_uppercase());
                break;
            }
        }
    }
    for &k in city_keys {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).map(str::trim) {
            if !s.is_empty() {
                vote.city = Some(s.to_owned());
                break;
            }
        }
    }
    vote
}

async fn query_geolite2_ripe(client: &Client, ip: &str) -> GeoConsensusVote {
    let mut vote = GeoConsensusVote {
        source: "geolite2".to_owned(),
        ..Default::default()
    };
    let url = format!(
        "https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={ip}&sourceapp=ai-network-protection"
    );
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(3)).send().await else {
        return vote;
    };
    if !resp.status().is_success() {
        return vote;
    }
    let Ok(v) = resp.json::<Value>().await else {
        return vote;
    };
    if let Some(loc) = v
        .get("data")
        .and_then(|d| d.get("located_resources"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.get("locations"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
    {
        if let Some(cc) = loc.get("country").and_then(|x| x.as_str()).map(str::trim) {
            if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) {
                vote.country_code = Some(cc.to_ascii_uppercase());
            }
        }
        if let Some(city) = loc.get("city").and_then(|x| x.as_str()).map(str::trim) {
            if !city.is_empty() {
                vote.city = Some(city.to_owned());
            }
        }
    }
    vote
}

async fn fetch_multi_source_geo_consensus(client: &Client, ip: &str) -> Vec<GeoConsensusVote> {
    let (v1, v2, v3, v4, v5, v6, v7, v8) = tokio::join!(
        query_geo_json(
            client,
            "ipinfo",
            format!("https://ipinfo.io/{ip}/json"),
            &["country"],
            &["city"],
        ),
        query_geo_json(
            client,
            "ipwho.is",
            format!("https://ipwho.is/{ip}"),
            &["country_code"],
            &["city"],
        ),
        query_geo_json(
            client,
            "ip.sb",
            format!("https://api.ip.sb/geoip/{ip}"),
            &["country_code"],
            &["city"],
        ),
        query_geo_json(
            client,
            "db-ip",
            format!("https://api.db-ip.com/v2/free/{ip}"),
            &["countryCode"],
            &["city"],
        ),
        query_geo_json(
            client,
            "geojs",
            format!("https://get.geojs.io/v1/ip/geo/{ip}.json"),
            &["country_code"],
            &["city"],
        ),
        query_geo_json(
            client,
            "ipapi.co",
            format!("https://ipapi.co/{ip}/json/"),
            &["country_code", "country"],
            &["city"],
        ),
        query_geo_json(
            client,
            "iplocation",
            format!("https://api.iplocation.net/?ip={ip}"),
            &["country_code2"],
            &[],
        ),
        query_geolite2_ripe(client, ip),
    );
    vec![v1, v2, v3, v4, v5, v6, v7, v8]
}

/// Fetch all 13 zero-key (incl. free proxycheck) + 8 GeoIP consensus + 7 optional-key IP intelligence,
/// threat, routing & registration sources concurrently!
pub async fn fetch_ip_purity_readings(
    client: &Client,
    exit_ip: Option<&str>,
    geo_asn: Option<u64>,
    keys: IntelApiKeys<'_>,
) -> PurityIntelBundle {
    let start = Instant::now();
    fn trim_k(k: Option<&str>) -> Option<&str> {
        k.map(str::trim).filter(|s| !s.is_empty())
    }
    let pc_key = trim_k(keys.proxycheck);
    let ab_key = trim_k(keys.abuseipdb);
    let cf_tok = trim_k(keys.cf_radar);
    let gn_key = trim_k(keys.greynoise);
    let cs_key = trim_k(keys.crowdsec);
    let vt_key = trim_k(keys.virustotal);
    let ir_key = trim_k(keys.ipregistry);
    let id_key = trim_k(keys.ipdata);
    let keyed_configured = pc_key.is_some()
        || ab_key.is_some()
        || cf_tok.is_some()
        || gn_key.is_some()
        || cs_key.is_some()
        || vt_key.is_some()
        || ir_key.is_some()
        || id_key.is_some();

    let Some(ip) = exit_ip.filter(|ip| is_public_ip(ip)) else {
        return PurityIntelBundle {
            keyed_configured,
            ..Default::default()
        };
    };

    // Wave A: ALL IP intelligence DBs + free/keyed proxycheck + threat/scan feeds + live BGP `ip.guide` + DoH PTR + 8 GeoIP consensus sources concurrently!
    let (
        (
            r_ipapi,
            r_ipquery,
            r_blackbox,
            r_ipapicom,
            r_netcoffee,
            r_iplocate,
            r_geoiplookup,
            r_freeipapi,
            r_shodan,
            r_sfs,
            r_onionoo,
            r_otx,
            r_pc,
        ),
        (r_ab, r_gn, r_cs, r_vt, r_ir, r_id),
        guide_res,
        ptr_hostname,
        geo_votes,
    ) = tokio::join!(
        async {
            tokio::join!(
                query_ipapi_is(client, ip),
                query_ipquery(client, ip),
                query_blackbox_v3(client, ip),
                query_ip_api_com(client, ip),
                query_netcoffee(client, ip),
                query_iplocate(client, ip),
                query_geoiplookup(client, ip),
                query_freeipapi(client, ip),
                query_shodan_internetdb(client, ip),
                query_stopforumspam(client, ip),
                query_onionoo(client, ip),
                query_otx(client, ip),
                query_proxycheck(client, ip, pc_key),
            )
        },
        async {
            tokio::join!(
                async {
                    match ab_key {
                        Some(k) => query_abuseipdb(client, ip, k).await,
                        None => ReputationReading {
                            source_name: "abuseipdb".to_owned(),
                            weight: 1.15,
                            status: "unconfigured".to_owned(),
                            ..Default::default()
                        },
                    }
                },
                async {
                    match gn_key {
                        Some(k) => Some(query_greynoise(client, ip, k).await),
                        None => None,
                    }
                },
                async {
                    match cs_key {
                        Some(k) => Some(query_crowdsec(client, ip, k).await),
                        None => None,
                    }
                },
                async {
                    match vt_key {
                        Some(k) => Some(query_virustotal(client, ip, k).await),
                        None => None,
                    }
                },
                async {
                    match ir_key {
                        Some(k) => Some(query_ipregistry(client, ip, k).await),
                        None => None,
                    }
                },
                async {
                    match id_key {
                        Some(k) => Some(query_ipdata(client, ip, k).await),
                        None => None,
                    }
                },
            )
        },
        query_ip_guide(client, ip),
        dnsbl::lookup_ptr_doh(client, ip),
        fetch_multi_source_geo_consensus(client, ip),
    );

    let mut readings = vec![
        r_ipapi,
        r_ipquery,
        r_blackbox,
        r_ipapicom,
        r_netcoffee,
        r_iplocate,
        r_geoiplookup,
        r_freeipapi,
        r_shodan,
        r_sfs,
        r_onionoo,
        r_otx,
        r_pc,
        r_ab,
    ];
    for opt_r in [r_gn, r_cs, r_vt, r_ir, r_id].into_iter().flatten() {
        readings.push(opt_r);
    }

    let (bgp_asn, bgp_org, bgp_prefix, bgp_rir) = guide_res;
    // Prefer authoritative live BGP announcing ASN (`ip.guide`) over potentially stale DB ASN!
    let effective_asn = bgp_asn
        .or(geo_asn)
        .or_else(|| readings.iter().find_map(|r| r.asn));

    // Wave B: Resolve PeeringDB + RIPEstat announced-prefixes + RDAP autnum + optional CF Radar concurrently
    let (
        peeringdb,
        (announced_v4_cidrs, announced_v4_total),
        (asn_registered_date, asn_age_years),
        cf_radar_bot_pct,
    ) = if let Some(asn) = effective_asn {
        let (pdb, pfx, rdap, cf_bot) = tokio::join!(
            query_peeringdb(client, asn),
            query_ripestat_announced_prefixes(client, asn),
            query_rdap_asn_registration(client, asn),
            async {
                match cf_tok {
                    Some(tok) => query_cf_radar_bot(client, asn, tok).await,
                    None => None,
                }
            }
        );
        (Some(pdb), pfx, rdap, cf_bot)
    } else {
        (None, (Vec::new(), 0), (None, None), None)
    };

    let routing = AsnRoutingInfo {
        bgp_asn,
        bgp_org,
        bgp_prefix,
        bgp_rir,
        announced_v4_cidrs,
        announced_v4_total,
        asn_registered_date,
        asn_age_years,
        ptr_hostname,
        cf_radar_bot_pct,
        geo_votes,
    };

    PurityIntelBundle {
        readings,
        peeringdb,
        routing,
        keyed_configured,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Extract RIR registered country code from RIPEstat whois JSON.
pub fn extract_rir_country_from_whois(json: &Value) -> Option<String> {
    let records = json.get("data")?.get("records")?.as_array()?;
    for block in records {
        let Some(entries) = block.as_array() else {
            continue;
        };
        for kv in entries {
            let key = kv.get("key").and_then(|v| v.as_str()).unwrap_or_default();
            if key.eq_ignore_ascii_case("country") {
                if let Some(val) = kv.get("value").and_then(|v| v.as_str()) {
                    let cc = val.trim().to_ascii_uppercase();
                    if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_alphabetic()) && cc != "EU" {
                        return Some(cc);
                    }
                }
            }
        }
    }
    None
}

/// Check Native vs. Broadcast IP status & RPKI route validation using standard public RIPEstat APIs (zero keys).
pub async fn run_native_and_rpki_check(
    client: &Client,
    ip_str: Option<&str>,
    geo: Option<&ExitGeoInfo>,
    lang: Lang,
) -> CheckItem {
    let start = Instant::now();
    let title =
        i18n::check_title("ip-native-rpki", lang).unwrap_or("Native vs. Broadcast & RPKI");
    let Some(ip) = ip_str.map(str::trim).filter(|s| is_public_ip(s)) else {
        return CheckItem::new(
            "ip-native-rpki",
            CheckCategory::NetworkLeak,
            title,
            CheckState::Unknown,
            pick(
                lang,
                "无可用公网 IP，跳过原生/广播与 RPKI 校验",
                "No public IP available; skipped Native/Broadcast & RPKI check",
            ),
        );
    };

    let net_url = format!(
        "https://stat.ripe.net/data/network-info/data.json?resource={ip}&sourceapp=ai-network-protection"
    );
    let whois_url = format!(
        "https://stat.ripe.net/data/whois/data.json?resource={ip}&sourceapp=ai-network-protection"
    );

    let (net_json, whois_json) = tokio::join!(
        async {
            client
                .get(&net_url)
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .ok()?
                .json::<Value>()
                .await
                .ok()
        },
        async {
            client
                .get(&whois_url)
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .ok()?
                .json::<Value>()
                .await
                .ok()
        },
    );

    let prefix = net_json
        .as_ref()
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get("prefix"))
        .and_then(|p| p.as_str())
        .map(str::to_owned);
    let asn = net_json
        .as_ref()
        .and_then(|v| v.get("data"))
        .and_then(|d| d.get("asns"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.as_str())
        .map(str::to_owned);

    let rpki = if let (Some(a), Some(p)) = (asn.as_deref(), prefix.as_deref()) {
        let rpki_url = format!(
            "https://stat.ripe.net/data/rpki-validation/data.json?resource={a}&prefix={p}&sourceapp=ai-network-protection"
        );
        match client
            .get(&rpki_url)
            .timeout(Duration::from_secs(2))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v.get("data")?.get("status")?.as_str().map(str::to_owned)),
            _ => None,
        }
    } else {
        None
    };

    let rir_cc = whois_json.as_ref().and_then(extract_rir_country_from_whois);
    let geo_cc = geo
        .and_then(|g| g.country_code.as_deref())
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty());

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut details = vec![format!(
        "{}: {ip} · {}: {} · ASN: {}",
        pick(lang, "查询 IP", "IP"),
        pick(lang, "宣告前缀", "Prefix"),
        prefix.as_deref().unwrap_or("-"),
        asn.as_deref()
            .map(|a| format!("AS{a}"))
            .unwrap_or_else(|| "-".to_owned()),
    )];
    details.push(format!(
        "{}: {} · {}: {}",
        pick(lang, "RIR 注册国家", "RIR Registered Country"),
        rir_cc.as_deref().unwrap_or("-"),
        pick(lang, "实际地理定位", "Observed Geo Country"),
        geo_cc.as_deref().unwrap_or("-"),
    ));
    details.push(format!("RPKI ROA: {}", rpki.as_deref().unwrap_or("unknown")));

    let is_rpki_invalid = rpki
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("invalid"));

    let (state, summary, suggestion) = match (rir_cc.as_deref(), geo_cc.as_deref()) {
        (Some(reg), Some(loc)) if reg == loc => {
            if is_rpki_invalid {
                (
                    CheckState::Warn,
                    match lang {
                        Lang::Zh => format!("原生 IP ({reg})，但 RPKI 路由验证为 invalid"),
                        Lang::En => {
                            format!("Native IP ({reg}), but RPKI ROA validation is invalid")
                        }
                    },
                    Some(pick(
                        lang,
                        "RPKI ROA 校验异常可能影响部分网络路由信誉。",
                        "Invalid RPKI ROA may negatively affect routing reputation.",
                    )),
                )
            } else {
                (
                    CheckState::Ok,
                    match lang {
                        Lang::Zh => format!(
                            "原生 IP（注册国与定位均为 {reg}）· RPKI: {}",
                            rpki.as_deref().unwrap_or("unknown")
                        ),
                        Lang::En => format!(
                            "Native IP (RIR & Geo both {reg}) · RPKI: {}",
                            rpki.as_deref().unwrap_or("unknown")
                        ),
                    },
                    None,
                )
            }
        }
        (Some(reg), Some(loc)) => (
            CheckState::Warn,
            match lang {
                Lang::Zh => format!(
                    "疑似广播 / 跨区宣告 IP（RIR 注册在 {reg}，实际定位在 {loc}）· RPKI: {}",
                    rpki.as_deref().unwrap_or("unknown")
                ),
                Lang::En => format!(
                    "Broadcast / Announced Abroad (RIR={reg}, Geo={loc}) · RPKI: {}",
                    rpki.as_deref().unwrap_or("unknown")
                ),
            },
            Some(pick(
                lang,
                "广播 IP（注册国与落地区不一致）在部分 AI/流媒体服务中可能出现地区识别分歧，建议按需优先选择原生段位。",
                "Broadcast IPs (registered in one country, announced in another) can trigger geo-consensus mismatches on some platforms.",
            )),
        ),
        _ => (
            CheckState::Ok,
            match lang {
                Lang::Zh => format!(
                    "路由信息已采集（RPKI: {}，RIR 国家字段暂缺）",
                    rpki.as_deref().unwrap_or("unknown")
                ),
                Lang::En => format!(
                    "Routing info collected (RPKI: {}, RIR country unavailable)",
                    rpki.as_deref().unwrap_or("unknown")
                ),
            },
            None,
        ),
    };

    let mut item =
        CheckItem::new("ip-native-rpki", CheckCategory::NetworkLeak, title, state, summary)
            .with_details(details)
            .with_duration(duration_ms);
    if let Some(sug) = suggestion {
        item = item.with_suggestion(sug);
    }
    item
}
