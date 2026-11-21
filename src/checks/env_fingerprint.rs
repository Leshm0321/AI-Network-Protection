use crate::i18n::{self, Lang, pick};
use crate::model::{
    CheckCategory, CheckItem, CheckState, EnvFingerprintReport, FingerprintSignal, RiskBand,
};
use crate::net::system::SystemSnapshot;

/// Mainland restricted IANA timezones.
pub const RESTRICTED_CN_TIMEZONES: &[&str] = &[
    "Asia/Shanghai",
    "Asia/Urumqi",
    "Asia/Chongqing",
    "Asia/Chungking",
    "Asia/Harbin",
    "Asia/Kashgar",
];

/// Partial-risk special administrative region timezones (Taiwan `Asia/Taipei` is explicitly exempt).
pub const PARTIAL_CN_TIMEZONES: &[&str] = &["Asia/Hong_Kong", "Asia/Macau"];

/// Common Simplified Chinese font families & Windows/macOS font filename fragments.
const SC_FONT_TOKENS: &[(&str, &str)] = &[
    ("microsoft yahei", "Microsoft YaHei"),
    ("msyh", "Microsoft YaHei"),
    ("simsun", "SimSun"),
    ("nsimsun", "NSimSun"),
    ("simhei", "SimHei"),
    ("kaiti", "KaiTi"),
    ("fangsong", "FangSong"),
    ("dengxian", "DengXian"),
    ("pingfang sc", "PingFang SC"),
    ("pingfang.ttc", "PingFang"),
    ("hiragino sans gb", "Hiragino Sans GB"),
    ("stheiti", "STHeiti"),
    ("stsong", "STSong"),
    ("songti sc", "Songti SC"),
    ("source han sans cn", "Source Han Sans CN"),
    ("source han sans sc", "Source Han Sans SC"),
    ("noto sans cjk sc", "Noto Sans CJK SC"),
    ("noto serif cjk sc", "Noto Serif CJK SC"),
    ("wenquanyi", "WenQuanYi"),
];

/// Traditional Chinese font families (ambiguous between TW/HK/MO -> low intensity).
const TC_FONT_TOKENS: &[(&str, &str)] = &[
    ("microsoft jhenghei", "Microsoft JhengHei"),
    ("msjh", "Microsoft JhengHei"),
    ("pmingliu", "PMingLiU"),
    ("mingliu", "MingLiU"),
    ("dfkai-sb", "DFKai-SB"),
    ("pingfang tc", "PingFang TC"),
    ("source han sans tw", "Source Han Sans TW"),
    ("noto sans cjk tc", "Noto Sans CJK TC"),
];

/// High-specificity domestic vendor / office suite fonts.
const VENDOR_FONT_TOKENS: &[(&str, &str)] = &[
    ("misans", "MiSans"),
    ("harmonyos sans", "HarmonyOS Sans"),
    ("honor sans", "HONOR Sans"),
    ("oppo sans", "OPPO Sans"),
    ("vivo sans", "vivo Sans"),
    ("alibaba puhuiti", "Alibaba PuHuiTi"),
    ("alibaba sans", "Alibaba Sans"),
    ("dingtalk jinbuti", "DingTalk JinBuTi"),
    ("douyin sans", "Douyin Sans"),
    ("hyqihei", "HYQiHei"),
    ("fzshusong", "FZShuSong"),
    ("fzkai", "FZKai"),
    ("fzhei", "FZHei"),
    ("fzfangsong", "FZFangSong"),
    ("方正", "Founder (FZ)"),
];

/// Hardware OEM patterns with intensity (0..=100).
const OEM_PATTERNS: &[(&str, &str, u8)] = &[
    ("harmonyos", "HarmonyOS", 100),
    ("huawei", "Huawei", 80),
    ("honor", "Honor", 80),
    ("meizu", "Meizu", 80),
    ("xiaomi", "Xiaomi", 65),
    ("redmi", "Redmi", 65),
    ("oppo", "OPPO", 60),
    ("vivo", "vivo", 60),
    ("oneplus", "OnePlus", 60),
    ("realme", "realme", 60),
    ("lenovo", "Lenovo", 45),
];

/// Score IANA timezone against restricted-region rules.
/// `Asia/Taipei` (Taiwan) is explicitly exempt and returns 0.
pub fn score_timezone_intensity(tz: Option<&str>) -> u8 {
    let Some(raw) = tz.map(str::trim).filter(|s| !s.is_empty()) else {
        return 0;
    };
    if raw.eq_ignore_ascii_case("Asia/Taipei") {
        return 0;
    }
    if RESTRICTED_CN_TIMEZONES
        .iter()
        .any(|z| z.eq_ignore_ascii_case(raw))
    {
        return 100;
    }
    if PARTIAL_CN_TIMEZONES
        .iter()
        .any(|z| z.eq_ignore_ascii_case(raw))
    {
        return 60;
    }
    0
}

/// Score OS locale (`zh-CN`/`zh-Hans` => 100, `zh-HK`/`zh-MO` => 50, `zh-TW` => 0).
pub fn score_locale_intensity(locale: Option<&str>) -> u8 {
    let Some(raw) = locale.map(str::trim).filter(|s| !s.is_empty()) else {
        return 0;
    };
    let lower = raw.to_ascii_lowercase().replace('_', "-");
    if lower.starts_with("zh-tw") || (lower.contains("hant") && lower.contains("tw")) {
        return 0;
    }
    if lower.starts_with("zh-cn") || lower.contains("hans") || lower == "zh" {
        return 100;
    }
    if lower.starts_with("zh-hk") || lower.starts_with("zh-mo") || lower.contains("hant") {
        return 50;
    }
    0
}

fn match_font_tokens(fonts: &[String], table: &[(&str, &str)]) -> Vec<String> {
    let mut hits = Vec::new();
    for &(needle, label) in table {
        let matched = fonts
            .iter()
            .any(|f| f.to_ascii_lowercase().contains(needle));
        if matched && !hits.iter().any(|h: &String| h == label) {
            hits.push(label.to_owned());
        }
    }
    hits
}

fn match_oem(vendor: Option<&str>, model: Option<&str>) -> (Option<&'static str>, u8) {
    let combined = format!(
        "{} {}",
        vendor.unwrap_or_default(),
        model.unwrap_or_default()
    )
    .to_ascii_lowercase();
    if combined.trim().is_empty() {
        return (None, 0);
    }
    for &(needle, label, intensity) in OEM_PATTERNS {
        if combined.contains(needle) {
            return (Some(label), intensity);
        }
    }
    (None, 0)
}

fn calc_contribution(weight: u8, intensity_pct: u8) -> u8 {
    ((weight as u32 * intensity_pct as u32 + 50) / 100) as u8
}

/// Pure OS-level environment fingerprint evaluator (weights sum to 100).
pub fn evaluate_env_fingerprint(
    sys: &SystemSnapshot,
    tz_env_override: Option<&str>,
    lang: Lang,
) -> (EnvFingerprintReport, CheckItem) {
    let mut signals = Vec::with_capacity(7);

    // 1. System Timezone (weight 28)
    let effective_tz = tz_env_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(sys.local_timezone_iana.as_deref());
    let tz_intensity = score_timezone_intensity(effective_tz);
    let tz_raw = match (sys.local_timezone_iana.as_deref(), tz_env_override) {
        (Some(os_tz), Some(ov)) if !ov.trim().is_empty() => {
            format!("{os_tz} (TZ={})", ov.trim())
        }
        (Some(os_tz), _) => os_tz.to_owned(),
        (None, Some(ov)) if !ov.trim().is_empty() => format!("TZ={}", ov.trim()),
        _ => pick(lang, "未知", "Unknown").to_owned(),
    };
    signals.push(FingerprintSignal {
        id: "timezone".to_owned(),
        label_zh: "系统时区".to_owned(),
        label_en: "System Timezone".to_owned(),
        weight: 28,
        intensity_pct: tz_intensity,
        contribution: calc_contribution(28, tz_intensity),
        raw: tz_raw,
        hit: tz_intensity >= 25,
    });

    // 2. System Language / Locale (weight 22)
    let loc_intensity = score_locale_intensity(sys.local_locale.as_deref());
    signals.push(FingerprintSignal {
        id: "locale".to_owned(),
        label_zh: "系统语言 / Locale".to_owned(),
        label_en: "OS Language / Locale".to_owned(),
        weight: 22,
        intensity_pct: loc_intensity,
        contribution: calc_contribution(22, loc_intensity),
        raw: sys
            .local_locale
            .clone()
            .unwrap_or_else(|| pick(lang, "未知", "Unknown").to_owned()),
        hit: loc_intensity >= 25,
    });

    // 3. Installed CJK Fonts (weight 16)
    let sc_hits = match_font_tokens(&sys.installed_fonts, SC_FONT_TOKENS);
    let tc_hits = match_font_tokens(&sys.installed_fonts, TC_FONT_TOKENS);
    let font_intensity = if !sc_hits.is_empty() {
        (75usize + sc_hits.len() * 8).min(100) as u8
    } else if !tc_hits.is_empty() {
        20
    } else {
        0
    };
    let mut combined_fonts = sc_hits;
    combined_fonts.extend(tc_hits);
    let fonts_raw = if combined_fonts.is_empty() {
        pick(lang, "未检出", "None detected").to_owned()
    } else if combined_fonts.len() > 4 {
        format!("{}… ({})", combined_fonts[..4].join(", "), combined_fonts.len())
    } else {
        combined_fonts.join(", ")
    };
    signals.push(FingerprintSignal {
        id: "cjk_fonts".to_owned(),
        label_zh: "已安装中文字体".to_owned(),
        label_en: "Installed CJK Fonts".to_owned(),
        weight: 16,
        intensity_pct: font_intensity,
        contribution: calc_contribution(16, font_intensity),
        raw: fonts_raw,
        hit: font_intensity >= 25,
    });

    // 4. Vendor / Regional Software Fonts (weight 12)
    let vendor_hits = match_font_tokens(&sys.installed_fonts, VENDOR_FONT_TOKENS);
    let vendor_font_intensity = match vendor_hits.len() {
        0 => 0,
        1 => 80,
        _ => 100,
    };
    let vendor_fonts_raw = if vendor_hits.is_empty() {
        pick(lang, "未检出", "None detected").to_owned()
    } else {
        vendor_hits.join(", ")
    };
    signals.push(FingerprintSignal {
        id: "vendor_fonts".to_owned(),
        label_zh: "厂商 / 软件特征字体".to_owned(),
        label_en: "Vendor / Suite Fonts".to_owned(),
        weight: 12,
        intensity_pct: vendor_font_intensity,
        contribution: calc_contribution(12, vendor_font_intensity),
        raw: vendor_fonts_raw,
        hit: vendor_font_intensity >= 25,
    });

    // 5. Installed Regional Browsers (weight 10)
    let browser_intensity = match sys.installed_regional_browsers.len() {
        0 => 0,
        1 => 80,
        _ => 100,
    };
    let browser_raw = if sys.installed_regional_browsers.is_empty() {
        pick(lang, "未检出", "None detected").to_owned()
    } else {
        sys.installed_regional_browsers.join(", ")
    };
    signals.push(FingerprintSignal {
        id: "regional_browsers".to_owned(),
        label_zh: "本机区域浏览器痕迹".to_owned(),
        label_en: "Regional Browsers Installed".to_owned(),
        weight: 10,
        intensity_pct: browser_intensity,
        contribution: calc_contribution(10, browser_intensity),
        raw: browser_raw,
        hit: browser_intensity >= 25,
    });

    // 6. Hardware OEM (weight 8)
    let (oem_name, oem_intensity) = match_oem(
        sys.hardware_vendor.as_deref(),
        sys.hardware_model.as_deref(),
    );
    let oem_raw = if let Some(name) = oem_name {
        format!(
            "{name} ({})",
            sys.hardware_model
                .as_deref()
                .or(sys.hardware_vendor.as_deref())
                .unwrap_or(name)
        )
    } else {
        sys.hardware_vendor
            .as_deref()
            .unwrap_or_else(|| pick(lang, "通用硬件", "Generic hardware"))
            .to_owned()
    };
    signals.push(FingerprintSignal {
        id: "hardware_oem".to_owned(),
        label_zh: "硬件设备品牌标识".to_owned(),
        label_en: "Hardware OEM Signature".to_owned(),
        weight: 8,
        intensity_pct: oem_intensity,
        contribution: calc_contribution(8, oem_intensity),
        raw: oem_raw,
        hit: oem_intensity >= 25,
    });

    // 7. UTC+8 Offset Signal (weight 4) — only counts if timezone is not explicitly non-restricted (e.g. Asia/Taipei / Asia/Singapore)
    let non_restricted_utc8 = effective_tz.is_some_and(|tz| {
        tz.eq_ignore_ascii_case("Asia/Taipei")
            || tz.eq_ignore_ascii_case("Asia/Singapore")
            || tz.eq_ignore_ascii_case("Asia/Kuala_Lumpur")
            || tz.eq_ignore_ascii_case("Australia/Perth")
    });
    let offset_intensity = if sys.local_utc_offset_secs == 8 * 3600 && !non_restricted_utc8 {
        75
    } else {
        0
    };
    let utc_hours = sys.local_utc_offset_secs as f64 / 3600.0;
    let offset_raw = if utc_hours >= 0.0 {
        format!("UTC+{utc_hours:.0}")
    } else {
        format!("UTC{utc_hours:.0}")
    };
    signals.push(FingerprintSignal {
        id: "utc_offset".to_owned(),
        label_zh: "时区偏移 (UTC+8)".to_owned(),
        label_en: "Timezone Offset (UTC+8)".to_owned(),
        weight: 4,
        intensity_pct: offset_intensity,
        contribution: calc_contribution(4, offset_intensity),
        raw: offset_raw,
        hit: offset_intensity >= 25,
    });

    let total: u8 = signals
        .iter()
        .map(|s| s.contribution as u16)
        .sum::<u16>()
        .min(100) as u8;
    let band = RiskBand::from_score(total);

    let report = EnvFingerprintReport {
        score: total,
        band,
        signals: signals.clone(),
    };

    let hit_count = signals.iter().filter(|s| s.hit).count();
    let mut details: Vec<String> = Vec::with_capacity(signals.len() + 2);
    details.push(match lang {
        Lang::Zh => format!(
            "综合指纹风险分: {total}/100 ({}) · 命中 {hit_count}/{} 项信号（与出口 IP 纯净度独立计算）",
            i18n::risk_band_label(band, lang),
            signals.len()
        ),
        Lang::En => format!(
            "OS Fingerprint Risk Score: {total}/100 ({}) · {hit_count}/{} signals matched (independent from IP purity)",
            i18n::risk_band_label(band, lang),
            signals.len()
        ),
    });
    for s in &signals {
        let name = pick(lang, &s.label_zh, &s.label_en);
        let tag = if s.hit {
            pick(lang, "命中", "HIT")
        } else {
            pick(lang, "低", "OK")
        };
        details.push(format!(
            "[{tag}] {name} (+{}/{}) — {}",
            s.contribution, s.weight, s.raw
        ));
    }

    let state = match band {
        RiskBand::Low => CheckState::Ok,
        RiskBand::Medium | RiskBand::High => CheckState::Warn,
    };

    let summary = match (band, lang) {
        (RiskBand::Low, Lang::Zh) => format!("本机环境指纹风险较低: {total}/100（命中 {hit_count} 项）"),
        (RiskBand::Low, Lang::En) => format!("Low OS fingerprint risk: {total}/100 ({hit_count} signals matched)"),
        (RiskBand::Medium, Lang::Zh) => {
            format!("本机环境指纹呈中等风险: {total}/100（命中 {hit_count} 项，建议关注时区与语言）")
        }
        (RiskBand::Medium, Lang::En) => format!(
            "Moderate OS fingerprint risk: {total}/100 ({hit_count} signals matched; check timezone/locale)"
        ),
        (RiskBand::High, Lang::Zh) => {
            format!("本机环境指纹风险较高: {total}/100（命中 {hit_count} 项强区域特征）")
        }
        (RiskBand::High, Lang::En) => format!(
            "High OS fingerprint risk: {total}/100 ({hit_count} strong regional signals matched)"
        ),
    };

    let mut item = CheckItem::new(
        "env-fingerprint",
        CheckCategory::LocalEnv,
        i18n::check_title("env-fingerprint", lang).unwrap_or("OS Fingerprint Risk Score"),
        state,
        summary,
    )
    .with_details(details);

    if band != RiskBand::Low {
        item = item.with_suggestion(pick(
            lang,
            "使用 AI CLI 时可通过环境变量临时覆盖时区（如 TZ=America/Los_Angeles 或 TZ=Asia/Tokyo），浏览器端建议使用独立英文 Profile 隔离（本工具仅只读评估，不会修改系统设置）。",
            "Consider overriding TZ (e.g. TZ=America/Los_Angeles or TZ=Asia/Tokyo) when running AI CLIs, and use a dedicated English browser profile. This tool is read-only and never modifies OS settings.",
        ));
    }

    (report, item)
}
