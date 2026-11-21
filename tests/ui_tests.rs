use ai_network_protection::App;
use ai_network_protection::config::CheckOptions;
use ai_network_protection::i18n::Lang;
use ai_network_protection::model::{
    CheckCategory, CheckItem, CheckState, DoctorReport, EnvFingerprintReport, ExitGeoInfo,
    FingerprintSignal, IpPurityFlags, IpPurityReport, NetworkPathInfo, NetworkType, PurityBand,
    RiskBand,
};
use ai_network_protection::store::{set_initial_options, set_initial_report};
use nsh_engine::{EngineConfig, Points, Root, Size};
use nsh_testing::Headless;

fn seed_sample_report() {
    let mut opts = CheckOptions::default();
    opts.lang = Lang::Zh;
    set_initial_options(opts);

    let items = vec![
        CheckItem::new(
            "exit",
            CheckCategory::NetworkLeak,
            "出口 IP 一致性",
            CheckState::Ok,
            "3/3 公共端点出口完全一致: 203.0.113.7 [US]",
        )
        .with_details(vec!["cloudflare: ip=203.0.113.7 loc=US".to_owned()])
        .with_duration(310),
        CheckItem::new(
            "ai-anthropic",
            CheckCategory::AiServices,
            "Anthropic / Claude",
            CheckState::Ok,
            "主站与 API 均可达，出口一致: 203.0.113.7 [US]",
        )
        .with_details(vec!["主站 Trace: ip=203.0.113.7".to_owned()])
        .with_duration(240),
        CheckItem::new(
            "claude-env-sync",
            CheckCategory::LocalEnv,
            "Claude 环境变量一致性",
            CheckState::Warn,
            "Shell 中存在未在 settings.json 定义的额外变量: ANTHROPIC_API_KEY",
        )
        .with_details(vec!["残留/额外环境变量 ANTHROPIC_API_KEY=sk-1****abcd".to_owned()])
        .with_suggestion("请清理残留的 ANTHROPIC_API_KEY 环境变量")
        .with_duration(12),
    ];

    set_initial_report(DoctorReport {
        generated_at: "2026-11-20 19:30:00".to_owned(),
        overall: CheckState::Warn,
        total_duration_ms: 562,
        network_path: NetworkPathInfo {
            mode_label: "直出 / WiFi 软路由透明代理".to_owned(),
            ..Default::default()
        },
        exit_geo: Some(ExitGeoInfo {
            ip: "203.0.113.7".to_owned(),
            country_code: Some("US".to_owned()),
            isp: Some("Example ISP".to_owned()),
            ..Default::default()
        }),
        ip_purity: Some(IpPurityReport {
            ip: Some("203.0.113.7".to_owned()),
            purity: Some(92),
            band: Some(PurityBand::High),
            network_type: NetworkType::Residential,
            flags: IpPurityFlags::default(),
            deductions: Vec::new(),
            sources_configured: true,
            proxycheck_status: "ok".to_owned(),
            abuseipdb_status: "ok".to_owned(),
        }),
        env_fingerprint: Some(EnvFingerprintReport {
            score: 18,
            band: RiskBand::Low,
            signals: vec![FingerprintSignal {
                id: "timezone".to_owned(),
                label_zh: "系统时区".to_owned(),
                label_en: "System Timezone".to_owned(),
                weight: 28,
                intensity_pct: 0,
                contribution: 0,
                raw: "America/Los_Angeles".to_owned(),
                hit: false,
            }],
        }),
        ai_probes: Vec::new(),
        items,
    });
}

#[test]
fn dashboard_renders_seeded_report_switches_tabs_and_toggles_bilingual_ui() -> Result<(), String> {
    seed_sample_report();

    let mut app = Headless::start(EngineConfig {
        viewport: Size::new(Points(1200.0), Points(800.0)),
        ..EngineConfig::new(Root::of::<App>())
    })
    .map_err(|e| format!("{e:?}"))?;

    app.wait_for("AI-Network-Protection")?;
    app.wait_for("出口 IP 一致性")?;
    app.wait_for("92/100 · 高纯净")?;
    app.wait_for("18/100 · 低风险")?;

    // Clicking the warning item updates the right-hand inspector with its suggestion
    app.press("id:check-claude-env-sync")?;
    app.wait_for("修复建议: 请清理残留的 ANTHROPIC_API_KEY 环境变量")?;

    // Toggling Hide-IP privacy mode masks public IPs across KPI cards & list
    app.press("id:hide-ip-toggle")?;
    app.wait_for("203.0.*.* [US]")?;

    // Toggling the animated 中 / EN pill switch switches UI chrome & check titles instantaneously to English
    app.press("id:lang-toggle")?;
    app.wait_for("Full Scan")?;
    app.wait_for("Exit IP Consistency")?;
    app.wait_for("92/100 · High Purity")?;
    app.wait_for("18/100 · Low Risk")?;
    app.wait_for("● IP Hidden")?;

    // Switching to Settings tab displays the optional configuration form in English including Apple toggle switches
    app.press("Settings")?;
    app.wait_for("Save & Re-Scan")?;
    app.wait_for("proxycheck.io API Key")?;
    app.wait_for("Cloudflare Radar API Token")?;
    app.wait_for("Enable 17 Public CIDR Threat/Datacenter Lists & Whole-ASN Abuse Density (on by default, 12h cache)")?;
    // Verify the Apple toggle switch row is interactive
    app.press("Enable 17 Public CIDR Threat/Datacenter Lists & Whole-ASN Abuse Density (on by default, 12h cache)")?;

    Ok(())
}
