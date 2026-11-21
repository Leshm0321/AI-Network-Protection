use crate::i18n::{self, Lang, pick};
use crate::model::{CheckCategory, CheckState, DoctorReport};

fn ansi_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn colorize(text: &str, code: &str) -> String {
    if ansi_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

fn state_badge(state: CheckState, lang: Lang) -> String {
    let raw = format!("[{} {}]", state.icon(), state.label(lang));
    match state {
        CheckState::Ok => colorize(&raw, "32;1"),
        CheckState::Warn => colorize(&raw, "33;1"),
        CheckState::Unknown => colorize(&raw, "90;1"),
        CheckState::Fail => colorize(&raw, "31;1"),
    }
}

pub fn render_cli_report(report: &DoctorReport, lang: Lang) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "\n{}\n",
        colorize(
            pick(
                lang,
                "================ AI-Network-Protection 体检报告 ================",
                "================ AI-Network-Protection Report =================="
            ),
            "36;1"
        )
    ));
    out.push_str(&format!(
        "{}: {}   {}: {:.1}s   {}: {}\n",
        pick(lang, "时间", "Time"),
        report.generated_at,
        pick(lang, "总耗时", "Duration"),
        report.total_duration_ms as f64 / 1000.0,
        pick(lang, "总体状态", "Overall"),
        state_badge(report.overall, lang)
    ));
    out.push_str(&format!(
        "{}: {}\n",
        pick(lang, "网络路径", "Network Path"),
        report.network_path.mode_label
    ));

    if let Some(ref geo) = report.exit_geo {
        let loc = [
            geo.country_code.as_deref(),
            geo.country.as_deref(),
            geo.city.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" / ");
        out.push_str(&format!(
            "{}: {}   {}: {}   ISP: {}\n",
            pick(lang, "出口 IP ", "Exit IP "),
            geo.ip,
            pick(lang, "地区", "Region"),
            if loc.is_empty() { "-" } else { &loc },
            geo.isp
                .as_deref()
                .or(geo.org.as_deref())
                .unwrap_or_else(|| pick(lang, "未知", "Unknown"))
        ));
    }

    if let Some(ref purity) = report.ip_purity {
        let score_str = match (purity.purity, purity.band) {
            (Some(s), Some(b)) => format!("{s}/100 ({})", i18n::purity_band_label(b, lang)),
            _ => pick(lang, "未配置信誉源 (启发式)", "Unconfigured (Heuristic)").to_owned(),
        };
        out.push_str(&format!(
            "{}: {} · {}\n",
            pick(lang, "IP 纯净度", "IP Purity"),
            score_str,
            i18n::network_type_label(purity.network_type, lang)
        ));
    }

    if let Some(ref fp) = report.env_fingerprint {
        out.push_str(&format!(
            "{}: {}/100 ({})\n",
            pick(lang, "环境指纹分", "OS Fingerprint"),
            fp.score,
            i18n::risk_band_label(fp.band, lang)
        ));
    }

    out.push_str(&format!(
        "{}: {} {}  {} {}  {} {}  {} {}\n",
        pick(lang, "统计    ", "Summary "),
        pick(lang, "通过", "Pass"),
        report.count_by_state(CheckState::Ok),
        pick(lang, "警告", "Warn"),
        report.count_by_state(CheckState::Warn),
        pick(lang, "未知", "Unknown"),
        report.count_by_state(CheckState::Unknown),
        pick(lang, "失败", "Fail"),
        report.count_by_state(CheckState::Fail),
    ));

    for category in [
        CheckCategory::NetworkLeak,
        CheckCategory::AiServices,
        CheckCategory::LocalEnv,
        CheckCategory::Controller,
    ] {
        let items: Vec<_> = report
            .items
            .iter()
            .filter(|i| i.category == category)
            .collect();
        if items.is_empty() {
            continue;
        }

        out.push_str(&format!(
            "\n{}\n",
            colorize(&format!("--- {} ---", category.label(lang)), "34;1")
        ));
        for item in items {
            let title = i18n::check_title(&item.key, lang).unwrap_or(&item.title);
            out.push_str(&format!(
                "{} {} ({:.1}s)\n",
                state_badge(item.state, lang),
                colorize(title, "1"),
                item.duration_ms as f64 / 1000.0
            ));
            out.push_str(&format!(
                "    {}: {}\n",
                pick(lang, "结论", "Summary"),
                item.summary
            ));
            for d in &item.details {
                out.push_str(&format!("      · {d}\n"));
            }
            if let Some(ref sug) = item.suggestion {
                out.push_str(&format!(
                    "    {}\n",
                    colorize(&format!("{}: {sug}", pick(lang, "建议", "Advice")), "33")
                ));
            }
        }
    }

    out.push('\n');
    out
}
