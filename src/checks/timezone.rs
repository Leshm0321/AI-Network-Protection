use crate::model::{CheckCategory, CheckItem, CheckState, ExitGeoInfo};
use crate::net::system::SystemSnapshot;

pub fn format_utc_offset(secs: i32) -> String {
    let sign = if secs >= 0 { "+" } else { "-" };
    let abs = secs.unsigned_abs();
    let hours = abs / 3600;
    let mins = (abs % 3600) / 60;
    if mins == 0 {
        format!("UTC{sign}{hours}")
    } else {
        format!("UTC{sign}{hours}:{mins:02}")
    }
}

/// Pure read-only evaluator comparing local OS timezone/locale against exit IP timezone
/// (read-only: never modifies Windows/macOS timezone settings).
pub fn evaluate_timezone_and_locale(
    sys: &SystemSnapshot,
    exit_geo: Option<&ExitGeoInfo>,
) -> CheckItem {
    let local_tz = sys
        .local_timezone_iana
        .as_deref()
        .unwrap_or("未知本地时区");
    let local_offset_str = format_utc_offset(sys.local_utc_offset_secs);
    let locale = sys.local_locale.as_deref().unwrap_or("未知");

    let mut details = vec![
        format!("本机时区: {local_tz} ({local_offset_str})"),
        format!("本机系统语言 (Locale): {locale}"),
    ];

    let Some(geo) = exit_geo else {
        return CheckItem::new(
            "timezone",
            CheckCategory::LocalEnv,
            "时区与地区指纹一致性",
            CheckState::Unknown,
            format!("未能获取出口 IP 时区信息（本机: {local_tz} {local_offset_str}）"),
        )
        .with_details(details);
    };

    let exit_tz = geo.timezone_iana.as_deref().unwrap_or("未知");
    let exit_offset = geo.timezone_offset_secs;
    let exit_offset_str = exit_offset
        .map(format_utc_offset)
        .unwrap_or_else(|| "未知偏移".to_owned());

    details.push(format!(
        "出口 IP 时区 ({}): {exit_tz} ({exit_offset_str})",
        geo.country_code.as_deref().unwrap_or("-")
    ));

    let locale_is_zh_cn = locale.to_ascii_lowercase().starts_with("zh-cn")
        || locale.to_ascii_lowercase().starts_with("zh_cn");
    let exit_is_overseas = geo
        .country_code
        .as_deref()
        .is_some_and(|c| !c.eq_ignore_ascii_case("CN"));

    let tz_matches = match exit_offset {
        Some(off) => off == sys.local_utc_offset_secs,
        None => sys
            .local_timezone_iana
            .as_deref()
            .is_some_and(|l| l.eq_ignore_ascii_case(exit_tz)),
    };

    if !tz_matches {
        let diff_hours = exit_offset
            .map(|off| ((sys.local_utc_offset_secs - off).abs() as f64) / 3600.0)
            .unwrap_or(0.0);
        if locale_is_zh_cn && exit_is_overseas {
            details.push(
                "地区语言提示: 本机 Locale 为 zh-CN，浏览器/客户端指纹中 Accept-Language 与海外出口存在差异".to_owned(),
            );
        }
        return CheckItem::new(
            "timezone",
            CheckCategory::LocalEnv,
            "时区与地区指纹一致性",
            CheckState::Warn,
            format!(
                "时区不一致（相差 {diff_hours:.1}h）：本机 {local_tz} ({local_offset_str}) vs 出口 {exit_tz} ({exit_offset_str})"
            ),
        )
        .with_details(details)
        .with_suggestion(
            "若使用网页版 ChatGPT / Claude 高敏账号，可在浏览器防指纹插件或系统设置中将时区与出口地区对齐（本工具为只读检测，不会修改系统时区）。",
        );
    }

    if locale_is_zh_cn && exit_is_overseas {
        details.push("提示: 时区已对齐，仅系统 Locale 仍为 zh-CN（一般 CLI 使用影响较小，Web 端可按需注意）".to_owned());
    }

    CheckItem::new(
        "timezone",
        CheckCategory::LocalEnv,
        "时区与地区指纹一致性",
        CheckState::Ok,
        format!("本机时区 ({local_tz} {local_offset_str}) 与出口时区 ({exit_tz}) 一致"),
    )
    .with_details(details)
}
