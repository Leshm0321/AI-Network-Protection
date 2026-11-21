use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use reqwest::Client;
use serde_json::Value;
use url::Url;

use crate::checks::env_fingerprint::RESTRICTED_CN_TIMEZONES;
use crate::i18n::{self, Lang, pick};
use crate::model::{CheckCategory, CheckItem, CheckState};

/// Core Claude environment variable names audited for shell/config consistency.
pub const CLAUDE_ENV_VARS: &[&str] = &[
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
];

/// Extended AI CLI environment variables that commonly cause hidden overrides or auth conflicts.
pub const EXTENDED_AI_ENV_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GEMINI_BASE_URL",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeEnvMap {
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvValidationResult {
    pub is_consistent: bool,
    pub differences: Vec<(String, String, String)>,
    pub missing_vars: Vec<String>,
    pub extra_vars: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeConfigSummary {
    pub claude_dir: Option<PathBuf>,
    pub settings_path: Option<PathBuf>,
    pub presets_found: Vec<String>,
    pub backups_count: usize,
    pub config_env: ClaudeEnvMap,
    pub format_errors: Vec<String>,
    pub format_warnings: Vec<String>,
    pub provider_name: String,
    pub base_url: Option<String>,
    pub auth_token: Option<String>,
    pub model: Option<String>,
}

/// Mask token/API key for safe terminal and UI display.
pub fn mask_secret(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let start: String = chars[..4].iter().collect();
    let end: String = chars[chars.len() - 4..].iter().collect();
    let mid_len = (chars.len() - 8).clamp(4, 16);
    format!("{start}{}{end}", "*".repeat(mid_len))
}

/// Detect provider type from `ANTHROPIC_BASE_URL`.
pub fn detect_provider_type(base_url: Option<&str>) -> &'static str {
    let Some(raw) = base_url else {
        return "Anthropic 官方 (默认)";
    };
    let url = raw.to_ascii_lowercase();
    if url.contains("anthropic.com") {
        "Anthropic 官方"
    } else if url.contains("openai.com") {
        "OpenAI"
    } else if url.contains("deepseek.com") {
        "DeepSeek"
    } else if url.contains("aliyuncs.com") || url.contains("dashscope") {
        "Qwen (阿里云)"
    } else if url.contains("bigmodel.cn") {
        "GLM (智谱)"
    } else if url.contains("moonshot.cn") {
        "Kimi (月之暗面)"
    } else if url.contains("openrouter.ai") {
        "OpenRouter"
    } else if url.contains("localhost") || url.contains("127.0.0.1") {
        "本地模型 / 本地反代 (Ollama/Local)"
    } else {
        "第三方中转 / 自定义网关"
    }
}

/// Cross-platform Claude config directory discovery.
pub fn candidate_claude_dirs(override_dir: Option<&str>) -> Vec<PathBuf> {
    if let Some(custom) = override_dir.filter(|s| !s.trim().is_empty()) {
        return vec![PathBuf::from(custom)];
    }

    let mut dirs = Vec::new();
    let home = dirs::home_dir();

    #[cfg(target_os = "windows")]
    {
        if let Some(ref h) = home {
            // Check %USERPROFILE%\.claude first, then %APPDATA%\.claude and %LOCALAPPDATA%\.claude.
            dirs.push(h.join(".claude"));
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            dirs.push(PathBuf::from(appdata).join(".claude"));
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            dirs.push(PathBuf::from(local).join(".claude"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(ref h) = home {
            dirs.push(h.join(".claude"));
            dirs.push(h.join("Library").join("Application Support").join("claude"));
            dirs.push(h.join("Library").join("Preferences").join("claude"));
        }
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        if let Some(ref h) = home {
            dirs.push(h.join(".claude"));
        }
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            dirs.push(PathBuf::from(xdg).join("claude"));
        } else if let Some(ref h) = home {
            dirs.push(h.join(".config").join("claude"));
        }
        if let Some(ref h) = home {
            dirs.push(h.join(".local").join("share").join("claude"));
        }
    }

    dirs
}

pub fn find_claude_dir(override_dir: Option<&str>) -> Option<PathBuf> {
    let candidates = candidate_claude_dirs(override_dir);
    // Prefer a directory that actually contains settings.json or settings_*.json
    for dir in &candidates {
        if dir.is_dir() {
            if dir.join("settings.json").is_file() {
                return Some(dir.clone());
            }
            if let Ok(entries) = std::fs::read_dir(dir) {
                let has_preset = entries.flatten().any(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.starts_with("settings_") && name.ends_with(".json")
                });
                if has_preset {
                    return Some(dir.clone());
                }
            }
        }
    }
    // Fallback to any existing .claude directory
    candidates.into_iter().find(|d| d.is_dir())
}

/// Parse & validate a Claude `settings.json` payload (pure logic, unit-testable).
pub fn parse_and_validate_settings_json(raw: &str) -> (ClaudeEnvMap, Vec<String>, Vec<String>) {
    let mut env_map = ClaudeEnvMap::default();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let parsed: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("settings.json 不是合法 JSON: {e}"));
            return (env_map, errors, warnings);
        }
    };

    let Some(obj) = parsed.as_object() else {
        errors.push("settings.json 根节点必须是 JSON 对象".to_owned());
        return (env_map, errors, warnings);
    };

    if let Some(env_val) = obj.get("env") {
        match env_val.as_object() {
            Some(env_obj) => {
                for (k, v) in env_obj {
                    if let Some(s) = v.as_str() {
                        env_map.values.insert(k.clone(), s.to_owned());
                    }
                }
            }
            None => {
                errors.push("settings.json 的 \"env\" 字段必须是对象".to_owned());
            }
        }
    }

    // Validate ANTHROPIC_BASE_URL if present
    if let Some(url_str) = env_map.values.get("ANTHROPIC_BASE_URL") {
        if url_str.trim().is_empty() {
            errors.push("ANTHROPIC_BASE_URL 为空字符串".to_owned());
        } else if Url::parse(url_str).is_err() {
            errors.push(format!("ANTHROPIC_BASE_URL 不是有效 URL: {url_str}"));
        } else if url_str.starts_with("http://")
            && !url_str.contains("localhost")
            && !url_str.contains("127.0.0.1")
        {
            warnings.push(format!(
                "ANTHROPIC_BASE_URL 使用明文 HTTP ({url_str})，存在凭证泄露风险"
            ));
        }
    }

    // Validate ANTHROPIC_AUTH_TOKEN if present
    if let Some(tok) = env_map.values.get("ANTHROPIC_AUTH_TOKEN") {
        if tok.trim().is_empty() {
            errors.push("ANTHROPIC_AUTH_TOKEN 不能为空".to_owned());
        } else if tok.trim().len() < 10 {
            warnings.push("ANTHROPIC_AUTH_TOKEN 长度过短（<10 字符），可能是占位符".to_owned());
        }
    }

    // Check simultaneous ANTHROPIC_AUTH_TOKEN + ANTHROPIC_API_KEY inside settings.json
    if env_map.values.contains_key("ANTHROPIC_AUTH_TOKEN")
        && env_map.values.contains_key("ANTHROPIC_API_KEY")
    {
        warnings.push(
            "settings.json 同时定义了 ANTHROPIC_AUTH_TOKEN 与 ANTHROPIC_API_KEY，可能引发鉴权优先级冲突"
                .to_owned(),
        );
    }

    if let Some(model) = env_map.values.get("ANTHROPIC_MODEL") {
        if model.trim().is_empty() {
            errors.push("ANTHROPIC_MODEL 不能为空".to_owned());
        }
    }

    (env_map, errors, warnings)
}

/// Compare `settings.json` env definitions against live process environment variables.
/// Pure function taking a `process_env` map so it can be unit-tested cleanly.
pub fn validate_environment_consistency(
    config_env: &ClaudeEnvMap,
    process_env: &BTreeMap<String, String>,
) -> EnvValidationResult {
    let mut differences = Vec::new();
    let mut missing_vars = Vec::new();
    let mut extra_vars = Vec::new();

    for var_name in CLAUDE_ENV_VARS {
        let cfg_val = config_env.values.get(*var_name);
        let env_val = process_env.get(*var_name);

        match (cfg_val, env_val) {
            (Some(c), Some(e)) if c != e => {
                differences.push(((*var_name).to_owned(), c.clone(), e.clone()));
            }
            (Some(_), None) => {
                missing_vars.push((*var_name).to_owned());
            }
            (None, Some(e)) => {
                extra_vars.push(((*var_name).to_owned(), e.clone()));
            }
            _ => {}
        }
    }

    // Also check if ANTHROPIC_API_KEY is present in process_env while settings uses AUTH_TOKEN or official login
    if let Some(api_key) = process_env.get("ANTHROPIC_API_KEY") {
        if config_env.values.get("ANTHROPIC_API_KEY") != Some(api_key) {
            extra_vars.push(("ANTHROPIC_API_KEY".to_owned(), api_key.clone()));
        }
    }

    let is_consistent = differences.is_empty() && extra_vars.is_empty();
    EnvValidationResult {
        is_consistent,
        differences,
        missing_vars,
        extra_vars,
    }
}

pub fn inspect_claude_config(override_dir: Option<&str>) -> ClaudeConfigSummary {
    let claude_dir = find_claude_dir(override_dir);
    let mut presets_found = Vec::new();
    let mut backups_count = 0usize;
    let mut settings_path = None;
    let mut config_env = ClaudeEnvMap::default();
    let mut format_errors = Vec::new();
    let mut format_warnings = Vec::new();

    if let Some(ref dir) = claude_dir {
        let sf = dir.join("settings.json");
        if sf.is_file() {
            settings_path = Some(sf.clone());
            match std::fs::read_to_string(&sf) {
                Ok(raw) => {
                    let (env, errs, warns) = parse_and_validate_settings_json(&raw);
                    config_env = env;
                    format_errors = errs;
                    format_warnings = warns;
                }
                Err(e) => {
                    format_errors.push(format!("无法读取 {}: {e}", sf.display()));
                }
            }
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("settings_") && name.ends_with(".json") {
                    presets_found.push(name);
                } else if name.starts_with("settings.json.backup.") {
                    backups_count += 1;
                }
            }
        }
        presets_found.sort();
    }

    let base_url = config_env.values.get("ANTHROPIC_BASE_URL").cloned();
    let auth_token = config_env.values.get("ANTHROPIC_AUTH_TOKEN").cloned();
    let model = config_env.values.get("ANTHROPIC_MODEL").cloned();
    let provider_name = detect_provider_type(base_url.as_deref()).to_owned();

    ClaudeConfigSummary {
        claude_dir,
        settings_path,
        presets_found,
        backups_count,
        config_env,
        format_errors,
        format_warnings,
        provider_name,
        base_url,
        auth_token,
        model,
    }
}

fn current_process_env_map() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for key in CLAUDE_ENV_VARS.iter().chain(EXTENDED_AI_ENV_VARS.iter()) {
        if let Ok(v) = std::env::var(key) {
            if !v.trim().is_empty() {
                map.insert((*key).to_owned(), v);
            }
        }
    }
    map
}

fn format_env_display(key: &str, value: &str) -> String {
    if key.contains("TOKEN") || key.contains("KEY") {
        mask_secret(value)
    } else {
        value.to_owned()
    }
}

/// High-risk third-party relay / domestic AI lab hostname keywords audited for Claude Code custom endpoints.
const RELAY_RISK_KEYWORDS: &[&str] = &[
    "deepseek",
    "moonshot",
    "zhipu",
    "bigmodel",
    "minimax",
    "dashscope",
    "aliyuncs",
    "siliconflow",
    "baichuan",
    "stepfun",
    "01.ai",
    "volces",
    "xfyun",
    "hunyuan",
    "qianfan",
    "openrouter",
];

/// Pure evaluator auditing `ANTHROPIC_BASE_URL` relay hostname + restricted timezone steganography risk.
pub fn evaluate_claude_endpoint_risk(
    effective_base_url: Option<&str>,
    os_timezone: Option<&str>,
    tz_env_override: Option<&str>,
    assume_first_party: bool,
    lang: Lang,
) -> CheckItem {
    let title = i18n::check_title("claude-endpoint-risk", lang)
        .unwrap_or("Claude Relay & Steganography Audit");
    let effective_tz = tz_env_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(os_timezone);
    let in_cn_tz = effective_tz.is_some_and(|tz| {
        RESTRICTED_CN_TIMEZONES
            .iter()
            .any(|z| z.eq_ignore_ascii_case(tz.trim()))
    });

    let Some(raw_url) = effective_base_url.map(str::trim).filter(|s| !s.is_empty()) else {
        let mut details = vec![
            pick(
                lang,
                "当前未配置自定义 ANTHROPIC_BASE_URL，默认直连 Anthropic 官方端点",
                "No custom ANTHROPIC_BASE_URL configured; defaults to official Anthropic endpoint",
            )
            .to_owned(),
            format!(
                "{}: {}",
                pick(lang, "生效时区", "Effective Timezone"),
                effective_tz.unwrap_or("-")
            ),
        ];
        if in_cn_tz {
            details.push(
                pick(
                    lang,
                    "提示：当前系统时区为受限区域时区，虽然未启用中转，但仍建议关注全局时区策略",
                    "Note: OS timezone is in a restricted region; while no custom relay is set, consider timezone alignment",
                )
                .to_owned(),
            );
        }
        return CheckItem::new(
            "claude-endpoint-risk",
            CheckCategory::LocalEnv,
            title,
            CheckState::Ok,
            pick(
                lang,
                "使用官方默认端点，无自定义中转隐写触发风险",
                "Official default endpoint in use; no custom relay steganography trigger",
            ),
        )
        .with_details(details);
    };

    let host = url::Url::parse(raw_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_else(|| raw_url.to_ascii_lowercase());

    if host == "api.anthropic.com" || host.ends_with(".anthropic.com") {
        return CheckItem::new(
            "claude-endpoint-risk",
            CheckCategory::LocalEnv,
            title,
            CheckState::Ok,
            match lang {
                Lang::Zh => format!("指向 Anthropic 官方域名 ({host})，无非官方中转标记风险"),
                Lang::En => format!("Points to official Anthropic host ({host}); no third-party relay trigger"),
            },
        )
        .with_details(vec![format!("ANTHROPIC_BASE_URL: {raw_url}")]);
    }

    let is_cn_tld = host.ends_with(".cn");
    let matched_kw: Vec<&str> = RELAY_RISK_KEYWORDS
        .iter()
        .copied()
        .filter(|kw| host.contains(kw))
        .collect();

    let mut details = vec![
        format!("ANTHROPIC_BASE_URL: {raw_url}"),
        format!("{}: {host}", pick(lang, "中转主机名", "Relay Hostname")),
        format!(
            "{}: {} (TZ={})",
            pick(lang, "系统时区", "OS Timezone"),
            os_timezone.unwrap_or("-"),
            tz_env_override.unwrap_or(pick(lang, "未设置", "unset"))
        ),
        format!(
            "_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL: {}",
            if assume_first_party {
                pick(lang, "已开启 (1)", "enabled (1)")
            } else {
                pick(lang, "未设置", "unset")
            }
        ),
    ];

    let mut risks = Vec::new();
    if is_cn_tld {
        risks.push(pick(lang, "命中 .cn 域名后缀", "matches .cn TLD").to_owned());
    }
    if !matched_kw.is_empty() {
        risks.push(match lang {
            Lang::Zh => format!("命中敏感中转/模型商关键词 ({})", matched_kw.join(", ")),
            Lang::En => format!("matches flagged provider keywords ({})", matched_kw.join(", ")),
        });
    }
    if in_cn_tz {
        risks.push(match lang {
            Lang::Zh => format!(
                "生效时区 {} 处于受限区间，可能触发日期分隔符/隐写特征",
                effective_tz.unwrap_or("")
            ),
            Lang::En => format!(
                "effective timezone {} is in a restricted zone and may trigger date-separator steganography",
                effective_tz.unwrap_or("")
            ),
        });
    }

    if assume_first_party && !in_cn_tz && risks.is_empty() {
        return CheckItem::new(
            "claude-endpoint-risk",
            CheckCategory::LocalEnv,
            title,
            CheckState::Ok,
            match lang {
                Lang::Zh => format!("自定义端点 ({host}) 已配置防护变量且时区安全"),
                Lang::En => format!("Custom endpoint ({host}) has first-party safeguard and safe timezone"),
            },
        )
        .with_details(details);
    }

    if !risks.is_empty() {
        for r in &risks {
            details.push(format!("! {r}"));
        }
        let state = if assume_first_party {
            CheckState::Warn
        } else {
            CheckState::Warn
        };
        let summary = match lang {
            Lang::Zh => format!(
                "自定义中转 ({host}) 存在 {} 项隐写/风控触发风险",
                risks.len()
            ),
            Lang::En => format!(
                "Custom relay ({host}) has {} steganography/risk trigger(s)",
                risks.len()
            ),
        };
        return CheckItem::new(
            "claude-endpoint-risk",
            CheckCategory::LocalEnv,
            title,
            state,
            summary,
        )
        .with_details(details)
        .with_suggestion(pick(
            lang,
            "使用自定义中转时，建议在启动 Claude Code 前设置 TZ=America/Los_Angeles（或 Asia/Tokyo）与 _CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL=1，并尽量避免使用 .cn 或敏感关键词中转域名。",
            "When using a custom relay, consider setting TZ=America/Los_Angeles (or Asia/Tokyo) and _CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL=1 before launching Claude Code, and avoid .cn or flagged provider hostnames.",
        ));
    }

    CheckItem::new(
        "claude-endpoint-risk",
        CheckCategory::LocalEnv,
        title,
        if assume_first_party {
            CheckState::Ok
        } else {
            CheckState::Warn
        },
        match lang {
            Lang::Zh => format!(
                "使用非官方自定义端点 ({host})，未命中高危关键词{}",
                if assume_first_party {
                    "（已启用 first-party 标记）"
                } else {
                    "（未设置 _CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL=1）"
                }
            ),
            Lang::En => format!(
                "Using custom endpoint ({host}) with no flagged keywords{}",
                if assume_first_party {
                    " (first-party safeguard enabled)"
                } else {
                    " (_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL=1 unset)"
                }
            ),
        },
    )
    .with_details(details)
}

/// Run all local Claude configuration, environment consistency, relay audit, and extended AI CLI checks.
pub async fn run_claude_and_local_ai_checks(
    client: &Client,
    override_claude_dir: Option<&str>,
    os_timezone: Option<&str>,
    run_api_test: bool,
    lang: Lang,
) -> Vec<CheckItem> {
    let mut items = Vec::new();
    let start = Instant::now();

    let summary = inspect_claude_config(override_claude_dir);
    let proc_env = current_process_env_map();

    // 1. Claude Config & Integrity Check
    items.push(build_claude_config_item(&summary, start.elapsed().as_millis() as u64));

    // 2. Environment Variable Consistency Check
    let env_val = validate_environment_consistency(&summary.config_env, &proc_env);
    items.push(build_env_consistency_item(&summary, &env_val));

    // 3. Claude Custom Endpoint & Steganography Risk Audit
    let effective_base_url = proc_env
        .get("ANTHROPIC_BASE_URL")
        .or(summary.base_url.as_ref())
        .map(String::as_str);
    let tz_override = std::env::var("TZ").ok();
    let assume_first_party = std::env::var("_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    items.push(evaluate_claude_endpoint_risk(
        effective_base_url,
        os_timezone,
        tz_override.as_deref(),
        assume_first_party,
        lang,
    ));

    // 4. Extended Local AI CLI Check (~/.claude.json + OPENAI_* + GEMINI_*)
    items.push(build_extended_ai_cli_item(&proc_env));

    // 5. Optional API Connectivity Test (opt-in only)
    if run_api_test {
        items.push(run_opt_in_api_test(client, &summary, &proc_env).await);
    }

    items
}

fn build_claude_config_item(summary: &ClaudeConfigSummary, duration_ms: u64) -> CheckItem {
    let mut details = Vec::new();
    match &summary.claude_dir {
        Some(dir) => details.push(format!("Claude 配置目录: {}", dir.display())),
        None => {
            details.push("未在本机标准路径找到 .claude 配置目录".to_owned());
            return CheckItem::new(
                "claude-config",
                CheckCategory::LocalEnv,
                "Claude 配置完整性",
                CheckState::Ok,
                "未检测到本地 .claude 配置目录（如未使用 Claude Code 可忽略）",
            )
            .with_details(details)
            .with_duration(duration_ms);
        }
    }

    match &summary.settings_path {
        Some(sf) => details.push(format!("激活配置: {}", sf.display())),
        None => details.push("激活配置: 未找到 settings.json（使用默认/官方 OAuth 配置）".to_owned()),
    }

    details.push(format!("识别 Provider: {}", summary.provider_name));
    if let Some(ref url) = summary.base_url {
        details.push(format!("ANTHROPIC_BASE_URL: {url}"));
    }
    if let Some(ref model) = summary.model {
        details.push(format!("ANTHROPIC_MODEL: {model}"));
    }
    if let Some(ref tok) = summary.auth_token {
        details.push(format!("ANTHROPIC_AUTH_TOKEN: {}", mask_secret(tok)));
    }
    if !summary.presets_found.is_empty() {
        details.push(format!(
            "发现预设配置 ({} 个): {}",
            summary.presets_found.len(),
            summary.presets_found.join(", ")
        ));
    }
    if summary.backups_count > 0 {
        details.push(format!("配置备份文件: {} 个", summary.backups_count));
    }

    if !summary.format_errors.is_empty() {
        details.extend(summary.format_errors.iter().map(|e| format!("错误: {e}")));
        return CheckItem::new(
            "claude-config",
            CheckCategory::LocalEnv,
            "Claude 配置完整性",
            CheckState::Fail,
            format!("settings.json 存在格式/字段错误: {}", summary.format_errors.join("；")),
        )
        .with_details(details)
        .with_suggestion("请修复或从备份恢复 ~/.claude/settings.json，避免 Claude Code 启动异常。")
        .with_duration(duration_ms);
    }

    if !summary.format_warnings.is_empty() {
        details.extend(summary.format_warnings.iter().map(|w| format!("警告: {w}")));
        return CheckItem::new(
            "claude-config",
            CheckCategory::LocalEnv,
            "Claude 配置完整性",
            CheckState::Warn,
            summary.format_warnings.join("；"),
        )
        .with_details(details)
        .with_duration(duration_ms);
    }

    let summary_text = if summary.base_url.is_some() {
        format!(
            "settings.json 校验通过（Provider: {}）",
            summary.provider_name
        )
    } else {
        "Claude 配置目录正常（未覆盖 Base URL，默认走官方 Anthropic）".to_owned()
    };

    CheckItem::new(
        "claude-config",
        CheckCategory::LocalEnv,
        "Claude 配置完整性",
        CheckState::Ok,
        summary_text,
    )
    .with_details(details)
    .with_duration(duration_ms)
}

fn build_env_consistency_item(
    summary: &ClaudeConfigSummary,
    res: &EnvValidationResult,
) -> CheckItem {
    let mut details = Vec::new();

    for (var, cfg, env) in &res.differences {
        details.push(format!(
            "冲突 {var}: settings.json={} vs Shell 环境变量={}",
            format_env_display(var, cfg),
            format_env_display(var, env)
        ));
    }
    for (var, env) in &res.extra_vars {
        details.push(format!(
            "残留/额外环境变量 {var}={}",
            format_env_display(var, env)
        ));
    }
    for var in &res.missing_vars {
        details.push(format!(
            "仅在 settings.json 中定义（当前 Shell 未导出）: {var}"
        ));
    }

    if !res.differences.is_empty() {
        return CheckItem::new(
            "claude-env-sync",
            CheckCategory::LocalEnv,
            "Claude 环境变量一致性",
            CheckState::Fail,
            format!(
                "检测到 {} 项 Shell 环境变量与 settings.json 冲突，终端中的变量会覆盖配置！",
                res.differences.len()
            ),
        )
        .with_details(details)
        .with_suggestion("请重新加载终端或清理 Shell 配置文件（~/.zshrc / ~/.bashrc / Windows 系统环境变量）中的旧 ANTHROPIC_* 变量。");
    }

    if !res.extra_vars.is_empty() {
        let names = res
            .extra_vars
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join("、");
        return CheckItem::new(
            "claude-env-sync",
            CheckCategory::LocalEnv,
            "Claude 环境变量一致性",
            CheckState::Warn,
            format!("Shell 中存在未在 settings.json 定义的额外变量: {names}"),
        )
        .with_details(details)
        .with_suggestion(
            "若你使用官方 Claude 订阅登录，残留的 ANTHROPIC_BASE_URL 或 ANTHROPIC_API_KEY 会劫持请求到错误端点或导致计费异常，建议核对并清理。",
        );
    }

    if !res.missing_vars.is_empty() && summary.settings_path.is_some() {
        details.push("说明: Claude Code 会自动读取 settings.json 中的 env 字段；若用外部脚本依赖 Shell 环境变量则需要重新加载终端。".to_owned());
    } else {
        details.push("未检测到 ANTHROPIC_* 环境变量冲突或残留覆盖。".to_owned());
    }

    CheckItem::new(
        "claude-env-sync",
        CheckCategory::LocalEnv,
        "Claude 环境变量一致性",
        CheckState::Ok,
        "Claude 环境变量与配置文件一致，无冲突覆盖",
    )
    .with_details(details)
}

fn build_extended_ai_cli_item(proc_env: &BTreeMap<String, String>) -> CheckItem {
    let mut details = Vec::new();
    let mut warnings = Vec::new();

    // 1. Check ~/.claude.json integrity & notable flags
    if let Some(home) = dirs::home_dir() {
        let claude_json = home.join(".claude.json");
        if claude_json.is_file() {
            match std::fs::read_to_string(&claude_json) {
                Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                    Ok(v) => {
                        let has_oauth = v.get("oauthAccount").is_some();
                        let has_custom_key = v
                            .get("customApiKeyResponses")
                            .and_then(|x| x.get("approved"))
                            .and_then(|x| x.as_array())
                            .is_some_and(|a| !a.is_empty());
                        details.push(format!(
                            "~/.claude.json: JSON 有效 (OAuth账号={}, 已批准自定义Key={})",
                            if has_oauth { "有" } else { "无" },
                            if has_custom_key { "有" } else { "无" }
                        ));
                        if has_oauth
                            && (proc_env.contains_key("ANTHROPIC_BASE_URL")
                                || proc_env.contains_key("ANTHROPIC_API_KEY"))
                        {
                            warnings.push(
                                "~/.claude.json 存在官方 OAuth 登录态，但当前 Shell 同时设置了 ANTHROPIC_BASE_URL/API_KEY，可能触发账号混用风险".to_owned(),
                            );
                        }
                    }
                    Err(e) => {
                        warnings.push(format!("~/.claude.json 解析失败（文件可能损坏）: {e}"));
                    }
                },
                Err(e) => {
                    details.push(format!("~/.claude.json 读取失败: {e}"));
                }
            }
        } else {
            details.push("~/.claude.json: 未发现".to_owned());
        }

        // Check ~/.codex and ~/.gemini presence (read-only)
        let codex_dir = home.join(".codex");
        if codex_dir.is_dir() {
            details.push(format!("检测到 Codex 配置目录: {}", codex_dir.display()));
        }
        let gemini_dir = home.join(".gemini");
        if gemini_dir.is_dir() {
            details.push(format!("检测到 Gemini CLI 配置目录: {}", gemini_dir.display()));
        }
    }

    // 2. Inspect OPENAI_* / GEMINI_* / Bedrock / Vertex env vars
    for key in EXTENDED_AI_ENV_VARS {
        if let Some(val) = proc_env.get(*key) {
            let masked = format_env_display(key, val);
            details.push(format!("检测到环境变量 {key}={masked}"));
            if *key == "OPENAI_BASE_URL" && !val.to_ascii_lowercase().contains("openai.com") {
                warnings.push(format!("OPENAI_BASE_URL 指向非官方地址 ({val})"));
            }
            if *key == "GOOGLE_GEMINI_BASE_URL"
                && !val.to_ascii_lowercase().contains("googleapis.com")
            {
                warnings.push(format!("GOOGLE_GEMINI_BASE_URL 指向非官方地址 ({val})"));
            }
            if (*key == "CLAUDE_CODE_USE_BEDROCK" || *key == "CLAUDE_CODE_USE_VERTEX")
                && (val == "1" || val.eq_ignore_ascii_case("true"))
            {
                details.push(format!("提示: 已启用云托管后端开关 {key}={val}"));
            }
        }
    }

    if details.is_empty() {
        details.push("未发现冲突的扩展 AI CLI 配置或覆盖变量".to_owned());
    }

    if !warnings.is_empty() {
        return CheckItem::new(
            "ai-cli-ext",
            CheckCategory::LocalEnv,
            "多 AI CLI 配置与覆盖检测",
            CheckState::Warn,
            warnings.join("；"),
        )
        .with_details(details)
        .with_suggestion("如非刻意使用第三方中转或自定义后端，请清理残留的 *_BASE_URL / *_API_KEY 环境变量。");
    }

    CheckItem::new(
        "ai-cli-ext",
        CheckCategory::LocalEnv,
        "多 AI CLI 配置与覆盖检测",
        CheckState::Ok,
        "本地 Claude / OpenAI / Gemini CLI 配置及环境变量无异常覆盖",
    )
    .with_details(details)
}

/// Opt-in non-billing API endpoint connectivity & latency check.
async fn run_opt_in_api_test(
    client: &Client,
    summary: &ClaudeConfigSummary,
    proc_env: &BTreeMap<String, String>,
) -> CheckItem {
    let start = Instant::now();
    let base_url = proc_env
        .get("ANTHROPIC_BASE_URL")
        .or(summary.base_url.as_ref())
        .cloned()
        .unwrap_or_else(|| "https://api.anthropic.com".to_owned());
    let token = proc_env
        .get("ANTHROPIC_AUTH_TOKEN")
        .or_else(|| proc_env.get("ANTHROPIC_API_KEY"))
        .or(summary.auth_token.as_ref())
        .cloned();

    let Some(token) = token else {
        return CheckItem::new(
            "claude-api-test",
            CheckCategory::AiServices,
            "已配置 API 连通性测试（手动）",
            CheckState::Unknown,
            "未在 settings.json 或环境变量中找到 ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY，跳过凭据测试",
        );
    };

    let clean_base = base_url.trim_end_matches('/');
    let provider = detect_provider_type(Some(clean_base));
    // Prefer non-billing GET /v1/models endpoint so running diagnostics never consumes tokens
    let models_url = if clean_base.ends_with("/v1") {
        format!("{clean_base}/models")
    } else {
        format!("{clean_base}/v1/models")
    };

    let mut req = client.get(&models_url);
    if provider.contains("Anthropic") {
        req = req
            .header("x-api-key", &token)
            .header("anthropic-version", "2023-06-01");
    } else {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let mut details = vec![
        format!("测试端点: GET {models_url} (不消耗 Token)"),
        format!("识别 Provider: {provider}"),
        format!("凭据: {}", mask_secret(&token)),
    ];

    match req.send().await {
        Ok(resp) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status = resp.status().as_u16();
            details.push(format!("响应状态: HTTP {status} ({latency_ms}ms)"));
            if (200..300).contains(&status) {
                CheckItem::new(
                    "claude-api-test",
                    CheckCategory::AiServices,
                    "已配置 API 连通性测试（手动）",
                    CheckState::Ok,
                    format!("{provider} API 鉴权与连通正常 ({latency_ms}ms)"),
                )
                .with_details(details)
                .with_duration(latency_ms)
            } else if status == 401 || status == 403 {
                CheckItem::new(
                    "claude-api-test",
                    CheckCategory::AiServices,
                    "已配置 API 连通性测试（手动）",
                    CheckState::Fail,
                    format!("API 鉴权失败 (HTTP {status})，请检查 Token 有效性或出口权限"),
                )
                .with_details(details)
                .with_duration(latency_ms)
            } else {
                CheckItem::new(
                    "claude-api-test",
                    CheckCategory::AiServices,
                    "已配置 API 连通性测试（手动）",
                    CheckState::Warn,
                    format!("API 端点可达但返回 HTTP {status}（部分中转未实现 /v1/models）"),
                )
                .with_details(details)
                .with_duration(latency_ms)
            }
        }
        Err(e) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            details.push(format!("错误: {e}"));
            CheckItem::new(
                "claude-api-test",
                CheckCategory::AiServices,
                "已配置 API 连通性测试（手动）",
                CheckState::Fail,
                format!("API 端点连接失败: {e}"),
            )
            .with_details(details)
            .with_duration(latency_ms)
        }
    }
}
