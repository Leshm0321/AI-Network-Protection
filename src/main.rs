#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::process::ExitCode;

use ai_network_protection::checks::run_all_checks;
use ai_network_protection::cli_output::render_cli_report;
use ai_network_protection::config::CheckOptions;
use ai_network_protection::i18n::Lang;
use ai_network_protection::model::CheckState;
use ai_network_protection::store::set_initial_options;
use clap::Parser;

/// AI-Network-Protection — 只读 AI 网络防风控与本地环境体检桌面应用 / Read-only AI Network & Environment Diagnostics (Windows & macOS)
#[derive(Debug, Parser)]
#[command(name = "AI-Network-Protection", version, about)]
struct Cli {
    /// 非交互单次体检并输出终端报告（不打开桌面窗口） / Run once in CLI mode
    #[arg(long)]
    cli: bool,

    /// 输出结构化 JSON 体检报告（不打开桌面窗口） / Output JSON report
    #[arg(long)]
    json: bool,

    /// 界面与输出语言 (zh / en) / UI and report language (zh / en)
    #[arg(long)]
    lang: Option<String>,

    /// 快速模式：长连接测试缩短为 8 秒（默认 15 秒） / Quick mode (8s keep-alive)
    #[arg(short = 'q', long)]
    quick: bool,

    /// 手动指定代理 URL / Explicit proxy URL (http://... or socks5h://...)
    #[arg(long)]
    proxy: Option<String>,

    /// 强制忽略系统代理和环境变量代理 / Ignore system & env proxy (direct / soft-router)
    #[arg(long)]
    no_proxy: bool,

    /// 预期独享/住宅出口 IP / Expected dedicated exit IP
    #[arg(long)]
    expected_ip: Option<String>,

    /// 预期出口国家代码 (ISO-2, e.g. US/JP/SG) / Expected exit country ISO-2 code
    #[arg(long)]
    expected_country: Option<String>,

    /// 可选：Clash / Mihomo External Controller 地址 / Optional Clash/Mihomo controller URL
    #[arg(long)]
    controller: Option<String>,

    /// 可选：Clash / Mihomo Controller Bearer Secret
    #[arg(long)]
    controller_secret: Option<String>,

    /// 可选：自定义 .claude 配置目录路径 / Optional .claude config directory override
    #[arg(long)]
    claude_dir: Option<String>,

    /// 可选：proxycheck.io API Key（用于 IP 纯净度精评） / Optional proxycheck.io API key
    #[arg(long)]
    proxycheck_key: Option<String>,

    /// 可选：AbuseIPDB API Key（用于 IP 纯净度精评） / Optional AbuseIPDB API key
    #[arg(long)]
    abuseipdb_key: Option<String>,

    /// 可选：Cloudflare Radar API Token（用于 ASN 28天 Bot 流量占比） / Optional Cloudflare Radar token
    #[arg(long)]
    cf_radar_token: Option<String>,

    /// 可选：GreyNoise API Key / Optional GreyNoise API key
    #[arg(long)]
    greynoise_key: Option<String>,

    /// 可选：CrowdSec CTI API Key / Optional CrowdSec CTI API key
    #[arg(long)]
    crowdsec_key: Option<String>,

    /// 可选：VirusTotal API Key / Optional VirusTotal API key
    #[arg(long)]
    virustotal_key: Option<String>,

    /// 可选：IPRegistry API Key / Optional IPRegistry API key
    #[arg(long)]
    ipregistry_key: Option<String>,

    /// 可选：IPData API Key / Optional IPData API key
    #[arg(long)]
    ipdata_key: Option<String>,

    /// 启用 17 份公开 CIDR 威胁/代理/机房列表与 ASN 滥用密度（默认已开启） / Enable 17 CIDR lists (on by default)
    #[arg(long)]
    cidr_lists: bool,

    /// 跳过 17 份公开 CIDR 威胁/机房列表下载（轻量模式） / Skip CIDR threat/datacenter list download
    #[arg(long)]
    no_cidr_lists: bool,

    /// 可选：仅对指定公网 IP 执行独立纯净度与黑名单体检 / Inspect an arbitrary public IPv4/IPv6 only
    #[arg(long)]
    target_ip: Option<String>,

    /// 隐私模式：对 CLI / JSON 输出中的所有公网 IP 自动打码 / Mask public IPs in CLI/JSON output
    #[arg(long)]
    hide_ip: bool,

    /// 长连接测试窗口秒数（默认 15，快速模式 8） / Keep-alive test window in seconds
    #[arg(long)]
    long_secs: Option<u64>,

    /// 手动开启：对当前配置的 ANTHROPIC_BASE_URL 执行只读 API 连通性测试 / Opt-in GET /v1/models test
    #[arg(long)]
    api_test: bool,

    /// 保守模式：仅测 Cloudflare 中立端点与本机环境 / Neutral endpoints only
    #[arg(long)]
    neutral_only: bool,
}

fn build_options(cli: &Cli) -> CheckOptions {
    let mut opts = CheckOptions::from_env_defaults();
    if let Some(ref raw_lang) = cli.lang {
        if let Some(parsed) = Lang::from_str_opt(raw_lang) {
            opts.lang = parsed;
        }
    }
    if cli.proxy.is_some() {
        opts.proxy = cli.proxy.clone();
    }
    opts.no_proxy = cli.no_proxy;
    if cli.expected_ip.is_some() {
        opts.expected_ip = cli.expected_ip.clone();
    }
    if let Some(ref cc) = cli.expected_country {
        opts.expected_country = Some(cc.trim().to_ascii_uppercase());
    }
    if cli.controller.is_some() {
        opts.controller_url = cli.controller.clone();
    }
    if cli.controller_secret.is_some() {
        opts.controller_secret = cli.controller_secret.clone();
    }
    if cli.claude_dir.is_some() {
        opts.claude_dir = cli.claude_dir.clone();
    }
    if cli.proxycheck_key.is_some() {
        opts.proxycheck_api_key = cli.proxycheck_key.clone();
    }
    if cli.abuseipdb_key.is_some() {
        opts.abuseipdb_api_key = cli.abuseipdb_key.clone();
    }
    if cli.cf_radar_token.is_some() {
        opts.cf_radar_token = cli.cf_radar_token.clone();
    }
    if cli.greynoise_key.is_some() {
        opts.greynoise_api_key = cli.greynoise_key.clone();
    }
    if cli.crowdsec_key.is_some() {
        opts.crowdsec_api_key = cli.crowdsec_key.clone();
    }
    if cli.virustotal_key.is_some() {
        opts.virustotal_api_key = cli.virustotal_key.clone();
    }
    if cli.ipregistry_key.is_some() {
        opts.ipregistry_api_key = cli.ipregistry_key.clone();
    }
    if cli.ipdata_key.is_some() {
        opts.ipdata_api_key = cli.ipdata_key.clone();
    }
    if cli.no_cidr_lists {
        opts.enable_cidr_lists = false;
    } else if cli.cidr_lists {
        opts.enable_cidr_lists = true;
    }
    if cli.target_ip.is_some() {
        opts.target_ip = cli.target_ip.clone();
    }
    if cli.quick {
        opts.long_conn_secs = 8;
    }
    if let Some(secs) = cli.long_secs {
        opts.long_conn_secs = secs.clamp(4, 120);
    }
    opts.run_api_test = cli.api_test;
    opts.neutral_only = cli.neutral_only;
    opts
}

#[cfg(target_os = "windows")]
fn attach_parent_console_if_cli() {
    let wants_console = std::env::args().skip(1).any(|arg| {
        matches!(
            arg.as_str(),
            "--cli" | "--json" | "-h" | "--help" | "-V" | "--version"
        )
    });
    if wants_console {
        unsafe extern "system" {
            fn AttachConsole(dw_process_id: u32) -> i32;
        }
        const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
        // SAFETY: Best-effort attach to parent console when invoked with CLI flags from a shell.
        unsafe {
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn resolve_sidecar_icon(filename: &str) -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next_to_exe = dir.join(filename);
            if next_to_exe.is_file() {
                return Some(next_to_exe);
            }
            let dev_assets = dir.join("..").join("..").join("assets").join(filename);
            if dev_assets.is_file() {
                return Some(dev_assets);
            }
        }
    }
    let cwd_assets = std::path::PathBuf::from("assets").join(filename);
    if cwd_assets.is_file() {
        return Some(cwd_assets);
    }
    None
}

fn main() -> ExitCode {
    #[cfg(target_os = "windows")]
    attach_parent_console_if_cli();

    env_logger::init();
    let cli = Cli::parse();
    let opts = build_options(&cli);

    if cli.cli || cli.json {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("初始化异步运行时失败: {e}");
                return ExitCode::FAILURE;
            }
        };
        let report = rt.block_on(run_all_checks(&opts));
        let output_report = if cli.hide_ip {
            report.masked_for_privacy()
        } else {
            report.clone()
        };
        if cli.json {
            match serde_json::to_string_pretty(&output_report) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("JSON 序列化失败: {e}");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            print!("{}", render_cli_report(&output_report, opts.lang));
        }
        return if report.overall == CheckState::Fail {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }

    set_initial_options(opts);

    #[cfg(target_os = "windows")]
    {
        nsh_platform_windows::set_ui_sets(vec![
            nsh_base::registry(),
            ai_network_protection::registry(),
        ]);
        nsh_platform_windows::run_app(
            nsh_platform_windows::AppSource::Rust(nsh_platform_windows::Root::of::<
                ai_network_protection::App,
            >()),
            nsh_platform_windows::AppOptions {
                title: "AI-Network-Protection".to_owned(),
                app_id: "dev.ai.network.protection".to_owned(),
                icon: resolve_sidecar_icon("icon.ico"),
                size: (1180, 760),
                ..Default::default()
            },
        )
    }

    #[cfg(target_os = "macos")]
    {
        nsh_platform_macos::set_ui_sets(vec![
            nsh_base::registry(),
            ai_network_protection::registry(),
        ]);
        nsh_platform_macos::run_app(
            nsh_platform_macos::AppSource::Rust(nsh_platform_macos::Root::of::<
                ai_network_protection::App,
            >()),
            nsh_platform_macos::AppOptions {
                title: "AI-Network-Protection".to_owned(),
                app_id: "dev.ai.network.protection".to_owned(),
                icon: resolve_sidecar_icon("icon.png"),
                size: (1180, 760),
                ..Default::default()
            },
        )
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        eprintln!("桌面 GUI 支持 Windows 与 macOS；在 Linux 上请使用 --cli 或 --json 模式。");
        ExitCode::FAILURE
    }
}
