use std::sync::OnceLock;

use nsh_core::prelude::*;
use tokio::sync::mpsc;

use crate::checks::{run_all_checks_streaming, run_target_ip_checks_streaming};
use crate::config::CheckOptions;
use crate::i18n::{Lang, pick};
use crate::model::{CheckCategory, CheckItem, DoctorReport};

static INITIAL_OPTIONS: OnceLock<CheckOptions> = OnceLock::new();
static INITIAL_REPORT: OnceLock<DoctorReport> = OnceLock::new();

/// Configure initial options from CLI before launching the NSH surface.
pub fn set_initial_options(opts: CheckOptions) {
    let _ = INITIAL_OPTIONS.set(opts);
}

/// Optional seed report for headless UI tests (avoids live network calls in unit tests).
pub fn set_initial_report(report: DoctorReport) {
    let _ = INITIAL_REPORT.set(report);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    All,
    NetworkLeak,
    AiServices,
    LocalEnv,
    Controller,
    Settings,
}

impl ActiveTab {
    pub fn key(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::NetworkLeak => "network",
            Self::AiServices => "ai",
            Self::LocalEnv => "local",
            Self::Controller => "controller",
            Self::Settings => "settings",
        }
    }

    pub fn label_for(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Self::All, Lang::Zh) => "全部",
            (Self::All, Lang::En) => "Overview",
            (Self::NetworkLeak, Lang::Zh) => "网络与泄漏",
            (Self::NetworkLeak, Lang::En) => "Network & Leaks",
            (Self::AiServices, Lang::Zh) => "AI 服务",
            (Self::AiServices, Lang::En) => "AI Services",
            (Self::LocalEnv, Lang::Zh) => "本地与配置",
            (Self::LocalEnv, Lang::En) => "Local & Config",
            (Self::Controller, Lang::Zh) => "软路由 / 内核",
            (Self::Controller, Lang::En) => "Router / Core",
            (Self::Settings, Lang::Zh) => "设置",
            (Self::Settings, Lang::En) => "Settings",
        }
    }

    pub fn label(self) -> &'static str {
        self.label_for(Lang::Zh)
    }

    pub fn matches(self, cat: CheckCategory) -> bool {
        match self {
            Self::All => true,
            Self::NetworkLeak => cat == CheckCategory::NetworkLeak,
            Self::AiServices => cat == CheckCategory::AiServices,
            Self::LocalEnv => cat == CheckCategory::LocalEnv,
            Self::Controller => cat == CheckCategory::Controller,
            Self::Settings => false,
        }
    }
}

#[derive(Clone)]
enum JobKind {
    Full(CheckOptions),
    TargetIp(String, CheckOptions),
}

struct JobCommand {
    nonce: u64,
    kind: JobKind,
}

enum JobEvent {
    Progress { nonce: u64, report: DoctorReport },
    Finished { nonce: u64, report: DoctorReport },
}

/// Reactive application state owned per NSH surface via `global::<AppState>()`.
#[derive(Clone)]
pub struct AppState {
    pub options: CheckOptions,
    pub report: Option<DoctorReport>,
    pub running: bool,
    pub mask_ips: bool,
    pub status_line: SharedString,
    pub active_tab: ActiveTab,
    pub selected_key: Option<String>,
    pub run_nonce: u64,
    cmd_tx: Option<mpsc::UnboundedSender<JobCommand>>,
}

impl Default for AppState {
    fn default() -> Self {
        let options = INITIAL_OPTIONS
            .get()
            .cloned()
            .unwrap_or_else(CheckOptions::from_env_defaults);
        let lang = options.lang;
        let report = INITIAL_REPORT.get().cloned();
        let selected_key = report
            .as_ref()
            .and_then(|r| r.items.first().map(|i| i.key.clone()));
        let status_line = if report.is_some() {
            SharedString::from(pick(lang, "体检已完成", "Diagnostics complete"))
        } else {
            SharedString::from(pick(
                lang,
                "准备就绪 · 点击「完整体检」或按 F5 手动开始",
                "Ready · Click Full Scan or press F5 to start",
            ))
        };
        Self {
            options,
            report,
            running: false,
            mask_ips: false,
            status_line,
            active_tab: ActiveTab::All,
            selected_key,
            run_nonce: 0,
            cmd_tx: None,
        }
    }
}

fn state_signal() -> Signal<AppState> {
    global::<AppState>()
}

/// Mount the permanent root-owned async job runner once inside `Dashboard()`.
/// Because `Dashboard()` never unmounts, triggering a scan from transient child views
/// (such as the welcome pane or settings panel) will NEVER cancel the background task.
pub fn mount_job_runner() {
    let already_mounted = state_signal().with_untracked(|s| s.cmd_tx.is_some());
    if already_mounted {
        return;
    }

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<JobCommand>();
    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<JobEvent>();

    state_signal().update(|s| {
        s.cmd_tx = Some(cmd_tx);
    });

    // Root-owned UI task: spawns the tokio dispatcher and receives streaming updates directly.
    spawn(async move {
        let _dispatcher = background(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let evt_tx_inner = evt_tx.clone();
                tokio::spawn(async move {
                    let (prog_tx, mut prog_rx) = mpsc::unbounded_channel::<DoctorReport>();
                    let nonce = cmd.nonce;

                    // Forward progressive Wave 1 / Wave 2 snapshots immediately to UI
                    let fwd_tx = evt_tx_inner.clone();
                    let fwd = tokio::spawn(async move {
                        while let Some(partial) = prog_rx.recv().await {
                            if fwd_tx
                                .send(JobEvent::Progress {
                                    nonce,
                                    report: partial,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    let final_report = match cmd.kind {
                        JobKind::Full(opts) => {
                            run_all_checks_streaming(&opts, Some(prog_tx)).await
                        }
                        JobKind::TargetIp(ip, opts) => {
                            run_target_ip_checks_streaming(&ip, &opts, Some(prog_tx)).await
                        }
                    };
                    let _ = fwd.await;

                    let _ = evt_tx_inner.send(JobEvent::Finished {
                        nonce,
                        report: final_report,
                    });
                });
            }
        });

        while let Some(evt) = evt_rx.recv().await {
            match evt {
                JobEvent::Progress { nonce, report } => {
                    state_signal().update(|s| {
                        if s.run_nonce != nonce || !s.running {
                            return;
                        }
                        apply_report_update(s, report, false);
                    });
                }
                JobEvent::Finished { nonce, report } => {
                    state_signal().update(|s| {
                        if s.run_nonce != nonce {
                            return;
                        }
                        apply_report_update(s, report, true);
                    });
                }
            }
        }
    });
}

pub fn lang() -> Lang {
    state_signal().with(|s| s.options.lang)
}

pub fn toggle_lang() {
    state_signal().update(|s| {
        let next = s.options.lang.toggled();
        s.options.lang = next;
        if let Some(ref r) = s.report {
            s.status_line = SharedString::from(match next {
                Lang::Zh => format!(
                    "体检完成 ({:.1}s) · 总体: {}",
                    r.total_duration_ms as f64 / 1000.0,
                    r.overall.label(next)
                ),
                Lang::En => format!(
                    "Completed ({:.1}s) · Overall: {}",
                    r.total_duration_ms as f64 / 1000.0,
                    r.overall.label(next)
                ),
            });
        } else if !s.running {
            s.status_line = SharedString::from(pick(
                next,
                "准备就绪 · 点击「完整体检」或按 F5 手动开始",
                "Ready · Click Full Scan or press F5 to start",
            ));
        }
    });
}

pub fn is_ip_masked() -> bool {
    state_signal().with(|s| s.mask_ips)
}

pub fn toggle_mask_ips() {
    state_signal().update(|s| {
        s.mask_ips = !s.mask_ips;
    });
}

pub fn active_tab() -> ActiveTab {
    state_signal().with(|s| s.active_tab)
}

pub fn set_active_tab(tab: ActiveTab) {
    state_signal().update(|s| {
        s.active_tab = tab;
        if tab != ActiveTab::Settings {
            if let Some(ref report) = s.report {
                let first_matching = report
                    .items
                    .iter()
                    .find(|i| tab.matches(i.category))
                    .map(|i| i.key.clone());
                let current_still_visible = s.selected_key.as_ref().is_some_and(|k| {
                    report
                        .items
                        .iter()
                        .any(|i| &i.key == k && tab.matches(i.category))
                });
                if !current_still_visible {
                    s.selected_key = first_matching;
                }
            }
        }
    });
}

pub fn is_running() -> bool {
    state_signal().with(|s| s.running)
}

pub fn status_line() -> SharedString {
    state_signal().with(|s| s.status_line.clone())
}

pub fn current_report() -> Option<DoctorReport> {
    state_signal().with(|s| s.report.clone())
}

pub fn current_options() -> CheckOptions {
    state_signal().with(|s| s.options.clone())
}

pub fn update_options(new_opts: CheckOptions) {
    state_signal().update(|s| {
        s.options = new_opts;
    });
}

pub fn selected_key() -> Option<String> {
    state_signal().with(|s| s.selected_key.clone())
}

pub fn select_item(key: String) {
    state_signal().update(|s| {
        s.selected_key = Some(key);
    });
}

pub fn filtered_items() -> Vec<CheckItem> {
    state_signal().with(|s| {
        let Some(ref report) = s.report else {
            return Vec::new();
        };
        report
            .items
            .iter()
            .filter(|i| s.active_tab.matches(i.category))
            .cloned()
            .collect()
    })
}

pub fn selected_item() -> Option<CheckItem> {
    state_signal().with(|s| {
        let report = s.report.as_ref()?;
        if let Some(ref key) = s.selected_key {
            if let Some(found) = report.items.iter().find(|i| &i.key == key) {
                return Some(found.clone());
            }
        }
        report
            .items
            .iter()
            .find(|i| s.active_tab.matches(i.category))
            .cloned()
            .or_else(|| report.items.first().cloned())
    })
}

/// Dispatch an asynchronous diagnostic run to the permanent root-owned runner.
pub fn trigger_check(quick: bool, with_api_test: bool) {
    let mut opts = state_signal().with_untracked(|s| s.options.clone());
    opts.target_ip = None;
    if quick {
        opts.long_conn_secs = 8;
    }
    opts.run_api_test = with_api_test;

    let lang = opts.lang;
    let secs = opts.long_conn_secs;
    let label = if with_api_test {
        pick(
            lang,
            "正在并发体检（含 API 连通性测试 · 结果实时刷新）...",
            "Running concurrent diagnostics (+ API test · live streaming)...",
        )
        .to_owned()
    } else if quick {
        match lang {
            Lang::Zh => format!("正在并发快速体检（长连接 {secs}s · 其余项 2~3s 内实时出结果）..."),
            Lang::En => format!("Running quick scan ({secs}s keep-alive · live streaming)..."),
        }
    } else {
        match lang {
            Lang::Zh => format!("正在并发完整体检（长连接 {secs}s · 其余项 2~3s 内实时出结果）..."),
            Lang::En => format!("Running full scan ({secs}s keep-alive · live streaming)..."),
        }
    };

    dispatch_job(label, JobKind::Full(opts));
}

/// Dispatch an arbitrary public IPv4/IPv6 inspection to the permanent root-owned runner.
pub fn trigger_target_ip_check(target_ip: String) {
    let clean = target_ip.trim().to_owned();
    if clean.is_empty() {
        return;
    }
    let opts = state_signal().with_untracked(|s| s.options.clone());
    let lang = opts.lang;
    let label = match lang {
        Lang::Zh => format!("正在并发体检目标 IP ({clean}) ..."),
        Lang::En => format!("Inspecting target IP ({clean}) ..."),
    };
    dispatch_job(label, JobKind::TargetIp(clean, opts));
}

fn dispatch_job(label: String, kind: JobKind) {
    let mut tx_opt = None;
    let mut nonce = 0u64;
    state_signal().update(|s| {
        s.run_nonce += 1;
        nonce = s.run_nonce;
        s.running = true;
        s.status_line = SharedString::from(label);
        if s.active_tab == ActiveTab::Settings {
            s.active_tab = ActiveTab::All;
        }
        tx_opt = s.cmd_tx.clone();
    });

    if let Some(tx) = tx_opt {
        let _ = tx.send(JobCommand { nonce, kind });
    } else {
        state_signal().update(|s| {
            if s.run_nonce == nonce {
                s.running = false;
                s.status_line = SharedString::from(pick(
                    s.options.lang,
                    "任务调度器尚未就绪，请重试",
                    "Job runner not mounted yet; please retry",
                ));
            }
        });
    }
}

fn apply_report_update(s: &mut AppState, report: DoctorReport, is_final: bool) {
    let first_key = report
        .items
        .iter()
        .find(|i| s.active_tab.matches(i.category))
        .or_else(|| report.items.first())
        .map(|i| i.key.clone());
    let keep_existing = s
        .selected_key
        .as_ref()
        .is_some_and(|k| report.items.iter().any(|i| &i.key == k));
    if !keep_existing {
        s.selected_key = first_key;
    }
    let cur_lang = s.options.lang;
    if is_final {
        s.status_line = SharedString::from(match cur_lang {
            Lang::Zh => format!(
                "体检完成 ({:.1}s) · 总体: {}",
                report.total_duration_ms as f64 / 1000.0,
                report.overall.label(cur_lang)
            ),
            Lang::En => format!(
                "Completed ({:.1}s) · Overall: {}",
                report.total_duration_ms as f64 / 1000.0,
                report.overall.label(cur_lang)
            ),
        });
        s.running = false;
    } else {
        s.status_line = SharedString::from(match cur_lang {
            Lang::Zh => format!(
                "已出 {} 项结果 ({:.1}s) · 后台正在完成长连接/路由校验...",
                report.items.len(),
                report.total_duration_ms as f64 / 1000.0
            ),
            Lang::En => format!(
                "{} checks ready ({:.1}s) · Finishing keep-alive / routing in background...",
                report.items.len(),
                report.total_duration_ms as f64 / 1000.0
            ),
        });
    }
    s.report = Some(report);
}
