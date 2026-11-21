use nsh_base::{button, input, theme as nsh_theme};
use nsh_core::prelude::*;

use crate::assets::APP_ICON;
use crate::i18n::{self, Lang, pick};
use crate::model::{CheckItem, CheckState};
use crate::store::{self, ActiveTab};
use crate::ui::motion::{appear, lang_pill_switch, scanning_dot};
use crate::ui::theme::{self, AppleElevation, motion as motion_tokens};
use crate::ui::{self, ButtonVariant};

const NAV_TABS: [ActiveTab; 5] = [
    ActiveTab::All,
    ActiveTab::NetworkLeak,
    ActiveTab::AiServices,
    ActiveTab::LocalEnv,
    ActiveTab::Controller,
];

fn display_text_privacy(raw: &str) -> String {
    if store::is_ip_masked() {
        i18n::mask_ips_in_text(raw)
    } else {
        raw.to_owned()
    }
}

/// Primary Apple-inspired Windows & macOS desktop dashboard built with Native Shell.
/// Does NOT auto-run scans on startup; users trigger local full/quick scans or inspect any target IP manually.
#[component]
pub fn Dashboard() -> impl IntoElement {
    // Mount permanent root-owned async job runner so unmounting Welcome/Settings panes never cancels active scans.
    store::mount_job_runner();

    // Desktop shortcuts (Cmd on macOS, Ctrl on Windows via `mod+`)
    on_key("f5", |_| {
        if !store::is_running() {
            store::trigger_check(false, false);
        }
    });
    on_key("mod+r", |_| {
        if !store::is_running() {
            store::trigger_check(true, false);
        }
    });
    on_key("mod+t", |_| {
        if !store::is_running() {
            store::trigger_check(true, true);
        }
    });
    for (idx, tab_kind) in [
        ActiveTab::All,
        ActiveTab::NetworkLeak,
        ActiveTab::AiServices,
        ActiveTab::LocalEnv,
        ActiveTab::Controller,
        ActiveTab::Settings,
    ]
    .iter()
    .enumerate()
    {
        let keystroke = match idx {
            0 => "mod+1",
            1 => "mod+2",
            2 => "mod+3",
            3 => "mod+4",
            4 => "mod+5",
            _ => "mod+6",
        };
        let target = *tab_kind;
        on_key(keystroke, move |_| store::set_active_tab(target));
    }

    view()
        .flex_1()
        .flex_row()
        .bg(move || nsh_theme().background)
        .text_color(move || nsh_theme().foreground)
        .child(sidebar_pane())
        .child(main_canvas())
}

/// Apple macOS-inspired left navigation sidebar with embedded squircle app icon, status dots & animated pill language switch.
fn sidebar_pane() -> impl IntoElement {
    view()
        .w(px(244.0))
        .flex_col()
        .justify_between()
        .p_3()
        .gap_3()
        .bg(move || nsh_theme().sidebar)
        .border_r_1()
        .border_color(move || nsh_theme().sidebar_border)
        .child(
            view()
                .flex_col()
                .gap_3()
                // Brand header with monochrome Apple squircle app icon
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_3()
                        .px_2()
                        .py_2()
                        .child(
                            image(APP_ICON)
                                .size(px(38.0))
                                .rounded(px(9.0))
                                .object_fit(ResizeMode::Cover)
                                .label("AI-Network-Protection Icon"),
                        )
                        .child(
                            view()
                                .flex_col()
                                .gap(px(2.0))
                                .child(
                                    text("AI-Network-Protection")
                                        .text_xs()
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(move || nsh_theme().sidebar_foreground),
                                )
                                .child(
                                    view()
                                        .flex_row()
                                        .items_center()
                                        .gap(px(6.0))
                                        .child(scanning_dot())
                                        .child(
                                            text(move || {
                                                let lang = store::lang();
                                                if store::is_running() {
                                                    SharedString::from(pick(
                                                        lang,
                                                        "正在体检...",
                                                        "Scanning...",
                                                    ))
                                                } else if let Some(r) = store::current_report() {
                                                    SharedString::from(match lang {
                                                        Lang::Zh => format!(
                                                            "总体: {}",
                                                            r.overall.label(lang)
                                                        ),
                                                        Lang::En => format!(
                                                            "Overall: {}",
                                                            r.overall.label(lang)
                                                        ),
                                                    })
                                                } else {
                                                    SharedString::from(pick(
                                                        lang,
                                                        "待命（手动触发）",
                                                        "Idle (Manual)",
                                                    ))
                                                }
                                            })
                                            .text_xs()
                                            .text_color(move || nsh_theme().muted_foreground),
                                        ),
                                ),
                        ),
                )
                .child(view().h(px(1.0)).bg(move || nsh_theme().sidebar_border))
                .child(
                    text(move || {
                        SharedString::from(pick(store::lang(), "体检分类", "CATEGORIES"))
                    })
                    .px_3()
                    .text_xs()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(move || nsh_theme().muted_foreground),
                )
                .child(
                    view().flex_col().gap(px(3.0)).children(
                        NAV_TABS.iter().map(|&tab_kind| {
                            let count_text = move || {
                                store::current_report()
                                    .map(|r| {
                                        let c = r
                                            .items
                                            .iter()
                                            .filter(|i| tab_kind.matches(i.category))
                                            .count();
                                        SharedString::from(c.to_string())
                                    })
                                    .unwrap_or_else(|| SharedString::from("-"))
                            };
                            let dot_state = move || {
                                let r = store::current_report()?;
                                let worst = r
                                    .items
                                    .iter()
                                    .filter(|i| tab_kind.matches(i.category))
                                    .filter(|i| {
                                        !(i.key == "controller-info"
                                            && i.state == CheckState::Unknown)
                                    })
                                    .map(|i| i.state)
                                    .max_by_key(|s| s.severity());
                                worst.or_else(|| {
                                    r.items
                                        .iter()
                                        .find(|i| tab_kind.matches(i.category))
                                        .map(|i| i.state)
                                })
                            };
                            ui::sidebar_item(
                                move || SharedString::from(tab_kind.label_for(store::lang())),
                                move || store::active_tab() == tab_kind,
                                count_text,
                                dot_state,
                                move || store::set_active_tab(tab_kind),
                            )
                        }),
                    ),
                ),
        )
        .child(
            view()
                .flex_col()
                .gap_2()
                .child(view().h(px(1.0)).bg(move || nsh_theme().sidebar_border))
                .child(ui::sidebar_item(
                    move || SharedString::from(ActiveTab::Settings.label_for(store::lang())),
                    move || store::active_tab() == ActiveTab::Settings,
                    || SharedString::from(""),
                    || None,
                    || store::set_active_tab(ActiveTab::Settings),
                ))
                // Smooth animated Day/Night-style 中 / EN pill switch
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px_2()
                        .pt_1()
                        .child(
                            text(move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "100% 只读诊断",
                                    "100% Read-Only",
                                ))
                            })
                            .text_xs()
                            .text_color(move || nsh_theme().muted_foreground),
                        )
                        .child(lang_pill_switch()),
                ),
        )
}

fn main_canvas() -> impl IntoElement {
    let target_ip_draft = signal(String::new());

    view()
        .flex_1()
        .min_w(px(0.0))
        .min_h(px(0.0))
        .flex_col()
        .p_5()
        .gap_4()
        .child(toolbar_header(target_ip_draft))
        .child(when(store::is_running, scanning_banner))
        .child(
            when(
                move || store::active_tab() == ActiveTab::Settings,
                settings_panel,
            )
            .otherwise(move || {
                when(
                    move || store::current_report().is_none() && !store::is_running(),
                    move || ready_welcome_pane(target_ip_draft),
                )
                .otherwise(|| {
                    view()
                        .flex_1()
                        .min_h(px(0.0))
                        .flex_col()
                        .gap_4()
                        .child(overview_strip())
                        .child(results_split_view())
                })
            }),
        )
}

fn toolbar_header(target_ip_draft: Signal<String>) -> impl IntoElement {
    let copied = signal(false);

    let section_title = move || {
        let lang = store::lang();
        SharedString::from(match (store::active_tab(), lang) {
            (ActiveTab::All, Lang::Zh) => "网络与 AI 环境全景体检",
            (ActiveTab::All, Lang::En) => "AI Network & Environment Overview",
            (ActiveTab::NetworkLeak, Lang::Zh) => "网络出口、纯净度与四类泄漏检测",
            (ActiveTab::NetworkLeak, Lang::En) => "Exit IP, Purity & Leak Detection",
            (ActiveTab::AiServices, Lang::Zh) => "主流 AI 服务连通与一致性",
            (ActiveTab::AiServices, Lang::En) => "AI Service Connectivity & Routing",
            (ActiveTab::LocalEnv, Lang::Zh) => "本地指纹、配置与防风控审计",
            (ActiveTab::LocalEnv, Lang::En) => "OS Fingerprint, Config & Relay Audit",
            (ActiveTab::Controller, Lang::Zh) => "软路由 / Mihomo 内核检查",
            (ActiveTab::Controller, Lang::En) => "Router / Mihomo Core Inspection",
            (ActiveTab::Settings, Lang::Zh) => "偏好设置与可选参数",
            (ActiveTab::Settings, Lang::En) => "Preferences & Optional Parameters",
        })
    };

    view()
        .flex_col()
        .gap_2()
        .child(
            view()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    view()
                        .flex_col()
                        .gap(px(2.0))
                        .child(
                            text(section_title)
                                .text_lg()
                                .font_weight(FontWeight::BOLD)
                                .text_color(move || nsh_theme().foreground),
                        )
                        .child(
                            text(move || {
                                SharedString::from(display_text_privacy(
                                    store::status_line().as_str(),
                                ))
                            })
                            .text_xs()
                            .text_color(move || nsh_theme().muted_foreground),
                        ),
                )
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(ui::app_button(
                            move || SharedString::from(pick(store::lang(), "完整体检", "Full Scan")),
                            ButtonVariant::Primary,
                            move || store::is_running(),
                            || store::trigger_check(false, false),
                        ))
                        .child(ui::app_button(
                            move || SharedString::from(pick(store::lang(), "快速体检", "Quick Scan")),
                            ButtonVariant::Secondary,
                            move || store::is_running(),
                            || store::trigger_check(true, false),
                        ))
                        .child(ui::app_button(
                            move || SharedString::from(pick(store::lang(), "含API测试", "+ API Test")),
                            ButtonVariant::Secondary,
                            move || store::is_running(),
                            || store::trigger_check(true, true),
                        ))
                        .child(hide_ip_button())
                        .child(ui::app_button(
                            move || {
                                let lang = store::lang();
                                if copied.get() {
                                    SharedString::from(pick(lang, "✓ 已复制", "✓ Copied"))
                                } else {
                                    SharedString::from(pick(lang, "复制 JSON", "Copy JSON"))
                                }
                            },
                            ButtonVariant::Ghost,
                            move || store::current_report().is_none(),
                            move || {
                                if let Some(report) = store::current_report() {
                                    let exported = if store::is_ip_masked() {
                                        report.masked_for_privacy()
                                    } else {
                                        report
                                    };
                                    if let Ok(json) = serde_json::to_string_pretty(&exported) {
                                        set_clipboard(json);
                                        copied.set(true);
                                        set_timeout(std::time::Duration::from_secs(2), move || {
                                            copied.set(false);
                                        });
                                    }
                                }
                            },
                        )),
                ),
        )
        // Compact quick target-IP lookup strip (always accessible in 1 click)
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    input()
                        .test_id("target-ip-input")
                        .value(move || target_ip_draft.get())
                        .on_change(move |v: &str| target_ip_draft.set(v.to_owned()))
                        .placeholder(move || {
                            pick(
                                store::lang(),
                                "输入任意公网 IPv4 / IPv6 单独体检纯净度、黑名单与原生/RPKI（留空则测本机出口）...",
                                "Enter any public IPv4 / IPv6 to inspect purity, DNSBL & Native/RPKI...",
                            )
                            .to_owned()
                        })
                        .placeholder_color(|| color(nsh_theme().muted_foreground))
                        .caret_color(|| color(nsh_theme().primary))
                        .flex_1()
                        .h(px(30.0))
                        .px_3()
                        .text_xs()
                        .rounded(px(8.0))
                        .border_1()
                        .border_color(move || nsh_theme().input)
                        .bg(move || nsh_theme().card)
                        .text_color(move || nsh_theme().foreground)
                        .focus(|s| s.border_color(move || nsh_theme().ring)),
                )
                .child(
                    button()
                        .test_id("inspect-ip-btn")
                        .disabled(move || {
                            store::is_running() || target_ip_draft.get().trim().is_empty()
                        })
                        .on_press(move || {
                            let ip = target_ip_draft.get_untracked();
                            if !ip.trim().is_empty() {
                                store::trigger_target_ip_check(ip);
                            }
                        })
                        .h(px(30.0))
                        .px_3()
                        .items_center()
                        .justify_center()
                        .rounded(px(8.0))
                        .border_1()
                        .border_color(move || nsh_theme().border)
                        .bg(move || nsh_theme().card)
                        .hover(|s| s.opacity(0.88))
                        .disabled_style(|s| s.opacity(0.45))
                        .child(
                            text(move || {
                                SharedString::from(pick(store::lang(), "查此 IP", "Inspect IP"))
                            })
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(move || nsh_theme().foreground),
                        ),
                ),
        )
}

fn hide_ip_button() -> impl IntoElement {
    let scale = animated_value(1.0);
    button()
        .test_id("hide-ip-toggle")
        .bind_scale(&scale)
        .on_press_down(move || {
            scale.spring(0.97, motion_tokens::PRESS);
        })
        .on_press_up(move || {
            scale.spring(1.0, motion_tokens::PRESS);
        })
        .on_press(store::toggle_mask_ips)
        .h(px(30.0))
        .px_3()
        .items_center()
        .justify_center()
        .rounded(px(8.0))
        .border_1()
        .border_color(move || {
            if store::is_ip_masked() {
                nsh_theme().primary
            } else {
                nsh_theme().border
            }
        })
        .bg(move || {
            if store::is_ip_masked() {
                nsh_theme().accent
            } else {
                nsh_theme().background
            }
        })
        .hover(|s| s.opacity(0.88))
        .child(
            text(move || {
                let lang = store::lang();
                if store::is_ip_masked() {
                    SharedString::from(pick(lang, "● 已隐藏 IP", "● IP Hidden"))
                } else {
                    SharedString::from(pick(lang, "隐藏 IP", "Hide IP"))
                }
            })
            .text_xs()
            .font_weight(FontWeight::MEDIUM)
            .text_color(move || {
                if store::is_ip_masked() {
                    nsh_theme().accent_foreground
                } else {
                    nsh_theme().muted_foreground
                }
            }),
        )
}

/// Clean Apple-style ready state shown on startup until the user manually triggers a scan.
fn ready_welcome_pane(target_ip_draft: Signal<String>) -> impl IntoElement {
    appear().index(0).lift(8.0).flex(true).child(
        ui::card()
            .flex_1()
            .items_center()
            .justify_center()
            .gap_4()
            .child(
                image(APP_ICON)
                    .size(px(64.0))
                    .rounded(px(15.0))
                    .object_fit(ResizeMode::Cover)
                    .label("AI-Network-Protection Welcome Icon"),
            )
            .child(
                view()
                    .flex_col()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        text(move || {
                            SharedString::from(pick(
                                store::lang(),
                                "准备就绪，等待手动启动体检",
                                "Ready to Inspect Your AI Network & Environment",
                            ))
                        })
                        .text_lg()
                        .font_weight(FontWeight::BOLD)
                        .text_color(move || nsh_theme().foreground),
                    )
                    .child(
                        text(move || {
                            SharedString::from(pick(
                                store::lang(),
                                "100% 只读诊断：零 Key 多源 IP 纯净度 · DoH DNSBL · 原生/RPKI · DNS/EDNS/IPv6/WebRTC/长连接 · 本机指纹与 Claude 配置审计",
                                "100% Read-Only: Zero-Key IP Purity · DoH DNSBL · Native/RPKI · DNS/EDNS/IPv6/WebRTC/Keep-Alive · OS Fingerprint & Claude Audit",
                            ))
                        })
                        .text_xs()
                        .text_color(move || nsh_theme().muted_foreground),
                    ),
            )
            .child(
                view()
                    .flex_row()
                    .items_center()
                    .gap_3()
                    .pt_2()
                    .child(ui::app_button(
                        move || {
                            SharedString::from(pick(
                                store::lang(),
                                "开始完整体检 (F5)",
                                "Start Full Scan (F5)",
                            ))
                        },
                        ButtonVariant::Primary,
                        move || store::is_running(),
                        || store::trigger_check(false, false),
                    ))
                    .child(ui::app_button(
                        move || {
                            SharedString::from(pick(
                                store::lang(),
                                "快速体检 8s (Ctrl+R)",
                                "Quick Scan 8s (Ctrl+R)",
                            ))
                        },
                        ButtonVariant::Secondary,
                        move || store::is_running(),
                        || store::trigger_check(true, false),
                    ))
                    .child(ui::app_button(
                        move || {
                            SharedString::from(pick(
                                store::lang(),
                                "单独检测上方输入的 IP",
                                "Inspect Target IP Above",
                            ))
                        },
                        ButtonVariant::Ghost,
                        move || store::is_running() || target_ip_draft.get().trim().is_empty(),
                        move || {
                            let ip = target_ip_draft.get_untracked();
                            if !ip.trim().is_empty() {
                                store::trigger_target_ip_check(ip);
                            }
                        },
                    )),
            ),
    )
}

fn scanning_banner() -> impl IntoElement {
    appear().index(0).lift(6.0).child(
        view()
            .flex_row()
            .items_center()
            .gap_3()
            .px_4()
            .py(px(10.0))
            .rounded(px(10.0))
            .bg(move || nsh_theme().accent)
            .border_1()
            .border_color(move || nsh_theme().primary)
            .child(scanning_dot())
            .child(
                text(move || SharedString::from(display_text_privacy(store::status_line().as_str())))
                    .text_xs()
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(move || nsh_theme().accent_foreground),
            ),
    )
}

fn overview_strip() -> impl IntoElement {
    let overall_state = move || {
        store::current_report()
            .map(|r| r.overall)
            .unwrap_or(CheckState::Unknown)
    };

    let overall_sub = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(lang, "等待体检结果...", "Waiting for scan..."));
        };
        SharedString::from(match lang {
            Lang::Zh => format!(
                "通过 {} · 警告 {} · 失败 {} ({:.1}s)",
                r.count_by_state(CheckState::Ok),
                r.count_by_state(CheckState::Warn),
                r.count_by_state(CheckState::Fail),
                r.total_duration_ms as f64 / 1000.0,
            ),
            Lang::En => format!(
                "Pass {} · Warn {} · Fail {} ({:.1}s)",
                r.count_by_state(CheckState::Ok),
                r.count_by_state(CheckState::Warn),
                r.count_by_state(CheckState::Fail),
                r.total_duration_ms as f64 / 1000.0,
            ),
        })
    };

    let exit_ip = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(lang, "检测中...", "Scanning..."));
        };
        if let Some(geo) = r.exit_geo {
            let cc = geo.country_code.unwrap_or_else(|| "-".to_owned());
            let shown_ip = display_text_privacy(&geo.ip);
            SharedString::from(format!("{shown_ip} [{cc}]"))
        } else {
            SharedString::from(pick(lang, "未获取到出口 IP", "No exit IP"))
        }
    };

    let exit_isp = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(lang, "归属地与网络路径", "Geo & network path"));
        };
        if let Some(geo) = r.exit_geo {
            let city = geo.city.unwrap_or_default();
            let isp = geo
                .isp
                .or(geo.org)
                .unwrap_or_else(|| pick(lang, "未知 ISP", "Unknown ISP").to_owned());
            if city.is_empty() {
                SharedString::from(isp)
            } else {
                SharedString::from(format!("{city} · {isp}"))
            }
        } else {
            SharedString::from(display_text_privacy(&r.network_path.mode_label))
        }
    };

    let purity_main = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(lang, "检测中...", "Scanning..."));
        };
        let Some(p) = r.ip_purity else {
            return SharedString::from("-");
        };
        match (p.purity, p.band) {
            (Some(score), Some(band)) => SharedString::from(format!(
                "{score}/100 · {}",
                i18n::purity_band_label(band, lang)
            )),
            _ => SharedString::from(i18n::network_type_label(p.network_type, lang)),
        }
    };

    let purity_sub = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(lang, "多源免 Key 评分", "Multi-source score"));
        };
        let Some(p) = r.ip_purity else {
            return SharedString::from("-");
        };
        if p.purity.is_some() {
            SharedString::from(format!(
                "{} · {} {}",
                i18n::network_type_label(p.network_type, lang),
                p.deductions.len(),
                pick(lang, "项扣分", "deductions")
            ))
        } else {
            SharedString::from(pick(
                lang,
                "情报源暂不可达",
                "Intel unreachable",
            ))
        }
    };

    let fp_main = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(lang, "检测中...", "Scanning..."));
        };
        let Some(fp) = r.env_fingerprint else {
            return SharedString::from(pick(lang, "仅本机体检适用", "Local scan only"));
        };
        SharedString::from(format!(
            "{}/100 · {}",
            fp.score,
            i18n::risk_band_label(fp.band, lang)
        ))
    };

    let fp_sub = move || {
        let lang = store::lang();
        let Some(r) = store::current_report() else {
            return SharedString::from(pick(
                lang,
                "时区 / 语言 / 字体 / OEM",
                "TZ / Locale / Fonts / OEM",
            ));
        };
        let Some(fp) = r.env_fingerprint else {
            return SharedString::from(pick(lang, "当前为指定 IP 模式", "Target IP mode"));
        };
        let hits = fp.signals.iter().filter(|s| s.hit).count();
        SharedString::from(match lang {
            Lang::Zh => format!("命中 {hits}/{} 项系统特征信号", fp.signals.len()),
            Lang::En => format!("{hits}/{} OS signals matched", fp.signals.len()),
        })
    };

    view()
        .flex_row()
        .gap_3()
        .child(
            appear().index(0).lift(8.0).flex(true).child(
                view()
                    .flex_1()
                    .min_w(px(0.0))
                    .p_3()
                    .gap(px(5.0))
                    .rounded(px(12.0))
                    .border_1()
                    .border_color(move || nsh_theme().border)
                    .bg(move || nsh_theme().card)
                    .apple_card_shadow()
                    .child(
                        text(move || {
                            SharedString::from(pick(store::lang(), "总体健康状态", "Overall Health"))
                        })
                        .text_xs()
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(move || nsh_theme().muted_foreground),
                    )
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .child(ui::status_badge_reactive(overall_state)),
                    )
                    .child(
                        text(overall_sub)
                            .text_xs()
                            .tabular_nums()
                            .number_of_lines(1)
                            .text_color(move || nsh_theme().muted_foreground),
                    ),
            ),
        )
        .child(
            appear().index(1).lift(8.0).flex(true).child(ui::metric_card(
                move || SharedString::from(pick(store::lang(), "出口 / 目标 IP", "Exit / Target IP")),
                exit_ip,
                exit_isp,
            )),
        )
        .child(
            appear().index(2).lift(8.0).flex(true).child(ui::metric_card(
                move || SharedString::from(pick(store::lang(), "IP 纯净度评分", "IP Purity Score")),
                purity_main,
                purity_sub,
            )),
        )
        .child(
            appear().index(3).lift(8.0).flex(true).child(ui::metric_card(
                move || {
                    SharedString::from(pick(
                        store::lang(),
                        "本机指纹风险分",
                        "OS Fingerprint Risk",
                    ))
                },
                fp_main,
                fp_sub,
            )),
        )
}

fn results_split_view() -> impl IntoElement {
    let items_memo = computed(store::filtered_items);

    view()
        .flex_1()
        .min_h(px(0.0))
        .flex_row()
        .gap_4()
        .child(
            // Left pane: check cards list
            ui::card()
                .flex_1()
                .min_w(px(0.0))
                .min_h(px(0.0))
                .child(
                    view()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .child(
                            text(move || {
                                SharedString::from(pick(store::lang(), "检测项目", "Checks"))
                            })
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(move || nsh_theme().muted_foreground),
                        )
                        .child(
                            text(move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "点击查看详细依据",
                                    "Select to inspect",
                                ))
                            })
                            .text_xs()
                            .text_color(move || nsh_theme().muted_foreground),
                        ),
                )
                .child(
                    scroll().flex_1().min_h(px(0.0)).child(
                        view().gap_2().child(
                            when(
                                move || items_memo.with(Vec::is_empty),
                                || {
                                    view().p_5().items_center().justify_center().child(
                                        text(move || {
                                            let lang = store::lang();
                                            if store::is_running() {
                                                SharedString::from(pick(
                                                    lang,
                                                    "正在并发检测出口、纯净度、DNSBL、四类泄漏、AI 服务与本机指纹...",
                                                    "Running concurrent checks for exit IP, purity, DNSBL, leaks, AI services & OS fingerprint...",
                                                ))
                                            } else {
                                                SharedString::from(pick(
                                                    lang,
                                                    "当前分类暂无结果，点击「完整体检」或按 F5 开始检测。",
                                                    "No results in this category. Click Full Scan or press F5.",
                                                ))
                                            }
                                        })
                                        .text_sm()
                                        .text_color(move || nsh_theme().muted_foreground),
                                    )
                                },
                            )
                            .otherwise(move || {
                                view().gap_2().child(each(
                                    items_memo,
                                    |item: &CheckItem| item.key.clone(),
                                    |item, idx| check_item_row(item, idx),
                                ))
                            }),
                        ),
                    ),
                ),
        )
        .child(detail_inspector_panel())
}

fn check_item_row(item: ReadSignal<CheckItem>, index: ReadSignal<usize>) -> impl IntoElement {
    let key = item.with_untracked(|i| i.key.clone());
    let key_for_sel = key.clone();
    let key_for_press = key.clone();
    let initial_idx = index.get_untracked() as u32;

    let is_selected =
        computed(move || store::selected_key().as_deref() == Some(key_for_sel.as_str()));
    let scale = animated_value(1.0);
    let test_id_str = format!("check-{key}");

    appear().index(initial_idx).lift(8.0).child(
        button()
            .test_id(&test_id_str)
            .selected(is_selected)
            .bind_scale(&scale)
            .on_press_down(move || {
                scale.spring(0.985, motion_tokens::PRESS);
            })
            .on_press_up(move || {
                scale.spring(1.0, motion_tokens::PRESS);
            })
            .on_press(move || store::select_item(key_for_press.clone()))
            .px_3()
            .py(px(10.0))
            .rounded(px(10.0))
            .border_1()
            .border_color(move || {
                if is_selected.get() {
                    nsh_theme().primary
                } else {
                    nsh_theme().border
                }
            })
            .bg(move || {
                if is_selected.get() {
                    nsh_theme().accent
                } else {
                    nsh_theme().background
                }
            })
            .hover(|s| s.opacity(0.92))
            .focus_visible(|s| s.outline(px(2.0)).outline_color(move || nsh_theme().ring))
            .child(
                view()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        view()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        view()
                                            .w(px(8.0))
                                            .h(px(8.0))
                                            .rounded_full()
                                            .bg(move || {
                                                theme::status_color(item.with(|i| i.state))
                                            }),
                                    )
                                    .child(
                                        text(move || {
                                            let lang = store::lang();
                                            item.with(|i| {
                                                SharedString::from(
                                                    i18n::check_title(&i.key, lang)
                                                        .unwrap_or(&i.title)
                                                        .to_owned(),
                                                )
                                            })
                                        })
                                        .text_sm()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(move || nsh_theme().foreground),
                                    ),
                            )
                            .child(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        text(move || {
                                            let ms = item.with(|i| i.duration_ms);
                                            if ms == 0 {
                                                SharedString::from("")
                                            } else {
                                                SharedString::from(format!(
                                                    "{:.1}s",
                                                    ms as f64 / 1000.0
                                                ))
                                            }
                                        })
                                        .text_xs()
                                        .tabular_nums()
                                        .text_color(move || nsh_theme().muted_foreground),
                                    )
                                    .child(
                                        text(move || {
                                            let lang = store::lang();
                                            SharedString::from(
                                                item.with(|i| i.state.label(lang)),
                                            )
                                        })
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(move || {
                                            theme::status_color(item.with(|i| i.state))
                                        }),
                                    ),
                            ),
                    )
                    .child(
                        text(move || {
                            SharedString::from(display_text_privacy(&item.with(|i| i.summary.clone())))
                        })
                        .text_xs()
                        .number_of_lines(2)
                        .text_color(move || nsh_theme().muted_foreground),
                    ),
            ),
    )
}

fn detail_inspector_panel() -> impl IntoElement {
    let selected = computed(store::selected_item);

    ui::card()
        .flex_1()
        .min_w(px(0.0))
        .min_h(px(0.0))
        .child(
            text(move || {
                SharedString::from(pick(
                    store::lang(),
                    "详情与诊断依据",
                    "Inspector & Evidence",
                ))
            })
            .text_xs()
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(move || nsh_theme().muted_foreground),
        )
        .child(
            scroll().flex_1().min_h(px(0.0)).child(dynamic(move || {
                let lang = store::lang();
                let masked = store::is_ip_masked();
                match selected.get() {
                    None => view()
                        .p_4()
                        .child(
                            text(pick(
                                lang,
                                "选择左侧任意检测项，即可查看完整采集证据与修复建议。",
                                "Select any check on the left to inspect collected evidence and advice.",
                            ))
                            .text_sm()
                            .text_color(move || nsh_theme().muted_foreground),
                        )
                        .into_element(),
                    Some(item) => {
                        let key = item.key.clone();
                        let display_title = i18n::check_title(&item.key, lang)
                            .unwrap_or(&item.title)
                            .to_owned();
                        let summary_text = if masked {
                            i18n::mask_ips_in_text(&item.summary)
                        } else {
                            item.summary.clone()
                        };
                        let mut col = view()
                            .gap_3()
                            .child(
                                view()
                                    .flex_row()
                                    .items_center()
                                    .justify_between()
                                    .pb_3()
                                    .border_b_1()
                                    .border_color(move || nsh_theme().border)
                                    .child(
                                        view()
                                            .flex_col()
                                            .gap(px(2.0))
                                            .child(
                                                text(display_title)
                                                    .text_base()
                                                    .font_weight(FontWeight::BOLD)
                                                    .text_color(move || nsh_theme().foreground),
                                            )
                                            .child(
                                                text(match lang {
                                                    Lang::Zh => format!(
                                                        "{} · 耗时 {:.2}s",
                                                        item.category.label(lang),
                                                        item.duration_ms as f64 / 1000.0
                                                    ),
                                                    Lang::En => format!(
                                                        "{} · {:.2}s",
                                                        item.category.label(lang),
                                                        item.duration_ms as f64 / 1000.0
                                                    ),
                                                })
                                                .text_xs()
                                                .tabular_nums()
                                                .text_color(move || nsh_theme().muted_foreground),
                                            ),
                                    )
                                    .child(ui::status_badge(item.state, lang)),
                            )
                            .child(
                                view()
                                    .p_3()
                                    .rounded(px(10.0))
                                    .bg(move || nsh_theme().background)
                                    .border_1()
                                    .border_color(move || nsh_theme().border)
                                    .child(ui::kv_row(
                                        pick(lang, "诊断结论", "Summary"),
                                        summary_text,
                                    )),
                            );

                        if !item.details.is_empty() {
                            let mut det = view()
                                .p_3()
                                .gap(px(6.0))
                                .rounded(px(10.0))
                                .bg(move || nsh_theme().background)
                                .border_1()
                                .border_color(move || nsh_theme().border)
                                .child(
                                    text(pick(lang, "采集证据", "Collected Evidence"))
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(move || nsh_theme().primary),
                                );
                            for (i, line) in item.details.iter().enumerate() {
                                if i > 0 {
                                    det = det.child(
                                        view()
                                            .h(px(1.0))
                                            .bg(move || nsh_theme().border)
                                            .opacity(0.55),
                                    );
                                }
                                let shown_line = if masked {
                                    i18n::mask_ips_in_text(line)
                                } else {
                                    line.clone()
                                };
                                det = det.child(
                                    text(shown_line)
                                        .text_xs()
                                        .text_color(move || nsh_theme().foreground),
                                );
                            }
                            col = col.child(det);
                        }

                        if let Some(ref sug) = item.suggestion {
                            let st = if item.state == CheckState::Fail {
                                CheckState::Fail
                            } else {
                                CheckState::Warn
                            };
                            let shown_sug = if masked {
                                i18n::mask_ips_in_text(sug)
                            } else {
                                sug.clone()
                            };
                            col = col.child(
                                view()
                                    .p_3()
                                    .rounded(px(10.0))
                                    .bg(move || theme::status_bg(st))
                                    .border_1()
                                    .border_color(move || theme::status_color(st))
                                    .child(
                                        text(format!(
                                            "{}: {shown_sug}",
                                            pick(lang, "修复建议", "Recommendation")
                                        ))
                                        .text_xs()
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(move || theme::status_color(st)),
                                    ),
                            );
                        }

                        appear()
                            .key(format!("inspector-{key}-{}-{masked}", lang.code()))
                            .index(0)
                            .lift(6.0)
                            .child(col)
                            .into_element()
                    }
                }
            })),
        )
}

fn settings_panel() -> impl IntoElement {
    let opts = store::current_options();
    let proxy_draft = signal(opts.proxy.unwrap_or_default());
    let expected_ip_draft = signal(opts.expected_ip.unwrap_or_default());
    let expected_country_draft = signal(opts.expected_country.unwrap_or_default());
    let controller_url_draft = signal(opts.controller_url.unwrap_or_default());
    let controller_secret_draft = signal(opts.controller_secret.unwrap_or_default());
    let proxycheck_key_draft = signal(opts.proxycheck_api_key.unwrap_or_default());
    let abuseipdb_key_draft = signal(opts.abuseipdb_api_key.unwrap_or_default());
    let cf_radar_token_draft = signal(opts.cf_radar_token.unwrap_or_default());
    let greynoise_key_draft = signal(opts.greynoise_api_key.unwrap_or_default());
    let crowdsec_key_draft = signal(opts.crowdsec_api_key.unwrap_or_default());
    let virustotal_key_draft = signal(opts.virustotal_api_key.unwrap_or_default());
    let ipregistry_key_draft = signal(opts.ipregistry_api_key.unwrap_or_default());
    let ipdata_key_draft = signal(opts.ipdata_api_key.unwrap_or_default());
    let enable_cidr_draft = signal(opts.enable_cidr_lists);
    let long_secs_draft = signal(opts.long_conn_secs.to_string());
    let neutral_only_draft = signal(opts.neutral_only);
    let no_proxy_draft = signal(opts.no_proxy);

    let save_and_run = move || {
        let mut next = store::current_options();
        let trim_opt = |s: String| {
            let t = s.trim().to_owned();
            if t.is_empty() { None } else { Some(t) }
        };
        next.proxy = trim_opt(proxy_draft.get_untracked());
        next.expected_ip = trim_opt(expected_ip_draft.get_untracked());
        next.expected_country =
            trim_opt(expected_country_draft.get_untracked()).map(|c| c.to_ascii_uppercase());
        next.controller_url = trim_opt(controller_url_draft.get_untracked());
        next.controller_secret = trim_opt(controller_secret_draft.get_untracked());
        next.proxycheck_api_key = trim_opt(proxycheck_key_draft.get_untracked());
        next.abuseipdb_api_key = trim_opt(abuseipdb_key_draft.get_untracked());
        next.cf_radar_token = trim_opt(cf_radar_token_draft.get_untracked());
        next.greynoise_api_key = trim_opt(greynoise_key_draft.get_untracked());
        next.crowdsec_api_key = trim_opt(crowdsec_key_draft.get_untracked());
        next.virustotal_api_key = trim_opt(virustotal_key_draft.get_untracked());
        next.ipregistry_api_key = trim_opt(ipregistry_key_draft.get_untracked());
        next.ipdata_api_key = trim_opt(ipdata_key_draft.get_untracked());
        next.enable_cidr_lists = enable_cidr_draft.get_untracked();
        next.long_conn_secs = long_secs_draft
            .get_untracked()
            .trim()
            .parse::<u64>()
            .unwrap_or(15)
            .clamp(4, 120);
        next.neutral_only = neutral_only_draft.get_untracked();
        next.no_proxy = no_proxy_draft.get_untracked();
        store::update_options(next);
        store::trigger_check(false, false);
    };

    scroll().flex_1().min_h(px(0.0)).child(
        view()
            .gap_4()
            .child(
                appear().index(0).lift(8.0).child(
                    ui::card()
                        .child(
                            text(move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "网络代理与出口基准（全部可选，留空自动适配软路由/本机代理）",
                                    "Proxy & Exit Baseline (Optional; auto-adapts to soft-router / local proxy)",
                                ))
                            })
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(move || nsh_theme().primary),
                        )
                        .child(ui::labeled_input(
                            move || SharedString::from(pick(store::lang(), "手动指定代理 URL", "Explicit Proxy URL")),
                            move || {
                                pick(
                                    store::lang(),
                                    "例如: http://127.0.0.1:7890 或 socks5h://127.0.0.1:7891",
                                    "e.g. http://127.0.0.1:7890 or socks5h://127.0.0.1:7891",
                                )
                                .to_owned()
                            },
                            proxy_draft,
                            false,
                        ))
                        .child(
                            view()
                                .flex_row()
                                .gap_3()
                                .child(view().flex_1().child(ui::labeled_input(
                                    move || SharedString::from(pick(store::lang(), "预期独享出口 IP", "Expected Dedicated IP")),
                                    move || pick(store::lang(), "例如: 203.0.113.10", "e.g. 203.0.113.10").to_owned(),
                                    expected_ip_draft,
                                    false,
                                )))
                                .child(view().flex_1().child(ui::labeled_input(
                                    move || SharedString::from(pick(store::lang(), "预期出口国家代码", "Expected Country (ISO-2)")),
                                    move || pick(store::lang(), "例如: US / JP / SG", "e.g. US / JP / SG").to_owned(),
                                    expected_country_draft,
                                    false,
                                ))),
                        ),
                ),
            )
            .child(
                appear().index(1).lift(8.0).child(
                    ui::card()
                        .child(
                            text(move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "IP 纯净度增强信誉源（默认已内置零 Key 多源 + DNSBL；以下均为可选增强）",
                                    "IP Purity Enhanced Intel (Zero-key multi-source + DNSBL built-in; optional extras below)",
                                ))
                            })
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(move || nsh_theme().primary),
                        )
                        .child(
                            view()
                                .flex_row()
                                .gap_3()
                                .child(view().flex_1().child(ui::labeled_input(
                                    "proxycheck.io API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选（也可通过 PROXYCHECK_API_KEY 注入）",
                                            "Optional (or set PROXYCHECK_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    proxycheck_key_draft,
                                    true,
                                )))
                                .child(view().flex_1().child(ui::labeled_input(
                                    "AbuseIPDB API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选（也可通过 ABUSEIPDB_API_KEY 注入）",
                                            "Optional (or set ABUSEIPDB_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    abuseipdb_key_draft,
                                    true,
                                ))),
                        )
                        .child(
                            view()
                                .flex_row()
                                .gap_3()
                                .child(view().flex_1().child(ui::labeled_input(
                                    "Cloudflare Radar API Token",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选：ASN 28天 Bot 占比 (CF_RADAR_TOKEN)",
                                            "Optional: 28d ASN bot ratio (CF_RADAR_TOKEN)",
                                        )
                                        .to_owned()
                                    },
                                    cf_radar_token_draft,
                                    true,
                                )))
                                .child(view().flex_1().child(ui::labeled_input(
                                    "GreyNoise API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选 (GREYNOISE_API_KEY)",
                                            "Optional (GREYNOISE_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    greynoise_key_draft,
                                    true,
                                ))),
                        )
                        .child(
                            view()
                                .flex_row()
                                .gap_3()
                                .child(view().flex_1().child(ui::labeled_input(
                                    "CrowdSec CTI API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选 (CROWDSEC_API_KEY)",
                                            "Optional (CROWDSEC_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    crowdsec_key_draft,
                                    true,
                                )))
                                .child(view().flex_1().child(ui::labeled_input(
                                    "VirusTotal API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选 (VIRUSTOTAL_API_KEY)",
                                            "Optional (VIRUSTOTAL_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    virustotal_key_draft,
                                    true,
                                ))),
                        )
                        .child(
                            view()
                                .flex_row()
                                .gap_3()
                                .child(view().flex_1().child(ui::labeled_input(
                                    "IPRegistry API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选 (IPREGISTRY_API_KEY)",
                                            "Optional (IPREGISTRY_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    ipregistry_key_draft,
                                    true,
                                )))
                                .child(view().flex_1().child(ui::labeled_input(
                                    "IPData API Key",
                                    move || {
                                        pick(
                                            store::lang(),
                                            "可选 (IPDATA_API_KEY)",
                                            "Optional (IPDATA_API_KEY)",
                                        )
                                        .to_owned()
                                    },
                                    ipdata_key_draft,
                                    true,
                                ))),
                        )
                        .child(ui::apple_switch_row(
                            enable_cidr_draft,
                            move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "启用 17 份公开 CIDR 威胁/机房列表与整 ASN 滥用密度分析（默认开启并内存缓存 12h）",
                                    "Enable 17 Public CIDR Threat/Datacenter Lists & Whole-ASN Abuse Density (on by default, 12h cache)",
                                ))
                            },
                        ))
                ),
            )
            .child(
                appear().index(2).lift(8.0).child(
                    ui::card()
                        .child(
                            text(move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "软路由 / Clash / Mihomo 控制 API（可选）",
                                    "Router / Clash / Mihomo External Controller (Optional)",
                                ))
                            })
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(move || nsh_theme().primary),
                        )
                        .child(
                            view()
                                .flex_row()
                                .gap_3()
                                .child(view().flex_1().child(ui::labeled_input(
                                    move || {
                                        SharedString::from(pick(
                                            store::lang(),
                                            "External Controller 地址（支持软路由 LAN）",
                                            "External Controller URL (LAN or Localhost)",
                                        ))
                                    },
                                    move || pick(store::lang(), "例如: http://192.168.1.1:9090", "e.g. http://192.168.1.1:9090").to_owned(),
                                    controller_url_draft,
                                    false,
                                )))
                                .child(view().flex_1().child(ui::labeled_input(
                                    "Bearer Secret",
                                    move || pick(store::lang(), "留空表示无密钥", "Leave blank if none").to_owned(),
                                    controller_secret_draft,
                                    true,
                                ))),
                        ),
                ),
            )
            .child(
                appear().index(3).lift(8.0).child(
                    ui::card()
                        .child(
                            text(move || SharedString::from(pick(store::lang(), "探测行为", "Probe Behavior")))
                                .text_xs()
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(move || nsh_theme().primary),
                        )
                        .child(ui::labeled_input(
                            move || {
                                SharedString::from(pick(
                                    store::lang(),
                                    "长连接测试窗口时长（秒，默认 15，范围 4~120）",
                                    "Keep-Alive Window (seconds, default 15, range 4–120)",
                                ))
                            },
                            "15",
                            long_secs_draft,
                            false,
                        ))
                        .child(
                            view()
                                .flex_col()
                                .gap_2()
                                .child(ui::apple_switch_row(
                                    neutral_only_draft,
                                    move || {
                                        SharedString::from(pick(
                                            store::lang(),
                                            "保守模式（不向 claude.ai / chatgpt.com / gemini 主站发请求）",
                                            "Neutral-only mode (skip probing claude.ai / chatgpt.com / gemini)",
                                        ))
                                    },
                                ))
                                .child(ui::apple_switch_row(
                                    no_proxy_draft,
                                    move || {
                                        SharedString::from(pick(
                                            store::lang(),
                                            "强制忽略系统/环境变量代理（直出 WiFi 软路由）",
                                            "Ignore system & env proxies (direct / Wi-Fi soft-router)",
                                        ))
                                    },
                                ))
                        )
                        .child(
                            view().flex_row().pt_2().child(ui::app_button(
                                move || {
                                    SharedString::from(pick(
                                        store::lang(),
                                        "保存并重新体检",
                                        "Save & Re-Scan",
                                    ))
                                },
                                ButtonVariant::Primary,
                                move || store::is_running(),
                                save_and_run,
                            )),
                        ),
                ),
            ),
    )
}
