use std::time::Duration;

use nsh_base::{button, theme as nsh_theme};
use nsh_core::prelude::*;

use crate::i18n::Lang;
use crate::model::CheckState;
use crate::store;
use crate::ui::theme::{self, AppleElevation, motion};

#[derive(Clone, Copy, PartialEq, Props)]
pub struct AppearProps {
    /// Stagger index among sibling cards (35 ms per step, capped at 7).
    #[prop(default)]
    pub index: u32,
    /// Vertical lift distance in points.
    #[prop(default = 10.0)]
    pub lift: f32,
    /// Fill parent flex axis when wrapping a growing container.
    #[prop(default)]
    pub flex: bool,
    pub children: Children,
}

/// Apple-style smooth fade & lift entrance animation driven natively by `AnimatedValue`.
#[component]
pub fn Appear(props: AppearProps) -> impl IntoElement {
    let progress = animated_value(0.0);
    let delay_ms = (props.index.min(7) as f32) * 35.0;
    let timing = if props.lift <= 6.0 {
        Timing {
            delay_ms,
            ..motion::INSPECTOR
        }
    } else {
        Timing {
            delay_ms,
            ..motion::ENTER
        }
    };
    progress.timing_with(1.0, timing);

    view()
        .when(props.flex, |v| v.flex_1().min_h(px(0.0)))
        .bind_opacity(&progress)
        .bind_translate_y(&progress.interpolate(&[0.0, 1.0], &[props.lift, 0.0]))
        .child(props.children)
}

/// Live Apple-style breathing dot: gently pulses while checks run, settles cleanly when idle.
#[component]
pub fn ScanningDot() -> impl IntoElement {
    let pulse = animated_value(1.0);
    let dim_phase = stored(false);

    set_interval(Duration::from_millis(760), move || {
        if store::is_running() {
            let next_dim = dim_phase.with(|d| {
                *d = !*d;
                *d
            });
            pulse.timing_with(if next_dim { 0.35 } else { 1.0 }, motion::PULSE);
        } else {
            dim_phase.with(|d| *d = false);
            pulse.spring(1.0, motion::SETTLE);
        }
    });

    view()
        .w(px(8.0))
        .h(px(8.0))
        .rounded_full()
        .bind_opacity(&pulse)
        .bind_scale(&pulse.interpolate(&[0.35, 1.0], &[0.82, 1.0]))
        .bg(move || {
            if store::is_running() {
                nsh_base::theme().primary
            } else {
                let st = store::current_report()
                    .map(|r| r.overall)
                    .unwrap_or(CheckState::Unknown);
                theme::status_color(st)
            }
        })
}

/// Smooth Day/Night-style sliding capsule switch for toggling between 中文 and EN.
/// Uses an elevated spring-animated pill thumb (`bind_translate_x`) that glides smoothly left ↔ right.
#[component]
pub fn LangPillSwitch() -> impl IntoElement {
    let initial_x = if store::lang() == Lang::En { 36.0 } else { 0.0 };
    let thumb_x = animated_value(initial_x);
    let press_scale = animated_value(1.0);

    button()
        .test_id("lang-toggle")
        .bind_scale(&press_scale)
        .on_press_down(move || {
            press_scale.spring(0.96, motion::PRESS);
        })
        .on_press_up(move || {
            press_scale.spring(1.0, motion::PRESS);
        })
        .on_press(move || {
            store::toggle_lang();
            let target_x = if store::lang() == Lang::En { 36.0 } else { 0.0 };
            thumb_x.spring(target_x, motion::SETTLE);
        })
        .relative()
        .w(px(78.0))
        .h(px(28.0))
        .p(px(2.0))
        .rounded_full()
        .border_1()
        .border_color(move || nsh_theme().border)
        .bg(move || nsh_theme().muted)
        .flex_row()
        .items_center()
        .overflow_hidden()
        .hover(|s| s.opacity(0.94))
        .focus_visible(|s| s.outline(px(2.0)).outline_color(move || nsh_theme().ring))
        // Smoothly sliding elevated capsule thumb
        .child(
            view()
                .absolute()
                .w(px(36.0))
                .h(px(22.0))
                .ml(px(2.0))
                .rounded_full()
                .bg(move || nsh_theme().card)
                .border_1()
                .border_color(move || nsh_theme().border)
                .apple_card_shadow()
                .z_index(1)
                .bind_translate_x(&thumb_x),
        )
        // Left label: 中文
        .child(
            view()
                .w(px(36.0))
                .h(px(22.0))
                .items_center()
                .justify_center()
                .z_index(2)
                .child(
                    text("中")
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(move || {
                            if store::lang() == Lang::Zh {
                                nsh_theme().foreground
                            } else {
                                nsh_theme().muted_foreground
                            }
                        }),
                ),
        )
        // Right label: EN
        .child(
            view()
                .w(px(36.0))
                .h(px(22.0))
                .items_center()
                .justify_center()
                .z_index(2)
                .child(
                    text("EN")
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(move || {
                            if store::lang() == Lang::En {
                                nsh_theme().foreground
                            } else {
                                nsh_theme().muted_foreground
                            }
                        }),
                ),
        )
}
