pub mod motion;
pub mod theme;

use nsh_base::{button, input, theme as nsh_theme};
use nsh_core::prelude::*;

use crate::i18n::Lang;
use crate::model::CheckState;
use crate::store;
use crate::ui::theme::{AppleElevation, motion as motion_tokens};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ButtonVariant {
    Primary,
    Secondary,
    Ghost,
}

/// Apple-style desktop push button with native spring press scale (`0.975`) and smooth hover tint.
pub fn app_button(
    label: impl IntoReactive<SharedString>,
    variant: ButtonVariant,
    disabled: impl Fn() -> bool + 'static,
    on_press: impl Fn() + 'static,
) -> impl IntoElement {
    let scale = animated_value(1.0);

    let bg_fn = move || {
        let t = nsh_theme();
        match variant {
            ButtonVariant::Primary => t.primary,
            ButtonVariant::Secondary => t.card,
            ButtonVariant::Ghost => t.background,
        }
    };
    let fg_fn = move || {
        let t = nsh_theme();
        match variant {
            ButtonVariant::Primary => t.primary_foreground,
            ButtonVariant::Secondary => t.foreground,
            ButtonVariant::Ghost => t.muted_foreground,
        }
    };

    button()
        .disabled(disabled)
        .bind_scale(&scale)
        .on_press_down(move || {
            scale.spring(0.97, motion_tokens::PRESS);
        })
        .on_press_up(move || {
            scale.spring(1.0, motion_tokens::PRESS);
        })
        .on_press(on_press)
        .h(px(30.0))
        .px_3()
        .items_center()
        .justify_center()
        .rounded(px(8.0))
        .border_1()
        .border_color(move || match variant {
            ButtonVariant::Primary => nsh_theme().primary,
            ButtonVariant::Secondary => nsh_theme().border,
            ButtonVariant::Ghost => nsh_theme().border,
        })
        .bg(bg_fn)
        .hover(|s| s.opacity(0.88))
        .focus_visible(|s| s.outline(px(2.0)).outline_color(move || nsh_theme().ring))
        .disabled_style(|s| s.opacity(0.45))
        .child(
            text(label)
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(fg_fn),
        )
}

/// Apple-style macOS sidebar navigation row with status indicator dot, count badge & spring press.
pub fn sidebar_item(
    label: impl IntoReactive<SharedString>,
    selected: impl Fn() -> bool + Copy + 'static,
    count_text: impl Fn() -> SharedString + 'static,
    dot_state: impl Fn() -> Option<CheckState> + 'static,
    on_press: impl Fn() + 'static,
) -> impl IntoElement {
    let scale = animated_value(1.0);
    let dot = computed(dot_state);

    button()
        .selected(selected)
        .bind_scale(&scale)
        .on_press_down(move || {
            scale.spring(0.98, motion_tokens::PRESS);
        })
        .on_press_up(move || {
            scale.spring(1.0, motion_tokens::PRESS);
        })
        .on_press(on_press)
        .h(px(34.0))
        .px_3()
        .rounded(px(8.0))
        .flex_row()
        .items_center()
        .justify_between()
        .style_when(selected, |s| s.bg(move || nsh_theme().sidebar_accent))
        .hover(|s| s.opacity(0.88))
        .focus_visible(|s| s.outline(px(2.0)).outline_color(move || nsh_theme().ring))
        .child(
            view()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    view()
                        .w(px(7.0))
                        .h(px(7.0))
                        .rounded_full()
                        .bg(move || match dot.get() {
                            Some(st) => theme::status_color(st),
                            None => nsh_theme().muted_foreground,
                        })
                        .opacity(move || if dot.get().is_some() { 1.0_f32 } else { 0.35 }),
                )
                .child(
                    text(label)
                        .text_sm()
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(move || {
                            if selected() {
                                nsh_theme().sidebar_accent_foreground
                            } else {
                                nsh_theme().sidebar_foreground
                            }
                        }),
                ),
        )
        .child(
            text(count_text)
                .text_xs()
                .tabular_nums()
                .text_color(move || {
                    if selected() {
                        nsh_theme().sidebar_accent_foreground
                    } else {
                        nsh_theme().muted_foreground
                    }
                }),
        )
}

/// Tinted Apple-style capsule status badge (`status-*-bg` + semantic dot + crisp label).
pub fn status_badge(state: CheckState, lang: Lang) -> impl IntoElement {
    view()
        .flex_row()
        .items_center()
        .gap(px(5.0))
        .px(px(9.0))
        .py(px(3.0))
        .rounded_full()
        .bg(move || theme::status_bg(state))
        .child(
            view()
                .w(px(6.0))
                .h(px(6.0))
                .rounded_full()
                .bg(move || theme::status_color(state)),
        )
        .child(
            text(state.label(lang))
                .text_xs()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(move || theme::status_color(state)),
        )
}

/// Reactive tinted capsule status badge (reacts to both state and language).
pub fn status_badge_reactive(state_fn: impl Fn() -> CheckState + Copy + 'static) -> impl IntoElement {
    view()
        .flex_row()
        .items_center()
        .gap(px(6.0))
        .px(px(10.0))
        .py(px(4.0))
        .rounded_full()
        .bg(move || theme::status_bg(state_fn()))
        .child(
            view()
                .w(px(7.0))
                .h(px(7.0))
                .rounded_full()
                .bg(move || theme::status_color(state_fn())),
        )
        .child(
            text(move || SharedString::from(state_fn().label(store::lang())))
                .text_xs()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(move || theme::status_color(state_fn())),
        )
}

/// Apple iOS/macOS-style sliding toggle switch row: description on the left,
/// spring-animated capsule switch with a gliding circular white knob on the right — all on ONE row.
pub fn apple_switch_row(
    checked: Signal<bool>,
    label: impl IntoReactive<SharedString>,
) -> impl IntoElement {
    let scale = animated_value(1.0);
    let knob_x = animated_value(if checked.get_untracked() { 18.0 } else { 0.0 });
    effect(move || {
        let on = checked.get();
        knob_x.spring(if on { 18.0 } else { 0.0 }, motion_tokens::SETTLE);
    });

    button()
        .bind_scale(&scale)
        .on_press_down(move || {
            scale.spring(0.985, motion_tokens::PRESS);
        })
        .on_press_up(move || {
            scale.spring(1.0, motion_tokens::PRESS);
        })
        .on_press(move || checked.set(!checked.get_untracked()))
        .flex_row()
        .items_center()
        .justify_between()
        .gap_3()
        .py(px(5.0))
        .child(
            text(label)
                .flex_1()
                .text_sm()
                .text_color(move || nsh_theme().foreground),
        )
        .child(
            view()
                .w(px(44.0))
                .h(px(26.0))
                .p(px(2.0))
                .flex_shrink_0()
                .flex_row()
                .items_center()
                .rounded_full()
                .bg(move || {
                    if checked.get() {
                        theme::status_color(CheckState::Ok)
                    } else {
                        nsh_theme().border
                    }
                })
                .child(
                    view()
                        .w(px(22.0))
                        .h(px(22.0))
                        .rounded_full()
                        .bg(rgba(0xFFFFFFFF))
                        .bind_translate_x(&knob_x)
                        .shadow([BoxShadow {
                            offset_x: px(0.0),
                            offset_y: px(1.0),
                            blur: px(3.0),
                            spread: px(0.0),
                            color: rgba(0x00000038).to_packed(),
                            inset: false,
                        }]),
                ),
        )
}

/// Elevated Apple-style card with soft adaptive shadow and 12pt radius.
pub fn card() -> View {
    view()
        .p_4()
        .gap_3()
        .rounded(px(12.0))
        .border_1()
        .border_color(move || nsh_theme().border)
        .bg(move || nsh_theme().card)
        .apple_card_shadow()
}

/// Compact Apple KPI metric card for the top overview strip.
pub fn metric_card(
    title: impl IntoReactive<SharedString>,
    value: impl IntoReactive<SharedString>,
    sub: impl IntoReactive<SharedString>,
) -> View {
    view()
        .flex_1()
        .min_w(px(0.0))
        .p_3()
        .gap(px(4.0))
        .rounded(px(12.0))
        .border_1()
        .border_color(move || nsh_theme().border)
        .bg(move || nsh_theme().card)
        .apple_card_shadow()
        .child(
            text(title)
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || nsh_theme().muted_foreground),
        )
        .child(
            text(value)
                .text_sm()
                .font_weight(FontWeight::SEMIBOLD)
                .tabular_nums()
                .number_of_lines(1)
                .text_color(move || nsh_theme().foreground),
        )
        .child(
            text(sub)
                .text_xs()
                .number_of_lines(1)
                .text_color(move || nsh_theme().muted_foreground),
        )
}

/// Styled Apple-like text field with crisp focus ring for the Settings panel.
pub fn labeled_input(
    field_label: impl IntoReactive<SharedString>,
    placeholder: impl IntoReactive<String>,
    value: Signal<String>,
    masked: bool,
) -> impl IntoElement {
    view()
        .gap(px(5.0))
        .child(
            text(field_label)
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || nsh_theme().muted_foreground),
        )
        .child(
            input()
                .value(move || value.get())
                .on_change(move |v: &str| value.set(v.to_owned()))
                .placeholder(placeholder)
                .placeholder_color(|| color(nsh_theme().muted_foreground))
                .caret_color(|| color(nsh_theme().primary))
                .masked(masked)
                .h(px(34.0))
                .px_3()
                .text_sm()
                .rounded(px(8.0))
                .border_1()
                .border_color(move || nsh_theme().input)
                .bg(move || nsh_theme().background)
                .text_color(move || nsh_theme().foreground)
                .focus(|s| s.border_color(move || nsh_theme().ring)),
        )
}

/// Clean Apple inset key-value row.
pub fn kv_row(
    label: impl IntoReactive<SharedString>,
    value: impl IntoReactive<SharedString>,
) -> impl IntoElement {
    view()
        .flex_row()
        .items_center()
        .justify_between()
        .gap_3()
        .py(px(4.0))
        .child(
            text(label)
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || nsh_theme().muted_foreground),
        )
        .child(
            text(value)
                .flex_1()
                .text_sm()
                .font_weight(FontWeight::MEDIUM)
                .text_color(move || nsh_theme().foreground),
        )
}
