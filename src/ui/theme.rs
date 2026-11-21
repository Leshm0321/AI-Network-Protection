use nsh_base::theme;
use nsh_core::animation::{Curve, EaseMode};
use nsh_core::element::{AdaptiveColor, BoxShadow, Easing, Rgba, Spring, StyleRefinement, Styled, Timing, rgba};
use nsh_core::geometry::px;

use crate::model::CheckState;

/// Read a custom semantic status foreground token from `theme.json`.
pub fn status_color(state: CheckState) -> AdaptiveColor {
    let t = theme();
    match state {
        CheckState::Ok => t.color("status-ok").unwrap_or(t.primary),
        CheckState::Warn => t.color("status-warn").unwrap_or(t.foreground),
        CheckState::Fail => t.color("status-fail").unwrap_or(t.destructive),
        CheckState::Unknown => t.color("status-unknown").unwrap_or(t.muted_foreground),
    }
}

/// Read a custom semantic tinted pill background token from `theme.json`.
pub fn status_bg(state: CheckState) -> AdaptiveColor {
    let t = theme();
    match state {
        CheckState::Ok => t.color("status-ok-bg").unwrap_or(t.muted),
        CheckState::Warn => t.color("status-warn-bg").unwrap_or(t.muted),
        CheckState::Fail => t.color("status-fail-bg").unwrap_or(t.muted),
        CheckState::Unknown => t.color("status-unknown-bg").unwrap_or(t.muted),
    }
}

/// Apple HIG-inspired motion tokens running on NSH's native compositor thread.
pub mod motion {
    use super::{Curve, EaseMode, Easing, Spring, Timing};

    /// Tactile button/row press sink & release spring.
    pub const PRESS: Spring = Spring {
        stiffness: 520.0,
        damping: 34.0,
        mass: 1.0,
        velocity: None,
        frame_rate: None,
    };

    /// Smooth badge / indicator settle spring.
    pub const SETTLE: Spring = Spring {
        stiffness: 340.0,
        damping: 28.0,
        mass: 1.0,
        velocity: None,
        frame_rate: None,
    };

    /// Calm Apple cubic-out card entrance.
    pub const ENTER: Timing = Timing::new(340.0, Easing::Curve(Curve::Cubic, EaseMode::Out));

    /// Snappy inspector content cross-lift when switching selected items.
    pub const INSPECTOR: Timing = Timing::new(240.0, Easing::Curve(Curve::Cubic, EaseMode::Out));

    /// Gentle breathing pulse during active scanning.
    pub const PULSE: Timing = Timing::new(720.0, Easing::Curve(Curve::Sin, EaseMode::InOut));
}

const fn shadow_layer(y: f32, blur: f32, spread: f32, color: Rgba) -> BoxShadow {
    BoxShadow {
        offset_x: px(0.0),
        offset_y: px(y),
        blur: px(blur),
        spread: px(spread),
        color: color.to_packed(),
        inset: false,
    }
}

const fn rgb_a(hex: u32, alpha: f32) -> Rgba {
    rgba((hex << 8) | ((alpha * 255.0 + 0.5) as u32))
}

const LIGHT_CARD_SHADOW: [BoxShadow; 2] = [
    shadow_layer(1.0, 2.0, 0.0, rgb_a(0x000000, 0.04)),
    shadow_layer(6.0, 16.0, -4.0, rgb_a(0x000000, 0.07)),
];

const DARK_CARD_SHADOW: [BoxShadow; 2] = [
    shadow_layer(1.0, 2.0, 0.0, rgb_a(0x000000, 0.30)),
    shadow_layer(8.0, 22.0, -4.0, rgb_a(0x000000, 0.42)),
];

/// Extension trait applying soft Apple-style adaptive elevation shadows.
pub trait AppleElevation: Styled + Sized {
    fn apple_card_shadow(self) -> Self {
        self.shadow(LIGHT_CARD_SHADOW)
            .dark(|s: StyleRefinement| s.shadow(DARK_CARD_SHADOW))
    }
}

impl<T: Styled + Sized> AppleElevation for T {}
