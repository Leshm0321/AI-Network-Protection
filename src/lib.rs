//! AI-Network-Protection — pure Rust + Native Shell (NSH) Windows & macOS desktop diagnostic app
//! for AI network, leak detection, and local Claude / AI CLI configuration health.

pub mod assets;
pub mod checks;
pub mod cli_output;
pub mod config;
pub mod i18n;
pub mod model;
pub mod net;
pub mod screens;
pub mod store;
pub mod ui;

use nsh_base::theme;
use nsh_core::prelude::*;

const APP_THEME_JSON: &str = include_str!("../theme.json");

/// Native Shell module registration (`nsh.json` `"rust": "."`).
#[native_module("ai-network-protection/native")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
    registry.assets(assets!());
}

/// Root NSH component mounted directly into the native Windows / macOS main window
/// and in `nsh_testing::Headless`.
#[component]
pub fn App() -> impl IntoElement {
    if let Ok(tokens) = nsh_base::tokens_of(Some(APP_THEME_JSON)) {
        nsh_core::element::set_tokens(tokens);
    }

    view()
        .flex_1()
        .bg(move || theme().background)
        .text_color(move || theme().foreground)
        .child(screens::dashboard::dashboard())
}
