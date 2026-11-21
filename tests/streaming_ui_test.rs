use ai_network_protection::App;
use ai_network_protection::config::CheckOptions;
use ai_network_protection::i18n::Lang;
use ai_network_protection::store::set_initial_options;
use nsh_engine::{EngineConfig, Points, Root, Size};
use nsh_testing::Headless;

/// Regression test for Owner-disposal cancellation bug:
/// Clicking "Inspect Target IP" or "Start Full Scan" from the Welcome pane immediately unmounts
/// the Welcome pane when `running` becomes true. Because the job runner is mounted on `Dashboard`'s
/// permanent root Owner, the background scan MUST NOT be cancelled and MUST finish cleanly.
#[test]
fn clicking_scan_from_welcome_pane_does_not_cancel_on_unmount() -> Result<(), String> {
    let mut opts = CheckOptions::default();
    opts.lang = Lang::Zh;
    opts.neutral_only = true;
    opts.long_conn_secs = 4;
    set_initial_options(opts);

    let mut app = Headless::start(EngineConfig {
        viewport: Size::new(Points(1200.0), Points(800.0)),
        ..EngineConfig::new(Root::of::<App>())
    })
    .map_err(|e| format!("{e:?}"))?;

    // 1. Must NOT auto-run on startup — Welcome pane must be visible
    app.wait_for("准备就绪，等待手动启动体检")?;

    // 2. Enter a non-public IP (fast deterministic target-ip path that completes in <1s without flaky internet)
    //    and click "单独检测上方输入的 IP" directly INSIDE the Welcome pane (which immediately unmounts!).
    app.type_text("id:target-ip-input", "127.0.0.1")?;
    app.press("单独检测上方输入的 IP")?;

    // 3. Verify the job completed cleanly despite Welcome pane unmounting!
    app.wait_for("目标地址不是合法公网 IPv4 / IPv6，无法查询信誉")?;
    app.wait_for("总体: 失败")?;

    Ok(())
}
