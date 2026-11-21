pub mod ai_services;
pub mod cidr_lists;
pub mod claude_env;
pub mod dns_leak;
pub mod dnsbl;
pub mod env_fingerprint;
pub mod exit;
pub mod ip_purity;
pub mod ipv6_leak;
pub mod long_conn;
pub mod mihomo_api;
pub mod proxy_env;
pub mod timezone;
pub mod webrtc_leak;

use std::time::Instant;

use tokio::sync::mpsc::UnboundedSender;

use crate::config::CheckOptions;
use crate::i18n::{self, Lang, pick};
use crate::model::{CheckCategory, CheckItem, CheckState, DoctorReport, NetworkPathInfo};
use crate::net::system::collect_system_snapshot;
use crate::net::{build_http_client, resolve_network_path};

fn intel_keys_from_opts(opts: &CheckOptions) -> ip_purity::IntelApiKeys<'_> {
    ip_purity::IntelApiKeys {
        proxycheck: opts.proxycheck_api_key.as_deref(),
        abuseipdb: opts.abuseipdb_api_key.as_deref(),
        cf_radar: opts.cf_radar_token.as_deref(),
        greynoise: opts.greynoise_api_key.as_deref(),
        crowdsec: opts.crowdsec_api_key.as_deref(),
        virustotal: opts.virustotal_api_key.as_deref(),
        ipregistry: opts.ipregistry_api_key.as_deref(),
        ipdata: opts.ipdata_api_key.as_deref(),
    }
}

fn localize_titles(items: &mut [CheckItem], lang: Lang) {
    for item in items {
        if let Some(t) = i18n::check_title(&item.key, lang) {
            item.title = t.to_owned();
        }
    }
}

/// Standalone IP intelligence diagnostics on an arbitrary public IPv4/IPv6 address
/// with full parallelism across geo, multi-source intel, DoH DNSBL, RIPEstat, and optional CIDR lists.
pub async fn run_target_ip_checks_streaming(
    target_ip: &str,
    opts: &CheckOptions,
    progress_tx: Option<UnboundedSender<DoctorReport>>,
) -> DoctorReport {
    let total_start = Instant::now();
    let lang = opts.lang;
    let clean_ip = target_ip.trim();

    if !ip_purity::is_public_ip(clean_ip) {
        let item = CheckItem::new(
            "ip-purity",
            CheckCategory::NetworkLeak,
            i18n::check_title("ip-purity", lang).unwrap_or("Exit IP Purity Score"),
            CheckState::Fail,
            pick(
                lang,
                "目标地址不是合法公网 IPv4 / IPv6，无法查询信誉",
                "Target is not a valid public IPv4 / IPv6 address",
            ),
        );
        return DoctorReport {
            generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            overall: CheckState::Fail,
            total_duration_ms: total_start.elapsed().as_millis() as u64,
            network_path: NetworkPathInfo {
                mode_label: format!(
                    "{}: {clean_ip}",
                    pick(lang, "指定 IP 体检模式", "Target IP Inspection")
                ),
                ..Default::default()
            },
            exit_geo: None,
            ip_purity: None,
            env_fingerprint: None,
            ai_probes: Vec::new(),
            items: vec![item],
        };
    }

    let sys = collect_system_snapshot().await;
    let net_path = resolve_network_path(opts, &sys);
    let client = build_http_client(net_path.proxy_url.as_deref(), opts.timeout_ms, true)
        .unwrap_or_else(|_| reqwest::Client::new());

    // Run ALL network calls concurrently in one wave!
    let (geo, purity_bundle, (dnsbl_sum, dnsbl_item), cidr_opt) =
        tokio::join!(
            exit::lookup_geo_info(&client, Some(clean_ip)),
            ip_purity::fetch_ip_purity_readings(
                &client,
                Some(clean_ip),
                None,
                intel_keys_from_opts(opts),
            ),
            dnsbl::run_dnsbl_check(&client, Some(clean_ip), lang),
            async {
                if opts.enable_cidr_lists {
                    Some(cidr_lists::run_optional_cidr_scan(&client, Some(clean_ip), lang).await)
                } else {
                    None
                }
            }
        );

    let (mut cidr_sum_ref, cidr_item) = match cidr_opt {
        Some((s, i)) => (Some(s), Some(i)),
        None => (None, None),
    };
    if let Some(ref mut cs) = cidr_sum_ref {
        if !purity_bundle.routing.announced_v4_cidrs.is_empty() {
            cs.asn_density = cidr_lists::compute_asn_abuse_density_from_cache(
                &purity_bundle.routing.announced_v4_cidrs,
            )
            .await;
        }
    }

    // Pure in-memory purity + ASN cross-check fusion (<0.1ms) while RIPEstat finishes
    let (purity_report, purity_item) = ip_purity::evaluate_multi_source_purity(
        Some(clean_ip),
        geo.as_ref(),
        &purity_bundle.readings,
        purity_bundle.peeringdb.as_ref(),
        Some(&purity_bundle.routing),
        Some(&dnsbl_sum),
        cidr_sum_ref.as_ref(),
        purity_bundle.keyed_configured,
        lang,
        purity_bundle.duration_ms,
    );

    // Emit partial result immediately before RIPEstat if streaming
    if let Some(ref tx) = progress_tx {
        let mut partial_items = vec![purity_item.clone(), dnsbl_item.clone()];
        if let Some(ref ci) = cidr_item {
            partial_items.push(ci.clone());
        }
        localize_titles(&mut partial_items, lang);
        let partial = DoctorReport {
            generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            overall: DoctorReport::compute_overall(&partial_items),
            total_duration_ms: total_start.elapsed().as_millis() as u64,
            network_path: NetworkPathInfo {
                mode_label: format!(
                    "{}: {clean_ip}",
                    pick(lang, "指定 IP 体检模式", "Target IP Inspection")
                ),
                ..net_path.clone()
            },
            exit_geo: geo.clone(),
            ip_purity: Some(purity_report.clone()),
            env_fingerprint: None,
            ai_probes: Vec::new(),
            items: partial_items,
        };
        let _ = tx.send(partial);
    }

    let native_rpki_item =
        ip_purity::run_native_and_rpki_check(&client, Some(clean_ip), geo.as_ref(), lang).await;

    let mut items = vec![purity_item, dnsbl_item, native_rpki_item];
    if let Some(ci) = cidr_item {
        items.push(ci);
    }
    localize_titles(&mut items, lang);

    let overall = DoctorReport::compute_overall(&items);
    let final_report = DoctorReport {
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        overall,
        total_duration_ms: total_start.elapsed().as_millis() as u64,
        network_path: NetworkPathInfo {
            mode_label: format!(
                "{}: {clean_ip}",
                pick(lang, "指定 IP 体检模式", "Target IP Inspection")
            ),
            ..net_path
        },
        exit_geo: geo,
        ip_purity: Some(purity_report),
        env_fingerprint: None,
        ai_probes: Vec::new(),
        items,
    };
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(final_report.clone());
    }
    final_report
}

pub async fn run_target_ip_checks(target_ip: &str, opts: &CheckOptions) -> DoctorReport {
    run_target_ip_checks_streaming(target_ip, opts, None).await
}

/// Execute the full diagnostic suite with progressive streaming updates:
/// - Wave 1 (~1s): Local OS snapshot, OS fingerprint, Exit IP & Geo -> immediately pushed to UI
/// - Wave 2 (~1.5–3s): ALL fast checks (AI services, multi-source IP purity, DoH DNSBL, Native/RPKI,
///   DNS/EDNS, IPv6, WebRTC, proxy/captive, Claude/local CLI, optional controller & CIDR) run fully in parallel
///   while `long_conn` runs asynchronously in the background -> immediately pushed to UI!
/// - Wave 3: Final `long_conn` keep-alive result replaces its in-progress row.
pub async fn run_all_checks_streaming(
    opts: &CheckOptions,
    progress_tx: Option<UnboundedSender<DoctorReport>>,
) -> DoctorReport {
    if let Some(ref target) = opts.target_ip {
        if !target.trim().is_empty() {
            return run_target_ip_checks_streaming(target, opts, progress_tx).await;
        }
    }

    let total_start = Instant::now();
    let lang = opts.lang;

    // Phase 1: Local system snapshot & network path resolution
    let sys = collect_system_snapshot().await;
    let net_path: NetworkPathInfo = resolve_network_path(opts, &sys);
    let proxy_url = net_path.proxy_url.clone();

    let client = build_http_client(proxy_url.as_deref(), opts.timeout_ms, true)
        .unwrap_or_else(|_| reqwest::Client::new());
    let no_redirect_client = build_http_client(proxy_url.as_deref(), opts.timeout_ms, false)
        .unwrap_or_else(|_| reqwest::Client::new());

    // Start long-connection keep-alive IMMEDIATELY in parallel so it overlaps with Exit IP + Wave 2!
    let long_secs = opts.long_conn_secs;
    let long_proxy = proxy_url.clone();
    let long_handle =
        tokio::spawn(async move { long_conn::run_long_connection_check(long_proxy.as_deref(), long_secs).await });

    // Local OS fingerprint is pure in-memory (<1ms)
    let tz_override = std::env::var("TZ").ok();
    let (fp_report, fp_item) =
        env_fingerprint::evaluate_env_fingerprint(&sys, tz_override.as_deref(), lang);

    // Phase 2: Exit IP consistency & geo lookup (fast ~0.4–1s)
    let exit_out = exit::run_exit_check(&client, opts.expected_ip.as_deref()).await;
    let exit_ip = exit_out.primary_ip.as_deref();
    let exit_country = exit_out
        .geo
        .as_ref()
        .and_then(|g| g.country_code.as_deref())
        .or(exit_out.primary_loc.as_deref());

    let tz_item = timezone::evaluate_timezone_and_locale(&sys, exit_out.geo.as_ref());

    // Push Wave 1 immediately to UI so Exit IP + OS Fingerprint + Timezone appear right away!
    if let Some(ref tx) = progress_tx {
        let mut wave1 = vec![exit_out.consistency_item.clone()];
        if let Some(ref ex) = exit_out.exclusive_item {
            wave1.push(ex.clone());
        }
        wave1.push(fp_item.clone());
        wave1.push(tz_item.clone());
        localize_titles(&mut wave1, lang);
        let _ = tx.send(DoctorReport {
            generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            overall: DoctorReport::compute_overall(&wave1),
            total_duration_ms: total_start.elapsed().as_millis() as u64,
            network_path: net_path.clone(),
            exit_geo: exit_out.geo.clone(),
            ip_purity: None,
            env_fingerprint: Some(fp_report.clone()),
            ai_probes: Vec::new(),
            items: wave1,
        });
    }

    let using_http_proxy = net_path.proxy_url.is_some();

    // Phase 3: ALL fast checks (including 12+ IP purity sources, PeeringDB, RDAP & 17 CIDR lists!) run 100% concurrently — NEVER blocked by long_conn!
    let geo_asn = exit_out.geo.as_ref().and_then(|g| g.asn);
    let (
        (ai_items, ai_probes),
        purity_bundle,
        (dnsbl_sum, dnsbl_item),
        native_rpki_item,
        cidr_opt,
        dns_item,
        ipv6_item,
        webrtc_item,
        proxy_items,
        claude_items,
        controller_items,
    ) = tokio::join!(
        ai_services::run_ai_services_checks(
            &client,
            &no_redirect_client,
            exit_ip,
            opts.neutral_only
        ),
        ip_purity::fetch_ip_purity_readings(
            &client,
            exit_ip,
            geo_asn,
            intel_keys_from_opts(opts),
        ),
        dnsbl::run_dnsbl_check(&client, exit_ip, lang),
        ip_purity::run_native_and_rpki_check(&client, exit_ip, exit_out.geo.as_ref(), lang),
        async {
            if opts.enable_cidr_lists {
                Some(cidr_lists::run_optional_cidr_scan(&client, exit_ip, lang).await)
            } else {
                None
            }
        },
        dns_leak::run_dns_leak_check(
            &client,
            &sys.dns_servers,
            exit_country,
            opts.expected_country.as_deref(),
        ),
        ipv6_leak::run_ipv6_leak_check(&sys.ipv6, exit_country),
        webrtc_leak::run_webrtc_check(
            exit_ip,
            opts.expected_ip.as_deref(),
            exit_out.network_ok,
            using_http_proxy,
        ),
        proxy_env::run_proxy_env_checks(&sys, &net_path),
        claude_env::run_claude_and_local_ai_checks(
            &client,
            opts.claude_dir.as_deref(),
            sys.local_timezone_iana.as_deref(),
            opts.run_api_test,
            lang,
        ),
        mihomo_api::run_mihomo_controller_checks(
            opts.controller_url.as_deref(),
            opts.controller_secret.as_deref(),
        ),
    );

    let (mut cidr_sum_ref, cidr_item) = match cidr_opt {
        Some((s, i)) => (Some(s), Some(i)),
        None => (None, None),
    };
    if let Some(ref mut cs) = cidr_sum_ref {
        if !purity_bundle.routing.announced_v4_cidrs.is_empty() {
            cs.asn_density = cidr_lists::compute_asn_abuse_density_from_cache(
                &purity_bundle.routing.announced_v4_cidrs,
            )
            .await;
        }
    }

    // Instant in-memory IP purity + ASN cross-check fusion (<0.1ms)
    let (purity_report, purity_item) = ip_purity::evaluate_multi_source_purity(
        exit_ip,
        exit_out.geo.as_ref(),
        &purity_bundle.readings,
        purity_bundle.peeringdb.as_ref(),
        Some(&purity_bundle.routing),
        Some(&dnsbl_sum),
        cidr_sum_ref.as_ref(),
        purity_bundle.keyed_configured,
        lang,
        purity_bundle.duration_ms,
    );

    let build_items = |long_item: CheckItem| {
        let mut items = Vec::with_capacity(24);
        items.push(exit_out.consistency_item.clone());
        if let Some(ref ex) = exit_out.exclusive_item {
            items.push(ex.clone());
        }
        items.push(purity_item.clone());
        items.push(dnsbl_item.clone());
        items.push(native_rpki_item.clone());
        if let Some(ref ci) = cidr_item {
            items.push(ci.clone());
        }
        items.push(dns_item.clone());
        items.push(ipv6_item.clone());
        items.push(webrtc_item.clone());
        items.push(long_item);
        items.extend(ai_items.clone());
        items.push(fp_item.clone());
        items.push(tz_item.clone());
        items.extend(proxy_items.clone());
        items.extend(claude_items.clone());
        items.extend(controller_items.clone());
        localize_titles(&mut items, lang);
        items
    };

    // Push Wave 2 immediately (~2–3s!) while long_conn finishes keeping alive in background!
    if let Some(ref tx) = progress_tx {
        let pending_long = CheckItem::new(
            "long-conn",
            CheckCategory::NetworkLeak,
            i18n::check_title("long-conn", lang).unwrap_or("Long-Connection Stability"),
            CheckState::Unknown,
            match lang {
                Lang::Zh => format!("TLS 长连接正在后台保持测试中（目标 {long_secs}s，其余检测项已就绪）..."),
                Lang::En => format!("Holding TLS keep-alive in background ({long_secs}s target; all other checks ready)..."),
            },
        );
        let wave2_items = build_items(pending_long);
        let _ = tx.send(DoctorReport {
            generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            overall: DoctorReport::compute_overall(&wave2_items),
            total_duration_ms: total_start.elapsed().as_millis() as u64,
            network_path: net_path.clone(),
            exit_geo: exit_out.geo.clone(),
            ip_purity: Some(purity_report.clone()),
            env_fingerprint: Some(fp_report.clone()),
            ai_probes: ai_probes.clone(),
            items: wave2_items,
        });
    }

    // Phase 4: Await the already-running long_conn task (started right after Phase 1!)
    let long_item = match long_handle.await {
        Ok(item) => item,
        Err(_) => CheckItem::new(
            "long-conn",
            CheckCategory::NetworkLeak,
            i18n::check_title("long-conn", lang).unwrap_or("Long-Connection Stability"),
            CheckState::Unknown,
            pick(lang, "长连接测试任务异常中断", "Long-connection task interrupted"),
        ),
    };

    let items = build_items(long_item);
    let overall = DoctorReport::compute_overall(&items);
    let final_report = DoctorReport {
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        overall,
        total_duration_ms: total_start.elapsed().as_millis() as u64,
        network_path: net_path,
        exit_geo: exit_out.geo,
        ip_purity: Some(purity_report),
        env_fingerprint: Some(fp_report),
        ai_probes,
        items,
    };
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(final_report.clone());
    }
    final_report
}

/// Non-streaming wrapper used by CLI/JSON single-shot invocations.
pub async fn run_all_checks(opts: &CheckOptions) -> DoctorReport {
    run_all_checks_streaming(opts, None).await
}
