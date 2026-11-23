use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ai_network_protection::checks::ai_services::evaluate_cf_service_check;
use ai_network_protection::checks::cidr_lists::{
    AsnAbuseDensity, CidrSummary, count_overlap_u64, match_ip_and_subnet24, merge_ipv4_cidrs,
    parse_ipv4_cidr_ranges,
};
use ai_network_protection::checks::claude_env::{
    ClaudeEnvMap, detect_provider_type, evaluate_claude_endpoint_risk, mask_secret,
    parse_and_validate_settings_json, validate_environment_consistency,
};
use ai_network_protection::checks::dns_leak::{
    DnsAnswer, DnsProbeFacts, build_dns_query, evaluate_dns_leak, is_fake_ip,
    is_local_or_gateway_dns, parse_dns_response,
};
use ai_network_protection::checks::dnsbl::{
    DnsblHit, DnsblKind, DnsblSummary, evaluate_dnsbl_summary, filter_valid_dnsbl_codes,
    reverse_ip_for_dnsbl,
};
use ai_network_protection::checks::env_fingerprint::{
    evaluate_env_fingerprint, score_locale_intensity, score_timezone_intensity,
};
use ai_network_protection::checks::exit::{
    EndpointTrace, evaluate_exclusive_ip, evaluate_exit_consistency,
};
use ai_network_protection::checks::ip_purity::{
    AsnRoutingInfo, GeoConsensusVote, PeeringDbInfo, ReputationReading, evaluate_ip_purity,
    evaluate_multi_source_purity, extract_rir_country_from_whois, parse_abuseipdb_json,
    parse_blackbox_v3_json, parse_cf_radar_bot_json, parse_crowdsec_json, parse_freeipapi_json,
    parse_geoiplookup_json, parse_greynoise_json, parse_ip_api_com_json, parse_ip_guide_json,
    parse_ipapi_is_json, parse_ipdata_json, parse_iplocate_json, parse_ipquery_json,
    parse_ipregistry_json, parse_netcoffee_json, parse_onionoo_json, parse_otx_json,
    parse_peeringdb_json, parse_proxycheck_json, parse_rdap_asn_registration_json,
    parse_ripestat_announced_prefixes_json, parse_shodan_internetdb_json, parse_stopforumspam_json,
    parse_virustotal_json,
};
use ai_network_protection::checks::ipv6_leak::{Ipv6EvalInput, evaluate_ipv6_leak};
use ai_network_protection::checks::long_conn::{LongConnSample, evaluate_long_connection};
use ai_network_protection::checks::mihomo_api::{
    evaluate_controller_ai_connections, evaluate_controller_killswitch,
    evaluate_controller_rules_and_mode,
};
use ai_network_protection::checks::timezone::evaluate_timezone_and_locale;
use ai_network_protection::checks::webrtc_leak::{
    build_stun_binding_request, evaluate_webrtc, parse_stun_response,
};
use ai_network_protection::i18n::{Lang, mask_ips_in_text};
use ai_network_protection::model::{
    AiServiceProbe, CheckState, ExitGeoInfo, NetworkType, PurityBand, RiskBand,
};
use ai_network_protection::net::system::{
    DnsServerEntry, Ipv6Snapshot, PhysicalIpv6Addr, SystemSnapshot,
};
use ai_network_protection::net::{TraceInfo, normalize_proxy_url, parse_cf_trace};

#[test]
fn parses_cloudflare_trace_and_rejects_html() {
    let body = "fl=21f12\nh=www.cloudflare.com\nip=203.0.113.42\nloc=US\ncolo=SJC\nwarp=off\n";
    let tr = parse_cf_trace(body).expect("should parse valid trace");
    assert_eq!(tr.ip, "203.0.113.42");
    assert_eq!(tr.loc.as_deref(), Some("US"));
    assert_eq!(tr.colo.as_deref(), Some("SJC"));

    assert!(parse_cf_trace("<!DOCTYPE html><html><body>403</body></html>").is_none());
    assert!(parse_cf_trace("ip=not-an-ip\n").is_none());
}

#[test]
fn normalizes_windows_ie_and_socks_proxy_urls() {
    assert_eq!(
        normalize_proxy_url("127.0.0.1:7890").as_deref(),
        Some("http://127.0.0.1:7890")
    );
    assert_eq!(
        normalize_proxy_url("socks5://127.0.0.1:7891").as_deref(),
        Some("socks5h://127.0.0.1:7891")
    );
    assert_eq!(
        normalize_proxy_url("http=127.0.0.1:7890;https=127.0.0.1:7891").as_deref(),
        Some("http://127.0.0.1:7891")
    );
}

#[test]
fn exit_consistency_detects_ip_hopping_and_mismatch() {
    let mk = |label: &str, ip: &str| EndpointTrace {
        label: label.to_owned(),
        url: format!("https://{label}/cdn-cgi/trace"),
        trace: Some(TraceInfo {
            ip: ip.to_owned(),
            loc: Some("US".to_owned()),
            colo: Some("LAX".to_owned()),
            warp: None,
        }),
        error: None,
        latency_ms: 120,
    };

    let (ok_item, primary, _) = evaluate_exit_consistency(
        &[
            mk("cloudflare", "1.2.3.4"),
            mk("challenges", "1.2.3.4"),
            mk("cloudflare-dns", "1.2.3.4"),
        ],
        Some("1.2.3.4"),
        200,
    );
    assert_eq!(ok_item.state, CheckState::Ok);
    assert_eq!(primary.as_deref(), Some("1.2.3.4"));

    let (hop_item, _, _) = evaluate_exit_consistency(
        &[
            mk("cloudflare", "1.2.3.4"),
            mk("challenges", "5.6.7.8"),
            mk("cloudflare-dns", "1.2.3.4"),
        ],
        None,
        200,
    );
    assert_eq!(hop_item.state, CheckState::Fail);

    let ex_fail = evaluate_exclusive_ip(Some("5.6.7.8"), Some("1.2.3.4")).unwrap();
    assert_eq!(ex_fail.state, CheckState::Fail);
}

#[test]
fn ai_service_flags_split_routing_vs_baseline() {
    let trace_probe = AiServiceProbe {
        provider: "Anthropic".to_owned(),
        endpoint: "https://claude.ai/cdn-cgi/trace".to_owned(),
        reachable: true,
        status_code: Some(200),
        observed_ip: Some("9.9.9.9".to_owned()),
        cf_loc: Some("SG".to_owned()),
        cf_colo: Some("SIN".to_owned()),
        latency_ms: 100,
        note: "ok".to_owned(),
    };
    let api_probe = AiServiceProbe {
        provider: "Anthropic".to_owned(),
        endpoint: "https://api.anthropic.com/v1/models".to_owned(),
        reachable: true,
        status_code: Some(401),
        observed_ip: None,
        cf_loc: None,
        cf_colo: None,
        latency_ms: 120,
        note: "ok".to_owned(),
    };

    let item = evaluate_cf_service_check(
        "ai-anthropic",
        "Anthropic / Claude",
        &trace_probe,
        &api_probe,
        Some("1.2.3.4"),
        220,
    );
    assert_eq!(item.state, CheckState::Fail);
}

#[test]
fn dns_packet_build_and_parse_a_and_txt() {
    let pkt = build_dns_query(0x1234, "claude.ai", 1);
    assert_eq!(&pkt[0..2], &[0x12, 0x34]);

    // Synthesize a minimal A record response echoing the query
    let mut resp = pkt.clone();
    resp[2] = 0x81;
    resp[3] = 0x80; // QR=1, RCODE=0
    resp[7] = 0x01; // ANCOUNT=1
    // Pointer to offset 12 (0xC00C), Type A (1), Class IN (1), TTL 60, RDLEN 4, IP 198.18.0.42
    resp.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 198, 18, 0, 42,
    ]);
    let answers = parse_dns_response(0x1234, &resp).expect("valid A response");
    assert_eq!(answers, vec![DnsAnswer::A(Ipv4Addr::new(198, 18, 0, 42))]);
    assert!(is_fake_ip("198.18.0.42"));
    assert!(is_local_or_gateway_dns("192.168.1.1"));
}

#[test]
fn dns_leak_soft_router_fake_ip_passes_and_cn_egress_warns() {
    let soft_router_ok = DnsProbeFacts {
        nic_entries: vec![DnsServerEntry {
            iface: "Wi-Fi".to_owned(),
            family: 4,
            servers: vec!["192.168.1.1".to_owned()],
        }],
        system_claude_ips: vec!["198.18.0.15".to_owned()],
        direct_114_claude_ips: vec![],
        egress_resolver_ip: Some("223.5.5.5".to_owned()),
        egress_resolver_country: Some("CN".to_owned()),
        egress_resolver_isp: Some("Alibaba".to_owned()),
        exit_country: Some("US".to_owned()),
        expected_country: None,
        ..Default::default()
    };
    assert_eq!(evaluate_dns_leak(&soft_router_ok, 100).state, CheckState::Ok);

    let cn_leak = DnsProbeFacts {
        nic_entries: vec![DnsServerEntry {
            iface: "Wi-Fi".to_owned(),
            family: 4,
            servers: vec!["114.114.114.114".to_owned()],
        }],
        system_claude_ips: vec!["160.79.104.10".to_owned()],
        direct_114_claude_ips: vec!["160.79.104.10".to_owned()],
        egress_resolver_ip: Some("202.96.128.86".to_owned()),
        egress_resolver_country: Some("CN".to_owned()),
        egress_resolver_isp: Some("China Telecom".to_owned()),
        exit_country: Some("US".to_owned()),
        expected_country: None,
        ..Default::default()
    };
    assert_eq!(evaluate_dns_leak(&cn_leak, 100).state, CheckState::Fail);
}

#[test]
fn ipv6_leak_catches_soft_router_dual_stack_bypass() {
    let input = Ipv6EvalInput {
        snapshot: Ipv6Snapshot {
            physical_public: vec![PhysicalIpv6Addr {
                iface: "Wi-Fi".to_owned(),
                addr: "2409:8a55::1".to_owned(),
            }],
            tun_adapters: vec![],
            tun_has_ipv6: false,
            ipv6_default_routes: vec!["Wi-Fi".to_owned()],
        },
        direct_v6_trace: Some(TraceInfo {
            ip: "2409:8a55::1".to_owned(),
            loc: Some("CN".to_owned()),
            colo: Some("HKG".to_owned()),
            warp: None,
        }),
        ipv4_exit_country: Some("US".to_owned()),
        has_local_tun: false,
    };
    let item = evaluate_ipv6_leak(&input, 150);
    assert_eq!(item.state, CheckState::Fail);
}

#[test]
fn stun_parser_decodes_xor_mapped_ipv4_and_webrtc_evaluates() {
    let tx = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let req = build_stun_binding_request(tx);
    assert_eq!(req.len(), 20);

    // Synthesize Binding Success (0x0101) with XOR-MAPPED-ADDRESS (0x0020) for 203.0.113.7
    let ip_u32 = u32::from(Ipv4Addr::new(203, 0, 113, 7));
    let xored = ip_u32 ^ 0x2112_a442;
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x0101u16.to_be_bytes());
    resp.extend_from_slice(&12u16.to_be_bytes());
    resp.extend_from_slice(&0x2112_a442u32.to_be_bytes());
    resp.extend_from_slice(&tx);
    // Attr header: type 0x0020, len 8
    resp.extend_from_slice(&0x0020u16.to_be_bytes());
    resp.extend_from_slice(&8u16.to_be_bytes());
    // Reserved 0, family IPv4 (1), port 0x1234, xored IP
    resp.extend_from_slice(&[0x00, 0x01, 0x12, 0x34]);
    resp.extend_from_slice(&xored.to_be_bytes());

    let parsed = parse_stun_response(tx, &resp).expect("should parse XOR-MAPPED-ADDRESS");
    assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));

    let leak = evaluate_webrtc(
        &[("stun.l.google.com:19302".to_owned(), Some("114.80.1.2".to_owned()))],
        Some("203.0.113.7"),
        None,
        true,
        false,
        100,
    );
    assert_eq!(leak.state, CheckState::Fail);

    let blocked = evaluate_webrtc(
        &[("stun.l.google.com:19302".to_owned(), None)],
        Some("203.0.113.7"),
        None,
        true,
        false,
        100,
    );
    assert_eq!(blocked.state, CheckState::Ok);
}

#[test]
fn long_connection_enforces_tolerance_threshold() {
    let ok = evaluate_long_connection(
        &LongConnSample {
            alive_ms: 25_000,
            closed: false,
            heartbeats_sent: 4,
            error: None,
        },
        30,
    );
    assert_eq!(ok.state, CheckState::Ok);

    let fail = evaluate_long_connection(
        &LongConnSample {
            alive_ms: 12_000,
            closed: true,
            heartbeats_sent: 2,
            error: Some("EOF".to_owned()),
        },
        30,
    );
    assert_eq!(fail.state, CheckState::Fail);
}

#[test]
fn claude_settings_and_env_validator_detect_conflicts() {
    let raw = r#"{
      "env": {
        "ANTHROPIC_BASE_URL": "https://api.deepseek.com",
        "ANTHROPIC_AUTH_TOKEN": "sk-1234567890abcdef",
        "ANTHROPIC_MODEL": "deepseek-reasoner"
      }
    }"#;
    let (cfg_env, errs, warns) = parse_and_validate_settings_json(raw);
    assert!(errs.is_empty());
    assert!(warns.is_empty());
    assert_eq!(
        detect_provider_type(cfg_env.values.get("ANTHROPIC_BASE_URL").map(String::as_str)),
        "DeepSeek"
    );
    assert_eq!(mask_secret("sk-1234567890abcdef"), "sk-1***********cdef");

    let mut proc_env = BTreeMap::new();
    proc_env.insert(
        "ANTHROPIC_BASE_URL".to_owned(),
        "https://other-relay.example.com".to_owned(),
    );
    proc_env.insert("ANTHROPIC_API_KEY".to_owned(), "sk-stale-key".to_owned());

    let val = validate_environment_consistency(&cfg_env, &proc_env);
    assert!(!val.is_consistent);
    assert_eq!(val.differences.len(), 1);
    assert_eq!(val.differences[0].0, "ANTHROPIC_BASE_URL");
    assert_eq!(val.extra_vars.len(), 1);
    assert_eq!(val.extra_vars[0].0, "ANTHROPIC_API_KEY");

    let empty_cfg = ClaudeEnvMap::default();
    let val2 = validate_environment_consistency(&empty_cfg, &BTreeMap::new());
    assert!(val2.is_consistent);
}

#[test]
fn timezone_check_warns_on_offset_mismatch() {
    let mut sys = SystemSnapshot::default();
    sys.local_timezone_iana = Some("Asia/Shanghai".to_owned());
    sys.local_utc_offset_secs = 8 * 3600;
    sys.local_locale = Some("zh-CN".to_owned());

    let geo = ExitGeoInfo {
        ip: "203.0.113.10".to_owned(),
        country_code: Some("US".to_owned()),
        timezone_iana: Some("America/Los_Angeles".to_owned()),
        timezone_offset_secs: Some(-8 * 3600),
        ..Default::default()
    };

    let item = evaluate_timezone_and_locale(&sys, Some(&geo));
    assert_eq!(item.state, CheckState::Warn);
}

#[test]
fn controller_evaluators_detect_killswitch_and_direct_leaks() {
    let proxies = serde_json::json!({
        "proxies": {
            "AI 专用": {
                "type": "Fallback",
                "now": "US-Residential",
                "all": ["US-Residential", "REJECT"]
            }
        }
    });
    assert_eq!(
        evaluate_controller_killswitch(Some(&proxies), 50).state,
        CheckState::Ok
    );

    let rules = serde_json::json!({
        "rules": [
            { "type": "AND", "payload": "((NETWORK,udp),(DST-PORT,3478/5349/19302-19309))", "proxy": "REJECT" },
            { "type": "DomainSuffix", "payload": "claude.ai", "proxy": "AI 专用" }
        ]
    });
    let configs = serde_json::json!({ "mode": "rule", "tun": { "enable": true }, "ipv6": false });
    assert_eq!(
        evaluate_controller_rules_and_mode("http://192.168.1.1:9090", Some(&configs), Some(&rules), 50).state,
        CheckState::Ok
    );

    let conns_leak = serde_json::json!({
        "connections": [
            { "metadata": { "host": "claude.ai", "process": "claude.exe" }, "chains": ["DIRECT"] }
        ]
    });
    assert_eq!(
        evaluate_controller_ai_connections(Some(&rules), Some(&conns_leak), 50).state,
        CheckState::Fail
    );
}

#[test]
fn env_fingerprint_scores_restricted_signals_and_exempts_taiwan() {
    // Taiwan must NOT add timezone or locale risk
    assert_eq!(score_timezone_intensity(Some("Asia/Taipei")), 0);
    assert_eq!(score_locale_intensity(Some("zh-TW")), 0);
    assert_eq!(score_timezone_intensity(Some("Asia/Hong_Kong")), 60);
    assert_eq!(score_timezone_intensity(Some("Asia/Shanghai")), 100);
    assert_eq!(score_locale_intensity(Some("zh-CN")), 100);

    let mut tw_sys = SystemSnapshot::default();
    tw_sys.local_timezone_iana = Some("Asia/Taipei".to_owned());
    tw_sys.local_utc_offset_secs = 8 * 3600;
    tw_sys.local_locale = Some("zh-TW".to_owned());
    let (tw_rep, tw_item) = evaluate_env_fingerprint(&tw_sys, None, Lang::En);
    assert_eq!(tw_rep.score, 0);
    assert_eq!(tw_rep.band, RiskBand::Low);
    assert_eq!(tw_item.state, CheckState::Ok);

    // Mainland CN system with vendor fonts & OEM scores High
    let mut cn_sys = SystemSnapshot::default();
    cn_sys.local_timezone_iana = Some("Asia/Shanghai".to_owned());
    cn_sys.local_utc_offset_secs = 8 * 3600;
    cn_sys.local_locale = Some("zh-CN".to_owned());
    cn_sys.installed_fonts = vec![
        "Microsoft YaHei (TrueType)".to_owned(),
        "SimSun & NSimSun".to_owned(),
        "MiSans Regular".to_owned(),
        "HarmonyOS Sans SC".to_owned(),
    ];
    cn_sys.hardware_vendor = Some("HUAWEI".to_owned());
    cn_sys.installed_regional_browsers = vec!["QQ Browser".to_owned()];

    let (cn_rep, cn_item) = evaluate_env_fingerprint(&cn_sys, None, Lang::Zh);
    assert!(cn_rep.score >= 70, "expected high score, got {}", cn_rep.score);
    assert_eq!(cn_rep.band, RiskBand::High);
    assert_eq!(cn_item.state, CheckState::Warn);

    // TZ override mitigates timezone contribution
    let (ov_rep, _) = evaluate_env_fingerprint(&cn_sys, Some("America/Los_Angeles"), Lang::En);
    assert!(ov_rep.score + 20 <= cn_rep.score);
}

#[test]
fn claude_endpoint_risk_audits_relay_keywords_and_timezone() {
    let ok = evaluate_claude_endpoint_risk(
        Some("https://api.anthropic.com"),
        Some("Asia/Shanghai"),
        None,
        false,
        Lang::En,
    );
    assert_eq!(ok.state, CheckState::Ok);

    let warn = evaluate_claude_endpoint_risk(
        Some("https://api.deepseek.com/anthropic"),
        Some("Asia/Shanghai"),
        None,
        false,
        Lang::Zh,
    );
    assert_eq!(warn.state, CheckState::Warn);
    assert!(warn.suggestion.is_some());

    let safe_custom = evaluate_claude_endpoint_risk(
        Some("https://relay.example.org"),
        Some("Asia/Shanghai"),
        Some("Asia/Tokyo"),
        true,
        Lang::En,
    );
    assert_eq!(safe_custom.state, CheckState::Ok);
}

#[test]
fn ip_purity_never_fabricates_zero_key_score_and_deducts_reputation_risks() {
    let geo_dc = ExitGeoInfo {
        ip: "198.51.100.20".to_owned(),
        country_code: Some("US".to_owned()),
        org: Some("DigitalOcean, LLC".to_owned()),
        ..Default::default()
    };
    let unconf = ReputationReading {
        status: "unconfigured".to_owned(),
        ..Default::default()
    };
    let (z_rep, z_item) =
        evaluate_ip_purity(Some("198.51.100.20"), Some(&geo_dc), &unconf, &unconf, false, Lang::En, 10);
    assert_eq!(z_rep.purity, None);
    assert_eq!(z_rep.network_type, NetworkType::Datacenter);
    assert_eq!(z_item.state, CheckState::Warn);

    // Reputation-backed datacenter + proxy + abuse
    let pc_json = serde_json::json!({
        "status": "ok",
        "198.51.100.20": {
            "proxy": "yes",
            "type": "VPN, Hosting",
            "risk": 80
        }
    });
    let ab_json = serde_json::json!({
        "data": {
            "abuseConfidenceScore": 50,
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": false
        }
    });
    let pc = parse_proxycheck_json(&pc_json, "198.51.100.20");
    let ab = parse_abuseipdb_json(&ab_json);
    let (rep, item) =
        evaluate_ip_purity(Some("198.51.100.20"), Some(&geo_dc), &pc, &ab, true, Lang::En, 40);
    // Weighted multi-source deduction: Datacenter(-32) + VPN(-28) + Abuse(-17) + HighRisk(-18) -> 5 (Low / Fail)
    assert!(rep.purity.unwrap() < 20, "expected low score, got {:?}", rep.purity);
    assert_eq!(rep.band, Some(PurityBand::Low));
    assert_eq!(item.state, CheckState::Fail);

    // Clean residential IP
    let pc_clean = parse_proxycheck_json(
        &serde_json::json!({
            "status": "ok",
            "203.0.113.5": { "proxy": "no", "type": "Residential", "risk": 0 }
        }),
        "203.0.113.5",
    );
    let ab_clean = parse_abuseipdb_json(&serde_json::json!({
        "data": { "abuseConfidenceScore": 0, "usageType": "Fixed Line ISP", "isTor": false }
    }));
    let (clean_rep, clean_item) =
        evaluate_ip_purity(Some("203.0.113.5"), None, &pc_clean, &ab_clean, true, Lang::Zh, 35);
    // Calibrated baseline 92 (only 2 sources, no DNSBL / ASN proof -> stays at 92, never inflated to 100!)
    assert_eq!(clean_rep.purity, Some(92));
    assert_eq!(clean_rep.band, Some(PurityBand::High));
    assert_eq!(clean_item.state, CheckState::Ok);
}

#[test]
fn zero_key_multi_source_purity_dnsbl_cidr_edns_and_privacy_masking() {
    // 1. Multi-source + ASN cross-check: Blackbox hosting disagrees with residential labels -> realistic < 95 score!
    let r1 = parse_ipapi_is_json(&serde_json::json!({
        "ip": "154.36.129.181",
        "is_datacenter": false,
        "is_vpn": false,
        "is_proxy": false,
        "is_tor": false,
        "is_abuser": false,
        "company": "NetLab Global",
        "asn": "AS979 NetLab Global"
    }));
    let r2 = parse_ipquery_json(&serde_json::json!({
        "ip": "154.36.129.181",
        "risk": { "is_vpn": false, "is_proxy": false, "is_tor": false, "is_datacenter": false, "risk_score": 0 }
    }));
    let r3 = parse_blackbox_v3_json(&serde_json::json!({
        "ip": "154.36.129.181",
        "error": null,
        "asn": { "name": "NETLAB-SDN", "number": 979 },
        "classification": "hosting",
        "signals": { "hosting": true, "proxy": false, "tor": false, "vpnasn": false, "residentialasn": false }
    }));
    let r4 = parse_ip_api_com_json(&serde_json::json!({
        "status": "success", "countryCode": "US", "isp": "NetLab Global", "as": "AS979 NetLab Global",
        "mobile": false, "proxy": false, "hosting": false
    }));
    let r5 = parse_netcoffee_json(&serde_json::json!({
        "ip": "154.36.129.181", "is_datacenter": false, "isResidential": true, "is_vpn": false, "is_proxy": false, "is_tor": false
    }));
    let r6 = parse_shodan_internetdb_json(&serde_json::json!({
        "ip": "154.36.129.181", "ports": [], "tags": [], "vulns": []
    }));
    let r7 = parse_stopforumspam_json(&serde_json::json!({
        "ip": { "appears": 0, "confidence": 0.0 }
    }));
    let pdb: PeeringDbInfo = parse_peeringdb_json(&serde_json::json!({
        "data": [{ "name_long": "NetLab Global ISP Backbone", "info_type": "Cable/DSL/ISP", "info_ratio": "Balanced", "info_prefixes4": 2000 }]
    }));
    assert!(pdb.found);
    let clean_bl = DnsblSummary { checked: 16, errors: 0, hits: vec![] };
    let (rep, item) = evaluate_multi_source_purity(
        Some("154.36.129.181"),
        None,
        &[r1, r2, r3, r4, r5, r6, r7],
        Some(&pdb),
        None,
        Some(&clean_bl),
        None,
        false,
        Lang::En,
        45,
    );
    // Because blackbox flagged hosting on an otherwise clean IP, score is realistically calibrated (< 96, > 80)
    let score = rep.purity.unwrap();
    assert!((80..96).contains(&score), "expected calibrated score in 80..96, got {score}");
    assert_eq!(item.state, CheckState::Ok);

    // 1b. Full 12-source + live BGP ip.guide + young ASN + whole-ASN abuse density + CF Radar calibration!
    let r8 = parse_iplocate_json(&serde_json::json!({
        "ip": "154.36.129.181",
        "asn": { "asn": "AS979", "name": "NetLab Global", "type": "isp" },
        "privacy": { "is_vpn": false, "is_proxy": false, "is_tor": false, "is_hosting": false, "is_abuser": false }
    }));
    let r9 = parse_geoiplookup_json(&serde_json::json!({
        "ip": "154.36.129.181", "asn": "AS979", "asn_org": "NetLab Global", "connection_type": "Corporate"
    }));
    let r10 = parse_freeipapi_json(&serde_json::json!({
        "ipAddress": "154.36.129.181", "isProxy": false, "asn": "979", "asnOrganization": "NetLab Global"
    }));
    let r11 = parse_onionoo_json(&serde_json::json!({ "relays": [], "bridges": [] }));
    let r12 = parse_otx_json(&serde_json::json!({ "pulse_info": { "count": 0 }, "asn": "AS11161" }));
    assert!(r8.ok && r9.ok && r10.ok && r11.ok && r12.ok);
    assert_eq!(r11.tor, Some(false));
    assert_eq!(r12.otx_pulses, Some(0));

    let (guide_asn, guide_org, guide_pfx, guide_rir) = parse_ip_guide_json(&serde_json::json!({
        "network": {
            "cidr": "154.36.129.0/24",
            "autonomous_system": { "asn": 11161, "organization": "DigitalVirt LLC", "rir": "ARIN" }
        }
    }));
    assert_eq!(guide_asn, Some(11161));
    assert_eq!(guide_org.as_deref(), Some("DigitalVirt LLC"));
    assert_eq!(guide_pfx.as_deref(), Some("154.36.129.0/24"));
    assert_eq!(guide_rir.as_deref(), Some("ARIN"));

    let (pfx_list, pfx_total) = parse_ripestat_announced_prefixes_json(&serde_json::json!({
        "data": { "prefixes": [{ "prefix": "154.36.129.0/24" }, { "prefix": "154.36.130.0/24" }] }
    }));
    assert_eq!(pfx_list.len(), 2);
    assert_eq!(pfx_total, 512);

    let (reg_dt, reg_age) = parse_rdap_asn_registration_json(&serde_json::json!({
        "events": [{ "eventAction": "registration", "eventDate": "2022-12-16T00:00:00Z" }]
    }));
    assert_eq!(reg_dt.as_deref(), Some("2022-12-16"));
    assert!(reg_age.is_some());

    let bot_pct = parse_cf_radar_bot_json(&serde_json::json!({
        "result": { "summary_0": { "bot": "86.4", "human": "13.6" } }
    }));
    assert_eq!(bot_pct, Some(86.4));

    let merged_asn = merge_ipv4_cidrs(&["154.36.129.0/24".to_owned(), "154.36.130.0/24".to_owned()]);
    let threat_ranges = merge_ipv4_cidrs(&["154.36.129.10/31".to_owned()]);
    assert_eq!(count_overlap_u64(&merged_asn, &threat_ranges), 2);

    let routing = AsnRoutingInfo {
        bgp_asn: guide_asn,
        bgp_org: guide_org,
        bgp_prefix: guide_pfx,
        bgp_rir: guide_rir,
        announced_v4_cidrs: pfx_list,
        announced_v4_total: pfx_total,
        asn_registered_date: reg_dt,
        asn_age_years: Some(3.8),
        ptr_hostname: None,
        cf_radar_bot_pct: bot_pct,
        geo_votes: vec![
            GeoConsensusVote { source: "ipinfo".to_owned(), country_code: Some("US".to_owned()), city: None },
            GeoConsensusVote { source: "ipwho.is".to_owned(), country_code: Some("US".to_owned()), city: None },
            GeoConsensusVote { source: "ip.sb".to_owned(), country_code: Some("US".to_owned()), city: None },
            GeoConsensusVote { source: "db-ip".to_owned(), country_code: Some("US".to_owned()), city: None },
        ],
    };
    let cidr_with_density = CidrSummary {
        loaded: 17,
        asn_density: Some(AsnAbuseDensity {
            asn_v4_size: 512,
            listed_in_asn: 18,
            per_10k: 351.5,
            baseline_per_10k: 37.0,
            ratio: 9.5,
        }),
        ..Default::default()
    };
    let (cal_rep, _) = evaluate_multi_source_purity(
        Some("154.36.129.181"),
        None,
        &[r8, r9, r10, r11, r12],
        None,
        Some(&routing),
        Some(&clean_bl),
        Some(&cidr_with_density),
        true,
        Lang::Zh,
        60,
    );
    let cal_score = cal_rep.purity.unwrap();
    // With young small ASN + 9.5x ASN abuse density + 86.4% CF Radar bot traffic + no PTR -> realistic ~70-80!
    assert!((65..=82).contains(&cal_score), "expected realistic score 65..=82, got {cal_score}");

    // 1c. Optional keyed parsers (GreyNoise, CrowdSec, VirusTotal, IPRegistry, IPData)
    let gn = parse_greynoise_json(&serde_json::json!({ "ip": "1.2.3.4", "noise": true, "riot": false, "classification": "malicious" }));
    assert_eq!(gn.abusive, Some(true));
    let cs = parse_crowdsec_json(&serde_json::json!({ "ip": "1.2.3.4", "reputation": "malicious", "ip_range_score": 5 }));
    assert_eq!(cs.abusive, Some(true));
    let vt = parse_virustotal_json(&serde_json::json!({ "data": { "attributes": { "last_analysis_stats": { "malicious": 3, "suspicious": 1 } } } }));
    assert_eq!(vt.abusive, Some(true));
    let ir = parse_ipregistry_json(&serde_json::json!({ "ip": "1.2.3.4", "connection": { "asn": 14061, "type": "hosting" }, "security": { "is_cloud_provider": true, "is_proxy": false, "is_vpn": false, "is_tor": false, "is_abuser": false } }));
    assert_eq!(ir.datacenter, Some(true));
    let id = parse_ipdata_json(&serde_json::json!({ "ip": "1.2.3.4", "asn": { "asn": "AS14061", "type": "hosting" }, "threat": { "is_datacenter": true, "is_tor": false, "is_proxy": false, "is_known_abuser": false } }));
    assert_eq!(id.datacenter, Some(true));

    // 2. DNSBL reversal & filtering
    assert_eq!(
        reverse_ip_for_dnsbl(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        "4.3.2.1"
    );
    let codes = filter_valid_dnsbl_codes(&[
        "127.0.0.1".to_owned(),
        "127.255.255.254".to_owned(),
        "127.0.0.9".to_owned(),
    ]);
    assert_eq!(codes, vec!["127.0.0.9".to_owned()]);
    let bl = DnsblSummary {
        checked: 10,
        errors: 0,
        hits: vec![DnsblHit {
            name: "DroneBL".to_owned(),
            kind: DnsblKind::Abuse,
            codes,
            proxy_flagged: true,
        }],
    };
    assert!(bl.proxy_hit());
    assert_eq!(evaluate_dnsbl_summary("203.0.113.5", &bl, Lang::En, 20).state, CheckState::Fail);

    // 3. CIDR interval parsing & /24 neighbor scan
    let ranges = parse_ipv4_cidr_ranges(
        "# comment\n203.0.113.10\n203.0.113.11\n203.0.113.12/31\n198.51.100.0/24\n",
    );
    let (exact, whole, neighbors) = match_ip_and_subnet24(&ranges, Ipv4Addr::new(203, 0, 113, 10));
    assert!(exact);
    assert!(!whole);
    assert_eq!(neighbors.len(), 3); // .11, .12, .13
    let (exact2, whole2, _) = match_ip_and_subnet24(&ranges, Ipv4Addr::new(198, 51, 100, 42));
    assert!(exact2);
    assert!(whole2);

    // 4. RIPEstat RIR country extraction
    let whois = serde_json::json!({
        "data": { "records": [[ { "key": "country", "value": "US" } ]] }
    });
    assert_eq!(extract_rir_country_from_whois(&whois).as_deref(), Some("US"));

    // 5. EDNS Client Subnet (ECS) China leak detection
    let ecs_facts = DnsProbeFacts {
        system_claude_ips: vec!["198.18.0.42".to_owned()],
        exit_country: Some("US".to_owned()),
        edns_resolver_ip: Some("1.1.1.1".to_owned()),
        edns_resolver_geo: Some("United States - Cloudflare".to_owned()),
        ecs_subnet: Some("113.88.12.0".to_owned()),
        ecs_geo: Some("China - ChinaNet".to_owned()),
        ..Default::default()
    };
    assert_eq!(evaluate_dns_leak(&ecs_facts, 80).state, CheckState::Warn);

    // 5b. Custom Clash fake-ip-range 28.0.0.1/8 & System Proxy remote DNS pass without false positive
    assert!(is_fake_ip("28.0.0.42"));
    assert!(is_fake_ip("28.12.34.56"));
    let custom_fakeip = DnsProbeFacts {
        system_claude_ips: vec!["28.0.1.15".to_owned()],
        exit_country: Some("US".to_owned()),
        ..Default::default()
    };
    assert_eq!(evaluate_dns_leak(&custom_fakeip, 40).state, CheckState::Ok);

    let proxy_remote_dns = DnsProbeFacts {
        exit_country: Some("US".to_owned()),
        egress_resolver_ip: Some("223.5.5.5".to_owned()),
        egress_resolver_country: Some("CN".to_owned()),
        edns_resolver_ip: Some("1.1.1.1".to_owned()),
        edns_resolver_geo: Some("United States - Cloudflare".to_owned()),
        using_http_proxy: true,
        ..Default::default()
    };
    assert_eq!(evaluate_dns_leak(&proxy_remote_dns, 50).state, CheckState::Ok);

    // 6. Privacy IP masking preserves LAN/Fake-IP while masking public IPs
    let masked = mask_ips_in_text("出口 154.36.129.181 网关 192.168.0.1 FakeIP 198.18.9.238 v6 2001:4860:4860::8888");
    assert!(masked.contains("154.36.*.*"));
    assert!(masked.contains("192.168.0.1"));
    assert!(masked.contains("198.18.9.238"));
    assert!(masked.contains("2001:4860:****"));
}
