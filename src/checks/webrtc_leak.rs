use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::model::{CheckCategory, CheckItem, CheckState};
use crate::net::normalize_ip;

const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
const STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
];

/// Build an RFC 5389 STUN Binding Request (20 bytes).
pub fn build_stun_binding_request(tx_id: [u8; 12]) -> [u8; 20] {
    let mut pkt = [0u8; 20];
    pkt[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    pkt[2..4].copy_from_slice(&0x0000u16.to_be_bytes()); // Message Length = 0
    pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt[8..20].copy_from_slice(&tx_id);
    pkt
}

/// Parse XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001) from a STUN Binding Success Response.
pub fn parse_stun_response(tx_id: [u8; 12], msg: &[u8]) -> Option<IpAddr> {
    if msg.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    if msg_type != 0x0101 {
        return None;
    }
    let magic = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if magic != STUN_MAGIC_COOKIE || msg[8..20] != tx_id {
        return None;
    }
    let msg_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let end = msg.len().min(20 + msg_len);

    let mut pos = 20usize;
    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let attr_len = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > end {
            break;
        }
        let val = &msg[pos..pos + attr_len];
        if (attr_type == 0x0020 || attr_type == 0x0001) && val.len() >= 8 {
            let family = val[1];
            if family == 0x01 && val.len() >= 8 {
                let raw = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
                let ip_u32 = if attr_type == 0x0020 {
                    raw ^ STUN_MAGIC_COOKIE
                } else {
                    raw
                };
                return Some(IpAddr::V4(Ipv4Addr::from(ip_u32)));
            } else if family == 0x02 && val.len() >= 20 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&val[4..20]);
                if attr_type == 0x0020 {
                    let mut mask = [0u8; 16];
                    mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                    mask[4..16].copy_from_slice(&tx_id);
                    for i in 0..16 {
                        octets[i] ^= mask[i];
                    }
                }
                return Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
        let padded = (attr_len + 3) & !3;
        pos += padded;
    }

    None
}

async fn probe_stun_server(host: &str, port: u16, timeout_ms: u64) -> Option<IpAddr> {
    let addrs = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()?
    .ok()?;
    let target = addrs.into_iter().find(|a| a.is_ipv4())?;

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let tx_id: [u8; 12] = rand::random();
    let req = build_stun_binding_request(tx_id);
    sock.send_to(&req, target).await.ok()?;

    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_stun_response(tx_id, &buf[..n])
}

/// Pure evaluator for WebRTC / STUN UDP leak across soft-router, TUN, and HTTP-proxy topologies.
pub fn evaluate_webrtc(
    observed_ips: &[(String, Option<String>)],
    reference_exit_ip: Option<&str>,
    expected_ip: Option<&str>,
    network_ok: bool,
    using_http_proxy: bool,
    duration_ms: u64,
) -> CheckItem {
    let mut details = Vec::new();
    let mut first_observed = None;

    for (server, ip_opt) in observed_ips {
        match ip_opt {
            Some(ip) => {
                if first_observed.is_none() {
                    first_observed = Some(ip.clone());
                }
                details.push(format!("STUN {server}: 返回公网 IP {ip}"));
            }
            None => {
                details.push(format!("STUN {server}: 无响应（UDP 被拦截或超时）"));
            }
        }
    }

    let anchor_ip = expected_ip
        .filter(|s| !s.trim().is_empty())
        .or(reference_exit_ip);

    match first_observed {
        None => {
            if network_ok {
                CheckItem::new(
                    "webrtc",
                    CheckCategory::NetworkLeak,
                    "WebRTC / STUN 防泄漏",
                    CheckState::Ok,
                    "UDP STUN 探测未返回公网地址且外网正常，说明 STUN 已被规则阻断（防泄漏生效）",
                )
                .with_details(details)
                .with_duration(duration_ms)
            } else {
                CheckItem::new(
                    "webrtc",
                    CheckCategory::NetworkLeak,
                    "WebRTC / STUN 防泄漏",
                    CheckState::Unknown,
                    "STUN 无响应且外网连通性未确认，无法判断是规则阻断还是断网",
                )
                .with_details(details)
                .with_duration(duration_ms)
            }
        }
        Some(obs) => {
            if let Some(anchor) = anchor_ip {
                if normalize_ip(&obs) == normalize_ip(anchor) {
                    return CheckItem::new(
                        "webrtc",
                        CheckCategory::NetworkLeak,
                        "WebRTC / STUN 防泄漏",
                        CheckState::Ok,
                        format!("WebRTC STUN 看到的公网 IP ({obs}) 与当前代理出口一致"),
                    )
                    .with_details(details)
                    .with_duration(duration_ms);
                }

                let hint = if using_http_proxy {
                    "当前使用 HTTP/SOCKS 端口代理（非 TUN），浏览器 WebRTC UDP 包会绕过代理直出。建议在浏览器禁用 WebRTC 暴露本地/公网 IP，或改用 TUN / 软路由拦截 UDP 3478/5349/19302-19309。"
                } else {
                    "UDP STUN 绕过了软路由/隧道直接暴露了真实出口 IP！建议在软路由规则中 REJECT UDP 3478/5349/19302-19309 或启用全流量 UDP 代理。"
                };

                return CheckItem::new(
                    "webrtc",
                    CheckCategory::NetworkLeak,
                    "WebRTC / STUN 防泄漏",
                    CheckState::Fail,
                    format!("WebRTC STUN 泄露 IP {obs}，与 HTTP 出口 {anchor} 不一致！"),
                )
                .with_details(details)
                .with_suggestion(hint)
                .with_duration(duration_ms);
            }

            CheckItem::new(
                "webrtc",
                CheckCategory::NetworkLeak,
                "WebRTC / STUN 防泄漏",
                CheckState::Warn,
                format!("WebRTC STUN 探测到 IP {obs}（但未获取到 HTTP 出口基准，请人工核对是否为真实国内 IP）"),
            )
            .with_details(details)
            .with_duration(duration_ms)
        }
    }
}

pub async fn run_webrtc_check(
    reference_exit_ip: Option<&str>,
    expected_ip: Option<&str>,
    network_ok: bool,
    using_http_proxy: bool,
) -> CheckItem {
    let start = Instant::now();
    let (r1, r2) = tokio::join!(
        probe_stun_server(STUN_SERVERS[0].0, STUN_SERVERS[0].1, 3500),
        probe_stun_server(STUN_SERVERS[1].0, STUN_SERVERS[1].1, 3500),
    );
    let results = vec![
        (
            format!("{}:{}", STUN_SERVERS[0].0, STUN_SERVERS[0].1),
            r1.map(|ip| ip.to_string()),
        ),
        (
            format!("{}:{}", STUN_SERVERS[1].0, STUN_SERVERS[1].1),
            r2.map(|ip| ip.to_string()),
        ),
    ];

    evaluate_webrtc(
        &results,
        reference_exit_ip,
        expected_ip,
        network_ok,
        using_http_proxy,
        start.elapsed().as_millis() as u64,
    )
}
