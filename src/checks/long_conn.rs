use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::model::{CheckCategory, CheckItem, CheckState};

const TARGET_HOST: &str = "www.cloudflare.com";
const TARGET_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongConnSample {
    pub alive_ms: u64,
    pub closed: bool,
    pub heartbeats_sent: u32,
    pub error: Option<String>,
}

/// Pure evaluator for TLS keep-alive stability with an 80% duration tolerance threshold.
pub fn evaluate_long_connection(sample: &LongConnSample, target_secs: u64) -> CheckItem {
    let threshold_ms = (target_secs * 1000) * 4 / 5;
    let alive_s = sample.alive_ms as f64 / 1000.0;
    let mut details = vec![
        format!("探测目标: {TARGET_HOST}:{TARGET_PORT} (TLS + HTTP/1.1 Keep-Alive 心跳)"),
        format!("目标窗口: {target_secs}s · 实际保持: {alive_s:.1}s · 心跳次数: {}", sample.heartbeats_sent),
    ];
    if let Some(ref err) = sample.error {
        details.push(format!("中断原因: {err}"));
    }

    if !sample.closed && sample.alive_ms >= threshold_ms {
        CheckItem::new(
            "long-conn",
            CheckCategory::NetworkLeak,
            "长连接稳定性",
            CheckState::Ok,
            format!("TLS 长连接稳定保持 {alive_s:.1}s 未断开，满足 ChatGPT / Claude 流式输出需求"),
        )
        .with_details(details)
        .with_duration(sample.alive_ms)
    } else {
        CheckItem::new(
            "long-conn",
            CheckCategory::NetworkLeak,
            "长连接稳定性",
            CheckState::Fail,
            format!("长连接在 {alive_s:.1}s 时断开（目标 {target_secs}s），流式回复可能频繁 Reconnecting"),
        )
        .with_details(details)
        .with_suggestion("请检查节点 TCP 空闲超时、软路由转发稳定性或更换低抖动线路。")
        .with_duration(sample.alive_ms)
    }
}

/// Establish a raw TCP stream either directly (soft-router / TUN) or via HTTP CONNECT / SOCKS5 proxy.
async fn connect_transport(proxy_url: Option<&str>) -> Result<TcpStream, String> {
    let connect_timeout = Duration::from_secs(10);
    let Some(raw_proxy) = proxy_url else {
        return tokio::time::timeout(connect_timeout, TcpStream::connect((TARGET_HOST, TARGET_PORT)))
            .await
            .map_err(|_| "TCP 连接超时".to_owned())?
            .map_err(|e| format!("TCP 连接失败: {e}"));
    };

    let parsed = Url::parse(raw_proxy).map_err(|e| format!("代理 URL 无效: {e}"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let phost = parsed
        .host_str()
        .ok_or_else(|| "代理缺少主机名".to_owned())?
        .to_owned();
    let pport = parsed
        .port_or_known_default()
        .ok_or_else(|| "代理缺少端口".to_owned())?;

    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect((phost.as_str(), pport)))
        .await
        .map_err(|_| format!("连接代理 {phost}:{pport} 超时"))?
        .map_err(|e| format!("连接代理 {phost}:{pport} 失败: {e}"))?;

    if scheme.starts_with("socks5") {
        // Minimal SOCKS5 handshake (RFC 1928)
        let has_auth = !parsed.username().is_empty();
        if has_auth {
            stream
                .write_all(&[0x05, 0x02, 0x00, 0x02])
                .await
                .map_err(|e| format!("SOCKS5 握手发送失败: {e}"))?;
        } else {
            stream
                .write_all(&[0x05, 0x01, 0x00])
                .await
                .map_err(|e| format!("SOCKS5 握手发送失败: {e}"))?;
        }
        let mut resp = [0u8; 2];
        stream
            .read_exact(&mut resp)
            .await
            .map_err(|e| format!("SOCKS5 握手读取失败: {e}"))?;
        if resp[0] != 0x05 {
            return Err("SOCKS5 协议版本不匹配".to_owned());
        }
        if resp[1] == 0x02 {
            let user = parsed.username().as_bytes();
            let pass = parsed.password().unwrap_or("").as_bytes();
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass);
            stream
                .write_all(&auth)
                .await
                .map_err(|e| format!("SOCKS5 认证发送失败: {e}"))?;
            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .await
                .map_err(|e| format!("SOCKS5 认证响应失败: {e}"))?;
            if auth_resp[1] != 0x00 {
                return Err("SOCKS5 认证被拒绝".to_owned());
            }
        } else if resp[1] != 0x00 {
            return Err(format!("SOCKS5 不支持的认证方式: {}", resp[1]));
        }

        // CONNECT with DOMAINNAME (0x03)
        let host_bytes = TARGET_HOST.as_bytes();
        let mut req = Vec::with_capacity(7 + host_bytes.len());
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        req.extend_from_slice(host_bytes);
        req.extend_from_slice(&TARGET_PORT.to_be_bytes());
        stream
            .write_all(&req)
            .await
            .map_err(|e| format!("SOCKS5 CONNECT 发送失败: {e}"))?;
        let mut hdr = [0u8; 4];
        stream
            .read_exact(&mut hdr)
            .await
            .map_err(|e| format!("SOCKS5 CONNECT 响应失败: {e}"))?;
        if hdr[1] != 0x00 {
            return Err(format!("SOCKS5 CONNECT 失败 (code={})", hdr[1]));
        }
        let skip = match hdr[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;
                len[0] as usize + 2
            }
            _ => return Err("SOCKS5 无效地址类型".to_owned()),
        };
        let mut discard = vec![0u8; skip];
        stream
            .read_exact(&mut discard)
            .await
            .map_err(|e| e.to_string())?;
        Ok(stream)
    } else {
        // HTTP CONNECT tunnel
        let mut req = format!(
            "CONNECT {TARGET_HOST}:{TARGET_PORT} HTTP/1.1\r\nHost: {TARGET_HOST}:{TARGET_PORT}\r\n"
        );
        if !parsed.username().is_empty() {
            use std::fmt::Write as _;
            let cred = format!("{}:{}", parsed.username(), parsed.password().unwrap_or(""));
            let b64 = simple_base64(cred.as_bytes());
            let _ = write!(req, "Proxy-Authorization: Basic {b64}\r\n");
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("HTTP CONNECT 发送失败: {e}"))?;

        let mut buf = Vec::with_capacity(512);
        let mut tmp = [0u8; 256];
        loop {
            let n = tokio::time::timeout(connect_timeout, stream.read(&mut tmp))
                .await
                .map_err(|_| "HTTP CONNECT 响应超时".to_owned())?
                .map_err(|e| format!("HTTP CONNECT 读取失败: {e}"))?;
            if n == 0 {
                return Err("代理在 CONNECT 握手期间断开连接".to_owned());
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        let header_str = String::from_utf8_lossy(&buf);
        if !header_str.starts_with("HTTP/1.1 200") && !header_str.starts_with("HTTP/1.0 200") {
            let first_line = header_str.lines().next().unwrap_or("未知状态");
            return Err(format!("代理拒绝 CONNECT: {first_line}"));
        }
        Ok(stream)
    }
}

fn simple_base64(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub async fn run_long_connection_check(proxy_url: Option<&str>, target_secs: u64) -> CheckItem {
    let start = Instant::now();
    let target_secs = target_secs.max(4);

    let sample = match probe_tls_keepalive(proxy_url, target_secs).await {
        Ok(s) => s,
        Err((err, heartbeats)) => LongConnSample {
            alive_ms: start.elapsed().as_millis() as u64,
            closed: true,
            heartbeats_sent: heartbeats,
            error: Some(err),
        },
    };

    evaluate_long_connection(&sample, target_secs)
}

async fn probe_tls_keepalive(
    proxy_url: Option<&str>,
    target_secs: u64,
) -> Result<LongConnSample, (String, u32)> {
    let start = Instant::now();
    let tcp = connect_transport(proxy_url).await.map_err(|e| (e, 0))?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| (format!("TLS 初始化失败: {e}"), 0))?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let server_name = ServerName::try_from(TARGET_HOST)
        .map_err(|e| (format!("域名无效: {e}"), 0))?;

    let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .map_err(|_| ("TLS 握手超时".to_owned(), 0))?
        .map_err(|e| (format!("TLS 握手失败: {e}"), 0))?;

    let ping_req = format!(
        "HEAD /cdn-cgi/trace HTTP/1.1\r\nHost: {TARGET_HOST}\r\nConnection: keep-alive\r\nUser-Agent: AI-Network-Protection/0.1\r\n\r\n"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(target_secs);
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(8));
    let mut heartbeats_sent = 0u32;
    let mut drain_buf = [0u8; 2048];

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                let _ = tls.shutdown().await;
                return Ok(LongConnSample {
                    alive_ms: start.elapsed().as_millis() as u64,
                    closed: false,
                    heartbeats_sent,
                    error: None,
                });
            }
            _ = heartbeat_interval.tick() => {
                tls.write_all(ping_req.as_bytes())
                    .await
                    .map_err(|e| (format!("发送心跳失败: {e}"), heartbeats_sent))?;
                heartbeats_sent += 1;
            }
            read_res = tls.read(&mut drain_buf) => {
                match read_res {
                    Ok(0) => {
                        return Err(("对端提前关闭 TLS 连接 (EOF)".to_owned(), heartbeats_sent));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return Err((format!("长连接读取错误: {e}"), heartbeats_sent));
                    }
                }
            }
        }
    }
}
