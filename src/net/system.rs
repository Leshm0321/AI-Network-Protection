use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServerEntry {
    pub iface: String,
    pub family: u8,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalIpv6Addr {
    pub iface: String,
    pub addr: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6Snapshot {
    pub physical_public: Vec<PhysicalIpv6Addr>,
    pub tun_adapters: Vec<String>,
    pub tun_has_ipv6: bool,
    pub ipv6_default_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProcInfo {
    pub name: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyInfo {
    pub enabled: bool,
    pub server: Option<String>,
    pub bypass: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub dns_servers: Vec<DnsServerEntry>,
    pub ipv6: Ipv6Snapshot,
    pub proxy_processes: Vec<ProxyProcInfo>,
    pub system_proxy: SystemProxyInfo,
    pub local_timezone_iana: Option<String>,
    pub local_utc_offset_secs: i32,
    pub local_locale: Option<String>,
    /// Read-only list of installed font names/filenames discovered on the OS.
    pub installed_fonts: Vec<String>,
    /// Read-only hardware OEM / manufacturer (e.g. "Apple", "HUAWEI", "Xiaomi", "LENOVO").
    pub hardware_vendor: Option<String>,
    /// Read-only hardware model identifier.
    pub hardware_model: Option<String>,
    /// Read-only list of detected regional browsers installed locally.
    pub installed_regional_browsers: Vec<String>,
}

pub fn is_public_ipv6(addr: &str) -> bool {
    let clean = addr.split('%').next().unwrap_or(addr).trim();
    match clean.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg0 = v6.segments()[0];
            // Exclude link-local fe80::/10 and ULA fc00::/7
            if (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            // Global unicast 2000::/3
            (seg0 & 0xe000) == 0x2000
        }
        _ => false,
    }
}

pub async fn collect_system_snapshot() -> SystemSnapshot {
    let local_timezone_iana = iana_time_zone::get_timezone().ok();
    let local_utc_offset_secs = chrono::Local::now().offset().local_minus_utc();
    let local_locale = sys_locale::get_locale();

    #[cfg(target_os = "windows")]
    let mut snap = collect_windows_snapshot().await;

    #[cfg(not(target_os = "windows"))]
    let mut snap = collect_unix_snapshot().await;

    snap.local_timezone_iana = local_timezone_iana;
    snap.local_utc_offset_secs = local_utc_offset_secs;
    snap.local_locale = local_locale;
    snap.installed_regional_browsers = detect_installed_regional_browsers();
    snap
}

/// Read-only check for common regional browser install directories/bundles on Windows & macOS.
fn detect_installed_regional_browsers() -> Vec<String> {
    let mut found = Vec::new();
    let mut push_unique = |label: &str| {
        if !found.iter().any(|x: &String| x == label) {
            found.push(label.to_owned());
        }
    };

    #[cfg(target_os = "windows")]
    {
        let roots: Vec<std::path::PathBuf> = ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"]
            .iter()
            .filter_map(|k| std::env::var_os(k).map(std::path::PathBuf::from))
            .collect();
        let candidates: &[(&str, &[&str])] = &[
            ("QQ Browser", &["Tencent\\QQBrowser"]),
            ("360 Browser", &["360\\360se6", "360\\360Chrome", "360\\360ChromeX"]),
            ("Quark", &["Quark"]),
            ("Sogou Explorer", &["SogouExplorer"]),
            ("Baidu Browser", &["Baidu\\BaiduBrowser"]),
            ("UC Browser", &["UCBrowser"]),
            ("2345 Browser", &["2345Soft\\2345Explorer"]),
            ("Liebao", &["liebao"]),
        ];
        for (label, rels) in candidates {
            if roots
                .iter()
                .any(|root| rels.iter().any(|rel| root.join(rel).exists()))
            {
                push_unique(label);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let mut app_dirs = vec![std::path::PathBuf::from("/Applications")];
        if let Some(home) = dirs::home_dir() {
            app_dirs.push(home.join("Applications"));
        }
        let candidates: &[(&str, &str)] = &[
            ("QQ Browser", "QQBrowser.app"),
            ("Quark", "Quark.app"),
            ("360 Browser", "360Chrome.app"),
            ("Sogou Explorer", "SogouExplorer.app"),
            ("UC Browser", "UCBrowser.app"),
        ];
        for (label, bundle) in candidates {
            if app_dirs.iter().any(|dir| dir.join(bundle).exists()) {
                push_unique(label);
            }
        }
    }

    found
}

async fn run_cmd_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        // CREATE_NO_WINDOW = 0x08000000 so terminal/GUI never flashes PowerShell windows
        cmd.creation_flags(0x0800_0000);
    }

    let child = cmd.spawn().ok()?;
    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout)
        .trim_start_matches('\u{feff}')
        .trim()
        .to_owned();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(target_os = "windows")]
async fn collect_windows_snapshot() -> SystemSnapshot {
    let ps = r#"
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })
$tunRegex = 'Meta|Mihomo|Clash|Sing-?Box|Wintun|TUN|TAP|WireGuard|Tailscale|ZeroTier|OpenVPN'
$ignorePhysRegex = 'Meta|Mihomo|Clash|Sing-?Box|Wintun|TUN|TAP|WireGuard|Tailscale|ZeroTier|OpenVPN|Loopback|Hyper-V|VMware|VirtualBox|Bluetooth|vEthernet'

$tunAdapters = @($adapters | Where-Object { $_.Name -match $tunRegex -or $_.InterfaceDescription -match $tunRegex } | Select-Object -ExpandProperty Name)
$physAdapters = @($adapters | Where-Object { $_.Name -notmatch $ignorePhysRegex -and $_.InterfaceDescription -notmatch $ignorePhysRegex })

$dnsList = @()
foreach ($a in $physAdapters) {
  foreach ($fam in @(2, 23)) {
    $s = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily $fam).ServerAddresses | Where-Object { $_ })
    if ($s.Count -gt 0) {
      $dnsList += [pscustomobject]@{ iface = $a.Name; family = $(if ($fam -eq 23) { 6 } else { 4 }); servers = $s }
    }
  }
}

$v6All = @(Get-NetIPAddress -AddressFamily IPv6)
$physIfIndexes = @($physAdapters | Select-Object -ExpandProperty ifIndex)
$physV6 = @($v6All | Where-Object {
  $_.InterfaceIndex -in $physIfIndexes -and $_.IPAddress -notmatch '^(fe80|fc|fd|::1)'
} | ForEach-Object { [pscustomobject]@{ iface = $_.InterfaceAlias; addr = $_.IPAddress } })

$tunV6 = @($v6All | Where-Object {
  $_.InterfaceAlias -in $tunAdapters -and $_.IPAddress -notmatch '^(fe80|::1)'
})

$v6Routes = @(Get-NetRoute -DestinationPrefix '::/0' | Where-Object { $_.State -ne 'Dead' } | Select-Object -ExpandProperty InterfaceAlias)

$procRegex = 'clash|mihomo|v2ray|xray|sing-?box|hysteria|tuic|wireguard|openvpn|surge|flclash|v2rayn|nekoray|nekobox|verge|tailscale|shadowsocks|trojan|naive'
$procs = @(Get-Process | Where-Object { $_.ProcessName -match $procRegex } | ForEach-Object {
  [pscustomobject]@{ name = "$($_.ProcessName).exe"; pid = [int]$_.Id }
})

$reg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$sysProxy = [pscustomobject]@{
  enabled = ([int]$reg.ProxyEnable -eq 1)
  server = $(if ($reg.ProxyServer) { [string]$reg.ProxyServer } else { $null })
  bypass = $(if ($reg.ProxyOverride) { [string]$reg.ProxyOverride } else { $null })
}

$fontNames = @()
foreach ($fp in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts', 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts')) {
  $fobj = Get-ItemProperty -Path $fp
  if ($fobj) {
    $fontNames += @($fobj.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Name) $($_.Value)" })
  }
}

$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$hwVendor = $(if ($cs -and $cs.Manufacturer) { [string]$cs.Manufacturer } else { $null })
$hwModel = $(if ($cs -and $cs.Model) { [string]$cs.Model } else { $null })

[pscustomobject]@{
  dns_servers = $dnsList
  physical_public = $physV6
  tun_adapters = $tunAdapters
  tun_has_ipv6 = ($tunV6.Count -gt 0)
  ipv6_default_routes = $v6Routes
  proxy_processes = $procs
  system_proxy = $sysProxy
  installed_fonts = $fontNames
  hardware_vendor = $hwVendor
  hardware_model = $hwModel
} | ConvertTo-Json -Compress -Depth 5
"#;

    let mut snap = SystemSnapshot::default();
    let Some(raw) = run_cmd_timeout(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", ps],
        12,
    )
    .await
    else {
        return snap;
    };

    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return snap;
    };

    snap.dns_servers = parse_json_array(v.get("dns_servers"))
        .into_iter()
        .filter_map(|item| {
            let iface = item.get("iface")?.as_str()?.to_owned();
            let family = item.get("family")?.as_u64()? as u8;
            let servers = parse_json_string_array(item.get("servers"));
            Some(DnsServerEntry {
                iface,
                family,
                servers,
            })
        })
        .collect();

    let physical_public = parse_json_array(v.get("physical_public"))
        .into_iter()
        .filter_map(|item| {
            let iface = item.get("iface")?.as_str()?.to_owned();
            let addr = item.get("addr")?.as_str()?.to_owned();
            if is_public_ipv6(&addr) {
                Some(PhysicalIpv6Addr { iface, addr })
            } else {
                None
            }
        })
        .collect();

    snap.ipv6 = Ipv6Snapshot {
        physical_public,
        tun_adapters: parse_json_string_array(v.get("tun_adapters")),
        tun_has_ipv6: v
            .get("tun_has_ipv6")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        ipv6_default_routes: parse_json_string_array(v.get("ipv6_default_routes")),
    };

    snap.proxy_processes = parse_json_array(v.get("proxy_processes"))
        .into_iter()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?.to_owned();
            let pid = item.get("pid")?.as_u64()? as u32;
            Some(ProxyProcInfo { name, pid })
        })
        .collect();

    if let Some(sp) = v.get("system_proxy") {
        snap.system_proxy = SystemProxyInfo {
            enabled: sp.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
            server: sp
                .get("server")
                .and_then(|x| x.as_str())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
            bypass: sp
                .get("bypass")
                .and_then(|x| x.as_str())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        };
    }

    snap.installed_fonts = parse_json_string_array(v.get("installed_fonts"));
    snap.hardware_vendor = v
        .get("hardware_vendor")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    snap.hardware_model = v
        .get("hardware_model")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    snap
}

#[cfg(not(target_os = "windows"))]
async fn collect_unix_snapshot() -> SystemSnapshot {
    let mut snap = SystemSnapshot::default();

    // 1. DNS servers: prefer `scutil --dns` on macOS, fallback to `/etc/resolv.conf`
    #[cfg(target_os = "macos")]
    if let Some(out) = run_cmd_timeout("scutil", &["--dns"], 5).await {
        let mut servers = Vec::new();
        for line in out.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("nameserver[") {
                if let Some((_, addr)) = rest.split_once(':') {
                    let ip = addr.trim().to_owned();
                    if !ip.is_empty() && !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
        if !servers.is_empty() {
            snap.dns_servers.push(DnsServerEntry {
                iface: "macOS Resolver".to_owned(),
                family: 4,
                servers,
            });
        }
    }

    if snap.dns_servers.is_empty() {
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            let servers: Vec<String> = content
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    line.strip_prefix("nameserver")
                        .and_then(|rest| rest.split_whitespace().next())
                        .map(str::to_owned)
                })
                .collect();
            if !servers.is_empty() {
                snap.dns_servers.push(DnsServerEntry {
                    iface: "resolv.conf".to_owned(),
                    family: 4,
                    servers,
                });
            }
        }
    }

    // 2. macOS network interfaces: public IPv6 & active utun/tun adapters + ::/0 default route
    #[cfg(target_os = "macos")]
    {
        if let Some(out) = run_cmd_timeout("ifconfig", &[], 5).await {
            let mut cur_iface = String::new();
            let mut cur_up = false;
            for line in out.lines() {
                if !line.starts_with('\t') && !line.starts_with(' ') {
                    if let Some((name, rest)) = line.split_once(':') {
                        cur_iface = name.trim().to_owned();
                        cur_up = rest.contains("<UP,") || rest.contains(",UP,") || rest.contains(",UP>");
                        if cur_up && cur_iface.starts_with("utun") {
                            // Only treat utun as proxy TUN if it has an inet/inet6 address later
                        }
                    }
                } else if cur_up {
                    let trimmed = line.trim();
                    if trimmed.starts_with("inet ") && cur_iface.starts_with("utun") {
                        if !snap.ipv6.tun_adapters.contains(&cur_iface) {
                            snap.ipv6.tun_adapters.push(cur_iface.clone());
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
                        if let Some(raw_addr) = rest.split_whitespace().next() {
                            let addr = raw_addr.split('%').next().unwrap_or(raw_addr);
                            if cur_iface.starts_with("utun") {
                                if !addr.starts_with("fe80:") && addr != "::1" {
                                    snap.ipv6.tun_has_ipv6 = true;
                                }
                            } else if is_public_ipv6(addr) {
                                snap.ipv6.physical_public.push(PhysicalIpv6Addr {
                                    iface: cur_iface.clone(),
                                    addr: addr.to_owned(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if let Some(out) = run_cmd_timeout("netstat", &["-rn", "-f", "inet6"], 5).await {
            for line in out.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[0] == "default" {
                    let iface = parts[3].to_owned();
                    if !snap.ipv6.ipv6_default_routes.contains(&iface) {
                        snap.ipv6.ipv6_default_routes.push(iface);
                    }
                }
            }
        }
    }

    // 3. Proxy processes via `ps`
    if let Some(out) = run_cmd_timeout("ps", &["-eo", "pid,comm"], 5).await {
        let keywords = [
            "clash", "mihomo", "v2ray", "xray", "sing-box", "singbox", "hysteria", "tuic",
            "wireguard", "openvpn", "surge", "flclash", "nekoray", "tailscale", "stash", "loon",
        ];
        for line in out.lines().skip(1) {
            let mut parts = line.split_whitespace();
            let Some(pid_str) = parts.next() else {
                continue;
            };
            let Some(comm) = parts.next() else {
                continue;
            };
            let lower = comm.to_ascii_lowercase();
            if keywords.iter().any(|k| lower.contains(k)) {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    snap.proxy_processes.push(ProxyProcInfo {
                        name: comm.to_owned(),
                        pid,
                    });
                }
            }
        }
    }

    // 4. macOS system proxy via `scutil --proxy` (HTTP / HTTPS / SOCKS)
    #[cfg(target_os = "macos")]
    if let Some(out) = run_cmd_timeout("scutil", &["--proxy"], 5).await {
        let mut http_en = false;
        let mut http_host = None;
        let mut http_port = None;
        let mut https_en = false;
        let mut https_host = None;
        let mut https_port = None;
        let mut socks_en = false;
        let mut socks_host = None;
        let mut socks_port = None;
        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("HTTPEnable :") && line.ends_with('1') {
                http_en = true;
            } else if let Some(v) = line.strip_prefix("HTTPProxy :") {
                http_host = Some(v.trim().to_owned());
            } else if let Some(v) = line.strip_prefix("HTTPPort :") {
                http_port = Some(v.trim().to_owned());
            } else if line.starts_with("HTTPSEnable :") && line.ends_with('1') {
                https_en = true;
            } else if let Some(v) = line.strip_prefix("HTTPSProxy :") {
                https_host = Some(v.trim().to_owned());
            } else if let Some(v) = line.strip_prefix("HTTPSPort :") {
                https_port = Some(v.trim().to_owned());
            } else if line.starts_with("SOCKSEnable :") && line.ends_with('1') {
                socks_en = true;
            } else if let Some(v) = line.strip_prefix("SOCKSProxy :") {
                socks_host = Some(v.trim().to_owned());
            } else if let Some(v) = line.strip_prefix("SOCKSPort :") {
                socks_port = Some(v.trim().to_owned());
            }
        }
        let server = if https_en {
            https_host
                .zip(https_port)
                .map(|(h, p)| format!("http://{h}:{p}"))
        } else if http_en {
            http_host
                .zip(http_port)
                .map(|(h, p)| format!("http://{h}:{p}"))
        } else if socks_en {
            socks_host
                .zip(socks_port)
                .map(|(h, p)| format!("socks5h://{h}:{p}"))
        } else {
            None
        };
        if let Some(srv) = server {
            snap.system_proxy = SystemProxyInfo {
                enabled: true,
                server: Some(srv),
                bypass: None,
            };
        }
    }

    // 5. Read-only font directory scan & hardware model on macOS/Unix
    let mut font_dirs: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(target_os = "macos")]
    {
        font_dirs.push(std::path::PathBuf::from("/System/Library/Fonts"));
        font_dirs.push(std::path::PathBuf::from("/System/Library/Fonts/Supplemental"));
        font_dirs.push(std::path::PathBuf::from("/Library/Fonts"));
        if let Some(home) = dirs::home_dir() {
            font_dirs.push(home.join("Library").join("Fonts"));
        }
        snap.hardware_vendor = Some("Apple".to_owned());
        snap.hardware_model = run_cmd_timeout("sysctl", &["-n", "hw.model"], 3).await;
    }
    #[cfg(not(target_os = "macos"))]
    {
        font_dirs.push(std::path::PathBuf::from("/usr/share/fonts"));
        if let Some(home) = dirs::home_dir() {
            font_dirs.push(home.join(".local/share/fonts"));
            font_dirs.push(home.join(".fonts"));
        }
    }
    for dir in font_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    snap.installed_fonts.push(name);
                }
            }
        }
    }

    snap
}

#[cfg(target_os = "windows")]
fn parse_json_array(value: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    match value {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(v) if !v.is_null() => vec![v.clone()],
        _ => Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn parse_json_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    parse_json_array(value)
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .filter(|s| !s.is_empty())
        .collect()
}
