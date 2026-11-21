# AI-Network-Protection

[中文](README.md) | English

A **read-only Windows & macOS native desktop diagnostic tool** built with [Native Shell (NSH)](https://github.com/longbridge/nsh) (pure Rust) for auditing AI network routing, leak risks, IP purity, OS environment fingerprints, and local AI CLI configurations — with built-in **Chinese & English** bilingual support.

- **Windows**: Native Win32 + Direct2D + DirectWrite (~15 MB single binary, zero Electron / WebView2 / Node dependencies)
- **macOS**: Native AppKit + Core Animation + CoreText (build `.app` locally on macOS or automatically via the included GitHub Actions workflow)
- **Apple HIG Aesthetic**: Monochrome minimalist Apple Squircle shield icon, macOS-style sidebar navigation with master-detail inspector, adaptive Light/Dark theme, native NSH spring/fade/pulse animations, smooth sliding capsule `中 / EN` language switch, and one-click **Hide IP** privacy mode.

> **100% Read-Only & Manual Start by Design**: Never modifies system DNS, network adapters, routes, OS timezone, fonts, or firewall rules. Launches in an idle ready state (no unwanted background traffic on startup) until you manually start a scan. Works out of the box on Wi-Fi soft-routers, local TUN clients, system/env proxies, or direct connections.

---

## Core Diagnostic Capabilities

### 1. Exit IP, Zero-Key Multi-Source IP Purity, DNSBL & Four Leak Checks
- **Exit IP Consistency & Dedicated IP Check**: Concurrent probing across 3 neutral Cloudflare trace endpoints with serial retry on failure to detect IP hopping or split routing.
- **Zero-Key Standalone Exit IP Purity Engine (0–100, higher is cleaner; baseline 92 + up to +8 positive evidence bonus)**:
  - Strictly decoupled from the OS fingerprint risk score (never merged or averaged); withholds numeric score if all sources are unreachable (**never fabricates a fake 100**).
  - **13 Built-In Zero-Key Risk Sources + 8-Source Geo Consensus + Whole-ASN Cross-Check**:
    - **IP Intelligence DBs (9 zero-key)**: `proxycheck.io` (auto-uses 100/day free tier when no key is set; accepts optional key for higher quota), `ipapi.is`, `ipquery.io`, `blackbox-v3`, `ip-api.com` (fallback `techniknews`), `net.coffee`, `iplocate.io`, `geoiplookup.io`, `freeipapi.com`.
    - **Multi-Source Geo Consensus (8)**: Concurrently polls `ipinfo.io`, `ipwho.is`, `IP.SB`, `DB-IP`, `GeoJS`, `ipapi.co`, `iplocation.net`, and `GeoLite2 (RIPEstat)` to detect country geo-splits.
    - **Threats & Scanning (4)**: Shodan `InternetDB` (open ports, proxy/cloud tags, CVEs), `StopForumSpam`, `Tor Onionoo` (consensus relays/bridges), `AlienVault OTX` (threat pulses).
    - **Registration & Routing**: `ip.guide` (live BGP announcing ASN/prefix/RIR to resolve stale DB ASNs), `PeeringDB` (network type & traffic ratio), `RIPEstat` (announced IPv4 space + RPKI/Native check), `RDAP` (ASN registration age), and DoH reverse `PTR` lookup.
  - **16 Public DoH DNSBL Zones**: Concurrent Cloudflare/Google DoH queries across SpamCop, Barracuda, PSBL, Mailspike, UCEPROTECT L1, GBUdb Truncate, NordSpam, JustSpam, SpamEatingMonkey, SPFBL, 0spam, InterServer, blocklist.de, S5H, DroneBL (with proxy code decoding), and dan.me.uk Tor exits.
  - **17 Public CIDR Threat/Proxy/Datacenter Lists + Whole-ASN Abuse Density (enabled by default, 12h in-memory cache)**: FireHOL L1/L2/L3, blocklist.de, GreenSnow, IPsum, ET Compromised, CINS Army, DShield, CyberCrime C&C, StopForumSpam 7d, BotScout 7d, public SOCKS/HTTPS proxies, Tor exits, and X4BNet DC/VPN — scoring exact hits, `/24` contaminated neighbors, and **whole-ASN abuse density vs. the global 3B routed IPv4 baseline**.
  - **Optional Commercial Key Extensions (8)**: Optionally configure `PROXYCHECK_API_KEY`, `ABUSEIPDB_API_KEY`, `CF_RADAR_TOKEN`, `GREYNOISE_API_KEY`, `CROWDSEC_API_KEY`, `VIRUSTOTAL_API_KEY`, `IPREGISTRY_API_KEY`, or `IPDATA_API_KEY` in Settings or env vars.
- **Native vs. Broadcast IP & RPKI Validation**: Standard RIPEstat RIR country vs. observed geo comparison and RPKI ROA route validation.
- **DNS & EDNS Client Subnet (ECS) Leak Detection**: Three-layer audit adapted for soft-routers & TUN clients (physical NIC DNS + direct UDP:53 Fake-IP probe + `whoami.ds.akahelp.net` + `edns.ip-api.com` ECS leak probe + domestic split-routing awareness).
- **IPv6 Leak / WebRTC (STUN) Leak / Long-Connection Stability / Captive Portal Preflight**.
- **Inspect Any Public IP & Hide-IP Privacy Mode**: Enter any public IPv4/IPv6 in the top bar (or `--target-ip`) to inspect candidate nodes directly; toggle **Hide IP** (or `--hide-ip`) to mask all public IPs across the UI and copied JSON reports.

### 2. Credential-Free AI Service Probing (OpenAI / Anthropic / Google)
- `chatgpt.com/cdn-cgi/trace` + `api.openai.com/v1/models`
- `claude.ai/cdn-cgi/trace` + `api.anthropic.com/v1/models`
- `gemini.google.com` + `aistudio.google.com` + `generativelanguage.googleapis.com`
- Zero account credentials sent and zero tokens spent (supports strict `--neutral-only` mode).

### 3. OS Fingerprint Risk, Relay Audit & Local AI CLI Diagnostics
- **OS Environment Fingerprint Risk Score (0–100, lower is cleaner; Low `0–30` / Medium `31–60` / High `61–100`)**:
  - Read-only OS-level scan across 7 weighted signals: system timezone (respects `TZ` override; explicitly exempts `Asia/Taipei`), OS locale (explicitly exempts `zh-TW`), installed CJK fonts, high-specificity regional vendor/office fonts (`MiSans`, `HarmonyOS Sans`, `OPPO Sans`, `Alibaba PuHuiTi`, Founder `FZ*`, etc.), installed regional browsers, hardware OEM signature, and UTC+8 offset.
- **Claude Code Custom Relay & Steganography Risk Audit**:
  - Audits effective `ANTHROPIC_BASE_URL` for `.cn` TLDs or flagged provider keywords, cross-checked against restricted OS timezones, `TZ` override, and `_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL`.
- **Local AI CLI & Environment Consistency**:
  - Cross-platform `.claude` discovery, `settings.json` / `settings_*.json` validation, provider detection, and masked secret display.
  - Shell env vs. `settings.json` consistency validation (overrides, missing vars, stale `ANTHROPIC_*` keys).
  - Extended checks for `~/.claude.json`, `~/.codex`, `~/.gemini`, `OPENAI_*`, `GEMINI_*`, proxy env conflicts (`HTTP_PROXY` / `NO_PROXY` / dead ports / multi-TUN), and read-only timezone/locale alignment.
  - Opt-in non-billing `GET /v1/models` connectivity test (`--api-test` or `+ API Test`).

### 4. Optional Soft-Router / Clash / Mihomo Controller Inspection
- Enter your LAN soft-router or localhost controller URL (e.g., `http://192.168.1.1:9090`) in Settings to audit core mode, STUN blocking rules, fail-closed Kill Switch fallback groups, and live AI connection chains.

---

## Build & Run

### Windows (Local Build)
```powershell
# Build compact Release binary (embeds assets/icon.ico automatically)
cargo +stable-x86_64-pc-windows-gnu build --release
# (Or simply `cargo build --release` if MSVC Build Tools are installed)

# Launch native desktop app
.\target\release\AI-Network-Protection.exe

# Non-interactive CLI / JSON mode (supports --lang en / --lang zh)
.\target\release\AI-Network-Protection.exe --cli --quick --lang en
.\target\release\AI-Network-Protection.exe --json --quick --lang en
```

### macOS (Build Locally on macOS)
```bash
# Option A: Build & run native AppKit binary via Cargo
cargo build --release
./target/release/AI-Network-Protection

# Option B: Package native .app bundle via NSH CLI (uses assets/icon.png from nsh.json)
nsh package --target macos
```

### Automated Cross-Platform CI (GitHub Actions)
The included [.github/workflows/release.yml](.github/workflows/release.yml) builds both platforms automatically on `v*` tags or manual `workflow_dispatch`:
- `AI-Network-Protection-windows-x64` (`AI-Network-Protection.exe`)
- `AI-Network-Protection-macos-arm64` (`AI-Network-Protection.app` zipped with Apple `.icns` icon)

---

## Optional Environment Variables & CLI Flags
| Env Var | CLI Flag | Description |
| --- | --- | --- |
| `ANP_LANG` | `--lang <zh\|en>` | UI & CLI output language (auto-detects OS locale by default) |
| `ANP_EXPECTED_IP` | `--expected-ip <IP>` | Expected dedicated exit IP address |
| `ANP_EXPECTED_COUNTRY` | `--expected-country <CC>` | Expected exit country ISO-2 code (e.g. `US`, `JP`, `SG`) |
| `PROXYCHECK_API_KEY` | `--proxycheck-key <KEY>` | Optional proxycheck.io API key for deeper IP purity scoring |
| `ABUSEIPDB_API_KEY` | `--abuseipdb-key <KEY>` | Optional AbuseIPDB API key for deeper IP purity scoring |
| `CF_RADAR_TOKEN` | `--cf-radar-token <TOK>` | Optional Cloudflare Radar token (28-day ASN bot traffic ratio) |
| — | `--no-cidr-lists` | Optional: skip downloading 17 CIDR threat/DC lists (enabled by default) |
| — | `--target-ip <IP>` | Optional: inspect an arbitrary public IPv4/IPv6 only |
| — | `--hide-ip` | Privacy mode: mask all public IPs in CLI / JSON output |
| `ANP_CONTROLLER_URL` | `--controller <URL>` | Optional soft-router / Clash / Mihomo External Controller URL |
| `ANP_CTRL_SECRET` | `--controller-secret <SEC>` | Optional Controller Bearer secret |

## Keyboard Shortcuts
- `F5`: Full Scan (30s keep-alive window)
- `Ctrl+R` / `Cmd+R`: Quick Scan (8s keep-alive window)
- `Ctrl+T` / `Cmd+T`: Quick Scan + Opt-in API Test
- `Ctrl+1` – `Ctrl+6` / `Cmd+1` – `Cmd+6`: Switch sidebar categories & Settings
- Bottom-left `EN` / `中文` pill in sidebar: Instant language toggle
