# AI-Network-Protection

中文 | [English](README.en.md)

基于 [Native Shell (NSH)](https://github.com/longbridge/nsh)（纯 Rust 原生桌面框架）构建的 **Windows & macOS 双端只读 AI 网络防风控与本地环境体检工具**，内置 **中英双语** 界面与终端输出。

- **Windows 端**：原生 Win32 + Direct2D + DirectWrite（单文件 ~15 MB，零 Electron / WebView2 / Node 依赖）
- **macOS 端**：原生 AppKit + Core Animation + CoreText（支持在 Mac 上本地构建 `.app`，或通过内置 GitHub Actions 云端自动打包）
- **设计风格**：Apple HIG 极简分层风格（黑白极简线条 Apple Squircle 盾牌图标、macOS 侧边栏导航 + 主从分栏检视器、自适应浅色/深色主题、NSH 原生弹簧按压与渐入/脉冲动画、侧边栏平滑滑动胶囊 `中 / EN` 切换开关、工具栏一键「隐藏 IP」隐私模式）

> **设计原则**：100% 只读诊断，**不修改**任何系统 DNS、网卡、路由、时区、字体或防火墙规则；应用启动后处于待命状态，**由用户手动触发检测**；开箱即适配 WiFi 软路由透明代理、本机 TUN 客户端、系统/环境变量代理与直连网络。

---

## 核心检查能力

### 1. 网络出口、零 Key 多源 IP 纯净度、黑名单与四类泄漏检测
- **出口 IP 一致性与独享核对**：Cloudflare 3 个中立端点并发探测 + 串行防拥塞重试，核对是否存在频繁跳 IP 或分流不一致。
- **零 Key 开箱即用 IP 纯净度评分引擎（0–100，高分更优，基准分 92 + 最高 +8 正向实证加分）**：
  - 与本机环境指纹风险分严格独立计算，绝不混算；所有情报源均不可达时留空分数，**绝不虚构满分**。
  - **13 个零 Key 风控源 + 8 源地理共识 + ASN 交叉评分全覆盖**：
    - **IP 情报库（9 个零 Key 源）**：`proxycheck.io`（免 Key 自动走 100 次/天免费额度，支持填 Key 扩容）、`ipapi.is`、`ipquery.io`、`blackbox-v3`、`ip-api.com`（降级 `techniknews`）、`net.coffee`、`iplocate.io`、`geoiplookup.io`、`freeipapi.com`。
    - **多源地理共识（8 源）**：并发聚合 `ipinfo.io`、`ipwho.is`、`IP.SB`、`DB-IP`、`GeoJS`、`ipapi.co`、`iplocation.net`、`GeoLite2 (RIPEstat)`，自动检测出口国家定位分歧。
    - **威胁与扫描（4 源）**：Shodan `InternetDB`（开放端口/代理标签/CVE）、`StopForumSpam`、`Tor Onionoo`（官方共识节点）、`AlienVault OTX`（威胁 Pulse）。
    - **注册与路由画像**：`ip.guide`（实时 BGP 宣告 ASN/前缀/RIR，修正旧库 ASN 漂移）、`PeeringDB`（网络类型与流量比）、`RIPEstat`（整 ASN 宣告 IPv4 空间与 RPKI/原生校验）、`RDAP`（ASN 注册年份与年龄）、DoH 反向 `PTR` 查询。
  - **16 份公开 DNSBL 黑名单实时扫描（原生 DoH）**：通过 Cloudflare / Google DoH 并发反查 SpamCop、Barracuda、PSBL、Mailspike、UCEPROTECT L1、GBUdb Truncate、NordSpam、JustSpam、SpamEatingMonkey、SPFBL、0spam、InterServer、blocklist.de、S5H、DroneBL（含代理特征码）与 dan.me.uk Tor 出口。
  - **17 份公开 CIDR 威胁/代理/机房列表 + 整 ASN 滥用密度（默认开启，内存缓存 12h）**：涵盖 FireHOL L1/L2/L3、blocklist.de、GreenSnow、IPsum、ET Compromised、CINS Army、DShield、CyberCrime C&C、StopForumSpam 7d、BotScout 7d、公开 SOCKS/HTTPS 代理、Tor 出口、X4BNet 机房/VPN 段，同时计算 `/24` 受污染邻居与**整 ASN 威胁密度（相对全球 30 亿路由 IPv4 基线的倍率）**。
  - **可选商业 Key 扩展（8 个）**：在「设置」页或环境变量选填 `PROXYCHECK_API_KEY`、`ABUSEIPDB_API_KEY`、`CF_RADAR_TOKEN`、`GREYNOISE_API_KEY`、`CROWDSEC_API_KEY`、`VIRUSTOTAL_API_KEY`、`IPREGISTRY_API_KEY`、`IPDATA_API_KEY`。
- **原生 IP vs 广播 IP & RPKI 路由验证**：经 RIPEstat 校验 RIR 注册国与实际落地区一致性，以及 BGP 路由宣告 RPKI ROA 状态。
- **DNS 与 EDNS 客户端子网（ECS）泄漏检测**：三层软路由/TUN 适配（物理网卡 DNS 审计 + UDP 53 Fake-IP/劫持探测 + `whoami.ds.akahelp.net` 权威解析出口 + `edns.ip-api.com` EDNS 子网透传检测 + 国内站点分流识别）。
- **IPv6 防泄漏 / WebRTC (STUN) 防泄漏 / 长连接稳定性 / Captive Portal 门户认证检测**。
- **任意公网 IP 独立体检 & 一键隐私打码**：顶部支持直接输入任意公网 IPv4/IPv6 独立体检纯净度、DNSBL 与原生/RPKI；工具栏支持一键「隐藏 IP」，界面展示与导出的 JSON 自动打码所有公网 IP。

### 2. 主流 AI 服务分层无账号探测（OpenAI / Anthropic / Google）
- `chatgpt.com/cdn-cgi/trace` + `api.openai.com/v1/models`
- `claude.ai/cdn-cgi/trace` + `api.anthropic.com/v1/models`
- `gemini.google.com` + `aistudio.google.com` + `generativelanguage.googleapis.com`
- 全程不携带登录态、不消耗 Token（支持保守模式 `--neutral-only`）。

### 3. 本机环境指纹、配置与非网络防风控审计
- **本机环境指纹风险评分（0–100，低分更优，低 `0–30` / 中 `31–60` / 高 `61–100`）**：
  - 操作系统级只读采集 7 维信号：系统时区（含 `TZ` 覆盖判定，明确豁免 `Asia/Taipei`）、系统语言/Locale（明确豁免 `zh-TW`）、已安装中文字体、高特征国产厂商/软件字体（`MiSans` / `HarmonyOS Sans` / `OPPO Sans` / `Alibaba PuHuiTi` / 方正 `FZ*` 等）、区域浏览器安装痕迹、硬件 OEM 标识与 UTC+8 偏移。
- **Claude Code 自定义中转与隐写风险审计**：
  - 审计生效的 `ANTHROPIC_BASE_URL` 域名是否命中 `.cn` 或敏感中转关键词，联动检查系统时区、`TZ` 覆盖与 `_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL` 防护状态。
- **本地 AI CLI 配置与环境变量冲突检查**：
  - `.claude` 目录跨平台发现、`settings.json` / `settings_*.json` 校验与 Provider 识别、Token 脱敏。
  - Shell 环境变量与 `settings.json` 一致性比对（覆盖冲突 / 缺失 / 残留 `ANTHROPIC_*`）。
  - `~/.claude.json`、`~/.codex`、`~/.gemini`、`OPENAI_*`、`GEMINI_*` 与代理环境变量（`HTTP_PROXY` / `NO_PROXY` / 死端口 / 多 TUN）冲突检查。
  - 本机时区 & 系统 Locale 与出口 IP 时区一致性只读对比。
  - 按需手动触发的只读 API 连通性测试（`GET /v1/models`，不扣费）。

### 4. 可选软路由 / Clash / Mihomo 控制 API 检查
- 在侧边栏「设置」中填入软路由 LAN 或本机控制器地址（如 `http://192.168.1.1:9090`），即可核验内核模式、STUN 阻断规则、断网保护（Kill Switch）与实时 AI 连接链。

---

## 构建与运行

### Windows（本地构建）
```powershell
# 构建轻量 Release 单文件（已内嵌 assets/icon.ico 桌面图标）
cargo +stable-x86_64-pc-windows-gnu build --release
# （若已安装 Visual Studio C++ Build Tools，直接 `cargo build --release` 即可）

# 双击运行桌面端，或命令行启动
.\target\release\AI-Network-Protection.exe

# 命令行 / JSON 单次体检模式（支持 --lang zh / --lang en）
.\target\release\AI-Network-Protection.exe --cli --quick
.\target\release\AI-Network-Protection.exe --cli --quick --lang en
.\target\release\AI-Network-Protection.exe --json --quick
```

### macOS（在 Mac 上本地构建）
```bash
# 方式 A：使用 Cargo 直接构建/运行原生 AppKit 应用
cargo build --release
./target/release/AI-Network-Protection

# 方式 B：使用 NSH CLI 打包原生 .app（自动使用 nsh.json 中的 assets/icon.png）
nsh package --target macos
```

### 双端自动构建（GitHub Actions）
仓库内置 [.github/workflows/release.yml](.github/workflows/release.yml)：推送 `v*` 标签或在 GitHub Actions 手动触发 `workflow_dispatch`，即可在云端同时产出：
- `AI-Network-Protection-windows-x64`（`AI-Network-Protection.exe`）
- `AI-Network-Protection-macos-arm64`（带 Apple `.icns` 图标的 `AI-Network-Protection.app` 压缩包）

---

## 可选环境变量与 CLI 参数
| 环境变量 | CLI 参数 | 说明 |
| --- | --- | --- |
| `ANP_LANG` | `--lang <zh\|en>` | 指定界面与报告语言（默认跟随系统语言） |
| `ANP_EXPECTED_IP` | `--expected-ip <IP>` | 预期独享出口 IP |
| `ANP_EXPECTED_COUNTRY` | `--expected-country <CC>` | 预期出口国家代码（ISO-2，如 `US`/`JP`/`SG`） |
| `PROXYCHECK_API_KEY` | `--proxycheck-key <KEY>` | 可选：proxycheck.io API Key（增强 IP 纯净度评分） |
| `ABUSEIPDB_API_KEY` | `--abuseipdb-key <KEY>` | 可选：AbuseIPDB API Key（增强 IP 纯净度评分） |
| `CF_RADAR_TOKEN` | `--cf-radar-token <TOK>` | 可选：Cloudflare Radar API Token（ASN 28天 Bot 流量占比） |
| — | `--no-cidr-lists` | 可选：跳过 17 份公开 CIDR 威胁/机房列表下载（轻量模式，默认已开启） |
| — | `--target-ip <IP>` | 可选：仅对指定公网 IPv4/IPv6 运行独立纯净度、DNSBL 与原生/RPKI 检查 |
| — | `--hide-ip` | 隐私模式：对 CLI / JSON 输出中的所有公网 IP 自动打码 |
| `ANP_CONTROLLER_URL` | `--controller <URL>` | 可选：软路由 / Clash / Mihomo External Controller 地址 |
| `ANP_CTRL_SECRET` | `--controller-secret <SEC>` | 可选：Controller Bearer Secret |

## 桌面快捷键
- `F5`：执行完整体检（30s 长连接）
- `Ctrl+R` / `Cmd+R`：执行快速体检（8s 长连接）
- `Ctrl+T` / `Cmd+T`：执行体检 + 手动 API 连通性测试
- `Ctrl+1` ~ `Ctrl+6` / `Cmd+1` ~ `Cmd+6`：切换侧边栏分类与设置页
- 侧边栏左下角 `EN` / `中文` 按钮：即时切换应用语言
