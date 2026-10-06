# origin-probe

A small Linux CLI that collects signals from the current device and reports
the estimated probability that its user is Chinese — with an itemized
evidence table so you can see *why*.

> [!IMPORTANT]
> **Consent is mandatory.** The tool prints a full list of everything it will
> inspect and refuses to run until you type `yes`. Nothing is written to disk;
> the only outbound traffic is the read-only IP-geolocation queries listed
> below.

## Usage

```sh
cargo build --release
./target/release/origin-probe            # consent prompt, then full scan
./target/release/origin-probe --offline  # skip all network checks
./target/release/origin-probe --json     # machine-readable report on stdout
```

## What it collects

| Area | Signals |
|---|---|
| System & hardware | os-release (incl. Chinese distros: deepin/UOS/Kylin/Anolis/…), kernel, arch (LoongArch), CPU (Loongson/Hygon/Phytium/Zhaoxin), DMI vendor, hostname, username, machine-id (truncated), MAC addresses |
| Locale & timezone | `LANG`/`LC_*`/`LANGUAGE`, `locale.conf`, generated locales, timezone zone name, UTC offset |
| Input | `GTK_IM_MODULE`/`QT_IM_MODULE`/`XMODIFIERS`, fcitx/ibus/sogou/rime processes, IME config dirs & packages, X11 keymap |
| Fonts | `fc-list :lang=zh` — SC vs TC/HK variants |
| Software | markers of Chinese software in PATH, `/opt/apps`, flatpak, snap, `.desktop` entries, dpkg |
| Mirrors | apt/pip/npm/cargo/docker/maven/go/conda configs pointing at tuna/aliyun/ustc/tencent/… |
| Identity | git `user.name`/`user.email` (Han chars, CN mail providers), count of shell-history lines containing Han characters (content is never printed), Chinese XDG dir names (~/桌面, ~/下载…), WiFi SSID, browser `Accept-Language` (Chrome/Chromium/Edge/Brave/Firefox) |
| Network | DNS resolvers (114.114.114.114, AliDNS, DNSPod, …), TCP:443 reachability matrix that detects a GFW-style signature (Google/YouTube/Facebook/Wikipedia unreachable while Baidu/QQ answer), public-IP geolocation + ISP via ip-api.com / ipapi.co / ipinfo.io |

## How scoring works

Each observation is a likelihood ratio (`>1` supports "user is Chinese", `<1`
counts against). Log-odds are summed from a neutral 50% prior, and each
category's total contribution is capped at ×25 so that many correlated weak
signals in one area can't dominate. Evidence flagged `mainland` additionally
distinguishes mainland-China-specific signals from the broader
Chinese-speaking world (TW/HK/SG/diaspora).

This is a heuristic, not identification — locale, timezone and software are
user-configurable, and IP geolocation reflects the egress point rather than
the person.

## Layout

```
src/main.rs    consent flow, report rendering, --json/--offline flags
src/finding.rs Finding { category, observed, lr, mainland } model
src/local.rs   all on-device collectors
src/net.rs     DNS table, TCP reachability matrix, IP geolocation
src/score.rs   log-odds combination + verdict bands
```

`cargo test` covers the scoring math and the zh locale/accept-language
classifiers.

## License

MIT — see [LICENSE](LICENSE).
