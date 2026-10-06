//! macOS collectors: `defaults` preferences, HIToolbox input sources,
//! /Applications scan, scutil DNS/hostname, ioreg identifiers.

use std::collections::BTreeSet;
use std::fs;

use crate::finding::{Category, Finding};
use crate::local::zh_locale;
use crate::net::{CN_DNS, GLOBAL_DNS};
use crate::util::*;

pub fn collect(v: &mut Vec<Finding>) {
    system(v);
    locale(v);
    input_sources(v);
    fonts(v);
    applications(v);
    dns(v);
    wifi(v);
}

// ---------------------------------------------------------------- system

fn system(v: &mut Vec<Finding>) {
    if let Some(ver) = run("sw_vers", &[]) {
        let pretty = ver
            .lines()
            .filter(|l| l.starts_with("ProductName:") || l.starts_with("ProductVersion:"))
            .filter_map(|l| l.split(':').nth(1).map(|s| s.trim().to_string()))
            .collect::<Vec<_>>()
            .join(" ");
        if !pretty.is_empty() {
            v.push(Finding::fact(Category::System, "os release", pretty));
        }
    }

    for (name, key) in [
        ("cpu model", "machdep.cpu.brand_string"),
        ("machine", "hw.model"),
    ] {
        if let Some(val) = run("sysctl", &["-n", key]) {
            v.push(Finding::fact(Category::System, name, val));
        }
    }

    // Hardware identifiers — the IOPlatform UUID plays the machine-id role.
    if let Some(ioreg) = run("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]) {
        for line in ioreg.lines() {
            for key in ["IOPlatformUUID", "IOPlatformSerialNumber"] {
                if line.contains(key) {
                    if let Some(val) = line.split('=').nth(1).map(|s| s.trim().trim_matches('"')) {
                        let shown = if val.len() > 12 {
                            format!("{}… (truncated)", &val[..12])
                        } else {
                            val.to_string()
                        };
                        v.push(Finding::fact(Category::System, key, shown));
                    }
                }
            }
        }
    }

    if let Some(h) = run("scutil", &["--get", "LocalHostName"])
        .or_else(|| run("scutil", &["--get", "ComputerName"]))
    {
        if has_han(&h) {
            v.push(Finding::signal(
                Category::System,
                "computer name",
                h,
                5.0,
                false,
                "computer name contains Han characters",
            ));
        } else {
            v.push(Finding::fact(Category::System, "computer name", h));
        }
    }

    // MACs via ifconfig.
    let mut macs = Vec::new();
    for iface in ["en0", "en1", "en2"] {
        if let Some(out) = run("ifconfig", &[iface]) {
            for line in out.lines() {
                let t = line.trim();
                if let Some(mac) = t.strip_prefix("ether ") {
                    macs.push(format!("{iface}={}", mac.trim()));
                }
            }
        }
    }
    if !macs.is_empty() {
        v.push(Finding::fact(
            Category::System,
            "mac addresses",
            macs.join("  "),
        ));
    }
}

// ---------------------------------------------------------------- locale

fn locale(v: &mut Vec<Finding>) {
    if let Some(l) = run("defaults", &["read", "-g", "AppleLocale"]) {
        match zh_locale(&l) {
            Some((lr, ml, note)) => v.push(Finding::signal(
                Category::Locale,
                "AppleLocale",
                l,
                lr,
                ml,
                note,
            )),
            None => v.push(Finding::fact(Category::Locale, "AppleLocale", l)),
        }
    }
    if let Some(langs) = run("defaults", &["read", "-g", "AppleLanguages"]) {
        let l = langs.to_lowercase();
        let (lr, ml, note) = if l.contains("zh-hans") || l.contains("zh-cn") {
            (
                12.0,
                true,
                "system language list prefers Simplified Chinese",
            )
        } else if l.contains("zh-hant") || l.contains("zh-tw") || l.contains("zh-hk") {
            (
                5.0,
                false,
                "system language list prefers Traditional Chinese",
            )
        } else if l.contains("zh") {
            (6.0, false, "a Chinese language is in the preferred list")
        } else {
            (1.0, false, "")
        };
        if lr > 1.0 {
            v.push(Finding::signal(
                Category::Locale,
                "AppleLanguages",
                truncate(&langs.replace('\n', " "), 90),
                lr,
                ml,
                note,
            ));
        } else {
            v.push(Finding::fact(
                Category::Locale,
                "AppleLanguages",
                truncate(&langs.replace('\n', " "), 90),
            ));
        }
    }
}

// ---------------------------------------------------------------- input

/// Input-method bundle IDs / names worth flagging. macOS ships Chinese IMEs
/// (SCIM = Simplified, TCIM = Traditional) but only enabled ones appear in
/// the HIToolbox plist, so presence there is a real signal.
fn input_sources(v: &mut Vec<Finding>) {
    let plist = run(
        "defaults",
        &["read", "com.apple.HIToolbox", "AppleEnabledInputSources"],
    )
    .or_else(|| {
        run(
            "defaults",
            &["read", "com.apple.HIToolbox", "AppleSelectedInputSources"],
        )
    });
    if let Some(p) = plist {
        let l = p.to_lowercase();
        let (lr, ml, note) =
            if contains_any(&l, &["sogou", "baidu", "qq", "讯飞", "ifly"]).is_some() {
                (15.0, true, "third-party Chinese IME enabled")
            } else if l.contains("squirrel") || l.contains("rime") {
                (6.0, false, "Rime/Squirrel IME enabled")
            } else if contains_any(&l, &["scim", "itabc"]).is_some() {
                (10.0, true, "built-in Simplified Chinese input enabled")
            } else if contains_any(&l, &["tcim", "zhuyin", "bopomofo", "cangjie"]).is_some() {
                (5.0, false, "built-in Traditional Chinese input enabled")
            } else {
                (1.0, false, "")
            };
        if lr > 1.0 {
            v.push(Finding::signal(
                Category::Input,
                "macos input sources",
                "(HIToolbox enabled list)",
                lr,
                ml,
                note,
            ));
        }
    }

    // Third-party IME .app bundles installed.
    let mut found = Vec::new();
    for dir in ["~/Library/Input Methods", "/Library/Input Methods"] {
        let d = dir.replace('~', &home().to_string_lossy());
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if contains_any(
                    &n,
                    &[
                        "sogou", "baidu", "qq", "squirrel", "rime", "ifly", "讯飞", "搜狗", "百度",
                    ],
                )
                .is_some()
                {
                    found.push(n);
                }
            }
        }
    }
    if !found.is_empty() {
        v.push(Finding::signal(
            Category::Input,
            "3rd-party IMEs",
            found.join(", "),
            14.0,
            true,
            "third-party Chinese IME bundle installed",
        ));
    }
}

// ---------------------------------------------------------------- fonts

fn fonts(v: &mut Vec<Finding>) {
    // macOS ships PingFang SC/TC, Songti, STHeiti etc. to every user, so
    // CJK fonts alone prove nothing here. Only *additionally installed*
    // Chinese fonts in user/system dirs hint at a Chinese-speaking user.
    let mut extra = Vec::new();
    for dir in ["~/Library/Fonts", "/Library/Fonts"] {
        let d = dir.replace('~', &home().to_string_lossy());
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if contains_any(
                    &n,
                    &[
                        "yahei",
                        "simsun",
                        "simhei",
                        "simkai",
                        "fangsong",
                        "仿宋",
                        "宋体",
                        "黑体",
                        "wenquanyi",
                        "文泉驿",
                        "sarasa",
                        "苹方",
                        "zpix",
                        "han sans sc",
                        "han serif sc",
                        "noto sans sc",
                        "noto serif sc",
                        "sourcehan",
                    ],
                )
                .is_some()
                {
                    extra.push(n);
                }
            }
        }
    }
    if extra.is_empty() {
        v.push(Finding::fact(
            Category::Fonts,
            "3rd-party zh fonts",
            "none (stock macOS fonts ignored)",
        ));
    } else {
        v.push(Finding::signal(
            Category::Fonts,
            "3rd-party zh fonts",
            truncate(&extra.join(", "), 90),
            4.0,
            true,
            "user installed extra Simplified-Chinese fonts",
        ));
    }
}

// ---------------------------------------------------------------- software

fn applications(v: &mut Vec<Finding>) {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let kw = [
        "wechat",
        "微信",
        "qq",
        "tencent",
        "腾讯",
        "dingtalk",
        "钉钉",
        "wps",
        "netease",
        "网易",
        "baidu",
        "百度",
        "sogou",
        "搜狗",
        "thunder",
        "迅雷",
        "youdao",
        "有道",
        "foxmail",
        "feishu",
        "飞书",
        "wemeet",
        "企业微信",
        "qqmusic",
        "kugou",
        "kuwo",
        "iqiyi",
        "爱奇艺",
        "youku",
        "优酷",
        "bilibili",
        "哔哩",
        "alipay",
        "支付宝",
        "taobao",
        "淘宝",
        "xunlei",
        "clash",
        "v2ray",
        "shadowrocket",
        "sing-box",
    ];
    for dir in [
        "/Applications".to_string(),
        format!("{}/Applications", home().display()),
    ] {
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if contains_any(&n, &kw).is_some() {
                    found.insert(n.trim_end_matches(".app").to_string());
                }
            }
        }
    }
    if found.is_empty() {
        v.push(Finding::fact(
            Category::Software,
            "cn software markers",
            "none found",
        ));
    } else {
        let items: Vec<String> = found.iter().take(15).cloned().collect();
        v.push(Finding::signal(
            Category::Software,
            "cn software markers",
            format!(
                "{} hit(s): {}",
                found.len(),
                truncate(&items.join(", "), 110)
            ),
            12.0,
            true,
            "Chinese software installed",
        ));
    }
}

// ---------------------------------------------------------------- dns & wifi

fn dns(v: &mut Vec<Finding>) {
    let Some(out) = run("scutil", &["--dns"]) else {
        return;
    };
    let servers: Vec<String> = out
        .lines()
        .filter(|l| l.trim().starts_with("nameserver["))
        .filter_map(|l| l.split(':').nth(1).map(|s| s.trim().to_string()))
        .collect();
    let servers: BTreeSet<String> = servers.into_iter().collect();
    if servers.is_empty() {
        return;
    }
    let joined = servers.iter().cloned().collect::<Vec<_>>().join(", ");
    if servers.iter().any(|s| CN_DNS.contains(&s.as_str())) {
        v.push(Finding::signal(
            Category::Network,
            "dns resolvers",
            joined,
            8.0,
            true,
            "a mainland Chinese public DNS is configured",
        ));
    } else if servers.iter().any(|s| GLOBAL_DNS.contains(&s.as_str())) {
        v.push(Finding::signal(
            Category::Network,
            "dns resolvers",
            joined,
            0.7,
            false,
            "global public DNS (mild evidence against CN)",
        ));
    } else {
        v.push(Finding::fact(Category::Network, "dns resolvers", joined));
    }
}

fn wifi(v: &mut Vec<Finding>) {
    for iface in ["en0", "en1"] {
        let Some(out) = run("ipconfig", &["getsummary", iface]) else {
            continue;
        };
        let Some(line) = out.lines().find(|l| l.trim_start().starts_with("SSID")) else {
            continue;
        };
        let Some(ssid) = line.split(':').nth(1).map(|s| s.trim().to_string()) else {
            continue;
        };
        if ssid.is_empty() {
            continue;
        }
        let l = ssid.to_lowercase();
        if has_han(&ssid) {
            v.push(Finding::signal(
                Category::Identity,
                "wifi ssid",
                ssid,
                6.0,
                false,
                "SSID contains Han characters",
            ));
        } else if l.starts_with("chinanet") || l.starts_with("cmcc") || l.starts_with("chinaunicom")
        {
            v.push(Finding::signal(
                Category::Identity,
                "wifi ssid",
                ssid,
                6.0,
                true,
                "Chinese carrier hotspot SSID",
            ));
        } else {
            v.push(Finding::fact(Category::Identity, "wifi ssid", ssid));
        }
        return;
    }
}
