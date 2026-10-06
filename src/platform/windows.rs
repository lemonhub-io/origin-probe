//! Windows collectors: `tzutil`, registry, PowerShell CIM/cmdlets (forced
//! UTF-8 so CJK survives), Fonts dir, Program Files / uninstall-registry
//! software scan, netsh SSID (byte-level check because console output is in
//! the OEM codepage, GBK on zh-CN systems).

use std::collections::BTreeSet;
use std::env;
use std::fs;

use crate::finding::{Category, Finding};
use crate::local::zh_locale;
use crate::net::{CN_DNS, GLOBAL_DNS};
use crate::util::*;

pub fn collect(v: &mut Vec<Finding>) {
    system(v);
    locale(v);
    timezone(v);
    language_list(v);
    fonts(v);
    software(v);
    dns(v);
    wifi(v);
}

/// tzutil zone id -> evidence. Pure function so it is unit-testable.
fn zh_win_tz(id: &str) -> Option<(f64, bool, &'static str)> {
    match id {
        "China Standard Time" => Some((12.0, true, "PRC system timezone")),
        "Taipei Standard Time" | "Hong Kong Standard Time" => {
            Some((4.0, false, "TW/HK system timezone"))
        }
        _ => None,
    }
}

fn zh_lang_tag(tag: &str) -> Option<(f64, bool, &'static str)> {
    let l = tag.to_lowercase();
    if l.contains("zh-hans") || l.contains("zh-cn") || l.contains("zh-sg") {
        Some((
            10.0,
            true,
            "Simplified Chinese Windows display/input language",
        ))
    } else if l.contains("zh-hant")
        || l.contains("zh-tw")
        || l.contains("zh-hk")
        || l.contains("zh-mo")
    {
        Some((5.0, false, "Traditional Chinese Windows language"))
    } else if l.contains("zh") {
        Some((5.0, false, "Chinese Windows language"))
    } else {
        None
    }
}

// ---------------------------------------------------------------- system

fn system(v: &mut Vec<Finding>) {
    if let Some(cap) = powershell("(Get-CimInstance Win32_OperatingSystem).Caption") {
        if has_han(&cap) {
            v.push(Finding::signal(
                Category::System,
                "os release",
                cap,
                10.0,
                true,
                "Chinese-language Windows edition",
            ));
        } else {
            v.push(Finding::fact(Category::System, "os release", cap));
        }
    }
    if let Some(cs) = powershell("(Get-CimInstance Win32_ComputerSystem).Manufacturer, (Get-CimInstance Win32_ComputerSystem).Model") {
        let label = cs.replace('\n', " ").trim().to_string();
        if !label.is_empty() {
            let hit = contains_any(&label, &["huawei", "xiaomi", "hasee", "tongfang", "mechrevo", "honor", "greatwall", "matebook", "redmi"]);
            match hit {
                Some(h) => v.push(Finding::signal(Category::System, "oem vendor", label, 4.0, true, format!("Chinese hardware brand ('{h}')"))),
                None if label.to_lowercase().contains("lenovo") => v.push(Finding::signal(
                    Category::System, "oem vendor", label, 1.5, true, "Lenovo is a Chinese brand but common worldwide")),
                None => v.push(Finding::fact(Category::System, "oem vendor", label)),
            }
        }
    }

    // Identifiers.
    if let Some(g) = reg_query("HKLM\\SOFTWARE\\Microsoft\\Cryptography", "MachineGuid") {
        v.push(Finding::fact(
            Category::System,
            "machine guid",
            format!("{}… (truncated)", &g[..g.len().min(12)]),
        ));
    }
    for (name, expr) in [
        ("bios serial", "(Get-CimInstance Win32_BIOS).SerialNumber"),
        (
            "board uuid",
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
        ),
    ] {
        if let Some(val) = powershell(expr) {
            let val = val.trim().to_string();
            if !val.is_empty() {
                let shown = if val.len() > 16 {
                    format!("{}… (truncated)", &val[..16])
                } else {
                    val
                };
                v.push(Finding::fact(Category::System, name, shown));
            }
        }
    }

    for (label, var) in [("hostname", "COMPUTERNAME"), ("username", "USERNAME")] {
        if let Ok(val) = env::var(var) {
            if has_han(&val) {
                v.push(Finding::signal(
                    Category::System,
                    label,
                    val,
                    5.0,
                    false,
                    "contains Han characters",
                ));
            } else {
                v.push(Finding::fact(Category::System, label, val));
            }
        }
    }

    // MAC addresses.
    if let Some(macs) = powershell("(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.Name)=$($_.MacAddress)\" }) -join '  '") {
        if !macs.is_empty() {
            v.push(Finding::fact(Category::System, "mac addresses", macs));
        }
    }
}

// ---------------------------------------------------------------- locale

fn locale(v: &mut Vec<Finding>) {
    if let Some(loc) = reg_query("HKCU\\Control Panel\\International", "LocaleName") {
        match zh_locale(&loc).or_else(|| zh_lang_tag(&loc)) {
            Some((lr, ml, note)) => v.push(Finding::signal(
                Category::Locale,
                "LocaleName",
                loc,
                lr,
                ml,
                note,
            )),
            None => v.push(Finding::fact(Category::Locale, "LocaleName", loc)),
        }
    }
    if let Some(sl) = powershell("(Get-WinSystemLocale).Name") {
        match zh_lang_tag(&sl) {
            Some((lr, ml, note)) => v.push(Finding::signal(
                Category::Locale,
                "system locale",
                sl,
                lr,
                ml,
                note,
            )),
            None => v.push(Finding::fact(Category::Locale, "system locale", sl)),
        }
    }
    if let Some(cul) = powershell("(Get-Culture).Name") {
        v.push(Finding::fact(Category::Locale, "current culture", cul));
    }
}

fn timezone(v: &mut Vec<Finding>) {
    if let Some(tz) = run("tzutil", &["/g"]) {
        match zh_win_tz(&tz) {
            Some((lr, ml, note)) => v.push(Finding::signal(
                Category::Locale,
                "timezone",
                tz,
                lr,
                ml,
                note,
            )),
            None => v.push(Finding::fact(Category::Locale, "timezone", tz)),
        }
    }
}

// ---------------------------------------------------------------- language list / IME

fn language_list(v: &mut Vec<Finding>) {
    let Some(out) = powershell(
        "Get-WinUserLanguageList | ForEach-Object { \"$($_.LanguageTag) [$($_.InputMethodTips -join ',')]\" }",
    ) else { return };
    let mut langs = Vec::new();
    let mut tips = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        langs.push(line.to_string());
        if let Some(start) = line.find('[') {
            let t = &line[start..];
            if t.contains("0804:") {
                tips.push("0804:* (PRC input method tips)");
            }
        }
    }
    let zh: Vec<&String> = langs.iter().filter(|l| zh_lang_tag(l).is_some()).collect();
    let joined = langs.join(", ");
    if !zh.is_empty() {
        let any_cn = zh
            .iter()
            .any(|l| zh_lang_tag(l).map(|(_, ml, _)| ml).unwrap_or(false));
        v.push(Finding::signal(
            Category::Input,
            "win user language list",
            truncate(&joined, 90),
            if any_cn { 10.0 } else { 5.0 },
            any_cn,
            "Chinese language pack configured",
        ));
    } else if !joined.is_empty() {
        v.push(Finding::fact(
            Category::Input,
            "win user language list",
            truncate(&joined, 90),
        ));
    }
    if !tips.is_empty() {
        v.push(Finding::signal(
            Category::Input,
            "ime tips",
            tips.join(", "),
            8.0,
            true,
            "PRC keyboard/IME (locale id 0804) installed",
        ));
    }
}

// ---------------------------------------------------------------- fonts

fn fonts(v: &mut Vec<Finding>) {
    let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let mut found = Vec::new();
    let mut total = 0usize;
    if let Ok(rd) = fs::read_dir(format!("{windir}\\Fonts")) {
        for e in rd.flatten() {
            total += 1;
            let n = e.file_name().to_string_lossy().to_lowercase();
            if contains_any(
                &n,
                &[
                    "msyh", "simsun", "simhei", "simkai", "simfang", "dengxian", "fangsong",
                    "kaiti", "nsimsun", "stsong", "stxihei", "stheiti", "youyuan", "fz",
                ],
            )
            .is_some()
            {
                found.push(n);
            }
        }
    }
    if !found.is_empty() {
        v.push(Finding::signal(
            Category::Fonts,
            "system fonts",
            format!(
                "{} zh fonts of {total} ({}; …)",
                found.len(),
                truncate(&found.join(", "), 70)
            ),
            8.0,
            true,
            "msyh/simsun-class fonts ship only with Chinese Windows images",
        ));
    } else if total > 0 {
        v.push(Finding::fact(
            Category::Fonts,
            "system fonts",
            format!("{total} fonts, no zh-specific families"),
        ));
    }
}

// ---------------------------------------------------------------- software

fn software(v: &mut Vec<Finding>) {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let kw = [
        "tencent",
        "wechat",
        "weixin",
        "qq",
        "dingtalk",
        "wps",
        "netease",
        "baidu",
        "sogou",
        "thunder",
        "xunlei",
        "youdao",
        "feishu",
        "lark",
        "wecom",
        "wxwork",
        "腾讯",
        "微信",
        "钉钉",
        "百度",
        "网易",
        "搜狗",
        "迅雷",
        "有道",
        "飞书",
        "爱奇艺",
        "优酷",
        "哔哩",
        "bilibili",
        "支付宝",
        "alipay",
    ];
    let mut dirs = vec![];
    for var in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "LOCALAPPDATA",
        "ProgramData",
    ] {
        if let Ok(d) = env::var(var) {
            dirs.push(d.clone());
            if var == "LOCALAPPDATA" {
                dirs.push(format!("{d}\\Programs"));
            }
        }
    }
    for d in dirs {
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if contains_any(&n, &kw).is_some() || has_han(&n) {
                    found.insert(format!("{n} ({d})"));
                }
            }
        }
    }

    // Installed-programs DisplayName from the uninstall registry keys.
    if let Some(out) = powershell(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName }",
    ) {
        for line in out.lines() {
            let n = line.trim();
            if n.is_empty() {
                continue;
            }
            if has_han(n) || contains_any(n, &kw).is_some() {
                found.insert(format!("{n} (uninstall entry)"));
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
    let Some(out) = powershell(
        "(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses",
    ) else { return };
    let servers: BTreeSet<String> = out
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.parse::<std::net::Ipv4Addr>().is_ok())
        .collect();
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
    // Console output is in the OEM codepage (GBK on zh-CN), so decode is
    // lossy — detect a CJK SSID by the presence of non-ASCII bytes.
    let Some(bytes) = run_bytes("netsh", &["wlan", "show", "interfaces"]) else {
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        let t = line.trim_start();
        if !t.starts_with("SSID") || t.starts_with("SSID B") || t.starts_with("BSSID") {
            continue;
        }
        let Some(raw_name) = t.splitn(2, ':').nth(1) else {
            continue;
        };
        let name = raw_name.trim();
        if name.is_empty() {
            continue;
        }
        if has_nonascii(raw_name.as_bytes()) {
            v.push(Finding::signal(
                Category::Identity,
                "wifi ssid",
                "(non-ASCII bytes)",
                6.0,
                false,
                "SSID contains non-ASCII bytes (likely CJK)",
            ));
        } else {
            let l = name.to_lowercase();
            if l.starts_with("chinanet") || l.starts_with("cmcc") || l.starts_with("chinaunicom") {
                v.push(Finding::signal(
                    Category::Identity,
                    "wifi ssid",
                    name,
                    6.0,
                    true,
                    "Chinese carrier hotspot SSID",
                ));
            } else {
                v.push(Finding::fact(Category::Identity, "wifi ssid", name));
            }
        }
        return;
    }
}
