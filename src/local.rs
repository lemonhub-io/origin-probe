//! Cross-platform collectors plus dispatch into `crate::platform::*`.
//! Everything here works on Linux, macOS and Windows; OS-specific probes
//! live in `src/platform/`.

use std::env;
use std::fs;
use std::path::PathBuf;

use crate::finding::{Category, Finding};
use crate::util::*;

pub fn collect() -> Vec<Finding> {
    let mut v = Vec::new();
    unix_identity(&mut v);
    env_locale(&mut v);
    unix_timezone(&mut v);
    gitconfig(&mut v);
    shell_history(&mut v);
    xdg_dirs(&mut v);
    mirror_files(&mut v);
    browser_lang(&mut v);

    #[cfg(target_os = "linux")]
    crate::platform::linux::collect(&mut v);
    #[cfg(target_os = "macos")]
    crate::platform::macos::collect(&mut v);
    #[cfg(windows)]
    crate::platform::windows::collect(&mut v);
    v
}

// ---------------------------------------------------------------- shared

#[cfg(unix)]
fn unix_identity(v: &mut Vec<Finding>) {
    let hostname = env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| read("/etc/hostname").map(|s| s.trim().to_string()))
        .or_else(|| run("hostname", &[]))
        .unwrap_or_else(|| "unknown".into());
    if has_han(&hostname) {
        v.push(Finding::signal(
            Category::System,
            "hostname",
            hostname,
            5.0,
            false,
            "hostname contains Han characters",
        ));
    } else {
        v.push(Finding::fact(Category::System, "hostname", hostname));
    }

    let user = env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into());
    if has_han(&user) {
        v.push(Finding::signal(
            Category::System,
            "username",
            user,
            6.0,
            false,
            "account name contains Han characters",
        ));
    } else {
        v.push(Finding::fact(Category::System, "username", user));
    }
}

#[cfg(not(unix))]
fn unix_identity(_v: &mut Vec<Finding>) {}

/// Classify a locale string; returns (lr, mainland, note) if it is Chinese.
pub(crate) fn zh_locale(s: &str) -> Option<(f64, bool, &'static str)> {
    let l = s.to_lowercase();
    if l.contains("zh_cn")
        || l.contains("zh-cn")
        || l.contains("chinese_china")
        || l.contains("chs")
    {
        Some((12.0, true, "Simplified Chinese / PRC locale"))
    } else if l.contains("zh_tw") || l.contains("zh-tw") || l.contains("cht") {
        Some((5.0, false, "Traditional Chinese (Taiwan) locale"))
    } else if l.contains("zh_hk")
        || l.contains("zh-hk")
        || l.contains("zh_mo")
        || l.contains("zh-mo")
    {
        Some((5.0, false, "Chinese locale (HK/Macau)"))
    } else if l.contains("zh_sg") || l.contains("zh-sg") {
        Some((3.0, false, "Chinese locale (Singapore)"))
    } else if l.contains("zh") {
        Some((6.0, false, "Chinese locale (unspecified region)"))
    } else {
        None
    }
}

fn env_locale(v: &mut Vec<Finding>) {
    for var in ["LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES"] {
        if let Ok(val) = env::var(var) {
            if val.is_empty() {
                continue;
            }
            match zh_locale(&val) {
                Some((lr, ml, note)) => {
                    v.push(Finding::signal(Category::Locale, var, val, lr, ml, note))
                }
                None => v.push(Finding::fact(Category::Locale, var, val)),
            }
        }
    }
}

#[cfg(unix)]
fn unix_timezone(v: &mut Vec<Finding>) {
    let mut zone: Option<String> = read("/etc/timezone").map(|s| s.trim().to_string());
    if zone.is_none() {
        if let Ok(link) = fs::read_link("/etc/localtime") {
            if let Some(s) = link.to_str() {
                if let Some(z) = s.split("zoneinfo/").nth(1) {
                    zone = Some(z.to_string());
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    if zone.is_none() {
        zone = run("timedatectl", &["show", "-p", "Timezone", "--value"]);
    }

    if let Some(z) = zone {
        let l = z.to_lowercase();
        let (lr, ml, note) = if l.contains("shanghai")
            || l.contains("chongqing")
            || l.contains("chungking")
            || l.contains("harbin")
            || l.contains("urumqi")
            || l.contains("kashgar")
            || l == "prc"
            || l.contains("beijing")
        {
            (12.0, true, "PRC timezone")
        } else if l.contains("hong_kong")
            || l.contains("hongkong")
            || l.contains("macau")
            || l.contains("macao")
        {
            (4.0, false, "Hong Kong/Macau timezone")
        } else if l.contains("taipei") {
            (4.0, false, "Taiwan timezone")
        } else {
            (1.0, false, "")
        };
        if lr > 1.0 {
            v.push(Finding::signal(
                Category::Locale,
                "timezone",
                z,
                lr,
                ml,
                note,
            ));
        } else {
            v.push(Finding::fact(Category::Locale, "timezone", z));
        }
    }

    if let Some(off) = run("date", &["+%z"]) {
        if off == "+0800" {
            v.push(Finding::signal(
                Category::Locale,
                "utc offset",
                "+0800",
                1.4,
                false,
                "UTC+8 is shared by CN, TW, HK, SG, MY",
            ));
        } else {
            v.push(Finding::fact(Category::Locale, "utc offset", off));
        }
    }
}

#[cfg(not(unix))]
fn unix_timezone(_v: &mut Vec<Finding>) {}

fn gitconfig(v: &mut Vec<Finding>) {
    if let Some(gc) = read(home().join(".gitconfig")) {
        let mut name = None;
        let mut email = None;
        for line in gc.lines() {
            let l = line.trim();
            if let Some((k, val)) = l.split_once('=') {
                match k.trim().to_lowercase().as_str() {
                    "name" => name = Some(val.trim().to_string()),
                    "email" => email = Some(val.trim().to_string()),
                    _ => {}
                }
            }
        }
        if let Some(n) = name {
            if has_han(&n) {
                v.push(Finding::signal(
                    Category::Identity,
                    "git user.name",
                    n,
                    6.0,
                    false,
                    "name written in Han characters",
                ));
            } else {
                v.push(Finding::fact(Category::Identity, "git user.name", n));
            }
        }
        if let Some(e) = email {
            let cn_mail = contains_any(
                &e.to_lowercase(),
                &[
                    "@qq.com",
                    "@163.com",
                    "@126.com",
                    "@yeah.net",
                    "@sina",
                    "@aliyun",
                    "@foxmail",
                    "@139.com",
                    "@189.cn",
                    "@wo.cn",
                    "@sohu.com",
                    "@tom.com",
                    "@gmail.cn",
                    "edu.cn",
                ],
            );
            match cn_mail {
                Some(d) => v.push(Finding::signal(
                    Category::Identity,
                    "git user.email",
                    e,
                    9.0,
                    true,
                    format!("Chinese mail provider ('{d}')"),
                )),
                None => v.push(Finding::fact(Category::Identity, "git user.email", e)),
            }
        }
    }
}

/// Shell history: count lines containing Han characters (content is never
/// shown, only the count).
fn shell_history(v: &mut Vec<Finding>) {
    let h = home();
    let mut files = vec![
        h.join(".bash_history"),
        h.join(".zsh_history"),
        h.join(".local/share/fish/fish_history"),
        h.join(".local/share/powershell/PSReadLine/ConsoleHost_history.txt"),
    ];
    // Windows PowerShell history lives under APPDATA.
    if let Ok(appdata) = env::var("APPDATA") {
        files.push(
            PathBuf::from(appdata)
                .join(r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
        );
    }
    let mut total_han = 0usize;
    let mut scanned = Vec::new();
    for f in files {
        if let Some(c) = read(&f) {
            let tail: String = c
                .rsplit('\n')
                .take(4000)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            let n = tail.lines().filter(|l| has_han(l)).count();
            total_han += n;
            scanned.push(format!("{}: {} han lines", f.display(), n));
        }
    }
    if !scanned.is_empty() {
        if total_han > 0 {
            v.push(Finding::signal(
                Category::Identity,
                "shell history",
                scanned.join("  "),
                8.0,
                false,
                format!("{total_han} history lines contain Han characters"),
            ));
        } else {
            v.push(Finding::fact(
                Category::Identity,
                "shell history",
                scanned.join("  "),
            ));
        }
    }
}

/// XDG user dirs in Chinese (~/桌面, ~/下载, ...) — applies on any OS.
fn xdg_dirs(v: &mut Vec<Finding>) {
    let h = home();
    let cn_dirs = [
        "桌面", "下载", "文档", "图片", "音乐", "视频", "模板", "公共",
    ];
    let present: Vec<&str> = cn_dirs
        .iter()
        .filter(|d| h.join(d).exists())
        .copied()
        .collect();
    let mut from_cfg = false;
    if let Some(ud) = read(h.join(".config/user-dirs.dirs")) {
        if cn_dirs.iter().any(|d| ud.contains(d)) {
            from_cfg = true;
        }
    }
    if !present.is_empty() || from_cfg {
        v.push(Finding::signal(
            Category::Identity,
            "xdg user dirs",
            if present.is_empty() {
                "configured in user-dirs.dirs".into()
            } else {
                present.join(", ")
            },
            7.0,
            true,
            "home directory uses Chinese standard folder names",
        ));
    }
}

/// Keyword list identifying Chinese package mirrors.
const MIRROR_KEYWORDS: &[&str] = &[
    "aliyun",
    "tuna",
    "tsinghua",
    "ustc",
    "163.com",
    "tencent",
    "mirrors.cloud.tencent",
    "huawei",
    "huaweicloud",
    "goproxy.cn",
    "npmmirror",
    "cnpmjs",
    "taobao",
    "edu.cn",
    "sjtug",
    "cn.archive.ubuntu",
    "rsproxy",
    "mirrors.opencas",
    "mirror.sjtu",
    "mirrors.bfsu",
    "mirrors.nju",
    "mirrors.zju",
    "mirrors.cqu",
    "mirrors.dlut",
    "mirror.lzu",
    "mirrors.neusoft",
    "developer.aliyun",
];

/// Scan a list of config files for references to Chinese package mirrors.
/// Returns the number of files that hit. Shared by the cross-platform
/// home-dir scan and the Linux system scan.
pub(crate) fn scan_mirror_files(v: &mut Vec<Finding>, files: Vec<PathBuf>) -> usize {
    let mut hits = 0;
    for f in files {
        let Some(content) = read(&f) else { continue };
        let low = content.to_lowercase();
        if let Some(k) = MIRROR_KEYWORDS.iter().find(|k| low.contains(**k)) {
            hits += 1;
            v.push(Finding::signal(
                Category::Mirrors,
                f.display().to_string(),
                format!("references '{k}'"),
                7.0,
                true,
                "package registry points at a Chinese mirror",
            ));
        }
    }
    hits
}

fn mirror_files(v: &mut Vec<Finding>) {
    let h = home();
    let files: Vec<PathBuf> = vec![
        "/etc/pip.conf".into(),
        "/etc/docker/daemon.json".into(),
        h.join(".pip/pip.conf"),
        h.join(".config/pip/pip.conf"),
        h.join(".npmrc"),
        h.join(".yarnrc"),
        h.join(".condarc"),
        h.join(".cargo/config.toml"),
        h.join(".cargo/config"),
        h.join(".docker/daemon.json"),
        h.join(".m2/settings.xml"),
        h.join(".config/go/env"),
        h.join(".gradle/gradle.properties"),
        h.join(".mvn/settings.xml"),
        // Shell rc files may export mirror env vars (brew, rustup, pip, …).
        h.join(".zshrc"),
        h.join(".zprofile"),
        h.join(".bashrc"),
        h.join(".bash_profile"),
        h.join(".profile"),
    ];
    let hits = scan_mirror_files(v, files.clone());
    if hits == 0 && !files.iter().any(|f| f.exists()) {
        v.push(Finding::fact(
            Category::Mirrors,
            "config files",
            "no config files found",
        ));
    }
}

// ------------------------------------------------------------ browsers

/// Classify a browser Accept-Language value; returns (lr, mainland, note).
fn zh_accept_lang(s: &str) -> Option<(f64, bool, &'static str)> {
    let l = s.to_lowercase();
    if l.contains("zh-cn") || l.contains("zh-hans") {
        Some((5.0, true, "browser language is Simplified Chinese"))
    } else if l.contains("zh-tw")
        || l.contains("zh-hk")
        || l.contains("zh-mo")
        || l.contains("zh-hant")
    {
        Some((4.0, false, "browser language is Traditional Chinese"))
    } else if l.contains("zh") {
        Some((4.0, false, "browser language is Chinese"))
    } else {
        None
    }
}

/// Chromium "Local State" location per OS, relative to the home dir.
#[cfg(target_os = "macos")]
fn chrome_local_states() -> Vec<PathBuf> {
    let h = home();
    let base = h.join("Library/Application Support");
    [
        "Google/Chrome",
        "Chromium",
        "Microsoft Edge",
        "BraveSoftware/Brave-Browser",
        "Vivaldi",
        "QQBrowser",
        "SogouExplorer",
    ]
    .iter()
    .map(|p| base.join(p).join("Local State"))
    .collect()
}

#[cfg(target_os = "linux")]
fn chrome_local_states() -> Vec<PathBuf> {
    let h = home();
    [
        ".config/google-chrome",
        ".config/chromium",
        ".config/microsoft-edge",
        ".config/BraveSoftware/Brave-Browser",
        ".config/vivaldi",
        ".config/qqbrowser",
        ".config/sogouexplorer",
    ]
    .iter()
    .map(|p| h.join(p).join("Local State"))
    .collect()
}

#[cfg(windows)]
fn chrome_local_states() -> Vec<PathBuf> {
    let local = env::var("LOCALAPPDATA").unwrap_or_default();
    let roaming = env::var("APPDATA").unwrap_or_default();
    [
        format!("{local}\\Google\\Chrome\\User Data"),
        format!("{local}\\Chromium\\User Data"),
        format!("{local}\\Microsoft\\Edge\\User Data"),
        format!("{local}\\BraveSoftware\\Brave-Browser\\User Data"),
        format!("{local}\\Vivaldi\\User Data"),
        format!("{roaming}\\Tencent\\QQBrowser"),
    ]
    .iter()
    .map(|p| PathBuf::from(p).join("Local State"))
    .collect()
}

/// Firefox profile roots per OS.
fn firefox_profiles() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    return vec![home().join("Library/Application Support/Firefox/Profiles")];
    #[cfg(target_os = "linux")]
    return vec![
        home().join(".mozilla/firefox"),
        home().join("snap/firefox/common/.mozilla/firefox"),
    ];
    #[cfg(windows)]
    return env::var("APPDATA")
        .map(|a| vec![PathBuf::from(a).join(r"Mozilla\Firefox\Profiles")])
        .unwrap_or_default();
    #[cfg(not(any(unix, windows)))]
    return vec![];
}

fn browser_lang(v: &mut Vec<Finding>) {
    for path in chrome_local_states() {
        let Some(body) = read(&path) else { continue };
        let Ok(j) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };
        let Some(lang) = j.pointer("/intl/accept_languages").and_then(|x| x.as_str()) else {
            continue;
        };
        let browser = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| {
                let n = n.to_string_lossy();
                // "User Data" is Windows Chrome's profile root — go one up.
                if n == "User Data" {
                    path.parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.file_name())
                        .map(|x| x.to_string_lossy().to_string())
                        .unwrap_or_else(|| "chromium".into())
                } else {
                    n.to_string()
                }
            })
            .unwrap_or_else(|| "chromium".into());
        match zh_accept_lang(lang) {
            Some((lr, ml, note)) => v.push(Finding::signal(
                Category::Identity,
                format!("{browser} accept-language"),
                lang,
                lr,
                ml,
                note,
            )),
            None => v.push(Finding::fact(
                Category::Identity,
                format!("{browser} accept-language"),
                truncate(lang, 60),
            )),
        }
    }
    for root in firefox_profiles() {
        if let Ok(rd) = fs::read_dir(root) {
            for e in rd.flatten().filter(|e| e.path().is_dir()) {
                let Some(prefs) = read(e.path().join("prefs.js")) else {
                    continue;
                };
                let Some(line) = prefs.lines().find(|l| l.contains("intl.locale.requested")) else {
                    continue;
                };
                let Some(lang) = line.split('"').nth(3) else {
                    continue;
                };
                match zh_accept_lang(lang) {
                    Some((lr, ml, note)) => v.push(Finding::signal(
                        Category::Identity,
                        "firefox locale",
                        lang,
                        lr,
                        ml,
                        note,
                    )),
                    None => v.push(Finding::fact(Category::Identity, "firefox locale", lang)),
                }
                break; // one profile is enough
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zh_locale_classification() {
        assert_eq!(
            zh_locale("zh_CN.UTF-8"),
            Some((12.0, true, "Simplified Chinese / PRC locale"))
        );
        assert!(zh_locale("zh_TW.UTF-8").is_some_and(|(lr, ml, _)| lr == 5.0 && !ml));
        assert!(zh_locale("zh_HK").is_some_and(|(_, ml, _)| !ml));
        assert!(zh_locale("en_US.UTF-8").is_none());
        assert!(zh_locale("ja_JP.UTF-8").is_none());
        // LANGUAGE colon lists
        assert!(zh_locale("zh_CN:en_US").is_some());
    }

    #[test]
    fn zh_accept_lang_classification() {
        assert!(
            zh_accept_lang("zh-CN,zh;q=0.9,en;q=0.8").is_some_and(|(lr, ml, _)| lr == 5.0 && ml)
        );
        assert!(zh_accept_lang("zh-TW,zh;q=0.9").is_some_and(|(_, ml, _)| !ml));
        assert!(zh_accept_lang("en-US,en;q=0.9").is_none());
    }

    #[test]
    fn han_detection() {
        assert!(has_han("桌面"));
        assert!(has_han("file名字"));
        assert!(!has_han("plain ascii"));
    }
}
