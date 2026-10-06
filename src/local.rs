//! Collectors for everything that can be learned without touching the
//! network: hardware, locale, timezone, input methods, fonts, installed
//! software, package-mirror configuration and user-level identity hints.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::finding::{Category, Finding};

pub fn collect() -> Vec<Finding> {
    let mut v = Vec::new();
    system(&mut v);
    locale(&mut v);
    timezone(&mut v);
    input_methods(&mut v);
    keymap(&mut v);
    fonts(&mut v);
    software(&mut v);
    mirrors(&mut v);
    identity(&mut v);
    browser_lang(&mut v);
    v
}

// ---------------------------------------------------------------- helpers

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn home() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| "/root".into()))
}

fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn has_han(s: &str) -> bool {
    s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
}

fn contains_any(hay: &str, needles: &[&str]) -> Option<String> {
    let low = hay.to_lowercase();
    needles
        .iter()
        .find(|n| low.contains(&n.to_lowercase()))
        .map(|s| s.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

// ---------------------------------------------------------------- system

fn system(v: &mut Vec<Finding>) {
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
            &hostname,
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
            &user,
            6.0,
            false,
            "account name contains Han characters",
        ));
    } else {
        v.push(Finding::fact(Category::System, "username", user));
    }

    if let Some(osr) = read("/etc/os-release") {
        let name = osr
            .lines()
            .find(|l| l.starts_with("PRETTY_NAME=") || l.starts_with("NAME="))
            .and_then(|l| l.split('=').nth(1))
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_else(|| "unknown".into());
        let low = osr.to_lowercase();
        // Chinese-produced distributions: a very strong signal.
        let cn_distro = contains_any(
            &low,
            &[
                "deepin",
                "\"uos\"",
                "uniontech",
                "kylin",
                "neokylin",
                "loongnix",
                "nfschina",
                "openkylin",
                "ukui",
                "alinux",
                "anolis",
                "opencloudos",
                "tencentos",
            ],
        );
        match cn_distro {
            Some(hit) => v.push(Finding::signal(
                Category::System,
                "os release",
                name,
                15.0,
                true,
                format!("Chinese-produced distribution ('{hit}')"),
            )),
            None => v.push(Finding::fact(Category::System, "os release", name)),
        }
    }

    if let Some(k) = run("uname", &["-sr"]) {
        v.push(Finding::fact(Category::System, "kernel", k));
    }

    let arch = run("uname", &["-m"]).unwrap_or_default();
    if arch.trim() == "loongarch64" {
        v.push(Finding::signal(
            Category::System,
            "arch",
            "loongarch64",
            12.0,
            true,
            "LoongArch is a Chinese-developed ISA",
        ));
    } else {
        v.push(Finding::fact(Category::System, "arch", arch.trim()));
    }

    if let Some(cpu) = read("/proc/cpuinfo").and_then(|c| {
        c.lines()
            .find(|l| l.to_lowercase().starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
    }) {
        let cn_cpu = contains_any(
            &cpu,
            &[
                "loongson",
                "hygon",
                "phytium",
                "kunpeng",
                "zhaoxin",
                "sunway",
                "sw64",
                "hisilicon",
            ],
        );
        match cn_cpu {
            Some(hit) => v.push(Finding::signal(
                Category::System,
                "cpu model",
                cpu,
                12.0,
                true,
                format!("Chinese-designed CPU ('{hit}')"),
            )),
            None => v.push(Finding::fact(Category::System, "cpu model", cpu)),
        }
    }

    let vendor = read("/sys/class/dmi/id/sys_vendor").map(|s| s.trim().to_string());
    let product = read("/sys/class/dmi/id/product_name").map(|s| s.trim().to_string());
    if vendor.is_some() || product.is_some() {
        let label = format!(
            "{} {}",
            vendor.clone().unwrap_or_default(),
            product.unwrap_or_default()
        );
        let label = label.trim().to_string();
        let hit = contains_any(
            &label,
            &[
                "huawei", "xiaomi", "hasee", "tongfang", "mechrevo", "thunderobot", "honor",
                "greatwall", "great wall", "tsinghua",
            ],
        );
        if let Some(h) = hit {
            v.push(Finding::signal(
                Category::System,
                "dmi vendor",
                label,
                4.0,
                true,
                format!("Chinese hardware brand ('{h}')"),
            ));
        } else if label.to_lowercase().contains("lenovo") {
            v.push(Finding::signal(
                Category::System,
                "dmi vendor",
                label,
                1.5,
                true,
                "Lenovo is a Chinese brand but common worldwide",
            ));
        } else {
            v.push(Finding::fact(Category::System, "dmi vendor", label));
        }
    }

    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Some(id) = read(p).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            v.push(Finding::fact(
                Category::System,
                "machine-id",
                format!("{}… (truncated)", &id[..id.len().min(12)]),
            ));
            break;
        }
    }

    let mut macs = Vec::new();
    if let Ok(dir) = fs::read_dir("/sys/class/net") {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            if let Ok(mac) = fs::read_to_string(e.path().join("address")) {
                let mac = mac.trim();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    macs.push(format!("{name}={mac}"));
                }
            }
        }
    }
    if !macs.is_empty() {
        v.push(Finding::fact(Category::System, "mac addresses", macs.join("  ")));
    }
}

// ---------------------------------------------------------------- locale

/// Classify a locale string; returns (lr, mainland, note) if it is Chinese.
fn zh_locale(s: &str) -> Option<(f64, bool, &'static str)> {
    let l = s.to_lowercase();
    if l.contains("zh_cn") || l.contains("zh-cn") || l.contains("chinese_china") || l.contains("chs") {
        Some((12.0, true, "Simplified Chinese / PRC locale"))
    } else if l.contains("zh_tw") || l.contains("zh-tw") || l.contains("cht") {
        Some((5.0, false, "Traditional Chinese (Taiwan) locale"))
    } else if l.contains("zh_hk") || l.contains("zh-hk") || l.contains("zh_mo") || l.contains("zh-mo") {
        Some((5.0, false, "Chinese locale (HK/Macau)"))
    } else if l.contains("zh_sg") || l.contains("zh-sg") {
        Some((3.0, false, "Chinese locale (Singapore)"))
    } else if l.contains("zh") {
        Some((6.0, false, "Chinese locale (unspecified region)"))
    } else {
        None
    }
}

fn locale(v: &mut Vec<Finding>) {
    for var in ["LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES"] {
        if let Ok(val) = env::var(var) {
            if val.is_empty() {
                continue;
            }
            match zh_locale(&val) {
                Some((lr, ml, note)) => v.push(Finding::signal(
                    Category::Locale,
                    var,
                    val,
                    lr,
                    ml,
                    note,
                )),
                None => v.push(Finding::fact(Category::Locale, var, val)),
            }
        }
    }

    for p in ["/etc/locale.conf", "/etc/default/locale"] {
        if let Some(c) = read(p) {
            let mut any = false;
            for line in c.lines().filter(|l| l.contains('=') && !l.starts_with('#')) {
                any = true;
                if let Some((_, val)) = line.split_once('=') {
                    let val = val.trim_matches('"').trim_matches('\'');
                    if let Some((lr, ml, note)) = zh_locale(val) {
                        v.push(Finding::signal(
                            Category::Locale,
                            format!("{p} ({})", line.split('=').next().unwrap_or("")),
                            val,
                            lr,
                            ml,
                            note,
                        ));
                    }
                }
            }
            if any {
                v.push(Finding::fact(
                    Category::Locale,
                    p,
                    truncate(&c.replace('\n', " "), 80),
                ));
            }
        }
    }

    if let Some(la) = run("locale", &["-a"]) {
        let zh: Vec<&str> = la
            .lines()
            .filter(|l| l.to_lowercase().contains("zh_"))
            .collect();
        if !zh.is_empty() {
            let has_cn = zh.iter().any(|l| l.to_lowercase().contains("zh_cn"));
            let lang_is_zh = env::var("LANG").map(|l| zh_locale(&l).is_some()).unwrap_or(false);
            if !lang_is_zh {
                v.push(Finding::signal(
                    Category::Locale,
                    "generated zh locales",
                    zh.join(", "),
                    if has_cn { 6.0 } else { 3.0 },
                    has_cn,
                    "zh locales installed although LANG is not Chinese",
                ));
            } else {
                v.push(Finding::fact(Category::Locale, "generated zh locales", zh.join(", ")));
            }
        }
    }
}

// ---------------------------------------------------------------- timezone

fn timezone(v: &mut Vec<Finding>) {
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
        } else if l.contains("hong_kong") || l.contains("hongkong") || l.contains("macau") || l.contains("macao") {
            (4.0, false, "Hong Kong/Macau timezone")
        } else if l.contains("taipei") {
            (4.0, false, "Taiwan timezone")
        } else {
            (1.0, false, "")
        };
        if lr > 1.0 {
            v.push(Finding::signal(Category::Locale, "timezone", z, lr, ml, note));
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

// ------------------------------------------------------------- input methods

fn input_methods(v: &mut Vec<Finding>) {
    // 1. Environment variables selecting an input method framework.
    let mut env_hit = false;
    for var in ["GTK_IM_MODULE", "QT_IM_MODULE", "XMODIFIERS", "INPUT_METHOD", "SDL_IM_MODULE"] {
        if let Ok(val) = env::var(var) {
            let l = val.to_lowercase();
            if l.contains("fcitx") || l.contains("ibus") || l.contains("scim") || l.contains("xim") {
                env_hit = true;
                v.push(Finding::signal(
                    Category::Input,
                    var,
                    val,
                    4.0,
                    false,
                    "an IM framework (commonly used for CJK input) is configured",
                ));
            } else {
                v.push(Finding::fact(Category::Input, var, val));
            }
        }
    }
    let _ = env_hit;

    // 2. Running processes.
    if let Some(pg) = run("pgrep", &["-a", "-f", "fcitx|ibus-daemon|sogou|scim|rime"]) {
        let procs: Vec<&str> = pg.lines().take(8).collect();
        let joined = procs.join("; ");
        let l = joined.to_lowercase();
        if l.contains("sogou") {
            v.push(Finding::signal(
                Category::Input,
                "im processes",
                truncate(&joined, 90),
                15.0,
                true,
                "Sogou Pinyin running (mainland-specific)",
            ));
        } else if l.contains("fcitx") || l.contains("ibus") {
            v.push(Finding::signal(
                Category::Input,
                "im processes",
                truncate(&joined, 90),
                7.0,
                false,
                "fcitx/ibus daemon running",
            ));
        }
    }

    // 3. Config / data directories for Chinese IMEs.
    let h = home();
    let ime_dirs = [
        ".config/fcitx",
        ".config/fcitx5",
        ".config/ibus",
        ".config/sogoupinyin",
        ".config/搜狗输入法",
        ".local/share/fcitx5/rime",
        ".local/share/fcitx5/pinyin",
        ".config/ibus/rime",
        ".config/fcitx/rime",
        ".config/fcitx/pinyin",
        ".config/Rime",
    ];
    let found: Vec<String> = ime_dirs
        .iter()
        .filter(|d| h.join(d).exists())
        .map(|d| d.to_string())
        .collect();
    if !found.is_empty() {
        let joined = found.join(", ");
        let l = joined.to_lowercase();
        let (lr, ml, note) = if l.contains("sogou") || l.contains("搜狗") {
            (12.0, true, "Sogou configuration present")
        } else if l.contains("pinyin") {
            (9.0, true, "pinyin input data present")
        } else if l.contains("rime") {
            (6.0, false, "Rime is popular in both CN and TW/HK")
        } else {
            (5.0, false, "IM framework configuration present")
        };
        v.push(Finding::signal(
            Category::Input,
            "ime config dirs",
            joined,
            lr,
            ml,
            note,
        ));
    }

    // 4. Installed IME packages (dpkg-based systems).
    if let Some(dpkg) = run("dpkg", &["-l"]) {
        let pkgs: BTreeSet<String> = dpkg
            .lines()
            .filter(|l| {
                let l = l.to_lowercase();
                l.contains("fcitx")
                    || l.contains("sogou")
                    || l.contains("rime")
                    || l.contains("ibus-pinyin")
                    || l.contains("ibus-libpinyin")
                    || l.contains("ibus-sunpinyin")
                    || l.contains("sunpinyin")
                    || l.contains("googlepinyin")
                    || l.contains("baidupinyin")
            })
            .filter_map(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
            .collect();
        if !pkgs.is_empty() {
            let joined: Vec<String> = pkgs.iter().take(12).cloned().collect();
            let l = joined.join(",").to_lowercase();
            let (lr, ml, note) = if l.contains("sogou") {
                (12.0, true, "Sogou IME package installed")
            } else if l.contains("pinyin") || l.contains("sunpinyin") || l.contains("googlepinyin") {
                (10.0, true, "pinyin IME engine installed")
            } else if l.contains("rime") {
                (6.0, false, "Rime IME installed")
            } else {
                (5.0, false, "IM framework packages installed")
            };
            v.push(Finding::signal(
                Category::Input,
                "ime packages",
                truncate(&joined.join(", "), 100),
                lr,
                ml,
                note,
            ));
        }
    }
}

// ---------------------------------------------------------------- keymap

fn keymap(v: &mut Vec<Finding>) {
    let status = run("localectl", &["status"]);
    let layout = status.as_deref().and_then(|s| {
        s.lines()
            .find(|l| l.contains("Layout:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
    });
    let layout = layout.or_else(|| {
        run("setxkbmap", &["-query"]).and_then(|s| {
            s.lines()
                .find(|l| l.trim_start().starts_with("layout:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        })
    });
    match layout {
        Some(l) if l.to_lowercase().starts_with("cn") => v.push(Finding::signal(
            Category::Input,
            "keyboard layout",
            l,
            3.0,
            true,
            "Chinese X11 keymap",
        )),
        Some(l) => v.push(Finding::fact(Category::Input, "keyboard layout", l)),
        None => {}
    }
}

// ---------------------------------------------------------------- fonts

fn fonts(v: &mut Vec<Finding>) {
    let Some(list) = run("fc-list", &[":lang=zh", "family"]) else {
        v.push(Finding::fact(Category::Fonts, "fc-list", "not available"));
        return;
    };
    let fams: BTreeSet<String> = list
        .lines()
        .flat_map(|l| l.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if fams.is_empty() {
        v.push(Finding::fact(Category::Fonts, "zh-capable fonts", "none found"));
        return;
    }
    let sc_markers = [
        " cjk sc", "han sans sc", "han serif sc", "wenquanyi", "文泉驿", "yahei", "雅黑",
        "simsun", "宋体", "simhei", "黑体", "simkai", "fangsong", "仿宋", "pingfang sc",
        "sarasa sc", "ukai", "uming", "noto sans sc", "noto serif sc", "苹方",
    ];
    let tc_markers = ["cjk tc", "cjk hk", "han sans tc", "han serif tc", "pingfang tc", "pingfang hk", "mingliu", "pmingliu", "sarasa tc"];
    let joined = fams.iter().cloned().collect::<Vec<_>>().join(",");
    let low = format!(" {} ", joined.to_lowercase());
    let sc = sc_markers.iter().filter(|m| low.contains(**m)).count();
    let tc = tc_markers.iter().filter(|m| low.contains(**m)).count();
    let sample: Vec<String> = fams.iter().take(8).cloned().collect();
    if sc > 0 {
        v.push(Finding::signal(
            Category::Fonts,
            "zh-capable fonts",
            format!("{} families ({}; …)", fams.len(), sample.join(", ")),
            5.0 + (sc.min(3) as f64),
            true,
            "Simplified-Chinese font variants installed",
        ));
    } else if tc > 0 {
        v.push(Finding::signal(
            Category::Fonts,
            "zh-capable fonts",
            format!("{} families ({}; …)", fams.len(), sample.join(", ")),
            3.0,
            false,
            "Traditional-Chinese font variants only",
        ));
    } else {
        v.push(Finding::fact(
            Category::Fonts,
            "zh-capable fonts",
            format!("{} families ({}; …)", fams.len(), sample.join(", ")),
        ));
    }
}

// ---------------------------------------------------------------- software

fn software(v: &mut Vec<Finding>) {
    let mut found: BTreeSet<String> = BTreeSet::new();

    // 1. Executables on PATH.
    let binaries = [
        "wechat", "weixin", "qq", "tim", "linuxqq", "wps", "wpp", "et", "wpspdf",
        "netease-cloud-music", "dingtalk", "youdao-dict", "baidunetdisk",
        "baidu-netdisk", "foxmail", "sogou-qimpanel", "sogoupinyin", "wechat-devtools",
        "xunlei", "thunder", "feishu", "lark", "wxwork", "electronic-wechat",
    ];
    if let Ok(path) = env::var("PATH") {
        let bins: BTreeSet<&str> = binaries.iter().copied().collect();
        for dir in path.split(':') {
            if let Ok(rd) = fs::read_dir(dir) {
                for e in rd.flatten() {
                    if let Some(name) = e.file_name().to_str() {
                        let n = name.to_lowercase();
                        if bins.contains(n.as_str()) || n.starts_with("sogou") || n.starts_with("com.tencent") {
                            found.insert(n);
                        }
                    }
                }
            }
        }
    }

    // 2. Vendor-prefixed install dirs (deepin/UOS style /opt/apps, flatpak, snap).
    let prefixes = [
        "com.qq.", "com.tencent.", "com.alibaba.", "com.baidu.", "com.netease.",
        "com.taobao.", "com.sogou.", "com.xunlei.", "cn.wps", "com.deepin.",
        "com.uniontech.", "com.aliyun.", "io.github.martinrotter", "cn.",
    ];
    for dir in ["/opt/apps", "/var/lib/flatpak/app", &format!("{}/snap", home().display())] {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if prefixes.iter().any(|p| n.starts_with(p)) {
                    found.insert(format!("{} ({})", n, dir));
                }
            }
        }
    }
    let extra_dirs = [
        format!("{}/.deepinwine", home().display()),
        format!("{}/.config/微信", home().display()),
        format!("{}/.config/Tencent", home().display()),
        format!("{}/.config/tencent-qq", home().display()),
        format!("{}/Documents/WeChat Files", home().display()),
        format!("{}/文档/WeChat Files", home().display()),
    ];
    for d in extra_dirs {
        if Path::new(&d).exists() {
            found.insert(d);
        }
    }

    // 3. Desktop entries + dpkg names.
    for apps_dir in ["/usr/share/applications", &format!("{}/.local/share/applications", home().display())] {
        if let Ok(rd) = fs::read_dir(apps_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if contains_any(
                    &n,
                    &["wechat", "qq", "wps", "sogou", "netease", "baidu", "tencent", "dingtalk", "feishu", "weixin"],
                )
                .is_some()
                {
                    found.insert(format!("{} (desktop entry)", n.trim_end_matches(".desktop")));
                }
            }
        }
    }
    if let Some(dpkg) = run("dpkg", &["-l"]) {
        for l in dpkg.lines() {
            let low = l.to_lowercase();
            if let Some(hit) = contains_any(
                &low,
                &["wechat", "weixin", "linuxqq", ".qq.", "wps-office", "sogou", "netease", "baidu", "tencent", "dingtalk", "xunlei", "deepin-wine", "ukui-", "kylin-"],
            ) {
                if let Some(pkg) = l.split_whitespace().nth(1) {
                    let _ = hit;
                    found.insert(format!("{pkg} (dpkg)"));
                }
            }
        }
    }

    if found.is_empty() {
        v.push(Finding::fact(Category::Software, "cn software markers", "none found"));
    } else {
        let items: Vec<String> = found.iter().take(15).cloned().collect();
        v.push(Finding::signal(
            Category::Software,
            "cn software markers",
            format!("{} hit(s): {}", found.len(), truncate(&items.join(", "), 110)),
            12.0,
            true,
            "Chinese software installed",
        ));
    }
}

// ---------------------------------------------------------------- mirrors

fn mirrors(v: &mut Vec<Finding>) {
    let h = home();
    let mut files: Vec<PathBuf> = vec![
        "/etc/apt/sources.list".into(),
        "/etc/pip.conf".into(),
        "/etc/docker/daemon.json".into(),
        "/etc/pacman.d/mirrorlist".into(),
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
    ];
    for glob_dir in ["/etc/apt/sources.list.d", "/etc/yum.repos.d"] {
        if let Ok(rd) = fs::read_dir(glob_dir) {
            for e in rd.flatten() {
                files.push(e.path());
            }
        }
    }

    let kw = [
        "aliyun", "tuna", "tsinghua", "ustc", "163.com", "tencent", "mirrors.cloud.tencent",
        "huawei", "huaweicloud", "goproxy.cn", "npmmirror", "cnpmjs", "taobao",
        "edu.cn", "sjtug", "cn.archive.ubuntu", "rsproxy", "mirrors.opencas",
        "mirror.sjtu", "mirrors.bfsu", "mirrors.nju", "mirrors.zju", "mirrors.cqu",
        "mirrors.dlut", "mirror.lzu", "mirrors.neusoft", "developer.aliyun",
    ];
    let mut hits = 0usize;
    for f in files {
        let Some(content) = read(&f) else { continue };
        let low = content.to_lowercase();
        if let Some(k) = kw.iter().find(|k| low.contains(**k)) {
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
    if hits == 0 {
        v.push(Finding::fact(
            Category::Mirrors,
            "config files",
            "no Chinese mirrors referenced",
        ));
    }
}

// ---------------------------------------------------------------- identity

fn identity(v: &mut Vec<Finding>) {
    let h = home();

    if let Some(gc) = read(h.join(".gitconfig")) {
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
                    "@qq.com", "@163.com", "@126.com", "@yeah.net", "@sina", "@aliyun",
                    "@foxmail", "@139.com", "@189.cn", "@wo.cn", "@sohu.com", "@tom.com",
                    "@gmail.cn", "edu.cn",
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

    // Shell history: count lines containing Han characters (content is never
    // shown, only the count).
    let mut total_han = 0usize;
    let mut scanned = Vec::new();
    for f in [
        h.join(".bash_history"),
        h.join(".zsh_history"),
        h.join(".local/share/fish/fish_history"),
    ] {
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
            v.push(Finding::fact(Category::Identity, "shell history", scanned.join("  ")));
        }
    }

    // XDG user dirs in Chinese (~/桌面, ~/下载, ...).
    let cn_dirs = ["桌面", "下载", "文档", "图片", "音乐", "视频", "模板", "公共"];
    let present: Vec<&str> = cn_dirs.iter().filter(|d| h.join(d).exists()).copied().collect();
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
            if present.is_empty() { "configured in user-dirs.dirs".into() } else { present.join(", ") },
            7.0,
            true,
            "home directory uses Chinese standard folder names",
        ));
    }

    // WiFi SSID.
    let ssid = run("iwgetid", &["-r"]).or_else(|| {
        run("nmcli", &["-t", "-f", "ACTIVE,SSID", "dev", "wifi"]).and_then(|out| {
            out.lines()
                .find(|l| l.starts_with("yes:"))
                .map(|l| l.trim_start_matches("yes:").to_string())
        })
    });
    if let Some(s) = ssid.filter(|s| !s.is_empty()) {
        let l = s.to_lowercase();
        if has_han(&s) {
            v.push(Finding::signal(Category::Identity, "wifi ssid", s, 6.0, false, "SSID contains Han characters"));
        } else if l.starts_with("chinanet") || l.starts_with("cmcc") || l.starts_with("chinaunicom") || l.starts_with("china-net") {
            v.push(Finding::signal(Category::Identity, "wifi ssid", s, 6.0, true, "Chinese carrier hotspot SSID"));
        } else {
            v.push(Finding::fact(Category::Identity, "wifi ssid", s));
        }
    }
}

// ------------------------------------------------------------ browsers

/// Classify a browser Accept-Language value; returns (lr, mainland, note).
fn zh_accept_lang(s: &str) -> Option<(f64, bool, &'static str)> {
    let l = s.to_lowercase();
    if l.contains("zh-cn") || l.contains("zh-hans") {
        Some((5.0, true, "browser language is Simplified Chinese"))
    } else if l.contains("zh-tw") || l.contains("zh-hk") || l.contains("zh-mo") || l.contains("zh-hant") {
        Some((4.0, false, "browser language is Traditional Chinese"))
    } else if l.contains("zh") {
        Some((4.0, false, "browser language is Chinese"))
    } else {
        None
    }
}

fn browser_lang(v: &mut Vec<Finding>) {
    let h = home();
    // Chromium-family: "Local State" JSON has intl.accept_languages.
    let chromes = [
        ".config/google-chrome/Local State",
        ".config/chromium/Local State",
        ".config/microsoft-edge/Local State",
        ".config/BraveSoftware/Brave-Browser/Local State",
        ".config/vivaldi/Local State",
        ".config/qqbrowser/Local State",
        ".config/sogouexplorer/Local State",
    ];
    for rel in chromes {
        let Some(body) = read(h.join(rel)) else { continue };
        let Ok(j) = serde_json::from_str::<serde_json::Value>(&body) else { continue };
        let Some(lang) = j.pointer("/intl/accept_languages").and_then(|x| x.as_str()) else { continue };
        let browser = rel.split('/').nth(1).unwrap_or("chromium");
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
    // Firefox: intl.locale.requested in prefs.js of each profile.
    if let Ok(rd) = fs::read_dir(h.join(".mozilla/firefox")) {
        for e in rd.flatten().filter(|e| e.path().is_dir()) {
            let Some(prefs) = read(e.path().join("prefs.js")) else { continue };
            let Some(line) = prefs.lines().find(|l| l.contains("intl.locale.requested")) else { continue };
            let Some(lang) = line.split('"').nth(3) else { continue };
            match zh_accept_lang(lang) {
                Some((lr, ml, note)) => {
                    v.push(Finding::signal(Category::Identity, "firefox locale", lang, lr, ml, note))
                }
                None => v.push(Finding::fact(Category::Identity, "firefox locale", lang)),
            }
            break; // one profile is enough
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zh_locale_classification() {
        assert_eq!(zh_locale("zh_CN.UTF-8"), Some((12.0, true, "Simplified Chinese / PRC locale")));
        assert!(zh_locale("zh_TW.UTF-8").is_some_and(|(lr, ml, _)| lr == 5.0 && !ml));
        assert!(zh_locale("zh_HK").is_some_and(|(_, ml, _)| !ml));
        assert!(zh_locale("en_US.UTF-8").is_none());
        assert!(zh_locale("ja_JP.UTF-8").is_none());
        // LANGUAGE colon lists
        assert!(zh_locale("zh_CN:en_US").is_some());
    }

    #[test]
    fn zh_accept_lang_classification() {
        assert!(zh_accept_lang("zh-CN,zh;q=0.9,en;q=0.8").is_some_and(|(lr, ml, _)| lr == 5.0 && ml));
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
