//! Linux-specific collectors: /etc & /sys filesystem, dpkg, fc-list,
//! fcitx/ibus-style input methods, NetworkManager/iwd for WiFi.

use std::collections::BTreeSet;
use std::env;
use std::fs;

use crate::finding::{Category, Finding};
use crate::local::zh_locale;
use crate::util::*;

pub fn collect(v: &mut Vec<Finding>) {
    system(v);
    locale_files(v);
    input_methods(v);
    keymap(v);
    fonts(v);
    software(v);
    apt_mirrors(v);
    wifi(v);
}

// ---------------------------------------------------------------- system

fn system(v: &mut Vec<Finding>) {
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
                "huawei",
                "xiaomi",
                "hasee",
                "tongfang",
                "mechrevo",
                "thunderobot",
                "honor",
                "greatwall",
                "great wall",
                "tsinghua",
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
        if let Some(id) = read(p)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
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
        v.push(Finding::fact(
            Category::System,
            "mac addresses",
            macs.join("  "),
        ));
    }
}

// ---------------------------------------------------------------- locale files

fn locale_files(v: &mut Vec<Finding>) {
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
            let lang_is_zh = env::var("LANG")
                .map(|l| zh_locale(&l).is_some())
                .unwrap_or(false);
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
                v.push(Finding::fact(
                    Category::Locale,
                    "generated zh locales",
                    zh.join(", "),
                ));
            }
        }
    }
}

// ------------------------------------------------------------- input methods

fn input_methods(v: &mut Vec<Finding>) {
    // 1. Environment variables selecting an input method framework.
    for var in [
        "GTK_IM_MODULE",
        "QT_IM_MODULE",
        "XMODIFIERS",
        "INPUT_METHOD",
        "SDL_IM_MODULE",
    ] {
        if let Ok(val) = env::var(var) {
            let l = val.to_lowercase();
            if l.contains("fcitx") || l.contains("ibus") || l.contains("scim") || l.contains("xim")
            {
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
            } else if l.contains("pinyin") || l.contains("sunpinyin") || l.contains("googlepinyin")
            {
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
        v.push(Finding::fact(
            Category::Fonts,
            "zh-capable fonts",
            "none found",
        ));
        return;
    }
    let sc_markers = [
        " cjk sc",
        "han sans sc",
        "han serif sc",
        "wenquanyi",
        "文泉驿",
        "yahei",
        "雅黑",
        "simsun",
        "宋体",
        "simhei",
        "黑体",
        "simkai",
        "fangsong",
        "仿宋",
        "pingfang sc",
        "sarasa sc",
        "ukai",
        "uming",
        "noto sans sc",
        "noto serif sc",
        "苹方",
    ];
    let tc_markers = [
        "cjk tc",
        "cjk hk",
        "han sans tc",
        "han serif tc",
        "pingfang tc",
        "pingfang hk",
        "mingliu",
        "pmingliu",
        "sarasa tc",
    ];
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
        "wechat",
        "weixin",
        "qq",
        "tim",
        "linuxqq",
        "wps",
        "wpp",
        "et",
        "wpspdf",
        "netease-cloud-music",
        "dingtalk",
        "youdao-dict",
        "baidunetdisk",
        "baidu-netdisk",
        "foxmail",
        "sogou-qimpanel",
        "sogoupinyin",
        "wechat-devtools",
        "xunlei",
        "thunder",
        "feishu",
        "lark",
        "wxwork",
        "electronic-wechat",
    ];
    if let Ok(path) = env::var("PATH") {
        let bins: BTreeSet<&str> = binaries.iter().copied().collect();
        for dir in path.split(':') {
            if let Ok(rd) = fs::read_dir(dir) {
                for e in rd.flatten() {
                    if let Some(name) = e.file_name().to_str() {
                        let n = name.to_lowercase();
                        if bins.contains(n.as_str())
                            || n.starts_with("sogou")
                            || n.starts_with("com.tencent")
                        {
                            found.insert(n);
                        }
                    }
                }
            }
        }
    }

    // 2. Vendor-prefixed install dirs (deepin/UOS style /opt/apps, flatpak, snap).
    let prefixes = [
        "com.qq.",
        "com.tencent.",
        "com.alibaba.",
        "com.baidu.",
        "com.netease.",
        "com.taobao.",
        "com.sogou.",
        "com.xunlei.",
        "cn.wps",
        "com.deepin.",
        "com.uniontech.",
        "com.aliyun.",
    ];
    for dir in [
        "/opt/apps".to_string(),
        "/var/lib/flatpak/app".to_string(),
        format!("{}/snap", home().display()),
    ] {
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if prefixes.iter().any(|p| n.starts_with(p)) {
                    found.insert(format!("{n} ({dir})"));
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
        if std::path::Path::new(&d).exists() {
            found.insert(d);
        }
    }

    // 3. Desktop entries + dpkg names.
    for apps_dir in [
        "/usr/share/applications".to_string(),
        format!("{}/.local/share/applications", home().display()),
    ] {
        if let Ok(rd) = fs::read_dir(&apps_dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if contains_any(
                    &n,
                    &[
                        "wechat", "qq", "wps", "sogou", "netease", "baidu", "tencent", "dingtalk",
                        "feishu", "weixin",
                    ],
                )
                .is_some()
                {
                    found.insert(format!(
                        "{} (desktop entry)",
                        n.trim_end_matches(".desktop")
                    ));
                }
            }
        }
    }
    if let Some(dpkg) = run("dpkg", &["-l"]) {
        for l in dpkg.lines() {
            let low = l.to_lowercase();
            if contains_any(
                &low,
                &[
                    "wechat",
                    "weixin",
                    "linuxqq",
                    ".qq.",
                    "wps-office",
                    "sogou",
                    "netease",
                    "baidu",
                    "tencent",
                    "dingtalk",
                    "xunlei",
                    "deepin-wine",
                    "ukui-",
                    "kylin-",
                ],
            )
            .is_some()
            {
                if let Some(pkg) = l.split_whitespace().nth(1) {
                    found.insert(format!("{pkg} (dpkg)"));
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

// ---------------------------------------------------------------- mirrors

fn apt_mirrors(v: &mut Vec<Finding>) {
    let mut files: Vec<std::path::PathBuf> = vec![
        "/etc/apt/sources.list".into(),
        "/etc/pacman.d/mirrorlist".into(),
    ];
    for glob_dir in ["/etc/apt/sources.list.d", "/etc/yum.repos.d"] {
        if let Ok(rd) = fs::read_dir(glob_dir) {
            for e in rd.flatten() {
                files.push(e.path());
            }
        }
    }
    crate::local::scan_mirror_files(v, files);
}

// ---------------------------------------------------------------- wifi

fn wifi(v: &mut Vec<Finding>) {
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
            v.push(Finding::signal(
                Category::Identity,
                "wifi ssid",
                s,
                6.0,
                false,
                "SSID contains Han characters",
            ));
        } else if l.starts_with("chinanet")
            || l.starts_with("cmcc")
            || l.starts_with("chinaunicom")
            || l.starts_with("china-net")
        {
            v.push(Finding::signal(
                Category::Identity,
                "wifi ssid",
                s,
                6.0,
                true,
                "Chinese carrier hotspot SSID",
            ));
        } else {
            v.push(Finding::fact(Category::Identity, "wifi ssid", s));
        }
    }
}
