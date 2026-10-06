//! Network collectors: DNS resolvers, a TCP reachability matrix designed to
//! detect Great-Firewall-style filtering, and public-IP geolocation.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::finding::{Category, Finding};

/// Sites normally reachable only from outside mainland China (blocked by the
/// GFW). Reaching them quickly is evidence *against* a mainland user.
const BLOCKED_IN_CN: &[&str] = &[
    "www.google.com",
    "www.youtube.com",
    "www.facebook.com",
    "en.wikipedia.org",
    "x.com",
    "www.instagram.com",
];

/// Popular Chinese services; fast reachability supports a CN user.
const CN_SERVICES: &[&str] = &[
    "www.baidu.com",
    "www.qq.com",
    "www.taobao.com",
    "www.jd.com",
    "www.163.com",
];

/// Neutral control hosts reachable nearly everywhere.
const CONTROL: &[&str] = &["github.com", "www.cloudflare.com", "crates.io"];

const CN_DNS: &[&str] = &[
    "114.114.114.114",
    "114.114.115.115", // 114DNS
    "223.5.5.5",
    "223.6.6.6", // AliDNS
    "119.29.29.29",
    "182.254.116.116", // DNSPod/Tencent
    "180.76.76.76",    // Baidu
    "1.2.4.8",
    "210.2.4.8", // CNNIC
];

const GLOBAL_DNS: &[&str] = &["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"];

pub fn collect() -> Vec<Finding> {
    let mut v = Vec::new();
    resolvers(&mut v);
    reachability(&mut v);
    geolocation(&mut v);
    v
}

// --------------------------------------------------------------- resolvers

fn resolvers(v: &mut Vec<Finding>) {
    let mut nameservers = Vec::new();
    if let Ok(c) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in c.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("nameserver") {
                let ns = rest.trim();
                if !ns.is_empty() {
                    nameservers.push(ns.to_string());
                }
            }
        }
    }
    if nameservers.is_empty() {
        v.push(Finding::fact(
            Category::Network,
            "dns resolvers",
            "none found",
        ));
        return;
    }
    let joined = nameservers.join(", ");
    if nameservers.iter().any(|n| CN_DNS.contains(&n.as_str())) {
        v.push(Finding::signal(
            Category::Network,
            "dns resolvers",
            joined,
            8.0,
            true,
            "a mainland Chinese public DNS is configured",
        ));
    } else if nameservers.iter().any(|n| GLOBAL_DNS.contains(&n.as_str())) {
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

// ------------------------------------------------------------- reachability

struct Probe {
    host: &'static str,
    ok: bool,
    ms: u128,
    err: Option<String>,
}

fn probe(host: &'static str) -> Probe {
    let t0 = Instant::now();
    let addrs: Vec<SocketAddr> = match (host, 443).to_socket_addrs() {
        Ok(it) => it.take(3).collect(),
        Err(e) => {
            return Probe {
                host,
                ok: false,
                ms: 0,
                err: Some(format!("dns: {e}")),
            };
        }
    };
    if addrs.is_empty() {
        return Probe {
            host,
            ok: false,
            ms: 0,
            err: Some("dns: no address".into()),
        };
    }
    let mut last_err = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_millis(1800)) {
            Ok(_) => {
                return Probe {
                    host,
                    ok: true,
                    ms: t0.elapsed().as_millis(),
                    err: None,
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Probe {
        host,
        ok: false,
        ms: t0.elapsed().as_millis(),
        err: last_err,
    }
}

fn reachability(v: &mut Vec<Finding>) {
    let (tx, rx) = mpsc::channel();
    let mut n = 0usize;
    for host in BLOCKED_IN_CN.iter().chain(CN_SERVICES).chain(CONTROL) {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(probe(host));
        });
        n += 1;
    }
    drop(tx);
    let probes: Vec<Probe> = rx.iter().take(n).collect();

    let fmt = |ps: &[&Probe]| -> String {
        ps.iter()
            .map(|p| {
                if p.ok {
                    format!("{}({}ms)", p.host, p.ms)
                } else {
                    let why = p.err.as_deref().unwrap_or("fail");
                    let why = if why.len() > 24 { &why[..24] } else { why };
                    format!("{}({why})", p.host)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    let blocked: Vec<&Probe> = probes
        .iter()
        .filter(|p| BLOCKED_IN_CN.contains(&p.host))
        .collect();
    let cn: Vec<&Probe> = probes
        .iter()
        .filter(|p| CN_SERVICES.contains(&p.host))
        .collect();
    let ctrl: Vec<&Probe> = probes
        .iter()
        .filter(|p| CONTROL.contains(&p.host))
        .collect();

    let blocked_ok = blocked.iter().filter(|p| p.ok).count();
    let cn_ok = cn.iter().filter(|p| p.ok).count();
    let ctrl_ok = ctrl.iter().filter(|p| p.ok).count();
    let cn_min = cn.iter().filter(|p| p.ok).map(|p| p.ms).min().unwrap_or(0);

    v.push(Finding::fact(
        Category::Network,
        "tcp:443 cn services",
        fmt(&cn),
    ));
    v.push(Finding::fact(
        Category::Network,
        "tcp:443 gfw-blocked sites",
        fmt(&blocked),
    ));
    v.push(Finding::fact(
        Category::Network,
        "tcp:443 control sites",
        fmt(&ctrl),
    ));

    if ctrl_ok == 0 && cn_ok == 0 {
        v.push(Finding::fact(
            Category::Network,
            "connectivity",
            "no outbound connectivity detected — reachability evidence skipped",
        ));
        return;
    }

    // The classic mainland signature: everything blocked by the GFW fails
    // while domestic services answer quickly.
    if blocked_ok == 0 && cn_ok >= 3 {
        v.push(Finding::signal(
            Category::Network,
            "gfw signature",
            format!(
                "0/{len} blocked sites reachable, {cn_ok}/{clen} CN services reachable",
                len = blocked.len(),
                clen = cn.len()
            ),
            15.0,
            true,
            "Google/YouTube/FB/Wikipedia all unreachable while CN services work",
        ));
    } else if blocked_ok >= 5 {
        v.push(Finding::signal(
            Category::Network,
            "gfw signature",
            format!(
                "{blocked_ok}/{len} blocked sites reachable",
                len = blocked.len()
            ),
            0.35,
            false,
            "GFW-blocked sites reachable — outside mainland or on a VPN/proxy",
        ));
    } else if blocked_ok > 0 && blocked_ok <= 2 && cn_ok >= 3 {
        v.push(Finding::signal(
            Category::Network,
            "gfw signature",
            format!(
                "{blocked_ok}/{len} blocked sites reachable",
                len = blocked.len()
            ),
            3.0,
            true,
            "partial reachability of blocked sites (unstable proxy or edge case)",
        ));
    }

    if cn_ok >= 3 && cn_min > 0 && cn_min < 50 {
        v.push(Finding::signal(
            Category::Network,
            "cn service latency",
            format!("best CN service RTT {cn_min}ms"),
            3.0,
            true,
            "sub-50ms RTT to CN services suggests being on/near the CN network",
        ));
    }
}

// ------------------------------------------------------------- geolocation

fn geolocation(v: &mut Vec<Finding>) {
    let endpoints = [
        ("ip-api.com", "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,query,timezone"),
        ("ipapi.co", "https://ipapi.co/json/"),
        ("ipinfo.io", "https://ipinfo.io/json"),
    ];
    for (name, url) in endpoints {
        let Ok(resp) = ureq::get(url)
            .timeout(Duration::from_secs(6))
            .set("User-Agent", "origin-probe/0.2")
            .call()
        else {
            continue;
        };
        let Ok(j) = resp.into_json::<serde_json::Value>() else {
            continue;
        };
        if j.get("status").and_then(|s| s.as_str()) == Some("fail") {
            continue;
        }
        let get = |keys: &[&str]| -> String {
            keys.iter()
                .find_map(|k| j.get(*k).and_then(|x| x.as_str()))
                .unwrap_or("")
                .to_string()
        };
        // Require at least one recognizable field so we don't accept an
        // arbitrary captive-portal page as a valid answer.
        if get(&["query", "ip"]).is_empty()
            && get(&["countryCode", "country_code", "country"]).is_empty()
        {
            continue;
        }
        let ip = get(&["query", "ip"]);
        let cc = get(&["countryCode", "country_code", "country"]).to_uppercase();
        let country = get(&["country", "country_name"]);
        let city = get(&["city"]);
        let region = get(&["regionName", "region"]);
        let isp = get(&["isp", "org"]);
        let tz = get(&["timezone"]);

        v.push(Finding::fact(
            Category::Network,
            "public ip",
            format!("{ip}  (via {name})"),
        ));
        if !city.is_empty() || !region.is_empty() || !country.is_empty() {
            v.push(Finding::fact(
                Category::Network,
                "ip geolocation",
                format!("{country} / {region} / {city}"),
            ));
        }
        if !isp.is_empty() {
            let l = isp.to_lowercase();
            let cn_isp = [
                "telecom", "unicom", "mobile", "cmcc", "chinanet", "cnnic", "aliyun", "tencent",
                "cernet", "cstnet", "china",
            ]
            .iter()
            .any(|k| l.contains(k));
            if cn_isp {
                v.push(Finding::signal(
                    Category::Network,
                    "isp/org",
                    isp.clone(),
                    4.0,
                    true,
                    "Chinese ISP/cloud provider",
                ));
            } else {
                v.push(Finding::fact(Category::Network, "isp/org", isp));
            }
        }
        if !tz.is_empty() {
            v.push(Finding::fact(Category::Network, "geo timezone", tz));
        }

        let (lr, ml, note) = match cc.as_str() {
            "CN" => (25.0, true, "public IP geolocates to mainland China"),
            "HK" | "MO" | "TW" => (2.5, false, "IP in greater-China region (HK/MO/TW)"),
            "SG" => (
                1.2,
                false,
                "IP in Singapore (large Chinese-speaking population)",
            ),
            "" => (1.0, false, ""),
            _ => (0.12, false, "public IP geolocates outside China"),
        };
        if lr != 1.0 {
            v.push(Finding::signal(
                Category::Network,
                "ip country",
                cc.clone(),
                lr,
                ml,
                note,
            ));
        }
        return;
    }
    v.push(Finding::fact(
        Category::Network,
        "ip geolocation",
        "all geolocation endpoints unreachable",
    ));
}
