mod finding;
mod local;
mod net;
mod score;

use std::io::{self, BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Instant;

use finding::{Category, Finding};

fn main() -> ExitCode {
    let mut offline = false;
    let mut json_out = false;
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--offline" | "--no-net" => offline = true,
            "--json" => json_out = true,
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown option: {other}\n");
                print_help();
                return ExitCode::FAILURE;
            }
        }
    }

    if !consent(offline) {
        eprintln!("\nAborted: consent not given. Nothing was collected.");
        return ExitCode::from(2);
    }

    let t0 = Instant::now();
    let mut findings = local::collect();
    if offline {
        findings.push(Finding::fact(
            Category::Network,
            "network checks",
            "skipped (--offline)",
        ));
    } else {
        eprintln!("[*] probing network (reachability + IP geolocation, up to ~10s)...");
        findings.extend(net::collect());
    }

    let s = score::combine(&findings);
    if json_out {
        print_json(&findings, &s);
    } else {
        print_report(&findings, &s, t0.elapsed(), offline);
    }
    ExitCode::SUCCESS
}

fn print_help() {
    println!(
        "origin-probe — estimate the likelihood that the current device user is Chinese

USAGE: origin-probe [--offline] [--json]

  --offline   skip all network checks (DNS table is still read locally)
  --json      emit findings + score as JSON instead of the text report
  -h, --help  show this help

The tool collects ONLY after you type 'yes' at the consent prompt."
    );
}

fn consent(offline: bool) -> bool {
    let net = if offline {
        "  - DISABLED via --offline\n"
    } else {
        "  - /etc/resolv.conf DNS resolvers\n  - TCP reachability to a fixed list of CN/global sites\n  - public IP geolocation via ip-api.com / ipapi.co / ipinfo.io\n"
    };
    // Everything until the report goes to stderr so that `--json` (or a
    // piped report) keeps stdout machine-readable.
    eprintln!(
        "=====================================================================
 origin-probe — consent required
=====================================================================
This tool will inspect the CURRENT device and report a probability that
its user is Chinese. To do that it will collect:

 Local:
  - os-release, kernel, arch, CPU model, DMI vendor, hostname, username
  - machine-id and MAC addresses (identifiers; shown truncated/masked)
  - locale env vars, locale.conf, generated locales, timezone
  - input-method env vars, processes, config dirs and packages
  - zh-capable fonts (fc-list)
  - markers of installed Chinese software (PATH, /opt/apps, flatpak,
    snap, .desktop entries, dpkg names)
  - package-mirror config files (~/.npmrc, pip.conf, cargo config,
    apt sources, docker daemon.json, maven settings, go env, ...)
  - git user.name/email, shell-history files (only the COUNT of lines
    containing Han characters; content is never printed), XDG dir names
  - current WiFi SSID
 Network:{net}
Data leaves this machine ONLY via the read-only geolocation queries
listed above (they expose your public IP to those services). Nothing is
written to disk and nothing else is transmitted.
====================================================================="
    );
    eprint!("Type 'yes' to start the scan: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => matches!(line.trim().to_lowercase().as_str(), "yes" | "y"),
    }
}

fn print_json(findings: &[Finding], s: &score::Score) {
    let out = serde_json::json!({
        "probability": s.prob,
        "verdict": score::verdict(s.prob),
        "log_odds": s.log_odds,
        "mainland_specific_hits": s.mainland_hits,
        "counter_evidence_rows": s.counter_evidence,
        "findings": findings,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn print_report(
    findings: &[Finding],
    s: &score::Score,
    elapsed: std::time::Duration,
    offline: bool,
) {
    let tty = io::stdout().is_terminal();
    let (g, r, bold, dim, x) = if tty {
        ("\x1b[32m", "\x1b[31m", "\x1b[1m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "", "")
    };

    println!("\n=====================================================================");
    println!(
        " origin-probe — report   (collected in {:.1}s{})",
        elapsed.as_secs_f64(),
        if offline { ", offline" } else { "" }
    );
    println!("=====================================================================");

    for cat in Category::ALL {
        let rows: Vec<&Finding> = findings.iter().filter(|f| f.category == cat).collect();
        if rows.is_empty() {
            continue;
        }
        println!("\n{bold}[{}]{x}", cat.title());
        for f in &rows {
            let mark = if f.lr > 1.0 {
                format!("{g}+{x}")
            } else if f.lr < 1.0 {
                format!("{r}-{x}")
            } else {
                " ".to_string()
            };
            let obs = if f.lr == 1.0 {
                format!("{dim}{}{x}", truncate(&f.observed, 88))
            } else {
                truncate(&f.observed, 88)
            };
            println!("  {mark} {:<26} {}", truncate(&f.name, 26), obs);
        }
    }

    let mut evidence: Vec<&Finding> = findings
        .iter()
        .filter(|f| (f.lr - 1.0).abs() > f64::EPSILON)
        .collect();
    println!("\n---------------------------------------------------------------------");
    println!(" Evidence");
    println!("---------------------------------------------------------------------");
    if evidence.is_empty() {
        println!("  (no signals found either way)");
    } else {
        evidence.sort_by(|a, b| {
            b.lr.ln()
                .abs()
                .partial_cmp(&a.lr.ln().abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for f in &evidence {
            // Pad before coloring so ANSI escapes don't skew column width.
            let plain = if f.lr > 1.0 { "for" } else { "against" };
            let arrow = format!("{}{:<7}{x}", if f.lr > 1.0 { g } else { r }, plain);
            println!(
                "  x{:<7.2} {:<26} {} {}",
                f.lr.max(1.0 / f.lr),
                truncate(&f.name, 26),
                arrow,
                if f.note.is_empty() {
                    f.observed.clone()
                } else {
                    f.note.clone()
                }
            );
        }
    }

    println!("\n---------------------------------------------------------------------");
    println!(" Verdict");
    println!("---------------------------------------------------------------------");
    let pct = s.prob * 100.0;
    let pct_s = if !(1.0..=99.0).contains(&pct) {
        format!("{pct:.1}")
    } else {
        format!("{pct:.0}")
    };
    println!("  Estimated probability the device user is Chinese:  {bold}{pct_s}%{x}");
    println!("  Qualitative verdict: {}", score::verdict(s.prob));
    println!(
        "  Mainland-specific signals: {}   counter-evidence rows: {}",
        s.mainland_hits, s.counter_evidence
    );
    if !s.by_category.is_empty() {
        let mut parts: Vec<String> = s
            .by_category
            .iter()
            .filter(|(_, w)| w.abs() > 0.05)
            .map(|(c, w)| format!("{} x{:.2}", c.title(), w.exp()))
            .collect();
        parts.sort();
        println!("  Per-category odds multiplier: {}", parts.join("   "));
    }
    println!(
        "\n  Note: statistical heuristics only. Locale/TZ/software can be set by\n  anyone; IP geolocation reflects the egress point, not the person."
    );
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
