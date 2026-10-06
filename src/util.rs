//! Shared helpers for collectors.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Run a command, return trimmed stdout on success.
pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Raw stdout bytes (for outputs that may not be UTF-8, e.g. GBK consoles).
#[cfg(windows)]
pub fn run_bytes(cmd: &str, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new(cmd).args(args).output().ok()?;
    (out.status.success() && !out.stdout.is_empty()).then_some(out.stdout)
}

/// Run a PowerShell snippet, forcing UTF-8 output so CJK survives.
#[cfg(windows)]
pub fn powershell(script: &str) -> Option<String> {
    let full = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}");
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &full],
    )
    .map(|s| s.trim_start_matches('\u{feff}').to_string())
}

/// Registry query helper: `reg query "HK..." /v Value` -> the REG_SZ data.
#[cfg(windows)]
pub fn reg_query(key: &str, value: &str) -> Option<String> {
    let out = run("reg", &["query", key, "/v", value])?;
    out.lines()
        .find(|l| l.contains("REG_"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.to_string())
}

pub fn home() -> PathBuf {
    PathBuf::from(
        env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .unwrap_or_default(),
    )
}

pub fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok()
}

pub fn has_han(s: &str) -> bool {
    s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
}

/// True if the byte slice contains non-ASCII bytes — used on Windows where
/// console output is in the OEM/ANSI codepage (GBK on zh-CN), so proper
/// UTF-8 decoding of CJK isn't guaranteed.
#[cfg(windows)]
pub fn has_nonascii(b: &[u8]) -> bool {
    b.iter().any(|&x| x >= 0x80)
}

pub fn contains_any(hay: &str, needles: &[&str]) -> Option<String> {
    let low = hay.to_lowercase();
    needles
        .iter()
        .find(|n| low.contains(&n.to_lowercase()))
        .map(|s| s.to_string())
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
