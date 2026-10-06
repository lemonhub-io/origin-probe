//! Evidence combination in log-odds space. Prior odds are neutral (1:1,
//! i.e. 50%). Every finding's likelihood ratio multiplies the odds; each
//! category's total contribution is capped so that many correlated weak
//! signals in one area cannot dominate the verdict.

use std::collections::BTreeMap;

use crate::finding::{Category, Finding};

/// Per-category cap on |log(lr)| contributions — ln(25), i.e. one category
/// alone can shift the odds by at most a factor of 25.
const CAT_CAP: f64 = 3.218_875_824_868_201;

#[derive(Debug)]
pub struct Score {
    /// Final probability in (0, 1).
    pub prob: f64,
    /// Total log-odds before the sigmoid.
    pub log_odds: f64,
    /// Number of evidence rows pointing specifically at mainland China.
    pub mainland_hits: usize,
    /// Number of evidence rows pointing against (lr < 1).
    pub counter_evidence: usize,
    /// Net log-odds contribution per category, after capping.
    pub by_category: BTreeMap<Category, f64>,
}

pub fn combine(findings: &[Finding]) -> Score {
    let mut raw: BTreeMap<Category, f64> = BTreeMap::new();
    let mut mainland_hits = 0usize;
    let mut counter = 0usize;
    for f in findings {
        if (f.lr - 1.0).abs() < f64::EPSILON || f.lr <= 0.0 {
            continue;
        }
        *raw.entry(f.category).or_default() += f.lr.ln();
        if f.lr > 1.0 {
            if f.mainland {
                mainland_hits += 1;
            }
        } else {
            counter += 1;
        }
    }
    let mut log_odds = 0.0;
    for c in raw.values_mut() {
        *c = c.clamp(-CAT_CAP, CAT_CAP);
        log_odds += *c;
    }
    let prob = 1.0 / (1.0 + (-log_odds).exp());
    Score {
        prob: prob.clamp(0.001, 0.999),
        log_odds,
        mainland_hits,
        counter_evidence: counter,
        by_category: raw,
    }
}

pub fn verdict(p: f64) -> &'static str {
    match p {
        p if p >= 0.9 => "very likely",
        p if p >= 0.7 => "likely",
        p if p >= 0.55 => "leaning yes",
        p if p >= 0.45 => "unclear / mixed evidence",
        p if p >= 0.3 => "leaning no",
        p if p >= 0.1 => "unlikely",
        _ => "very unlikely",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Finding};

    fn sig(lr: f64, cat: Category) -> Finding {
        Finding::signal(cat, "t", "t", lr, false, "")
    }

    #[test]
    fn empty_is_neutral() {
        assert_eq!(combine(&[]).prob, 0.5);
    }

    #[test]
    fn single_signal_scales() {
        // odds 1:1 * 10 => p = 10/11
        let s = combine(&[sig(10.0, Category::Locale)]);
        assert!((s.prob - 10.0 / 11.0).abs() < 1e-9);
    }

    #[test]
    fn counter_evidence_divides() {
        // lr=0.5 halves the odds
        let s = combine(&[sig(0.5, Category::Network)]);
        assert!((s.prob - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn category_cap_limits_correlated_signals() {
        // 4 signals of lr=10 in one category: ln(10)*4 = 9.2 > cap ln(25)
        let s = combine(&vec![sig(10.0, Category::Input); 4]);
        assert!((s.prob - 25.0 / 26.0).abs() < 1e-9);
    }

    #[test]
    fn different_categories_not_capped_together() {
        // ln(10)+ln(10) across two categories = ln(100) => p = 100/101
        let s = combine(&[sig(10.0, Category::Input), sig(10.0, Category::Locale)]);
        assert!((s.prob - 100.0 / 101.0).abs() < 1e-9);
    }

    #[test]
    fn mainland_and_counter_counted() {
        let mut f = sig(5.0, Category::Network);
        f.mainland = true;
        let s = combine(&[f, sig(0.5, Category::Locale)]);
        assert_eq!(s.mainland_hits, 1);
        assert_eq!(s.counter_evidence, 1);
    }
}
