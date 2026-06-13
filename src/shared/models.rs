use serde::Deserialize;

/// Maintainer reputation information for trust factor computation.
#[derive(Debug, Clone)]
pub struct MaintainerInfo {
    /// Oldest package first_submitted timestamp as proxy for account age.
    pub account_created_date: u64,
    /// Number of packages maintained.
    pub number_of_packages: u32,
    /// Whether the current maintainer is the original submitter.
    pub is_original_submitter: bool,
    /// Days since maintainer change (orphan takeover or submitter changed).
    pub days_since_takeover: Option<u32>,
}

/// Information about an NPM package referenced in PKGBUILD.
#[derive(Debug, Clone, Deserialize)]
pub struct NpmPackageInfo {
    pub scripts: NpmScripts,
    #[serde(default)]
    pub maintainer_account_age: u32,    // days
    #[serde(default)]
    pub maintainer_package_count: u32,
    #[serde(default)]
    pub github_repo_exists: bool,
    #[serde(default)]
    pub github_stars: u32,
    #[serde(default)]
    pub github_commit_freshness: u32,   // days since last commit
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NpmScripts {
    #[serde(default)]
    pub preinstall: String,
    #[serde(default)]
    pub install: String,
    #[serde(default)]
    pub postinstall: String,
}

/// A single AUR comment with its parsed date.
#[derive(Debug, Clone)]
pub struct CommentEntry {
    /// Unix timestamp parsed from the comment date (e.g. "2025-08-04 15:08 (UTC)").
    pub timestamp: i64,
    /// Comment text with HTML tags stripped.
    pub text: String,
}

/// All data a feature needs to run its analysis.
pub struct PackageContext {
    pub name: String,
    pub metadata: Option<AurPackage>,
    pub pkgbuild_content: Option<String>,
    pub install_script_content: Option<String>,
    pub prior_pkgbuild_content: Option<String>,
    pub git_log: Vec<GitCommit>,
    pub maintainer_packages: Vec<AurPackage>,
    pub github_stars: Option<u32>,
    pub github_not_found: bool,
    pub aur_comments: Vec<CommentEntry>,
    /// Pre-computed maintainer reputation info (set by coordinator).
    pub maintainer_info: Option<MaintainerInfo>,
    /// True if orphan takeover pattern detected (B-ORPHAN-TAKEOVER signal emitted).
    pub has_orphan_takeover: bool,
    /// True if new malicious diff detected (T-MALICIOUS-DIFF signal emitted).
    pub has_new_malicious_diff: bool,
    /// NPM package metadata (set if PKGBUILD uses npm/yarn and package identified).
    pub npm_info: Option<NpmPackageInfo>,
}

/// Package metadata from AUR RPC API v5.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurPackage {
    pub name: String,
    pub package_base: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    pub num_votes: u32,
    pub popularity: f64,
    pub out_of_date: Option<u64>,
    pub maintainer: Option<String>,
    pub submitter: Option<String>,
    pub first_submitted: u64,
    #[allow(dead_code)]
    pub last_modified: u64,
    pub license: Option<Vec<String>>,
}

/// Lightweight entry from the AUR metadata dump (packages-meta-v1.json.gz).
#[derive(Debug, Deserialize)]
pub struct MetaDumpPackage {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "LastModified")]
    pub last_modified: u64,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
}

/// A single git commit from the AUR package repo.
#[derive(Debug, Clone)]
pub struct GitCommit {
    pub author: String,
    pub timestamp: u64,
    pub diff: Option<String>,
}
