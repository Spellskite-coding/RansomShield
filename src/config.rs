use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Only log detections, never touch the offending process.
    Monitor,
    /// Log and kill the offending process.
    Enforce,
}

/// An executable exempted from the burst/entropy heuristic. Anchored on
/// both path and content hash - see `trust::TrustStore` for why.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedExecutable {
    pub path: PathBuf,
    /// Lowercase hex SHA-256 of the executable's current content, e.g. the
    /// output of `sha256sum /usr/bin/gpg`.
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Directories to watch (recursively, via FAN_MARK_FILESYSTEM on their mount).
    pub watch_dirs: Vec<PathBuf>,

    /// Decoy files. Any write to one of these is treated as a near-certain
    /// ransomware signal, regardless of entropy or rate.
    #[serde(default)]
    pub honeypots: Vec<PathBuf>,

    pub mode: Mode,

    /// Shannon entropy (bits/byte, 0..8) above which a rewritten file is
    /// considered "encrypted-looking".
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Number of high-entropy file writes by the same PID within
    /// `burst_window_secs` that triggers the rate-based heuristic.
    #[serde(default = "default_burst_file_count")]
    pub burst_file_count: usize,

    #[serde(default = "default_burst_window_secs")]
    pub burst_window_secs: u64,

    /// How many bytes to sample from a closed file to compute entropy.
    #[serde(default = "default_sample_bytes")]
    pub sample_bytes: usize,

    /// Where quarantined files (and the manifest of what was quarantined)
    /// are kept for later review by a sysadmin.
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: PathBuf,

    /// Only count a high-entropy write toward the burst heuristic if its
    /// directory has previously been observed holding ordinary
    /// (low-entropy) content. This is what tells apart "your documents
    /// folder is suddenly full of ciphertext" (ransomware) from "your
    /// backup/export folder just received a batch of new archives"
    /// (routine, already-compressed output) - both look identical from a
    /// single event's entropy alone. Directories a honeypot lives in, or
    /// that already contain real files when ransomshield starts watching
    /// them, qualify immediately. Disable only if you understand this
    /// weakens detection in directories the daemon has never seen
    /// low-entropy activity in.
    #[serde(default = "default_true")]
    pub require_directory_baseline: bool,

    /// Where human-readable incident reports (one .txt file per detection)
    /// are written, so a sysadmin can see what ransomshield did after the
    /// fact.
    #[serde(default = "default_incident_reports_dir")]
    pub incident_reports_dir: PathBuf,

    /// Optional command run (not waited on) on every detection, with
    /// incident details passed as RANSOMSHIELD_* environment variables.
    /// Plug in your own email/Slack/PagerDuty/SMS notifier here; left
    /// unset, ransomshield only logs and writes the text report.
    #[serde(default)]
    pub notify_command: Option<String>,

    /// Executables exempted from the burst/entropy heuristic (e.g. a known
    /// backup or encryption tool) - see `TrustedExecutable`. Honeypot
    /// detection always applies regardless of this list.
    #[serde(default)]
    pub trusted_executables: Vec<TrustedExecutable>,
}

fn default_true() -> bool {
    true
}

fn default_entropy_threshold() -> f64 {
    7.5
}
fn default_burst_file_count() -> usize {
    15
}
fn default_burst_window_secs() -> u64 {
    10
}
fn default_sample_bytes() -> usize {
    8192
}
fn default_quarantine_dir() -> PathBuf {
    PathBuf::from("/var/lib/ransomshield/quarantine")
}
fn default_incident_reports_dir() -> PathBuf {
    PathBuf::from("/var/lib/ransomshield/incidents")
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: Config = serde_json::from_str(&data)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        anyhow::ensure!(!cfg.watch_dirs.is_empty(), "watch_dirs must not be empty");
        Ok(cfg)
    }
}
