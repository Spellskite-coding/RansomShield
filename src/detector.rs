use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// Too many *distinct files* high-entropy-rewritten by the same PID in
    /// the time window.
    Burst { count: usize },
}

/// Tracks, per originating PID, the set of distinct files recently seen
/// with a high-entropy write, so we can catch the "many files rewritten as
/// ciphertext in a few seconds" pattern that a single event can't reveal on
/// its own. Deliberately keyed on distinct paths (not raw write events) so
/// that one large file written in many chunks - each producing its own
/// FAN_MODIFY/FAN_CLOSE_WRITE event - doesn't get mistaken for many files.
///
/// Also tracks, per directory, whether ordinary (low-entropy) content has
/// ever been seen there. A burst of high-entropy writes only counts as
/// suspicious in a directory that used to hold plain content - otherwise a
/// directory that only ever receives already-compressed output (backups,
/// exports, media) would trip the same heuristic as actual encryption.
pub struct Detector {
    burst_file_count: usize,
    burst_window: Duration,
    require_directory_baseline: bool,
    recent_writes: HashMap<i32, HashMap<PathBuf, Instant>>,
    directories_with_plaintext_history: HashSet<PathBuf>,
}

impl Detector {
    pub fn new(cfg: &Config) -> Self {
        Self {
            burst_file_count: cfg.burst_file_count,
            burst_window: Duration::from_secs(cfg.burst_window_secs),
            require_directory_baseline: cfg.require_directory_baseline,
            recent_writes: HashMap::new(),
            directories_with_plaintext_history: HashSet::new(),
        }
    }

    /// Record that `path` was written with ordinary (low-entropy) content,
    /// establishing its directory as one that holds real plaintext data.
    pub fn note_plaintext_activity(&mut self, path: &Path) {
        if let Some(dir) = path.parent() {
            self.directories_with_plaintext_history.insert(dir.to_path_buf());
        }
    }

    /// Whether `path`'s directory, or any ancestor of it, has previously
    /// held ordinary plaintext content. Walking up the ancestor chain
    /// (rather than checking only the immediate parent) closes an evasion
    /// path where an attacker creates a brand-new subdirectory under an
    /// already-baselined tree (e.g. a fresh subfolder inside a user's
    /// already-active home directory) and fills only that subdirectory with
    /// high-entropy output: the subdirectory itself never received a
    /// plaintext write, so a same-directory-only check would never flag it,
    /// even though everything above it is known-real user data.
    fn has_plaintext_baseline(&self, path: &Path) -> bool {
        let mut dir = path.parent();
        while let Some(d) = dir {
            if self.directories_with_plaintext_history.contains(d) {
                return true;
            }
            dir = d.parent();
        }
        false
    }

    /// Record a high-entropy write to `path` from `pid` and return the
    /// verdict for it.
    pub fn observe_high_entropy_write(&mut self, pid: i32, path: &Path) -> Verdict {
        if self.require_directory_baseline && !self.has_plaintext_baseline(path) {
            return Verdict::Clean;
        }

        let now = Instant::now();
        let window = self.burst_window;

        // Opportunistically drop bookkeeping for any pid whose most recent
        // high-entropy write has aged out of the window, for every pid, not
        // just this one. Without this, a pid that never reaches
        // burst_file_count - the overwhelming majority of activity on a
        // busy host: shells, cron jobs, short-lived admin commands - would
        // sit in this map for the rest of the daemon's lifetime, since
        // forget() is only ever called after an actual detection. Left
        // unbounded, that's a slow memory leak driven by ordinary process
        // churn, not just attacker behavior.
        self.recent_writes.retain(|_, files| {
            files.retain(|_, &mut seen| now.duration_since(seen) <= window);
            !files.is_empty()
        });

        let files = self.recent_writes.entry(pid).or_default();
        files.insert(path.to_path_buf(), now);

        if files.len() >= self.burst_file_count {
            Verdict::Burst { count: files.len() }
        } else {
            Verdict::Clean
        }
    }

    /// Distinct files recently touched by `pid`, for quarantine purposes.
    pub fn files_for_pid(&self, pid: i32) -> Vec<PathBuf> {
        self.recent_writes
            .get(&pid)
            .map(|files| files.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Drop bookkeeping for a PID once we've responded to it (killed or
    /// otherwise dealt with), so a reused PID starts with a clean slate.
    pub fn forget(&mut self, pid: i32) {
        self.recent_writes.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            watch_dirs: vec![PathBuf::from("/data")],
            honeypots: vec![],
            mode: crate::config::Mode::Enforce,
            entropy_threshold: 7.5,
            burst_file_count: 3,
            burst_window_secs: 10,
            sample_bytes: 8192,
            quarantine_dir: PathBuf::from("/tmp/quarantine"),
            require_directory_baseline: true,
            incident_reports_dir: PathBuf::from("/tmp/incidents"),
            notify_command: None,
            trusted_executables: vec![],
        }
    }

    #[test]
    fn baseline_extends_to_a_brand_new_subdirectory_of_a_known_tree() {
        let cfg = test_config();
        let mut d = Detector::new(&cfg);
        d.note_plaintext_activity(Path::new("/data/victim/seed.txt"));

        // A subdirectory that itself never held plaintext, but sits under an
        // already-baselined parent, must still count toward the burst
        // heuristic - otherwise creating a fresh subfolder is a free pass.
        let sub = Path::new("/data/victim/brand_new_subdir");
        assert!(matches!(
            d.observe_high_entropy_write(1234, &sub.join("a.bin")),
            Verdict::Clean
        ));
        assert!(matches!(
            d.observe_high_entropy_write(1234, &sub.join("b.bin")),
            Verdict::Clean
        ));
        assert!(matches!(
            d.observe_high_entropy_write(1234, &sub.join("c.bin")),
            Verdict::Burst { count: 3 }
        ));
    }

    #[test]
    fn directories_with_no_baselined_ancestor_stay_clean() {
        let cfg = test_config();
        let mut d = Detector::new(&cfg);
        // No note_plaintext_activity call anywhere: nothing in this tree has
        // ever been observed holding plaintext.
        let dir = Path::new("/data/totally_unseen");
        for i in 0..10 {
            assert!(matches!(
                d.observe_high_entropy_write(1, &dir.join(format!("f{i}.bin"))),
                Verdict::Clean
            ));
        }
    }

    #[test]
    fn stale_per_pid_bookkeeping_does_not_accumulate_forever() {
        let mut cfg = test_config();
        cfg.burst_window_secs = 0; // every entry is immediately "stale" on the next call
        let mut d = Detector::new(&cfg);
        d.note_plaintext_activity(Path::new("/data/victim/seed.txt"));

        // Many distinct one-shot pids, each writing exactly one file (well
        // under burst_file_count) - the pattern of ordinary process churn
        // that used to leak one HashMap entry per pid forever.
        for pid in 0..500 {
            d.observe_high_entropy_write(pid, Path::new("/data/victim/x.bin"));
        }

        // The very next observation (from yet another pid) sweeps out
        // everything whose window has elapsed; only that pid's own
        // just-inserted entry should remain.
        d.observe_high_entropy_write(999_999, Path::new("/data/victim/y.bin"));
        assert_eq!(d.recent_writes.len(), 1, "stale per-pid entries were not swept");
    }
}
