use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::TrustedExecutable;

/// Lets an operator exempt specific, known executables (e.g. `gpg`,
/// `restic`, an in-house backup tool) from the burst/entropy heuristic, so
/// legitimate bulk encryption of files in a directory that already has a
/// plaintext baseline - which otherwise looks identical to ransomware -
/// doesn't get killed.
///
/// Trust is anchored on *both* the executable's path (via `/proc/<pid>/exe`)
/// and a SHA-256 of its current on-disk content, not on path or process
/// name alone: a path match with a mismatching hash is treated as
/// untrusted (and logged loudly), so replacing/trojanizing a trusted binary
/// - or a malicious process merely naming itself the same thing - does not
/// grant the bypass. Honeypot detection is never subject to this bypass:
/// no legitimate trusted tool has a reason to touch a honeypot file.
pub struct TrustStore {
    trusted: Vec<TrustedExecutable>,
    /// Keyed by pid; value is (trusted?, when checked, that process's boot-relative
    /// start time). The start time is what makes a cache hit mean "the same
    /// process I checked before", not just "some process currently wearing
    /// this pid number" - see `process_starttime`.
    cache: HashMap<i32, (bool, Instant, u64)>,
    cache_ttl: Duration,
}

impl TrustStore {
    pub fn new(trusted: Vec<TrustedExecutable>) -> Self {
        Self { trusted, cache: HashMap::new(), cache_ttl: Duration::from_secs(60) }
    }

    /// Whether `pid`'s executable is on the trust list, right now. Cached
    /// briefly per PID so a burst of events from the same process doesn't
    /// re-hash its executable on every single write.
    pub fn is_trusted(&mut self, pid: i32) -> bool {
        if self.trusted.is_empty() {
            return false;
        }

        let now = Instant::now();
        let starttime = Self::process_starttime(pid);

        if let (Some((trusted, checked_at, cached_start)), Some(start)) =
            (self.cache.get(&pid), starttime)
        {
            if *cached_start == start && now.duration_since(*checked_at) < self.cache_ttl {
                return *trusted;
            }
        }

        let result = self.compute_trust(pid);
        // Only cache when we could read a start time to bind the entry to -
        // otherwise a subsequent lookup could never invalidate it correctly
        // and we'd rather recompute than risk serving a stale verdict.
        if let Some(start) = starttime {
            self.cache.insert(pid, (result, now, start));
        }
        // Bound cache growth on a long-running daemon watching a busy host
        // with lots of short-lived PIDs: drop anything stale well past its
        // TTL rather than accumulating forever.
        self.cache.retain(|_, (_, checked_at, _)| now.duration_since(*checked_at) < self.cache_ttl * 4);
        result
    }

    /// The process's start time (field 22 of `/proc/<pid>/stat`, in clock
    /// ticks since boot) - unique to a given (pid, lifetime) pair on this
    /// system. Used to make sure a cache hit refers to the exact same
    /// process we last checked, not merely the same pid number: PIDs are
    /// reused once the kernel's pid space wraps around, and without this
    /// check a short-lived trusted process's cached "trusted" verdict could
    /// otherwise be handed, for up to `cache_ttl`, to a completely different
    /// and untrusted process that happened to reuse its pid.
    ///
    /// `comm` (the second field) is parsed defensively by searching for the
    /// last `)` rather than splitting on whitespace, since it can itself
    /// contain spaces or parentheses.
    fn process_starttime(pid: i32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rsplit_once(')')?.1;
        after_comm.split_whitespace().nth(19)?.parse().ok()
    }

    fn compute_trust(&self, pid: i32) -> bool {
        let Ok(exe_path) = fs::read_link(format!("/proc/{pid}/exe")) else {
            return false;
        };

        let Some(entry) = self.trusted.iter().find(|t| t.path == exe_path) else {
            return false;
        };

        let Ok(mut f) = fs::File::open(&exe_path) else {
            return false;
        };

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let Ok(n) = f.read(&mut buf) else { return false };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();

        if digest.eq_ignore_ascii_case(&entry.sha256) {
            true
        } else {
            warn!(
                pid,
                path = %exe_path.display(),
                "executable at a configured trusted path has an unexpected hash - NOT trusting it \
                 (binary was replaced/updated since the hash was configured, or this is spoofing)"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_starttime_is_stable_and_present_for_self() {
        let pid = std::process::id() as i32;
        let a = TrustStore::process_starttime(pid);
        let b = TrustStore::process_starttime(pid);
        assert!(a.is_some(), "expected a start time for our own running process");
        assert_eq!(a, b, "start time must be stable across repeated reads");
    }

    #[test]
    fn process_starttime_is_none_for_a_pid_that_does_not_exist() {
        assert_eq!(TrustStore::process_starttime(999_999_999), None);
    }

    #[test]
    fn a_cache_entry_with_a_mismatched_starttime_is_not_trusted_blindly() {
        let exe = std::env::current_exe().unwrap();
        let mut f = fs::File::open(&exe).unwrap();
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sha256: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();

        let pid = std::process::id() as i32;
        let mut store = TrustStore::new(vec![TrustedExecutable { path: exe, sha256 }]);

        // Poison the cache as if we'd previously (wrongly) decided this pid
        // was untrusted, under a starttime that does not match its real,
        // current one - simulating the pid having been reused by a
        // different process since that entry was made.
        let now = Instant::now();
        store.cache.insert(pid, (false, now, 0));

        // A real, unmodified copy of the trusted binary at the trusted path
        // is running as this very test process, so the correct, freshly
        // computed answer is `true` - the mismatched starttime must force
        // that recheck rather than returning the poisoned cached `false`.
        assert!(store.is_trusted(pid));
    }
}
