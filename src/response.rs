use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{error, info, warn};

use crate::config::Mode;
use crate::incident::IncidentReporter;
use crate::quarantine::Quarantine;
use crate::trust::TrustStore;

/// Neutralize a process suspected of encrypting files, and preserve the
/// evidence for a sysadmin to review:
///
/// 1. Confirm the pid still refers to the process that did the writing.
/// 2. SIGSTOP it immediately, so it cannot write anything else while we act.
/// 3. Move every file it touched during the detection window into
///    quarantine (off the live filesystem, with a manifest entry), rather
///    than leaving encrypted-looking files in place.
/// 4. SIGKILL the process.
/// 5. Write a human-readable incident report and, if configured, run the
///    operator's notify command - so the detection is visible without
///    someone having to go looking through logs.
///
/// In `Monitor` mode we only log and still write an incident report (marked
/// as observation-only): nothing is touched, so operators can tune
/// thresholds safely before switching a host to `Enforce`.
///
/// Returns `true` when the suspect process is confirmed gone. The caller uses
/// this to decide whether to clear its bookkeeping: clearing it after a failed
/// kill would hand a still-running ransomware process a fresh counter.
pub fn handle_detection(
    mode: Mode,
    pid: i32,
    expected_starttime: Option<u64>,
    reason: &str,
    affected_files: &[PathBuf],
    quarantine: &Quarantine,
    incidents: &IncidentReporter,
) -> bool {
    warn!(pid, reason, ?affected_files, "ransomware-like behavior detected");

    if mode == Mode::Monitor {
        info!(pid, "monitor mode: not touching the process or its files");
        incidents.report(mode, pid, reason, affected_files, &[], false);
        return true;
    }

    // Identity check before anything lethal. The event that triggered this may
    // have been sitting in the fanotify queue for a while - the queue is
    // deliberately unbounded, and the loop stalls for the whole duration of a
    // response - so by now the pid may belong to a completely different
    // process. The trust cache already guards its verdicts this way; the kill
    // path is where getting it wrong is most expensive, because the daemon
    // runs as root with CAP_KILL and would take out an innocent process (and,
    // via quarantine, relocate its files).
    if !still_the_same_process(pid, expected_starttime) {
        warn!(
            pid,
            "suspect process is gone or the pid now belongs to a different process; \
             not signalling anything"
        );
        incidents.report(mode, pid, reason, affected_files, &[], false);
        return true;
    }

    let target = Pid::from_raw(pid);

    if let Err(e) = signal::kill(target, Signal::SIGSTOP) {
        error!(pid, error = %e, "failed to SIGSTOP suspect process (may have already exited)");
    }

    let mut quarantined_files = Vec::new();
    for path in affected_files {
        if let Some(dest) = quarantine_one(quarantine, path, pid, reason) {
            quarantined_files.push(dest);
        }
    }

    // ESRCH means the process is already gone, which is the outcome we wanted.
    // Any other error means it is still running and we failed to stop it: say
    // so, loudly, and let the caller keep counting against it.
    let neutralized = match signal::kill(target, Signal::SIGKILL) {
        Ok(()) => {
            info!(pid, "killed suspect process");
            true
        }
        Err(Errno::ESRCH) => {
            info!(pid, "suspect process had already exited");
            true
        }
        Err(e) => {
            error!(
                pid,
                error = %e,
                "FAILED to SIGKILL suspect process - it may still be encrypting; keeping its \
                 detection state so the next event re-triggers immediately"
            );
            false
        }
    };

    incidents.report(mode, pid, reason, affected_files, &quarantined_files, neutralized);
    neutralized
}

/// Whether `pid` still refers to the process we observed writing.
///
/// `/proc/<pid>/stat` field 22 is the process's boot-relative start time,
/// unique to a given (pid, lifetime) pair, so comparing it catches pid reuse.
/// PID 1 is refused outright: nothing good comes of this daemon signalling
/// init, whatever the heuristics say.
fn still_the_same_process(pid: i32, expected_starttime: Option<u64>) -> bool {
    if pid <= 1 {
        warn!(pid, "refusing to signal pid <= 1");
        return false;
    }
    let Some(expected) = expected_starttime else {
        // We never managed to read a start time for it (very short-lived
        // process). Requiring one would mean never acting on fast attackers,
        // so fall back to "does it still exist", which is what the daemon did
        // before this check existed.
        return TrustStore::process_starttime(pid).is_some();
    };
    TrustStore::process_starttime(pid) == Some(expected)
}

fn quarantine_one(quarantine: &Quarantine, path: &Path, pid: i32, reason: &str) -> Option<PathBuf> {
    match quarantine.take(path, pid, reason) {
        Ok(Some(dest)) => Some(dest),
        Ok(None) => {
            info!(path = %path.display(), "file already gone or out of scope, nothing to quarantine");
            None
        }
        Err(e) => {
            error!(path = %path.display(), error = %e, "failed to quarantine file");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_pid_matches_its_recorded_start_time() {
        let pid = std::process::id() as i32;
        let start = TrustStore::process_starttime(pid);
        assert!(start.is_some());
        assert!(still_the_same_process(pid, start));
    }

    #[test]
    fn a_mismatched_start_time_means_the_pid_was_recycled() {
        let pid = std::process::id() as i32;
        assert!(
            !still_the_same_process(pid, Some(0)),
            "a pid whose start time no longer matches must not be signalled"
        );
    }

    #[test]
    fn init_is_never_signalled() {
        assert!(!still_the_same_process(1, None));
        assert!(!still_the_same_process(0, None));
    }

    #[test]
    fn a_dead_pid_is_not_signalled() {
        assert!(!still_the_same_process(999_999_999, None));
    }
}
