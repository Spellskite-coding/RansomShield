use std::path::{Path, PathBuf};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{error, info, warn};

use crate::config::Mode;
use crate::incident::IncidentReporter;
use crate::quarantine::Quarantine;

/// Neutralize a process suspected of encrypting files, and preserve the
/// evidence for a sysadmin to review:
///
/// 1. SIGSTOP the process immediately, so it cannot write anything else
///    while we act on it.
/// 2. Move every file it touched during the detection window into
///    quarantine (off the live filesystem, with a manifest entry), rather
///    than leaving encrypted-looking files in place.
/// 3. SIGKILL the process.
/// 4. Write a human-readable incident report and, if configured, run the
///    operator's notify command - so the detection is visible without
///    someone having to go looking through logs.
///
/// In `Monitor` mode we only log and still write an incident report (marked
/// as observation-only): nothing is touched, so operators can tune
/// thresholds safely before switching a host to `Enforce`.
pub fn handle_detection(
    mode: Mode,
    pid: i32,
    reason: &str,
    affected_files: &[PathBuf],
    quarantine: &Quarantine,
    incidents: &IncidentReporter,
) {
    warn!(pid, reason, ?affected_files, "ransomware-like behavior detected");

    if mode == Mode::Monitor {
        info!(pid, "monitor mode: not touching the process or its files");
        incidents.report(mode, pid, reason, affected_files, &[], false);
        return;
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

    match signal::kill(target, Signal::SIGKILL) {
        Ok(()) => info!(pid, "killed suspect process"),
        Err(e) => error!(pid, error = %e, "failed to SIGKILL suspect process"),
    }

    incidents.report(mode, pid, reason, affected_files, &quarantined_files, true);
}

fn quarantine_one(quarantine: &Quarantine, path: &Path, pid: i32, reason: &str) -> Option<PathBuf> {
    match quarantine.take(path, pid, reason) {
        Ok(Some(dest)) => Some(dest),
        Ok(None) => {
            info!(path = %path.display(), "file already gone, nothing to quarantine");
            None
        }
        Err(e) => {
            error!(path = %path.display(), error = %e, "failed to quarantine file");
            None
        }
    }
}
