use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::{error, info};

use crate::config::Mode;

/// Writes a human-readable incident report for every detection (so a
/// sysadmin can see, after the fact, exactly what ransomshield saw and did
/// - the JSONL quarantine manifest is machine-oriented, this is meant to be
/// read directly), and optionally runs an operator-supplied command to push
/// an active notification (email, Slack, PagerDuty, SMS, whatever the
/// sysadmin already uses - ransomshield doesn't hardcode a channel, it just
/// hands the incident details to a script via environment variables).
pub struct IncidentReporter {
    dir: PathBuf,
    notify_command: Option<String>,
}

impl IncidentReporter {
    pub fn new(dir: &Path, notify_command: Option<String>) -> Result<Self> {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating incident reports dir {}", dir.display()))?;
        // Incident reports name affected files and PIDs; keep them root-only
        // rather than relying on create_dir_all's umask-dependent default -
        // see the identical reasoning in quarantine.rs.
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!("setting permissions on incident reports dir {}", dir.display())
        })?;
        Ok(Self { dir: dir.to_path_buf(), notify_command })
    }

    /// Record one incident: a text report on disk, plus an optional
    /// notify-command invocation. `action_taken` distinguishes an Enforce
    /// response (process killed, files quarantined) from a Monitor-mode
    /// observation (logged only, nothing touched).
    pub fn report(
        &self,
        mode: Mode,
        pid: i32,
        reason: &str,
        affected_files: &[PathBuf],
        quarantined_files: &[PathBuf],
        action_taken: bool,
    ) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let report_path = self.dir.join(format!("{stamp}_{pid}.txt"));

        let body = format!(
            "RansomShield incident report\n\
             =============================\n\
             Time (unix epoch seconds): {stamp}\n\
             Mode: {mode:?}\n\
             Action taken: {}\n\
             Suspect PID: {pid}\n\
             Reason: {}\n\
             \n\
             Affected files ({}):\n{}\n\
             \n\
             Quarantined to ({}):\n{}\n",
            if action_taken {
                "yes - process killed (SIGSTOP then SIGKILL), files below moved to quarantine"
            } else {
                "no - monitor mode or the process could not be neutralized, see logs"
            },
            sanitize(reason),
            affected_files.len(),
            format_list(affected_files),
            quarantined_files.len(),
            format_list(quarantined_files),
        );

        match fs::write(&report_path, &body) {
            Ok(()) => info!(path = %report_path.display(), "incident report written"),
            Err(e) => error!(path = %report_path.display(), error = %e, "failed to write incident report"),
        }

        if let Some(cmd) = &self.notify_command {
            self.notify(cmd, pid, reason, &report_path, action_taken);
        }
    }

    /// Spawns the configured notify command and does not wait for it, so a
    /// slow or hanging notification script (e.g. a flaky mail relay) can
    /// never delay the detection loop from handling the next event.
    fn notify(&self, cmd: &str, pid: i32, reason: &str, report_path: &Path, action_taken: bool) {
        let result = std::process::Command::new(cmd)
            .env("RANSOMSHIELD_PID", pid.to_string())
            .env("RANSOMSHIELD_REASON", sanitize(reason))
            .env("RANSOMSHIELD_REPORT_PATH", report_path)
            .env("RANSOMSHIELD_ACTION_TAKEN", action_taken.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match result {
            Ok(mut child) => {
                let notify_pid = child.id();
                info!(cmd, pid = notify_pid, "notify command spawned");
                // Not calling wait() at all would leak a zombie process-table
                // entry for the rest of the daemon's lifetime (every
                // detection spawns one), since nothing else in the process
                // reaps it. Reap it on a dedicated thread so a slow/hanging
                // script still can't block the detection loop.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(e) => error!(cmd, error = %e, "failed to spawn notify command"),
        }
    }
}

fn format_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "  (none)".to_string();
    }
    paths
        .iter()
        .map(|p| format!("  - {}", sanitize(&p.display().to_string())))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip control characters out of anything attacker-controlled before it is
/// written into a report or handed to a notify hook.
///
/// Filenames may contain newlines, quotes, escape sequences - anything but
/// `/` and NUL. Interpolated raw into this plain-text report, a file named
/// e.g. `invoice.txt\n\nAffected files (0):\n  (none)\n` injects
/// structurally valid lines and forges the record, which matters when the
/// report is the artifact an incident responder reads. The same strings go
/// into `RANSOMSHIELD_*` for an operator hook that runs as root, where an
/// unquoted expansion or an `eval` turns a filename into command execution.
/// (The JSONL quarantine manifest was already safe: serde_json escapes.)
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}
