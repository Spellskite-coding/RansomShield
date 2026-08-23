use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use nix::unistd::Whence;
use tracing::{debug, info, warn};

use crate::baseline;
use crate::config::Config;
use crate::detector::{Detector, Verdict};
use crate::entropy::shannon_entropy;
use crate::honeypot;
use crate::incident::IncidentReporter;
use crate::quarantine::Quarantine;
use crate::response;
use crate::trust::TrustStore;

const WATCHED_EVENTS: MaskFlags = MaskFlags::from_bits_truncate(
    MaskFlags::FAN_CLOSE_WRITE.bits() | MaskFlags::FAN_MODIFY.bits(),
);

/// Reads up to `budget` bytes of the file behind `fd`, sampled from up to
/// three points (start, middle, end) instead of only its head, and returns
/// the *highest* Shannon entropy measured across those samples - `None` if
/// the file is empty.
///
/// Sampling only a file's first few KB (as this used to do) is blind to
/// intermittent/partial encryption, a technique some real ransomware uses
/// specifically to evade entropy-based detectors: leave the first N bytes
/// as-is and only encrypt from some offset onward, so a head-only sample
/// keeps reading as ordinary plaintext while the rest of the file is
/// destroyed. Scoring each sampled chunk on its own and taking the max
/// (rather than concatenating all the sampled bytes into one buffer and
/// scoring that) matters: blending a plaintext chunk together with a
/// high-entropy one computes the entropy of the *mixture*, which can land
/// comfortably back under the threshold even though a pure high-entropy
/// chunk was read - silently defeating the point of sampling more than one
/// offset in the first place.
fn max_sampled_entropy(fd: std::os::fd::BorrowedFd, budget: usize) -> Option<f64> {
    let size = nix::unistd::lseek(&fd, 0, Whence::SeekEnd).unwrap_or(0).max(0) as u64;

    let probe = |offset: u64, len: usize| -> Option<f64> {
        if len == 0 || nix::unistd::lseek(&fd, offset as i64, Whence::SeekSet).is_err() {
            return None;
        }
        let mut chunk = vec![0u8; len];
        let n = nix::unistd::read(&fd, &mut chunk).unwrap_or(0);
        chunk.truncate(n);
        (!chunk.is_empty()).then(|| shannon_entropy(&chunk))
    };

    let samples: Vec<f64> = if size as usize <= budget {
        probe(0, budget).into_iter().collect()
    } else {
        let third = budget / 3;
        let last = budget - 2 * third;
        [probe(0, third), probe(size / 2, third), probe(size.saturating_sub(last as u64), last)]
            .into_iter()
            .flatten()
            .collect()
    };

    samples.into_iter().reduce(f64::max)
}

/// One-time setup: initialize the fanotify group, mark the watched
/// directories, and seed the plaintext-directory baseline. Kept separate
/// from the event loop so the caller can learn, before declaring the
/// daemon "ready", whether monitoring actually came up - starting to
/// listen for connections/events successfully is the bar `sd_notify`
/// READY should be gated on, not just "the process is alive".
fn init(cfg: &Config) -> Result<(Fanotify, Detector, Quarantine, IncidentReporter)> {
    // FAN_UNLIMITED_QUEUE removes the default event queue cap (historically
    // 16384). A fast, aggressive ransomware run is precisely the scenario
    // that generates a huge burst of events in a short time - the one case
    // where we can least afford to silently drop events and miss files.
    // Requires CAP_SYS_ADMIN, which this daemon already needs for
    // FAN_MARK_FILESYSTEM.
    let group = Fanotify::init(
        InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_CLOEXEC | InitFlags::FAN_UNLIMITED_QUEUE,
        EventFFlags::O_RDONLY,
    )
    .context("fanotify_init failed (need CAP_SYS_ADMIN, i.e. run as root)")?;

    for dir in &cfg.watch_dirs {
        let handle = std::fs::File::open(dir)
            .with_context(|| format!("opening watch dir {}", dir.display()))?;
        // FAN_MARK_FILESYSTEM watches the whole mount the path belongs to.
        // For this to stay scoped to what you actually intend, `dir` should
        // be its own mount point (a dedicated volume/bind mount), not a
        // subdirectory of a much larger filesystem such as `/`.
        group
            .mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                WATCHED_EVENTS,
                &handle,
                None::<&std::path::Path>,
            )
            .with_context(|| format!("fanotify_mark failed for {}", dir.display()))?;
        info!(dir = %dir.display(), "watching");
    }

    let mut detector = Detector::new(cfg);
    let quarantine = Quarantine::new(&cfg.quarantine_dir)?;
    let incidents = IncidentReporter::new(&cfg.incident_reports_dir, cfg.notify_command.clone())?;

    for dir in &cfg.watch_dirs {
        baseline::seed(&mut detector, dir, cfg.sample_bytes, cfg.entropy_threshold);
    }

    Ok((group, detector, quarantine, incidents))
}

/// Blocking fanotify read/dispatch loop. Meant to run on a dedicated
/// (blocking) thread: `Fanotify::read_events` blocks the calling thread
/// until events are available.
///
/// `ready_tx` is signaled exactly once, right after initialization
/// succeeds or fails, so the caller can gate its systemd `READY=1`
/// notification (and thus `Restart=on-failure` semantics) on monitoring
/// having actually come up rather than merely having started a thread.
pub fn run(
    cfg: Config,
    honeypots: HashSet<PathBuf>,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let sample_bytes = cfg.sample_bytes;
    let (group, mut detector, quarantine, incidents) = match init(&cfg) {
        Ok(v) => {
            let _ = ready_tx.send(Ok(()));
            v
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    let own_pid = std::process::id() as i32;
    let mut trust = TrustStore::new(cfg.trusted_executables.clone());
    info!(mode = ?cfg.mode, trusted_executables = cfg.trusted_executables.len(), "ransomshield monitor loop started");

    // A single spurious read_events() failure is worth retrying, but
    // retrying it in a tight loop forever (e.g. if the fd became invalid
    // for good) would pin a CPU core and flood the logs while providing no
    // actual protection. Back off between retries and give up after
    // MAX_CONSECUTIVE_READ_FAILURES so the process exits non-zero and
    // systemd's Restart=on-failure can give monitoring a clean restart.
    const MAX_CONSECUTIVE_READ_FAILURES: u32 = 20;
    let mut consecutive_failures = 0u32;

    loop {
        let events = match group.read_events() {
            Ok(ev) => {
                consecutive_failures = 0;
                ev
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_READ_FAILURES {
                    return Err(e).context(format!(
                        "fanotify read_events failed {consecutive_failures} times in a row, giving up"
                    ));
                }
                warn!(error = %e, consecutive_failures, "fanotify read_events failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(200 * consecutive_failures.min(10) as u64));
                continue;
            }
        };

        for event in events {
            let pid = event.pid();
            if pid == own_pid || pid <= 0 {
                continue;
            }

            let Some(fd) = event.fd() else {
                // Queue overflow marker event: no fd attached.
                warn!("fanotify event queue overflowed; some events were dropped");
                continue;
            };

            let path = std::fs::read_link(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&fd)))
                .unwrap_or_else(|_| PathBuf::from("<unknown>"));

            if honeypot::is_honeypot(&honeypots, &path) {
                let mut affected = detector.files_for_pid(pid);
                affected.push(path.clone());
                response::handle_detection(
                    cfg.mode,
                    pid,
                    &format!("honeypot touched: {}", path.display()),
                    &affected,
                    &quarantine,
                    &incidents,
                );
                detector.forget(pid);
                continue;
            }

            let Some(entropy) = max_sampled_entropy(fd, sample_bytes) else {
                continue;
            };
            debug!(pid, path = %path.display(), entropy, "file write observed");

            if entropy < cfg.entropy_threshold {
                detector.note_plaintext_activity(&path);
            } else if trust.is_trusted(pid) {
                debug!(pid, path = %path.display(), "high-entropy write from a trusted executable, not counting toward burst");
            } else if let Verdict::Burst { count } = detector.observe_high_entropy_write(pid, &path) {
                let affected = detector.files_for_pid(pid);
                response::handle_detection(
                    cfg.mode,
                    pid,
                    &format!(
                        "{count} high-entropy file rewrites within {}s (last: {})",
                        cfg.burst_window_secs,
                        path.display()
                    ),
                    &affected,
                    &quarantine,
                    &incidents,
                );
                detector.forget(pid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;

    fn pseudo_random_bytes(n: usize) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut data = vec![0u8; n];
        for b in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xFF) as u8;
        }
        data
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ransomshield_test_{}_{}", std::process::id(), name));
        path
    }

    #[test]
    fn max_sampled_entropy_catches_a_random_tail_behind_a_plaintext_header() {
        // Reproduces the intermittent-encryption evasion this sampling
        // exists to catch: a file whose first `sample_bytes` never change
        // (an attacker deliberately leaving the head alone) but whose tail
        // was rewritten with high-entropy data. A head-only sample would
        // read this as ordinary plaintext.
        let path = temp_path("live_tail.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all("the quick brown fox jumps over the lazy dog ".repeat(200).as_bytes()).unwrap();
            f.write_all(&pseudo_random_bytes(64 * 1024)).unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let max_e = max_sampled_entropy(f.as_fd(), 8192);
        let _ = std::fs::remove_file(&path);

        let max_e = max_e.expect("file is not empty");
        assert!(max_e > 7.5, "expected the random tail to pull the maximum up, got {max_e}");
    }

    #[test]
    fn max_sampled_entropy_is_none_for_an_empty_file() {
        let path = temp_path("live_empty.bin");
        std::fs::File::create(&path).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let result = max_sampled_entropy(f.as_fd(), 8192);
        let _ = std::fs::remove_file(&path);
        assert!(result.is_none());
    }

    #[test]
    fn max_sampled_entropy_of_a_small_all_plaintext_file_stays_low() {
        // Regression guard: a file at or under the sample budget must not
        // start reading as suspicious just because it's now sampled at
        // (only) one point instead of three - false positives on ordinary
        // small files would be a real regression, not just a missed catch.
        let path = temp_path("live_small_plaintext.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"just an ordinary short text file\n").unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let e = max_sampled_entropy(f.as_fd(), 8192);
        let _ = std::fs::remove_file(&path);

        let e = e.expect("file is not empty");
        assert!(e < 4.5, "expected low entropy for ordinary small text, got {e}");
    }
}
