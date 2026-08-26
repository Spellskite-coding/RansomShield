use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use nix::unistd::Whence;
use tracing::{debug, info, warn};

use crate::baseline;
use crate::config::Config;
use crate::detector::{Detector, Verdict};
use crate::entropy::shannon_entropy;
use crate::honeypot::Honeypots;
use crate::incident::IncidentReporter;
use crate::quarantine::Quarantine;
use crate::response;
use crate::trust::TrustStore;

const WATCHED_EVENTS: MaskFlags = MaskFlags::from_bits_truncate(
    MaskFlags::FAN_CLOSE_WRITE.bits() | MaskFlags::FAN_MODIFY.bits(),
);

/// How many points in a file to sample for entropy. Each probe gets
/// `sample_bytes / PROBE_COUNT` bytes, so the total read per event is
/// unchanged from a single-probe scheme.
const PROBE_COUNT: usize = 5;

/// A tiny xorshift64 PRNG, seeded from the clock. Used only to pick entropy
/// sampling offsets - never for anything security-critical in the
/// cryptographic sense - so a non-CSPRNG with no external dependency is the
/// right tool.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x243F_6A88_85A3_08D3);
        // Never seed a xorshift with zero: it would stay zero forever.
        Self(nanos | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Uniform-ish value in `0..bound`. Modulo bias is irrelevant here.
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 { 0 } else { self.next() % bound }
    }
}

/// Reads up to `budget` bytes of the file behind `fd`, sampled from several
/// *randomly chosen* offsets, and returns the highest Shannon entropy
/// measured across those samples - `None` if the file is empty.
///
/// Sampling only a file's first few KB is blind to intermittent/partial
/// encryption, a technique real ransomware uses specifically to evade
/// entropy-based detectors: leave the head as-is and only encrypt from some
/// offset onward, so a head-only sample keeps reading as ordinary plaintext
/// while the rest of the file is destroyed.
///
/// Sampling at *fixed* points (start, middle, end - what this used to do) only
/// moves the problem. Those offsets are derived from public constants and the
/// file's own size, so an attacker can compute them exactly and leave
/// plaintext in precisely those windows. That was confirmed in testing: a
/// 1 MiB file with only the three 2,730-byte probe windows left intact - 99.2%
/// of it high-entropy - measured 4.397 bits/byte and sailed under a 7.5
/// threshold. Choosing offsets at random per event removes the target: an
/// attacker cannot align plaintext with positions they cannot predict, and
/// each additional probe multiplies the odds against them.
///
/// Scoring each chunk on its own and taking the max (rather than
/// concatenating everything into one buffer and scoring that) matters:
/// blending a plaintext chunk with a high-entropy one computes the entropy of
/// the *mixture*, which can land comfortably back under the threshold even
/// though a pure high-entropy chunk was read.
fn max_sampled_entropy(fd: std::os::fd::BorrowedFd, budget: usize, rng: &mut Rng) -> Option<f64> {
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

    // Small enough to read whole: no sampling decision to make, and no way to
    // hide anything between probes.
    if size as usize <= budget {
        return probe(0, budget);
    }

    let chunk = (budget / PROBE_COUNT).max(1);
    let span = size.saturating_sub(chunk as u64).saturating_add(1);

    (0..PROBE_COUNT)
        .filter_map(|_| probe(rng.below(span), chunk))
        .reduce(f64::max)
}

/// The `(st_dev, st_ino)` of the file an event refers to.
fn inode_of(fd: std::os::fd::BorrowedFd) -> Option<(u64, u64)> {
    let st = nix::sys::stat::fstat(fd).ok()?;
    Some((st.st_dev as u64, st.st_ino as u64))
}

/// One-time setup: initialize the fanotify group, mark the watched
/// directories, and seed the plaintext-directory baseline. Kept separate
/// from the event loop so the caller can learn, before declaring the
/// daemon "ready", whether monitoring actually came up - starting to
/// listen for connections/events successfully is the bar `sd_notify`
/// READY should be gated on, not just "the process is alive".
///
/// Also returns the canonicalized watch roots, which every event path is
/// checked against - see the scope filter in `run`.
fn init(
    cfg: &Config,
) -> Result<(Fanotify, Detector, Quarantine, IncidentReporter, Vec<PathBuf>)> {
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

    let mut roots = Vec::new();

    for dir in &cfg.watch_dirs {
        let handle = std::fs::File::open(dir)
            .with_context(|| format!("opening watch dir {}", dir.display()))?;
        // FAN_MARK_FILESYSTEM watches the whole mount the path belongs to,
        // not just this directory. That is deliberate (it is the only way to
        // catch writes through any path to the same files), but it means the
        // kernel hands us events from everywhere on that filesystem - so the
        // daemon filters them back down to `watch_dirs` itself, in `run`.
        // Without that filter a default install (watch_dirs = ["/home"], and
        // /home is rarely its own mount) would let the daemon kill processes
        // and relocate files anywhere on /.
        group
            .mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                WATCHED_EVENTS,
                &handle,
                None::<&std::path::Path>,
            )
            .with_context(|| format!("fanotify_mark failed for {}", dir.display()))?;

        let canonical = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        info!(dir = %dir.display(), scope = %canonical.display(), "watching");
        roots.push(canonical);
    }

    let mut detector = Detector::new(cfg);
    let quarantine = Quarantine::new(&cfg.quarantine_dir, roots.clone())?;
    let incidents = IncidentReporter::new(&cfg.incident_reports_dir, cfg.notify_command.clone())?;

    for dir in &cfg.watch_dirs {
        baseline::seed(&mut detector, dir, cfg.sample_bytes, cfg.entropy_threshold);
    }

    Ok((group, detector, quarantine, incidents, roots))
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
    mut honeypots: Honeypots,
    ready_tx: tokio::sync::oneshot::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let sample_bytes = cfg.sample_bytes;
    let (group, mut detector, quarantine, incidents, roots) = match init(&cfg) {
        Ok(v) => {
            let _ = ready_tx.send(Ok(()));
            v
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e.to_string()));
            return Err(e);
        }
    };

    // A honeypot outside every watch root is provisioned fine and then never
    // fires: it looks like protection while providing none. Say so at startup
    // rather than letting an operator discover it during an incident.
    if !honeypots.is_empty() && !honeypots.all_within(&roots) {
        warn!("at least one configured honeypot is not under any watch_dir - it will never trigger");
    }

    let own_pid = std::process::id() as i32;
    let mut trust = TrustStore::new(cfg.trusted_executables.clone());
    let mut rng = Rng::new();
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

            // Honeypot identity is the inode, not the path. A path is a string
            // that can be detached from its inode - a hard link, a rename, or
            // an unlink-while-open (which makes /proc/self/fd read
            // "<path> (deleted)") all let an attacker write to the very same
            // canary while matching no configured path.
            let ident = inode_of(fd);
            let honeypot_hit = ident.and_then(|(dev, ino)| {
                honeypots.lookup(dev, ino).map(|p| (dev, ino, p.to_path_buf()))
            });

            let path = match std::fs::read_link(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&fd)
            )) {
                Ok(p) => p,
                Err(e) => {
                    // Previously this substituted the literal path "<unknown>",
                    // which collapsed every unresolvable write by a pid into a
                    // single entry in the distinct-file burst counter, so they
                    // could never add up to a detection.
                    debug!(pid, error = %e, "could not resolve event path, skipping event");
                    continue;
                }
            };

            if let Some((dev, ino, canary_path)) = honeypot_hit {
                // Deliberately does NOT include the canary itself in the files
                // to quarantine. Quarantine moves a file off the live
                // filesystem, so including it made the daemon destroy its own
                // trap on the first hit - and nothing re-provisions honeypots
                // outside startup. One throwaway `touch` per honeypot was
                // enough to disarm them all before the real payload ran.
                let affected = detector.files_for_pid(pid);
                let neutralized = response::handle_detection(
                    cfg.mode,
                    pid,
                    detector.starttime_for_pid(pid),
                    &format!("honeypot touched: {}", canary_path.display()),
                    &affected,
                    &quarantine,
                    &incidents,
                );
                honeypots.rearm(dev, ino);
                if neutralized {
                    detector.forget(pid);
                }
                continue;
            }

            // Scope filter. FAN_MARK_FILESYSTEM delivers events for the entire
            // mount, so without this the daemon acts - lethally, and by
            // relocating files - far outside the directories the operator
            // actually declared. This also drops the bulk of the event volume
            // on a busy host before any I/O is done for it.
            if !roots.iter().any(|r| path.starts_with(r)) {
                continue;
            }

            let Some(entropy) = max_sampled_entropy(fd, sample_bytes, &mut rng) else {
                continue;
            };
            debug!(pid, path = %path.display(), entropy, "file write observed");

            if entropy < cfg.entropy_threshold {
                detector.note_plaintext_activity(&path);
            } else if trust.is_trusted(pid) {
                debug!(pid, path = %path.display(), "high-entropy write from a trusted executable, not counting toward burst");
            } else if let Verdict::Burst { count } = detector.observe_high_entropy_write(pid, &path) {
                let affected = detector.files_for_pid(pid);
                let neutralized = response::handle_detection(
                    cfg.mode,
                    pid,
                    detector.starttime_for_pid(pid),
                    &format!(
                        "{count} high-entropy file rewrites within {}s (last: {})",
                        cfg.burst_window_secs,
                        path.display()
                    ),
                    &affected,
                    &quarantine,
                    &incidents,
                );
                // Only clear the bookkeeping once the process is confirmed
                // gone. Clearing it after a failed kill would hand a still-
                // running ransomware process a fresh counter, forcing it to
                // re-accumulate burst_file_count files before tripping again -
                // forever, while it keeps encrypting.
                if neutralized {
                    detector.forget(pid);
                }
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
        let max_e = max_sampled_entropy(f.as_fd(), 8192, &mut Rng::new());
        let _ = std::fs::remove_file(&path);

        let max_e = max_e.expect("file is not empty");
        assert!(max_e > 7.5, "expected the random tail to pull the maximum up, got {max_e}");
    }

    #[test]
    fn max_sampled_entropy_is_none_for_an_empty_file() {
        let path = temp_path("live_empty.bin");
        std::fs::File::create(&path).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let result = max_sampled_entropy(f.as_fd(), 8192, &mut Rng::new());
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
        let e = max_sampled_entropy(f.as_fd(), 8192, &mut Rng::new());
        let _ = std::fs::remove_file(&path);

        let e = e.expect("file is not empty");
        assert!(e < 4.5, "expected low entropy for ordinary small text, got {e}");
    }
}
