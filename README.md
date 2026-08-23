# RansomShield

A behavior-based ransomware detection daemon for Linux servers, written in Rust.

RansomShield does not care whether a file was *modified* - that happens constantly on any
real server. It watches for the specific *pattern* of a file being encrypted: a process
rewriting many files with high-entropy (encrypted/random-looking) content in a short window,
or touching a decoy "honeypot" file no legitimate process should ever open. When it sees that
pattern, it freezes the offending process (`SIGSTOP`), moves the files it touched into
quarantine, kills the process (`SIGKILL`), and writes an incident report - typically before a
ransomware run has gotten past a handful of files.

It runs as a `systemd` service and is built around `fanotify(7)`, a mainline Linux kernel API -
no kernel modules, no eBPF, no unsafe code in the daemon itself.

## How it works

1. **Filesystem monitoring** - `fanotify` with `FAN_MARK_FILESYSTEM` watches every file close
   on the mount(s) holding the configured `watch_dirs`. This needs `CAP_SYS_ADMIN`.
2. **Entropy sampling** - when a file is closed after being written, RansomShield samples it
   (up to `sample_bytes` total, split across up to three points - start, middle, end - for
   anything bigger than that budget) through the same file descriptor the kernel handed it in
   the event (not by re-opening the path), and computes the Shannon entropy of each sampled
   chunk independently, keeping the highest. Sampling more than just the head matters: some
   ransomware deliberately leaves a file's beginning untouched and only encrypts from partway
   through, specifically to dodge head-only entropy checks. Encrypted/compressed data sits near
   the theoretical maximum (~8 bits/byte); plain text and most documents sit well below it.
3. **Directory baseline** - a high-entropy write only counts toward detection if its directory,
   *or any ancestor of it*, has previously held ordinary (low-entropy) content - either observed
   live, or found during a one-time startup scan of existing files. Checking the whole ancestor
   chain (not just the exact directory) means a brand-new subdirectory created under an
   already-active tree is covered from the moment it's created, not only once something plaintext
   happens to be written into that exact subdirectory itself. This is what tells apart "your
   documents folder is suddenly full of ciphertext" (suspicious) from "your backup/export folder
   just received a batch of new archives" (routine). Without it, any workload that legitimately
   produces batches of new compressed files (backups, media exports, build artifacts) would
   trigger false positives.
4. **Burst detection** - if the same process high-entropy-rewrites enough *distinct* files
   (`burst_file_count`, default 8) within a time window (`burst_window_secs`, default 10s) in a
   directory that has a plaintext baseline, it's treated as ransomware.
5. **Honeypots** - decoy files planted at operator-chosen paths. Any write to one is an instant,
   high-confidence signal, independent of the burst/entropy heuristics - a legitimate process
   has no reason to ever touch them.
6. **Trusted executables (allowlist)** - specific tools (by exact path *and* SHA-256 of their
   current binary content, e.g. a known backup or encryption script) can be exempted from the
   burst/entropy heuristic, so legitimate bulk encryption in a directory that already has a
   plaintext baseline - which otherwise looks identical to ransomware - doesn't get killed. A
   path match with a mismatching hash (e.g. a different binary placed at that path) is treated
   as *not* trusted. This bypass never applies to honeypot detection - a trusted tool that
   touches a honeypot is killed just the same.
7. **Response** (`Enforce` mode) - `SIGSTOP` the process immediately (so it can't write anything
   else while being handled), move every file it touched during the detection window into
   quarantine (`fs::rename`, symlink-safe), then `SIGKILL` it. `Monitor` mode does everything
   except touch the process/files, for safely tuning thresholds before enabling enforcement.
8. **Incident reporting** - every detection (in both modes) writes a human-readable `.txt`
   report to `incident_reports_dir`, and optionally runs an operator-supplied `notify_command`
   (spawned, never waited on) with the incident details as `RANSOMSHIELD_*` environment
   variables - point it at your own email/Slack/PagerDuty/SMS script.

## Building

```sh
cargo build --release
```

For a fully portable binary that doesn't depend on the target's glibc version (recommended for
distribution across mixed-distro fleets):

```sh
docker run --rm -v "$(pwd)":/src -w /src rust:alpine sh -c \
  'apk add --no-cache musl-dev && cargo build --release --target x86_64-unknown-linux-musl'
```

## Configuration

JSON file, default path `/etc/ransomshield/config.json`:

```json
{
  "watch_dirs": ["/data"],
  "honeypots": ["/data/.honeypot/DO_NOT_TOUCH.docx"],
  "mode": "enforce",
  "entropy_threshold": 7.5,
  "burst_file_count": 8,
  "burst_window_secs": 10,
  "sample_bytes": 8192,
  "quarantine_dir": "/var/lib/ransomshield/quarantine",
  "require_directory_baseline": true,
  "incident_reports_dir": "/var/lib/ransomshield/incidents",
  "notify_command": "/opt/notify_hook.sh",
  "trusted_executables": [
    {"path": "/usr/bin/gpg", "sha256": "<sha256sum /usr/bin/gpg>"}
  ]
}
```

| Field | Meaning |
|---|---|
| `watch_dirs` | Directories to monitor. Each should be its own mount point - `FAN_MARK_FILESYSTEM` watches the *whole* filesystem a path belongs to, so pointing this at a subdirectory of `/` would watch far more than intended. |
| `honeypots` | Decoy file paths. Created automatically if missing. |
| `mode` | `"monitor"` (log only) or `"enforce"` (kill + quarantine). Start in `monitor` to tune thresholds against real traffic before enabling enforcement. |
| `entropy_threshold` | Bits/byte above which a write is treated as "encrypted-looking" (0-8 scale). |
| `burst_file_count` / `burst_window_secs` | How many distinct high-entropy files from the same process, in how many seconds, before it's ransomware. |
| `sample_bytes` | How many bytes to sample per file for entropy. |
| `quarantine_dir` | Where quarantined files and `manifest.jsonl` are kept. |
| `require_directory_baseline` | See "Directory baseline" above. Disable only if you understand it weakens detection in directories the daemon has never observed plaintext activity in. |
| `incident_reports_dir` | Where per-incident `.txt` reports are written. |
| `notify_command` | Optional external command run on every detection. |
| `trusted_executables` | `[{"path", "sha256"}]` list exempted from the burst/entropy heuristic. Get the hash with `sha256sum <path>`. Use sparingly and specifically (a known backup/admin script), not for broad general-purpose crypto tools - see "Effectiveness & limitations". |

## Deployment

### Automated (recommended)

Clone the repo on the server you want to protect and run the installer as root. It builds the
daemon, installs the binary/config/systemd unit, starts the service, and verifies it actually
came up - printing a clear pass/fail summary either way.

```sh
git clone <this-repo>
cd ransomshield
sudo ./install.sh /data /home        # directories to watch; defaults to /home if omitted
```

Starts in `monitor` mode by default (logs and writes incident reports, never kills/quarantines) -
pass `--enforce` instead once you've reviewed monitor-mode reports against real traffic and are
confident in the thresholds. Safe to re-run to rebuild/upgrade: it never overwrites an existing
`/etc/ransomshield/config.json`, so thresholds you've already tuned are preserved.

### Manual

```sh
sudo cp target/release/ransomshield /usr/local/bin/
sudo cp systemd/ransomshield.service /etc/systemd/system/
sudo mkdir -p /etc/ransomshield && sudo cp your-config.json /etc/ransomshield/config.json
sudo mkdir -p /var/lib/ransomshield/quarantine /var/lib/ransomshield/incidents
sudo systemctl daemon-reload
sudo systemctl enable --now ransomshield
```

The unit requests only `CAP_SYS_ADMIN` (for `fanotify`) and `CAP_KILL` (to neutralize
processes) - not full root capabilities - and sets `NoNewPrivileges`/`ProtectSystem=strict`,
which makes the whole filesystem read-only except `/etc/ransomshield`. **If you deploy by hand
instead of via `install.sh`**, you also need to grant write access to your quarantine dir,
incident reports dir, and every `watch_dir` (honeypot files are created there) - e.g. via a
`/etc/systemd/system/ransomshield.service.d/local.conf` drop-in:

```ini
[Service]
ReadWritePaths=/etc/ransomshield /var/lib/ransomshield/quarantine /var/lib/ransomshield/incidents /data /home
```

`install.sh` generates this drop-in automatically from whatever directories you pass it.

### Uninstalling

```sh
sudo ./uninstall.sh            # stops/disables the service, removes the binary
                                # and systemd unit; leaves your config,
                                # quarantined files, and incident reports on disk
sudo ./uninstall.sh --purge    # also deletes /etc/ransomshield and
                                # /var/lib/ransomshield
```

Safe to re-run. Config and data are kept by default specifically so a routine
or accidental uninstall can never silently destroy quarantined evidence or
incident history - pass `--purge` once you've confirmed you don't need them.

## Testing

All adversarial testing happens exclusively inside disposable Docker containers, never on a
host, and never with real malware - only simulated I/O *patterns*:

- `src/bin/attack_sim.rs` - a single process that seeds plaintext files, then rewrites them with
  random high-entropy bytes and deletes the originals, mimicking the observable shape of a
  ransomware run without any actual encryption or malicious code.
- `src/bin/legit_backup_sim.rs` - a single process that writes new already-random-looking files
  to a fresh directory, mimicking a legitimate backup/export job, used to check for false
  positives.
- `src/bin/legit_encrypt_sim.rs` - a single process that seeds plaintext files then encrypts them
  in place, mimicking a user running a trusted tool like `gpg` on their own files - used to
  validate the `trusted_executables` allowlist (and, by overwriting this binary's path with a
  different binary before running it, that hash-mismatched impostors are still caught).
- `docker/benign_activity.sh` - ordinary low-entropy file writes, for a second false-positive
  check.
- `docker/notify_hook.sh` - example notification hook (appends to a log file); swap for your
  own email/Slack/PagerDuty script.
- `docker/Dockerfile.{ubuntu,debian,fedora,almalinux,rockylinux}` - systemd-enabled test images
  covering both major packaging families (deb/rpm) and both bleeding-edge (Fedora) and
  conservative-enterprise (RockyLinux/AlmaLinux, RHEL-family) glibc/kernel baselines. The
  `trusted_executables` hash baked into `docker/config.json` is recomputed at image build time
  against the binary actually in the image (rather than trusting a hash committed to the repo),
  so the trust-allowlist test can't silently go stale across a toolchain/compiler change.

```sh
cargo build --release
docker build -f docker/Dockerfile.ubuntu -t ransomshield-test:ubuntu .
docker run -d --name rs-test --cap-add SYS_ADMIN --cap-add KILL \
  --entrypoint /usr/local/bin/ransomshield ransomshield-test:ubuntu \
  --config /etc/ransomshield/config.json --verbose

docker exec rs-test /usr/local/bin/legit-backup-sim /data/backups 15   # should all survive
docker exec rs-test /usr/local/bin/attack-sim /data/victim 20         # should be stopped early
docker logs rs-test
```

### Unit tests

`cargo test` (run inside the same build container as above - see "Building") covers the pure
logic that's cheap to exercise without a real fanotify group: entropy scoring, the directory-
baseline walk (including a brand-new subdirectory of an already-baselined tree), the burst
detector's per-pid bookkeeping cleanup, and the trust cache's process-identity check.

## Effectiveness & limitations

Across 5 distros (Ubuntu, Debian, RockyLinux, AlmaLinux, Fedora) in repeated test runs:

- The simulated ransomware process was consistently detected and killed after `burst_file_count`
  files (default 8), leaving the rest of the batch untouched in plaintext - real damage
  limitation, not just after-the-fact alerting. In a 300-file stress run, only 8 files (2.7%)
  were touched before the process was stopped, all 8 recovered intact in quarantine, and the
  detect-to-kill response added well under a second end to end.
- Daemon overhead is negligible: ~2 MB RSS at idle/under load in testing.
- The simulated legitimate backup workload (15 new compressed-looking files, single process, in
  a directory that never held plaintext) was never flagged, after adding the directory-baseline
  gate - a naive entropy+burst heuristic without it *did* false-positive on this exact scenario
  during testing.
- The simulated legitimate *in-place encryption* workload (a trusted, allowlisted tool
  encrypting 20 of the user's own files in a directory with plaintext history - the one FP
  scenario the directory-baseline gate alone can't tell apart from ransomware) was never
  flagged once allowlisted by path+hash; a differing binary placed at that same path (simulated
  spoofing) was still detected and stopped like any other attack, and a *trusted* process
  touching a honeypot was still killed - the allowlist narrows only the burst/entropy heuristic,
  never the honeypot signal.
- Honeypot touches were detected on the very first write, every time.
- Two independent multi-pass security+stability reviews (SAST) across the whole codebase found
  no confirmed high-confidence vulnerabilities (several candidate findings were raised and
  independently re-checked, none held up under scrutiny). Real bugs found and fixed anyway:
  symlink handling in quarantine/honeypot provisioning, systemd readiness gating so a failed
  `fanotify_init` doesn't silently exit 0 (defeating `Restart=on-failure`), a blocking-thread
  shutdown hang on SIGTERM, an unbounded fanotify-read retry loop, and a zombie-process leak from
  unreaped notify-command children.

### Third review: adversarial (red-team) testing

A further round of SAST plus live adversarial testing - custom attack tooling built from scratch
and run only against this project's own simulators inside a disposable Docker container, never
real malware - found and fixed four real gaps, and confirmed two more that are disclosed below
as deliberate, unfixed tradeoffs rather than patched:

Fixed:

- **Intermittent/partial-encryption evasion.** Entropy used to be sampled only from a file's
  first `sample_bytes`. A file left with its header untouched and only encrypted/corrupted from
  some later offset onward - a real technique some ransomware uses specifically to dodge
  head-only entropy detectors - sampled as ordinary plaintext and went completely undetected in
  testing. Fixed by sampling up to three points (start, middle, end) and scoring each
  independently, taking the highest reading - concatenating the sampled bytes into one buffer
  first (an intermediate version of this fix) turned out to still be evadable, since blending a
  plaintext chunk with a high-entropy one scores the entropy of the *mixture*, which can land
  back under the threshold.
- **Brand-new-subdirectory bypass of the directory-baseline gate.** The burst heuristic requires
  a directory to have previously held plaintext before counting high-entropy writes in it - but
  only checked a file's immediate parent directory. A subdirectory created fresh under an
  already-baselined tree (e.g. a new folder inside a user's active home directory) inherited none
  of that history and so was never protected at all: 20 high-entropy files written directly into
  one went completely undetected in testing. Fixed by walking up the ancestor chain instead of
  checking only the immediate parent.
- **Unbounded memory growth (DoS) from ordinary process churn.** The burst tracker kept one
  bookkeeping entry per distinct PID it had ever seen write a high-entropy file, and only ever
  removed one after that PID triggered an actual detection - so any process that legitimately
  writes a single high-entropy file and exits (which describes an enormous amount of normal
  server activity: short-lived scripts, cron jobs, admin one-liners) leaked a small amount of
  memory forever. 3,000 one-shot writers grew the daemon's RSS from ~1.9 MB to ~3.0 MB with no
  way back down; on a busy, long-lived server this is a slow path to OOM (i.e. to the protection
  itself going down). Fixed with an opportunistic sweep that drops any PID's bookkeeping once its
  own window has elapsed - confirmed by re-running the same 3,000-process load, then observing
  RSS drop back down once the sweep next runs.
- **Trust-cache identity gap.** The trusted-executable cache kept its "trusted" verdict for a PID
  for 60 seconds based on the PID number alone, with no check that it still refers to the same
  process. That's a real gap in principle (a reused PID, or a trusted-but-scriptable tool that
  changes what code it's running mid-life, could inherit unearned trust for the rest of the
  window) - a live PID-recycling or code-injection proof-of-concept wasn't achievable in this
  sandboxed test environment (writing to `/proc/sys/kernel/pid_max` was blocked read-only, and
  installing a compiler for a custom PoC hit repeated network failures pulling apt packages), so
  this one is a proactive fix from code-level reasoning rather than a confirmed live exploit.
  Fixed by binding each cache entry to the process's boot-relative start time (from
  `/proc/<pid>/stat`), so a cache hit means "the exact same process", not just "the same PID
  number".
- Quarantine and incident-report directories are now created with explicit `0700` permissions by
  the daemon itself, rather than relying on `install.sh` (which already did this) or an
  umask-dependent default from `create_dir_all` - defense in depth for a manual or non-`install.sh`
  deployment.

Confirmed, disclosed, **not** fixed (see caveats below for why):

- **Distributed multi-process burst evasion.** Splitting the same amount of encryption across
  several concurrent processes, each staying under `burst_file_count`, evades the burst heuristic
  entirely - confirmed with 4 workers x 7 files each (28 files total, 0 detected) even though a
  single process doing all 28 would have been stopped at file 8.
- **Silent honeypot disarming.** Deleting a honeypot file produces no fanotify event under the
  mask this daemon watches (`FAN_CLOSE_WRITE`/`FAN_MODIFY` - deletion is neither), so an attacker
  who finds and removes a honeypot disarms that specific trap with no detection at all, confirmed
  in testing. The daemon's other defenses (burst/entropy heuristic, any other honeypots) are
  unaffected.

Caveats, honestly:

- This is heuristic, behavior-based detection - not a cryptographic guarantee. A patient
  attacker who deliberately encrypts below the burst threshold, spread over a long time, could
  evade the burst heuristic (honeypots remain a strong independent signal in that case, but
  aren't guaranteed to be touched first). In practice this matters mainly against a
  well-resourced, patient attacker deliberately staying under the radar - not the common
  opportunistic ransomware case, which wants to encrypt as much as possible as fast as possible
  and is exactly what the burst heuristic is built to catch quickly.
- Detection is scoped per originating PID, by design (this is what lets ordinary, unrelated
  activity on a shared host coexist without one process's writes counting against another's
  threshold) - the tradeoff is the confirmed distributed multi-process evasion described above.
  Honeypots are unaffected by this and remain the independent backstop for that scenario.
- Honeypots are a strong signal only for as long as they exist and are watched for writes -
  deletion is silent, as described above. Plant more than one, in more than one location.
- The trusted-executables allowlist is a scalpel, not a broad exemption: allowlist specific,
  narrow admin/backup scripts you actually control, not general-purpose system crypto tools -
  anything that can be invoked to bulk-process arbitrary files, if allowlisted, is a tool an
  attacker could in principle also invoke directly against victim files to bypass the burst
  heuristic (though never honeypot detection). This also means: don't allowlist anything that
  itself has a plugin/hook/scripting surface (e.g. a shell, an interpreter) rather than being a
  fixed, self-contained tool - the trust cache's 60-second window is checked against the trusted
  process's identity (see "Trust-cache identity gap" above), not against what code it's actually
  running at every instant.
- Detection thresholds are defaults, not universal constants - tune `entropy_threshold`,
  `burst_file_count`, and `burst_window_secs` against your actual workload, ideally starting in
  `monitor` mode.
- Testing here used simulated I/O *patterns*, never real ransomware samples - by design, per a
  strict no-real-malware testing policy. Real-world validation against actual ransomware
  families has not been performed.
- It's a young project that has had three review passes, not a production track record. Treat it
  as a strong additional layer, not a sole line of defense - keep offline/immutable backups
  regardless.
