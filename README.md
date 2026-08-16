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
2. **Entropy sampling** - when a file is closed after being written, RansomShield reads the
   first few KB through the same file descriptor the kernel handed it in the event (not by
   re-opening the path) and computes its Shannon entropy. Encrypted/compressed data sits near
   the theoretical maximum (~8 bits/byte); plain text and most documents sit well below it.
3. **Directory baseline** - a high-entropy write only counts toward detection if its directory
   has *previously* held ordinary (low-entropy) content - either observed live, or found during
   a one-time startup scan of existing files. This is what tells apart "your documents folder
   is suddenly full of ciphertext" (suspicious) from "your backup/export folder just received a
   batch of new archives" (routine). Without it, any workload that legitimately produces batches
   of new compressed files (backups, media exports, build artifacts) would trigger false
   positives.
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

```sh
sudo cp target/release/ransomshield /usr/local/bin/
sudo cp systemd/ransomshield.service /etc/systemd/system/
sudo mkdir -p /etc/ransomshield && sudo cp your-config.json /etc/ransomshield/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now ransomshield
```

The unit requests only `CAP_SYS_ADMIN` (for `fanotify`) and `CAP_KILL` (to neutralize
processes) - not full root capabilities - and sets `NoNewPrivileges`/`ProtectSystem=strict`.

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
  conservative-enterprise (RockyLinux/AlmaLinux, RHEL-family) glibc/kernel baselines.

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

Caveats, honestly:

- This is heuristic, behavior-based detection - not a cryptographic guarantee. A patient
  attacker who deliberately encrypts below the burst threshold, spread over a long time, could
  evade the burst heuristic (honeypots remain a strong independent signal in that case, but
  aren't guaranteed to be touched first). In practice this matters mainly against a
  well-resourced, patient attacker deliberately staying under the radar - not the common
  opportunistic ransomware case, which wants to encrypt as much as possible as fast as possible
  and is exactly what the burst heuristic is built to catch quickly.
- The trusted-executables allowlist is a scalpel, not a broad exemption: allowlist specific,
  narrow admin/backup scripts you actually control, not general-purpose system crypto tools -
  anything that can be invoked to bulk-process arbitrary files, if allowlisted, is a tool an
  attacker could in principle also invoke directly against victim files to bypass the burst
  heuristic (though never honeypot detection).
- Detection thresholds are defaults, not universal constants - tune `entropy_threshold`,
  `burst_file_count`, and `burst_window_secs` against your actual workload, ideally starting in
  `monitor` mode.
- Testing here used simulated I/O *patterns*, never real ransomware samples - by design, per a
  strict no-real-malware testing policy. Real-world validation against actual ransomware
  families has not been performed.
- It's a young project that has had two review passes, not a production track record. Treat it
  as a strong additional layer, not a sole line of defense - keep offline/immutable backups
  regardless.
