use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const CANARY_CONTENT: &[u8] =
    b"This file is a RansomShield canary. Do not delete. Any modification triggers an incident response.\n";

/// Canary files are deliberately world-writable. A honeypot only works if the
/// attacker can actually take the bait: with the daemon's root umask the
/// canary would be mode 0644 root-owned, so an unprivileged process - the
/// common ransomware case on a data server - gets EACCES trying to open it,
/// and a *failed* open produces no fanotify event at all. The trap would be
/// physically incapable of firing.
///
/// Writable file inside a root-owned, non-world-writable parent directory is
/// the sweet spot: the attacker can write to it (the trap fires) but cannot
/// unlink or rename it (no write permission on the directory), which also
/// closes the "silently delete the honeypot" and "rename it first" evasions.
const CANARY_MODE: u32 = 0o666;

/// The provisioned decoy files, identified by `(st_dev, st_ino)` rather than
/// by path.
///
/// Path-based identity is trivially defeated, because a path is just a string
/// that can be detached from the inode it used to name. All three of these
/// bypass a path comparison while writing to the very same canary inode:
///
/// - a hard link to the canary under some other name;
/// - `open()` then `unlink()` then `write()`, after which the kernel renders
///   the path as `<path> (deleted)` in `/proc/self/fd`, matching nothing;
/// - `rename()` before writing - and rename is not in the watched event mask,
///   so it is invisible on its own.
///
/// The inode is stable across all three. It is also cheaper to check: fanotify
/// already hands us an open descriptor, so one `fstat` replaces a `readlink`
/// plus a `canonicalize` on the hot path.
pub struct Honeypots {
    /// (st_dev, st_ino) -> the path we provisioned it at, for re-arming.
    by_inode: HashMap<(u64, u64), PathBuf>,
}

impl Honeypots {
    /// Creates the configured decoy files on disk if missing and records the
    /// inode of each.
    pub fn provision(paths: &[PathBuf]) -> Result<Self> {
        let mut by_inode = HashMap::new();

        for p in paths {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent dir for honeypot {}", p.display()))?;
            }
            // Check via symlink_metadata (does not follow the final component)
            // rather than Path::exists()/fs::write's own O_CREAT, which would
            // both follow a symlink planted at `p` and write the fixed canary
            // content through it to whatever it points at.
            match fs::symlink_metadata(p) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    warn!(path = %p.display(), "honeypot path is a symlink, refusing to provision through it");
                    continue;
                }
                Ok(_) => {
                    // Already exists as a regular file/dir - leave the content
                    // alone, but still make sure it is takeable bait.
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(CANARY_MODE));
                }
                Err(_) => {
                    fs::write(p, CANARY_CONTENT)
                        .with_context(|| format!("writing honeypot file {}", p.display()))?;
                    fs::set_permissions(p, fs::Permissions::from_mode(CANARY_MODE))
                        .with_context(|| format!("setting permissions on honeypot {}", p.display()))?;
                    info!(path = %p.display(), "provisioned honeypot file");
                }
            }

            let meta = fs::metadata(p)
                .with_context(|| format!("stat'ing honeypot path {}", p.display()))?;
            by_inode.insert((meta.dev(), meta.ino()), p.clone());
        }

        Ok(Self { by_inode })
    }

    pub fn is_empty(&self) -> bool {
        self.by_inode.is_empty()
    }

    /// The path this inode was provisioned at, if it is one of our canaries.
    pub fn lookup(&self, dev: u64, ino: u64) -> Option<&Path> {
        self.by_inode.get(&(dev, ino)).map(|p| p.as_path())
    }

    /// Whether any configured honeypot lives under one of `roots`. A canary on
    /// an unwatched filesystem is provisioned successfully and then never
    /// fires, which is worse than having no canary at all: it looks like
    /// protection.
    pub fn all_within(&self, roots: &[PathBuf]) -> bool {
        self.by_inode
            .values()
            .all(|p| roots.iter().any(|r| p.starts_with(r)))
    }

    /// Re-arm a canary after an incident: restore its content and re-record
    /// its inode.
    ///
    /// Without this, responding to a honeypot hit permanently disarmed the
    /// trap - the response quarantined every affected file, the canary was in
    /// that list, and quarantine is a `rename` off the live filesystem, so the
    /// canary deleted itself. `provision()` only runs at daemon startup, so
    /// nothing put it back. One throwaway `touch` per honeypot was enough to
    /// strip the daemon of its honeypot signal entirely until a restart.
    pub fn rearm(&mut self, dev: u64, ino: u64) {
        let Some(path) = self.by_inode.get(&(dev, ino)).cloned() else { return };

        if let Err(e) = fs::write(&path, CANARY_CONTENT) {
            warn!(path = %path.display(), error = %e, "could not re-arm honeypot after incident");
            return;
        }
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(CANARY_MODE));

        // Rewriting may have produced a new inode (e.g. the attacker renamed
        // the old one away and fs::write created a fresh file), so re-key.
        match fs::metadata(&path) {
            Ok(meta) => {
                self.by_inode.remove(&(dev, ino));
                self.by_inode.insert((meta.dev(), meta.ino()), path.clone());
                info!(path = %path.display(), "honeypot re-armed");
            }
            Err(e) => warn!(path = %path.display(), error = %e, "honeypot re-armed but could not re-stat it"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("rs_hp_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn ids(path: &Path) -> (u64, u64) {
        let m = fs::metadata(path).unwrap();
        (m.dev(), m.ino())
    }

    #[test]
    fn a_hard_link_to_the_canary_is_still_recognized_as_the_canary() {
        // Path-based identity used to miss this entirely: same inode, and the
        // event reports the *link's* path, which matches no configured
        // honeypot.
        let dir = tmpdir("hardlink");
        let canary = dir.join("DO_NOT_TOUCH.docx");
        let hp = Honeypots::provision(&[canary.clone()]).unwrap();

        let link = dir.join("harmless.txt");
        fs::hard_link(&canary, &link).unwrap();

        let (dev, ino) = ids(&link);
        assert!(hp.lookup(dev, ino).is_some(), "writing through a hard link must still be a honeypot hit");
    }

    #[test]
    fn renaming_the_canary_before_writing_does_not_shake_off_detection() {
        let dir = tmpdir("rename");
        let canary = dir.join("DO_NOT_TOUCH.docx");
        let hp = Honeypots::provision(&[canary.clone()]).unwrap();

        let renamed = dir.join("DO_NOT_TOUCH.docx.locked");
        fs::rename(&canary, &renamed).unwrap();

        let (dev, ino) = ids(&renamed);
        assert!(hp.lookup(dev, ino).is_some(), "rename does not change the inode, so the trap must still fire");
    }

    #[test]
    fn the_canary_is_writable_by_an_unprivileged_attacker() {
        // A trap the attacker cannot open for writing produces no fanotify
        // event and can never fire.
        let dir = tmpdir("mode");
        let canary = dir.join("bait.docx");
        Honeypots::provision(&[canary.clone()]).unwrap();
        let mode = fs::metadata(&canary).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, CANARY_MODE, "canary must be world-writable bait, got {mode:o}");
    }

    #[test]
    fn re_arming_restores_a_canary_that_an_incident_consumed() {
        let dir = tmpdir("rearm");
        let canary = dir.join("bait.docx");
        let mut hp = Honeypots::provision(&[canary.clone()]).unwrap();
        let (dev, ino) = ids(&canary);

        // Simulate what the response used to do to its own trap.
        fs::remove_file(&canary).unwrap();
        assert!(!canary.exists());

        hp.rearm(dev, ino);
        assert!(canary.exists(), "the canary must be back on disk after an incident");

        let (d2, i2) = ids(&canary);
        assert!(hp.lookup(d2, i2).is_some(), "and the re-armed canary must be tracked under its new inode");
    }

    #[test]
    fn a_honeypot_outside_every_watch_root_is_reported() {
        let dir = tmpdir("scope");
        let canary = dir.join("bait.docx");
        let hp = Honeypots::provision(&[canary]).unwrap();
        assert!(hp.all_within(&[dir.clone()]));
        assert!(!hp.all_within(&[PathBuf::from("/nowhere-near-here")]));
        let mut f = fs::File::create(dir.join("x")).unwrap();
        let _ = f.write_all(b"x");
    }
}
