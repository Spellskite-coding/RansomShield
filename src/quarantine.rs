use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

#[derive(Serialize)]
struct ManifestEntry<'a> {
    quarantined_at_unix: u64,
    pid: i32,
    reason: &'a str,
    original_path: String,
    quarantine_name: String,
}

/// Moves files suspected of being ransomware output out of harm's way and
/// keeps an append-only manifest so a sysadmin can review/restore them
/// later, instead of leaving encrypted-looking files sitting in place.
pub struct Quarantine {
    dir: PathBuf,
    /// Canonicalized watch roots. Nothing outside these is ever touched - see
    /// `take`.
    roots: Vec<PathBuf>,
}

impl Quarantine {
    pub fn new(dir: &Path, roots: Vec<PathBuf>) -> Result<Self> {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating quarantine dir {}", dir.display()))?;
        // Quarantined content is exactly what a ransomware run just wrote,
        // so it's ransomware payload output at rest; set 0700 explicitly
        // rather than trusting create_dir_all's umask-dependent default
        // (install.sh already does this too, but the daemon shouldn't
        // depend on that - this dir can also be created directly by the
        // daemon itself, e.g. a manual, non-install.sh deployment, or a
        // fresh boot where the directory was deleted).
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting permissions on quarantine dir {}", dir.display()))?;
        Ok(Self { dir: dir.to_path_buf(), roots })
    }

    /// Move `original` into quarantine and record it in the manifest.
    /// Returns `Ok(None)` if the file was already gone by the time we got
    /// to it (e.g. the process deleted it itself), or if it falls outside
    /// every watch root.
    pub fn take(&self, original: &Path, pid: i32, reason: &str) -> Result<Option<PathBuf>> {
        // Re-resolve by path rather than by the fd the fanotify event
        // originally carried, so re-check the path is still a plain file
        // and not a symlink planted in the meantime: the cross-device
        // fallback below uses fs::copy, which (unlike fs::rename) follows
        // symlinks, and would otherwise let anything capable of replacing
        // this path with a symlink make root read and copy an arbitrary
        // target it points to.
        let Ok(meta) = fs::symlink_metadata(original) else {
            return Ok(None);
        };
        if meta.file_type().is_symlink() {
            warn!(
                path = %original.display(),
                pid,
                "path to quarantine is a symlink, refusing to follow it; removing the symlink itself instead"
            );
            let _ = fs::remove_file(original);
            return Ok(None);
        }

        // Containment. `symlink_metadata` above only vets the *final*
        // component; neither `fs::rename` nor the `fs::copy` fallback stops at
        // a symlinked *directory* in the prefix. An attacker with a second,
        // un-stopped process can swap a parent directory for a symlink to
        // /etc between detection and quarantine and have root relocate
        // arbitrary system files. Canonicalizing resolves those prefix
        // symlinks, so requiring the result to sit under a configured watch
        // root closes that whole class - and also keeps a filesystem-wide
        // fanotify mark from ever letting the daemon act outside the scope
        // the operator actually declared.
        let canonical = original
            .canonicalize()
            .unwrap_or_else(|_| original.to_path_buf());
        if !self.roots.iter().any(|r| canonical.starts_with(r)) {
            warn!(
                path = %original.display(),
                resolved = %canonical.display(),
                pid,
                "refusing to quarantine a file that resolves outside every watch_dir"
            );
            return Ok(None);
        }

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let quarantine_name = quarantine_name(stamp, pid, original);
        let dest = self.dir.join(&quarantine_name);

        match fs::rename(original, &dest) {
            Ok(()) => {}
            // Cross-device or other rename failure: fall back to copy+remove.
            Err(_) => {
                fs::copy(original, &dest)
                    .with_context(|| format!("copying {} to quarantine", original.display()))?;
                let _ = fs::remove_file(original);
            }
        }

        info!(original = %original.display(), quarantined_as = %dest.display(), pid, "file quarantined");

        if let Err(e) = self.append_manifest(&ManifestEntry {
            quarantined_at_unix: stamp,
            pid,
            reason,
            original_path: original.display().to_string(),
            quarantine_name: quarantine_name.clone(),
        }) {
            error!(error = %e, "failed to write quarantine manifest entry");
        }

        Ok(Some(dest))
    }

    fn append_manifest(&self, entry: &ManifestEntry) -> Result<()> {
        let manifest_path = self.dir.join("manifest.jsonl");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&manifest_path)
            .with_context(|| format!("opening {}", manifest_path.display()))?;
        writeln!(f, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }
}

/// A bounded, collision-free name for a quarantined file.
///
/// The previous scheme embedded the whole original path with `/` replaced by
/// `_`, which had two problems, both reachable by an attacker who simply
/// chooses their own filenames. Linux caps a single filename at 255 bytes, so
/// a deep enough path made both the rename *and* the copy fallback fail with
/// ENAMETOOLONG, leaving the encrypted file in place while the response
/// reported success. And the `/` -> `_` substitution is not injective:
/// `/data/x/y` and `/data/x_y` collided, silently overwriting one piece of
/// evidence with another.
///
/// Truncating the readable part and appending a hash of the *full* path fixes
/// both: the name is always well under the limit, and distinct paths always
/// produce distinct names. The manifest carries the untruncated original.
fn quarantine_name(stamp: u64, pid: i32, original: &Path) -> String {
    const MAX_READABLE: usize = 120;

    let full = original.to_string_lossy();
    let digest = Sha256::digest(full.as_bytes());
    let short_hash: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();

    let sanitized: String = full
        .chars()
        .map(|c| if c == '/' || c.is_control() { '_' } else { c })
        .collect();
    // Truncate on a char boundary so multi-byte filenames stay valid UTF-8.
    let readable: String = sanitized.chars().rev().take(MAX_READABLE).collect::<Vec<_>>()
        .into_iter().rev().collect();

    format!("{stamp}_{pid}_{readable}_{short_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("rs_q_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_very_deep_path_still_produces_a_usable_filename() {
        // This used to fail with ENAMETOOLONG, leaving the encrypted file in
        // place while the daemon logged a successful response.
        let mut deep = PathBuf::from("/data");
        for _ in 0..40 {
            deep = deep.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }
        let name = quarantine_name(1, 2, &deep.join("payload.bin"));
        assert!(name.len() < 255, "quarantine name must fit in a filename, got {}", name.len());
    }

    #[test]
    fn paths_that_used_to_collide_now_get_distinct_names() {
        // `/` -> `_` is not injective; these two both became "data_x_y".
        let a = quarantine_name(1, 2, Path::new("/data/x/y"));
        let b = quarantine_name(1, 2, Path::new("/data/x_y"));
        assert_ne!(a, b, "distinct originals must not overwrite each other in quarantine");
    }

    #[test]
    fn files_outside_every_watch_root_are_refused() {
        let qdir = tmpdir("q_scope");
        let root = tmpdir("q_root");
        let outside = tmpdir("q_outside");

        let victim = outside.join("important.conf");
        fs::write(&victim, b"nowhere near a watch_dir\n").unwrap();

        let q = Quarantine::new(&qdir, vec![root.canonicalize().unwrap()]).unwrap();
        assert_eq!(q.take(&victim, 42, "burst").unwrap(), None);
        assert!(victim.exists(), "a file outside the watched scope must be left alone");
    }

    #[test]
    fn files_inside_a_watch_root_are_still_quarantined() {
        let qdir = tmpdir("q_in");
        let root = tmpdir("q_root_in");
        let victim = root.join("cipher.bin");
        fs::write(&victim, b"ciphertext\n").unwrap();

        let q = Quarantine::new(&qdir, vec![root.canonicalize().unwrap()]).unwrap();
        let dest = q.take(&victim, 42, "burst").unwrap();
        assert!(dest.is_some(), "in-scope files must still be quarantined");
        assert!(!victim.exists());
    }
}
