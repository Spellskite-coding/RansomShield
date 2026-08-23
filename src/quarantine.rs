use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
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
}

impl Quarantine {
    pub fn new(dir: &Path) -> Result<Self> {
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
        Ok(Self { dir: dir.to_path_buf() })
    }

    /// Move `original` into quarantine and record it in the manifest.
    /// Returns `Ok(None)` if the file was already gone by the time we got
    /// to it (e.g. the process deleted it itself).
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

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sanitized = original.to_string_lossy().replace('/', "_");
        let quarantine_name = format!("{stamp}_{pid}_{sanitized}");
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
