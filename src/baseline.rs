use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::{fs, path::PathBuf};

use tracing::{info, warn};

use crate::detector::Detector;
use crate::entropy::shannon_entropy;

const MAX_FILES_SCANNED: usize = 50_000;

/// Reads up to `budget` bytes of `f`'s content, sampled from up to three
/// points (start, middle, end) instead of only its head, and returns the
/// *lowest* Shannon entropy measured across those samples - `None` if the
/// file is empty.
///
/// Unlike the equivalent helper in `fanotify_monitor.rs` (which takes the
/// max, because for live detection *any* sampled chunk reading as
/// high-entropy is suspicious), this takes the min: this scan's job is only
/// to recognize "has this directory ever held ordinary content", and a file
/// with *any* identifiable plaintext chunk - even one that's partly
/// high-entropy elsewhere (an existing compressed attachment in an
/// otherwise-plaintext document, say) - is reasonable evidence of that.
/// Concatenating all sampled bytes into one buffer first, instead, would
/// score the entropy of the mixture rather than of either chunk, which for
/// a large plaintext file already partly rewritten with random data before
/// a restart could land back above the threshold and wrongly withhold the
/// baseline this file should otherwise have granted.
fn min_sampled_entropy(f: &mut fs::File, budget: usize) -> Option<f64> {
    let size = f.seek(SeekFrom::End(0)).unwrap_or(0);

    let mut probe = |offset: u64, len: usize| -> Option<f64> {
        if len == 0 || f.seek(SeekFrom::Start(offset)).is_err() {
            return None;
        }
        let mut chunk = vec![0u8; len];
        let n = f.read(&mut chunk).unwrap_or(0);
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

    samples.into_iter().reduce(f64::min)
}

/// Walks `root` once at startup, sampling existing files so directories
/// that already hold ordinary content are immediately recognized as having
/// a plaintext baseline. Without this, a daemon restart would momentarily
/// "forget" that a directory has real user data, weakening the burst
/// heuristic right when it matters most (right after (re)start).
pub fn seed(detector: &mut Detector, root: &Path, sample_bytes: usize, entropy_threshold: f64) {
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut scanned = 0usize;

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "baseline scan: cannot read directory");
                continue;
            }
        };

        for entry in entries.flatten() {
            if scanned >= MAX_FILES_SCANNED {
                warn!(
                    limit = MAX_FILES_SCANNED,
                    "baseline scan: file limit reached, stopping early (directories not yet \
                     seen will build up a baseline organically as normal writes happen)"
                );
                return;
            }

            // DirEntry::metadata() does not follow symlinks (equivalent to
            // lstat), so symlinked directories are treated as neither a
            // dir nor a regular file here and simply skipped - avoids
            // symlink cycles during the walk.
            let Ok(meta) = entry.metadata() else { continue };
            let path = entry.path();

            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }

            scanned += 1;
            let Ok(mut f) = fs::File::open(&path) else { continue };

            if min_sampled_entropy(&mut f, sample_bytes).is_some_and(|e| e < entropy_threshold) {
                detector.note_plaintext_activity(&path);
            }
        }
    }

    info!(scanned, dir = %root.display(), "baseline scan complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
    fn min_sampled_entropy_finds_a_plaintext_header_behind_a_large_random_tail() {
        let path = temp_path("baseline_header.bin");
        {
            let mut f = fs::File::create(&path).unwrap();
            // Plaintext header, larger than a single probe's share of the
            // budget, so the "start" probe reads only plaintext.
            f.write_all("the quick brown fox jumps over the lazy dog ".repeat(200).as_bytes()).unwrap();
            // A large high-entropy tail - the intermittent-encryption
            // shape: only the back of the file was ever touched.
            f.write_all(&pseudo_random_bytes(64 * 1024)).unwrap();
        }
        let mut f = fs::File::open(&path).unwrap();
        let min_e = min_sampled_entropy(&mut f, 8192);
        let _ = fs::remove_file(&path);

        let min_e = min_e.expect("file is not empty");
        assert!(min_e < 4.5, "expected the plaintext header to pull the minimum down, got {min_e}");
    }

    #[test]
    fn min_sampled_entropy_is_none_for_an_empty_file() {
        let path = temp_path("baseline_empty.bin");
        fs::File::create(&path).unwrap();
        let mut f = fs::File::open(&path).unwrap();
        let result = min_sampled_entropy(&mut f, 8192);
        let _ = fs::remove_file(&path);
        assert!(result.is_none());
    }
}
