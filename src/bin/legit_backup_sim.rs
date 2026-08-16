//! Simulates a LEGITIMATE backup/archival job: a single process creating
//! several brand-new, already-compressed-looking (high-entropy) files in a
//! directory that never held plaintext content. Used to check ransomshield
//! does not false-positive on this common, benign server workload.
//! No pre-existing files are touched or deleted.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut f = fs::File::open("/dev/urandom")?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn main() -> std::io::Result<()> {
    let mut args = env::args().skip(1);
    let target_dir = PathBuf::from(args.next().unwrap_or_else(|| "/data/backups".to_string()));
    let file_count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(15);

    fs::create_dir_all(&target_dir)?;

    println!("[legit-backup] pid={} writing {file_count} new archive-like files to {}", std::process::id(), target_dir.display());
    for i in 0..file_count {
        let path = target_dir.join(format!("backup_{i}.tar.gz"));
        let payload = random_bytes(65536)?;
        let mut f = fs::File::create(&path)?;
        f.write_all(&payload)?;
        println!("[legit-backup] wrote {}", path.display());
    }

    println!("[legit-backup] done (if you're reading this, ransomshield did not stop this process).");
    Ok(())
}
