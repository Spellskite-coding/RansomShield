//! Single-process file-encryption *pattern* simulator, for testing
//! ransomshield's detection inside a Docker test container only.
//!
//! Mimics the observable I/O shape of ransomware (many files rewritten with
//! high-entropy data in quick succession from one process) without any
//! actual encryption, exploit, or malware code. Never run outside a
//! disposable test container, and only against a directory meant for this.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut f = fs::File::open("/dev/urandom")?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn main() -> std::io::Result<()> {
    let mut args = env::args().skip(1);
    let target_dir = PathBuf::from(args.next().unwrap_or_else(|| "/data/victim".to_string()));
    let file_count: usize = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    fs::create_dir_all(&target_dir)?;

    println!("[attack-sim] pid={} seeding {file_count} normal-looking files in {}", std::process::id(), target_dir.display());
    for i in 0..file_count {
        let path = target_dir.join(format!("document_{i}.txt"));
        fs::write(&path, format!("This is a normal plain-text document number {i}.\nLorem ipsum dolor sit amet.\n"))?;
    }

    std::thread::sleep(Duration::from_millis(500));

    println!("[attack-sim] rewriting files with high-entropy data (simulated encryption pass, single process)");
    for i in 0..file_count {
        let src = target_dir.join(format!("document_{i}.txt"));
        let dst = target_dir.join(format!("document_{i}.txt.locked"));
        let payload = random_bytes(65536)?;
        let mut f = fs::File::create(&dst)?;
        f.write_all(&payload)?;
        f.sync_all()?;
        let _ = fs::remove_file(&src);
        println!("[attack-sim] encrypted-looking rewrite: {}", dst.display());
    }

    println!("[attack-sim] done (if you're reading this, ransomshield did not stop this process).");
    Ok(())
}
