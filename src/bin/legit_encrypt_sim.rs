//! Simulates a LEGITIMATE encryption tool (e.g. `gpg -c` run in a loop) used
//! by a user or script to encrypt several of their own files in place,
//! inside a directory that already has ordinary plaintext content. This is
//! the false-positive scenario the trusted-executables allowlist exists
//! for: without it, this looks identical to ransomware to the burst
//! heuristic. Writes real (locally generated, non-secret) high-entropy
//! bytes, no actual cryptography or malicious code.

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
    let target_dir = PathBuf::from(args.next().unwrap_or_else(|| "/data/victim".to_string()));
    let file_count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);

    fs::create_dir_all(&target_dir)?;

    println!(
        "[legit-encrypt] pid={} seeding {file_count} plaintext files in {}",
        std::process::id(),
        target_dir.display()
    );
    for i in 0..file_count {
        let path = target_dir.join(format!("document_{i}.txt"));
        fs::write(&path, format!("This is a normal plain-text document number {i}.\nLorem ipsum dolor sit amet.\n"))?;
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    println!("[legit-encrypt] user-requested encryption of their own files (single trusted process)");
    for i in 0..file_count {
        let dst = target_dir.join(format!("document_{i}.txt.gpg"));
        let payload = random_bytes(65536)?;
        let mut f = fs::File::create(&dst)?;
        f.write_all(&payload)?;
        println!("[legit-encrypt] encrypted: {}", dst.display());
    }

    println!("[legit-encrypt] done (if you're reading this, ransomshield did not stop this process).");
    Ok(())
}
