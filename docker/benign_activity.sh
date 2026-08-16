#!/usr/bin/env bash
# Normal, non-malicious file activity in the same watched directory, used to
# check ransomshield does NOT flag ordinary usage (false-positive check).
set -euo pipefail

TARGET_DIR="${1:-/data/victim}"
mkdir -p "$TARGET_DIR"

for i in $(seq 1 5); do
    echo "log line $(date -Iseconds) iteration $i" >> "$TARGET_DIR/app.log"
    sleep 1
done

echo "[benign] done."
