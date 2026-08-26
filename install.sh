#!/usr/bin/env bash
# RansomShield installer: builds the daemon from this checkout, installs the
# binary, config, and systemd service, then starts and verifies it.
#
# Usage:
#   sudo ./install.sh                     # watches /home, starts in monitor mode
#   sudo ./install.sh /data /srv/www      # watches the given directories instead
#   sudo ./install.sh --enforce /data     # starts directly in enforce mode (see warning below)
#
# Safe to re-run: rebuilds and reinstalls the binary and systemd unit, but
# never touches an existing /etc/ransomshield/config.json (so re-running to
# upgrade doesn't clobber thresholds you've already tuned).
set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi
log_info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$1"; }
log_ok()   { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
log_warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
log_err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }
die() { log_err "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BIN_DEST=/usr/local/bin/ransomshield
CONFIG_DIR=/etc/ransomshield
CONFIG_FILE="$CONFIG_DIR/config.json"
UNIT_SRC="$SCRIPT_DIR/systemd/ransomshield.service"
UNIT_DEST=/etc/systemd/system/ransomshield.service
UNIT_DROPIN_DIR=/etc/systemd/system/ransomshield.service.d
QUARANTINE_DIR=/var/lib/ransomshield/quarantine
INCIDENTS_DIR=/var/lib/ransomshield/incidents
SERVICE_NAME=ransomshield

MODE="monitor"
WATCH_DIRS=()

usage() {
    cat <<EOF
Usage: sudo $0 [--enforce] [DIR...]

  DIR...      Directories to watch for ransomware-like activity.
              Defaults to /home if none given.
  --enforce   Start in Enforce mode (kill + quarantine) instead of the
              default Monitor mode (log only). Only pass this once you've
              already reviewed monitor-mode incident reports on real traffic
              and are confident in the thresholds - see the README.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --enforce) MODE="enforce"; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) die "unknown option: $1 (see --help)" ;;
        *) WATCH_DIRS+=("$1"); shift ;;
    esac
done
if [ "${#WATCH_DIRS[@]}" -eq 0 ]; then
    WATCH_DIRS=(/home)
fi

# ---------------------------------------------------------------------------
# Preflight checks - fail fast and clearly, this runs as root
# ---------------------------------------------------------------------------
log_info "RansomShield installer starting - preflight checks"

[ "$(id -u)" -eq 0 ] || die "must be run as root (try: sudo $0 $*)"

[ "$(uname -s)" = "Linux" ] || die "RansomShield only runs on Linux (uses fanotify, a Linux-only kernel API)"

command -v systemctl >/dev/null 2>&1 || die "systemd/systemctl not found - this installer only supports systemd-managed hosts"
[ -d /run/systemd/system ] || die "systemd does not appear to be the running init system (no /run/systemd/system) - refusing to install a systemd service"

[ -f "$SCRIPT_DIR/Cargo.toml" ] && [ -f "$SCRIPT_DIR/src/main.rs" ] || \
    die "run this script from inside a RansomShield checkout (Cargo.toml/src/main.rs not found next to it)"

suggest_toolchain_install() {
    local id="unknown"
    [ -f /etc/os-release ] && id="$(. /etc/os-release && echo "$ID")"
    case "$id" in
        ubuntu|debian) echo "  apt update && apt install -y cargo build-essential" ;;
        fedora)        echo "  dnf install -y cargo gcc" ;;
        rhel|rocky|almalinux|centos) echo "  dnf install -y cargo gcc  (enable EPEL/CRB first if not found)" ;;
        arch)          echo "  pacman -S rust base-devel" ;;
        opensuse*|sles) echo "  zypper install -y cargo gcc" ;;
        *)              echo "  install a Rust toolchain (cargo, rustc) and a C compiler for your distro, or via https://rustup.rs" ;;
    esac
}

missing_tools=()
command -v cargo >/dev/null 2>&1 || missing_tools+=("cargo")
command -v rustc >/dev/null 2>&1 || missing_tools+=("rustc")
command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || missing_tools+=("a C compiler (cc/gcc/clang, needed to link)")
if [ "${#missing_tools[@]}" -gt 0 ]; then
    log_err "missing build tools: ${missing_tools[*]}"
    log_info "on this system, try:"
    suggest_toolchain_install
    exit 1
fi

log_ok "preflight checks passed"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
log_info "building ransomshield --release from $SCRIPT_DIR (this can take a minute or two)"
if ! ( cd "$SCRIPT_DIR" && cargo build --release --bin ransomshield ); then
    die "build failed - see cargo output above"
fi

BUILT_BIN="$SCRIPT_DIR/target/release/ransomshield"
[ -x "$BUILT_BIN" ] || die "build reported success but $BUILT_BIN is missing or not executable"
log_ok "build succeeded: $BUILT_BIN"

# ---------------------------------------------------------------------------
# Stop any existing instance before replacing files (upgrade-safe: don't
# leave a mix of an old running process and new-on-disk config/unit).
# ---------------------------------------------------------------------------
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    log_info "stopping existing $SERVICE_NAME service before upgrading"
    systemctl stop "$SERVICE_NAME"
fi

# ---------------------------------------------------------------------------
# Install binary
# ---------------------------------------------------------------------------
install -m 0755 -o root -g root "$BUILT_BIN" "$BIN_DEST"
log_ok "installed binary to $BIN_DEST"

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
install -d -m 0750 -o root -g root "$CONFIG_DIR"
install -d -m 0700 -o root -g root "$QUARANTINE_DIR"
install -d -m 0700 -o root -g root "$INCIDENTS_DIR"
log_ok "created $CONFIG_DIR, $QUARANTINE_DIR, $INCIDENTS_DIR"

# Create any watch directory that doesn't exist yet, so the daemon doesn't
# fail to start over a missing mountpoint/directory. Only touched if
# missing - never alters permissions of a directory that already exists.
for d in "${WATCH_DIRS[@]}"; do
    d="${d%/}"
    if [ ! -d "$d" ]; then
        install -d -m 0755 -o root -g root "$d"
        log_warn "$d did not exist, created it"
    fi
done

# ---------------------------------------------------------------------------
# Config - never overwrite an existing one (preserves tuned thresholds
# across a reinstall/upgrade).
# ---------------------------------------------------------------------------
json_escape() {
    # Minimal but correct JSON string escaping for the paths we embed.
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

EFFECTIVE_WATCH_DIRS=("${WATCH_DIRS[@]}")

if [ -f "$CONFIG_FILE" ]; then
    log_warn "$CONFIG_FILE already exists, leaving its contents untouched (watch_dirs/mode arguments to this run are ignored)"
    # Contents are preserved, but permissions are corrected: earlier versions
    # installed this world-readable, and the daemon now refuses to start on a
    # group/world-writable config.
    current_mode="$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || echo unknown)"
    if [ "$current_mode" != "600" ]; then
        chmod 0600 "$CONFIG_FILE"
        chown root:root "$CONFIG_FILE"
        log_warn "tightened $CONFIG_FILE from mode $current_mode to 0600 (it lists your honeypot locations and thresholds)"
    fi
    # The ReadWritePaths drop-in below must grant access to what's actually
    # configured, not to this run's (ignored) arguments - otherwise a
    # reinstall after watch_dirs changed by hand would grant access to the
    # wrong set of directories. Best-effort extraction; if the existing
    # file doesn't parse as expected, fall back to this run's arguments
    # rather than silently generating an empty ReadWritePaths.
    mapfile -t parsed_dirs < <(
        awk '/"watch_dirs"/{f=1} f{buf=buf $0; if ($0 ~ /\]/){print buf; exit}}' "$CONFIG_FILE" 2>/dev/null \
            | grep -oE '"[^"]*"' | tail -n +2 | tr -d '"'
    )
    if [ "${#parsed_dirs[@]}" -gt 0 ]; then
        EFFECTIVE_WATCH_DIRS=("${parsed_dirs[@]}")
        log_info "using watch_dirs from existing config for systemd permissions: ${EFFECTIVE_WATCH_DIRS[*]}"
    else
        log_warn "could not parse watch_dirs out of the existing $CONFIG_FILE, falling back to this run's arguments for systemd permissions - if that's wrong, adjust $UNIT_DROPIN_DIR/local.conf by hand"
    fi
else
    watch_dirs_json="["
    honeypots_json="["
    first=1
    for d in "${WATCH_DIRS[@]}"; do
        d="${d%/}"
        [ -n "$d" ] || die "empty directory argument"
        if [ "$first" -eq 0 ]; then watch_dirs_json+=","; honeypots_json+=","; fi
        watch_dirs_json+="\"$(json_escape "$d")\""
        honeypots_json+="\"$(json_escape "$d/.ransomshield-honeypot/DO_NOT_DELETE.txt")\""
        first=0
    done
    watch_dirs_json+="]"
    honeypots_json+="]"

    cat > "$CONFIG_FILE" <<EOF
{
  "watch_dirs": $watch_dirs_json,
  "honeypots": $honeypots_json,
  "mode": "$MODE"
}
EOF
    # 0600, not 0644. This file lists exactly where the honeypots are, which
    # directories are watched, the detection thresholds, and the trusted-binary
    # allowlist - i.e. a complete map of what an attacker needs to avoid. Only
    # root needs to read it.
    chmod 0600 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    log_ok "wrote $CONFIG_FILE (mode=$MODE, watch_dirs=${WATCH_DIRS[*]})"
    if [ "$MODE" = "enforce" ]; then
        log_warn "starting directly in enforce mode - make sure you've already validated this workload against false positives (see README)"
    fi
fi

# ---------------------------------------------------------------------------
# systemd unit + a drop-in granting write access to the directories this
# specific install actually needs (ProtectSystem=strict in the base unit
# makes everything else read-only - see systemd/ransomshield.service).
# ---------------------------------------------------------------------------
install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DEST"
install -d -m 0755 "$UNIT_DROPIN_DIR"

rwpaths="$CONFIG_DIR $QUARANTINE_DIR $INCIDENTS_DIR"
for d in "${EFFECTIVE_WATCH_DIRS[@]}"; do
    rwpaths+=" ${d%/}"
done

cat > "$UNIT_DROPIN_DIR/local.conf" <<EOF
# Generated by install.sh - adds write access (on top of the base unit's
# ProtectSystem=strict) to this install's actual quarantine/incident/watch
# directories. Re-run install.sh after changing watch_dirs to regenerate.
[Service]
ReadWritePaths=$rwpaths
EOF
log_ok "installed systemd unit + ReadWritePaths drop-in ($rwpaths)"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
log_ok "enabled $SERVICE_NAME (will start on boot)"

log_info "starting $SERVICE_NAME"
if ! systemctl restart "$SERVICE_NAME"; then
    log_err "systemctl restart $SERVICE_NAME failed"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
    exit 1
fi

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
log_info "verifying installation"

ready=0
for _ in $(seq 1 20); do
    if systemctl is-active --quiet "$SERVICE_NAME" && journalctl -u "$SERVICE_NAME" --no-pager 2>/dev/null | grep -q "ransomshield ready"; then
        ready=1
        break
    fi
    sleep 0.5
done

if [ "$ready" -ne 1 ]; then
    log_err "$SERVICE_NAME did not reach the ready state in time"
    log_info "service status:"
    systemctl status "$SERVICE_NAME" --no-pager || true
    log_info "recent logs:"
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
    exit 1
fi

installed_version="$("$BIN_DEST" --version 2>/dev/null || echo unknown)"
enabled_state="$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || echo unknown)"

echo
log_ok "RansomShield is installed and running"
cat <<EOF

  Binary:          $BIN_DEST ($installed_version)
  Config:          $CONFIG_FILE
  Service:         $(systemctl is-active "$SERVICE_NAME") / enabled=$enabled_state
  Mode:            $(grep -o '"mode": *"[^"]*"' "$CONFIG_FILE" 2>/dev/null || echo unknown)
  Watching:        ${WATCH_DIRS[*]}
  Quarantine dir:  $QUARANTINE_DIR
  Incident reports: $INCIDENTS_DIR

  Live logs:       journalctl -u $SERVICE_NAME -f
  Edit config:     $CONFIG_FILE (then: systemctl restart $SERVICE_NAME)

EOF

if [ "$MODE" = "monitor" ]; then
    cat <<EOF
  Currently in MONITOR mode: nothing gets killed or quarantined yet, only
  logged and reported to $INCIDENTS_DIR. Let it run against real traffic for
  a while, review the incident reports, tune $CONFIG_FILE if needed, then
  switch "mode" to "enforce" and run: systemctl restart $SERVICE_NAME

EOF
fi

log_ok "done"
