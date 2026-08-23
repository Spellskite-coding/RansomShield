#!/usr/bin/env bash
# RansomShield uninstaller: stops and disables the service, and removes the
# binary and systemd unit installed by install.sh.
#
# Usage:
#   sudo ./uninstall.sh            # removes the binary/service, keeps your
#                                   # config, quarantined files, and incident
#                                   # reports on disk
#   sudo ./uninstall.sh --purge     # also removes /etc/ransomshield and
#                                   # /var/lib/ransomshield (config, every
#                                   # quarantined file, every incident report)
#
# Safe to re-run: every step only acts on things that still exist, so running
# this again after a first successful (or partial) uninstall is a no-op.
set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers (match install.sh)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_RESET=""
fi
log_info() { printf '%s[*]%s %s\n' "$C_BLUE" "$C_RESET" "$1"; }
log_ok()   { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
log_warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
log_err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }
die() { log_err "$1"; exit 1; }

# ---------------------------------------------------------------------------
# Config (mirrors install.sh's paths)
# ---------------------------------------------------------------------------
BIN_DEST=/usr/local/bin/ransomshield
CONFIG_DIR=/etc/ransomshield
UNIT_DEST=/etc/systemd/system/ransomshield.service
UNIT_DROPIN_DIR=/etc/systemd/system/ransomshield.service.d
DATA_DIR=/var/lib/ransomshield
SERVICE_NAME=ransomshield

PURGE=0

usage() {
    cat <<EOF
Usage: sudo $0 [--purge]

  --purge   Also delete $CONFIG_DIR and $DATA_DIR (your config, every
            quarantined file, and every incident report). Without this
            flag they are left on disk so you can review or restore them
            later - this is the default specifically so an accidental or
            routine uninstall can never silently destroy quarantined
            evidence or incident history.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must be run as root (try: sudo $0 $*)"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found - this uninstaller only supports systemd-managed hosts"
[ -d /run/systemd/system ] || die "systemd does not appear to be the running init system (no /run/systemd/system) - refusing to run systemctl commands against it"

log_info "RansomShield uninstaller starting"

# ---------------------------------------------------------------------------
# Stop + disable the service before removing anything on disk, so systemd
# never ends up pointing at a unit file that's about to disappear.
# ---------------------------------------------------------------------------
if systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1 \
   && systemctl list-unit-files "$SERVICE_NAME.service" | grep -q "$SERVICE_NAME.service"; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "stopping $SERVICE_NAME"
        systemctl stop "$SERVICE_NAME"
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "disabling $SERVICE_NAME"
        systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    log_ok "service stopped and disabled"
else
    log_warn "$SERVICE_NAME service is not known to systemd, nothing to stop/disable"
fi

# ---------------------------------------------------------------------------
# Remove the unit file, its drop-in, and the binary.
# ---------------------------------------------------------------------------
removed_anything=0

if [ -e "$UNIT_DEST" ]; then
    rm -f "$UNIT_DEST"
    log_ok "removed $UNIT_DEST"
    removed_anything=1
fi

if [ -d "$UNIT_DROPIN_DIR" ]; then
    rm -rf "$UNIT_DROPIN_DIR"
    log_ok "removed $UNIT_DROPIN_DIR"
    removed_anything=1
fi

if [ "$removed_anything" -eq 1 ]; then
    systemctl daemon-reload
    log_ok "systemd daemon-reload done"
fi

if [ -e "$BIN_DEST" ]; then
    rm -f "$BIN_DEST"
    log_ok "removed $BIN_DEST"
else
    log_warn "$BIN_DEST not found, nothing to remove"
fi

# ---------------------------------------------------------------------------
# Config and data - kept by default (see usage()), removed only with --purge.
# ---------------------------------------------------------------------------
if [ "$PURGE" -eq 1 ]; then
    for d in "$CONFIG_DIR" "$DATA_DIR"; do
        if [ -d "$d" ]; then
            rm -rf "$d"
            log_ok "purged $d"
        fi
    done
else
    for d in "$CONFIG_DIR" "$DATA_DIR"; do
        [ -d "$d" ] && log_warn "left in place (rerun with --purge to delete): $d"
    done
fi

log_ok "RansomShield uninstalled"
