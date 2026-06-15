#!/usr/bin/env bash
# =============================================================================
# harden.sh — final, opt-in hardening step for a SIFT-MCPS install (B-MVP-046)
# =============================================================================
#
# install.sh provisions the SIFT AppArmor profiles in COMPLAIN mode by default so
# a fresh install never breaks run_command on an unexpected access pattern. The
# ENFORCE posture is KNOWN-GOOD: RUN-3 / B-MVP-026 proved run_command runs under
# the full security stack (Landlock + seccomp=kill + systemd cgroup + AppArmor =
# ENFORCE). This script flips the two SIFT profiles to enforce mode as a
# DELIBERATE, documented final step. It is self-contained — it sources nothing.
#
# Equivalent to running the installer with: ./install.sh --apparmor-enforce
#
# Usage:
#   sudo ./harden.sh              # flip SIFT AppArmor profiles to enforce
#   ./harden.sh                   # auto-escalates each privileged step via sudo
#   ./harden.sh --complain        # revert the SIFT profiles back to complain
#   ./harden.sh -h | --help
#
# Idempotent and reversible. Only the SIFT profiles (sift-gateway, dfir-exec) are
# touched; no other AppArmor profile on the host is changed.

set -euo pipefail

log()  { printf '[harden] %s\n' "$*"; }
warn() { printf '[harden] WARNING: %s\n' "$*" >&2; }
die()  { printf '[harden] FATAL: %s\n' "$*" >&2; exit 1; }

sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

# The profiles install.sh provisions under /etc/apparmor.d/.
SIFT_APPARMOR_PROFILES=(
  /etc/apparmor.d/sift-gateway
  /etc/apparmor.d/dfir-exec
)

usage() {
  printf 'Usage: ./harden.sh [--complain] [-h|--help]\n\n'
  printf 'Final opt-in hardening: flip the SIFT AppArmor profiles to ENFORCE mode\n'
  printf '(the install default is complain). Equivalent to ./install.sh --apparmor-enforce.\n\n'
  printf '  --complain   Revert the SIFT profiles to complain mode (undo enforce).\n'
  printf '  -h, --help   Show this help.\n'
}

MODE="enforce"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enforce)      MODE="enforce"; shift ;;
    --complain)     MODE="complain"; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              warn "Unknown option '$1' — ignored. Run ./harden.sh -h for help."; shift ;;
  esac
done

if ! command -v aa-status >/dev/null 2>&1 && ! command -v apparmor_parser >/dev/null 2>&1; then
  die "AppArmor tooling not found (no aa-status / apparmor_parser). Is AppArmor installed and enabled?"
fi

apply_profile() {
  # $1 = path to an installed AppArmor profile.
  local profile="$1"
  if [[ ! -f "$profile" ]]; then
    warn "Profile not found, skipping: $profile (run ./install.sh first?)"
    return 0
  fi

  if [[ "$MODE" == "enforce" ]]; then
    # Prefer aa-enforce (sets the profile flag + reloads); fall back to a plain
    # reload (apparmor_parser -r WITHOUT -C) which loads in enforce mode.
    if command -v aa-enforce >/dev/null 2>&1; then
      sudo_if_needed aa-enforce "$profile" >/dev/null 2>&1 \
        || sudo_if_needed apparmor_parser -r "$profile" \
        || { warn "Failed to enforce $profile"; return 1; }
    else
      sudo_if_needed apparmor_parser -r "$profile" \
        || { warn "Failed to enforce $profile"; return 1; }
    fi
    log "ENFORCE: $profile"
  else
    if command -v aa-complain >/dev/null 2>&1; then
      sudo_if_needed aa-complain "$profile" >/dev/null 2>&1 \
        || sudo_if_needed apparmor_parser -C -r "$profile" \
        || { warn "Failed to set complain on $profile"; return 1; }
    else
      sudo_if_needed apparmor_parser -C -r "$profile" \
        || { warn "Failed to set complain on $profile"; return 1; }
    fi
    log "COMPLAIN: $profile"
  fi
}

log "Applying SIFT AppArmor posture: ${MODE}."
rc=0
for profile in "${SIFT_APPARMOR_PROFILES[@]}"; do
  apply_profile "$profile" || rc=1
done

if [[ "$rc" -ne 0 ]]; then
  warn "One or more SIFT profiles could not be set to ${MODE}. Check: sudo aa-status"
  exit 1
fi

if command -v aa-status >/dev/null 2>&1; then
  log "Current SIFT profile status:"
  sudo_if_needed aa-status 2>/dev/null | grep -E 'sift-gateway|dfir-exec' || \
    warn "  SIFT profiles not visible in aa-status; verify with: sudo aa-status"
fi

log "Done. SIFT AppArmor profiles are now in ${MODE} mode."
if [[ "$MODE" == "enforce" ]]; then
  log "Restart services to pick up the enforced posture cleanly:"
  log "  sudo systemctl restart sift-gateway.service sift-job-worker.service"
fi
