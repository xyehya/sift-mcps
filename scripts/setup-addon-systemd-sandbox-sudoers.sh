#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_SERVICE_USER="${SUDO_USER:-$(id -un 2>/dev/null || printf 'sift-service')}"
SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-$DEFAULT_SERVICE_USER}"
HELPER_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sift-addon-systemd-sandbox"
HELPER_DST="/usr/local/sbin/sift-addon-systemd-sandbox"
SUDOERS_FILE="/etc/sudoers.d/sift-addon-systemd-sandbox"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-user) SERVICE_USER="${2:?missing service user}"; shift 2 ;;
    --helper-src) HELPER_SRC="${2:?missing helper source}"; shift 2 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || { printf 'ERROR: run as root\n' >&2; exit 1; }
id -u "$SERVICE_USER" >/dev/null 2>&1 || { printf 'ERROR: service user not found\n' >&2; exit 1; }
[[ -f "$HELPER_SRC" ]] || { printf 'ERROR: helper source not found\n' >&2; exit 1; }
VISUDO_BIN="$(command -v visudo || true)"
[[ -z "$VISUDO_BIN" && -x /usr/sbin/visudo ]] && VISUDO_BIN=/usr/sbin/visudo
[[ -n "$VISUDO_BIN" ]] || { printf 'ERROR: visudo not found\n' >&2; exit 1; }

install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<EOF
# Managed by sift-mcps. Only the validating add-on sandbox broker may preserve
# its explicitly allowlisted environment into a root-only EnvironmentFile.
Cmnd_Alias SIFT_ADDON_SANDBOX = ${HELPER_DST} *
${SERVICE_USER} ALL=(root) NOPASSWD:SETENV: SIFT_ADDON_SANDBOX
EOF
chmod 0440 "$tmp"
"$VISUDO_BIN" -cf "$tmp" >/dev/null
install -o root -g root -m 0440 "$tmp" "$SUDOERS_FILE"
