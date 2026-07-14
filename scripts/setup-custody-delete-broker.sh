#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
CASES_ROOT="${SIFT_CASES_ROOT:-/cases}"
HELPER_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sift-custody-delete-broker"
HELPER_DST="/usr/local/sbin/sift-custody-delete-broker"
CONFIG_DIR="/etc/sift"
CONFIG_FILE="${CONFIG_DIR}/custody-delete.json"
SUDOERS_FILE="/etc/sudoers.d/sift-custody-delete-broker"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-user) SERVICE_USER="${2:?missing service user}"; shift 2 ;;
    --cases-root) CASES_ROOT="${2:?missing cases root}"; shift 2 ;;
    --helper-src) HELPER_SRC="${2:?missing helper source}"; shift 2 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || { printf 'ERROR: run as root\n' >&2; exit 1; }
id -u "$SERVICE_USER" >/dev/null 2>&1 || { printf 'ERROR: service user not found\n' >&2; exit 1; }
[[ "$CASES_ROOT" == /* && "$CASES_ROOT" != / ]] || { printf 'ERROR: invalid cases root\n' >&2; exit 1; }
[[ "$CASES_ROOT" =~ ^/[A-Za-z0-9._/-]+$ && "$CASES_ROOT" != */../* \
   && "$CASES_ROOT" != *///* && "$CASES_ROOT" != */ ]] || {
  printf 'ERROR: cases root is unsafe for the fixed AppArmor template\n' >&2
  exit 1
}
[[ -f "$HELPER_SRC" ]] || { printf 'ERROR: helper source not found\n' >&2; exit 1; }
VISUDO_BIN="$(command -v visudo || true)"
[[ -z "$VISUDO_BIN" && -x /usr/sbin/visudo ]] && VISUDO_BIN=/usr/sbin/visudo
[[ -n "$VISUDO_BIN" ]] || { printf 'ERROR: visudo not found\n' >&2; exit 1; }
install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST"
install -d -o root -g root -m 0755 "$CONFIG_DIR"
config_tmp="$(mktemp)"
sudoers_tmp="$(mktemp)"
trap 'rm -f "$config_tmp" "$sudoers_tmp"' EXIT
python3 - "$CASES_ROOT" "$SERVICE_USER" >"$config_tmp" <<'PY'
import json, sys
print(json.dumps({"cases_root": sys.argv[1], "service_user": sys.argv[2]}, sort_keys=True))
PY
install -o root -g root -m 0644 "$config_tmp" "$CONFIG_FILE"
printf '%s\n' \
  '# Managed by sift-mcps. Exact no-argument custody-delete broker only.' \
  "${SERVICE_USER} ALL=(root) NOPASSWD: ${HELPER_DST} \"\"" >"$sudoers_tmp"
chmod 0440 "$sudoers_tmp"
"$VISUDO_BIN" -cf "$sudoers_tmp" >/dev/null
install -o root -g root -m 0440 "$sudoers_tmp" "$SUDOERS_FILE"
