#!/usr/bin/env bash
# Install the RUN-3 root-owned systemd scope helper and its sudoers drop-in.
set -euo pipefail

DEFAULT_SERVICE_USER="${SUDO_USER:-$(id -un 2>/dev/null || printf 'sift-service')}"
SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-$DEFAULT_SERVICE_USER}"
HELPER_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sift-run-command-systemd-scope"
HELPER_DST="/usr/local/sbin/sift-run-command-systemd-scope"
SUDOERS_FILE="/etc/sudoers.d/sift-run-command-systemd-scope"
PRINT_ONLY=0

usage() {
  cat <<'EOF'
Usage: sudo scripts/setup-run-command-systemd-scope-sudoers.sh [options]

Options:
  --service-user USER   Service user allowed to invoke the root-owned helper
  --helper-src PATH     Source helper script to install
  --helper-dst PATH     Installed helper path
  --print               Print sudoers content and exit
  -h, --help            Show this help

The helper validates the RUN-3 systemd-run scope shape, derives the configured
runtime user's gid, and then execs systemd-run as root. Sudoers grants only this
helper path; it does not grant a shell or raw systemd-run.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-user) SERVICE_USER="${2:?missing service user}"; shift 2 ;;
    --helper-src) HELPER_SRC="${2:?missing helper source}"; shift 2 ;;
    --helper-dst) HELPER_DST="${2:?missing helper destination}"; shift 2 ;;
    --print) PRINT_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

content="$(cat <<EOF
# Managed by sift-mcps scripts/setup-run-command-systemd-scope-sudoers.sh
# RUN-3 run_command cgroup scope helper only. The helper validates unit name,
# runtime user, resource-control properties, and worker argv before calling
# systemd-run as root.
Cmnd_Alias SIFT_RUN_COMMAND_SCOPE = ${HELPER_DST} *
${SERVICE_USER} ALL=(root) NOPASSWD: SIFT_RUN_COMMAND_SCOPE
EOF
)"

if [[ "${PRINT_ONLY}" -eq 1 ]]; then
  printf '%s\n' "${content}"
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root, e.g. sudo $0 --service-user ${SERVICE_USER}" >&2
  exit 1
fi
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  echo "ERROR: service user does not exist: ${SERVICE_USER}" >&2
  exit 1
fi
if [[ ! -f "${HELPER_SRC}" ]]; then
  echo "ERROR: helper source not found: ${HELPER_SRC}" >&2
  exit 1
fi
VISUDO_BIN="$(command -v visudo || true)"
[[ -z "${VISUDO_BIN}" && -x /usr/sbin/visudo ]] && VISUDO_BIN="/usr/sbin/visudo"
[[ -n "${VISUDO_BIN}" ]] || { echo "ERROR: visudo not found" >&2; exit 1; }

install -o root -g root -m 0755 "${HELPER_SRC}" "${HELPER_DST}"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
printf '%s\n' "${content}" > "${tmp}"
chmod 0440 "${tmp}"
"${VISUDO_BIN}" -cf "${tmp}" >/dev/null
install -o root -g root -m 0440 "${tmp}" "${SUDOERS_FILE}"

cat <<EOF
Installed RUN-3 run_command systemd scope helper.

Service user: ${SERVICE_USER}
Helper:       ${HELPER_DST}
Sudoers:      ${SUDOERS_FILE}
EOF
