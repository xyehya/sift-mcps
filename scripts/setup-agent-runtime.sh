#!/usr/bin/env bash
# Configure native Linux user isolation for run_command.
#
# This script must run as root. It creates a restricted local user and applies
# POSIX ACLs so run_command can read evidence but write only to analysis output
# directories. The gateway still validates commands before execution; ACLs are
# the host-level backstop.
set -euo pipefail

RUNTIME_USER="${SIFT_EXECUTE_AS_USER:-agent_runtime}"
DEFAULT_SERVICE_USER="${SUDO_USER:-$(id -un 2>/dev/null || printf 'sift_gateway')}"
SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-$DEFAULT_SERVICE_USER}"
CASES_ROOT="${SIFT_CASES_ROOT:-/cases}"
STATE_ROOT="${SIFT_STATE_DIR:-/var/lib/sift}"

usage() {
    cat <<'EOF'
Usage: sudo scripts/setup-agent-runtime.sh [options]

Options:
  --runtime-user USER   Restricted execution user (default: agent_runtime)
  --service-user USER   Gateway service user allowed to sudo to runtime user
                        (default: SIFT_GATEWAY_SERVICE_USER, else invoking user)
  --cases-root PATH     Cases root containing case directories (default: /cases)
  --state-root PATH     SIFT integrity-record root (default: /var/lib/sift)
  -h, --help            Show this help

The script writes /etc/sudoers.d/sift-agent-runtime. The sudoers rule allows
the gateway service user to run commands as the low-privilege runtime user only:

  SERVICE_USER ALL=(RUNTIME_USER) NOPASSWD: ALL

Root escalation for privileged forensic tools, if enabled, must be configured
separately with narrow command-specific sudoers rules. For disk-image ingest
mounting, use scripts/setup-ingest-mount-sudoers.sh (a full-path, no-wildcard
allowlist for the mount helpers only).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runtime-user)
            RUNTIME_USER="${2:?missing runtime user}"
            shift 2
            ;;
        --service-user)
            SERVICE_USER="${2:?missing service user}"
            shift 2
            ;;
        --cases-root)
            CASES_ROOT="${2:?missing cases root}"
            shift 2
            ;;
        --state-root)
            STATE_ROOT="${2:?missing state root}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root, for example: sudo $0 --service-user ${SERVICE_USER}" >&2
    exit 1
fi

for cmd in setfacl getfacl; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: required command not found: ${cmd}" >&2
        exit 1
    fi
done
VISUDO_BIN="$(command -v visudo || true)"
if [[ -z "${VISUDO_BIN}" && -x /usr/sbin/visudo ]]; then
    VISUDO_BIN="/usr/sbin/visudo"
fi
if [[ -z "${VISUDO_BIN}" ]]; then
    echo "ERROR: required command not found: visudo" >&2
    exit 1
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    echo "ERROR: service user does not exist: ${SERVICE_USER}" >&2
    exit 1
fi

if ! id -u "${RUNTIME_USER}" >/dev/null 2>&1; then
    nologin="/usr/sbin/nologin"
    [[ -x "${nologin}" ]] || nologin="/sbin/nologin"
    [[ -x "${nologin}" ]] || nologin="/bin/false"
    useradd -r -M -s "${nologin}" "${RUNTIME_USER}"
fi

if getent group fuse >/dev/null 2>&1; then
    usermod -aG fuse "${RUNTIME_USER}"
else
    echo "WARN: group 'fuse' does not exist; skipping FUSE group membership" >&2
fi

mkdir -p "${CASES_ROOT}" "${STATE_ROOT}"

setfacl -m "u:${RUNTIME_USER}:x" "${CASES_ROOT}"
setfacl -d -m "u:${RUNTIME_USER}:x" "${CASES_ROOT}"

configure_case() {
    local case_dir="$1"
    [[ -d "${case_dir}" ]] || return 0

    setfacl -m "u:${RUNTIME_USER}:r-x" "${case_dir}"

    for writable in "${case_dir}/agent" "${case_dir}/agent/outputs" "${case_dir}/agent/run_commands" "${case_dir}/extractions" "${case_dir}/tmp"; do
        mkdir -p "${writable}"
        setfacl -m "u:${RUNTIME_USER}:rwx" "${writable}"
        find "${writable}" -xdev -exec setfacl -m "u:${RUNTIME_USER}:rwx" {} + || \
            echo "WARN: could not set ACL on every existing item in ${writable}; mounted filesystems may reject ACL changes" >&2
        find "${writable}" -xdev -type d -exec setfacl -d -m "u:${RUNTIME_USER}:rwx" {} + || \
            echo "WARN: could not set default ACL on every directory in ${writable}" >&2
    done

    if [[ -d "${case_dir}/evidence" ]]; then
        setfacl -R -m "u:${RUNTIME_USER}:rX" "${case_dir}/evidence" || \
            echo "WARN: could not set ACL on every file in ${case_dir}/evidence; immutable sealed files may already be protected" >&2
        find "${case_dir}/evidence" -type d -exec setfacl -d -m "u:${RUNTIME_USER}:rX" {} + || \
            echo "WARN: could not set default ACL on every directory in ${case_dir}/evidence" >&2
    fi

    # Legacy temp-test shadows; production integrity records live under STATE_ROOT.
    for protected in "${case_dir}/audit" \
        "${case_dir}/approvals.jsonl" \
        "${case_dir}/evidence-ledger.jsonl" \
        "${case_dir}/evidence-manifest.json" \
        "${case_dir}/evidence-verify-state.json"; do
        [[ -e "${protected}" ]] || continue
        setfacl -R -m "u:${RUNTIME_USER}:---" "${protected}"
        if [[ -d "${protected}" ]]; then
            find "${protected}" -type d -exec setfacl -d -m "u:${RUNTIME_USER}:---" {} +
        fi
    done
}

while IFS= read -r -d '' case_dir; do
    configure_case "${case_dir}"
done < <(find "${CASES_ROOT}" -mindepth 1 -maxdepth 1 -type d -print0)

# Integrity records are outside the case tree. The runtime user should not read
# or write audit, approvals, ledgers, manifests, or anchors.
setfacl -R -m "u:${RUNTIME_USER}:---" "${STATE_ROOT}"
find "${STATE_ROOT}" -type d -exec setfacl -d -m "u:${RUNTIME_USER}:---" {} +

sudoers_file="/etc/sudoers.d/sift-agent-runtime"
tmp_sudoers="$(mktemp)"
trap 'rm -f "${tmp_sudoers}"' EXIT
{
    echo "# Managed by sift-mcps scripts/setup-agent-runtime.sh"
    echo "${SERVICE_USER} ALL=(${RUNTIME_USER}) NOPASSWD: ALL"
} > "${tmp_sudoers}"
chmod 0440 "${tmp_sudoers}"
"${VISUDO_BIN}" -cf "${tmp_sudoers}" >/dev/null
install -o root -g root -m 0440 "${tmp_sudoers}" "${sudoers_file}"

cat <<EOF
Configured run_command native user isolation.

Runtime user: ${RUNTIME_USER}
Gateway user: ${SERVICE_USER}
Cases root:   ${CASES_ROOT}
State root:   ${STATE_ROOT}
Sudoers:      ${sudoers_file}

Ensure gateway.yaml has execute.runtime_user: "${RUNTIME_USER}" (install.sh
configures this by default); restart the gateway service after ACL changes to apply.
EOF
