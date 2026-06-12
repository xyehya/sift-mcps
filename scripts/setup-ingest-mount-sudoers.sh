#!/usr/bin/env bash
# Configure a NARROW, audited root-escalation allowlist for forensic disk-image
# mounting (the opensearch-mcp ingest path).
#
# Why this exists
# ---------------
# Ingesting a disk image (E01/raw/VMDK/...) into OpenSearch requires mounting it,
# which needs root: opensearch_mcp/containers.py shells out to xmount, ewfmount,
# mount, ntfs-3g, losetup, qemu-nbd, modprobe nbd, partprobe, umount, and
# fusermount via `sudo`. The gateway/worker must NOT run as root, and the service
# user must NOT carry a blanket `ALL=(ALL) NOPASSWD: ALL` grant. This script
# writes a command-specific sudoers drop-in that lets the gateway service user
# run ONLY those mount helpers as root, with full binary paths and no shell or
# wildcard commands (charter D3). `modprobe` is pinned to its exact `nbd` args so
# it cannot load arbitrary kernel modules, and `tee` (an arbitrary root-write
# primitive used only by the optional Samba share repoint) is deliberately NOT
# included.
#
# Least-privilege note: on a workstation where the service runs as the human admin
# account (which already has broad NOPASSWD sudo), this allowlist is documentary
# until that broad grant is removed. To actually enforce least privilege, run the
# gateway/worker as a DEDICATED service user whose ONLY root capability is this
# drop-in. See docs/regenerate/security-architecture.md.
set -euo pipefail

DEFAULT_SERVICE_USER="${SUDO_USER:-$(id -un 2>/dev/null || printf 'sift_gateway')}"
SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-$DEFAULT_SERVICE_USER}"
SUDOERS_FILE="/etc/sudoers.d/sift-ingest-mount"
PRINT_ONLY=0

usage() {
    cat <<'EOF'
Usage: sudo scripts/setup-ingest-mount-sudoers.sh [options]

Options:
  --service-user USER   Gateway service user granted the mount allowlist
                        (default: SIFT_GATEWAY_SERVICE_USER, else invoking user)
  --print               Print the generated sudoers content and exit (no install).
                        Use this to review the exact rule before applying it.
  -h, --help            Show this help

Writes /etc/sudoers.d/sift-ingest-mount granting the service user NOPASSWD root
for the specific forensic mount helpers only. Validated with `visudo -cf` before
install. Pair with a dedicated (non-admin) service user to enforce least
privilege.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-user) SERVICE_USER="${2:?missing service user}"; shift 2 ;;
        --print) PRINT_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# Resolve mount-helper full paths on this host; include only those present.
# `modprobe` is intentionally pinned to its exact args (the sole nbd call) rather
# than allowing arbitrary module loads.
resolve() { command -v "$1" 2>/dev/null || true; }

ANY_ARG_BINS=(xmount ewfmount mount umount ntfs-3g losetup qemu-nbd partprobe fusermount fusermount3)
cmnds=()
for b in "${ANY_ARG_BINS[@]}"; do
    p="$(resolve "$b")"
    [[ -n "${p}" ]] && cmnds+=("${p}")
done
modprobe_path="$(resolve modprobe)"
[[ -n "${modprobe_path}" ]] && cmnds+=("${modprobe_path} nbd max_part=8")

if [[ "${#cmnds[@]}" -eq 0 ]]; then
    echo "ERROR: no mount helpers found on PATH; nothing to allowlist" >&2
    exit 1
fi

# Join into a single Cmnd_Alias (comma-separated).
joined=""
for c in "${cmnds[@]}"; do
    if [[ -z "${joined}" ]]; then joined="${c}"; else joined="${joined}, ${c}"; fi
done

content="$(cat <<EOF
# Managed by sift-mcps scripts/setup-ingest-mount-sudoers.sh
# Narrow root escalation for forensic disk-image mounting only (ingest path).
# Full-path commands, no shell/wildcards; modprobe pinned to nbd; tee excluded.
Cmnd_Alias SIFT_MOUNT = ${joined}
${SERVICE_USER} ALL=(root) NOPASSWD: SIFT_MOUNT
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
VISUDO_BIN="$(command -v visudo || true)"
[[ -z "${VISUDO_BIN}" && -x /usr/sbin/visudo ]] && VISUDO_BIN="/usr/sbin/visudo"
[[ -n "${VISUDO_BIN}" ]] || { echo "ERROR: visudo not found" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
printf '%s\n' "${content}" > "${tmp}"
chmod 0440 "${tmp}"
"${VISUDO_BIN}" -cf "${tmp}" >/dev/null
install -o root -g root -m 0440 "${tmp}" "${SUDOERS_FILE}"

cat <<EOF
Installed forensic mount allowlist.

Service user: ${SERVICE_USER}
Sudoers:      ${SUDOERS_FILE}
Allowed:      ${joined}

To enforce least privilege, run the gateway/worker as a dedicated service user
and remove any broad "ALL=(ALL) NOPASSWD: ALL" grant for that user.
EOF
