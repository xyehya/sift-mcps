# shellcheck shell=bash
# =============================================================================
# lib/common.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_COMMON_SOURCED:-}" ]] && return 0
_SIFT_LIB_COMMON_SOURCED=1

# --- early helpers (no dependencies) -----------------------------------------
log()   { printf '[sift-mcps] %s\n' "$*"; }
warn()  { printf '[sift-mcps] WARNING: %s\n' "$*" >&2; }
die()   { printf '[sift-mcps] FATAL: %s\n' "$*" >&2; exit 1; }

sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

user_name() {
  if [[ "$(id -u)" -eq 0 ]]; then echo "${SUDO_USER:-root}"; else id -un; fi
}
group_name() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then id -gn "$SUDO_USER"; else id -gn; fi
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

random_hex() { openssl rand -hex "$1"; }

# --- offline / download-integrity helpers (B-MVP-004) ------------------------
# True when offline mode is engaged. In offline mode every network download
# step calls offline_die with a message pointing at the operator-staged path it
# would otherwise fetch, so a hardened/air-gapped install fails loudly and
# actionably instead of silently reaching the internet.
is_offline() { [[ "${SIFT_OFFLINE:-0}" == "1" ]]; }

# In offline mode, abort the current download step with an actionable message.
# $1 = human label, $2 = the path/operation the operator must stage instead.
offline_die() {
  die "SIFT_OFFLINE=1: refusing to fetch $1. Stage it offline first: $2"
}

# Verify $1 (a file) matches the expected SHA-256 $2. Returns non-zero (and
# warns) on mismatch or when sha256sum is unavailable; callers decide whether a
# mismatch is fatal. Never prints the file contents.
verify_sha256() {
  local file="$1" expected="$2"
  if ! command -v sha256sum >/dev/null 2>&1; then
    warn "sha256sum not available — cannot verify $(basename "$file") checksum."
    return 2
  fi
  local actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [[ "$actual" == "$expected" ]]; then
    return 0
  fi
  warn "SHA-256 mismatch for $(basename "$file"): expected $expected, got $actual."
  return 1
}

# --- service-user ownership helpers ------------------------------------------
# The installer runs as the operator (who keeps NOPASSWD root via sudo_if_needed),
# but the gateway/worker run as the dedicated non-admin user sift-service. The
# secret/config tree (SIFT_HOME = /var/lib/sift/.sift) and the runtime state dirs
# are owned by sift-service so the SERVICE can read/write them at runtime. Because
# the operator is NOT sift-service, install-time writes/reads/stat of those
# 0600/0700 paths cross an ownership boundary and must go through sudo.

# Read a (possibly sift-service-owned 0600) file as the operator.
svc_read() { sudo_if_needed cat "$1" 2>/dev/null || true; }

# Test for a (possibly sift-service-owned) file's existence as the operator.
svc_test_f() { sudo_if_needed test -f "$1"; }

# Install $1 (a temp file the operator created) to $2 owned sift-service with
# mode $3. Atomic (install(1) does temp+rename). Used for every secret/config
# file that lands under SIFT_HOME so the running service can read it while the
# operator cannot leave it operator-owned.
svc_install_file() {
  local src="$1" dst="$2" mode="$3"
  sudo_if_needed install -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" \
    -m "$mode" "$src" "$dst"
}

# =============================================================================
# Paths — everything derived from REPO_DIR and system conventions
# =============================================================================
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# Runtime checkout used by systemd WorkingDirectory, Docker compose files, and
# add-on manifests. Operators can still use the normal flow:
#   git clone ... && cd sift-mcps && ./install.sh
# In that case the installer stages the checkout here, then re-execs from the
# staged tree so services are not tied to a temporary clone location.
SIFT_MCPS_INSTALL_ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
SIFT_INSTALL_REEXEC_ENV="SIFT_MCPS_INSTALL_REEXECED"

# Hard-code the SIFT-native Python.  Must be ≥ 3.10.
SYSTEM_PYTHON="/usr/bin/python3.12"

SIFT_STATE_DIR="${SIFT_STATE_DIR:-/var/lib/sift}"
# SIFT_HOME (secrets + gateway.yaml + TLS + backups) lives UNDER the service
# user's passwd home (/var/lib/sift) as /var/lib/sift/.sift. Owned by sift-service.
# NOTE: the system units reference this by its ABSOLUTE path (${SIFT_HOME}), not
# %h — for a SYSTEM service %h resolves to /root, not User='s home (systemd.unit(5)).
SIFT_HOME="${SIFT_HOME:-$SIFT_STATE_DIR/.sift}"
SIFT_TLS_DIR="${SIFT_TLS_DIR:-$SIFT_HOME/tls}"
SIFT_BACKUP_DIR="${SIFT_BACKUP_DIR:-$SIFT_HOME/backups}"
SIFT_CONFIG="${SIFT_CONFIG:-$SIFT_HOME/gateway.yaml}"
SIFT_CASES_ROOT="${SIFT_CASES_ROOT:-${SIFT_CASE_ROOT:-/cases}}"
SIFT_CASE_ROOT="${SIFT_CASE_ROOT:-$SIFT_CASES_ROOT}"
SIFT_PASSWORDS_DIR="${SIFT_PASSWORDS_DIR:-$SIFT_STATE_DIR/passwords}"
SIFT_VERIFICATION_DIR="${SIFT_VERIFICATION_DIR:-$SIFT_STATE_DIR/verification}"
SIFT_TOKENS_DIR="${SIFT_TOKENS_DIR:-$SIFT_STATE_DIR/tokens}"
SIFT_SNAPSHOTS_DIR="${SIFT_SNAPSHOTS_DIR:-$SIFT_STATE_DIR/snapshots}"
SIFT_ENRICHMENT_DIR="${SIFT_ENRICHMENT_DIR:-$SIFT_STATE_DIR/enrichment}"
# Shared Volatility3 symbol cache: setgid (2775) group `sift` so BOTH the
# service user (sift-service) and the run_command runtime user (agent_runtime)
# can populate/share it. Exported into both systemd units as SIFT_VOL_SYMBOLS.
# Lives under /var/cache (FHS: regenerable cached data), deliberately NOT under
# $SIFT_STATE_DIR — setup-agent-runtime.sh stamps a recursive `u:agent_runtime:---`
# deny ACL over all of /var/lib/sift, which would override the `sift` group grant
# and make the cache unwritable by the runtime user. /var/cache/sift is outside
# that deny sweep so both users can share it.
SIFT_VOL_SYMBOLS="${SIFT_VOL_SYMBOLS:-/var/cache/sift/volatility-symbols}"
SIFT_EXAMINER="${SIFT_EXAMINER:-examiner}"
SIFT_EXECUTE_AS_USER="${SIFT_EXECUTE_AS_USER:-agent_runtime}"
# Dedicated non-admin system user that the gateway + durable job worker run as.
# Its PRIMARY group is its own per-user group (sift-service). The `sift` group
# below is ONLY the shared vol-symbol-cache group — keep the two distinct.
SIFT_GATEWAY_SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
SIFT_GATEWAY_SERVICE_GROUP="${SIFT_GATEWAY_SERVICE_GROUP:-sift}"
MATERIALS_FILE="${MATERIALS_FILE:-$SIFT_TOKENS_DIR/installer-handoff.txt}"
# System (not --user) systemd services: gateway + worker run as sift-service.
SYSTEMD_SYSTEM_DIR="${SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}"
GATEWAY_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-gateway.service"
JOB_WORKER_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-job-worker.service"
# feat/opensearch-workers: dedicated least-privilege OpenSearch ingest/enrich
# worker template + how many instances to start (N parallel workers claim
# ingest/enrich jobs via FOR UPDATE SKIP LOCKED). Default 2; override with
# SIFT_OPENSEARCH_WORKERS. Installed only when OpenSearch is enabled.
OPENSEARCH_WORKER_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-opensearch-worker@.service"
SIFT_OPENSEARCH_WORKERS="${SIFT_OPENSEARCH_WORKERS:-2}"

# --- Download pins (B-MVP-004) -----------------------------------------------
# Every external network download is version-pinned and (where the upstream
# does not publish a checksum file) SHA-256-pinned in this script, mirroring the
# Supabase CLI pin pattern in scripts/setup-supabase.sh. Refresh these together:
# bump the version, recompute the SHA-256 with `sha256sum`, and re-verify on the
# live VM. Verdicts and provenance live in docs/operator/reference-data-provenance.md
# (the D1-D8 ledger).
#
# uv (D1): we download the per-arch uv release tarball from GitHub and
# SHA-256-verify it against a pinned hash BEFORE installing. There is no
# pipe-to-shell fallback on any arch — an arch without a pinned, verified hash
# fails CLOSED (supply-chain guard: fail-closed beats fail-open).
#
# Provenance of the pinned hashes: the values below are the upstream-published
# checksums from each release's `<triple>.tar.gz.sha256` asset at
# https://github.com/astral-sh/uv/releases/download/<ver>/<triple>.tar.gz.sha256
# (NOT locally recomputed). Refresh together on a version bump: bump
# SIFT_UV_VERSION, then for each supported triple set the ledger var to the
# value from that release's published `.sha256` asset, and re-verify on a live VM.
SIFT_UV_VERSION="${SIFT_UV_VERSION:-0.11.21}"
# x86_64 (primary; SIFT VM is x86_64). Published 0.11.21 .sha256:
SIFT_UV_TARBALL_SHA256="${SIFT_UV_TARBALL_SHA256:-8c88519b0ef0af9801fcdee419bbb12116bd9e6b18e162ae093c932d8b264050}"
# aarch64 (secondary). Published 0.11.21 uv-aarch64-unknown-linux-gnu.tar.gz.sha256.
# Empty default ⇒ that arch dies fail-closed with an actionable message; set this
# (or override) to install on aarch64.
SIFT_UV_TARBALL_SHA256_AARCH64="${SIFT_UV_TARBALL_SHA256_AARCH64:-88e800834007cc5efd4675f166eb2a51e7e3ad19876d85fa8805a6fb5c922397}"
# Hayabusa (D2): pinned release tag + SHA-256 of the lin-x64-gnu zip (upstream
# ships no checksum file, so the hash is pinned here like the Supabase CLI).
SIFT_HAYABUSA_TAG="${SIFT_HAYABUSA_TAG:-v3.9.0}"
SIFT_HAYABUSA_SHA256="${SIFT_HAYABUSA_SHA256:-ffb31e02bd47d840d999d964d4663287cdb194a22ea856904348786acba414d7}"
# BGE embedding model (D3): canonical revision (git commit) on Hugging Face Hub
# for BAAI/bge-base-en-v1.5. The seed/query loaders pass this revision so the
# weights are reproducible, and verify it after load (B-MVP-015).
SIFT_RAG_MODEL_NAME="${SIFT_RAG_MODEL_NAME:-BAAI/bge-base-en-v1.5}"
SIFT_RAG_MODEL_REVISION="${SIFT_RAG_MODEL_REVISION:-a5beb1e3e68b9ab74eb54cfd186867f64f240e1a}"
# RAG Chroma bundle (D4, legacy chroma path only): pin the release tag so the
# (already checksum-verified) bundle comes from a fixed release, not "latest".
SIFT_RAG_INDEX_TAG="${SIFT_RAG_INDEX_TAG:-rag-index-v1}"
# GeoIP (D6): the OpenSearch ip2geo datasource hits a live unauthenticated
# endpoint. Off by default; set SIFT_GEOIP_ENABLED=1 to opt in.
SIFT_GEOIP_ENABLED="${SIFT_GEOIP_ENABLED:-0}"
# Offline mode (B-MVP-004): when set, NO network fetch is attempted. Each
# download step short-circuits with an actionable message pointing at the
# operator-staged artifact path it expects instead.
SIFT_OFFLINE="${SIFT_OFFLINE:-0}"
SIFT_HF_HOME="${SIFT_HF_HOME:-$SIFT_STATE_DIR/.cache/huggingface}"

VENV_DIR="$REPO_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

_same_path() {
  local a="$1" b="$2"
  [[ "$(cd "$a" 2>/dev/null && pwd -P)" == "$(cd "$b" 2>/dev/null && pwd -P)" ]]
}

# shellcheck disable=SC2164  # `set -Eeuo pipefail` (set by the install.sh
# entrypoint that sources this module) makes any failing `cd` abort the script,
# so the explicit `|| exit` guards SC2164 wants are redundant. Flagged only when
# this lib is linted standalone (the entrypoint's `set -e` is in another file);
# `shellcheck -x install.sh` does not flag it. Verbatim from pre-#18 install.sh.
stage_repo_to_install_root() {
  local src="$REPO_DIR"
  local dst="$SIFT_MCPS_INSTALL_ROOT"

  mkdir -p "$dst" 2>/dev/null || sudo_if_needed mkdir -p "$dst"
  if _same_path "$src" "$dst"; then
    return 0
  fi
  if [[ "${!SIFT_INSTALL_REEXEC_ENV:-0}" == "1" ]]; then
    die "Installer re-execed but REPO_DIR ($src) is still not SIFT_MCPS_INSTALL_ROOT ($dst)."
  fi

  log "Staging checkout into runtime tree: $dst"
  local owner group
  owner="$(user_name)"
  group="$(group_name)"
  sudo_if_needed chown -R "$owner:$group" "$dst"

  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude='.git' \
      --exclude='.venv' \
      --exclude='__pycache__' \
      --exclude='*.pyc' \
      --exclude='.mcp.json' \
      --exclude='node_modules' \
      --exclude='.DS_Store' \
      "$src/" "$dst/"
  else
    (
      cd "$src"
      tar \
        --exclude='./.git' \
        --exclude='./.venv' \
        --exclude='*/__pycache__' \
        --exclude='*.pyc' \
        --exclude='./.mcp.json' \
        --exclude='*/node_modules' \
        --exclude='.DS_Store' \
        -cf - .
    ) | (
      cd "$dst"
      tar -xf -
    )
  fi

  log "Continuing install from staged runtime tree."
  cd "$dst"
  export "$SIFT_INSTALL_REEXEC_ENV=1"
  exec "$dst/install.sh" "$@"
}

# --- globals relocated from later phase sections (definition order preserved
#     relative to use: bash resolves globals at call time, and these are all
#     consumed only inside functions that run under main()) -------------------
SIFT_TLS_CA_DAYS="${SIFT_TLS_CA_DAYS:-3650}"
SIFT_TLS_LEAF_DAYS="${SIFT_TLS_LEAF_DAYS:-730}"
SIFT_TLS_CA_CN="${SIFT_TLS_CA_CN:-Protocol SIFT Gateway local CA}"


SUPABASE_PROJECT_ENV="$HOME/.sift/supabase-project/sift-supabase.env"

# FM-1/FM-2 (#5): OPENSEARCH_UP tracks whether OpenSearch came up healthy.
# main() reads this to gate seed_addon_backends and the post-seed restart.
OPENSEARCH_UP=0
