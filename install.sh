#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# sift-mcps installer — hardened, idempotent, zero-arguments
#
#   ./install.sh
#
# Provisions a complete MCP runtime for AI-driven forensics on SIFT Workstation.
# Re-run safe: every step checks whether work is already done.
#
# Design invariants:
#   - Uses /usr/bin/python3.12 (SIFT native).  No uv-managed Python.
#   - Single native sync path (--extra full): core + OpenSearch + RAG knowledge.
#   - Venv always matches system Python; mismatched venvs are rebuilt.
#   - OpenCTI is an external add-on; prepare/register it via scripts/setup-addon.sh.
#   - Supabase is auto-provisioned unless external credentials are supplied.
#   - Every step is idempotent.
# =============================================================================

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
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
# uv (D1): the versioned install script itself pins APP_VERSION internally; we
# pin the script URL by version and SHA-256-verify the downloaded x86_64 tarball
# out of band so the pipe-to-shell is no longer "latest + unauthenticated".
SIFT_UV_VERSION="${SIFT_UV_VERSION:-0.11.21}"
SIFT_UV_TARBALL_SHA256="${SIFT_UV_TARBALL_SHA256:-8c88519b0ef0af9801fcdee419bbb12116bd9e6b18e162ae093c932d8b264050}"
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

# =============================================================================
# Phase 0 — pre-flight
# =============================================================================

check_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
      warn "Target OS is Ubuntu 22.04/24.04; detected ${PRETTY_NAME:-unknown}.  Proceeding anyway."
    elif [[ "${VERSION_ID:-}" != "22.04" && "${VERSION_ID:-}" != "24.04" ]]; then
      warn "Target Ubuntu versions are 22.04/24.04; detected ${VERSION_ID:-unknown}.  Proceeding anyway."
    fi
  fi
}

check_python() {
  if [[ ! -x "$SYSTEM_PYTHON" ]]; then
    # Fall back through candidates
    for candidate in /usr/bin/python3.11 /usr/bin/python3.10 /usr/bin/python3; do
      if [[ -x "$candidate" ]]; then
        SYSTEM_PYTHON="$candidate"
        break
      fi
    done
  fi
  [[ -x "$SYSTEM_PYTHON" ]] || die "No usable Python found (tried /usr/bin/python3.12, .11, .10, python3)."
  local ver
  ver=$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || true
  local major
  major=$("$SYSTEM_PYTHON" -c 'import sys; print(sys.version_info.major)' 2>/dev/null) || true
  if [[ -z "$major" || "$major" -lt 3 ]]; then
    die "Python ≥ 3.10 required; $SYSTEM_PYTHON reports version '$ver'."
  fi
  local minor
  minor=$("$SYSTEM_PYTHON" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null) || true
  if [[ "$major" -eq 3 && "$minor" -lt 10 ]]; then
    die "Python ≥ 3.10 required; $SYSTEM_PYTHON reports version '$ver'."
  fi
  log "System Python: $SYSTEM_PYTHON ($ver)"
  export SYSTEM_PYTHON
}

# =============================================================================
# Phase 1 — uv (Python package manager)
# =============================================================================

resolve_uv() {
  if command -v uv >/dev/null 2>&1; then command -v uv; return; fi
  if [[ -x "$HOME/.local/bin/uv" ]]; then echo "$HOME/.local/bin/uv"; return; fi
  echo ""
}

install_uv_if_needed() {
  local uv_bin
  uv_bin="$(resolve_uv)"
  if [[ -n "$uv_bin" ]]; then
    log "uv found: $uv_bin"
    UV_BIN="$uv_bin"
    return
  fi
  if is_offline; then
    offline_die "uv ${SIFT_UV_VERSION}" \
      "pre-install uv via your OS package manager or place the uv binary on PATH (e.g. ~/.local/bin/uv) before re-running ./install.sh"
  fi
  require_cmd curl
  # B-MVP-004 (D1): pin uv to a specific version and SHA-256-verify the tarball.
  # The versioned install script (astral.sh/uv/<ver>/install.sh) pins APP_VERSION
  # internally, so we no longer pipe an unpinned "latest" script to the shell.
  # We additionally download the x86_64 tarball ourselves and SHA-256-verify it
  # against the pinned hash; on match we install from the verified tarball, and
  # only fall back to the (still version-pinned) script if the arch is not x86_64.
  log "Installing uv ${SIFT_UV_VERSION} (pinned)."
  local tmpd tarball arch
  tmpd="$(mktemp -d)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
    tarball="$tmpd/uv-x86_64-unknown-linux-gnu.tar.gz"
    if curl -fsSL -o "$tarball" \
        "https://github.com/astral-sh/uv/releases/download/${SIFT_UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"; then
      if verify_sha256 "$tarball" "$SIFT_UV_TARBALL_SHA256"; then
        log "  uv tarball SHA-256 verified."
        mkdir -p "$HOME/.local/bin"
        tar -xzf "$tarball" -C "$tmpd"
        local uv_extracted
        uv_extracted="$(find "$tmpd" -type f -name uv | head -1)"
        if [[ -n "$uv_extracted" ]]; then
          install -m 755 "$uv_extracted" "$HOME/.local/bin/uv"
        fi
      else
        rm -rf "$tmpd"
        die "uv ${SIFT_UV_VERSION} tarball failed SHA-256 verification — refusing to install (supply-chain guard). Set SIFT_UV_TARBALL_SHA256 if you intentionally bumped the pin."
      fi
    fi
  fi
  rm -rf "$tmpd"
  uv_bin="$(resolve_uv)"
  if [[ -z "$uv_bin" ]]; then
    # Arch fallback: the version-pinned install script (NOT the unpinned latest).
    log "  Falling back to the version-pinned uv install script for arch '$arch'."
    curl -LsSf "https://astral.sh/uv/${SIFT_UV_VERSION}/install.sh" | sh
    uv_bin="$(resolve_uv)"
  fi
  [[ -n "$uv_bin" ]] || die "uv install completed but uv binary not found."
  UV_BIN="$uv_bin"
}

apt_install_packages() {
  local packages=("$@")
  [[ "${#packages[@]}" -gt 0 ]] || return 0
  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi

  if ! sudo_if_needed apt-get update; then
    warn "apt-get update failed, likely due to an unrelated third-party apt source."
    warn "Continuing with existing package indexes and attempting: apt-get install -y ${packages[*]}"
  fi
  sudo_if_needed apt-get install -y "${packages[@]}"
}

install_host_prereqs() {
  local missing=()
  command -v rg >/dev/null 2>&1 || missing+=(ripgrep)
  command -v setfacl >/dev/null 2>&1 || missing+=(acl)
  if [[ "${#missing[@]}" -gt 0 ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
      warn "Missing host tools (${missing[*]}) and apt-get is unavailable."
    else
      log "Installing host prerequisites: ${missing[*]}"
      apt_install_packages "${missing[@]}" || warn "Host prerequisite package install failed: ${missing[*]}"
      local still_missing=()
      command -v setfacl >/dev/null 2>&1 || still_missing+=(acl)
      # ripgrep is useful for investigator workflows but not required to finish
      # provisioning. Do not let a stale third-party apt key block the stack.
      command -v rg >/dev/null 2>&1 || warn "ripgrep is still missing; install it later with: sudo apt-get install -y ripgrep"
      if [[ "${#still_missing[@]}" -gt 0 ]]; then
        die "Required host tools are still missing after apt install attempt: ${still_missing[*]}.
  If apt is blocked by a third-party repository key, fix or disable that source, then re-run:
    sudo apt-get update
    sudo apt-get install -y ${still_missing[*]}"
      fi
    fi
  fi

  # Docker presence check for OpenSearch (#8). We do NOT attempt to install
  # Docker ourselves (distro-specific / risky). Just detect + warn so the
  # operator knows what to do.  Seeding is gated in main() via OPENSEARCH_UP.
  if [[ "${SIFT_OPENSEARCH_ENABLED:-true}" == "true" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
      warn "Docker not found. OpenSearch requires Docker."
      warn "  Install Docker (https://docs.docker.com/engine/install/) and re-run."
      warn "  Continuing without OpenSearch — set SIFT_OPENSEARCH_ENABLED=false to silence this."
    fi
  fi
}

ensure_docker_ready_for_supabase() {
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" || "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    die "Docker is required for local Supabase provisioning, but docker was not found.
  Install Docker Engine and the compose plugin, then re-run:
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose-plugin
    sudo usermod -aG docker $(user_name)
  Then log out and back in, or run: newgrp docker"
  fi

  if ! docker compose version >/dev/null 2>&1; then
    die "Docker Compose v2 is required for local Supabase provisioning.
  Install it, then re-run:
    sudo apt-get update
    sudo apt-get install -y docker-compose-plugin"
  fi

  if docker ps >/dev/null 2>&1; then
    log "Docker daemon reachable."
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1; then
    log "Docker daemon not reachable — attempting: sudo systemctl start docker"
    sudo_if_needed systemctl start docker 2>/dev/null || true
    sleep 2
  fi

  if docker ps >/dev/null 2>&1; then
    log "Docker daemon reachable after start."
    return 0
  fi

  local operator
  operator="$(user_name)"
  if getent group docker >/dev/null 2>&1 && ! id -nG "$operator" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    die "Docker is installed but '$operator' cannot access the daemon.
  Add the operator to the docker group and refresh the login session:
    sudo usermod -aG docker $operator
    newgrp docker
  Then re-run:
    cd $(printf '%q' "$REPO_DIR")
    ./install.sh"
  fi

  die "Docker daemon is not reachable.
  Try:
    sudo systemctl status docker --no-pager
    sudo systemctl start docker
    docker ps
  Then re-run ./install.sh."
}

# =============================================================================
# Phase 2 — venv integrity + sync
# =============================================================================

_venv_python_version() {
  "$VENV_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "none"
}

_ensure_venv_integrity() {
  # Returns 0 if the venv exists, uses the system Python, and is import-healthy.
  if [[ ! -x "$VENV_PYTHON" ]]; then
    log "No venv found at $VENV_DIR — will create."
    return 1
  fi
  local sys_ver venv_ver
  sys_ver=$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  venv_ver=$(_venv_python_version)
  if [[ "$venv_ver" != "$sys_ver" ]]; then
    warn "Venv Python ($venv_ver) ≠ system Python ($sys_ver) — rebuilding venv."
    rm -rf "$VENV_DIR"
    return 1
  fi
  # Quick import-smoke of a core package to catch half-baked venvs
  if ! "$VENV_PYTHON" -c 'import yaml' 2>/dev/null; then
    warn "Venv import smoke test failed — will repair via sync."
    return 1
  fi
  log "Venv integrity OK (Python $venv_ver)."
  return 0
}

sync_workspace() {
  log "Syncing workspace (system Python: $SYSTEM_PYTHON)."
  export UV_PYTHON="$SYSTEM_PYTHON"
  export UV_NO_MANAGED_PYTHON=1
  export UV_PYTHON_DOWNLOADS=never

  # Default --extra full (OpenSearch + RAG knowledge are native forensic
  # capabilities). core-only installs use --extra core (gateway + portal +
  # in-process core tools only). External add-ons such as OpenCTI are never
  # pulled by the native installer; scripts/setup-addon.sh requests their extras
  # explicitly when an operator prepares them.
  local sync_extra="full"
  [[ "${SIFT_CORE_ONLY:-0}" == "1" ]] && sync_extra="core"
  log "Workspace extra: $sync_extra"
  "$UV_BIN" sync \
    --extra "$sync_extra" \
    --project "$REPO_DIR" \
    --python "$SYSTEM_PYTHON" \
    --no-managed-python \
    --no-python-downloads

  # Post-sync: verify the venv can import critical packages
  log "Verifying venv baseline imports."
  local ok=1
  for pkg in yaml mcp sift_core sift_gateway; do
    if ! "$VENV_PYTHON" -c "import $pkg" 2>/dev/null; then
      warn "Post-sync import of '$pkg' failed — workspace may be incomplete."
      ok=0
    fi
  done
  if [[ "$ok" -eq 0 ]]; then
    warn "Some imports failed.  Attempting one retry with --reinstall..."
    "$UV_BIN" sync \
      --extra "$sync_extra" \
      --project "$REPO_DIR" \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python \
      --no-python-downloads \
      --reinstall 2>/dev/null || warn "Retry sync also had issues — check network."
  fi
  log "Workspace sync complete."
}

repair_pyewf_venv_link() {
  [[ -x "$VENV_PYTHON" ]] || return 0
  if "$VENV_PYTHON" -c 'import pyewf' >/dev/null 2>&1; then
    log "pyewf import OK in venv."
    return 0
  fi

  local pyewf_origin
  pyewf_origin="$("$SYSTEM_PYTHON" - <<'PY' 2>/dev/null || true
import importlib.util
spec = importlib.util.find_spec("pyewf")
print(spec.origin if spec and spec.origin else "")
PY
)"
  if [[ -z "$pyewf_origin" || ! -e "$pyewf_origin" ]]; then
    warn "pyewf is not importable from system Python; install python3-libewf/libewf bindings if EWF tooling needs pyewf."
    return 0
  fi

  local site_dir
  site_dir="$("$VENV_PYTHON" - <<'PY'
import site
paths = site.getsitepackages()
print(paths[0] if paths else "")
PY
)"
  if [[ -z "$site_dir" || ! -d "$site_dir" ]]; then
    warn "Could not locate venv site-packages for pyewf relink."
    return 0
  fi

  ln -sfn "$pyewf_origin" "$site_dir/$(basename "$pyewf_origin")"
  if "$VENV_PYTHON" -c 'import pyewf' >/dev/null 2>&1; then
    log "Linked system pyewf into venv: $pyewf_origin"
  else
    warn "pyewf relink did not make pyewf importable in the venv."
  fi
}

# =============================================================================
# Phase 3 — state directories
# =============================================================================

install_state_dirs() {
  # Runtime state is owned by sift-service so the SERVICE can read/write it. The
  # installer runs as the operator, so every mkdir/chown crosses the boundary via
  # sudo. The service user + `sift` group must already exist (ensure_gateway_service_user).
  local svc="$SIFT_GATEWAY_SERVICE_USER"
  log "Creating SIFT state directories (owned by service user: $svc)."

  # /var/lib/sift itself must be world-traversable (0755) so the service can
  # reach its SIFT_HOME/state children and the world-readable symbol-cache parent
  # is reachable; its sensitive children keep tight modes below.
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_STATE_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_PASSWORDS_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_VERIFICATION_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_TOKENS_DIR"
  # REVIEW: snapshots kept at uid/gid 1000 (the operator) as before — snapshot
  # tooling historically writes them as the interactive operator, not the service.
  sudo_if_needed install -d -m 755 -o 1000 -g 1000 "$SIFT_SNAPSHOTS_DIR"
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_ENRICHMENT_DIR"
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_CASE_ROOT"

  # B-MVP-015 / B-MVP-004 (D3): explicit Hugging Face cache under the service
  # home so the BGE embedding weights live with the service that uses them
  # (gateway/worker run as sift-service and read HF_HOME from their unit env),
  # not in the operator's home. 0755 so the seed (run by the operator via uv)
  # and the running service can both reach it; weights are public, not secret.
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$(dirname "$SIFT_HF_HOME")"
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_HF_HOME"

  # SIFT_HOME (secrets + gateway.yaml + TLS + backups): 0700 owned sift-service.
  # NOT group `sift` — secrets must NOT be readable by agent_runtime.
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_HOME"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_TLS_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_BACKUP_DIR"

  # Shared Volatility3 symbol cache under /var/cache (NOT $SIFT_STATE_DIR — see
  # the SIFT_VOL_SYMBOLS definition: /var/lib/sift carries a recursive
  # agent_runtime deny ACL). 2775 (setgid) group `sift` so both sift-service and
  # agent_runtime inherit the group and can share PDB symbols. The group-write
  # default ACL (so cached files are group-writable, not just group-readable) is
  # asserted in join_shared_symbol_group, after configure_agent_runtime ensures acl.
  sudo_if_needed install -d -m 0755 "$(dirname "$SIFT_VOL_SYMBOLS")"
  sudo_if_needed install -d -m 2775 -o "$svc" -g "$SIFT_GATEWAY_SERVICE_GROUP" "$SIFT_VOL_SYMBOLS"
  # Re-assert setgid bit (install -m may be masked by umask on some coreutils).
  sudo_if_needed chmod 2775 "$SIFT_VOL_SYMBOLS"
}

ensure_gateway_service_user() {
  if [[ -z "${SIFT_GATEWAY_SERVICE_USER:-}" ]]; then
    SIFT_GATEWAY_SERVICE_USER="sift-service"
  fi
  local svc="$SIFT_GATEWAY_SERVICE_USER"

  # Primary per-user group (sift-service) — distinct from the shared `sift` group.
  if ! getent group "$svc" >/dev/null 2>&1; then
    log "Creating gateway service primary group: $svc"
    sudo_if_needed groupadd -r "$svc"
  fi

  # Shared symbol-cache group (`sift`) — supplementary group for sift-service and
  # (later) agent_runtime. Used ONLY for the 2775 volatility-symbols cache.
  if ! getent group "$SIFT_GATEWAY_SERVICE_GROUP" >/dev/null 2>&1; then
    log "Creating shared symbol-cache group: $SIFT_GATEWAY_SERVICE_GROUP"
    sudo_if_needed groupadd -r "$SIFT_GATEWAY_SERVICE_GROUP"
  fi

  if id -u "$svc" >/dev/null 2>&1; then
    log "Gateway service user exists: $svc"
  else
    local nologin="/usr/sbin/nologin"
    [[ -x "$nologin" ]] || nologin="/sbin/nologin"
    [[ -x "$nologin" ]] || nologin="/bin/false"
    log "Creating dedicated gateway service user: $svc (home=$SIFT_STATE_DIR, group=$svc)"
    sudo_if_needed useradd -r -M -s "$nologin" -d "$SIFT_STATE_DIR" -g "$svc" "$svc"
  fi

  # Idempotently add the service user to the shared symbol group.
  if ! id -nG "$svc" 2>/dev/null | tr ' ' '\n' | grep -qx "$SIFT_GATEWAY_SERVICE_GROUP"; then
    log "Adding $svc to shared symbol group: $SIFT_GATEWAY_SERVICE_GROUP"
    sudo_if_needed usermod -aG "$SIFT_GATEWAY_SERVICE_GROUP" "$svc"
  fi
}

# Add agent_runtime to the shared `sift` group so it can write the shared
# Volatility3 symbol cache. Idempotent. Grants NOTHING else — `sift` gates only
# the 2775 vol-symbols dir; agent_runtime gains no access to SIFT_HOME secrets
# (those stay group sift-service, mode 0700/0600).
join_shared_symbol_group() {
  # Group-write default ACL on the shared symbol cache: setgid alone propagates
  # group ownership but new files still land 0644 (group read-only), so a symbol
  # generated by one user can't be rewritten by the other. A default ACL grants
  # group `sift` rwx on the dir and on inherited files. Runs here (not in
  # install_state_dirs) because configure_agent_runtime has ensured `acl` by now.
  if command -v setfacl >/dev/null 2>&1 && [[ -d "$SIFT_VOL_SYMBOLS" ]]; then
    sudo_if_needed setfacl -m "g:${SIFT_GATEWAY_SERVICE_GROUP}:rwx" \
      -d -m "g:${SIFT_GATEWAY_SERVICE_GROUP}:rwx" "$SIFT_VOL_SYMBOLS" 2>/dev/null \
      || warn "Could not set group-write ACL on $SIFT_VOL_SYMBOLS — cross-user symbol caching may be read-only."
  fi

  local rt="${SIFT_EXECUTE_AS_USER:-}"
  if [[ -z "$rt" || "$rt" == "__current__" ]]; then
    return 0
  fi
  if ! id -u "$rt" >/dev/null 2>&1; then
    warn "join_shared_symbol_group: runtime user '$rt' not found — skipping vol-symbol group membership."
    return 0
  fi
  if ! id -nG "$rt" 2>/dev/null | tr ' ' '\n' | grep -qx "$SIFT_GATEWAY_SERVICE_GROUP"; then
    log "Adding $rt to shared symbol group: $SIFT_GATEWAY_SERVICE_GROUP"
    sudo_if_needed usermod -aG "$SIFT_GATEWAY_SERVICE_GROUP" "$rt"
  fi
}

configure_agent_runtime() {
  if [[ -z "${SIFT_EXECUTE_AS_USER:-}" || "${SIFT_EXECUTE_AS_USER}" == "__current__" ]]; then
    warn "execute.runtime_user disabled; run_command will execute as the gateway user. Use only for development."
    return 0
  fi

  if ! command -v setfacl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      log "Installing acl package for run_command native user isolation."
      apt_install_packages acl || true
    fi
  fi

  require_cmd setfacl
  require_cmd getfacl
  if ! command -v visudo >/dev/null 2>&1 && [[ ! -x /usr/sbin/visudo ]]; then
    die "Missing required command: visudo"
  fi

  log "Configuring run_command native user isolation: runtime=${SIFT_EXECUTE_AS_USER}, service=${SIFT_GATEWAY_SERVICE_USER}."
  sudo_if_needed "$REPO_DIR/scripts/setup-agent-runtime.sh" \
    --runtime-user "$SIFT_EXECUTE_AS_USER" \
    --service-user "$SIFT_GATEWAY_SERVICE_USER" \
    --cases-root "$SIFT_CASES_ROOT" \
    --state-root "$SIFT_STATE_DIR"
}

configure_ingest_mount_sudoers() {
  if ! command -v visudo >/dev/null 2>&1 && [[ ! -x /usr/sbin/visudo ]]; then
    die "Missing required command: visudo"
  fi
  log "Configuring forensic ingest mount sudoers for service user: ${SIFT_GATEWAY_SERVICE_USER}."
  sudo_if_needed "$REPO_DIR/scripts/setup-ingest-mount-sudoers.sh" \
    --service-user "$SIFT_GATEWAY_SERVICE_USER"
}

# =============================================================================
# Phase 4 — assets (triage DBs, RAG index, hayabusa, FUSE)
# =============================================================================

configure_fuse() {
  local fuse_conf="/etc/fuse.conf"
  if [[ -f "$fuse_conf" ]] && grep -q '^user_allow_other$' "$fuse_conf" 2>/dev/null; then
    log "FUSE user_allow_other already enabled."
    return
  fi
  log "Enabling user_allow_other in /etc/fuse.conf (forensic image mounting)."
  if [[ -f "$fuse_conf" ]]; then
    sudo_if_needed sed -i 's/^#\s*user_allow_other\b.*/user_allow_other/' "$fuse_conf"
    if ! grep -q '^user_allow_other$' "$fuse_conf"; then
      echo 'user_allow_other' | sudo_if_needed tee -a "$fuse_conf" >/dev/null
    fi
  else
    echo 'user_allow_other' | sudo_if_needed tee "$fuse_conf" >/dev/null
  fi
}

prepare_enrichment_assets() {
  # SIFT_ENRICHMENT_DIR is sift-service-owned 0755 (install_state_dirs); the
  # operator must create the symlink/subdir via sudo. The symlink target is the
  # world-readable repo data dir under /opt, which the service reads through it.
  log "Preparing enrichment asset pointers."
  if [[ -d "$REPO_DIR/packages/forensic-knowledge/data" ]]; then
    sudo_if_needed ln -sfn "$REPO_DIR/packages/forensic-knowledge/data" "$SIFT_ENRICHMENT_DIR/forensic-knowledge"
  else
    warn "forensic-knowledge data directory not found."
  fi
  sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$SIFT_ENRICHMENT_DIR/forensic-rag"
}

download_rag_index() {
  local rag_data_dir="$REPO_DIR/packages/forensic-rag-mcp/data"
  local chroma_dir="$rag_data_dir/chroma"

  if [[ -d "$chroma_dir" ]]; then
    log "RAG knowledge index already exists at $chroma_dir — preserving."
    return
  fi

  if is_offline; then
    warn "SIFT_OFFLINE=1: skipping RAG Chroma bundle download (legacy chroma path)."
    warn "  Stage the bundle at $chroma_dir, or use the default SIFT_RAG_IMPORT_SOURCE=direct path (bundled JSONL, no download)."
    return
  fi
  # B-MVP-004 (D4): pin the release tag (the bundle's internal SHA-256 file is
  # still verified by download_index.py) instead of resolving "latest".
  log "Downloading pre-built RAG knowledge index ${SIFT_RAG_INDEX_TAG} (22K+ records, ~1-3 GB)..."
  if "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads \
    python -m rag_mcp.scripts.download_index --dest "$rag_data_dir" --tag "$SIFT_RAG_INDEX_TAG"; then
    log "RAG knowledge index downloaded and verified."
  else
    warn "RAG knowledge index download FAILED."
    warn "  forensic-rag-mcp will start in degraded mode."
    warn "  Retry: python -m rag_mcp.scripts.download_index --tag $SIFT_RAG_INDEX_TAG"
  fi
}

import_rag_pgvector() {
  local rag_data_dir="$REPO_DIR/packages/forensic-rag-mcp/data"
  local chroma_dir="$rag_data_dir/chroma"
  local dsn="${SIFT_CONTROL_PLANE_DSN:-${DATABASE_URL:-${POSTGRES_DSN:-}}}"

  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  if [[ -z "$dsn" ]]; then
    warn "SIFT_CONTROL_PLANE_DSN is not set — skipping Supabase pgvector RAG import."
    warn "  Chroma RAG may be present, but kb_search_knowledge will use only existing pgvector rows."
    return 0
  fi
  if [[ ! -d "$chroma_dir" ]]; then
    warn "Chroma RAG index not found at $chroma_dir — skipping Supabase pgvector RAG import."
    warn "  Retry after download: rag-mcp-import-chroma-pgvector --chroma-dir '$chroma_dir'"
    return 0
  fi

  log "Importing downloaded RAG knowledge index into Supabase pgvector."
  if SIFT_CONTROL_PLANE_DSN="$dsn" "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads \
    rag-mcp-import-chroma-pgvector --chroma-dir "$chroma_dir"; then
    log "Supabase pgvector RAG import completed."
  else
    warn "Supabase pgvector RAG import FAILED."
    warn "  Retry: SIFT_CONTROL_PLANE_DSN='<dsn>' rag-mcp-import-chroma-pgvector --chroma-dir '$chroma_dir'"
  fi
}

seed_rag_pgvector_direct() {
  local knowledge_dir="$REPO_DIR/packages/forensic-rag-mcp/knowledge"
  local dsn="${SIFT_CONTROL_PLANE_DSN:-${DATABASE_URL:-${POSTGRES_DSN:-}}}"

  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  if [[ -z "$dsn" ]]; then
    warn "SIFT_CONTROL_PLANE_DSN is not set — skipping direct Supabase pgvector RAG seed."
    warn "  kb_search_knowledge will use only existing pgvector rows."
    return 0
  fi
  if [[ ! -d "$knowledge_dir" ]]; then
    warn "Bundled RAG knowledge directory not found at $knowledge_dir — skipping pgvector seed."
    return 0
  fi

  log "Seeding bundled RAG knowledge directly into Supabase pgvector."
  # B-MVP-015 / B-MVP-004 (D3): pin the model name + revision and use an explicit
  # HF_HOME under the service-home cache. In offline mode set HF_HUB_OFFLINE so
  # sentence-transformers loads only from the pre-staged cache and never reaches
  # Hugging Face Hub. SIFT_HF_HOME is created/owned sift-service in install_state_dirs.
  local hf_offline=0
  is_offline && hf_offline=1
  # Run the seed AS the gateway service user (not the installer), from a
  # service-traversable CWD, using the venv console script directly. Two
  # fresh-install failure modes this avoids (both observed during BATCH-LV1):
  #   1. the installer cannot write the sift-service-owned HF_HOME cache
  #      ([Errno 13] .../.cache/huggingface/hub);
  #   2. sentence-transformers probes the model id relative to CWD, and the
  #      installer's $HOME is not traversable by the service user
  #      ([Errno 13] 'BAAI/bge-base-en-v1.5/modules.json').
  # The service user owns HF_HOME and is the same identity that reads the model
  # cache at query time. Any operator-set proxy env is forwarded explicitly.
  local seed_bin="$REPO_DIR/.venv/bin/rag-mcp-seed-pgvector"
  local svc="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
  local as_svc=(); [[ "$(id -un)" != "$svc" ]] && as_svc=(sudo -u "$svc")
  if ( cd "$SIFT_STATE_DIR" && "${as_svc[@]}" env \
        SIFT_CONTROL_PLANE_DSN="$dsn" \
        RAG_MODEL_NAME="$SIFT_RAG_MODEL_NAME" \
        RAG_MODEL_REVISION="$SIFT_RAG_MODEL_REVISION" \
        HF_HOME="$SIFT_HF_HOME" \
        HF_HUB_OFFLINE="$hf_offline" \
        TRANSFORMERS_OFFLINE="$hf_offline" \
        http_proxy="${http_proxy:-}" https_proxy="${https_proxy:-}" \
        HTTP_PROXY="${HTTP_PROXY:-}" HTTPS_PROXY="${HTTPS_PROXY:-}" \
        no_proxy="${no_proxy:-}" NO_PROXY="${NO_PROXY:-}" \
        "$seed_bin" --knowledge-dir "$knowledge_dir" --embedding-mode model ); then
    log "Direct Supabase pgvector RAG seed completed."
  else
    warn "Direct Supabase pgvector RAG seed FAILED."
    if is_offline; then
      warn "  Offline mode: pre-stage the model cache at $SIFT_HF_HOME (revision $SIFT_RAG_MODEL_REVISION) from an internet-connected host."
    fi
    warn "  Retry: SIFT_CONTROL_PLANE_DSN='<dsn>' rag-mcp-seed-pgvector --knowledge-dir '$knowledge_dir' --embedding-mode model"
  fi
}

load_rag_pgvector() {
  # Default path: build embeddings from the bundled knowledge corpus directly
  # into Supabase pgvector. The legacy Chroma release bundle remains an explicit
  # compatibility/import path for old snapshots and larger prebuilt corpora.
  case "${SIFT_RAG_IMPORT_SOURCE:-direct}" in
    direct)
      seed_rag_pgvector_direct
      ;;
    chroma)
      download_rag_index
      import_rag_pgvector
      ;;
    *)
      warn "Unknown SIFT_RAG_IMPORT_SOURCE='${SIFT_RAG_IMPORT_SOURCE}' — expected direct or chroma; using direct."
      seed_rag_pgvector_direct
      ;;
  esac
}

install_hayabusa() {
  log "Installing hayabusa detection engine."
  # binary_dir/rules_dir live under SIFT_HOME (sift-service-owned 0700). The
  # operator downloads/extracts into an operator temp, then installs the artifacts
  # owned sift-service so the service (and run_command via the runtime user, which
  # invokes the system-wide /usr/local/bin/hayabusa symlink) can execute them.
  local binary_dir="$SIFT_HOME/bin"
  local rules_dir="$SIFT_HOME/hayabusa-rules"

  if sudo_if_needed test -x "$binary_dir/hayabusa"; then
    log "hayabusa already installed (preserving $binary_dir/hayabusa)."
    return
  fi

  require_cmd unzip

  # B-MVP-004 (D2): pin the Hayabusa release tag + SHA-256 of the lin-x64-gnu zip
  # instead of resolving "latest". Upstream publishes no checksum file, so the
  # hash is pinned in this script (SIFT_HAYABUSA_SHA256) like the Supabase CLI.
  local tag="$SIFT_HAYABUSA_TAG"
  local asset="hayabusa-${tag#v}-lin-x64-gnu.zip"
  local url="https://github.com/Yamato-Security/hayabusa/releases/download/${tag}/${asset}"

  if is_offline; then
    warn "SIFT_OFFLINE=1: skipping hayabusa download. Detection will be unavailable until staged."
    warn "  Stage offline: place the hayabusa binary at $binary_dir/hayabusa (and rules at $rules_dir),"
    warn "  or pre-download $asset and extract it there, then re-run ./install.sh."
    return
  fi

  log "Downloading hayabusa ${tag} (pinned)..."
  local tmpd
  tmpd="$(mktemp -d)"

  if ! curl -fsSL -o "$tmpd/$asset" "$url"; then
    warn "hayabusa download failed.  Detection will be unavailable."
    rm -rf "$tmpd"
    return
  fi

  # SHA-256 pin is a hard gate: a mismatch means the pinned artifact changed
  # upstream (or was tampered with). Refuse to install rather than run an
  # unverified detection binary.
  if ! verify_sha256 "$tmpd/$asset" "$SIFT_HAYABUSA_SHA256"; then
    warn "hayabusa ${tag} failed SHA-256 verification — refusing to install (supply-chain guard)."
    warn "  If you intentionally bumped the pin, set SIFT_HAYABUSA_TAG and SIFT_HAYABUSA_SHA256."
    rm -rf "$tmpd"
    return
  fi
  log "  hayabusa SHA-256 verified."

  if ! file "$tmpd/$asset" | grep -q 'Zip archive'; then
    warn "hayabusa download was not a valid ZIP.  Detection will be unavailable."
    rm -rf "$tmpd"
    return
  fi

  unzip -qo "$tmpd/$asset" -d "$tmpd/extracted"
  local extracted
  extracted=$(find "$tmpd/extracted" -name 'hayabusa-*' -type f | head -1)
  if [[ -z "$extracted" ]]; then
    warn "Could not find hayabusa binary in archive."
    rm -rf "$tmpd"
    return
  fi

  sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$binary_dir"
  svc_install_file "$extracted" "$binary_dir/hayabusa" 755
  log "hayabusa installed: $(sudo_if_needed "$binary_dir/hayabusa" help 2>&1 | head -1)"

  if [[ -d "$tmpd/extracted/rules" ]]; then
    sudo_if_needed rm -rf "$rules_dir"
    sudo_if_needed cp -r "$tmpd/extracted/rules" "$rules_dir"
    sudo_if_needed chown -R "$SIFT_GATEWAY_SERVICE_USER:$SIFT_GATEWAY_SERVICE_USER" "$rules_dir"
    log "hayabusa rules installed: $(sudo_if_needed find "$rules_dir" -name '*.yml' | wc -l) YAML files"
  else
    warn "Bundled rules not found in release archive."
  fi
  rm -rf "$tmpd"
}

install_hayabusa_system_links() {
  local binary="$SIFT_HOME/bin/hayabusa"
  sudo_if_needed test -x "$binary" || return 0
  sudo_if_needed ln -sf "$binary" /usr/local/bin/hayabusa 2>/dev/null || true
}

fix_volatility_permissions() {
  # NO-OP (intentional). Volatility3 symbols no longer go to /opt/volatility3.
  # They now live in the shared, group-writable cache at
  # $SIFT_VOL_SYMBOLS (= /var/cache/sift/volatility-symbols, mode 2775, group
  # `sift`), created by install_state_dirs and exported into both systemd units
  # as SIFT_VOL_SYMBOLS. parse_memory.py / worker.py read SIFT_VOL_SYMBOLS and
  # write symbols there, shared between sift-service and agent_runtime.
  # The old `chmod -R a+w /opt/volatility3` hack is removed so /opt/volatility3
  # is NOT left world-writable.
  return 0
}

# =============================================================================
# Phase 5 — TLS
# =============================================================================

# BATCH-TLS1 / B-MVP-001: internal/local-CA profile for the IP-only lab VM.
#
# Trust model: one long-lived local CA ("Protocol SIFT Gateway local CA") signs
# the gateway leaf. Clients trust the CA *once* (import ca-cert.pem); the leaf can
# then be renewed without re-trusting anything. The CA is NEVER rotated by a
# normal rerun (clients would lose trust) — only `scripts/rotate-tls.sh --rotate-ca`
# does that, with explicit DANGER labelling.
#
# CA validity (10y) > leaf validity (2y), so the signer outlives every leaf it
# issues. ACME/domain certs are a deferred future profile (see docs §11) and are
# not built here.
SIFT_TLS_CA_DAYS="${SIFT_TLS_CA_DAYS:-3650}"
SIFT_TLS_LEAF_DAYS="${SIFT_TLS_LEAF_DAYS:-730}"
SIFT_TLS_CA_CN="${SIFT_TLS_CA_CN:-Protocol SIFT Gateway local CA}"

# _tls_san_value -> "IP:<primary>,IP:127.0.0.1,DNS:<hostname>,DNS:localhost"
# SANs are DERIVED from the VM's real primary IP and hostname, never hardcoded.
# Loopback (127.0.0.1 / localhost) is always included so on-box `/health` and
# OpenSearch loopback checks verify cleanly. The primary IP falls back to
# 127.0.0.1 only when `hostname -I` yields nothing.
_tls_san_value() {
  local first_ip host
  first_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$first_ip" ]] || first_ip="127.0.0.1"
  host="$(hostname 2>/dev/null)"
  [[ -n "$host" ]] || host="localhost"
  if [[ "$first_ip" == "127.0.0.1" ]]; then
    printf 'IP:127.0.0.1,DNS:%s,DNS:localhost' "$host"
  else
    printf 'IP:%s,IP:127.0.0.1,DNS:%s,DNS:localhost' "$first_ip" "$host"
  fi
}

# _tls_write_leaf_ext <file> — x509 v3 extensions for the gateway LEAF cert:
# not-a-CA, server auth EKU (Chrome/modern clients require it), and the derived
# SAN list. Written to a caller-owned temp.
_tls_write_leaf_ext() {
  local out="$1"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=%s\n' "$(_tls_san_value)"
  } > "$out"
}

# _tls_sign_leaf <tmpd> <ca-cert> <ca-key> — generate a fresh leaf KEY + cert
# signed by the EXISTING CA, leaving $tmpd/gateway-key.pem and
# $tmpd/gateway-cert.pem. Used by both first-install and leaf-renewal so the two
# paths cannot drift. Operates only in the caller's temp dir; never touches the
# live tree (the caller installs the results).
_tls_sign_leaf() {
  local tmpd="$1" ca_cert="$2" ca_key="$3"
  local ext="$tmpd/leaf-ext.cnf"
  _tls_write_leaf_ext "$ext"
  openssl genrsa -out "$tmpd/gateway-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -key "$tmpd/gateway-key.pem" \
    -out "$tmpd/gateway-csr.pem" -subj "/CN=$(hostname)" >/dev/null 2>&1
  openssl x509 -req -days "$SIFT_TLS_LEAF_DAYS" -in "$tmpd/gateway-csr.pem" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -out "$tmpd/gateway-cert.pem" -extfile "$ext" >/dev/null 2>&1
}

generate_tls() {
  require_cmd openssl
  # SIFT_TLS_DIR is sift-service-owned 0700 (created by install_state_dirs). The
  # operator generates the material in an operator-owned temp dir, then installs
  # each file owned sift-service so the running gateway can read its key/cert.
  if svc_test_f "$SIFT_TLS_DIR/ca-cert.pem" \
     && svc_test_f "$SIFT_TLS_DIR/gateway-cert.pem" \
     && svc_test_f "$SIFT_TLS_DIR/gateway-key.pem"; then
    # Idempotent rerun: PRESERVE the CA and leaf. Clients keep their trust; a
    # rerun must never silently rotate the CA. Leaf renewal is an explicit
    # operator action via scripts/rotate-tls.sh.
    log "TLS material already exists — preserving CA and gateway cert."
    return
  fi

  log "Generating local CA and gateway certificate (internal-CA lab profile)."
  local tmpd
  tmpd="$(mktemp -d)"
  # CA extensions via -addext (openssl req does NOT accept -extfile; only the
  # `openssl x509` leaf-signing step does). basicConstraints critical CA:TRUE so
  # clients accept it as an issuer; keyUsage limited to cert/CRL signing.
  openssl genrsa -out "$tmpd/ca-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -x509 -days "$SIFT_TLS_CA_DAYS" -key "$tmpd/ca-key.pem" \
    -out "$tmpd/ca-cert.pem" -subj "/CN=$SIFT_TLS_CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

  _tls_sign_leaf "$tmpd" "$tmpd/ca-cert.pem" "$tmpd/ca-key.pem"

  # Private keys -> 0600 sift-service; certs -> 0644 sift-service (world-readable
  # cert is fine — only the matching private key is sensitive). The ca-cert is
  # also handed to analysts (handoff references $SIFT_TLS_DIR/ca-cert.pem).
  svc_install_file "$tmpd/ca-key.pem"      "$SIFT_TLS_DIR/ca-key.pem"      600
  svc_install_file "$tmpd/gateway-key.pem" "$SIFT_TLS_DIR/gateway-key.pem" 600
  svc_install_file "$tmpd/ca-cert.pem"     "$SIFT_TLS_DIR/ca-cert.pem"     644
  svc_install_file "$tmpd/gateway-cert.pem" "$SIFT_TLS_DIR/gateway-cert.pem" 644
  rm -rf "$tmpd"
}

# =============================================================================
# Phase 6 — examiner account (local PBKDF2 legacy + Supabase-first bootstrap)
# =============================================================================

write_default_examiner() {
  # SIFT_PASSWORDS_DIR is sift-service-owned 0700. The operator hashes the temp
  # password into an operator-owned temp JSON, then installs it owned sift-service
  # 0600 so the gateway can read the legacy PBKDF2 fallback credential.
  local password_file="$SIFT_PASSWORDS_DIR/$SIFT_EXAMINER.json"
  if svc_test_f "$password_file"; then
    log "Default examiner password already exists — preserving."
    TEMP_PASSWORD_CREATED=0
    TEMP_PASSWORD=""
    return
  fi
  TEMP_PASSWORD="Agentir-$(random_hex 12)"
  TEMP_PASSWORD_CREATED=1
  local tmp
  tmp="$(mktemp)"
  export SIFT_EXAMINER TEMP_PASSWORD EXAMINER_TMP_OUT="$tmp"
  "$SYSTEM_PYTHON" - <<'PY'
import hashlib, json, os, secrets

examiner = os.environ["SIFT_EXAMINER"]
password = os.environ["TEMP_PASSWORD"]
out = os.environ["EXAMINER_TMP_OUT"]
salt = secrets.token_bytes(32)
entry = {
    "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex(),
    "salt": salt.hex(),
    "must_reset_password": True,
    "created_by": "sift-mcps install.sh",
}
with open(out, "w") as handle:
    os.chmod(out, 0o600)
    json.dump(entry, handle)
    handle.flush()
    os.fsync(handle.fileno())
PY
  svc_install_file "$tmp" "$password_file" 600
  rm -f "$tmp"
  unset EXAMINER_TMP_OUT
}

# OS1-BOOTSTRAP: seed enabled add-on backends into app.mcp_backends.
# Runs after gateway is up and DB is reachable. Idempotent via upsert (ON CONFLICT).
# Only registers backends whose install-time enablement flag is "true" AND whose
# manifest file exists. Raw OpenSearch credentials, DSNs, and MCP tokens are NEVER
# stored — only env-ref metadata (env_refs pointing to gateway process env vars).
# If SIFT_CONTROL_PLANE_DSN is absent this is a no-op; core-only mode skips it.
# Seed one stdio add-on backend into app.mcp_backends (idempotent upsert).
# Args: $1 = backend name, $2 = manifest path, $3 = venv entry-point script,
#       $4 = JSON object of env_refs (gateway-env -> child-env), default "{}".
# No raw secrets are stored — only env_ref names; the gateway resolves the
# actual values from its own process environment at load time.
_seed_one_addon_backend() {
  local backend_name="$1"
  local manifest_path="$2"
  local entry_point="$3"
  local env_refs_json="${4:-}"
  [[ -n "$env_refs_json" ]] || env_refs_json="{}"

  if [[ ! -f "$manifest_path" ]]; then
    warn "seed_addon_backends: $backend_name manifest not found at $manifest_path — skipping."
    return 0
  fi

  log "Seeding $backend_name into app.mcp_backends (idempotent upsert)."
  export SIFT_CONTROL_PLANE_DSN="$SEED_CP_DSN"
  export SEED_BACKEND_NAME="$backend_name"
  export SEED_MANIFEST_PATH="$manifest_path"
  export SEED_ENTRY_POINT="$entry_point"
  export SEED_ENV_REFS_JSON="$env_refs_json"
  export SEED_UV_BIN="$UV_BIN"
  export SEED_PYTHON_BIN="$SYSTEM_PYTHON"
  export SEED_REPO_DIR="$REPO_DIR"

  if ! "$VENV_DIR/bin/python" - <<'PY'
import json, os, sys
from pathlib import Path

dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
backend_name = os.environ["SEED_BACKEND_NAME"]
manifest_path = Path(os.environ["SEED_MANIFEST_PATH"])
entry_point = os.environ["SEED_ENTRY_POINT"]
env_refs = json.loads(os.environ.get("SEED_ENV_REFS_JSON") or "{}")
repo_dir = os.environ["SEED_REPO_DIR"]
entry_script = Path(repo_dir) / ".venv" / "bin" / entry_point
if not entry_script.exists():
    print(f"seed_addon_backends: entrypoint not found: {entry_script}", file=sys.stderr)
    sys.exit(1)

try:
    from sift_gateway.mcp_backends_registry import McpBackendRegistry, normalize_connection_config
except ImportError as exc:
    print(f"seed_addon_backends: sift_gateway not importable: {exc} — skipping", file=sys.stderr)
    sys.exit(0)

manifest = json.loads(manifest_path.read_text())

# Connection config: stdio, no raw secrets — env_refs map gateway process env
# vars into the backend child process env at gateway load time.
connection = {
    "type": "stdio",
    "command": str(entry_script),
    "args": [],
    "manifest_path": str(manifest_path),
    "env_refs": env_refs,
}

try:
    registry = McpBackendRegistry(dsn)
    registry.register(
        name=backend_name,
        config=connection,
        manifest=manifest,
        actor=None,
    )
    print(f"seed_addon_backends: {backend_name} registered/updated in app.mcp_backends.")
except Exception as exc:
    print(f"seed_addon_backends: registration error: {exc}", file=sys.stderr)
    sys.exit(1)
PY
  then
    warn "seed_addon_backends: $SEED_BACKEND_NAME seeding failed — operator can register via Portal -> Backends."
    return 1
  fi
}

seed_addon_backends() {
  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"
  if [[ -z "$cp_dsn" ]]; then
    log "seed_addon_backends: no control-plane DSN — skipping DB backend seeding."
    return 0
  fi
  export SEED_CP_DSN="$cp_dsn"

  # opensearch-mcp: gated by SIFT_OPENSEARCH_ENABLED. The OPENSEARCH_CONFIG/
  # OPENSEARCH_HOST env refs are resolved by the gateway from its own env.
  if [[ "${SIFT_OPENSEARCH_ENABLED:-}" == "true" ]]; then
    if _seed_one_addon_backend \
      "opensearch-mcp" \
      "$REPO_DIR/packages/opensearch-mcp/sift-backend.json" \
      "opensearch-mcp" \
      '{"OPENSEARCH_CONFIG": "OPENSEARCH_CONFIG", "OPENSEARCH_HOST": "OPENSEARCH_HOST"}'; then
      OPENSEARCH_SEEDED=true
    fi
  else
    log "seed_addon_backends: SIFT_OPENSEARCH_ENABLED != true — skipping opensearch-mcp seeding."
  fi

  # forensic-rag-mcp (BATCH-OSX-RAG): the knowledge add-on. Gated by
  # SIFT_RAG_ENABLED. It resolves the control-plane DSN via the
  # SIFT_CONTROL_PLANE_DSN env ref to reach the pgvector knowledge corpus; no
  # raw DSN is stored in app.mcp_backends.
  if [[ "${SIFT_RAG_ENABLED:-true}" == "true" ]]; then
    if _seed_one_addon_backend \
      "forensic-rag-mcp" \
      "$REPO_DIR/packages/forensic-rag-mcp/sift-backend.json" \
      "rag-mcp" \
      '{"SIFT_CONTROL_PLANE_DSN": "SIFT_CONTROL_PLANE_DSN"}'; then
      RAG_SEEDED=true
    fi
  else
    log "seed_addon_backends: SIFT_RAG_ENABLED != true — skipping forensic-rag-mcp seeding."
  fi
}

# A1-BOOTSTRAP: create the operator in Supabase Auth (Admin API) with status=invited.
# This runs AFTER gateway config is written (so SUPABASE_URL/SERVICE_ROLE_KEY are
# available in the environment) and after the gateway is started (so the DB is live).
# It is idempotent: if the handoff file already has a supabase_operator_email line,
# the bootstrap is skipped.
bootstrap_supabase_operator() {
  local sb_url="${SUPABASE_URL:-}"
  local sb_key="${SUPABASE_SERVICE_ROLE_KEY:-}"
  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"

  if [[ -z "$sb_url" || -z "$sb_key" ]]; then
    warn "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set — skipping Supabase operator bootstrap."
    warn "  Set these env vars and re-run ./install.sh to provision the Supabase operator account."
    SUPABASE_OPERATOR_CREATED=0
    return
  fi
  if [[ -z "$cp_dsn" ]]; then
    warn "SIFT_CONTROL_PLANE_DSN is not set — skipping Supabase operator bootstrap."
    warn "  The installer will not create an auth user without the matching app.operator_profiles row."
    warn "  Set SIFT_CONTROL_PLANE_DSN (or DATABASE_URL/POSTGRES_DSN) and re-run ./install.sh."
    SUPABASE_OPERATOR_CREATED=0
    return
  fi

  # Idempotency: skip if already bootstrapped
  if svc_test_f "$MATERIALS_FILE" && svc_read "$MATERIALS_FILE" | grep -q '^supabase_operator_email=' 2>/dev/null; then
    log "Supabase operator already bootstrapped — preserving."
    SUPABASE_OPERATOR_EMAIL="$(svc_read "$MATERIALS_FILE" | awk -F= '$1=="supabase_operator_email"{sub(/^[^=]*=/,""); print; exit}' || true)"
    if [[ -z "$SUPABASE_OPERATOR_EMAIL" ]]; then
      SUPABASE_OPERATOR_EMAIL="${SIFT_EXAMINER}@operators.sift.local"
    fi
    SUPABASE_OPERATOR_CREATED=0
    SUPABASE_OPERATOR_MAPPED=1
    export SUPABASE_OPERATOR_EMAIL SUPABASE_OPERATOR_MAPPED
    return
  fi

  # A1-BOOTSTRAP: generate one-time installer password for Supabase operator.
  # The operator MUST reset this on first login (status=invited in DB).
  local sb_temp_password
  sb_temp_password="SiftReset-$(random_hex 16)"
  local sb_email="${SIFT_EXAMINER}@operators.sift.local"

  log "Provisioning Supabase operator: $sb_email (status=invited, forced-reset on first login)."
  export SUPABASE_URL="$sb_url" SUPABASE_SERVICE_ROLE_KEY="$sb_key"
  export SIFT_CONTROL_PLANE_DSN="$cp_dsn"
  export SB_OPERATOR_EMAIL="$sb_email" SB_OPERATOR_TEMP_PW="$sb_temp_password"
  export SB_OPERATOR_EXAMINER="$SIFT_EXAMINER"

  local create_result
  create_result=$("$VENV_DIR/bin/python" - <<'PY' 2>&1
import json, os, sys, time, urllib.request, urllib.error

url = os.environ["SUPABASE_URL"].rstrip("/")
key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
email = os.environ["SB_OPERATOR_EMAIL"]
password = os.environ["SB_OPERATOR_TEMP_PW"]
examiner = os.environ["SB_OPERATOR_EXAMINER"]

try:
    import psycopg
    from psycopg.types.json import Jsonb
except Exception as exc:
    print(f"error:psycopg_unavailable:{exc}")
    sys.exit(0)


def _request(method, path, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    last_exc = None
    for attempt in range(1, 7):
        req = urllib.request.Request(
            f"{url}{path}",
            data=body,
            method=method,
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or attempt == 6:
                raise
            last_exc = exc
        except urllib.error.URLError as exc:
            if attempt == 6:
                raise
            last_exc = exc
        time.sleep(min(2 * attempt, 10))
    if last_exc is not None:
        raise last_exc
    return {}


def _auth_user_by_email(conn):
    with conn.cursor() as cur:
        cur.execute(
            "select id::text from auth.users where lower(email) = lower(%s) limit 1",
            (email,),
        )
        row = cur.fetchone()
        return str(row[0]) if row else None


def _profile_for(conn, auth_user_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            select id::text, status
            from app.operator_profiles
            where auth_user_id = %s or lower(email) = lower(%s)
            order by created_at
            limit 1
            """,
            (auth_user_id, email),
        )
        row = cur.fetchone()
        return (str(row[0]), str(row[1])) if row else (None, None)


def _upsert_operator_profile(conn, auth_user_id, prior_status):
    target_status = "active" if prior_status == "active" else "invited"
    metadata = {
        "installer_bootstrap": True,
        "bootstrap_source": "install.sh",
        "forced_reset_required": target_status == "invited",
    }
    profile_id, _status = _profile_for(conn, auth_user_id)
    with conn.cursor() as cur:
        if profile_id:
            cur.execute(
                """
                update app.operator_profiles
                set auth_user_id = %s,
                    display_name = %s,
                    email = %s,
                    status = case when status = 'active' then 'active' else %s end,
                    system_role = 'owner',
                    legacy_examiner_id = %s,
                    metadata = coalesce(metadata, '{}'::jsonb) || %s,
                    updated_at = now()
                where id = %s
                returning id::text, status
                """,
                (
                    auth_user_id,
                    examiner,
                    email,
                    target_status,
                    examiner,
                    Jsonb(metadata),
                    profile_id,
                ),
            )
        else:
            cur.execute(
                """
                insert into app.operator_profiles
                  (auth_user_id, display_name, email, status, system_role,
                   legacy_examiner_id, metadata)
                values (%s, %s, %s, %s, 'owner', %s, %s)
                returning id::text, status
                """,
                (auth_user_id, examiner, email, target_status, examiner, Jsonb(metadata)),
            )
        row = cur.fetchone()
        return str(row[0]), str(row[1])


def _create_auth_user():
    payload = {
        "email": email,
        "password": password,
        "email_confirm": True,
        "user_metadata": {
            "sift_principal_kind": "operator",
            "display_name": examiner,
            "installer_bootstrap": True,
        },
    }
    data = _request("POST", "/auth/v1/admin/users", payload)
    return str(data.get("id") or (data.get("user") or {}).get("id") or "")


def _reset_existing_auth_user(auth_user_id):
    payload = {
        "password": password,
        "email_confirm": True,
        "user_metadata": {
            "sift_principal_kind": "operator",
            "display_name": examiner,
            "installer_bootstrap": True,
        },
    }
    _request("PUT", f"/auth/v1/admin/users/{auth_user_id}", payload)


def _delete_auth_user(auth_user_id):
    try:
        _request("DELETE", f"/auth/v1/admin/users/{auth_user_id}", None)
    except Exception:
        pass


created_auth_user = False
reset_existing_password = False
auth_user_id = ""
try:
    with psycopg.connect(dsn) as conn:
        auth_user_id = _auth_user_by_email(conn)
        prior_profile_id = None
        prior_profile_status = None
        if auth_user_id:
            prior_profile_id, prior_profile_status = _profile_for(conn, auth_user_id)
        if not auth_user_id:
            auth_user_id = _create_auth_user()
            if not auth_user_id:
                print("error:no_id_in_response")
                sys.exit(0)
            created_auth_user = True
        elif prior_profile_status != "active":
            _reset_existing_auth_user(auth_user_id)
            reset_existing_password = True
        profile_id, profile_status = _upsert_operator_profile(
            conn, auth_user_id, prior_profile_status
        )
        conn.commit()
except urllib.error.HTTPError as exc:
    body = exc.read()[:200].decode("utf-8", errors="replace")
    print(f"http_error:{exc.code}:{body}")
except Exception as exc:
    if created_auth_user and auth_user_id:
        _delete_auth_user(auth_user_id)
    print(f"error:{exc}")
else:
    print("ok:" + json.dumps({
        "auth_user_id": auth_user_id,
        "operator_profile_id": profile_id,
        "profile_status": profile_status,
        "created_auth_user": created_auth_user,
        "reset_existing_password": reset_existing_password,
    }, separators=(",", ":")))
PY
)

  local rc=$?
  if [[ "$rc" -ne 0 ]] || [[ "$create_result" == error:* ]] || [[ "$create_result" == http_error:* ]]; then
    warn "Supabase operator bootstrap FAILED: $create_result"
    warn "  The legacy local examiner password is still available as a fallback."
    SUPABASE_OPERATOR_CREATED=0
    SB_OPERATOR_USER_ID=""
    return
  fi

  local bootstrap_json sb_user_id profile_status password_handoff
  bootstrap_json="${create_result#ok:}"
  sb_user_id="$("$VENV_DIR/bin/python" -c 'import json,sys; print(json.loads(sys.argv[1])["auth_user_id"])' "$bootstrap_json")"
  profile_status="$("$VENV_DIR/bin/python" -c 'import json,sys; print(json.loads(sys.argv[1])["profile_status"])' "$bootstrap_json")"
  password_handoff="$("$VENV_DIR/bin/python" -c 'import json,sys; d=json.loads(sys.argv[1]); print("1" if d.get("created_auth_user") or d.get("reset_existing_password") else "0")' "$bootstrap_json")"
  SB_OPERATOR_USER_ID="$sb_user_id"
  SUPABASE_OPERATOR_EMAIL="$sb_email"
  SUPABASE_OPERATOR_MAPPED=1
  if [[ "$password_handoff" == "1" ]]; then
    SUPABASE_OPERATOR_CREATED=1
    SUPABASE_OPERATOR_TEMP_PASSWORD="$sb_temp_password"
    export SUPABASE_OPERATOR_TEMP_PASSWORD
  else
    SUPABASE_OPERATOR_CREATED=0
    SUPABASE_OPERATOR_TEMP_PASSWORD=""
  fi
  export SB_OPERATOR_USER_ID SUPABASE_OPERATOR_EMAIL SUPABASE_OPERATOR_MAPPED

  log "Supabase operator mapped: auth_user_id=$sb_user_id  app.status=$profile_status."
  if [[ "$password_handoff" == "1" ]]; then
    log "NOTE: The one-time Supabase login password is written to: $MATERIALS_FILE"
    log "  The operator MUST reset this password immediately after first login."
  fi

  # Unset temp password from env so it's not inherited by child processes.
  unset SB_OPERATOR_TEMP_PW
}

# A1-BOOTSTRAP: validate the evidence/cases root directory and warn if missing.
validate_evidence_root() {
  log "Validating evidence root: $SIFT_CASES_ROOT"
  if [[ ! -d "$SIFT_CASES_ROOT" ]]; then
    warn "Evidence root '$SIFT_CASES_ROOT' does not exist — creating."
    # Owned by the service user to match install_state_dirs (the gateway
    # reads/registers evidence here). Normally install_state_dirs already created
    # it; this is the defensive fallback.
    sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$SIFT_CASES_ROOT" || \
      warn "Could not create '$SIFT_CASES_ROOT' — operator must create it manually."
    return
  fi
  if [[ ! -r "$SIFT_CASES_ROOT" ]]; then
    warn "Evidence root '$SIFT_CASES_ROOT' is not readable by the current user."
    return
  fi
  local case_count
  case_count=$(find "$SIFT_CASES_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l || echo 0)
  log "Evidence root OK: $SIFT_CASES_ROOT ($case_count existing case directories)."
}

# =============================================================================
# Phase 7 — gateway + opensearch config
# =============================================================================

_render_file() {
  # Render $src (env-var substituted) to $dst with mode $3. Optional $4 = owner:
  #   service (default) -> dst lands owned sift-service (SIFT_HOME secrets/config)
  #   root              -> dst lands owned root:root via sudo (/etc/systemd/system units)
  # The substitution always happens in an operator-writable temp; we then cross
  # the ownership boundary with a single sudo install, so the operator never has
  # to write directly into a sift-service- or root-owned directory.
  local src="$1" dst="$2" mode="$3" owner="${4:-service}"
  export SIFT_HOME SIFT_TLS_DIR SIFT_CONFIG SIFT_CASES_ROOT SIFT_CASE_ROOT
  export SIFT_GATEWAY_TOKEN SIFT_SERVICE_TOKEN SIFT_PORTAL_SESSION_SECRET
  export SIFT_EXECUTE_AS_USER SIFT_VOL_SYMBOLS SIFT_GATEWAY_SERVICE_USER
  export SIFT_EXAMINER SIFT_MCPS_ROOT UV_BIN PYTHON_BIN OPENCTI_URL OPENCTI_TOKEN
  export SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED SIFT_OPENSEARCH_ENABLED
  # B-MVP-015 / B-MVP-004: model cache + pins rendered into the systemd units.
  export SIFT_HF_HOME SIFT_RAG_MODEL_NAME SIFT_RAG_MODEL_REVISION

  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
  # Honor flags already set by main() (e.g. core-only); default to enabled.
  SIFT_RAG_ENABLED="${SIFT_RAG_ENABLED:-true}"
  SIFT_OPENSEARCH_ENABLED="${SIFT_OPENSEARCH_ENABLED:-true}"
  SIFT_OPENCTI_ENABLED="${SIFT_OPENCTI_ENABLED:-false}"

  local rendered
  rendered="$(mktemp)"
  "$SYSTEM_PYTHON" - "$src" "$rendered" "$mode" <<'PY'
import os, sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])  # operator-owned temp; final install is done in bash
mode = int(sys.argv[3], 8)
text = src.read_text()
for key, value in os.environ.items():
    text = text.replace("${" + key + "}", value)
with open(dst, "w") as handle:
    handle.write(text)
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(dst, mode)
PY

  if [[ "$owner" == "root" ]]; then
    sudo_if_needed install -o root -g root -m "$mode" "$rendered" "$dst"
  else
    svc_install_file "$rendered" "$dst" "$mode"
  fi
  rm -f "$rendered"
}

# A1-BOOTSTRAP: write the Supabase env file that the systemd service reads.
# Supabase secrets are NEVER stored in gateway.yaml — only in this env file
# which is chmod 600 and owned by the runtime user.
write_supabase_env() {
  local supabase_env_file="$SIFT_HOME/supabase.env"
  local sb_url="${SUPABASE_URL:-}"
  local sb_anon="${SUPABASE_ANON_KEY:-}"
  local sb_service="${SUPABASE_SERVICE_ROLE_KEY:-}"

  if [[ -z "$sb_url" && -z "$sb_anon" && -z "$sb_service" ]]; then
    log "No SUPABASE_* env vars set — skipping supabase.env."
    log "  To enable Supabase auth, set SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY"
    log "  and re-run ./install.sh, or write them to $supabase_env_file manually."
    return
  fi

  if svc_test_f "$supabase_env_file"; then
    log "Supabase env file already exists — preserving $supabase_env_file."
    return
  fi

  log "Writing Supabase env file: $supabase_env_file"
  # Write to an operator-owned temp, then install it owned sift-service 0600 so
  # the running service can read it but it never lives operator-owned. SIFT_HOME
  # is created by install_state_dirs (owned sift-service 0700).
  local tmp
  tmp="$(mktemp)"
  {
    printf '# Supabase environment — managed by sift-mcps install.sh\n'
    printf '# Secrets are stored here, not in gateway.yaml.\n'
    [[ -n "$sb_url" ]]     && printf 'SUPABASE_URL=%s\n' "$sb_url"
    [[ -n "$sb_anon" ]]    && printf 'SUPABASE_ANON_KEY=%s\n' "$sb_anon"
    [[ -n "$sb_service" ]] && printf 'SUPABASE_SERVICE_ROLE_KEY=%s\n' "$sb_service"
  } > "$tmp"
  svc_install_file "$tmp" "$supabase_env_file" 600
  rm -f "$tmp"
}

# =============================================================================
# Preflight — Supabase env sourcing / auto-provisioning
# =============================================================================
# Integration contract (fixed — see SCOPE in install.sh header):
#   scripts/setup-supabase.sh writes $HOME/.sift/supabase-project/sift-supabase.env
#   containing: export SUPABASE_URL=... SUPABASE_ANON_KEY=... SUPABASE_SERVICE_ROLE_KEY=...
#               export SIFT_CONTROL_PLANE_DSN=postgresql://...
# We source that file, or invoke the script to create it, before any Supabase-dependent
# step runs. Guarded by --core-only and --external-supabase flags.

SUPABASE_PROJECT_ENV="$HOME/.sift/supabase-project/sift-supabase.env"

preflight_supabase() {
  # Not needed for core-only or when operator supplies creds externally.
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" || "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    return 0
  fi

  # Step 1: source the env file if SUPABASE_URL is absent and the file exists.
  if [[ -z "${SUPABASE_URL:-}" && -f "$SUPABASE_PROJECT_ENV" ]]; then
    log "Sourcing Supabase env from $SUPABASE_PROJECT_ENV"
    # shellcheck disable=SC1090
    source "$SUPABASE_PROJECT_ENV"
  fi

  # Step 2: env still absent → invoke setup-supabase.sh (the Supabase agent's script).
  if [[ -z "${SUPABASE_URL:-}" && -f "$REPO_DIR/scripts/setup-supabase.sh" ]]; then
    log "SUPABASE_URL not set — running scripts/setup-supabase.sh to provision Supabase."
    bash "$REPO_DIR/scripts/setup-supabase.sh" \
      || die "scripts/setup-supabase.sh failed.  Cannot continue without Supabase."
    if [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$SUPABASE_PROJECT_ENV"
    fi
  fi

  # Step 3: still empty → die with an actionable message.
  if [[ -z "${SUPABASE_URL:-}" || -z "${SIFT_CONTROL_PLANE_DSN:-}" ]]; then
    die "Supabase credentials not found.
  Option A (auto-provision): ensure scripts/setup-supabase.sh exists in the repo.
  Option B (external):        export SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY SIFT_CONTROL_PLANE_DSN
                               then re-run: ./install.sh --external-supabase
  Option C (manual file):     write those exports to $SUPABASE_PROJECT_ENV and re-run."
  fi

  log "Supabase preflight OK: SUPABASE_URL=${SUPABASE_URL}"
  export SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY SIFT_CONTROL_PLANE_DSN
}

_env_file_value() {
  # The env files live under SIFT_HOME and are sift-service-owned 0600, so the
  # operator must read them via sudo. svc_read returns empty for a missing file.
  local file="$1" key="$2"
  svc_test_f "$file" || return 0
  svc_read "$file" | awk -F= -v k="$key" '$1 == k {sub(/^[^=]*=/, ""); print; exit}' || true
}

_resolved_control_plane_dsn() {
  local dsn="${SIFT_CONTROL_PLANE_DSN:-${DATABASE_URL:-${POSTGRES_DSN:-}}}"
  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/supabase.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  printf '%s' "$dsn"
}

_resolved_token_pepper() {
  local pepper="${SIFT_TOKEN_PEPPER:-}"
  if [[ -z "$pepper" ]]; then
    pepper="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_TOKEN_PEPPER")"
  fi
  if [[ -z "$pepper" ]]; then
    pepper="$(_env_file_value "$SIFT_HOME/supabase.env" "SIFT_TOKEN_PEPPER")"
  fi
  if [[ -z "$pepper" ]]; then
    pepper="$(random_hex 32)"
  fi
  printf '%s' "$pepper"
}

# B-MVP-010: resolve the portal session secret for env-indirection. Preserve an
# existing value so re-runs do not invalidate live operator sessions; otherwise
# mint a fresh one. The VALUE lives only in the 0600 control-plane.env file
# (gateway.yaml carries only the env-var NAME).
_resolved_session_secret() {
  local secret="${SIFT_PORTAL_SESSION_SECRET:-}"
  if [[ -z "$secret" ]]; then
    secret="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_PORTAL_SESSION_SECRET")"
  fi
  # Upgrade path: if a prior install wrote the literal into gateway.yaml, reuse
  # that exact value so existing operator portal sessions are not invalidated when
  # we move it to env-indirection (B-MVP-010). The literal is stripped from the
  # config by _migrate_gateway_config below.
  if [[ -z "$secret" ]] && svc_test_f "$SIFT_CONFIG"; then
    secret="$(svc_read "$SIFT_CONFIG" | awk -F'"' '/^[[:space:]]*session_secret:[[:space:]]*"/{print $2; exit}')"
  fi
  if [[ -z "$secret" ]]; then
    secret="$(random_hex 32)"
  fi
  printf '%s' "$secret"
}

write_control_plane_env() {
  local control_env_file="$SIFT_HOME/control-plane.env"
  local cp_dsn token_pepper session_secret
  local existing_dsn existing_pepper existing_secret
  cp_dsn="$(_resolved_control_plane_dsn)"
  token_pepper="$(_resolved_token_pepper)"
  # B-MVP-010: the portal session secret value lives here (env-indirection); the
  # gateway config carries only its name. Always resolve it so the portal has a
  # session secret even on core-only installs with no DSN.
  session_secret="$(_resolved_session_secret)"
  existing_dsn="$(_env_file_value "$control_env_file" "SIFT_CONTROL_PLANE_DSN")"
  existing_pepper="$(_env_file_value "$control_env_file" "SIFT_TOKEN_PEPPER")"
  existing_secret="$(_env_file_value "$control_env_file" "SIFT_PORTAL_SESSION_SECRET")"

  # Only skip entirely when there is nothing at all to write (no DSN, no pepper,
  # and no session secret) — otherwise the session secret alone is worth a file.
  if [[ -z "$cp_dsn" && -z "$token_pepper" && -z "$session_secret" ]]; then
    log "No control-plane env vars set — skipping control-plane.env."
    log "  To enable DB authority, set SIFT_CONTROL_PLANE_DSN and re-run ./install.sh."
    return
  fi

  if [[ -n "$existing_dsn" && -n "$existing_pepper" && -n "$existing_secret" ]]; then
    log "Control-plane env file already complete — preserving $control_env_file."
    export SIFT_CONTROL_PLANE_DSN="$existing_dsn"
    export SIFT_TOKEN_PEPPER="$existing_pepper"
    export SIFT_PORTAL_SESSION_SECRET="$existing_secret"
    return
  fi

  [[ -n "$existing_dsn" ]] && cp_dsn="$existing_dsn"
  [[ -n "$existing_pepper" ]] && token_pepper="$existing_pepper"
  [[ -n "$existing_secret" ]] && session_secret="$existing_secret"

  log "Writing control-plane env file: $control_env_file"
  # Operator-owned temp -> sift-service-owned 0600 (see write_supabase_env).
  local tmp
  tmp="$(mktemp)"
  {
    printf '# SIFT control-plane environment — managed by sift-mcps install.sh\n'
    printf '# Secrets are stored here, not in gateway.yaml.\n'
    [[ -n "$cp_dsn" ]] && printf 'SIFT_CONTROL_PLANE_DSN=%s\n' "$cp_dsn"
    # When a control-plane DSN is configured, Postgres is the active-case + audit
    # authority. SIFT_DB_ACTIVE signals that process-wide so the gateway AND the
    # async job worker (which has no per-request AuthorityContext) suppress the
    # legacy file-audit "Audit write failed" warning and treat the DB envelope as
    # authority. Non-secret flag; read by sift_core.active_case_context and
    # sift_common.audit. (Both units read this file via EnvironmentFile.)
    [[ -n "$cp_dsn" ]] && printf 'SIFT_DB_ACTIVE=1\n'
    [[ -n "$token_pepper" ]] && printf 'SIFT_TOKEN_PEPPER=%s\n' "$token_pepper"
    [[ -n "$session_secret" ]] && printf 'SIFT_PORTAL_SESSION_SECRET=%s\n' "$session_secret"
  } > "$tmp"
  svc_install_file "$tmp" "$control_env_file" 600
  rm -f "$tmp"
  [[ -n "$cp_dsn" ]] && export SIFT_CONTROL_PLANE_DSN="$cp_dsn"
  [[ -n "$token_pepper" ]] && export SIFT_TOKEN_PEPPER="$token_pepper"
  [[ -n "$session_secret" ]] && export SIFT_PORTAL_SESSION_SECRET="$session_secret"
}

# =============================================================================
# DB migrations — apply supabase/migrations/*.sql against SIFT_CONTROL_PLANE_DSN
# =============================================================================
# Migrations are idempotent (CREATE ... IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
# Uses psycopg3 (available in the venv) with autocommit + simple-query protocol
# so multi-statement DDL files execute correctly (no parameter binding = no parse
# step that would reject semicolons).
# Guards: skips if --core-only or SIFT_CONTROL_PLANE_DSN empty.
apply_db_migrations() {
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" ]]; then
    log "apply_db_migrations: core-only — skipping."
    return 0
  fi

  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"
  if [[ -z "$cp_dsn" ]]; then
    log "apply_db_migrations: SIFT_CONTROL_PLANE_DSN not set — skipping."
    return 0
  fi

  local migrations_dir="$REPO_DIR/supabase/migrations"
  if [[ ! -d "$migrations_dir" ]]; then
    log "apply_db_migrations: no migrations directory at $migrations_dir — skipping."
    return 0
  fi

  # Collect and sort migration files by filename (lexicographic = timestamp order).
  local migration_files=()
  while IFS= read -r -d '' f; do
    migration_files+=("$f")
  done < <(find "$migrations_dir" -maxdepth 1 -name '*.sql' -print0 | sort -z)

  if [[ "${#migration_files[@]}" -eq 0 ]]; then
    log "apply_db_migrations: no .sql files found in $migrations_dir."
    return 0
  fi

  log "apply_db_migrations: applying ${#migration_files[@]} migration(s) via psycopg3."
  export SIFT_CONTROL_PLANE_DSN="$cp_dsn"
  export MIGRATIONS_DIR="$migrations_dir"

  # Pass filenames via a NUL-delimited env string.
  local files_joined
  files_joined="$(printf '%s\n' "${migration_files[@]}")"
  export MIGRATION_FILES_LIST="$files_joined"

  local result
  result=$("$VENV_DIR/bin/python" - <<'PY'
import os, sys
from pathlib import Path

dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
files_raw = os.environ.get("MIGRATION_FILES_LIST", "")
files = [f for f in files_raw.splitlines() if f.strip()]

try:
    import psycopg
except ImportError as exc:
    print(f"skip:psycopg_unavailable:{exc}", file=sys.stderr)
    sys.exit(0)

first_file = True
for fpath in files:
    p = Path(fpath)
    sql_text = p.read_text(encoding="utf-8")
    try:
        # autocommit + no params = simple-query protocol; handles multi-statement DDL.
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(sql_text)
        print(f"ok:{p.name}")
    except Exception as exc:
        short = str(exc).split('\n')[0][:120]
        duplicate_ok = "already exists" in short or "Duplicate" in type(exc).__name__
        if first_file and not duplicate_ok:
            # First/foundational migration failing likely means DB is unreachable.
            print(f"fatal:{p.name}:{short}", file=sys.stderr)
            sys.exit(1)
        print(f"warn:{p.name}:{short}", file=sys.stderr)
    first_file = False
PY
  2>&1) || {
    warn "apply_db_migrations: foundational migration failed (DB unreachable?)."
    warn "  $result"
    die "Cannot continue — DB migrations required.  Fix SIFT_CONTROL_PLANE_DSN and re-run."
  }

  # Parse results and emit per-file log/warn.
  local had_warn=0
  while IFS= read -r line; do
    case "$line" in
      ok:*)   log "  migration applied: ${line#ok:}" ;;
      warn:*) warn "  migration skipped/warned: ${line#warn:}"; had_warn=1 ;;
      skip:*) log "  $line" ;;
      *)      [[ -n "$line" ]] && log "  $line" ;;
    esac
  done <<< "$result"

  if [[ "$had_warn" -eq 1 ]]; then
    warn "apply_db_migrations: some migrations warned — schema may be partially applied."
    warn "  This is often safe (IF NOT EXISTS clauses). Verify manually if needed."
  else
    log "apply_db_migrations: all migrations applied successfully."
  fi
}

write_gateway_config() {
  # SIFT_CONFIG lives under SIFT_HOME (sift-service-owned 0700/0600), so the
  # existence check must use sudo.
  if svc_test_f "$SIFT_CONFIG"; then
    log "Gateway config exists — preserving $SIFT_CONFIG."
    CONFIG_CREATED=0
    SIFT_GATEWAY_TOKEN=""
    SIFT_SERVICE_TOKEN=""
    SIFT_PORTAL_SESSION_SECRET=""
    _migrate_gateway_config
    return
  fi
  SIFT_GATEWAY_TOKEN="sift_gw_$(random_hex 24)"
  SIFT_SERVICE_TOKEN="sift_svc_$(random_hex 24)"
  # B-MVP-010: the portal session secret is no longer rendered into gateway.yaml
  # (the template carries only session_secret_env, the env-var NAME). The VALUE is
  # owned by write_control_plane_env (control-plane.env, 0600). Keep the var empty
  # here so a stale literal can never leak into the rendered config.
  SIFT_PORTAL_SESSION_SECRET=""
  SIFT_TOKEN_CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  CONFIG_CREATED=1
  export SIFT_GATEWAY_TOKEN SIFT_SERVICE_TOKEN SIFT_PORTAL_SESSION_SECRET SIFT_TOKEN_CREATED_AT
  _render_file "$REPO_DIR/configs/gateway.yaml.template" "$SIFT_CONFIG" 0600
}

_migrate_gateway_config() {
  log "Checking gateway config compatibility."
  # SIFT_CONFIG is sift-service-owned 0600. The operator runs the (uv) migration,
  # so it reads/writes operator-owned temps and the result is installed back
  # owned sift-service. Read the live config into a temp via sudo.
  local cfg_src cfg_out
  cfg_src="$(mktemp)"
  cfg_out="$(mktemp)"
  if ! sudo_if_needed cat "$SIFT_CONFIG" > "$cfg_src" 2>/dev/null; then
    warn "_migrate_gateway_config: could not read $SIFT_CONFIG — skipping migration."
    rm -f "$cfg_src" "$cfg_out"
    return 0
  fi
  export SIFT_CONFIG_SRC="$cfg_src" SIFT_CONFIG_OUT="$cfg_out"
  export SIFT_MCPS_ROOT PYTHON_BIN OPENCTI_URL OPENCTI_TOKEN
  export SIFT_EXECUTE_AS_USER
  export SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED
  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  SIFT_RAG_ENABLED="true"
  SIFT_OPENCTI_ENABLED="${SIFT_OPENCTI_ENABLED:-false}"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"

  "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads python - <<'PY'
import os, sys
from pathlib import Path
import yaml

src = Path(os.environ["SIFT_CONFIG_SRC"])
out = Path(os.environ["SIFT_CONFIG_OUT"])
cfg = yaml.safe_load(src.read_text()) or {}
changed = False

# Normalise TLS key names
gateway = cfg.setdefault("gateway", {})
tls = gateway.get("tls")
if isinstance(tls, dict):
    if "certfile" not in tls and "cert" in tls:
        tls["certfile"] = tls.pop("cert")
        changed = True
    if "keyfile" not in tls and "key" in tls:
        tls["keyfile"] = tls.pop("key")
        changed = True

# B-MVP-010: migrate an inline portal session secret to env-indirection. The
# literal value was already copied into control-plane.env by write_control_plane_env
# (via _resolved_session_secret reading this same file), so here we just strip the
# literal and replace it with the env-var NAME. Idempotent.
portal_cfg = cfg.setdefault("portal", {})
if isinstance(portal_cfg, dict) and "session_secret" in portal_cfg:
    portal_cfg.pop("session_secret", None)
    portal_cfg["session_secret_env"] = "SIFT_PORTAL_SESSION_SECRET"
    changed = True
elif isinstance(portal_cfg, dict) and not portal_cfg.get("session_secret_env"):
    portal_cfg["session_secret_env"] = "SIFT_PORTAL_SESSION_SECRET"
    changed = True

# RAG / triage / opencti enabled flags
enrichment = cfg.setdefault("enrichment", {})
if enrichment.get("forensic_rag") is not True and os.environ.get("SIFT_RAG_ENABLED") == "true":
    enrichment["forensic_rag"] = True
    changed = True

# NOTE: the installer no longer auto-enables add-on backends. Add-ons are
# external/optional and are integrated through the portal self-service contract
# door (validate -> register -> hot-reload), which writes their backend entry.
# We only normalise args for whatever backends already exist (e.g.
# portal-registered ones) below — we never add or enable a backend here.
cfg.setdefault("backends", {})

# Native runtime user for run_command. Existing configs predate this key, so
# migrate them to the installer default instead of leaving production same-user.
execute = cfg.setdefault("execute", {})
if isinstance(execute, dict) and "runtime_user" not in execute:
    execute["runtime_user"] = os.environ.get("SIFT_EXECUTE_AS_USER") or "agent_runtime"
    changed = True

# Backend arg normalisation (ensure --python, --no-managed-python, --no-python-downloads)
root = os.environ.get("SIFT_MCPS_ROOT") or ""
python_bin = os.environ.get("PYTHON_BIN") or ""
for backend in (cfg.get("backends") or {}).values():
    if not isinstance(backend, dict):
        continue
    args = backend.get("args")
    if not isinstance(args, list) or not args or args[0] != "run":
        continue
    if "--python" in args and "--no-managed-python" in args and "--no-python-downloads" in args:
        continue
    script = args[-1]
    project = root
    if "--project" in args:
        try:
            project = args[args.index("--project") + 1]
        except IndexError:
            project = root
    backend["args"] = [
        "run", "--project", project, "--python", python_bin,
        "--no-managed-python", "--no-python-downloads", script,
    ]
    changed = True

if changed:
    with open(out, "w") as handle:
        os.chmod(out, 0o600)
        yaml.safe_dump(cfg, handle, sort_keys=False)
        handle.flush()
        os.fsync(handle.fileno())
    print("changed")
else:
    print("unchanged")
PY

  # Install the migrated config back, owned sift-service 0600, only if changed.
  if [[ -s "$cfg_out" ]]; then
    log "Gateway config migrated — installing updated $SIFT_CONFIG (owned $SIFT_GATEWAY_SERVICE_USER)."
    svc_install_file "$cfg_out" "$SIFT_CONFIG" 600
  fi
  rm -f "$cfg_src" "$cfg_out"
}

write_opensearch_config() {
  # OPENSEARCH_CONFIG (opensearch.env) points the opensearch-mcp backend at this
  # file, so it must be sift-service-readable. SIFT_HOME is sift-service-owned
  # 0700 — write to an operator temp, then install owned sift-service 0600.
  local os_config="$SIFT_HOME/opensearch.yaml"
  if svc_test_f "$os_config"; then
    log "OpenSearch client config exists — preserving $os_config."
    return
  fi
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<'YAML'
host: http://127.0.0.1:9200
user: admin
password: admin
verify_certs: false
YAML
  svc_install_file "$tmp" "$os_config" 600
  rm -f "$tmp"
}

# FM-2: write gateway env file for OpenSearch env_refs so the backend process
# receives OPENSEARCH_CONFIG and OPENSEARCH_HOST from the gateway's environment.
# Idempotent (recreate only if missing); chmod 600 to guard the config path.
# Called only when SIFT_OPENSEARCH_ENABLED=true; consumed by the gateway
# service via EnvironmentFile=-${SIFT_HOME}/opensearch.env.
write_opensearch_env() {
  [[ "${SIFT_OPENSEARCH_ENABLED:-false}" == "true" ]] || return 0
  local os_env_file="$SIFT_HOME/opensearch.env"
  if svc_test_f "$os_env_file"; then
    log "OpenSearch env file already exists — preserving $os_env_file."
    return
  fi
  log "Writing OpenSearch gateway env file: $os_env_file"
  # Operator-owned temp -> sift-service-owned 0600 (see write_supabase_env).
  local tmp
  tmp="$(mktemp)"
  {
    printf '# OpenSearch env — gateway env_refs for opensearch-mcp backend\n'
    printf '# Written by sift-mcps install.sh. Idempotent — delete to regenerate.\n'
    printf 'OPENSEARCH_CONFIG=%s/opensearch.yaml\n' "$SIFT_HOME"
    printf 'OPENSEARCH_HOST=http://127.0.0.1:9200\n'
  } > "$tmp"
  svc_install_file "$tmp" "$os_env_file" 600
  rm -f "$tmp"
}

# BATCH-PMI3: write the gateway/worker env file that points the forensic-knowledge
# loader at the installed data dir. Without FK_DATA_DIR in the service env, the
# loader cannot resolve the data dir under the service user (no source tree /
# importlib.resources data on a packaged install), so build_response and the
# run_command path silently skip FK enrichment. FK data is a core runtime dep
# (D4); prepare_enrichment_assets lays it down at
# $SIFT_ENRICHMENT_DIR/forensic-knowledge, which is the path we publish here.
# Consumed by both units via EnvironmentFile=-${SIFT_HOME}/forensic-knowledge.env.
# Idempotent (recreate only if missing). FK_DATA_DIR is a non-secret path.
write_fk_env() {
  local fk_data_dir="$SIFT_ENRICHMENT_DIR/forensic-knowledge"
  local fk_env_file="$SIFT_HOME/forensic-knowledge.env"
  if svc_test_f "$fk_env_file"; then
    log "forensic-knowledge env file already exists — preserving $fk_env_file."
    return
  fi
  log "Writing forensic-knowledge env file: $fk_env_file"
  # Non-secret path file: install owned sift-service, mode 0644. (SIFT_HOME is
  # 0700 sift-service, so only the service can traverse to it regardless.)
  local tmp
  tmp="$(mktemp)"
  {
    printf '# forensic-knowledge env — FK_DATA_DIR for the FK loader (core enrichment)\n'
    printf '# Written by sift-mcps install.sh. Idempotent — delete to regenerate.\n'
    printf 'FK_DATA_DIR=%s\n' "$fk_data_dir"
  } > "$tmp"
  svc_install_file "$tmp" "$fk_env_file" 644
  rm -f "$tmp"
}

# =============================================================================
# Phase 8 — OpenSearch (Docker)
# =============================================================================

_opensearch_api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "http://127.0.0.1:9200$path" -H "Content-Type: application/json" -d "$body" >/dev/null
  else
    curl -fsS -X "$method" "http://127.0.0.1:9200$path" >/dev/null
  fi
}

# FM-1/FM-2 (#5): OPENSEARCH_UP tracks whether OpenSearch came up healthy.
# main() reads this to gate seed_addon_backends and the post-seed restart.
OPENSEARCH_UP=0

start_opensearch() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker not found — skipping OpenSearch.  Install Docker and re-run."
    warn "  opensearch-mcp backend will NOT be seeded (set SIFT_OPENSEARCH_ENABLED=false to silence)."
    OPENSEARCH_UP=0
    return 0
  fi
  docker compose version >/dev/null 2>&1 || warn "Docker Compose v2 not available."
  if ! docker ps >/dev/null 2>&1; then
    warn "Docker daemon not reachable — attempting start."
    sudo_if_needed systemctl start docker 2>/dev/null || true
    sleep 2
  fi
  if ! docker ps >/dev/null 2>&1; then
    warn "Docker not usable — skipping OpenSearch.  opensearch-mcp backend will NOT be seeded."
    OPENSEARCH_UP=0
    return 0
  fi

  log "Starting OpenSearch."
  docker compose -f "$REPO_DIR/docker-compose.yml" up -d opensearch

  log "Waiting for OpenSearch health (up to 600 s)."
  local api_status="unknown" docker_health="unknown" attempt
  for attempt in $(seq 1 300); do
    docker_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' sift-opensearch 2>/dev/null || true)"
    api_status="$(curl -fsS --max-time 5 http://127.0.0.1:9200/_cluster/health 2>/dev/null \
      | "$SYSTEM_PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status","unknown"))' 2>/dev/null || true)"
    api_status="${api_status:-unknown}"
    docker_health="${docker_health:-unknown}"

    if [[ "$api_status" == "green" || "$api_status" == "yellow" || "$docker_health" == "healthy" ]]; then
      log "OpenSearch healthy: api=$api_status docker=$docker_health"
      OPENSEARCH_UP=1
      break
    fi
    if [[ "$attempt" -eq 1 || $(( attempt % 15 )) -eq 0 ]]; then
      log "OpenSearch wait: api=$api_status docker=$docker_health"
    fi
    sleep 2
  done
  if [[ "$OPENSEARCH_UP" -eq 0 ]]; then
    warn "OpenSearch not healthy after 600 s (last api=${api_status:-unknown}, docker=${docker_health:-unknown}) — opensearch-mcp backend will NOT be seeded."
    warn "  Check: docker logs opensearch  |  docker compose -f $REPO_DIR/docker-compose.yml ps"
  fi
}

configure_opensearch_cluster() {
  command -v docker >/dev/null 2>&1 || return 0
  curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || return 0

  log "Applying OpenSearch cluster settings."
  _opensearch_api PUT "/_cluster/settings" '{"persistent":{"cluster.max_shards_per_node":3000}}' \
    || warn "Could not raise cluster.max_shards_per_node."

  log "OpenSearch smoke test."
  _opensearch_api POST "/case-test-evtx-smoketest/_doc/test-1?refresh=true" \
    '{"event.code":4624,"@timestamp":"2024-01-01T00:00:00Z","host.name":"test"}' \
    || warn "OpenSearch smoke index failed."
  local found
  found="$(curl -fsS "http://127.0.0.1:9200/case-test-evtx-smoketest/_search?q=event.code:4624&size=1" 2>/dev/null \
    | "$SYSTEM_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["hits"]["total"]["value"])' 2>/dev/null || echo 0)"
  if [[ "$found" == "1" ]]; then
    log "OpenSearch smoke test passed."
  else
    warn "OpenSearch smoke test expected 1 hit, got $found."
  fi
  curl -fsS -X DELETE "http://127.0.0.1:9200/case-test-evtx-smoketest" >/dev/null 2>&1 || true
}

configure_geoip_pipeline() {
  # B-MVP-004 (D6): the ip2geo datasource fetches from a live, unauthenticated
  # endpoint (geoip.maps.opensearch.org). OFF by default; opt in with
  # SIFT_GEOIP_ENABLED=1. Always skipped in offline mode.
  if [[ "${SIFT_GEOIP_ENABLED:-0}" != "1" ]]; then
    log "GeoIP enrichment disabled by default (set SIFT_GEOIP_ENABLED=1 to enable). Skipping ip2geo datasource."
    return 0
  fi
  if is_offline; then
    warn "SIFT_OFFLINE=1: skipping GeoIP datasource (it fetches from a live endpoint). Stage a local GeoLite2 datasource if needed."
    return 0
  fi
  curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || return 0
  log "Configuring GeoIP enrichment (SIFT_GEOIP_ENABLED=1)."

  curl -fsS -X PUT "http://127.0.0.1:9200/_plugins/geospatial/ip2geo/datasource/maxmind-city" \
    -H "Content-Type: application/json" \
    -d '{"endpoint":"https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json","update_interval_in_days":3}' \
    >/dev/null 2>&1 || warn "GeoIP datasource skipped."

  _opensearch_api PUT "/_ingest/pipeline/sift-geoip" '{
    "description": "GeoIP enrichment for source.ip",
    "processors": [{
      "ip2geo": {
        "field": "source.ip",
        "datasource": "maxmind-city",
        "target_field": "source.geo",
        "ignore_missing": true,
        "on_failure": [{
          "set": {
            "field": "source.geo.error",
            "value": "GeoIP lookup failed: {{_ingest.on_failure_message}}"
          }
        }]
      }
    }]
  }' || warn "GeoIP ingest pipeline not created."

  local pattern
  for pattern in "case-*-evtx-*" "case-*-iis-*" "case-*-httperr-*" "case-*-firewall-*" "case-*-ssh-*" "case-*-accesslog-*"; do
    _opensearch_api PUT "/$pattern/_settings" '{"index.default_pipeline":"sift-geoip"}' 2>/dev/null || true
  done
}

# PMI1: Security-Analytics hygiene for OpenSearch 3.5.
# The 3.5 Security-Analytics percolator has a field-alias regression
# (opensearch-project/security-analytics#755) that makes Sigma detectors emit
# 0 findings, so detection is handled by Hayabusa during evtx ingest instead.
# This function keeps Sigma detectors DISABLED and removes any dead detectors /
# orphaned monitors so a fresh install does not accumulate non-functional state,
# then seeds the Sigma alias names so templates can auto-attach them.
# Talks to OpenSearch over plain http on loopback with NO auth (security plugin
# is disabled; :9200 is bound to 127.0.0.1 — the loopback isolation boundary).
# Best-effort: never fails the install. Run AFTER install_opensearch_templates
# so the alias-bearing templates exist.
configure_opensearch_detections() {
  curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || return 0
  log "Configuring OpenSearch Security Analytics (Sigma detectors disabled — 3.5 regression; detection via Hayabusa)."
  "$SYSTEM_PYTHON" - <<'PY' || warn "Security Analytics hygiene skipped (plugin may be unavailable)."
import json, sys, time, urllib.request, urllib.error
from collections import Counter

URL = "http://127.0.0.1:9200"
HEADERS = {"Content-Type": "application/json"}


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# Step 1: see whether pre-packaged Sigma rules have loaded (for logging only).
hits = []
for attempt in range(6):
    try:
        resp = api("POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=true",
                   {"query": {"match_all": {}}, "size": 5000})
        hits = resp.get("hits", {}).get("hits", [])
        if hits:
            break
        if attempt < 5:
            time.sleep(10)
    except Exception as exc:  # noqa: BLE001
        if attempt < 5:
            time.sleep(10)
        else:
            print(f"  Security Analytics rules API not ready: {exc}")
            sys.exit(0)

cat_counts = Counter(h.get("_source", {}).get("category", "") for h in hits)
print(f"  Sigma detectors: disabled (OpenSearch 3.5 field alias regression)")
print(f"  Available rules: {len(hits)} ({cat_counts.get('windows', 0)} Windows)")
print(f"  Detection via Hayabusa during evtx ingest (if installed)")

# Step 2: seed indices so templates auto-attach the Sigma aliases (3.x needs an
# alias to be backed by at least one index).
_SEEDS = {
    "case-seed-evtx-init": "sift-sigma-windows",
    "case-seed-ssh-init": "sift-sigma-linux",
    "case-seed-accesslog-init": "sift-sigma-web",
    "case-seed-json-init": "sift-sigma-network",
}
for seed_idx in _SEEDS:
    try:
        api("PUT", f"/{seed_idx}", {"settings": {"number_of_replicas": 0}})
    except Exception:  # noqa: BLE001
        pass  # already exists or template not registered yet

# Step 3: delete any existing sift- detectors (they produce 0 findings on 3.5).
try:
    existing = api("POST", "/_plugins/_security_analytics/detectors/_search",
                   {"query": {"match_all": {}}, "size": 100})
    for hit in existing.get("hits", {}).get("hits", []):
        name = hit.get("_source", {}).get("name", "")
        if name.startswith("sift-"):
            try:
                api("DELETE", f"/_plugins/_security_analytics/detectors/{hit['_id']}")
                print(f"  Removed non-functional detector: {name}")
            except Exception:  # noqa: BLE001
                pass
except Exception:  # noqa: BLE001
    pass

# Step 4: clean up orphaned monitors from pre-3.5 detector attempts.
try:
    monitors = api("GET", "/_plugins/_alerting/monitors/_search",
                   {"query": {"match_all": {}}, "size": 50})
    for hit in monitors.get("hits", {}).get("hits", []):
        name = hit.get("_source", {}).get("name", "")
        if name.startswith("sift-") or name.startswith("sigma_"):
            try:
                api("DELETE", f"/_plugins/_alerting/monitors/{hit['_id']}")
                print(f"  Removed orphaned monitor: {name}")
            except Exception:  # noqa: BLE001
                pass
except Exception:  # noqa: BLE001
    pass  # alerting plugin may not be installed

# Step 5: attach Sigma aliases to any existing matching indices (idempotent).
_ALIAS_PATTERNS = {
    "sift-sigma-windows": "case-*-evtx-*",
    "sift-sigma-linux": "case-*-ssh-*",
    "sift-sigma-web": "case-*-accesslog-*",
    "sift-sigma-network": "case-*-json-*",
}
for alias, pattern in _ALIAS_PATTERNS.items():
    try:
        api("POST", "/_aliases", {"actions": [{"add": {"index": pattern, "alias": alias}}]})
    except Exception:  # noqa: BLE001
        pass  # no matching indices yet — aliases auto-attach via templates
PY
}

install_opensearch_templates() {
  curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || return 0
  log "Installing OpenSearch templates and pipelines."
  local tmp_config rc
  tmp_config="$(mktemp)"
  if svc_test_f "$SIFT_HOME/opensearch.yaml"; then
    svc_read "$SIFT_HOME/opensearch.yaml" > "$tmp_config"
  else
    cat > "$tmp_config" <<'YAML'
host: http://127.0.0.1:9200
user: admin
password: admin
verify_certs: false
YAML
  fi
  OPENSEARCH_CONFIG="$tmp_config" OPENSEARCH_HOST="http://127.0.0.1:9200" \
    "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads python - <<'PY'
from opensearch_mcp.client import get_client
from opensearch_mcp.mappings import ensure_winlog_pipeline

client = get_client()
result = ensure_winlog_pipeline(client)
if result.get("status") not in {"ok", "warning"}:
    raise SystemExit(result)
print(result.get("status", "ok"))
PY
  rc=$?
  rm -f "$tmp_config"
  if [[ "$rc" -ne 0 ]]; then
    warn "OpenSearch template bootstrap failed — opensearch-mcp retries at startup."
  fi
}

# =============================================================================
# Phase 9 — Optional OpenCTI add-on helpers
# =============================================================================

prepare_opencti_secrets() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  # OpenCTI secret/id files live under SIFT_HOME (sift-service-owned 0700). Read
  # them via sudo and (re)create them owned sift-service. _svc_write_secret_line
  # writes a single value to an operator temp and installs it owned sift-service.
  local tmp
  if [[ -z "${OPENCTI_TOKEN:-}" ]]; then
    if svc_test_f "$SIFT_HOME/opencti-token"; then
      OPENCTI_TOKEN="$(svc_read "$SIFT_HOME/opencti-token")"
      log "OpenCTI admin token already exists."
    else
      OPENCTI_TOKEN=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
      tmp="$(mktemp)"; printf '%s\n' "$OPENCTI_TOKEN" > "$tmp"
      svc_install_file "$tmp" "$SIFT_HOME/opencti-token" 600; rm -f "$tmp"
      log "OpenCTI admin token saved."
    fi
  fi

  if svc_test_f "$SIFT_HOME/opencti-encryption-key"; then
    OPENCTI_ENCRYPTION_KEY="$(svc_read "$SIFT_HOME/opencti-encryption-key")"
  else
    OPENCTI_ENCRYPTION_KEY="$(openssl rand -base64 32)"
    tmp="$(mktemp)"; printf '%s\n' "$OPENCTI_ENCRYPTION_KEY" > "$tmp"
    svc_install_file "$tmp" "$SIFT_HOME/opencti-encryption-key" 600; rm -f "$tmp"
  fi

  if svc_test_f "$SIFT_HOME/opencti-health-key"; then
    OPENCTI_HEALTH_ACCESS_KEY="$(svc_read "$SIFT_HOME/opencti-health-key")"
  else
    OPENCTI_HEALTH_ACCESS_KEY=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    tmp="$(mktemp)"; printf '%s\n' "$OPENCTI_HEALTH_ACCESS_KEY" > "$tmp"
    svc_install_file "$tmp" "$SIFT_HOME/opencti-health-key" 600; rm -f "$tmp"
  fi

  export OPENCTI_TOKEN OPENCTI_ENCRYPTION_KEY OPENCTI_HEALTH_ACCESS_KEY
  export OPENCTI_URL="http://127.0.0.1:8080"
}

install_opencti() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  prepare_opencti_secrets
  log "Deploying OpenCTI stack."
  OPENCTI_ADMIN_TOKEN="$OPENCTI_TOKEN" \
  OPENCTI_ENCRYPTION_KEY="$OPENCTI_ENCRYPTION_KEY" \
  OPENCTI_HEALTH_ACCESS_KEY="$OPENCTI_HEALTH_ACCESS_KEY" \
    docker compose -f "$REPO_DIR/docker-compose.opencti.yml" up -d

  log "Waiting for OpenCTI (up to 5 min)..."
  local deadline=$(( $(date +%s) + 300 ))
  until curl -sf "http://127.0.0.1:8080/health?health_access_key=$OPENCTI_HEALTH_ACCESS_KEY" >/dev/null 2>&1; do
    [[ $(date +%s) -lt $deadline ]] || { warn "OpenCTI not healthy within 5 min."; return; }
    sleep 10
  done
  log "OpenCTI ready at http://127.0.0.1:8080"
}

install_opencti_feeds() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  # Connector id files under SIFT_HOME (sift-service-owned 0700): read via sudo,
  # (re)create owned sift-service.
  local id_file tmp
  id_file="$SIFT_HOME/opencti-connector-mitre-id"
  if svc_test_f "$id_file"; then
    OPENCTI_CONNECTOR_MITRE_ID="$(svc_read "$id_file")"
  else
    OPENCTI_CONNECTOR_MITRE_ID=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    tmp="$(mktemp)"; printf '%s\n' "$OPENCTI_CONNECTOR_MITRE_ID" > "$tmp"
    svc_install_file "$tmp" "$id_file" 600; rm -f "$tmp"
  fi

  id_file="$SIFT_HOME/opencti-connector-cisa-kev-id"
  if svc_test_f "$id_file"; then
    OPENCTI_CONNECTOR_CISA_KEV_ID="$(svc_read "$id_file")"
  else
    OPENCTI_CONNECTOR_CISA_KEV_ID=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    tmp="$(mktemp)"; printf '%s\n' "$OPENCTI_CONNECTOR_CISA_KEV_ID" > "$tmp"
    svc_install_file "$tmp" "$id_file" 600; rm -f "$tmp"
  fi

  export OPENCTI_CONNECTOR_MITRE_ID OPENCTI_CONNECTOR_CISA_KEV_ID
  log "Deploying OpenCTI feed connectors (MITRE ATT&CK + CISA KEV)."
  OPENCTI_ADMIN_TOKEN="$OPENCTI_TOKEN" \
  OPENCTI_CONNECTOR_MITRE_ID="$OPENCTI_CONNECTOR_MITRE_ID" \
  OPENCTI_CONNECTOR_CISA_KEV_ID="$OPENCTI_CONNECTOR_CISA_KEV_ID" \
    docker compose -f "$REPO_DIR/docker-compose.opencti-connectors.yml" up -d
}

# =============================================================================
# Phase 10 — systemd service
# =============================================================================

install_systemd_service() {
  # SYSTEM (not --user) services: the gateway + durable worker run as the
  # dedicated non-admin user sift-service via [Service] User=/Group=. Unit files
  # are root-owned 0644 in /etc/systemd/system; the operator installs them via
  # sudo. SIFT_VOL_SYMBOLS (shared symbol cache) and SIFT_HOME (absolute, used in
  # the units' EnvironmentFile lines instead of %h) are rendered into both units.
  SIFT_GATEWAY_TOKEN=""
  SIFT_SERVICE_TOKEN=""
  SIFT_PORTAL_SESSION_SECRET=""
  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  SIFT_EXAMINER="$SIFT_EXAMINER"
  export SIFT_MCPS_ROOT UV_BIN PYTHON_BIN SIFT_CONFIG SIFT_EXAMINER
  export SIFT_GATEWAY_SERVICE_USER SIFT_VOL_SYMBOLS

  [[ -x "$VENV_DIR/bin/sift-gateway" ]] || die "Missing gateway entrypoint: $VENV_DIR/bin/sift-gateway. Run install workspace sync first."
  [[ -x "$VENV_DIR/bin/sift-job-worker" ]] || warn "Missing durable job worker entrypoint: $VENV_DIR/bin/sift-job-worker."

  if sudo_if_needed test -f "$GATEWAY_SERVICE_FILE"; then
    log "Updating systemd system service $GATEWAY_SERVICE_FILE."
  else
    log "Writing systemd system service $GATEWAY_SERVICE_FILE."
  fi
  _render_file "$REPO_DIR/configs/systemd/sift-gateway.service" "$GATEWAY_SERVICE_FILE" 0644 root
  if sudo_if_needed test -f "$JOB_WORKER_SERVICE_FILE"; then
    log "Updating systemd system service $JOB_WORKER_SERVICE_FILE."
  else
    log "Writing systemd system service $JOB_WORKER_SERVICE_FILE."
  fi
  _render_file "$REPO_DIR/configs/systemd/sift-job-worker.service" "$JOB_WORKER_SERVICE_FILE" 0644 root

  # feat/opensearch-workers: dedicated OpenSearch ingest/enrich worker template.
  # Only when OpenSearch is enabled — the FUSE-mount ingest pipeline runs here
  # (the only unit with MountFlags=shared), NOT in the hardened gateway/job-worker.
  local _os_worker_instances=()
  if [[ "${SIFT_OPENSEARCH_ENABLED:-true}" == "true" ]]; then
    if [[ -x "$VENV_DIR/bin/sift-opensearch-worker" ]]; then
      _render_file "$REPO_DIR/configs/systemd/sift-opensearch-worker@.service" \
        "$OPENSEARCH_WORKER_SERVICE_FILE" 0644 root
      local _n="${SIFT_OPENSEARCH_WORKERS:-2}"
      [[ "$_n" =~ ^[0-9]+$ && "$_n" -ge 1 ]] || _n=2
      local _i
      for _i in $(seq 1 "$_n"); do
        _os_worker_instances+=("sift-opensearch-worker@${_i}.service")
      done
      log "OpenSearch ingest/enrich workers: ${_n} instance(s) (override with SIFT_OPENSEARCH_WORKERS)."
    else
      warn "Missing OpenSearch worker entrypoint: $VENV_DIR/bin/sift-opensearch-worker (ingest will not run decoupled)."
    fi
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found — service file written but not started."
    return
  fi
  sudo_if_needed systemctl daemon-reload
  sudo_if_needed systemctl enable sift-gateway.service sift-job-worker.service
  sudo_if_needed systemctl restart sift-gateway.service sift-job-worker.service
  if [[ ${#_os_worker_instances[@]} -gt 0 ]]; then
    sudo_if_needed systemctl enable "${_os_worker_instances[@]}"
    sudo_if_needed systemctl restart "${_os_worker_instances[@]}"
  fi
}

# =============================================================================
# Phase 11 — validation
# =============================================================================

poll_gateway() {
  local label="${1:-initial}"
  log "Waiting for gateway health (up to 30 s) [${label}]."
  local body=""
  for _ in $(seq 1 30); do
    body="$(curl -kfsS https://127.0.0.1:4508/health 2>/dev/null || true)"
    if [[ -n "$body" ]]; then
      break
    fi
    sleep 1
  done
  if [[ -z "$body" ]]; then
    warn "Gateway not reachable.  Check: sudo journalctl -u sift-gateway -n 50"
    return
  fi

  # Parse JSON body: verify status=ok and surface any degraded subsystems.
  local gw_status supabase_status
  gw_status="$("$SYSTEM_PYTHON" -c \
    'import json,sys; d=json.loads(sys.argv[1]); print(d.get("status","unknown"))' \
    "$body" 2>/dev/null || echo "parse_error")"
  supabase_status="$("$SYSTEM_PYTHON" -c \
    'import json,sys; d=json.loads(sys.argv[1]); print((d.get("supabase") or d.get("db") or {}).get("status","unknown"))' \
    "$body" 2>/dev/null || echo "unknown")"

  if [[ "$gw_status" == "ok" ]]; then
    log "Gateway health OK [${label}]: status=$gw_status supabase=$supabase_status"
  elif [[ "$gw_status" == "degraded" ]]; then
    warn "Gateway is DEGRADED [${label}].  Full health body:"
    warn "  $body"
    # Surface the specific failing subsystem if we can parse it.
    local reason
    reason="$("$SYSTEM_PYTHON" -c \
      'import json,sys; d=json.loads(sys.argv[1]); print(d.get("reason") or d.get("error") or "")' \
      "$body" 2>/dev/null || true)"
    [[ -n "$reason" ]] && warn "  Reason: $reason"
    if [[ "${SIFT_CORE_ONLY:-0}" != "1" && "$supabase_status" != "ok" && "$supabase_status" != "unknown" ]]; then
      warn "  Supabase connection is not OK ($supabase_status)."
      warn "  Verify SUPABASE_URL/ANON_KEY/SERVICE_ROLE_KEY are set and the Supabase project is reachable."
    fi
  else
    warn "Gateway returned unexpected status '$gw_status' [${label}] — body: $body"
  fi
}

# =============================================================================
# Phase 12 — handoff
# =============================================================================

write_handoff() {
  local existing_temp_password existing_gateway_token existing_service_token
  local existing_sb_email existing_sb_pw
  local expected_sb_email
  existing_temp_password=""
  existing_gateway_token=""
  existing_service_token=""
  existing_sb_email=""
  existing_sb_pw=""
  expected_sb_email="${SIFT_EXAMINER}@operators.sift.local"
  # MATERIALS_FILE lives in SIFT_TOKENS_DIR (sift-service-owned 0700). Read prior
  # values via sudo; the file is (re)written below into an operator temp and
  # installed owned sift-service 0600. The operator reads it post-install with
  # `sudo cat "$MATERIALS_FILE"` (print_summary points here).
  if svc_test_f "$MATERIALS_FILE"; then
    local _mat
    _mat="$(svc_read "$MATERIALS_FILE")"
    existing_temp_password="$(printf '%s\n' "$_mat" | awk -F= '$1=="temporary_examiner_password"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_gateway_token="$(printf '%s\n' "$_mat" | awk -F= '$1=="examiner_fallback_token"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_service_token="$(printf '%s\n' "$_mat" | awk -F= '$1=="hermes_service_token"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_sb_email="$(printf '%s\n' "$_mat" | awk -F= '$1=="supabase_operator_email"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_sb_pw="$(printf '%s\n' "$_mat" | awk -F= '$1=="supabase_operator_temp_password"{sub(/^[^=]*=/,""); print; exit}' || true)"
  fi
  local _handoff_tmp
  _handoff_tmp="$(mktemp)"
  umask 077
  {
    printf 'sift-mcps installer handoff\n'
    printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'portal_url=https://%s:4508/portal/\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'gateway_mcp_url=https://%s:4508/mcp\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'ca_cert=%s/ca-cert.pem\n' "$SIFT_TLS_DIR"
    printf 'tls_profile=internal-local-ca\n'
    # Client trust steps (no private key material is ever written here). The CA
    # cert is public; copy it to the client and import it once. Renewal of the
    # gateway LEAF keeps this same CA, so clients do NOT re-import on renewal.
    printf 'tls_trust_copy=sudo cp %s/ca-cert.pem /tmp/sift-ca.pem  # then scp to client\n' "$SIFT_TLS_DIR"
    printf 'tls_trust_browser=import /tmp/sift-ca.pem as a trusted Authority (Firefox: Settings>Certificates>Authorities>Import; Chrome: Settings>Privacy>Security>Manage certificates>Authorities>Import)\n'
    printf 'tls_trust_python=export REQUESTS_CA_BUNDLE=/path/to/sift-ca.pem SSL_CERT_FILE=/path/to/sift-ca.pem  # MCP/Python clients\n'
    printf 'tls_trust_curl=curl --cacert /path/to/sift-ca.pem https://%s:4508/health\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'tls_renewal=sudo ./scripts/rotate-tls.sh --renew-leaf   # renews leaf, keeps CA (no client re-trust); see maintenance-guide §11\n'
    printf 'gateway_config=%s\n' "$SIFT_CONFIG"
    printf 'examiner=%s\n' "$SIFT_EXAMINER"
    printf 'expected_supabase_operator_email=%s\n' "$expected_sb_email"
    # A1-BOOTSTRAP: Supabase-first operator credentials (forced-reset on first login).
    if [[ "${SUPABASE_OPERATOR_CREATED:-0}" -eq 1 ]]; then
      printf 'supabase_operator_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'portal_login_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'supabase_operator_temp_password=%s\n' "${SUPABASE_OPERATOR_TEMP_PASSWORD:-}"
      printf 'supabase_auth=enabled\n'
      printf 'supabase_forced_reset=required_on_first_login\n'
    elif [[ -n "$existing_sb_email" ]]; then
      printf 'supabase_operator_email=%s\n' "$existing_sb_email"
      printf 'portal_login_email=%s\n' "$existing_sb_email"
      if [[ -n "$existing_sb_pw" ]]; then
        printf 'supabase_operator_temp_password=%s\n' "$existing_sb_pw"
      else
        printf 'supabase_operator_temp_password=already-reset\n'
      fi
      printf 'supabase_auth=enabled\n'
      printf 'supabase_forced_reset=check_if_completed\n'
    elif [[ "${SUPABASE_OPERATOR_MAPPED:-0}" -eq 1 ]]; then
      printf 'supabase_operator_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'portal_login_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'supabase_operator_temp_password=existing-supabase-user\n'
      printf 'supabase_auth=enabled\n'
      printf 'supabase_forced_reset=check_if_completed\n'
    else
      printf 'supabase_auth=not_bootstrapped\n'
      printf 'portal_login_email=unavailable_until_supabase_bootstrap_succeeds\n'
    fi
    # Legacy local PBKDF2 examiner password (fallback when Supabase is not configured).
    if [[ "${TEMP_PASSWORD_CREATED:-0}" -eq 1 ]]; then
      printf 'temporary_examiner_password=%s\n' "$TEMP_PASSWORD"
    elif [[ -n "$existing_temp_password" && "$existing_temp_password" != "existing-password-preserved" ]]; then
      printf 'temporary_examiner_password=%s\n' "$existing_temp_password"
    else
      printf 'temporary_examiner_password=existing-password-preserved\n'
    fi
    if [[ "${CONFIG_CREATED:-0}" -eq 1 ]]; then
      printf 'examiner_fallback_token=%s\n' "$SIFT_GATEWAY_TOKEN"
      printf 'hermes_service_token=%s\n' "$SIFT_SERVICE_TOKEN"
    elif [[ -n "$existing_gateway_token" || -n "$existing_service_token" ]]; then
      [[ -n "$existing_gateway_token" ]] && printf 'examiner_fallback_token=%s\n' "$existing_gateway_token"
      [[ -n "$existing_service_token" ]] && printf 'hermes_service_token=%s\n' "$existing_service_token"
    else
      printf 'tokens=existing-gateway-config-preserved\n'
    fi
    # Supabase provisioning mode (auto vs external vs missing).
    if [[ "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
      printf 'supabase_provision_mode=external\n'
    elif [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
      printf 'supabase_provision_mode=auto_provisioned\n'
      printf 'supabase_project_env=%s\n' "$SUPABASE_PROJECT_ENV"
    else
      printf 'supabase_provision_mode=not_provisioned\n'
    fi
    # Migration apply result.
    printf 'db_migrations_applied=%s\n' "${DB_MIGRATIONS_RESULT:-skipped}"
    # OpenSearch backend seeding status.
    printf 'opensearch_backend_seeded=%s\n' "${OPENSEARCH_SEEDED:-false}"
    printf 'opensearch_available=%s\n' "${OPENSEARCH_UP:-0}"
    # System services (User=sift-service) — start at boot via multi-user.target.
    printf 'service_scope=system\n'
    printf 'service_user=%s\n' "$SIFT_GATEWAY_SERVICE_USER"
  } > "$_handoff_tmp"
  svc_install_file "$_handoff_tmp" "$MATERIALS_FILE" 600
  rm -f "$_handoff_tmp"
  # A1-BOOTSTRAP: clear the temp password from env now that it's in the handoff file.
  unset SUPABASE_OPERATOR_TEMP_PASSWORD
}

# =============================================================================
# Phase 13 — OS hardening (best-effort)
# =============================================================================

configure_immutable_capability() {
  [[ -x "$VENV_PYTHON" ]] || return 0
  if ! command -v setcap &>/dev/null; then
    warn "setcap not found — skipping CAP_LINUX_IMMUTABLE."
    return 0
  fi
  local cap_target
  cap_target="$(readlink -f "$VENV_PYTHON" 2>/dev/null || printf '%s' "$VENV_PYTHON")"
  if sudo_if_needed setcap cap_linux_immutable+ep "$cap_target" 2>/dev/null; then
    if command -v getcap &>/dev/null && getcap "$cap_target" 2>/dev/null | grep -q 'cap_linux_immutable'; then
      log "setcap cap_linux_immutable+ep verified on $cap_target."
    else
      warn "setcap returned success but CAP_LINUX_IMMUTABLE is not visible on $cap_target."
    fi
  else
    warn "Could not apply CAP_LINUX_IMMUTABLE to $cap_target; evidence immutable flags will remain best-effort until Phase 3.4."
  fi
}

configure_auditd() {
  # B-MVP-014: HR2 found auditd ABSENT at runtime on the live VM (package not
  # installed, /etc/audit/rules.d missing), so the shipped rules were never
  # loaded. Install + enable the daemon, then load a persistent forensic ruleset.
  local rules_src="${REPO_DIR}/configs/audit/99-sift-evidence.rules"
  [[ -f "$rules_src" ]] || return 0

  if ! command -v auditctl &>/dev/null; then
    if is_offline; then
      warn "SIFT_OFFLINE=1: auditd not installed and cannot be fetched. Pre-install the 'auditd' package, then re-run."
      return 0
    fi
    log "auditd not installed — installing the auditd package."
    if ! apt_install_packages auditd audispd-plugins; then
      warn "Could not install auditd — kernel-level evidence/secret auditing will be unavailable."
      return 0
    fi
  fi

  # rules.d is the persistent, boot-loaded location. Create it if the fresh
  # package layout has not yet (auditd creates it, but be defensive).
  sudo_if_needed install -d -m 750 /etc/audit/rules.d 2>/dev/null || true

  local rules_dst="/etc/audit/rules.d/99-sift-evidence.rules"
  local tmp
  tmp="$(mktemp)"
  sed -e "s|CASES_ROOT|${SIFT_CASE_ROOT}|g" \
      -e "s|SIFT_HOME|${SIFT_HOME}|g" \
      -e "s|INSTALL_ROOT|${SIFT_MCPS_INSTALL_ROOT}|g" \
      "$rules_src" > "$tmp"
  sudo_if_needed cp "$tmp" "$rules_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 640 "$rules_dst"

  # Enable + start the daemon so rules survive reboot (persistent via rules.d).
  if command -v systemctl &>/dev/null; then
    sudo_if_needed systemctl enable auditd.service 2>/dev/null || true
    sudo_if_needed systemctl restart auditd.service 2>/dev/null \
      || sudo_if_needed systemctl start auditd.service 2>/dev/null || true
  fi

  # Load the rules now (augenrules compiles rules.d into the running kernel set).
  if command -v augenrules &>/dev/null; then
    sudo_if_needed augenrules --load 2>/dev/null || warn "augenrules --load reported an issue; rules will load on next boot."
  elif command -v auditctl &>/dev/null; then
    sudo_if_needed auditctl -R "$rules_dst" 2>/dev/null || true
  fi

  if command -v auditctl &>/dev/null && sudo_if_needed auditctl -l 2>/dev/null | grep -q 'sift_evidence_write'; then
    log "auditd active with SIFT forensic rules loaded."
  else
    warn "auditd rules installed to $rules_dst but not confirmed live; verify with: sudo auditctl -l | grep sift_"
  fi
}

configure_apparmor() {
  if ! command -v aa-status &>/dev/null; then
    warn "AppArmor not found — skipping profile."
    return 0
  fi
  [[ -x "$VENV_PYTHON" ]] || return 0
  local profile_src="${REPO_DIR}/configs/apparmor/sift-gateway.template"
  local profile_dst="/etc/apparmor.d/sift-gateway"
  local tmp
  tmp="$(mktemp)"
  sed "s|@@PYTHON_BIN@@|${VENV_PYTHON}|g" "$profile_src" > "$tmp"
  sudo_if_needed cp "$tmp" "$profile_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 644 "$profile_dst"
  sudo_if_needed apparmor_parser -C -r "$profile_dst" 2>/dev/null || true
  log "AppArmor profile installed (complain mode)."
}

# =============================================================================
# Phase 14 — summary
# =============================================================================

print_summary() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$ip" ]] || ip="SIFT_VM"
  log "Install complete."
  printf '\n'
  printf 'Portal:       https://%s:4508/portal/\n' "$ip"
  printf 'MCP endpoint: https://%s:4508/mcp\n' "$ip"
  printf 'CA cert:      %s/ca-cert.pem\n' "$SIFT_TLS_DIR"
  printf 'Config:       %s\n' "$SIFT_CONFIG"
  printf 'Secrets:      %s   (read with: sudo cat)\n' "$MATERIALS_FILE"
  printf 'Evidence root: %s\n' "$SIFT_CASES_ROOT"
  printf '\n'

  # Supabase provisioning mode.
  if [[ "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    printf 'Supabase:     external (credentials supplied by operator)\n'
  elif [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
    printf 'Supabase:     auto-provisioned via scripts/setup-supabase.sh\n'
    printf '              credentials: %s\n' "$SUPABASE_PROJECT_ENV"
  elif [[ "${SIFT_CORE_ONLY:-0}" == "1" ]]; then
    printf 'Supabase:     skipped (core-only install)\n'
  else
    printf 'Supabase:     NOT provisioned — re-run install.sh after running scripts/setup-supabase.sh\n'
  fi

  # DB migration result.
  printf 'DB migrations: %s\n' "${DB_MIGRATIONS_RESULT:-skipped}"

  # OpenSearch backend.
  if [[ "${SIFT_CORE_ONLY:-0}" != "1" ]]; then
    if [[ "${OPENSEARCH_SEEDED:-false}" == "true" ]]; then
      printf 'OpenSearch:   backend seeded and registered in app.mcp_backends\n'
    elif [[ "${OPENSEARCH_UP:-0}" -eq 1 ]]; then
      printf 'OpenSearch:   running but backend seed was skipped\n'
    else
      printf 'OpenSearch:   not available (Docker absent or unhealthy)\n'
    fi
  fi

  # Service scope.
  printf 'Services:     system (run as %s; start at boot via multi-user.target)\n' "$SIFT_GATEWAY_SERVICE_USER"

  printf '\n'
  printf 'Next steps:\n'
  # A1-BOOTSTRAP: Supabase-first login instructions when provisioned.
  if [[ "${SUPABASE_OPERATOR_CREATED:-0}" -eq 1 ]]; then
    printf '  1. Sign into the portal with:\n'
    printf '       email:    %s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
    printf '       password: (see %s -> supabase_operator_temp_password)\n' "$MATERIALS_FILE"
    printf '     You will be FORCED to reset this password on first login.\n'
    printf '  2. After reset, create a case and activate it with your new password.\n'
    printf '  3. Mount or copy evidence into the active case evidence directory.\n'
    printf '  4. Generate an AI agent credential from Portal -> Agents.\n'
  elif [[ "${SUPABASE_OPERATOR_MAPPED:-0}" -eq 1 ]]; then
    printf '  1. Sign into the portal with your existing Supabase operator account:\n'
    printf '       email:    %s\n' "${SUPABASE_OPERATOR_EMAIL:-${SIFT_EXAMINER}@operators.sift.local}"
    printf '       password: existing Supabase password\n'
    printf '  2. Create a case and activate it with password re-auth.\n'
    printf '  3. Mount or copy evidence into the active case evidence directory.\n'
    printf '  4. Generate an AI agent credential from Portal -> Agents.\n'
  else
    printf '  1. Supabase operator bootstrap did not complete, so portal login is not ready.\n'
    printf '     Expected operator email after a successful bootstrap: %s@operators.sift.local\n' "$SIFT_EXAMINER"
    printf '     Check gateway/Supabase health and re-run ./install.sh.\n'
    printf '  2. After bootstrap, use %s -> portal_login_email and supabase_operator_temp_password.\n' "$MATERIALS_FILE"
  fi
  printf '  5. Trust the local CA on the analyst machine (do this ONCE):\n'
  printf '       copy   %s/ca-cert.pem to the client\n' "$SIFT_TLS_DIR"
  printf '       browser: import it as a trusted Authority (Firefox/Chrome)\n'
  printf '       python : export REQUESTS_CA_BUNDLE=<ca-cert.pem> SSL_CERT_FILE=<ca-cert.pem>\n'
  printf '       curl   : curl --cacert <ca-cert.pem> https://%s:4508/health\n' "$ip"
  printf '     Leaf renewal (sudo ./scripts/rotate-tls.sh --renew-leaf) keeps this CA, so no re-trust.\n'
  printf '  6. Add-on backends are OPTIONAL and external. To integrate one, prepare it with\n'
  printf '     scripts/setup-addon.sh, then register it from Portal -> Backends\n'
  printf '     (validate -> register -> hot-reload). The core ships with none enabled.\n'
}

# =============================================================================
# Uninstall — reverse what install.sh provisioned
# =============================================================================
#
#   ./install.sh --uninstall                # remove the software install only
#   ./install.sh --uninstall --purge-data   # ALSO wipe forensic/state data
#
# Two tiers, on purpose:
#   * Base uninstall removes install *artifacts* — the systemd service, the venv,
#     ~/.sift (config, TLS, secrets, hayabusa), the system-hardening configs
#     (auditd rules, AppArmor profile), the hayabusa symlink, and any docker
#     containers (without touching their volumes). This is safe and reversible
#     by re-running install.sh.
#   * --purge-data additionally destroys DATA that install.sh seeded but that the
#     investigation owns: /var/lib/sift (integrity records, tokens, passwords,
#     snapshots) + /cases (EVIDENCE) + docker volumes (indexed evidence). This is
#     irreversible, so it requires a typed "yes" unless -y/--yes is given.

_confirm_destructive() {
  # $1 = prompt. Honors ASSUME_YES. Dies on anything but a typed "yes".
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    log "Assuming yes (-y): $1"
    return 0
  fi
  local reply=""
  printf '[sift-mcps] %s\n' "$1" >&2
  printf '[sift-mcps] Type "yes" to proceed: ' >&2
  read -r reply 2>/dev/null || reply=""
  [[ "$reply" == "yes" ]] || die "Aborted — nothing was purged."
}

uninstall_systemd() {
  # System (not --user) services now: stop/disable/remove via sudo.
  if command -v systemctl >/dev/null 2>&1; then
    sudo_if_needed systemctl stop sift-gateway.service sift-job-worker.service 2>/dev/null || true
    sudo_if_needed systemctl disable sift-gateway.service sift-job-worker.service 2>/dev/null || true
  fi
  local removed=0
  for service_file in "$GATEWAY_SERVICE_FILE" "$JOB_WORKER_SERVICE_FILE"; do
    if sudo_if_needed test -f "$service_file"; then
      sudo_if_needed rm -f "$service_file"
      removed=1
      log "Removed systemd system service ($service_file)."
    fi
  done
  command -v systemctl >/dev/null 2>&1 && sudo_if_needed systemctl daemon-reload 2>/dev/null || true
  [[ "$removed" -eq 1 ]] || log "No systemd system services to remove."
}

uninstall_docker_stacks() {
  command -v docker >/dev/null 2>&1 || return 0
  docker compose version >/dev/null 2>&1 || return 0
  local down_args=(down)
  if [[ "${PURGE_DATA:-0}" == "1" ]]; then
    down_args=(down -v)   # -v removes named volumes (indexed evidence)
  fi
  local compose
  for compose in docker-compose.yml docker-compose.opencti.yml docker-compose.opencti-connectors.yml; do
    [[ -f "$REPO_DIR/$compose" ]] || continue
    docker compose -f "$REPO_DIR/$compose" "${down_args[@]}" 2>/dev/null || true
  done
  if [[ "${PURGE_DATA:-0}" == "1" ]]; then
    log "Stopped docker stacks and removed their volumes."
  else
    log "Stopped docker stacks (volumes preserved)."
  fi
}

uninstall_system_hardening() {
  # auditd evidence rules
  local rules_dst="/etc/audit/rules.d/99-sift-evidence.rules"
  if [[ -f "$rules_dst" ]]; then
    sudo_if_needed rm -f "$rules_dst"
    if command -v augenrules >/dev/null 2>&1; then
      sudo_if_needed augenrules --load 2>/dev/null || true
    fi
    log "Removed auditd evidence rules."
  fi
  # AppArmor profile
  local profile_dst="/etc/apparmor.d/sift-gateway"
  if [[ -f "$profile_dst" ]]; then
    sudo_if_needed apparmor_parser -R "$profile_dst" 2>/dev/null || true
    sudo_if_needed rm -f "$profile_dst"
    log "Removed AppArmor profile."
  fi
  # hayabusa system-wide symlink
  if [[ -L /usr/local/bin/hayabusa ]]; then
    sudo_if_needed rm -f /usr/local/bin/hayabusa
    log "Removed /usr/local/bin/hayabusa symlink."
  fi
  # native run_command user-isolation sudoers bridge
  if [[ -f /etc/sudoers.d/sift-agent-runtime ]]; then
    sudo_if_needed rm -f /etc/sudoers.d/sift-agent-runtime
    log "Removed run_command runtime sudoers bridge."
  fi
}

uninstall_runtime() {
  # CAP_LINUX_IMMUTABLE lived on the venv python — removing the venv drops it.
  if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    log "Removed venv ($VENV_DIR)."
  fi
  # SIFT_HOME (=/var/lib/sift/.sift) is sift-service-owned 0700 — remove via sudo.
  # This removes config/TLS/secrets/hayabusa but leaves the rest of
  # /var/lib/sift (state) intact; that is only wiped by --purge-data.
  if sudo_if_needed test -d "$SIFT_HOME"; then
    sudo_if_needed rm -rf "$SIFT_HOME"
    log "Removed $SIFT_HOME (config, TLS, secrets, backups, hayabusa)."
  fi
}

_purge_tree() {
  # Remove a directory tree that may contain evidence files marked immutable
  # (chattr +i) or append-only (chattr +a) by the forensic write-protection
  # (CAP_LINUX_IMMUTABLE). A plain `rm -rf` returns "Operation not permitted" on
  # those, so the attributes MUST be cleared first. No-op on filesystems without
  # chattr support.
  local target="$1"
  [[ -d "$target" ]] || return 0
  if command -v chattr >/dev/null 2>&1; then
    # -R recurses; ignore errors on fs/files that don't carry the attrs.
    sudo_if_needed chattr -R -f -i "$target" 2>/dev/null || true
    sudo_if_needed chattr -R -f -a "$target" 2>/dev/null || true
  fi
  sudo_if_needed rm -rf "$target"
}

purge_data() {
  [[ "${PURGE_DATA:-0}" == "1" ]] || return 0
  _confirm_destructive "ABOUT TO PERMANENTLY DELETE: $SIFT_STATE_DIR (integrity records, tokens, passwords, snapshots) and $SIFT_CASE_ROOT (EVIDENCE, incl. immutable-flagged files). This cannot be undone."
  if [[ -d "$SIFT_STATE_DIR" ]]; then
    _purge_tree "$SIFT_STATE_DIR"
    log "Purged state dir ($SIFT_STATE_DIR)."
  fi
  if [[ -d "$SIFT_CASE_ROOT" ]]; then
    _purge_tree "$SIFT_CASE_ROOT"
    log "Purged case root ($SIFT_CASE_ROOT) — EVIDENCE deleted (immutable flags cleared first)."
  fi
}

do_uninstall() {
  log "Uninstalling sift-mcps."
  if [[ "${PURGE_DATA:-0}" == "1" ]]; then
    log "Mode: FULL WIPE (--purge-data) — software + state + evidence."
  else
    log "Mode: software only — /var/lib/sift and /cases are preserved (use --purge-data to wipe them)."
  fi
  uninstall_systemd
  uninstall_docker_stacks
  uninstall_system_hardening
  uninstall_runtime
  purge_data

  log "Uninstall complete."
  if [[ "${PURGE_DATA:-0}" != "1" ]]; then
    printf '\n'
    printf 'Preserved (data — not touched):\n'
    printf '  State:    %s   (integrity records, tokens, passwords, snapshots)\n' "$SIFT_STATE_DIR"
    printf '  Evidence: %s\n' "$SIFT_CASE_ROOT"
    printf '  Docker volumes (if any) left intact.\n'
    printf 'To wipe those too:  ./install.sh --uninstall --purge-data\n'
  fi
  printf 'The repo checkout itself was left in place. Reinstall with: ./install.sh [--core-only]\n'
}

# =============================================================================
# main
# =============================================================================

main() {
  local original_args=("$@")
  SIFT_CORE_ONLY="${SIFT_CORE_ONLY:-0}"
  local uninstall_mode=0
  # Track compatibility flags.
  local flag_no_opencti=0 flag_no_rag=0
  SIFT_EXTERNAL_SUPABASE="${SIFT_EXTERNAL_SUPABASE:-0}"

  # Parse flags (#1: new flags + existing)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes)               ASSUME_YES=1; shift ;;
      --core-only)            SIFT_CORE_ONLY=1; shift ;;
      --uninstall|--remove)   uninstall_mode=1; shift ;;
      --purge-data)           PURGE_DATA=1; shift ;;
      --no-opencti)           flag_no_opencti=1; shift ;;
      --no-rag)               flag_no_rag=1; shift ;;
      --external-supabase)    SIFT_EXTERNAL_SUPABASE=1; shift ;;
      --offline)              SIFT_OFFLINE=1; shift ;;
      --enable-geoip)         SIFT_GEOIP_ENABLED=1; shift ;;
      -h|--help)
        printf 'Usage: ./install.sh [OPTIONS]\n\n'
        printf 'Provisions (or removes) a sift-mcps stack on SIFT Workstation.\n'
        printf 'No arguments required for install — native components are provisioned idempotently.\n'
        printf 'Run from a normal clone; the installer stages itself into %s before provisioning.\n' "$SIFT_MCPS_INSTALL_ROOT"
        printf 'Re-run safe: every install step is idempotent.\n\n'
        printf '  --core-only          Install gateway + portal + in-process core tools only.\n'
        printf '                       Skips OpenSearch, RAG, Docker, and forensic-tool downloads.\n'
        printf '  --no-rag             Disable forensic-rag-mcp backend.\n'
        printf '  --no-opencti         Accepted for compatibility; OpenCTI is external and\n'
        printf '                       never installed by install.sh. Use scripts/setup-addon.sh.\n'
        printf '  --external-supabase  Skip Supabase auto-provisioning.  Requires that\n'
        printf '                       SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY,\n'
        printf '                       and SIFT_CONTROL_PLANE_DSN are already exported in env.\n'
        printf '  --offline            Hardened/air-gapped install: attempt NO network downloads.\n'
        printf '                       Each download step fails loudly pointing at the operator-\n'
        printf '                       staged artifact path it expects (uv, hayabusa, HF model cache,\n'
        printf '                       Supabase CLI). Equivalent to SIFT_OFFLINE=1.\n'
        printf '  --enable-geoip       Enable the OpenSearch ip2geo datasource (off by default; it\n'
        printf '                       fetches from a live endpoint). Equivalent to SIFT_GEOIP_ENABLED=1.\n'
        printf '  --uninstall          Reverse the install: stop/remove the systemd service, venv,\n'
        printf '                       ~/.sift (config/TLS/secrets), auditd + AppArmor configs, the\n'
        printf '                       hayabusa symlink, and docker containers. Preserves data\n'
        printf '                       (/var/lib/sift, /cases, docker volumes).\n'
        printf '  --purge-data         With --uninstall, ALSO delete /var/lib/sift and /cases\n'
        printf '                       (EVIDENCE) and docker volumes. Irreversible — prompts unless -y.\n'
        printf '  -y, --yes            Assume yes to destructive prompts (non-interactive purge).\n'
        exit 0
        ;;
      *)
        warn "Unknown option '$1' — ignored.  Run ./install.sh -h for help."
        shift
        ;;
    esac
  done
  export SIFT_EXTERNAL_SUPABASE
  # B-MVP-004: propagate offline/geoip/model-cache controls to all sub-steps
  # (including scripts/setup-supabase.sh invoked by preflight_supabase).
  export SIFT_OFFLINE SIFT_GEOIP_ENABLED SIFT_HF_HOME
  export SIFT_UV_VERSION SIFT_UV_TARBALL_SHA256 SIFT_HAYABUSA_TAG SIFT_HAYABUSA_SHA256
  export SIFT_RAG_MODEL_NAME SIFT_RAG_MODEL_REVISION SIFT_RAG_INDEX_TAG
  if is_offline; then
    log "OFFLINE MODE (SIFT_OFFLINE=1): no network downloads will be attempted; staged artifacts required."
  fi

  if [[ "$uninstall_mode" == "1" ]]; then
    do_uninstall
    exit 0
  fi

  stage_repo_to_install_root "${original_args[@]}"

  # --- pre-flight ---
  check_os
  check_python
  require_cmd awk
  require_cmd curl

  # --- install prerequisites needed by early preflight ---
  install_host_prereqs
  # Local Supabase is Docker-backed; make Docker reachable before
  # scripts/setup-supabase.sh. A fresh clone install can then recover when the
  # daemon is merely stopped.
  ensure_docker_ready_for_supabase

  # --- native backend enablement (#1) ---
  # OpenCTI and other external add-ons are prepared/registerable via
  # scripts/setup-addon.sh, not installed by this native path.
  if [[ "$SIFT_CORE_ONLY" == "1" ]]; then
    log "CORE-ONLY install: gateway + portal + in-process core tools."
    SIFT_OPENCTI_ENABLED="false"
    SIFT_RAG_ENABLED="false"
    SIFT_OPENSEARCH_ENABLED="false"
  else
    # RAG: --no-rag flag or explicit env=false overrides.
    if [[ "$flag_no_rag" -eq 1 || "${SIFT_RAG_ENABLED:-}" == "false" ]]; then
      SIFT_RAG_ENABLED="false"
      log "RAG backend disabled (--no-rag or SIFT_RAG_ENABLED=false)."
    else
      SIFT_RAG_ENABLED="${SIFT_RAG_ENABLED:-true}"
    fi

    # OpenSearch: default enabled.
    SIFT_OPENSEARCH_ENABLED="${SIFT_OPENSEARCH_ENABLED:-true}"

    if [[ "$flag_no_opencti" -eq 1 ]]; then
      log "OpenCTI is external; --no-opencti is accepted as a no-op compatibility flag."
    elif [[ "${SIFT_OPENCTI_ENABLED:-}" == "true" ]]; then
      warn "SIFT_OPENCTI_ENABLED=true is ignored by install.sh."
      warn "  Prepare OpenCTI with scripts/setup-addon.sh, then register it via Portal -> Backends."
    fi
    SIFT_OPENCTI_ENABLED="false"
    log "OpenCTI native install disabled: external add-on only (scripts/setup-addon.sh)."
  fi
  export SIFT_CORE_ONLY SIFT_OPENCTI_ENABLED SIFT_RAG_ENABLED SIFT_OPENSEARCH_ENABLED

  # --- preflight: Supabase (integration contract) ---
  # Must run before write_supabase_env / write_control_plane_env so those see
  # the exported vars. Skipped for --core-only or --external-supabase.
  preflight_supabase

  # --- install ---
  install_uv_if_needed

  # Ensure venv integrity before sync
  _ensure_venv_integrity || true  # best-effort; sync_workspace will fix remaining issues

  sync_workspace
  repair_pyewf_venv_link
  # The service user + shared `sift` group must exist before install_state_dirs
  # chowns the state/secret tree to sift-service.
  ensure_gateway_service_user
  install_state_dirs
  configure_agent_runtime
  # agent_runtime is created by configure_agent_runtime (setup-agent-runtime.sh);
  # add it to the shared `sift` group AFTER, so it can write the vol symbol cache.
  # This grants NOTHING else — `sift` is used only for that 2775 cache dir.
  join_shared_symbol_group
  configure_ingest_mount_sudoers
  configure_fuse
  generate_tls
  write_default_examiner
  write_supabase_env   # A1-BOOTSTRAP: Supabase secrets in ~/.sift/supabase.env
  write_control_plane_env

  # Apply DB migrations BEFORE bootstrap_supabase_operator and seed_addon_backends
  # so the schema is in place when those functions run (#2).
  DB_MIGRATIONS_RESULT="skipped"
  if [[ "$SIFT_CORE_ONLY" != "1" ]]; then
    if apply_db_migrations; then
      DB_MIGRATIONS_RESULT="applied"
    else
      DB_MIGRATIONS_RESULT="failed"
    fi
  fi

  write_gateway_config
  prepare_enrichment_assets   # FK enrichment is core (D4: FK data is a core runtime dep)
  write_fk_env                 # BATCH-PMI3: FK_DATA_DIR in ~/.sift/forensic-knowledge.env

  # Track whether OpenSearch came up (set by start_opensearch).
  OPENSEARCH_UP=0
  OPENSEARCH_SEEDED=false
  RAG_SEEDED=false

  if [[ "$SIFT_CORE_ONLY" != "1" ]]; then
    if [[ "${SIFT_RAG_ENABLED:-true}" == "true" ]]; then
      load_rag_pgvector
    fi
    install_hayabusa
    write_opensearch_config
    write_opensearch_env    # FM-2: write gateway env file for OPENSEARCH_CONFIG/OPENSEARCH_HOST (#3)
    start_opensearch        # sets OPENSEARCH_UP=1 if healthy

    # FM-1/FM-2 (#5): gate OpenSearch cluster config and seeding on real availability.
    if [[ "$OPENSEARCH_UP" -eq 1 ]]; then
      configure_opensearch_cluster
      configure_geoip_pipeline
      install_opensearch_templates
      configure_opensearch_detections   # PMI1: keep Sigma disabled; clean dead detectors/monitors; seed aliases
    else
      warn "OpenSearch not available — skipping cluster config, GeoIP pipeline, and template install."
      warn "  opensearch-mcp backend will NOT be seeded; set SIFT_OPENSEARCH_ENABLED=false to suppress."
      SIFT_OPENSEARCH_ENABLED="false"
      export SIFT_OPENSEARCH_ENABLED
    fi

    install_hayabusa_system_links
    fix_volatility_permissions
  else
    log "CORE-ONLY: skipped add-on backends, OpenSearch/Docker, and forensic-tool downloads."
  fi

  # OSX1: seed enabled add-on backends into app.mcp_backends BEFORE the gateway
  # starts so its first registry read (Gateway.__init__) already includes
  # opensearch-mcp. This removes the historical "no tools until restart" race —
  # seed_addon_backends talks to Postgres directly (it does NOT need the gateway
  # running), it only needs the schema (apply_db_migrations ran above) and a
  # resolvable control-plane DSN. Gated on OPENSEARCH_UP: if OpenSearch never came
  # healthy, SIFT_OPENSEARCH_ENABLED was set to false above, so this is a no-op.
  # Belt-and-suspenders: even if a row is seeded later (operator registers via the
  # portal), the gateway's _late_start_checker now re-reads app.mcp_backends and
  # mounts late-seeded backends without a restart (Gateway.reload_backend_registry).
  seed_addon_backends

  # A1-BOOTSTRAP: validate evidence/cases root before starting services.
  validate_evidence_root

  install_systemd_service

  # NOTE: loginctl linger removed — the gateway/worker are now SYSTEM services
  # (User=sift-service, WantedBy=multi-user.target), so they start at boot and
  # survive operator logout without per-user lingering.

  configure_immutable_capability
  configure_auditd
  configure_apparmor
  poll_gateway "initial"

  # A1-BOOTSTRAP: Supabase operator bootstrap runs after the gateway is up
  # (Postgres must be reachable for the DB principal insert to succeed later).
  # Runs only when SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set.
  SUPABASE_OPERATOR_CREATED=0
  SB_OPERATOR_USER_ID=""
  SUPABASE_OPERATOR_MAPPED=0
  SUPABASE_OPERATOR_EMAIL=""
  SUPABASE_OPERATOR_TEMP_PASSWORD=""
  bootstrap_supabase_operator

  # OSX1: seed_addon_backends + the post-seed gateway restart were moved to
  # BEFORE install_systemd_service (above), so the gateway sees opensearch-mcp on
  # its first start and the restart workaround is no longer needed. A late seed
  # (e.g. operator registers a backend via the portal) is now picked up live by
  # the gateway's _late_start_checker -> reload_backend_registry, also without a
  # restart.

  write_handoff
  print_summary
}

# Run main() only when executed directly. When sourced (e.g. by
# scripts/setup-addon.sh) this file acts as a function library: sourcing it
# defines the provisioning functions and resolves the path vars without
# kicking off an install.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
