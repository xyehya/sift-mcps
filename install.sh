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
#   - Single uv sync path (--extra full) — no feature toggles.
#   - Venv always matches system Python; mismatched venvs are rebuilt.
#   - OpenCTI auto-detected when Docker + ≥14 GB RAM are available.
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

# =============================================================================
# Paths — everything derived from REPO_DIR and system conventions
# =============================================================================
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Hard-code the SIFT-native Python.  Must be ≥ 3.10.
SYSTEM_PYTHON="/usr/bin/python3.12"

SIFT_HOME="${SIFT_HOME:-$HOME/.sift}"
SIFT_TLS_DIR="${SIFT_TLS_DIR:-$SIFT_HOME/tls}"
SIFT_BACKUP_DIR="${SIFT_BACKUP_DIR:-$SIFT_HOME/backups}"
SIFT_CONFIG="${SIFT_CONFIG:-$SIFT_HOME/gateway.yaml}"
SIFT_CASES_ROOT="${SIFT_CASES_ROOT:-${SIFT_CASE_ROOT:-/cases}}"
SIFT_CASE_ROOT="${SIFT_CASE_ROOT:-$SIFT_CASES_ROOT}"
SIFT_STATE_DIR="${SIFT_STATE_DIR:-/var/lib/sift}"
SIFT_PASSWORDS_DIR="${SIFT_PASSWORDS_DIR:-$SIFT_STATE_DIR/passwords}"
SIFT_VERIFICATION_DIR="${SIFT_VERIFICATION_DIR:-$SIFT_STATE_DIR/verification}"
SIFT_TOKENS_DIR="${SIFT_TOKENS_DIR:-$SIFT_STATE_DIR/tokens}"
SIFT_SNAPSHOTS_DIR="${SIFT_SNAPSHOTS_DIR:-$SIFT_STATE_DIR/snapshots}"
SIFT_ENRICHMENT_DIR="${SIFT_ENRICHMENT_DIR:-$SIFT_STATE_DIR/enrichment}"
SIFT_WINDOWS_TRIAGE_DB_DIR="${SIFT_WINDOWS_TRIAGE_DB_DIR:-$SIFT_STATE_DIR/windows-triage}"
SIFT_EXAMINER="${SIFT_EXAMINER:-examiner}"
MATERIALS_FILE="${MATERIALS_FILE:-$SIFT_TOKENS_DIR/installer-handoff.txt}"
SYSTEMD_USER_DIR="${SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
GATEWAY_SERVICE_FILE="$SYSTEMD_USER_DIR/sift-gateway.service"

VENV_DIR="$REPO_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

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
  require_cmd curl
  log "Installing uv."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  uv_bin="$(resolve_uv)"
  [[ -n "$uv_bin" ]] || die "uv install completed but uv binary not found."
  UV_BIN="$uv_bin"
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

  # Default --extra full (RAG is a core forensic capability); core-only installs
  # use --extra core (gateway + portal + in-process core tools, no add-on backends).
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

# =============================================================================
# Phase 3 — state directories
# =============================================================================

install_state_dirs() {
  local owner group
  owner="$(user_name)"
  group="$(group_name)"
  log "Creating SIFT state directories."
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$SIFT_STATE_DIR"
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$SIFT_PASSWORDS_DIR"
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$SIFT_VERIFICATION_DIR"
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$SIFT_TOKENS_DIR"
  sudo_if_needed install -d -m 755 -o 1000 -g 1000 "$SIFT_SNAPSHOTS_DIR"
  sudo_if_needed install -d -m 755 -o "$owner" -g "$group" "$SIFT_ENRICHMENT_DIR"
  sudo_if_needed install -d -m 755 -o "$owner" -g "$group" "$SIFT_WINDOWS_TRIAGE_DB_DIR"
  sudo_if_needed install -d -m 755 -o "$owner" -g "$group" "$SIFT_CASE_ROOT"
  install -d -m 700 "$SIFT_HOME" "$SIFT_TLS_DIR" "$SIFT_BACKUP_DIR"
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

download_triage_databases() {
  log "Downloading triage baseline databases."
  if [[ -f "$SIFT_WINDOWS_TRIAGE_DB_DIR/known_good.db" && -f "$SIFT_WINDOWS_TRIAGE_DB_DIR/context.db" ]]; then
    log "Triage databases already present — skipping."
    return
  fi
  if "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads \
    python -m windows_triage_mcp.scripts.download_databases --dest "$SIFT_WINDOWS_TRIAGE_DB_DIR"; then
    log "Triage databases downloaded."
  else
    warn "Triage database download FAILED.  windows-triage-mcp will run in degraded mode."
  fi
}

prepare_enrichment_assets() {
  log "Preparing enrichment asset pointers."
  if [[ -d "$REPO_DIR/packages/forensic-knowledge/data" ]]; then
    ln -sfn "$REPO_DIR/packages/forensic-knowledge/data" "$SIFT_ENRICHMENT_DIR/forensic-knowledge"
  else
    warn "forensic-knowledge data directory not found."
  fi
  install -d -m 755 "$SIFT_ENRICHMENT_DIR/forensic-rag"
}

download_rag_index() {
  local rag_data_dir="$REPO_DIR/packages/forensic-rag-mcp/data"
  local chroma_dir="$rag_data_dir/chroma"

  if [[ -d "$chroma_dir" ]]; then
    log "RAG knowledge index already exists at $chroma_dir — preserving."
    return
  fi

  log "Downloading pre-built RAG knowledge index (22K+ records, ~1-3 GB)..."
  if "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads \
    python -m rag_mcp.scripts.download_index --dest "$rag_data_dir"; then
    log "RAG knowledge index downloaded and verified."
  else
    warn "RAG knowledge index download FAILED."
    warn "  forensic-rag-mcp will start in degraded mode."
    warn "  Retry: python -m rag_mcp.scripts.download_index"
  fi
}

install_hayabusa() {
  log "Installing hayabusa detection engine."
  local binary_dir="$SIFT_HOME/bin"
  local rules_dir="$SIFT_HOME/hayabusa-rules"

  if [[ -x "$binary_dir/hayabusa" ]]; then
    local ver
    ver=$("$binary_dir/hayabusa" help 2>&1 | head -1 || true)
    log "hayabusa already installed: $ver"
    return
  fi

  require_cmd unzip

  local tag
  tag=$(curl -fsS "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest" 2>/dev/null \
    | "$SYSTEM_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || echo "")

  if [[ -z "$tag" ]]; then
    warn "Could not resolve latest hayabusa release.  Detection will be unavailable."
    return
  fi

  local asset="hayabusa-${tag#v}-lin-x64-gnu.zip"
  local url="https://github.com/Yamato-Security/hayabusa/releases/download/${tag}/${asset}"
  log "Downloading hayabusa ${tag}..."
  local tmpd
  tmpd="$(mktemp -d)"

  if ! curl -fsSL -o "$tmpd/$asset" "$url"; then
    warn "hayabusa download failed.  Detection will be unavailable."
    rm -rf "$tmpd"
    return
  fi

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

  install -d -m 755 "$binary_dir"
  install -m 755 "$extracted" "$binary_dir/hayabusa"
  log "hayabusa installed: $("$binary_dir/hayabusa" help 2>&1 | head -1)"

  if [[ -d "$tmpd/extracted/rules" ]]; then
    rm -rf "$rules_dir"
    cp -r "$tmpd/extracted/rules" "$rules_dir"
    log "hayabusa rules installed: $(find "$rules_dir" -name '*.yml' | wc -l) YAML files"
  else
    warn "Bundled rules not found in release archive."
  fi
  rm -rf "$tmpd"
}

install_hayabusa_system_links() {
  local binary="$SIFT_HOME/bin/hayabusa"
  [[ -x "$binary" ]] || return 0
  sudo_if_needed ln -sf "$binary" /usr/local/bin/hayabusa 2>/dev/null || true
}

fix_volatility_permissions() {
  # Volatility 3 downloads PDB symbol files at runtime into its package dir.
  # If /opt/volatility3 is root-owned the gateway user can't write the cache
  # and every vol3 plugin exits 1 with "Cannot write necessary symbol file".
  local vol_base="/opt/volatility3"
  [[ -d "$vol_base" ]] || return 0
  local symbols_dir
  symbols_dir=$(find "$vol_base" -type d -name "symbols" 2>/dev/null | head -1)
  [[ -n "$symbols_dir" ]] || return 0
  log "Fixing Volatility 3 symbol directory write permissions: $symbols_dir"
  sudo_if_needed chmod -R a+w "$symbols_dir" 2>/dev/null || \
    sudo_if_needed chown -R "$(id -u):$(id -g)" "$symbols_dir" 2>/dev/null || \
    warn "Could not fix Volatility 3 symbol permissions — memory ingest may fail on first plugin run."
}

# =============================================================================
# Phase 5 — TLS
# =============================================================================

generate_tls() {
  require_cmd openssl
  install -d -m 700 "$SIFT_TLS_DIR"
  if [[ -f "$SIFT_TLS_DIR/ca-cert.pem" && -f "$SIFT_TLS_DIR/gateway-cert.pem" && -f "$SIFT_TLS_DIR/gateway-key.pem" ]]; then
    log "TLS material already exists — preserving."
    return
  fi

  log "Generating self-signed CA and gateway certificate."
  local first_ip san_file
  first_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$first_ip" ]] || first_ip="127.0.0.1"
  san_file="$(mktemp)"
  printf 'subjectAltName=IP:%s,IP:127.0.0.1,DNS:%s,DNS:localhost\n' \
    "$first_ip" "$(hostname)" > "$san_file"

  openssl genrsa -out "$SIFT_TLS_DIR/ca-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -x509 -days 3650 -key "$SIFT_TLS_DIR/ca-key.pem" \
    -out "$SIFT_TLS_DIR/ca-cert.pem" -subj "/CN=sift-mcps-CA" >/dev/null 2>&1
  openssl genrsa -out "$SIFT_TLS_DIR/gateway-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -key "$SIFT_TLS_DIR/gateway-key.pem" \
    -out "$SIFT_TLS_DIR/gateway-csr.pem" -subj "/CN=$(hostname)" >/dev/null 2>&1
  openssl x509 -req -days 730 -in "$SIFT_TLS_DIR/gateway-csr.pem" \
    -CA "$SIFT_TLS_DIR/ca-cert.pem" -CAkey "$SIFT_TLS_DIR/ca-key.pem" \
    -CAcreateserial -out "$SIFT_TLS_DIR/gateway-cert.pem" \
    -extfile "$san_file" >/dev/null 2>&1
  rm -f "$san_file"
  chmod 600 "$SIFT_TLS_DIR/"*-key.pem
  chmod 644 "$SIFT_TLS_DIR/"*-cert.pem
}

# =============================================================================
# Phase 6 — examiner account
# =============================================================================

write_default_examiner() {
  local password_file="$SIFT_PASSWORDS_DIR/$SIFT_EXAMINER.json"
  if [[ -f "$password_file" ]]; then
    log "Default examiner password already exists — preserving."
    TEMP_PASSWORD_CREATED=0
    TEMP_PASSWORD=""
    return
  fi
  TEMP_PASSWORD="Agentir-$(random_hex 12)"
  TEMP_PASSWORD_CREATED=1
  export SIFT_PASSWORDS_DIR SIFT_EXAMINER TEMP_PASSWORD
  "$SYSTEM_PYTHON" - <<'PY'
import hashlib, json, os, secrets, tempfile
from pathlib import Path

passwords_dir = Path(os.environ["SIFT_PASSWORDS_DIR"])
examiner = os.environ["SIFT_EXAMINER"]
password = os.environ["TEMP_PASSWORD"]
salt = secrets.token_bytes(32)
entry = {
    "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex(),
    "salt": salt.hex(),
    "must_reset_password": True,
    "created_by": "sift-mcps install.sh",
}
passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
fd, tmp = tempfile.mkstemp(dir=str(passwords_dir), suffix=".tmp")
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(entry, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, passwords_dir / f"{examiner}.json")
except BaseException:
    try: os.unlink(tmp)
    except OSError: pass
    raise
PY
}

# =============================================================================
# Phase 7 — gateway + opensearch config
# =============================================================================

_render_file() {
  local src="$1" dst="$2" mode="$3"
  export SIFT_HOME SIFT_TLS_DIR SIFT_CONFIG SIFT_CASES_ROOT SIFT_CASE_ROOT
  export SIFT_WINDOWS_TRIAGE_DB_DIR
  export SIFT_GATEWAY_TOKEN SIFT_SERVICE_TOKEN SIFT_PORTAL_SESSION_SECRET
  export SIFT_EXAMINER SIFT_MCPS_ROOT UV_BIN PYTHON_BIN OPENCTI_URL OPENCTI_TOKEN
  export SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED SIFT_WINDOWS_TRIAGE_ENABLED SIFT_OPENSEARCH_ENABLED

  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
  # Honor flags already set by main() (e.g. core-only); default to enabled.
  SIFT_RAG_ENABLED="${SIFT_RAG_ENABLED:-true}"
  SIFT_WINDOWS_TRIAGE_ENABLED="${SIFT_WINDOWS_TRIAGE_ENABLED:-true}"
  SIFT_OPENSEARCH_ENABLED="${SIFT_OPENSEARCH_ENABLED:-true}"
  SIFT_OPENCTI_ENABLED="${SIFT_OPENCTI_ENABLED:-false}"

  "$SYSTEM_PYTHON" - "$src" "$dst" "$mode" <<'PY'
import os, stat, sys, tempfile
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
text = src.read_text()
for key, value in os.environ.items():
    text = text.replace("${" + key + "}", value)
dst.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=str(dst.parent), suffix=".tmp")
try:
    os.fchmod(fd, mode)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, dst)
    os.chmod(dst, mode)
except BaseException:
    try: os.unlink(tmp)
    except OSError: pass
    raise
PY
}

write_gateway_config() {
  if [[ -f "$SIFT_CONFIG" ]]; then
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
  SIFT_PORTAL_SESSION_SECRET="$(random_hex 32)"
  SIFT_TOKEN_CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  CONFIG_CREATED=1
  export SIFT_GATEWAY_TOKEN SIFT_SERVICE_TOKEN SIFT_PORTAL_SESSION_SECRET SIFT_TOKEN_CREATED_AT
  _render_file "$REPO_DIR/configs/gateway.yaml.template" "$SIFT_CONFIG" 0600
}

_migrate_gateway_config() {
  log "Checking gateway config compatibility."
  export SIFT_CONFIG SIFT_MCPS_ROOT PYTHON_BIN OPENCTI_URL OPENCTI_TOKEN
  export SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED SIFT_WINDOWS_TRIAGE_ENABLED
  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  SIFT_RAG_ENABLED="true"
  SIFT_WINDOWS_TRIAGE_ENABLED="true"
  SIFT_OPENCTI_ENABLED="${SIFT_OPENCTI_ENABLED:-false}"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"

  "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads python - <<'PY'
import os, tempfile
from pathlib import Path
import yaml

path = Path(os.environ["SIFT_CONFIG"])
cfg = yaml.safe_load(path.read_text()) or {}
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

# RAG / triage / opencti enabled flags
enrichment = cfg.setdefault("enrichment", {})
if enrichment.get("forensic_rag") is not True and os.environ.get("SIFT_RAG_ENABLED") == "true":
    enrichment["forensic_rag"] = True
    changed = True

rag_backend = cfg.setdefault("backends", {}).get("forensic-rag-mcp")
if isinstance(rag_backend, dict) and rag_backend.get("enabled") is not True and os.environ.get("SIFT_RAG_ENABLED") == "true":
    rag_backend["enabled"] = True
    changed = True

wt_backend = cfg.setdefault("backends", {}).get("windows-triage-mcp")
if isinstance(wt_backend, dict) and wt_backend.get("enabled") is not True:
    wt_backend["enabled"] = True
    changed = True

if os.environ.get("SIFT_OPENCTI_ENABLED") == "true":
    octi = cfg.setdefault("backends", {}).setdefault("opencti-mcp", {})
    if octi.get("enabled") is not True:
        octi["enabled"] = True
        changed = True
    env = octi.setdefault("env", {})
    url = os.environ.get("OPENCTI_URL") or "http://127.0.0.1:8080"
    token = os.environ.get("OPENCTI_TOKEN") or ""
    if env.get("OPENCTI_URL") != url:
        env["OPENCTI_URL"] = url
        changed = True
    if env.get("OPENCTI_TOKEN") != token:
        env["OPENCTI_TOKEN"] = token
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
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            yaml.safe_dump(cfg, handle, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise
PY
}

write_opensearch_config() {
  local os_config="$SIFT_HOME/opensearch.yaml"
  if [[ -f "$os_config" ]]; then
    log "OpenSearch client config exists — preserving $os_config."
    return
  fi
  umask 077
  cat > "$os_config" <<'YAML'
host: http://127.0.0.1:9200
user: admin
password: admin
verify_certs: false
YAML
  chmod 600 "$os_config"
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

start_opensearch() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker not found — skipping OpenSearch.  Install Docker and re-run."
    return 0
  fi
  docker compose version >/dev/null 2>&1 || warn "Docker Compose v2 not available."
  if ! docker ps >/dev/null 2>&1; then
    warn "Docker daemon not reachable — attempting start."
    sudo_if_needed systemctl start docker 2>/dev/null || true
    sleep 2
  fi
  docker ps >/dev/null 2>&1 || { warn "Docker not usable — skipping OpenSearch."; return 0; }

  log "Starting OpenSearch."
  docker compose -f "$REPO_DIR/docker-compose.yml" up -d opensearch

  log "Waiting for OpenSearch health (up to 180 s)."
  local status="unknown"
  for _ in $(seq 1 90); do
    status="$(curl -fsS http://127.0.0.1:9200/_cluster/health 2>/dev/null \
      | "$SYSTEM_PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status","unknown"))' 2>/dev/null || true)"
    if [[ "$status" == "green" || "$status" == "yellow" ]]; then
      log "OpenSearch healthy: $status"
      break
    fi
    sleep 2
  done
  [[ "$status" == "green" || "$status" == "yellow" ]] || warn "OpenSearch not healthy after 180 s — check docker logs."
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
  curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || return 0
  log "Configuring GeoIP enrichment."

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

install_opensearch_templates() {
  curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || return 0
  log "Installing OpenSearch templates and pipelines."
  "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads python - <<'PY' || warn "OpenSearch template bootstrap failed — opensearch-mcp retries at startup."
from opensearch_mcp.client import get_client
from opensearch_mcp.mappings import ensure_winlog_pipeline

client = get_client()
result = ensure_winlog_pipeline(client)
if result.get("status") not in {"ok", "warning"}:
    raise SystemExit(result)
print(result.get("status", "ok"))
PY
}

# =============================================================================
# Phase 9 — OpenCTI (auto-detected)
# =============================================================================

_detect_opencti() {
  # Returns 0 if OpenCTI should be enabled: Docker available + ≥ 14 GB RAM.
  command -v docker >/dev/null 2>&1 || return 1
  docker compose version >/dev/null 2>&1 || return 1
  docker ps >/dev/null 2>&1 || return 1
  local total_ram_mb
  total_ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  [[ "$total_ram_mb" -ge 14336 ]] || return 1
  return 0
}

prepare_opencti_secrets() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  if [[ -z "${OPENCTI_TOKEN:-}" ]]; then
    if [[ -f "$SIFT_HOME/opencti-token" ]]; then
      OPENCTI_TOKEN="$(< "$SIFT_HOME/opencti-token")"
      log "OpenCTI admin token already exists."
    else
      OPENCTI_TOKEN=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
      printf '%s\n' "$OPENCTI_TOKEN" > "$SIFT_HOME/opencti-token"
      chmod 600 "$SIFT_HOME/opencti-token"
      log "OpenCTI admin token saved."
    fi
  fi

  if [[ -f "$SIFT_HOME/opencti-encryption-key" ]]; then
    OPENCTI_ENCRYPTION_KEY="$(< "$SIFT_HOME/opencti-encryption-key")"
  else
    OPENCTI_ENCRYPTION_KEY="$(openssl rand -base64 32)"
    printf '%s\n' "$OPENCTI_ENCRYPTION_KEY" > "$SIFT_HOME/opencti-encryption-key"
    chmod 600 "$SIFT_HOME/opencti-encryption-key"
  fi

  if [[ -f "$SIFT_HOME/opencti-health-key" ]]; then
    OPENCTI_HEALTH_ACCESS_KEY="$(< "$SIFT_HOME/opencti-health-key")"
  else
    OPENCTI_HEALTH_ACCESS_KEY=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_HEALTH_ACCESS_KEY" > "$SIFT_HOME/opencti-health-key"
    chmod 600 "$SIFT_HOME/opencti-health-key"
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

  local id_file
  id_file="$SIFT_HOME/opencti-connector-mitre-id"
  if [[ -f "$id_file" ]]; then
    OPENCTI_CONNECTOR_MITRE_ID="$(< "$id_file")"
  else
    OPENCTI_CONNECTOR_MITRE_ID=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_CONNECTOR_MITRE_ID" > "$id_file"
    chmod 600 "$id_file"
  fi

  id_file="$SIFT_HOME/opencti-connector-cisa-kev-id"
  if [[ -f "$id_file" ]]; then
    OPENCTI_CONNECTOR_CISA_KEV_ID="$(< "$id_file")"
  else
    OPENCTI_CONNECTOR_CISA_KEV_ID=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_CONNECTOR_CISA_KEV_ID" > "$id_file"
    chmod 600 "$id_file"
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
  install -d -m 700 "$SYSTEMD_USER_DIR"
  SIFT_GATEWAY_TOKEN=""
  SIFT_SERVICE_TOKEN=""
  SIFT_PORTAL_SESSION_SECRET=""
  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  SIFT_CONFIG="$SIFT_CONFIG"
  SIFT_EXAMINER="$SIFT_EXAMINER"
  export SIFT_MCPS_ROOT UV_BIN PYTHON_BIN SIFT_CONFIG SIFT_EXAMINER

  [[ -x "$VENV_DIR/bin/sift-gateway" ]] || die "Missing gateway entrypoint: $VENV_DIR/bin/sift-gateway. Run install workspace sync first."

  if [[ -f "$GATEWAY_SERVICE_FILE" ]]; then
    log "Updating systemd user service $GATEWAY_SERVICE_FILE."
  else
    log "Writing systemd user service $GATEWAY_SERVICE_FILE."
  fi
  _render_file "$REPO_DIR/configs/systemd/sift-gateway.service" "$GATEWAY_SERVICE_FILE" 0644

  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found — service file written but not started."
    return
  fi
  systemctl --user daemon-reload
  systemctl --user enable sift-gateway.service
  systemctl --user restart sift-gateway.service
}

# =============================================================================
# Phase 11 — validation
# =============================================================================

poll_gateway() {
  log "Waiting for gateway health (up to 30 s)."
  for _ in $(seq 1 30); do
    if curl -kfsS https://127.0.0.1:4508/health >/dev/null 2>&1; then
      log "Gateway health endpoint reachable."
      return
    fi
    sleep 1
  done
  warn "Gateway not reachable.  Check: journalctl --user -u sift-gateway -n 50"
}

# =============================================================================
# Phase 12 — handoff
# =============================================================================

write_handoff() {
  local existing_temp_password existing_gateway_token existing_service_token
  existing_temp_password=""
  existing_gateway_token=""
  existing_service_token=""
  if [[ -f "$MATERIALS_FILE" ]]; then
    existing_temp_password="$(awk -F= '$1=="temporary_examiner_password"{sub(/^[^=]*=/,""); print; exit}' "$MATERIALS_FILE" || true)"
    existing_gateway_token="$(awk -F= '$1=="examiner_fallback_token"{sub(/^[^=]*=/,""); print; exit}' "$MATERIALS_FILE" || true)"
    existing_service_token="$(awk -F= '$1=="hermes_service_token"{sub(/^[^=]*=/,""); print; exit}' "$MATERIALS_FILE" || true)"
  fi
  umask 077
  {
    printf 'sift-mcps installer handoff\n'
    printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'portal_url=https://%s:4508/portal/\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'gateway_mcp_url=https://%s:4508/mcp\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'ca_cert=%s/ca-cert.pem\n' "$SIFT_TLS_DIR"
    printf 'gateway_config=%s\n' "$SIFT_CONFIG"
    printf 'examiner=%s\n' "$SIFT_EXAMINER"
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
  } > "$MATERIALS_FILE"
  chmod 600 "$MATERIALS_FILE"
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
  sudo_if_needed setcap cap_linux_immutable+ep "$VENV_PYTHON" 2>/dev/null || true
  log "setcap cap_linux_immutable+ep applied to $VENV_PYTHON."
}

configure_auditd() {
  if ! command -v augenrules &>/dev/null && ! command -v auditctl &>/dev/null; then
    warn "auditd not found — skipping audit rules."
    return 0
  fi
  local rules_src="${REPO_DIR}/configs/audit/99-sift-evidence.rules"
  [[ -f "$rules_src" ]] || return 0
  local rules_dst="/etc/audit/rules.d/99-sift-evidence.rules"
  local tmp
  tmp="$(mktemp)"
  sed "s|CASES_ROOT|${SIFT_CASE_ROOT}|g" "$rules_src" > "$tmp"
  sudo_if_needed cp "$tmp" "$rules_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 640 "$rules_dst"
  if command -v augenrules &>/dev/null; then
    sudo_if_needed augenrules --load
  else
    sudo_if_needed auditctl -R "$rules_dst"
  fi
  log "auditd rules installed."
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
  printf 'Secrets:      %s\n' "$MATERIALS_FILE"
  printf '\n'
  printf 'Next steps:\n'
  printf '  1. On the analyst machine, trust the CA cert or set REQUESTS_CA_BUNDLE.\n'
  printf '  2. Configure Hermes with configs/hermes-forensics-profile.yaml and the service token.\n'
  printf '  3. Sign into the portal as %s and reset the temporary password.\n' "$SIFT_EXAMINER"
}

# =============================================================================
# main
# =============================================================================

main() {
  SIFT_CORE_ONLY="${SIFT_CORE_ONLY:-0}"
  # Parse no-arg flags only (-y, --yes for non-interactive)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes) shift ;;   # accepted but ignored — we are always non-interactive
      --core-only) SIFT_CORE_ONLY=1; shift ;;
      -h|--help)
        printf 'Usage: ./install.sh [--core-only]\n\n'
        printf 'Provisions a sift-mcps stack on SIFT Workstation.\n'
        printf 'No arguments required — everything is auto-detected.\n'
        printf 'Re-run safe: every step is idempotent.\n\n'
        printf '  --core-only   Install gateway + portal + in-process core tools only.\n'
        printf '                Skips all add-on backends (opensearch, rag, windows-triage,\n'
        printf '                opencti), OpenSearch/Docker, and forensic-tool downloads.\n'
        exit 0
        ;;
      *)
        warn "Unknown option '$1' — ignored.  Run ./install.sh -h for help."
        shift
        ;;
    esac
  done

  # --- pre-flight ---
  check_os
  check_python
  require_cmd awk
  require_cmd curl

  # --- backend enablement ---
  if [[ "$SIFT_CORE_ONLY" == "1" ]]; then
    log "CORE-ONLY install: gateway + portal + in-process core tools; all add-on backends disabled."
    SIFT_OPENCTI_ENABLED="false"
    SIFT_RAG_ENABLED="false"
    SIFT_WINDOWS_TRIAGE_ENABLED="false"
    SIFT_OPENSEARCH_ENABLED="false"
  else
    SIFT_RAG_ENABLED="${SIFT_RAG_ENABLED:-true}"
    SIFT_WINDOWS_TRIAGE_ENABLED="${SIFT_WINDOWS_TRIAGE_ENABLED:-true}"
    SIFT_OPENSEARCH_ENABLED="${SIFT_OPENSEARCH_ENABLED:-true}"
    # auto-detect OpenCTI
    if _detect_opencti; then
      SIFT_OPENCTI_ENABLED="true"
      log "OpenCTI auto-detected: Docker available, sufficient RAM."
    else
      SIFT_OPENCTI_ENABLED="false"
      log "OpenCTI not enabled (requires Docker + ≥14 GB RAM)."
    fi
  fi
  export SIFT_CORE_ONLY SIFT_OPENCTI_ENABLED SIFT_RAG_ENABLED SIFT_WINDOWS_TRIAGE_ENABLED SIFT_OPENSEARCH_ENABLED

  # --- install ---
  install_uv_if_needed

  # Ensure venv integrity before sync
  _ensure_venv_integrity || true  # best-effort; sync_workspace will fix remaining issues

  sync_workspace
  install_state_dirs
  configure_fuse
  generate_tls
  write_default_examiner
  prepare_opencti_secrets
  write_gateway_config
  prepare_enrichment_assets   # FK enrichment is core (D4: FK data is a core runtime dep)

  if [[ "$SIFT_CORE_ONLY" != "1" ]]; then
    download_triage_databases
    download_rag_index
    install_hayabusa
    write_opensearch_config
    start_opensearch
    configure_opensearch_cluster
    configure_geoip_pipeline
    install_opensearch_templates
    install_opencti
    install_opencti_feeds
    install_hayabusa_system_links
    fix_volatility_permissions
  else
    log "CORE-ONLY: skipped add-on backends, OpenSearch/Docker, and forensic-tool downloads."
  fi

  install_systemd_service
  configure_immutable_capability
  configure_auditd
  configure_apparmor
  poll_gateway
  write_handoff
  print_summary
}

main "$@"
