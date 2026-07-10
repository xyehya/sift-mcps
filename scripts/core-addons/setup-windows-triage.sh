#!/usr/bin/env bash
set -Eeuo pipefail

# First-party Windows-triage core add-on pack. This deliberately lives outside
# scripts/setup-addon.sh, which is reserved for external integrations.
# The pack is an installer/control-plane actor; the registered stdio child gets
# an empty env_refs map and therefore never receives DB credentials.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=lib/bootstrap.sh
source "$REPO_DIR/lib/bootstrap.sh"
sift_source_core_addon_libraries

readonly WINTRIAGE_BACKEND_NAME="windows-triage-mcp"
readonly WINTRIAGE_ENTRYPOINT="windows-triage-mcp"
readonly WINTRIAGE_DEFAULT_DATA_DIR="/var/lib/sift/windows-triage"
readonly WINTRIAGE_REGISTRY_DB="known_good_registry.db"
readonly WINTRIAGE_REGISTRY_PROVENANCE="${WINTRIAGE_REGISTRY_DB}.provenance.json"

wintriage_usage() {
  cat <<'EOF'
Usage: scripts/core-addons/setup-windows-triage.sh --install [OPTIONS]

Install and reconcile the first-party Windows-triage MCP backend.

Options:
  --install          Required explicit non-interactive installation action.
  --with-registry    Also provision the optional ~12 GiB full registry baseline.
                     It is never selected by --install alone.
  --offline          Refuse all network access. Pre-stage known_good.db and
                     context.db in /var/lib/sift/windows-triage. With
                     --with-registry, also pre-stage known_good_registry.db
                     and set SIFT_WINDOWS_TRIAGE_REGISTRY_SHA256 plus
                     SIFT_WINDOWS_TRIAGE_REGISTRY_PROVENANCE.
  -h, --help         Show this help.

Environment:
  SIFT_OFFLINE=1     Equivalent to --offline.
  SIFT_CONTROL_PLANE_DSN (or DATABASE_URL/POSTGRES_DSN, or the installed
                       control-plane.env) is used only by installer-side
                       registry reconciliation. It is never sent to the MCP
                       subprocess or stored in the backend connection.
  SIFT_WINDOWS_TRIAGE_REGISTRY_SHA256
                       Required only for offline --with-registry. SHA-256 of
                       the staged decompressed known_good_registry.db.
  SIFT_WINDOWS_TRIAGE_REGISTRY_PROVENANCE
                       Required only for offline --with-registry. A concise,
                       non-secret release/source descriptor recorded locally.

The first-party pack fixes the runtime data directory at
/var/lib/sift/windows-triage. This lets sift-service use the backend's native
default and keeps the registry env_refs empty.
EOF
}

wintriage_require_staged_runtime() {
  local staged_root="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
  staged_root="${staged_root%/}"
  if [[ "$REPO_DIR" != "$staged_root" ]]; then
    die "Windows-triage pack must run from staged core runtime $staged_root, not $REPO_DIR. Re-run: sudo $staged_root/scripts/core-addons/setup-windows-triage.sh --install"
  fi
  [[ -x "$VENV_PYTHON" ]] \
    || die "Core runtime venv is missing at $VENV_DIR. Run the mandatory core installer first."
}

wintriage_validate_environment() {
  local configured_dir="${SIFT_WINDOWS_TRIAGE_DB_DIR:-${WT_DATA_DIR:-$WINTRIAGE_DEFAULT_DATA_DIR}}"
  if [[ "$configured_dir" != "$WINTRIAGE_DEFAULT_DATA_DIR" ]]; then
    die "First-party Windows-triage uses $WINTRIAGE_DEFAULT_DATA_DIR only. A custom directory would require a gateway child env_ref; this pack deliberately registers none."
  fi
  [[ -z "${WT_KNOWN_GOOD_DB:-}" && -z "${WT_CONTEXT_DB:-}" && -z "${WT_REGISTRY_DB:-}" ]] \
    || die "WT_*_DB overrides are not supported by the first-party pack; stage all baselines in $WINTRIAGE_DEFAULT_DATA_DIR."
}

wintriage_prepare_data_dir() {
  [[ ! -L "$WINTRIAGE_DEFAULT_DATA_DIR" ]] \
    || die "Refusing symlinked Windows-triage data directory: $WINTRIAGE_DEFAULT_DATA_DIR"
  sudo_if_needed install -d \
    -o "$SIFT_GATEWAY_SERVICE_USER" \
    -g "$SIFT_GATEWAY_SERVICE_USER" \
    -m 0750 \
    "$WINTRIAGE_DEFAULT_DATA_DIR"
}

wintriage_sync_runtime() {
  UV_BIN="$(resolve_uv)"
  [[ -n "$UV_BIN" ]] \
    || die "uv is required to install the Windows-triage pack. Install mandatory core first."

  local -a offline_flag=()
  if is_offline; then
    offline_flag=(--offline)
  fi
  log "Installing Windows-triage into the existing core runtime without pruning core packages."
  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
    "$UV_BIN" sync --inexact --extra windows-triage \
      --project "$REPO_DIR" \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python --no-python-downloads \
      "${offline_flag[@]}"
  [[ -x "$VENV_DIR/bin/$WINTRIAGE_ENTRYPOINT" ]] \
    || die "Windows-triage entrypoint missing after sync: $VENV_DIR/bin/$WINTRIAGE_ENTRYPOINT"
}

wintriage_write_offline_registry_provenance() {
  local registry_path="$WINTRIAGE_DEFAULT_DATA_DIR/$WINTRIAGE_REGISTRY_DB"
  local expected_sha="${SIFT_WINDOWS_TRIAGE_REGISTRY_SHA256:-}"
  local source_descriptor="${SIFT_WINDOWS_TRIAGE_REGISTRY_PROVENANCE:-}"

  [[ "$expected_sha" =~ ^[A-Fa-f0-9]{64}$ ]] \
    || die "Offline registry staging requires SIFT_WINDOWS_TRIAGE_REGISTRY_SHA256 (64 hex characters)."
  [[ -n "$source_descriptor" && ${#source_descriptor} -le 512 && "$source_descriptor" != *$'\n'* ]] \
    || die "Offline registry staging requires single-line SIFT_WINDOWS_TRIAGE_REGISTRY_PROVENANCE (at most 512 characters)."
  svc_test_f "$registry_path" \
    || die "Offline registry baseline is missing: $registry_path. Stage the verified decompressed file first."
  local actual_sha
  actual_sha="$(sudo_if_needed sha256sum "$registry_path" | awk '{print $1}')"
  [[ "$actual_sha" == "${expected_sha,,}" ]] \
    || die "Offline registry baseline hash verification failed: $registry_path"

  REGISTRY_PATH="$registry_path" \
  REGISTRY_SHA256="${expected_sha,,}" \
  REGISTRY_SOURCE="$source_descriptor" \
  REGISTRY_PROVENANCE_PATH="$WINTRIAGE_DEFAULT_DATA_DIR/$WINTRIAGE_REGISTRY_PROVENANCE" \
  sudo_if_needed -u "$SIFT_GATEWAY_SERVICE_USER" env \
    REGISTRY_PATH="$registry_path" \
    REGISTRY_SHA256="${expected_sha,,}" \
    REGISTRY_SOURCE="$source_descriptor" \
    REGISTRY_PROVENANCE_PATH="$WINTRIAGE_DEFAULT_DATA_DIR/$WINTRIAGE_REGISTRY_PROVENANCE" \
    "$SYSTEM_PYTHON" - <<'PY'
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

out = Path(os.environ["REGISTRY_PROVENANCE_PATH"])
payload = {
    "schema": "sift.windows-triage.registry-provenance/v1",
    "asset": Path(os.environ["REGISTRY_PATH"]).name,
    "sha256": os.environ["REGISTRY_SHA256"],
    "source": os.environ["REGISTRY_SOURCE"],
    "verified_at": datetime.now(UTC).isoformat(),
}
with tempfile.NamedTemporaryFile(
    mode="w", encoding="utf-8", dir=out.parent, prefix=f".{out.name}.", delete=False
) as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
    temporary = Path(handle.name)
os.replace(temporary, out)
os.chmod(out, 0o640)
PY
}

wintriage_stage_or_download_baselines() {
  local with_registry="$1"
  local known_good="$WINTRIAGE_DEFAULT_DATA_DIR/known_good.db"
  local context="$WINTRIAGE_DEFAULT_DATA_DIR/context.db"

  if is_offline; then
    svc_test_f "$known_good" \
      || die "SIFT_OFFLINE=1: baseline is missing: $known_good. Stage the verified decompressed file before rerunning."
    svc_test_f "$context" \
      || die "SIFT_OFFLINE=1: baseline is missing: $context. Stage the verified decompressed file before rerunning."
    if [[ "$with_registry" == "1" ]]; then
      wintriage_write_offline_registry_provenance
    fi
    return
  fi

  local -a registry_flag=()
  if [[ "$with_registry" == "1" ]]; then
    registry_flag=(--with-registry --yes)
  fi
  SIFT_WINDOWS_TRIAGE_DB_DIR="$WINTRIAGE_DEFAULT_DATA_DIR" \
    "$VENV_PYTHON" -m windows_triage_mcp.scripts.download_databases \
      --dest "$WINTRIAGE_DEFAULT_DATA_DIR" "${registry_flag[@]}"
}

wintriage_set_service_readable() {
  local filename path
  for filename in known_good.db context.db "$WINTRIAGE_REGISTRY_DB" "$WINTRIAGE_REGISTRY_PROVENANCE"; do
    path="$WINTRIAGE_DEFAULT_DATA_DIR/$filename"
    [[ -e "$path" ]] || continue
    [[ ! -L "$path" ]] || die "Refusing symlinked Windows-triage baseline artifact: $path"
    sudo_if_needed chown "$SIFT_GATEWAY_SERVICE_USER:$SIFT_GATEWAY_SERVICE_USER" "$path"
    sudo_if_needed chmod 0640 "$path"
  done
}

wintriage_validate_backend() {
  local registry_path="$WINTRIAGE_DEFAULT_DATA_DIR/$WINTRIAGE_REGISTRY_DB"
  sudo_if_needed -u "$SIFT_GATEWAY_SERVICE_USER" env \
    -u SIFT_CONTROL_PLANE_DSN -u DATABASE_URL -u POSTGRES_DSN \
    SIFT_WINDOWS_TRIAGE_DB_DIR="$WINTRIAGE_DEFAULT_DATA_DIR" \
    "$VENV_PYTHON" - "$registry_path" <<'PY'
import sys
from pathlib import Path

from windows_triage_mcp.server import WindowsTriageServer

server = WindowsTriageServer()
registry = Path(sys.argv[1])
print(
    "windows-triage baseline health: "
    f"known_good={server.known_good_db.is_available()} "
    f"context={server.context_db.is_available()} "
    f"registry={registry.exists() and server.registry_db is not None}"
)
if not server.known_good_db.is_available() or not server.context_db.is_available():
    raise SystemExit("required Windows-triage baseline validation failed")
PY
}

wintriage_reconcile_registry() {
  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"
  [[ -n "$cp_dsn" ]] \
    || die "No control-plane DSN is available for Windows-triage registry reconciliation. Restore $SIFT_HOME/control-plane.env or provide SIFT_CONTROL_PLANE_DSN, then rerun this pack."

  # Installer-side DB-authoritative registration. Empty env_refs is a security
  # invariant: the backend child receives no control-plane/DB credential.
  SEED_CP_DSN="$cp_dsn" \
    _seed_one_addon_backend \
      "$WINTRIAGE_BACKEND_NAME" \
      "$REPO_DIR/packages/windows-triage-mcp/sift-backend.json" \
      "$WINTRIAGE_ENTRYPOINT" \
      '{}'
}

wintriage_main() {
  local install=0 with_registry=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install) install=1 ;;
      --with-registry) with_registry=1 ;;
      --offline) SIFT_OFFLINE=1 ;;
      -h|--help) wintriage_usage; return 0 ;;
      *) die "Unknown Windows-triage pack option: $1. Run --help for usage." ;;
    esac
    shift
  done
  [[ "$install" == "1" ]] \
    || die "Refusing implicit Windows-triage installation. Re-run with --install."
  export SIFT_OFFLINE

  wintriage_require_staged_runtime
  wintriage_validate_environment
  wintriage_prepare_data_dir
  wintriage_sync_runtime
  wintriage_stage_or_download_baselines "$with_registry"
  wintriage_set_service_readable
  wintriage_validate_backend
  wintriage_reconcile_registry

  log "Windows-triage core add-on is installed and reconciled. Re-run: sudo $REPO_DIR/scripts/core-addons/setup-windows-triage.sh --install"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  wintriage_main "$@"
fi
