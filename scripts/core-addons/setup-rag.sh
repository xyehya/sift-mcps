#!/usr/bin/env bash
set -Eeuo pipefail

# First-party RAG core-addon installer.
#
# This command is intentionally separate from scripts/setup-addon.sh: RAG is a
# SIFT-owned pack, not an external integration.  It installs the `rag` extra
# additively, verifies the shipped portable snapshot, imports pgvector
# through an installer-owned gateway module, and reconciles the trusted
# gateway-owned registry record.  The resulting RAG runtime is in-process in
# sift-gateway; no RAG stdio subprocess is given a control-plane DSN.
#
# Usage:
#   scripts/core-addons/setup-rag.sh --install [--offline]
#
# Offline mode does no network I/O. Stage the hash-pinned wheels and canonical
# Qwen model revision under $SIFT_HF_HOME first; the snapshot ships with SIFT.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=lib/bootstrap.sh
source "$REPO_DIR/lib/bootstrap.sh"
sift_source_first_party_addon_libraries

usage() {
  cat <<'EOF'
Usage: scripts/core-addons/setup-rag.sh --install [--offline]

Install the first-party RAG pack after mandatory SIFT core is available.

  --install   Required non-interactive install mode (safe for install.sh).
  --offline   Refuse all package/model network access; require staged artifacts.
  --help      Show this message.
EOF
}

install_requested=0
offline_requested=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) install_requested=1 ;;
    --offline) offline_requested=1 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "unknown RAG core-addon option: $1" ;;
  esac
  shift
done
[[ "$install_requested" -eq 1 ]] || { usage >&2; die "--install is required"; }

if [[ "$offline_requested" -eq 1 ]]; then
  export SIFT_OFFLINE=1
fi

readonly RAG_MODEL_NAME="Qwen/Qwen3-Embedding-0.6B"
readonly RAG_MODEL_REVISION="97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3"
readonly RAG_SNAPSHOT_ARCHIVE="$REPO_DIR/artifacts/qwen3-embedding-0.6b-1024-sift-rag-v1.tar.zst"
readonly RAG_SNAPSHOT_SHA256="1030d3901d116c1c4fe7e82148da2eb07857afaebb0702a01aa2532273b870b4"
readonly RAG_MANIFEST="$REPO_DIR/packages/forensic-rag-mcp/sift-backend.json"

[[ -x "$VENV_PYTHON" ]] || die \
  "SIFT core runtime venv is missing at $VENV_PYTHON. Run ./install.sh first."
[[ -f "$RAG_SNAPSHOT_ARCHIVE" && -f "$RAG_MANIFEST" ]] || die \
  "RAG pack artifacts are incomplete. Restore the pinned Qwen snapshot and backend manifest, then rerun $0 --install."
verify_sha256 "$RAG_SNAPSHOT_ARCHIVE" "$RAG_SNAPSHOT_SHA256" || die \
  "RAG snapshot SHA-256 verification failed; restore the canonical release artifact."
require_cmd tar

mapfile -t snapshot_members < <(tar --zstd -tf "$RAG_SNAPSHOT_ARCHIVE" | LC_ALL=C sort)
expected_members=(
  "qwen3-embedding-0.6b-1024/"
  "qwen3-embedding-0.6b-1024/embeddings.f32.npy"
  "qwen3-embedding-0.6b-1024/manifest.json"
  "qwen3-embedding-0.6b-1024/records.jsonl"
)
[[ "${snapshot_members[*]}" == "${expected_members[*]}" ]] || die \
  "RAG snapshot member set is invalid; refusing extraction."

UV_BIN="$(resolve_uv)"
[[ -n "$UV_BIN" ]] || die "uv is required to install the RAG pack; install uv then rerun $0 --install."

sync_flags=(sync --inexact --extra rag --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads)
if is_offline; then
  sync_flags+=(--offline)
fi
log "Installing first-party RAG runtime extra into the existing SIFT venv."
sync_env=(UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never)
if is_offline; then
  sync_env=(UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never UV_OFFLINE=1)
fi
sync_env+=(
  "UV_CACHE_DIR=${UV_CACHE_DIR:-${SIFT_UV_CACHE_DIR:-/var/cache/sift/uv}}"
  "PIP_CACHE_DIR=${PIP_CACHE_DIR:-${SIFT_PIP_CACHE_DIR:-/var/cache/sift/pip}}"
)
if ! env "${sync_env[@]}" "$UV_BIN" "${sync_flags[@]}"; then
  if is_offline; then
    die "Offline RAG runtime install failed. Stage the hash-pinned rag wheel/dependency artifacts in the uv cache, then rerun $0 --install --offline."
  fi
  die "RAG runtime extra installation failed. Check the pinned dependency artifacts, then rerun $0 --install."
fi

cp_dsn="$(_resolved_control_plane_dsn)"
[[ -n "$cp_dsn" ]] || die \
  "RAG requires the gateway control-plane DSN for installer-owned pgvector provisioning. Configure core control-plane.env, then rerun $0 --install."

require_cmd id
id "$SIFT_GATEWAY_SERVICE_USER" >/dev/null 2>&1 || die \
  "Gateway service account $SIFT_GATEWAY_SERVICE_USER is unavailable. Complete mandatory core setup before installing RAG."
sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$SIFT_HF_HOME"

hf_offline=0
is_offline && hf_offline=1
as_gateway_service=()
if [[ "$(id -un)" != "$SIFT_GATEWAY_SERVICE_USER" ]]; then
  as_gateway_service=(sudo -u "$SIFT_GATEWAY_SERVICE_USER")
fi
snapshot_stage="$(sudo_if_needed mktemp -d -p "$SIFT_STATE_DIR" rag-qwen-snapshot.XXXXXX)"
trap 'sudo_if_needed rm -rf -- "${snapshot_stage:-}"' EXIT
sudo_if_needed chown "$SIFT_GATEWAY_SERVICE_USER:$SIFT_GATEWAY_SERVICE_USER" "$snapshot_stage"
"${as_gateway_service[@]}" tar --zstd -xf "$RAG_SNAPSHOT_ARCHIVE" -C "$snapshot_stage"

log "Verifying the pinned Qwen model/snapshot and importing pgvector through installer authority."
if ! (
  cd "$SIFT_STATE_DIR"
  "${as_gateway_service[@]}" env \
    SIFT_CONTROL_PLANE_DSN="$cp_dsn" \
    HF_HOME="$SIFT_HF_HOME" \
    HF_HUB_OFFLINE="$hf_offline" \
    TRANSFORMERS_OFFLINE="$hf_offline" \
    RAG_MODEL_NAME="$RAG_MODEL_NAME" \
    RAG_MODEL_REVISION="$RAG_MODEL_REVISION" \
    "$VENV_PYTHON" -m rag_mcp.pgvector_snapshot_import \
      "$snapshot_stage/qwen3-embedding-0.6b-1024"
); then
  if is_offline; then
    die "Offline RAG provisioning failed. Stage canonical Qwen revision $RAG_MODEL_REVISION under $SIFT_HF_HOME and verify the shipped snapshot before rerunning $0 --install --offline."
  fi
  die "RAG pgvector provisioning failed. The importer refuses a non-empty mismatched corpus; rebuild the disposable database or restore the canonical snapshot, then rerun $0 --install."
fi
sudo_if_needed rm -rf -- "$snapshot_stage"
snapshot_stage=""
trap - EXIT

reconcile_first_party_gateway_backend "forensic-rag-mcp" "$RAG_MANIFEST" || die \
  "RAG corpus was seeded but registry reconciliation failed. Restore gateway control-plane access and rerun $0 --install."

# When the gateway is already active, restart exactly that service so its
# registry reload sees the new gateway-owned pack immediately.  During a fresh
# install the unit may not exist yet; install.sh starts it after the pack.
if command -v systemctl >/dev/null 2>&1 && sudo_if_needed systemctl is-active --quiet sift-gateway; then
  log "Restarting active sift-gateway to load the RAG registry entry."
  sudo_if_needed systemctl restart sift-gateway
  sudo_if_needed systemctl is-active --quiet sift-gateway || die \
    "sift-gateway did not return active after RAG reconciliation; inspect systemctl status sift-gateway."
fi

log "RAG core add-on ready: pinned Qwen snapshot imported, gateway-owned registry reconciled."
rerun="$0 --install"
[[ "$offline_requested" -eq 1 ]] && rerun+=" --offline"
log "Health probe: kb_get_knowledge_stats. Rerun: $rerun"
