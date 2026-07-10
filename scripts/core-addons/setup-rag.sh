#!/usr/bin/env bash
set -Eeuo pipefail

# First-party RAG core-addon installer.
#
# This command is intentionally separate from scripts/setup-addon.sh: RAG is a
# SIFT-owned pack, not an external integration.  It installs the `rag` extra
# additively, verifies the shipped corpus SHA-256 manifest, seeds pgvector
# through an installer-owned gateway module, and reconciles the trusted
# gateway-owned registry record.  The resulting RAG runtime is in-process in
# sift-gateway; no RAG stdio subprocess is given a control-plane DSN.
#
# Usage:
#   scripts/core-addons/setup-rag.sh --install [--offline]
#
# Offline mode does no network I/O.  Stage the hash-pinned wheels in the uv
# cache and the canonical BGE model revision under $SIFT_HF_HOME first.

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

readonly RAG_MODEL_NAME="BAAI/bge-base-en-v1.5"
readonly RAG_MODEL_REVISION="a5beb1e3e68b9ab74eb54cfd186867f64f240e1a"
readonly KNOWLEDGE_DIR="$REPO_DIR/packages/forensic-rag-mcp/knowledge"
readonly KNOWLEDGE_MANIFEST="$KNOWLEDGE_DIR/manifest.sha256"
readonly RAG_MANIFEST="$REPO_DIR/packages/forensic-rag-mcp/sift-backend.json"

[[ -x "$VENV_PYTHON" ]] || die \
  "SIFT core runtime venv is missing at $VENV_PYTHON. Run ./install.sh first."
[[ -d "$KNOWLEDGE_DIR" && -f "$KNOWLEDGE_MANIFEST" && -f "$RAG_MANIFEST" ]] || die \
  "RAG pack artifacts are incomplete. Restore the shipped knowledge corpus and manifest, then rerun $0 --install."

UV_BIN="$(resolve_uv)"
[[ -n "$UV_BIN" ]] || die "uv is required to install the RAG pack; install uv then rerun $0 --install."

sync_flags=(sync --inexact --extra rag --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads)
if is_offline; then
  sync_flags+=(--offline)
fi
log "Installing first-party RAG runtime extra into the existing SIFT venv."
if is_offline; then
  sync_env=(UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never UV_OFFLINE=1)
else
  sync_env=(UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never)
fi
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
log "Verifying pinned RAG corpus and seeding pgvector through the gateway authority path."
if ! (
  cd "$SIFT_STATE_DIR"
  "${as_gateway_service[@]}" env \
    SIFT_CONTROL_PLANE_DSN="$cp_dsn" \
    HF_HOME="$SIFT_HF_HOME" \
    HF_HUB_OFFLINE="$hf_offline" \
    TRANSFORMERS_OFFLINE="$hf_offline" \
    "$VENV_PYTHON" -m sift_gateway.rag_provision \
      --knowledge-dir "$KNOWLEDGE_DIR" \
      --manifest "$KNOWLEDGE_MANIFEST" \
      --model-name "$RAG_MODEL_NAME" \
      --model-revision "$RAG_MODEL_REVISION"
); then
  if is_offline; then
    die "Offline RAG provisioning failed. Stage canonical BGE model revision $RAG_MODEL_REVISION under $SIFT_HF_HOME and verify the shipped corpus manifest before rerunning $0 --install --offline."
  fi
  die "RAG pgvector provisioning failed. Check the control plane and pinned model/corpus artifacts, then rerun $0 --install."
fi

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

log "RAG core add-on ready: pinned corpus seeded, gateway-owned registry reconciled."
rerun="$0 --install"
[[ "$offline_requested" -eq 1 ]] && rerun+=" --offline"
log "Health probe: kb_get_knowledge_stats. Rerun: $rerun"
