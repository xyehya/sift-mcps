#!/usr/bin/env bash
# Cursor Cloud environment install hook (runs on VM startup after git pull).
set -euo pipefail

log() { printf '[cloud-install] %s\n' "$*"; }

# Node 24 for frontend (nvm); stale exec-daemon node v22 shadows it on default PATH.
export PATH="$HOME/.nvm/versions/node/v24.13.1/bin:$HOME/.local/bin:$PATH"

if ! command -v tailscale >/dev/null 2>&1; then
  log "Installing Tailscale"
  curl -fsSL https://tailscale.com/install.sh | sh
fi

# Persist proxy + CA env for shells and MCP HTTP clients that honor standard vars.
PROFILE_SNIPPET="$HOME/.cursor-cloud-tailscale.env"
cat > "$PROFILE_SNIPPET" <<'ENV'
# Sourced by cloud agent shells when userspace Tailscale is ready.
if [[ -f /tmp/tailscaled.ready ]]; then
  export ALL_PROXY="socks5h://127.0.0.1:1055"
  export HTTPS_PROXY="http://127.0.0.1:1054"
  export HTTP_PROXY="http://127.0.0.1:1054"
  export NODE_EXTRA_CA_CERTS="/tmp/sift-ca.pem"
  export SSL_CERT_FILE="/tmp/sift-ca.pem"
  export REQUESTS_CA_BUNDLE="/tmp/sift-ca.pem"
fi
ENV

for rc in "$HOME/.bashrc" "$HOME/.profile"; do
  if [[ -f "$rc" ]] && ! grep -q 'cursor-cloud-tailscale.env' "$rc" 2>/dev/null; then
    printf '\n# Cursor Cloud Tailscale proxy env\n[ -f "$HOME/.cursor-cloud-tailscale.env" ] && . "$HOME/.cursor-cloud-tailscale.env"\n' >> "$rc"
  fi
done

# Host-native codebase-memory-mcp (Linux binary). Never commit the binary;
# portable MCP configs resolve via ${userHome} / PATH.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -x "$REPO_ROOT/scripts/cloud/bootstrap-agent-tools.sh" ]]; then
  log "Bootstrapping codebase-memory-mcp"
  bash "$REPO_ROOT/scripts/cloud/bootstrap-agent-tools.sh"
else
  log "WARN: scripts/cloud/bootstrap-agent-tools.sh missing — skip MCP binary install"
fi

# --- Project dependency toolchain (Python workspace + portal frontend) ---
# The base image is NOT guaranteed to ship uv or Node 24, and the committed
# .cursor/environment.json is the single source of truth for setup (no external
# snapshot deps). Install idempotently so a fresh VM comes up able to lint/test/
# build/run. No secrets are read or written here.
if [[ ! -x "$HOME/.local/bin/uv" ]] && ! command -v uv >/dev/null 2>&1; then
  log "Installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Node 24.13.1 via nvm — frontend engines require >=24.13.1 <25.
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if [[ ! -x "$NVM_DIR/versions/node/v24.13.1/bin/node" ]]; then
  log "Installing Node 24.13.1 via nvm"
  # nvm.sh is not nounset-clean; relax -u only while sourcing/using it.
  set +u
  # shellcheck source=/dev/null
  [[ -s "$NVM_DIR/nvm.sh" ]] && . "$NVM_DIR/nvm.sh"
  nvm install 24.13.1
  nvm alias default 24.13.1
  set -u
fi

log "Syncing Python workspace deps (uv sync --locked)"
uv sync --locked \
  --extra core --extra rag --extra opencti --extra windows-triage --extra dev

if [[ -f "$REPO_ROOT/packages/case-dashboard/frontend/package.json" ]]; then
  log "Installing portal frontend deps (npm ci)"
  npm --prefix "$REPO_ROOT/packages/case-dashboard/frontend" ci
fi

log "Install complete"
