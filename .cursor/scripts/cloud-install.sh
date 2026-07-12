#!/usr/bin/env bash
# Cursor Cloud environment install hook (runs on VM startup after git pull).
set -euo pipefail

log() { printf '[cloud-install] %s\n' "$*"; }

# Prefer the workspace toolchain over the base image's stale Node 22.
export PATH="$HOME/.local/bin:$PATH"

if ! command -v tailscale >/dev/null 2>&1; then
  log "Installing Tailscale"
  curl -fsSL https://tailscale.com/install.sh | sh
fi

# Persist proxy + CA env for shells and MCP HTTP clients that honor standard vars.
PROFILE_SNIPPET="$HOME/.cursor-cloud-tailscale.env"
cat > "$PROFILE_SNIPPET" <<'ENV'
# Persistent Cursor Cloud toolchain plus Tailscale network env when ready.
# Node 24 must win over the base image's stale Node 22 for later agent shells.
export PATH="$HOME/.nvm/versions/node/v24.13.1/bin:$HOME/.local/bin:$PATH"
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
    # shellcheck disable=SC2016 # Keep $HOME literal for the shell that later sources this file.
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
# Pin the bootstrap version so a cold image does not depend on an unversioned
# moving branch. PROFILE=/dev/null keeps this non-interactive hook from
# rewriting user shell profiles; the hook owns PATH for its own process.
# This hook owns its runtime toolchain; do not source an arbitrary caller path.
export NVM_DIR="$HOME/.nvm"
NVM_VERSION="v0.40.3"
NVM_INSTALL_URL="https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh"
NVM_INSTALL_SHA256="2d8359a64a3cb07c02389ad88ceecd43f2fa469c06104f92f98df5b6f315275f"

install_nvm() {
  local install_script

  if ! command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "ERROR: sha256sum is required to verify the nvm installer" >&2
    return 1
  fi

  install_script="$(mktemp)"
  if ! curl --fail --show-error --location --proto '=https' --tlsv1.2 \
    "$NVM_INSTALL_URL" --output "$install_script"; then
    rm -f "$install_script"
    return 1
  fi

  if ! printf '%s  %s\n' "$NVM_INSTALL_SHA256" "$install_script" \
    | sha256sum --check --status; then
    printf '%s\n' "ERROR: nvm installer checksum verification failed" >&2
    rm -f "$install_script"
    return 1
  fi

  if ! NVM_INSTALL_VERSION="$NVM_VERSION" PROFILE=/dev/null bash "$install_script"; then
    rm -f "$install_script"
    return 1
  fi
  rm -f "$install_script"
}

if [[ ! -x "$NVM_DIR/versions/node/v24.13.1/bin/node" ]]; then
  if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
    log "Installing nvm"
    install_nvm
  fi

  log "Installing Node 24.13.1 via nvm"
  # nvm.sh is not nounset-clean; relax -u only while sourcing/using it.
  set +u
  if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
    printf '%s\n' "ERROR: nvm bootstrap did not create $NVM_DIR/nvm.sh" >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source "$NVM_DIR/nvm.sh"
  if ! command -v nvm >/dev/null 2>&1; then
    printf '%s\n' "ERROR: nvm bootstrap did not provide the nvm command" >&2
    exit 1
  fi
  nvm install 24.13.1
  nvm alias default 24.13.1
  set -u
fi

export PATH="$NVM_DIR/versions/node/v24.13.1/bin:$PATH"

log "Syncing Python workspace deps (uv sync --locked)"
uv sync --locked \
  --extra core --extra rag --extra opencti --extra windows-triage --extra dev

if [[ -f "$REPO_ROOT/packages/case-dashboard/frontend/package.json" ]]; then
  log "Installing portal frontend deps (npm ci)"
  npm --prefix "$REPO_ROOT/packages/case-dashboard/frontend" ci
fi

log "Install complete"
