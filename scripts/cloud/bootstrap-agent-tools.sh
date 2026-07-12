#!/usr/bin/env bash
# Cloud / Linux agent bootstrap: install DeusData codebase-memory-mcp for THIS host.
# Does not rewrite agent MCP configs (repo already commits portable entries).
# Safe on macOS too, but intended for Cursor Cloud environment install/snapshot.
set -euo pipefail

INSTALL_SH_URL="${CODEBASE_MEMORY_MCP_INSTALL_URL:-https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/main/install.sh}"
BIN_DIR="${CODEBASE_MEMORY_MCP_DIR:-$HOME/.local/bin}"
BIN="$BIN_DIR/codebase-memory-mcp"

export PATH="$BIN_DIR:$PATH"

if [[ -x "$BIN" ]]; then
  echo "codebase-memory-mcp already present: $BIN ($("$BIN" --version 2>/dev/null || echo unknown))"
else
  echo "Installing codebase-memory-mcp into $BIN_DIR (skip agent config rewrite)..."
  curl -fsSL "$INSTALL_SH_URL" | bash -s -- --skip-config --dir="$BIN_DIR"
fi

if [[ ! -x "$BIN" ]]; then
  # install.sh may place on PATH under a different name/layout; resolve
  if command -v codebase-memory-mcp >/dev/null 2>&1; then
    BIN="$(command -v codebase-memory-mcp)"
  else
    echo "ERROR: codebase-memory-mcp not found after install" >&2
    exit 1
  fi
fi

echo "OK binary=$BIN"
"$BIN" --version || true

# Ensure login/non-login shells and agent PATH see ~/.local/bin
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "NOTE: add to PATH: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo "Bootstrap complete. Cursor MCP uses \${userHome}/.local/bin/codebase-memory-mcp;"
echo "Claude/Codex/OpenCode use bare command 'codebase-memory-mcp' on PATH."
