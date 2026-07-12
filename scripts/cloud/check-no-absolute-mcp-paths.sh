#!/usr/bin/env bash
# Fail if committed agent MCP configs embed machine-absolute home paths.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FILES=(
  "$ROOT/.cursor/mcp.json"
  "$ROOT/.mcp.json"
  "$ROOT/.codex/config.toml"
  "$ROOT/opencode.json"
)

bad=0
for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || continue
  if grep -Ene '/Users/|/home/[a-zA-Z0-9._-]+/|C:\\Users\\' "$f" >/dev/null 2>&1; then
    echo "FAIL: absolute machine path in $f" >&2
    grep -Ene '/Users/|/home/[a-zA-Z0-9._-]+/|C:\\Users\\' "$f" >&2 || true
    bad=1
  fi
done

if [[ "$bad" -ne 0 ]]; then
  echo "Use \${userHome}/.local/bin/... (Cursor) or bare 'codebase-memory-mcp' on PATH." >&2
  exit 1
fi

echo "OK: no absolute home paths in MCP agent configs"
