#!/usr/bin/env bash
# Cursor Cloud environment start hook (runs once when the VM boots).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/cloud-tailscale-up.sh"
