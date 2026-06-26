#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
frontend_root="$repo_root/packages/case-dashboard/frontend"
cd "$frontend_root"

exec npm exec -- typescript-language-server --stdio
