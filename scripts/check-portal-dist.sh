#!/usr/bin/env bash
# G8 — CI dist-freshness guard for the committed portal-v3 frontend build.
#
# WHY: install.sh ships a COMMITTED frontend build (the gateway mounts
# packages/case-dashboard/src/case_dashboard/static/v2 directly — there is no
# node on the install VM). That model silently depends on every frontend change
# re-committing the built dist. If a contributor edits frontend/src but forgets
# to rebuild + commit, the portal ships STALE assets and nobody notices.
#
# WHAT: rebuild the frontend from source and fail if the committed dist differs
# from the fresh build (i.e. the committed dist is stale / not reproducible).
#
# REQUIRES node + npm (see frontend/package.json engines: node >=24.13.1 <25).
# This is a CI-ONLY check — do NOT run it on the install VM (no node there).
#
# Usage:
#   scripts/check-portal-dist.sh
# Exit 0 = dist is fresh; non-zero = stale dist or build failure.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$REPO_ROOT/packages/case-dashboard/frontend"
DIST_DIR="$REPO_ROOT/packages/case-dashboard/src/case_dashboard/static/v2"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "check-portal-dist: node/npm not found — this is a CI-only check; skipping is NOT safe in CI." >&2
  echo "  Install node (>=24.13.1 <25) and npm, then re-run." >&2
  exit 2
fi

if [[ ! -d "$FRONTEND_DIR" ]]; then
  echo "check-portal-dist: frontend dir missing at $FRONTEND_DIR" >&2
  exit 2
fi

echo "check-portal-dist: installing frontend deps (npm ci) ..."
( cd "$FRONTEND_DIR" && npm ci )

echo "check-portal-dist: building frontend (npm run build -> $DIST_DIR) ..."
( cd "$FRONTEND_DIR" && npm run build )

echo "check-portal-dist: checking committed dist is in sync with the fresh build ..."
# Limit the diff to the dist dir so unrelated working-tree state is ignored.
if ! git -C "$REPO_ROOT" diff --exit-code -- "$DIST_DIR"; then
  echo "" >&2
  echo "check-portal-dist: FAIL — committed portal dist is STALE." >&2
  echo "  Rebuild and commit the dist:" >&2
  echo "    cd packages/case-dashboard/frontend && npm ci && npm run build" >&2
  echo "    git add packages/case-dashboard/src/case_dashboard/static/v2 && git commit" >&2
  exit 1
fi

echo "check-portal-dist: OK — committed portal dist matches a fresh build."
