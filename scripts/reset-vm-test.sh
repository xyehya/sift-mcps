#!/usr/bin/env bash
# reset-vm-test.sh — reset SIFT VM to a clean state for start-to-end pipeline testing
#
# Usage:
#   ./scripts/reset-vm-test.sh [--case CASE_ID] [--wipe-case] [--help]
#
#   --case CASE_ID   Case to wipe indices for (default: from gateway.yaml)
#   --wipe-case      Also delete the case directory (prompts for y/N confirmation)
#   --help           Show this message
#
# What this does:
#   1. Finds the active case from gateway.yaml
#   2. Deletes all OpenSearch indices for that case (case-{case_id}-*)
#   3. Optionally removes the case directory from /cases/
#   4. Kills and restarts the gateway process
#   5. Reports health
#
# After reset, the operator must:
#   1. Open portal → create a new case (or re-activate via gateway.yaml)
#   2. Copy evidence to /cases/{case_id}/evidence/
#   3. Seal via portal → Evidence tab
#   4. Start the agent

set -euo pipefail

OPENSEARCH_URL="http://localhost:9200"
GATEWAY_YAML="${HOME}/.agentir/gateway.yaml"
CASE_ID=""
WIPE_CASE=false
CASE_DIR_DELETED=false

# Locate uv — it's never in PATH for non-login shells on this VM
UV="${HOME}/.local/bin/uv"
UV_PROJECT="${HOME}/sift-mcps-test"
UV_PYTHON="/usr/bin/python3.12"

usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -22
    exit 0
}

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[reset] $*"; }

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)      CASE_ID="$2"; shift 2 ;;
        --wipe-case) WIPE_CASE=true; shift ;;
        --help|-h)   usage ;;
        *)           die "Unknown argument: $1" ;;
    esac
done

# Resolve case_id from gateway.yaml if not provided
if [[ -z "$CASE_ID" ]]; then
    [[ -f "$GATEWAY_YAML" ]] || die "gateway.yaml not found at $GATEWAY_YAML"
    CASE_DIR=$(python3 -c "
import yaml
c = yaml.safe_load(open('$GATEWAY_YAML'))
print(c.get('case', {}).get('dir', ''))
" 2>/dev/null || true)
    [[ -n "$CASE_DIR" ]] && CASE_ID=$(basename "$CASE_DIR")
fi

[[ -z "$CASE_ID" ]] && die "Could not resolve case_id. Pass --case CASE_ID or set case.dir in gateway.yaml"

info "Target case: $CASE_ID"

# -------------------------------------------------------------------------
# Step 1: Wipe OpenSearch indices for this case
# -------------------------------------------------------------------------
info "Checking OpenSearch..."
OS_HEALTH=$(curl -sf "${OPENSEARCH_URL}/_cluster/health" 2>/dev/null) \
    || die "OpenSearch not reachable at ${OPENSEARCH_URL}"
info "OpenSearch status: $(echo "$OS_HEALTH" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","?"))')"

PATTERN="case-${CASE_ID}-*"
INDICES=$(curl -sf "${OPENSEARCH_URL}/_cat/indices/${PATTERN}?h=index" 2>/dev/null | tr '\n' ' ' || true)

if [[ -z "${INDICES// }" ]]; then
    info "No OpenSearch indices found matching: ${PATTERN}"
else
    info "Found indices: $INDICES"
    echo -n "[reset] Delete these indices? [y/N] "
    read -r CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        curl -sf -X DELETE "${OPENSEARCH_URL}/${PATTERN}" \
            | python3 -c 'import json,sys; r=json.load(sys.stdin); print("[reset] Delete result:", "acknowledged" if r.get("acknowledged") else r)' \
            2>/dev/null \
            || info "Index delete returned non-JSON (may still have succeeded)"
        info "Indices wiped."
    else
        info "Skipped index deletion."
    fi
fi

# -------------------------------------------------------------------------
# Step 2: Optionally wipe the case directory
# -------------------------------------------------------------------------
if $WIPE_CASE; then
    CASES_ROOT=$(python3 -c "
import yaml
c = yaml.safe_load(open('$GATEWAY_YAML'))
print(c.get('case', {}).get('root', '/cases'))
" 2>/dev/null || echo "/cases")
    TARGET_DIR="${CASES_ROOT}/${CASE_ID}"

    if [[ -d "$TARGET_DIR" ]]; then
        info "Case directory: $TARGET_DIR"
        echo -n "[reset] PERMANENTLY DELETE $TARGET_DIR? [y/N] "
        read -r CONFIRM2
        if [[ "$CONFIRM2" =~ ^[Yy]$ ]]; then
            # Remove immutable flags on any sealed evidence files before deleting
            find "$TARGET_DIR" -type f 2>/dev/null | while read -r f; do
                sudo chattr -i "$f" 2>/dev/null || true
            done
            rm -rf "$TARGET_DIR"
            CASE_DIR_DELETED=true
            info "Case directory deleted."
            # Clear case.dir in gateway.yaml so gateway starts in no-case mode
            python3 -c "
import yaml
p = '$GATEWAY_YAML'
c = yaml.safe_load(open(p))
c.setdefault('case', {})['dir'] = ''
open(p, 'w').write(yaml.dump(c, default_flow_style=False))
" 2>/dev/null && info "gateway.yaml case.dir cleared." || info "WARNING: Could not update gateway.yaml"
        else
            info "Skipped case directory deletion."
        fi
    else
        info "Case directory not found: $TARGET_DIR (already clean)"
        CASE_DIR_DELETED=true
    fi
fi

# -------------------------------------------------------------------------
# Step 3: Kill and restart gateway
# -------------------------------------------------------------------------
info "Restarting gateway..."

# Kill all gateway processes (uv launcher + python worker)
GATEWAY_PIDS=$(pgrep -f "sift-gateway" 2>/dev/null || true)
if [[ -n "$GATEWAY_PIDS" ]]; then
    info "Killing gateway PIDs: $GATEWAY_PIDS"
    echo "$GATEWAY_PIDS" | xargs kill 2>/dev/null || true
    sleep 3
fi

# Locate uv
[[ -x "$UV" ]] || die "uv not found at $UV. Adjust UV= in this script."

# Restart gateway in background using same invocation observed via ps
nohup "$UV" run \
    --project "$UV_PROJECT" \
    --python "$UV_PYTHON" \
    --no-managed-python \
    --no-python-downloads \
    sift-gateway --config "$GATEWAY_YAML" \
    >>"${HOME}/.agentir/gateway.log" 2>&1 &

GW_PID=$!
info "Gateway launched (PID $GW_PID). Log: ~/.agentir/gateway.log"

# -------------------------------------------------------------------------
# Step 4: Wait for health
# -------------------------------------------------------------------------
info "Waiting for gateway to become healthy..."
HEALTHY=false
for i in {1..15}; do
    sleep 2
    HEALTH=$(curl -sk "https://localhost:4508/health" 2>/dev/null \
             || curl -sf "http://localhost:4508/health" 2>/dev/null \
             || true)
    if [[ -n "$HEALTH" ]]; then
        TOOL_COUNT=$(echo "$HEALTH" | python3 -c \
            'import json,sys; print(json.load(sys.stdin).get("tools_count","?"))' 2>/dev/null || echo "?")
        STATUS=$(echo "$HEALTH" | python3 -c \
            'import json,sys; print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo "?")
        info "Gateway healthy — status: $STATUS | tools: $TOOL_COUNT"
        HEALTHY=true
        break
    fi
    info "Waiting... ($i/15)"
done

$HEALTHY || info "WARNING: Gateway did not respond after 30s. Check ~/.agentir/gateway.log"

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
echo ""
echo "=== Reset complete ==="
echo "Case:       $CASE_ID"
echo "Indices:    wiped for pattern case-${CASE_ID}-*"
if $WIPE_CASE; then
    $CASE_DIR_DELETED && echo "Case dir:   deleted" || echo "Case dir:   NOT deleted (user declined)"
else
    echo "Case dir:   kept (use --wipe-case to delete)"
fi
echo ""
echo "Next steps for start-to-end pipeline test:"
echo "  1. Copy evidence to /cases/{new_case_id}/evidence/"
echo "  2. Portal → New Case → enter casename → create"
echo "  3. Portal → Evidence tab → Seal Manifest"
echo "  4. Agent: case_status → evidence_list → idx_ingest(...)"
