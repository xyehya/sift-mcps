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
# SIFT_HOME moved under the service user's home in the non-admin cutover; the
# config is owned sift-service 0600, so reads/writes below go through sudo.
GATEWAY_YAML="${SIFT_HOME:-/var/lib/sift/.sift}/gateway.yaml"
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
    sudo test -f "$GATEWAY_YAML" || die "gateway.yaml not found at $GATEWAY_YAML"
    CASE_DIR=$(sudo cat "$GATEWAY_YAML" | python3 -c "
import yaml, sys
c = yaml.safe_load(sys.stdin)
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
    CASES_ROOT=$(sudo cat "$GATEWAY_YAML" | python3 -c "
import yaml, sys
c = yaml.safe_load(sys.stdin)
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
            # Clear case.dir in gateway.yaml so gateway starts in no-case mode.
            # The config is owned sift-service 0600: render to a temp, then
            # sudo-install back preserving sift-service ownership/mode.
            _RVT_TMP=$(mktemp)
            if sudo cat "$GATEWAY_YAML" | python3 -c "
import yaml, sys
c = yaml.safe_load(sys.stdin)
c.setdefault('case', {})['dir'] = ''
sys.stdout.write(yaml.dump(c, default_flow_style=False))
" > "$_RVT_TMP" 2>/dev/null && [[ -s "$_RVT_TMP" ]]; then
                sudo install -o sift-service -g sift-service -m 600 "$_RVT_TMP" "$GATEWAY_YAML" \
                    && info "gateway.yaml case.dir cleared." \
                    || info "WARNING: Could not write gateway.yaml"
            else
                info "WARNING: Could not update gateway.yaml"
            fi
            rm -f "$_RVT_TMP"
        else
            info "Skipped case directory deletion."
        fi
    else
        info "Case directory not found: $TARGET_DIR (already clean)"
        CASE_DIR_DELETED=true
    fi
fi

# -------------------------------------------------------------------------
# Step 3: Restart gateway (systemd system service — matches install.sh)
# -------------------------------------------------------------------------
info "Restarting gateway..."

# install.sh ships the gateway as a systemd system service (running as the
# dedicated non-admin user sift-service) that runs the venv binary directly
# (.venv/bin/sift-gateway). Prefer restarting that unit so we match the
# production service path; fall back to launching the venv binary directly
# only if the unit is absent.
if systemctl list-unit-files sift-gateway.service >/dev/null 2>&1 \
   && systemctl cat sift-gateway.service >/dev/null 2>&1; then
    sudo systemctl restart sift-gateway.service \
        && info "Restarted sift-gateway.service (systemd system)." \
        || info "WARNING: sudo systemctl restart sift-gateway.service failed."
else
    info "No sift-gateway.service unit found — falling back to direct venv binary."
    GATEWAY_PIDS=$(pgrep -f "sift-gateway" 2>/dev/null || true)
    if [[ -n "$GATEWAY_PIDS" ]]; then
        info "Killing gateway PIDs: $GATEWAY_PIDS"
        echo "$GATEWAY_PIDS" | xargs kill 2>/dev/null || true
        sleep 2
    fi
    GW_BIN=""
    for cand in "${UV_PROJECT}/.venv/bin/sift-gateway" "${HOME}/sift-mcps/.venv/bin/sift-gateway"; do
        [[ -x "$cand" ]] && { GW_BIN="$cand"; break; }
    done
    [[ -n "$GW_BIN" ]] || die "Could not find .venv/bin/sift-gateway. Re-run install.sh."
    nohup "$GW_BIN" --config "$GATEWAY_YAML" \
        >>"${HOME}/.sift/gateway.log" 2>&1 &
    info "Gateway launched directly (PID $!). Log: ~/.sift/gateway.log"
fi

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

$HEALTHY || info "WARNING: Gateway did not respond after 30s. Check ~/.sift/gateway.log"

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
echo "  4. Agent: case_status → evidence_list → opensearch_ingest(...)"
