#!/usr/bin/env bash
# verify-ingest-prereqs.sh — verify all binaries and libraries required for
# E01 ingest are present on this SIFT VM before Phase R6 integration testing.
# Run: bash scripts/verify-ingest-prereqs.sh
set -euo pipefail

FAIL=0
PASS=0

_check() {
    local label="$1"; shift
    if "$@" &>/dev/null; then
        echo "  OK  $label"
        PASS=$(( PASS + 1 ))
    else
        echo " MISS $label"
        FAIL=$(( FAIL + 1 ))
    fi
}

_check_cmd() {
    local label="$1"
    local cmd="$2"
    if command -v "$cmd" &>/dev/null; then
        echo "  OK  $label ($cmd)"
        PASS=$(( PASS + 1 ))
    else
        echo " MISS $label — install hint: ${3:-}"
        FAIL=$(( FAIL + 1 ))
    fi
}

echo "=== Mount tools ==="
_check_cmd "ewfmount (libewf)" ewfmount "apt install libewf-dev"
_check_cmd "fusermount (fuse)" fusermount "apt install fuse"
_check_cmd "fdisk (util-linux)" fdisk "apt install util-linux"
_check "passwordless sudo for mount" sudo -n mount --version

echo
echo "=== Zimmerman Tools ==="
_check_cmd "AmcacheParser" AmcacheParser "download from https://ericzimmerman.github.io/"
_check_cmd "AppCompatCacheParser" AppCompatCacheParser "download from https://ericzimmerman.github.io/"
_check_cmd "RECmd" RECmd "download from https://ericzimmerman.github.io/"
_check_cmd "MFTECmd" MFTECmd "download from https://ericzimmerman.github.io/"
_check_cmd "JLECmd" JLECmd "download from https://ericzimmerman.github.io/"
_check_cmd "LECmd" LECmd "download from https://ericzimmerman.github.io/"
_check_cmd "SBECmd" SBECmd "download from https://ericzimmerman.github.io/"

echo
echo "=== Detection ==="
if command -v hayabusa &>/dev/null && file -L "$(which hayabusa)" 2>/dev/null | grep -q "ELF"; then
    echo "  OK  hayabusa ($(hayabusa help 2>&1 | head -1))"
    PASS=$(( PASS + 1 ))
else
    echo " MISS hayabusa — install via install.sh or download from https://github.com/Yamato-Security/hayabusa"
    FAIL=$(( FAIL + 1 ))
fi
# Check rules in both possible locations
RULES_OK=0
for d in "$HOME/.agentir/hayabusa-rules" "/usr/local/share/hayabusa-rules"; do
    if [[ -d "$d" ]] && [[ $(find "$d" -name '*.yml' 2>/dev/null | wc -l) -gt 100 ]]; then
        echo "  OK  hayabusa-rules ($d: $(find "$d" -name '*.yml' | wc -l) YAML files)"
        PASS=$(( PASS + 1 ))
        RULES_OK=1
        break
    fi
done
[[ "$RULES_OK" -eq 1 ]] || { echo " MISS hayabusa-rules — run install.sh (rules are bundled with hayabusa release)"; FAIL=$(( FAIL + 1 )); }

echo
echo "=== Python libraries ==="
# Check inside the uv project venv (same Python that opensearch-mcp runs under)
_UV="$(command -v uv 2>/dev/null || echo "${HOME}/.local/bin/uv")"
_UV_RUN() { "$_UV" run --project "$(dirname "$(dirname "$0")")" --python /usr/bin/python3.12 --no-managed-python --no-python-downloads "$@" 2>/dev/null; }
_check "evtx (pyevtx-rs)" _UV_RUN python3 -c "import evtx"
_check "regipy" _UV_RUN python3 -c "import regipy"

echo
echo "=== OpenSearch ==="
if curl -s "http://127.0.0.1:9200/_cluster/health" 2>/dev/null | grep -q '"status"'; then
    echo "  OK  OpenSearch reachable at http://127.0.0.1:9200"
    PASS=$(( PASS + 1 ))
else
    echo " MISS OpenSearch not reachable at http://127.0.0.1:9200 — check: docker ps | grep opensearch"
    FAIL=$(( FAIL + 1 ))
fi

echo
echo "=== Result: $PASS passed, $FAIL missing ==="
exit $FAIL
