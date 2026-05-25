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
_check_cmd "hayabusa" hayabusa "download from https://github.com/Yamato-Security/hayabusa"
if ls /usr/local/share/hayabusa-rules/config &>/dev/null; then
    echo "  OK  hayabusa-rules (/usr/local/share/hayabusa-rules/config)"
    PASS=$(( PASS + 1 ))
else
    echo " MISS hayabusa-rules — clone to /usr/local/share/hayabusa-rules"
    FAIL=$(( FAIL + 1 ))
fi

echo
echo "=== Python libraries ==="
_check "python-evtx" python3 -c "import evtx"
if [ $? -ne 0 ]; then echo "         pip install python-evtx"; fi
_check "regipy" python3 -c "import regipy"
if [ $? -ne 0 ]; then echo "         pip install regipy"; fi

echo
echo "=== OpenSearch ==="
if curl -sk "https://localhost:9200/_cluster/health" 2>/dev/null | grep -q '"status"'; then
    echo "  OK  OpenSearch reachable at https://localhost:9200"
    PASS=$(( PASS + 1 ))
else
    echo " MISS OpenSearch not reachable at https://localhost:9200 — check docker-compose"
    FAIL=$(( FAIL + 1 ))
fi

echo
echo "=== Result: $PASS passed, $FAIL missing ==="
exit $FAIL
