#!/usr/bin/env bash
#
# build-release.sh - Create compressed database assets for GitHub Release
#
# Compresses known_good.db and context.db with zstd (and, with --with-registry,
# the optional ~12GB known_good_registry.db), generates checksums + metadata.
# Output goes to release/ directory ready for upload.
#
# Usage:
#   ./scripts/build-release.sh                       # Build the default 2-DB assets
#   ./scripts/build-release.sh --output /tmp/rel     # Custom output directory
#   ./scripts/build-release.sh --data /path/to/dbs   # Custom source DB directory
#   ./scripts/build-release.sh --with-registry       # ALSO build known_good_registry.db.zst
#
# The optional registry baseline (known_good_registry.db, ~12GB -> ~500MB .zst)
# is only built with --with-registry, mirroring the opt-in downloader
# (windows_triage_mcp.scripts.download_databases --with-registry). It must be
# present in the data dir or the build fails closed. Keeping it gated means the
# default release stays small; XYE-37: prevents it being silently dropped when a
# release is regenerated via this script.
#
# Upload with gh CLI:
#   gh release create triage-db-v2025.02 --latest=false release/*.zst release/checksums.sha256 \
#     --title "Triage Databases v2025.02" \
#     --notes "Pre-built triage databases for windows-triage"
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
OUTPUT_DIR="${SCRIPT_DIR}/../release"
WITH_REGISTRY=0
REGISTRY_DB="known_good_registry.db"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --data) DATA_DIR="$2"; shift 2 ;;
        --with-registry) WITH_REGISTRY=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# The default release set; the optional registry baseline is appended on demand.
DBS=(known_good.db context.db)
if [[ $WITH_REGISTRY -eq 1 ]]; then
    if [[ -f "${DATA_DIR}/${REGISTRY_DB}" ]]; then
        DBS+=("${REGISTRY_DB}")
    else
        echo "Error: --with-registry requested but ${DATA_DIR}/${REGISTRY_DB} not found" >&2
        exit 1
    fi
fi

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}Building Release Assets${NC}"
echo "════════════════════════════════════════"
echo ""

# Check databases exist
for db in "${DBS[@]}"; do
    if [[ ! -f "${DATA_DIR}/${db}" ]]; then
        echo -e "${RED}Error: ${DATA_DIR}/${db} not found${NC}"
        echo "Build databases first: python scripts/import_all.py"
        exit 1
    fi
done

# Check zstd
if ! command -v zstd &>/dev/null; then
    echo -e "${RED}Error: zstd is required${NC}"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Compress databases
for db in "${DBS[@]}"; do
    echo -n "  Compressing ${db}..."
    original_size=$(stat -c%s "${DATA_DIR}/${db}")
    original_mb=$((original_size / 1024 / 1024))

    zstd -3 --no-progress -f -o "${OUTPUT_DIR}/${db}.zst" "${DATA_DIR}/${db}" 2>/dev/null

    compressed_size=$(stat -c%s "${OUTPUT_DIR}/${db}.zst")
    compressed_mb=$((compressed_size / 1024 / 1024))
    ratio=$((compressed_size * 100 / original_size))

    echo -e " ${GREEN}done${NC} (${original_mb}MB -> ${compressed_mb}MB, ${ratio}%)"
done

echo ""

# Generate checksums
echo -n "  Generating checksums..."
cd "$OUTPUT_DIR"
sha256sum *.zst > checksums.sha256
cd - >/dev/null
echo -e " ${GREEN}done${NC}"

# Record database metadata
echo -n "  Generating metadata..."
DATA_DIR="${DATA_DIR}" OUTPUT_DIR="${OUTPUT_DIR}" DBLIST="${DBS[*]}" python3 -c "
import json, sqlite3, os
from datetime import datetime

data_dir = os.environ['DATA_DIR']
output_dir = os.environ['OUTPUT_DIR']
dbs = os.environ['DBLIST'].split()

meta = {
    'created': datetime.now().isoformat(),
    'databases': {}
}

for db in dbs:
    db_path = os.path.join(data_dir, db)
    size = os.path.getsize(db_path)
    conn = sqlite3.connect(db_path)
    tables = {}
    for (table,) in conn.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall():
        (count,) = conn.execute(f'SELECT COUNT(*) FROM [{table}]').fetchone()
        tables[table] = count
    conn.close()
    meta['databases'][db] = {
        'size_bytes': size,
        'tables': tables
    }

with open(os.path.join(output_dir, 'metadata.json'), 'w') as f:
    json.dump(meta, f, indent=2)
" 2>/dev/null
echo -e " ${GREEN}done${NC}"

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Release assets ready in: ${OUTPUT_DIR}/${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "Files:"
ls -lh "${OUTPUT_DIR}/"
echo ""
echo "To create a GitHub release:"
echo "  gh release create triage-db-vYYYY.MM --latest=false ${OUTPUT_DIR}/*.zst ${OUTPUT_DIR}/checksums.sha256 ${OUTPUT_DIR}/metadata.json \\"
echo "    --title 'Triage Databases vYYYY.MM' \\"
echo "    --notes-file RELEASE_NOTES.md"
