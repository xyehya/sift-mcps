#!/usr/bin/env bash
#
# inventory-sift-tools.sh - read-only SIFT VM tool/path inventory helper.
#
# Regenerates the raw facts behind docs/inventory/sift-tool-inventory.md.
# READ-ONLY: it never writes VM files, never restarts/stops services, never
# downloads anything, and never prints secret VALUES (only paths/modes/owners).
#
# Usage:
#   Run ON the SIFT VM (as the login or service-capable user):
#     ./scripts/inventory-sift-tools.sh
#   Or from the host over SSH:
#     sshpass -p '<pw>' ssh sansforensics@<vm> 'bash -s' < scripts/inventory-sift-tools.sh
#
# sudo (for root-owned config/TLS modes) is used only if available and
# passwordless or pre-authenticated; otherwise those sections are skipped with
# a note. This script does not embed any password.

set -u

CONFIG_DIR="/var/lib/sift/.sift"
VENV_BIN="/opt/sift-mcps/.venv/bin"

section() { printf '\n===== %s =====\n' "$1"; }

have_sudo() {
  command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}

SUDO=""
if have_sudo; then
  SUDO="sudo -n"
fi

section "HOST"
uname -a 2>/dev/null
( lsb_release -d 2>/dev/null || cat /etc/os-release 2>/dev/null | grep -i pretty )

section "CORE TOOL PATHS (command -v + readlink -f)"
TOOLS="python3.12 python3 uv supabase supabase-go docker rg hayabusa vol volshell
fls mmls ewfmount icat istat img_stat ffind blkls
tsk_comparedir tsk_gettimes tsk_imageinfo tsk_loaddb tsk_recover
log2timeline.py psort.py pinfo.py bulk_extractor strings jq curl openssl git
sqlite3 photorec testdisk foremost scalpel exiftool yara tshark binwalk
chainsaw capa floss node npm"
for t in $TOOLS; do
  p="$(command -v "$t" 2>/dev/null)"
  if [ -n "$p" ]; then
    rp="$(readlink -f "$p" 2>/dev/null)"
    if [ "$rp" != "$p" ]; then
      printf '%-20s -> %s :: real=%s\n' "$t" "$p" "$rp"
    else
      printf '%-20s -> %s\n' "$t" "$p"
    fi
  else
    printf '%-20s -> MISSING\n' "$t"
  fi
done

section "DPKG OWNERSHIP (sample core binaries)"
for b in /usr/bin/fls /usr/bin/ewfmount /usr/bin/bulk_extractor \
         /usr/bin/log2timeline.py /usr/bin/rg /usr/bin/jq /usr/bin/docker; do
  o="$(dpkg -S "$b" 2>/dev/null | head -1)"
  printf '%-26s %s\n' "$b" "${o:-NOT-DPKG-OWNED}"
done

section "FORENSIC APT PACKAGES"
dpkg -l 2>/dev/null | awk '/^ii/ {print $2}' \
  | grep -iE 'sleuthkit|plaso|bulk-extractor|libewf|testdisk|foremost|scalpel|yara|volatility|afflib|ssdeep|hashdeep|exif' \
  | sort -u

section "VENV ENTRYPOINTS ($VENV_BIN)"
ls -l "$VENV_BIN" 2>/dev/null | grep -E 'sift-|mcp|opensearch|rag|regipy' || echo "venv not readable here"

section "SYSTEMD UNITS"
for unit in sift-gateway.service sift-job-worker.service; do
  echo "--- $unit ---"
  systemctl show "$unit" -p WorkingDirectory -p User -p Group \
    -p ExecStart -p EnvironmentFiles -p FragmentPath 2>/dev/null \
    || echo "(systemctl unavailable)"
done

section "CONFIG / TLS PATHS (modes/owners; no values)"
if [ -n "$SUDO" ]; then
  $SUDO ls -la "$CONFIG_DIR" 2>/dev/null
  echo "--- tls ---"
  $SUDO ls -la "$CONFIG_DIR/tls" 2>/dev/null
  echo "--- env file KEY NAMES only (values redacted) ---"
  for f in control-plane.env supabase.env opensearch.env forensic-knowledge.env; do
    echo "[$f]"
    $SUDO grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$CONFIG_DIR/$f" 2>/dev/null \
      | sed 's/=$//' | sed 's/^/  /'
  done
else
  echo "(no passwordless sudo; skipping root-owned config inspection)"
  ls -la "$CONFIG_DIR" 2>/dev/null || echo "(config dir not readable as this user)"
fi

section "HAYABUSA"
ls -l /usr/local/bin/hayabusa 2>/dev/null
if [ -n "$SUDO" ]; then
  $SUDO ls -l "$CONFIG_DIR/bin/hayabusa" 2>/dev/null
  printf 'hayabusa rule .yml count: '
  $SUDO sh -c "find '$CONFIG_DIR/hayabusa-rules' -name '*.yml' 2>/dev/null | wc -l"
fi

section "VOLATILITY 3 + SYMBOL CACHE"
ls -ld /opt/volatility3 2>/dev/null
ls -ld /var/cache/sift/volatility-symbols 2>/dev/null

section "DOCKER RESOURCES"
docker images --format '{{.Repository}}:{{.Tag}}  {{.Size}}' 2>/dev/null | sort
echo "--- containers ---"
docker ps -a --format '{{.Names}} | {{.Status}} | {{.Ports}}' 2>/dev/null
echo "--- volumes ---"
docker volume ls --format '{{.Name}}' 2>/dev/null
echo "--- networks ---"
docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null

section "LISTENING PORTS (sift/supabase/opensearch)"
if [ -n "$SUDO" ]; then
  $SUDO ss -tlnp 2>/dev/null | grep -E ':(4508|9200|54321|54322)' || true
else
  ss -tln 2>/dev/null | grep -E ':(4508|9200|54321|54322)' || true
fi

section "OPENSEARCH HEALTH + INDICES"
curl -s http://127.0.0.1:9200/_cluster/health 2>/dev/null | head -c 300; echo
curl -s 'http://127.0.0.1:9200/_cat/indices?h=index,docs.count,store.size&s=index' 2>/dev/null

section "GATEWAY HEALTH"
curl -sk https://127.0.0.1:4508/health 2>/dev/null | head -c 300; echo

echo
echo "Done (read-only). See docs/inventory/sift-tool-inventory.md for the curated map."
