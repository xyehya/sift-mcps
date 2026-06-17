#!/usr/bin/env bash
# stage-evidence.sh — copy evidence bytes into the active SIFT case's evidence/
# folder with the correct service-user ownership, ready to Seal in the portal.
#
# WHY THIS EXISTS
#   The portal does NOT upload evidence bytes: the operator copies them onto the
#   SIFT VM, then Seals them in the portal. Seal sets each file read-only +
#   immutable (chattr +i) and REQUIRES the file to be owned by the gateway
#   service user (sift-service); it deliberately never chowns for you. The case
#   evidence dir is sift-service-owned (0755), so a plain `sudo cp` lands the
#   file root-owned and the seal then fails closed with evidence_immutability_failed.
#   This helper copies the bytes in AND sets the right ownership/permissions.
#
# USAGE
#   scripts/stage-evidence.sh <source-file> [<source-file> ...] [--case <case_key>]
#
#     <source-file>   Path on the VM to the evidence byte file(s) (e.g. an E01,
#                     raw/dd image, memory dump) — typically from a mount or the
#                     copy you brought over from the host.
#     --case          Target case_key (e.g. case-rocba-round-2-06151840). If
#                     omitted, the deployment's ACTIVE case is resolved from the
#                     control plane (Postgres).
#
# AFTER STAGING
#   In the portal (active case) -> Evidence -> Rescan (if needed) -> Seal.
#
# Run on the SIFT VM as a sudo-capable operator (e.g. sansforensics). The script
# elevates the individual copy/chown steps with sudo itself.
set -euo pipefail

SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
CASES_ROOT="${SIFT_CASES_ROOT:-/cases}"
ENV_FILE="${SIFT_CONTROL_PLANE_ENV:-/var/lib/sift/.sift/control-plane.env}"
VENV_PY="${SIFT_VENV_PYTHON:-/opt/sift-mcps/.venv/bin/python}"

die() { echo "error: $*" >&2; exit 2; }

case_key=""
sources=()
while [ $# -gt 0 ]; do
  case "$1" in
    --case)   case_key="${2:-}"; shift 2 ;;
    --case=*) case_key="${1#*=}"; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do sources+=("$1"); shift; done ;;
    -*) die "unknown option: $1" ;;
    *)  sources+=("$1"); shift ;;
  esac
done

[ "${#sources[@]}" -gt 0 ] || die "no source files given. Usage: $0 <source-file> [...] [--case <case_key>]"

# Resolve the active case from the control plane when --case is not supplied.
resolve_active_case() {
  sudo test -r "$ENV_FILE" || die "cannot read $ENV_FILE to resolve the active case; pass --case <case_key>."
  [ -x "$VENV_PY" ] || die "python interpreter not found: $VENV_PY (set SIFT_VENV_PYTHON)."
  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<'PY'
import os, psycopg
dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN")
if not dsn:
    raise SystemExit("SIFT_CONTROL_PLANE_DSN not set in the control-plane env")
with psycopg.connect(dsn) as conn, conn.cursor() as cur:
    cur.execute(
        "select c.case_key "
        "from app.active_case_state s "
        "join app.cases c on c.id = s.active_case_id "
        "where s.scope = 'deployment' and s.active_case_id is not null"
    )
    row = cur.fetchone()
    print(row[0] if row else "")
PY
  local out rc
  out="$(sudo bash -c "set -a; . '$ENV_FILE'; set +a; '$VENV_PY' '$tmp'" 2>/dev/null)"; rc=$?
  rm -f "$tmp"
  [ "$rc" -eq 0 ] || return 1
  printf '%s' "$out"
}

if [ -z "$case_key" ]; then
  case_key="$(resolve_active_case || true)"
  [ -n "$case_key" ] || die "could not resolve the active case; activate one in the portal or pass --case <case_key>."
  echo "Active case: $case_key"
fi

evidence_dir="$CASES_ROOT/$case_key/evidence"
sudo test -d "$evidence_dir" || die "evidence dir not found: $evidence_dir (is the case created/activated?)"

echo "Target: $evidence_dir  (files will be owned by $SERVICE_USER:$SERVICE_USER, mode 0644)"
echo
staged=0
for src in "${sources[@]}"; do
  if [ ! -f "$src" ]; then echo "  SKIP (not a file): $src" >&2; continue; fi
  base="$(basename -- "$src")"
  dest="$evidence_dir/$base"
  if sudo test -e "$dest"; then
    # Refuse to clobber an already-sealed (immutable) file.
    if sudo lsattr -- "$dest" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      echo "  SKIP (already sealed/immutable): $dest" >&2; continue
    fi
    echo "  overwriting existing: $dest"
  fi
  echo "  copying: $src"
  sudo rsync --info=progress2 -- "$src" "$dest"
  sudo chown "$SERVICE_USER:$SERVICE_USER" -- "$dest"
  sudo chmod 0644 -- "$dest"
  staged=$((staged + 1))
done

echo
echo "Staged $staged file(s). Current evidence dir:"
sudo ls -la "$evidence_dir"
echo
echo "NEXT: portal (active case) -> Evidence tab -> Rescan (if the file is not listed) -> Seal (password)."
echo "      Seal hashes the file and sets it read-only (0444) + immutable (chattr +i)."
