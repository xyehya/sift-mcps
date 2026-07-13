#!/usr/bin/env bash
# stage-evidence.sh — stage or prepare evidence bytes in the active SIFT case's
# evidence/ folder, ready to Seal in the portal.
#
# WHY THIS EXISTS
#   The portal does NOT upload evidence bytes: the operator copies them onto the
#   SIFT VM, then Seals them in the portal. Seal sets each file read-only +
#   immutable (chattr +i) and REQUIRES the file to be owned by the gateway
#   service user (sift-service); it deliberately never chowns for you. The case
#   evidence dir is sift-service-owned (0755), so a plain `sudo cp` lands the
#   file root-owned and the seal then fails closed with evidence_immutability_failed.
#   This helper has two deliberately separate modes:
#     * copy mode copies specified source bytes in and sets their metadata; and
#     * --prepare fixes only root- or service-owned manual copies already in the
#       canonical active-case evidence directory. It accepts no paths and never
#       seals evidence.
#
# USAGE
#   scripts/stage-evidence.sh <source-file> [<source-file> ...] [--case <case_key>]
#   scripts/stage-evidence.sh --prepare
#
#     <source-file>   Path on the VM to the evidence byte file(s) (e.g. an E01,
#                     raw/dd image, memory dump) — typically from a mount or the
#                     copy you brought over from the host.
#     --case          Target case_key (e.g. case-rocba-round-2-06151840). If
#                     omitted, the deployment's ACTIVE case is resolved from the
#                     control plane (Postgres).
#     --prepare        Prepare root-owned files already manually copied into the
#                     active case's canonical evidence directory. No paths or
#                     --case are allowed in this mode.
#
# AFTER STAGING
#   In the portal (active case) -> Evidence -> Rescan (if needed) -> Seal.
#
# Run on the SIFT VM as a sudo-capable operator (e.g. sansforensics), not as
# `sudo stage-evidence.sh`. The script elevates only its individual metadata and
# copy steps. Portal Seal remains the only operation that makes evidence immutable.
set -euo pipefail

SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
CASES_ROOT="${SIFT_CASES_ROOT:-/cases}"
ENV_FILE="${SIFT_CONTROL_PLANE_ENV:-/var/lib/sift/.sift/control-plane.env}"
VENV_PY="${SIFT_VENV_PYTHON:-/opt/sift-mcps/.venv/bin/python}"
PREPARE_PYTHON="/usr/bin/python3.12"
PREPARE_HELPER="/usr/local/lib/sift/prepare_evidence.py"

die() { echo "error: $*" >&2; exit 2; }

authenticate_sudo() {
  # A terminal lets sudo prompt normally once. A non-interactive invocation must
  # fail rather than hang for a password; NOPASSWD operator deployments still work.
  if [ -t 0 ]; then sudo -v; else sudo -n -v; fi
}

case_key=""
case_requested=0
prepare=0
sources=()
while [ $# -gt 0 ]; do
  case "$1" in
    --case)   case_key="${2:-}"; case_requested=1; shift 2 ;;
    --case=*) case_key="${1#*=}"; case_requested=1; shift ;;
    --prepare) prepare=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do sources+=("$1"); shift; done ;;
    -*) die "unknown option: $1" ;;
    *)  sources+=("$1"); shift ;;
  esac
done

if [ "$prepare" -eq 1 ]; then
  [ "${#sources[@]}" -eq 0 ] || die "--prepare does not accept source files. Run it only after a manual sudo copy into the evidence directory."
  [ "$case_requested" -eq 0 ] || die "--prepare always resolves the portal's active case; do not pass --case."
else
  [ "${#sources[@]}" -gt 0 ] || die "no source files given. Usage: $0 <source-file> [...] [--case <case_key>]"
fi

if [ "$prepare" -eq 1 ]; then
  [ "$(id -u)" -ne 0 ] || die "run --prepare as a sudo-capable operator, not with sudo on this script"
  # This invocation intentionally accepts no case, path, user, or environment
  # override. The installed root-owned helper resolves the DB-active *unsealed*
  # case itself, then descriptor-pins files before fchown/fchmod.
  authenticate_sudo || die "sudo authentication is required"
  sudo "$PREPARE_PYTHON" -I "$PREPARE_HELPER"
  echo
  echo "NEXT: portal (active case) -> Evidence tab -> Rescan (if needed) -> Seal (password)."
  echo "      Seal, not --prepare, hashes the file and applies immutable +i (the write-protection boundary)."
  exit 0
fi

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

[[ "$case_key" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "invalid case key"
requested_evidence_dir="$CASES_ROOT/$case_key/evidence"
sudo test -d "$requested_evidence_dir" || die "evidence dir not found: $requested_evidence_dir (is the case created/activated?)"
evidence_dir="$(sudo readlink -f -- "$requested_evidence_dir")" || die "cannot resolve evidence dir: $requested_evidence_dir"
[ "$evidence_dir" = "$requested_evidence_dir" ] || die "evidence dir is not the canonical case evidence directory"

# Prompt once up front for copy mode. --prepare uses its own fixed installed
# helper above and deliberately cannot inherit these caller-configurable paths.
authenticate_sudo || die "sudo authentication is required"

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
echo "      Seal hashes the file and applies immutable +i (the write-protection boundary)."
