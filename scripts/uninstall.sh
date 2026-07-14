#!/usr/bin/env bash
# =============================================================================
# uninstall.sh — Protocol SIFT Gateway greenfield uninstaller
#
# Resets a SIFT Workstation to stock by removing everything this project added.
# Never touches: Docker engine, stock SANS forensics tools (/opt/zimmermantools,
# system Python, apt CLIs such as yara/tshark when preinstalled).
#
# USAGE
#   ./scripts/uninstall.sh                         # dry-run full greenfield plan
#   ./scripts/uninstall.sh --yes --i-understand    # live wipe (cases preserved)
#   ./scripts/uninstall.sh --yes --i-understand --keep-caches
#   ./scripts/uninstall.sh --yes --i-understand --data --i-understand-evidence-loss
#
# FLAGS
#   --yes / -y              Execute (otherwise dry-run only)
#   --i-understand          Required for any live stack teardown
#   --data                  Also purge personalized evidence under /cases
#                           (or set SIFT_PURGE_DATA=1)
#   --i-understand-evidence-loss
#                           Second gate required with --data
#                           (or set SIFT_PURGE_EVIDENCE_ACK=1)
#   --keep-caches           Optional: spare /var/cache/sift download caches +
#                           Docker images only (volumes/.venv/secrets still wiped)
#                           (or set SIFT_KEEP_CACHES=1). OFF by default.
#   --execute-as USER       Override SIFT_EXECUTE_AS_USER (default: agent_runtime)
#   --service-user USER     Override SIFT_GATEWAY_SERVICE_USER (default: sift-service)
#   --install-root PATH     Override SIFT_MCPS_INSTALL_ROOT (default: /opt/sift-mcps)
#   --state-dir PATH        Override SIFT_STATE_DIR (default: /var/lib/sift)
#   --cases-root PATH       Override SIFT_CASES_ROOT (default: /cases)
#   --cache-root PATH       Override SIFT_CACHE_ROOT (default: /var/cache/sift)
#   -h, --help              Print this help and exit
#
# --data targets PERSONALIZED case/evidence only.
#
# Default live wipe removes the whole SIFT stack: containers, named volumes,
# config/secrets, .venv, state. Optional --keep-caches only spares regenerable
# download caches under /var/cache/sift and unused Docker images (faster test
# re-spins). It does NOT keep volumes, .venv, or secrets.
# =============================================================================
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# 1) Helpers
# ---------------------------------------------------------------------------
log()  { printf '[uninstall] %s\n' "$*"; }
warn() { printf '[uninstall] WARNING: %s\n' "$*" >&2; }
die()  { printf '[uninstall] FATAL: %s\n' "$*" >&2; exit 1; }

sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

action() {
  local verb="$1" target="$2"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run] WOULD %s: %s\n' "$verb" "$target"
  else
    log "$verb: $target"
  fi
}

run_if_live() {
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

# Clears chattr +i/+a before rm (evidence / sealed trees).
_purge_tree() {
  local target="$1"
  [[ -d "$target" ]] || return 0
  if command -v chattr >/dev/null 2>&1; then
    sudo_if_needed chattr -R -f -i "$target" 2>/dev/null || true
    sudo_if_needed chattr -R -f -a "$target" 2>/dev/null || true
  fi
  sudo_if_needed rm -rf "$target"
}

# ---------------------------------------------------------------------------
# 2) Path constants (must match lib/common.sh durable-cache contract)
# ---------------------------------------------------------------------------
SIFT_GATEWAY_SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
SIFT_GATEWAY_SERVICE_GROUP="${SIFT_GATEWAY_SERVICE_GROUP:-sift}"
SIFT_EXECUTE_AS_USER="${SIFT_EXECUTE_AS_USER:-agent_runtime}"
SIFT_MCPS_INSTALL_ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
SIFT_STATE_DIR="${SIFT_STATE_DIR:-/var/lib/sift}"
SIFT_HOME="${SIFT_HOME:-$SIFT_STATE_DIR/.sift}"
SIFT_CASES_ROOT="${SIFT_CASES_ROOT:-/cases}"
SIFT_CACHE_ROOT="${SIFT_CACHE_ROOT:-/var/cache/sift}"
SIFT_UV_CACHE_DIR="${SIFT_UV_CACHE_DIR:-$SIFT_CACHE_ROOT/uv}"
SIFT_PIP_CACHE_DIR="${SIFT_PIP_CACHE_DIR:-$SIFT_CACHE_ROOT/pip}"
SIFT_HF_HOME="${SIFT_HF_HOME:-$SIFT_CACHE_ROOT/huggingface}"
SIFT_WINDOWS_TRIAGE_DATA_DIR="${SIFT_WINDOWS_TRIAGE_DATA_DIR:-$SIFT_CACHE_ROOT/windows-triage}"
SIFT_HAYABUSA_CACHE_DIR="${SIFT_HAYABUSA_CACHE_DIR:-$SIFT_CACHE_ROOT/hayabusa}"
SIFT_VOL_SYMBOLS="${SIFT_VOL_SYMBOLS:-$SIFT_CACHE_ROOT/volatility-symbols}"

SIFT_BIN_DIR="${SIFT_BIN_DIR:-$HOME/.sift/bin}"
SUPABASE_PROJECT_DIR="${SIFT_SUPABASE_PROJECT_DIR:-$HOME/.sift/supabase-project}"

SYSTEMD_SYSTEM_DIR="${SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}"
GATEWAY_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-gateway.service"
JOB_WORKER_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-job-worker.service"
OPENSEARCH_WORKER_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-opensearch-worker@.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ---------------------------------------------------------------------------
# 3) Flag parsing
# ---------------------------------------------------------------------------
DRY_RUN=1
ASSUME_YES=0
I_UNDERSTAND=0
PURGE_DATA=0
I_UNDERSTAND_EVIDENCE=0
KEEP_CACHES=0

# Env mirrors (explicit flags still win when passed).
[[ "${SIFT_PURGE_DATA:-0}" == "1" ]] && PURGE_DATA=1
[[ "${SIFT_PURGE_EVIDENCE_ACK:-0}" == "1" ]] && I_UNDERSTAND_EVIDENCE=1
[[ "${SIFT_KEEP_CACHES:-0}" == "1" ]] && KEEP_CACHES=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)
      ASSUME_YES=1
      DRY_RUN=0
      shift
      ;;
    --i-understand)
      I_UNDERSTAND=1
      shift
      ;;
    --data)
      PURGE_DATA=1
      shift
      ;;
    --i-understand-evidence-loss)
      I_UNDERSTAND_EVIDENCE=1
      shift
      ;;
    --keep-caches)
      KEEP_CACHES=1
      shift
      ;;
    --execute-as)
      shift
      [[ $# -gt 0 ]] || die "--execute-as requires an argument."
      SIFT_EXECUTE_AS_USER="$1"
      shift
      ;;
    --service-user)
      shift
      [[ $# -gt 0 ]] || die "--service-user requires an argument."
      SIFT_GATEWAY_SERVICE_USER="$1"
      shift
      ;;
    --install-root)
      shift
      [[ $# -gt 0 ]] || die "--install-root requires an argument."
      SIFT_MCPS_INSTALL_ROOT="$1"
      shift
      ;;
    --state-dir)
      shift
      [[ $# -gt 0 ]] || die "--state-dir requires an argument."
      SIFT_STATE_DIR="$1"
      SIFT_HOME="$SIFT_STATE_DIR/.sift"
      shift
      ;;
    --cases-root)
      shift
      [[ $# -gt 0 ]] || die "--cases-root requires an argument."
      SIFT_CASES_ROOT="$1"
      shift
      ;;
    --cache-root)
      shift
      [[ $# -gt 0 ]] || die "--cache-root requires an argument."
      SIFT_CACHE_ROOT="$1"
      SIFT_UV_CACHE_DIR="$SIFT_CACHE_ROOT/uv"
      SIFT_PIP_CACHE_DIR="$SIFT_CACHE_ROOT/pip"
      SIFT_HF_HOME="$SIFT_CACHE_ROOT/huggingface"
      SIFT_WINDOWS_TRIAGE_DATA_DIR="$SIFT_CACHE_ROOT/windows-triage"
      SIFT_HAYABUSA_CACHE_DIR="$SIFT_CACHE_ROOT/hayabusa"
      SIFT_VOL_SYMBOLS="$SIFT_CACHE_ROOT/volatility-symbols"
      shift
      ;;
    -h|--help)
      sed -n '3,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    # Removed component-menu options: fail closed with a pointer.
    --components|--all|--remove-evidence)
      die "Option '$1' was removed. Greenfield wipe is the only path. See --help.
  Evidence: add --data --i-understand-evidence-loss
  Bandwidth caches: add --keep-caches"
      ;;
    *)
      die "Unknown option: '$1'. Run with --help for usage."
      ;;
  esac
done

# ---------------------------------------------------------------------------
# 4) Confirmation gates
# ---------------------------------------------------------------------------
check_live_gate() {
  if [[ "$DRY_RUN" -eq 0 ]] && [[ "$I_UNDERSTAND" -ne 1 ]]; then
    die "Live greenfield teardown requires --i-understand in addition to --yes.
  Re-run with:  --yes --i-understand
  Optional:     --keep-caches   (preserve /var/cache/sift + Docker images)
  Optional:     --data --i-understand-evidence-loss   (also purge /cases)"
  fi
}

confirm_evidence_removal() {
  if [[ "$PURGE_DATA" -ne 1 ]]; then
    return 0
  fi
  if [[ "$I_UNDERSTAND_EVIDENCE" -ne 1 ]]; then
    die "Personalized evidence removal requires --i-understand-evidence-loss (or SIFT_PURGE_EVIDENCE_ACK=1) with --data."
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    action "remove PERSONALIZED EVIDENCE" "$SIFT_CASES_ROOT (all forensic case data — IRREVERSIBLE)"
    return 0
  fi
  if [[ -t 0 ]]; then
    printf '[uninstall] WARNING: YOU ARE ABOUT TO PERMANENTLY DELETE %s\n' "$SIFT_CASES_ROOT" >&2
    printf '[uninstall] This contains ALL personalized forensic case data. This CANNOT be undone.\n' >&2
    printf '[uninstall] Type exactly "DELETE EVIDENCE" to confirm: ' >&2
    local reply=""
    read -r reply || reply=""
    if [[ "$reply" != "DELETE EVIDENCE" ]]; then
      die "Evidence removal aborted. Nothing was deleted under $SIFT_CASES_ROOT."
    fi
  else
    log "Non-TTY: evidence purge authorized by --data + --i-understand-evidence-loss + --yes."
  fi
  _purge_tree "$SIFT_CASES_ROOT"
  log "Evidence root removed: $SIFT_CASES_ROOT (ALL personalized forensic data destroyed)"
}

# Best-effort: mirror hayabusa out of SIFT_HOME into durable cache before secrets wipe.
_preserve_hayabusa_into_cache() {
  [[ "$KEEP_CACHES" -eq 1 ]] || return 0
  local src_bin="$SIFT_HOME/bin/hayabusa"
  local src_rules="$SIFT_HOME/hayabusa-rules"
  if ! sudo_if_needed test -x "$src_bin" 2>/dev/null; then
    return 0
  fi
  action "preserve hayabusa into durable cache" "$SIFT_HAYABUSA_CACHE_DIR"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    sudo_if_needed install -d -m 755 "$SIFT_HAYABUSA_CACHE_DIR/bin" "$SIFT_HAYABUSA_CACHE_DIR/rules"
    sudo_if_needed cp -a "$src_bin" "$SIFT_HAYABUSA_CACHE_DIR/bin/hayabusa" 2>/dev/null || \
      warn "Could not copy hayabusa binary into durable cache (non-fatal)."
    if sudo_if_needed test -d "$src_rules" 2>/dev/null; then
      sudo_if_needed rm -rf "$SIFT_HAYABUSA_CACHE_DIR/rules"
      sudo_if_needed cp -a "$src_rules" "$SIFT_HAYABUSA_CACHE_DIR/rules" 2>/dev/null || \
        warn "Could not copy hayabusa rules into durable cache (non-fatal)."
    fi
  fi
}

# ---------------------------------------------------------------------------
# 5) Teardown partitions (install reverse order)
# ---------------------------------------------------------------------------

# Stop gateway/workers before touching Docker so nothing restarts containers
# or holds named volumes open. Unit-file removal happens later.
stop_sift_services() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local _os_workers=() _u _wlink
  for _u in $(systemctl list-units --all --plain --no-legend 'sift-opensearch-worker@*.service' 2>/dev/null | awk '{print $1}'); do
    _os_workers+=("$_u")
  done
  for _wlink in "$SYSTEMD_SYSTEM_DIR"/multi-user.target.wants/sift-opensearch-worker@*.service; do
    [[ -e "$_wlink" ]] || continue
    _os_workers+=("$(basename "$_wlink")")
  done
  action "systemctl stop + disable" "sift-gateway.service sift-job-worker.service"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    sudo_if_needed systemctl stop sift-gateway.service sift-job-worker.service 2>/dev/null || true
    sudo_if_needed systemctl disable sift-gateway.service sift-job-worker.service 2>/dev/null || true
  fi
  if [[ ${#_os_workers[@]} -gt 0 ]]; then
    action "systemctl stop + disable" "OpenSearch workers: ${_os_workers[*]}"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      sudo_if_needed systemctl stop "${_os_workers[@]}" 2>/dev/null || true
      sudo_if_needed systemctl disable "${_os_workers[@]}" 2>/dev/null || true
    fi
  fi
  action "systemctl stop (best-effort)" "system-sift\\x2dopensearch\\x2dworker.slice"
  run_if_live sudo_if_needed systemctl stop "system-sift\\x2dopensearch\\x2dworker.slice" 2>/dev/null || true
}

# Authoritative Docker purge: never depend solely on `compose down -v` (it
# silently no-ops when env/secrets are missing and leaves volumes in place).
_docker_project_name() { basename "$REPO_DIR"; }

_docker_force_rm_matching_containers() {
  command -v docker >/dev/null 2>&1 || return 0
  local project="$1"
  local id name
  while read -r id name; do
    [[ -n "$id" && -n "$name" ]] || continue
    case "$name" in
      sift-opensearch|sift-opensearch-*|sift-opencti|sift-opencti-*)
        ;;
      supabase_*_"${project}"|supabase_db_"${project}")
        ;;
      *)
        continue
        ;;
    esac
    action "docker rm -f" "$name"
    run_if_live docker rm -f "$id" 2>/dev/null || true
  # Do not combine -q with --format: -q suppresses the format and yields
  # ID-only lines, so name matching never fires and volumes stay in use.
  done < <(docker ps -a --format '{{.ID}} {{.Names}}' 2>/dev/null || true)
}

_docker_list_sift_volumes() {
  command -v docker >/dev/null 2>&1 || return 0
  local project="$1"
  local vol
  for vol in $(docker volume ls --quiet 2>/dev/null || true); do
    case "$vol" in
      "${project}_opensearch-data"|sift-mcps_opensearch-data) printf '%s\n' "$vol" ;;
      sift-opencti-shared_*|sift-opencti-*) printf '%s\n' "$vol" ;;
      supabase_*_"${project}"|supabase_db_"${project}") printf '%s\n' "$vol" ;;
    esac
  done
}

_docker_force_rm_volume() {
  local vol="$1"
  action "docker volume rm" "$vol"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  if docker volume rm "$vol" 2>/dev/null; then
    return 0
  fi
  # Volume still held: drop matching SIFT containers and any container
  # currently using this volume, then retry.
  _docker_force_rm_matching_containers "$(_docker_project_name)"
  local cid
  for cid in $(docker ps -aq --filter "volume=$vol" 2>/dev/null || true); do
    docker rm -f "$cid" 2>/dev/null || true
  done
  docker volume rm -f "$vol" 2>/dev/null || docker volume rm "$vol" 2>/dev/null || true
}

force_purge_sift_docker_state() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker not found — skipping container/volume force purge."
    return 0
  fi
  local project
  project="$(_docker_project_name)"

  # Compose is best-effort only (may fail without env files).
  local connectors_compose="$REPO_DIR/docker-compose.opencti-connectors.yml"
  if [[ -f "$connectors_compose" ]]; then
    action "docker compose down" "OpenCTI connectors (best-effort: $connectors_compose)"
    run_if_live docker compose -f "$connectors_compose" down --remove-orphans 2>/dev/null || true
  fi
  local opencti_compose="$REPO_DIR/docker-compose.opencti-shared.yml"
  if [[ -f "$opencti_compose" ]]; then
    action "docker compose down -v" "OpenCTI shared (best-effort: $opencti_compose)"
    run_if_live docker compose -f "$opencti_compose" down -v --remove-orphans 2>/dev/null || true
  fi
  local os_compose="$REPO_DIR/docker-compose.yml"
  if [[ -f "$os_compose" ]]; then
    action "docker compose down -v" "OpenSearch (best-effort: $os_compose)"
    run_if_live docker compose -f "$os_compose" down -v --remove-orphans 2>/dev/null || true
  fi

  _docker_force_rm_matching_containers "$project"

  local vol leftover=()
  while read -r vol; do
    [[ -n "$vol" ]] || continue
    _docker_force_rm_volume "$vol"
  done < <(_docker_list_sift_volumes "$project")

  if [[ "$DRY_RUN" -eq 0 ]]; then
    while read -r vol; do
      [[ -n "$vol" ]] || continue
      leftover+=("$vol")
    done < <(_docker_list_sift_volumes "$project")
    if [[ ${#leftover[@]} -gt 0 ]]; then
      die "Named SIFT Docker volumes still present after purge: ${leftover[*]}
  Reinstall will mint new credentials against stale volume data and fail.
  Free the volumes (docker rm -f <containers>; docker volume rm -f …) and re-run."
    fi
    log "Verified: no leftover SIFT OpenSearch/OpenCTI/Supabase named volumes."
  fi

  # Networks (best-effort; may still be in use by unrelated containers).
  local net
  for net in sift-net sift-opencti-app-net "${SIFT_SUPABASE_NETWORK:-sift-supabase-local}"; do
    if docker network inspect "$net" >/dev/null 2>&1; then
      action "docker network rm" "$net"
      run_if_live docker network rm "$net" 2>/dev/null || true
    fi
  done
}

# --- 5a OpenCTI env/secrets (containers/volumes: force_purge_sift_docker_state)
teardown_opencti() {
  local f
  for f in \
    "$SIFT_HOME/opencti-stack.env" \
    "$SIFT_HOME/opencti-shared.env" \
    "$SIFT_HOME/opencti-connectors.env" \
    "$SIFT_HOME/opencti-query.env"; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f (OpenCTI secret)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done
}

# --- 5b OpenSearch config (containers/volumes: force_purge_sift_docker_state)
teardown_opensearch() {
  local f
  for f in "$SIFT_HOME/opensearch.yaml" "$SIFT_HOME/opensearch.env" \
           "$SIFT_HOME/opensearch-admin.env" "$SIFT_HOME/opensearch-root-ca.pem"; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f (OpenSearch config)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done
}

# --- 5c Supabase CLI + project env (containers/volumes: force_purge_…)
teardown_supabase() {
  local sb_bin=""
  if command -v supabase >/dev/null 2>&1; then
    sb_bin="$(command -v supabase)"
  elif [[ -x "$SIFT_BIN_DIR/supabase" ]]; then
    sb_bin="$SIFT_BIN_DIR/supabase"
    export PATH="$SIFT_BIN_DIR:$PATH"
  fi

  if [[ -n "$sb_bin" ]]; then
    action "supabase stop" "Supabase CLI local stack"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      (cd "$REPO_DIR" && supabase stop --no-backup 2>/dev/null) \
        || (cd "$REPO_DIR" && supabase stop 2>/dev/null) \
        || warn "supabase stop encountered an error (stack may already be down)."
    fi

    local sb_dir
    sb_dir="$(dirname "$sb_bin")"
    if [[ -f "$sb_dir/supabase" ]]; then
      action "remove" "$sb_dir/supabase (Supabase CLI binary)"
      run_if_live sudo_if_needed rm -f "$sb_dir/supabase"
    fi
    if [[ -f "$sb_dir/supabase-go" ]]; then
      action "remove" "$sb_dir/supabase-go (Supabase CLI Go binary)"
      run_if_live sudo_if_needed rm -f "$sb_dir/supabase-go"
    fi
  else
    warn "Supabase CLI not found — skipping supabase stop."
  fi

  if [[ -f "$SUPABASE_PROJECT_DIR/sift-supabase.env" ]]; then
    action "remove" "$SUPABASE_PROJECT_DIR/sift-supabase.env"
    run_if_live rm -f "$SUPABASE_PROJECT_DIR/sift-supabase.env"
  fi
  if [[ "$DRY_RUN" -eq 0 ]] && [[ -d "$SUPABASE_PROJECT_DIR" ]]; then
    rmdir --ignore-fail-on-non-empty "$SUPABASE_PROJECT_DIR" 2>/dev/null || true
  fi
}

# --- 5d Docker images only when NOT --keep-caches (volumes always already gone)
teardown_docker_images() {
  if [[ "$KEEP_CACHES" -eq 1 ]]; then
    log "Keeping Docker images (--keep-caches). Named volumes were still purged."
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  action "docker image rm (if unused)" "SIFT OpenSearch / OpenCTI / connector images"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    docker image rm \
      "opensearchproject/opensearch@sha256:dbb01641baadae5104e18acd888bf05e8fdd9af3567fd30624a76ba3e5a31dec" \
      2>/dev/null || true
    docker image rm "opensearchproject/opensearch:3.5.0" 2>/dev/null || true
    local img
    for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | \
      grep -E '^(opencti/platform|opencti/worker|minio/minio|redis|rabbitmq)(:|$)' || true); do
      docker image rm "$img" 2>/dev/null || true
    done
  fi
}

# --- 5e AppArmor (gateway + fixed custody broker + dfir-exec)
teardown_apparmor() {
  local profile_dst
  for profile_dst in \
    /etc/apparmor.d/sift-gateway \
    /etc/apparmor.d/sift-custody-delete-broker \
    /etc/apparmor.d/dfir-exec; do
    if sudo_if_needed test -f "$profile_dst" 2>/dev/null; then
      action "AppArmor unload + remove" "$profile_dst"
      if [[ "$DRY_RUN" -eq 0 ]]; then
        if command -v apparmor_parser >/dev/null 2>&1; then
          sudo_if_needed apparmor_parser -R "$profile_dst" 2>/dev/null || \
            warn "apparmor_parser -R returned an error for $profile_dst."
        fi
        sudo_if_needed rm -f "$profile_dst"
      fi
    else
      log "AppArmor profile not present at $profile_dst — nothing to remove."
    fi
  done
}

# --- 5f auditd
teardown_auditd() {
  local rules_dst="/etc/audit/rules.d/99-sift-evidence.rules"
  if sudo_if_needed test -f "$rules_dst" 2>/dev/null; then
    action "remove" "$rules_dst (SIFT auditd evidence rules)"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      sudo_if_needed rm -f "$rules_dst"
      if command -v augenrules >/dev/null 2>&1; then
        sudo_if_needed augenrules --load 2>/dev/null || \
          warn "augenrules --load reported an issue; rules will take effect on next reboot."
      elif command -v auditctl >/dev/null 2>&1; then
        sudo_if_needed auditctl -D 2>/dev/null || true
      fi
    fi
  else
    log "auditd SIFT evidence rules not present — nothing to remove."
  fi
}

# --- 5g systemd units, sudoers, helpers, users (services already stopped earlier)
teardown_systemd_and_users() {
  local f _wlink

  for f in "$GATEWAY_SERVICE_FILE" "$JOB_WORKER_SERVICE_FILE" "$OPENSEARCH_WORKER_SERVICE_FILE"; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done
  # Drop multi-user wants links for workers if unit file already gone.
  for _wlink in "$SYSTEMD_SYSTEM_DIR"/multi-user.target.wants/sift-opensearch-worker@*.service; do
    [[ -e "$_wlink" ]] || continue
    action "remove" "$_wlink"
    run_if_live sudo_if_needed rm -f "$_wlink"
  done

  if command -v systemctl >/dev/null 2>&1; then
    action "systemctl daemon-reload" "(after unit file removal)"
    run_if_live sudo_if_needed systemctl daemon-reload 2>/dev/null || true
    run_if_live sudo_if_needed systemctl reset-failed 'sift-*' 2>/dev/null || true
  fi

  for f in \
    /etc/sudoers.d/sift-agent-runtime \
    /etc/sudoers.d/sift-ingest-mount \
    /etc/sudoers.d/sift-custody-delete-broker \
    /etc/sudoers.d/sift-run-command-systemd-scope \
    /etc/sudoers.d/sift-addon-systemd-sandbox; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f (sudoers drop-in)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done

  for f in \
    /usr/local/sbin/sift-run-command-systemd-scope \
    /usr/local/sbin/sift-custody-delete-broker \
    /usr/local/sbin/sift-addon-systemd-sandbox \
    /usr/local/sbin/sift-addon-stdio-relay; do
    if sudo_if_needed test -e "$f" 2>/dev/null; then
      action "remove" "$f"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done

  if sudo_if_needed test -e /etc/sift/custody-delete.json 2>/dev/null; then
    action "remove" "/etc/sift/custody-delete.json"
    run_if_live sudo_if_needed rm -f /etc/sift/custody-delete.json
  fi
  if sudo_if_needed test -e /etc/sift/custody-delete-dsn 2>/dev/null; then
    action "remove" "/etc/sift/custody-delete-dsn"
    run_if_live sudo_if_needed rm -f /etc/sift/custody-delete-dsn
  fi

  if [[ -L /usr/local/bin/hayabusa ]]; then
    action "remove" "/usr/local/bin/hayabusa (hayabusa symlink)"
    run_if_live sudo_if_needed rm -f /usr/local/bin/hayabusa
  fi

  if id -u "$SIFT_EXECUTE_AS_USER" >/dev/null 2>&1; then
    action "userdel" "$SIFT_EXECUTE_AS_USER (run_command isolation user)"
    run_if_live sudo_if_needed userdel "$SIFT_EXECUTE_AS_USER" 2>/dev/null || \
      warn "userdel $SIFT_EXECUTE_AS_USER failed — remove manually if needed."
  fi
  if id -u "$SIFT_GATEWAY_SERVICE_USER" >/dev/null 2>&1; then
    action "userdel" "$SIFT_GATEWAY_SERVICE_USER (gateway service user)"
    run_if_live sudo_if_needed userdel "$SIFT_GATEWAY_SERVICE_USER" 2>/dev/null || \
      warn "userdel $SIFT_GATEWAY_SERVICE_USER failed — remove manually if needed."
  fi
  if getent group "$SIFT_GATEWAY_SERVICE_GROUP" >/dev/null 2>&1; then
    action "groupdel" "$SIFT_GATEWAY_SERVICE_GROUP (shared symbol-cache group)"
    run_if_live sudo_if_needed groupdel "$SIFT_GATEWAY_SERVICE_GROUP" 2>/dev/null || \
      warn "groupdel $SIFT_GATEWAY_SERVICE_GROUP failed (may still have members)."
  fi
  if getent group "$SIFT_GATEWAY_SERVICE_USER" >/dev/null 2>&1; then
    action "groupdel" "$SIFT_GATEWAY_SERVICE_USER (service primary group)"
    run_if_live sudo_if_needed groupdel "$SIFT_GATEWAY_SERVICE_USER" 2>/dev/null || true
  fi
}

# --- 5h FUSE line revert (configure_fuse)
teardown_fuse_conf() {
  local fuse_conf="/etc/fuse.conf"
  if [[ -f "$fuse_conf" ]] && grep -q '^user_allow_other$' "$fuse_conf" 2>/dev/null; then
    action "remove user_allow_other line from" "$fuse_conf"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      sudo_if_needed sed -i '/^user_allow_other$/d' "$fuse_conf" 2>/dev/null || \
        warn "Could not remove user_allow_other from $fuse_conf."
    fi
  fi
}

# --- 5i Runtime tree + SIFT_HOME (always remove .venv; never keep secrets)
teardown_runtime() {
  _preserve_hayabusa_into_cache

  local venv_dir="$SIFT_MCPS_INSTALL_ROOT/.venv"
  if [[ -d "$venv_dir" ]]; then
    action "rm -rf" "$venv_dir (.venv — always removed; uv cache may remain)"
    # Service/root-owned bytecode under site-packages is common after a live run.
    run_if_live sudo_if_needed rm -rf "$venv_dir"
  fi
  # Also drop a venv in the source clone if operator ran sync there.
  if [[ -d "$REPO_DIR/.venv" ]] && \
     [[ "$(cd "$REPO_DIR" 2>/dev/null && pwd -P)" != "$(cd "$SIFT_MCPS_INSTALL_ROOT" 2>/dev/null && pwd -P)" ]]; then
    action "rm -rf" "$REPO_DIR/.venv (clone venv)"
    run_if_live sudo_if_needed rm -rf "$REPO_DIR/.venv"
  fi

  if [[ -d "$SIFT_MCPS_INSTALL_ROOT" ]] && \
     [[ "$(cd "$SIFT_MCPS_INSTALL_ROOT" 2>/dev/null && pwd -P)" != "$(cd "$REPO_DIR" 2>/dev/null && pwd -P)" ]]; then
    action "rm -rf" "$SIFT_MCPS_INSTALL_ROOT (staged runtime tree)"
    run_if_live sudo_if_needed rm -rf "$SIFT_MCPS_INSTALL_ROOT"
  fi

  if sudo_if_needed test -d "$SIFT_HOME" 2>/dev/null; then
    action "rm -rf" "$SIFT_HOME (gateway config, TLS/CA, secrets, hayabusa under home)"
    run_if_live sudo_if_needed rm -rf "$SIFT_HOME"
  fi

  local addon_register_dir="$HOME/.sift/addon-register"
  if [[ -d "$addon_register_dir" ]]; then
    action "rm -rf" "$addon_register_dir"
    run_if_live rm -rf "$addon_register_dir"
  fi
}

# --- 5j /var/lib/sift state (never /cases unless --data)
teardown_state() {
  if ! sudo_if_needed test -d "$SIFT_STATE_DIR" 2>/dev/null; then
    log "State dir $SIFT_STATE_DIR not present — nothing to remove."
    return 0
  fi

  local _cases_real _entry _entry_real
  _cases_real="$(cd "$SIFT_CASES_ROOT" 2>/dev/null && pwd -P || echo "$SIFT_CASES_ROOT")"
  while IFS= read -r -d '' _entry; do
    _entry_real="$(cd "$_entry" 2>/dev/null && pwd -P || echo "$_entry")"
    if [[ "$_entry_real" == "$_cases_real" || "$_cases_real" == "$_entry_real"/* ]]; then
      log "Preserved $_entry (evidence/cases root or ancestor — use --data to purge)."
      continue
    fi
    action "rm -rf" "$_entry (SIFT state under $SIFT_STATE_DIR)"
    run_if_live sudo_if_needed rm -rf "$_entry"
  done < <(sudo_if_needed find "$SIFT_STATE_DIR" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)

  if [[ "$DRY_RUN" -eq 0 ]]; then
    sudo_if_needed rmdir --ignore-fail-on-non-empty "$SIFT_STATE_DIR" 2>/dev/null || true
  else
    action "rmdir (if empty)" "$SIFT_STATE_DIR"
  fi
}

# --- 5k Durable cache tree
teardown_or_preserve_caches() {
  if [[ "$KEEP_CACHES" -eq 1 ]]; then
    log "Preserving durable caches under $SIFT_CACHE_ROOT:"
    log "  uv=$SIFT_UV_CACHE_DIR"
    log "  pip=$SIFT_PIP_CACHE_DIR"
    log "  huggingface=$SIFT_HF_HOME"
    log "  windows-triage=$SIFT_WINDOWS_TRIAGE_DATA_DIR"
    log "  hayabusa=$SIFT_HAYABUSA_CACHE_DIR"
    log "  volatility-symbols=$SIFT_VOL_SYMBOLS"
    return 0
  fi
  if sudo_if_needed test -d "$SIFT_CACHE_ROOT" 2>/dev/null; then
    action "rm -rf" "$SIFT_CACHE_ROOT (all durable SIFT caches)"
    run_if_live sudo_if_needed rm -rf "$SIFT_CACHE_ROOT"
  fi
}

# --- 5l Operator leftovers + preinstall backups
teardown_operator_leftovers() {
  if [[ -d "$HOME/.sift" ]]; then
    action "rm -rf" "$HOME/.sift (operator leftover)"
    run_if_live rm -rf "$HOME/.sift"
  fi
  local backups="/var/backups/sift"
  if sudo_if_needed test -d "$backups" 2>/dev/null; then
    action "rm -rf" "$backups (preinstall backups)"
    run_if_live sudo_if_needed rm -rf "$backups"
  fi
}

# ---------------------------------------------------------------------------
# 6) Main
# ---------------------------------------------------------------------------
main() {
  check_live_gate

  printf '\n'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '========================================================\n'
    printf '  DRY RUN — greenfield wipe plan (nothing deleted).\n'
    printf '  Re-run with --yes --i-understand to execute.\n'
    printf '========================================================\n'
  else
    printf '========================================================\n'
    printf '  LIVE greenfield wipe — SIFT stack WILL be removed.\n'
    printf '========================================================\n'
  fi
  printf '  keep-caches: %s\n' "$([[ "$KEEP_CACHES" -eq 1 ]] && echo ON || echo OFF)"
  printf '  purge /cases (--data): %s\n' "$([[ "$PURGE_DATA" -eq 1 ]] && echo YES || echo no)"
  printf '\n'

  log "--- stop SIFT systemd services ---"
  stop_sift_services

  log "--- Docker containers + named volumes (always purged) ---"
  force_purge_sift_docker_state

  log "--- OpenCTI secrets ---"
  teardown_opencti

  log "--- OpenSearch config ---"
  teardown_opensearch

  log "--- Supabase teardown ---"
  teardown_supabase

  log "--- Docker images ---"
  teardown_docker_images

  log "--- AppArmor teardown ---"
  teardown_apparmor

  log "--- auditd teardown ---"
  teardown_auditd

  log "--- FUSE conf revert ---"
  teardown_fuse_conf

  log "--- systemd units + users teardown ---"
  teardown_systemd_and_users

  log "--- runtime + SIFT_HOME teardown ---"
  teardown_runtime

  log "--- state directory teardown ---"
  teardown_state

  log "--- durable cache teardown ---"
  teardown_or_preserve_caches

  log "--- operator leftovers ---"
  teardown_operator_leftovers

  if [[ "$PURGE_DATA" -eq 1 ]]; then
    log "--- personalized evidence teardown (--data) ---"
    confirm_evidence_removal
  fi

  printf '\n'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '=== Dry-run complete. No changes were made. ===\n'
    printf 'Live:  ./scripts/uninstall.sh --yes --i-understand\n'
    printf 'Spare download caches/images: add --keep-caches\n'
    printf 'Also wipe /cases:     add --data --i-understand-evidence-loss\n'
  else
    printf '=== Greenfield uninstall complete. ===\n'
    printf 'Source repo checkout was NOT removed.\n'
    if [[ "$KEEP_CACHES" -eq 1 ]]; then
      printf 'Spared regenerable caches under %s and Docker images (--keep-caches).\n' "$SIFT_CACHE_ROOT"
      printf 'Named volumes, .venv, and secrets were still removed.\n'
    fi
    if [[ "$PURGE_DATA" -ne 1 ]]; then
      printf 'Evidence under %s was NOT removed (pass --data to purge).\n' "$SIFT_CASES_ROOT"
    fi
    printf 'Reinstall: ./install.sh [--with-rag] [--with-windows-triage]\n'
  fi
  printf '\n'
}

main "$@"
