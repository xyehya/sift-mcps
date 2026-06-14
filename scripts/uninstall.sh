#!/usr/bin/env bash
# =============================================================================
# uninstall.sh — Protocol SIFT Gateway component uninstaller
#
# Removes all or a selected subset of installed/provisioned components.
# Implements B-MVP-007 decided for BATCH-UN1.
#
# USAGE
#   ./scripts/uninstall.sh                        # interactive menu (dry-run)
#   ./scripts/uninstall.sh --components opencti   # dry-run named add-on(s)
#   ./scripts/uninstall.sh --all                  # dry-run full stack
#   ./scripts/uninstall.sh --all --yes --i-understand   # ACTUALLY remove all
#
#   --components <list>     Comma-separated subset; valid tokens:
#                             opencti opensearch supabase runtime systemd
#                             state cache auditd apparmor tls
#   --all                   All components (except /cases — evidence is NEVER
#                           included; see --remove-evidence)
#   --yes                   Confirm deletions (otherwise dry-run only)
#   --i-understand          Extra gate required when --all or any core component
#                           (systemd, runtime, supabase, state, cache) is selected
#   --remove-evidence       Unlock evidence teardown (HIGHEST BLAST RADIUS)
#   --i-understand-evidence-loss
#                           Second confirmation gate for evidence removal
#   --execute-as USER       Override SIFT_EXECUTE_AS_USER (default: agent_runtime)
#   --service-user USER     Override SIFT_GATEWAY_SERVICE_USER (default: sift-service)
#   --install-root PATH     Override SIFT_MCPS_INSTALL_ROOT (default: /opt/sift-mcps)
#   --state-dir PATH        Override SIFT_STATE_DIR (default: /var/lib/sift)
#   --cases-root PATH       Override SIFT_CASES_ROOT (default: /cases)
#   -h, --help              Print this help and exit
#
# DRY-RUN BY DEFAULT — prints what WOULD be removed.
# Pass --yes (and --i-understand for core components) to actually delete.
#
# /cases IS NEVER REMOVED unless --remove-evidence AND
# --i-understand-evidence-loss are both passed, AND --yes is set, AND the
# operator types "DELETE EVIDENCE" at the interactive prompt.
# =============================================================================
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '[uninstall] %s\n' "$*"; }
warn() { printf '[uninstall] WARNING: %s\n' "$*" >&2; }
die()  { printf '[uninstall] FATAL: %s\n' "$*" >&2; exit 1; }

sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

# Print what WOULD be done; actual deletion is gated by DRY_RUN=0.
# $1 = action verb ("remove" / "stop+disable" etc.)
# $2 = target description
action() {
  local verb="$1" target="$2"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run] WOULD %s: %s\n' "$verb" "$target"
  else
    log "$verb: $target"
  fi
}

# Execute a command only when not in dry-run mode.
# Never echo secret-looking strings (no $(...) expansions with sensitive vars).
run_if_live() {
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Path constants (mirroring install.sh variable declarations)
# ---------------------------------------------------------------------------
SIFT_GATEWAY_SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
SIFT_GATEWAY_SERVICE_GROUP="${SIFT_GATEWAY_SERVICE_GROUP:-sift}"
SIFT_EXECUTE_AS_USER="${SIFT_EXECUTE_AS_USER:-agent_runtime}"
SIFT_MCPS_INSTALL_ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
SIFT_STATE_DIR="${SIFT_STATE_DIR:-/var/lib/sift}"
SIFT_HOME="${SIFT_HOME:-$SIFT_STATE_DIR/.sift}"
SIFT_CASES_ROOT="${SIFT_CASES_ROOT:-/cases}"

# Supabase CLI (setup-supabase.sh: installs to $HOME/.sift/bin or /usr/local/bin)
SIFT_BIN_DIR="${SIFT_BIN_DIR:-$HOME/.sift/bin}"
SUPABASE_PROJECT_DIR="${SIFT_SUPABASE_PROJECT_DIR:-$HOME/.sift/supabase-project}"

# Systemd unit files (install_systemd_service: /etc/systemd/system/*.service)
SYSTEMD_SYSTEM_DIR="${SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}"
GATEWAY_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-gateway.service"
JOB_WORKER_SERVICE_FILE="$SYSTEMD_SYSTEM_DIR/sift-job-worker.service"

# Repo root for docker-compose files.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------
DRY_RUN=1
ASSUME_YES=0
I_UNDERSTAND=0
REMOVE_EVIDENCE=0
I_UNDERSTAND_EVIDENCE=0
ALL_COMPONENTS=0
INTERACTIVE_MENU=1
declare -A COMPONENTS

parse_component_list() {
  # Validate and set component flags from a comma-separated string.
  local raw="$1"
  local IFS=','
  local tok
  for tok in $raw; do
    tok="${tok// /}"
    case "$tok" in
      opencti|opensearch|supabase|runtime|systemd|state|cache|auditd|apparmor|tls)
        COMPONENTS["$tok"]=1
        ;;
      *)
        die "Unknown component: '$tok'. Valid: opencti opensearch supabase runtime systemd state cache auditd apparmor tls"
        ;;
    esac
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --components)
      shift
      [[ $# -gt 0 ]] || die "--components requires an argument."
      parse_component_list "$1"
      INTERACTIVE_MENU=0
      shift
      ;;
    --all)
      ALL_COMPONENTS=1
      INTERACTIVE_MENU=0
      shift
      ;;
    --yes|-y)
      ASSUME_YES=1
      DRY_RUN=0
      shift
      ;;
    --i-understand)
      I_UNDERSTAND=1
      shift
      ;;
    --remove-evidence)
      REMOVE_EVIDENCE=1
      shift
      ;;
    --i-understand-evidence-loss)
      I_UNDERSTAND_EVIDENCE=1
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
    -h|--help)
      sed -n '3,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      die "Unknown option: '$1'. Run with --help for usage."
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Interactive menu (when no --components or --all given)
# ---------------------------------------------------------------------------
run_interactive_menu() {
  printf '\n'
  printf '===== Protocol SIFT Gateway — component uninstaller =====\n'
  printf '\n'
  printf 'Select components to remove (space-separated numbers, or "all"):\n'
  printf '\n'
  printf '  Add-on stacks (safe to remove without disturbing SPG core):\n'
  printf '    1) opencti    — OpenCTI Docker stack + images (~4.4 GB)\n'
  printf '    2) opensearch — OpenSearch Docker stack + images\n'
  printf '\n'
  printf '  SPG core (removes the running platform — requires --i-understand):\n'
  printf '    3) systemd    — sift-gateway + sift-job-worker units, service user\n'
  printf '    4) supabase   — Supabase CLI local stack + env file\n'
  printf '    5) runtime    — /opt/sift-mcps checkout, .venv, SIFT_HOME secrets/TLS\n'
  printf '    6) state      — /var/lib/sift (tokens, passwords, snapshots, enrichment)\n'
  printf '    7) cache      — /var/cache/sift (Volatility3 symbols)\n'
  printf '    8) auditd     — SIFT auditd rules (/etc/audit/rules.d/99-sift-evidence.rules)\n'
  printf '    9) apparmor   — sift-gateway AppArmor profile\n'
  printf '   10) tls        — TLS/CA material under SIFT_HOME/tls\n'
  printf '\n'
  printf '   all — all of the above (requires --i-understand at final confirm)\n'
  printf '\n'
  printf 'NOTE: /cases (evidence) is NEVER included in any selection shown here.\n'
  printf '      To remove evidence you must pass --remove-evidence\n'
  printf '      AND --i-understand-evidence-loss AND --yes on the command line.\n'
  printf '\n'
  local selection=""
  printf 'Selection: '
  read -r selection || selection=""
  if [[ "$selection" == "all" ]]; then
    ALL_COMPONENTS=1
  else
    local tok
    for tok in $selection; do
      case "$tok" in
        1) COMPONENTS["opencti"]=1 ;;
        2) COMPONENTS["opensearch"]=1 ;;
        3) COMPONENTS["systemd"]=1 ;;
        4) COMPONENTS["supabase"]=1 ;;
        5) COMPONENTS["runtime"]=1 ;;
        6) COMPONENTS["state"]=1 ;;
        7) COMPONENTS["cache"]=1 ;;
        8) COMPONENTS["auditd"]=1 ;;
        9) COMPONENTS["apparmor"]=1 ;;
        10) COMPONENTS["tls"]=1 ;;
        *) warn "Ignored unknown selection: $tok" ;;
      esac
    done
  fi

  if [[ "$ALL_COMPONENTS" -eq 0 ]] && [[ "${#COMPONENTS[@]}" -eq 0 ]]; then
    log "No components selected. Exiting without changes."
    exit 0
  fi

  printf '\n'
  if [[ "$ALL_COMPONENTS" -eq 1 ]]; then
    printf 'Selected: ALL COMPONENTS (full teardown)\n'
  else
    printf 'Selected: %s\n' "${!COMPONENTS[*]}"
  fi
  printf '\n'
  printf 'This is a DRY RUN. Re-run with --yes (and --i-understand for core) to delete.\n'
  printf '\n'
}

# ---------------------------------------------------------------------------
# Confirmation gates
# ---------------------------------------------------------------------------
check_core_gate() {
  # Core components (those that tear down the running SPG) require --i-understand.
  local core_requested=0
  if [[ "$ALL_COMPONENTS" -eq 1 ]]; then
    core_requested=1
  else
    local c
    for c in systemd supabase runtime state cache auditd apparmor tls; do
      [[ "${COMPONENTS[$c]+_}" == "_" ]] && core_requested=1 && break
    done
  fi

  if [[ "$core_requested" -eq 1 ]] && [[ "$DRY_RUN" -eq 0 ]] && [[ "$I_UNDERSTAND" -ne 1 ]]; then
    die "Removing core components requires --i-understand in addition to --yes.
  Core teardown is irreversible without a reinstall.
  Re-run with:  --yes --i-understand"
  fi
}

confirm_evidence_removal() {
  # Evidence removal requires THREE separate gates: --remove-evidence,
  # --i-understand-evidence-loss, --yes, AND a typed "DELETE EVIDENCE" prompt.
  if [[ "$REMOVE_EVIDENCE" -ne 1 ]]; then
    return 0
  fi
  if [[ "$I_UNDERSTAND_EVIDENCE" -ne 1 ]]; then
    die "Evidence removal requires --i-understand-evidence-loss in addition to --remove-evidence."
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    action "remove EVIDENCE ROOT" "$SIFT_CASES_ROOT (all forensic case data — IRREVERSIBLE)"
    return 0
  fi
  # Triple-confirm at the interactive prompt.
  printf '[uninstall] WARNING: YOU ARE ABOUT TO PERMANENTLY DELETE %s\n' "$SIFT_CASES_ROOT" >&2
  printf '[uninstall] This contains ALL forensic case data. This CANNOT be undone.\n' >&2
  printf '[uninstall] Type exactly "DELETE EVIDENCE" to confirm: ' >&2
  local reply=""
  read -r reply || reply=""
  if [[ "$reply" != "DELETE EVIDENCE" ]]; then
    die "Evidence removal aborted. Nothing was deleted."
  fi
  _purge_tree "$SIFT_CASES_ROOT"
  log "Evidence root removed: $SIFT_CASES_ROOT (ALL forensic data destroyed)"
}

# ---------------------------------------------------------------------------
# Teardown helpers
# ---------------------------------------------------------------------------

# Mirrors install.sh's _purge_tree: clears chattr +i/+a before rm.
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
# Per-component teardown functions
# (Each is labelled with the install.sh function it reverses.)
# ---------------------------------------------------------------------------

# Reverses: install_opencti + install_opencti_feeds (Phase 9) and prepare_opencti_secrets
#           docker-compose.opencti.yml / docker-compose.opencti-connectors.yml
teardown_opencti() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker not found — skipping OpenCTI teardown."
    return 0
  fi

  # Connectors compose
  local connectors_compose="$REPO_DIR/docker-compose.opencti-connectors.yml"
  if [[ -f "$connectors_compose" ]]; then
    action "docker compose down" "OpenCTI feed connectors ($connectors_compose)"
    run_if_live docker compose -f "$connectors_compose" down --remove-orphans 2>/dev/null || true
  fi

  # Main OpenCTI compose (opensearch, redis, rabbitmq, minio, opencti, worker)
  # Named volumes: opencti-opensearch-data, opencti-redis, opencti-rabbitmq, opencti-minio
  # Network: sift-opencti-net
  local opencti_compose="$REPO_DIR/docker-compose.opencti.yml"
  if [[ -f "$opencti_compose" ]]; then
    action "docker compose down -v" "OpenCTI stack + named volumes ($opencti_compose)"
    run_if_live docker compose -f "$opencti_compose" down -v --remove-orphans 2>/dev/null || true
  fi

  # Remove OpenCTI images to reclaim ~4.4 GB
  action "docker image rm (if unused)" "opencti/platform opencti/worker opencti/connector-mitre opencti/connector-cisa-known-exploited-vulnerabilities"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    local img
    for img in \
      "opencti/platform:latest" \
      "opencti/worker:latest" \
      "opencti/connector-mitre:latest" \
      "opencti/connector-cisa-known-exploited-vulnerabilities:latest" \
      "redis:7.4" \
      "rabbitmq:4.0-management" \
      "minio/minio:latest"; do
      docker image rm "$img" 2>/dev/null || true
    done
    # OpenSearch image used only by the OpenCTI compose stack.
    # NOTE: the native sift-opensearch uses the pinned digest image, not a tag;
    # only remove the tag reference used by opencti if opensearch teardown is NOT
    # being requested alongside (to avoid removing a shared image prematurely).
    if [[ "${COMPONENTS[opensearch]+_}" != "_" ]]; then
      : # opensearch teardown will remove that image in its own step
    else
      docker image rm "opensearchproject/opensearch:3.5.0" 2>/dev/null || true
    fi
  fi

  # Connector ID files under SIFT_HOME (install_opencti_feeds: svc_install_file):
  #   $SIFT_HOME/opencti-connector-mitre-id
  #   $SIFT_HOME/opencti-connector-cisa-kev-id
  # prepare_opencti_secrets files:
  #   $SIFT_HOME/opencti-token
  #   $SIFT_HOME/opencti-encryption-key
  #   $SIFT_HOME/opencti-health-key
  local f
  for f in \
    "$SIFT_HOME/opencti-token" \
    "$SIFT_HOME/opencti-encryption-key" \
    "$SIFT_HOME/opencti-health-key" \
    "$SIFT_HOME/opencti-connector-mitre-id" \
    "$SIFT_HOME/opencti-connector-cisa-kev-id"; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f (OpenCTI secret)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done

  # Remove the sift-opencti-net Docker network if present.
  if command -v docker >/dev/null 2>&1 && docker network inspect sift-opencti-net >/dev/null 2>&1; then
    action "docker network rm" "sift-opencti-net"
    run_if_live docker network rm sift-opencti-net 2>/dev/null || true
  fi
}

# Reverses: start_opensearch + write_opensearch_config + write_opensearch_env (Phase 7/8)
#           docker-compose.yml (opensearch service, volume opensearch-data, network sift-net)
teardown_opensearch() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker not found — skipping OpenSearch teardown."
    return 0
  fi

  local compose_file="$REPO_DIR/docker-compose.yml"
  if [[ -f "$compose_file" ]]; then
    action "docker compose down -v" "OpenSearch stack + named volume opensearch-data ($compose_file)"
    run_if_live docker compose -f "$compose_file" down -v --remove-orphans 2>/dev/null || true
  fi

  # Remove the pinned-digest OpenSearch image.
  action "docker image rm (if unused)" "opensearchproject/opensearch (pinned digest)"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    docker image rm \
      "opensearchproject/opensearch@sha256:dbb01641baadae5104e18acd888bf05e8fdd9af3567fd30624a76ba3e5a31dec" \
      2>/dev/null || true
    # Also the plain tag used by the connectors compose:
    docker image rm "opensearchproject/opensearch:3.5.0" 2>/dev/null || true
  fi

  # Remove the sift-net Docker network.
  if docker network inspect sift-net >/dev/null 2>&1; then
    action "docker network rm" "sift-net"
    run_if_live docker network rm sift-net 2>/dev/null || true
  fi

  # Config files written by write_opensearch_config / write_opensearch_env (Phase 7):
  #   $SIFT_HOME/opensearch.yaml
  #   $SIFT_HOME/opensearch.env
  local f
  for f in "$SIFT_HOME/opensearch.yaml" "$SIFT_HOME/opensearch.env"; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f (OpenSearch config)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done
}

# Reverses: scripts/setup-supabase.sh (supabase start -> down) and its CLI install
#           Creates: $HOME/.sift/supabase-project/sift-supabase.env
#                    $HOME/.sift/bin/supabase + supabase-go (or /usr/local/bin)
teardown_supabase() {
  # Resolve Supabase CLI binary location (mirrors resolve_supabase_cli in setup-supabase.sh).
  local sb_bin=""
  if command -v supabase >/dev/null 2>&1; then
    sb_bin="$(command -v supabase)"
  elif [[ -x "$SIFT_BIN_DIR/supabase" ]]; then
    sb_bin="$SIFT_BIN_DIR/supabase"
    export PATH="$SIFT_BIN_DIR:$PATH"
  fi

  if [[ -n "$sb_bin" ]]; then
    action "supabase stop" "Supabase CLI local stack (Postgres, Auth, API) — containers only; volumes preserved by supabase stop"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      # supabase stop leaves Docker volumes (the data) intact. The operator must
      # run `supabase db reset` or `docker volume rm` if they want to purge data.
      (cd "$REPO_DIR" && supabase stop 2>/dev/null) || warn "supabase stop encountered an error (stack may already be down)."
    fi

    # Remove the Supabase Docker network used for isolation
    # (setup-supabase.sh: sift-supabase-local)
    local supa_net="${SIFT_SUPABASE_NETWORK:-sift-supabase-local}"
    if command -v docker >/dev/null 2>&1 && docker network inspect "$supa_net" >/dev/null 2>&1; then
      action "docker network rm" "$supa_net"
      run_if_live docker network rm "$supa_net" 2>/dev/null || true
    fi

    # Remove the CLI binary + sibling (install_supabase_cli: SIFT_BIN_DIR or /usr/local/bin)
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
    warn "Supabase CLI not found on PATH or in $SIFT_BIN_DIR — skipping supabase stop."
  fi

  # Remove the env output file (write_output_env in setup-supabase.sh):
  #   $HOME/.sift/supabase-project/sift-supabase.env
  if [[ -f "$SUPABASE_PROJECT_DIR/sift-supabase.env" ]]; then
    action "remove" "$SUPABASE_PROJECT_DIR/sift-supabase.env (Supabase credentials env file)"
    run_if_live rm -f "$SUPABASE_PROJECT_DIR/sift-supabase.env"
  fi
  # Remove the project dir if empty after cleanup.
  if [[ "$DRY_RUN" -eq 0 ]] && [[ -d "$SUPABASE_PROJECT_DIR" ]]; then
    rmdir --ignore-fail-on-non-empty "$SUPABASE_PROJECT_DIR" 2>/dev/null || true
  fi
}

# Reverses: install_systemd_service (Phase 10) + ensure_gateway_service_user (Phase 3)
#           Creates: /etc/systemd/system/sift-gateway.service
#                    /etc/systemd/system/sift-job-worker.service
#                    system user sift-service + group sift-service + group sift
#           Also reverses: configure_agent_runtime -> setup-agent-runtime.sh (agent_runtime user)
#                          configure_ingest_mount_sudoers -> /etc/sudoers.d/sift-ingest-mount
teardown_systemd() {
  # Stop and disable both services (mirrors uninstall_systemd in install.sh).
  if command -v systemctl >/dev/null 2>&1; then
    action "systemctl stop + disable" "sift-gateway.service sift-job-worker.service"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      sudo_if_needed systemctl stop sift-gateway.service sift-job-worker.service 2>/dev/null || true
      sudo_if_needed systemctl disable sift-gateway.service sift-job-worker.service 2>/dev/null || true
    fi
  fi

  # Remove unit files (install_systemd_service: _render_file to /etc/systemd/system/).
  local f
  for f in "$GATEWAY_SERVICE_FILE" "$JOB_WORKER_SERVICE_FILE"; do
    if sudo_if_needed test -f "$f" 2>/dev/null; then
      action "remove" "$f (systemd unit file)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done

  if command -v systemctl >/dev/null 2>&1; then
    action "systemctl daemon-reload" "(after unit file removal)"
    run_if_live sudo_if_needed systemctl daemon-reload 2>/dev/null || true
  fi

  # Remove the sudoers drop-ins written by setup-agent-runtime.sh,
  # setup-ingest-mount-sudoers.sh, and the RUN-3 systemd scope helper setup:
  #   /etc/sudoers.d/sift-agent-runtime
  #   /etc/sudoers.d/sift-ingest-mount
  #   /etc/sudoers.d/sift-run-command-systemd-scope
  for f in /etc/sudoers.d/sift-agent-runtime /etc/sudoers.d/sift-ingest-mount /etc/sudoers.d/sift-run-command-systemd-scope; do
    if [[ -f "$f" ]]; then
      action "remove" "$f (sudoers drop-in)"
      run_if_live sudo_if_needed rm -f "$f"
    fi
  done
  if [[ -f /usr/local/sbin/sift-run-command-systemd-scope ]]; then
    action "remove" "/usr/local/sbin/sift-run-command-systemd-scope"
    run_if_live sudo_if_needed rm -f /usr/local/sbin/sift-run-command-systemd-scope
  fi

  # Remove the hayabusa system-wide symlink (install_hayabusa_system_links):
  #   /usr/local/bin/hayabusa -> $SIFT_HOME/bin/hayabusa
  if [[ -L /usr/local/bin/hayabusa ]]; then
    action "remove" "/usr/local/bin/hayabusa (hayabusa symlink)"
    run_if_live sudo_if_needed rm -f /usr/local/bin/hayabusa
  fi

  # Remove the agent_runtime execution user (setup-agent-runtime.sh: useradd -r).
  if id -u "$SIFT_EXECUTE_AS_USER" >/dev/null 2>&1; then
    action "userdel" "$SIFT_EXECUTE_AS_USER (run_command isolation user)"
    run_if_live sudo_if_needed userdel "$SIFT_EXECUTE_AS_USER" 2>/dev/null || \
      warn "userdel $SIFT_EXECUTE_AS_USER failed — remove manually if needed."
  fi

  # Remove the sift-service dedicated user and its primary group (ensure_gateway_service_user).
  if id -u "$SIFT_GATEWAY_SERVICE_USER" >/dev/null 2>&1; then
    action "userdel" "$SIFT_GATEWAY_SERVICE_USER (gateway service user)"
    run_if_live sudo_if_needed userdel "$SIFT_GATEWAY_SERVICE_USER" 2>/dev/null || \
      warn "userdel $SIFT_GATEWAY_SERVICE_USER failed — remove manually if needed."
  fi

  # Remove the shared symbol-cache group `sift` (ensure_gateway_service_user: groupadd -r sift).
  if getent group "$SIFT_GATEWAY_SERVICE_GROUP" >/dev/null 2>&1; then
    action "groupdel" "$SIFT_GATEWAY_SERVICE_GROUP (shared symbol-cache group)"
    run_if_live sudo_if_needed groupdel "$SIFT_GATEWAY_SERVICE_GROUP" 2>/dev/null || \
      warn "groupdel $SIFT_GATEWAY_SERVICE_GROUP failed (may still have members) — remove manually."
  fi
}

# Reverses: sync_workspace + stage_repo_to_install_root + uninstall_runtime (Phase 2/pre-flight)
#           and all secrets/config under SIFT_HOME written by:
#             generate_tls, write_gateway_config, write_supabase_env,
#             write_control_plane_env, write_fk_env, write_opensearch_config,
#             write_opensearch_env, write_default_examiner, install_hayabusa
#           Creates: $SIFT_MCPS_INSTALL_ROOT (staged checkout)
#                    $SIFT_MCPS_INSTALL_ROOT/.venv
#                    $SIFT_HOME (0700, sift-service) with all sub-dirs and files
teardown_runtime() {
  # Remove the venv (sync_workspace; also drops CAP_LINUX_IMMUTABLE setcap).
  local venv_dir="$SIFT_MCPS_INSTALL_ROOT/.venv"
  if [[ -d "$venv_dir" ]]; then
    action "rm -rf" "$venv_dir (.venv)"
    run_if_live rm -rf "$venv_dir"
  fi

  # Remove the staged install root (stage_repo_to_install_root) if it exists and
  # differs from the current repo checkout (we never remove the source clone).
  if [[ -d "$SIFT_MCPS_INSTALL_ROOT" ]] && \
     [[ "$(cd "$SIFT_MCPS_INSTALL_ROOT" 2>/dev/null && pwd -P)" != "$(cd "$REPO_DIR" 2>/dev/null && pwd -P)" ]]; then
    action "rm -rf" "$SIFT_MCPS_INSTALL_ROOT (staged runtime tree)"
    run_if_live sudo_if_needed rm -rf "$SIFT_MCPS_INSTALL_ROOT"
  fi

  # Remove SIFT_HOME entirely (config, TLS/CA, secrets, backups, hayabusa, logs).
  # This covers: gateway.yaml (write_gateway_config), supabase.env (write_supabase_env),
  # control-plane.env (write_control_plane_env), opensearch.yaml (write_opensearch_config),
  # opensearch.env (write_opensearch_env), forensic-knowledge.env (write_fk_env),
  # tls/ (generate_tls), backups/ (SIFT_BACKUP_DIR), bin/hayabusa (install_hayabusa),
  # hayabusa-rules/ (install_hayabusa), addon-register/ (setup-addon.sh), logs/.
  if sudo_if_needed test -d "$SIFT_HOME" 2>/dev/null; then
    action "rm -rf" "$SIFT_HOME (gateway config, TLS/CA, secrets, hayabusa, logs — sift-service-owned)"
    run_if_live sudo_if_needed rm -rf "$SIFT_HOME"
  fi

  # Remove the enrichment symlink (prepare_enrichment_assets):
  #   $SIFT_STATE_DIR/enrichment/forensic-knowledge -> .../forensic-knowledge/data
  local enrich_link="$SIFT_STATE_DIR/enrichment/forensic-knowledge"
  if sudo_if_needed test -L "$enrich_link" 2>/dev/null; then
    action "remove" "$enrich_link (forensic-knowledge data symlink)"
    run_if_live sudo_if_needed rm -f "$enrich_link"
  fi
  local enrich_rag="$SIFT_STATE_DIR/enrichment/forensic-rag"
  if sudo_if_needed test -d "$enrich_rag" 2>/dev/null; then
    action "rm -rf" "$enrich_rag (forensic-rag enrichment dir)"
    run_if_live sudo_if_needed rm -rf "$enrich_rag"
  fi

  # Remove the legacy addon-register dir under operator home
  # (setup-addon.sh: REGISTER_DIR=$HOME/.sift/addon-register).
  local addon_register_dir="$HOME/.sift/addon-register"
  if [[ -d "$addon_register_dir" ]]; then
    action "rm -rf" "$addon_register_dir (add-on register payloads)"
    run_if_live rm -rf "$addon_register_dir"
  fi

  # Remove the examiner password file (write_default_examiner):
  #   $SIFT_STATE_DIR/passwords/<examiner>.json
  # The passwords dir is also removed in state teardown; remove here too so a
  # runtime-only teardown still cleans it.
  local pw_dir="$SIFT_STATE_DIR/passwords"
  if sudo_if_needed test -d "$pw_dir" 2>/dev/null; then
    action "rm -rf" "$pw_dir (examiner password dir — sift-service-owned)"
    run_if_live sudo_if_needed rm -rf "$pw_dir"
  fi
}

# Reverses: install_state_dirs (Phase 3) — but NOT /cases (evidence)
#           Creates: /var/lib/sift (root dir)
#                    /var/lib/sift/passwords, verification, tokens, snapshots,
#                    enrichment, .sift (SIFT_HOME — covered above), .cache/huggingface
#           Also covers the handoff file (write_handoff):
#             /var/lib/sift/tokens/installer-handoff.txt
teardown_state() {
  # Enumerate the sub-dirs created by install_state_dirs that are safe to remove.
  # SIFT_HOME (.sift) is covered by teardown_runtime and is not re-listed here.
  local dirs_to_remove=(
    "$SIFT_STATE_DIR/verification"
    "$SIFT_STATE_DIR/tokens"
    "$SIFT_STATE_DIR/snapshots"
    "$SIFT_STATE_DIR/enrichment"
    "$SIFT_STATE_DIR/.cache"
  )

  local d
  for d in "${dirs_to_remove[@]}"; do
    if sudo_if_needed test -d "$d" 2>/dev/null; then
      action "rm -rf" "$d"
      run_if_live sudo_if_needed rm -rf "$d"
    fi
  done

  # Remove the /var/lib/sift root if it is now empty (best-effort).
  if [[ "$DRY_RUN" -eq 0 ]] && sudo_if_needed test -d "$SIFT_STATE_DIR" 2>/dev/null; then
    # Only remove the root when it's completely empty; fail silently if not.
    sudo_if_needed rmdir --ignore-fail-on-non-empty "$SIFT_STATE_DIR" 2>/dev/null || true
    if ! sudo_if_needed test -d "$SIFT_STATE_DIR" 2>/dev/null; then
      log "Removed $SIFT_STATE_DIR (empty)."
    else
      log "Preserved $SIFT_STATE_DIR (still has content — may include /cases or SIFT_HOME)."
    fi
  else
    action "rmdir (if empty)" "$SIFT_STATE_DIR"
  fi
}

# Reverses: install_state_dirs for /var/cache/sift (SIFT_VOL_SYMBOLS)
#           Creates: /var/cache/sift/volatility-symbols (mode 2775, group sift)
teardown_cache() {
  local cache_root="/var/cache/sift"
  if sudo_if_needed test -d "$cache_root" 2>/dev/null; then
    action "rm -rf" "$cache_root (Volatility3 symbol cache and other SIFT caches)"
    run_if_live sudo_if_needed rm -rf "$cache_root"
  fi
  # Also remove the HF model cache if it was placed under $SIFT_STATE_DIR/.cache
  # (seeded by seed_rag_pgvector_direct / install_state_dirs as sift-service-owned).
  local hf_cache="$SIFT_STATE_DIR/.cache/huggingface"
  if sudo_if_needed test -d "$hf_cache" 2>/dev/null; then
    action "rm -rf" "$hf_cache (Hugging Face BGE model cache)"
    run_if_live sudo_if_needed rm -rf "$hf_cache"
  fi
}

# Reverses: configure_auditd (Phase 13)
#           Creates: /etc/audit/rules.d/99-sift-evidence.rules
teardown_auditd() {
  local rules_dst="/etc/audit/rules.d/99-sift-evidence.rules"
  if [[ -f "$rules_dst" ]]; then
    action "remove" "$rules_dst (SIFT auditd evidence rules)"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      sudo_if_needed rm -f "$rules_dst"
      # Reload the remaining rules so the SIFT rules are no longer in the kernel set.
      if command -v augenrules >/dev/null 2>&1; then
        sudo_if_needed augenrules --load 2>/dev/null || \
          warn "augenrules --load reported an issue; rules will take effect on next reboot."
      elif command -v auditctl >/dev/null 2>&1; then
        # Flush runtime rules (they reload from rules.d on next start).
        sudo_if_needed auditctl -D 2>/dev/null || true
      fi
      log "auditd SIFT evidence rules removed."
    fi
  else
    log "auditd SIFT evidence rules not present at $rules_dst — nothing to remove."
  fi
}

# Reverses: configure_apparmor (Phase 13)
#           Creates: /etc/apparmor.d/sift-gateway
teardown_apparmor() {
  local profile_dst="/etc/apparmor.d/sift-gateway"
  if [[ -f "$profile_dst" ]]; then
    action "AppArmor unload + remove" "$profile_dst"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      if command -v apparmor_parser >/dev/null 2>&1; then
        sudo_if_needed apparmor_parser -R "$profile_dst" 2>/dev/null || \
          warn "apparmor_parser -R returned an error (profile may not have been loaded)."
      fi
      sudo_if_needed rm -f "$profile_dst"
      log "AppArmor profile removed."
    fi
  else
    log "AppArmor profile not present at $profile_dst — nothing to remove."
  fi
}

# Reverses: generate_tls (Phase 5) — the TLS/CA material under $SIFT_HOME/tls
#           Creates: $SIFT_HOME/tls/ca-cert.pem, ca-key.pem,
#                    gateway-cert.pem, gateway-key.pem
# NOTE: This also removes /etc/fuse.conf user_allow_other (configure_fuse Phase 4),
# but only reverting the line we wrote, not purging the file.
teardown_tls() {
  local tls_dir="$SIFT_HOME/tls"
  if sudo_if_needed test -d "$tls_dir" 2>/dev/null; then
    action "rm -rf" "$tls_dir (TLS/CA key material — CONFIDENTIAL)"
    run_if_live sudo_if_needed rm -rf "$tls_dir"
  else
    log "TLS directory $tls_dir not present — nothing to remove."
  fi

  # Revert configure_fuse: remove the user_allow_other line from /etc/fuse.conf
  # if it was written by the installer (best-effort: only remove the line, never
  # the whole file which may have other content).
  local fuse_conf="/etc/fuse.conf"
  if [[ -f "$fuse_conf" ]] && grep -q '^user_allow_other$' "$fuse_conf" 2>/dev/null; then
    action "remove user_allow_other line from" "$fuse_conf (configure_fuse reversal)"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      # sed -i in-place removal; avoid any shell expansion that might expose secrets.
      sudo_if_needed sed -i '/^user_allow_other$/d' "$fuse_conf" 2>/dev/null || \
        warn "Could not remove user_allow_other from $fuse_conf."
    fi
  fi
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------
main() {
  # Run interactive menu if no --components / --all was given.
  if [[ "$INTERACTIVE_MENU" -eq 1 ]]; then
    run_interactive_menu
  fi

  # When --all, populate all component flags.
  if [[ "$ALL_COMPONENTS" -eq 1 ]]; then
    COMPONENTS["opencti"]=1
    COMPONENTS["opensearch"]=1
    COMPONENTS["supabase"]=1
    COMPONENTS["runtime"]=1
    COMPONENTS["systemd"]=1
    COMPONENTS["state"]=1
    COMPONENTS["cache"]=1
    COMPONENTS["auditd"]=1
    COMPONENTS["apparmor"]=1
    COMPONENTS["tls"]=1
  fi

  if [[ "${#COMPONENTS[@]}" -eq 0 ]]; then
    log "No components selected. Exiting without changes."
    exit 0
  fi

  # Gate: core components require --i-understand when not dry-running.
  check_core_gate

  # Announce mode.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '\n'
    printf '========================================================\n'
    printf '  DRY RUN — nothing will be deleted.\n'
    printf '  Re-run with --yes (and --i-understand for core)\n'
    printf '  to actually remove selected components.\n'
    printf '========================================================\n'
    printf '\n'
  else
    printf '\n'
    printf '========================================================\n'
    printf '  LIVE RUN — selected components WILL be removed.\n'
    printf '========================================================\n'
    printf '\n'
  fi

  # Run teardown in a safe order: add-ons first, then core.
  # Add-ons can be removed without touching SPG core; core teardown last.

  # 1. OpenCTI (external add-on — reverses install_opencti + install_opencti_feeds)
  if [[ "${COMPONENTS[opencti]+_}" == "_" ]]; then
    log "--- OpenCTI teardown ---"
    teardown_opencti
  fi

  # 2. OpenSearch core stack (reverses start_opensearch / write_opensearch_*)
  if [[ "${COMPONENTS[opensearch]+_}" == "_" ]]; then
    log "--- OpenSearch teardown ---"
    teardown_opensearch
  fi

  # 3. Supabase CLI local stack (reverses scripts/setup-supabase.sh)
  if [[ "${COMPONENTS[supabase]+_}" == "_" ]]; then
    log "--- Supabase teardown ---"
    teardown_supabase
  fi

  # 4. AppArmor profile (reverses configure_apparmor)
  if [[ "${COMPONENTS[apparmor]+_}" == "_" ]]; then
    log "--- AppArmor teardown ---"
    teardown_apparmor
  fi

  # 5. auditd rules (reverses configure_auditd)
  if [[ "${COMPONENTS[auditd]+_}" == "_" ]]; then
    log "--- auditd teardown ---"
    teardown_auditd
  fi

  # 6. TLS/CA material (reverses generate_tls + configure_fuse)
  if [[ "${COMPONENTS[tls]+_}" == "_" ]]; then
    log "--- TLS/CA teardown ---"
    teardown_tls
  fi

  # 7. systemd units + service user (reverses install_systemd_service + ensure_gateway_service_user)
  if [[ "${COMPONENTS[systemd]+_}" == "_" ]]; then
    log "--- systemd + service user teardown ---"
    teardown_systemd
  fi

  # 8. Runtime tree + SIFT_HOME secrets (reverses sync_workspace + stage_repo_to_install_root)
  if [[ "${COMPONENTS[runtime]+_}" == "_" ]]; then
    log "--- runtime + SIFT_HOME teardown ---"
    teardown_runtime
  fi

  # 9. State directories under /var/lib/sift (reverses install_state_dirs, minus /cases)
  if [[ "${COMPONENTS[state]+_}" == "_" ]]; then
    log "--- state directory teardown ---"
    teardown_state
  fi

  # 10. Cache directories (/var/cache/sift, HF model cache)
  if [[ "${COMPONENTS[cache]+_}" == "_" ]]; then
    log "--- cache teardown ---"
    teardown_cache
  fi

  # Evidence — ONLY when every required gate is satisfied.
  # Default and --all NEVER reach here without the explicit flags.
  if [[ "$REMOVE_EVIDENCE" -eq 1 ]]; then
    log "--- evidence teardown (HIGHEST BLAST RADIUS) ---"
    confirm_evidence_removal
  fi

  printf '\n'
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '=== Dry-run complete. No changes were made. ===\n'
    printf 'To actually remove the listed resources, add --yes\n'
    printf '(and --i-understand for core components).\n'
  else
    printf '=== Uninstall complete. ===\n'
    printf 'The source repo checkout was NOT removed.\n'
    printf 'Reinstall with: ./install.sh\n'
    if [[ "$REMOVE_EVIDENCE" -ne 1 ]]; then
      printf '\n'
      printf 'Evidence under %s was NOT removed (protected by default).\n' "$SIFT_CASES_ROOT"
    fi
  fi
  printf '\n'
}

main "$@"
