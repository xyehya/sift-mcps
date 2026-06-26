# shellcheck shell=bash
# =============================================================================
# lib/services.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_SERVICES_SOURCED:-}" ]] && return 0
_SIFT_LIB_SERVICES_SOURCED=1

# =============================================================================
# Phase 10 — systemd service
# =============================================================================

install_systemd_service() {
  # SYSTEM (not --user) services: the gateway + durable worker run as the
  # dedicated non-admin user sift-service via [Service] User=/Group=. Unit files
  # are root-owned 0644 in /etc/systemd/system; the operator installs them via
  # sudo. SIFT_VOL_SYMBOLS (shared symbol cache) and SIFT_HOME (absolute, used in
  # the units' EnvironmentFile lines instead of %h) are rendered into both units.
  SIFT_GATEWAY_TOKEN=""
  SIFT_SERVICE_TOKEN=""
  SIFT_PORTAL_SESSION_SECRET=""
  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  SIFT_EXAMINER="$SIFT_EXAMINER"
  export SIFT_MCPS_ROOT UV_BIN PYTHON_BIN SIFT_CONFIG SIFT_EXAMINER
  export SIFT_GATEWAY_SERVICE_USER SIFT_VOL_SYMBOLS

  [[ -x "$VENV_DIR/bin/sift-gateway" ]] || die "Missing gateway entrypoint: $VENV_DIR/bin/sift-gateway. Run install workspace sync first."
  [[ -x "$VENV_DIR/bin/sift-job-worker" ]] || warn "Missing durable job worker entrypoint: $VENV_DIR/bin/sift-job-worker."

  if sudo_if_needed test -f "$GATEWAY_SERVICE_FILE"; then
    log "Updating systemd system service $GATEWAY_SERVICE_FILE."
  else
    log "Writing systemd system service $GATEWAY_SERVICE_FILE."
  fi
  _render_file "$REPO_DIR/configs/systemd/sift-gateway.service" "$GATEWAY_SERVICE_FILE" 0644 root
  if sudo_if_needed test -f "$JOB_WORKER_SERVICE_FILE"; then
    log "Updating systemd system service $JOB_WORKER_SERVICE_FILE."
  else
    log "Writing systemd system service $JOB_WORKER_SERVICE_FILE."
  fi
  _render_file "$REPO_DIR/configs/systemd/sift-job-worker.service" "$JOB_WORKER_SERVICE_FILE" 0644 root

  # feat/opensearch-workers: dedicated OpenSearch ingest/enrich worker template.
  # Only when OpenSearch is enabled — the FUSE-mount ingest pipeline runs here
  # (the only unit with CAP_SYS_ADMIN + host mount namespace for FUSE), NOT in the
  # hardened gateway/job-worker.
  local _os_worker_instances=()
  if [[ "${SIFT_OPENSEARCH_ENABLED:-true}" == "true" ]]; then
    if [[ -x "$VENV_DIR/bin/sift-opensearch-worker" ]]; then
      _render_file "$REPO_DIR/configs/systemd/sift-opensearch-worker@.service" \
        "$OPENSEARCH_WORKER_SERVICE_FILE" 0644 root
      local _n="${SIFT_OPENSEARCH_WORKERS:-2}"
      [[ "$_n" =~ ^[0-9]+$ && "$_n" -ge 1 ]] || _n=2
      local _i
      for _i in $(seq 1 "$_n"); do
        _os_worker_instances+=("sift-opensearch-worker@${_i}.service")
      done
      log "OpenSearch ingest/enrich workers: ${_n} instance(s) (override with SIFT_OPENSEARCH_WORKERS)."
    else
      warn "Missing OpenSearch worker entrypoint: $VENV_DIR/bin/sift-opensearch-worker (ingest will not run decoupled)."
    fi
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found — service file written but not started."
    return
  fi
  sudo_if_needed systemctl daemon-reload
  sudo_if_needed systemctl enable sift-gateway.service sift-job-worker.service
  sudo_if_needed systemctl restart sift-gateway.service sift-job-worker.service
  if [[ ${#_os_worker_instances[@]} -gt 0 ]]; then
    sudo_if_needed systemctl enable "${_os_worker_instances[@]}"
    sudo_if_needed systemctl restart "${_os_worker_instances[@]}"
  fi
}

# =============================================================================
# Phase 11 — validation
# =============================================================================

poll_gateway() {
  local label="${1:-initial}"
  log "Waiting for gateway health (up to 30 s) [${label}]."
  local body=""
  for _ in $(seq 1 30); do
    body="$(curl -kfsS https://127.0.0.1:4508/health 2>/dev/null || true)"
    if [[ -n "$body" ]]; then
      break
    fi
    sleep 1
  done
  if [[ -z "$body" ]]; then
    warn "Gateway not reachable.  Check: sudo journalctl -u sift-gateway -n 50"
    return
  fi

  # Parse JSON body: verify status=ok and surface any degraded subsystems.
  local gw_status supabase_status
  gw_status="$("$SYSTEM_PYTHON" -c \
    'import json,sys; d=json.loads(sys.argv[1]); print(d.get("status","unknown"))' \
    "$body" 2>/dev/null || echo "parse_error")"
  supabase_status="$("$SYSTEM_PYTHON" -c \
    'import json,sys; d=json.loads(sys.argv[1]); print((d.get("supabase") or d.get("db") or {}).get("status","unknown"))' \
    "$body" 2>/dev/null || echo "unknown")"

  if [[ "$gw_status" == "ok" ]]; then
    log "Gateway health OK [${label}]: status=$gw_status supabase=$supabase_status"
  elif [[ "$gw_status" == "degraded" ]]; then
    warn "Gateway is DEGRADED [${label}].  Full health body:"
    warn "  $body"
    # Surface the specific failing subsystem if we can parse it.
    local reason
    reason="$("$SYSTEM_PYTHON" -c \
      'import json,sys; d=json.loads(sys.argv[1]); print(d.get("reason") or d.get("error") or "")' \
      "$body" 2>/dev/null || true)"
    [[ -n "$reason" ]] && warn "  Reason: $reason"
    if [[ "${SIFT_CORE_ONLY:-0}" != "1" && "$supabase_status" != "ok" && "$supabase_status" != "unknown" ]]; then
      warn "  Supabase connection is not OK ($supabase_status)."
      warn "  Verify SUPABASE_URL/ANON_KEY/SERVICE_ROLE_KEY are set and the Supabase project is reachable."
    fi
  else
    warn "Gateway returned unexpected status '$gw_status' [${label}] — body: $body"
  fi
}
