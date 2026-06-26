# shellcheck shell=bash
# =============================================================================
# lib/addons.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_ADDONS_SOURCED:-}" ]] && return 0
_SIFT_LIB_ADDONS_SOURCED=1

# =============================================================================
# Phase 9 — Optional OpenCTI add-on helpers
# =============================================================================

prepare_opencti_secrets() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  # OpenCTI secret/id files live under SIFT_HOME (sift-service-owned 0700). Read
  # them via sudo and (re)create them owned sift-service. _svc_write_secret_line
  # writes a single value to an operator temp and installs it owned sift-service.
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "${tmp:-}"; trap - EXIT' EXIT
  if [[ -z "${OPENCTI_TOKEN:-}" ]]; then
    if svc_test_f "$SIFT_HOME/opencti-token"; then
      OPENCTI_TOKEN="$(svc_read "$SIFT_HOME/opencti-token")"
      log "OpenCTI admin token already exists."
    else
      OPENCTI_TOKEN=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
      printf '%s\n' "$OPENCTI_TOKEN" > "$tmp"
      svc_install_file "$tmp" "$SIFT_HOME/opencti-token" 600
      log "OpenCTI admin token saved."
    fi
  fi

  if svc_test_f "$SIFT_HOME/opencti-encryption-key"; then
    OPENCTI_ENCRYPTION_KEY="$(svc_read "$SIFT_HOME/opencti-encryption-key")"
  else
    OPENCTI_ENCRYPTION_KEY="$(openssl rand -base64 32)"
    printf '%s\n' "$OPENCTI_ENCRYPTION_KEY" > "$tmp"
    svc_install_file "$tmp" "$SIFT_HOME/opencti-encryption-key" 600
  fi

  if svc_test_f "$SIFT_HOME/opencti-health-key"; then
    OPENCTI_HEALTH_ACCESS_KEY="$(svc_read "$SIFT_HOME/opencti-health-key")"
  else
    OPENCTI_HEALTH_ACCESS_KEY=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_HEALTH_ACCESS_KEY" > "$tmp"
    svc_install_file "$tmp" "$SIFT_HOME/opencti-health-key" 600
  fi

  export OPENCTI_TOKEN OPENCTI_ENCRYPTION_KEY OPENCTI_HEALTH_ACCESS_KEY
  export OPENCTI_URL="http://127.0.0.1:8080"
  rm -f "$tmp"
  trap - EXIT
}

install_opencti() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  prepare_opencti_secrets
  log "Deploying OpenCTI stack."
  OPENCTI_ADMIN_TOKEN="$OPENCTI_TOKEN" \
  OPENCTI_ENCRYPTION_KEY="$OPENCTI_ENCRYPTION_KEY" \
  OPENCTI_HEALTH_ACCESS_KEY="$OPENCTI_HEALTH_ACCESS_KEY" \
    docker compose -f "$REPO_DIR/docker-compose.opencti.yml" up -d

  log "Waiting for OpenCTI (up to 5 min)..."
  local deadline=$(( $(date +%s) + 300 ))
  until curl -sf "http://127.0.0.1:8080/health?health_access_key=$OPENCTI_HEALTH_ACCESS_KEY" >/dev/null 2>&1; do
    [[ $(date +%s) -lt $deadline ]] || { warn "OpenCTI not healthy within 5 min."; return; }
    sleep 10
  done
  log "OpenCTI ready at http://127.0.0.1:8080"
}

install_opencti_feeds() {
  [[ "${SIFT_OPENCTI_ENABLED:-false}" == "true" ]] || return 0

  # Connector id files under SIFT_HOME (sift-service-owned 0700): read via sudo,
  # (re)create owned sift-service.
  local id_file tmp
  tmp="$(mktemp)"
  trap 'rm -f "${tmp:-}"; trap - EXIT' EXIT
  id_file="$SIFT_HOME/opencti-connector-mitre-id"
  if svc_test_f "$id_file"; then
    OPENCTI_CONNECTOR_MITRE_ID="$(svc_read "$id_file")"
  else
    OPENCTI_CONNECTOR_MITRE_ID=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_CONNECTOR_MITRE_ID" > "$tmp"
    svc_install_file "$tmp" "$id_file" 600
  fi

  id_file="$SIFT_HOME/opencti-connector-cisa-kev-id"
  if svc_test_f "$id_file"; then
    OPENCTI_CONNECTOR_CISA_KEV_ID="$(svc_read "$id_file")"
  else
    OPENCTI_CONNECTOR_CISA_KEV_ID=$("$SYSTEM_PYTHON" -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_CONNECTOR_CISA_KEV_ID" > "$tmp"
    svc_install_file "$tmp" "$id_file" 600
  fi

  export OPENCTI_CONNECTOR_MITRE_ID OPENCTI_CONNECTOR_CISA_KEV_ID
  log "Deploying OpenCTI feed connectors (MITRE ATT&CK + CISA KEV)."
  OPENCTI_ADMIN_TOKEN="$OPENCTI_TOKEN" \
  OPENCTI_CONNECTOR_MITRE_ID="$OPENCTI_CONNECTOR_MITRE_ID" \
  OPENCTI_CONNECTOR_CISA_KEV_ID="$OPENCTI_CONNECTOR_CISA_KEV_ID" \
    docker compose -f "$REPO_DIR/docker-compose.opencti-connectors.yml" up -d
  rm -f "$tmp"
  trap - EXIT
}
