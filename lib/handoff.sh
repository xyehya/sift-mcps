# shellcheck shell=bash
# =============================================================================
# lib/handoff.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_HANDOFF_SOURCED:-}" ]] && return 0
_SIFT_LIB_HANDOFF_SOURCED=1

# =============================================================================
# Phase 12 — handoff
# =============================================================================

write_handoff() {
  local existing_temp_password existing_gateway_token existing_service_token
  local existing_sb_email existing_sb_pw
  local expected_sb_email
  existing_temp_password=""
  existing_gateway_token=""
  existing_service_token=""
  existing_sb_email=""
  existing_sb_pw=""
  expected_sb_email="${SIFT_EXAMINER}@operators.sift.local"
  # MATERIALS_FILE lives in SIFT_TOKENS_DIR (sift-service-owned 0700). Read prior
  # values via sudo; the file is (re)written below into an operator temp and
  # installed owned sift-service 0600. The operator reads it post-install with
  # `sudo cat "$MATERIALS_FILE"` (print_summary points here).
  if svc_test_f "$MATERIALS_FILE"; then
    local _mat
    _mat="$(svc_read "$MATERIALS_FILE")"
    existing_temp_password="$(printf '%s\n' "$_mat" | awk -F= '$1=="temporary_examiner_password"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_gateway_token="$(printf '%s\n' "$_mat" | awk -F= '$1=="examiner_fallback_token"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_service_token="$(printf '%s\n' "$_mat" | awk -F= '$1=="hermes_service_token"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_sb_email="$(printf '%s\n' "$_mat" | awk -F= '$1=="supabase_operator_email"{sub(/^[^=]*=/,""); print; exit}' || true)"
    existing_sb_pw="$(printf '%s\n' "$_mat" | awk -F= '$1=="supabase_operator_temp_password"{sub(/^[^=]*=/,""); print; exit}' || true)"
  fi
  local _handoff_tmp
  _handoff_tmp="$(mktemp)"
  umask 077
  {
    printf 'sift-mcps installer handoff\n'
    printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'portal_url=https://%s:4508/portal/\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'gateway_mcp_url=https://%s:4508/mcp\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'ca_cert=%s/ca-cert.pem\n' "$SIFT_TLS_DIR"
    printf 'tls_profile=internal-local-ca\n'
    # Client trust steps (no private key material is ever written here). The CA
    # cert is public; copy it to the client and import it once. Renewal of the
    # gateway LEAF keeps this same CA, so clients do NOT re-import on renewal.
    printf 'tls_trust_copy=sudo cp %s/ca-cert.pem /tmp/sift-ca.pem  # then scp to client\n' "$SIFT_TLS_DIR"
    printf 'tls_trust_browser=import /tmp/sift-ca.pem as a trusted Authority (Firefox: Settings>Certificates>Authorities>Import; Chrome: Settings>Privacy>Security>Manage certificates>Authorities>Import)\n'
    printf 'tls_trust_python=export REQUESTS_CA_BUNDLE=/path/to/sift-ca.pem SSL_CERT_FILE=/path/to/sift-ca.pem  # MCP/Python clients\n'
    printf 'tls_trust_curl=curl --cacert /path/to/sift-ca.pem https://%s:4508/health\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'tls_renewal=sudo ./scripts/rotate-tls.sh --renew-leaf   # renews leaf, keeps CA (no client re-trust); see maintenance-guide §11\n'
    printf 'gateway_config=%s\n' "$SIFT_CONFIG"
    printf 'examiner=%s\n' "$SIFT_EXAMINER"
    printf 'expected_supabase_operator_email=%s\n' "$expected_sb_email"
    # A1-BOOTSTRAP: Supabase-first operator credentials (forced-reset on first login).
    if [[ "${SUPABASE_OPERATOR_CREATED:-0}" -eq 1 ]]; then
      printf 'supabase_operator_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'portal_login_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'supabase_operator_temp_password=%s\n' "${SUPABASE_OPERATOR_TEMP_PASSWORD:-}"
      printf 'supabase_auth=enabled\n'
      printf 'supabase_forced_reset=required_on_first_login\n'
    elif [[ -n "$existing_sb_email" ]]; then
      printf 'supabase_operator_email=%s\n' "$existing_sb_email"
      printf 'portal_login_email=%s\n' "$existing_sb_email"
      if [[ -n "$existing_sb_pw" ]]; then
        printf 'supabase_operator_temp_password=%s\n' "$existing_sb_pw"
      else
        printf 'supabase_operator_temp_password=already-reset\n'
      fi
      printf 'supabase_auth=enabled\n'
      printf 'supabase_forced_reset=check_if_completed\n'
    elif [[ "${SUPABASE_OPERATOR_MAPPED:-0}" -eq 1 ]]; then
      printf 'supabase_operator_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'portal_login_email=%s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
      printf 'supabase_operator_temp_password=existing-supabase-user\n'
      printf 'supabase_auth=enabled\n'
      printf 'supabase_forced_reset=check_if_completed\n'
    else
      printf 'supabase_auth=not_bootstrapped\n'
      printf 'portal_login_email=unavailable_until_supabase_bootstrap_succeeds\n'
    fi
    # Legacy local PBKDF2 examiner password (fallback when Supabase is not configured).
    if [[ "${TEMP_PASSWORD_CREATED:-0}" -eq 1 ]]; then
      printf 'temporary_examiner_password=%s\n' "$TEMP_PASSWORD"
    elif [[ -n "$existing_temp_password" && "$existing_temp_password" != "existing-password-preserved" ]]; then
      printf 'temporary_examiner_password=%s\n' "$existing_temp_password"
    else
      printf 'temporary_examiner_password=existing-password-preserved\n'
    fi
    if [[ "${CONFIG_CREATED:-0}" -eq 1 ]]; then
      printf 'examiner_fallback_token=%s\n' "$SIFT_GATEWAY_TOKEN"
      printf 'hermes_service_token=%s\n' "$SIFT_SERVICE_TOKEN"
    elif [[ -n "$existing_gateway_token" || -n "$existing_service_token" ]]; then
      [[ -n "$existing_gateway_token" ]] && printf 'examiner_fallback_token=%s\n' "$existing_gateway_token"
      [[ -n "$existing_service_token" ]] && printf 'hermes_service_token=%s\n' "$existing_service_token"
    else
      printf 'tokens=existing-gateway-config-preserved\n'
    fi
    # Supabase provisioning mode (auto vs external vs missing).
    if [[ "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
      printf 'supabase_provision_mode=external\n'
    elif [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
      printf 'supabase_provision_mode=auto_provisioned\n'
      printf 'supabase_project_env=%s\n' "$SUPABASE_PROJECT_ENV"
    else
      printf 'supabase_provision_mode=not_provisioned\n'
    fi
    # Migration apply result.
    printf 'db_migrations_applied=%s\n' "${DB_MIGRATIONS_RESULT:-skipped}"
    # OpenSearch backend seeding status.
    printf 'opensearch_backend_seeded=%s\n' "${OPENSEARCH_SEEDED:-false}"
    printf 'opensearch_available=%s\n' "${OPENSEARCH_UP:-0}"
    # System services (User=sift-service) — start at boot via multi-user.target.
    printf 'service_scope=system\n'
    printf 'service_user=%s\n' "$SIFT_GATEWAY_SERVICE_USER"
  } > "$_handoff_tmp"
  svc_install_file "$_handoff_tmp" "$MATERIALS_FILE" 600
  rm -f "$_handoff_tmp"
  # A1-BOOTSTRAP: clear the temp password from env now that it's in the handoff file.
  unset SUPABASE_OPERATOR_TEMP_PASSWORD
}

