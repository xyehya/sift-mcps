# shellcheck shell=bash
# =============================================================================
# lib/teardown.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_TEARDOWN_SOURCED:-}" ]] && return 0
_SIFT_LIB_TEARDOWN_SOURCED=1

# =============================================================================
# Phase 14 — summary
# =============================================================================

print_summary() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$ip" ]] || ip="SIFT_VM"
  log "Install complete."
  printf '\n'
  printf 'Portal:       https://%s:4508/portal/\n' "$ip"
  printf 'MCP endpoint: https://%s:4508/mcp\n' "$ip"
  printf 'CA cert:      %s/ca-cert.pem\n' "$SIFT_TLS_DIR"
  printf 'Config:       %s\n' "$SIFT_CONFIG"
  printf 'Secrets:      %s   (read with: sudo cat)\n' "$MATERIALS_FILE"
  printf 'Evidence root: %s\n' "$SIFT_CASES_ROOT"
  printf 'Durable cache: %s (uv/HF/wintriage; survives uninstall --keep-caches)\n' \
    "${SIFT_CACHE_ROOT:-/var/cache/sift}"
  printf '\n'

  # Supabase provisioning mode.
  if [[ "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    printf 'Supabase:     external (credentials supplied by operator)\n'
  elif [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
    printf 'Supabase:     auto-provisioned via scripts/setup-supabase.sh\n'
    printf '              credentials: %s\n' "$SUPABASE_PROJECT_ENV"
  else
    printf 'Supabase:     NOT provisioned — re-run install.sh after running scripts/setup-supabase.sh\n'
  fi

  # DB migration result.
  printf 'DB migrations: %s\n' "${DB_MIGRATIONS_RESULT:-skipped}"

  # OpenSearch backend.
  if [[ "${OPENSEARCH_SEEDED:-false}" == "true" ]]; then
    printf 'OpenSearch:   backend seeded and registered in app.mcp_backends\n'
  elif [[ "${OPENSEARCH_UP:-0}" -eq 1 ]]; then
    printf 'OpenSearch:   running but backend seed was skipped\n'
  else
    printf 'OpenSearch:   not available (Docker absent or unhealthy)\n'
  fi

  printf 'First-party packs: RAG=%s Windows-triage=%s Windows registry baseline=%s\n' \
    "${SIFT_WITH_RAG:-0}" "${SIFT_WITH_WINDOWS_TRIAGE:-0}" \
    "${SIFT_WITH_WINDOWS_TRIAGE_REGISTRY:-0}"

  # Service scope.
  printf 'Services:     system (run as %s; start at boot via multi-user.target)\n' "$SIFT_GATEWAY_SERVICE_USER"

  printf '\n'
  printf 'Next steps:\n'
  # A1-BOOTSTRAP: Supabase-first login instructions when provisioned.
  if [[ "${SUPABASE_OPERATOR_CREATED:-0}" -eq 1 ]]; then
    printf '  1. Sign into the portal with:\n'
    printf '       email:    %s\n' "${SUPABASE_OPERATOR_EMAIL:-}"
    printf '       password: (see %s -> supabase_operator_temp_password)\n' "$MATERIALS_FILE"
    printf '     You will be FORCED to reset this password on first login.\n'
    printf '  2. After reset, create a case and activate it with your new password.\n'
    printf '  3. Mount or copy evidence into the active case evidence directory, then\n'
    printf '     chown it to the gateway service user (operator copies are often root-\n'
    printf '     owned; the seal makes bytes immutable in-process, which needs service\n'
    printf '     ownership):  sudo chown -R %s:%s <case-dir>/evidence/\n' "${SIFT_GATEWAY_SERVICE_USER:-sift-service}" "${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
    printf '  4. Generate an AI agent credential from Portal -> Agents.\n'
  elif [[ "${SUPABASE_OPERATOR_MAPPED:-0}" -eq 1 ]]; then
    printf '  1. Sign into the portal with your existing Supabase operator account:\n'
    printf '       email:    %s\n' "${SUPABASE_OPERATOR_EMAIL:-${SIFT_EXAMINER}@operators.sift.local}"
    printf '       password: existing Supabase password\n'
    printf '  2. Create a case and activate it with password re-auth.\n'
    printf '  3. Mount or copy evidence into the active case evidence directory, then\n'
    printf '     chown it to the gateway service user (operator copies are often root-\n'
    printf '     owned; the seal makes bytes immutable in-process, which needs service\n'
    printf '     ownership):  sudo chown -R %s:%s <case-dir>/evidence/\n' "${SIFT_GATEWAY_SERVICE_USER:-sift-service}" "${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
    printf '  4. Generate an AI agent credential from Portal -> Agents.\n'
  else
    printf '  1. Supabase operator bootstrap did not complete, so portal login is not ready.\n'
    printf '     Expected operator email after a successful bootstrap: %s@operators.sift.local\n' "$SIFT_EXAMINER"
    printf '     Check gateway/Supabase health and re-run ./install.sh.\n'
    printf '  2. After bootstrap, use %s -> portal_login_email and supabase_operator_temp_password.\n' "$MATERIALS_FILE"
  fi
  printf '  5. Trust the local CA on the analyst machine (do this ONCE):\n'
  printf '       copy   %s/ca-cert.pem to the client\n' "$SIFT_TLS_DIR"
  printf '       browser: import it as a trusted Authority (Firefox/Chrome)\n'
  printf '       python : export REQUESTS_CA_BUNDLE=<ca-cert.pem> SSL_CERT_FILE=<ca-cert.pem>\n'
  printf '       curl   : curl --cacert <ca-cert.pem> https://%s:4508/health\n' "$ip"
  printf '     Leaf renewal (sudo ./scripts/rotate-tls.sh --renew-leaf) keeps this CA, so no re-trust.\n'
  printf '  6. OpenCTI and other external integrations are optional. Prepare OpenCTI with\n'
  printf '     scripts/setup-addon.sh opencti, then register it from Portal -> Backends\n'
  printf '     (validate -> register -> hot-reload). First-party packs are selected at install time.\n'
}

# =============================================================================
# Uninstall — DELEGATED to scripts/uninstall.sh (the single greenfield teardown)
# =============================================================================
#
#   ./install.sh --uninstall   # tear down the SIFT stack (greenfield, no --data)
#
# D5 / immutability boundary #2 (#16): the INSTALLER MUST HAVE NO CODE PATH THAT
# CAN DELETE CASE EVIDENCE. There is therefore no inline purge here and no
# data-purge flag on install.sh. `./install.sh --uninstall` is a thin shim that
# runs the canonical uninstaller `scripts/uninstall.sh`, which:
#   * NEVER touches /cases unless an operator runs IT directly with --data AND
#     --i-understand-evidence-loss AND --yes (plus typed confirm on a TTY); and
#   * optionally preserves durable regenerable caches via --keep-caches.
# This shim deliberately NEVER passes --data / evidence-loss flags through.

do_uninstall() {
  local uninstaller="$REPO_DIR/scripts/uninstall.sh"
  if [[ ! -x "$uninstaller" ]]; then
    if [[ -f "$uninstaller" ]]; then
      uninstaller=("bash" "$uninstaller")
    else
      die "Canonical uninstaller not found at $REPO_DIR/scripts/uninstall.sh — cannot uninstall."
    fi
  else
    # shellcheck disable=SC2128  # false positive: in THIS (mutually-exclusive)
    # branch $uninstaller is still the string path from line above, not an array.
    uninstaller=("$uninstaller")
  fi

  log "Uninstalling sift-mcps (greenfield stack wipe — evidence under /cases is never touched here)."
  log "Delegating to the canonical uninstaller: scripts/uninstall.sh"

  # Greenfield stack teardown. Evidence stays off-limits by construction
  # (we never forward --data). --i-understand is required because this tears
  # down the running platform; we add it here (this shim is itself the
  # explicit `--uninstall` intent).
  local args=(--i-understand)
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    args+=(--yes)
  else
    log "Running in DRY-RUN mode (scripts/uninstall.sh default). Re-run with -y/--yes to actually remove."
  fi
  if [[ "${SIFT_KEEP_CACHES:-0}" == "1" ]]; then
    args+=(--keep-caches)
    log "SIFT_KEEP_CACHES=1: durable /var/cache/sift + Docker images will be preserved."
  fi

  "${uninstaller[@]}" "${args[@]}"

  log "Uninstall delegation complete."
  printf '\n'
  printf 'Preserved by ./install.sh --uninstall:\n'
  printf '  Evidence: %s   (only scripts/uninstall.sh --data can purge personalized cases)\n' "$SIFT_CASE_ROOT"
  if [[ "${SIFT_KEEP_CACHES:-0}" == "1" ]]; then
    printf '  Caches:   %s (uv/HF/wintriage/hayabusa) + Docker images\n' \
      "${SIFT_CACHE_ROOT:-/var/cache/sift}"
  fi
  printf 'The repo checkout itself was left in place. Reinstall with: ./install.sh\n'
  printf 'Personalized evidence wipe (gated):\n'
  printf '  scripts/uninstall.sh --yes --i-understand --data --i-understand-evidence-loss\n'
  printf 'Fast reinstall loop (keep bandwidth caches):\n'
  printf '  scripts/uninstall.sh --yes --i-understand --keep-caches\n'
}
