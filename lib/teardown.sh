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
  printf '\n'

  # Supabase provisioning mode.
  if [[ "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    printf 'Supabase:     external (credentials supplied by operator)\n'
  elif [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
    printf 'Supabase:     auto-provisioned via scripts/setup-supabase.sh\n'
    printf '              credentials: %s\n' "$SUPABASE_PROJECT_ENV"
  elif [[ "${SIFT_CORE_ONLY:-0}" == "1" ]]; then
    printf 'Supabase:     skipped (core-only install)\n'
  else
    printf 'Supabase:     NOT provisioned — re-run install.sh after running scripts/setup-supabase.sh\n'
  fi

  # DB migration result.
  printf 'DB migrations: %s\n' "${DB_MIGRATIONS_RESULT:-skipped}"

  # OpenSearch backend.
  if [[ "${SIFT_CORE_ONLY:-0}" != "1" ]]; then
    if [[ "${OPENSEARCH_SEEDED:-false}" == "true" ]]; then
      printf 'OpenSearch:   backend seeded and registered in app.mcp_backends\n'
    elif [[ "${OPENSEARCH_UP:-0}" -eq 1 ]]; then
      printf 'OpenSearch:   running but backend seed was skipped\n'
    else
      printf 'OpenSearch:   not available (Docker absent or unhealthy)\n'
    fi
  fi

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
  printf '  6. Add-on backends are OPTIONAL and external. To integrate one, prepare it with\n'
  printf '     scripts/setup-addon.sh, then register it from Portal -> Backends\n'
  printf '     (validate -> register -> hot-reload). The core ships with none enabled.\n'
}

# =============================================================================
# Uninstall — DELEGATED to scripts/uninstall.sh (the single, gated teardown)
# =============================================================================
#
#   ./install.sh --uninstall   # tear down the SIFT software install
#
# D5 / immutability boundary #2 (#16): the INSTALLER MUST HAVE NO CODE PATH THAT
# CAN DELETE CASE EVIDENCE. There is therefore no inline purge here and no
# data-purge flag on install.sh. `./install.sh --uninstall` is a thin shim that
# runs the canonical, multi-gated uninstaller `scripts/uninstall.sh`, which:
#   * NEVER touches /cases (evidence) unless an operator runs IT directly with the
#     two explicit evidence-removal gate flags AND --yes AND types
#     "DELETE EVIDENCE" at its prompt; and
#   * preserves the evidence root even when its own state-purge runs (it actively
#     guards the cases root / any ancestor).
# This shim deliberately NEVER passes those evidence-removal gate flags through:
# evidence teardown is only ever reachable by invoking scripts/uninstall.sh directly.
#
# Scope of the delegated software teardown (no data loss): systemd units + service
# users, the staged runtime + venv + SIFT_HOME (config/TLS/secrets/hayabusa), and
# the system-hardening drop-ins (auditd rules, AppArmor profile). Forensic STATE
# under /var/lib/sift, docker data volumes, and EVIDENCE under /cases are preserved.
# To remove those, run scripts/uninstall.sh directly with the appropriate
# (non-evidence) components — e.g. `scripts/uninstall.sh --components state,cache,
# opensearch,supabase --yes --i-understand`.

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
    # branch $uninstaller is still the string path from line 126, not an array.
    uninstaller=("$uninstaller")
  fi

  log "Uninstalling sift-mcps (software only — evidence under /cases is never touched here)."
  log "Delegating to the canonical, evidence-gated uninstaller: scripts/uninstall.sh"

  # Software-only teardown that preserves DATA (state, docker volumes) and EVIDENCE:
  #   systemd  — sift-gateway/sift-job-worker units + service users
  #   runtime  — staged tree, .venv, SIFT_HOME (config/TLS/secrets/hayabusa)
  #   auditd   — /etc/audit/rules.d/99-sift-evidence.rules
  #   apparmor — /etc/apparmor.d/sift-gateway
  #   tls      — TLS/CA material under SIFT_HOME/tls
  # NEVER: state, cache, opensearch, supabase, opencti (data) — and NEVER evidence.
  # --i-understand is required because these tear down the running platform; we add
  # it here (this shim is itself the explicit `--uninstall` intent). We never add
  # the evidence-removal gate flags, so evidence stays off-limits by construction.
  # shellcheck disable=SC2054  # the commas form a single --components VALUE (a
  # comma-separated component list), not array-element separators.
  local args=(--components systemd,runtime,auditd,apparmor,tls --i-understand)
  if [[ "${ASSUME_YES:-0}" == "1" ]]; then
    args+=(--yes)
  else
    log "Running in DRY-RUN mode (scripts/uninstall.sh default). Re-run with -y/--yes to actually remove."
  fi

  "${uninstaller[@]}" "${args[@]}"

  log "Uninstall delegation complete."
  printf '\n'
  printf 'Preserved (never removed by ./install.sh --uninstall):\n'
  printf '  State:    %s   (integrity records, tokens, passwords, snapshots)\n' "$SIFT_STATE_DIR"
  printf '  Evidence: %s   (immutable; only the gated scripts/uninstall.sh evidence path can ever touch it)\n' "$SIFT_CASE_ROOT"
  printf '  Docker volumes (if any) left intact.\n'
  printf 'To remove forensic STATE or docker data too, run scripts/uninstall.sh directly\n'
  printf 'with non-evidence components, e.g.:\n'
  printf '  scripts/uninstall.sh --components state,cache,opensearch,supabase --yes --i-understand\n'
  printf 'The repo checkout itself was left in place. Reinstall with: ./install.sh [--core-only]\n'
}
