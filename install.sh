#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# sift-mcps installer — hardened, idempotent, zero-arguments
#
#   ./install.sh
#
# Provisions a complete MCP runtime for AI-driven forensics on SIFT Workstation.
# Re-run safe: every step checks whether work is already done.
#
# Design invariants:
#   - Uses /usr/bin/python3.12 (SIFT native).  No uv-managed Python.
#   - Mandatory native sync path (--extra core): gateway, portal, operations,
#     workers, OpenSearch, and opensearch-mcp.
#   - First-party packs are opt-in only: --with-rag, --with-windows-triage.
#   - Venv always matches system Python; mismatched venvs are rebuilt.
#   - OpenCTI is an external add-on; prepare/register it via scripts/setup-addon.sh.
#   - Supabase is auto-provisioned unless external credentials are supplied.
#   - Every step is idempotent.
# =============================================================================

# =============================================================================
# Thin entrypoint (#18 modularization). The provisioning logic lives in
# source-guarded lib/*.sh modules; this file derives REPO_DIR, loads the
# explicit full-installer library surface, then runs main() ONLY on direct
# execution. External helpers source their own small library set directly;
# they never source this CLI/orchestrator.
# =============================================================================

# REPO_DIR = the directory containing THIS install.sh (the repo / staged runtime
# tree root). Derived from this file's own location, never from an environment
# value, before the trusted bootstrap module is sourced.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/bootstrap.sh
source "$REPO_DIR/lib/bootstrap.sh"
sift_source_full_installer_libraries

# =============================================================================
# main
# =============================================================================

run_first_party_core_addons() {
  local pack_args=(--install)
  is_offline && pack_args+=(--offline)

  if [[ "${SIFT_WITH_RAG:-0}" == "1" ]]; then
    log "Installing first-party RAG core add-on."
    bash "$REPO_DIR/scripts/core-addons/setup-rag.sh" "${pack_args[@]}" || die \
      "First-party RAG installation failed; refusing a partial core-addon install."
    RAG_SEEDED=true
  fi

  if [[ "${SIFT_WITH_WINDOWS_TRIAGE:-0}" == "1" ]]; then
    local windows_args=("${pack_args[@]}")
    [[ "${SIFT_WITH_WINDOWS_TRIAGE_REGISTRY:-0}" == "1" ]] && windows_args+=(--with-registry)
    log "Installing first-party Windows-triage core add-on."
    bash "$REPO_DIR/scripts/core-addons/setup-windows-triage.sh" "${windows_args[@]}" || die \
      "First-party Windows-triage installation failed; refusing a partial core-addon install."
    WINDOWS_TRIAGE_SEEDED=true
  fi
}

main() {
  local original_args=("$@")
  local uninstall_mode=0
  local with_rag=0 with_windows_triage=0 with_windows_triage_registry=0
  local interactive=0
  SIFT_EXTERNAL_SUPABASE="${SIFT_EXTERNAL_SUPABASE:-0}"
  # B-MVP-046: AppArmor stays in complain mode unless explicitly opted into enforce.
  SIFT_APPARMOR_ENFORCE="${SIFT_APPARMOR_ENFORCE:-0}"

  # Legacy disable controls would make the mandatory core nondeterministic.
  # Do not silently honor an inherited environment value from an old install.
  # The staging boundary re-execs this installer from /opt and deliberately
  # carries internal mandatory-core state. Reject legacy user input only on the
  # initial invocation; otherwise the second process would reject its own
  # exported SIFT_OPENSEARCH_ENABLED/SIFT_RAG_ENABLED values.
  if [[ "${!SIFT_INSTALL_REEXEC_ENV:-0}" != "1" ]]; then
    local legacy_core_control
    for legacy_core_control in SIFT_CORE_ONLY SIFT_OPENSEARCH_ENABLED SIFT_RAG_ENABLED; do
      if [[ -v "$legacy_core_control" ]]; then
        die "$legacy_core_control is no longer supported. Use the documented positive --with-* pack flags."
      fi
    done
  fi

  # Parse positive options. Bare ./install.sh is deliberately non-interactive.
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes)               ASSUME_YES=1; shift ;;
      --uninstall|--remove)   uninstall_mode=1; shift ;;
      --with-rag)             with_rag=1; shift ;;
      --with-windows-triage)  with_windows_triage=1; shift ;;
      --with-windows-triage-registry)
                              with_windows_triage=1; with_windows_triage_registry=1; shift ;;
      --with-core-addons)     with_rag=1; with_windows_triage=1; shift ;;
      --interactive)          interactive=1; shift ;;
      --external-supabase)    SIFT_EXTERNAL_SUPABASE=1; shift ;;
      --offline)              SIFT_OFFLINE=1; shift ;;
      --enable-geoip)         SIFT_GEOIP_ENABLED=1; shift ;;
      --apparmor-enforce)     SIFT_APPARMOR_ENFORCE=1; shift ;;
      -h|--help)
        printf 'Usage: ./install.sh [OPTIONS]\n\n'
        printf 'Provisions (or removes) a sift-mcps stack on SIFT Workstation.\n'
        printf 'No arguments required for install — native components are provisioned idempotently.\n'
        printf 'Run from a normal clone; the installer stages itself into %s before provisioning.\n' "$SIFT_MCPS_INSTALL_ROOT"
        printf 'Re-run safe: every install step is idempotent.\n\n'
        printf '  --with-rag           Install the first-party RAG knowledge pack after core.\n'
        printf '  --with-windows-triage\n'
        printf '                       Install the first-party Windows-triage baseline pack after core.\n'
        printf '  --with-windows-triage-registry\n'
        printf '                       Also install the explicit large Windows registry baseline.\n'
        printf '  --with-core-addons   Install both first-party packs (not the large registry baseline).\n'
        printf '  --interactive        Explicitly prompt for first-party pack selection.\n'
        printf '  --external-supabase  Skip Supabase auto-provisioning.  Requires that\n'
        printf '                       SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY,\n'
        printf '                       and SIFT_CONTROL_PLANE_DSN are already exported in env.\n'
        printf '  --offline            Hardened/air-gapped install: attempt NO network downloads.\n'
        printf '                       Each download step fails loudly pointing at the operator-\n'
        printf '                       staged artifact path it expects (uv, hayabusa, HF model cache,\n'
        printf '                       Supabase CLI). Equivalent to SIFT_OFFLINE=1.\n'
        printf '  --enable-geoip       Enable the OpenSearch ip2geo datasource (off by default; it\n'
        printf '                       fetches from a live endpoint). Equivalent to SIFT_GEOIP_ENABLED=1.\n'
        printf '  --apparmor-enforce   Load the SIFT AppArmor profiles in ENFORCE mode instead of\n'
        printf '                       the complain-mode default. Opt-in hardening (B-MVP-046); the\n'
        printf '                       same posture is available post-install via ./harden.sh.\n'
        printf '  --uninstall          Reverse the SOFTWARE install: delegates to scripts/uninstall.sh\n'
        printf '                       to stop/remove the systemd service + service users, venv,\n'
        printf '                       ~/.sift (config/TLS/secrets), and auditd + AppArmor configs.\n'
        printf '                       PRESERVES all data: /var/lib/sift state, docker volumes, and\n'
        printf '                       /cases EVIDENCE are never touched. Dry-run unless -y is given.\n'
        printf '                       To remove forensic STATE/docker data, run scripts/uninstall.sh\n'
        printf '                       directly with non-evidence components. EVIDENCE can only be\n'
        printf '                       removed via the gated scripts/uninstall.sh evidence path.\n'
        printf '  -y, --yes            Proceed non-interactively (otherwise --uninstall is a dry-run).\n'
        exit 0
        ;;
      *)
        die "Unknown or removed option '$1'. Run ./install.sh --help for supported positive options."
        ;;
    esac
  done

  _sift_read_pack_env() {
    local env_name="$1" current="$2" raw="${!1-}"
    local reexeced="${!SIFT_INSTALL_REEXEC_ENV:-0}"
    case "$raw" in
      "") printf '%s' "$current" ;;
      true) printf '1' ;;
      false) printf '%s' "$current" ;;
      # The initial process serializes pack choices as 0/1 for its trusted
      # /opt re-exec.  Those internal values are not accepted from a caller.
      0|1)
        [[ "$reexeced" == "1" ]] || die "$env_name must be exactly true or false when set."
        printf '%s' "$raw"
        ;;
      *) die "$env_name must be exactly true or false when set." ;;
    esac
  }

  with_rag="$(_sift_read_pack_env SIFT_WITH_RAG "$with_rag")"
  with_windows_triage="$(_sift_read_pack_env SIFT_WITH_WINDOWS_TRIAGE "$with_windows_triage")"
  with_windows_triage_registry="$(_sift_read_pack_env SIFT_WITH_WINDOWS_TRIAGE_REGISTRY "$with_windows_triage_registry")"
  [[ "$with_windows_triage_registry" == "1" ]] && with_windows_triage=1

  if [[ "$interactive" == "1" ]]; then
    local reply
    read -r -p 'Install first-party RAG pack? [y/N] ' reply
    [[ "$reply" =~ ^[Yy]$ ]] && with_rag=1
    read -r -p 'Install first-party Windows-triage pack? [y/N] ' reply
    [[ "$reply" =~ ^[Yy]$ ]] && with_windows_triage=1
    if [[ "$with_windows_triage" == "1" ]]; then
      read -r -p 'Install the explicit large Windows registry baseline? [y/N] ' reply
      [[ "$reply" =~ ^[Yy]$ ]] && with_windows_triage_registry=1
    fi
  fi

  # Installer-control-plane state only; no child-process credentials flow here.
  SIFT_OPENSEARCH_ENABLED=true
  SIFT_RAG_ENABLED=false
  SIFT_OPENCTI_ENABLED=false
  export SIFT_EXTERNAL_SUPABASE SIFT_OPENSEARCH_ENABLED SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED
  export SIFT_WITH_RAG="$with_rag" SIFT_WITH_WINDOWS_TRIAGE="$with_windows_triage"
  export SIFT_WITH_WINDOWS_TRIAGE_REGISTRY="$with_windows_triage_registry"
  # B-MVP-004: propagate offline/geoip/model-cache controls to all sub-steps
  # (including scripts/setup-supabase.sh invoked by preflight_supabase).
  export SIFT_OFFLINE SIFT_GEOIP_ENABLED SIFT_HF_HOME
  export SIFT_UV_VERSION SIFT_UV_TARBALL_SHA256 SIFT_HAYABUSA_TAG SIFT_HAYABUSA_SHA256
  export SIFT_RAG_MODEL_NAME SIFT_RAG_MODEL_REVISION SIFT_RAG_INDEX_TAG
  if is_offline; then
    log "OFFLINE MODE (SIFT_OFFLINE=1): no network downloads will be attempted; staged artifacts required."
  fi

  if [[ "$uninstall_mode" == "1" ]]; then
    do_uninstall
    exit 0
  fi

  stage_repo_to_install_root "${original_args[@]}"

  # --- pre-flight ---
  check_os
  check_python
  require_cmd awk
  require_cmd curl

  # --- install prerequisites needed by early preflight ---
  install_host_prereqs
  # Local Supabase is Docker-backed; make Docker reachable before
  # scripts/setup-supabase.sh. A fresh clone install can then recover when the
  # daemon is merely stopped.
  ensure_docker_ready_for_supabase

  log "Mandatory core selected: gateway, portal, operations, workers, OpenSearch, and opensearch-mcp."
  log "OpenCTI remains an external integration: scripts/setup-addon.sh opencti."

  # --- preflight: Supabase (integration contract) ---
  # Must run before write_supabase_env / write_control_plane_env so those see
  # the exported vars. Skipped only for explicitly supplied external credentials.
  preflight_supabase

  # --- install ---
  install_uv_if_needed

  # Ensure venv integrity before sync
  _ensure_venv_integrity || true  # best-effort; sync_workspace will fix remaining issues

  sync_workspace
  repair_pyewf_venv_link
  # The service user + shared `sift` group must exist before install_state_dirs
  # chowns the state/secret tree to sift-service.
  ensure_gateway_service_user
  # XYE-42: on a fresh install, move any orphaned /cases + state aside (backup +
  # warn) so a prior teardown's leftover evidence never collides or is clobbered.
  backup_preexisting_data_if_fresh
  install_state_dirs
  configure_agent_runtime
  # agent_runtime is created by configure_agent_runtime (setup-agent-runtime.sh);
  # add it to the shared `sift` group AFTER, so it can write the vol symbol cache.
  # This grants NOTHING else — `sift` is used only for that 2775 cache dir.
  join_shared_symbol_group
  configure_ingest_mount_sudoers
  configure_fuse
  generate_tls
  write_default_examiner
  write_supabase_env   # A1-BOOTSTRAP: Supabase secrets in ~/.sift/supabase.env
  write_control_plane_env

  # Apply DB migrations BEFORE bootstrap_supabase_operator and seed_addon_backends
  # so the schema is in place when those functions run (#2).
  DB_MIGRATIONS_RESULT="skipped"
  if apply_db_migrations; then
    DB_MIGRATIONS_RESULT="applied"
    # G1: the sift_audit_writer role is created by a migration INSIDE
    # apply_db_migrations, so it only exists now. Mint its password + write the
    # scoped SIFT_AUDIT_WRITER_DSN so least-privilege is ACTIVE (fail-soft).
    provision_audit_writer
  else
    DB_MIGRATIONS_RESULT="failed"
  fi

  write_gateway_config
  prepare_enrichment_assets   # FK enrichment is core (D4: FK data is a core runtime dep)
  write_fk_env                 # BATCH-PMI3: FK_DATA_DIR in ~/.sift/forensic-knowledge.env

  # Track whether OpenSearch came up (set by start_opensearch).
  OPENSEARCH_UP=0
  OPENSEARCH_SEEDED=false
  RAG_SEEDED=false

  install_hayabusa
  ensure_opensearch_admin_credentials
  start_opensearch        # sets OPENSEARCH_UP=1 if healthy
  if [[ "$OPENSEARCH_UP" -ne 1 ]]; then
    die "Mandatory core OpenSearch did not become healthy; refusing a partial installation. Fix Docker/OpenSearch and re-run."
  fi
  write_opensearch_config
  write_opensearch_env    # gateway env refs for the mandatory opensearch-mcp
  configure_opensearch_cluster
  configure_geoip_pipeline
  install_opensearch_templates
  configure_opensearch_detections
  install_hayabusa_system_links
  report_hayabusa_status
  install_zimmerman_symlinks
  install_complementary_tools

  # OSX1: seed enabled add-on backends into app.mcp_backends BEFORE the gateway
  # starts so its first registry read (Gateway.__init__) already includes
  # opensearch-mcp. This removes the historical "no tools until restart" race —
  # seed_addon_backends talks to Postgres directly (it does NOT need the gateway
  # running), it only needs the schema (apply_db_migrations ran above) and a
  # resolvable control-plane DSN. OpenSearch is mandatory and has already passed
  # its health check above, so the core backend must be seeded before services.
  # Belt-and-suspenders: even if a row is seeded later (operator registers via the
  # portal), the gateway's _late_start_checker now re-reads app.mcp_backends and
  # mounts late-seeded backends without a restart (Gateway.reload_backend_registry).
  seed_addon_backends

  # First-party packs are explicitly selected positive additions. They run
  # after mandatory core/backend reconciliation and before the initial service
  # start, so a fresh gateway sees every selected registry entry on first boot.
  run_first_party_core_addons

  # A1-BOOTSTRAP: validate evidence/cases root before starting services.
  validate_evidence_root

  install_systemd_service

  # NOTE: loginctl linger removed — the gateway/worker are now SYSTEM services
  # (User=sift-service, WantedBy=multi-user.target), so they start at boot and
  # survive operator logout without per-user lingering.

  configure_run_command_systemd_scope
  configure_immutable_capability
  configure_auditd
  configure_apparmor
  poll_gateway "initial"

  # A1-BOOTSTRAP: Supabase operator bootstrap runs after the gateway is up
  # (Postgres must be reachable for the DB principal insert to succeed later).
  # Runs only when SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set.
  SUPABASE_OPERATOR_CREATED=0
  SB_OPERATOR_USER_ID=""
  SUPABASE_OPERATOR_MAPPED=0
  SUPABASE_OPERATOR_EMAIL=""
  SUPABASE_OPERATOR_TEMP_PASSWORD=""
  bootstrap_supabase_operator

  # OSX1: seed_addon_backends + the post-seed gateway restart were moved to
  # BEFORE install_systemd_service (above), so the gateway sees opensearch-mcp on
  # its first start and the restart workaround is no longer needed. A late seed
  # (e.g. operator registers a backend via the portal) is now picked up live by
  # the gateway's _late_start_checker -> reload_backend_registry, also without a
  # restart.

  write_handoff
  print_summary
}

# Run main() only when executed directly.  The guard still permits focused
# shell-unit tests to source this CLI, but external integration helpers source
# lib/bootstrap.sh and their narrow library set instead.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
