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
#   - Single native sync path (--extra full): core + OpenSearch + RAG knowledge.
#   - Venv always matches system Python; mismatched venvs are rebuilt.
#   - OpenCTI is an external add-on; prepare/register it via scripts/setup-addon.sh.
#   - Supabase is auto-provisioned unless external credentials are supplied.
#   - Every step is idempotent.
# =============================================================================

# =============================================================================
# Thin entrypoint (#18 modularization). The provisioning logic lives in
# source-guarded lib/*.sh modules; this file derives REPO_DIR, sources the
# modules (dependency order: common first — it defines every global the other
# modules read at call time), then runs main() ONLY on direct execution. When
# sourced (scripts/setup-addon.sh) the functions become available WITHOUT
# kicking off an install — the BASH_SOURCE guard at the foot of this file
# preserves that contract.
# =============================================================================

# REPO_DIR = the directory containing THIS install.sh (the repo / staged runtime
# tree root). Derived from this file's own location so that when
# scripts/setup-addon.sh sources install.sh, REPO_DIR still resolves to the repo
# root (not scripts/). lib/common.sh honours this pre-set value.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIFT_INSTALL_LIB_DIR="${SIFT_INSTALL_LIB_DIR:-$REPO_DIR/lib}"

# Source order: common defines all globals + early helpers FIRST; the rest are
# pure function-definition modules (bash resolves globals at call time, so their
# relative order does not matter for correctness — grouped by concern).
for _sift_lib in \
  common \
  preflight \
  python \
  state \
  assets \
  tls \
  examiner \
  supabase \
  migrations \
  config \
  opensearch \
  addons \
  services \
  handoff \
  hardening \
  teardown \
; do
  # shellcheck source=/dev/null
  source "$SIFT_INSTALL_LIB_DIR/${_sift_lib}.sh" \
    || { printf '[sift-mcps] FATAL: cannot source lib/%s.sh\n' "$_sift_lib" >&2; exit 1; }
done
unset _sift_lib

# =============================================================================
# main
# =============================================================================

main() {
  local original_args=("$@")
  SIFT_CORE_ONLY="${SIFT_CORE_ONLY:-0}"
  local uninstall_mode=0
  # Track compatibility flags.
  local flag_no_opencti=0 flag_no_rag=0
  SIFT_EXTERNAL_SUPABASE="${SIFT_EXTERNAL_SUPABASE:-0}"
  # B-MVP-046: AppArmor stays in complain mode unless explicitly opted into enforce.
  SIFT_APPARMOR_ENFORCE="${SIFT_APPARMOR_ENFORCE:-0}"

  # Parse flags (#1: new flags + existing)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes)               ASSUME_YES=1; shift ;;
      --core-only)            SIFT_CORE_ONLY=1; shift ;;
      --uninstall|--remove)   uninstall_mode=1; shift ;;
      --no-opencti)           flag_no_opencti=1; shift ;;
      --no-rag)               flag_no_rag=1; shift ;;
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
        printf '  --core-only          Install gateway + portal + in-process core tools only.\n'
        printf '                       Skips OpenSearch, RAG, Docker, and forensic-tool downloads.\n'
        printf '  --no-rag             Disable forensic-rag-mcp backend.\n'
        printf '  --no-opencti         Accepted for compatibility; OpenCTI is external and\n'
        printf '                       never installed by install.sh. Use scripts/setup-addon.sh.\n'
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
        warn "Unknown option '$1' — ignored.  Run ./install.sh -h for help."
        shift
        ;;
    esac
  done
  export SIFT_EXTERNAL_SUPABASE
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

  # --- native backend enablement (#1) ---
  # OpenCTI and other external add-ons are prepared/registerable via
  # scripts/setup-addon.sh, not installed by this native path.
  if [[ "$SIFT_CORE_ONLY" == "1" ]]; then
    log "CORE-ONLY install: gateway + portal + in-process core tools."
    SIFT_OPENCTI_ENABLED="false"
    SIFT_RAG_ENABLED="false"
    SIFT_OPENSEARCH_ENABLED="false"
  else
    # RAG: --no-rag flag or explicit env=false overrides.
    if [[ "$flag_no_rag" -eq 1 || "${SIFT_RAG_ENABLED:-}" == "false" ]]; then
      SIFT_RAG_ENABLED="false"
      log "RAG backend disabled (--no-rag or SIFT_RAG_ENABLED=false)."
    else
      SIFT_RAG_ENABLED="${SIFT_RAG_ENABLED:-true}"
    fi

    # OpenSearch: default enabled.
    SIFT_OPENSEARCH_ENABLED="${SIFT_OPENSEARCH_ENABLED:-true}"

    if [[ "$flag_no_opencti" -eq 1 ]]; then
      log "OpenCTI is external; --no-opencti is accepted as a no-op compatibility flag."
    elif [[ "${SIFT_OPENCTI_ENABLED:-}" == "true" ]]; then
      warn "SIFT_OPENCTI_ENABLED=true is ignored by install.sh."
      warn "  Prepare OpenCTI with scripts/setup-addon.sh, then register it via Portal -> Backends."
    fi
    SIFT_OPENCTI_ENABLED="false"
    log "OpenCTI native install disabled: external add-on only (scripts/setup-addon.sh)."
  fi
  export SIFT_CORE_ONLY SIFT_OPENCTI_ENABLED SIFT_RAG_ENABLED SIFT_OPENSEARCH_ENABLED

  # --- preflight: Supabase (integration contract) ---
  # Must run before write_supabase_env / write_control_plane_env so those see
  # the exported vars. Skipped for --core-only or --external-supabase.
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
  if [[ "$SIFT_CORE_ONLY" != "1" ]]; then
    if apply_db_migrations; then
      DB_MIGRATIONS_RESULT="applied"
      # G1: the sift_audit_writer role is created by a migration INSIDE
      # apply_db_migrations, so it only exists now. Mint its password + write the
      # scoped SIFT_AUDIT_WRITER_DSN so least-privilege is ACTIVE (fail-soft).
      provision_audit_writer
    else
      DB_MIGRATIONS_RESULT="failed"
    fi
  fi

  write_gateway_config
  prepare_enrichment_assets   # FK enrichment is core (D4: FK data is a core runtime dep)
  write_fk_env                 # BATCH-PMI3: FK_DATA_DIR in ~/.sift/forensic-knowledge.env

  # Track whether OpenSearch came up (set by start_opensearch).
  OPENSEARCH_UP=0
  OPENSEARCH_SEEDED=false
  RAG_SEEDED=false

  if [[ "$SIFT_CORE_ONLY" != "1" ]]; then
    if [[ "${SIFT_RAG_ENABLED:-true}" == "true" ]]; then
      load_rag_pgvector
    fi
    install_hayabusa
    write_opensearch_config
    write_opensearch_env    # FM-2: write gateway env file for OPENSEARCH_CONFIG/OPENSEARCH_HOST (#3)
    start_opensearch        # sets OPENSEARCH_UP=1 if healthy

    # FM-1/FM-2 (#5): gate OpenSearch cluster config and seeding on real availability.
    if [[ "$OPENSEARCH_UP" -eq 1 ]]; then
      configure_opensearch_cluster
      configure_geoip_pipeline
      install_opensearch_templates
      configure_opensearch_detections   # PMI1: keep Sigma disabled; clean dead detectors/monitors; seed aliases
    else
      warn "OpenSearch not available — skipping cluster config, GeoIP pipeline, and template install."
      warn "  opensearch-mcp backend will NOT be seeded; set SIFT_OPENSEARCH_ENABLED=false to suppress."
      SIFT_OPENSEARCH_ENABLED="false"
      export SIFT_OPENSEARCH_ENABLED
    fi

    install_hayabusa_system_links
    report_hayabusa_status
    install_zimmerman_symlinks
    install_complementary_tools
  else
    log "CORE-ONLY: skipped add-on backends, OpenSearch/Docker, and forensic-tool downloads."
  fi

  # OSX1: seed enabled add-on backends into app.mcp_backends BEFORE the gateway
  # starts so its first registry read (Gateway.__init__) already includes
  # opensearch-mcp. This removes the historical "no tools until restart" race —
  # seed_addon_backends talks to Postgres directly (it does NOT need the gateway
  # running), it only needs the schema (apply_db_migrations ran above) and a
  # resolvable control-plane DSN. Gated on OPENSEARCH_UP: if OpenSearch never came
  # healthy, SIFT_OPENSEARCH_ENABLED was set to false above, so this is a no-op.
  # Belt-and-suspenders: even if a row is seeded later (operator registers via the
  # portal), the gateway's _late_start_checker now re-reads app.mcp_backends and
  # mounts late-seeded backends without a restart (Gateway.reload_backend_registry).
  seed_addon_backends

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

# Run main() only when executed directly. When sourced (e.g. by
# scripts/setup-addon.sh) this file acts as a function library: sourcing it
# defines the provisioning functions and resolves the path vars without
# kicking off an install.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
