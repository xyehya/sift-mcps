# shellcheck shell=bash
# =============================================================================
# lib/bootstrap.sh — trusted, explicit installer library boundary.
#
# Both install.sh and scripts/setup-addon.sh load this tiny module directly from
# the repository tree.  It exposes named, allow-listed library sets so helper
# scripts never need to source the top-level installer (and therefore cannot
# accidentally inherit its CLI/orchestration behavior).
# =============================================================================
[[ -n "${_SIFT_LIB_BOOTSTRAP_SOURCED:-}" ]] && return 0
_SIFT_LIB_BOOTSTRAP_SOURCED=1

# The caller sets REPO_DIR from its own immutable script location before
# sourcing this module.  Do not accept a user-controlled library directory:
# installer helpers can run elevated and source is code execution.
[[ -n "${REPO_DIR:-}" && -d "$REPO_DIR/lib" ]] \
  || { printf '[sift-mcps] FATAL: REPO_DIR must name a repository with lib/\n' >&2; return 1; }
export SIFT_INSTALL_LIB_DIR="$REPO_DIR/lib"

_sift_source_library_modules() {
  local module
  for module in "$@"; do
    case "$module" in
      common|preflight|python|state|assets|tls|examiner|supabase|migrations|config|opensearch|addons|services|handoff|hardening|teardown)
        ;;
      *)
        printf '[sift-mcps] FATAL: unsupported installer library %q\n' "$module" >&2
        return 1
        ;;
    esac
    # shellcheck source=/dev/null
    source "$SIFT_INSTALL_LIB_DIR/${module}.sh" \
      || { printf '[sift-mcps] FATAL: cannot source lib/%s.sh\n' "$module" >&2; return 1; }
  done
}

# Source the complete implementation required only by install.sh's CLI
# orchestrator.  Inputs: none.  Output: the installation function surface.
sift_source_full_installer_libraries() {
  _sift_source_library_modules \
    common preflight python state assets tls examiner supabase migrations config \
    opensearch addons services handoff hardening teardown
}

# Source the minimal, explicit API used by the external-integration helper.
# Inputs: none.  Output: common logging/path helpers, runtime-extra management,
# OpenSearch compatibility helpers, and OpenCTI preparation helpers.  This is
# deliberately not the installer CLI and it never invokes main().
sift_source_external_addon_libraries() {
  _sift_source_library_modules common python config opensearch addons
}

# Source the deliberately small installer-side API used by first-party core
# add-on packs. The pack runs as the installer/control-plane authority, so it
# may use the trusted registry reconciler; its spawned MCP child still receives
# only the explicit env_refs saved in the registry record.
sift_source_core_addon_libraries() {
  _sift_source_library_modules common python supabase examiner
}
