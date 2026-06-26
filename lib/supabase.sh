# shellcheck shell=bash
# =============================================================================
# lib/supabase.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_SUPABASE_SOURCED:-}" ]] && return 0
_SIFT_LIB_SUPABASE_SOURCED=1

# Phase 7 — gateway + opensearch config
# =============================================================================

_render_file() {
  # Render $src (env-var substituted) to $dst with mode $3. Optional $4 = owner:
  #   service (default) -> dst lands owned sift-service (SIFT_HOME secrets/config)
  #   root              -> dst lands owned root:root via sudo (/etc/systemd/system units)
  # The substitution always happens in an operator-writable temp; we then cross
  # the ownership boundary with a single sudo install, so the operator never has
  # to write directly into a sift-service- or root-owned directory.
  local src="$1" dst="$2" mode="$3" owner="${4:-service}"
  export SIFT_HOME SIFT_TLS_DIR SIFT_CONFIG SIFT_CASES_ROOT SIFT_CASE_ROOT
  export SIFT_GATEWAY_TOKEN SIFT_SERVICE_TOKEN SIFT_PORTAL_SESSION_SECRET
  export SIFT_EXECUTE_AS_USER SIFT_VOL_SYMBOLS SIFT_GATEWAY_SERVICE_USER
  export SIFT_EXAMINER SIFT_MCPS_ROOT UV_BIN PYTHON_BIN OPENCTI_URL OPENCTI_TOKEN
  export SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED SIFT_OPENSEARCH_ENABLED
  # B-MVP-015 / B-MVP-004: model cache + pins rendered into the systemd units.
  export SIFT_HF_HOME SIFT_RAG_MODEL_NAME SIFT_RAG_MODEL_REVISION

  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
  # Honor flags already set by main() (e.g. core-only); default to enabled.
  SIFT_RAG_ENABLED="${SIFT_RAG_ENABLED:-true}"
  SIFT_OPENSEARCH_ENABLED="${SIFT_OPENSEARCH_ENABLED:-true}"
  SIFT_OPENCTI_ENABLED="${SIFT_OPENCTI_ENABLED:-false}"

  local rendered
  rendered="$(mktemp)"
  "$SYSTEM_PYTHON" - "$src" "$rendered" "$mode" <<'PY'
import os, sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])  # operator-owned temp; final install is done in bash
mode = int(sys.argv[3], 8)
text = src.read_text()
for key, value in os.environ.items():
    text = text.replace("${" + key + "}", value)
with open(dst, "w") as handle:
    handle.write(text)
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(dst, mode)
PY

  if [[ "$owner" == "root" ]]; then
    sudo_if_needed install -o root -g root -m "$mode" "$rendered" "$dst"
  else
    svc_install_file "$rendered" "$dst" "$mode"
  fi
  rm -f "$rendered"
}

# A1-BOOTSTRAP: write the Supabase env file that the systemd service reads.
# Supabase secrets are NEVER stored in gateway.yaml — only in this env file
# which is chmod 600 and owned by the runtime user.
write_supabase_env() {
  local supabase_env_file="$SIFT_HOME/supabase.env"
  local sb_url="${SUPABASE_URL:-}"
  local sb_anon="${SUPABASE_ANON_KEY:-}"
  local sb_service="${SUPABASE_SERVICE_ROLE_KEY:-}"

  if [[ -z "$sb_url" && -z "$sb_anon" && -z "$sb_service" ]]; then
    log "No SUPABASE_* env vars set — skipping supabase.env."
    log "  To enable Supabase auth, set SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY"
    log "  and re-run ./install.sh, or write them to $supabase_env_file manually."
    return
  fi

  if svc_test_f "$supabase_env_file"; then
    log "Supabase env file already exists — preserving $supabase_env_file."
    return
  fi

  log "Writing Supabase env file: $supabase_env_file"
  # Write to an operator-owned temp, then install it owned sift-service 0600 so
  # the running service can read it but it never lives operator-owned. SIFT_HOME
  # is created by install_state_dirs (owned sift-service 0700).
  local tmp
  tmp="$(mktemp)"
  {
    printf '# Supabase environment — managed by sift-mcps install.sh\n'
    printf '# Secrets are stored here, not in gateway.yaml.\n'
    [[ -n "$sb_url" ]]     && printf 'SUPABASE_URL=%s\n' "$sb_url"
    [[ -n "$sb_anon" ]]    && printf 'SUPABASE_ANON_KEY=%s\n' "$sb_anon"
    [[ -n "$sb_service" ]] && printf 'SUPABASE_SERVICE_ROLE_KEY=%s\n' "$sb_service"
  } > "$tmp"
  svc_install_file "$tmp" "$supabase_env_file" 600
  rm -f "$tmp"
}

# =============================================================================
# Preflight — Supabase env sourcing / auto-provisioning
# =============================================================================
# Integration contract (fixed — see SCOPE in install.sh header):
#   scripts/setup-supabase.sh writes $HOME/.sift/supabase-project/sift-supabase.env
#   containing: export SUPABASE_URL=... SUPABASE_ANON_KEY=... SUPABASE_SERVICE_ROLE_KEY=...
#               export SIFT_CONTROL_PLANE_DSN=postgresql://...
# We source that file, or invoke the script to create it, before any Supabase-dependent
# step runs. Guarded by --core-only and --external-supabase flags.


preflight_supabase() {
  # Not needed for core-only or when operator supplies creds externally.
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" || "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    return 0
  fi

  # Step 1: source the env file if SUPABASE_URL is absent and the file exists.
  if [[ -z "${SUPABASE_URL:-}" && -f "$SUPABASE_PROJECT_ENV" ]]; then
    log "Sourcing Supabase env from $SUPABASE_PROJECT_ENV"
    # shellcheck disable=SC1090
    source "$SUPABASE_PROJECT_ENV"
  fi

  # Step 2: env still absent → invoke setup-supabase.sh (the Supabase agent's script).
  if [[ -z "${SUPABASE_URL:-}" && -f "$REPO_DIR/scripts/setup-supabase.sh" ]]; then
    log "SUPABASE_URL not set — running scripts/setup-supabase.sh to provision Supabase."
    bash "$REPO_DIR/scripts/setup-supabase.sh" \
      || die "scripts/setup-supabase.sh failed.  Cannot continue without Supabase."
    if [[ -f "$SUPABASE_PROJECT_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$SUPABASE_PROJECT_ENV"
    fi
  fi

  # Step 3: still empty → die with an actionable message.
  if [[ -z "${SUPABASE_URL:-}" || -z "${SIFT_CONTROL_PLANE_DSN:-}" ]]; then
    die "Supabase credentials not found.
  Option A (auto-provision): ensure scripts/setup-supabase.sh exists in the repo.
  Option B (external):        export SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY SIFT_CONTROL_PLANE_DSN
                               then re-run: ./install.sh --external-supabase
  Option C (manual file):     write those exports to $SUPABASE_PROJECT_ENV and re-run."
  fi

  log "Supabase preflight OK: SUPABASE_URL=${SUPABASE_URL}"
  export SUPABASE_URL SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY SIFT_CONTROL_PLANE_DSN
}

_env_file_value() {
  # The env files live under SIFT_HOME and are sift-service-owned 0600, so the
  # operator must read them via sudo. svc_read returns empty for a missing file.
  local file="$1" key="$2"
  svc_test_f "$file" || return 0
  svc_read "$file" | awk -F= -v k="$key" '$1 == k {sub(/^[^=]*=/, ""); print; exit}' || true
}

_resolved_control_plane_dsn() {
  local dsn="${SIFT_CONTROL_PLANE_DSN:-${DATABASE_URL:-${POSTGRES_DSN:-}}}"
  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/supabase.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  printf '%s' "$dsn"
}

_resolved_token_pepper() {
  local pepper="${SIFT_TOKEN_PEPPER:-}"
  if [[ -z "$pepper" ]]; then
    pepper="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_TOKEN_PEPPER")"
  fi
  if [[ -z "$pepper" ]]; then
    pepper="$(_env_file_value "$SIFT_HOME/supabase.env" "SIFT_TOKEN_PEPPER")"
  fi
  if [[ -z "$pepper" ]]; then
    pepper="$(random_hex 32)"
  fi
  printf '%s' "$pepper"
}

# B-MVP-010: resolve the portal session secret for env-indirection. Preserve an
# existing value so re-runs do not invalidate live operator sessions; otherwise
# mint a fresh one. The VALUE lives only in the 0600 control-plane.env file
# (gateway.yaml carries only the env-var NAME).
_resolved_session_secret() {
  local secret="${SIFT_PORTAL_SESSION_SECRET:-}"
  if [[ -z "$secret" ]]; then
    secret="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_PORTAL_SESSION_SECRET")"
  fi
  # Upgrade path: if a prior install wrote the literal into gateway.yaml, reuse
  # that exact value so existing operator portal sessions are not invalidated when
  # we move it to env-indirection (B-MVP-010). The literal is stripped from the
  # config by _migrate_gateway_config below.
  if [[ -z "$secret" ]] && svc_test_f "$SIFT_CONFIG"; then
    secret="$(svc_read "$SIFT_CONFIG" | awk -F'"' '/^[[:space:]]*session_secret:[[:space:]]*"/{print $2; exit}')"
  fi
  if [[ -z "$secret" ]]; then
    secret="$(random_hex 32)"
  fi
  printf '%s' "$secret"
}

write_control_plane_env() {
  local control_env_file="$SIFT_HOME/control-plane.env"
  local cp_dsn token_pepper session_secret
  local existing_dsn existing_pepper existing_secret
  cp_dsn="$(_resolved_control_plane_dsn)"
  token_pepper="$(_resolved_token_pepper)"
  # B-MVP-010: the portal session secret value lives here (env-indirection); the
  # gateway config carries only its name. Always resolve it so the portal has a
  # session secret even on core-only installs with no DSN.
  session_secret="$(_resolved_session_secret)"
  existing_dsn="$(_env_file_value "$control_env_file" "SIFT_CONTROL_PLANE_DSN")"
  existing_pepper="$(_env_file_value "$control_env_file" "SIFT_TOKEN_PEPPER")"
  existing_secret="$(_env_file_value "$control_env_file" "SIFT_PORTAL_SESSION_SECRET")"

  # Only skip entirely when there is nothing at all to write (no DSN, no pepper,
  # and no session secret) — otherwise the session secret alone is worth a file.
  if [[ -z "$cp_dsn" && -z "$token_pepper" && -z "$session_secret" ]]; then
    log "No control-plane env vars set — skipping control-plane.env."
    log "  To enable DB authority, set SIFT_CONTROL_PLANE_DSN and re-run ./install.sh."
    return
  fi

  if [[ -n "$existing_dsn" && -n "$existing_pepper" && -n "$existing_secret" ]]; then
    log "Control-plane env file already complete — preserving $control_env_file."
    export SIFT_CONTROL_PLANE_DSN="$existing_dsn"
    export SIFT_TOKEN_PEPPER="$existing_pepper"
    export SIFT_PORTAL_SESSION_SECRET="$existing_secret"
    return
  fi

  [[ -n "$existing_dsn" ]] && cp_dsn="$existing_dsn"
  [[ -n "$existing_pepper" ]] && token_pepper="$existing_pepper"
  [[ -n "$existing_secret" ]] && session_secret="$existing_secret"

  log "Writing control-plane env file: $control_env_file"
  # Operator-owned temp -> sift-service-owned 0600 (see write_supabase_env).
  local tmp
  tmp="$(mktemp)"
  {
    printf '# SIFT control-plane environment — managed by sift-mcps install.sh\n'
    printf '# Secrets are stored here, not in gateway.yaml.\n'
    [[ -n "$cp_dsn" ]] && printf 'SIFT_CONTROL_PLANE_DSN=%s\n' "$cp_dsn"
    # When a control-plane DSN is configured, Postgres is the active-case + audit
    # authority. SIFT_DB_ACTIVE signals that process-wide so the gateway AND the
    # async job worker (which has no per-request AuthorityContext) suppress the
    # legacy file-audit "Audit write failed" warning and treat the DB envelope as
    # authority. Non-secret flag; read by sift_core.active_case_context and
    # sift_common.audit. (Both units read this file via EnvironmentFile.)
    [[ -n "$cp_dsn" ]] && printf 'SIFT_DB_ACTIVE=1\n'
    [[ -n "$token_pepper" ]] && printf 'SIFT_TOKEN_PEPPER=%s\n' "$token_pepper"
    [[ -n "$session_secret" ]] && printf 'SIFT_PORTAL_SESSION_SECRET=%s\n' "$session_secret"
  } > "$tmp"
  svc_install_file "$tmp" "$control_env_file" 600
  rm -f "$tmp"
  [[ -n "$cp_dsn" ]] && export SIFT_CONTROL_PLANE_DSN="$cp_dsn"
  [[ -n "$token_pepper" ]] && export SIFT_TOKEN_PEPPER="$token_pepper"
  [[ -n "$session_secret" ]] && export SIFT_PORTAL_SESSION_SECRET="$session_secret"
}

# =============================================================================
# DB migrations — apply supabase/migrations/*.sql against SIFT_CONTROL_PLANE_DSN
# =============================================================================
# Migrations are idempotent (CREATE ... IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
# Uses psycopg3 (available in the venv) with autocommit + simple-query protocol
# so multi-statement DDL files execute correctly (no parameter binding = no parse
# step that would reject semicolons).
# Guards: skips if --core-only or SIFT_CONTROL_PLANE_DSN empty.
