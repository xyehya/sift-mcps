# shellcheck shell=bash
# =============================================================================
# lib/config.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_CONFIG_SOURCED:-}" ]] && return 0
_SIFT_LIB_CONFIG_SOURCED=1

write_gateway_config() {
  # SIFT_CONFIG lives under SIFT_HOME (sift-service-owned 0700/0600), so the
  # existence check must use sudo.
  if svc_test_f "$SIFT_CONFIG"; then
    log "Gateway config exists — preserving $SIFT_CONFIG."
    CONFIG_CREATED=0
    SIFT_GATEWAY_TOKEN=""
    SIFT_SERVICE_TOKEN=""
    SIFT_PORTAL_SESSION_SECRET=""
    _migrate_gateway_config
    return
  fi
  SIFT_GATEWAY_TOKEN="sift_gw_$(random_hex 24)"
  SIFT_SERVICE_TOKEN="sift_svc_$(random_hex 24)"
  # B-MVP-010: the portal session secret is no longer rendered into gateway.yaml
  # (the template carries only session_secret_env, the env-var NAME). The VALUE is
  # owned by write_control_plane_env (control-plane.env, 0600). Keep the var empty
  # here so a stale literal can never leak into the rendered config.
  SIFT_PORTAL_SESSION_SECRET=""
  SIFT_TOKEN_CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  CONFIG_CREATED=1
  export SIFT_GATEWAY_TOKEN SIFT_SERVICE_TOKEN SIFT_PORTAL_SESSION_SECRET SIFT_TOKEN_CREATED_AT
  _render_file "$REPO_DIR/configs/gateway.yaml.template" "$SIFT_CONFIG" 0600
}

_migrate_gateway_config() {
  log "Checking gateway config compatibility."
  # SIFT_CONFIG is sift-service-owned 0600. The operator runs the (uv) migration,
  # so it reads/writes operator-owned temps and the result is installed back
  # owned sift-service. Read the live config into a temp via sudo.
  local cfg_src cfg_out
  cfg_src="$(mktemp)"
  cfg_out="$(mktemp)"
  trap 'rm -f "${cfg_src:-}" "${cfg_out:-}"; trap - EXIT' EXIT
  if ! sudo_if_needed cat "$SIFT_CONFIG" > "$cfg_src" 2>/dev/null; then
    warn "_migrate_gateway_config: could not read $SIFT_CONFIG — skipping migration."
    rm -f "$cfg_src" "$cfg_out"
    trap - EXIT
    return 0
  fi
  export SIFT_CONFIG_SRC="$cfg_src" SIFT_CONFIG_OUT="$cfg_out"
  export SIFT_MCPS_ROOT PYTHON_BIN OPENCTI_URL OPENCTI_TOKEN
  export SIFT_EXECUTE_AS_USER
  export SIFT_RAG_ENABLED SIFT_OPENCTI_ENABLED
  SIFT_MCPS_ROOT="$REPO_DIR"
  PYTHON_BIN="$SYSTEM_PYTHON"
  SIFT_RAG_ENABLED="true"
  SIFT_OPENCTI_ENABLED="${SIFT_OPENCTI_ENABLED:-false}"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"

  "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads python - <<'PY'
import os, sys
from pathlib import Path
import yaml

src = Path(os.environ["SIFT_CONFIG_SRC"])
out = Path(os.environ["SIFT_CONFIG_OUT"])
cfg = yaml.safe_load(src.read_text()) or {}
changed = False

# Normalise TLS key names
gateway = cfg.setdefault("gateway", {})
tls = gateway.get("tls")
if isinstance(tls, dict):
    if "certfile" not in tls and "cert" in tls:
        tls["certfile"] = tls.pop("cert")
        changed = True
    if "keyfile" not in tls and "key" in tls:
        tls["keyfile"] = tls.pop("key")
        changed = True

# B-MVP-010: migrate an inline portal session secret to env-indirection. The
# literal value was already copied into control-plane.env by write_control_plane_env
# (via _resolved_session_secret reading this same file), so here we just strip the
# literal and replace it with the env-var NAME. Idempotent.
portal_cfg = cfg.setdefault("portal", {})
if isinstance(portal_cfg, dict) and "session_secret" in portal_cfg:
    portal_cfg.pop("session_secret", None)
    portal_cfg["session_secret_env"] = "SIFT_PORTAL_SESSION_SECRET"
    changed = True
elif isinstance(portal_cfg, dict) and not portal_cfg.get("session_secret_env"):
    portal_cfg["session_secret_env"] = "SIFT_PORTAL_SESSION_SECRET"
    changed = True

# RAG / triage / opencti enabled flags
enrichment = cfg.setdefault("enrichment", {})
if enrichment.get("forensic_rag") is not True and os.environ.get("SIFT_RAG_ENABLED") == "true":
    enrichment["forensic_rag"] = True
    changed = True

# NOTE: the installer no longer auto-enables add-on backends. Add-ons are
# external/optional and are integrated through the portal self-service contract
# door (validate -> register -> hot-reload), which writes their backend entry.
# We only normalise args for whatever backends already exist (e.g.
# portal-registered ones) below — we never add or enable a backend here.
cfg.setdefault("backends", {})

# Native runtime user for run_command. Existing configs predate this key, so
# migrate them to the installer default instead of leaving production same-user.
execute = cfg.setdefault("execute", {})
if isinstance(execute, dict) and "runtime_user" not in execute:
    execute["runtime_user"] = os.environ.get("SIFT_EXECUTE_AS_USER") or "agent_runtime"
    changed = True
if isinstance(execute, dict):
    security = execute.setdefault("security", {})
    if isinstance(security, dict):
        if security.get("mode") != "allowlist":
            security["mode"] = "allowlist"
            changed = True
        if security.get("allowed_binaries") in (None, [], ()):
            security["allowed_binaries"] = ["@mvp_forensic"]
            changed = True
        if security.get("unlisted_policy") != "contained":
            security["unlisted_policy"] = "contained"
            changed = True

# Backend arg normalisation (ensure --python, --no-managed-python, --no-python-downloads)
root = os.environ.get("SIFT_MCPS_ROOT") or ""
python_bin = os.environ.get("PYTHON_BIN") or ""
for backend in (cfg.get("backends") or {}).values():
    if not isinstance(backend, dict):
        continue
    args = backend.get("args")
    if not isinstance(args, list) or not args or args[0] != "run":
        continue
    if "--python" in args and "--no-managed-python" in args and "--no-python-downloads" in args:
        continue
    script = args[-1]
    project = root
    if "--project" in args:
        try:
            project = args[args.index("--project") + 1]
        except IndexError:
            project = root
    backend["args"] = [
        "run", "--project", project, "--python", python_bin,
        "--no-managed-python", "--no-python-downloads", script,
    ]
    changed = True

if changed:
    with open(out, "w") as handle:
        os.chmod(out, 0o600)
        yaml.safe_dump(cfg, handle, sort_keys=False)
        handle.flush()
        os.fsync(handle.fileno())
    print("changed")
else:
    print("unchanged")
PY

  # Install the migrated config back, owned sift-service 0600, only if changed.
  if [[ -s "$cfg_out" ]]; then
    log "Gateway config migrated — installing updated $SIFT_CONFIG (owned $SIFT_GATEWAY_SERVICE_USER)."
    svc_install_file "$cfg_out" "$SIFT_CONFIG" 600
  fi
  rm -f "$cfg_src" "$cfg_out"
  trap - EXIT
}

write_opensearch_config() {
  # OPENSEARCH_CONFIG (opensearch.env) points the opensearch-mcp backend at this
  # file, so it must be sift-service-readable. SIFT_HOME is sift-service-owned
  # 0700 — write to an operator temp, then install owned sift-service 0600.
  local os_config="$SIFT_HOME/opensearch.yaml"
  if svc_test_f "$os_config"; then
    log "OpenSearch client config exists — preserving $os_config."
    return
  fi
  local tmp
  tmp="$(mktemp)"
  # Clean up the secret-bearing temp on any set -e abort (e.g. svc_install_file
  # failure) so the rendered credentials never linger in /tmp; self-clearing.
  trap 'rm -f "${tmp:-}"; trap - EXIT' EXIT
  cat > "$tmp" <<'YAML'
host: http://127.0.0.1:9200
user: admin
password: admin
verify_certs: false
YAML
  svc_install_file "$tmp" "$os_config" 600
  rm -f "$tmp"
  trap - EXIT
}

# FM-2: write gateway env file for OpenSearch env_refs so the backend process
# receives OPENSEARCH_CONFIG and OPENSEARCH_HOST from the gateway's environment.
# Idempotent (recreate only if missing); chmod 600 to guard the config path.
# Called only when SIFT_OPENSEARCH_ENABLED=true; consumed by the gateway
# service via EnvironmentFile=-${SIFT_HOME}/opensearch.env.
write_opensearch_env() {
  [[ "${SIFT_OPENSEARCH_ENABLED:-false}" == "true" ]] || return 0
  local os_env_file="$SIFT_HOME/opensearch.env"
  if svc_test_f "$os_env_file"; then
    log "OpenSearch env file already exists — preserving $os_env_file."
    return
  fi
  log "Writing OpenSearch gateway env file: $os_env_file"
  # Operator-owned temp -> sift-service-owned 0600 (see write_supabase_env).
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "${tmp:-}"; trap - EXIT' EXIT
  {
    printf '# OpenSearch env — gateway env_refs for opensearch-mcp backend\n'
    printf '# Written by sift-mcps install.sh. Idempotent — delete to regenerate.\n'
    printf 'OPENSEARCH_CONFIG=%s/opensearch.yaml\n' "$SIFT_HOME"
    printf 'OPENSEARCH_HOST=http://127.0.0.1:9200\n'
  } > "$tmp"
  svc_install_file "$tmp" "$os_env_file" 600
  rm -f "$tmp"
  trap - EXIT
}

# BATCH-PMI3: write the gateway/worker env file that points the forensic-knowledge
# loader at the installed data dir. Without FK_DATA_DIR in the service env, the
# loader cannot resolve the data dir under the service user (no source tree /
# importlib.resources data on a packaged install), so build_response and the
# run_command path silently skip FK enrichment. FK data is a core runtime dep
# (D4); prepare_enrichment_assets lays it down at
# $SIFT_ENRICHMENT_DIR/forensic-knowledge, which is the path we publish here.
# Consumed by both units via EnvironmentFile=-${SIFT_HOME}/forensic-knowledge.env.
# Idempotent (recreate only if missing). FK_DATA_DIR is a non-secret path.
write_fk_env() {
  local fk_data_dir="$SIFT_ENRICHMENT_DIR/forensic-knowledge"
  local fk_env_file="$SIFT_HOME/forensic-knowledge.env"
  if svc_test_f "$fk_env_file"; then
    log "forensic-knowledge env file already exists — preserving $fk_env_file."
    return
  fi
  log "Writing forensic-knowledge env file: $fk_env_file"
  # Non-secret path file: install owned sift-service, mode 0644. (SIFT_HOME is
  # 0700 sift-service, so only the service can traverse to it regardless.)
  local tmp
  tmp="$(mktemp)"
  {
    printf '# forensic-knowledge env — FK_DATA_DIR for the FK loader (core enrichment)\n'
    printf '# Written by sift-mcps install.sh. Idempotent — delete to regenerate.\n'
    printf 'FK_DATA_DIR=%s\n' "$fk_data_dir"
  } > "$tmp"
  svc_install_file "$tmp" "$fk_env_file" 644
  rm -f "$tmp"
}

# =============================================================================
