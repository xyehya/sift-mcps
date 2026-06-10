#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# setup-addon.sh — OPTIONAL helper for external add-on backends
# =============================================================================
#
# The SIFT Protocol Gateway (SPG) — core + gateway + portal + the agent's
# in-process MCP server — is the product. It is installed by:
#
#       ./install.sh --core-only
#
# and is complete on its own. Add-on backends (OpenCTI, OpenSearch,
# windows-triage, or ANY backend a third party writes to the
# SIFT MCP Backend Contract) are EXTERNAL, INDEPENDENT, and OPTIONAL. The three
# shipped here are merely *reference implementations* of the contract. An
# NOTE: forensic-rag-mcp removed as add-on (BATCH-PMI2); RAG served by the
# gateway core tool rag_search_case (Supabase pgvector) instead.
# operator may run zero, one, or several — or bring their own.
#
# There is exactly ONE integration door, identical for every backend:
#
#       point the portal at the backend's `sift-backend.json` manifest
#         -> the portal validates it against the spec
#         -> on pass, it registers the backend and hot-reloads the gateway
#
# This script NEVER registers anything and NEVER edits gateway.yaml. The core
# stays add-on-agnostic. All this helper does is, per backend you select:
#
#   1. (optionally) provision that reference backend's prerequisites
#      (downloads / Docker stacks / index bootstrap), and
#   2. prompt for + ECHO every config and env variable, then
#   3. write a ready-to-submit register payload to
#      ~/.sift/addon-register/<name>.json
#
# You then drive validate -> register -> hot-reload yourself, from
# Portal -> Backends (or the REST API). That is the same door a community
# backend uses — the payload this script writes carries an explicit
# `manifest_path`, exactly as an external backend would.
#
# Usage:
#   ./scripts/setup-addon.sh            # interactive menu
#   ./scripts/setup-addon.sh --help
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Source install.sh as a function library (it self-guards: main() runs only when
# install.sh is executed directly). This gives us the provisioning functions and
# the resolved SIFT_* / REPO_DIR path vars without kicking off an install.
# shellcheck source=/dev/null
source "$REPO_ROOT/install.sh"

# install.sh defines log/warn/die; add a couple of local helpers.
hr()  { printf -- '---------------------------------------------------------------\n'; }
ask() {
  # ask "Prompt" "default" -> echoes the answer (default if empty)
  local prompt="$1" default="${2:-}" reply=""
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$prompt" "$default" >&2
  else
    printf '%s: ' "$prompt" >&2
  fi
  read -r reply || reply=""
  printf '%s' "${reply:-$default}"
}
ask_yes() {
  # ask_yes "Prompt" -> returns 0 for yes (default Y)
  local reply=""
  printf '%s [Y/n]: ' "$1" >&2
  read -r reply || reply=""
  [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '4,52p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

# --- resolve the bits the payloads need ------------------------------------
UV_BIN="$(resolve_uv)"
[[ -n "$UV_BIN" ]] || die "uv not found. Run ./install.sh --core-only first."
SIFT_MCPS_ROOT="$REPO_DIR"
PYTHON_BIN="$SYSTEM_PYTHON"
REGISTER_DIR="$SIFT_HOME/addon-register"
install -d -m 700 "$REGISTER_DIR"

# Payload globals (reset per backend).
PAYLOAD_NAME="" PAYLOAD_TYPE="stdio" PAYLOAD_COMMAND="" PAYLOAD_URL="" PAYLOAD_MANIFEST=""
declare -a PAYLOAD_ARGS=()
declare -a PAYLOAD_ENV=()

reset_payload() {
  PAYLOAD_NAME="" PAYLOAD_TYPE="stdio" PAYLOAD_COMMAND="" PAYLOAD_URL="" PAYLOAD_MANIFEST=""
  PAYLOAD_ARGS=()
  PAYLOAD_ENV=()
}

stdio_args() {
  # stdio_args <entry-script> -> fills PAYLOAD_ARGS with the standard uv invocation
  PAYLOAD_ARGS=(run --project "$SIFT_MCPS_ROOT" --python "$PYTHON_BIN"
                --no-managed-python --no-python-downloads "$1")
}

print_manifest_summary() {
  local mf="$1"
  if [[ ! -f "$mf" ]]; then
    warn "Manifest not found: $mf"
    return 1
  fi
  "$SYSTEM_PYTHON" - "$mf" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
caps = m.get("capabilities", {})
print(f"  manifest   : {sys.argv[1]}")
print(f"  namespace  : {m.get('namespace', '?')}   (tool prefix: {m.get('namespace','?')}_*)")
print(f"  spec_ver   : {m.get('spec_version', '?')}")
print(f"  provides   : {caps.get('provides', [])}")
print(f"  requires   : {caps.get('requires', [])}")
print(f"  health     : {m.get('health', '?')}")
print(f"  tools      : {len(m.get('tools', []))} declared")
PY
}

write_payload() {
  local out="$REGISTER_DIR/${PAYLOAD_NAME}.json"
  local args_str env_str
  args_str="$(printf '%s\n' "${PAYLOAD_ARGS[@]:-}")"
  env_str="$(printf '%s\n' "${PAYLOAD_ENV[@]:-}")"
  PAYLOAD_NAME="$PAYLOAD_NAME" PAYLOAD_TYPE="$PAYLOAD_TYPE" PAYLOAD_COMMAND="$PAYLOAD_COMMAND" \
  PAYLOAD_URL="$PAYLOAD_URL" PAYLOAD_MANIFEST="$PAYLOAD_MANIFEST" \
  PAYLOAD_ARGS_STR="$args_str" PAYLOAD_ENV_STR="$env_str" \
  "$SYSTEM_PYTHON" - "$out" <<'PY'
import json, os, sys
out = sys.argv[1]
config = {"type": os.environ.get("PAYLOAD_TYPE", "stdio"), "enabled": True}
if os.environ.get("PAYLOAD_COMMAND"):
    config["command"] = os.environ["PAYLOAD_COMMAND"]
if os.environ.get("PAYLOAD_URL"):
    config["url"] = os.environ["PAYLOAD_URL"]
args = [a for a in os.environ.get("PAYLOAD_ARGS_STR", "").splitlines() if a]
if args:
    config["args"] = args
env = {}
for line in os.environ.get("PAYLOAD_ENV_STR", "").splitlines():
    if not line.strip() or "=" not in line:
        continue
    k, v = line.split("=", 1)
    env[k] = v
if env:
    config["env"] = env
if os.environ.get("PAYLOAD_MANIFEST"):
    config["manifest_path"] = os.environ["PAYLOAD_MANIFEST"]
doc = {"name": os.environ["PAYLOAD_NAME"], "config": config}
with open(out, "w") as fh:
    fh.write(json.dumps(doc, indent=2) + "\n")
print(out)
PY
}

echo_vars_and_emit() {
  # Echo every variable, write the payload, print next-step hints.
  hr
  log "Resolved configuration for '$PAYLOAD_NAME' (every value shown — nothing hidden):"
  printf '  name        : %s\n' "$PAYLOAD_NAME"
  printf '  transport   : %s\n' "$PAYLOAD_TYPE"
  [[ -n "$PAYLOAD_COMMAND" ]] && printf '  command     : %s\n' "$PAYLOAD_COMMAND"
  [[ -n "$PAYLOAD_URL" ]]     && printf '  url         : %s\n' "$PAYLOAD_URL"
  if [[ ${#PAYLOAD_ARGS[@]} -gt 0 ]]; then
    printf '  args        : %s\n' "${PAYLOAD_ARGS[*]}"
  fi
  if [[ ${#PAYLOAD_ENV[@]} -gt 0 ]]; then
    printf '  env:\n'
    local kv
    for kv in "${PAYLOAD_ENV[@]}"; do printf '    %s\n' "$kv"; done
  fi
  [[ -n "$PAYLOAD_MANIFEST" ]] && printf '  manifest    : %s\n' "$PAYLOAD_MANIFEST"
  local out
  out="$(write_payload)"
  hr
  log "Register payload written: $out"
  log "Integrate it through the ONE generic contract door (NOT this script):"
  printf '    Portal -> Backends -> Add backend -> paste/point at the manifest -> Validate -> Register\n'
  printf '  Or via REST (examiner-authed), validate first (read-only), then register:\n'
  printf '    curl -k -X POST https://<host>:4508/api/v1/backends/validate -d @%s\n' "$out"
  printf '    curl -k -X POST https://<host>:4508/api/v1/backends          -d @%s\n' "$out"
  hr
}

# =============================================================================
# Reference add-on backends (examples of the contract — not special-cased core)
# =============================================================================
# NOTE BATCH-PMI2: forensic-rag-mcp (setup_rag) has been removed from this
# menu.  RAG has a single agent-facing home: the gateway core tool
# rag_search_case (Supabase pgvector).  The forensic-rag-mcp package remains
# as a library/CLI for the Chroma->pgvector import step only; it no longer
# has agent-facing tools and does not need to be registered as an add-on.
# Use:  python -m rag_mcp.pgvector_chroma_import
#       python -m rag_mcp.pgvector_seed

setup_wintriage() {
  reset_payload
  PAYLOAD_NAME="windows-triage-mcp"
  PAYLOAD_MANIFEST="$REPO_DIR/packages/windows-triage-mcp/sift-backend.json"
  log "== windows-triage-mcp (reference backend, provides: reference, baseline) =="
  print_manifest_summary "$PAYLOAD_MANIFEST" || true
  SIFT_WINDOWS_TRIAGE_DB_DIR="$(ask 'Triage baseline DB dir' "$SIFT_WINDOWS_TRIAGE_DB_DIR")"
  if ask_yes "Provision prerequisites (download triage baseline databases)?"; then
    download_triage_databases || warn "Triage DB download incomplete — backend may start degraded."
  fi
  stdio_args "windows-triage-mcp"
  PAYLOAD_COMMAND="$UV_BIN"
  PAYLOAD_ENV=("SIFT_WINDOWS_TRIAGE_DB_DIR=$SIFT_WINDOWS_TRIAGE_DB_DIR")
  echo_vars_and_emit
}

setup_opensearch() {
  reset_payload
  PAYLOAD_NAME="opensearch-mcp"
  PAYLOAD_MANIFEST="$REPO_DIR/packages/opensearch-mcp/sift-backend.json"
  log "== opensearch-mcp (reference backend, provides: search, ingest, enrichment) =="
  print_manifest_summary "$PAYLOAD_MANIFEST" || true
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker not found. This backend declares requires:[\"https://localhost:9200\"];"
    warn "without a reachable OpenSearch the portal will register it but mark it UNAVAILABLE (core stays up)."
  fi
  local os_config os_host
  os_config="$(ask 'OPENSEARCH_CONFIG path' "$SIFT_HOME/opensearch.yaml")"
  os_host="$(ask 'OPENSEARCH_HOST' 'http://127.0.0.1:9200')"
  if command -v docker >/dev/null 2>&1 && ask_yes "Provision prerequisites (write config, start OpenSearch via Docker, configure cluster/geoip/templates)?"; then
    { write_opensearch_config && start_opensearch && configure_opensearch_cluster \
        && configure_geoip_pipeline && install_opensearch_templates; } \
      || warn "OpenSearch provisioning incomplete — check Docker and retry; backend will be UNAVAILABLE until reachable."
  fi
  stdio_args "opensearch-mcp"
  PAYLOAD_COMMAND="$UV_BIN"
  PAYLOAD_ENV=("OPENSEARCH_CONFIG=$os_config" "OPENSEARCH_HOST=$os_host")
  echo_vars_and_emit
}

setup_opencti() {
  reset_payload
  PAYLOAD_NAME="opencti-mcp"
  PAYLOAD_MANIFEST="$REPO_DIR/packages/opencti-mcp/sift-backend.json"
  log "== opencti-mcp (reference backend, provides: reference, threat-intel) =="
  print_manifest_summary "$PAYLOAD_MANIFEST" || true
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker not found — OpenCTI's own stack cannot be started here. You can still point at an external OpenCTI."
  fi
  local octi_url octi_token
  octi_url="$(ask 'OPENCTI_URL' 'http://127.0.0.1:8080')"
  if command -v docker >/dev/null 2>&1 && ask_yes "Provision prerequisites (prepare secrets, start OpenCTI stack + feeds — needs >=14 GB RAM)?"; then
    { prepare_opencti_secrets && install_opencti && install_opencti_feeds; } \
      || warn "OpenCTI provisioning incomplete — backend will be UNAVAILABLE until reachable."
    octi_token="${OPENCTI_TOKEN:-}"
  fi
  octi_token="$(ask 'OPENCTI_TOKEN' "${octi_token:-}")"
  stdio_args "opencti-mcp"
  PAYLOAD_COMMAND="$UV_BIN"
  PAYLOAD_ENV=("OPENCTI_URL=$octi_url" "OPENCTI_TOKEN=$octi_token")
  echo_vars_and_emit
}

setup_custom() {
  reset_payload
  log "== Custom / community backend (your own conformant SIFT MCP backend) =="
  log "This is the SAME path the reference backends use — proving the contract is open."
  PAYLOAD_NAME="$(ask 'Backend name (lowercase, digits, hyphens)')"
  [[ "$PAYLOAD_NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { warn "Invalid backend name — skipping."; return; }
  PAYLOAD_TYPE="$(ask 'Transport (stdio/http)' 'stdio')"
  if [[ "$PAYLOAD_TYPE" == "http" ]]; then
    PAYLOAD_URL="$(ask 'Backend base URL (e.g. https://host:port)')"
    PAYLOAD_MANIFEST="$(ask 'Manifest path or URL (sift-backend.json)')"
  else
    PAYLOAD_COMMAND="$(ask 'Command to launch the backend (e.g. uv or an executable)')"
    local raw_args
    raw_args="$(ask 'Args (space-separated, optional)' '')"
    if [[ -n "$raw_args" ]]; then
      # shellcheck disable=SC2206
      PAYLOAD_ARGS=($raw_args)
    fi
    PAYLOAD_MANIFEST="$(ask 'Manifest path (local sift-backend.json the gateway can read)')"
  fi
  log "Add env vars (KEY=VALUE). Blank line to finish."
  while true; do
    local kv
    kv="$(ask '  env' '')"
    [[ -z "$kv" ]] && break
    [[ "$kv" == *=* ]] || { warn "  expected KEY=VALUE; skipped"; continue; }
    PAYLOAD_ENV+=("$kv")
  done
  echo_vars_and_emit
}

# =============================================================================
# Menu
# =============================================================================

main_menu() {
  hr
  log "SPG add-on integration helper — SPG core is already complete on its own."
  log "Select OPTIONAL external add-on backends to prepare (any subset, or a custom one):"
  printf '   1) windows-triage-mcp    (provides: reference, baseline)\n'
  printf '   2) opensearch-mcp        (provides: search, ingest, enrichment; needs Docker)\n'
  printf '   3) opencti-mcp           (provides: reference, threat-intel; needs Docker + RAM)\n'
  printf '   4) custom / community backend (bring your own conformant manifest)\n'
  printf '   a) all reference backends (1-3)\n'
  printf '   q) quit\n'
  hr
  local sel
  sel="$(ask 'Selection (e.g. "1 2" or "a")' '')"
  [[ -z "$sel" || "$sel" == "q" ]] && { log "Nothing selected — exiting."; exit 0; }
  if [[ "$sel" == "a" ]]; then sel="1 2 3"; fi
  sel="${sel//,/ }"
  local tok
  for tok in $sel; do
    case "$tok" in
      1) setup_wintriage ;;
      2) setup_opensearch ;;
      3) setup_opencti ;;
      4) setup_custom ;;
      *) warn "Unknown selection: $tok (ignored)" ;;
    esac
  done

  hr
  log "Done. Register payloads are in: $REGISTER_DIR"
  log "Reminder: this script changed NOTHING in the gateway. Integration happens"
  log "through the portal/REST contract door — validate first, then register."
  log "After registering: confirm with tools/list (namespaced tools appear) and"
  log "environment_summary (backend health). Disabling it makes its tools vanish;"
  log "the SPG core never goes down with it."
}

main_menu
