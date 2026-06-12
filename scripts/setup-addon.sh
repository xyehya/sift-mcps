#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# setup-addon.sh — OPTIONAL helper for external add-on backends
# =============================================================================
#
# The SIFT Protocol Gateway (SPG) — core + gateway + portal + the agent's
# in-process MCP server — is the product. The native stack is installed by:
#
#       ./install.sh
#
# and is complete on its own. Add-on backends (OpenCTI, OpenSearch,
# forensic-rag, or ANY backend a third party writes to the
# SIFT MCP Backend Contract) are EXTERNAL, INDEPENDENT, and OPTIONAL. The ones
# shipped here are merely *reference implementations* of the contract. An
# NOTE (BATCH-OSX-RAG): forensic-rag-mcp is registered as the knowledge
# reference backend (kb_search_knowledge etc.) backed by Supabase pgvector;
# the gateway rag_search_case shim PMI2 added has been removed.
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
# AD2: PAYLOAD_ENV_REFS holds CHILD_ENV=GATEWAY_ENV name->name pairs. The
# register payload must carry env_refs (the only env shape the gateway registry
# accepts), NEVER a raw `env` map — normalize_connection_config rejects raw
# secret fields including "env". The gateway resolves each gateway-env name from
# its OWN process environment at backend startup, so no secret value is ever
# written to ~/.sift/addon-register/<name>.json or stored in app.mcp_backends.
declare -a PAYLOAD_ENV_REFS=()

reset_payload() {
  PAYLOAD_NAME="" PAYLOAD_TYPE="stdio" PAYLOAD_COMMAND="" PAYLOAD_URL="" PAYLOAD_MANIFEST=""
  PAYLOAD_ARGS=()
  PAYLOAD_ENV_REFS=()
}

stdio_args() {
  # stdio_args <entry-script> [extra ...] -> fills PAYLOAD_ARGS with the
  # standard uv invocation. Extras let external reference add-ons stay out of
  # the native installer while remaining runnable through the same checkout.
  local entry_script="$1"
  shift || true
  PAYLOAD_ARGS=(run --project "$SIFT_MCPS_ROOT")
  local extra
  for extra in "$@"; do
    PAYLOAD_ARGS+=(--extra "$extra")
  done
  PAYLOAD_ARGS+=(--python "$PYTHON_BIN"
                --no-managed-python --no-python-downloads "$entry_script")
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
  local args_str env_refs_str
  args_str="$(printf '%s\n' "${PAYLOAD_ARGS[@]:-}")"
  # AD2: emit env_refs (CHILD=GATEWAY name->name), never a raw env value map.
  env_refs_str="$(printf '%s\n' "${PAYLOAD_ENV_REFS[@]:-}")"
  PAYLOAD_NAME="$PAYLOAD_NAME" PAYLOAD_TYPE="$PAYLOAD_TYPE" PAYLOAD_COMMAND="$PAYLOAD_COMMAND" \
  PAYLOAD_URL="$PAYLOAD_URL" PAYLOAD_MANIFEST="$PAYLOAD_MANIFEST" \
  PAYLOAD_ARGS_STR="$args_str" PAYLOAD_ENV_REFS_STR="$env_refs_str" \
  "$SYSTEM_PYTHON" - "$out" <<'PY'
import json, os, re, sys
out = sys.argv[1]
config = {"type": os.environ.get("PAYLOAD_TYPE", "stdio"), "enabled": True}
if os.environ.get("PAYLOAD_COMMAND"):
    config["command"] = os.environ["PAYLOAD_COMMAND"]
if os.environ.get("PAYLOAD_URL"):
    config["url"] = os.environ["PAYLOAD_URL"]
args = [a for a in os.environ.get("PAYLOAD_ARGS_STR", "").splitlines() if a]
if args:
    config["args"] = args
# env_refs: each line is CHILD_ENV_NAME=GATEWAY_ENV_NAME. Both sides must be
# valid env identifiers; the gateway resolves GATEWAY_ENV_NAME from its own
# process environment at backend startup. No secret VALUES live in this file.
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
env_refs = {}
for line in os.environ.get("PAYLOAD_ENV_REFS_STR", "").splitlines():
    if not line.strip() or "=" not in line:
        continue
    child, gateway_var = line.split("=", 1)
    child, gateway_var = child.strip(), gateway_var.strip()
    if not (_NAME.match(child) and _NAME.match(gateway_var)):
        raise SystemExit(
            f"env_refs entry {child!r}->{gateway_var!r} is not a valid "
            "CHILD_ENV=GATEWAY_ENV identifier pair"
        )
    env_refs[child] = gateway_var
if env_refs:
    config["env_refs"] = env_refs
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
  if [[ ${#PAYLOAD_ENV_REFS[@]} -gt 0 ]]; then
    printf '  env_refs (child <- gateway env var; values resolved from gateway env, not stored):\n'
    local kv
    for kv in "${PAYLOAD_ENV_REFS[@]}"; do printf '    %s\n' "$kv"; done
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
# BATCH-OSX-RAG: forensic-rag-mcp is restored as the knowledge reference
# backend (kb_search_knowledge / kb_list_knowledge_sources /
# kb_get_knowledge_stats), backed by Supabase pgvector. The gateway
# rag_search_case shim that PMI2 added has been removed. The Chroma->pgvector
# importers remain as CLI helpers for the knowledge load step:
#   python -m rag_mcp.pgvector_chroma_import
#   python -m rag_mcp.pgvector_seed
setup_rag() {
  reset_payload
  PAYLOAD_NAME="forensic-rag-mcp"
  PAYLOAD_MANIFEST="$REPO_DIR/packages/forensic-rag-mcp/sift-backend.json"
  log "== forensic-rag-mcp (reference backend, provides: reference; pgvector knowledge) =="
  print_manifest_summary "$PAYLOAD_MANIFEST" || true
  warn "This backend reads the shared knowledge corpus from Supabase pgvector."
  warn "Ensure the knowledge corpus is loaded (rag-mcp-import-chroma-pgvector / rag-mcp-seed-pgvector)."
  warn "It resolves the control-plane DSN from the SIFT_CONTROL_PLANE_DSN env ref;"
  warn "no raw DSN is stored in the register payload."
  warn "RAG_MODEL_NAME (query embedding model) is read from the gateway's own"
  warn "environment; set it there (default BAAI/bge-base-en-v1.5) before registering."
  stdio_args "rag-mcp" "full"
  PAYLOAD_COMMAND="$UV_BIN"
  # env_refs only (CHILD=GATEWAY name->name): the gateway resolves both names
  # from its OWN process env at backend startup. No raw DSN or value is stored.
  PAYLOAD_ENV_REFS=(
    "SIFT_CONTROL_PLANE_DSN=SIFT_CONTROL_PLANE_DSN"
    "RAG_MODEL_NAME=RAG_MODEL_NAME"
  )
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
  if command -v docker >/dev/null 2>&1 && ask_yes "Provision prerequisites (write config, start OpenSearch via Docker, configure cluster/geoip/templates)?"; then
    { write_opensearch_config && start_opensearch && configure_opensearch_cluster \
        && configure_geoip_pipeline && install_opensearch_templates; } \
      || warn "OpenSearch provisioning incomplete — check Docker and retry; backend will be UNAVAILABLE until reachable."
  fi
  warn "OPENSEARCH_CONFIG / OPENSEARCH_HOST are resolved from the gateway's own"
  warn "environment (matching install.sh seed_addon_backends). Set them there"
  warn "(e.g. OPENSEARCH_CONFIG=$SIFT_HOME/opensearch.yaml,"
  warn " OPENSEARCH_HOST=http://127.0.0.1:9200) before registering."
  stdio_args "opensearch-mcp" "standard"
  PAYLOAD_COMMAND="$UV_BIN"
  # env_refs only: name->name, resolved from gateway env. Matches install.sh.
  PAYLOAD_ENV_REFS=(
    "OPENSEARCH_CONFIG=OPENSEARCH_CONFIG"
    "OPENSEARCH_HOST=OPENSEARCH_HOST"
  )
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
  if command -v docker >/dev/null 2>&1 && ask_yes "Provision prerequisites (prepare secrets, start OpenCTI stack + feeds — needs >=14 GB RAM)?"; then
    SIFT_OPENCTI_ENABLED=true
    { prepare_opencti_secrets && install_opencti && install_opencti_feeds; } \
      || warn "OpenCTI provisioning incomplete — backend will be UNAVAILABLE until reachable."
  fi
  warn "OpenCTI credentials are NEVER written to the register payload. The child"
  warn "OPENCTI_URL / OPENCTI_TOKEN are resolved by the gateway from its OWN env"
  warn "vars SIFT_OPENCTI_URL / SIFT_OPENCTI_TOKEN at backend startup. Set those"
  warn "in the gateway environment (systemd EnvironmentFile) before registering."
  stdio_args "opencti-mcp" "opencti"
  PAYLOAD_COMMAND="$UV_BIN"
  # env_refs only (spec §4.3): CHILD=GATEWAY name->name. The raw token never
  # touches this file or app.mcp_backends; the registry rejects a raw `env` map.
  PAYLOAD_ENV_REFS=(
    "OPENCTI_URL=SIFT_OPENCTI_URL"
    "OPENCTI_TOKEN=SIFT_OPENCTI_TOKEN"
  )
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
  log "Add env_refs as CHILD_ENV=GATEWAY_ENV (the child var <- the gateway env"
  log "var the gateway resolves it from). Secrets stay in the gateway env, never"
  log "in the payload. Blank line to finish."
  while true; do
    local kv
    kv="$(ask '  env_ref (CHILD=GATEWAY)' '')"
    [[ -z "$kv" ]] && break
    [[ "$kv" == *=* ]] || { warn "  expected CHILD_ENV=GATEWAY_ENV; skipped"; continue; }
    PAYLOAD_ENV_REFS+=("$kv")
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
  printf '   1) opensearch-mcp        (provides: search, ingest, enrichment; needs Docker)\n'
  printf '   2) opencti-mcp           (provides: reference, threat-intel; needs Docker + RAM)\n'
  printf '   3) forensic-rag-mcp      (provides: reference; pgvector knowledge corpus)\n'
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
      1) setup_opensearch ;;
      2) setup_opencti ;;
      3) setup_rag ;;
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
