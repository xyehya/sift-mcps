#!/usr/bin/env bash
set -Eeuo pipefail

AUTO_YES=0
START_SERVICE=1
RUN_DOCKER=1
DOWNLOAD_DB=1
INSTALL_RAG=1
ENABLE_OPENCTI=0

usage() {
  cat <<'USAGE'
Usage: ./install.sh [-y] [--no-start] [--skip-docker] [--skip-db] [--skip-rag] [--enable-opencti]

Install sift-mcps on a SIFT Workstation VM.

Options:
  -y, --yes          Run non-interactively.
  --no-start         Write config and service files, but do not start systemd service.
  --skip-docker      Skip Docker/OpenSearch startup.
  --skip-db          Skip downloading triage baseline databases.
  --skip-rag         Skip forensic-rag-mcp and its ML dependencies.
  --enable-opencti   Deploy local OpenCTI stack (requires >=14 GB RAM, resizes VM first).
  -h, --help         Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) AUTO_YES=1 ;;
    --no-start) START_SERVICE=0 ;;
    --skip-docker) RUN_DOCKER=0 ;;
    --skip-db) DOWNLOAD_DB=0 ;;
    --skip-rag) INSTALL_RAG=0 ;;
    --enable-opencti) ENABLE_OPENCTI=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTIR_HOME="${AGENTIR_HOME:-$HOME/.agentir}"
AGENTIR_TLS_DIR="${AGENTIR_TLS_DIR:-$AGENTIR_HOME/tls}"
AGENTIR_BACKUP_DIR="${AGENTIR_BACKUP_DIR:-$AGENTIR_HOME/backups}"
AGENTIR_CONFIG="${AGENTIR_CONFIG:-$AGENTIR_HOME/gateway.yaml}"
AGENTIR_CASE_ROOT="${AGENTIR_CASE_ROOT:-/cases}"
AGENTIR_STATE_DIR="${AGENTIR_STATE_DIR:-/var/lib/agentir}"
AGENTIR_PASSWORDS_DIR="${AGENTIR_PASSWORDS_DIR:-$AGENTIR_STATE_DIR/passwords}"
AGENTIR_VERIFICATION_DIR="${AGENTIR_VERIFICATION_DIR:-$AGENTIR_STATE_DIR/verification}"
AGENTIR_ENRICHMENT_DIR="${AGENTIR_ENRICHMENT_DIR:-$AGENTIR_STATE_DIR/enrichment}"
AGENTIR_WINDOWS_TRIAGE_DB_DIR="${AGENTIR_WINDOWS_TRIAGE_DB_DIR:-$AGENTIR_STATE_DIR/windows-triage}"
AGENTIR_TOKENS_DIR="${AGENTIR_TOKENS_DIR:-$AGENTIR_STATE_DIR/tokens}"
AGENTIR_SNAPSHOTS_DIR="${AGENTIR_SNAPSHOTS_DIR:-$AGENTIR_STATE_DIR/snapshots}"
AGENTIR_EXAMINER="${AGENTIR_EXAMINER:-examiner}"
MATERIALS_FILE="${MATERIALS_FILE:-$AGENTIR_TOKENS_DIR/installer-handoff.txt}"
SYSTEMD_USER_DIR="${SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
GATEWAY_SERVICE_FILE="$SYSTEMD_USER_DIR/sift-gateway.service"

log() { printf '[sift-mcps] %s\n' "$*"; }
warn() { printf '[sift-mcps] WARNING: %s\n' "$*" >&2; }
die() { printf '[sift-mcps] ERROR: %s\n' "$*" >&2; exit 1; }

confirm() {
  [[ "$AUTO_YES" -eq 1 ]] && return 0
  printf '%s [y/N] ' "$1"
  read -r reply
  [[ "$reply" == "y" || "$reply" == "Y" || "$reply" == "yes" || "$reply" == "YES" ]]
}

sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

user_name() {
  if [[ "$(id -u)" -eq 0 ]]; then
    echo "${SUDO_USER:-root}"
  else
    id -un
  fi
}

group_name() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    id -gn "$SUDO_USER"
  else
    id -gn
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

check_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
      warn "Target OS is Ubuntu 22.04/24.04; detected ${PRETTY_NAME:-unknown}."
      confirm "Continue anyway?" || die "Installer cancelled."
    elif [[ "${VERSION_ID:-}" != "22.04" && "${VERSION_ID:-}" != "24.04" ]]; then
      warn "Target Ubuntu versions are 22.04/24.04; detected ${VERSION_ID:-unknown}."
      confirm "Continue anyway?" || die "Installer cancelled."
    fi
  fi
}

check_python() {
  require_cmd python3
  python3 - <<'PY' || die "Python 3.10 or newer is required."
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
}

resolve_uv() {
  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return
  fi
  if [[ -x "$HOME/.local/bin/uv" ]]; then
    echo "$HOME/.local/bin/uv"
    return
  fi
  if [[ -x "$HOME/.local/share/uv/bin/uv" ]]; then
    echo "$HOME/.local/share/uv/bin/uv"
    return
  fi
  echo ""
}

install_uv_if_needed() {
  UV_BIN="$(resolve_uv)"
  if [[ -n "$UV_BIN" ]]; then
    export UV_BIN
    log "uv found: $UV_BIN"
    return
  fi
  require_cmd curl
  log "Installing uv with the official installer."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  UV_BIN="$(resolve_uv)"
  [[ -n "$UV_BIN" ]] || die "uv install completed but uv was not found."
  export UV_BIN
}

sync_workspace() {
  if [[ "$INSTALL_RAG" -eq 1 ]]; then
    log "Syncing full uv workspace."
    "$UV_BIN" sync --extra full --project "$REPO_DIR"
  else
    log "Syncing standard uv workspace without forensic-rag-mcp."
    "$UV_BIN" sync --extra standard --project "$REPO_DIR"
  fi
}

install_state_dirs() {
  local owner group
  owner="$(user_name)"
  group="$(group_name)"
  log "Creating agentir state directories."
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$AGENTIR_STATE_DIR"
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$AGENTIR_PASSWORDS_DIR"
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$AGENTIR_VERIFICATION_DIR"
  sudo_if_needed install -d -m 700 -o "$owner" -g "$group" "$AGENTIR_TOKENS_DIR"
  sudo_if_needed install -d -m 755 -o 1000 -g 1000 "$AGENTIR_SNAPSHOTS_DIR"
  sudo_if_needed install -d -m 755 -o "$owner" -g "$group" "$AGENTIR_ENRICHMENT_DIR"
  sudo_if_needed install -d -m 755 -o "$owner" -g "$group" "$AGENTIR_WINDOWS_TRIAGE_DB_DIR"
  sudo_if_needed install -d -m 755 -o "$owner" -g "$group" "$AGENTIR_CASE_ROOT"
  install -d -m 700 "$AGENTIR_HOME" "$AGENTIR_TLS_DIR" "$AGENTIR_BACKUP_DIR"
}

download_triage_databases() {
  [[ "$DOWNLOAD_DB" -eq 1 ]] || { warn "Skipping triage database download."; return; }
  log "Downloading triage baseline databases."
  if [[ -f "$AGENTIR_WINDOWS_TRIAGE_DB_DIR/known_good.db" && -f "$AGENTIR_WINDOWS_TRIAGE_DB_DIR/context.db" ]]; then
    log "Triage databases already exist; skipping download."
    return
  fi
  # Run the python downloader. If it fails, print a warning but do not fail the installer.
  if ! "$UV_BIN" run --project "$REPO_DIR" python -m windows_triage_mcp.scripts.download_databases --dest "$AGENTIR_WINDOWS_TRIAGE_DB_DIR"; then
    warn "Triage baseline databases could not be downloaded. Backend will run in degraded mode."
  fi
}

prepare_enrichment_assets() {
  log "Preparing enrichment asset pointers."
  if [[ -d "$REPO_DIR/packages/forensic-knowledge/data" ]]; then
    ln -sfn "$REPO_DIR/packages/forensic-knowledge/data" "$AGENTIR_ENRICHMENT_DIR/forensic-knowledge"
  else
    warn "forensic-knowledge data directory not found."
  fi
  install -d -m 755 "$AGENTIR_ENRICHMENT_DIR/forensic-rag"
}

generate_tls() {
  require_cmd openssl
  install -d -m 700 "$AGENTIR_TLS_DIR"
  if [[ -f "$AGENTIR_TLS_DIR/ca-cert.pem" && -f "$AGENTIR_TLS_DIR/gateway-cert.pem" && -f "$AGENTIR_TLS_DIR/gateway-key.pem" ]]; then
    log "TLS material already exists; preserving it."
    return
  fi

  log "Generating self-signed CA and gateway certificate."
  local first_ip san_file
  first_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$first_ip" ]] || first_ip="127.0.0.1"
  san_file="$(mktemp)"
  printf 'subjectAltName=IP:%s,IP:127.0.0.1,DNS:%s\n' "$first_ip" "$(hostname)" > "$san_file"

  openssl genrsa -out "$AGENTIR_TLS_DIR/ca-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -x509 -days 3650 -key "$AGENTIR_TLS_DIR/ca-key.pem" \
    -out "$AGENTIR_TLS_DIR/ca-cert.pem" -subj "/CN=sift-mcps-CA" >/dev/null 2>&1
  openssl genrsa -out "$AGENTIR_TLS_DIR/gateway-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -key "$AGENTIR_TLS_DIR/gateway-key.pem" \
    -out "$AGENTIR_TLS_DIR/gateway-csr.pem" -subj "/CN=$(hostname)" >/dev/null 2>&1
  openssl x509 -req -days 730 -in "$AGENTIR_TLS_DIR/gateway-csr.pem" \
    -CA "$AGENTIR_TLS_DIR/ca-cert.pem" -CAkey "$AGENTIR_TLS_DIR/ca-key.pem" \
    -CAcreateserial -out "$AGENTIR_TLS_DIR/gateway-cert.pem" \
    -extfile "$san_file" >/dev/null 2>&1
  rm -f "$san_file"
  chmod 600 "$AGENTIR_TLS_DIR/"*-key.pem
  chmod 644 "$AGENTIR_TLS_DIR/"*-cert.pem
}

random_hex() {
  local bytes="$1"
  openssl rand -hex "$bytes"
}

write_default_examiner() {
  local password_file temp_password
  password_file="$AGENTIR_PASSWORDS_DIR/$AGENTIR_EXAMINER.json"
  if [[ -f "$password_file" ]]; then
    log "Default examiner password already exists; preserving it."
    TEMP_PASSWORD_CREATED=0
    TEMP_PASSWORD=""
    return
  fi
  temp_password="Agentir-$(random_hex 12)"
  TEMP_PASSWORD="$temp_password"
  TEMP_PASSWORD_CREATED=1
  export AGENTIR_PASSWORDS_DIR AGENTIR_EXAMINER TEMP_PASSWORD
  python3 - <<'PY'
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

passwords_dir = Path(os.environ["AGENTIR_PASSWORDS_DIR"])
examiner = os.environ["AGENTIR_EXAMINER"]
password = os.environ["TEMP_PASSWORD"]
salt = secrets.token_bytes(32)
entry = {
    "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex(),
    "salt": salt.hex(),
    "must_reset_password": True,
    "created_by": "sift-mcps install.sh",
}
passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
fd, tmp = tempfile.mkstemp(dir=str(passwords_dir), suffix=".tmp")
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(entry, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, passwords_dir / f"{examiner}.json")
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
}

render_file() {
  local src="$1" dst="$2" mode="$3"
  export AGENTIR_HOME AGENTIR_TLS_DIR AGENTIR_CONFIG AGENTIR_CASE_ROOT
  export AGENTIR_WINDOWS_TRIAGE_DB_DIR
  export AGENTIR_GATEWAY_TOKEN AGENTIR_SERVICE_TOKEN AGENTIR_PORTAL_SESSION_SECRET
  export AGENTIR_EXAMINER SIFT_MCPS_ROOT UV_BIN OPENCTI_URL OPENCTI_TOKEN
  export AGENTIR_RAG_ENABLED AGENTIR_OPENCTI_ENABLED
  export AGENTIR_WINDOWS_TRIAGE_ENABLED
  SIFT_MCPS_ROOT="$REPO_DIR"
  OPENCTI_URL="${OPENCTI_URL:-http://127.0.0.1:8080}"
  OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"
  if [[ "$INSTALL_RAG" -eq 1 ]]; then
    AGENTIR_RAG_ENABLED="true"
  else
    AGENTIR_RAG_ENABLED="false"
  fi
  if [[ "$DOWNLOAD_DB" -eq 1 ]]; then
    AGENTIR_WINDOWS_TRIAGE_ENABLED="true"
  else
    AGENTIR_WINDOWS_TRIAGE_ENABLED="false"
  fi
  if [[ "$ENABLE_OPENCTI" -eq 1 ]]; then
    AGENTIR_OPENCTI_ENABLED="true"
  else
    AGENTIR_OPENCTI_ENABLED="false"
  fi
  python3 - "$src" "$dst" "$mode" <<'PY'
import os
import stat
import sys
import tempfile
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
mode = int(sys.argv[3], 8)
text = src.read_text()
for key, value in os.environ.items():
    text = text.replace("${" + key + "}", value)
dst.parent.mkdir(parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=str(dst.parent), suffix=".tmp")
try:
    os.fchmod(fd, mode)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, dst)
    os.chmod(dst, mode)
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
}

write_gateway_config() {
  if [[ -f "$AGENTIR_CONFIG" ]]; then
    log "Gateway config exists; preserving $AGENTIR_CONFIG."
    CONFIG_CREATED=0
    AGENTIR_GATEWAY_TOKEN=""
    AGENTIR_SERVICE_TOKEN=""
    AGENTIR_PORTAL_SESSION_SECRET=""
    migrate_gateway_config
    return
  fi
  AGENTIR_GATEWAY_TOKEN="agentir_gw_$(random_hex 24)"
  AGENTIR_SERVICE_TOKEN="agentir_svc_$(random_hex 24)"
  AGENTIR_PORTAL_SESSION_SECRET="$(random_hex 32)"
  AGENTIR_TOKEN_CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  CONFIG_CREATED=1
  export AGENTIR_GATEWAY_TOKEN AGENTIR_SERVICE_TOKEN AGENTIR_PORTAL_SESSION_SECRET AGENTIR_TOKEN_CREATED_AT
  render_file "$REPO_DIR/configs/gateway.yaml.template" "$AGENTIR_CONFIG" 0600
}

migrate_gateway_config() {
  log "Checking gateway config compatibility."
  export AGENTIR_CONFIG INSTALL_RAG DOWNLOAD_DB
  "$UV_BIN" run --project "$REPO_DIR" python - <<'PY'
import os
import tempfile
from pathlib import Path

import yaml

path = Path(os.environ["AGENTIR_CONFIG"])
install_rag = os.environ.get("INSTALL_RAG") == "1"
cfg = yaml.safe_load(path.read_text()) or {}
changed = False

gateway = cfg.setdefault("gateway", {})
tls = gateway.get("tls")
if isinstance(tls, dict):
    if "certfile" not in tls and "cert" in tls:
        tls["certfile"] = tls.pop("cert")
        changed = True
    if "keyfile" not in tls and "key" in tls:
        tls["keyfile"] = tls.pop("key")
        changed = True

if not install_rag:
    enrichment = cfg.setdefault("enrichment", {})
    if enrichment.get("forensic_rag") is not False:
        enrichment["forensic_rag"] = False
        changed = True
    rag_backend = cfg.setdefault("backends", {}).get("forensic-rag-mcp")
    if isinstance(rag_backend, dict) and rag_backend.get("enabled") is not False:
        rag_backend["enabled"] = False
        changed = True

if os.environ.get("DOWNLOAD_DB") != "1":
    wt_backend = cfg.setdefault("backends", {}).get("windows-triage-mcp")
    if isinstance(wt_backend, dict) and wt_backend.get("enabled") is not False:
        wt_backend["enabled"] = False
        changed = True

if changed:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            yaml.safe_dump(cfg, handle, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
PY
}

write_opensearch_config() {
  local os_config="$AGENTIR_HOME/opensearch.yaml"
  if [[ -f "$os_config" ]]; then
    log "OpenSearch client config exists; preserving $os_config."
    return
  fi
  umask 077
  cat > "$os_config" <<'YAML'
host: http://127.0.0.1:9200
user: admin
password: admin
verify_certs: false
YAML
  chmod 600 "$os_config"
}

start_opensearch() {
  [[ "$RUN_DOCKER" -eq 1 ]] || { warn "Skipping OpenSearch Docker startup."; return; }
  require_cmd docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."
  if ! docker ps >/dev/null 2>&1; then
    warn "Docker daemon is not reachable for this user."
    if command -v systemctl >/dev/null 2>&1; then
      sudo_if_needed systemctl start docker || true
    fi
  fi
  docker ps >/dev/null 2>&1 || die "Docker is installed but not usable by this shell."

  log "Starting OpenSearch with docker compose."
  docker compose -f "$REPO_DIR/docker-compose.yml" up -d opensearch
  log "Waiting for OpenSearch health."
  local status
  status="unknown"
  for _ in $(seq 1 90); do
    status="$(curl -fsS http://127.0.0.1:9200/_cluster/health 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","unknown"))' 2>/dev/null || true)"
    if [[ "$status" == "green" || "$status" == "yellow" ]]; then
      log "OpenSearch healthy: $status"
      return
    fi
    sleep 2
  done
  die "OpenSearch did not become healthy within 180 seconds."
}

opensearch_api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "http://127.0.0.1:9200$path" \
      -H "Content-Type: application/json" \
      -d "$body" >/dev/null
  else
    curl -fsS -X "$method" "http://127.0.0.1:9200$path" >/dev/null
  fi
}

configure_opensearch_cluster() {
  [[ "$RUN_DOCKER" -eq 1 ]] || return 0
  log "Applying OpenSearch cluster settings."
  opensearch_api PUT "/_cluster/settings" \
    '{"persistent":{"cluster.max_shards_per_node":3000}}' \
    || warn "Could not raise cluster.max_shards_per_node."

  log "Running OpenSearch smoke test."
  opensearch_api POST "/case-test-evtx-smoketest/_doc/test-1?refresh=true" \
    '{"event.code":4624,"@timestamp":"2024-01-01T00:00:00Z","host.name":"test"}' \
    || warn "OpenSearch smoke index failed."
  local found
  found="$(curl -fsS "http://127.0.0.1:9200/case-test-evtx-smoketest/_search?q=event.code:4624&size=1" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["hits"]["total"]["value"])' 2>/dev/null || echo 0)"
  if [[ "$found" == "1" ]]; then
    log "OpenSearch smoke test passed."
  else
    warn "OpenSearch smoke test expected 1 hit, got $found."
  fi
  curl -fsS -X DELETE "http://127.0.0.1:9200/case-test-evtx-smoketest" >/dev/null 2>&1 || true
}

configure_geoip_pipeline() {
  [[ "$RUN_DOCKER" -eq 1 ]] || return 0
  log "Configuring OpenSearch GeoIP enrichment."
  curl -fsS -X PUT "http://127.0.0.1:9200/_plugins/geospatial/ip2geo/datasource/maxmind-city" \
    -H "Content-Type: application/json" \
    -d '{"endpoint":"https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json","update_interval_in_days":3}' \
    >/dev/null 2>&1 || warn "GeoIP datasource skipped; internet or plugin may be unavailable."

  opensearch_api PUT "/_ingest/pipeline/agentir-geoip" '{
    "description": "GeoIP enrichment for source.ip",
    "processors": [{
      "ip2geo": {
        "field": "source.ip",
        "datasource": "maxmind-city",
        "target_field": "source.geo",
        "ignore_missing": true,
        "on_failure": [{
          "set": {
            "field": "source.geo.error",
            "value": "GeoIP lookup failed: {{_ingest.on_failure_message}}"
          }
        }]
      }
    }]
  }' || warn "GeoIP ingest pipeline could not be created."

  local pattern
  for pattern in "case-*-evtx-*" "case-*-iis-*" "case-*-httperr-*" "case-*-firewall-*" "case-*-ssh-*" "case-*-accesslog-*"; do
    opensearch_api PUT "/$pattern/_settings" '{"index.default_pipeline":"agentir-geoip"}' 2>/dev/null || true
  done
}

install_opensearch_templates() {
  [[ "$RUN_DOCKER" -eq 1 ]] || return 0
  log "Installing OpenSearch templates and pipelines if cluster is reachable."
  "$UV_BIN" run --project "$REPO_DIR" python - <<'PY' || warn "OpenSearch template bootstrap failed; opensearch-mcp will retry at backend startup."
from opensearch_mcp.client import get_client
from opensearch_mcp.mappings import ensure_winlog_pipeline

client = get_client()
result = ensure_winlog_pipeline(client)
if result.get("status") not in {"ok", "warning"}:
    raise SystemExit(result)
print(result.get("status", "ok"))
PY
}

install_opencti() {
  [[ "$ENABLE_OPENCTI" -eq 1 ]] || return 0
  [[ "$RUN_DOCKER" -eq 1 ]] || { warn "OpenCTI requires Docker; skipping (--skip-docker set)."; return 0; }

  # RAM gate: OpenCTI platform alone wants 4+ GB; with Redis/RabbitMQ/MinIO need headroom
  local total_ram_mb
  total_ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if [[ "$total_ram_mb" -lt 14336 ]]; then
    die "OpenCTI requires >=14 GB RAM. VM has ${total_ram_mb} MB. Resize the VM first (host has headroom)."
  fi

  log "Deploying local OpenCTI stack (RAM: ${total_ram_mb} MB)."

  # Generate admin token (UUID) if not already set
  if [[ -z "${OPENCTI_TOKEN:-}" ]]; then
    OPENCTI_TOKEN=$(python3 -c "import uuid; print(uuid.uuid4())")
    printf '%s\n' "$OPENCTI_TOKEN" > "$AGENTIR_HOME/opencti-token"
    chmod 600 "$AGENTIR_HOME/opencti-token"
    log "OpenCTI admin token saved to $AGENTIR_HOME/opencti-token"
  fi
  export OPENCTI_TOKEN
  export OPENCTI_URL="http://127.0.0.1:8080"

  # Bring up OpenCTI stack (separate compose file, shares agentir-net with opensearch)
  OPENCTI_ADMIN_TOKEN="$OPENCTI_TOKEN" \
    docker compose -f "$REPO_DIR/docker-compose.opencti.yml" up -d

  # Wait for OpenCTI platform health (first-run schema init takes 2-5 min)
  log "Waiting for OpenCTI platform to be ready (up to 5 min on first run)..."
  local deadline=$(( $(date +%s) + 300 ))
  until curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; do
    [[ $(date +%s) -lt $deadline ]] || { warn "OpenCTI did not become healthy within 5 min; check: docker logs agentir-opencti"; break; }
    sleep 10
  done
  log "OpenCTI ready at http://127.0.0.1:8080"
}

install_systemd_service() {
  install -d -m 700 "$SYSTEMD_USER_DIR"
  if [[ ! -f "$GATEWAY_SERVICE_FILE" ]]; then
    AGENTIR_GATEWAY_TOKEN=""
    AGENTIR_SERVICE_TOKEN=""
    AGENTIR_PORTAL_SESSION_SECRET=""
    export SIFT_MCPS_ROOT="$REPO_DIR" UV_BIN AGENTIR_CONFIG AGENTIR_EXAMINER
    render_file "$REPO_DIR/configs/systemd/sift-gateway.service" "$GATEWAY_SERVICE_FILE" 0644
  else
    log "Systemd user service exists; preserving $GATEWAY_SERVICE_FILE."
  fi

  [[ "$START_SERVICE" -eq 1 ]] || { warn "Skipping gateway service start."; return; }
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found; service file written but not started."
    return
  fi
  systemctl --user daemon-reload
  systemctl --user enable sift-gateway.service
  systemctl --user restart sift-gateway.service
}

poll_gateway() {
  [[ "$START_SERVICE" -eq 1 ]] || return 0
  log "Waiting for gateway health."
  for _ in $(seq 1 60); do
    if curl -kfsS https://127.0.0.1:4508/health >/dev/null 2>&1; then
      log "Gateway health endpoint is reachable."
      return
    fi
    sleep 2
  done
  warn "Gateway health endpoint did not become reachable. Check: journalctl --user -u sift-gateway -e"
}

write_handoff() {
  local existing_temp_password existing_gateway_token existing_service_token
  existing_temp_password=""
  existing_gateway_token=""
  existing_service_token=""
  if [[ -f "$MATERIALS_FILE" ]]; then
    existing_temp_password="$(awk -F= '$1=="temporary_examiner_password"{sub(/^[^=]*=/,""); print; exit}' "$MATERIALS_FILE" || true)"
    existing_gateway_token="$(awk -F= '$1=="examiner_fallback_token"{sub(/^[^=]*=/,""); print; exit}' "$MATERIALS_FILE" || true)"
    existing_service_token="$(awk -F= '$1=="hermes_service_token"{sub(/^[^=]*=/,""); print; exit}' "$MATERIALS_FILE" || true)"
  fi
  umask 077
  {
    printf 'sift-mcps installer handoff\n'
    printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'portal_url=https://%s:4508/portal/\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'gateway_mcp_url=https://%s:4508/mcp\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf 'ca_cert=%s/ca-cert.pem\n' "$AGENTIR_TLS_DIR"
    printf 'gateway_config=%s\n' "$AGENTIR_CONFIG"
    printf 'examiner=%s\n' "$AGENTIR_EXAMINER"
    if [[ "${TEMP_PASSWORD_CREATED:-0}" -eq 1 ]]; then
      printf 'temporary_examiner_password=%s\n' "$TEMP_PASSWORD"
    elif [[ -n "$existing_temp_password" && "$existing_temp_password" != "existing-password-preserved" ]]; then
      printf 'temporary_examiner_password=%s\n' "$existing_temp_password"
    else
      printf 'temporary_examiner_password=existing-password-preserved\n'
    fi
    if [[ "${CONFIG_CREATED:-0}" -eq 1 ]]; then
      printf 'examiner_fallback_token=%s\n' "$AGENTIR_GATEWAY_TOKEN"
      printf 'hermes_service_token=%s\n' "$AGENTIR_SERVICE_TOKEN"
    elif [[ -n "$existing_gateway_token" || -n "$existing_service_token" ]]; then
      [[ -n "$existing_gateway_token" ]] && printf 'examiner_fallback_token=%s\n' "$existing_gateway_token"
      [[ -n "$existing_service_token" ]] && printf 'hermes_service_token=%s\n' "$existing_service_token"
    else
      printf 'tokens=existing-gateway-config-preserved\n'
    fi
  } > "$MATERIALS_FILE"
  chmod 600 "$MATERIALS_FILE"
}

configure_immutable_capability() {
  # Phase 17a: grant CAP_LINUX_IMMUTABLE to the venv Python so the gateway
  # process can set/clear chattr +i on evidence files without running as root.
  local venv_py
  venv_py="$(readlink -f "${REPO_DIR}/.venv/bin/python3.11" 2>/dev/null || true)"
  if [[ -z "$venv_py" || ! -f "$venv_py" ]]; then
    warn "configure_immutable_capability: .venv/bin/python3.11 not found — skipping setcap"
    return 0
  fi
  if ! command -v setcap &>/dev/null; then
    warn "configure_immutable_capability: setcap not found (install libcap2-bin) — skipping"
    return 0
  fi
  sudo_if_needed setcap cap_linux_immutable+ep "$venv_py"
  log "setcap cap_linux_immutable+ep applied to $venv_py"
}

configure_auditd() {
  # Phase 17b: install kernel audit rules for evidence write/attribute events.
  if ! command -v augenrules &>/dev/null && ! command -v auditctl &>/dev/null; then
    warn "configure_auditd: auditd not found — skipping audit rule installation"
    return 0
  fi
  local rules_src="${REPO_DIR}/configs/audit/99-agentir-evidence.rules"
  local rules_dst="/etc/audit/rules.d/99-agentir-evidence.rules"
  # Substitute CASES_ROOT placeholder
  local tmp
  tmp="$(mktemp)"
  sed "s|CASES_ROOT|${AGENTIR_CASE_ROOT}|g" "$rules_src" > "$tmp"
  sudo_if_needed cp "$tmp" "$rules_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 640 "$rules_dst"
  if command -v augenrules &>/dev/null; then
    sudo_if_needed augenrules --load
  else
    sudo_if_needed auditctl -R "$rules_dst"
  fi
  log "auditd rules installed → $rules_dst (CASES_ROOT=${AGENTIR_CASE_ROOT})"
}

configure_apparmor() {
  # Phase 17c: install AppArmor profile for sift-gateway in complain mode.
  if ! command -v aa-status &>/dev/null; then
    warn "configure_apparmor: AppArmor tools not found — skipping profile installation"
    return 0
  fi
  local venv_py
  venv_py="$(readlink -f "${REPO_DIR}/.venv/bin/python3.11" 2>/dev/null || true)"
  if [[ -z "$venv_py" || ! -f "$venv_py" ]]; then
    warn "configure_apparmor: .venv/bin/python3.11 not found — skipping AppArmor profile"
    return 0
  fi
  local profile_src="${REPO_DIR}/configs/apparmor/sift-gateway.template"
  local profile_dst="/etc/apparmor.d/sift-gateway"
  local tmp
  tmp="$(mktemp)"
  sed "s|@@PYTHON_BIN@@|${venv_py}|g" "$profile_src" > "$tmp"
  sudo_if_needed cp "$tmp" "$profile_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 644 "$profile_dst"
  # Load in complain mode — use aa-enforce after validating with aa-logprof
  # -C = complain mode; -r = replace existing
  sudo_if_needed apparmor_parser -C -r "$profile_dst" || true
  log "AppArmor profile installed in complain mode → $profile_dst (binary: $venv_py)"
  log "  Run 'sudo aa-logprof' after exercising the gateway, then 'sudo aa-enforce $profile_dst'"
}

print_summary() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$ip" ]] || ip="SIFT_VM"
  log "Install complete."
  printf '\n'
  printf 'Portal:       https://%s:4508/portal/\n' "$ip"
  printf 'MCP endpoint: https://%s:4508/mcp\n' "$ip"
  printf 'CA cert:      %s/ca-cert.pem\n' "$AGENTIR_TLS_DIR"
  printf 'Config:       %s\n' "$AGENTIR_CONFIG"
  printf 'Secrets:      %s\n' "$MATERIALS_FILE"
  printf '\n'
  printf 'Next steps:\n'
  printf '  1. On the analyst machine, trust the CA cert or set REQUESTS_CA_BUNDLE.\n'
  printf '  2. Configure Hermes with configs/hermes-forensics-profile.yaml and the service token.\n'
  printf '  3. Sign into the portal as %s and reset the temporary password.\n' "$AGENTIR_EXAMINER"
}

main() {
  check_os
  check_python
  require_cmd awk
  require_cmd curl
  install_uv_if_needed
  sync_workspace
  install_state_dirs
  download_triage_databases
  prepare_enrichment_assets
  generate_tls
  write_default_examiner
  write_gateway_config
  write_opensearch_config
  start_opensearch
  configure_opensearch_cluster
  configure_geoip_pipeline
  install_opensearch_templates
  install_opencti
  install_systemd_service
  configure_immutable_capability
  configure_auditd
  configure_apparmor
  poll_gateway
  write_handoff
  print_summary
}

main "$@"
