# shellcheck shell=bash
# =============================================================================
# lib/opensearch.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_OPENSEARCH_SOURCED:-}" ]] && return 0
_SIFT_LIB_OPENSEARCH_SOURCED=1

# Phase 8 — OpenSearch (Docker)
# =============================================================================

_opensearch_admin_env_file() { printf '%s/opensearch-admin.env' "$SIFT_HOME"; }
_opensearch_ca_file() { printf '%s/opensearch-root-ca.pem' "$SIFT_HOME"; }

ensure_opensearch_admin_credentials() {
  local credential_file tmp
  credential_file="$(_opensearch_admin_env_file)"
  if svc_test_f "$credential_file"; then
    return 0
  fi
  require_cmd openssl
  tmp="$(mktemp)"
  umask 077
  printf 'SIFT_OPENSEARCH_ADMIN_PASSWORD=%s\n' "$(openssl rand -base64 36 | tr -d '\n')" > "$tmp"
  svc_install_file "$tmp" "$credential_file" 600
  rm -f "$tmp"
  log "Generated a service-owned OpenSearch admin credential."
}

_load_opensearch_admin_credentials() {
  # This file is created by the installer itself with mode 0600 under the
  # service account.  Never log or accept its value from an untrusted CLI arg.
  local credential_file
  credential_file="$(_opensearch_admin_env_file)"
  # shellcheck disable=SC1090
  source <(svc_read "$credential_file") || return 1
  [[ -n "${SIFT_OPENSEARCH_ADMIN_PASSWORD:-}" ]]
}

_opensearch_curl() {
  local method="$1" path="$2" body="${3:-}"
  _load_opensearch_admin_credentials || return 1
  local -a args=(--fail --silent --show-error --max-time 15 --cacert "$(_opensearch_ca_file)"
    --user "admin:${SIFT_OPENSEARCH_ADMIN_PASSWORD}" -X "$method"
    "https://localhost:9200${path}")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data "$body")
  # The verified CA lives below the service-owned 0700 state directory.  The
  # installer operator deliberately cannot traverse that directory, so use the
  # same narrowly-scoped privilege helper already used for service state reads.
  sudo_if_needed curl "${args[@]}"
}

_opensearch_api() {
  local method="$1" path="$2" body="${3:-}"
  _opensearch_curl "$method" "$path" "$body" >/dev/null
}


start_opensearch() {
  if ! command -v docker >/dev/null 2>&1; then
    warn "Docker not found — skipping OpenSearch.  Install Docker and re-run."
    warn "  The mandatory core install will fail closed after this preflight."
    OPENSEARCH_UP=0
    return 0
  fi
  docker compose version >/dev/null 2>&1 || warn "Docker Compose v2 not available."
  if ! docker ps >/dev/null 2>&1; then
    warn "Docker daemon not reachable — attempting start."
    sudo_if_needed systemctl start docker 2>/dev/null || true
    sleep 2
  fi
  if ! docker ps >/dev/null 2>&1; then
    warn "Docker not usable — skipping OpenSearch.  The mandatory core install will fail closed after this preflight."
    OPENSEARCH_UP=0
    return 0
  fi

  log "Starting OpenSearch."
  _load_opensearch_admin_credentials || die "OpenSearch admin credential is unavailable."
  export SIFT_OPENSEARCH_ADMIN_PASSWORD
  docker compose -f "$REPO_DIR/docker-compose.yml" up -d opensearch

  log "Waiting for OpenSearch health (up to 600 s)."
  local api_status="unknown" docker_health="unknown" attempt
  for attempt in $(seq 1 300); do
    docker_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' sift-opensearch 2>/dev/null || true)"
    # Before the CA is copied out of the immutable image, this is a narrow
    # localhost bootstrap probe only.  The post-start CA-bound probe below is
    # the acceptance condition used by clients and follow-on configuration.
    api_status="$(curl -kfsS --user "admin:${SIFT_OPENSEARCH_ADMIN_PASSWORD}" --max-time 5 https://127.0.0.1:9200/_cluster/health 2>/dev/null \
      | "$SYSTEM_PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status","unknown"))' 2>/dev/null || true)"
    api_status="${api_status:-unknown}"
    docker_health="${docker_health:-unknown}"

    if [[ "$api_status" == "green" || "$api_status" == "yellow" || "$docker_health" == "healthy" ]]; then
      log "OpenSearch healthy: api=$api_status docker=$docker_health"
      OPENSEARCH_UP=1
      break
    fi
    if [[ "$attempt" -eq 1 || $(( attempt % 15 )) -eq 0 ]]; then
      log "OpenSearch wait: api=$api_status docker=$docker_health"
    fi
    sleep 2
  done
  if [[ "$OPENSEARCH_UP" -eq 0 ]]; then
    warn "OpenSearch not healthy after 600 s (last api=${api_status:-unknown}, docker=${docker_health:-unknown}) — the mandatory core install will fail closed."
    warn "  Check: docker logs opensearch  |  docker compose -f $REPO_DIR/docker-compose.yml ps"
    return
  fi
  local ca_file tmp_ca
  ca_file="$(_opensearch_ca_file)"
  if ! svc_test_f "$ca_file"; then
    tmp_ca="$(mktemp)"
    docker cp sift-opensearch:/usr/share/opensearch/config/root-ca.pem "$tmp_ca" \
      || die "Could not extract the OpenSearch CA from the pinned image."
    svc_install_file "$tmp_ca" "$ca_file" 644
    rm -f "$tmp_ca"
  fi
  # The CA is a runtime artifact from the immutable image, not a committed
  # trust anchor.  Validate its basic lifetime/signature properties before it
  # becomes the client trust root, then prove a TLS-authenticated API request.
  sudo_if_needed openssl x509 -in "$ca_file" -noout -checkend 0 >/dev/null \
    || die "The extracted OpenSearch CA is expired or invalid."
  sudo_if_needed openssl verify -CAfile "$ca_file" "$ca_file" >/dev/null \
    || die "The extracted OpenSearch CA failed self-verification."
  _opensearch_curl GET '/_cluster/health' >/dev/null \
    || die "OpenSearch TLS certificate or authentication verification failed."
}

configure_opensearch_cluster() {
  command -v docker >/dev/null 2>&1 || return 0
  _opensearch_curl GET "/_cluster/health" >/dev/null 2>&1 || return 0

  log "Applying OpenSearch cluster settings."
  _opensearch_api PUT "/_cluster/settings" '{"persistent":{"cluster.max_shards_per_node":3000}}' \
    || warn "Could not raise cluster.max_shards_per_node."

  log "OpenSearch smoke test."
  _opensearch_api POST "/case-test-evtx-smoketest/_doc/test-1?refresh=true" \
    '{"event.code":4624,"@timestamp":"2024-01-01T00:00:00Z","host.name":"test"}' \
    || warn "OpenSearch smoke index failed."
  local found
  found="$(_opensearch_curl GET "/case-test-evtx-smoketest/_search?q=event.code:4624&size=1" 2>/dev/null \
    | "$SYSTEM_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["hits"]["total"]["value"])' 2>/dev/null || echo 0)"
  if [[ "$found" == "1" ]]; then
    log "OpenSearch smoke test passed."
  else
    warn "OpenSearch smoke test expected 1 hit, got $found."
  fi
  _opensearch_api DELETE "/case-test-evtx-smoketest" || true
}

configure_geoip_pipeline() {
  # B-MVP-004 (D6): the ip2geo datasource fetches from a live, unauthenticated
  # endpoint (geoip.maps.opensearch.org). OFF by default; opt in with
  # SIFT_GEOIP_ENABLED=1. Always skipped in offline mode.
  if [[ "${SIFT_GEOIP_ENABLED:-0}" != "1" ]]; then
    log "GeoIP enrichment disabled by default (set SIFT_GEOIP_ENABLED=1 to enable). Skipping ip2geo datasource."
    return 0
  fi
  if is_offline; then
    warn "SIFT_OFFLINE=1: skipping GeoIP datasource (it fetches from a live endpoint). Stage a local GeoLite2 datasource if needed."
    return 0
  fi
  _opensearch_curl GET "/_cluster/health" >/dev/null 2>&1 || return 0
  log "Configuring GeoIP enrichment (SIFT_GEOIP_ENABLED=1)."

  _opensearch_curl PUT "/_plugins/geospatial/ip2geo/datasource/maxmind-city" \
    '{"endpoint":"https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json","update_interval_in_days":3}' \
    >/dev/null 2>&1 || warn "GeoIP datasource skipped."

  _opensearch_api PUT "/_ingest/pipeline/sift-geoip" '{
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
  }' || warn "GeoIP ingest pipeline not created."

  local pattern
  for pattern in "case-*-evtx-*" "case-*-iis-*" "case-*-httperr-*" "case-*-firewall-*" "case-*-ssh-*" "case-*-accesslog-*"; do
    _opensearch_api PUT "/$pattern/_settings" '{"index.default_pipeline":"sift-geoip"}' 2>/dev/null || true
  done
}

# PMI1: Security-Analytics hygiene for OpenSearch 3.5.
# The 3.5 Security-Analytics percolator has a field-alias regression
# (opensearch-project/security-analytics#755) that makes Sigma detectors emit
# 0 findings, so detection is handled by Hayabusa during evtx ingest instead.
# This function keeps Sigma detectors DISABLED and removes any dead detectors /
# orphaned monitors so a fresh install does not accumulate non-functional state,
# then seeds the Sigma alias names so templates can auto-attach them.
# Talks to OpenSearch through the TLS/authenticated loopback endpoint.
# Best-effort: never fails the install. Run AFTER install_opensearch_templates
# so the alias-bearing templates exist.
configure_opensearch_detections() {
  _opensearch_curl GET "/_cluster/health" >/dev/null 2>&1 || return 0
  log "Configuring OpenSearch Security Analytics (Sigma detectors disabled — 3.5 regression; detection via Hayabusa)."
  OPENSEARCH_CONFIG="$SIFT_HOME/opensearch.yaml" "$SYSTEM_PYTHON" - <<'PY' || warn "Security Analytics hygiene skipped (plugin may be unavailable)."
import json, sys, time, urllib.request, urllib.error
from collections import Counter

import base64, os, ssl, yaml

config = yaml.safe_load(open(os.environ["OPENSEARCH_CONFIG"]))
URL = config["host"]
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Basic " + base64.b64encode(
        f"{config['user']}:{config['password']}".encode()
    ).decode(),
}
CONTEXT = ssl.create_default_context(cafile=config["ca_certs"])


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(req, timeout=30, context=CONTEXT) as resp:
        return json.loads(resp.read())


# Step 1: see whether pre-packaged Sigma rules have loaded (for logging only).
hits = []
for attempt in range(6):
    try:
        resp = api("POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=true",
                   {"query": {"match_all": {}}, "size": 5000})
        hits = resp.get("hits", {}).get("hits", [])
        if hits:
            break
        if attempt < 5:
            time.sleep(10)
    except Exception as exc:  # noqa: BLE001
        if attempt < 5:
            time.sleep(10)
        else:
            print(f"  Security Analytics rules API not ready: {exc}")
            sys.exit(0)

cat_counts = Counter(h.get("_source", {}).get("category", "") for h in hits)
print(f"  Sigma detectors: disabled (OpenSearch 3.5 field alias regression)")
print(f"  Available rules: {len(hits)} ({cat_counts.get('windows', 0)} Windows)")
print(f"  Detection via Hayabusa during evtx ingest (if installed)")

# Step 2: seed indices so templates auto-attach the Sigma aliases (3.x needs an
# alias to be backed by at least one index).
_SEEDS = {
    "case-seed-evtx-init": "sift-sigma-windows",
    "case-seed-ssh-init": "sift-sigma-linux",
    "case-seed-accesslog-init": "sift-sigma-web",
    "case-seed-json-init": "sift-sigma-network",
}
for seed_idx in _SEEDS:
    try:
        api("PUT", f"/{seed_idx}", {"settings": {"number_of_replicas": 0}})
    except Exception:  # noqa: BLE001
        pass  # already exists or template not registered yet

# Step 3: delete any existing sift- detectors (they produce 0 findings on 3.5).
try:
    existing = api("POST", "/_plugins/_security_analytics/detectors/_search",
                   {"query": {"match_all": {}}, "size": 100})
    for hit in existing.get("hits", {}).get("hits", []):
        name = hit.get("_source", {}).get("name", "")
        if name.startswith("sift-"):
            try:
                api("DELETE", f"/_plugins/_security_analytics/detectors/{hit['_id']}")
                print(f"  Removed non-functional detector: {name}")
            except Exception:  # noqa: BLE001
                pass
except Exception:  # noqa: BLE001
    pass

# Step 4: clean up orphaned monitors from pre-3.5 detector attempts.
try:
    monitors = api("GET", "/_plugins/_alerting/monitors/_search",
                   {"query": {"match_all": {}}, "size": 50})
    for hit in monitors.get("hits", {}).get("hits", []):
        name = hit.get("_source", {}).get("name", "")
        if name.startswith("sift-") or name.startswith("sigma_"):
            try:
                api("DELETE", f"/_plugins/_alerting/monitors/{hit['_id']}")
                print(f"  Removed orphaned monitor: {name}")
            except Exception:  # noqa: BLE001
                pass
except Exception:  # noqa: BLE001
    pass  # alerting plugin may not be installed

# Step 5: attach Sigma aliases to any existing matching indices (idempotent).
_ALIAS_PATTERNS = {
    "sift-sigma-windows": "case-*-evtx-*",
    "sift-sigma-linux": "case-*-ssh-*",
    "sift-sigma-web": "case-*-accesslog-*",
    "sift-sigma-network": "case-*-json-*",
}
for alias, pattern in _ALIAS_PATTERNS.items():
    try:
        api("POST", "/_aliases", {"actions": [{"add": {"index": pattern, "alias": alias}}]})
    except Exception:  # noqa: BLE001
        pass  # no matching indices yet — aliases auto-attach via templates
PY
}

install_opensearch_templates() {
  _opensearch_curl GET "/_cluster/health" >/dev/null 2>&1 || return 0
  log "Installing OpenSearch templates and pipelines."
  local tmp_config tmp_ca rc
  tmp_config="$(mktemp)"
  tmp_ca="$(mktemp)"
  if svc_test_f "$SIFT_HOME/opensearch.yaml"; then
    svc_read "$SIFT_HOME/opensearch.yaml" > "$tmp_config"
    # The service's CA path is intentionally inaccessible to the installer
    # operator.  Give only this short-lived bootstrap client a private copy.
    svc_read "$(_opensearch_ca_file)" > "$tmp_ca"
    chmod 600 "$tmp_ca"
    sed -i "s#^ca_certs:.*#ca_certs: $tmp_ca#" "$tmp_config"
  else
    cat > "$tmp_config" <<'YAML'
host: https://localhost:9200
user: admin
password: unused
verify_certs: true
ca_certs: /dev/null
YAML
  fi
  OPENSEARCH_CONFIG="$tmp_config" OPENSEARCH_HOST="https://localhost:9200" \
    "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads python - <<'PY'
from opensearch_mcp.client import get_client
from opensearch_mcp.mappings import ensure_winlog_pipeline

client = get_client()
result = ensure_winlog_pipeline(client)
if result.get("status") not in {"ok", "warning"}:
    raise SystemExit(result)
print(result.get("status", "ok"))
PY
  rc=$?
  rm -f "$tmp_config" "$tmp_ca"
  if [[ "$rc" -ne 0 ]]; then
    warn "OpenSearch template bootstrap failed — opensearch-mcp retries at startup."
  fi
}
