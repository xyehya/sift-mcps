#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only gate for the OpenCTI shared-OpenSearch target path.
#
# This command deliberately does not create credentials, transfer data, or
# start/stop containers. It proves that the operator has supplied the immutable
# images/CA/credentials and that the secure core compose contract is intact.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/prepare-opencti-shared-opensearch.sh --check

Read-only preflight for the security-enabled OpenCTI shared-OpenSearch target.
It never transfers data, changes OpenSearch security, or starts containers.

Required environment for a passing target check:
  OPENCTI_PLATFORM_IMAGE, OPENCTI_WORKER_IMAGE, OPENCTI_REDIS_IMAGE,
  OPENCTI_RABBITMQ_IMAGE, OPENCTI_MINIO_IMAGE, and the four
  OPENCTI_CONNECTOR_*_IMAGE values (all immutable @sha256 images)
  OPENCTI_OPENSEARCH_CA, OPENCTI_OPENSEARCH_USER, OPENCTI_OPENSEARCH_PASSWORD
  OPENCTI_ADMIN_PASSWORD, OPENCTI_ADMIN_TOKEN, OPENCTI_WORKER_TOKEN,
  OPENCTI_RABBITMQ_PASSWORD,
  OPENCTI_MINIO_SECRET_KEY, OPENCTI_ENCRYPTION_KEY, OPENCTI_HEALTH_ACCESS_KEY

The explicit docker-compose.dev-insecure.yml profile is never an acceptance
target and must not be used for shared mode.
EOF
}

[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && { usage; exit 0; }
[[ "${1:-}" == "--check" && $# -eq 1 ]] || { usage >&2; exit 2; }

core_compose="$REPO_DIR/docker-compose.yml"
shared_compose="$REPO_DIR/docker-compose.opencti-shared.yml"
role_file="$REPO_DIR/configs/opensearch/security/opencti-platform-role.yml"
tuple_file="$REPO_DIR/configs/opencti/shared-target-versions.env"
[[ -f "$core_compose" && -f "$shared_compose" && -f "$role_file" && -f "$tuple_file" ]] \
  || { printf 'FATAL: shared OpenCTI target artifacts are incomplete.\n' >&2; exit 1; }

# Trusted repository-owned constants only; this file is forbidden from carrying
# credentials and every consumed value is validated below.
# shellcheck disable=SC1090
source "$tuple_file"
[[ "$OPENCTI_VERSION" =~ ^7\.[0-9]{6}\.[0-9]+$ ]] \
  || { printf 'FATAL: invalid pinned OpenCTI version.\n' >&2; exit 1; }
[[ "$PYCTI_VERSION" == "$OPENCTI_VERSION" ]] \
  || { printf 'FATAL: pycti must exactly match the pinned OpenCTI version.\n' >&2; exit 1; }
[[ "$OPENSEARCH_VERSION" == "3.5.0" ]] \
  || { printf 'FATAL: unsupported shared-target OpenSearch version.\n' >&2; exit 1; }
export OPENCTI_PLATFORM_IMAGE OPENCTI_WORKER_IMAGE OPENCTI_REDIS_IMAGE
export OPENCTI_RABBITMQ_IMAGE OPENCTI_MINIO_IMAGE
export OPENCTI_CONNECTOR_MITRE_IMAGE OPENCTI_CONNECTOR_CISA_KEV_IMAGE
export OPENCTI_CONNECTOR_THREATFOX_IMAGE OPENCTI_CONNECTOR_URLHAUS_IMAGE

command -v docker >/dev/null 2>&1 || {
  printf 'FATAL: Docker is required to validate the shared compose contract.\n' >&2
  exit 1
}
docker compose version >/dev/null 2>&1 || {
  printf 'FATAL: Docker Compose v2 is required for the shared target.\n' >&2
  exit 1
}

if grep -Eq 'DISABLE_SECURITY_PLUGIN[=:]true|plugins\.security\.disabled[=:]true' "$core_compose"; then
  printf 'FATAL: core OpenSearch Security is disabled. Enable and prove TLS/authentication before shared mode.\n' >&2
  exit 1
fi
grep -q 'OPENSEARCH_INITIAL_ADMIN_PASSWORD' "$core_compose" || {
  printf 'FATAL: core OpenSearch compose does not require an authenticated admin identity.\n' >&2
  exit 1
}
grep -q 'https://localhost:9200' "$core_compose" || {
  printf 'FATAL: core OpenSearch health contract does not require TLS.\n' >&2
  exit 1
}

for image_var in OPENCTI_PLATFORM_IMAGE OPENCTI_WORKER_IMAGE OPENCTI_REDIS_IMAGE OPENCTI_RABBITMQ_IMAGE OPENCTI_MINIO_IMAGE OPENCTI_CONNECTOR_MITRE_IMAGE OPENCTI_CONNECTOR_CISA_KEV_IMAGE OPENCTI_CONNECTOR_THREATFOX_IMAGE OPENCTI_CONNECTOR_URLHAUS_IMAGE; do
  value="${!image_var:-}"
  [[ "$value" == *@sha256:* ]] || {
    printf 'FATAL: %s must be an immutable @sha256 image reference.\n' "$image_var" >&2
    exit 1
  }
done

[[ "$OPENCTI_PLATFORM_IMAGE" == "opencti/platform@sha256:9cbf5b159faeea7eadd33f1643abf96d4d27f8659bc68a15c148085dc4cc77f1" ]] \
  || { printf 'FATAL: OpenCTI platform image does not match the accepted tuple.\n' >&2; exit 1; }
[[ "$OPENCTI_WORKER_IMAGE" == "opencti/worker@sha256:3cb80d6f9f4816fdd2c4f8565807851388be3e247ef2348ef34a553be8d414ea" ]] \
  || { printf 'FATAL: OpenCTI worker image does not match the accepted tuple.\n' >&2; exit 1; }
[[ -r "${OPENCTI_OPENSEARCH_CA:-}" ]] \
  || { printf 'FATAL: OPENCTI_OPENSEARCH_CA must name a readable verified CA file.\n' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 \
  || { printf 'FATAL: openssl is required for CA validation.\n' >&2; exit 1; }
openssl x509 -in "$OPENCTI_OPENSEARCH_CA" -noout -checkend 0 >/dev/null 2>&1 \
  || { printf 'FATAL: OpenSearch CA is invalid, expired, or not yet valid.\n' >&2; exit 1; }
cert_text="$(openssl x509 -in "$OPENCTI_OPENSEARCH_CA" -noout -text 2>/dev/null)"
grep -Eqi 'Signature Algorithm: (sha256|sha384|sha512)' <<<"$cert_text" \
  || { printf 'FATAL: OpenSearch CA must use a SHA-2 signature.\n' >&2; exit 1; }
if grep -q 'Public Key Algorithm: rsaEncryption' <<<"$cert_text"; then
  grep -Eq 'Public-Key: \((2048|3072|4096|[5-9][0-9]{3,}) bit\)' <<<"$cert_text" \
    || { printf 'FATAL: OpenSearch CA RSA key is below 2048 bits.\n' >&2; exit 1; }
fi
for secret_var in OPENCTI_OPENSEARCH_USER OPENCTI_OPENSEARCH_PASSWORD OPENCTI_ADMIN_PASSWORD OPENCTI_ADMIN_TOKEN OPENCTI_WORKER_TOKEN OPENCTI_RABBITMQ_PASSWORD OPENCTI_MINIO_SECRET_KEY OPENCTI_ENCRYPTION_KEY OPENCTI_HEALTH_ACCESS_KEY; do
  [[ -n "${!secret_var:-}" ]] || {
    printf 'FATAL: %s must be supplied through the operator environment/secret store.\n' "$secret_var" >&2
    exit 1
  }
done

for image_var in OPENCTI_PLATFORM_IMAGE OPENCTI_WORKER_IMAGE OPENCTI_CONNECTOR_MITRE_IMAGE OPENCTI_CONNECTOR_CISA_KEV_IMAGE OPENCTI_CONNECTOR_THREATFOX_IMAGE OPENCTI_CONNECTOR_URLHAUS_IMAGE; do
  image="${!image_var}"
  if [[ "${SIFT_OFFLINE:-0}" == "1" ]]; then
    docker image inspect "$image" >/dev/null 2>&1 \
      || { printf 'FATAL: offline mode requires cached pinned image %s.\n' "$image_var" >&2; exit 1; }
  else
    if ! docker manifest inspect "$image" >/dev/null 2>&1; then
      docker image inspect "$image" >/dev/null 2>&1 \
        || { printf 'FATAL: pinned image %s is unavailable from the registry and local cache.\n' "$image_var" >&2; exit 1; }
      printf 'WARNING: registry probe failed for %s; using exact cached digest.\n' "$image_var" >&2
    fi
  fi
done

pycti_spec="$(SIFT_REPO_DIR="$REPO_DIR" python3 - <<'PY'
import os, pathlib, tomllib
p = tomllib.loads((pathlib.Path(os.environ["SIFT_REPO_DIR"]) / "packages/opencti-mcp/pyproject.toml").read_text())
print(next(x for x in p["project"]["dependencies"] if x.startswith("pycti")))
PY
)"
[[ "$pycti_spec" == "pycti==${PYCTI_VERSION}" ]] \
  || { printf 'FATAL: package metadata does not pin the accepted pycti version.\n' >&2; exit 1; }

check_url="${OPENCTI_OPENSEARCH_CHECK_URL:-https://127.0.0.1:9200}"
export OPENCTI_OPENSEARCH_CHECK_URL
live_version="$(python3 - 2>/dev/null <<'PY'
import base64, json, os, ssl, urllib.parse, urllib.request
url = os.environ["OPENCTI_OPENSEARCH_CHECK_URL"]
parsed = urllib.parse.urlparse(url)
if parsed.scheme != "https" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
    raise SystemExit("OpenSearch check URL must be HTTPS loopback")
ctx = ssl.create_default_context(cafile=os.environ["OPENCTI_OPENSEARCH_CA"])
token = base64.b64encode(
    f'{os.environ["OPENCTI_OPENSEARCH_USER"]}:{os.environ["OPENCTI_OPENSEARCH_PASSWORD"]}'.encode()
).decode()
request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
with urllib.request.urlopen(request, context=ctx, timeout=10) as response:
    payload = json.load(response)
print(payload["version"]["number"])
PY
)" || { printf 'FATAL: authenticated TLS OpenSearch tuple probe failed.\n' >&2; exit 1; }
[[ "$live_version" == "$OPENSEARCH_VERSION" ]] \
  || { printf 'FATAL: live OpenSearch version %s does not match accepted %s.\n' "$live_version" "$OPENSEARCH_VERSION" >&2; exit 1; }

role_body="$(sed '/^[[:space:]]*#/d' "$role_file")"
wildcard_pattern="^[[:space:]]*-[[:space:]]*[\"']?\\*[\"']?[[:space:]]*$"
if grep -Eq "$wildcard_pattern" <<<"$role_body" \
  || grep -Eq 'index_patterns:.*"\*"' <<<"$role_body" \
  || grep -Eq "index_patterns:.*'\\*'" <<<"$role_body" \
  || grep -Eq 'all_access|readall|restapi:admin' <<<"$role_body"; then
  printf 'FATAL: OpenCTI role contains a broad index/security permission.\n' >&2
  exit 1
fi
grep -Eq 'opencti\*' "$role_file" || {
  printf 'FATAL: OpenCTI role must contain the opencti* index boundary.\n' >&2
  exit 1
}
grep -q 'ELASTICSEARCH__ENGINE_CHECK=true' "$shared_compose" || {
  printf 'FATAL: shared compose must keep OpenCTI compatibility checks enabled.\n' >&2
  exit 1
}
grep -q 'external: true' "$shared_compose" || {
  printf 'FATAL: shared compose must attach to a pre-created core network.\n' >&2
  exit 1
}
if grep -q 'opencti-opensearch' "$shared_compose"; then
  printf 'FATAL: shared compose still declares a dedicated OpenCTI OpenSearch service.\n' >&2
  exit 1
fi

docker compose -f "$shared_compose" config --quiet >/dev/null || {
  printf 'FATAL: shared OpenCTI compose configuration is invalid.\n' >&2
  exit 1
}

printf 'Shared OpenCTI target preflight passed (read-only): OpenCTI=%s pycti=%s OpenSearch=%s.\n' \
  "$OPENCTI_VERSION" "$PYCTI_VERSION" "$OPENSEARCH_VERSION"
printf 'Next gates: apply the role through Security admin, run compatibility/capacity tests, then start the fresh empty OpenCTI target.\n'
