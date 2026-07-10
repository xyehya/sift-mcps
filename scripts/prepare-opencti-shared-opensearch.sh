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
  OPENCTI_RABBITMQ_IMAGE, OPENCTI_MINIO_IMAGE (all immutable @sha256 images)
  OPENCTI_OPENSEARCH_CA, OPENCTI_OPENSEARCH_USER, OPENCTI_OPENSEARCH_PASSWORD
  OPENCTI_ADMIN_TOKEN, OPENCTI_WORKER_TOKEN, OPENCTI_RABBITMQ_PASSWORD,
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
[[ -f "$core_compose" && -f "$shared_compose" && -f "$role_file" ]] \
  || { printf 'FATAL: shared OpenCTI target artifacts are incomplete.\n' >&2; exit 1; }

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

for image_var in OPENCTI_PLATFORM_IMAGE OPENCTI_WORKER_IMAGE OPENCTI_REDIS_IMAGE OPENCTI_RABBITMQ_IMAGE OPENCTI_MINIO_IMAGE; do
  value="${!image_var:-}"
  [[ "$value" == *@sha256:* ]] || {
    printf 'FATAL: %s must be an immutable @sha256 image reference.\n' "$image_var" >&2
    exit 1
  }
done

[[ -r "${OPENCTI_OPENSEARCH_CA:-}" ]] \
  || { printf 'FATAL: OPENCTI_OPENSEARCH_CA must name a readable verified CA file.\n' >&2; exit 1; }
for secret_var in OPENCTI_OPENSEARCH_USER OPENCTI_OPENSEARCH_PASSWORD OPENCTI_ADMIN_TOKEN OPENCTI_WORKER_TOKEN OPENCTI_RABBITMQ_PASSWORD OPENCTI_MINIO_SECRET_KEY OPENCTI_ENCRYPTION_KEY OPENCTI_HEALTH_ACCESS_KEY; do
  [[ -n "${!secret_var:-}" ]] || {
    printf 'FATAL: %s must be supplied through the operator environment/secret store.\n' "$secret_var" >&2
    exit 1
  }
done

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

printf 'Shared OpenCTI target preflight passed (read-only).\n'
printf 'Next gates: apply the role through Security admin, run compatibility/capacity tests, then start the fresh empty OpenCTI target.\n'
