#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { printf 'FATAL: run as root\n' >&2; exit 1; }
ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
COMPOSE="$ROOT/docker-compose.opencti-shared.yml"
CONNECTORS_COMPOSE="$ROOT/docker-compose.opencti-connectors.yml"
STACK_ENV="/var/lib/sift/.sift/opencti-stack.env"
SHARED_ENV="/var/lib/sift/.sift/opencti-shared.env"
TUPLE="$ROOT/configs/opencti/shared-target-versions.env"

command -v docker >/dev/null || { printf 'FATAL: Docker is required.\n' >&2; exit 1; }
# The directory is the gateway service home and must remain service-owned.
# Root owns only the OpenCTI stack secret files inside it.
mkdir -p /var/lib/sift/.sift
if [[ ! -f "$STACK_ENV" ]]; then
  umask 077
  cat >"$STACK_ENV" <<EOF
OPENCTI_ADMIN_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')
OPENCTI_ADMIN_TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4())')
OPENCTI_WORKER_TOKEN=$(python3 -c 'import uuid; print(uuid.uuid4())')
OPENCTI_RABBITMQ_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')
OPENCTI_MINIO_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
OPENCTI_ENCRYPTION_KEY=$(openssl rand -hex 32)
OPENCTI_HEALTH_ACCESS_KEY=$(openssl rand -base64 48 | tr -d '\n')
EOF
fi
chown root:root "$STACK_ENV"; chmod 600 "$STACK_ENV"

SIFT_MCPS_ROOT="$ROOT" "$ROOT/.venv/bin/python" "$ROOT/scripts/provision-opencti-shared-opensearch.py"
set -a
# Runtime-generated root-only environment files.
# shellcheck disable=SC1090
source "$STACK_ENV"
# shellcheck disable=SC1090
source "$SHARED_ENV"
# shellcheck disable=SC1090
source "$TUPLE"
set +a
bash "$ROOT/scripts/prepare-opencti-shared-opensearch.sh" --check
docker compose --env-file "$STACK_ENV" -f "$COMPOSE" up -d redis rabbitmq minio opencti
for _ in $(seq 1 120); do
  [[ "$(docker inspect sift-opencti --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true)" == healthy ]] && break
  sleep 5
done
[[ "$(docker inspect sift-opencti --format '{{.State.Health.Status}}')" == healthy ]] || { docker logs --tail 80 sift-opencti >&2; exit 1; }
if [[ "${SIFT_OFFLINE:-0}" != "1" ]]; then
  for image in "$OPENCTI_CONNECTOR_MITRE_IMAGE" "$OPENCTI_CONNECTOR_CISA_KEV_IMAGE" "$OPENCTI_CONNECTOR_THREATFOX_IMAGE" "$OPENCTI_CONNECTOR_URLHAUS_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null
  done
fi
"$ROOT/.venv/bin/python" "$ROOT/scripts/provision-opencti-api-identities.py"
set -a
# Runtime-generated root-only environment file.
# shellcheck disable=SC1090
source "$STACK_ENV"
set +a
OPENCTI_WORKER_COUNT="${SIFT_OPENCTI_WORKERS:-8}"
[[ "$OPENCTI_WORKER_COUNT" =~ ^[1-8]$ ]] \
  || { printf 'FATAL: SIFT_OPENCTI_WORKERS must be an integer from 1 through 8.\n' >&2; exit 1; }
docker compose --env-file "$STACK_ENV" -f "$COMPOSE" up -d --scale worker="$OPENCTI_WORKER_COUNT" worker
if [[ "${SIFT_OFFLINE:-0}" == "1" ]]; then
  printf 'Offline mode: public-feed connectors are prepared but not started.\n'
else
  CONNECTORS_ENV="/var/lib/sift/.sift/opencti-connectors.env"
  # shellcheck disable=SC1090
  source "$CONNECTORS_ENV"
  export OPENCTI_CONNECTOR_MITRE_IMAGE OPENCTI_CONNECTOR_CISA_KEV_IMAGE
  export OPENCTI_CONNECTOR_THREATFOX_IMAGE OPENCTI_CONNECTOR_URLHAUS_IMAGE
  export OPENCTI_CONNECTOR_MITRE_TOKEN OPENCTI_CONNECTOR_CISA_KEV_TOKEN
  export OPENCTI_CONNECTOR_THREATFOX_TOKEN OPENCTI_CONNECTOR_URLHAUS_TOKEN
  export OPENCTI_CONNECTOR_MITRE_ID OPENCTI_CONNECTOR_CISA_KEV_ID
  export OPENCTI_CONNECTOR_THREATFOX_ID OPENCTI_CONNECTOR_URLHAUS_ID
  "$ROOT/.venv/bin/python" "$ROOT/scripts/bootstrap-opencti-mitre-provenance.py"
  docker compose -f "$CONNECTORS_COMPOSE" config --quiet
  docker compose -f "$CONNECTORS_COMPOSE" up -d
  "$ROOT/.venv/bin/python" "$ROOT/scripts/verify-opencti-public-feeds.py"
  printf 'Pinned public feeds started: MITRE ATT&CK, CISA KEV, ThreatFox, URLhaus.\n'
fi
systemctl restart sift-gateway
printf 'Secure shared-target OpenCTI provisioned.\n'
