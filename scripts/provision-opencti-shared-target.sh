#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { printf 'FATAL: run as root\n' >&2; exit 1; }
ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
COMPOSE="$ROOT/docker-compose.opencti-shared.yml"
STACK_ENV="/var/lib/sift/.sift/opencti-stack.env"
SHARED_ENV="/var/lib/sift/.sift/opencti-shared.env"
TUPLE="$ROOT/configs/opencti/shared-target-versions.env"

command -v docker >/dev/null || { printf 'FATAL: Docker is required.\n' >&2; exit 1; }
install -d -m 700 -o root -g root /var/lib/sift/.sift
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
"$ROOT/.venv/bin/python" "$ROOT/scripts/provision-opencti-api-identities.py"
set -a
# Runtime-generated root-only environment file.
# shellcheck disable=SC1090
source "$STACK_ENV"
set +a
docker compose --env-file "$STACK_ENV" -f "$COMPOSE" up -d worker
systemctl restart sift-gateway
printf 'Secure shared-target OpenCTI provisioned.\n'
