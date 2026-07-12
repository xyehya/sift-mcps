#!/usr/bin/env bash
# Idempotent userspace Tailscale bring-up for Cursor Cloud agents.
# Requires runtime secrets: TS_AUTHKEY, SIFT_CA_CERT (never commit values).
set -euo pipefail

TS_SOCKET="${TS_SOCKET:-/tmp/tailscaled.sock}"
TS_STATE_DIR="${TS_STATE_DIR:-/tmp/tailscaled.state}"
TS_SOCKS_PORT="${TS_SOCKS_PORT:-1055}"
TS_HTTP_PROXY_PORT="${TS_HTTP_PROXY_PORT:-1054}"
SIFT_CA_PATH="${SIFT_CA_PATH:-/tmp/sift-ca.pem}"
TS_READY_MARKER="${TS_READY_MARKER:-/tmp/tailscaled.ready}"

log() { printf '[cloud-tailscale] %s\n' "$*"; }

if [[ -z "${TS_AUTHKEY:-}" ]]; then
  log "TS_AUTHKEY missing — skip Tailscale (configure as Runtime Secret on the environment)."
  exit 0
fi

mkdir -p "$TS_STATE_DIR"

if [[ -n "${SIFT_CA_CERT:-}" ]]; then
  printf '%s\n' "$SIFT_CA_CERT" > "$SIFT_CA_PATH"
  chmod 600 "$SIFT_CA_PATH"
fi

# Stop systemd tailscaled if the package installer enabled it (kernel mode won't work here).
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop tailscaled 2>/dev/null || true
fi

if ! ss -ltn 2>/dev/null | grep -q ":${TS_SOCKS_PORT} "; then
  log "Starting userspace tailscaled (SOCKS ${TS_SOCKS_PORT}, HTTP proxy ${TS_HTTP_PROXY_PORT})"
  tailscaled \
    --tun=userspace-networking \
    --socks5-server="localhost:${TS_SOCKS_PORT}" \
    --outbound-http-proxy-listen="localhost:${TS_HTTP_PROXY_PORT}" \
    --socket="$TS_SOCKET" \
    --statedir="$TS_STATE_DIR" &
  sleep 2
fi

if ! tailscale --socket="$TS_SOCKET" status >/dev/null 2>&1; then
  host_slug="cursor-cloud-agent-$(hostname | tr -cd 'a-zA-Z0-9' | cut -c1-12)"
  log "Joining tailnet as ${host_slug}"
  tailscale --socket="$TS_SOCKET" up \
    --authkey="$TS_AUTHKEY" \
    --accept-routes \
    --hostname="$host_slug"
fi

: > "$TS_READY_MARKER"
log "Tailscale up; SOCKS socks5h://127.0.0.1:${TS_SOCKS_PORT}"
