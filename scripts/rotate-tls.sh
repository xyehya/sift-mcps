#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# rotate-tls.sh — operator TLS lifecycle for the Protocol SIFT Gateway
# =============================================================================
#
# BATCH-TLS1 / B-MVP-001: internal/local-CA profile for the IP-only lab VM.
#
# Two operations, deliberately separated by blast radius:
#
#   --renew-leaf   SAFE. Issues a fresh gateway leaf cert+key signed by the
#                  EXISTING CA, with SANs re-derived from the VM's current
#                  primary IP + hostname + loopback. Clients that already trust
#                  the CA keep working — NO re-trust needed. Use this when the
#                  leaf is near expiry or the VM's IP changed.
#
#   --rotate-ca    DANGER. Generates a BRAND-NEW CA and a new leaf under it.
#                  EVERY client that imported the old CA MUST re-import the new
#                  ca-cert.pem or TLS will fail closed. Only use this if the CA
#                  private key is believed compromised or is expiring. Requires
#                  the explicit --i-understand-clients-lose-trust flag.
#
# Both operations:
#   * generate material in an operator-owned temp dir, then install each file
#     owned by the gateway service user with the same modes install.sh uses
#     (keys 0600, certs 0644);
#   * NEVER print private key material to stdout, logs, or anywhere;
#   * restart the gateway (unless --no-restart) and verify /health.
#
# Run on the VM as the operator (uses sudo where needed):
#
#   sudo ./scripts/rotate-tls.sh --renew-leaf
#   sudo ./scripts/rotate-tls.sh --rotate-ca --i-understand-clients-lose-trust
#
# ACME/domain certs are a deferred future profile (see
# docs/operator/maintenance-guide.md §11); this script implements the local-CA
# profile only.
# =============================================================================

log()  { printf '[rotate-tls] %s\n' "$*"; }
warn() { printf '[rotate-tls] WARNING: %s\n' "$*" >&2; }
die()  { printf '[rotate-tls] ERROR: %s\n' "$*" >&2; exit 1; }

sudo_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

# --- Path + identity conventions (must match install.sh) ---------------------
SIFT_STATE_DIR="${SIFT_STATE_DIR:-/var/lib/sift}"
SIFT_HOME="${SIFT_HOME:-$SIFT_STATE_DIR/.sift}"
SIFT_TLS_DIR="${SIFT_TLS_DIR:-$SIFT_HOME/tls}"
SIFT_GATEWAY_SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
SIFT_GATEWAY_SERVICE="${SIFT_GATEWAY_SERVICE:-sift-gateway.service}"

SIFT_TLS_LEAF_DAYS="${SIFT_TLS_LEAF_DAYS:-730}"
SIFT_TLS_CA_DAYS="${SIFT_TLS_CA_DAYS:-3650}"
SIFT_TLS_CA_CN="${SIFT_TLS_CA_CN:-Protocol SIFT Gateway local CA}"

HEALTH_URL="${HEALTH_URL:-https://127.0.0.1:4508/health}"

# --- Helpers -----------------------------------------------------------------
svc_test_f() { sudo_if_needed test -f "$1"; }

# Install $1 (operator temp) to $2 owned by the service user, mode $3 (atomic).
svc_install_file() {
  local src="$1" dst="$2" mode="$3"
  sudo_if_needed install -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" \
    -m "$mode" "$src" "$dst"
}

# Copy a (possibly service-owned) file into an operator temp so openssl can read
# it without running as the service user. CA key is read this way for signing.
svc_copy_out() {
  local src="$1" dst="$2"
  sudo_if_needed cat "$src" > "$dst"
}

# Derived SANs: real primary IP + loopback + hostname + localhost. Never hardcoded.
tls_san_value() {
  local first_ip host
  first_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$first_ip" ]] || first_ip="127.0.0.1"
  host="$(hostname 2>/dev/null)"
  [[ -n "$host" ]] || host="localhost"
  if [[ "$first_ip" == "127.0.0.1" ]]; then
    printf 'IP:127.0.0.1,DNS:%s,DNS:localhost' "$host"
  else
    printf 'IP:%s,IP:127.0.0.1,DNS:%s,DNS:localhost' "$first_ip" "$host"
  fi
}

write_leaf_ext() {
  local out="$1"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=%s\n' "$(tls_san_value)"
  } > "$out"
}

# Sign a fresh leaf key+cert in $tmpd against the given CA cert/key.
sign_leaf() {
  local tmpd="$1" ca_cert="$2" ca_key="$3"
  local ext="$tmpd/leaf-ext.cnf"
  write_leaf_ext "$ext"
  openssl genrsa -out "$tmpd/gateway-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -key "$tmpd/gateway-key.pem" \
    -out "$tmpd/gateway-csr.pem" -subj "/CN=$(hostname)" >/dev/null 2>&1
  openssl x509 -req -days "$SIFT_TLS_LEAF_DAYS" -in "$tmpd/gateway-csr.pem" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -out "$tmpd/gateway-cert.pem" -extfile "$ext" >/dev/null 2>&1
}

restart_gateway() {
  if [[ "${NO_RESTART:-0}" -eq 1 ]]; then
    log "--no-restart given; not restarting $SIFT_GATEWAY_SERVICE."
    log "The new leaf is on disk but the running gateway still serves the old one."
    log "Restart later with: sudo systemctl restart $SIFT_GATEWAY_SERVICE"
    return 0
  fi
  log "Restarting $SIFT_GATEWAY_SERVICE to load the new certificate."
  sudo_if_needed systemctl restart "$SIFT_GATEWAY_SERVICE"
}

verify_health() {
  [[ "${NO_RESTART:-0}" -eq 1 ]] && return 0
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sk --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
      log "Gateway /health reachable over TLS after rotation."
      return 0
    fi
    sleep 2
  done
  warn "Gateway /health not reachable after restart — check 'journalctl -u $SIFT_GATEWAY_SERVICE'."
  return 1
}

# Print a sanitized summary of the live leaf (subject/issuer/dates/SAN). Never
# prints key material.
show_leaf_summary() {
  local tmp
  tmp="$(mktemp)"
  if svc_copy_out "$SIFT_TLS_DIR/gateway-cert.pem" "$tmp" 2>/dev/null; then
    log "New gateway leaf:"
    openssl x509 -in "$tmp" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/    /'
    openssl x509 -in "$tmp" -noout -ext subjectAltName 2>/dev/null \
      | grep -v 'X509v3 Subject Alternative Name' | sed 's/^ */    SAN: /'
  fi
  rm -f "$tmp"
}

# --- Operations --------------------------------------------------------------
renew_leaf() {
  require_ca
  log "Renewing gateway LEAF against the existing CA (clients keep their trust)."
  local tmpd
  tmpd="$(mktemp -d)"
  chmod 700 "$tmpd"
  trap 'rm -rf "$tmpd"' RETURN
  svc_copy_out "$SIFT_TLS_DIR/ca-cert.pem" "$tmpd/ca-cert.pem"
  svc_copy_out "$SIFT_TLS_DIR/ca-key.pem"  "$tmpd/ca-key.pem"
  chmod 600 "$tmpd/ca-key.pem"
  sign_leaf "$tmpd" "$tmpd/ca-cert.pem" "$tmpd/ca-key.pem"
  svc_install_file "$tmpd/gateway-key.pem"  "$SIFT_TLS_DIR/gateway-key.pem"  600
  svc_install_file "$tmpd/gateway-cert.pem" "$SIFT_TLS_DIR/gateway-cert.pem" 644
  log "Leaf renewed. CA fingerprint unchanged; no client re-trust required."
  restart_gateway
  verify_health || true
  show_leaf_summary
}

rotate_ca() {
  if [[ "${CA_CONFIRMED:-0}" -ne 1 ]]; then
    die "Refusing --rotate-ca without --i-understand-clients-lose-trust.
     DANGER: a new CA invalidates trust for EVERY client that imported the old
     ca-cert.pem. They must all re-import the new $SIFT_TLS_DIR/ca-cert.pem."
  fi
  warn "DANGER: rotating the CA. All existing clients lose trust until they"
  warn "re-import the new ca-cert.pem. Proceeding in 3s (Ctrl-C to abort)..."
  sleep 3
  local tmpd
  tmpd="$(mktemp -d)"
  chmod 700 "$tmpd"
  trap 'rm -rf "$tmpd"' RETURN
  # CA extensions via -addext (openssl req does NOT accept -extfile).
  openssl genrsa -out "$tmpd/ca-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -x509 -days "$SIFT_TLS_CA_DAYS" -key "$tmpd/ca-key.pem" \
    -out "$tmpd/ca-cert.pem" -subj "/CN=$SIFT_TLS_CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  sign_leaf "$tmpd" "$tmpd/ca-cert.pem" "$tmpd/ca-key.pem"
  svc_install_file "$tmpd/ca-key.pem"       "$SIFT_TLS_DIR/ca-key.pem"       600
  svc_install_file "$tmpd/gateway-key.pem"  "$SIFT_TLS_DIR/gateway-key.pem"  600
  svc_install_file "$tmpd/ca-cert.pem"      "$SIFT_TLS_DIR/ca-cert.pem"      644
  svc_install_file "$tmpd/gateway-cert.pem" "$SIFT_TLS_DIR/gateway-cert.pem" 644
  log "New CA + leaf installed. RE-DISTRIBUTE $SIFT_TLS_DIR/ca-cert.pem to ALL clients."
  restart_gateway
  verify_health || true
  show_leaf_summary
}

require_ca() {
  svc_test_f "$SIFT_TLS_DIR/ca-cert.pem" \
    || die "CA cert not found at $SIFT_TLS_DIR/ca-cert.pem — run ./install.sh first."
  svc_test_f "$SIFT_TLS_DIR/ca-key.pem" \
    || die "CA key not found at $SIFT_TLS_DIR/ca-key.pem — cannot sign a new leaf."
}

usage() {
  cat <<EOF
Usage: rotate-tls.sh <operation> [options]

Operations:
  --renew-leaf    Renew the gateway leaf cert against the existing CA (SAFE).
  --rotate-ca     Generate a brand-new CA + leaf (DANGER: clients lose trust).

Options:
  --i-understand-clients-lose-trust   Required confirmation for --rotate-ca.
  --no-restart                        Install material but do not restart/verify.
  -h, --help                          Show this help.

Examples:
  sudo ./scripts/rotate-tls.sh --renew-leaf
  sudo ./scripts/rotate-tls.sh --rotate-ca --i-understand-clients-lose-trust

No private key material is ever printed. See maintenance-guide.md §11.
EOF
}

main() {
  require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
  require_cmd openssl

  local op=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --renew-leaf) op="renew" ;;
      --rotate-ca)  op="rotate" ;;
      --i-understand-clients-lose-trust) CA_CONFIRMED=1 ;;
      --no-restart) NO_RESTART=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown argument: $1 (try --help)" ;;
    esac
    shift
  done

  case "$op" in
    renew)  renew_leaf ;;
    rotate) rotate_ca ;;
    "")     usage; exit 2 ;;
  esac
}

main "$@"
