# shellcheck shell=bash
# =============================================================================
# lib/tls.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_TLS_SOURCED:-}" ]] && return 0
_SIFT_LIB_TLS_SOURCED=1

# Phase 5 — TLS
# =============================================================================

# BATCH-TLS1 / B-MVP-001: internal/local-CA profile for the IP-only lab VM.
#
# Trust model: one long-lived local CA ("Protocol SIFT Gateway local CA") signs
# the gateway leaf. Clients trust the CA *once* (import ca-cert.pem); the leaf can
# then be renewed without re-trusting anything. The CA is NEVER rotated by a
# normal rerun (clients would lose trust) — only `scripts/rotate-tls.sh --rotate-ca`
# does that, with explicit DANGER labelling.
#
# CA validity (10y) > leaf validity (2y), so the signer outlives every leaf it
# issues. ACME/domain certs are a deferred future profile (see docs §11) and are
# not built here.
# _tls_san_value -> "IP:<primary>,IP:127.0.0.1,DNS:<hostname>,DNS:localhost"
# SANs are DERIVED from the VM's real primary IP and hostname, never hardcoded.
# Loopback (127.0.0.1 / localhost) is always included so on-box `/health` and
# OpenSearch loopback checks verify cleanly. The primary IP falls back to
# 127.0.0.1 only when `hostname -I` yields nothing.
_tls_san_value() {
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

# _tls_write_leaf_ext <file> — x509 v3 extensions for the gateway LEAF cert:
# not-a-CA, server auth EKU (Chrome/modern clients require it), and the derived
# SAN list. Written to a caller-owned temp.
_tls_write_leaf_ext() {
  local out="$1"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=%s\n' "$(_tls_san_value)"
  } > "$out"
}

# _tls_sign_leaf <tmpd> <ca-cert> <ca-key> — generate a fresh leaf KEY + cert
# signed by the EXISTING CA, leaving $tmpd/gateway-key.pem and
# $tmpd/gateway-cert.pem. Used by both first-install and leaf-renewal so the two
# paths cannot drift. Operates only in the caller's temp dir; never touches the
# live tree (the caller installs the results).
_tls_sign_leaf() {
  local tmpd="$1" ca_cert="$2" ca_key="$3"
  local ext="$tmpd/leaf-ext.cnf"
  _tls_write_leaf_ext "$ext"
  openssl genrsa -out "$tmpd/gateway-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -key "$tmpd/gateway-key.pem" \
    -out "$tmpd/gateway-csr.pem" -subj "/CN=$(hostname)" >/dev/null 2>&1
  openssl x509 -req -days "$SIFT_TLS_LEAF_DAYS" -in "$tmpd/gateway-csr.pem" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -out "$tmpd/gateway-cert.pem" -extfile "$ext" >/dev/null 2>&1
}

generate_tls() {
  require_cmd openssl
  # SIFT_TLS_DIR is sift-service-owned 0700 (created by install_state_dirs). The
  # operator generates the material in an operator-owned temp dir, then installs
  # each file owned sift-service so the running gateway can read its key/cert.
  if svc_test_f "$SIFT_TLS_DIR/ca-cert.pem" \
     && svc_test_f "$SIFT_TLS_DIR/gateway-cert.pem" \
     && svc_test_f "$SIFT_TLS_DIR/gateway-key.pem"; then
    # Idempotent rerun: PRESERVE the CA and leaf. Clients keep their trust; a
    # rerun must never silently rotate the CA. Leaf renewal is an explicit
    # operator action via scripts/rotate-tls.sh.
    log "TLS material already exists — preserving CA and gateway cert."
    return
  fi

  log "Generating local CA and gateway certificate (internal-CA lab profile)."
  local tmpd
  tmpd="$(mktemp -d)"
  # CA extensions via -addext (openssl req does NOT accept -extfile; only the
  # `openssl x509` leaf-signing step does). basicConstraints critical CA:TRUE so
  # clients accept it as an issuer; keyUsage limited to cert/CRL signing.
  openssl genrsa -out "$tmpd/ca-key.pem" 4096 >/dev/null 2>&1
  openssl req -new -x509 -days "$SIFT_TLS_CA_DAYS" -key "$tmpd/ca-key.pem" \
    -out "$tmpd/ca-cert.pem" -subj "/CN=$SIFT_TLS_CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

  _tls_sign_leaf "$tmpd" "$tmpd/ca-cert.pem" "$tmpd/ca-key.pem"

  # Private keys -> 0600 sift-service; certs -> 0644 sift-service (world-readable
  # cert is fine — only the matching private key is sensitive). The ca-cert is
  # also handed to analysts (handoff references $SIFT_TLS_DIR/ca-cert.pem).
  svc_install_file "$tmpd/ca-key.pem"      "$SIFT_TLS_DIR/ca-key.pem"      600
  svc_install_file "$tmpd/gateway-key.pem" "$SIFT_TLS_DIR/gateway-key.pem" 600
  svc_install_file "$tmpd/ca-cert.pem"     "$SIFT_TLS_DIR/ca-cert.pem"     644
  svc_install_file "$tmpd/gateway-cert.pem" "$SIFT_TLS_DIR/gateway-cert.pem" 644
  rm -rf "$tmpd"
}

