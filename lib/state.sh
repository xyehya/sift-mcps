# shellcheck shell=bash
# =============================================================================
# lib/state.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_STATE_SOURCED:-}" ]] && return 0
_SIFT_LIB_STATE_SOURCED=1

# =============================================================================
# Phase 3 — state directories
# =============================================================================

# Edge-case (XYE-42): a prior install was torn down — e.g. via scripts/uninstall.sh,
# which PRESERVES /cases by design — leaving orphaned evidence and/or state behind.
# A fresh install seeds an EMPTY control-plane DB, so those leftover case dirs would
# no longer match any registered case. Rather than abort or silently clobber them,
# move the orphaned data to a timestamped backup and proceed with clean directories,
# warning the operator where it went.
#
# Triggers ONLY on a fresh install (no prior gateway config at $SIFT_HOME). An
# idempotent re-run / in-place upgrade keeps $SIFT_HOME, so a live case is never moved.
# Override the backup location with SIFT_PREINSTALL_BACKUP_DIR (default /var/backups/sift).
backup_preexisting_data_if_fresh() {
  # Prior config present => idempotent re-run/upgrade. Never move data.
  if sudo_if_needed test -e "$SIFT_HOME"; then
    return 0
  fi

  # Collect data roots that exist AND are non-empty (orphaned by a prior teardown).
  local to_backup=() root
  for root in "$SIFT_CASE_ROOT" "$SIFT_STATE_DIR"; do
    if sudo_if_needed test -d "$root" && \
       [[ -n "$(sudo_if_needed find "$root" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
      to_backup+=("$root")
    fi
  done
  [[ ${#to_backup[@]} -eq 0 ]] && return 0

  local stamp backup_root
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup_root="${SIFT_PREINSTALL_BACKUP_DIR:-/var/backups/sift}/preinstall-$stamp"
  warn "Fresh install, but pre-existing SIFT data was found (no prior config at $SIFT_HOME)."
  warn "  This is normal after scripts/uninstall.sh (which preserves /cases). To avoid losing"
  warn "  it or colliding with the new empty control-plane, it is being moved aside:"
  sudo_if_needed install -d -m 700 "$backup_root"

  local src base dst
  for src in "${to_backup[@]}"; do
    base="$(basename "$src")"
    dst="$backup_root/$base"
    warn "    $src  ->  $dst"
    # Same-filesystem mv is a fast rename and works even on immutable-flagged
    # evidence inside (rename touches only the parent dir, not the immutable
    # files). That is the ONLY move the installer performs.
    #
    # D5 / immutability boundary #2: the installer must have NO code path that can
    # delete evidence. So a cross-filesystem move is NOT auto-completed by a
    # copy-then-delete of the source (that would mean unlocking the immutability
    # flags and recursively removing the cases/state root from inside install.sh).
    # Instead we copy the bytes across, LEAVE the source untouched, and tell the
    # operator to remove it by hand via the gated scripts/uninstall.sh path.
    if ! sudo_if_needed mv "$src" "$dst" 2>/dev/null; then
      if sudo_if_needed cp -a "$src" "$dst"; then
        warn "    Cross-filesystem move: copied $src -> $dst but LEFT the original"
        warn "    in place (installer never deletes evidence/state). Remove the"
        warn "    original yourself once verified, e.g. via scripts/uninstall.sh."
      else
        die "Failed to copy pre-existing data aside ($src -> $dst); aborting so no data is lost."
      fi
    fi
  done
  warn "  Pre-install backup complete: $backup_root"
  warn "  It may contain write-protected (immutable-flagged) evidence; the installer"
  warn "  will not unlock or remove it. Use the gated scripts/uninstall.sh evidence"
  warn "  path if you ever need to delete it."
  warn "  Proceeding with a clean install."
}

install_state_dirs() {
  # Runtime state is owned by sift-service so the SERVICE can read/write it. The
  # installer runs as the operator, so every mkdir/chown crosses the boundary via
  # sudo. The service user + `sift` group must already exist (ensure_gateway_service_user).
  local svc="$SIFT_GATEWAY_SERVICE_USER"
  log "Creating SIFT state directories (owned by service user: $svc)."

  # /var/lib/sift itself must be world-traversable (0755) so the service can
  # reach its SIFT_HOME/state children and the world-readable symbol-cache parent
  # is reachable; its sensitive children keep tight modes below.
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_STATE_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_PASSWORDS_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_VERIFICATION_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_TOKENS_DIR"
  # REVIEW: snapshots kept at uid/gid 1000 (the operator) as before — snapshot
  # tooling historically writes them as the interactive operator, not the service.
  sudo_if_needed install -d -m 755 -o 1000 -g 1000 "$SIFT_SNAPSHOTS_DIR"
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_ENRICHMENT_DIR"
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_CASE_ROOT"

  # B-MVP-015 / B-MVP-004 (D3): explicit Hugging Face cache under the service
  # home so the BGE embedding weights live with the service that uses them
  # (gateway/worker run as sift-service and read HF_HOME from their unit env),
  # not in the operator's home. 0755 so the seed (run by the operator via uv)
  # and the running service can both reach it; weights are public, not secret.
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$(dirname "$SIFT_HF_HOME")"
  sudo_if_needed install -d -m 755 -o "$svc" -g "$svc" "$SIFT_HF_HOME"

  # SIFT_HOME (secrets + gateway.yaml + TLS + backups): 0700 owned sift-service.
  # NOT group `sift` — secrets must NOT be readable by agent_runtime.
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_HOME"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_TLS_DIR"
  sudo_if_needed install -d -m 700 -o "$svc" -g "$svc" "$SIFT_BACKUP_DIR"

  # Shared Volatility3 symbol cache under /var/cache (NOT $SIFT_STATE_DIR — see
  # the SIFT_VOL_SYMBOLS definition: /var/lib/sift carries a recursive
  # agent_runtime deny ACL). 2775 (setgid) group `sift` so both sift-service and
  # agent_runtime inherit the group and can share PDB symbols. The group-write
  # default ACL (so cached files are group-writable, not just group-readable) is
  # asserted in join_shared_symbol_group, after configure_agent_runtime ensures acl.
  sudo_if_needed install -d -m 0755 "$(dirname "$SIFT_VOL_SYMBOLS")"
  sudo_if_needed install -d -m 2775 -o "$svc" -g "$SIFT_GATEWAY_SERVICE_GROUP" "$SIFT_VOL_SYMBOLS"
  # Re-assert setgid bit (install -m may be masked by umask on some coreutils).
  sudo_if_needed chmod 2775 "$SIFT_VOL_SYMBOLS"
}

ensure_gateway_service_user() {
  if [[ -z "${SIFT_GATEWAY_SERVICE_USER:-}" ]]; then
    SIFT_GATEWAY_SERVICE_USER="sift-service"
  fi
  local svc="$SIFT_GATEWAY_SERVICE_USER"

  # Primary per-user group (sift-service) — distinct from the shared `sift` group.
  if ! getent group "$svc" >/dev/null 2>&1; then
    log "Creating gateway service primary group: $svc"
    sudo_if_needed groupadd -r "$svc"
  fi

  # Shared symbol-cache group (`sift`) — supplementary group for sift-service and
  # (later) agent_runtime. Used ONLY for the 2775 volatility-symbols cache.
  if ! getent group "$SIFT_GATEWAY_SERVICE_GROUP" >/dev/null 2>&1; then
    log "Creating shared symbol-cache group: $SIFT_GATEWAY_SERVICE_GROUP"
    sudo_if_needed groupadd -r "$SIFT_GATEWAY_SERVICE_GROUP"
  fi

  if id -u "$svc" >/dev/null 2>&1; then
    log "Gateway service user exists: $svc"
  else
    local nologin="/usr/sbin/nologin"
    [[ -x "$nologin" ]] || nologin="/sbin/nologin"
    [[ -x "$nologin" ]] || nologin="/bin/false"
    log "Creating dedicated gateway service user: $svc (home=$SIFT_STATE_DIR, group=$svc)"
    sudo_if_needed useradd -r -M -s "$nologin" -d "$SIFT_STATE_DIR" -g "$svc" "$svc"
  fi

  # Idempotently add the service user to the shared symbol group.
  if ! id -nG "$svc" 2>/dev/null | tr ' ' '\n' | grep -qx "$SIFT_GATEWAY_SERVICE_GROUP"; then
    log "Adding $svc to shared symbol group: $SIFT_GATEWAY_SERVICE_GROUP"
    sudo_if_needed usermod -aG "$SIFT_GATEWAY_SERVICE_GROUP" "$svc"
  fi
}

# Add agent_runtime to the shared `sift` group so it can write the shared
# Volatility3 symbol cache. Idempotent. Grants NOTHING else — `sift` gates only
# the 2775 vol-symbols dir; agent_runtime gains no access to SIFT_HOME secrets
# (those stay group sift-service, mode 0700/0600).
join_shared_symbol_group() {
  # Group-write default ACL on the shared symbol cache: setgid alone propagates
  # group ownership but new files still land 0644 (group read-only), so a symbol
  # generated by one user can't be rewritten by the other. A default ACL grants
  # group `sift` rwx on the dir and on inherited files. Runs here (not in
  # install_state_dirs) because configure_agent_runtime has ensured `acl` by now.
  if command -v setfacl >/dev/null 2>&1 && [[ -d "$SIFT_VOL_SYMBOLS" ]]; then
    sudo_if_needed setfacl -m "g:${SIFT_GATEWAY_SERVICE_GROUP}:rwx" \
      -d -m "g:${SIFT_GATEWAY_SERVICE_GROUP}:rwx" "$SIFT_VOL_SYMBOLS" 2>/dev/null \
      || warn "Could not set group-write ACL on $SIFT_VOL_SYMBOLS — cross-user symbol caching may be read-only."
  fi

  local rt="${SIFT_EXECUTE_AS_USER:-}"
  if [[ -z "$rt" || "$rt" == "__current__" ]]; then
    return 0
  fi
  if ! id -u "$rt" >/dev/null 2>&1; then
    warn "join_shared_symbol_group: runtime user '$rt' not found — skipping vol-symbol group membership."
    return 0
  fi
  if ! id -nG "$rt" 2>/dev/null | tr ' ' '\n' | grep -qx "$SIFT_GATEWAY_SERVICE_GROUP"; then
    log "Adding $rt to shared symbol group: $SIFT_GATEWAY_SERVICE_GROUP"
    sudo_if_needed usermod -aG "$SIFT_GATEWAY_SERVICE_GROUP" "$rt"
  fi
}

configure_agent_runtime() {
  if [[ -z "${SIFT_EXECUTE_AS_USER:-}" || "${SIFT_EXECUTE_AS_USER}" == "__current__" ]]; then
    warn "execute.runtime_user disabled; run_command will execute as the gateway user. Use only for development."
    return 0
  fi

  if ! command -v setfacl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      log "Installing acl package for run_command native user isolation."
      apt_install_packages acl || true
    fi
  fi

  require_cmd setfacl
  require_cmd getfacl
  if ! command -v visudo >/dev/null 2>&1 && [[ ! -x /usr/sbin/visudo ]]; then
    die "Missing required command: visudo"
  fi

  log "Configuring run_command native user isolation: runtime=${SIFT_EXECUTE_AS_USER}, service=${SIFT_GATEWAY_SERVICE_USER}."
  sudo_if_needed "$REPO_DIR/scripts/setup-agent-runtime.sh" \
    --runtime-user "$SIFT_EXECUTE_AS_USER" \
    --service-user "$SIFT_GATEWAY_SERVICE_USER" \
    --cases-root "$SIFT_CASES_ROOT" \
    --state-root "$SIFT_STATE_DIR"
  # B-MVP-045: write_gateway_config (below, in main()) already sets
  # execute.runtime_user="${SIFT_EXECUTE_AS_USER}" in gateway.yaml programmatically.
  # Restate that here so the setup-agent-runtime.sh hint ("Set execute.runtime_user
  # ... in gateway.yaml") is not mistaken for an unfulfilled manual TODO: it is the
  # configured default; only a service restart (after ACL changes) is needed to apply.
  log "configured execute.runtime_user=${SIFT_EXECUTE_AS_USER} in gateway.yaml (restart applies after ACL changes)."
}

configure_ingest_mount_sudoers() {
  if ! command -v visudo >/dev/null 2>&1 && [[ ! -x /usr/sbin/visudo ]]; then
    die "Missing required command: visudo"
  fi
  log "Configuring forensic ingest mount sudoers for service user: ${SIFT_GATEWAY_SERVICE_USER}."
  sudo_if_needed "$REPO_DIR/scripts/setup-ingest-mount-sudoers.sh" \
    --service-user "$SIFT_GATEWAY_SERVICE_USER"
}

