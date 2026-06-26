# shellcheck shell=bash
# =============================================================================
# lib/python.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_PYTHON_SOURCED:-}" ]] && return 0
_SIFT_LIB_PYTHON_SOURCED=1

# =============================================================================
# Phase 1 — uv (Python package manager)
# =============================================================================

resolve_uv() {
  if command -v uv >/dev/null 2>&1; then command -v uv; return; fi
  if [[ -x "$HOME/.local/bin/uv" ]]; then echo "$HOME/.local/bin/uv"; return; fi
  echo ""
}

install_uv_if_needed() {
  local uv_bin
  uv_bin="$(resolve_uv)"
  if [[ -n "$uv_bin" ]]; then
    log "uv found: $uv_bin"
    UV_BIN="$uv_bin"
    return
  fi
  if is_offline; then
    offline_die "uv ${SIFT_UV_VERSION}" \
      "pre-install uv via your OS package manager or place the uv binary on PATH (e.g. ~/.local/bin/uv) before re-running ./install.sh"
  fi
  require_cmd curl
  # B-MVP-004 (D1) / #17: pin uv to a specific version and SHA-256-verify the
  # per-arch release tarball BEFORE installing. Every install path is hash-gated;
  # there is NO pipe-to-shell fallback on any arch. An arch without a pinned,
  # verified hash fails CLOSED (supply-chain guard — fail-closed beats fail-open).
  log "Installing uv ${SIFT_UV_VERSION} (pinned, SHA-256-verified)."

  # Resolve this arch to its uv release triple + the ledger var holding the
  # pinned, upstream-published SHA-256 for that triple. Unsupported arch dies.
  local arch triple expected_sha
  arch="$(uname -m 2>/dev/null || echo unknown)"
  case "$arch" in
    x86_64 | amd64)
      triple="uv-x86_64-unknown-linux-gnu"
      expected_sha="$SIFT_UV_TARBALL_SHA256"
      ;;
    aarch64 | arm64)
      triple="uv-aarch64-unknown-linux-gnu"
      expected_sha="$SIFT_UV_TARBALL_SHA256_AARCH64"
      ;;
    *)
      die "uv: unsupported CPU architecture '${arch}'. No SHA-256-pinned uv tarball is configured for it, and unhashed installs are refused (supply-chain guard). Pre-install uv via your OS package manager / place the uv binary on PATH (e.g. ~/.local/bin/uv), or set SIFT_UV_TARBALL_SHA256_$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]') to the upstream-published checksum for '${triple:-uv-${arch}-unknown-linux-gnu}' and re-run ./install.sh."
      ;;
  esac

  # Refuse to fetch when the ledger var for this arch is empty — fail closed
  # rather than download something we cannot verify.
  if [[ -z "$expected_sha" ]]; then
    die "uv: no pinned SHA-256 for arch '${arch}' (${triple}). Refusing to fetch an unverifiable tarball (supply-chain guard). Set SIFT_UV_TARBALL_SHA256_$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]') to the upstream-published checksum and re-run ./install.sh."
  fi

  local tmpd tarball
  tmpd="$(mktemp -d)"
  tarball="$tmpd/${triple}.tar.gz"
  if ! curl -fsSL -o "$tarball" \
      "https://github.com/astral-sh/uv/releases/download/${SIFT_UV_VERSION}/${triple}.tar.gz"; then
    rm -rf "$tmpd"
    die "uv: failed to download ${triple}.tar.gz for ${SIFT_UV_VERSION}. Check network connectivity or pre-install uv on PATH."
  fi
  if ! verify_sha256 "$tarball" "$expected_sha"; then
    rm -rf "$tmpd"
    die "uv ${SIFT_UV_VERSION} (${triple}) tarball failed SHA-256 verification — refusing to install (supply-chain guard). If you intentionally bumped the pin, set the matching SIFT_UV_TARBALL_SHA256[_<ARCH>] to the upstream-published checksum."
  fi
  log "  uv tarball SHA-256 verified (${triple})."
  mkdir -p "$HOME/.local/bin"
  tar -xzf "$tarball" -C "$tmpd"
  local uv_extracted
  uv_extracted="$(find "$tmpd" -type f -name uv | head -1)"
  if [[ -n "$uv_extracted" ]]; then
    install -m 755 "$uv_extracted" "$HOME/.local/bin/uv"
  fi
  rm -rf "$tmpd"

  uv_bin="$(resolve_uv)"
  [[ -n "$uv_bin" ]] || die "uv install completed but uv binary not found."
  UV_BIN="$uv_bin"
}


# =============================================================================
# Phase 2 — venv integrity + sync
# =============================================================================

_venv_python_version() {
  "$VENV_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "none"
}

_ensure_venv_integrity() {
  # Returns 0 if the venv exists, uses the system Python, and is import-healthy.
  if [[ ! -x "$VENV_PYTHON" ]]; then
    log "No venv found at $VENV_DIR — will create."
    return 1
  fi
  local sys_ver venv_ver
  sys_ver=$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  venv_ver=$(_venv_python_version)
  if [[ "$venv_ver" != "$sys_ver" ]]; then
    warn "Venv Python ($venv_ver) ≠ system Python ($sys_ver) — rebuilding venv."
    rm -rf "$VENV_DIR"
    return 1
  fi
  # Quick import-smoke of a core package to catch half-baked venvs
  if ! "$VENV_PYTHON" -c 'import yaml' 2>/dev/null; then
    warn "Venv import smoke test failed — will repair via sync."
    return 1
  fi
  log "Venv integrity OK (Python $venv_ver)."
  return 0
}

sync_workspace() {
  log "Syncing workspace (system Python: $SYSTEM_PYTHON)."
  export UV_PYTHON="$SYSTEM_PYTHON"
  export UV_NO_MANAGED_PYTHON=1
  export UV_PYTHON_DOWNLOADS=never

  # Default --extra full (OpenSearch + RAG knowledge are native forensic
  # capabilities). core-only installs use --extra core (gateway + portal +
  # in-process core tools only). External add-ons such as OpenCTI are never
  # pulled by the native installer; scripts/setup-addon.sh requests their extras
  # explicitly when an operator prepares them.
  local sync_extra="full"
  [[ "${SIFT_CORE_ONLY:-0}" == "1" ]] && sync_extra="core"
  log "Workspace extra: $sync_extra"
  "$UV_BIN" sync \
    --extra "$sync_extra" \
    --project "$REPO_DIR" \
    --python "$SYSTEM_PYTHON" \
    --no-managed-python \
    --no-python-downloads

  # Post-sync: verify the venv can import critical packages
  log "Verifying venv baseline imports."
  local ok=1
  for pkg in yaml mcp sift_core sift_gateway case_dashboard; do
    if ! "$VENV_PYTHON" -c "import $pkg" 2>/dev/null; then
      warn "Post-sync import of '$pkg' failed — workspace may be incomplete."
      ok=0
    fi
  done
  if [[ "$ok" -eq 0 ]]; then
    warn "Some imports failed.  Attempting one retry with --reinstall..."
    "$UV_BIN" sync \
      --extra "$sync_extra" \
      --project "$REPO_DIR" \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python \
      --no-python-downloads \
      --reinstall 2>/dev/null || warn "Retry sync also had issues — check network."
  fi
  log "Workspace sync complete."
}

repair_pyewf_venv_link() {
  [[ -x "$VENV_PYTHON" ]] || return 0
  if "$VENV_PYTHON" -c 'import pyewf' >/dev/null 2>&1; then
    log "pyewf import OK in venv."
    return 0
  fi

  local pyewf_origin
  pyewf_origin="$("$SYSTEM_PYTHON" - <<'PY' 2>/dev/null || true
import importlib.util
spec = importlib.util.find_spec("pyewf")
print(spec.origin if spec and spec.origin else "")
PY
)"
  if [[ -z "$pyewf_origin" || ! -e "$pyewf_origin" ]]; then
    warn "pyewf is not importable from system Python; install python3-libewf/libewf bindings if EWF tooling needs pyewf."
    return 0
  fi

  local site_dir
  site_dir="$("$VENV_PYTHON" - <<'PY'
import site
paths = site.getsitepackages()
print(paths[0] if paths else "")
PY
)"
  if [[ -z "$site_dir" || ! -d "$site_dir" ]]; then
    warn "Could not locate venv site-packages for pyewf relink."
    return 0
  fi

  ln -sfn "$pyewf_origin" "$site_dir/$(basename "$pyewf_origin")"
  if "$VENV_PYTHON" -c 'import pyewf' >/dev/null 2>&1; then
    log "Linked system pyewf into venv: $pyewf_origin"
  else
    warn "pyewf relink did not make pyewf importable in the venv."
  fi
}
