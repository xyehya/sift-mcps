# shellcheck shell=bash
# =============================================================================
# lib/assets.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_ASSETS_SOURCED:-}" ]] && return 0
_SIFT_LIB_ASSETS_SOURCED=1

# Phase 4 — assets (triage DBs, RAG index, hayabusa, FUSE)
# =============================================================================

configure_fuse() {
  local fuse_conf="/etc/fuse.conf"
  if [[ -f "$fuse_conf" ]] && grep -q '^user_allow_other$' "$fuse_conf" 2>/dev/null; then
    log "FUSE user_allow_other already enabled."
    return
  fi
  log "Enabling user_allow_other in /etc/fuse.conf (forensic image mounting)."
  if [[ -f "$fuse_conf" ]]; then
    sudo_if_needed sed -i 's/^#\s*user_allow_other\b.*/user_allow_other/' "$fuse_conf"
    if ! grep -q '^user_allow_other$' "$fuse_conf"; then
      echo 'user_allow_other' | sudo_if_needed tee -a "$fuse_conf" >/dev/null
    fi
  else
    echo 'user_allow_other' | sudo_if_needed tee "$fuse_conf" >/dev/null
  fi
}

prepare_enrichment_assets() {
  # SIFT_ENRICHMENT_DIR is sift-service-owned 0755 (install_state_dirs); the
  # operator must create the symlink/subdir via sudo. The symlink target is the
  # world-readable repo data dir under /opt, which the service reads through it.
  log "Preparing enrichment asset pointers."
  if [[ -d "$REPO_DIR/packages/forensic-knowledge/data" ]]; then
    sudo_if_needed ln -sfn "$REPO_DIR/packages/forensic-knowledge/data" "$SIFT_ENRICHMENT_DIR/forensic-knowledge"
  else
    warn "forensic-knowledge data directory not found."
  fi
  sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$SIFT_ENRICHMENT_DIR/forensic-rag"
}

download_rag_index() {
  local rag_data_dir="$REPO_DIR/packages/forensic-rag-mcp/data"
  local chroma_dir="$rag_data_dir/chroma"

  if [[ -d "$chroma_dir" ]]; then
    log "RAG knowledge index already exists at $chroma_dir — preserving."
    return
  fi

  if is_offline; then
    warn "SIFT_OFFLINE=1: skipping RAG Chroma bundle download (legacy chroma path)."
    warn "  Stage the bundle at $chroma_dir, or use the default SIFT_RAG_IMPORT_SOURCE=direct path (bundled JSONL, no download)."
    return
  fi
  # B-MVP-004 (D4): pin the release tag (the bundle's internal SHA-256 file is
  # still verified by download_index.py) instead of resolving "latest".
  log "Downloading pre-built RAG knowledge index ${SIFT_RAG_INDEX_TAG} (22K+ records, ~1-3 GB)..."
  if "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads \
    python -m rag_mcp.scripts.download_index --dest "$rag_data_dir" --tag "$SIFT_RAG_INDEX_TAG"; then
    log "RAG knowledge index downloaded and verified."
  else
    warn "RAG knowledge index download FAILED."
    warn "  forensic-rag-mcp will start in degraded mode."
    warn "  Retry: python -m rag_mcp.scripts.download_index --tag $SIFT_RAG_INDEX_TAG"
  fi
}

import_rag_pgvector() {
  local rag_data_dir="$REPO_DIR/packages/forensic-rag-mcp/data"
  local chroma_dir="$rag_data_dir/chroma"
  local dsn="${SIFT_CONTROL_PLANE_DSN:-${DATABASE_URL:-${POSTGRES_DSN:-}}}"

  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  if [[ -z "$dsn" ]]; then
    warn "SIFT_CONTROL_PLANE_DSN is not set — skipping Supabase pgvector RAG import."
    warn "  Chroma RAG may be present, but kb_search_knowledge will use only existing pgvector rows."
    return 0
  fi
  if [[ ! -d "$chroma_dir" ]]; then
    warn "Chroma RAG index not found at $chroma_dir — skipping Supabase pgvector RAG import."
    warn "  Retry after download: rag-mcp-import-chroma-pgvector --chroma-dir '$chroma_dir'"
    return 0
  fi

  log "Importing downloaded RAG knowledge index into Supabase pgvector."
  if SIFT_CONTROL_PLANE_DSN="$dsn" "$UV_BIN" run --project "$REPO_DIR" --python "$SYSTEM_PYTHON" --no-managed-python --no-python-downloads \
    rag-mcp-import-chroma-pgvector --chroma-dir "$chroma_dir"; then
    log "Supabase pgvector RAG import completed."
  else
    warn "Supabase pgvector RAG import FAILED."
    warn "  Retry: SIFT_CONTROL_PLANE_DSN='<dsn>' rag-mcp-import-chroma-pgvector --chroma-dir '$chroma_dir'"
  fi
}

seed_rag_pgvector_direct() {
  local knowledge_dir="$REPO_DIR/packages/forensic-rag-mcp/knowledge"
  local dsn="${SIFT_CONTROL_PLANE_DSN:-${DATABASE_URL:-${POSTGRES_DSN:-}}}"

  if [[ -z "$dsn" ]]; then
    dsn="$(_env_file_value "$SIFT_HOME/control-plane.env" "SIFT_CONTROL_PLANE_DSN")"
  fi
  if [[ -z "$dsn" ]]; then
    warn "SIFT_CONTROL_PLANE_DSN is not set — skipping direct Supabase pgvector RAG seed."
    warn "  kb_search_knowledge will use only existing pgvector rows."
    return 0
  fi
  if [[ ! -d "$knowledge_dir" ]]; then
    warn "Bundled RAG knowledge directory not found at $knowledge_dir — skipping pgvector seed."
    return 0
  fi

  log "Seeding bundled RAG knowledge directly into Supabase pgvector."
  # B-MVP-015 / B-MVP-004 (D3): pin the model name + revision and use an explicit
  # HF_HOME under the service-home cache. In offline mode set HF_HUB_OFFLINE so
  # sentence-transformers loads only from the pre-staged cache and never reaches
  # Hugging Face Hub. SIFT_HF_HOME is created/owned sift-service in install_state_dirs.
  local hf_offline=0
  is_offline && hf_offline=1
  # Run the seed AS the gateway service user (not the installer), from a
  # service-traversable CWD, using the venv console script directly. Two
  # fresh-install failure modes this avoids (both observed during BATCH-LV1):
  #   1. the installer cannot write the sift-service-owned HF_HOME cache
  #      ([Errno 13] .../.cache/huggingface/hub);
  #   2. sentence-transformers probes the model id relative to CWD, and the
  #      installer's $HOME is not traversable by the service user
  #      ([Errno 13] 'BAAI/bge-base-en-v1.5/modules.json').
  # The service user owns HF_HOME and is the same identity that reads the model
  # cache at query time. Any operator-set proxy env is forwarded explicitly.
  local seed_bin="$REPO_DIR/.venv/bin/rag-mcp-seed-pgvector"
  local svc="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
  local as_svc=(); [[ "$(id -un)" != "$svc" ]] && as_svc=(sudo -u "$svc")
  if ( cd "$SIFT_STATE_DIR" && "${as_svc[@]}" env \
        SIFT_CONTROL_PLANE_DSN="$dsn" \
        RAG_MODEL_NAME="$SIFT_RAG_MODEL_NAME" \
        RAG_MODEL_REVISION="$SIFT_RAG_MODEL_REVISION" \
        HF_HOME="$SIFT_HF_HOME" \
        HF_HUB_OFFLINE="$hf_offline" \
        TRANSFORMERS_OFFLINE="$hf_offline" \
        http_proxy="${http_proxy:-}" https_proxy="${https_proxy:-}" \
        HTTP_PROXY="${HTTP_PROXY:-}" HTTPS_PROXY="${HTTPS_PROXY:-}" \
        no_proxy="${no_proxy:-}" NO_PROXY="${NO_PROXY:-}" \
        "$seed_bin" --knowledge-dir "$knowledge_dir" --embedding-mode model ); then
    log "Direct Supabase pgvector RAG seed completed."
  else
    warn "Direct Supabase pgvector RAG seed FAILED."
    if is_offline; then
      warn "  Offline mode: pre-stage the model cache at $SIFT_HF_HOME (revision $SIFT_RAG_MODEL_REVISION) from an internet-connected host."
    fi
    warn "  Retry: SIFT_CONTROL_PLANE_DSN='<dsn>' rag-mcp-seed-pgvector --knowledge-dir '$knowledge_dir' --embedding-mode model"
  fi
}

load_rag_pgvector() {
  # Default path: build embeddings from the bundled knowledge corpus directly
  # into Supabase pgvector. The legacy Chroma release bundle remains an explicit
  # compatibility/import path for old snapshots and larger prebuilt corpora.
  case "${SIFT_RAG_IMPORT_SOURCE:-direct}" in
    direct)
      seed_rag_pgvector_direct
      ;;
    chroma)
      download_rag_index
      import_rag_pgvector
      ;;
    *)
      warn "Unknown SIFT_RAG_IMPORT_SOURCE='${SIFT_RAG_IMPORT_SOURCE}' — expected direct or chroma; using direct."
      seed_rag_pgvector_direct
      ;;
  esac
}

install_hayabusa() {
  log "Installing hayabusa detection engine."
  # binary_dir/rules_dir live under SIFT_HOME (sift-service-owned 0700). The
  # operator downloads/extracts into an operator temp, then installs the artifacts
  # owned sift-service so the service (and run_command via the runtime user, which
  # invokes the system-wide /usr/local/bin/hayabusa symlink) can execute them.
  local binary_dir="$SIFT_HOME/bin"
  local rules_dir="$SIFT_HOME/hayabusa-rules"

  if sudo_if_needed test -x "$binary_dir/hayabusa"; then
    log "hayabusa already installed (preserving $binary_dir/hayabusa)."
    return
  fi

  require_cmd unzip

  # B-MVP-004 (D2): pin the Hayabusa release tag + SHA-256 of the lin-x64-gnu zip
  # instead of resolving "latest". Upstream publishes no checksum file, so the
  # hash is pinned in this script (SIFT_HAYABUSA_SHA256) like the Supabase CLI.
  local tag="$SIFT_HAYABUSA_TAG"
  local asset="hayabusa-${tag#v}-lin-x64-gnu.zip"
  local url="https://github.com/Yamato-Security/hayabusa/releases/download/${tag}/${asset}"

  if is_offline; then
    warn "SIFT_OFFLINE=1: skipping hayabusa download. Detection will be unavailable until staged."
    warn "  Stage offline: place the hayabusa binary at $binary_dir/hayabusa (and rules at $rules_dir),"
    warn "  or pre-download $asset and extract it there, then re-run ./install.sh."
    return
  fi

  log "Downloading hayabusa ${tag} (pinned)..."
  local tmpd
  tmpd="$(mktemp -d)"

  if ! curl -fsSL -o "$tmpd/$asset" "$url"; then
    warn "hayabusa download failed.  Detection will be unavailable."
    rm -rf "$tmpd"
    return
  fi

  # SHA-256 pin is a hard gate: a mismatch means the pinned artifact changed
  # upstream (or was tampered with). Refuse to install rather than run an
  # unverified detection binary.
  if ! verify_sha256 "$tmpd/$asset" "$SIFT_HAYABUSA_SHA256"; then
    warn "hayabusa ${tag} failed SHA-256 verification — refusing to install (supply-chain guard)."
    warn "  If you intentionally bumped the pin, set SIFT_HAYABUSA_TAG and SIFT_HAYABUSA_SHA256."
    rm -rf "$tmpd"
    return
  fi
  log "  hayabusa SHA-256 verified."

  if ! file "$tmpd/$asset" | grep -q 'Zip archive'; then
    warn "hayabusa download was not a valid ZIP.  Detection will be unavailable."
    rm -rf "$tmpd"
    return
  fi

  unzip -qo "$tmpd/$asset" -d "$tmpd/extracted"
  local extracted
  extracted=$(find "$tmpd/extracted" -name 'hayabusa-*' -type f | head -1)
  if [[ -z "$extracted" ]]; then
    warn "Could not find hayabusa binary in archive."
    rm -rf "$tmpd"
    return
  fi

  sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$binary_dir"
  svc_install_file "$extracted" "$binary_dir/hayabusa" 755
  log "hayabusa installed: $(sudo_if_needed "$binary_dir/hayabusa" help 2>&1 | head -1)"

  if [[ -d "$tmpd/extracted/rules" ]]; then
    sudo_if_needed rm -rf "$rules_dir"
    sudo_if_needed cp -r "$tmpd/extracted/rules" "$rules_dir"
    sudo_if_needed chown -R "$SIFT_GATEWAY_SERVICE_USER:$SIFT_GATEWAY_SERVICE_USER" "$rules_dir"
    log "hayabusa rules installed: $(sudo_if_needed find "$rules_dir" -name '*.yml' | wc -l) YAML files"
  else
    warn "Bundled rules not found in release archive."
  fi
  rm -rf "$tmpd"
}

install_hayabusa_system_links() {
  local binary="$SIFT_HOME/bin/hayabusa"
  sudo_if_needed test -x "$binary" || return 0
  sudo_if_needed ln -sfn "$binary" /usr/local/bin/hayabusa 2>/dev/null || true
}

report_hayabusa_status() {
  # XYE-26: emit a clear post-install STATUS line for Hayabusa so the operator
  # knows whether Sigma detection will run, without changing any download logic.
  local binary="$SIFT_HOME/bin/hayabusa"
  local rules_dir="$SIFT_HOME/hayabusa-rules"
  if sudo_if_needed test -x "$binary"; then
    local rules_count=0
    if sudo_if_needed test -d "$rules_dir"; then
      rules_count="$(sudo_if_needed find "$rules_dir" -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"
    fi
    log "STATUS hayabusa: installed at $binary (rules: ${rules_count} *.yml under $rules_dir). Sigma detection will run during evtx ingest."
  else
    warn "STATUS hayabusa: NOT installed. evtx ingest will index logs but SKIP Sigma detection."
    warn "  Stage offline: place the binary at $binary (and rules at $rules_dir), then re-run ./install.sh;"
    warn "  or re-run ./install.sh online to download the pinned release."
  fi
}

# Emit one dotnet wrapper for a single EZ Tool .dll into $bindir/<Tool>.
# $1 = the .dll path (e.g. /opt/zimmermantools/MFTECmd.dll), $2 = target bin dir.
# Idempotent: if $bindir/<Tool> already exists (the SANS image ships its own
# wrappers), this is a no-op. Echoes "created" / "exists" / "" (skipped) so the
# caller can count. Never fatal.
_zimmerman_emit_wrapper() {
  local dll="$1" bindir="$2"
  local base tool wrapper tmp
  base="$(basename "$dll")"        # e.g. MFTECmd.dll
  tool="${base%.dll}"              # e.g. MFTECmd
  [[ -n "$tool" ]] || { echo ""; return 0; }
  wrapper="$bindir/$tool"
  # Idempotent: a pre-existing entry (SANS-image wrapper or a prior run) wins.
  if sudo_if_needed test -e "$wrapper"; then
    echo "exists"
    return 0
  fi
  # The EZ Tools are .NET assemblies; the canonical SANS wrapper is a tiny
  # bash shim that execs `dotnet <Tool>.dll "$@"`. We mirror that exactly so a
  # bare install (no SANS wrappers) still gets <Tool> on PATH for run_command.
  # Build in an operator-owned temp, then install atomically as root mode 0755.
  tmp="$(mktemp)"
  {
    printf '#!/bin/bash\n'
    # SC2016: the single-quoted string is a printf FORMAT spec, not a value to
    # expand — `%q` shell-quotes "$dll" into it, and "${@}" is literal text we
    # want written verbatim into the generated wrapper. Single quotes are correct.
    # shellcheck disable=SC2016
    printf 'exec dotnet %q "${@}"\n' "$dll"
  } > "$tmp"
  if sudo_if_needed install -m 0755 "$tmp" "$wrapper" 2>/dev/null; then
    rm -f "$tmp"
    echo "created"
  else
    rm -f "$tmp"
    echo ""
  fi
}

install_zimmerman_symlinks() {
  # Zimmerman EZ Tools are installed at /opt/zimmermantools by the SANS image as
  # .NET assemblies: <Tool>.dll + <Tool>.exe + <Tool>.runtimeconfig.json. The
  # working /usr/local/bin/<Tool> entries are bash wrappers that `dotnet`-run the
  # .dll. On the OFFICIAL SANS image those wrappers already exist; on a BARE
  # install they may be absent. We make each <Tool> available on PATH for
  # run_command by emitting the dotnet wrapper for every *.dll that lacks one.
  # Idempotent: a tool that already has a /usr/local/bin entry is skipped, so a
  # re-run (or the SANS-provided wrappers) is a clean no-op.
  #
  # (Rewrite, not removal: the old body linked /opt/zimmermantools/<Tool> as if
  # the tools were native ELF binaries — they are not, so it matched nothing and
  # logged "no known EZ Tool binaries found." This is the bare-SIFT install
  # track where the SANS wrappers can be missing, so emitting wrappers is real
  # work, not dead code.)
  local zimmerman_dir="/opt/zimmermantools"
  local bindir="/usr/local/bin"
  if ! sudo_if_needed test -d "$zimmerman_dir"; then
    log "Zimmerman tools not found at $zimmerman_dir — skipping EZ Tool wrappers."
    return 0
  fi
  if ! command -v dotnet >/dev/null 2>&1; then
    warn "Zimmerman EZ Tools present at $zimmerman_dir but 'dotnet' is not on PATH —"
    warn "  cannot create runnable wrappers. Install the .NET runtime, then re-run ./install.sh."
    return 0
  fi
  local created=0 existing=0 dll result
  # Discover .dll assemblies at the top level of /opt/zimmermantools (the SANS
  # layout). NUL-delimited so spaces in names are safe; sudo because the dir may
  # not be operator-readable.
  while IFS= read -r -d '' dll; do
    result="$(_zimmerman_emit_wrapper "$dll" "$bindir")"
    case "$result" in
      created) created=$((created + 1)) ;;
      exists)  existing=$((existing + 1)) ;;
    esac
  done < <(sudo_if_needed find "$zimmerman_dir" -maxdepth 1 -type f -name '*.dll' -print0 2>/dev/null)

  if [[ "$created" -gt 0 || "$existing" -gt 0 ]]; then
    log "Zimmerman EZ Tools: $created wrapper(s) created, $existing already present under $bindir (from $zimmerman_dir/*.dll)."
  else
    log "Zimmerman tools dir exists but contains no *.dll EZ Tool assemblies — nothing to wrap."
  fi

  # Best-effort: repair a dangling /usr/local/bin/hayabusa symlink left by a
  # prior layout. If /opt/hayabusa/hayabusa exists and the system link is
  # broken (points nowhere), repoint it at the real binary. Never fails.
  if [[ -x /opt/hayabusa/hayabusa ]]; then
    if [[ -L /usr/local/bin/hayabusa && ! -e /usr/local/bin/hayabusa ]]; then
      sudo_if_needed ln -sfn /opt/hayabusa/hayabusa /usr/local/bin/hayabusa 2>/dev/null || true
      log "Repointed dangling /usr/local/bin/hayabusa symlink at /opt/hayabusa/hayabusa."
    fi
  fi
}

# Best-effort install of complementary forensic CLIs that the default SANS SIFT
# image ships only as libraries (no CLI). Each add is independently guarded:
# a failure only warns and continues. The default install MUST still succeed if
# every one of these fails — never `die` here.
# Helper: emit the actionable "still missing" advisory for a complementary CLI
# that we could not (or did not) install, so a skip is NEVER a silent success.
# $1 = package/command name, $2 = reason fragment.
_complementary_missing_advisory() {
  local pkg="$1" reason="$2"
  warn "  $pkg NOT installed ($reason) — the agent will run WITHOUT it."
  warn "    Add it later with: sudo apt-get install -y $pkg"
}

install_complementary_tools() {
  # Verify/repair the complementary forensic CLIs that the stock SANS SIFT image
  # ships only as libraries (no CLI): yara, tshark, binwalk. Idempotent — a tool
  # already on PATH is left untouched. Best-effort: a failure or a skip (offline,
  # apt unavailable, apt failure) only WARNS with an actionable advisory and
  # continues; the default install MUST still succeed. Never `die` here.
  local pkgs=(yara tshark binwalk)
  local pkg
  local missing=()
  for pkg in "${pkgs[@]}"; do
    if command -v "$pkg" >/dev/null 2>&1; then
      log "  $pkg already present — skipping."
    else
      missing+=("$pkg")
    fi
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "Complementary forensic CLIs all present (yara, tshark, binwalk) — nothing to do."
  else
    # Offline: never reach the network. Emit a clear, actionable advisory naming
    # exactly what is missing and how to add it, then continue (non-fatal).
    if is_offline; then
      warn "Complementary forensic tools: SIFT_OFFLINE=1 — NOT installing ${missing[*]}."
      for pkg in "${missing[@]}"; do
        _complementary_missing_advisory "$pkg" "offline mode"
      done
    elif ! command -v apt-get >/dev/null 2>&1; then
      warn "Complementary forensic tools: apt-get unavailable — cannot install ${missing[*]}."
      for pkg in "${missing[@]}"; do
        _complementary_missing_advisory "$pkg" "apt-get unavailable"
      done
    else
      log "Installing complementary forensic CLIs (best-effort): ${missing[*]}."
      # tshark pulls in wireshark-common, whose postinst opens an interactive
      # debconf prompt ("allow non-superusers to capture?") that hangs a
      # non-interactive install. Pre-seed the answer (false = no setuid dumpcap;
      # the forensic agent reads PCAPs, it does not live-capture). Best-effort.
      for pkg in "${missing[@]}"; do
        if [[ "$pkg" == "tshark" ]]; then
          echo "wireshark-common wireshark-common/install-setuid boolean false" \
            | sudo_if_needed debconf-set-selections 2>/dev/null || true
        fi
      done
      # Refresh indexes ONCE (not once per package), best-effort: a failing
      # third-party apt source must not abort the run; fall back to existing
      # indexes. Then install per-package so one unavailable package does not
      # block the others (`apt-get install -y a b c` is all-or-nothing).
      if ! sudo_if_needed apt-get update; then
        warn "  apt-get update failed (likely an unrelated third-party source) — continuing with existing indexes."
      fi
      for pkg in "${missing[@]}"; do
        if sudo_if_needed env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"; then
          log "  installed $pkg."
        else
          _complementary_missing_advisory "$pkg" "best-effort apt install failed"
        fi
      done
    fi
  fi

  # zeek has no apt candidate on the stock SIFT image — advisory-only, never fail.
  if ! command -v zeek >/dev/null 2>&1; then
    warn "  zeek not present and has no default apt candidate — skipping (install from the Zeek repo if needed)."
  fi
  return 0
}
