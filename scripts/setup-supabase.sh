#!/usr/bin/env bash
# setup-supabase.sh — Supabase CLI-based bring-up for the SIFT VM.
#
# Uses the official Supabase CLI (`supabase start`) to provision:
#   db (postgres 15) + auth (gotrue) + api (kong)
# Disabled: studio, inbucket, storage, realtime, edge_runtime, analytics.
#
# On success writes $HOME/.sift/supabase-project/sift-supabase.env (chmod 600):
#   export SUPABASE_URL=http://127.0.0.1:54321
#   export SUPABASE_ANON_KEY=<from CLI>
#   export SUPABASE_SERVICE_ROLE_KEY=<from CLI>
#   export SIFT_CONTROL_PLANE_DSN=postgresql://postgres:postgres@127.0.0.1:54322/postgres
#
# Usage:
#   ./scripts/setup-supabase.sh            # idempotent bring-up
#   ./scripts/setup-supabase.sh --reset    # supabase db reset (prompt)
#   ./scripts/setup-supabase.sh --reset --yes   # no prompt
#   ./scripts/setup-supabase.sh --stop     # supabase stop (keep data)
#
# After success:
#   source ~/.sift/supabase-project/sift-supabase.env
#   ./install.sh
#
set -Eeuo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
# Pinned Supabase CLI version (linux amd64 standalone binary).
# Tarball: https://github.com/supabase/cli/releases/download/v2.105.0/supabase_2.105.0_linux_amd64.tar.gz
SUPABASE_CLI_VERSION="2.105.0"
SUPABASE_CLI_URL="https://github.com/supabase/cli/releases/download/v${SUPABASE_CLI_VERSION}/supabase_${SUPABASE_CLI_VERSION}_linux_amd64.tar.gz"
SUPABASE_CLI_SHA256="11ac4410c11e8b03f0cc7fd9316d68146695b0e06115a0663364b07e7feb6db8"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${SIFT_SUPABASE_PROJECT_DIR:-$HOME/.sift/supabase-project}"
OUT_ENV_FILE="$OUT_DIR/sift-supabase.env"
SIFT_BIN_DIR="${SIFT_BIN_DIR:-$HOME/.sift/bin}"

# ── Helpers ──────────────────────────────────────────────────────────────────
log()  { printf '[setup-supabase] %s\n' "$*"; }
warn() { printf '[setup-supabase] WARNING: %s\n' "$*" >&2; }
die()  { printf '[setup-supabase] FATAL: %s\n' "$*" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
DO_RESET=0
DO_STOP=0
RESET_YES=0
for arg in "$@"; do
  case "$arg" in
    --reset)        DO_RESET=1 ;;
    --stop)         DO_STOP=1 ;;
    -y|--yes)       RESET_YES=1 ;;
    --help|-h)
      sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0
      ;;
    *) die "Unknown argument: $arg  (use --reset [--yes], --stop, or --help)" ;;
  esac
done

# ── Preconditions ─────────────────────────────────────────────────────────────
check_deps() {
  log "Checking prerequisites..."

  if ! command -v docker >/dev/null 2>&1; then
    die "docker not found. Install Docker Engine: https://docs.docker.com/engine/install/"
  fi

  if ! docker compose version >/dev/null 2>&1; then
    die "docker compose plugin not found (need v2). Run: sudo apt-get install docker-compose-plugin"
  fi

  if ! docker ps >/dev/null 2>&1; then
    log "Docker daemon is not reachable — attempting: sudo systemctl start docker"
    sudo systemctl start docker 2>/dev/null || true
    sleep 2
  fi

  if ! docker ps >/dev/null 2>&1; then
    cat >&2 <<'DOCKERERR'
[setup-supabase] FATAL: Docker daemon is not reachable.
  Possible causes:
    1. Docker is not running:        sudo systemctl start docker
    2. User not in docker group:     sudo usermod -aG docker $USER
                                     newgrp docker   (or log out and back in)
    3. On SIFT VM, run as the target user (not root) after the group is added.
DOCKERERR
    exit 1
  fi

  log "Prerequisites OK."
}

# ── Supabase CLI install / path ────────────────────────────────────────────────
resolve_supabase_cli() {
  # 1. Already on PATH at the right version?
  if command -v supabase >/dev/null 2>&1; then
    local supabase_path supabase_dir
    supabase_path="$(command -v supabase)"
    supabase_dir="$(dirname "$supabase_path")"
    local ver
    ver="$(supabase --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [[ "$ver" == "$SUPABASE_CLI_VERSION" && -x "$supabase_dir/supabase-go" ]]; then
      log "supabase CLI v${SUPABASE_CLI_VERSION} already on PATH."
      return
    fi
    if [[ "$ver" == "$SUPABASE_CLI_VERSION" ]]; then
      warn "supabase CLI on PATH is v${SUPABASE_CLI_VERSION}, but sibling supabase-go is missing. Reinstalling pinned package."
    else
      warn "supabase CLI on PATH is v${ver:-unknown}; need v${SUPABASE_CLI_VERSION}. Installing pinned version."
    fi
  fi

  # 2. Already installed in our bin dir?
  if [[ -x "$SIFT_BIN_DIR/supabase" && -x "$SIFT_BIN_DIR/supabase-go" ]]; then
    local ver
    ver="$("$SIFT_BIN_DIR/supabase" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [[ "$ver" == "$SUPABASE_CLI_VERSION" ]]; then
      log "supabase CLI v${SUPABASE_CLI_VERSION} found at $SIFT_BIN_DIR/supabase."
      export PATH="$SIFT_BIN_DIR:$PATH"
      return
    fi
  fi

  # 3. Download the pinned standalone binary.
  install_supabase_cli
  export PATH="$SIFT_BIN_DIR:$PATH"
}

install_supabase_cli() {
  log "Installing Supabase CLI v${SUPABASE_CLI_VERSION} to $SIFT_BIN_DIR ..."

  # Try /usr/local/bin first (requires sudo); fall back to ~/.sift/bin.
  local install_dir="$SIFT_BIN_DIR"
  if sudo -n true 2>/dev/null; then
    install_dir="/usr/local/bin"
  fi
  mkdir -p "$SIFT_BIN_DIR"

  if ! command -v curl >/dev/null 2>&1; then
    die "curl not found. Install with: sudo apt-get install curl"
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmpdir'" EXIT

  log "  Downloading: $SUPABASE_CLI_URL"
  curl -fsSL -o "$tmpdir/supabase.tar.gz" "$SUPABASE_CLI_URL" \
    || die "Download failed. Check network connectivity or try again."

  # Verify SHA256 if sha256sum is available (advisory check — not blocking on mismatch
  # since the pinned hash may differ across architectures; treat mismatch as warning).
  if command -v sha256sum >/dev/null 2>&1; then
    local actual
    actual="$(sha256sum "$tmpdir/supabase.tar.gz" | awk '{print $1}')"
    if [[ "$actual" == "$SUPABASE_CLI_SHA256" ]]; then
      log "  SHA256 verified."
    else
      warn "  SHA256 mismatch (expected $SUPABASE_CLI_SHA256, got $actual)."
      warn "  This is expected if the pinned hash in this script is stale or the architecture"
      warn "  differs.  Continuing — verify manually if this is a production install."
    fi
  fi

  tar -xzf "$tmpdir/supabase.tar.gz" -C "$tmpdir"

  # The platform package contains two colocated binaries: supabase (shim) and
  # supabase-go (Go CLI). Install both into the SAME directory; moving only the
  # shim breaks `supabase start`.
  local bin_path go_bin_path
  bin_path="$(find "$tmpdir" -type f -name 'supabase' | head -1)"
  [[ -n "$bin_path" ]] || die "supabase binary not found in tarball."
  go_bin_path="$(find "$tmpdir" -type f -name 'supabase-go' | head -1)"
  [[ -n "$go_bin_path" ]] || die "supabase-go binary not found in tarball."

  if [[ "$install_dir" == "/usr/local/bin" ]]; then
    sudo install -m 755 "$bin_path" "$install_dir/supabase"
    sudo install -m 755 "$go_bin_path" "$install_dir/supabase-go"
    log "  Installed to /usr/local/bin/supabase + /usr/local/bin/supabase-go (via sudo)."
  else
    install -m 755 "$bin_path" "$install_dir/supabase"
    install -m 755 "$go_bin_path" "$install_dir/supabase-go"
    log "  Installed to $install_dir/supabase + $install_dir/supabase-go."
    log "  Tip: add $install_dir to your PATH permanently (e.g. in ~/.bashrc):"
    log "    export PATH=\"$install_dir:\$PATH\""
  fi

  trap - EXIT
  rm -rf "$tmpdir"
}

# ── Ensure config.toml exists ─────────────────────────────────────────────────
ensure_config_toml() {
  local config_toml="$REPO_DIR/supabase/config.toml"
  if [[ -f "$config_toml" ]]; then
    log "supabase/config.toml already present."
    return
  fi

  # This should not happen — the file is checked into the repo.
  # If it's missing, run `supabase init` without clobbering migrations.
  warn "supabase/config.toml not found. Running 'supabase init' to create it."
  warn "Existing migrations/ directory will be preserved."

  # supabase init exits non-zero if config.toml already exists; we already
  # checked it doesn't exist above, so this is safe.
  (cd "$REPO_DIR" && supabase init --workdir supabase) \
    || die "'supabase init' failed. Run manually from $REPO_DIR: supabase init"

  # Paranoia: ensure migrations were not touched.
  if [[ -d "$REPO_DIR/supabase/migrations" ]]; then
    log "Migrations directory preserved."
  fi
}

# ── Bring up the stack ────────────────────────────────────────────────────────
supabase_start() {
  log "Starting Supabase stack (supabase start) — this may take a few minutes on first run..."
  log "  Working dir: $REPO_DIR"
  log "  Postgres: supabase/postgres:15.8.1.085 (major_version=15 in config.toml)"
  log "  GoTrue:   CLI-managed (jwt_expiry=172800 in config.toml)"
  log "  Kong:     CLI-managed (routes /auth/v1/* to GoTrue)"
  log "  Disabled: studio, inbucket, storage, realtime, edge_runtime, analytics"

  # Defense-in-depth network isolation: put ALL Supabase containers on ONE
  # dedicated docker network whose published ports bind to 127.0.0.1 only.
  # `--network-id` attaches every CLI-managed container to this single network,
  # so they share inter-container DNS (db/auth/kong reach each other) while
  # nothing is exposed beyond loopback.
  local net_id="${SIFT_SUPABASE_NETWORK:-sift-supabase-local}"
  if ! docker network inspect "$net_id" >/dev/null 2>&1; then
    docker network create -o 'com.docker.network.bridge.host_binding_ipv4=127.0.0.1' "$net_id" \
      || die "Failed to create docker network '$net_id'."
    log "  Created loopback-bound docker network: $net_id"
  else
    log "  Reusing docker network: $net_id"
  fi

  # `supabase start` is idempotent: if already running, it prints status and exits 0.
  (cd "$REPO_DIR" && supabase start --network-id "$net_id") \
    || die "'supabase start' failed. Check: supabase status  /  docker ps  /  docker logs"
}

# ── Capture credentials ───────────────────────────────────────────────────────
capture_credentials() {
  log "Capturing credentials from 'supabase status'..."

  local status_output
  status_output="$(cd "$REPO_DIR" && supabase status -o env 2>/dev/null)" \
    || status_output="$(cd "$REPO_DIR" && supabase status 2>/dev/null)" \
    || die "'supabase status' failed. Is the stack running? Try: supabase start"

  # Parse env-format output.  Key names emitted by the CLI:
  #   API_URL, ANON_KEY, SERVICE_ROLE_KEY, DB_URL, STUDIO_URL, etc.
  local api_url anon_key service_key db_url
  api_url="$(printf '%s\n' "$status_output"       | grep -E '^API_URL='          | cut -d= -f2- | tr -d '"' || true)"
  anon_key="$(printf '%s\n' "$status_output"      | grep -E '^ANON_KEY='         | cut -d= -f2- | tr -d '"' || true)"
  service_key="$(printf '%s\n' "$status_output"   | grep -E '^SERVICE_ROLE_KEY=' | cut -d= -f2- | tr -d '"' || true)"
  db_url="$(printf '%s\n' "$status_output"        | grep -E '^DB_URL='           | cut -d= -f2- | tr -d '"' || true)"

  # Fallbacks: if `supabase status -o env` was not available (older CLI), parse human output.
  if [[ -z "$api_url" ]]; then
    api_url="$(printf '%s\n' "$status_output"     | grep -oE 'http://127\.0\.0\.1:[0-9]+' | head -1 || true)"
  fi
  if [[ -z "$anon_key" ]]; then
    anon_key="$(printf '%s\n' "$status_output"    | grep -A1 -i 'anon key'       | tail -1 | awk '{print $NF}' || true)"
  fi
  if [[ -z "$service_key" ]]; then
    service_key="$(printf '%s\n' "$status_output" | grep -A1 -i 'service_role'   | tail -1 | awk '{print $NF}' || true)"
  fi

  if [[ -z "$api_url" || -z "$anon_key" || -z "$service_key" ]]; then
    warn "Could not fully parse 'supabase status' output. Raw output:"
    printf '%s\n' "$status_output" >&2
    die "Could not extract API_URL, ANON_KEY, or SERVICE_ROLE_KEY. See output above."
  fi

  # The CLI always binds to 127.0.0.1; normalise to the expected URL.
  # Default API port is 54321 (config.toml [api] port).
  SUPABASE_URL="${api_url:-http://127.0.0.1:54321}"
  SUPABASE_ANON_KEY="$anon_key"
  SUPABASE_SERVICE_ROLE_KEY="$service_key"

  # DB_URL from status is the full DSN; if absent, build it from known defaults.
  if [[ -n "$db_url" ]]; then
    SIFT_CONTROL_PLANE_DSN="$db_url"
  else
    SIFT_CONTROL_PLANE_DSN="postgresql://postgres:postgres@127.0.0.1:54322/postgres"
  fi
}

# ── Write output env file ─────────────────────────────────────────────────────
write_output_env() {
  mkdir -p "$OUT_DIR"
  install -m 600 /dev/null "$OUT_ENV_FILE"
  cat > "$OUT_ENV_FILE" <<OUTENV
# Source this file before running ./install.sh
# Generated by setup-supabase.sh from 'supabase status'.
# Re-generated on every successful run — do not edit manually.
export SUPABASE_URL=${SUPABASE_URL}
export SUPABASE_ANON_KEY=${SUPABASE_ANON_KEY}
export SUPABASE_SERVICE_ROLE_KEY=${SUPABASE_SERVICE_ROLE_KEY}
export SIFT_CONTROL_PLANE_DSN=${SIFT_CONTROL_PLANE_DSN}
OUTENV
  chmod 600 "$OUT_ENV_FILE"
  log "Output env written to $OUT_ENV_FILE (chmod 600)."
}

# ── Migration status report ───────────────────────────────────────────────────
report_migrations() {
  log "Migration status:"
  (cd "$REPO_DIR" && supabase migration list 2>/dev/null) || true
}

# ── Reset ─────────────────────────────────────────────────────────────────────
do_reset() {
  if [[ "$RESET_YES" -eq 0 ]]; then
    printf '[setup-supabase] WARNING: --reset runs `supabase db reset` which DROPS and recreates\n'
    printf '  the local database from migrations. All data is lost.\n'
    printf '  Type YES to confirm: '
    read -r confirm
    [[ "$confirm" == "YES" ]] || { log "Aborted."; exit 0; }
  fi

  log "Running: supabase db reset ..."
  (cd "$REPO_DIR" && supabase db reset) \
    || die "'supabase db reset' failed. Is the stack running? Try: supabase start first."
  log "Reset complete."
  exit 0
}

# ── Stop ──────────────────────────────────────────────────────────────────────
do_stop() {
  log "Stopping Supabase stack (data preserved)..."
  (cd "$REPO_DIR" && supabase stop) || true
  log "Stack stopped."
  exit 0
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  check_deps
  resolve_supabase_cli

  if [[ "$DO_STOP" -eq 1 ]]; then
    do_stop
  fi

  if [[ "$DO_RESET" -eq 1 ]]; then
    do_reset
  fi

  ensure_config_toml
  supabase_start
  capture_credentials
  write_output_env
  report_migrations

  cat <<SUMMARY

[setup-supabase] Supabase stack is up.

  SUPABASE_URL:             ${SUPABASE_URL}
  ANON_KEY (first 24):      ${SUPABASE_ANON_KEY:0:24}...
  SERVICE_ROLE_KEY (24):    ${SUPABASE_SERVICE_ROLE_KEY:0:24}...
  SIFT_CONTROL_PLANE_DSN:   ${SIFT_CONTROL_PLANE_DSN%@*}@...  (password omitted)

  Output env file:  ${OUT_ENV_FILE}

Next steps:
  1. source ${OUT_ENV_FILE}
  2. ./install.sh       # applies SIFT DB migrations + provisions operator account

Other commands:
  supabase status               # check running services
  supabase migration list       # see applied migrations
  $0 --reset [--yes]  # drop + recreate DB from migrations
  $0 --stop           # stop stack (keep volumes)
SUMMARY
}

main "$@"
