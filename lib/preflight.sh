# shellcheck shell=bash
# =============================================================================
# lib/preflight.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_PREFLIGHT_SOURCED:-}" ]] && return 0
_SIFT_LIB_PREFLIGHT_SOURCED=1

# Phase 0 — pre-flight
# =============================================================================

check_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
      warn "Target OS is Ubuntu 22.04/24.04; detected ${PRETTY_NAME:-unknown}.  Proceeding anyway."
    elif [[ "${VERSION_ID:-}" != "22.04" && "${VERSION_ID:-}" != "24.04" ]]; then
      warn "Target Ubuntu versions are 22.04/24.04; detected ${VERSION_ID:-unknown}.  Proceeding anyway."
    fi
  fi
}

check_python() {
  if [[ ! -x "$SYSTEM_PYTHON" ]]; then
    # Fall back through candidates
    for candidate in /usr/bin/python3.11 /usr/bin/python3.10 /usr/bin/python3; do
      if [[ -x "$candidate" ]]; then
        SYSTEM_PYTHON="$candidate"
        break
      fi
    done
  fi
  [[ -x "$SYSTEM_PYTHON" ]] || die "No usable Python found (tried /usr/bin/python3.12, .11, .10, python3)."
  local ver
  ver=$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || true
  local major
  major=$("$SYSTEM_PYTHON" -c 'import sys; print(sys.version_info.major)' 2>/dev/null) || true
  if [[ -z "$major" || "$major" -lt 3 ]]; then
    die "Python ≥ 3.10 required; $SYSTEM_PYTHON reports version '$ver'."
  fi
  local minor
  minor=$("$SYSTEM_PYTHON" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null) || true
  if [[ "$major" -eq 3 && "$minor" -lt 10 ]]; then
    die "Python ≥ 3.10 required; $SYSTEM_PYTHON reports version '$ver'."
  fi
  log "System Python: $SYSTEM_PYTHON ($ver)"
  export SYSTEM_PYTHON
}

apt_install_packages() {
  local packages=("$@")
  [[ "${#packages[@]}" -gt 0 ]] || return 0
  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi

  if ! sudo_if_needed apt-get update; then
    warn "apt-get update failed, likely due to an unrelated third-party apt source."
    warn "Continuing with existing package indexes and attempting: apt-get install -y ${packages[*]}"
  fi
  sudo_if_needed apt-get install -y "${packages[@]}"
}

install_host_prereqs() {
  local missing=()
  command -v rg >/dev/null 2>&1 || missing+=(ripgrep)
  command -v setfacl >/dev/null 2>&1 || missing+=(acl)
  if [[ "${#missing[@]}" -gt 0 ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
      warn "Missing host tools (${missing[*]}) and apt-get is unavailable."
    else
      log "Installing host prerequisites: ${missing[*]}"
      apt_install_packages "${missing[@]}" || warn "Host prerequisite package install failed: ${missing[*]}"
      local still_missing=()
      command -v setfacl >/dev/null 2>&1 || still_missing+=(acl)
      # ripgrep is useful for investigator workflows but not required to finish
      # provisioning. Do not let a stale third-party apt key block the stack.
      command -v rg >/dev/null 2>&1 || warn "ripgrep is still missing; install it later with: sudo apt-get install -y ripgrep"
      if [[ "${#still_missing[@]}" -gt 0 ]]; then
        die "Required host tools are still missing after apt install attempt: ${still_missing[*]}.
  If apt is blocked by a third-party repository key, fix or disable that source, then re-run:
    sudo apt-get update
    sudo apt-get install -y ${still_missing[*]}"
      fi
    fi
  fi

  # Docker presence check for OpenSearch (#8). We do NOT attempt to install
  # Docker ourselves (distro-specific / risky). Just detect + warn so the
  # operator knows what to do.  Seeding is gated in main() via OPENSEARCH_UP.
  if [[ "${SIFT_OPENSEARCH_ENABLED:-true}" == "true" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
      warn "Docker not found. OpenSearch requires Docker."
      warn "  Install Docker (https://docs.docker.com/engine/install/) and re-run."
      warn "  Continuing without OpenSearch — set SIFT_OPENSEARCH_ENABLED=false to silence this."
    fi
  fi
}

ensure_docker_ready_for_supabase() {
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" || "${SIFT_EXTERNAL_SUPABASE:-0}" == "1" ]]; then
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    die "Docker is required for local Supabase provisioning, but docker was not found.
  Install Docker Engine and the compose plugin, then re-run:
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose-plugin
    sudo usermod -aG docker $(user_name)
  Then log out and back in, or run: newgrp docker"
  fi

  if ! docker compose version >/dev/null 2>&1; then
    die "Docker Compose v2 is required for local Supabase provisioning.
  Install it, then re-run:
    sudo apt-get update
    sudo apt-get install -y docker-compose-plugin"
  fi

  if docker ps >/dev/null 2>&1; then
    log "Docker daemon reachable."
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1; then
    log "Docker daemon not reachable — attempting: sudo systemctl start docker"
    sudo_if_needed systemctl start docker 2>/dev/null || true
    sleep 2
  fi

  if docker ps >/dev/null 2>&1; then
    log "Docker daemon reachable after start."
    return 0
  fi

  local operator
  operator="$(user_name)"
  if getent group docker >/dev/null 2>&1 && ! id -nG "$operator" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    die "Docker is installed but '$operator' cannot access the daemon.
  Add the operator to the docker group and refresh the login session:
    sudo usermod -aG docker $operator
    newgrp docker
  Then re-run:
    cd $(printf '%q' "$REPO_DIR")
    ./install.sh"
  fi

  die "Docker daemon is not reachable.
  Try:
    sudo systemctl status docker --no-pager
    sudo systemctl start docker
    docker ps
  Then re-run ./install.sh."
}
