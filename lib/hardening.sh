# shellcheck shell=bash
# =============================================================================
# lib/hardening.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_HARDENING_SOURCED:-}" ]] && return 0
_SIFT_LIB_HARDENING_SOURCED=1

# =============================================================================
# Phase 13 — OS hardening (best-effort)
# =============================================================================

configure_immutable_capability() {
  [[ -x "$VENV_PYTHON" ]] || return 0
  if ! command -v setcap &>/dev/null; then
    warn "setcap not found — skipping CAP_LINUX_IMMUTABLE."
    return 0
  fi
  local cap_target
  cap_target="$(readlink -f "$VENV_PYTHON" 2>/dev/null || printf '%s' "$VENV_PYTHON")"
  # Never grant a file capability to the resolved venv interpreter: on SIFT it
  # is /usr/bin/python3.12, which would privilege every local Python process.
  # The systemd units grant CAP_LINUX_IMMUTABLE only to SIFT service processes.
  if command -v getcap &>/dev/null && getcap "$cap_target" 2>/dev/null | grep -q 'cap_linux_immutable'; then
    sudo_if_needed setcap -r "$cap_target" || die \
      "Could not remove unsafe global CAP_LINUX_IMMUTABLE from $cap_target."
  fi
  log "CAP_LINUX_IMMUTABLE is confined to the gateway service; workers and add-ons drop it."
}

configure_auditd() {
  # B-MVP-014: HR2 found auditd ABSENT at runtime on the live VM (package not
  # installed, /etc/audit/rules.d missing), so the shipped rules were never
  # loaded. Install + enable the daemon, then load a persistent forensic ruleset.
  local rules_src="${REPO_DIR}/configs/audit/99-sift-evidence.rules"
  [[ -f "$rules_src" ]] || return 0

  if ! command -v auditctl &>/dev/null; then
    if is_offline; then
      warn "SIFT_OFFLINE=1: auditd not installed and cannot be fetched. Pre-install the 'auditd' package, then re-run."
      return 0
    fi
    log "auditd not installed — installing the auditd package."
    if ! apt_install_packages auditd audispd-plugins; then
      warn "Could not install auditd — kernel-level evidence/secret auditing will be unavailable."
      return 0
    fi
  fi

  # rules.d is the persistent, boot-loaded location. Create it if the fresh
  # package layout has not yet (auditd creates it, but be defensive).
  sudo_if_needed install -d -m 750 /etc/audit/rules.d 2>/dev/null || true

  local rules_dst="/etc/audit/rules.d/99-sift-evidence.rules"
  local tmp
  tmp="$(mktemp)"
  sed -e "s|CASES_ROOT|${SIFT_CASE_ROOT}|g" \
      -e "s|SIFT_HOME|${SIFT_HOME}|g" \
      -e "s|INSTALL_ROOT|${SIFT_MCPS_INSTALL_ROOT}|g" \
      "$rules_src" > "$tmp"
  sudo_if_needed cp "$tmp" "$rules_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 640 "$rules_dst"

  # Enable + start the daemon so rules survive reboot (persistent via rules.d).
  if command -v systemctl &>/dev/null; then
    sudo_if_needed systemctl enable auditd.service 2>/dev/null || true
    sudo_if_needed systemctl restart auditd.service 2>/dev/null \
      || sudo_if_needed systemctl start auditd.service 2>/dev/null || true
  fi

  # Load the rules now (augenrules compiles rules.d into the running kernel set).
  if command -v augenrules &>/dev/null; then
    sudo_if_needed augenrules --load 2>/dev/null || warn "augenrules --load reported an issue; rules will load on next boot."
  elif command -v auditctl &>/dev/null; then
    sudo_if_needed auditctl -R "$rules_dst" 2>/dev/null || true
  fi

  if command -v auditctl &>/dev/null && sudo_if_needed auditctl -l 2>/dev/null | grep -q 'sift_evidence_write'; then
    log "auditd active with SIFT forensic rules loaded."
  else
    warn "auditd rules installed to $rules_dst but not confirmed live; verify with: sudo auditctl -l | grep sift_"
  fi
}

# Load an AppArmor profile in enforce mode (default) or explicit development complain mode.
# Enforce mode is the secure install default. Complain mode is an explicit
# local-development override and cannot be mistaken for acceptance posture.
_apparmor_load_profile() {
  local profile_dst="$1"
  if [[ "${SIFT_APPARMOR_ENFORCE:-0}" == "1" ]]; then
    sudo_if_needed apparmor_parser -r "$profile_dst" || die \
      "Could not load required AppArmor profile $profile_dst in enforce mode."
  else
    sudo_if_needed apparmor_parser -C -r "$profile_dst" 2>/dev/null || true
  fi
}

configure_apparmor() {
  if ! command -v aa-status &>/dev/null; then
    if [[ "${SIFT_APPARMOR_ENFORCE:-0}" == "1" ]]; then
      die "AppArmor is required for the secure install but aa-status is unavailable."
    fi
    warn "AppArmor not found — explicit development complain profile cannot be loaded."
    return 0
  fi
  [[ -x "$VENV_PYTHON" ]] || return 0
  local profile_src="${REPO_DIR}/configs/apparmor/sift-gateway.template"
  local profile_dst="/etc/apparmor.d/sift-gateway"
  local tmp
  tmp="$(mktemp)"
  cp "$profile_src" "$tmp"
  sudo_if_needed cp "$tmp" "$profile_dst"
  rm -f "$tmp"
  sudo_if_needed chmod 644 "$profile_dst"
  _apparmor_load_profile "$profile_dst"

  profile_src="${REPO_DIR}/configs/apparmor/dfir-exec.template"
  profile_dst="/etc/apparmor.d/dfir-exec"
  if [[ -f "$profile_src" ]]; then
    tmp="$(mktemp)"
    sed -e "s|@@DFIR_EXEC_LAUNCHER@@|${VENV_DIR}/bin/dfir-exec-launcher|g" \
        -e "s|@@PYTHON_BIN@@|${VENV_PYTHON}|g" \
        -e "s|@@SIFT_MCPS_ROOT@@|${REPO_DIR}|g" \
        -e "s|@@SIFT_CASES_ROOT@@|${SIFT_CASES_ROOT}|g" \
        -e "s|@@SIFT_VOL_SYMBOLS@@|${SIFT_VOL_SYMBOLS}|g" \
        "$profile_src" > "$tmp"
    sudo_if_needed cp "$tmp" "$profile_dst"
    rm -f "$tmp"
    sudo_if_needed chmod 644 "$profile_dst"
    _apparmor_load_profile "$profile_dst"
  fi
  if [[ "${SIFT_APPARMOR_ENFORCE:-0}" == "1" ]]; then
    sudo_if_needed aa-status 2>/dev/null | grep -Fq 'sift-gateway' || die \
      "Required sift-gateway AppArmor profile is not loaded."
    log "AppArmor profiles installed (ENFORCE mode)."
  else
    log "AppArmor profiles installed (complain mode). Run ./harden.sh (or"
    log "  ./install.sh --apparmor-enforce) for the proven enforce posture."
  fi
}

verify_gateway_apparmor_attachment() {
  [[ "${SIFT_APPARMOR_ENFORCE:-0}" == "1" ]] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0
  local pid label
  pid="$(sudo_if_needed systemctl show -p MainPID --value sift-gateway.service)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || die \
    "sift-gateway has no live MainPID for AppArmor attachment verification."
  label="$(sudo_if_needed cat "/proc/${pid}/attr/current" 2>/dev/null || true)"
  [[ "$label" == "sift-gateway (enforce)" ]] || die \
    "sift-gateway AppArmor attachment failed (observed: ${label:-unreadable})."
  log "sift-gateway is attached to AppArmor profile sift-gateway (ENFORCE)."
}

configure_run_command_systemd_scope() {
  if ! command -v visudo >/dev/null 2>&1 && [[ ! -x /usr/sbin/visudo ]]; then
    die "Missing required command: visudo"
  fi
  log "Configuring RUN-3 run_command systemd scope helper for service user: ${SIFT_GATEWAY_SERVICE_USER}."
  sudo_if_needed "$REPO_DIR/scripts/setup-run-command-systemd-scope-sudoers.sh" \
    --service-user "$SIFT_GATEWAY_SERVICE_USER" \
    --helper-src "$REPO_DIR/scripts/sift-run-command-systemd-scope"
}

configure_addon_systemd_sandbox() {
  if ! command -v visudo >/dev/null 2>&1 && [[ ! -x /usr/sbin/visudo ]]; then
    die "Missing required command: visudo"
  fi
  log "Configuring destination-constrained stdio add-on sandbox."
  sudo_if_needed "$REPO_DIR/scripts/setup-addon-systemd-sandbox-sudoers.sh" \
    --service-user "$SIFT_GATEWAY_SERVICE_USER" \
    --helper-src "$REPO_DIR/scripts/sift-addon-systemd-sandbox"
}
