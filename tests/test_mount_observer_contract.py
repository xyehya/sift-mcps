"""Fail-on-revert deployment contract for the host mount observer."""

from __future__ import annotations

from _installer_support import REPO_ROOT

UNIT = REPO_ROOT / "configs" / "systemd" / "sift-mount-observer.service"
PROFILE = REPO_ROOT / "configs" / "apparmor" / "sift-mount-observer.template"
GATEWAY_PROFILE = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"
SERVICES = REPO_ROOT / "lib" / "services.sh"
HARDENING = REPO_ROOT / "lib" / "hardening.sh"
UNINSTALL = REPO_ROOT / "scripts" / "uninstall.sh"


def test_observer_runs_unprivileged_in_host_mount_namespace() -> None:
    unit = UNIT.read_text(encoding="utf-8")

    assert "User=${SIFT_GATEWAY_SERVICE_USER}" in unit
    assert "Group=${SIFT_GATEWAY_SERVICE_USER}" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "AmbientCapabilities=\n" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "AppArmorProfile=sift-mount-observer" in unit
    directives = {
        line.strip().split("=", 1)[0]
        for line in unit.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }
    for forbidden in (
        "ProtectSystem",
        "PrivateTmp",
        "PrivateMounts",
        "ReadOnlyPaths",
        "ReadWritePaths",
    ):
        assert forbidden not in directives
    assert "CAP_SYS_ADMIN" not in unit
    assert "CAP_SYS_PTRACE" not in unit


def test_observer_apparmor_is_directory_only_and_cannot_mutate_mounts() -> None:
    profile = PROFILE.read_text(encoding="utf-8")

    assert "/opt/sift-mcps/.venv/bin/sift-mount-observer rix," in profile
    assert "/opt/sift-mcps/.venv/bin/python            rix," in profile
    assert "/opt/sift-mcps/.venv/bin/python3           rix," in profile
    assert "/opt/sift-mcps/.venv/bin/python3.[0-9]*    rix," in profile
    assert "/usr/bin/python3                           rix," in profile
    assert "/usr/bin/python3.[0-9]*                    rix," in profile
    assert "/opt/sift-mcps/.venv/bin/**" not in profile
    assert "/usr/bin/**" not in profile
    assert "@@SIFT_CASES_ROOT@@/*/evidence/            r," in profile
    assert "deny @@SIFT_CASES_ROOT@@/*/evidence/**     rw," in profile
    assert "owner /proc/@{pid}/mountinfo               r," in profile
    assert "/proc/sys/kernel/random/boot_id            r," in profile
    assert "network unix stream," in profile
    assert {"deny mount,", "deny remount,", "deny umount,"} <= {
        line.strip() for line in profile.splitlines()
    }
    assert "/proc/1/" not in profile
    assert "capability sys_admin" not in profile
    assert "capability sys_ptrace" not in profile


def test_gateway_can_only_reach_fixed_observer_socket() -> None:
    profile = GATEWAY_PROFILE.read_text(encoding="utf-8")

    assert "/run/sift-mount-observer/observer.sock     rw," in profile
    assert "/proc/1/" not in profile


def test_install_upgrade_and_uninstall_cover_observer_assets() -> None:
    services = SERVICES.read_text(encoding="utf-8")
    hardening = HARDENING.read_text(encoding="utf-8")
    uninstall = UNINSTALL.read_text(encoding="utf-8")

    assert "configs/systemd/sift-mount-observer.service" in services
    assert 'chown root:root "$VENV_DIR/bin/sift-mount-observer"' in services
    assert 'chmod 0755 "$VENV_DIR/bin/sift-mount-observer"' in services
    assert "systemctl restart sift-mount-observer.service" in services
    assert "configs/apparmor/sift-mount-observer.template" in hardening
    assert "sift-mount-observer (enforce)" in hardening
    assert "MOUNT_OBSERVER_SERVICE_FILE" in uninstall
    assert "/etc/apparmor.d/sift-mount-observer" in uninstall
