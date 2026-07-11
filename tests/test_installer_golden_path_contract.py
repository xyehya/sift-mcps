"""Fail-on-revert contract tests for P1's mandatory-core installer path."""

from __future__ import annotations

import os
import subprocess
import tomllib

import pytest
from _installer_support import INSTALL_SH, REPO_ROOT


def _installer(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    runtime_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"}
    if env:
        runtime_env.update(env)
    return subprocess.run(
        ["bash", str(INSTALL_SH), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=runtime_env,
    )


def test_positive_pack_cli_contract_is_documented() -> None:
    """Bare core has no disable switch; packs are explicit positive choices."""
    result = _installer("--help")
    assert result.returncode == 0, result.stderr
    for option in (
        "--with-rag",
        "--with-windows-triage",
        "--with-windows-triage-registry",
        "--with-core-addons",
        "--interactive",
        "--apparmor-complain",
    ):
        assert option in result.stdout
    for removed in ("--core-only", "--no-rag", "--no-opencti"):
        assert removed not in result.stdout


@pytest.mark.parametrize("removed", ["--core-only", "--no-rag", "--no-opencti"])
def test_removed_disable_flags_fail_before_install(removed: str) -> None:
    """A removed flag cannot be ignored into a partial install."""
    result = _installer(removed)
    assert result.returncode != 0
    assert "Unknown or removed option" in result.stderr


@pytest.mark.parametrize(
    ("env_name", "value"),
    [
        ("SIFT_CORE_ONLY", "1"),
        ("SIFT_OPENSEARCH_ENABLED", "false"),
        ("SIFT_RAG_ENABLED", "false"),
        ("SIFT_WITH_RAG", "yes"),
    ],
)
def test_legacy_or_non_strict_environment_controls_fail_closed(
    env_name: str, value: str
) -> None:
    """Only the documented true/false pack environment grammar is accepted."""
    result = _installer(env={env_name: value})
    assert result.returncode != 0
    assert env_name in result.stderr


def test_internal_reexec_accepts_its_own_mandatory_core_state() -> None:
    """The /opt re-exec must not reject installer-owned state as legacy input."""
    result = _installer(
        "--help",
        env={
            "SIFT_MCPS_INSTALL_REEXECED": "1",
            "SIFT_OPENSEARCH_ENABLED": "true",
            "SIFT_RAG_ENABLED": "false",
        },
    )
    assert result.returncode == 0, result.stderr


def test_internal_reexec_accepts_serialized_positive_pack_flags() -> None:
    """Staged execution receives installer-owned 0/1 values, not user grammar."""
    result = _installer(
        "--help",
        env={
            "SIFT_MCPS_INSTALL_REEXECED": "1",
            "SIFT_WITH_RAG": "1",
            "SIFT_WITH_WINDOWS_TRIAGE": "1",
            "SIFT_WITH_WINDOWS_TRIAGE_REGISTRY": "0",
        },
    )
    assert result.returncode == 0, result.stderr


def test_root_extra_taxonomy_makes_opensearch_mandatory() -> None:
    """The root package models core and first-party packs without full/standard aliases."""
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = project["project"]["optional-dependencies"]
    assert {"core", "rag", "windows-triage", "core-addons", "opencti"} <= set(extras)
    assert "standard" not in extras and "full" not in extras
    assert "opensearch-mcp" in extras["core"]
    assert "rag-mcp" in extras["rag"]
    assert "windows-triage-mcp" in extras["windows-triage"]
    assert project["tool"]["uv"]["package"] is True
    assert (REPO_ROOT / "src" / "sift_mcps" / "__init__.py").is_file()


def test_core_sync_and_opensearch_health_are_mandatory() -> None:
    """Installer source must fail rather than silently omit core OpenSearch."""
    installer = INSTALL_SH.read_text(encoding="utf-8")
    python_lib = (REPO_ROOT / "lib" / "python.sh").read_text(encoding="utf-8")
    assert 'local sync_extras=(--extra core)' in python_lib
    assert 'sync_extras+=(--extra rag)' in python_lib
    assert 'sync_extras+=(--extra windows-triage)' in python_lib
    assert "Mandatory core OpenSearch did not become healthy" in installer
    assert 'SIFT_OPENSEARCH_ENABLED=true' in installer
    assert "scripts/core-addons/setup-rag.sh" in installer
    assert "scripts/core-addons/setup-windows-triage.sh" in installer


def test_secure_os_hardening_is_default_and_service_scoped() -> None:
    installer = INSTALL_SH.read_text(encoding="utf-8")
    hardening = (REPO_ROOT / "lib" / "hardening.sh").read_text(encoding="utf-8")
    units = [
        REPO_ROOT / "configs" / "systemd" / "sift-gateway.service",
        REPO_ROOT / "configs" / "systemd" / "sift-job-worker.service",
        REPO_ROOT / "configs" / "systemd" / "sift-opensearch-worker@.service",
    ]
    gateway_unit = units[0].read_text(encoding="utf-8")
    gateway_profile = (
        REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"
    ).read_text(encoding="utf-8")

    assert "SIFT_APPARMOR_ENFORCE=1" in installer
    assert "--apparmor-complain" in installer
    assert "setcap cap_linux_immutable+ep" not in hardening
    assert 'setcap -r "$cap_target"' in hardening
    assert "profile sift-gateway {" in gateway_profile
    assert "profile sift-addon {" in gateway_profile
    assert gateway_profile.count("/opt/sift-mcps/.venv/lib/**") == 2
    assert "/etc/mime.types" in gateway_profile
    services = (REPO_ROOT / "lib" / "services.sh").read_text(encoding="utf-8")
    assert 'die "Mandatory gateway is not reachable.' in services
    assert 'die "Mandatory gateway is DEGRADED' in services
    assert "/usr/bin/setpriv                          px -> &sift-addon," in gateway_profile
    assert "pix ->" not in gateway_profile
    assert "pux ->" not in gateway_profile
    assert "capability linux_immutable," in gateway_profile
    assert "/var/lib/sift/.sift/opensearch.yaml       r," in gateway_profile
    assert "/var/lib/sift/.sift/opensearch-root-ca.pem r," in gateway_profile
    addon_profile = gateway_profile.split("profile sift-addon {", 1)[1]
    assert "/var/lib/sift/.sift/tls/" not in addon_profile
    for secret_file in (
        "control-plane.env",
        "supabase.env",
        "audit-writer.env",
        "ca-key.pem",
    ):
        assert secret_file not in addon_profile
    assert "AppArmorProfile=sift-gateway" in gateway_unit
    assert "verify_gateway_apparmor_attachment" in installer
    assert installer.index("configure_apparmor") < installer.index(
        "install_systemd_service"
    )
    assert "AmbientCapabilities=CAP_LINUX_IMMUTABLE" in gateway_unit
    assert "SIFT_DROP_BACKEND_CAPABILITIES=1" in gateway_unit
    for unit in units[1:]:
        assert "AmbientCapabilities=CAP_LINUX_IMMUTABLE" not in unit.read_text(
            encoding="utf-8"
        )
