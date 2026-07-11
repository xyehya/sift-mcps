"""Fail-on-revert contract for destination-constrained stdio add-ons."""

from __future__ import annotations

from _installer_support import REPO_ROOT

HELPER = REPO_ROOT / "scripts" / "sift-addon-systemd-sandbox"
SETUP = REPO_ROOT / "scripts" / "setup-addon-systemd-sandbox-sudoers.sh"


def test_helper_is_default_deny_and_structured() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "IPAddressDeny=any" in source
    assert "IPAddressAllow=127.0.0.0/8" in source
    assert "IPAddressAllow=::1/128" in source
    assert 'network_policy" == none' in source
    assert "AppArmorProfile=sift-addon" in source
    assert "NoNewPrivileges=yes" in source
    assert "CapabilityBoundingSet=" in source
    assert "AmbientCapabilities=" in source
    assert "ProtectSystem=strict" in source
    assert "--pipe --wait --quiet --collect" in source
    assert "eval " not in source
    assert "bash -c" not in source
    assert "sh -c" not in source


def test_only_approved_backend_command_policy_pairs_exist() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "/opt/sift-mcps/.venv/bin/opensearch-mcp" in source
    assert "/opt/sift-mcps/.venv/bin/windows-triage-mcp" in source
    assert "/opt/sift-mcps/.venv/bin/opencti-mcp" in source
    assert "OpenSearch backend policy mismatch" in source
    assert "Windows-triage backend policy mismatch" in source
    assert "OpenCTI backend policy mismatch" in source
    assert '[[ $# -eq 1 ]]' in source


def test_secret_environment_uses_root_only_file_not_argv() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "mktemp /run/sift-addon/environment." in source
    assert 'chmod 0600 "$env_file"' in source
    assert 'EnvironmentFile=${env_file}' in source
    assert 'trap cleanup EXIT' in source
    assert 'exec /usr/bin/systemd-run' not in source
    assert "--setenv" not in source
    assert "OPENCTI_TOKEN=" not in source


def test_sudoers_grants_only_validating_helper_with_setenv() -> None:
    source = SETUP.read_text(encoding="utf-8")
    assert "NOPASSWD:SETENV: SIFT_ADDON_SANDBOX" in source
    assert "/usr/bin/systemd-run" not in source
    assert "visudo" in source
