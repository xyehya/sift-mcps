"""Fail-on-revert tests for the external OpenCTI helper boundary."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from _installer_support import LIB_DIR, REPO_ROOT

SETUP = REPO_ROOT / "scripts" / "setup-addon.sh"


def test_setup_addon_help_is_non_installing() -> None:
    result = subprocess.run(
        ["bash", str(SETUP), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"},
    )
    assert result.returncode == 0, result.stderr
    assert "setup-addon.sh opencti" in result.stdout
    assert "Select OPTIONAL external" not in result.stdout


@pytest.mark.skipif(
    not Path("/usr/bin/python3.12").exists(),
    reason="payload execution uses the SIFT-native Python path; live VM proof covers it",
)
def test_opencti_payload_uses_gateway_env_refs_without_secret_values(tmp_path: Path) -> None:
    """The external payload is valid and never contains raw OpenCTI credentials."""
    root = tmp_path / "repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(SETUP, scripts / SETUP.name)
    shutil.copytree(LIB_DIR, root / "lib")
    shutil.copytree(
        REPO_ROOT / "packages" / "opencti-mcp",
        root / "packages" / "opencti-mcp",
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
    )
    staged = tmp_path / "staged"
    (staged / ".venv" / "bin").mkdir(parents=True)
    (staged / ".venv" / "bin" / "opencti-mcp").write_text("#!/bin/sh\n", encoding="utf-8")
    (staged / ".venv" / "bin" / "opencti-mcp").chmod(0o755)
    shutil.copytree(
        REPO_ROOT / "packages" / "opencti-mcp",
        staged / "packages" / "opencti-mcp",
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_uv.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()

    result = subprocess.run(
        ["bash", str(scripts / SETUP.name), "opencti", "--offline"],
        cwd=root,
        capture_output=True,
        text=True,
        env={
            "PATH": f"{fake_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(home),
            "SIFT_MCPS_INSTALL_ROOT": str(staged),
        },
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    payload_path = home / ".sift" / "addon-register" / "opencti-mcp.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    config = payload["config"]
    assert config["command"] == str(staged / ".venv" / "bin" / "opencti-mcp")
    assert config["env_refs"] == {
        "OPENCTI_URL": "SIFT_OPENCTI_URL",
        "OPENCTI_TOKEN": "SIFT_OPENCTI_TOKEN",
    }
    serialized = payload_path.read_text(encoding="utf-8")
    assert "SIFT_OPENCTI_URL" in serialized
    assert "SIFT_OPENCTI_TOKEN" in serialized
    assert "OPENCTI_ADMIN_TOKEN" not in serialized


def test_setup_addon_never_sources_top_level_installer() -> None:
    source = SETUP.read_text(encoding="utf-8")
    assert 'source "$REPO_ROOT/install.sh"' not in source
    assert "sift_source_external_addon_libraries" in source
    assert "SIFT_CONTROL_PLANE_DSN" not in source


def test_setup_addon_keeps_only_the_shipped_external_flow() -> None:
    """First-party packs belong to install.sh; no obsolete menu handlers remain."""
    source = SETUP.read_text(encoding="utf-8")
    for removed in ("setup_opensearch()", "setup_wintriage()", "setup_custom()", "ask_yes()"):
        assert removed not in source
    assert 'setup_opencti()' in source
    assert 'opencti [--provision] [--offline]' in source
