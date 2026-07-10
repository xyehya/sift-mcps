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
    assert 'local sync_extra="core"' in python_lib
    assert "Mandatory core OpenSearch did not become healthy" in installer
    assert 'SIFT_OPENSEARCH_ENABLED=true' in installer
    assert "scripts/core-addons/setup-rag.sh" in installer
    assert "scripts/core-addons/setup-windows-triage.sh" in installer
