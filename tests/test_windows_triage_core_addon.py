"""Fail-on-revert contract tests for the first-party Windows-triage pack."""

from __future__ import annotations

import subprocess

from _installer_support import REPO_ROOT, run_bash

CORE_ADDON = REPO_ROOT / "scripts" / "core-addons" / "setup-windows-triage.sh"


def test_core_addon_help_is_explicit_and_noninteractive() -> None:
    result = subprocess.run(
        ["bash", str(CORE_ADDON), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--install" in result.stdout
    assert "--with-registry" in result.stdout
    assert "--offline" in result.stdout
    assert "~12 GiB" in result.stdout


def test_core_addon_defaults_to_no_large_registry_baseline() -> None:
    script = f'''
set -Eeuo pipefail
source "{CORE_ADDON}"
wintriage_require_staged_runtime() {{ :; }}
wintriage_validate_environment() {{ :; }}
wintriage_prepare_data_dir() {{ :; }}
wintriage_sync_runtime() {{ :; }}
wintriage_set_service_readable() {{ :; }}
wintriage_validate_backend() {{ :; }}
wintriage_reconcile_registry() {{ :; }}
wintriage_stage_or_download_baselines() {{ CAPTURE="$1"; }}
wintriage_main --install
printf 'RESULT=%s\n' "$CAPTURE"
'''
    result = run_bash(script)

    assert result.returncode == 0, result.stderr
    assert "RESULT=0" in result.stdout


def test_core_addon_passes_empty_env_refs_to_trusted_reconciler() -> None:
    """The DB-authoritative installer may use a DSN, but its child may not."""
    script = f'''
set -Eeuo pipefail
source "{CORE_ADDON}"
_resolved_control_plane_dsn() {{ printf '%s' 'postgresql://installer-control-plane'; }}
_seed_one_addon_backend() {{
  [[ "$1" == "windows-triage-mcp" ]]
  [[ "$2" == "$REPO_DIR/packages/windows-triage-mcp/sift-backend.json" ]]
  [[ "$3" == "windows-triage-mcp" ]]
  [[ "$4" == "{{}}" ]]
  [[ "$4" != *SIFT_CONTROL_PLANE_DSN* ]]
  [[ "$4" != *DATABASE_URL* ]]
  [[ "$4" != *POSTGRES_DSN* ]]
}}
wintriage_reconcile_registry
'''
    result = run_bash(script)

    assert result.returncode == 0, result.stderr


def test_core_addon_refuses_implicit_install() -> None:
    result = subprocess.run(
        ["bash", str(CORE_ADDON)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "Refusing implicit Windows-triage installation" in result.stderr


def test_core_addon_uses_narrow_library_boundary() -> None:
    source = CORE_ADDON.read_text(encoding="utf-8")

    assert "sift_source_core_addon_libraries" in source
    assert "source \"$REPO_DIR/install.sh\"" not in source
    assert "_seed_one_addon_backend" in source
    assert "'{}'" in source
