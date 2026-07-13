"""Fail-on-revert contract for the operator-only evidence intake helper."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STAGE_EVIDENCE = REPO_ROOT / "scripts" / "stage-evidence.sh"


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def _write_prepare_shims(shim_dir: Path) -> None:
    """Model the fixed root-helper call without executing it locally."""
    _write_executable(
        shim_dir / "sudo",
        """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-v" ] || { [ "${1:-}" = "-n" ] && [ "${2:-}" = "-v" ]; }; then exit 0; fi
printf 'sudo:%s\\n' "$*" >> "$STAGE_EVIDENCE_TEST_LOG"
""",
    )


def test_stage_evidence_copies_then_sets_service_owner_and_mode(tmp_path: Path) -> None:
    """The supported pre-agent path must repair sudo-copy ownership deterministically."""
    case_key = "case-stage-evidence-contract"
    cases_root = tmp_path / "cases"
    evidence_dir = cases_root / case_key / "evidence"
    evidence_dir.mkdir(parents=True)
    source = tmp_path / "-operator-copy.E01"
    source.write_bytes(b"test evidence")
    command_log = tmp_path / "commands.log"
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()

    _write_executable(
        shim_dir / "sudo",
        """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-v" ] || { [ "${1:-}" = "-n" ] && [ "${2:-}" = "-v" ]; }; then exit 0; fi
exec "$@"
""",
    )
    _write_executable(
        shim_dir / "rsync",
        """#!/usr/bin/env bash
set -euo pipefail
printf 'rsync:%s\n' "$*" >> "$STAGE_EVIDENCE_TEST_LOG"
while [ "$#" -gt 2 ]; do shift; done
cp "$1" "$2"
""",
    )
    _write_executable(
        shim_dir / "chown",
        """#!/usr/bin/env bash
set -euo pipefail
printf 'chown:%s\n' "$*" >> "$STAGE_EVIDENCE_TEST_LOG"
""",
    )
    _write_executable(
        shim_dir / "chmod",
        """#!/usr/bin/env bash
set -euo pipefail
printf 'chmod:%s\n' "$*" >> "$STAGE_EVIDENCE_TEST_LOG"
""",
    )

    env = {
        **os.environ,
        "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
        "SIFT_CASES_ROOT": str(cases_root),
        "SIFT_GATEWAY_SERVICE_USER": "sift-service",
        "STAGE_EVIDENCE_TEST_LOG": str(command_log),
    }
    result = subprocess.run(
        ["bash", str(STAGE_EVIDENCE), str(source), "--case", case_key],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    destination = evidence_dir / source.name
    assert result.returncode == 0, result.stderr
    assert destination.read_bytes() == source.read_bytes()
    assert command_log.read_text(encoding="utf-8").splitlines() == [
        f"rsync:--info=progress2 -- {source} {destination}",
        f"chown:sift-service:sift-service -- {destination}",
        f"chmod:0644 -- {destination}",
    ]


def test_prepare_calls_only_the_fixed_pathless_root_helper(tmp_path: Path) -> None:
    """The public wrapper supplies no operator-controlled target to root."""
    command_log = tmp_path / "commands.log"
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    _write_prepare_shims(shim_dir)

    env = {
        **os.environ,
        "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
        "STAGE_EVIDENCE_TEST_LOG": str(command_log),
    }
    result = subprocess.run(
        ["bash", str(STAGE_EVIDENCE), "--prepare"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert command_log.read_text(encoding="utf-8").splitlines() == [
        "sudo:/usr/bin/python3.12 -I /usr/local/lib/sift/prepare_evidence.py",
    ]


def test_prepare_rejects_source_paths_before_privileged_work(tmp_path: Path) -> None:
    """Prepare never turns an operator-supplied path into a privileged action."""
    result = subprocess.run(
        [
            "bash",
            str(STAGE_EVIDENCE),
            "--prepare",
            "/tmp/not-an-evidence-file",
            "--case",
            "case-stage-evidence-contract",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--prepare does not accept source files" in result.stderr


def test_prepare_rejects_explicit_case_before_privileged_work(tmp_path: Path) -> None:
    """Prepare must always bind to the portal's DB-active case."""
    result = subprocess.run(
        ["bash", str(STAGE_EVIDENCE), "--prepare", "--case", "case-not-active"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "always resolves the portal's active case" in result.stderr
