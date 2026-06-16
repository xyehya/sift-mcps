#!/usr/bin/env python3
"""Run package-scoped coverage gates used by CI.

Floors are based on AU2 measurements from 2026-06-16, set just below observed
coverage. Ratchet upward after a package adds meaningful tests; do not lower a
floor unless a measured, reviewed package split makes the old floor invalid.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PackageCoverageGate:
    name: str
    tests: str
    source: str
    observed: int
    floor: int
    pytest_args: tuple[str, ...] = ()


PACKAGE_GATES: tuple[PackageCoverageGate, ...] = (
    PackageCoverageGate(
        name="forensic-knowledge",
        tests="packages/forensic-knowledge/tests",
        source="packages/forensic-knowledge/src/forensic_knowledge",
        observed=72,
        floor=70,
    ),
    # AU2 locks today's very low common baseline; Axis C should ratchet this
    # after direct AuditWriter/parser tests land.
    PackageCoverageGate(
        name="sift-common",
        tests="packages/sift-common/tests",
        source="packages/sift-common/src/sift_common",
        observed=4,
        floor=3,
    ),
    PackageCoverageGate(
        name="sift-core",
        tests="packages/sift-core/tests",
        source="packages/sift-core/src/sift_core",
        observed=62,
        floor=60,
    ),
    PackageCoverageGate(
        name="sift-gateway",
        tests="packages/sift-gateway/tests",
        source="packages/sift-gateway/src/sift_gateway",
        observed=59,
        floor=57,
    ),
    PackageCoverageGate(
        name="opensearch-mcp",
        tests="packages/opensearch-mcp/tests",
        source="packages/opensearch-mcp/src/opensearch_mcp",
        observed=52,
        floor=50,
        pytest_args=("-m", "not integration"),
    ),
    PackageCoverageGate(
        name="case-dashboard",
        tests="packages/case-dashboard/tests",
        source="packages/case-dashboard/src/case_dashboard",
        observed=45,
        floor=43,
    ),
    PackageCoverageGate(
        name="forensic-rag-mcp",
        tests="packages/forensic-rag-mcp/tests",
        source="packages/forensic-rag-mcp/src/rag_mcp",
        observed=21,
        floor=19,
    ),
    PackageCoverageGate(
        name="opencti-mcp",
        tests="packages/opencti-mcp/tests",
        source="packages/opencti-mcp/src/opencti_mcp",
        observed=20,
        floor=18,
    ),
    PackageCoverageGate(
        name="windows-triage-mcp",
        tests="packages/windows-triage-mcp/tests",
        source="packages/windows-triage-mcp/src/windows_triage_mcp",
        observed=48,
        floor=46,
    ),
)


def coverage_command(gate: PackageCoverageGate, report_dir: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        *gate.pytest_args,
        gate.tests,
        f"--cov={gate.source}",
        "--cov-branch",
        "--cov-report=term",
        f"--cov-report=json:{report_dir / f'{gate.name}.json'}",
        f"--cov-fail-under={gate.floor}",
    ]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    report_dir = repo_root / ".coverage-reports"
    report_dir.mkdir(exist_ok=True)

    failures: list[str] = []
    for gate in PACKAGE_GATES:
        command = coverage_command(gate, report_dir)
        print(
            f"\n== {gate.name}: observed {gate.observed}%, "
            f"floor {gate.floor}% ==",
            flush=True,
        )
        print(shlex.join(command), flush=True)
        result = subprocess.run(command, cwd=repo_root, check=False)
        if result.returncode:
            failures.append(gate.name)

    if failures:
        print(
            "\nCoverage gates failed for: " + ", ".join(failures),
            file=sys.stderr,
        )
        return 1

    print("\nAll package coverage floors passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
