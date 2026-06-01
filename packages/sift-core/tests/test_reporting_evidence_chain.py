"""Evidence chain provenance in core report generation.

Migrated from report-mcp (Phase 2 — reporting is now core-owned). Verifies:
  - every generate_report_data() result includes an 'evidence_chain' key
  - OK status: no warning keys added
  - UNSEALED status: 'evidence_chain_warning' set, no integrity_warning
  - violation status: 'integrity_warning' set, contains status name
  - manifest_hash is forwarded from load_manifest()
  - chain_status error is caught and reflected in evidence_chain.status
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from sift_core.evidence_chain import ChainStatus


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "16d-test", "name": "Phase16d", "examiner": "alice"})
    )
    (tmp_path / "findings.json").write_text("[]")
    (tmp_path / "timeline.json").write_text("[]")
    (tmp_path / "todos.json").write_text("[]")
    return tmp_path


def _chain_result(status: ChainStatus, version: int = 1, ok_count: int = 2) -> dict:
    return {
        "status": status,
        "manifest_version": version,
        "ok_count": ok_count,
        "issues": [] if status == ChainStatus.OK else [f"issue for {status}"],
    }


def _fake_manifest(hash_val: str = "abc123") -> dict:
    return {"version": 1, "manifest_hash": hash_val, "files": []}


def _run_generate(case_dir: Path, chain_status_result: dict, manifest: dict | None = None):
    """Invoke generate_report_data('status', case_dir) with mocked evidence chain."""
    from sift_core.reporting import generate_report_data

    with (
        patch("sift_core.reporting._ev_chain_status", return_value=chain_status_result),
        patch("sift_core.reporting.load_manifest", return_value=manifest),
        patch("sift_core.reporting.list_evidence_data", return_value={"evidence": []}),
        patch("sift_core.reporting.reconcile_verification", return_value=[]),
    ):
        return generate_report_data("status", case_dir)


class TestEvidenceChainAlwaysPresent:
    def test_ok_status_has_evidence_chain(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK))
        assert "evidence_chain" in result

    def test_unsealed_has_evidence_chain(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.UNSEALED, version=0, ok_count=0))
        assert "evidence_chain" in result

    def test_violation_has_evidence_chain(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.MODIFIED))
        assert "evidence_chain" in result

    def test_evidence_chain_has_required_keys(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK), _fake_manifest())
        ec = result["evidence_chain"]
        assert "status" in ec
        assert "manifest_version" in ec
        assert "ok_count" in ec
        assert "issues" in ec
        assert "manifest_hash" in ec

    def test_status_is_string(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK))
        assert isinstance(result["evidence_chain"]["status"], str)


class TestOkStatus:
    def test_no_integrity_warning(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK))
        assert "integrity_warning" not in result or result.get("integrity_warning") is None
        assert "evidence_chain_warning" not in result

    def test_manifest_hash_forwarded(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK), _fake_manifest("deadbeef"))
        assert result["evidence_chain"]["manifest_hash"] == "deadbeef"

    def test_manifest_version_forwarded(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK, version=3))
        assert result["evidence_chain"]["manifest_version"] == 3

    def test_ok_count_forwarded(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.OK, ok_count=5))
        assert result["evidence_chain"]["ok_count"] == 5


class TestUnsealedStatus:
    def test_sets_evidence_chain_warning(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.UNSEALED, version=0, ok_count=0))
        assert "evidence_chain_warning" in result
        assert isinstance(result["evidence_chain_warning"], str)
        assert len(result["evidence_chain_warning"]) > 0

    def test_no_integrity_warning_for_unsealed(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.UNSEALED, version=0, ok_count=0))
        assert "integrity_warning" not in result

    def test_warning_mentions_portal(self, case_dir):
        result = _run_generate(case_dir, _chain_result(ChainStatus.UNSEALED, version=0, ok_count=0))
        assert "Portal" in result["evidence_chain_warning"]


@pytest.mark.parametrize("status", [
    ChainStatus.MODIFIED,
    ChainStatus.MISSING,
    ChainStatus.UNREGISTERED,
    ChainStatus.LEDGER_ERROR,
])
class TestViolationStatus:
    def test_sets_integrity_warning(self, case_dir, status):
        result = _run_generate(case_dir, _chain_result(status))
        assert "integrity_warning" in result
        assert result["integrity_warning"]

    def test_integrity_warning_contains_status(self, case_dir, status):
        result = _run_generate(case_dir, _chain_result(status))
        assert str(status) in result["integrity_warning"]

    def test_no_evidence_chain_warning_for_violations(self, case_dir, status):
        result = _run_generate(case_dir, _chain_result(status))
        assert "evidence_chain_warning" not in result

    def test_integrity_warning_mentions_do_not_distribute(self, case_dir, status):
        result = _run_generate(case_dir, _chain_result(status))
        assert "NOT" in result["integrity_warning"] or "not" in result["integrity_warning"]


class TestChainStatusError:
    def test_exception_produces_ledger_error_status(self, case_dir):
        from sift_core.reporting import generate_report_data

        with (
            patch("sift_core.reporting._ev_chain_status", side_effect=RuntimeError("boom")),
            patch("sift_core.reporting.load_manifest", return_value=None),
            patch("sift_core.reporting.list_evidence_data", return_value={"evidence": []}),
            patch("sift_core.reporting.reconcile_verification", return_value=[]),
        ):
            result = generate_report_data("status", case_dir)

        ec = result["evidence_chain"]
        assert ec["status"] == str(ChainStatus.LEDGER_ERROR)
        assert any("boom" in issue for issue in ec["issues"])

    def test_load_manifest_exception_does_not_crash(self, case_dir):
        from sift_core.reporting import generate_report_data

        with (
            patch("sift_core.reporting._ev_chain_status", return_value=_chain_result(ChainStatus.OK)),
            patch("sift_core.reporting.load_manifest", side_effect=OSError("stat fail")),
            patch("sift_core.reporting.list_evidence_data", return_value={"evidence": []}),
            patch("sift_core.reporting.reconcile_verification", return_value=[]),
        ):
            result = generate_report_data("status", case_dir)

        assert result["evidence_chain"]["manifest_hash"] is None
        assert result["evidence_chain"]["status"] == str(ChainStatus.OK)
