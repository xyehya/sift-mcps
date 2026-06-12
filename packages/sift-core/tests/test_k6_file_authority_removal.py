"""BATCH-K6: file-authority removal + tamper regressions (core surfaces).

Proves that in DB-active mode the report verification, audit summary, and backup
snapshot derive their integrity/authority from Postgres (or are explicitly
labelled non-authoritative), so tampering with, deleting, or staling the legacy
JSON/JSONL/ledger files cannot change report integrity, spoof the audit trail, or
let a backup masquerade as the record of truth.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from sift_core.audit_ops import audit_summary_data
from sift_core.backup_ops import create_backup_data
from sift_core.evidence_chain import ChainStatus
from sift_core.investigation_store import compute_content_hash
from sift_core.reporting import (
    generate_report_data,
    reconcile_verification_db,
)


@pytest.fixture
def db_active(monkeypatch):
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    yield


def _finding(item_id: str, observation: str, *, status: str = "APPROVED") -> dict:
    item = {
        "id": item_id,
        "title": f"Finding {item_id}",
        "status": status,
        "observation": observation,
        "approved_by": "alice",
        "approved_at": "2026-06-08T00:00:00Z",
    }
    item["content_hash"] = compute_content_hash(item)
    return item


# --------------------------------------------------------------------------
# reconcile_verification_db — DB content-hash is the verification authority
# --------------------------------------------------------------------------
class TestReconcileVerificationDb:
    def test_matching_hash_is_verified(self):
        f = _finding("F-1", "clean observation")
        alerts = reconcile_verification_db([f], [])
        assert alerts == [{"id": "F-1", "status": "VERIFIED"}]

    def test_mutated_content_without_rehash_is_mismatch(self):
        f = _finding("F-1", "original")
        # Row content mutated after approval but content_hash NOT updated.
        f["observation"] = "tampered after approval"
        alerts = reconcile_verification_db([f], [])
        assert alerts == [{"id": "F-1", "status": "DESCRIPTION_MISMATCH"}]

    def test_missing_db_hash_flagged(self):
        f = _finding("F-1", "x")
        f.pop("content_hash")
        alerts = reconcile_verification_db([f], [])
        assert alerts == [{"id": "F-1", "status": "APPROVED_NO_DB_HASH"}]


# --------------------------------------------------------------------------
# generate_report_data — DB-active report ignores the file verification ledger
# --------------------------------------------------------------------------
def _gen(case_dir: Path, **kwargs):
    with (
        patch(
            "sift_core.reporting._ev_chain_status",
            return_value={
                "status": ChainStatus.OK,
                "manifest_version": 2,
                "ok_count": 1,
                "issues": [],
            },
        ),
        patch(
            "sift_core.reporting.load_manifest",
            return_value={"manifest_hash": "mh"},
        ),
        patch("sift_core.reporting.list_evidence_data", return_value={"evidence": []}),
    ):
        return generate_report_data("full", case_dir, **kwargs)


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "k6-test", "name": "K6", "examiner": "alice"})
    )
    (tmp_path / "findings.json").write_text("[]")
    (tmp_path / "timeline.json").write_text("[]")
    (tmp_path / "todos.json").write_text("[]")
    return tmp_path


class TestReportDbVerificationAuthority:
    def test_db_active_uses_db_hash_and_never_reads_file_ledger(self, case_dir):
        approved = _finding("F-1", "db authoritative observation")
        inputs = {"findings": [approved], "timeline": [], "iocs": []}

        # B-MVP-011: the file-ledger reconcile path was retired entirely, so DB
        # mode reading it is now structurally impossible (nothing to patch out).
        result = _gen(case_dir, investigation_inputs=inputs)

        assert result["verification_authority"] == "db-content-hash"
        # Verification derives purely from the DB content hash.
        assert {"id": "F-1", "status": "VERIFIED"} in result["verification_alerts"]
        assert "integrity_warning" not in result

    def test_db_active_flags_db_row_mutation(self, case_dir):
        approved = _finding("F-1", "original")
        approved["observation"] = "mutated without rehash"
        inputs = {"findings": [approved], "timeline": [], "iocs": []}
        result = _gen(case_dir, investigation_inputs=inputs)
        assert result["verification_authority"] == "db-content-hash"
        assert any(
            a.get("status") == "DESCRIPTION_MISMATCH"
            for a in result["verification_alerts"]
        )
        assert "integrity_warning" in result

    def test_non_db_mode_marks_verification_unavailable(self, case_dir):
        # B-MVP-011: the legacy file-ledger path is retired. With no
        # investigation_inputs and DB authority inactive, verification authority
        # is reported as unavailable (no silent file-ledger fallback).
        result = _gen(case_dir)
        assert result["verification_authority"] == "unavailable"
        assert any(
            a.get("alert") == "VERIFICATION_UNAVAILABLE"
            for a in result.get("verification_alerts", [])
        )


# --------------------------------------------------------------------------
# audit_summary_data — file mirror is explicitly non-authoritative in DB mode
# --------------------------------------------------------------------------
class TestAuditSummaryAuthority:
    def test_db_active_without_reader_labels_legacy_mirror(self, tmp_path, db_active):
        summary = audit_summary_data(tmp_path)
        assert summary["authority"] == "legacy-file-mirror"
        assert summary["db_active"] is True

    def test_legacy_mode_labels_file(self, tmp_path):
        summary = audit_summary_data(tmp_path)
        assert summary["authority"] == "file"
        assert summary["db_active"] is False

    def test_db_reader_overrides_tampered_files(self, tmp_path, db_active):
        # A tampered local audit mirror must not change the DB-derived summary.
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        (audit_dir / "evil.jsonl").write_text(
            json.dumps({"audit_id": "fake", "mcp": "evil", "tool": "spoof"}) + "\n"
        )
        db_summary = {"total_entries": 7, "audit_ids": 7, "by_mcp": {"gateway": 7}}
        result = audit_summary_data(tmp_path, db_audit_reader=lambda: dict(db_summary))
        assert result["total_entries"] == 7
        assert result["authority"] == "db-audit-events"
        assert result["db_active"] is True
        assert "evil" not in result.get("by_mcp", {})


# --------------------------------------------------------------------------
# backup_ops — a backup is an export snapshot, never authority, in DB mode
# --------------------------------------------------------------------------
class TestBackupAuthorityLabel:
    def _make_case(self, tmp_path: Path) -> Path:
        case = tmp_path / "case"
        case.mkdir()
        (case / "CASE.yaml").write_text(
            yaml.dump({"case_id": "bk-1", "name": "BK", "examiner": "alice"})
        )
        (case / "findings.json").write_text("[]")
        return case

    def test_db_active_backup_marked_snapshot_only(self, tmp_path, db_active):
        case = self._make_case(tmp_path)
        result = create_backup_data(case, str(tmp_path / "dest"), "alice")
        manifest = json.loads(
            (Path(result["backup_path"]) / "backup-manifest.json").read_text()
        )
        assert manifest["authority"] == "db-postgres"
        assert manifest["snapshot_only"] is True
        assert any("must not be restored as authority" in n for n in manifest["notes"])

    def test_legacy_backup_marked_file_authority(self, tmp_path):
        case = self._make_case(tmp_path)
        result = create_backup_data(case, str(tmp_path / "dest"), "alice")
        manifest = json.loads(
            (Path(result["backup_path"]) / "backup-manifest.json").read_text()
        )
        assert manifest["authority"] == "file"
        assert manifest["snapshot_only"] is False
