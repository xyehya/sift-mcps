"""Custody / provenance appendix and approved-only enforcement (BATCH-J1).

Verifies F-MVP-4 deliverables in core report generation:
  - unapproved findings never reach the report body;
  - the custody appendix carries per-finding provenance (approval hash +
    provenance/audit refs) for approved findings only;
  - the appendix carries evidence seal / hash-chain proof references;
  - provenance refs never leak absolute case/evidence/mount paths;
  - a supplied re-auth event id is recorded as the inclusion authorization.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from sift_core.evidence_chain import ChainStatus
from sift_core.reporting import (
    _provenance_refs,
    build_custody_appendix,
    generate_report_data,
)


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "j1-test", "name": "J1Custody", "examiner": "alice"})
    )
    findings = [
        {
            "id": "F-1",
            "title": "Approved finding",
            "status": "APPROVED",
            "content_hash": "hash-approved-1",
            "approved_by": "alice",
            "approved_at": "2026-06-08T00:00:00Z",
            "provenance": [{"id": "prov-1"}],
            "audit_ids": ["aud-1"],
            "observation": "approved observation",
        },
        {
            "id": "F-2",
            "title": "Draft finding — must never appear",
            "status": "draft",
            "content_hash": "hash-draft",
            "observation": "SECRET draft observation",
        },
        {
            "id": "F-3",
            "title": "Rejected finding — must never appear",
            "status": "REJECTED",
            "observation": "rejected observation",
        },
    ]
    import json

    (tmp_path / "findings.json").write_text(json.dumps(findings))
    (tmp_path / "timeline.json").write_text("[]")
    (tmp_path / "todos.json").write_text("[]")
    return tmp_path


def _gen(case_dir: Path, profile="full", **kwargs):
    with (
        patch(
            "sift_core.reporting._ev_chain_status",
            return_value={
                "status": ChainStatus.OK,
                "manifest_version": 2,
                "ok_count": 3,
                "issues": [],
            },
        ),
        patch(
            "sift_core.reporting.load_manifest",
            return_value={"manifest_hash": "manifest-hash-xyz"},
        ),
        patch("sift_core.reporting.list_evidence_data", return_value={"evidence": []}),
        patch("sift_core.reporting.reconcile_verification", return_value=[]),
    ):
        return generate_report_data(profile, case_dir, **kwargs)


class TestApprovedOnly:
    def test_only_approved_finding_in_body(self, case_dir):
        result = _gen(case_dir, "full")
        body = result["report_data"].get("findings", [])
        ids = {f.get("id") for f in body}
        assert ids == {"F-1"}

    def test_draft_and_rejected_text_absent_everywhere(self, case_dir):
        import json as _json

        result = _gen(case_dir, "full")
        blob = _json.dumps(result, default=str)
        assert "SECRET draft observation" not in blob
        assert "rejected observation" not in blob
        assert "F-2" not in blob
        assert "F-3" not in blob

    def test_appendix_provenance_approved_only(self, case_dir):
        result = _gen(case_dir, "full")
        fp = result["custody_appendix"]["finding_provenance"]
        assert [e["id"] for e in fp] == ["F-1"]


class TestCustodyAppendix:
    def test_appendix_present_on_every_profile(self, case_dir):
        for profile in ("full", "executive", "ioc", "timeline", "findings", "status"):
            result = _gen(case_dir, profile)
            assert "custody_appendix" in result, profile

    def test_appendix_has_seal_proof(self, case_dir):
        result = _gen(case_dir, "full")
        seal = result["custody_appendix"]["evidence_seal"]
        assert seal["manifest_version"] == 2
        assert seal["manifest_hash"] == "manifest-hash-xyz"
        assert seal["seal_status"] == str(ChainStatus.OK)

    def test_finding_provenance_carries_hash_and_refs(self, case_dir):
        result = _gen(case_dir, "full")
        entry = result["custody_appendix"]["finding_provenance"][0]
        assert entry["id"] == "F-1"
        assert entry["content_hash"] == "hash-approved-1"
        assert entry["approved_by"] == "alice"
        assert "prov-1" in entry["provenance_refs"]
        assert "aud-1" in entry["provenance_refs"]

    def test_reauth_event_recorded(self, case_dir):
        result = _gen(case_dir, "full", reauth_audit_event_id="evt-123")
        assert result["reauth_audit_event_id"] == "evt-123"
        assert result["custody_appendix"]["authorized_by_reauth_event"] == "evt-123"

    def test_custody_summary_folded_in(self, case_dir):
        custody = {"seal_status": "sealed", "events": [{"event_type": "MANIFEST_SEALED"}]}
        result = _gen(case_dir, "full", custody=custody)
        assert result["custody_appendix"]["custody"] == custody

    def test_db_custody_drives_visible_evidence_chain(self, case_dir):
        custody = {
            "seal_status": "sealed",
            "manifest_version": 7,
            "active_count": 2,
            "head_hash": "sha256:db-head",
            "issues": [],
        }
        result = _gen(case_dir, "full", custody=custody)
        assert result["evidence_chain"]["status"] == "sealed"
        assert result["evidence_chain"]["manifest_version"] == 7
        assert result["evidence_chain"]["head_hash"] == "sha256:db-head"
        assert "evidence_chain_warning" not in result


class TestProvenanceSanitization:
    def test_absolute_paths_dropped(self):
        item = {
            "provenance": [{"id": "prov-ok"}],
            "audit_ids": ["aud-ok"],
            "source_evidence": [
                "/mnt/evidence/disk.E01",
                "C:\\Cases\\secret",
                "relative/label.txt",
            ],
        }
        refs = _provenance_refs(item)
        assert "prov-ok" in refs
        assert "aud-ok" in refs
        assert "relative/label.txt" in refs
        assert not any(r.startswith("/") for r in refs)
        assert not any(r.startswith("C:") for r in refs)

    def test_appendix_note_present(self):
        appendix = build_custody_appendix([], {"status": "unsealed"}, custody=None)
        assert appendix["verification_note"]
        assert "custody" not in appendix
