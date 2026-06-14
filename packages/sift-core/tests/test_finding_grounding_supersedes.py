"""P1 fixes for record_finding:

(d) grounding-credit: a reference backend is credited when the finding cites an
    audit_id produced by that backend (works in DB-active mode where the local
    JSONL may be absent), so findings stop reading "WEAK / forensic-rag missing"
    after kb_search_knowledge actually ran.
(e) supersedes: native self-correction chain field, normalized to a list and
    surfaced in the result + persisted on the finding.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import sift_core.case_manager as cm
from sift_core.case_io import case_audit_dir, case_records_dir
from sift_core.case_manager import CaseManager

AUDIT_ID = "siftcore-alice-20260614-001"


def _write_audit_entry(audit_dir: Path, audit_id: str, tool: str = "run_command") -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "mcp": "sift-core",
        "tool": tool,
        "audit_id": audit_id,
        "examiner": "alice",
    }
    with open(audit_dir / "sift-core.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _register_evidence(case_dir: Path) -> None:
    records = case_records_dir(case_dir)
    records.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence").mkdir(exist_ok=True)
    (case_dir / "evidence" / "auth.log").write_text("log line\n")
    manifest = {
        "files": [
            {"path": "evidence/auth.log", "sha256": "0" * 64, "status": "SEALED"}
        ]
    }
    (records / "evidence-manifest.json").write_text(json.dumps(manifest))


def _finding(audit_id: str, **extra) -> dict:
    f = {
        "title": "t",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "confidence_justification": "single corroborated source",
        "event_timestamp": "2026-06-10T00:00:00Z",
        "audit_ids": [audit_id],
        "artifacts": [
            {
                "source": "evidence/auth.log",
                "extraction": "grep failed logons",
                "content": "Failed password for root",
                "audit_id": audit_id,
            }
        ],
    }
    f.update(extra)
    return f


@pytest.fixture
def file_manager(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-p1"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-p1\nstatus: active\n")
    _register_evidence(case_dir)
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    return CaseManager(), case_dir


# --- (d) grounding credit ---------------------------------------------------


def test_grounding_credits_cited_reference_audit_id(file_manager):
    """A finding citing a forensic-rag audit_id is not 'WEAK / rag missing'."""
    mgr, case_dir = file_manager
    mgr._active_case_path = case_dir  # bind active case for the scorer
    _write_audit_entry(case_audit_dir(case_dir), AUDIT_ID)

    with patch.object(
        cm,
        "_declared_reference_backends",
        return_value=["forensic-rag-mcp", "forensic-knowledge"],
    ):
        # Cite a forensic-rag audit id (prefix 'forensicrag').
        finding = _finding(AUDIT_ID)
        finding["audit_ids"] = [AUDIT_ID, "forensicrag-alice-20260614-007"]
        grounding = mgr._score_grounding(finding)

    assert "forensic-rag-mcp" in grounding.get("sources_consulted", [])
    assert grounding.get("level") in {"PARTIAL", "STRONG"}
    assert grounding.get("level") != "WEAK"


def test_grounding_weak_without_any_reference_citation(file_manager):
    mgr, case_dir = file_manager
    mgr._active_case_path = case_dir  # bind active case for the scorer
    with patch.object(
        cm,
        "_declared_reference_backends",
        return_value=["forensic-rag-mcp", "forensic-knowledge"],
    ):
        grounding = mgr._score_grounding({"audit_ids": [], "type": "finding"})
    # No reference backend consulted → still flagged.
    assert grounding.get("level") == "WEAK"
    assert "forensic-rag-mcp" in grounding.get("sources_missing", [])


# --- (e) supersedes ---------------------------------------------------------


def test_supersedes_is_persisted_and_surfaced(file_manager):
    mgr, case_dir = file_manager
    _write_audit_entry(case_audit_dir(case_dir), AUDIT_ID)

    res = mgr.record_finding(
        _finding(AUDIT_ID, supersedes="F-alice-003"),
        examiner_override="alice",
    )
    assert res["status"] == "STAGED", res
    # Normalized to a list and surfaced in the result.
    assert res.get("supersedes") == ["F-alice-003"]
    # Persisted on the stored finding.
    findings = json.loads((case_dir / "findings.json").read_text())
    assert findings[-1].get("supersedes") == ["F-alice-003"]


def test_supersedes_list_is_deduped(file_manager):
    mgr, case_dir = file_manager
    _write_audit_entry(case_audit_dir(case_dir), AUDIT_ID)

    res = mgr.record_finding(
        _finding(AUDIT_ID, supersedes=["F-alice-003", "F-alice-003", "F-alice-001"]),
        examiner_override="alice",
    )
    assert res["status"] == "STAGED", res
    assert res.get("supersedes") == ["F-alice-003", "F-alice-001"]
