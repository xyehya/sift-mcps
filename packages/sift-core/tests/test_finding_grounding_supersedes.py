"""P1 fixes + P35-3 grounding rewrite for record_finding:

(d) grounding-credit: a reference backend is credited when the finding cites an
    audit_id produced by that backend (works in DB-active mode where the local
    JSONL may be absent), so findings stop reading "WEAK / forensic-rag missing"
    after kb_search_knowledge actually ran.
(e) supersedes: native self-correction chain field, normalized to a list and
    surfaced in the result + persisted on the finding.
(f) P35-3: attribution via tool→backend off the DB audit trail; WEAK/MEDIUM/HIGH
    scale by count of DISTINCT credited backends (0-1=WEAK, 2=MEDIUM, 3+=HIGH);
    sift-core credited per operator decision; PARTIAL folded into WEAK.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import sift_core.case_manager as cm
from sift_core.case_io import case_audit_dir, case_records_dir
from sift_core.case_manager import CaseManager
from sift_core.agent_tools import _record_finding
from sift_common.audit import AuditWriter

AUDIT_ID = "siftcore-alice-20260614-001"

# Well-known backend names for grounding attribution tests (P35-3).
_KB_BACKEND = "forensic-rag-mcp"
_WT_BACKEND = "windows-triage-mcp"
_OCTI_BACKEND = "opencti-mcp"
_CORE_BACKEND = "sift-core"

# Canonical UUIDs used as gateway envelope ids in Unit-1+ DB-authority mode.
_KB_UUID = "aaaaaaaa-0001-0001-0001-000000000001"
_WT_UUID = "bbbbbbbb-0002-0002-0002-000000000002"
_OCTI_UUID = "cccccccc-0003-0003-0003-000000000003"


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


def _write_trail_entry(
    audit_dir: Path,
    *,
    audit_id: str,
    tool: str,
    backend: str,
    audit_aliases: list[str] | None = None,
    envelope_event_id: str = "",
    jsonl_filename: str | None = None,
) -> None:
    """Write a single audit trail entry into <audit_dir>/<backend>.jsonl.

    Mirrors the shape that ``list_audit_provenance_db`` returns for DB entries
    and that ``_scan_audit_trail`` reads from JSONL files, so the grounding
    scorer's trail attribution path is exercised in file-mode.
    """
    audit_dir.mkdir(parents=True, exist_ok=True)
    entry: dict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "audit_id": audit_id,
        "backend": backend,
        "audit_aliases": audit_aliases or [],
        "envelope_event_id": envelope_event_id,
        "examiner": "alice",
    }
    fname = jsonl_filename or f"{backend}.jsonl"
    with open(audit_dir / fname, "a", encoding="utf-8") as f:
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
    # sift-core (AUDIT_ID) + forensic-rag-mcp = 2 distinct backends → MEDIUM
    assert grounding.get("level") == "MEDIUM"
    assert grounding.get("sources_count") == 2


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


# --- (f) P35-3 grounding rewrite: tool→backend attribution + WEAK/MEDIUM/HIGH -


# Shared helper: patch _declared_reference_backends to a known 3-source set.
_REF_BACKENDS = [_KB_BACKEND, _WT_BACKEND, _OCTI_BACKEND]


def _grounding_with_backends(
    mgr: CaseManager, case_dir: Path, finding: dict
) -> dict:
    """Call _score_grounding with the full reference backend set patched in."""
    mgr._active_case_path = case_dir
    with patch.object(cm, "_declared_reference_backends", return_value=_REF_BACKENDS):
        return mgr._score_grounding(finding)


def test_grounding_medium_two_distinct_backends(file_manager):
    """kb + wintriage cited via trail entries → MEDIUM (2 distinct backends)."""
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    # Write trail entries for kb and wintriage; each has its own backend.
    _write_trail_entry(
        adir,
        audit_id="forensicrag-alice-20260614-010",
        tool="kb_search_knowledge",
        backend=_KB_BACKEND,
    )
    _write_trail_entry(
        adir,
        audit_id="windowstriage-alice-20260614-020",
        tool="wintriage_check_process_tree",
        backend=_WT_BACKEND,
        jsonl_filename=f"{_WT_BACKEND}.jsonl",
    )
    finding = _finding(
        AUDIT_ID,
        audit_ids=["forensicrag-alice-20260614-010", "windowstriage-alice-20260614-020"],
    )
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert grounding.get("level") == "MEDIUM", grounding
    assert grounding.get("sources_count") == 2
    assert _KB_BACKEND in grounding.get("sources_consulted", [])
    assert _WT_BACKEND in grounding.get("sources_consulted", [])
    # Not suppressed (the old >=2 → {} guard is gone).
    assert grounding != {}


def test_grounding_high_three_distinct_backends(file_manager):
    """kb + wintriage + opencti cited → HIGH (3 distinct backends)."""
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    _write_trail_entry(
        adir,
        audit_id="forensicrag-alice-20260614-010",
        tool="kb_search_knowledge",
        backend=_KB_BACKEND,
    )
    _write_trail_entry(
        adir,
        audit_id="windowstriage-alice-20260614-020",
        tool="wintriage_check_process_tree",
        backend=_WT_BACKEND,
        jsonl_filename=f"{_WT_BACKEND}.jsonl",
    )
    _write_trail_entry(
        adir,
        audit_id="opencti-alice-20260614-030",
        tool="opencti_search",
        backend=_OCTI_BACKEND,
        jsonl_filename=f"{_OCTI_BACKEND}.jsonl",
    )
    finding = _finding(
        AUDIT_ID,
        audit_ids=[
            "forensicrag-alice-20260614-010",
            "windowstriage-alice-20260614-020",
            "opencti-alice-20260614-030",
        ],
    )
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert grounding.get("level") == "HIGH", grounding
    assert grounding.get("sources_count") == 3


def test_grounding_weak_single_backend(file_manager):
    """One backend cited → WEAK (count=1)."""
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    _write_trail_entry(
        adir,
        audit_id="forensicrag-alice-20260614-010",
        tool="kb_search_knowledge",
        backend=_KB_BACKEND,
    )
    finding = _finding(AUDIT_ID, audit_ids=["forensicrag-alice-20260614-010"])
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert grounding.get("level") == "WEAK", grounding
    assert grounding.get("sources_count") == 1


def test_grounding_dedups_same_backend(file_manager):
    """3 audit_ids all resolving to wintriage → still WEAK (1 distinct backend)."""
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    for i, aid in enumerate(
        ["windowstriage-alice-20260614-001", "windowstriage-alice-20260614-002",
         "windowstriage-alice-20260614-003"]
    ):
        _write_trail_entry(
            adir,
            audit_id=aid,
            tool="wintriage_check_system",
            backend=_WT_BACKEND,
            jsonl_filename=f"{_WT_BACKEND}.jsonl",
        )
    finding = _finding(
        AUDIT_ID,
        audit_ids=[
            "windowstriage-alice-20260614-001",
            "windowstriage-alice-20260614-002",
            "windowstriage-alice-20260614-003",
        ],
    )
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert grounding.get("level") == "WEAK", grounding
    assert grounding.get("sources_count") == 1


def test_grounding_credits_envelope_uuid(file_manager):
    """Unit-1 regression guard: bare-UUID canonical (proxied add-on) is credited.

    Post-Unit-1 the agent receives the gateway envelope UUID as audit_id.
    The entry's ``audit_id`` is the backend-native scheme id; the UUID lives
    in ``envelope_event_id`` (and in ``audit_aliases``).  The scorer must
    credit the backend when the finding cites the UUID.
    """
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    # Trail entry: canonical = native id, alias+envelope = UUID (as gateway sets it).
    _write_trail_entry(
        adir,
        audit_id="forensicrag-alice-20260614-010",  # canonical (native scheme)
        tool="kb_search_knowledge",
        backend=_KB_BACKEND,
        audit_aliases=[_KB_UUID],
        envelope_event_id=_KB_UUID,
    )
    # Finding cites ONLY the UUID (what the agent actually got back).
    finding = _finding(AUDIT_ID, audit_ids=[_KB_UUID])
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert _KB_BACKEND in grounding.get("sources_consulted", []), (
        "UUID canonical should be credited via envelope_event_id / audit_aliases match"
    )
    assert grounding.get("level") in {"WEAK", "MEDIUM", "HIGH"}
    assert grounding.get("level") != "STRONG"  # vocab sanity


def test_grounding_credits_native_alias(file_manager):
    """Finding cites native alias (``windowstriage-*``); UUID is the canonical.

    The gateway stores the UUID as canonical and the native id as an alias.
    If the agent somehow cites the alias instead of the UUID, the scorer must
    still credit the backend via ``audit_aliases`` match.
    """
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    native_id = "windowstriage-alice-20260614-020"
    _write_trail_entry(
        adir,
        audit_id=_WT_UUID,  # canonical = UUID (proxied)
        tool="wintriage_check_process_tree",
        backend=_WT_BACKEND,
        audit_aliases=[native_id],
        envelope_event_id=_WT_UUID,
        jsonl_filename=f"{_WT_BACKEND}.jsonl",
    )
    # Finding cites the native alias, not the UUID.
    finding = _finding(AUDIT_ID, audit_ids=[native_id])
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert _WT_BACKEND in grounding.get("sources_consulted", []), (
        "Native alias should be credited via audit_aliases match"
    )


def test_grounding_credits_run_command(file_manager):
    """run_command / sift-core is credited per operator decision (P35-3 §1)."""
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    shell_id = "siftcore-alice-20260614-001"
    _write_trail_entry(
        adir,
        audit_id=shell_id,
        tool="run_command",
        backend=_CORE_BACKEND,
    )
    finding = _finding(AUDIT_ID, audit_ids=[shell_id])
    grounding = _grounding_with_backends(mgr, case_dir, finding)
    assert _CORE_BACKEND in grounding.get("sources_consulted", []), (
        "sift-core should be credited as a grounding source for run_command calls"
    )


def test_record_finding_surfaces_medium_grounding(file_manager):
    """Surface test: drive through _record_finding; assert grounding.level scaled.

    This is the MCP-fix-surfacing mandatory test: the grounding block is
    attached to the result dict by agent_tools._record_finding (line ~1239-1241).
    We must assert the field survives that path, not just test _score_grounding
    directly.
    """
    mgr, case_dir = file_manager
    adir = case_audit_dir(case_dir)
    # sift-core entry for AUDIT_ID (artifact's audit_id must exist in trail).
    _write_trail_entry(
        adir,
        audit_id=AUDIT_ID,
        tool="run_command",
        backend=_CORE_BACKEND,
    )
    # Two more distinct backends → MEDIUM when combined with sift-core.
    _write_trail_entry(
        adir,
        audit_id="forensicrag-alice-20260614-010",
        tool="kb_search_knowledge",
        backend=_KB_BACKEND,
    )
    _write_trail_entry(
        adir,
        audit_id="windowstriage-alice-20260614-020",
        tool="wintriage_check_process_tree",
        backend=_WT_BACKEND,
        jsonl_filename=f"{_WT_BACKEND}.jsonl",
    )
    # finding.audit_ids includes all three; artifact cites AUDIT_ID (sift-core).
    # sift-core + kb + wintriage = 3 distinct backends → HIGH at the grounding level.
    # (We assert >=MEDIUM to keep the test robust to future scale adjustments.)
    finding = _finding(
        AUDIT_ID,
        audit_ids=[AUDIT_ID, "forensicrag-alice-20260614-010", "windowstriage-alice-20260614-020"],
    )
    audit = AuditWriter("sift-core", audit_dir=str(adir))

    with patch.object(cm, "_declared_reference_backends", return_value=_REF_BACKENDS):
        result = _record_finding(
            {"finding": finding},
            examiner="alice",
            manager=mgr,
            audit=audit,
        )

    assert result.get("status") == "STAGED", result
    grounding = result.get("grounding")
    assert grounding is not None, (
        "grounding block must be present in the _record_finding result "
        "(MCP-fix-surfacing: the block lives in agent_tools._record_finding, "
        "not just _score_grounding)"
    )
    # sift-core + forensic-rag-mcp + windows-triage-mcp = 3 distinct backends → HIGH
    assert grounding.get("level") in {"MEDIUM", "HIGH"}, grounding
    assert grounding.get("sources_count", 0) >= 2
    assert _KB_BACKEND in grounding.get("sources_consulted", [])
    assert _WT_BACKEND in grounding.get("sources_consulted", [])
