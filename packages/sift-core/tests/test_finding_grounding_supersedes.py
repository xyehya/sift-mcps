"""Axis B grounding (DB-only) + supersedes + the surface seam + field allowlist.

Rebuild model (plan BE-2/BE-5/BE-7):
  - grounding credits a backend ONLY when a cited audit_id resolves to a real
    `list_audit_provenance_db` row whose backend is a DECLARED reference backend
    (forensic-rag-mcp / windows-triage-mcp / opencti-mcp). NO prefix-shape or
    JSONL fallbacks (those were agent-fakeable backdoors).
  - run_command/sift-core is NOT grounding (Axis A); opensearch is NOT grounding
    (Axis A). Distinct-backend count scales WEAK/MEDIUM/HIGH.
  - the record_finding result dict IS the agent surface (no outputSchema): it
    carries provenance_grade + grounding + confidence_derivation; agent_tools
    must not recompute grounding.
  - agent-supplied grounding/provenance_grade/confidence_derivation are stripped
    by _ALLOWED_FINDING_FIELDS (cannot be pre-seeded).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import sift_core.case_manager as cm
from sift_common.audit import AuditWriter
from sift_core.agent_tools import _record_finding
from sift_core.case_manager import _ALLOWED_FINDING_FIELDS, CaseManager

CASE_UUID = "22222222-2222-2222-2222-222222222222"
_KB = "forensic-rag-mcp"
_WT = "windows-triage-mcp"
_OCTI = "opencti-mcp"
_REF_BACKENDS = [_KB, _WT, _OCTI]

_KB_UUID = "aaaaaaaa-0001-0001-0001-000000000001"
_WT_UUID = "bbbbbbbb-0002-0002-0002-000000000002"


def _audit_row(
    audit_id: str,
    *,
    tool: str,
    backend: str = "",
    evidence_refs=None,
    aliases=None,
    envelope: str = "",
) -> dict:
    return {
        "audit_id": audit_id,
        "tool": tool,
        "backend": backend,
        "evidence_refs": list(evidence_refs or []),
        "audit_aliases": list(aliases or []),
        "envelope_event_id": envelope,
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


def _finding(confidence: str = "MEDIUM", *, audit_ids=None, **extra) -> dict:
    f = {
        "title": "t",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": confidence,
        "confidence_justification": "single corroborated source",
        "event_timestamp": "2026-06-10T00:00:00Z",
        "audit_ids": list(audit_ids or []),
    }
    f.update(extra)
    return f


def _grounding(rows: list[dict], finding: dict) -> dict:
    """Score grounding purely over the given DB rows (no DB plumbing needed)."""
    mgr = CaseManager()
    with patch.object(cm, "_declared_reference_backends", return_value=list(_REF_BACKENDS)):
        return mgr._score_grounding(finding, audit_entries=rows)


# --------------------------------------------------------------------------- #
# Axis B grounding: distinct-backend scaling + DB-only attribution.
# --------------------------------------------------------------------------- #
class TestGroundingScaling:
    def test_single_backend_is_weak(self):
        rows = [_audit_row("kb-1", tool="kb_search_knowledge", backend=_KB)]
        g = _grounding(rows, _finding(audit_ids=["kb-1"]))
        assert g["level"] == "WEAK"
        assert g["sources_count"] == 1
        assert _KB in g["sources_consulted"]

    def test_two_distinct_backends_is_medium(self):
        rows = [
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_process_tree", backend=_WT),
        ]
        g = _grounding(rows, _finding(audit_ids=["kb-1", "wt-1"]))
        assert g["level"] == "MEDIUM"
        assert g["sources_count"] == 2
        assert {_KB, _WT} <= set(g["sources_consulted"])

    def test_three_distinct_backends_is_high(self):
        rows = [
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_process_tree", backend=_WT),
            _audit_row("octi-1", tool="cti_search", backend=_OCTI),
        ]
        g = _grounding(rows, _finding(audit_ids=["kb-1", "wt-1", "octi-1"]))
        assert g["level"] == "HIGH"
        assert g["sources_count"] == 3

    def test_dedups_same_backend(self):
        rows = [
            _audit_row(f"wt-{i}", tool="wintriage_check_system", backend=_WT)
            for i in range(3)
        ]
        g = _grounding(rows, _finding(audit_ids=["wt-0", "wt-1", "wt-2"]))
        assert g["level"] == "WEAK"
        assert g["sources_count"] == 1  # 3 ids, ONE distinct backend

    def test_weak_without_any_reference_citation(self):
        g = _grounding([], _finding(audit_ids=[]))
        assert g["level"] == "WEAK"
        assert g["sources_count"] == 0
        assert _KB in g["sources_missing"]


# --------------------------------------------------------------------------- #
# Axis B credit forms: envelope UUID + native alias (proxied add-on ids).
# --------------------------------------------------------------------------- #
class TestGroundingCreditForms:
    def test_credits_via_envelope_uuid(self):
        rows = [
            _audit_row("forensicrag-alice-20260614-010", tool="kb_search_knowledge",
                       backend=_KB, aliases=[_KB_UUID], envelope=_KB_UUID),
        ]
        # The agent cites ONLY the gateway envelope UUID it received.
        g = _grounding(rows, _finding(audit_ids=[_KB_UUID]))
        assert _KB in g["sources_consulted"]
        assert g["level"] in {"WEAK", "MEDIUM", "HIGH"}

    def test_credits_via_native_alias(self):
        native = "windowstriage-alice-20260614-020"
        rows = [
            _audit_row(_WT_UUID, tool="wintriage_check_process_tree", backend=_WT,
                       aliases=[native], envelope=_WT_UUID),
        ]
        g = _grounding(rows, _finding(audit_ids=[native]))
        assert _WT in g["sources_consulted"]


# --------------------------------------------------------------------------- #
# Axis B exclusions: run_command / opensearch are EVIDENCE, not grounding.
# --------------------------------------------------------------------------- #
class TestGroundingExclusions:
    def test_run_command_not_grounding(self):
        rows = [_audit_row("rc-1", tool="run_command", backend="sift-core")]
        g = _grounding(rows, _finding(audit_ids=["rc-1"]))
        assert "sift-core" not in g.get("sources_consulted", [])
        assert g["sources_count"] == 0  # run_command is Axis A, never Axis B

    def test_opensearch_not_grounding(self):
        rows = [_audit_row("os-1", tool="opensearch_search", backend="opensearch-mcp")]
        g = _grounding(rows, _finding(audit_ids=["os-1"]))
        assert g["sources_count"] == 0  # opensearch is primary evidence (Axis A)


# --------------------------------------------------------------------------- #
# Anti-backdoor: forged ids and prefix-shape ids are NOT credited (no fallback).
# --------------------------------------------------------------------------- #
class TestGroundingAntiBackdoor:
    def test_forged_prefix_id_with_no_db_row_not_credited(self):
        """A fabricated `forensicrag-…` id that resolves to NO DB row gets zero
        credit — the old prefix-shape fallback (a grading backdoor) is gone."""
        g = _grounding([], _finding(audit_ids=["forensicrag-deadbeef-20260101-001"]))
        assert g["sources_count"] == 0
        assert _KB not in g.get("sources_consulted", [])

    def test_cited_id_for_wrong_backend_not_credited(self):
        """Citing a real run_command id cannot inflate grounding by name-shape."""
        rows = [_audit_row("rc-1", tool="run_command", backend="sift-core")]
        g = _grounding(rows, _finding(audit_ids=["rc-1", "kb-not-in-db"]))
        assert g["sources_count"] == 0


# --------------------------------------------------------------------------- #
# DB-mode integration fixture (supersedes / surface / allowlist guard).
# --------------------------------------------------------------------------- #
class _CapturingStore:
    def __init__(self):
        self.findings: dict = {}
        self.timeline: dict = {}
        self.iocs: dict = {}
        self.todos: dict = {}
        self.order: list[str] = []

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        if item_id not in self.findings:
            self.order.append(item_id)
        self.findings[item_id] = dict(payload)
        return {"applied": True}

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        self.timeline[item_id] = dict(payload)
        return {"applied": True}

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        self.iocs[item_id] = dict(payload)
        return {"applied": True}

    def upsert_todo(self, case_id, item_id, payload, *, actor=None):
        self.todos[item_id] = dict(payload)
        return {"applied": True}

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return list(self.timeline.values())

    def list_iocs(self, case_id):
        return list(self.iocs.values())

    def list_todos(self, case_id):
        return list(self.todos.values())

    def last(self) -> dict:
        return self.findings[self.order[-1]]


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    from sift_core.active_case_context import AuthorityContext, use_active_case_context

    case_dir = tmp_path / "case-grd-db"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-grd-db\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-grd-db", "status": "open"},
    )
    state: dict = {"audit": [], "sealed": []}
    store = _CapturingStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.list_audit_provenance_db",
        lambda cid: list(state["audit"]),
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_sealed_evidence_db",
        lambda cid: list(state["sealed"]),
    )
    monkeypatch.setattr(cm, "_declared_reference_backends", lambda: list(_REF_BACKENDS))
    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-grd-db",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, state, case_dir


# --------------------------------------------------------------------------- #
# supersedes: normalized to a deduped list, persisted + surfaced.
# --------------------------------------------------------------------------- #
class TestSupersedes:
    def test_supersedes_persisted_and_surfaced(self, db_manager):
        mgr, store, state, _ = db_manager
        state["audit"] = [_audit_row("rc-1", tool="run_command", backend="sift-core",
                                     evidence_refs=["ev-1"])]
        res = mgr.record_finding(
            _finding(audit_ids=["rc-1"], supersedes="F-alice-003"),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        assert res.get("supersedes") == ["F-alice-003"]
        assert store.last().get("supersedes") == ["F-alice-003"]

    def test_supersedes_list_deduped(self, db_manager):
        mgr, store, state, _ = db_manager
        state["audit"] = [_audit_row("rc-1", tool="run_command", backend="sift-core",
                                     evidence_refs=["ev-1"])]
        res = mgr.record_finding(
            _finding(audit_ids=["rc-1"],
                     supersedes=["F-alice-003", "F-alice-003", "F-alice-001"]),
            examiner_override="alice",
        )
        assert res.get("supersedes") == ["F-alice-003", "F-alice-001"]


# --------------------------------------------------------------------------- #
# Surface seam (fail-on-revert): the record_finding result dict carries the
# two-axis grading; agent_tools._record_finding must NOT recompute grounding.
# --------------------------------------------------------------------------- #
class TestSurface:
    def test_record_finding_result_surfaces_two_axis(self, db_manager, tmp_path):
        mgr, store, state, _ = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-1"]),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_system", backend=_WT),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-1", "path": "evidence/d.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        audit = AuditWriter("sift-core", audit_dir=str(tmp_path / "audit"))
        finding = _finding("HIGH", audit_ids=["rc-1", "kb-1", "wt-1"])
        result = _record_finding(
            {"finding": finding}, examiner="alice", manager=mgr, audit=audit
        )
        assert result.get("status") == "STAGED", result
        # The MCP surface seam: these three keys must be present on the result.
        assert result.get("provenance_grade") == "REFERENCED"
        grounding = result.get("grounding")
        assert grounding is not None and grounding.get("sources_count") == 2
        cd = result.get("confidence_derivation")
        assert cd is not None and "clamped" in cd
        assert cd["final"] == "HIGH" and cd["clamped"] is False

    def test_clamp_surfaces_guidance(self, db_manager, tmp_path):
        mgr, store, state, _ = db_manager
        # engaged but zero grounding -> HIGH clamps to LOW -> guidance surfaced.
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-1"]),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-1", "path": "evidence/d.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        audit = AuditWriter("sift-core", audit_dir=str(tmp_path / "audit"))
        result = _record_finding(
            {"finding": _finding("HIGH", audit_ids=["rc-1"])},
            examiner="alice", manager=mgr, audit=audit,
        )
        assert result["confidence_derivation"]["clamped"] is True
        assert "confidence_guidance" in result


# --------------------------------------------------------------------------- #
# Field allowlist guard: agent cannot pre-seed grading fields.
# --------------------------------------------------------------------------- #
class TestAllowlistGuard:
    def test_allowlist_excludes_grading_fields(self):
        for k in ("grounding", "provenance_grade", "confidence_derivation",
                  "source_evidence"):
            assert k not in _ALLOWED_FINDING_FIELDS, k

    def test_agent_seeded_grading_fields_are_stripped(self, db_manager):
        mgr, store, state, _ = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-1"]),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-1", "path": "evidence/real.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        finding = _finding("MEDIUM", audit_ids=["rc-1", "kb-1"])
        # Agent attempts to pre-seed server-owned grading fields.
        finding["grounding"] = {"level": "HIGH", "sources_count": 99}
        finding["provenance_grade"] = "HACKED"
        finding["confidence_derivation"] = {"final": "HIGH", "clamped": False}
        finding["source_evidence"] = "/etc/passwd"
        res = mgr.record_finding(finding, examiner_override="alice")
        assert res["status"] == "STAGED", res
        f = store.last()
        # Server values win; the agent's forged values are gone.
        assert f["provenance_grade"] == "REFERENCED"
        assert f["grounding"]["sources_count"] == 1  # server-computed (kb only)
        assert f["confidence_derivation"]["basis"]["grounding_count"] == 1
        assert f.get("source_evidence", "") == "evidence/real.E01"
        assert f.get("source_evidence") != "/etc/passwd"
