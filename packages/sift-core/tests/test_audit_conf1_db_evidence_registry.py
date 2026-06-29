"""AUDIT-CONF-1 (two-axis rebuild): DB evidence registry + audit trail drive
the REFERENCED/UNREFERENCED provenance grade and the display `source_evidence`.

The legacy false-PARTIAL bug (building `registered` from an empty file manifest)
is moot: there is no per-artifact FULL/PARTIAL path-walk anymore. Instead:
  - a cited run_command carrying a gateway `evidence_ref` that hits a sealed
    evidence_id ⇒ Axis A engaged ⇒ provenance_grade=REFERENCED + source_evidence;
  - a cited opensearch_* result ⇒ Axis A engaged ⇒ REFERENCED;
  - neither ⇒ UNREFERENCED;
  - a cited artifact audit_id that does not resolve in the DB trail ⇒ REJECTED
    (fail-closed; DB outage yields an empty trail).

Layer-2 unit tests for the two DB readers (`list_sealed_evidence_db` /
`list_audit_provenance_db`) are unchanged — those functions were not modified.
"""

from __future__ import annotations

import pytest
import sift_core.case_manager as cm
from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.case_manager import CaseManager

CASE_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
E01_REL = "evidence/rocba-cdrive.e01"
E01_SHA256 = "a" * 64  # bare hex
EVID_ID = "486ef9e2-1111-2222-3333-444444444444"
GW_AUDIT_ID = "siftgateway-claude-20260625-003"
_KB = "forensic-rag-mcp"


def _audit_row(audit_id, *, tool, backend="", evidence_refs=None, aliases=None):
    return {
        "audit_id": audit_id,
        "tool": tool,
        "backend": backend,
        "evidence_refs": list(evidence_refs or []),
        "audit_aliases": list(aliases or [audit_id]),
        "envelope_event_id": "",
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


def _finding_with_artifact(audit_id: str) -> dict:
    return {
        "title": "RDP lateral movement",
        "type": "finding",
        "host": "WS01",
        "observation": "RDP login from 10.1.1.50 in the sealed E01",
        "interpretation": "Attacker pivoted via RDP",
        "confidence": "HIGH",
        "confidence_justification": "ewfinfo over sealed E01, gateway-resolved evidence_ref",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "artifacts": [
            {
                "source": E01_REL,
                "extraction": "ewfinfo",
                "content": "EWF metadata",
                "audit_id": audit_id,
            }
        ],
    }


class _InMemoryStore:
    def __init__(self):
        self.findings: dict = {}

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        self.findings[item_id] = dict(payload)
        return {"applied": True}

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        return {"applied": True}

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        return {"applied": True}

    def upsert_todo(self, case_id, todo_id, payload, *, actor=None):
        return {"applied": True}

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return []

    def list_iocs(self, case_id):
        return []

    def list_todos(self, case_id):
        return []


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    """CaseManager in DB-active mode; the DB readers are faked via `state`."""
    case_dir = tmp_path / "case-conf1"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-conf1\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)

    state: dict = {"audit": [], "sealed": []}
    store = _InMemoryStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-conf1", "status": "open"},
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_audit_provenance_db",
        lambda cid: list(state["audit"]),
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_sealed_evidence_db",
        lambda cid: list(state["sealed"]),
    )
    monkeypatch.setattr(cm, "_declared_reference_backends", lambda: [_KB])

    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-conf1",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, state


# ---------------------------------------------------------------------------
# Layer-1 integration: REFERENCED grade + source_evidence + fail-closed.
# ---------------------------------------------------------------------------


class TestReferencedGradeAndSourceEvidence:
    def test_run_command_evidence_ref_grades_referenced(self, db_manager):
        """A cited run_command with a gateway evidence_ref to a sealed object ⇒
        REFERENCED + source_evidence resolved (display path)."""
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row(GW_AUDIT_ID, tool="run_command", backend="sift-core",
                       evidence_refs=[EVID_ID])
        ]
        state["sealed"] = [
            {"evidence_id": EVID_ID, "path": E01_REL, "sha256": E01_SHA256,
             "status": "sealed"}
        ]
        res = mgr.record_finding(
            _finding_with_artifact(GW_AUDIT_ID), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        f = next(iter(store.findings.values()))
        assert f["provenance_grade"] == "REFERENCED"
        assert f.get("source_evidence") == E01_REL
        assert f["confidence_derivation"]["basis"]["evidence_engaged"] is True

    def test_opensearch_citation_grades_referenced(self, db_manager):
        """A cited opensearch_* result engages Axis A directly (no trace needed)."""
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("os-1", tool="opensearch_search", backend="opensearch-mcp")
        ]
        finding = _finding_with_artifact("os-1")
        res = mgr.record_finding(finding, examiner_override="alice")
        assert res["status"] == "STAGED", res
        f = next(iter(store.findings.values()))
        assert f["provenance_grade"] == "REFERENCED"

    def test_foreign_ref_does_not_engage_evidence(self, db_manager):
        """An evidence_ref NOT in the sealed registry cannot set source_evidence;
        the run_command still engages Axis A (it read *some* sealed evidence), but
        source_evidence stays empty for the unknown id."""
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row(GW_AUDIT_ID, tool="run_command", backend="sift-core",
                       evidence_refs=["ffffffff-dead-beef-0000-000000000000"])
        ]
        state["sealed"] = [
            {"evidence_id": EVID_ID, "path": E01_REL, "sha256": E01_SHA256,
             "status": "sealed"}
        ]
        res = mgr.record_finding(
            _finding_with_artifact(GW_AUDIT_ID), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        f = next(iter(store.findings.values()))
        # engaged (run_command carried refs) but the foreign ref doesn't resolve
        # to a sealed display path.
        assert f["provenance_grade"] == "REFERENCED"
        assert f.get("source_evidence", "") == ""

    def test_run_command_without_refs_is_unreferenced(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row(GW_AUDIT_ID, tool="run_command", backend="sift-core")
        ]
        res = mgr.record_finding(
            _finding_with_artifact(GW_AUDIT_ID), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        f = next(iter(store.findings.values()))
        assert f["provenance_grade"] == "UNREFERENCED"
        assert f["confidence"] == "LOW"  # not engaged -> floor


class TestFailClosed:
    def test_empty_trail_rejects_cited_artifact(self, db_manager):
        """DB outage / empty trail ⇒ the artifact audit_id does not resolve ⇒
        REJECTED (fail-closed; never staged on an unverifiable citation)."""
        mgr, store, state = db_manager
        state["audit"] = []  # nothing resolves
        res = mgr.record_finding(
            _finding_with_artifact(GW_AUDIT_ID), examiner_override="alice"
        )
        assert res["status"] == "REJECTED", res
        assert "not found in audit trail" in res["error"]

    def test_db_read_error_fails_closed(self, db_manager, monkeypatch):
        """list_audit_provenance_db raising ⇒ _scan_audit_trail returns empty ⇒
        cited artifact rejected (no crash, no fail-open)."""
        mgr, store, state = db_manager

        def boom(cid):
            raise RuntimeError("simulated DB outage")

        monkeypatch.setattr(
            "sift_core.investigation_store.list_audit_provenance_db", boom
        )
        res = mgr.record_finding(
            _finding_with_artifact(GW_AUDIT_ID), examiner_override="alice"
        )
        assert res["status"] == "REJECTED", res


# ---------------------------------------------------------------------------
# Layer-2 unit tests: list_sealed_evidence_db (DB reader unchanged).
# ---------------------------------------------------------------------------


class TestListSealedEvidenceDbUnit:
    def test_empty_case_id_returns_empty(self):
        from sift_core.investigation_store import list_sealed_evidence_db

        assert list_sealed_evidence_db("") == []
        assert list_sealed_evidence_db(None) == []  # type: ignore[arg-type]

    def test_missing_dsn_returns_empty(self, monkeypatch):
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
        assert list_sealed_evidence_db(CASE_UUID) == []

    def test_strips_sha256_prefix(self, monkeypatch):
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")

        class _FakeCur:
            def __init__(self, rows):
                self._rows = rows

            def execute(self, sql, params):
                pass

            def fetchall(self):
                return self._rows

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        class _FakeConn:
            def __init__(self, rows):
                self._rows = rows

            def cursor(self):
                return _FakeCur(self._rows)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        monkeypatch.setattr(
            "psycopg.connect",
            lambda dsn, **kw: _FakeConn(
                [("486ef9e2-0000-0000-0000-000000000001",
                  "evidence/rocba-cdrive.e01", f"sha256:{'b' * 64}")]
            ),
        )

        rows = list_sealed_evidence_db(CASE_UUID)
        assert len(rows) == 1
        assert rows[0]["sha256"] == "b" * 64
        assert rows[0]["path"] == "evidence/rocba-cdrive.e01"
        assert rows[0]["status"] == "sealed"
        assert rows[0]["evidence_id"] == "486ef9e2-0000-0000-0000-000000000001"

    def test_db_error_returns_empty_list(self, monkeypatch):
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")

        def _boom(dsn, **kw):
            raise OSError("connection refused")

        monkeypatch.setattr("psycopg.connect", _boom)
        assert list_sealed_evidence_db(CASE_UUID) == []

    def test_row_with_null_display_path_skipped(self, monkeypatch):
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")

        class _FakeCur:
            def execute(self, sql, params):
                pass

            def fetchall(self):
                return [
                    ("evid-null", None, f"sha256:{'d' * 64}"),
                    ("evid-ok", "evidence/ok.e01", f"sha256:{'e' * 64}"),
                ]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        class _FakeConn:
            def cursor(self):
                return _FakeCur()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        monkeypatch.setattr("psycopg.connect", lambda dsn, **kw: _FakeConn())

        rows = list_sealed_evidence_db(CASE_UUID)
        assert len(rows) == 1
        assert rows[0]["path"] == "evidence/ok.e01"


# ---------------------------------------------------------------------------
# Layer-2 unit tests: list_audit_provenance_db (DB reader unchanged).
# ---------------------------------------------------------------------------


def _result_details(audit_id: str, evidence_refs: list[str]) -> dict:
    return {
        "tool": "run_command",
        "backend": "siftgateway",
        "audit_aliases": [audit_id, "envelope-uuid-aaaa"],
        "backend_audit_id": audit_id,
        "envelope_event_id": "envelope-uuid-aaaa",
        "detail": {"provenance": {"evidence_refs": evidence_refs}},
        "result_summary": {"exit_code": 0},
    }


def _make_fake_conn(rows):
    class _FakeCur:
        def execute(self, sql, params):
            pass

        def fetchall(self):
            return rows

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    class _FakeConn:
        def cursor(self):
            return _FakeCur()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    return _FakeConn()


class TestListAuditProvenanceDbUnit:
    def test_empty_case_id_returns_empty(self):
        from sift_core.investigation_store import list_audit_provenance_db

        assert list_audit_provenance_db("") == []
        assert list_audit_provenance_db(None) == []  # type: ignore[arg-type]

    def test_missing_dsn_returns_empty(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
        assert list_audit_provenance_db(CASE_UUID) == []

    def test_parses_result_row_with_evidence_refs(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        details = _result_details("siftgateway-claude-20260625-003", [EVID_ID])
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([(details,)])
        )

        rows = list_audit_provenance_db(CASE_UUID)
        assert len(rows) == 1
        e = rows[0]
        assert e["audit_id"] == "siftgateway-claude-20260625-003"
        assert e["tool"] == "run_command"
        assert e["evidence_refs"] == [EVID_ID]
        assert e["input_files"] == []
        assert e["case_id"] == CASE_UUID
        assert "envelope-uuid-aaaa" in e["audit_aliases"]
        assert e["envelope_event_id"] == "envelope-uuid-aaaa"

    def test_skips_row_without_backend_audit_id(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        details = {"tool": "run_command",
                   "detail": {"provenance": {"evidence_refs": [EVID_ID]}}}
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([(details,)])
        )
        assert list_audit_provenance_db(CASE_UUID) == []

    def test_missing_provenance_yields_empty_refs(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        details = {"tool": "run_command",
                   "backend_audit_id": "siftgateway-claude-20260625-009"}
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([(details,)])
        )
        rows = list_audit_provenance_db(CASE_UUID)
        assert len(rows) == 1
        assert rows[0]["evidence_refs"] == []

    def test_db_error_returns_empty_list(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")

        def _boom(dsn, **kw):
            raise OSError("connection refused")

        monkeypatch.setattr("psycopg.connect", _boom)
        assert list_audit_provenance_db(CASE_UUID) == []

    def test_non_dict_details_skipped(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([("not a dict",)])
        )
        assert list_audit_provenance_db(CASE_UUID) == []

    def test_ingest_row_populates_input_files_and_params(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        details = {
            "backend_audit_id": "opensearchingest-evtx-001",
            "tool": "ingest_evtx",
            "hostname": "WS01",
            "input_files": ["evidence/triage/WS01/Security.evtx"],
            "result_summary": "1000 indexed",
        }
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([(details,)])
        )
        rows = list_audit_provenance_db(CASE_UUID)
        assert len(rows) == 1
        e = rows[0]
        assert e["tool"] == "ingest_evtx"
        assert e["input_files"] == ["evidence/triage/WS01/Security.evtx"]
        assert e["params"]["hostname"] == "WS01"
        assert e["params"]["hosts"] == ["WS01"]

    def test_ingest_row_without_input_files_stays_empty(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        details = {
            "backend_audit_id": "opensearchingest-evtx-002",
            "tool": "ingest_evtx",
            "hostname": "WS01",
            "result_summary": "1000 indexed",
        }
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([(details,)])
        )
        rows = list_audit_provenance_db(CASE_UUID)
        assert rows[0]["input_files"] == []
