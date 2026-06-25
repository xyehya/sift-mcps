"""AUDIT-CONF-1: provenance confidence grading reads DB evidence registry in
DB-authority mode.

Root cause: when db_authority_active() is True, the on-disk evidence.json is
``{"files": []}`` — the real sealed registry lives in ``app.evidence_objects``.
``record_finding`` was building ``registered`` from the empty file manifest, so
confidence was always PARTIAL and every artifact was hard-rejected as
"Artifact sources not in evidence registry".

Fix: in DB-authority mode, load sealed evidence from Postgres via
``list_sealed_evidence_db(case_id)`` (investigation_store.py).

Tests here:
1. DB mode — list_sealed_evidence_db returns a sealed E01 → artifact grades FULL
   and finding is STAGED (not rejected).
2. DB mode — DB error in list_sealed_evidence_db → empty registered → artifact
   rejected (fail-closed; no crash).
3. list_sealed_evidence_db unit: happy path returns correct shaped entries.
4. list_sealed_evidence_db unit: strips sha256: prefix correctly.
5. list_sealed_evidence_db unit: empty case_id → [] (no DB dial).
6. list_sealed_evidence_db unit: missing DSN → [] (no DB dial).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import sift_core.case_manager as cm
from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.case_io import case_audit_dir, case_records_dir
from sift_core.case_manager import CaseManager

CASE_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
AUDIT_ID = "siftcore-alice-20260625-001"
E01_REL = "evidence/rocba-cdrive.e01"
E01_SHA256 = "a" * 64  # bare hex


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_audit_entry(
    audit_dir: Path,
    audit_id: str,
    input_files: list[str] | None = None,
) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    entry: dict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "mcp": "sift-core",
        "tool": "run_command",
        "audit_id": audit_id,
        "examiner": "alice",
    }
    if input_files is not None:
        entry["input_files"] = input_files
    with open(audit_dir / "sift-core.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _empty_file_manifest(case_dir: Path) -> None:
    """Simulate DB-authority mode: on-disk evidence.json has no files."""
    records = case_records_dir(case_dir)
    records.mkdir(parents=True, exist_ok=True)
    (records / "evidence-manifest.json").write_text(json.dumps({"files": []}))


def _make_e01(case_dir: Path) -> Path:
    ev_dir = case_dir / "evidence"
    ev_dir.mkdir(exist_ok=True)
    e01 = ev_dir / "rocba-cdrive.e01"
    e01.write_bytes(b"\x00" * 8)
    return e01


def _finding_with_artifact(case_dir: Path, audit_id: str, e01_abs: str) -> dict:
    return {
        "title": "RDP lateral movement",
        "type": "finding",
        "host": "WS01",
        "observation": "RDP login from 10.1.1.50",
        "interpretation": "Attacker pivoted via RDP",
        "confidence": "HIGH",
        "confidence_justification": "Direct event-log evidence from sealed E01",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "artifacts": [
            {
                "source": e01_abs,
                "extraction": "fls -r",
                "content": "found artefact",
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
    """CaseManager in DB-active mode. on-disk manifest is empty."""
    case_dir = tmp_path / "case-conf1"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        f"case_id: case-conf1\nstatus: active\n"
    )
    _empty_file_manifest(case_dir)

    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://test-dsn-never-dialed")

    store = _InMemoryStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-conf1", "status": "open"},
    )
    # Stub out the DB audit-id lookup so artifact audit_id validation passes.
    monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", lambda *a, **k: True)

    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-conf1",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, case_dir


# ---------------------------------------------------------------------------
# ITEM-1 integration tests
# ---------------------------------------------------------------------------


class TestDbEvidenceRegistryConfidence:
    def test_db_sealed_evidence_grades_artifact_full_and_stages(
        self, db_manager, monkeypatch
    ):
        """DB-mode: list_sealed_evidence_db returns sealed E01 ⇒ FULL grade ⇒ STAGED."""
        mgr, store, case_dir = db_manager
        e01 = _make_e01(case_dir)
        e01_abs = str(e01)

        # Write audit entry that cites the E01 as input_files.
        _write_audit_entry(
            case_audit_dir(case_dir),
            AUDIT_ID,
            input_files=[e01_abs],
        )

        # Stub list_sealed_evidence_db to return the sealed E01 entry.
        sealed_ev = [
            {
                "path": E01_REL,
                "sha256": E01_SHA256,
                "status": "sealed",
            }
        ]
        monkeypatch.setattr(
            "sift_core.investigation_store.list_sealed_evidence_db",
            lambda case_id: sealed_ev,
        )

        res = mgr.record_finding(
            _finding_with_artifact(case_dir, AUDIT_ID, e01_abs),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        # Artifact should not be in unregistered_sources (no REJECTED).
        assert "unregistered_sources" not in res

    def test_db_evidence_registry_db_error_fails_closed_reject(
        self, db_manager, monkeypatch
    ):
        """DB-mode: DB error in list_sealed_evidence_db ⇒ empty registered ⇒ artifact
        rejected (fail-closed). Must NOT crash."""
        mgr, store, case_dir = db_manager
        e01 = _make_e01(case_dir)
        e01_abs = str(e01)

        _write_audit_entry(
            case_audit_dir(case_dir),
            AUDIT_ID,
            input_files=[e01_abs],
        )

        def boom(case_id):
            raise RuntimeError("simulated DB outage")

        monkeypatch.setattr("sift_core.investigation_store.list_sealed_evidence_db", boom)

        res = mgr.record_finding(
            _finding_with_artifact(case_dir, AUDIT_ID, e01_abs),
            examiner_override="alice",
        )
        # Must not crash and must reject (fail-closed — evidence not confirmed).
        assert res["status"] == "REJECTED", res
        assert "evidence registry" in res.get("error", "").lower()

    def test_file_mode_uses_manifest_not_db(self, tmp_path, monkeypatch):
        """File-mode: evidence.json manifest is used; list_sealed_evidence_db not called."""
        case_dir = tmp_path / "case-file"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: case-file\nstatus: active\n")

        # Create e01 and register it in the file manifest.
        e01 = _make_e01(case_dir)
        e01_abs = str(e01)
        records = case_records_dir(case_dir)
        records.mkdir(parents=True, exist_ok=True)
        manifest = {
            "files": [
                {"path": E01_REL, "sha256": E01_SHA256, "status": "SEALED"}
            ]
        }
        (records / "evidence-manifest.json").write_text(json.dumps(manifest))

        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
        monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)

        db_call_count = []

        def should_not_be_called(case_id):
            db_call_count.append(case_id)
            return []

        monkeypatch.setattr(
            "sift_core.investigation_store.list_sealed_evidence_db",
            should_not_be_called,
        )

        mgr = CaseManager()
        _write_audit_entry(
            case_audit_dir(case_dir),
            AUDIT_ID,
            input_files=[e01_abs],
        )
        res = mgr.record_finding(
            _finding_with_artifact(case_dir, AUDIT_ID, e01_abs),
            examiner_override="alice",
        )
        # File-mode should work and NOT call list_sealed_evidence_db.
        assert db_call_count == [], "list_sealed_evidence_db must not be called in file mode"
        assert res["status"] == "STAGED", res


# ---------------------------------------------------------------------------
# list_sealed_evidence_db unit tests (no DB required)
# ---------------------------------------------------------------------------


class TestListSealedEvidenceDbUnit:
    def test_empty_case_id_returns_empty(self):
        from sift_core.investigation_store import list_sealed_evidence_db

        assert list_sealed_evidence_db("") == []
        assert list_sealed_evidence_db(None) == []  # type: ignore[arg-type]

    def test_missing_dsn_returns_empty(self, monkeypatch):
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
        result = list_sealed_evidence_db(CASE_UUID)
        assert result == []

    def test_strips_sha256_prefix(self, monkeypatch):
        """current_sha256 = 'sha256:<hex>' → returned as bare hex."""
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
                [("486ef9e2-0000-0000-0000-000000000001", "evidence/rocba-cdrive.e01", f"sha256:{'b' * 64}")]
            ),
        )

        rows = list_sealed_evidence_db(CASE_UUID)
        assert len(rows) == 1
        assert rows[0]["sha256"] == "b" * 64
        assert rows[0]["path"] == "evidence/rocba-cdrive.e01"
        assert rows[0]["status"] == "sealed"
        assert rows[0]["evidence_id"] == "486ef9e2-0000-0000-0000-000000000001"

    def test_sha256_without_prefix_kept_as_is(self, monkeypatch):
        """current_sha256 with no prefix → returned unchanged."""
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")

        class _FakeCur:
            def execute(self, sql, params):
                pass

            def fetchall(self):
                return [("evid-1", "evidence/rocba-cdrive.e01", "c" * 64)]

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
        assert rows[0]["sha256"] == "c" * 64
        assert rows[0]["evidence_id"] == "evid-1"

    def test_db_error_returns_empty_list(self, monkeypatch):
        """Any DB exception → [] (fail-closed, no raise)."""
        from sift_core.investigation_store import list_sealed_evidence_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")

        def _boom(dsn, **kw):
            raise OSError("connection refused")

        monkeypatch.setattr("psycopg.connect", _boom)
        result = list_sealed_evidence_db(CASE_UUID)
        assert result == []

    def test_row_with_null_display_path_skipped(self, monkeypatch):
        """Rows with a null/empty display_path must be skipped."""
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
# AUDIT-CONF-1 Layer-2: list_audit_provenance_db unit tests
# ---------------------------------------------------------------------------


EVID_ID = "486ef9e2-1111-2222-3333-444444444444"


def _result_details(audit_id: str, evidence_refs: list[str]) -> dict:
    """A representative app.audit_events.details blob for an mcp.tool.result row."""
    return {
        "tool": "run_command",
        "backend": "siftgateway",
        "principal": "claude",
        "elapsed_ms": 1200,
        "audit_aliases": [audit_id, "envelope-uuid-aaaa"],
        "backend_audit_id": audit_id,
        "envelope_event_id": "envelope-uuid-aaaa",
        "detail": {
            "provenance": {
                "evidence_refs": evidence_refs,
                "input_sha256s": ["skipped:too_large"],
            }
        },
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
        details = {"tool": "run_command", "detail": {"provenance": {"evidence_refs": [EVID_ID]}}}
        monkeypatch.setattr(
            "psycopg.connect", lambda dsn, **kw: _make_fake_conn([(details,)])
        )
        assert list_audit_provenance_db(CASE_UUID) == []

    def test_missing_provenance_yields_empty_refs(self, monkeypatch):
        from sift_core.investigation_store import list_audit_provenance_db

        monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://fake")
        details = {"tool": "run_command", "backend_audit_id": "siftgateway-claude-20260625-009"}
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


# ---------------------------------------------------------------------------
# AUDIT-CONF-1 Layer-2: pure-DB evidence-ref FULL path integration tests
# ---------------------------------------------------------------------------


GW_AUDIT_ID = "siftgateway-claude-20260625-003"


def _finding_db_evidence_ref(case_dir, audit_id: str) -> dict:
    """A finding whose artifact cites a gateway audit_id; the source is the
    relative E01 path the agent passed (pre-resolution)."""
    return {
        "title": "RDP lateral movement (DB evidence-ref)",
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


class TestDbEvidenceRefFullPath:
    def _patch_db_helpers(self, monkeypatch, *, sealed_evid, audit_refs):
        """Patch both DB helpers: sealed registry + audit provenance trail."""
        sealed_ev = [
            {
                "evidence_id": sealed_evid,
                "path": E01_REL,
                "sha256": E01_SHA256,
                "status": "sealed",
            }
        ] if sealed_evid else []
        monkeypatch.setattr(
            "sift_core.investigation_store.list_sealed_evidence_db",
            lambda case_id: sealed_ev,
        )
        audit_entries = [
            {
                "audit_id": GW_AUDIT_ID,
                "tool": "run_command",
                "evidence_refs": audit_refs,
                "audit_aliases": [GW_AUDIT_ID],
                "envelope_event_id": "",
                "input_files": [],
                "result_summary": {},
                "params": {},
                "case_id": CASE_UUID,
            }
        ]
        monkeypatch.setattr(
            "sift_core.investigation_store.list_audit_provenance_db",
            lambda case_id: audit_entries,
        )

    def test_sealed_evidence_ref_grades_full_and_not_low(self, db_manager, monkeypatch):
        """Pure-DB: audit evidence_refs hits a sealed evidence_id ⇒ artifact FULL,
        source_evidence set, finding NOT clamped to LOW (reaches MEDIUM ceiling)."""
        mgr, store, case_dir = db_manager
        _make_e01(case_dir)
        # NO JSONL audit file — the trail comes entirely from the DB helper.
        self._patch_db_helpers(
            monkeypatch, sealed_evid=EVID_ID, audit_refs=[EVID_ID]
        )

        res = mgr.record_finding(
            _finding_db_evidence_ref(case_dir, GW_AUDIT_ID),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        assert "unregistered_sources" not in res

        staged = next(iter(store.findings.values()))
        art = staged["artifacts"][0]
        assert art["provenance_grade"] == "FULL", art
        assert art["source_evidence"], art
        chain = art.get("provenance_chain", [])
        assert chain and chain[0].get("role") == "evidence_ref", chain
        assert chain[0].get("evidence_id") == EVID_ID
        # Confidence ceiling: FULL + >=1 resolved MCP id → MEDIUM (not LOW).
        assert staged.get("confidence") in ("MEDIUM", "HIGH"), staged.get("confidence")

    def test_unsealed_foreign_ref_does_not_grade_full(self, db_manager, monkeypatch):
        """Pure-DB: audit cites an evidence_ref that is NOT in the sealed registry
        ⇒ artifact does NOT grade FULL; finding is rejected (source not registered)."""
        mgr, store, case_dir = db_manager
        _make_e01(case_dir)
        # Sealed registry has EVID_ID, but the audit row points at a FOREIGN id.
        self._patch_db_helpers(
            monkeypatch,
            sealed_evid=EVID_ID,
            audit_refs=["ffffffff-dead-beef-0000-000000000000"],
        )

        res = mgr.record_finding(
            _finding_db_evidence_ref(case_dir, GW_AUDIT_ID),
            examiner_override="alice",
        )
        # Foreign ref cannot grade FULL; no input_files either → artifact source
        # (relative E01 path) IS in the sealed registry by PATH, so it stages
        # PARTIAL.  The key assertion: it did NOT grade FULL via the foreign ref.
        if res["status"] == "STAGED":
            staged = next(iter(store.findings.values()))
            art = staged["artifacts"][0]
            assert art.get("provenance_grade") != "FULL", art
            assert staged.get("confidence") == "LOW", staged.get("confidence")
        else:
            assert res["status"] == "REJECTED", res

    def test_no_sealed_evidence_ref_cannot_grade_full(self, db_manager, monkeypatch):
        """Pure-DB: empty sealed registry ⇒ no evidence_id can match ⇒ not FULL."""
        mgr, store, case_dir = db_manager
        _make_e01(case_dir)
        self._patch_db_helpers(
            monkeypatch, sealed_evid="", audit_refs=[EVID_ID]
        )

        res = mgr.record_finding(
            _finding_db_evidence_ref(case_dir, GW_AUDIT_ID),
            examiner_override="alice",
        )
        # No sealed registry → registered set empty → artifact source rejected.
        if res["status"] == "STAGED":
            staged = next(iter(store.findings.values()))
            assert staged["artifacts"][0].get("provenance_grade") != "FULL"
        else:
            assert res["status"] == "REJECTED", res
