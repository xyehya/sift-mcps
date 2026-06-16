"""AUT2-B3: record_finding artifact audit_id validation.

Fresh ``run_command`` audit ids must validate immediately even when the audit
JSONL was written by another process into a different (but plausible) audit dir,
when the agent cites the ``rc-<audit_id>`` receipt form, or when only the DB
transport audit authority (``app.audit_events``) recorded the call. Genuinely
unknown ids stay rejected (fail closed).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import sift_core.case_manager as cm
from sift_core.case_io import case_audit_dir, case_records_dir
from sift_core.case_manager import CaseManager

AUDIT_ID = "siftcore-alice-20260610-001"
CASE_UUID = "22222222-2222-2222-2222-222222222222"


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
    """Seed a minimal sealed manifest so artifact sources pass the registry gate."""
    records = case_records_dir(case_dir)
    records.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence").mkdir(exist_ok=True)
    (case_dir / "evidence" / "auth.log").write_text("log line\n")
    manifest = {
        "files": [
            {
                "path": "evidence/auth.log",
                "sha256": "0" * 64,
                "status": "SEALED",
            }
        ]
    }
    (records / "evidence-manifest.json").write_text(json.dumps(manifest))


def _finding(audit_id: str) -> dict:
    return {
        "title": "Suspicious logon burst",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "confidence_justification": "single corroborated source",
        "event_timestamp": "2026-06-10T00:00:00Z",
        "artifacts": [
            {
                "source": "evidence/auth.log",
                "extraction": "grep failed logons",
                "content": "Failed password for root",
                "audit_id": audit_id,
            }
        ],
    }


@pytest.fixture
def file_manager(tmp_path, monkeypatch):
    """File-mode CaseManager with an active tmp case (no DB authority)."""
    case_dir = tmp_path / "case-aut2"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-aut2\nstatus: active\n")
    _register_evidence(case_dir)
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    return CaseManager(), case_dir


class TestJsonlScanBroadening:
    def test_accepts_audit_id_from_state_root_audit_dir(self, file_manager):
        mgr, case_dir = file_manager
        _write_audit_entry(case_audit_dir(case_dir), AUDIT_ID)
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "STAGED", res

    def test_accepts_audit_id_from_in_case_audit_dir(self, file_manager):
        """Audit written to the in-case audit/ dir by another process validates."""
        mgr, case_dir = file_manager
        _write_audit_entry(case_dir / "audit", AUDIT_ID)
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "STAGED", res

    def test_accepts_audit_id_from_env_audit_dir(self, file_manager, tmp_path, monkeypatch):
        mgr, case_dir = file_manager
        env_dir = tmp_path / "env-audit"
        monkeypatch.setenv("SIFT_AUDIT_DIR", str(env_dir))
        _write_audit_entry(env_dir, AUDIT_ID)
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "STAGED", res

    def test_accepts_rc_receipt_form_and_canonicalizes(self, file_manager):
        mgr, case_dir = file_manager
        _write_audit_entry(case_audit_dir(case_dir), AUDIT_ID)
        res = mgr.record_finding(_finding(f"rc-{AUDIT_ID}"), examiner_override="alice")
        assert res["status"] == "STAGED", res
        findings = json.loads((case_dir / "findings.json").read_text())
        art = findings[-1]["artifacts"][0]
        assert art["audit_id"] == AUDIT_ID  # rc- receipt canonicalized

    def test_rejects_unknown_audit_id_with_recent_hint(self, file_manager):
        mgr, case_dir = file_manager
        _write_audit_entry(case_audit_dir(case_dir), AUDIT_ID)
        res = mgr.record_finding(
            _finding("siftcore-alice-20260610-999"), examiner_override="alice"
        )
        assert res["status"] == "REJECTED"
        assert "not found in audit trail" in res["error"]
        assert AUDIT_ID in res["error"]  # actionable: lists known-good recent ids

    def test_rejects_missing_audit_id(self, file_manager):
        mgr, _ = file_manager
        finding = _finding(AUDIT_ID)
        finding["artifacts"][0].pop("audit_id")
        res = mgr.record_finding(finding, examiner_override="alice")
        assert res["status"] == "REJECTED"
        assert "missing audit_id" in res["error"]


class _InMemoryStore:
    def __init__(self):
        self.findings = {}
        self.timeline = {}
        self.iocs = {}
        self.todos = {}

    def _up(self, bucket, item_id, payload):
        bucket[item_id] = dict(payload)
        return {"applied": True}

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        return self._up(self.findings, item_id, payload)

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        return self._up(self.timeline, item_id, payload)

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        return self._up(self.iocs, item_id, payload)

    def upsert_todo(self, case_id, todo_id, payload, *, actor=None):
        return self._up(self.todos, todo_id, payload)

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return list(self.timeline.values())

    def list_iocs(self, case_id):
        return list(self.iocs.values())

    def list_todos(self, case_id):
        return list(self.todos.values())


@pytest.fixture
def db_active_manager(tmp_path, monkeypatch):
    """CaseManager under a DB-active AuthorityContext with an in-memory store."""
    from sift_core.active_case_context import AuthorityContext, use_active_case_context

    case_dir = tmp_path / "case-aut2-db"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-aut2-db\nstatus: active\n")
    _register_evidence(case_dir)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://test")

    store = _InMemoryStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    # BU1: _require_active_case now resolves the closed-case safety belt from DB
    # authority. Provide a non-closed DB case row so the gate passes without a
    # real Postgres connection (the dummy DSN above is never dialed).
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-aut2-db", "status": "open"},
    )

    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-aut2-db",
        artifact_path=str(case_dir),
        db_active=True,
    )
    mgr = CaseManager()
    with use_active_case_context(ctx):
        yield mgr, store, case_dir


class TestDbAuditAuthority:
    def test_accepts_audit_id_recorded_in_db_audit_events(
        self, db_active_manager, monkeypatch
    ):
        """No JSONL anywhere, but app.audit_events recorded the tool call."""
        mgr, store, case_dir = db_active_manager
        calls: list[tuple[str, str, list[str]]] = []

        def fake_db_lookup(dsn, case_id, candidates):
            calls.append((dsn, case_id, list(candidates)))
            return AUDIT_ID in candidates

        monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", fake_db_lookup)
        res = mgr.record_finding(_finding(f"rc-{AUDIT_ID}"), examiner_override="alice")
        assert res["status"] == "STAGED", res
        dsn, case_id, candidates = calls[0]
        assert dsn == "postgresql://test"
        assert case_id == CASE_UUID
        # Both the receipt form and the stripped base id were checked.
        assert f"rc-{AUDIT_ID}" in candidates
        assert AUDIT_ID in candidates
        # Canonicalized id landed on the DB-stored finding artifact.
        staged = next(iter(store.findings.values()))
        assert staged["artifacts"][0]["audit_id"] == AUDIT_ID

    def test_unknown_id_still_rejected_when_db_has_no_record(
        self, db_active_manager, monkeypatch
    ):
        mgr, _, _ = db_active_manager
        monkeypatch.setattr(
            cm, "_db_audit_event_has_audit_id", lambda *a, **k: False
        )
        res = mgr.record_finding(
            _finding("siftcore-alice-20260610-777"), examiner_override="alice"
        )
        assert res["status"] == "REJECTED"
        assert "not found in audit trail" in res["error"]

    def test_db_lookup_failure_fails_closed(self, db_active_manager, monkeypatch):
        mgr, _, _ = db_active_manager

        def boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr(cm, "_db_audit_event_has_audit_id", boom)
        res = mgr.record_finding(_finding(AUDIT_ID), examiner_override="alice")
        assert res["status"] == "REJECTED"


class TestCandidateAuditDirs:
    def test_dirs_cover_state_root_in_case_and_env(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case-dirs"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: case-dirs\n")
        monkeypatch.setenv("SIFT_AUDIT_DIR", str(tmp_path / "explicit-audit"))
        dirs = CaseManager()._candidate_audit_dirs(case_dir)
        assert case_audit_dir(case_dir) in dirs
        assert (case_dir / "audit") in dirs
        assert (tmp_path / "explicit-audit") in dirs
        # Deduped
        assert len(dirs) == len({str(d) for d in dirs})
