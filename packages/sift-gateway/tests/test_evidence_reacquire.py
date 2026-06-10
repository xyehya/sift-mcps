"""Re-acquisition (operator re-seal of a legitimately changed evidence item).

Exercises ``EvidenceAuthorityService.reacquire()`` and the ``_ensure_registered``
hardening without a live database. A fake psycopg connection routes SQL by
substring and returns scripted rows (same pattern as
``test_evidence_proof_export.py``), so we can assert:

- reacquire() hashes the mounted replacement, calls ``app.evidence_reacquire``
  with the freshly computed hash + reason + reauth id, and returns a cleared
  (sealed) chain head.
- reacquire() of a missing file raises ``evidence_file_missing_cannot_reacquire``
  (the operator must retire, not re-acquire) and never calls the RPC.
- reacquire() of an unknown display path raises ``evidence_object_not_found``.
- _ensure_registered() never re-registers an already sealed/violated item (the
  bug that made the seal path crash on a violated object) but still registers a
  detected item.
"""

from __future__ import annotations

import hashlib

import pytest

import sift_gateway.portal_services as ps
from sift_gateway.portal_services import EvidenceAuthorityService, PortalServiceError


_CASE = "11111111-1111-1111-1111-111111111111"


class _Cursor:
    def __init__(self, conn):
        self.conn = conn
        self._last = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.statements.append((" ".join(sql.split()), params))
        self._last = self.conn.router(sql, params)

    def fetchone(self):
        rows = self._last or []
        return rows[0] if rows else None

    def fetchall(self):
        return list(self._last or [])


class _Connection:
    def __init__(self, router, statements):
        self.router = router
        self.statements = statements
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.commits += 1


class _FakeDb:
    """Scripted DB backing the service. Returns rows keyed by SQL substring."""

    def __init__(self):
        self.statements: list = []
        self.evidence_id: str | None = "ev-obj-1"
        self.object_status = "violated"
        self.manifest_version = 4
        self.head_seal_status = "sealed"  # aggregate head AFTER re-acquire
        self.reacquire_calls: list = []
        self.register_calls: list = []

    def router(self, sql, params):
        s = " ".join(sql.split())
        if "app.evidence_reacquire(" in s:
            self.reacquire_calls.append(params)
            return [(
                _CASE, self.manifest_version + 1, 30, "sha256:" + "a" * 64,
                "sha256:" + "b" * 64, self.head_seal_status, 5, [],
                "MANIFEST_SEALED", None,
            )]
        if "from app.evidence_objects where case_id = %s and display_path = %s" in s:
            return [(self.evidence_id,)] if self.evidence_id else []
        if "select status from app.evidence_objects where id = %s" in s:
            return [(self.object_status,)] if self.object_status else []
        if "from app.evidence_gate_status" in s and "manifest_version" in s:
            return [(self.manifest_version,)]
        if "app.evidence_detect" in s:
            return [(self.evidence_id,)]
        if "app.evidence_register(" in s:
            self.register_calls.append(params)
            return [(self.evidence_id,)]
        return []


@pytest.fixture
def service(monkeypatch, tmp_path):
    db = _FakeDb()

    def fake_connect(self):
        return _Connection(db.router, db.statements)

    monkeypatch.setattr(ps._BasePortalDbService, "_connect", fake_connect)
    svc = EvidenceAuthorityService("postgresql://service@localhost/sift")
    monkeypatch.setattr(svc, "_case_artifact_path", lambda case_id: tmp_path)
    (tmp_path / "evidence").mkdir()
    return svc, db, tmp_path


class TestReacquire:
    def test_reacquire_clears_violation_with_new_hash(self, service):
        svc, db, tmp_path = service
        content = b"RE-IMAGED-MEMORY-BYTES" * 1000
        (tmp_path / "evidence" / "Rocba-Memory.raw").write_bytes(content)
        new_sha = "sha256:" + hashlib.sha256(content).hexdigest()

        result = svc.reacquire(
            case_id=_CASE,
            display_path="evidence/Rocba-Memory.raw",
            reason="Original acquisition corrupted; re-imaged from source",
            reauth_audit_event_id="reauth-1",
            actor=None,
            examiner="codex",
        )

        # The aggregate head returned is no longer violated.
        assert result["seal_status"] == "sealed"
        assert result["display_path"] == "evidence/Rocba-Memory.raw"
        assert result["sha256"] == new_sha
        assert result["bytes"] == len(content)
        # The RPC carried the object id, case, the freshly computed hash/bytes,
        # the operator reason, and the reauth id (positional SQL order).
        assert db.reacquire_calls, "expected an app.evidence_reacquire call"
        call = db.reacquire_calls[-1]
        assert call[0] == db.evidence_id
        assert call[1] == _CASE
        assert call[2] == new_sha
        assert call[3] == len(content)
        assert call[6] == "Original acquisition corrupted; re-imaged from source"
        assert call[7] == "reauth-1"

    def test_reacquire_missing_file_raises_retire_hint(self, service):
        svc, db, tmp_path = service
        # No bytes on disk -> nothing to hash -> operator must retire instead.
        with pytest.raises(PortalServiceError) as ei:
            svc.reacquire(
                case_id=_CASE,
                display_path="evidence/Rocba-Memory.raw",
                reason="re-image",
                reauth_audit_event_id="reauth-1",
                actor=None,
                examiner="codex",
            )
        assert ei.value.reason == "evidence_file_missing_cannot_reacquire"
        assert ei.value.http_status == 409
        assert not db.reacquire_calls

    def test_reacquire_unknown_object_raises(self, service):
        svc, db, tmp_path = service
        db.evidence_id = None  # display path not registered in the case
        (tmp_path / "evidence" / "ghost.raw").write_bytes(b"x")
        with pytest.raises(PortalServiceError) as ei:
            svc.reacquire(
                case_id=_CASE,
                display_path="evidence/ghost.raw",
                reason="re-image",
                reauth_audit_event_id="reauth-1",
                actor=None,
                examiner="codex",
            )
        assert ei.value.reason == "evidence_object_not_found"
        assert not db.reacquire_calls


class TestEnsureRegisteredRobustness:
    def test_sealed_object_not_reregistered(self, service):
        svc, db, tmp_path = service
        db.evidence_id = "ev-sealed"
        db.object_status = "sealed"
        out = svc._ensure_registered(
            _CASE, "evidence/disk.e01",
            display_name="disk.e01", description=None, source=None,
            actor_user_id=None, actor_service_identity_id=None,
        )
        assert out == "ev-sealed"
        # Re-registering a sealed item raises evidence_register_invalid_state in
        # SQL and (pre-fix) crashed the seal path — it must be skipped.
        assert not db.register_calls

    def test_violated_object_not_reregistered(self, service):
        svc, db, tmp_path = service
        db.evidence_id = "ev-viol"
        db.object_status = "violated"
        out = svc._ensure_registered(
            _CASE, "evidence/disk.e01",
            display_name="disk.e01", description=None, source=None,
            actor_user_id=None, actor_service_identity_id=None,
        )
        assert out == "ev-viol"
        assert not db.register_calls

    def test_detected_object_is_registered(self, service):
        svc, db, tmp_path = service
        db.evidence_id = "ev-det"
        db.object_status = "detected"
        out = svc._ensure_registered(
            _CASE, "evidence/disk.e01",
            display_name="disk.e01", description="d", source="s",
            actor_user_id=None, actor_service_identity_id=None,
        )
        assert out == "ev-det"
        assert db.register_calls, "a detected object must still be registered"
