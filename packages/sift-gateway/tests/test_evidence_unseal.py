"""Operator UNSEAL transition (clear +i so sealed bytes can be replaced).

Exercises ``EvidenceAuthorityService.unseal()`` without a live database. A fake
psycopg connection routes SQL by substring and returns scripted rows (same
pattern as ``test_evidence_reacquire.py``), and ``sift_core.evidence_chain``'s
unharden/harden are monkeypatched so no chattr/CAP_LINUX_IMMUTABLE is needed.

Asserts:
- unseal() clears the immutable flag (calls unharden_sealed_evidence with the
  case dir + the case-relative path) and records the transition through
  ``app.evidence_unseal`` with the operator reason + reauth id, returning the
  contract dict (registered/unsealed/immutable=False).
- unseal() rejects a call with no re-auth id (it never touches +i or the DB).
- unseal() maps an EvidenceHardeningError from unharden to
  ``evidence_unseal_failed`` (HTTP 500) and never records the DB transition.
- unseal() of an unknown display path raises ``evidence_object_not_found``.
- unseal() of a missing-on-disk item raises (nothing to unlock).
"""

from __future__ import annotations

import pytest

import sift_gateway.portal_services as ps
from sift_gateway.portal_services import EvidenceAuthorityService, PortalServiceError

_CASE = "22222222-2222-2222-2222-222222222222"


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
    def __init__(self):
        self.statements: list = []
        self.evidence_id: str | None = "ev-obj-1"
        # Per-object status AFTER unseal (the RPC flips it to detected/unsealed).
        self.object_status = "detected"
        self.object_seal_status = "unsealed"
        # Aggregate head AFTER unseal: case drops to unsealed -> agent gate blocks.
        self.head_seal_status = "unsealed"
        self.unseal_calls: list = []

    def router(self, sql, params):
        s = " ".join(sql.split())
        if "app.evidence_unseal(" in s:
            self.unseal_calls.append(params)
            return [(self.head_seal_status,)]
        if "select status, seal_status from app.evidence_objects where id = %s" in s:
            return [(self.object_status, self.object_seal_status)]
        if "from app.evidence_objects where case_id = %s and display_path = %s" in s:
            return [(self.evidence_id,)] if self.evidence_id else []
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


def _patch_unharden(monkeypatch, *, raises: bool = False):
    """Patch sift_core.evidence_chain.unharden_sealed_evidence; return call log."""
    import sift_core.evidence_chain as ec

    calls: list = []

    def fake_unharden(case_dir, rel_paths):
        calls.append((case_dir, list(rel_paths)))
        if raises:
            raise ec.EvidenceHardeningError("could not clear immutable flag")
        return [{"path": p, "owner": "root", "immutable": False} for p in rel_paths]

    # Contract A (unharden_sealed_evidence) is built in parallel by the sift-core
    # team and may not yet exist on the module; raising=False lets us install the
    # stub the gateway imports lazily either way.
    monkeypatch.setattr(ec, "unharden_sealed_evidence", fake_unharden, raising=False)
    return calls


class TestUnseal:
    def test_unseal_clears_immutable_and_records_transition(self, service, monkeypatch):
        svc, db, tmp_path = service
        calls = _patch_unharden(monkeypatch)
        (tmp_path / "evidence" / "disk.E01").write_bytes(b"DISK-IMAGE" * 100)

        result = svc.unseal(
            case_id=_CASE,
            display_path="evidence/disk.E01",
            reason="Need to add a second acquisition slice",
            reauth_audit_event_id="reauth-99",
            actor=None,
            examiner="codex",
        )

        # Contract return dict.
        assert result == {
            "evidence_id": "ev-obj-1",
            "display_path": "evidence/disk.E01",
            "status": "detected",
            "seal_status": "unsealed",
            "immutable": False,
        }
        # +i was cleared on the case-relative path under the case dir.
        assert calls, "expected unharden_sealed_evidence to be called"
        case_dir, rel_paths = calls[-1]
        assert case_dir == tmp_path
        assert rel_paths == ["evidence/disk.E01"]
        # The DB transition carried the reason + reauth id (positional SQL order:
        # evidence_id, reason, reauth, actor_user, actor_service).
        assert db.unseal_calls, "expected an app.evidence_unseal call"
        call = db.unseal_calls[-1]
        assert call[0] == "ev-obj-1"
        assert call[1] == "Need to add a second acquisition slice"
        assert call[2] == "reauth-99"

    def test_unseal_requires_reauth(self, service, monkeypatch):
        svc, db, tmp_path = service
        calls = _patch_unharden(monkeypatch)
        (tmp_path / "evidence" / "disk.E01").write_bytes(b"x")
        with pytest.raises(PortalServiceError) as ei:
            svc.unseal(
                case_id=_CASE,
                display_path="evidence/disk.E01",
                reason="re-image",
                reauth_audit_event_id="",
                actor=None,
                examiner="codex",
            )
        assert ei.value.reason == "unseal_requires_reauth"
        assert ei.value.http_status == 403
        # No FS or DB side effects before the re-auth check.
        assert not calls
        assert not db.unseal_calls

    def test_unseal_unharden_failure_maps_to_500_and_skips_db(self, service, monkeypatch):
        svc, db, tmp_path = service
        calls = _patch_unharden(monkeypatch, raises=True)
        (tmp_path / "evidence" / "disk.E01").write_bytes(b"x")
        with pytest.raises(PortalServiceError) as ei:
            svc.unseal(
                case_id=_CASE,
                display_path="evidence/disk.E01",
                reason="re-image",
                reauth_audit_event_id="reauth-99",
                actor=None,
                examiner="codex",
            )
        assert ei.value.reason == "evidence_unseal_failed"
        assert ei.value.http_status == 500
        # +i clear was attempted but failed -> the DB transition is NOT recorded.
        assert calls
        assert not db.unseal_calls

    def test_unseal_unknown_object_raises(self, service, monkeypatch):
        svc, db, tmp_path = service
        db.evidence_id = None
        calls = _patch_unharden(monkeypatch)
        (tmp_path / "evidence" / "ghost.E01").write_bytes(b"x")
        with pytest.raises(PortalServiceError) as ei:
            svc.unseal(
                case_id=_CASE,
                display_path="evidence/ghost.E01",
                reason="re-image",
                reauth_audit_event_id="reauth-99",
                actor=None,
                examiner="codex",
            )
        assert ei.value.reason == "evidence_object_not_found"
        assert not calls
        assert not db.unseal_calls

    def test_unseal_missing_file_raises(self, service, monkeypatch):
        svc, db, tmp_path = service
        calls = _patch_unharden(monkeypatch)
        # No bytes on disk: nothing to unlock -> resolve raises before unharden/DB.
        with pytest.raises(PortalServiceError):
            svc.unseal(
                case_id=_CASE,
                display_path="evidence/disk.E01",
                reason="re-image",
                reauth_audit_event_id="reauth-99",
                actor=None,
                examiner="codex",
            )
        assert not calls
        assert not db.unseal_calls
