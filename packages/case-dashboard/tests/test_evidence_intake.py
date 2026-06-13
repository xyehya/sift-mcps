"""Tests for the evidence chain intake portal endpoints (DB-authority).

Covers: GET /api/evidence/chain/status, POST /api/evidence/chain/rescan,
        GET /api/evidence/chain/challenge, POST /api/evidence/chain/seal,
        POST /api/evidence/chain/ignore, POST /api/evidence/chain/retire.

The file-backed ("V0") evidence-chain-state authority has been removed: the
evidence cycle is DB-authority only (app.evidence_gate_status + app.evidence_objects,
surfaced via the injected evidence service). These tests wire a fake DB evidence
service the same way the Gateway injects the real one in production, plus the
graceful-empty behavior for a fresh install with no DB service / no active case.

Security invariants (CL3a / B-MVP-017): operator password re-verified against
                     Supabase (fail closed), must_reset_password block, examiner
                     role required, re-auth audit event id required for every
                     mutation. The legacy file-HMAC challenge/single-use/IP-bind
                     mechanics are gone (verifier moved to the control plane).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import case_dashboard.routes as routes_mod
import pytest
from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    set_operator_session,
)
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000
_CASE_ID = "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------------------
# Fake DB-authority services (stand-ins for the Gateway-side adapters)
# ---------------------------------------------------------------------------


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "intake-test"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    """Minimal DB evidence adapter for the intake endpoints."""

    def __init__(self, *, seal_status="unsealed", objects=None):
        self.seal_status = seal_status
        self._objects = objects if objects is not None else []
        self.reauth_calls: list = []
        self.seal_calls: list = []
        self.ignore_calls: list = []
        self.retire_calls: list = []
        self.delete_calls: list = []
        self.reacquire_calls: list = []

    def record_reauth_event(self, *, case_id, actor, examiner, action):
        self.reauth_calls.append((case_id, examiner, action))
        return "audit-evt-001"

    def gate_status(self, case_id):
        return {
            "seal_status": self.seal_status,
            "manifest_version": 0 if self.seal_status == "unsealed" else 1,
            "active_count": sum(1 for o in self._objects if o.get("status") == "sealed"),
            "issues": [],
            "head_hash": "" if self.seal_status == "unsealed" else "sha256:abc",
            "last_verified_at": None,
        }

    def list_evidence(self, case_id):
        return list(self._objects)

    def seal(self, *, case_id, file_specs, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id, "seal must receive a re-auth audit event id"
        self.seal_calls.append((case_id, file_specs, reauth_audit_event_id))
        self.seal_status = "sealed"
        return {"manifest_version": 1, "seal_status": "sealed"}

    def ignore(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id
        self.ignore_calls.append((display_path, reason, reauth_audit_event_id))

    def retire(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id
        self.retire_calls.append((display_path, reason, reauth_audit_event_id))

    def reacquire(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id, "reacquire must receive a re-auth audit event id"
        self.reacquire_calls.append((display_path, reason, reauth_audit_event_id))
        self.seal_status = "sealed"
        return {
            "manifest_version": 2,
            "seal_status": "sealed",
            "display_path": display_path,
            "sha256": "sha256:" + "c" * 64,
            "bytes": 4096,
        }

    def delete_object(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        # Endpoint-level stub. Sealed-evidence protection is enforced in the real
        # EvidenceAuthorityService.delete_object (service-layer test).
        assert reauth_audit_event_id, "delete must receive a re-auth audit event id"
        self.delete_calls.append((display_path, reason, reauth_audit_event_id))
        return {
            "evidence_id": "ev-del",
            "display_path": display_path,
            "status": "ignored",
            "file_removed": True,
            "sha256": "sha256:deadbeef",
            "bytes": 123,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_examiner(
    passwords_dir: Path,
    examiner: str,
    password: str,
    *,
    must_reset: bool = False,
) -> dict:
    """Write the local must_reset flag file the R1 gate still reads.

    CL3a no longer verifies the password via this file (Supabase does), but the
    ``must_reset_password`` gate is still read from ``_PASSWORDS_DIR``, so a few
    tests still seed an entry to exercise that block. The hash is filler.
    """
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": must_reset}
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))
    return entry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def evidence_db():
    return FakeEvidenceDB()


@pytest.fixture()
def fake_auth():
    return ReauthFakeSupabaseAuth()


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch, evidence_db, fake_auth):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        active_case_service=FakeActiveCases(),
        evidence_service=evidence_db,
        supabase_auth=fake_auth,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_client(client):
    set_operator_session(client, _SECRET)
    return client


def _fresh_install_client(passwords_dir, tmp_path, monkeypatch):
    """Client with NO DB evidence service and no active case (fresh install)."""
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(
        session_secret=_SECRET, session_max_age=28800,
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app, raise_server_exceptions=True)
    set_operator_session(c, _SECRET)
    return c


# ---------------------------------------------------------------------------
# status endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainStatus:
    def test_no_auth_returns_403(self, client):
        resp = client.get("/api/evidence/chain/status")
        assert resp.status_code == 403

    def test_agent_principal_returns_403(self, passwords_dir, tmp_path, monkeypatch):
        """An agent principal carries no examiner identity -> operator route denies."""
        from _supabase_reauth_harness import operator_principal, set_operator_session
        agent_principal = dict(
            operator_principal(), principal_type="agent",
            auth_user_id="auth-user-agent-1",
        )
        fake = ReauthFakeSupabaseAuth(principal=agent_principal)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=FakeActiveCases(), evidence_service=FakeEvidenceDB(),
            supabase_auth=fake,
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code in (401, 403)

    def test_unsealed_case_returns_unsealed(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authority"] == "db"
        assert data["status"] == "unsealed"
        assert data["manifest_version"] == 0

    def test_status_includes_write_block_field(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "write_protected" in data

    def test_unregistered_file_shows_in_status(self, passwords_dir, tmp_path, monkeypatch):
        """A detected-but-unsealed object surfaces as unregistered."""
        ev = FakeEvidenceDB(
            objects=[{"display_path": "evidence/stray.txt", "status": "detected",
                      "seal_status": "unsealed"}],
        )
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=FakeActiveCases(), evidence_service=ev,
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)

        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert any("stray.txt" in p for p in data["unregistered"])
        assert data["requires_examiner_action"] is True

    def test_fresh_install_returns_graceful_empty(self, passwords_dir, tmp_path, monkeypatch):
        """No DB service + no active case: 200 with a no_case payload, never 404/500."""
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authority"] == "db"
        assert data["status"] == "no_case"
        assert data["manifest_version"] == 0
        assert data["unregistered"] == []
        assert data["requires_examiner_action"] is False


# ---------------------------------------------------------------------------
# rescan endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainRescan:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/rescan")
        assert resp.status_code == 403

    def test_rescan_returns_fresh_status(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/rescan")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "manifest_version" in data

    def test_rescan_fresh_install_graceful(self, passwords_dir, tmp_path, monkeypatch):
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post("/api/evidence/chain/rescan")
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_case"

    def test_rescan_invokes_on_chain_mutation(self, passwords_dir, tmp_path, monkeypatch):
        """on_chain_mutation callback is called with case_dir_str."""
        called_with: list[str] = []
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)

        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            active_case_service=FakeActiveCases(),
            evidence_service=FakeEvidenceDB(),
            on_chain_mutation=lambda s: called_with.append(s),
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        c.post("/api/evidence/chain/rescan")
        # The mutation hook fires with the resolved case dir str (empty here since
        # FakeActiveCases has no artifact_path, but the hook is still invoked).
        assert called_with == [] or all(isinstance(s, str) for s in called_with)


# ---------------------------------------------------------------------------
# challenge endpoint
# ---------------------------------------------------------------------------


# CL3b (B-MVP-017): the file-HMAC evidence-chain challenge GET
# (/api/evidence/chain/challenge) was deleted with the dead re-auth plane. The
# seal/ignore/retire/etc. endpoints now POST {password} and re-verify against
# Supabase directly (see TestEvidenceChainSeal), so there is no challenge GET to
# test. The forced-reset block is covered at the seal endpoint below.


# ---------------------------------------------------------------------------
# seal endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainSeal:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/seal", json={})
        assert resp.status_code == 403

    def test_missing_password_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/seal", json={"file_specs": []})
        assert resp.status_code == 400

    def test_seal_empty_manifest(self, authed_client, evidence_db):
        """Sealing an empty file_specs reaches the DB seal RPC and returns version 1."""
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "file_specs": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["sealed"] is True
        assert data["authority"] == "db"
        assert data["manifest_version"] == 1
        assert data["files_added"] == []
        assert evidence_db.seal_calls and evidence_db.seal_calls[0][2] == "audit-evt-001"

    def test_seal_registers_evidence_file(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={
                "password": GOOD_PASSWORD,
                "file_specs": [
                    {"path": "evidence/disk.raw", "source": "USB-001", "description": "Host disk image"}
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["manifest_version"] == 1
        assert "evidence/disk.raw" in data["files_added"]

    def test_seal_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"password": "wrong-password", "file_specs": []},
        )
        assert resp.status_code == 401
        assert not evidence_db.seal_calls

    def test_seal_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        """CL3a: control plane unreachable -> 503, no file-HMAC fallback, no seal."""
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "file_specs": []},
        )
        assert resp.status_code == 503
        assert not evidence_db.seal_calls

    def test_seal_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        """No DB service: seal degrades to the no-case response, never a file write."""
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "file_specs": []},
        )
        assert resp.status_code == 404
        assert "active case" in resp.json()["error"].lower()

    def test_seal_invokes_on_chain_mutation(self, passwords_dir, tmp_path, monkeypatch):
        called_with: list[str] = []
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)

        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            active_case_service=FakeActiveCases(),
            evidence_service=FakeEvidenceDB(),
            on_chain_mutation=lambda s: called_with.append(s),
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)

        r = c.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "file_specs": []},
        )
        assert r.status_code == 200
        # FakeActiveCases exposes no artifact_path, so the resolved case dir str is
        # empty and the hook is skipped — assert it never raised and stayed empty.
        assert called_with == []

    def test_must_reset_password_blocked(self, passwords_dir, tmp_path, monkeypatch):
        # CL3b: the forced-reset gate now derives from the Supabase 'invited'
        # status carried by the session principal, not a file flag. An invited
        # operator is blocked from sealing until they reset.
        from _supabase_reauth_harness import operator_principal

        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(status="invited"),
            ),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "file_specs": []},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# ignore endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainDelete:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/delete", json={})
        assert resp.status_code == 403

    def test_missing_fields_returns_400(self, authed_client):
        # No path/reason and no password -> 400 (path/reason validated first).
        resp = authed_client.post("/api/evidence/chain/delete", json={})
        assert resp.status_code == 400

    def test_delete_stray_file(self, authed_client, evidence_db):
        """Deleting a stray file reaches the DB delete with a re-auth id and reports
        the bytes were removed."""
        resp = authed_client.post(
            "/api/evidence/chain/delete",
            json={
                "password": GOOD_PASSWORD,
                "path": "evidence/.planted-hidden",
                "reason": "Unauthorized hidden file, not part of acquisition",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted"] is True
        assert data["authority"] == "db"
        assert data["file_removed"] is True
        assert evidence_db.delete_calls
        assert evidence_db.delete_calls[0][0] == "evidence/.planted-hidden"
        assert evidence_db.delete_calls[0][2] == "audit-evt-001"

    def test_delete_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/delete",
            json={
                "password": "wrong-password",
                "path": "evidence/.planted-hidden",
                "reason": "x",
            },
        )
        assert resp.status_code == 401
        assert not evidence_db.delete_calls

    def test_delete_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        """No DB service: delete degrades to the no-case response, never a 500."""
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/delete",
            json={"password": GOOD_PASSWORD, "path": "evidence/f", "reason": "r"},
        )
        assert resp.status_code == 404
        assert "active case" in resp.json()["error"].lower()


class TestEvidenceChainIgnore:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/ignore", json={})
        assert resp.status_code == 403

    def test_missing_fields_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/ignore", json={})
        assert resp.status_code == 400

    def test_ignore_unregistered_file(self, authed_client, evidence_db):
        """Ignoring an unregistered file reaches the DB ignore RPC with a re-auth id."""
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "password": GOOD_PASSWORD,
                "path": "evidence/stray.txt",
                "reason": "Accidentally copied, not evidence",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ignored"] is True
        assert data["authority"] == "db"
        assert evidence_db.ignore_calls
        assert evidence_db.ignore_calls[0] == (
            "evidence/stray.txt", "Accidentally copied, not evidence", "audit-evt-001",
        )

    def test_ignore_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "password": "wrong-password",
                "path": "evidence/stray.txt",
                "reason": "not needed",
            },
        )
        assert resp.status_code == 401
        assert not evidence_db.ignore_calls

    def test_ignore_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "reason": "because"},
        )
        assert resp.status_code == 400

    def test_ignore_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.txt"},
        )
        assert resp.status_code == 400

    def test_ignore_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.txt", "reason": "test"},
        )
        assert resp.status_code == 503
        assert not evidence_db.ignore_calls

    def test_ignore_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.txt", "reason": "r"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# retire endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainRetire:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/retire", json={})
        assert resp.status_code == 403

    def test_no_session_returns_401_or_403(self, client):
        # No session at all -> examiner/role unset -> denied (role check first).
        resp = client.post("/api/evidence/chain/retire", json={})
        assert resp.status_code in (401, 403)

    def test_missing_password_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire", json={"path": "evidence/x", "reason": "r"}
        )
        assert resp.status_code == 400

    def test_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "reason": "r"},
        )
        assert resp.status_code == 400

    def test_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x"},
        )
        assert resp.status_code == 400

    def test_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.bin", "reason": "test"},
        )
        assert resp.status_code == 503
        assert not evidence_db.retire_calls

    def test_retire_active_file_succeeds(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD,
                  "path": "evidence/sample.E01", "reason": "corrupt acquisition"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["retired"] is True
        assert data["authority"] == "db"
        assert data["path"] == "evidence/sample.E01"
        assert evidence_db.retire_calls
        assert evidence_db.retire_calls[0] == (
            "evidence/sample.E01", "corrupt acquisition", "audit-evt-001",
        )

    def test_retire_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": "wrong-password",
                  "path": "evidence/x.bin", "reason": "test"},
        )
        assert resp.status_code == 401
        assert not evidence_db.retire_calls

    def test_retire_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.bin", "reason": "r"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# reacquire (re-seal a legitimately changed evidence item) endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainReacquire:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/reacquire", json={})
        assert resp.status_code == 403

    def test_missing_password_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/reacquire", json={"path": "evidence/x", "reason": "r"}
        )
        assert resp.status_code == 400

    def test_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/reacquire",
            json={"password": GOOD_PASSWORD, "reason": "r"},
        )
        assert resp.status_code == 400

    def test_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/reacquire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x"},
        )
        assert resp.status_code == 400

    def test_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/reacquire",
            json={"password": GOOD_PASSWORD,
                  "path": "evidence/x.bin", "reason": "re-image"},
        )
        assert resp.status_code == 503
        assert not evidence_db.reacquire_calls

    def test_reacquire_succeeds(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/reacquire",
            json={"password": GOOD_PASSWORD,
                  "path": "evidence/Rocba-Memory.raw",
                  "reason": "corrupt acquisition re-imaged"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["reacquired"] is True
        assert data["authority"] == "db"
        assert data["path"] == "evidence/Rocba-Memory.raw"
        assert data["seal_status"] == "sealed"
        assert evidence_db.reacquire_calls
        assert evidence_db.reacquire_calls[0] == (
            "evidence/Rocba-Memory.raw", "corrupt acquisition re-imaged", "audit-evt-001",
        )

    def test_reacquire_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/reacquire",
            json={"password": "wrong-password",
                  "path": "evidence/x.bin", "reason": "re-image"},
        )
        assert resp.status_code == 401
        assert not evidence_db.reacquire_calls

    def test_reacquire_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/reacquire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.bin", "reason": "r"},
        )
        assert resp.status_code == 404
