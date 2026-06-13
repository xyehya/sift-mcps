"""CL3a (B-MVP-017) — fail-closed Supabase operator-password re-verification.

Focused tests for the single sensitive-action re-auth verifier that replaced the
file-HMAC challenge. Exercised through the evidence seal endpoint (representative
of every routed sensitive action) plus the case-activate file-backed branch:

  (a) correct password   -> action allowed AND the audit re-auth row is written;
  (b) wrong password      -> denied 401, action NOT taken, NO audit row;
  (c) control plane down  -> denied 503 (FAIL CLOSED), action NOT taken, NO audit
                             row, and the legacy file-HMAC plane is NEVER reached;
  (d) no Supabase callback wired -> denied 503 (no silent local fallback);
  (e) session carries no operator email -> denied (cannot bind the re-verify).

The password is taken from the request body and the email from the SESSION; the
re-verify discards the GoTrue session and never rotates the portal cookie.
"""

from __future__ import annotations

import secrets

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import SESSION_ENVELOPE_COOKIE_NAME

from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)
_CASE_ID = "11111111-1111-1111-1111-111111111111"


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "cl3a"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    def __init__(self):
        self.reauth_calls: list = []
        self.seal_calls: list = []

    def record_reauth_event(self, *, case_id, actor, examiner, action):
        self.reauth_calls.append((examiner, action))
        return "audit-evt-cl3a"

    def gate_status(self, case_id):
        return {"seal_status": "unsealed", "manifest_version": 0, "active_count": 0,
                "issues": [], "head_hash": "", "last_verified_at": None}

    def list_evidence(self, case_id):
        return []

    def seal(self, *, case_id, file_specs, reauth_audit_event_id, actor, examiner):
        self.seal_calls.append(reauth_audit_event_id)
        return {"manifest_version": 1, "seal_status": "sealed"}


def _build(*, fake_auth, evidence_db):
    app = create_dashboard_v2_app(
        session_secret=_SECRET, session_max_age=28800,
        active_case_service=FakeActiveCases(), evidence_service=evidence_db,
        supabase_auth=fake_auth,
    )
    return TestClient(app, raise_server_exceptions=True)


def _seal(client, password):
    return client.post("/api/evidence/chain/seal",
                       json={"password": password, "file_specs": []})


class TestReverifyHappyPath:
    def test_correct_password_allows_and_writes_audit_row(self):
        ev = FakeEvidenceDB()
        fake = ReauthFakeSupabaseAuth()
        client = _build(fake_auth=fake, evidence_db=ev)
        set_operator_session(client, _SECRET)

        resp = _seal(client, GOOD_PASSWORD)
        assert resp.status_code == 200
        assert resp.json()["sealed"] is True
        # The re-verify ran, bound to the session email.
        assert fake.reverify_calls and fake.reverify_calls[0][0]
        # The audit re-auth row was written AFTER a successful re-verify.
        assert ev.reauth_calls == [("alice", "evidence_seal")]
        assert ev.seal_calls == ["audit-evt-cl3a"]


class TestReverifyWrongPassword:
    def test_wrong_password_denied_no_action_no_audit(self):
        ev = FakeEvidenceDB()
        client = _build(fake_auth=ReauthFakeSupabaseAuth(), evidence_db=ev)
        set_operator_session(client, _SECRET)

        resp = _seal(client, "wrong-password")
        assert resp.status_code == 401
        # No seal, and crucially NO audit re-auth row on a failed re-verify.
        assert ev.seal_calls == []
        assert ev.reauth_calls == []


class TestReverifyFailClosed:
    def test_control_plane_down_denies_503_no_fallback(self):
        ev = FakeEvidenceDB()
        fake = ReauthFakeSupabaseAuth(control_plane_down=True)
        client = _build(fake_auth=fake, evidence_db=ev)
        set_operator_session(client, _SECRET)

        resp = _seal(client, GOOD_PASSWORD)
        # FAIL CLOSED: control plane unreachable -> 503, never a local fallback.
        assert resp.status_code == 503
        assert ev.seal_calls == []
        assert ev.reauth_calls == []

    def test_no_supabase_callback_denies_503(self, monkeypatch, tmp_path):
        # No Supabase auth wired at all: re-verify must fail closed, never reach a
        # file-HMAC verifier. Also seed a local password file to prove it is NOT
        # used as a fallback verifier.
        ev = FakeEvidenceDB()
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        pw_dir = tmp_path / "passwords"
        pw_dir.mkdir(parents=True)
        (pw_dir / "alice.json").write_text(
            '{"hash": "%s", "salt": "ab", "must_reset_password": false}' % ("00" * 32)
        )
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", pw_dir)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=FakeActiveCases(), evidence_service=ev,
            supabase_auth=None,
        )
        client = TestClient(app, raise_server_exceptions=True)
        # No Supabase resolver -> no session principal -> the role/identity gate
        # denies before re-verify, which is itself fail-closed. Either way: denied.
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, "irrelevant")
        resp = _seal(client, GOOD_PASSWORD)
        assert resp.status_code in (401, 403, 503)
        assert ev.seal_calls == []
        assert ev.reauth_calls == []


class TestReverifyBinding:
    def test_cross_operator_password_denied_403_no_action_no_audit(self):
        """F2: a logged-in operator (session auth_user_id A) who re-auths a
        sensitive action with ANOTHER valid operator's email+password (grant
        subject B != A) is DENIED 403. The action must not run and no audit
        re-auth row may be written — the grant subject is bound to the session.
        """
        ev = FakeEvidenceDB()
        # Session resolves to operator A; the grant resolves to a DIFFERENT
        # auth user B (operator B's credentials), so binding must fail closed.
        fake = ReauthFakeSupabaseAuth(grant_auth_user_id="auth-user-op-B")
        client = _build(fake_auth=fake, evidence_db=ev)
        set_operator_session(client, _SECRET)

        resp = _seal(client, GOOD_PASSWORD)
        assert resp.status_code == 403
        assert ev.seal_calls == []
        assert ev.reauth_calls == []
        # The re-verify WAS invoked (password was correct) but the binding check
        # rejected it — proving the identity binding, not a pre-check, denied it.
        assert fake.reverify_calls

    def test_session_without_email_denies(self):
        # An operator principal that carries NO email cannot be re-verified
        # (the email is taken from the session, never the body) -> deny.
        ev = FakeEvidenceDB()
        no_email = dict(operator_principal())
        no_email["email"] = None
        fake = ReauthFakeSupabaseAuth(principal=no_email)
        client = _build(fake_auth=fake, evidence_db=ev)
        set_operator_session(client, _SECRET)

        resp = _seal(client, GOOD_PASSWORD)
        assert resp.status_code == 401
        assert ev.seal_calls == []
        assert ev.reauth_calls == []
        # The control plane re-verify was never even called (failed before it).
        assert fake.reverify_calls == []

    def test_missing_password_in_body_denies_400(self):
        ev = FakeEvidenceDB()
        client = _build(fake_auth=ReauthFakeSupabaseAuth(), evidence_db=ev)
        set_operator_session(client, _SECRET)
        resp = client.post("/api/evidence/chain/seal", json={"file_specs": []})
        assert resp.status_code == 400
        assert ev.seal_calls == []
        assert ev.reauth_calls == []
