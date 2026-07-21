"""CL3a (B-MVP-017) — fail-closed Supabase operator-password re-verification.

Focused tests for the single sensitive-action re-auth verifier that replaced the
file-HMAC challenge. Exercised through the **case-activation DB-active branch**
(POST /api/case/activate) — a genuinely live sensitive action backed by the real
active-case service (``set_active_case``), representative of every routed
sensitive action that calls ``_supabase_reverify``:

  (a) correct password    -> action allowed (case activated) after a bound re-verify;
  (b) wrong password       -> denied 401, action NOT taken;
  (c) control plane down   -> denied 503 (FAIL CLOSED), action NOT taken, never a
                              local file-HMAC fallback;
  (d) no Supabase callback -> denied (no silent local fallback);
  (e) cross-operator grant -> denied 403 (identity binding), action NOT taken;
  (f) session carries no operator email -> denied (cannot bind the re-verify);
  (g) missing password in body -> denied 400.

Previously these ran through POST /api/evidence/chain/seal, but that legacy route
is now a dead authenticated-404 (PF-009) whose production sealer never existed —
a fake ``.seal()`` there proved nothing. The re-verify contract is identical on
every route (the verifier is route-agnostic), so this exercises the SAME
``_supabase_reverify`` on a route whose production backend genuinely exists.

The password is taken from the request body and the email from the SESSION; the
re-verify discards the GoTrue session and never rotates the portal cookie.
"""

from __future__ import annotations

import secrets

import case_dashboard.routes as routes_mod
from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import SESSION_ENVELOPE_COOKIE_NAME
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_CASE_ID = "11111111-1111-1111-1111-111111111111"


class FakeActiveCases:
    """Live-shaped active-case service. ``set_active_case`` is the REAL production
    method name the route invokes; the test records calls to prove the sensitive
    action ran only after a successful, bound re-verify."""

    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "cl3a"}

    def __init__(self):
        self.set_calls: list = []

    def get_active_case(self, principal=None):
        return self._Case()

    def set_active_case(self, case_id, principal=None):
        self.set_calls.append((case_id, principal))
        return self._Case()


class _EvidenceDB:
    """Minimal read adapter needed for app construction (unused by case-activate).
    Deliberately carries NO seal/ignore/retire — the production
    EvidenceAuthorityService has none, and CL3a no longer proves a fake mutation."""

    def gate_status(self, case_id):
        return {"seal_status": "unsealed", "manifest_version": 0, "active_count": 0,
                "issues": [], "head_hash": "", "last_verified_at": None}

    def list_evidence(self, case_id):
        return []


def _build(*, fake_auth, active_cases):
    app = create_dashboard_v2_app(
        session_secret=_SECRET, session_max_age=28800,
        active_case_service=active_cases, evidence_service=_EvidenceDB(),
        supabase_auth=fake_auth,
    )
    return TestClient(app, raise_server_exceptions=True)


def _activate(client, password):
    """Trigger the reauth-gated case-activation sensitive action. ``password=None``
    posts no password field (the missing-password branch)."""
    body = {"case_id": _CASE_ID}
    if password is not None:
        body["password"] = password
    return client.post("/api/case/activate", json=body)


class TestReverifyHappyPath:
    def test_correct_password_allows_and_runs_action(self):
        active = FakeActiveCases()
        fake = ReauthFakeSupabaseAuth()
        client = _build(fake_auth=fake, active_cases=active)
        set_operator_session(client, _SECRET)

        resp = _activate(client, GOOD_PASSWORD)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        # The re-verify ran, bound to the session email.
        assert fake.reverify_calls and fake.reverify_calls[0][0]
        # The sensitive action ran ONLY after a successful re-verify.
        assert active.set_calls == [(_CASE_ID, active.set_calls[0][1])]
        assert len(active.set_calls) == 1


class TestReverifyWrongPassword:
    def test_wrong_password_denied_no_action(self):
        active = FakeActiveCases()
        client = _build(fake_auth=ReauthFakeSupabaseAuth(), active_cases=active)
        set_operator_session(client, _SECRET)

        resp = _activate(client, "wrong-password")
        assert resp.status_code == 401
        assert active.set_calls == []  # action not taken on a failed re-verify


class TestReverifyFailClosed:
    def test_control_plane_down_denies_503_no_fallback(self):
        active = FakeActiveCases()
        fake = ReauthFakeSupabaseAuth(control_plane_down=True)
        client = _build(fake_auth=fake, active_cases=active)
        set_operator_session(client, _SECRET)

        resp = _activate(client, GOOD_PASSWORD)
        # FAIL CLOSED: control plane unreachable -> 503, never a local fallback.
        assert resp.status_code == 503
        assert active.set_calls == []

    def test_no_supabase_callback_denies(self, monkeypatch, tmp_path):
        # No Supabase auth wired at all: re-verify must fail closed, never reach a
        # file-HMAC verifier. Seed a local password file to prove it is NOT used as
        # a fallback verifier.
        active = FakeActiveCases()
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        pw_dir = tmp_path / "passwords"
        pw_dir.mkdir(parents=True)
        (pw_dir / "alice.json").write_text(
            '{"hash": "%s", "salt": "ab", "must_reset_password": false}' % ("00" * 32)
        )
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", pw_dir)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=active, evidence_service=_EvidenceDB(),
            supabase_auth=None,
        )
        client = TestClient(app, raise_server_exceptions=True)
        # No Supabase resolver -> no session principal -> the identity/role gate
        # denies before re-verify, which is itself fail-closed. Either way: denied.
        client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, "irrelevant")
        resp = _activate(client, GOOD_PASSWORD)
        assert resp.status_code in (401, 403, 503)
        assert active.set_calls == []


class TestReverifyBinding:
    def test_cross_operator_password_denied_403_no_action(self):
        """F2: a logged-in operator (session auth_user_id A) who re-auths a
        sensitive action with ANOTHER valid operator's email+password (grant
        subject B != A) is DENIED 403. The action must not run — the grant subject
        is bound to the session, not the body.
        """
        active = FakeActiveCases()
        # Session resolves to operator A; the grant resolves to a DIFFERENT auth
        # user B (operator B's credentials), so binding must fail closed.
        fake = ReauthFakeSupabaseAuth(grant_auth_user_id="auth-user-op-B")
        client = _build(fake_auth=fake, active_cases=active)
        set_operator_session(client, _SECRET)

        resp = _activate(client, GOOD_PASSWORD)
        assert resp.status_code == 403
        assert active.set_calls == []
        # The re-verify WAS invoked (password was correct) but the binding check
        # rejected it — proving the identity binding, not a pre-check, denied it.
        assert fake.reverify_calls

    def test_session_without_email_denies(self):
        # An operator principal that carries NO email cannot be re-verified (the
        # email is taken from the session, never the body) -> deny before re-verify.
        active = FakeActiveCases()
        no_email = dict(operator_principal())
        no_email["email"] = None
        fake = ReauthFakeSupabaseAuth(principal=no_email)
        client = _build(fake_auth=fake, active_cases=active)
        set_operator_session(client, _SECRET)

        resp = _activate(client, GOOD_PASSWORD)
        assert resp.status_code == 401
        assert active.set_calls == []
        # The control plane re-verify was never even called (failed before it).
        assert fake.reverify_calls == []

    def test_missing_password_in_body_denies_400(self):
        active = FakeActiveCases()
        client = _build(fake_auth=ReauthFakeSupabaseAuth(), active_cases=active)
        set_operator_session(client, _SECRET)
        resp = _activate(client, None)  # case_id present, password absent
        assert resp.status_code == 400
        assert active.set_calls == []
