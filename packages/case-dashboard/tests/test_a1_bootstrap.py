"""A1-BOOTSTRAP targeted tests.

Covers:
- _make_case_name: frozen format, collision suffix (-NN)
- post_supabase_forced_reset: happy path, auth guards, error propagation
- must_reset flag in post_supabase_login response
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

import case_dashboard.routes as routes_mod
import pytest
from case_dashboard.routes import _make_case_name, create_dashboard_v2_app
from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)


# ---------------------------------------------------------------------------
# _make_case_name unit tests
# ---------------------------------------------------------------------------

class FrozenDatetime1433(datetime):
    """Freeze to 2026-05-25T14:12:33 → MMDDHHSS = 05251433."""
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 5, 25, 14, 12, 33, tzinfo=timezone.utc)
        return value if tz is None else value.astimezone(tz)


def test_make_case_name_frozen_format(tmp_path, monkeypatch):
    """_make_case_name produces case-<slug>-<MMDDHHSS> (frozen A1-BOOTSTRAP convention)."""
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime1433)
    case_id, path = _make_case_name("rocba-cdrive", tmp_path)
    assert case_id == "case-rocba-cdrive-05251433"
    assert path == (tmp_path / "case-rocba-cdrive-05251433").resolve()


def test_make_case_name_no_collision_no_suffix(tmp_path, monkeypatch):
    """No collision suffix when directory does not exist."""
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime1433)
    case_id, _ = _make_case_name("myslug", tmp_path)
    assert "-01" not in case_id
    assert case_id == "case-myslug-05251433"


def test_make_case_name_collision_adds_nn_suffix(tmp_path, monkeypatch):
    """When base name exists, appends -01, -02 etc."""
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime1433)
    # Pre-create the base directory to force collision.
    base = tmp_path / "case-myslug-05251433"
    base.mkdir()
    case_id, path = _make_case_name("myslug", tmp_path)
    assert case_id == "case-myslug-05251433-01"
    assert path == (tmp_path / "case-myslug-05251433-01").resolve()


def test_make_case_name_collision_increments_until_free(tmp_path, monkeypatch):
    """Increments suffix until a free slot is found."""
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime1433)
    (tmp_path / "case-myslug-05251433").mkdir()
    (tmp_path / "case-myslug-05251433-01").mkdir()
    (tmp_path / "case-myslug-05251433-02").mkdir()
    case_id, _ = _make_case_name("myslug", tmp_path)
    assert case_id == "case-myslug-05251433-03"


def test_make_case_name_99_collision_raises(tmp_path, monkeypatch):
    """Raises ValueError after 99 collision suffixes."""
    monkeypatch.setattr(routes_mod, "datetime", FrozenDatetime1433)
    (tmp_path / "case-myslug-05251433").mkdir()
    for nn in range(1, 100):
        (tmp_path / f"case-myslug-05251433-{nn:02d}").mkdir()
    with pytest.raises(ValueError, match="Too many case-directory collisions"):
        _make_case_name("myslug", tmp_path)


# ---------------------------------------------------------------------------
# must_reset flag in login response
# ---------------------------------------------------------------------------

class PortalAuthError(Exception):
    def __init__(self, http_status: int, reason: str):
        super().__init__(reason)
        self.http_status = http_status
        self.reason = reason


class FakeSupabaseAuthInvited:
    """Returns an 'invited' status principal to test must_reset handoff."""

    def __init__(self, status="invited"):
        self._status = status
        self.forced_reset_calls: list = []

    async def login(self, email, password, source_ip):
        at = "access-" + secrets.token_hex(8)
        rt = "refresh-" + secrets.token_hex(8)
        principal = {
            "principal_type": "operator",
            "principal_id": "op-invited",
            "auth_user_id": "auth-op-invited",
            "display_name": "alice",
            "email": email,
            "system_role": "owner",
            "status": self._status,
            "case_memberships": [],
        }
        return {
            "access_token": at,
            "refresh_token": rt,
            "expires_at": 9999999999,
            "sub": "auth-op-invited",
            "fingerprint": "fp-test",
            "principal": principal,
        }

    async def resolve(self, access_token, source_ip):
        return None  # not needed for these tests

    async def refresh(self, refresh_token, source_ip):
        return None

    async def forced_reset(self, access_token, new_password, source_ip):
        self.forced_reset_calls.append((access_token, new_password, source_ip))

    # Stubs for unused C3 methods
    async def logout(self, access_token, source_ip): pass
    async def issue_principal(self, *a, **kw): pass
    async def revoke_principal(self, *a, **kw): pass
    async def list_principals(self, *a, **kw): return []


def test_supabase_login_returns_must_reset_true_when_invited():
    """POST /api/auth/login returns must_reset=true when principal.status=='invited'."""
    fake_auth = FakeSupabaseAuthInvited(status="invited")
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        supabase_auth=fake_auth,
    )
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "TempPass123!"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["must_reset"] is True


def test_supabase_login_returns_must_reset_false_when_active(tmp_path, monkeypatch):
    """POST /api/auth/login returns must_reset=false when principal.status=='active'."""
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path)
    fake_auth = FakeSupabaseAuthInvited(status="active")
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        supabase_auth=fake_auth,
    )
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "MyPass123!"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["must_reset"] is False
    # CL3b: login no longer mirrors the password into a local file-HMAC store
    # (_sync_local_reauth_password was deleted with the dead re-auth plane); the
    # forced-reset signal is the Supabase 'invited' status, not a local file.
    assert not (tmp_path / "alice.json").exists()


# ---------------------------------------------------------------------------
# post_supabase_forced_reset endpoint
# ---------------------------------------------------------------------------

def _make_forced_reset_app(fake_auth):
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        supabase_auth=fake_auth,
    )


def _make_envelope(at: str) -> str:
    return generate_session_envelope(
        access_token=at,
        refresh_token="rt-test",
        expires_at=9999999999,
        sub="auth-op-test",
        fingerprint="fp-test",
        secret=_SECRET,
    )


def test_forced_reset_requires_session_cookie():
    """POST /api/auth/forced-reset returns 401 when no session cookie is present."""
    fake_auth = FakeSupabaseAuthInvited()
    app = _make_forced_reset_app(fake_auth)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.post("/api/auth/forced-reset", json={"new_password": "NewPass123!"})
    assert resp.status_code == 401


def test_forced_reset_requires_new_password():
    """POST /api/auth/forced-reset returns 400 when new_password is missing."""
    fake_auth = FakeSupabaseAuthInvited()
    app = _make_forced_reset_app(fake_auth)
    client = TestClient(app, raise_server_exceptions=True)
    envelope = _make_envelope("access-test-token")
    resp = client.post(
        "/api/auth/forced-reset",
        json={},
        cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
    )
    assert resp.status_code == 400
    assert "new_password" in resp.json()["error"]


def test_forced_reset_happy_path():
    """POST /api/auth/forced-reset calls forced_reset callback and returns must_reset=false."""
    fake_auth = FakeSupabaseAuthInvited()
    app = _make_forced_reset_app(fake_auth)
    client = TestClient(app, raise_server_exceptions=True)
    envelope = _make_envelope("access-test-token")
    resp = client.post(
        "/api/auth/forced-reset",
        json={"new_password": "NewSecurePass123!"},
        cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["must_reset"] is False
    # Verify the callback was called with the correct access token
    assert len(fake_auth.forced_reset_calls) == 1
    at_used, pw_used, _ = fake_auth.forced_reset_calls[0]
    assert at_used == "access-test-token"
    assert pw_used == "NewSecurePass123!"


def test_forced_reset_returns_503_when_supabase_not_configured():
    """POST /api/auth/forced-reset returns 503 when Supabase auth is not configured."""
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        supabase_auth=None,
    )
    client = TestClient(app, raise_server_exceptions=True)
    envelope = _make_envelope("access-test-token")
    resp = client.post(
        "/api/auth/forced-reset",
        json={"new_password": "NewPass123!"},
        cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
    )
    assert resp.status_code == 503


def test_forced_reset_propagates_callback_error():
    """POST /api/auth/forced-reset surfaces callback errors (e.g. principal not invited)."""
    class FakeAuthRaises(FakeSupabaseAuthInvited):
        async def forced_reset(self, access_token, new_password, source_ip):
            raise PortalAuthError(400, "principal_not_invited")

    fake_auth = FakeAuthRaises()
    app = _make_forced_reset_app(fake_auth)
    client = TestClient(app, raise_server_exceptions=True)
    envelope = _make_envelope("access-test-token")
    resp = client.post(
        "/api/auth/forced-reset",
        json={"new_password": "NewPass123!"},
        cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
    )
    assert resp.status_code == 400
    assert "principal_not_invited" in resp.json()["error"]
