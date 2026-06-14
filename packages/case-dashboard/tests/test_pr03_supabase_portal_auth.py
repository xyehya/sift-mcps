"""PR03A — portal Supabase JWT identity tests (Unit C).

Covers doc 19 §4.4, §4.5 (portal half), §7, and §9 portal bullet:
  - login calls the supplied Supabase callback and sets a Secure/HttpOnly cookie
  - /api/auth/me returns the operator profile + memberships (no token material)
  - expired access token refreshes or fails closed based on callback result
  - logout clears the cookie and calls the logout callback
  - agent/service principals are denied on normal portal operator APIs
  - legacy session accepted only when the legacy flag is enabled
  - legacy PBKDF2 setup/challenge/reset endpoints fail closed in Supabase mode
  - agent JWT/session create returns token material once and stores no raw token
  - revoke disables the app principal and calls the supplied revoke callback

A FAKE supabase_auth object implements the C3 contract — no live network. The
fake returns PLAIN DICTS and raises PortalAuthError(http_status, reason) where
the contract requires it.
"""

from __future__ import annotations

import secrets

import case_dashboard.routes as routes_mod
import pytest
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)

_OPERATOR = {
    "principal_type": "operator",
    "principal_id": "op-1",
    "auth_user_id": "auth-user-op-1",
    "display_name": "alice",
    "email": "alice@example.com",
    "system_role": "owner",
    "status": "active",
    "case_memberships": [{"case_id": "case-1", "role": "lead"}],
}

_AGENT = {
    "principal_type": "agent",
    "principal_id": "agent-1",
    "auth_user_id": "auth-user-agent-1",
    "display_name": "hermes",
    "email": None,
    "system_role": None,
    "status": "active",
    "case_memberships": [],
}


class PortalAuthError(Exception):
    """Mirror of the Gateway's denial exception (carries http_status + reason)."""

    def __init__(self, http_status: int, reason: str):
        super().__init__(reason)
        self.http_status = http_status
        self.reason = reason


class FakeSupabaseAuth:
    """In-memory C3 callback implementation. Records calls; never touches network."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.tokens_issued: list[dict] = []
        self.revoked: list[tuple] = []
        self.logged_out: list[str] = []
        # Map access_token -> principal dict for resolve().
        self._resolvable: dict[str, dict] = {}
        # Map refresh_token -> refreshed login dict for refresh().
        self._refreshable: dict[str, dict] = {}
        self._counter = 0
        self.fail_login_for: set[str] = set()
        self.deny_kinds_as_403 = True

    # --- C3 methods -------------------------------------------------------

    async def login(self, email, password, source_ip):
        self.calls.append(("login", email, source_ip))
        if email in self.fail_login_for or password == "wrong":
            raise PortalAuthError(401, "Invalid credentials")
        if email == "agent@example.com":
            raise PortalAuthError(403, "Agent principals may not use the portal")
        at = "access-" + secrets.token_hex(8)
        rt = "refresh-" + secrets.token_hex(8)
        self._resolvable[at] = _OPERATOR
        return {
            "access_token": at,
            "refresh_token": rt,
            "expires_at": 9999999999,
            "sub": _OPERATOR["auth_user_id"],
            "fingerprint": "fp-" + secrets.token_hex(4),
            "principal": _OPERATOR,
        }

    async def resolve(self, access_token, source_ip):
        self.calls.append(("resolve", access_token[:8], source_ip))
        return self._resolvable.get(access_token)

    async def refresh(self, refresh_token, source_ip):
        self.calls.append(("refresh", refresh_token[:8], source_ip))
        return self._refreshable.get(refresh_token)

    async def issue_principal(
        self, creator, kind, display_name, system_role, tool_scopes, case_id, source_ip
    ):
        self.calls.append(("issue_principal", kind, display_name, case_id, source_ip))
        self._counter += 1
        result = {
            "principal_type": kind,
            "principal_id": f"{kind}-{self._counter}",
            "auth_user_id": f"auth-{kind}-{self._counter}",
            "access_token": "issued-access-" + secrets.token_hex(8),
            "refresh_token": "issued-refresh-" + secrets.token_hex(8),
            "expires_at": 9999999999,
            "fingerprint": "fp-" + secrets.token_hex(4),
            "display_name": display_name,
            "default_case_id": case_id if kind == "agent" else None,
        }
        self.tokens_issued.append(result)
        return result

    async def reverify_password(
        self, email, password, source_ip, *, expected_auth_user_id=None
    ):
        """CL3b (B-MVP-022): fail-closed re-verify used by sensitive actions.

        Accepts the operator's good password ("pw", same as login) and binds the
        grant subject to the active session (expected_auth_user_id). Wrong
        password -> 401; identity mismatch -> 403; mirroring the real callback.
        """
        self.calls.append(("reverify_password", email, source_ip))
        if password == "wrong" or password != "pw":
            raise PortalAuthError(401, "Invalid credentials")
        if expected_auth_user_id and expected_auth_user_id != _OPERATOR["auth_user_id"]:
            raise PortalAuthError(403, "Re-auth identity mismatch")
        return {"ok": True, "auth_user_id": _OPERATOR["auth_user_id"]}

    async def revoke_principal(self, creator, principal_type, principal_id, source_ip):
        self.calls.append(("revoke_principal", principal_type, principal_id, source_ip))
        self.revoked.append((principal_type, principal_id))
        return None

    async def logout(self, access_token, source_ip):
        self.calls.append(("logout", access_token[:8], source_ip))
        self.logged_out.append(access_token)
        return None

    async def list_principals(self, creator, source_ip):
        self.calls.append(("list_principals", source_ip))
        # Deliberately include token-ish keys to prove the route strips them.
        return [
            {
                "principal_type": "agent",
                "principal_id": "agent-1",
                "display_name": "hermes",
                "status": "active",
                "token_type": "supabase_jwt",
                "last_issued_at": "2026-06-10T01:42:31Z",
                "last_issued_expires_at": "2026-06-12T01:42:31Z",
                "last_issued_token_ttl_seconds": 172800,
                "last_issued_fingerprint": "fp-agent",
                "access_token": "LEAK-SHOULD-BE-STRIPPED",
                "refresh_token": "LEAK-SHOULD-BE-STRIPPED",
            }
        ]


class _ActiveCase:
    def __init__(self, case_id="11111111-1111-1111-1111-111111111111"):
        self.case_id = case_id

    def as_dict(self):
        return {"case_id": self.case_id, "name": "Active"}


class _ActiveCases:
    def __init__(self, case_id="11111111-1111-1111-1111-111111111111"):
        self.case_id = case_id

    def get_active_case(self):
        return _ActiveCase(self.case_id)


@pytest.fixture()
def fake_auth():
    return FakeSupabaseAuth()


@pytest.fixture()
def app(fake_auth):
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        supabase_auth=fake_auth,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


def _envelope_for(result: dict) -> str:
    return generate_session_envelope(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        expires_at=result["expires_at"],
        sub=result["sub"],
        fingerprint=result["fingerprint"],
        secret=_SECRET,
    )


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


class TestLogin:
    def test_login_calls_callback_and_sets_secure_httponly_cookie(self, client, fake_auth):
        resp = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "pw"}
        )
        assert resp.status_code == 200
        assert ("login", "alice@example.com", "testclient") in [
            c for c in fake_auth.calls if c[0] == "login"
        ]
        set_cookie = resp.headers.get("set-cookie", "")
        assert SESSION_ENVELOPE_COOKIE_NAME in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "secure" in set_cookie.lower()
        assert "samesite" in set_cookie.lower()

    def test_login_response_carries_no_token_material(self, client, fake_auth):
        resp = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "pw"}
        )
        body = resp.text
        assert "access-" not in body
        assert "refresh-" not in body
        data = resp.json()
        assert "access_token" not in data
        assert "refresh_token" not in data

    def test_login_wrong_password_maps_to_401(self, client):
        resp = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "wrong"}
        )
        assert resp.status_code == 401

    def test_login_agent_principal_denied_403(self, client):
        resp = client.post(
            "/api/auth/login", json={"email": "agent@example.com", "password": "pw"}
        )
        assert resp.status_code == 403

    def test_login_missing_fields_400(self, client):
        assert client.post("/api/auth/login", json={"email": "x"}).status_code == 400


# ---------------------------------------------------------------------------
# B-MVP-011: the local examiner.json PBKDF2 login fallback is removed entirely
# (not merely suppressed). The setup/challenge/reset endpoints no longer exist,
# and setup-required is a no-op that always reports no local setup.
# ---------------------------------------------------------------------------


class TestLocalLoginFallbackRemoved:
    def test_setup_required_is_noop_with_supabase(self, fake_auth, tmp_path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path / "passwords")
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            supabase_auth=fake_auth,
        )
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.get("/api/auth/setup-required")
        assert resp.status_code == 200
        assert resp.json() == {"required": False, "setup_required": False}

        # The legacy local-account endpoints are gone (404, not 403).
        assert client.post(
            "/api/auth/setup", json={"examiner": "alice", "password": "securepass1"}
        ).status_code == 404
        assert client.get("/api/auth/challenge?examiner=alice").status_code == 404
        assert client.post(
            "/api/auth/reset-password",
            json={"challenge_id": "x", "response": "y", "new_password": "securepass2"},
        ).status_code == 404

    def test_login_fails_closed_without_control_plane(self, tmp_path, monkeypatch):
        """No Supabase callback -> login returns 503, never a silent local fallback."""
        monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", tmp_path / "passwords")
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            supabase_auth=None,
        )
        client = TestClient(app, raise_server_exceptions=True)

        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "pw"},
        )
        assert resp.status_code == 503
        assert "Control plane unavailable" in resp.json()["error"]

        # Legacy local endpoints are gone regardless of Supabase availability.
        assert client.get("/api/auth/setup-required").json() == {
            "required": False,
            "setup_required": False,
        }
        assert client.get("/api/auth/challenge?examiner=alice").status_code == 404


# ---------------------------------------------------------------------------
# me + middleware resolve
# ---------------------------------------------------------------------------


class TestMe:
    def test_me_returns_operator_profile_and_memberships(self, client):
        login = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "pw"}
        )
        cookie = login.cookies[SESSION_ENVELOPE_COOKIE_NAME]
        resp = client.get("/api/auth/me", cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie})
        assert resp.status_code == 200
        data = resp.json()
        assert data["principal_type"] == "operator"
        assert data["display_name"] == "alice"
        assert data["system_role"] == "owner"
        assert data["case_memberships"] == [{"case_id": "case-1", "role": "lead"}]
        # No token material anywhere.
        assert "access_token" not in data and "refresh_token" not in data

    def test_me_without_session_401(self, client):
        assert client.get("/api/auth/me").status_code == 401

    def test_expired_access_token_refreshes_and_rotates_cookie(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        # Build an envelope whose access token does NOT resolve, but whose refresh
        # token DOES refresh into a fresh, resolvable operator session.
        stale_at = "stale-access"
        good_at = "fresh-access"
        rt = "good-refresh"
        fake_auth._resolvable[good_at] = _OPERATOR
        fake_auth._refreshable[rt] = {
            "access_token": good_at,
            "refresh_token": "rotated-refresh",
            "expires_at": 9999999999,
            "sub": _OPERATOR["auth_user_id"],
            "fingerprint": "fp-new",
            "principal": _OPERATOR,
        }
        envelope = generate_session_envelope(
            access_token=stale_at,
            refresh_token=rt,
            expires_at=1,
            sub=_OPERATOR["auth_user_id"],
            fingerprint="fp-old",
            secret=_SECRET,
        )
        resp = client.get(
            "/api/auth/me", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 200
        assert resp.json()["principal_type"] == "operator"
        # Cookie was rotated.
        assert SESSION_ENVELOPE_COOKIE_NAME in resp.headers.get("set-cookie", "")
        assert any(c[0] == "refresh" for c in fake_auth.calls)

    def test_expired_with_no_refresh_fails_closed_and_clears_cookie(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        envelope = generate_session_envelope(
            access_token="dead-access",
            refresh_token="dead-refresh",  # not in _refreshable
            expires_at=1,
            sub="x",
            fingerprint="fp",
            secret=_SECRET,
        )
        resp = client.get(
            "/api/auth/me", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 401
        set_cookie = resp.headers.get("set-cookie", "")
        assert SESSION_ENVELOPE_COOKIE_NAME in set_cookie
        assert "max-age=0" in set_cookie.lower()


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_clears_cookie_and_calls_callback(self, client, fake_auth):
        login = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "pw"}
        )
        cookie = login.cookies[SESSION_ENVELOPE_COOKIE_NAME]
        resp = client.post(
            "/api/auth/logout", cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie}
        )
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert SESSION_ENVELOPE_COOKIE_NAME in set_cookie
        assert "max-age=0" in set_cookie.lower()
        assert len(fake_auth.logged_out) == 1


# ---------------------------------------------------------------------------
# agent/service denied on operator APIs
# ---------------------------------------------------------------------------


class TestAgentDenied:
    def test_agent_principal_denied_on_me(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        at = "agent-access"
        fake_auth._resolvable[at] = _AGENT
        envelope = generate_session_envelope(
            access_token=at,
            refresh_token="agent-refresh",
            expires_at=9999999999,
            sub=_AGENT["auth_user_id"],
            fingerprint="fp",
            secret=_SECRET,
        )
        resp = client.get(
            "/api/auth/me", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        # Resolved agent => examiner/role are None => operator API denies.
        assert resp.status_code == 401

    def test_agent_principal_denied_on_findings(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        at = "agent-access-2"
        fake_auth._resolvable[at] = _AGENT
        envelope = generate_session_envelope(
            access_token=at,
            refresh_token="agent-refresh-2",
            expires_at=9999999999,
            sub=_AGENT["auth_user_id"],
            fingerprint="fp",
            secret=_SECRET,
        )
        resp = client.get(
            "/api/findings", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# legacy session plane removed (B-MVP-023): only Supabase envelope or 401
# ---------------------------------------------------------------------------


class TestLegacyFlag:
    def test_unauthenticated_returns_401(self, client):
        # With the legacy sift_session cookie / Bearer fallback removed, a
        # request that carries no valid Supabase session envelope gets 401.
        resp = client.get("/api/auth/me", cookies={"sift_session": "stale.token.value"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# principal create / revoke / list
# ---------------------------------------------------------------------------


class TestPrincipalLifecycle:
    def _operator_cookie(self, client):
        login = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "pw"}
        )
        return login.cookies[SESSION_ENVELOPE_COOKIE_NAME]

    def test_create_returns_token_once_and_stores_no_raw_token(self, client, fake_auth):
        cookie = self._operator_cookie(client)
        resp = client.post(
            "/api/auth/principals",
            json={
                "kind": "agent",
                "display_name": "Scanner agent",
                "tool_scopes": ["mcp:*"],
                "password": "pw",  # B-MVP-022: credential issuance re-auths
            },
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 201
        data = resp.json()
        # Token material present exactly here, with non-recoverable warning.
        assert data["access_token"].startswith("issued-access-")
        assert data["refresh_token"].startswith("issued-refresh-")
        assert "cannot be recovered" in data["warning"].lower()
        # The portal stores nothing: no module-level cache of raw tokens.
        assert not hasattr(routes_mod, "_ISSUED_TOKENS")

    def test_create_agent_defaults_to_active_case(self, fake_auth):
        active_case_id = "11111111-1111-1111-1111-111111111111"
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            supabase_auth=fake_auth,
            active_case_service=_ActiveCases(active_case_id),
        )
        client = TestClient(app, raise_server_exceptions=True)
        cookie = self._operator_cookie(client)
        resp = client.post(
            "/api/auth/principals",
            json={
                "kind": "agent",
                "display_name": "Scanner agent",
                "tool_scopes": ["mcp:*"],
                "password": "pw",  # B-MVP-022: credential issuance re-auths
            },
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 201
        assert resp.json()["default_case_id"] == active_case_id
        assert fake_auth.calls[-1] == (
            "issue_principal",
            "agent",
            "Scanner agent",
            active_case_id,
            "testclient",
        )

    def test_create_requires_owner_admin(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        # Resolve a non-owner operator (system_role=operator) via envelope.
        plain_op = dict(_OPERATOR, system_role="operator", principal_id="op-2")
        at = "plain-op-access"
        fake_auth._resolvable[at] = plain_op
        envelope = generate_session_envelope(
            access_token=at, refresh_token="r", expires_at=9999999999,
            sub="x", fingerprint="fp", secret=_SECRET,
        )
        resp = client.post(
            "/api/auth/principals",
            json={"kind": "agent", "display_name": "x"},
            cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
        )
        assert resp.status_code == 403

    def test_create_validates_kind(self, client):
        cookie = self._operator_cookie(client)
        resp = client.post(
            "/api/auth/principals",
            json={"kind": "robot", "display_name": "x", "password": "pw"},
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 400

    def test_create_denied_on_wrong_password(self, client, fake_auth):
        """B-MVP-022: a wrong re-auth password denies issuance — no credential."""
        cookie = self._operator_cookie(client)
        resp = client.post(
            "/api/auth/principals",
            json={"kind": "agent", "display_name": "x", "password": "wrong"},
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 401
        # No credential issued: issue_principal was never called.
        assert not any(c[0] == "issue_principal" for c in fake_auth.calls)

    def test_create_denied_when_password_missing(self, client, fake_auth):
        """B-MVP-022: a missing re-auth password fails closed — no credential."""
        cookie = self._operator_cookie(client)
        resp = client.post(
            "/api/auth/principals",
            json={"kind": "agent", "display_name": "x"},
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 400
        assert not any(c[0] == "issue_principal" for c in fake_auth.calls)

    def test_revoke_calls_callback_and_disables_principal(self, client, fake_auth):
        cookie = self._operator_cookie(client)
        resp = client.delete(
            "/api/auth/principals/agent/agent-9",
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 200
        assert ("agent", "agent-9") in fake_auth.revoked

    def test_list_strips_token_material(self, client, fake_auth):
        cookie = self._operator_cookie(client)
        resp = client.get(
            "/api/auth/principals",
            cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie},
        )
        assert resp.status_code == 200
        assert "LEAK-SHOULD-BE-STRIPPED" not in resp.text
        items = resp.json()["principals"]
        assert items[0]["principal_id"] == "agent-1"
        assert items[0]["token_type"] == "supabase_jwt"
        assert items[0]["last_issued_expires_at"] == "2026-06-12T01:42:31Z"
        assert items[0]["last_issued_token_ttl_seconds"] == 172800
        assert "access_token" not in items[0]
        assert "refresh_token" not in items[0]


# ---------------------------------------------------------------------------
# refresh endpoint
# ---------------------------------------------------------------------------


class TestRefreshEndpoint:
    def test_explicit_refresh_rotates_cookie(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        rt = "explicit-refresh"
        fake_auth._refreshable[rt] = {
            "access_token": "new-access",
            "refresh_token": "newer-refresh",
            "expires_at": 9999999999,
            "sub": _OPERATOR["auth_user_id"],
            "fingerprint": "fp-x",
            "principal": _OPERATOR,
        }
        fake_auth._resolvable["new-access"] = _OPERATOR
        envelope = generate_session_envelope(
            access_token="old-access", refresh_token=rt, expires_at=1,
            sub=_OPERATOR["auth_user_id"], fingerprint="fp", secret=_SECRET,
        )
        resp = client.post(
            "/api/auth/refresh", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 200
        assert SESSION_ENVELOPE_COOKIE_NAME in resp.headers.get("set-cookie", "")
        # No token material in body.
        assert "new-access" not in resp.text

    def test_refresh_without_cookie_401(self, client):
        assert client.post("/api/auth/refresh").status_code == 401


# ---------------------------------------------------------------------------
# C1 (HIGH) — agent/service principals denied on operator portal APIs even with
# a valid Supabase JWT in the session-envelope cookie. Principal-truthiness is
# never treated as authorization.
# ---------------------------------------------------------------------------


class TestC1OperatorOnlyEnforcement:
    def _agent_envelope(self, fake_auth):
        at = "c1-agent-access"
        fake_auth._resolvable[at] = _AGENT
        return generate_session_envelope(
            access_token=at,
            refresh_token="c1-agent-refresh",
            expires_at=9999999999,
            sub=_AGENT["auth_user_id"],
            fingerprint="fp",
            secret=_SECRET,
        )

    def test_agent_jwt_cannot_enumerate_principal_roster(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        envelope = self._agent_envelope(fake_auth)
        resp = client.get(
            "/api/auth/principals", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 403
        # The roster must NOT leak even partially.
        assert "agent-1" not in resp.text
        # The list callback must never have been invoked.
        assert not any(c[0] == "list_principals" for c in fake_auth.calls)

    def test_agent_jwt_cannot_create_principal(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        envelope = self._agent_envelope(fake_auth)
        resp = client.post(
            "/api/auth/principals",
            json={"kind": "agent", "display_name": "x"},
            cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
        )
        assert resp.status_code == 403
        assert not any(c[0] == "issue_principal" for c in fake_auth.calls)

    def test_agent_jwt_cannot_revoke_principal(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        envelope = self._agent_envelope(fake_auth)
        resp = client.delete(
            "/api/auth/principals/agent/agent-9",
            cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope},
        )
        assert resp.status_code == 403
        assert fake_auth.revoked == []

    def test_operator_can_still_list(self, client):
        login = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "pw"}
        )
        cookie = login.cookies[SESSION_ENVELOPE_COOKIE_NAME]
        resp = client.get(
            "/api/auth/principals", cookies={SESSION_ENVELOPE_COOKIE_NAME: cookie}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# C10 (MED-LO) — fail-closed/scoping gaps on refresh + absolute envelope cap.
# ---------------------------------------------------------------------------


class TestC10RefreshHardening:
    def test_refresh_callback_raises_clears_cookie(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)

        async def _boom(refresh_token, source_ip):
            raise PortalAuthError(401, "revoked")

        fake_auth.refresh = _boom  # type: ignore[assignment]
        envelope = generate_session_envelope(
            access_token="x", refresh_token="dead", expires_at=1,
            sub="s", fingerprint="fp", secret=_SECRET,
        )
        resp = client.post(
            "/api/auth/refresh", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 401
        set_cookie = resp.headers.get("set-cookie", "")
        assert SESSION_ENVELOPE_COOKIE_NAME in set_cookie
        assert "max-age=0" in set_cookie.lower()

    def test_non_operator_refresh_denied_and_cookie_cleared(self, app, fake_auth):
        client = TestClient(app, raise_server_exceptions=True)
        rt = "agent-refresh-c10"
        fake_auth._refreshable[rt] = {
            "access_token": "agent-new-access",
            "refresh_token": "agent-newer-refresh",
            "expires_at": 9999999999,
            "sub": _AGENT["auth_user_id"],
            "fingerprint": "fp",
            "principal": _AGENT,  # non-operator
        }
        envelope = generate_session_envelope(
            access_token="agent-old", refresh_token=rt, expires_at=1,
            sub=_AGENT["auth_user_id"], fingerprint="fp", secret=_SECRET,
        )
        resp = client.post(
            "/api/auth/refresh", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 401
        assert "max-age=0" in resp.headers.get("set-cookie", "").lower()

    def test_envelope_older_than_absolute_cap_is_rejected(self, app, fake_auth):
        import time as _time

        from case_dashboard.session_jwt import (
            ABSOLUTE_ENVELOPE_LIFETIME_SECONDS,
            verify_session_envelope,
        )

        client = TestClient(app, raise_server_exceptions=True)
        at = "old-but-resolvable"
        fake_auth._resolvable[at] = _OPERATOR
        # Stamp issued_at older than the absolute cap.
        old_eiat = int(_time.time()) - ABSOLUTE_ENVELOPE_LIFETIME_SECONDS - 10
        envelope = generate_session_envelope(
            access_token=at, refresh_token="r", expires_at=9999999999,
            sub=_OPERATOR["auth_user_id"], fingerprint="fp", secret=_SECRET,
            issued_at=old_eiat,
        )
        # Direct verifier rejects it outright.
        assert verify_session_envelope(envelope, _SECRET) is None
        # And the middleware treats it as no session -> /api/auth/me is 401.
        resp = client.get(
            "/api/auth/me", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 401

    def test_rotation_preserves_original_issued_at(self, app, fake_auth):
        """A refresh must NOT reset eiat — the absolute cap survives rotation."""
        import time as _time

        from case_dashboard.session_jwt import verify_session_envelope

        client = TestClient(app, raise_server_exceptions=True)
        rt = "rotate-preserve-rt"
        fake_auth._refreshable[rt] = {
            "access_token": "rot-access",
            "refresh_token": "rot-newer-refresh",
            "expires_at": 9999999999,
            "sub": _OPERATOR["auth_user_id"],
            "fingerprint": "fp-r",
            "principal": _OPERATOR,
        }
        fake_auth._resolvable["rot-access"] = _OPERATOR
        original_eiat = int(_time.time()) - 1000
        envelope = generate_session_envelope(
            access_token="rot-old", refresh_token=rt, expires_at=1,
            sub=_OPERATOR["auth_user_id"], fingerprint="fp", secret=_SECRET,
            issued_at=original_eiat,
        )
        resp = client.post(
            "/api/auth/refresh", cookies={SESSION_ENVELOPE_COOKIE_NAME: envelope}
        )
        assert resp.status_code == 200
        # Extract the rotated cookie and confirm eiat was carried forward.
        rotated = client.cookies.get(SESSION_ENVELOPE_COOKIE_NAME)
        payload = verify_session_envelope(rotated, _SECRET)
        assert payload is not None
        assert payload["eiat"] == original_eiat
