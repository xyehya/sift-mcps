"""Shared Supabase-envelope re-auth test harness (CL3a / B-MVP-017).

CL3a moved every sensitive-action re-auth from the legacy file-HMAC challenge
to a fail-closed Supabase GoTrue password re-verify. The legacy-plane tests
authenticated with the (now-removed, B-MVP-023) legacy session cookie and
answered an HMAC challenge. They are migrated to this harness, which:

  * authenticates via the Supabase session-envelope cookie so the request
    carries an operator ``principal`` (with email) — the email the re-verify
    binds to is taken from the SESSION, never the request body; and
  * wires a fake Supabase callback exposing ``resolve`` + ``reverify_password``
    so a sensitive action can be re-verified without any live network.

A sensitive action now submits ``{"password": ...}`` (over TLS in production,
same as login) instead of an HMAC ``{challenge_id, response}`` pair. The fake's
``reverify_password`` accepts ``_GOOD_PASSWORD`` and fails closed otherwise,
mirroring the production Supabase grant (wrong password -> 401, control plane
unreachable -> 503).
"""

from __future__ import annotations

import secrets
from typing import Any

from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)

# Canonical operator credentials used across the migrated suites.
GOOD_PASSWORD = "password123"
OPERATOR_EMAIL = "alice@operators.sift.local"
OPERATOR_AUTH_USER_ID = "auth-user-op-alice"

# The access token an envelope carries; the fake resolves it to OPERATOR.
_ACCESS_TOKEN = "reauth-access-" + secrets.token_hex(8)


def operator_principal(
    *,
    display_name: str = "alice",
    email: str = OPERATOR_EMAIL,
    system_role: str = "owner",
    status: str = "active",
    auth_user_id: str = OPERATOR_AUTH_USER_ID,
    principal_id: str = "op-alice",
) -> dict[str, Any]:
    return {
        "principal_type": "operator",
        "principal_id": principal_id,
        "auth_user_id": auth_user_id,
        "display_name": display_name,
        "email": email,
        "system_role": system_role,
        "status": status,
        "case_memberships": [],
    }


class ReauthFakeSupabaseAuth:
    """Minimal C3 callback with operator resolve + fail-closed reverify_password.

    ``control_plane_down`` flips the re-verify to raise a 503 so a test can prove
    the sensitive action FAILS CLOSED when the control plane is unreachable —
    never falling back to a local verifier.
    """

    class _Error(Exception):
        def __init__(self, http_status: int, reason: str):
            super().__init__(reason)
            self.http_status = http_status
            self.reason = reason

    def __init__(
        self,
        *,
        principal: dict[str, Any] | None = None,
        good_password: str = GOOD_PASSWORD,
        control_plane_down: bool = False,
        grant_auth_user_id: str | None = None,
    ):
        self._principal = principal or operator_principal()
        self._good_password = good_password
        self.control_plane_down = control_plane_down
        # The auth user the password GRANT resolves to. Defaults to the session
        # principal's own id (the normal case). Set it to a DIFFERENT id to model
        # a cross-operator binding attack (session A re-auths with operator B's
        # email+password): the grant subject must match the session.
        self._grant_auth_user_id = grant_auth_user_id or self._principal["auth_user_id"]
        self.reverify_calls: list[tuple[str, str | None]] = []

    async def resolve(self, access_token: str, source_ip: str | None):
        if access_token == _ACCESS_TOKEN:
            return self._principal
        return None

    async def refresh(self, refresh_token: str, source_ip: str | None):
        return None

    async def reverify_password(
        self,
        email: str,
        password: str,
        source_ip: str | None,
        *,
        expected_auth_user_id: str | None = None,
    ) -> dict[str, Any]:
        self.reverify_calls.append((email, source_ip))
        if self.control_plane_down:
            # Mirror SupabaseUnavailableError -> HTTP 503 (fail closed).
            raise self._Error(503, "supabase_unavailable")
        if password != self._good_password:
            # Mirror GoTrue wrong-password -> InvalidTokenError -> HTTP 401.
            raise self._Error(401, "invalid_token")
        # The grant resolves to _grant_auth_user_id; it must match the active
        # session (expected_auth_user_id) or the re-verify is forbidden (403),
        # exactly as the real callback binds the grant subject to the session.
        if expected_auth_user_id and expected_auth_user_id != self._grant_auth_user_id:
            raise self._Error(403, "forbidden")
        return {"ok": True, "auth_user_id": self._grant_auth_user_id,
                "principal_id": self._principal["principal_id"]}


def operator_envelope(secret: str, *, sub: str = OPERATOR_AUTH_USER_ID) -> str:
    """A signed session envelope the fake resolves to the operator principal."""
    return generate_session_envelope(
        access_token=_ACCESS_TOKEN,
        refresh_token="reauth-refresh-" + secrets.token_hex(8),
        expires_at=9999999999,
        sub=sub,
        fingerprint="fp-reauth",
        secret=secret,
    )


def set_operator_session(client, secret: str) -> None:
    """Attach the operator session-envelope cookie to a TestClient."""
    client.cookies[SESSION_ENVELOPE_COOKIE_NAME] = operator_envelope(secret)
