"""SEC-6 — the legacy PR02 ``/api/tokens/*`` lifecycle has been REMOVED.

Previously this module exercised the create/list/revoke/rotate/reactivate flow
for legacy service tokens. SEC-6 (DSS-CAN-014/015) removes that lifecycle
entirely: agent/service credentials are issued solely through the Supabase
principal API (``/api/auth/principals``), which already enforces owner/admin
authority + password step-up. These fail-on-revert tests assert the legacy
routes are no longer mounted (a re-introduction would flip the 404s and fail).
"""

from __future__ import annotations

import secrets

import pytest
from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

# 32-byte hex secret so the session envelope HMAC (bytes.fromhex) is valid.
_SECRET = secrets.token_hex(32)


def _operator_client() -> TestClient:
    """Portal client authenticated as an owner operator (so a 404 below proves
    the route is GONE, not merely auth-blocked)."""
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        api_keys={},
        supabase_auth=ReauthFakeSupabaseAuth(
            principal=operator_principal(system_role="owner")
        ),
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    return client


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/tokens"),
        ("POST", "/api/tokens"),
        ("DELETE", "/api/tokens/some-token-id"),
        ("POST", "/api/tokens/some-token-id/rotate"),
        ("POST", "/api/tokens/some-token-id/reactivate"),
    ],
)
def test_legacy_token_routes_are_removed(method, path):
    client = _operator_client()
    resp = client.request(method, path, json={})
    # The route no longer exists — Starlette returns 404 (unrouted) / 405. It must
    # never be a 2xx success: the legacy lifecycle is retired, not flag-gated.
    assert resp.status_code in (404, 405), (
        f"{method} {path} returned {resp.status_code}; the legacy /api/tokens "
        "lifecycle must stay removed"
    )


def test_principal_api_is_the_supported_issuance_surface():
    # The replacement surface is still mounted (issuance moved here, with
    # owner/admin + step-up enforced by the handler).
    client = _operator_client()
    resp = client.get("/api/auth/principals")
    assert resp.status_code != 404
