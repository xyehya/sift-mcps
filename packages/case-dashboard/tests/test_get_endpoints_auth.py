"""Tests for Examiner Portal GET API endpoints authentication validation.

B-MVP-023: migrated from the legacy sift_session JWT cookie to the
Supabase-envelope harness. The app is instantiated with
legacy_portal_session_enabled=False and a supabase_auth fake so the
Supabase-envelope path is the only active auth plane.
"""

from __future__ import annotations

import secrets
import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import SESSION_ENVELOPE_COOKIE_NAME

from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)


def _make_app(*, system_role: str = "owner"):
    """App with Supabase-envelope auth, legacy plane disabled."""
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        supabase_auth=ReauthFakeSupabaseAuth(
            principal=operator_principal(system_role=system_role)
        ),
        legacy_portal_session_enabled=False,
    )


def _readonly_app():
    return _make_app(system_role="readonly")


@pytest.fixture()
def client():
    return TestClient(_make_app())


@pytest.fixture()
def readonly_client():
    return TestClient(_readonly_app())


class TestGetEndpointsAuth:
    @pytest.mark.parametrize("path", [
        "/api/findings",
        "/api/findings/f-1",
        "/api/timeline",
        "/api/evidence",
        "/api/audit/f-1",
        "/api/delta",
        "/api/case",
        "/api/todos",
        "/api/iocs",
        "/api/summary",
    ])
    def test_unauthenticated_returns_401(self, client, path):
        resp = client.get(path)
        assert resp.status_code == 401
        assert resp.json() == {"error": "Authentication required"}

    @pytest.mark.parametrize("path", [
        "/api/findings",
        "/api/findings/f-1",
        "/api/timeline",
        "/api/audit/f-1",
        "/api/delta",
        "/api/case",
        "/api/todos",
        "/api/iocs",
        "/api/summary",
    ])
    def test_authenticated_examiner_passes_auth(self, client, path, monkeypatch):
        # Prevent actually loading files, we just want to verify auth phase passes
        # (resulting in "no active case" 404 response).
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)

        set_operator_session(client, _SECRET)
        resp = client.get(path)
        # Auth passes, so it resolves case dir, finds None, and returns 404 (No active case)
        assert resp.status_code == 404
        assert "No active case" in resp.json().get("error", "")

    @pytest.mark.parametrize("path", [
        "/api/findings",
        "/api/findings/f-1",
        "/api/timeline",
        "/api/audit/f-1",
        "/api/delta",
        "/api/case",
        "/api/todos",
        "/api/iocs",
        "/api/summary",
    ])
    def test_authenticated_readonly_passes_auth(self, readonly_client, path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)

        set_operator_session(readonly_client, _SECRET)
        resp = readonly_client.get(path)
        assert resp.status_code == 404
        assert "No active case" in resp.json().get("error", "")

    @pytest.mark.parametrize("role", ["owner", "readonly"])
    def test_evidence_list_degrades_to_empty_on_fresh_install(self, role, monkeypatch):
        # Evidence is DB-authority only; with no DB service / no active case the
        # list endpoint degrades gracefully to an empty 200 (never a file read,
        # never 404), so a fresh install never blocks the evidence UI.
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)

        c = TestClient(_make_app(system_role=role))
        set_operator_session(c, _SECRET)
        resp = c.get("/api/evidence")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.parametrize("path", [
        "/api/findings",
        "/api/findings/f-1",
        "/api/timeline",
        "/api/evidence",
        "/api/audit/f-1",
        "/api/delta",
        "/api/case",
        "/api/todos",
        "/api/iocs",
        "/api/summary",
    ])
    def test_unauthenticated_no_envelope_returns_401_or_403(self, client, path):
        # No session envelope cookie present → handlers enforce 401/403.
        resp = client.get(path)
        assert resp.status_code in (401, 403)
