"""Tests for Examiner Portal GET API endpoints authentication validation.
"""

from __future__ import annotations

import secrets
import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt

_SECRET = secrets.token_hex(32)

@pytest.fixture()
def client():
    app = create_dashboard_v2_app(session_secret=_SECRET)
    return TestClient(app)

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

        cookie_val = generate_jwt("alice", "examiner", _SECRET, max_age=3600)
        client.cookies.set(COOKIE_NAME, cookie_val)
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
    def test_authenticated_readonly_passes_auth(self, client, path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)

        cookie_val = generate_jwt("bob", "readonly", _SECRET, max_age=3600)
        client.cookies.set(COOKIE_NAME, cookie_val)
        resp = client.get(path)
        assert resp.status_code == 404
        assert "No active case" in resp.json().get("error", "")

    @pytest.mark.parametrize("role", ["examiner", "readonly"])
    def test_evidence_list_degrades_to_empty_on_fresh_install(self, client, role, monkeypatch):
        # Evidence is DB-authority only; with no DB service / no active case the
        # list endpoint degrades gracefully to an empty 200 (never a file read,
        # never 404), so a fresh install never blocks the evidence UI.
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)

        cookie_val = generate_jwt("alice", role, _SECRET, max_age=3600)
        client.cookies.set(COOKIE_NAME, cookie_val)
        resp = client.get("/api/evidence")
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
    def test_authenticated_invalid_role_blocked(self, client, path):
        # role "agent" is not allowed in examiner portal
        cookie_val = generate_jwt("agent-1", "agent", _SECRET, max_age=3600)
        client.cookies.set(COOKIE_NAME, cookie_val)
        resp = client.get(path)
        assert resp.status_code == 403
        assert resp.json() == {"error": "Examiner or Readonly role required"}
