"""Tests for reports endpoints in Examiner Portal.
"""

from __future__ import annotations

import json
import secrets
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch
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


@pytest.fixture()
def auth_examiner_cookie(client):
    cookie_val = generate_jwt("alice", "examiner", _SECRET, max_age=3600)
    client.cookies.set(COOKIE_NAME, cookie_val)
    return client


@pytest.fixture()
def auth_readonly_cookie(client):
    cookie_val = generate_jwt("bob", "readonly", _SECRET, max_age=3600)
    client.cookies.set(COOKIE_NAME, cookie_val)
    return client


class TestReportsEndpoints:
    def test_unauthenticated_returns_401(self, client):
        assert client.get("/api/reports").status_code == 401
        assert client.post("/api/reports/generate").status_code == 401
        assert client.post(f"/api/reports/{uuid.uuid4()}/save").status_code == 401
        assert client.get(f"/api/reports/{uuid.uuid4()}").status_code == 401
        assert client.get(f"/api/reports/{uuid.uuid4()}/download").status_code == 401

    def test_readonly_returns_403(self, auth_readonly_cookie):
        assert auth_readonly_cookie.get("/api/reports").status_code == 403
        assert auth_readonly_cookie.post("/api/reports/generate").status_code == 403
        assert auth_readonly_cookie.post(f"/api/reports/{uuid.uuid4()}/save").status_code == 403
        assert auth_readonly_cookie.get(f"/api/reports/{uuid.uuid4()}").status_code == 403
        assert auth_readonly_cookie.get(f"/api/reports/{uuid.uuid4()}/download").status_code == 403

    def test_no_active_case_returns_404(self, auth_examiner_cookie, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)
        assert auth_examiner_cookie.get("/api/reports").status_code == 404
        assert auth_examiner_cookie.post("/api/reports/generate", json={"profile": "full"}).status_code == 404
        assert auth_examiner_cookie.post(f"/api/reports/{uuid.uuid4()}/save").status_code == 404
        assert auth_examiner_cookie.get(f"/api/reports/{uuid.uuid4()}").status_code == 404
        assert auth_examiner_cookie.get(f"/api/reports/{uuid.uuid4()}/download").status_code == 404

    def test_invalid_uuid_returns_400(self, auth_examiner_cookie, tmp_path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)
        assert auth_examiner_cookie.post("/api/reports/invalid-uuid/save").status_code == 400
        assert auth_examiner_cookie.get("/api/reports/invalid-uuid").status_code == 400
        assert auth_examiner_cookie.get("/api/reports/invalid-uuid/download").status_code == 400

    def test_unknown_profile_returns_400(self, auth_examiner_cookie, tmp_path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)
        resp = auth_examiner_cookie.post("/api/reports/generate", json={"profile": "nonexistent"})
        assert resp.status_code == 400
        assert "Unknown profile" in resp.json()["error"]

    def test_rate_limit_max_1_in_flight(self, auth_examiner_cookie, tmp_path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)

        # Mock _generate to simulate blocking or slow behavior, or simply verify lock works
        # If we insert case_id into _IN_FLIGHT_GENERATIONS manually:
        case_id = tmp_path.name
        routes_mod._IN_FLIGHT_GENERATIONS.add(case_id)
        try:
            resp = auth_examiner_cookie.post("/api/reports/generate", json={"profile": "full"})
            assert resp.status_code == 429
            assert "Too many attempts" in resp.json()["error"]
        finally:
            routes_mod._IN_FLIGHT_GENERATIONS.discard(case_id)

    def test_generate_save_load_download_flow(self, auth_examiner_cookie, tmp_path, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)

        fake_report = {
            "profile": "executive",
            "report_data": {
                "metadata": {"case_id": "test-case", "name": "Test Case"},
                "summary": {"findings_approved": 2},
                "findings": [{"id": "F-1", "title": "Suspect activity", "observation": "Observed suspicious payload"}]
            },
            "sections": [
                {"name": "Executive Summary", "type": "narrative"},
                {"name": "Approved Findings", "type": "data_narrative", "data_key": "findings"}
            ],
            "writing_guidance": "Test guidance",
        }

        # Clear pending reports
        routes_mod._PENDING_REPORTS.clear()

        with patch("report_mcp.server._generate", return_value=fake_report):
            resp = auth_examiner_cookie.post("/api/reports/generate", json={"profile": "executive"})
            assert resp.status_code == 200
            data = resp.json()
            report_id = data["id"]
            assert report_id in routes_mod._PENDING_REPORTS

            # Get draft by ID
            resp_draft = auth_examiner_cookie.get(f"/api/reports/{report_id}")
            assert resp_draft.status_code == 200
            assert resp_draft.json()["id"] == report_id

            # Save draft
            resp_save = auth_examiner_cookie.post(f"/api/reports/{report_id}/save")
            assert resp_save.status_code == 200
            assert resp_save.json()["status"] == "saved"

            # Check that it is listed
            resp_list = auth_examiner_cookie.get("/api/reports")
            assert resp_list.status_code == 200
            listed = resp_list.json()
            assert len(listed) == 1
            assert listed[0]["id"] == report_id
            assert listed[0]["profile"] == "executive"
            assert listed[0]["examiner"] == "alice"

            # Get saved report by ID (which loads from file)
            resp_get = auth_examiner_cookie.get(f"/api/reports/{report_id}")
            assert resp_get.status_code == 200
            assert resp_get.json()["id"] == report_id

            # Download report as markdown
            resp_dl = auth_examiner_cookie.get(f"/api/reports/{report_id}/download")
            assert resp_dl.status_code == 200
            assert resp_dl.headers["content-type"].startswith("text/markdown")
            assert "Content-Disposition" in resp_dl.headers
            assert "Suspect activity" in resp_dl.text
            assert "Observed suspicious payload" in resp_dl.text
