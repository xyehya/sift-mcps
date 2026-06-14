"""Tests for the portal-owned case-metadata endpoint (F-E).

Setting case metadata is examiner-triggered in the portal — it is not on the
agent MCP surface. The validation/persistence logic lives in
sift_core.case_metadata; this exercises the route wiring + role guard.

B-MVP-023: migrated from the legacy sift_session JWT cookie to the
Supabase-envelope harness.
"""

from __future__ import annotations

import secrets

import pytest
import yaml
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app

from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)


@pytest.fixture()
def client():
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        supabase_auth=ReauthFakeSupabaseAuth(),
        legacy_portal_session_enabled=False,
    )
    return TestClient(app)


@pytest.fixture()
def examiner(client):
    set_operator_session(client, _SECRET)
    return client


@pytest.fixture()
def readonly():
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        supabase_auth=ReauthFakeSupabaseAuth(
            principal=operator_principal(system_role="readonly")
        ),
        legacy_portal_session_enabled=False,
    )
    c = TestClient(app)
    set_operator_session(c, _SECRET)
    return c


@pytest.fixture()
def case_dir(tmp_path, monkeypatch):
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "meta-case", "name": "MetaCase", "examiner": "alice"})
    )
    monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: tmp_path)
    return tmp_path


class TestCaseMetadataEndpoint:
    def test_unauthenticated_401(self, client):
        assert client.post("/api/case/metadata", json={"field": "severity", "value": "high"}).status_code == 401

    def test_readonly_403(self, readonly, case_dir):
        assert readonly.post("/api/case/metadata", json={"field": "severity", "value": "high"}).status_code == 403

    def test_examiner_can_set_metadata(self, examiner, case_dir):
        resp = examiner.post("/api/case/metadata", json={"field": "severity", "value": "high"})
        assert resp.status_code == 200
        assert resp.json() == {"status": "set", "field": "severity", "value": "high"}
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert meta["severity"] == "high"
        # identity/lifecycle fields preserved
        assert meta["case_id"] == "meta-case"

    def test_missing_field_400(self, examiner, case_dir):
        assert examiner.post("/api/case/metadata", json={"value": "high"}).status_code == 400

    def test_protected_field_400(self, examiner, case_dir):
        resp = examiner.post("/api/case/metadata", json={"field": "case_id", "value": "x"})
        assert resp.status_code == 400
        assert "protected" in resp.json()["error"].lower()

    def test_invalid_enum_400(self, examiner, case_dir):
        resp = examiner.post("/api/case/metadata", json={"field": "severity", "value": "nope"})
        assert resp.status_code == 400
        assert "Invalid value" in resp.json()["error"]

    def test_no_active_case_404(self, examiner, monkeypatch):
        monkeypatch.setattr(routes_mod, "_resolve_case_dir", lambda: None)
        assert examiner.post("/api/case/metadata", json={"field": "severity", "value": "high"}).status_code == 404
