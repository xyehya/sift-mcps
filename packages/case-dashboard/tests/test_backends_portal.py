"""Tests for portal-owned backends and services API proxies (Phase 6.3)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

import pytest
import yaml
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt

_SECRET = secrets.token_hex(32)


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def mock_gateway():
    gateway = MagicMock()
    gateway.evaluate_requirement.side_effect = lambda req: req != "unmet:req"
    gateway.backends = {}
    gateway.config = {"backends": {}}
    gateway._pending_backends = {}
    gateway._reload_event = MagicMock()
    gateway._build_tool_map = AsyncMock()
    return gateway


@pytest.fixture()
def client(passwords_dir, mock_gateway, tmp_path, monkeypatch):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(session_secret=_SECRET)
    app.state.gateway = mock_gateway
    return TestClient(app)


def _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=None):
    if passwords_dir:
        passwords_dir.mkdir(parents=True, exist_ok=True)
        # Setup PBKDF2 hash for password123
        pbkdf2_bin = hashlib.pbkdf2_hmac("sha256", b"password123", b"salt123", 600000)
        entry = {
            "hash": pbkdf2_bin.hex(),
            "salt": "salt123",
            "must_reset_password": False
        }
        (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))

    token = generate_jwt(examiner, role, _SECRET, max_age=3600)
    client.cookies[COOKIE_NAME] = token
    return token


def _get_challenge_response(client, passwords_dir, examiner="alice"):
    resp = client.get("/api/commit/challenge")
    assert resp.status_code == 200
    chal = resp.json()
    challenge_id = chal["challenge_id"]
    nonce = chal["nonce"]

    # Compute HMAC response
    pbkdf2_bin = hashlib.pbkdf2_hmac("sha256", b"password123", b"salt123", 600000)
    response_hmac = hmac.new(
        pbkdf2_bin, nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return challenge_id, response_hmac


class TestBackendsPortal:
    def test_unauthenticated_401(self, client):
        assert client.get("/api/backends").status_code == 401
        assert client.post("/api/backends", json={}).status_code == 401
        assert client.post("/api/backends/validate", json={}).status_code == 401
        assert client.post("/api/backends/reload", json={}).status_code == 401
        assert client.post("/api/services/test/start", json={}).status_code == 401

    def test_readonly_role_denied_for_mutations(self, client, passwords_dir):
        _setup_cookie(client, examiner="bob", role="readonly", passwords_dir=passwords_dir)
        # GET is allowed
        assert client.get("/api/backends").status_code == 200

        # POSTs are denied
        assert client.post("/api/backends", json={}).status_code == 403
        assert client.post("/api/backends/validate", json={}).status_code == 403
        assert client.post("/api/backends/reload", json={}).status_code == 403
        assert client.post("/api/services/test/start", json={}).status_code == 403

    def test_mutating_requests_reject_missing_origin(self, client, passwords_dir):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

        # Missing Origin header
        headers = {}
        assert client.post("/api/backends", json={}, headers=headers).status_code == 400
        assert client.post("/api/backends/validate", json={}, headers=headers).status_code == 400
        assert client.post("/api/backends/reload", json={}, headers=headers).status_code == 400
        assert client.post("/api/services/test/start", json={}, headers=headers).status_code == 400

        # Wrong Origin header
        headers = {"origin": "http://malicious.site"}
        assert client.post("/api/backends", json={}, headers=headers).status_code == 400

    def test_validate_route_rejects_missing_origin_but_skips_challenge(self, client, passwords_dir):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

        # Correct Origin header, but NO challenge credentials
        headers = {"origin": "http://testserver"}
        resp = client.post(
            "/api/backends/validate",
            json={"name": "test-backend", "config": {"type": "stdio", "command": "true"}},
            headers=headers
        )
        # Should proceed to validation logic (which will fail because manifest is missing, returning 422, not 400/401)
        assert resp.status_code == 422
        assert "manifest is missing" in resp.json()["reasons"][0]["reason"]

    def test_reload_route_requires_challenge(self, client, passwords_dir):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}

        # Missing challenge
        resp = client.post("/api/backends/reload", json={}, headers=headers)
        assert resp.status_code == 400
        assert "challenge_id" in resp.json()["error"]

        # Valid challenge
        challenge_id, response = _get_challenge_response(client, passwords_dir)
        resp = client.post(
            "/api/backends/reload",
            json={"challenge_id": challenge_id, "response": response},
            headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_config"  # config path doesn't exist in test tmp_path

    def test_register_route_requires_challenge_and_handles_success(self, client, passwords_dir, mock_gateway, tmp_path, monkeypatch):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}

        # Write gateway config path
        config_path = tmp_path / "gateway.yaml"
        monkeypatch.setattr(routes_mod, "_GATEWAY_CONFIG_PATH", config_path)
        from sift_gateway.rest import _gateway_config_path
        monkeypatch.setattr("sift_gateway.rest._gateway_config_path", lambda: config_path)

        # Write temporary manifest
        manifest = {
            "spec_version": "1.0",
            "name": "test-backend",
            "version": "1.0.0",
            "tier": "addon",
            "transport": "stdio",
            "namespace": "test",
            "instructions": "Test instructions.",
            "capabilities": {
                "provides": ["search"],
                "requires": [],
                "enriches_responses": False
            },
            "tools": [
                {
                    "name": "test_search",
                    "description": "test tool",
                    "read_only": True,
                    "readOnlyHint": True,
                    "evidence_class": "read_only",
                    "category": "search-analysis",
                    "recommended_phase": "ANALYZE"
                },
                {
                    "name": "test_health",
                    "description": "test health tool",
                    "read_only": True,
                    "readOnlyHint": True,
                    "evidence_class": "read_only",
                    "category": "search-analysis",
                    "recommended_phase": "ANALYZE",
                    "health": True
                }
            ],
            "health": "test_health"
        }
        manifest_path = tmp_path / "sift-backend.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        # Valid challenge + config payload
        challenge_id, response = _get_challenge_response(client, passwords_dir)
        payload = {
            "name": "test-backend",
            "config": {
                "type": "stdio",
                "command": "true",
                "manifest_path": str(manifest_path)
            },
            "challenge_id": challenge_id,
            "response": response
        }

        resp = client.post("/api/backends", json=payload, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["registered"] is True

        # Check config was written
        assert config_path.exists()
        cfg_doc = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "test-backend" in cfg_doc["backends"]

    def test_register_rejects_invalid_name(self, client, passwords_dir, mock_gateway, tmp_path, monkeypatch):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}

        challenge_id, response = _get_challenge_response(client, passwords_dir)
        payload = {
            "name": "../test_backend",  # Path traversal / invalid characters
            "config": {"type": "stdio", "command": "true"},
            "challenge_id": challenge_id,
            "response": response
        }
        resp = client.post("/api/backends", json=payload, headers=headers)
        assert resp.status_code == 422
        assert any("name" in r["field"] for r in resp.json()["reasons"])

    def test_list_backends_includes_disabled_and_gated_and_redacts_secrets(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

        # Set config in mock gateway
        mock_gateway.config = {
            "backends": {
                "active-backend": {"type": "stdio", "enabled": True, "command": "true"},
                "disabled-backend": {"type": "stdio", "enabled": False, "command": "true"},
                "gated-backend": {"type": "http", "enabled": True, "url": "http://localhost:1234", "bearer_token": "secret_token"}
            }
        }
        # mock active backend in gateway.backends
        active_bk = MagicMock()
        active_bk.started = True
        active_bk.enabled = True
        active_bk.health_check = AsyncMock(return_value={"status": "ok"})
        # active-backend manifest
        active_bk.manifest = {
            "capabilities": {"provides": ["search"], "requires": []}
        }

        # gated backend in gateway.backends
        gated_bk = MagicMock()
        gated_bk.started = False
        gated_bk.enabled = True
        gated_bk.manifest = {
            "capabilities": {"provides": ["search"], "requires": ["unmet:req"]}
        }

        mock_gateway.backends = {
            "active-backend": active_bk,
            "gated-backend": gated_bk
        }

        resp = client.get("/api/backends")
        assert resp.status_code == 200
        backends = {b["name"]: b for b in resp.json()["backends"]}

        assert len(backends) == 3
        assert backends["active-backend"]["enabled"] is True
        assert backends["active-backend"]["started"] is True
        assert backends["active-backend"]["health"] == {"status": "ok"}

        assert backends["disabled-backend"]["enabled"] is False
        assert backends["disabled-backend"]["started"] is False
        assert backends["disabled-backend"]["health"] == {"status": "disabled"}

        assert backends["gated-backend"]["enabled"] is True
        assert backends["gated-backend"]["started"] is False
        assert backends["gated-backend"]["unmet_requires"] == ["unmet:req"]
        assert backends["gated-backend"]["health"] == {"status": "gated", "detail": "Unmet requirements: unmet:req"}

        # Secret verification check: no secrets should leak in listing
        content = resp.text
        assert "secret_token" not in content

    def test_stop_service_allowed_for_gated_or_disabled_started_backends(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}

        mock_gateway.config = {
            "backends": {
                "test-gated": {"type": "stdio", "enabled": True, "command": "true"}
            }
        }

        # Start service should fail if gated/disabled
        active_bk = MagicMock()
        active_bk.started = True
        active_bk.manifest = {
            "capabilities": {"provides": ["search"], "requires": ["unmet:req"]}
        }
        active_bk.stop = AsyncMock()
        mock_gateway.backends = {"test-gated": active_bk}

        # Try to start -> should be rejected because requirements are unmet
        challenge_id, response = _get_challenge_response(client, passwords_dir)
        start_resp = client.post(
            "/api/services/test-gated/start",
            json={"challenge_id": challenge_id, "response": response},
            headers=headers
        )
        assert start_resp.status_code == 400
        assert "unmet requirements" in start_resp.json()["error"]

        # Try to stop -> should be allowed even if requirements are unmet
        challenge_id, response = _get_challenge_response(client, passwords_dir)
        stop_resp = client.post(
            "/api/services/test-gated/stop",
            json={"challenge_id": challenge_id, "response": response},
            headers=headers
        )
        assert stop_resp.status_code == 200
        assert stop_resp.json()["status"] == "stopped"
        assert active_bk.stop.called
