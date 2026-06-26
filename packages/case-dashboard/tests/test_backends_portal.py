"""Tests for portal-owned backends and services API proxies (Phase 6.3)."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app

from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

_SECRET = secrets.token_hex(32)


class _RegistryRecord:
    def __init__(self, name, *, transport="stdio", enabled=True, manifest=None, updated_at=None):
        self.id = f"id-{name}"
        self.name = name
        self.transport = transport
        self.namespace = name.split("-", 1)[0]
        self.tier = "addon"
        self.enabled = enabled
        self.connection = {"type": transport}
        self.manifest = manifest or {"capabilities": {"provides": ["search"], "requires": []}}
        self.manifest_source = None
        self.manifest_sha256 = "0" * 64
        self.health_status = "unknown"
        self.health_detail = None
        self.health_checked_at = None
        self.created_at = updated_at or datetime.now(timezone.utc)
        self.updated_at = updated_at or self.created_at

    def public_dict(self, *, started, available, pending_apply):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.transport,
            "transport": self.transport,
            "namespace": self.namespace,
            "tier": self.tier,
            "enabled": self.enabled,
            "started": started,
            "available": available,
            "pending_apply": pending_apply,
            "connection": dict(self.connection),
            "manifest_source": self.manifest_source,
            "manifest_sha256": self.manifest_sha256,
            "health": {"status": self.health_status, "detail": self.health_detail, "checked_at": None},
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class _Registry:
    def __init__(self, records=None):
        self.records = list(records or [])
        self.registered = []
        self.unregistered = []

    def list_backends(self):
        return list(self.records)

    def register(self, *, name, config, manifest, actor=None):
        del actor
        record = _RegistryRecord(
            name,
            transport=config.get("type", "stdio"),
            enabled=config.get("enabled", True),
            manifest=manifest,
            updated_at=datetime.now(timezone.utc) + timedelta(seconds=1),
        )
        self.registered.append((name, config, manifest))
        self.records = [r for r in self.records if r.name != name] + [record]
        return record

    def update_health(self, name, status, detail=None):
        for record in self.records:
            if record.name == name:
                record.health_status = status
                record.health_detail = detail

    def unregister(self, name, *, actor=None):
        del actor
        self.unregistered.append(name)
        self.records = [record for record in self.records if record.name != name]

    def set_enabled(self, name, enabled, *, actor=None):
        del actor
        for record in self.records:
            if record.name == name:
                record.enabled = enabled
                self.enabled_changes = getattr(self, "enabled_changes", [])
                self.enabled_changes.append((name, enabled))
                return record
        exc = Exception(f"Unknown backend: {name}")
        exc.http_status = 404
        raise exc


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
    gateway.mcp_backend_registry = _Registry()
    gateway._mcp_catalog_loaded_at = datetime.now(timezone.utc)
    gateway._build_tool_map = AsyncMock()
    return gateway


@pytest.fixture()
def fake_auth():
    return ReauthFakeSupabaseAuth()


@pytest.fixture()
def client(passwords_dir, mock_gateway, tmp_path, monkeypatch, fake_auth):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(session_secret=_SECRET, supabase_auth=fake_auth)
    app.state.gateway = mock_gateway
    c = TestClient(app)
    c._fake_auth = fake_auth  # so _setup_cookie can swap the resolved role
    return c


def _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=None):
    """Attach a Supabase operator/readonly session (CL3a re-auth harness).

    ``role='readonly'`` swaps the fake auth's resolved principal to a readonly
    operator so the operator route role checks see the same role as before.
    """
    system_role = "readonly" if role == "readonly" else "owner"
    client._fake_auth._principal = operator_principal(
        display_name=examiner, system_role=system_role,
        principal_id=f"op-{examiner}",
    )
    set_operator_session(client, _SECRET)


# CL3a: a sensitive backend/service action now submits {"password": ...} which is
# re-verified against Supabase, replacing the old HMAC challenge/response.
_REAUTH_BODY = {"password": GOOD_PASSWORD}


class TestBackendsPortal:
    def test_unauthenticated_401(self, client):
        assert client.get("/api/backends").status_code == 401
        assert client.post("/api/backends", json={}).status_code == 401
        assert client.post("/api/backends/validate", json={}).status_code == 401
        assert client.post("/api/backends/reload", json={}).status_code == 401
        assert client.request("DELETE", "/api/backends/test", json={}).status_code == 401
        assert client.post("/api/services/test/start", json={}).status_code == 401

    def test_readonly_role_denied_for_mutations(self, client, passwords_dir):
        _setup_cookie(client, examiner="bob", role="readonly", passwords_dir=passwords_dir)
        # GET is allowed
        assert client.get("/api/backends").status_code == 200

        # POSTs are denied
        assert client.post("/api/backends", json={}).status_code == 403
        assert client.post("/api/backends/validate", json={}).status_code == 403
        assert client.post("/api/backends/reload", json={}).status_code == 403
        assert client.request("DELETE", "/api/backends/test", json={}).status_code == 403
        assert client.post("/api/services/test/start", json={}).status_code == 403

    def test_mutating_requests_reject_missing_origin(self, client, passwords_dir):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

        # Missing Origin header
        headers = {}
        assert client.post("/api/backends", json={}, headers=headers).status_code == 400
        assert client.post("/api/backends/validate", json={}, headers=headers).status_code == 400
        assert client.post("/api/backends/reload", json={}, headers=headers).status_code == 400
        assert client.request("DELETE", "/api/backends/test", json={}, headers=headers).status_code == 400
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

        # Missing password
        resp = client.post("/api/backends/reload", json={}, headers=headers)
        assert resp.status_code == 400
        assert "password" in resp.json()["error"].lower()

        # Valid re-auth
        resp = client.post(
            "/api/backends/reload",
            json=dict(_REAUTH_BODY),
            headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "current"
        assert resp.json()["authority"] == "app.mcp_backends"

    def test_unregister_route_requires_challenge_and_handles_success(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}
        mock_gateway.mcp_backend_registry.records = [_RegistryRecord("test-backend")]

        resp = client.request(
            "DELETE",
            "/api/backends/test-backend",
            json={},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "password" in resp.json()["error"].lower()

        resp = client.request(
            "DELETE",
            "/api/backends/test-backend",
            json=dict(_REAUTH_BODY),
            headers=headers,
        )

        assert resp.status_code == 200
        assert resp.json() == {
            "unregistered": True,
            "name": "test-backend",
            "status": "unregistered_pending_restart",
            "pending_apply": True,
            "restart_required": True,
        }
        assert mock_gateway.mcp_backend_registry.unregistered == ["test-backend"]

    def test_register_route_requires_challenge_and_handles_success(self, client, passwords_dir, mock_gateway, tmp_path, monkeypatch):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}

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
        # SEC-4: a registered stdio command must be an installed/allowlisted
        # launcher (absolute path in an allowlisted dir).
        launcher = tmp_path / "test-backend-launcher"
        launcher.write_text("#!/bin/sh\n", encoding="utf-8")
        monkeypatch.setenv("SIFT_ADDON_COMMAND_ALLOWLIST_DIRS", str(tmp_path))

        # Valid re-auth + config payload
        payload = {
            "name": "test-backend",
            "config": {
                "type": "stdio",
                "command": str(launcher),
                "manifest_path": str(manifest_path)
            },
            "password": GOOD_PASSWORD,
        }

        resp = client.post("/api/backends", json=payload, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["registered"] is True
        assert resp.json()["restart_required"] is True
        assert resp.json()["pending_apply"] is True

        assert mock_gateway.mcp_backend_registry.registered
        name, config, stored_manifest = mock_gateway.mcp_backend_registry.registered[-1]
        assert name == "test-backend"
        assert config["manifest_path"] == str(manifest_path)
        assert stored_manifest["health"] == "test_health"

    def test_register_rejects_invalid_name(self, client, passwords_dir, mock_gateway, tmp_path, monkeypatch):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        headers = {"origin": "http://testserver"}

        payload = {
            "name": "../test_backend",  # Path traversal / invalid characters
            "config": {"type": "stdio", "command": "true"},
            "password": GOOD_PASSWORD,
        }
        resp = client.post("/api/backends", json=payload, headers=headers)
        assert resp.status_code == 422
        assert any("name" in r["field"] for r in resp.json()["reasons"])

    def test_list_backends_includes_disabled_and_gated_and_redacts_secrets(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)

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
        mock_gateway.mcp_backend_registry = _Registry(
            [
                _RegistryRecord("active-backend", enabled=True, manifest=active_bk.manifest),
                _RegistryRecord("disabled-backend", enabled=False),
                _RegistryRecord("gated-backend", transport="http", enabled=True, manifest=gated_bk.manifest),
            ]
        )

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

        # Start service should fail if gated/disabled
        active_bk = MagicMock()
        active_bk.started = True
        active_bk.manifest = {
            "capabilities": {"provides": ["search"], "requires": ["unmet:req"]}
        }
        active_bk.stop = AsyncMock()
        mock_gateway.backends = {"test-gated": active_bk}
        mock_gateway.mcp_backend_registry = _Registry(
            [_RegistryRecord("test-gated", enabled=True, manifest=active_bk.manifest)]
        )

        # Try to start -> should be rejected because requirements are unmet
        start_resp = client.post(
            "/api/services/test-gated/start",
            json=dict(_REAUTH_BODY),
            headers=headers
        )
        assert start_resp.status_code == 400
        assert "unmet requirements" in start_resp.json()["error"]

        # Try to stop -> should be allowed even if requirements are unmet
        stop_resp = client.post(
            "/api/services/test-gated/stop",
            json=dict(_REAUTH_BODY),
            headers=headers
        )
        assert stop_resp.status_code == 200
        assert stop_resp.json()["status"] == "stopped"
        assert active_bk.stop.called


class TestBackendEnableDisable:
    """PT1/WI5 — operator enable/disable of a backend registry row (re-auth gated)."""

    def test_enable_disable_requires_auth_role_and_origin(self, client, passwords_dir):
        # Unauthenticated
        assert client.post("/api/backends/test/enabled", json={"enabled": False}).status_code == 401
        # Readonly role
        _setup_cookie(client, examiner="bob", role="readonly", passwords_dir=passwords_dir)
        assert client.post(
            "/api/backends/test/enabled",
            json={"enabled": False},
            headers={"origin": "http://testserver"},
        ).status_code == 403
        # Examiner but missing Origin
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        assert client.post("/api/backends/test/enabled", json={"enabled": False}).status_code == 400

    def test_disable_backend_flips_registry_row(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        mock_gateway.mcp_backend_registry = _Registry(
            [_RegistryRecord("opencti-mcp", enabled=True)]
        )
        headers = {"origin": "http://testserver"}
        resp = client.post(
            "/api/backends/opencti-mcp/enabled",
            json={"enabled": False, "password": GOOD_PASSWORD},
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["restart_required"] is True
        assert ("opencti-mcp", False) in mock_gateway.mcp_backend_registry.enabled_changes

    def test_enable_unknown_backend_404(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        mock_gateway.mcp_backend_registry = _Registry([])
        headers = {"origin": "http://testserver"}
        resp = client.post(
            "/api/backends/ghost/enabled",
            json={"enabled": True, "password": GOOD_PASSWORD},
            headers=headers,
        )
        assert resp.status_code == 404

    def test_enable_rejects_non_boolean(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="alice", role="examiner", passwords_dir=passwords_dir)
        mock_gateway.mcp_backend_registry = _Registry(
            [_RegistryRecord("opencti-mcp", enabled=True)]
        )
        headers = {"origin": "http://testserver"}
        resp = client.post(
            "/api/backends/opencti-mcp/enabled",
            json={"enabled": "yes", "password": GOOD_PASSWORD},
            headers=headers,
        )
        assert resp.status_code == 400


class TestHealthPanelRoute:
    """PT1/WI4 — portal health feed proxies the gateway /health probe."""

    def test_health_requires_auth(self, client):
        assert client.get("/api/health").status_code == 401

    def test_health_readonly_allowed(self, client, passwords_dir, mock_gateway):
        _setup_cookie(client, examiner="bob", role="readonly", passwords_dir=passwords_dir)
        mock_gateway.backends = {}
        mock_gateway._tool_map = {}
        resp = client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert "backends" in body
        assert "supabase" in body
        assert "evidence_root" in body
