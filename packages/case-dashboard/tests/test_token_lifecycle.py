"""Phase 13f — Portal service-token lifecycle tests.

Drivers: SIFT-MCPS-PLAN.md Phase 13 / TASKS.md 13f.
"""

from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient

from case_dashboard.routes import create_dashboard_v2_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_api_keys(examiner_token: str, agent_token: str) -> dict:
    """Minimal gateway api_keys dict with one examiner and one agent token."""
    return {
        examiner_token: {
            "token_id": "examiner-test",
            "examiner": "alice",
            "agent_id": None,
            "role": "examiner",
            "label": "Test examiner",
            "created_by": "test",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": None,
            "revoked_at": None,
            "last_used_at": None,
            "last_used_ip": None,
        },
        agent_token: {
            "token_id": "hermes-default",
            "examiner": "hermes",
            "agent_id": "hermes-default",
            "role": "agent",
            "label": "Default Hermes token",
            "created_by": "installer",
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": None,
            "revoked_at": None,
            "last_used_at": None,
            "last_used_ip": None,
        },
    }


@pytest.fixture()
def tmp_gateway_config(tmp_path):
    """Write a minimal gateway.yaml to tmp_path and return its path."""
    examiner_token = "sift_gw_" + secrets.token_hex(24)
    agent_token = "sift_svc_" + secrets.token_hex(24)
    api_keys = _make_api_keys(examiner_token, agent_token)
    config = {"api_keys": api_keys}
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(yaml.dump(config), encoding="utf-8")
    return cfg_path, api_keys, examiner_token, agent_token


@pytest.fixture()
def app_and_tokens(tmp_gateway_config):
    """Return a TestClient wired with a real gateway.yaml and token fixtures."""
    cfg_path, api_keys, examiner_token, agent_token = tmp_gateway_config
    app = create_dashboard_v2_app(
        session_secret="test-secret-32-chars-xxxxxxxxxxxxxx",
        api_keys=api_keys,
        gateway_config_path=str(cfg_path),
    )
    client = TestClient(app, raise_server_exceptions=True)
    return client, examiner_token, agent_token, api_keys, cfg_path


# ---------------------------------------------------------------------------
# GET /api/tokens — list
# ---------------------------------------------------------------------------


class TestListTokens:
    def test_unauthenticated_returns_401(self, app_and_tokens):
        client, *_ = app_and_tokens
        resp = client.get("/api/tokens")
        assert resp.status_code == 401

    def test_returns_agent_tokens_only(self, app_and_tokens):
        client, examiner_token, agent_token, api_keys, _ = app_and_tokens
        resp = client.get("/api/tokens", headers={"Authorization": f"Bearer {examiner_token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        roles = {t["role"] for t in data["tokens"]}
        assert "examiner" not in roles  # Examiner gateway tokens must be hidden

    def test_never_returns_raw_token_value(self, app_and_tokens):
        client, examiner_token, agent_token, api_keys, _ = app_and_tokens
        resp = client.get("/api/tokens", headers={"Authorization": f"Bearer {examiner_token}"})
        body = resp.text
        assert agent_token not in body
        assert examiner_token not in body

    def test_agent_token_can_list(self, app_and_tokens):
        """Agents cannot use portal API at all (blocked by gateway AuthMiddleware R4).
        But if somehow they bypass that layer, the route itself doesn't block on role=agent
        for GET (read-only) — the gateway-level R4 is the gate, not this route.
        list_tokens only checks authentication, not examiner-specific role.
        """
        client, examiner_token, agent_token, api_keys, _ = app_and_tokens
        # In portal-app-only testing the gateway AuthMiddleware is not in the stack,
        # so the PortalSessionMiddleware sets role from the bearer token.
        # But the portal middleware only accepts examiner role for bearer tokens (Phase 12c).
        # Agent tokens therefore have examiner=None from PortalSessionMiddleware → 401.
        resp = client.get("/api/tokens", headers={"Authorization": f"Bearer {agent_token}"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/tokens — create
# ---------------------------------------------------------------------------


class TestCreateToken:
    def _create(self, client, examiner_token, **body_kwargs):
        payload = {"agent_id": "hermes-test", "label": "Test agent", **body_kwargs}
        return client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json=payload,
        )

    def test_create_returns_raw_token_once(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = self._create(client, examiner_token)
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["token"].startswith("sift_svc_")
        assert len(data["token"].removeprefix("sift_svc_")) == 48

    def test_create_persists_to_config(self, app_and_tokens):
        client, examiner_token, _, api_keys, cfg_path = app_and_tokens
        resp = self._create(client, examiner_token, agent_id="scanner-01", label="Scanner")
        assert resp.status_code == 201
        # Config file must be updated
        config = yaml.safe_load(cfg_path.read_text())
        new_token_raw = resp.json()["token"]
        assert new_token_raw in config["api_keys"]
        assert config["api_keys"][new_token_raw]["agent_id"] == "scanner-01"

    def test_create_updates_in_memory_api_keys(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        resp = self._create(client, examiner_token, agent_id="memory-test", label="Memory")
        assert resp.status_code == 201
        new_raw = resp.json()["token"]
        assert new_raw in api_keys  # shared dict reference updated in-place

    def test_create_requires_examiner_role(self, app_and_tokens):
        client, examiner_token, agent_token, api_keys, _ = app_and_tokens
        # Add a readonly token to api_keys
        ro_token = "sift_gw_" + secrets.token_hex(24)
        api_keys[ro_token] = {
            "token_id": "ro-test",
            "examiner": "reader",
            "agent_id": None,
            "role": "readonly",
            "revoked_at": None,
            "expires_at": None,
        }
        resp = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {ro_token}"},
            json={"agent_id": "x", "label": "x"},
        )
        assert resp.status_code == 403

    def test_create_duplicate_agent_id_rejected(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        # First create succeeds
        r1 = self._create(client, examiner_token, agent_id="dup-agent", label="First")
        assert r1.status_code == 201
        # Second create with same agent_id → 409
        r2 = self._create(client, examiner_token, agent_id="dup-agent", label="Second")
        assert r2.status_code == 409
        assert "already exists" in r2.json()["error"]

    def test_create_invalid_agent_id_rejected(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = self._create(client, examiner_token, agent_id="UPPERCASE-ID", label="bad")
        assert resp.status_code == 400

    def test_create_missing_label_rejected(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json={"agent_id": "x"},
        )
        assert resp.status_code == 400

    def test_create_invalid_role_rejected(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = self._create(client, examiner_token, role="superuser")
        assert resp.status_code == 400

    def test_create_bad_expires_at_rejected(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = self._create(
            client, examiner_token, agent_id="exp-test", label="exp", expires_at="not-a-date"
        )
        assert resp.status_code == 400

    def test_unauthenticated_returns_403(self, app_and_tokens):
        # create_token calls _require_examiner_role() first; with no auth the role
        # is None → 403 (not examiner), consistent with post_delta behavior.
        client, *_ = app_and_tokens
        resp = client.post("/api/tokens", json={"agent_id": "x", "label": "y"})
        assert resp.status_code == 403

    def test_create_no_config_path_returns_503(self, tmp_path):
        """When gateway_config_path is not set, create returns 503."""
        examiner_token = "sift_gw_" + secrets.token_hex(24)
        api_keys = {
            examiner_token: {
                "token_id": "e1",
                "examiner": "alice",
                "agent_id": None,
                "role": "examiner",
                "revoked_at": None,
                "expires_at": None,
            }
        }
        app = create_dashboard_v2_app(
            session_secret="test-secret-32-chars-xxxxxxxxxxxxxx",
            api_keys=api_keys,
            gateway_config_path=None,
        )
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json={"agent_id": "x", "label": "y"},
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# DELETE /api/tokens/{token_id} — revoke
# ---------------------------------------------------------------------------


class TestRevokeToken:
    def _create_svc_token(self, client, examiner_token, agent_id="revoke-test"):
        resp = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json={"agent_id": agent_id, "label": f"Token for {agent_id}"},
        )
        assert resp.status_code == 201
        return resp.json()

    def test_revoke_sets_revoked_at(self, app_and_tokens):
        client, examiner_token, _, api_keys, cfg_path = app_and_tokens
        created = self._create_svc_token(client, examiner_token)
        token_id = created["token_id"]

        resp = client.delete(
            f"/api/tokens/{token_id}",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["revoked_at"] is not None

        # In-memory dict updated
        raw = created["token"]
        assert api_keys[raw]["revoked_at"] is not None

        # Config file updated
        config = yaml.safe_load(cfg_path.read_text())
        assert config["api_keys"][raw]["revoked_at"] is not None

    def test_double_revoke_returns_409(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        created = self._create_svc_token(client, examiner_token, agent_id="dbl-revoke")
        token_id = created["token_id"]
        client.delete(
            f"/api/tokens/{token_id}",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        resp2 = client.delete(
            f"/api/tokens/{token_id}",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp2.status_code == 409

    def test_cannot_revoke_examiner_token(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        token_id = api_keys[examiner_token]["token_id"]
        resp = client.delete(
            f"/api/tokens/{token_id}",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp.status_code == 403

    def test_revoke_unknown_id_returns_404(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = client.delete(
            "/api/tokens/does-not-exist",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp.status_code == 404

    def test_revoke_requires_examiner_role(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        ro_token = "sift_gw_" + secrets.token_hex(24)
        api_keys[ro_token] = {
            "token_id": "ro-rev",
            "examiner": "reader",
            "agent_id": None,
            "role": "readonly",
            "revoked_at": None,
            "expires_at": None,
        }
        created = self._create_svc_token(client, examiner_token, agent_id="ro-agent")
        resp = client.delete(
            f"/api/tokens/{created['token_id']}",
            headers={"Authorization": f"Bearer {ro_token}"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/tokens/{token_id}/rotate
# ---------------------------------------------------------------------------


class TestRotateToken:
    def _create_svc_token(self, client, examiner_token, agent_id="rot-test"):
        resp = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json={"agent_id": agent_id, "label": f"Token for {agent_id}"},
        )
        assert resp.status_code == 201
        return resp.json()

    def test_rotate_returns_new_raw_token(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        created = self._create_svc_token(client, examiner_token)
        old_raw = created["token"]
        token_id = created["token_id"]

        resp = client.post(
            f"/api/tokens/{token_id}/rotate",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["token"].startswith("sift_svc_")
        assert data["token"] != old_raw
        assert data["revoked_token_id"] == token_id

    def test_rotate_revokes_old_token(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        created = self._create_svc_token(client, examiner_token, agent_id="rot-old")
        old_raw = created["token"]
        token_id = created["token_id"]

        client.post(
            f"/api/tokens/{token_id}/rotate",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert api_keys[old_raw]["revoked_at"] is not None

    def test_rotate_new_token_in_memory(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        created = self._create_svc_token(client, examiner_token, agent_id="rot-mem")
        resp = client.post(
            f"/api/tokens/{created['token_id']}/rotate",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        new_raw = resp.json()["token"]
        assert new_raw in api_keys
        assert api_keys[new_raw]["revoked_at"] is None

    def test_rotate_persists_to_config(self, app_and_tokens):
        client, examiner_token, _, _, cfg_path = app_and_tokens
        created = self._create_svc_token(client, examiner_token, agent_id="rot-disk")
        old_raw = created["token"]
        resp = client.post(
            f"/api/tokens/{created['token_id']}/rotate",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        new_raw = resp.json()["token"]
        config = yaml.safe_load(cfg_path.read_text())
        assert config["api_keys"][old_raw]["revoked_at"] is not None
        assert new_raw in config["api_keys"]
        assert config["api_keys"][new_raw]["revoked_at"] is None

    def test_rotate_revoked_token_returns_409(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        created = self._create_svc_token(client, examiner_token, agent_id="rot-409")
        token_id = created["token_id"]
        # Revoke first
        client.delete(
            f"/api/tokens/{token_id}",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        resp = client.post(
            f"/api/tokens/{token_id}/rotate",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp.status_code == 409

    def test_rotate_unknown_id_returns_404(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        resp = client.post(
            "/api/tokens/does-not-exist/rotate",
            headers={"Authorization": f"Bearer {examiner_token}"},
        )
        assert resp.status_code == 404

    def test_rotate_requires_examiner_role(self, app_and_tokens):
        client, examiner_token, _, api_keys, _ = app_and_tokens
        ro_token = "sift_gw_" + secrets.token_hex(24)
        api_keys[ro_token] = {
            "token_id": "ro-rot",
            "examiner": "reader",
            "agent_id": None,
            "role": "readonly",
            "revoked_at": None,
            "expires_at": None,
        }
        created = self._create_svc_token(client, examiner_token, agent_id="rot-rbac")
        resp = client.post(
            f"/api/tokens/{created['token_id']}/rotate",
            headers={"Authorization": f"Bearer {ro_token}"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Two different agent tokens produce separable metadata
# ---------------------------------------------------------------------------


class TestTokenSeparability:
    """Two service tokens must have distinct token_ids visible in list output."""

    def test_two_tokens_have_different_token_ids(self, app_and_tokens):
        client, examiner_token, *_ = app_and_tokens
        r1 = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json={"agent_id": "agent-a", "label": "Agent A"},
        )
        r2 = client.post(
            "/api/tokens",
            headers={"Authorization": f"Bearer {examiner_token}"},
            json={"agent_id": "agent-b", "label": "Agent B"},
        )
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["token_id"] != r2.json()["token_id"]
        assert r1.json()["token"] != r2.json()["token"]

        resp = client.get("/api/tokens", headers={"Authorization": f"Bearer {examiner_token}"})
        ids = [t["token_id"] for t in resp.json()["tokens"]]
        assert r1.json()["token_id"] in ids
        assert r2.json()["token_id"] in ids
