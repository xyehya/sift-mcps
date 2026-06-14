"""PR02 portal service-token lifecycle tests.

B-MVP-023: migrated from the legacy examiner Bearer-token fallback to the
Supabase-envelope harness. The legacy auth plane (sift_session cookie + examiner
Bearer fallback) has been removed; the portal authenticates only via the
Supabase session envelope. Examiner identity for these token-lifecycle calls now
comes from an operator principal resolved off the session-envelope cookie.
"""

from __future__ import annotations

from datetime import datetime, timezone
import secrets

import pytest
import yaml
from starlette.testclient import TestClient

from case_dashboard.routes import create_dashboard_v2_app
from sift_gateway.token_gen import token_fingerprint
from sift_gateway.token_registry import RegistryToken

from _supabase_reauth_harness import (
    ReauthFakeSupabaseAuth,
    operator_principal,
    set_operator_session,
)

# 32-byte hex secret so the session envelope HMAC (bytes.fromhex) is valid.
_SECRET = secrets.token_hex(32)


def _make_api_keys(agent_token: str) -> dict:
    return {
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


class FakeTokenRegistry:
    def __init__(self) -> None:
        self.tokens: dict[str, dict] = {}
        self.raw_seen: list[str] = []

    def list_tokens(self):
        return [
            {
                "token_id": token_id,
                "token_fingerprint": info["token_fingerprint"],
                "agent_id": info["agent_id"],
                "label": info["label"],
                "role": info["role"],
                "created_by": info["created_by"],
                "created_at": info["created_at"],
                "expires_at": info["expires_at"],
                "revoked_at": info["revoked_at"],
                "last_used_at": None,
                "case_id": info.get("case_id"),
                "status": "revoked" if info["revoked_at"] else "active",
            }
            for token_id, info in sorted(self.tokens.items())
        ]

    def create_token(
        self, *, raw_token, agent_id, label, role, created_by, expires_at, case_id=None
    ):
        if any(
            info["agent_id"] == agent_id and info["revoked_at"] is None
            for info in self.tokens.values()
        ):
            raise ValueError("duplicate active agent_id")
        token_id = f"00000000-0000-0000-0000-{len(self.tokens) + 1:012d}"
        exp = (
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expires_at
            else datetime(2026, 9, 1, tzinfo=timezone.utc)
        )
        info = {
            "token_fingerprint": token_fingerprint(raw_token),
            "agent_id": agent_id,
            "label": label,
            "role": role,
            "created_by": created_by,
            "created_at": "2026-06-07T00:00:00+00:00",
            "expires_at": exp.isoformat(),
            "revoked_at": None,
            "case_id": case_id,
        }
        self.raw_seen.append(raw_token)
        self.tokens[token_id] = info
        return RegistryToken(
            id=token_id,
            token_fingerprint=info["token_fingerprint"],
            role=role,
            principal=agent_id,
            principal_type="agent",
            agent_id=agent_id,
            service_identity_id=None,
            created_by=created_by,
            case_id=case_id,
            label=label,
            expires_at=exp,
            scopes=frozenset({"mcp:*"}),
        )

    def revoke_token(self, token_id, *, revoked_by):
        info = self.tokens.get(token_id)
        if info is None or info["revoked_at"] is not None:
            return None
        info["revoked_at"] = "2026-06-07T00:00:00+00:00"
        return info["revoked_at"]

    def rotate_token(self, token_id, *, new_raw_token, rotated_by):
        info = self.tokens.get(token_id)
        if info is None or info["revoked_at"] is not None:
            return None
        info["revoked_at"] = "2026-06-07T00:00:00+00:00"
        return self.create_token(
            raw_token=new_raw_token,
            agent_id=info["agent_id"],
            label=info["label"],
            role=info["role"],
            created_by=rotated_by,
            expires_at=info["expires_at"],
            case_id=info.get("case_id"),
        )

    def reactivate_token(self, token_id):
        info = self.tokens.get(token_id)
        if info is None or info["revoked_at"] is None:
            return False
        info["revoked_at"] = None
        return True


def _build_app(api_keys, cfg_path, *, token_registry=None, active_case_service=None,
               system_role="owner"):
    """Build a v2 portal app wired with an operator Supabase principal."""
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        api_keys=api_keys,
        gateway_config_path=str(cfg_path),
        token_registry=token_registry,
        active_case_service=active_case_service,
        supabase_auth=ReauthFakeSupabaseAuth(
            principal=operator_principal(system_role=system_role)
        ),
    )


@pytest.fixture()
def tmp_gateway_config(tmp_path):
    agent_token = "sift_svc_" + secrets.token_hex(24)
    api_keys = _make_api_keys(agent_token)
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(yaml.dump({"api_keys": api_keys}), encoding="utf-8")
    return cfg_path, api_keys, agent_token


@pytest.fixture()
def app_and_tokens(tmp_gateway_config):
    cfg_path, api_keys, agent_token = tmp_gateway_config
    registry = FakeTokenRegistry()
    app = _build_app(api_keys, cfg_path, token_registry=registry)
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    return client, agent_token, api_keys, cfg_path, registry


def _create(client, **body_kwargs):
    payload = {"agent_id": "hermes-test", "label": "Test agent", **body_kwargs}
    return client.post("/api/tokens", json=payload)


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


def test_legacy_list_never_returns_raw_token_value(tmp_gateway_config):
    cfg_path, api_keys, agent_token = tmp_gateway_config
    app = _build_app(api_keys, cfg_path, token_registry=None)
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    resp = client.get("/api/tokens")
    assert resp.status_code == 200
    body = resp.text
    assert agent_token not in body


def test_unauthenticated_cannot_use_portal_token_list(tmp_gateway_config):
    # With the legacy Bearer plane removed, a request with no Supabase operator
    # session envelope cannot list tokens (handler enforces 401).
    cfg_path, api_keys, _ = tmp_gateway_config
    app = _build_app(api_keys, cfg_path, token_registry=None)
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/api/tokens")
    assert resp.status_code == 401


def test_create_returns_raw_token_once_and_writes_hash_only_registry(app_and_tokens):
    client, _, api_keys, cfg_path, registry = app_and_tokens
    resp = _create(client, agent_id="scanner-01", label="Scanner")
    assert resp.status_code == 201
    data = resp.json()
    raw = data["token"]
    assert raw.startswith("sift_svc_")
    assert len(raw.removeprefix("sift_svc_")) == 48
    assert data["token_fingerprint"] == token_fingerprint(raw)

    config = yaml.safe_load(cfg_path.read_text())
    assert raw not in config["api_keys"]
    assert raw not in api_keys
    assert raw not in registry.tokens
    stored = registry.tokens[data["token_id"]]
    assert stored["agent_id"] == "scanner-01"
    assert stored["token_fingerprint"] == token_fingerprint(raw)


def test_create_agent_token_defaults_to_active_case(tmp_gateway_config):
    cfg_path, api_keys, _ = tmp_gateway_config
    registry = FakeTokenRegistry()
    active_case_id = "11111111-1111-1111-1111-111111111111"
    app = _build_app(
        api_keys, cfg_path,
        token_registry=registry,
        active_case_service=_ActiveCases(active_case_id),
    )
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)

    created = _create(client, agent_id="case-bound").json()
    assert created["case_id"] == active_case_id
    assert registry.tokens[created["token_id"]]["case_id"] == active_case_id

    rotated = client.post(
        f"/api/tokens/{created['token_id']}/rotate",
    ).json()
    assert rotated["case_id"] == active_case_id
    assert registry.tokens[rotated["token_id"]]["case_id"] == active_case_id


def test_create_requires_db_registry(tmp_gateway_config):
    cfg_path, api_keys, _ = tmp_gateway_config
    app = _build_app(api_keys, cfg_path, token_registry=None)
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    resp = _create(client)
    assert resp.status_code == 503


def test_create_validates_role_agent_id_label_and_expiry(app_and_tokens):
    client, *_ = app_and_tokens
    assert _create(client, agent_id="UPPER", label="bad").status_code == 400
    assert _create(client, label="").status_code == 400
    assert _create(client, role="superuser").status_code == 400
    assert _create(client, expires_at="not-a-date").status_code == 400


def test_create_duplicate_agent_id_rejected(app_and_tokens):
    client, *_ = app_and_tokens
    assert _create(client, agent_id="dup-agent", label="First").status_code == 201
    resp = _create(client, agent_id="dup-agent", label="Second")
    assert resp.status_code == 409


def test_create_requires_examiner_role(tmp_gateway_config):
    # A readonly operator principal must be denied (403) on token creation.
    cfg_path, api_keys, _ = tmp_gateway_config
    registry = FakeTokenRegistry()
    app = _build_app(api_keys, cfg_path, token_registry=registry, system_role="readonly")
    client = TestClient(app, raise_server_exceptions=True)
    set_operator_session(client, _SECRET)
    resp = client.post("/api/tokens", json={"agent_id": "x", "label": "x"})
    assert resp.status_code == 403


def test_revoke_sets_registry_revoked_at_without_raw_config_write(app_and_tokens):
    client, _, api_keys, cfg_path, registry = app_and_tokens
    created = _create(client, agent_id="revoke-test").json()
    resp = client.delete(f"/api/tokens/{created['token_id']}")
    assert resp.status_code == 200
    raw = created["token"]
    assert registry.tokens[created["token_id"]]["revoked_at"] is not None
    assert raw not in api_keys
    assert raw not in yaml.safe_load(cfg_path.read_text())["api_keys"]


def test_revoke_unknown_or_already_revoked_returns_404(app_and_tokens):
    client, *_ = app_and_tokens
    created = _create(client, agent_id="dbl-revoke").json()
    url = f"/api/tokens/{created['token_id']}"
    assert client.delete(url).status_code == 200
    assert client.delete(url).status_code == 404
    resp = client.delete("/api/tokens/does-not-exist")
    assert resp.status_code == 404


def test_rotate_returns_new_raw_once_and_keeps_config_hash_only(app_and_tokens):
    client, _, api_keys, cfg_path, registry = app_and_tokens
    created = _create(client, agent_id="rot-test").json()
    old_raw = created["token"]
    resp = client.post(f"/api/tokens/{created['token_id']}/rotate")
    assert resp.status_code == 201
    data = resp.json()
    new_raw = data["token"]
    assert new_raw.startswith("sift_svc_")
    assert new_raw != old_raw
    assert data["revoked_token_id"] == created["token_id"]
    assert data["token_fingerprint"] == token_fingerprint(new_raw)
    assert registry.tokens[created["token_id"]]["revoked_at"] is not None
    assert old_raw not in api_keys
    assert new_raw not in api_keys
    config = yaml.safe_load(cfg_path.read_text())
    assert old_raw not in config["api_keys"]
    assert new_raw not in config["api_keys"]


def test_rotate_revoked_or_unknown_returns_404(app_and_tokens):
    client, *_ = app_and_tokens
    created = _create(client, agent_id="rot-409").json()
    client.delete(f"/api/tokens/{created['token_id']}")
    assert client.post(
        f"/api/tokens/{created['token_id']}/rotate",
    ).status_code == 404
    assert client.post(
        "/api/tokens/does-not-exist/rotate",
    ).status_code == 404


def test_reactivate_revoked_token(app_and_tokens):
    client, _, _, _, registry = app_and_tokens
    created = _create(client, agent_id="reactivate-test").json()
    token_id = created["token_id"]
    client.delete(f"/api/tokens/{token_id}")
    assert registry.tokens[token_id]["revoked_at"] is not None
    resp = client.post(f"/api/tokens/{token_id}/reactivate")
    assert resp.status_code == 200
    assert registry.tokens[token_id]["revoked_at"] is None


def test_two_tokens_have_different_token_ids(app_and_tokens):
    client, *_ = app_and_tokens
    r1 = _create(client, agent_id="agent-a", label="Agent A")
    r2 = _create(client, agent_id="agent-b", label="Agent B")
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["token_id"] != r2.json()["token_id"]
    assert r1.json()["token"] != r2.json()["token"]

    resp = client.get("/api/tokens")
    ids = [t["token_id"] for t in resp.json()["tokens"]]
    assert r1.json()["token_id"] in ids
    assert r2.json()["token_id"] in ids
