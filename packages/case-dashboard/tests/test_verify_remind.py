"""Tests for Phase 16-verify-remind — HMAC verify state tracking and reminder.

Covers:
  _read_verify_state / _hmac_verify_needed helpers
  _build_evidence_chain_status includes hmac_verify_needed
  POST /api/evidence/chain/verify-hmac — auth, happy path, state write
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import (
    _hmac_verify_needed,
    _read_verify_state,
    _VERIFY_STATE_FILE,
    create_dashboard_v2_app,
)
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()


def _make_evidence_response(stored_hash_hex: str, nonce: str) -> str:
    return hmac_mod.new(bytes.fromhex(stored_hash_hex), nonce.encode(), "sha256").hexdigest()


def _setup_examiner(passwords_dir: Path, examiner: str, password: str) -> dict:
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": False}
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))
    return entry


def _session_cookie(examiner: str = "alice", role: str = "examiner") -> str:
    return generate_jwt(examiner, role, _SECRET, max_age=3600)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def case_dir(tmp_path):
    from agentir_core.evidence_chain import init_evidence_chain

    cd = tmp_path / "case-16vr"
    cd.mkdir()
    (cd / "CASE.yaml").write_text("case_id: case-16vr\ntitle: Test\nexaminer: alice\n")
    (cd / "evidence").mkdir()
    init_evidence_chain(cd)
    return cd


@pytest.fixture()
def app(passwords_dir, case_dir, tmp_path, monkeypatch):
    routes_mod._evidence_challenges.clear()
    routes_mod._challenges.clear()
    routes_mod._login_challenges.clear()
    monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(session_secret=_SECRET, session_max_age=28800)


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_client(client, passwords_dir):
    _setup_examiner(passwords_dir, "alice", "password123")
    client.cookies[COOKIE_NAME] = _session_cookie()
    return client


def _full_challenge(client: TestClient, passwords_dir: Path, examiner: str = "alice") -> tuple[str, str]:
    entry = json.loads((passwords_dir / f"{examiner}.json").read_text())
    resp = client.get("/api/evidence/chain/challenge")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    response = _make_evidence_response(entry["hash"], data["nonce"])
    return data["challenge_id"], response


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


class TestReadVerifyState:
    def test_missing_file_returns_empty(self, case_dir):
        assert _read_verify_state(case_dir) == {}

    def test_valid_file_returns_dict(self, case_dir):
        state = {"last_hmac_verified_at": "2026-05-25T10:00:00+00:00", "last_hmac_verified_by": "alice"}
        (case_dir / _VERIFY_STATE_FILE).write_text(json.dumps(state))
        assert _read_verify_state(case_dir) == state

    def test_corrupt_file_returns_empty(self, case_dir):
        (case_dir / _VERIFY_STATE_FILE).write_text("not-json{{")
        assert _read_verify_state(case_dir) == {}


class TestHmacVerifyNeeded:
    def test_empty_state_needs_verify(self):
        assert _hmac_verify_needed({}) is True

    def test_none_timestamp_needs_verify(self):
        assert _hmac_verify_needed({"last_hmac_verified_at": None}) is True

    def test_recent_verify_not_needed(self):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert _hmac_verify_needed({"last_hmac_verified_at": recent}) is False

    def test_old_verify_needs_remind(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        assert _hmac_verify_needed({"last_hmac_verified_at": old}) is True

    def test_exactly_24h_needs_remind(self):
        ts = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        assert _hmac_verify_needed({"last_hmac_verified_at": ts}) is True

    def test_invalid_timestamp_needs_verify(self):
        assert _hmac_verify_needed({"last_hmac_verified_at": "not-a-date"}) is True


# ---------------------------------------------------------------------------
# _build_evidence_chain_status includes verify fields
# ---------------------------------------------------------------------------


class TestChainStatusIncludesVerifyFields:
    def test_no_verify_state_hmac_needed_true(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "hmac_verify_needed" in data
        assert data["hmac_verify_needed"] is True
        assert data["hmac_last_verified_at"] is None
        assert data["hmac_last_verified_by"] is None

    def test_recent_verify_state_hmac_needed_false(self, authed_client, case_dir):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        (case_dir / _VERIFY_STATE_FILE).write_text(json.dumps({
            "last_hmac_verified_at": recent,
            "last_hmac_verified_by": "alice",
        }))
        resp = authed_client.get("/api/evidence/chain/status")
        data = resp.json()
        assert data["hmac_verify_needed"] is False
        assert data["hmac_last_verified_at"] == recent
        assert data["hmac_last_verified_by"] == "alice"


# ---------------------------------------------------------------------------
# POST /api/evidence/chain/verify-hmac
# ---------------------------------------------------------------------------


class TestVerifyHmacEndpoint:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 403

    def test_agent_role_returns_403(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        client.cookies[COOKIE_NAME] = _session_cookie(role="agent")
        resp = client.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 403

    def test_missing_fields_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/verify-hmac", json={})
        assert resp.status_code == 400
        assert "Missing" in resp.json()["error"]

    def test_wrong_password_returns_401(self, authed_client, passwords_dir):
        # Get challenge with correct examiner, respond with wrong HMAC
        resp = authed_client.get("/api/evidence/chain/challenge")
        data = resp.json()
        resp2 = authed_client.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": data["challenge_id"],
            "response": "deadbeef" * 8,
        })
        assert resp2.status_code == 401

    def test_happy_path_ok_result(self, authed_client, passwords_dir, case_dir):
        cid, response = _full_challenge(authed_client, passwords_dir)
        resp = authed_client.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid,
            "response": response,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "verified" in data
        assert "verified_at" in data
        assert data["verified_by"] == "alice"

    def test_writes_state_file_on_success(self, authed_client, passwords_dir, case_dir):
        cid, response = _full_challenge(authed_client, passwords_dir)
        authed_client.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid,
            "response": response,
        })
        state_path = case_dir / _VERIFY_STATE_FILE
        assert state_path.exists()
        state = json.loads(state_path.read_text())
        assert state["last_hmac_verified_by"] == "alice"
        assert "last_hmac_verified_at" in state

    def test_chain_status_hmac_needed_false_after_verify(self, authed_client, passwords_dir):
        cid, response = _full_challenge(authed_client, passwords_dir)
        authed_client.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid,
            "response": response,
        })
        resp = authed_client.get("/api/evidence/chain/status")
        data = resp.json()
        assert data["hmac_verify_needed"] is False

    def test_challenge_consumed_after_use(self, authed_client, passwords_dir):
        cid, response = _full_challenge(authed_client, passwords_dir)
        authed_client.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid,
            "response": response,
        })
        # Replay same challenge — must fail
        resp2 = authed_client.post("/api/evidence/chain/verify-hmac", json={
            "challenge_id": cid,
            "response": response,
        })
        assert resp2.status_code == 401

    def test_invalid_json_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/verify-hmac",
            content=b"not-json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400
