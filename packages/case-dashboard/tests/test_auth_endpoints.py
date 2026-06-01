"""Tests for Phase 12d — portal auth endpoints.

Drivers: SIFT-MCPS-PLAN.md §Phase 12 / TASKS.md §12d.
Covers: setup-required, setup, challenge, login, reset-password, logout, me.
Security invariants tested: R1, R2, R3, R6, R8.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import secrets
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import case_dashboard.routes as routes_mod
from case_dashboard.routes import (
    _EXAMINER_RE,
    create_dashboard_v2_app,
)
from case_dashboard.session_jwt import COOKIE_NAME, generate_jwt, verify_jwt

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_password(password: str, salt_hex: str) -> str:
    """Compute PBKDF2 hash matching server-side storage."""
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()


def _derive_auth_key(stored_hash_hex: str) -> bytes:
    """Derive auth key exactly as the server does (R8)."""
    return hmac_mod.new(
        bytes.fromhex(stored_hash_hex), b"sift-auth-v1", hashlib.sha256
    ).digest()


def _make_login_response(stored_hash_hex: str, nonce: str) -> str:
    """Compute the HMAC login response as the browser would."""
    auth_key = _derive_auth_key(stored_hash_hex)
    return hmac_mod.new(auth_key, nonce.encode(), "sha256").hexdigest()


def _setup_examiner(passwords_dir: Path, examiner: str, password: str, *, must_reset: bool = False):
    """Write a password entry directly (bypassing the API for test setup)."""
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": must_reset}
    path = passwords_dir / f"{examiner}.json"
    path.write_text(json.dumps(entry))
    return entry


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    """Redirect _PASSWORDS_DIR to a temp directory for test isolation."""
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch):
    routes_mod._login_challenges.clear()
    routes_mod._challenges.clear()
    # Redirect Path.home() so lockout files land in tmp, not ~/.sift
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(session_secret=_SECRET, session_max_age=28800)


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# setup-required
# ---------------------------------------------------------------------------


class TestSetupRequired:
    def test_required_when_no_passwords(self, client):
        resp = client.get("/api/auth/setup-required")
        assert resp.status_code == 200
        assert resp.json() == {"required": True}

    def test_not_required_when_password_exists(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        resp = client.get("/api/auth/setup-required")
        assert resp.status_code == 200
        assert resp.json() == {"required": False}

    def test_no_auth_required_for_this_endpoint(self, client):
        resp = client.get("/api/auth/setup-required")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------


class TestSetup:
    def test_creates_examiner_account(self, client, passwords_dir):
        resp = client.post(
            "/api/auth/setup",
            json={"examiner": "alice", "password": "securepass1"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True, "examiner": "alice"}
        assert (passwords_dir / "alice.json").exists()

    def test_returns_409_when_already_set_up(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        resp = client.post(
            "/api/auth/setup",
            json={"examiner": "bob", "password": "securepass1"},
        )
        assert resp.status_code == 409

    def test_rejects_invalid_examiner_name(self, client):
        resp = client.post(
            "/api/auth/setup",
            json={"examiner": "Alice Jones!", "password": "securepass1"},
        )
        assert resp.status_code == 400

    def test_rejects_short_password(self, client):
        resp = client.post(
            "/api/auth/setup",
            json={"examiner": "alice", "password": "short"},
        )
        assert resp.status_code == 400

    def test_password_stored_hashed_not_plaintext(self, client, passwords_dir):
        resp = client.post(
            "/api/auth/setup",
            json={"examiner": "alice", "password": "securepass1"},
        )
        assert resp.status_code == 200
        entry = json.loads((passwords_dir / "alice.json").read_text())
        assert "hash" in entry
        assert "securepass1" not in json.dumps(entry)
        assert entry.get("must_reset_password") is False


# ---------------------------------------------------------------------------
# challenge
# ---------------------------------------------------------------------------


class TestChallenge:
    def test_returns_challenge_for_known_examiner(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        resp = client.get("/api/auth/challenge?examiner=alice")
        assert resp.status_code == 200
        data = resp.json()
        assert "challenge_id" in data
        assert "nonce" in data
        assert "salt" in data
        assert data["iterations"] == 600000

    def test_r3_returns_challenge_for_unknown_examiner(self, client):
        """R3: Unknown examiner gets a fake challenge — no 404 or 400."""
        resp = client.get("/api/auth/challenge?examiner=nobody")
        assert resp.status_code == 200
        data = resp.json()
        assert "challenge_id" in data
        assert "nonce" in data
        assert "salt" in data

    def test_r3_fake_challenge_stored_in_login_challenges(self, client):
        resp = client.get("/api/auth/challenge?examiner=nobody")
        assert resp.status_code == 200
        cid = resp.json()["challenge_id"]
        assert cid in routes_mod._login_challenges
        assert routes_mod._login_challenges[cid]["_fake"] is True

    def test_real_challenge_not_marked_fake(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        resp = client.get("/api/auth/challenge?examiner=alice")
        cid = resp.json()["challenge_id"]
        assert routes_mod._login_challenges[cid].get("_fake") is False

    def test_rejects_invalid_examiner_name(self, client):
        resp = client.get("/api/auth/challenge?examiner=INVALID!!!")
        assert resp.status_code == 400

    def test_r6_per_examiner_cap(self, client, passwords_dir):
        """R6: >5 in-flight challenges for same examiner evicts oldest, not error."""
        _setup_examiner(passwords_dir, "alice", "password123")
        cids = []
        for _ in range(6):
            r = client.get("/api/auth/challenge?examiner=alice")
            cids.append(r.json()["challenge_id"])
        # After 6 requests, at most 5 should be in _login_challenges for alice
        alice_count = sum(
            1 for v in routes_mod._login_challenges.values()
            if v["examiner"] == "alice"
        )
        assert alice_count <= routes_mod._MAX_LOGIN_CHALLENGES_PER_EXAMINER

    def test_r6_total_pool_cap(self, client):
        """R6: Total pool capped at 200; oldest evicted on overflow."""
        for i in range(220):
            examiner = f"u{i:04d}"
            if not _EXAMINER_RE.match(examiner):
                continue
            # Inject directly to avoid hitting the per-examiner limit
            routes_mod._login_challenges[secrets.token_hex(16)] = {
                "nonce": secrets.token_hex(32),
                "examiner": examiner,
                "created_at": time.time() - i,
                "bound_ip": "127.0.0.1",
                "_fake": False,
            }
        # Trigger a new request to exercise the cap logic
        client.get("/api/auth/challenge?examiner=alice")
        assert len(routes_mod._login_challenges) <= routes_mod._MAX_LOGIN_CHALLENGES + 1


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


class TestLogin:
    def _do_login(self, client, passwords_dir, examiner="alice", password="password123"):
        entry = _setup_examiner(passwords_dir, examiner, password)
        challenge_resp = client.get(f"/api/auth/challenge?examiner={examiner}")
        data = challenge_resp.json()
        stored_hash = entry["hash"]
        response_hex = _make_login_response(stored_hash, data["nonce"])
        return client.post(
            "/api/auth/login",
            json={
                "challenge_id": data["challenge_id"],
                "examiner": examiner,
                "response": response_hex,
            },
        )

    def test_valid_login_returns_200_and_sets_cookie(self, client, passwords_dir):
        resp = self._do_login(client, passwords_dir)
        assert resp.status_code == 200
        data = resp.json()
        assert data["examiner"] == "alice"
        assert data["role"] == "examiner"
        assert COOKIE_NAME in resp.cookies

    def test_valid_login_cookie_is_valid_jwt(self, client, passwords_dir):
        resp = self._do_login(client, passwords_dir)
        cookie = resp.cookies[COOKIE_NAME]
        payload = verify_jwt(cookie, _SECRET)
        assert payload is not None
        assert payload["sub"] == "alice"

    def test_wrong_password_returns_401(self, client, passwords_dir):
        entry = _setup_examiner(passwords_dir, "alice", "correct-password")
        challenge_resp = client.get("/api/auth/challenge?examiner=alice")
        data = challenge_resp.json()
        wrong_hash = hashlib.pbkdf2_hmac(
            "sha256", b"wrong-password", bytes.fromhex(entry["salt"]), _PBKDF2_ITERS
        ).hex()
        bad_response = _make_login_response(wrong_hash, data["nonce"])
        resp = client.post(
            "/api/auth/login",
            json={
                "challenge_id": data["challenge_id"],
                "examiner": "alice",
                "response": bad_response,
            },
        )
        assert resp.status_code == 401

    def test_r3_fake_challenge_always_fails(self, client):
        """R3: Login with a fake (unknown examiner) challenge always fails."""
        challenge_resp = client.get("/api/auth/challenge?examiner=nobody")
        data = challenge_resp.json()
        resp = client.post(
            "/api/auth/login",
            json={
                "challenge_id": data["challenge_id"],
                "examiner": "nobody",
                "response": "a" * 64,
            },
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "Invalid credentials"

    def test_r3_fake_challenge_same_http_status_as_real_mismatch(
        self, client, passwords_dir
    ):
        """R3: Fake challenge failure must match real challenge failure — same HTTP 401."""
        # Real examiner, wrong password
        entry = _setup_examiner(passwords_dir, "alice", "correct")
        cr = client.get("/api/auth/challenge?examiner=alice")
        data = cr.json()
        wrong_response = _make_login_response("00" * 32, data["nonce"])
        real_fail = client.post(
            "/api/auth/login",
            json={
                "challenge_id": data["challenge_id"],
                "examiner": "alice",
                "response": wrong_response,
            },
        )

        # Fake examiner
        cr2 = client.get("/api/auth/challenge?examiner=nobody")
        data2 = cr2.json()
        fake_fail = client.post(
            "/api/auth/login",
            json={
                "challenge_id": data2["challenge_id"],
                "examiner": "nobody",
                "response": "b" * 64,
            },
        )

        assert real_fail.status_code == fake_fail.status_code == 401
        assert real_fail.json()["error"] == fake_fail.json()["error"] == "Invalid credentials"

    def test_must_reset_flag_included_in_response(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        challenge_resp = client.get("/api/auth/challenge?examiner=alice")
        data = challenge_resp.json()
        # Get real hash for proper response
        entry = json.loads((passwords_dir / "alice.json").read_text())
        response_hex = _make_login_response(entry["hash"], data["nonce"])
        resp = client.post(
            "/api/auth/login",
            json={
                "challenge_id": data["challenge_id"],
                "examiner": "alice",
                "response": response_hex,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["must_reset"] is True

    def test_missing_fields_returns_400(self, client):
        resp = client.post("/api/auth/login", json={"examiner": "alice"})
        assert resp.status_code == 400

    def test_expired_challenge_returns_401(self, client, passwords_dir):
        entry = _setup_examiner(passwords_dir, "alice", "password123")
        cr = client.get("/api/auth/challenge?examiner=alice")
        data = cr.json()

        # Artificially expire the challenge
        cid = data["challenge_id"]
        routes_mod._login_challenges[cid]["created_at"] = time.time() - 9999

        response_hex = _make_login_response(entry["hash"], data["nonce"])
        resp = client.post(
            "/api/auth/login",
            json={
                "challenge_id": cid,
                "examiner": "alice",
                "response": response_hex,
            },
        )
        assert resp.status_code == 401

    def test_challenge_single_use(self, client, passwords_dir):
        entry = _setup_examiner(passwords_dir, "alice", "password123")
        cr = client.get("/api/auth/challenge?examiner=alice")
        data = cr.json()
        response_hex = _make_login_response(entry["hash"], data["nonce"])
        payload = {"challenge_id": data["challenge_id"], "examiner": "alice", "response": response_hex}
        resp1 = client.post("/api/auth/login", json=payload)
        assert resp1.status_code == 200
        # Same challenge on second request must fail (already consumed)
        resp2 = client.post("/api/auth/login", json=payload)
        assert resp2.status_code == 401


# ---------------------------------------------------------------------------
# R2: Login lockout does not affect commit lockout and vice versa
# ---------------------------------------------------------------------------


class TestR2LockoutNamespaceSeparation:
    def test_login_failures_do_not_pollute_commit_lockout(self, client, passwords_dir):
        """R2: Exhausting login lockout must not affect commit lockout counter."""
        _setup_examiner(passwords_dir, "alice", "correct")

        # Record several login failures using the login-namespace key
        for _ in range(5):
            routes_mod._record_login_failure("alice")

        # Commit lockout check should return None (not locked)
        assert routes_mod._check_commit_lockout("alice") is None

    def test_commit_failures_do_not_pollute_login_lockout(self, client, passwords_dir):
        """R2: Exhausting commit lockout must not affect login lockout counter."""
        _setup_examiner(passwords_dir, "alice", "correct")

        # Record several commit failures using the plain examiner key
        for _ in range(3):
            routes_mod._record_commit_failure("alice")

        # Login lockout check should return None (not locked)
        assert routes_mod._check_login_lockout("alice") is None

    def test_login_failure_count_uses_namespaced_key(self, client):
        """R2: Login failure count reads login:{examiner}, not examiner directly."""
        routes_mod._record_login_failure("alice")
        routes_mod._record_login_failure("alice")

        # login_failure_count should return 2
        assert routes_mod._login_failure_count("alice") == 2
        # commit_failure_count for "alice" (plain key) should return 0
        assert routes_mod._commit_failure_count("alice") == 0


# ---------------------------------------------------------------------------
# R1: must_reset blocks writes
# ---------------------------------------------------------------------------


@pytest.fixture()
def active_case_dir(tmp_path, monkeypatch):
    """Create a minimal active case dir and set SIFT_CASE_DIR for the test."""
    case_dir = tmp_path / "cases" / "test-case"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: test-case\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    return case_dir


class TestR1MustResetBlocks:
    def test_must_reset_examiner_cannot_post_delta(
        self, client, passwords_dir, active_case_dir
    ):
        """R1: must_reset_password=true prevents delta writes."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        token = generate_jwt("alice", "examiner", _SECRET)
        resp = client.post(
            "/api/delta",
            json={"items": []},
            cookies={COOKIE_NAME: token},
        )
        assert resp.status_code == 403

    def test_must_reset_examiner_cannot_delete_delta(
        self, client, passwords_dir, active_case_dir
    ):
        """R1: must_reset_password=true prevents delta item deletion."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        token = generate_jwt("alice", "examiner", _SECRET)
        resp = client.delete(
            "/api/delta/someid",
            cookies={COOKIE_NAME: token},
        )
        assert resp.status_code == 403

    def test_non_reset_examiner_can_access_write_routes(
        self, client, passwords_dir, active_case_dir
    ):
        """R1: Normal examiner (no must_reset) is allowed through auth check."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=False)
        token = generate_jwt("alice", "examiner", _SECRET)
        # Case dir exists but no delta file → 404, but that means auth passed (not 401 or 403)
        resp = client.post(
            "/api/delta",
            json={"items": []},
            cookies={COOKIE_NAME: token},
        )
        assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_returns_200(self, client):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200

    def test_logout_clears_cookie(self, client):
        resp = client.post("/api/auth/logout")
        # Starlette sets Max-Age=0 to clear cookie
        cookie_header = resp.headers.get("set-cookie", "")
        assert COOKIE_NAME in cookie_header
        assert "max-age=0" in cookie_header.lower()


# ---------------------------------------------------------------------------
# me
# ---------------------------------------------------------------------------


class TestMe:
    def test_me_returns_401_without_session(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_returns_examiner_info_with_valid_cookie(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        token = generate_jwt("alice", "examiner", _SECRET)
        resp = client.get("/api/auth/me", cookies={COOKIE_NAME: token})
        assert resp.status_code == 200
        data = resp.json()
        assert data["examiner"] == "alice"
        assert data["role"] == "examiner"
        assert data["expires_at"] is not None

    def test_r1_me_reads_must_reset_from_disk(self, client, passwords_dir):
        """R1: /api/auth/me re-reads must_reset_password from disk, not just JWT."""
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        token = generate_jwt("alice", "examiner", _SECRET)
        resp = client.get("/api/auth/me", cookies={COOKIE_NAME: token})
        assert resp.status_code == 200
        assert resp.json()["must_reset"] is True

    def test_me_no_session_no_bearer(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401
        assert "error" in resp.json()
