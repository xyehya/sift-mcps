"""Tests for Phase 16a — evidence chain intake portal endpoints.

Covers: GET /api/evidence/chain/status, POST /api/evidence/chain/rescan,
        GET /api/evidence/chain/challenge, POST /api/evidence/chain/seal,
        POST /api/evidence/chain/ignore.

Security invariants: HMAC verification, IP binding, single-use challenge,
                     must_reset_password block, examiner role required.
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
from case_dashboard.routes import create_dashboard_v2_app
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
    """Compute evidence HMAC response: HMAC-SHA256(stored_pbkdf2_hash, nonce)."""
    return hmac_mod.new(bytes.fromhex(stored_hash_hex), nonce.encode(), "sha256").hexdigest()


def _setup_examiner(
    passwords_dir: Path,
    examiner: str,
    password: str,
    *,
    must_reset: bool = False,
) -> dict:
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": must_reset}
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
    """Create a minimal case directory with init_evidence_chain applied."""
    from sift_core.evidence_chain import init_evidence_chain

    cd = tmp_path / "case-test-001"
    cd.mkdir()
    (cd / "CASE.yaml").write_text("case_id: case-test-001\ntitle: Test\nexaminer: alice\n")
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


# ---------------------------------------------------------------------------
# Helper: full HMAC challenge-response cycle
# ---------------------------------------------------------------------------


def _get_evidence_challenge(client: TestClient) -> tuple[str, str, str]:
    """Obtain evidence challenge. Returns (challenge_id, nonce, stored_hash_hex)."""
    resp = client.get("/api/evidence/chain/challenge")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["challenge_id"], data["nonce"], None  # stored_hash obtained separately


def _full_evidence_challenge(
    client: TestClient, passwords_dir: Path, examiner: str = "alice"
) -> tuple[str, str]:
    """Returns (challenge_id, response_hmac)."""
    entry = json.loads((passwords_dir / f"{examiner}.json").read_text())
    resp = client.get("/api/evidence/chain/challenge")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    response = _make_evidence_response(entry["hash"], data["nonce"])
    return data["challenge_id"], response


# ---------------------------------------------------------------------------
# status endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainStatus:
    def test_no_auth_returns_403(self, client):
        resp = client.get("/api/evidence/chain/status")
        assert resp.status_code == 403

    def test_agent_role_returns_403(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        client.cookies[COOKIE_NAME] = _session_cookie(role="agent")
        resp = client.get("/api/evidence/chain/status")
        assert resp.status_code == 403

    def test_unsealed_case_returns_unsealed(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "unsealed"
        assert data["manifest_version"] == 0

    def test_status_includes_write_block_field(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "write_protected" in data

    def test_unregistered_file_shows_in_status(self, authed_client, case_dir, passwords_dir):
        """After sealing an empty manifest then dropping a file, status shows unregistered."""
        from sift_core.evidence_chain import seal_manifest
        from sift_core.approval_auth import derive_ledger_key

        entry = json.loads((passwords_dir / "alice.json").read_text())
        key = derive_ledger_key(entry["hash"])
        seal_manifest(case_dir, [], "alice", key)

        (case_dir / "evidence" / "stray.txt").write_text("intruder")

        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "unregistered"
        assert any("stray.txt" in p for p in data["unregistered"])

    def test_no_active_case_returns_404(self, client, passwords_dir, monkeypatch):
        _setup_examiner(passwords_dir, "alice", "password123")
        client.cookies[COOKIE_NAME] = _session_cookie()
        monkeypatch.delenv("AGENTIR_CASE_DIR", raising=False)
        resp = client.get("/api/evidence/chain/status")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# rescan endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainRescan:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/rescan")
        assert resp.status_code == 403

    def test_rescan_returns_fresh_status(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/rescan")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "manifest_version" in data

    def test_rescan_invokes_on_chain_mutation(self, passwords_dir, case_dir, tmp_path, monkeypatch):
        """on_chain_mutation callback is called with case_dir_str."""
        called_with: list[str] = []
        monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        routes_mod._evidence_challenges.clear()
        _setup_examiner(passwords_dir, "alice", "password123")

        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            on_chain_mutation=lambda s: called_with.append(s),
        )
        c = TestClient(app, raise_server_exceptions=True)
        c.cookies[COOKIE_NAME] = _session_cookie()
        c.post("/api/evidence/chain/rescan")
        assert str(case_dir) in called_with


# ---------------------------------------------------------------------------
# challenge endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainChallenge:
    def test_no_auth_returns_403(self, client):
        resp = client.get("/api/evidence/chain/challenge")
        assert resp.status_code == 403

    def test_returns_challenge_fields(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/challenge")
        assert resp.status_code == 200
        data = resp.json()
        assert "challenge_id" in data
        assert "nonce" in data
        assert "salt" in data
        assert data["iterations"] == 600000

    def test_challenge_stored_in_evidence_challenges(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/challenge")
        cid = resp.json()["challenge_id"]
        assert cid in routes_mod._evidence_challenges

    def test_must_reset_password_blocked(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        client.cookies[COOKIE_NAME] = _session_cookie()
        resp = client.get("/api/evidence/chain/challenge")
        assert resp.status_code == 403
        assert "reset" in resp.json()["error"].lower()

    def test_no_password_configured_returns_403(self, client, passwords_dir):
        # passwords_dir exists but no alice.json
        passwords_dir.mkdir(parents=True, exist_ok=True)
        client.cookies[COOKIE_NAME] = _session_cookie()
        resp = client.get("/api/evidence/chain/challenge")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# seal endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainSeal:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/seal", json={})
        assert resp.status_code == 403

    def test_missing_challenge_fields_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/seal", json={"file_specs": []})
        assert resp.status_code == 400

    def test_invalid_challenge_id_returns_401(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": "bad", "response": "bad", "file_specs": []},
        )
        assert resp.status_code == 401

    def test_seal_empty_manifest(self, authed_client, passwords_dir):
        """Sealing an empty file_specs creates manifest version 1."""
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": challenge_id, "response": response, "file_specs": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["sealed"] is True
        assert data["manifest_version"] == 1
        assert data["files_added"] == []

    def test_seal_registers_evidence_file(self, authed_client, passwords_dir, case_dir):
        """Sealing with a real file creates manifest version 1 with the file registered."""
        evidence_file = case_dir / "evidence" / "disk.raw"
        evidence_file.write_bytes(b"disk image content")

        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={
                "challenge_id": challenge_id,
                "response": response,
                "file_specs": [
                    {"path": "evidence/disk.raw", "source": "USB-001", "description": "Host disk image"}
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["manifest_version"] == 1
        assert "evidence/disk.raw" in data["files_added"]

    def test_seal_wrong_password_returns_401(self, authed_client, passwords_dir, case_dir):
        resp = authed_client.get("/api/evidence/chain/challenge")
        data = resp.json()
        resp2 = authed_client.post(
            "/api/evidence/chain/seal",
            json={
                "challenge_id": data["challenge_id"],
                "response": "deadbeef" * 8,
                "file_specs": [],
            },
        )
        assert resp2.status_code == 401

    def test_challenge_is_single_use(self, authed_client, passwords_dir):
        """Re-submitting the same challenge_id after success must fail."""
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp1 = authed_client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": challenge_id, "response": response, "file_specs": []},
        )
        assert resp1.status_code == 200
        # Second use of same challenge
        challenge_id2, response2 = challenge_id, response
        resp2 = authed_client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": challenge_id2, "response": response2, "file_specs": []},
        )
        assert resp2.status_code == 401

    def test_seal_nonexistent_file_returns_400(self, authed_client, passwords_dir):
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={
                "challenge_id": challenge_id,
                "response": response,
                "file_specs": [{"path": "evidence/ghost.raw"}],
            },
        )
        assert resp.status_code == 400

    def test_seal_path_traversal_returns_400(self, authed_client, passwords_dir):
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={
                "challenge_id": challenge_id,
                "response": response,
                "file_specs": [{"path": "../../../etc/passwd"}],
            },
        )
        assert resp.status_code == 400

    def test_seal_invokes_on_chain_mutation(self, passwords_dir, case_dir, tmp_path, monkeypatch):
        called_with: list[str] = []
        monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        routes_mod._evidence_challenges.clear()
        entry = _setup_examiner(passwords_dir, "alice", "password123")

        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            on_chain_mutation=lambda s: called_with.append(s),
        )
        c = TestClient(app, raise_server_exceptions=True)
        c.cookies[COOKIE_NAME] = _session_cookie()

        resp = c.get("/api/evidence/chain/challenge")
        data = resp.json()
        response = _make_evidence_response(entry["hash"], data["nonce"])
        c.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": data["challenge_id"], "response": response, "file_specs": []},
        )
        assert str(case_dir) in called_with

    def test_must_reset_password_blocked(self, client, passwords_dir, case_dir, monkeypatch):
        monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
        _setup_examiner(passwords_dir, "alice", "password123", must_reset=True)
        client.cookies[COOKIE_NAME] = _session_cookie()
        resp = client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": "x", "response": "y", "file_specs": []},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# ignore endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainIgnore:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/ignore", json={})
        assert resp.status_code == 403

    def test_missing_fields_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/ignore", json={"challenge_id": "x"})
        assert resp.status_code == 400

    def test_ignore_unregistered_file(self, authed_client, passwords_dir, case_dir):
        """Ignoring an unregistered file creates a new manifest version with FILE_IGNORED."""
        from sift_core.evidence_chain import load_ledger, load_manifest

        stray = case_dir / "evidence" / "stray.txt"
        stray.write_text("unintended")

        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "challenge_id": challenge_id,
                "response": response,
                "path": "evidence/stray.txt",
                "reason": "Accidentally copied, not evidence",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ignored"] is True
        assert data["manifest_version"] == 1

        ledger = load_ledger(case_dir)
        assert len(ledger) == 1
        assert ledger[0]["event"] == "FILE_IGNORED"
        assert ledger[0]["path"] == "evidence/stray.txt"

    def test_ignore_wrong_password_returns_401(self, authed_client, passwords_dir):
        resp = authed_client.get("/api/evidence/chain/challenge")
        data = resp.json()
        resp2 = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "challenge_id": data["challenge_id"],
                "response": "00" * 32,
                "path": "evidence/stray.txt",
                "reason": "not needed",
            },
        )
        assert resp2.status_code == 401

    def test_ignore_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"challenge_id": "x", "response": "y", "reason": "because"},
        )
        assert resp.status_code == 400

    def test_ignore_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"challenge_id": "x", "response": "y", "path": "evidence/x.txt"},
        )
        assert resp.status_code == 400

    def test_ignore_invalid_challenge_returns_401(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "challenge_id": "notreal",
                "response": "deadbeef" * 8,
                "path": "evidence/x.txt",
                "reason": "test",
            },
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# retire endpoint (Phase 16-retire)
# ---------------------------------------------------------------------------


class TestEvidenceChainRetire:
    def _seal_evidence_file(self, client, passwords_dir, case_dir, filename="evidence/sample.E01"):
        """Helper: write evidence file and seal it via the portal."""
        from sift_core.evidence_chain import seal_manifest
        import hashlib, json

        (case_dir / filename).write_bytes(b"DISK_IMAGE_CONTENT")
        entry = json.loads((passwords_dir / "alice.json").read_text())
        resp = client.get("/api/evidence/chain/challenge")
        data = resp.json()
        response = hmac_mod.new(
            bytes.fromhex(entry["hash"]), data["nonce"].encode(), "sha256"
        ).hexdigest()
        r = client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": data["challenge_id"], "response": response,
                  "file_specs": [{"path": filename}]},
        )
        assert r.status_code == 200, r.text
        return filename

    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/retire", json={})
        assert resp.status_code == 403

    def test_agent_role_returns_403(self, client, passwords_dir):
        _setup_examiner(passwords_dir, "alice", "password123")
        client.cookies[COOKIE_NAME] = _session_cookie(role="agent")
        resp = client.post("/api/evidence/chain/retire", json={})
        assert resp.status_code == 403

    def test_missing_challenge_fields_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/retire", json={"path": "evidence/x", "reason": "r"})
        assert resp.status_code == 400

    def test_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": "x", "response": "y", "reason": "r"},
        )
        assert resp.status_code == 400

    def test_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": "x", "response": "y", "path": "evidence/x"},
        )
        assert resp.status_code == 400

    def test_invalid_challenge_returns_401(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": "notreal", "response": "deadbeef" * 8,
                  "path": "evidence/x.bin", "reason": "test"},
        )
        assert resp.status_code == 401

    def test_retire_active_file_succeeds(self, authed_client, passwords_dir, case_dir):
        filename = self._seal_evidence_file(authed_client, passwords_dir, case_dir)
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": challenge_id, "response": response,
                  "path": filename, "reason": "corrupt acquisition"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["retired"] is True
        assert data["path"] == filename
        assert data["manifest_version"] == 2

    def test_retire_deletes_file_from_disk(self, authed_client, passwords_dir, case_dir):
        filename = self._seal_evidence_file(authed_client, passwords_dir, case_dir)
        assert (case_dir / filename).exists()
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": challenge_id, "response": response,
                  "path": filename, "reason": "test"},
        )
        assert not (case_dir / filename).exists()

    def test_retire_writes_file_retired_ledger_event(self, authed_client, passwords_dir, case_dir):
        from sift_core.evidence_chain import load_ledger
        filename = self._seal_evidence_file(authed_client, passwords_dir, case_dir)
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": challenge_id, "response": response,
                  "path": filename, "reason": "bad acquisition"},
        )
        ledger = load_ledger(case_dir)
        assert ledger[-1]["event"] == "FILE_RETIRED"
        assert ledger[-1]["path"] == filename
        assert ledger[-1]["reason"] == "bad acquisition"

    def test_retire_chain_status_ok_after_retire(self, authed_client, passwords_dir, case_dir):
        from sift_core.evidence_chain import chain_status
        filename = self._seal_evidence_file(authed_client, passwords_dir, case_dir)
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": challenge_id, "response": response,
                  "path": filename, "reason": "corrupt"},
        )
        result = chain_status(case_dir)
        assert result["status"] == "ok"

    def test_retire_unregistered_path_returns_400(self, authed_client, passwords_dir):
        challenge_id, response = _full_evidence_challenge(authed_client, passwords_dir)
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": challenge_id, "response": response,
                  "path": "evidence/ghost.bin", "reason": "oops"},
        )
        assert resp.status_code == 400
        assert "not registered" in resp.json()["error"]

    def test_retire_wrong_password_returns_401(self, authed_client, passwords_dir):
        resp = authed_client.get("/api/evidence/chain/challenge")
        data = resp.json()
        resp2 = authed_client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": data["challenge_id"], "response": "00" * 32,
                  "path": "evidence/x.bin", "reason": "test"},
        )
        assert resp2.status_code == 401

    def test_retire_invokes_on_chain_mutation(self, passwords_dir, case_dir, tmp_path, monkeypatch):
        from sift_core.evidence_chain import seal_manifest
        import json as json_mod

        routes_mod._evidence_challenges.clear()
        routes_mod._challenges.clear()
        routes_mod._login_challenges.clear()
        monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)

        called_with = []
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            on_chain_mutation=lambda x: called_with.append(x),
        )
        client = TestClient(app, raise_server_exceptions=True)
        _setup_examiner(passwords_dir, "alice", "password123")
        client.cookies[COOKIE_NAME] = _session_cookie()

        # Seal via direct call (bypass portal to keep test fast)
        ev_file = case_dir / "evidence" / "sample.bin"
        ev_file.write_bytes(b"DATA")
        entry = json_mod.loads((passwords_dir / "alice.json").read_text())
        resp = client.get("/api/evidence/chain/challenge")
        data = resp.json()
        response = hmac_mod.new(
            bytes.fromhex(entry["hash"]), data["nonce"].encode(), "sha256"
        ).hexdigest()
        r = client.post(
            "/api/evidence/chain/seal",
            json={"challenge_id": data["challenge_id"], "response": response,
                  "file_specs": [{"path": "evidence/sample.bin"}]},
        )
        assert r.status_code == 200
        called_with.clear()

        resp = client.get("/api/evidence/chain/challenge")
        data = resp.json()
        response = hmac_mod.new(
            bytes.fromhex(entry["hash"]), data["nonce"].encode(), "sha256"
        ).hexdigest()
        r = client.post(
            "/api/evidence/chain/retire",
            json={"challenge_id": data["challenge_id"], "response": response,
                  "path": "evidence/sample.bin", "reason": "test"},
        )
        assert r.status_code == 200
        assert len(called_with) == 1
