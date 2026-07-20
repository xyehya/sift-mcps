"""Tests for the evidence chain intake portal endpoints (DB-authority).

Covers: GET /api/evidence/chain/status,
        GET /api/evidence/chain/challenge, POST /api/evidence/chain/seal,
        POST /api/evidence/chain/ignore, POST /api/evidence/chain/retire.

The file-backed ("V0") evidence-chain-state authority has been removed: the
evidence cycle is DB-authority only (app.evidence_gate_status + app.evidence_objects,
surfaced via the injected evidence service). These tests wire a fake DB evidence
service the same way the Gateway injects the real one in production, plus the
graceful-empty behavior for a fresh install with no DB service / no active case.

Security invariants (CL3a / B-MVP-017): operator password re-verified against
                     Supabase (fail closed), must_reset_password block, examiner
                     role required, re-auth audit event id required for every
                     mutation. The legacy file-HMAC challenge/single-use/IP-bind
                     mechanics are gone (verifier moved to the control plane).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import case_dashboard.routes as routes_mod
import pytest
from _supabase_reauth_harness import (
    GOOD_PASSWORD,
    ReauthFakeSupabaseAuth,
    set_operator_session,
)
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_PBKDF2_ITERS = 600_000
_CASE_ID = "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------------------
# Fake DB-authority services (stand-ins for the Gateway-side adapters)
# ---------------------------------------------------------------------------


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "intake-test"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeEvidenceDB:
    """Minimal DB evidence adapter for the intake endpoints."""

    def __init__(
        self,
        *,
        seal_status="unsealed",
        gate_state="BLOCKED_PENDING",
        objects=None,
        storage_status=None,
    ):
        self.seal_status = seal_status
        self.gate_state = gate_state
        self._objects = objects if objects is not None else []
        self.storage_status = storage_status if storage_status is not None else {}
        self.reauth_calls: list = []
        self.seal_calls: list = []
        self.resume_calls: list = []
        self.ignore_calls: list = []
        self.retire_calls: list = []
        self.delete_calls: list = []
        self.reacquire_calls: list = []
        self.unseal_calls: list = []
        self.recovery_begin_calls: list = []
        self.recovery_complete_calls: list = []
        self.storage_profile_calls: list = []

    def record_reauth_event(self, *, case_id, actor, examiner, action, binding=None):
        self.reauth_calls.append((case_id, examiner, action, binding))
        return "audit-evt-001"

    def change_storage_profile(
        self, *, case_id, profile, reason, idempotency_key,
        reauth_audit_event_id, actor,
    ):
        assert reauth_audit_event_id
        self.storage_profile_calls.append(
            (case_id, profile, reason, idempotency_key, reauth_audit_event_id, actor)
        )
        return {
            "storage_profile": profile,
            "storage_availability": "FULL_VERIFY_REQUIRED",
            "storage_remediation": "FULL_VERIFY",
            "generation": 2,
        }

    def gate_status(self, case_id):
        return {
            "seal_status": self.seal_status,
            "gate_state": self.gate_state,
            "manifest_version": 0 if self.seal_status == "unsealed" else 1,
            "active_count": sum(1 for o in self._objects if o.get("status") == "sealed"),
            "issues": [],
            "head_hash": "" if self.seal_status == "unsealed" else "sha256:abc",
            "last_verified_at": None,
            **self.storage_status,
        }

    def list_evidence(self, case_id):
        return list(self._objects)

    def seal(self, *, case_id, file_specs, reason, idempotency_key, reauth_audit_event_id, actor, examiner, storage_profile="LOCAL_IMMUTABLE"):
        assert reauth_audit_event_id, "seal must receive a re-auth audit event id"
        assert storage_profile in {"LOCAL_IMMUTABLE", "EXTERNALLY_READ_ONLY"}
        self.seal_calls.append((case_id, file_specs, reauth_audit_event_id))
        self.seal_status = "sealed"
        return {"seal_status": "sealed", "manifest_version": 1}

    def resume_seal(self, *, case_id, operation_id, actor, examiner, resume_reauth_audit_event_id):
        self.resume_calls.append((case_id, operation_id, examiner, resume_reauth_audit_event_id))
        return {"seal_status": "sealed", "manifest_version": 2, "operation_id": operation_id}

    def ignore(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner, idempotency_key):
        assert reauth_audit_event_id
        assert idempotency_key
        self.ignore_calls.append((display_path, reason, reauth_audit_event_id))

    def retire(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner, idempotency_key):
        assert reauth_audit_event_id
        assert idempotency_key
        self.retire_calls.append((display_path, reason, reauth_audit_event_id))

    def reacquire(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id, "reacquire must receive a re-auth audit event id"
        self.reacquire_calls.append((display_path, reason, reauth_audit_event_id))
        self.seal_status = "sealed"
        return {
            "manifest_version": 2,
            "seal_status": "sealed",
            "display_path": display_path,
            "sha256": "sha256:" + "c" * 64,
            "bytes": 4096,
        }

    def unseal(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner):
        assert reauth_audit_event_id, "unseal must receive a re-auth audit event id"
        self.unseal_calls.append((display_path, reason, reauth_audit_event_id))
        self.seal_status = "unsealed"
        return {
            "evidence_id": "ev-unsealed",
            "display_path": display_path,
            "status": "registered",
            "seal_status": "unsealed",
            "immutable": False,
        }

    def recovery_object_id(self, *, case_id, display_path):
        return "22222222-2222-4222-8222-222222222222"

    def begin_recovery(self, **kwargs):
        self.recovery_begin_calls.append(kwargs)
        return {
            "operation_id": "33333333-3333-4333-8333-333333333333",
            "operation_phase": "FILESYSTEM_APPLYING",
            "action": str(kwargs["action"]),
            "ready_for_replacement": True,
        }

    def recovery_operation_action(self, *, case_id, operation_id):
        return "REPLACE_REACQUIRE"

    def complete_recovery(self, **kwargs):
        self.recovery_complete_calls.append(kwargs)
        return {
            "reacquired": True, "manifest_version": 2,
            "evidence_version_id": "44444444-4444-4444-8444-444444444444",
            "seal_status": "sealed",
        }

    def evidence_history(self, case_id, evidence_object_id):
        return {
            "evidence_object_id": evidence_object_id,
            "versions": [{"evidence_version_id": "v1", "manifest_version": 1}],
            "events": [{"event_id": "e1", "seq": 1, "event_type": "MANIFEST_SEALED"}],
        }

    def delete_object(self, *, case_id, display_path, reason, reauth_audit_event_id, actor, examiner, idempotency_key):
        # Endpoint-level stub. Sealed-evidence protection is enforced in the real
        # EvidenceAuthorityService.delete_object (service-layer test).
        assert reauth_audit_event_id, "delete must receive a re-auth audit event id"
        assert idempotency_key
        self.delete_calls.append((display_path, reason, reauth_audit_event_id))
        return {
            "evidence_id": "ev-del",
            "display_path": display_path,
            "status": "ignored",
            "file_removed": True,
            "sha256": "sha256:deadbeef",
            "bytes": 123,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_examiner(
    passwords_dir: Path,
    examiner: str,
    password: str,
    *,
    must_reset: bool = False,
) -> dict:
    """Write the local must_reset flag file the R1 gate still reads.

    CL3a no longer verifies the password via this file (Supabase does), but the
    ``must_reset_password`` gate is still read from ``_PASSWORDS_DIR``, so a few
    tests still seed an entry to exercise that block. The hash is filler.
    """
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": must_reset}
    (passwords_dir / f"{examiner}.json").write_text(json.dumps(entry))
    return entry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    monkeypatch.setattr(routes_mod, "_PASSWORDS_DIR", d)
    return d


@pytest.fixture()
def evidence_db():
    return FakeEvidenceDB()


@pytest.fixture()
def fake_auth():
    return ReauthFakeSupabaseAuth()


@pytest.fixture()
def app(passwords_dir, tmp_path, monkeypatch, evidence_db, fake_auth):
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    return create_dashboard_v2_app(
        session_secret=_SECRET,
        session_max_age=28800,
        active_case_service=FakeActiveCases(),
        evidence_service=evidence_db,
        supabase_auth=fake_auth,
    )


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_client(client):
    set_operator_session(client, _SECRET)
    return client


def _fresh_install_client(passwords_dir, tmp_path, monkeypatch):
    """Client with NO DB evidence service and no active case (fresh install)."""
    monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
    app = create_dashboard_v2_app(
        session_secret=_SECRET, session_max_age=28800,
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app, raise_server_exceptions=True)
    set_operator_session(c, _SECRET)
    return c


# ---------------------------------------------------------------------------
# status endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainStatus:
    def test_no_auth_returns_403(self, client):
        resp = client.get("/api/evidence/chain/status")
        assert resp.status_code == 403

    def test_agent_principal_returns_403(self, passwords_dir, tmp_path, monkeypatch):
        """An agent principal carries no examiner identity -> operator route denies."""
        from _supabase_reauth_harness import operator_principal, set_operator_session
        agent_principal = dict(
            operator_principal(), principal_type="agent",
            auth_user_id="auth-user-agent-1",
        )
        fake = ReauthFakeSupabaseAuth(principal=agent_principal)
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=FakeActiveCases(), evidence_service=FakeEvidenceDB(),
            supabase_auth=fake,
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code in (401, 403)

    def test_unsealed_case_returns_unsealed(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authority"] == "db"
        assert data["status"] == "unsealed"
        assert data["manifest_version"] == 0

    def test_status_includes_write_block_field(self, authed_client):
        resp = authed_client.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "write_protected" in data

    def test_status_preserves_precise_unavailable_gate_state(
        self, passwords_dir, tmp_path, monkeypatch
    ):
        ev = FakeEvidenceDB(
            seal_status="violated", gate_state="BLOCKED_UNAVAILABLE"
        )
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            active_case_service=FakeActiveCases(),
            evidence_service=ev,
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        client = TestClient(app, raise_server_exceptions=True)
        set_operator_session(client, _SECRET)

        response = client.get("/api/evidence/chain/status")

        assert response.status_code == 200
        assert response.json()["gate_state"] == "BLOCKED_UNAVAILABLE"

    def test_status_surfaces_only_public_storage_authority_fields(
        self, passwords_dir, tmp_path, monkeypatch
    ):
        source_identity = "a" * 64
        mount_instance = "b" * 64
        ev = FakeEvidenceDB(
            seal_status="sealed",
            gate_state="OPEN",
            storage_status={
                "storage_profile": "LOCAL_IMMUTABLE",
                "storage_availability": "AVAILABLE",
                "storage_remediation": "NONE",
                "storage_source_identity": source_identity,
                "storage_verified_mount_instance": mount_instance,
                "storage_read_only": True,
                "storage_generation": 4,
                "storage_verified_generation": 4,
                "storage_last_full_verified_at": "2026-07-14T12:34:56+00:00",
                "storage_observed_mount_path": "/private/mnt/evidence",
                "storage_raw_mount_options": "ro,secret=must-not-surface",
            },
        )
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            active_case_service=FakeActiveCases(),
            evidence_service=ev,
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        client = TestClient(app, raise_server_exceptions=True)
        set_operator_session(client, _SECRET)

        response = client.get("/api/evidence/chain/status")

        assert response.status_code == 200
        body = response.json()
        assert {
            key: body[key]
            for key in (
                "storage_profile",
                "storage_availability",
                "storage_remediation",
                "storage_source_identity",
                "storage_verified_mount_instance",
                "storage_read_only",
                "storage_generation",
                "storage_verified_generation",
                "storage_last_full_verified_at",
            )
        } == {
            "storage_profile": "LOCAL_IMMUTABLE",
            "storage_availability": "AVAILABLE",
            "storage_remediation": "NONE",
            "storage_source_identity": source_identity,
            "storage_verified_mount_instance": mount_instance,
            "storage_read_only": True,
            "storage_generation": 4,
            "storage_verified_generation": 4,
            "storage_last_full_verified_at": "2026-07-14T12:34:56+00:00",
        }
        assert "storage_observed_mount_path" not in body
        assert "storage_raw_mount_options" not in body

    def test_status_uses_safe_storage_defaults_when_authority_fields_are_absent(
        self, authed_client
    ):
        body = authed_client.get("/api/evidence/chain/status").json()

        assert body["storage_profile"] == "UNKNOWN"
        assert body["storage_availability"] == "UNAVAILABLE"
        assert body["storage_remediation"] == "FULL_VERIFY"
        assert body["storage_source_identity"] is None
        assert body["storage_verified_mount_instance"] is None
        assert body["storage_read_only"] is None
        assert body["storage_generation"] is None
        assert body["storage_verified_generation"] is None
        assert body["storage_last_full_verified_at"] is None

    def test_status_rejects_malformed_storage_authority_fields(
        self, passwords_dir, tmp_path, monkeypatch
    ):
        ev = FakeEvidenceDB(
            storage_status={
                "storage_profile": "/mnt/evidence",
                "storage_availability": ["AVAILABLE"],
                "storage_remediation": {"value": "NONE"},
                "storage_source_identity": "/private/source",
                "storage_verified_mount_instance": "A" * 64,
                "storage_read_only": 1,
                "storage_generation": True,
                "storage_verified_generation": 0,
                "storage_last_full_verified_at": "/private/verified-at",
            }
        )
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET,
            session_max_age=28800,
            active_case_service=FakeActiveCases(),
            evidence_service=ev,
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        client = TestClient(app, raise_server_exceptions=True)
        set_operator_session(client, _SECRET)

        body = client.get("/api/evidence/chain/status").json()

        assert body["storage_profile"] == "UNKNOWN"
        assert body["storage_availability"] == "UNAVAILABLE"
        assert body["storage_remediation"] == "FULL_VERIFY"
        assert body["storage_source_identity"] is None
        assert body["storage_verified_mount_instance"] is None
        assert body["storage_read_only"] is None
        assert body["storage_generation"] is None
        assert body["storage_verified_generation"] is None
        assert body["storage_last_full_verified_at"] is None
        assert "/private/" not in json.dumps(body)

    def test_unregistered_file_shows_in_status(self, passwords_dir, tmp_path, monkeypatch):
        """A detected-but-unsealed object surfaces as unregistered."""
        ev = FakeEvidenceDB(
            objects=[{"display_path": "evidence/stray.txt", "status": "detected",
                      "seal_status": "unsealed"}],
        )
        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            active_case_service=FakeActiveCases(), evidence_service=ev,
            supabase_auth=ReauthFakeSupabaseAuth(),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)

        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert any("stray.txt" in p for p in data["unregistered"])
        assert data["requires_examiner_action"] is True

    def test_fresh_install_returns_graceful_empty(self, passwords_dir, tmp_path, monkeypatch):
        """No DB service + no active case: 200 with a no_case payload, never 404/500."""
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.get("/api/evidence/chain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authority"] == "db"
        assert data["status"] == "no_case"
        assert data["manifest_version"] == 0
        assert data["unregistered"] == []
        assert data["requires_examiner_action"] is False


# ---------------------------------------------------------------------------
# challenge endpoint
# ---------------------------------------------------------------------------


# CL3b (B-MVP-017): the file-HMAC evidence-chain challenge GET
# (/api/evidence/chain/challenge) was deleted with the dead re-auth plane. The
# seal/ignore/retire/etc. endpoints now POST {password} and re-verify against
# Supabase directly (see TestEvidenceChainSeal), so there is no challenge GET to
# test. The forced-reset block is covered at the seal endpoint below.


# ---------------------------------------------------------------------------
# seal endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainSeal:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/seal", json={})
        assert resp.status_code == 403

    def test_missing_password_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/seal", json={"file_specs": []})
        assert resp.status_code == 400

    @pytest.mark.parametrize(
        "body",
        [
            {"password": GOOD_PASSWORD, "idempotency_key": "key", "file_specs": [{"path": "evidence/disk.raw"}]},
            {"password": GOOD_PASSWORD, "reason": "intake", "file_specs": [{"path": "evidence/disk.raw"}]},
            {"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "key", "file_specs": [{"path": "../disk.raw"}]},
            {"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "key", "file_specs": [{"path": "evidence/disk.raw", "unknown": True}]},
            {"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "key", "file_specs": [{"path": "evidence/disk.raw"}], "unknown": True},
        ],
    )
    def test_seal_rejects_unbound_or_unknown_input(self, authed_client, evidence_db, body):
        resp = authed_client.post("/api/evidence/chain/seal", json=body)
        assert resp.status_code == 400
        assert not evidence_db.seal_calls

    def test_seal_empty_manifest_is_rejected(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "seal-empty", "file_specs": []},
        )
        assert resp.status_code == 400
        assert not evidence_db.seal_calls

    def test_seal_registers_evidence_file(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={
                "password": GOOD_PASSWORD,
                "reason": "Initial intake",
                "idempotency_key": "seal-001",
                "file_specs": [
                    {"path": "evidence/disk.raw", "source": "USB-001", "description": "Host disk image"}
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["manifest_version"] == 1
        assert "evidence/disk.raw" in data["files_added"]

    def test_resume_uses_server_operation_id_after_fresh_reauth(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal/resume",
            json={"password": GOOD_PASSWORD, "operation_id": "33333333-3333-3333-3333-333333333333"},
        )
        assert resp.status_code == 200
        assert resp.json()["manifest_version"] == 2
        assert evidence_db.resume_calls == [
            (_CASE_ID, "33333333-3333-3333-3333-333333333333", "alice", "audit-evt-001")
        ]
        assert evidence_db.reauth_calls[-1][2] == "evidence_seal_resume"
        assert evidence_db.reauth_calls[-1][3] == {
            "operation_id": "33333333-3333-3333-3333-333333333333"
        }

    def test_resume_rejects_malformed_operation_id_before_service(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal/resume",
            json={"password": GOOD_PASSWORD, "operation_id": "not-a-uuid"},
        )
        assert resp.status_code == 400
        assert not evidence_db.resume_calls

    @pytest.mark.parametrize("phase", ["REQUESTED", "LEDGER_COMMITTED"])
    def test_resume_nonresumable_phase_rejects_before_filesystem_orchestration(
        self, phase, authed_client, evidence_db, monkeypatch
    ):
        class NotResumableError(Exception):
            reason = "custody_operation_not_resumable"
            http_status = 404

        def reject_resume(**_kwargs):
            raise NotResumableError(phase)

        monkeypatch.setattr(evidence_db, "resume_seal", reject_resume)
        resp = authed_client.post(
            "/api/evidence/chain/seal/resume",
            json={
                "password": GOOD_PASSWORD,
                "operation_id": "33333333-3333-3333-3333-333333333333",
            },
        )

        assert resp.status_code == 404
        assert resp.json() == {"error": "custody_operation_not_resumable"}
        assert not evidence_db.resume_calls
        assert not evidence_db.seal_calls

    def test_seal_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"password": "wrong-password", "reason": "intake", "idempotency_key": "seal-002", "file_specs": [{"path": "evidence/disk.raw"}]},
        )
        assert resp.status_code == 401
        assert not evidence_db.seal_calls

    def test_seal_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        """CL3a: control plane unreachable -> 503, no file-HMAC fallback, no seal."""
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "seal-003", "file_specs": [{"path": "evidence/disk.raw"}]},
        )
        assert resp.status_code == 503
        assert not evidence_db.seal_calls

    def test_seal_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        """No DB service: seal degrades to the no-case response, never a file write."""
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "seal-004", "file_specs": [{"path": "evidence/disk.raw"}]},
        )
        assert resp.status_code == 404
        assert "active case" in resp.json()["error"].lower()

    def test_must_reset_password_blocked(self, passwords_dir, tmp_path, monkeypatch):
        # CL3b: the forced-reset gate now derives from the Supabase 'invited'
        # status carried by the session principal, not a file flag. An invited
        # operator is blocked from sealing until they reset.
        from _supabase_reauth_harness import operator_principal

        monkeypatch.setattr("case_dashboard.routes.Path.home", lambda: tmp_path)
        app = create_dashboard_v2_app(
            session_secret=_SECRET, session_max_age=28800,
            supabase_auth=ReauthFakeSupabaseAuth(
                principal=operator_principal(status="invited"),
            ),
        )
        c = TestClient(app, raise_server_exceptions=True)
        set_operator_session(c, _SECRET)
        resp = c.post(
            "/api/evidence/chain/seal",
            json={"password": GOOD_PASSWORD, "reason": "intake", "idempotency_key": "seal-006", "file_specs": [{"path": "evidence/disk.raw"}]},
        )
        assert resp.status_code == 403


class TestEvidenceChainIgnore:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/ignore", json={})
        assert resp.status_code == 403

    def test_missing_fields_returns_400(self, authed_client):
        resp = authed_client.post("/api/evidence/chain/ignore", json={})
        assert resp.status_code == 400

    def test_ignore_unregistered_file(self, authed_client, evidence_db):
        """Ignoring an unregistered file reaches the DB ignore RPC with a re-auth id."""
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "password": GOOD_PASSWORD,
                "path": "evidence/stray.txt",
                "reason": "Accidentally copied, not evidence",
                "idempotency_key": "ignore-stray-1",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ignored"] is True
        assert data["authority"] == "db"
        assert evidence_db.ignore_calls
        assert evidence_db.ignore_calls[0] == (
            "evidence/stray.txt", "Accidentally copied, not evidence", "audit-evt-001",
        )

    def test_ignore_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={
                "password": "wrong-password",
                "path": "evidence/stray.txt",
                "reason": "not needed",
                "idempotency_key": "ignore-stray-2",
            },
        )
        assert resp.status_code == 401
        assert not evidence_db.ignore_calls

    def test_ignore_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "reason": "because"},
        )
        assert resp.status_code == 400

    def test_ignore_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.txt"},
        )
        assert resp.status_code == 400

    def test_ignore_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.txt", "reason": "test", "idempotency_key": "ignore-down"},
        )
        assert resp.status_code == 503
        assert not evidence_db.ignore_calls

    def test_ignore_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/ignore",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.txt", "reason": "r", "idempotency_key": "ignore-fresh"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# retire endpoint
# ---------------------------------------------------------------------------


class TestEvidenceChainRetire:
    def test_no_auth_returns_403(self, client):
        resp = client.post("/api/evidence/chain/retire", json={})
        assert resp.status_code == 403

    def test_no_session_returns_401_or_403(self, client):
        # No session at all -> examiner/role unset -> denied (role check first).
        resp = client.post("/api/evidence/chain/retire", json={})
        assert resp.status_code in (401, 403)

    def test_missing_password_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire", json={"path": "evidence/x", "reason": "r"}
        )
        assert resp.status_code == 400

    def test_missing_path_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "reason": "r"},
        )
        assert resp.status_code == 400

    def test_missing_reason_returns_400(self, authed_client):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x"},
        )
        assert resp.status_code == 400

    def test_control_plane_down_fails_closed(self, authed_client, evidence_db, fake_auth):
        fake_auth.control_plane_down = True
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.bin", "reason": "test", "idempotency_key": "retire-down"},
        )
        assert resp.status_code == 503
        assert not evidence_db.retire_calls

    def test_retire_active_file_succeeds(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD,
                  "path": "evidence/sample.E01", "reason": "corrupt acquisition", "idempotency_key": "retire-active"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["retired"] is True
        assert data["authority"] == "db"
        assert data["path"] == "evidence/sample.E01"
        assert evidence_db.retire_calls
        assert evidence_db.retire_calls[0] == (
            "evidence/sample.E01", "corrupt acquisition", "audit-evt-001",
        )

    def test_retire_wrong_password_returns_401(self, authed_client, evidence_db):
        resp = authed_client.post(
            "/api/evidence/chain/retire",
            json={"password": "wrong-password",
                  "path": "evidence/x.bin", "reason": "test", "idempotency_key": "retire-wrong"},
        )
        assert resp.status_code == 401
        assert not evidence_db.retire_calls

    def test_retire_fresh_install_graceful_no_case(self, passwords_dir, tmp_path, monkeypatch):
        c = _fresh_install_client(passwords_dir, tmp_path, monkeypatch)
        resp = c.post(
            "/api/evidence/chain/retire",
            json={"password": GOOD_PASSWORD, "path": "evidence/x.bin", "reason": "r", "idempotency_key": "retire-fresh"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# durable Replace/Reacquire and exact Restore endpoints
# ---------------------------------------------------------------------------


class TestEvidenceRecovery:
    def test_removed_custody_recovery_routes_are_absent(self, authed_client):
        # P4.23 CP3 custody sweep: same-object Replace/Reacquire, Exact Restore,
        # the generic recovery engine, Delete Stray, external storage-profile
        # change, and installation signing-key rotation are permanently out of
        # scope (EVIDENCE-CUSTODY-SPEC.md "Out of Scope"). Their backend routes are
        # deleted; an authenticated POST must 404 (route gone), never 200/401/403.
        # Fail-on-revert at the HTTP surface — the source-level absence is locked
        # by tests/test_p423_cp3_custody_sweep_absence.py.
        removed_routes = (
            "/api/evidence/chain/unseal",
            "/api/evidence/chain/reacquire",
            "/api/evidence/chain/delete",
            "/api/evidence/chain/replace/begin",
            "/api/evidence/chain/restore/begin",
            "/api/evidence/chain/recovery/complete",
            "/api/evidence/storage/profile",
            "/api/evidence/chain/signing-key/rotate",
        )
        for route in removed_routes:
            assert authed_client.post(route, json={}).status_code == 404, route

    def test_object_history_is_path_free_and_uuid_scoped(self, authed_client):
        object_id = "22222222-2222-4222-8222-222222222222"
        response = authed_client.get(f"/api/evidence/objects/{object_id}/history")
        assert response.status_code == 200
        assert response.json()["evidence_object_id"] == object_id
        assert "path" not in response.text
        assert authed_client.get("/api/evidence/objects/not-a-uuid/history").status_code == 400
