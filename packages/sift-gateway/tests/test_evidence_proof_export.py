"""BATCH-K3: EvidenceAuthorityService DB-first proof export, tamper, verify.

These tests exercise the DB-authority cutover behaviour of
EvidenceAuthorityService without a live database. A fake psycopg connection
routes SQL by substring and returns scripted rows, so we can assert:

- Sealed evidence that is missing/modified on the mounted tree escalates the
  case chain to violated via app.evidence_mark_violation (DB gate fails closed).
- Proof export derives material from DB custody state, re-verifies mounted bytes
  by full re-hash, and records metadata/hash via app.evidence_record_proof_export.
- Optional Solana anchor metadata is folded into the recorded export metadata as
  external proof and never decides gate state.
- verify() re-hashes sealed objects and records the outcome via app.evidence_verify.

File manifests/ledgers/anchor JSON are never read for any gate decision here.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import sift_gateway.portal_services as ps
from case_dashboard.routes import create_dashboard_v2_app
from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sift_gateway.custody_operations import PinnedEvidenceFile, PostureBatch
from sift_gateway.portal_services import EvidenceAuthorityService, PortalServiceError
from starlette.testclient import TestClient

_CASE = "11111111-1111-1111-1111-111111111111"


class _PortalAuth:
    async def resolve(self, access_token: str, source_ip: str | None):
        del source_ip
        if access_token != "composed-test-token":
            return None
        return {
            "principal_type": "operator",
            "principal_id": "composed-operator",
            "auth_user_id": "composed-auth-user",
            "display_name": "composed examiner",
            "email": "composed@example.invalid",
            "system_role": "examiner",
            "status": "active",
            "case_memberships": [],
        }

    async def refresh(self, refresh_token: str, source_ip: str | None):
        del refresh_token, source_ip
        return None


class _PortalActiveCase:
    class _Case:
        def __init__(self, artifact_path: Path):
            self.artifact_path = artifact_path

        def as_dict(self):
            return {
                "case_id": _CASE,
                "case_key": "composed-case",
                "artifact_path": str(self.artifact_path),
            }

    def __init__(self, artifact_path: Path):
        self.case = self._Case(artifact_path)

    def get_active_case(self, principal=None):
        del principal
        return self.case


class _Cursor:
    def __init__(self, conn):
        self.conn = conn
        self._last = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.statements.append((sql, params))
        self._last = self.conn.router(sql, params)

    def fetchone(self):
        rows = self._last or []
        return rows[0] if rows else None

    def fetchall(self):
        return list(self._last or [])


class _Connection:
    def __init__(self, router, statements):
        self.router = router
        self.statements = statements
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.commits += 1


class _FakeDb:
    """Scripted DB backing the service. Returns rows keyed by SQL substring."""

    def __init__(self):
        self.statements: list = []
        self.seal_status = "sealed"
        self.manifest_version = 1
        self.head_hash = "sha256:" + "d" * 64
        self.manifest_hash = "sha256:" + "e" * 64
        self.sealed_objects: list = []  # (id, display_path, sha256, bytes)
        self.custody_events: list = []
        self.proof_export_id = "99999999-9999-9999-9999-999999999999"
        self.violation_calls: list = []
        self.verify_calls: list = []
        self.record_calls: list = []
        self.issues: list[dict[str, Any]] = []

    def router(self, sql, params):
        s = " ".join(sql.split())
        if "select seal_status,issues,manifest_version,manifest_hash" in s:
            return [(self.seal_status, self.issues, self.manifest_version, self.manifest_hash)]
        if (
            "from app.evidence_storage_authorities" in s
            and "profile,source_identity,verified_mount_instance,state" in s
        ):
            return [("LOCAL_IMMUTABLE", None, None, "AVAILABLE", 1, 1, None, datetime.now(timezone.utc), "NONE")]
        if "select v.id::text,v.item_facts" in s:
            return [("storage-receipt-1", [])]
        if "select a.profile,a.source_identity,a.verified_mount_instance" in s:
            return [("LOCAL_IMMUTABLE", None, None, "AVAILABLE", 1, 1, None,
                     self.manifest_version, self.manifest_hash, "storage-receipt-1",
                     len(self.sealed_objects))]
        if "select a.profile,a.generation,h.manifest_version,h.manifest_hash" in s:
            return [("LOCAL_IMMUTABLE", 1, self.manifest_version, self.manifest_hash)]
        if "select o.id::text,o.display_path,v.id::text,v.sha256,v.bytes" in s:
            return [(o[0], o[1], f"version-{o[0]}", o[2], o[3]) for o in self.sealed_objects]
        if "o.status in ('sealed','violated')" in s:
            return [
                (
                    o[0],
                    o[1],
                    o[2],
                    o[3],
                    datetime.now(timezone.utc),
                    {},
                    "violated" if self.seal_status == "violated" else "sealed",
                )
                for o in self.sealed_objects
            ]
        if "status in ('ignored','retired')" in s:
            return []
        if "evidence_storage_commit_full_verify" in s:
            self.verify_calls.append((True, params))
            return [(None,)]
        if "evidence_storage_record_verify_failure" in s:
            self.verify_calls.append((False, params))
            return [(None,)]
        if "evidence_record_inventory_classification_v2" in s:
            findings = getattr(params[3], "obj", params[3])
            if self.seal_status == "violated" and not any(
                finding["code"] == "PERSISTED_VIOLATION" for finding in findings
            ):
                raise RuntimeError("persisted_custody_violation_requires_recovery")
            durable_causes = [
                issue
                for issue in self.issues
                if issue.get("code") not in {
                    "PERSISTED_VIOLATION", "DETECTED_NEW_ITEM", "UNSAFE_PENDING_ITEM",
                    "INVENTORY_SCAN_FAILED",
                }
            ]
            self.issues = []
            for issue in [*findings, *durable_causes]:
                if issue not in self.issues:
                    self.issues.append(issue)
            return [(None,)]
        if "evidence_gate_status" in s and "seal_status, manifest_version, head_hash" in s:
            return [(self.seal_status, self.manifest_version, self.head_hash, len(self.sealed_objects), self.issues, None)]
        if "from app.evidence_gate_status" in s and "seal_status" in s and "head_hash" not in s:
            return [(self.seal_status,)]
        if "from app.evidence_gate_status" in s and "manifest_version" in s:
            return [(self.manifest_version,)]
        if "evidence_detect" in s:
            return [("obj-detect",)]
        if "evidence_mark_violation" in s or "evidence_mark_admission_violation" in s:
            self.violation_calls.append(params)
            self.seal_status = "violated"
            self.issues = getattr(params[3], "obj", params[3])
            return [(self.seal_status, self.manifest_version, 1, self.head_hash, self.manifest_hash, "violated", 0, [], "CHAIN_VIOLATION", None)]
        if "evidence_verify" in s:
            self.verify_calls.append(params)
            return [(_CASE, self.manifest_version, 1, self.head_hash, self.manifest_hash, self.seal_status, 0, [], "CHAIN_VERIFIED", None)]
        if "evidence_record_proof_export" in s:
            self.record_calls.append(params)
            return [(self.proof_export_id,)]
        if "manifest_hash, head_hash from app.evidence_chain_heads" in s or (
            "manifest_hash, head_hash" in s and "evidence_chain_heads" in s
        ):
            return [(self.manifest_hash, self.head_hash)]
        if "from app.evidence_objects" in s and "status = 'sealed'" in s and "current_sha256" in s:
            return [(o[1], o[2], o[3]) for o in self.sealed_objects]
        if "from app.evidence_objects" in s and "status = 'sealed'" in s:
            return [(o[0], o[1], o[3]) for o in self.sealed_objects]
        if (
            "select id::text, display_name, display_path, description, source" in s
            and "order by display_path" in s
        ):
            return [
                (
                    o[0],
                    Path(o[1]).name,
                    o[1],
                    None,
                    None,
                    "violated" if self.seal_status == "violated" else "sealed",
                    "violated" if self.seal_status == "violated" else "sealed",
                    o[2],
                    o[3],
                    None,
                    None,
                )
                for o in self.sealed_objects
            ]
        if "from app.evidence_objects" in s and "order by display_path" in s and "display_path, status, seal_status" in s:
            return [(o[1], "sealed", "sealed", o[2], o[3]) for o in self.sealed_objects]
        if "evidence_custody_events" in s:
            return list(self.custody_events)
        return []


class _PostureAdapter:
    def prepare(self, case_dir: Path, paths: list[str]) -> PostureBatch:
        return PostureBatch(
            root_fd=-1,
            files=[
                PinnedEvidenceFile(
                    path=display_path,
                    fd=os.open(case_dir / display_path, os.O_RDONLY),
                    before={},
                )
                for display_path in paths
            ],
        )

    def apply(self, batch: PostureBatch) -> None:
        del batch
        return None

    def verify(self, batch: PostureBatch) -> list[dict[str, Any]]:
        receipts = []
        for pinned in batch.files:
            st = os.fstat(pinned.fd)
            content = os.pread(pinned.fd, st.st_size, 0)
            receipts.append(
                {
                    "path": pinned.path,
                    "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                    "bytes": len(content),
                    "owner": f"{st.st_uid}:{st.st_gid}",
                    "mode": oct(st.st_mode & 0o777),
                    "immutable": True,
                    "st_dev": st.st_dev,
                    "st_ino": st.st_ino,
                    "st_mtime_ns": st.st_mtime_ns,
                    "st_ctime_ns": st.st_ctime_ns,
                    "st_nlink": st.st_nlink,
                }
            )
        return receipts

    def close(self, batch: PostureBatch) -> None:
        for pinned in batch.files:
            os.close(pinned.fd)


@pytest.fixture
def service(monkeypatch, tmp_path):
    db = _FakeDb()

    def fake_connect(self):
        return _Connection(db.router, db.statements)

    monkeypatch.setattr(ps._BasePortalDbService, "_connect", fake_connect)
    adapter = _PostureAdapter()
    svc = EvidenceAuthorityService(
        "postgresql://service@localhost/sift", posture_adapter=adapter
    )
    monkeypatch.setattr(svc, "_case_artifact_path", lambda case_id: tmp_path)
    key_path = tmp_path / "custody-signing.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    monkeypatch.setenv("SIFT_CUSTODY_SIGNING_KEY_PATH", str(key_path))
    # This legacy fake has no P4.23.6 checkpoint tables; proof-export tests
    # isolate its byte-verification behaviour from the separately tested ledger.
    monkeypatch.setattr(svc, "verify_ledger", lambda *, case_id: {"verified": True, "issues": []})
    monkeypatch.setattr("sift_core.evidence_chain.get_immutable_flag_fd", lambda _fd: True)
    (tmp_path / "evidence").mkdir()
    return svc, db, tmp_path


def _make_sealed_file(tmp_path: Path, rel: str, content: bytes):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    sha = "sha256:" + hashlib.sha256(content).hexdigest()
    return sha, len(content)


def test_full_verify_rejects_zero_active_set_before_posture_or_receipt(
    service,
) -> None:
    svc, db, _tmp_path = service

    class _ForbiddenPosture:
        def prepare(self, _case_dir, _paths):
            raise AssertionError("zero-active-set Full Verify reached posture adapter")

    svc._posture_adapter = _ForbiddenPosture()

    with pytest.raises(PortalServiceError) as exc_info:
        svc.verify(
            case_id=_CASE,
            actor={"principal_type": "operator", "principal_id": "operator-1"},
        )

    assert exc_info.value.reason == "full_verify_requires_sealed_evidence"
    assert exc_info.value.http_status == 409
    assert db.verify_calls == []


class TestTamperDetection:
    @pytest.mark.parametrize("condition", ["changed", "missing"])
    def test_dashboard_status_composes_double_reconciliation_without_no_case(
        self, service, condition
    ):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"original")
        db.sealed_objects = [("obj-composed", "evidence/disk.bin", sha, size)]
        mounted = tmp_path / "evidence" / "disk.bin"
        if condition == "changed":
            mounted.write_bytes(b"changed-longer")
        else:
            mounted.unlink()
        session_secret = secrets.token_hex(32)
        client = TestClient(
            create_dashboard_v2_app(
                session_secret=session_secret,
                supabase_auth=_PortalAuth(),
                active_case_service=_PortalActiveCase(tmp_path),
                evidence_service=svc,
            )
        )
        client.cookies[SESSION_ENVELOPE_COOKIE_NAME] = generate_session_envelope(
            access_token="composed-test-token",
            refresh_token=secrets.token_hex(24),
            expires_at=9_999_999_999,
            sub="composed-auth-user",
            fingerprint="composed-test",
            secret=session_secret,
        )

        response = client.get("/api/evidence/chain/status")

        assert response.status_code == 200
        payload = response.json()

        assert payload["status"] == "violated"
        assert payload["gate_state"] == "BLOCKED_VIOLATION"
        expected = ["evidence/disk.bin"]
        assert payload["missing"] == (expected if condition == "missing" else [])
        assert payload["modified"] == (expected if condition == "changed" else [])
        classification_calls = [
            params
            for sql, params in db.statements
            if "evidence_record_inventory_classification_v2" in sql
        ]
        assert len(classification_calls) == 2
        second_findings = getattr(
            classification_calls[1][3], "obj", classification_calls[1][3]
        )
        assert second_findings[0]["code"] == "PERSISTED_VIOLATION"

    def test_gate_status_surfaces_path_free_storage_authority(self, service):
        svc, _db, _tmp_path = service

        status = svc.gate_status(_CASE)

        assert status["storage_profile"] == "LOCAL_IMMUTABLE"
        assert status["storage_availability"] == "AVAILABLE"
        assert status["storage_source_identity"] is None
        assert status["storage_verified_mount_instance"] is None
        assert status["storage_generation"] == 1
        assert status["storage_verified_generation"] == 1
        assert status["storage_read_only"] is None
        assert status["storage_last_full_verified_at"] is not None
        assert status["storage_remediation"] == "NONE"
        assert "observed_mount_instance" not in status

    def test_modified_sealed_file_marks_violation(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"x" * 64)
        # Sealed record claims the original 64 bytes; tamper grows the file.
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").write_bytes(b"x" * 128)

        svc.gate_status(_CASE)  # triggers _scan_evidence -> tamper check

        assert db.violation_calls, "expected a mark_violation call for a modified sealed file"
        # The violation reason and offending object are passed to the RPC.
        last = db.violation_calls[-1]
        assert last[0] == _CASE
        assert last[1] == "obj-1"

    def test_missing_sealed_file_marks_violation(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"y" * 32)
        db.sealed_objects = [("obj-2", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").unlink()

        svc.gate_status(_CASE)

        assert db.violation_calls
        assert db.violation_calls[-1][1] == "obj-2"

    def test_intact_sealed_file_no_violation(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"z" * 16)
        db.sealed_objects = [("obj-3", "evidence/disk.bin", sha, size)]

        svc.gate_status(_CASE)

        assert not db.violation_calls

    def test_already_violated_remains_blocked_without_duplicate_event(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"q" * 8)
        db.sealed_objects = [("obj-4", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").unlink()
        db.seal_status = "violated"

        svc.gate_status(_CASE)

        assert not db.violation_calls
        classification = next(
            params
            for sql, params in db.statements
            if "evidence_record_inventory_classification_v2" in sql
        )
        assert classification[1]
        findings = getattr(classification[3], "obj", classification[3])
        assert [finding["code"] for finding in findings] == [
            "PERSISTED_VIOLATION",
            "SEALED_EVIDENCE_MISSING",
        ]


class TestProofExport:
    def test_export_records_metadata_and_hash(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"a" * 100)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]

        result = svc.export_proof(case_id=_CASE)

        assert result["export_id"] == db.proof_export_id
        assert result["verified"] is True
        assert result["proof_hash"].startswith("sha256:")
        assert db.record_calls, "expected a record_proof_export call"
        # verified flag passed positionally to the RPC (6th arg).
        rec = db.record_calls[-1]
        assert rec[0] == _CASE
        assert rec[5] is True  # verified

    def test_export_reports_unverified_when_bytes_changed(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"a" * 100)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").write_bytes(b"a" * 50)

        result = svc.export_proof(case_id=_CASE)

        assert result["verified"] is False
        assert any("mismatch" in str(i).lower() for i in result["issues"])
        assert db.record_calls[-1][5] is False

    def test_solana_anchor_recorded_as_external_proof(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"a" * 10)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        anchor = {
            "solana_tx": "abc123",
            "confirmed": True,
            "solana_cluster": "devnet",
            "anchor_payload": "SIFT|aaaa|bbbb",
            "explorer_url": "https://solscan.io/tx/abc123?cluster=devnet",
        }

        result = svc.export_proof(case_id=_CASE, anchor=anchor)

        assert result["anchor"]["solana_tx"] == "abc123"
        assert result["anchor"]["confirmed"] is True
        # Anchor folded into recorded metadata; never authority over verify.
        metadata = db.record_calls[-1][7]
        meta = metadata.obj if hasattr(metadata, "obj") else metadata
        assert meta["anchor"]["solana_tx"] == "abc123"

    def test_unconfigured_anchor_still_exports(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"a" * 10)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]

        result = svc.export_proof(case_id=_CASE, anchor=None)

        assert result["anchor"] is None
        assert result["export_id"] == db.proof_export_id

    def test_latest_proof_export_returns_none_when_absent(self, service):
        svc, db, tmp_path = service
        # No proof_exports rows scripted -> router returns [] for that select.
        assert svc.latest_proof_export(_CASE) is None


class TestVerify:
    def test_verify_records_ok_when_intact(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"v" * 20)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]

        result = svc.verify(case_id=_CASE)

        assert result["verified"] is True
        assert db.verify_calls
        assert db.verify_calls[-1][0] is True

    def test_verify_records_failure_when_modified(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"v" * 20)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").write_bytes(b"v" * 99)

        result = svc.verify(case_id=_CASE)

        assert result["verified"] is False
        assert db.verify_calls[-1][0] is False

    def test_successful_hash_does_not_hide_authoritative_blocking_issue(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"v" * 20)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        db.seal_status = "violated"
        db.issues = [
            {
                "code": "CONTENT_CHANGED",
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "RESTORE_REACQUIRE_RETIRE",
                "evidence_object_id": "obj-1",
                "observation_id": "observation-1",
                "full_verification_required": False,
            }
        ]

        result = svc.verify(case_id=_CASE)

        assert db.verify_calls[-1][0] is True
        assert result["verified"] is False
        assert result["seal_status"] == "violated"
        assert result["gate_state"] == "BLOCKED_VIOLATION"
        assert result["issues"][0]["code"] == "PERSISTED_VIOLATION"
        assert result["verification_issues"] == []

    @pytest.mark.parametrize(
        "blocking_code",
        ("LEDGER_INVALID", "CONFLICTING_AUTHORITY", "FUTURE_UNKNOWN_VIOLATION"),
    )
    def test_repeated_full_verify_cannot_launder_durable_cause(
        self, service, blocking_code
    ):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"v" * 20)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        db.seal_status = "violated"
        db.issues = [
            {
                "code": "PERSISTED_VIOLATION",
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "RESTORE_REACQUIRE_RETIRE",
                "evidence_object_id": None,
                "observation_id": None,
                "full_verification_required": False,
            },
            {
                "code": "FULL_VERIFY_REQUIRED",
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "FULL_VERIFY",
                "evidence_object_id": None,
                "observation_id": None,
                "full_verification_required": True,
            },
            {
                "code": "INVENTORY_SCAN_FAILED",
                "gate_state": "BLOCKED_UNAVAILABLE",
                "recovery": "INVESTIGATE_AVAILABILITY",
                "evidence_object_id": None,
                "observation_id": None,
                "full_verification_required": False,
            },
            {
                "code": blocking_code,
                "gate_state": "BLOCKED_VIOLATION",
                "recovery": "RESTORE_REACQUIRE_RETIRE",
                "evidence_object_id": None,
                "observation_id": None,
                "full_verification_required": False,
            },
        ]

        first = svc.verify(case_id=_CASE)
        second = svc.verify(case_id=_CASE)

        for result in (first, second):
            assert result["verified"] is False
            assert result["seal_status"] == "violated"
            assert result["gate_state"] == "BLOCKED_VIOLATION"
            assert blocking_code in {issue["code"] for issue in result["issues"]}
        assert len([call for call in db.verify_calls if call[0] is True]) == 2
