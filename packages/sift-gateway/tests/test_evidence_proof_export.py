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
from pathlib import Path

import pytest

import sift_gateway.portal_services as ps
from sift_gateway.portal_services import EvidenceAuthorityService


_CASE = "11111111-1111-1111-1111-111111111111"


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

    def router(self, sql, params):
        s = " ".join(sql.split())
        if "evidence_gate_status" in s and "seal_status, manifest_version, head_hash" in s:
            return [(self.seal_status, self.manifest_version, self.head_hash, len(self.sealed_objects), [], None)]
        if "from app.evidence_gate_status" in s and "seal_status" in s and "head_hash" not in s:
            return [(self.seal_status,)]
        if "from app.evidence_gate_status" in s and "manifest_version" in s:
            return [(self.manifest_version,)]
        if "evidence_detect" in s:
            return [("obj-detect",)]
        if "evidence_mark_violation" in s:
            self.violation_calls.append(params)
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
        if "from app.evidence_objects" in s and "order by display_path" in s and "display_path, status, seal_status" in s:
            return [(o[1], "sealed", "sealed", o[2], o[3]) for o in self.sealed_objects]
        if "evidence_custody_events" in s:
            return list(self.custody_events)
        return []


@pytest.fixture
def service(monkeypatch, tmp_path):
    db = _FakeDb()

    def fake_connect(self):
        return _Connection(db.router, db.statements)

    monkeypatch.setattr(ps._BasePortalDbService, "_connect", fake_connect)
    svc = EvidenceAuthorityService("postgresql://service@localhost/sift")
    monkeypatch.setattr(svc, "_case_artifact_path", lambda case_id: tmp_path)
    (tmp_path / "evidence").mkdir()
    return svc, db, tmp_path


def _make_sealed_file(tmp_path: Path, rel: str, content: bytes):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    sha = "sha256:" + hashlib.sha256(content).hexdigest()
    return sha, len(content)


class TestTamperDetection:
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

    def test_already_violated_does_not_redetect(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"q" * 8)
        db.sealed_objects = [("obj-4", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").unlink()
        db.seal_status = "violated"

        svc.gate_status(_CASE)

        assert not db.violation_calls


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
        assert any("Modified" in i for i in result["issues"])
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
        assert db.verify_calls[-1][1] is True  # ok flag

    def test_verify_records_failure_when_modified(self, service):
        svc, db, tmp_path = service
        sha, size = _make_sealed_file(tmp_path, "evidence/disk.bin", b"v" * 20)
        db.sealed_objects = [("obj-1", "evidence/disk.bin", sha, size)]
        (tmp_path / "evidence" / "disk.bin").write_bytes(b"v" * 99)

        result = svc.verify(case_id=_CASE)

        assert result["verified"] is False
        assert db.verify_calls[-1][1] is False
