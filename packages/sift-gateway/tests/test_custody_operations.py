from __future__ import annotations

import hashlib
import os
import pwd
from dataclasses import replace
from pathlib import Path

import pytest
from sift_gateway.custody_operations import (
    CustodyOperationError,
    CustodyOperationPhase,
    CustodyOperationRecord,
    LocalImmutablePostureAdapter,
    PinnedEvidenceFile,
    PostureBatch,
    SealCommand,
    public_operation,
)
from sift_gateway.portal_services import EvidenceAuthorityService, PortalServiceError

CASE_ID = "11111111-1111-1111-1111-111111111111"
REAUTH_ID = "22222222-2222-2222-2222-222222222222"


class FakeRepository:
    def __init__(self) -> None:
        self.record = CustodyOperationRecord(
            operation_id="33333333-3333-3333-3333-333333333333",
            case_id=CASE_ID,
            action="ADD_SEAL",
            phase=CustodyOperationPhase.GATE_BLOCKED,
            idempotency_key="seal-001",
            request_digest="sha256:" + "a" * 64,
            failed_from_phase=None,
            failure_code=None,
            result=None,
        )
        self.calls: list[tuple[str, object]] = []

    def begin_or_resume(self, command: SealCommand) -> CustodyOperationRecord:
        self.calls.append(("begin_or_resume", command))
        if self.record.phase == CustodyOperationPhase.COMPLETED:
            return self.record
        self.record = replace(
            self.record,
            phase=CustodyOperationPhase.GATE_BLOCKED,
            failed_from_phase=None,
            failure_code=None,
        )
        return self.record

    def advance(
        self,
        operation_id: str,
        expected: CustodyOperationPhase,
        target: CustodyOperationPhase,
        *,
        facts: dict | None = None,
    ) -> CustodyOperationRecord:
        self.calls.append(("advance", (expected, target, facts)))
        assert self.record.phase == expected
        self.record = replace(self.record, phase=target)
        return self.record

    def fail(
        self,
        operation_id: str,
        expected: CustodyOperationPhase,
        failure_code: str,
    ) -> CustodyOperationRecord:
        self.calls.append(("fail", (expected, failure_code)))
        self.record = replace(
            self.record,
            phase=CustodyOperationPhase.FAILED_RECOVERABLE,
            failed_from_phase=expected,
            failure_code=failure_code,
        )
        return self.record

    def commit_verified_seal(
        self,
        operation_id: str,
        *,
        items: list[dict],
        examiner: str,
    ) -> CustodyOperationRecord:
        self.calls.append(("commit_verified_seal", items))
        assert self.record.phase == CustodyOperationPhase.FILESYSTEM_VERIFIED
        self.record = replace(
            self.record,
            phase=CustodyOperationPhase.COMPLETED,
            result={
                "case_id": CASE_ID,
                "manifest_version": 7,
                "seal_status": "sealed",
                "operation_id": operation_id,
                "operation_phase": "COMPLETED",
            },
        )
        return self.record

    def get_incomplete(self, case_id: str) -> CustodyOperationRecord | None:
        return self.record if self.record.phase != CustodyOperationPhase.COMPLETED else None


class FakePosture:
    def __init__(self, *, fail_apply: bool = False, fail_verify: bool = False) -> None:
        self.fail_apply = fail_apply
        self.fail_verify = fail_verify
        self.calls: list[tuple[str, list[str]]] = []

    def prepare(self, case_dir: Path, paths: list[str]):
        self.calls.append(("prepare", paths))
        self.receipts = []
        for path in paths:
            target = case_dir / path
            st = target.stat()
            data = target.read_bytes()
            self.receipts.append({
                "path": path, "owner": "sift-service", "mode": "0644", "immutable": True,
                "st_dev": st.st_dev, "st_ino": st.st_ino, "st_nlink": st.st_nlink,
                "sha256": "sha256:" + hashlib.sha256(data).hexdigest(), "bytes": len(data),
            })
        return PostureBatch(
            root_fd=-1,
            files=[PinnedEvidenceFile(r["path"], -1, dict(r)) for r in self.receipts],
        )

    def apply(self, batch) -> None:
        paths = [receipt["path"] for receipt in self.receipts]
        self.calls.append(("apply", paths))
        if self.fail_apply:
            raise PortalServiceError("posture_apply_failed", http_status=500)

    def verify(self, batch) -> list[dict]:
        paths = [receipt["path"] for receipt in self.receipts]
        self.calls.append(("verify", paths))
        if self.fail_verify:
            raise PortalServiceError("posture_verify_failed", http_status=500)
        return self.receipts

    def close(self, batch) -> None:
        self.calls.append(("close", []))


@pytest.fixture
def seal_service(monkeypatch, tmp_path):
    repo = FakeRepository()
    posture = FakePosture()
    service = EvidenceAuthorityService(
        "postgresql://unused", custody_repository=repo, posture_adapter=posture
    )
    monkeypatch.setattr(service, "_scan_evidence", lambda case_id: [])
    monkeypatch.setattr(service, "_case_artifact_path", lambda case_id: tmp_path)
    monkeypatch.setattr(service, "_seal_object_for_path", lambda case_id, path: {
        "evidence_object_id": "44444444-4444-4444-4444-444444444444",
        "status": "detected",
    })
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.raw").write_bytes(b"forensic bytes")
    return service, repo, posture


def _seal(service: EvidenceAuthorityService):
    return service.seal(
        case_id=CASE_ID,
        file_specs=[{"path": "evidence/disk.raw", "description": "disk"}],
        reason="Initial evidence intake",
        idempotency_key="seal-001",
        reauth_audit_event_id=REAUTH_ID,
        actor={"principal_type": "operator", "principal_id": "55555555-5555-5555-5555-555555555555"},
        examiner="examiner",
    )


def test_seal_blocks_then_applies_verifies_and_commits(seal_service):
    service, repo, posture = seal_service

    result = _seal(service)

    assert result["operation_phase"] == "COMPLETED"
    assert [call[0] for call in repo.calls] == [
        "begin_or_resume",
        "advance",
        "advance",
        "commit_verified_seal",
    ]
    assert repo.calls[1][1][:2] == (
        CustodyOperationPhase.GATE_BLOCKED,
        CustodyOperationPhase.FILESYSTEM_APPLYING,
    )
    assert repo.calls[2][1][:2] == (
        CustodyOperationPhase.FILESYSTEM_APPLYING,
        CustodyOperationPhase.FILESYSTEM_VERIFIED,
    )
    assert posture.calls == [
        ("prepare", ["evidence/disk.raw"]),
        ("apply", ["evidence/disk.raw"]),
        ("verify", ["evidence/disk.raw"]),
        ("close", []),
    ]
    item = repo.calls[-1][1][0]
    assert item["sha256"].startswith("sha256:")
    assert item["bytes"] == len(b"forensic bytes")
    assert item["immutable"] is True


@pytest.mark.parametrize("failure", ["apply", "verify"])
def test_seal_failure_is_recoverable_and_never_commits(seal_service, failure):
    service, repo, posture = seal_service
    if failure == "apply":
        posture.fail_apply = True
    else:
        posture.fail_verify = True

    with pytest.raises(PortalServiceError):
        _seal(service)

    assert repo.record.phase == CustodyOperationPhase.FAILED_RECOVERABLE
    assert repo.record.failed_from_phase == CustodyOperationPhase.FILESYSTEM_APPLYING
    assert all(call[0] != "commit_verified_seal" for call in repo.calls)


def test_exact_retry_returns_completed_result_without_filesystem_replay(seal_service):
    service, repo, posture = seal_service
    first = _seal(service)
    posture.calls.clear()
    repo.calls.clear()

    second = _seal(service)

    assert second == first
    assert posture.calls == []
    assert [call[0] for call in repo.calls] == ["begin_or_resume"]


@pytest.mark.parametrize(
    ("phase", "recoverable"),
    [
        (CustodyOperationPhase.REQUESTED, False),
        (CustodyOperationPhase.GATE_BLOCKED, True),
        (CustodyOperationPhase.FILESYSTEM_APPLYING, True),
        (CustodyOperationPhase.FILESYSTEM_VERIFIED, True),
        (CustodyOperationPhase.FAILED_RECOVERABLE, True),
        (CustodyOperationPhase.LEDGER_COMMITTED, False),
    ],
)
def test_public_operation_marks_only_server_resumable_phases(phase, recoverable, seal_service):
    _service, repo, _posture = seal_service
    assert public_operation(replace(repo.record, phase=phase))["recoverable"] is recoverable


def test_seal_requires_reason_idempotency_and_reauth(seal_service):
    service, repo, _posture = seal_service
    base = dict(
        case_id=CASE_ID,
        file_specs=[{"path": "evidence/disk.raw"}],
        reason="reason",
        idempotency_key="key",
        reauth_audit_event_id=REAUTH_ID,
        actor=None,
        examiner="examiner",
    )
    for field in ("reason", "idempotency_key", "reauth_audit_event_id"):
        args = dict(base)
        args[field] = ""
        with pytest.raises(PortalServiceError):
            service.seal(**args)
    assert repo.calls == []


def test_seal_rejects_unknown_file_spec_fields_and_traversal(seal_service):
    service, _repo, _posture = seal_service
    common = dict(
        case_id=CASE_ID, reason="reason", idempotency_key="key",
        reauth_audit_event_id=REAUTH_ID, actor=None, examiner="examiner",
    )
    with pytest.raises(PortalServiceError):
        service.seal(file_specs=[{"path": "evidence/disk.raw", "unexpected": True}], **common)
    with pytest.raises(PortalServiceError):
        service.seal(file_specs=[{"path": "../disk.raw"}], **common)


def _adapter(monkeypatch):
    user = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr("sift_core.evidence_chain.set_immutable_flag_fd", lambda fd, enabled: True)
    monkeypatch.setattr("sift_core.evidence_chain.get_immutable_flag_fd", lambda fd: True)
    return LocalImmutablePostureAdapter(service_user=user)


def test_posture_adapter_pins_hashes_and_verifies_same_inode(monkeypatch, tmp_path):
    adapter = _adapter(monkeypatch)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o755)
    target = evidence / "disk.raw"
    target.write_bytes(b"bytes")
    target.chmod(0o644)
    batch = adapter.prepare(tmp_path, ["evidence/disk.raw"])
    try:
        before = dict(batch.files[0].before)
        adapter.apply(batch)
        receipts = adapter.verify(batch)
        assert receipts[0]["sha256"] == before["sha256"]
        assert receipts[0]["st_ino"] == before["st_ino"]
        assert receipts[0]["mode"] == "0644"
        assert receipts[0]["immutable"] is True
    finally:
        adapter.close(batch)


@pytest.mark.parametrize("kind", ["entry_symlink", "hardlink", "nonregular"])
def test_posture_adapter_rejects_unsafe_entries_before_apply(monkeypatch, tmp_path, kind):
    adapter = _adapter(monkeypatch)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / "source"
    source.write_bytes(b"x")
    source.chmod(0o644)
    target = evidence / "target"
    if kind == "entry_symlink":
        target.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, target)
    else:
        target.mkdir()
    with pytest.raises((CustodyOperationError, OSError)):
        adapter.prepare(tmp_path, ["evidence/target"])


def test_posture_adapter_rejects_symlink_root_and_missing_nofollow(monkeypatch, tmp_path):
    adapter = _adapter(monkeypatch)
    real = tmp_path / "real"
    real.mkdir()
    (real / "disk.raw").write_bytes(b"x")
    (tmp_path / "evidence").symlink_to(real)
    with pytest.raises((CustodyOperationError, OSError)):
        adapter.prepare(tmp_path, ["evidence/disk.raw"])

    (tmp_path / "evidence").unlink()
    (tmp_path / "evidence").mkdir()
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(CustodyOperationError):
        adapter.prepare(tmp_path, ["evidence/disk.raw"])


def test_posture_adapter_fails_on_ioctl_and_digest_drift(monkeypatch, tmp_path):
    adapter = _adapter(monkeypatch)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "disk.raw"
    target.write_bytes(b"before")
    target.chmod(0o644)
    batch = adapter.prepare(tmp_path, ["evidence/disk.raw"])
    monkeypatch.setattr("sift_core.evidence_chain.set_immutable_flag_fd", lambda fd, enabled: False)
    with pytest.raises(CustodyOperationError):
        adapter.apply(batch)
    adapter.close(batch)

    monkeypatch.setattr("sift_core.evidence_chain.set_immutable_flag_fd", lambda fd, enabled: True)
    batch = adapter.prepare(tmp_path, ["evidence/disk.raw"])
    try:
        target.write_bytes(b"after!")
        with pytest.raises(CustodyOperationError):
            adapter.verify(batch)
    finally:
        adapter.close(batch)
