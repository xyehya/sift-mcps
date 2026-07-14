from __future__ import annotations

import hashlib
import json
import os
import pwd
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from sift_core.evidence_storage import StorageProfile
from sift_gateway.custody_operations import (
    CustodyAction,
    CustodyOperationError,
    CustodyOperationPhase,
    CustodyOperationRecord,
    CustodyOperationRepositoryProtocol,
    DispositionCustodyOperation,
    ExternalReadOnlyPostureAdapter,
    LocalCustodyDeleteBroker,
    LocalImmutablePostureAdapter,
    ObjectCustodyCommand,
    PinnedEvidenceFile,
    PostureBatch,
    SealCommand,
    public_operation,
)
from sift_gateway.portal_services import EvidenceAuthorityService, PortalServiceError

CASE_ID = "11111111-1111-1111-1111-111111111111"
REAUTH_ID = "22222222-2222-2222-2222-222222222222"
ACTOR_ID = "55555555-5555-5555-5555-555555555555"


class FakeDeleteBroker:
    def __init__(self, callback=None) -> None:
        self.callback = callback
        self.operation_ids: list[str] = []

    def delete(self, *, operation_id: str) -> None:
        self.operation_ids.append(operation_id)
        if self.callback is not None:
            self.callback()


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

    def prepare(self, case_dir: Path, paths: list[str], *, expected_root_paths=None):
        del expected_root_paths
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
        "postgresql://unused",
        custody_repository=cast(CustodyOperationRepositoryProtocol, repo),
        posture_adapter=posture,
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
        actor={"principal_type": "operator", "principal_id": ACTOR_ID},
        examiner="examiner",
    )


class FakeDispositionRepository:
    def __init__(self, action: CustodyAction) -> None:
        self.record = CustodyOperationRecord(
            operation_id="66666666-6666-4666-8666-666666666666",
            case_id=CASE_ID,
            action=action.value,
            phase=CustodyOperationPhase.GATE_BLOCKED,
            idempotency_key="disposition-001",
            request_digest="sha256:" + "b" * 64,
            failed_from_phase=None,
            failure_code=None,
            result=None,
        )
        self.calls: list[tuple[str, object]] = []

    def begin_or_resume(self, command: ObjectCustodyCommand) -> CustodyOperationRecord:
        self.calls.append(("begin_or_resume", command))
        return self.record

    def advance(self, operation_id, expected, target, *, facts=None):
        self.calls.append(("advance", (expected, target, facts)))
        assert self.record.phase == expected
        prepared = facts if target is CustodyOperationPhase.FILESYSTEM_APPLYING else self.record.prepared_facts
        verified = facts if target is CustodyOperationPhase.FILESYSTEM_VERIFIED else self.record.verified_facts
        self.record = replace(
            self.record, phase=target, prepared_facts=prepared, verified_facts=verified
        )
        return self.record

    def fail(self, operation_id, expected, failure_code):
        self.calls.append(("fail", (expected, failure_code)))
        self.record = replace(
            self.record,
            phase=CustodyOperationPhase.FAILED_RECOVERABLE,
            failed_from_phase=expected,
            failure_code=failure_code,
        )
        return self.record

    def commit_verified_disposition(self, operation_id, *, item, examiner):
        self.calls.append(("commit_verified_disposition", item))
        assert self.record.phase is CustodyOperationPhase.FILESYSTEM_VERIFIED
        self.record = replace(
            self.record,
            phase=CustodyOperationPhase.COMPLETED,
            result={"operation_phase": "COMPLETED", **item},
        )
        return self.record


def _disposition_command(action: CustodyAction) -> ObjectCustodyCommand:
    return ObjectCustodyCommand(
        action=action,
        case_id=CASE_ID,
        evidence_object_id="44444444-4444-4444-8444-444444444444",
        actor_user_id=ACTOR_ID,
        actor_service_identity_id=None,
        reason="Operator disposition",
        reauth_audit_event_id=REAUTH_ID,
        idempotency_key="disposition-001",
    )


def test_delete_stray_blocks_gate_before_descriptor_pinned_unlink(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "stray.bin"
    target.write_bytes(b"untrusted stray bytes")
    repo = FakeDispositionRepository(CustodyAction.DELETE_STRAY)
    seen: list[bool] = []
    original_advance = repo.advance

    def advance(*args, **kwargs):
        seen.append(target.exists())
        return original_advance(*args, **kwargs)

    repo.advance = advance
    runner = DispositionCustodyOperation(
        cast(CustodyOperationRepositoryProtocol, repo),
        lambda _case_id: tmp_path,
        lambda _case_id, _object_id: {
            "evidence_object_id": "44444444-4444-4444-8444-444444444444",
            "display_path": "evidence/stray.bin",
            "status": "detected",
            "seal_status": "unsealed",
        },
        FakeDeleteBroker(target.unlink),
    )

    result = runner.execute(_disposition_command(CustodyAction.DELETE_STRAY), examiner="examiner")

    assert seen[0] is True
    assert target.exists() is False
    assert result["file_removed"] is True
    assert result["sha256"] == "sha256:" + hashlib.sha256(b"untrusted stray bytes").hexdigest()
    assert [name for name, _ in repo.calls] == [
        "begin_or_resume", "advance", "advance", "commit_verified_disposition"
    ]


def test_delete_stray_rejects_missing_initial_item_without_committing(tmp_path):
    (tmp_path / "evidence").mkdir()
    repo = FakeDispositionRepository(CustodyAction.DELETE_STRAY)
    runner = DispositionCustodyOperation(
        cast(CustodyOperationRepositoryProtocol, repo),
        lambda _case_id: tmp_path,
        lambda _case_id, _object_id: {
            "evidence_object_id": "44444444-4444-4444-8444-444444444444",
            "display_path": "evidence/missing.bin",
            "status": "detected",
            "seal_status": "unsealed",
        },
        FakeDeleteBroker(),
    )

    with pytest.raises(CustodyOperationError, match="delete_requires_readable_pending_item"):
        runner.execute(
            _disposition_command(CustodyAction.DELETE_STRAY), examiner="examiner"
        )

    assert not (tmp_path / "evidence" / "missing.bin").exists()
    assert "commit_verified_disposition" not in [name for name, _ in repo.calls]


@pytest.mark.parametrize("action", [CustodyAction.IGNORE, CustodyAction.RETIRE])
def test_non_delete_disposition_never_mutates_evidence_bytes(tmp_path, action):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "disk.raw"
    target.write_bytes(b"preserved evidence")
    repo = FakeDispositionRepository(action)
    runner = DispositionCustodyOperation(
        cast(CustodyOperationRepositoryProtocol, repo),
        lambda _case_id: tmp_path,
        lambda _case_id, _object_id: {
            "evidence_object_id": "44444444-4444-4444-8444-444444444444",
            "display_path": "evidence/disk.raw",
            "status": "detected" if action is CustodyAction.IGNORE else "sealed",
            "seal_status": "unsealed" if action is CustodyAction.IGNORE else "sealed",
            "current_sha256": "sha256:" + hashlib.sha256(b"preserved evidence").hexdigest(),
            "current_bytes": len(b"preserved evidence"),
            "current_version_id": "77777777-7777-4777-8777-777777777777",
        },
        FakeDeleteBroker(lambda: pytest.fail("non-delete action reached delete broker")),
    )

    runner.execute(_disposition_command(action), examiner="examiner")

    assert target.read_bytes() == b"preserved evidence"


def test_delete_resume_after_unlink_commits_stored_pre_unlink_facts(tmp_path):
    (tmp_path / "evidence").mkdir()
    repo = FakeDispositionRepository(CustodyAction.DELETE_STRAY)
    item = {
        "evidence_object_id": "44444444-4444-4444-8444-444444444444",
        "display_path": "evidence/stray.bin",
        "prior_status": "detected",
        "prior_seal_status": "unsealed",
        "present": True,
        "sha256": "sha256:" + hashlib.sha256(b"gone").hexdigest(),
        "bytes": 4,
        "st_dev": 1,
        "st_ino": 2,
        "st_nlink": 1,
    }
    repo.record = replace(
        repo.record,
        phase=CustodyOperationPhase.FILESYSTEM_APPLYING,
        prepared_facts={"item": item},
    )
    broker = FakeDeleteBroker()
    runner = DispositionCustodyOperation(
        cast(CustodyOperationRepositoryProtocol, repo),
        lambda _case_id: tmp_path,
        lambda *_args: pytest.fail("resume must use stored facts"),
        broker,
    )

    result = runner.execute(_disposition_command(CustodyAction.DELETE_STRAY), examiner="examiner")

    assert result["file_removed"] is True
    assert result["sha256"] == item["sha256"]
    assert broker.operation_ids == [repo.record.operation_id]


def test_delete_resume_missing_without_broker_receipt_is_rejected(tmp_path):
    (tmp_path / "evidence").mkdir()
    repo = FakeDispositionRepository(CustodyAction.DELETE_STRAY)
    item = {
        "evidence_object_id": "44444444-4444-4444-8444-444444444444",
        "display_path": "evidence/stray.bin",
        "prior_status": "detected",
        "prior_seal_status": "unsealed",
        "present": True,
        "sha256": "sha256:" + hashlib.sha256(b"gone").hexdigest(),
        "bytes": 4,
        "st_dev": 1,
        "st_ino": 2,
        "st_nlink": 1,
    }
    repo.record = replace(
        repo.record,
        phase=CustodyOperationPhase.FILESYSTEM_APPLYING,
        prepared_facts={"item": item},
    )

    def reject_missing() -> None:
        raise CustodyOperationError("delete_broker_rejected", http_status=409)

    broker = FakeDeleteBroker(reject_missing)
    runner = DispositionCustodyOperation(
        cast(CustodyOperationRepositoryProtocol, repo),
        lambda _case_id: tmp_path,
        lambda *_args: pytest.fail("resume must use stored facts"),
        broker,
    )

    with pytest.raises(CustodyOperationError, match="delete_broker_rejected"):
        runner.execute(_disposition_command(CustodyAction.DELETE_STRAY), examiner="examiner")

    assert broker.operation_ids == [repo.record.operation_id]
    assert "commit_verified_disposition" not in [name for name, _ in repo.calls]


def test_local_delete_broker_sends_only_operation_authority(monkeypatch):
    seen: dict[str, object] = {}

    def run(argv, **kwargs):
        seen["argv"] = argv
        seen["request"] = json.loads(kwargs["input"])
        return type("Completed", (), {"returncode": 0, "stdout": '{"removed":true,"schema_version":1}'})()

    monkeypatch.setattr("sift_gateway.custody_operations.subprocess.run", run)
    LocalCustodyDeleteBroker().delete(
        operation_id="33333333-3333-3333-3333-333333333333"
    )

    assert seen["argv"] == [
        "/usr/bin/sudo", "-n", "-u", "root",
        "/usr/local/sbin/sift-custody-delete-broker",
    ]
    assert set(cast(dict, seen["request"])) == {
        "schema_version", "operation_id", "runner_instance_id"
    }


class _ResumeLookupCursor:
    def __init__(self, phase: CustodyOperationPhase) -> None:
        self.phase = phase
        self.allowed: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, _sql, params) -> None:
        self.allowed = list(params[2])

    def fetchone(self):
        if self.phase.value not in self.allowed:
            return None
        return (
            {"action": "ADD_SEAL", "files": [{"path": "evidence/disk.raw"}]},
            "Initial evidence intake",
            "seal-001",
            REAUTH_ID,
            ACTOR_ID,
            None,
        )


class _ResumeLookupConnection:
    def __init__(self, phase: CustodyOperationPhase) -> None:
        self.cursor_instance = _ResumeLookupCursor(phase)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return self.cursor_instance


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


@pytest.mark.parametrize(
    "phase",
    [CustodyOperationPhase.REQUESTED, CustodyOperationPhase.LEDGER_COMMITTED],
)
def test_resume_service_rejects_nonresumable_phase_before_orchestration(
    phase, seal_service, monkeypatch
):
    service, repo, posture = seal_service
    lookup = _ResumeLookupConnection(phase)
    monkeypatch.setattr(service, "_connect", lambda: lookup)
    scan_calls: list[str] = []
    monkeypatch.setattr(service, "_scan_evidence", scan_calls.append)

    with pytest.raises(PortalServiceError) as exc:
        service.resume_seal(
            case_id=CASE_ID,
            operation_id=repo.record.operation_id,
            actor={"principal_type": "operator", "principal_id": ACTOR_ID},
            examiner="examiner",
            resume_reauth_audit_event_id="66666666-6666-6666-6666-666666666666",
        )

    assert exc.value.reason == "custody_operation_not_resumable"
    assert exc.value.http_status == 404
    assert lookup.cursor_instance.allowed == [
        CustodyOperationPhase.GATE_BLOCKED.value,
        CustodyOperationPhase.FILESYSTEM_APPLYING.value,
        CustodyOperationPhase.FILESYSTEM_VERIFIED.value,
        CustodyOperationPhase.FAILED_RECOVERABLE.value,
    ]
    assert repo.calls == []
    assert posture.calls == []
    assert scan_calls == []


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


def test_external_adapter_observes_without_local_mutation(monkeypatch, tmp_path):
    from sift_core.evidence_storage import ExternalStorageFacts

    facts = ExternalStorageFacts("a" * 64, "b" * 64, "ext4", True)
    monkeypatch.setattr("sift_gateway.custody_operations.external_storage_facts", lambda _fd: facts)
    monkeypatch.setattr(
        "sift_core.evidence_chain.set_immutable_flag_fd",
        lambda *_args: pytest.fail("external storage must never invoke local mutation"),
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.raw").write_bytes(b"external evidence")
    adapter = ExternalReadOnlyPostureAdapter()
    batch = adapter.prepare(tmp_path, ["evidence/disk.raw"])
    try:
        adapter.apply(batch)
        receipt = adapter.verify(batch)[0]
        assert receipt["storage_source_identity"] == "a" * 64
        assert receipt["mount_instance_identity"] == "b" * 64
        assert receipt["read_only"] is True
        assert "owner" not in receipt and "mode" not in receipt
        assert "immutable" not in receipt
    finally:
        adapter.close(batch)


@pytest.mark.parametrize("unsafe_kind", ("symlink", "directory", "hardlink", "extra"))
def test_external_adapter_requires_exact_safe_root_inventory(
    monkeypatch, tmp_path, unsafe_kind
):
    from sift_core.evidence_storage import ExternalStorageFacts

    facts = ExternalStorageFacts("a" * 64, "b" * 64, "ext4", True)
    monkeypatch.setattr(
        "sift_gateway.custody_operations.external_storage_facts", lambda _fd: facts
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "disk.raw"
    target.write_bytes(b"external evidence")
    sibling = evidence / "unsafe"
    if unsafe_kind == "symlink":
        sibling.symlink_to(target)
    elif unsafe_kind == "directory":
        sibling.mkdir()
    elif unsafe_kind == "hardlink":
        os.link(target, sibling)
    else:
        sibling.write_bytes(b"omitted regular evidence")

    with pytest.raises(CustodyOperationError, match="external_inventory_target_set_mismatch"):
        ExternalReadOnlyPostureAdapter().prepare(tmp_path, ["evidence/disk.raw"])


def test_external_adapter_rechecks_exact_root_inventory_before_receipt(
    monkeypatch, tmp_path
):
    from sift_core.evidence_storage import ExternalStorageFacts

    facts = ExternalStorageFacts("a" * 64, "b" * 64, "ext4", True)
    monkeypatch.setattr(
        "sift_gateway.custody_operations.external_storage_facts", lambda _fd: facts
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.raw").write_bytes(b"external evidence")
    adapter = ExternalReadOnlyPostureAdapter()
    batch = adapter.prepare(tmp_path, ["evidence/disk.raw"])
    try:
        (evidence / "raced.raw").write_bytes(b"appeared after prepare")
        with pytest.raises(
            CustodyOperationError, match="external_inventory_target_set_mismatch"
        ):
            adapter.verify(batch)
    finally:
        adapter.close(batch)


def test_external_seal_race_never_reaches_commit(monkeypatch, tmp_path):
    from sift_core.evidence_storage import ExternalStorageFacts

    facts = ExternalStorageFacts("a" * 64, "b" * 64, "ext4", True)
    monkeypatch.setattr(
        "sift_gateway.custody_operations.external_storage_facts", lambda _fd: facts
    )

    class RacingExternalAdapter(ExternalReadOnlyPostureAdapter):
        def apply(self, batch):
            super().apply(batch)
            (tmp_path / "evidence" / "raced.raw").write_bytes(b"raced")

    repo = FakeRepository()
    service = EvidenceAuthorityService(
        "postgresql://unused",
        custody_repository=cast(CustodyOperationRepositoryProtocol, repo),
        external_posture_adapter=RacingExternalAdapter(),
    )
    monkeypatch.setattr(service, "_scan_evidence", lambda _case_id: [])
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: tmp_path)
    monkeypatch.setattr(
        service, "_seal_expected_root_paths", lambda _case_id, paths: paths
    )
    monkeypatch.setattr(
        service,
        "_seal_object_for_path",
        lambda _case_id, _path: {
            "evidence_object_id": "44444444-4444-4444-4444-444444444444",
            "status": "detected",
        },
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.raw").write_bytes(b"external evidence")

    with pytest.raises(
        PortalServiceError, match="external_inventory_target_set_mismatch"
    ):
        service.seal(
            case_id=CASE_ID,
            file_specs=[{"path": "evidence/disk.raw"}],
            reason="external intake",
            idempotency_key="external-race",
            reauth_audit_event_id=REAUTH_ID,
            actor={"principal_type": "operator", "principal_id": ACTOR_ID},
            examiner="examiner",
            storage_profile=StorageProfile.EXTERNALLY_READ_ONLY.value,
        )

    assert all(call[0] != "commit_verified_seal" for call in repo.calls)
    assert repo.record.phase is CustodyOperationPhase.FAILED_RECOVERABLE


def test_external_root_authority_excludes_retired_paths():
    class Cursor:
        sql = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params):
            self.sql = " ".join(sql.split())

        def fetchall(self):
            return [("evidence/sealed.raw",), ("evidence/ignored.raw",)]

    class Connection:
        def __init__(self):
            self.cursor_instance = Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return self.cursor_instance

    connection = Connection()
    service = cast(EvidenceAuthorityService, object.__new__(EvidenceAuthorityService))
    service._connect = lambda: connection  # type: ignore[method-assign]

    expected = service._seal_expected_root_paths(
        CASE_ID, ["evidence/new.raw"]
    )

    assert expected == [
        "evidence/ignored.raw",
        "evidence/new.raw",
        "evidence/sealed.raw",
    ]
    assert "'retired'" not in connection.cursor_instance.sql


def test_external_adapter_fails_closed_when_mount_instance_changes(monkeypatch, tmp_path):
    from sift_core.evidence_storage import ExternalStorageFacts

    initial = ExternalStorageFacts("a" * 64, "b" * 64, "ext4", True)
    changed = ExternalStorageFacts("a" * 64, "c" * 64, "ext4", True)
    calls = 0

    def mount_facts(_fd):
        nonlocal calls
        calls += 1
        return initial if calls < 3 else changed

    monkeypatch.setattr("sift_gateway.custody_operations.external_storage_facts", mount_facts)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "disk.raw").write_bytes(b"external evidence")
    adapter = ExternalReadOnlyPostureAdapter()
    with pytest.raises(CustodyOperationError, match="external_evidence_changed_while_hashing"):
        adapter.prepare(tmp_path, ["evidence/disk.raw"])


def test_full_verify_failure_records_path_free_append_only_outcome():
    class Cursor:
        sql = ""
        params = None
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, sql, params): self.sql, self.params = sql, params

    class Connection:
        def __init__(self):
            self.cursor_instance, self.committed = Cursor(), False
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return self.cursor_instance
        def commit(self): self.committed = True

    connection = Connection()
    service = cast(EvidenceAuthorityService, object.__new__(EvidenceAuthorityService))
    service._connect = lambda: connection  # type: ignore[method-assign]
    service._record_storage_verify_failure(
        case_id=CASE_ID, generation=3, profile=StorageProfile.EXTERNALLY_READ_ONLY,
        manifest_version=4, manifest_hash="sha256:" + "a" * 64,
        failure_code="READ_WRITE_DRIFT", correlation_id="full-verify:test",
        actor_user_id=ACTOR_ID,
    )
    assert "evidence_storage_record_verify_failure" in connection.cursor_instance.sql
    assert connection.cursor_instance.params[5:7] == ("READ_WRITE_DRIFT", "full-verify:test")
    assert connection.committed is True


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
