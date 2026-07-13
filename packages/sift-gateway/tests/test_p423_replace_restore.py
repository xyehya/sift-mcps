from __future__ import annotations

import hashlib
import os
import pwd
from dataclasses import replace

import pytest
from sift_gateway.custody_operations import (
    CustodyAction,
    CustodyOperationError,
    CustodyOperationPhase,
    CustodyOperationRecord,
    ObjectCustodyCommand,
    RecoveryCustodyOperation,
)

CASE_ID = "11111111-1111-1111-1111-111111111111"
OBJECT_ID = "22222222-2222-4222-8222-222222222222"
ACTOR_ID = "33333333-3333-4333-8333-333333333333"
REAUTH_ID = "44444444-4444-4444-8444-444444444444"
COMPLETE_REAUTH_ID = "55555555-5555-4555-8555-555555555555"
RETRY_REAUTH_ID = "88888888-8888-4888-8888-888888888888"
VERSION_ID = "66666666-6666-4666-8666-666666666666"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class RecoveryRepository:
    def __init__(self) -> None:
        self.record: CustodyOperationRecord | None = None
        self.calls: list[str] = []
        self.used_completion_receipts: set[str] = set()
        self.fail_commit_once = False

    def begin_or_resume(self, command):
        self.calls.append("begin")
        self.record = CustodyOperationRecord(
            operation_id="77777777-7777-4777-8777-777777777777",
            case_id=command.case_id,
            action=command.action.value,
            phase=CustodyOperationPhase.GATE_BLOCKED,
            idempotency_key=command.idempotency_key,
            request_digest="sha256:" + "a" * 64,
            failed_from_phase=None,
            failure_code=None,
            result=None,
        )
        return self.record

    def advance(self, operation_id, expected, target, *, facts=None):
        self.calls.append(f"advance:{expected.value}:{target.value}")
        assert self.record is not None and self.record.phase == expected
        updates = {"phase": target}
        if target == CustodyOperationPhase.FILESYSTEM_APPLYING:
            updates["prepared_facts"] = facts
        if target == CustodyOperationPhase.FILESYSTEM_VERIFIED:
            updates["verified_facts"] = facts
        self.record = replace(self.record, **updates)
        return self.record

    def fail(self, operation_id, expected, failure_code):
        self.calls.append(f"fail:{expected.value}:{failure_code}")
        assert self.record is not None
        self.record = replace(
            self.record, phase=CustodyOperationPhase.FAILED_RECOVERABLE,
            failed_from_phase=expected, failure_code=failure_code,
        )
        return self.record

    def authorize_recovery_completion(
        self, operation_id, *, actor_user_id, completion_reauth_audit_event_id
    ):
        self.calls.append("authorize_completion")
        assert actor_user_id == ACTOR_ID
        assert self.record is not None
        if completion_reauth_audit_event_id in self.used_completion_receipts:
            raise CustodyOperationError("recovery_completion_receipt_already_used")
        if self.used_completion_receipts and (
            self.record.phase != CustodyOperationPhase.FAILED_RECOVERABLE
            or self.record.failed_from_phase not in {
                CustodyOperationPhase.FILESYSTEM_APPLYING,
                CustodyOperationPhase.FILESYSTEM_VERIFIED,
            }
        ):
            raise CustodyOperationError("recovery_completion_already_authorized")
        self.used_completion_receipts.add(completion_reauth_audit_event_id)
        self.record = replace(
            self.record, phase=CustodyOperationPhase.FILESYSTEM_APPLYING,
            failed_from_phase=None, failure_code=None,
        )
        return self.record

    def commit_verified_recovery(self, operation_id, *, item, examiner):
        self.calls.append("commit_recovery")
        assert self.record is not None
        if self.fail_commit_once:
            self.fail_commit_once = False
            raise RuntimeError("interrupted after verification")
        restored = self.record.action == CustodyAction.RESTORE_EXACT.value
        self.record = replace(
            self.record, phase=CustodyOperationPhase.COMPLETED,
            result={
                "operation_id": operation_id,
                "restored_exact": restored,
                "reacquired": not restored,
                "evidence_version_id": VERSION_ID,
                "manifest_version": 4 if restored else 5,
                "seal_status": "sealed",
            },
        )
        return self.record

    def commit_verified_seal(self, operation_id, *, items, examiner):
        raise AssertionError("recovery must not call Add/Seal finalizer")

    def get_incomplete(self, case_id):
        return self.record


def _command(action: CustodyAction) -> ObjectCustodyCommand:
    return ObjectCustodyCommand(
        action=action, case_id=CASE_ID, evidence_object_id=OBJECT_ID,
        actor_user_id=ACTOR_ID, actor_service_identity_id=None,
        reason="operator recovery", reauth_audit_event_id=REAUTH_ID,
        idempotency_key=f"intent-{action.value.lower()}",
    )


def _object(original: bytes):
    return {
        "evidence_object_id": OBJECT_ID, "display_path": "evidence/disk.raw",
        "status": "violated", "current_version_id": VERSION_ID,
        "current_sha256": _sha(original), "current_bytes": len(original),
    }


def _operation(monkeypatch, tmp_path, original: bytes):
    repo = RecoveryRepository()
    immutable = {"value": True}
    monkeypatch.setattr(
        "sift_core.evidence_chain.get_immutable_flag_fd", lambda _fd: immutable["value"]
    )

    def set_flag(_fd, enabled):
        immutable["value"] = enabled
        return True

    monkeypatch.setattr("sift_core.evidence_chain.set_immutable_flag_fd", set_flag)
    op = RecoveryCustodyOperation(
        repo, lambda _case_id: tmp_path, lambda _case_id, _object_id: _object(original),
        service_user=pwd.getpwuid(os.getuid()).pw_name,
    )
    return op, repo, immutable


def test_exact_restore_can_begin_while_original_file_is_missing(monkeypatch, tmp_path):
    original = b"original evidence"
    (tmp_path / "evidence").mkdir()
    op, repo, immutable = _operation(monkeypatch, tmp_path, original)

    begun = op.begin(_command(CustodyAction.RESTORE_EXACT), examiner="examiner")

    assert begun["ready_for_replacement"] is True
    assert repo.record is not None
    prepared_facts = repo.record.prepared_facts
    assert prepared_facts is not None
    assert prepared_facts["item"]["observed_at_begin"] == {"present": False}
    assert immutable["value"] is True


def test_changed_violation_can_begin_replace_and_complete_as_new_version(monkeypatch, tmp_path):
    original = b"original evidence"
    replacement = b"legitimate reacquisition"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "disk.raw"
    target.write_bytes(b"already drifted")
    target.chmod(0o644)
    op, repo, immutable = _operation(monkeypatch, tmp_path, original)

    op.begin(_command(CustodyAction.REPLACE_REACQUIRE), examiner="examiner")
    assert immutable["value"] is False
    target.write_bytes(replacement)
    assert repo.record is not None
    result = op.complete(
        repo.record.operation_id, actor_user_id=ACTOR_ID,
        completion_reauth_audit_event_id=COMPLETE_REAUTH_ID, examiner="examiner",
    )

    assert result["reacquired"] is True
    assert immutable["value"] is True
    assert repo.calls[-3:] == [
        "authorize_completion",
        "advance:FILESYSTEM_APPLYING:FILESYSTEM_VERIFIED",
        "commit_recovery",
    ]


def test_restore_rejects_non_exact_bytes_and_keeps_gate_recoverable(monkeypatch, tmp_path):
    original = b"original evidence"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    op, repo, _immutable = _operation(monkeypatch, tmp_path, original)
    op.begin(_command(CustodyAction.RESTORE_EXACT), examiner="examiner")
    target = evidence / "disk.raw"
    target.write_bytes(b"not original")
    target.chmod(0o644)

    with pytest.raises(CustodyOperationError, match="restore_hash_mismatch"):
        assert repo.record is not None
        op.complete(
            repo.record.operation_id, actor_user_id=ACTOR_ID,
            completion_reauth_audit_event_id=COMPLETE_REAUTH_ID, examiner="examiner",
        )

    assert repo.record is not None
    assert repo.record.phase == CustodyOperationPhase.FAILED_RECOVERABLE
    assert "commit_recovery" not in repo.calls


@pytest.mark.parametrize("failure_phase", ["applying", "verified"])
def test_fresh_completion_receipt_recovers_after_authorized_failure(
    monkeypatch, tmp_path, failure_phase
):
    original = b"original evidence"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "disk.raw"
    target.write_bytes(b"wrong bytes" if failure_phase == "applying" else original)
    target.chmod(0o644)
    op, repo, _immutable = _operation(monkeypatch, tmp_path, original)
    op.begin(_command(CustodyAction.RESTORE_EXACT), examiner="examiner")
    assert repo.record is not None
    operation_id = repo.record.operation_id
    if failure_phase == "verified":
        repo.fail_commit_once = True

    expected_error = (
        "restore_hash_mismatch"
        if failure_phase == "applying"
        else "recovery_complete_failed"
    )
    with pytest.raises(Exception, match=expected_error):
        op.complete(
            operation_id, actor_user_id=ACTOR_ID,
            completion_reauth_audit_event_id=COMPLETE_REAUTH_ID, examiner="examiner",
        )
    assert repo.record is not None
    assert repo.record.phase == CustodyOperationPhase.FAILED_RECOVERABLE
    assert repo.record.failed_from_phase == (
        CustodyOperationPhase.FILESYSTEM_APPLYING
        if failure_phase == "applying"
        else CustodyOperationPhase.FILESYSTEM_VERIFIED
    )

    target.write_bytes(original)
    result = op.complete(
        operation_id, actor_user_id=ACTOR_ID,
        completion_reauth_audit_event_id=RETRY_REAUTH_ID, examiner="examiner",
    )
    assert result["restored_exact"] is True
    assert repo.record is not None
    assert repo.record.phase == CustodyOperationPhase.COMPLETED
    assert repo.calls.count("commit_recovery") == (1 if failure_phase == "applying" else 2)

    with pytest.raises(CustodyOperationError, match="receipt_already_used"):
        repo.authorize_recovery_completion(
            operation_id, actor_user_id=ACTOR_ID,
            completion_reauth_audit_event_id=COMPLETE_REAUTH_ID,
        )
