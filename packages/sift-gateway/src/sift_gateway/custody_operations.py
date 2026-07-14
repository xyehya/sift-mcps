"""Durable operator-owned evidence custody operation seams.

This module deliberately has no MCP registration.  It is used only by the
human Portal service.  Postgres owns operation identity and phase transitions;
the filesystem adapter owns the narrowly-scoped Local Immutable posture.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pwd
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from sift_core.evidence_storage import (
    StorageAuthorityError,
    StorageProfile,
    external_storage_facts,
)

logger = logging.getLogger(__name__)

# systemd supplies one INVOCATION_ID to every process in a service activation and
# rotates it on restart.  Non-systemd development gets a process-lifetime nonce:
# it is stable for duplicate requests in this process but can never impersonate a
# previous process after a hard interruption.
_RUNNER_INSTANCE_ID = os.environ.get("INVOCATION_ID") or f"process:{uuid.uuid4()}"


class CustodyOperationPhase(StrEnum):
    REQUESTED = "REQUESTED"
    GATE_BLOCKED = "GATE_BLOCKED"
    FILESYSTEM_APPLYING = "FILESYSTEM_APPLYING"
    FILESYSTEM_VERIFIED = "FILESYSTEM_VERIFIED"
    LEDGER_COMMITTED = "LEDGER_COMMITTED"
    COMPLETED = "COMPLETED"
    FAILED_RECOVERABLE = "FAILED_RECOVERABLE"


class CustodyAction(StrEnum):
    """Closed, server-selected vocabulary for durable custody operations.

    Values are cumulative: later packets may implement an action-specific
    finalizer, but must not invent another operation runner or accept a free-form
    action from a Portal request.
    """

    ADD_SEAL = "ADD_SEAL"
    REPLACE_REACQUIRE = "REPLACE_REACQUIRE"
    RESTORE_EXACT = "RESTORE_EXACT"
    IGNORE = "IGNORE"
    DELETE_STRAY = "DELETE_STRAY"
    RETIRE = "RETIRE"


class RecoveryAction(StrEnum):
    """Recovery choices Ticket 4 may delegate to Ticket 3 authority."""

    REPLACE_REACQUIRE = CustodyAction.REPLACE_REACQUIRE
    RESTORE_EXACT = CustodyAction.RESTORE_EXACT


RESUMABLE_SEAL_PHASES = (
    CustodyOperationPhase.GATE_BLOCKED,
    CustodyOperationPhase.FILESYSTEM_APPLYING,
    CustodyOperationPhase.FILESYSTEM_VERIFIED,
    CustodyOperationPhase.FAILED_RECOVERABLE,
)


@dataclass(frozen=True)
class SealCommand:
    case_id: str
    file_specs: tuple[dict[str, str | None], ...]
    actor_user_id: str | None
    actor_service_identity_id: str | None
    reason: str
    reauth_audit_event_id: str
    idempotency_key: str
    storage_profile: StorageProfile = StorageProfile.LOCAL_IMMUTABLE
    schema_version: int = 3
    runner_instance_id: str = _RUNNER_INSTANCE_ID
    resume_reauth_audit_event_id: str | None = None

    @property
    def action(self) -> CustodyAction:
        return CustodyAction.ADD_SEAL

    def operation_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "action": self.action,
            "files": list(self.file_specs),
        }
        if self.schema_version == 3:
            payload["storage_profile"] = self.storage_profile.value
        elif (
            self.schema_version != 1
            or self.storage_profile is not StorageProfile.LOCAL_IMMUTABLE
        ):
            raise ValueError("unsupported seal command schema")
        return payload


@dataclass(frozen=True)
class ObjectCustodyCommand:
    """Typed command for one server-resolved Evidence Object.

    Portal request bodies must never populate ``action`` directly. Route/service
    code selects the enum member for its fixed operator workflow.
    """

    action: CustodyAction
    case_id: str
    evidence_object_id: str
    actor_user_id: str | None
    actor_service_identity_id: str | None
    reason: str
    reauth_audit_event_id: str
    idempotency_key: str
    runner_instance_id: str = _RUNNER_INSTANCE_ID
    resume_reauth_audit_event_id: str | None = None

    def __post_init__(self) -> None:
        if self.action is CustodyAction.ADD_SEAL:
            raise ValueError("ADD_SEAL requires SealCommand")

    def operation_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "action": self.action.value,
            "evidence_object_id": self.evidence_object_id,
        }


class CustodyOperationCommandProtocol(Protocol):
    """Typed internal command accepted by the shared operation repository."""

    @property
    def case_id(self) -> str: ...

    @property
    def actor_user_id(self) -> str | None: ...

    @property
    def actor_service_identity_id(self) -> str | None: ...

    @property
    def reason(self) -> str: ...

    @property
    def reauth_audit_event_id(self) -> str: ...

    @property
    def idempotency_key(self) -> str: ...

    @property
    def runner_instance_id(self) -> str: ...

    @property
    def resume_reauth_audit_event_id(self) -> str | None: ...

    @property
    def action(self) -> CustodyAction: ...

    def operation_payload(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class RecoverySelection:
    """Path-free recovery selection passed across the Ticket 4/Ticket 3 seam."""

    case_id: str
    evidence_object_id: str
    action: RecoveryAction

    def __post_init__(self) -> None:
        if not isinstance(self.action, RecoveryAction):
            raise ValueError("recovery action must be server-selected")


@dataclass(frozen=True)
class AuthorizedRecoveryIntent:
    """Server-created, scoped authority for one operator recovery choice.

    The Portal service creates this only after fresh step-up authentication. It
    deliberately carries no password, filesystem path, raw command, or browser
    receipt; Postgres consumes the single-use audit capability by identifier.
    """

    selection: RecoverySelection
    actor_user_id: str
    reason: str
    reauth_audit_event_id: str
    idempotency_key: str

    def __post_init__(self) -> None:
        normalized_reason = self.reason.strip()
        if not 1 <= len(normalized_reason) <= 1000:
            raise ValueError("recovery reason must contain 1 to 1000 characters")
        if not 1 <= len(self.idempotency_key) <= 128:
            raise ValueError(
                "recovery idempotency key must contain 1 to 128 characters"
            )
        for name, value in (
            ("case_id", self.selection.case_id),
            ("evidence_object_id", self.selection.evidence_object_id),
            ("actor_user_id", self.actor_user_id),
            ("reauth_audit_event_id", self.reauth_audit_event_id),
        ):
            try:
                uuid.UUID(value)
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be a UUID") from exc
        object.__setattr__(self, "reason", normalized_reason)


class RecoveryAuthorityProtocol(Protocol):
    """Operator-only recovery authority; it accepts only a scoped intent.

    Password verification and authorization-intent creation stay in the Portal
    service. Action-specific finalization stays inside the implementation.
    """

    def execute_authorized_recovery(
        self, intent: AuthorizedRecoveryIntent, *, examiner: str
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CustodyOperationRecord:
    operation_id: str
    case_id: str
    action: str
    phase: CustodyOperationPhase
    idempotency_key: str
    request_digest: str
    failed_from_phase: CustodyOperationPhase | None
    failure_code: str | None
    result: dict[str, Any] | None
    runner_instance_id: str | None = None
    prepared_facts: dict[str, Any] | None = None
    verified_facts: dict[str, Any] | None = None


class CustodyOperationRepositoryProtocol(Protocol):
    def begin_or_resume(
        self, command: CustodyOperationCommandProtocol
    ) -> CustodyOperationRecord: ...

    def advance(
        self,
        operation_id: str,
        expected: CustodyOperationPhase,
        target: CustodyOperationPhase,
        *,
        facts: dict[str, Any] | None = None,
    ) -> CustodyOperationRecord: ...

    def fail(
        self,
        operation_id: str,
        expected: CustodyOperationPhase,
        failure_code: str,
    ) -> CustodyOperationRecord: ...

    def commit_verified_seal(
        self,
        operation_id: str,
        *,
        items: list[dict[str, Any]],
        examiner: str,
    ) -> CustodyOperationRecord: ...

    def authorize_recovery_completion(
        self,
        operation_id: str,
        *,
        actor_user_id: str,
        completion_reauth_audit_event_id: str,
    ) -> CustodyOperationRecord: ...

    def commit_verified_recovery(
        self,
        operation_id: str,
        *,
        item: dict[str, Any],
        examiner: str,
    ) -> CustodyOperationRecord: ...

    def commit_verified_disposition(
        self,
        operation_id: str,
        *,
        item: dict[str, Any],
        examiner: str,
    ) -> CustodyOperationRecord: ...

    def resume_disposition(
        self,
        operation_id: str,
        *,
        actor_user_id: str,
        resume_reauth_audit_event_id: str,
    ) -> CustodyOperationRecord: ...

    def get_incomplete(self, case_id: str) -> CustodyOperationRecord | None: ...


class LocalImmutablePostureProtocol(Protocol):
    def prepare(self, case_dir: Path, paths: list[str]) -> PostureBatch: ...

    def apply(self, batch: PostureBatch) -> None: ...

    def verify(self, batch: PostureBatch) -> list[dict[str, Any]]: ...

    def close(self, batch: PostureBatch) -> None: ...


@dataclass
class PinnedEvidenceFile:
    path: str
    fd: int
    before: dict[str, Any]


@dataclass
class PostureBatch:
    root_fd: int
    files: list[PinnedEvidenceFile]


class CustodyOperationError(Exception):
    def __init__(self, reason: str, *, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


def _jsonb(value: Any) -> Any:
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover - deployment dependency
        return json.dumps(value)
    return Jsonb(value)


def _request_digest(command: CustodyOperationCommandProtocol) -> str:
    material = {
        "case_id": command.case_id,
        "action": command.action.value,
        "actor_user_id": command.actor_user_id,
        "actor_service_identity_id": command.actor_service_identity_id,
        "reason": command.reason,
        "reauth_audit_event_id": command.reauth_audit_event_id,
        "idempotency_key": command.idempotency_key,
        "payload": command.operation_payload(),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _record(row: Any) -> CustodyOperationRecord:
    if not row:
        raise RuntimeError("custody_operation_missing")
    failed_from = CustodyOperationPhase(str(row[6])) if row[6] else None
    result = row[8] if isinstance(row[8], dict) else None
    return CustodyOperationRecord(
        operation_id=str(row[0]),
        case_id=str(row[1]),
        action=str(row[2]),
        phase=CustodyOperationPhase(str(row[3])),
        idempotency_key=str(row[4]),
        request_digest=str(row[5]),
        failed_from_phase=failed_from,
        failure_code=str(row[7]) if row[7] else None,
        result=result,
        runner_instance_id=str(row[9]) if len(row) > 9 and row[9] else None,
        prepared_facts=row[10] if len(row) > 10 and isinstance(row[10], dict) else None,
        verified_facts=row[11] if len(row) > 11 and isinstance(row[11], dict) else None,
    )


_OP_COLUMNS = """
  id::text, case_id::text, action, phase, idempotency_key, request_digest,
  failed_from_phase, failure_code, result
  , runner_instance_id, prepared_facts, verified_facts
"""


class CustodyOperationRepository:
    """Typed service-role wrapper over the migrated custody-operation RPCs."""

    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect

    def begin_or_resume(
        self, command: CustodyOperationCommandProtocol
    ) -> CustodyOperationRecord:
        try:
            action = CustodyAction(command.action)
        except (TypeError, ValueError) as exc:
            raise CustodyOperationError(
                "custody_action_unknown", http_status=400
            ) from exc
        with self._connect() as conn:
            with conn.cursor() as cur:
                if isinstance(command, SealCommand) and command.schema_version == 3:
                    cur.execute(
                        f"""select {_OP_COLUMNS}
                             from app.custody_operation_begin_or_resume_storage_v3(
                               %s,%s,%s,%s,%s,%s,%s,%s,%s
                             )""",
                        (
                            command.case_id,
                            _jsonb(command.operation_payload()),
                            _request_digest(command),
                            command.reason,
                            command.reauth_audit_event_id,
                            command.idempotency_key,
                            command.actor_user_id,
                            command.runner_instance_id,
                            command.resume_reauth_audit_event_id,
                        ),
                    )
                    row = cur.fetchone()
                    conn.commit()
                    return _record(row)
                cur.execute(
                    f"""
                    select {_OP_COLUMNS}
                    from app.custody_operation_begin_or_resume(
                      %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        command.case_id,
                        action.value,
                        _jsonb(command.operation_payload()),
                        _request_digest(command),
                        command.reason,
                        command.reauth_audit_event_id,
                        command.idempotency_key,
                        command.actor_user_id,
                        command.actor_service_identity_id,
                        command.runner_instance_id,
                        command.resume_reauth_audit_event_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def advance(
        self,
        operation_id: str,
        expected: CustodyOperationPhase,
        target: CustodyOperationPhase,
        *,
        facts: dict[str, Any] | None = None,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_advance(%s, %s, %s, %s, %s)""",
                    (
                        operation_id,
                        expected.value,
                        target.value,
                        _jsonb(facts or {}),
                        _RUNNER_INSTANCE_ID,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def fail(
        self,
        operation_id: str,
        expected: CustodyOperationPhase,
        failure_code: str,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_fail(%s, %s, %s, %s)""",
                    (
                        operation_id,
                        expected.value,
                        failure_code[:96],
                        _RUNNER_INSTANCE_ID,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def commit_verified_seal(
        self,
        operation_id: str,
        *,
        items: list[dict[str, Any]],
        examiner: str,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_commit_verified_seal_storage_v3(%s, %s, %s, %s)""",
                    (operation_id, _jsonb(items), examiner, _RUNNER_INSTANCE_ID),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def authorize_recovery_completion(
        self,
        operation_id: str,
        *,
        actor_user_id: str,
        completion_reauth_audit_event_id: str,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_authorize_recovery_completion(
                           %s, %s, %s, %s
                         )""",
                    (
                        operation_id,
                        actor_user_id,
                        completion_reauth_audit_event_id,
                        _RUNNER_INSTANCE_ID,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def commit_verified_recovery(
        self,
        operation_id: str,
        *,
        item: dict[str, Any],
        examiner: str,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_commit_verified_recovery(
                           %s, %s, %s, %s
                         )""",
                    (operation_id, _jsonb(item), examiner, _RUNNER_INSTANCE_ID),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def commit_verified_disposition(
        self,
        operation_id: str,
        *,
        item: dict[str, Any],
        examiner: str,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_commit_verified_disposition(
                           %s, %s, %s, %s
                         )""",
                    (operation_id, _jsonb(item), examiner, _RUNNER_INSTANCE_ID),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def resume_disposition(
        self,
        operation_id: str,
        *,
        actor_user_id: str,
        resume_reauth_audit_event_id: str,
    ) -> CustodyOperationRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""select {_OP_COLUMNS}
                         from app.custody_operation_resume_disposition(%s,%s,%s,%s)""",
                    (
                        operation_id,
                        actor_user_id,
                        resume_reauth_audit_event_id,
                        _RUNNER_INSTANCE_ID,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return _record(row)

    def get_incomplete(self, case_id: str) -> CustodyOperationRecord | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    select {_OP_COLUMNS}
                    from app.custody_operations
                    where case_id = %s and phase <> 'COMPLETED'
                    order by created_at desc
                    limit 1
                    """,
                    (case_id,),
                )
                row = cur.fetchone()
        return _record(row) if row else None


class LocalImmutablePostureAdapter:
    """Prevalidate, hash, harden, and verify the same pinned descriptors."""

    def __init__(self, *, service_user: str | None = None) -> None:
        self._service_user = service_user or os.environ.get(
            "SIFT_GATEWAY_SERVICE_USER", "sift-service"
        )

    @staticmethod
    def _hash_fd(fd: int) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        os.lseek(fd, 0, os.SEEK_SET)
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        return "sha256:" + digest.hexdigest(), size

    def prepare(self, case_dir: Path, paths: list[str]) -> PostureBatch:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise CustodyOperationError("o_nofollow_required", http_status=500)
        expected_uid = pwd.getpwnam(self._service_user).pw_uid
        root_fd = os.open(
            case_dir / "evidence",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow,
        )
        batch = PostureBatch(root_fd=root_fd, files=[])
        try:
            # Open and validate every direct entry before mutating any inode.
            for rel_path in paths:
                parts = Path(rel_path).parts
                if (
                    len(parts) != 2
                    or parts[0] != "evidence"
                    or parts[1] in ("", ".", "..")
                ):
                    raise CustodyOperationError(
                        "invalid_evidence_path", http_status=400
                    )
                fd = os.open(
                    parts[1],
                    os.O_RDONLY | os.O_CLOEXEC | nofollow,
                    dir_fd=root_fd,
                )
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                        raise CustodyOperationError(
                            "evidence_regular_single_link_required", http_status=400
                        )
                    if st.st_uid != expected_uid:
                        raise CustodyOperationError(
                            "evidence_service_owner_required", http_status=409
                        )
                    if stat.S_IMODE(st.st_mode) != 0o644:
                        raise CustodyOperationError(
                            "evidence_mode_0644_required", http_status=409
                        )
                    sha256, size = self._hash_fd(fd)
                    batch.files.append(
                        PinnedEvidenceFile(
                            rel_path,
                            fd,
                            {
                                "path": rel_path,
                                "sha256": sha256,
                                "bytes": size,
                                "st_dev": st.st_dev,
                                "st_ino": st.st_ino,
                                "st_nlink": st.st_nlink,
                            },
                        )
                    )
                except Exception:
                    os.close(fd)
                    raise

            return batch
        except Exception:
            self.close(batch)
            raise

    def apply(self, batch: PostureBatch) -> None:
        from sift_core.evidence_chain import set_immutable_flag_fd

        for item in batch.files:
            if not set_immutable_flag_fd(item.fd, True):
                raise CustodyOperationError(
                    "evidence_immutability_failed", http_status=500
                )

    def verify(self, batch: PostureBatch) -> list[dict[str, Any]]:
        from sift_core.evidence_chain import get_immutable_flag_fd

        receipts: list[dict[str, Any]] = []
        expected_uid = pwd.getpwnam(self._service_user).pw_uid
        for item in batch.files:
            st = os.fstat(item.fd)
            immutable = get_immutable_flag_fd(item.fd)
            sha256, size = self._hash_fd(item.fd)
            if (
                st.st_dev != item.before["st_dev"]
                or st.st_ino != item.before["st_ino"]
                or st.st_nlink != 1
                or st.st_uid != expected_uid
                or stat.S_IMODE(st.st_mode) != 0o644
                or immutable is not True
                or sha256 != item.before["sha256"]
                or size != item.before["bytes"]
            ):
                raise CustodyOperationError(
                    "evidence_posture_verification_failed", http_status=409
                )
            receipts.append(
                {
                    **item.before,
                    "owner": self._service_user,
                    "mode": "0644",
                    "immutable": True,
                    "st_mtime_ns": st.st_mtime_ns,
                    "st_ctime_ns": st.st_ctime_ns,
                }
            )
        return receipts

    def close(self, batch: PostureBatch) -> None:
        for item in batch.files:
            try:
                os.close(item.fd)
            except OSError:
                pass
        batch.files.clear()
        try:
            os.close(batch.root_fd)
        except OSError:
            pass


class ExternalReadOnlyPostureAdapter:
    """Full-hash external evidence without invoking local mutation primitives."""

    @staticmethod
    def _hash_fd(fd: int) -> tuple[str, int]:
        return LocalImmutablePostureAdapter._hash_fd(fd)

    def prepare(self, case_dir: Path, paths: list[str]) -> PostureBatch:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise CustodyOperationError("o_nofollow_required", http_status=500)
        root_fd = os.open(
            case_dir / "evidence",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow,
        )
        batch = PostureBatch(root_fd=root_fd, files=[])
        try:
            root_facts = external_storage_facts(root_fd)
            for rel_path in paths:
                parts = Path(rel_path).parts
                if (
                    len(parts) != 2
                    or parts[0] != "evidence"
                    or parts[1] in ("", ".", "..")
                ):
                    raise CustodyOperationError(
                        "invalid_evidence_path", http_status=400
                    )
                fd = os.open(
                    parts[1], os.O_RDONLY | os.O_CLOEXEC | nofollow, dir_fd=root_fd
                )
                try:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        raise CustodyOperationError(
                            "evidence_regular_single_link_required", http_status=400
                        )
                    entry_facts = external_storage_facts(fd)
                    if entry_facts != root_facts:
                        raise CustodyOperationError(
                            "external_nested_mount_forbidden", http_status=409
                        )
                    sha256, size = self._hash_fd(fd)
                    after = os.fstat(fd)
                    if (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                        before.st_nlink,
                    ) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                        after.st_nlink,
                    ) or external_storage_facts(fd) != root_facts:
                        raise CustodyOperationError(
                            "external_evidence_changed_while_hashing", http_status=409
                        )
                    batch.files.append(
                        PinnedEvidenceFile(
                            rel_path,
                            fd,
                            {
                                "path": rel_path,
                                "sha256": sha256,
                                "bytes": size,
                                "st_dev": after.st_dev,
                                "st_ino": after.st_ino,
                                "st_mtime_ns": after.st_mtime_ns,
                                "st_ctime_ns": after.st_ctime_ns,
                                "st_nlink": after.st_nlink,
                                "storage_profile": StorageProfile.EXTERNALLY_READ_ONLY.value,
                                "storage_source_identity": root_facts.source_identity,
                                "mount_instance_identity": root_facts.mount_instance_identity,
                                "read_only": True,
                            },
                        )
                    )
                except Exception:
                    os.close(fd)
                    raise
            return batch
        except (StorageAuthorityError, OSError) as exc:
            self.close(batch)
            raise CustodyOperationError(
                "external_storage_unavailable", http_status=409
            ) from exc
        except Exception:
            self.close(batch)
            raise

    def apply(self, batch: PostureBatch) -> None:
        # Externally read-only posture is observed, never applied locally.
        if not batch.files:
            raise CustodyOperationError("external_evidence_required", http_status=409)

    def verify(self, batch: PostureBatch) -> list[dict[str, Any]]:
        receipts: list[dict[str, Any]] = []
        try:
            root_facts = external_storage_facts(batch.root_fd)
            for item in batch.files:
                st = os.fstat(item.fd)
                sha256, size = self._hash_fd(item.fd)
                facts = external_storage_facts(item.fd)
                if (
                    facts != root_facts
                    or item.before.get("storage_source_identity")
                    != facts.source_identity
                    or item.before.get("mount_instance_identity")
                    != facts.mount_instance_identity
                    or st.st_dev != item.before.get("st_dev")
                    or st.st_ino != item.before.get("st_ino")
                    or st.st_nlink != 1
                    or sha256 != item.before.get("sha256")
                    or size != item.before.get("bytes")
                ):
                    raise CustodyOperationError(
                        "external_evidence_posture_verification_failed", http_status=409
                    )
                receipts.append({**item.before, "read_only": True})
            return receipts
        except StorageAuthorityError as exc:
            raise CustodyOperationError(
                "external_storage_unavailable", http_status=409
            ) from exc

    def close(self, batch: PostureBatch) -> None:
        for item in batch.files:
            try:
                os.close(item.fd)
            except OSError:
                pass
        batch.files.clear()
        try:
            os.close(batch.root_fd)
        except OSError:
            pass


class SealCustodyOperation:
    """Gate-first orchestration over frozen repository and posture interfaces."""

    def __init__(
        self,
        repository: CustodyOperationRepositoryProtocol,
        posture: LocalImmutablePostureProtocol,
        case_dir: Callable[[str], Path | None],
        object_for_path: Callable[[str, str], dict[str, Any]],
    ) -> None:
        self._repository = repository
        self._posture = posture
        self._case_dir = case_dir
        self._object_for_path = object_for_path

    def execute(self, command: SealCommand, *, examiner: str) -> dict[str, Any]:
        try:
            operation = self._repository.begin_or_resume(command)
        except Exception as exc:
            sqlstate = getattr(exc, "sqlstate", None)
            if sqlstate == "P4231":
                raise CustodyOperationError(
                    "idempotency_key_reused", http_status=409
                ) from exc
            if sqlstate == "28000":
                raise CustodyOperationError(
                    "seal_reauth_scope_mismatch", http_status=403
                ) from exc
            if sqlstate == "55000":
                raise CustodyOperationError(
                    "custody_violation_requires_recovery", http_status=409
                ) from exc
            if sqlstate in ("23505", "P4232"):
                raise CustodyOperationError(
                    "custody_operation_active", http_status=409
                ) from exc
            raise CustodyOperationError(
                "custody_operation_unavailable", http_status=503
            ) from exc
        if operation.phase == CustodyOperationPhase.COMPLETED:
            return dict(operation.result or {})
        current = CustodyOperationPhase.GATE_BLOCKED
        batch: PostureBatch | None = None
        try:
            case_dir = self._case_dir(command.case_id)
            if case_dir is None:
                raise CustodyOperationError(
                    "case_artifact_path_unavailable", http_status=404
                )
            paths = [str(spec["path"]) for spec in command.file_specs]
            batch = self._posture.prepare(case_dir, paths)
            specs = {str(spec["path"]): spec for spec in command.file_specs}
            prepared_items: list[dict[str, Any]] = []
            for pinned in batch.files:
                obj = self._object_for_path(command.case_id, pinned.path)
                if obj.get("status") not in ("detected", "registered"):
                    raise CustodyOperationError("evidence_not_pending", http_status=409)
                spec = specs[pinned.path]
                prepared_items.append(
                    {
                        "evidence_object_id": str(obj["evidence_object_id"]),
                        "display_path": pinned.path,
                        "display_name": Path(pinned.path).name,
                        "description": spec.get("description"),
                        "source": spec.get("source"),
                        **pinned.before,
                    }
                )
            operation = self._repository.advance(
                operation.operation_id,
                CustodyOperationPhase.GATE_BLOCKED,
                CustodyOperationPhase.FILESYSTEM_APPLYING,
                facts={"items": prepared_items},
            )
            current = operation.phase
            self._posture.apply(batch)
            receipts = self._posture.verify(batch)
            items: list[dict[str, Any]] = []
            prepared_by_path = {str(item["path"]): item for item in prepared_items}
            for receipt in receipts:
                path = str(receipt["path"])
                prepared = prepared_by_path.get(path)
                if prepared is None:
                    raise CustodyOperationError(
                        "posture_receipt_missing", http_status=500
                    )
                items.append({**prepared, **receipt})
            operation = self._repository.advance(
                operation.operation_id,
                CustodyOperationPhase.FILESYSTEM_APPLYING,
                CustodyOperationPhase.FILESYSTEM_VERIFIED,
                facts={"items": items},
            )
            current = operation.phase
            operation = self._repository.commit_verified_seal(
                operation.operation_id, items=items, examiner=examiner
            )
            return dict(operation.result or {})
        except Exception as exc:
            if getattr(exc, "sqlstate", None) in ("23505", "40001", "P4231"):
                exc = CustodyOperationError(
                    "custody_operation_conflict", http_status=409
                )
            elif hasattr(exc, "reason") and hasattr(exc, "http_status"):
                error_state = vars(exc)
                exc = CustodyOperationError(
                    str(error_state["reason"]),
                    http_status=int(error_state["http_status"]),
                )
            failure = (
                exc.reason
                if isinstance(exc, CustodyOperationError)
                else type(exc).__name__
            )
            try:
                self._repository.fail(operation.operation_id, current, failure)
            except Exception as persist_exc:
                logger.warning(
                    "custody failure state persistence failed operation_id=%s phase=%s code=%s db_code=%s",
                    operation.operation_id,
                    current.value,
                    failure[:96],
                    getattr(persist_exc, "sqlstate", "unknown"),
                )
            if isinstance(exc, CustodyOperationError):
                raise
            raise CustodyOperationError(
                "seal_failed_recoverable", http_status=500
            ) from exc
        finally:
            if batch is not None:
                self._posture.close(batch)


class RecoveryCustodyOperation:
    """Durable gate-first Replace/Reacquire and exact Restore orchestration.

    Begin and complete are deliberately separate operator ceremonies.  Begin
    commits ``GATE_BLOCKED`` and the prepared original-version facts before it
    clears Local Immutable protection.  Complete reopens the server-resolved
    object, hashes all bytes, restores protection, verifies the same descriptor,
    and only then invokes the action-specific Postgres finalizer.
    """

    def __init__(
        self,
        repository: CustodyOperationRepositoryProtocol,
        case_dir: Callable[[str], Path | None],
        object_for_id: Callable[[str, str], dict[str, Any]],
        *,
        service_user: str | None = None,
    ) -> None:
        self._repository = repository
        self._case_dir = case_dir
        self._object_for_id = object_for_id
        self._service_user = service_user or os.environ.get(
            "SIFT_GATEWAY_SERVICE_USER", "sift-service"
        )

    @staticmethod
    def _validate_relative_path(value: str) -> tuple[str, str]:
        parts = Path(value).parts
        if len(parts) != 2 or parts[0] != "evidence" or parts[1] in ("", ".", ".."):
            raise CustodyOperationError("invalid_evidence_path", http_status=409)
        return parts[0], parts[1]

    def _open_object(self, case_id: str, display_path: str) -> tuple[int, int]:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise CustodyOperationError("o_nofollow_required", http_status=500)
        _prefix, name = self._validate_relative_path(display_path)
        case_dir = self._case_dir(case_id)
        if case_dir is None:
            raise CustodyOperationError(
                "case_artifact_path_unavailable", http_status=404
            )
        root_fd = os.open(
            case_dir / "evidence",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow,
        )
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | nofollow, dir_fd=root_fd)
        except Exception:
            os.close(root_fd)
            raise
        return root_fd, fd

    def _verified_descriptor_facts(
        self, case_id: str, evidence_object_id: str
    ) -> tuple[dict[str, Any], int, int]:
        from sift_core.evidence_chain import get_immutable_flag_fd

        obj = self._object_for_id(case_id, evidence_object_id)
        display_path = str(obj.get("display_path") or "")
        root_fd, fd = self._open_object(case_id, display_path)
        try:
            st = os.fstat(fd)
            expected_uid = pwd.getpwnam(self._service_user).pw_uid
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_nlink != 1
                or st.st_uid != expected_uid
                or stat.S_IMODE(st.st_mode) != 0o644
            ):
                raise CustodyOperationError(
                    "evidence_recovery_posture_invalid", http_status=409
                )
            sha256, size = LocalImmutablePostureAdapter._hash_fd(fd)
            return (
                {
                    "evidence_object_id": evidence_object_id,
                    "display_path": display_path,
                    "path": display_path,
                    "sha256": sha256,
                    "bytes": size,
                    "owner": self._service_user,
                    "mode": "0644",
                    "immutable": get_immutable_flag_fd(fd),
                    "st_dev": st.st_dev,
                    "st_ino": st.st_ino,
                    "st_nlink": st.st_nlink,
                    "st_mtime_ns": st.st_mtime_ns,
                    "st_ctime_ns": st.st_ctime_ns,
                },
                root_fd,
                fd,
            )
        except Exception:
            os.close(fd)
            os.close(root_fd)
            raise

    def begin(self, command: ObjectCustodyCommand, *, examiner: str) -> dict[str, Any]:
        del examiner
        if command.action not in (
            CustodyAction.REPLACE_REACQUIRE,
            CustodyAction.RESTORE_EXACT,
        ):
            raise CustodyOperationError("recovery_action_required", http_status=400)
        operation = self._repository.begin_or_resume(command)
        if operation.phase == CustodyOperationPhase.COMPLETED:
            return dict(operation.result or {})
        if operation.phase != CustodyOperationPhase.GATE_BLOCKED:
            raise CustodyOperationError(
                "custody_operation_not_resumable", http_status=409
            )
        current = CustodyOperationPhase.GATE_BLOCKED
        root_fd: int | None = None
        fd: int | None = None
        try:
            obj = self._object_for_id(command.case_id, command.evidence_object_id)
            if str(obj.get("status")) not in ("sealed", "violated"):
                raise CustodyOperationError(
                    "recovery_object_not_admitted", http_status=409
                )
            expected_sha256 = str(obj.get("current_sha256") or "")
            current_version_id = str(obj.get("current_version_id") or "")
            if not expected_sha256.startswith("sha256:") or not current_version_id:
                raise CustodyOperationError(
                    "recovery_original_version_missing", http_status=409
                )
            # Recovery may start after bytes are missing, changed, or already
            # have posture drift.  DB original-version facts authorize the
            # object; mounted bytes are only an observation at this phase.
            display_path = str(obj.get("display_path") or "")
            observed: dict[str, Any]
            try:
                from sift_core.evidence_chain import get_immutable_flag_fd

                root_fd, fd = self._open_object(command.case_id, display_path)
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise CustodyOperationError(
                        "evidence_regular_single_link_required", http_status=409
                    )
                observed_sha256, observed_bytes = LocalImmutablePostureAdapter._hash_fd(
                    fd
                )
                observed = {
                    "present": True,
                    "sha256": observed_sha256,
                    "bytes": observed_bytes,
                    "st_dev": st.st_dev,
                    "st_ino": st.st_ino,
                    "st_nlink": st.st_nlink,
                    "uid": st.st_uid,
                    "mode": f"{stat.S_IMODE(st.st_mode):04o}",
                    "immutable": get_immutable_flag_fd(fd),
                }
            except FileNotFoundError:
                observed = {"present": False}
                root_fd = None
                fd = None
            prepared = {
                "evidence_object_id": command.evidence_object_id,
                "display_path": display_path,
                "path": display_path,
                "original_sha256": expected_sha256,
                "original_bytes": obj.get("current_bytes"),
                "original_version_id": current_version_id,
                "observed_at_begin": observed,
            }
            operation = self._repository.advance(
                operation.operation_id,
                CustodyOperationPhase.GATE_BLOCKED,
                CustodyOperationPhase.FILESYSTEM_APPLYING,
                facts={"item": prepared},
            )
            current = operation.phase
            from sift_core.evidence_chain import (
                get_immutable_flag_fd,
                set_immutable_flag_fd,
            )

            if fd is not None:
                if get_immutable_flag_fd(fd) is True and not set_immutable_flag_fd(
                    fd, False
                ):
                    raise CustodyOperationError(
                        "evidence_unprotect_failed", http_status=500
                    )
                if get_immutable_flag_fd(fd) is not False:
                    raise CustodyOperationError(
                        "evidence_unprotect_verification_failed", http_status=409
                    )
            return {
                "operation_id": operation.operation_id,
                "operation_phase": operation.phase.value,
                "action": command.action.value,
                "evidence_object_id": command.evidence_object_id,
                "ready_for_replacement": True,
            }
        except Exception as exc:
            failure = (
                exc.reason
                if isinstance(exc, CustodyOperationError)
                else type(exc).__name__
            )
            try:
                self._repository.fail(operation.operation_id, current, failure)
            except Exception:
                logger.warning(
                    "recovery begin failure persistence failed", exc_info=True
                )
            if isinstance(exc, CustodyOperationError):
                raise
            raise CustodyOperationError(
                "recovery_begin_failed", http_status=500
            ) from exc
        finally:
            if fd is not None:
                os.close(fd)
            if root_fd is not None:
                os.close(root_fd)

    def complete(
        self,
        operation_id: str,
        *,
        actor_user_id: str,
        completion_reauth_audit_event_id: str,
        examiner: str,
    ) -> dict[str, Any]:
        operation = self._repository.authorize_recovery_completion(
            operation_id,
            actor_user_id=actor_user_id,
            completion_reauth_audit_event_id=completion_reauth_audit_event_id,
        )
        if operation.phase == CustodyOperationPhase.COMPLETED:
            return dict(operation.result or {})
        prepared = operation.prepared_facts or {}
        item_before = prepared.get("item") if isinstance(prepared, dict) else None
        if not isinstance(item_before, dict):
            raise CustodyOperationError(
                "recovery_prepared_facts_missing", http_status=409
            )
        evidence_object_id = str(item_before.get("evidence_object_id") or "")
        root_fd: int | None = None
        fd: int | None = None
        try:
            item, root_fd, fd = self._verified_descriptor_facts(
                operation.case_id, evidence_object_id
            )
            original_sha256 = str(item_before.get("original_sha256") or "")
            if operation.action == CustodyAction.RESTORE_EXACT.value:
                if item["sha256"] != original_sha256:
                    raise CustodyOperationError(
                        "restore_hash_mismatch", http_status=409
                    )
            elif operation.action == CustodyAction.REPLACE_REACQUIRE.value:
                if item["sha256"] == original_sha256:
                    raise CustodyOperationError(
                        "replace_requires_changed_bytes_use_restore", http_status=409
                    )
            else:
                raise CustodyOperationError("recovery_action_required", http_status=409)

            from sift_core.evidence_chain import (
                get_immutable_flag_fd,
                set_immutable_flag_fd,
            )

            if get_immutable_flag_fd(fd) is not True and not set_immutable_flag_fd(
                fd, True
            ):
                raise CustodyOperationError(
                    "evidence_immutability_failed", http_status=500
                )
            if get_immutable_flag_fd(fd) is not True:
                raise CustodyOperationError(
                    "evidence_posture_verification_failed", http_status=409
                )
            st = os.fstat(fd)
            verified = {
                **item,
                "immutable": True,
                "st_mtime_ns": st.st_mtime_ns,
                "st_ctime_ns": st.st_ctime_ns,
                "original_sha256": original_sha256,
                "original_bytes": item_before.get("original_bytes"),
                "original_version_id": item_before.get("original_version_id"),
            }
            operation = self._repository.advance(
                operation.operation_id,
                CustodyOperationPhase.FILESYSTEM_APPLYING,
                CustodyOperationPhase.FILESYSTEM_VERIFIED,
                facts={"item": verified},
            )
            operation = self._repository.commit_verified_recovery(
                operation.operation_id, item=verified, examiner=examiner
            )
            return dict(operation.result or {})
        except Exception as exc:
            failure = (
                exc.reason
                if isinstance(exc, CustodyOperationError)
                else type(exc).__name__
            )
            try:
                self._repository.fail(operation.operation_id, operation.phase, failure)
            except Exception:
                logger.warning(
                    "recovery completion failure persistence failed", exc_info=True
                )
            if isinstance(exc, CustodyOperationError):
                raise
            raise CustodyOperationError(
                "recovery_complete_failed", http_status=500
            ) from exc
        finally:
            if fd is not None:
                os.close(fd)
            if root_fd is not None:
                os.close(root_fd)


class DispositionCustodyOperation:
    """Gate-first Portal-only Ignore/Delete/Retire orchestration."""

    _ACTIONS = (CustodyAction.IGNORE, CustodyAction.DELETE_STRAY, CustodyAction.RETIRE)

    def __init__(
        self,
        repository: CustodyOperationRepositoryProtocol,
        case_dir: Callable[[str], Path | None],
        object_for_id: Callable[[str, str], dict[str, Any]],
    ) -> None:
        self._repository = repository
        self._case_dir = case_dir
        self._object_for_id = object_for_id

    @staticmethod
    def _name(display_path: str) -> str:
        parts = Path(display_path).parts
        if len(parts) != 2 or parts[0] != "evidence" or parts[1] in ("", ".", ".."):
            raise CustodyOperationError("invalid_evidence_path", http_status=409)
        return parts[1]

    def _pin(self, case_id: str, display_path: str) -> tuple[int, int]:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise CustodyOperationError("o_nofollow_required", http_status=500)
        case_dir = self._case_dir(case_id)
        if case_dir is None:
            raise CustodyOperationError(
                "case_artifact_path_unavailable", http_status=404
            )
        root_fd = os.open(
            case_dir / "evidence",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow,
        )
        try:
            fd = os.open(
                self._name(display_path),
                os.O_RDONLY | os.O_CLOEXEC | nofollow,
                dir_fd=root_fd,
            )
        except Exception:
            os.close(root_fd)
            raise
        return root_fd, fd

    def _prepare_item(
        self, command: ObjectCustodyCommand, obj: dict[str, Any]
    ) -> tuple[dict[str, Any], int | None, int | None]:
        status = str(obj.get("status") or "")
        seal_status = str(obj.get("seal_status") or "")
        if command.action is CustodyAction.IGNORE:
            if status != "detected" or seal_status != "unsealed":
                raise CustodyOperationError(
                    "disposition_object_not_pending", http_status=409
                )
        elif command.action is CustodyAction.DELETE_STRAY:
            if (
                status not in ("detected", "registered", "ignored")
                or seal_status != "unsealed"
            ):
                raise CustodyOperationError(
                    "disposition_object_not_pending", http_status=409
                )
        elif status not in ("sealed", "violated") or not obj.get("current_version_id"):
            raise CustodyOperationError(
                "retire_requires_versioned_evidence", http_status=409
            )
        display_path = str(obj.get("display_path") or "")
        item: dict[str, Any] = {
            "evidence_object_id": command.evidence_object_id,
            "display_path": display_path,
            "prior_status": status,
            "prior_seal_status": seal_status,
            "original_version_id": obj.get("current_version_id"),
            "original_sha256": obj.get("current_sha256"),
            "original_bytes": obj.get("current_bytes"),
        }
        try:
            root_fd, fd = self._pin(command.case_id, display_path)
        except FileNotFoundError as exc:
            if command.action is CustodyAction.IGNORE:
                raise CustodyOperationError(
                    "ignore_requires_readable_pending_item", http_status=409
                ) from exc
            if command.action is CustodyAction.DELETE_STRAY:
                raise CustodyOperationError(
                    "delete_requires_readable_pending_item", http_status=409
                ) from exc
            item.update({"present": False, "file_removed": False})
            return item, None, None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            os.close(root_fd)
            raise CustodyOperationError(
                "evidence_regular_single_link_required", http_status=409
            )
        sha256, size = LocalImmutablePostureAdapter._hash_fd(fd)
        item.update(
            {
                "present": True,
                "sha256": sha256,
                "bytes": size,
                "st_dev": st.st_dev,
                "st_ino": st.st_ino,
                "st_nlink": st.st_nlink,
            }
        )
        return item, root_fd, fd

    def execute(
        self,
        command: ObjectCustodyCommand,
        *,
        examiner: str,
        resumed_operation: CustodyOperationRecord | None = None,
    ) -> dict[str, Any]:
        if command.action not in self._ACTIONS:
            raise CustodyOperationError("disposition_action_required", http_status=400)
        operation = resumed_operation or self._repository.begin_or_resume(command)
        if operation.phase is CustodyOperationPhase.COMPLETED:
            return dict(operation.result or {})
        if operation.phase not in (
            CustodyOperationPhase.GATE_BLOCKED,
            CustodyOperationPhase.FILESYSTEM_APPLYING,
            CustodyOperationPhase.FILESYSTEM_VERIFIED,
        ):
            raise CustodyOperationError(
                "custody_operation_not_resumable", http_status=409
            )
        current = operation.phase
        root_fd: int | None = None
        fd: int | None = None
        try:
            if operation.phase is CustodyOperationPhase.GATE_BLOCKED:
                obj = self._object_for_id(command.case_id, command.evidence_object_id)
                if str(obj.get("evidence_object_id")) != command.evidence_object_id:
                    raise CustodyOperationError(
                        "disposition_object_binding_changed", http_status=409
                    )
                item, root_fd, fd = self._prepare_item(command, obj)
                operation = self._repository.advance(
                    operation.operation_id,
                    CustodyOperationPhase.GATE_BLOCKED,
                    CustodyOperationPhase.FILESYSTEM_APPLYING,
                    facts={"item": item},
                )
                current = operation.phase
            else:
                stored = (
                    operation.verified_facts
                    if operation.phase is CustodyOperationPhase.FILESYSTEM_VERIFIED
                    else operation.prepared_facts
                ) or {}
                item = stored.get("item")
                if not isinstance(item, dict):
                    raise CustodyOperationError(
                        "disposition_facts_missing", http_status=409
                    )

            if operation.phase is CustodyOperationPhase.FILESYSTEM_APPLYING:
                if command.action is CustodyAction.DELETE_STRAY:
                    if fd is None:
                        try:
                            root_fd, fd = self._pin(
                                command.case_id, str(item["display_path"])
                            )
                        except FileNotFoundError:
                            root_fd = None
                            fd = None
                    if fd is not None:
                        before = os.fstat(fd)
                        sha256, size = LocalImmutablePostureAdapter._hash_fd(fd)
                        if (
                            sha256 != item.get("sha256")
                            or size != item.get("bytes")
                            or before.st_dev != item.get("st_dev")
                            or before.st_ino != item.get("st_ino")
                        ):
                            raise CustodyOperationError(
                                "delete_descriptor_identity_changed", http_status=409
                            )
                        name = self._name(str(item["display_path"]))
                        directory_entry = os.stat(
                            name, dir_fd=root_fd, follow_symlinks=False
                        )
                        if (directory_entry.st_dev, directory_entry.st_ino) != (
                            before.st_dev,
                            before.st_ino,
                        ):
                            raise CustodyOperationError(
                                "delete_directory_entry_changed", http_status=409
                            )
                        os.unlink(name, dir_fd=root_fd)
                        item["file_removed"] = True
                    elif item.get("present") is True:
                        item["file_removed"] = True
                    else:
                        item["file_removed"] = False
                else:
                    item["file_removed"] = False
                operation = self._repository.advance(
                    operation.operation_id,
                    CustodyOperationPhase.FILESYSTEM_APPLYING,
                    CustodyOperationPhase.FILESYSTEM_VERIFIED,
                    facts={"item": item},
                )
                current = operation.phase
            operation = self._repository.commit_verified_disposition(
                operation.operation_id, item=item, examiner=examiner
            )
            return dict(operation.result or {})
        except Exception as exc:
            failure = (
                exc.reason
                if isinstance(exc, CustodyOperationError)
                else type(exc).__name__
            )
            try:
                self._repository.fail(operation.operation_id, current, failure)
            except Exception:
                logger.warning(
                    "custody disposition failure persistence failed", exc_info=True
                )
            if isinstance(exc, CustodyOperationError):
                raise
            raise CustodyOperationError(
                "disposition_failed_recoverable", http_status=500
            ) from exc
        finally:
            if fd is not None:
                os.close(fd)
            if root_fd is not None:
                os.close(root_fd)


def public_operation(record: CustodyOperationRecord | None) -> dict[str, Any] | None:
    """Return path-free, authorization-free state safe for the human Portal."""
    if record is None:
        return None
    return {
        "operation_id": record.operation_id,
        "action": record.action,
        "phase": record.phase.value,
        "failed_from_phase": (
            record.failed_from_phase.value if record.failed_from_phase else None
        ),
        "failure_code": record.failure_code,
        "recoverable": record.action
        in {
            "ADD_SEAL",
            "REPLACE_REACQUIRE",
            "RESTORE_EXACT",
            "IGNORE",
            "DELETE_STRAY",
            "RETIRE",
        }
        and record.phase in RESUMABLE_SEAL_PHASES,
    }
