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
    runner_instance_id: str = _RUNNER_INSTANCE_ID
    resume_reauth_audit_event_id: str | None = None

    @property
    def action(self) -> CustodyAction:
        return CustodyAction.ADD_SEAL

    def operation_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "action": self.action,
            "files": list(self.file_specs),
        }


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


class RecoveryAuthorityProtocol(Protocol):
    """Operator-only recovery authority; it never accepts paths or receipts.

    Portal authentication, scoped re-authentication, durable command creation,
    and action-specific finalization stay inside the implementing authority.
    Inventory/disposition code may pass only this server-selected object choice.
    """

    def execute_authorized_recovery(
        self, selection: RecoverySelection, *, examiner: str
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
            raise CustodyOperationError("custody_action_unknown", http_status=400) from exc
        with self._connect() as conn:
            with conn.cursor() as cur:
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
                    (operation_id, expected.value, target.value, _jsonb(facts or {}), _RUNNER_INSTANCE_ID),
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
                    (operation_id, expected.value, failure_code[:96], _RUNNER_INSTANCE_ID),
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
                         from app.custody_operation_commit_verified_seal(%s, %s, %s, %s)""",
                    (operation_id, _jsonb(items), examiner, _RUNNER_INSTANCE_ID),
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
                if len(parts) != 2 or parts[0] != "evidence" or parts[1] in ("", ".", ".."):
                    raise CustodyOperationError("invalid_evidence_path", http_status=400)
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
                        raise CustodyOperationError("evidence_mode_0644_required", http_status=409)
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
                raise CustodyOperationError("evidence_posture_verification_failed", http_status=409)
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
                raise CustodyOperationError("seal_reauth_scope_mismatch", http_status=403) from exc
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
                raise CustodyOperationError("case_artifact_path_unavailable", http_status=404)
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
                    raise CustodyOperationError("posture_receipt_missing", http_status=500)
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
            failure = exc.reason if isinstance(exc, CustodyOperationError) else type(exc).__name__
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
            raise CustodyOperationError("seal_failed_recoverable", http_status=500) from exc
        finally:
            if batch is not None:
                self._posture.close(batch)


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
        "recoverable": record.action == "ADD_SEAL"
        and record.phase in RESUMABLE_SEAL_PHASES,
    }
