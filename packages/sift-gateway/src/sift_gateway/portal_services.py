"""Gateway-owned DB adapters injected into the operator portal.

These services close the B-MVP-5 live binding gap: the portal already had DI
slots for evidence, investigation, report, and job state, but production startup
was not wiring concrete Postgres-backed implementations. The services in this
module keep filesystem access server-side, store no absolute paths in Postgres,
and return only portal-safe relative display paths / opaque IDs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import sys
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, LiteralString

from sift_core.evidence_storage import (
    StorageAuthorityError,
    external_storage_facts,
)

from sift_gateway.custody_drift import (
    AuthorityEvidence,
    DriftCode,
    EntryKind,
    FileIdentity,
    InventorySnapshot,
    MountedEvidence,
    StorageAvailability,
    StorageProfile,
    classify_inventory,
)
from sift_gateway.custody_operations import (
    RESUMABLE_SEAL_PHASES,
    CustodyAction,
    CustodyOperationError,
    CustodyOperationRepository,
    CustodyOperationRepositoryProtocol,
    DispositionCustodyOperation,
    ExternalReadOnlyPostureAdapter,
    LocalImmutablePostureAdapter,
    LocalImmutablePostureProtocol,
    ObjectCustodyCommand,
    RecoveryCustodyOperation,
    SealCommand,
    SealCustodyOperation,
    public_operation,
)
from sift_gateway.custody_proof import (
    CustodyProofError,
    load_signing_key,
    sign_bundle,
    verify_bundle,
)

logger = logging.getLogger(__name__)


class PortalServiceError(Exception):
    def __init__(self, reason: str, *, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise RuntimeError("psycopg is required for portal DB services") from exc
    return psycopg.connect(dsn)


def _jsonb(value: Any):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover
        return json.dumps(value)
    return Jsonb(value)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _compact_label(value: Any, *, limit: int = 90) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    cut = text[: max(0, limit - 3)].rstrip()
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0].rstrip()
    return f"{cut.rstrip(' ,.;:-')}..."


def _first_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, dict):
            for key in (
                "message",
                "error",
                "detail",
                "title",
                "finding_id",
                "description",
            ):
                found = _first_text(value.get(key))
                if found:
                    return found
            continue
        if isinstance(value, list):
            for item in value:
                found = _first_text(item)
                if found:
                    return found
            continue
        text = _compact_label(value)
        if text:
            return text
    return ""


def _event_details(row: dict[str, Any]) -> dict[str, Any]:
    details = row.get("details")
    return details if isinstance(details, dict) else {}


def _activity_args(row: dict[str, Any]) -> dict[str, Any]:
    for details in (_event_details(row), row.get("_pre_details")):
        if not isinstance(details, dict):
            continue
        args = details.get("arguments")
        if isinstance(args, dict):
            return args
    return {}


def _activity_tool(row: dict[str, Any]) -> str:
    details = _event_details(row)
    return _compact_label(
        details.get("tool") or row.get("event_type") or "activity", limit=64
    )


def _activity_backend(row: dict[str, Any]) -> str:
    details = _event_details(row)
    return _compact_label(
        details.get("backend") or row.get("source") or "unknown", limit=64
    )


def _activity_kind(tool: str, status: str) -> str:
    if status == "failure":
        return "alert"
    if tool == "record_finding":
        return "discovery"
    if tool in {"record_timeline_event", "manage_todo"}:
        return "io"
    if tool == "run_command" or tool.startswith("opensearch_"):
        return "analysis"
    return "info"


def _activity_label(row: dict[str, Any]) -> str:
    details = _event_details(row)
    tool = _activity_tool(row)
    status = str(row.get("status") or details.get("status") or "").lower()
    summary = _compact_label(row.get("summary"), limit=90)
    result = details.get("result_summary")
    detail = details.get("detail")
    args = _activity_args(row)

    if status == "failure":
        reason = _first_text(result, detail, summary)
        return _compact_label(
            f"{tool} failed - {reason}" if reason else f"{tool} failed"
        )

    if tool == "record_finding":
        title = _first_text(args.get("title"), result)
        confidence = _first_text(args.get("confidence"))
        suffix = f" ({confidence})" if confidence else ""
        return _compact_label(
            f"Recorded finding - {title}{suffix}" if title else "Recorded finding"
        )

    if tool == "record_timeline_event":
        desc = _first_text(args.get("description"), args.get("title"), result)
        return _compact_label(
            f"Timeline event added - {desc}" if desc else "Timeline event added"
        )

    if tool == "manage_todo":
        action = _first_text(args.get("action"), args.get("operation"))
        return _compact_label(f"TODO {action}" if action else "TODO updated")

    if tool == "run_command":
        command = _first_text(
            args.get("command"),
            detail.get("command") if isinstance(detail, dict) else None,
        )
        exit_code = None
        if isinstance(result, dict):
            exit_code = result.get("exit_code")
        if exit_code is None and isinstance(detail, dict):
            exit_code = detail.get("exit_code")
        exit_part = f" (exit {exit_code})" if exit_code is not None else ""
        return _compact_label(
            f"Ran command - {command}{exit_part}"
            if command
            else f"Ran command{exit_part}"
        )

    if tool.startswith("opensearch_"):
        op = tool.removeprefix("opensearch_").replace("_", " ")
        count = None
        if isinstance(result, dict):
            for key in ("hits", "count", "total", "records"):
                if result.get(key) is not None:
                    count = result.get(key)
                    break
        count_part = f" - {count} hits" if count is not None else ""
        return _compact_label(f"OpenSearch {op}{count_part}")

    # Generic add-on tool: format as "namespace op" for any "prefix_action" pattern.
    if "_" in tool:
        ns, _, rest = tool.partition("_")
        op = rest.replace("_", " ")
        return _compact_label(f"{ns} {op}" if op else ns)

    return summary or _compact_label(tool)


def _collapse_activity_rows(
    rows: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in rows:
        key = str(row.get("request_id") or row.get("id") or "")
        if not key:
            continue
        if key not in grouped:
            grouped[key] = row
            order.append(key)
            continue
        details = _event_details(row)
        if details.get("phase") == "pre_dispatch" and details.get("arguments"):
            grouped[key]["_pre_details"] = details
    return [grouped[key] for key in order[:limit]]


def _actor_columns(actor: Any) -> tuple[str, str | None, str | None, str | None]:
    if not isinstance(actor, dict):
        return "system", None, None, None
    ptype = str(actor.get("principal_type") or "")
    pid = str(actor.get("principal_id") or "") or None
    agent_id = str(actor.get("agent_id") or "") or None
    if ptype in ("operator", "user"):
        return "user", pid, None, None
    if ptype == "agent":
        return "agent", None, agent_id or pid, None
    if ptype == "service":
        return "service", None, None, pid
    return "system", None, None, None


def _safe_item_id(row: dict[str, Any], fallback_prefix: str, idx: int) -> str:
    value = row.get("id") or row.get("item_id") or row.get("todo_id")
    if value:
        return str(value)
    return f"{fallback_prefix}-{idx:03d}"


class _BasePortalDbService:
    def __init__(self, dsn: str, *, legacy_sync: bool = False) -> None:
        self._dsn = dsn
        # BATCH-K2: legacy_sync backfills DB rows from case JSON. It is OFF by
        # default so that in DB-active mode Postgres is authority and tampering
        # with findings.json / timeline.json / iocs.json / todos.json cannot be
        # re-imported into the DB read model. Enable only for a one-time legacy
        # bridge against a non-DB-active case.
        self._legacy_sync = bool(legacy_sync)

    def _connect(self):
        return _connect(self._dsn)

    def _case_artifact_path(self, case_id: str) -> Path | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select legacy_case_dir from app.cases where id = %s",
                    (case_id,),
                )
                row = cur.fetchone()
        if not row or not row[0]:
            return None
        path = Path(str(row[0]))
        return path if path.is_dir() else None

    def _read_json_list(self, case_id: str, filename: str) -> list[dict[str, Any]]:
        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            return []
        path = case_dir / filename
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            if path.exists():
                logger.warning(
                    "Failed to read %s for case %s: %s", filename, case_id, e
                )
            return []
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            rows = data.get("items") or data.get("files") or []
            return [row for row in rows if isinstance(row, dict)]
        return []

    def _write_json_list(
        self, case_id: str, filename: str, rows: list[dict[str, Any]]
    ) -> None:
        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            return
        path = case_dir / filename
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(rows, handle, indent=2, default=str)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, path)
            except Exception:
                with contextlib_suppress_oserror():
                    os.unlink(tmp)
                raise
        except OSError as exc:
            logger.warning("artifact mirror write failed for %s: %s", filename, exc)

    def _sync_findings(self, case_id: str) -> None:
        if not self._legacy_sync:
            return
        rows = self._read_json_list(case_id, "findings.json")
        if not rows:
            return
        with self._connect() as conn:
            with conn.cursor() as cur:
                for idx, payload in enumerate(rows, start=1):
                    item_id = _safe_item_id(payload, "F-sync", idx)
                    cur.execute(
                        """
                        insert into app.investigation_findings
                          (case_id, item_id, status, content_hash, payload,
                           created_by, approved_by, approved_at, rejected_by,
                           rejected_at, source, updated_at)
                        values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                'artifact_sync', now())
                        on conflict (case_id, item_id) do update
                          set status = excluded.status,
                              content_hash = excluded.content_hash,
                              payload = excluded.payload,
                              created_by = excluded.created_by,
                              approved_by = excluded.approved_by,
                              approved_at = excluded.approved_at,
                              rejected_by = excluded.rejected_by,
                              rejected_at = excluded.rejected_at,
                              source = 'artifact_sync',
                              updated_at = now()
                        """,
                        (
                            case_id,
                            item_id,
                            str(payload.get("status") or "DRAFT"),
                            payload.get("content_hash"),
                            _jsonb(payload),
                            payload.get("created_by") or payload.get("examiner"),
                            payload.get("approved_by"),
                            payload.get("approved_at") or None,
                            payload.get("rejected_by"),
                            payload.get("rejected_at") or None,
                        ),
                    )
            conn.commit()

    def _sync_timeline(self, case_id: str) -> None:
        if not self._legacy_sync:
            return
        rows = self._read_json_list(case_id, "timeline.json")
        if not rows:
            return
        with self._connect() as conn:
            with conn.cursor() as cur:
                for idx, payload in enumerate(rows, start=1):
                    item_id = _safe_item_id(payload, "T-sync", idx)
                    cur.execute(
                        """
                        insert into app.investigation_timeline_events
                          (case_id, item_id, status, content_hash, payload,
                           created_by, approved_by, approved_at, rejected_by,
                           rejected_at, source, updated_at)
                        values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                'artifact_sync', now())
                        on conflict (case_id, item_id) do update
                          set status = excluded.status,
                              content_hash = excluded.content_hash,
                              payload = excluded.payload,
                              created_by = excluded.created_by,
                              approved_by = excluded.approved_by,
                              approved_at = excluded.approved_at,
                              rejected_by = excluded.rejected_by,
                              rejected_at = excluded.rejected_at,
                              source = 'artifact_sync',
                              updated_at = now()
                        """,
                        (
                            case_id,
                            item_id,
                            str(payload.get("status") or "DRAFT"),
                            payload.get("content_hash"),
                            _jsonb(payload),
                            payload.get("created_by") or payload.get("examiner"),
                            payload.get("approved_by"),
                            payload.get("approved_at") or None,
                            payload.get("rejected_by"),
                            payload.get("rejected_at") or None,
                        ),
                    )
            conn.commit()

    def _sync_iocs(self, case_id: str) -> None:
        if not self._legacy_sync:
            return
        rows = self._read_json_list(case_id, "iocs.json")
        if not rows:
            return
        with self._connect() as conn:
            with conn.cursor() as cur:
                for idx, payload in enumerate(rows, start=1):
                    item_id = _safe_item_id(payload, "IOC-sync", idx)
                    cur.execute(
                        """
                        insert into app.investigation_iocs
                          (case_id, item_id, status, value, ioc_type, payload,
                           created_by, approved_by, approved_at, rejected_by,
                           rejected_at, source, updated_at)
                        values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                'artifact_sync', now())
                        on conflict (case_id, item_id) do update
                          set status = excluded.status,
                              value = excluded.value,
                              ioc_type = excluded.ioc_type,
                              payload = excluded.payload,
                              created_by = excluded.created_by,
                              approved_by = excluded.approved_by,
                              approved_at = excluded.approved_at,
                              rejected_by = excluded.rejected_by,
                              rejected_at = excluded.rejected_at,
                              source = 'artifact_sync',
                              updated_at = now()
                        """,
                        (
                            case_id,
                            item_id,
                            str(payload.get("status") or "DRAFT"),
                            payload.get("value"),
                            payload.get("type") or payload.get("ioc_type"),
                            _jsonb(payload),
                            payload.get("created_by") or payload.get("examiner"),
                            payload.get("approved_by"),
                            payload.get("approved_at") or None,
                            payload.get("rejected_by"),
                            payload.get("rejected_at") or None,
                        ),
                    )
            conn.commit()

    def _sync_todos(self, case_id: str) -> None:
        if not self._legacy_sync:
            return
        rows = self._read_json_list(case_id, "todos.json")
        if not rows:
            return
        with self._connect() as conn:
            with conn.cursor() as cur:
                for idx, payload in enumerate(rows, start=1):
                    todo_id = str(
                        payload.get("todo_id")
                        or payload.get("id")
                        or f"TODO-sync-{idx:03d}"
                    )
                    cur.execute(
                        """
                        insert into app.investigation_todos
                          (case_id, todo_id, status, priority, assignee, payload,
                           created_by, completed_at, source, updated_at)
                        values (%s, %s, %s, %s, %s, %s, %s, %s,
                                'artifact_sync', now())
                        on conflict (case_id, todo_id) do update
                          set status = excluded.status,
                              priority = excluded.priority,
                              assignee = excluded.assignee,
                              payload = excluded.payload,
                              created_by = excluded.created_by,
                              completed_at = excluded.completed_at,
                              source = excluded.source,
                              updated_at = now()
                        """,
                        (
                            case_id,
                            todo_id,
                            str(payload.get("status") or "open"),
                            str(payload.get("priority") or "medium"),
                            payload.get("assignee"),
                            _jsonb(payload),
                            payload.get("created_by") or payload.get("examiner"),
                            payload.get("completed_at") or None,
                        ),
                    )
            conn.commit()


class contextlib_suppress_oserror:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, OSError)


class EvidenceAuthorityService(_BasePortalDbService):
    """DB evidence/custody adapter over the C1 RPCs."""

    def __init__(
        self,
        dsn: str,
        *,
        legacy_sync: bool = False,
        custody_repository: CustodyOperationRepositoryProtocol | None = None,
        posture_adapter: LocalImmutablePostureProtocol | None = None,
        external_posture_adapter: LocalImmutablePostureProtocol | None = None,
    ) -> None:
        super().__init__(dsn, legacy_sync=legacy_sync)
        self._custody_repository = custody_repository or CustodyOperationRepository(
            self._connect
        )
        self._posture_adapter = posture_adapter or LocalImmutablePostureAdapter()
        self._external_posture_adapter = (
            external_posture_adapter or ExternalReadOnlyPostureAdapter()
        )

    def change_storage_profile(
        self,
        *,
        case_id: str,
        profile: str,
        reason: str,
        idempotency_key: str,
        reauth_audit_event_id: str,
        actor: Any,
    ) -> dict[str, Any]:
        try:
            selected = StorageProfile(profile)
        except ValueError as exc:
            raise PortalServiceError(
                "invalid_storage_profile", http_status=400
            ) from exc
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        if actor_type != "user" or not actor_user or actor_service:
            raise PortalServiceError("storage_profile_actor_required", http_status=403)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select app.evidence_storage_change_profile(
                         %s,%s,%s,%s,%s,%s)""",
                    (
                        case_id,
                        selected.value,
                        reason,
                        idempotency_key,
                        reauth_audit_event_id,
                        actor_user,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        if not row or not isinstance(row[0], dict):
            raise PortalServiceError("storage_profile_change_failed", http_status=503)
        return dict(row[0])

    def reconcile_for_admission(self, case_id: str) -> dict[str, Any]:
        """Observe the mounted inventory and persist custody state, fail closed.

        This method performs no filesystem mutation.  Every direct entry is
        observed, including unsafe or unreadable entries; unknown regular files
        become DETECTED and therefore block the aggregate gate.  Sealed entries
        use cheap identity/size/ctime checks here; each referenced version is
        descriptor-pinned and posture-checked by ``resolve_evidence_reference``.
        """
        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            raise PortalServiceError("evidence_authority_unavailable", http_status=503)
        evidence_dir = case_dir / "evidence"

        with self._connect() as conn:
            with conn.cursor() as cur:
                # Hold the same case-scoped transaction lease as every custody
                # finalizer across authority reads, filesystem scan, and the
                # persisted classification. A scan begun before Restore cannot
                # commit stale findings after Restore opens the gate.
                cur.execute(
                    "select pg_advisory_xact_lock(hashtextextended(%s,0))",
                    (case_id,),
                )
                cur.execute(
                    """select seal_status,issues,manifest_version,manifest_hash
                       from app.evidence_chain_heads where case_id=%s""",
                    (case_id,),
                )
                head_row = cur.fetchone()
                cur.execute(
                    """select profile,source_identity,verified_mount_instance,state,generation,
                              verified_generation,read_only,last_full_verified_at,remediation
                       from app.evidence_storage_authorities where case_id=%s""",
                    (case_id,),
                )
                storage_row = cur.fetchone()
                if not storage_row:
                    raise PortalServiceError(
                        "evidence_storage_authority_unavailable", http_status=503
                    )
                storage_profile = StorageProfile(str(storage_row[0]))
                storage_issue_codes = {
                    "STORAGE_UNAVAILABLE",
                    "MOUNT_IDENTITY_CHANGED",
                    "STORAGE_SOURCE_CHANGED",
                    "STORAGE_FULL_VERIFY_REQUIRED",
                    "POSTURE_DRIFT",
                    "READ_WRITE_DRIFT",
                    "STORAGE_PROFILE_CHANGED",
                }
                head_issues = (
                    head_row[1]
                    if head_row and len(head_row) > 1 and isinstance(head_row[1], list)
                    else []
                )
                storage_recoverable_head = bool(head_issues) and all(
                    isinstance(issue, dict)
                    and issue.get("code") in storage_issue_codes
                    and issue.get("storage_generation") == storage_row[4]
                    for issue in head_issues
                )
                persisted_head_violation = bool(
                    head_row
                    and str(head_row[0]) == "violated"
                    and not storage_recoverable_head
                )
                cur.execute(
                    """select v.id::text,v.item_facts,v.created_at
                       from app.evidence_storage_verifications v
                       join app.evidence_storage_authorities a on a.case_id=v.case_id
                       join app.evidence_chain_heads h on h.case_id=v.case_id
                       where v.case_id=%s and v.outcome='SUCCESS'
                         and v.generation=a.generation and v.profile=a.profile
                         and v.manifest_version=h.manifest_version
                         and v.manifest_hash=h.manifest_hash
                         and jsonb_array_length(v.item_facts)=(select count(*)
                           from app.evidence_objects o
                           where o.case_id=v.case_id and o.status='sealed')
                         and not exists(
                           select 1 from app.evidence_objects o
                           join app.evidence_versions ev on ev.id=o.current_version_id
                           where o.case_id=v.case_id and o.status='sealed'
                             and not exists(select 1 from jsonb_array_elements(v.item_facts) x
                               where (x->>'evidence_object_id')::uuid=o.id
                                 and (x->>'evidence_version_id')::uuid=ev.id
                                 and x->>'sha256'=ev.sha256
                                 and (x->>'bytes')::bigint=ev.bytes))
                       order by v.created_at desc,v.id desc limit 1""",
                    (case_id,),
                )
                receipt_row = cur.fetchone()
                receipt_items = (
                    receipt_row[1]
                    if receipt_row and isinstance(receipt_row[1], list)
                    else []
                )
                storage_receipt_by_object = {
                    str(item.get("evidence_object_id")): {
                        **item,
                        "_authority_created_at": (
                            receipt_row[2]
                            if receipt_row and len(receipt_row) > 2
                            else None
                        ),
                    }
                    for item in receipt_items
                    if isinstance(item, dict)
                }
                cur.execute(
                    """
                    select o.id::text, o.display_path, o.current_sha256, o.current_bytes,
                           o.sealed_at, v.metadata, o.status, v.id::text
                    from app.evidence_objects o
                    left join app.evidence_versions v on v.id=o.current_version_id
                    where o.case_id = %s and o.status in ('sealed','violated')
                      and o.current_version_id is not null
                    """,
                    (case_id,),
                )
                sealed = {
                    str(row[1]): {
                        "id": str(row[0]),
                        "sha256": str(row[2] or ""),
                        "bytes": row[3],
                        "sealed_at": row[4],
                        "metadata": row[5]
                        if len(row) > 5 and isinstance(row[5], dict)
                        else {},
                        "authority_status": str(row[6]) if len(row) > 6 else "sealed",
                        "version_id": str(row[7]) if len(row) > 7 and row[7] else "",
                    }
                    for row in cur.fetchall()
                }
                cur.execute(
                    """select distinct on (r.evidence_object_id)
                              r.evidence_object_id::text,r.evidence_version_id::text,
                              r.sha256,r.bytes,r.st_dev,r.st_ino,r.st_mtime_ns,
                              r.st_ctime_ns,r.st_nlink,r.owner_name,r.mode,r.immutable,
                              r.created_at
                       from app.evidence_exact_restore_posture_receipts r
                       join app.evidence_storage_authorities a on a.case_id=r.case_id
                         and a.profile=r.storage_profile
                         and a.generation=r.storage_generation
                       join app.evidence_objects o on o.id=r.evidence_object_id
                         and o.case_id=r.case_id and o.current_version_id=r.evidence_version_id
                       where r.case_id=%s
                       order by r.evidence_object_id,r.created_at desc,r.id desc""",
                    (case_id,),
                )
                restore_receipt_by_object = {
                    str(row[0]): {
                        "evidence_object_id": str(row[0]),
                        "evidence_version_id": str(row[1]),
                        "sha256": str(row[2]),
                        "bytes": row[3],
                        "st_dev": row[4],
                        "st_ino": row[5],
                        "st_mtime_ns": row[6],
                        "st_ctime_ns": row[7],
                        "st_nlink": row[8],
                        "owner": str(row[9]),
                        "mode": str(row[10]),
                        "immutable": bool(row[11]),
                        "_authority_created_at": row[12] if len(row) > 12 else None,
                    }
                    for row in cur.fetchall()
                }
                cur.execute(
                    """select display_path from app.evidence_objects
                       where case_id=%s and status in ('ignored','retired')""",
                    (case_id,),
                )
                dispositioned_paths = {str(row[0]) for row in cur.fetchall()}
                live: set[str] = set()
                unsafe: list[str] = []
                storage_available = True
                external_facts = None
                correlation_id = (
                    _admission_correlation_id() or f"portal-{uuid.uuid4().hex}"
                )
                observed_facts: list[MountedEvidence] = []
                pending_detected: list[tuple[str, str, int | None]] = []
                scan_complete = True
                if not evidence_dir.is_dir():
                    storage_available = False
                    unsafe.append("evidence_storage_unavailable")
                    cur.execute(
                        "select app.evidence_storage_record_observation(%s,%s,false,null,null,null)",
                        (case_id, storage_profile.value),
                    )
                else:
                    if storage_profile is StorageProfile.EXTERNALLY_READ_ONLY:
                        root_fd: int | None = None
                        try:
                            root_fd = os.open(
                                evidence_dir,
                                os.O_RDONLY
                                | os.O_CLOEXEC
                                | os.O_DIRECTORY
                                | getattr(os, "O_NOFOLLOW", 0),
                            )
                            external_facts = external_storage_facts(
                                root_fd,
                                require_read_only=False,
                                expected_mount_path=evidence_dir,
                            )
                            cur.execute(
                                """select observed.profile,observed.source_identity,
                                          observed.verified_mount_instance,observed.state,
                                          observed.generation,observed.verified_generation,
                                          observed.read_only,observed.last_full_verified_at,
                                          observed.remediation
                                   from app.evidence_storage_record_observation(
                                     %s,%s,true,%s,%s,%s) observed""",
                                (
                                    case_id,
                                    storage_profile.value,
                                    external_facts.source_identity,
                                    external_facts.mount_instance_identity,
                                    external_facts.read_only,
                                ),
                            )
                            observed_storage_row = cur.fetchone()
                            if not observed_storage_row:
                                raise StorageAuthorityError(
                                    "external storage observation unavailable"
                                )
                            # The observation RPC may advance UNAVAILABLE or a
                            # restored read-only posture to FULL_VERIFY_REQUIRED.
                            # Classification in this same locked transaction
                            # must use that returned authority, not the snapshot
                            # read before the live mount observation.
                            storage_row = observed_storage_row
                            storage_available = True
                            if str(storage_row[3]) != "AVAILABLE":
                                unsafe.append("external_storage_full_verify_required")
                        except (OSError, StorageAuthorityError):
                            storage_available = False
                            unsafe.append("evidence_storage_unavailable")
                            cur.execute(
                                "select app.evidence_storage_record_observation(%s,%s,false,null,null,null)",
                                (case_id, storage_profile.value),
                            )
                        finally:
                            if root_fd is not None:
                                os.close(root_fd)
                    if (
                        storage_profile is StorageProfile.EXTERNALLY_READ_ONLY
                        and external_facts is None
                    ):
                        # The external root is unavailable or no longer mounted at
                        # the canonical evidence root. Never inventory the local
                        # underlay exposed by mount loss as though it were evidence.
                        entries = []
                    else:
                        try:
                            entries = sorted(
                                os.scandir(evidence_dir), key=lambda item: item.name
                            )
                        except OSError:
                            entries = []
                            scan_complete = False
                            storage_available = False
                            unsafe.append("evidence_inventory_unavailable")
                    for entry in entries:
                        rel = f"evidence/{entry.name}"
                        observation_id = hashlib.sha256(
                            rel.encode("utf-8")
                        ).hexdigest()[:32]
                        live.add(rel)
                        if rel in dispositioned_paths:
                            continue
                        try:
                            st = entry.stat(follow_symlinks=False)
                            regular = entry.is_file(follow_symlinks=False)
                        except OSError:
                            scan_complete = False
                            storage_available = False
                            unsafe.append("evidence_inventory_unavailable")
                            break
                        if not regular or st is None or st.st_nlink != 1:
                            kind = (
                                EntryKind.SYMLINK
                                if entry.is_symlink()
                                else (
                                    EntryKind.DIRECTORY
                                    if st is not None and stat.S_ISDIR(st.st_mode)
                                    else EntryKind.OTHER
                                )
                            )
                            observed_facts.append(
                                MountedEvidence(
                                    observation_id=observation_id,
                                    evidence_object_id=None,
                                    entry_kind=kind,
                                    byte_count=st.st_size if st else None,
                                    hidden=entry.name.startswith("."),
                                )
                            )
                            pending_detected.append(
                                (rel, entry.name, st.st_size if st else None)
                            )
                            unsafe.append("unsafe_evidence_inventory_entry")
                            continue
                        known = sealed.get(rel)
                        if known is None:
                            observed_facts.append(
                                MountedEvidence(
                                    observation_id=observation_id,
                                    evidence_object_id=None,
                                    entry_kind=EntryKind.REGULAR,
                                    identity=FileIdentity(
                                        st.st_dev,
                                        st.st_ino,
                                        st.st_size,
                                        st.st_mtime_ns,
                                        st.st_ctime_ns,
                                        st.st_nlink,
                                    ),
                                    hidden=entry.name.startswith("."),
                                )
                            )
                            pending_detected.append((rel, entry.name, st.st_size))
                            continue
                        immutable: bool | None = None
                        if storage_profile is StorageProfile.LOCAL_IMMUTABLE:
                            try:
                                from sift_core.evidence_chain import (
                                    get_immutable_flag_fd,
                                )

                                flags_fd = os.open(
                                    entry.path,
                                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                )
                                try:
                                    immutable = get_immutable_flag_fd(flags_fd)
                                finally:
                                    os.close(flags_fd)
                            except OSError:
                                scan_complete = False
                                storage_available = False
                                unsafe.append("evidence_inventory_unavailable")
                                break
                        observed_facts.append(
                            MountedEvidence(
                                observation_id=observation_id,
                                evidence_object_id=known["id"],
                                entry_kind=EntryKind.REGULAR,
                                identity=FileIdentity(
                                    st.st_dev,
                                    st.st_ino,
                                    st.st_size,
                                    st.st_mtime_ns,
                                    st.st_ctime_ns,
                                    st.st_nlink,
                                ),
                                immutable=immutable,
                                read_only=(
                                    external_facts.read_only if external_facts else None
                                ),
                                mount_identity=(
                                    external_facts.mount_instance_identity
                                    if external_facts
                                    else None
                                ),
                                storage_source_identity=(
                                    external_facts.source_identity
                                    if external_facts
                                    else None
                                ),
                            )
                        )
                if not scan_complete:
                    # A partial inventory is not evidence of object absence or
                    # tampering.  Discard all per-object conclusions and let the
                    # aggregate UNAVAILABLE state be the only classification.
                    live.clear()
                    observed_facts.clear()
                    pending_detected.clear()
                    unsafe = [
                        item
                        for item in unsafe
                        if item != "unsafe_evidence_inventory_entry"
                    ]
                elif storage_available:
                    for rel, display_name, size in pending_detected:
                        self._record_detected_observation(
                            cur,
                            case_id,
                            rel,
                            display_name,
                            size,
                            correlation_id,
                        )
                expected_facts: list[AuthorityEvidence] = []
                for known in sealed.values():
                    posture = known["metadata"].get("posture", {})
                    receipt_authority_ambiguous = False
                    if storage_profile is StorageProfile.EXTERNALLY_READ_ONLY:
                        receipt = storage_receipt_by_object.get(known["id"], {})
                    else:
                        candidates = [
                            candidate
                            for candidate in (
                                storage_receipt_by_object.get(known["id"]),
                                restore_receipt_by_object.get(known["id"]),
                            )
                            if candidate
                            and candidate.get("evidence_version_id")
                            == known["version_id"]
                            and candidate.get("sha256") == known["sha256"]
                            and candidate.get("bytes") == known["bytes"]
                        ]
                        if len(candidates) == 2:
                            first_created = candidates[0].get("_authority_created_at")
                            second_created = candidates[1].get("_authority_created_at")
                            # Equal or missing receipt time cannot establish
                            # which complete verification superseded which
                            # per-object restore. Fail closed to the historical
                            # version facts and require another Full Verify.
                            receipt = (
                                max(
                                    candidates,
                                    key=lambda candidate: candidate[
                                        "_authority_created_at"
                                    ],
                                )
                                if isinstance(first_created, datetime)
                                and isinstance(second_created, datetime)
                                and first_created != second_created
                                else {}
                            )
                            receipt_authority_ambiguous = not receipt
                        else:
                            receipt = candidates[0] if candidates else {}
                    if receipt_authority_ambiguous:
                        # Two otherwise-current posture authorities without a
                        # strict ordering cannot be resolved from historical
                        # version metadata. Suppress every fallback so the
                        # classifier emits FULL_VERIFY_REQUIRED explicitly.
                        posture = {}
                    receipt_matches_current = (
                        receipt.get("evidence_version_id") == known["version_id"]
                        and receipt.get("sha256") == known["sha256"]
                        and receipt.get("bytes") == known["bytes"]
                    )
                    if receipt_matches_current:
                        posture = receipt
                    identity = None
                    if (
                        all(
                            posture.get(key) is not None
                            for key in (
                                "st_dev",
                                "st_ino",
                                "st_mtime_ns",
                                "st_ctime_ns",
                                "st_nlink",
                            )
                        )
                        and known["bytes"] is not None
                    ):
                        identity = FileIdentity(
                            int(posture["st_dev"]),
                            int(posture["st_ino"]),
                            int(known["bytes"]),
                            int(posture["st_mtime_ns"]),
                            int(posture["st_ctime_ns"]),
                            int(posture["st_nlink"]),
                        )
                    if (
                        identity is None
                        and storage_profile is StorageProfile.LOCAL_IMMUTABLE
                        and not receipt_authority_ambiguous
                    ):
                        observed = next(
                            (
                                item
                                for item in observed_facts
                                if item.evidence_object_id == known["id"]
                            ),
                            None,
                        )
                        sealed_at = known.get("sealed_at")
                        sealed_ns = (
                            int(sealed_at.timestamp() * 1_000_000_000)
                            if isinstance(sealed_at, datetime)
                            else 0
                        )
                        if (
                            observed is not None
                            and observed.identity is not None
                            and known["bytes"] is not None
                            and observed.identity.byte_count == int(known["bytes"])
                            and sealed_ns >= observed.identity.ctime_ns
                        ):
                            identity = observed.identity
                    sha = str(known["sha256"] or "").removeprefix("sha256:")
                    if len(sha) == 64 and known["bytes"] is not None:
                        expected_facts.append(
                            AuthorityEvidence(
                                evidence_object_id=known["id"],
                                sha256=sha,
                                byte_count=int(known["bytes"]),
                                storage_profile=storage_profile,
                                identity=identity,
                                mount_identity=(
                                    (
                                        str(storage_row[2])
                                        if storage_row[2] is not None
                                        else None
                                    )
                                    if storage_profile
                                    is StorageProfile.EXTERNALLY_READ_ONLY
                                    else None
                                ),
                                storage_source_identity=(
                                    (
                                        str(storage_row[1])
                                        if storage_row[1] is not None
                                        else None
                                    )
                                    if storage_profile
                                    is StorageProfile.EXTERNALLY_READ_ONLY
                                    else None
                                ),
                            )
                        )
                persisted_violation_object_ids = tuple(
                    known["id"]
                    for known in sealed.values()
                    if known["authority_status"] == "violated"
                )
                classification = classify_inventory(
                    InventorySnapshot(
                        availability=(
                            StorageAvailability.UNAVAILABLE
                            if not storage_available
                            else (
                                StorageAvailability.VERIFICATION_REQUIRED
                                if str(storage_row[3]) == "FULL_VERIFY_REQUIRED"
                                or storage_row[5] != storage_row[4]
                                else StorageAvailability.AVAILABLE
                            )
                        ),
                        storage_profile=storage_profile,
                        expected=tuple(expected_facts),
                        observed=tuple(observed_facts),
                        persisted_violation_object_ids=(persisted_violation_object_ids),
                        persisted_head_violation=persisted_head_violation,
                    )
                )
                findings = [
                    {
                        "code": finding.code.value,
                        "gate_state": finding.gate_state.value,
                        "recovery": finding.recovery.value,
                        "evidence_object_id": finding.evidence_object_id,
                        "observation_id": finding.observation_id,
                        "full_verification_required": finding.full_verification_required,
                    }
                    for finding in classification.findings
                ]
                violation_reasons = {
                    DriftCode.CONTENT_CHANGED: "sealed_evidence_changed",
                    DriftCode.SEALED_EVIDENCE_MISSING: "sealed_evidence_missing",
                    DriftCode.UNSAFE_SEALED_ENTRY: "unsafe_evidence_inventory_entry",
                }
                # Persist the complete classification before latching individual
                # objects.  The classification RPC deliberately rejects a caller
                # that observes a pre-existing violation without carrying the
                # PERSISTED_VIOLATION finding.  Marking an object first makes this
                # transaction's new CONTENT_CHANGED/MISSING finding look like an
                # unacknowledged old violation and prevents Portal recovery reads.
                # Both writes remain atomic in this transaction, so admission can
                # never observe an open gate between the classification and latch.
                cur.execute(
                    "select app.evidence_record_inventory_classification_v2(%s,%s,%s,%s)",
                    (
                        case_id,
                        correlation_id,
                        classification.gate_state.value,
                        _jsonb(findings),
                    ),
                )
                for finding in classification.findings:
                    reason = violation_reasons.get(finding.code)
                    if (
                        reason
                        and finding.evidence_object_id
                        and finding.evidence_object_id
                        not in persisted_violation_object_ids
                    ):
                        self._record_admission_violation(
                            cur,
                            case_id,
                            finding.evidence_object_id,
                            reason,
                            findings,
                            correlation_id,
                        )
                        unsafe.append(reason)
            conn.commit()
        execution_authority = None
        if storage_available:
            try:
                execution_authority = self.storage_execution_authority(case_id)
            except PortalServiceError:
                storage_available = False
                unsafe.append("evidence_storage_authority_unavailable")
        return {
            "state": "available" if storage_available else "unavailable",
            "gate_state": classification.gate_state.value,
            "observed": len(live),
            "issues": sorted(set(unsafe)),
            "correlation_id": correlation_id,
            "execution_authority": execution_authority,
        }

    def storage_execution_authority(self, case_id: str) -> dict[str, Any]:
        """Return and live-check the DB-authoritative execution snapshot.

        This is Gateway-private state.  It binds execution to the current
        storage generation, manifest, successful verification receipt, source,
        mount instance, and read-only posture without exposing mount material.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select a.profile,a.source_identity,a.verified_mount_instance,
                              a.state,a.generation,a.verified_generation,a.read_only,
                              h.manifest_version,h.manifest_hash,
                              (select v.id::text from app.evidence_storage_verifications v
                               where v.case_id=a.case_id and v.outcome='SUCCESS'
                                 and v.generation=a.generation and v.profile=a.profile
                                 and v.manifest_version=h.manifest_version
                                 and v.manifest_hash=h.manifest_hash
                                 and jsonb_array_length(v.item_facts)=(select count(*)
                                   from app.evidence_objects o
                                   where o.case_id=a.case_id and o.status='sealed')
                                 and not exists(
                                   select 1 from app.evidence_objects o
                                   join app.evidence_versions ev on ev.id=o.current_version_id
                                   where o.case_id=a.case_id and o.status='sealed'
                                     and not exists(select 1
                                       from jsonb_array_elements(v.item_facts) x
                                       where (x->>'evidence_object_id')::uuid=o.id
                                         and (x->>'evidence_version_id')::uuid=ev.id
                                         and x->>'sha256'=ev.sha256
                                         and (x->>'bytes')::bigint=ev.bytes))
                               order by v.created_at desc,v.id desc limit 1),
                              (select count(*) from app.evidence_objects o
                               where o.case_id=a.case_id and o.status='sealed')
                       from app.evidence_storage_authorities a
                       join app.evidence_chain_heads h on h.case_id=a.case_id
                       where a.case_id=%s""",
                    (case_id,),
                )
                row = cur.fetchone()
        if (
            not row
            or str(row[3]) != "AVAILABLE"
            or row[5] != row[4]
            or (int(row[10] or 0) > 0 and not row[9])
        ):
            raise PortalServiceError(
                "external_storage_full_verify_required", http_status=403
            )
        profile = StorageProfile(str(row[0]))
        if profile is StorageProfile.EXTERNALLY_READ_ONLY:
            case_dir = self._case_artifact_path(case_id)
            if case_dir is None:
                raise PortalServiceError(
                    "evidence_storage_unavailable", http_status=409
                )
            root_fd: int | None = None
            try:
                root_fd = os.open(
                    case_dir / "evidence",
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_DIRECTORY
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                facts = external_storage_facts(
                    root_fd, expected_mount_path=case_dir / "evidence"
                )
            except (OSError, StorageAuthorityError) as exc:
                raise PortalServiceError(
                    "evidence_storage_unavailable", http_status=409
                ) from exc
            finally:
                if root_fd is not None:
                    os.close(root_fd)
            if (
                facts.source_identity != str(row[1])
                or facts.mount_instance_identity != str(row[2])
                or row[6] is not True
            ):
                raise PortalServiceError("evidence_posture_changed", http_status=403)
        return {
            "storage_profile": profile.value,
            "storage_source_identity": str(row[1] or ""),
            "mount_instance_identity": str(row[2] or ""),
            "storage_generation": int(row[4]),
            "storage_verified_generation": int(row[5]),
            "storage_manifest_version": int(row[7] or 0),
            "storage_manifest_hash": str(row[8] or ""),
            "storage_verification_receipt_id": str(row[9] or ""),
        }

    def revalidate_execution_authority(
        self, case_id: str, expected: dict[str, Any]
    ) -> dict[str, Any]:
        """Fail closed if DB or mounted authority changed since admission."""
        current = self.storage_execution_authority(case_id)
        if not expected or current != expected:
            raise PortalServiceError("evidence_authority_changed", http_status=403)
        return current

    @contextmanager
    def hold_execution_authority(
        self, case_id: str, expected: dict[str, Any]
    ) -> Iterator[None]:
        """Hold the shared case custody lock through descriptor pin/dispatch.

        Every custody/profile/source/Full Verify transition takes the matching
        exclusive advisory transaction lock in its Postgres RPC. Holding the
        shared form prevents such a transition from committing after the final
        authority read but before the admitted process pins its descriptors.
        """
        with self._connect() as conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "select pg_advisory_xact_lock_shared("
                        "hashtextextended(%s::text, 0))",
                        (case_id,),
                    )
                self.revalidate_execution_authority(case_id, expected)
            except PortalServiceError:
                raise
            except Exception as exc:
                raise PortalServiceError(
                    "evidence_authority_lock_unavailable", http_status=503
                ) from exc
            yield

    @staticmethod
    def _record_detected_observation(
        cur: Any,
        case_id: str,
        display_path: str,
        display_name: str,
        size: int | None,
        correlation_id: str | None,
    ) -> str:
        cur.execute(
            "select app.evidence_observe_admission(%s, %s, %s, %s, %s, null, null)",
            (case_id, display_path, display_name, size, correlation_id),
        )
        row = cur.fetchone()
        if not row or not row[0]:
            raise PortalServiceError("evidence_observation_failed", http_status=503)
        return str(row[0])

    @staticmethod
    def _record_admission_violation(
        cur: Any,
        case_id: str,
        evidence_id: str,
        reason: str,
        findings: list[dict[str, Any]],
        correlation_id: str | None,
    ) -> None:
        cur.execute(
            "select app.evidence_mark_admission_violation"
            "(%s, %s, %s, %s, %s, null, null)",
            (case_id, evidence_id, reason, _jsonb(findings), correlation_id),
        )

    def gate_status(self, case_id: str) -> dict[str, Any]:
        reconciliation = self.reconcile_for_admission(case_id)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select seal_status, manifest_version, head_hash, active_count,
                           issues, last_verified_at
                    from app.evidence_gate_status(%s)
                    """,
                    (case_id,),
                )
                row = cur.fetchone()
                cur.execute(
                    """select profile,source_identity,verified_mount_instance,state,
                              generation,verified_generation,read_only,last_full_verified_at,remediation
                       from app.evidence_storage_authorities where case_id=%s""",
                    (case_id,),
                )
                storage = cur.fetchone()
                cur.execute(
                    """
                    select display_path
                    from app.evidence_objects
                    where case_id = %s and status in ('detected', 'registered')
                    order by display_path
                    """,
                    (case_id,),
                )
                unregistered = [str(r[0]) for r in cur.fetchall()]
        incomplete = public_operation(self._custody_repository.get_incomplete(case_id))
        storage_public = {
            "storage_profile": str(storage[0]) if storage else "UNKNOWN",
            "storage_availability": str(storage[3]) if storage else "UNAVAILABLE",
            "storage_source_identity": str(storage[1])
            if storage and storage[1]
            else None,
            "storage_verified_mount_instance": (
                str(storage[2]) if storage and storage[2] else None
            ),
            "storage_generation": int(storage[4]) if storage else None,
            "storage_verified_generation": (
                int(storage[5]) if storage and storage[5] is not None else None
            ),
            "storage_read_only": (
                bool(storage[6]) if storage and storage[6] is not None else None
            ),
            "storage_last_full_verified_at": (_iso(storage[7]) if storage else None),
            "storage_remediation": str(storage[8]) if storage else "FULL_VERIFY",
        }
        if not row:
            return {
                "seal_status": "unsealed",
                "manifest_version": 0,
                "head_hash": "",
                "active_count": 0,
                "issues": [],
                "last_verified_at": None,
                "unregistered": unregistered,
                "incomplete_operation": incomplete,
                "gate_state": reconciliation["gate_state"],
                **storage_public,
            }
        return {
            "seal_status": row[0],
            "manifest_version": row[1],
            "head_hash": row[2],
            "active_count": row[3],
            "issues": row[4] if isinstance(row[4], list) else [],
            "last_verified_at": _iso(row[5]),
            "unregistered": unregistered,
            "incomplete_operation": incomplete,
            "gate_state": reconciliation["gate_state"],
            **storage_public,
        }

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        self.reconcile_for_admission(case_id)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, display_name, display_path, description, source,
                           status, seal_status, current_sha256, current_bytes,
                           registered_at, sealed_at
                    from app.evidence_objects
                    where case_id = %s
                    order by display_path
                    """,
                    (case_id,),
                )
                rows = cur.fetchall()
        return [
            {
                "evidence_id": r[0],
                "display_name": r[1],
                "display_path": r[2],
                "description": r[3],
                "source": r[4],
                "status": r[5],
                "seal_status": r[6],
                "current_sha256": r[7],
                "current_bytes": r[8],
                "registered_at": _iso(r[9]),
                "sealed_at": _iso(r[10]),
            }
            for r in rows
        ]

    def custody_events(self, case_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select seq, event_type, manifest_version, prev_hash, event_hash,
                           evidence_object_id::text, reauth_audit_event_id::text,
                           created_at
                    from app.evidence_custody_events
                    where case_id = %s
                    order by seq
                    """,
                    (case_id,),
                )
                rows = cur.fetchall()
        return [
            {
                "seq": r[0],
                "event_type": r[1],
                "manifest_version": r[2],
                "prev_hash": r[3],
                "event_hash": r[4],
                "evidence_id": r[5],
                "reauth_audit_event_id": r[6],
                "created_at": _iso(r[7]),
            }
            for r in rows
        ]

    def evidence_history(self, case_id: str, evidence_object_id: str) -> dict[str, Any]:
        """Return path-free append-only version/event history for one object."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select id::text from app.evidence_objects
                       where id=%s and case_id=%s""",
                    (evidence_object_id, case_id),
                )
                if not cur.fetchone():
                    raise PortalServiceError(
                        "evidence_object_not_found", http_status=404
                    )
                cur.execute(
                    """select id::text,manifest_version,sha256,bytes,entry_status,
                              manifest_hash,created_at,custody_operation_id::text
                       from app.evidence_versions
                       where evidence_object_id=%s and case_id=%s
                       order by manifest_version,id""",
                    (evidence_object_id, case_id),
                )
                versions = cur.fetchall()
                cur.execute(
                    """select id::text,seq,event_type,manifest_version,event_hash,
                              created_at,custody_operation_id::text
                       from app.evidence_custody_events
                       where evidence_object_id=%s and case_id=%s
                       order by seq""",
                    (evidence_object_id, case_id),
                )
                events = cur.fetchall()
        return {
            "evidence_object_id": evidence_object_id,
            "versions": [
                {
                    "evidence_version_id": str(r[0]),
                    "manifest_version": r[1],
                    "sha256": r[2],
                    "bytes": r[3],
                    "entry_status": r[4],
                    "manifest_hash": r[5],
                    "created_at": _iso(r[6]),
                    "custody_operation_id": str(r[7]) if r[7] else None,
                }
                for r in versions
            ],
            "events": [
                {
                    "event_id": str(r[0]),
                    "seq": r[1],
                    "event_type": r[2],
                    "manifest_version": r[3],
                    "event_hash": r[4],
                    "created_at": _iso(r[5]),
                    "custody_operation_id": str(r[6]) if r[6] else None,
                }
                for r in events
            ],
        }

    def resolve_evidence_reference(self, case_id: str, ref: str) -> dict[str, Any]:
        """Resolve an opaque evidence id or relative display path for worker use.

        The returned absolute path is private Gateway/worker state only. Public
        serializers must omit ``path``; the private durable-job serializer is
        expected to retain it for final descriptor binding.
        """
        self.reconcile_for_admission(case_id)
        display_path = None
        try:
            display_path = _relative_display_path(ref)
        except PortalServiceError:
            display_path = None
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select o.id::text, o.display_path, o.status, o.seal_status,
                           v.id::text, v.sha256, v.bytes, v.entry_status,
                           h.seal_status
                    from app.evidence_objects o
                    join app.evidence_versions v on v.id = o.current_version_id
                    join app.evidence_chain_heads h on h.case_id = o.case_id
                    where o.case_id = %s
                      and (o.id::text = %s or o.display_path = %s)
                    """,
                    (case_id, ref, display_path),
                )
                row = cur.fetchone()
                cur.execute(
                    """select profile,source_identity,verified_mount_instance,state,
                              generation,verified_generation,read_only
                       from app.evidence_storage_authorities where case_id=%s""",
                    (case_id,),
                )
                storage = cur.fetchone()
                cur.execute(
                    """select v.id::text,v.item_facts from app.evidence_storage_verifications v
                       join app.evidence_storage_authorities a on a.case_id=v.case_id
                       join app.evidence_chain_heads h on h.case_id=v.case_id
                       where v.case_id=%s and v.outcome='SUCCESS'
                         and v.generation=a.generation and v.profile=a.profile
                         and v.manifest_version=h.manifest_version
                         and v.manifest_hash=h.manifest_hash
                         and jsonb_array_length(v.item_facts)=(select count(*)
                           from app.evidence_objects o
                           where o.case_id=v.case_id and o.status='sealed')
                         and not exists(
                           select 1 from app.evidence_objects o
                           join app.evidence_versions ev on ev.id=o.current_version_id
                           where o.case_id=v.case_id and o.status='sealed'
                             and not exists(select 1 from jsonb_array_elements(v.item_facts) x
                               where (x->>'evidence_object_id')::uuid=o.id
                                 and (x->>'evidence_version_id')::uuid=ev.id
                                 and x->>'sha256'=ev.sha256
                                 and (x->>'bytes')::bigint=ev.bytes))
                       order by v.created_at desc,v.id desc limit 1""",
                    (case_id,),
                )
                verification_row = cur.fetchone()
        if not row:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        if (
            row[2] != "sealed"
            or row[3] != "sealed"
            or row[7] != "ACTIVE"
            or row[8] != "sealed"
        ):
            raise PortalServiceError("evidence_object_not_sealed", http_status=403)
        path = self._resolve_evidence_path(case_id, str(row[1]))
        if not storage:
            raise PortalServiceError(
                "evidence_storage_authority_unavailable", http_status=503
            )
        profile = StorageProfile(str(storage[0]))
        execution_authority = self.storage_execution_authority(case_id)
        verification_items = (
            verification_row[1]
            if verification_row and isinstance(verification_row[1], list)
            else []
        )
        verified_item = next(
            (
                item
                for item in verification_items
                if isinstance(item, dict)
                and str(item.get("evidence_object_id")) == str(row[0])
                and str(item.get("evidence_version_id")) == str(row[4])
            ),
            None,
        )
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise PortalServiceError("evidence_identity_unsafe", http_status=403)
            immutable = None
            external = None
            if profile is StorageProfile.LOCAL_IMMUTABLE:
                from sift_core.evidence_chain import get_immutable_flag_fd

                immutable = get_immutable_flag_fd(fd)
            else:
                try:
                    external = external_storage_facts(fd)
                except StorageAuthorityError as exc:
                    raise PortalServiceError(
                        "evidence_posture_changed", http_status=403
                    ) from exc
        finally:
            os.close(fd)
        if row[6] is not None and st.st_size != int(row[6]):
            raise PortalServiceError("evidence_version_changed", http_status=403)
        immutable_required = (
            profile is StorageProfile.LOCAL_IMMUTABLE
            and sys.platform.startswith("linux")
        )
        if immutable_required and immutable is not True:
            raise PortalServiceError("evidence_posture_changed", http_status=403)
        if profile is StorageProfile.EXTERNALLY_READ_ONLY and (
            str(storage[3]) != "AVAILABLE"
            or storage[5] != storage[4]
            or external is None
            or external.source_identity != str(storage[1])
            or external.mount_instance_identity != str(storage[2])
            or not isinstance(verified_item, dict)
            or not verification_row
            or str(verification_row[0])
            != execution_authority["storage_verification_receipt_id"]
            or (
                st.st_dev,
                st.st_ino,
                st.st_size,
                st.st_mtime_ns,
                st.st_ctime_ns,
                st.st_nlink,
            )
            != (
                int(verified_item.get("st_dev", -1)),
                int(verified_item.get("st_ino", -1)),
                int(verified_item.get("bytes", -1)),
                int(verified_item.get("st_mtime_ns", -1)),
                int(verified_item.get("st_ctime_ns", -1)),
                int(verified_item.get("st_nlink", -1)),
            )
            or str(verified_item.get("sha256")) != str(row[5])
            or str(verified_item.get("storage_source_identity")) != str(storage[1])
            or str(verified_item.get("mount_instance_identity")) != str(storage[2])
        ):
            raise PortalServiceError(
                "external_storage_full_verify_required", http_status=403
            )
        return {
            "evidence_id": str(row[0]),
            "version_id": str(row[4]),
            "display_path": str(row[1]),
            "path": path,
            "sha256": str(row[5]),
            "bytes": st.st_size,
            "st_dev": st.st_dev,
            "st_ino": st.st_ino,
            "st_mtime_ns": st.st_mtime_ns,
            "st_ctime_ns": st.st_ctime_ns,
            "immutable_required": immutable_required,
            "storage_profile": profile.value,
            "storage_source_identity": (
                external.source_identity if external is not None else ""
            ),
            "mount_instance_identity": (
                external.mount_instance_identity if external is not None else ""
            ),
            "read_only_required": profile is StorageProfile.EXTERNALLY_READ_ONLY,
            "storage_generation": execution_authority["storage_generation"],
            "storage_verified_generation": execution_authority[
                "storage_verified_generation"
            ],
            "storage_manifest_version": execution_authority["storage_manifest_version"],
            "storage_manifest_hash": execution_authority["storage_manifest_hash"],
            "storage_verification_receipt_id": execution_authority[
                "storage_verification_receipt_id"
            ],
        }

    def record_reauth_event(
        self,
        *,
        case_id: str,
        actor: Any,
        examiner: str,
        action: str,
        binding: dict[str, Any] | None = None,
    ) -> str | None:
        actor_type, actor_user, actor_agent, actor_service = _actor_columns(actor)
        details: dict[str, Any] = {"examiner": examiner, "action": action}
        if binding is not None:
            details["binding"] = binding
        with self._connect() as conn:
            with conn.cursor() as cur:
                if binding is not None:
                    lock_material = json.dumps(
                        {
                            "case_id": case_id,
                            "action": action,
                            "actor_type": actor_type,
                            "actor_user": actor_user,
                            "actor_service": actor_service,
                            "idempotency_key": binding.get("idempotency_key"),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    cur.execute(
                        "select pg_advisory_xact_lock(hashtextextended(%s, 0))",
                        (lock_material,),
                    )
                    cur.execute(
                        """
                        select id::text, details
                        from app.audit_events
                        where case_id = %s and event_type = %s
                          and source = 'portal_reauth'
                          and actor_type = %s
                          and actor_user_id is not distinct from %s
                          and actor_service_identity_id is not distinct from %s
                          and details->'binding'->>'idempotency_key' = %s
                        order by created_at desc limit 1
                        """,
                        (
                            case_id,
                            f"reauth.{action}",
                            actor_type,
                            actor_user,
                            actor_service,
                            str(binding.get("idempotency_key") or ""),
                        ),
                    )
                    existing = cur.fetchone()
                    if existing:
                        if existing[1] != details:
                            raise PortalServiceError(
                                "idempotency_key_reused", http_status=409
                            )
                        return str(existing[0])
                cur.execute(
                    """
                    insert into app.audit_events
                      (case_id, event_type, actor_type, actor_user_id,
                       actor_agent_id, actor_service_identity_id, source,
                       status, summary, details)
                    values (%s, %s, %s, %s, %s, %s, 'portal_reauth',
                            'success', %s, %s)
                    returning id::text
                    """,
                    (
                        case_id,
                        f"reauth.{action}",
                        actor_type,
                        actor_user,
                        actor_agent,
                        actor_service,
                        f"operator re-auth for {action}",
                        _jsonb(details),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0]) if row and row[0] else None

    def seal(
        self,
        *,
        case_id: str,
        file_specs: list[dict[str, Any]],
        reason: str,
        idempotency_key: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
        storage_profile: str = StorageProfile.LOCAL_IMMUTABLE.value,
        command_schema_version: int = 3,
        resume_reauth_audit_event_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate the Portal command, then delegate the durable operation."""
        reason = " ".join(reason.split())
        idempotency_key = idempotency_key.strip()
        if not reason:
            raise PortalServiceError("seal_reason_required", http_status=400)
        if not idempotency_key or len(idempotency_key) > 128:
            raise PortalServiceError("seal_idempotency_key_required", http_status=400)
        if not reauth_audit_event_id:
            raise PortalServiceError("seal_requires_reauth", http_status=403)
        if not file_specs or len(file_specs) > 1000:
            raise PortalServiceError("seal_requires_items", http_status=400)
        try:
            profile = StorageProfile(storage_profile)
        except ValueError as exc:
            raise PortalServiceError(
                "invalid_storage_profile", http_status=400
            ) from exc

        allowed_spec_keys = {"path", "description", "source"}
        normalized_specs: list[dict[str, str | None]] = []
        seen_paths: set[str] = set()
        for spec in file_specs:
            if not isinstance(spec, dict) or set(spec) - allowed_spec_keys:
                raise PortalServiceError("invalid_seal_file_spec", http_status=400)
            display_path = _relative_display_path(str(spec.get("path") or ""))
            if len(display_path) > 1024:
                raise PortalServiceError("evidence_path_too_long", http_status=400)
            if display_path in seen_paths:
                raise PortalServiceError("duplicate_seal_path", http_status=400)
            seen_paths.add(display_path)
            description = str(spec.get("description") or "")
            source = str(spec.get("source") or "")
            if len(description) > 1000 or len(source) > 500:
                raise PortalServiceError("evidence_metadata_too_long", http_status=400)
            normalized_specs.append(
                {
                    "path": display_path,
                    "description": description or None,
                    "source": source or None,
                }
            )
        normalized_specs.sort(key=lambda item: str(item["path"]))

        self._scan_evidence(case_id)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        command = SealCommand(
            case_id=case_id,
            file_specs=tuple(normalized_specs),
            actor_user_id=actor_user,
            actor_service_identity_id=actor_service,
            reason=reason,
            reauth_audit_event_id=reauth_audit_event_id,
            idempotency_key=idempotency_key,
            storage_profile=profile,
            schema_version=command_schema_version,
            resume_reauth_audit_event_id=resume_reauth_audit_event_id,
        )
        try:
            result = SealCustodyOperation(
                self._custody_repository,
                (
                    self._posture_adapter
                    if profile is StorageProfile.LOCAL_IMMUTABLE
                    else self._external_posture_adapter
                ),
                self._case_artifact_path,
                self._seal_object_for_path,
                self._seal_expected_root_paths,
            ).execute(command, examiner=examiner)
            return self._finalize_custody_result(result)
        except CustodyOperationError as exc:
            raise PortalServiceError(exc.reason, http_status=exc.http_status) from exc

    def resume_seal(
        self,
        *,
        case_id: str,
        operation_id: str,
        actor: Any,
        examiner: str,
        resume_reauth_audit_event_id: str,
    ) -> dict[str, Any]:
        """Resume one path-free incomplete Add/Seal operation after fresh Portal re-auth."""
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        if actor_type != "user" or not actor_user or actor_service:
            raise PortalServiceError("seal_resume_actor_mismatch", http_status=403)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select command,reason,idempotency_key,reauth_audit_event_id::text,
                              actor_user_id::text,actor_service_identity_id::text
                       from app.custody_operations
                       where id=%s and case_id=%s and action='ADD_SEAL'
                         and phase=any(%s)""",
                    (
                        operation_id,
                        case_id,
                        [phase.value for phase in RESUMABLE_SEAL_PHASES],
                    ),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("custody_operation_not_resumable", http_status=404)
        if str(row[4] or "") != actor_user or row[5] is not None:
            raise PortalServiceError("seal_resume_actor_mismatch", http_status=403)
        command = row[0] if isinstance(row[0], dict) else {}
        files = command.get("files") if isinstance(command, dict) else None
        schema_version = command.get("schema_version")
        storage_profile = str(
            command.get("storage_profile")
            or (StorageProfile.LOCAL_IMMUTABLE.value if schema_version == 1 else "")
        )
        if (
            command.get("action") != "ADD_SEAL"
            or schema_version not in {1, 3}
            or storage_profile not in {profile.value for profile in StorageProfile}
            or (
                schema_version == 1
                and storage_profile != StorageProfile.LOCAL_IMMUTABLE
            )
            or not isinstance(files, list)
        ):
            raise PortalServiceError(
                "custody_operation_command_invalid", http_status=409
            )
        return self.seal(
            case_id=case_id,
            file_specs=files,
            reason=str(row[1] or ""),
            idempotency_key=str(row[2] or ""),
            reauth_audit_event_id=str(row[3] or ""),
            actor=actor,
            examiner=examiner,
            storage_profile=storage_profile,
            command_schema_version=int(schema_version),
            resume_reauth_audit_event_id=resume_reauth_audit_event_id,
        )

    def _seal_object_for_path(self, case_id: str, display_path: str) -> dict[str, Any]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select id::text, status from app.evidence_objects
                       where case_id = %s and display_path = %s""",
                    (case_id, display_path),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        return {"evidence_object_id": str(row[0]), "status": str(row[1])}

    def _seal_expected_root_paths(
        self, case_id: str, selected_paths: list[str]
    ) -> tuple[list[str], list[str]]:
        """Resolve required current paths and optional retired history."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select display_path,status from app.evidence_objects
                       where case_id=%s and status in ('sealed','ignored','retired')
                       order by display_path""",
                    (case_id,),
                )
                rows = [(str(row[0]), str(row[1])) for row in cur.fetchall()]
        required = set(selected_paths)
        required.update(
            path for path, status in rows if status in ("sealed", "ignored")
        )
        optional = {
            path
            for path, status in rows
            if status == "retired" and path not in required
        }
        return sorted(required), sorted(optional)

    def _harden_sealed_files(
        self, case_id: str, file_specs: list[dict[str, Any]]
    ) -> None:
        """Apply the service-owned + immutable FS posture to the sealed files.

        Resolves the case dir, derives case-relative paths, and delegates to
        ``sift_core.evidence_chain.harden_sealed_evidence`` which re-validates each
        path inside ``evidence/`` and fails closed if immutability cannot be set.
        Maps any hardening failure to a fail-closed seal error so the DB seal is
        never written for un-hardened bytes.
        """
        from sift_core.evidence_chain import (
            EvidenceHardeningError,
            harden_sealed_evidence,
        )

        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            raise PortalServiceError("case_artifact_path_unavailable", http_status=404)
        rel_paths = [
            _relative_display_path(str(spec.get("path") or "")) for spec in file_specs
        ]
        service_user = os.environ.get("SIFT_GATEWAY_SERVICE_USER", "sift-service")
        try:
            harden_sealed_evidence(case_dir, rel_paths, service_user=service_user)
        except EvidenceHardeningError as exc:
            logger.error("evidence seal hardening failed for case %s: %s", case_id, exc)
            raise PortalServiceError(
                "evidence_immutability_failed", http_status=500
            ) from exc

    def _recovery_object_for_id(
        self, case_id: str, evidence_object_id: str
    ) -> dict[str, Any]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select id::text,display_path,status,current_version_id::text,
                              current_sha256,current_bytes,seal_status
                       from app.evidence_objects
                       where id=%s and case_id=%s""",
                    (evidence_object_id, case_id),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        return {
            "evidence_object_id": str(row[0]),
            "display_path": str(row[1]),
            "status": str(row[2]),
            "current_version_id": str(row[3]) if row[3] else None,
            "current_sha256": str(row[4]) if row[4] else None,
            "current_bytes": int(row[5]) if row[5] is not None else None,
            "seal_status": str(row[6]),
        }

    def _execute_disposition(
        self,
        *,
        case_id: str,
        display_path: str,
        action: CustodyAction,
        reason: str,
        idempotency_key: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        if actor_type != "user" or not actor_user or actor_service:
            raise PortalServiceError("disposition_actor_required", http_status=403)
        path = _relative_display_path(display_path)
        evidence_object_id = self._evidence_id_for_path(case_id, path)
        if not evidence_object_id:
            self._scan_evidence(case_id)
            evidence_object_id = self._evidence_id_for_path(case_id, path)
        if not evidence_object_id:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        command = ObjectCustodyCommand(
            action=action,
            case_id=case_id,
            evidence_object_id=evidence_object_id,
            actor_user_id=actor_user,
            actor_service_identity_id=None,
            reason=reason,
            reauth_audit_event_id=reauth_audit_event_id,
            idempotency_key=idempotency_key,
        )
        try:
            result = DispositionCustodyOperation(
                self._custody_repository,
                self._case_artifact_path,
                self._recovery_object_for_id,
            ).execute(command, examiner=examiner)
            return self._finalize_custody_result(result)
        except CustodyOperationError as exc:
            raise PortalServiceError(exc.reason, http_status=exc.http_status) from exc

    def disposition_operation_action(self, *, case_id: str, operation_id: str) -> str:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select action from app.custody_operations
                       where id=%s and case_id=%s
                         and action in ('IGNORE','DELETE_STRAY','RETIRE')""",
                    (operation_id, case_id),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("custody_operation_not_found", http_status=404)
        return str(row[0])

    def resume_disposition(
        self,
        *,
        case_id: str,
        operation_id: str,
        actor: Any,
        examiner: str,
        resume_reauth_audit_event_id: str,
    ) -> dict[str, Any]:
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        if actor_type != "user" or not actor_user or actor_service:
            raise PortalServiceError("disposition_actor_required", http_status=403)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select command,reason,idempotency_key,reauth_audit_event_id::text,
                              actor_user_id::text,actor_service_identity_id::text,action
                       from app.custody_operations
                       where id=%s and case_id=%s
                         and action in ('IGNORE','DELETE_STRAY','RETIRE')
                         and phase=any(%s)""",
                    (
                        operation_id,
                        case_id,
                        [phase.value for phase in RESUMABLE_SEAL_PHASES],
                    ),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("custody_operation_not_resumable", http_status=404)
        if str(row[4] or "") != actor_user or row[5] is not None:
            raise PortalServiceError("disposition_actor_required", http_status=403)
        stored = row[0] if isinstance(row[0], dict) else {}
        evidence_object_id = str(stored.get("evidence_object_id") or "")
        try:
            action = CustodyAction(str(row[6]))
            if action not in (
                CustodyAction.IGNORE,
                CustodyAction.DELETE_STRAY,
                CustodyAction.RETIRE,
            ):
                raise ValueError("stored disposition action invalid")
            command = ObjectCustodyCommand(
                action=action,
                case_id=case_id,
                evidence_object_id=evidence_object_id,
                actor_user_id=actor_user,
                actor_service_identity_id=None,
                reason=str(row[1] or ""),
                reauth_audit_event_id=str(row[3] or ""),
                idempotency_key=str(row[2] or ""),
                resume_reauth_audit_event_id=resume_reauth_audit_event_id,
            )
            resumed = self._custody_repository.resume_disposition(
                operation_id,
                actor_user_id=actor_user,
                resume_reauth_audit_event_id=resume_reauth_audit_event_id,
            )
            result = DispositionCustodyOperation(
                self._custody_repository,
                self._case_artifact_path,
                self._recovery_object_for_id,
            ).execute(command, examiner=examiner, resumed_operation=resumed)
            return self._finalize_custody_result(result)
        except (CustodyOperationError, ValueError) as exc:
            reason = (
                exc.reason
                if isinstance(exc, CustodyOperationError)
                else "custody_operation_command_invalid"
            )
            status = exc.http_status if isinstance(exc, CustodyOperationError) else 409
            raise PortalServiceError(reason, http_status=status) from exc

    def recovery_object_id(self, *, case_id: str, display_path: str) -> str:
        """Resolve a Portal display path to the server-authoritative object ID."""
        evidence_object_id = self._evidence_id_for_path(
            case_id, _relative_display_path(display_path)
        )
        if not evidence_object_id:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        return evidence_object_id

    def recovery_operation_action(self, *, case_id: str, operation_id: str) -> str:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select action from app.custody_operations
                       where id=%s and case_id=%s
                         and action in ('REPLACE_REACQUIRE','RESTORE_EXACT')""",
                    (operation_id, case_id),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("custody_operation_not_found", http_status=404)
        return str(row[0])

    def begin_recovery(
        self,
        *,
        case_id: str,
        display_path: str,
        action: CustodyAction | str,
        reason: str,
        idempotency_key: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        """Begin one durable Replace/Reacquire or exact Restore operation."""
        try:
            action = CustodyAction(action)
        except (TypeError, ValueError) as exc:
            raise PortalServiceError(
                "recovery_action_required", http_status=400
            ) from exc
        if action not in (CustodyAction.REPLACE_REACQUIRE, CustodyAction.RESTORE_EXACT):
            raise PortalServiceError("recovery_action_required", http_status=400)
        normalized_reason = " ".join(reason.split())
        if not 1 <= len(normalized_reason) <= 1000:
            raise PortalServiceError("recovery_reason_required", http_status=400)
        if not 1 <= len(idempotency_key.strip()) <= 128:
            raise PortalServiceError(
                "recovery_idempotency_key_required", http_status=400
            )
        rel = _relative_display_path(display_path)
        evidence_object_id = self._evidence_id_for_path(case_id, rel)
        if not evidence_object_id:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        if actor_type != "user" or not actor_user or actor_service:
            raise PortalServiceError("recovery_actor_required", http_status=403)
        command = ObjectCustodyCommand(
            action=action,
            case_id=case_id,
            evidence_object_id=evidence_object_id,
            actor_user_id=actor_user,
            actor_service_identity_id=None,
            reason=normalized_reason,
            reauth_audit_event_id=reauth_audit_event_id,
            idempotency_key=idempotency_key.strip(),
        )
        try:
            result = RecoveryCustodyOperation(
                self._custody_repository,
                self._case_artifact_path,
                self._recovery_object_for_id,
            ).begin(command, examiner=examiner)
            return result
        except CustodyOperationError as exc:
            raise PortalServiceError(exc.reason, http_status=exc.http_status) from exc

    def complete_recovery(
        self,
        *,
        case_id: str,
        operation_id: str,
        completion_reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        """Hash, re-protect, and atomically finalize one blocked recovery."""
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        if actor_type != "user" or not actor_user or actor_service:
            raise PortalServiceError("recovery_actor_required", http_status=403)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select 1 from app.custody_operations
                       where id=%s and case_id=%s
                         and action in ('REPLACE_REACQUIRE','RESTORE_EXACT')""",
                    (operation_id, case_id),
                )
                if not cur.fetchone():
                    raise PortalServiceError(
                        "custody_operation_not_found", http_status=404
                    )
        try:
            result = RecoveryCustodyOperation(
                self._custody_repository,
                self._case_artifact_path,
                self._recovery_object_for_id,
            ).complete(
                operation_id,
                actor_user_id=actor_user,
                completion_reauth_audit_event_id=completion_reauth_audit_event_id,
                examiner=examiner,
            )
            return self._finalize_custody_result(result)
        except CustodyOperationError as exc:
            raise PortalServiceError(exc.reason, http_status=exc.http_status) from exc

    def ignore(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        return self._execute_disposition(
            case_id=case_id,
            display_path=display_path,
            action=CustodyAction.IGNORE,
            reason=reason,
            idempotency_key=idempotency_key or f"ignore:{reauth_audit_event_id}",
            reauth_audit_event_id=reauth_audit_event_id,
            actor=actor,
            examiner=examiner,
        )

    def retire(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        return self._execute_disposition(
            case_id=case_id,
            display_path=display_path,
            action=CustodyAction.RETIRE,
            reason=reason,
            idempotency_key=idempotency_key or f"retire:{reauth_audit_event_id}",
            reauth_audit_event_id=reauth_audit_event_id,
            actor=actor,
            examiner=examiner,
        )

    def delete_object(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        """Delete a non-sealed stray through the durable custody operation.

        The operation blocks admission before pinning and hashing the directory
        entry, then unlinks only that same inode. The recorded pre-unlink digest,
        size, and identity are committed append-only. Sealed evidence is never
        eligible; Retire preserves its bytes and version history.
        """
        return self._execute_disposition(
            case_id=case_id,
            display_path=display_path,
            action=CustodyAction.DELETE_STRAY,
            reason=reason,
            idempotency_key=idempotency_key or f"delete:{reauth_audit_event_id}",
            reauth_audit_event_id=reauth_audit_event_id,
            actor=actor,
            examiner=examiner,
        )

    def _scan_evidence(self, case_id: str) -> None:
        """Legacy full-tree reconciliation used by operator verification paths.

        Two responsibilities, both DB-first:

        - Newly appeared files under ``evidence/`` are recorded via
          ``app.evidence_detect`` (idempotent). A new ``detected`` row keeps the
          aggregate seal status non-OK until the operator registers/ignores and
          reseals, so a post-seal addition fails the gate closed.
        - Sealed files that have gone missing or changed bytes on disk are
          escalated through the DB violation authority. Admission uses
          ``reconcile_for_admission`` and the closed drift classifier instead.

        File proofs (manifest/ledger/anchor JSON) are not read here; tampering
        with them cannot change the DB-active gate state.
        """
        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            return
        evidence_dir = case_dir / "evidence"
        if not evidence_dir.is_dir():
            return
        live: dict[str, int] = {}
        with self._connect() as conn:
            with conn.cursor() as cur:
                # Detection includes hidden entries so operator inventory remains
                # a superset of the gateway's evidence-reference admission surface.
                for path in sorted(evidence_dir.rglob("*")):
                    if path.is_symlink() or not path.is_file():
                        continue
                    rel = path.relative_to(case_dir).as_posix()
                    try:
                        size = path.stat().st_size
                    except OSError:
                        continue
                    live[rel] = size
                    cur.execute(
                        "select app.evidence_detect(%s, %s, %s, %s, null, null)",
                        (case_id, rel, path.name, size),
                    )
            conn.commit()
        self._detect_seal_tamper(case_id, live)

    def _detect_seal_tamper(self, case_id: str, live: dict[str, int]) -> None:
        """Mark a case violated when a sealed evidence item is missing/modified.

        ``live`` maps the relative display path to its current byte size on the
        mounted tree. A sealed object whose file is absent (missing) or whose
        size differs from the sealed ``current_bytes`` (modified) is a custody
        violation. We do not re-hash here (stat-check, matching the file gate's
        fast path); a full re-hash happens at proof export. Idempotent: once the
        case is already ``violated`` we do not append duplicate violation events.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select coalesce(seal_status, 'unsealed') "
                    "from app.evidence_gate_status(%s)",
                    (case_id,),
                )
                head = cur.fetchone()
                if head and head[0] == "violated":
                    return
                cur.execute(
                    """
                    select id::text, display_path, current_bytes
                    from app.evidence_objects
                    where case_id = %s and status = 'sealed' and seal_status = 'sealed'
                    """,
                    (case_id,),
                )
                sealed = cur.fetchall()
                issues: list[str] = []
                offenders: list[tuple[str, str]] = []
                for obj_id, display_path, sealed_bytes in sealed:
                    rel = str(display_path)
                    if rel not in live:
                        issues.append(f"Missing: {rel}")
                        offenders.append((str(obj_id), rel))
                    elif sealed_bytes is not None and live[rel] != int(sealed_bytes):
                        issues.append(f"Modified: {rel}")
                        offenders.append((str(obj_id), rel))
                if not offenders:
                    return
                for obj_id, _rel in offenders:
                    cur.execute(
                        "select app.evidence_mark_violation(%s, %s, %s, %s, null, null)",
                        (
                            case_id,
                            obj_id,
                            "sealed_evidence_changed_or_missing",
                            _jsonb(issues),
                        ),
                    )
            conn.commit()

    def verify(
        self,
        *,
        case_id: str,
        actor: Any = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Re-verify sealed evidence against mounted bytes and record the outcome.

        Re-hashes every sealed object's mounted file and compares against the
        sealed ``current_sha256``. Records the result through ``app.evidence_verify``
        (which escalates to ``violated`` on failure). Returns the chain-head dict.
        DB is the authority; no file manifest/ledger is consulted.
        """
        actor_type, actor_user, _actor_agent, _actor_service = _actor_columns(actor)
        del actor_type
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select a.profile,a.generation,h.manifest_version,h.manifest_hash
                       from app.evidence_storage_authorities a
                       join app.evidence_chain_heads h on h.case_id=a.case_id
                       where a.case_id=%s""",
                    (case_id,),
                )
                authority = cur.fetchone()
                cur.execute(
                    """select o.id::text,o.display_path,v.id::text,v.sha256,v.bytes
                       from app.evidence_objects o join app.evidence_versions v
                         on v.id=o.current_version_id
                       where o.case_id=%s and o.status='sealed' order by o.id""",
                    (case_id,),
                )
                sealed = cur.fetchall()
        if not authority:
            raise PortalServiceError(
                "evidence_storage_authority_unavailable", http_status=503
            )
        if not sealed or int(authority[2] or 0) <= 0 or not authority[3]:
            # Full Verify proves an already committed active manifest.  Initial
            # external intake belongs to Add & Seal, which hashes the complete
            # target set and atomically binds its first source/mount receipt.
            # Reject here before touching a posture adapter or writing either a
            # success or failure verification receipt.
            raise PortalServiceError(
                "full_verify_requires_sealed_evidence", http_status=409
            )
        profile = StorageProfile(str(authority[0]))
        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            raise PortalServiceError("evidence_storage_unavailable", http_status=409)
        adapter: LocalImmutablePostureProtocol = (
            self._posture_adapter
            if profile is StorageProfile.LOCAL_IMMUTABLE
            else self._external_posture_adapter
        )
        correlation_id = f"full-verify:{uuid.uuid4().hex}"
        try:
            batch = adapter.prepare(case_dir, [str(row[1]) for row in sealed])
        except Exception:
            failure_code = self._storage_verify_failure_code(case_dir, profile)
            self._record_storage_verify_failure(
                case_id=case_id,
                generation=int(authority[1]),
                profile=profile,
                manifest_version=int(authority[2] or 0),
                manifest_hash=str(authority[3] or ""),
                failure_code=failure_code,
                correlation_id=correlation_id,
                actor_user_id=actor_user,
                note=note,
            )
            raise
        try:
            try:
                receipts = adapter.verify(batch)
            except Exception:
                failure_code = self._storage_verify_failure_code(case_dir, profile)
                self._record_storage_verify_failure(
                    case_id=case_id,
                    generation=int(authority[1]),
                    profile=profile,
                    manifest_version=int(authority[2] or 0),
                    manifest_hash=str(authority[3] or ""),
                    failure_code=failure_code,
                    correlation_id=correlation_id,
                    actor_user_id=actor_user,
                    note=note,
                )
                raise
        finally:
            adapter.close(batch)
        expected = {str(row[1]): row for row in sealed}
        items: list[dict[str, Any]] = []
        issues: list[str] = []
        for receipt in receipts:
            row = expected.get(str(receipt.get("path")))
            if (
                not row
                or receipt.get("sha256") != row[3]
                or int(receipt.get("bytes", -1)) != int(row[4])
            ):
                issues.append("mounted_evidence_digest_mismatch")
                continue
            items.append(
                {
                    **receipt,
                    "evidence_object_id": str(row[0]),
                    "evidence_version_id": str(row[2]),
                }
            )
        ok = not issues and len(items) == len(sealed)
        manifest_version = int(authority[2] or 0)
        if ok:
            source_identity = (
                str(items[0].get("storage_source_identity"))
                if items and profile is StorageProfile.EXTERNALLY_READ_ONLY
                else None
            )
            mount_instance = (
                str(items[0].get("mount_instance_identity"))
                if items and profile is StorageProfile.EXTERNALLY_READ_ONLY
                else None
            )
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """select app.evidence_storage_commit_full_verify(
                             %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            case_id,
                            int(authority[1]),
                            profile.value,
                            source_identity,
                            mount_instance,
                            True
                            if profile is StorageProfile.EXTERNALLY_READ_ONLY
                            else None,
                            manifest_version,
                            _jsonb(items),
                            correlation_id,
                            actor_user,
                            note,
                        ),
                    )
                conn.commit()
        else:
            self._record_storage_verify_failure(
                case_id=case_id,
                generation=int(authority[1]),
                profile=profile,
                manifest_version=manifest_version,
                manifest_hash=str(authority[3] or ""),
                failure_code="MOUNTED_EVIDENCE_MISMATCH",
                correlation_id=correlation_id,
                actor_user_id=actor_user,
                note=note,
            )
        result = self.gate_status(case_id)
        # ``issues`` above are local hashing failures. The gate status carries
        # the authoritative structured custody issues after the success/failure
        # receipt and immediate reconciliation; never replace those with an
        # empty local list and report a misleading green recovery.
        result["verification_issues"] = issues
        result["verified"] = bool(
            ok
            and result.get("seal_status") == "sealed"
            and result.get("gate_state") == "OPEN"
            and not result.get("issues")
        )
        return result

    @staticmethod
    def _storage_verify_failure_code(case_dir: Path, profile: StorageProfile) -> str:
        if profile is StorageProfile.LOCAL_IMMUTABLE:
            return "FULL_VERIFY_FAILED"
        root_fd: int | None = None
        try:
            root_fd = os.open(
                case_dir / "evidence",
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0),
            )
            facts = external_storage_facts(
                root_fd,
                require_read_only=False,
                expected_mount_path=case_dir / "evidence",
            )
            return "FULL_VERIFY_FAILED" if facts.read_only else "READ_WRITE_DRIFT"
        except (OSError, StorageAuthorityError):
            return "STORAGE_UNAVAILABLE"
        finally:
            if root_fd is not None:
                os.close(root_fd)

    def _record_storage_verify_failure(
        self,
        *,
        case_id: str,
        generation: int,
        profile: StorageProfile,
        manifest_version: int,
        manifest_hash: str,
        failure_code: str,
        correlation_id: str,
        actor_user_id: str | None,
        note: str | None = None,
    ) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select app.evidence_storage_record_verify_failure(
                         %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        case_id,
                        generation,
                        profile.value,
                        manifest_version,
                        manifest_hash,
                        failure_code,
                        correlation_id,
                        actor_user_id,
                        note,
                    ),
                )
            conn.commit()

    def _reverify_sealed(self, case_id: str) -> tuple[bool, list[str], int]:
        """Full re-hash of sealed objects vs. their sealed DB hash.

        Returns (ok, issues, manifest_version). ok is False on any
        missing/modified file. Used by verify() and export_proof().
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select coalesce(manifest_version, 0) "
                    "from app.evidence_gate_status(%s)",
                    (case_id,),
                )
                head = cur.fetchone()
                manifest_version = int(head[0]) if head else 0
                cur.execute(
                    """
                    select display_path, current_sha256, current_bytes
                    from app.evidence_objects
                    where case_id = %s and status = 'sealed' and seal_status = 'sealed'
                    order by display_path
                    """,
                    (case_id,),
                )
                sealed = cur.fetchall()
        issues: list[str] = []
        for display_path, sealed_sha, sealed_bytes in sealed:
            rel = str(display_path)
            try:
                path = self._resolve_evidence_path(case_id, rel)
            except PortalServiceError:
                issues.append(f"Missing: {rel}")
                continue
            actual_sha, actual_bytes = _hash_file(path)
            if (
                sealed_bytes is not None
                and actual_bytes != int(sealed_bytes)
                or sealed_sha
                and f"sha256:{actual_sha}" != str(sealed_sha)
            ):
                issues.append(f"Modified: {rel}")
        return (not issues, issues, manifest_version)

    def verify_ledger(self, *, case_id: str) -> dict[str, Any]:
        """Fast DB-only chain/checkpoint verification; never reads evidence bytes."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select valid,issue_code,event_count,head_hash from app.evidence_verify_signed_ledger(%s)",
                    (case_id,),
                )
                chain_check = cur.fetchone()
                cur.execute(
                    """select seq,prev_hash,event_hash from app.evidence_custody_events
                       where case_id=%s order by seq""",
                    (case_id,),
                )
                events = cur.fetchall()
                cur.execute(
                    "select head_seq,head_hash from app.evidence_chain_heads where case_id=%s",
                    (case_id,),
                )
                head = cur.fetchone()
                cur.execute(
                    """select canonical_payload,key_id,signature,k.public_key
                       from app.custody_signature_checkpoints c
                       left join app.custody_signing_keys k on k.key_id=c.key_id
                       where c.case_id=%s and c.state='SIGNED'
                       order by c.signed_at desc limit 1""",
                    (case_id,),
                )
                checkpoint = cur.fetchone()
        issues: list[str] = []
        if not chain_check or not bool(chain_check[0]):
            issues.append(
                str(chain_check[1])
                if chain_check and chain_check[1]
                else "CUSTODY_LEDGER_CHAIN_INVALID"
            )
        previous = ""
        for expected_seq, row in enumerate(events, start=1):
            if int(row[0]) != expected_seq or str(row[1] or "") != previous:
                issues.append("CUSTODY_LEDGER_CHAIN_INVALID")
                break
            previous = str(row[2] or "")
        if not head or int(head[0] or 0) != len(events) or str(head[1] or "") != previous:
            issues.append("CUSTODY_LEDGER_HEAD_INVALID")
        current_head_hash = str(head[1] or "") if head else ""
        key_id: str | None = None
        if checkpoint:
            payload, key_id, signature, public_key = checkpoint
            try:
                verify_bundle(
                    {
                        "format": "sift-custody-proof/v1",
                        "payload": payload if isinstance(payload, dict) else {},
                        "signature": {
                            "algorithm": "Ed25519", "key_id": str(key_id),
                            "public_key": str(public_key), "value": str(signature),
                        },
                    },
                    trusted_keys={str(key_id): str(public_key)},
                )
                if (
                    str(payload.get("case_id") or "") != case_id
                    or str(payload.get("ledger_tip_hash") or "") != current_head_hash
                    or int(payload.get("manifest_version") or -1) != int(
                        self._ledger_manifest_version(case_id)
                    )
                ):
                    issues.append("CUSTODY_SIGNATURE_CHECKPOINT_STALE")
            except CustodyProofError:
                issues.append("CUSTODY_SIGNATURE_INVALID")
        else:
            issues.append("CUSTODY_SIGNATURE_CHECKPOINT_MISSING")
        return {"verified": not issues, "issues": issues, "key_id": key_id,
                "event_count": len(events), "byte_reads": 0}

    def _ledger_manifest_version(self, case_id: str) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("select manifest_version from app.evidence_chain_heads where case_id=%s", (case_id,))
                row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else -1

    def finalize_pending_signature(self, *, operation_id: str) -> dict[str, Any]:
        """Service-only completion of the DB latch using the fixed-path key."""
        try:
            key = load_signing_key()
        except CustodyProofError as exc:
            raise PortalServiceError(exc.args[0], http_status=503) from exc
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """select canonical_payload from app.custody_signature_checkpoints
                       where custody_operation_id=%s and state='PENDING_SIGNATURE'""",
                    (operation_id,),
                )
                row = cur.fetchone()
                if not row or not isinstance(row[0], dict):
                    raise PortalServiceError("custody_signature_checkpoint_unavailable", http_status=409)
                payload = row[0]
                signed = sign_bundle(payload, key)
                cur.execute(
                    """insert into app.custody_signing_keys(key_id,algorithm,public_key)
                       values(%s,'Ed25519',%s) on conflict(key_id) do nothing""",
                    (key.key_id, key.public_key_b64),
                )
                cur.execute(
                    "select app.custody_signature_finalize(%s,%s,%s)",
                    (operation_id, key.key_id, signed["signature"]["value"]),
                )
            conn.commit()
        return {"operation_id": operation_id, "key_id": key.key_id, "signed": True}

    def _finalize_custody_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Cross the service-only signature latch after a custody DB commit."""
        operation_id = str(result.get("operation_id") or "")
        if not operation_id:
            raise PortalServiceError("custody_signature_operation_missing", http_status=500)
        signed = self.finalize_pending_signature(operation_id=operation_id)
        return {
            **result,
            "operation_phase": "COMPLETED",
            "signature_key_id": signed["key_id"],
        }

    def rotate_signing_key(
        self, *, actor_user_id: str, reauth_audit_event_id: str, reason: str
    ) -> dict[str, Any]:
        """Record a Portal-authorized public-key rotation; never exports private bytes."""
        try:
            key = load_signing_key()
        except CustodyProofError as exc:
            raise PortalServiceError(exc.args[0], http_status=503) from exc
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("select key_id from app.custody_signing_keys where retired_at is null for update")
                old = cur.fetchone()
                cur.execute(
                    """insert into app.custody_signing_keys(key_id,algorithm,public_key)
                       values(%s,'Ed25519',%s) on conflict(key_id) do nothing""",
                    (key.key_id, key.public_key_b64),
                )
                if old and str(old[0]) != key.key_id:
                    cur.execute("update app.custody_signing_keys set retired_at=now() where key_id=%s", (old[0],))
                cur.execute(
                    """insert into app.custody_signing_key_rotations(prior_key_id,new_key_id,reason,reauth_audit_event_id,actor_user_id)
                       values(%s,%s,%s,%s,%s)""",
                    (str(old[0]) if old else None, key.key_id, reason, reauth_audit_event_id, actor_user_id),
                )
            conn.commit()
        return {"key_id": key.key_id, "public_key": key.public_key_b64}

    def export_proof(
        self,
        *,
        case_id: str,
        actor: Any = None,
        export_kind: str = "bundle",
        anchor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a DB-derived proof export and record its metadata in Postgres.

        Proof material is derived from DB custody authority, not file manifests:
        the sealed evidence-object snapshot, the append-only custody event chain,
        and the current chain head. Mounted evidence is re-verified (full
        re-hash); the verify outcome and a content hash over the proof material
        are recorded through ``app.evidence_record_proof_export``. An optional
        Solana ``anchor`` result is folded into the recorded metadata as external
        proof only — it is never authority and lack of it does not block.

        Returns a portal-safe dict (no absolute paths): export id, kind,
        manifest_version, manifest_hash, ledger_tip_hash, verified, anchor.
        """
        # Export is deliberately the expensive path: Full Verify Evidence first,
        # then a DB-only ledger pass, then detached signing.  Verify Ledger below
        # never invokes `_reverify_sealed`, preserving the public distinction.
        full_verify = self.verify(case_id=case_id, actor=actor)
        ledger = self.verify_ledger(case_id=case_id)
        actor_type, actor_user, _actor_agent, _actor_service = _actor_columns(actor)
        del actor_type
        verified = bool(full_verify.get("verified")) and bool(ledger.get("verified"))
        issues = [*full_verify.get("verification_issues", []), *ledger.get("issues", [])]
        manifest_version = int(full_verify.get("manifest_version") or 0)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select manifest_hash, head_hash
                    from app.evidence_chain_heads where case_id = %s
                    """,
                    (case_id,),
                )
                head = cur.fetchone()
                manifest_hash = str(head[0]) if head and head[0] else None
                ledger_tip_hash = str(head[1]) if head and head[1] else None
                cur.execute(
                    """
                    select display_path, status, seal_status, current_sha256,
                           current_bytes
                    from app.evidence_objects
                    where case_id = %s
                    order by display_path
                    """,
                    (case_id,),
                )
                objects = [
                    {
                        "display_path": str(r[0]),
                        "status": r[1],
                        "seal_status": r[2],
                        "sha256": r[3],
                        "bytes": r[4],
                    }
                    for r in cur.fetchall()
                ]
                cur.execute(
                    """
                    select seq, event_type, manifest_version, prev_hash, event_hash
                    from app.evidence_custody_events
                    where case_id = %s order by seq
                    """,
                    (case_id,),
                )
                events = [
                    {
                        "seq": r[0],
                        "event_type": r[1],
                        "manifest_version": r[2],
                        "prev_hash": r[3],
                        "event_hash": r[4],
                    }
                    for r in cur.fetchall()
                ]
                cur.execute(
                    "select key_id,algorithm,public_key,activated_at,retired_at from app.custody_signing_keys order by activated_at"
                )
                signing_keys = [
                    {"key_id": str(r[0]), "algorithm": str(r[1]), "public_key": str(r[2]),
                     "activated_at": _iso(r[3]), "retired_at": _iso(r[4])}
                    for r in cur.fetchall()
                ]
        proof_material = {
            "format": "sift-custody-proof-payload/v1",
            "case_id": case_id,
            "manifest_version": manifest_version,
            "manifest_hash": manifest_hash,
            "ledger_tip_hash": ledger_tip_hash,
            "objects": objects,
            "custody_events": events,
            "signing_keys": signing_keys,
            "verified": verified,
            "issues": issues,
        }
        try:
            signed_bundle = sign_bundle(proof_material, load_signing_key())
        except CustodyProofError as exc:
            raise PortalServiceError(exc.args[0], http_status=503) from exc
        proof_hash = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    proof_material, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
            ).hexdigest()
        )
        metadata: dict[str, Any] = {
            "proof_hash": proof_hash,
            "signing_key_id": signed_bundle["signature"]["key_id"],
            "object_count": len(objects),
            "custody_event_count": len(events),
            "issues": issues,
        }
        anchor_meta: dict[str, Any] | None = None
        if anchor is not None:
            # Solana is external proof only: record the result, never authority.
            anchor_meta = {
                "solana_tx": anchor.get("solana_tx"),
                "confirmed": bool(anchor.get("confirmed", False)),
                "cluster": anchor.get("solana_cluster") or anchor.get("cluster"),
                "anchor_payload": anchor.get("anchor_payload"),
                "explorer_url": anchor.get("explorer_url"),
            }
            metadata["anchor"] = anchor_meta
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select app.evidence_record_proof_export(
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        case_id,
                        manifest_version,
                        export_kind,
                        manifest_hash,
                        ledger_tip_hash,
                        verified,
                        actor_user,
                        _jsonb(metadata),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return {
            "export_id": str(row[0]) if row and row[0] else None,
            "export_kind": export_kind,
            "manifest_version": manifest_version,
            "manifest_hash": manifest_hash,
            "ledger_tip_hash": ledger_tip_hash,
            "proof_hash": proof_hash,
            "verified": verified,
            "issues": issues,
            "anchor": anchor_meta,
            "bundle": signed_bundle,
        }

    def latest_proof_export(self, case_id: str) -> dict[str, Any] | None:
        """Return portal-safe metadata for the most recent proof export, if any."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, manifest_version, export_kind, manifest_hash,
                           ledger_tip_hash, verified, verified_at, metadata
                    from app.evidence_proof_exports
                    where case_id = %s
                    order by created_at desc
                    limit 1
                    """,
                    (case_id,),
                )
                row = cur.fetchone()
        if not row:
            return None
        metadata = row[7] if isinstance(row[7], dict) else {}
        return {
            "export_id": row[0],
            "manifest_version": row[1],
            "export_kind": row[2],
            "manifest_hash": row[3],
            "ledger_tip_hash": row[4],
            "verified": row[5],
            "verified_at": _iso(row[6]),
            "anchor": metadata.get("anchor"),
            "proof_hash": metadata.get("proof_hash"),
        }

    def _resolve_evidence_path(self, case_id: str, display_path: str) -> Path:
        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            raise PortalServiceError("case_artifact_path_unavailable", http_status=404)
        candidate = (case_dir / display_path).resolve()
        case_resolved = case_dir.resolve()
        if not candidate.is_relative_to(case_resolved) or not candidate.is_file():
            raise PortalServiceError("evidence_file_unavailable", http_status=404)
        return candidate

    def _ensure_detected(
        self,
        case_id: str,
        display_path: str,
        actor_user_id: str | None,
        actor_service_identity_id: str | None,
    ) -> str:
        existing = self._evidence_id_for_path(case_id, display_path)
        if existing:
            return existing
        path = self._resolve_evidence_path(case_id, display_path)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select app.evidence_detect(%s, %s, %s, %s, %s, %s)",
                    (
                        case_id,
                        display_path,
                        path.name,
                        path.stat().st_size,
                        actor_user_id,
                        actor_service_identity_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        if not row:
            raise PortalServiceError("evidence_detection_failed", http_status=503)
        return str(row[0])

    def _ensure_registered(
        self,
        case_id: str,
        display_path: str,
        *,
        display_name: str,
        description: str | None,
        source: str | None,
        actor_user_id: str | None,
        actor_service_identity_id: str | None,
    ) -> str:
        evidence_id = self._ensure_detected(
            case_id, display_path, actor_user_id, actor_service_identity_id
        )
        with self._connect() as conn:
            with conn.cursor() as cur:
                # Only the detected->registered transition is valid in
                # app.evidence_register; it raises evidence_register_invalid_state
                # for any other status. An item that is already sealed (or has
                # been escalated to violated, or operator-dispositioned to
                # ignored/retired) keeps its existing registration — re-registering
                # it would raise and (pre-fix) crash the whole seal path. Skip the
                # register call in that case and reuse the existing id; the
                # durable Replace/Reacquire operation handles changed sealed bytes.
                cur.execute(
                    "select status from app.evidence_objects where id = %s",
                    (evidence_id,),
                )
                srow = cur.fetchone()
                status = str(srow[0]) if srow and srow[0] is not None else None
                if status in (None, "detected", "registered"):
                    cur.execute(
                        """
                        select id::text
                        from app.evidence_register(%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            evidence_id,
                            display_name,
                            description,
                            source,
                            actor_user_id,
                            actor_service_identity_id,
                        ),
                    )
                    row = cur.fetchone()
                    if row and row[0]:
                        evidence_id = str(row[0])
            conn.commit()
        return evidence_id

    def _evidence_id_for_path(self, case_id: str, display_path: str) -> str | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select id::text from app.evidence_objects where case_id = %s and display_path = %s",
                    (case_id, display_path),
                )
                row = cur.fetchone()
        return str(row[0]) if row else None

    def _next_manifest_version(self, case_id: str) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select manifest_version from app.evidence_gate_status(%s)",
                    (case_id,),
                )
                row = cur.fetchone()
        return int(row[0] or 0) + 1 if row else 1


class InvestigationService(_BasePortalDbService):
    """DB read/mutation adapter for findings, timeline, IOCs, and TODOs.

    BATCH-K2: this adapter delegates the authoritative approve/reject/edit
    transition and report inputs to the core ``PostgresInvestigationStore`` so the
    Gateway and core agree on one content-hash/version-guarded transition. List
    reads project the DB ``status``/``version`` columns onto the payload, never the
    case-JSON status, so file tampering cannot change portal state.
    """

    def _store(self):
        from sift_core.investigation_store import PostgresInvestigationStore

        return PostgresInvestigationStore(self._dsn)

    def list_findings(self, case_id: str) -> list[dict[str, Any]]:
        self._sync_findings(case_id)
        return self._store().list_findings(case_id)

    def list_timeline(self, case_id: str) -> list[dict[str, Any]]:
        self._sync_timeline(case_id)
        return self._store().list_timeline(case_id)

    def list_iocs(self, case_id: str) -> list[dict[str, Any]]:
        self._sync_iocs(case_id)
        return self._store().list_iocs(case_id)

    def list_todos(self, case_id: str) -> list[dict[str, Any]]:
        self._sync_todos(case_id)
        return self._store().list_todos(case_id)

    def apply_review(
        self,
        *,
        case_id: str,
        actions: list[dict[str, Any]],
        examiner: str,
        reauth_audit_event_id: str | None,
        actor: Any = None,
    ) -> dict[str, Any]:
        """Apply operator approve/reject/edit decisions to DB authority.

        Each action: {id, action, modifications?, note?, rejection_reason?,
        content_hash_at_review?, version_at_review?}. Returns approve/reject/edit
        counts and a list of skipped items (stale or conflicting). The transition
        is content-hash/version guarded and atomic.
        """
        from sift_core.investigation_store import ReviewAction

        parsed: list[ReviewAction] = []
        for entry in actions:
            if not isinstance(entry, dict):
                continue
            item_id = str(entry.get("id") or entry.get("item_id") or "").strip()
            if not item_id:
                continue
            parsed.append(
                ReviewAction(
                    item_id=item_id,
                    action=str(entry.get("action") or "").strip().lower(),
                    modifications=entry.get("modifications") or None,
                    note=entry.get("note") or None,
                    rejection_reason=entry.get("rejection_reason")
                    or entry.get("reason")
                    or None,
                    content_hash_at_review=entry.get("content_hash_at_review"),
                    version_at_review=entry.get("version_at_review"),
                )
            )
        result = self._store().apply_review(
            case_id,
            parsed,
            examiner=examiner,
            reauth_audit_event_id=reauth_audit_event_id,
            actor=actor,
        )
        return result.as_dict()

    def report_inputs(self, case_id: str) -> dict[str, list[dict[str, Any]]]:
        """Approved findings/timeline/IOCs for report generation (DB authority)."""
        return self._store().report_inputs(case_id)

    def audit_events(self, case_id: str, audit_ids: list[str]) -> list[dict[str, Any]]:
        """Return ``app.audit_events`` rows for this case matching ``audit_ids``.

        BATCH-K6: the portal audit view sources audit entries from Postgres
        (DB authority) rather than scanning the local ``audit/*.jsonl`` mirror, so
        tampering with or deleting the JSONL files cannot spoof, hide, or fabricate
        the audit trail shown for a finding. Scoped to ``case_id`` so a leaked
        event id from another case cannot be surfaced here.

        Resolution order (any match returns the row once):
        1. ``id::text = any(%s)`` — uuid PK match (legacy / direct references).
        2. ``details->>'backend_audit_id' = any(%s)`` — gateway-stamped core-plane id.
        3. ``details->'audit_aliases' ?| %s`` — any alias in the per-response set
           stamped by the gateway envelope (sub-plane ids: shell exec, ingest, etc.).

        SECURITY INVARIANT: every predicate is ANDed with ``case_id = %s`` so a
        requested id that belongs to another case is never surfaced here, even if
        that case's audit row carries a matching alias.  Rows that satisfy multiple
        predicates are de-duplicated by ``DISTINCT ON (id)`` in SQL.

        Each returned row carries an ``audit_id`` field set to the requested
        human/backend-scheme id it satisfied, mirroring the old file-mode JSONL
        reader so the frontend can group results by ``audit_id``.  A single DB
        row may appear more than once if it satisfies multiple requested ids.

        Note: ``audit_aliases`` are response-asserted by the backend that ran the
        tool — within-case corroboration is only as trustworthy as that backend.
        Cross-case surfacing is structurally blocked by the ``case_id`` scope.
        """
        ids = [str(a) for a in (audit_ids or []) if str(a).strip()]
        if not ids:
            return []
        # §9.6 superset resolver: match any id the agent could have cited so
        # every gateway-issued audit handle resolves, regardless of backend.
        # Predicates (all ANDed with case_id):
        #   - PK uuid / backend_audit_id / audit_aliases  (existing)
        #   - envelope_event_id — call-row uuid always present in result details
        #   - request_id column  — 100% populated, links call↔result pair
        #   - details->>'audit_id' (the clause at the bottom of the SQL below) —
        #     INTENTIONAL defense-in-depth / future-proofing seam, kept on purpose
        #     (G2): no producer writes a top-level details.audit_id today (every
        #     writer uses backend_audit_id / envelope_event_id / audit_aliases),
        #     so it currently matches nothing — DO NOT delete it as dead code. It
        #     mirrors the same predicate in case_manager.py:214
        #     (_db_audit_event_has_audit_id) so a future writer that emits
        #     details.audit_id resolves through BOTH the fail-closed write-side
        #     verifier and this read-side resolver without a code change.
        #
        # §9.6 dedup fix: each envelope produces TWO rows per tool call — a
        # pre-dispatch 'requested' row (PK = envelope_event_id) and a result row
        # (different PK, details->>'envelope_event_id' = envelope_event_id).
        # Citing the envelope_event_id matches BOTH via id::text AND via the
        # envelope_event_id predicate, so naïve DISTINCT ON(id) returns both.
        # The panel would show a sparse 'requested' stub alongside the rich result.
        #
        # Fix: dedupe by request_id (the stable identifier linking the pair),
        # preferring the result row (status != 'requested') over the call stub.
        # NULL-safe: rows with NULL request_id (reauth.*, lifecycle, job.* events)
        # must NOT be collapsed — each has a unique PK and may independently be
        # cited as a provenance reference (e.g. reauth_audit_event_id).
        # COALESCE(request_id, id::text) gives every NULL-request_id row its own
        # unique dedup key (its PK uuid) while request_id-bearing envelope pairs
        # still collapse to one row.  DISTINCT ON expr MUST match the leading
        # ORDER BY expr exactly — both use the same COALESCE expression.
        #
        # Note: literal '?' is safe here — psycopg3 only treats %s/%()s as
        # placeholders (qmark-paramstyle drivers would misparse this).
        sql = (
            "select distinct on (coalesce(request_id, id::text)) "
            "id::text, event_type, actor_type, source, status, summary, "
            "request_id, job_id::text, created_at, details "
            "from app.audit_events "
            "where case_id = %s and ("
            "    id::text = any(%s) "
            "    or details->>'backend_audit_id' = any(%s) "
            "    or details->'audit_aliases' ?| %s "
            "    or details->>'envelope_event_id' = any(%s) "
            "    or request_id = any(%s) "
            "    or details->>'audit_id' = any(%s)"
            ") "
            "order by coalesce(request_id, id::text), (status = 'requested'), created_at"
        )
        db_rows: list[dict[str, Any]] = []
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (case_id, ids, ids, ids, ids, ids, ids))
                cols = [d[0] for d in (cur.description or ())]
                for record in cur.fetchall():
                    row = dict(zip(cols, record, strict=False))
                    row["created_at"] = _iso(row.get("created_at"))
                    db_rows.append(row)

            # Batch-fetch the paired mcp.tool.call events so the panel can show
            # the real tool arguments (command/purpose/etc.).  Each result row
            # stamped by the gateway envelope carries details.envelope_event_id
            # pointing to its pre-dispatch call record.  One query, case-scoped.
            envelope_ids = [
                str(row.get("details", {}).get("envelope_event_id") or "")
                for row in db_rows
                if isinstance(row.get("details"), dict)
                and row["details"].get("envelope_event_id")
            ]
            call_args: dict[str, Any] = {}  # envelope_event_id → arguments dict
            if envelope_ids:
                call_sql = (
                    "select id::text, details "
                    "from app.audit_events "
                    # SECURITY: case_id scope preserved — same invariant as above.
                    "where case_id = %s and id::text = any(%s)"
                )
                with conn.cursor() as cur2:
                    cur2.execute(call_sql, (case_id, envelope_ids))
                    for call_id, call_details in cur2.fetchall():
                        if isinstance(call_details, dict):
                            args = call_details.get("arguments")
                            if args is not None:
                                call_args[call_id] = args

        # Attach paired-call arguments onto each result row before fan-out.
        for row in db_rows:
            det = row.get("details") or {}
            eid = det.get("envelope_event_id") if isinstance(det, dict) else None
            if eid and eid in call_args:
                row["arguments"] = call_args[eid]

        # Label each DB row with the requested human id(s) it satisfies so the
        # frontend (AuditTrailPanel) can group by audit_id.  The old file-mode
        # reader returned raw JSONL entries that carried audit_id = the human id;
        # this fan-out preserves that contract for DB-mode rows.
        #
        # One DB row can back multiple requested ids (e.g. backend_audit_id matches
        # one cited id while an alias matches a second) → emit one copy per matched
        # id.  Defensive fallback: if no requested id maps to the row (impossible
        # given the SQL matched it) emit a single row keyed by its uuid.
        out: list[dict[str, Any]] = []
        for row in db_rows:
            row_uuid = row.get("id", "")
            details = row.get("details") or {}
            row_req_id = str(row.get("request_id") or "")
            bid = details.get("backend_audit_id")
            aliases: set[str] = set(details.get("audit_aliases") or [])
            envelope_eid = details.get("envelope_event_id") or ""
            detail_audit_id = details.get("audit_id") or ""
            # §9.6: match against every handle the superset SQL may have matched.
            matched = [
                # SIM109's tuple-membership suggestion would silently drop the
                # aliases/envelope_eid/row_req_id/detail_audit_id fallbacks below.
                aid
                for aid in ids
                if (
                    aid == row_uuid
                    or aid == bid
                    or aid in aliases
                    or (envelope_eid and aid == envelope_eid)
                    or (row_req_id and aid == row_req_id)
                    or (detail_audit_id and aid == detail_audit_id)
                )
            ]
            if not matched:
                # Defensive: SQL matched the row but we can't pin it to a
                # specific requested id — emit once keyed by the uuid PK.
                row_copy = dict(row)
                row_copy["audit_id"] = row_uuid
                out.append(row_copy)
            else:
                for aid in matched:
                    row_copy = dict(row)
                    row_copy["audit_id"] = aid
                    out.append(row_copy)

        out.sort(key=lambda r: r.get("created_at") or "")
        return out

    def audit_events_recent(
        self, case_id: str, *, limit: int = 30
    ) -> list[dict[str, Any]]:
        """Return recent DB-authoritative tool activity for one active case.

        This is the real-mode source for the portal Overview agent-activity
        feed. It reads only ``app.audit_events`` scoped to the server-resolved
        ``case_id`` and collapses the requested/result envelope pair by
        request_id so the UI shows one row per tool call.
        """
        try:
            safe_limit = int(limit or 30)
        except (TypeError, ValueError):
            safe_limit = 30
        safe_limit = max(1, min(safe_limit, 100))
        sql = (
            "select id::text, event_type, actor_type, source, status, summary, "
            "request_id, job_id::text, created_at, details "
            "from app.audit_events "
            "where case_id = %s "
            "order by created_at desc "
            "limit %s"
        )
        rows: list[dict[str, Any]] = []
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (case_id, safe_limit * 2))
                cols = [d[0] for d in (cur.description or ())]
                for record in cur.fetchall():
                    row = dict(zip(cols, record, strict=False))
                    row["created_at"] = _iso(row.get("created_at"))
                    rows.append(row)

        events: list[dict[str, Any]] = []
        for row in _collapse_activity_rows(rows, safe_limit):
            details = _event_details(row)
            tool = _activity_tool(row)
            status = str(
                row.get("status") or details.get("status") or "requested"
            ).lower()
            events.append(
                {
                    "id": str(row.get("id") or ""),
                    "ts": row.get("created_at"),
                    "tool": tool,
                    "backend": _activity_backend(row),
                    "status": status,
                    "principal": _compact_label(details.get("principal"), limit=80),
                    "kind": _activity_kind(tool, status),
                    "text": _activity_label(row),
                }
            )
        return events

    def create_todo(
        self,
        *,
        case_id: str,
        examiner: str,
        actor: Any,
        description: str,
        priority: str,
        assignee: str,
        related_findings: list[str],
    ) -> dict[str, Any]:
        del actor
        self._sync_todos(case_id)
        seq = self._next_todo_seq(case_id, examiner)
        todo_id = f"TODO-{examiner}-{seq:03d}"
        todo = {
            "todo_id": todo_id,
            "description": description,
            "status": "open",
            "priority": priority,
            "assignee": assignee,
            "related_findings": related_findings,
            "created_by": examiner,
            "examiner": examiner,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [],
            "completed_at": None,
        }
        self._upsert_todo(case_id, todo_id, todo, source="portal")
        self._mirror_todos(case_id)
        return todo

    def update_todo(
        self,
        *,
        case_id: str,
        todo_id: str,
        examiner: str,
        actor: Any,
        patch: dict[str, Any],
    ) -> dict[str, Any] | None:
        del actor
        rows = self.list_todos(case_id)
        todo = next((row for row in rows if row.get("todo_id") == todo_id), None)
        if todo is None:
            return None
        for key in (
            "description",
            "priority",
            "status",
            "assignee",
            "related_findings",
        ):
            if key in patch:
                todo[key] = patch[key]
        if patch.get("note"):
            todo.setdefault("notes", []).append(
                {
                    "note": patch["note"],
                    "by": examiner,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            )
        if todo.get("status") == "completed":
            todo["completed_at"] = (
                todo.get("completed_at") or datetime.now(timezone.utc).isoformat()
            )
        else:
            todo["completed_at"] = None
        self._upsert_todo(case_id, todo_id, todo, source="portal")
        self._mirror_todos(case_id)
        return todo

    def delete_todo(
        self, *, case_id: str, todo_id: str, examiner: str, actor: Any
    ) -> bool:
        del examiner, actor
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "delete from app.investigation_todos where case_id = %s and todo_id = %s",
                    (case_id, todo_id),
                )
                deleted = cur.rowcount > 0
            conn.commit()
        if deleted:
            self._mirror_todos(case_id)
        return deleted

    def _payload_rows(self, sql: LiteralString, case_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (case_id,))
                rows = cur.fetchall()
        out = []
        for (payload,) in rows:
            if isinstance(payload, dict):
                out.append(payload)
            elif isinstance(payload, str):
                try:
                    parsed = json.loads(payload)
                    if isinstance(parsed, dict):
                        out.append(parsed)
                except ValueError:
                    pass
        return out

    def _next_todo_seq(self, case_id: str, examiner: str) -> int:
        prefix = f"TODO-{examiner}-"
        rows = self.list_todos(case_id)
        max_seq = 0
        for row in rows:
            tid = str(row.get("todo_id") or "")
            if tid.startswith(prefix):
                try:
                    max_seq = max(max_seq, int(tid[len(prefix) :]))
                except ValueError:
                    pass
        return max_seq + 1

    def _upsert_todo(
        self, case_id: str, todo_id: str, payload: dict[str, Any], *, source: str
    ) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into app.investigation_todos
                      (case_id, todo_id, status, priority, assignee, payload,
                       created_by, completed_at, source, updated_at)
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                    on conflict (case_id, todo_id) do update
                      set status = excluded.status,
                          priority = excluded.priority,
                          assignee = excluded.assignee,
                          payload = excluded.payload,
                          completed_at = excluded.completed_at,
                          source = excluded.source,
                          updated_at = now()
                    """,
                    (
                        case_id,
                        todo_id,
                        str(payload.get("status") or "open"),
                        str(payload.get("priority") or "medium"),
                        payload.get("assignee"),
                        _jsonb(payload),
                        payload.get("created_by") or payload.get("examiner"),
                        payload.get("completed_at") or None,
                        source,
                    ),
                )
            conn.commit()

    def _mirror_todos(self, case_id: str) -> None:
        self._write_json_list(case_id, "todos.json", self.list_todos(case_id))


class ReportService(_BasePortalDbService):
    """DB report metadata adapter and approved-only eligibility gate."""

    def list_reports(self, case_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select report_id::text, profile, examiner, status, exported,
                           created_at, updated_at, metadata
                    from app.report_metadata
                    where case_id = %s
                    order by created_at desc
                    """,
                    (case_id,),
                )
                rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "profile": r[1],
                "examiner": r[2],
                "status": r[3],
                "exported": r[4],
                "created_at": _iso(r[5]),
                "updated_at": _iso(r[6]),
                "metadata": r[7] if isinstance(r[7], dict) else {},
            }
            for r in rows
        ]

    def report_eligibility(self, case_id: str) -> dict[str, Any]:
        self._sync_findings(case_id)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                      count(*) filter (where upper(status) = 'APPROVED') as approved,
                      count(*) as total
                    from app.investigation_findings
                    where case_id = %s
                    """,
                    (case_id,),
                )
                row = cur.fetchone() or (0, 0)
        approved = int(row[0] or 0)
        total = int(row[1] or 0)
        return {
            "eligible": approved > 0,
            "approved_findings": approved,
            "total_findings": total,
            "reason": None if approved > 0 else "no approved findings",
        }

    def record_report(
        self,
        *,
        case_id: str,
        report_id: str,
        profile: str,
        examiner: str,
        created_at: str,
        reauth_audit_event_id: str | None,
        seal_status: str | None,
        manifest_version: int | None,
        manifest_hash: str | None,
        chain_head_hash: str | None,
        exported: bool = False,
        **metadata: Any,
    ) -> None:
        status = "exported" if exported else "generated"
        meta_payload = {
            "profile": profile,
            "examiner": examiner,
            "created_at": created_at,
            **metadata,
        }
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into app.report_metadata
                      (case_id, report_id, profile, examiner, status,
                       reauth_audit_event_id, seal_status, manifest_version,
                       manifest_hash, chain_head_hash, exported, metadata,
                       created_at, updated_at)
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, coalesce(%s::timestamptz, now()), now())
                    on conflict (case_id, report_id) do update
                      set profile = excluded.profile,
                          examiner = excluded.examiner,
                          status = excluded.status,
                          reauth_audit_event_id = coalesce(excluded.reauth_audit_event_id, app.report_metadata.reauth_audit_event_id),
                          seal_status = excluded.seal_status,
                          manifest_version = excluded.manifest_version,
                          manifest_hash = excluded.manifest_hash,
                          chain_head_hash = excluded.chain_head_hash,
                          exported = app.report_metadata.exported or excluded.exported,
                          metadata = excluded.metadata,
                          updated_at = now()
                    """,
                    (
                        case_id,
                        report_id,
                        profile,
                        examiner,
                        status,
                        reauth_audit_event_id,
                        seal_status,
                        manifest_version,
                        manifest_hash,
                        chain_head_hash,
                        exported,
                        _jsonb(meta_payload),
                        created_at or None,
                    ),
                )
            conn.commit()

    def addon_status(self, case_id: str) -> list[dict[str, Any]]:
        del case_id
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select name, namespace, enabled, health_status, health_detail,
                           health_checked_at, tier
                    from app.mcp_backends
                    order by name
                    """
                )
                rows = cur.fetchall()
        return [
            {
                "name": r[0],
                "namespace": r[1],
                "enabled": r[2],
                "health_status": r[3],
                "health_detail": r[4],
                "health_checked_at": _iso(r[5]),
                "tier": r[6],
            }
            for r in rows
        ]


def _relative_display_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    if not value:
        raise PortalServiceError("evidence_path_required", http_status=400)
    if value.startswith("/") or "/../" in f"/{value}/" or value.startswith("../"):
        raise PortalServiceError("invalid_relative_evidence_path", http_status=400)
    if not value.startswith("evidence/"):
        value = f"evidence/{value}"
    return value


def _hash_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def _admission_fingerprint(path: Path) -> tuple[os.stat_result, bool | None]:
    """Read one cheap descriptor-pinned identity and immutable posture."""
    from sift_core.evidence_chain import get_immutable_flag_fd

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise OSError("unsafe evidence file")
        return current, get_immutable_flag_fd(fd)
    finally:
        os.close(fd)


def _admission_correlation_id() -> str | None:
    try:
        from sift_core.active_case_context import current_active_case

        context = current_active_case()
    except ImportError:  # pragma: no cover - defensive
        context = None
    value = getattr(context, "request_id", None)
    return str(value) if value else None


def _manifest_hash(case_id: str, version: int, items: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        {"case_id": case_id, "version": version, "items": items},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _chain_head_dict(row: Any) -> dict[str, Any]:
    if not row:
        return {}
    return {
        "case_id": row[0],
        "manifest_version": row[1],
        "head_seq": row[2],
        "head_hash": row[3],
        "manifest_hash": row[4],
        "seal_status": row[5],
        "active_count": row[6],
        "issues": row[7] if isinstance(row[7], list) else [],
        "last_event_type": row[8],
        "last_verified_at": _iso(row[9]),
    }
