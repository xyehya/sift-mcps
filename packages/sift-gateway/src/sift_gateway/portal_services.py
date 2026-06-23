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
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
            for key in ("message", "error", "detail", "title", "finding_id", "description"):
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
    return _compact_label(details.get("tool") or row.get("event_type") or "activity", limit=64)


def _activity_backend(row: dict[str, Any]) -> str:
    details = _event_details(row)
    return _compact_label(details.get("backend") or row.get("source") or "unknown", limit=64)


def _activity_kind(tool: str, status: str) -> str:
    if status == "failure":
        return "alert"
    if tool == "record_finding":
        return "discovery"
    if tool in {"record_timeline_event", "manage_todo"}:
        return "io"
    if tool.startswith("kb_"):
        return "info"
    if (
        tool == "run_command"
        or tool.startswith("opensearch_")
        or tool.startswith("wintriage_")
    ):
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
        return _compact_label(f"{tool} failed - {reason}" if reason else f"{tool} failed")

    if tool == "record_finding":
        title = _first_text(args.get("title"), result)
        confidence = _first_text(args.get("confidence"))
        suffix = f" ({confidence})" if confidence else ""
        return _compact_label(f"Recorded finding - {title}{suffix}" if title else "Recorded finding")

    if tool == "record_timeline_event":
        desc = _first_text(args.get("description"), args.get("title"), result)
        return _compact_label(f"Timeline event added - {desc}" if desc else "Timeline event added")

    if tool == "manage_todo":
        action = _first_text(args.get("action"), args.get("operation"))
        return _compact_label(f"TODO {action}" if action else "TODO updated")

    if tool == "run_command":
        command = _first_text(args.get("command"), detail.get("command") if isinstance(detail, dict) else None)
        exit_code = None
        if isinstance(result, dict):
            exit_code = result.get("exit_code")
        if exit_code is None and isinstance(detail, dict):
            exit_code = detail.get("exit_code")
        exit_part = f" (exit {exit_code})" if exit_code is not None else ""
        return _compact_label(f"Ran command - {command}{exit_part}" if command else f"Ran command{exit_part}")

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

    if tool.startswith("wintriage_"):
        op = tool.removeprefix("wintriage_").replace("_", " ")
        return _compact_label(f"Triage {op}")

    if tool.startswith("kb_"):
        op = tool.removeprefix("kb_").replace("_", " ")
        return _compact_label(f"Knowledge base {op}")

    return summary or _compact_label(tool)


def _collapse_activity_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
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
                logger.warning("Failed to read %s for case %s: %s", filename, case_id, e)
            return []
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            rows = data.get("items") or data.get("files") or []
            return [row for row in rows if isinstance(row, dict)]
        return []

    def _write_json_list(self, case_id: str, filename: str, rows: list[dict[str, Any]]) -> None:
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
                    todo_id = str(payload.get("todo_id") or payload.get("id") or f"TODO-sync-{idx:03d}")
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

    def gate_status(self, case_id: str) -> dict[str, Any]:
        self._scan_evidence(case_id)
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
                    """
                    select display_path
                    from app.evidence_objects
                    where case_id = %s and status in ('detected', 'registered')
                    order by display_path
                    """,
                    (case_id,),
                )
                unregistered = [str(r[0]) for r in cur.fetchall()]
        if not row:
            return {
                "seal_status": "unsealed",
                "manifest_version": 0,
                "head_hash": "",
                "active_count": 0,
                "issues": [],
                "last_verified_at": None,
                "unregistered": unregistered,
            }
        return {
            "seal_status": row[0],
            "manifest_version": row[1],
            "head_hash": row[2],
            "active_count": row[3],
            "issues": row[4] if isinstance(row[4], list) else [],
            "last_verified_at": _iso(row[5]),
            "unregistered": unregistered,
        }

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        self._scan_evidence(case_id)
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

    def resolve_evidence_reference(self, case_id: str, ref: str) -> dict[str, Any]:
        """Resolve an opaque evidence id or relative display path for worker use.

        The returned absolute path is for Gateway/worker internals only. Callers
        that serialize this result must use ``display_path``/``evidence_id`` and
        never the ``path`` field.
        """
        self._scan_evidence(case_id)
        display_path = None
        try:
            display_path = _relative_display_path(ref)
        except PortalServiceError:
            display_path = None
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, display_path, status, seal_status
                    from app.evidence_objects
                    where case_id = %s
                      and (id::text = %s or display_path = %s)
                    """,
                    (case_id, ref, display_path),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        if row[2] != "sealed" or row[3] != "sealed":
            raise PortalServiceError("evidence_object_not_sealed", http_status=403)
        path = self._resolve_evidence_path(case_id, str(row[1]))
        return {"evidence_id": str(row[0]), "display_path": str(row[1]), "path": path}

    def record_reauth_event(
        self, *, case_id: str, actor: Any, examiner: str, action: str
    ) -> str | None:
        actor_type, actor_user, actor_agent, actor_service = _actor_columns(actor)
        with self._connect() as conn:
            with conn.cursor() as cur:
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
                        _jsonb({"examiner": examiner, "action": action}),
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
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        self._scan_evidence(case_id)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        items: list[dict[str, Any]] = []
        for spec in file_specs:
            display_path = _relative_display_path(str(spec.get("path") or ""))
            evidence_id = self._ensure_registered(
                case_id,
                display_path,
                display_name=Path(display_path).name,
                description=str(spec.get("description") or "") or None,
                source=str(spec.get("source") or "") or None,
                actor_user_id=actor_user,
                actor_service_identity_id=actor_service,
            )
            path = self._resolve_evidence_path(case_id, display_path)
            sha256, size = _hash_file(path)
            items.append(
                {
                    "evidence_object_id": evidence_id,
                    "sha256": f"sha256:{sha256}",
                    "bytes": size,
                    "registered_by": examiner,
                }
            )
        if not items:
            raise PortalServiceError("seal_requires_items", http_status=400)
        manifest_version = self._next_manifest_version(case_id)
        manifest_hash = _manifest_hash(case_id, manifest_version, items)
        # B-MVP-048: harden the bytes on disk (service-owned + immutable) BEFORE
        # recording the logical seal, so a seal can never be recorded as sealed
        # while the evidence is still operator-copied root:root and mutable. Fail
        # CLOSED: if the FS posture cannot be applied, the DB seal is not written.
        self._harden_sealed_files(case_id, file_specs)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select case_id::text, manifest_version, head_seq, head_hash,
                           manifest_hash, seal_status, active_count, issues,
                           last_event_type, last_verified_at
                    from app.evidence_seal(%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        case_id,
                        _jsonb(items),
                        manifest_version,
                        manifest_hash,
                        reauth_audit_event_id,
                        actor_user,
                        actor_service,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return _chain_head_dict(row)

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

    def reacquire(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        """Re-acquire (re-seal) a sealed/violated evidence item at its new bytes.

        Used when an operator legitimately re-images an evidence item whose bytes
        changed (e.g. a corrupted acquisition is re-acquired). We hash the mounted
        replacement, record an append-only supersession (old sha -> new sha +
        operator reason) through ``app.evidence_reacquire``, flip the item back to
        ``sealed``, and clear the case violation. The item must already exist and
        be present on disk — a missing item cannot be re-acquired (retire it
        instead). DB is the authority; no file manifest/ledger is consulted.
        """
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        rel = _relative_display_path(display_path)
        evidence_id = self._evidence_id_for_path(case_id, rel)
        if not evidence_id:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        try:
            path = self._resolve_evidence_path(case_id, rel)
        except PortalServiceError as exc:
            # A re-acquisition needs mounted bytes to hash. A missing file is a
            # retire, not a re-acquire — tell the operator which path to take.
            raise PortalServiceError(
                "evidence_file_missing_cannot_reacquire", http_status=409
            ) from exc
        sha256, size = _hash_file(path)
        items = [
            {
                "evidence_object_id": evidence_id,
                "sha256": f"sha256:{sha256}",
                "bytes": size,
                "registered_by": examiner,
            }
        ]
        manifest_version = self._next_manifest_version(case_id)
        manifest_hash = _manifest_hash(case_id, manifest_version, items)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select case_id::text, manifest_version, head_seq, head_hash,
                           manifest_hash, seal_status, active_count, issues,
                           last_event_type, last_verified_at
                    from app.evidence_reacquire(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        evidence_id,
                        case_id,
                        f"sha256:{sha256}",
                        size,
                        manifest_version,
                        manifest_hash,
                        reason,
                        reauth_audit_event_id,
                        actor_user,
                        actor_service,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        # B-MVP-048: a re-acquired item is sealed again, so re-apply the
        # service-owned + immutable FS posture to its new bytes (the operator
        # re-imaged with a mutable, operator-owned file). Fail CLOSED with the
        # same mapping used by _harden_sealed_files so a reacquire never leaves
        # the DB sealed while the bytes stay mutable.
        self._harden_sealed_files(case_id, [{"path": rel}])
        result = _chain_head_dict(row)
        result["display_path"] = rel
        result["sha256"] = f"sha256:{sha256}"
        result["bytes"] = size
        return result

    def unseal(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        """Operator unlock of a sealed evidence item so its bytes can be replaced.

        The deliberate inverse of seal: clears the on-disk immutable (+i) flag via
        ``sift_core.evidence_chain.unharden_sealed_evidence`` and records the
        logical transition through ``app.evidence_unseal`` (object -> status
        ``registered``, seal_status ``unsealed``). The recompute drops the case
        aggregate seal status to ``unsealed`` so the fail-closed agent evidence
        gate BLOCKS every agent MCP tool until the operator re-seals — that gate
        block is the intended control while bytes are being swapped/re-imaged.

        Re-auth gated: ``reauth_audit_event_id`` must be non-empty. The item must
        already exist and be present on disk (a missing item is a retire, not an
        unseal). DB is the authority; no file manifest/ledger is consulted.
        """
        del examiner
        if not str(reauth_audit_event_id or "").strip():
            raise PortalServiceError("unseal_requires_reauth", http_status=403)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        rel = _relative_display_path(display_path)
        evidence_id = self._evidence_id_for_path(case_id, rel)
        if not evidence_id:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        # The bytes must be present to unlock them (otherwise there is nothing to
        # clear +i on — a missing item is a retire, not an unseal).
        self._resolve_evidence_path(case_id, rel)
        # Clear the immutable flag BEFORE the DB write: if the FS posture cannot
        # be relaxed we must not record an unsealed transition (which would tell
        # the operator the bytes are now editable when they are not).
        self._unharden_sealed_files(case_id, [rel])
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select seal_status
                    from app.evidence_unseal(%s, %s, %s, %s, %s)
                    """,
                    (
                        evidence_id,
                        reason,
                        reauth_audit_event_id,
                        actor_user,
                        actor_service,
                    ),
                )
                cur.fetchone()
                # Read back the item's resulting per-object status for the
                # contract return (the RPC returns the case chain head).
                cur.execute(
                    "select status, seal_status from app.evidence_objects where id = %s",
                    (evidence_id,),
                )
                obj = cur.fetchone()
            conn.commit()
        status = str(obj[0]) if obj else "registered"
        seal_status = str(obj[1]) if obj else "unsealed"
        return {
            "evidence_id": evidence_id,
            "display_path": rel,
            "status": status,
            "seal_status": seal_status,
            "immutable": False,
        }

    def _unharden_sealed_files(self, case_id: str, rel_paths: list[str]) -> None:
        """Clear the immutable flag on the given sealed evidence files.

        Mirrors ``_harden_sealed_files`` but in reverse: resolves the case dir,
        re-validates each case-relative path inside ``evidence/`` (delegated to
        ``sift_core.evidence_chain.unharden_sealed_evidence``), and maps any
        failure to a fail-closed unseal error so an unseal is never recorded for
        bytes that are still immutable.
        """
        from sift_core.evidence_chain import (
            EvidenceHardeningError,
            unharden_sealed_evidence,
        )

        case_dir = self._case_artifact_path(case_id)
        if case_dir is None:
            raise PortalServiceError("case_artifact_path_unavailable", http_status=404)
        try:
            unharden_sealed_evidence(case_dir, rel_paths)
        except EvidenceHardeningError as exc:
            logger.error("evidence unseal unhardening failed for case %s: %s", case_id, exc)
            raise PortalServiceError(
                "evidence_unseal_failed", http_status=500
            ) from exc

    def ignore(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        del examiner
        self._scan_evidence(case_id)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        path = _relative_display_path(display_path)
        evidence_id = self._ensure_detected(case_id, path, actor_user, actor_service)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select id::text, display_path, status from app.evidence_ignore(%s, %s, %s, %s, %s)",
                    (evidence_id, reason, reauth_audit_event_id, actor_user, actor_service),
                )
                row = cur.fetchone()
            conn.commit()
        return {"evidence_id": row[0], "display_path": row[1], "status": row[2]} if row else {}

    def retire(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        del examiner
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        path = _relative_display_path(display_path)
        evidence_id = self._evidence_id_for_path(case_id, path)
        if not evidence_id:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select id::text, display_path, status from app.evidence_retire(%s, %s, %s, %s, %s)",
                    (evidence_id, reason, reauth_audit_event_id, actor_user, actor_service),
                )
                row = cur.fetchone()
            conn.commit()
        return {"evidence_id": row[0], "display_path": row[1], "status": row[2]} if row else {}

    def delete_object(
        self,
        *,
        case_id: str,
        display_path: str,
        reason: str,
        reauth_audit_event_id: str,
        actor: Any,
        examiner: str,
    ) -> dict[str, Any]:
        """Operator-delete a non-sealed stray file: physically unlink the bytes
        and record an auditable disposition.

        This exists because ``ignore``/``retire`` only change DB status — the file
        bytes stay on disk and remain readable by the AI agent (which can ``cat``
        any relative path under ``evidence/`` once the gate is OK). To actually
        prevent agent access to a planted/stray/hidden file the operator must be
        able to remove the bytes. Sealed evidence can never be deleted here
        (custody integrity); use the retire path for that.

        Forensic record: the file's sha256 + size are captured before unlink and
        embedded in the append-only custody event via ``evidence_ignore``.
        """
        del examiner
        self._scan_evidence(case_id)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        path = _relative_display_path(display_path)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select id::text, status, seal_status "
                    "from app.evidence_objects where case_id = %s and display_path = %s",
                    (case_id, path),
                )
                row = cur.fetchone()
        if not row:
            raise PortalServiceError("evidence_object_not_found", http_status=404)
        evidence_id, status, seal_status = str(row[0]), row[1], row[2]
        if status not in ("detected", "registered", "ignored") or seal_status != "unsealed":
            # Sealed/violated evidence is custody-protected and must not be deleted.
            raise PortalServiceError("cannot_delete_sealed_evidence", http_status=409)

        # Capture a forensic record of the bytes, then remove them. The file may
        # already be absent (e.g. a transient copy temp that was renamed away), in
        # which case we still record the disposition.
        file_removed = False
        sha: str | None = None
        size: int | None = None
        try:
            abspath: Path | None = self._resolve_evidence_path(case_id, path)
        except PortalServiceError:
            abspath = None
        if abspath is not None:
            try:
                sha, size = _hash_file(abspath)
            except OSError:
                sha, size = None, None
            try:
                abspath.unlink()
                file_removed = True
            except OSError as exc:
                raise PortalServiceError(
                    "evidence_file_delete_failed", http_status=500
                ) from exc

        full_reason = (
            f"operator_deleted_stray_file: {reason.strip()}"
            f" | removed={file_removed} sha256={sha} bytes={size}"
        )
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select id::text, display_path, status "
                    "from app.evidence_ignore(%s, %s, %s, %s, %s)",
                    (evidence_id, full_reason, reauth_audit_event_id, actor_user, actor_service),
                )
                disp = cur.fetchone()
            conn.commit()
        return {
            "evidence_id": disp[0] if disp else evidence_id,
            "display_path": path,
            "status": disp[2] if disp else "ignored",
            "file_removed": file_removed,
            "sha256": sha,
            "bytes": size,
        }

    def _scan_evidence(self, case_id: str) -> None:
        """Reconcile the mounted evidence tree against DB custody authority.

        Two responsibilities, both DB-first:

        - Newly appeared files under ``evidence/`` are recorded via
          ``app.evidence_detect`` (idempotent). A new ``detected`` row keeps the
          aggregate seal status non-OK until the operator registers/ignores and
          reseals, so a post-seal addition fails the gate closed.
        - Sealed files that have gone missing or changed bytes on disk are a
          tamper event. We escalate the case chain to ``violated`` via
          ``app.evidence_mark_violation`` so the DB gate fails closed. File
          manifests/ledgers are never consulted for this decision — only the
          mounted bytes vs. the sealed DB version metadata.

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
                # Detection MUST surface every real file under evidence/, including
                # hidden/dotfiles. The AI agent can read any file in this tree via
                # run_command (relative paths) once the gate is OK, so operator
                # visibility must be a superset of agent access — hiding a file here
                # would make a planted hidden file agent-readable yet operator-
                # invisible (a backdoor). Transient copy temps are handled instead
                # by letting the operator delete stray files from the portal.
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
    ) -> dict[str, Any]:
        """Re-verify sealed evidence against mounted bytes and record the outcome.

        Re-hashes every sealed object's mounted file and compares against the
        sealed ``current_sha256``. Records the result through ``app.evidence_verify``
        (which escalates to ``violated`` on failure). Returns the chain-head dict.
        DB is the authority; no file manifest/ledger is consulted.
        """
        self._scan_evidence(case_id)
        actor_type, actor_user, _actor_agent, actor_service = _actor_columns(actor)
        del actor_type
        ok, issues, manifest_version = self._reverify_sealed(case_id)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select case_id::text, manifest_version, head_seq, head_hash,
                           manifest_hash, seal_status, active_count, issues,
                           last_event_type, last_verified_at
                    from app.evidence_verify(%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        case_id,
                        ok,
                        manifest_version,
                        _jsonb(issues),
                        actor_user,
                        actor_service,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        result = _chain_head_dict(row)
        result["verified"] = ok
        result["issues"] = issues
        return result

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
            if sealed_bytes is not None and actual_bytes != int(sealed_bytes):
                issues.append(f"Modified: {rel}")
            elif sealed_sha and f"sha256:{actual_sha}" != str(sealed_sha):
                issues.append(f"Modified: {rel}")
        return (not issues, issues, manifest_version)

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
        self._scan_evidence(case_id)
        actor_type, actor_user, _actor_agent, _actor_service = _actor_columns(actor)
        del actor_type
        verified, issues, manifest_version = self._reverify_sealed(case_id)
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
        proof_material = {
            "case_id": case_id,
            "manifest_version": manifest_version,
            "manifest_hash": manifest_hash,
            "ledger_tip_hash": ledger_tip_hash,
            "objects": objects,
            "custody_events": events,
            "verified": verified,
            "issues": issues,
        }
        proof_hash = "sha256:" + hashlib.sha256(
            json.dumps(proof_material, sort_keys=True, separators=(",", ":"), default=str).encode(
                "utf-8"
            )
        ).hexdigest()
        metadata: dict[str, Any] = {
            "proof_hash": proof_hash,
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
                # re-acquisition path (app.evidence_reacquire) handles re-sealing a
                # changed item.
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

    def audit_events(
        self, case_id: str, audit_ids: list[str]
    ) -> list[dict[str, Any]]:
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
        #   - details->>'audit_id' — parity with case_manager.py:97
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
                cols = [d[0] for d in cur.description]
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
                aid for aid in ids
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
                cols = [d[0] for d in cur.description]
                for record in cur.fetchall():
                    row = dict(zip(cols, record, strict=False))
                    row["created_at"] = _iso(row.get("created_at"))
                    rows.append(row)

        events: list[dict[str, Any]] = []
        for row in _collapse_activity_rows(rows, safe_limit):
            details = _event_details(row)
            tool = _activity_tool(row)
            status = str(row.get("status") or details.get("status") or "requested").lower()
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
        for key in ("description", "priority", "status", "assignee", "related_findings"):
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
            todo["completed_at"] = todo.get("completed_at") or datetime.now(timezone.utc).isoformat()
        else:
            todo["completed_at"] = None
        self._upsert_todo(case_id, todo_id, todo, source="portal")
        self._mirror_todos(case_id)
        return todo

    def delete_todo(self, *, case_id: str, todo_id: str, examiner: str, actor: Any) -> bool:
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

    def _payload_rows(self, sql: str, case_id: str) -> list[dict[str, Any]]:
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
                    max_seq = max(max_seq, int(tid[len(prefix):]))
                except ValueError:
                    pass
        return max_seq + 1

    def _upsert_todo(self, case_id: str, todo_id: str, payload: dict[str, Any], *, source: str) -> None:
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
