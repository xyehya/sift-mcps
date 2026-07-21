"""Gateway-owned DB adapters injected into the operator portal.

These services close the B-MVP-5 live binding gap: the portal already had DI
slots for evidence, investigation, report, and job state, but production startup
was not wiring concrete Postgres-backed implementations. The services in this
module keep filesystem access server-side, store no absolute paths in Postgres,
and return only portal-safe relative display paths / opaque IDs.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, LiteralString

from sift_core.evidence_storage import StorageProfile

from sift_gateway.custody import admission as custody_admission

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

    def gate_status(self, case_id: str) -> dict[str, Any]:
        """Custody gate status — a PURE computed-gate read (no reconciliation).

        Reads the authoritative four-state gate via ``admission.gate_state`` — no
        disk scan, no ``app.evidence_inventory`` / ``app.admission_observations``
        write. Reconciliation happens in exactly ONE place, the target
        custody-status route (``GET /portal/custody/status`` ->
        ``admission.reconcile``); this read method (and therefore the passive 15s
        chain-status poll and every future read caller) can never scan disk or grow
        the observation history (SPEC §Pre-seal staging window: "no continuous
        observation"). Agent dispatch reconciliation is separate and unchanged (it
        runs through ``policy_middleware`` -> ``check_evidence_gate_db``, not here).
        """
        gate = custody_admission.gate_state(case_id, self._dsn)
        with self._connect() as conn:
            with conn.cursor() as cur:
                # Unregistered (Add & Seal targets) is the point-in-time Pending
                # list, which lives in ``app.evidence_inventory`` — ``custody_
                # reconcile`` upserts on-disk entries there and NEVER creates an
                # ``evidence_object`` (EC-1/EC-4; there is no ``detected``/
                # ``registered`` object status in the target model). This mirrors
                # ``app.custody_gate_state``'s ``v_pending`` predicate EXACTLY so
                # the surfaced list matches the authoritative BLOCKED_PENDING gate:
                # present, safe (regular), undisposed, and not an active sealed
                # object's path.
                cur.execute(
                    """
                    select i.display_path
                    from app.evidence_inventory i
                    where i.case_id = %(case_id)s
                      and i.disposition = 'pending'
                      and i.entry_kind = 'regular'
                      and not exists (
                          select 1 from app.evidence_objects o
                          where o.case_id = %(case_id)s and o.status = 'sealed'
                            and o.display_path = i.display_path
                      )
                    order by i.display_path
                    """,
                    {"case_id": case_id},
                )
                unregistered = [str(r[0]) for r in cur.fetchall()]
        return {
            "gate_state": gate["gate_state"],
            "manifest_version": gate["manifest_version"],
            "issues": gate["issues"],
            "unregistered": unregistered,
        }

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        """EC-4-compliant inventory listing — a PURE DB read (no reconciliation).

        Field contract is unchanged (``current_sha256`` / ``current_bytes`` /
        ``description`` / ``source`` / ``seal_status`` / ``registered_at`` — both
        ``case_dashboard.routes.get_evidence`` and ``_db_evidence_chain_status``
        key off these exact names).

        Sealed rendering is gated on CURRENT-MANIFEST authority (CP3 final fix):
        an Evidence Object renders Sealed ONLY when its current Evidence Version is
        an ACTIVE member of the case's LATEST Manifest Version — never from
        ``evidence_objects.status`` alone and never from a historical membership.
        Because ``custody_seal_commit`` / ``custody_retire`` carry still-sealed
        objects forward into each new manifest as new ACTIVE membership rows, a
        join to *every* ACTIVE membership fanned one object into multiple rows; the
        ``latest_manifest`` CTE constrains the join to the single current manifest,
        so each object yields at most one row and a Retired object (absent as ACTIVE
        from the latest manifest) renders Retired exactly once.

        Pending / Ignored come from ``app.evidence_inventory`` (present-on-disk
        truth; ``custody_reconcile`` writes it, never ``evidence_objects`` —
        EC-1/EC-4). The inventory branch excludes a path only when an object at that
        path has authoritative current-manifest membership (not merely a stale
        ``status='sealed'`` row), so a sealed path is never duplicated as Pending
        while a retired object's surviving bytes correctly resurface as Pending for
        explicit reacquisition. Digest/bytes stay sealed-only (the inventory
        ``sha256`` is a cheap fingerprint, not the custody digest), so nothing
        digestless ever renders Sealed.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    with latest_manifest as (
                        select id
                        from app.manifest_versions
                        where case_id = %(case_id)s
                        order by manifest_version desc
                        limit 1
                    )
                    select o.id::text, o.display_name, o.display_path,
                           o.description, o.source, o.status,
                           v.sha256, v.bytes, m.manifest_version,
                           o.registered_at, o.sealed_at
                    from app.evidence_objects o
                    left join app.evidence_versions v on v.id = o.current_version_id
                    left join app.manifest_membership mm
                      on mm.manifest_version_id = (select id from latest_manifest)
                         and mm.evidence_object_id = o.id
                         and mm.evidence_version_id = o.current_version_id
                         and mm.entry_status = 'ACTIVE'
                    left join app.manifest_versions m on m.id = mm.manifest_version_id
                    where o.case_id = %(case_id)s
                    union all
                    select i.id::text, i.display_name, i.display_path,
                           null::text, null::text,
                           case when i.disposition = 'ignored'
                                then 'ignored' else 'detected' end,
                           null::text, i.bytes, null::integer,
                           i.first_observed_at, null::timestamptz
                    from app.evidence_inventory i
                    where i.case_id = %(case_id)s
                      and i.entry_kind = 'regular'
                      and not exists (
                          select 1
                          from app.evidence_objects o
                          join app.manifest_membership mm
                            on mm.manifest_version_id = (select id from latest_manifest)
                               and mm.evidence_object_id = o.id
                               and mm.evidence_version_id = o.current_version_id
                               and mm.entry_status = 'ACTIVE'
                          where o.case_id = %(case_id)s
                            and o.display_path = i.display_path
                      )
                    order by display_path
                    """,
                    {"case_id": case_id},
                )
                rows = cur.fetchall()
        result: list[dict[str, Any]] = []
        for (
            evidence_id,
            display_name,
            display_path,
            description,
            source,
            raw_status,
            sha256,
            size,
            manifest_version,
            registered_at,
            sealed_at,
        ) in rows:
            sealed = manifest_version is not None
            result.append(
                {
                    "evidence_id": evidence_id,
                    "display_name": display_name,
                    "display_path": display_path,
                    "description": description,
                    "source": source,
                    "status": "sealed" if sealed else raw_status,
                    "seal_status": "sealed" if sealed else "unsealed",
                    "current_sha256": sha256 if sealed else None,
                    "current_bytes": size if sealed else None,
                    "manifest_version": manifest_version,
                    "registered_at": _iso(registered_at),
                    "sealed_at": _iso(sealed_at) if sealed else None,
                }
            )
        return result

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


