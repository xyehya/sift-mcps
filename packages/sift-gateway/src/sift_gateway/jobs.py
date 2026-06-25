"""Gateway adapter over the BATCH-D1 durable job state machine.

The Gateway is the only policy boundary between portal/agent callers and the
Postgres job control plane. Callers never touch ``app.jobs`` directly; they go
through this service, which:

  * enqueues work via the ``app.enqueue_job`` RPC and returns ONLY the opaque
    ``job_id`` (plus the Gateway audit event id stored as
    ``enqueue_audit_event_id`` on the job row);
  * polls status via the ``app.job_status_public`` sanitized read model and
    returns an agent-safe subset — never ``spec_internal``, ``worker_id``, lease
    internals, local OS paths, or raw DB errors;
  * reaps stale leases via the ``app.expire_stale_jobs`` RPC from a
    Gateway-owned background hook.

Column/RPC/view names here are pinned to
``supabase/migrations/202606081200_durable_jobs.sql``; do not drift from it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sift_gateway.identity import Identity

logger = logging.getLogger(__name__)

# feat/opensearch-workers: "ingest" is RE-ENABLED. The OpenSearch ingest pipeline
# (FUSE-mount E01 + Hayabusa + vol3 -> index) is decoupled from the gateway stdio
# proxy and dispatched as a durable job to the dedicated, least-privilege
# ``sift-opensearch-worker@`` units (the only place with the shared mount
# namespace FUSE needs). "enrich" rides the same path. The gateway remains the
# sole enqueue boundary (OpenSearchJobDispatchMiddleware enqueues here after
# auth/evidence-gate/audit). "report" stays a forward-looking allowlist entry.
_VALID_JOB_TYPES = frozenset({"ingest", "enrich", "report", "run_command"})

# Fields exposed by app.job_status_public that are safe to return to
# portal/agent callers. The view itself excludes spec_internal and lease
# internals; this is the explicit allow-list the adapter returns, so a future
# view change cannot silently widen the agent surface.
#
# feat/opensearch-workers adds two REALTIME fields for the decoupled workers:
#   * worker_label  — non-sensitive liveness label of the worker holding the job
#                     (e.g. ``osw-1-ab12cd``); null when not leased. Lets the
#                     agent/operator see N-way parallel ingest and live progress.
#   * current_step  — latest job step {step_index,name,status,detail,updated_at}
#                     with path-free detail counts (handler contract). Surfaces
#                     phase + indexed/host/hayabusa progress before the terminal
#                     result_public lands.
_PUBLIC_STATUS_FIELDS = (
    "job_id",
    "job_type",
    "status",
    "case_id",
    "evidence_id",
    "priority",
    "attempts",
    "max_attempts",
    "spec_public",
    "result_public",
    "error_summary",
    "provenance_id",
    "created_at",
    "started_at",
    "finished_at",
    "updated_at",
    "step_count",
    "steps_succeeded",
    "worker_label",
    "current_step",
)


class JobServiceError(Exception):
    def __init__(self, reason: str, *, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise RuntimeError("psycopg is required for durable job access") from exc
    return psycopg.connect(dsn)


def _jsonb(value: dict[str, Any]):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover
        return value
    return Jsonb(value)


def _dt_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _principal_type(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return "operator" if principal.principal_type == "user" else principal.principal_type
    if isinstance(principal, dict):
        value = principal.get("principal_type")
        return str(value) if value else None
    return None


def _principal_id(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return principal.principal_id
    if isinstance(principal, dict):
        value = principal.get("principal_id")
        return str(value) if value else None
    return None


def _agent_id(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return principal.agent_id
    if isinstance(principal, dict):
        value = principal.get("agent_id")
        return str(value) if value else None
    return None


def _requested_by(principal: Any) -> tuple[str, str | None, str | None, str | None]:
    """Map a principal to (requested_by_type, user_id, agent_id, service_id).

    Mirrors the audit actor model used by ActiveCaseService / the backend
    registry so attribution on the job row matches the audit event.
    """
    ptype = _principal_type(principal)
    pid = _principal_id(principal)
    if ptype == "operator":
        return "user", pid, None, None
    if ptype == "agent":
        return "agent", None, _agent_id(principal) or pid, None
    if ptype == "service":
        return "service", None, None, pid
    return "system", None, None, None


@dataclass(frozen=True)
class EnqueuedJob:
    job_id: str

    def public_dict(self) -> dict[str, Any]:
        # Enqueue returns ONLY the opaque job id to portal/agent callers. The
        # Gateway audit linkage (enqueue_audit_event_id) is persisted on the job
        # row server-side and is never echoed back to the caller.
        return {"job_id": self.job_id}


class JobService:
    """Gateway-owned adapter over the D1 durable job RPCs/view."""

    def __init__(self, dsn: str, *, audit: Any | None = None) -> None:
        self._dsn = dsn
        self._audit = audit

    def _connect(self):
        return _connect(self._dsn)

    # -- enqueue ------------------------------------------------------------

    def enqueue_job(
        self,
        *,
        job_type: str,
        case_id: str | None = None,
        evidence_id: str | None = None,
        spec_public: dict[str, Any] | None = None,
        spec_internal: dict[str, Any] | None = None,
        priority: int = 100,
        max_attempts: int = 3,
        actor: Any | None = None,
    ) -> EnqueuedJob:
        """Create a queued job via ``app.enqueue_job`` and return its id only.

        A single transaction writes the Gateway enqueue audit event first, then
        calls the RPC with that audit event id as ``p_enqueue_audit_event_id`` so
        the durable row carries ``enqueue_audit_event_id`` for the audit chain.
        Returns only the opaque ``job_id`` (no spec/internal/worker data).
        """
        if job_type not in _VALID_JOB_TYPES:
            raise JobServiceError("invalid_job_type")
        spec_public = spec_public if isinstance(spec_public, dict) else {}
        spec_internal = spec_internal if isinstance(spec_internal, dict) else {}

        with self._connect() as conn:
            with conn.cursor() as cur:
                audit_event_id = self._insert_audit(
                    cur,
                    event_type="job.enqueued",
                    actor=actor,
                    case_id=case_id,
                    status="success",
                    summary=f"enqueued {job_type} job",
                    details={
                        "job_type": job_type,
                        **({"case_id": case_id} if case_id else {}),
                        **({"evidence_id": evidence_id} if evidence_id else {}),
                    },
                )
                rb_type, rb_user, rb_agent, rb_service = _requested_by(actor)
                cur.execute(
                    """
                    select app.enqueue_job(
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        job_type,
                        case_id,
                        evidence_id,
                        _jsonb(spec_public),
                        _jsonb(spec_internal),
                        int(priority),
                        int(max_attempts),
                        rb_type,
                        rb_user,
                        rb_agent,
                        rb_service,
                        audit_event_id,
                    ),
                )
                row = cur.fetchone()
                if not row or row[0] is None:
                    raise JobServiceError("job_enqueue_failed", http_status=500)
                job_id = str(row[0])
                conn.commit()
        self._notify_audit("job.enqueued", actor, job_id)
        return EnqueuedJob(job_id=job_id)

    # -- status -------------------------------------------------------------

    def job_status_public(self, job_id: str, principal: Any | None = None) -> dict[str, Any]:
        """Return the sanitized status for ``job_id`` from ``app.job_status_public``.

        Only the agent-safe allow-list is returned. ``spec_internal``,
        ``worker_id``, lease internals, local paths, and DB errors are never
        exposed. Case membership is enforced when a principal is supplied.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select job_id::text, job_type, status, case_id::text,
                           evidence_id::text, priority, attempts, max_attempts,
                           spec_public, result_public, error_summary,
                           provenance_id::text, created_at, started_at,
                           finished_at, updated_at, step_count, steps_succeeded,
                           worker_label, current_step
                    from app.job_status_public
                    where job_id = %s
                    """,
                    (job_id,),
                )
                row = cur.fetchone()
        if not row:
            raise JobServiceError("job_not_found", http_status=404)
        record = dict(zip(_PUBLIC_STATUS_FIELDS, row, strict=True))
        if principal is not None:
            self._assert_case_member(principal, record.get("case_id"))
        return self._sanitize_status(record)

    def list_ingest_jobs_for_case(
        self,
        case_id: str,
        *,
        include_terminal: bool = True,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return recent ingest/enrich durable jobs for ``case_id`` from app.job_status_public.

        Used by opensearch_ingest_status in DB-active mode to populate ingests[]
        instead of returning an empty list. Only the safe allow-list fields are
        returned (no spec_internal, lease internals, or worker_id). Fail-closed:
        returns [] on any DB/connection error so opensearch_ingest_status degrades
        gracefully.

        Args:
            case_id: The case UUID to filter by (required; "*" not supported here —
                the caller filters when needed).
            include_terminal: When True (default), include recently finished jobs
                (succeeded/failed) as well as active ones so the agent can see
                the last completed run. When False, only pending/running/retrying.
            limit: Max rows returned (default 10, hard cap).
        """
        limit = max(1, min(limit, 50))
        if include_terminal:
            status_filter = "('pending', 'running', 'retrying', 'succeeded', 'failed')"
        else:
            status_filter = "('pending', 'running', 'retrying')"
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        select job_id::text, job_type, status, case_id::text,
                               evidence_id::text, priority, attempts, max_attempts,
                               spec_public, result_public, error_summary,
                               provenance_id::text, created_at, started_at,
                               finished_at, updated_at, step_count, steps_succeeded,
                               worker_label, current_step
                        from app.job_status_public
                        where case_id = %s
                          and job_type in ('ingest', 'enrich')
                          and status in {status_filter}
                        order by created_at desc
                        limit %s
                        """,
                        (case_id, limit),
                    )
                    rows = cur.fetchall()
        except Exception:  # noqa: BLE001 - fail-closed; caller returns []
            logger.warning(
                "list_ingest_jobs_for_case: DB error listing jobs for case %s", case_id
            )
            return []
        return [self._sanitize_status(dict(zip(_PUBLIC_STATUS_FIELDS, row, strict=True))) for row in rows]

    def _sanitize_status(self, record: dict[str, Any]) -> dict[str, Any]:
        sanitized: dict[str, Any] = {}
        for field in _PUBLIC_STATUS_FIELDS:
            value = record.get(field)
            if field in ("created_at", "started_at", "finished_at", "updated_at"):
                value = _dt_iso(value)
            sanitized[field] = value
        return sanitized

    def _assert_case_member(self, principal: Any, case_id: str | None) -> None:
        """Deny status reads for cases the principal is not a member of.

        A null case_id (system/maintenance job) is readable. Operators with an
        owner/admin system role bypass per-case membership (mirrors
        ActiveCaseService list semantics).
        """
        if not case_id:
            return
        sys_role = None
        if isinstance(principal, Identity):
            sys_role = principal.system_role
        elif isinstance(principal, dict):
            sys_role = principal.get("system_role")
        if sys_role in ("owner", "admin"):
            return
        default_case = None
        if isinstance(principal, Identity):
            default_case = principal.case_id
        elif isinstance(principal, dict):
            default_case = principal.get("case_id") or principal.get("default_case_id")
        if default_case and str(default_case) == str(case_id):
            return
        memberships = ()
        if isinstance(principal, Identity):
            memberships = principal.case_memberships
            for m in memberships:
                if m.case_id == case_id:
                    return
        elif isinstance(principal, dict):
            memberships = principal.get("case_memberships") or ()
            for m in memberships:
                if isinstance(m, dict) and str(m.get("case_id")) == case_id:
                    return
        raise JobServiceError("job_case_membership_required", http_status=403)

    # -- reaper -------------------------------------------------------------

    def expire_stale_jobs(self) -> int:
        """Reclaim leases whose worker stopped heartbeating.

        Calls the ``app.expire_stale_jobs`` RPC and returns the number of jobs
        re-queued or marked expired. Safe to call periodically from a
        Gateway-owned background hook; it needs no per-row worker identity.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("select app.expire_stale_jobs()")
                row = cur.fetchone()
                conn.commit()
        count = int(row[0]) if row and row[0] is not None else 0
        if count:
            logger.info("expire_stale_jobs reclaimed %d stale job lease(s)", count)
        return count

    # -- audit --------------------------------------------------------------

    def _insert_audit(
        self,
        cur: Any,
        *,
        event_type: str,
        actor: Any | None,
        case_id: str | None,
        status: str,
        summary: str,
        details: dict[str, Any],
    ) -> str:
        """Insert a gateway audit event and return its id (for job linkage)."""
        actor_type, actor_user, actor_agent, actor_service = _requested_by(actor)
        columns = {
            "user": ("actor_user_id", actor_user),
            "agent": ("actor_agent_id", actor_agent),
            "service": ("actor_service_identity_id", actor_service),
        }
        fields = ["case_id", "event_type", "actor_type", "source", "status", "summary", "details"]
        values: list[Any] = [
            case_id,
            event_type,
            actor_type,
            "gateway_jobs",
            status,
            summary,
            _jsonb(details),
        ]
        actor_column, actor_id = columns.get(actor_type, (None, None))
        if actor_column and actor_id:
            fields.insert(3, actor_column)
            values.insert(3, actor_id)
        cur.execute(
            f"""
            insert into app.audit_events ({", ".join(fields)})
            values ({", ".join(["%s"] * len(values))})
            returning id::text
            """,
            values,
        )
        row = cur.fetchone()
        return str(row[0]) if row and row[0] is not None else None

    def _notify_audit(self, event_type: str, actor: Any | None, job_id: str) -> None:
        if self._audit is None:
            return
        try:
            principal = getattr(actor, "principal", None)
            if principal is None and isinstance(actor, dict):
                principal = actor.get("display_name") or actor.get("email")
            self._audit.log(
                tool=event_type,
                params={"job_id": job_id},
                result_summary="success",
                source="gateway_jobs",
                extra={"job_id": job_id},
                examiner_override=principal,
            )
        except Exception as exc:
            logger.warning("Audit log failed for %s (job %s): %s", event_type, job_id, exc)
