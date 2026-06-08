"""Shared audit helpers for gateway proxy-side auditing.

BATCH-K1: in DB-active mode the Gateway's authoritative audit trail is
``app.audit_events`` (DB-first), not the local JSONL mirror. :class:`DbAuditWriter`
is the single helper used by the MCP policy middleware to reserve a pre-dispatch
audit envelope and write the result/failure receipt for each tool call. A failed
*required* audit write raises :class:`AuditPersistError` so a mutating call can
fail closed rather than execute unaudited.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class AuditPersistError(Exception):
    """Raised when a required DB audit write cannot be persisted."""


def _identity_attr(principal: Any, name: str) -> Any:
    if principal is None:
        return None
    if isinstance(principal, dict):
        return principal.get(name)
    return getattr(principal, name, None)


def _actor_columns(principal: Any) -> tuple[str, str | None, str | None, str | None, str | None]:
    """Map a principal to (actor_type, user_id, agent_id, service_id, token_id).

    Mirrors the actor model used by ActiveCaseService / JobService so the
    transport envelope attribution matches lifecycle audit events.
    """
    ptype = _identity_attr(principal, "principal_type")
    pid = _identity_attr(principal, "principal_id")
    token_id = _identity_attr(principal, "token_id")
    token_id = str(token_id) if token_id else None
    if ptype == "user":
        return "user", (str(pid) if pid else None), None, None, token_id
    if ptype == "agent":
        agent_id = _identity_attr(principal, "agent_id") or pid
        return "agent", None, (str(agent_id) if agent_id else None), None, token_id
    if ptype == "service":
        return "service", None, None, (str(pid) if pid else None), token_id
    return "system", None, None, None, token_id


def _jsonb(value: dict[str, Any]):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover - test/non-psycopg env
        return value
    return Jsonb(value)


class DbAuditWriter:
    """DB-first audit-event writer for ``app.audit_events`` (K1).

    Each write opens its own short service connection (the same pattern as
    ActiveCaseService/JobService) and commits independently, so a transport
    audit row is durable regardless of the tool's own transaction. ``connect``
    is injectable for unit tests; production passes a DSN.
    """

    def __init__(self, dsn: str | None = None, *, connect: Any | None = None) -> None:
        self._dsn = dsn
        self._connect_override = connect

    def _connect(self):
        if self._connect_override is not None:
            return self._connect_override()
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - deployment env
            raise AuditPersistError("psycopg is required for DB audit") from exc
        return psycopg.connect(self._dsn)

    def record(
        self,
        *,
        event_type: str,
        actor: Any,
        case_id: str | None,
        source: str,
        status: str,
        summary: str | None = None,
        details: dict[str, Any] | None = None,
        job_id: str | None = None,
        request_id: str | None = None,
    ) -> str:
        """Insert one audit event and return its id. Raises AuditPersistError on failure."""
        actor_type, user_id, agent_id, service_id, token_id = _actor_columns(actor)
        fields = ["event_type", "actor_type", "source", "status"]
        values: list[Any] = [event_type, actor_type, source, status]
        if case_id:
            fields.append("case_id")
            values.append(case_id)
        if user_id:
            fields.append("actor_user_id")
            values.append(user_id)
        if agent_id:
            fields.append("actor_agent_id")
            values.append(agent_id)
        if service_id:
            fields.append("actor_service_identity_id")
            values.append(service_id)
        if token_id:
            fields.append("actor_token_id")
            values.append(token_id)
        if job_id:
            fields.append("job_id")
            values.append(job_id)
        if request_id:
            fields.append("request_id")
            values.append(request_id)
        if summary is not None:
            fields.append("summary")
            values.append(summary)
        fields.append("details")
        values.append(_jsonb(details or {}))
        sql = (
            f"insert into app.audit_events ({', '.join(fields)}) "
            f"values ({', '.join(['%s'] * len(values))}) returning id::text"
        )
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, values)
                    row = cur.fetchone()
                conn.commit()
        except AuditPersistError:
            raise
        except Exception as exc:
            raise AuditPersistError(f"audit_events insert failed: {type(exc).__name__}") from exc
        if not row or row[0] is None:
            raise AuditPersistError("audit_events insert returned no id")
        return str(row[0])


def _extract_audit_id(result: list) -> str | None:
    """Extract audit_id from backend response content."""
    for item in result:
        text = getattr(item, "text", None)
        if text:
            try:
                data = json.loads(text)
                return data.get("audit_id")
            except (json.JSONDecodeError, AttributeError):
                pass
    return None


def _truncate_params(params: dict, max_len: int = 1000) -> dict:
    """Truncate large param values for audit storage."""
    truncated = {}
    for k, v in params.items():
        s = str(v)
        truncated[k] = s[:max_len] + "..." if len(s) > max_len else v
    return truncated


def _summarize_result(result: list) -> dict:
    """Extract lightweight summary from backend response."""
    for item in result:
        text = getattr(item, "text", None)
        if text:
            try:
                data = json.loads(text)
                summary = {}
                for key in ("exit_code", "success", "error", "truncated", "found"):
                    if key in data:
                        summary[key] = data[key]
                return summary
            except (json.JSONDecodeError, AttributeError):
                pass
    return {"raw_items": len(result)}
