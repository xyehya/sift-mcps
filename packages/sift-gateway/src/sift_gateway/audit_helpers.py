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
import uuid
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
    token_id = _resolve_db_token_id(token_id, pid)
    if ptype == "user":
        return "user", (str(pid) if pid else None), None, None, token_id
    if ptype == "agent":
        agent_id = _identity_attr(principal, "agent_id") or pid
        return "agent", None, (str(agent_id) if agent_id else None), None, token_id
    if ptype == "service":
        return "service", None, None, (str(pid) if pid else None), token_id
    return "system", None, None, None, token_id


def _resolve_db_token_id(token_id: Any, principal_id: Any) -> str | None:
    """Resolve a value safe for the ``audit_events.actor_token_id`` FK column.

    This is a correctness guard, not a legacy shim. It returns a real
    ``app.mcp_tokens.id`` value, never a Supabase principal id/hash. Supabase JWT
    identities reuse their principal row id as ``Identity.token_id`` for FastMCP
    client attribution; that value is not an ``app.mcp_tokens`` row, so writing it
    to ``audit_events.actor_token_id`` would violate the foreign key. We therefore
    drop it (return ``None``) whenever the token id matches the principal id, or is
    not a UUID. PR02 tokens that carry a distinct UUID token id remain valid for
    the FK and are passed through unchanged.
    """
    if not token_id:
        return None
    value = str(token_id)
    if principal_id and value == str(principal_id):
        return None
    try:
        uuid.UUID(value)
    except (TypeError, ValueError):
        return None
    return value


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


# Maximum nesting depth explored by _collect_audit_ids_from_obj.  Prevents
# pathologically deep responses (e.g. {"a":{"a":{…2000 deep…}}}) from
# exhausting the Python call stack before the count budget is hit.
_AUDIT_MAX_DEPTH = 64


def _collect_audit_ids_from_obj(
    obj: Any, out: list[str], budget: list[int], depth: int = 0
) -> None:
    """Recursively collect values under ``audit_id``/``audit_ids`` keys.

    Conservative: only follows dict and list nodes; collects non-empty strings
    under keys whose name is exactly ``audit_id`` or ``audit_ids``.  Bounded by
    ``budget[0]`` (item count) and ``depth`` (nesting level, capped at
    ``_AUDIT_MAX_DEPTH``) so neither the output list nor the call stack can grow
    unbounded regardless of response shape.
    """
    if budget[0] <= 0 or depth > _AUDIT_MAX_DEPTH:
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in ("audit_id", "audit_ids"):
                if isinstance(val, str) and val.strip():
                    out.append(val.strip())
                    budget[0] -= 1
                elif isinstance(val, (list, tuple)):
                    for item in val:
                        if budget[0] <= 0:
                            break
                        if isinstance(item, str) and item.strip():
                            out.append(item.strip())
                            budget[0] -= 1
            else:
                # Recurse into nested dicts/lists (e.g. provenance, stages)
                _collect_audit_ids_from_obj(val, out, budget, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            if budget[0] <= 0:
                break
            _collect_audit_ids_from_obj(item, out, budget, depth + 1)


def _extract_all_audit_ids(result: list) -> list[str]:
    """Return every audit-id string visible in *result* content, deduped.

    Collects values found under ``audit_id`` or ``audit_ids`` keys anywhere in
    the parsed JSON response (top-level, nested ``provenance``, ``stages``,
    ingest provenance, etc.).  Only string values that appear under those exact
    key names are gathered — no arbitrary strings.  The output list is bounded
    by ``_AUDIT_MAX_ITEMS`` and deduplicated while preserving first-seen order.
    """
    seen: set[str] = set()
    collected: list[str] = []
    budget = [_AUDIT_MAX_ITEMS]
    for item in result:
        text = getattr(item, "text", None)
        if not text:
            continue
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, AttributeError, TypeError):
            continue
        _collect_audit_ids_from_obj(data, collected, budget)
    # Deduplicate preserving first-seen order.
    out: list[str] = []
    for aid in collected:
        if aid not in seen:
            seen.add(aid)
            out.append(aid)
    return out


# ---------------------------------------------------------------------------
# Audit-detail redaction + bounding (gateway-centric detail capture).
#
# The MCP transport envelope now records the tool's REDACTED arguments
# (pre-dispatch) and a BOUNDED result detail (post-dispatch) in the
# ``app.audit_events`` ``details`` JSONB. Operators need the command/query that
# was run and the rich provenance, but the audit row must never carry raw
# secrets, JWTs, DSNs, service keys, passwords, or full case/evidence absolute
# paths, and must not bloat. We therefore reuse the gateway's own response-guard
# redactors (secret + sensitive-path) and then bound every value.
#
# Redaction policy mirrors the agent-facing choke point so the same prefixes /
# secret patterns are enforced for the audit detail.
# ---------------------------------------------------------------------------

# Per-string / total-bytes ceilings for an audit detail block. Large argument or
# result values are truncated with an explicit marker so rows stay small.
_AUDIT_MAX_STR = 4_096          # max chars per individual string value
_AUDIT_MAX_TOTAL = 16_384       # soft ceiling on the serialized detail block
_AUDIT_MAX_ITEMS = 200          # max items kept from any one list
_AUDIT_TRUNC_MARK = "...[truncated]"


def _bound_value(value: Any, *, _budget: list[int]) -> Any:
    """Recursively bound a JSON-like value for compact audit storage.

    ``_budget`` is a single-element list tracking the remaining total character
    budget across the whole structure; once exhausted, further content is
    dropped with a marker. Strings longer than ``_AUDIT_MAX_STR`` are truncated.
    Lists are capped at ``_AUDIT_MAX_ITEMS``. This runs AFTER redaction, so a
    secret can never straddle a truncation boundary and leak a partial value.
    """
    if _budget[0] <= 0:
        return _AUDIT_TRUNC_MARK
    if isinstance(value, str):
        s = value
        if len(s) > _AUDIT_MAX_STR:
            s = s[:_AUDIT_MAX_STR] + _AUDIT_TRUNC_MARK
        if len(s) > _budget[0]:
            s = s[: max(_budget[0], 0)] + _AUDIT_TRUNC_MARK
        _budget[0] -= len(s)
        return s
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        _budget[0] -= 8
        return value
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if _budget[0] <= 0:
                out["_truncated"] = True
                break
            key = str(k)
            _budget[0] -= len(key)
            out[key] = _bound_value(v, _budget=_budget)
        return out
    if isinstance(value, (list, tuple)):
        out_items: list[Any] = []
        for index, item in enumerate(value):
            if index >= _AUDIT_MAX_ITEMS or _budget[0] <= 0:
                out_items.append(_AUDIT_TRUNC_MARK)
                break
            out_items.append(_bound_value(item, _budget=_budget))
        return out_items
    # Unknown type -> bounded string form.
    return _bound_value(str(value), _budget=_budget)


def redact_for_audit(value: Any, *, case_dir: str | None = None) -> Any:
    """Redact then bound a JSON-like value for the audit ``details`` JSONB.

    Order: secret redaction (critical+high -> ``[REDACTED:...]``) -> sensitive
    absolute-path redaction (case/evidence/mount/state prefixes ->
    ``[REDACTED:absolute_path]``; in-case absolutes collapse to relative display
    paths) -> bounding/truncation. Redaction always runs (no override) so the
    operator audit row never carries a raw secret or full host path. Failures in
    the redactor degrade to a bounded, secret-stripped string rather than
    leaking the original.
    """
    try:
        from sift_gateway.response_guard import (
            redact_paths_structured,
            redact_structured,
        )

        case_dir_resolved: str | None = None
        if case_dir:
            try:
                import os.path

                case_dir_resolved = os.path.realpath(case_dir)
            except (OSError, ValueError):
                case_dir_resolved = case_dir

        redacted, _ = redact_structured(value, override_active=False)
        redacted, _ = redact_paths_structured(
            redacted, case_dir_resolved=case_dir_resolved
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("audit detail redaction failed; storing marker: %s", exc)
        return {"_redaction_error": type(exc).__name__}
    return _bound_value(redacted, _budget=[_AUDIT_MAX_TOTAL])


# Top-level run_command response keys that carry rich, operator-useful
# provenance/detail. Each is independently redacted+bounded before storage.
_RUN_COMMAND_DETAIL_KEYS = (
    "provenance",
    "stages",
    "failed_stages",
    "privilege_escalation",
    "exit_code",
    "full_output_sha256",
    "full_output_bytes",
    "agent_action",
    "warnings",
)


def _extract_run_command_detail(result: list, *, case_dir: str | None = None) -> dict | None:
    """Extract the rich run_command provenance/detail block from the response.

    Returns a redacted+bounded dict (command, exit_code, input/output hashes,
    pipeline stages, privilege events) or ``None`` if the response is not a
    parseable run_command payload. The command string itself is redacted like
    any other argument so a secret embedded in the command never lands raw.
    """
    for item in result:
        text = getattr(item, "text", None)
        if not text:
            continue
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, AttributeError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        is_run_command = (
            data.get("tool") == "run_command"
            or data.get("tool_name") == "run_command"
            or "provenance" in data
        )
        if not is_run_command:
            continue
        detail: dict[str, Any] = {}
        for key in _RUN_COMMAND_DETAIL_KEYS:
            if key in data:
                detail[key] = data[key]
        # exit_code is carried inside the parsed ``data`` payload, not at the top
        # level; surface it for the detail block when present. (The command
        # string itself is captured pre-dispatch as the redacted call arguments,
        # not echoed in the agent-facing result.)
        if "exit_code" not in detail:
            inner = data.get("data")
            if isinstance(inner, dict) and "exit_code" in inner:
                detail["exit_code"] = inner["exit_code"]
        if not detail:
            return None
        return redact_for_audit(detail, case_dir=case_dir)
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
