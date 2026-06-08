"""Request-local authority context for Gateway/worker-owned core tool calls.

BATCH-K1: this is the single ``AuthorityContext`` contract that the Gateway (for
MCP/REST request paths) and the local job worker load from Postgres authority and
pass down into in-process ``sift-core`` tools. In DB-active mode it is the *only*
source of the active case for authoritative work — core resolvers must not fall
back to ``SIFT_CASE_DIR`` / ``~/.sift/active_case`` / ``CASE.yaml`` to decide which
case a mutating call targets (see :func:`db_authority_active`).

The context carries the case UUID, case key, the worker-only artifact path, the
calling principal, the membership role, the caller's tool scopes, the evidence
gate status/version observed at request time, the request id, and the audit event
ids reserved for the call so mutating handlers can attach them to DB transitions.

``ActiveCaseContext`` remains as a backward-compatible alias for the historical
name used across the codebase.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class AuthorityContext:
    case_id: str
    case_key: str
    artifact_path: str | None = None
    membership_role: str | None = None
    # K1 additive fields (all defaulted so existing positional/keyword
    # constructors keep working). principal/scopes/evidence-gate snapshot let
    # core handlers audit and gate without re-reading tamperable local state.
    principal: str | None = None
    principal_type: str | None = None
    tool_scopes: frozenset[str] = frozenset()
    evidence_gate_status: str | None = None
    evidence_gate_version: int | None = None
    request_id: str | None = None
    # When True, authoritative work must use this context only and fail closed
    # if it is missing — never the legacy env/pointer-file fallback.
    db_active: bool = False
    # Audit event ids reserved for this request (pre-dispatch envelope first,
    # then result/failure receipt). A mutable list so a later middleware can
    # attach the reserved id without rebuilding the frozen context.
    audit_event_ids: list[str] = field(default_factory=list)

    @property
    def case_dir(self) -> Path | None:
        if not self.artifact_path:
            return None
        return Path(self.artifact_path)

    @property
    def primary_audit_event_id(self) -> str | None:
        return self.audit_event_ids[0] if self.audit_event_ids else None

    def record_audit_event(self, event_id: str | None) -> None:
        """Attach a reserved audit event id (no-op for empty ids)."""
        if event_id:
            self.audit_event_ids.append(str(event_id))


# Backward-compatible alias for the historical name used across sift-core,
# sift-gateway, and the worker handlers.
ActiveCaseContext = AuthorityContext


_ACTIVE_CASE_CONTEXT: ContextVar[AuthorityContext | None] = ContextVar(
    "sift_active_case_context",
    default=None,
)


def current_active_case() -> AuthorityContext | None:
    return _ACTIVE_CASE_CONTEXT.get()


# Canonical accessor name for the K1 contract; alias of current_active_case().
current_authority_context = current_active_case


def _env_db_active() -> bool:
    return os.environ.get("SIFT_DB_ACTIVE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def db_authority_active() -> bool:
    """Return True when Postgres is the active-case authority for this call.

    DB-active is signalled either by the current request's
    :class:`AuthorityContext` (``db_active=True``, set by the Gateway/worker when
    the case was loaded from Postgres) or by the process-wide ``SIFT_DB_ACTIVE``
    env flag (set by the worker bootstrap when a control-plane DSN is configured).

    When this returns True, core resolvers must not read ``SIFT_CASE_DIR`` or
    ``~/.sift/active_case`` as active-case authority; they use the context and
    fail closed if it is absent.
    """
    ctx = current_active_case()
    if ctx is not None and ctx.db_active:
        return True
    return _env_db_active()


@contextmanager
def use_active_case_context(context: AuthorityContext | None) -> Iterator[None]:
    token = _ACTIVE_CASE_CONTEXT.set(context)
    try:
        yield
    finally:
        _ACTIVE_CASE_CONTEXT.reset(token)


# Canonical alias matching the AuthorityContext name.
use_authority_context = use_active_case_context
