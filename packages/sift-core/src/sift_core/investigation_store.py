"""Typed investigation authority port + Postgres-backed store (BATCH-K2).

In DB-active mode (see :func:`sift_core.active_case_context.db_authority_active`),
findings, timeline events, IOCs, and TODOs are Postgres authority. The case-local
``findings.json`` / ``timeline.json`` / ``iocs.json`` / ``todos.json`` /
``approvals.jsonl`` files become bridge/export artifacts only — tampering with them
must not be able to change portal state or report eligibility.

This module defines the :class:`InvestigationAuthorityStore` port that core
mutating tools and the Gateway/portal adapters use, and a concrete
:class:`PostgresInvestigationStore` that writes ``app.investigation_*`` rows.

Authority invariants enforced here:

* Agents (and artifact sync) may only create or update DRAFT/PROPOSED rows. A row
  a human has APPROVED or REJECTED is "human locked" and an agent upsert against it
  is refused (returns the existing row unchanged) rather than downgrading it.
* Approve/reject/edit transitions are operator actions: they carry the actor, a
  re-auth audit event id, a recomputed content hash, and the observed row
  ``version``. A stale version (someone else wrote in between) fails closed.
* Every authoritative mutation runs in a single DB transaction.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Status values that represent a final human decision; agents must not overwrite.
HUMAN_LOCKED_STATUSES = frozenset({"APPROVED", "REJECTED"})

# Status values an agent / artifact sync is allowed to write.
AGENT_WRITABLE_STATUSES = frozenset({"DRAFT", "PROPOSED"})


class InvestigationStoreError(Exception):
    """Raised when an authoritative investigation mutation cannot complete."""


class StaleVersionError(InvestigationStoreError):
    """Raised when an approve/edit observed a stale row version (race lost)."""

    def __init__(self, item_id: str, observed: int | None, actual: int | None) -> None:
        super().__init__(
            f"stale version for {item_id}: observed={observed} actual={actual}"
        )
        self.item_id = item_id
        self.observed = observed
        self.actual = actual


@dataclass(frozen=True)
class ReviewAction:
    """A single approve/reject/edit decision against one investigation row."""

    item_id: str
    action: str  # "approve" | "reject" | "edit"
    modifications: dict[str, Any] | None = None
    note: str | None = None
    rejection_reason: str | None = None
    # Optimistic-lock guard: the content hash / version the operator reviewed.
    content_hash_at_review: str | None = None
    version_at_review: int | None = None


@dataclass(frozen=True)
class ReviewResult:
    approved: int = 0
    rejected: int = 0
    edited: int = 0
    skipped: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "rejected": self.rejected,
            "edited": self.edited,
            "skipped": [{"id": i, "reason": r} for (i, r) in self.skipped],
        }


class InvestigationAuthorityStore(ABC):
    """Port for the DB-active investigation authority used by core + portal."""

    # --- reads ---
    @abstractmethod
    def list_findings(self, case_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_timeline(self, case_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_iocs(self, case_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_todos(self, case_id: str) -> list[dict[str, Any]]: ...

    # --- agent / draft writes ---
    @abstractmethod
    def upsert_finding(
        self, case_id: str, item_id: str, payload: dict[str, Any], *, actor: Any = None
    ) -> dict[str, Any]: ...

    @abstractmethod
    def upsert_timeline_event(
        self, case_id: str, item_id: str, payload: dict[str, Any], *, actor: Any = None
    ) -> dict[str, Any]: ...

    @abstractmethod
    def upsert_ioc(
        self, case_id: str, item_id: str, payload: dict[str, Any], *, actor: Any = None
    ) -> dict[str, Any]: ...

    @abstractmethod
    def upsert_todo(
        self, case_id: str, todo_id: str, payload: dict[str, Any], *, actor: Any = None
    ) -> dict[str, Any]: ...

    # --- operator transitions ---
    @abstractmethod
    def apply_review(
        self,
        case_id: str,
        actions: list[ReviewAction],
        *,
        examiner: str,
        reauth_audit_event_id: str | None,
        actor: Any = None,
    ) -> ReviewResult: ...

    # --- report inputs ---
    @abstractmethod
    def report_inputs(self, case_id: str) -> dict[str, list[dict[str, Any]]]: ...


# --------------------------------------------------------------------------- #
# Content hash — single shared implementation used by ALL call sites.
#
# HASH_EXCLUDE_KEYS is the authoritative exclude set (19 keys).  Every module
# that previously redeclared its own narrow copy (case_io, case_manager,
# reporting, routes) now imports this set directly (BATCH-NW1).
#
# EXISTING DEPLOYMENTS NOTE: if you have stored content_hash values that were
# produced by the old narrow exclude set (15 keys — missing provenance_detail,
# provenance_chain, provenance_grade, provenance_gaps), those hashes will
# differ from hashes produced by this implementation.  A fresh database has no
# pre-existing hashes so no migration is needed for new installs.  For existing
# deployments a re-hash pass is required:
#   1. For each approved finding/timeline event row in the DB, call
#      compute_content_hash(row_payload) and write the result back to the
#      content_hash column (and the payload JSON's "content_hash" key).
#   2. For file-backed case dirs, recompute each finding/timeline content_hash
#      and re-write findings.json / timeline.json.
# No migration script is provided here; it belongs in a separate BATCH.
# --------------------------------------------------------------------------- #

HASH_EXCLUDE_KEYS: frozenset[str] = frozenset({
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "examiner_notes",
    "examiner_modifications",
    "content_hash",
    "verification",
    "modified_at",
    "provenance",
    "provenance_detail",
    "provenance_chain",
    "provenance_grade",
    "provenance_warnings",
    "provenance_gaps",
    "timeline_event_id",
    "source_evidence",
})

# Private alias kept for internal use within this module.
_HASH_EXCLUDE_KEYS = HASH_EXCLUDE_KEYS


def compute_content_hash(item: dict[str, Any]) -> str:
    """Canonical SHA-256 content hash for an investigation item.

    Excludes all volatile/provenance fields (see HASH_EXCLUDE_KEYS) and any
    internal ``_``-prefixed projection keys added by the DB store (e.g.
    ``_version``).  This is the single authoritative implementation used by
    every call site — case_io, case_manager, reporting, and the portal routes
    all delegate here (BATCH-NW1).
    """
    import hashlib

    hashable = {
        k: v
        for k, v in item.items()
        if k not in HASH_EXCLUDE_KEYS and not k.startswith("_")
    }
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def is_human_locked(status: Any) -> bool:
    return str(status or "").strip().upper() in HUMAN_LOCKED_STATUSES


# --------------------------------------------------------------------------- #
# Postgres-backed store
# --------------------------------------------------------------------------- #

_EDITABLE_FIELDS = {
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "description",
    "host",
    "affected_account",
    "event_type",
    "mitre_ids",
    "related_findings",
    "timestamp",
    "source",
    "value",
}


def _jsonb(value: Any):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover - deployment env
        return json.dumps(value)
    return Jsonb(value)


def _as_dict(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    return {}


class PostgresInvestigationStore(InvestigationAuthorityStore):
    """Authoritative investigation store over ``app.investigation_*``.

    Mutations use parameterized SQL in a single transaction per call (matching the
    existing portal_services adapter pattern). The store never persists or returns
    absolute filesystem paths; payloads are agent/portal-supplied JSON.
    """

    # (table, id_column) per logical kind.
    _KIND_TABLE = {
        "finding": ("app.investigation_findings", "item_id"),
        "timeline": ("app.investigation_timeline_events", "item_id"),
        "ioc": ("app.investigation_iocs", "item_id"),
    }

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - deployment env
            raise InvestigationStoreError("psycopg is required for the DB store") from exc
        return psycopg.connect(self._dsn)

    # --- reads ---
    def _payload_rows(self, table: str, case_id: str, order: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"select payload, status, version from {table} "
                    f"where case_id = %s order by {order}",
                    (case_id,),
                )
                rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for payload, status, version in rows:
            row = _as_dict(payload)
            if not row:
                continue
            # The DB status/version are authority; project them onto the payload so
            # readers (portal/report) never trust a stale status baked into JSON.
            row["status"] = status
            row["_version"] = version
            out.append(row)
        return out

    def list_findings(self, case_id: str) -> list[dict[str, Any]]:
        return self._payload_rows(
            "app.investigation_findings", case_id, "updated_at desc, item_id"
        )

    def list_timeline(self, case_id: str) -> list[dict[str, Any]]:
        return self._payload_rows(
            "app.investigation_timeline_events", case_id, "updated_at desc, item_id"
        )

    def list_iocs(self, case_id: str) -> list[dict[str, Any]]:
        return self._payload_rows(
            "app.investigation_iocs", case_id, "updated_at desc, item_id"
        )

    def list_todos(self, case_id: str) -> list[dict[str, Any]]:
        return self._payload_rows(
            "app.investigation_todos", case_id, "updated_at desc, todo_id"
        )

    # --- agent / draft writes ---
    def _agent_upsert(
        self, kind: str, case_id: str, item_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        table, id_col = self._KIND_TABLE[kind]
        # Never persist internal projection markers (e.g. _version) into the JSONB.
        payload = {k: v for k, v in payload.items() if not k.startswith("_")}
        status = str(payload.get("status") or "DRAFT")
        # An agent must never assert a human-final status.
        if status.upper() in HUMAN_LOCKED_STATUSES:
            status = "DRAFT"
        payload = {**payload, "status": status}
        content_hash = payload.get("content_hash") or compute_content_hash(payload)
        payload["content_hash"] = content_hash
        created_by = payload.get("created_by") or payload.get("examiner")
        value = payload.get("value") if kind == "ioc" else None
        ioc_type = (payload.get("type") or payload.get("ioc_type")) if kind == "ioc" else None
        with self._connect() as conn:
            with conn.cursor() as cur:
                # Refuse to overwrite a human-locked row: leave it untouched and
                # return the persisted row so the agent learns it was not applied.
                cur.execute(
                    f"select status, version from {table} "
                    f"where case_id = %s and {id_col} = %s for update",
                    (case_id, item_id),
                )
                existing = cur.fetchone()
                if existing and is_human_locked(existing[0]):
                    conn.rollback()
                    return {
                        "item_id": item_id,
                        "status": existing[0],
                        "version": existing[1],
                        "applied": False,
                        "reason": "human_locked",
                    }
                if kind == "ioc":
                    cur.execute(
                        """
                        insert into app.investigation_iocs
                          (case_id, item_id, status, value, ioc_type, payload,
                           created_by, source, version, updated_at)
                        values (%s, %s, %s, %s, %s, %s, %s, 'agent', 1, now())
                        on conflict (case_id, item_id) do update
                          set status = excluded.status,
                              value = excluded.value,
                              ioc_type = excluded.ioc_type,
                              payload = excluded.payload,
                              created_by = coalesce(app.investigation_iocs.created_by, excluded.created_by),
                              version = app.investigation_iocs.version + 1,
                              updated_at = now()
                        returning status, version
                        """,
                        (
                            case_id, item_id, status, value, ioc_type,
                            _jsonb(payload), created_by,
                        ),
                    )
                else:
                    cur.execute(
                        f"""
                        insert into {table}
                          (case_id, {id_col}, status, content_hash, payload,
                           created_by, source, version, updated_at)
                        values (%s, %s, %s, %s, %s, %s, 'agent', 1, now())
                        on conflict (case_id, {id_col}) do update
                          set status = excluded.status,
                              content_hash = excluded.content_hash,
                              payload = excluded.payload,
                              created_by = coalesce({table}.created_by, excluded.created_by),
                              version = {table}.version + 1,
                              updated_at = now()
                        returning status, version
                        """,
                        (
                            case_id, item_id, status, content_hash,
                            _jsonb(payload), created_by,
                        ),
                    )
                row = cur.fetchone()
            conn.commit()
        return {
            "item_id": item_id,
            "status": row[0] if row else status,
            "version": row[1] if row else 1,
            "applied": True,
        }

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        return self._agent_upsert("finding", case_id, item_id, payload)

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        return self._agent_upsert("timeline", case_id, item_id, payload)

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        return self._agent_upsert("ioc", case_id, item_id, payload)

    def upsert_todo(self, case_id, todo_id, payload, *, actor=None):
        status = str(payload.get("status") or "open")
        priority = str(payload.get("priority") or "medium")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into app.investigation_todos
                      (case_id, todo_id, status, priority, assignee, payload,
                       created_by, completed_at, source, version, updated_at)
                    values (%s, %s, %s, %s, %s, %s, %s, %s, 'agent', 1, now())
                    on conflict (case_id, todo_id) do update
                      set status = excluded.status,
                          priority = excluded.priority,
                          assignee = excluded.assignee,
                          payload = excluded.payload,
                          completed_at = excluded.completed_at,
                          version = app.investigation_todos.version + 1,
                          updated_at = now()
                    returning status, version
                    """,
                    (
                        case_id, todo_id, status, priority,
                        payload.get("assignee"), _jsonb(payload),
                        payload.get("created_by") or payload.get("examiner"),
                        payload.get("completed_at") or None,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return {"todo_id": todo_id, "status": row[0] if row else status,
                "version": row[1] if row else 1, "applied": True}

    # --- operator transitions ---
    def _find_kind(self, cur, case_id: str, item_id: str):
        for kind, (table, id_col) in self._KIND_TABLE.items():
            cur.execute(
                f"select payload, status, version from {table} "
                f"where case_id = %s and {id_col} = %s for update",
                (case_id, item_id),
            )
            row = cur.fetchone()
            if row:
                return kind, table, id_col, row
        return None, None, None, None

    def apply_review(
        self, case_id, actions, *, examiner, reauth_audit_event_id, actor=None
    ) -> ReviewResult:
        approved = rejected = edited = 0
        skipped: list[tuple[str, str]] = []
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            try:
                with conn.cursor() as cur:
                    for act in actions:
                        kind, table, id_col, row = self._find_kind(cur, case_id, act.item_id)
                        if row is None:
                            skipped.append((act.item_id, "not found"))
                            continue
                        payload, cur_status, cur_version = _as_dict(row[0]), row[1], row[2]

                        # Optimistic lock: reject stale approve/edit. A None guard
                        # means the client did not assert a version (accept).
                        if (
                            act.version_at_review is not None
                            and act.version_at_review != cur_version
                        ):
                            skipped.append((act.item_id, "stale version"))
                            continue
                        if (
                            act.content_hash_at_review
                            and payload.get("content_hash")
                            and act.content_hash_at_review != payload.get("content_hash")
                        ):
                            skipped.append((act.item_id, "stale content hash"))
                            continue

                        action = (act.action or "").lower()
                        mods = act.modifications or {}
                        # Verify modification originals still match (no silent clobber).
                        conflict = False
                        for field, mod in mods.items():
                            if isinstance(mod, dict) and "original" in mod:
                                if payload.get(field) != mod.get("original"):
                                    skipped.append((act.item_id, f"field '{field}' changed since review"))
                                    conflict = True
                                    break
                        if conflict:
                            continue
                        for field, mod in mods.items():
                            if field not in _EDITABLE_FIELDS:
                                continue
                            new_val = mod.get("modified") if isinstance(mod, dict) else mod
                            payload[field] = new_val
                            payload.setdefault("examiner_modifications", {})[field] = {
                                "original": mod.get("original") if isinstance(mod, dict) else None,
                                "modified": new_val,
                                "modified_by": examiner,
                                "modified_at": now,
                            }
                        if act.note:
                            payload.setdefault("examiner_notes", []).append(
                                {"note": act.note, "by": examiner, "at": now}
                            )

                        if action == "approve":
                            new_hash = compute_content_hash(payload)
                            payload["content_hash"] = new_hash
                            payload["status"] = "APPROVED"
                            payload["approved_at"] = now
                            payload["approved_by"] = examiner
                            payload["modified_at"] = now
                            self._write_review(
                                cur, table, id_col, case_id, act.item_id, payload,
                                "APPROVED", new_hash, examiner, reauth_audit_event_id,
                                cur_version,
                            )
                            approved += 1
                        elif action == "reject":
                            payload["status"] = "REJECTED"
                            payload["rejected_at"] = now
                            payload["rejected_by"] = examiner
                            if act.rejection_reason:
                                payload["rejection_reason"] = act.rejection_reason
                            payload["modified_at"] = now
                            self._write_review(
                                cur, table, id_col, case_id, act.item_id, payload,
                                "REJECTED", payload.get("content_hash"), examiner,
                                reauth_audit_event_id, cur_version,
                            )
                            rejected += 1
                        elif action == "edit":
                            if not mods:
                                continue
                            new_hash = compute_content_hash(payload)
                            payload["content_hash"] = new_hash
                            payload["modified_at"] = now
                            self._write_review(
                                cur, table, id_col, case_id, act.item_id, payload,
                                cur_status, new_hash, examiner, reauth_audit_event_id,
                                cur_version,
                            )
                            edited += 1
                        else:
                            skipped.append((act.item_id, f"unknown action {action}"))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return ReviewResult(approved, rejected, edited, tuple(skipped))

    def _write_review(
        self, cur, table, id_col, case_id, item_id, payload, status, content_hash,
        examiner, reauth_audit_event_id, observed_version,
    ) -> None:
        # version guard is also enforced atomically in the UPDATE WHERE clause so a
        # concurrent transaction that bumped version (committed after our SELECT in
        # READ COMMITTED) cannot be clobbered.
        approved_by = examiner if status == "APPROVED" else None
        rejected_by = examiner if status == "REJECTED" else None
        if table == "app.investigation_iocs":
            cur.execute(
                f"""
                update {table}
                  set status = %s, value = %s, ioc_type = %s, payload = %s,
                      content_hash = %s, approved_by = %s, rejected_by = %s,
                      reauth_audit_event_id = %s, version = version + 1, updated_at = now()
                where case_id = %s and {id_col} = %s and version = %s
                """,
                (
                    status, payload.get("value"),
                    payload.get("type") or payload.get("ioc_type"),
                    _jsonb(payload), content_hash, approved_by, rejected_by,
                    reauth_audit_event_id, case_id, item_id, observed_version,
                ),
            )
        else:
            cur.execute(
                f"""
                update {table}
                  set status = %s, payload = %s, content_hash = %s,
                      approved_by = %s, rejected_by = %s,
                      reauth_audit_event_id = %s, version = version + 1, updated_at = now()
                where case_id = %s and {id_col} = %s and version = %s
                """,
                (
                    status, _jsonb(payload), content_hash, approved_by, rejected_by,
                    reauth_audit_event_id, case_id, item_id, observed_version,
                ),
            )
        if cur.rowcount != 1:
            raise StaleVersionError(item_id, observed_version, None)

    # --- report inputs ---
    def report_inputs(self, case_id: str) -> dict[str, list[dict[str, Any]]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select payload, content_hash, approved_by, version "
                    "from app.investigation_findings "
                    "where case_id = %s and upper(status) = 'APPROVED' order by item_id",
                    (case_id,),
                )
                findings = self._approved_payloads(cur.fetchall())
                cur.execute(
                    "select payload, content_hash, approved_by, version "
                    "from app.investigation_timeline_events "
                    "where case_id = %s and upper(status) = 'APPROVED' order by item_id",
                    (case_id,),
                )
                timeline = self._approved_payloads(cur.fetchall())
                cur.execute(
                    "select payload, content_hash, approved_by, version "
                    "from app.investigation_iocs "
                    "where case_id = %s and upper(status) = 'APPROVED' order by item_id",
                    (case_id,),
                )
                iocs = self._approved_payloads(cur.fetchall())
        return {"findings": findings, "timeline": timeline, "iocs": iocs}

    @staticmethod
    def _approved_payloads(rows) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for payload, content_hash, approved_by, version in rows:
            row = _as_dict(payload)
            if not row:
                continue
            # DB columns are authority over whatever the payload JSON carried.
            row["status"] = "APPROVED"
            if content_hash:
                row["content_hash"] = content_hash
            if approved_by:
                row["approved_by"] = approved_by
            row["_version"] = version
            out.append(row)
        return out


def control_plane_dsn() -> str | None:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    return dsn or None


def audit_writer_dsn() -> str | None:
    """L-1b: the least-privilege audit-write DSN, when configured.

    Returns the value of ``SIFT_AUDIT_WRITER_DSN`` (the scoped ``sift_audit_writer``
    role's connection string) or ``None`` when it is unset/empty. Callers on the
    forward-write path prefer this over :func:`control_plane_dsn` so the audit
    forward-writes run under the least-privilege role; they fall back to the full
    control-plane DSN when this is unset (non-breaking rollout — least-privilege
    activates only once the operator sets the secret).
    """
    dsn = os.environ.get("SIFT_AUDIT_WRITER_DSN", "").strip()
    return dsn or None


def audit_forward_write_dsn() -> str | None:
    """The DSN the audit forward-write path should connect with.

    Prefers the scoped :func:`audit_writer_dsn` (L-1b least-privilege role);
    falls back to the full :func:`control_plane_dsn` when the scoped DSN is unset
    so provenance keeps working before the operator provisions the role/secret.
    A debug note is logged on fallback so it is observable that least-privilege
    is not yet active. Returns ``None`` only when NEITHER is configured.
    """
    scoped = audit_writer_dsn()
    if scoped:
        return scoped
    full = control_plane_dsn()
    if full:
        logger.debug(
            "audit forward-write: SIFT_AUDIT_WRITER_DSN unset — falling back to "
            "the full control-plane DSN (L-1b least-privilege role not active)"
        )
    return full


def resolve_investigation_store() -> InvestigationAuthorityStore | None:
    """Return a DB authority store when the current call is DB-active.

    Returns ``None`` in legacy/file mode so callers keep their file-backed path.
    Fails closed (raises) only when DB authority is required but unusable; the
    decision to require it belongs to the caller.
    """
    from sift_core.active_case_context import db_authority_active

    if not db_authority_active():
        return None
    dsn = control_plane_dsn()
    if not dsn:
        # BU3 (XYE-21): DB authority is active but no control-plane DSN is
        # configured. This is a misconfiguration, not a file-mode deployment;
        # fail closed rather than silently downgrading to the tamperable file
        # mirror. (The gateway also refuses to start in this state.)
        raise InvestigationStoreError(
            "DB authority is active but no control-plane DSN is configured"
        )
    return PostgresInvestigationStore(dsn)


# BU1: inverse of the gateway's CASE.yaml->DB status map. DB-authoritative case
# rows store the lifecycle status as ``active``/``draft``/``paused``/...; the
# file world (and every CASE.yaml reader) speaks ``open``/``closed``/... so the
# DB-native readers project the DB status back to that vocabulary.
_DB_STATUS_TO_CASE_YAML = {
    "active": "open",
    "draft": "draft",
    "paused": "paused",
    "closed": "closed",
    "archived": "archived",
}

# app.cases columns the metadata reader projects, in select order.
_CASE_ROW_COLUMNS = (
    "id::text",
    "case_key",
    "title",
    "description",
    "status",
    "legacy_case_dir",
    "metadata",
)


def _case_meta_from_row(row: Any) -> dict[str, Any]:
    """Project an ``app.cases`` row into a CASE.yaml-shaped metadata dict.

    The JSONB ``metadata`` column already carries the examiner identity and the
    case-brief intake fields (see the gateway ``ActiveCaseService`` writer); the
    dedicated columns (``case_key``/``title``/``description``/``status``) are the
    authority for those four and override anything stale in the JSONB blob.
    """
    case_id, case_key, title, description, status, _legacy_dir, metadata = row
    meta: dict[str, Any] = dict(metadata or {})
    meta["case_id"] = str(case_key)
    meta["name"] = str(title) if title is not None else ""
    if description is not None:
        meta["description"] = str(description)
    meta["status"] = _DB_STATUS_TO_CASE_YAML.get(str(status), str(status))
    return meta


# --------------------------------------------------------------------------- #
# E1 (XYE-34): per-process connection reuse for the case-metadata authority read.
#
# Opening a fresh psycopg connection on every case-metadata read (the BU1 shape)
# is a TCP+TLS+auth round-trip per fail-closed authority check. E1 reuses ONE
# connection per (pid, dsn) and re-queries the live row each call. We cache the
# *socket*, never the *result*: the closed-case refusal / examiner-identity /
# report-inclusion decisions must always read the current DB row.
#
# Design constraints (see docs/drafts/e1-connection-reuse-spec.md §4):
#   * autocommit=True            — fresh MVCC snapshot per statement; no
#                                  idle-in-transaction; never a frozen snapshot
#                                  that could serve a stale "open" for a closed
#                                  case.
#   * prepare_threshold=None     — disable client-side prepared statements so the
#                                  design stays safe if the DSN is ever repointed
#                                  at a transaction pooler (PgBouncer et al.).
#   * connect_timeout=5          — a DB outage fails closed FAST instead of
#                                  hanging the hot path.
#   * statement_timeout=5000ms / idle_in_transaction_session_timeout=10000ms
#                                  — server-side backstops on the same posture.
#   * default_transaction_read_only=on
#                                  — this path never writes; deny it write rights
#                                    at the session level. (A dedicated read-only
#                                    DB ROLE is the stronger posture and is a
#                                    deploy follow-up; the SET is the in-code
#                                    floor until that role is provisioned.)
#
# READ COMMITTED + autocommit is the ONLY isolation posture allowed here. Raising
# the isolation level would hold a transaction open and freeze the snapshot,
# which could serve a stale authority read — forbidden (see the guard test).
# --------------------------------------------------------------------------- #

# Cache of live connections keyed by (os.getpid(), dsn). pid-keying ensures a
# forked child never *uses* a connection it inherited from the parent.
_CONN_CACHE: dict[tuple[int, str], Any] = {}

# Guards the cache dict ONLY (create / evict / fork-clear). It is NEVER held
# across cur.execute(): psycopg3 Connection is internally thread-safe, and a lock
# around execute would serialize every case-metadata read in the process behind
# one connection. The off-event-loop threadpool (gateway _run_core) means
# concurrent reads can share the cached connection — that is safe by design.
_CACHE_LOCK = threading.Lock()

# psycopg application_name for this path — visible in pg_stat_activity so a leak
# or unbounded backend growth is diagnosable. Carries no secret.
_CASE_STORE_APPLICATION_NAME = "sift-case-store"


def _psycopg():
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise InvestigationStoreError("psycopg is required for the DB store") from exc
    return psycopg


def _connection_for(dsn: str):
    """Create one hardened, read-only, autocommit connection for ``dsn``.

    This is the single connection-creation point and the default provider for
    :class:`PostgresCaseStore`. Tests inject a fake provider to prove reuse
    without a live database.
    """
    psycopg = _psycopg()
    conn = psycopg.connect(
        dsn,
        autocommit=True,
        prepare_threshold=None,
        connect_timeout=5,
        application_name=_CASE_STORE_APPLICATION_NAME,
        options="-c statement_timeout=5000 -c idle_in_transaction_session_timeout=10000",
    )
    try:
        # Read-only posture at the session level (autocommit ⇒ this SET sticks
        # for the connection). The authority read needs no write rights.
        conn.execute("SET default_transaction_read_only = on")
    except BaseException:
        try:
            conn.close()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
        raise
    return conn


def _borrow_connection(dsn: str, provider):
    """Return the cached connection for ``(pid, dsn)``, creating it if absent.

    The connection is NOT closed by the caller — it is reused on the next read.
    Creation happens under the lock so a burst of first-time readers opens at
    most one connection; execute() runs after the lock is released.
    """
    key = (os.getpid(), dsn)
    with _CACHE_LOCK:
        conn = _CONN_CACHE.get(key)
        if conn is None:
            conn = provider(dsn)
            _CONN_CACHE[key] = conn
        return conn


def _evict(pid: int, dsn: str) -> None:
    """Drop the cached connection for ``(pid, dsn)`` and best-effort close it.

    Called when a read hit a connection-level error (the socket is already dead)
    or any query error (do not leave a possibly-poisoned connection cached).
    """
    key = (pid, dsn)
    with _CACHE_LOCK:
        conn = _CONN_CACHE.pop(key, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:  # pragma: no cover - the socket is typically already gone
            pass


def _clear_cache() -> None:
    """Fork hook: drop inherited cache entries WITHOUT closing them.

    Registered via ``os.register_at_fork(after_in_child=...)``. After fork the
    child's connection objects wrap file descriptors duplicated from the parent;
    letting the child close one would send a libpq Terminate on the shared server
    connection and corrupt the parent's session. So we drop the references
    (pid-keying already prevents the child from *using* them) but never call
    ``close()``. We also reset the lock: a thread may have held it at fork time,
    leaving it locked with no owner in the single-threaded child.
    """
    global _CACHE_LOCK
    _CONN_CACHE.clear()
    _CACHE_LOCK = threading.Lock()


# Register the fork hook once at import. Best-effort: not all platforms expose
# os.register_at_fork (the SIFT VM is Linux, where it is present).
try:
    os.register_at_fork(after_in_child=_clear_cache)
except (AttributeError, ValueError):  # pragma: no cover - non-fork platforms
    pass


class PostgresCaseStore:
    """Read-only DB authority for ``app.cases`` metadata (BU1; E1 conn reuse).

    Mirrors the gateway ``ActiveCaseService`` query so in-process core readers
    (orientation, status, reporting) can resolve case metadata from Postgres
    instead of the tamperable CASE.yaml mirror, without depending on the gateway
    package. Writes remain portal/gateway-owned (BU2).

    E1 (XYE-34): reuses one cached connection per process via the module-level
    provider/cache above. The connection is reused; the row is always re-read.
    A ``connection_provider`` may be injected for tests; it defaults to the
    module pooled provider :func:`_connection_for`.
    """

    def __init__(self, dsn: str, *, connection_provider=None) -> None:
        self._dsn = dsn
        # Injectable creation point; default = the module per-process provider.
        self._provider = (
            connection_provider if connection_provider is not None else _connection_for
        )

    def _borrow(self):
        return _borrow_connection(self._dsn, self._provider)

    def _query(self, conn, case_id: str) -> dict[str, Any] | None:
        with conn.cursor() as cur:
            cur.execute(
                f"select {', '.join(_CASE_ROW_COLUMNS)} from app.cases "
                "where id::text = %s or case_key = %s",
                (case_id, case_id),
            )
            row = cur.fetchone()
        if not row:
            return None
        return _case_meta_from_row(row)

    def get_case_metadata(self, case_id: str) -> dict[str, Any] | None:
        """Return CASE.yaml-shaped metadata for ``case_id`` (UUID or case_key).

        Reuses the cached per-process connection. Error posture (spec §4.3):

        * Connection-level error (``OperationalError`` / ``InterfaceError`` — a
          dead socket after a server idle-timeout): evict the dead connection,
          reconnect once, retry the SELECT once (the read is idempotent). If the
          retry also fails, fail closed with :class:`InvestigationStoreError`.
        * Any other error (programming / data error): evict and fail closed
          immediately — no retry loop.
        * Never fall back to a file, never return stale/empty on error.
        """
        psycopg = _psycopg()
        conn_errors = (psycopg.OperationalError, psycopg.InterfaceError)
        try:
            conn = self._borrow()
            return self._query(conn, case_id)
        except conn_errors:
            # Connection-level: evict and fall through to the single retry.
            _evict(os.getpid(), self._dsn)
        except InvestigationStoreError:
            _evict(os.getpid(), self._dsn)
            raise
        except Exception as exc:
            # Query/programming/data error: the statement is the problem, not the
            # socket. Evict (don't leave a poisoned connection cached) and fail
            # closed at once — NO retry.
            _evict(os.getpid(), self._dsn)
            raise InvestigationStoreError(
                f"case-metadata read failed for {case_id}"
            ) from exc

        # Reconnect-and-retry exactly once (connection-level error path only).
        try:
            conn = self._borrow()
            return self._query(conn, case_id)
        except Exception as exc:
            _evict(os.getpid(), self._dsn)
            raise InvestigationStoreError(
                f"case-metadata read failed for {case_id} after one reconnect"
            ) from exc


def resolve_case_metadata() -> dict[str, Any] | None:
    """Return DB-authoritative, CASE.yaml-shaped case metadata, or ``None``.

    BU1: in DB-active mode this is the *only* source of case metadata for the
    orientation/status/report readers; they must not read CASE.yaml. Returns
    ``None`` in legacy/file mode so those readers keep their file path. When DB
    authority is active, any DB failure (or a missing case row, or a missing
    active-case context) raises so callers fail closed instead of serving
    stale/tampered file values.

    BU3 (XYE-21): a DB-active call with no control-plane DSN is a
    misconfiguration and fails closed here too — there is no implicit file-mode
    fallback. (The gateway also refuses to start without a DSN.)
    """
    from sift_core.active_case_context import current_active_case, db_authority_active

    if not db_authority_active():
        return None
    dsn = control_plane_dsn()
    if not dsn:
        raise InvestigationStoreError(
            "DB authority is active but no control-plane DSN is configured"
        )
    ctx = current_active_case()
    case_id = ctx.case_id if ctx is not None else None
    if not case_id:
        raise InvestigationStoreError(
            "DB authority is active but no case is bound to the request context"
        )
    meta = PostgresCaseStore(dsn).get_case_metadata(case_id)
    if meta is None:
        raise InvestigationStoreError(f"case {case_id} not found in app.cases")
    return meta
