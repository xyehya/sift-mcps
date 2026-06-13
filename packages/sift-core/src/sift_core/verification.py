"""Approval-commit ledger — DB authority (FORK-2).

The approval-commit ledger records, per approved finding/timeline/IOC item, a
tamper-evident commit event at the moment an operator approves it in the portal
review path.

History
-------
This ledger used to live in a FILE HMAC ledger at
``/var/lib/sift/verification/{case-id}.jsonl`` (``write_ledger_entry`` +
``compute_hmac``), keyed with a local PBKDF2 hash. CL3b (B-MVP-017, 718684e)
retired the file-HMAC RE-AUTH plane; FORK-2 retires the last remaining
file-ledger WRITER and moves the approval-commit ledger into Postgres so the DB
is the SOLE authority — matching how investigation ``content_hash``
(``app.investigation_*``) and the evidence custody chain
(``app.evidence_custody_events``) are already DB-authoritative.

The DB ledger (``app.approval_commit_events`` + ``app.approval_commit_heads``,
migration ``202606141200_approval_ledger_db.sql``) is an APPEND-ONLY, per-case
hash-linked chain (prev_hash/event_hash) with a mutation-blocking trigger. Tamper
-evidence comes from the SHA-256 chain + DB-level immutability — equivalent to
the file HMAC ledger WITHOUT a secret key (it mirrors the locked
``evidence_custody_events`` pattern).

Retired file-ledger code
------------------------
``compute_hmac`` and ``write_ledger_entry`` (the file-authority writer) and the
keyed-HMAC concept are gone — the DB hash chain replaces them. ``VERIFICATION_DIR``
and ``_validate_case_id`` are kept ONLY because ``sift_core.backup_ops`` may copy a
pre-existing legacy ``{case_id}.jsonl`` into a backup as a read-only artifact;
they are no longer a write path.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Legacy file-ledger location. RETIRED as a write authority: nothing in this
# module writes here anymore. Kept defined because sift_core.backup_ops imports it
# to copy a pre-existing legacy ledger artifact (read-only export) if one exists.
VERIFICATION_DIR = Path(os.environ.get("SIFT_VERIFICATION_DIR", "/var/lib/sift/verification"))


def _validate_case_id(case_id: str) -> None:
    if not case_id:
        raise ValueError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def _control_plane_dsn() -> str | None:
    """Resolve the control-plane DSN the same way the DB stores do.

    Reuses :data:`SIFT_CONTROL_PLANE_DSN` (the env var read by
    ``sift_core.investigation_store.control_plane_dsn``). Returns None when no DB
    control plane is configured (file-backed / unit-test deployments).
    """
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    return dsn or None


def _connect(dsn: str):
    """Open a psycopg connection (lazy import, mirrors PostgresInvestigationStore)."""
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise RuntimeError("psycopg is required for the DB approval-commit ledger") from exc
    return psycopg.connect(dsn)


def append_approval_commit_event_db(
    case_id: str,
    *,
    item_id: str,
    item_type: str,
    content_hash: str | None,
    action: str = "APPROVED",
    reauth_audit_event_id: str | None = None,
    approved_by: str | None = None,
    actor_user_id: str | None = None,
    actor_service_identity_id: str | None = None,
    details: dict[str, Any] | None = None,
    dsn: str | None = None,
    connect: Callable[[str], Any] | None = None,
) -> str | None:
    """Append one approval-commit event to the DB hash-chain ledger.

    Calls ``app.approval_append_commit_event(...)`` which atomically links
    prev_hash, computes ``event_hash = sha256(canonical payload)``, inserts the
    append-only row, and advances the per-case chain head. Tamper-evidence is the
    DB chain + the append-only trigger; no secret HMAC key is involved.

    Returns the new event id, or ``None`` when no DB control plane is configured
    (file-backed deployments have no approval-commit ledger authority — the file
    ledger that used to serve that role is retired and is NOT written here).

    ``dsn``/``connect`` are injection points for tests (the repo's fake-psycopg
    idiom); production resolves the DSN from :data:`SIFT_CONTROL_PLANE_DSN`.
    """
    resolved_dsn = dsn or _control_plane_dsn()
    if not resolved_dsn:
        return None

    from json import dumps as _json_dumps

    opener = connect or _connect
    payload_details = _json_dumps(details or {}, sort_keys=True, default=str)
    with opener(resolved_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select app.approval_append_commit_event("
                "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
                (
                    case_id,
                    item_id,
                    item_type,
                    action,
                    content_hash,
                    reauth_audit_event_id,
                    approved_by,
                    actor_user_id,
                    actor_service_identity_id,
                    payload_details,
                ),
            )
            row = cur.fetchone()
        commit = getattr(conn, "commit", None)
        if callable(commit):
            commit()
    return str(row[0]) if row and row[0] else None


def read_approval_commit_tip_db(
    case_id: str,
    *,
    dsn: str | None = None,
    connect: Callable[[str], Any] | None = None,
) -> dict[str, Any] | None:
    """Read the approval-commit ledger tip (head seq/hash + event count) for a case.

    Reconciliation/report authority read. Returns ``None`` when no DB control
    plane is configured. The DB ledger is the AUTHORITY for the approval-commit
    chain; this never consults a file.
    """
    resolved_dsn = dsn or _control_plane_dsn()
    if not resolved_dsn:
        return None

    opener = connect or _connect
    with opener(resolved_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select head_seq, head_hash, event_count "
                "from app.approval_commit_tip(%s)",
                (case_id,),
            )
            row = cur.fetchone()
    if not row:
        return {"head_seq": 0, "head_hash": "", "event_count": 0}
    return {
        "head_seq": int(row[0] or 0),
        "head_hash": str(row[1] or ""),
        "event_count": int(row[2] or 0),
    }
