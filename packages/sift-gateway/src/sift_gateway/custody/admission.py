"""Read-only evidence admission: reconciliation, gate projection, resolution.

This module is the **deep module** behind the Custody Gate (SPEC §Custody Gate
and Admission). It absorbs the concerns the as-built ``evidence_gate.py`` and the
``custody_drift.py`` classifier used to split across the Gateway and
``portal_services.py``:

* **read-only reconciliation** — scan the canonical local evidence directory
  without mutating a byte (via the single core scanner
  ``classify_inventory_entries``) and persist the snapshot through the
  ``app.custody_reconcile`` RPC (which upserts ``evidence_inventory`` under
  present-on-disk truth and appends one ``admission_observations`` row);
* **drift classification to the four gate states** — delegated to the computed
  ``app.custody_gate_state`` SQL function, so the four public states project from
  authoritative facts, never from a latched marker;
* **sealed-version resolution + descriptor pinning** — resolve an agent-supplied
  evidence reference to an active sealed Evidence Version and pin the exact file
  identity into an :class:`AdmittedEvidenceBinding` for the final descriptor open.

The single reconciliation implementation serves all three callers named in the
SPEC — reconcile-before-dispatch, operator Refresh, and the Gateway-internal
periodic pass (D3) — distinguished only by the ``trigger`` argument. The periodic
pass is a *caller*, never a second implementation.

Scope note (P4.23 CP1): this module is LOCAL_IMMUTABLE only. Externally mounted
evidence is out of scope for the target model (SPEC §Local storage only); the
as-built external-storage machinery in ``evidence_storage.py`` /
``portal_services.py`` is dormant and removed by its owning packets. The Gateway
never mutates evidence bytes or custody state here — the fixed local helper and
re-authenticated Portal Seal are the only mutation surfaces.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Any, Literal, TypedDict

from sift_core.custody_types import ChainStatus
from sift_core.execute.evidence_binding import (
    AdmittedEvidenceBinding,
    classify_inventory_entries,
)

logger = logging.getLogger(__name__)

# The four public custody gate states (SPEC §Custody Gate and Admission). The
# computed ``app.custody_gate_state`` function is authority for which one holds.
GateState = Literal[
    "OPEN", "BLOCKED_PENDING", "BLOCKED_VIOLATION", "BLOCKED_UNAVAILABLE"
]

# Projection of the four gate states onto the legacy ChainStatus shape so
# ``evidence_gate.build_block_response`` and existing response consumers keep the
# same envelope during the rewire. OPEN is the only unblocked state.
_GATE_TO_CHAIN_STATUS: dict[str, ChainStatus] = {
    "OPEN": ChainStatus.OK,
    "BLOCKED_PENDING": ChainStatus.UNSEALED,
    "BLOCKED_VIOLATION": ChainStatus.LEDGER_ERROR,
    "BLOCKED_UNAVAILABLE": ChainStatus.MISSING,
}

_GATE_ISSUE: dict[str, str] = {
    "BLOCKED_PENDING": "Unadmitted local evidence requires Add and Seal or Ignore",
    "BLOCKED_VIOLATION": "Sealed evidence changed or an unsafe entry was detected",
    "BLOCKED_UNAVAILABLE": "The canonical evidence directory is unavailable",
}


class GateResult(TypedDict):
    """The gate decision returned to the dispatch/orientation callers.

    ``blocked`` and ``status``/``issues``/``manifest_version`` preserve the
    envelope the middleware and orientation paths already consume; ``gate_state``
    carries the authoritative four-state projection.
    """

    blocked: bool
    gate_state: GateState
    status: ChainStatus
    issues: list[str]
    manifest_version: int


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------
def reconcile(
    case_id: str | None,
    case_dir: str | os.PathLike[str] | None,
    dsn: str | None,
    *,
    trigger: Literal["dispatch", "refresh", "periodic"] = "dispatch",
    correlation_id: str | None = None,
) -> GateResult:
    """Persist one read-only reconciliation and return the resulting gate.

    Scans the case's evidence directory, persists the snapshot via
    ``app.custody_reconcile`` (present-on-disk truth; append-only observation),
    and returns the computed four-state gate. Fail-closed: a missing case/DSN, an
    unavailable directory, or any database error yields a blocked result. This is
    the sole reconciliation entry point for dispatch, Refresh, and the
    Gateway-internal periodic pass.
    """
    if not case_id or not dsn:
        return _blocked("BLOCKED_UNAVAILABLE", ["No active case — create a case first"])

    entries = classify_inventory_entries(str(case_dir)) if case_dir else None
    storage_available = entries is not None

    try:
        import psycopg
        from psycopg.types.json import Jsonb
    except ImportError as exc:  # pragma: no cover - deployment env
        logger.error("admission.reconcile: psycopg unavailable: %s", exc)
        return _blocked("BLOCKED_UNAVAILABLE", ["Evidence authority unavailable"])

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select app.custody_reconcile(%s, %s, %s, %s, %s, null, null)",
                    (
                        case_id,
                        Jsonb(entries or []),
                        storage_available,
                        trigger,
                        correlation_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
    except Exception as exc:
        logger.error("admission.reconcile: failed for %s: %s", case_id, exc)
        return _blocked("BLOCKED_UNAVAILABLE", ["Evidence reconciliation unavailable"])

    return _gate_result(str(row[0]) if row and row[0] else "BLOCKED_PENDING")


def gate_state(case_id: str | None, dsn: str | None) -> GateResult:
    """Read the computed custody gate for a case WITHOUT reconciling.

    Used by the orientation/read paths (``case_info``/``evidence_info``) that must
    reflect authoritative custody state but do not themselves drive a scan. The
    authoritative dispatch decision runs :func:`reconcile` immediately before this
    (reconcile-before-dispatch). Fail-closed on any error.
    """
    if not case_id or not dsn:
        return _blocked("BLOCKED_UNAVAILABLE", ["No active case — create a case first"])
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        logger.error("admission.gate_state: psycopg unavailable: %s", exc)
        return _blocked("BLOCKED_UNAVAILABLE", ["Evidence authority unavailable"])
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("select app.custody_gate_state(%s)", (case_id,))
                row = cur.fetchone()
    except Exception as exc:
        logger.error("admission.gate_state: query failed for %s: %s", case_id, exc)
        return _blocked("BLOCKED_UNAVAILABLE", ["Evidence authority unavailable"])
    return _gate_result(str(row[0]) if row and row[0] else "BLOCKED_PENDING")


def resolve_sealed_version(
    case_id: str | None,
    ref: str,
    case_dir: str | os.PathLike[str] | None,
    dsn: str | None,
) -> AdmittedEvidenceBinding | None:
    """Resolve one evidence reference to a pinned active sealed Evidence Version.

    ``ref`` is an opaque evidence id or a relative display path. Returns a fully
    pinned :class:`AdmittedEvidenceBinding` when the reference is an ACTIVE sealed
    object whose on-disk identity still matches its committed version, else
    ``None`` (fail-closed: the caller denies dispatch). The absolute path is
    private Gateway/worker state; public serializers omit it. LOCAL_IMMUTABLE
    only — descriptor pinning re-checks the exact file identity at open time.
    """
    if not case_id or not dsn or not ref:
        return None
    try:
        import psycopg
    except ImportError:  # pragma: no cover - deployment env
        return None
    display_ref = ref if ref.startswith("evidence/") else f"evidence/{ref}"
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select o.id::text, o.display_path, v.id::text, v.sha256, v.bytes,
                           v.st_dev, v.st_ino, m.manifest_version, m.manifest_hash
                    from app.evidence_objects o
                    join app.evidence_versions v on v.id = o.current_version_id
                    join app.manifest_membership mm on mm.evidence_object_id = o.id
                       and mm.evidence_version_id = v.id and mm.entry_status = 'ACTIVE'
                    join app.manifest_versions m on m.id = mm.manifest_version_id
                    where o.case_id = %s and o.status = 'sealed'
                      and (o.id::text = %s or o.display_path = %s)
                    order by m.manifest_version desc
                    limit 1
                    """,
                    (case_id, ref, display_ref),
                )
                row = cur.fetchone()
    except Exception as exc:
        logger.error("admission.resolve: query failed for %s/%s: %s", case_id, ref, exc)
        return None
    if not row:
        return None

    (evidence_id, display_path, version_id, sha256, size, v_dev, v_ino,
     manifest_version, manifest_hash) = row

    # Descriptor pinning: stat the sealed file now and require its identity to
    # match the committed version before admitting it.
    if not case_dir:
        return None
    path = Path(str(case_dir)) / str(display_path)
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return None
    if size is not None and int(st.st_size) != int(size):
        return None
    if v_dev is not None and int(st.st_dev) != int(v_dev):
        return None
    if v_ino is not None and int(st.st_ino) != int(v_ino):
        return None

    return AdmittedEvidenceBinding(
        ref=ref,
        evidence_id=str(evidence_id),
        version_id=str(version_id),
        display_path=str(display_path),
        path=str(path),
        sha256=str(sha256),
        bytes=int(size if size is not None else st.st_size),
        st_dev=int(st.st_dev),
        st_ino=int(st.st_ino),
        st_mtime_ns=int(st.st_mtime_ns),
        st_ctime_ns=int(st.st_ctime_ns),
        immutable_required=True,
        storage_profile="LOCAL_IMMUTABLE",
        read_only_required=False,
        storage_generation=int(manifest_version),
        storage_verified_generation=int(manifest_version),
        storage_manifest_version=int(manifest_version),
        storage_manifest_hash=str(manifest_hash),
        storage_verification_receipt_id="",
    )


def current_storage_authority(
    binding: AdmittedEvidenceBinding | None = None,
) -> dict[str, Any]:
    """LOCAL_IMMUTABLE execution authority for a resolved binding.

    The run_command evidence-binding path binds this snapshot before dispatch and
    the worker compares it at execution. For LOCAL_IMMUTABLE the authority is the
    sealed generation and manifest identity; there is no external mount identity.
    """
    if binding is None:
        return {"storage_profile": "LOCAL_IMMUTABLE"}
    return {
        "storage_profile": "LOCAL_IMMUTABLE",
        "storage_generation": binding["storage_generation"],
        "storage_manifest_version": binding["storage_manifest_version"],
        "storage_manifest_hash": binding["storage_manifest_hash"],
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _gate_result(state: str) -> GateResult:
    gs: GateState = state if state in _GATE_TO_CHAIN_STATUS else "BLOCKED_PENDING"  # type: ignore[assignment]
    issues = [] if gs == "OPEN" else [_GATE_ISSUE.get(gs, "Evidence gate blocked")]
    return GateResult(
        blocked=gs != "OPEN",
        gate_state=gs,
        status=_GATE_TO_CHAIN_STATUS[gs],
        issues=issues,
        manifest_version=0,
    )


def _blocked(state: GateState, issues: list[str]) -> GateResult:
    return GateResult(
        blocked=True,
        gate_state=state,
        status=_GATE_TO_CHAIN_STATUS[state],
        issues=issues,
        manifest_version=0,
    )
