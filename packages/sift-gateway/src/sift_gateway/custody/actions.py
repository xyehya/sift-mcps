"""DB-only custody actions: Ignore, Retire, Full Verify, Verify-and-Reprotect.

FROZEN INTERFACE (P4.23 CP1, 2026-07-20). CP2A implements the bodies against the
frozen custody RPCs (``app.custody_ignore`` / ``custody_retire`` /
``custody_reprotect``) and reconciliation.

These are the non-Seal custody mutations. Each is a SINGLE atomic transaction with
NO persistent failure state (SPEC §Drift, EC-2a): a failed attempt rolls back
completely, records nothing that blocks the case, and never prevents a subsequent
attempt. Only Seal has an incomplete-operation record. While a Seal is active,
DB-only actions on targets OUTSIDE its target set remain permitted; targets inside
its set are rejected with a shaped "seal in progress — resume it" error (EC-2b).

* **Ignore** excludes a pending inventory entry (it stays on disk, inaccessible to
  MCP; a later explicit Add and Seal may admit it as a new object).
* **Retire** excludes a sealed object from a new Manifest Version. It changes only
  PostgreSQL authority — never deletes, modifies, unprotects, or repairs bytes —
  and is permitted for any object with a committed sealed record regardless of
  current bytes.
* **Full Verify** is read-only and requires no fresh password: it recomputes the
  full SHA-256 and validates identity/posture/membership. It changes no bytes,
  metadata, manifests, or custody history; the gate opens only from verified
  facts. Modelled as a reconciliation, not a custody event.
* **Verify and Reprotect** restores ownership/mode/immutable posture for a file
  whose bytes and digest still match its committed version. It verifies the digest
  before and after applying the fixed posture and appends one
  ``EVIDENCE_REPROTECTED`` event; it cannot repair changed bytes, rename, change
  membership, or create a new version.
"""

from __future__ import annotations

from dataclasses import dataclass

from sift_gateway.custody.reauth import OperatorSession


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    """The recorded outcome of a DB-only custody action (idempotent by key)."""

    action: str
    receipt_id: str
    gate_state: str


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The read-only Full Verify outcome (no custody-state change by assertion)."""

    gate_state: str
    verified: bool
    findings: tuple[str, ...] = ()


def ignore(
    *,
    session: OperatorSession,
    case_id: str,
    display_path: str,
    password: str,
    reason: str,
    idempotency_key: str,
) -> ActionReceipt:
    """Exclude a pending inventory entry (DB-only, single atomic transaction).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_ignore``. The
    signature and single-transaction / no-failure-state contract are frozen here.
    """
    raise NotImplementedError("CP2A implements Ignore")


def retire(
    *,
    session: OperatorSession,
    case_id: str,
    evidence_object_id: str,
    password: str,
    reason: str,
    idempotency_key: str,
) -> ActionReceipt:
    """Retire a sealed object into a new Manifest Version (DB-only, byte-safe).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_retire``.
    """
    raise NotImplementedError("CP2A implements Retire")


def full_verify(*, session: OperatorSession, case_id: str) -> VerifyResult:
    """Read-only Full Verify of the active sealed set (no fresh password).

    NOT IMPLEMENTED in CP1 — CP2A implements this over reconciliation + a full
    from-disk digest/posture check. The read-only contract is frozen here.
    """
    raise NotImplementedError("CP2A implements Full Verify")


def verify_and_reprotect(
    *,
    session: OperatorSession,
    case_id: str,
    evidence_object_id: str,
    password: str,
    reason: str,
    idempotency_key: str,
) -> ActionReceipt:
    """Restore posture for an identical-bytes object (DB-only + fixed posture).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_reprotect``,
    verifying the digest before and after. The narrow posture-only contract is
    frozen here.
    """
    raise NotImplementedError("CP2A implements Verify and Reprotect")
