"""DB-only custody actions: the unified Resolve flow + read-only Full Verify.

FROZEN INTERFACE (P4.23 CP1, re-frozen 2026-07-20 repair round 1). CP2A
implements the bodies against the frozen custody RPCs (``app.custody_ignore`` /
``custody_retire`` / ``custody_reprotect``) and reconciliation.

These are the non-Seal custody mutations. Each is a SINGLE atomic transaction with
NO persistent failure state (SPEC §Drift, EC-2a): a failed attempt rolls back
completely, records nothing that blocks the case, and never prevents a subsequent
attempt. Only Seal has an incomplete-operation record. While a Seal is active,
DB-only actions on targets OUTSIDE its target set remain permitted; targets inside
its set are rejected with a shaped "seal in progress — resume it" error (EC-2b).

**D4 — one password, one Resolve entry.** The Portal presents drift resolution as
one uniform per-finding flow with batch reauthentication (one password covering N
selected targets). The public domain surface is a SINGLE entry, :func:`resolve`,
so the route stays "one domain call, zero business logic". :func:`resolve`
verifies the password once (via ``reauth.record_batch_reauth`` -> one
:class:`~sift_gateway.custody.reauth.BatchReauth` receipt carrying the target
array), then dispatches each finding to the honest, DISTINCT recorded verb:

* new entry -> Add and Seal (``custody.seal``) or Ignore;
* deleted sealed object -> Retire;
* changed sealed object -> Retire (optional reacquire-as-new at the next Seal);
* posture-only drift, identical bytes -> Verify and Reprotect.

The honest verbs are module-private (:func:`_ignore` / :func:`_retire` /
:func:`_reprotect`); they consume a per-target ``reauth_id`` from the
:class:`~sift_gateway.custody.reauth.BatchReauth`, so the RECORDED custody verbs
stay distinct (SPEC) while the operator surface stays a single batch call. No
disposition may leave an active manifest entry whose bytes differ from its
committed Evidence Version. **Full Verify** (:func:`full_verify`) is read-only and
requires no fresh password: it recomputes the full SHA-256 and validates
identity/posture/membership, changing no bytes, metadata, manifests, or custody
history; the gate opens only from verified facts.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from sift_gateway.custody.reauth import BatchReauth, OperatorSession

# The honest drift-resolution verbs, kept distinct in the recorded chain (SPEC).
ResolveVerb = Literal["IGNORE", "RETIRE", "REPROTECT", "ADD_SEAL"]
# Structured Full Verify finding classes (PostgreSQL-authoritative correlation).
VerifyFindingCode = Literal[
    "CONTENT_CHANGED",
    "SEALED_EVIDENCE_MISSING",
    "POSTURE_DRIFT",
    "UNSAFE_ENTRY",
    "STORAGE_UNAVAILABLE",
]


@dataclass(frozen=True, slots=True)
class FindingDisposition:
    """One operator-chosen disposition inside a batch Resolve (D4 input).

    Binds a single drift finding to the honest verb the operator selected.
    ``target`` is a case-relative ``evidence/<name>`` display path (Ignore /
    Add-and-Seal) or an ``evidence_object_id`` (Retire / Reprotect). CP2A routes
    it to the matching RPC under the per-target ``reauth_id`` from the batch.
    """

    verb: ResolveVerb
    target: str
    supersedes_object_id: str | None = None


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    """The recorded outcome of one DB-only custody verb (idempotent by key).

    ``audit_id`` is the custody audit / reauth event id the RPC recorded, so
    PostgreSQL-authoritative verification and export can correlate the receipt to
    the chain (re-frozen — was previously absent).
    """

    action: ResolveVerb
    receipt_id: str
    audit_id: str
    gate_state: str


@dataclass(frozen=True, slots=True)
class VerifyFinding:
    """One structured Full Verify finding (re-frozen — was an opaque string).

    Carries the machine-readable ``code`` and the ``evidence_object_id`` /
    ``display_path`` it concerns so export/verification correlation is
    PostgreSQL-authoritative rather than a free-text message parse.
    """

    code: VerifyFindingCode
    evidence_object_id: str | None = None
    display_path: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The read-only Full Verify outcome (no custody-state change by assertion)."""

    gate_state: str
    verified: bool
    findings: tuple[VerifyFinding, ...] = field(default_factory=tuple)


def resolve(
    *,
    session: OperatorSession,
    case_id: str,
    password: str,
    dispositions: Sequence[FindingDisposition],
    batch_key: str,
) -> tuple[ActionReceipt, ...]:
    """Run the unified per-finding Resolve flow under ONE password (D4).

    The single domain entry the ``resolve_findings`` route calls. Verifies
    ``password`` exactly once via ``reauth.record_batch_reauth`` -> one
    :class:`~sift_gateway.custody.reauth.BatchReauth` receipt carrying the target
    array, then dispatches each :class:`FindingDisposition` to its honest,
    DISTINCT recorded verb (:func:`_ignore` / :func:`_retire` / :func:`_reprotect`,
    or Add and Seal via ``custody.seal``) using the per-target ``reauth_id`` from
    the batch. Each verb is one atomic transaction with no persistent failure
    state; a verb that rolls back never blocks the others or the case. Returns one
    :class:`ActionReceipt` per disposition, in input order.

    NOT IMPLEMENTED in CP1 — CP2A implements the batch dispatch. The single-entry
    / one-password / distinct-recorded-verb contract is frozen here.
    """
    raise NotImplementedError("CP2A implements the unified Resolve flow")


def full_verify(*, session: OperatorSession, case_id: str) -> VerifyResult:
    """Read-only Full Verify of the active sealed set (no fresh password).

    NOT IMPLEMENTED in CP1 — CP2A implements this over reconciliation + a full
    from-disk digest/posture check. The read-only, structured-finding contract is
    frozen here.
    """
    raise NotImplementedError("CP2A implements Full Verify")


# ---------------------------------------------------------------------------
# Honest recorded verbs — module-private (consumed by :func:`resolve` only).
# Each stays a DISTINCT recorded custody verb (SPEC) but is NOT a route-facing
# surface: the operator surface is the single batch :func:`resolve`. CP2A
# implements each over its RPC, consuming a per-target ``reauth_id`` from the
# BatchReauth receipt (never a per-verb password).
# ---------------------------------------------------------------------------
def _ignore(
    *, case_id: str, display_path: str, batch: BatchReauth, reauth_id: str
) -> ActionReceipt:
    """Exclude a pending inventory entry (DB-only, single atomic transaction).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_ignore``.
    """
    raise NotImplementedError("CP2A implements Ignore")


def _retire(
    *, case_id: str, evidence_object_id: str, batch: BatchReauth, reauth_id: str
) -> ActionReceipt:
    """Retire a sealed object into a new Manifest Version (DB-only, byte-safe).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_retire``.
    """
    raise NotImplementedError("CP2A implements Retire")


def _reprotect(
    *, case_id: str, evidence_object_id: str, batch: BatchReauth, reauth_id: str
) -> ActionReceipt:
    """Restore posture for an identical-bytes object (DB-only + fixed posture).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_reprotect``,
    verifying the digest before and after.
    """
    raise NotImplementedError("CP2A implements Verify and Reprotect")
