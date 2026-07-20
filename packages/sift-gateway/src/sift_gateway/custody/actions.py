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

**ADD_SEAL in a Resolve batch — type reconciliation (CP2A delta close).** The
frozen :class:`FindingDisposition` carries NO ``snapshot_observation_id``, but a
real ``seal.SealTarget`` requires one (it is the snapshot authority that closes
the snapshot->seal TOCTOU). An ``ADD_SEAL`` disposition therefore cannot build a
seal target inside :func:`resolve`; the "new entry -> Add and Seal" choice is
driven through the seal machine (``seal.begin_seal`` / ``commit_seal``) with
snapshot-bound targets and its own single reauth. :func:`resolve` owns the three
DB-only verbs; an ``ADD_SEAL`` disposition is rejected shaped BEFORE any reauth is
recorded, so no orphaned authorization is written.
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sift_gateway.custody import seal as custody_seal
from sift_gateway.custody.reauth import (
    BatchReauth,
    OperatorSession,
    _batch_target_key,
    _dsn,
    record_batch_reauth,
)

logger = logging.getLogger(__name__)

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

# The DB-only verbs :func:`resolve` dispatches (ADD_SEAL is the seal machine's).
_DB_ONLY_VERBS: frozenset[str] = frozenset({"IGNORE", "RETIRE", "REPROTECT"})


class ActionError(Exception):
    """A fail-closed DB-only custody-action failure, shaped by the CP2B route.

    Carries a stable machine-readable ``reason`` + ``http_status``; an error
    signal, not part of the frozen ≤6 callable/data interface (the route boundary
    duck-types ``.reason``). Raw database diagnostics never travel on it.
    """

    def __init__(self, reason: str, *, http_status: int = 409) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


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
    """The read-only Full Verify outcome (no custody-state change by assertion).

    ``verification_id`` is the PostgreSQL-authoritative verification/audit event id
    the read recorded (re-frozen — mirrors :attr:`ActionReceipt.audit_id`), so a
    Full Verify result can be correlated into export/audit without a later
    return-type change.
    """

    gate_state: str
    verified: bool
    verification_id: str
    findings: tuple[VerifyFinding, ...] = field(default_factory=tuple)


def resolve(
    *,
    session: OperatorSession,
    case_id: str,
    password: str,
    reason: str,
    dispositions: Sequence[FindingDisposition],
    batch_key: str,
) -> tuple[ActionReceipt, ...]:
    """Run the unified per-finding Resolve flow under ONE password (D4).

    The single domain entry the ``resolve_findings`` route calls. Verifies
    ``password`` exactly once (with the single batch ``reason``) via
    ``reauth.record_batch_reauth`` -> one
    :class:`~sift_gateway.custody.reauth.BatchReauth` receipt whose per-target
    ``(action, target, reauth_id)`` entries carry a distinct reauth event PER
    finding — so a HETEROGENEOUS batch (Ignore / Retire / Reprotect mixed) is
    expressible. It then dispatches each :class:`FindingDisposition` to its honest,
    DISTINCT recorded verb (:func:`_ignore` / :func:`_retire` / :func:`_reprotect`)
    using that target's bound ``reauth_id``; each RPC independently recomputes and
    compares its own single-target binding (no cross-target replay). Each verb is
    one atomic transaction with no persistent failure state; a verb that rolls
    back never leaves the case blocked. Returns one :class:`ActionReceipt` per
    disposition, in input order.

    New-file Add-and-Seal is NOT dispatched here (a ``FindingDisposition`` has no
    snapshot binding — see the module docstring); an ``ADD_SEAL`` verb is rejected
    shaped before any reauth is recorded.
    """
    if not dispositions:
        raise ActionError("invalid_request", http_status=400)
    # Reject ADD_SEAL up front so no orphaned batch reauth is written for a verb
    # that must go through the snapshot-bound seal machine.
    if any(d.verb not in _DB_ONLY_VERBS for d in dispositions):
        raise ActionError("invalid_request", http_status=400)

    batch_targets = [(str(d.verb), d.target) for d in dispositions]
    batch = record_batch_reauth(
        session=session,
        password=password,
        case_id=case_id,
        reason=reason,
        targets=batch_targets,
        batch_key=batch_key,
    )
    reauth_by: dict[tuple[str, str], str] = {
        (action, target): reauth_id for (action, target, reauth_id) in batch.entries
    }

    receipts: list[ActionReceipt] = []
    for disposition in dispositions:
        reauth_id = reauth_by[(str(disposition.verb), disposition.target)]
        if disposition.verb == "IGNORE":
            receipts.append(
                _ignore(
                    case_id=case_id,
                    display_path=disposition.target,
                    batch=batch,
                    reauth_id=reauth_id,
                )
            )
        elif disposition.verb == "RETIRE":
            receipts.append(
                _retire(
                    case_id=case_id,
                    evidence_object_id=disposition.target,
                    batch=batch,
                    reauth_id=reauth_id,
                )
            )
        else:  # REPROTECT (the only remaining DB-only verb).
            receipts.append(
                _reprotect(
                    case_id=case_id,
                    evidence_object_id=disposition.target,
                    batch=batch,
                    reauth_id=reauth_id,
                )
            )
    return tuple(receipts)


def full_verify(*, session: OperatorSession, case_id: str) -> VerifyResult:
    """Read-only Full Verify of the active sealed set (no fresh password).

    Recomputes the full SHA-256 from disk for every active sealed object and
    validates identity/link-safety/posture against its committed Evidence Version,
    producing structured findings. It changes no bytes, metadata, manifests, or
    custody history; the gate is READ (computed), never asserted. Records one
    verification audit event and returns its id as the correlation handle.
    Fail-closed: an unavailable evidence directory yields a ``STORAGE_UNAVAILABLE``
    finding and a blocked gate.
    """
    dsn = _dsn()
    import psycopg
    from psycopg.types.json import Jsonb

    findings: list[VerifyFinding] = []
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        evidence_dir = _evidence_dir_opt(cur, case_id)
        cur.execute(
            """
            select o.id::text, o.display_path, o.current_sha256,
                   v.bytes, v.st_dev, v.st_ino, v.mode
            from app.evidence_objects o
            join app.evidence_versions v on v.id = o.current_version_id
            where o.case_id = %s and o.status = 'sealed'
            """,
            (case_id,),
        )
        sealed = cur.fetchall()
        if evidence_dir is None:
            findings.append(VerifyFinding(code="STORAGE_UNAVAILABLE"))
        else:
            for obj_id, display_path, sha256, vbytes, vdev, vino, vmode in sealed:
                findings.extend(
                    _verify_one(
                        evidence_dir, str(obj_id), str(display_path),
                        str(sha256), vbytes, vdev, vino, vmode,
                    )
                )

        cur.execute("select app.custody_gate_state(%s)", (case_id,))
        gate = str(_fetchone(cur)[0] or "BLOCKED_PENDING")
        verified = not findings and gate == "OPEN"
        cur.execute(
            """
            insert into app.audit_events
              (case_id, event_type, actor_type, actor_user_id, source, status,
               summary, details)
            values (%s, 'custody.full_verify', 'user', %s, 'portal', %s,
                    'operator full verify',
                    jsonb_build_object('gate', %s, 'verified', %s,
                                       'findings', %s))
            returning id::text
            """,
            (
                case_id, session.actor_user_id,
                "success" if verified else "warning",
                gate, verified,
                Jsonb([_finding_json(f) for f in findings]),
            ),
        )
        verification_id = str(_fetchone(cur)[0])
        conn.commit()

    return VerifyResult(
        gate_state=gate,
        verified=verified,
        verification_id=verification_id,
        findings=tuple(findings),
    )


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
    key = _batch_target_key(batch.batch_key, "IGNORE", display_path)
    import psycopg

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        actor = _reauth_actor(cur, reauth_id)
        _reject_if_seal_overlap(cur, case_id, display_path)  # EC-2b overlap guard
        cur.execute(
            "select r.id::text from app.custody_ignore(%s,%s,%s,%s,%s,%s,null) r",
            (case_id, display_path, batch.reason, reauth_id, key, actor),
        )
        receipt_id = str(_fetchone(cur)[0])
        gate = _gate(cur, case_id)
        conn.commit()
    return ActionReceipt(
        action="IGNORE", receipt_id=receipt_id, audit_id=reauth_id, gate_state=gate
    )


def _retire(
    *, case_id: str, evidence_object_id: str, batch: BatchReauth, reauth_id: str
) -> ActionReceipt:
    """Retire a sealed object into a new Manifest Version (DB-only, byte-safe).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_retire``.
    """
    key = _batch_target_key(batch.batch_key, "RETIRE", evidence_object_id)
    import psycopg

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        actor = _reauth_actor(cur, reauth_id)
        _reject_if_seal_overlap(  # EC-2b overlap guard (resolve object -> path)
            cur, case_id, _object_display_path(cur, case_id, evidence_object_id)
        )
        cur.execute(
            "select r.id::text from app.custody_retire(%s,%s,%s,%s,%s,%s,null) r",
            (case_id, evidence_object_id, batch.reason, reauth_id, key, actor),
        )
        receipt_id = str(_fetchone(cur)[0])
        gate = _gate(cur, case_id)
        conn.commit()
    return ActionReceipt(
        action="RETIRE", receipt_id=receipt_id, audit_id=reauth_id, gate_state=gate
    )


def _reprotect(
    *, case_id: str, evidence_object_id: str, batch: BatchReauth, reauth_id: str
) -> ActionReceipt:
    """Restore posture for an identical-bytes object (DB-only + fixed posture).

    NOT IMPLEMENTED in CP1 — CP2A implements this over ``app.custody_reprotect``,
    verifying the digest before and after.
    """
    key = _batch_target_key(batch.batch_key, "REPROTECT", evidence_object_id)
    import psycopg
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        actor = _reauth_actor(cur, reauth_id)
        _reject_if_seal_overlap(  # EC-2b overlap guard (resolve object -> path)
            cur, case_id, _object_display_path(cur, case_id, evidence_object_id)
        )
        # Reprotect is available ONLY for identical bytes and safe identity/link
        # posture. Restore the fixed sealed-file posture on the same pinned fd,
        # then re-hash before the RPC records EVIDENCE_REPROTECTED.
        posture = _restore_reprotect_posture(cur, case_id, evidence_object_id)
        posture["reason"] = batch.reason
        cur.execute(
            "select r.id::text from app.custody_reprotect(%s,%s,%s,%s,%s,%s,null) r",
            (
                case_id, evidence_object_id, Jsonb(posture), reauth_id, key, actor,
            ),
        )
        receipt_id = str(_fetchone(cur)[0])
        gate = _gate(cur, case_id)
        conn.commit()
    return ActionReceipt(
        action="REPROTECT", receipt_id=receipt_id, audit_id=reauth_id, gate_state=gate
    )


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------
def _fetchone(cur: Any) -> Any:
    """Fetch a row that MUST exist (RPC/aggregate always returns one), else fail."""
    row = cur.fetchone()
    if row is None:
        raise ActionError("custody_internal", http_status=500)
    return row


def _reauth_actor(cur: Any, reauth_id: str) -> str:
    """The actor bound to a reauth event (the verb has no ``session`` argument).

    The honest-verb signatures carry no ``session``; the RPC's ``p_actor_user_id``
    must equal the reauth event's ``actor_user_id`` (which it re-checks by scalar
    equality), so the actor is derived from the authorization being consumed.
    """
    cur.execute(
        "select actor_user_id::text from app.audit_events where id = %s", (reauth_id,)
    )
    row = cur.fetchone()
    if not row or not row[0]:
        raise ActionError("reauth_scope_mismatch", http_status=403)
    return str(row[0])


def _object_display_path(cur: Any, case_id: str, evidence_object_id: str) -> str | None:
    """Resolve an object's display path for the EC-2b overlap check (read-only)."""
    cur.execute(
        "select display_path from app.evidence_objects where id = %s and case_id = %s",
        (evidence_object_id, case_id),
    )
    row = cur.fetchone()
    return str(row[0]) if row and row[0] else None


def _reject_if_seal_overlap(cur: Any, case_id: str, display_path: str | None) -> None:
    """Reject a DB-only action whose target is inside an ACTIVE Seal's set (EC-2b).

    Python read-then-reject BEFORE any mutation: SELECT the active (non-committed)
    seal operation for the case and test membership of ``display_path`` in its
    recorded target array (``jsonb_exists`` == the ``?`` element test). A target
    INSIDE the set is rejected shaped ``seal_in_progress``; a DISJOINT target
    proceeds — EC-2b permits non-overlapping DB-only actions during an active Seal
    (SPEC Custody Lifecycle scenario 11). A ``None`` display path (unresolved
    object) cannot overlap by path.

    Residual TOCTOU (documented — NOT a migration edit): this Python pre-check
    catches the normal case; the atomic backstops are the one-active-Seal-per-case
    unique constraint and seal-commit's D1 from-disk re-verification, so a race
    that slips the pre-check surfaces as a seal-commit inconsistency, never silent
    corruption. Truly-atomic RPC-level enforcement would be a CP3 stop-and-amend
    migration, out of the CP2A lane (the frozen CP1 RPCs are not edited here).
    """
    if display_path is None:
        return
    cur.execute(
        "select exists(select 1 from app.custody_seal_operations s "
        "where s.case_id = %s and s.phase <> 'COMMITTED' "
        "and jsonb_exists(s.targets, %s))",
        (case_id, display_path),
    )
    if _fetchone(cur)[0]:
        raise ActionError("seal_in_progress", http_status=409)


def _gate(cur: Any, case_id: str) -> str:
    cur.execute("select app.custody_gate_state(%s)", (case_id,))
    row = cur.fetchone()
    return str(row[0]) if row and row[0] else "BLOCKED_PENDING"


def _evidence_dir_opt(cur: Any, case_id: str) -> Path | None:
    cur.execute("select legacy_case_dir from app.cases where id = %s", (case_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    evidence_dir = Path(str(row[0])) / "evidence"
    return evidence_dir if evidence_dir.is_dir() else None


def _hash_path(path: Path) -> tuple[str, int] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return None
        return _hash_fd(fd)
    finally:
        os.close(fd)


def _hash_fd(fd: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return "sha256:" + digest.hexdigest(), size


def _verify_one(
    evidence_dir: Path,
    obj_id: str,
    display_path: str,
    committed_sha256: str,
    vbytes: Any,
    vdev: Any,
    vino: Any,
    vmode: Any,
) -> list[VerifyFinding]:
    """Read-only per-object verification against the committed version."""
    name = display_path.split("/", 1)[-1]
    path = evidence_dir / name
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return [
            VerifyFinding(
                code="SEALED_EVIDENCE_MISSING",
                evidence_object_id=obj_id,
                display_path=display_path,
            )
        ]
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return [
            VerifyFinding(
                code="UNSAFE_ENTRY", evidence_object_id=obj_id, display_path=display_path
            )
        ]
    hashed = _hash_path(path)
    if hashed is None:
        return [
            VerifyFinding(
                code="UNSAFE_ENTRY", evidence_object_id=obj_id, display_path=display_path
            )
        ]
    sha256, size = hashed
    if sha256 != committed_sha256 or (vbytes is not None and int(vbytes) != size):
        return [
            VerifyFinding(
                code="CONTENT_CHANGED",
                evidence_object_id=obj_id,
                display_path=display_path,
            )
        ]
    findings: list[VerifyFinding] = []
    if (
        (vino is not None and int(vino) != st.st_ino)
        or (vdev is not None and int(vdev) != st.st_dev)
        or (vmode is not None and str(vmode) != _mode_str(st.st_mode))
    ):
        findings.append(
            VerifyFinding(
                code="POSTURE_DRIFT",
                evidence_object_id=obj_id,
                display_path=display_path,
            )
        )
    return findings


def _restore_reprotect_posture(
    cur: Any, case_id: str, evidence_object_id: str
) -> dict[str, Any]:
    """Verify bytes, restore fixed posture, then verify bytes again on one fd."""
    cur.execute(
        """
        select o.display_path, v.sha256, v.bytes, v.st_dev, v.st_ino
        from app.evidence_objects o
        join app.evidence_versions v on v.id = o.current_version_id
        where o.id = %s and o.case_id = %s and o.current_version_id is not null
        """,
        (evidence_object_id, case_id),
    )
    row = cur.fetchone()
    if not row:
        raise ActionError("target_not_pending", http_status=409)
    display_path, committed_sha256 = str(row[0]), str(row[1])
    committed_bytes, committed_dev, committed_ino = row[2], row[3], row[4]
    evidence_dir = _evidence_dir_opt(cur, case_id)
    if evidence_dir is None:
        raise ActionError("storage_unavailable", http_status=409)

    parts = Path(display_path).parts
    if len(parts) != 2 or parts[0] != "evidence" or parts[1] in ("", ".", ".."):
        raise ActionError("reprotect_bytes_changed", http_status=409)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(
            evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow
        )
    except OSError as exc:
        raise ActionError("reprotect_bytes_changed", http_status=409) from exc

    try:
        try:
            fd = os.open(
                parts[1], os.O_RDONLY | os.O_CLOEXEC | nofollow, dir_fd=root_fd
            )
        except OSError as exc:
            raise ActionError("reprotect_bytes_changed", http_status=409) from exc
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ActionError("reprotect_bytes_changed", http_status=409)
            if committed_dev is not None and int(committed_dev) != before.st_dev:
                raise ActionError("reprotect_bytes_changed", http_status=409)
            if committed_ino is not None and int(committed_ino) != before.st_ino:
                raise ActionError("reprotect_bytes_changed", http_status=409)
            before_sha256, before_size = _hash_fd(fd)
            if before_sha256 != committed_sha256 or (
                committed_bytes is not None and int(committed_bytes) != before_size
            ):
                raise ActionError("reprotect_bytes_changed", http_status=409)

            try:
                custody_seal._apply_fixed_file_posture(fd)
            except custody_seal.SealError as exc:
                raise ActionError("custody_internal", http_status=500) from exc

            after = os.fstat(fd)
            after_sha256, after_size = _hash_fd(fd)
            if (
                after_sha256 != before_sha256
                or after_size != before_size
                or after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_nlink != 1
                or stat.S_IMODE(after.st_mode) != 0o644
                or custody_seal.get_immutable_flag_fd(fd) is not True
            ):
                raise ActionError("custody_internal", http_status=500)
            return {
                "sha256": committed_sha256,
                "mode": "0644",
                "immutable": True,
            }
        except OSError as exc:
            raise ActionError("reprotect_bytes_changed", http_status=409) from exc
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def _mode_str(mode: int) -> str:
    return oct(stat.S_IMODE(mode)).replace("0o", "0")


def _finding_json(finding: VerifyFinding) -> dict[str, Any]:
    return {
        "code": finding.code,
        "evidence_object_id": finding.evidence_object_id,
        "display_path": finding.display_path,
        "detail": finding.detail,
    }
