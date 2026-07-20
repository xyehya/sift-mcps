"""Add and Seal — the one REQUESTED -> PROTECTED -> COMMITTED custody machine.

FROZEN INTERFACE (P4.23 CP1, re-frozen 2026-07-20 repair round 1). CP2A
implements the bodies against the frozen custody RPCs (``app.custody_seal_begin``
/ ``custody_seal_protect`` / ``custody_seal_commit``) and the frozen ``reauth``
builder.

Add and Seal is the only custody operation that crosses PostgreSQL and filesystem
protection (SPEC §Add and Seal). It is one small idempotent state machine:

    REQUESTED -> PROTECTED -> COMMITTED

* ``REQUESTED`` records the authorized intent and blocks admission before any
  filesystem mutation.
* ``PROTECTED`` applies immutable protection and re-verifies the exact file
  identity, full SHA-256, size, ownership, mode, and link posture FROM DISK — the
  commit records what was verified under protection, never what a prior Refresh
  snapshot displayed (SPEC D1; kills the snapshot->seal TOCTOU).
* ``COMMITTED`` atomically creates the Evidence Object/Version, advances the
  Manifest Version, and appends the canonical custody events.

Retry uses the SAME idempotency key and must produce exactly one object, version,
manifest transition, and canonical event set. There is no abort path; an
incomplete Seal only completes (SPEC §4). There is NO FAILED_RECOVERABLE latch
(EC-2) — an incomplete operation is a resume pointer, never a case-wide brick.

**Phased seam (re-frozen — D2 staging window).** The seam is split into
:func:`begin_seal` (REQUESTED) and :func:`commit_seal` (PROTECTED -> COMMITTED)
so it can express BOTH supported paths without a second state machine:

* **Fresh case (single-shot expressible).** The operator stages files, Refreshes,
  then :func:`begin_seal` with the snapshot's targets and :func:`commit_seal` with
  the same targets — no staging window is opened.
* **Sealed case (D2 staging window).** :func:`begin_seal` with the intended NEW
  files opens a bounded staging window: the reauthorized ``REQUESTED`` phase lifts
  the evidence-directory immutable flag ONLY, appends ``SEAL_WINDOW_OPENED``, and
  keeps the gate blocked (agent work paused). The operator then stages exactly
  those files and Refreshes; :func:`commit_seal` re-verifies them from disk,
  restores full posture, and closes the window (``SEAL_WINDOW_CLOSED``).

**opens_staging_window — docstring/RPC reconciliation (CP2A delta close).** The
frozen ``custody_seal_begin`` RPC REQUIRES a non-empty ``p_targets`` (an empty set
raises ``invalid_seal_request``). Code wins: :func:`begin_seal` therefore ALWAYS
takes a non-empty target set (the frozen ``targets=None`` default is rejected at
runtime with a shaped ``invalid_request``); for a sealed case those are the
intended new files. Whether a ``begin_seal`` opens a staging window is DERIVED and
validated server-side from whether the case already has a committed sealed set
(SPEC D2) — it is NEVER trusted from the caller. Interruption resumes under the
SAME idempotency key: a repeated :func:`begin_seal` returns the in-flight
operation (resume pointer) and :func:`commit_seal` carries the resume
reauthorization.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pwd
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sift_core.evidence_posture import get_immutable_flag_fd, set_immutable_flag_fd

from sift_gateway.custody.reauth import (
    OperatorSession,
    ReauthError,
    _dsn,
    _record_resume_reauth,
    _resolve_operator,
    build_binding,
    record_reauth,
)

logger = logging.getLogger(__name__)

SealPhase = Literal["REQUESTED", "PROTECTED", "COMMITTED"]


class SealError(Exception):
    """A fail-closed Add-and-Seal failure, shaped by the thin CP2B route (EC-3).

    Carries a stable machine-readable ``reason`` and an ``http_status``; it is an
    error signal, not part of the frozen ≤6 callable/data interface (the route
    boundary duck-types ``.reason``). Raw database diagnostics never travel on it.
    The "refresh"-directing reasons (``seal_snapshot_stale`` / ``seal_target_*``)
    tell the operator to re-Refresh and re-select — there is no partial admission.
    """

    def __init__(self, reason: str, *, http_status: int = 409) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class SealTarget:
    """One evidence file selected for sealing from a specific Refresh snapshot.

    ``snapshot_observation_id`` is the ``app.admission_observations.id`` of the
    Refresh reconciliation that surfaced this target — REQUIRED (re-frozen): every
    legitimate seal target references the snapshot row it came from, which is the
    snapshot authority that closes the snapshot->seal TOCTOU. No supported
    ``SealTarget`` legitimately lacks it. All targets in one Add and Seal MUST
    carry the same ``snapshot_observation_id``, and CP2A rejects a commit whose
    snapshot is not the case's most recent reconciliation.
    """

    display_path: str
    snapshot_observation_id: int
    display_name: str | None = None
    source: str | None = None
    supersedes_object_id: str | None = None


@dataclass(frozen=True, slots=True)
class SealResult:
    """The outcome of a Seal phase call (idempotent under the same key)."""

    operation_id: str
    phase: SealPhase
    manifest_version: int | None
    manifest_hash: str | None
    gate_state: str
    # True while a D2 staging window is open (server-derived at begin, closed at
    # commit). The gate stays blocked and agent work is paused for its duration.
    staging_window_open: bool = False
    sealed_object_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class SealStatus:
    """Path-free blocked-gate status for a reloaded Portal (SPEC §4).

    Exposes the incomplete operation's id + idempotency key so a reloaded Portal
    can resubmit the same operation, and NOTHING else — no stored commands, paths,
    reasons, credentials, or reauthentication material.
    """

    gate_state: str
    incomplete_operation_id: str | None
    incomplete_idempotency_key: str | None
    staging_window_open: bool = False


def begin_seal(
    *,
    session: OperatorSession,
    case_id: str,
    password: str,
    reason: str,
    idempotency_key: str,
    targets: Sequence[SealTarget] | None = None,
) -> SealResult:
    """Drive a Seal to ``REQUESTED`` (idempotent; resume-safe).

    Verifies the initial reauthorization (EC-6 canonical binding) and records the
    authorized intent via ``custody_seal_begin``, enforcing one active Seal per
    case. Whether this opens a D2 staging window is DERIVED server-side from the
    case's committed-sealed-set state, never trusted from the caller:

    * a case with a committed sealed set -> opens the bounded staging window
      (directory immutability lifted, ``SEAL_WINDOW_OPENED`` appended, gate
      blocked); the ``targets`` are the intended NEW files to add;
    * a fresh case -> no window; ``targets`` are the latest Refresh snapshot's
      selected files.

    ``targets`` is REQUIRED and non-empty (the frozen ``| None`` default is
    rejected — see the module docstring's opens_staging_window reconciliation).
    A repeated call under the SAME ``idempotency_key`` returns the in-flight
    operation (the resume pointer), producing no duplicate.
    """
    if not targets:
        raise SealError("invalid_request", http_status=400)
    snapshot_ids = {t.snapshot_observation_id for t in targets}
    if len(snapshot_ids) != 1:
        # All targets in one Add and Seal share exactly one snapshot (re-frozen).
        raise SealError("invalid_request", http_status=400)
    display_paths = [t.display_path for t in targets]

    # EC-6: the reauth binding is built from these exact display paths; the SQL
    # builder (in record_reauth) and every verifier order them COLLATE "C", so a
    # mixed-case multi-file set can never drift between writer and verifier.
    binding = build_binding(idempotency_key, reason, display_paths)
    reauth_id = record_reauth(
        session=session,
        password=password,
        action="ADD_SEAL",
        case_id=case_id,
        binding=binding,
    )
    request_digest = _request_digest(case_id, idempotency_key, reason, display_paths)

    import psycopg
    from psycopg.types.json import Jsonb

    evidence_dir: Path | None = None
    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        # opens_staging_window is DERIVED server-side: a committed sealed set means
        # this begin is adding evidence to a sealed case (SPEC D2). Never trusted
        # from the caller.
        cur.execute(
            "select exists(select 1 from app.evidence_objects "
            "where case_id = %s and status = 'sealed')",
            (case_id,),
        )
        opens_window = bool(_fetchone(cur)[0])
        cur.execute(
            "select r.id::text, r.phase, r.opens_staging_window "
            "from app.custody_seal_begin(%s,%s,%s,%s,%s,%s,%s,%s,null) r",
            (
                case_id, idempotency_key, request_digest, reason, reauth_id,
                Jsonb(display_paths), session.actor_user_id, opens_window,
            ),
        )
        row = _fetchone(cur)
        operation_id, phase, window = str(row[0]), str(row[1]), bool(row[2])
        if window:
            # Resolve the dir inside the txn so we can lift its immutable flag for
            # staging once the window open is durably recorded (below).
            evidence_dir = _evidence_dir(cur, case_id)
        cur.execute("select app.custody_gate_state(%s)", (case_id,))
        gate = _fetchone(cur)[0]
        conn.commit()

    # D2: lift the evidence-directory immutable flag ONLY after the window open is
    # committed — the directory is mutable only inside the window (SEAL_WINDOW_OPENED
    # was appended by custody_seal_begin). Fail toward immutable on a crash between
    # the DB commit and this lift; a same-key resume re-runs begin and re-lifts.
    if window and evidence_dir is not None:
        _set_directory_immutable(evidence_dir, immutable=False)

    return SealResult(
        operation_id=operation_id,
        phase=phase,  # type: ignore[arg-type]
        manifest_version=None,
        manifest_hash=None,
        gate_state=str(gate) if gate else "BLOCKED_PENDING",
        staging_window_open=window,
        sealed_object_ids=(),
    )


def commit_seal(
    *,
    session: OperatorSession,
    case_id: str,
    idempotency_key: str,
    targets: Sequence[SealTarget],
    password: str | None = None,
    reason: str | None = None,
    resume: bool = False,
) -> SealResult:
    """Drive ``PROTECTED -> COMMITTED`` for the targets of the latest snapshot.

    ``targets`` is the final selected set from the most recent Refresh snapshot
    (post-window for a sealed case). CP2A re-verifies every target from disk under
    protection (``custody_seal_protect``) — a target that vanished or changed
    since its ``snapshot_observation_id`` fails with a shaped error directing a
    new Refresh; there is no partial admission — then commits atomically
    (``custody_seal_commit``), advancing the Manifest Version and closing any open
    staging window (``SEAL_WINDOW_CLOSED``). A COMMITTED operation replays its
    recorded result idempotently.

    **Conditional reauth (operator decision 2026-07-20).** ``password``/``reason``
    are OPTIONAL and required only on a resubmission:

    * **Happy-path single-shot** (fresh case, uninterrupted begin->commit): omit
      both. Commit CONSUMES the authorization recorded at :func:`begin_seal`
      (operation-bound, ``custody_seal_commit`` with a null resume reauth uses the
      operation's begin ``reauth_audit_event_id``) — the operator is prompted
      ONCE, at begin.
    * **Resubmission** — ``resume=True`` (crash resume) OR a commit that closes a
      begin-opened staging window (the sealed-case add): ``password`` + ``reason``
      are REQUIRED and carry a fresh reauthorization that authorizes continuation
      (SPEC §4; the ``custody_seal_commit`` resume-reauth path). CP2A enforces
      "required" by reading the operation's recorded phase/``opens_staging_window``
      state — the DB records the begin authorization to consume, so no new RPC or
      migration is needed. There is no separate resume-credential (SPEC §Reauth).
    """
    if not targets:
        raise SealError("invalid_request", http_status=400)
    snapshot_ids = {t.snapshot_observation_id for t in targets}
    if len(snapshot_ids) != 1:
        raise SealError("invalid_request", http_status=400)
    snapshot_id = next(iter(snapshot_ids))
    display_paths = [t.display_path for t in targets]

    import psycopg
    from psycopg.types.json import Jsonb

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        cur.execute(
            "select id::text, phase, opens_staging_window, targets, actor_user_id::text "
            "from app.custody_seal_operations where case_id = %s and idempotency_key = %s",
            (case_id, idempotency_key),
        )
        op = cur.fetchone()
        if not op:
            # begin was never recorded — nothing to resume/commit.
            raise SealError("seal_operation_not_found", http_status=409)
        operation_id, phase, opens_window = str(op[0]), str(op[1]), bool(op[2])
        recorded_targets = list(op[3] or [])

        if phase == "COMMITTED":
            # Idempotent replay of the recorded result — no reauth, no fs work.
            cur.execute(
                "select result from app.custody_seal_operations where id = %s",
                (operation_id,),
            )
            result = _fetchone(cur)[0] or {}
            sealed_ids = _sealed_object_ids(cur, operation_id)
            conn.rollback()
            return _committed_result(operation_id, result, sealed_ids)

        # Defense in depth: the committed set must equal the reauthorized targets
        # (docstring obligation — seal_commit cross-checks p_items vs targets).
        if sorted(str(t) for t in recorded_targets) != sorted(display_paths):
            raise SealError("seal_targets_mismatch", http_status=409)

        # Snapshot recency: the selected snapshot must be the case's MOST RECENT
        # reconciliation, or a newer Refresh has superseded it (TOCTOU close).
        cur.execute(
            "select max(id) from app.admission_observations where case_id = %s",
            (case_id,),
        )
        latest = _fetchone(cur)[0]
        if latest is None or int(latest) != int(snapshot_id):
            raise SealError("seal_snapshot_stale", http_status=409)

        # The snapshot's on-disk facts, to detect change-since-snapshot at protect.
        cur.execute(
            "select display_path, bytes, st_ino, st_dev "
            "from app.evidence_inventory where case_id = %s",
            (case_id,),
        )
        inventory = {
            str(r[0]): {"bytes": r[1], "st_ino": r[2], "st_dev": r[3]}
            for r in cur.fetchall()
        }
        evidence_dir = _evidence_dir(cur, case_id)
        # End the read txn before filesystem work + the (network) verifier call.
        conn.rollback()

        # Conditional fresh reauth (single-shot consumes begin's authorization).
        require_fresh = bool(resume) or opens_window
        resume_reauth_id: str | None = None
        if require_fresh:
            if not password or not reason:
                raise SealError("reauth_required", http_status=403)
            resume_reauth_id = _record_resume_reauth(
                session=session,
                case_id=case_id,
                operation_id=operation_id,
                password=password,
            )

        # PROTECTED (SPEC D1): recompute every digest/identity/posture FROM DISK
        # and apply immutable protection; the commit records what was verified.
        facts = _protect_and_verify(evidence_dir, targets, inventory)

        examiner = _examiner_email(cur, session.actor_user_id)
        cur.execute(
            "select app.custody_seal_protect(%s, %s, %s, null)",
            (operation_id, Jsonb({"items": facts}), session.actor_user_id),
        )
        cur.execute(
            "select r.id::text, r.phase, r.result "
            "from app.custody_seal_commit(%s, %s, %s, %s) r",
            (operation_id, Jsonb(facts), examiner, resume_reauth_id),
        )
        row = _fetchone(cur)
        committed_id, committed_phase, result = str(row[0]), str(row[1]), row[2] or {}
        sealed_ids = _sealed_object_ids(cur, committed_id)
        conn.commit()

    return SealResult(
        operation_id=committed_id,
        phase=committed_phase,  # type: ignore[arg-type]
        manifest_version=result.get("manifest_version"),
        manifest_hash=result.get("manifest_hash"),
        gate_state=str(result.get("gate") or "OPEN"),
        staging_window_open=False,
        sealed_object_ids=sealed_ids,
    )


def seal_status(*, case_id: str, dsn: str | None) -> SealStatus:
    """Return the path-free blocked-gate + incomplete-operation status.

    Exposes only the computed gate plus the incomplete operation's id +
    idempotency key so a reloaded Portal can resubmit (SPEC §4). Fail-closed: any
    error yields a blocked status with no operation handle.
    """
    resolved = (dsn or "").strip() or (
        os.environ.get("SIFT_CONTROL_PLANE_DSN") or ""
    ).strip()
    if not case_id or not resolved:
        return SealStatus("BLOCKED_UNAVAILABLE", None, None, False)
    try:
        import psycopg

        with psycopg.connect(resolved) as conn, conn.cursor() as cur:
            cur.execute(
                """
                select app.custody_gate_state(%s),
                       s.id::text, s.idempotency_key, s.opens_staging_window
                from (select 1) _
                left join lateral (
                    select id, idempotency_key, opens_staging_window
                    from app.custody_seal_operations
                    where case_id = %s and phase <> 'COMMITTED'
                    order by created_at desc limit 1
                ) s on true
                """,
                (case_id, case_id),
            )
            row = cur.fetchone()
    except Exception as exc:
        logger.warning("seal_status: query failed for %s: %s", case_id, exc)
        return SealStatus("BLOCKED_UNAVAILABLE", None, None, False)

    state = str(row[0]) if row and row[0] else "BLOCKED_PENDING"
    return SealStatus(
        gate_state=state,
        incomplete_operation_id=str(row[1]) if row and row[1] else None,
        incomplete_idempotency_key=str(row[2]) if row and row[2] else None,
        staging_window_open=bool(row[3]) if row and row[3] is not None else False,
    )


# ---------------------------------------------------------------------------
# Internal helpers — module-private (never acceptance surfaces).
# ---------------------------------------------------------------------------
def _fetchone(cur: Any) -> Any:
    """Fetch a row that MUST exist (RPC/aggregate always returns one), else fail."""
    row = cur.fetchone()
    if row is None:
        raise SealError("storage_unavailable", http_status=500)
    return row


def _request_digest(
    case_id: str, idempotency_key: str, reason: str, display_paths: list[str]
) -> str:
    """Stable ``sha256:...`` digest of the seal request (idempotency correlation).

    Deterministic over the same (case, key, reason, target set), so a resume under
    the same key returns the in-flight operation, while the SAME key with a
    DIFFERENT request is rejected ``idempotency_key_reused`` by the RPC.
    """
    material = json.dumps(
        {
            "case_id": case_id,
            "idempotency_key": idempotency_key,
            "reason": reason.strip(),
            "targets": sorted(display_paths),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _evidence_dir(cur: Any, case_id: str) -> Path:
    """Resolve the case's canonical evidence directory, fail-closed."""
    cur.execute("select legacy_case_dir from app.cases where id = %s", (case_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        raise SealError("storage_unavailable", http_status=409)
    evidence_dir = Path(str(row[0])) / "evidence"
    if not evidence_dir.is_dir():
        raise SealError("storage_unavailable", http_status=409)
    return evidence_dir


def _hash_fd(fd: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return "sha256:" + digest.hexdigest(), size


def _set_directory_immutable(evidence_dir: Path, *, immutable: bool) -> None:
    """Apply or lift the evidence-DIRECTORY immutable flag (SPEC D2).

    A committed seal leaves the evidence directory itself create/delete/rename
    protected (immutable), so unprivileged force-adds are physically impossible
    (SPEC Add-and-Seal amendment); the flag is lifted ONLY inside a reauthorized
    staging window. fd-based and ``O_NOFOLLOW``; when applying, the flag is
    verified. Monkeypatchable at the ``sift_core.evidence_posture`` seam (hosts
    without CAP_LINUX_IMMUTABLE).
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(
        evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow
    )
    try:
        if not set_immutable_flag_fd(dir_fd, immutable):
            raise SealError("seal_protect_failed", http_status=500)
        if immutable and get_immutable_flag_fd(dir_fd) is not True:
            raise SealError("seal_protect_failed", http_status=409)
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def _protect_and_verify(
    evidence_dir: Path,
    targets: Sequence[SealTarget],
    inventory: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply immutable protection and recompute every fact FROM DISK (SPEC D1).

    fd-based and never following a symlink: opens the evidence directory and each
    target with ``O_NOFOLLOW``, validates it is a service-owned, single-linked,
    ``0644`` regular file, hashes it, applies the immutable flag via the
    ``sift_core.evidence_posture`` primitive (monkeypatchable at the seam for
    hosts without CAP_LINUX_IMMUTABLE), then re-verifies posture + digest.

    The committed digest is what THIS function computed under protection, never a
    prior snapshot value (the TOCTOU kill). A target that vanished since its
    snapshot, or whose on-disk identity differs from the snapshot inventory, fails
    with a shaped ``seal_target_*`` error directing a new Refresh — no partial
    admission.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        service_uid = pwd.getpwnam(_service_user()).pw_uid
    except KeyError as exc:  # service user unknown -> cannot verify ownership.
        raise SealError("storage_unavailable", http_status=500) from exc

    root_fd = os.open(
        evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | nofollow
    )
    open_fds: list[int] = []
    facts: list[dict[str, Any]] = []
    try:
        for target in targets:
            disp = target.display_path
            parts = disp.split("/")
            if len(parts) != 2 or parts[0] != "evidence" or parts[1] in ("", ".", ".."):
                raise SealError("invalid_request", http_status=400)
            name = parts[1]
            try:
                fd = os.open(
                    name, os.O_RDONLY | os.O_CLOEXEC | nofollow, dir_fd=root_fd
                )
            except FileNotFoundError as exc:
                raise SealError("seal_target_vanished", http_status=409) from exc
            except OSError as exc:  # e.g. ELOOP on a symlinked target.
                raise SealError("seal_target_unsafe", http_status=409) from exc
            open_fds.append(fd)

            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise SealError("seal_target_unsafe", http_status=409)
            if st.st_uid != service_uid:
                raise SealError("seal_target_owner", http_status=409)
            if stat.S_IMODE(st.st_mode) != 0o644:
                raise SealError("seal_target_mode", http_status=409)

            inv = inventory.get(disp)
            if inv is not None and (
                (inv.get("st_ino") is not None and int(inv["st_ino"]) != st.st_ino)
                or (inv.get("bytes") is not None and int(inv["bytes"]) != st.st_size)
            ):
                raise SealError("seal_target_changed", http_status=409)

            sha256, size = _hash_fd(fd)
            if not set_immutable_flag_fd(fd, True):
                raise SealError("seal_protect_failed", http_status=500)

            st2 = os.fstat(fd)
            sha256_after, size_after = _hash_fd(fd)
            if (
                get_immutable_flag_fd(fd) is not True
                or sha256_after != sha256
                or size_after != size
                or st2.st_ino != st.st_ino
                or st2.st_dev != st.st_dev
                or st2.st_nlink != 1
                or stat.S_IMODE(st2.st_mode) != 0o644
            ):
                raise SealError("seal_protect_failed", http_status=409)

            facts.append(
                {
                    "display_path": disp,
                    "display_name": target.display_name or name,
                    "sha256": sha256,
                    "bytes": size,
                    "st_dev": st.st_dev,
                    "st_ino": st.st_ino,
                    "st_nlink": 1,
                    "owner": _service_user(),
                    "mode": "0644",
                    "immutable": True,
                    "source": target.source,
                    "supersedes_object_id": target.supersedes_object_id,
                }
            )
        # D2: with every file protected, make the evidence DIRECTORY itself
        # immutable (create/delete/rename lock) so unprivileged force-adds are
        # physically impossible; verify it took. Re-applied at a staging-window
        # re-commit (this runs for both the fresh commit and the window commit),
        # restoring the posture the window temporarily lifted.
        if not set_immutable_flag_fd(root_fd, True):
            raise SealError("seal_protect_failed", http_status=500)
        if get_immutable_flag_fd(root_fd) is not True:
            raise SealError("seal_protect_failed", http_status=409)
        return facts
    finally:
        for fd in open_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.close(root_fd)
        except OSError:
            pass


def _service_user() -> str:
    return os.environ.get("SIFT_GATEWAY_SERVICE_USER", "sift-service")


def _examiner_email(cur: Any, actor_user_id: str) -> str | None:
    """Best-effort operator email for the version's ``registered_by`` (read-only)."""
    try:
        email, _ = _resolve_operator(cur, actor_user_id)
        return email
    except ReauthError:
        return None
    finally:
        # _resolve_operator only reads; drop its txn so it never lingers.
        try:
            cur.connection.rollback()
        except Exception:
            pass


def _sealed_object_ids(cur: Any, operation_id: str) -> tuple[str, ...]:
    """The Evidence Objects newly sealed by this operation (version-linked)."""
    cur.execute(
        "select o.id::text from app.evidence_objects o "
        "join app.evidence_versions v on v.id = o.current_version_id "
        "where v.seal_operation_id = %s order by o.display_path collate \"C\"",
        (operation_id,),
    )
    return tuple(str(r[0]) for r in cur.fetchall())


def _committed_result(
    operation_id: str, result: dict[str, Any], sealed_ids: tuple[str, ...]
) -> SealResult:
    return SealResult(
        operation_id=operation_id,
        phase="COMMITTED",
        manifest_version=result.get("manifest_version"),
        manifest_hash=result.get("manifest_hash"),
        gate_state=str(result.get("gate") or "OPEN"),
        staging_window_open=False,
        sealed_object_ids=sealed_ids,
    )
