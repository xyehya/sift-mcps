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
* **Sealed case (D2 staging window).** :func:`begin_seal` with NO targets opens a
  bounded staging window: the reauthorized ``REQUESTED`` phase lifts the
  evidence-directory immutable flag ONLY, appends ``SEAL_WINDOW_OPENED``, and
  keeps the gate blocked (agent work paused). The operator then stages new
  evidence and Refreshes; only THEN are the final targets known and passed to
  :func:`commit_seal`, which restores full posture and closes the window
  (``SEAL_WINDOW_CLOSED``).

Whether a ``begin_seal`` opens a staging window is **derived and validated
server-side** from whether the case already has a committed sealed set (SPEC D2);
it is NEVER trusted from the caller. Interruption resumes under the SAME
idempotency key: a repeated :func:`begin_seal` returns the in-flight operation
(resume pointer) and :func:`commit_seal` carries the resume reauthorization.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from sift_gateway.custody.reauth import OperatorSession

SealPhase = Literal["REQUESTED", "PROTECTED", "COMMITTED"]


@dataclass(frozen=True, slots=True)
class SealTarget:
    """One evidence file selected for sealing from a specific Refresh snapshot.

    ``snapshot_observation_id`` is the ``app.admission_observations.id`` of the
    Refresh reconciliation that surfaced this target (re-frozen). It gives CP2A
    the snapshot authority to prove every target came from the LATEST server-side
    snapshot before sealing — closing the snapshot->seal TOCTOU the amendment
    fixed. All targets in one Add and Seal MUST carry the same
    ``snapshot_observation_id``, and CP2A rejects a commit whose snapshot is not
    the case's most recent reconciliation.
    """

    display_path: str
    snapshot_observation_id: int | None = None
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
      blocked); ``targets`` may be ``None`` because the final set is not yet
      staged;
    * a fresh case -> no window; ``targets`` are the latest Refresh snapshot's
      selected files.

    A repeated call under the SAME ``idempotency_key`` returns the in-flight
    operation (the resume pointer), producing no duplicate.

    NOT IMPLEMENTED in CP1 — CP2A implements the orchestration over the frozen
    RPCs. The signature, phases, and server-derived-window contract are frozen.
    """
    raise NotImplementedError("CP2A implements the Add and Seal REQUESTED phase")


def commit_seal(
    *,
    session: OperatorSession,
    case_id: str,
    idempotency_key: str,
    targets: Sequence[SealTarget],
    password: str,
    reason: str,
    resume: bool = False,
) -> SealResult:
    """Drive ``PROTECTED -> COMMITTED`` for the targets of the latest snapshot.

    ``targets`` is the final selected set from the most recent Refresh snapshot
    (post-window for a sealed case). CP2A re-verifies every target from disk under
    protection (``custody_seal_protect``) — a target that vanished or changed
    since its ``snapshot_observation_id`` fails with a shaped error directing a
    new Refresh; there is no partial admission — then commits atomically
    (``custody_seal_commit``), advancing the Manifest Version and closing any open
    staging window (``SEAL_WINDOW_CLOSED``). ``resume=True`` carries a fresh
    resume reauthorization to complete an interrupted operation under the same
    key; a COMMITTED operation replays its recorded result idempotently.

    NOT IMPLEMENTED in CP1 — CP2A implements the protect+commit orchestration over
    the frozen RPCs. The signature and the snapshot-verification contract are
    frozen here.
    """
    raise NotImplementedError("CP2A implements the Add and Seal PROTECTED/COMMITTED phases")


def seal_status(*, case_id: str, dsn: str | None) -> SealStatus:
    """Return the path-free blocked-gate + incomplete-operation status.

    NOT IMPLEMENTED in CP1 — CP2A implements the read over the computed gate +
    ``custody_seal_operations``. The path-free contract is frozen here.
    """
    raise NotImplementedError("CP2A implements seal status")
