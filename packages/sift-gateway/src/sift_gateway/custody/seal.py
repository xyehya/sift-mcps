"""Add and Seal — the one REQUESTED -> PROTECTED -> COMMITTED custody machine.

FROZEN INTERFACE (P4.23 CP1, 2026-07-20). CP2A implements the bodies against the
frozen custody RPCs (``app.custody_seal_begin`` / ``custody_seal_protect`` /
``custody_seal_commit``) and the frozen ``reauth`` builder.

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

**D2 — staging window inside REQUESTED.** Adding evidence to a case that already
has a committed sealed set happens INSIDE this same machine, not as a separate
operation: :func:`add_and_seal` is called with ``opens_staging_window=True``. The
reauthorized ``REQUESTED`` phase lifts the evidence-directory immutable flag only,
appends ``SEAL_WINDOW_OPENED``/``SEAL_WINDOW_CLOSED`` custody events, and keeps the
gate blocked (agent work is paused for the window's duration). ``PROTECTED`` /
``COMMITTED`` restore full directory + per-file immutability. No separate window
operation or second state machine exists.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from sift_gateway.custody.reauth import OperatorSession

SealPhase = Literal["REQUESTED", "PROTECTED", "COMMITTED"]


@dataclass(frozen=True, slots=True)
class SealTarget:
    """One evidence file selected for sealing from the latest Refresh snapshot."""

    display_path: str
    display_name: str | None = None
    source: str | None = None
    supersedes_object_id: str | None = None


@dataclass(frozen=True, slots=True)
class SealResult:
    """The outcome of an Add and Seal call (idempotent under the same key)."""

    operation_id: str
    phase: SealPhase
    manifest_version: int | None
    manifest_hash: str | None
    gate_state: str
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


def add_and_seal(
    *,
    session: OperatorSession,
    case_id: str,
    targets: Sequence[SealTarget],
    password: str,
    reason: str,
    idempotency_key: str,
    opens_staging_window: bool = False,
) -> SealResult:
    """Run one Add and Seal to completion (or resume an in-flight one).

    Drives ``custody_seal_begin`` (reauth-verified REQUESTED), then re-verifies
    every target from disk under protection and calls ``custody_seal_protect``,
    then commits atomically via ``custody_seal_commit``. A selected target that
    vanished or changed since the Refresh snapshot fails with a shaped error
    directing a new Refresh; there is no partial admission.

    ``opens_staging_window=True`` seals additional evidence into a case that
    already has a committed sealed set (D2): the REQUESTED phase opens the bounded
    staging window described in the module docstring.

    NOT IMPLEMENTED in CP1 — CP2A implements the orchestration over the frozen
    RPCs. The signature, phases, and D2 contract are frozen here.
    """
    raise NotImplementedError("CP2A implements the Add and Seal orchestration")


def retry_seal(
    *,
    session: OperatorSession,
    case_id: str,
    idempotency_key: str,
    password: str,
    reason: str,
) -> SealResult:
    """Resume an interrupted Seal under the SAME idempotency key (SPEC §4).

    Fresh reauthorization authorizes continuation; a COMMITTED operation replays
    its recorded result. Produces exactly one object/version/manifest/event set.

    NOT IMPLEMENTED in CP1 — CP2A implements resume over ``custody_seal_commit``'s
    optional resume reauthorization. The signature is frozen here.
    """
    raise NotImplementedError("CP2A implements Seal resume")


def seal_status(*, case_id: str, dsn: str | None) -> SealStatus:
    """Return the path-free blocked-gate + incomplete-operation status.

    NOT IMPLEMENTED in CP1 — CP2A implements the read over the computed gate +
    ``custody_seal_operations``. The path-free contract is frozen here.
    """
    raise NotImplementedError("CP2A implements seal status")
