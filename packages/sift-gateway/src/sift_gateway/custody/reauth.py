"""Uniform custody re-authentication and the ONE canonical binding builder.

FROZEN INTERFACE (P4.23 CP1, re-frozen 2026-07-20 repair round 1). CP2A
implements the password verification + audit recording; the binding builder here
is a NON-AUTHORITATIVE mirror (see EC-6 below) and the SQL builder is the single
source of the persisted binding.

Every retained operator custody mutation uses one server-side model
(SPEC §Reauthentication and Idempotency):

    active Portal session + current password + reason + idempotency key + target

The Gateway re-verifies the password with the identity authority and binds the
resulting audit record to the actor, case, action, target, and idempotency key.

**EC-6 — single-source binding (re-frozen).** The persisted reauth binding is
split into two enforced parts, and NEITHER side re-derives the other under a
different language/locale/collation default:

  1. ``{idempotency_key, reason, targets}`` is the canonical JSON binding. It is
     produced by exactly ONE builder — the SQL function
     ``app.custody_reauth_binding`` — whose target array is ordered by RAW BYTE
     ORDER (``COLLATE "C"``). :func:`record_reauth` MUST persist the value
     returned by that SQL function into the reauth audit event's
     ``details.binding`` (SQL-authoritative), and every custody RPC re-derives
     the SAME SQL builder and compares ``details->'binding' IS DISTINCT FROM``
     it verbatim. Writer and verifier are therefore byte-identical by
     construction. :func:`build_binding` below is a Python MIRROR of that SQL
     form for local pre-checks/tests only; it is NEVER the persisted authority.
  2. ``{actor, case, action}`` is bound by SCALAR EQUALITY inside each custody
     RPC against the audit-event columns (``actor_user_id``, ``case_id``,
     ``event_type``) — see ``supabase/migrations/202607132200_custody_rpcs.sql``.
     They are deliberately NOT inside the JSON binding, so they cannot drift
     across a language/collation boundary either.

  Target normalization is fixed on both sides: case-relative POSIX display paths
  exactly as produced by the read-only scanner (``evidence/<name>``), NO unicode
  normalization (raw UTF-8 code points), ordered by code point == ``COLLATE "C"``.
  The as-built engine sorted in Python (code point) and verified in SQL (locale
  collation), which denied every mixed-case multi-file seal. **The mixed-case
  multi-file target set is the permanent regression fixture, and it must fail if
  either side's sort/normalization discipline changes.**
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

# The custody actions that carry a reauth binding (SPEC §Reauthentication).
CustodyAction = str  # one of: ADD_SEAL | IGNORE | RETIRE | REPROTECT | ANCHOR


@runtime_checkable
class OperatorSession(Protocol):
    """Minimal authenticated-operator session bound by custody audit rows.

    FROZEN, **IP1-extensible**. This is the smallest session shape the custody
    module set depends on — the stable operator identity plus the runtime Portal
    session id that the reauth audit rows bind. IP1's ``identity/pairing.py``
    EXTENDS this Protocol with the full session type (device, expiry, pairing,
    etc.); because every frozen custody signature below depends ONLY on these two
    members, IP1's additions cannot break CP2A/CP2B code. Do not widen it here.

    * ``actor_user_id`` — the stable operator identity: ``app.operator_profiles.id``
      (the ``actor_user_id`` the custody RPCs bind and compare by scalar equality).
    * ``session_id`` — the runtime Portal session id proving the reauth happened
      inside a live authenticated session (never persisted as authority material).
    """

    @property
    def actor_user_id(self) -> str: ...

    @property
    def session_id(self) -> str: ...


@dataclass(frozen=True, slots=True)
class ReauthBinding:
    """A NON-AUTHORITATIVE mirror of the canonical reauth binding (EC-6).

    Immutable value object for local pre-checks/tests. ``targets`` is stored
    already in canonical byte order. :meth:`as_dict` mirrors the SQL
    ``app.custody_reauth_binding`` shape, but the PERSISTED authority is always
    the value returned by that SQL function (see the module docstring); this
    class is never written to ``details.binding`` verbatim by an authoritative
    path.
    """

    idempotency_key: str
    reason: str
    targets: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "reason": self.reason,
            "targets": list(self.targets),
        }


@dataclass(frozen=True, slots=True)
class BatchReauth:
    """One password verification covering N targets (D4 — the batch receipt).

    FROZEN. The unified Portal Resolve flow verifies the operator password ONCE
    and this value is the pre-authorized batch receipt the domain verbs consume.
    Because each custody RPC (``custody_ignore``/``custody_retire``/
    ``custody_reprotect``) verifies a SINGLE-target binding, one password yields
    N per-target reauth audit events (one per target, each a distinct
    ``idempotency_key`` derived from ``batch_key`` so the reauth-idempotency
    unique index never collides). ``reauth_ids[i]`` is the audit event id that
    authorizes the verb acting on ``targets[i]``; ``batch_key`` correlates them.

    This carries the target ARRAY (SPEC §Drift, batch reauthentication) and the
    per-target authorizations the verbs consume — NOT a shared password or any
    reauthentication secret.
    """

    batch_key: str
    case_id: str
    action: CustodyAction
    targets: tuple[str, ...]
    reauth_ids: tuple[str, ...]


def build_binding(
    idempotency_key: str, reason: str, targets: Sequence[str]
) -> ReauthBinding:
    """Build the Python MIRROR of the canonical reauth binding (EC-6).

    Targets are ordered by ``sorted()`` (Unicode code point == UTF-8 byte order
    == SQL ``COLLATE "C"``); ``reason`` is stripped to match the SQL ``btrim``.
    The result mirrors ``app.custody_reauth_binding`` byte-for-byte so a local
    pre-check/test can compare against the SQL-persisted authority — but the
    PERSISTED binding is always produced by the SQL builder, never this value.
    Do NOT construct a binding for persistence any other way.
    """
    return ReauthBinding(
        idempotency_key=idempotency_key,
        reason=reason.strip(),
        targets=tuple(sorted(str(t) for t in targets)),
    )


def record_reauth(
    *,
    session: OperatorSession,
    password: str,
    action: CustodyAction,
    case_id: str,
    binding: ReauthBinding,
) -> str:
    """Re-verify the operator password and record ONE bound reauth audit event.

    Returns the reauth audit event id the custody RPCs consume. The persisted
    ``details.binding`` MUST be the value returned by the SQL
    ``app.custody_reauth_binding(binding.idempotency_key, binding.reason,
    list(binding.targets))`` called in the SAME transaction — so writer and
    verifier are the single SQL builder (EC-6); the ``binding`` argument supplies
    only the inputs. Actor/case/action are bound by the RPC's scalar-equality
    comparison, not the JSON. Fail-closed: a failed verification raises and
    records nothing that authorizes a mutation.

    NOT IMPLEMENTED in CP1 — CP2A implements the identity-authority verification
    and the ``portal_reauth`` audit write. The signature and the SQL-authoritative
    binding contract are frozen here.
    """
    raise NotImplementedError("CP2A implements custody re-authentication recording")


def record_batch_reauth(
    *,
    session: OperatorSession,
    password: str,
    action: CustodyAction,
    case_id: str,
    targets: Sequence[str],
    batch_key: str,
) -> BatchReauth:
    """Verify the password ONCE and record N per-target reauth events (D4).

    The single seam behind the unified Resolve flow's "one password covers N
    selected targets". Verifies ``password`` a single time against the identity
    authority, then records one single-target reauth audit event per target —
    each with a distinct ``idempotency_key`` derived from ``batch_key`` (so the
    reauth-idempotency unique index never collides) and a single-target SQL
    binding — and returns the :class:`BatchReauth` receipt the domain verbs
    consume. Fail-closed: a failed verification records nothing and authorizes no
    verb.

    NOT IMPLEMENTED in CP1 — CP2A implements it over :func:`record_reauth`. The
    signature and the one-password/N-per-target-event contract are frozen here.
    """
    raise NotImplementedError("CP2A implements batch custody re-authentication")
