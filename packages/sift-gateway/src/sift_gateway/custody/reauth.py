"""Uniform custody re-authentication and the ONE canonical binding builder.

FROZEN INTERFACE (P4.23 CP1, 2026-07-20). CP2A implements the password
verification + audit recording; the binding builder below is implemented here and
MUST NOT be re-derived anywhere else.

Every retained operator custody mutation uses one server-side model
(SPEC §Reauthentication and Idempotency):

    active Portal session + current password + reason + idempotency key + target

The Gateway re-verifies the password with the identity authority and binds the
resulting audit record to the actor, case, action, target, and idempotency key.

**EC-6 — the single binding source.** The audit binding is built by exactly ONE
builder — :func:`build_binding` — as a canonical form whose target array is
ordered by RAW BYTE ORDER. Python's ``sorted()`` orders ``str`` by Unicode code
point, and UTF-8 is byte-order-preserving, so ``sorted(targets)`` is byte-for-byte
identical to the SQL ``app.custody_reauth_binding`` builder's
``ORDER BY x COLLATE "C"``. Verification compares the STORED binding against that
single canonical form; no component may re-derive the ordering under a locale
default or database collation. The as-built engine sorted in Python (code point)
and verified in SQL (locale collation), which denied every mixed-case multi-file
seal. **The mixed-case multi-file target set is the permanent regression
fixture.**
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# Placeholder for the authenticated operator session. IP1 (identity/pairing.py)
# replaces this alias with the real session type; the frozen custody signatures
# below depend only on the name, not its shape.
type OperatorSession = Any

# The custody actions that carry a reauth binding (SPEC §Reauthentication).
CustodyAction = str  # one of: ADD_SEAL | IGNORE | RETIRE | REPROTECT | ANCHOR


@dataclass(frozen=True, slots=True)
class ReauthBinding:
    """The canonical audit binding for one re-authenticated custody mutation.

    Immutable value object. ``targets`` is stored already in canonical byte order.
    :meth:`as_dict` yields the exact mapping the Gateway persists as the reauth
    audit event's ``details.binding`` (stored as jsonb, whose object-key order is
    normalized by PostgreSQL — only the target ARRAY order is significant, and it
    matches ``app.custody_reauth_binding``).
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


def build_binding(
    idempotency_key: str, reason: str, targets: Sequence[str]
) -> ReauthBinding:
    """Build THE canonical reauth binding (the single source of truth — EC-6).

    Targets are ordered by ``sorted()`` (Unicode code point == UTF-8 byte order ==
    SQL ``COLLATE "C"``). ``reason`` is stripped to match the SQL ``btrim``. The
    result is byte-for-byte equivalent to ``app.custody_reauth_binding`` so a
    Python writer and a SQL verifier can never disagree. Do NOT construct a binding
    any other way.
    """
    return ReauthBinding(
        idempotency_key=idempotency_key,
        reason=reason.strip(),
        targets=tuple(sorted(str(t) for t in targets)),
    )


def bindings_match(stored: dict[str, Any], expected: ReauthBinding) -> bool:
    """Compare a stored binding against the single canonical form, verbatim.

    Used only where a Python-side pre-check is useful; the authoritative
    comparison is the ``IS DISTINCT FROM`` check inside the custody RPCs against
    ``app.custody_reauth_binding``.
    """
    return stored == expected.as_dict()


def record_reauth(
    *,
    session: OperatorSession,
    password: str,
    action: CustodyAction,
    case_id: str,
    binding: ReauthBinding,
) -> str:
    """Re-verify the operator password and record the bound reauth audit event.

    Returns the reauth audit event id the custody RPCs consume. Fail-closed: a
    failed verification raises and records nothing that authorizes a mutation.

    NOT IMPLEMENTED in CP1 — CP2A implements the identity-authority verification
    and the ``portal_reauth`` audit write. The signature and the ``binding``
    contract are frozen here.
    """
    raise NotImplementedError("CP2A implements custody re-authentication recording")
