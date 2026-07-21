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

import hashlib
import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# The custody actions that carry a reauth binding (SPEC §Reauthentication).
CustodyAction = str  # one of: ADD_SEAL | IGNORE | RETIRE | REPROTECT | ANCHOR

# --- Identity-authority verifier seam (Option 1, operator-approved 2026-07-20) ---
# The injected operator-password verifier. MODULE-LEVEL, underscore == NOT public
# API, so it never inflates the frozen ≤6 public-interface census (§12). Contract:
# a callable ``(email, password, expected_auth_user_id) -> None`` that RE-VERIFIES
# the operator password against the identity authority and RAISES on ANY failure
# (mirroring ``SupabaseAuth.reverify_password``'s fail-closed contract); it returns
# on success and MUST NOT return a truthy/falsy verdict that could be ignored.
#
# ROOT wires the concrete synchronous-bridge-over-async(reverify_password) into
# this global during CP3 gateway integration (server startup); CP2A never edits
# gateway startup. Tests assign ``reauth._VERIFIER`` directly to a fake.
#
# FAIL-CLOSED ABSOLUTE: an UNSET verifier means the identity authority is
# unreachable from this process, so every reauth path raises
# ``ReauthError('reauth_unavailable')`` and records NOTHING. A missing verifier
# MUST NEVER degrade to "skip verification".
_OperatorPasswordVerifier = Callable[..., None]
_VERIFIER: _OperatorPasswordVerifier | None = None

# Short action label -> audit ``event_type`` suffix. ADD_SEAL MUST map to
# ``evidence_seal`` because ``app.custody_seal_begin`` verifies the consumed reauth
# event has exactly ``event_type = 'reauth.evidence_seal'``. The DB-only action
# RPCs do not gate on event_type, but distinct types keep the audit chain honest
# and keep the reauth-idempotency index (which includes event_type) from colliding.
_ACTION_EVENT: dict[str, str] = {
    "ADD_SEAL": "evidence_seal",
    "IGNORE": "evidence_ignore",
    "RETIRE": "evidence_retire",
    "REPROTECT": "evidence_reprotect",
    "ANCHOR": "custody_anchor",
}


class ReauthError(Exception):
    """A fail-closed custody re-authentication failure.

    Carries a stable machine-readable ``reason`` (mapped to a shaped operator code
    by the thin CP2B route — EC-3) and an ``http_status``. It is an error signal,
    not part of the frozen ≤6 callable/data interface the parallel lanes build
    against; the route boundary shapes it by duck-typing ``.reason``. Raw database
    diagnostics never travel on it.
    """

    def __init__(self, reason: str, *, http_status: int = 403) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status

# One batch-reauth request target: (action, case-relative target). A single D4
# Resolve batch is HETEROGENEOUS — it mixes verbs across targets.
BatchTarget = tuple[CustodyAction, str]
# One recorded per-target authorization in a batch: (action, target, reauth_id).
# reauth_id is the single-target reauth audit event that authorizes `action` on
# `target`; it is what the honest verb consumes.
BatchReauthEntry = tuple[CustodyAction, str, str]


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
    """One password verification covering a HETEROGENEOUS batch (D4 receipt).

    FROZEN. The unified Portal Resolve flow verifies the operator password ONCE
    (with one batch ``reason``, per the uniform reauth model) and this value is
    the pre-authorized batch receipt the domain verbs consume. A batch mixes verbs
    across targets — new files (Ignore / Add and Seal), deleted sealed objects
    (Retire), changed sealed objects (Retire) — so the authorization is per
    target, not batch-wide.

    ``entries`` is one :data:`BatchReauthEntry` ``(action, target, reauth_id)``
    per target. Because each custody RPC (``custody_ignore`` / ``custody_retire``
    / ``custody_reprotect``) independently recomputes and compares its own
    SINGLE-target binding, one password yields N per-target reauth audit events —
    each with a distinct ``idempotency_key`` derived from ``batch_key`` so the
    reauth-idempotency unique index never collides and no cross-target replay is
    possible. ``entries[i][2]`` is the reauth event the honest verb for
    ``entries[i][0]`` acting on ``entries[i][1]`` consumes.

    This carries the per-target authorizations the verbs consume — NOT a shared
    password or any reauthentication secret.
    """

    batch_key: str
    case_id: str
    reason: str
    entries: tuple[BatchReauthEntry, ...]


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


# ---------------------------------------------------------------------------
# Shared plumbing — the ONE home for DSN resolution, identity-authority
# verification, and the SQL-authoritative reauth audit write. seal.py / actions.py
# import the private helpers they need (``_dsn`` / ``_batch_target_key`` /
# ``_record_resume_reauth``) rather than re-implementing them, so the EC-6 rule
# (writer == the single SQL builder) is enforced from one place.
# ---------------------------------------------------------------------------
def _dsn() -> str:
    """Resolve the control-plane DSN, fail-closed.

    The frozen mutation signatures do not take a ``dsn`` (unlike CP2B's ledger
    functions and :func:`seal_status`), so the custody mutation layer resolves it
    from the same ``SIFT_CONTROL_PLANE_DSN`` the Gateway and the composed tests
    use (``token_registry.CONTROL_PLANE_DSN_ENV``). Absent DSN == the authority is
    unreachable -> fail closed.
    """
    dsn = (os.environ.get("SIFT_CONTROL_PLANE_DSN") or "").strip()
    if not dsn:
        raise ReauthError("reauth_unavailable", http_status=503)
    return dsn


def _batch_target_key(batch_key: str, action: str, target: str) -> str:
    """Derive the distinct per-target idempotency key for a D4 batch target.

    Deterministic and language-independent from ``(batch_key, action, target)`` so
    BOTH the reauth writer (:func:`record_batch_reauth`) and the honest verb that
    later consumes it (``actions._ignore`` / ``_retire`` / ``_reprotect``, which
    must pass the SAME key to their RPC as ``p_idempotency_key``) compute the
    identical key without threading it through the frozen 3-tuple
    :data:`BatchReauthEntry`. Distinct per target -> the reauth-idempotency unique
    index never collides across a heterogeneous batch; stable across a resubmitted
    batch (same ``batch_key``) -> the action receipts replay idempotently. Bounded
    to 66 chars (<= the 128 the schema requires).
    """
    digest = hashlib.sha256(
        f"{batch_key}\x00{action}\x00{target}".encode()
    ).hexdigest()
    return "b:" + digest


def _resolve_operator(cur: Any, actor_user_id: str) -> tuple[str, str | None]:
    """Return ``(email, auth_user_id)`` for the actor, fail-closed if absent.

    The identity authority verifies by the operator's OWN email (never a
    request-body email — mirrors the portal ``_supabase_reverify`` contract), so
    the email is sourced from ``app.operator_profiles`` by the session's stable
    ``actor_user_id``. A session whose operator carries no email fails re-auth
    closed (SPEC §Reauthentication; the as-built portal returns 401 here).
    """
    cur.execute(
        "select email::text, auth_user_id::text from app.operator_profiles where id = %s",
        (actor_user_id,),
    )
    row = cur.fetchone()
    if not row or not row[0]:
        raise ReauthError("reauth_unavailable", http_status=401)
    return str(row[0]), (str(row[1]) if row[1] else None)


def _run_verifier(email: str, password: str, auth_user_id: str | None) -> None:
    """Invoke the injected identity-authority verifier, fail-closed.

    FAIL-CLOSED ABSOLUTE: an unset verifier (:data:`_VERIFIER` is ``None``) raises
    ``reauth_unavailable`` and the caller records NOTHING. The verifier RAISES on a
    wrong password / unknown user / control-plane error; any such raise is mapped
    to a shaped ``reauth_failed`` denial (the route never leaks which). Only a
    clean return authorizes the audit write.
    """
    verifier = _VERIFIER
    if verifier is None:
        raise ReauthError("reauth_unavailable", http_status=503)
    try:
        verifier(email=email, password=password, expected_auth_user_id=auth_user_id)
    except ReauthError:
        raise
    except Exception as exc:  # any verifier failure == deny, record nothing.
        logger.warning("custody reauth verification denied: %s", type(exc).__name__)
        raise ReauthError("reauth_failed", http_status=401) from exc


def _insert_reauth_event(
    cur: Any,
    *,
    session: OperatorSession,
    action: str,
    case_id: str,
    examiner: str,
    idempotency_key: str,
    reason: str,
    targets: Sequence[str],
) -> str:
    """Persist ONE bound ``portal_reauth`` audit event and return its id.

    EC-6: the persisted ``details.binding`` is produced by the single SQL builder
    ``app.custody_reauth_binding`` INSIDE the INSERT, so Python never constructs
    the persisted binding — writer and every custody-RPC verifier are byte-
    identical by construction. Idempotent under the reauth-idempotency index:
    re-recording the same ``(case, event_type, actor, idempotency_key)`` returns
    the existing event when its binding/action/examiner match, and raises
    ``idempotency_key_reused`` when they differ (SPEC §4 resume-safety).
    """
    event_type = f"reauth.{_ACTION_EVENT.get(action, action.lower())}"
    from psycopg.types.json import Jsonb

    targets_json = Jsonb(list(targets))
    # Serialize concurrent same-key reauth writers per (case, event_type, actor,
    # key) so the SELECT-then-INSERT idempotency check cannot race.
    cur.execute(
        "select pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"{case_id}|{event_type}|{session.actor_user_id}|{idempotency_key}",),
    )
    cur.execute(
        """
        select id::text,
               (details->'binding'
                  is distinct from app.custody_reauth_binding(%s, %s, %s)
                or details->>'action' is distinct from %s
                or details->>'examiner' is distinct from %s) as differs
        from app.audit_events
        where case_id = %s and event_type = %s and source = 'portal_reauth'
          and actor_type = 'user'
          and actor_user_id is not distinct from %s
          and details->'binding'->>'idempotency_key' = %s
        order by created_at desc limit 1
        """,
        (
            idempotency_key, reason, targets_json,
            _ACTION_EVENT.get(action, action.lower()), examiner,
            case_id, event_type, session.actor_user_id, idempotency_key,
        ),
    )
    existing = cur.fetchone()
    if existing:
        if existing[1]:
            raise ReauthError("idempotency_key_reused", http_status=409)
        return str(existing[0])

    cur.execute(
        """
        insert into app.audit_events
          (case_id, event_type, actor_type, actor_user_id, source, status,
           summary, details)
        values (%s, %s, 'user', %s, 'portal_reauth', 'success', %s,
                jsonb_build_object(
                  'action', %s::text,
                  'examiner', %s::text,
                  'binding', app.custody_reauth_binding(%s, %s, %s)))
        returning id::text
        """,
        (
            case_id, event_type, session.actor_user_id,
            f"operator re-auth for {_ACTION_EVENT.get(action, action.lower())}",
            _ACTION_EVENT.get(action, action.lower()), examiner,
            idempotency_key, reason, targets_json,
        ),
    )
    row = cur.fetchone()
    if not row or not row[0]:
        raise ReauthError("reauth_unavailable", http_status=503)
    return str(row[0])


def _record_resume_reauth(
    *, session: OperatorSession, case_id: str, operation_id: str, password: str
) -> str:
    """Verify the password and record a seal RESUME reauth (binding {operation_id}).

    The resume / staging-window-close authorization consumed by
    ``app.custody_seal_commit`` (``event_type = 'reauth.evidence_seal_resume'``,
    ``details.binding = {'operation_id': <op>}``). Its binding is intentionally NOT
    the canonical targets binding — it authorizes CONTINUATION of a specific
    operation, not a target set (SPEC §4; there is no separate resume credential).
    Fail-closed: verification runs before any write; a failure records nothing.
    """
    import psycopg

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        email, auth_user_id = _resolve_operator(cur, session.actor_user_id)
        conn.rollback()  # end the read txn; nothing is persisted before verify.
        _run_verifier(email, password, auth_user_id)
        cur.execute(
            """
            insert into app.audit_events
              (case_id, event_type, actor_type, actor_user_id, source, status,
               summary, details)
            values (%s, 'reauth.evidence_seal_resume', 'user', %s,
                    'portal_reauth', 'success', %s,
                    jsonb_build_object(
                      'action', 'evidence_seal_resume', 'examiner', %s::text,
                      'binding', jsonb_build_object('operation_id', %s::text)))
            returning id::text
            """,
            (
                case_id, session.actor_user_id,
                "operator re-auth for evidence_seal_resume", email,
                str(operation_id),
            ),
        )
        row = cur.fetchone()
        conn.commit()
    if not row or not row[0]:
        raise ReauthError("reauth_unavailable", http_status=503)
    return str(row[0])


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
    import psycopg

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        email, auth_user_id = _resolve_operator(cur, session.actor_user_id)
        conn.rollback()  # end the read txn; nothing is persisted before verify.
        _run_verifier(email, password, auth_user_id)  # fail-closed; raises on deny.
        event_id = _insert_reauth_event(
            cur,
            session=session,
            action=action,
            case_id=case_id,
            examiner=email,
            idempotency_key=binding.idempotency_key,
            reason=binding.reason,
            targets=binding.targets,
        )
        conn.commit()
    return event_id


def record_batch_reauth(
    *,
    session: OperatorSession,
    password: str,
    case_id: str,
    reason: str,
    targets: Sequence[BatchTarget],
    batch_key: str,
) -> BatchReauth:
    """Verify the password ONCE and record N per-target reauth events (D4).

    The single seam behind the unified Resolve flow's "one password + one reason
    covers a heterogeneous batch of N targets". Verifies ``password`` a single
    time against the identity authority, then for each ``(action, target)`` in
    ``targets`` records one single-target reauth audit event — each with a
    distinct ``idempotency_key`` derived from ``batch_key`` (so the reauth-
    idempotency unique index never collides) and its own single-target SQL binding
    — and returns the :class:`BatchReauth` receipt (one
    :data:`BatchReauthEntry` per target) the domain verbs consume. Fail-closed: a
    failed verification records nothing and authorizes no verb.

    NOT IMPLEMENTED in CP1 — CP2A implements it over :func:`record_reauth`. The
    signature and the one-password / per-target-heterogeneous-event contract are
    frozen here.
    """
    import psycopg

    if not targets:
        raise ReauthError("invalid_request", http_status=400)

    with psycopg.connect(_dsn()) as conn, conn.cursor() as cur:
        email, auth_user_id = _resolve_operator(cur, session.actor_user_id)
        conn.rollback()  # end the read txn; nothing is persisted before verify.
        # ONE password verification covers the whole heterogeneous batch.
        _run_verifier(email, password, auth_user_id)
        entries: list[BatchReauthEntry] = []
        for action, target in targets:
            per_target_key = _batch_target_key(batch_key, action, target)
            reauth_id = _insert_reauth_event(
                cur,
                session=session,
                action=action,
                case_id=case_id,
                examiner=email,
                idempotency_key=per_target_key,
                reason=reason,
                targets=[target],
            )
            entries.append((action, target, reauth_id))
        # All N per-target reauth events commit together; any failure rolls the
        # whole batch back so a partially-authorized batch is never recorded.
        conn.commit()

    return BatchReauth(
        batch_key=batch_key,
        case_id=case_id,
        reason=reason,
        entries=tuple(entries),
    )
