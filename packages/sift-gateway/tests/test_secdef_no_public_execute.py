"""SEC-13 — guard: no ``app`` SECURITY DEFINER function carries PUBLIC EXECUTE.

Migration ``202606242200_revoke_public_execute_secdef.sql`` (commit 05e9782)
revokes the PostgreSQL default ``PUBLIC EXECUTE`` from every ``app`` SECURITY
DEFINER function and re-grants only ``service_role``. That closed the
``app.evidence_unseal`` exposure (DSS-CAN-013 / W1-S1, CWE-732/266) — but the
revoke alone is INERT against a *future* SECDEF function that re-acquires the
default grant. A freshly ``CREATE``d function has ``proacl IS NULL``, which means
PUBLIC holds EXECUTE by default; that is exactly how ``evidence_unseal`` slipped
past the earlier ``202606141400`` sweep.

This is that missing guard. It is a LIVE-DB invariant test: it queries
``pg_proc`` for every SECURITY DEFINER function in schema ``app`` and asserts
PUBLIC cannot EXECUTE it. ``has_function_privilege('public', oid, 'EXECUTE')``
resolves the role via Postgres' ``get_role_oid_or_public`` (so ``'public'`` is the
PUBLIC pseudo-role) and folds in the NULL-proacl default-grant case, so it fails
on both an explicit and a defaulted PUBLIC EXECUTE — catching the recurrence
class, not just today's functions.

Gating (mirrors the repo's DSN/psycopg idiom, e.g.
``test_k4_host_identity_authority.py``'s ``pytest.importorskip("psycopg")`` and
the ``SIFT_CONTROL_PLANE_DSN`` env used across the gateway): the test SKIPS
cleanly when psycopg is unavailable or no control-plane DSN is configured (CI has
no live DB). With a control-plane DSN present it runs against the real schema and
must PASS, since 202606242200 revoked PUBLIC. The DSN is read from the
environment only — never hardcoded, never echoed into skip/assert output.
"""

from __future__ import annotations

import os

import pytest

# Source-of-truth env-var name for the control-plane DSN (fall back to the
# literal if the gateway package can't be imported for any reason).
try:
    from sift_gateway.token_registry import CONTROL_PLANE_DSN_ENV
except Exception:  # pragma: no cover - defensive: keep the test self-contained
    CONTROL_PLANE_DSN_ENV = "SIFT_CONTROL_PLANE_DSN"


# Every SECURITY DEFINER function in schema ``app``, with the two privilege
# facts we care about. No untrusted input is interpolated — the role names are
# fixed SQL literals and there are no bind parameters (static, read-only query).
_SECDEF_PRIVILEGE_SQL = """
    select
        p.oid::regprocedure::text                                  as fn_sig,
        has_function_privilege('public', p.oid, 'EXECUTE')         as public_can_execute,
        case
            when exists (select 1 from pg_roles where rolname = 'service_role')
                then has_function_privilege('service_role', p.oid, 'EXECUTE')
            else null
        end                                                        as service_role_can_execute
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'app'
      and p.prosecdef = true
    order by fn_sig
"""


def _control_plane_dsn() -> str:
    """Return the configured control-plane DSN, or skip the test if absent.

    Skips (does not error) when unset, so CI — which has no live DB — passes
    cleanly. The DSN value itself is never surfaced in the skip reason.
    """
    dsn = os.environ.get(CONTROL_PLANE_DSN_ENV, "").strip()
    if not dsn:
        pytest.skip(
            f"no control-plane DSN configured ({CONTROL_PLANE_DSN_ENV} unset) — "
            "SECDEF PUBLIC-EXECUTE guard requires a live control-plane database"
        )
    return dsn


def test_no_app_secdef_function_has_public_execute():
    """No ``app`` SECURITY DEFINER function may be EXECUTE-able by PUBLIC.

    Any future SECDEF function that re-acquires the default ``PUBLIC EXECUTE``
    (the way ``app.evidence_unseal`` once did) fails this test, naming itself.
    """
    psycopg = pytest.importorskip("psycopg")
    dsn = _control_plane_dsn()

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(_SECDEF_PRIVILEGE_SQL)
            rows = cur.fetchall()

    # A zero-row result means the control-plane schema isn't applied on this DB
    # (no ``app`` SECDEF functions at all). Treat that as "can't run the guard
    # here" rather than a misleading vacuous pass.
    if not rows:
        pytest.skip(
            "no app SECURITY DEFINER functions found — control-plane schema "
            "not applied on the connected database; cannot evaluate the guard"
        )

    public_executable = [
        fn_sig for (fn_sig, public_can_execute, _svc) in rows if public_can_execute
    ]
    assert not public_executable, (
        "app SECURITY DEFINER function(s) are EXECUTE-able by PUBLIC — the "
        "default PUBLIC EXECUTE was not revoked (see migration "
        "202606242200_revoke_public_execute_secdef.sql). Offenders: "
        + ", ".join(public_executable)
    )


def test_app_secdef_functions_grant_execute_to_service_role():
    """Companion over-revoke guard: each ``app`` SECDEF function must still grant
    EXECUTE to ``service_role`` (the legitimate privileged caller the migration
    preserves) — catching a sweep that revoked PUBLIC *and* the intended grantee.

    Only enforced where ``service_role`` exists (it is absent on a non-Supabase
    Postgres; there the query returns NULL and nothing is asserted).
    """
    psycopg = pytest.importorskip("psycopg")
    dsn = _control_plane_dsn()

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(_SECDEF_PRIVILEGE_SQL)
            rows = cur.fetchall()

    if not rows:
        pytest.skip(
            "no app SECURITY DEFINER functions found — control-plane schema "
            "not applied on the connected database; cannot evaluate the guard"
        )

    # service_role_can_execute is None when the role doesn't exist — skip the
    # over-revoke assertion entirely on a non-Supabase Postgres.
    if all(svc is None for (_sig, _pub, svc) in rows):
        pytest.skip("service_role not present on this database — over-revoke guard N/A")

    missing_service_role = [
        fn_sig
        for (fn_sig, _pub, service_role_can_execute) in rows
        if service_role_can_execute is False
    ]
    assert not missing_service_role, (
        "app SECURITY DEFINER function(s) do NOT grant EXECUTE to service_role "
        "(over-revoke — the legitimate privileged caller lost access). "
        "Offenders: " + ", ".join(missing_service_role)
    )
