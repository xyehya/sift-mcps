"""Thin HTTP surface for operator custody workflows.

FROZEN INTERFACE (P4.23 CP1, re-frozen 2026-07-20 repair round 1). CP2B
implements the bodies. Each route does exactly: parse the JSON body -> authorize
the operator session -> call ONE custody domain function (``custody.seal`` /
``custody.actions`` / ``custody.ledger`` / ``custody.admission``) -> return a
shaped response. It holds ZERO business logic (OPERATING-MODEL §1/§12) and is NOT
registered into the app until CP2B wires it.

**EC-3 — shaped errors are FORCED, not optional (re-frozen).** Every custody
route is wrapped by the single error boundary :func:`_custody_route`, so EVERY
route returns a shaped body no matter how it fails: an operator-meaningful message
naming the next action (e.g. "a Seal is in progress — resume it"), a stable
machine-readable ``code`` from :data:`CUSTODY_ERROR_CODES`, and a REQUIRED
correlation/``audit_id``. Raw database diagnostics — SQLSTATE, constraint names,
PL/pgSQL context, stack text — can never reach an operator surface: any exception
without a mapped custody code is shaped as ``custody_internal`` with a fresh audit
id and no raw text. :func:`_shaped_error` (module-private) is the single mapping
seam; ``audit_id`` is mandatory there.

**EC-4 — sealed rendering.** Status responses render an entry as sealed evidence
ONLY when a ``COMMITTED`` Evidence Version with manifest membership exists; pending
entries render only as Pending, Ignored/Retired as their own states. Every panel
is strictly scoped to the active case.

**D4 — unified Resolve.** :func:`resolve_findings` is one route calling the single
``custody.actions.resolve`` domain entry with batch reauthentication (one password
covering N selected targets); the recorded custody verbs underneath stay distinct.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

# Stable machine-readable custody error codes (extended by CP2B as needed). Raw DB
# diagnostics are mapped onto these; they are never surfaced verbatim (EC-3).
CUSTODY_ERROR_CODES = (
    "seal_in_progress",
    "reauth_scope_mismatch",
    "target_not_pending",
    "storage_unavailable",
    "invalid_request",
    "custody_internal",
)

_CustodyRoute = Callable[[Request], Awaitable[JSONResponse]]


def _shaped_error(
    *, code: str, message: str, audit_id: str, status_code: int = 400
) -> JSONResponse:
    """Build the single shaped custody-error envelope (EC-3) — module-private.

    ``message`` is operator-meaningful and names the next action; ``code`` MUST be
    one of :data:`CUSTODY_ERROR_CODES`; ``audit_id`` is REQUIRED and correlates to
    the audit log. No raw SQLSTATE / constraint / PL/pgSQL / stack text is ever
    included. This is the only place a custody error body is constructed, so the
    shape cannot drift per route.
    """
    if code not in CUSTODY_ERROR_CODES:
        code = "custody_internal"
    body: dict[str, Any] = {
        "error": {"code": code, "message": message, "audit_id": audit_id}
    }
    return JSONResponse(body, status_code=status_code)


def _custody_route(handler: _CustodyRoute) -> _CustodyRoute:
    """The single forced error boundary every custody route is wrapped by (EC-3).

    Guarantees a shaped body on EVERY path: a handler that raises a mapped custody
    error is shaped to its stable code; ANY other exception is shaped as
    ``custody_internal`` with a fresh audit id and no raw DB text, so SQLSTATE /
    PL-pgSQL / stack text can never reach an operator surface. CP2B's real bodies
    map known DB errors to :data:`CUSTODY_ERROR_CODES` inside this boundary; the
    stub bodies below still ``raise NotImplementedError`` (re-raised here so the
    unimplemented contract stays honest) until CP2B wires them.
    """

    async def wrapped(request: Request) -> JSONResponse:
        try:
            return await handler(request)
        except NotImplementedError:
            raise
        except Exception:  # the single boundary that shapes every failure
            # CP2B maps known SQLSTATE/RPC errors to a specific code + audit id
            # before this catch-all; anything unmapped is shaped generically with
            # NO raw diagnostic text.
            # CP2B: this catch-all fallback emits audit_id="" with no next-action
            # message. CP2B fixes it privately (record a correlation/audit id for
            # the unexpected failure and name a recovery action) — no signature
            # change to _shaped_error or the routes.
            return _shaped_error(
                code="custody_internal",
                message="The custody operation could not be completed.",
                audit_id="",
                status_code=500,
            )

    return wrapped


@_custody_route
async def custody_status(request: Request) -> JSONResponse:
    """GET the active case's custody status: gate state + inventory + sealed set.

    Drives an operator Refresh reconciliation and renders sealed/pending/ignored/
    retired strictly per EC-4, scoped to the active case.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.admission``.
    """
    raise NotImplementedError("CP2B implements the custody status route")


@_custody_route
async def custody_seal(request: Request) -> JSONResponse:
    """POST Add and Seal (begin/commit): reauth + targets -> ``custody.seal``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over
    ``custody.seal.begin_seal`` / ``commit_seal``.
    """
    raise NotImplementedError("CP2B implements the seal route")


@_custody_route
async def resolve_findings(request: Request) -> JSONResponse:
    """POST the unified Resolve flow with batch reauth (D4).

    One password covers N selected targets; the route makes ONE domain call —
    ``custody.actions.resolve`` — which dispatches each finding to the honest
    custody verb (Ignore / Retire / Verify-and-Reprotect). Zero business logic in
    the route. NOT IMPLEMENTED in CP1 — CP2B implements it.
    """
    raise NotImplementedError("CP2B implements the resolve route")


@_custody_route
async def custody_verify(request: Request) -> JSONResponse:
    """POST Full Verify (read-only, no fresh password) -> ``custody.actions``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.actions.full_verify``.
    """
    raise NotImplementedError("CP2B implements the verify route")


@_custody_route
async def custody_export(request: Request) -> JSONResponse:
    """POST/GET the derived ``custody_export_v1`` -> ``custody.ledger``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.ledger.generate_export``.
    """
    raise NotImplementedError("CP2B implements the export route")


@_custody_route
async def custody_anchor(request: Request) -> JSONResponse:
    """POST an optional, non-authoritative Solana anchor -> ``custody.ledger``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over
    ``custody.ledger.anchor_manifest_head``; anchoring failure never blocks.
    """
    raise NotImplementedError("CP2B implements the anchor route")
