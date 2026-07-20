"""Thin HTTP surface for operator custody workflows.

FROZEN INTERFACE (P4.23 CP1, 2026-07-20). CP2B implements the bodies. Each route
does exactly: parse the JSON body -> authorize the operator session -> call ONE
custody domain function (``custody.seal`` / ``custody.actions`` / ``custody.ledger``
/ ``custody.admission``) -> return a shaped response. It holds ZERO business logic
(OPERATING-MODEL §1/§12) and is NOT registered into the app until CP2B wires it.

**EC-3 — shaped errors only.** Custody routes return an operator-meaningful
message naming the next action (e.g. "a Seal is in progress — resume it"), a
stable machine-readable ``code``, and a correlation/``audit_id``. Raw database
diagnostics — SQLSTATE, constraint names, PL/pgSQL context, stack text — never
reach an operator surface. :func:`shaped_error` is the single mapping seam.

**EC-4 — sealed rendering.** Status responses render an entry as sealed evidence
ONLY when a ``COMMITTED`` Evidence Version with manifest membership exists; pending
entries render only as Pending, Ignored/Retired as their own states. Every panel
is strictly scoped to the active case.

**D4 — unified Resolve.** :func:`resolve_findings` presents one per-finding flow
with batch reauthentication (one password covering N selected targets); the
recorded custody verbs underneath stay distinct (new -> Add and Seal or Ignore;
deleted sealed -> Retire; changed sealed -> Retire, optional reacquire-as-new).
"""

from __future__ import annotations

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


def shaped_error(
    *, code: str, message: str, audit_id: str | None = None, status_code: int = 400
) -> JSONResponse:
    """Build the single shaped custody-error envelope (EC-3).

    ``message`` is operator-meaningful and names the next action; ``code`` is one
    of :data:`CUSTODY_ERROR_CODES`; ``audit_id`` correlates to the audit log. No
    raw SQLSTATE / constraint / PL/pgSQL / stack text is ever included.
    """
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if audit_id is not None:
        body["error"]["audit_id"] = audit_id
    return JSONResponse(body, status_code=status_code)


async def custody_status(request: Request) -> JSONResponse:
    """GET the active case's custody status: gate state + inventory + sealed set.

    Drives an operator Refresh reconciliation and renders sealed/pending/ignored/
    retired strictly per EC-4, scoped to the active case.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.admission``.
    """
    raise NotImplementedError("CP2B implements the custody status route")


async def custody_seal(request: Request) -> JSONResponse:
    """POST Add and Seal (or resume): reauth + targets -> ``custody.seal``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.seal.add_and_seal``
    / ``retry_seal``.
    """
    raise NotImplementedError("CP2B implements the seal route")


async def resolve_findings(request: Request) -> JSONResponse:
    """POST the unified Resolve flow with batch reauth (D4).

    One password covers N selected targets; the route dispatches each to the
    honest custody verb (Ignore / Retire / Verify-and-Reprotect) in
    ``custody.actions``. NOT IMPLEMENTED in CP1 — CP2B implements it.
    """
    raise NotImplementedError("CP2B implements the resolve route")


async def custody_verify(request: Request) -> JSONResponse:
    """POST Full Verify (read-only, no fresh password) -> ``custody.actions``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.actions.full_verify``.
    """
    raise NotImplementedError("CP2B implements the verify route")


async def custody_export(request: Request) -> JSONResponse:
    """POST/GET the derived ``custody_export_v1`` -> ``custody.ledger``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over ``custody.ledger.generate_export``.
    """
    raise NotImplementedError("CP2B implements the export route")


async def custody_anchor(request: Request) -> JSONResponse:
    """POST an optional, non-authoritative Solana anchor -> ``custody.ledger``.

    NOT IMPLEMENTED in CP1 — CP2B implements this over
    ``custody.ledger.anchor_manifest_head``; anchoring failure never blocks.
    """
    raise NotImplementedError("CP2B implements the anchor route")
