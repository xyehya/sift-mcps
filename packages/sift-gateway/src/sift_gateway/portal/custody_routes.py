"""Thin HTTP surface for operator custody workflows.

FROZEN INTERFACE (P4.23 CP1, re-frozen 2026-07-20 repair round 1). CP2B
implements the bodies. Each route does exactly: parse the JSON body -> authorize
the operator session -> call ONE custody domain function (``custody.seal`` /
``custody.actions`` / ``custody.ledger`` / ``custody.admission``) -> return a
shaped response. It holds ZERO business logic (OPERATING-MODEL §1/§12).

**Repair round 1 — real operator auth (was: unauth-read exposure + dead
writes).** ``custody_routes_list()`` is mounted by ``server.py`` as its own
Starlette sub-app wrapped in ``case_dashboard.auth.PortalSessionMiddleware`` —
the SAME Supabase-session middleware ``dashboard_app`` uses — at
``/portal/custody`` (registered ahead of the broader ``Mount("/portal", ...)``
so it is tried first). The shared top-level ``AuthMiddleware`` deliberately
sets ``identity=None`` for every ``/portal``-prefixed path ("portal sub-app
owns its own auth", ``auth.py`` dispatch) and is NOT touched here. Because of
that, ``sift_gateway.auth.require_control_plane_operator`` — which treats an
absent identity/role as an implicit single-user operator — is WRONG for these
routes: it would fail OPEN for an anonymous caller. Every route instead uses
:func:`_require_authenticated_operator` / :func:`_require_examiner` below,
which read ``request.state.role``/``request.state.principal`` (set by
``PortalSessionMiddleware``) with a POSITIVE allow-list and deny an absent
session outright — no anonymous-is-operator fallback for custody.

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

import dataclasses
import logging
import os
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from sift_gateway.active_case import ActiveCase, ActiveCaseError
from sift_gateway.custody import actions, admission, ledger, seal

logger = logging.getLogger(__name__)

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

_MAX_REQUEST_BYTES = 10 * 1024 * 1024

_CustodyRoute = Callable[[Request], Awaitable[JSONResponse]]


def _new_audit_id() -> str:
    """A fresh correlation id for a failure that has no DB audit event.

    Never persisted material — a bare correlation handle the operator can quote
    and an operator can grep logs by (:func:`_custody_route` logs it alongside
    the exception it shaped).
    """
    return str(uuid.uuid4())


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
    PL-pgSQL / stack text can never reach an operator surface.
    """

    async def wrapped(request: Request) -> JSONResponse:
        try:
            return await handler(request)
        except NotImplementedError:
            raise
        except Exception as exc:  # the single boundary that shapes every failure
            audit_id = _new_audit_id()
            logger.error(
                "custody route %s failed (audit_id=%s): %s",
                request.url.path,
                audit_id,
                exc,
            )
            return _shaped_error(
                code="custody_internal",
                message=(
                    "The custody operation could not be completed. Retry, and "
                    f"quote correlation id {audit_id} if it recurs."
                ),
                audit_id=audit_id,
                status_code=500,
            )

    return wrapped


# ---------------------------------------------------------------------------
# Request-scoped helpers (parse / authorize only — no business logic).
# ---------------------------------------------------------------------------
async def _read_json_body(request: Request) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    raw_body = await request.body()
    if len(raw_body) > _MAX_REQUEST_BYTES:
        return None, _shaped_error(
            code="invalid_request",
            message="Request body too large.",
            audit_id=_new_audit_id(),
            status_code=413,
        )
    import json

    try:
        body = json.loads(raw_body or b"{}")
    except json.JSONDecodeError:
        return None, _shaped_error(
            code="invalid_request",
            message="The request body must be valid JSON.",
            audit_id=_new_audit_id(),
        )
    if not isinstance(body, dict):
        return None, _shaped_error(
            code="invalid_request",
            message="The request body must be a JSON object.",
            audit_id=_new_audit_id(),
        )
    return body, None


# Portal roles PortalSessionMiddleware assigns an authenticated operator
# principal (case_dashboard.auth._examiner_role_from_principal): "examiner" or
# "readonly". Agent/service principals never reach a Portal session cookie at
# all (they authenticate to /mcp with a bearer token, a disjoint transport),
# so a valid, non-None role here already implies "authenticated human Portal
# operator" — no separate principal_type check is needed.
_AUTHENTICATED_PORTAL_ROLES = frozenset({"examiner", "readonly"})


def _require_authenticated_operator(request: Request) -> JSONResponse | None:
    """Deny-by-default: only an authenticated Portal operator may read custody.

    Unlike ``sift_gateway.auth.require_control_plane_operator`` (correct for
    ``/api/v1`` control-plane routes, wrong here), an absent session is DENIED,
    never treated as an implicit single-user operator — custody inventory must
    never be readable by an unauthenticated caller (STRIDE boundary #7).
    """
    role = getattr(request.state, "role", None)
    if role not in _AUTHENTICATED_PORTAL_ROLES:
        return _shaped_error(
            code="invalid_request",
            message="Authentication required to read custody status.",
            audit_id=_new_audit_id(),
            status_code=401,
        )
    return None


def _require_examiner(request: Request) -> JSONResponse | None:
    """Mutating/reauth-bearing custody actions require the examiner role.

    Readonly Portal sessions may observe custody state but never mutate it
    (matches ``sift_gateway.auth._CONTROL_PLANE_DENIED_ROLES``'s own framing).
    """
    if getattr(request.state, "role", None) != "examiner":
        return _shaped_error(
            code="invalid_request",
            message="Examiner role required for this custody action.",
            audit_id=_new_audit_id(),
            status_code=403,
        )
    return None


def _require_active_case(request: Request) -> tuple[ActiveCase | None, JSONResponse | None]:
    gateway = request.app.state.gateway
    active_case_service = getattr(gateway, "active_case_service", None)
    if active_case_service is None:
        return None, _shaped_error(
            code="storage_unavailable",
            message="Case authority is unavailable.",
            audit_id=_new_audit_id(),
            status_code=503,
        )
    try:
        case = active_case_service.get_active_case(getattr(request.state, "principal", None))
    except ActiveCaseError as exc:
        return None, _shaped_error(
            code="invalid_request",
            message="No active case — activate a case before working with custody.",
            audit_id=_new_audit_id(),
            status_code=exc.http_status,
        )
    return case, None


@dataclasses.dataclass(frozen=True, slots=True)
class _RequestOperatorSession:
    """The minimal :class:`~sift_gateway.custody.reauth.OperatorSession` this
    request satisfies, built from the authenticated Portal session principal."""

    actor_user_id: str
    session_id: str


def _operator_session(request: Request) -> _RequestOperatorSession | None:
    """Build the domain-layer session from ``request.state.principal``.

    ``PortalSessionMiddleware`` sets ``request.state.principal`` to the plain
    dict ``supabase_auth._principal_dict`` shape ({principal_type, principal_id,
    auth_user_id, display_name, email, system_role, status, case_memberships})
    — never ``request.state.identity`` (a distinct, MCP/bearer-token concept
    this Portal session middleware never populates). ``principal_id`` is the
    same ``app.operator_profiles.id`` authority ``active_case.py`` already uses
    for actor columns; ``auth_user_id`` (the stable Supabase subject) stands in
    for the non-authoritative ``session_id`` this Protocol asks for.
    """
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, dict):
        return None
    principal_id = principal.get("principal_id")
    if not principal_id:
        return None
    return _RequestOperatorSession(
        actor_user_id=str(principal_id),
        session_id=str(principal.get("auth_user_id") or ""),
    )


def _asdict(value: Any) -> dict[str, Any]:
    return dataclasses.asdict(value)


# ---------------------------------------------------------------------------
# Routes.
# ---------------------------------------------------------------------------
@_custody_route
async def custody_status(request: Request) -> JSONResponse:
    """GET the active case's custody status: gate state + inventory + sealed set.

    Drives an operator Refresh reconciliation and renders sealed/pending/ignored/
    retired strictly per EC-4, scoped to the active case.
    """
    auth_error = _require_authenticated_operator(request)
    if auth_error is not None:
        return auth_error
    case, case_error = _require_active_case(request)
    if case_error is not None or case is None:
        return case_error  # type: ignore[return-value]

    gateway = request.app.state.gateway
    evidence_dir = f"{case.artifact_path}/evidence" if case.artifact_path else None
    gate = admission.reconcile(
        case.case_id, evidence_dir, gateway.control_plane_dsn, trigger="refresh"
    )

    evidence_service = getattr(gateway, "evidence_service", None)
    inventory = evidence_service.list_evidence(case.case_id) if evidence_service else []
    return JSONResponse(
        {
            "gate_state": gate["gate_state"],
            "manifest_version": gate["manifest_version"],
            "issues": gate["issues"],
            # EC-4: EvidenceAuthorityService.list_evidence gates "sealed" on a
            # COMMITTED version with ACTIVE manifest membership — a detected-only
            # or digestless object is classified pending, never sealed.
            "sealed": [item for item in inventory if item["status"] == "sealed"],
            "pending": [
                item for item in inventory if item["status"] in ("detected", "registered")
            ],
            "ignored": [item for item in inventory if item["status"] == "ignored"],
            "retired": [item for item in inventory if item["status"] == "retired"],
        }
    )


@_custody_route
async def custody_seal(request: Request) -> JSONResponse:
    """POST Add and Seal (begin/commit): reauth + targets -> ``custody.seal``.

    Body carries an explicit ``phase`` ("begin" | "commit") so the route dispatch
    is a plain lookup, not an inferred business decision. ``targets`` is a list of
    ``{display_path, snapshot_observation_id, display_name?, source?,
    supersedes_object_id?}`` from the most recent Refresh snapshot.
    """
    auth_error = _require_examiner(request)
    if auth_error is not None:
        return auth_error
    body, body_error = await _read_json_body(request)
    if body_error is not None or body is None:
        return body_error  # type: ignore[return-value]
    case, case_error = _require_active_case(request)
    if case_error is not None or case is None:
        return case_error  # type: ignore[return-value]
    session = _operator_session(request)
    if session is None:
        return _shaped_error(
            code="invalid_request",
            message="Operator identity is required to seal evidence.",
            audit_id=_new_audit_id(),
            status_code=401,
        )

    phase = body.get("phase")
    if phase not in ("begin", "commit"):
        return _shaped_error(
            code="invalid_request",
            message="phase must be 'begin' or 'commit'.",
            audit_id=_new_audit_id(),
        )
    idempotency_key = body.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not idempotency_key:
        return _shaped_error(
            code="invalid_request",
            message="idempotency_key is required.",
            audit_id=_new_audit_id(),
        )
    raw_targets = body.get("targets")
    targets = None
    if raw_targets is not None:
        if not isinstance(raw_targets, list):
            return _shaped_error(
                code="invalid_request",
                message="targets must be a list.",
                audit_id=_new_audit_id(),
            )
        parsed_targets = []
        for item in raw_targets:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("display_path"), str)
                or not isinstance(item.get("snapshot_observation_id"), int)
            ):
                return _shaped_error(
                    code="invalid_request",
                    message="Each target requires display_path and snapshot_observation_id.",
                    audit_id=_new_audit_id(),
                )
            parsed_targets.append(
                seal.SealTarget(
                    display_path=item["display_path"],
                    snapshot_observation_id=item["snapshot_observation_id"],
                    display_name=item.get("display_name"),
                    source=item.get("source"),
                    supersedes_object_id=item.get("supersedes_object_id"),
                )
            )
        targets = tuple(parsed_targets)

    if phase == "begin":
        password = body.get("password")
        reason = body.get("reason")
        if not isinstance(password, str) or not password or not isinstance(reason, str) or not reason:
            return _shaped_error(
                code="invalid_request",
                message="password and reason are required to begin a Seal.",
                audit_id=_new_audit_id(),
            )
        result = seal.begin_seal(
            session=session,
            case_id=case.case_id,
            password=password,
            reason=reason,
            idempotency_key=idempotency_key,
            targets=targets,
        )
    else:
        if targets is None:
            return _shaped_error(
                code="invalid_request",
                message="targets is required to commit a Seal.",
                audit_id=_new_audit_id(),
            )
        resume = bool(body.get("resume", False))
        password = body.get("password") if resume else None
        reason = body.get("reason") if resume else None
        if resume and (not isinstance(password, str) or not password or not isinstance(reason, str) or not reason):
            return _shaped_error(
                code="invalid_request",
                message="password and reason are required to resume a Seal.",
                audit_id=_new_audit_id(),
            )
        result = seal.commit_seal(
            session=session,
            case_id=case.case_id,
            idempotency_key=idempotency_key,
            targets=targets,
            password=password,
            reason=reason,
            resume=resume,
        )
    return JSONResponse(_asdict(result))


@_custody_route
async def resolve_findings(request: Request) -> JSONResponse:
    """POST the unified Resolve flow with batch reauth (D4).

    One password covers N selected targets; the route makes ONE domain call —
    ``custody.actions.resolve`` — which dispatches each finding to the honest
    custody verb (Ignore / Retire / Verify-and-Reprotect). Zero business logic in
    the route.
    """
    auth_error = _require_examiner(request)
    if auth_error is not None:
        return auth_error
    body, body_error = await _read_json_body(request)
    if body_error is not None or body is None:
        return body_error  # type: ignore[return-value]
    case, case_error = _require_active_case(request)
    if case_error is not None or case is None:
        return case_error  # type: ignore[return-value]
    session = _operator_session(request)
    if session is None:
        return _shaped_error(
            code="invalid_request",
            message="Operator identity is required to resolve findings.",
            audit_id=_new_audit_id(),
            status_code=401,
        )

    password = body.get("password")
    reason = body.get("reason")
    batch_key = body.get("batch_key")
    raw_dispositions = body.get("dispositions")
    if (
        not isinstance(password, str)
        or not password
        or not isinstance(reason, str)
        or not reason
        or not isinstance(batch_key, str)
        or not batch_key
        or not isinstance(raw_dispositions, list)
        or not raw_dispositions
    ):
        return _shaped_error(
            code="invalid_request",
            message="password, reason, batch_key, and dispositions are required.",
            audit_id=_new_audit_id(),
        )
    dispositions = []
    for item in raw_dispositions:
        if (
            not isinstance(item, dict)
            or item.get("verb") not in ("IGNORE", "RETIRE", "REPROTECT", "ADD_SEAL")
            or not isinstance(item.get("target"), str)
            or not item.get("target")
        ):
            return _shaped_error(
                code="invalid_request",
                message="Each disposition requires a known verb and a target.",
                audit_id=_new_audit_id(),
            )
        dispositions.append(
            actions.FindingDisposition(
                verb=item["verb"],
                target=item["target"],
                supersedes_object_id=item.get("supersedes_object_id"),
            )
        )

    receipts = actions.resolve(
        session=session,
        case_id=case.case_id,
        password=password,
        reason=reason,
        dispositions=tuple(dispositions),
        batch_key=batch_key,
    )
    return JSONResponse({"receipts": [_asdict(receipt) for receipt in receipts]})


@_custody_route
async def custody_verify(request: Request) -> JSONResponse:
    """POST Full Verify (read-only, no fresh password) -> ``custody.actions``."""
    auth_error = _require_authenticated_operator(request)
    if auth_error is not None:
        return auth_error
    case, case_error = _require_active_case(request)
    if case_error is not None or case is None:
        return case_error  # type: ignore[return-value]
    session = _operator_session(request)
    if session is None:
        return _shaped_error(
            code="invalid_request",
            message="Operator identity is required to run Full Verify.",
            audit_id=_new_audit_id(),
            status_code=401,
        )
    result = actions.full_verify(session=session, case_id=case.case_id)
    return JSONResponse(_asdict(result))


@_custody_route
async def custody_export(request: Request) -> JSONResponse:
    """POST/GET the derived ``custody_export_v1`` -> ``custody.ledger``."""
    auth_error = _require_authenticated_operator(request)
    if auth_error is not None:
        return auth_error
    case, case_error = _require_active_case(request)
    if case_error is not None or case is None:
        return case_error  # type: ignore[return-value]
    session = _operator_session(request)
    if session is None:
        return _shaped_error(
            code="invalid_request",
            message="Operator identity is required to generate a custody export.",
            audit_id=_new_audit_id(),
            status_code=401,
        )
    gateway = request.app.state.gateway
    export = ledger.generate_export(
        session=session, case_id=case.case_id, dsn=gateway.control_plane_dsn
    )
    return JSONResponse(
        {
            "schema_version": export.schema_version,
            "export_digest": export.export_digest,
            "source_ledger_head": export.source_ledger_head,
            "document": export.document,
        }
    )


@_custody_route
async def custody_anchor(request: Request) -> JSONResponse:
    """POST an optional, non-authoritative Solana anchor -> ``custody.ledger``.

    Anchoring is unconfigured (and this returns ``anchored: false``) unless
    ``SIFT_SOLANA_KEYPAIR`` names a service-only fee-payer key; anchoring failure
    never blocks (SPEC §Solana). ``password``/``reason``/``idempotency_key``
    present together select the manual/final mode; absent together select the
    automatic mode. A partial set is a shaped ``invalid_request``, never silently
    treated as either mode.
    """
    auth_error = _require_examiner(request)
    if auth_error is not None:
        return auth_error
    body, body_error = await _read_json_body(request)
    if body_error is not None or body is None:
        return body_error  # type: ignore[return-value]
    case, case_error = _require_active_case(request)
    if case_error is not None or case is None:
        return case_error  # type: ignore[return-value]

    password = body.get("password")
    reason = body.get("reason")
    idempotency_key = body.get("idempotency_key")
    report_digest = body.get("report_digest")
    manual = any(value is not None for value in (password, reason, idempotency_key))
    session = _operator_session(request) if manual else None
    if manual and session is None:
        return _shaped_error(
            code="invalid_request",
            message="Operator identity is required for a manual anchor.",
            audit_id=_new_audit_id(),
            status_code=401,
        )

    gateway = request.app.state.gateway
    anchorer = ledger._build_solana_anchorer(
        keypair_path=os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip() or None,
        rpc_url=os.environ.get("SIFT_SOLANA_RPC_URL", "").strip() or None,
        cluster=os.environ.get("SIFT_SOLANA_CLUSTER", "mainnet").strip() or "mainnet",
    )
    try:
        receipt = ledger.anchor_manifest_head(
            case_id=case.case_id,
            dsn=gateway.control_plane_dsn,
            anchorer=anchorer,
            session=session,
            password=password,
            reason=reason,
            idempotency_key=idempotency_key,
            report_digest=report_digest,
        )
    except ValueError as exc:
        return _shaped_error(
            code="invalid_request", message=str(exc), audit_id=_new_audit_id()
        )
    if receipt is None:
        return JSONResponse({"anchored": False, "reason": "solana_anchoring_disabled"})
    return JSONResponse({"anchored": True, **_asdict(receipt)})


def custody_routes_list() -> list[Route]:
    """The custody route table.

    Paths are relative to the ``/portal/custody`` mount point ``server.py``
    wraps in ``PortalSessionMiddleware`` — NOT absolute ``/portal/custody/*``
    paths (this table is never registered at the gateway's top level, where
    ``request.state.role``/``request.state.principal`` would never be set).
    """
    return [
        Route("/status", custody_status, methods=["GET"]),
        Route("/seal", custody_seal, methods=["POST"]),
        Route("/resolve", resolve_findings, methods=["POST"]),
        Route("/verify", custody_verify, methods=["POST"]),
        Route("/export", custody_export, methods=["POST", "GET"]),
        Route("/anchor", custody_anchor, methods=["POST"]),
    ]
