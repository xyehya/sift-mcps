"""Portal backends and services proxy route handlers (Phase 6.3).

Extracted from routes.py (D4 / XYE-72).  Contains only the gateway
backend/service API cluster:

  _verify_origin          — CSRF-style same-origin guard for mutation endpoints
  _resolve_gateway        — retrieve gateway reference from app state
  get_backends_route      — GET  /api/backends
  get_health_route        — GET  /api/health
  validate_backend_route  — POST /api/backends/validate
  register_backend_route  — POST /api/backends
  unregister_backend_route — DELETE /api/backends/{name}
  reload_backends_route   — POST /api/backends/reload
  set_backend_enabled_route — POST /api/backends/{name}/enabled
  start_service_route     — POST /api/services/{name}/start
  stop_service_route      — POST /api/services/{name}/stop
  restart_service_route   — POST /api/services/{name}/restart

Shared auth helpers (_require_portal_role, _require_examiner_role,
_resolve_examiner) are reproduced here verbatim — they are pure functions with
no module-state dependencies.  _supabase_reverify is imported lazily inside
each handler to avoid circular imports (routes.py is the owner of _SUPABASE_AUTH).
"""

from __future__ import annotations

import logging

from sift_common.identifiers import is_valid_examiner_slug
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure auth helpers (no module-state dependencies; matches routes.py originals)
# ---------------------------------------------------------------------------


def _resolve_examiner(request: Request) -> str | None:
    """Get examiner from auth middleware state.  R9: always use getattr."""
    examiner = getattr(request.state, "examiner", None)
    if not examiner or examiner == "anonymous":
        return None
    if not is_valid_examiner_slug(examiner):
        return None
    return examiner


def _require_examiner_role(request: Request) -> JSONResponse | None:
    """Return 403 unless the authenticated portal principal is an examiner."""
    if getattr(request.state, "role", None) != "examiner":
        return JSONResponse(
            {"error": "Examiner role required"},
            status_code=403,
        )
    return None


def _require_portal_role(request: Request) -> JSONResponse | None:
    """Return 403 unless the authenticated principal has examiner or readonly role."""
    role = getattr(request.state, "role", None)
    if role not in ("examiner", "readonly"):
        return JSONResponse(
            {"error": "Examiner or Readonly role required"},
            status_code=403,
        )
    return None


# ---------------------------------------------------------------------------
# Gateway helpers (only used by this cluster)
# ---------------------------------------------------------------------------


def _resolve_gateway(request: Request):
    """Retrieve gateway reference from application state."""
    root_app = request.scope.get("app")
    if root_app and hasattr(root_app, "state") and hasattr(root_app.state, "gateway"):
        return root_app.state.gateway
    if hasattr(request.app, "state") and hasattr(request.app.state, "gateway"):
        return request.app.state.gateway
    return None


def _verify_origin(request: Request) -> JSONResponse | None:
    """CSRF-style same-origin guard: reject mutation requests whose Origin header
    does not match the Host header.  Returns None on success."""
    origin = request.headers.get("origin")
    if not origin:
        return JSONResponse({"error": "Missing Origin header"}, status_code=400)
    host = request.headers.get("host")
    from urllib.parse import urlparse
    parsed_origin = urlparse(origin)
    origin_host = parsed_origin.netloc
    if not origin_host or origin_host != host:
        if origin_host.replace("localhost", "127.0.0.1") != host.replace("localhost", "127.0.0.1"):
            return JSONResponse({"error": f"Origin mismatch: {origin_host} vs {host}"}, status_code=400)
    return None


# ---------------------------------------------------------------------------
# Phase 6.3 — Portal Backends & Services Proxy Routes
# ---------------------------------------------------------------------------


async def get_backends_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)
    from sift_gateway.rest import list_backends
    request.app.state.gateway = gateway
    return await list_backends(request)


async def get_health_route(request: Request) -> JSONResponse:
    """PT1/WI4 — operator health panel feed.

    Proxies the Gateway's own ``/health`` probe (the single source of truth for
    backend/Supabase/evidence-root health) so the portal panel does not have to
    reach a second origin. Idle mounted stdio backends are normalized to ``ok``
    by ``health_endpoint`` (sift_gateway.health._operator_backend_health), so the
    panel shows them as ready rather than "stopped". Operator/readonly only; the
    response carries no token, key, or DSN material.
    """
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)
    from sift_gateway.health import health_endpoint
    request.app.state.gateway = gateway
    return await health_endpoint(request)


async def validate_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    from sift_gateway.rest import validate_backend_logic
    response, status_code = validate_backend_logic(gateway, body)
    return JSONResponse(response, status_code=status_code)


async def register_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    actor = getattr(request.state, "principal", None) or getattr(request.state, "identity", None)
    from sift_gateway.rest import register_backend_logic
    response, status_code = await register_backend_logic(gateway, body, actor=actor)
    return JSONResponse(response, status_code=status_code)


async def unregister_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        body = {}

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import unregister_backend

    request.app.state.gateway = gateway
    return await unregister_backend(request)


async def reload_backends_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import reload_backends
    request.app.state.gateway = gateway
    return await reload_backends(request)


async def set_backend_enabled_route(request: Request) -> JSONResponse:
    """PT1/WI5 — operator enable/disable of an add-on backend (re-auth gated).

    Proxies the registry ``set_enabled`` write via the gateway REST helper. Never
    edits the DB directly from the frontend; the registry owns the write and the
    change applies to the served /mcp catalog on Gateway restart.
    """
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import set_backend_enabled
    request.app.state.gateway = gateway
    return await set_backend_enabled(request)


async def start_service_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import start_service
    request.app.state.gateway = gateway
    return await start_service(request)


async def stop_service_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import stop_service
    request.app.state.gateway = gateway
    return await stop_service(request)


async def restart_service_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    # CL3a (B-MVP-017): re-verify the operator password against Supabase
    # (fail closed) instead of the local file-HMAC challenge.
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import restart_service
    request.app.state.gateway = gateway
    return await restart_service(request)
