"""API key authentication middleware and examiner identity resolution."""

import hmac
import logging
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths exempt from authentication.
# /mcp is handled by its own ASGI-level auth (MCPAuthASGIApp) because
# BaseHTTPMiddleware buffers responses and breaks SSE streaming.
_PUBLIC_PATHS = {
    "/health",
    "/health/",
    "/api/v1/health",
    "/api/v1/health/",
    "/mcp",
    "/api/v1/setup/join",
    # Examiner Portal + legacy dashboard HTML only — API endpoints require auth
    "/portal",
    "/portal/",
    "/dashboard",
    "/dashboard/",
}

# Paths matched by prefix (all sub-paths are public)
_PUBLIC_PREFIXES: tuple[str, ...] = ()

# Static asset extensions that bypass auth on portal/dashboard paths
_STATIC_ASSET_EXTS = frozenset({"png", "jpg", "svg", "ico", "css", "js"})

# Maximum length for bearer tokens (DoS protection against megabyte-sized headers)
_MAX_TOKEN_LENGTH = 1024


def verify_api_key(token: str, api_keys: dict) -> dict | None:
    """Timing-safe key lookup with expiry checking. Returns key_info dict or None."""
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        return None
    matched_key = None
    for candidate in api_keys:
        if hmac.compare_digest(token, candidate) and matched_key is None:
            matched_key = candidate
    if matched_key is None:
        return None
    key_info = api_keys.get(matched_key, {})
    if not isinstance(key_info, dict):
        logger.error("API key config for matched key is not a dict, got %s", type(key_info).__name__)
        return None
    if key_info.get("revoked_at"):
        logger.warning("Revoked token used (token_id=%s)", key_info.get("token_id"))
        return None
    expires_at = key_info.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                logger.warning("Expired token used (examiner=%s)", key_info.get("examiner"))
                return None
        except (ValueError, AttributeError):
            pass  # Malformed date — treat as no expiry
    return key_info


class AuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for API key authentication.

    Checks the Authorization header for a Bearer token and resolves
    it to an examiner identity from the config's api_keys mapping.

    If no api_keys are configured, auth is disabled (single-user mode)
    and examiner defaults to "anonymous".
    """

    def __init__(self, app, api_keys: dict | None = None, token_registry=None):
        super().__init__(app)
        self.api_keys = api_keys or {}
        self.token_registry = token_registry

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # R4 (Phase 12f): Block agent tokens from portal API before any passthrough
        if path.startswith("/portal/api/") and self.api_keys:
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
                key_info = verify_api_key(token, self.api_keys)
                if key_info is not None and key_info.get("role") == "agent":
                    logger.warning(
                        "Agent token blocked from portal API: path=%s agent=%s",
                        path,
                        key_info.get("examiner", key_info.get("analyst", "unknown")),
                    )
                    return JSONResponse(
                        {"error": "Agent tokens cannot access portal"},
                        status_code=403,
                    )
                if (
                    key_info is not None
                    and key_info.get("role") == "readonly"
                    and request.method not in ("GET", "HEAD")
                ):
                    logger.warning(
                        "Readonly token blocked from portal write: path=%s token_id=%s",
                        path,
                        key_info.get("token_id"),
                    )
                    return JSONResponse(
                        {"error": "Readonly role cannot modify portal resources"},
                        status_code=403,
                    )

        # Public paths skip gateway auth.
        # /mcp and /mcp/* are handled by MCPAuthASGIApp (ASGI-level auth).
        # Portal paths (/portal/...) are handled by PortalSessionMiddleware inside the portal app.
        is_portal_static = (
            path.startswith(("/portal/", "/dashboard/"))
            and path.rsplit(".", 1)[-1] in _STATIC_ASSET_EXTS
        )
        if (
            path in _PUBLIC_PATHS
            or path.startswith("/mcp/")
            or path.startswith(_PUBLIC_PREFIXES)
            or is_portal_static
            or path.startswith("/portal/")  # portal sub-app owns its own auth
        ):
            request.state.identity = None
            request.state.examiner = None
            request.state.role = None
            return await call_next(request)

        # If no api_keys configured, auth is disabled (single-user mode)
        if not self.api_keys and self.token_registry is None:
            from sift_gateway.identity import resolve_identity
            identity = resolve_identity(None, self.api_keys, source_ip=request.client.host if request.client else "unknown", auth_surface="rest")
            request.state.identity = identity
            request.state.examiner = identity.principal
            request.state.role = identity.role
            request.state.token_id = identity.token_id
            request.state.source_ip = identity.source_ip
            return await call_next(request)

        # Extract bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )

        token = auth_header[7:].strip()

        from sift_gateway.identity import resolve_identity
        identity = resolve_identity(
            token,
            self.api_keys,
            source_ip=request.client.host if request.client else "unknown",
            auth_surface="rest",
            token_registry=self.token_registry,
        )
        if identity is None:
            logger.warning("AuthMiddleware: rejected invalid or expired token")
            return JSONResponse(
                {"error": "Invalid API key"},
                status_code=403,
            )

        request.state.identity = identity
        request.state.examiner = identity.principal
        request.state.role = identity.role
        request.state.token_id = identity.token_id
        request.state.source_ip = identity.source_ip
        return await call_next(request)


def resolve_examiner(request: Request) -> dict:
    """Extract examiner identity from a request that has passed through AuthMiddleware.

    Returns:
        Dict with examiner and role keys.
    """
    # Support both new (examiner) and legacy (analyst) attribute names
    examiner = getattr(request.state, "examiner", None)
    if examiner is None:
        examiner = getattr(request.state, "analyst", "anonymous")
    return {
        "examiner": examiner,
        "role": getattr(request.state, "role", "examiner"),
    }
