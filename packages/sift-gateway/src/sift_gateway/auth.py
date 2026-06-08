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

    def __init__(self, app, api_keys: dict | None = None, token_registry=None,
                 resolver=None, auth_config=None):
        super().__init__(app)
        self.api_keys = api_keys or {}
        self.token_registry = token_registry
        # PR03A: shared Supabase identity resolver + parsed auth config.
        self.resolver = resolver
        self.auth_config = auth_config

    def _supabase_enabled(self) -> bool:
        cfg = self.auth_config
        return bool(self.resolver is not None and cfg is not None and getattr(cfg, "enabled", False))

    def _legacy_token_fallback(self) -> bool:
        cfg = self.auth_config
        if cfg is None:
            return True  # no PR03 config => legacy-only deployment
        return bool(getattr(cfg, "legacy_token_fallback_enabled", True))

    def _anonymous_examiner_allowed(self) -> bool:
        cfg = self.auth_config
        if cfg is None:
            return True  # preserve pre-PR03 single-user behavior
        return bool(getattr(cfg, "legacy_anonymous_examiner_enabled", False))

    async def _resolve_supabase(self, token: str, source_ip: str | None):
        """Return (identity, http_status) — identity or a denial status code."""
        from sift_gateway.supabase_auth import SupabaseAuthError

        try:
            identity = await self.resolver.resolve(
                token, source_ip=source_ip, auth_surface="rest"
            )
            return identity, None
        except SupabaseAuthError as exc:
            return None, getattr(exc, "http_status", 401)

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

        source_ip = request.client.host if request.client else "unknown"

        # Anonymous single-user / examiner mode. Only when no credential authority
        # is configured AND (pre-PR03 deployment OR anonymous_examiner explicitly
        # enabled). With Supabase enabled this implicit anonymous mode is off.
        if (
            not self.api_keys
            and self.token_registry is None
            and not self._supabase_enabled()
            and self._anonymous_examiner_allowed()
        ):
            from sift_gateway.identity import resolve_identity
            identity = resolve_identity(None, self.api_keys, source_ip=source_ip, auth_surface="rest")
            self._stamp(request, identity)
            return await call_next(request)

        # Extract bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )

        token = auth_header[7:].strip()

        # 1) Supabase JWT first when enabled.
        if self._supabase_enabled():
            identity, deny_status = await self._resolve_supabase(token, source_ip)
            if identity is not None:
                self._stamp(request, identity)
                return await call_next(request)
            # A valid-looking JWT that the resolver mapped to no/disabled principal
            # yields 403; invalid/expired yields 401. If Supabase rejected it as an
            # unknown token (401) we still allow the legacy fallback below.
            if deny_status == 403:
                logger.warning("AuthMiddleware: Supabase principal denied (403)")
                return JSONResponse({"error": "Forbidden"}, status_code=403)
            # B9(b): a 5xx is an auth-backend OUTAGE, not a bad token. Always log
            # it. When legacy fallback is disabled there is no other authority, so
            # fail closed as 503 rather than masquerading as a 401/403. When
            # legacy fallback is enabled the bridge below may still authenticate.
            if deny_status is not None and deny_status >= 500:
                logger.warning(
                    "AuthMiddleware: Supabase auth backend unavailable (status=%s)",
                    deny_status,
                )
                if not self._legacy_token_fallback():
                    return JSONResponse(
                        {"error": "Authentication service unavailable"},
                        status_code=503,
                    )

        # 2) PR02 token-registry / legacy api_keys fallback only when enabled.
        if self._legacy_token_fallback() and (self.api_keys or self.token_registry is not None):
            from sift_gateway.identity import resolve_identity
            identity = resolve_identity(
                token,
                self.api_keys,
                source_ip=source_ip,
                auth_surface="rest",
                token_registry=self.token_registry,
            )
            if identity is not None:
                self._stamp(request, identity)
                return await call_next(request)

        logger.warning("AuthMiddleware: rejected invalid or expired token")
        return JSONResponse({"error": "Invalid API key"}, status_code=403)

    def _stamp(self, request: Request, identity) -> None:
        request.state.identity = identity
        request.state.examiner = identity.principal
        request.state.role = identity.role
        request.state.token_id = identity.token_id
        request.state.source_ip = identity.source_ip


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


# BATCH-B1 (F-MVP-3): for the MVP, REST tool execution is operator-only. AI
# agents use the Gateway MCP surface (/mcp) exclusively, which is the only path
# that runs the SIFT policy middleware stack (tool authz, evidence gate, response
# guard, rate limit). Letting an agent token execute a tool over REST would let
# it bypass that entire MCP policy boundary, so agent/service principals are
# denied on the REST tool path.
_REST_TOOL_OPERATOR_TYPES = frozenset({"user", "operator", "examiner"})


def is_agent_principal(request: Request) -> bool:
    """Return True when the authenticated principal is a non-operator (agent/service).

    Resolution order, most authoritative first:
      1. The resolved :class:`Identity` ``principal_type`` (Supabase / token
         registry / api-key path all populate this).
      2. The stamped ``request.state.role`` (``agent``/``service``).

    Anonymous single-user mode (no identity, no role) is treated as operator so
    existing single-operator deployments keep working.
    """
    identity = getattr(request.state, "identity", None)
    principal_type = getattr(identity, "principal_type", None)
    if principal_type is not None:
        return principal_type not in _REST_TOOL_OPERATOR_TYPES
    role = getattr(request.state, "role", None)
    if role in ("agent", "service"):
        return True
    return False
