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
    # Root only redirects to /portal/ (see server.py root_redirect)
    "/",
    "/health",
    "/health/",
    "/api/v1/health",
    "/api/v1/health/",
    "/mcp",
    "/api/v1/setup/join",
    # Examiner Portal HTML only — API endpoints require auth
    "/portal",
    "/portal/",
}

# Paths matched by prefix (all sub-paths are public)
_PUBLIC_PREFIXES: tuple[str, ...] = ()

# Static asset extensions that bypass auth on portal paths
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
            path.startswith("/portal/")
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
        # SEC-1: record whether Supabase is the active authority for this request
        # so control-plane step-up (require_recent_reauth) is a no-op on pure
        # legacy / single-user deployments and enforced only where re-auth exists.
        request.state.supabase_enabled = self._supabase_enabled()


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


# SEC-1 (DSS-CAN-002): the Gateway `/api/v1` control plane (backend registry,
# service lifecycle, join-code mint) must be operator-only. `AuthMiddleware`
# proves *who* but applies no authority gate to `/api/v1`, so a sandboxed
# agent/service principal — exactly what the least-priv sandbox exists to
# contain — could register/start backends or mint join codes. These shared
# dependencies are the single authority + step-up gate the mutation handlers
# invoke (CWE-862 missing function-level authorization; deny-by-default).
#
# Operator principal_types allowed to mutate the control plane. Anything else
# (agent/service) is denied. Mirrors `_REST_TOOL_OPERATOR_TYPES`.
_CONTROL_PLANE_OPERATOR_TYPES = frozenset({"user", "operator", "examiner"})
# Roles denied control-plane mutation even when principal_type is a human/user
# (readonly examiners may observe but never mutate).
_CONTROL_PLANE_DENIED_ROLES = frozenset({"agent", "service", "readonly"})


def require_control_plane_operator(request: Request) -> JSONResponse | None:
    """Deny-by-default authority gate for `/api/v1` control-plane mutations.

    Returns ``None`` when the authenticated principal may mutate the control
    plane (examiner / operator / single-user-anonymous), or a 403
    :class:`JSONResponse` when it may not. Invoke at the TOP of every
    control-plane mutation handler (register/unregister/enable backends,
    service start/stop/restart, mint join-code).

    Denial rules (deny-by-default):
      - ``principal_type`` in {agent, service} -> 403 (the sandboxed principal
        the least-priv model exists to contain).
      - ``role`` in {agent, service, readonly} -> 403 (readonly users observe,
        never mutate).
      - Anonymous single-user mode (no identity, no role) is treated as
        operator so existing single-operator deployments keep working — this
        mirrors :func:`is_agent_principal`'s anonymous handling.

    Generic 403 body (no principal/secret material echoed); the denial is
    logged with the non-PII rationale for the authorization matrix.
    """
    identity = getattr(request.state, "identity", None)
    principal_type = getattr(identity, "principal_type", None)
    role = getattr(request.state, "role", None)

    denied_reason: str | None = None
    if principal_type is not None and principal_type not in _CONTROL_PLANE_OPERATOR_TYPES:
        denied_reason = f"principal_type={principal_type}"
    elif role in _CONTROL_PLANE_DENIED_ROLES:
        denied_reason = f"role={role}"

    if denied_reason is not None:
        logger.warning(
            "Control-plane mutation denied (%s) path=%s method=%s token_id=%s",
            denied_reason,
            request.url.path,
            request.method,
            getattr(request.state, "token_id", None),
        )
        return JSONResponse(
            {"error": "Operator authority required for control-plane mutation"},
            status_code=403,
        )
    return None


def _recent_reauth_denied(exc: Exception) -> JSONResponse:
    """Map a step-up re-verify failure to a fail-closed denial (default 401).

    Honors a typed ``.http_status`` (clamped to 4xx/5xx) when the reverify
    primitive raises a Supabase auth error; otherwise denies 401. Never returns
    < 400, never echoes token or password material.
    """
    status = getattr(exc, "http_status", None)
    if not isinstance(status, int) or status < 400 or status > 599:
        status = 401
    if status == 503:
        msg = "Control plane unavailable — re-auth could not be verified."
    elif status == 403:
        msg = "Re-auth denied for this operator."
    else:
        msg = "Re-authentication failed."
    return JSONResponse({"error": msg}, status_code=status)


async def require_recent_reauth(request: Request, body: dict) -> JSONResponse | None:
    """Step-up re-auth gate for the highest-impact control-plane mutations.

    Applied to *register-a-new-backend* and *mint-join-code* (decision: examiner
    + step-up). This is **password re-entry only**, mirroring the canonical
    portal primitive ``case_dashboard.routes._supabase_reverify``: the operator
    email is sourced from the AUTHENTICATED bearer identity (never the request
    body), and only the password is read from the body. Returns ``None`` when
    the step-up requirement is satisfied (or not applicable), or a fail-closed
    denial :class:`JSONResponse` otherwise.

    Behavior:
      - **No-op when Supabase is not the active authority** (``request.state.
        supabase_enabled`` is false) — pure legacy / single-user deployments
        have no re-auth plane, so step-up cannot apply. Preserves pre-Supabase
        behavior.
      - **When Supabase is enabled**, re-verify the operator's submitted
        password against Supabase via the shared portal primitive
        (``app.state.supabase_reverify`` -> ``SupabaseAuthCallbacks.
        reverify_password``), using the bearer identity's own ``email`` +
        ``auth_user_id`` (``expected_auth_user_id``) so the grant's subject must
        match this token's principal — a stolen bearer token cannot be
        step-upped with a different operator's password. The grant's session
        tokens are discarded by the primitive.

    Fail-closed denials mirror ``_supabase_reverify`` exactly:
      - no re-verify primitive wired                       -> 503
      - bearer identity carries no operator email          -> 401
      - missing password in body                           -> 400
      - wrong password / identity mismatch / non-operator /
        control plane unreachable                          -> per reverify_password
                                                               (401 / 403 / 503)
    Never returns ``None`` except on a verified re-auth or the no-op case.
    """
    if not getattr(request.state, "supabase_enabled", False):
        return None  # no re-auth plane on legacy/single-user deployments

    reverify = getattr(request.app.state, "supabase_reverify", None)
    if not callable(reverify):
        # Supabase is the active authority but the re-verify primitive is not
        # wired — fail closed rather than silently skipping step-up.
        logger.warning(
            "Step-up required but supabase_reverify is not wired; denying %s",
            request.url.path,
        )
        return JSONResponse(
            {"error": "Re-auth unavailable: control plane not wired."},
            status_code=503,
        )

    # Email comes from the AUTHENTICATED bearer identity, never the body — the
    # password is the only operator-supplied secret (mirrors _supabase_reverify).
    identity = getattr(request.state, "identity", None)
    email = getattr(identity, "email", None)
    if not isinstance(email, str) or not email.strip():
        return JSONResponse(
            {"error": "Re-auth unavailable: token carries no operator email."},
            status_code=401,
        )
    email = email.strip()

    if not isinstance(body, dict):
        body = {}
    password = body.get("password")
    if not isinstance(password, str) or not password:
        return JSONResponse(
            {"error": "Re-auth required: confirm your password."},
            status_code=400,
        )

    expected_auth_user_id = getattr(identity, "auth_user_id", None)
    source_ip = getattr(request.state, "source_ip", None)
    try:
        await reverify(
            email,
            password,
            source_ip,
            expected_auth_user_id=expected_auth_user_id,
        )
    except Exception as exc:  # noqa: BLE001 - never leak token/password material
        # FAIL CLOSED on ANY error (incl. a TypeError from a primitive that
        # cannot bind expected_auth_user_id): never retry without the identity
        # binding and never fall through to "allowed".
        return _recent_reauth_denied(exc)
    return None
