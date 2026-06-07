"""Portal session middleware for the case-dashboard sub-app.

PR03A target: validate the Supabase session envelope cookie on each request by
calling the Gateway-injected ``supabase_auth`` resolver. If the access token is
expired and a refresh token is present, the middleware refreshes through the
resolver and rotates the cookie. The resolved app principal (operator / agent /
service) is placed on ``request.state.principal``; ``request.state.examiner`` and
``request.state.role`` are derived for backward-compatible route handlers.

Legacy behavior — the HMAC ``sift_session`` cookie and the examiner Bearer-token
fallback — is retained ONLY when ``legacy_portal_session_enabled`` is true. The
Gateway passes the real flag; tests default it to true so existing suites stay
green.

Route handlers read request.state via getattr() (R9) and decide 401/403. This
middleware never returns 401/403 itself.
"""

from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from case_dashboard.session_jwt import (
    COOKIE_NAME,
    COOKIE_PATH,
    COOKIE_SAME_SITE,
    SESSION_ENVELOPE_COOKIE_NAME,
    SESSION_ENVELOPE_COOKIE_PATH,
    SESSION_ENVELOPE_COOKIE_SAME_SITE,
    verify_jwt,
    generate_jwt,
    generate_session_envelope,
    verify_session_envelope,
)

logger = logging.getLogger(__name__)

_MAX_TOKEN_LENGTH = 1024


def _verify_bearer(token: str, api_keys: dict) -> dict | None:
    """Timing-safe bearer lookup with expiry check. Returns key_info or None."""
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
        return None
    if key_info.get("revoked_at"):
        return None
    expires_at = key_info.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                return None
        except (ValueError, AttributeError):
            pass
    return key_info


def _examiner_role_from_principal(principal: dict) -> tuple[str | None, str | None]:
    """Map a resolved app principal dict to (examiner, role) for legacy handlers.

    Only operator principals get an examiner identity + portal role. Agent and
    service principals are intentionally left without (examiner, role) so the
    existing portal-agent-block keeps denying them on operator routes.
    """
    if not isinstance(principal, dict):
        return None, None
    ptype = principal.get("principal_type")
    if ptype != "operator":
        return None, None
    examiner = (
        principal.get("display_name")
        or principal.get("email")
        or principal.get("principal_id")
    )
    system_role = principal.get("system_role") or "operator"
    # Portal RBAC distinguishes only examiner vs readonly. readonly maps to
    # readonly; everything else (operator/lead/owner/admin) is examiner.
    role = "readonly" if system_role == "readonly" else "examiner"
    return examiner, role


class PortalSessionMiddleware(BaseHTTPMiddleware):
    """Resolve principal identity for portal requests.

    Priority:
      1. Supabase session envelope cookie -> resolve via supabase_auth -> set
         request.state.principal/examiner/role (with refresh + cookie rotation).
      2. (legacy only) sift_session cookie -> verify JWT -> set examiner/role.
      3. (legacy only) Authorization: Bearer token in api_keys, examiner role.
      4. Neither -> examiner=None, role=None, principal=None (handlers enforce 401).
    """

    def __init__(
        self,
        app,
        *,
        session_secret: str,
        api_keys: dict,
        session_max_age: int = 28800,
        supabase_auth=None,
        legacy_portal_session_enabled: bool = True,
    ):
        super().__init__(app)
        self._session_secret = session_secret
        self._api_keys = api_keys
        self._session_max_age = session_max_age
        self._supabase_auth = supabase_auth
        self._legacy_enabled = legacy_portal_session_enabled

    def _set_envelope_cookie(self, response, envelope: str) -> None:
        response.set_cookie(
            SESSION_ENVELOPE_COOKIE_NAME,
            envelope,
            max_age=self._session_max_age,
            path=SESSION_ENVELOPE_COOKIE_PATH,
            httponly=True,
            secure=True,
            samesite=SESSION_ENVELOPE_COOKIE_SAME_SITE,
        )

    def _clear_envelope_cookie(self, response) -> None:
        response.set_cookie(
            SESSION_ENVELOPE_COOKIE_NAME,
            "",
            max_age=0,
            path=SESSION_ENVELOPE_COOKIE_PATH,
            httponly=True,
            secure=True,
            samesite=SESSION_ENVELOPE_COOKIE_SAME_SITE,
        )

    async def _resolve_supabase(self, request: Request, call_next):
        """Attempt Supabase-envelope auth. Returns (response, handled: bool).

        On success sets request.state and returns the awaited downstream response
        (handled=True). If no envelope / no resolver, returns (None, False) so the
        caller can fall through to legacy paths.
        """
        if self._supabase_auth is None or not self._session_secret:
            return None, False

        cookie_val = request.cookies.get(SESSION_ENVELOPE_COOKIE_NAME)
        if not cookie_val:
            return None, False

        envelope = verify_session_envelope(cookie_val, self._session_secret)
        if envelope is None:
            return None, False

        source_ip = request.client.host if request.client else "unknown"
        access_token = envelope.get("at", "")
        refresh_token = envelope.get("rt", "")

        principal = None
        rotated_envelope: str | None = None

        # 1. Try resolving the current access token.
        try:
            principal = await self._supabase_auth.resolve(access_token, source_ip)
        except Exception as exc:  # noqa: BLE001 - never leak token material
            logger.warning("portal resolve failed: %s", type(exc).__name__)
            principal = None

        # 2. If unresolved and we hold a refresh token, try refreshing.
        if principal is None and refresh_token:
            try:
                refreshed = await self._supabase_auth.refresh(refresh_token, source_ip)
            except Exception as exc:  # noqa: BLE001
                logger.warning("portal refresh failed: %s", type(exc).__name__)
                refreshed = None
            refreshed_principal = refreshed.get("principal") if refreshed else None
            # Only operator portal sessions are refreshable via the envelope
            # (C10.2). Agent/service JWTs belong on /mcp, never the portal cookie.
            if (
                isinstance(refreshed_principal, dict)
                and refreshed_principal.get("principal_type") == "operator"
            ):
                principal = refreshed_principal
                rotated_envelope = generate_session_envelope(
                    access_token=refreshed.get("access_token", ""),
                    refresh_token=refreshed.get("refresh_token", ""),
                    expires_at=int(refreshed.get("expires_at", 0)),
                    sub=refreshed.get("sub", envelope.get("sub", "")),
                    fingerprint=refreshed.get("fingerprint", ""),
                    secret=self._session_secret,
                    # Preserve original issued-at so the absolute ceiling holds.
                    issued_at=envelope.get("eiat"),
                )

        if principal is None:
            # Fail closed: drop the envelope cookie and let handlers enforce 401.
            request.state.principal = None
            request.state.examiner = None
            request.state.role = None
            response = await call_next(request)
            self._clear_envelope_cookie(response)
            return response, True

        request.state.principal = principal
        examiner, role = _examiner_role_from_principal(principal)
        request.state.examiner = examiner
        request.state.role = role

        response = await call_next(request)
        if rotated_envelope is not None:
            self._set_envelope_cookie(response, rotated_envelope)
        return response, True

    async def dispatch(self, request: Request, call_next):
        # 1. Supabase session envelope (target path).
        response, handled = await self._resolve_supabase(request, call_next)
        if handled:
            return response

        # Legacy paths only when explicitly enabled.
        if self._legacy_enabled:
            # 2. Cookie-based JWT auth (legacy sift_session)
            cookie_val = request.cookies.get(COOKIE_NAME)
            if cookie_val and self._session_secret:
                payload = verify_jwt(cookie_val, self._session_secret)
                if payload is not None:
                    request.state.examiner = payload.get("sub")
                    request.state.role = payload.get("role", "examiner")
                    request.state.principal = None

                    now = int(time.time())
                    exp = payload.get("exp", 0)
                    iat = payload.get("iat", 0)

                    should_refresh = False
                    if exp - now < self._session_max_age * 0.9 and now - iat > 300:
                        should_refresh = True

                    response = await call_next(request)

                    if should_refresh:
                        new_token = generate_jwt(
                            sub=request.state.examiner,
                            role=request.state.role,
                            secret=self._session_secret,
                            max_age=self._session_max_age,
                        )
                        response.set_cookie(
                            COOKIE_NAME,
                            new_token,
                            max_age=self._session_max_age,
                            path=COOKIE_PATH,
                            httponly=True,
                            secure=True,
                            samesite=COOKIE_SAME_SITE,
                        )
                    return response

            # 3. Bearer token fallback — examiner role only
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer ") and self._api_keys:
                token = auth_header[7:].strip()
                key_info = _verify_bearer(token, self._api_keys)
                if key_info is not None and key_info.get("role", "") == "examiner":
                    request.state.examiner = key_info.get(
                        "examiner", key_info.get("analyst", "unknown")
                    )
                    request.state.role = "examiner"
                    request.state.principal = None
                    return await call_next(request)

        # 4. No valid auth — route handlers enforce 401
        request.state.examiner = None
        request.state.role = None
        request.state.principal = None
        return await call_next(request)
