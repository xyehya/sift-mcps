"""Portal session middleware for the case-dashboard sub-app.

Validates the agentir_session cookie (JWT) and sets request.state.examiner /
request.state.role. Falls back to Bearer token for backward compatibility
(examiner-role tokens only; agent tokens are never accepted here).

Route handlers read request.state via getattr() (R9) and decide 401/403.
This middleware never returns 401/403 itself.
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
    verify_jwt,
    generate_jwt,
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


class PortalSessionMiddleware(BaseHTTPMiddleware):
    """Resolve examiner identity for portal requests.

    Priority:
      1. agentir_session cookie → verify JWT → set examiner/role
      2. Authorization: Bearer token in api_keys, examiner role only → set examiner/role
      3. Neither → examiner=None, role=None (route handlers enforce 401)
    """

    def __init__(self, app, *, session_secret: str, api_keys: dict, session_max_age: int = 28800):
        super().__init__(app)
        self._session_secret = session_secret
        self._api_keys = api_keys
        self._session_max_age = session_max_age

    async def dispatch(self, request: Request, call_next):
        # 1. Cookie-based JWT auth
        cookie_val = request.cookies.get(COOKIE_NAME)
        if cookie_val and self._session_secret:
            payload = verify_jwt(cookie_val, self._session_secret)
            if payload is not None:
                request.state.examiner = payload.get("sub")
                request.state.role = payload.get("role", "examiner")

                # Sliding session refresh check
                now = int(time.time())
                exp = payload.get("exp", 0)
                iat = payload.get("iat", 0)
                
                # Refresh if >10% elapsed (exp - now < max_age * 0.9)
                # and at least 5 minutes (300s) have passed since iat to avoid churn
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

        # 2. Bearer token fallback — examiner role only
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer ") and self._api_keys:
            token = auth_header[7:].strip()
            key_info = _verify_bearer(token, self._api_keys)
            if key_info is not None and key_info.get("role", "") == "examiner":
                request.state.examiner = key_info.get(
                    "examiner", key_info.get("analyst", "unknown")
                )
                request.state.role = "examiner"
                return await call_next(request)

        # 3. No valid auth — route handlers enforce 401
        request.state.examiner = None
        request.state.role = None
        return await call_next(request)
