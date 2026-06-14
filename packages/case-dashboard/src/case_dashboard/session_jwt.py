"""JWT helpers for portal session cookies.

Implements HMAC-SHA256 JWTs using stdlib only — no external JWT library.
The session secret is stored as 32-byte hex in gateway.yaml and passed in
as a hex string; bytes.fromhex() converts it to raw bytes before signing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

# PR03A — Supabase-backed session envelope cookie. Distinct name from the legacy
# sift_session cookie so the two paths never collide. The envelope carries the
# Supabase access/refresh tokens (signed, never logged) so the portal can resolve
# and refresh the principal on each request without re-prompting for a password.
SESSION_ENVELOPE_COOKIE_NAME = "sift_portal_session"
SESSION_ENVELOPE_COOKIE_PATH = "/portal"
SESSION_ENVELOPE_COOKIE_SAME_SITE = "strict"

_ENVELOPE_HEADER_B64 = (
    base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "SIFTENV"}, separators=(",", ":")).encode()
    )
    .rstrip(b"=")
    .decode()
)

# Absolute ceiling on a portal session lifetime, independent of the sliding
# session_max_age and the per-rotation refresh. Once `eiat` (the ORIGINAL
# issued-at, preserved across rotations) is older than this cap, the envelope is
# rejected — so a stolen HttpOnly cookie cannot be refreshed indefinitely even if
# the Gateway refresh callback is lax (C10.3). 12 hours.
ABSOLUTE_ENVELOPE_LIFETIME_SECONDS = 12 * 60 * 60

_HEADER_B64 = (
    base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    .rstrip(b"=")
    .decode()
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def generate_jwt(sub: str, role: str, secret: str, max_age: int = 28800) -> str:
    """Generate a signed portal session JWT.

    Args:
        sub: examiner username
        role: "examiner" or "readonly"
        secret: portal_session_secret from gateway.yaml — 32-byte hex string
        max_age: session lifetime in seconds (default 8h / 28800s)

    Returns:
        Compact JWT string: base64url(header).base64url(payload).base64url(sig)
    """
    now = int(time.time())
    payload = {
        "sub": sub,
        "role": role,
        "iat": now,
        "exp": now + max_age,
        "jti": secrets.token_hex(16),
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{_HEADER_B64}.{payload_b64}"
    sig = _b64url_encode(
        hmac.new(bytes.fromhex(secret), signing_input.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{signing_input}.{sig}"


_revoked_jtis: set[str] = set()


def is_revoked(jti: str) -> bool:
    """Check if a JWT has been revoked (in-memory)."""
    return jti in _revoked_jtis


def verify_jwt(token: str, secret: str) -> dict | None:
    """Verify a portal session JWT and return its payload.

    Returns the payload dict on success, None on any failure (never raises).
    Checks: structure, HMAC-SHA256 signature (timing-safe), expiry, revocation.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = _b64url_encode(
            hmac.new(
                bytes.fromhex(secret), signing_input.encode("ascii"), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(expected_sig, sig_b64):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if not isinstance(payload, dict):
            return None
        jti = payload.get("jti")
        if jti and is_revoked(jti):
            return None
        if payload.get("exp", 0) <= time.time():
            return None
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PR03A — Supabase session envelope (signed cookie carrying token material)
# ---------------------------------------------------------------------------
#
# The envelope is an HMAC-SHA256 signed JSON blob. It is NOT a Supabase JWT: it
# wraps the Supabase access/refresh tokens so the portal can re-validate and
# refresh them on each request. The signature is keyed with the portal session
# secret (same stdlib HMAC approach as the legacy cookie). Token values inside
# the envelope are never logged.
#
# Envelope payload keys:
#   at  -> Supabase access token
#   rt  -> Supabase refresh token
#   exp -> Supabase access-token expiry (int unix seconds)
#   sub -> Supabase JWT subject (auth.users.id)
#   fp  -> non-secret token fingerprint for audit correlation
#   eiat-> envelope issued-at (int unix seconds)


def generate_session_envelope(
    *,
    access_token: str,
    refresh_token: str,
    expires_at: int,
    sub: str,
    fingerprint: str,
    secret: str,
    issued_at: int | None = None,
) -> str:
    """Sign a portal session envelope carrying Supabase token material.

    The returned value is `base64url(header).base64url(payload).base64url(sig)`.
    Token values are embedded but the whole envelope is opaque/signed; never log
    the raw return value or its decoded `at`/`rt` fields.

    ``issued_at`` carries the ORIGINAL session issued-at across cookie rotations
    so the absolute-lifetime ceiling cannot be reset by refreshing. On first login
    leave it None (stamped to now); on rotation pass the prior envelope's `eiat`.
    """
    payload = {
        "at": access_token,
        "rt": refresh_token,
        "exp": int(expires_at),
        "sub": sub,
        "fp": fingerprint,
        "eiat": int(issued_at) if issued_at is not None else int(time.time()),
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{_ENVELOPE_HEADER_B64}.{payload_b64}"
    sig = _b64url_encode(
        hmac.new(bytes.fromhex(secret), signing_input.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{signing_input}.{sig}"


def verify_session_envelope(token: str, secret: str) -> dict | None:
    """Verify a portal session envelope and return its payload.

    Returns the payload dict on success (with `at`/`rt`/`exp`/`sub`/`fp`/`eiat`),
    None on any failure. Never raises. Does NOT check the Supabase access-token
    expiry — that is the resolver's job; the envelope HMAC only proves the cookie
    was issued by this portal and not tampered with.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        if header_b64 != _ENVELOPE_HEADER_B64:
            return None
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = _b64url_encode(
            hmac.new(
                bytes.fromhex(secret), signing_input.encode("ascii"), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(expected_sig, sig_b64):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if not isinstance(payload, dict):
            return None
        if not payload.get("at") or not payload.get("sub"):
            return None
        # Absolute-lifetime ceiling (C10.3): reject envelopes whose ORIGINAL
        # issued-at is older than the cap, regardless of refresh activity. A
        # missing/invalid eiat is treated as expired (fail closed).
        eiat = payload.get("eiat")
        if not isinstance(eiat, (int, float)):
            return None
        if int(time.time()) - int(eiat) > ABSOLUTE_ENVELOPE_LIFETIME_SECONDS:
            return None
        return payload
    except Exception:
        return None
