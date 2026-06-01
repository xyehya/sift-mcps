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

COOKIE_NAME = "sift_session"
COOKIE_PATH = "/portal"
COOKIE_SAME_SITE = "strict"

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


def revoke_jti(jti: str) -> None:
    """Revoke a JWT by its JTI (in-memory)."""
    _revoked_jtis.add(jti)


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
