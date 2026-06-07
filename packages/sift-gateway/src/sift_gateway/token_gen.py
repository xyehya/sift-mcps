"""Bearer token generation for the sift-mcps gateway."""

import hashlib
import secrets


def generate_gateway_token() -> str:
    """Generate a bearer token for gateway API authentication.

    Format: ``sift_gw_`` prefix + 48 hex characters (192 bits entropy).
    """
    return f"sift_gw_{secrets.token_hex(24)}"


def generate_service_token() -> str:
    """Generate a service bearer token for agent MCP clients (mcp.json).

    Format: ``sift_svc_`` prefix + 48 hex characters (192 bits entropy).
    """
    return f"sift_svc_{secrets.token_hex(24)}"


def token_fingerprint(token: str) -> str:
    """Return the non-secret 16-hex SHA-256 fingerprint for a token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def token_digest(token: str) -> str:
    """Return the full 64-hex SHA-256 digest of a token.

    Used as an internal cache key where the 16-hex fingerprint (64 bits) would be
    collision-prone. Never store the raw token; the digest is one-way.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_hash(token: str, pepper: str) -> str:
    """Return the PR02 peppered registry hash for a token."""
    return hashlib.sha256((pepper + token).encode("utf-8")).hexdigest()
