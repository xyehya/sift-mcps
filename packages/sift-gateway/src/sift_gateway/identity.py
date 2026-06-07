from dataclasses import dataclass
import hashlib
from typing import Any


@dataclass(frozen=True)
class CaseMembership:
    """An immutable operator case membership (PR03A FROZEN CONTRACT C2)."""

    case_id: str
    role: str


@dataclass(frozen=True)
class Identity:
    principal: str
    principal_type: str  # "user" | "agent" | "service"
    token_id: str | None
    agent_id: str | None
    created_by: str | None
    role: str
    source_ip: str | None
    auth_surface: str  # "mcp" | "portal" | "rest"
    case_id: str | None = None
    tool_scopes: frozenset[str] = frozenset()
    token_fingerprint: str | None = None
    # PR03A unified Supabase JWT identity (FROZEN CONTRACT C2 — all additive,
    # defaulted so existing Identity(...) constructors keep working).
    auth_user_id: str | None = None
    principal_id: str | None = None
    system_role: str | None = None
    case_memberships: tuple[CaseMembership, ...] = ()

def _hash_token(token: str) -> str:
    """Return a safe token fingerprint (first 16 hex chars of SHA-256). Never stores raw token."""
    from sift_gateway.token_gen import token_fingerprint

    return token_fingerprint(token)

def resolve_identity(
    token: str | None,
    api_keys: dict[str, dict[str, Any]],
    source_ip: str | None = None,
    auth_surface: str = "mcp",
    token_registry: Any | None = None,
) -> Identity | None:
    if not api_keys and token_registry is None:
        return Identity(
            principal="anonymous",
            principal_type="user",
            token_id=None,
            agent_id=None,
            created_by=None,
            role="examiner",
            source_ip=source_ip,
            auth_surface=auth_surface,
        )
    if token is None:
        return None

    if token_registry is not None:
        record = token_registry.lookup_token(token)
        if record is not None:
            return Identity(
                principal=record.principal,
                principal_type=record.principal_type,
                token_id=record.id,
                agent_id=record.agent_id,
                created_by=record.created_by,
                role=record.role,
                source_ip=source_ip,
                auth_surface=auth_surface,
                case_id=record.case_id,
                tool_scopes=record.scopes,
                token_fingerprint=record.token_fingerprint,
            )

    from sift_gateway.auth import verify_api_key
    key_info = verify_api_key(token, api_keys)
    if key_info is None:
        return None

    role = key_info.get("role", "examiner")
    
    if role == "agent":
        principal_type = "agent"
        principal = key_info.get("agent_id") or key_info.get("examiner", "unknown")
    elif role == "service":
        principal_type = "service"
        principal = key_info.get("examiner", "unknown")
    else:
        principal_type = "user"
        principal = key_info.get("examiner", "unknown")

    return Identity(
        principal=principal,
        principal_type=principal_type,
        token_id=key_info.get("token_id") or _hash_token(token),
        agent_id=key_info.get("agent_id"),
        created_by=key_info.get("created_by"),
        role=role,
        source_ip=source_ip,
        auth_surface=auth_surface,
    )
