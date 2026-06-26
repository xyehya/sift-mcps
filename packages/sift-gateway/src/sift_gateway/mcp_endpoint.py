"""MCP transport helpers for the sift-mcps gateway."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token, get_http_request
from mcp.types import TextContent, Tool
from sift_common.instructions import GATEWAY as _GATEWAY_INSTRUCTIONS
from starlette.responses import JSONResponse

from sift_gateway.rate_limit import check_examiner_rate_limit, check_rate_limit

logger = logging.getLogger(__name__)

# Maximum MCP request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024


_LAST_429_AUDIT: dict[str, float] = {}
_429_AUDIT_INTERVAL = 5.0  # limit to one audit log entry per 5 seconds per key/IP


def _hash_token(token: str) -> str:
    """Compatibility wrapper for the shared non-secret token fingerprint."""
    from sift_gateway.token_gen import token_fingerprint

    return token_fingerprint(token)


def _build_gateway_instructions(gateway: Any) -> str:
    """Compose aggregate /mcp instructions from core policy + add-on manifests."""
    addon_lines: list[str] = []
    for backend_name, backend in sorted(getattr(gateway, "backends", {}).items()):
        manifest = getattr(backend, "manifest", None)
        if not manifest:
            continue

        reqs = manifest.get("capabilities", {}).get("requires", [])
        unmet = [req for req in reqs if not gateway.evaluate_requirement(req)]
        if unmet:
            addon_lines.append(
                f"- {backend_name}: configured but currently unavailable "
                f"(unmet requires: {', '.join(unmet)})."
            )
            continue

        provides = manifest.get("capabilities", {}).get("provides", [])
        tools = manifest.get("tools", [])
        categories = sorted({
            str(tool.get("category", ""))
            for tool in tools
            if tool.get("category")
        })
        phases = sorted({
            str(tool.get("recommended_phase", ""))
            for tool in tools
            if tool.get("recommended_phase")
        })
        health = manifest.get("health", "")
        line = (
            f"- {backend_name}: provides {', '.join(provides) or 'unspecified'}; "
            f"{len(tools)} declared tools"
        )
        if categories:
            line += f"; categories: {', '.join(categories)}"
        if phases:
            line += f"; phases: {', '.join(phases)}"
        if health:
            line += f"; health: {health}"
        line += "."
        addon_lines.append(line)

    if not addon_lines:
        addon_text = (
            "No add-on backend is currently configured and requirement-satisfied. "
            "Use core tools only unless tools/list shows add-on tools."
        )
    else:
        addon_text = "\n".join(addon_lines)

    return (
        f"{_GATEWAY_INSTRUCTIONS}\n\n"
        "ADD-ON MANIFEST SUMMARY:\n"
        "This section is generated from loaded sift-backend.json manifests and "
        "current requires[] checks at gateway startup. For live backend health "
        "and the exact tool surface, call case_info, capability_guide, "
        "and tools/list.\n"
        f"{addon_text}"
    )


def _backend_manifest_instructions(backend: Any) -> str | None:
    manifest = getattr(backend, "manifest", None)
    if not manifest:
        return None
    text = manifest.get("_resolved_instructions") or manifest.get("instructions")
    if isinstance(text, str) and text.strip():
        return text
    return None


def log_rate_limit_violation(gateway: Any, key: str, client_ip: str, identity: Any = None):
    now = time.monotonic()
    last_log = _LAST_429_AUDIT.get(key, 0.0)
    if now - last_log >= _429_AUDIT_INTERVAL:
        _LAST_429_AUDIT[key] = now
        extra = {
            "source_ip": client_ip,
            "status": "rate_limited",
        }
        if identity:
            extra.update({
                "principal": identity.principal,
                "principal_type": identity.principal_type,
                "agent_id": identity.agent_id,
                "created_by": identity.created_by,
                "auth_surface": identity.auth_surface,
                "role": identity.role,
                "token_id": identity.token_id,
            })
        else:
            extra.update({
                "principal": "anonymous",
                "principal_type": "user",
                "auth_surface": "mcp",
                "role": "unknown",
            })
        
        if gateway and hasattr(gateway, "_audit"):
            try:
                gateway._audit.log(
                    tool="rate_limit",
                    params={},
                    result_summary="rate_limited",
                    source="gateway_rate_limiter",
                    extra=extra
                )
            except Exception as exc:
                logger.warning("Failed to write rate limit audit: %s", exc)


# ---------------------------------------------------------------------------
# ASGI-level auth wrapper
# ---------------------------------------------------------------------------


class SiftTokenVerifier(TokenVerifier):
    """FastMCP token verifier — Supabase JWT is the sole credential authority.

    PR03A (D30): a Supabase-issued JWT is validated through the shared
    :class:`SupabaseIdentityResolver` and mapped to a SIFT app principal.

    SEC-6 (DSS-CAN-015): the legacy PR02 hash-token registry and
    ``gateway.yaml`` api-key fallback have been removed entirely — a legacy
    token never authenticates on ``/mcp`` and is never granted the ``mcp:*``
    wildcard. Identity resolution happens HERE (not in the raw ASGI guard),
    closing B-14: the normal ``/mcp`` path does exactly one token lookup. A
    Supabase outage fails closed (the token is denied; there is no fallback).
    """

    def __init__(
        self,
        *,
        api_keys: dict[str, dict] | None = None,
        token_registry: Any | None = None,
        base_url: str | None = None,
        resolver: Any | None = None,
    ) -> None:
        super().__init__(base_url=base_url, required_scopes=None)
        self.api_keys = api_keys or {}
        self.token_registry = token_registry
        self.resolver = resolver

    async def verify_token(self, token: str) -> AccessToken | None:
        identity = None

        # Supabase JWT is the SOLE credential authority (SEC-6). No legacy PR02 /
        # api-key fallback: an outage or a bad token both deny.
        if self.resolver is not None:
            from sift_gateway.supabase_auth import (
                SupabaseAuthError,
                SupabaseUnavailableError,
            )

            try:
                identity = await self.resolver.resolve(token, auth_surface="mcp")
            except SupabaseUnavailableError:
                # An auth-backend outage is not a valid token. With no legacy
                # fallback we FAIL CLOSED (deny). No token material in the log.
                logger.warning(
                    "MCP verify_token: Supabase auth backend unavailable; "
                    "failing closed (deny)"
                )
                identity = None
            except SupabaseAuthError:
                # Invalid/expired/unmapped/disabled/ambiguous — normal denial.
                identity = None
            except Exception:  # unexpected transport error — deny, no token in log
                logger.warning("MCP verify_token: unexpected resolver error; denying")
                identity = None

        if identity is None:
            return None

        # Readonly principals may not call MCP tools.
        if getattr(identity, "role", None) == "readonly":
            return None

        # B-10: a principal with no active tool scope grants nothing. SEC-6: there
        # is no longer an mcp:* compatibility default — scopes come solely from the
        # DB-backed principal_tool_scopes carried on the resolved identity.
        scopes = sorted(identity.tool_scopes) if identity.tool_scopes else []

        return AccessToken(
            token=token,
            client_id=identity.token_id or identity.principal,
            scopes=scopes,
            claims={
                "sift_identity": _identity_to_claims(identity),
            },
        )


def _identity_to_claims(identity: Any) -> dict:
    return {
        "principal": identity.principal,
        "principal_type": identity.principal_type,
        "token_id": identity.token_id,
        "agent_id": identity.agent_id,
        "created_by": identity.created_by,
        "role": identity.role,
        "source_ip": identity.source_ip,
        "auth_surface": identity.auth_surface,
        "case_id": identity.case_id,
        "tool_scopes": sorted(identity.tool_scopes),
        "token_fingerprint": identity.token_fingerprint,
        "auth_user_id": getattr(identity, "auth_user_id", None),
        "principal_id": getattr(identity, "principal_id", None),
        "system_role": getattr(identity, "system_role", None),
        "case_memberships": [
            {"case_id": m.case_id, "role": m.role}
            for m in getattr(identity, "case_memberships", ()) or ()
        ],
    }


def _identity_from_claims(claims: dict | None, *, source_ip: str | None = None):
    if not claims:
        return None
    data = claims.get("sift_identity") if "sift_identity" in claims else claims
    if not isinstance(data, dict):
        return None
    from sift_gateway.identity import CaseMembership, Identity

    memberships = tuple(
        CaseMembership(case_id=str(m.get("case_id")), role=str(m.get("role")))
        for m in (data.get("case_memberships") or [])
        if isinstance(m, dict) and m.get("case_id") is not None
    )
    return Identity(
        principal=str(data.get("principal") or "unknown"),
        principal_type=str(data.get("principal_type") or "agent"),
        token_id=data.get("token_id"),
        agent_id=data.get("agent_id"),
        created_by=data.get("created_by"),
        role=str(data.get("role") or "agent"),
        source_ip=source_ip or data.get("source_ip"),
        auth_surface=str(data.get("auth_surface") or "mcp"),
        case_id=data.get("case_id"),
        tool_scopes=frozenset(data.get("tool_scopes") or ()),
        token_fingerprint=data.get("token_fingerprint"),
        auth_user_id=data.get("auth_user_id"),
        principal_id=data.get("principal_id"),
        system_role=data.get("system_role"),
        case_memberships=memberships,
    )


def current_mcp_identity() -> Any | None:
    """Return the SIFT identity for the current FastMCP request when available."""
    source_ip: str | None = None
    try:
        request = get_http_request()
        state_identity = getattr(request.state, "identity", None)
        source_ip = getattr(request.state, "source_ip", None)
        if state_identity is not None:
            return state_identity
    except RuntimeError:
        pass

    access_token = get_access_token()
    if access_token is None:
        return None
    return _identity_from_claims(access_token.claims, source_ip=source_ip)


class MCPAuthASGIApp:
    """ASGI connection guard for the MCP mount.

    We cannot use Starlette's ``BaseHTTPMiddleware`` for the ``/mcp`` route
    because it buffers responses and breaks SSE streaming.  Instead this thin
    ASGI wrapper enforces connection-level policy, sets identity on
    ``scope["state"]`` for downstream policy middleware, and delegates to the
    FastMCP ASGI app.
    """

    def __init__(
        self,
        app: Any,
        api_keys: dict[str, dict] | None = None,
        allowed_origins: set[str] | None = None,
        examiner_calls_per_minute: int = 120,
        gateway: Any | None = None,
        token_registry: Any | None = None,
        verifier_owns_identity: bool = False,
    ):
        self.app = app
        self.api_keys = api_keys or {}
        self.allowed_origins = allowed_origins or set()
        self.gateway = gateway
        self.token_registry = token_registry
        # B-14: when the FastMCP TokenVerifier owns identity resolution, this raw
        # ASGI guard keeps ONLY identity-free connection guards (IP rate limit,
        # body-size cap, Origin allow-list, path normalization) and does NOT
        # perform a second PR02/Supabase token lookup on the normal path.
        self.verifier_owns_identity = verifier_owns_identity
        # Initialize the examiner rate limiter singleton with configured limit
        from sift_gateway.rate_limit import get_examiner_rate_limiter
        get_examiner_rate_limiter(limit=examiner_calls_per_minute)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        # Ensure scope["state"] exists
        scope.setdefault("state", {})

        # Rate limit check (before auth or any processing).
        # Extract real client IP — check X-Forwarded-For for reverse proxy setups.
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        # Trust X-Forwarded-For only from localhost (proxy on same machine)
        if client_ip in ("127.0.0.1", "::1"):
            headers = dict(scope.get("headers", []))
            forwarded = headers.get(b"x-forwarded-for", b"").decode()
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()
        if not check_rate_limit(client_ip):
            log_rate_limit_violation(self.gateway, f"ip:{client_ip}", client_ip)
            resp = JSONResponse(
                {"error": "Rate limit exceeded"},
                status_code=429,
            )
            await resp(scope, receive, send)
            return

        # Request size validation via Content-Length header
        content_length = _get_content_length(scope)
        if content_length is None and scope.get("method", "") == "POST":
            resp = JSONResponse(
                {"error": "Content-Length header required"},
                status_code=411,
            )
            await resp(scope, receive, send)
            return
        if content_length is not None and content_length > _MAX_REQUEST_BYTES:
            resp = JSONResponse(
                {"error": f"Request body too large (max {_MAX_REQUEST_BYTES} bytes)"},
                status_code=413,
            )
            await resp(scope, receive, send)
            return

        # Origin validation: browser requests set Origin; Hermes/curl do not.
        # Reject cross-origin browser requests to prevent CSRF via the MCP endpoint.
        if self.allowed_origins:
            raw_headers = dict(scope.get("headers", []))
            origin = raw_headers.get(b"origin", b"").decode("latin-1", errors="replace")
            if origin and origin not in self.allowed_origins:
                resp = JSONResponse({"error": "Forbidden"}, status_code=403)
                await resp(scope, receive, send)
                return

        # B-14: when the FastMCP TokenVerifier owns identity, do NOT resolve the
        # token here. Connection-level guards (IP/body/Origin) already ran above.
        # Per-principal rate limiting, readonly/scope checks, and identity
        # resolution happen in the verifier + SIFT policy middleware (post-auth).
        if self.verifier_owns_identity:
            await self._delegate(scope, receive, send)
            return

        from sift_gateway.identity import resolve_identity
        if not self.api_keys and self.token_registry is None:
            # No keys configured — single-user / anonymous mode
            identity = resolve_identity(None, self.api_keys, source_ip=client_ip, auth_surface="mcp")
            scope["state"]["identity"] = identity
            scope["state"]["examiner"] = identity.principal
            scope["state"]["role"] = identity.role
            scope["state"]["source_ip"] = identity.source_ip
            scope["state"]["token_id"] = identity.token_id
            if not check_examiner_rate_limit("anonymous"):
                log_rate_limit_violation(self.gateway, "examiner:anonymous", client_ip, identity)
                resp = JSONResponse({"error": "Rate limit exceeded"}, status_code=429)
                await resp(scope, receive, send)
                return
            await self._delegate(scope, receive, send)
            return

        # Extract and verify bearer token
        token = _extract_bearer_token(scope)
        if token is None:
            resp = JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )
            await resp(scope, receive, send)
            return

        identity = resolve_identity(
            token,
            self.api_keys,
            source_ip=client_ip,
            auth_surface="mcp",
            token_registry=self.token_registry,
        )
        if identity is None:
            logger.warning("MCP endpoint: rejected invalid or expired token")
            resp = JSONResponse({"error": "Invalid API key"}, status_code=403)
            await resp(scope, receive, send)
            return

        if identity.role == "readonly":
            resp = JSONResponse(
                {"error": "Readonly role cannot call MCP tools"},
                status_code=403,
            )
            await resp(scope, receive, send)
            return
        scope["state"]["identity"] = identity
        scope["state"]["examiner"] = identity.principal
        scope["state"]["role"] = identity.role
        scope["state"]["source_ip"] = identity.source_ip
        scope["state"]["token_id"] = identity.token_id

        # Per-examiner post-auth rate limit
        if not check_examiner_rate_limit(identity.principal):
            log_rate_limit_violation(self.gateway, f"examiner:{identity.principal}", client_ip, identity)
            resp = JSONResponse({"error": "Rate limit exceeded"}, status_code=429)
            await resp(scope, receive, send)
            return

        await self._delegate(scope, receive, send)
        return

    async def _delegate(self, scope: dict, receive: Any, send: Any) -> None:
        if hasattr(self.app, "handle_request"):
            await self.app.handle_request(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _stamp_identity_extra(extra: dict, identity: Any, examiner: str | None = None) -> dict:
    """Stamp universal-identity fields (F-F) onto an audit ``extra`` dict.

    When an :class:`Identity` is present, attribution comes from it; otherwise
    fall back to the flat ``examiner`` (anonymous/single-user mode). Mutates and
    returns ``extra`` for convenience.
    """
    if identity:
        extra.update({
            "principal": identity.principal,
            "principal_type": identity.principal_type,
            "agent_id": identity.agent_id,
            "created_by": identity.created_by,
            "auth_surface": identity.auth_surface,
        })
    else:
        extra.update({
            "principal": examiner or "anonymous",
            "principal_type": "user",
            "auth_surface": "mcp",
        })
    return extra


def _extract_request_context(_server: Any = None) -> dict:
    """Pull examiner, role, token_id, source_ip, and identity from FastMCP context."""
    if _server is not None:
        try:
            ctx = _server.request_context
            request = getattr(ctx, "request", None)
            if request is not None:
                state = request.state
                identity = getattr(state, "identity", None)
                if identity is not None:
                    return {
                        "examiner": identity.principal,
                        "role": identity.role,
                        "token_id": identity.token_id,
                        "source_ip": identity.source_ip,
                        "identity": identity,
                    }
                examiner = getattr(state, "examiner", None) or getattr(
                    state, "analyst", None
                )
                return {
                    "examiner": examiner,
                    "role": getattr(state, "role", "unknown"),
                    "token_id": getattr(state, "token_id", None),
                    "source_ip": getattr(state, "source_ip", None),
                    "identity": None,
                }
        except LookupError:
            pass

    identity = current_mcp_identity()
    if identity is not None:
        return {
            "examiner": identity.principal,
            "role": identity.role,
            "token_id": identity.token_id,
            "source_ip": identity.source_ip,
            "identity": identity,
        }

    try:
        request = get_http_request()
        state = request.state
        examiner = getattr(state, "examiner", None) or getattr(state, "analyst", None)
        return {
            "examiner": examiner,
            "role": getattr(state, "role", "unknown"),
            "token_id": getattr(state, "token_id", None),
            "source_ip": getattr(state, "source_ip", None),
            "identity": getattr(state, "identity", None),
        }
    except RuntimeError:
        return {
            "examiner": None,
            "role": "unknown",
            "token_id": None,
            "source_ip": None,
            "identity": None,
        }


def _build_case_context(case_dir_str: str) -> dict | None:
    """Build gateway-injected case context for aggregate MCP responses."""
    if not case_dir_str:
        return None
    case_dir = Path(case_dir_str).resolve()
    case_id = case_dir.name
    meta_path = case_dir / "CASE.yaml"
    if meta_path.exists():
        try:
            meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
            case_id = str(meta.get("case_id") or case_id)
        except (OSError, yaml.YAMLError):
            pass
    # F-MVP-2: appended to agent-facing MCP responses after the response guard,
    # so it must be agent-safe at the source — opaque case id + relative display
    # dirs only, never the absolute /cases/... artifact path.
    return {
        "id": case_id,
        "evidence_dir": "evidence",
        "agent_dir": "agent",
    }


def _append_case_context(contents: list[TextContent], case_dir_str: str, tool_name: str | None = None) -> list[TextContent]:
    """Append _case metadata as gateway response middleware."""
    context = _build_case_context(case_dir_str)
    if context is None:
        return contents
    if tool_name in ["case_info"]:
        return contents + [
            TextContent(type="text", text=json.dumps({"_case": context}, indent=2))
        ]
    return contents


def _get_content_length(scope: dict) -> int | None:
    """Extract Content-Length from raw ASGI scope headers. Returns None if absent or invalid."""
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"content-length":
            try:
                return int(value.decode("latin-1"))
            except (ValueError, OverflowError, UnicodeDecodeError):
                return None
    return None


def _extract_bearer_token(scope: dict) -> str | None:
    """Pull the bearer token from raw ASGI scope headers."""
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"authorization":
            try:
                decoded = value.decode("latin-1")
            except (UnicodeDecodeError, AttributeError):
                logger.warning("MCP endpoint: failed to decode authorization header")
                return None
            if decoded.lower().startswith("bearer "):
                return decoded[7:].strip()
    return None


# ---------------------------------------------------------------------------
# Synthetic gateway tools
# ---------------------------------------------------------------------------


_CORE_TOOLS_SUMMARY: dict | None = None


def _core_tools_summary() -> dict:
    """Compact availability summary of core forensic tools (cached per-process).

    Installed binaries do not change mid-run, so the inventory probe runs at
    most once per process. Never includes absolute binary paths.
    """
    global _CORE_TOOLS_SUMMARY
    if _CORE_TOOLS_SUMMARY is not None:
        return _CORE_TOOLS_SUMMARY
    try:
        from sift_core.execute.tools.discovery import build_tool_inventory

        inventory = build_tool_inventory()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("core tool inventory unavailable: %s", exc)
        return {"error": "core tool inventory unavailable"}

    available_by_category: dict[str, list[str]] = {}
    missing: list[str] = []
    for tool in inventory.get("tools", []):
        if tool.get("available"):
            category = tool.get("category") or "uncategorized"
            available_by_category.setdefault(category, []).append(tool["name"])
        else:
            missing.append(tool["name"])

    _CORE_TOOLS_SUMMARY = {
        "total_cataloged": inventory.get("total_cataloged", 0),
        "total_available": inventory.get("total_available", 0),
        "available_by_category": {
            category: sorted(names)
            for category, names in sorted(available_by_category.items())
        },
        "missing": sorted(missing),
        "hint": (
            "Full inventory incl. allowlisted-but-uncataloged binaries: "
            "get_tool_help('inventory')."
        ),
    }
    return _CORE_TOOLS_SUMMARY


def _capability_guide(gateway: Any) -> dict:
    """Build a live manifest-derived guide for currently usable add-on tools."""
    available = set(getattr(gateway, "_available_backends", set()))
    meta_index: dict[str, dict] = getattr(gateway, "_tool_manifest_meta", {})
    guide: dict[str, Any] = {
        "platform": "sift-mcps",
        "purpose": (
            "ADD-ON backend capabilities only, from enabled requirement-satisfied "
            "manifests, plus a compact core_tools availability summary. For core "
            "tool usage details use get_tool_help; for the full installed-binary "
            "inventory use get_tool_help('inventory'). Use tools/list "
            "for exact input schemas before calling a tool."
        ),
        "scope": "add-on backends only",
        "core_tools": _core_tools_summary(),
        "available_backends": [],
        "unavailable_backends": [],
        "groups": {
            "by_provides": {},
            "by_category": {},
            "by_recommended_phase": {},
        },
    }

    for backend_name, backend in sorted(getattr(gateway, "backends", {}).items()):
        manifest = getattr(backend, "manifest", None)
        if not manifest:
            continue

        reqs = list(manifest.get("capabilities", {}).get("requires", []))
        unmet = [req for req in reqs if not gateway.evaluate_requirement(req)]
        if backend_name not in available or unmet:
            guide["unavailable_backends"].append({
                "backend": backend_name,
                "status": "unavailable",
                "unmet_requires": unmet,
            })
            continue

        provides = list(manifest.get("capabilities", {}).get("provides", []))
        tool_entries: list[dict] = []
        for decl in manifest.get("tools", []):
            tool_name = decl.get("name")
            if not tool_name or tool_name not in meta_index:
                continue
            meta = meta_index[tool_name]
            if meta.get("hidden_from_agent"):
                continue

            entry = {
                "name": tool_name,
                "description": decl.get("description", ""),
                "category": meta.get("category", ""),
                "recommended_phase": meta.get("recommended_phase", ""),
                "health": bool(meta.get("health")),
                "when_to_use": decl.get("when_to_use", ""),
                "avoid_when": decl.get("avoid_when", ""),
                "output_notes": decl.get("output_notes", ""),
            }
            tool_entries.append({k: v for k, v in entry.items() if v not in ("", None)})

            for provided in provides:
                guide["groups"]["by_provides"].setdefault(provided, []).append(tool_name)
            category = meta.get("category")
            if category:
                guide["groups"]["by_category"].setdefault(category, []).append(tool_name)
            phase = meta.get("recommended_phase")
            if phase:
                guide["groups"]["by_recommended_phase"].setdefault(phase, []).append(tool_name)

        health_tool = manifest.get("health")
        guide["available_backends"].append({
            "backend": backend_name,
            "provides": provides,
            "requires": reqs,
            "unmet_requires": [],
            "health_tool": health_tool,
            "instructions": _backend_manifest_instructions(backend) or "",
            "tools": tool_entries,
        })

    for groups in guide["groups"].values():
        for key, names in list(groups.items()):
            groups[key] = sorted(set(names))

    if not guide["available_backends"]:
        guide["note"] = (
            "No add-on backend is registered — this is the expected default, not "
            "an error. Core forensic tools are available via run_command and get_tool_help."
        )
    return guide


async def _handle_capability_guide(gateway: Any) -> Sequence[TextContent]:
    return [
        TextContent(
            type="text",
            text=json.dumps(_capability_guide(gateway), indent=2, default=str),
        )
    ]


def _extract_dict_from_tool_result(result: list) -> dict:
    """Pull a dict out of TextContent tool results."""
    for item in result:
        text = getattr(item, "text", "")
        if text and text.strip().startswith("{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
    return {"raw": str(result)[:1000]}
