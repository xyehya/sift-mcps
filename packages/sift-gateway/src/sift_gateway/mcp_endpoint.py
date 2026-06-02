"""Streamable HTTP MCP endpoint for the sift-mcps gateway.

Exposes the gateway's aggregated tools via the MCP protocol using a
low-level ``Server`` that proxies through the gateway's existing backend
infrastructure.  The ``StreamableHTTPSessionManager`` provides ASGI
request handling; we wrap it with an auth layer and mount it as a route
in the Starlette app.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import TextContent, Tool
from sift_common.instructions import (
    FORENSIC_MCP,
    FORENSIC_RAG,
    OPENCTI,
    OPENSEARCH,
    WINDOWS_TRIAGE,
)
from sift_common.instructions import GATEWAY as _GATEWAY_INSTRUCTIONS
from starlette.requests import Request
from starlette.responses import JSONResponse

from sift_gateway.audit_helpers import _extract_audit_id, _summarize_result, _truncate_params
from sift_gateway.evidence_gate import (
    build_block_response,
    check_evidence_gate,
)
from sift_gateway.identity import _hash_token  # re-exported for callers/tests
from sift_gateway.rate_limit import check_examiner_rate_limit, check_rate_limit
from sift_gateway.response_guard import (
    cap_tool_result,
    get_override_status,
    is_override_active,
    output_cap_bytes,
    redact_tool_result,
)

logger = logging.getLogger(__name__)

# Static instruction map for known local backends.
# Used by create_backend_mcp_server() so per-backend MCP endpoints deliver
# backend-specific instructions to clients during the Initialize handshake,
# regardless of whether the backend subprocess has started yet.
_BACKEND_INSTRUCTIONS: dict[str, str] = {
    "forensic-mcp": FORENSIC_MCP,
    "forensic-rag-mcp": FORENSIC_RAG,
    "windows-triage-mcp": WINDOWS_TRIAGE,
    "opencti-mcp": OPENCTI,
    "opensearch-mcp": OPENSEARCH,
}

# Maximum MCP request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024


_LAST_429_AUDIT: dict[str, float] = {}
_429_AUDIT_INTERVAL = 5.0  # limit to one audit log entry per 5 seconds per key/IP

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


class MCPAuthASGIApp:
    """ASGI app that authenticates requests then delegates to the session manager.

    We cannot use Starlette's ``BaseHTTPMiddleware`` for the ``/mcp`` route
    because it buffers responses and breaks SSE streaming.  Instead this thin
    ASGI wrapper reads the ``Authorization`` header from the raw scope,
    performs timing-safe key lookup, sets identity on ``scope["state"]``,
    and delegates to ``session_manager.handle_request``.
    """

    def __init__(
        self,
        session_manager: StreamableHTTPSessionManager,
        api_keys: dict[str, dict] | None = None,
        allowed_origins: set[str] | None = None,
        examiner_calls_per_minute: int = 120,
        gateway: Any | None = None,
    ):
        self.session_manager = session_manager
        self.api_keys = api_keys or {}
        self.allowed_origins = allowed_origins or set()
        self.gateway = gateway
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

        from sift_gateway.identity import resolve_identity
        if not self.api_keys:
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
            await self.session_manager.handle_request(scope, receive, send)
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

        identity = resolve_identity(token, self.api_keys, source_ip=client_ip, auth_surface="mcp")
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

        await self.session_manager.handle_request(scope, receive, send)
        return


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


def _extract_request_context(server: Server) -> dict:
    """Pull examiner, role, token_id, source_ip, and identity from the current MCP request context."""
    result: dict = {"examiner": None, "role": "unknown", "token_id": None, "source_ip": None, "identity": None}
    try:
        ctx = server.request_context
        request: Request | None = ctx.request
        if request is not None:
            state = request.state
            identity = getattr(state, "identity", None)
            result["identity"] = identity
            if identity is not None:
                result["examiner"] = identity.principal
                result["role"] = identity.role
                result["token_id"] = identity.token_id
                result["source_ip"] = identity.source_ip
            else:
                examiner = getattr(state, "examiner", None) or getattr(state, "analyst", None)
                result["examiner"] = examiner
                result["role"] = getattr(state, "role", "unknown")
                result["token_id"] = getattr(state, "token_id", None)
                result["source_ip"] = getattr(state, "source_ip", None)
    except LookupError:
        pass
    return result


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
    return {
        "id": case_id,
        "dir": str(case_dir),
        "evidence_dir": str(case_dir / "evidence"),
        "agent_dir": str(case_dir / "agent"),
    }


def _append_case_context(contents: list[TextContent], case_dir_str: str) -> list[TextContent]:
    """Append _case metadata as gateway response middleware."""
    context = _build_case_context(case_dir_str)
    if context is None:
        return contents
    return contents + [
        TextContent(type="text", text=json.dumps({"_case": context}, indent=2))
    ]


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

# In-process core status tools always included in the environment summary.
# Add-on health tools are discovered from each backend's manifest (a tool
# declared with ``"health": true``) — the gateway hardcodes no add-on name.
_CORE_ENV_SUMMARY_TOOLS: list[tuple[str, str, dict]] = [
    ("case_status", "sift-core", {}),
    ("evidence_list", "sift-core", {}),
    ("list_available_tools", "sift-core", {}),
]


def _env_summary_tools(gateway: Any) -> list[tuple[str, str, dict]]:
    """Core status tools + each available backend's manifest-declared health tool."""
    tools = list(_CORE_ENV_SUMMARY_TOOLS)
    meta_index: dict[str, dict] = getattr(gateway, "_tool_manifest_meta", {})
    for tool_name, meta in meta_index.items():
        if meta.get("health"):
            tools.append(
                (tool_name, meta.get("backend", ""), meta.get("health_args", {}))
            )
    return tools


async def _handle_environment_summary(gateway: Any) -> Sequence[TextContent]:
    """Call health/status tools from every backend and aggregate results."""
    summary: dict = {
        "platform": "sift-mcps",
        "backends": {},
        "degraded": [],
        "unavailable": [],
    }

    for tool_name, backend_name, args in _env_summary_tools(gateway):
        try:
            result = await asyncio.wait_for(
                gateway.call_tool(tool_name, args),
                timeout=8.0,
            )
            # Normalise result to dict
            parsed = _extract_dict_from_tool_result(result) if isinstance(result, list) else result
            summary["backends"][backend_name] = {
                "status": "healthy",
                "tool": tool_name,
                "result": parsed,
            }
        except asyncio.TimeoutError:
            summary["backends"][backend_name] = {"status": "degraded", "error": "timeout"}
            summary["degraded"].append(backend_name)
        except Exception as e:
            summary["backends"][backend_name] = {"status": "unavailable", "error": str(e)[:200]}
            summary["unavailable"].append(backend_name)

    summary["verdict"] = (
        "ready" if not summary["unavailable"]
        else "degraded" if summary["degraded"]
        else "impaired"
    )

    return [TextContent(type="text", text=json.dumps(summary, indent=2, default=str))]


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


# ---------------------------------------------------------------------------
# MCP server factory
# ---------------------------------------------------------------------------


def create_mcp_server(gateway: Any) -> Server:
    """Build a low-level MCP ``Server`` that proxies through *gateway*.

    ``@server.list_tools()`` aggregates tools from all backends (with
    collision-prefixed names).  ``@server.call_tool()`` routes to the
    correct backend, injecting analyst identity from the HTTP request.
    """
    server = Server("sift-gateway", instructions=_GATEWAY_INSTRUCTIONS)

    # Core-policy agent-view filter: portal-managed in-process tools.
    # Add-on tools opt out of the agent view via their manifest
    # (``"hidden_from_agent": true``) — the gateway lists no add-on name here.
    _AGENT_FILTERED_TOOLS: frozenset[str] = frozenset({
        "evidence_register",  # portal-only — always returns remediation block
    })

    # Categories / phase hints for IN-PROCESS CORE + gateway-synthetic tools only.
    # Add-on tools carry their own ``category`` / ``recommended_phase`` in the
    # backend manifest (Phase 6.1) — no add-on tool name appears in core code.
    _CORE_TOOL_CATEGORIES: dict[str, str] = {
        # ── session-start: first calls every session ──
        "workflow_status": "session-start",
        "environment_summary": "session-start",
        "case_status": "session-start",
        "case_file_structure": "session-start",
        # ── evidence-survey: inspect evidence before ingest ──
        "evidence_list": "evidence-survey",
        "evidence_verify": "evidence-survey",
        "audit_summary": "evidence-survey",
        # ── detection: forensic tool execution ──
        "list_available_tools": "detection",
        "get_tool_help": "detection",
        "check_tools": "detection",
        "suggest_tools": "detection",
        "run_command": "detection",
        # ── findings: record and review findings ──
        "record_finding": "findings",
        "record_timeline_event": "findings",
        "list_existing_findings": "findings",
        "query_case": "findings",
        "manage_todo": "findings",
        "log_reasoning": "findings",
        "log_external_action": "findings",
        "record_action": "findings",
        # Reporting + case-metadata are portal-owned (F-E) and bundle
        # export/import is dropped from the agent surface (F-C) — not agent tools.
        # ── admin: maintenance operations ──
        "backup_case": "admin",
        "open_case_dashboard": "admin",
    }

    # Recommend core/synthetic tools per investigation phase.
    _CORE_TOOL_PHASES: dict[str, str] = {
        # ORIENT: fresh case — understand what we have
        "workflow_status": "ORIENT",
        "environment_summary": "ORIENT",
        "case_status": "ORIENT",
        "case_list": "ORIENT",
        "case_file_structure": "ORIENT",
        "evidence_list": "ORIENT",
        "evidence_verify": "ORIENT",
        "audit_summary": "ORIENT",
        # TRIAGE: evidence indexed — start analysis
        "run_command": "TRIAGE",
        "suggest_tools": "TRIAGE",
        "list_available_tools": "TRIAGE",
        "get_tool_help": "TRIAGE",
        "check_tools": "TRIAGE",
        # FINDINGS: stage and review findings
        "record_finding": "FINDINGS",
        "record_timeline_event": "FINDINGS",
        "list_existing_findings": "FINDINGS",
        "query_case": "FINDINGS",
        "manage_todo": "FINDINGS",
        "log_reasoning": "FINDINGS",
        "log_external_action": "FINDINGS",
        "record_action": "FINDINGS",
        # REPORTING phase is examiner-driven in the portal (F-E); no agent
        # report tools remain to recommend here.
    }

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        tools = await gateway.get_tools_list()
        # Manifest-declared UX metadata for add-on tools (rebuilt per tool-map).
        manifest_meta: dict[str, dict] = getattr(gateway, "_tool_manifest_meta", {})
        hidden_addon_tools = {
            n for n, m in manifest_meta.items() if m.get("hidden_from_agent")
        }
        # Filter portal-only core tools + manifest-flagged add-on tools from agent view
        tools = [
            t for t in tools
            if t.name not in _AGENT_FILTERED_TOOLS and t.name not in hidden_addon_tools
        ]
        # Synthetic gateway-level tool — add before annotation loop so meta gets set
        tools.append(Tool(
            name="environment_summary",
            description="Single-call environment overview. Collapses case_status, evidence_list, available core tooling, and the health tool each enabled add-on declares in its manifest into one response. Call this after workflow_status for a complete picture of platform readiness.",
            inputSchema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True},
        ))
        # Annotate with category + recommended phase. Core/synthetic tools use the
        # core hint maps; add-on tools use their backend manifest declaration.
        for t in tools:
            addon_meta = manifest_meta.get(t.name, {})
            category = _CORE_TOOL_CATEGORIES.get(t.name) or addon_meta.get("category", "")
            phase = _CORE_TOOL_PHASES.get(t.name) or addon_meta.get("recommended_phase", "")
            meta = dict(t.meta) if t.meta else {}
            if category:
                meta["category"] = category
            if phase:
                meta["recommended_for_phase"] = phase
            if meta:
                t.meta = meta
        return tools

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
        req_ctx = _extract_request_context(server)
        examiner = req_ctx["examiner"]
        identity = req_ctx["identity"]
        _effective_principal = identity.principal if identity else examiner

        _start = time.monotonic()
        _status = "ok"
        _backend_audit_id: str | None = None
        _final_contents: list[TextContent] = []
        _block_audited = False  # gate writes its own richer line; skip the envelope

        try:
            # Evidence chain gate — binary F-A block-all. Applies to EVERY agent
            # tool, including the synthetic environment_summary: UNSEALED and
            # every non-OK status block all agent tools until the examiner
            # re-seals the chain in the portal.
            case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
            gate = check_evidence_gate(case_dir_str)
            if gate["blocked"]:
                _status = "blocked"
                _block_audited = True
                gate_status = gate["status"]
                extra_fields = _stamp_identity_extra({
                    "role": req_ctx["role"],
                    "token_id": req_ctx["token_id"],
                    "source_ip": req_ctx["source_ip"],
                    "evidence_chain_status": gate_status,
                    "issues": gate["issues"],
                    "manifest_version": gate["manifest_version"],
                }, identity, examiner)

                try:
                    await asyncio.to_thread(
                        gateway._audit.log,
                        tool=name,
                        params={},
                        result_summary=f"blocked: evidence_chain_{gate_status}",
                        source="gateway_evidence_gate",
                        extra=extra_fields,
                        examiner_override=_effective_principal,
                    )
                except Exception as exc:
                    logger.warning("evidence_gate: audit write failed: %s", exc)

                _final_contents = _append_case_context(
                    [TextContent(type="text", text=json.dumps(build_block_response(name, gate), indent=2))],
                    case_dir_str,
                )
                return _final_contents

            # Synthetic gateway tool — aggregates backend health. Gated above
            # like any other agent tool; only reached once the chain is OK.
            if name == "environment_summary":
                _final_contents = list(await _handle_environment_summary(gateway))
                return _final_contents

            try:
                result = await gateway.call_tool(name, arguments, examiner=examiner)
            except KeyError as e:
                _status = "error"
                logger.warning("MCP call_tool unknown tool: %s", e)
                _final_contents = _append_case_context(
                    [TextContent(type="text", text=f"Error: unknown tool {name}")],
                    case_dir_str,
                )
                return _final_contents
            except (RuntimeError, ConnectionError, OSError) as e:
                _status = "error"
                logger.error("MCP call_tool backend error for %s: %s", name, e)
                _final_contents = _append_case_context(
                    [
                        TextContent(
                            type="text",
                            text=f"Error: backend failure for {name} — backend will auto-restart on next call, retry once",
                        )
                    ],
                    case_dir_str,
                )
                return _final_contents
            except Exception as e:
                # Catch ClosedResourceError / BrokenResourceError (anyio) and
                # similar transport errors that indicate a dead session.
                exc_str = str(type(e).__name__).lower()
                if "closed" in exc_str or "broken" in exc_str or "resource" in exc_str:
                    _status = "transport_error"
                    logger.error(
                        "MCP call_tool transport error for %s: %s: %s",
                        name,
                        type(e).__name__,
                        e,
                    )
                    _final_contents = _append_case_context(
                        [
                            TextContent(
                                type="text",
                                text=f"Error: backend connection lost for {name} — retry once to trigger reconnect",
                            )
                        ],
                        case_dir_str,
                    )
                    return _final_contents
                raise  # Re-raise non-transport exceptions to fall through to generic handler
            except (asyncio.CancelledError, BaseExceptionGroup) as e:
                _status = "error"
                logger.error(
                    "MCP call_tool unexpected error for %s: %s: %s",
                    name,
                    type(e).__name__,
                    e,
                )
                _final_contents = _append_case_context(
                    [
                        TextContent(
                            type="text",
                            text=f"Error: unexpected failure for {name} — if this persists, report to examiner",
                        )
                    ],
                    case_dir_str,
                )
                return _final_contents

            # Normalise to list of TextContent for the MCP protocol
            raw_contents: list[TextContent] = []
            for item in result:
                if isinstance(item, TextContent):
                    raw_contents.append(item)
                elif hasattr(item, "model_dump"):
                    raw_contents.append(
                        TextContent(type="text", text=json.dumps(item.model_dump()))
                    )
                else:
                    raw_contents.append(TextContent(type="text", text=str(item)))

            # Extract backend audit_id from raw response before any redaction
            _backend_audit_id = _extract_audit_id(raw_contents)

            # Trust layer: redact critical+high secrets, then cap oversized
            # output — redact-then-cap so a secret can never straddle the
            # truncation boundary and leak half. The size cap is the single
            # central ceiling on bytes any one tool response delivers to Hermes.
            override = is_override_active(case_dir_str)
            cap = output_cap_bytes()
            contents: list[TextContent] = []
            all_findings: list[dict] = []
            cap_events: list[dict] = []
            for tc in raw_contents:
                redacted_text, findings = redact_tool_result(tc.text, override_active=override)
                all_findings.extend(findings)
                capped_text, cap_meta = cap_tool_result(
                    redacted_text, max_bytes=cap, case_dir=case_dir_str, tool_name=name
                )
                if cap_meta:
                    cap_events.append(cap_meta)
                contents.append(TextContent(type="text", text=capped_text))

            sift_context: dict = {}

            if all_findings:
                warning_names = sorted({f["pattern_name"] for f in all_findings})
                try:
                    await asyncio.to_thread(
                        gateway._audit.log,
                        tool=name,
                        params={},
                        result_summary=f"response_guard: {len(all_findings)} pattern(s) detected",
                        source="gateway_response_guard",
                        extra={
                            "examiner": examiner,
                            "findings": [
                                {"pattern_name": f["pattern_name"], "severity": f["severity"],
                                 "char_offset": f["char_offset"]}
                                for f in all_findings
                            ],
                            "redact_override_active": override,
                            **({"override_by": get_override_status(case_dir_str).get("enabled_by")} if override else {}),
                        },
                    )
                except Exception as exc:
                    logger.warning("response_guard: audit write failed: %s", exc)
                sift_context["secret_warning"] = warning_names
                sift_context["redact_override_active"] = override

            if cap_events:
                try:
                    await asyncio.to_thread(
                        gateway._audit.log,
                        tool=name,
                        params={},
                        result_summary=f"output_cap: {len(cap_events)} response(s) capped at {cap} bytes",
                        source="gateway_output_cap",
                        extra={"examiner": examiner, "cap_events": cap_events},
                    )
                except Exception as exc:
                    logger.warning("output_cap: audit write failed: %s", exc)
                sift_context["output_capped"] = [
                    {
                        "original_bytes": ev["original_bytes"],
                        "returned_bytes": ev["returned_bytes"],
                        "cap_bytes": ev["cap_bytes"],
                        **({"output_file": ev["output_file"]} if "output_file" in ev else {}),
                    }
                    for ev in cap_events
                ]

            # Inject a single _sift_context note covering redaction + cap events.
            if sift_context and contents:
                contents.append(
                    TextContent(type="text", text=json.dumps({"_sift_context": sift_context}))
                )

            _final_contents = _append_case_context(contents, case_dir_str)
            return _final_contents

        finally:
            # Gateway transport envelope — one entry per call_tool, except on a
            # gate block (the gate already wrote a richer line, so a second
            # envelope entry would double-count). Records WHO called and links to
            # the backend's own detailed audit entry via backend_audit_id.
            # Params and result content are NOT logged here — backends own that.
            if not _block_audited:
                elapsed_ms = round((time.monotonic() - _start) * 1000, 1)
                backend_name = getattr(gateway, "_tool_map", {}).get(name, "unknown")
                try:
                    extra_fields = _stamp_identity_extra({
                        "role": req_ctx["role"],
                        "token_id": req_ctx["token_id"],
                        "source_ip": req_ctx["source_ip"],
                        "backend": backend_name,
                        "status": _status,
                        "backend_audit_id": _backend_audit_id,
                    }, identity, examiner)

                    await asyncio.to_thread(
                        gateway._audit.log,
                        tool=name,
                        params={},
                        result_summary=_status,
                        source="gateway_mcp_envelope",
                        elapsed_ms=elapsed_ms,
                        extra=extra_fields,
                        examiner_override=_effective_principal,
                    )
                except Exception as exc:
                    logger.warning("gateway envelope audit write failed for %s: %s", name, exc)

    return server


def create_backend_mcp_server(gateway: Any, backend_name: str) -> Server:
    """Build a low-level MCP ``Server`` exposing only *backend_name*'s tools.

    Unlike :func:`create_mcp_server` (which aggregates all backends), this
    creates a dedicated server for a single backend.  Each gets its own
    ``Server`` + ``StreamableHTTPSessionManager`` + ``MCPAuthASGIApp`` triple
    so that MCP sessions are isolated per backend.
    """
    backend = gateway.backends[backend_name]
    instructions = _BACKEND_INSTRUCTIONS.get(backend_name)
    if instructions is None:
        instructions = backend.instructions
    server = Server(f"sift-gateway/{backend_name}", instructions=instructions)

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        if not backend.started:
            try:
                await gateway.ensure_backend_started(backend_name)
            except (asyncio.TimeoutError, RuntimeError, ConnectionError, OSError):
                raise RuntimeError(f"Backend {backend_name} failed to start") from None
        backend.last_tool_call = time.monotonic()
        return await backend.list_tools()

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> Sequence[TextContent]:
        if not backend.started:
            await gateway.ensure_backend_started(backend_name)
        backend.last_tool_call = time.monotonic()

        req_ctx = _extract_request_context(server)
        examiner = req_ctx["examiner"]

        _start = time.monotonic()
        try:
            result = await backend.call_tool(name, arguments)
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.error(
                "Per-backend call_tool error for %s/%s: %s", backend_name, name, e
            )
            return [
                TextContent(
                    type="text",
                    text=f"Error: backend failure for {name} — backend will auto-restart on next call, retry once",
                )
            ]
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
            logger.error(
                "Per-backend call_tool unexpected error for %s/%s: %s: %s",
                backend_name,
                name,
                type(e).__name__,
                e,
            )
            return [
                TextContent(
                    type="text",
                    text=f"Error: unexpected failure for {name} — if this persists, report to examiner",
                )
            ]

        # Normalise to list of TextContent
        contents: list[TextContent] = []
        for item in result:
            if isinstance(item, TextContent):
                contents.append(item)
            elif hasattr(item, "model_dump"):
                contents.append(
                    TextContent(type="text", text=json.dumps(item.model_dump()))
                )
            else:
                contents.append(TextContent(type="text", text=str(item)))

        # Per-backend audit for HTTP backends (this path bypasses
        # Gateway.call_tool, so centralized audit doesn't cover it)
        from sift_gateway.backends.http_backend import HttpMCPBackend

        if isinstance(backend, HttpMCPBackend):
            elapsed_ms = (time.monotonic() - _start) * 1000
            try:
                identity = req_ctx["identity"]
                extra_fields = _stamp_identity_extra({
                    "backend": backend_name,
                    "backend_audit_id": _extract_audit_id(result),
                }, identity, examiner)

                await asyncio.to_thread(
                    gateway._audit.log,
                    tool=name,
                    params=_truncate_params(arguments),
                    result_summary=_summarize_result(result),
                    source="gateway_proxy",
                    elapsed_ms=round(elapsed_ms, 1),
                    extra=extra_fields,
                    examiner_override=identity.principal if identity else examiner,
                )
            except Exception as exc:
                logger.warning(
                    "Gateway audit failed for %s/%s: %s", backend_name, name, exc
                )

        return contents

    return server


# ---------------------------------------------------------------------------
# Session manager factory
# ---------------------------------------------------------------------------


def create_session_manager(mcp_server: Server) -> StreamableHTTPSessionManager:
    """Create a ``StreamableHTTPSessionManager`` wrapping *mcp_server*."""
    return StreamableHTTPSessionManager(
        app=mcp_server,
        stateless=False,
    )
