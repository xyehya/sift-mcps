"""SIFT-owned FastMCP policy middleware for the gateway MCP surface."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from fastmcp.server.middleware import Middleware
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from sift_core.active_case_context import (
    ActiveCaseContext,
    current_active_case,
    use_active_case_context,
)
from sift_core.agent_tools import core_tool_names

from sift_gateway.active_case import ActiveCase, ActiveCaseError
from sift_gateway.audit_helpers import (
    _extract_audit_id,
    _extract_run_command_detail,
    _summarize_result as _summarize_audit_result,
    redact_for_audit,
)
from sift_gateway.evidence_gate import (
    build_block_response,
    check_evidence_gate,
    check_evidence_gate_db,
)
from sift_gateway.mcp_endpoint import (
    _append_case_context,
    _stamp_identity_extra,
    current_mcp_identity,
    log_rate_limit_violation,
)
from sift_gateway.rate_limit import check_examiner_rate_limit
from sift_gateway.response_guard import (
    _display_spill_path,
    get_override_status,
    guard_tool_result,
    is_override_active,
    output_cap_bytes,
)
from sift_gateway.supabase_auth import is_scope_satisfied, is_tool_allowed

logger = logging.getLogger(__name__)
_CURRENT_ACTIVE_CASE: ContextVar[ActiveCase | None] = ContextVar(
    "sift_gateway_active_case",
    default=None,
)


@contextmanager
def _use_gateway_active_case(case: ActiveCase | None):
    token = _CURRENT_ACTIVE_CASE.set(case)
    try:
        yield
    finally:
        _CURRENT_ACTIVE_CASE.reset(token)


def _current_gateway_active_case() -> ActiveCase | None:
    return _CURRENT_ACTIVE_CASE.get()


def _tool_name(context: Any) -> str:
    return str(getattr(context.message, "name", "unknown"))


def _tool_args(context: Any) -> dict:
    args = getattr(context.message, "arguments", None)
    return args if isinstance(args, dict) else {}


def _request_context() -> dict:
    identity = current_mcp_identity()
    if identity is not None:
        return {
            "examiner": identity.principal,
            "role": identity.role,
            "token_id": identity.token_id,
            "source_ip": identity.source_ip,
            "identity": identity,
        }
    return {
        "examiner": None,
        "role": "unknown",
        "token_id": None,
        "source_ip": None,
        "identity": None,
    }


def _active_case_service(gateway: Any):
    service = getattr(gateway, "active_case_service", None)
    if service is not None and service.__class__.__module__.startswith("unittest.mock"):
        return None
    return service


def _error_result(error: str, detail: str, *, tool: str | None = None) -> ToolResult:
    payload = {"error": error, "detail": detail}
    if tool:
        payload["tool"] = tool
    return ToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
        is_error=True,
    )


def _case_extra(case: ActiveCase | None) -> dict[str, Any]:
    if case is None:
        return {}
    return {
        "case_id": case.case_id,
        "case_key": case.case_key,
        "case_membership_role": case.membership_role,
    }


def _case_text(case: ActiveCase, tool_name: str | None = None) -> TextContent:
    # F-MVP-2: this case context is appended to MCP responses AFTER the response
    # guard has run, so it must be agent-safe at the source. The agent gets opaque
    # case IDs and RELATIVE display dirs only — never the absolute artifact path,
    # which would expose the host's /cases/... location.
    payload = {
        "case_context": {
            "id": case.case_id,
            "case_id": case.case_key,
            "case_key": case.case_key,
            "evidence_dir": "evidence" if case.artifact_path else None,
            "agent_dir": "agent" if case.artifact_path else None,
            "source": "postgres_active_case_state",
        }
    }
    if tool_name:
        payload["case_context"]["tool"] = tool_name
    return TextContent(type="text", text=json.dumps(payload, indent=2))


_READ_ONLY_NONCORE_TOOLS = frozenset({"capability_guide", "get_tool_help", "job_status"})
_CASE_CONTEXT_RESPONSE_TOOLS = frozenset({"case_info", "evidence_info", "capability_guide"})


def _tool_read_only(gateway: Any, name: str) -> bool:
    """Return True only when the tool is positively known to be read-only.

    Used by the DB-first audit envelope to decide which tools must fail closed
    when a required pre-dispatch audit write fails. Unknown tools are treated as
    mutating (fail-safe), so a missing manifest never silently downgrades a
    write to a best-effort audit.
    """
    try:
        from sift_core.agent_tools import core_tool_specs

        for spec in core_tool_specs():
            if spec.name == name:
                return bool(getattr(spec, "read_only", False))
    except Exception:  # pragma: no cover - defensive
        pass
    if name in _READ_ONLY_NONCORE_TOOLS:
        return True
    meta = getattr(gateway, "_tool_manifest_meta", None) or {}
    entry = meta.get(name)
    if isinstance(entry, dict) and "read_only" in entry:
        return bool(entry["read_only"])
    return False


def _is_case_scoped_tool(gateway: Any, name: str) -> bool:
    if name in core_tool_names():
        return name not in {"get_tool_help", "capability_guide"}
    fn = getattr(gateway, "is_case_scoped_tool", None)
    if callable(fn):
        return bool(fn(name))
    return False


def _safe_case_args(gateway: Any, name: str) -> set[str] | None:
    """Return safe case argument names for injection, or None if unknown.

    OS2: Gateway.safe_case_argument_names() now returns:
      - set (possibly empty): manifest-declared; empty means case-scoped but
        no injection argument needed — let the call through without injection.
      - None: not declared in manifest and not found in schema — unknown; the
        caller must deny fail-closed (original behaviour).

    When the gateway method does not exist or returns None, this returns None
    so the middleware continues to fail closed for undeclared proxy tools.
    """
    fn = getattr(gateway, "safe_case_argument_names", None)
    if callable(fn):
        result = fn(name)
        if result is None:
            return None
        return set(result)
    return None


def _is_gateway_local_tool(gateway: Any, name: str) -> bool:
    return name in (getattr(gateway, "_gateway_local_tools", None) or set())


class ToolAuthorizationMiddleware(Middleware):
    """B-10: SIFT-owned per-principal tool authorization for list AND call.

    Uses the single :func:`is_tool_allowed` helper for both ``on_list_tools``
    (filter advertised tools) and ``on_call_tool`` (reject before dispatch),
    guaranteeing list/call consistency. Denied calls return a normal MCP error
    result and are audited WITHOUT invoking the tool (local or proxied). Denied
    tools are absent from ``list_tools``.

    Authorization is SIFT-owned: it does not delegate to FastMCP require_scopes.

    B6: when auth is configured (``auth_enabled``), a request with no resolvable
    SIFT identity (e.g. a token whose claims lack ``sift_identity``) FAILS CLOSED
    — it lists nothing and is denied on call. Only genuine anonymous single-user
    mode (no verifier/keys/registry) leaves the catalog open.
    """

    def __init__(self, gateway: Any, *, auth_enabled: bool = False) -> None:
        self.gateway = gateway
        self.auth_enabled = auth_enabled

    async def on_list_tools(self, context, call_next):
        tools = list(await call_next(context))
        identity = current_mcp_identity()
        if identity is None:
            if self.auth_enabled:
                # B6: auth configured but no identity → advertise nothing.
                return []
            # Genuine anonymous single-user mode: leave the catalog as-is.
            return tools
        return [tool for tool in tools if is_tool_allowed(identity, tool.name)]

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        identity = current_mcp_identity()
        if identity is None:
            if not self.auth_enabled:
                # Genuine anonymous single-user mode.
                return await call_next(context)
            # B6: auth configured but no identity → fail closed.
            return await self._deny(name, identity=None, reason="no_identity")

        # B3: per-principal rate limit. On the verifier-owns-identity path the
        # raw ASGI guard no longer applies a per-examiner throttle (only IP/body/
        # Origin remain), so the per-principal limit lives here in SIFT policy
        # middleware, before tool dispatch.
        if not check_examiner_rate_limit(identity.principal):
            source_ip = getattr(identity, "source_ip", None)
            log_rate_limit_violation(
                self.gateway,
                f"examiner:{identity.principal}",
                source_ip or "unknown",
                identity,
            )
            return self._rate_limited(name)

        if is_tool_allowed(identity, name):
            return await call_next(context)
        return await self._deny(name, identity=identity, reason="tool_scope")

    def _rate_limited(self, name: str) -> ToolResult:
        payload = {
            "error": "rate_limit_exceeded",
            "tool": name,
            "detail": "per-principal MCP rate limit exceeded",
        }
        return ToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
            is_error=True,
        )

    async def _deny(self, name: str, *, identity: Any, reason: str) -> ToolResult:
        # Denied: audit WITHOUT invoking the tool, return a normal MCP error.
        req_ctx = _request_context()
        extra_fields = _stamp_identity_extra(
            {
                "role": req_ctx["role"],
                "token_id": req_ctx["token_id"],
                "source_ip": req_ctx["source_ip"],
                "status": "denied",
                "denial_reason": reason,
            },
            identity,
            req_ctx["examiner"],
        )
        try:
            await asyncio.to_thread(
                self.gateway._audit.log,
                tool=name,
                params={},
                result_summary=f"denied: {reason}",
                source="gateway_tool_authz",
                extra=extra_fields,
                examiner_override=identity.principal if identity else None,
            )
        except Exception as exc:
            logger.warning("tool_authz: audit write failed: %s", exc)

        payload = {
            "error": "tool_not_authorized",
            "tool": name,
            "detail": "principal lacks an active tool scope for this tool",
        }
        return ToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
            is_error=True,
        )


_PROHIBITED_OP_ARG_KEYS = ("operation", "action", "op", "command", "mode")


class AddonAuthorityMiddleware(Middleware):
    """H1 (BATCH-D2): enforce add-on authority_contract before backend dispatch.

    Runs after :class:`ToolAuthorizationMiddleware` (so the caller already holds a
    gateway tool scope for the tool) but before the evidence gate, audit
    envelope, and proxy dispatch. For add-on tools only — core in-process tools
    carry no manifest authority contract and are skipped.

    Enforcement is fail-closed and happens BEFORE the backend is ever invoked:

      * ``required_scopes``: every manifest-declared scope on the tool must be
        satisfied by the caller's identity scopes. A missing required scope is
        denied (``addon_scope_missing``).
      * ``prohibited_operations``: a query-only/non-authoritative add-on must
        never perform an authority operation (seal evidence, approve findings,
        bypass gateway, ...). If the tool name itself, or an
        operation/action-style argument value, names a prohibited operation, the
        call is denied (``addon_prohibited_operation``).

    ``non_authoritative`` is honored as advisory state: it is surfaced in the
    audit trail and, when set, tightens prohibited-operation matching to fail
    closed. The Gateway — not the add-on — remains the authority boundary.
    """

    def __init__(self, gateway: Any, *, auth_enabled: bool = False) -> None:
        self.gateway = gateway
        self.auth_enabled = auth_enabled

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        fn = getattr(self.gateway, "addon_authority_for_tool", None)
        profile = fn(name) if callable(fn) else None
        # Core tools and unknown/unmapped tools carry no add-on contract.
        if not profile:
            return await call_next(context)

        identity = current_mcp_identity()

        required_scopes = profile.get("required_scopes") or []
        if required_scopes:
            missing = [
                scope
                for scope in required_scopes
                if not is_scope_satisfied(identity, scope)
            ]
            if missing:
                return await self._deny(
                    name,
                    identity=identity,
                    reason="addon_scope_missing",
                    detail=(
                        "principal is missing add-on tool scope(s) required by "
                        "this backend tool"
                    ),
                    extra={"missing_scopes": sorted(missing)},
                )

        prohibited = {op for op in (profile.get("prohibited_operations") or []) if op}
        if prohibited:
            attempted = self._attempted_prohibited_operations(
                name, _tool_args(context), prohibited
            )
            if attempted:
                return await self._deny(
                    name,
                    identity=identity,
                    reason="addon_prohibited_operation",
                    detail=(
                        "add-on backend is non-authoritative and may not perform "
                        "this authority operation"
                    ),
                    extra={
                        "prohibited_operations": sorted(attempted),
                        "non_authoritative": bool(profile.get("non_authoritative")),
                    },
                )

        return await call_next(context)

    def _attempted_prohibited_operations(
        self, tool_name: str, args: dict, prohibited: set[str]
    ) -> set[str]:
        """Return the prohibited operation names this call would perform."""
        hits: set[str] = set()
        if tool_name in prohibited:
            hits.add(tool_name)
        for key in _PROHIBITED_OP_ARG_KEYS:
            value = args.get(key)
            if isinstance(value, str) and value in prohibited:
                hits.add(value)
        return hits

    async def _deny(
        self,
        name: str,
        *,
        identity: Any,
        reason: str,
        detail: str,
        extra: dict[str, Any] | None = None,
    ) -> ToolResult:
        req_ctx = _request_context()
        audit_extra = _stamp_identity_extra(
            {
                "role": req_ctx["role"],
                "token_id": req_ctx["token_id"],
                "source_ip": req_ctx["source_ip"],
                "status": "denied",
                "denial_reason": reason,
                **(extra or {}),
            },
            identity,
            req_ctx["examiner"],
        )
        try:
            await asyncio.to_thread(
                self.gateway._audit.log,
                tool=name,
                params={},
                result_summary=f"denied: {reason}",
                source="gateway_addon_authority",
                extra=audit_extra,
                examiner_override=identity.principal if identity else None,
            )
        except Exception as exc:
            logger.warning("addon_authority: audit write failed: %s", exc)

        payload = {"error": reason, "tool": name, "detail": detail}
        if extra:
            payload.update(extra)
        return ToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
            is_error=True,
        )


class EvidenceGateMiddleware(Middleware):
    """Block all MCP tool calls when the active evidence chain is not OK."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        case = _current_gateway_active_case()
        if case is None and _active_case_service(self.gateway) is not None:
            return await call_next(context)
        case_dir_str = case.artifact_path if case is not None else os.environ.get("SIFT_CASE_DIR", "")
        dsn = getattr(self.gateway, "control_plane_dsn", None)
        if case is not None and dsn:
            gate = check_evidence_gate_db(case.case_id, dsn)
        else:
            gate = check_evidence_gate(case_dir_str)
        if not gate["blocked"]:
            return await call_next(context)

        req_ctx = _request_context()
        identity = req_ctx["identity"]
        examiner = req_ctx["examiner"]
        effective_principal = identity.principal if identity else examiner
        gate_status = gate["status"]
        extra_fields = _stamp_identity_extra(
            {
                "role": req_ctx["role"],
                "token_id": req_ctx["token_id"],
                "source_ip": req_ctx["source_ip"],
                "evidence_chain_status": gate_status,
                "issues": gate["issues"],
                "manifest_version": gate["manifest_version"],
                **_case_extra(case),
            },
            identity,
            examiner,
        )
        try:
            await asyncio.to_thread(
                self.gateway._audit.log,
                tool=name,
                params={},
                result_summary=f"blocked: evidence_chain_{gate_status}",
                source="gateway_evidence_gate",
                extra=extra_fields,
                examiner_override=effective_principal,
            )
        except Exception as exc:
            logger.warning("evidence_gate: audit write failed: %s", exc)

        contents = [
            TextContent(
                type="text",
                text=json.dumps(build_block_response(name, gate), indent=2),
            ),
        ]
        if case is not None:
            contents.append(_case_text(case, name))
        else:
            contents = _append_case_context(contents, case_dir_str, name)
        return ToolResult(
            content=contents,
            structured_content=build_block_response(name, gate),
            is_error=True,
        )


class ResponseGuardMiddleware(Middleware):
    """Redact and cap final ToolResult content and structured_content."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        result = await call_next(context)
        name = _tool_name(context)
        case = _current_gateway_active_case()
        case_dir_str = case.artifact_path if case is not None else os.environ.get("SIFT_CASE_DIR", "")
        override_key = case.case_id if case is not None else ""
        if not case_dir_str:
            case_dir_str = None
        override = is_override_active(override_key or (case_dir_str or ""))
        cap = output_cap_bytes()

        result, findings, cap_events = guard_tool_result(
            result,
            override_active=override,
            case_dir=case_dir_str,
            tool_name=name,
            cap_bytes=cap,
        )

        req_ctx = _request_context()
        examiner = req_ctx["examiner"]
        sift_context: dict[str, Any] = {}

        if findings:
            warning_names = sorted({f["pattern_name"] for f in findings})
            try:
                await asyncio.to_thread(
                    self.gateway._audit.log,
                    tool=name,
                    params={},
                    result_summary=f"response_guard: {len(findings)} pattern(s) detected",
                    source="gateway_response_guard",
                    extra={
                        "examiner": examiner,
                        **_case_extra(case),
                        "findings": [
                            {
                                "pattern_name": f["pattern_name"],
                                "severity": f["severity"],
                                "char_offset": f["char_offset"],
                                **({"path": f["path"]} if "path" in f else {}),
                            }
                            for f in findings
                        ],
                        "redact_override_active": override,
                        **(
                            {
                                "override_by": get_override_status(override_key or (case_dir_str or "")).get(
                                    "enabled_by"
                                )
                            }
                            if override
                            else {}
                        ),
                    },
                )
            except Exception as exc:
                logger.warning("response_guard: audit write failed: %s", exc)
            sift_context["secret_warning"] = warning_names
            sift_context["redact_override_active"] = override

        if cap_events:
            try:
                await asyncio.to_thread(
                    self.gateway._audit.log,
                    tool=name,
                    params={},
                    result_summary=(
                        f"output_cap: {len(cap_events)} response(s) capped at {cap} bytes"
                    ),
                    source="gateway_output_cap",
                    extra={"examiner": examiner, "cap_events": cap_events, **_case_extra(case)},
                )
            except Exception as exc:
                logger.warning("output_cap: audit write failed: %s", exc)
            # F-MVP-2: the agent-visible _sift_context must carry only a relative
            # display path; cap_events keep the absolute path for the audit log.
            sift_context["output_capped"] = [
                {
                    "original_bytes": ev["original_bytes"],
                    "returned_bytes": ev["returned_bytes"],
                    "cap_bytes": ev["cap_bytes"],
                    **(
                        {"output_file": _display_spill_path(ev["output_file"], case_dir_str)}
                        if "output_file" in ev
                        else {}
                    ),
                }
                for ev in cap_events
            ]

        if sift_context and result.content:
            result.content.append(
                TextContent(type="text", text=json.dumps({"_sift_context": sift_context}))
            )
            result.meta = dict(result.meta or {})
            result.meta["_sift_context"] = sift_context

        return result


class CaseContextMiddleware(Middleware):
    """Resolve and append DB active-case context to selected gateway responses."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        identity = current_mcp_identity()
        service = _active_case_service(self.gateway)
        case: ActiveCase | None = None
        if service is not None:
            try:
                case = service.require_active_case_for_principal(identity)
            except ActiveCaseError as exc:
                if _is_case_scoped_tool(self.gateway, name):
                    await self._audit_denial(name, identity, exc.reason)
                    return _error_result(
                        "active_case_denied",
                        exc.reason,
                        tool=name,
                    )

        # K1: when the case was resolved from the Postgres active-case service,
        # this request is DB-active. The context becomes the single authority for
        # the active case; core resolvers must not fall back to env/pointer files.
        core_context = (
            ActiveCaseContext(
                case_id=case.case_id,
                case_key=case.case_key,
                artifact_path=case.artifact_path,
                membership_role=case.membership_role,
                principal=getattr(identity, "principal", None),
                principal_type=getattr(identity, "principal_type", None),
                tool_scopes=getattr(identity, "tool_scopes", frozenset()) or frozenset(),
                request_id=uuid.uuid4().hex,
                db_active=service is not None,
            )
            if case is not None
            else None
        )
        with _use_gateway_active_case(case), use_active_case_context(core_context):
            result = await call_next(context)
        if case is not None and name in _CASE_CONTEXT_RESPONSE_TOOLS:
            result.content = list(result.content or [])
            result.content.append(_case_text(case, name))
        elif service is None and name in _CASE_CONTEXT_RESPONSE_TOOLS:
            result.content = _append_case_context(
                list(result.content or []),
                os.environ.get("SIFT_CASE_DIR", ""),
                name,
            )
        return result

    async def _audit_denial(self, name: str, identity: Any, reason: str) -> None:
        req_ctx = _request_context()
        extra_fields = _stamp_identity_extra(
            {
                "role": req_ctx["role"],
                "token_id": req_ctx["token_id"],
                "source_ip": req_ctx["source_ip"],
                "status": "denied",
                "denial_reason": reason,
            },
            identity,
            req_ctx["examiner"],
        )
        try:
            await asyncio.to_thread(
                self.gateway._audit.log,
                tool=name,
                params={},
                result_summary=f"denied: {reason}",
                source="gateway_active_case",
                extra=extra_fields,
                examiner_override=identity.principal if identity else None,
            )
        except Exception as exc:
            logger.warning("active_case: audit write failed: %s", exc)


class ProxyActiveCaseMiddleware(Middleware):
    """B-11: inject DB case args for safe proxied tools or deny implicit-env tools."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        if (
            name in core_tool_names()
            or _is_gateway_local_tool(self.gateway, name)
            or not _is_case_scoped_tool(self.gateway, name)
        ):
            return await call_next(context)
        case = _current_gateway_active_case()
        if case is None:
            return await call_next(context)
        safe_args = _safe_case_args(self.gateway, name)
        # OS2: safe_args == None means the tool's case-arg contract is unknown
        # (no manifest declaration and no schema property found) — deny
        # fail-closed to prevent an unguarded proxy from implicitly using
        # whatever case the backend assumes from its environment.
        # safe_args == set() (empty) means the manifest explicitly declares
        # "no injection argument" — the tool is case-scoped but resolves the
        # active case internally; let it through without injecting args.
        if safe_args is None:
            await self._audit_denial(name, case, "proxy_requires_implicit_case")
            return _error_result(
                "active_case_proxy_denied",
                "proxied case-scoped tool does not expose a safe case_id/case_key argument",
                tool=name,
            )
        if not safe_args:
            # Manifest says no injection args — pass through unmodified.
            return await call_next(context)
        args = _tool_args(context)
        # case_dir carries the DB-authoritative active-case directory
        # (artifact_path) so backends that touch the case filesystem (ingest,
        # inspect, enrich, summary, host-fix) never resolve the case from a
        # local file/env. It is gateway-injected; a mismatching client value is
        # denied. artifact_path is the authority and must never leak from the
        # client, so an empty DB artifact_path means we still overwrite (clear).
        for key, expected in (
            ("case_id", case.case_id),
            ("case_key", case.case_key),
            ("case_dir", case.artifact_path or ""),
        ):
            if key not in safe_args:
                continue
            supplied = args.get(key)
            if supplied and str(supplied) != expected:
                await self._audit_denial(name, case, "client_case_mismatch")
                return _error_result(
                    "active_case_mismatch",
                    f"client-supplied {key} does not match the DB active case",
                    tool=name,
                )
            args[key] = expected
        return await call_next(context)

    async def _audit_denial(self, name: str, case: ActiveCase, reason: str) -> None:
        req_ctx = _request_context()
        identity = req_ctx["identity"]
        extra_fields = _stamp_identity_extra(
            {
                "role": req_ctx["role"],
                "token_id": req_ctx["token_id"],
                "source_ip": req_ctx["source_ip"],
                "status": "denied",
                "denial_reason": reason,
                **_case_extra(case),
            },
            identity,
            req_ctx["examiner"],
        )
        try:
            await asyncio.to_thread(
                self.gateway._audit.log,
                tool=name,
                params={},
                result_summary=f"denied: {reason}",
                source="gateway_proxy_active_case",
                extra=extra_fields,
                examiner_override=identity.principal if identity else None,
            )
        except Exception as exc:
            logger.warning("proxy_active_case: audit write failed: %s", exc)


class AuditEnvelopeMiddleware(Middleware):
    """Write the gateway MCP transport envelope for each allowed tool call.

    K1: in DB-active mode (a control-plane ``db_audit`` sink is wired) this is
    DB-first. Before dispatch it reserves a ``requested`` envelope row in
    ``app.audit_events`` and attaches its id to the request's
    :class:`AuthorityContext` so mutating core handlers can reference it. If that
    *required* pre-dispatch audit write fails and the tool is mutating, the call
    fails closed and the backend is never invoked. After dispatch it writes a
    ``success``/``failure`` receipt row. The JSONL writer is kept as a
    best-effort legacy/export mirror, never the authority.
    """

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        req_ctx = _request_context()
        identity = req_ctx["identity"]
        examiner = req_ctx["examiner"]
        effective_principal = identity.principal if identity else examiner
        case = _current_gateway_active_case()
        backend_name = self._backend_name(name)
        db_audit = getattr(self.gateway, "db_audit", None)
        case_dir = case.artifact_path if case is not None else None

        request_id = self._request_id()
        envelope_event_id: str | None = None

        # Capture the tool's REDACTED arguments for the operator audit trail.
        # This applies uniformly to core and proxied add-on tools, so e.g.
        # opensearch query_strings and run_command commands are recorded.
        # Secrets and sensitive absolute paths are stripped and large values
        # bounded before storage (see redact_for_audit).
        redacted_args = redact_for_audit(_tool_args(context), case_dir=case_dir)

        # --- DB-first pre-dispatch envelope (required for mutating tools) ------
        if db_audit is not None:
            try:
                envelope_event_id = await asyncio.to_thread(
                    db_audit.record,
                    event_type="mcp.tool.call",
                    actor=identity,
                    case_id=case.case_id if case is not None else None,
                    source="gateway_mcp_envelope",
                    status="requested",
                    summary=f"requested {name}",
                    request_id=request_id,
                    details={
                        "tool": name,
                        "backend": backend_name,
                        "phase": "pre_dispatch",
                        "principal": effective_principal,
                        "principal_type": getattr(identity, "principal_type", None),
                        "role": req_ctx["role"],
                        "token_id": req_ctx["token_id"],
                        "source_ip": req_ctx["source_ip"],
                        "case_key": case.case_key if case is not None else None,
                        "arguments": redacted_args,
                    },
                )
                self._attach_audit_event(envelope_event_id, request_id)
            except Exception as exc:
                if self._tool_is_mutating(name):
                    logger.warning(
                        "mcp_envelope: required pre-dispatch DB audit failed for "
                        "mutating tool %s; failing closed: %s",
                        name,
                        exc,
                    )
                    return _error_result(
                        "audit_unavailable",
                        "required audit could not be persisted; mutating call denied",
                        tool=name,
                    )
                logger.warning(
                    "mcp_envelope: pre-dispatch DB audit failed for read-only tool "
                    "%s; proceeding: %s",
                    name,
                    exc,
                )

        # --- dispatch ---------------------------------------------------------
        start = time.monotonic()
        status = "ok"
        backend_audit_id: str | None = None
        result: ToolResult | None = None
        try:
            result = await call_next(context)
            if result.is_error:
                status = "error"
            backend_audit_id = _extract_audit_id(list(result.content or []))
            return result
        except Exception:
            status = "error"
            raise
        finally:
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            # Build a BOUNDED result detail for the receipt: a lightweight
            # summary for every tool, plus the rich run_command provenance block
            # (command/hashes/stages/privilege events) when present. Both are
            # redacted + bounded so no secret or host path lands in the row.
            result_content = list(result.content or []) if result is not None else []
            result_detail: dict[str, Any] = {}
            try:
                summary = _summarize_audit_result(result_content)
                if summary:
                    result_detail["result_summary"] = redact_for_audit(
                        summary, case_dir=case_dir
                    )
                rc_detail = _extract_run_command_detail(
                    result_content, case_dir=case_dir
                )
                if rc_detail:
                    result_detail["detail"] = rc_detail
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "mcp_envelope: result detail extraction failed for %s: %s",
                    name,
                    exc,
                )
            # DB-first result/failure receipt (best-effort: the tool already ran).
            if db_audit is not None:
                try:
                    await asyncio.to_thread(
                        db_audit.record,
                        event_type="mcp.tool.result",
                        actor=identity,
                        case_id=case.case_id if case is not None else None,
                        source="gateway_mcp_envelope",
                        status="success" if status == "ok" else "failure",
                        summary=f"{status} {name}",
                        request_id=request_id,
                        details={
                            "tool": name,
                            "backend": backend_name,
                            "phase": "result",
                            "status": status,
                            "elapsed_ms": elapsed_ms,
                            "backend_audit_id": backend_audit_id,
                            "envelope_event_id": envelope_event_id,
                            "principal": effective_principal,
                            **result_detail,
                        },
                    )
                except Exception as exc:
                    logger.warning(
                        "mcp_envelope: result DB audit write failed for %s: %s", name, exc
                    )
            # Legacy/export JSONL mirror (never authority).
            extra_fields = _stamp_identity_extra(
                {
                    "role": req_ctx["role"],
                    "token_id": req_ctx["token_id"],
                    "source_ip": req_ctx["source_ip"],
                    "backend": backend_name,
                    "status": status,
                    "backend_audit_id": backend_audit_id,
                    "request_id": request_id,
                    "audit_event_id": envelope_event_id,
                    **_case_extra(case),
                },
                identity,
                examiner,
            )
            try:
                await asyncio.to_thread(
                    self.gateway._audit.log,
                    tool=name,
                    params={},
                    result_summary=status,
                    source="gateway_mcp_envelope",
                    elapsed_ms=elapsed_ms,
                    extra=extra_fields,
                    examiner_override=effective_principal,
                )
            except Exception as exc:
                logger.warning("gateway envelope audit write failed for %s: %s", name, exc)

    def _request_id(self) -> str:
        ctx = current_active_case()
        if ctx is not None and getattr(ctx, "request_id", None):
            return str(ctx.request_id)
        return uuid.uuid4().hex

    def _attach_audit_event(self, event_id: str | None, request_id: str) -> None:
        ctx = current_active_case()
        if ctx is not None and event_id:
            ctx.record_audit_event(event_id)

    def _tool_is_mutating(self, name: str) -> bool:
        return not _tool_read_only(self.gateway, name)

    def _backend_name(self, tool_name: str) -> str:
        if tool_name in core_tool_names() or tool_name == "capability_guide":
            return "sift-core"
        return getattr(self.gateway, "_tool_map", {}).get(tool_name, "unknown")


def gateway_policy_middlewares(
    gateway: Any, *, auth_enabled: bool = False
) -> list[Middleware]:
    """Return middleware in FastMCP execution order.

    ToolAuthorizationMiddleware (B-10) runs first so denied tools are rejected
    before the evidence gate, audit envelope, and tool dispatch, and filtered
    out of list_tools. ``auth_enabled`` makes it fail closed when a configured
    verifier yields no SIFT identity (B6). AddonAuthorityMiddleware (H1/BATCH-D2)
    runs next so missing add-on required_scopes and prohibited authority
    operations are denied before the evidence gate, audit envelope, and dispatch.
    """
    return [
        ToolAuthorizationMiddleware(gateway, auth_enabled=auth_enabled),
        AddonAuthorityMiddleware(gateway, auth_enabled=auth_enabled),
        CaseContextMiddleware(gateway),
        AuditEnvelopeMiddleware(gateway),
        ProxyActiveCaseMiddleware(gateway),
        EvidenceGateMiddleware(gateway),
        ResponseGuardMiddleware(gateway),
    ]
