"""SIFT-owned FastMCP policy middleware for the gateway MCP surface."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

from fastmcp.server.middleware import Middleware
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from sift_core.agent_tools import core_tool_names

from sift_gateway.audit_helpers import _extract_audit_id
from sift_gateway.evidence_gate import build_block_response, check_evidence_gate
from sift_gateway.mcp_endpoint import (
    _append_case_context,
    _stamp_identity_extra,
    current_mcp_identity,
)
from sift_gateway.response_guard import (
    get_override_status,
    guard_tool_result,
    is_override_active,
    output_cap_bytes,
)

logger = logging.getLogger(__name__)


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


class EvidenceGateMiddleware(Middleware):
    """Block all MCP tool calls when the active evidence chain is not OK."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
        case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
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

        contents = _append_case_context(
            [
                TextContent(
                    type="text",
                    text=json.dumps(build_block_response(name, gate), indent=2),
                )
            ],
            case_dir_str,
            name,
        )
        return ToolResult(content=contents, structured_content=build_block_response(name, gate))


class ResponseGuardMiddleware(Middleware):
    """Redact and cap final ToolResult content and structured_content."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        result = await call_next(context)
        name = _tool_name(context)
        case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
        override = is_override_active(case_dir_str)
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
                                "override_by": get_override_status(case_dir_str).get(
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

        if sift_context and result.content:
            result.content.append(
                TextContent(type="text", text=json.dumps({"_sift_context": sift_context}))
            )
            result.meta = dict(result.meta or {})
            result.meta["_sift_context"] = sift_context

        return result


class CaseContextMiddleware(Middleware):
    """Append active-case context to selected gateway responses."""

    async def on_call_tool(self, context, call_next):
        result = await call_next(context)
        result.content = _append_case_context(
            list(result.content or []),
            os.environ.get("SIFT_CASE_DIR", ""),
            _tool_name(context),
        )
        return result


class AuditEnvelopeMiddleware(Middleware):
    """Write the gateway MCP transport envelope for each allowed tool call."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_call_tool(self, context, call_next):
        name = _tool_name(context)
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
            req_ctx = _request_context()
            identity = req_ctx["identity"]
            examiner = req_ctx["examiner"]
            effective_principal = identity.principal if identity else examiner
            elapsed_ms = round((time.monotonic() - start) * 1000, 1)
            backend_name = self._backend_name(name)
            extra_fields = _stamp_identity_extra(
                {
                    "role": req_ctx["role"],
                    "token_id": req_ctx["token_id"],
                    "source_ip": req_ctx["source_ip"],
                    "backend": backend_name,
                    "status": status,
                    "backend_audit_id": backend_audit_id,
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

    def _backend_name(self, tool_name: str) -> str:
        if tool_name in core_tool_names() or tool_name == "capability_guide":
            return "sift-core"
        return getattr(self.gateway, "_tool_map", {}).get(tool_name, "unknown")


def gateway_policy_middlewares(gateway: Any) -> list[Middleware]:
    """Return middleware in FastMCP execution order."""
    return [
        EvidenceGateMiddleware(gateway),
        AuditEnvelopeMiddleware(gateway),
        CaseContextMiddleware(),
        ResponseGuardMiddleware(gateway),
    ]
