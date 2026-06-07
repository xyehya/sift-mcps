"""FastMCP 3 server assembly for the SIFT gateway."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.proxy import FastMCPProxy
from fastmcp.tools import Tool, ToolResult
from mcp.types import TextContent, ToolAnnotations
from pydantic import PrivateAttr
from sift_core.agent_tools import call_core_tool, core_tool_names, core_tool_specs

from sift_gateway.mcp_endpoint import (
    SiftTokenVerifier,
    _build_gateway_instructions,
    _handle_capability_guide,
    current_mcp_identity,
)
from sift_gateway.policy_middleware import gateway_policy_middlewares

logger = logging.getLogger(__name__)


_AGENT_FILTERED_TOOLS: frozenset[str] = frozenset({
    "evidence_register",
})

_CORE_TOOL_CATEGORIES: dict[str, str] = {
    "case_info": "session-start",
    "capability_guide": "session-start",
    "evidence_info": "evidence-survey",
    "get_tool_help": "detection",
    "run_command": "detection",
    "record_finding": "findings",
    "record_timeline_event": "findings",
    "list_existing_findings": "findings",
    "manage_todo": "findings",
}

_CORE_TOOL_PHASES: dict[str, str] = {
    "case_info": "ORIENT",
    "capability_guide": "ORIENT",
    "evidence_info": "ORIENT",
    "run_command": "TRIAGE",
    "get_tool_help": "TRIAGE",
    "record_finding": "FINDINGS",
    "record_timeline_event": "FINDINGS",
    "list_existing_findings": "FINDINGS",
    "manage_todo": "FINDINGS",
}


class GatewayLocalTool(Tool):
    """FastMCP local tool that delegates to the existing gateway core path."""

    _gateway: Any = PrivateAttr()
    _handler: Callable[[dict[str, Any], str | None], Any] | None = PrivateAttr(default=None)

    def __init__(
        self,
        *,
        gateway: Any,
        handler: Callable[[dict[str, Any], str | None], Any] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._gateway = gateway
        self._handler = handler

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        identity = current_mcp_identity()
        examiner = identity.principal if identity else None
        if self._handler is not None:
            value = await self._handler(arguments, examiner)
        else:
            value = await asyncio.to_thread(
                call_core_tool,
                self.name,
                arguments,
                examiner=examiner,
                audit=self._gateway._audit,
            )
        if isinstance(value, ToolResult):
            return value
        if isinstance(value, list):
            return ToolResult(content=value)
        return ToolResult(content=[TextContent(type="text", text=str(value))])


class GatewayToolCatalogMiddleware(Middleware):
    """Apply SIFT manifest/core list metadata to FastMCP tool listings."""

    def __init__(self, gateway: Any) -> None:
        self.gateway = gateway

    async def on_list_tools(self, context, call_next):
        tools = list(await call_next(context))
        manifest_meta: dict[str, dict] = getattr(self.gateway, "_tool_manifest_meta", {})
        hidden_addon_tools = {
            name for name, meta in manifest_meta.items() if meta.get("hidden_from_agent")
        }
        filtered = [
            tool
            for tool in tools
            if tool.name not in _AGENT_FILTERED_TOOLS
            and tool.name not in hidden_addon_tools
        ]
        for tool in filtered:
            addon_meta = manifest_meta.get(tool.name, {})
            category = _CORE_TOOL_CATEGORIES.get(tool.name) or addon_meta.get("category", "")
            phase = _CORE_TOOL_PHASES.get(tool.name) or addon_meta.get(
                "recommended_phase", ""
            )
            meta = dict(tool.meta) if tool.meta else {}
            if category:
                meta["category"] = category
            if phase:
                meta["recommended_for_phase"] = phase
            if meta:
                tool.meta = meta
        return filtered


def create_gateway_mcp_server(
    gateway: Any,
    *,
    api_keys: dict[str, dict] | None = None,
    token_registry: Any | None = None,
    base_url: str | None = None,
) -> FastMCP:
    """Create the aggregate FastMCP server for the gateway."""
    verifier = None
    if api_keys or token_registry is not None:
        verifier = SiftTokenVerifier(
            api_keys=api_keys,
            token_registry=token_registry,
            base_url=base_url,
        )
    middlewares = [
        GatewayToolCatalogMiddleware(gateway),
        *gateway_policy_middlewares(gateway),
    ]
    mcp = FastMCP(
        "sift-gateway",
        instructions=_build_gateway_instructions(gateway),
        auth=verifier,
        middleware=middlewares,
    )
    gateway._fastmcp_server = mcp

    _register_core_tools(mcp, gateway)
    _mount_addon_proxies(mcp, gateway)
    return mcp


def _register_core_tools(mcp: FastMCP, gateway: Any) -> None:
    for spec in core_tool_specs():
        mcp.add_tool(
            GatewayLocalTool(
                gateway=gateway,
                name=spec.name,
                description=spec.description,
                parameters=spec.input_schema,
                annotations=ToolAnnotations(readOnlyHint=spec.read_only),
                meta={
                    "category": _CORE_TOOL_CATEGORIES.get(spec.name),
                    "recommended_for_phase": _CORE_TOOL_PHASES.get(spec.name),
                },
            )
        )

    async def _guide(arguments: dict[str, Any], examiner: str | None):
        del arguments, examiner
        return list(await _handle_capability_guide(gateway))

    mcp.add_tool(
        GatewayLocalTool(
            gateway=gateway,
            handler=_guide,
            name="capability_guide",
            description=(
                "ADD-ON backends only: manifest-derived guide to currently usable "
                "add-on tools, grouped by backend, provides[], category, and "
                "recommended phase. Returns empty when no add-on backend is "
                "registered - that is expected, NOT an error."
            ),
            parameters={"type": "object", "properties": {}},
            annotations=ToolAnnotations(readOnlyHint=True),
            meta={
                "category": _CORE_TOOL_CATEGORIES["capability_guide"],
                "recommended_for_phase": _CORE_TOOL_PHASES["capability_guide"],
            },
        )
    )


def _mount_addon_proxies(mcp: FastMCP, gateway: Any) -> None:
    for backend_name, backend in sorted(getattr(gateway, "backends", {}).items()):
        manifest = getattr(backend, "manifest", None)
        if not manifest:
            continue
        reqs = manifest.get("capabilities", {}).get("requires", [])
        unmet = [req for req in reqs if not gateway.evaluate_requirement(req)]
        if unmet:
            continue
        proxy = _create_backend_proxy(backend_name, backend.config, manifest)
        namespace = str(manifest.get("namespace") or "") or None
        mcp.mount(
            proxy,
            namespace=namespace,
            tool_names=_tool_rename_map(manifest),
        )


def _tool_rename_map(manifest: dict) -> dict[str, str] | None:
    namespace = str(manifest.get("namespace") or "")
    if not namespace:
        return None
    prefix = f"{namespace}_"
    mapping = {
        str(tool["name"]): str(tool["name"])[len(prefix) :]
        for tool in manifest.get("tools", [])
        if isinstance(tool.get("name"), str) and str(tool["name"]).startswith(prefix)
    }
    return mapping or None


def _create_backend_proxy(backend_name: str, config: dict, manifest: dict):
    backend_type = config.get("type", "stdio")
    if backend_type == "http":
        return _create_http_proxy(backend_name, config)
    if backend_type == "stdio":
        transport = _stdio_transport(config)
        return create_proxy(transport, name=f"sift-gateway/{backend_name}")
    raise ValueError(f"Unknown backend type for proxy: {backend_type!r}")


def _stdio_transport(config: dict) -> StdioTransport:
    command = config.get("command")
    if not command:
        raise ValueError("stdio backend proxy requires command")
    env = dict(os.environ)
    configured_env = config.get("env") or {}
    env.update(configured_env)
    env = {str(k): str(v) for k, v in env.items() if v}
    args = [str(arg) for arg in config.get("args", [])]
    return StdioTransport(
        command=str(command),
        args=args,
        env=env,
        cwd=config.get("cwd"),
        keep_alive=False,
    )


def _create_http_proxy(backend_name: str, config: dict) -> FastMCPProxy:
    url = str(config.get("url") or "")
    _validate_egress_url(url, label=f"{backend_name}.url")

    def client_factory() -> Client:
        headers = {}
        for key, value in (config.get("headers") or {}).items():
            if str(key).lower() == "authorization":
                continue
            headers[str(key)] = str(value)
        tls_cert = config.get("tls_cert")
        verify: bool | str = str(os.path.expanduser(tls_cert)) if tls_cert else True

        def httpx_client_factory(
            headers=None,
            timeout=None,
            auth=None,
            follow_redirects: bool | None = None,
            **kwargs,
        ):
            del follow_redirects, kwargs
            return httpx.AsyncClient(
                headers=headers,
                timeout=timeout or httpx.Timeout(30.0, read=300.0),
                auth=auth,
                verify=verify,
                follow_redirects=False,
            )

        transport = StreamableHttpTransport(
            url=url,
            headers=headers or None,
            auth=config.get("bearer_token") or None,
            httpx_client_factory=httpx_client_factory,
        )
        transport.forward_incoming_headers = False
        client = Client(transport)
        if hasattr(client.transport, "forward_incoming_headers"):
            client.transport.forward_incoming_headers = False
        return client

    return FastMCPProxy(
        client_factory=client_factory,
        name=f"sift-gateway/{backend_name}",
    )


def _validate_egress_url(url: str, *, label: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be an http(s) URL with a hostname")
    host = parsed.hostname
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"{label} hostname could not be resolved") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(f"{label} resolves to a blocked private/link-local address")


async def assert_mounted_tool_names(mcp: FastMCP, expected: set[str]) -> None:
    """Startup assertion for manifest namespace preservation."""
    actual = {tool.name for tool in await mcp.list_tools()}
    missing = expected - actual
    if missing:
        raise ValueError(f"Mounted proxy tools missing from FastMCP catalog: {sorted(missing)}")
