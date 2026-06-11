"""FastMCP 3 server assembly for the SIFT gateway."""

from __future__ import annotations

import asyncio
import ipaddress
import json
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
    "job_status": "ingest",
    "ingest_job": "ingest",
    "run_command_job": "detection",
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
    "job_status": "INGEST",
    "ingest_job": "INGEST",
    "run_command_job": "TRIAGE",
}


_DB_ORIENTED_TOOLS: frozenset[str] = frozenset({"case_info", "evidence_info"})
_INTERNAL_RESOLVED_EVIDENCE_REFS = "_resolved_evidence_refs"
_INTERNAL_EVIDENCE_REF_ERROR = "_evidence_ref_error"


def _overlay_db_evidence_gate(gateway: Any, tool_name: str, text: str) -> str:
    """AUT1-B1: overlay DB-authority evidence-gate status onto the file-backed
    orientation returned by ``case_info``/``evidence_info``.

    In DB-active deployments the evidence gate that actually governs execution is
    ``app.evidence_gate_status`` (resolved by the gateway/policy path), but the
    core orientation tools still describe the legacy file manifest. When the file
    manifest is absent/stale these two disagree (e.g. orientation says
    ``unsealed/ok=false`` while the DB gate is ``sealed`` and tools run), which is
    a stall trap for an autonomous agent following the documented "ok=false → hand
    back to operator" loop. This overlay makes orientation reflect the same DB gate
    the agent's mutating calls hit. It is a no-op in legacy/file mode (no
    control-plane DSN) so core tools stay file-based there.
    """
    dsn = getattr(gateway, "control_plane_dsn", None)
    if not dsn:
        return text
    from sift_gateway.policy_middleware import _current_gateway_active_case

    case = _current_gateway_active_case()
    if case is None:
        return text
    try:
        from sift_gateway.evidence_gate import check_evidence_gate_db

        gate = check_evidence_gate_db(case.case_id, dsn)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("evidence-gate overlay failed for %s: %s", tool_name, exc)
        return text
    try:
        obj = json.loads(text)
    except (TypeError, ValueError):
        return text
    if not isinstance(obj, dict):
        return text

    # gate["status"] is a ChainStatus(str, Enum); use its plain value ("ok",
    # "unsealed", ...) so orientation matches the rest of the API surface rather
    # than serialising the enum repr ("ChainStatus.OK").
    status = getattr(gate["status"], "value", gate["status"])
    blocked = bool(gate["blocked"])
    issues = gate["issues"]
    manifest_version = gate["manifest_version"]
    if tool_name == "case_info":
        chain = obj.get("evidence_chain")
        if isinstance(chain, dict):
            chain["status"] = status
            chain["ok"] = not blocked
            chain["issues"] = issues
            chain["manifest_version"] = manifest_version
            chain["authority"] = "db"
        _overlay_db_findings_counters(gateway, obj, case.case_id)
    elif tool_name == "evidence_info":
        obj["chain_status"] = status
        obj["issues"] = issues
        obj["manifest_version"] = manifest_version
        obj["requires_examiner_action"] = blocked
        obj["authority"] = "db"
        _overlay_db_evidence_listing(gateway, obj, case.case_id)
    return json.dumps(obj, indent=2, default=str)


def _overlay_db_findings_counters(gateway: Any, obj: dict[str, Any], case_id: str) -> None:
    """AUT2-B6: make case_info findings counters DB-authoritative.

    ``list_existing_findings`` reads ``app.investigation_findings`` in DB-active
    deployments, while the file-backed orientation counters can lag (the case
    JSON is only a mirror). Replace the counters with the same DB rows the list
    tool reports and mark them ``authority: db``. Best-effort: any failure keeps
    the file-backed counters so orientation never breaks on a DB hiccup.
    """
    dsn = getattr(gateway, "control_plane_dsn", None)
    if not dsn:
        return
    try:
        from sift_core.investigation_store import PostgresInvestigationStore

        rows = PostgresInvestigationStore(dsn).list_findings(case_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("DB findings counter overlay failed: %s", exc)
        return
    statuses = [
        str(row.get("status") or "") for row in rows or [] if isinstance(row, dict)
    ]
    counters = obj.get("findings")
    if not isinstance(counters, dict):
        counters = {}
        obj["findings"] = counters
    counters["total"] = len(statuses)
    counters["draft"] = sum(1 for s in statuses if s == "DRAFT")
    counters["approved"] = sum(1 for s in statuses if s == "APPROVED")
    counters["authority"] = "db"


def _overlay_db_evidence_listing(gateway: Any, obj: dict[str, Any], case_id: str) -> None:
    """Replace legacy file-manifest evidence listing with DB evidence objects.

    The DB service returns only portal-safe fields plus an internal path on the
    resolver path. ``list_evidence`` has no path field, but this helper still
    copies fields explicitly so agent-facing orientation never grows a new local
    path by accident.
    """
    service = getattr(gateway, "evidence_service", None)
    lister = getattr(service, "list_evidence", None)
    if not callable(lister):
        return
    try:
        rows = lister(case_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("DB evidence listing overlay failed: %s", exc)
        return
    sealed: list[dict[str, Any]] = []
    unregistered: list[str] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "")
        seal_status = str(row.get("seal_status") or "")
        display_path = str(row.get("display_path") or "")
        if status in {"detected", "registered"}:
            if display_path:
                unregistered.append(display_path)
            continue
        if status != "sealed" or seal_status != "sealed":
            continue
        sealed.append(
            {
                "evidence_id": row.get("evidence_id"),
                "display_name": row.get("display_name"),
                "display_path": display_path,
                "description": row.get("description"),
                "source": row.get("source"),
                "status": status,
                "seal_status": seal_status,
                "sha256": row.get("current_sha256"),
                "size_bytes": row.get("current_bytes"),
                "sealed_at": row.get("sealed_at"),
            }
        )
    obj["evidence_files"] = sealed
    obj["total_evidence_files"] = len(sealed)
    obj["unregistered_files"] = unregistered
    obj["listing_authority"] = "db"


def _prepare_core_tool_arguments(gateway: Any, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Strip private fields from client args and inject Gateway-resolved refs."""
    prepared = dict(arguments or {})
    prepared.pop(_INTERNAL_RESOLVED_EVIDENCE_REFS, None)
    prepared.pop(_INTERNAL_EVIDENCE_REF_ERROR, None)
    if tool_name != "run_command" or not prepared.get("evidence_refs"):
        return prepared
    try:
        resolved = _resolve_db_evidence_refs(gateway, prepared.get("evidence_refs"))
    except Exception as exc:  # noqa: BLE001 - return typed core error, no raw path
        reason = getattr(exc, "reason", None) or str(exc) or "evidence_ref_resolution_failed"
        prepared[_INTERNAL_EVIDENCE_REF_ERROR] = str(reason)
        return prepared
    if resolved:
        prepared[_INTERNAL_RESOLVED_EVIDENCE_REFS] = resolved
    return prepared


def _resolve_db_evidence_refs(gateway: Any, evidence_refs: Any) -> list[dict[str, str]]:
    if not evidence_refs:
        return []
    if isinstance(evidence_refs, str):
        refs = [evidence_refs]
    elif isinstance(evidence_refs, (list, tuple)):
        refs = [str(ref) for ref in evidence_refs if str(ref).strip()]
    else:
        return []
    from sift_gateway.policy_middleware import _current_gateway_active_case

    case = _current_gateway_active_case()
    service = getattr(gateway, "evidence_service", None)
    resolver = getattr(service, "resolve_evidence_reference", None)
    if case is None or not callable(resolver):
        return []
    resolved: list[dict[str, str]] = []
    for ref in refs:
        item = resolver(case.case_id, ref)
        resolved.append(
            {
                "ref": ref,
                "evidence_id": str(item.get("evidence_id") or ""),
                "display_path": str(item.get("display_path") or ref),
                "path": str(item.get("path") or ""),
            }
        )
    return resolved


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
            arguments = _prepare_core_tool_arguments(self._gateway, self.name, arguments)
            value = await asyncio.to_thread(
                call_core_tool,
                self.name,
                arguments,
                examiner=examiner,
                audit=self._gateway._audit,
            )
            if self.name in _DB_ORIENTED_TOOLS and isinstance(value, str):
                value = await asyncio.to_thread(
                    _overlay_db_evidence_gate, self._gateway, self.name, value
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
    resolver: Any | None = None,
    legacy_fallback_enabled: bool = True,
) -> FastMCP:
    """Create the aggregate FastMCP server for the gateway."""
    verifier = None
    # A verifier is needed whenever any credential authority exists: a Supabase
    # resolver, the PR02 registry, or legacy api_keys.
    auth_enabled = bool(resolver is not None or api_keys or token_registry is not None)
    if auth_enabled:
        verifier = SiftTokenVerifier(
            api_keys=api_keys,
            token_registry=token_registry,
            base_url=base_url,
            resolver=resolver,
            legacy_fallback_enabled=legacy_fallback_enabled,
        )
    # B6: when auth is configured, tool authorization fails closed on a missing
    # identity. In anonymous single-user mode (no verifier) the catalog is open.
    middlewares = [
        GatewayToolCatalogMiddleware(gateway),
        *gateway_policy_middlewares(gateway, auth_enabled=auth_enabled),
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

    _register_gateway_job_tools(mcp, gateway)


def _register_gateway_job_tools(mcp: FastMCP, gateway: Any) -> None:
    if getattr(gateway, "job_service", None) is None:
        return
    from sift_gateway.job_tools import gateway_job_tool_specs

    for spec in gateway_job_tool_specs():
        async def _handler(
            arguments: dict[str, Any],
            examiner: str | None,
            *,
            _tool_handler=spec["handler"],
        ):
            return await _tool_handler(gateway, arguments, examiner)

        mcp.add_tool(
            GatewayLocalTool(
                gateway=gateway,
                handler=_handler,
                name=spec["name"],
                description=spec["description"],
                parameters=spec["parameters"],
                annotations=ToolAnnotations(readOnlyHint=bool(spec["read_only"])),
                meta={
                    "category": spec["category"],
                    "recommended_for_phase": spec["phase"],
                },
            )
        )


def _mount_addon_proxies(mcp: FastMCP, gateway: Any) -> None:
    for backend_name, backend in sorted(getattr(gateway, "backends", {}).items()):
        mount_single_addon_proxy(mcp, gateway, backend_name, backend)


def mount_single_addon_proxy(
    mcp: FastMCP, gateway: Any, backend_name: str, backend: Any
) -> bool:
    """Mount one add-on backend's FastMCP stdio/http proxy onto ``mcp``.

    Idempotent: a ``gateway._mounted_proxy_backends`` set tracks which backends
    already have a proxy mounted so a late-seeded reload (OSX1) does not mount the
    same backend twice. Requirement-gated backends are skipped (returns ``False``).

    Returns ``True`` when a new proxy was mounted this call.
    """
    manifest = getattr(backend, "manifest", None)
    if not manifest:
        return False
    mounted = getattr(gateway, "_mounted_proxy_backends", None)
    if mounted is None:
        mounted = set()
        gateway._mounted_proxy_backends = mounted
    if backend_name in mounted:
        return False
    reqs = manifest.get("capabilities", {}).get("requires", [])
    unmet = [req for req in reqs if not gateway.evaluate_requirement(req)]
    if unmet:
        return False
    proxy = _create_backend_proxy(backend_name, backend.config, manifest)
    namespace = str(manifest.get("namespace") or "") or None
    mcp.mount(
        proxy,
        namespace=namespace,
        tool_names=_tool_rename_map(manifest),
    )
    mounted.add(backend_name)
    return True


def expected_mounted_tool_names(gateway: Any) -> set[str]:
    expected: set[str] = set()
    local_tools = getattr(gateway, "_gateway_local_tools", None) or set()
    for backend_name, backend in sorted(getattr(gateway, "backends", {}).items()):
        manifest = getattr(backend, "manifest", None)
        if not manifest:
            continue
        reqs = manifest.get("capabilities", {}).get("requires", [])
        unmet = [req for req in reqs if not gateway.evaluate_requirement(req)]
        if unmet:
            continue
        for tool in manifest.get("tools", []):
            tool_name = tool.get("name")
            if isinstance(tool_name, str) and tool_name and tool_name not in local_tools:
                expected.add(tool_name)
    return expected


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
    env = _stdio_base_env()
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


def _stdio_base_env() -> dict[str, str]:
    """Return the minimal process environment stdio add-ons need to start."""
    env: dict[str, str] = {}
    for key in (
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TMPDIR",
        "TEMP",
        "TMP",
    ):
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key, value in os.environ.items():
        if key.startswith("LC_") and value:
            env[key] = value
    return env


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
