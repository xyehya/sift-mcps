"""Gateway class: backend management, tool aggregation, FastAPI app."""

import asyncio
import contextlib
import logging
import time

from fastapi import FastAPI
from fastmcp.utilities.lifespan import combine_lifespans
from mcp.types import TextContent, Tool
from sift_common.audit import AuditWriter
from sift_core.agent_tools import (
    call_core_tool,
    core_tool_names,
    core_tool_specs,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route

from sift_gateway.auth import AuthMiddleware


class _PortalHTTPSGuard:
    """Return 400 on plain-HTTP portal requests when TLS is configured."""

    def __init__(self, app, tls_configured: bool):
        self.app = app
        self.tls_configured = tls_configured

    async def __call__(self, scope, receive, send):
        if (
            self.tls_configured
            and scope["type"] == "http"
            and scope.get("scheme") == "http"
            and scope.get("path", "").startswith("/portal")
        ):
            resp = PlainTextResponse(
                "Portal requires HTTPS. Connect via https://...", status_code=400
            )
            await resp(scope, receive, send)
            return
        await self.app(scope, receive, send)


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce security headers on all responses, and portal-specific CSP."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        content_type = response.headers.get("content-type", "")
        if "text/html" in content_type:
            path = request.url.path
            if path.startswith("/portal"):
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "font-src 'self' https://fonts.gstatic.com"
                )
        return response



class _NormalizeMCPPath:
    """Append trailing slash to mounted MCP paths internally.

    Starlette Mount("/mcp") and Mount("/mcp/name") return a 307 redirect for
    the exact no-slash path. MCP streaming clients should use /mcp without
    handling a redirect, so this middleware rewrites the path in-place before
    Starlette routing.
    """

    def __init__(
        self,
        app,
        backend_paths: frozenset[str] = frozenset(),
        aggregate_path: str = "/mcp",
    ):
        self.app = app
        self.backend_paths = backend_paths
        self.aggregate_path = aggregate_path

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path", "") in (
            self.backend_paths | {self.aggregate_path}
        ):
            scope = dict(scope)
            scope["path"] += "/"
            if scope.get("raw_path"):
                scope["raw_path"] = scope["raw_path"] + b"/"
        await self.app(scope, receive, send)


from sift_gateway.audit_helpers import (
    _extract_audit_id,
    _summarize_result,
    _truncate_params,
)
from sift_gateway.backends import MCPBackend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.config import apply_case_env, apply_execute_security_env
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import MCPAuthASGIApp
from sift_gateway.mcp_server import (
    _normalize_output_schema,
    create_gateway_mcp_server,
    expected_mounted_tool_names,
)
from sift_gateway.rest import rest_routes
from sift_gateway.token_registry import create_token_registry

logger = logging.getLogger(__name__)


_RETIRED_CORE_BACKENDS = frozenset(
    {"forensic-mcp", "case-mcp", "sift-mcp", "report-mcp"}
)


def _sanitize_output_schema(tool: Tool) -> None:
    """B-MVP-038 gateway defense: repair/strip any aggregated tool's invalid
    ``outputSchema`` before it is advertised.

    The MCP spec requires ``outputSchema`` to be an object-typed JSON Schema.
    A single tool advertising an invalid schema (observed in the wild:
    ``outputSchema.type = null``) is rejected wholesale by
    strict MCP clients (the Claude Code harness) with ``expected "object"`` —
    which drops the *entire* aggregated tools/list and degrades the whole MCP
    surface. The FastMCP ``/mcp`` path already normalizes via the catalog
    middleware; this applies the same single-source repair to every
    aggregation-built Tool object on the REST/``get_tools_list`` and
    ``_tool_cache`` paths — core tools and proxied backends alike — so no single
    tool can poison the catalog. Best-effort: never raises (a non-dict / None
    ``outputSchema`` is a safe no-op in ``_normalize_output_schema``).
    """
    try:
        _normalize_output_schema(tool)
    except Exception as exc:  # pragma: no cover - defensive; must not break list
        logger.warning(
            "outputSchema sanitization failed for tool %r: %s; stripping schema",
            getattr(tool, "name", "?"),
            exc,
        )
        with contextlib.suppress(Exception):
            tool.outputSchema = None


class Gateway:
    """Aggregates multiple MCP backends behind a single HTTP service.

    Manages backend lifecycles, builds a unified tool map, and routes
    tool calls to the appropriate backend.
    """

    def __init__(self, config: dict):
        self.config = config
        apply_case_env(self.config)
        apply_execute_security_env(self.config)
        self.backends: dict[str, MCPBackend] = {}
        # OSX1: FastMCP proxy mount bookkeeping. Backends whose stdio/http proxy
        # is mounted on the live FastMCP server. Used so a late-seeded registry
        # reload (reload_backend_registry) mounts a newly-appeared backend exactly
        # once without a full gateway restart.
        self._mounted_proxy_backends: set[str] = set()
        self._fastmcp_server = None
        self._tool_map: dict[str, str] = {}  # tool_name -> backend_name
        self._tool_cache: dict[str, Tool] = {}  # tool_name -> Tool object
        self._start_locks: dict[str, asyncio.Lock] = {}
        self._audit = AuditWriter(mcp_name="sift-gateway")
        self._available_backends: set[str] = set()
        self.mcp_backend_registry = None
        self._mcp_catalog_loaded_at = None
        # tool_name -> manifest-declared UX metadata (category / recommended_phase /
        # health / health_args / hidden_from_agent / backend). Rebuilt on every
        # _build_tool_map so the gateway never hardcodes add-on tool names.
        self._tool_manifest_meta: dict[str, dict] = {}
        self.active_case_service = None
        self.control_plane_dsn = None
        self.evidence_service = None
        self.investigation_service = None
        self.report_service = None
        self._gateway_local_tools: set[str] = set()
        # BATCH-D2: Gateway adapter over the D1 durable job state machine. Built
        # in create_app() once the control-plane DSN is resolved.
        self.job_service = None
        # BATCH-K1: DB-first transport audit sink (app.audit_events). Wired in
        # create_app() when a control-plane DSN is present; None means file-only
        # legacy audit (no DB-active enforcement).
        self.db_audit = None

        # Register declaration-driven providers: grounding reference backends
        # and the available-backend capability summary (both keyed on manifest
        # capabilities.provides — no hardcoded add-on names).
        from sift_core.case_manager import (
            set_backend_capability_provider,
            set_reference_backend_provider,
        )
        set_reference_backend_provider(self.get_reference_backends)
        set_backend_capability_provider(self.get_available_backend_capabilities)

        # D22A: add-on backend authority is app.mcp_backends, not gateway.yaml.
        # If there is no control-plane DSN, serve core tools only and make the
        # stale yaml block inert rather than treating it as fallback authority.
        from sift_gateway.token_registry import registry_config

        dsn, _ = registry_config(config)
        self.control_plane_dsn = dsn
        if dsn:
            try:
                from sift_gateway.mcp_backends_registry import McpBackendRegistry

                self.mcp_backend_registry = McpBackendRegistry(dsn, audit=self._audit)
                self.backends, self._mcp_catalog_loaded_at = (
                    self.mcp_backend_registry.create_backend_instances()
                )
                logger.info(
                    "Loaded %d add-on backend(s) from app.mcp_backends",
                    len(self.backends),
                )
                # B-MVP-032: warn if any first-party backend's on-disk
                # sift-backend.json has drifted from the registered manifest
                # snapshot this install is serving. Warn-only: never blocks boot,
                # never mutates the registry.
                try:
                    self.mcp_backend_registry.check_manifest_drift()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("manifest-drift check skipped: %s", exc)
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error("Failed to load app.mcp_backends registry: %s", exc)
                self.backends = {}
                self._mcp_catalog_loaded_at = None
        elif config.get("backends"):
            logger.warning(
                "Ignoring gateway.yaml backends because no control-plane DSN is "
                "configured; serving core tools only"
            )

    @property
    def lazy_start(self) -> bool:
        """Whether backends start on first request instead of on boot."""
        gw_config = self.config.get("gateway", {})
        return gw_config.get("lazy_start", False)

    @property
    def idle_timeout(self) -> int:
        """Seconds of idle time before a backend is stopped. 0 = never."""
        gw_config = self.config.get("gateway", {})
        return gw_config.get("idle_timeout_seconds", 0)

    async def start(self) -> None:
        """Build the manifest tool map for the FastMCP gateway.

        D27b moves the MCP wire layer to FastMCP proxy providers, so the
        gateway no longer starts the retired low-level backend sessions during
        app startup. REST service controls can still start a backend explicitly.
        """
        await self._build_tool_map()

    async def _notify_backend_case(self, backend) -> None:
        """Best-effort active-case notification for backends that support it.

        PR03B removed active-case env inheritance. HTTP backends may grow a
        dedicated DB-context notification API later; until then startup must not
        fail just because there is nothing to notify.
        """
        if not isinstance(backend, HttpMCPBackend):
            return
        logger.debug("No HTTP active-case notification endpoint for %s", backend.name)

    async def stop(self) -> None:
        """Stop all backends."""
        for name, backend in self.backends.items():
            try:
                await asyncio.wait_for(backend.stop(), timeout=10.0)
                logger.info("Stopped backend: %s", name)
            except asyncio.TimeoutError:
                logger.error("Backend %s stop timed out after 10s", name)
            except (ConnectionError, OSError) as exc:
                logger.error("Error stopping backend %s (connection): %s", name, exc)
            except BaseException as exc:
                logger.error(
                    "Error stopping backend %s: %s: %s", name, type(exc).__name__, exc
                )
        self._tool_map.clear()
        self._tool_cache.clear()

    async def restart_backends(self) -> None:
        """Stop and restart all backends to reload active case."""
        logger.info("Restarting all MCP backends...")
        await self.stop()
        await self.start()


    def evaluate_requirement(self, req: str) -> bool:
        """Evaluate a declared backend requirement."""
        import os
        import re
        import shutil
        
        req = req.strip()
        if not req:
            return True
            
        if req.lower() == "docker":
            return shutil.which("docker") is not None
            
        if req.lower().startswith("ram:"):
            try:
                total_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
                total_gb = total_bytes / (1024 ** 3)
            except Exception:
                total_gb = 16.0
                
            match = re.match(r"ram:(\d+(?:\.\d+)?)\s*(gb|g|mb|m)?", req, re.IGNORECASE)
            if match:
                val = float(match.group(1))
                unit = (match.group(2) or "gb").lower()
                required_gb = val if "g" in unit else val / 1024
                return total_gb >= required_gb
            return True
            
        if req.lower().startswith("env:"):
            var_name = req[4:].strip()
            if var_name not in os.environ:
                return False
            val = os.environ[var_name]
            if val.startswith("/") or val.startswith("./") or val.startswith("../"):
                if not os.path.exists(val):
                    return False
            return True
            
        host = ""
        port = 0
        if req.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            try:
                parsed = urlparse(req)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            except Exception:
                pass
        elif ":" in req:
            parts = req.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
                
        if host and port:
            import socket
            try:
                with socket.create_connection((host, port), timeout=2.0):
                    return True
            except Exception:
                return False

        # Fail closed: an unrecognized requirement string is treated as unmet so
        # a typo'd `requires[]` entry gates the backend loudly instead of
        # silently passing. The backend is omitted from tools/list (core stays
        # up); the operator sees the warning and fixes the manifest.
        logger.warning(
            "Unknown requirement format: %r — treating as UNMET (backend gated).", req
        )
        return False

    def get_reference_backends(self) -> list[str]:
        res = []
        for name in self._available_backends:
            backend = self.backends.get(name)
            manifest = getattr(backend, "manifest", None) if backend else None
            if manifest:
                provides = manifest.get("capabilities", {}).get("provides", [])
                if "reference" in provides:
                    res.append(name)
        return res

    def get_available_backend_capabilities(self) -> list[dict]:
        """Registered + available backends with the capabilities their manifests
        advertise. Declaration-driven; the core uses this to build
        platform_capabilities without hardcoding add-on names or probing for
        installed packages."""
        res = []
        for name in self._available_backends:
            backend = self.backends.get(name)
            manifest = getattr(backend, "manifest", None) if backend else None
            if not manifest:
                continue
            res.append(
                {
                    "name": name,
                    "namespace": manifest.get("namespace", ""),
                    "provides": list(
                        manifest.get("capabilities", {}).get("provides", [])
                    ),
                }
            )
        return res

    async def _build_tool_map(self) -> None:
        """Build a map from tool names to backend names.

        If two backends expose the same tool name, raises ValueError.
        """
        raw_map: dict[str, list[str]] = {}  # tool_name -> [backend_names]
        tool_objects: dict[str, Tool] = {}  # tool_name -> Tool
        manifest_meta: dict[str, dict] = {}  # tool_name -> UX metadata from manifest
        self._available_backends.clear()

        for name, backend in self.backends.items():
            is_available = True
            manifest = getattr(backend, "manifest", None)
            if manifest:
                reqs = manifest.get("capabilities", {}).get("requires", [])
                for r in reqs:
                    if not self.evaluate_requirement(r):
                        logger.warning(
                            "Backend %s requires %r which is not met. Gating this backend.",
                            name,
                            r,
                        )
                        is_available = False
                        break
            if not is_available:
                continue

            self._available_backends.add(name)

            # Index manifest-declared UX metadata so the gateway can categorize
            # tools, recommend phases, and filter the agent view without
            # hardcoding any add-on tool name (R-no-hardcoded-names).
            if manifest:
                # H1 (BATCH-D2): the backend-level authority_contract is advisory
                # add-on metadata; the Gateway is the enforcement boundary. Index
                # it per tool so AddonAuthorityMiddleware can deny prohibited
                # operations and missing required_scopes BEFORE backend dispatch.
                authority_contract = manifest.get("authority_contract")
                if not isinstance(authority_contract, dict):
                    authority_contract = None
                for t_decl in manifest.get("tools", []):
                    t_meta_name = t_decl.get("name")
                    if not t_meta_name:
                        continue
                    required_scopes = t_decl.get("required_scopes")
                    required_scopes = (
                        [str(s) for s in required_scopes]
                        if isinstance(required_scopes, list)
                        else []
                    )
                    # OS2: safe_case_argument_names — manifest-declared list of
                    # argument names that the Gateway may safely inject the DB
                    # active case_id into without the agent's explicit input.
                    # - list present (possibly empty): manifest knows whether this
                    #   tool accepts a case arg; empty means "case-scoped but no
                    #   injection argument" (allowed through without injection).
                    # - None (key absent): legacy/unknown; falls back to schema
                    #   property detection in safe_case_argument_names().
                    _raw_scans = t_decl.get("safe_case_argument_names")
                    if isinstance(_raw_scans, list):
                        _scans_value: list[str] | None = [
                            str(s) for s in _raw_scans
                            if s in ("case_id", "case_key", "case_dir")
                        ]
                    else:
                        _scans_value = None

                    manifest_meta[t_meta_name] = {
                        "backend": name,
                        # K1: read-only marker for the DB-first audit envelope so
                        # only mutating add-on tools fail closed on audit failure.
                        "read_only": bool(
                            t_decl.get("read_only") or t_decl.get("readOnlyHint", False)
                        ),
                        "category": t_decl.get("category", ""),
                        "recommended_phase": t_decl.get("recommended_phase", ""),
                        "health": bool(t_decl.get("health", False)),
                        "health_args": t_decl.get("health_args", {}) or {},
                        "hidden_from_agent": bool(t_decl.get("hidden_from_agent", False)),
                        "when_to_use": t_decl.get("when_to_use", ""),
                        "avoid_when": t_decl.get("avoid_when", ""),
                        "output_notes": t_decl.get("output_notes", ""),
                        "case_scoped": t_decl.get(
                            "case_scoped", manifest.get("default_case_scoped")
                        ),
                        "required_scopes": required_scopes,
                        "authority_contract": authority_contract,
                        # OS2: None means absent/unknown; [] means declared-empty.
                        "safe_case_argument_names": _scans_value,
                    }

            if backend.started:
                try:
                    tools = await asyncio.wait_for(backend.list_tools(), timeout=15.0)
                    declared_names = set()
                    if manifest:
                        declared_names = {t["name"] for t in manifest.get("tools", [])}
                    for tool in tools:
                        if tool.name in self._gateway_local_tools:
                            # Gateway-local tools intentionally shadow add-on
                            # tools when the gateway owns the policy boundary
                            # for the operation (for example opensearch_ingest
                            # in DB-active mode).
                            continue
                        if manifest:
                            ns = manifest.get("namespace", "")
                            if ns and not tool.name.startswith(f"{ns}_"):
                                raise ValueError(
                                    f"Tool '{tool.name}' from backend '{name}' does not start with declared namespace prefix '{ns}_'"
                                )
                            if tool.name not in declared_names:
                                raise ValueError(
                                    f"Tool '{tool.name}' from backend '{name}' is not declared in the manifest 'tools' block"
                                )
                        else:
                            logger.warning(
                                "Backend '%s' has no manifest. Gracefully degrading namespace enforcement.",
                                name,
                            )
                        raw_map.setdefault(tool.name, []).append(name)
                        tool_objects[tool.name] = tool
                except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                    if isinstance(exc, ValueError):
                        raise
                    logger.error("Failed to list tools for %s: %s", name, exc)
            else:
                if manifest:
                    ns = manifest.get("namespace", "")
                    for t_decl in manifest.get("tools", []):
                        t_name = t_decl["name"]
                        if t_name in self._gateway_local_tools:
                            continue
                        if ns and not t_name.startswith(f"{ns}_"):
                            raise ValueError(
                                f"Tool '{t_name}' declared in manifest for backend '{name}' does not start with declared namespace prefix '{ns}_'"
                            )
                        tool_obj = Tool(
                            name=t_name,
                            description=t_decl.get("description", ""),
                            inputSchema={"type": "object", "properties": {}},
                            annotations={"readOnlyHint": True} if t_decl.get("read_only") or t_decl.get("readOnlyHint") else None,
                        )
                        raw_map.setdefault(t_name, []).append(name)
                        tool_objects[t_name] = tool_obj
                else:
                    logger.warning(
                        "Backend '%s' is not started and has no manifest. Tools cannot be discovered.",
                        name,
                    )

        new_map: dict[str, str] = {}
        for tool_name, backend_names in raw_map.items():
            if len(backend_names) > 1:
                raise ValueError(
                    f"Tool name collision for {tool_name!r} across backends: {backend_names}"
                )
            if tool_name in core_tool_names():
                raise ValueError(
                    f"Tool name {tool_name!r} from backend {backend_names[0]} collides with in-process core tool"
                )
            new_map[tool_name] = backend_names[0]

        self._tool_map = new_map  # atomic reference swap
        new_cache: dict[str, Tool] = {}
        for mapped_name in new_map:
            if mapped_name in tool_objects:
                cached_tool = Tool(
                    name=mapped_name,
                    title=tool_objects[mapped_name].title,
                    description=tool_objects[mapped_name].description or "",
                    inputSchema=tool_objects[mapped_name].inputSchema,
                    outputSchema=tool_objects[mapped_name].outputSchema,
                    icons=tool_objects[mapped_name].icons,
                    annotations=tool_objects[mapped_name].annotations,
                    meta=tool_objects[mapped_name].meta,
                    execution=tool_objects[mapped_name].execution,
                )
                # B-MVP-038 (gateway defense): a single proxied backend that
                # advertises an invalid outputSchema (e.g. type:null) must not be
                # able to poison the aggregate tools/list — strict MCP clients
                # reject the whole list and the entire surface drops. Repair (or
                # as a last resort strip) any non-object outputSchema here so the
                # tool still surfaces. Applied to the cached copy that is served
                # whenever the live backend list_tools is unavailable.
                _sanitize_output_schema(cached_tool)
                new_cache[mapped_name] = cached_tool
        self._tool_cache = new_cache
        # Keep metadata only for tools that survived into the live map.
        self._tool_manifest_meta = {
            t: manifest_meta[t] for t in new_map if t in manifest_meta
        }

        logger.info(
            "Tool map built: %d add-on tools across %d add-on backends; %d core tools in-process",
            len(self._tool_map),
            len(self.backends),
            len(core_tool_names()),
        )

    async def ensure_backend_started(self, backend_name: str) -> None:
        """Start a backend if it's not running (for lazy start mode).

        Uses a per-backend asyncio.Lock with double-check to prevent
        concurrent requests from spawning duplicate subprocesses.
        Also rebuilds the tool map after starting.
        """
        backend = self.backends.get(backend_name)
        if backend is None:
            return
        if backend.started:
            backend.last_tool_call = time.monotonic()
            return
        lock = self._start_locks.setdefault(backend_name, asyncio.Lock())
        async with lock:
            if backend.started:
                backend.last_tool_call = time.monotonic()
                return
            logger.info("Lazy-starting backend: %s", backend_name)
            await asyncio.wait_for(backend.start(), timeout=60.0)
            backend.last_tool_call = time.monotonic()
            await self._build_tool_map()

    async def _idle_reaper(self) -> None:
        """Background task that stops backends idle longer than the timeout."""
        timeout = self.idle_timeout
        if timeout <= 0:
            return
        logger.info("Idle reaper started (timeout=%ds)", timeout)
        while True:
            await asyncio.sleep(60)
            now = time.monotonic()
            reaped = False
            for name, backend in list(self.backends.items()):
                # Skip HTTP backends — they're remote servers, disconnecting
                # just drops our session for no benefit (server keeps running)
                if isinstance(backend, HttpMCPBackend):
                    continue
                if backend.started and backend.last_tool_call > 0:
                    idle = now - backend.last_tool_call
                    if idle > timeout:
                        logger.info(
                            "Stopping idle backend: %s (idle %.0fs)", name, idle
                        )
                        try:
                            await backend.stop()
                            reaped = True
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            logger.error(
                                "Error stopping idle backend %s: %s", name, exc
                            )
            if reaped:
                await self._build_tool_map()

    async def reload_backend_registry(self) -> bool:
        """OSX1: pick up backends seeded into app.mcp_backends after __init__.

        The gateway instantiates add-on backends ONCE in ``__init__`` from
        ``app.mcp_backends``. When the installer (or an operator via the portal)
        seeds a row *after* the gateway started, that backend was historically
        invisible until a full restart — the "no tools until restart" race. This
        re-reads the registry, instantiates any enabled row not already present,
        mounts its FastMCP proxy onto the live aggregate server, and rebuilds the
        tool map. It is additive only (never drops a running backend here) and a
        no-op when there is no control-plane registry.

        Returns ``True`` when at least one new backend was added this call.
        """
        registry = self.mcp_backend_registry
        if registry is None:
            return False
        try:
            instances, loaded_at = await asyncio.to_thread(
                registry.create_backend_instances
            )
        except (Exception, BaseExceptionGroup) as exc:
            logger.warning("reload_backend_registry: registry read failed: %s", exc)
            return False

        new_names = [name for name in instances if name not in self.backends]
        if not new_names:
            # Keep the catalog timestamp fresh even when nothing changed.
            if loaded_at is not None:
                self._mcp_catalog_loaded_at = loaded_at
            return False

        from sift_gateway.mcp_server import mount_single_addon_proxy

        added = False
        for name in new_names:
            backend = instances[name]
            self.backends[name] = backend
            logger.info("reload_backend_registry: discovered late-seeded backend %s", name)
            mcp = self._fastmcp_server
            if mcp is not None:
                try:
                    mount_single_addon_proxy(mcp, self, name, backend)
                except (Exception, BaseExceptionGroup) as exc:
                    logger.warning(
                        "reload_backend_registry: proxy mount failed for %s: %s",
                        name,
                        exc,
                    )
            added = True

        if added:
            self._mcp_catalog_loaded_at = loaded_at
            await self._build_tool_map()
            logger.info(
                "reload_backend_registry: mounted %d late-seeded backend(s): %s",
                len(new_names),
                ", ".join(new_names),
            )
        return added

    async def _late_start_checker(self) -> None:
        """Periodically retry failed backends, pick up late-seeded ones, re-sync.

        OSX1: also re-reads ``app.mcp_backends`` so a backend row seeded after the
        gateway started (the install seed/operator-register race) becomes visible
        WITHOUT a full restart.
        """
        while True:
            try:
                await asyncio.sleep(30)
                # OSX1: discover backends seeded into the registry after boot.
                try:
                    await self.reload_backend_registry()
                except (Exception, BaseExceptionGroup) as exc:
                    logger.warning("Late registry reload failed (will retry): %s", exc)
                for name, backend in list(self.backends.items()):
                    if not backend.started:
                        # OSX1 dedupe: an add-on already served by a mounted
                        # FastMCP proxy does NOT need a second, persistent stdio
                        # subprocess started here — the agent /mcp path uses the
                        # proxy (keep_alive=False, per-session spawn) and the REST
                        # path lazy-starts on demand. Eagerly starting it would
                        # spawn a redundant subprocess that nothing consumes.
                        if name in self._mounted_proxy_backends:
                            continue
                        try:
                            await asyncio.wait_for(backend.start(), timeout=30.0)
                            logger.info("Late-started backend: %s", name)
                            await self._build_tool_map()
                            logger.info(
                                "Tool map rebuilt after late-starting: %s", name
                            )
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            logger.warning("Late-start failed for %s: %s", name, exc)
                            continue
                    # Rebuild tool map if backend reconnected with new code
                    if getattr(backend, "_tool_map_stale", False):
                        backend._tool_map_stale = False
                        await self._build_tool_map()
                        logger.info("Tool map rebuilt after %s reconnected", name)
            except (Exception, BaseExceptionGroup) as exc:
                logger.error("Late-start checker error (will retry): %s", exc)

    @property
    def job_reaper_interval(self) -> int:
        """Seconds between durable-job lease-expiry sweeps. 0 disables."""
        gw_config = self.config.get("gateway", {})
        jobs_cfg = gw_config.get("jobs", {}) if isinstance(gw_config.get("jobs"), dict) else {}
        try:
            return int(jobs_cfg.get("reaper_interval_seconds", 60))
        except (TypeError, ValueError):
            return 60

    async def _job_reaper(self) -> None:
        """Gateway-owned periodic sweep of expired D1 job leases.

        Calls the JobService ``expire_stale_jobs`` adapter (the ``app.
        expire_stale_jobs`` RPC) on a fixed interval so leases whose worker
        stopped heartbeating are re-queued or marked expired. A null/absent job
        service (no control-plane DSN) makes this a no-op so core-only mode is
        unaffected.
        """
        interval = self.job_reaper_interval
        if interval <= 0 or self.job_service is None:
            return
        logger.info("Durable-job reaper started (interval=%ds)", interval)
        while True:
            try:
                await asyncio.sleep(interval)
                await asyncio.to_thread(self.job_service.expire_stale_jobs)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive loop
                logger.warning("Durable-job reaper sweep failed (will retry): %s", exc)

    async def list_tools(self) -> dict[str, str]:
        """Return the current tool map (tool_name -> backend_name)."""
        result = {name: "sift-core" for name in core_tool_names()}
        result.update({name: "sift-gateway" for name in self._gateway_local_tools})
        result.update(self._tool_map)
        return result

    def is_case_scoped_tool(self, tool_name: str) -> bool:
        """Return whether a mounted/add-on tool requires active-case context."""
        if tool_name in core_tool_names():
            return tool_name not in {"get_tool_help", "capability_guide"}
        if tool_name in self._gateway_local_tools:
            return True
        meta = self._tool_manifest_meta.get(tool_name, {})
        if isinstance(meta.get("case_scoped"), bool):
            return bool(meta["case_scoped"])
        tool = self._tool_cache.get(tool_name)
        schema = getattr(tool, "inputSchema", None) if tool else None
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        if any(k in props for k in ("case_id", "case_key", "case_dir")):
            return True
        if any(k in props for k in ("path", "evidence_path", "artifact_path", "file_path")):
            return True
        category = str(meta.get("category") or "").lower()
        phase = str(meta.get("recommended_phase") or "").lower()
        return bool(category or phase) and "reference" not in category

    def safe_case_argument_names(self, tool_name: str) -> set[str] | None:
        """Return the set of argument names safe for DB active-case injection.

        OS2: manifest-declared ``safe_case_argument_names`` takes priority over
        schema-property detection so that tools work correctly even when the
        backend is not yet started and the schema is a placeholder ``{}``.

        Return values:
          - ``set`` (possibly empty): manifest says exactly which args receive
            the injected case_id (empty = case-scoped but no injection arg;
            the middleware lets the call through without injection).
          - ``None``: no manifest declaration and no schema properties match;
            the middleware treats this as "unknown" and denies the call to fail
            closed (original behaviour for non-OpenSearch add-ons).
        """
        # OS2: prefer manifest-declared names over placeholder schema.
        meta = self._tool_manifest_meta.get(tool_name)
        if meta is not None:
            manifest_names = meta.get("safe_case_argument_names")
            if manifest_names is not None:
                # Manifest explicitly declared (possibly empty list).
                return set(manifest_names)
        # Fallback: derive from live schema properties when manifest is absent
        # or the tool entry predates the safe_case_argument_names field.
        tool = self._tool_cache.get(tool_name)
        schema = getattr(tool, "inputSchema", None) if tool else None
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}
        found = {name for name in ("case_id", "case_key", "case_dir") if name in props}
        # Return None (not an empty set) when neither manifest nor schema has
        # an answer — the middleware must deny fail-closed in that case.
        return found if found else None

    def addon_authority_for_tool(self, tool_name: str) -> dict | None:
        """Return the H1 add-on authority enforcement profile for a tool.

        The profile combines the tool-level ``required_scopes`` and the
        backend-level ``authority_contract`` (``non_authoritative``,
        ``prohibited_operations``) declared in the add-on manifest. Returns
        ``None`` for in-process core tools and unknown/unmapped tools (core
        tools enforce their own policy and never carry an add-on contract).
        """
        meta = self._tool_manifest_meta.get(tool_name)
        if not meta:
            return None
        contract = meta.get("authority_contract") or {}
        prohibited = contract.get("prohibited_operations")
        prohibited = (
            [str(op) for op in prohibited] if isinstance(prohibited, list) else []
        )
        return {
            "backend": meta.get("backend"),
            "required_scopes": list(meta.get("required_scopes") or []),
            "non_authoritative": bool(contract.get("non_authoritative", False)),
            "prohibited_operations": prohibited,
        }

    async def get_tools_list(self) -> list[Tool]:
        """Return MCP ``Tool`` objects for all aggregated tools.

        Shared by both the REST and MCP surfaces.
        """
        by_name: dict[str, Tool] = {}
        for name in self._available_backends:
            backend = self.backends[name]
            if backend.started:
                try:
                    for t in await backend.list_tools():
                        by_name[t.name] = t
                except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                    logger.error("get_tools_list: backend error: %s", exc)

        tools: list[Tool] = []
        for spec in core_tool_specs():
            tool = Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.input_schema,
                outputSchema=spec.output_schema,
                annotations={"readOnlyHint": True} if spec.read_only else None,
            )
            # B-MVP-038 (gateway defense): same never-raise repair as proxied
            # tools, so a core tool with a malformed outputSchema also cannot
            # break the aggregate tools/list. No-op when output_schema is None.
            _sanitize_output_schema(tool)
            tools.append(tool)
        if self.job_service is not None:
            from sift_gateway.job_tools import gateway_job_tool_specs

            for spec in gateway_job_tool_specs():
                tools.append(
                    Tool(
                        name=spec["name"],
                        description=spec["description"],
                        inputSchema=spec["parameters"],
                        annotations={"readOnlyHint": True} if spec["read_only"] else None,
                        meta={
                            "category": spec["category"],
                            "recommended_for_phase": spec["phase"],
                        },
                    )
                )
        for mapped_name in self._tool_map:
            src = by_name.get(mapped_name)
            if src is None:
                # Use cached Tool from _build_tool_map if available
                cached = self._tool_cache.get(mapped_name)
                if cached:
                    tools.append(cached)
                else:
                    tools.append(
                        Tool(
                            name=mapped_name,
                            description="",
                            inputSchema={"type": "object", "properties": {}},
                        )
                    )
            else:
                proxied_tool = Tool(
                    name=mapped_name,
                    title=src.title,
                    description=src.description or "",
                    inputSchema=src.inputSchema,
                    outputSchema=src.outputSchema,
                    icons=src.icons,
                    annotations=src.annotations,
                    meta=src.meta,
                    execution=src.execution,
                )
                # B-MVP-038 (gateway defense): sanitize the live-proxied tool's
                # outputSchema the same way core tools are normalized above, so a
                # backend advertising an invalid (e.g. type:null) outputSchema
                # cannot break the aggregate list for strict MCP clients.
                _sanitize_output_schema(proxied_tool)
                tools.append(proxied_tool)
        return tools

    async def call_tool(
        self,
        name: str,
        arguments: dict,
        examiner: str | None = None,
        identity=None,
    ) -> list:
        """Route a tool call to the correct backend.

        Args:
            name: The (possibly prefixed) tool name.
            arguments: Tool arguments dict.
            examiner: Optional examiner identity for auditing.

        Returns:
            List of content items from the backend.

        Raises:
            KeyError: If the tool name is not in the tool map.
            RuntimeError: If the backend is not started.
        """
        active_case = None
        if self.active_case_service is not None and self.is_case_scoped_tool(name):
            active_case = self.active_case_service.require_active_case_for_principal(identity)
            if not active_case.artifact_path:
                raise RuntimeError("Active case has no artifact path for case-scoped tool")

        if name in core_tool_names():
            logger.info(
                "Routing tool %s -> in-process sift-core (examiner=%s)",
                name,
                examiner,
            )
            from sift_core.active_case_context import (
                ActiveCaseContext,
                use_active_case_context,
            )

            context = (
                ActiveCaseContext(
                    case_id=active_case.case_id,
                    case_key=active_case.case_key,
                    artifact_path=active_case.artifact_path,
                    membership_role=active_case.membership_role,
                    principal=getattr(identity, "principal", None),
                    principal_type=getattr(identity, "principal_type", None),
                    tool_scopes=getattr(identity, "tool_scopes", frozenset()) or frozenset(),
                    # K1: a DB active-case service means Postgres is authority for
                    # this request; core must use this context, not env/pointer files.
                    db_active=self.active_case_service is not None,
                )
                if active_case is not None
                else None
            )

            def _run_core():
                with use_active_case_context(context):
                    return call_core_tool(
                        name,
                        arguments,
                        examiner=examiner,
                        audit=self._audit,
                    )

            text = await asyncio.to_thread(_run_core)
            return [TextContent(type="text", text=text)]

        if name not in self._tool_map:
            raise KeyError(f"Unknown tool: {name}")

        backend_name = self._tool_map[name]
        backend = self.backends[backend_name]

        if active_case is not None and self.is_case_scoped_tool(name):
            safe_args = self.safe_case_argument_names(name)
            # OS2: None = unknown/undeclared → deny fail-closed.
            # empty set = manifest says no injection arg → pass through.
            if safe_args is None:
                raise RuntimeError(
                    "proxied case-scoped tool does not expose a safe case_id/case_key argument"
                )
            if safe_args:
                arguments = dict(arguments)
                # case_dir carries the DB-authoritative case directory
                # (artifact_path) for filesystem-touching backends. Gateway-
                # injected; a mismatching client value is rejected.
                for key, expected in (
                    ("case_id", active_case.case_id),
                    ("case_key", active_case.case_key),
                    ("case_dir", active_case.artifact_path or ""),
                ):
                    if key not in safe_args:
                        continue
                    supplied = arguments.get(key)
                    if supplied and str(supplied) != expected:
                        raise RuntimeError(f"client-supplied {key} does not match DB active case")
                    arguments[key] = expected

        # Lazy recovery — restart backend if it crashed
        if not backend.started:
            await self.ensure_backend_started(backend_name)

        backend.last_tool_call = time.monotonic()

        logger.info(
            "Routing tool %s -> backend %s (examiner=%s)",
            name,
            backend_name,
            examiner,
        )

        _start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                backend.call_tool(name, arguments), timeout=300.0
            )
        except asyncio.TimeoutError as exc:
            logger.error(
                "Tool call %s on backend %s timed out after 300s",
                name,
                backend_name,
            )
            if isinstance(backend, HttpMCPBackend):
                elapsed_ms = (time.monotonic() - _start) * 1000
                try:
                    await asyncio.to_thread(
                        self._audit.log,
                        tool=name,
                        params=_truncate_params(arguments),
                        result_summary="timeout after 300s",
                        source="gateway_proxy",
                        elapsed_ms=round(elapsed_ms, 1),
                        extra={"backend": backend_name, "examiner": examiner},
                    )
                except Exception as audit_exc:
                    logger.warning(
                        "Gateway audit failed for %s (timeout path): %s", name, audit_exc
                    )
            raise RuntimeError(f"Tool call {name} timed out after 300s") from exc

        # Centralized audit for HTTP backends (stdio backends audit themselves)
        if isinstance(backend, HttpMCPBackend):
            elapsed_ms = (time.monotonic() - _start) * 1000
            try:
                await asyncio.to_thread(
                    self._audit.log,
                    tool=name,
                    params=_truncate_params(arguments),
                    result_summary=_summarize_result(result),
                    source="gateway_proxy",
                    elapsed_ms=round(elapsed_ms, 1),
                    extra={
                        "backend": backend_name,
                        "examiner": examiner,
                        "backend_audit_id": _extract_audit_id(result),
                    },
                )
            except Exception as exc:
                logger.warning("Gateway audit failed for %s: %s", name, exc)

        return result

    def create_app(self) -> FastAPI:
        """Build a FastAPI application with all routes and middleware.

        The app manages the gateway lifecycle via lifespan events.
        Includes both REST and Streamable HTTP MCP surfaces.
        """
        gateway = self
        api_keys = self.config.get("api_keys", {})
        self._api_keys = api_keys
        token_registry = create_token_registry(self.config)
        from sift_gateway.token_registry import registry_config

        dsn, _ = registry_config(self.config)
        self.control_plane_dsn = dsn
        if dsn:
            try:
                from sift_gateway.audit_helpers import DbAuditWriter

                self.db_audit = DbAuditWriter(dsn)
            except Exception as exc:  # pragma: no cover - defensive startup
                logger.warning("DB audit writer init failed: %s", exc)
            try:
                from sift_gateway.active_case import ActiveCaseService

                self.active_case_service = ActiveCaseService(dsn, audit=self._audit)
            except Exception as exc:  # pragma: no cover - defensive startup
                logger.warning("Active-case service init failed: %s", exc)
            try:
                from sift_gateway.jobs import JobService

                self.job_service = JobService(dsn, audit=self._audit)
            except Exception as exc:  # pragma: no cover - defensive startup
                logger.warning("Job service init failed: %s", exc)
            try:
                from sift_gateway.portal_services import (
                    EvidenceAuthorityService,
                    InvestigationService,
                    ReportService,
                )

                self.evidence_service = EvidenceAuthorityService(dsn)
                self.investigation_service = InvestigationService(dsn)
                self.report_service = ReportService(dsn)
            except Exception as exc:  # pragma: no cover - defensive startup
                logger.warning("Portal DB services init failed: %s", exc)
        self._gateway_local_tools = set()
        if self.job_service is not None:
            from sift_gateway.job_tools import GATEWAY_JOB_TOOLS

            self._gateway_local_tools.update(GATEWAY_JOB_TOOLS)

        # PR03A: build the shared Supabase identity resolver + portal callbacks.
        # Fail-soft: if Supabase is disabled or env/DSN is absent, the gateway
        # runs PR02/legacy-only exactly as before.
        from sift_gateway.config import load_auth_config

        auth_config = load_auth_config(self.config)
        resolver = None
        supabase_callbacks = None
        if auth_config.configured:
            try:
                from sift_gateway.supabase_auth import (
                    AgentServiceIssuance,
                    SupabaseAuthCallbacks,
                    SupabaseAuthClient,
                    SupabaseIdentityResolver,
                    SupabasePrincipalRepository,
                )
                if dsn:
                    sb_client = SupabaseAuthClient(auth_config)
                    repo = SupabasePrincipalRepository(dsn)
                    resolver = SupabaseIdentityResolver(
                        auth_config, client=sb_client, repository=repo
                    )
                    issuance = AgentServiceIssuance(
                        auth_config, sb_client, dsn=dsn, audit=self._audit
                    )
                    supabase_callbacks = SupabaseAuthCallbacks(
                        auth_config, sb_client, repo, resolver,
                        audit=self._audit, agent_issuance=issuance,
                    )
                else:
                    logger.warning(
                        "Supabase auth enabled but no control-plane DSN; "
                        "running PR02/legacy auth only"
                    )
            except Exception as exc:  # pragma: no cover - defensive startup
                logger.warning("Supabase auth init failed (%s); legacy auth only", exc)
                resolver = None
                supabase_callbacks = None

        # Compute allowed origins for Origin header validation (4c)
        gw_conf = self.config.get("gateway", {})
        host = gw_conf.get("host", "127.0.0.1")
        port = gw_conf.get("port", 4508)
        tls_configured = bool(gw_conf.get("tls", {}).get("certfile"))
        scheme = "https" if tls_configured else "http"
        gateway_base_url = f"{scheme}://{host}:{port}"
        allowed_origins: set[str] = {
            gateway_base_url,
            "https://localhost:4508",
            "https://127.0.0.1:4508",
        }
        examiner_calls_per_minute: int = (
            gw_conf.get("rate_limit", {}).get("examiner_calls_per_minute", 120)
        )

        # Build aggregate FastMCP endpoint. Per-backend /mcp/{name} routes
        # are intentionally not mounted (D3/F-7).
        gateway_mcp = create_gateway_mcp_server(
            gateway,
            api_keys=api_keys,
            token_registry=token_registry,
            base_url=f"{gateway_base_url}/mcp",
            resolver=resolver,
            legacy_fallback_enabled=auth_config.legacy_token_fallback_enabled,
        )
        mcp_app = gateway_mcp.http_app(path="/")
        # B-14: when a FastMCP verifier owns identity (Supabase resolver and/or
        # PR02 registry/api_keys), the raw ASGI guard keeps only IP/body/Origin
        # checks and does NOT re-resolve the token on the normal path.
        verifier_owns_identity = bool(
            resolver is not None or api_keys or token_registry is not None
        )
        mcp_asgi_app = MCPAuthASGIApp(
            mcp_app,
            api_keys=api_keys,
            allowed_origins=allowed_origins,
            examiner_calls_per_minute=examiner_calls_per_minute,
            gateway=gateway,
            token_registry=token_registry,
            verifier_owns_identity=verifier_owns_identity,
        )

        @contextlib.asynccontextmanager
        async def app_lifespan(app):
            """Start gateway metadata/background tasks around the FastAPI app."""
            import os as _os
            await gateway.start()
            # wave8/ingest-tools (Blocker B): close the startup mount race. Add-on
            # backend proxies are mounted at app-build time from the backends that
            # __init__ loaded from app.mcp_backends. A backend row seeded into the
            # registry AFTER __init__ but BEFORE serving (the install-seed /
            # operator-register window) would otherwise only be picked up by the
            # 30s _late_start_checker — so a client connecting right after restart
            # would see only the core in-process tools. Re-read the registry and
            # mount any newly-appeared backend HERE, before the first /mcp request
            # is served, so the aggregate tools/list is complete from the start.
            try:
                await gateway.reload_backend_registry()
            except Exception as exc:  # pragma: no cover - defensive startup
                logger.warning("pre-serve backend registry reload failed: %s", exc)
            expected_tools = expected_mounted_tool_names(gateway)
            actual_tools = set((await gateway.list_tools()).keys())
            missing_tools = expected_tools - actual_tools
            if missing_tools:
                raise ValueError(
                    "Mounted proxy tools missing from gateway catalog: "
                    f"{sorted(missing_tools)}"
                )
            # LV1: pre-warm the mounted add-on proxies BEFORE serving /mcp. The
            # mounted FastMCP proxies are lazy stdio subprocesses — without this,
            # the client's FIRST aggregate tools/list spawns the heavy backends
            # (rag-mcp loads the embedder; opensearch-mcp loads its deps) inline
            # and races the client's list timeout -> "Client is not connected" ->
            # the add-on tools drop and tools/list times out (LV1). Warming the
            # aggregate here (with keep_alive=True keeping the subprocess hot)
            # makes the full core+add-on catalog complete and instant from the
            # first reconnect. Best-effort: never fail startup on a slow/absent
            # backend — the 30s late-start checker + per-call lazy start remain.
            try:
                await asyncio.wait_for(
                    gateway_mcp.list_tools(run_middleware=False), timeout=90.0
                )
            except Exception as exc:  # pragma: no cover - best-effort warm
                logger.warning("pre-serve add-on proxy warm-up incomplete: %s", exc)
            reaper_task = None
            if gateway.idle_timeout > 0:
                reaper_task = asyncio.create_task(gateway._idle_reaper())
            late_start_task = asyncio.create_task(gateway._late_start_checker())

            # BATCH-D2: Gateway-owned durable-job lease reaper (app.expire_stale_jobs).
            job_reaper_task = None
            if gateway.job_service is not None and gateway.job_reaper_interval > 0:
                job_reaper_task = asyncio.create_task(gateway._job_reaper())

            # PR03B: no active-case env watcher. Evidence-gate cache invalidation
            # is driven by DB active-case context and portal mutation callbacks.
            watcher_task = None

            yield
            if reaper_task is not None:
                reaper_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reaper_task
            if job_reaper_task is not None:
                job_reaper_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await job_reaper_task
            if watcher_task is not None:
                watcher_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await watcher_task
            late_start_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await late_start_task
            await gateway.stop()

        routes = []
        routes.extend(health_routes())
        routes.extend(rest_routes())

        # Examiner Portal (optional — installed separately)
        try:
            from case_dashboard.routes import create_dashboard_v2_app

            portal_cfg = self.config.get("portal", {})
            portal_secret: str = portal_cfg.get("session_secret", "")
            portal_max_age: int = int(portal_cfg.get("session_max_age", 28800))
            # Resolve the gateway config path for token lifecycle endpoints.
            # Use SIFT_GATEWAY_CONFIG env var if set, otherwise the
            # conventional ~/.sift/gateway.yaml that rest.py uses.
            import os as _os
            from pathlib import Path as _Path
            _gw_config_path: str | None = _os.environ.get("SIFT_GATEWAY_CONFIG") or str(
                _Path.home() / ".sift" / "gateway.yaml"
            )
            from sift_gateway.evidence_gate import invalidate_evidence_cache
            from sift_gateway.response_guard import (
                cancel_override,
                enable_override,
                get_override_status,
            )

            dashboard_app = create_dashboard_v2_app(
                session_secret=portal_secret,
                session_max_age=portal_max_age,
                api_keys=api_keys,
                gateway_config_path=_gw_config_path,
                token_registry=token_registry,
                supabase_auth=supabase_callbacks,
                active_case_service=self.active_case_service,
                evidence_service=self.evidence_service,
                investigation_service=self.investigation_service,
                report_service=self.report_service,
                job_service=self.job_service,
                on_chain_mutation=invalidate_evidence_cache,
                on_case_activated=None,
                on_override_get_status=get_override_status,
                on_override_enable=enable_override,
                on_override_cancel=cancel_override,
            )
            dashboard_app.state.gateway = self

            # PT1/WI3: ergonomic root + bare-/portal redirects. Mount("/portal")
            # only serves "/portal/..."; a request for "/" or "/portal" (no
            # trailing slash) would otherwise 404. Redirect both to "/portal/".
            async def _redirect_to_portal(_request) -> RedirectResponse:
                return RedirectResponse(url="/portal/", status_code=307)

            routes.append(Route("/", _redirect_to_portal, methods=["GET"]))
            routes.append(Route("/portal", _redirect_to_portal, methods=["GET"]))
            routes.append(Mount("/portal", app=dashboard_app))
        except ImportError as exc:
            logger.info("Portal dashboard not available (optional dependency): %s", exc)

        routes.append(Mount("/mcp", app=mcp_asgi_app))

        app = FastAPI(
            routes=routes,
            lifespan=combine_lifespans(app_lifespan, mcp_app.lifespan),
        )

        # Attach gateway to app state so endpoints can access it
        app.state.gateway = gateway

        async def _sanitized_error(request, exc):
            """Global unhandled exception handler — never leak file paths or tracebacks."""
            logger.exception("Unhandled error: %s", exc)
            from starlette.responses import JSONResponse as _JSONResponse
            return _JSONResponse({"error": "Internal server error"}, status_code=500)

        app.add_exception_handler(Exception, _sanitized_error)

        # Add auth middleware (skips /mcp — handled by MCPAuthASGIApp).
        # PR03A: Supabase JWT validated first via the shared resolver; PR02/legacy
        # api_keys are fallback behind explicit flags in auth_config.
        app.add_middleware(
            AuthMiddleware,
            api_keys=api_keys,
            token_registry=token_registry,
            resolver=resolver,
            auth_config=auth_config,
        )

        # CORS — restrict origins to the gateway's own URL
        gw_cfg = self.config.get("gateway", {})
        tls_configured = bool(gw_cfg.get("tls", {}).get("certfile"))
        scheme = "https" if tls_configured else "http"
        gw_host = gw_cfg.get("host", "0.0.0.0")
        gw_port = gw_cfg.get("port", 4508)
        gateway_origin = f"{scheme}://{gw_host}:{gw_port}"
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[gateway_origin, "https://localhost:4508"],
            allow_methods=["GET", "POST", "DELETE"],
            allow_credentials=True,
            allow_headers=["Authorization", "Content-Type", "MCP-Protocol-Version"],
        )

        # Normalize aggregate MCP path (must be outermost = added last)
        app.add_middleware(_NormalizeMCPPath, backend_paths=frozenset())

        # HTTPS enforcement for portal paths (outermost — added after _NormalizeMCPPath)
        app.add_middleware(_PortalHTTPSGuard, tls_configured=tls_configured)

        # Secure headers middleware (outermost — added after _PortalHTTPSGuard)
        app.add_middleware(SecureHeadersMiddleware)

        return app
