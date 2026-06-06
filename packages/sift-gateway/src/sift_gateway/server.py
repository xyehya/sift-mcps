"""Gateway class: backend management, tool aggregation, Starlette app."""

import asyncio
import contextlib
import logging
import time

import anyio
from mcp.types import TextContent, Tool
from sift_common.audit import AuditWriter
from sift_core.agent_tools import (
    call_core_tool,
    core_tool_names,
    core_tool_specs,
)
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount

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
            and scope.get("path", "").startswith(("/portal", "/dashboard"))
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
            if path.startswith("/portal") or path.startswith("/dashboard"):
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
from sift_gateway.backends import MCPBackend, create_backend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.config import apply_case_env, apply_execute_security_env
from sift_gateway.health import health_routes
from sift_gateway.mcp_endpoint import (
    MCPAuthASGIApp,
    create_backend_mcp_server,
    create_mcp_server,
    create_session_manager,
)
from sift_gateway.rest import rest_routes

logger = logging.getLogger(__name__)


_RETIRED_CORE_BACKENDS = frozenset(
    {"forensic-mcp", "case-mcp", "sift-mcp", "report-mcp"}
)


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
        self._tool_map: dict[str, str] = {}  # tool_name -> backend_name
        self._tool_cache: dict[str, Tool] = {}  # tool_name -> Tool object
        self._start_locks: dict[str, asyncio.Lock] = {}
        self._reload_event = asyncio.Event()
        self._pending_backends: dict[str, dict] = {}
        self._audit = AuditWriter(mcp_name="sift-gateway")
        self._available_backends: set[str] = set()
        # tool_name -> manifest-declared UX metadata (category / recommended_phase /
        # health / health_args / hidden_from_agent / backend). Rebuilt on every
        # _build_tool_map so the gateway never hardcodes add-on tool names.
        self._tool_manifest_meta: dict[str, dict] = {}

        # Register declaration-driven providers: grounding reference backends
        # and the available-backend capability summary (both keyed on manifest
        # capabilities.provides — no hardcoded add-on names).
        from sift_core.case_manager import (
            set_backend_capability_provider,
            set_reference_backend_provider,
        )
        set_reference_backend_provider(self.get_reference_backends)
        set_backend_capability_provider(self.get_available_backend_capabilities)

        # Create backend instances from config
        backends_config = config.get("backends", {})
        for name, backend_conf in backends_config.items():
            if name in _RETIRED_CORE_BACKENDS or name == "sift-core":
                raise ValueError(
                    f"Core backend {name} is not allowed as a configured subprocess/add-on backend"
                )
            if not backend_conf.get("enabled", True):
                logger.info("Backend %s is disabled, skipping", name)
                continue
            try:
                backend = create_backend(name, backend_conf)
                self.backends[name] = backend
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error("Failed to create backend %s: %s", name, exc)

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
        """Start all enabled backends and build the tool map.

        When ``lazy_start`` is enabled in gateway config, backends are
        not started here. They start on first request instead.
        """
        if self.lazy_start:
            logger.info("Lazy start enabled. Backends start on first request.")
            return

        async def _start_one(name: str, backend) -> None:
            try:
                await asyncio.wait_for(backend.start(), timeout=60.0)
                logger.info("Started backend: %s", name)
            except asyncio.TimeoutError:
                logger.error("Backend %s start timed out after 60s", name)
            except (ConnectionError, OSError) as exc:
                logger.error("Failed to start backend %s (connection): %s", name, exc)
            except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
                logger.error(
                    "Failed to start backend %s: %s: %s",
                    name,
                    type(exc).__name__,
                    exc,
                )

        await asyncio.gather(
            *(_start_one(name, bk) for name, bk in self.backends.items())
        )
        await self._build_tool_map()

        # Push active case to all started HTTP backends on startup
        for _name, backend in self.backends.items():
            if backend.started:
                await self._notify_backend_case(backend)

    async def _notify_backend_case(self, backend) -> None:
        """Best-effort active-case notification for backends that support it.

        Stdio backends inherit SIFT_CASE_DIR from the gateway process, and
        backends are restarted on portal case changes. HTTP backends may grow a
        dedicated case notification API later; until then startup must not fail
        just because there is nothing to notify.
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
                for t_decl in manifest.get("tools", []):
                    t_meta_name = t_decl.get("name")
                    if not t_meta_name:
                        continue
                    manifest_meta[t_meta_name] = {
                        "backend": name,
                        "category": t_decl.get("category", ""),
                        "recommended_phase": t_decl.get("recommended_phase", ""),
                        "health": bool(t_decl.get("health", False)),
                        "health_args": t_decl.get("health_args", {}) or {},
                        "hidden_from_agent": bool(t_decl.get("hidden_from_agent", False)),
                        "when_to_use": t_decl.get("when_to_use", ""),
                        "avoid_when": t_decl.get("avoid_when", ""),
                        "output_notes": t_decl.get("output_notes", ""),
                    }

            if backend.started:
                try:
                    tools = await asyncio.wait_for(backend.list_tools(), timeout=15.0)
                    declared_names = set()
                    if manifest:
                        declared_names = {t["name"] for t in manifest.get("tools", [])}
                    for tool in tools:
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
                new_cache[mapped_name] = Tool(
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

    async def _late_start_checker(self) -> None:
        """Periodically retry failed backends and re-sync case on started ones."""
        while True:
            try:
                await anyio.sleep(30)
                for name, backend in self.backends.items():
                    if not backend.started:
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

    async def _backend_loader(self) -> None:
        """Start backends added after gateway boot (e.g. wintools after join).

        Runs inside an anyio task group so that streamablehttp_client's
        cancel scopes are properly managed.  Backends started here are
        stopped in the finally block (same task) to avoid cancel-scope
        mismatch between start() and stop().
        """
        dynamic: dict[str, MCPBackend] = {}
        try:
            while True:
                await self._reload_event.wait()
                self._reload_event.clear()
                pending = dict(self._pending_backends)
                for name, conf in pending.items():
                    loaded = False
                    for attempt in range(6):
                        if attempt > 0:
                            await anyio.sleep(10)
                        try:
                            bk = create_backend(name, conf)
                            self.backends[name] = bk
                            await bk.start()
                            await self._build_tool_map()
                            dynamic[name] = bk
                            loaded = True
                            logger.info("Loaded backend: %s", name)
                            break
                        except (
                            Exception,
                            asyncio.CancelledError,
                            BaseExceptionGroup,
                        ) as exc:
                            self.backends.pop(name, None)
                            logger.warning(
                                "Backend %s attempt %d/6: %s",
                                name,
                                attempt + 1,
                                exc,
                            )
                    self._pending_backends.pop(name, None)
                    if not loaded:
                        logger.warning(
                            "Could not load %s after retries — "
                            "restart gateway to load it",
                            name,
                        )
        finally:
            for _name, bk in dynamic.items():
                if not bk.started:
                    continue
                try:
                    await bk.stop()
                except BaseException:
                    pass

    async def list_tools(self) -> dict[str, str]:
        """Return the current tool map (tool_name -> backend_name)."""
        result = {name: "sift-core" for name in core_tool_names()}
        result.update(self._tool_map)
        return result

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
            tools.append(
                Tool(
                    name=spec.name,
                    description=spec.description,
                    inputSchema=spec.input_schema,
                    annotations={"readOnlyHint": True} if spec.read_only else None,
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
                tools.append(
                    Tool(
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
                )
        return tools

    async def call_tool(
        self, name: str, arguments: dict, examiner: str | None = None
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
        if name in core_tool_names():
            logger.info(
                "Routing tool %s -> in-process sift-core (examiner=%s)",
                name,
                examiner,
            )
            text = await asyncio.to_thread(
                call_core_tool,
                name,
                arguments,
                examiner=examiner,
                audit=self._audit,
            )
            return [TextContent(type="text", text=text)]

        if name not in self._tool_map:
            raise KeyError(f"Unknown tool: {name}")

        backend_name = self._tool_map[name]
        backend = self.backends[backend_name]

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
                except Exception:
                    pass
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

    def create_app(self) -> Starlette:
        """Build a Starlette application with all routes and middleware.

        The app manages the gateway lifecycle via lifespan events.
        Includes both REST and Streamable HTTP MCP surfaces.

        Each backend gets a dedicated MCP endpoint at ``/mcp/{name}``
        alongside the aggregate endpoint at ``/mcp``.
        """
        gateway = self
        api_keys = self.config.get("api_keys", {})
        self._api_keys = api_keys

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

        # Build aggregate MCP endpoint components
        mcp_server = create_mcp_server(gateway)
        session_manager = create_session_manager(mcp_server)
        mcp_asgi_app = MCPAuthASGIApp(
            session_manager,
            api_keys=api_keys,
            allowed_origins=allowed_origins,
            examiner_calls_per_minute=examiner_calls_per_minute,
        )

        # Build per-backend MCP endpoints
        backend_session_managers = []
        per_backend_routes = []
        for name in self.backends:
            b_server = create_backend_mcp_server(gateway, name)
            b_sm = create_session_manager(b_server)
            b_asgi = MCPAuthASGIApp(
                b_sm,
                api_keys=api_keys,
                allowed_origins=allowed_origins,
                examiner_calls_per_minute=examiner_calls_per_minute,
            )
            backend_session_managers.append(b_sm)
            per_backend_routes.append(Mount(f"/mcp/{name}", app=b_asgi))

        @contextlib.asynccontextmanager
        async def lifespan(app):
            """Start backends → all MCP session managers → yield → stop."""
            import os as _os
            await gateway.start()
            reaper_task = None
            if gateway.idle_timeout > 0:
                reaper_task = asyncio.create_task(gateway._idle_reaper())
            late_start_task = asyncio.create_task(gateway._late_start_checker())

            # Phase 17d: inotify watcher for real-time evidence cache invalidation
            watcher_task = None
            _case_dir_str = _os.environ.get("SIFT_CASE_DIR", "")
            if _case_dir_str:
                try:
                    from sift_gateway.evidence_gate import invalidate_evidence_cache
                    from sift_gateway.evidence_watcher import watch_evidence_dir
                    watcher_task = asyncio.create_task(
                        watch_evidence_dir(_case_dir_str, invalidate_evidence_cache)
                    )
                except ImportError:
                    pass

            async with contextlib.AsyncExitStack() as stack:
                await stack.enter_async_context(session_manager.run())
                for b_sm in backend_session_managers:
                    try:
                        await stack.enter_async_context(b_sm.run())
                    except (
                        Exception,
                        asyncio.CancelledError,
                        BaseExceptionGroup,
                    ) as exc:
                        logger.error(
                            "Per-backend session manager failed to start: %s", exc
                        )
                # Backend loader runs in anyio task group so that
                # streamablehttp_client cancel scopes are properly managed.
                async with anyio.create_task_group() as loader_tg:
                    loader_tg.start_soon(gateway._backend_loader)
                    yield
                    loader_tg.cancel_scope.cancel()
            if reaper_task is not None:
                reaper_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reaper_task
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

        # Examiner Portal + legacy dashboard (optional — installed separately)
        try:
            from case_dashboard.routes import (
                create_dashboard_app,
                create_dashboard_v2_app,
            )

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

            async def _on_case_activated(case_dir_str: str) -> None:
                gateway.config.setdefault("case", {})["dir"] = case_dir_str
                apply_case_env(gateway.config)
                await gateway.restart_backends()

            dashboard_app = create_dashboard_v2_app(
                session_secret=portal_secret,
                session_max_age=portal_max_age,
                api_keys=api_keys,
                gateway_config_path=_gw_config_path,
                on_chain_mutation=invalidate_evidence_cache,
                on_case_activated=_on_case_activated,
                on_override_get_status=get_override_status,
                on_override_enable=enable_override,
                on_override_cancel=cancel_override,
            )
            dashboard_app.state.gateway = self
            routes.append(Mount("/portal", app=dashboard_app))
            routes.append(Mount("/dashboard", app=create_dashboard_app()))
        except ImportError:
            pass

        # Per-backend routes BEFORE aggregate (Starlette matches first)
        routes.extend(per_backend_routes)
        routes.append(Mount("/mcp", app=mcp_asgi_app))

        app = Starlette(
            routes=routes,
            lifespan=lifespan,
        )

        # Attach gateway to app state so endpoints can access it
        app.state.gateway = gateway

        async def _sanitized_error(request, exc):
            """Global unhandled exception handler — never leak file paths or tracebacks."""
            logger.exception("Unhandled error: %s", exc)
            from starlette.responses import JSONResponse as _JSONResponse
            return _JSONResponse({"error": "Internal server error"}, status_code=500)

        app.add_exception_handler(Exception, _sanitized_error)

        # Add auth middleware (skips /mcp — handled by MCPAuthASGIApp)
        app.add_middleware(AuthMiddleware, api_keys=api_keys)

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

        # Normalize per-backend MCP paths (must be outermost = added last)
        backend_paths = frozenset(f"/mcp/{name}" for name in self.backends)
        app.add_middleware(_NormalizeMCPPath, backend_paths=backend_paths)

        # HTTPS enforcement for portal paths (outermost — added after _NormalizeMCPPath)
        app.add_middleware(_PortalHTTPSGuard, tls_configured=tls_configured)

        # Secure headers middleware (outermost — added after _PortalHTTPSGuard)
        app.add_middleware(SecureHeadersMiddleware)

        return app
