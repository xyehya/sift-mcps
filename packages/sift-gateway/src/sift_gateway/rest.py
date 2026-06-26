"""REST API routes for /api/v1/."""

import asyncio
import copy
import json
import logging
import os
import socket
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlparse

import jsonschema
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from sift_gateway.auth import (
    is_agent_principal,
    require_control_plane_operator,
    require_recent_reauth,
    resolve_examiner,
)
from sift_gateway.join import (
    check_join_rate_limit,
    generate_join_code,
    record_join_failure,
    store_join_code,
    validate_and_consume_join_code,
)
from sift_gateway.rate_limit import check_rate_limit
from sift_gateway.token_gen import generate_gateway_token
from sift_gateway.backends import (
    SCHEMA_PATH,
    load_and_validate_manifest,
    validate_manifest_contract,
)
from sift_gateway.health import _operator_backend_health

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
_MAX_REQUEST_BYTES = 10 * 1024 * 1024


async def _read_json_body(request: Request) -> tuple[dict | None, JSONResponse | None]:
    raw_body = await request.body()
    if len(raw_body) > _MAX_REQUEST_BYTES:
        return None, JSONResponse(
            {"error": f"Request body too large (max {_MAX_REQUEST_BYTES} bytes)"},
            status_code=413,
        )
    try:
        body = json.loads(raw_body or b"{}")
    except json.JSONDecodeError:
        return None, JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return None, JSONResponse({"error": "JSON body must be an object"}, status_code=400)
    return body, None


def _gateway_config_path() -> Path:
    configured = os.environ.get("SIFT_GATEWAY_CONFIG")
    return Path(configured) if configured else Path.home() / ".sift" / "gateway.yaml"


def _normalize_backend_payload(body: dict) -> tuple[str, dict, dict | None, list[dict]]:
    reasons: list[dict] = []
    name = body.get("name") or body.get("backend")
    if not isinstance(name, str) or not name.strip():
        reasons.append({"field": "name", "reason": "Backend name is required."})
        name = ""
    else:
        name = name.strip()
        import re
        if not re.match(r"^[a-z0-9][a-z0-9-]*$", name):
            reasons.append(
                {
                    "field": "name",
                    "reason": "Backend name must contain only lowercase letters, digits, and hyphens, and start with an alphanumeric character.",
                }
            )

    config = body.get("config")
    if config is None:
        config = {
            key: body[key]
            for key in (
                "type",
                "command",
                "args",
                "env",
                "url",
                "bearer_token",
                "bearer_token_env",
                "tls_cert",
                "tls_cert_env",
                "manifest_path",
                "enabled",
                "env_refs",
            )
            if key in body
        }
    if not isinstance(config, dict):
        reasons.append({"field": "config", "reason": "Backend config must be an object."})
        config = {}
    config = dict(config)
    config.setdefault("type", "stdio")

    inline_manifest = body.get("manifest")
    if inline_manifest is not None and not isinstance(inline_manifest, dict):
        reasons.append({"field": "manifest", "reason": "Manifest must be an object."})
        inline_manifest = None

    return name, config, inline_manifest, reasons


def _manifest_reasons(manifest: dict, manifest_path: Path | None = None) -> list[dict]:
    reasons: list[dict] = []
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        return [{"field": "schema", "reason": f"Backend schema is unreadable: {exc}"}]

    spec_version = manifest.get("spec_version")
    if not isinstance(spec_version, str) or not spec_version.startswith("1."):
        reasons.append(
            {
                "field": "spec_version",
                "reason": f"Unsupported spec_version: {spec_version!r}. Gateway only supports version 1.x.",
            }
        )

    validator = jsonschema.Draft7Validator(schema)
    for error in sorted(validator.iter_errors(manifest), key=lambda e: list(e.path)):
        path = ".".join(str(part) for part in error.path) or "manifest"
        reasons.append({"field": path, "reason": error.message})

    try:
        validate_manifest_contract(copy.deepcopy(manifest), manifest_path)
    except ValueError as exc:
        reasons.append({"field": "manifest", "reason": str(exc)})

    return reasons


def _load_manifest_for_rest(
    name: str, config: dict, inline_manifest: dict | None
) -> tuple[dict | None, list[dict]]:
    if inline_manifest is not None:
        reasons = _manifest_reasons(inline_manifest)
        return (copy.deepcopy(inline_manifest) if not reasons else None), reasons
    explicit_path = config.get("manifest_path")
    if isinstance(explicit_path, str) and not explicit_path.startswith(("http://", "https://")):
        manifest_path = Path(explicit_path)
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                return None, [{"field": "manifest", "reason": str(exc)}]
            if not isinstance(manifest, dict):
                return None, [{"field": "manifest", "reason": "Manifest must be an object."}]
            reasons = _manifest_reasons(manifest, manifest_path)
            return (manifest if not reasons else None), reasons
    try:
        manifest = load_and_validate_manifest(name, config)
        return manifest, []
    except ValueError as exc:
        return None, [{"field": "manifest", "reason": str(exc)}]


def _requirement_status(gateway, manifest: dict | None) -> tuple[list[str], list[str]]:
    if not manifest:
        return [], []
    requires = list(manifest.get("capabilities", {}).get("requires", []))
    unmet = [req for req in requires if not gateway.evaluate_requirement(req)]
    return requires, unmet


async def list_tools(request: Request) -> JSONResponse:
    """GET /api/v1/tools — list all aggregated tools.

    Query params:
        backend: filter tools by backend name
    """
    gateway = request.app.state.gateway
    backend_filter = request.query_params.get("backend")

    # Reuse gateway.get_tools_list() for descriptions and schemas
    all_tools = await gateway.get_tools_list()

    tools = []
    for t in sorted(all_tools, key=lambda x: x.name):
        backend_name = gateway._tool_map.get(t.name, "")
        if backend_filter and backend_name != backend_filter:
            continue
        tools.append(
            {
                "name": t.name,
                "backend": backend_name,
                "description": t.description or "",
                "input_schema": t.inputSchema,
            }
        )

    return JSONResponse({"tools": tools, "count": len(tools)})


async def call_tool(request: Request) -> JSONResponse:
    """POST /api/v1/tools/{tool_name} — call a tool.

    Body:
        {"arguments": {...}}
    """
    # Rate limit check (before any body processing)
    # Trust X-Forwarded-For only from localhost (proxy on same machine)
    client_ip = request.client.host if request.client else "unknown"
    if client_ip in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
    if not check_rate_limit(client_ip):
        return JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429,
        )

    gateway = request.app.state.gateway
    tool_name = request.path_params["tool_name"]
    identity = resolve_examiner(request)

    # BATCH-B1 (F-MVP-3): REST tool execution is operator-only for the MVP.
    # Agents must use the Gateway MCP surface (/mcp), which is the only path that
    # enforces the SIFT policy middleware (tool authz + evidence gate + response
    # guard + rate limit). Reject agent/service tokens here so they cannot use
    # REST to bypass that MCP policy boundary.
    if is_agent_principal(request):
        logger.warning(
            "Agent/service token blocked from REST tool execution: tool=%s principal=%s",
            tool_name,
            identity.get("examiner"),
        )
        return JSONResponse(
            {
                "error": "REST tool execution is operator-only; agents must use the Gateway MCP surface",
                "tool": tool_name,
            },
            status_code=403,
        )

    # Read the raw body and enforce actual size limit.
    # Checking Content-Length alone is insufficient because the header
    # can be absent or spoofed; reading the body is authoritative.
    raw_body = await request.body()
    if len(raw_body) > _MAX_REQUEST_BYTES:
        return JSONResponse(
            {"error": f"Request body too large (max {_MAX_REQUEST_BYTES} bytes)"},
            status_code=413,
        )

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    arguments = body.get("arguments", {})
    if not isinstance(arguments, dict):
        return JSONResponse({"error": "arguments must be an object"}, status_code=400)

    from sift_core.agent_tools import core_tool_names

    if tool_name not in gateway._tool_map and tool_name not in core_tool_names():
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )

    try:
        try:
            result = await gateway.call_tool(
                tool_name,
                arguments,
                examiner=identity.get("examiner"),
                identity=getattr(request.state, "identity", None),
            )
        except TypeError as exc:
            if "identity" not in str(exc):
                raise
            result = await gateway.call_tool(
                tool_name,
                arguments,
                examiner=identity.get("examiner"),
            )
        # Serialize content items
        serialized = []
        for item in result:
            if hasattr(item, "model_dump"):
                serialized.append(item.model_dump())
            elif hasattr(item, "__dict__"):
                serialized.append(item.__dict__)
            else:
                serialized.append(str(item))

        return JSONResponse(
            {
                "tool": tool_name,
                "backend": gateway._tool_map.get(tool_name, "sift-core"),
                "result": serialized,
            }
        )
    except KeyError as exc:
        logger.error("Tool call failed — tool not in map: %s — %s", tool_name, exc)
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
        try:
            from sift_gateway.active_case import ActiveCaseError
        except Exception:  # pragma: no cover - defensive import fallback
            ActiveCaseError = ()  # type: ignore[assignment]
        if isinstance(exc, ActiveCaseError):
            return JSONResponse(
                {"error": exc.reason, "tool": tool_name},
                status_code=exc.http_status,
            )
        message = str(exc)
        if message in {
            "proxied case-scoped tool does not expose a safe case_id/case_key argument",
            "client-supplied case_id does not match DB active case",
            "client-supplied case_key does not match DB active case",
            "Active case has no artifact path for case-scoped tool",
        }:
            return JSONResponse(
                {"error": message, "tool": tool_name},
                status_code=403,
            )
        logger.error(
            "Tool call failed: %s — %s: %s",
            tool_name,
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return JSONResponse(
            {
                "error": "Tool call failed",
                "tool": tool_name,
                "error_type": type(exc).__name__,
            },
            status_code=500,
        )


async def list_backends(request: Request) -> JSONResponse:
    """GET /api/v1/backends — list all backends with status."""
    gateway = request.app.state.gateway
    registry = getattr(gateway, "mcp_backend_registry", None)
    if registry is None:
        return JSONResponse(
            {
                "backends": [],
                "count": 0,
                "authority": "app.mcp_backends",
                "control_plane": "unavailable",
            }
        )

    try:
        records = registry.list_backends()
    except Exception as exc:
        logger.warning("Failed to list app.mcp_backends: %s", exc)
        return JSONResponse({"error": "mcp backend registry unavailable"}, status_code=503)

    backends = []
    proxy_mounted_set = getattr(gateway, "_mounted_proxy_backends", None) or set()
    for record in records:
        name = record.name
        enabled = record.enabled
        backend = gateway.backends.get(name)
        started = backend.started if backend else False
        proxy_mounted = name in proxy_mounted_set
        manifest = getattr(backend, "manifest", None) if backend else record.manifest
        requires, unmet_requires = _requirement_status(gateway, manifest)

        health = {"status": "disabled"}
        if enabled:
            if unmet_requires:
                health = {"status": "gated", "detail": f"Unmet requirements: {', '.join(unmet_requires)}"}
            elif not started:
                # A proxy-mounted add-on (OSX1) runs no persistent subprocess: it
                # lazy-starts per call. Mirror /health's operator translation so it
                # reads "ok — starts on demand" instead of a misleading "stopped".
                # A non-mounted, not-started backend stays "stopped" unchanged.
                health = _operator_backend_health(gateway, name, {"status": "stopped"})
                if proxy_mounted:
                    try:
                        registry.update_health(name, health.get("status", "unknown"), health.get("detail"))
                    except Exception as e:
                        logger.warning("Failed to persist health status for backend %s: %s", name, e)
            else:
                try:
                    health = await backend.health_check()
                except (RuntimeError, ConnectionError, OSError) as e:
                    logger.warning("Health check failed for backend %s: %s", name, e)
                    health = {"status": "error", "detail": str(e)}
                except Exception as e:
                    logger.warning("Health check unexpected error for backend %s: %s", name, e)
                    health = {"status": "error"}
                try:
                    registry.update_health(name, health.get("status", "unknown"), health.get("detail"))
                except Exception as e:
                    logger.warning("Failed to persist health status for backend %s: %s", name, e)

        item = record.public_dict(
            started=started,
            available=enabled and not unmet_requires,
            pending_apply=_backend_pending_apply(gateway, record),
        )
        item.update(
            {
                "health": health,
                "requires": requires,
                "unmet_requires": unmet_requires,
                "on_demand": proxy_mounted,
            }
        )
        backends.append(item)

    return JSONResponse(
        {"backends": backends, "count": len(backends), "authority": "app.mcp_backends"}
    )


def _backend_pending_apply(gateway, record) -> bool:
    loaded_at = getattr(gateway, "_mcp_catalog_loaded_at", None)
    if loaded_at is None:
        return bool(record.enabled)
    updated_at = getattr(record, "updated_at", None)
    if updated_at is None:
        return False
    return updated_at > loaded_at


def _registry_record_by_name(gateway, name: str):
    registry = getattr(gateway, "mcp_backend_registry", None)
    if registry is None:
        return None
    try:
        for record in registry.list_backends():
            if record.name == name:
                return record
    except Exception as exc:
        logger.warning("Failed to query app.mcp_backends for %s: %s", name, exc)
    return None


# ---------------------------------------------------------------------------
# Service management endpoints
# ---------------------------------------------------------------------------


async def list_services(request: Request) -> JSONResponse:
    """GET /api/v1/services — list all backends with health and started status."""
    gateway = request.app.state.gateway

    services = []
    for name, backend in gateway.backends.items():
        try:
            health = await backend.health_check()
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
            logger.warning("Health check failed for service %s: %s", name, e)
            health = {"status": "error"}

        services.append(
            {
                "name": name,
                "type": backend.config.get("type", "stdio"),
                "started": backend.started,
                "health": health,
            }
        )

    return JSONResponse({"services": services, "count": len(services)})


async def start_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/start — start a backend and rebuild tool map."""
    authz = require_control_plane_operator(request)  # SEC-1: operator-only
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    record = _registry_record_by_name(gateway, name)
    if record is None:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    if not record.enabled:
        return JSONResponse({"error": f"Cannot control service for disabled backend: {name}"}, status_code=400)

    # Resolve manifest and check requirements
    backend = gateway.backends.get(name)
    if backend is None:
        return JSONResponse(
            {"error": f"Backend {name} is registered but pending Gateway restart", "restart_required": True},
            status_code=409,
        )
    manifest = getattr(backend, "manifest", None) or record.manifest

    requires, unmet_requires = _requirement_status(gateway, manifest)
    if unmet_requires:
        return JSONResponse({"error": f"Cannot start backend with unmet requirements: {', '.join(unmet_requires)}"}, status_code=400)

    if backend.started:
        return JSONResponse({"status": "already_running", "name": name})

    try:
        await asyncio.wait_for(backend.start(), timeout=30.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except Exception as e:
        logger.error("Failed to start service %s: %s", name, e)
        return JSONResponse(
            {"error": f"Failed to start service {name}"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "started", "name": name})


async def stop_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/stop — stop a backend and rebuild tool map."""
    authz = require_control_plane_operator(request)  # SEC-1: operator-only
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if _registry_record_by_name(gateway, name) is None:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends.get(name)
    if not backend or not backend.started:
        return JSONResponse({"status": "already_stopped", "name": name})

    try:
        await asyncio.wait_for(backend.stop(), timeout=10.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Stop timed out for {name}"}, status_code=504)
    except Exception as e:
        logger.error("Failed to stop service %s: %s", name, e)
        return JSONResponse(
            {"error": f"Failed to stop service {name}"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "stopped", "name": name})


async def restart_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/restart — stop + start a backend."""
    authz = require_control_plane_operator(request)  # SEC-1: operator-only
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    record = _registry_record_by_name(gateway, name)
    if record is None:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    if not record.enabled:
        return JSONResponse({"error": f"Cannot control service for disabled backend: {name}"}, status_code=400)

    # Resolve manifest and check requirements for start
    backend = gateway.backends.get(name)
    if backend is None:
        return JSONResponse(
            {"error": f"Backend {name} is registered but pending Gateway restart", "restart_required": True},
            status_code=409,
        )
    manifest = getattr(backend, "manifest", None) or record.manifest

    requires, unmet_requires = _requirement_status(gateway, manifest)
    if unmet_requires:
        return JSONResponse({"error": f"Cannot start backend with unmet requirements: {', '.join(unmet_requires)}"}, status_code=400)

    # Stop if running
    if backend.started:
        try:
            await asyncio.wait_for(backend.stop(), timeout=10.0)
        except Exception as e:
            logger.error("Failed to stop service %s during restart: %s", name, e)
            return JSONResponse(
                {"error": f"Failed to stop service {name} during restart"},
                status_code=500,
            )

    # Start
    try:
        await asyncio.wait_for(backend.start(), timeout=30.0)
    except asyncio.TimeoutError:
        await gateway._build_tool_map()
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except Exception as e:
        logger.error("Failed to start service %s during restart: %s", name, e)
        await gateway._build_tool_map()
        return JSONResponse(
            {"error": f"Failed to start service {name} during restart"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "restarted", "name": name})


# ---------------------------------------------------------------------------
# Join code endpoints
# ---------------------------------------------------------------------------


async def create_join_code(request: Request) -> JSONResponse:
    """POST /api/v1/setup/join-code — generate a one-time join code.

    Requires bearer token auth (authenticated examiner).
    """
    # SEC-1: control-plane mutation (mints a credential that bootstraps a fresh
    # gateway token / new backend) — operator-only + step-up re-auth.
    authz = require_control_plane_operator(request)
    if authz is not None:
        return authz

    expires_hours = 2
    data: dict = {}
    body = await request.body()
    if body:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        if not isinstance(data, dict):
            return JSONResponse({"error": "JSON body must be an object"}, status_code=400)
        expires_hours = data.get("expires_hours", 2)

    reauth = await require_recent_reauth(request, data)  # SEC-1: step-up on mint
    if reauth is not None:
        return reauth

    if (
        not isinstance(expires_hours, (int, float))
        or expires_hours < 1
        or expires_hours > 48
    ):
        return JSONResponse(
            {"error": "expires_hours must be between 1 and 48"},
            status_code=400,
        )

    code = generate_join_code()
    store_join_code(code, expires_hours=expires_hours)

    gateway = request.app.state.gateway
    gw_url = _get_gateway_url(gateway)
    parsed = urlparse(gw_url)
    host_port = f"{parsed.hostname}:{parsed.port}"

    return JSONResponse(
        {
            "code": code,
            "expires_hours": expires_hours,
            "instructions": f"sift join --sift {host_port} --code {code}",
        }
    )


async def join_gateway(request: Request) -> JSONResponse:
    """POST /api/v1/setup/join — exchange join code for gateway credentials.

    Unauthenticated — the join code is the auth mechanism.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not check_join_rate_limit(client_ip):
        return JSONResponse(
            {"error": "Too many failed attempts. Try again later."},
            status_code=429,
        )

    try:
        body = json.loads(await request.body())
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    code = body.get("code", "")
    machine_type = body.get("machine_type", "examiner")
    hostname = body.get("hostname", "")
    wintools_url = body.get("wintools_url")
    wintools_token = body.get("wintools_token")
    wintools_cert = body.get("wintools_cert")

    matched_hash = await validate_and_consume_join_code(code)
    if not matched_hash:
        record_join_failure(client_ip)
        return JSONResponse(
            {"error": "Invalid or expired join code"},
            status_code=403,
        )

    examiner_name = hostname or machine_type
    gateway = request.app.state.gateway

    # Generate a bearer token only for non-wintools joins
    if machine_type != "wintools":
        new_token = generate_gateway_token()
        _add_api_key_to_config(gateway, new_token, examiner_name)
    else:
        new_token = None

    # If wintools: register DB metadata only. D22A forbids persisting the
    # received bearer token in gateway.yaml or Postgres; keep it as a process
    # env value for this runtime and require a Gateway restart with the same env
    # reference configured to expose the backend on /mcp.
    wintools_registered = False
    wintools_restart_required = False
    if machine_type == "wintools" and wintools_url and wintools_token:
        parsed = urlparse(wintools_url)
        if parsed.scheme not in ("http", "https"):
            return JSONResponse(
                {"error": "wintools_url must use http or https scheme"},
                status_code=400,
            )
        if not parsed.hostname:
            return JSONResponse(
                {"error": "wintools_url must include a hostname"},
                status_code=400,
            )
        # Store pinned TLS cert if provided
        cert_path_str = None
        if wintools_cert:
            logger.debug("wintools_cert first 50 chars: %r", wintools_cert[:50])
            # Accept string or dict with "cert" key (PowerShell may serialize either)
            if isinstance(wintools_cert, dict):
                wintools_cert = wintools_cert.get("cert", "")
            if not isinstance(wintools_cert, str):
                wintools_cert = ""
            # Strip UTF-8 BOM that PowerShell 5.1 Get-Content -Raw may prepend
            wintools_cert = wintools_cert.lstrip("\ufeff")
            from pathlib import Path

            cert_path = Path.home() / ".sift" / "tls" / "wintools-cert.pem"
            cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if wintools_cert.strip().startswith("-----BEGIN CERTIFICATE-----"):
                cert_path.write_text(wintools_cert)
                os.chmod(str(cert_path), 0o600)
                cert_path_str = str(cert_path)
                logger.info("Stored wintools TLS cert at %s", cert_path)
            else:
                logger.warning("Invalid wintools_cert in join body (not PEM)")

        token_env = "SIFT_BACKEND_WINTOOLS_MCP_TOKEN"
        os.environ[token_env] = str(wintools_token)
        backend_config = {
            "type": "http",
            "url": wintools_url,
            "bearer_token_env": token_env,
            "enabled": True,
        }
        if cert_path_str:
            cert_env = "SIFT_BACKEND_WINTOOLS_MCP_TLS_CERT"
            os.environ[cert_env] = cert_path_str
            backend_config["tls_cert_env"] = cert_env
        register_response, register_status = await register_backend_logic(
            gateway,
            {"name": "wintools-mcp", "config": backend_config},
            actor=None,
        )
        if register_status < 400:
            wintools_registered = True
            wintools_restart_required = True
        else:
            logger.warning(
                "wintools backend registry registration failed: %s",
                register_response.get("error") or register_response.get("reasons"),
            )

    # Build response (after hot-load so backends list is current)
    backends = list(gateway.backends.keys())
    gw_url = _get_gateway_url(gateway)

    response = {
        "gateway_url": gw_url,
        "backends": backends,
        "examiner": examiner_name,
        "sift_examiner": os.environ.get("SIFT_EXAMINER", ""),
    }
    if new_token:
        response["gateway_token"] = new_token

    if wintools_registered:
        response["wintools_registered"] = True
        response["restart_required"] = wintools_restart_required
        response["credential_refs"] = {
            "bearer_token_env": "SIFT_BACKEND_WINTOOLS_MCP_TOKEN"
        }
        if "SIFT_BACKEND_WINTOOLS_MCP_TLS_CERT" in os.environ:
            response["credential_refs"]["tls_cert_env"] = (
                "SIFT_BACKEND_WINTOOLS_MCP_TLS_CERT"
            )
        samba_config = _load_samba_config()
        if samba_config:
            smb_host = _get_sift_ip()
            share_name = samba_config.get("share_name", "")
            smb_user = samba_config.get("smb_user", "")
            if smb_host and share_name and smb_user:
                response["smb_share"] = share_name
                response["smb_user"] = smb_user
                response["smb_host"] = smb_host

    return JSONResponse(response)


async def join_status(request: Request) -> JSONResponse:
    """GET /api/v1/setup/join-status — check pending join codes (authenticated)."""
    import time

    from sift_gateway.join import _load_state

    state = _load_state()
    now = time.time()
    active = 0
    for info in state.get("codes", {}).values():
        if not info.get("used", False) and now <= info.get("expires_ts", 0):
            active += 1

    return JSONResponse({"active_codes": active})


_CONFIG_LOCK = threading.Lock()


def _atomic_yaml_write(config_path, config: dict) -> None:
    """Write YAML config atomically via temp file + fsync + os.replace."""
    import yaml

    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_path = tempfile.mkstemp(dir=str(config_path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(config_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _add_api_key_to_config(gateway, token: str, examiner: str) -> None:
    """Add a new API key to the gateway config and write to disk."""
    from pathlib import Path

    with _CONFIG_LOCK:
        config_path = Path.home() / ".sift" / "gateway.yaml"
        if config_path.exists():
            import yaml

            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            except (yaml.YAMLError, OSError) as e:
                logger.warning("Failed to read gateway config %s: %s", config_path, e)
                config = {}
        else:
            config = {}

        if "api_keys" not in config:
            config["api_keys"] = {}

        config["api_keys"][token] = {
            "examiner": examiner,
            "role": "examiner",
        }

        try:
            _atomic_yaml_write(config_path, config)
        except OSError as e:
            logger.error("Failed to write gateway config: %s", e)
            raise HTTPException(
                status_code=500, detail="Failed to save configuration"
            ) from e

    # Also update the in-memory gateway auth keys (shared dict reference)
    if hasattr(gateway, "_api_keys"):
        gateway._api_keys[token] = {"examiner": examiner, "role": "examiner"}


def _get_gateway_url(gateway) -> str:
    """Build the gateway URL from config."""
    gw_config = gateway.config.get("gateway", {})
    host = gw_config.get("host", "127.0.0.1")
    port = gw_config.get("port", 4508)
    tls = gw_config.get("tls", {})

    if host == "0.0.0.0":
        # UDP connect trick: queries routing table without sending packets
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                host = s.getsockname()[0]
        except OSError:
            host = "127.0.0.1"

    scheme = "https" if tls.get("certfile") else "http"
    return f"{scheme}://{host}:{port}"


def _load_samba_config() -> dict | None:
    """Read ~/.sift/samba.yaml if it exists."""
    from pathlib import Path

    import yaml

    path = Path.home() / ".sift" / "samba.yaml"
    if not path.is_file():
        return None
    try:
        return yaml.safe_load(path.read_text())
    except (yaml.YAMLError, OSError) as e:
        logger.warning("Failed to read samba config %s: %s", path, e)
        return None


def _get_sift_ip() -> str | None:
    """Read static IP from ~/.sift/network.yaml, fall back to primary interface IP."""
    from pathlib import Path

    import yaml

    path = Path.home() / ".sift" / "network.yaml"
    if path.is_file():
        try:
            doc = yaml.safe_load(path.read_text())
            ip = doc.get("static_ip")
            if ip:
                return ip
        except (yaml.YAMLError, OSError) as e:
            logger.warning("Failed to read network config %s: %s", path, e)
    # Fall back to primary interface IP (same as hostname -I)
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


async def reload_backends(request: Request) -> JSONResponse:
    """POST /api/v1/backends/reload — refresh DB registry status.

    D34 is restart-to-apply for FastMCP catalog exposure. This endpoint does not
    live-remount providers; it reports which DB rows are pending Gateway restart.
    """
    authz = require_control_plane_operator(request)  # SEC-1: operator-only
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    registry = getattr(gateway, "mcp_backend_registry", None)
    if registry is None:
        return JSONResponse(
            {"status": "registry_unavailable", "pending": [], "restart_required": False},
            status_code=503,
        )
    try:
        records = registry.list_backends()
    except Exception as exc:
        logger.warning("Failed to reload app.mcp_backends metadata: %s", exc)
        return JSONResponse({"error": "mcp backend registry unavailable"}, status_code=503)

    pending = [record.name for record in records if _backend_pending_apply(gateway, record)]
    return JSONResponse(
        {
            "status": "restart_required" if pending else "current",
            "pending": pending,
            "restart_required": bool(pending),
            "authority": "app.mcp_backends",
        }
    )


def _sanitize_reasons(reasons: list[dict]) -> list[dict]:
    sanitized = []
    for r in reasons:
        field = r.get("field", "")
        reason = r.get("reason", "")
        if any(k in field for k in ("bearer_token", "tls_cert", "env")):
            reason = f"Invalid value for {field}."
        elif "bearer_token" in reason or "tls_cert" in reason or "env" in reason:
            reason = "Secret value validation failed."
        sanitized.append({"field": field, "reason": reason})
    return sanitized


def validate_backend_logic(gateway, body: dict) -> tuple[dict, int]:
    name, config, inline_manifest, reasons = _normalize_backend_payload(body)
    if not reasons and (inline_manifest is None or set(config) - {"type"}):
        try:
            from sift_gateway.mcp_backends_registry import normalize_connection_config

            normalize_connection_config(config)
        except Exception as exc:
            reasons.append({"field": "config", "reason": str(exc)})
    manifest = None
    if not reasons:
        manifest, reasons = _load_manifest_for_rest(name, config, inline_manifest)

    reasons = _sanitize_reasons(reasons)
    requires, unmet = _requirement_status(gateway, manifest)
    status_code = 200 if not reasons else 422
    response = {
        "valid": not reasons,
        "name": name,
        "transport": (manifest or {}).get("transport", config.get("type", "stdio")),
        "namespace": (manifest or {}).get("namespace", ""),
        "provides": (manifest or {}).get("capabilities", {}).get("provides", []),
        "requires": requires,
        "unmet_requires": unmet,
        "tools": [
            {
                "name": tool.get("name", ""),
                "category": tool.get("category", ""),
                "recommended_phase": tool.get("recommended_phase", ""),
                "health": bool(tool.get("health")),
                "hidden_from_agent": bool(tool.get("hidden_from_agent", False)),
            }
            for tool in (manifest or {}).get("tools", [])
        ],
        "reasons": reasons,
    }
    if manifest:
        response["instructions"] = (
            manifest.get("_resolved_instructions") or manifest.get("instructions") or ""
        )
        response["available"] = not unmet and config.get("enabled", True)
    return response, status_code


async def register_backend_logic(gateway, body: dict, *, actor=None) -> tuple[dict, int]:
    name, config, inline_manifest, reasons = _normalize_backend_payload(body)
    registry = getattr(gateway, "mcp_backend_registry", None)
    if inline_manifest is not None and "manifest_path" not in config:
        reasons.append(
            {
                "field": "manifest_path",
                "reason": "Registration requires a manifest_path or URL; inline manifests are validate-only.",
            }
        )
    if not reasons:
        try:
            from sift_gateway.mcp_backends_registry import (
                assert_stdio_command_allowlisted,
                normalize_connection_config,
            )

            normalize_connection_config(config)
            # SEC-4: a registered stdio backend launches as the gateway account,
            # so constrain its command to the installed add-on catalog (reject
            # arbitrary interpreters/binaries) at the registration surface.
            if str(config.get("type") or "stdio") == "stdio":
                assert_stdio_command_allowlisted(config.get("command"))
        except Exception as exc:
            reasons.append({"field": "config", "reason": str(exc)})

    manifest = None
    if not reasons:
        manifest, reasons = _load_manifest_for_rest(name, config, None)

    reasons = _sanitize_reasons(reasons)
    if reasons:
        return {"registered": False, "name": name, "reasons": reasons}, 422

    assert manifest is not None
    if registry is None:
        return {
            "registered": False,
            "name": name,
            "error": "mcp backend registry unavailable",
            "restart_required": False,
        }, 503
    enabled = bool(config.get("enabled", True))
    requires, unmet = _requirement_status(gateway, manifest)
    try:
        record = registry.register(name=name, config=config, manifest=manifest, actor=actor)
    except Exception as exc:
        http_status = getattr(exc, "http_status", None)
        msg = str(exc)
        if any(k in msg for k in ("bearer_token", "tls_cert", "env")):
            msg = "Backend credential reference validation failed."
        if http_status is None or int(http_status) >= 500:
            logger.warning("mcp backend registry write failed for %s: %s", name, msg)
            return {
                "registered": False,
                "name": name,
                "error": "mcp backend registry write failed",
            }, 503
        return {
            "registered": False,
            "name": name,
            "reasons": [{"field": "config", "reason": msg}],
        }, int(http_status)

    return {
        "registered": True,
        "id": record.id,
        "name": record.name,
        "enabled": enabled,
        "available": enabled and not unmet,
        "requires": requires,
        "unmet_requires": unmet,
        "reload_scheduled": False,
        "pending_apply": True,
        "restart_required": True,
    }, 201


async def validate_backend(request: Request) -> JSONResponse:
    """POST /api/v1/backends/validate — validate a backend manifest/config."""
    # SEC-1: validation triggers a remote manifest fetch (egress) and is a
    # control-plane operation — operator-only, not agent/service/readonly.
    authz = require_control_plane_operator(request)
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    body, error = await _read_json_body(request)
    if error:
        return error
    assert body is not None
    response, status_code = validate_backend_logic(gateway, body)
    return JSONResponse(response, status_code=status_code)


async def register_backend(request: Request) -> JSONResponse:
    """POST /api/v1/backends — validate, persist, and hot-register a backend."""
    # SEC-1: registering a backend persists a row the gateway later launches
    # (stdio process / HTTP egress) — operator-only + step-up re-auth.
    authz = require_control_plane_operator(request)
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    body, error = await _read_json_body(request)
    if error:
        return error
    assert body is not None
    reauth = await require_recent_reauth(request, body)  # SEC-1: step-up
    if reauth is not None:
        return reauth
    actor = getattr(request.state, "identity", None)
    response, status_code = await register_backend_logic(gateway, body, actor=actor)
    return JSONResponse(response, status_code=status_code)


async def unregister_backend(request: Request) -> JSONResponse:
    """DELETE /api/v1/backends/{name} — remove a backend registry row.

    D34 keeps FastMCP add-on mounts fixed for the current process lifetime, so
    unregister is a DB/catalog change that requires Gateway restart to apply to
    the served `/mcp` catalog.
    """
    authz = require_control_plane_operator(request)  # SEC-1: operator-only
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    registry = getattr(gateway, "mcp_backend_registry", None)
    if registry is None:
        return JSONResponse(
            {
                "unregistered": False,
                "name": request.path_params["name"],
                "error": "mcp backend registry unavailable",
                "restart_required": False,
            },
            status_code=503,
        )

    name = request.path_params["name"]
    actor = getattr(request.state, "identity", None)
    try:
        registry.unregister(name, actor=actor)
    except Exception as exc:
        http_status = getattr(exc, "http_status", None)
        if http_status == 404:
            return JSONResponse(
                {"unregistered": False, "name": name, "error": f"Unknown backend: {name}"},
                status_code=404,
            )
        message = str(exc)
        if any(k in message for k in ("bearer_token", "tls_cert", "env")):
            message = "Backend credential reference validation failed."
        if http_status is not None and int(http_status) < 500:
            return JSONResponse(
                {"unregistered": False, "name": name, "error": message},
                status_code=int(http_status),
            )
        logger.warning("mcp backend registry unregister failed for %s: %s", name, message)
        return JSONResponse(
            {
                "unregistered": False,
                "name": name,
                "error": "mcp backend registry unregister failed",
            },
            status_code=503,
        )

    return JSONResponse(
        {
            "unregistered": True,
            "name": name,
            "status": "unregistered_pending_restart",
            "pending_apply": True,
            "restart_required": True,
        }
    )


async def set_backend_enabled(request: Request) -> JSONResponse:
    """POST /api/v1/backends/{name}/enabled — enable or disable a backend row.

    PT1/WI5: operator add-on enable/disable. Flips the ``enabled`` column on the
    registry row via ``registry.set_enabled``; it never edits the DB directly
    from the frontend. Like register/unregister (D34), this is a catalog change
    that the served /mcp aggregate applies on Gateway restart, so it reports
    ``restart_required``. Body: {"enabled": bool}.
    """
    authz = require_control_plane_operator(request)  # SEC-1: operator-only
    if authz is not None:
        return authz
    gateway = request.app.state.gateway
    name = request.path_params["name"]
    registry = getattr(gateway, "mcp_backend_registry", None)
    if registry is None:
        return JSONResponse(
            {"name": name, "error": "mcp backend registry unavailable"},
            status_code=503,
        )

    if _registry_record_by_name(gateway, name) is None:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    body, error = await _read_json_body(request)
    if error:
        return error
    assert body is not None
    if "enabled" not in body or not isinstance(body.get("enabled"), bool):
        return JSONResponse(
            {"error": "Body must include boolean 'enabled'"}, status_code=400
        )
    enabled = bool(body["enabled"])

    actor = getattr(request.state, "identity", None)
    try:
        record = registry.set_enabled(name, enabled, actor=actor)
    except Exception as exc:
        http_status = getattr(exc, "http_status", None)
        if http_status == 404:
            return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)
        logger.warning("mcp backend set_enabled failed for %s: %s", name, exc)
        return JSONResponse(
            {"name": name, "error": "mcp backend registry write failed"},
            status_code=503,
        )

    return JSONResponse(
        {
            "name": record.name,
            "enabled": record.enabled,
            "status": "enabled_pending_restart" if record.enabled else "disabled_pending_restart",
            "pending_apply": True,
            "restart_required": True,
        }
    )


def rest_routes() -> list[Route]:
    """Return REST API v1 routes."""
    return [
        Route("/api/v1/tools", list_tools, methods=["GET"]),
        Route("/api/v1/tools/{tool_name}", call_tool, methods=["POST"]),
        Route("/api/v1/backends", list_backends, methods=["GET"]),
        Route("/api/v1/backends", register_backend, methods=["POST"]),
        Route("/api/v1/backends/{name}", unregister_backend, methods=["DELETE"]),
        Route("/api/v1/backends/{name}/enabled", set_backend_enabled, methods=["POST"]),
        Route("/api/v1/backends/validate", validate_backend, methods=["POST"]),
        Route("/api/v1/backends/reload", reload_backends, methods=["POST"]),
        Route("/api/v1/services", list_services, methods=["GET"]),
        Route("/api/v1/services/{name}/start", start_service, methods=["POST"]),
        Route("/api/v1/services/{name}/stop", stop_service, methods=["POST"]),
        Route("/api/v1/services/{name}/restart", restart_service, methods=["POST"]),
        Route("/api/v1/setup/join-code", create_join_code, methods=["POST"]),
        Route("/api/v1/setup/join", join_gateway, methods=["POST"]),
        Route("/api/v1/setup/join-status", join_status, methods=["GET"]),
    ]
