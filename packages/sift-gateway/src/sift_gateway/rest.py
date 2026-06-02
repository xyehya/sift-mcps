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

from sift_gateway.auth import resolve_examiner
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
    create_backend,
    load_and_validate_manifest,
    validate_manifest_contract,
)

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
                "tls_cert",
                "manifest_path",
                "enabled",
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

    if tool_name not in gateway._tool_map:
        return JSONResponse(
            {"error": f"Tool not found: {tool_name}"},
            status_code=404,
        )

    try:
        result = await gateway.call_tool(
            tool_name, arguments, examiner=identity.get("examiner")
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
                "backend": gateway._tool_map[tool_name],
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

    backends = []
    for name, backend in gateway.backends.items():
        try:
            health = await backend.health_check()
        except (RuntimeError, ConnectionError, OSError) as e:
            logger.warning("Health check failed for backend %s: %s", name, e)
            health = {"status": "error", "detail": str(e)}
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
            logger.warning("Health check unexpected error for backend %s: %s", name, e)
            health = {"status": "error"}

        backends.append(
            {
                "name": name,
                "type": backend.config.get("type", "stdio"),
                "enabled": backend.enabled,
                "health": health,
            }
        )

    return JSONResponse({"backends": backends, "count": len(backends)})


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
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]
    if backend.started:
        return JSONResponse({"status": "already_running", "name": name})

    try:
        await asyncio.wait_for(backend.start(), timeout=30.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Start timed out for {name}"}, status_code=504)
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
        logger.error("Failed to start service %s: %s", name, e)
        return JSONResponse(
            {"error": f"Failed to start service {name}"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "started", "name": name})


async def stop_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/stop — stop a backend and rebuild tool map."""
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]
    if not backend.started:
        return JSONResponse({"status": "already_stopped", "name": name})

    try:
        await asyncio.wait_for(backend.stop(), timeout=10.0)
    except asyncio.TimeoutError:
        return JSONResponse({"error": f"Stop timed out for {name}"}, status_code=504)
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
        logger.error("Failed to stop service %s: %s", name, e)
        return JSONResponse(
            {"error": f"Failed to stop service {name}"}, status_code=500
        )

    await gateway._build_tool_map()
    return JSONResponse({"status": "stopped", "name": name})


async def restart_service(request: Request) -> JSONResponse:
    """POST /api/v1/services/{name}/restart — stop + start a backend."""
    gateway = request.app.state.gateway
    name = request.path_params["name"]

    if name not in gateway.backends:
        return JSONResponse({"error": f"Unknown backend: {name}"}, status_code=404)

    backend = gateway.backends[name]

    # Stop if running
    if backend.started:
        try:
            await asyncio.wait_for(backend.stop(), timeout=10.0)
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
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
    except (Exception, asyncio.CancelledError, BaseExceptionGroup) as e:
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
    expires_hours = 2
    body = await request.body()
    if body:
        try:
            data = json.loads(body)
            expires_hours = data.get("expires_hours", 2)
        except json.JSONDecodeError:
            pass

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

    # If wintools: add wintools backend to config and hot-load
    wintools_registered = False
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

        # Write to disk
        _add_wintools_backend(
            gateway, wintools_url, wintools_token, tls_cert=cert_path_str
        )
        wintools_registered = True

        # Schedule background loading.  The backend loader retries until
        # wintools-mcp is online (Windows installer starts it after
        # receiving this join response).
        backend_config = {
            "type": "http",
            "url": wintools_url,
            "bearer_token": wintools_token,
            "enabled": True,
        }
        if cert_path_str:
            backend_config["tls_cert"] = cert_path_str
        gateway._pending_backends["wintools-mcp"] = backend_config
        gateway._reload_event.set()

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
            except (yaml.YAMLError, OSError):
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


def _add_wintools_backend(
    gateway, url: str, token: str, tls_cert: str | None = None
) -> None:
    """Add a wintools-mcp HTTP backend to the gateway config."""
    from pathlib import Path

    import yaml

    with _CONFIG_LOCK:
        config_path = Path.home() / ".sift" / "gateway.yaml"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            except (yaml.YAMLError, OSError):
                config = {}
        else:
            config = {}

        if "backends" not in config:
            config["backends"] = {}

        config["backends"]["wintools-mcp"] = {
            "type": "http",
            "url": url,
            "bearer_token": token,
            "enabled": True,
        }
        if tls_cert:
            config["backends"]["wintools-mcp"]["tls_cert"] = tls_cert

        try:
            _atomic_yaml_write(config_path, config)
        except OSError as e:
            logger.error("Failed to write gateway config: %s", e)
            raise HTTPException(
                status_code=500, detail="Failed to save configuration"
            ) from e


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
    except Exception:
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
        except Exception:
            pass
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
    """POST /api/v1/backends/reload — schedule loading of new backends.

    Re-reads gateway.yaml and starts any backends not yet loaded.
    Does not restart existing backends (safe for active sessions).
    """
    from pathlib import Path

    import yaml

    from sift_gateway.config import load_config

    gateway = request.app.state.gateway
    config_path = Path.home() / ".sift" / "gateway.yaml"
    if not config_path.exists():
        return JSONResponse({"status": "no_config", "pending": []})
    try:
        config = load_config(str(config_path))
    except (ValueError, yaml.YAMLError, OSError):
        return JSONResponse({"error": "failed to read gateway.yaml"}, status_code=500)

    pending = []
    for name, conf in config.get("backends", {}).items():
        if not conf.get("enabled", True):
            continue
        existing = gateway.backends.get(name)
        if existing and existing.started:
            continue
        gateway._pending_backends[name] = conf
        pending.append(name)

    if pending:
        gateway._reload_event.set()
    return JSONResponse({"status": "reload_scheduled", "pending": pending})


async def validate_backend(request: Request) -> JSONResponse:
    """POST /api/v1/backends/validate — validate a backend manifest/config."""
    gateway = request.app.state.gateway
    body, error = await _read_json_body(request)
    if error:
        return error
    assert body is not None

    name, config, inline_manifest, reasons = _normalize_backend_payload(body)
    manifest = None
    if not reasons:
        manifest, reasons = _load_manifest_for_rest(name, config, inline_manifest)

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
    return JSONResponse(response, status_code=status_code)


async def register_backend(request: Request) -> JSONResponse:
    """POST /api/v1/backends — validate, persist, and hot-register a backend."""
    gateway = request.app.state.gateway
    body, error = await _read_json_body(request)
    if error:
        return error
    assert body is not None

    name, config, inline_manifest, reasons = _normalize_backend_payload(body)
    if inline_manifest is not None and "manifest_path" not in config:
        reasons.append(
            {
                "field": "manifest_path",
                "reason": "Registration requires a manifest_path or URL; inline manifests are validate-only.",
            }
        )

    manifest = None
    if not reasons:
        manifest, reasons = _load_manifest_for_rest(name, config, None)

    if reasons:
        return JSONResponse(
            {"registered": False, "name": name, "reasons": reasons},
            status_code=422,
        )

    assert manifest is not None
    enabled = bool(config.get("enabled", True))
    requires, unmet = _requirement_status(gateway, manifest)
    try:
        backend = create_backend(name, config)
    except ValueError as exc:
        return JSONResponse(
            {
                "registered": False,
                "name": name,
                "reasons": [{"field": "config", "reason": str(exc)}],
            },
            status_code=422,
        )

    with _CONFIG_LOCK:
        config_path = _gateway_config_path()
        if config_path.exists():
            import yaml

            try:
                config_doc = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            except (yaml.YAMLError, OSError):
                return JSONResponse(
                    {"registered": False, "error": "failed to read gateway.yaml"},
                    status_code=500,
                )
        else:
            config_doc = {}

        config_doc.setdefault("backends", {})[name] = config
        try:
            _atomic_yaml_write(config_path, config_doc)
        except OSError:
            logger.exception("Failed to write gateway config")
            return JSONResponse(
                {"registered": False, "error": "failed to write gateway.yaml"},
                status_code=500,
            )

    gateway.config.setdefault("backends", {})[name] = config
    if enabled:
        gateway.backends[name] = backend
        await gateway._build_tool_map()
        if not unmet:
            gateway._pending_backends[name] = config
            gateway._reload_event.set()
    else:
        gateway.backends.pop(name, None)
        await gateway._build_tool_map()

    return JSONResponse(
        {
            "registered": True,
            "name": name,
            "enabled": enabled,
            "available": enabled and not unmet,
            "requires": requires,
            "unmet_requires": unmet,
            "reload_scheduled": enabled and not unmet,
        },
        status_code=201,
    )


def rest_routes() -> list[Route]:
    """Return REST API v1 routes."""
    return [
        Route("/api/v1/tools", list_tools, methods=["GET"]),
        Route("/api/v1/tools/{tool_name}", call_tool, methods=["POST"]),
        Route("/api/v1/backends", list_backends, methods=["GET"]),
        Route("/api/v1/backends", register_backend, methods=["POST"]),
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
