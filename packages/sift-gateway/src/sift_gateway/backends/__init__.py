"""MCP backend implementations."""

import json
import logging
import os
import shutil
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse
import jsonschema

from sift_gateway.backends.base import MCPBackend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend

logger = logging.getLogger(__name__)

# Load schema
SCHEMA_PATH = Path(__file__).parent.parent / "sift-backend.schema.json"
VALID_EVIDENCE_CLASSES = {"read_only", "analysis", "mutating"}
VALID_PHASES = {"SURVEY", "INGEST", "ANALYZE", "CORRELATE", "FINDING"}


def _validate_remote_fetch_url(url: str, *, label: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"{label} must be an http(s) URL with a hostname")
    try:
        infos = socket.getaddrinfo(
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
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


def _validate_manifest_instructions(manifest: dict, manifest_path: Path | None) -> None:
    """Validate and resolve optional backend-level manifest instructions."""
    inline = manifest.get("instructions")
    path_value = manifest.get("instructions_path")

    if inline and path_value:
        raise ValueError("Manifest must use only one of instructions or instructions_path.")
    if inline is not None and not str(inline).strip():
        raise ValueError("Manifest instructions must not be empty when provided.")
    if not path_value:
        return
    if manifest_path is None:
        raise ValueError(
            "Manifest instructions_path is only supported for local manifests."
        )

    rel_path = Path(str(path_value))
    if rel_path.is_absolute():
        raise ValueError("Manifest instructions_path must be relative to the backend package.")

    package_root = manifest_path.resolve().parent
    resolved = (package_root / rel_path).resolve()
    try:
        resolved.relative_to(package_root)
    except ValueError as exc:
        raise ValueError(
            "Manifest instructions_path must stay inside the backend package."
        ) from exc

    if not resolved.is_file():
        raise ValueError(f"Manifest instructions_path is not readable: {path_value}")
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Manifest instructions_path is not readable: {path_value}") from exc
    if not text.strip():
        raise ValueError("Manifest instructions_path file must not be empty.")
    manifest["_resolved_instructions"] = text


def validate_manifest_contract(manifest: dict, manifest_path: Path | None = None) -> None:
    """Validate cross-field Backend Contract invariants."""
    _validate_manifest_instructions(manifest, manifest_path)

    namespace = manifest.get("namespace", "")
    tools = manifest.get("tools", [])
    if not tools:
        raise ValueError("Manifest must declare at least one tool.")

    declared_tools: dict[str, dict] = {}
    health_tools: list[str] = []
    for tool in tools:
        tool_name = tool.get("name", "")
        if tool_name in declared_tools:
            raise ValueError(f"Duplicate tool declaration: {tool_name}")
        declared_tools[tool_name] = tool

        if namespace and not tool_name.startswith(f"{namespace}_"):
            raise ValueError(
                f"Tool '{tool_name}' does not start with declared namespace "
                f"prefix '{namespace}_'"
            )

        read_only = tool.get("read_only")
        read_only_hint = tool.get("readOnlyHint")
        evidence_class = tool.get("evidence_class")
        if read_only != read_only_hint:
            raise ValueError(
                f"Tool '{tool_name}' has inconsistent read_only/readOnlyHint "
                f"values ({read_only!r} vs {read_only_hint!r})."
            )
        if evidence_class not in VALID_EVIDENCE_CLASSES:
            raise ValueError(
                f"Tool '{tool_name}' has invalid evidence_class: {evidence_class!r}"
            )
        if evidence_class == "read_only" and read_only is not True:
            raise ValueError(
                f"Tool '{tool_name}' evidence_class=read_only requires read_only=true."
            )
        if evidence_class == "mutating" and read_only is not False:
            raise ValueError(
                f"Tool '{tool_name}' evidence_class=mutating requires read_only=false."
            )
        if tool.get("recommended_phase") not in VALID_PHASES:
            raise ValueError(
                f"Tool '{tool_name}' has invalid recommended_phase: "
                f"{tool.get('recommended_phase')!r}"
            )
        if tool.get("health"):
            health_tools.append(tool_name)

    health_name = manifest.get("health")
    if not health_name:
        raise ValueError("Manifest must declare top-level health tool name.")
    if health_name not in declared_tools:
        raise ValueError(
            f"Top-level health tool '{health_name}' is not declared in tools[]."
        )
    if not declared_tools[health_name].get("health"):
        raise ValueError(
            f"Top-level health tool '{health_name}' must have tool-level "
            '"health": true.'
        )
    if len(health_tools) != 1:
        raise ValueError(
            "Manifest must declare exactly one tool with health=true; "
            f"found {len(health_tools)}."
        )


def load_and_validate_manifest(name: str, config: dict) -> dict | None:
    backend_type = config.get("type", "stdio")
    manifest_data = None
    manifest_source = None

    explicit_path = config.get("manifest_path")

    if backend_type == "stdio":
        if explicit_path:
            manifest_path = Path(explicit_path)
            manifest_source = str(manifest_path)
        else:
            # well-known path: packages/<name>/sift-backend.json
            mcps_root = os.environ.get("SIFT_MCPS_ROOT")
            if mcps_root:
                manifest_path = Path(mcps_root) / "packages" / name / "sift-backend.json"
            else:
                manifest_path = Path(__file__).resolve().parents[5] / "packages" / name / "sift-backend.json"
            manifest_source = f"well-known path {manifest_path}"
        
        try:
            if manifest_path.exists():
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            else:
                logger.warning("Manifest not found for stdio backend %s at %s", name, manifest_path)
        except Exception as e:
            logger.warning("Failed to load manifest for stdio backend %s from %s: %s", name, manifest_path, e)

    elif backend_type == "http":
        if explicit_path:
            # manifest_path could be a local file path or a URL
            if explicit_path.startswith(("http://", "https://")):
                import httpx
                try:
                    _validate_remote_fetch_url(explicit_path, label="manifest_path")
                    resp = httpx.get(explicit_path, timeout=5.0, follow_redirects=False)
                    if resp.status_code == 200:
                        manifest_data = resp.json()
                        manifest_source = explicit_path
                    else:
                        logger.warning("Failed to fetch manifest for HTTP backend %s from URL %s: status %d", name, explicit_path, resp.status_code)
                except Exception as e:
                    logger.warning("Failed to fetch manifest for HTTP backend %s from URL %s: %s", name, explicit_path, e)
            else:
                manifest_path = Path(explicit_path)
                manifest_source = str(manifest_path)
                try:
                    if manifest_path.exists():
                        with open(manifest_path, "r", encoding="utf-8") as f:
                            manifest_data = json.load(f)
                except Exception as e:
                    logger.warning("Failed to load manifest for HTTP backend %s from file %s: %s", name, manifest_path, e)
        else:
            # Default /manifest fetch from the backend URL
            url = config.get("url")
            if url:
                manifest_url = url.rstrip("/") + "/manifest"
                import httpx
                try:
                    _validate_remote_fetch_url(manifest_url, label="backend manifest URL")
                    resp = httpx.get(manifest_url, timeout=5.0, follow_redirects=False)
                    if resp.status_code == 200:
                        manifest_data = resp.json()
                        manifest_source = manifest_url
                    else:
                        logger.warning("Failed to fetch manifest for HTTP backend %s from /manifest: status %d", name, resp.status_code)
                except Exception as e:
                    logger.warning("Failed to fetch manifest for HTTP backend %s from /manifest: %s", name, e)

    if manifest_data is None:
        # Contract graduation (Phase 6.4): a missing manifest is always a hard
        # reject — every add-on must ship a conformant sift-backend.json.
        raise ValueError(
            f"Backend manifest is missing/invalid for {name} (looked in {manifest_source}). "
            "Every add-on backend must ship a conformant sift-backend.json."
        )

    # Validate against JSON schema
    try:
        if not SCHEMA_PATH.exists():
            logger.error("JSON schema file not found at %s", SCHEMA_PATH)
            return manifest_data

        with open(SCHEMA_PATH, "r", encoding="utf-8") as sf:
            schema = json.load(sf)

        # spec_version major-version compatibility: gateway accepts 1.x, rejects 2.x.
        spec_version = manifest_data.get("spec_version")
        if not isinstance(spec_version, str) or not spec_version.startswith("1."):
            raise jsonschema.ValidationError(f"Unsupported spec_version: {spec_version}. Gateway only supports version 1.x.")

        jsonschema.validate(instance=manifest_data, schema=schema)
        local_manifest_path = manifest_path if "manifest_path" in locals() else None
        validate_manifest_contract(manifest_data, local_manifest_path)
        logger.info("Successfully validated manifest for backend %s from %s", name, manifest_source)
        return manifest_data
    except Exception as e:
        # Contract graduation (Phase 6.4): an invalid manifest is always a hard reject.
        logger.warning("Manifest validation failed for backend %s from %s: %s", name, manifest_source, e)
        raise ValueError(f"Backend manifest validation failed for {name}: {e}") from e


def create_backend(name: str, config: dict, *, manifest: dict | None = None) -> MCPBackend:
    """Factory: create a backend from config.

    Args:
        name: Backend name (e.g. "forensic-mcp").
        config: Backend config dict with at minimum a "type" key.

    Returns:
        An MCPBackend instance.

    Raises:
        ValueError: If the backend type is unknown or config is invalid.
    """
    backend_type = config.get("type", "stdio")
    if manifest is None:
        manifest = load_and_validate_manifest(name, config)

    if backend_type == "stdio":
        # Validate required keys for stdio
        command = config.get("command")
        if not command:
            raise ValueError(f"Backend {name!r}: stdio type requires 'command' key")
        if not isinstance(command, str):
            raise ValueError(
                f"Backend {name!r}: 'command' must be a string, got {type(command).__name__}"
            )
        # Warn (don't fail) if command not found on PATH — it may exist at runtime
        if shutil.which(command) is None:
            logger.warning("Backend %s: command %r not found on PATH", name, command)
        return StdioMCPBackend(name, config, manifest=manifest)

    elif backend_type == "http":
        # Validate required keys for http
        url = config.get("url")
        if not url:
            raise ValueError(f"Backend {name!r}: http type requires 'url' key")
        if not isinstance(url, str):
            raise ValueError(
                f"Backend {name!r}: 'url' must be a string, got {type(url).__name__}"
            )
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Backend {name!r}: URL must use http or https scheme, got {parsed.scheme!r}"
            )
        if not parsed.hostname:
            raise ValueError(f"Backend {name!r}: URL must include a hostname")
        return HttpMCPBackend(name, config, manifest=manifest)

    else:
        raise ValueError(f"Unknown backend type: {backend_type!r} for backend {name!r}")


__all__ = ["MCPBackend", "StdioMCPBackend", "HttpMCPBackend", "create_backend"]
