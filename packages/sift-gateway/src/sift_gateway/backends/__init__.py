"""MCP backend implementations."""

import json
import logging
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse
import jsonschema

from sift_gateway.backends.base import MCPBackend
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend

logger = logging.getLogger(__name__)

# Load schema
SCHEMA_PATH = Path(__file__).parent.parent / "sift-backend.schema.json"


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
                    resp = httpx.get(explicit_path, timeout=5.0)
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
                    resp = httpx.get(manifest_url, timeout=5.0)
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
        logger.info("Successfully validated manifest for backend %s from %s", name, manifest_source)
        return manifest_data
    except Exception as e:
        # Contract graduation (Phase 6.4): an invalid manifest is always a hard reject.
        logger.warning("Manifest validation failed for backend %s from %s: %s", name, manifest_source, e)
        raise ValueError(f"Backend manifest validation failed for {name}: {e}") from e


def create_backend(name: str, config: dict) -> MCPBackend:
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
