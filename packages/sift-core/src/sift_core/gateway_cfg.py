"""Shared helpers for connecting to the local agentir gateway.

Reads ~/.agentir/gateway.yaml. Always uses 127.0.0.1 for local access.
"""

from __future__ import annotations

import ssl
from pathlib import Path


def _read_gateway_config() -> dict:
    import yaml

    gateway_config = Path.home() / ".agentir" / "gateway.yaml"
    if not gateway_config.exists():
        return {}
    try:
        with open(gateway_config) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def get_local_gateway_url() -> str:
    """Build the local gateway URL from gateway.yaml.

    Always returns http(s)://127.0.0.1:{port}. Falls back to http://127.0.0.1:4508.
    """
    config = _read_gateway_config()
    gw = config.get("gateway", {})
    if isinstance(gw, dict):
        port = gw.get("port", 4508)
        tls = gw.get("tls", {})
        scheme = "https" if isinstance(tls, dict) and tls.get("certfile") else "http"
        return f"{scheme}://127.0.0.1:{port}"
    return "http://127.0.0.1:4508"


def get_local_ssl_context() -> ssl.SSLContext | None:
    """Return an SSL context for local gateway connections, or None if no TLS."""
    config = _read_gateway_config()
    gw = config.get("gateway", {})
    if not isinstance(gw, dict):
        return None
    tls = gw.get("tls", {})
    if not isinstance(tls, dict) or not tls.get("certfile"):
        return None

    ca = find_ca_cert()
    ctx = ssl.create_default_context()
    if ca:
        try:
            ctx.load_verify_locations(ca)
            return ctx
        except (ssl.SSLError, OSError):
            pass
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def find_ca_cert() -> str | None:
    ca_path = Path.home() / ".agentir" / "tls" / "ca-cert.pem"
    if ca_path.exists():
        return str(ca_path)
    return None
