"""HTTP transport for opensearch-mcp."""

from starlette.middleware.trustedhost import TrustedHostMiddleware

from opensearch_mcp.registry import create_server

# DNS-rebinding protection: only accept requests whose Host header targets the
# local bind. The pre-FastMCP-3 server set
# ``transport_security.enable_dns_rebinding_protection`` +
# ``allowed_hosts`` on the in-SDK app; FastMCP 3's ``http_app()`` no longer plumbs
# ``TransportSecuritySettings`` into the session manager, so we re-establish the
# Host-header allowlist at the ASGI edge (TrustedHostMiddleware strips the port
# before matching, so ``127.0.0.1:4625`` matches ``127.0.0.1``).
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]


def create_http_app():
    """Create ASGI app for HTTP transport with DNS-rebinding protection."""
    app = create_server().http_app(transport="http")
    return TrustedHostMiddleware(app, allowed_hosts=ALLOWED_HOSTS)
