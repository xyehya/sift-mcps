"""HTTP transport for opensearch-mcp."""

from opensearch_mcp.registry import create_server


def create_http_app():
    """Create ASGI app for HTTP transport."""
    return create_server().http_app(transport="http")
