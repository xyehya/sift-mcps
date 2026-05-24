"""Bearer token generation for the sift-mcps gateway."""

import secrets


def generate_gateway_token() -> str:
    """Generate a bearer token for gateway API authentication.

    Format: ``agentir_gw_`` prefix + 48 hex characters (192 bits entropy).
    """
    return f"agentir_gw_{secrets.token_hex(24)}"


def generate_service_token() -> str:
    """Generate a service bearer token for agent MCP clients (mcp.json).

    Format: ``agentir_svc_`` prefix + 48 hex characters (192 bits entropy).
    """
    return f"agentir_svc_{secrets.token_hex(24)}"
