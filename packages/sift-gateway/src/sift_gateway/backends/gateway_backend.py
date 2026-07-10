"""Gateway-owned first-party backend adapter.

This adapter represents a first-party pack whose MCP tools execute in the
gateway process rather than in a credential-bearing child process.  The
registry still owns its manifest, enablement, health, and audit metadata; the
adapter merely supplies the typed tool declarations to the aggregate catalog.
"""

from __future__ import annotations

from typing import Any

from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend


class GatewayOwnedMCPBackend(MCPBackend):
    """A deliberately small, allow-listed in-process backend declaration.

    Gateway-owned transports are not a generic extension point: accepting an
    arbitrary manifest here would give a portal registration a route into the
    trusted gateway process.  ``create_backend`` enforces the one supported
    first-party name before constructing this adapter.
    """

    def __init__(self, name: str, config: dict[str, Any], manifest: dict[str, Any]):
        super().__init__(name, config, manifest=manifest)
        self._started = True

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        # There is no child process or connection to stop.  Keeping this adapter
        # live prevents the generic idle reaper from making a registered pack
        # disappear from the agent catalog.
        self._started = True

    async def list_tools(self) -> list[Tool]:
        if self.name != "forensic-rag-mcp":  # defense in depth beside factory allowlist
            raise RuntimeError(f"unsupported gateway-owned backend: {self.name}")
        from sift_gateway.rag_tools import rag_tool_catalog

        return rag_tool_catalog()

    async def call_tool(self, name: str, arguments: dict) -> list:
        del name, arguments
        raise RuntimeError(
            "gateway-owned tools must be dispatched by the gateway policy path"
        )

    async def health_check(self) -> dict[str, Any]:
        return {"status": "ok", "type": "gateway"}
