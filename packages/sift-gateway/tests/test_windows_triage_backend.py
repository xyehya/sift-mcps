from __future__ import annotations

import json
from pathlib import Path

from mcp.types import Tool

from sift_gateway.server import Gateway

# Load the real migrated manifest so the test tracks the shipped namespace + tool set.
_MANIFEST = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "windows-triage-mcp"
        / "sift-backend.json"
    ).read_text()
)
_WINTRIAGE_TOOLS = {t["name"] for t in _MANIFEST["tools"]}


class _FakeBackend:
    started = True
    manifest = _MANIFEST

    async def list_tools(self):
        return [
            Tool(name=name, description="", inputSchema={"type": "object"})
            for name in _WINTRIAGE_TOOLS
        ]


async def test_gateway_lists_windows_triage_tools_when_backend_enabled():
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    gateway.backends["windows-triage-mcp"] = _FakeBackend()
    await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    # Every advertised tool is namespaced under the manifest prefix and survives aggregation.
    assert _WINTRIAGE_TOOLS.issubset(tool_names)
    assert all(name.startswith("wintriage_") for name in _WINTRIAGE_TOOLS)
