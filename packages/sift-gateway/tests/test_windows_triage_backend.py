from __future__ import annotations

from mcp.types import Tool

from sift_gateway.server import Gateway


class _FakeBackend:
    started = True

    async def list_tools(self):
        return [
            Tool(name=name, description="", inputSchema={"type": "object"})
            for name in {
                "check_file",
                "check_process_tree",
                "check_service",
                "check_scheduled_task",
                "check_autorun",
                "check_registry",
                "check_hash",
                "analyze_filename",
                "check_lolbin",
                "check_hijackable_dll",
                "check_pipe",
                "get_db_stats",
                "get_health",
            }
        ]


async def test_gateway_lists_windows_triage_tools_when_backend_enabled():
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    gateway.backends["windows-triage-mcp"] = _FakeBackend()
    await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    assert {
        "check_file",
        "check_process_tree",
        "check_service",
        "check_scheduled_task",
        "check_autorun",
        "check_registry",
        "check_hash",
        "analyze_filename",
        "check_lolbin",
        "check_hijackable_dll",
        "check_pipe",
        "get_db_stats",
        "get_health",
    }.issubset(tool_names)
