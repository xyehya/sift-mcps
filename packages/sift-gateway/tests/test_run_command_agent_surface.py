"""Agent-facing run_command contract: compact discovery and structured results."""

from __future__ import annotations

import json

from fastmcp.tools import ToolResult
from mcp.types import TextContent
from sift_common.instructions import GATEWAY
from sift_common.testing.surface import assert_passes_output_schema
from sift_core.agent_tools import core_tool_specs
from sift_core.execute.tools.discovery import get_tool_help
from sift_gateway.mcp_endpoint import _build_gateway_instructions
from sift_gateway.mcp_server import GatewayLocalTool, create_gateway_mcp_server
from sift_gateway.response_guard import guard_tool_result
from sift_gateway.server import Gateway


def _run_command_spec():
    return next(spec for spec in core_tool_specs() if spec.name == "run_command")


def test_run_command_advertises_a_compact_output_first_contract():
    """tools/list is the DFIR agent's first execution decision point."""
    spec = _run_command_spec()
    properties = spec.input_schema["properties"]

    assert "input_files" not in properties
    assert properties["save_output"]["default"] is True
    assert properties["preview_lines"]["default"] == 40
    assert "sealed originals" in properties["evidence_refs"]["description"].lower()
    assert "case-relative" in properties["working_dir"]["description"]
    assert isinstance(spec.output_schema, dict)
    assert spec.output_schema["type"] == "object"
    assert {"success", "tool", "audit_id"}.issubset(spec.output_schema["required"])
    assert "next_action" in spec.output_schema["properties"]
    assert "stderr_output_ref" in spec.output_schema["properties"]
    assert len(spec.description) < 700


def test_run_command_help_explains_the_saved_output_loop_without_hiding_policy():
    """On-demand help carries execution detail that does not belong at init."""
    card = get_tool_help("run_command")

    assert card["workflow"][0].startswith("Use evidence_refs")
    assert "full_output_ref" in card["workflow"][2]
    assert "audit_id" in card["workflow"][3]
    assert "vetted forensic device operands" in card["policy"]["path_restrictions"]


async def test_gateway_tools_list_advertises_run_command_output_schema():
    """The registered MCP surface must retain the core registry's contract."""
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": []}}})
    mcp = create_gateway_mcp_server(gateway)
    advertised = {tool.name: tool for tool in await mcp.list_tools()}

    assert advertised["run_command"].output_schema == _run_command_spec().output_schema


async def test_gateway_local_tool_populates_structured_content_for_run_command():
    """A declared output schema must survive the local-core adapter (Seam B)."""
    spec = _run_command_spec()
    payload = {
        "success": True,
        "tool": "run_command",
        "audit_id": "AUD-001",
        "examiner": "analyst",
        "data": {"stdout": "one\ntwo\n"},
        "exit_code": 0,
        "full_output_ref": "agent/run_commands/output1/stdout.txt",
        "next_action": {
            "type": "inspect_saved_output",
            "output_ref": "agent/run_commands/output1/stdout.txt",
            "command": "head -n 40 agent/run_commands/output1/stdout.txt",
        },
    }

    async def _handler(_arguments, _examiner):
        return json.dumps(payload)

    tool = GatewayLocalTool(
        gateway=object(),
        handler=_handler,
        name="run_command",
        description=spec.description,
        parameters=spec.input_schema,
        output_schema=spec.output_schema,
    )
    result = await tool.run({"command": "echo one", "purpose": "test"})

    assert isinstance(result, ToolResult)
    assert result.structured_content == payload
    assert json.loads(result.content[0].text) == payload
    assert_passes_output_schema(spec.output_schema, result, tool_name="run_command")


def test_response_guard_cap_preserves_typed_run_command_receipt(tmp_path):
    """A capped response must remain valid for the declared MCP output schema."""
    spec = _run_command_spec()
    payload = {
        "success": True,
        "tool": "run_command",
        "audit_id": "AUD-CAPPED-001",
        "data": {"stdout": "x" * 8_000},
        "exit_code": 0,
    }
    result = ToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
    )

    guarded, _findings, cap_events = guard_tool_result(
        result,
        override_active=False,
        case_dir=str(tmp_path),
        tool_name="run_command",
        cap_bytes=500,
    )

    assert cap_events
    assert guarded.structured_content["success"] is True
    assert guarded.structured_content["tool"] == "run_command"
    assert guarded.structured_content["audit_id"] == "AUD-CAPPED-001"
    assert_passes_output_schema(spec.output_schema, guarded, tool_name="run_command")


def test_initialize_instructions_are_short_and_delegate_capability_detail():
    """Initialization orients an agent without duplicating every tool manual."""
    instructions = _build_gateway_instructions(object())

    assert instructions == GATEWAY
    assert "input_files" not in instructions
    assert "full_output_path" not in instructions
    assert "ADD-ON MANIFEST SUMMARY" not in instructions
    assert len(instructions) < 1_400
