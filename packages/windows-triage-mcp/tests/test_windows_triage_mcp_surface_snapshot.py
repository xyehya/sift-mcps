from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from windows_triage_mcp.registry import create_server

SNAPSHOT_PATH = Path(__file__).parent / "fixtures" / "mcp_surface_golden.json"


def test_mcp_surface_snapshot() -> None:
    snapshot = asyncio.run(_collect_snapshot())
    if os.environ.get("UPDATE_MCP_GOLDENS") == "1":
        SNAPSHOT_PATH.write_text(_to_json(snapshot), encoding="utf-8")
    expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    assert snapshot == expected


async def _collect_snapshot() -> dict[str, Any]:
    mcp = create_server()
    return {
        "backend": "windows-triage-mcp",
        "tools": [_tool(item) for item in await mcp.list_tools()],
        "prompts": [_prompt(item) for item in await mcp.list_prompts()],
        "resources": [_resource(item) for item in await mcp.list_resources()],
        "resource_templates": [
            _resource_template(item) for item in await mcp.list_resource_templates()
        ],
    }


def _tool(item: Any) -> dict[str, Any]:
    return _stable(
        {
            "name": item.name,
            "title": item.title,
            "description": item.description,
            "input_schema": item.parameters,
            "output_schema": item.output_schema,
            "annotations": _model_dump(item.annotations),
            "meta": item.meta,
        }
    )


def _prompt(item: Any) -> dict[str, Any]:
    return _stable(
        {
            "name": item.name,
            "title": item.title,
            "description": item.description,
            "arguments": [_model_dump(argument) for argument in item.arguments],
        }
    )


def _resource(item: Any) -> dict[str, Any]:
    return _stable(
        {
            "uri": str(item.uri),
            "name": item.name,
            "title": item.title,
            "description": item.description,
            "mime_type": item.mime_type,
            "annotations": _model_dump(item.annotations),
            "meta": item.meta,
        }
    )


def _resource_template(item: Any) -> dict[str, Any]:
    return _stable(
        {
            "uri_template": str(item.uri_template),
            "name": item.name,
            "title": item.title,
            "description": item.description,
            "mime_type": item.mime_type,
            "annotations": _model_dump(item.annotations),
            "meta": item.meta,
        }
    )


def _model_dump(item: Any) -> dict[str, Any] | None:
    if item is None:
        return None
    if hasattr(item, "model_dump"):
        return item.model_dump(mode="json", by_alias=True, exclude_none=True)
    return item


def _stable(value: Any) -> Any:
    return json.loads(_to_json(value))


def _to_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str) + "\n"
