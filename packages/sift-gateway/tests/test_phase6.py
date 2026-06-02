import asyncio
import json
from pathlib import Path

import pytest

from sift_gateway.backends import load_and_validate_manifest
from sift_gateway.mcp_endpoint import _capability_guide
from sift_gateway.server import Gateway


def _execute_security():
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def _tool(name: str, *, health: bool = False, hidden: bool = False) -> dict:
    tool = {
        "name": name,
        "description": f"{name} description",
        "read_only": True,
        "readOnlyHint": True,
        "evidence_class": "read_only",
        "category": "search-analysis",
        "recommended_phase": "ANALYZE",
        "when_to_use": f"use {name}",
        "avoid_when": f"avoid {name}",
        "output_notes": f"notes {name}",
    }
    if health:
        tool["health"] = True
    if hidden:
        tool["hidden_from_agent"] = True
    return tool


def _manifest(*, requires: list[str] | None = None) -> dict:
    return {
        "spec_version": "1.0",
        "name": "sample-addon",
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": "sample",
        "instructions": "Sample manifest guidance.",
        "capabilities": {
            "provides": ["search", "enrichment"],
            "requires": requires or [],
            "enriches_responses": False,
        },
        "tools": [
            _tool("sample_search"),
            _tool("sample_health", health=True),
            _tool("sample_hidden", hidden=True),
        ],
        "health": "sample_health",
    }


class _FakeBackend:
    started = False

    def __init__(self, manifest: dict):
        self.manifest = manifest


def test_capability_guide_uses_available_manifest_guidance_only():
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["sample-addon"] = _FakeBackend(_manifest())
    gateway.backends["gated-addon"] = _FakeBackend(_manifest(requires=["unknown:req"]))

    asyncio.run(gateway._build_tool_map())

    guide = _capability_guide(gateway)
    available = {b["backend"]: b for b in guide["available_backends"]}
    unavailable = {b["backend"]: b for b in guide["unavailable_backends"]}

    assert set(available) == {"sample-addon"}
    assert "gated-addon" in unavailable
    assert unavailable["gated-addon"]["unmet_requires"] == ["unknown:req"]

    sample = available["sample-addon"]
    assert sample["provides"] == ["search", "enrichment"]
    assert sample["health_tool"] == "sample_health"
    assert sample["instructions"] == "Sample manifest guidance."

    tool_names = {tool["name"] for tool in sample["tools"]}
    assert tool_names == {"sample_search", "sample_health"}
    assert "sample_hidden" not in json.dumps(guide)
    assert guide["groups"]["by_provides"]["search"] == ["sample_health", "sample_search"]
    assert guide["groups"]["by_category"]["search-analysis"] == [
        "sample_health",
        "sample_search",
    ]
    assert guide["groups"]["by_recommended_phase"]["ANALYZE"] == [
        "sample_health",
        "sample_search",
    ]
    search_tool = next(t for t in sample["tools"] if t["name"] == "sample_search")
    assert search_tool["when_to_use"] == "use sample_search"
    assert search_tool["avoid_when"] == "avoid sample_search"
    assert search_tool["output_notes"] == "notes sample_search"


def test_manifest_instructions_path_is_package_local_and_readable(tmp_path):
    guidance = tmp_path / "GUIDANCE.md"
    guidance.write_text("Local backend guidance.", encoding="utf-8")
    manifest = _manifest()
    manifest.pop("instructions")
    manifest["instructions_path"] = "GUIDANCE.md"
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_and_validate_manifest(
        "sample-addon",
        {"type": "stdio", "command": "true", "manifest_path": str(manifest_path)},
    )

    assert loaded["_resolved_instructions"] == "Local backend guidance."


def test_manifest_instructions_path_cannot_escape_package(tmp_path):
    outside = tmp_path.parent / "outside-guidance.md"
    outside.write_text("escape", encoding="utf-8")
    manifest = _manifest()
    manifest.pop("instructions")
    manifest["instructions_path"] = "../outside-guidance.md"
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="must stay inside the backend package"):
        load_and_validate_manifest(
            "sample-addon",
            {"type": "stdio", "command": "true", "manifest_path": str(manifest_path)},
        )


def test_gateway_core_has_no_hardcoded_addon_names():
    src_root = Path(__file__).resolve().parents[1] / "src" / "sift_gateway"
    combined = (
        (src_root / "mcp_endpoint.py").read_text(encoding="utf-8")
        + "\n"
        + (src_root / "server.py").read_text(encoding="utf-8")
    )
    forbidden = [
        "opensearch",
        "wintriage",
        "cti_",
        "kb_",
        "forensic-rag",
        "opencti",
        "windows-triage",
    ]
    assert [name for name in forbidden if name in combined] == []
