import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from mcp.types import ListToolsRequest, TextContent
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

from sift_gateway.backends import load_and_validate_manifest
from sift_gateway.auth import AuthMiddleware
from sift_gateway.mcp_endpoint import (
    _capability_guide,
    _handle_environment_summary,
    create_mcp_server,
)
from sift_gateway.rest import rest_routes
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
        self.config = {"type": manifest.get("transport", "stdio")}
        self.enabled = True

    async def health_check(self):
        return {"status": "ok"}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _manifest_paths() -> list[Path]:
    return sorted((_repo_root() / "packages").glob("*/sift-backend.json"))


def _gateway_with_fake_backends(*manifests: dict) -> Gateway:
    gateway = Gateway({"backends": {}, **_execute_security()})
    for manifest in manifests:
        gateway.backends[manifest["name"]] = _FakeBackend(manifest)
    asyncio.run(gateway._build_tool_map())
    return gateway


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


def test_capability_guide_exact_shape_and_omits_disabled_or_gated_addons():
    sample = _manifest()
    gated = _manifest(requires=["unknown:req"])
    gated["name"] = "gated-addon"
    gateway = _gateway_with_fake_backends(sample, gated)

    guide = _capability_guide(gateway)

    assert set(guide) == {
        "platform",
        "purpose",
        "scope",
        "available_backends",
        "unavailable_backends",
        "groups",
    }
    assert guide["scope"] == "add-on backends only"
    assert set(guide["groups"]) == {
        "by_provides",
        "by_category",
        "by_recommended_phase",
    }
    assert guide["available_backends"] == [
        {
            "backend": "sample-addon",
            "provides": ["search", "enrichment"],
            "requires": [],
            "unmet_requires": [],
            "health_tool": "sample_health",
            "instructions": "Sample manifest guidance.",
            "tools": [
                {
                    "name": "sample_search",
                    "description": "sample_search description",
                    "category": "search-analysis",
                    "recommended_phase": "ANALYZE",
                    "health": False,
                    "when_to_use": "use sample_search",
                    "avoid_when": "avoid sample_search",
                    "output_notes": "notes sample_search",
                },
                {
                    "name": "sample_health",
                    "description": "sample_health description",
                    "category": "search-analysis",
                    "recommended_phase": "ANALYZE",
                    "health": True,
                    "when_to_use": "use sample_health",
                    "avoid_when": "avoid sample_health",
                    "output_notes": "notes sample_health",
                },
            ],
        }
    ]
    assert guide["unavailable_backends"] == [
        {
            "backend": "gated-addon",
            "status": "unavailable",
            "unmet_requires": ["unknown:req"],
        }
    ]
    assert "sample_hidden" not in json.dumps(guide)
    assert "gated-addon" not in json.dumps(guide["available_backends"])


def test_all_shipped_manifests_validate_with_guidance_fields():
    paths = _manifest_paths()
    assert {path.parent.name for path in paths} == {
        "forensic-rag-mcp",
        "opencti-mcp",
        "opensearch-mcp",
        "windows-triage-mcp",
    }

    for path in paths:
        manifest = load_and_validate_manifest(
            path.parent.name,
            {"type": "stdio", "command": "true", "manifest_path": str(path)},
        )
        assert manifest is not None
        assert manifest.get("instructions") or manifest.get("_resolved_instructions")
        for tool in manifest["tools"]:
            assert tool.get("when_to_use")


def test_opensearch_is_not_reference_but_other_reference_manifests_drive_grounding():
    manifests = []
    for path in _manifest_paths():
        manifests.append(
            load_and_validate_manifest(
                path.parent.name,
                {"type": "stdio", "command": "true", "manifest_path": str(path)},
            )
        )

    gateway = _gateway_with_fake_backends(*manifests)

    reference_backends = set(gateway.get_reference_backends())
    assert reference_backends == {
        "forensic-rag-mcp",
        "opencti-mcp",
        "windows-triage-mcp",
    }
    assert "opensearch-mcp" not in reference_backends


def test_tools_list_annotations_derive_from_manifest_metadata():
    gateway = _gateway_with_fake_backends(_manifest())
    server = create_mcp_server(gateway)
    handler = server.request_handlers.get(ListToolsRequest)
    assert handler is not None

    result = asyncio.run(handler(ListToolsRequest()))
    list_result = result.root if hasattr(result, "root") else result
    tools = {tool.name: tool for tool in list_result.tools}

    sample = tools["sample_search"]
    assert sample.meta["category"] == "search-analysis"
    assert sample.meta["recommended_for_phase"] == "ANALYZE"
    assert "sample_hidden" not in tools


def test_environment_summary_health_tools_are_manifest_driven():
    gateway = _gateway_with_fake_backends(_manifest())
    gateway.call_tool = AsyncMock(
        side_effect=[
            [TextContent(type="text", text='{"case": "ok"}')],
            [TextContent(type="text", text='{"evidence": "ok"}')],
            [TextContent(type="text", text='{"tools": "ok"}')],
            [TextContent(type="text", text='{"sample": "healthy"}')],
        ]
    )

    contents = asyncio.run(_handle_environment_summary(gateway))
    summary = json.loads(contents[0].text)

    assert [call.args for call in gateway.call_tool.call_args_list] == [
        ("case_status", {}),
        ("evidence_list", {}),
        ("list_available_tools", {}),
        ("sample_health", {}),
    ]
    assert summary["backends"]["sample-addon"]["tool"] == "sample_health"
    assert summary["backends"]["sample-addon"]["result"] == {"sample": "healthy"}


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


def test_manifest_missing_hard_rejects(tmp_path):
    with pytest.raises(ValueError, match="manifest is missing/invalid"):
        load_and_validate_manifest(
            "missing-addon",
            {
                "type": "stdio",
                "command": "true",
                "manifest_path": str(tmp_path / "missing-sift-backend.json"),
            },
        )


def _rest_client(gateway: Gateway) -> TestClient:
    app = Starlette(
        routes=rest_routes(),
        middleware=[Middleware(AuthMiddleware, api_keys={})],
    )
    app.state.gateway = gateway
    return TestClient(app)


def test_backends_validate_route_pass_and_fail():
    gateway = Gateway({"backends": {}, **_execute_security()})
    client = _rest_client(gateway)

    good = client.post(
        "/api/v1/backends/validate",
        json={"name": "sample-addon", "manifest": _manifest()},
    )
    assert good.status_code == 200
    assert good.json()["valid"] is True
    assert good.json()["namespace"] == "sample"
    assert good.json()["available"] is True

    bad_manifest = _manifest()
    bad_manifest["tools"][0]["recommended_phase"] = "TRIAGE"
    bad = client.post(
        "/api/v1/backends/validate",
        json={"name": "bad-addon", "manifest": bad_manifest},
    )
    assert bad.status_code == 422
    payload = bad.json()
    assert payload["valid"] is False
    assert any("recommended_phase" in reason["field"] for reason in payload["reasons"])


def test_register_route_rejects_nonconformant_manifest_without_exposing_tools(tmp_path, monkeypatch):
    config_path = tmp_path / "gateway.yaml"
    monkeypatch.setenv("SIFT_GATEWAY_CONFIG", str(config_path))
    gateway = Gateway({"backends": {}, **_execute_security()})
    client = _rest_client(gateway)

    bad_manifest = _manifest()
    bad_manifest["tools"][0]["name"] = "bad_search"
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")

    response = client.post(
        "/api/v1/backends",
        json={
            "name": "sample-addon",
            "config": {
                "type": "stdio",
                "command": "true",
                "manifest_path": str(manifest_path),
            },
        },
    )

    assert response.status_code == 422
    assert response.json()["registered"] is False
    assert "sample_search" not in gateway._tool_map
    assert not config_path.exists()


def test_register_route_keeps_gated_backend_unavailable(tmp_path, monkeypatch):
    config_path = tmp_path / "gateway.yaml"
    monkeypatch.setenv("SIFT_GATEWAY_CONFIG", str(config_path))
    manifest = _manifest(requires=["unknown:req"])
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    gateway = Gateway({"backends": {}, **_execute_security()})
    client = _rest_client(gateway)

    response = client.post(
        "/api/v1/backends",
        json={
            "name": "sample-addon",
            "config": {
                "type": "stdio",
                "command": "true",
                "manifest_path": str(manifest_path),
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["registered"] is True
    assert payload["available"] is False
    assert payload["unmet_requires"] == ["unknown:req"]
    assert "sample_search" not in gateway._tool_map
    assert "sample-addon" not in gateway._available_backends


def test_gateway_core_has_no_hardcoded_addon_names():
    src_root = Path(__file__).resolve().parents[1] / "src" / "sift_gateway"
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in src_root.rglob("*.py")
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
