import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

from sift_gateway.backends import load_and_validate_manifest
from sift_gateway.auth import AuthMiddleware
from sift_gateway.mcp_endpoint import (
    _capability_guide,
)
from sift_gateway.mcp_server import (
    GatewayToolCatalogMiddleware,
    assert_mounted_tool_names,
    expected_mounted_tool_names,
    _stdio_transport,
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
        self.config = {"type": manifest.get("transport", "stdio"), "command": "true"}
        self.enabled = True

    async def health_check(self):
        return {"status": "ok"}


class _FakeRegistry:
    def __init__(self):
        self.registered = []
        self.unregistered = []

    def register(self, *, name, config, manifest, actor=None):
        del actor
        self.registered.append((name, config, manifest))
        return type("Record", (), {"id": f"id-{name}", "name": name})()

    def unregister(self, name, *, actor=None):
        del actor
        self.unregistered.append(name)

    def list_backends(self):
        return []


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _manifest_paths() -> list[Path]:
    # Enumerate routable backend manifests only. Library add-ons (transport
    # "library" / standalone_server=false, e.g. forensic-knowledge) ship a
    # sift-backend.json to declare their authority contract but are imported
    # in-process and are not routable MCP backends.
    paths = []
    for path in sorted((_repo_root() / "packages").glob("*/sift-backend.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            paths.append(path)
            continue
        capabilities = data.get("capabilities")
        standalone = (
            capabilities.get("standalone_server", True)
            if isinstance(capabilities, dict)
            else True
        )
        if data.get("transport") == "library" or standalone is False:
            continue
        paths.append(path)
    return paths


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
        "core_tools",
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


def test_capability_guide_core_tools_section_compact_cached_no_paths():
    """AUT2-B8: capability_guide carries a cached core-tool availability summary."""
    import sift_gateway.mcp_endpoint as mcp_endpoint
    from sift_core.execute.tools import discovery as core_discovery

    mcp_endpoint._CORE_TOOLS_SUMMARY = None
    core_discovery._INVENTORY_CACHE = None
    try:
        gateway = Gateway({"backends": {}, **_execute_security()})
        guide = _capability_guide(gateway)
        core = guide["core_tools"]

        assert set(core) == {
            "total_cataloged",
            "total_available",
            "available_by_category",
            "missing",
            "hint",
        }
        assert core["total_cataloged"] >= core["total_available"] >= 0
        available_names = [
            name
            for names in core["available_by_category"].values()
            for name in names
        ]
        assert len(available_names) == core["total_available"]
        assert len(core["missing"]) == core["total_cataloged"] - core["total_available"]
        assert "get_tool_help('inventory')" in core["hint"]

        # Never leak absolute binary paths to the agent.
        rendered = json.dumps(core)
        assert "/usr/" not in rendered and "/opt/" not in rendered
        for name in available_names + core["missing"]:
            assert not name.startswith("/")

        # Cached per-process: a second guide reuses the same summary object
        # instead of re-probing binary availability.
        assert _capability_guide(gateway)["core_tools"] is core
    finally:
        mcp_endpoint._CORE_TOOLS_SUMMARY = None
        core_discovery._INVENTORY_CACHE = None
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
    mcp = FastMCP("test", middleware=[GatewayToolCatalogMiddleware(gateway)])

    @mcp.tool(name="sample_search")
    def sample_search():
        return "ok"

    @mcp.tool(name="sample_hidden")
    def sample_hidden():
        return "hidden"

    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}

    sample = tools["sample_search"]
    assert sample.meta["category"] == "search-analysis"
    assert sample.meta["recommended_for_phase"] == "ANALYZE"
    assert "sample_hidden" not in tools


def test_capability_guide_health_tools_are_manifest_driven():
    gateway = _gateway_with_fake_backends(_manifest())

    guide = _capability_guide(gateway)

    assert guide["available_backends"][0]["health_tool"] == "sample_health"


def test_expected_mounted_tool_names_are_manifest_driven():
    gateway = _gateway_with_fake_backends(_manifest())

    assert expected_mounted_tool_names(gateway) == {
        "sample_search",
        "sample_health",
        "sample_hidden",
    }


def test_mounted_tool_name_assertion_detects_missing_proxy_tool():
    mcp = FastMCP("test")

    with pytest.raises(ValueError, match="sample_search"):
        asyncio.run(assert_mounted_tool_names(mcp, {"sample_search"}))


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
    gateway.mcp_backend_registry = _FakeRegistry()
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
    assert gateway.mcp_backend_registry.registered[0][0] == "sample-addon"


def test_unregister_route_deletes_registry_row_and_requires_restart():
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.mcp_backend_registry = _FakeRegistry()
    client = _rest_client(gateway)

    response = client.delete("/api/v1/backends/sample-addon")

    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "unregistered": True,
        "name": "sample-addon",
        "status": "unregistered_pending_restart",
        "pending_apply": True,
        "restart_required": True,
    }
    assert gateway.mcp_backend_registry.unregistered == ["sample-addon"]


def test_stdio_proxy_env_does_not_inherit_unreferenced_process_secrets(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("SIFT_BACKEND_SECRET", "raw-secret")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")

    transport = _stdio_transport(
        {
            "type": "stdio",
            "command": "true",
            "env": {"BACKEND_TOKEN": "resolved-secret"},
        }
    )

    assert transport.env["PATH"] == "/usr/bin"
    assert transport.env["LC_ALL"] == "C.UTF-8"
    assert transport.env["BACKEND_TOKEN"] == "resolved-secret"
    assert "SIFT_BACKEND_SECRET" not in transport.env


def test_gateway_core_has_no_hardcoded_addon_names():
    # This invariant disciplines EXTERNAL/third-party MCP add-on backends so they
    # plug into the modular schema-registered surface without the gateway core
    # ever knowing them by name (naming convention, no-execute, conflict-free).
    # OpenSearch is intentionally EXEMPT: it is a first-party/core capability, so
    # the gateway is allowed to reference it directly (e.g. the job-backed ingest
    # policy shadow in job_tools.py). The forbidden list therefore covers only the
    # external extensions (OpenCTI, windows-triage, forensic-rag/KB) that the
    # add-on schema contract is designed for.
    src_root = Path(__file__).resolve().parents[1] / "src" / "sift_gateway"
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in src_root.rglob("*.py")
    )
    forbidden = [
        "wintriage",
        "cti_",
        "kb_",
        "forensic-rag",
        "opencti",
        "windows-triage",
    ]
    assert [name for name in forbidden if name in combined] == []
