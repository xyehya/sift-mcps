"""OpenCTI MCP add-on contract enforcement tests.

Verifies:
- sift-backend.json declares non-authoritative / query-only / prohibited ops
- All tools in the registry have readOnlyHint=True and evidence_class=read_only
- No tool has destructiveHint=True
- No mutation function is registered in the REGISTRY
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

SIFT_BACKEND_JSON = Path(__file__).resolve().parents[1] / "sift-backend.json"


# ---------------------------------------------------------------------------
# sift-backend.json contract
# ---------------------------------------------------------------------------


def test_sift_backend_json_exists():
    assert SIFT_BACKEND_JSON.exists()


def test_sift_backend_json_non_authoritative():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    contract = data["authority_contract"]
    assert contract["non_authoritative"] is True
    assert contract["plane"] == "reference"
    assert contract["query_only"] is True


def test_sift_backend_json_prohibited_operations():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    prohibited = data["authority_contract"]["prohibited_operations"]
    for op in ("create_case", "seal_evidence", "approve_finding", "approve_report", "bypass_gateway"):
        assert op in prohibited, f"prohibited_operations must include {op!r}"


def test_sift_backend_json_authority_disclaimer():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    disclaimer = data["authority_contract"]["authority_disclaimer"]
    assert len(disclaimer) > 20


def test_sift_backend_json_all_tools_read_only():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    for tool in data["tools"]:
        assert tool.get("read_only") is True, f"tool {tool['name']!r} must have read_only: true"
        assert tool.get("readOnlyHint") is True, f"tool {tool['name']!r} must have readOnlyHint: true"
        assert tool.get("evidence_class") == "read_only", (
            f"tool {tool['name']!r} must have evidence_class: read_only"
        )


def test_sift_backend_json_all_tools_have_required_scopes():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    for tool in data["tools"]:
        scopes = tool.get("required_scopes", [])
        assert isinstance(scopes, list) and len(scopes) > 0, (
            f"tool {tool['name']!r} must declare required_scopes"
        )


# ---------------------------------------------------------------------------
# Registry-level contract (Python objects)
# ---------------------------------------------------------------------------


def test_registry_all_tools_read_only_annotation():
    """All registered tools must have readOnlyHint=True and destructiveHint=False."""
    from opencti_mcp.registry import REGISTRY

    for tool_def in REGISTRY:
        ann = tool_def.annotations
        assert ann.readOnlyHint is True, (
            f"tool {tool_def.name!r} must have readOnlyHint=True"
        )
        assert ann.destructiveHint is False, (
            f"tool {tool_def.name!r} must have destructiveHint=False"
        )


def test_registry_no_mutation_tool_names():
    """No tool name should suggest mutation, case creation, or evidence sealing."""
    from opencti_mcp.registry import REGISTRY

    forbidden_prefixes = (
        "create_", "update_", "delete_", "write_", "seal_",
        "approve_", "reject_", "register_", "post_", "patch_",
    )
    for tool_def in REGISTRY:
        for prefix in forbidden_prefixes:
            assert not tool_def.name.startswith(prefix), (
                f"OpenCTI tool {tool_def.name!r} looks like a mutation tool — "
                f"only query-only tools are allowed"
            )


def test_registry_tool_catalog_meta_evidence_class():
    """All tool catalog entries must mark evidence_class as read_only."""
    from opencti_mcp.registry import TOOL_CATALOG_META

    for tool_key, meta in TOOL_CATALOG_META.items():
        assert meta.get("evidence_class") == "read_only", (
            f"TOOL_CATALOG_META[{tool_key!r}] must have evidence_class: read_only"
        )
        assert meta.get("case_scoped") is False, (
            f"TOOL_CATALOG_META[{tool_key!r}] must have case_scoped: False (reference plane)"
        )


def test_registry_function_count_matches_backend_json():
    """Tool count in registry must match tool count in sift-backend.json."""
    from opencti_mcp.registry import REGISTRY

    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    backend_tool_names = {t["name"] for t in data["tools"]}
    registry_tool_names = {t.name for t in REGISTRY}
    assert registry_tool_names == backend_tool_names, (
        f"Registry tools {registry_tool_names} must match sift-backend.json tools {backend_tool_names}"
    )


# ---------------------------------------------------------------------------
# BATCH-AD2: manifest provably conforms to the gateway Backend Contract end to
# end — it validates through the SAME loader the registration door uses, its
# namespace is consistent, and the gateway derives a query-only, scope-gated,
# non-authoritative authority profile from it.
# ---------------------------------------------------------------------------


def test_manifest_validates_through_gateway_loader():
    """The shipped manifest passes the gateway's load_and_validate_manifest —
    the exact path the portal/REST registration door runs. This is stronger
    than field-by-field assertions: it proves schema + cross-field contract."""
    from sift_gateway.backends import load_and_validate_manifest

    loaded = load_and_validate_manifest(
        "opencti-mcp",
        {"type": "stdio", "command": "true", "manifest_path": str(SIFT_BACKEND_JSON)},
    )
    assert loaded is not None
    assert loaded["namespace"] == "cti"


def test_manifest_namespace_consistent_with_every_tool():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    ns = data["namespace"]
    assert ns
    for tool in data["tools"]:
        assert tool["name"].startswith(f"{ns}_"), (
            f"tool {tool['name']!r} must start with namespace prefix {ns}_"
        )


def test_manifest_declares_standard_non_authoritative_prohibited_operations():
    """Per spec §2.5, a non-authoritative add-on declares the full standard
    prohibited-operations set. OpenCTI is the reference add-on; it must carry
    all of them so the gateway denies any authority operation fail-closed."""
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    prohibited = set(data["authority_contract"]["prohibited_operations"])
    standard = {
        "create_case",
        "activate_case",
        "seal_evidence",
        "register_evidence",
        "approve_finding",
        "reject_finding",
        "approve_report",
        "include_in_report",
        "issue_agent_credential",
        "bypass_gateway",
    }
    missing = standard - prohibited
    assert not missing, f"non-authoritative add-on missing prohibited ops: {sorted(missing)}"


def test_manifest_uses_no_raw_secret_fields():
    """The manifest must never carry raw secrets — secrets are supplied via
    env_refs in the connection config (resolved from gateway env), never in
    sift-backend.json. Guard the whole file text."""
    text = SIFT_BACKEND_JSON.read_text(encoding="utf-8")
    lowered = text.lower()
    for forbidden in ("token", "password", "api_key", "secret", "bearer"):
        # 'token' may legitimately appear in prose; assert no JSON key uses it.
        assert f'"{forbidden}"' not in lowered, (
            f"manifest must not declare a raw {forbidden!r} field"
        )


def test_gateway_derives_query_only_scope_gated_authority_profile():
    """The gateway, after building its tool map from the shipped manifest,
    exposes a per-tool authority profile that is non-authoritative, carries the
    cti:read required scope, and inherits the prohibited-operation set."""
    import asyncio

    from sift_gateway.server import Gateway

    manifest = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))

    class _FakeBackend:
        started = False

        def __init__(self, m):
            self.manifest = m
            self.config = {"type": "stdio", "command": "true"}
            self.enabled = True

    gateway = Gateway(
        {"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}}
    )
    gateway.backends["opencti-mcp"] = _FakeBackend(manifest)
    asyncio.run(gateway._build_tool_map())

    profile = gateway.addon_authority_for_tool("cti_search_threat_intel")
    assert profile is not None
    assert profile["non_authoritative"] is True
    assert profile["required_scopes"] == ["cti:read"]
    assert "seal_evidence" in profile["prohibited_operations"]
    assert "bypass_gateway" in profile["prohibited_operations"]
