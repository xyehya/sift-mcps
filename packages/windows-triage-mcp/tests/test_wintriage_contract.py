"""Windows Triage MCP add-on contract enforcement tests.

Verifies:
- sift-backend.json declares non-authoritative / query-only / prohibited ops
- All canonical tools in the registry have readOnlyHint=True and destructiveHint=False
- No mutation function is registered in REGISTRY
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


def test_registry_all_canonical_tools_read_only_annotation():
    """All canonical registered tools must have readOnlyHint=True and destructiveHint=False."""
    from windows_triage_mcp.registry import REGISTRY

    for tool_def in REGISTRY:
        ann = tool_def.annotations
        assert ann.readOnlyHint is True, (
            f"tool {tool_def.name!r} must have readOnlyHint=True"
        )
        assert ann.destructiveHint is False, (
            f"tool {tool_def.name!r} must have destructiveHint=False"
        )


def test_registry_no_mutation_tool_names():
    """No canonical tool name should suggest mutation, case creation, or evidence sealing."""
    from windows_triage_mcp.registry import REGISTRY

    forbidden_prefixes = (
        "create_", "update_", "delete_", "write_", "seal_",
        "approve_", "reject_", "register_", "post_", "patch_",
    )
    for tool_def in REGISTRY:
        for prefix in forbidden_prefixes:
            assert not tool_def.name.startswith(prefix), (
                f"Windows Triage tool {tool_def.name!r} looks like a mutation tool"
            )


def test_registry_tool_count_matches_backend_json():
    """Canonical tool count in registry must match sift-backend.json."""
    from windows_triage_mcp.registry import REGISTRY

    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    backend_tool_names = {t["name"] for t in data["tools"]}
    registry_tool_names = {t.name for t in REGISTRY}
    assert registry_tool_names == backend_tool_names, (
        f"Registry tools {registry_tool_names} must match sift-backend.json tools {backend_tool_names}"
    )
