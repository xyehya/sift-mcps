"""forensic-knowledge loader tests.

Covers:
- Loader returns data for canonical knowledge categories
- Path traversal protection in _sanitize_name
- Non-authoritative contract: loader has no mutation, case, or evidence APIs
- sift-backend.json contract fields are present and correct
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import forensic_knowledge.loader as loader


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIFT_BACKEND_JSON = Path(__file__).resolve().parents[1] / "sift-backend.json"


@pytest.fixture(autouse=True)
def _clear_cache():
    """Ensure each test starts with a clean loader cache."""
    loader.clear_cache()
    yield
    loader.clear_cache()


# ---------------------------------------------------------------------------
# sift-backend.json contract tests
# ---------------------------------------------------------------------------


def test_sift_backend_json_exists():
    assert SIFT_BACKEND_JSON.exists(), "sift-backend.json must exist for Gateway registry awareness"


def test_sift_backend_json_non_authoritative():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    contract = data.get("authority_contract", {})
    assert contract.get("non_authoritative") is True, "must declare non_authoritative: true"
    assert contract.get("plane") == "reference", "must declare plane: reference"
    assert contract.get("query_only") is True, "must declare query_only: true"


def test_sift_backend_json_prohibited_operations_present():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    prohibited = data.get("authority_contract", {}).get("prohibited_operations", [])
    assert isinstance(prohibited, list), "prohibited_operations must be a list"
    assert len(prohibited) >= 5, "prohibited_operations must be non-trivial"
    # Core authority operations must be explicitly prohibited
    for op in ("create_case", "seal_evidence", "approve_finding", "approve_report", "bypass_gateway"):
        assert op in prohibited, f"prohibited_operations must include {op!r}"


def test_sift_backend_json_standalone_server_false():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    caps = data.get("capabilities", {})
    assert caps.get("standalone_server") is False, "forensic-knowledge is a library, not a server"


def test_sift_backend_json_tier_addon():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    assert data.get("tier") == "addon"
    assert data.get("transport") == "library"


def test_sift_backend_json_authority_disclaimer_present():
    data = json.loads(SIFT_BACKEND_JSON.read_text(encoding="utf-8"))
    disclaimer = data.get("authority_contract", {}).get("authority_disclaimer", "")
    assert len(disclaimer) > 20, "authority_disclaimer must be a non-empty descriptive string"


# ---------------------------------------------------------------------------
# Artifact loader tests
# ---------------------------------------------------------------------------


def test_get_artifact_known():
    """amcache is a well-known Windows artifact."""
    result = loader.get_artifact("amcache")
    assert result is not None, "amcache artifact must exist"
    assert isinstance(result, dict)
    # Minimal required fields
    assert "name" in result or "description" in result


def test_get_artifact_unknown_returns_none():
    result = loader.get_artifact("does_not_exist_xyz")
    assert result is None


def test_get_artifact_path_traversal_rejected():
    with pytest.raises(ValueError, match="Invalid name"):
        loader.get_artifact("../etc/passwd")


def test_list_artifacts_returns_list():
    arts = loader.list_artifacts()
    assert isinstance(arts, list)
    assert len(arts) > 0, "must return at least some artifacts"


def test_list_artifacts_platform_filter():
    windows_arts = loader.list_artifacts(platform="windows")
    assert isinstance(windows_arts, list)
    assert len(windows_arts) > 0, "windows artifacts must exist"


def test_artifact_catalog_has_ids():
    catalog = loader.artifact_catalog(platform="windows")
    assert isinstance(catalog, list)
    assert len(catalog) > 0
    for entry in catalog:
        assert "id" in entry
        assert "name" in entry
        assert "platform" in entry


def test_artifact_catalog_id_roundtrip():
    """IDs in catalog must be usable with get_artifact."""
    catalog = loader.artifact_catalog(platform="windows")
    assert catalog, "must have at least one windows artifact"
    first = catalog[0]
    artifact = loader.get_artifact(first["id"])
    assert artifact is not None, f"get_artifact({first['id']!r}) must return data when id comes from catalog"


# ---------------------------------------------------------------------------
# Tool loader tests
# ---------------------------------------------------------------------------


def test_list_tools_returns_list():
    tools = loader.list_tools()
    assert isinstance(tools, list)
    assert len(tools) > 0, "must return at least some tools"


def test_list_tools_entries_have_required_keys():
    tools = loader.list_tools()
    for tool in tools[:5]:
        assert "name" in tool
        assert "category" in tool


def test_get_tool_unknown_returns_none():
    result = loader.get_tool("nonexistent_tool_xyz_123")
    assert result is None


# ---------------------------------------------------------------------------
# Discipline loader tests
# ---------------------------------------------------------------------------


def test_get_rules_returns_list():
    rules = loader.get_rules()
    assert isinstance(rules, list)
    assert len(rules) > 0, "discipline rules must exist"


def test_get_confidence_definitions_returns_dict():
    conf = loader.get_confidence_definitions()
    assert isinstance(conf, dict)
    assert len(conf) > 0, "confidence definitions must exist"


def test_get_anti_patterns_returns_list():
    patterns = loader.get_anti_patterns()
    assert isinstance(patterns, list)
    assert len(patterns) > 0, "anti-patterns must exist"


def test_get_evidence_standards_returns_dict():
    standards = loader.get_evidence_standards()
    assert isinstance(standards, dict)


def test_get_evidence_template_returns_dict():
    template = loader.get_evidence_template()
    assert isinstance(template, dict)


def test_list_playbooks_returns_list():
    playbooks = loader.list_playbooks()
    assert isinstance(playbooks, list)
    assert len(playbooks) > 0, "playbooks must exist"


def test_list_playbook_slugs_matches_list():
    slugs = loader.list_playbook_slugs()
    listed = loader.list_playbooks()
    assert len(slugs) == len(listed), "slug count and list count should match"


def test_get_playbook_known():
    """credential_access is a known playbook slug."""
    result = loader.get_playbook("credential_access")
    assert result is not None, "credential_access playbook must exist"
    assert isinstance(result, dict)


def test_get_playbook_unknown_returns_none():
    result = loader.get_playbook("nonexistent_playbook_xyz")
    assert result is None


def test_get_playbook_path_traversal_rejected():
    with pytest.raises(ValueError, match="Invalid name"):
        loader.get_playbook("../../etc/shadow")


def test_list_checkpoints_returns_list():
    checkpoints = loader.list_checkpoints()
    assert isinstance(checkpoints, list)


def test_list_collection_checklists_returns_list():
    checklists = loader.list_collection_checklists()
    assert isinstance(checklists, list)
    assert len(checklists) > 0, "collection checklists must exist"


def test_get_collection_checklist_known():
    """event_logs is a known checklist."""
    result = loader.get_collection_checklist("event_logs")
    assert result is not None, "event_logs checklist must exist"


def test_get_collection_checklist_path_traversal_rejected():
    with pytest.raises(ValueError, match="Invalid name"):
        loader.get_collection_checklist("../etc/shadow")


# ---------------------------------------------------------------------------
# Non-authoritative contract: no mutation APIs exist in loader
# ---------------------------------------------------------------------------


def test_loader_has_no_mutation_apis():
    """The loader module must not expose any case/evidence mutation functions."""
    import inspect

    mutation_patterns = (
        "create_case",
        "seal_evidence",
        "approve_finding",
        "approve_report",
        "register_evidence",
        "bypass_gateway",
        "write_",
        "update_",
        "delete_",
        "post_",
        "patch_",
    )
    public_fns = [
        name for name, obj in inspect.getmembers(loader, inspect.isfunction)
        if not name.startswith("_")
    ]
    for fn_name in public_fns:
        for pattern in mutation_patterns:
            assert not fn_name.startswith(pattern) and pattern not in fn_name, (
                f"loader.{fn_name} looks like a mutation API — forensic-knowledge is read-only reference data"
            )
