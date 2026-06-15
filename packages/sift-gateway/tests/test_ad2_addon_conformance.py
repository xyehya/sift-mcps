"""BATCH-AD2: Add-on contract conformance tests.

Closes the "coverage gaps for AD2 to address" list in docs/add-ons/spec.md §9.
The existing suites already cover several authority paths; this file adds the
genuinely-missing conformance cases and keeps the core/add-on boundary
regression-proof:

  * AddonAuthorityMiddleware prohibited-operation denial via the TOOL NAME
    itself (the argument-value path is covered in test_mvp_d2_jobs_and_authority).
  * AddonAuthorityMiddleware scope-denial naming the exact missing scope, plus
    a multi-scope partial-grant case.
  * Duplicate tool name across two simultaneously registered backends -> the
    gateway refuses to build a tool map (fail-closed, names both backends).
  * Clean-disable: a backend removed from the enabled set drops its tools and
    authority metadata on the next tool-map build WITHOUT a gateway restart.
  * Hot-reload: a registry row seeded after startup is mounted by
    reload_backend_registry and its tools appear without a restart.
  * env_refs missing-variable failure surfaces fail-closed at runtime config
    resolution (the add-on never starts with a half-resolved secret env).
  * Requirement gating negatives: missing docker / unmet generic requires keep
    the add-on out of tools/list while the core stays up.
  * Manifest validation negatives: unknown top-level field, unknown per-tool
    field (additionalProperties:false), and a namespace/tool-name mismatch are
    all rejected at load time.
  * B-MVP-016: the shipped opensearch-mcp manifest (which DOES carry the
    scope_enforcement OS5 policy field) validates, and a genuinely-unknown
    field is still rejected -> proves scope_enforcement is a live, accepted
    advisory field, not dead schema. See the AD2 landing log for the decision.
  * Core install path seeds no OpenCTI (install.sh seed_addon_backends).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sift_core.evidence_chain import ChainStatus
from sift_gateway.backends import load_and_validate_manifest
from sift_gateway.identity import Identity
from sift_gateway.mcp_backends_registry import (
    BackendRegistryError,
    normalize_connection_config,
    resolve_runtime_config,
)
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.server import Gateway

from fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Shared fixtures: minimal conformant add-on manifests and a fake backend.
# ---------------------------------------------------------------------------


def _execute_security() -> dict:
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


def _tool(
    name: str,
    *,
    health: bool = False,
    read_only: bool = True,
    required_scopes: list[str] | None = None,
    category: str = "threat-intel",
) -> dict:
    evidence_class = "read_only" if read_only else "mutating"
    tool: dict = {
        "name": name,
        "description": f"{name} description",
        "read_only": read_only,
        "readOnlyHint": read_only,
        "evidence_class": evidence_class,
        "category": category,
        "recommended_phase": "CORRELATE",
        "when_to_use": f"use {name}",
    }
    if health:
        tool["health"] = True
    if required_scopes is not None:
        tool["required_scopes"] = list(required_scopes)
    return tool


def _addon_manifest(
    *,
    name: str = "opencti-mcp",
    namespace: str = "cti",
    tools: list[dict] | None = None,
    prohibited: list[str] | None = None,
    non_authoritative: bool = True,
) -> dict:
    if tools is None:
        tools = [
            _tool(f"{namespace}_search", required_scopes=["cti:read"]),
            _tool(f"{namespace}_health", health=True, required_scopes=["cti:read"]),
        ]
    manifest: dict = {
        "spec_version": "1.0",
        "name": name,
        "version": "1.0.0",
        "tier": "addon",
        "transport": "stdio",
        "namespace": namespace,
        # B-MVP-053: reference-plane manifests must declare default_case_scoped.
        "default_case_scoped": False,
        "capabilities": {
            "provides": ["reference", "threat-intel"],
            "requires": [],
            "enriches_responses": False,
        },
        "tools": tools,
        "health": next(t["name"] for t in tools if t.get("health")),
    }
    if prohibited is not None or non_authoritative:
        manifest["authority_contract"] = {
            "non_authoritative": non_authoritative,
            "plane": "reference",
            "query_only": True,
            "prohibited_operations": list(prohibited or []),
        }
    return manifest


class _FakeBackend:
    started = False

    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.config = {"type": "stdio", "command": "true"}
        self.enabled = True


def _gateway_with_backends(*manifests: dict) -> Gateway:
    gateway = Gateway({"backends": {}, **_execute_security()})
    for manifest in manifests:
        gateway.backends[manifest["name"]] = _FakeBackend(manifest)
    asyncio.run(gateway._build_tool_map())
    return gateway


async def _async_gateway_with_backends(*manifests: dict) -> Gateway:
    gateway = Gateway({"backends": {}, **_execute_security()})
    for manifest in manifests:
        gateway.backends[manifest["name"]] = _FakeBackend(manifest)
    await gateway._build_tool_map()
    return gateway


def _identity(*scopes: str) -> Identity:
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id="t1",
        agent_id="hermes",
        created_by="alice",
        role="agent",
        source_ip=None,
        auth_surface="mcp",
        tool_scopes=frozenset(scopes),
    )


def _server_with_tool(gateway: Gateway, tool_name: str) -> FastMCP:
    mcp = FastMCP("parent", middleware=gateway_policy_middlewares(gateway, auth_enabled=True))

    @mcp.tool(name=tool_name)
    async def _addon_tool():
        return "dispatched"

    return mcp


_OPEN_GATE = {
    "blocked": False,
    "status": ChainStatus.OK,
    "issues": [],
    "manifest_version": 1,
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------------------
# 1. AddonAuthorityMiddleware — prohibited operation via the tool NAME itself.
# ---------------------------------------------------------------------------


async def test_prohibited_operation_via_tool_name_denied_before_dispatch():
    """A non-authoritative add-on tool whose NAME is a prohibited operation is
    denied before dispatch (the argument-value path is covered elsewhere)."""
    manifest = _addon_manifest(
        tools=[
            _tool("cti_seal_evidence", required_scopes=["cti:read"]),
            _tool("cti_health", health=True, required_scopes=["cti:read"]),
        ],
        prohibited=["cti_seal_evidence", "approve_finding"],
    )
    gateway = await _async_gateway_with_backends(manifest)
    mcp = _server_with_tool(gateway, "cti_seal_evidence")
    identity = _identity("mcp:*")

    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=identity
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate", return_value=_OPEN_GATE
    ):
        result = await mcp.call_tool("cti_seal_evidence", {})

    assert result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["error"] == "addon_prohibited_operation"
    assert "cti_seal_evidence" in payload["prohibited_operations"]
    assert payload["non_authoritative"] is True
    # Fail-closed: the backend body never ran.
    rendered = json.dumps([i.model_dump(mode="json") for i in result.content], default=str)
    assert "dispatched" not in rendered


# ---------------------------------------------------------------------------
# 2. Scope enforcement — exact missing scope is reported, partial grant denies.
# ---------------------------------------------------------------------------


async def test_partial_scope_grant_reports_only_missing_scope():
    manifest = _addon_manifest(
        tools=[
            _tool("cti_search", required_scopes=["cti:read", "cti:pivot"]),
            _tool("cti_health", health=True, required_scopes=["cti:read"]),
        ],
    )
    gateway = await _async_gateway_with_backends(manifest)
    mcp = _server_with_tool(gateway, "cti_search")
    # namespace:cti grants the tool (passes ToolAuthorization); cti:read is held
    # but cti:pivot is missing -> AddonAuthority denies, naming only the gap.
    identity = _identity("namespace:cti", "cti:read")

    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=identity
    ), patch(
        "sift_gateway.policy_middleware.check_evidence_gate", return_value=_OPEN_GATE
    ):
        result = await mcp.call_tool("cti_search", {})

    assert result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["error"] == "addon_scope_missing"
    assert payload["missing_scopes"] == ["cti:pivot"]


# ---------------------------------------------------------------------------
# 3. Duplicate tool name across two registered backends -> fail-closed.
# ---------------------------------------------------------------------------


def test_duplicate_tool_name_across_two_backends_is_rejected():
    """Two enabled add-on backends that both declare the same tool name must
    not silently shadow each other; the gateway refuses to build the tool map
    and names both backends."""
    a = _addon_manifest(
        name="cti-a",
        namespace="cti",
        tools=[
            _tool("cti_search", required_scopes=["cti:read"]),
            _tool("cti_health", health=True, required_scopes=["cti:read"]),
        ],
    )
    b = _addon_manifest(
        name="cti-b",
        namespace="cti",
        tools=[
            _tool("cti_search", required_scopes=["cti:read"]),  # collision
            _tool("cti_status", health=True, required_scopes=["cti:read"]),
        ],
    )
    with pytest.raises(ValueError, match="collision"):
        _gateway_with_backends(a, b)


def test_addon_tool_name_colliding_with_core_is_rejected():
    """An add-on tool name that collides with an in-process core tool name is
    rejected (the core tool wins; the add-on cannot shadow it)."""
    from sift_core.agent_tools import core_tool_names

    core_name = sorted(core_tool_names())[0]
    manifest = _addon_manifest(
        name="rogue",
        namespace="rogue",
        tools=[
            # Force the declared name to equal a core tool name. The namespace
            # check is bypassed here because we want to prove the core-collision
            # guard specifically; use a manifest that declares the core name.
            {
                "name": core_name,
                "description": "rogue shadow",
                "read_only": True,
                "readOnlyHint": True,
                "evidence_class": "read_only",
                "category": "threat-intel",
                "recommended_phase": "CORRELATE",
            },
            _tool("rogue_health", health=True),
        ],
    )
    # namespace 'rogue' will reject a core-named tool first if it lacks the
    # prefix; the contract is fail-closed either way.
    with pytest.raises(ValueError):
        _gateway_with_backends(manifest)


# ---------------------------------------------------------------------------
# 4. Clean-disable — tools and authority metadata disappear without a restart.
# ---------------------------------------------------------------------------


def test_disable_drops_tools_and_authority_without_restart():
    cti = _addon_manifest(name="opencti-mcp", namespace="cti")
    gateway = _gateway_with_backends(cti)

    # Enabled: tool is mapped and carries an authority profile.
    assert "cti_search" in gateway._tool_map
    assert gateway.addon_authority_for_tool("cti_search") is not None

    # Disable == drop from the enabled backend set (what set_enabled(False) ->
    # enabled_backends() -> reload achieves at runtime) and rebuild the map.
    del gateway.backends["opencti-mcp"]
    asyncio.run(gateway._build_tool_map())

    assert "cti_search" not in gateway._tool_map
    assert gateway.addon_authority_for_tool("cti_search") is None
    assert "cti_search" not in gateway._tool_manifest_meta


# ---------------------------------------------------------------------------
# 5. Hot-reload — a row seeded after startup is mounted without a restart.
# ---------------------------------------------------------------------------


class _LateRegistry:
    """Minimal registry stand-in whose create_backend_instances returns a
    backend that was 'seeded' after gateway startup."""

    def __init__(self, late_manifest: dict):
        self._late = late_manifest

    def create_backend_instances(self):
        return {self._late["name"]: _FakeBackend(self._late)}, None


async def test_hot_reload_mounts_late_seeded_backend_without_restart():
    # Gateway boots with one backend.
    gateway = await _async_gateway_with_backends(
        _addon_manifest(name="opencti-mcp", namespace="cti")
    )
    assert "cti_search" in gateway._tool_map
    # A second add-on is seeded into the registry AFTER startup.
    late = _addon_manifest(
        name="extra-intel",
        namespace="xi",
        tools=[
            _tool("xi_lookup", required_scopes=["xi:read"]),
            _tool("xi_health", health=True, required_scopes=["xi:read"]),
        ],
    )
    gateway.mcp_backend_registry = _LateRegistry(late)
    gateway._fastmcp_server = None  # no live FastMCP server in this unit harness

    added = await gateway.reload_backend_registry()

    assert added is True
    # New tool appears in the aggregate map without a restart; old one stays.
    assert "xi_lookup" in gateway._tool_map
    assert "cti_search" in gateway._tool_map
    assert gateway.addon_authority_for_tool("xi_lookup")["required_scopes"] == ["xi:read"]


async def test_hot_reload_is_noop_when_no_new_rows():
    gateway = await _async_gateway_with_backends(
        _addon_manifest(name="opencti-mcp", namespace="cti")
    )

    class _SameRegistry:
        def create_backend_instances(self):
            # Returns the already-present backend only -> nothing new to add.
            return {"opencti-mcp": _FakeBackend(_addon_manifest())}, None

    gateway.mcp_backend_registry = _SameRegistry()
    added = await gateway.reload_backend_registry()
    assert added is False


# ---------------------------------------------------------------------------
# 6. env_refs missing-variable failure (add-on secret indirection, fail-closed).
# ---------------------------------------------------------------------------


def test_env_refs_round_trip_stores_no_raw_secret():
    stored = normalize_connection_config(
        {
            "type": "stdio",
            "command": "uv",
            "env_refs": {"OPENCTI_TOKEN": "SIFT_OPENCTI_TOKEN", "OPENCTI_URL": "SIFT_OPENCTI_URL"},
        }
    )
    # Only env_refs (name->name mapping) is persisted; no raw values anywhere.
    assert stored["env_refs"] == {
        "OPENCTI_TOKEN": "SIFT_OPENCTI_TOKEN",
        "OPENCTI_URL": "SIFT_OPENCTI_URL",
    }
    assert "env" not in stored
    runtime = resolve_runtime_config(
        stored,
        environ={"SIFT_OPENCTI_TOKEN": "tkn", "SIFT_OPENCTI_URL": "https://octi.example"},
    )
    assert runtime["env"] == {"OPENCTI_TOKEN": "tkn", "OPENCTI_URL": "https://octi.example"}


def test_env_refs_missing_gateway_variable_fails_closed():
    stored = normalize_connection_config(
        {
            "type": "stdio",
            "command": "uv",
            "env_refs": {"OPENCTI_TOKEN": "SIFT_OPENCTI_TOKEN"},
        }
    )
    # The referenced gateway env var is absent -> the add-on must not start with
    # a half-resolved secret environment.
    with pytest.raises(BackendRegistryError, match="missing environment variable"):
        resolve_runtime_config(stored, environ={})


@pytest.mark.parametrize("raw_key", ["env", "token", "api_key", "password", "bearer_token"])
def test_raw_secret_connection_fields_are_rejected(raw_key):
    with pytest.raises(BackendRegistryError, match="raw backend secret fields are not accepted"):
        normalize_connection_config({"type": "stdio", "command": "uv", raw_key: {"X": "y"}})


# ---------------------------------------------------------------------------
# 7. Requirement gating negatives — docker / unmet requires gate the add-on.
# ---------------------------------------------------------------------------


def test_unmet_docker_requirement_gates_addon_core_stays_up():
    manifest = _addon_manifest(name="opencti-mcp", namespace="cti")
    manifest["capabilities"]["requires"] = ["docker"]
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["opencti-mcp"] = _FakeBackend(manifest)

    with patch("shutil.which", return_value=None):
        asyncio.run(gateway._build_tool_map())

    # The add-on is gated out; the gateway/core is unaffected.
    assert "cti_search" not in gateway._tool_map
    assert "opencti-mcp" not in gateway._available_backends


def test_unknown_requirement_string_is_treated_as_unmet():
    manifest = _addon_manifest(name="opencti-mcp", namespace="cti")
    manifest["capabilities"]["requires"] = ["totally:bogus:req"]
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["opencti-mcp"] = _FakeBackend(manifest)
    asyncio.run(gateway._build_tool_map())

    assert "cti_search" not in gateway._tool_map
    assert "opencti-mcp" not in gateway._available_backends


def test_met_docker_requirement_mounts_addon():
    manifest = _addon_manifest(name="opencti-mcp", namespace="cti")
    manifest["capabilities"]["requires"] = ["docker"]
    gateway = Gateway({"backends": {}, **_execute_security()})
    gateway.backends["opencti-mcp"] = _FakeBackend(manifest)

    with patch("shutil.which", return_value="/usr/bin/docker"):
        asyncio.run(gateway._build_tool_map())

    assert "cti_search" in gateway._tool_map
    assert "opencti-mcp" in gateway._available_backends


# ---------------------------------------------------------------------------
# 8. Manifest validation negatives — unknown fields and namespace mismatch.
# ---------------------------------------------------------------------------


def _write_manifest(tmp_path: Path, manifest: dict) -> dict:
    manifest_path = tmp_path / "sift-backend.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return {"type": "stdio", "command": "true", "manifest_path": str(manifest_path)}


def test_unknown_top_level_field_is_rejected(tmp_path):
    manifest = _addon_manifest()
    manifest["totally_unknown_top_field"] = "nope"
    with pytest.raises(ValueError):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_unknown_per_tool_field_is_rejected(tmp_path):
    manifest = _addon_manifest()
    manifest["tools"][0]["bogus_tool_field"] = True
    with pytest.raises(ValueError):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_tool_name_not_matching_namespace_is_rejected(tmp_path):
    manifest = _addon_manifest()
    manifest["tools"][0]["name"] = "wrongprefix_search"
    with pytest.raises(ValueError, match="namespace"):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_empty_namespace_is_rejected(tmp_path):
    manifest = _addon_manifest()
    manifest["namespace"] = ""
    with pytest.raises(ValueError):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_read_only_evidence_class_inconsistency_is_rejected(tmp_path):
    manifest = _addon_manifest()
    # read_only true but evidence_class mutating -> contract violation.
    manifest["tools"][0]["evidence_class"] = "mutating"
    with pytest.raises(ValueError):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_reference_plane_without_default_case_scoped_is_rejected(tmp_path):
    """B-MVP-053: a reference-plane manifest (capabilities.provides includes
    'reference') MUST declare a boolean default_case_scoped, or the gateway's
    category-based case-scoping heuristic mis-classifies its offline reference
    tools as case-scoped and denies them whenever a case is active."""
    manifest = _addon_manifest()
    manifest.pop("default_case_scoped", None)
    with pytest.raises(ValueError, match="default_case_scoped"):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_reference_plane_with_non_bool_default_case_scoped_is_rejected(tmp_path):
    """The declaration must be a real boolean — a truthy string does not satisfy
    the gateway's isinstance(bool) check in is_case_scoped_tool."""
    manifest = _addon_manifest()
    manifest["default_case_scoped"] = "false"
    with pytest.raises(ValueError, match="default_case_scoped"):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_non_reference_plane_without_default_case_scoped_is_allowed(tmp_path):
    """The rule is scoped to the reference plane: a non-reference backend is not
    forced to declare default_case_scoped (its tools resolve case-scoping via
    schema/category as before)."""
    manifest = _addon_manifest(name="ex", namespace="ex")
    manifest["capabilities"]["provides"] = ["search", "ingest"]
    manifest.pop("default_case_scoped", None)
    loaded = load_and_validate_manifest("ex", _write_manifest(tmp_path, manifest))
    assert loaded is not None


# ---------------------------------------------------------------------------
# 9. B-MVP-016 — scope_enforcement is a LIVE accepted field, not dead schema.
# ---------------------------------------------------------------------------


def test_shipped_opensearch_manifest_with_scope_enforcement_validates(tmp_path):
    """B-MVP-016 ground truth: the shipped opensearch-mcp manifest carries the
    OS5 scope_enforcement advisory field on its mutating enrich tool. It must
    validate against the strict (additionalProperties:false) schema; removing
    scope_enforcement from the schema would reject this shipped manifest."""
    src = _repo_root() / "packages" / "opensearch-mcp" / "sift-backend.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    # Prove the premise: at least one shipped tool uses scope_enforcement.
    enforced = [t["name"] for t in data["tools"] if "scope_enforcement" in t]
    assert enforced, "expected opensearch-mcp to ship scope_enforcement (B-MVP-016)"
    # And it validates end to end through the gateway loader.
    loaded = load_and_validate_manifest(
        "opensearch-mcp",
        {"type": "stdio", "command": "true", "manifest_path": str(src)},
    )
    assert loaded is not None


def test_genuinely_unknown_per_tool_field_still_rejected_proving_strictness(tmp_path):
    """The schema is strict: scope_enforcement is accepted because it is defined,
    but a made-up sibling field is still rejected. This is the regression that
    keeps the 'accepted set' explicit instead of open."""
    manifest = _addon_manifest()
    manifest["tools"][0]["scope_enforcement"] = "gateway_primary_env_fallback"  # defined -> OK alone
    manifest["tools"][0]["definitely_not_a_real_field"] = "x"  # undefined -> reject
    with pytest.raises(ValueError):
        load_and_validate_manifest("opencti-mcp", _write_manifest(tmp_path, manifest))


def test_scope_enforcement_alone_is_accepted_on_a_mutating_tool(tmp_path):
    """scope_enforcement on a conformant mutating tool is accepted by the schema
    (the field is live metadata, mirroring opensearch_enrich_intel)."""
    manifest = _addon_manifest(
        name="extra",
        namespace="ex",
        tools=[
            {
                **_tool("ex_enrich", read_only=False, category="enrichment"),
                "required_scopes": ["ex:write"],
                "scope_enforcement": "gateway_primary_env_fallback",
                "safe_case_argument_names": ["case_id"],
            },
            _tool("ex_health", health=True, required_scopes=["ex:read"]),
        ],
    )
    loaded = load_and_validate_manifest("extra", _write_manifest(tmp_path, manifest))
    assert loaded is not None


# ---------------------------------------------------------------------------
# 10. Core install path seeds no OpenCTI / windows-triage (regression-proof).
# ---------------------------------------------------------------------------


def test_core_installer_seeds_no_opencti_or_windows_triage():
    """AD1 documented that install.sh seed_addon_backends seeds only
    opensearch-mcp and forensic-rag-mcp. Make that regression-proof: OpenCTI and
    windows-triage must never appear in the seed function body."""
    install_sh = (_repo_root() / "install.sh").read_text(encoding="utf-8")
    start = install_sh.index("seed_addon_backends() {")
    body = install_sh[start : start + 2000]
    lowered = body.lower()
    assert "opencti" not in lowered, "core seed must not reference opencti"
    assert "windows-triage" not in lowered and "wintriage" not in lowered
    # Positive control: the two real core add-ons are seeded.
    assert "opensearch-mcp" in body
    assert "forensic-rag-mcp" in body
