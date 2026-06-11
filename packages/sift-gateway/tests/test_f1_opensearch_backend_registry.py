"""BATCH-F1 / OS1: Gateway backend-registry surfaces OpenSearch derived-plane metadata.

The OpenSearch backend is a derived, rebuildable, case-scoped plane. Its
manifest declares ``default_case_scoped`` and a ``data_plane`` block; the
registry record must round-trip that metadata and expose it in the public dict
so the portal/registry can show the plane carries no authority. This test is
fenced to a new file so it does not overlap BATCH-G1 in the gateway src.

OS1 additions cover:
- Requirement gating: opensearch_* tools appear in aggregate catalog only when
  the OpenSearch TCP endpoint is reachable; they are absent (gated) otherwise.
- Disabled flag: a disabled backend is excluded from the available set and
  therefore from tools/list.
- No-raw-secret: normalize_connection_config rejects raw credentials; only
  env_refs are accepted for OpenSearch connection metadata.
- Aggregate catalog smoke: Gateway._build_tool_map populates _tool_map with
  opensearch_* names when requirements pass and leaves it empty when they fail.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from mcp.types import Tool

from sift_gateway.mcp_backends_registry import (
    BackendRegistryError,
    BackendRegistryRecord,
    manifest_sha256,
    normalize_connection_config,
)
from sift_gateway.server import Gateway

# ---------------------------------------------------------------------------
# Fixtures — shared manifest + tool set from the shipped manifest file
# ---------------------------------------------------------------------------

_MANIFEST_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "opensearch-mcp"
    / "sift-backend.json"
)
_MANIFEST = json.loads(_MANIFEST_PATH.read_text())
_OPENSEARCH_TOOLS = {t["name"] for t in _MANIFEST["tools"]}


# ---------------------------------------------------------------------------
# Fake backend class
# ---------------------------------------------------------------------------

class _FakeOSBackend:
    """A fake opensearch-mcp backend that reports started=True and lists tools."""

    def __init__(self, *, started: bool = True):
        self.started = started
        self.manifest = _MANIFEST
        self.last_tool_call: float = 0.0

    async def list_tools(self) -> list[Tool]:
        return [
            Tool(name=name, description="indexed evidence search", inputSchema={"type": "object"})
            for name in _OPENSEARCH_TOOLS
        ]

    async def stop(self) -> None:  # pragma: no cover
        pass


def _record(*, data_plane=None, default_case_scoped=None) -> BackendRegistryRecord:
    now = datetime(2026, 6, 8, tzinfo=timezone.utc)
    return BackendRegistryRecord(
        id="11111111-1111-1111-1111-111111111111",
        name="opensearch-mcp",
        namespace="opensearch",
        transport="stdio",
        tier="addon",
        enabled=True,
        connection={"type": "stdio", "command": "python", "args": ["-m", "opensearch_mcp"]},
        data_plane=data_plane,
        default_case_scoped=default_case_scoped,
        manifest={"namespace": "opensearch"},
        manifest_source="well-known",
        manifest_sha256="deadbeef",
        health_status="unknown",
        health_detail=None,
        health_checked_at=None,
        registered_by=None,
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# Existing F1 tests (preserved)
# ---------------------------------------------------------------------------

def test_public_dict_surfaces_case_scope_and_data_plane():
    data_plane = {
        "dependencies": ["opensearch", "postgres-opensearch-provenance"],
        "writes": True,
        "notes": "derived/rebuildable",
    }
    record = _record(data_plane=data_plane, default_case_scoped=True)
    pub = record.public_dict(started=True, available=True, pending_apply=False)

    assert pub["default_case_scoped"] is True
    assert pub["data_plane"] == data_plane
    # Must be JSON-serializable for the registry/portal surface.
    json.dumps(pub)


def test_public_dict_data_plane_none_when_absent():
    record = _record(data_plane=None, default_case_scoped=None)
    pub = record.public_dict(started=False, available=False, pending_apply=False)
    assert pub["data_plane"] is None
    assert pub["default_case_scoped"] is None


def test_opensearch_manifest_declares_derived_case_scoped_plane():
    """The shipped opensearch-mcp manifest declares the F1 derived-plane contract."""
    manifest = _MANIFEST

    assert manifest["default_case_scoped"] is True
    data_plane = manifest["data_plane"]
    assert data_plane["writes"] is True
    assert "opensearch" in data_plane["dependencies"]
    assert "postgres-opensearch-provenance" in data_plane["dependencies"]
    # Stable manifest digest still computes (registry stores this).
    assert manifest_sha256(manifest)


# ---------------------------------------------------------------------------
# OS1 additions: requirement gating
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_opensearch_tools_appear_in_aggregate_catalog_when_requirement_met():
    """When the OpenSearch endpoint TCP check passes, opensearch_* appear in tools/list."""
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    gateway.backends["opensearch-mcp"] = _FakeOSBackend(started=True)

    # Patch evaluate_requirement so the http://localhost:9200 check returns True
    with patch.object(gateway, "evaluate_requirement", return_value=True):
        await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    # Every declared opensearch_* tool must appear in the aggregate catalog.
    assert _OPENSEARCH_TOOLS.issubset(tool_names), (
        f"Missing tools from aggregate catalog: {_OPENSEARCH_TOOLS - tool_names}"
    )
    assert all(name.startswith("opensearch_") for name in _OPENSEARCH_TOOLS)


@pytest.mark.asyncio
async def test_opensearch_tools_absent_from_aggregate_catalog_when_requirement_unmet():
    """When the OpenSearch endpoint is unreachable, opensearch_* are absent from tools/list."""
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    gateway.backends["opensearch-mcp"] = _FakeOSBackend(started=True)

    # Patch evaluate_requirement to simulate OpenSearch unreachable
    with patch.object(gateway, "evaluate_requirement", return_value=False):
        await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    opensearch_in_catalog = {n for n in tool_names if n.startswith("opensearch_")}
    assert not opensearch_in_catalog, (
        f"opensearch_* tools should be gated but found: {opensearch_in_catalog}"
    )


@pytest.mark.asyncio
async def test_opensearch_backend_disabled_excludes_tools():
    """A backend with enabled=False in the DB must not expose any tools.

    The Gateway only calls _build_tool_map over self.backends (which contains
    only the enabled rows from app.mcp_backends at startup). This test
    simulates the case where the registry never loaded an opensearch backend
    (i.e. it was disabled), confirming no opensearch_* leak into tools/list.
    """
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    # No opensearch backend added — simulates disabled/unregistered state
    await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    opensearch_in_catalog = {n for n in tool_names if n.startswith("opensearch_")}
    assert not opensearch_in_catalog, (
        f"Disabled opensearch backend leaked tools: {opensearch_in_catalog}"
    )


@pytest.mark.asyncio
async def test_opensearch_backend_not_started_tools_come_from_manifest():
    """A registered but not-yet-started backend: tools derive from the manifest.

    This simulates a backend that is in app.mcp_backends but the subprocess
    hasn't started yet (lazy_start or startup failure). The manifest-declared
    tool list must appear in tools/list when requirements are met.
    """
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})
    gateway.backends["opensearch-mcp"] = _FakeOSBackend(started=False)

    with patch.object(gateway, "evaluate_requirement", return_value=True):
        await gateway._build_tool_map()

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    assert _OPENSEARCH_TOOLS.issubset(tool_names), (
        f"Manifest-declared tools missing from catalog: {_OPENSEARCH_TOOLS - tool_names}"
    )


# ---------------------------------------------------------------------------
# OS1 additions: no-raw-secret storage contract
# ---------------------------------------------------------------------------

def test_opensearch_connection_no_raw_password_stored():
    """Raw OpenSearch credentials must be rejected by normalize_connection_config."""
    for raw_key in ("password", "api_key", "token", "bearer_token", "secret"):
        config = {
            "type": "stdio",
            "command": "uv",
            "args": ["run", "opensearch-mcp"],
            raw_key: "super-secret-value",
        }
        with pytest.raises(BackendRegistryError, match="raw backend secret fields"):
            normalize_connection_config(config)


def test_opensearch_env_refs_stored_without_resolving_secrets():
    """env_refs for OPENSEARCH_CONFIG and OPENSEARCH_HOST are stored safely.

    The registry stores only env var *names*, not values. Actual credentials
    (the OpenSearch password in opensearch.yaml) never enter the DB row.
    """
    stored = normalize_connection_config(
        {
            "type": "stdio",
            "command": "uv",
            "args": ["run", "opensearch-mcp"],
            "env_refs": {
                "OPENSEARCH_CONFIG": "OPENSEARCH_CONFIG",
                "OPENSEARCH_HOST": "OPENSEARCH_HOST",
            },
        }
    )
    # env_refs round-trips as a dict of name -> name (no resolution at store time).
    assert stored["env_refs"] == {
        "OPENSEARCH_CONFIG": "OPENSEARCH_CONFIG",
        "OPENSEARCH_HOST": "OPENSEARCH_HOST",
    }
    # The resolved env dict must NOT be present in stored form.
    assert "env" not in stored
    # No raw credential key appears.
    for secret_key in ("password", "api_key", "bearer_token", "token", "secret"):
        assert secret_key not in stored


# ---------------------------------------------------------------------------
# OS1 additions: manifest requires field correctness
# ---------------------------------------------------------------------------

def test_opensearch_manifest_requires_http_endpoint():
    """The manifest requires field should use http (not https) for the default local endpoint.

    evaluate_requirement does a TCP socket connect on the declared port; the
    scheme is informational. We verify the manifest uses http://localhost:9200
    (matching the install.sh default) rather than the stale https://localhost:9200.
    """
    reqs = _MANIFEST.get("capabilities", {}).get("requires", [])
    assert reqs, "opensearch-mcp manifest must declare at least one requirement"
    # The default local OpenSearch endpoint is HTTP, not HTTPS.
    assert "http://localhost:9200" in reqs, (
        f"Expected 'http://localhost:9200' in requires, got: {reqs}"
    )


def test_evaluate_requirement_http_localhost_9200_reachable_vs_not():
    """evaluate_requirement handles http://localhost:9200 correctly.

    We mock the socket.create_connection call to test both paths without
    requiring a live OpenSearch instance.
    """
    gateway = Gateway({"backends": {}, "execute": {"security": {"denied_binaries": ["env"]}}})

    # Simulate reachable
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = lambda s, *a: None
        result = gateway.evaluate_requirement("http://localhost:9200")
    assert result is True
    mock_conn.assert_called_once_with(("localhost", 9200), timeout=2.0)

    # Simulate unreachable
    with patch("socket.create_connection", side_effect=OSError("refused")):
        result = gateway.evaluate_requirement("http://localhost:9200")
    assert result is False
