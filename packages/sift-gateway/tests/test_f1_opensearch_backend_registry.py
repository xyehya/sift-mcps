"""BATCH-F1: Gateway backend-registry surfaces OpenSearch derived-plane metadata.

The OpenSearch backend is a derived, rebuildable, case-scoped plane. Its
manifest declares ``default_case_scoped`` and a ``data_plane`` block; the
registry record must round-trip that metadata and expose it in the public dict
so the portal/registry can show the plane carries no authority. This test is
fenced to a new file so it does not overlap BATCH-G1 in the gateway src.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sift_gateway.mcp_backends_registry import BackendRegistryRecord, manifest_sha256


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
    manifest_path = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "opensearch-mcp"
        / "sift-backend.json"
    )
    manifest = json.loads(manifest_path.read_text())

    assert manifest["default_case_scoped"] is True
    data_plane = manifest["data_plane"]
    assert data_plane["writes"] is True
    assert "opensearch" in data_plane["dependencies"]
    assert "postgres-opensearch-provenance" in data_plane["dependencies"]
    # Stable manifest digest still computes (registry stores this).
    assert manifest_sha256(manifest)
