"""P4.23.7 replacement-first guards for retired custody contracts."""

from __future__ import annotations

import inspect

import case_dashboard.routes as portal_routes
from sift_core import agent_tools


def test_core_mcp_catalog_has_no_custody_mutation_tools() -> None:
    """MCP exposes analysis tools only; custody mutation is Portal-only."""
    names = {spec.name for spec in agent_tools.core_tool_specs()}
    retired = {
        "evidence_register",
        "evidence_unseal",
        "evidence.seal",
        "evidence.unseal",
        "seal_evidence",
        "unseal_evidence",
    }
    assert names.isdisjoint(retired)


def test_core_orientation_cannot_reintroduce_file_custody_reads() -> None:
    """The DB gateway, not sift-core, supplies custody orientation to agents."""
    source = inspect.getsource(agent_tools._case_info) + inspect.getsource(
        agent_tools._evidence_info
    )
    assert "chain_status(" not in source
    assert "list_evidence_status_data(" not in source
    assert "load_manifest(" not in source
    assert "authority_required" in source


def test_public_portal_contract_has_no_hmac_verify_or_rescan_route() -> None:
    """Retired aliases cannot silently return as public Portal behavior."""
    source = inspect.getsource(portal_routes._dashboard_api_routes)
    assert "/api/evidence/chain/full-verify" in source
    assert "/api/evidence/chain/verify-hmac" not in source
    assert "/api/evidence/chain/rescan" not in source
    assert "post_evidence_chain_full_verify" in source
