"""P4.23 CP2B — absence (fail-on-revert) tests for every deletion (OPERATING-MODEL §9).

Each test proves a removed as-built custody surface stays removed. These are
cheap, DB-free structural checks — a regression that reintroduces any of these
symbols/imports should fail here before it reaches a live gateway.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest

_GATEWAY_SRC = Path(__file__).resolve().parents[1] / "src" / "sift_gateway"
_CORE_SRC = (
    Path(__file__).resolve().parents[2] / "sift-core" / "src" / "sift_core"
)


def test_custody_drift_module_is_unimportable():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("sift_gateway.custody_drift")


def test_custody_proof_module_is_unimportable():
    # The whole module is deleted: signing key loading, bundle sign/verify, and
    # the canonical-JSON helper all moved (in spirit) into custody/ledger.py
    # without the Ed25519 signing authority (SPEC §Custody Ledger).
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("sift_gateway.custody_proof")


def test_sift_core_custody_anchor_module_is_unimportable():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("sift_core.custody_anchor")


def test_portal_services_no_longer_imports_custody_drift_or_custody_operations():
    source = (_GATEWAY_SRC / "portal_services.py").read_text()
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "sift_gateway.custody_drift" not in imported_modules
    assert "sift_gateway.custody_operations" not in imported_modules
    assert "sift_gateway.custody_proof" not in imported_modules


def test_evidence_authority_service_has_no_custody_mutation_surface():
    # The mutation/signing surface (seal, resume_seal, ignore, retire,
    # delete_object, verify, verify_ledger, export_proof, finalize_pending_
    # signature, rotate_signing_key, ...) is gone: superseded by CP2A's
    # custody/seal.py + custody/actions.py and this packet's custody/ledger.py,
    # called directly by portal/custody_routes.py — never through this service.
    from sift_gateway.portal_services import EvidenceAuthorityService

    removed_attrs = (
        "seal",
        "resume_seal",
        "ignore",
        "retire",
        "delete_object",
        "verify",
        "verify_ledger",
        "record_reauth_event",
        "resolve_evidence_reference",
        "finalize_pending_signature",
        "rotate_signing_key",
        "export_proof",
        "latest_proof_export",
        "reconcile_for_admission",
        "disposition_operation_action",
        "resume_disposition",
        "recovery_object_id",
        "recovery_operation_action",
        "begin_recovery",
        "complete_recovery",
    )
    for attr in removed_attrs:
        assert not hasattr(EvidenceAuthorityService, attr), f"{attr} should be removed"

    # __init__ no longer takes the custody_operations-typed injection points.
    params = set(inspect.signature(EvidenceAuthorityService.__init__).parameters)
    assert "custody_repository" not in params
    assert "posture_adapter" not in params
    assert "external_posture_adapter" not in params


def test_evidence_authority_service_retains_ec4_rewired_reads():
    # The read surface that CP2B rewired onto custody.admission stays present
    # (this is a rewrite, not a deletion).
    from sift_gateway.portal_services import EvidenceAuthorityService

    assert hasattr(EvidenceAuthorityService, "gate_status")
    assert hasattr(EvidenceAuthorityService, "list_evidence")
    assert hasattr(EvidenceAuthorityService, "custody_events")


def test_custody_routes_not_registered_before_cp2b_is_absent_as_a_concept():
    # Sanity: the routes ARE now registered (CP2B wires them) — this is the
    # positive counterpart proving server.py picks up custody_routes_list().
    source = (_GATEWAY_SRC / "server.py").read_text()
    assert "custody_routes_list" in source


def test_signing_symbols_are_gone_from_the_source_tree():
    # Fail-on-revert: no surviving source file references the deleted signing
    # API by name (a reintroduction anywhere would be a SPEC violation — no
    # installation-held Ed25519 key, signature latch, or trusted-key registry).
    forbidden = ("load_signing_key", "sign_bundle", "verify_bundle", "CustodyProofError")
    hits = []
    for path in _GATEWAY_SRC.rglob("*.py"):
        text = path.read_text()
        for symbol in forbidden:
            if symbol in text:
                hits.append((path, symbol))
    assert hits == []
