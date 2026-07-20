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
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ROOT_TESTS = _REPO_ROOT / "tests"

# repair round 1, MUST-FIX 2: tests/test_custody_signing_authority_provision.py
# imported the (already-deleted) custody_proof module and broke CI collection
# suite-wide (testpaths=["tests","packages"]) — the absence harness only
# scanned packages/sift-gateway/src, never the root-level tests/ tree where
# the actual stale importer lived. Every scan below now covers both.
_DELETED_MODULE_NAMES = ("custody_drift", "custody_proof", "custody_anchor")


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
    # Scans packages/sift-gateway/src AND the root-level tests/ tree — the
    # signing-authority test this round deleted lived in the latter, which the
    # original scan (repair round 1) missed.
    forbidden = ("load_signing_key", "sign_bundle", "verify_bundle", "CustodyProofError")
    hits = []
    for base in (_GATEWAY_SRC, _ROOT_TESTS):
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            text = path.read_text()
            for symbol in forbidden:
                if symbol in text:
                    hits.append((path, symbol))
    assert hits == []


def test_no_stale_import_of_a_deleted_custody_module_anywhere_in_the_repo():
    # Fail-on-revert for THIS round's exact CI-collection break: an AST-based
    # (import statements only, so a docstring merely MENTIONING one of these
    # module names as historical context is never a false positive — several
    # of this packet's own docstrings say things like "absorbs the as-built
    # custody_proof.py") scan for any `import sift_gateway.custody_proof`,
    # `from sift_gateway import custody_proof`, or
    # `from sift_gateway.custody_proof import X` (and the drift/anchor
    # equivalents) anywhere under packages/ or the root tests/ tree — not just
    # packages/sift-gateway/src, where the stale importer this round fixed did
    # NOT live (it was in the root tests/ suite). Matches pytest's own CI
    # collection scope exactly: testpaths = ["tests", "packages"].
    search_roots = (_REPO_ROOT / "packages", _ROOT_TESTS)
    hits: list[tuple[Path, str]] = []
    for root in search_roots:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.rsplit(".", 1)[-1] in _DELETED_MODULE_NAMES:
                            hits.append((path, alias.name))
                elif isinstance(node, ast.ImportFrom) and node.module:
                    tail = node.module.rsplit(".", 1)[-1]
                    if tail in _DELETED_MODULE_NAMES:
                        hits.append((path, node.module))
                    elif tail in ("sift_gateway", "sift_core"):
                        for alias in node.names:
                            if alias.name in _DELETED_MODULE_NAMES:
                                hits.append((path, f"{node.module}.{alias.name}"))
    assert hits == []
