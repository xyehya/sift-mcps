"""Regression: IOC content-hash must not raise NameError('hashlib').

record_finding processes IOC-bearing findings through _process_iocs, which
computes a content hash via _compute_ioc_hash. That helper used hashlib.sha256
while the module never imported hashlib, so every IOC-bearing finding raised
NameError: name 'hashlib' is not defined (caught and surfaced as noise on each
finding). This pins the import so the hash computes cleanly.

D6 (XYE-74): _compute_ioc_hash was extracted to sift_core.ioc_helpers.
case_manager re-exports it for backward compat. The ``hashlib`` import
now lives in ioc_helpers, not case_manager directly.
"""

from __future__ import annotations

import sift_core.ioc_helpers as ioc_mod
import sift_core.case_manager as cm
from sift_core.case_manager import _compute_ioc_hash
from sift_core.ioc_helpers import _compute_ioc_hash as _compute_ioc_hash_direct


def test_ioc_helpers_imports_hashlib():
    # hashlib now lives in ioc_helpers (where _compute_ioc_hash is defined).
    assert hasattr(ioc_mod, "hashlib"), "ioc_helpers must import hashlib at module scope"


def test_case_manager_reexports_compute_ioc_hash():
    # Backward-compat: case_manager must still expose _compute_ioc_hash so that
    # existing callers importing from case_manager keep working without changes.
    assert hasattr(cm, "_compute_ioc_hash"), (
        "case_manager must re-export _compute_ioc_hash from ioc_helpers"
    )


def test_compute_ioc_hash_does_not_raise():
    ioc = {
        "value": "203.0.113.7",
        "type": "ipv4",
        "category": "c2",
        "description": "exfil endpoint",
        "tags": ["rdp"],
        "mitre_techniques": ["T1021.001"],
    }
    digest = _compute_ioc_hash(ioc)
    assert isinstance(digest, str)
    assert len(digest) == 64  # sha256 hex
    # Stable/deterministic for the same logical IOC.
    assert digest == _compute_ioc_hash(dict(ioc))


def test_compute_ioc_hash_same_from_both_import_paths():
    # The re-export and the direct import must resolve to the same function.
    ioc = {"value": "10.0.0.1", "type": "ipv4-addr"}
    assert _compute_ioc_hash(ioc) == _compute_ioc_hash_direct(ioc)
