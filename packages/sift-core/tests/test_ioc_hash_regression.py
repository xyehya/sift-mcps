"""Regression: IOC content-hash must not raise NameError('hashlib').

record_finding processes IOC-bearing findings through _process_iocs, which
computes a content hash via _compute_ioc_hash. That helper used hashlib.sha256
while the module never imported hashlib, so every IOC-bearing finding raised
NameError: name 'hashlib' is not defined (caught and surfaced as noise on each
finding). This pins the import so the hash computes cleanly.
"""

from __future__ import annotations

import sift_core.case_manager as cm
from sift_core.case_manager import _compute_ioc_hash


def test_case_manager_imports_hashlib():
    assert hasattr(cm, "hashlib"), "case_manager must import hashlib at module scope"


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
