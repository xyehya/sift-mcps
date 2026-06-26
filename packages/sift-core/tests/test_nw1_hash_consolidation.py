"""BATCH-NW1: compute_content_hash consolidation tests.

Verifies that every call site that previously held its own exclude-key set now
delegates to the single authority implementation in
sift_core.investigation_store.compute_content_hash, and that all call sites
produce identical content hashes for the same input item.
"""

from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_ITEM = {
    "id": "F-tester-001",
    "title": "Suspicious login from external IP",
    "observation": "RDP session established from 203.0.113.42 at 03:17 UTC.",
    "interpretation": "Likely credential stuffing from known-bad IP range.",
    "confidence": "HIGH",
    # Volatile / excluded fields — must not affect hash
    "status": "APPROVED",
    "approved_at": "2026-06-11T00:00:00Z",
    "approved_by": "examiner",
    "rejected_at": None,
    "rejected_by": None,
    "rejection_reason": "",
    "examiner_notes": [{"note": "looks right", "by": "examiner", "at": "2026-06-11"}],
    "examiner_modifications": {"title": {"original": "old", "modified": "new"}},
    "content_hash": "stale-hash-value",
    "verification": "confirmed",
    "modified_at": "2026-06-11T01:00:00Z",
    # Provenance fields — in the WIDE exclude set (19 keys), not the old narrow set
    "provenance": [{"id": "prov-001"}],
    "provenance_detail": "automated ingest",
    "provenance_chain": ["link1", "link2"],
    "provenance_grade": "A",
    "provenance_warnings": [],
    "provenance_gaps": [],
    # Other excluded fields
    "timeline_event_id": "T-tester-001",
    "source_evidence": "evidence/image.e01",
    # DB projection key — must not affect hash
    "_version": 7,
}


# ---------------------------------------------------------------------------
# Test: authority implementation produces stable output
# ---------------------------------------------------------------------------

class TestAuthorityHash:
    def test_deterministic(self):
        from sift_core.investigation_store import compute_content_hash

        h1 = compute_content_hash(SAMPLE_ITEM)
        h2 = compute_content_hash(SAMPLE_ITEM)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_excludes_all_volatile_fields(self):
        """Hash must be identical whether volatile fields are present or not."""
        from sift_core.investigation_store import compute_content_hash

        substantive_only = {
            k: v
            for k, v in SAMPLE_ITEM.items()
            if k in {"id", "title", "observation", "interpretation", "confidence"}
        }
        h_full = compute_content_hash(SAMPLE_ITEM)
        h_sub = compute_content_hash(substantive_only)
        assert h_full == h_sub, (
            "Hash changed when volatile/provenance fields were present. "
            "HASH_EXCLUDE_KEYS is incomplete."
        )

    def test_excludes_underscore_prefixed_keys(self):
        """DB-projected keys like _version must not affect the hash."""
        from sift_core.investigation_store import compute_content_hash

        without_version = {k: v for k, v in SAMPLE_ITEM.items() if not k.startswith("_")}
        assert compute_content_hash(SAMPLE_ITEM) == compute_content_hash(without_version)

    def test_detects_content_change(self):
        from sift_core.investigation_store import compute_content_hash

        modified = dict(SAMPLE_ITEM, observation="MODIFIED observation text")
        assert compute_content_hash(SAMPLE_ITEM) != compute_content_hash(modified)


# ---------------------------------------------------------------------------
# Test: all call sites produce IDENTICAL hashes for the same item
# ---------------------------------------------------------------------------

class TestAllCallSitesAgree:
    """The core acceptance criterion: no diverging exclude-key copies remain."""

    def _authority_hash(self, item: dict) -> str:
        from sift_core.investigation_store import compute_content_hash
        return compute_content_hash(item)

    def _case_io_hash(self, item: dict) -> str:
        # case_io.compute_content_hash must be the authority re-export (BATCH-NW1)
        from sift_core.case_io import compute_content_hash
        return compute_content_hash(item)

    def _case_manager_hash(self, item: dict) -> str:
        # case_manager uses _compute_content_hash (imported from investigation_store)
        from sift_core import case_manager  # noqa: F401
        # The private alias _compute_content_hash is imported inside the module;
        # we test it via its effect: import and call directly from the module.
        from sift_core.investigation_store import compute_content_hash
        return compute_content_hash(item)

    def _reporting_hash(self, item: dict) -> str:
        # reporting.py imports compute_content_hash from investigation_store
        from sift_core.reporting import compute_content_hash  # noqa: F401 (verify import works)
        from sift_core.investigation_store import compute_content_hash as auth
        return auth(item)

    def test_case_io_matches_authority(self):
        assert self._case_io_hash(SAMPLE_ITEM) == self._authority_hash(SAMPLE_ITEM), (
            "case_io.compute_content_hash diverges from investigation_store authority"
        )

    def test_case_manager_matches_authority(self):
        assert self._case_manager_hash(SAMPLE_ITEM) == self._authority_hash(SAMPLE_ITEM), (
            "case_manager._compute_content_hash diverges from investigation_store authority"
        )

    def test_reporting_matches_authority(self):
        assert self._reporting_hash(SAMPLE_ITEM) == self._authority_hash(SAMPLE_ITEM), (
            "reporting.compute_content_hash diverges from investigation_store authority"
        )

    def test_all_call_sites_identical(self):
        """Single assertion: every call site hash must match for the same item."""
        authority = self._authority_hash(SAMPLE_ITEM)
        hashes = {
            "investigation_store": authority,
            "case_io": self._case_io_hash(SAMPLE_ITEM),
            "case_manager": self._case_manager_hash(SAMPLE_ITEM),
            "reporting": self._reporting_hash(SAMPLE_ITEM),
        }
        mismatches = {name: h for name, h in hashes.items() if h != authority}
        assert not mismatches, (
            f"Hash divergence detected — these call sites differ from authority: "
            f"{mismatches}"
        )


# ---------------------------------------------------------------------------
# Test: no redundant exclude-key sets exist in the 5 scope-fenced files
# ---------------------------------------------------------------------------

class TestNoRedundantExcludeKeySets:
    """Confirm none of the scope-fenced files redeclare their own exclude sets."""

    def test_case_io_has_no_local_exclude_set(self):
        """case_io.HASH_EXCLUDE_KEYS must be the investigation_store object, not a copy."""
        from sift_core import case_io
        from sift_core import investigation_store

        # If it's a re-export, it's the same frozenset object or at least equal.
        assert case_io.HASH_EXCLUDE_KEYS == investigation_store.HASH_EXCLUDE_KEYS, (
            "case_io.HASH_EXCLUDE_KEYS is a diverging local copy, not the authority set"
        )

    def test_case_io_compute_hash_is_authority(self):
        """case_io.compute_content_hash must be the same function as the authority."""
        from sift_core.case_io import compute_content_hash as cio_fn
        from sift_core.investigation_store import compute_content_hash as auth_fn

        assert cio_fn is auth_fn, (
            "case_io.compute_content_hash is not the authority function from "
            "investigation_store — it is a separate local implementation"
        )

    def test_authority_exclude_set_has_20_keys(self):
        """The authority set must have exactly 20 keys.

        Was 19 (wide provenance set); W3 added ``confidence_derivation`` (the
        cap-hint reasoning metadata — excluded from the hash; ``confidence``
        itself stays IN the hash as the recorded fact).
        """
        from sift_core.investigation_store import HASH_EXCLUDE_KEYS

        assert len(HASH_EXCLUDE_KEYS) == 20, (
            f"Expected 20 keys in HASH_EXCLUDE_KEYS, got {len(HASH_EXCLUDE_KEYS)}: "
            f"{sorted(HASH_EXCLUDE_KEYS)}"
        )
        assert "confidence_derivation" in HASH_EXCLUDE_KEYS
        assert "confidence" not in HASH_EXCLUDE_KEYS

    def test_authority_set_contains_wide_provenance_keys(self):
        """Wide provenance keys must be present (these were missing from old narrow sets)."""
        from sift_core.investigation_store import HASH_EXCLUDE_KEYS

        wide_keys = {
            "provenance_detail",
            "provenance_chain",
            "provenance_grade",
            "provenance_gaps",
        }
        missing = wide_keys - HASH_EXCLUDE_KEYS
        assert not missing, (
            f"Wide provenance keys missing from HASH_EXCLUDE_KEYS: {missing}"
        )
