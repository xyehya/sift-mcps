"""Tests for sift_core.verification HMAC ledger module.

CL3b (B-MVP-017): the password-keyed file-HMAC re-auth helpers (``derive_hmac_key``
/ ``verify_items`` / ``rehmac_entries`` / ``read_ledger`` / ``copy_ledger_to_case``)
were part of the dead file-HMAC re-auth plane and were deleted with it. The tests
that covered them were dropped. What remains here covers the file-authority COMMIT
ledger *writer* (``write_ledger_entry`` + ``compute_hmac`` + case-id validation),
which is still live (called from the case-dashboard ``_apply_delta`` path).
"""

from __future__ import annotations

import json

import pytest
from sift_core.verification import (
    compute_hmac,
    write_ledger_entry,
)

# A 32-byte ledger key (HMAC-SHA256 key length). The password-derived key
# helper was removed with the dead re-auth plane; the commit ledger writer
# takes an already-derived key.
_LEDGER_KEY = bytes(range(32))


@pytest.fixture(autouse=True)
def _patch_verification_dir(tmp_path, monkeypatch):
    """Redirect VERIFICATION_DIR to tmp_path for all tests."""
    monkeypatch.setattr("sift_core.verification.VERIFICATION_DIR", tmp_path)


def test_compute_hmac_deterministic_and_content_bound():
    """A known key+description produces a stable HMAC; different content differs."""
    h1 = compute_hmac(_LEDGER_KEY, "Malware found on host A")
    h2 = compute_hmac(_LEDGER_KEY, "Malware found on host A")
    assert h1 == h2
    assert len(h1) == 64  # hex SHA-256

    h3 = compute_hmac(_LEDGER_KEY, "Malware found on host B")
    assert h3 != h1


def test_write_ledger_entry_appends(tmp_path):
    """write_ledger_entry appends a JSONL line readable from disk."""
    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "hmac": compute_hmac(_LEDGER_KEY, "Test finding"),
        "content_snapshot": "Test finding",
        "approved_by": "alice",
        "approved_at": "2026-01-01T00:00:00Z",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)

    path = tmp_path / "INC-2026-001.jsonl"
    assert path.exists()
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["finding_id"] == "F-001"
    assert lines[0]["content_snapshot"] == "Test finding"

    # Second write appends rather than overwrites.
    write_ledger_entry("INC-2026-001", {**entry, "finding_id": "F-002"})
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert [line_["finding_id"] for line_ in lines] == ["F-001", "F-002"]


def test_case_id_validation():
    """Rejects path traversal and empty case IDs at the write boundary."""
    with pytest.raises(ValueError, match="path traversal"):
        write_ledger_entry("../evil", {"finding_id": "F-001"})

    with pytest.raises(ValueError, match="path traversal"):
        write_ledger_entry("../../etc/passwd", {"finding_id": "F-001"})

    with pytest.raises(ValueError, match="empty"):
        write_ledger_entry("", {"finding_id": "F-001"})
