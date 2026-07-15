"""Tests for sift_gateway.evidence_gate.

BU3 (XYE-21) removed the file-backed gate (``check_evidence_gate`` + its 30s TTL
cache). The gate is now DB-authority only (``check_evidence_gate_db``, covered in
test_evidence_gate_db.py). This module covers the remaining surface:
``build_block_response`` shaping.
"""

from __future__ import annotations

import json

from sift_core.custody_types import ChainStatus
from sift_gateway.evidence_gate import build_block_response


class TestBuildBlockResponse:
    def test_violation_uses_violation_reason(self):
        gate = {
            "blocked": True,
            "status": ChainStatus.MISSING,
            "issues": ["Missing: evidence/disk.E01"],
            "manifest_version": 1,
        }
        resp = build_block_response("sift_run_command", gate)
        assert resp["blocked"] is True
        assert resp["reason"] == "evidence_chain_violation"
        assert resp["tool"] == "sift_run_command"
        assert resp["status"] == ChainStatus.MISSING
        assert "remediation" in resp

    def test_unsealed_uses_unsealed_reason(self):
        gate = {
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No sealed manifest"],
            "manifest_version": 0,
        }
        resp = build_block_response("sift_run_command", gate)
        assert resp["reason"] == "evidence_chain_unsealed"

    def test_json_serialisable(self):
        gate = {
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No sealed manifest"],
            "manifest_version": 0,
        }
        resp = build_block_response("case_status", gate)
        json.dumps(resp)  # must not raise — ChainStatus is a str-enum so it serialises
