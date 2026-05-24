"""Tests for sift_gateway.evidence_gate.

Verifies the 30s TTL cache, mtime-based invalidation, manual invalidation,
and structured block/pass results.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agentir_core.evidence_chain import ChainStatus, init_evidence_chain, seal_manifest
from sift_gateway.evidence_gate import (
    _CACHE,
    _TTL,
    build_block_response,
    check_evidence_gate,
    invalidate_evidence_cache,
)

_KEY = b"test-derived-key-32bytes-padding!"


@pytest.fixture(autouse=True)
def clear_cache():
    _CACHE.clear()
    yield
    _CACHE.clear()


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "CASE.yaml").write_text("case_id: gate-test\ntitle: T\nexaminer: alice\n")
    init_evidence_chain(tmp_path)
    return tmp_path


@pytest.fixture
def sealed_case(case_dir):
    ev = case_dir / "evidence" / "disk.E01"
    ev.write_bytes(b"disk image data")
    seal_manifest(case_dir, [{"path": "evidence/disk.E01"}], "alice", _KEY)
    return case_dir


# ---------------------------------------------------------------------------
# No case / no manifest
# ---------------------------------------------------------------------------

class TestNoCase:
    def test_no_case_dir_is_blocked(self):
        result = check_evidence_gate(None)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED

    def test_empty_string_is_blocked(self):
        result = check_evidence_gate("")
        assert result["blocked"] is True

    def test_nonexistent_case_dir_is_blocked(self, tmp_path):
        result = check_evidence_gate(str(tmp_path / "nonexistent"))
        assert result["blocked"] is True

    def test_unsealed_manifest_is_blocked(self, case_dir):
        result = check_evidence_gate(str(case_dir))
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNSEALED


# ---------------------------------------------------------------------------
# Sealed / OK
# ---------------------------------------------------------------------------

class TestSealedCase:
    def test_sealed_clean_case_passes(self, sealed_case):
        result = check_evidence_gate(str(sealed_case))
        assert result["blocked"] is False
        assert result["status"] == ChainStatus.OK
        assert result["manifest_version"] == 1

    def test_result_has_required_keys(self, sealed_case):
        result = check_evidence_gate(str(sealed_case))
        assert "blocked" in result
        assert "status" in result
        assert "issues" in result
        assert "manifest_version" in result


# ---------------------------------------------------------------------------
# TTL cache
# ---------------------------------------------------------------------------

class TestTTLCache:
    def test_result_is_cached(self, sealed_case):
        key = str(sealed_case)
        check_evidence_gate(key)
        assert key in _CACHE

    def test_second_call_uses_cache(self, sealed_case):
        key = str(sealed_case)
        call_count = 0
        original = __import__("agentir_core.evidence_chain", fromlist=["chain_status"]).chain_status

        def counting_chain_status(cd):
            nonlocal call_count
            call_count += 1
            return original(cd)

        with patch("sift_gateway.evidence_gate.chain_status", counting_chain_status):
            check_evidence_gate(key)
            check_evidence_gate(key)
        assert call_count == 1

    def test_cache_expires_after_ttl(self, sealed_case):
        key = str(sealed_case)
        check_evidence_gate(key)
        # Manually expire the cache entry
        _CACHE[key]["expire_at"] = time.monotonic() - 1.0
        _CACHE[key]["manifest_mtime"] = 0  # force mtime mismatch too

        call_count = 0
        original = __import__("agentir_core.evidence_chain", fromlist=["chain_status"]).chain_status

        def counting_chain_status(cd):
            nonlocal call_count
            call_count += 1
            return original(cd)

        with patch("sift_gateway.evidence_gate.chain_status", counting_chain_status):
            check_evidence_gate(key)
        assert call_count == 1


# ---------------------------------------------------------------------------
# mtime-based cache invalidation
# ---------------------------------------------------------------------------

class TestMtimeInvalidation:
    def test_manifest_change_triggers_refresh(self, sealed_case):
        key = str(sealed_case)
        check_evidence_gate(key)  # populate cache

        ev2 = sealed_case / "evidence" / "mem.raw"
        ev2.write_bytes(b"memory dump")
        # Seal a new version → manifest file is rewritten → mtime changes
        seal_manifest(sealed_case, [{"path": "evidence/mem.raw"}], "alice", _KEY)

        call_count = 0
        original = __import__("agentir_core.evidence_chain", fromlist=["chain_status"]).chain_status

        def counting_chain_status(cd):
            nonlocal call_count
            call_count += 1
            return original(cd)

        with patch("sift_gateway.evidence_gate.chain_status", counting_chain_status):
            result = check_evidence_gate(key)
        assert call_count == 1
        assert result["manifest_version"] == 2


# ---------------------------------------------------------------------------
# Manual invalidation
# ---------------------------------------------------------------------------

class TestManualInvalidation:
    def test_invalidate_clears_cache(self, sealed_case):
        key = str(sealed_case)
        check_evidence_gate(key)
        assert key in _CACHE
        invalidate_evidence_cache(key)
        assert key not in _CACHE

    def test_invalidate_missing_key_is_noop(self):
        invalidate_evidence_cache("/nonexistent/path")  # must not raise


# ---------------------------------------------------------------------------
# Violation cases
# ---------------------------------------------------------------------------

class TestViolations:
    def test_missing_file_blocks(self, sealed_case):
        key = str(sealed_case)
        (sealed_case / "evidence" / "disk.E01").unlink()
        result = check_evidence_gate(key)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.MISSING

    def test_unregistered_file_blocks(self, sealed_case):
        key = str(sealed_case)
        seal_manifest(sealed_case, [], "alice", _KEY)  # seal empty state
        invalidate_evidence_cache(key)
        (sealed_case / "evidence" / "surprise.bin").write_bytes(b"unknown file")
        result = check_evidence_gate(key)
        assert result["blocked"] is True
        assert result["status"] == ChainStatus.UNREGISTERED

    def test_issues_list_present_on_block(self, sealed_case):
        key = str(sealed_case)
        (sealed_case / "evidence" / "disk.E01").unlink()
        result = check_evidence_gate(key)
        assert isinstance(result["issues"], list)
        assert len(result["issues"]) > 0


# ---------------------------------------------------------------------------
# build_block_response
# ---------------------------------------------------------------------------

class TestBuildBlockResponse:
    def test_structure(self):
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

    def test_json_serialisable(self):
        gate = {
            "blocked": True,
            "status": ChainStatus.UNSEALED,
            "issues": ["No sealed manifest"],
            "manifest_version": 0,
        }
        resp = build_block_response("case_status", gate)
        json.dumps(resp)  # must not raise — ChainStatus is a str-enum so it serialises
