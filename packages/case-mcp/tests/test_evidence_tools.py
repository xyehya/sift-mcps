"""Tests for case-mcp evidence tools (Phase 16c).

Covers:
- evidence_register: always returns portal-remediation block (never writes)
- evidence_list: reads System B manifest (evidence-manifest.json)
- evidence_verify: delegates to chain_status() on System B
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import yaml

from case_mcp.server import create_server
from case_mcp.server import _resolve_case_dir


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_KEY = b"test-derived-key-32bytes-padding!"


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "CASE.yaml").write_text(
        "case_id: test-case-001\ntitle: Test\nexaminer: alice\n"
    )
    return tmp_path


@pytest.fixture
def server_with_case(case_dir, monkeypatch):
    """Return (server, tools_dict) with SIFT_CASE_DIR pointing at case_dir."""
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")
    s = create_server()
    tools = {t.name: t for t in s._tool_manager.list_tools()}
    return s, tools, case_dir


def _call(tool, **kwargs):
    """Call a FastMCP tool and return its result dict (handles sync and async)."""
    import asyncio
    import inspect
    result = tool.fn(**kwargs)
    if inspect.isawaitable(result):
        return asyncio.get_event_loop().run_until_complete(result)
    return result


# ---------------------------------------------------------------------------
# evidence_register — always blocked
# ---------------------------------------------------------------------------


class TestEvidenceRegisterBlocked:
    def test_returns_blocked_true(self, server_with_case):
        _, tools, _ = server_with_case
        result = _call(tools["evidence_register"], path="evidence/sample.dd", description="disk")
        assert result["blocked"] is True

    def test_returns_portal_required_action(self, server_with_case):
        _, tools, _ = server_with_case
        result = _call(tools["evidence_register"], path="evidence/sample.dd")
        assert result["action"] == "portal_required"

    def test_does_not_write_evidence_json(self, server_with_case):
        _, tools, case_dir = server_with_case
        _call(tools["evidence_register"], path="evidence/sample.dd")
        assert not (case_dir / "evidence.json").exists()

    def test_does_not_write_manifest(self, server_with_case):
        _, tools, case_dir = server_with_case
        _call(tools["evidence_register"], path="evidence/sample.dd")
        assert not (case_dir / "evidence-manifest.json").exists()

    def test_portal_hint_present(self, server_with_case):
        _, tools, _ = server_with_case
        result = _call(tools["evidence_register"], path="evidence/sample.dd")
        assert "portal_hint" in result
        assert "Portal" in result["portal_hint"]


# ---------------------------------------------------------------------------
# evidence_list — reads System B manifest
# ---------------------------------------------------------------------------


class TestEvidenceListSystemB:
    def test_no_manifest_returns_empty(self, server_with_case):
        _, tools, _ = server_with_case
        result = _call(tools["evidence_list"])
        assert result["evidence"] == []
        assert result["source"] == "manifest_v2"

    def test_env_case_dir_wins_over_legacy_active_case_file(self, server_with_case, tmp_path, monkeypatch):
        _, tools, case_dir = server_with_case
        stale_case = tmp_path / "stale-case"
        stale_case.mkdir()
        legacy_pointer = tmp_path / ".sift" / "active_case"
        legacy_pointer.parent.mkdir()
        legacy_pointer.write_text(str(stale_case))
        monkeypatch.setattr("case_mcp.server.Path.home", lambda: tmp_path)

        manifest = {
            "version": 1,
            "case_id": "test-case-001",
            "created_at": "2026-01-01T00:00:00+00:00",
            "created_by": "alice",
            "previous_manifest_hash": "",
            "manifest_hash": "sha256:abc123",
            "files": [
                {"path": "evidence/current.dd", "status": "ACTIVE", "sha256": "aa", "bytes": 1, "mtime_ns": 0, "registered_at": "", "registered_by": "alice", "source": "", "description": ""}
            ],
        }
        (case_dir / "evidence-manifest.json").write_text(json.dumps(manifest))

        assert _resolve_case_dir() == case_dir
        result = _call(tools["evidence_list"])
        assert result["evidence"][0]["path"] == "evidence/current.dd"

    def test_reads_manifest_files(self, server_with_case):
        _, tools, case_dir = server_with_case
        manifest = {
            "version": 1,
            "case_id": "test-case-001",
            "created_at": "2026-01-01T00:00:00+00:00",
            "created_by": "alice",
            "previous_manifest_hash": "",
            "manifest_hash": "sha256:abc123",
            "files": [
                {
                    "path": "evidence/sample.dd",
                    "sha256": "deadbeef",
                    "bytes": 1024,
                    "mtime_ns": 0,
                    "registered_at": "2026-01-01T00:00:00+00:00",
                    "registered_by": "alice",
                    "source": "",
                    "description": "disk image",
                    "status": "ACTIVE",
                }
            ],
        }
        (case_dir / "evidence-manifest.json").write_text(json.dumps(manifest))
        result = _call(tools["evidence_list"])
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["path"] == "evidence/sample.dd"
        assert result["manifest_version"] == 1
        assert result["source"] == "manifest_v2"

    def test_ignores_ignored_entries(self, server_with_case):
        _, tools, case_dir = server_with_case
        manifest = {
            "version": 2,
            "case_id": "test-case-001",
            "created_at": "2026-01-01T00:00:00+00:00",
            "created_by": "alice",
            "previous_manifest_hash": "",
            "manifest_hash": "sha256:abc",
            "files": [
                {"path": "evidence/active.dd", "status": "ACTIVE", "sha256": "aa", "bytes": 1, "mtime_ns": 0, "registered_at": "", "registered_by": "alice", "source": "", "description": ""},
                {"path": "evidence/noise.log", "status": "IGNORED", "sha256": "", "bytes": 0, "mtime_ns": 0, "registered_at": "", "registered_by": "alice", "source": "", "description": "not evidence"},
            ],
        }
        (case_dir / "evidence-manifest.json").write_text(json.dumps(manifest))
        result = _call(tools["evidence_list"])
        paths = [f["path"] for f in result["evidence"]]
        assert "evidence/active.dd" in paths
        assert "evidence/noise.log" not in paths

    def test_does_not_read_old_evidence_json(self, server_with_case):
        _, tools, case_dir = server_with_case
        old = {"files": [{"path": "/tmp/old.dd", "sha256": "old_hash"}]}
        (case_dir / "evidence.json").write_text(json.dumps(old))
        result = _call(tools["evidence_list"])
        paths = [f.get("path") for f in result["evidence"]]
        assert "/tmp/old.dd" not in paths


# ---------------------------------------------------------------------------
# evidence_verify — delegates to chain_status (System B)
# ---------------------------------------------------------------------------


class TestEvidenceVerifySystemB:
    def test_unsealed_when_no_manifest(self, server_with_case):
        _, tools, _ = server_with_case
        result = _call(tools["evidence_verify"])
        assert result["status"] == "unsealed"
        assert result["source"] == "manifest_v2"

    def test_ok_when_manifest_matches_disk(self, server_with_case):
        from sift_core.evidence_chain import init_evidence_chain, seal_manifest

        _, tools, case_dir = server_with_case
        init_evidence_chain(case_dir)
        ev_file = case_dir / "evidence" / "sample.dd"
        ev_file.write_bytes(b"DISK_IMAGE_CONTENT")
        seal_manifest(
            case_dir,
            file_specs=[{"path": "evidence/sample.dd", "description": "test"}],
            examiner="alice",
            derived_key=_KEY,
        )
        result = _call(tools["evidence_verify"])
        assert result["status"] == "ok"
        assert result["ok_count"] == 1
        assert result["source"] == "manifest_v2"

    def test_modified_when_file_size_changes(self, server_with_case):
        from sift_core.evidence_chain import init_evidence_chain, seal_manifest

        _, tools, case_dir = server_with_case
        init_evidence_chain(case_dir)
        ev_file = case_dir / "evidence" / "sample.dd"
        ev_file.write_bytes(b"ORIGINAL")
        seal_manifest(
            case_dir,
            file_specs=[{"path": "evidence/sample.dd"}],
            examiner="alice",
            derived_key=_KEY,
        )
        ev_file.write_bytes(b"TAMPERED_CONTENT_LONGER")
        result = _call(tools["evidence_verify"])
        assert result["status"] == "modified"
        assert "operator_action_required" in result

    def test_missing_when_file_deleted(self, server_with_case):
        from sift_core.evidence_chain import init_evidence_chain, seal_manifest

        _, tools, case_dir = server_with_case
        init_evidence_chain(case_dir)
        ev_file = case_dir / "evidence" / "sample.dd"
        ev_file.write_bytes(b"DATA")
        seal_manifest(
            case_dir,
            file_specs=[{"path": "evidence/sample.dd"}],
            examiner="alice",
            derived_key=_KEY,
        )
        ev_file.unlink()
        result = _call(tools["evidence_verify"])
        assert result["status"] == "missing"
        assert "operator_action_required" in result

    def test_no_operator_action_on_ok(self, server_with_case):
        from sift_core.evidence_chain import init_evidence_chain, seal_manifest

        _, tools, case_dir = server_with_case
        init_evidence_chain(case_dir)
        ev_file = case_dir / "evidence" / "sample.dd"
        ev_file.write_bytes(b"GOOD")
        seal_manifest(
            case_dir,
            file_specs=[{"path": "evidence/sample.dd"}],
            examiner="alice",
            derived_key=_KEY,
        )
        result = _call(tools["evidence_verify"])
        assert "operator_action_required" not in result

    def test_does_not_read_old_evidence_json(self, server_with_case):
        _, tools, case_dir = server_with_case
        old = {"files": [{"path": "/tmp/old.dd", "sha256": "abc", "registered_at": "2026-01-01", "registered_by": "alice"}]}
        (case_dir / "evidence.json").write_text(json.dumps(old))
        result = _call(tools["evidence_verify"])
        # Should be unsealed (reads manifest, not evidence.json)
        assert result["status"] == "unsealed"
        assert result["source"] == "manifest_v2"


# ---------------------------------------------------------------------------
# R0-6: evidence_list — shows unregistered files in evidence/
# ---------------------------------------------------------------------------


class TestEvidenceListUnregistered:
    def test_shows_unregistered_files(self, server_with_case):
        """Files in evidence/ not in manifest appear in unregistered list."""
        _, tools, case_dir = server_with_case
        (case_dir / "evidence" / "mystery.e01").write_bytes(b"EVF" + b"\x00" * 100)
        result = _call(tools["evidence_list"])
        unregistered = result.get("unregistered", [])
        paths = [f["path"] for f in unregistered]
        assert any("mystery.e01" in p for p in paths)

    def test_registered_files_not_in_unregistered(self, server_with_case):
        """Files sealed in manifest should NOT appear in unregistered list."""
        _, tools, case_dir = server_with_case
        ev_file = case_dir / "evidence" / "sample.dd"
        ev_file.write_bytes(b"DISK_IMAGE")
        manifest = {
            "version": 1,
            "case_id": "test-case-001",
            "created_at": "2026-01-01T00:00:00+00:00",
            "created_by": "alice",
            "previous_manifest_hash": "",
            "manifest_hash": "sha256:abc",
            "files": [
                {
                    "path": "evidence/sample.dd",
                    "sha256": "deadbeef",
                    "bytes": 10,
                    "mtime_ns": 0,
                    "registered_at": "2026-01-01T00:00:00+00:00",
                    "registered_by": "alice",
                    "source": "",
                    "description": "disk",
                    "status": "ACTIVE",
                }
            ],
        }
        (case_dir / "evidence-manifest.json").write_text(json.dumps(manifest))
        result = _call(tools["evidence_list"])
        unregistered_paths = [f["path"] for f in result.get("unregistered", [])]
        assert not any("sample.dd" in p for p in unregistered_paths)

    def test_unregistered_has_registered_false(self, server_with_case):
        """Unregistered files have registered=False flag."""
        _, tools, case_dir = server_with_case
        (case_dir / "evidence" / "unknown.vmdk").write_bytes(b"KDMV" + b"\x00" * 100)
        result = _call(tools["evidence_list"])
        unregistered = result.get("unregistered", [])
        assert len(unregistered) >= 1
        assert all(f["registered"] is False for f in unregistered)

    def test_unregistered_includes_action_required(self, server_with_case):
        """Unregistered file entry includes an action_required hint about portal sealing."""
        _, tools, case_dir = server_with_case
        (case_dir / "evidence" / "raw.img").write_bytes(b"\x00" * 10)
        result = _call(tools["evidence_list"])
        unregistered = result.get("unregistered", [])
        assert len(unregistered) >= 1
        hint = unregistered[0].get("action_required", "")
        assert "portal" in hint.lower() or "Portal" in hint

    def test_unregistered_empty_when_all_registered(self, server_with_case):
        """No extra files in evidence/ → unregistered list is empty."""
        _, tools, case_dir = server_with_case
        ev_file = case_dir / "evidence" / "sealed.dd"
        ev_file.write_bytes(b"DATA")
        manifest = {
            "version": 1,
            "case_id": "test-case-001",
            "created_at": "2026-01-01T00:00:00+00:00",
            "created_by": "alice",
            "previous_manifest_hash": "",
            "manifest_hash": "sha256:abc",
            "files": [
                {
                    "path": "evidence/sealed.dd",
                    "sha256": "aabbcc",
                    "bytes": 4,
                    "mtime_ns": 0,
                    "registered_at": "2026-01-01T00:00:00+00:00",
                    "registered_by": "alice",
                    "source": "",
                    "description": "",
                    "status": "ACTIVE",
                }
            ],
        }
        (case_dir / "evidence-manifest.json").write_text(json.dumps(manifest))
        result = _call(tools["evidence_list"])
        assert result["unregistered"] == []


class TestLegacyToolsHidden:
    def test_legacy_tools_not_in_registry(self, server_with_case):
        _, tools, _ = server_with_case
        assert "case_init" not in tools
        assert "case_activate" not in tools


class TestCaseFileStructure:
    def test_case_file_structure_excludes_sensitive(self, server_with_case, case_dir):
        _, tools, _ = server_with_case
        assert "case_file_structure" in tools

        # Create some test files/dirs
        (case_dir / "evidence").mkdir(exist_ok=True)
        (case_dir / "evidence" / "test.e01").write_bytes(b"123")
        (case_dir / "extractions").mkdir(exist_ok=True)
        (case_dir / "extractions" / "dump.txt").write_bytes(b"hello")

        # Exclude directories
        (case_dir / "audit").mkdir(exist_ok=True)
        (case_dir / "audit" / "audit.jsonl").write_bytes(b"{}")
        (case_dir / ".git").mkdir(exist_ok=True)
        (case_dir / ".git" / "config").write_bytes(b"")

        # Exclude basenames
        (case_dir / "evidence-ledger.jsonl").write_bytes(b"")
        (case_dir / "evidence-verify-state.json").write_bytes(b"")
        (case_dir / "temp.tmp").write_bytes(b"")

        result = _call(tools["case_file_structure"])

        assert "case_id" in result
        assert "case_dir" in result

        # Check directories
        dirs = result["directories"]
        assert "evidence" in dirs
        assert "extractions" in dirs
        assert "audit" not in dirs
        assert ".git" not in dirs

        # Check files
        files = {f["path"]: f["size_bytes"] for f in result["files"]}
        assert "evidence/test.e01" in files
        assert files["evidence/test.e01"] == 3
        assert "extractions/dump.txt" in files
        assert files["extractions/dump.txt"] == 5

        assert "audit/audit.jsonl" not in files
        assert ".git/config" not in files
        assert "evidence-ledger.jsonl" not in files
        assert "evidence-verify-state.json" not in files
        assert "temp.tmp" not in files
