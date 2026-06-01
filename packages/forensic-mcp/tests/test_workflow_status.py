"""Tests for workflow_status tool (Phase B1).

Phase detection: ORIENT → SEALED → INGESTING → TRIAGE → FINDINGS → REPORTING.
Plus EVIDENCE_VIOLATION (tampering detection — uses same chain_status() the
gateway evidence gate already calls on every tool invocation).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from forensic_mcp.server import create_server


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def case_dir(tmp_path):
    """Minimal case directory with CASE.yaml."""
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "test-wf-001", "title": "Workflow Test", "examiner": "alice"})
    )
    return tmp_path


@pytest.fixture
def server_with_case(case_dir, monkeypatch):
    """Return (server, tools_dict) with AGENTIR_CASE_DIR set.

    Mock chain_status to OK for normal phase-detection tests.
    monkeypatch.setattr stays active for the full test duration
    (unlike with patch(...) which exits after create_server).
    """
    monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("AGENTIR_EXAMINER", "alice")

    import sift_core.evidence_chain as _ec

    def _mock_ok(case_dir):
        return {"status": "ok", "issues": [], "manifest_version": 0, "ok_count": 0}

    monkeypatch.setattr(_ec, "chain_status", _mock_ok)
    s = create_server()
    tools = {t.name: t for t in s._tool_manager.list_tools()}
    return s, tools, case_dir


@pytest.fixture
def _clear_chain_mock(monkeypatch):
    """Undo any chain_status mock so per-test mocks can take over."""
    import sift_core.evidence_chain as _ec

    monkeypatch.undo()


def _call(tool, **kwargs):
    """Call a FastMCP tool synchronously."""
    import asyncio
    import inspect

    result = tool.fn(**kwargs)
    if inspect.isawaitable(result):
        return asyncio.get_event_loop().run_until_complete(result)
    return result


def _mock_chain(monkeypatch, status, issues=None, manifest_version=0, ok_count=0):
    """Install a chain_status mock that returns the given state."""
    import sift_core.evidence_chain as _ec

    def _fn(case_dir):
        return {
            "status": status,
            "issues": issues or [],
            "manifest_version": manifest_version,
            "ok_count": ok_count,
        }

    monkeypatch.setattr(_ec, "chain_status", _fn)


def _mock_chain_import_error(monkeypatch):
    """Simulate sift_core not being importable."""
    import sift_core.evidence_chain as _ec

    def _fn(case_dir):
        raise ImportError("No sift_core")

    monkeypatch.setattr(_ec, "chain_status", _fn)


# ---------------------------------------------------------------------------
# Normal phase detection tests (chain_status → OK)
# ---------------------------------------------------------------------------


def test_workflow_status_fresh_case_oriented(server_with_case):
    """Fresh case with no evidence and no findings → ORIENT phase."""
    _s, tools, _case_dir = server_with_case
    result = _call(tools["workflow_status"])
    assert result["phase"] == "ORIENT"
    assert result["case_id"] == "test-wf-001"
    assert result["evidence_chain"]["status"] == "ok"
    assert result["evidence_summary"]["sealed_files"] == 0
    assert result["findings_summary"]["total"] == 0
    assert len(result["next_steps"]) > 0
    assert "available_capabilities" in result


def test_workflow_status_sealed_evidence(server_with_case):
    """Evidence sealed but not ingested → SEALED phase."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01", "sha256": "abc123"}]
    }))
    result = _call(tools["workflow_status"])
    assert result["phase"] == "SEALED"
    assert result["evidence_summary"]["sealed_files"] == 1
    assert any("idx_ingest" in s.lower() for s in result["next_steps"])


def test_workflow_status_post_ingest_triage(server_with_case):
    """Evidence ingested but no findings → TRIAGE phase."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    ingest_dir = Path.home() / ".agentir" / "ingest-status"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    status_file = ingest_dir / "test-wf-001-100.json"
    status_file.write_text(json.dumps({
        "run_id": "run-001", "pid": 100, "status": "complete",
        "case_id": "test-wf-001", "started": "2026-05-01T00:00:00Z",
        "hosts": [{"hostname": "TEST-HOST"}], "totals": {"docs_indexed": 1000},
    }))
    try:
        result = _call(tools["workflow_status"])
        assert result["phase"] == "TRIAGE"
        assert result["indexing_status"]["complete"] is True
    finally:
        status_file.unlink(missing_ok=True)


def test_workflow_status_with_draft_findings(server_with_case):
    """Draft findings exist → FINDINGS phase."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    ingest_dir = Path.home() / ".agentir" / "ingest-status"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    sf = ingest_dir / "test-wf-001-101.json"
    sf.write_text(json.dumps({
        "run_id": "run-002", "pid": 101, "status": "complete",
        "case_id": "test-wf-001", "hosts": [], "totals": {},
    }))
    (case_dir / "findings.json").write_text(json.dumps([{
        "id": "F-alice-001", "title": "Suspicious execution", "status": "DRAFT",
        "staged": "2026-05-01T00:10:00Z",
    }]))
    try:
        result = _call(tools["workflow_status"])
        assert result["phase"] == "FINDINGS"
        assert result["findings_summary"]["draft"] == 1
    finally:
        sf.unlink(missing_ok=True)


def test_workflow_status_with_approved_findings(server_with_case):
    """Approved findings → REPORTING phase."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    ingest_dir = Path.home() / ".agentir" / "ingest-status"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    sf = ingest_dir / "test-wf-001-102.json"
    sf.write_text(json.dumps({
        "run_id": "run-003", "pid": 102, "status": "complete",
        "case_id": "test-wf-001", "hosts": [], "totals": {},
    }))
    (case_dir / "findings.json").write_text(json.dumps([
        {"id": "F-alice-001", "status": "APPROVED", "staged": "2026-05-01T00:10:00Z"},
        {"id": "F-alice-002", "status": "DRAFT", "staged": "2026-05-01T00:15:00Z"},
    ]))
    try:
        result = _call(tools["workflow_status"])
        assert result["phase"] == "REPORTING"
        assert result["findings_summary"]["approved"] == 1
    finally:
        sf.unlink(missing_ok=True)


def test_workflow_status_no_case(monkeypatch):
    """No active case → NO_CASE phase."""
    monkeypatch.delenv("AGENTIR_CASE_DIR", raising=False)
    monkeypatch.setenv("AGENTIR_CASE_DIR", "/tmp/nonexistent-case-xyz")
    monkeypatch.setenv("AGENTIR_EXAMINER", "alice")
    s = create_server()
    tools = {t.name: t for t in s._tool_manager.list_tools()}
    result = _call(tools["workflow_status"])
    assert result["phase"] == "NO_CASE"


def test_workflow_status_ingesting_phase(server_with_case):
    """Ingestion running → INGESTING phase."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    ingest_dir = Path.home() / ".agentir" / "ingest-status"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    sf = ingest_dir / "test-wf-001-103.json"
    sf.write_text(json.dumps({
        "run_id": "run-004", "pid": 103, "status": "running",
        "case_id": "test-wf-001", "hosts": [], "totals": {},
    }))
    try:
        result = _call(tools["workflow_status"])
        assert result["phase"] == "INGESTING"
    finally:
        sf.unlink(missing_ok=True)


def test_workflow_status_ingest_failed(server_with_case):
    """Ingestion failed → SEALED phase with error."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    ingest_dir = Path.home() / ".agentir" / "ingest-status"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    sf = ingest_dir / "test-wf-001-104.json"
    sf.write_text(json.dumps({
        "run_id": "run-005", "pid": 104, "status": "failed",
        "case_id": "test-wf-001", "error": "shard_capacity_exhausted: disk full",
        "hosts": [], "totals": {},
    }))
    try:
        result = _call(tools["workflow_status"])
        assert result["phase"] == "SEALED"
        assert result["indexing_status"]["failed"] is True
    finally:
        sf.unlink(missing_ok=True)


def test_workflow_status_evidence_json_fallback(server_with_case):
    """Fall back to evidence.json if evidence-manifest.json is absent."""
    _s, tools, case_dir = server_with_case
    (case_dir / "evidence.json").write_text(json.dumps({
        "files": [{"name": "disk.dd", "path": "evidence/disk.dd"}]
    }))
    result = _call(tools["workflow_status"])
    assert result["phase"] == "SEALED"
    assert result["evidence_summary"]["sealed_files"] == 1


# ---------------------------------------------------------------------------
# Evidence chain violation tests (same chain_status the gateway uses)
# ---------------------------------------------------------------------------


@pytest.fixture
def svr(case_dir, monkeypatch):
    """Server with AGENTIR_CASE_DIR set — no chain_status mock by default."""
    monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("AGENTIR_EXAMINER", "alice")
    s = create_server()
    tools = {t.name: t for t in s._tool_manager.list_tools()}
    return s, tools, case_dir


def test_workflow_status_chain_violation_modified(svr, monkeypatch):
    """MODIFIED → EVIDENCE_VIOLATION with HITL signal."""
    _s, tools, case_dir = svr
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    _mock_chain(monkeypatch, "modified", issues=["Modified: evidence/image.e01"], manifest_version=1)
    result = _call(tools["workflow_status"])
    assert result["phase"] == "EVIDENCE_VIOLATION"
    assert result["evidence_chain"]["status"] == "modified"
    assert any("Portal" in s for s in result["next_steps"])


def test_workflow_status_chain_violation_missing(svr, monkeypatch):
    """MISSING → EVIDENCE_VIOLATION."""
    _s, tools, case_dir = svr
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    _mock_chain(monkeypatch, "missing", issues=["Missing: evidence/image.e01"])
    result = _call(tools["workflow_status"])
    assert result["phase"] == "EVIDENCE_VIOLATION"
    assert result["evidence_chain"]["status"] == "missing"


def test_workflow_status_chain_violation_unregistered(svr, monkeypatch):
    """UNREGISTERED → EVIDENCE_VIOLATION."""
    _s, tools, case_dir = svr
    _mock_chain(monkeypatch, "unregistered", issues=["Unregistered: evidence/unknown.bin"])
    result = _call(tools["workflow_status"])
    assert result["phase"] == "EVIDENCE_VIOLATION"
    assert result["evidence_chain"]["status"] == "unregistered"


def test_workflow_status_chain_violation_ledger_error(svr, monkeypatch):
    """LEDGER_ERROR → EVIDENCE_VIOLATION."""
    _s, tools, case_dir = svr
    _mock_chain(monkeypatch, "ledger_error", issues=["Manifest hash mismatch"])
    result = _call(tools["workflow_status"])
    assert result["phase"] == "EVIDENCE_VIOLATION"
    assert any("HMAC" in s for s in result["next_steps"])


def test_workflow_status_chain_unsealed(svr, monkeypatch):
    """UNSEALED with no evidence files → ORIENT with BLOCKED note."""
    _s, tools, case_dir = svr
    _mock_chain(monkeypatch, "unsealed", manifest_version=0)
    result = _call(tools["workflow_status"])
    assert result["phase"] == "ORIENT"
    assert result["evidence_chain"]["status"] == "unsealed"
    assert any("BLOCKED" in s for s in result["next_steps"])


def test_workflow_status_chain_ok_with_sealed(svr, monkeypatch):
    """OK with sealed evidence → normal SEALED phase."""
    _s, tools, case_dir = svr
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    _mock_chain(monkeypatch, "ok", manifest_version=1, ok_count=1)
    result = _call(tools["workflow_status"])
    assert result["phase"] == "SEALED"
    assert result["evidence_chain"]["status"] == "ok"


def test_workflow_status_chain_import_error_graceful(svr, monkeypatch):
    """When sift_core is not importable, defaults to 'unsealed'."""
    _s, tools, case_dir = svr
    (case_dir / "evidence-manifest.json").write_text(json.dumps({
        "files": [{"name": "image.e01", "path": "evidence/image.e01"}]
    }))
    _mock_chain_import_error(monkeypatch)
    result = _call(tools["workflow_status"])
    assert result["evidence_chain"]["status"] == "unsealed"
    # Falls through to normal phase detection, chain defaults to unsealed
    assert result["phase"] == "SEALED"
