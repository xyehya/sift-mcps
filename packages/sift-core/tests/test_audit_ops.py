"""Tests for sift_core.audit_ops data functions."""

import json

import pytest
import yaml

from sift_core.audit_ops import audit_summary_data


@pytest.fixture
def case_dir(tmp_path):
    """Create a minimal case directory with audit subdirectory."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()
    (case_path / "audit").mkdir()
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(
            {
                "case_id": case_id,
                "name": "Test Case",
                "status": "open",
                "examiner": "tester",
            },
            f,
        )
    return case_path


@pytest.fixture
def sample_audit(case_dir):
    """Write sample audit entries across multiple JSONL files."""
    sift_entries = [
        {
            "ts": "2026-02-19T10:00:00Z",
            "mcp": "sift-mcp",
            "tool": "run_tool",
            "examiner": "tester",
            "audit_id": "sift-tester-20260219-001",
        },
        {
            "ts": "2026-02-19T10:05:00Z",
            "mcp": "sift-mcp",
            "tool": "get_tool_help",
            "examiner": "tester",
            "audit_id": "sift-tester-20260219-002",
        },
        {
            "ts": "2026-02-19T10:10:00Z",
            "mcp": "sift-mcp",
            "tool": "run_tool",
            "examiner": "tester",
            "audit_id": "sift-tester-20260219-003",
        },
    ]
    with open(case_dir / "audit" / "sift-mcp.jsonl", "w") as f:
        for entry in sift_entries:
            f.write(json.dumps(entry) + "\n")

    forensic_entries = [
        {
            "ts": "2026-02-19T10:01:00Z",
            "mcp": "forensic-mcp",
            "tool": "record_finding",
            "examiner": "tester",
            "audit_id": "forensic-tester-20260219-001",
        },
        {
            "ts": "2026-02-19T10:06:00Z",
            "mcp": "forensic-mcp",
            "tool": "record_timeline_event",
            "examiner": "tester",
            "audit_id": "forensic-tester-20260219-002",
        },
    ]
    with open(case_dir / "audit" / "forensic-mcp.jsonl", "w") as f:
        for entry in forensic_entries:
            f.write(json.dumps(entry) + "\n")

    return sift_entries + forensic_entries


@pytest.fixture
def sample_approvals(case_dir):
    """Write sample approval entries."""
    approvals = [
        {
            "ts": "2026-02-19T11:00:00Z",
            "item_id": "F-tester-001",
            "action": "APPROVED",
            "os_user": "testuser",
            "examiner": "tester",
        },
        {
            "ts": "2026-02-19T11:05:00Z",
            "item_id": "T-tester-001",
            "action": "APPROVED",
            "os_user": "testuser",
            "examiner": "tester",
        },
    ]
    with open(case_dir / "approvals.jsonl", "w") as f:
        for entry in approvals:
            f.write(json.dumps(entry) + "\n")
    return approvals


class TestAuditSummaryData:
    def test_summary_counts_entries(self, case_dir, sample_audit):
        result = audit_summary_data(case_dir)
        assert result["total_entries"] == 5
        assert result["audit_ids"] == 5

    def test_summary_by_mcp(self, case_dir, sample_audit):
        result = audit_summary_data(case_dir)
        assert "sift-mcp" in result["by_mcp"]
        assert "forensic-mcp" in result["by_mcp"]
        assert result["by_mcp"]["sift-mcp"] == 3
        assert result["by_mcp"]["forensic-mcp"] == 2

    def test_summary_by_tool(self, case_dir, sample_audit):
        result = audit_summary_data(case_dir)
        assert "run_tool" in result["by_tool"]["sift-mcp"]
        assert result["by_tool"]["sift-mcp"]["run_tool"] == 2
        assert "record_finding" in result["by_tool"]["forensic-mcp"]

    def test_summary_includes_approvals(self, case_dir, sample_audit, sample_approvals):
        result = audit_summary_data(case_dir)
        assert result["total_entries"] == 7
        assert "agentir-cli" in result["by_mcp"]

    def test_summary_empty(self, case_dir):
        result = audit_summary_data(case_dir)
        assert result["total_entries"] == 0
        assert result["audit_ids"] == 0
        assert result["by_mcp"] == {}

    def test_summary_deduplicates_audit_ids(self, case_dir):
        """Same audit_id appearing twice in different files counts once."""
        for backend in ("backend-a.jsonl", "backend-b.jsonl"):
            with open(case_dir / "audit" / backend, "w") as f:
                f.write(
                    json.dumps(
                        {
                            "ts": "2026-01-01T00:00:00Z",
                            "tool": "some_tool",
                            "audit_id": "shared-id-001",
                        }
                    )
                    + "\n"
                )
        result = audit_summary_data(case_dir)
        assert result["total_entries"] == 2
        assert result["audit_ids"] == 1

    def test_mcp_field_derived_from_filename(self, case_dir):
        """Entry without mcp field gets mcp derived from JSONL filename."""
        entry = {
            "ts": "2026-01-01T00:00:00Z",
            "tool": "some_tool",
            "examiner": "tester",
        }
        with open(case_dir / "audit" / "custom-backend.jsonl", "w") as f:
            f.write(json.dumps(entry) + "\n")
        result = audit_summary_data(case_dir)
        assert "custom-backend" in result["by_mcp"]
