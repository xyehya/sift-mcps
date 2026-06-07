"""JOB-0 baseline execution smoke tests for current core behavior."""

from __future__ import annotations

import hashlib
import json

import pytest

from sift_core.evidence_chain import (
    ChainStatus,
    chain_status,
    init_evidence_chain,
    load_ledger,
    load_manifest,
    seal_manifest,
)
from sift_common.audit import AuditWriter

_KEY = b"job0-baseline-derived-key-32bytes"


@pytest.fixture
def baseline_case_dir(tmp_path):
    case_dir = tmp_path / "INC-2026-JOB0"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(
        "case_id: INC-2026-JOB0\ntitle: JOB-0 baseline\nexaminer: analyst\n"
    )
    return case_dir


def test_evidence_integrity_baseline_uses_temp_case_state(baseline_case_dir, monkeypatch):
    """Seal one tiny temp evidence file and verify current manifest/status shape."""
    monkeypatch.setattr("sift_core.evidence_chain._set_immutable", lambda *_args: True)

    evidence_file = baseline_case_dir / "evidence" / "mini.txt"
    evidence_file.write_bytes(b"baseline evidence\n")

    init_evidence_chain(baseline_case_dir)
    manifest = seal_manifest(
        baseline_case_dir,
        [{"path": "evidence/mini.txt", "source": "unit-fixture", "description": "tiny"}],
        "analyst",
        _KEY,
    )
    status = chain_status(baseline_case_dir)
    ledger = load_ledger(baseline_case_dir)
    loaded = load_manifest(baseline_case_dir)

    assert status == {
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 1,
        "ok_count": 1,
    }
    assert loaded == manifest
    assert manifest["case_id"] == "INC-2026-JOB0"
    assert manifest["files"][0]["path"] == "evidence/mini.txt"
    assert manifest["files"][0]["sha256"] == hashlib.sha256(b"baseline evidence\n").hexdigest()
    assert manifest["files"][0]["status"] == "ACTIVE"
    assert ledger[-1]["event"] == "MANIFEST_SEALED"
    assert ledger[-1]["files_added"] == ["evidence/mini.txt"]


def test_audit_writer_baseline_jsonl_append_shape(tmp_path, monkeypatch):
    """Write two audit events to an explicit temp audit dir and assert JSONL shape."""
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("SIFT_EXAMINER", "Analyst One")

    writer = AuditWriter("baseline-mcp", audit_dir=str(audit_dir))
    first_id = writer.log(
        tool="baseline_check",
        params={"case": "INC-2026-JOB0", "mode": "smoke"},
        result_summary={"ok": True},
        case_id="INC-2026-JOB0",
        elapsed_ms=12.34,
    )
    second_id = writer.log(
        tool="baseline_check",
        params={"case": "INC-2026-JOB0", "mode": "repeat"},
        result_summary=["one", "two"],
        case_id="INC-2026-JOB0",
    )

    lines = (audit_dir / "baseline-mcp.jsonl").read_text().splitlines()
    entries = [json.loads(line) for line in lines]

    assert len(entries) == 2
    assert first_id == entries[0]["audit_id"]
    assert second_id == entries[1]["audit_id"]
    assert entries[0]["mcp"] == "baseline-mcp"
    assert entries[0]["tool"] == "baseline_check"
    assert entries[0]["examiner"] == "analyst-one"
    assert entries[0]["case_id"] == "INC-2026-JOB0"
    assert entries[0]["params"] == {"case": "INC-2026-JOB0", "mode": "smoke"}
    assert entries[0]["result_summary"] == {"ok": True}
    assert entries[0]["elapsed_ms"] == 12.3
    assert entries[1]["result_summary"] == {"count": 2, "type": "list"}
    assert (audit_dir / "baseline-mcp.seq").exists()
