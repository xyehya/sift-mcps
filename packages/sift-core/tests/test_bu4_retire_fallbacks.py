"""BU4 regressions for residual active-case and evidence-ref fallbacks."""

from __future__ import annotations

import json

import pytest

import sift_core.agent_tools as agent_tools
from sift_common.audit import AuditWriter
from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.agent_tools import _run_command
from sift_core.evidence_chain import init_evidence_chain, seal_manifest

_KEY = b"bu4-run-command-derived-key-32bytes"


@pytest.fixture
def sealed_case(tmp_path, monkeypatch):
    monkeypatch.setattr("sift_core.evidence_chain._set_immutable", lambda *_a: True)
    case_dir = tmp_path / "case-bu4-file-mode"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: BU4-FILE\nexaminer: analyst\n")
    ev = case_dir / "evidence" / "disk.txt"
    ev.write_bytes(b"sealed evidence bytes\n")
    init_evidence_chain(case_dir)
    seal_manifest(
        case_dir,
        [{"path": "evidence/disk.txt", "source": "fixture", "description": "d"}],
        "analyst",
        _KEY,
    )
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "__current__")
    return case_dir


def test_db_active_audit_case_id_uses_authority_context_not_pointer(
    tmp_path, monkeypatch
):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("SIFT_ACTIVE_CASE", "STALE-ENV")
    monkeypatch.setattr(
        "sift_common.audit.Path.home",
        lambda: (_ for _ in ()).throw(AssertionError("active_case pointer read")),
    )
    writer = AuditWriter("sift-core", audit_dir=str(audit_dir))
    ctx = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="DB-001",
        artifact_path=str(tmp_path / "case"),
        db_active=True,
    )

    with use_active_case_context(ctx):
        assert (
            writer.log(
                "run_command",
                {},
                {"exit_code": 0},
                audit_id="AUD-BU4-1",
            )
            == "AUD-BU4-1"
        )

    entry = json.loads((audit_dir / "sift-core.jsonl").read_text().strip())
    assert entry["case_id"] == "11111111-1111-1111-1111-111111111111"


def test_resolve_case_dir_does_not_read_active_case_pointer(monkeypatch):
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.setattr(
        "sift_common.Path.home",
        lambda: (_ for _ in ()).throw(AssertionError("active_case pointer read")),
    )

    from sift_common import resolve_case_dir

    assert resolve_case_dir() == ""


def test_db_active_run_command_requires_gateway_resolved_evidence_refs(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case-db-bu4"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: DB-BU4\nexaminer: analyst\n")
    (case_dir / "evidence" / "db.txt").write_text("db bytes\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")

    def _resolve_evidence_ref_should_not_run(*_args, **_kwargs):
        raise AssertionError("file evidence-ref fallback reached")

    def _execute_should_not_run(*_args, **_kwargs):
        raise AssertionError("command executed without DB evidence refs")

    monkeypatch.setattr(
        "sift_core.execute.security.resolve_evidence_ref",
        _resolve_evidence_ref_should_not_run,
    )
    monkeypatch.setattr(agent_tools, "_execute_command", _execute_should_not_run)
    audit = AuditWriter(mcp_name="sift-core")
    ctx = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="DB-BU4",
        artifact_path=str(case_dir),
        db_active=True,
    )

    with use_active_case_context(ctx):
        out = _run_command(
            {
                "command": "cat evidence/db.txt",
                "purpose": "missing gateway DB refs must fail closed",
                "evidence_refs": ["ev-1"],
            },
            examiner="analyst",
            audit=audit,
        )

    assert out["success"] is False
    assert out["error"] == (
        "evidence_refs require gateway-resolved DB evidence refs in DB-authority mode"
    )


def test_file_mode_run_command_evidence_ref_fallback_still_works(sealed_case):
    audit = AuditWriter(mcp_name="sift-core")
    out = _run_command(
        {
            "command": "cat evidence/disk.txt",
            "purpose": "legacy file-mode evidence refs still resolve",
            "evidence_refs": ["disk.txt"],
        },
        examiner="analyst",
        audit=audit,
    )

    assert out["success"] is True
    assert out["provenance"]["evidence_refs"] == ["disk.txt"]
