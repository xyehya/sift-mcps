"""BATCH-I1 — sandboxed run_command uplift.

Covers the four I1 deliverables:
  * evidence refs (not arbitrary paths), fail-closed against the sealed manifest;
  * output refs resolved internally to the case write-jail;
  * a tight MVP forensic allowlist (opt-in, deny-floor still on top);
  * agent-facing path sanitization + hash-linked provenance receipts.
"""

from __future__ import annotations

import json

import pytest

import sift_core.agent_tools as agent_tools
from sift_common.audit import AuditWriter
from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.agent_tools import _run_command
from sift_core.evidence_chain import init_evidence_chain, seal_manifest
from sift_core.execute.catalog import clear_catalog_cache
from sift_core.execute.security import (
    EvidenceRefError,
    resolve_evidence_ref,
    resolve_output_ref,
    sanitize_path_value,
    sanitize_paths_deep,
)
from sift_core.execute.security_policy import (
    MVP_FORENSIC_ALLOWLIST,
    build_security_policy,
    matches_allowed_binary,
)

_KEY = b"i1-run-command-uplift-derived-key32"


@pytest.fixture(autouse=True)
def _run_as_current_user(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "__current__")
    clear_catalog_cache()


@pytest.fixture
def sealed_case(tmp_path, monkeypatch):
    """A case with one sealed evidence file and the env wired for resolution."""
    monkeypatch.setattr("sift_core.evidence_chain._set_immutable", lambda *_a: True)
    case_dir = tmp_path / "case-i1-06080101"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: I1-001\nexaminer: analyst\n")
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
    return case_dir


# --- evidence-ref resolution -------------------------------------------------


def test_evidence_ref_resolves_sealed_by_relative_path(sealed_case):
    resolved = resolve_evidence_ref("evidence/disk.txt", case_dir=sealed_case)
    assert resolved == str((sealed_case / "evidence" / "disk.txt").resolve())


def test_evidence_ref_resolves_sealed_by_basename(sealed_case):
    resolved = resolve_evidence_ref("disk.txt", case_dir=sealed_case)
    assert resolved == str((sealed_case / "evidence" / "disk.txt").resolve())


def test_evidence_ref_unknown_fails_closed(sealed_case):
    with pytest.raises(EvidenceRefError):
        resolve_evidence_ref("does-not-exist.E01", case_dir=sealed_case)


def test_evidence_ref_unsealed_case_fails_closed(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-unsealed-06080202"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "raw.txt").write_bytes(b"x")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    with pytest.raises(EvidenceRefError):
        resolve_evidence_ref("evidence/raw.txt", case_dir=case_dir)


def test_evidence_ref_rejects_absolute_path_input(sealed_case):
    # The agent cannot smuggle an arbitrary absolute path through the door.
    with pytest.raises(EvidenceRefError):
        resolve_evidence_ref(str(sealed_case / "evidence" / "disk.txt"), case_dir=sealed_case)


# --- output-ref resolution ---------------------------------------------------


def test_output_ref_resolves_into_run_commands_jail(sealed_case):
    out = resolve_output_ref("timeline", case_dir=sealed_case)
    assert out == str(sealed_case.resolve() / "agent" / "run_commands" / "timeline")


def test_output_ref_rejects_traversal(sealed_case):
    # Separators are stripped to a safe leaf; traversal can never escape.
    out = resolve_output_ref("../../etc/passwd", case_dir=sealed_case)
    assert out.startswith(str(sealed_case.resolve() / "agent" / "run_commands"))
    assert "/etc/passwd" not in out


# --- path sanitization -------------------------------------------------------


def test_sanitize_in_case_absolute_becomes_relative(sealed_case):
    abs_path = str(sealed_case / "agent" / "run_commands" / "out.txt")
    assert sanitize_path_value(abs_path, case_dir=sealed_case) == "agent/run_commands/out.txt"


def test_sanitize_out_of_case_absolute_redacted(sealed_case):
    assert (
        sanitize_path_value("/cases/other-case/evidence/secret.E01", case_dir=sealed_case)
        == "[REDACTED:absolute_path]"
    )


def test_sanitize_embedded_path_in_free_text(sealed_case):
    text = f"reading {sealed_case}/evidence/disk.txt now"
    out = sanitize_path_value(text, case_dir=sealed_case)
    assert "evidence/disk.txt" in out
    assert str(sealed_case) not in out
    assert "reading" in out and "now" in out


def test_sanitize_deep_scrubs_nested_structures(sealed_case):
    payload = {
        "a": str(sealed_case / "agent" / "x"),
        "b": ["/cases/elsewhere/y", "plain text", 7],
    }
    out = sanitize_paths_deep(payload, case_dir=sealed_case)
    assert out["a"] == "agent/x"
    assert out["b"][0] == "[REDACTED:absolute_path]"
    assert out["b"][1] == "plain text"
    assert out["b"][2] == 7


def test_sanitize_leaves_non_paths_alone(sealed_case):
    assert sanitize_path_value("just a sentence", case_dir=sealed_case) == "just a sentence"


# --- MVP allowlist -----------------------------------------------------------


def test_mvp_allowlist_alias_expands_in_policy():
    policy = build_security_policy(
        {"mode": "allowlist", "allowed_binaries": ["@mvp_forensic"]}
    )
    assert policy["mode"] == "allowlist"
    assert matches_allowed_binary("mmls", policy["allowed_binaries"])
    assert matches_allowed_binary("strings", policy["allowed_binaries"])
    # A binary outside the curated set is not silently allowed.
    assert not matches_allowed_binary("ssh", policy["allowed_binaries"])


def test_mvp_allowlist_excludes_acquisition_tools():
    # Imaging/acquisition stays operator-only, not agent-reachable.
    for tool in ("dd", "dc3dd", "mount", "losetup", "fdisk"):
        assert tool not in MVP_FORENSIC_ALLOWLIST


def test_deny_floor_overrides_allowlist():
    # @mvp_forensic must never re-enable a denied interpreter.
    policy = build_security_policy(
        {"mode": "allowlist", "allowed_binaries": ["@mvp_forensic", "bash"]}
    )
    assert "bash" in policy["denied_binaries"]


# --- end-to-end run_command --------------------------------------------------


def test_run_command_with_evidence_ref_returns_provenance_and_job_id(sealed_case):
    audit = AuditWriter(mcp_name="sift-core")
    out = _run_command(
        {
            "command": "cat evidence/disk.txt",
            "purpose": "read sealed evidence via ref",
            "evidence_refs": ["disk.txt"],
            "output_ref": "catdump",
            "save_output": True,
        },
        examiner="analyst",
        audit=audit,
    )
    assert out["success"] is True
    # B-MVP-029 dedup: job_id is canonical inside provenance only (no root copy).
    prov = out["provenance"]
    assert prov["job_id"].startswith("rc-")
    # audit_id is canonical at the response root only (set by build_response).
    assert prov["job_id"] == f"rc-{out['audit_id']}"
    assert prov["evidence_refs"] == ["disk.txt"]
    # Input hash present and matches the sealed file.
    assert len(prov["input_sha256s"]) == 1
    # Output saved and surfaced only as a relative ref (full_output_ref is the
    # single canonical output key; full_output_path alias was dropped).
    assert out["full_output_ref"].startswith("agent/run_commands/")
    assert not out["full_output_ref"].startswith("/")

    # No absolute case path anywhere in the agent-facing payload.
    blob = json.dumps(out)
    assert str(sealed_case) not in blob


def test_run_command_accepts_gateway_resolved_db_evidence_ref_without_manifest(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case-db-06090101"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: DB-001\nexaminer: analyst\n")
    ev = case_dir / "evidence" / "db.txt"
    ev.write_bytes(b"db authoritative bytes\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")

    def _fake_execute(*_args, **_kwargs):
        return {"exit_code": 0, "stdout": "ok\n", "stderr": "", "stdout_total_bytes": 3}

    monkeypatch.setattr(agent_tools, "_execute_command", _fake_execute)
    audit = AuditWriter(mcp_name="sift-core")
    ctx = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="DB-001",
        artifact_path=str(case_dir),
        db_active=True,
    )

    with use_active_case_context(ctx):
        out = _run_command(
            {
                "command": "cat evidence/db.txt",
                "purpose": "read DB evidence via gateway ref",
                "evidence_refs": ["ev-1"],
                "_resolved_evidence_refs": [
                    {
                        "evidence_id": "ev-1",
                        "display_path": "evidence/db.txt",
                        "path": str(ev),
                    }
                ],
            },
            examiner="analyst",
            audit=audit,
        )

    assert out["success"] is True
    assert out["provenance"]["evidence_refs"] == ["ev-1"]
    assert out["provenance"]["input_count"] == 1
    blob = json.dumps(out)
    assert str(case_dir) not in blob
    assert str(ev) not in blob


def test_run_command_saved_output_uses_db_active_case_not_stale_env(
    tmp_path, monkeypatch
):
    real_case = tmp_path / "case-db-output-real"
    stale_case = tmp_path / "case-db-output-stale"
    for case_dir, case_id in ((real_case, "REAL"), (stale_case, "STALE")):
        (case_dir / "agent").mkdir(parents=True)
        (case_dir / "evidence").mkdir()
        (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\nexaminer: analyst\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(stale_case))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")

    audit = AuditWriter(mcp_name="sift-core")
    ctx = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="REAL",
        artifact_path=str(real_case),
        db_active=True,
    )

    with use_active_case_context(ctx):
        out = _run_command(
            {
                "command": "echo ok",
                "purpose": "save output under DB active case",
                "save_output": True,
                "output_ref": "dbout",
            },
            examiner="analyst",
            audit=audit,
        )

    assert out["success"] is True
    assert out["full_output_ref"].startswith("agent/run_commands/dbout/")
    blob = json.dumps(out)
    assert str(real_case) not in blob
    assert str(stale_case) not in blob
    saved = real_case / out["full_output_ref"]
    assert saved.is_file()
    assert not any((stale_case / "agent" / "run_commands").glob("**/*"))


def test_run_command_rejects_internal_evidence_refs_without_db_context(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case-db-06090102"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: DB-002\nexaminer: analyst\n")
    ev = case_dir / "evidence" / "db.txt"
    ev.write_bytes(b"db authoritative bytes\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")

    audit = AuditWriter(mcp_name="sift-core")
    out = _run_command(
        {
            "command": "cat evidence/db.txt",
            "purpose": "client-supplied private refs must not work",
            "evidence_refs": ["ev-1"],
            "_resolved_evidence_refs": [
                {
                    "evidence_id": "ev-1",
                    "display_path": "evidence/db.txt",
                    "path": str(ev),
                }
            ],
        },
        examiner="analyst",
        audit=audit,
    )

    assert out["success"] is False
    assert out["error"] == "internal evidence refs require DB authority context"


def test_run_command_unknown_evidence_ref_fails_closed(sealed_case):
    audit = AuditWriter(mcp_name="sift-core")
    out = _run_command(
        {
            "command": "echo hi",
            "purpose": "bad ref",
            "evidence_refs": ["nope.E01"],
        },
        examiner="analyst",
        audit=audit,
    )
    assert out["success"] is False
    assert "nope.E01" in out["error"]


def test_run_command_stdout_paths_sanitized(sealed_case):
    audit = AuditWriter(mcp_name="sift-core")
    # echo prints an in-case absolute path; the response must show it relative.
    abs_target = str(sealed_case / "evidence" / "disk.txt")
    out = _run_command(
        {
            "command": f"echo {abs_target}",
            "purpose": "verify stdout path scrub",
        },
        examiner="analyst",
        audit=audit,
    )
    assert out["success"] is True
    blob = json.dumps(out)
    assert str(sealed_case) not in blob
    assert "evidence/disk.txt" in blob
