"""BATCH-I1 — sandboxed run_command uplift.

Covers the four I1 deliverables:
  * evidence refs (not arbitrary paths), fail-closed against the sealed manifest;
  * output refs resolved internally to the case write-jail;
  * a tight MVP forensic allowlist (opt-in, deny-floor still on top);
  * agent-facing path sanitization + hash-linked provenance receipts.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
import sift_core.agent_tools as agent_tools
from sift_common.audit import AuditWriter
from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.agent_tools import _run_command
from sift_core.evidence_chain import init_evidence_chain, seal_manifest
from sift_core.execute.catalog import clear_catalog_cache
from sift_core.execute.evidence_binding import use_final_open_authority_validator
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
from sift_core.execute.tools import generic

_STORAGE_AUTHORITY = {
    "storage_profile": "LOCAL_IMMUTABLE",
    "storage_source_identity": "",
    "mount_instance_identity": "",
    "storage_generation": 1,
    "storage_verified_generation": 1,
    "storage_manifest_version": 1,
    "storage_manifest_hash": "sha256:manifest",
    "storage_verification_receipt_id": "receipt-1",
}

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


# --- agent-facing input contract --------------------------------------------


def test_run_command_schema_exposes_sealed_evidence_refs_not_raw_input_files():
    """The registry is the agent-facing MCP schema source of truth."""
    spec = next(item for item in agent_tools.CORE_TOOL_SPECS if item.name == "run_command")
    properties = spec.input_schema["properties"]

    assert "evidence_refs" in properties
    assert "input_files" not in properties


def test_run_command_rejects_legacy_input_files_before_execution(sealed_case, monkeypatch):
    def _must_not_execute(*_args, **_kwargs):
        pytest.fail("legacy input_files must be rejected before any command or hash read")

    monkeypatch.setattr(agent_tools, "_execute_command", _must_not_execute)
    monkeypatch.setattr(
        agent_tools.hashlib,
        "sha256",
        lambda: pytest.fail("legacy input_files must be rejected before hashing"),
    )

    out = _run_command(
        {
            "command": "cat evidence/disk.txt",
            "purpose": "prove legacy raw provenance paths are closed",
            "input_files": ["/usr/share/zoneinfo/UTC"],
        },
        examiner="analyst",
        audit=AuditWriter(mcp_name="sift-core"),
    )

    assert out["success"] is False
    assert "input_files is no longer accepted" in out["error"]
    assert "evidence_refs" in out["error"]


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


def test_run_command_defaults_to_saved_output_with_a_focused_follow_up(sealed_case):
    """The agent's normal path keeps full output out of its immediate context."""
    out = _run_command(
        {
            "command": "cat evidence/disk.txt",
            "purpose": "read a sealed artifact without expanding context",
            "evidence_refs": ["evidence/disk.txt"],
        },
        examiner="analyst",
        audit=AuditWriter(mcp_name="sift-core"),
    )

    assert out["success"] is True
    output_ref = out["full_output_ref"]
    assert output_ref.startswith("agent/run_commands/")
    assert (sealed_case / output_ref).is_file()
    assert out["next_action"] == {
        "type": "inspect_saved_output",
        "output_ref": output_ref,
        "command": f"head -n 40 {output_ref}",
    }


def test_run_command_surfaces_saved_stderr_when_stdout_is_empty(sealed_case):
    """A failed forensic command must not strand its only useful output stream."""
    out = _run_command(
        {
            "command": "ls agent/does-not-exist",
            "purpose": "exercise the stderr-only saved-output contract",
        },
        examiner="analyst",
        audit=AuditWriter(mcp_name="sift-core"),
    )

    assert out["success"] is False
    stderr_ref = out["stderr_output_ref"]
    assert stderr_ref.startswith("agent/run_commands/")
    assert stderr_ref.endswith("_stderr.txt")
    assert out["full_output_ref"] == stderr_ref
    assert stderr_ref in out["output_files"]
    assert (sealed_case / stderr_ref).is_file()
    assert out["next_action"]["output_ref"] == stderr_ref
    assert str(sealed_case) not in json.dumps(out)


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

    with (
        use_active_case_context(ctx),
        use_final_open_authority_validator(lambda _expected: None),
    ):
        out = _run_command(
            {
                "command": "cat evidence/db.txt",
                "purpose": "read DB evidence via gateway ref",
                "evidence_refs": ["ev-1"],
                "_resolved_evidence_refs": [
                    {
                        "evidence_id": "ev-1",
                        "version_id": "ver-1",
                        "display_path": "evidence/db.txt",
                        "path": str(ev),
                        "sha256": "sha256:" + hashlib.sha256(ev.read_bytes()).hexdigest(),
                        "bytes": ev.stat().st_size,
                        "st_dev": ev.stat().st_dev,
                        "st_ino": ev.stat().st_ino,
                        "st_mtime_ns": ev.stat().st_mtime_ns,
                        "st_ctime_ns": ev.stat().st_ctime_ns,
                        **_STORAGE_AUTHORITY,
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


def test_gateway_admitted_provenance_uses_bound_db_sha_without_path_reopen(
    tmp_path, monkeypatch
):
    from sift_core.execute import evidence_binding

    case_dir = tmp_path / "case-db-provenance"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: DB-002\nexaminer: analyst\n")
    evidence = case_dir / "evidence" / "sealed.raw"
    evidence.write_bytes(b"admitted bytes")
    admitted_stat = evidence.stat()
    admitted_sha = "sha256:" + hashlib.sha256(b"admitted bytes").hexdigest()
    replacement = case_dir / "replacement.raw"
    replacement.write_bytes(b"replacement bytes")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")

    real_validate = evidence_binding.validate_binding_fd

    def validate_then_replace(fd, binding):
        result = real_validate(fd, binding)
        os.replace(replacement, evidence)
        return result

    monkeypatch.setattr(evidence_binding, "validate_binding_fd", validate_then_replace)
    monkeypatch.setattr(
        agent_tools,
        "open",
        lambda *_args, **_kwargs: pytest.fail(
            "Gateway-admitted provenance must not reopen evidence content"
        ),
        raising=False,
    )
    monkeypatch.setattr(
        agent_tools,
        "_execute_command",
        lambda *_args, **_kwargs: {
            "exit_code": 0,
            "stdout": "ok\n",
            "stderr": "",
            "stdout_total_bytes": 3,
        },
    )
    binding = {
        "evidence_id": "ev-2",
        "version_id": "ver-2",
        "display_path": "evidence/sealed.raw",
        "path": str(evidence),
        "sha256": admitted_sha,
        "bytes": admitted_stat.st_size,
        "st_dev": admitted_stat.st_dev,
        "st_ino": admitted_stat.st_ino,
        "st_mtime_ns": admitted_stat.st_mtime_ns,
        "st_ctime_ns": admitted_stat.st_ctime_ns,
        "immutable_required": False,
        **_STORAGE_AUTHORITY,
    }
    context = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111112",
        case_key="DB-002",
        artifact_path=str(case_dir),
        db_active=True,
    )

    with (
        use_active_case_context(context),
        use_final_open_authority_validator(lambda _expected: None),
    ):
        result = _run_command(
            {
                "command": "cat evidence/sealed.raw",
                "purpose": "bound provenance",
                "evidence_refs": ["ev-2"],
                "_resolved_evidence_refs": [binding],
            },
            examiner="analyst",
            audit=AuditWriter(mcp_name="sift-core"),
        )

    assert result["success"] is True
    assert result["provenance"]["input_sha256s"] == [admitted_sha]
    assert evidence.read_bytes() == b"replacement bytes"


def test_run_command_final_open_revalidates_db_authority_before_process_start(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case-db-final-open"
    (case_dir / "evidence").mkdir(parents=True)
    evidence = case_dir / "evidence" / "sealed.raw"
    evidence.write_bytes(b"sealed bytes")
    admitted_stat = evidence.stat()
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    started = []
    monkeypatch.setattr(
        agent_tools,
        "_execute_command",
        lambda *_args, **_kwargs: started.append(True),
    )
    current_authority = dict(_STORAGE_AUTHORITY)

    def revalidate(expected):
        if expected != current_authority:
            raise ValueError("evidence authority changed at final open")

    context = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111114",
        case_key="DB-FINAL",
        artifact_path=str(case_dir),
        db_active=True,
    )
    resolved = {
        "evidence_id": "ev-final",
        "version_id": "ver-final",
        "display_path": "evidence/sealed.raw",
        "path": str(evidence),
        "sha256": "sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "bytes": admitted_stat.st_size,
        "st_dev": admitted_stat.st_dev,
        "st_ino": admitted_stat.st_ino,
        "st_mtime_ns": admitted_stat.st_mtime_ns,
        "st_ctime_ns": admitted_stat.st_ctime_ns,
        **_STORAGE_AUTHORITY,
    }

    # The earlier gateway check passed, then DB authority changed before core's
    # final parent-side evidence open.
    assert current_authority == _STORAGE_AUTHORITY
    current_authority["storage_generation"] = 2
    with (
        use_active_case_context(context),
        use_final_open_authority_validator(revalidate),
    ):
        result = _run_command(
            {
                "command": "cat evidence/sealed.raw",
                "purpose": "prove final-open authority denial",
                "evidence_refs": ["ev-final"],
                "_resolved_evidence_refs": [resolved],
            },
            examiner="analyst",
            audit=AuditWriter(mcp_name="sift-core"),
        )

    assert result["success"] is False
    assert result["error"] == "evidence authority changed at final open"
    assert started == []


def test_run_command_transition_after_successful_final_check_cannot_start_process(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case-db-final-lock"
    (case_dir / "evidence").mkdir(parents=True)
    evidence = case_dir / "evidence" / "sealed.raw"
    evidence.write_bytes(b"sealed bytes")
    admitted_stat = evidence.stat()
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    started = []
    monkeypatch.setattr(
        agent_tools,
        "_execute_command",
        lambda *_args, **_kwargs: started.append(True),
    )
    context = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111115",
        case_key="DB-FINAL-LOCK",
        artifact_path=str(case_dir),
        db_active=True,
    )
    resolved = {
        "evidence_id": "ev-final-lock",
        "version_id": "ver-final-lock",
        "display_path": "evidence/sealed.raw",
        "path": str(evidence),
        "sha256": "sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "bytes": admitted_stat.st_size,
        "st_dev": admitted_stat.st_dev,
        "st_ino": admitted_stat.st_ino,
        "st_mtime_ns": admitted_stat.st_mtime_ns,
        "st_ctime_ns": admitted_stat.st_ctime_ns,
        **_STORAGE_AUTHORITY,
    }

    def validate_then_attempt_transition(expected):
        assert expected == _STORAGE_AUTHORITY
        # The DB read succeeded. The matching exclusive transition lock cannot
        # commit while the execution lease is held through process dispatch.
        raise ValueError("storage transition blocked by execution lock")

    with (
        use_active_case_context(context),
        use_final_open_authority_validator(validate_then_attempt_transition),
    ):
        result = _run_command(
            {
                "command": "cat evidence/sealed.raw",
                "purpose": "prove final-open transition serialization",
                "evidence_refs": ["ev-final-lock"],
                "_resolved_evidence_refs": [resolved],
            },
            examiner="analyst",
            audit=AuditWriter(mcp_name="sift-core"),
        )

    assert result["success"] is False
    assert result["error"] == "storage transition blocked by execution lock"
    assert started == []


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


@pytest.mark.parametrize(
    "command",
    [
        "setsid PECmd.exe --help",
        "setsid dotnet /opt/zimmermantools/SrumECmd.dll --help",
        "prlimit -- PECmd.exe --help",
        "flock /tmp/lock PECmd.exe --help",
        "dotnet /opt/zimmermantools/EvtxECmd.dll --help",
    ],
)
def test_run_command_surface_rejects_unreviewed_entrypoints_before_execution(
    sealed_case, monkeypatch, command
):
    """Issue #50: sync MCP execution must fail before its executor boundary."""
    called = False

    def _execute_should_not_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("unreviewed command reached the executor")

    monkeypatch.setattr(generic, "execute", _execute_should_not_run)
    out = _run_command(
        {"command": command, "purpose": "attempt launcher-wrapper bypass"},
        examiner="analyst",
        audit=AuditWriter(mcp_name="sift-core"),
    )

    assert called is False
    assert out["success"] is False
    assert out["audit_id"]
    assert "allowlist mode" in out["error"] or "blocked by security policy" in out["error"]


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


def test_run_command_partial_failure_surfaces_on_parsed_output(sealed_case, monkeypatch):
    """C1 regression: partial_failure must reach the agent whether or not the
    output was catalog-parsed.

    generic.run_command stamps ``partial_failure`` / ``partial_failure_note`` on
    the exec_result ROOT when a pipeline stage exits nonzero but still produces
    output. The agent wrapper used to keep those signals only on the un-parsed
    path (``resp_data = exec_result``) and silently drop them on the large-output
    parsed path (``resp_data = exec_result["_parsed"]``). This exercises the
    parsed path and proves the signal now surfaces on the response root.
    """
    parsed_block = {
        "format": "text",
        "truncated": True,
        "preview": ["line one", "line two"],
        "total_lines": 9001,
    }

    def _fake_execute(*_args, **_kwargs):
        # Mirrors generic.run_command's large-output pipeline result with a
        # masked upstream failure: top-level exit 0 (the final stage succeeded),
        # an upstream stage exited nonzero, and stdout exceeded the byte budget
        # so it was catalog-parsed into ``_parsed`` (raw stdout dropped to None).
        return {
            "exit_code": 0,
            "stdout": None,
            "stderr": "",
            "stdout_total_bytes": 250_000,
            "stages": [
                {
                    "binary": "mmls",
                    "exit_code": 1,
                    "argv": ["mmls", "evidence/disk.txt"],
                    "stderr_tail": "Cannot determine partition type",
                },
                {"binary": "sort", "exit_code": 0, "argv": ["sort"]},
            ],
            "_parsed": parsed_block,
            "_output_format": "parsed_text",
            "partial_failure": True,
            "partial_failure_note": (
                "An upstream stage exited nonzero (e.g. a path was "
                "inaccessible) but a later stage exited 0; output may be "
                "incomplete. See per-stage exit codes and stderr_tail in "
                "'stages'."
            ),
        }

    monkeypatch.setattr(agent_tools, "_execute_command", _fake_execute)
    audit = AuditWriter(mcp_name="sift-core")
    out = _run_command(
        {
            "command": "mmls evidence/disk.txt | sort",
            "purpose": "trigger a parsed-output partial failure",
        },
        examiner="analyst",
        audit=audit,
    )

    # The output WAS catalog-parsed: the inline data block is the parsed view…
    assert out["data"] == parsed_block
    # …and the partial-failure signal does NOT hide inside that data block.
    assert "partial_failure" not in out["data"]
    assert "partial_failure_note" not in out["data"]
    # The fix: it is surfaced on the response root regardless of parsing.
    assert out["partial_failure"] is True
    assert "partial_failure_note" in out
    assert "incomplete" in out["partial_failure_note"]
