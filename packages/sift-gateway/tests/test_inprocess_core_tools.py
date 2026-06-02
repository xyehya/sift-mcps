from __future__ import annotations

import json
from pathlib import Path

from sift_core.case_ops import case_init_data
from sift_gateway.server import Gateway


def _execute_security():
    return {
        "execute": {
            "runtime_user": "__current__",
            "security": {"denied_binaries": ["env"]},
        }
    }


async def test_core_tools_are_in_process_when_core_backends_disabled(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="Core Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="CORE-001",
    )
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    monkeypatch.setenv("SIFT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    with pytest.raises(ValueError, match="Core backend.*is not allowed"):
        Gateway(
            {
                "case": {"root": str(cases_root), "dir": case["case_dir"]},
                **_execute_security(),
                "backends": {
                    "case-mcp": {"enabled": True, "type": "stdio", "command": "missing-case-mcp"},
                },
            }
        )

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            **_execute_security(),
            "backends": {},
        }
    )

    assert gateway.backends == {}

    tool_names = {tool.name for tool in await gateway.get_tools_list()}
    assert {
        "case_status",
        "evidence_list",
        "record_finding",
        "record_timeline_event",
        "workflow_status",
        "manage_todo",
        "log_reasoning",
        "log_external_action",
        "run_command",
        "list_available_tools",
        "get_tool_help",
        "check_tools",
        "suggest_tools",
    }.issubset(tool_names)

    tool_map = await gateway.list_tools()
    assert tool_map["case_status"] == "sift-core"
    assert tool_map["record_finding"] == "sift-core"
    assert tool_map["run_command"] == "sift-core"

    result = await gateway.call_tool("case_status", {}, examiner="alice")
    payload = json.loads(result[0].text)
    assert payload["case_id"] == "CORE-001"
    assert Path(payload["path"]) == Path(case["case_dir"])

    result = await gateway.call_tool(
        "run_command",
        {"command": ["date"], "purpose": "test in-process execute"},
        examiner="alice",
    )
    payload = json.loads(result[0].text)
    assert payload["tool"] == "run_command"
    assert payload["success"] is True
    assert payload["metadata"]["exit_code"] == 0
    assert payload["audit_id"]


async def test_run_command_denied_binary_blocked_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="Deny Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="DENY-001",
    )
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    monkeypatch.setenv("SIFT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            "backends": {},
            "execute": {"security": {"denied_binaries": ["echo"]}},
        }
    )

    result = await gateway.call_tool(
        "run_command",
        {"command": ["env"], "purpose": "verify deny floor"},
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    assert payload["tool"] == "run_command"
    assert payload["success"] is False
    assert "blocked by security policy" in payload["error"]


async def test_run_command_allowlist_mode_permits_configured_command(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="Allowlist Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="ALLOW-001",
    )
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    monkeypatch.setenv("SIFT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            "backends": {},
            "execute": {
                "runtime_user": "__current__",
                "security": {
                    "mode": "allowlist",
                    "allowed_binaries": ["date"],
                    "denied_binaries": ["echo"],
                }
            },
        }
    )

    result = await gateway.call_tool(
        "run_command",
        {"command": ["date"], "purpose": "verify allowlist permit"},
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    assert payload["tool"] == "run_command"
    assert payload["success"] is True
    assert payload["metadata"]["exit_code"] == 0


async def test_run_command_allowlist_mode_blocks_unlisted_command(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="Allowlist Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="ALLOW-002",
    )
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    monkeypatch.setenv("SIFT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            "backends": {},
            "execute": {
                "runtime_user": "__current__",
                "security": {
                    "mode": "allowlist",
                    "allowed_binaries": ["date"],
                    "denied_binaries": ["echo"],
                }
            },
        }
    )

    result = await gateway.call_tool(
        "run_command",
        {"command": ["cat", "--version"], "purpose": "verify allowlist deny"},
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    assert payload["tool"] == "run_command"
    assert payload["success"] is False
    assert "not allowed by execute.security allowlist mode" in payload["error"]


async def test_run_command_allowlist_mode_keeps_deny_floor_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="Allowlist Floor Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="ALLOW-003",
    )
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    monkeypatch.setenv("SIFT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            "backends": {},
            "execute": {
                "runtime_user": "__current__",
                "security": {
                    "mode": "allowlist",
                    "allowed_binaries": ["date", "env"],
                    "denied_binaries": ["echo"],
                }
            },
        }
    )

    result = await gateway.call_tool(
        "run_command",
        {"command": ["env"], "purpose": "verify deny floor wins"},
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    assert payload["tool"] == "run_command"
    assert payload["success"] is False
    assert "blocked by security policy" in payload["error"]


async def test_run_command_preserves_case_cwd_jail(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="CWD Jail Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="CWD-001",
    )
    case_dir = Path(case["case_dir"])
    work_dir = case_dir / "agent" / "scratch"
    work_dir.mkdir(parents=True)
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    monkeypatch.setenv("SIFT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            "backends": {},
            **_execute_security(),
        }
    )

    result = await gateway.call_tool(
        "run_command",
        {
            "command": ["pwd"],
            "purpose": "verify cwd jail",
            "working_dir": "agent/scratch",
        },
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    assert payload["success"] is True
    assert payload["data"]["stdout"].strip() == str(work_dir)

    result = await gateway.call_tool(
        "run_command",
        {
            "command": ["pwd"],
            "purpose": "verify cwd escape blocked",
            "working_dir": "../outside",
        },
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    assert payload["success"] is False
    assert payload["error"] == "Path must be within the case directory"


async def test_run_command_privileged_escalation_integration(tmp_path, monkeypatch):
    import shutil
    import os
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name="Priv Case",
        examiner="alice",
        cases_dir=cases_root,
        case_id="PRIV-001",
    )
    monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("SIFT_CASE_DIR", case["case_dir"])
    state_dir = tmp_path / "state"
    monkeypatch.setenv("SIFT_STATE_DIR", str(state_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")

    gateway = Gateway(
        {
            "case": {"root": str(cases_root), "dir": case["case_dir"]},
            "backends": {},
            **_execute_security(),
        }
    )

    # Mock finding mount and sudo binaries
    monkeypatch.setattr(shutil, "which", lambda cmd: f"/usr/bin/{cmd}" if cmd in ("mount", "sudo") else None)
    monkeypatch.setattr(os.path, "exists", lambda path: path == "/usr/bin/sudo" or os.path.exists(path))

    # Mock isolated execution inside generic to fail directly first, then succeed via sudo
    from sift_core.execute.tools import generic
    calls = []
    def fake_execute(cmd_list, **kwargs):
        calls.append(cmd_list)
        first_argv = cmd_list[0]["argv"]
        if first_argv[0] != "/usr/bin/sudo":
            return {"exit_code": 1, "stdout": "", "stderr": "mount: requires root\n", "stdout_total_bytes": 0}
        else:
            return {"exit_code": 0, "stdout": "ok\n", "stderr": "", "stdout_total_bytes": 3}
    monkeypatch.setattr(generic, "execute", fake_execute)

    result = await gateway.call_tool(
        "run_command",
        {
            "command": ["mount", "/dev/sdb1", str(Path(case["case_dir"]) / "tmp")],
            "purpose": "test mount integration",
        },
        examiner="alice",
    )
    payload = json.loads(result[0].text)

    # 1. Verify the response metadata privilege details are returned
    assert payload["success"] is True
    assert payload["privilege_escalation"]["mechanism"] == "sudo_fallback"
    assert payload["privilege_escalation"]["status"] == "success"

    # 2. Verify that calls were made directly then with sudo
    assert len(calls) == 2
    assert calls[0] == [{"argv": ["/usr/bin/mount", "/dev/sdb1", str(Path(case["case_dir"]) / "tmp")], "redirects": []}]
    assert calls[1] == [{"argv": ["/usr/bin/sudo", "-n", "--", "/usr/bin/mount", "/dev/sdb1", str(Path(case["case_dir"]) / "tmp")], "redirects": [], "runtime_user": ""}]

    # 3. Verify audit entries are written under SIFT_STATE_DIR / PRIV-001 / audit / sift-gateway.jsonl
    audit_file = state_dir / "PRIV-001" / "audit" / "sift-gateway.jsonl"
    assert audit_file.is_file()
    lines = audit_file.read_text().splitlines()
    entries = [json.loads(line) for line in lines]

    # There should be entries for:
    # - fallback_attempt privilege event
    # - success outcome privilege event
    # - main run_command audit entry (which should contain privilege_escalation and privilege_events)
    pe_events = [e for e in entries if e.get("tool") == "privilege_escalation"]
    assert len(pe_events) == 2
    assert pe_events[0]["result_summary"]["status"] == "fallback_attempt"
    assert pe_events[1]["result_summary"]["status"] == "success"

    main_entry = [e for e in entries if e.get("tool") == "run_command"][0]
    assert main_entry["privilege_escalation"]["mechanism"] == "sudo_fallback"
