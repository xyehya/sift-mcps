"""Regression tests for QA findings from the live Hermes forensic-agent session.

Each test pins a concrete contract that the real agent exercised and that
either failed or returned a misleading result during the SIFT MCP QA assessment.
These are the root-cause fixes, not symptom patches.
"""

from __future__ import annotations

import json
from pathlib import Path

from sift_core.case_ops import case_init_data
from sift_gateway.server import Gateway


def _make_gateway(tmp_path, monkeypatch, case_id: str) -> tuple[Gateway, dict]:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cases_root = tmp_path / "cases"
    case = case_init_data(
        name=f"QA Case {case_id}",
        examiner="alice",
        cases_dir=cases_root,
        case_id=case_id,
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
                "security": {"denied_binaries": ["env"]},
            },
        }
    )
    return gateway, case


async def _call(gateway: Gateway, name: str, args: dict, examiner: str = "hermes-default") -> dict:
    result = await gateway.call_tool(name, args, examiner=examiner)
    return json.loads(result[0].text)


# ── Finding 1: manage_todo schema/handler contract ────────────────────────


async def test_manage_todo_create_matches_schema(tmp_path, monkeypatch):
    """Schema advertises action='create'; the handler must accept it."""
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "TODO-CREATE")
    payload = await _call(
        gateway,
        "manage_todo",
        {"action": "create", "description": "QA todo", "priority": "low"},
    )
    assert "error" not in payload, payload
    assert payload.get("todo_id"), payload


async def test_manage_todo_add_alias_still_works(tmp_path, monkeypatch):
    """Backward-compat: legacy action='add' must keep working."""
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "TODO-ADD")
    payload = await _call(
        gateway,
        "manage_todo",
        {"action": "add", "description": "QA todo legacy", "priority": "low"},
    )
    assert payload.get("todo_id"), payload


async def test_manage_todo_schema_enum_lists_create(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "TODO-SCHEMA")
    tools = {t.name: t for t in await gateway.get_tools_list()}
    enum = tools["manage_todo"].inputSchema["properties"]["action"]["enum"]
    assert "create" in enum
    payload = await _call(gateway, "manage_todo", {"action": "bogus"})
    # Error message must name the same canonical verb the schema advertises.
    assert "create" in json.dumps(payload)


# ── Finding 2: legacy suggest_tools was removed by the core refactor ───────


async def test_removed_suggest_tools_not_advertised(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "SUGGEST-1")
    tools = {tool.name for tool in await gateway.get_tools_list()}
    assert "suggest_tools" not in tools
    assert "get_tool_help" in tools


async def test_unknown_removed_suggest_tools_is_unknown(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "SUGGEST-2")
    try:
        await _call(gateway, "suggest_tools", {"artifact_type": "no_such_artifact_xyz"})
    except KeyError as exc:
        assert "Unknown tool: suggest_tools" in str(exc)
    else:
        raise AssertionError("removed suggest_tools unexpectedly resolved")


# ── Finding 3: internal errors must not masquerade as "unknown tool" ───────


async def test_internal_keyerror_not_reported_as_unknown_tool(tmp_path, monkeypatch):
    """A KeyError raised *inside* a core tool must surface as a structured
    error for that tool, never as the gateway's 'unknown tool' message."""
    from sift_core import agent_tools

    gateway, _ = _make_gateway(tmp_path, monkeypatch, "KEYERR")

    def _boom(*a, **k):
        raise KeyError("exit_code")

    monkeypatch.setattr(agent_tools, "_run_command", _boom)
    result = await gateway.call_tool(
        "run_command",
        {"command": ["date"], "purpose": "trigger internal keyerror"},
        examiner="alice",
    )
    text = result[0].text
    assert "unknown tool" not in text.lower(), text
    payload = json.loads(text)
    assert payload.get("tool") == "run_command"
    assert payload.get("success") is False
    assert "error" in payload


# ── Finding 4: preview_lines must cap inline output ───────────────────────


async def test_preview_lines_caps_inline_stdout(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "PREVIEW")
    payload = await _call(
        gateway,
        "run_command",
        {
            "command": ["seq", "1", "2000"],
            "purpose": "preview cap",
            "preview_lines": 5,
        },
        examiner="alice",
    )
    data = payload["data"]
    stdout = data.get("stdout") or ""
    assert stdout.count("\n") <= 5, f"stdout not capped: {stdout!r}"
    assert data.get("stdout_truncated") is True
    assert data.get("stdout_total_bytes", 0) > len(stdout.encode())


# ── Finding 5: compound command provenance ────────────────────────────────


async def test_compound_command_records_all_segments(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "PROVENANCE")
    payload = await _call(
        gateway,
        "run_command",
        {
            "command": "pwd && whoami && date",
            "purpose": "compound provenance",
        },
        examiner="alice",
    )
    data = payload["data"]
    assert data.get("original_command") == "pwd && whoami && date"
    binaries = [Path(s["argv"][0]).name for s in data.get("command", [])]
    assert {"pwd", "whoami", "date"}.issubset(set(binaries)), data.get("command")


# ── Finding 6: examiner identity consistency across success and error ──────


async def test_examiner_consistent_on_error_path(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "EXAMINER")
    ok = await _call(
        gateway,
        "run_command",
        {"command": ["date"], "purpose": "ok"},
        examiner="hermes-default",
    )
    blocked = await _call(
        gateway,
        "run_command",
        {"command": ["env"], "purpose": "blocked"},
        examiner="hermes-default",
    )
    assert ok["examiner"] == "hermes-default"
    assert blocked["examiner"] == "hermes-default", blocked


# ── Finding 8: awk system() escape stays blocked (description now claims it) ──


async def test_awk_system_escape_blocked(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "AWK")
    payload = await _call(
        gateway,
        "run_command",
        {"command": ["awk", "BEGIN { system(\"id\") }"], "purpose": "awk escape probe"},
        examiner="alice",
    )
    assert payload["success"] is False
    assert "awk" in payload["error"].lower()


# ── Finding 10: empty/invalid category must not strand the agent ──────────


async def test_list_available_tools_unknown_category_lists_valid(tmp_path, monkeypatch):
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "CATS")
    tools = {tool.name for tool in await gateway.get_tools_list()}
    assert "list_available_tools" not in tools
    assert {"case_info", "evidence_info", "get_tool_help"}.issubset(tools)


# ── Finding 3 (clarity): capability_guide empty state is self-explanatory ──


def test_capability_guide_empty_state_has_note():
    from sift_gateway.mcp_endpoint import _capability_guide
    from sift_gateway.server import Gateway

    gateway = Gateway(
        {
            "backends": {},
            "execute": {"runtime_user": "__current__", "security": {"denied_binaries": ["env"]}},
        }
    )
    guide = _capability_guide(gateway)
    assert guide["scope"] == "add-on backends only"
    assert guide["available_backends"] == []
    assert "note" in guide and "expected" in guide["note"].lower()


# ── Session 35: large-output save path (root cause behind KeyError/no path) ──


async def test_large_output_no_preview_returns_path_not_keyerror(tmp_path, monkeypatch):
    """Over-budget output WITHOUT preview_lines must succeed and surface
    full_output_path. The pre-fix code popped _output_format/output_file before
    reading them, so this exact path raised `KeyError: '_output_format'` and the
    full output (saved on disk) was never reachable via the response."""
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "LARGE-OUT")
    payload = await _call(
        gateway,
        "run_command",
        {"command": ["seq", "1", "5000"], "purpose": "large output, no preview"},
        examiner="alice",
    )
    assert "keyerror" not in json.dumps(payload).lower(), payload
    assert payload["success"] is True, payload
    path = payload.get("full_output_path")
    assert path, f"full_output_path missing on saved large output: {payload}"
    assert Path(path).is_file(), path
    assert payload.get("full_output_bytes", 0) > 10_240, payload


async def test_preview_plus_save_surfaces_recoverable_full_output(tmp_path, monkeypatch):
    """preview_lines + save_output must cap inline stdout AND return a
    full_output_path whose file holds the COMPLETE (un-truncated) output."""
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "SAVE-PREVIEW")
    payload = await _call(
        gateway,
        "run_command",
        {
            "command": ["seq", "1", "5000"],
            "purpose": "preview plus save",
            "preview_lines": 5,
            "save_output": True,
        },
        examiner="alice",
    )
    assert payload["success"] is True, payload
    data = payload["data"]
    assert (data.get("stdout") or "").count("\n") <= 5, data
    assert data.get("stdout_truncated") is True, data
    path = payload.get("full_output_path")
    assert path and Path(path).is_file(), payload
    with open(path) as fh:
        assert sum(1 for _ in fh) == 5000, "saved file must hold the full output"


async def test_unsaved_command_mints_no_empty_output_dir(tmp_path, monkeypatch):
    """A small command with no save_output must not create an empty
    agent/run_commands/outputN/ directory (executor dir-creation was eager)."""
    gateway, case = _make_gateway(tmp_path, monkeypatch, "NO-EMPTY-DIR")
    payload = await _call(
        gateway,
        "run_command",
        {"command": ["date"], "purpose": "tiny output"},
        examiner="alice",
    )
    assert payload["success"] is True, payload
    run_commands = Path(case["case_dir"]) / "agent" / "run_commands"
    dirs = list(run_commands.glob("output*")) if run_commands.exists() else []
    assert dirs == [], f"unexpected empty output dirs minted: {dirs}"
