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


# ── Finding 2: suggest_tools artifact resolution ──────────────────────────


async def test_suggest_tools_resolves_advertised_display_name(tmp_path, monkeypatch):
    """Exact display names from available_artifacts must resolve to suggestions."""
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "SUGGEST-1")
    for artifact in ("Security Event Log", "RDP Event Logs", "MFT"):
        payload = await _call(
            gateway, "suggest_tools", {"artifact_type": artifact}
        )
        assert payload.get("suggestions"), f"no suggestions for {artifact!r}: {payload}"


async def test_suggest_tools_miss_lists_canonical_ids(tmp_path, monkeypatch):
    """A miss should advertise identifiers that the resolver actually accepts."""
    gateway, _ = _make_gateway(tmp_path, monkeypatch, "SUGGEST-2")
    payload = await _call(
        gateway, "suggest_tools", {"artifact_type": "no_such_artifact_xyz"}
    )
    assert payload["suggestions"] == []
    advertised = payload["available_artifacts"]
    assert advertised
    # Every advertised identifier must itself resolve.
    sample = advertised[0]
    key = sample["id"] if isinstance(sample, dict) else sample
    follow = await _call(gateway, "suggest_tools", {"artifact_type": key})
    assert follow.get("suggestions"), f"advertised id {key!r} did not resolve: {follow}"


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
    payload = await _call(
        gateway, "list_available_tools", {"category": "not_a_category_xyz"}
    )
    assert payload["count"] == 0
    assert payload.get("available_categories"), payload
    # A real category drawn from the list must return tools.
    real = payload["available_categories"][0]
    follow = await _call(gateway, "list_available_tools", {"category": real})
    assert follow["count"] > 0


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
