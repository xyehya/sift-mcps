from __future__ import annotations

import json

import pytest
import yaml

from forensic_mcp.server import create_server


@pytest.fixture
def tools(tmp_path, monkeypatch):
    (tmp_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": "case-tool-001", "title": "Tool Consolidation"})
    )
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path))
    monkeypatch.setenv("SIFT_EXAMINER", "alice")
    server = create_server()
    return {tool.name: tool for tool in server._tool_manager.list_tools()}


def _call(tool, **kwargs):
    import asyncio
    import inspect

    result = tool.fn(**kwargs)
    if inspect.isawaitable(result):
        return asyncio.get_event_loop().run_until_complete(result)
    return result


def test_findings_reader_is_renamed_and_old_readers_are_hidden(tools):
    names = set(tools)

    assert "list_existing_findings" in names
    assert "query_case" in names
    assert "manage_todo" in names
    for old_name in (
        "get_findings",
        "get_timeline",
        "get_actions",
        "add_todo",
        "list_todos",
        "update_todo",
        "complete_todo",
    ):
        assert old_name not in names

    assert getattr(tools["list_existing_findings"].annotations, "readOnlyHint", None) is True
    assert getattr(tools["query_case"].annotations, "readOnlyHint", None) is True
    assert getattr(tools["manage_todo"].annotations, "readOnlyHint", None) is not True


def test_list_existing_findings_returns_paginated_findings(tools, tmp_path, monkeypatch):
    case_dir = tmp_path
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    (case_dir / "findings.json").write_text(
        json.dumps(
            [
                {"id": "F-001", "status": "DRAFT", "title": "Draft finding"},
                {"id": "F-002", "status": "APPROVED", "title": "Approved finding"},
            ]
        )
    )

    result = _call(tools["list_existing_findings"], status="DRAFT")

    assert result["total"] == 1
    assert result["findings"][0]["id"] == "F-001"


def test_query_case_routes_timeline_and_actions(tools, tmp_path, monkeypatch):
    case_dir = tmp_path
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    (case_dir / "timeline.json").write_text(
        json.dumps(
            [
                {
                    "id": "T-001",
                    "status": "DRAFT",
                    "timestamp": "2026-05-01T00:00:00Z",
                    "event_type": "auth",
                    "source": "Security.evtx",
                }
            ]
        )
    )
    (case_dir / "actions.jsonl").write_text(
        json.dumps({"action": "noted", "timestamp": "2026-05-01T00:00:01Z"}) + "\n"
    )

    timeline = _call(tools["query_case"], record_type="timeline", event_type="auth")
    assert timeline["total"] == 1
    assert timeline["events"][0]["id"] == "T-001"

    actions = _call(tools["query_case"], record_type="actions", limit=5)
    assert actions["record_type"] == "actions"
    assert len(actions["actions"]) == 1


def test_manage_todo_add_list_update_complete(tools):
    added = _call(
        tools["manage_todo"],
        action="add",
        description="Correlate 4624 logons",
        priority="high",
    )
    todo_id = added["todo_id"]

    listed = _call(tools["manage_todo"], action="list", status="open")
    assert any(todo["todo_id"] == todo_id for todo in listed["todos"])

    updated = _call(
        tools["manage_todo"],
        action="update",
        todo_id=todo_id,
        note="Checked Security.evtx",
    )
    assert updated["todo_id"] == todo_id

    completed = _call(tools["manage_todo"], action="complete", todo_id=todo_id)
    assert completed["todo_id"] == todo_id
    listed_completed = _call(tools["manage_todo"], action="list", status="completed")
    assert any(todo["todo_id"] == todo_id for todo in listed_completed["todos"])
