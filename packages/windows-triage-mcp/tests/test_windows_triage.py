from __future__ import annotations

import json

import pytest

from windows_triage_mcp.db import BaselineDB
from windows_triage_mcp.server import WindowsTriageServer


def _write_json(root, name, records):
    (root / f"{name}.json").write_text(json.dumps({"records": records}))


@pytest.fixture()
def server(tmp_path):
    _write_json(
        tmp_path,
        "files",
        [
            {
                "path": r"C:\Windows\System32\cmd.exe",
                "sha256": "a" * 64,
                "os_version": "Windows 10",
            }
        ],
    )
    _write_json(
        tmp_path,
        "process_trees",
        [{"process_name": "cmd.exe", "parent_name": "explorer.exe"}],
    )
    _write_json(
        tmp_path,
        "services",
        [
            {
                "service_name": "EventLog",
                "binary_path": r"C:\Windows\System32\svchost.exe",
                "os_version": "Windows 10",
            }
        ],
    )
    _write_json(
        tmp_path,
        "scheduled_tasks",
        [{"task_path": r"\Microsoft\Windows\Defrag\ScheduledDefrag", "os_version": "Windows 10"}],
    )
    _write_json(
        tmp_path,
        "autoruns",
        [
            {
                "key_path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                "value_name": "SecurityHealth",
                "os_version": "Windows 10",
            }
        ],
    )
    _write_json(
        tmp_path,
        "registry",
        [
            {
                "hive": "HKLM",
                "key_path": r"HKLM\System\CurrentControlSet\Control\Session Manager",
                "value_name": "BootExecute",
                "os_version": "Windows 10",
            }
        ],
    )
    _write_json(tmp_path, "loldrivers", [{"sha256": "b" * 64, "name": "bad.sys"}])
    _write_json(tmp_path, "lolbins", [{"filename": "mshta.exe", "capabilities": ["hta"]}])
    _write_json(tmp_path, "hijackable_dlls", [{"dll_name": "version.dll"}])
    _write_json(tmp_path, "pipes", [{"pipe_name": r"\pipe\spoolss"}])
    (tmp_path / "metadata.json").write_text(json.dumps({"version": "test"}))
    return WindowsTriageServer(BaselineDB(tmp_path))


def test_all_13_tools_are_registered(server):
    tools = {tool.name for tool in server.mcp._tool_manager.list_tools()}
    assert tools == {
        "check_file",
        "check_process_tree",
        "check_service",
        "check_scheduled_task",
        "check_autorun",
        "check_registry",
        "check_hash",
        "analyze_filename",
        "check_lolbin",
        "check_hijackable_dll",
        "check_pipe",
        "get_db_stats",
        "get_health",
    }


def test_check_file_expected_lolbin_and_hash_mismatch(server):
    result = server.check_file(r"C:\Windows\System32\cmd.exe", "a" * 64, "Windows 10")
    assert result["verdict"] == "EXPECTED_LOLBIN"
    assert result["is_lolbin"] is True

    result = server.check_file(r"C:\Windows\System32\cmd.exe", "c" * 64, "Windows 10")
    assert result["verdict"] == "SUSPICIOUS"
    assert "hash differs" in result["reasons"][0]


def test_check_process_tree_expected(server):
    result = server.check_process_tree("cmd.exe", "explorer.exe")
    assert result["verdict"] == "EXPECTED"


def test_check_service_requires_os_and_detects_path_mismatch(server):
    with pytest.raises(ValueError, match="os_version"):
        server.check_service("EventLog")
    result = server.check_service("EventLog", r"C:\Temp\svchost.exe", "Windows 10")
    assert result["verdict"] == "SUSPICIOUS"


def test_check_scheduled_task_autorun_and_registry(server):
    assert server.check_scheduled_task(
        r"\Microsoft\Windows\Defrag\ScheduledDefrag", "Windows 10"
    )["verdict"] == "EXPECTED"
    assert server.check_autorun(
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "SecurityHealth",
        "Windows 10",
    )["verdict"] == "EXPECTED"
    assert server.check_registry(
        r"HKLM\System\CurrentControlSet\Control\Session Manager",
        "BootExecute",
        "HKLM",
        "Windows 10",
    )["verdict"] == "EXPECTED"


def test_hash_lolbin_hijackable_dll_and_pipe(server):
    assert server.check_hash("b" * 64)["verdict"] == "SUSPICIOUS"
    assert server.check_lolbin("mshta.exe")["verdict"] == "EXPECTED_LOLBIN"
    assert server.check_hijackable_dll("version.dll")["verdict"] == "SUSPICIOUS"
    assert server.check_pipe(r"\pipe\postex_123")["verdict"] == "SUSPICIOUS"
    assert server.check_pipe(r"\pipe\spoolss")["verdict"] == "EXPECTED"


def test_analyze_filename_detects_deception(server):
    result = server.analyze_filename("invoice.pdf.exe")
    assert result["verdict"] == "SUSPICIOUS"


def test_missing_db_is_degraded_and_not_trusted(tmp_path):
    server = WindowsTriageServer(BaselineDB(tmp_path / "missing"))
    health = server.get_health()
    assert health["status"] == "degraded"
    result = server.check_file(r"C:\Windows\System32\cmd.exe")
    assert result["status"] == "degraded"
    assert result["verdict"] == "UNKNOWN"
    assert result["db_available"] is False

