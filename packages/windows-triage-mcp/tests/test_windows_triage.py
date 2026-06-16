from __future__ import annotations

import json
from pathlib import Path
import pytest

from mcp.types import CallToolRequest, ListToolsRequest
from windows_triage_mcp.config import Config
from windows_triage_mcp.db import KnownGoodDB, ContextDB, RegistryDB
from windows_triage_mcp.server import WindowsTriageServer


@pytest.fixture()
def server(tmp_path):
    kg_path = tmp_path / "known_good.db"
    ctx_path = tmp_path / "context.db"
    reg_path = tmp_path / "known_good_registry.db"

    # 1. Initialize databases using their schemas
    kg_db = KnownGoodDB(kg_path, read_only=False, cache_size=0)
    kg_db.init_schema()

    ctx_db = ContextDB(ctx_path, read_only=False, cache_size=0)
    ctx_db.init_schema()

    reg_db = RegistryDB(reg_path, read_only=False, cache_size=0)
    reg_db.init_schema()

    # 2. Add OS Version
    kg_db.add_os_version(
        short_name="Win10_21H2_Pro",
        os_family="Windows 10",
    )

    # 3. Add baseline files
    kg_db.upsert_files_batch(
        [
            {
                "path": r"C:\Windows\System32\cmd.exe",
                "sha256": "a" * 64,
                "file_size": 232323,
            }
        ],
        os_short_name="Win10_21H2_Pro"
    )

    # 4. Add process trees
    ctx_db.add_expected_process(
        process_name="cmd.exe",
        valid_parents=["explorer.exe"],
    )

    # 5. Add services
    kg_db.upsert_service(
        service_name="EventLog",
        os_short_name="Win10_21H2_Pro",
        binary_path=r"C:\Windows\System32\svchost.exe",
    )

    # 6. Add scheduled tasks
    kg_db.upsert_task(
        task_path=r"\Microsoft\Windows\Defrag\ScheduledDefrag",
        os_short_name="Win10_21H2_Pro",
        task_name="ScheduledDefrag",
    )

    # 7. Add autoruns
    kg_db.upsert_autorun(
        hive="HKLM",
        key_path=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        os_short_name="Win10_21H2_Pro",
        value_name="SecurityHealth",
    )

    # 8. Add registry key/value
    reg_db.connect().execute(
        "INSERT INTO baseline_registry (hive, key_path_lower, value_name, value_type, value_data, os_versions, value_data_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "SYSTEM",
            "hklm\\system\\currentcontrolset\\control\\session manager",
            "BootExecute",
            "REG_MULTI_SZ",
            "autocheck autochk *",
            json.dumps(["Win10_21H2_Pro"]),
            "hash"
        )
    )
    reg_db.connect().commit()

    # 9. Add lolbin
    ctx_db.add_lolbin(
        filename="mshta.exe",
        name="mshta",
        functions=["hta"],
    )
    ctx_db.add_lolbin(
        filename="cmd.exe",
        name="cmd",
        functions=["execute"],
    )

    # 10. Add vulnerable driver
    ctx_db.add_vulnerable_driver(
        filename="bad.sys",
        sha256="b" * 64,
        vendor="MagicalVendor",
    )

    # 11. Add hijackable DLL
    ctx_db.connect().execute(
        "INSERT INTO hijackable_dlls (dll_name_lower, hijack_type, vulnerable_exe) VALUES (?, ?, ?)",
        ("version.dll", "sideloading", "someapp.exe")
    )
    ctx_db.connect().commit()

    # 12. Create Config
    config = Config(
        known_good_db=kg_path,
        context_db=ctx_path,
        registry_db=reg_path,
        skip_db_validation=True,
        cache_size=0,
    )

    # 13. Instantiate server
    srv = WindowsTriageServer(
        config=config,
        known_good_path=kg_path,
        context_path=ctx_path,
        registry_path=reg_path,
    )
    yield srv
    srv.close_databases()


@pytest.mark.asyncio
async def test_consolidated_tools_are_registered(server):
    handler = server.server.request_handlers[ListToolsRequest]
    res = await handler(ListToolsRequest())
    tools = {tool.name for tool in res.root.tools}
    assert tools == {
        "wintriage_check_artifact",
        "wintriage_check_process_tree",
        "wintriage_check_system",
        "wintriage_check_registry",
        "wintriage_check_pipe",
        "wintriage_server_status",
    }


async def _call_tool(server, name: str, arguments: dict) -> dict:
    handler = server.server.request_handlers[CallToolRequest]
    res = await handler(CallToolRequest(params={"name": name, "arguments": arguments}))
    return json.loads(res.root.content[0].text)


@pytest.mark.asyncio
async def test_check_artifact_routes_file_hash_lolbin_and_dll(server):
    file_result = await _call_tool(
        server,
        "wintriage_check_artifact",
        {
            "type": "file",
            "value": r"C:\Windows\System32\cmd.exe",
            "hash": "a" * 64,
            "os_version": "Win10_21H2_Pro",
        },
    )
    assert file_result["verdict"] == "EXPECTED_LOLBIN"
    assert file_result["artifact_type"] == "file"
    assert file_result["interpretation_constraint"] == "UNKNOWN means not-in-database, NOT suspicious"

    hash_result = await _call_tool(server, "wintriage_check_artifact", {"type": "hash", "value": "b" * 64})
    assert hash_result["verdict"] == "SUSPICIOUS"
    assert hash_result["artifact_type"] == "hash"

    lolbin_result = await _call_tool(server, "wintriage_check_artifact", {"type": "lolbin", "value": "mshta.exe"})
    assert lolbin_result["is_lolbin"] is True
    assert lolbin_result["artifact_type"] == "lolbin"

    dll_result = await _call_tool(server, "wintriage_check_artifact", {"type": "dll", "value": "version.dll"})
    assert dll_result["is_hijackable"] is True
    assert dll_result["artifact_type"] == "dll"


@pytest.mark.asyncio
async def test_lolbin_bare_name_gets_format_hint(server):
    # XYE-29 item 6: a bare name (no extension) can never match the LOLBAS
    # catalog; the UNKNOWN result must carry a non-breaking 'name.exe' hint.
    bare = await server._check_lolbin("certutil")
    assert bare["is_lolbin"] is False
    assert bare["queried"] == "certutil"
    assert "certutil.exe" in bare["hint"]

    # A proper filename that is simply absent stays a miss with NO format hint.
    absent = await server._check_lolbin("notathing.exe")
    assert absent["is_lolbin"] is False
    assert "hint" not in absent

    # A real catalog hit never carries the hint.
    hit = await server._check_lolbin("mshta.exe")
    assert hit["is_lolbin"] is True
    assert "hint" not in hit


def test_artifact_out_promotes_lolbin_hint_to_reasons():
    # XYE-29 item 6: the served FastMCP surface promotes the bare-name hint into
    # the UNKNOWN result's reasons so it is visible without digging into subtype_data.
    from windows_triage_mcp.registry import ArtifactType, _artifact_out

    out = _artifact_out(
        ArtifactType.lolbin,
        {"is_lolbin": False, "queried": "certutil", "hint": "try 'certutil.exe'"},
    )
    assert out.verdict.value == "UNKNOWN"
    assert out.is_lolbin is False
    assert any("certutil.exe" in reason for reason in out.reasons)
    assert out.subtype_data.get("hint") == "try 'certutil.exe'"

    # No hint on a real hit; reasons stay clean.
    hit = _artifact_out(
        ArtifactType.lolbin,
        {"is_lolbin": True, "name": "mshta", "functions": ["hta"]},
    )
    assert hit.verdict.value == "EXPECTED_LOLBIN"
    assert all("name.exe" not in reason for reason in hit.reasons)


@pytest.mark.asyncio
async def test_check_system_routes_service_task_and_autorun(server):
    service_result = await _call_tool(
        server,
        "wintriage_check_system",
        {
            "type": "service",
            "name": "EventLog",
            "binary_path": r"C:\Windows\System32\svchost.exe",
            "os_version": "Win10_21H2_Pro",
        },
    )
    assert service_result["verdict"] == "EXPECTED"
    assert service_result["system_type"] == "service"

    task_result = await _call_tool(
        server,
        "wintriage_check_system",
        {
            "type": "scheduled_task",
            "name": r"\Microsoft\Windows\Defrag\ScheduledDefrag",
            "os_version": "Win10_21H2_Pro",
        },
    )
    assert task_result["verdict"] == "EXPECTED"
    assert task_result["system_type"] == "scheduled_task"

    autorun_result = await _call_tool(
        server,
        "wintriage_check_system",
        {
            "type": "autorun",
            "name": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "SecurityHealth",
            "os_version": "Win10_21H2_Pro",
        },
    )
    assert autorun_result["verdict"] == "EXPECTED"
    assert autorun_result["system_type"] == "autorun"


@pytest.mark.asyncio
async def test_server_status_routes_health_db_stats_and_all(server):
    health = await _call_tool(server, "wintriage_server_status", {"resource": "health"})
    assert "status" in health
    assert health["resource"] == "health"

    stats = await _call_tool(server, "wintriage_server_status", {"resource": "db_stats"})
    assert "known_good_db" in stats
    assert stats["resource"] == "db_stats"

    all_status = await _call_tool(server, "wintriage_server_status", {"resource": "all"})
    assert "health" in all_status
    assert "db_stats" in all_status
    assert all_status["resource"] == "all"


@pytest.mark.asyncio
async def test_check_file_expected_lolbin_and_hash_mismatch(server):
    # Note: cmd.exe is built-in LOLBin, but not in lolbins context table (unless explicitly added).
    # Since cmd.exe is hardcoded as built-in LOLBin in _find_lolbin, it will return is_lolbin=True.
    result = await server._check_file(r"C:\Windows\System32\cmd.exe", "a" * 64, "Win10_21H2_Pro")
    assert result["verdict"] == "EXPECTED_LOLBIN"
    assert result["is_lolbin"] is True

    result = await server._check_file(r"C:\Windows\System32\cmd.exe", "c" * 64, "Win10_21H2_Pro")
    assert result["verdict"] == "SUSPICIOUS"
    assert "Hash does not match baseline" in result["findings"][0]["description"]


@pytest.mark.asyncio
async def test_check_process_tree_expected(server):
    result = await server._check_process_tree("cmd.exe", "explorer.exe")
    assert result["verdict"] == "EXPECTED"


@pytest.mark.asyncio
async def test_check_service_requires_os_and_detects_path_mismatch(server):
    res = await server._check_service("EventLog")
    assert "os_version is required" in res["error"]

    # When service matches but binary path is mismatched
    result = await server._check_service("EventLog", r"C:\Temp\svchost.exe", "Win10_21H2_Pro")
    assert result["verdict"] == "SUSPICIOUS"


@pytest.mark.asyncio
async def test_check_scheduled_task_autorun_and_registry(server):
    result_task = await server._check_scheduled_task(
        r"\Microsoft\Windows\Defrag\ScheduledDefrag", "Win10_21H2_Pro"
    )
    assert result_task["verdict"] == "EXPECTED"

    result_autorun = await server._check_autorun(
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "SecurityHealth",
        "Win10_21H2_Pro",
    )
    assert result_autorun["verdict"] == "EXPECTED"

    result_registry = await server._check_registry(
        r"HKLM\System\CurrentControlSet\Control\Session Manager",
        "BootExecute",
        None,
        "Win10_21H2_Pro",
    )
    assert result_registry["verdict"] == "EXPECTED"


@pytest.mark.asyncio
async def test_check_registry_absent_db_warns(server):
    # XYE-27: when the optional ~12GB registry DB is not installed, the result
    # must carry a clear, non-breaking warning (mirrors db_stats available:false).
    server.registry_db = None
    raw = await server._check_registry(r"HKLM\SOFTWARE\Foo", None, None, None)
    assert raw["error"] == "Registry database not available"
    assert raw["registry_db_available"] is False
    assert raw["lookup_performed"] is False
    assert "not installed" in raw["note"].lower()
    # Steer the caller to the no-DB alternative.
    assert "wintriage_check_system" in raw["note"]


@pytest.mark.asyncio
async def test_hash_lolbin_hijackable_dll_and_pipe(server):
    result_hash = await server._check_hash("b" * 64)
    assert result_hash["verdict"] == "SUSPICIOUS"

    result_lol = await server._check_lolbin("mshta.exe")
    assert result_lol["is_lolbin"] is True

    result_dll = await server._check_hijackable_dll("version.dll")
    assert result_dll["is_hijackable"] is True
    assert result_dll["verdict"] == "EXPECTED_LOLBIN"

    result_pipe_susp = await server._check_pipe(r"\pipe\postex_123")
    assert result_pipe_susp["verdict"] == "SUSPICIOUS"

    result_pipe_exp = await server._check_pipe(r"\pipe\spoolss")
    assert result_pipe_exp["verdict"] == "EXPECTED"


@pytest.mark.asyncio
async def test_analyze_filename_detects_deception(server):
    result = await server._analyze_filename("invoice.pdf.exe")
    assert result["is_suspicious"] is True
    assert any("double extension" in f["description"].lower() for f in result["findings"])


@pytest.mark.asyncio
async def test_missing_db_is_degraded_and_not_trusted(tmp_path):
    # Setup server with non-existent DB files
    config = Config(
        known_good_db=tmp_path / "missing_kg.db",
        context_db=tmp_path / "missing_ctx.db",
        registry_db=tmp_path / "missing_reg.db",
        skip_db_validation=True,
    )
    srv = WindowsTriageServer(
        config=config,
        known_good_path=tmp_path / "missing_kg.db",
        context_path=tmp_path / "missing_ctx.db",
        registry_path=tmp_path / "missing_reg.db",
    )

    health = await srv._get_health()
    assert health["status"] == "degraded"
    assert health["databases"]["known_good"].startswith("error:")
    assert health["databases"]["context"].startswith("error:")

    # Check that tools return degraded or unknown status and do not return EXPECTED
    result = await srv._check_file(r"C:\Windows\System32\cmd.exe")
    assert result["verdict"] == "UNKNOWN"

    srv.close_databases()
