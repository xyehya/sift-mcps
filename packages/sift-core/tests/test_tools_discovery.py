"""Tests for the installed-tools inventory in execute.tools.discovery (AUT2-B8)."""

from __future__ import annotations

import pytest
from sift_core.execute.security_policy import MVP_FORENSIC_ALLOWLIST
from sift_core.execute.tools import discovery
from sift_core.execute.tools.discovery import (
    build_tool_inventory,
    check_tools,
    get_tool_help,
)


@pytest.fixture(autouse=True)
def _reset_inventory_cache():
    discovery._INVENTORY_CACHE = None
    yield
    discovery._INVENTORY_CACHE = None


def _walk_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)
    elif isinstance(obj, str):
        yield obj


def test_tool_help_inventory_returns_availability_booleans():
    inv = get_tool_help("inventory")

    assert inv["name"] == "inventory"
    assert inv["total_cataloged"] == len(inv["tools"]) > 0
    assert inv["total_available"] == sum(1 for t in inv["tools"] if t["available"])

    for entry in inv["tools"]:
        # "invoke_as" is present only when the catalog name differs from the
        # invocable binary (e.g. "regripper" → invoke_as "rip.pl").
        assert set(entry) <= {"name", "category", "available", "invoke_as", "availability_note"}
        assert {"name", "category", "available"} <= set(entry)
        assert isinstance(entry["available"], bool)

    assert "run_command" in inv["hint"]
    assert "allowlisted" in inv["hint"]


def test_tool_help_inventory_covers_allowlisted_uncataloged_binaries():
    inv = get_tool_help("inventory")

    cataloged = {t["name"].lower() for t in inv["tools"]}
    extra_names = {e["name"] for e in inv["allowlisted_extra"]}

    assert extra_names, "expected at least one allowlisted-but-uncataloged binary"
    assert extra_names <= MVP_FORENSIC_ALLOWLIST
    assert not {n.lower() for n in extra_names} & cataloged
    for entry in inv["allowlisted_extra"]:
        assert set(entry) == {"name", "available"}
        assert isinstance(entry["available"], bool)


def test_tool_help_inventory_contains_no_absolute_paths():
    inv = get_tool_help("inventory")
    for text in _walk_strings(inv):
        assert not text.startswith("/"), f"absolute path leaked: {text}"
        assert "/usr/" not in text and "/opt/" not in text


def test_tool_help_star_alias_matches_inventory():
    assert get_tool_help("*") == get_tool_help("inventory")


def test_inventory_is_cached_single_probe_pass(monkeypatch):
    calls: list[str] = []
    real_find = discovery.find_binary

    def counting_find(name, extra_paths=None):
        calls.append(name)
        return real_find(name, extra_paths)

    monkeypatch.setattr(discovery, "find_binary", counting_find)

    first = build_tool_inventory()
    probes_after_first = len(calls)
    assert probes_after_first > 0

    second = build_tool_inventory()
    assert second is first
    assert len(calls) == probes_after_first, "second call must not re-probe binaries"


def test_tool_help_unknown_tool_errors_helpfully():
    result = get_tool_help("definitely-not-a-real-tool")
    assert "error" in result
    assert "not in catalog" in result["error"]
    assert "get_tool_help('inventory')" in result["error"]


def test_run_command_help_mentions_inventory_discovery():
    help_card = get_tool_help("run_command")
    assert "get_tool_help('inventory')" in help_card["discovery"]


def test_run_command_help_distinguishes_synchronous_and_durable_lanes():
    """Agents must not mistake an rc receipt for a pollable durable job."""
    help_card = get_tool_help("run_command")

    assert help_card["execution_lanes"]["synchronous"] == {
        "tool": "run_command",
        "result": "inline preview and rc-* receipt; not a durable job",
        "use_for": "quick, bounded commands",
    }
    assert help_card["execution_lanes"]["durable"] == {
        "tool": "run_command_job",
        "result": "pollable UUID job_id; poll with running_commands_status",
        "use_for": "long-running or parallel commands while the job worker is healthy",
    }


@pytest.mark.parametrize("tool_name", ["PECmd", "SrumECmd"])
def test_windows_only_zimmerman_tools_are_not_advertised_as_linux_executable(tool_name):
    """Fail on reversion: these remain knowledge cards, not Linux execution promises."""
    inventory = get_tool_help("inventory")
    entry = next(tool for tool in inventory["tools"] if tool["name"] == tool_name)
    help_card = get_tool_help(tool_name)

    assert entry["available"] is False
    assert "Windows-only" in entry["availability_note"]
    assert help_card["available"] is False
    assert "Linux run_command and run_command_job lanes" in help_card["availability_note"]
    assert "usage_hint" not in help_card


@pytest.mark.parametrize("tool_name", ["PECmd", "SrumECmd"])
def test_check_tools_does_not_advertise_non_executable_catalog_entries(monkeypatch, tool_name):
    """Fail on reversion: knowledge-only Windows tools remain unavailable.

    A detectable binary must not override the catalog's execution boundary in
    either the named-tool or full-catalog check_tools response.
    """
    monkeypatch.setattr(discovery, "find_binary", lambda _binary: "/mock/bin/tool")

    named_result = check_tools([tool_name])
    all_results = check_tools()

    assert named_result[tool_name] == {
        "available": False,
        "binary_path": "/mock/bin/tool",
    }
    assert all_results[tool_name] == {
        "available": False,
        "binary_path": "/mock/bin/tool",
    }


def test_check_tools_keeps_executable_catalog_entries_available(monkeypatch):
    """agent_executable entries remain available when their binary is found."""
    monkeypatch.setattr(discovery, "find_binary", lambda _binary: "/mock/bin/tool")

    named_result = check_tools(["exiftool"])
    all_results = check_tools()

    assert named_result["exiftool"]["available"] is True
    assert all_results["exiftool"]["available"] is True


def test_yara_help_does_not_claim_a_bundled_rules_inventory():
    """Fail on reversion: rules are an operator input, never a shipped catalog asset."""
    help_card = get_tool_help("yara")

    assert "operator-provisioned read-only rule file" in help_card["description"]
    assert "no YARA rules inventory" in help_card["description"]


def test_inventory_regripper_shows_invoke_as_rip_pl():
    """Catalog name 'regripper' must surface invoke_as='rip.pl' so agents know
    the real binary name without trial-and-error."""
    inv = get_tool_help("inventory")
    rr = next((t for t in inv["tools"] if t["name"] == "regripper"), None)
    assert rr is not None, "regripper must be in catalog"
    assert rr.get("invoke_as") == "rip.pl", (
        "regripper catalog entry must surface invoke_as='rip.pl' (the real binary)"
    )


def test_inventory_vol_catalog_name_matches_binary():
    """Catalog name for Volatility 3 must be 'vol' (the invocable binary),
    not 'vol3'. No invoke_as needed when name == binary."""
    inv = get_tool_help("inventory")
    # 'vol3' must NOT appear — it was the old broken catalog name.
    vol3_entry = next((t for t in inv["tools"] if t["name"] == "vol3"), None)
    assert vol3_entry is None, "old 'vol3' catalog name must be gone"
    # 'vol' must exist.
    vol_entry = next((t for t in inv["tools"] if t["name"] == "vol"), None)
    assert vol_entry is not None, "catalog must have a 'vol' entry"
    # Binary matches name, so no invoke_as needed.
    assert "invoke_as" not in vol_entry
