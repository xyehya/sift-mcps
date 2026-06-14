"""Tests for the installed-tools inventory in execute.tools.discovery (AUT2-B8)."""

from __future__ import annotations

import pytest

from sift_core.execute.tools import discovery
from sift_core.execute.security_policy import MVP_FORENSIC_ALLOWLIST
from sift_core.execute.tools.discovery import build_tool_inventory, get_tool_help


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
        assert set(entry) <= {"name", "category", "available", "invoke_as"}
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
