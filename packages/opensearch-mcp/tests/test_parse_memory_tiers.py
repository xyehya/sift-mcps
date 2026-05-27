"""Unit tests for parse_memory TIER lists.

UAT 2026-04-23 BUG 4 regression coverage. Pins TIER_3 does NOT include
`windows.registry.hashdump` (unloadable in Vol3 2.26.2 — listed under
"The following plugins could not be loaded" in the help output) or
`windows.vadinfo` (compute-heavy, forensic value overlaps cheaper
plugins already in the tier). Both were removed based on live-UAT
evidence.

A plugin-availability auto-detect mechanism was drafted but reverted
after self-review revealed the argparse-`(choose from ...)` format it
parsed doesn't exist in Vol3 2.26.2's actual `--help` output (Vol3
renders plugins via subparsers + a separate "could not be loaded"
section). Real vol-help parsing may come back as a separate ticket.
"""

from __future__ import annotations


class TestTier1Promotion:
    def test_psscan_in_tier_1(self):
        """windows.psscan promoted to Tier 1 — hidden/exited processes in every default run."""
        from opensearch_mcp.parse_memory import TIER_1

        assert "windows.psscan" in TIER_1

    def test_netscan_in_tier_1(self):
        """windows.netscan promoted to Tier 1 — historical/closed connections in every default run."""
        from opensearch_mcp.parse_memory import TIER_1

        assert "windows.netscan" in TIER_1

    def test_tier_2_no_duplicate_psscan_netscan(self):
        """TIER_2 must not contain duplicates after psscan/netscan moved to TIER_1."""
        from opensearch_mcp.parse_memory import TIER_2

        assert TIER_2.count("windows.psscan") == 1
        assert TIER_2.count("windows.netscan") == 1

    def test_tier_1_subset_of_tier_2(self):
        """TIER_1 must remain a strict subset of TIER_2."""
        from opensearch_mcp.parse_memory import TIER_1, TIER_2

        assert set(TIER_1).issubset(set(TIER_2))


class TestTier3PluginList:
    def test_hashdump_removed_from_tier_3(self):
        """`windows.registry.hashdump` isn't in Vol3 2.26.2's argparse
        choice list; keeping it in TIER_3 produced per-plugin errors
        on every memory host. Pin removal."""
        from opensearch_mcp.parse_memory import TIER_3

        assert "windows.registry.hashdump" not in TIER_3

    def test_vadinfo_removed_from_tier_3(self):
        """`windows.vadinfo` compute-heavy (>60s on 5GB images, times
        out); forensic value overlaps malfind + dlllist + ldrmodules +
        handles already in the tier. Pin removal."""
        from opensearch_mcp.parse_memory import TIER_3

        assert "windows.vadinfo" not in TIER_3

    def test_tier_3_still_contains_retained_plugins(self):
        """Regression guard: the pair-removal must NOT have dropped
        anything else. Pin the remaining TIER_3 additions beyond
        TIER_2."""
        from opensearch_mcp.parse_memory import TIER_2, TIER_3

        tier_3_only = set(TIER_3) - set(TIER_2)
        assert "windows.handles" in tier_3_only
        assert "windows.filescan" in tier_3_only
        assert "windows.malfind" in tier_3_only
        assert "windows.shimcachemem" in tier_3_only
        assert "windows.driverscan" in tier_3_only
        assert "windows.mutantscan" in tier_3_only
        assert "timeliner" in tier_3_only

    def test_natural_keys_and_timestamp_map_in_sync_with_tier_3(self):
        """Both `_NATURAL_KEYS` and `_TIMESTAMP_FIELD` must not
        reference removed plugins — otherwise dead entries accumulate
        and future readers can't tell what's live."""
        from opensearch_mcp.parse_memory import _NATURAL_KEYS, _TIMESTAMP_FIELD

        assert "windows.registry.hashdump" not in _NATURAL_KEYS
        assert "windows.registry.hashdump" not in _TIMESTAMP_FIELD
        assert "windows.vadinfo" not in _TIMESTAMP_FIELD
