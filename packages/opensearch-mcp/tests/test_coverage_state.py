"""Unit tests for _build_coverage_state helper in server.py.

Pure computation — no OpenSearch connection required.
"""

from __future__ import annotations


def _build(**kwargs):
    from opensearch_mcp.server import _build_coverage_state

    artifacts = kwargs.get("artifacts", {})
    enrichment = kwargs.get("enrichment", {})
    case_dir = kwargs.get("case_dir", None)
    return _build_coverage_state(artifacts, enrichment, case_dir=case_dir)


class TestEmptyCase:
    def test_no_artifacts_all_not_run(self):
        state = _build()
        assert state["disk_artifacts"]["evtx"] == "not_run"
        assert state["disk_artifacts"]["hayabusa"] == "not_run"
        assert state["disk_artifacts"]["browser"] == "not_available"
        assert state["disk_artifacts"]["autoruns"] == "not_available"

    def test_no_artifacts_memory_none(self):
        state = _build()
        assert state["memory"]["tier_run"] is None
        assert state["memory"]["plugins_run"] == []
        assert len(state["memory"]["plugins_not_run"]) > 0

    def test_no_artifacts_enrichment_not_run(self):
        state = _build()
        assert state["enrichment"]["triage"] == "not_run"
        assert state["enrichment"]["threat_intel"] == "not_run"

    def test_no_artifacts_no_gaps_for_enrichment(self):
        # No data → don't suggest enrichment (nothing to enrich)
        state = _build()
        gap_cmds = [g["command"] for g in state["gaps"]]
        assert not any("enrich" in c for c in gap_cmds)


class TestDiskArtifacts:
    def test_evtx_indexed(self):
        state = _build(artifacts={"evtx": {"docs": 100, "hosts": ["host1"], "indices": []}})
        assert state["disk_artifacts"]["evtx"] == "indexed"

    def test_amcache_via_delim_key(self):
        state = _build(artifacts={"delim-amcache": {"docs": 50, "hosts": [], "indices": []}})
        assert state["disk_artifacts"]["amcache"] == "indexed"

    def test_mft_via_delim_mftecmd(self):
        state = _build(artifacts={"delim-mftecmd": {"docs": 200, "hosts": [], "indices": []}})
        assert state["disk_artifacts"]["mft"] == "indexed"

    def test_srum_via_delim_srumecmd(self):
        state = _build(artifacts={"delim-srumecmd": {"docs": 10, "hosts": [], "indices": []}})
        assert state["disk_artifacts"]["srum"] == "indexed"

    def test_browser_always_not_available(self):
        # Even with artifacts present, browser stays not_available (no first-class parser)
        state = _build(artifacts={"evtx": {"docs": 1, "hosts": [], "indices": []}})
        assert state["disk_artifacts"]["browser"] == "not_available"

    def test_mft_gap_when_absent(self):
        state = _build(artifacts={"evtx": {"docs": 1, "hosts": [], "indices": []}})
        gap_gaps = [g["coverage_gap"] for g in state["gaps"]]
        assert any("MFT" in g for g in gap_gaps)

    def test_no_mft_gap_when_indexed(self):
        state = _build(artifacts={"mft": {"docs": 1, "hosts": [], "indices": []}})
        gap_gaps = [g["coverage_gap"] for g in state["gaps"]]
        assert not any("MFT" in g for g in gap_gaps)


class TestMemoryTierDetection:
    def _vol_art(self, plugins: list[str]) -> dict:
        from opensearch_mcp.parse_memory import _plugin_to_index_suffix

        return {
            _plugin_to_index_suffix(p): {"docs": 10, "hosts": ["host1"], "indices": []}
            for p in plugins
        }

    def test_tier_1_detected(self):
        from opensearch_mcp.parse_memory import TIER_1

        state = _build(artifacts=self._vol_art(TIER_1))
        assert state["memory"]["tier_run"] == 1

    def test_tier_2_detected(self):
        from opensearch_mcp.parse_memory import TIER_2

        state = _build(artifacts=self._vol_art(TIER_2))
        assert state["memory"]["tier_run"] == 2

    def test_plugins_run_populated(self):
        from opensearch_mcp.parse_memory import TIER_1

        state = _build(artifacts=self._vol_art(TIER_1))
        assert "windows.pslist" in state["memory"]["plugins_run"]
        assert "windows.psscan" in state["memory"]["plugins_run"]
        assert "windows.netscan" in state["memory"]["plugins_run"]

    def test_plugins_not_run_excludes_present(self):
        from opensearch_mcp.parse_memory import TIER_2

        state = _build(artifacts=self._vol_art(TIER_2))
        for p in TIER_2:
            assert p not in state["memory"]["plugins_not_run"]

    def test_tier1_gap_includes_derived_hostname(self):
        from opensearch_mcp.parse_memory import TIER_1

        art = self._vol_art(TIER_1)
        state = _build(artifacts=art)
        tier2_gaps = [g for g in state["gaps"] if "Tier 2" in g["coverage_gap"]]
        assert tier2_gaps
        assert "host1" in tier2_gaps[0]["command"]

    def test_no_memory_gap_after_tier_2(self):
        from opensearch_mcp.parse_memory import TIER_2

        state = _build(artifacts=self._vol_art(TIER_2))
        memory_gaps = [g for g in state["gaps"] if "memory" in g["coverage_gap"].lower() or "Tier" in g["coverage_gap"]]
        assert not memory_gaps


class TestEnrichmentState:
    def test_triage_done(self):
        state = _build(
            artifacts={"evtx": {"docs": 1, "hosts": [], "indices": []}},
            enrichment={"triage": {"checked": 100, "suspicious": 2}},
        )
        assert state["enrichment"]["triage"] == "done"

    def test_threat_intel_done(self):
        state = _build(
            artifacts={"evtx": {"docs": 1, "hosts": [], "indices": []}},
            enrichment={"threat_intel": {"checked": 50, "malicious": 1}},
        )
        assert state["enrichment"]["threat_intel"] == "done"

    def test_enrichment_gaps_when_data_present_but_not_run(self):
        state = _build(artifacts={"evtx": {"docs": 1, "hosts": [], "indices": []}})
        gap_cmds = [g["command"] for g in state["gaps"]]
        assert any("enrich_triage" in c for c in gap_cmds)
        assert any("enrich_intel" in c for c in gap_cmds)

    def test_no_enrichment_gaps_when_both_done(self):
        state = _build(
            artifacts={"evtx": {"docs": 1, "hosts": [], "indices": []}},
            enrichment={
                "triage": {"checked": 1, "suspicious": 0},
                "threat_intel": {"checked": 1, "malicious": 0},
            },
        )
        gap_cmds = [g["command"] for g in state["gaps"]]
        assert not any("enrich" in c for c in gap_cmds)


class TestFilesystemMetaPath:
    def test_no_case_dir_returns_none(self):
        state = _build()
        assert state["filesystem_meta_path"] is None

    def test_case_dir_no_sidecar_returns_none(self, tmp_path):
        state = _build(case_dir=tmp_path)
        assert state["filesystem_meta_path"] is None

    def test_sidecar_present_returns_relative_path(self, tmp_path):
        sidecar_dir = tmp_path / "agent" / "ingest"
        sidecar_dir.mkdir(parents=True)
        sidecar = sidecar_dir / "abc123-filesystem-meta.json"
        sidecar.write_text('{"image_type": "ntfs_volume"}')

        state = _build(case_dir=tmp_path)
        assert state["filesystem_meta_path"] == "agent/ingest/abc123-filesystem-meta.json"

    def test_most_recent_sidecar_wins(self, tmp_path):
        import time

        sidecar_dir = tmp_path / "agent" / "ingest"
        sidecar_dir.mkdir(parents=True)
        old = sidecar_dir / "run-old-filesystem-meta.json"
        new = sidecar_dir / "run-new-filesystem-meta.json"
        old.write_text('{"image_type": "partitioned_disk"}')
        time.sleep(0.01)
        new.write_text('{"image_type": "ntfs_volume"}')

        state = _build(case_dir=tmp_path)
        assert "run-new" in state["filesystem_meta_path"]
