"""Surface tests for the worker-OOM + tier-2 MCP items.

Items covered:
- ITEM 1 (M-WORKER-DBDROP): memory_ram_preflight helper + preview surface
  (IngestOut.warning) + aggregate surface (result_public.warning).
- ITEM 2 (M-DOCCOUNT): IngestRun.total_indexed description relabel.
- ITEM 3 (auto-path memory derives hostname when absent).
- ITEM 4 (F4/Hayabusa Option B): coverage_state.gaps[] remediation entry.
- ITEM 5a (M-FIELDVALS): advisory on unmapped-field empty result.
- ITEM 5c (M-DRYRUN-MEM): memory dry_run carries dispatched_to + estimate.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# ITEM 1: memory_ram_preflight helper (parse_memory.py)
# ---------------------------------------------------------------------------


class TestMemoryRamPreflightHelper:
    """Unit tests for the parse_memory helpers — tested at the impl layer
    for the logic, but the surface tests below cover the MCP-facing planes."""

    def test_read_mem_available_bytes_returns_int(self, tmp_path, monkeypatch):
        """_read_mem_available_bytes parses kB value from /proc/meminfo."""
        from opensearch_mcp.parse_memory import _read_mem_available_bytes

        fake_meminfo = tmp_path / "meminfo"
        fake_meminfo.write_text(
            "MemTotal:       32768000 kB\n"
            "MemFree:        12345678 kB\n"
            "MemAvailable:   28000000 kB\n"
            "Buffers:          123456 kB\n"
        )
        with patch("builtins.open", side_effect=lambda *a, **kw: open(str(fake_meminfo))):
            # Direct Path.read_text monkeypatch
            from pathlib import Path as _P
            real_read = _P.read_text

            def _fake_read(self, *a, **kw):
                if str(self) == "/proc/meminfo":
                    return fake_meminfo.read_text()
                return real_read(self, *a, **kw)

            monkeypatch.setattr(_P, "read_text", _fake_read)
            result = _read_mem_available_bytes()

        assert result == 28000000 * 1024  # kB → bytes

    def test_read_mem_available_bytes_returns_none_on_missing_file(self, monkeypatch):
        """Returns None when /proc/meminfo is unreadable — never raises."""
        from opensearch_mcp.parse_memory import _read_mem_available_bytes
        from pathlib import Path as _P

        def _raise(*a, **kw):
            raise OSError("No such file")

        monkeypatch.setattr(_P, "read_text", _raise)
        assert _read_mem_available_bytes() is None

    def test_preflight_failsafe_on_unreadable_meminfo(self, tmp_path, monkeypatch):
        """memory_ram_preflight returns None when /proc/meminfo is unreadable."""
        from opensearch_mcp.parse_memory import memory_ram_preflight
        from pathlib import Path as _P

        raw = tmp_path / "test.raw"
        raw.write_bytes(b"\x00" * (20 * 1024 * 1024 * 1024 // 1024))  # tiny file

        def _raise(*a, **kw):
            raise OSError("unreadable")

        monkeypatch.setattr(_P, "read_text", _raise)
        result = memory_ram_preflight(raw)
        assert result is None  # never raises, never refuses

    def test_preflight_warns_when_ram_low(self, tmp_path, monkeypatch):
        """memory_ram_preflight returns a string when available RAM < required."""
        from opensearch_mcp.parse_memory import memory_ram_preflight, _read_mem_available_bytes
        from pathlib import Path as _P

        # 10 GB image, but only 8 GB available
        image_gb = 10
        avail_gb = 8
        raw = tmp_path / "test.raw"
        raw.write_bytes(b"\x00" * 8)  # tiny stand-in; we'll mock stat
        # Mock stat to return 10 GB size
        real_stat = _P.stat

        def _fake_stat(self, *a, **kw):
            if str(self) == str(raw):
                st = MagicMock()
                st.st_size = image_gb * 1024**3
                return st
            return real_stat(self, *a, **kw)

        monkeypatch.setattr(_P, "stat", _fake_stat)
        monkeypatch.setattr(
            "opensearch_mcp.parse_memory._read_mem_available_bytes",
            lambda: avail_gb * 1024**3,
        )
        warn = memory_ram_preflight(raw)
        assert warn is not None
        assert "image" in warn.lower() or "low memory" in warn.lower()
        assert "10.0 GB" in warn
        assert "8.0 GB" in warn

    def test_preflight_no_warn_when_ample(self, tmp_path, monkeypatch):
        """memory_ram_preflight returns None when RAM is ample."""
        from opensearch_mcp.parse_memory import memory_ram_preflight
        from pathlib import Path as _P

        raw = tmp_path / "test.raw"
        raw.write_bytes(b"\x00" * 8)
        real_stat = _P.stat

        def _fake_stat(self, *a, **kw):
            if str(self) == str(raw):
                st = MagicMock()
                st.st_size = 10 * 1024**3  # 10 GB image
                return st
            return real_stat(self, *a, **kw)

        monkeypatch.setattr(_P, "stat", _fake_stat)
        # 40 GB available → well above 10 GB + 4 GB headroom
        monkeypatch.setattr(
            "opensearch_mcp.parse_memory._read_mem_available_bytes",
            lambda: 40 * 1024**3,
        )
        assert memory_ram_preflight(raw) is None

    def test_preflight_env_headroom_override(self, tmp_path, monkeypatch):
        """SIFT_MEM_PREFLIGHT_HEADROOM_GB=24 triggers warning on a 19 GB image with 31 GB avail."""
        from opensearch_mcp.parse_memory import memory_ram_preflight
        from pathlib import Path as _P

        raw = tmp_path / "test.raw"
        raw.write_bytes(b"\x00" * 8)
        real_stat = _P.stat

        def _fake_stat(self, *a, **kw):
            if str(self) == str(raw):
                st = MagicMock()
                st.st_size = 19 * 1024**3  # 19 GB image
                return st
            return real_stat(self, *a, **kw)

        monkeypatch.setattr(_P, "stat", _fake_stat)
        # 31 GB available — above 19+4=23 GB (normal) but below 19+24=43 GB (env override)
        monkeypatch.setattr(
            "opensearch_mcp.parse_memory._read_mem_available_bytes",
            lambda: 31 * 1024**3,
        )
        monkeypatch.setenv("SIFT_MEM_PREFLIGHT_HEADROOM_GB", "24")
        warn = memory_ram_preflight(raw)
        assert warn is not None, "SIFT_MEM_PREFLIGHT_HEADROOM_GB=24 must trigger warning with 31 GB avail on 19 GB image"


# ---------------------------------------------------------------------------
# ITEM 1: Preview surface test (idx_ingest_memory → IngestOut.warning)
# ---------------------------------------------------------------------------


_CASE_ID = "case-ram-test"


def _make_evidence(tmp_path: Path) -> Path:
    """Create a minimal fake case dir with a .raw evidence file."""
    case_dir = tmp_path / _CASE_ID
    (case_dir / "evidence").mkdir(parents=True)
    raw = case_dir / "evidence" / "test.raw"
    raw.write_bytes(b"\x00" * 8)
    return case_dir


class TestMemoryPreviewWarnSurface:
    """ITEM 1 surface tests — preview plane (idx_ingest_memory dry_run=True).

    Tests at the registry/impl surface where IngestOut.warning maps to raw.get("warning").
    """

    def _run_preview(self, tmp_path, monkeypatch, *, ram_available_bytes: int, image_bytes: int = 20 * 1024**3):
        """Call idx_ingest_memory(dry_run=True) with mocked RAM + image size."""
        import opensearch_mcp.server as srv

        case_dir = _make_evidence(tmp_path)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setattr(srv, "_get_active_case", lambda: _CASE_ID)

        from pathlib import Path as _P
        real_stat = _P.stat

        def _fake_stat(self, *a, **kw):
            s = real_stat(self, *a, **kw)
            if self.suffix == ".raw":
                st = MagicMock()
                st.st_size = image_bytes
                return st
            return s

        monkeypatch.setattr(_P, "stat", _fake_stat)
        monkeypatch.setattr(
            "opensearch_mcp.parse_memory._read_mem_available_bytes",
            lambda: ram_available_bytes,
        )
        # Patch _derive_hostname_from_image to return quickly without vol3
        monkeypatch.setattr(
            "opensearch_mcp.server._derive_hn",
            lambda path, timeout=120: ("srl-forge", "registry"),
            raising=False,
        )
        # Also patch at parse_memory level for the hostname derive call
        import opensearch_mcp.parse_memory as _pm
        monkeypatch.setattr(_pm, "_derive_hostname_from_image", lambda p, timeout=120: ("srl-forge", "registry"))

        from opensearch_mcp.server import idx_ingest_memory

        return idx_ingest_memory(path="evidence/test.raw", hostname="srl-forge", tier=1, dry_run=True)

    def test_memory_preview_warns_when_ram_low(self, tmp_path, monkeypatch):
        """Low RAM (5 GB avail, 20 GB image) → IngestOut.warning is non-None."""
        resp = self._run_preview(
            tmp_path, monkeypatch,
            ram_available_bytes=5 * 1024**3,   # 5 GB avail
            image_bytes=20 * 1024**3,          # 20 GB image → needs 24 GB
        )
        assert resp["status"] == "preview"
        assert resp.get("warning") is not None, (
            "Low RAM preview must carry 'warning' key in response"
        )
        assert "low memory" in resp["warning"].lower() or "image" in resp["warning"].lower()

    def test_memory_preview_no_warn_when_ample(self, tmp_path, monkeypatch):
        """Ample RAM (40 GB avail, 5 GB image) → no warning."""
        resp = self._run_preview(
            tmp_path, monkeypatch,
            ram_available_bytes=40 * 1024**3,  # 40 GB avail
            image_bytes=5 * 1024**3,           # 5 GB image → needs 9 GB
        )
        assert resp["status"] == "preview"
        assert resp.get("warning") is None

    def test_memory_preview_dispatched_to_present(self, tmp_path, monkeypatch):
        """M-DRYRUN-MEM: preview must include dispatched_to field."""
        resp = self._run_preview(
            tmp_path, monkeypatch,
            ram_available_bytes=40 * 1024**3,
            image_bytes=5 * 1024**3,
        )
        assert resp.get("dispatched_to") == "opensearch-worker", (
            "M-DRYRUN-MEM: dispatched_to must be present in memory dry_run response"
        )

    def test_memory_preview_estimate_present(self, tmp_path, monkeypatch):
        """M-DRYRUN-MEM: preview must include estimate dict."""
        resp = self._run_preview(
            tmp_path, monkeypatch,
            ram_available_bytes=40 * 1024**3,
            image_bytes=5 * 1024**3,
        )
        est = resp.get("estimate")
        assert isinstance(est, dict), "M-DRYRUN-MEM: estimate must be a dict in memory dry_run"
        assert "plugin_count" in est
        assert "note" in est


# ---------------------------------------------------------------------------
# ITEM 1: Aggregate surface test (ingest_job._aggregate → result_public.warning)
# ---------------------------------------------------------------------------


class TestAggregateMemWarningSurface:
    """ITEM 1: _aggregate must lift totals.mem_warning → detail["warning"]."""

    def test_aggregate_surfaces_mem_warning(self):
        """Status record with totals.mem_warning → _aggregate detail["warning"] set."""
        from opensearch_mcp.ingest_job import _aggregate

        run_ids = {"run-mem-1"}
        latest_by_run = {
            "run-mem-1": {
                "status": "complete",
                "totals": {
                    "indexed": 5000,
                    "artifacts_complete": 10,
                    "artifacts_total": 10,
                    "hosts_complete": 1,
                    "hosts_total": 1,
                    "mem_warning": "Low memory: image ~19.0 GB, available RAM ~8.0 GB",
                },
                "hosts": [],
            }
        }
        result = _aggregate(latest_by_run, run_ids)
        assert result["detail"].get("warning"), (
            "M-WORKER-DBDROP: totals.mem_warning must surface as detail['warning'] in _aggregate"
        )
        assert "Low memory" in result["detail"]["warning"]

    def test_aggregate_no_warning_when_absent(self):
        """No mem_warning in totals → no detail["warning"] key."""
        from opensearch_mcp.ingest_job import _aggregate

        run_ids = {"run-mem-2"}
        latest_by_run = {
            "run-mem-2": {
                "status": "complete",
                "totals": {
                    "indexed": 5000,
                    "artifacts_complete": 10,
                    "artifacts_total": 10,
                    "hosts_complete": 1,
                    "hosts_total": 1,
                },
                "hosts": [],
            }
        }
        result = _aggregate(latest_by_run, run_ids)
        assert "warning" not in result["detail"], (
            "No mem_warning in totals → detail['warning'] must not be set"
        )


# ---------------------------------------------------------------------------
# ITEM 2: M-DOCCOUNT — IngestRun.total_indexed field description relabel
# ---------------------------------------------------------------------------


class TestMDocCountFieldRelabel:
    """ITEM 2: IngestRun.total_indexed description must mention duplicate collapse."""

    def test_total_indexed_description_mentions_duplicate_collapse(self):
        from opensearch_mcp.registry import IngestRun

        schema = IngestRun.model_json_schema()
        desc = schema["properties"]["total_indexed"].get("description", "")
        assert "duplicate" in desc.lower() or "collapse" in desc.lower(), (
            f"M-DOCCOUNT: total_indexed description must mention duplicate/collapse, got: {desc!r}"
        )

    def test_total_indexed_description_mentions_opensearch_count(self):
        from opensearch_mcp.registry import IngestRun

        schema = IngestRun.model_json_schema()
        desc = schema["properties"]["total_indexed"].get("description", "")
        assert "opensearch_count" in desc, (
            f"M-DOCCOUNT: description must point at opensearch_count to verify, got: {desc!r}"
        )


# ---------------------------------------------------------------------------
# ITEM 3: Auto-path memory skip deleted — derives hostname when absent
# ---------------------------------------------------------------------------


class TestAutoPathMemoryDerivesHostname:
    """ITEM 3: The `if not hostname: skip` block is removed.
    idx_ingest_memory is called unconditionally even with empty hostname;
    derivation runs inside it.
    """

    def test_auto_path_memory_calls_idx_ingest_memory_with_empty_hostname(
        self, tmp_path, monkeypatch
    ):
        """In the auto-path multi-container branch, memory containers with
        hostname='' must NOT be skipped — idx_ingest_memory must be called
        and returns status (started or derived hostname), not status=skipped.

        Tests ITEM 3: the `if not hostname: skip` block is removed; the
        call to idx_ingest_memory is unconditional (hostname='' is OK since
        idx_ingest_memory derives it internally).
        """
        import opensearch_mcp.server as srv
        from unittest.mock import MagicMock, patch

        case_dir = tmp_path / "case-auto"
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True)
        # "memory" marker in filename → _looks_like_memory returns True
        raw = evidence_dir / "Rocba-Memory.raw"
        raw.write_bytes(b"\x00" * (5 * 1024**2))  # 5 MB so size_mb check passes
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setattr(srv, "_get_active_case", lambda: "case-auto")

        idx_calls: list[dict] = []

        def _fake_idx(path, hostname, *, tier=1, plugins=None, dry_run=True):
            idx_calls.append({"path": path, "hostname": hostname})
            return {"status": "started", "run_id": "r-1", "pid": 1234}

        monkeypatch.setattr(srv, "idx_ingest_memory", _fake_idx)

        # Mock out the OS client so shard headroom check doesn't fail
        mock_client = MagicMock()
        with (
            patch("opensearch_mcp.server.get_client", return_value=mock_client),
            patch(
                "opensearch_mcp.shard_capacity.check_shard_headroom",
                return_value=(True, "ok"),
            ),
            patch("opensearch_mcp.ingest.discover", return_value=[]),
        ):
            # Call opensearch_ingest with format='auto' and NO hostname
            result = srv.opensearch_ingest(
                path="evidence/",
                format="auto",
                hostname="",   # ← empty — old code would skip memory
                dry_run=False,
            )

        # Must NOT skip the memory container
        skipped = [
            c for c in result.get("containers", [])
            if c.get("status") == "skipped"
        ]
        assert not skipped, (
            f"ITEM 3: Memory container must NOT be skipped with hostname=''; "
            f"result={result}"
        )
        assert idx_calls, "ITEM 3: idx_ingest_memory must have been called"


# ---------------------------------------------------------------------------
# ITEM 4: F4/Hayabusa — coverage_state.gaps[] remediation entry
# ---------------------------------------------------------------------------


class TestHayabusaGapInCoverageState:
    """ITEM 4 (Option B): _build_coverage_state must emit a hayabusa gap
    when evtx is indexed but hayabusa is not.
    """

    def _build(self, artifacts: dict, enrichment: dict | None = None):
        from opensearch_mcp.server import _build_coverage_state

        return _build_coverage_state(artifacts, enrichment or {})

    def test_hayabusa_gap_when_evtx_indexed_but_hayabusa_not_run(self):
        """evtx=indexed, hayabusa=not_run → a gap with hayabusa remediation."""
        state = self._build(artifacts={"evtx": {"docs": 1000, "hosts": ["h1"], "indices": []}})
        gap_texts = [g["coverage_gap"] for g in state["gaps"]]
        assert any("hayabusa" in t.lower() or "Hayabusa" in t for t in gap_texts), (
            f"ITEM 4: hayabusa gap missing when evtx indexed but hayabusa absent; gaps={gap_texts}"
        )

    def test_hayabusa_gap_command_mentions_force_reingest(self):
        """The hayabusa remediation gap must point to force re-ingest."""
        state = self._build(artifacts={"evtx": {"docs": 1000, "hosts": ["h1"], "indices": []}})
        hayabusa_gaps = [
            g for g in state["gaps"]
            if "hayabusa" in g.get("coverage_gap", "").lower()
            or "Hayabusa" in g.get("coverage_gap", "")
        ]
        assert hayabusa_gaps, "ITEM 4: no hayabusa gap found"
        cmd = hayabusa_gaps[0].get("command", "")
        assert "force" in cmd.lower() or "force=True" in cmd, (
            f"ITEM 4: hayabusa gap command must mention force re-ingest; command={cmd!r}"
        )

    def test_no_hayabusa_gap_when_both_indexed(self):
        """When hayabusa index is present, no hayabusa gap should appear."""
        state = self._build(artifacts={
            "evtx": {"docs": 1000, "hosts": ["h1"], "indices": []},
            "hayabusa": {"docs": 500, "hosts": ["h1"], "indices": []},
        })
        gap_texts = [g["coverage_gap"] for g in state["gaps"]]
        assert not any("hayabusa" in t.lower() for t in gap_texts), (
            "ITEM 4: no hayabusa gap expected when hayabusa index is present"
        )

    def test_no_hayabusa_gap_when_evtx_not_indexed(self):
        """Without evtx data, no hayabusa gap (hayabusa needs raw evtx)."""
        state = self._build(artifacts={})
        gap_texts = [g["coverage_gap"] for g in state["gaps"]]
        assert not any(
            "hayabusa" in t.lower()
            and "sigma" in t.lower()
            for t in gap_texts
        ), (
            "ITEM 4: hayabusa-specific gap must not appear when evtx is absent"
        )


# ---------------------------------------------------------------------------
# ITEM 5a: M-FIELDVALS — advisory on unmapped-field empty result
# ---------------------------------------------------------------------------


class TestFieldValuesAdvisory:
    """ITEM 5a: opensearch_field_values must add 'advisory' when a field is
    absent from the mapping (empty values AND field not in mapping).
    """

    def _mock_client_for_field_values(
        self,
        monkeypatch,
        *,
        buckets: list,
        field_in_mapping: bool,
        top_fields: list[str] | None = None,
    ):
        """Patch get_client + os search to return given buckets."""
        client = MagicMock()
        # search returns empty or non-empty aggregation
        client.search.return_value = {
            "aggregations": {
                "values": {"buckets": buckets}
            },
            "hits": {"total": {"value": 0}},
        }
        # get_field_mapping: either returns the field or not
        field_name = "nonexistent.field"
        if field_in_mapping:
            client.indices.get_field_mapping.return_value = {
                "test-idx": {"mappings": {field_name: {"full_name": field_name, "mapping": {}}}}
            }
        else:
            client.indices.get_field_mapping.side_effect = [
                # First call: check if field is mapped (empty = absent)
                {"test-idx": {"mappings": {}}},
                # Second call: get all top-level fields for advisory
                {"test-idx": {"mappings": {f: {} for f in (top_fields or ["host.name", "@timestamp"])}}},
            ]
        return client

    def test_bogus_field_returns_advisory(self, monkeypatch):
        """Empty values + field not in mapping → advisory key present."""
        import opensearch_mcp.server as srv

        client = MagicMock()
        client.search.return_value = {
            "aggregations": {"values": {"buckets": []}},
        }
        # get_field_mapping: first call (field mapping check) returns no field
        # second call (all fields for advisory) returns some fields
        client.indices.get_field_mapping.side_effect = [
            {"test-idx": {"mappings": {}}},   # field absent
            {"test-idx": {"mappings": {"host.name": {}, "@timestamp": {}, "event.code": {}}}},
        ]

        with (
            patch("opensearch_mcp.server._get_os", return_value=client),
            patch("opensearch_mcp.server._resolve_index", return_value="test-idx-*"),
            patch("opensearch_mcp.server._validate_index", return_value=None),
            patch("opensearch_mcp.server._os_call", side_effect=lambda fn, *a, **kw: fn(*a, **kw)),
            patch("opensearch_mcp.server.audit", MagicMock()),
        ):
            monkeypatch.setenv("SIFT_CASE_DIR", "/fake/case")
            resp = srv.opensearch_field_values("nonexistent.field", index="test-idx-*")

        assert resp.get("advisory"), (
            "M-FIELDVALS: empty values for absent field must have 'advisory' key"
        )
        assert "not in the mapping" in resp["advisory"]

    def test_real_field_with_values_no_advisory(self, monkeypatch):
        """Non-empty values → no advisory (field exists and has data)."""
        import opensearch_mcp.server as srv

        client = MagicMock()
        client.search.return_value = {
            "aggregations": {
                "values": {"buckets": [{"key": "SYSTEM", "doc_count": 500}]}
            },
        }

        with (
            patch("opensearch_mcp.server._get_os", return_value=client),
            patch("opensearch_mcp.server._resolve_index", return_value="test-idx-*"),
            patch("opensearch_mcp.server._validate_index", return_value=None),
            patch("opensearch_mcp.server._os_call", side_effect=lambda fn, *a, **kw: fn(*a, **kw)),
            patch("opensearch_mcp.server.audit", MagicMock()),
        ):
            monkeypatch.setenv("SIFT_CASE_DIR", "/fake/case")
            resp = srv.opensearch_field_values("winlog.provider_name", index="test-idx-*")

        assert resp.get("values")
        assert "advisory" not in resp, "No advisory when values are returned"
