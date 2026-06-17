"""Unit tests for B-MVP-042: _derive_hostname_from_image and ingest_memory wiring.

All vol3 subprocess calls are mocked via monkeypatch on ``run_vol3_plugin``.
No filesystem access to real memory images is performed.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

import opensearch_mcp.parse_memory as _pm
from opensearch_mcp.parse_memory import _derive_hostname_from_image


# ---------------------------------------------------------------------------
# Fixtures — sample vol3 JSON rows (verbatim shapes from live VM probe)
# ---------------------------------------------------------------------------

# Registry printkey row as returned by vol3 -r json for
# "ControlSet001\Control\ComputerName\ComputerName"
_REGISTRY_ROW_CS001_CN = {
    "Data": '"SRL-FORGE"',
    "Hive Offset": "0xf80344000",
    "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
    "Last Write Time": "2020-11-02T01:12:22+00:00",
    "Name": "ComputerName",
    "Type": "REG_SZ",
    "Volatile": False,
    "__children": [],
}

# Registry printkey row for ActiveComputerName (same shape)
_REGISTRY_ROW_CS001_ACN = {
    "Data": '"SRL-FORGE"',
    "Hive Offset": "0xf80344000",
    "Key": r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName",
    "Last Write Time": "2020-11-02T01:12:22+00:00",
    "Name": "ComputerName",
    "Type": "REG_SZ",
    "Volatile": False,
    "__children": [],
}

# A "noise" row returned for a different hive (not SYSTEM) — must be ignored
_REGISTRY_ROW_NOISE = {
    "Data": "-",
    "Hive Offset": "0x00dead00",
    "Key": r"\REGISTRY\USER\S-1-5-21-xxx\Control\ComputerName\ComputerName",
    "Last Write Time": "2020-11-02T01:12:22+00:00",
    "Name": "ComputerName",
    "Type": "REG_SZ",
    "Volatile": False,
    "__children": [],
}

# envars row (unanimously COMPUTERNAME=SRL-FORGE on test image)
_ENVARS_ROW = {
    "Block": "0xdead1234",
    "PID": 4,
    "Process": "System",
    "Value": "SRL-FORGE",
    "Variable": "COMPUTERNAME",
    "__children": [],
}

_IMAGE = Path("/fake/Rocba-Memory.raw")


# ---------------------------------------------------------------------------
# PRIMARY: windows.registry.printkey
# ---------------------------------------------------------------------------


class TestDeriveRegistry:
    def test_active_computer_name_cs001_returns_stripped_hostname(self, monkeypatch):
        """Primary probe: ActiveComputerName / ControlSet001 → strip quotes → SRL-FORGE."""

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                return [_REGISTRY_ROW_NOISE, _REGISTRY_ROW_CS001_ACN]
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "registry"

    def test_computer_name_cs001_fallback_returns_hostname(self, monkeypatch):
        """ActiveComputerName key raises → falls back to ComputerName key."""
        call_count = {"n": 0}

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                call_count["n"] += 1
                key = (plugin_args or [""])[1] if plugin_args and len(plugin_args) >= 2 else ""
                if "ActiveComputerName" in key:
                    # Simulate ControlSet001\ActiveComputerName returning no usable row
                    return [_REGISTRY_ROW_NOISE]
                if "ComputerName" in key and "Active" not in key and "ControlSet001" in key:
                    return [_REGISTRY_ROW_CS001_CN]
                return []
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "registry"

    def test_controlset001_failure_falls_back_to_controlset002(self, monkeypatch):
        """If ControlSet001 keys yield nothing, ControlSet002 is tried."""
        cs002_row = dict(_REGISTRY_ROW_CS001_CN)
        cs002_row["Key"] = cs002_row["Key"].replace("ControlSet001", "ControlSet002")
        cs002_row["Data"] = '"SRL-FORGE"'

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                key = (plugin_args or [""])[1] if plugin_args and len(plugin_args) >= 2 else ""
                if "ControlSet001" in key:
                    return [_REGISTRY_ROW_NOISE]
                if "ControlSet002" in key:
                    return [cs002_row]
                return []
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "registry"

    def test_reg_sz_double_quotes_are_stripped(self, monkeypatch):
        """REG_SZ Data renders with surrounding literal double-quotes: strip them."""
        row = dict(_REGISTRY_ROW_CS001_ACN)
        row["Data"] = '"MY-HOST"'  # verbatim vol3 output

        monkeypatch.setattr(
            _pm,
            "run_vol3_plugin",
            lambda *a, **kw: [row] if kw.get("plugin_args") or "printkey" in (a[1] if len(a) > 1 else "") else [],
        )
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "MY-HOST"
        assert source == "registry"

    def test_noise_rows_are_ignored(self, monkeypatch):
        """Rows not from \\REGISTRY\\MACHINE\\SYSTEM\\ must be skipped."""

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                # Only noise rows — no SYSTEM hive match
                return [_REGISTRY_ROW_NOISE, _REGISTRY_ROW_NOISE]
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        # Falls through all 4 registry probes then attempts envars
        # envars returns empty too → returns None
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname is None
        assert source == ""

    def test_probe_order_is_active_computer_name_first(self, monkeypatch):
        """ActiveComputerName must be tried before plain ComputerName."""
        tried_keys: list[str] = []

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                key = (plugin_args or [""])[1] if plugin_args and len(plugin_args) >= 2 else ""
                tried_keys.append(key)
                # First call succeeds
                if "ActiveComputerName" in key and "ControlSet001" in key:
                    return [_REGISTRY_ROW_CS001_ACN]
                return []
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, _ = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        # ActiveComputerName must appear before ComputerName in tried_keys
        assert any("ActiveComputerName" in k for k in tried_keys)
        acn_idx = next(i for i, k in enumerate(tried_keys) if "ActiveComputerName" in k)
        cn_only = [i for i, k in enumerate(tried_keys) if "ComputerName" in k and "Active" not in k]
        # If we found it on the first probe, ComputerName was never tried — that's fine
        if cn_only:
            assert acn_idx < cn_only[0]


# ---------------------------------------------------------------------------
# SECONDARY: windows.envars fallback
# ---------------------------------------------------------------------------


class TestDeriveEnvars:
    def test_envars_used_when_registry_fails(self, monkeypatch):
        """When all registry probes return nothing, envars COMPUTERNAME is used."""

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                return [_REGISTRY_ROW_NOISE]
            if plugin == "windows.envars":
                return [_ENVARS_ROW, _ENVARS_ROW]  # two rows, same value
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "envars"

    def test_envars_no_quote_stripping(self, monkeypatch):
        """envars Value is raw — no quote-stripping must be applied."""
        row = dict(_ENVARS_ROW)
        row["Value"] = "SRL-FORGE"  # no surrounding quotes in envars

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                return []
            if plugin == "windows.envars":
                return [row]
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "envars"

    def test_envars_majority_vote(self, monkeypatch):
        """Majority vote: if multiple values appear, most common wins."""
        rows = (
            [{"Variable": "COMPUTERNAME", "Value": "HOST-A", "__children": []}] * 3
            + [{"Variable": "COMPUTERNAME", "Value": "HOST-B", "__children": []}] * 2
        )

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                return []
            if plugin == "windows.envars":
                return rows
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "HOST-A"
        assert source == "envars"

    def test_envars_variable_case_insensitive(self, monkeypatch):
        """COMPUTERNAME lookup is case-insensitive (Variable.upper())."""
        row = {"Variable": "computername", "Value": "SRL-FORGE", "__children": []}

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                return []
            if plugin == "windows.envars":
                return [row]
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "envars"


# ---------------------------------------------------------------------------
# Last-resort: both probes fail → None
# ---------------------------------------------------------------------------


class TestDeriveFailure:
    def test_returns_none_when_both_probes_fail(self, monkeypatch):
        """If registry and envars both yield nothing, return (None, '')."""

        monkeypatch.setattr(_pm, "run_vol3_plugin", lambda *a, **kw: [])
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname is None
        assert source == ""

    def test_registry_runtime_error_falls_through_to_envars(self, monkeypatch):
        """RuntimeError from registry probe is swallowed; envars still attempted."""
        call_count = {"n": 0}

        def _fake_vol(image_path, plugin, timeout=3600, plugin_args=None):
            if plugin == "windows.registry.printkey":
                raise RuntimeError("vol3 failed (exit 1): some error")
            if plugin == "windows.envars":
                return [_ENVARS_ROW]
            return []

        monkeypatch.setattr(_pm, "run_vol3_plugin", _fake_vol)
        hostname, source = _derive_hostname_from_image(_IMAGE)
        assert hostname == "SRL-FORGE"
        assert source == "envars"


# ---------------------------------------------------------------------------
# ingest_memory wiring: derivation + last-resort error path
# ---------------------------------------------------------------------------


class TestIngestMemoryHostnameWiring:
    """Test that ingest_memory calls _derive_hostname_from_image when hostname is empty."""

    def _make_client(self):
        """Return a mock OpenSearch client."""
        return MagicMock()

    def test_explicit_hostname_bypasses_derivation(self, monkeypatch, tmp_path):
        """Operator-supplied hostname= must never trigger the deriver."""
        image = tmp_path / "test.raw"
        image.write_bytes(b"x")

        derive_called = {"n": 0}

        def _spy_derive(path, timeout=60):
            derive_called["n"] += 1
            return ("DERIVED", "registry")

        monkeypatch.setattr(_pm, "_derive_hostname_from_image", _spy_derive)

        # Stub out the vol3 preflight and plugin runs so we don't need a real image
        monkeypatch.setattr(_pm, "_find_vol3", lambda: "/bin/true")
        import subprocess as _sp
        monkeypatch.setattr(
            _sp,
            "run",
            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""),
        )

        _pm.ingest_memory(
            image_path=image,
            client=self._make_client(),
            case_id="test-case",
            hostname="EXPLICIT-HOST",
            plugins=["windows.pslist"],
        )

        assert derive_called["n"] == 0, "Deriver must NOT be called when hostname is supplied"

    def test_empty_hostname_triggers_derivation(self, monkeypatch, tmp_path):
        """When hostname='', _derive_hostname_from_image is called."""
        image = tmp_path / "test.raw"
        image.write_bytes(b"x")

        derive_called = {"n": 0}

        def _fake_derive(path, timeout=60):
            derive_called["n"] += 1
            return ("DERIVED-HOST", "registry")

        monkeypatch.setattr(_pm, "_derive_hostname_from_image", _fake_derive)
        monkeypatch.setattr(_pm, "_find_vol3", lambda: "/bin/true")
        import subprocess as _sp
        monkeypatch.setattr(
            _sp,
            "run",
            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""),
        )

        result = _pm.ingest_memory(
            image_path=image,
            client=self._make_client(),
            case_id="test-case",
            hostname="",
            plugins=["windows.pslist"],
        )

        assert derive_called["n"] == 1
        meta = result.get("_meta", {})
        assert meta.get("hostname") == "DERIVED-HOST"
        assert meta.get("hostname_source") == "registry"

    def test_derive_none_returns_structured_error(self, monkeypatch, tmp_path):
        """When _derive_hostname_from_image returns None, the last-resort error is returned."""
        image = tmp_path / "test.raw"
        image.write_bytes(b"x")

        monkeypatch.setattr(_pm, "_derive_hostname_from_image", lambda *a, **kw: (None, ""))

        result = _pm.ingest_memory(
            image_path=image,
            client=self._make_client(),
            case_id="test-case",
            hostname="",
            plugins=["windows.pslist"],
        )

        assert "error" in result
        assert "hostname" in result["error"].lower()
        assert "detail" in result  # hint that auto-derivation was attempted

    def test_hostname_source_operator_in_meta(self, monkeypatch, tmp_path):
        """Operator-supplied hostname yields hostname_source='operator' in _meta."""
        image = tmp_path / "test.raw"
        image.write_bytes(b"x")

        monkeypatch.setattr(_pm, "_find_vol3", lambda: "/bin/true")
        import subprocess as _sp
        monkeypatch.setattr(
            _sp,
            "run",
            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""),
        )

        result = _pm.ingest_memory(
            image_path=image,
            client=self._make_client(),
            case_id="test-case",
            hostname="EXPLICIT",
            plugins=["windows.pslist"],
        )

        meta = result.get("_meta", {})
        assert meta.get("hostname_source") == "operator"

    def test_caller_provided_source_is_preserved(self, monkeypatch, tmp_path):
        """XYE-11: when the caller pre-derived the hostname and passes the real
        source, _meta reports that source instead of mislabeling it 'operator'.

        Mirrors the server-side opensearch_ingest wrapper, which derives the
        hostname before spawning the worker (so the worker always receives a
        non-empty --hostname) and forwards --hostname-source.
        """
        image = tmp_path / "test.raw"
        image.write_bytes(b"x")

        derive_called = {"n": 0}

        def _spy_derive(path, timeout=60):
            derive_called["n"] += 1
            return ("SHOULD-NOT-BE-USED", "registry")

        monkeypatch.setattr(_pm, "_derive_hostname_from_image", _spy_derive)
        monkeypatch.setattr(_pm, "_find_vol3", lambda: "/bin/true")
        import subprocess as _sp
        monkeypatch.setattr(
            _sp,
            "run",
            lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""),
        )

        result = _pm.ingest_memory(
            image_path=image,
            client=self._make_client(),
            case_id="test-case",
            hostname="SRL-FORGE",
            hostname_source="registry",
            plugins=["windows.pslist"],
        )

        # Caller already derived; the worker must not re-derive...
        assert derive_called["n"] == 0
        meta = result.get("_meta", {})
        # ...and must report the forwarded source, not "operator".
        assert meta.get("hostname") == "SRL-FORGE"
        assert meta.get("hostname_source") == "registry"
