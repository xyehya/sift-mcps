"""Destination-resolution precedence for the baseline downloader (B-MVP-047).

The add-on's runtime reads the triage databases from the dir resolved by
``config.get_config`` (``SIFT_WINDOWS_TRIAGE_DB_DIR`` -> ``WT_DATA_DIR`` ->
``/var/lib/sift/windows-triage``). The downloader must defer to that same single
source so it lands the download exactly where the runtime later reads it.
Regression guard for the fresh-install bug where the ~5.9GB baseline wrote into
the package's ``data/`` source dir instead of the configured dir.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from windows_triage_mcp.config import reset_config
from windows_triage_mcp.scripts import download_databases as dd


def _run_main(monkeypatch, argv, env):
    """Invoke main() with patched argv/env, capturing the resolved dest dir."""
    captured: dict[str, Path] = {}

    def _fake_download(dest_dir, tag="latest"):
        captured["dest"] = Path(dest_dir)
        return True

    monkeypatch.setattr(dd, "download_databases", _fake_download)
    monkeypatch.setattr(dd.sys, "argv", ["download_databases", *argv])
    for key in ("SIFT_WINDOWS_TRIAGE_DB_DIR", "WT_DATA_DIR"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # get_config() is a process-wide singleton; clear it so each run resolves
    # against the env this case just set.
    reset_config()

    with pytest.raises(SystemExit) as exc:
        dd.main()
    assert exc.value.code == 0
    return captured["dest"]


def test_explicit_dest_wins(monkeypatch):
    dest = _run_main(
        monkeypatch,
        ["--dest", "/explicit/dir"],
        {"SIFT_WINDOWS_TRIAGE_DB_DIR": "/env/sift", "WT_DATA_DIR": "/env/wt"},
    )
    assert dest == Path("/explicit/dir")


def test_sift_env_used_when_no_flag(monkeypatch):
    dest = _run_main(
        monkeypatch,
        [],
        {"SIFT_WINDOWS_TRIAGE_DB_DIR": "/env/sift", "WT_DATA_DIR": "/env/wt"},
    )
    assert dest == Path("/env/sift")


def test_wt_data_dir_fallback(monkeypatch):
    dest = _run_main(monkeypatch, [], {"WT_DATA_DIR": "/env/wt"})
    assert dest == Path("/env/wt")


def test_runtime_default_when_unset(monkeypatch):
    dest = _run_main(monkeypatch, [], {})
    # Defers to the add-on's runtime default — the same dir config.get_config
    # uses when nothing is set, so the download and runtime agree by default.
    assert dest == Path("/var/lib/sift/windows-triage")
