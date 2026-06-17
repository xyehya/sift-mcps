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

    def _fake_download(dest_dir, tag="latest", with_registry=False):
        captured["dest"] = Path(dest_dir)
        captured["with_registry"] = with_registry
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


def _run_main_capture(monkeypatch, argv):
    """main() with patched argv/env, capturing the with_registry flag (XYE-27)."""
    captured: dict[str, object] = {}

    def _fake_download(dest_dir, tag="latest", with_registry=False):
        captured["dest"] = Path(dest_dir)
        captured["with_registry"] = with_registry
        return True

    monkeypatch.setattr(dd, "download_databases", _fake_download)
    monkeypatch.setattr(dd.sys, "argv", ["download_databases", *argv])
    for key in ("SIFT_WINDOWS_TRIAGE_DB_DIR", "WT_DATA_DIR"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WT_DATA_DIR", "/env/wt")
    reset_config()
    with pytest.raises(SystemExit) as exc:
        dd.main()
    assert exc.value.code == 0
    return captured


def test_registry_off_by_default(monkeypatch):
    # XYE-27: the optional ~12GB registry baseline must never be pulled unless
    # explicitly requested.
    captured = _run_main_capture(monkeypatch, [])
    assert captured["with_registry"] is False


def test_registry_opt_in_with_yes_and_space(monkeypatch):
    # XYE-27: --with-registry opts in; --yes bypasses the confirm prompt; the
    # disk-space gate still runs (stubbed True here).
    monkeypatch.setattr(dd, "_check_registry_disk_space", lambda dest: True)
    captured = _run_main_capture(monkeypatch, ["--with-registry", "--yes"])
    assert captured["with_registry"] is True


def test_registry_opt_in_aborts_when_no_space(monkeypatch):
    # XYE-27: insufficient disk space aborts before any download (exit 1).
    monkeypatch.setattr(dd, "_check_registry_disk_space", lambda dest: False)
    monkeypatch.setattr(
        dd, "download_databases", lambda *a, **k: pytest.fail("must not download")
    )
    monkeypatch.setattr(
        dd.sys, "argv", ["download_databases", "--with-registry", "--yes"]
    )
    monkeypatch.setenv("WT_DATA_DIR", "/env/wt")
    reset_config()
    with pytest.raises(SystemExit) as exc:
        dd.main()
    assert exc.value.code == 1


def test_temp_dir_colocated_with_dest(monkeypatch, tmp_path):
    """The per-attempt temp dir must be created under dest, not system /tmp.

    The compressed .zst (up to ~500 MB for the registry asset) is downloaded
    into the temp dir before being decompressed (~12 GB) into dest. Keeping the
    temp dir on the same filesystem as dest means the single disk-space check at
    dest correctly covers the whole pipeline; otherwise a small/separate system
    /tmp (often a tmpfs) could fill mid-download even though dest has room, and
    the disk check would give a false "OK".
    """
    dest = tmp_path / "baseline"

    release = {
        "tag_name": "triage-db-test",
        "assets": [
            {"name": "known_good.db.zst", "url": "http://x/kg"},
            {"name": "context.db.zst", "url": "http://x/ctx"},
            {"name": "checksums.sha256", "url": "http://x/sums"},
        ],
    }
    monkeypatch.setattr(dd, "_fetch_release", lambda tag="latest": release)

    captured: dict[str, object] = {}
    real_mkdtemp = dd.tempfile.mkdtemp

    def _spy_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        captured["dir_kwarg"] = kwargs.get("dir")
        captured["temp_dir"] = Path(path)
        return path

    monkeypatch.setattr(dd.tempfile, "mkdtemp", _spy_mkdtemp)

    # Stub the network + decompress so only the temp-dir placement is exercised.
    monkeypatch.setattr(dd, "_download_asset", lambda url, p: p.write_bytes(b""))
    monkeypatch.setattr(dd, "_verify_checksums", lambda temp_dir: True)
    monkeypatch.setattr(dd, "_decompress_zst", lambda src, p: p.write_bytes(b""))
    monkeypatch.setattr(dd, "_verify_database", lambda *a, **k: True)

    assert dd.download_databases(dest) is True

    # The temp dir is created with dir=dest and therefore lives under dest, so a
    # single free-space check at dest covers both the .zst and the decompressed
    # DB on one filesystem.
    assert captured["dir_kwarg"] == dest
    assert captured["temp_dir"].parent == dest
