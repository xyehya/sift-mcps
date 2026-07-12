"""Destination-resolution precedence for the baseline downloader (B-MVP-047).

The add-on's runtime reads the triage databases from the dir resolved by
``config.get_config`` (``SIFT_WINDOWS_TRIAGE_DB_DIR`` -> ``WT_DATA_DIR`` ->
``/var/cache/sift/windows-triage``). The downloader must defer to that same single
source so it lands the download exactly where the runtime later reads it.
Regression guard for the fresh-install bug where the ~5.9GB baseline wrote into
the package's ``data/`` source dir instead of the configured dir.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from windows_triage_mcp.config import Config, reset_config
from windows_triage_mcp.exceptions import ConfigurationError
from windows_triage_mcp.scripts import download_databases as dd
from windows_triage_mcp.server import WindowsTriageServer


def _run_main(monkeypatch, argv, env):
    """Invoke main() with patched argv/env, capturing the resolved dest dir."""
    captured: dict[str, object] = {}

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
    return cast(Path, captured["dest"])


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
    assert dest == Path("/var/cache/sift/windows-triage")


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
        "tag_name": dd.DEFAULT_RELEASE_TAG,
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
    monkeypatch.setattr(dd, "_verify_checksums", lambda temp_dir, required: True)
    monkeypatch.setattr(
        dd,
        "_load_checksums",
        lambda path: {"known_good.db.zst": "a" * 64, "context.db.zst": "b" * 64},
    )
    monkeypatch.setattr(dd, "_decompress_zst", lambda src, p: p.write_bytes(b""))
    monkeypatch.setattr(dd, "_verify_database", lambda *a, **k: True)
    monkeypatch.setattr(dd, "_installed_baseline_is_verified", lambda *a: False)
    monkeypatch.setattr(dd, "_adopt_verified_pinned_baseline", lambda *a: False)
    monkeypatch.setattr(dd, "PINNED_BASELINE", {})

    assert dd.download_databases(dest) is True

    # The temp dir is created with dir=dest and therefore lives under dest, so a
    # single free-space check at dest covers both the .zst and the decompressed
    # DB on one filesystem.
    assert captured["dir_kwarg"] == dest
    assert cast(Path, captured["temp_dir"]).parent == dest


def test_registry_checksum_is_required_and_verified(monkeypatch, tmp_path):
    """The optional 12 GiB registry asset must never bypass SHA-256 verification."""
    temp_dir = tmp_path / "download"
    temp_dir.mkdir()
    registry_asset = temp_dir / dd.REGISTRY_ASSET
    registry_asset.write_bytes(b"registry")
    expected = dd._sha256_file(registry_asset)

    (temp_dir / "checksums.sha256").write_text(
        f"{expected}  {dd.REGISTRY_ASSET}\n", encoding="utf-8"
    )
    assert dd._verify_checksums(temp_dir, (dd.REGISTRY_ASSET,)) is True

    # Revert control: a release manifest without the registry hash must fail
    # closed even if the file was downloaded successfully.
    (temp_dir / "checksums.sha256").write_text("", encoding="utf-8")
    assert dd._verify_checksums(temp_dir, (dd.REGISTRY_ASSET,)) is False


def test_registry_provenance_records_verified_hash(tmp_path):
    registry_db = tmp_path / dd.REGISTRY_DB_NAME
    registry_db.write_bytes(b"decompressed registry baseline")
    source_hash = "a" * 64

    dd._write_registry_provenance(tmp_path, "triage-db-test", source_hash)

    provenance = tmp_path / f"{dd.REGISTRY_DB_NAME}.provenance.json"
    content = provenance.read_text(encoding="utf-8")
    assert '"release_tag": "triage-db-test"' in content
    assert f'"compressed_asset_sha256": "{source_hash}"' in content
    assert dd._sha256_file(registry_db) in content


def test_programmatic_registry_download_keeps_disk_space_guard(monkeypatch, tmp_path):
    monkeypatch.setattr(dd, "_check_registry_disk_space", lambda dest: False)
    monkeypatch.setattr(
        dd, "_fetch_release", lambda tag="latest": pytest.fail("must not fetch")
    )

    assert dd.download_databases(tmp_path, with_registry=True) is False


def test_verified_pinned_install_skips_release_and_download(monkeypatch, tmp_path):
    """Fail-on-revert: an unchanged verified install must remain network-free."""
    monkeypatch.setattr(dd, "_installed_baseline_is_verified", lambda *a: True)
    monkeypatch.setattr(
        dd, "_fetch_release", lambda *a: pytest.fail("must not contact GitHub")
    )
    monkeypatch.setattr(
        dd, "_download_asset", lambda *a: pytest.fail("must not download assets")
    )

    assert dd.download_databases(tmp_path, tag=dd.DEFAULT_RELEASE_TAG) is True


def test_unpinned_release_is_rejected_before_network(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dd, "_fetch_release", lambda *a: pytest.fail("must not contact GitHub")
    )

    assert dd.download_databases(tmp_path, tag="latest") is False


def test_installed_baseline_requires_matching_bytes_and_pinned_tag(
    monkeypatch, tmp_path
):
    known_good = tmp_path / "known_good.db"
    context = tmp_path / "context.db"
    known_good.write_bytes(b"known-good")
    context.write_bytes(b"context")
    compressed = {
        "known_good.db.zst": "a" * 64,
        "context.db.zst": "b" * 64,
    }
    monkeypatch.setattr(
        dd,
        "PINNED_BASELINE",
        {
            "known_good.db": {
                "compressed_asset": "known_good.db.zst",
                "compressed_asset_sha256": "a" * 64,
                "decompressed_sha256": dd._sha256_file(known_good),
                "size_bytes": known_good.stat().st_size,
            },
            "context.db": {
                "compressed_asset": "context.db.zst",
                "compressed_asset_sha256": "b" * 64,
                "decompressed_sha256": dd._sha256_file(context),
                "size_bytes": context.stat().st_size,
            },
        },
    )
    dd._write_baseline_provenance(tmp_path, dd.DEFAULT_RELEASE_TAG, compressed)

    # Isolate provenance/hash semantics; database schema validation is covered
    # by downloader tests and must still be called by the validator.
    original_verify = dd._verify_database
    try:
        dd._verify_database = lambda *a, **k: True
        assert dd._installed_baseline_is_verified(tmp_path, dd.DEFAULT_RELEASE_TAG)
        assert not dd._installed_baseline_is_verified(tmp_path, "triage-db-other")
        context.write_bytes(b"tampered")
        assert not dd._installed_baseline_is_verified(tmp_path, dd.DEFAULT_RELEASE_TAG)
    finally:
        dd._verify_database = original_verify


def test_failed_replacement_validation_preserves_installed_databases(
    monkeypatch, tmp_path
):
    """A bad download must not overwrite the last installed baseline."""
    known_good = tmp_path / "known_good.db"
    context = tmp_path / "context.db"
    known_good.write_bytes(b"old-known-good")
    context.write_bytes(b"old-context")
    release = {
        "tag_name": dd.DEFAULT_RELEASE_TAG,
        "assets": [
            {"name": "known_good.db.zst", "url": "http://x/kg"},
            {"name": "context.db.zst", "url": "http://x/ctx"},
            {"name": "checksums.sha256", "url": "http://x/sums"},
        ],
    }
    monkeypatch.setattr(dd, "_installed_baseline_is_verified", lambda *a: False)
    monkeypatch.setattr(dd, "_fetch_release", lambda *a: release)
    monkeypatch.setattr(dd, "_download_asset", lambda url, p: p.write_bytes(b"asset"))
    monkeypatch.setattr(dd, "_verify_checksums", lambda *a: True)
    monkeypatch.setattr(dd, "_decompress_zst", lambda src, p: p.write_bytes(b"new"))
    monkeypatch.setattr(dd, "_verify_database", lambda *a, **k: False)

    assert dd.download_databases(tmp_path) is False
    assert known_good.read_bytes() == b"old-known-good"
    assert context.read_bytes() == b"old-context"


def test_incomplete_release_transaction_is_runtime_fail_closed(tmp_path):
    marker = dd._begin_baseline_transaction(tmp_path, dd.DEFAULT_RELEASE_TAG)
    assert marker.is_file()
    assert not dd.verify_installed_baseline(tmp_path)

    with pytest.raises(ConfigurationError, match="update is incomplete"):
        WindowsTriageServer(
            config=Config(
                data_dir=tmp_path,
                known_good_db=tmp_path / "known_good.db",
                context_db=tmp_path / "context.db",
            )
        )


def test_transaction_marker_is_commit_boundary(tmp_path):
    marker = dd._begin_baseline_transaction(tmp_path, dd.DEFAULT_RELEASE_TAG)
    assert marker.read_text(encoding="utf-8") == f"{dd.DEFAULT_RELEASE_TAG}\n"
    dd._finish_baseline_transaction(marker)
    assert not marker.exists()


def test_registry_opt_in_reuses_verified_core(monkeypatch, tmp_path):
    """Registry-only provisioning must not fetch or replace the verified core set."""
    known_good = tmp_path / "known_good.db"
    context = tmp_path / "context.db"
    known_good.write_bytes(b"preserve-known-good")
    context.write_bytes(b"preserve-context")
    release = {
        "tag_name": dd.DEFAULT_RELEASE_TAG,
        "assets": [
            {"name": dd.REGISTRY_ASSET, "url": "http://x/registry"},
            {"name": "checksums.sha256", "url": "http://x/sums"},
        ],
    }
    downloaded: list[str] = []
    monkeypatch.setattr(dd, "_installed_baseline_is_verified", lambda *a: True)
    monkeypatch.setattr(dd, "_check_registry_disk_space", lambda *a: True)
    monkeypatch.setattr(dd, "_fetch_release", lambda *a: release)

    def fake_download(url, path):
        downloaded.append(path.name)
        path.write_bytes(b"asset")

    monkeypatch.setattr(dd, "_download_asset", fake_download)
    monkeypatch.setattr(dd, "_verify_checksums", lambda *a: True)
    monkeypatch.setattr(
        dd,
        "_load_checksums",
        lambda *a: {
            "known_good.db.zst": dd.PINNED_BASELINE["known_good.db"][
                "compressed_asset_sha256"
            ],
            "context.db.zst": dd.PINNED_BASELINE["context.db"][
                "compressed_asset_sha256"
            ],
            dd.REGISTRY_ASSET: "c" * 64,
        },
    )
    monkeypatch.setattr(
        dd, "_decompress_zst", lambda src, path: path.write_bytes(b"registry")
    )
    monkeypatch.setattr(dd, "_verify_database", lambda *a, **k: True)

    assert dd.download_databases(tmp_path, with_registry=True)
    assert downloaded == ["checksums.sha256", dd.REGISTRY_ASSET]
    assert known_good.read_bytes() == b"preserve-known-good"
    assert context.read_bytes() == b"preserve-context"
