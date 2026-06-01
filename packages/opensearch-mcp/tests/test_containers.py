"""Tests for container handling (containers.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.containers import (
    MountContext,
    cleanup_tmpdir,
    detect_container,
    extract_container,
    is_velociraptor_collection,
    normalize_velociraptor,
    read_velociraptor_hostname,
)

# ---------------------------------------------------------------------------
# detect_container
# ---------------------------------------------------------------------------


class TestDetectContainer:
    def test_zip(self, tmp_path):
        f = tmp_path / "triage.zip"
        f.touch()
        assert detect_container(f) == "archive"

    def test_7z(self, tmp_path):
        f = tmp_path / "triage.7z"
        f.touch()
        assert detect_container(f) == "archive"

    def test_tar_gz(self, tmp_path):
        f = tmp_path / "triage.tar.gz"
        f.touch()
        assert detect_container(f) == "archive"

    def test_tar(self, tmp_path):
        f = tmp_path / "triage.tar"
        f.touch()
        assert detect_container(f) == "archive"

    def test_e01(self, tmp_path):
        f = tmp_path / "evidence.e01"
        f.touch()
        assert detect_container(f) == "ewf"

    def test_ex01(self, tmp_path):
        f = tmp_path / "evidence.ex01"
        f.touch()
        assert detect_container(f) == "ewf"

    def test_vmdk(self, tmp_path):
        f = tmp_path / "disk.vmdk"
        f.touch()
        assert detect_container(f) == "nbd"

    def test_vhd(self, tmp_path):
        f = tmp_path / "disk.vhd"
        f.touch()
        assert detect_container(f) == "nbd"

    def test_vhdx(self, tmp_path):
        f = tmp_path / "disk.vhdx"
        f.touch()
        assert detect_container(f) == "nbd"

    def test_dd(self, tmp_path):
        f = tmp_path / "disk.dd"
        f.touch()
        assert detect_container(f) == "raw"

    def test_raw(self, tmp_path):
        f = tmp_path / "disk.raw"
        f.touch()
        assert detect_container(f) == "raw"

    def test_img(self, tmp_path):
        f = tmp_path / "disk.img"
        f.touch()
        assert detect_container(f) == "raw"

    def test_iso(self, tmp_path):
        f = tmp_path / "evidence.iso"
        f.touch()
        assert detect_container(f) == "raw"

    def test_iso_uppercase(self, tmp_path):
        f = tmp_path / "evidence.ISO"
        f.touch()
        assert detect_container(f) == "raw"

    def test_directory(self, tmp_path):
        assert detect_container(tmp_path) == "directory"

    def test_unknown(self, tmp_path):
        f = tmp_path / "evidence.xyz"
        f.touch()
        assert detect_container(f) == "unknown"


# ---------------------------------------------------------------------------
# extract_container
# ---------------------------------------------------------------------------


class TestExtractContainer:
    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_calls_7z(self, mock_subprocess, tmp_path):
        mock_subprocess.run.return_value = MagicMock(returncode=0)
        src = tmp_path / "test.zip"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        call_args = mock_subprocess.run.call_args[0][0]
        assert call_args[0] == "7z"
        assert str(src) in call_args

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_with_password(self, mock_subprocess, tmp_path):
        mock_subprocess.run.return_value = MagicMock(returncode=0)
        src = tmp_path / "test.7z"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest, password="infected")
        call_args = mock_subprocess.run.call_args[0][0]
        assert "-pinfected" in call_args

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_exit_1_is_warning(self, mock_subprocess, tmp_path):
        """7z exit code 1 (warning) should not raise."""
        mock_subprocess.run.return_value = MagicMock(returncode=1)
        src = tmp_path / "test.zip"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)  # should not raise

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_7z_exit_2_raises(self, mock_subprocess, tmp_path):
        """7z exit code 2+ (error) should raise."""
        import subprocess

        mock_subprocess.run.return_value = MagicMock(returncode=2, stdout=b"", stderr=b"error")
        mock_subprocess.CalledProcessError = subprocess.CalledProcessError
        src = tmp_path / "test.zip"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(subprocess.CalledProcessError):
            extract_container(src, dest)

    @patch("opensearch_mcp.containers.subprocess")
    def test_extract_tar(self, mock_subprocess, tmp_path):
        mock_subprocess.run.return_value = MagicMock(returncode=0)
        src = tmp_path / "test.tar.gz"
        src.touch()
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        call_args = mock_subprocess.run.call_args[0][0]
        assert call_args[0] == "tar"

    def test_unknown_format_raises(self, tmp_path):
        src = tmp_path / "test.xyz"
        src.touch()
        with pytest.raises(ValueError, match="Unknown archive"):
            extract_container(src, tmp_path)


# ---------------------------------------------------------------------------
# MountContext
# ---------------------------------------------------------------------------


class TestMountContext:
    @patch("opensearch_mcp.containers.subprocess")
    def test_cleanup_calls_umount(self, mock_subprocess):
        mock_subprocess.run.return_value.returncode = 0
        ctx = MountContext()
        ctx.add_mount(Path("/mnt/vol0"))
        ctx.add_mount(Path("/mnt/vol1"))
        ctx.cleanup()
        # umount called twice in reverse order
        calls = mock_subprocess.run.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == ["sudo", "umount", "/mnt/vol1"]
        assert calls[1][0][0] == ["sudo", "umount", "/mnt/vol0"]

    @patch("opensearch_mcp.containers.subprocess")
    def test_cleanup_fuse_and_nbd(self, mock_subprocess):
        mock_subprocess.run.return_value.returncode = 0
        ctx = MountContext()
        ctx.add_fuse(Path("/mnt/ewf"))
        ctx.add_nbd("/dev/nbd0")
        ctx.cleanup()
        calls = mock_subprocess.run.call_args_list
        cmds = [c[0][0] for c in calls]
        assert ["sudo", "fusermount", "-u", "/mnt/ewf"] in cmds
        assert ["sudo", "qemu-nbd", "-d", "/dev/nbd0"] in cmds


# ---------------------------------------------------------------------------
# Velociraptor
# ---------------------------------------------------------------------------


class TestVelociraptor:
    def test_is_velociraptor_collection_true(self, tmp_path):
        (tmp_path / "uploads" / "auto").mkdir(parents=True)
        assert is_velociraptor_collection(tmp_path)

    def test_is_velociraptor_collection_false(self, tmp_path):
        assert not is_velociraptor_collection(tmp_path)

    def test_normalize_velociraptor_decodes_paths(self, tmp_path):
        auto = tmp_path / "uploads" / "auto"
        (auto / "C%3A" / "Windows" / "System32" / "config").mkdir(parents=True)
        (auto / "C%3A" / "Windows" / "System32" / "config" / "SYSTEM").touch()
        (auto / "C%3A" / "Program%20Files").mkdir(parents=True)

        result = normalize_velociraptor(tmp_path)
        assert result == auto
        # C%3A should be renamed to C:
        assert (auto / "C:" / "Windows" / "System32" / "config" / "SYSTEM").is_file()
        # Program%20Files should be renamed to Program Files
        assert (auto / "C:" / "Program Files").is_dir()

    def test_normalize_velociraptor_no_auto_dir_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Not a Velociraptor"):
            normalize_velociraptor(tmp_path)

    def test_read_velociraptor_hostname(self, tmp_path):
        ctx = {
            "client_info": {
                "fqdn": "WORKSTATION01.corp.local",
                "hostname": "WORKSTATION01",
            }
        }
        (tmp_path / "collection_context.json").write_text(json.dumps(ctx))
        assert read_velociraptor_hostname(tmp_path) == "WORKSTATION01.corp.local"

    def test_read_velociraptor_hostname_fallback(self, tmp_path):
        ctx = {"client_info": {"hostname": "WKS01"}}
        (tmp_path / "collection_context.json").write_text(json.dumps(ctx))
        assert read_velociraptor_hostname(tmp_path) == "WKS01"

    def test_read_velociraptor_hostname_missing(self, tmp_path):
        assert read_velociraptor_hostname(tmp_path) is None

    def test_read_velociraptor_hostname_invalid_json(self, tmp_path):
        (tmp_path / "collection_context.json").write_text("not json")
        assert read_velociraptor_hostname(tmp_path) is None


# ---------------------------------------------------------------------------
# cleanup_tmpdir
# ---------------------------------------------------------------------------


class TestCleanupTmpdir:
    def test_removes_directory(self, tmp_path):
        d = tmp_path / "ingest-tmp"
        d.mkdir()
        (d / "file.txt").write_text("test")
        cleanup_tmpdir(d)
        assert not d.exists()

    def test_nonexistent_dir_warns(self, tmp_path, capsys):
        d = tmp_path / "nonexistent"
        cleanup_tmpdir(d)  # should not raise
        # No assertion needed — just verify it doesn't crash


# ---------------------------------------------------------------------------
# _parse_fdisk_output
# ---------------------------------------------------------------------------


class TestParseFdiskOutput:
    def test_parses_mbr_output(self):
        from opensearch_mcp.containers import _parse_fdisk_output

        output = """Disk /dev/sda: 50 GiB, 53687091200 bytes, 104857600 sectors
Sector size (logical/physical): 512 bytes / 512 bytes

Device     Boot   Start       End   Sectors  Size Id Type
/dev/sda1  *       2048   1023999   1021952  499M  7 HPFS/NTFS/exFAT
/dev/sda2       1024000 104857599 103833600 49.5G  7 HPFS/NTFS/exFAT
"""
        parts = _parse_fdisk_output(output)
        assert len(parts) == 2
        assert parts[0]["start"] == 2048
        assert parts[0]["sector_size"] == 512

    def test_empty_output(self):
        from opensearch_mcp.containers import _parse_fdisk_output

        assert _parse_fdisk_output("") == []


# ---------------------------------------------------------------------------
# R0-7: make_ingest_tmpdir — uses SIFT_CASE_DIR not ~/.sift/cases/
# ---------------------------------------------------------------------------


class TestMakeIngestTmpdir:
    def test_uses_agentir_case_dir(self, tmp_path, monkeypatch):
        """SIFT_CASE_DIR set → tmpdir lands under that case dir."""
        from opensearch_mcp.containers import make_ingest_tmpdir

        case_dir = tmp_path / "rocba-20260525-1200"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        result = make_ingest_tmpdir("rocba-20260525-1200")
        assert str(result).startswith(str(case_dir / "tmp"))
        assert result.is_dir()

    def test_falls_back_to_cases_root(self, tmp_path, monkeypatch):
        """No SIFT_CASE_DIR → uses SIFT_CASES_ROOT/case_id/tmp/."""
        from opensearch_mcp.containers import make_ingest_tmpdir

        cases_root = tmp_path / "cases"
        case_dir = cases_root / "fallback-case-001"
        case_dir.mkdir(parents=True)
        monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
        monkeypatch.setenv("SIFT_CASES_ROOT", str(cases_root))
        result = make_ingest_tmpdir("fallback-case-001")
        assert str(result).startswith(str(case_dir / "tmp"))
        assert result.is_dir()

    def test_env_var_wins_over_legacy_agentir_dir(self, tmp_path, monkeypatch):
        """SIFT_CASE_DIR beats SIFT_CASES_DIR (legacy env var)."""
        from opensearch_mcp.containers import make_ingest_tmpdir

        case_dir = tmp_path / "portal-case-20260525-1000"
        case_dir.mkdir()
        legacy_cases = tmp_path / "legacy" / "cases"
        legacy_case = legacy_cases / "portal-case-20260525-1000"
        legacy_case.mkdir(parents=True)
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
        monkeypatch.setenv("SIFT_CASES_DIR", str(legacy_cases))
        result = make_ingest_tmpdir("portal-case-20260525-1000")
        assert str(result).startswith(str(case_dir / "tmp"))


# ---------------------------------------------------------------------------
# TSK filesystem metadata helpers
# Fixtures captured from a real SIFT VM test run (2026-05-29).
# ---------------------------------------------------------------------------

# Real mmls output captured from SIFT VM (2026-05-29) — 200 MiB MBR+NTFS image.
_MMLS_PARTITIONED = """\
 DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000409599   0000407552   NTFS / exFAT (0x07)
"""

# fsstat -o 2048 output on the NTFS partition (same real image).
_FSSTAT_NTFS = """\
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 441CFA4D1B6716A8
OEM Name: NTFS
Version: Windows XP

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 4
First Cluster of MFT Mirror: 25471
Size of MFT Entries: 1024 bytes
Size of Index Records: 4096 bytes
Range: 0 - 27
Root Directory: 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 50943
Total Sector Range: 0 - 407551
"""

# img_stat output — note real output uses a tab after "Sector size:".
_IMG_STAT = """\
 IMAGE FILE INFORMATION
--------------------------------------------
Image Type: raw

Size in bytes: 209715200
Sector size:\t512
"""


class TestParseMmlsOutput:
    def test_partitioned_disk_returns_real_partition(self):
        from opensearch_mcp.containers import _parse_mmls_output

        parts = _parse_mmls_output(_MMLS_PARTITIONED)
        assert len(parts) == 1
        assert parts[0]["slot"] == "000:000"
        assert parts[0]["start"] == 2048
        assert parts[0]["length"] == 407552

    def test_meta_and_unallocated_skipped(self):
        from opensearch_mcp.containers import _parse_mmls_output

        parts = _parse_mmls_output(_MMLS_PARTITIONED)
        slots = [p["slot"] for p in parts]
        assert "Meta" not in slots
        assert "-------" not in slots

    def test_empty_output_returns_empty_list(self):
        from opensearch_mcp.containers import _parse_mmls_output

        assert _parse_mmls_output("") == []


class TestParseFsstatOutput:
    def test_fs_type(self):
        from opensearch_mcp.containers import _parse_fsstat_output

        result = _parse_fsstat_output(_FSSTAT_NTFS)
        assert result["fs_type"] == "NTFS"

    def test_sector_size_uppercase(self):
        from opensearch_mcp.containers import _parse_fsstat_output

        result = _parse_fsstat_output(_FSSTAT_NTFS)
        assert result["sector_size"] == 512

    def test_cluster_size(self):
        from opensearch_mcp.containers import _parse_fsstat_output

        result = _parse_fsstat_output(_FSSTAT_NTFS)
        assert result["cluster_size"] == 4096


class TestParseImgStatOutput:
    def test_image_format(self):
        from opensearch_mcp.containers import _parse_img_stat_output

        result = _parse_img_stat_output(_IMG_STAT)
        assert result["image_format"] == "raw"

    def test_size_bytes(self):
        from opensearch_mcp.containers import _parse_img_stat_output

        result = _parse_img_stat_output(_IMG_STAT)
        assert result["size_bytes"] == 209715200

    def test_sector_size_lowercase(self):
        from opensearch_mcp.containers import _parse_img_stat_output

        result = _parse_img_stat_output(_IMG_STAT)
        assert result["sector_size"] == 512


class TestCollectFilesystemMeta:
    """Integration-level tests for _collect_filesystem_meta using mocked subprocess."""

    @patch("opensearch_mcp.containers.subprocess")
    def test_partitioned_disk_branch(self, mock_subprocess):
        from unittest.mock import MagicMock

        from opensearch_mcp.containers import _collect_filesystem_meta

        def _run(cmd, **kw):
            tool = cmd[0]
            if tool == "mmls":
                return MagicMock(stdout=_MMLS_PARTITIONED, returncode=0)
            if tool == "img_stat":
                return MagicMock(stdout=_IMG_STAT, returncode=0)
            if tool == "fsstat":
                return MagicMock(stdout=_FSSTAT_NTFS, returncode=0)
            return MagicMock(stdout="", returncode=1)

        mock_subprocess.run.side_effect = _run

        result = _collect_filesystem_meta("/fake/disk.img", "disk")
        assert result["image_type"] == "partitioned_disk"
        assert len(result["partitions"]) == 1
        assert result["partitions"][0]["start_sector"] == 2048
        assert result["partitions"][0]["fs_type"] == "NTFS"
        assert result["size_bytes"] == 209715200

    @patch("opensearch_mcp.containers.subprocess")
    def test_ntfs_volume_branch(self, mock_subprocess):
        from unittest.mock import MagicMock

        from opensearch_mcp.containers import _collect_filesystem_meta

        def _run(cmd, **kw):
            tool = cmd[0]
            if tool == "mmls":
                # Volume image: mmls exits non-zero, no output
                return MagicMock(stdout="", returncode=1)
            if tool == "img_stat":
                return MagicMock(stdout=_IMG_STAT, returncode=0)
            if tool == "fsstat":
                return MagicMock(stdout=_FSSTAT_NTFS, returncode=0)
            return MagicMock(stdout="", returncode=1)

        mock_subprocess.run.side_effect = _run

        result = _collect_filesystem_meta("/fake/volume.img", "raw")
        assert result["image_type"] == "ntfs_volume"
        assert result["fs_type"] == "NTFS"
        assert result["size_bytes"] == 209715200

    def test_memory_image_branch(self, tmp_path):
        from opensearch_mcp.containers import _collect_filesystem_meta

        img = tmp_path / "mem.lime"
        img.write_bytes(b"LIME" + b"\x00" * 100)

        result = _collect_filesystem_meta(str(img), "memory")
        assert result["image_type"] == "memory_image"
        assert result["memory_format"] == "lime"
        assert result["size_bytes"] == 104

    @patch("opensearch_mcp.containers.subprocess")
    def test_tool_absent_returns_unknown(self, mock_subprocess):
        import subprocess as _real_subprocess

        from opensearch_mcp.containers import _collect_filesystem_meta

        mock_subprocess.run.side_effect = FileNotFoundError("mmls not found")
        mock_subprocess.CalledProcessError = _real_subprocess.CalledProcessError

        result = _collect_filesystem_meta("/fake/disk.img", "disk")
        assert result["image_type"] == "unknown"
