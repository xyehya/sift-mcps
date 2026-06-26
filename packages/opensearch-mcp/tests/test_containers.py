"""Tests for container handling (containers.py)."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.containers import (
    ArchiveRejected,
    MountContext,
    cleanup_tmpdir,
    detect_container,
    extract_container,
    is_velociraptor_collection,
    normalize_velociraptor,
    read_velociraptor_hostname,
)

HAVE_7Z = shutil.which("7z") is not None


# ---------------------------------------------------------------------------
# Archive-building helpers for the SEC-8 hardening tests
# ---------------------------------------------------------------------------


def _add_tar_file(tf: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    tf.addfile(ti, io.BytesIO(data))


def _add_tar_special(tf: tarfile.TarFile, name: str, ttype: bytes, linkname: str = "") -> None:
    ti = tarfile.TarInfo(name)
    ti.type = ttype
    ti.linkname = linkname
    if ttype in (tarfile.CHRTYPE, tarfile.BLKTYPE):
        ti.devmajor = 1
        ti.devminor = 3
    tf.addfile(ti)


def _clean_member():
    from opensearch_mcp.containers import _Member

    return _Member(name="ok.txt", size=5, kind="file", setid=False)

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
    """Clean-path extraction with the real tar/7z binaries (SEC-8 chokepoint)."""

    def test_extract_clean_tar(self, tmp_path):
        src = tmp_path / "triage.tar"
        with tarfile.open(src, "w") as tf:
            _add_tar_file(tf, "host/note.txt", b"hello")
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)  # should not raise
        assert (dest / "host" / "note.txt").read_bytes() == b"hello"

    def test_extract_clean_tar_gz(self, tmp_path):
        src = tmp_path / "triage.tar.gz"
        with tarfile.open(src, "w:gz") as tf:
            _add_tar_file(tf, "data.bin", b"abc" * 100)
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        assert (dest / "data.bin").is_file()

    @pytest.mark.skipif(not HAVE_7Z, reason="7z binary not on PATH")
    def test_extract_clean_7z(self, tmp_path):
        member = tmp_path / "evidence.txt"
        member.write_text("clean")
        src = tmp_path / "triage.7z"
        subprocess.run(["7z", "a", str(src), str(member)], check=True, capture_output=True)
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        assert (dest / "evidence.txt").read_text() == "clean"

    @pytest.mark.skipif(not HAVE_7Z, reason="7z binary not on PATH")
    def test_extract_7z_warning_rc1_is_failure(self, tmp_path, monkeypatch):
        """SEC-8: 7z rc==1 (warning) must be treated as FAILURE, not success."""
        import opensearch_mcp.containers as containers

        # Force preflight to pass with a single benign member, then make the
        # extraction subprocess return rc==1 (warning) — it must raise.
        monkeypatch.setattr(
            containers, "_list_7z_members", lambda *a, **k: [_clean_member()]
        )
        real_run = subprocess.run

        def fake_run(cmd, *a, **k):
            if cmd[:2] == ["7z", "x"]:
                return MagicMock(returncode=1, stdout=b"", stderr=b"warning")
            return real_run(cmd, *a, **k)

        monkeypatch.setattr(containers.subprocess, "run", fake_run)
        src = tmp_path / "x.7z"
        src.write_bytes(b"PK")
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(subprocess.CalledProcessError):
            extract_container(src, dest)

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
    def test_uses_sift_case_dir(self, tmp_path, monkeypatch):
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

    def test_env_var_wins_over_legacy_sift_dir(self, tmp_path, monkeypatch):
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


# ---------------------------------------------------------------------------
# SEC-8: malicious-member rejection (the app REJECTS — not merely "no escape")
# ---------------------------------------------------------------------------


class TestMaliciousArchiveRejected:
    """Each fixture asserts extract_container RAISES before/instead of writing."""

    def _build(self, tmp_path, builder):
        src = tmp_path / "evil.tar"
        with tarfile.open(src, "w") as tf:
            _add_tar_file(tf, "host/real.txt", b"keep")  # a benign member too
            builder(tf)
        dest = tmp_path / "out"
        dest.mkdir()
        return src, dest

    def test_traversal_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path, lambda tf: _add_tar_file(tf, "../escape.txt", b"x")
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)
        assert not (tmp_path / "escape.txt").exists()

    def test_absolute_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path, lambda tf: _add_tar_file(tf, "/etc/sift_pwn", b"x")
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)

    def test_symlink_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path,
            lambda tf: _add_tar_special(tf, "link", tarfile.SYMTYPE, "/etc/passwd"),
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)

    def test_hardlink_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path,
            lambda tf: _add_tar_special(tf, "hl", tarfile.LNKTYPE, "host/real.txt"),
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)

    def test_char_device_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path, lambda tf: _add_tar_special(tf, "dev/null", tarfile.CHRTYPE)
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)

    def test_fifo_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path, lambda tf: _add_tar_special(tf, "pipe", tarfile.FIFOTYPE)
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)

    def test_setuid_member_rejected(self, tmp_path):
        src, dest = self._build(
            tmp_path, lambda tf: _add_tar_file(tf, "rootkit", b"x", mode=0o4755)
        )
        with pytest.raises(ArchiveRejected):
            extract_container(src, dest)


# ---------------------------------------------------------------------------
# SEC-8: decompression-bomb / disk-exhaustion caps
# ---------------------------------------------------------------------------


class TestDecompressionBombCaps:
    def test_compression_ratio_cap_rejects(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIFT_ARCHIVE_MAX_RATIO", "5")
        src = tmp_path / "bomb.tar.gz"
        with tarfile.open(src, "w:gz") as tf:
            _add_tar_file(tf, "zeros.bin", b"\x00" * 200_000)  # compresses ~>>5:1
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveRejected, match="ratio"):
            extract_container(src, dest)

    def test_entry_count_cap_rejects(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIFT_ARCHIVE_MAX_ENTRIES", "2")
        src = tmp_path / "many.tar"
        with tarfile.open(src, "w") as tf:
            for i in range(5):
                _add_tar_file(tf, f"f{i}.txt", b"x")
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveRejected, match="entry count"):
            extract_container(src, dest)

    def test_uncompressed_total_cap_rejects(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SIFT_ARCHIVE_MAX_UNCOMPRESSED_BYTES", "50")
        src = tmp_path / "big.tar"
        with tarfile.open(src, "w") as tf:
            _add_tar_file(tf, "data.bin", b"y" * 200)
        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveRejected, match="uncompressed size"):
            extract_container(src, dest)

    def test_clean_archive_passes_caps(self, tmp_path):
        """A normal small archive must NOT trip any cap (fail-on-revert guard)."""
        src = tmp_path / "ok.tar"
        with tarfile.open(src, "w") as tf:
            _add_tar_file(tf, "a.txt", b"hello world")
        dest = tmp_path / "out"
        dest.mkdir()
        extract_container(src, dest)
        assert (dest / "a.txt").is_file()


# ---------------------------------------------------------------------------
# SEC-8: 7z -slt listing parser + attribute classification
# ---------------------------------------------------------------------------


_SLT_SAMPLE = """\
7-Zip 26.01

Listing archive: /cases/x/triage.7z

--
Path = /cases/x/triage.7z
Type = 7z
Physical Size = 1234

----------
Path = host/note.txt
Folder = -
Size = 12
Attributes = A_ -rw-r--r--

Path = host/sub
Folder = +
Size = 0
Attributes = D_ drwxr-xr-x

Path = host/evil-link
Folder = -
Size = 0
Attributes = A_ lrwxrwxrwx

Path = host/setuid-bin
Folder = -
Size = 100
Attributes = A_ -rwsr-xr-x

Path = ../escape.txt
Folder = -
Size = 5
Attributes = A_ -rw-r--r--
"""


class Test7zSltParser:
    def test_parser_skips_archive_header_record(self):
        from opensearch_mcp.containers import _parse_7z_slt

        members = _parse_7z_slt(_SLT_SAMPLE)
        names = [m.name for m in members]
        # The archive's own /cases/x/triage.7z header must NOT be a member.
        assert "/cases/x/triage.7z" not in names
        assert "host/note.txt" in names

    def test_parser_classifies_kinds_and_setid(self):
        from opensearch_mcp.containers import _parse_7z_slt

        by_name = {m.name: m for m in _parse_7z_slt(_SLT_SAMPLE)}
        assert by_name["host/note.txt"].kind == "file"
        assert by_name["host/sub"].kind == "dir"
        assert by_name["host/evil-link"].kind == "symlink"
        assert by_name["host/setuid-bin"].setid is True

    def test_policy_rejects_symlink_member(self):
        from opensearch_mcp.containers import _enforce_policy, _Member

        with pytest.raises(ArchiveRejected, match="symlink"):
            _enforce_policy(
                Path("/nonexistent.7z"),
                Path("/tmp"),
                [_Member("l", 0, "symlink", False)],
            )

    def test_policy_rejects_traversal_member(self):
        from opensearch_mcp.containers import _enforce_policy, _Member

        with pytest.raises(ArchiveRejected, match="unsafe member path"):
            _enforce_policy(
                Path("/nonexistent.7z"),
                Path("/tmp"),
                [_Member("../escape.txt", 5, "file", False)],
            )

    def test_url_encoded_velociraptor_name_is_safe(self):
        """Velociraptor C%3A members are relative — must not be flagged unsafe."""
        from opensearch_mcp.containers import _is_unsafe_path

        assert _is_unsafe_path("uploads/auto/C%3A/Windows/System32") is False
        assert _is_unsafe_path("C:/Windows") is True  # real absolute drive path


# ---------------------------------------------------------------------------
# SEC-8 surfacing: the rejection reason rides the worker failed/result_public
# envelope (Seam C — the aggregate that becomes result_public).
# ---------------------------------------------------------------------------


class TestArchiveRejectionSurface:
    def test_reason_surfaces_on_failed_envelope(self):
        from opensearch_mcp.ingest_job import _aggregate
        from opensearch_mcp.ingest_status import HALT_ARCHIVE_REJECTED

        rid = "run-sec8"
        rec = {
            "status": "failed",
            "error": f"{HALT_ARCHIVE_REJECTED}: disallowed member type symlink: 'l'",
        }
        out = _aggregate({rid: rec}, {rid})
        assert out["failed"] is True
        assert HALT_ARCHIVE_REJECTED in out["error"]
        assert "symlink" in out["error"]


# ---------------------------------------------------------------------------
# SEC-8: memory archive path stages INSIDE the case jail (was /tmp)
# ---------------------------------------------------------------------------


class TestMemoryPathJail:
    def test_memory_block_uses_case_jail_not_tmp(self):
        """The memory archive block must stage via make_ingest_tmpdir, not /tmp."""
        import inspect

        from opensearch_mcp.ingest_cli import cmd_ingest_memory

        src = inspect.getsource(cmd_ingest_memory)
        assert "make_ingest_tmpdir" in src
        assert "extract_container" in src
        assert "tempfile.mkdtemp" not in src

    @pytest.mark.skipif(not HAVE_7Z, reason="7z binary not on PATH")
    def test_extract_lands_in_case_dir(self, tmp_path, monkeypatch):
        from opensearch_mcp.containers import make_ingest_tmpdir

        case_dir = tmp_path / "case-sec8"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

        mem = tmp_path / "image.raw"
        mem.write_bytes(b"MEMDUMP" * 100)
        src = tmp_path / "mem.7z"
        subprocess.run(["7z", "a", str(src), str(mem)], check=True, capture_output=True)

        jail = make_ingest_tmpdir("case-sec8")
        extract_container(src, jail)
        staged = list(jail.rglob("image.raw"))
        assert staged, "extracted image not found in case jail"
        assert staged[0].resolve().is_relative_to(case_dir.resolve())
