"""Integration-level tests for filesystem-meta sidecar write in server.py.

These tests exercise the wiring in _launch_container_ingest and
idx_ingest_memory that writes agent/ingest/<run_id>-filesystem-meta.json
and attaches filesystem_meta_path to the response dict.

No OpenSearch connection is required. The key mocks are:
  - _spawn_ingest → fake process (no subprocess)
  - read_active_ingests → [] (no concurrent guard hit)
  - audit.log → None (no AuditWriter needed)
  - sift_dir → tmp_path (no real ~/.sift writes)
  - containers.subprocess → partitioned_disk TSK output
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures: TSK outputs that represent a partitioned disk (same as test_containers.py)
# ---------------------------------------------------------------------------

_MMLS_PARTITIONED = """\
 DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000409599   0000407552   NTFS / exFAT (0x07)
"""

_FSSTAT_NTFS = """\
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Version: Windows XP

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
"""

_IMG_STAT = """\
 IMAGE FILE INFORMATION
--------------------------------------------
Image Type: raw

Size in bytes: 209715200
Sector size:\t512
"""


def _tsk_side_effect(cmd, **kw):
    tool = cmd[0]
    if tool == "mmls":
        return MagicMock(stdout=_MMLS_PARTITIONED, returncode=0)
    if tool == "img_stat":
        return MagicMock(stdout=_IMG_STAT, returncode=0)
    if tool == "fsstat":
        return MagicMock(stdout=_FSSTAT_NTFS, returncode=0)
    return MagicMock(stdout="", returncode=1)


# ---------------------------------------------------------------------------
# _launch_container_ingest sidecar write
# ---------------------------------------------------------------------------


class TestLaunchContainerIngestSidecar:
    @patch("opensearch_mcp.containers.subprocess")
    @patch("opensearch_mcp.server.audit")
    @patch("opensearch_mcp.server._spawn_ingest")
    @patch("opensearch_mcp.ingest_status.read_active_ingests")
    @patch("opensearch_mcp.paths.sift_dir")
    def test_sidecar_written_on_partitioned_disk(
        self,
        mock_sift_dir,
        mock_read_active,
        mock_spawn,
        mock_audit,
        mock_subprocess,
        tmp_path,
        monkeypatch,
    ):
        from opensearch_mcp.server import _launch_container_ingest

        # Redirect ~/.sift writes to tmp_path
        mock_sift_dir.return_value = tmp_path
        mock_read_active.return_value = []
        mock_spawn.return_value = MagicMock(pid=9999)
        mock_audit.log.return_value = None
        mock_subprocess.run.side_effect = _tsk_side_effect

        # Set SIFT_CASE_DIR so the sidecar write path is active
        case_dir = tmp_path / "mycase-001"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

        # Create a fake image file (needed for log_file open)
        fake_image = tmp_path / "disk.img"
        fake_image.touch()

        resp = _launch_container_ingest(str(fake_image), "mycase-001")

        # Response should carry the relative path
        assert "filesystem_meta_path" in resp, f"Missing filesystem_meta_path in {resp}"
        rel = resp["filesystem_meta_path"]
        assert rel.startswith("agent/ingest/")
        assert rel.endswith("-filesystem-meta.json")

        # The physical file must exist under case_dir
        sidecar = case_dir / rel
        assert sidecar.exists(), f"Sidecar not written at {sidecar}"

        # Content must be valid JSON with partitioned_disk
        meta = json.loads(sidecar.read_text())
        assert meta["image_type"] == "partitioned_disk"
        assert meta["partitions"][0]["start_sector"] == 2048
        assert meta["partitions"][0]["fs_type"] == "NTFS"

    @patch("opensearch_mcp.containers.subprocess")
    @patch("opensearch_mcp.server.audit")
    @patch("opensearch_mcp.server._spawn_ingest")
    @patch("opensearch_mcp.ingest_status.read_active_ingests")
    @patch("opensearch_mcp.paths.sift_dir")
    def test_no_sidecar_when_tsk_absent(
        self,
        mock_sift_dir,
        mock_read_active,
        mock_spawn,
        mock_audit,
        mock_subprocess,
        tmp_path,
        monkeypatch,
    ):
        from opensearch_mcp.server import _launch_container_ingest

        mock_sift_dir.return_value = tmp_path
        mock_read_active.return_value = []
        mock_spawn.return_value = MagicMock(pid=9999)
        mock_audit.log.return_value = None
        mock_subprocess.run.side_effect = FileNotFoundError("mmls not found")

        case_dir = tmp_path / "mycase-002"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

        fake_image = tmp_path / "disk.img"
        fake_image.touch()

        resp = _launch_container_ingest(str(fake_image), "mycase-002")

        # When TSK tools are absent, image_type == "unknown" → no sidecar written
        assert "filesystem_meta_path" not in resp
        sidecars = list((case_dir / "agent" / "ingest").glob("*-filesystem-meta.json")) if (case_dir / "agent" / "ingest").exists() else []
        assert sidecars == []


# ---------------------------------------------------------------------------
# idx_ingest_memory sidecar write
# ---------------------------------------------------------------------------


class TestMemoryIngestSidecar:
    @patch("opensearch_mcp.shard_capacity.check_shard_headroom")
    @patch("opensearch_mcp.bulk.reset_circuit_breaker")
    @patch("opensearch_mcp.server.get_client")
    @patch("opensearch_mcp.server.audit")
    @patch("opensearch_mcp.server._spawn_ingest")
    @patch("opensearch_mcp.ingest_status.write_status")
    @patch("opensearch_mcp.ingest_status.read_active_ingests")
    @patch("opensearch_mcp.paths.sift_dir")
    def test_memory_sidecar_written(
        self,
        mock_sift_dir,
        mock_read_active,
        mock_write_status,
        mock_spawn,
        mock_audit,
        mock_get_client,
        mock_reset_cb,
        mock_shard,
        tmp_path,
        monkeypatch,
    ):
        """idx_ingest_memory must write a memory_image sidecar via _collect_filesystem_meta."""
        from opensearch_mcp.server import idx_ingest_memory

        mock_sift_dir.return_value = tmp_path
        mock_read_active.return_value = []
        mock_spawn.return_value = MagicMock(pid=9998)
        mock_audit.log.return_value = None
        mock_get_client.return_value = MagicMock()
        mock_shard.return_value = (True, "")

        case_dir = tmp_path / "mycase-mem"
        case_dir.mkdir()
        monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

        # Create a LiME memory image inside evidence/ (path guard requires this)
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir()
        lime_image = evidence_dir / "mem.lime"
        lime_image.write_bytes(b"LIME" + b"\x00" * 200)

        resp = idx_ingest_memory(
            path="evidence/mem.lime",
            hostname="testhost",
            tier=1,
            dry_run=False,
        )

        assert "filesystem_meta_path" in resp, f"Missing filesystem_meta_path in {resp}"
        rel = resp["filesystem_meta_path"]
        sidecar = case_dir / rel
        assert sidecar.exists(), f"Memory sidecar not written at {sidecar}"

        meta = json.loads(sidecar.read_text())
        assert meta["image_type"] == "memory_image"
        assert meta["memory_format"] == "lime"
