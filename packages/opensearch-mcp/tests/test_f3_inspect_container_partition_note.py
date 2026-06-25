"""F3-DIAG: opensearch_inspect_container surfaces a partition_note for E01 /
raw images that have no partition table (single-volume), so the agent doesn't
dead-end on `mmls` (exit 1, empty output)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import opensearch_mcp.server as srv
from opensearch_mcp.server import opensearch_inspect_container


_EWFINFO_OUT = (
    "ewfinfo 20140608\n\n"
    "Acquiry information\n"
    "\tCase number:\t\tROCBA-1\n"
    "\tExaminer name:\t\tanalyst\n\n"
    "EWF information\n"
    "\tFile format:\t\tEncase 6\n\n"
    "Media information\n"
    "\tMedia size:\t\t81 GiB (87431311360 bytes)\n"
)


def test_e01_single_volume_gets_partition_note(monkeypatch, tmp_path):
    """E01 success path with no partitions → partition_note present, pointing
    at fls -i ewf -f ntfs."""
    fake = tmp_path / "disk.E01"
    fake.write_bytes(b"EVF\x09")

    monkeypatch.setattr(srv, "_resolve_tool_path", lambda p, **kw: (fake, None))
    monkeypatch.setattr(srv, "_case_relative_ref", lambda p: "evidence/disk.E01")
    # ewfinfo binary "exists"
    monkeypatch.setattr(srv.Path, "exists", lambda self: str(self).endswith("ewfinfo"))

    proc = MagicMock(returncode=0, stdout=_EWFINFO_OUT, stderr="")
    with patch("subprocess.run", return_value=proc):
        result = opensearch_inspect_container("evidence/disk.E01")

    assert result["container_type"] == "e01"
    assert "partition_note" in result, result
    assert "fls -i ewf -f ntfs" in result["partition_note"]
    assert "mmls will" in result["partition_note"]


def test_e01_with_partitions_no_note(monkeypatch, tmp_path):
    """If partitions WERE discovered, no note is added (note is only for the
    single-volume dead-end)."""
    fake = tmp_path / "disk.E01"
    fake.write_bytes(b"EVF\x09")

    monkeypatch.setattr(srv, "_resolve_tool_path", lambda p, **kw: (fake, None))
    monkeypatch.setattr(srv, "_case_relative_ref", lambda p: "evidence/disk.E01")
    monkeypatch.setattr(srv.Path, "exists", lambda self: str(self).endswith("ewfinfo"))

    # _parse_ewfinfo returns no partitions; inject one post-hoc to simulate a
    # multi-partition image by patching _parse_ewfinfo.
    monkeypatch.setattr(
        srv, "_parse_ewfinfo",
        lambda out: {"partitions": [{"slot": "00", "type": "ntfs"}]},
    )
    proc = MagicMock(returncode=0, stdout=_EWFINFO_OUT, stderr="")
    with patch("subprocess.run", return_value=proc):
        result = opensearch_inspect_container("evidence/disk.E01")

    assert result["container_type"] == "e01"
    assert "partition_note" not in result, result
