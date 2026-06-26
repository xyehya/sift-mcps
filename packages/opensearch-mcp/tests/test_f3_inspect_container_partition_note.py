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


# ---------------------------------------------------------------------------
# REGISTRY-SURFACE tests (the actual agent-facing contract). The earlier impl
# tests passed gates but the fix was INERT live because InspectContainerOut
# (the Pydantic out_model) dropped partition_note. These pin the surface.
# ---------------------------------------------------------------------------


class TestInspectContainerRegistrySurface:
    def test_out_model_has_partition_note_field(self):
        from opensearch_mcp.registry import InspectContainerOut

        assert "partition_note" in InspectContainerOut.model_fields

    def test_out_model_serializes_partition_note(self):
        """A partition_note set on the model must survive model_dump (the
        payload the agent actually receives)."""
        from opensearch_mcp.registry import InspectContainerOut

        out = InspectContainerOut(
            path="evidence/disk.E01",
            resolved_path="evidence/disk.E01",
            container_type="e01",
            tool_available=True,
            partition_note="no partition table — use fls -i ewf -f ntfs",
        )
        dumped = out.model_dump(mode="json")
        assert dumped["partition_note"] == "no partition table — use fls -i ewf -f ntfs"

    def test_out_model_partition_note_defaults_none(self):
        from opensearch_mcp.registry import InspectContainerOut

        out = InspectContainerOut(
            path="p", resolved_path="p", container_type="file", tool_available=False
        )
        assert out.model_dump(mode="json")["partition_note"] is None

    def test_run_inspect_container_propagates_partition_note(self, monkeypatch):
        """End-to-end registry surface: when the impl returns partition_note, the
        ToolResult structured_content (what the agent sees) carries it."""
        import asyncio

        from opensearch_mcp import registry

        raw = {
            "path": "evidence/disk.E01",
            "resolved_path": "evidence/disk.E01",
            "container_type": "e01",
            "tool_available": True,
            "partitions": [],
            "partition_note": "no partition table detected — use fls -i ewf -f ntfs <path> directly",
        }

        class _FakeImpl:
            def opensearch_inspect_container(self, **kwargs):
                return raw

        monkeypatch.setattr(registry, "_impl_server", lambda: _FakeImpl())

        params = registry.InspectContainerIn(path="evidence/disk.E01")
        result = asyncio.run(registry.run_opensearch_inspect_container(params))
        sc = result.structured_content
        assert sc["partition_note"] == raw["partition_note"]
        assert sc["container_type"] == "e01"
