"""B2 regression — case_info file-structure walk must survive ingest FUSE mounts.

While an OpenSearch ingest worker has an E01 FUSE-mounted under the case
``tmp/`` (``tmp/ingest-<id>/xmount-<...>/``), the old ``rglob('*')`` walk
descended into the mount and died with
``OSError: [Errno 5] Input/output error``, breaking ``case_info`` for every
agent. The walk must (a) prune ``tmp/ingest-*`` / ``xmount-*`` staging dirs and
(b) defensively skip any entry that raises ``OSError``.
"""

from __future__ import annotations

import os

import pytest

from sift_core.agent_tools import _case_file_structure


def _make_case(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-b2-06140101"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence" / "rocba-cdrive.e01").write_bytes(b"E01\x00data")
    (case_dir / "reports").mkdir()
    (case_dir / "tmp").mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: B2-001\nexaminer: analyst\n")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.delenv("SIFT_CASES_ROOT", raising=False)
    monkeypatch.delenv("SIFT_CASES_DIR", raising=False)
    return case_dir


def test_ingest_mount_subtree_excluded(tmp_path, monkeypatch):
    """tmp/ingest-*/xmount-* staging is pruned from the walk (not counted)."""
    case_dir = _make_case(tmp_path, monkeypatch)
    mount = case_dir / "tmp" / "ingest-abc123" / "xmount-rocba-cdrive" / "$GetCurrent"
    mount.mkdir(parents=True)
    (mount / "media").write_bytes(b"would-be-mounted-content")

    result = _case_file_structure()

    # No path under the ingest mount staging appears anywhere.
    assert all("ingest-abc123" not in d for d in _read_dirs(case_dir))
    # tmp subtree contributes zero files (mount pruned).
    assert result["file_counts_by_subtree"].get("tmp", 0) == 0
    # Real case files still counted.
    assert result["file_counts_by_subtree"].get("evidence", 0) == 1
    assert "evidence" in result["top_level_dirs"]


def _read_dirs(case_dir):
    import json

    data = json.loads(
        (case_dir / "agent" / "case_file_structure.json").read_text()
    )
    return data["directories"]


def test_oserror_entry_does_not_crash(tmp_path, monkeypatch):
    """A directory whose scandir raises OSError is skipped, tool still returns."""
    case_dir = _make_case(tmp_path, monkeypatch)
    bad = case_dir / "tmp" / "ingest-live" / "xmount-x"
    bad.mkdir(parents=True)

    real_scandir = os.scandir

    def flaky_scandir(path, *args, **kwargs):
        # Simulate a FUSE mount returning Errno 5 mid-walk for the mount path.
        if "xmount-x" in str(path):
            raise OSError(5, "Input/output error")
        return real_scandir(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", flaky_scandir)

    # Must not raise even though an io-erroring path exists under the case.
    result = _case_file_structure()
    assert result["total_files"] >= 1
    assert result["file_counts_by_subtree"].get("evidence", 0) == 1


def test_normal_tree_intact(tmp_path, monkeypatch):
    """Non-mount tmp content and other subtrees are still walked normally."""
    case_dir = _make_case(tmp_path, monkeypatch)
    (case_dir / "tmp" / "scratch.txt").write_text("ok")
    (case_dir / "reports" / "r1.json").write_text("{}")

    result = _case_file_structure()

    assert result["file_counts_by_subtree"].get("tmp", 0) == 1
    assert result["file_counts_by_subtree"].get("reports", 0) == 1
    assert result["file_counts_by_subtree"].get("evidence", 0) == 1
    assert result["total_files"] >= 3
