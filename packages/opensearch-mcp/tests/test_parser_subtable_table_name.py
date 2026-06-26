"""Regression test for issue #13: parse_srum / parse_prefetch must thread a
per-CSV ``table_name`` into ``ingest_csv`` so that multiple sub-tables sharing
ONE OpenSearch index do not collide on the same content-hash ``_id``.

SrumECmd and PECmd each emit several CSV sub-tables (NetworkUsages /
AppResourceUseInfo; PECmd_Output / PECmd_Timeline) into one index. After
XYE-40 the content-hash ``_id`` folds only raw evidence columns + index_name +
the logical ``table`` — so two sub-table rows with IDENTICAL raw content
collide on the same ``_id`` (silent overwrite / data loss) UNLESS the parser
supplies a distinct ``table_name`` per CSV.

These tests drive the real wintools parser loops with ``run_tool_and_get_csv``
mocked to return two sub-table CSVs (identical raw content, different stems)
and ``flush_bulk`` patched to capture the emitted bulk actions. They assert:
  (a) the two rows get DISTINCT ``_id``s, and
  (b) each row carries its correct ``sift.table`` stamp.

Before the fix (no ``table_name`` passed) both rows hash to the SAME ``_id``
and neither carries ``sift.table`` — so both assertions fail.
"""

import csv
from unittest.mock import MagicMock, patch

import opensearch_mcp.parse_prefetch as parse_prefetch_mod
import opensearch_mcp.parse_srum as parse_srum_mod
from opensearch_mcp.parse_csv import table_name_from_stem


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def _capture_factory():
    """Return (captured_list, side_effect) for patching flush_bulk."""
    captured: list[dict] = []

    def capture(_client, actions):
        captured.extend(actions)
        return len(actions), 0

    return captured, capture


def test_table_name_from_stem_strips_timestamp_prefix():
    """The shared helper mirrors tools.py multi_csv stem stripping."""
    assert (
        table_name_from_stem("20260329224802_NetworkUsages") == "NetworkUsages"
    )
    # No timestamp prefix -> full stem.
    assert table_name_from_stem("PECmd_Output") == "PECmd_Output"
    # Non-digit leading segment -> full stem.
    assert table_name_from_stem("abc_def") == "abc_def"


def test_srum_subtables_get_distinct_ids_and_table_stamp(tmp_path):
    """Two SrumECmd sub-tables with identical raw rows -> distinct _id +
    correct per-sub-table sift.table. Regression for issue #13."""
    # Two EZ-tools-named CSVs, IDENTICAL raw content column.
    csv_a = tmp_path / "20260329224802_NetworkUsages.csv"
    csv_b = tmp_path / "20260329224802_AppResourceUseInfo.csv"
    row = [{"ExeInfo": "C:\\Windows\\System32\\svchost.exe", "BytesSent": "1024"}]
    _write_csv(csv_a, row)
    _write_csv(csv_b, row)

    captured, capture = _capture_factory()

    with (
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=capture),
        patch(
            "opensearch_mcp.wintools.run_tool_and_get_csv",
            return_value=[csv_a, csv_b],
        ),
        patch("sift_common.resolve_case_dir", return_value=str(tmp_path)),
        patch("opensearch_mcp.parse_srum.shutil.copy2"),
    ):
        # Call the real wintools loop directly; copy2 is patched out and
        # the staged SRUDB.dat need not exist.
        parse_srum_mod._parse_srum_wintools(
            srum_path=tmp_path / "SRUDB.dat",
            client=MagicMock(),
            index_name="case-x-srum-host1",
            hostname="HOST1",
        )

    assert len(captured) == 2, f"expected 2 rows, got {len(captured)}"
    ids = [a["_id"] for a in captured]
    tables = {a["_source"].get("sift.table") for a in captured}

    # (a) distinct ids despite identical raw content
    assert ids[0] != ids[1], "sub-table rows collided on the same _id (#13)"
    # (b) each row carries its correct sift.table stamp
    assert tables == {"NetworkUsages", "AppResourceUseInfo"}, (
        f"unexpected sift.table set: {tables}"
    )


def test_prefetch_subtables_get_distinct_ids_and_table_stamp(tmp_path):
    """Two PECmd sub-tables with identical raw rows -> distinct _id +
    correct per-sub-table sift.table. Regression for issue #13."""
    csv_main = tmp_path / "20260329224802_PECmd_Output.csv"
    csv_timeline = tmp_path / "20260329224802_PECmd_Timeline.csv"
    row = [{"ExecutableName": "EVIL.EXE", "RunCount": "3"}]
    _write_csv(csv_main, row)
    _write_csv(csv_timeline, row)

    captured, capture = _capture_factory()

    with (
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=capture),
        patch(
            "opensearch_mcp.wintools.run_tool_and_get_csv",
            return_value=[csv_main, csv_timeline],
        ),
    ):
        parse_prefetch_mod._parse_prefetch_wintools(
            prefetch_dir=tmp_path,
            client=MagicMock(),
            index_name="case-x-prefetch-host1",
            hostname="HOST1",
        )

    assert len(captured) == 2, f"expected 2 rows, got {len(captured)}"
    ids = [a["_id"] for a in captured]
    tables = {a["_source"].get("sift.table") for a in captured}

    assert ids[0] != ids[1], "sub-table rows collided on the same _id (#13)"
    assert tables == {"PECmd_Output", "PECmd_Timeline"}, (
        f"unexpected sift.table set: {tables}"
    )
