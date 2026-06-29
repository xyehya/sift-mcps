"""Tests for the per-CSV ``table_name`` derivation helper (issue #13).

When a parser emits several CSV sub-tables into ONE OpenSearch index, each CSV
must thread a distinct ``table_name`` into ``ingest_csv`` so two sub-table rows
with identical raw content do not collide on the same content-hash ``_id``.
``table_name_from_stem`` derives that logical table name from the CSV stem.
"""

from opensearch_mcp.parse_csv import table_name_from_stem


def test_table_name_from_stem_strips_timestamp_prefix():
    """The shared helper mirrors tools.py multi_csv stem stripping."""
    assert (
        table_name_from_stem("20260329224802_NetworkUsages") == "NetworkUsages"
    )
    # No timestamp prefix -> full stem.
    assert table_name_from_stem("PECmd_Output") == "PECmd_Output"
    # Non-digit leading segment -> full stem.
    assert table_name_from_stem("abc_def") == "abc_def"
