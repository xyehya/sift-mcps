"""Prefetch parsing via Plaso (prefetch parser)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch


def parse_prefetch(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int, str]:
    """Parse prefetch files via Plaso. Returns (count_indexed, count_bulk_failed, note).

    On a Plaso failure the directory is skipped and a note is returned rather
    than raising.
    """
    try:
        cnt, bf = _parse_prefetch_plaso(
            prefetch_dir,
            client,
            index_name,
            hostname,
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            vss_id=vss_id,
            source_file=source_file,
            host_dict=host_dict,
        )
        return cnt, bf, ""
    except subprocess.CalledProcessError as e:
        note = "prefetch: skipped — Plaso parse failed."
        print(f"  prefetch: Plaso failed ({e})", file=sys.stderr)
        return 0, 0, note


def _parse_prefetch_plaso(
    prefetch_dir: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int]:
    """Parse prefetch via Plaso prefetch parser."""
    from opensearch_mcp.parse_plaso import parse_prefetch as _plaso_prefetch

    return _plaso_prefetch(
        prefetch_dir=prefetch_dir,
        client=client,
        index_name=index_name,
        hostname=hostname,
        ingest_audit_id=ingest_audit_id,
        pipeline_version=pipeline_version,
        vss_id=vss_id,
        source_file=source_file,
        host_dict=host_dict,
    )
