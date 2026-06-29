"""SRUM parsing via Plaso (esedb/srum parser)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch


# F9 (LIVE-CONFIRMED + WIRED for the Plaso path).
#
# Root cause (confirmed from code): there is NO application-id → name resolution
# step anywhere in the opensearch-mcp ingest code.  The `application` field on a
# SRUM document is written 1:1 from whatever the parser tool emits.  SRUM stores
# each row's application as a numeric SruDbId foreign key into SruDbIdMapTable.
#
# Live ground truth (case-test-case-06251017-srum-rocba, every row
# sift.parse_method:"plaso"): Plaso's esedb/srum emits EITHER a resolved name
# (application:"TermService", user_identifier:"S-1-5-20") OR a bare numeric id
# (application:1, user_identifier:2, data_type:"windows:srum:network_usage")
# when the SruDbIdMapTable entry for that id does not decode to a name.  Plaso
# itself printed "Application: 1" in `message`, so re-resolving is unreliable —
# FLAGGING (this helper) is the correct, validated behaviour.  Without it a bare
# `1` is indexed as if it were an application NAME, misleading top-egress views.
#
# WIRED: applied in parse_plaso._ingest_jsonl, gated on
# data_type == "windows:srum:network_usage" (that path is shared by other Plaso
# parsers, so only SRUM network-usage docs are touched).
def flag_unresolved_srum_application(doc: dict) -> dict:
    """Flag a SRUM document whose ``application`` is an unresolved numeric id.

    If ``doc["application"]`` is a bare integer (e.g. ``"1"`` or ``1``) — i.e. an
    unresolved SruDbId rather than a resolved executable name — set
    ``application_unresolved = True`` and preserve the raw id in
    ``application_id``.  Resolved string names (e.g. ``"TermService"``) and
    missing/empty values are left untouched.  Mutates and returns ``doc``.
    """
    if not isinstance(doc, dict):
        return doc
    app = doc.get("application")
    if app is None or app == "":
        return doc
    # Bare integer (int, or a string that is all digits) ⇒ unresolved SruDbId.
    is_bare_int = isinstance(app, int) and not isinstance(app, bool)
    if isinstance(app, str) and app.strip().isdigit():
        is_bare_int = True
    if is_bare_int:
        doc["application_unresolved"] = True
        doc["application_id"] = str(app).strip()
    return doc


def parse_srum(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    case_id: str = "",
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int, str]:
    """Parse a SRUM database via Plaso. Returns (count_indexed, count_bulk_failed, note).

    SRUDB.dat from KAPE triage is frequently dirty/locked. Plaso's esedb parser
    cannot always recover a dirty database; when it fails the file is skipped and
    a note is returned rather than raising.
    """
    try:
        cnt, bf = _parse_srum_plaso(
            srum_path,
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
    except subprocess.CalledProcessError:
        note = "srum: skipped — dirty database could not be parsed by Plaso."
        print(f"  {note}", file=sys.stderr)
        return 0, 0, note


def _parse_srum_plaso(
    srum_path: Path,
    client: OpenSearch,
    index_name: str,
    hostname: str,
    ingest_audit_id: str = "",
    pipeline_version: str = "",
    vss_id: str = "",
    source_file: str = "",
    host_dict=None,
) -> tuple[int, int]:
    """Parse SRUM via Plaso esedb/srum parser."""
    from opensearch_mcp.parse_plaso import parse_srum as _plaso_srum

    return _plaso_srum(
        srum_path=srum_path,
        client=client,
        index_name=index_name,
        hostname=hostname,
        ingest_audit_id=ingest_audit_id,
        pipeline_version=pipeline_version,
        vss_id=vss_id,
        source_file=source_file,
        host_dict=host_dict,
    )
