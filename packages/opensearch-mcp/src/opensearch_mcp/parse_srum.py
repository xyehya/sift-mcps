"""SRUM parsing — wintools-first (SrumECmd), Plaso fallback."""

from __future__ import annotations

import shutil
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
#
# SrumECmd / CSV path: N/A here.  parse_csv.py has no `application` field at all
# (the SrumECmd CSV uses a different column, e.g. ExeInfo), so this Plaso-shaped
# flag does not apply.  Wiring a SrumECmd-path equivalent is DEFERRED until a
# SrumECmd-parsed case exists to confirm that column's semantics.
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
    """Parse SRUM database. Returns (count_indexed, count_bulk_failed, note).

    Strategy: wintools-first (SrumECmd on Windows), Plaso fallback.
    SRUDB.dat from KAPE triage is frequently dirty/locked — SrumECmd
    handles this (built-in repair), Plaso's esedb parser does not.
    """
    from opensearch_mcp.wintools import mark_wintools_down, wintools_available

    _fallback_note = (
        "srum: parsed with Plaso fallback (reduced fidelity). "
        "Provision wintools-mcp with SrumECmd for reliable SRUM analysis."
    )

    if wintools_available():
        try:
            cnt, bf = _parse_srum_wintools(
                srum_path,
                client,
                index_name,
                hostname,
                case_id=case_id,
                ingest_audit_id=ingest_audit_id,
                pipeline_version=pipeline_version,
                vss_id=vss_id,
                source_file=source_file,
                host_dict=host_dict,
            )
            return cnt, bf, ""  # wintools succeeded — no note
        except Exception as e:
            print(f"  srum: SrumECmd failed ({e}), trying Plaso...", file=sys.stderr)
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                mark_wintools_down()

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
        return cnt, bf, _fallback_note  # Plaso succeeded with reduced fidelity
    except subprocess.CalledProcessError:
        print(
            "  srum: skipped — dirty database, needs Windows workstation\n"
            f"  NOTE: {_fallback_note}",
            file=sys.stderr,
        )
        return 0, 0, _fallback_note


def _parse_srum_wintools(
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
) -> tuple[int, int]:
    """Parse SRUM via SrumECmd on Windows (wintools-mcp).

    Stages SRUDB.dat + SRU log files to the case extractions directory
    (on the SMB share). SrumECmd's ManagedEsent needs write access for
    dirty ESE database recovery.
    """
    from sift_common import resolve_case_dir

    from opensearch_mcp.parse_csv import ingest_csv, table_name_from_stem
    from opensearch_mcp.wintools import run_tool_and_get_csv

    case_dir_str = resolve_case_dir()
    if not case_dir_str:
        raise RuntimeError("No active case directory")
    case_dir = Path(case_dir_str)

    # Stage SRUM to case extractions (on the SMB share) for ESE recovery
    srum_workdir = case_dir / "extractions" / "srum" / hostname
    srum_workdir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(srum_path, srum_workdir / "SRUDB.dat")

    # Also copy SRU log files if present (needed for full recovery)
    sru_dir = srum_path.parent
    for log_file in sru_dir.glob("SRU*.log"):
        shutil.copy2(log_file, srum_workdir / log_file.name)

    # Pass the staged path — run_tool_and_get_csv handles UNC conversion
    csv_files = run_tool_and_get_csv(
        tool_binary="SrumECmd.exe",
        input_flag="-f",
        evidence_path=str(srum_workdir / "SRUDB.dat"),
        purpose="Parse SRUM database for resource usage monitoring",
        hostname=hostname,
    )

    if not csv_files:
        raise RuntimeError("SrumECmd produced no CSV output")

    total_count = 0
    total_failed = 0
    for csv_file in csv_files:
        # SrumECmd emits several sub-tables (NetworkUsages, AppResourceUseInfo,
        # ...) into ONE index. Derive a per-CSV table_name so _doc_id folds the
        # logical table into the content-hash seed — otherwise two sub-tables
        # with identical raw columns collide on the same _id (silent overwrite).
        table_name = table_name_from_stem(csv_file.stem)
        count, _sk, bf = ingest_csv(
            csv_path=csv_file,
            client=client,
            index_name=index_name,
            hostname=hostname,
            source_file=source_file or str(srum_path),
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            table_name=table_name,
            vss_id=vss_id,
            parse_method="SrumECmd",
            host_dict=host_dict,
        )
        total_count += count
        total_failed += bf

    return total_count, total_failed


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
