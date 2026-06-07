"""OpenSearch MCP server — 17 tools for forensic evidence querying, ingest, and enrichment.

Module-import side effect: installs a SIGCHLD reaper (see
`_install_sigchld_reaper`) so child zombies from ingest subprocesses
are reaped without blocking the gateway. Any process that imports
this module gets the handler.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from sift_core.case_io import cases_root, resolve_case_path
from mcp.server.fastmcp import FastMCP
from opensearchpy.exceptions import (
    AuthorizationException,
    ConnectionTimeout,
    RequestError,
)
from opensearchpy.exceptions import ConnectionError as OSConnectionError
from sift_common.audit import AuditWriter
from sift_common.instructions import OPENSEARCH

from opensearch_mcp.client import get_client
from opensearch_mcp.host_dictionary import detect_host_id_mapping_type

logger = logging.getLogger(__name__)


def _validate_index(index: str) -> str | None:
    """Validate all index segments start with 'case-'. Returns error or None."""
    if not index or not index.strip():
        return "Index parameter must not be empty"
    for segment in index.split(","):
        segment = segment.strip()
        if not segment:
            continue
        if not segment.startswith("case-"):
            return (
                f"Index segment '{segment}' must start with 'case-' "
                "(security: blocks access to system indices)"
            )
    return None


server = FastMCP("opensearch-mcp", instructions=OPENSEARCH)
audit = AuditWriter(mcp_name="opensearch-mcp")

# --- Enrichment Token Budget: Layer 11 shimcache/amcache decay ---
_shimcache_reminder_count = 0


def _add_shimcache_reminder(resp: dict, index_pattern: str, docs: list) -> None:
    """Add discipline reminder when query hits shimcache/amcache indices."""
    global _shimcache_reminder_count
    hits = (
        "shimcache" in index_pattern
        or "appcompatcache" in index_pattern
        or "amcache" in index_pattern
    )
    if not hits and docs:
        hits = any(
            "shimcache" in d.get("_index", "")
            or "appcompatcache" in d.get("_index", "")
            or "amcache" in d.get("_index", "")
            for d in docs
        )
    if not hits:
        return
    _shimcache_reminder_count += 1
    if _shimcache_reminder_count <= 2:
        resp["discipline_reminder"] = (
            "IMPORTANT: Shimcache and Amcache prove FILE PRESENCE only, "
            "never execution. The 'Executed' column in AppCompatCacheParser "
            "is unreliable on all Windows versions — do not use it to prove "
            "or disprove execution. To prove execution: check Prefetch, "
            "RegRipper BAM plugin (rip.pl -r SYSTEM -p bam — Windows 10 1709+ only, "
            "entries expire after 7 days, local executables only), UserAssist "
            "(rip.pl -r NTUSER.DAT -p userassist), or process creation "
            "events (EID 4688, Sysmon EID 1)."
        )
    else:
        resp["discipline_reminder"] = "Shimcache/Amcache = PRESENCE only, not execution."


# --- Enrichment Token Budget: Layer 9 investigation hints decay ---
_hints_delivered = False


def _add_investigation_hints(resp: dict, artifacts: dict) -> None:
    """Add investigation hints to opensearch_case_summary. Full on first call, pointer after."""
    global _hints_delivered
    if _hints_delivered:
        resp["investigation_hints"] = [
            "MFT/USN/evtx indexed — use get_tool_help for investigation patterns"
        ]
        return

    hints = []
    art_keys = set(artifacts.keys())
    has_mft = any("mft" in k for k in art_keys)
    has_usn = any("usn" in k or "usnjournal" in k for k in art_keys)
    has_evtx = any("evtx" in k for k in art_keys)
    has_prefetch = any("prefetch" in k or "pecmd" in k for k in art_keys)
    if has_mft:
        hints.append(
            'MFT indexed. Timestomping: "SI<FN".keyword:True OR '
            "uSecZeros.keyword:True (exclude WinSxS). "
            "Deleted: InUse.keyword:False. ADS: HasAds.keyword:True. "
            "Zone.Identifier: ZoneIdContents:* AND FileName:(*.exe OR *.dll OR *.ps1)"
        )
    if has_usn:
        hints.append(
            "USN Journal indexed. Use time_from/time_to. "
            "Deleted Prefetch: UpdateReasons:*Delete* AND ParentPath:*Prefetch*. "
            "Code deployment: Name:(*.exe OR *.dll OR *.ps1) AND UpdateReasons:*FileCreate*. "
            "SDelete: Name:AAAAAAA* AND UpdateReasons:*Rename* "
            "(verify with surrounding entries). "
            "Cross-host: same filename across case-*-usn-*"
        )
    if has_evtx:
        hints.append(
            "EVTX indexed. Key queries: event.code:4624 (logons), "
            "event.code:4688 (process creation), event.code:7045 (service install). "
            "Use opensearch_aggregate on event.code for frequency overview."
        )
    if has_prefetch and has_mft:
        hints.append(
            "Cross-ref Prefetch+MFT: prefetched exe with InUse=False in MFT = "
            "executed then deleted (anti-forensics)."
        )

    if not hints:
        return

    # Budget: sort by doc count, keep top 3, cap at 500 chars
    def _doc_count(hint: str) -> int:
        for art_name, art_info in artifacts.items():
            if isinstance(art_info, dict) and art_name in hint.lower():
                return art_info.get("docs", 0)
        return 0

    hints.sort(key=_doc_count, reverse=True)
    kept: list[str] = []
    total = 0
    for hint in hints:
        if total + len(hint) > 500 and kept:
            break
        kept.append(hint)
        total += len(hint)
        if len(kept) >= 3:
            break

    resp["investigation_hints"] = kept
    _hints_delivered = True


def _build_coverage_state(
    artifacts: dict,
    enrichment: dict,
    case_dir: "Path | None" = None,
) -> dict:
    """Compute coverage state for opensearch_case_summary.

    Compares present artifact keys against expected registry. Returns
    disk_artifacts, memory tier/plugin state, enrichment status, actionable
    gaps, and filesystem_meta_path (relative path to the most recent sidecar,
    or None). No new OpenSearch queries.
    """
    from pathlib import Path as _Path
    from opensearch_mcp.parse_memory import TIER_1, TIER_2, TIER_3, _plugin_to_index_suffix

    art_keys = set(artifacts.keys())

    # Disk artifact registry: skill_area → (candidate index keys, absent_status)
    _DISK: dict[str, tuple[set[str], str]] = {
        "evtx":       ({"evtx"},                    "not_run"),
        "hayabusa":   ({"hayabusa"},                 "not_run"),
        "amcache":    ({"amcache", "delim-amcache"}, "not_run"),
        "shimcache":  ({"shimcache"},                "not_run"),
        "registry":   ({"registry"},                 "not_run"),
        "shellbags":  ({"shellbags"},                "not_run"),
        "jumplists":  ({"jumplists"},                "not_run"),
        "lnk":        ({"lnk"},                      "not_run"),
        "recyclebin": ({"recyclebin"},               "not_run"),
        "mft":        ({"mft", "delim-mftecmd"},     "not_run"),
        "usn":        ({"usn"},                      "not_run"),
        "prefetch":   ({"prefetch"},                 "not_run"),
        "srum":       ({"srum", "delim-srumecmd"},   "not_run"),
        "tasks":      ({"tasks"},                    "not_run"),
        "browser":    (set(),                        "not_available"),
        "autoruns":   (set(),                        "not_available"),
    }
    disk_artifacts = {
        skill: "indexed" if any(k in art_keys for k in keys) else absent
        for skill, (keys, absent) in _DISK.items()
    }

    # Memory: which vol-* indices are present
    vol_keys = {k for k in art_keys if k.startswith("vol-")}
    suffix_to_plugin = {_plugin_to_index_suffix(p): p for p in TIER_3}

    if vol_keys:
        t3_excl = set(TIER_3) - set(TIER_2)
        t2_excl = set(TIER_2) - set(TIER_1)
        if any(_plugin_to_index_suffix(p) in vol_keys for p in t3_excl):
            tier_run = 3
        elif any(_plugin_to_index_suffix(p) in vol_keys for p in t2_excl):
            tier_run = 2
        else:
            tier_run = 1
        plugins_run = sorted(
            suffix_to_plugin[k] for k in vol_keys if k in suffix_to_plugin
        )
        plugins_not_run = [p for p in TIER_3 if _plugin_to_index_suffix(p) not in vol_keys]
    else:
        tier_run = None
        plugins_run = []
        plugins_not_run = list(TIER_1)

    memory: dict = {
        "tier_run": tier_run,
        "plugins_run": plugins_run,
        "plugins_not_run": plugins_not_run,
    }

    # Enrichment: derive from already-computed enrichment dict
    enrichment_state = {
        "triage": "done" if "triage" in enrichment else "not_run",
        "threat_intel": "done" if "threat_intel" in enrichment else "not_run",
    }

    # Gaps: actionable items derived from what's absent
    gaps: list[dict] = []

    if not vol_keys:
        gaps.append({
            "coverage_gap": "No memory analysis run — process, network, and module data unavailable.",
            "when_to_run": "When a memory image is available in evidence/.",
            "command": "opensearch_ingest(path='<memory_image>', format='memory', hostname='<hostname>', tier=1)",
            "output_path": None,
            "next_mcp_step": "opensearch_case_summary to verify vol-pslist, vol-netscan, vol-psscan indices",
            "warning": "Tier 1 takes 2-5 minutes on a 16GB image.",
        })
    elif tier_run == 1:
        mem_host = next(
            (h for k, v in artifacts.items() if k.startswith("vol-") for h in v.get("hosts", [])),
            "<hostname>",
        )
        gaps.append({
            "coverage_gap": "Memory Tier 2 not run — dlllist, envars, getsids, ldrmodules not indexed.",
            "when_to_run": "When suspicious processes or services found in Tier 1 results.",
            "command": f"opensearch_ingest(path='<memory_image>', format='memory', hostname='{mem_host}', tier=2)",
            "output_path": None,
            "next_mcp_step": "opensearch_search on vol-dlllist or vol-ldrmodules after completion",
            "warning": "Tier 2 adds 5-10 minutes on a 16GB image.",
        })

    if disk_artifacts.get("mft") == "not_run":
        gaps.append({
            "coverage_gap": "MFT not indexed — file creation/deletion/timestomping analysis unavailable.",
            "when_to_run": "Include in initial ingest when disk image is available.",
            "command": "opensearch_ingest(path='<disk_image>', format='auto', hostname='<hostname>')",
            "output_path": None,
            "next_mcp_step": "opensearch_search on mft index for InUse=False (deleted) or SI<FN (timestomping)",
            "warning": None,
        })

    if enrichment_state["triage"] == "not_run" and art_keys:
        gaps.append({
            "coverage_gap": "Triage enrichment not run — file/service/registry baselines not checked.",
            "when_to_run": "After initial ingest completes.",
            "command": "opensearch_enrich_triage()",
            "output_path": None,
            "next_mcp_step": "opensearch_case_summary to verify enrichment.triage counts",
            "warning": None,
        })

    if enrichment_state["threat_intel"] == "not_run" and art_keys:
        gaps.append({
            "coverage_gap": "Threat intel enrichment not run — IPs and hashes not checked against OpenCTI.",
            "when_to_run": "After initial ingest; requires OpenCTI running.",
            "command": "opensearch_enrich_intel()",
            "output_path": None,
            "next_mcp_step": "opensearch_case_summary to verify enrichment.threat_intel counts",
            "warning": "Takes 15-60 minutes for large IOC corpora.",
        })

    # Locate most-recent filesystem sidecar for this case
    filesystem_meta_path: str | None = None
    if case_dir is not None:
        sidecars = sorted(
            _Path(case_dir).glob("agent/ingest/*-filesystem-meta.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if sidecars:
            try:
                filesystem_meta_path = str(sidecars[0].relative_to(case_dir))
            except ValueError:
                filesystem_meta_path = str(sidecars[0])

    return {
        "disk_artifacts": disk_artifacts,
        "memory": memory,
        "enrichment": enrichment_state,
        "gaps": gaps,
        "filesystem_meta_path": filesystem_meta_path,
    }


# --- Field name mismatch detection (cached per case) ---
_case_index_cache: dict[str, set[str]] = {}

_FIELD_HINT_EVTX_EVTXECMD = (
    "This case has EvtxECmd CSV indices alongside native evtx indices. "
    "EvtxECmd uses different field names — key mappings:\n"
    "SAFE ALIASES: event.code (evtx) = EventId (EvtxECmd). "
    "@timestamp (evtx) = TimeCreated (EvtxECmd). host.name = same.\n"
    "FIELDS THAT DON'T MAP 1:1 — EvtxECmd PayloadData is POSITIONAL:\n"
    "  UserName = Subject account (NOT the target user)\n"
    "  RemoteHost = Source IP (when present)\n"
    "  ExecutableInfo = Process path (when present)\n"
    "  EID 4624 (Logon): PayloadData1='Target: DOMAIN\\User', "
    "PayloadData2='LogonType N' (3=network, 10=RDP)\n"
    "  EID 4688 (Process): PayloadData1='Parent process: path', "
    "ExecutableInfo=new process\n"
    "  EID 7045 (Service): PayloadData1='Name: ServiceName', "
    "PayloadData2='StartType: ...'\n"
    "  EID 4648 (Explicit Creds): PayloadData1='Target: DOMAIN\\User', "
    "PayloadData2='TargetServerName: host'\n"
    "  EID 4672 (Special Privs): PayloadData1='PrivilegeList: ...'\n"
    "EvtxECmd queries: EventId:4624 AND PayloadData1:*username*, "
    "EventId:4688 AND ExecutableInfo:*process*, "
    "EventId:7045 AND PayloadData1:*servicename*, "
    "EventId:4624 AND PayloadData2:*LogonType 3* (lateral movement).\n"
    "Prefer native evtx (case-*-evtx-*) when available — proper ECS fields."
)

_field_hint_delivered = False


def _get_case_indices(index_pattern: str, client) -> set[str]:
    """Get index names for a pattern, cached per case prefix.

    Handles comma-separated patterns (e.g., 'case-x-evtx-*,case-x-delim-*').
    """
    cache_key = index_pattern
    if cache_key in _case_index_cache:
        return _case_index_cache[cache_key]
    names: set[str] = set()
    # Handle comma-separated patterns
    for segment in index_pattern.split(","):
        segment = segment.strip()
        if not segment:
            continue
        try:
            cat_result = client.cat.indices(index=segment, format="json", h="index")
            if cat_result:
                names.update(i["index"] for i in cat_result)
        except Exception:
            pass
    if names:
        _case_index_cache[cache_key] = names
    return names


def invalidate_index_cache() -> None:
    """Clear the index cache after ingest operations."""
    _case_index_cache.clear()


def _add_field_hint(resp: dict, index_pattern: str, client) -> None:
    """Add field_hint when query targets indices with different field names.

    Full hint on first delivery, one-line pointer after (token budget).
    """
    global _field_hint_delivered
    if "*" not in index_pattern:
        return
    idx_names = _get_case_indices(index_pattern, client)
    has_evtx = any("-evtx-" in n and "-evtxecmd-" not in n for n in idx_names)
    has_evtxecmd = any("-evtxecmd-" in n for n in idx_names)
    if not (has_evtx and has_evtxecmd):
        return
    if _field_hint_delivered:
        resp["field_hint"] = (
            "Mixed evtx/EvtxECmd indices — use case-*-evtx-* for ECS fields "
            "or case-*-delim-evtxecmd-* for CSV fields."
        )
    else:
        resp["field_hint"] = _FIELD_HINT_EVTX_EVTXECMD
        _field_hint_delivered = True


def reset_enrichment_state() -> None:
    """Reset enrichment counters for test isolation."""
    global _shimcache_reminder_count, _hints_delivered, _field_hint_delivered
    _shimcache_reminder_count = 0
    _hints_delivered = False
    _field_hint_delivered = False
    _case_index_cache.clear()


_client = None
_client_verified = False


def _get_os():
    """Get cached OpenSearch client. Health check on first call only.

    If the cached client hits a connection error (OpenSearch went down),
    the next _get_os() call will create a fresh client and re-verify.
    """
    global _client, _client_verified
    if _client is None:
        try:
            _client = get_client()
        except FileNotFoundError as e:
            raise RuntimeError(str(e)) from e
    if not _client_verified:
        try:
            _client.cluster.health()
            _client_verified = True
            # Auto-install winlog pipeline + evtx template + 14 non-evtx
            # templates on first verified connection. Idempotent —
            # validate-before-PUT means a broken pipeline body never
            # replaces the running one.
            try:
                from opensearch_mcp.mappings import ensure_winlog_pipeline

                _install_result = ensure_winlog_pipeline(_client)
                if _install_result.get("status") != "ok":
                    logger.warning(
                        "winlog pipeline install reported %s: %s",
                        _install_result.get("status"),
                        _install_result.get("error") or _install_result.get("other_templates"),
                    )
            except Exception as _install_e:
                logger.warning(
                    "winlog pipeline auto-install failed (non-fatal): %s",
                    _install_e,
                )
        except Exception as e:
            _client = None
            raise RuntimeError(
                f"OpenSearch not running or not reachable: {e}\n"
                "Run 'opensearch-setup' to start OpenSearch."
            ) from e
    return _client


def _os_call(fn, *args, **kwargs):
    """Call an OpenSearch client method, resetting cache on connection failure."""
    global _client, _client_verified
    try:
        return fn(*args, **kwargs)
    except (OSConnectionError, ConnectionTimeout) as e:
        _client = None
        _client_verified = False
        raise RuntimeError(
            "OpenSearch connection temporarily lost — client reset. "
            "Retry your query. If it persists: "
            "docker ps | grep sift-opensearch"
        ) from e
    except AuthorizationException as e:
        _client = None
        _client_verified = False
        raise RuntimeError(
            "OpenSearch authentication failed. Check opensearch.yaml credentials."
        ) from e
    except RequestError as e:
        # 400 Bad Request — malformed query, missing field, etc.
        info = getattr(e, "info", None) or {}
        err = info.get("error", {})
        reason = err.get("reason", str(e)) if isinstance(err, dict) else str(e)
        raise ValueError(f"Query error: {reason}") from e


# Fields excluded from opensearch_search results by default (token optimization).
# These are duplicated content, raw unparsed data where parsed equivalents
# exist, or metadata with zero triage value. Full docs via opensearch_get_event.
_SEARCH_EXCLUDE_FIELDS = frozenset(
    {
        # Duplicated content (parsed equivalents exist)
        "ExtraFieldInfo",  # Hayabusa: duplicates Details
        "Payload",  # EvtxECmd: raw XML, PayloadData1-6 already extracted
        "FilesLoaded",  # PECmd: bulk DLL list
        "Directories",  # PECmd: bulk directory list
        "task.xml",  # Scheduled tasks: full XML
        "wer.full_text",  # WER: full crash report text
        # EvtxECmd duplicate/metadata
        "SourceFile",  # duplicates vhir.source_file
        "Computer",  # duplicated to host.name by parse_delimited
        # Metadata (available via opensearch_get_event, zero triage value)
        "ExtraDataOffset",
        "HiddenRecord",
        "Keywords",
        "ChunkNumber",
        "pipeline_version",
        "vhir.source_file",
        "vhir.ingest_audit_id",
        "vhir.parse_method",
        # MFT structural fields (low triage value, high field count)
        "UpdateSequenceNumber",
        "LogfileSequenceNumber",
        "SecurityId",
        "ReferenceCount",
        "NameType",
        "IsAds",
        "Is256",
        # --- EvtxECmd low-value fields ---
        "RecordNumber",
        "EventRecordId",
        "ProcessId",
        "ThreadId",
        "UserId",
    }
)

_MAX_FIELD_CHARS = 500


def _strip_hits(
    hits: list[dict],
    exclude_fields: frozenset[str] = _SEARCH_EXCLUDE_FIELDS,
    max_chars: int = _MAX_FIELD_CHARS,
) -> list[dict]:
    """Extract _source from hits with field exclusion and truncation.

    Default behavior (compact): excludes bloat fields and truncates
    values > 500 chars. Pass empty exclude_fields and large max_chars
    for full documents.
    """
    results = []
    for hit in hits:
        src = hit.get("_source", {})
        idx_name = hit.get("_index", "")
        doc: dict = {"_id": hit.get("_id"), "_index": idx_name}
        # Note: _type extraction via rsplit is unreliable for dashed hostnames
        # (e.g., evtx-web-server-01 → type=evtx-web-server). Use _index for
        # authoritative artifact type. Removed _type field from results.

        truncated_fields = []
        for key, val in src.items():
            if key in exclude_fields:
                continue
            sval = str(val) if not isinstance(val, str) else val
            if len(sval) > max_chars:
                doc[key] = sval[:max_chars] + "..."
                truncated_fields.append(key)
            else:
                doc[key] = val

        if truncated_fields:
            doc["_truncated"] = truncated_fields

        results.append(doc)
    return results


def _resolve_index(index: str, case_id: str) -> str:
    """Resolve index pattern from explicit index, case_id, or active case."""
    if index:
        return index
    from opensearch_mcp.paths import sanitize_index_component

    cid = case_id or _get_active_case() or ""
    if cid:
        return f"case-{sanitize_index_component(cid)}-*"
    return "case-*"


def _detect_preparsed_csvs(path: Path) -> str | None:
    """Check for pre-parsed CSV output and suggest the right ingest tool."""
    # Scan flat + one level of subdirs (avoid full tree walk on USB)
    # Single-pass scan: collect CSVs and subdirs together
    csv_files = []
    subdirs = []
    for entry in path.iterdir():
        if entry.is_file() and entry.suffix.lower() == ".csv":
            csv_files.append(entry)
        elif entry.is_dir() and not entry.name.startswith("."):
            subdirs.append(entry)
    for d in subdirs:
        csv_files.extend(f for f in d.iterdir() if f.suffix.lower() == ".csv")
        if len(csv_files) >= 100:
            break
    csv_files = csv_files[:100]
    if not csv_files:
        return None

    # ZimmermanTools patterns
    zt_patterns = {
        "amcache": "Amcache",
        "shimcache": "AppCompatCache",
        "evtxecmd": "EvtxECmd",
        "mft": "MFTECmd",
        "prefetch": "PECmd",
        "registry": "RECmd",
        "shellbags": "SBECmd",
        "usn": "UsnJrnl",
    }
    found_zt: set[str] = set()
    for f in csv_files:
        name_lower = f.name.lower()
        for key, pattern in zt_patterns.items():
            if pattern.lower() in name_lower:
                found_zt.add(key)

    # Hayabusa detection (check header of first few CSVs)
    hayabusa = False
    for f in csv_files[:5]:
        try:
            with open(f, "r", errors="replace") as fh:
                header = fh.read(200).lower()
            if "ruletitle" in header and "eventid" in header:
                hayabusa = True
                break
        except OSError:
            pass

    parts = []
    if found_zt:
        parts.append(
            f"Detected ZimmermanTools CSV output "
            f"({', '.join(sorted(found_zt))}). "
            "Use opensearch_ingest(path=..., format='delimited', hostname=...) "
            "to ingest."
        )
    if hayabusa:
        parts.append(
            "Detected Hayabusa CSV output. "
            "Use opensearch_ingest(path=..., format='delimited', hostname=...) "
            "to ingest."
        )
    if not parts and csv_files:
        parts.append(
            f"Found {len(csv_files)} CSV files but no raw Windows "
            "artifacts. If these are pre-parsed tool output, use "
            "opensearch_ingest(path=..., format='delimited', hostname=...)."
        )
    return " ".join(parts) if parts else None


def _detect_hostnames_from_filenames(path: Path) -> set[str]:
    """Best-effort hostname detection from forensic CSV naming.

    Supports two patterns:
    - Suffix: EvtxECmd-hostname.csv (ZimmermanTools)
    - Prefix: hayabusa-caseid-hostname.csv (Hayabusa pipeline output)
    """
    if not path.is_dir():
        return set()
    from collections import Counter

    exts = {".csv", ".tsv"}
    files = [f for f in path.iterdir() if f.suffix.lower() in exts][:50]
    if not files:
        return set()
    # Suffix pattern: tool-hostname.csv
    suffix_counts: Counter = Counter()
    # Prefix pattern: tool-caseid-hostname.csv (last segment after last -)
    for f in files:
        parts = f.stem.rsplit("-", 1)
        if len(parts) == 2 and len(parts[1]) >= 2:
            suffix_counts[parts[1].lower()] += 1
    threshold = len(files) * 0.3
    return {h for h, c in suffix_counts.items() if c >= threshold}


def _validate_path(path: str) -> str | None:
    """Validate path is in allowed locations. Returns error string or None."""
    from opensearch_mcp.paths import sift_home

    p = Path(path).resolve()
    home = sift_home().resolve()
    allowed = [
        home,
        cases_root().resolve(),  # operator-configured cases root (canonical)
        Path("/mnt").resolve(),
        Path("/media").resolve(),
        Path("/run/media").resolve(),
        Path("/evidence").resolve(),
        Path("/cases").resolve(),  # static belt: well-known default mount
        Path("/tmp").resolve(),
    ]
    if not any(p.is_relative_to(a) for a in allowed):
        return (
            f"Path not in allowed locations "
            f"(~/, /mnt/, /media/, /evidence/, /cases/, /tmp/): {path}"
        )
    return None


def _resolve_tool_path(path: str, *, default_subdir: str = "evidence") -> tuple[Path | None, dict | None]:
    """Resolve a tool path under the active case and return a structured error."""
    try:
        return resolve_case_path(path, default_subdir=default_subdir), None
    except ValueError as exc:
        msg = str(exc)
        return None, {
            "error": "Path must be within the case directory",
            "details": msg,
            "portal_hint": "Use a path under the active case, such as evidence/filename.e01.",
        }


@server.tool(annotations={"readOnlyHint": True})
def opensearch_search(
    query: str,
    index: str = "",
    case_id: str = "",
    limit: int = 50,
    offset: int = 0,
    sort: str = "@timestamp:desc",
    time_from: str = "",
    time_to: str = "",
    compact: bool = True,
) -> dict:
    """Search indexed evidence using OpenSearch query_string syntax.

    Use for targeted lookups by indicator, user, IP, hash, or exact field value.
    Prefer opensearch_aggregate for frequency counts; prefer opensearch_timeline for activity spikes.

    Returns: {hits: [{_id, _index, @timestamp, <fields>}], total, offset, truncated}
    Output cap: limit max 200; compact=True strips bloat fields and truncates values
      to 500 chars. Use opensearch_get_event(event_id, index) to fetch a full document.

    Example:
      opensearch_search(query='event.code:4688 AND process.name:*powershell*',
                 case_id='rocba-drive-20260526-1417')

    Notes:
      - OpenSearch tokenizes on dots/hyphens — include the extension:
        'ServiceUpdater.exe' not 'ServiceUpdater'. Use wildcards: '*ServiceUpdater*'.
      - Quote values with special chars: source.ip:"::1" (IPv6 needs quotes).
      - WinRM/Operational often dominates (50%+). Add
        NOT winlog.channel:"Microsoft-Windows-WinRM/Operational" to focus queries.
      - Use offset for pagination when total > limit.

    Args:
        query: OpenSearch query_string (e.g., 'event.code:4624 AND user.name:admin').
            Quote values with special chars: source.ip:"::1" (IPv6 needs quotes).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID from case_info. If omitted, defaults to the active
            portal case from SIFT_CASE_DIR.
        limit: Max results (default 50, max 200).
        offset: Skip first N results for pagination (default 0).
        sort: Sort field:order (default @timestamp:desc).
        time_from: Start time (ISO 8601, e.g., '2023-01-25T14:00:00Z').
        time_to: End time (ISO 8601).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()
    limit = min(limit, 200)

    sort_field, _, sort_order = sort.partition(":")
    if sort_order not in ("asc", "desc", ""):
        sort_order = "desc"
    sort_body = [{sort_field: {"order": sort_order or "desc", "unmapped_type": "date"}}]

    query_body: dict = {"query_string": {"query": query}}
    if time_from or time_to:
        range_filter: dict = {"@timestamp": {}}
        if time_from:
            range_filter["@timestamp"]["gte"] = time_from
        if time_to:
            range_filter["@timestamp"]["lte"] = time_to
        query_body = {
            "bool": {"must": [{"query_string": {"query": query}}, {"range": range_filter}]}
        }

    search_body: dict = {
        "query": query_body,
        "sort": sort_body,
        "size": limit,
    }
    if offset > 0:
        search_body["from"] = min(offset, 10000)  # OpenSearch max_result_window

    result = _os_call(
        client.search,
        index=index,
        body=search_body,
    )

    total = result["hits"]["total"]["value"]
    total_capped = result["hits"]["total"].get("relation") == "gte"
    if compact:
        docs = _strip_hits(result["hits"]["hits"])
    else:
        docs = _strip_hits(result["hits"]["hits"], exclude_fields=frozenset(), max_chars=999999)

    resp: dict = {"total": total, "returned": len(docs), "results": docs, "compact": compact}
    if total_capped:
        resp["total_capped"] = True
        resp["total_note"] = f"At least {total} results. Use opensearch_count for exact total."
    if not docs:
        resp["hint"] = (
            "No results. If searching for filenames, include the extension "
            "(e.g., 'svchost.exe' not 'svchost'). Use wildcards for partial: "
            "'*svchost*'. OpenSearch tokenizes on dots/hyphens."
        )
    if compact:
        resp["note"] = (
            "Results are compact — bloat fields excluded, long values truncated. "
            "Use opensearch_get_event(id, index) for full documents."
        )

    # Detect when query targets indices with different field naming.
    # Check existing index names (cached per case), not results, because
    # field-specific queries silently miss index types using different names.
    _add_field_hint(resp, index, client)

    _add_shimcache_reminder(resp, index, docs)
    aid = audit.log(
        tool="opensearch_search",
        params={"query": query, "index": index, "limit": limit},
        result_summary=f"{total} total, {len(docs)} returned",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_count(
    query: str = "*",
    index: str = "",
    case_id: str = "",
) -> dict:
    """Count matching documents — returns a scalar, no documents returned.

    Use to verify index population or check magnitude before committing to
    opensearch_search. Faster than opensearch_search with limit=0. Use opensearch_aggregate when
    you need counts per value, not a single total.

    Returns: {count: N, audit_id}

    Example:
      opensearch_count(query='event.code:4624', case_id='rocba-drive-20260526-1417')

    Args:
        query: OpenSearch query_string (default: all).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID from case_info. If omitted, defaults to the active
            portal case from SIFT_CASE_DIR.
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()
    result = _os_call(
        client.count,
        index=index,
        body={"query": {"query_string": {"query": query}}},
    )
    resp = {"count": result["count"]}
    aid = audit.log(
        tool="opensearch_count",
        params={"query": query, "index": index},
        result_summary=f"count={result['count']}",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_aggregate(
    field: str,
    query: str = "*",
    index: str = "",
    case_id: str = "",
    limit: int = 50,
) -> dict:
    """Aggregate (group by) a field — frequency analysis, top-N counts.

    Use for distribution overview: top event codes, top users, top process names.
    Prefer over opensearch_search when you need a distribution, not individual documents.
    Use opensearch_field_values when you only need the value set without frequency ranking.

    Returns: {field, total_docs, buckets: [{key, count}], truncated, audit_id}
    Output cap: limit max 500 buckets; truncated=true when capped.

    Example:
      opensearch_aggregate(field='event.code', case_id='rocba-drive-20260526-1417')

    Notes:
      - CSV/registry fields (Path, KeyPath, ValueData) require .keyword suffix:
        field='Path.keyword'. evtx fields (event.code, process.name) are already
        keyword-typed — no suffix needed. Check opensearch_case_summary include_fields=True
        to confirm field types.
      - Scope with query= first: query='user.name:SYSTEM' then aggregate on
        process.name to see only SYSTEM-context processes.

    Args:
        field: Field to aggregate on (e.g., 'host.name', 'event.code').
        query: OpenSearch query_string filter (default: all).
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID from case_info. If omitted, defaults to the active
            portal case from SIFT_CASE_DIR.
        limit: Max buckets (default 50, max 500).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()
    limit = min(limit, 500)

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {"agg": {"terms": {"field": field, "size": limit}}},
            "size": 0,
        },
    )

    buckets = [
        {"key": b["key"], "count": b["doc_count"]}
        for b in result["aggregations"]["agg"]["buckets"]
    ]

    resp = {
        "field": field,
        "total_docs": result["hits"]["total"]["value"],
        "buckets": buckets,
        "truncated": len(buckets) >= limit,
    }
    aid = audit.log(
        tool="opensearch_aggregate",
        params={"field": field, "query": query, "index": index},
        result_summary=f"{len(buckets)} buckets",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_get_event(
    event_id: str,
    index: str,
) -> dict:
    """Retrieve a single full document by its _id — all fields, no truncation.

    Use after opensearch_search returns a hit worth inspecting completely.
    opensearch_search compact=True strips fields and truncates values to 500 chars;
    this returns the complete source with every field intact.

    Returns: {_id, _index, <all source fields>, _note}

    Example:
      opensearch_get_event(event_id='abc123def456',
                    index='case-rocba-drive-20260526-1417-evtx-srl-forge')

    Notes:
      - index must be an exact index name, not a wildcard pattern.
      - Obtain _id and _index from opensearch_search hit objects.

    Args:
        event_id: Document _id from search results.
        index: Exact index name (not a pattern).
    """
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()
    result = _os_call(client.get, index=index, id=event_id)
    doc = {"_id": result["_id"], "_index": result["_index"]}
    doc.update(result.get("_source", {}))
    doc["_note"] = "Full document — all fields included, no truncation"
    aid = audit.log(
        tool="opensearch_get_event",
        params={"event_id": event_id, "index": index},
        result_summary=f"doc {event_id}",
    )
    if aid:
        doc["audit_id"] = aid
    return doc


@server.tool(annotations={"readOnlyHint": True})
def opensearch_timeline(
    query: str = "*",
    index: str = "",
    case_id: str = "",
    interval: str = "1h",
    time_field: str = "@timestamp",
    time_from: str = "",
    time_to: str = "",
) -> dict:
    """Show event count over time as a date histogram — temporal spike detection.

    Use to identify activity bursts and narrow a time window before opensearch_search
    or opensearch_aggregate. After locating a spike, scope subsequent queries with
    time_from/time_to to focus on that period.

    Returns: {total_docs, interval, buckets: [{time: ISO8601, count: N}], audit_id}

    Example:
      opensearch_timeline(query='event.code:4688', case_id='rocba-drive-20260526-1417',
                   interval='1h', time_from='2026-05-01T00:00:00Z')

    Notes:
      - interval must match \\d+[smhd]: 30m, 1h, 6h, 1d. Invalid format returns error.
      - Narrow with time_from/time_to before querying large indices — full-case
        histograms on 1M+ events produce thousands of buckets.

    Args:
        query: OpenSearch query_string filter.
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID from case_info. If omitted, defaults to the active
            portal case from SIFT_CASE_DIR.
        interval: Histogram bucket size (e.g., '1m', '1h', '1d').
        time_field: Timestamp field (default @timestamp).
        time_from: Start time (ISO 8601, e.g., '2023-01-25T14:00:00Z').
        time_to: End time (ISO 8601).
    """
    import re as _re_mod

    if not _re_mod.match(r"^\d+[smhd]$", interval):
        return {
            "error": f"Invalid interval '{interval}'. Use Ns/Nm/Nh/Nd (e.g., 1h, 30m).",
            "next_step": "Retry opensearch_timeline with an interval like 1h or 30m.",
        }
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()

    query_body: dict = {"query_string": {"query": query}}
    if time_from or time_to:
        range_filter: dict = {time_field: {}}
        if time_from:
            range_filter[time_field]["gte"] = time_from
        if time_to:
            range_filter[time_field]["lte"] = time_to
        query_body = {
            "bool": {"must": [{"query_string": {"query": query}}, {"range": range_filter}]}
        }

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": query_body,
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": time_field,
                        "fixed_interval": interval,
                        "min_doc_count": 1,
                    }
                }
            },
            "size": 0,
        },
    )

    buckets = [
        {"time": b["key_as_string"], "count": b["doc_count"]}
        for b in result["aggregations"]["timeline"]["buckets"]
    ]

    resp = {
        "total_docs": result["hits"]["total"]["value"],
        "interval": interval,
        "buckets": buckets,
    }
    aid = audit.log(
        tool="opensearch_timeline",
        params={"query": query, "index": index, "interval": interval},
        result_summary=f"{len(buckets)} buckets",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_field_values(
    field: str,
    query: str = "*",
    index: str = "",
    case_id: str = "",
    limit: int = 50,
) -> dict:
    """List unique values for a field with occurrence counts — field discovery.

    Use to enumerate what values exist before writing targeted queries: all
    usernames, all process names, all registry key paths. Use opensearch_aggregate
    when ranked frequency matters more than the value set.

    Returns: {field, values: [{value, count}], truncated, audit_id}
    Output cap: limit max 500 values; truncated=true when capped.

    Example:
      opensearch_field_values(field='winlog.provider_name',
                       case_id='rocba-drive-20260526-1417')

    Notes:
      - Append .keyword for CSV/text fields: field='Path.keyword'.
        evtx fields (event.code, process.name) are already keyword-typed.
      - Scope with query= to narrow: query='event.code:4624' to enumerate
        only logon source users.

    Args:
        field: Field to enumerate (e.g., 'winlog.provider_name').
        query: OpenSearch query_string filter.
        index: Index pattern. Overrides case_id if provided.
        case_id: Case ID from case_info. If omitted, defaults to the active
            portal case from SIFT_CASE_DIR.
        limit: Max values (default 50, max 500).
    """
    index = _resolve_index(index, case_id)
    err = _validate_index(index)
    if err:
        return {"error": err}
    client = _get_os()
    limit = min(limit, 500)

    result = _os_call(
        client.search,
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "aggs": {"values": {"terms": {"field": field, "size": limit}}},
            "size": 0,
        },
    )

    values = [
        {"value": b["key"], "count": b["doc_count"], "doc_count": b["doc_count"]}
        for b in result["aggregations"]["values"]["buckets"]
    ]

    resp = {"field": field, "values": values, "truncated": len(values) >= limit}
    aid = audit.log(
        tool="opensearch_field_values",
        params={"field": field, "query": query, "index": index},
        result_summary=f"{len(values)} values",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_status() -> dict:
    """Show OpenSearch cluster health and all case index doc counts.

    Use to verify the cluster is reachable and see what cases have indexed data.
    Use opensearch_case_summary for per-case artifact breakdown and coverage state.

    Returns: {cluster_status, indices: [{index, docs, size, status}], total_indices}
    """
    client = _get_os()

    indices = _os_call(client.cat.indices, format="json")
    case_indices = [
        {
            "index": idx["index"],
            "docs": int(idx.get("docs.count", 0)),
            "size": idx.get("store.size", "0"),
            "status": idx.get("status", "unknown"),
        }
        for idx in indices
        if idx["index"].startswith("case-")
    ]

    case_indices.sort(key=lambda x: x["index"])

    health = _os_call(client.cluster.health)
    cluster_status = health.get("status")
    nodes = health.get("number_of_nodes", 0)
    if cluster_status == "yellow" and nodes <= 1:
        cluster_status = "yellow (normal for single-node deployment)"

    resp = {
        "cluster_status": cluster_status,
        "indices": case_indices,
        "total_indices": len(case_indices),
    }
    aid = audit.log(
        tool="opensearch_status",
        params={},
        result_summary=f"{len(case_indices)} indices",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_shard_status() -> dict:
    """Report OpenSearch shard usage and capacity headroom.

    Use before large ingests to check whether the cluster can accept new indices.
    A full disk image ingest can add 40+ shards. status=warning at <10% headroom;
    status=critical at <2%.

    Returns: {current_shards, max_shards_per_node, data_nodes, max_total,
      headroom_pct, status: ok|warning|critical, top_indices_by_shard_count}
    """
    from opensearch_mcp.shard_capacity import _resolve_setting

    client = _get_os()
    try:
        stats = client.cluster.stats(
            filter_path=["indices.shards.total", "nodes.count.data"],
            request_timeout=10,
        )
        # flat_settings=True conflicts with dotted filter_path; drop it.
        settings = client.cluster.get_settings(
            include_defaults=True,
            filter_path=[
                "persistent.cluster.max_shards_per_node",
                "transient.cluster.max_shards_per_node",
                "defaults.cluster.max_shards_per_node",
            ],
            request_timeout=10,
        )
    except Exception as e:
        return {"status": "error", "error": str(e)}

    current = (stats.get("indices") or {}).get("shards", {}).get("total", 0) or 0
    data_nodes = (stats.get("nodes") or {}).get("count", {}).get("data", 1) or 1
    try:
        max_per_node = int(_resolve_setting(settings, "cluster.max_shards_per_node", default=1000))
    except (TypeError, ValueError):
        max_per_node = 1000
    max_total = max_per_node * int(data_nodes)
    headroom_pct = round(((max_total - current) / max_total) * 100, 1) if max_total else 0.0

    # Top 10 indices by shard count for capacity diagnosis.
    # Exclude system/hidden indices (.opendistro_security, .tasks, etc.)
    # so the top-10 reflects case data, not cluster housekeeping.
    try:
        indices_info = client.cat.indices(format="json", request_timeout=10) or []
    except Exception:
        indices_info = []
    visible = [i for i in indices_info if not (i.get("index") or "").startswith(".")]
    top_indices = sorted(
        visible,
        key=lambda i: int(i.get("pri", 0) or 0) + int(i.get("rep", 0) or 0),
        reverse=True,
    )[:10]
    top = [
        {
            "index": i.get("index"),
            "primary_shards": int(i.get("pri", 0) or 0),
            "replica_shards": int(i.get("rep", 0) or 0),
            "doc_count": int(i.get("docs.count", 0) or 0),
            "size": i.get("store.size"),
        }
        for i in top_indices
    ]

    aid = audit.log(
        tool="opensearch_shard_status",
        params={},
        result_summary=(f"{current}/{max_total} shards ({headroom_pct}% headroom)"),
    )
    resp = {
        "current_shards": int(current),
        "max_shards_per_node": max_per_node,
        "data_nodes": int(data_nodes),
        "max_total": max_total,
        "headroom_pct": headroom_pct,
        "status": ("ok" if headroom_pct >= 10 else "warning" if headroom_pct >= 2 else "critical"),
        "top_indices_by_shard_count": top,
    }
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_case_summary(case_id: str = "", include_fields: bool = False) -> dict:
    """Get complete coverage overview for a case — first call every indexed session.

    Returns hosts, artifact types with doc counts, enrichment state, and
    coverage_state with gaps that include exact opensearch_ingest commands to fill them.
    Call this before any other opensearch_* tool to understand what's indexed and what's missing.

    Returns:
      {case_id, hosts: [str],
       artifacts: {type: {docs, hosts, indices}},
       total_docs, time_range,
       enrichment: {triage: {checked, suspicious}},
       investigation_hints: [str],
       coverage_state: {
         disk_artifacts: {type: indexed|not_run|not_available},
         memory: {tier_run, plugins_run: [str], plugins_not_run: [str]},
         enrichment: {triage: done|not_run, threat_intel: done|not_run},
         gaps: [{coverage_gap, when_to_run, command, next_mcp_step, warning}],
         filesystem_meta_path: str|null
       },
       audit_id}

    Example:
      opensearch_case_summary(case_id='rocba-drive-20260526-1417')

    Notes:
      - gaps[].command is the exact opensearch_ingest call to fill the gap — use verbatim.
      - filesystem_meta_path is the partition/filesystem sidecar JSON from ingest
        (null if not collected).
      - Call with include_fields=True to get field type mappings per artifact,
        needed to determine .keyword suffix requirements in aggregations.

    Args:
        case_id: Case ID from case_info. If omitted, defaults to the active
            portal case from SIFT_CASE_DIR.
        include_fields: Include field mappings per artifact type (large output).
            Default False to keep response compact.
    """
    from opensearch_mcp.paths import sanitize_index_component

    cid = case_id or _get_active_case()
    if not cid:
        return {
            "error": "No active case.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ and create or select a case.",
            "next_step": "Call case_info after the examiner activates a portal case.",
        }

    client = _get_os()
    safe = sanitize_index_component(cid)
    pattern = f"case-{safe}-*"
    resp: dict = {}

    # Get all indices for this case
    try:
        indices = _os_call(client.cat.indices, index=pattern, format="json")
    except ValueError:
        # RequestError — likely no matching indices
        return {"case_id": cid, "error": "No indices found for this case"}
    except RuntimeError as e:
        return {"case_id": cid, "error": str(e)}
    except Exception as e:
        return {"case_id": cid, "error": f"OpenSearch error: {type(e).__name__}"}

    if not indices:
        return {"case_id": cid, "hosts": [], "artifacts": {}, "total_docs": 0}

    # Get hosts from document field (reliable — index name parsing
    # breaks on hostnames with dashes)
    hosts: set = set()
    try:
        host_agg = client.search(
            index=pattern,
            body={
                "size": 0,
                "aggs": {"hosts": {"terms": {"field": "host.name", "size": 500}}},
            },
        )
        for bucket in host_agg["aggregations"]["hosts"]["buckets"]:
            hosts.add(bucket["key"].lower())
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Host detection query failed: {e}")

    # Build artifact map — strip known hostnames from index suffixes
    # to extract the artifact type. Index format: case-{id}-{type}-{host}
    # where both type and host may contain dashes.
    artifacts: dict = {}
    total_docs = 0
    prefix = f"case-{safe}-"
    host_suffixes = sorted(hosts, key=len, reverse=True)  # longest first
    for idx in indices:
        name = idx["index"]
        docs = int(idx.get("docs.count", 0))
        total_docs += docs
        remainder = name[len(prefix) :] if name.startswith(prefix) else name
        # Try stripping each known host suffix
        artifact_type = remainder
        matched_host = ""
        for h in host_suffixes:
            suffix = f"-{h}"
            if remainder.endswith(suffix):
                artifact_type = remainder[: -len(suffix)]
                matched_host = h
                break
        if artifact_type not in artifacts:
            artifacts[artifact_type] = {"docs": 0, "hosts": [], "indices": []}
        artifacts[artifact_type]["docs"] += docs
        if matched_host and matched_host not in artifacts[artifact_type]["hosts"]:
            artifacts[artifact_type]["hosts"].append(matched_host)
        artifacts[artifact_type]["indices"].append(name)

    # Aggregate sub-indices (e.g., delim-amcache-devicecontainers → delim-amcache)
    # to prevent 30 hosts × 6 sub-tables = 180 entries bloating the response.
    _AGGREGATE_PREFIXES = (
        "delim-amcache-",
        "delim-mftecmd-",
        "delim-srumecmd-",
        "delim-sqlecmd-",
    )
    merged: dict = {}
    for atype, info in artifacts.items():
        parent = atype
        for pfx in _AGGREGATE_PREFIXES:
            if atype.startswith(pfx):
                parent = pfx.rstrip("-")
                break
        if parent not in merged:
            merged[parent] = {"docs": 0, "hosts": [], "indices": []}
        merged[parent]["docs"] += info["docs"]
        for h in info.get("hosts", []):
            if h not in merged[parent]["hosts"]:
                merged[parent]["hosts"].append(h)
        merged[parent]["indices"].extend(info["indices"])
    artifacts = merged

    # Get field mappings per artifact type with types (sample one index per type)
    def _flatten_props(props: dict, prefix: str = "") -> list[dict]:
        fields = []
        for key, val in props.items():
            full = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
            if isinstance(val, dict) and "properties" in val:
                fields.extend(_flatten_props(val["properties"], full))
            elif isinstance(val, dict):
                fields.append({"field": full, "type": val.get("type", "object")})
            else:
                fields.append({"field": full, "type": "unknown"})
        return fields

    fields_per_type: dict = {}
    if include_fields:
        for atype, info in artifacts.items():
            if not info["indices"]:
                continue
            try:
                mapping = client.indices.get_mapping(index=info["indices"][0])
                idx_name = info["indices"][0]
                props = mapping.get(idx_name, {}).get("mappings", {}).get("properties", {})
                fields_per_type[atype] = sorted(_flatten_props(props), key=lambda f: f["field"])[
                    :150
                ]
            except Exception as e:
                resp.setdefault("warnings", []).append(
                    f"Field mapping query failed for {atype}: {e}"
                )

    # Enrichment status
    enrichment: dict = {}
    try:
        triage_count = client.count(
            index=pattern,
            body={"query": {"exists": {"field": "triage.checked"}}},
        )["count"]
        if triage_count:
            suspicious = client.count(
                index=pattern,
                body={"query": {"term": {"triage.verdict": "SUSPICIOUS"}}},
            )["count"]
            enrichment["triage"] = {
                "checked": triage_count,
                "suspicious": suspicious,
            }
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Triage stats query failed: {e}")

    try:
        intel_count = client.count(
            index=pattern,
            body={"query": {"exists": {"field": "threat_intel.checked"}}},
        )["count"]
        if intel_count:
            malicious = client.count(
                index=pattern,
                body={"query": {"term": {"threat_intel.verdict": "MALICIOUS"}}},
            )["count"]
            enrichment["threat_intel"] = {
                "checked": intel_count,
                "malicious": malicious,
            }
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Intel stats query failed: {e}")

    # Time range (single query for both min and max)
    time_range: dict = {}
    try:
        ts_result = client.search(
            index=pattern,
            body={
                "size": 0,
                "aggs": {
                    "min_ts": {"min": {"field": "@timestamp"}},
                    "max_ts": {"max": {"field": "@timestamp"}},
                },
            },
        )
        min_val = ts_result["aggregations"]["min_ts"].get("value_as_string")
        max_val = ts_result["aggregations"]["max_ts"].get("value_as_string")
        if min_val:
            time_range["earliest"] = min_val
        if max_val:
            time_range["latest"] = max_val
    except Exception as e:
        resp.setdefault("warnings", []).append(f"Time range query failed: {e}")

    # Only surface hosts that own at least one index — ghost hostnames from
    # within event fields (e.g. lateral movement targets in Hayabusa ECS data)
    # appear in the host.name aggregation but have no indices of their own.
    indexed_hosts = {
        h for info in artifacts.values() for h in info.get("hosts", [])
    }
    resp.update(
        {
            "case_id": cid,
            "hosts": sorted(indexed_hosts),
            "artifacts": artifacts,
            "total_docs": total_docs,
            "time_range": time_range,
            "enrichment": enrichment,
        }
    )
    if fields_per_type:
        resp["fields_per_type"] = fields_per_type
    _add_investigation_hints(resp, artifacts)
    _case_dir_env = os.environ.get("SIFT_CASE_DIR", "").strip()
    _summary_case_dir = Path(_case_dir_env) if _case_dir_env else None
    resp["coverage_state"] = _build_coverage_state(artifacts, enrichment, case_dir=_summary_case_dir)
    aid = audit.log(
        tool="opensearch_case_summary",
        params={"case_id": cid},
        result_summary=f"{len(indexed_hosts)} hosts, {len(artifacts)} artifact types, {total_docs} docs",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool(annotations={"readOnlyHint": True})
def opensearch_inspect_container(path: str) -> dict:
    """Inspect a forensic container (E01, raw image) without mounting — pre-ingest survey.

    Use before opensearch_ingest to verify integrity, check size, and identify partitions.
    Does NOT mount the image. Follow with opensearch_ingest(dry_run=True) for the full plan.

    Returns: {container_type, size_bytes, size_human, hashes, partitions[],
      acquiry_info (E01 only), tool_available}

    Example:
      opensearch_inspect_container(path='evidence/rocba-cdrive.e01')

    Notes:
      - Uses ewfinfo for E01; fdisk/img_stat for raw images.
      - tool_available=false means the inspection tool wasn't found on the SIFT VM —
        fall back to run_command(['ewfinfo', path]) directly.

    Args:
        path: Container path under the active case. Bare filenames resolve
            to SIFT_CASE_DIR/evidence/.
    """
    import subprocess

    resolved, err = _resolve_tool_path(path, default_subdir="evidence")
    if err or resolved is None:
        return {"error": f"Container not found: {path}", "detail": err}
    resolved_str = str(resolved)

    result: dict = {
        "path": path,
        "resolved_path": resolved_str,
        "container_type": "unknown",
        "tool_available": False,
    }

    # Try ewfinfo for E01 files
    ewfinfo_bin = None
    for candidate in ("/usr/bin/ewfinfo", "/usr/local/bin/ewfinfo"):
        if Path(candidate).exists():
            ewfinfo_bin = candidate
            break

    if ewfinfo_bin:
        result["tool_available"] = True
        try:
            proc = subprocess.run(
                [ewfinfo_bin, resolved_str],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                result["container_type"] = "e01"
                info = _parse_ewfinfo(proc.stdout)
                result.update(info)
                return result
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Fallback: raw image inspection via fdisk or img_stat
    for tool in ("/usr/sbin/fdisk", "/usr/bin/img_stat"):
        tool_path = tool
        if not Path(tool).exists():
            continue
        result["tool_available"] = True
        try:
            proc = subprocess.run(
                [tool_path, "-l", resolved_str],
                capture_output=True, text=True, timeout=30, shell=False,
            )
            if proc.returncode == 0:
                result["container_type"] = "raw"
                result["raw_info"] = proc.stdout.strip()[:2000]
                break
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:
        # Last resort: just stat the file
        try:
            st = resolved.stat()
            result["container_type"] = "file"
            result["size_bytes"] = st.st_size
            result["size_human"] = _human_size(st.st_size)
        except OSError:
            pass

    return result


def _parse_ewfinfo(output: str) -> dict:
    """Parse ewfinfo output into structured dict."""
    info: dict = {}
    lines = output.splitlines()
    section = "general"
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Detect sections
        if line.startswith("Acquiry information"):
            section = "acquiry"
            continue
        elif line.startswith("EWF information"):
            section = "ewf"
            continue
        elif line.startswith("Media information"):
            section = "media"
            continue
        elif line.startswith("Digest hash information"):
            section = "hashes"
            if "hashes" not in info:
                info["hashes"] = {}
            continue

        if "\t" not in line and ":" not in line:
            continue

        # Parse key: value (tab-separated or colon-separated)
        if "\t" in line:
            parts = line.split("\t", 1)
        else:
            parts = line.split(":", 1)

        if len(parts) != 2:
            continue
        key = parts[0].strip().rstrip(":")
        value = parts[1].strip()

        if section == "acquiry":
            info.setdefault("acquiry", {})[key] = value
        elif section == "ewf":
            info.setdefault("ewf", {})[key] = value
        elif section == "media":
            if key == "Media size":
                # Parse "81 GiB (87431311360 bytes)"
                info["size_human"] = value.split("(")[0].strip() if "(" in value else value
                if "(" in value and "bytes" in value:
                    try:
                        info["size_bytes"] = int(value.split("(")[1].split("bytes")[0].strip())
                    except (ValueError, IndexError):
                        pass
            info.setdefault("media", {})[key] = value
        elif section == "hashes":
            info["hashes"][key] = value

    return info


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PiB"


def _launch_container_ingest(
    resolved_path: str,
    case_id: str,
    hostname: str = "",
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    source_timezone: str = "",
    all_logs: bool = False,
    reduced_ids: bool = False,
    full: bool = False,
    force: bool = False,
    vss: bool = False,
    password: str = "",
    no_hayabusa: bool = False,
    hosts: list | None = None,
) -> dict:
    """Launch the scan subprocess for a disk/archive container."""
    import sys
    import uuid as _uuid

    from opensearch_mcp.ingest_status import read_active_ingests as _read_active
    from opensearch_mcp.paths import sift_dir

    _running = [i for i in _read_active() if i.get("status") == "running"]
    if len(_running) >= _MAX_CONCURRENT_INGESTS:
        return {
            "error": (
                f"Too many concurrent ingests ({len(_running)} running, "
                f"max {_MAX_CONCURRENT_INGESTS}). Use opensearch_ingest_status()."
            ),
        }

    run_id = str(_uuid.uuid4())
    env = os.environ.copy()
    env["SIFT_INGEST_RUN_ID"] = run_id

    cmd = [
        sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        "scan",
        resolved_path,
        "--case",
        case_id,
        "--yes",
    ]
    if hostname:
        cmd.extend(["--hostname", hostname])
    if force:
        cmd.append("--clean")
    if include:
        cmd.extend(["--include", ",".join(include)])
    if exclude:
        cmd.extend(["--exclude", ",".join(exclude)])
    if source_timezone:
        cmd.extend(["--source-timezone", source_timezone])
    if all_logs:
        cmd.append("--all-logs")
    if reduced_ids:
        cmd.append("--reduced-ids")
    if full:
        cmd.append("--full")
    if vss:
        cmd.append("--vss")
    if password:
        env["SIFT_ARCHIVE_PASSWORD"] = password
    if no_hayabusa:
        cmd.append("--no-hayabusa")

    log_dir = sift_dir() / "ingest-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.log"
    log_fh = open(log_file, "w")

    proc = _spawn_ingest(cmd, env, log_fh, run_id)
    log_fh.close()

    # Collect filesystem metadata sidecar while the ingest subprocess starts
    from opensearch_mcp.containers import _collect_filesystem_meta

    _fs_meta = _collect_filesystem_meta(resolved_path, "disk")
    _fs_meta_rel: str | None = None
    _case_dir_env_ci = os.environ.get("SIFT_CASE_DIR", "").strip()
    if _case_dir_env_ci and _fs_meta.get("image_type") != "unknown":
        import json as _json_ci

        _sidecar_dir = Path(_case_dir_env_ci) / "agent" / "ingest"
        _sidecar_dir.mkdir(parents=True, exist_ok=True)
        _sidecar_path = _sidecar_dir / f"{run_id}-filesystem-meta.json"
        _sidecar_path.write_text(_json_ci.dumps(_fs_meta, indent=2))
        _fs_meta_rel = f"agent/ingest/{run_id}-filesystem-meta.json"

    host_names = [h.hostname for h in hosts] if hosts else ([hostname] if hostname else [])
    aid = audit.log(
        tool="opensearch_ingest",
        params={
            "path": resolved_path,
            "dry_run": False,
            "hosts": host_names,
            "pid": proc.pid,
            "run_id": run_id,
        },
        result_summary=f"started ingest (pid {proc.pid}) for {len(hosts or [])} hosts",
        input_files=[resolved_path],
    )
    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "hosts": host_names,
        "case_id": case_id,
        "message": (
            "Ingest started. IMPORTANT: Call opensearch_ingest_status() every 30 seconds "
            "to monitor progress and report it to the examiner as a checklist. "
            "Continue polling until status is 'complete' or 'failed'."
        ),
    }
    if _fs_meta_rel:
        resp["filesystem_meta_path"] = _fs_meta_rel
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def opensearch_ingest(
    path: str,
    format: str = "auto",
    hostname: str = "",
    index_suffix: str = "",
    time_field: str = "",
    delimiter: str = "",
    recursive: bool = False,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    source_timezone: str = "",
    all_logs: bool = False,
    reduced_ids: bool = False,
    full: bool = False,
    tier: int = 1,
    plugins: list[str] | None = None,
    dry_run: bool = True,
    force: bool = False,
    vss: bool = False,
    password: str = "",
    no_hayabusa: bool = False,
) -> dict:
    """Preview or ingest evidence into OpenSearch.

    Call after case_info and evidence_info. Use dry_run=True
    first. Case ID is resolved from the active case set in the Examiner Portal;
    no case_id parameter is accepted.

    Formats:
      - auto: E01/VHDX/raw/archive containers, mounted images, or Windows
        artifact directories. Example:
        opensearch_ingest(path="evidence/rocba-cdrive.e01", format="auto", dry_run=True)
      - json: JSON/JSONL evidence. Example:
        opensearch_ingest(path="evidence/events.jsonl", format="json", hostname="host1")
      - delimited: CSV/TSV/Zeek/bodyfile text evidence. Example:
        opensearch_ingest(path="evidence/hayabusa", format="delimited", hostname="auto")
      - accesslog: Apache/Nginx access logs. Example:
        opensearch_ingest(path="evidence/access.log", format="accesslog", hostname="web01")
      - memory: Volatility 3 memory-image parsing. Example:
        opensearch_ingest(path="evidence/memdump.raw", format="memory", hostname="host1", tier=1)

    Memory tier plugins (format="memory"):
      Tier 1 (default): pslist, psscan, pstree, cmdline, netstat, netscan,
        svcscan, modules, registry.hivelist, windows.info — run first.
      Tier 2: dlllist, envars, getsids, ldrmodules — after suspicious PIDs found.
      Tier 3: malfind, vadinfo, dumpfiles — targeted, high cost, high noise.

    Ingest can add baseline context automatically for supported artifacts.
    Keep enrichment decisions explicit after ingest: use opensearch_case_summary to
    inspect coverage, then opensearch_enrich_triage or opensearch_enrich_intel when baseline
    or threat-intel enrichment needs rerun.

    Args:
        path: Evidence path under the active case. Bare filenames resolve to
            SIFT_CASE_DIR/evidence/. Known relative subdirs like evidence/
            resolve from SIFT_CASE_DIR.
        format: One of auto, json, delimited, accesslog, memory.
        hostname: Source hostname. Auto-detected from directory structure
            for some auto-format evidence. Required for json, accesslog,
            memory, and most delimited ingests. For delimited, hostname="auto"
            detects hostnames from filenames in a flat directory.
        index_suffix: Optional index suffix for json, delimited, or accesslog.
        time_field: Optional timestamp field for json or delimited.
        delimiter: Optional delimiter for delimited input.
        recursive: For delimited directories, treat immediate subdirectories
            as hostnames.
        include: Only these artifact types (e.g., ["mft", "usn"]).
        exclude: Skip these artifact types (e.g., ["jumplists"]).
        source_timezone: Evidence system's local timezone (e.g., "Eastern Standard Time").
        all_logs: Parse all evtx files (default: forensic logs only).
        reduced_ids: Filter to ~78 high-value Event IDs.
        full: Include all tiers including MFT, USN, timeline.
        tier: Memory analysis depth (1=fast, 2=moderate, 3=deep).
        plugins: Memory plugin override; runs only these Volatility plugins.
        dry_run: Preview without indexing (default True). Set False to execute
            immediately if path and parameters are confirmed.
        force: Allow re-ingest when data already exists (default False). Required
            when dry_run=False and the case already has indexed docs — prevents
            accidental re-indexing. Set True only after reviewing opensearch_case_summary.
    """
    import subprocess as _check_sp
    from pathlib import Path

    from opensearch_mcp.containers import detect_container
    from opensearch_mcp.ingest import discover

    case_id = _get_active_case()
    if not case_id:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }
    ingest_format = format.strip().lower()
    if ingest_format not in {"auto", "json", "delimited", "accesslog", "memory"}:
        return {
            "error": f"Unsupported ingest format: {format}",
            "supported_formats": ["auto", "json", "delimited", "accesslog", "memory"],
            "next_step": (
                "Use format='auto' for forensic containers or Windows artifact "
                "directories; use json, delimited, accesslog, or memory for "
                "specific evidence types."
            ),
        }
    if ingest_format == "json":
        if not hostname:
            return {
                "error": "hostname is required for format='json'.",
                "next_step": "Call opensearch_ingest(..., format='json', hostname='<source-host>', dry_run=True).",
            }
        return idx_ingest_json(path, hostname, index_suffix, time_field, dry_run)
    if ingest_format == "delimited":
        return idx_ingest_delimited(
            path,
            hostname=hostname,
            index_suffix=index_suffix,
            time_field=time_field,
            delimiter=delimiter,
            recursive=recursive,
            dry_run=dry_run,
        )
    if ingest_format == "accesslog":
        if not hostname:
            return {
                "error": "hostname is required for format='accesslog'.",
                "next_step": (
                    "Call opensearch_ingest(..., format='accesslog', hostname='<web-host>', dry_run=True)."
                ),
            }
        return idx_ingest_accesslog(path, hostname, index_suffix or "accesslog", dry_run)
    if ingest_format == "memory":
        if not hostname:
            return {
                "error": "hostname is required for format='memory'.",
                "next_step": "Call opensearch_ingest(..., format='memory', hostname='<source-host>', dry_run=True).",
            }
        return idx_ingest_memory(path, hostname, tier=tier, plugins=plugins, dry_run=dry_run)

    evidence_path, path_error = _resolve_tool_path(path)
    if path_error:
        return path_error
    assert evidence_path is not None
    resolved_path = str(evidence_path)
    if not evidence_path.exists():
        return {"error": f"Path not found: {path}", "resolved_path": resolved_path}

    # Container files (VHDX, E01, 7z, raw) — preview without mounting
    container_type = detect_container(evidence_path)
    if container_type in ("ewf", "raw", "nbd", "archive"):
        if dry_run:
            sudo_ok = _check_sp.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
            resp = {
                "status": "preview",
                "container": {
                    "type": container_type,
                    "file": evidence_path.name,
                    "size_mb": round(evidence_path.stat().st_size / 1048576),
                },
                "case_id": case_id,
                "message": (
                    f"Container image detected ({container_type}). "
                    "Set dry_run=false to mount and ingest."
                ),
            }
            if not sudo_ok:
                resp["warning"] = (
                    "Container mounting requires sudo. If ingest fails, "
                    "mount manually and point opensearch_ingest at the mount."
                )
            if hostname:
                resp["hostname"] = hostname
            else:
                resp["suggested_hostname"] = evidence_path.stem.split("-")[0]
            # Check if this case already has indexed data so the agent doesn't
            # blindly re-ingest a container that's already fully processed.
            try:
                _cli = _get_os()
                if _cli is not None:
                    _existing = (
                        _cli.cat.indices(
                            index=f"case-{case_id}-*",
                            format="json",
                            h="index,docs.count",
                        )
                        or []
                    )
                    _total = sum(int(r.get("docs.count") or 0) for r in _existing)
                    if _total > 0:
                        resp["already_indexed"] = {
                            "doc_count": _total,
                            "index_count": len(_existing),
                            "message": (
                                f"This case already has {_total:,} docs across "
                                f"{len(_existing)} indices. "
                                "Call opensearch_case_summary to review coverage. "
                                "Only set dry_run=false to add new evidence."
                            ),
                        }
                        resp["message"] = (
                            f"Container image detected ({container_type}). "
                            f"Case already indexed ({_total:,} docs across "
                            f"{len(_existing)} indices) — "
                            "review with opensearch_case_summary before re-ingesting."
                        )
            except Exception:
                pass
            aid = audit.log(
                tool="opensearch_ingest",
                params={
                    "path": resolved_path,
                    "dry_run": True,
                    "container": container_type,
                },
                result_summary=f"container preview: {container_type}",
            )
            if aid:
                resp["audit_id"] = aid
            return resp
        # dry_run=False falls through to subprocess launch below

    elif not evidence_path.is_dir():
        return {"error": f"Not a directory or supported container: {path}"}

    # Discover (directories only — containers handled by CLI subprocess)
    if evidence_path.is_dir():
        hosts = discover(evidence_path, hostname=hostname or None)
    else:
        hosts = []  # container file — skip discover, go to subprocess

    if not hosts and evidence_path.is_dir():
        # Scan for forensic containers before returning "no artifacts" error (B3 fix)
        containers_found = []
        try:
            for f in sorted(evidence_path.iterdir()):
                if f.is_file():
                    ctype = detect_container(f)
                    if ctype in ("ewf", "raw", "nbd", "archive"):
                        try:
                            rel = str(f.relative_to(Path(os.environ.get("SIFT_CASE_DIR", "")).resolve()))
                        except ValueError:
                            rel = str(f)
                        containers_found.append({
                            "path": str(f),
                            "relative_path": rel,
                            "type": ctype,
                            "size_mb": round(f.stat().st_size / 1_048_576),
                        })
        except OSError:
            pass
        if containers_found:
            if dry_run:
                return {
                    "status": "containers_detected",
                    "case_id": case_id,
                    "message": (
                        f"The directory contains {len(containers_found)} forensic container file(s). "
                        "Re-run opensearch_ingest with the container file path directly."
                    ),
                    "containers": containers_found,
                    "next_step": (
                        f"Call opensearch_ingest(path=\"{containers_found[0]['relative_path']}\", "
                        "format=\"auto\", "
                        f"hostname=\"<hostname>\", dry_run=True) to preview ingest."
                    ),
                }

            from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb
            from opensearch_mcp.shard_capacity import (
                _estimate_new_shards,
                check_shard_headroom,
            )

            _reset_cb()
            if not force:
                try:
                    _cli = _get_os()
                    if _cli is not None:
                        _existing = (
                            _cli.cat.indices(
                                index=f"case-{case_id}-*",
                                format="json",
                                h="index,docs.count",
                            )
                            or []
                        )
                        _total = sum(int(r.get("docs.count") or 0) for r in _existing)
                        if _total > 0:
                            return {
                                "status": "already_indexed",
                                "case_id": case_id,
                                "doc_count": _total,
                                "index_count": len(_existing),
                                "message": (
                                    f"This case already has {_total:,} docs across "
                                    f"{len(_existing)} indices. Re-ingest blocked to "
                                    "prevent accidental data duplication."
                                ),
                                "next_step": (
                                    "1. Call opensearch_case_summary to review current coverage. "
                                    "2. If re-ingest is intentional, set force=True. "
                                    "3. To add new evidence only, use a different evidence file path."
                                ),
                            }
                except Exception:
                    pass
            ok, reason = check_shard_headroom(
                get_client(),
                expected_new_shards=_estimate_new_shards("evtx") * len(containers_found),
                min_headroom_pct=10.0,
            )
            if not ok:
                return {"status": "failed", "error": "shard_capacity", "message": reason}

            def _looks_like_memory(container: dict) -> bool:
                fname = container["path"].lower()
                return any(
                    marker in fname
                    for marker in ("memory", "memdump", "ram", ".vmem", ".dmp", ".mem")
                ) or (container["type"] == "raw" and container.get("size_mb", 0) > 4096)

            started = []
            for c in sorted(containers_found, key=_looks_like_memory):
                rel_path = c["relative_path"]
                is_memory = _looks_like_memory(c)

                if is_memory:
                    if not hostname:
                        started.append(
                            {
                                "path": rel_path,
                                "status": "skipped",
                                "reason": "Memory format requires hostname= parameter",
                            }
                        )
                        continue
                    result = idx_ingest_memory(
                        rel_path,
                        hostname,
                        tier=tier,
                        plugins=plugins,
                        dry_run=False,
                    )
                    started.append({"path": rel_path, "format": "memory", **result})
                    continue

                result = _launch_container_ingest(
                    c["path"],
                    case_id,
                    hostname=hostname,
                    include=include,
                    exclude=exclude,
                    source_timezone=source_timezone,
                    all_logs=all_logs,
                    reduced_ids=reduced_ids,
                    full=full,
                    force=force,
                    vss=vss,
                    password=password,
                    no_hayabusa=no_hayabusa,
                    hosts=[],
                )
                started.append({"path": rel_path, "format": "auto", **result})

            return {
                "status": "multi_started",
                "case_id": case_id,
                "containers": started,
                "message": (
                    f"Launched {len(started)} ingest(s). Poll opensearch_ingest_status() for progress."
                ),
            }
        csv_hint = _detect_preparsed_csvs(evidence_path)
        if csv_hint:
            return {
                "error": ("No raw Windows artifacts found (no registry hives, evtx files, etc.)."),
                "suggestion": csv_hint,
            }
        return {"error": f"No Windows artifacts found in {path}"}

    # dry_run: return discovery summary
    if dry_run:
        client = _get_os()
        summary = []
        for host in hosts:
            artifact_names = sorted({a[0] for a in host.artifacts})
            evtx_count = 0
            if host.evtx_dir:
                evtx_count = sum(1 for f in host.evtx_dir.iterdir() if f.suffix.lower() == ".evtx")
            # Check existing indices — map artifact names to index suffixes
            existing = {}
            from opensearch_mcp.ingest import _artifact_to_tool
            from opensearch_mcp.tools import TOOLS as _TOOLS

            checked_suffixes = set()
            for aname in artifact_names:
                tool_name = _artifact_to_tool(aname)
                if not tool_name or tool_name not in _TOOLS:
                    continue
                suffix = _TOOLS[tool_name].index_suffix
                if suffix in checked_suffixes:
                    continue
                checked_suffixes.add(suffix)
                from opensearch_mcp.paths import build_index_name as _build_idx  # noqa: E402

                idx = _build_idx(case_id, suffix, host.hostname)
                try:
                    r = client.count(index=idx)
                    existing[idx] = r["count"]
                except Exception:
                    pass
            if evtx_count:
                from opensearch_mcp.paths import build_index_name as _build_idx  # noqa: E402

                idx = _build_idx(case_id, "evtx", host.hostname)
                try:
                    r = client.count(index=idx)
                    existing[idx] = r["count"]
                except Exception:
                    pass

            host_info = {
                "hostname": host.hostname,
                "artifacts": artifact_names,
            }
            if evtx_count:
                host_info["evtx_files"] = evtx_count
            if existing:
                host_info["existing"] = existing
            summary.append(host_info)

        aid = audit.log(
            tool="opensearch_ingest",
        params={"path": resolved_path, "dry_run": True},
            result_summary=f"discovery: {len(hosts)} hosts",
        )
        resp = {"status": "preview", "hosts": summary, "case_id": case_id}
        if aid:
            resp["audit_id"] = aid
        return resp

    # dry_run=False: launch ingest as a subprocess that survives gateway restart.
    # Defensive reset — breaker state is module-level in the MCP
    # server process; clear any inherited state from prior tool
    # invocations in the same server lifetime.
    from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb

    _reset_cb()

    # Already-indexed guard: block accidental re-ingests without explicit force=True.
    if not force:
        try:
            _cli = _get_os()
            if _cli is not None:
                _existing = (
                    _cli.cat.indices(
                        index=f"case-{case_id}-*",
                        format="json",
                        h="index,docs.count",
                    )
                    or []
                )
                _total = sum(int(r.get("docs.count") or 0) for r in _existing)
                if _total > 0:
                    return {
                        "status": "already_indexed",
                        "case_id": case_id,
                        "doc_count": _total,
                        "index_count": len(_existing),
                        "message": (
                            f"This case already has {_total:,} docs across "
                            f"{len(_existing)} indices. Re-ingest blocked to "
                            "prevent accidental data duplication."
                        ),
                        "next_step": (
                            "1. Call opensearch_case_summary to review current coverage. "
                            "2. If re-ingest is intentional, set force=True. "
                            "3. To add new evidence only, use a different evidence file path."
                        ),
                    }
        except Exception:
            pass

    # Pre-flight: abort if cluster shard capacity is exhausted. Halts
    # loudly instead of discovering the condition mid-ingest through
    # silent bulk rejections.
    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    client = get_client()
    ok, reason = check_shard_headroom(
        client,
        expected_new_shards=_estimate_new_shards("evtx"),
        min_headroom_pct=10.0,
    )
    if not ok:
        aid = audit.log(
            tool="opensearch_ingest",
            params={"path": resolved_path, "dry_run": False},
            result_summary=f"aborted: {reason[:120]}",
        )
        # Write terminal status so opensearch_ingest_status surfaces the
        # refusal (otherwise it returns "no active ingests" after a
        # refuse). Error-prefix convention: HALT_SHARD_CAPACITY.
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.ingest_status import (
            HALT_SHARD_CAPACITY,
            write_status,
        )

        write_status(
            case_id=case_id,
            pid=os.getpid(),
            run_id="",  # no run yet — refusal happens before subprocess spawn
            status="failed",
            hosts=[],
            totals={},
            started=_dt.now(_tz.utc).isoformat(),
            error=f"{HALT_SHARD_CAPACITY}: {reason}",
        )
        resp = {"status": "failed", "error": "shard_capacity", "message": reason}
        if aid:
            resp["audit_id"] = aid
        return resp

    return _launch_container_ingest(
        resolved_path,
        case_id,
        hostname=hostname,
        include=include,
        exclude=exclude,
        source_timezone=source_timezone,
        all_logs=all_logs,
        reduced_ids=reduced_ids,
        full=full,
        force=force,
        vss=vss,
        password=password,
        no_hayabusa=no_hayabusa,
        hosts=hosts,
    )


@server.tool(annotations={"readOnlyHint": True})
def opensearch_ingest_status(case_id: str = "") -> dict:
    """Check status of running or recent ingest operations.

    Defaults to active case. Pass case_id="*" to see all cases.

    Args:
        case_id: Filter to this case (default: active case). "*" for all.
    """
    from opensearch_mcp.ingest_status import read_active_ingests

    ingests = read_active_ingests()

    # Filter by case (default: active case)
    filter_case = case_id or _get_active_case() or ""
    if not filter_case:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }

    if filter_case and filter_case != "*":
        ingests = [i for i in ingests if i.get("case_id") == filter_case]

    if not ingests:
        return {"ingests": [], "message": "No active or recent ingests."}

    summaries = []
    for ing in ingests:
        status = ing.get("status", "unknown")
        elapsed = ing.get("elapsed_seconds", 0)
        minutes = int(elapsed // 60)

        totals = ing.get("totals", {})
        bf = ing.get("bulk_failed", 0) or totals.get("bulk_failed", 0)
        s = {
            "case_id": ing.get("case_id"),
            "status": status,
            "pid": ing.get("pid"),
            "elapsed": f"{minutes}m",
            "total_indexed": totals.get("indexed", 0),
            "bulk_failed": bf,
            "hosts_complete": totals.get("hosts_complete", 0),
            "hosts_total": totals.get("hosts_total", 0),
            "artifacts_complete": totals.get("artifacts_complete", 0),
            "artifacts_total": totals.get("artifacts_total", 0),
            "log_file": ing.get("log_file", ""),
        }
        # Warn the LLM/user when rejections occurred — makes silent
        # drops visible in the response payload, not only in stderr.
        if bf > 0:
            warnings = s.setdefault("warnings", [])
            reason = ing.get("bulk_failed_reason", "")
            warn_msg = f"{bf:,} events rejected by OpenSearch during bulk write"
            if reason:
                warn_msg += f" (first reason: {reason[:160]})"
            warn_msg += (
                ". Likely cluster capacity or mapping issue. Run opensearch_shard_status() to diagnose."
            )
            warnings.append(warn_msg)

        # Build per-host checklist for the LLM to present
        checklist = []
        for h in ing.get("hosts", []):
            hostname = h.get("hostname", "?")
            for a in h.get("artifacts", []):
                a_status = a.get("status", "pending")
                indexed = a.get("indexed", 0)
                if a_status == "complete":
                    icon = "done"
                    detail = f"{indexed:,} docs submitted"
                elif a_status == "running":
                    files_done = a.get("files_done", 0)
                    files_total = a.get("files_total", 0)
                    if files_total:
                        detail = f"{files_done}/{files_total} files, {indexed:,} so far"
                    else:
                        detail = f"{indexed:,} so far" if indexed else "starting"
                    icon = "running"
                elif a_status == "failed":
                    icon = "failed"
                    detail = a.get("error", "unknown error")
                else:
                    icon = "pending"
                    detail = "waiting"
                checklist.append(
                    {
                        "host": hostname,
                        "artifact": a["name"],
                        "status": icon,
                        "detail": detail,
                    }
                )
        s["checklist"] = checklist

        if status == "running":
            s["message"] = (
                "Ingest in progress. Present the checklist above to the examiner. "
                "Call opensearch_ingest_status() again in 30 seconds for updated progress."
            )
        elif status == "killed":
            s["message"] = (
                "Ingest process died unexpectedly. Re-run to continue — dedup prevents duplicates."
            )
        elif status == "failed":
            # Error-prefix convention: refuse sites write status=failed
            # with error="<halt_token>: <reason>". Surface the prefix
            # in the message so the client sees which halt path fired.
            _err = ing.get("error", "") or ""
            _prefix = ""
            if ":" in _err:
                _prefix = _err.split(":", 1)[0].strip()
            s["halt_reason"] = _prefix or "unspecified"
            if _prefix == "shard_capacity_exhausted":
                s["message"] = (
                    f"Ingest refused before start ({_prefix}). No documents "
                    f"were indexed. Address the underlying condition "
                    f"(raise cluster.max_shards_per_node, archive old cases, "
                    f"or run opensearch_shard_status() to inspect) then re-run."
                )
            elif _prefix == "circuit_breaker_tripped":
                s["message"] = (
                    f"Ingest halted mid-run ({_prefix}). "
                    f"{totals.get('indexed', 0):,} docs indexed before halt. "
                    f"Re-run on the same evidence after resolving capacity; "
                    f"dedup prevents duplicates."
                )
            elif _prefix == "hayabusa_no_rules":
                s["message"] = f"Ingest failed ({_prefix}): {_err[:200]}"
            else:
                s["message"] = f"Ingest failed: {_err[:200]}"
        elif status == "complete":
            invalidate_index_cache()  # new indices may exist
            errors = [
                f"{item['host']}/{item['artifact']}: {item['detail']}"
                for item in checklist
                if item["status"] == "failed"
            ]
            if errors:
                s["message"] = f"Ingest complete with {len(errors)} error(s)."
                s["errors"] = errors
            else:
                s["message"] = (
                    f"Ingest complete. {totals.get('indexed', 0):,} docs submitted "
                    f"across {totals.get('hosts_total', 0)} host(s) in {minutes}m."
                )
            # Layer 1: post-ingest next_steps
            artifacts_done = {item["artifact"] for item in checklist if item["status"] == "done"}
            next_steps = []
            if "evtx" in artifacts_done or any("evtx" in a for a in artifacts_done):
                next_steps.append(
                    "Run opensearch_case_summary for investigation overview, "
                    "then opensearch_aggregate on host.name and event.code"
                )
            if "hayabusa" in artifacts_done or any("hayabusa" in a for a in artifacts_done):
                next_steps.append(
                    "Query Hayabusa alerts: opensearch_search(query='Level:critical OR "
                    "Level:high', index='case-*-hayabusa-*')"
                )
            # Pick a concrete artifact_type example from what was ingested
            example_type = "event_logs_security"
            for art in artifacts_done:
                if "evtx" in art:
                    example_type = "event_logs_security"
                    break
                if "prefetch" in art or "pecmd" in art:
                    example_type = "prefetch"
                    break
                if "amcache" in art:
                    example_type = "amcache"
                    break
            next_steps.append(
                f"Call get_tool_help(tool_name='{example_type}') "
                "for deep analysis tools beyond OpenSearch queries"
            )
            s["next_steps"] = next_steps

        # Attach the preflight host-discovery report for THIS ingest's
        # run_id. Per-run-id keying prevents concurrent ingests from
        # overwriting each other's reports.
        _hd_case = s.get("case_id") or filter_case
        _hd_run_id = ing.get("run_id", "")
        if _hd_case and _hd_case != "*" and _hd_run_id:
            import json as _json

            _hd_path = (
                cases_root() / _hd_case / "host-discovery-reports" / f"{_hd_run_id}.json"
            )
            if _hd_path.exists():
                try:
                    s["host_discovery"] = _json.loads(_hd_path.read_text(encoding="utf-8"))
                except (OSError, _json.JSONDecodeError):
                    pass  # Non-fatal — operator can read the file directly.

        summaries.append(s)

    return {"ingests": summaries}


def idx_ingest_json(
    path: str,
    hostname: str,
    index_suffix: str = "",
    time_field: str = "",
    dry_run: bool = True,
) -> dict:
    """Ingest JSON/JSONL file into OpenSearch.

    Args:
        path: JSON/JSONL path under the active case. Bare filenames resolve
            to SIFT_CASE_DIR/evidence/.
        hostname: Source hostname.
        index_suffix: Index suffix (default: json-{filename}).
        time_field: Timestamp field name (default: auto-detect).
        dry_run: Preview (default True). Set False to execute immediately.
    """
    resolved, path_error = _resolve_tool_path(path)
    if path_error:
        return path_error
    assert resolved is not None
    resolved_path = str(resolved)
    if dry_run:
        from opensearch_mcp.parse_json import _detect_json_format

        p = resolved
        if not p.exists():
            return {"error": f"Path not found: {path}", "resolved_path": resolved_path}
        if p.is_file():
            fmt = _detect_json_format(p)
            return {"status": "preview", "file": p.name, "format": fmt}
        files = sorted(f.name for f in p.iterdir() if f.suffix.lower() in (".json", ".jsonl"))
        return {"status": "preview", "files": files, "count": len(files)}

    return _launch_background("json", resolved_path, hostname, index_suffix, time_field)


def idx_ingest_delimited(
    path: str,
    hostname: str = "",
    index_suffix: str = "",
    time_field: str = "",
    delimiter: str = "",
    recursive: bool = False,
    dry_run: bool = True,
) -> dict:
    """Ingest delimited files (CSV, TSV, Zeek, bodyfile) into OpenSearch.

    Args:
        path: Delimited file or directory under the active case. Bare filenames
            resolve to SIFT_CASE_DIR/evidence/.
        hostname: Source hostname. Required unless recursive=True.
            Use hostname="auto" to auto-detect hostnames from filenames
            in a flat directory (e.g., Hayabusa per-host CSVs).
        index_suffix: Index suffix (default: format-{filename}).
        time_field: Timestamp field (default: auto-detect).
        delimiter: Delimiter character (default: auto-detect).
        recursive: Treat immediate subdirectories as hosts (dirname =
            hostname). One level only — does NOT walk nested
            subdirectories. Top-level files directly inside `path`
            are ignored when recursive=True; use a non-recursive
            per-host call or `hostname="auto"` for flat layouts.
        dry_run: Preview (default True). Set False to execute immediately.
    """
    resolved, path_error = _resolve_tool_path(path)
    if path_error:
        return path_error
    assert resolved is not None
    resolved_path = str(resolved)
    if not resolved.exists():
        return {"error": f"Path not found: {path}", "resolved_path": resolved_path}

    # Auto-detect mode: flat directory with multi-host files
    if hostname == "auto":
        p = resolved
        if not p.is_dir():
            return {"error": "hostname='auto' requires a directory path"}
        detected = _detect_hostnames_from_filenames(p)
        if not detected:
            return {"error": "Could not auto-detect hostnames from filenames."}
        if dry_run:
            return {
                "status": "preview",
                "auto_detect": True,
                "detected_hostnames": sorted(detected),
                "total_hosts": len(detected),
            }
        # Single background process iterates all detected hosts sequentially
        return _launch_background(
            "delimited",
            resolved_path,
            "",
            index_suffix,
            time_field,
            delimiter=delimiter,
            auto_hosts=",".join(sorted(detected)),
        )

    # Recursive mode: subdirs are hosts
    if recursive:
        p = resolved
        if not p.is_dir():
            return {"error": "recursive requires a directory path"}
        subdirs = sorted(d for d in p.iterdir() if d.is_dir() and not d.name.startswith("."))
        if not subdirs:
            return {"error": f"No subdirectories found in {path}"}
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        if dry_run:
            hosts_preview = []
            for d in subdirs:
                files = [f.name for f in d.iterdir() if f.suffix.lower() in exts]
                if files:
                    hosts_preview.append(
                        {
                            "hostname": d.name,
                            "files": len(files),
                        }
                    )
            return {
                "status": "preview",
                "recursive": True,
                "hosts": hosts_preview,
                "total_hosts": len(hosts_preview),
            }
        # Single background process iterates all hosts sequentially
        return _launch_background(
            "delimited",
            resolved_path,
            "",
            index_suffix,
            time_field,
            delimiter=delimiter,
            recursive=True,
        )

    # Non-recursive: hostname required
    if not hostname:
        suggestion = _detect_hostnames_from_filenames(resolved)
        if suggestion:
            return {
                "error": "hostname is required for non-recursive ingest.",
                "detected_hostnames": sorted(suggestion),
                "suggestion": (
                    "Detected possible hostnames from filenames: "
                    + ", ".join(sorted(suggestion))
                    + ". Pass hostname=... to confirm, or use "
                    "recursive=true for per-host subdirectories."
                ),
            }
        return {
            "error": (
                "hostname is required. Pass hostname='...' or use "
                "recursive=true for per-host subdirectories."
            )
        }

    if dry_run:
        from opensearch_mcp.parse_delimited import _detect_delimited_format

        p = resolved
        if p.is_file():
            fmt = _detect_delimited_format(p)
            return {"status": "preview", "file": p.name, "format": fmt.get("format")}
        exts = {".csv", ".tsv", ".log", ".txt", ".dat"}
        files = sorted(f.name for f in p.iterdir() if f.suffix.lower() in exts)
        return {"status": "preview", "files": files, "count": len(files)}

    return _launch_background(
        "delimited",
        resolved_path,
        hostname,
        index_suffix,
        time_field,
        delimiter=delimiter,
    )


def idx_ingest_accesslog(
    path: str,
    hostname: str,
    index_suffix: str = "accesslog",
    dry_run: bool = True,
) -> dict:
    """Ingest Apache/Nginx access logs into OpenSearch.

    Args:
        path: Access log path under the active case. Bare filenames resolve
            to SIFT_CASE_DIR/evidence/.
        hostname: Source hostname.
        index_suffix: Index suffix (default: accesslog).
        dry_run: Preview (default True). Set False to execute immediately.
    """
    resolved, path_error = _resolve_tool_path(path)
    if path_error:
        return path_error
    assert resolved is not None
    resolved_path = str(resolved)
    if not resolved.exists():
        return {"error": f"Path not found: {path}", "resolved_path": resolved_path}
    if dry_run:
        p = resolved
        if p.is_file():
            return {"status": "preview", "file": p.name}
        files = sorted(
            f.name
            for f in p.iterdir()
            if f.suffix.lower() in (".log", ".txt") or "access" in f.name.lower()
        )
        return {"status": "preview", "files": files, "count": len(files)}

    return _launch_background("accesslog", resolved_path, hostname, index_suffix)


@server.tool()
def opensearch_enrich_intel(
    case_id: str = "",
    dry_run: bool = True,
    force: bool = False,
) -> dict:
    """Enrich indexed evidence with OpenCTI threat intelligence.

    Extracts unique IOCs (IPs, hashes, domains) from indexed data,
    looks them up in OpenCTI via the gateway, and stamps matching
    documents with threat_intel.verdict and confidence.

    No LLM tokens consumed — all lookups are programmatic.

    Args:
        case_id: Case to enrich (default: active case).
        dry_run: Extract and count IOCs without lookup (default True).
        force: Re-enrich even if already enriched (default False).

    Execute mode (dry_run=False) runs asynchronously. The tool returns
    immediately with `{status: "started", pid, run_id, log_file}`; the
    worker enriches in the background. For realistic corpora (1k–10k
    IOCs × rate-limited OpenCTI), enrichment takes 15–60 minutes,
    which is well past the gateway's 300-second synchronous tool
    timeout — hence the async shape.

    Progress is surfaced through the existing `opensearch_ingest_status`
    tool. Enrichment runs appear alongside ingest runs with
    `artifact_name="intel"` — use that to disambiguate.
    """
    from opensearch_mcp.paths import sanitize_index_component
    from opensearch_mcp.threat_intel import extract_unique_iocs

    cid = case_id or _get_active_case()
    if not cid:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }

    if dry_run:
        client = _get_os()
        safe_case = sanitize_index_component(cid)
        iocs = extract_unique_iocs(client, f"case-{safe_case}-*", force=force)
        return {
            "status": "preview",
            "case_id": cid,
            "ips": len(iocs["ip"]),
            "hashes": len(iocs["hash"]),
            "domains": len(iocs["domain"]),
            "total_iocs": sum(len(v) for v in iocs.values()),
        }

    return _launch_enrich_background(cid, force=force)


@server.tool()
def opensearch_enrich_triage(
    case_id: str = "",
) -> dict:
    """Run triage baseline enrichment on already-indexed data.

    Checks indexed filenames and services against the Windows baseline
    database (known_good.db) via the gateway. Stamps documents with
    triage.verdict (EXPECTED, SUSPICIOUS, UNKNOWN, EXPECTED_LOLBIN).

    Use this after ingesting evidence to add baseline context, or to
    re-enrich after the triage database is updated.

    Requires gateway with windows-triage-mcp backend running.

    Args:
        case_id: Case to enrich (default: active case).
    """
    from opensearch_mcp.triage_remote import enrich_remote

    cid = case_id or _get_active_case()
    if not cid:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }

    client = _get_os()
    results = enrich_remote(client, cid)

    if "error" in results:
        return results

    total_enriched = sum(r.get("enriched", 0) for r in results.values() if isinstance(r, dict))
    resp = {
        "status": "complete",
        "documents_enriched": total_enriched,
        "details": results,
    }
    aid = audit.log(
        tool="opensearch_enrich_triage",
        params={"case_id": cid},
        result_summary=f"{total_enriched} docs enriched",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


_MAX_CONCURRENT_INGESTS = 3


def _install_sigchld_reaper() -> None:
    """Install a SIGCHLD handler to reap child zombies (UAT 2026-04-22
    Fix 3.3).

    `_spawn_ingest` uses `start_new_session=True` + systemd-run which
    detaches the ingest worker from the MCP server's session, but the
    immediate Popen child (the systemd-run helper or the bare Popen
    fallback) is still the MCP server's direct child from a fork
    perspective. When it exits, it becomes a zombie until reaped.
    Without this handler, zombies accumulate in `ps` until the server
    restarts — cosmetic but annoying for operators.

    Bug 3 concurrency cap is NOT blocked by this (fixed separately via
    the liveness sweep in `ingest_status.read_active_ingests` which
    now detects Z-state). This handler is pure kernel-table hygiene.

    Idempotent: safe to call multiple times; signal.signal is replaced
    each time with the same semantics.
    """
    import signal

    def _reap(*_args):
        try:
            while True:
                pid, _status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break  # No more children ready to reap
        except (ChildProcessError, InterruptedError):
            pass
        except Exception:  # noqa: BLE001
            pass  # Handler must never raise

    try:
        signal.signal(signal.SIGCHLD, _reap)
    except (OSError, ValueError):
        # Some environments (Windows, restricted) don't allow SIGCHLD
        # signal handlers. Silent no-op.
        pass


# Install on module import so the handler is active for any Popen
# that runs through this process. Idempotent.
_install_sigchld_reaper()


def _spawn_ingest(cmd, env, stdout, run_id):
    """Spawn ingest subprocess, isolated in its own cgroup when possible.

    Uses systemd-run --user --scope for cgroup isolation so OOM kills
    the ingest, not the gateway. Falls back to bare Popen if systemd-run
    is unavailable or fails (missing D-Bus, non-systemd host, etc.).
    """
    import subprocess as _sp
    import time as _time

    # Ensure D-Bus address is available for systemd-run --user
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        import os

        uid = os.getuid()
        bus = f"unix:path=/run/user/{uid}/bus"
        env["DBUS_SESSION_BUS_ADDRESS"] = bus
    if "XDG_RUNTIME_DIR" not in env:
        import os

        env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"

    scope_cmd = [
        "systemd-run",
        "--user",
        "--scope",
        "--property=MemoryMax=8G",
        "--property=MemoryHigh=6G",
        f"--unit=sift-ingest-{run_id[:12]}",
    ] + cmd

    try:
        proc = _sp.Popen(
            scope_cmd,
            stdout=stdout,
            stderr=_sp.STDOUT,
            env=env,
            start_new_session=True,
        )
        # systemd-run may fail after Popen succeeds (no D-Bus, etc.)
        _time.sleep(0.3)
        if proc.poll() is not None and proc.returncode != 0:
            # Clean up failed scope unit
            _sp.run(
                ["systemctl", "--user", "reset-failed", f"sift-ingest-{run_id[:12]}"],
                capture_output=True,
            )
            proc = _sp.Popen(
                cmd,
                stdout=stdout,
                stderr=_sp.STDOUT,
                env=env,
                start_new_session=True,
            )
    except (FileNotFoundError, OSError):
        proc = _sp.Popen(
            cmd,
            stdout=stdout,
            stderr=_sp.STDOUT,
            env=env,
            start_new_session=True,
        )
    return proc


def _launch_background(
    subcommand,
    path,
    hostname,
    index_suffix="",
    time_field="",
    delimiter="",
    recursive=False,
    auto_hosts="",
):
    """Launch a generic ingest as background subprocess with concurrency control."""
    import os as _os
    import sys as _sys
    import uuid as _uuid
    from datetime import datetime, timezone

    # Defensive breaker reset — covers idx_ingest_json/delimited/accesslog.
    from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb
    from opensearch_mcp.ingest_status import read_active_ingests, write_status

    _reset_cb()

    # Pre-flight shard capacity check — single insertion point covers
    # json / delimited / accesslog subcommands routed through here.
    # (opensearch_ingest and idx_ingest_memory have their own pre-flight
    # before their specific subprocess launches.)
    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    ok, reason = check_shard_headroom(
        get_client(),
        expected_new_shards=_estimate_new_shards(subcommand),
        min_headroom_pct=10.0,
    )
    if not ok:
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.ingest_status import (
            HALT_SHARD_CAPACITY,
            write_status,
        )

        _active_case_id = _get_active_case() or ""
        if _active_case_id:
            write_status(
                case_id=_active_case_id,
                pid=os.getpid(),
                run_id="",
                status="failed",
                hosts=[],
                totals={},
                started=_dt.now(_tz.utc).isoformat(),
                error=f"{HALT_SHARD_CAPACITY}: {reason}",
            )
        return {"status": "failed", "error": "shard_capacity", "message": reason}

    active_case_id = _get_active_case()
    if not active_case_id:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }

    # Concurrency gate — prevent OpenSearch OOM from unbounded parallelism
    active = read_active_ingests()
    running = [i for i in active if i.get("status") in ("running", "starting")]
    if len(running) >= _MAX_CONCURRENT_INGESTS:
        return {
            "error": (
                f"Too many concurrent ingests ({len(running)} running, "
                f"max {_MAX_CONCURRENT_INGESTS}). Wait for current ingests "
                "to complete. Use opensearch_ingest_status() to check progress."
            ),
            "running": [{"case_id": r.get("case_id"), "pid": r.get("pid")} for r in running],
        }

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["SIFT_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        subcommand,
        path,
        "--case",
        active_case_id,
    ]
    if hostname:
        cmd.extend(["--hostname", hostname])
    if index_suffix:
        cmd.extend(["--index-suffix", index_suffix])
    if time_field:
        cmd.extend(["--time-field", time_field])
    if delimiter:
        cmd.extend(["--delimiter", delimiter])
    if recursive:
        cmd.append("--recursive")
    if auto_hosts:
        cmd.extend(["--auto-hosts", auto_hosts])

    # Log to file instead of DEVNULL so errors are visible
    from opensearch_mcp.paths import sift_dir

    log_dir = sift_dir() / "ingest-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.log"
    log_fh = open(log_file, "w")

    # Write placeholder status BEFORE spawn to close TOCTOU window
    started_ts = datetime.now(timezone.utc).isoformat()
    write_status(
        case_id=active_case_id,
        pid=0,
        run_id=run_id,
        status="starting",
        hosts=[{"hostname": hostname, "artifacts": [{"name": subcommand, "status": "starting"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    proc = _spawn_ingest(cmd, env, log_fh, run_id)
    log_fh.close()  # Safe: Popen dup2'd the fd, subprocess has its own copy
    # Remove orphaned PID-0 placeholder
    _safe_case = active_case_id.replace("/", "_").replace("\\", "_").replace("..", "_")
    _pid0 = sift_dir() / "ingest-status" / f"{_safe_case}-0.json"
    _pid0.unlink(missing_ok=True)
    write_status(
        case_id=active_case_id,
        pid=proc.pid,
        run_id=run_id,
        status="running",
        hosts=[{"hostname": hostname, "artifacts": [{"name": subcommand, "status": "running"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "log_file": str(log_file),
        "message": (
            f"Ingest started. Call opensearch_ingest_status() to monitor progress. Log file: {log_file}"
        ),
    }
    aid = audit.log(
        tool=f"idx_ingest_{subcommand}",
        params={"path": path, "hostname": hostname},
        result_summary=f"Background ingest started (pid={proc.pid})",
        input_files=[path],
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def _launch_enrich_background(case_id: str, force: bool = False) -> dict:
    """Launch opensearch_enrich_intel as a background subprocess.

    Mirrors `_launch_background` but shaped for enrichment: no path
    positional, no hostname, no shard-capacity preflight (enrichment
    doesn't create new indices — it stamps existing docs). Returns
    immediately with `{status: "started", pid, run_id, log_file}` so
    the gateway's 300s synchronous tool timeout cannot kill a real
    enrichment run (UAT 2026-04-23 B79: 5,426-IOC corpus × rate-limited
    OpenCTI = 15–60 min, 3×–12× the timeout).

    Status records use `artifact_name="intel"` so the sweep + monotonic
    transition protection in `ingest_status` apply equally; operators
    watch progress via `opensearch_ingest_status` (intel and ingest runs
    interleave there — disambiguate on `artifact_name`).
    """
    import os as _os
    import sys as _sys
    import uuid as _uuid
    from datetime import datetime, timezone

    from opensearch_mcp.ingest_status import read_active_ingests, write_status

    active_case_id = _get_active_case()
    if not active_case_id:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }
    # An explicit case_id arg (not the active case) is respected: pass
    # it through to the worker and use it for status-file keying.
    status_case = case_id or active_case_id

    # Concurrency gate — same cap as ingest. Enrichment is one-per-case
    # and typically long; running multiple simultaneously would starve
    # the rate limiter.
    active = read_active_ingests()
    running = [i for i in active if i.get("status") in ("running", "starting")]
    if len(running) >= _MAX_CONCURRENT_INGESTS:
        return {
            "error": (
                f"Too many concurrent ingest/enrich runs ({len(running)} "
                f"running, max {_MAX_CONCURRENT_INGESTS}). Wait for "
                "current runs to complete. Use opensearch_ingest_status() to check."
            ),
            "running": [{"case_id": r.get("case_id"), "pid": r.get("pid")} for r in running],
        }

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["SIFT_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        "enrich-intel",
        "--case",
        status_case,
    ]
    if force:
        cmd.append("--force")

    from opensearch_mcp.paths import sift_dir

    log_dir = sift_dir() / "ingest-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{run_id}.log"
    log_fh = open(log_file, "w")

    # Pre-spawn placeholder status so the TOCTOU window is closed.
    started_ts = datetime.now(timezone.utc).isoformat()
    write_status(
        case_id=status_case,
        pid=0,
        run_id=run_id,
        status="starting",
        hosts=[{"hostname": "(enrich)", "artifacts": [{"name": "intel", "status": "starting"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    proc = _spawn_ingest(cmd, env, log_fh, run_id)
    log_fh.close()
    # Remove orphaned PID-0 placeholder.
    _safe_case = status_case.replace("/", "_").replace("\\", "_").replace("..", "_")
    _pid0 = sift_dir() / "ingest-status" / f"{_safe_case}-0.json"
    _pid0.unlink(missing_ok=True)
    write_status(
        case_id=status_case,
        pid=proc.pid,
        run_id=run_id,
        status="running",
        hosts=[{"hostname": "(enrich)", "artifacts": [{"name": "intel", "status": "running"}]}],
        totals={"indexed": 0, "artifacts_total": 1, "artifacts_complete": 0},
        started=started_ts,
        log_file=str(log_file),
    )

    resp = {
        "status": "started",
        "pid": proc.pid,
        "run_id": run_id,
        "case_id": status_case,
        "log_file": str(log_file),
        "message": (
            "Intel enrichment started. Call opensearch_ingest_status() to monitor "
            f"progress (artifact_name='intel'). Log file: {log_file}"
        ),
    }
    aid = audit.log(
        tool="opensearch_enrich_intel",
        params={"case_id": status_case, "force": force},
        result_summary=f"Background enrichment started (pid={proc.pid})",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def idx_ingest_memory(
    path: str,
    hostname: str,
    tier: int = 1,
    plugins: list[str] | None = None,
    dry_run: bool = True,
) -> dict:
    """Parse a memory image with Volatility 3 and index results.

    Args:
        path: Memory image path under the active case. Bare filenames resolve
            to SIFT_CASE_DIR/evidence/.
        hostname: Source hostname for the memory image.
        tier: Analysis depth (1=fast/essential, 2=moderate, 3=deep).
        plugins: Override tier — run only these specific plugins.
        dry_run: Preview plugins (default True). Set False to execute.
    """
    resolved, path_error = _resolve_tool_path(path)
    if path_error:
        return path_error
    assert resolved is not None
    resolved_path = str(resolved)
    if not resolved.exists():
        return {"error": f"Path not found: {path}", "resolved_path": resolved_path}
    from opensearch_mcp.parse_memory import TIER_1, TIER_2, TIER_3

    if plugins:
        plugin_list = plugins
    elif tier >= 3:
        plugin_list = TIER_3
    elif tier >= 2:
        plugin_list = TIER_2
    else:
        plugin_list = TIER_1

    if dry_run:
        resp = {
            "status": "preview",
            "tier": tier,
            "plugins": plugin_list,
            "plugin_count": len(plugin_list),
        }
        aid = audit.log(
            tool="idx_ingest_memory",
            params={"path": resolved_path, "dry_run": True, "tier": tier},
            result_summary=f"preview: {len(plugin_list)} plugins",
        )
        if aid:
            resp["audit_id"] = aid
        return resp

    # dry_run=False: defensive reset, pre-flight, then launch subprocess.
    from opensearch_mcp.bulk import reset_circuit_breaker as _reset_cb

    _reset_cb()

    from opensearch_mcp.shard_capacity import (
        _estimate_new_shards,
        check_shard_headroom,
    )

    ok, reason = check_shard_headroom(
        get_client(),
        expected_new_shards=_estimate_new_shards("memory"),
        min_headroom_pct=10.0,
    )
    if not ok:
        aid = audit.log(
            tool="idx_ingest_memory",
            params={"path": resolved_path, "dry_run": False, "tier": tier},
            result_summary=f"aborted: {reason[:120]}",
        )
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        from opensearch_mcp.ingest_status import (
            HALT_SHARD_CAPACITY,
            write_status,
        )

        _active = _get_active_case() or ""
        if _active:
            write_status(
                case_id=_active,
                pid=os.getpid(),
                run_id="",
                status="failed",
                hosts=[],
                totals={},
                started=_dt.now(_tz.utc).isoformat(),
                error=f"{HALT_SHARD_CAPACITY}: {reason}",
            )
        resp = {"status": "failed", "error": "shard_capacity", "message": reason}
        if aid:
            resp["audit_id"] = aid
        return resp

    import os as _os
    import sys as _sys
    import uuid as _uuid

    from opensearch_mcp.ingest_status import read_active_ingests as _read_mem

    active_case_id = _get_active_case()
    if not active_case_id:
        return {
            "error": "No active case.",
            "action": "Create a case in the Examiner Portal first.",
            "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
        }

    # Concurrency gate (same as _launch_background)
    _running_mem = [i for i in _read_mem() if i.get("status") in ("running", "starting")]
    if len(_running_mem) >= _MAX_CONCURRENT_INGESTS:
        return {
            "error": (
                f"Too many concurrent ingests ({len(_running_mem)} running, "
                f"max {_MAX_CONCURRENT_INGESTS}). Wait for current ingests "
                "to complete. Use opensearch_ingest_status() to check progress."
            ),
        }

    run_id = str(_uuid.uuid4())
    env = _os.environ.copy()
    env["SIFT_INGEST_RUN_ID"] = run_id

    cmd = [
        _sys.executable,
        "-m",
        "opensearch_mcp.ingest_cli",
        "memory",
        resolved_path,
        "--hostname",
        hostname,
        "--case",
        active_case_id,
        "--tier",
        str(tier),
        "--yes",
    ]
    if plugins:
        cmd.extend(["--plugins", ",".join(plugins)])

    from opensearch_mcp.paths import sift_dir as _vd

    _ld = _vd() / "ingest-logs"
    _ld.mkdir(parents=True, exist_ok=True)
    _lf = _ld / f"{run_id}.log"
    _lfh = open(_lf, "w")

    # Write placeholder status BEFORE spawn (same TOCTOU fix as _launch_background)
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from opensearch_mcp.ingest_status import write_status as _ws_mem

    _started_ts = _dt.now(_tz.utc).isoformat()
    _ws_mem(
        case_id=active_case_id,
        pid=0,
        run_id=run_id,
        status="starting",
        hosts=[{"hostname": hostname, "artifacts": [{"name": "memory", "status": "starting"}]}],
        totals={"indexed": 0, "artifacts_total": len(plugin_list), "artifacts_complete": 0},
        started=_started_ts,
        log_file=str(_lf),
    )

    proc = _spawn_ingest(cmd, env, _lfh, run_id)
    _lfh.close()  # Safe: Popen dup2'd the fd, subprocess has its own copy
    # Remove orphaned PID-0 placeholder
    _safe_case_m = active_case_id.replace("/", "_").replace("\\", "_").replace("..", "_")
    _pid0_m = _vd() / "ingest-status" / f"{_safe_case_m}-0.json"
    _pid0_m.unlink(missing_ok=True)

    # Collect filesystem metadata sidecar for memory image
    from opensearch_mcp.containers import _collect_filesystem_meta as _cfm_mem
    import json as _json_mem

    _fs_meta_m = _cfm_mem(resolved_path, "memory")
    _fs_meta_rel_m: str | None = None
    _case_dir_env_m = _os.environ.get("SIFT_CASE_DIR", "").strip()
    if _case_dir_env_m and _fs_meta_m.get("image_type") != "unknown":
        _sidecar_dir_m = Path(_case_dir_env_m) / "agent" / "ingest"
        _sidecar_dir_m.mkdir(parents=True, exist_ok=True)
        _sidecar_path_m = _sidecar_dir_m / f"{run_id}-filesystem-meta.json"
        _sidecar_path_m.write_text(_json_mem.dumps(_fs_meta_m, indent=2))
        _fs_meta_rel_m = f"agent/ingest/{run_id}-filesystem-meta.json"

    resp = {
        "status": "started",
        "pid": proc.pid,
        "tier": tier,
        "plugins": plugin_list,
        "message": (
            f"Memory analysis started ({len(plugin_list)} plugins). "
            "This may take several minutes. Use opensearch_ingest_status() to monitor."
        ),
    }
    if _fs_meta_rel_m:
        resp["filesystem_meta_path"] = _fs_meta_rel_m
    aid = audit.log(
        tool="idx_ingest_memory",
        params={"path": resolved_path, "tier": tier, "pid": proc.pid, "run_id": run_id},
        result_summary=f"started tier {tier} ({len(plugin_list)} plugins)",
        input_files=[resolved_path],
    )
    if aid:
        resp["audit_id"] = aid
    return resp


def _get_active_case() -> str | None:
    """Return active case ID for index construction.

    Portal workflow: reads SIFT_CASE_DIR set by gateway in every
    stdio subprocess environment. CLI fallback: reads the legacy pointer file.
    Returns None when neither source is set — callers must handle this.
    """
    import os
    from pathlib import Path

    # Primary: SIFT_CASE_DIR set by gateway in every stdio subprocess env
    case_dir = os.environ.get("SIFT_CASE_DIR", "").strip()
    if case_dir:
        return Path(case_dir).name.lower()  # lowercase required for OpenSearch indices

    # Legacy CLI fallback — not used in portal workflow
    from opensearch_mcp.paths import sift_dir

    active_case_file = sift_dir() / "active_case"
    if active_case_file.exists():
        raw = active_case_file.read_text().strip()
        if raw:
            return Path(raw).name.lower()
    return None


@server.tool(annotations={"readOnlyHint": True})
def opensearch_list_detections(
    severity: str = "",
    detector_type: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List detection findings from Security Analytics (Sigma) or suggest Hayabusa alternatives.

    Args:
        severity: Filter by severity (critical, high, medium, low).
                  Empty = all severities.
        detector_type: Filter by detector type (windows, linux, dns, etc.).
                  Empty = all detectors.
        limit: Max results (default 50).
        offset: Starting position for pagination (default 0).
    """
    limit = min(limit, 500)
    client = _get_os()

    # Fetch more than requested when filtering by severity (API doesn't support it)
    fetch_size = limit * 3 if severity else limit
    params: dict = {
        "size": fetch_size,
        "startIndex": offset,
        "sortOrder": "desc",
    }
    if detector_type:
        params["detectorType"] = detector_type

    try:
        response = _os_call(
            client.transport.perform_request,
            "GET",
            "/_plugins/_security_analytics/findings/_search",
            params=params,
        )
    except (RuntimeError, ValueError, Exception) as e:
        if "security_analytics" in str(e).lower() or "400" in str(e) or "404" in str(e):
            resp = {"error": "Security Analytics plugin not available", "findings": []}
            # Still suggest Hayabusa when SA is unavailable
            try:
                hb_count = client.count(index="case-*-hayabusa-*")["count"]
                if hb_count:
                    resp["suggestion"] = (
                        f"Sigma detectors unavailable. {hb_count:,} Hayabusa alerts available. "
                        "Query: opensearch_search(query='Level:critical OR Level:high', "
                        "index='case-*-hayabusa-*')"
                    )
                else:
                    resp["suggestion"] = (
                        "Sigma detectors unavailable on OpenSearch 3.5. "
                        "Hayabusa runs during evtx ingest if installed."
                    )
            except Exception:
                resp["suggestion"] = (
                    "Sigma detectors unavailable. Check Hayabusa: "
                    "opensearch_search(query='Level:*', index='case-*-hayabusa-*')"
                )
            return resp
        raise

    sev_filter = severity.lower() if severity else ""
    findings = []
    for finding in response.get("findings", []):
        rules = []
        for q in finding.get("queries", []):
            rules.append(
                {
                    "name": q.get("name"),
                    "tags": q.get("tags", []),
                }
            )

        # Python-side severity filter — API doesn't support severity param
        if sev_filter and rules:
            if not any(sev_filter in t.lower() for r in rules for t in r.get("tags", [])):
                continue

        findings.append(
            {
                "id": finding.get("id"),
                "timestamp": finding.get("timestamp"),
                "index": finding.get("index"),
                "rules": rules,
                "matched_docs": len(finding.get("related_doc_ids", [])),
            }
        )

        if len(findings) >= limit:
            break

    # Suggest Hayabusa when Sigma returns empty
    hayabusa_hint = ""
    if not findings:
        try:
            hb_count = client.count(index="case-*-hayabusa-*")["count"]
            if hb_count:
                hayabusa_hint = (
                    f"No Sigma detections. {hb_count:,} Hayabusa alerts available. "
                    "Query: opensearch_search(query='Level:critical OR Level:high', "
                    "index='case-*-hayabusa-*')"
                )
            else:
                hayabusa_hint = (
                    "No Sigma detections (disabled on OpenSearch 3.5). "
                    "Hayabusa runs during evtx ingest if installed."
                )
        except Exception:
            hayabusa_hint = "No Sigma detections."

    resp = {
        "findings": findings,
        "total": response.get("total_findings", 0),
        "returned": len(findings),
        "offset": offset,
    }
    if hayabusa_hint:
        resp["suggestion"] = hayabusa_hint
    aid = audit.log(
        tool="opensearch_list_detections",
        params={
            "severity": severity,
            "detector_type": detector_type,
            "limit": limit,
            "offset": offset,
        },
        result_summary=f"{len(findings)} findings",
    )
    if aid:
        resp["audit_id"] = aid
    return resp


@server.tool()
def opensearch_host_fix(raw: str, new_canonical: str) -> dict:
    """Correct a wrong host.id mapping in the active case.

    Use this tool when an earlier `opensearch_ingest` auto-applied a wrong
 proposal (e.g., proposed `wkstn01` for raw `wksn01` but the operator
 confirms `wksn01` is actually a separate host).

    Behavior:
      1. Edits the case host-dictionary in memory: removes `raw` from
 any existing canonical's alias list, then either adds `raw` to
 `new_canonical`'s alias list (if `new_canonical` exists) or
 creates `new_canonical` with `raw` as its first alias.
      2. **Saves the dictionary atomically to disk.** This happens
 BEFORE the reindex so a crash mid-call leaves the dict
 reflecting operator intent.
      3. Runs `update_by_query` across the case indices with a term
 filter on `host.name:<raw>`, scripting `host.id = new_canonical`.
 host.name is never touched.

    On large hosts (5M+ docs) the `update_by_query` may exceed the
 sift-gateway 300s tool-call timeout. When that happens: the dict is
 already saved, OpenSearch continues the reindex server-side, and a
 re-call is idempotent (dict no-op + finishes the remaining reindex).

    Returns:
      {"raw": ..., "new_canonical": ..., "docs_updated": N, "dict_path": ...}
    """
    from opensearch_mcp.host_dictionary import InvalidHostnameValue

    try:
        return _case_host_fix_impl(raw, new_canonical)
    except InvalidHostnameValue as e:
        return {
            "status": "rejected",
            "error": f"InvalidHostnameValue: {e}",
            "raw": raw,
            "new_canonical": new_canonical,
            "dict_saved": False,
            "isError": True,
        }
    except Exception as e:
        # Last-resort envelope — any unexpected exception still returns
        # a structured response with isError: True rather than bubbling
        # to FastMCP as a generic ToolError.
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "raw": raw,
            "new_canonical": new_canonical,
            "isError": True,
        }


def _case_host_fix_impl(raw: str, new_canonical: str) -> dict:
    """Correct a wrong host.id mapping in the active case.

    Use this tool when an earlier `opensearch_ingest` auto-applied a wrong
    decision (e.g., proposed `wkstn01` for raw `wksn01` but the operator
    confirms `wksn01` is actually a separate host).

    Behavior:
      1. Edits the case host-dictionary in memory: removes `raw` from
         any existing canonical's alias list, then either adds `raw` to
         `new_canonical`'s alias list (if `new_canonical` exists) or
         creates `new_canonical` with `raw` as its first alias.
      2. **Saves the dictionary atomically to disk.** This happens
         BEFORE the reindex so a crash mid-call leaves the dict
         reflecting operator intent.
      3. Runs `update_by_query` across the case indices with a term
         filter on `host.name:<raw>`, scripting `host.id = new_canonical`.
         host.name is never touched.

    On large hosts (5M+ docs) the `update_by_query` may exceed the
    sift-gateway 300s tool-call timeout. When that happens: the dict is
    already saved, OpenSearch continues the reindex server-side, and a
    re-call is idempotent (dict no-op + finishes the remaining reindex).

    Returns:
      {"raw": ..., "new_canonical": ..., "docs_updated": N, "dict_path": ...}
    """
    from opensearch_mcp.host_dictionary import HostDictionary

    # Resolve active case → case dir → dict path.
    # Use SIFT_CASE_DIR directly if set (preserves actual dir name including case).
    # Fall back to legacy pointer file without lowercasing (filesystem names may be uppercase).
    import os as _os

    _case_dir_env = _os.environ.get("SIFT_CASE_DIR", "").strip()
    if _case_dir_env:
        case_dir = Path(_case_dir_env)
        case_id = case_dir.name.lower()  # lowercase for index naming only
    else:
        # Legacy CLI fallback — not used in portal workflow
        from opensearch_mcp.paths import sift_dir as _sift_dir

        _active_case_file = _sift_dir() / "active_case"  # Legacy CLI fallback
        if not _active_case_file.exists():
            return {
                "error": "No active case.",
                "action": "Create a case in the Examiner Portal first.",
                "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
            }
        _raw = _active_case_file.read_text().strip()
        if not _raw:
            return {
                "error": "No active case.",
                "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
            }
        case_id = Path(_raw).name
        # Try absolute path first, then cases_root/<case_id>
        _raw_path = Path(_raw)
        case_dir = _raw_path if _raw_path.is_absolute() and _raw_path.is_dir() else cases_root() / case_id
    if not case_dir.is_dir():
        return {"error": f"Case directory not found: {case_dir}"}
    dict_path = case_dir / "host-dictionary.yaml"
    if not dict_path.exists():
        return {
            "error": (
                f"host-dictionary.yaml not found at {dict_path}. "
                "Run opensearch_ingest at least once to create it."
            )
        }

    # 1. In-memory dict edits.
    host_dict = HostDictionary.load(dict_path)

    # Edge case: `raw` is itself a canonical name (operator wants to
    # collapse it into another canonical). If we leave the orphan
    # canonical entry in place, _rebuild_alias_map sets raw → raw via
    # the canonical-self-mapping, which overrides the new alias and
    # makes the fix invisible. Delete the canonical entry to ensure
    # the new mapping wins.
    if raw in host_dict.hosts and raw != new_canonical:
        del host_dict.hosts[raw]

    for canonical, entry in host_dict.hosts.items():
        aliases = entry.get("aliases", []) or []
        if raw in aliases and canonical != new_canonical:
            aliases.remove(raw)

    # Catch adversarial-input rejection from add_alias/add_canonical and
    # return a structured error response. Without this, the exception
    # propagates to MCP framework as a generic ToolError — the operator
    # loses the dict-saved/retry context.
    from opensearch_mcp.host_dictionary import InvalidHostnameValue

    try:
        if new_canonical in host_dict.hosts:
            host_dict.add_alias(raw, new_canonical)
        else:
            host_dict.add_canonical(new_canonical)
            if raw != new_canonical:
                host_dict.add_alias(raw, new_canonical)
        host_dict._rebuild_alias_map()
    except InvalidHostnameValue as e:
        return {
            "status": "rejected",
            "error": f"InvalidHostnameValue: {e}",
            "raw": raw,
            "new_canonical": new_canonical,
            "dict_saved": False,
            "isError": True,
        }

    # 2. Save BEFORE reindex.
    host_dict.save()

    # 3. update_by_query with term-DSL filter (NOT query_string — raw
    # values may contain Lucene metacharacters; term filter treats them
    # as exact-value).
    client = _get_os()
    index_pattern = f"case-{case_id.lower()}-*"

    # H1 defensive: refuse to write through indices where host.id is
    # non-keyword (pre-v1 upgrade path). Uses the shared detector
    # imported at module top so a long-running gateway picks it up via
    # the host_dictionary module path, not lazy through ingest_cli.
    try:
        _mappings = client.indices.get_mapping(index=index_pattern, allow_no_indices=True)
        _bad_indices = []
        for _idx_name, _body in (_mappings or {}).items():
            _props = _body.get("mappings", {}).get("properties", {})
            _ht = detect_host_id_mapping_type(_props)
            if _ht is not None and _ht != "keyword":
                _bad_indices.append(_idx_name)
        if _bad_indices:
            return {
                "status": "mapping_upgrade_required",
                "error": (
                    f"{len(_bad_indices)} indices have host.id as non-keyword "
                    "from a pre-v1 ingest. opensearch_host_fix would silently leave "
                    "host.id unqueryable on those indices. Reindex or delete "
                    "before retrying."
                ),
                "indices_text": _bad_indices,
                "raw": raw,
                "new_canonical": new_canonical,
                "dict_saved": True,
                "dict_path": str(dict_path),
                "isError": True,
            }
    except Exception:
        # Mapping check is best-effort; cluster errors fall through.
        pass

    # Scoped reindex: filter to docs where host.name matches raw AND
    # host.id is not yet new_canonical. Retry-after-timeout only
    # touches docs that still need flipping.
    #
    # Defense in depth (WSL2 R5): also gate inside the painless script
    # with `ctx.op = 'noop'` when host.id is already at new_canonical.
    # Reason: the must_not term query depends on host.id being a
    # keyword-mapped field. On a pre-v1 text-mapped index the term
    # query against host.id can match unexpectedly (analyzed text
    # tokenization), so the bool filter alone isn't enough. The script
    # guard works regardless of mapping type — the engine treats noop
    # as "no write, no version bump" and the cost stays bounded.
    body = {
        "query": {
            "bool": {
                "must": [{"term": {"host.name": raw}}],
                "must_not": [{"term": {"host.id": new_canonical}}],
            }
        },
        "script": {
            "source": (
                "if (ctx._source['host.id'] == params.id) { ctx.op = 'noop'; return; } "
                "ctx._source['host.id'] = params.id"
            ),
            "lang": "painless",
            "params": {"id": new_canonical},
        },
    }
    try:
        # WSL2 R4 Test 3: default client read_timeout (~10s) fires
        # false-negative on multi-hundred-thousand-doc hosts even when
        # the cluster completes the work. Raise to 600s so v1 covers
        # ~6M-doc hosts at typical 10K/sec throughput. v2 backlog has
        # `wait_for_completion=false` + task polling for larger.
        result = client.update_by_query(
            index=index_pattern,
            body=body,
            refresh=True,
            conflicts="proceed",
            request_timeout=600,
        )
    except Exception as e:
        err_resp = {
            "status": "reindex_failed",
            "error": f"update_by_query failed: {type(e).__name__}: {e}",
            "raw": raw,
            "new_canonical": new_canonical,
            "dict_saved": True,
            "dict_path": str(dict_path),
            "retry_hint": (
                "Dict is saved with the new mapping. Re-call opensearch_host_fix "
                "with the same args to retry the reindex."
            ),
            "isError": True,
        }
        try:
            audit.log(
                tool="opensearch_host_fix",
                params={
                    "raw": raw,
                    "new_canonical": new_canonical,
                    "case_id": case_id,
                },
                result_summary=(f"dict saved at {dict_path}; reindex failed ({type(e).__name__})"),
            )
        except Exception:
            pass
        return err_resp
    resp = {
        "raw": raw,
        "new_canonical": new_canonical,
        "docs_updated": result.get("updated", 0),
        "took_ms": result.get("took", 0),
        "dict_path": str(dict_path),
    }
    try:
        aid = audit.log(
            tool="opensearch_host_fix",
            params={
                "raw": raw,
                "new_canonical": new_canonical,
                "case_id": case_id,
            },
            result_summary=(
                f"dict updated, {resp['docs_updated']} docs reindexed on host.name={raw!r}"
            ),
        )
        if aid:
            resp["audit_id"] = aid
    except Exception:
        pass
    return resp


def main():
    """Run the MCP server."""
    from opensearch_mcp.registry import create_server

    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
