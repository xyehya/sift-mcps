"""Search result formatting and autosave helpers for OpenSearch MCP.

Pure data-shaping utilities extracted from ``opensearch_mcp.server`` (D5/XYE-73).
These helpers have no OpenSearch I/O or FastMCP dependency; they operate only on
already-fetched result sets and the active-case directory (for disk spill).

Ownership: one concern — how search hits and aggregate buckets are shaped,
trimmed, and optionally spilled to disk before returning to the caller.

Do NOT add OpenSearch client calls, FastMCP tool registrations, or case-resolution
logic to this module. Those live in ``server.py`` (impl engine) and
``registry.py`` (typed contract).
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Field exclusion / truncation — compact hit formatting
# ---------------------------------------------------------------------------

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
        "SourceFile",  # duplicates sift.source_file
        "Computer",  # duplicated to host.name by parse_delimited
        # Metadata (available via opensearch_get_event, zero triage value)
        "ExtraDataOffset",
        "HiddenRecord",
        "Keywords",
        "ChunkNumber",
        "pipeline_version",
        "sift.source_file",
        "sift.ingest_audit_id",
        "sift.parse_method",
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


# ---------------------------------------------------------------------------
# Constant-field hoisting — deduplicates per-hit repetition in response
# ---------------------------------------------------------------------------

# Search result fields that are typically constant across an entire result set
# (provenance/case scoping injected at ingest). When every returned hit carries
# the same value, they are hoisted into a single response header (`common_fields`)
# instead of repeated on every hit. This is a candidate list; the hoist still
# verifies per-call that the value is actually identical across all hits.
_HOISTABLE_CONSTANT_FIELDS: tuple[str, ...] = (
    "sift.case_id",
    "sift.provenance_id",
)

# Marker the hoister stores per-hit-key so a hit that genuinely lacks a field is
# never confused with a field whose value happens to equal a real document value.
_HOIST_MISSING = object()


def _hoist_constant_fields(
    docs: list[dict],
    candidate_fields: tuple[str, ...] = _HOISTABLE_CONSTANT_FIELDS,
) -> tuple[dict, list[dict]]:
    """Lift fields that are identical across *all* hits into one header.

    Returns ``(common_fields, slim_docs)``. A candidate field is hoisted only
    when it is present on every hit with the *same* value (the mixed/partial
    case is left untouched so correctness is preserved). The hoisted keys are
    stripped from each per-hit document; ``_id``/``_index`` are never hoisted.
    """
    if not docs:
        return {}, docs

    common: dict = {}
    for field in candidate_fields:
        if field in {"_id", "_index"}:
            continue
        first = docs[0].get(field, _HOIST_MISSING)
        if first is _HOIST_MISSING:
            continue
        identical = all(hit.get(field, _HOIST_MISSING) == first for hit in docs)
        if identical:
            common[field] = first

    if not common:
        return {}, docs

    slim_docs = [
        {key: value for key, value in hit.items() if key not in common}
        for hit in docs
    ]
    return common, slim_docs


# ---------------------------------------------------------------------------
# Autosave (disk spill) — large result sets written to <case>/agent/<kind>/
# ---------------------------------------------------------------------------

# Autosave caps (mirror run_command output-cap disk spill). A result set
# exceeding EITHER the hit/bucket count threshold OR the serialized byte cap is
# written in full to <case>/agent/<kind>/ and only a small inline preview is
# returned. The byte cap catches the "few but huge docs" case the count
# threshold misses (e.g. 20 large SRUM rows that still flood context).
_SEARCH_AUTOSAVE_THRESHOLD = 20
_SEARCH_INLINE_TOP_N = 20
_SEARCH_AUTOSAVE_MAX_BYTES = 64 * 1024  # 64 KiB inline ceiling for search hits
_AGG_AUTOSAVE_THRESHOLD = 100
_AGG_INLINE_TOP_N = 50
_AGG_AUTOSAVE_MAX_BYTES = 32 * 1024  # 32 KiB inline ceiling for aggregate buckets


def _payload_bytes(payload) -> int:
    """Approximate the serialized JSON byte size of a result payload.

    Used by the byte-size autosave cap so a small *count* of very large
    documents (e.g. 20 fat SRUM rows) still spills to disk instead of flooding
    context. Best-effort: any serialization failure returns 0 so the byte cap
    simply does not trigger (the count threshold still applies).
    """
    import json as _json

    try:
        return len(_json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def _save_full_results(kind: str, payload) -> str | None:
    """Persist a full result payload under ``<case>/agent/<kind>/`` and return a
    case-relative ref (e.g. ``agent/searches/search_<uuid>.json``).

    Mirrors the run_command / output-cap disk-spill pattern so a large result
    set (search hits, aggregate buckets, ...) can be saved once and
    grepped/transformed on disk by the agent instead of being dumped inline
    (PTC "query -> save -> grep" loop). ``kind`` selects both the subdirectory
    and the filename prefix (``searches`` -> ``search_*.json``;
    ``aggregations`` -> ``aggregation_*.json``). Returns ``None`` if there is no
    active case dir or the write fails (the caller then degrades to returning
    the inline preview without a path).

    Active-case resolution uses :func:`opensearch_mcp.server.active_case_dir`
    (Gateway-authoritative). The import is deferred to function-call time to
    avoid a module-level circular import (server imports search_format;
    search_format lazily imports server only when the function is actually called,
    by which point both modules are fully initialised).
    """
    import json as _json
    import uuid as _uuid

    # Lazy import: avoids circular import at module load time.
    from opensearch_mcp.server import active_case_dir

    case_dir = active_case_dir()
    if not case_dir:
        return None
    # filename prefix per kind: searches -> "search", aggregations -> "aggregation"
    prefix = {"searches": "search", "aggregations": "aggregation"}.get(
        kind, kind.rstrip("s") or kind
    )
    try:
        case_resolved = Path(case_dir).resolve()
        out_dir = case_resolved / "agent" / kind
        # Safety: stay under <case>/agent (parallels run_command + output cap).
        if not out_dir.is_relative_to(case_resolved / "agent"):
            return None
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{prefix}_{_uuid.uuid4().hex}.json"
        target = out_dir / fname
        with open(target, "w", encoding="utf-8") as fh:
            _json.dump(payload, fh, ensure_ascii=False, default=str)
        return f"agent/{kind}/{fname}"
    except OSError as exc:  # pragma: no cover - defensive
        logger.warning("opensearch %s: failed to persist full results: %s", kind, exc)
        return None


def _autosave_or_inline(
    kind: str,
    items: list,
    *,
    count_threshold: int,
    byte_cap: int,
    inline_n: int,
    note_builder,
) -> tuple[list, str | None, str | None]:
    """Decide between returning a result set inline and spilling it to disk.

    Shared by :func:`opensearch_search` and :func:`opensearch_aggregate` so the
    byte/count autosave policy lives in ONE place. Triggers when ``items``
    exceeds EITHER ``count_threshold`` OR the serialized ``byte_cap`` (a small
    count of very large items still floods context). Returns
    ``(inline_items, full_path, note)``:

    - Not triggered: ``(items, None, None)`` — the whole set stays inline.
    - Triggered + save SUCCESS: full set written under ``<case>/agent/<kind>/``;
      returns ``(preview, full_path, note_builder(full_path, len(preview),
      len(items)))`` where ``preview`` is the top-N shrunk by bytes until it
      fits ``byte_cap`` (exact prior success behavior).
    - Triggered + save FAILURE (no active case dir / write error): STILL caps the
      preview to the byte-shrunk top-N and returns ``(preview, None, failure_note)``
      so an oversized set never floods context uncapped. This closes the gap where
      a save failure previously returned the full oversized set inline.

    ``note_builder(full_path, inline_count, total_count)`` builds the success-path
    note; the failure note is generated here.
    """
    total = len(items)
    if not (total > count_threshold or _payload_bytes(items) > byte_cap):
        return items, None, None

    def _shrink(seq: list) -> list:
        preview = seq[:inline_n]
        # Byte-driven spill of fat items: even the inline top-N may be large, so
        # halve the preview until it fits the byte cap (or one item remains).
        while len(preview) > 1 and _payload_bytes(preview) > byte_cap:
            preview = preview[: max(1, len(preview) // 2)]
        return preview

    full_path = _save_full_results(kind, items)
    preview = _shrink(items)
    if full_path:
        return preview, full_path, note_builder(full_path, len(preview), total)
    # No case dir to spill to / write failed: degrade but still cap the inline.
    note = (
        f"Could not persist full set; inline truncated to {len(preview)} of "
        f"{total}. Narrow the query or set an active case to capture the rest."
    )
    return preview, None, note
