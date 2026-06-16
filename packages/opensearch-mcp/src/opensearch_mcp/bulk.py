"""Shared bulk indexing helper for evtx and CSV ingest."""

from __future__ import annotations

import contextvars
import os
import sys
import threading
import time

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import ConnectionError as OSConnectionError
from opensearchpy.exceptions import ConnectionTimeout, TransportError

# ---------------------------------------------------------------------------
# Provenance stamping (BATCH-F1)
# ---------------------------------------------------------------------------
# Every indexed document must carry the case/provenance IDs so the OpenSearch
# plane stays derived-but-traceable back to authoritative Postgres state. Rather
# than thread a provenance dict through all 14 parser modules, the ingest caller
# sets this context var (wave8/ingest-tools: the add-on `ingest_cli scan` direct
# path) and every action funnelled through flush_bulk is stamped centrally. The
# fields use the existing `sift.*` provenance namespace already present on
# indexed docs (source_file, ingest_audit_id, ...). Stamping is opaque-ID-only:
# no OS/mount/case paths.
#
# A ContextVar (not thread-local) is used so the stamp follows the logical
# ingest scope and never leaks across concurrent in-process ingests. Empty by
# default, so any ingest path that does not set it is unchanged.
_provenance_ctx: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "opensearch_ingest_provenance", default=None
)

# Only opaque-ID provenance keys are accepted onto documents. This is an
# allow-list so a future caller cannot smuggle a path-bearing field into every
# indexed doc through the provenance channel.
_ALLOWED_PROVENANCE_KEYS = frozenset(
    {
        "sift.case_id",
        "sift.evidence_id",
        "sift.provenance_id",
        "sift.job_id",
    }
)


def set_ingest_provenance(provenance: dict[str, str] | None) -> contextvars.Token:
    """Set the provenance IDs stamped onto every doc indexed in this scope.

    Returns a token; pass it to :func:`reset_ingest_provenance` to restore the
    previous value (use a try/finally so the stamp never outlives the job).
    Only opaque-ID keys in ``_ALLOWED_PROVENANCE_KEYS`` are kept; any path-like
    or unknown key is dropped defensively.
    """
    cleaned: dict[str, str] | None = None
    if provenance:
        cleaned = {
            str(k): str(v)
            for k, v in provenance.items()
            if k in _ALLOWED_PROVENANCE_KEYS and v not in (None, "")
        }
        if not cleaned:
            cleaned = None
    return _provenance_ctx.set(cleaned)


def reset_ingest_provenance(token: contextvars.Token) -> None:
    """Restore the provenance context to its pre-:func:`set_ingest_provenance` value."""
    try:
        _provenance_ctx.reset(token)
    except (ValueError, LookupError):  # pragma: no cover - token from another context
        _provenance_ctx.set(None)


def _stamp_provenance(actions: list[dict]) -> None:
    """Stamp the active provenance IDs onto each action's ``_source`` in place.

    No-op when no provenance scope is active (CLI / non-job ingest). Existing
    keys on the doc are not overwritten (a parser-set value wins), so re-ingest
    determinism and parser-owned fields are preserved.
    """
    provenance = _provenance_ctx.get()
    if not provenance:
        return
    for action in actions:
        source = action.get("_source")
        if not isinstance(source, dict):
            continue
        for key, value in provenance.items():
            source.setdefault(key, value)

_INITIAL_BACKOFF = 10
_MAX_BACKOFF = 120
_MAX_RETRIES = 10

# Circuit breaker — trip after N consecutive 100%-failure batches
# matching systemic error patterns. Prevents silent data loss when a
# cluster-wide condition (shard limit, cluster block) rejects every
# write indefinitely. Threshold is env-tunable (min 1 — operator
# typo of 0 would defeat the purpose of the breaker).
_SYSTEMIC_ERROR_PATTERNS = (
    "validation_exception",
    "cluster_block_exception",
    "this action would add",
    "maximum shards open",
    "blocked by",
    "illegal_argument_exception",
)
_CIRCUIT_BREAKER_THRESHOLD = max(1, int(os.environ.get("SIFT_SHARD_BREAKER_THRESHOLD", "3")))

# Rev 6: thread-local state. Concurrent in-process MCP tools used to
# share a module-global counter and could cross-halt each other.
# Subprocess-launched ingests still get a fresh state per process.
# Note: if a future MCP handler runs async coroutines with direct
# in-process flush_bulk, migrate to contextvars.ContextVar — today
# every ingest path subprocess-isolates so thread-local is enough.
_tls = threading.local()


def _get_counter() -> int:
    return getattr(_tls, "consecutive_systemic_failures", 0)


def _set_counter(n: int) -> None:
    _tls.consecutive_systemic_failures = n


def get_last_bulk_reason() -> str:
    """Return the first-error reason from the most recent bulk failure
    (thread-local). Empty string when the last batch succeeded or no
    batches have run yet. Callers that write ingest status read this
    to populate the status file's `bulk_failed_reason` field — gives
    operators the mapping/validation cause without digging in stderr.
    """
    return getattr(_tls, "last_bulk_reason", "")


def clear_last_bulk_reason() -> None:
    """Reset the thread-local last-error tracker. Call at ingest start."""
    _tls.last_bulk_reason = ""


class ShardCapacityExhausted(RuntimeError):
    """Raised when N consecutive bulk batches are fully rejected for
    systemic reasons (shard limit, cluster block). Signals callers to
    halt the ingest — retrying won't help until capacity is restored.
    """


def reset_circuit_breaker() -> None:
    """Call at ingest start to clear thread-local state from prior runs.

    Clears BOTH the circuit-breaker counter AND the last-bulk-reason
    tracker — both live on the same `_tls` and both need to be reset
    per ingest so an in-process MCP tool (idx_ingest_json,
    idx_ingest_delimited, idx_ingest_accesslog, idx_ingest_memory,
    opensearch_ingest) running a second time in the same thread doesn't
    inherit stale state from the prior call. Subprocess-launched
    ingests get a fresh process regardless — this matters for the
    in-process path.
    """
    _set_counter(0)
    _tls.last_bulk_reason = ""


def _is_systemic_failure(success: int, total: int, errors: list | None) -> tuple[bool, str]:
    """Scan bulk errors for systemic patterns (shard-limit, cluster-block).

    Returns (is_systemic, representative_reason). Scans up to 200
    errors (Rev 6: raised from 50). Systemic failures typically hit
    100% of a batch anyway, but a mixed batch could have 51+
    non-systemic errors before a systemic one — 200 is safe buffer.
    """
    if total == 0 or success > 0:
        return False, ""
    representative = ""
    for err in (errors or [])[:200]:  # Rev 6: raised from 50
        if not isinstance(err, dict):
            continue
        for action_type in ("index", "create", "update"):
            info = err.get(action_type, {})
            if not info.get("error"):
                continue
            e = info["error"]
            reason = e.get("reason", str(e)) if isinstance(e, dict) else str(e)
            reason_lower = reason.lower()
            if any(p in reason_lower for p in _SYSTEMIC_ERROR_PATTERNS):
                return True, reason
            if not representative:
                representative = reason
            break
    return False, representative


def flush_bulk(client: OpenSearch, actions: list[dict]) -> tuple[int, int]:
    """Bulk index actions with persistent retry on timeout.

    Returns (success_count, failed_count).
    Never gives up on a batch — retries with increasing backoff until
    OpenSearch accepts it or max retries exceeded. Under sustained
    pressure, splits the batch in half and retries smaller chunks.

    Raises ShardCapacityExhausted if N consecutive batches fail for
    systemic reasons (e.g., cluster-wide shard limit).
    """
    # Stamp case/evidence/job provenance onto every doc when an ingest job
    # scope is active (BATCH-F1). No-op for CLI/non-job ingest.
    _stamp_provenance(actions)
    return _flush_with_retry(client, actions, attempt=0)


def _flush_with_retry(client: OpenSearch, actions: list[dict], attempt: int) -> tuple[int, int]:
    """Recursive retry with backoff and batch splitting."""
    if not actions:
        return 0, 0

    try:
        success, errors = helpers.bulk(
            client,
            actions,
            max_retries=2,
            raise_on_error=False,
            request_timeout=60,
        )
        failed = len(actions) - success

        # Circuit breaker: detect systemic (cluster-wide) failures and
        # halt ingest if they persist across multiple batches. State is
        # thread-local (Rev 6) so concurrent in-process tools don't
        # cross-halt each other.
        is_sys, sys_reason = _is_systemic_failure(
            success, len(actions), errors if isinstance(errors, list) else None
        )
        if is_sys:
            _set_counter(_get_counter() + 1)
            if _get_counter() >= _CIRCUIT_BREAKER_THRESHOLD:
                raise ShardCapacityExhausted(
                    f"Halting ingest: {_get_counter()} "
                    f"consecutive batches fully rejected. Last reason: "
                    f"{sys_reason[:200]}. Likely cause: cluster shard "
                    f"limit or cluster block. Raise "
                    f"cluster.max_shards_per_node or archive old cases."
                )
        else:
            _set_counter(0)  # reset on partial success

        if failed:
            # Extract first error reason to help diagnose mapping
            # conflicts. Written to stderr AND stored in thread-local
            # state so ingest-status writers can surface it via
            # get_last_bulk_reason() — operators see the cause in the
            # status file, not only in the log.
            reason = ""
            if isinstance(errors, list) and errors:
                first = errors[0]
                if isinstance(first, dict):
                    for action_type in ("index", "create", "update"):
                        info = first.get(action_type, {})
                        if info.get("error"):
                            err = info["error"]
                            reason = (
                                err.get("reason", str(err)) if isinstance(err, dict) else str(err)
                            )
                            break
            msg = f"WARNING: {failed}/{len(actions)} docs failed in bulk batch"
            if reason:
                msg += f" — {reason[:200]}"
                # Preserve the first reason across the ingest run —
                # later batches without failures shouldn't clobber it
                # with "". Only overwrite when this batch has its own
                # non-empty reason.
                _tls.last_bulk_reason = reason[:500]
            print(msg, file=sys.stderr)
        return success, failed

    except (ConnectionTimeout, OSConnectionError):
        if attempt >= _MAX_RETRIES:
            index = actions[0].get("_index", "") if actions else ""
            print(
                f"\n*** DATA LOSS: {len(actions)} events not indexed after "
                f"{_MAX_RETRIES} retries (timeout) — {index} ***\n"
                f"  Recovery: re-run ingest on the same evidence (dedup is safe)\n",
                file=sys.stderr,
            )
            return 0, len(actions)

        # If batch is large enough, split and retry smaller chunks
        if len(actions) > 200 and 3 <= attempt <= 5:  # cap split depth
            mid = len(actions) // 2
            print(
                f"WARNING: Bulk timeout (attempt {attempt + 1}), "
                f"splitting batch {len(actions)} -> 2x{mid}",
                file=sys.stderr,
            )
            s1, f1 = _flush_with_retry(client, actions[:mid], attempt + 1)
            s2, f2 = _flush_with_retry(client, actions[mid:], attempt + 1)
            return s1 + s2, f1 + f2

        wait = min(_INITIAL_BACKOFF * (2**attempt), _MAX_BACKOFF)
        print(
            f"WARNING: Bulk timeout (attempt {attempt + 1}/{_MAX_RETRIES}), "
            f"retrying {len(actions)} docs in {wait}s...",
            file=sys.stderr,
        )
        time.sleep(wait)
        return _flush_with_retry(client, actions, attempt + 1)

    except TransportError as e:
        if attempt >= _MAX_RETRIES:
            index = actions[0].get("_index", "") if actions else ""
            print(
                f"\n*** DATA LOSS: {len(actions)} events not indexed after "
                f"{_MAX_RETRIES} retries ({e}) — {index} ***\n"
                f"  Recovery: re-run ingest on the same evidence (dedup is safe)\n",
                file=sys.stderr,
            )
            return 0, len(actions)

        wait = min(_INITIAL_BACKOFF * (2**attempt), _MAX_BACKOFF)
        print(
            f"WARNING: Bulk error ({e}), retrying in {wait}s...",
            file=sys.stderr,
        )
        time.sleep(wait)
        return _flush_with_retry(client, actions, attempt + 1)
