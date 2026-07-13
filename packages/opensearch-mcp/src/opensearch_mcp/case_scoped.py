"""Backend case-scoped OpenSearch read chokepoint (Phase 1).

Single, cohesive place that enforces the active-case *index-prefix* isolation
boundary for OpenSearch reads inside the ``opensearch-mcp`` backend. The intent
is that every tool that fans out across indices funnels its index targeting and
its result post-filtering through these helpers, so a cross-case read cannot be
introduced by accident (a future tool that calls ``client.count(index="case-*")``
or sweeps a cluster-wide plugin endpoint is the failure mode this closes).

Where authority lives (do NOT re-implement authorization here)
--------------------------------------------------------------
Authorization is the Gateway's job, not the backend's. The Gateway resolves the
DB-authoritative active case per principal (security-model gates ④ CaseContext /
⑥ ProxyActiveCase) and INJECTS ``case_id``/``case_dir`` into the tool call. This
backend has no user identity and no DB creds, so "the active case" here is
exactly those injected values, and the isolation primitive is the derived index
name ``case-{key}-*``. These helpers operate on the already-resolved prefix; they
do NOT make access decisions about *which* case the caller may see — that already
happened upstream (security-model boundary #5, data-plane scoping).

Fail-closed contract
--------------------
When the active-case prefix cannot be resolved (no active case in this call's
context), :func:`resolve_active_case_prefix` returns ``None`` and the caller MUST
return an empty / zero result — NEVER a cluster-wide one. This mirrors SEC-7
``opensearch_status``/``opensearch_shard_status`` (empty index list with no
active case rather than enumerating every case).

``sift.case_id`` term-filter (defense in depth)
------------------------------------------------
A ``{"term": {"sift.case_id": <case-key>}}`` clause is applied on top of the
index-prefix boundary for every case-scoped query.  The field is stamped by the
ingest provenance channel and declared as a ``keyword`` by the shared case
metadata component template.  ``case_id`` supplied by the Gateway is an opaque
database UUID, whereas the index and ingest value use the case-directory key, so
the helper resolves that key from the injected active-case directory.  It must
never compare the UUID to the derived field.

Existing indices are handled by the operator-only ``case_id_backfill`` module.
The prefix remains the authorization/isolation primitive; this clause is a
derived-data consistency check and must not be repurposed as authorization.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from opensearch_mcp.paths import build_index_pattern

_UUID_CASE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def resolve_active_case_prefix(case_id: str = "", case_dir: str = "") -> str | None:
    """Resolve the active-case index prefix ``case-{key}-`` (or ``None``).

    Thin single-entry wrapper over the SEC-7 resolver so every case-scoped tool
    has one chokepoint to call. The lazy import avoids a circular import with
    :mod:`opensearch_mcp.server` (which imports this module). Returns ``None``
    when no active case resolves in this call's context — the caller MUST fail
    closed (return empty), never fall back to a cluster-wide query.
    """
    from opensearch_mcp.server import _resolve_active_prefix

    return _resolve_active_prefix(case_id, case_dir)


def active_case_index_pattern(prefix: str) -> str:
    """The active case's index glob, e.g. ``case-foo-*``.

    Use this in place of any ``case-*`` (all-cases) target.
    """
    return f"{prefix}*"


def resolve_query_index(
    index: str,
    case_id: str,
    *,
    active_case_key: str,
) -> str:
    """Resolve a query target without bypassing the case-scoped chokepoint.

    The Gateway normally injects an opaque database UUID as ``case_id`` and an
    active-case directory that the backend has already reduced to
    ``active_case_key``.  The UUID is deliberately not made into an index name;
    a standalone caller may still provide a case key.  Callers must pair this
    with :func:`validate_query_index` before OpenSearch I/O.
    """
    if index:
        return index
    case_key = case_id.strip()
    if _UUID_CASE_ID_RE.fullmatch(case_key):
        case_key = ""
    if not case_key:
        case_key = active_case_key.strip()
    return build_index_pattern(case_key) if case_key else "case-*"


def validate_query_index(index: str, *, active_prefix: str | None) -> str | None:
    """Reject an empty, broad, system, or foreign-case query target.

    With Gateway-injected active-case context, every comma-separated segment
    must begin with that exact prefix.  Without it, preserve the standalone
    compatibility floor that permits only ``case-`` targets; the Gateway still
    owns authorization and complete active-case binding for agent calls.
    """
    if not index or not index.strip():
        return "Index parameter must not be empty"
    for segment in index.split(","):
        segment = segment.strip()
        if not segment:
            return "Index contains an empty segment (remove stray/leading/trailing commas)"
        if active_prefix is not None:
            if not segment.startswith(active_prefix):
                return (
                    f"Index segment '{segment}' is outside the active case "
                    "(security: cross-case access denied; allowed prefix "
                    f"'{active_prefix}')"
                )
            continue
        if not segment.startswith("case-"):
            return (
                f"Index segment '{segment}' must start with 'case-' "
                "(security: blocks access to system indices)"
            )
    return None


def artifact_index_pattern(prefix: str, artifact: str) -> str:
    """An intra-case artifact-family glob, e.g. ``case-foo-hayabusa-*``.

    Use this in place of any ``case-*-{artifact}-*`` (all-cases) target.
    """
    return f"{prefix}{artifact}-*"


def in_active_case(index: str, prefix: str) -> bool:
    """True iff ``index`` belongs to the active case (``index`` startswith prefix)."""
    return bool(index) and index.startswith(prefix)


def filter_rows_by_index_prefix(
    rows: Iterable[Mapping[str, Any]],
    prefix: str,
    *,
    index_key: str = "index",
) -> list[dict[str, Any]]:
    """Drop any row whose ``index`` is outside the active case.

    The defensive post-filter for results from an inherently cluster-wide source
    (e.g. the Security-Analytics findings API, which takes no index target): keep
    only rows whose ``index_key`` value is within the active-case prefix. A row
    with a missing/blank index is dropped (fail closed — it cannot be proven to
    belong to the active case).
    """
    return [dict(r) for r in rows if in_active_case(str(r.get(index_key, "")), prefix)]


def strip_case_prefix(index: str, prefix: str) -> str:
    """Reduce a full ``case-{key}-evtx-host`` index to its logical tail.

    Returns the active-case-relative logical name (``evtx-host``) so the agent
    sees a name scoped to its own case rather than the embedded case key. Returns
    ``index`` unchanged when it does not carry the prefix (callers post-filter
    first, so this is a defensive no-op).
    """
    return index[len(prefix):] if index.startswith(prefix) else index


def case_id_term_filter(case_id: str = "", case_dir: str = "") -> dict[str, Any] | None:
    """Return the active case-key's keyword term filter, or ``None`` standalone.

    Gateway calls receive the opaque database UUID in ``case_id`` and the
    authoritative case directory in ``case_dir``.  Indexed documents carry the
    directory-derived case key, so resolve the prefix first and extract that key.
    A standalone caller with no resolvable case keeps the existing compatibility
    behavior (no derived term clause); agent calls are always gateway-bound.
    """
    prefix = resolve_active_case_prefix(case_id, case_dir)
    if not prefix or not prefix.startswith("case-") or not prefix.endswith("-"):
        return None
    case_key = prefix.removeprefix("case-").removesuffix("-")
    if not case_key:
        return None
    return {"term": {"sift.case_id": case_key}}


def with_case_id_term_filter(
    query: Mapping[str, Any], case_id: str = "", case_dir: str = ""
) -> dict[str, Any]:
    """Wrap a query with the active case's derived ``sift.case_id`` filter.

    The original query remains in ``must`` so user-supplied query syntax cannot
    escape the generated filter.  Absence of an active case is a standalone-only
    compatibility case; the Gateway supplies authoritative context for agents.
    """
    term_filter = case_id_term_filter(case_id, case_dir)
    if term_filter is None:
        return dict(query)
    return {"bool": {"must": [dict(query)], "filter": [term_filter]}}
