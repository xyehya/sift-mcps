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

``sift.case_id`` term-filter (DEFERRED — see :func:`case_id_term_filter`)
------------------------------------------------------------------------
A ``{"term": {"sift.case_id": <case_id>}}`` query clause would be a useful
belt-and-suspenders filter ON TOP of the index-prefix boundary. It is NOT wired
in Phase 1 because the field is not safe to filter on yet: ``sift.case_id`` is
stamped opportunistically by the ingest provenance channel (``bulk.py``) but is
NOT declared in any index mapping template under ``mappings/`` (its siblings
``sift.source_file``/``sift.ingest_audit_id`` ARE), so it falls to dynamic
mapping and is not guaranteed to be a ``keyword`` a ``term`` query would match.
Adding the clause today would be inert-or-incorrect. Closing this needs a mapping
migration declaring ``sift.case_id: keyword`` + a backfill, tracked as Phase 2.
The index-prefix boundary is the enforced isolation primitive in the meantime.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


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


def case_id_term_filter(case_id: str) -> dict[str, Any] | None:  # noqa: ARG001
    """DEFERRED defense-in-depth ``sift.case_id`` term clause — returns ``None``.

    Intentionally a no-op in Phase 1. See the module docstring: ``sift.case_id``
    is not declared ``keyword`` in any mapping template, so a ``term`` filter on
    it is not guaranteed to match and must not be relied on for isolation. This
    stub marks the single place to wire the clause once a mapping migration lands
    (Phase 2); until then the index-prefix boundary is the enforced primitive.
    """
    return None
