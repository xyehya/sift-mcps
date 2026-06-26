"""Static conformance guard: no cross-case OpenSearch reads in the backend.

Why this exists
---------------
The ``opensearch-mcp`` backend enforces active-case isolation by deriving every
index target from the *active-case index prefix* (``case-{key}-*``, built via
:func:`opensearch_mcp.server.build_index_pattern` / the chokepoint helpers in
:mod:`opensearch_mcp.case_scoped`). The historical failure mode — and the source
of a real cross-case count leak — was a tool that issued an OpenSearch read
against the *all-cases* glob ``case-*`` (e.g. ``client.count(index="case-*-hayabusa-*")``
counted Hayabusa alerts across **every** case), or swept a cluster-wide Security
Analytics plugin endpoint that takes no index scoping at all. That leak lived in
``opensearch_list_detections``, which has since been removed.

This guard statically scans the backend source (no OpenSearch needed) for the two
shapes that re-introduce a cross-case read, and fails CI if a new one appears:

  1. A ``client.count(...)`` / ``client.search(...)`` / ``client.cat.indices(...)``
     call whose ``index=`` argument is a **string literal** (or f-string) that
     begins with the all-cases glob ``case-*`` (rather than an active-prefix
     *variable* such as ``build_index_pattern(case_id)``). A literal ``case-*`` is
     the smell — the active-case pattern is always ``case-{key}-*`` and is built
     at runtime, never written as a ``case-*`` literal.

  2. A ``...transport.perform_request(...)`` to a cluster-wide Security Analytics
     plugin endpoint (``/_plugins/_security_analytics/...``), which returns
     case-bearing data but accepts no per-case index target.

Allowlist
---------
Each flagged call-site is matched against :data:`ALLOWLIST` (keyed by the
enclosing function name + call kind + the literal prefix). The set of flagged
sites MUST equal the allowlist exactly — a NEW cross-case site fails the test,
and removing an allowlisted one (without updating the allowlist) also fails, so
the allowlist cannot silently rot.

After the removal of ``opensearch_list_detections`` and its detection resources,
the only remaining flagged site is the pre-existing field-mapping catalog
resource, which reads index *metadata* (a schema/field dictionary), not case
documents — see its allowlist entry for the rationale and the Phase-2 follow-up.
The data-bearing leak class (``count``/``search`` over ``case-*`` and the SA
plugin sweeps) is now EMPTY.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "opensearch_mcp"
_SCANNED_FILES = ("server.py", "registry.py")

_CROSS_CASE_GLOB = "case-*"
_SA_PLUGIN_PREFIX = "/_plugins/_security_analytics/"
_INDEX_CALL_ATTRS = {"count", "search"}  # client.<attr>(index=...)


# A flagged call-site is identified by (enclosing_function, kind, literal_prefix)
# so the allowlist survives line-number churn.
#
# The ONLY allowlisted site is the field-mapping catalog resource. It calls
# `cat.indices(index="case-*-{artifact}-*", h="index")` to sample the first
# matching index purely to read its field MAPPING (a deployment-uniform schema
# dictionary), and returns field names — never case documents or per-case counts.
# It is NOT a data read. Tightening it to the active-case prefix is a Phase-2
# follow-up (see opensearch_mcp.case_scoped). It is allowlisted, not ignored, so
# any *additional* cross-case site still fails this guard.
ALLOWLIST: set[tuple[str, str, str]] = {
    ("opensearch_field_catalog_resource", "cat.indices", "case-*-"),
}


def _leading_str_literal(node: ast.expr | None) -> str | None:
    """Return the leading string-literal value of a Constant or f-string, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # f-string
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                return part.value
            # A leading FormattedValue means the string does not start with a
            # literal prefix we can vet — treat as non-literal.
            return None
    return None


def _index_kwarg(call: ast.Call) -> str | None:
    for kw in call.keywords:
        if kw.arg == "index":
            return _leading_str_literal(kw.value)
    return None


def _call_kind(call: ast.Call) -> str | None:
    """Classify a Call node as one of the index-targeting / plugin shapes, else None."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr in _INDEX_CALL_ATTRS:
        return func.attr
    # `*.cat.indices(...)`
    if (
        func.attr == "indices"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "cat"
    ):
        return "cat.indices"
    if func.attr == "perform_request":
        return "perform_request"
    return None


def _collect_flagged() -> set[tuple[str, str, str]]:
    flagged: set[tuple[str, str, str]] = set()
    for fname in _SCANNED_FILES:
        tree = ast.parse((_SRC / fname).read_text(encoding="utf-8"), filename=fname)
        _walk(tree, enclosing="<module>", flagged=flagged)
    return flagged


def _walk(node: ast.AST, enclosing: str, flagged: set[tuple[str, str, str]]) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _walk(child, enclosing=child.name, flagged=flagged)
            continue
        if isinstance(child, ast.Call):
            kind = _call_kind(child)
            if kind == "perform_request":
                for arg in (*child.args, *(kw.value for kw in child.keywords)):
                    lit = _leading_str_literal(arg)
                    if lit and lit.startswith(_SA_PLUGIN_PREFIX):
                        flagged.add((enclosing, kind, _SA_PLUGIN_PREFIX))
            elif kind in {"count", "search", "cat.indices"}:
                idx = _index_kwarg(child)
                if idx and idx.startswith(_CROSS_CASE_GLOB):
                    flagged.add((enclosing, kind, idx))
        _walk(child, enclosing=enclosing, flagged=flagged)


def test_no_unexpected_cross_case_opensearch_calls() -> None:
    flagged = _collect_flagged()
    unexpected = flagged - ALLOWLIST
    assert not unexpected, (
        "New cross-case OpenSearch call-site(s) detected (index='case-*...' on "
        "count/search/cat.indices, or a cluster-wide Security Analytics plugin "
        f"sweep). Scope to the active-case prefix instead: {sorted(unexpected)}"
    )
    stale = ALLOWLIST - flagged
    assert not stale, (
        f"ALLOWLIST entries no longer present in source (remove them): {sorted(stale)}"
    )


def test_no_data_bearing_cross_case_reads() -> None:
    """The data-exfil leak class (count/search over case-* + SA plugin sweeps) is EMPTY.

    cat.indices reads index *names*/mappings (metadata), so it is excluded here;
    document-bearing reads must never target all cases.
    """
    data_leaks = {
        site
        for site in _collect_flagged()
        if site[1] in {"count", "search", "perform_request"}
    }
    assert not data_leaks, (
        f"Data-bearing cross-case OpenSearch read(s) detected: {sorted(data_leaks)}"
    )
