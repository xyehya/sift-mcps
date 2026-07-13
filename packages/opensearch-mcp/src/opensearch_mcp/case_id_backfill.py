"""Operator-only migration for the derived ``sift.case_id`` keyword field.

This module is deliberately not an MCP tool.  The Gateway remains the policy
boundary for agent requests; this is a measured maintenance operation over
derived OpenSearch indices.  It plans by default and mutates only with
``--apply``.  An incompatible historical field type is reported without writes
so an operator can rebuild that derived index from its authoritative evidence.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

from opensearch_mcp.client import get_client
from opensearch_mcp.paths import build_index_pattern, normalize_case_key

_CASE_ID_FIELD = "sift.case_id"
_SAFE_CASE_KEY = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}$")
_BACKFILL_SCRIPT = "ctx._source['sift.case_id'] = params.case_id"


def _mapping_type(properties: dict[str, Any]) -> str | None:
    """Return the field type for flat or nested OpenSearch mapping forms."""
    direct = properties.get(_CASE_ID_FIELD)
    if isinstance(direct, dict) and isinstance(direct.get("type"), str):
        return str(direct["type"])
    nested = properties.get("sift")
    if isinstance(nested, dict):
        nested_props = nested.get("properties")
        if isinstance(nested_props, dict):
            field = nested_props.get("case_id")
            if isinstance(field, dict) and isinstance(field.get("type"), str):
                return str(field["type"])
    return None


def _term_count(client: Any, index: str, case_key: str) -> int:
    result = client.count(index=index, body={"query": {"term": {_CASE_ID_FIELD: case_key}}})
    return int(result.get("count", 0))


def plan_or_apply_case_id_backfill(
    client: Any, case_key: str, *, apply: bool = False
) -> dict[str, Any]:
    """Plan or apply a measured case-ID backfill for one case-index family.

    Missing fields are added as keyword mappings and every document is stamped
    from the case key encoded by the trusted maintenance invocation.  Existing
    non-keyword mappings are not changed in place: OpenSearch cannot safely
    change a field type, so the result fails closed with the exact derived
    indices to rebuild/re-ingest.
    """
    case_key = normalize_case_key(case_key)
    if not _SAFE_CASE_KEY.fullmatch(case_key):
        raise ValueError("case_key must contain only lowercase letters, digits, dots, underscores, or hyphens")

    pattern = build_index_pattern(case_key)
    mappings = client.indices.get_mapping(index=pattern, allow_no_indices=True) or {}
    plans: list[dict[str, Any]] = []
    incompatible: list[str] = []

    for index, body in sorted(mappings.items()):
        props = body.get("mappings", {}).get("properties", {})
        field_type = _mapping_type(props if isinstance(props, dict) else {})
        before_count = int(client.count(index=index, body={"query": {"match_all": {}}}).get("count", 0))
        plan = {"index": index, "mapping_type": field_type, "before_count": before_count}
        if field_type not in (None, "keyword"):
            plan["status"] = "requires_reindex"
            incompatible.append(index)
        else:
            plan["status"] = "ready"
        plans.append(plan)

    result: dict[str, Any] = {
        "case_key": case_key,
        "index_pattern": pattern,
        "apply": apply,
        "indices": plans,
        "rollback": "OpenSearch is derived: rebuild an affected index from authoritative evidence if rollback is needed.",
    }
    if incompatible:
        result["status"] = "requires_reindex"
        result["incompatible_indices"] = incompatible
        return result
    if not apply:
        result["status"] = "planned"
        return result

    for plan in plans:
        index = str(plan["index"])
        if plan["mapping_type"] is None:
            client.indices.put_mapping(
                index=index,
                body={"properties": {_CASE_ID_FIELD: {"type": "keyword", "ignore_above": 1024}}},
            )
        update = client.update_by_query(
            index=index,
            body={
                "query": {"match_all": {}},
                "script": {
                    "lang": "painless",
                    "source": _BACKFILL_SCRIPT,
                    "params": {"case_id": case_key},
                },
            },
            conflicts="proceed",
            refresh=True,
        )
        plan["updated"] = int(update.get("updated", 0))
        plan["term_count"] = _term_count(client, index, case_key)
        plan["status"] = (
            "migrated" if plan["term_count"] == plan["before_count"] else "count_mismatch"
        )

    mismatched = [str(plan["index"]) for plan in plans if plan["status"] == "count_mismatch"]
    result["status"] = "count_mismatch" if mismatched else "migrated"
    if mismatched:
        result["mismatched_indices"] = mismatched
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_key", help="Case directory key, not the opaque database UUID")
    parser.add_argument("--apply", action="store_true", help="Apply mapping and document backfill")
    args = parser.parse_args(argv)
    result = plan_or_apply_case_id_backfill(get_client(), args.case_key, apply=args.apply)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"planned", "migrated"} else 2


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
