#!/usr/bin/env python3
"""PTC recipe: scope-then-drill. Aggregate a field, then fetch sample events for
the top-N values — one local pass instead of N context-dumping round-trips.

opensearch_aggregate(field) → top-N buckets → for each, opensearch_search(field:value)
for a few sample hits, saved to disk. Prints the distribution + sample _id/index per
value so you can opensearch_get_event or jq the saved files next.

Usage:
  python3 scripts/ptc/recipes/aggregate_then_fetch.py --field event.code
  python3 scripts/ptc/recipes/aggregate_then_fetch.py --field winlog.provider_name \
      --query 'event.code:4624' --top 5 --samples 3
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ptc import MCP, family  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--field", required=True, help="field to aggregate (add .keyword for text fields)")
    ap.add_argument("--query", default="*", help="query_string pre-filter")
    ap.add_argument("--top", type=int, default=5, help="top-N values to drill into")
    ap.add_argument("--samples", type=int, default=3, help="sample events per value")
    args = ap.parse_args()

    m = MCP()
    agg = m.call("opensearch_aggregate", {"field": args.field, "query": args.query, "limit": args.top})
    buckets = agg.get("buckets", []) if isinstance(agg, dict) else []
    if not buckets:
        print(f"  no buckets for field={args.field} query={args.query}: {str(agg)[:150]}")
        return 1

    print(f"=== {args.field} distribution (query={args.query}) ===")
    field = args.field.split(".keyword")[0]
    for b in buckets[:args.top]:
        val = b.get("key")
        cnt = b.get("count")
        # quote string values for query_string
        q = f'{field}:"{val}"' if isinstance(val, str) else f"{field}:{val}"
        full_q = q if args.query == "*" else f"({args.query}) AND {q}"
        s = m.call("opensearch_search", {"query": full_q, "limit": args.samples})
        samples = [(h.get("id"), family(h.get("index", ""))) for h in s.get("results", [])[:args.samples]]
        print(f"  {cnt:>8}  {field}={val}   ({s.get('_ptc_saved')})")
        for sid, idx in samples:
            print(f"             sample _id={sid} index={idx}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
