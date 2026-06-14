#!/usr/bin/env python3
"""PTC recipe: find the activity spike, then drill into it.

opensearch_timeline(query, interval) → locate the busiest bucket(s) → fetch events
from the peak window (saved to disk) → print the top buckets + a sample from the peak.
One local pass instead of eyeballing a histogram then re-querying by hand.

Usage:
  python3 scripts/ptc/recipes/timeline_drill.py --query 'event.code:4625'
  python3 scripts/ptc/recipes/timeline_drill.py --query '*' --interval 1d --fetch 20
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ptc import MCP, family  # noqa: E402


def _bucket_time(b: dict) -> str:
    return b.get("time") or b.get("key_as_string") or b.get("timestamp") or str(b.get("key", ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", default="*")
    ap.add_argument("--interval", default="1h", help="Ns/Nm/Nh/Nd")
    ap.add_argument("--fetch", type=int, default=20, help="events to pull from the peak bucket")
    args = ap.parse_args()

    m = MCP()
    tl = m.call("opensearch_timeline", {"query": args.query, "interval": args.interval})
    buckets = tl.get("buckets", []) if isinstance(tl, dict) else []
    nonzero = [b for b in buckets if (b.get("count") or b.get("doc_count") or 0)]
    if not nonzero:
        print(f"  no activity for query={args.query} interval={args.interval}: {str(tl)[:150]}")
        return 1

    def cnt(b: dict) -> int:
        return int(b.get("count") or b.get("doc_count") or 0)

    ranked = sorted(nonzero, key=cnt, reverse=True)
    print(f"=== top activity buckets (query={args.query} interval={args.interval}) ===")
    for b in ranked[:6]:
        print(f"  {cnt(b):>8}  {_bucket_time(b)}")

    peak = ranked[0]
    t = _bucket_time(peak)
    print(f"  >> peak window: {t} ({cnt(peak)} events) — fetching {args.fetch} samples")
    s = m.call("opensearch_search",
               {"query": args.query, "limit": args.fetch, "time_from": t, "sort": "@timestamp:asc"})
    print(f"     saved {s.get('returned')} hits -> {s.get('_ptc_saved')}")
    for h in s.get("results", [])[:5]:
        f = h.get("fields", {})
        print(f"       {f.get('@timestamp','?')}  {family(h.get('index',''))}  code={f.get('event.code','-')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
