#!/usr/bin/env python3
"""PTC recipe: pivot N IOCs across the whole case → cross-artifact footprint.

For each indicator (IP, hash, domain, username, filename...) runs one
opensearch_search across all case indices, saves the full hits to local disk, and
reports which artifact families mention it + how many — then the artifacts where
ALL indicators co-occur. Bulk stays on disk; only the footprint enters context.

Usage:
  python3 scripts/ptc/recipes/ioc_pivot.py 81.30.144.115 213.202.233.104
  python3 scripts/ptc/recipes/ioc_pivot.py --limit 200 evil.exe a1b2c3...
"""
from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ptc import MCP, family  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("iocs", nargs="+", help="indicators to pivot (IP/hash/domain/user/file)")
    ap.add_argument("--limit", type=int, default=200, help="hits per IOC (max 200)")
    args = ap.parse_args()

    m = MCP()
    foot: dict[str, dict] = {}
    for ioc in args.iocs:
        r = m.call("opensearch_search", {"query": f'"{ioc}"', "limit": args.limit})
        if not isinstance(r, dict) or "results" not in r:
            print(f"  {ioc}: ERROR {str(r)[:120]}")
            continue
        by = collections.Counter(family(h.get("index", "")) for h in r["results"])
        foot[ioc] = {"total": r.get("total"), "returned": r.get("returned"),
                     "by_artifact": dict(by.most_common()), "saved": r.get("_ptc_saved")}

    print("=== IOC cross-artifact footprint ===")
    for ioc, f in foot.items():
        print(f"  {ioc}: total={f['total']} returned={f['returned']}  ({f['saved']})")
        for art, n in list(f["by_artifact"].items())[:8]:
            print(f"      {n:>5}  {art}")
    if len(foot) > 1:
        shared = set.intersection(*[set(f["by_artifact"]) for f in foot.values()])
        print("  >> artifacts where ALL indicators co-occur:", sorted(shared) or "(none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
