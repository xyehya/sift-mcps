---
name: ptc
description: >-
  Programmatic tool calling (PTC) for SIFT forensic investigation. Script multiple
  gateway MCP tool calls from the local bash terminal, save full results to local
  disk, and pull only slim summaries into context — instead of dumping large tool
  responses inline. Use when an investigation needs large opensearch result sets,
  multi-query correlation, IOC pivots across artifacts, aggregate-then-drill, or
  timeline spike analysis, or any time tool output is mostly noise and would flood
  context. Triggers: "correlate", "pivot this IOC", "across artifacts", "big query",
  "save tokens / reduce context", "aggregate then fetch", "find the spike".
---

# PTC — programmatic tool calling for SIFT

The gateway MCP tools return large, spammy payloads (often ~90% boilerplate). Calling
them one-by-one and reading the raw output into context is wasteful and loses the thread
on multi-step correlation. PTC fixes this: a local bridge (`scripts/ptc/ptc.py`) speaks
MCP-over-HTTPS to the same gateway, so you can **chain calls in one bash command, filter
and correlate on local disk, and surface only the answer.**

Measured: a 200-hit `opensearch_search` = ~256 KB on disk but ~10 lines in context
(~99% cut); a 2-IOC cross-artifact pivot over 2M docs = ~10-line correlation.

It runs **in this terminal, not in the run_command jail** — full Python is available, and
the gateway still enforces auth, the evidence gate, and re-auth (PTC is not a bypass).

## When to use PTC vs a direct MCP tool
- Direct MCP tool call: a single small lookup (one count, one event, a 5-hit search).
- PTC: many hits, multiple queries, correlation/aggregation/joins, or pulling `compact=false`
  full docs (safe — bulk lands on disk, not context).

## The bridge (no setup needed if already wired)
`scripts/ptc/ptc.py` reads the live endpoint + bearer token from `~/.claude.json`
(`projects/<repo>/mcpServers/siftgateway`) and verifies TLS against `scripts/ptc/ca-cert.pem`.
If the CA is missing, fetch once:
`scp sansforensics@192.168.122.81:/var/lib/sift/.sift/tls/ca-cert.pem scripts/ptc/ca-cert.pem`

## Quick use
```bash
# any single tool, full result saved to scripts/ptc/out/, summary printed
python3 scripts/ptc/ptc.py call opensearch_search '{"query":"event.code:4625","limit":200}'
python3 scripts/ptc/ptc.py tools         # list tool names
```
Then `jq` / `python3` over the saved `scripts/ptc/out/<tool>_*.json` — never paste the file.

## Recipes (parametrized; compose or copy)
```bash
# 1) pivot N indicators across the whole case -> which artifacts mention each + co-occurrence
python3 scripts/ptc/recipes/ioc_pivot.py 81.30.144.115 213.202.233.104 evil.exe

# 2) scope-then-drill: distribution of a field, then sample events for the top values
python3 scripts/ptc/recipes/aggregate_then_fetch.py --field event.code --top 5 --samples 3
python3 scripts/ptc/recipes/aggregate_then_fetch.py --field winlog.provider_name --query 'event.code:4624'

# 3) find the activity spike, then fetch events from the peak window
python3 scripts/ptc/recipes/timeline_drill.py --query 'event.code:4625' --interval 1d
```

## Writing a new combo (library use)
```python
import sys; sys.path.insert(0, "scripts/ptc")
from ptc import MCP, family
m = MCP()
a = m.call("opensearch_search", {"query": "event.code:4625", "limit": 200, "compact": False})
# a["results"] are full hits; a["_ptc_saved"] is the on-disk path. Filter locally, print only the answer.
```
`m.call(name, args)` returns the parsed payload (and saves the full JSON to `out/`).
`family(index)` reduces a verbose case index name to its artifact family.

## Rules
- Print summaries/counts/correlations, NOT raw saved files.
- Mutations (record_finding, record_timeline_event, opensearch_ingest) still go through the
  gateway policy + re-auth — PTC does not change authority.
- Keep `scripts/ptc/out/` and `ca-cert.pem` local (already gitignored).
- See `docs/optimization/tool-audit-2026-06-14.md` for the response-efficiency/schema findings
  that complement PTC by slimming the summaries that do return.
