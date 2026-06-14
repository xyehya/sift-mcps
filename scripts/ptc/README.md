# PTC — Programmatic Tool Calling (host-side) for the SIFT gateway

**What:** a local bridge that lets the agent script multiple gateway MCP tool calls
**in this terminal** (not in the `run_command` jail), filter/correlate the results on
local disk, and pull only a slim summary into context. The bulk never enters the
agent's context window.

**Why:** measured on the live Rocba case (2.08M docs) —
- `opensearch_search` limit=200 → **256 KB on disk, ~10 lines in context** (~99% cut).
- 2-query IOC pivot across the whole case → ~19K hits processed, ~10-line correlation.

This is the answer to the "10% signal / 90% spam" tool-response problem: don't slim the
MCP response on the wire — script the calls locally and keep raw bulk on disk.

## How it works (the bridge — proven, mirrors `scripts/phase2_gate_test.py`)
- `ptc.py` reads the **live** gateway endpoint + bearer token from `~/.claude.json`
  (`projects/<repo>/mcpServers/siftgateway`), falling back to `.mcp.json`. The token is
  the session's own; it is **read at call time, never written out or printed**.
- TLS is **verified against the gateway CA** (`scripts/ptc/ca-cert.pem`, fetched once from
  the VM `/var/lib/sift/.sift/tls/ca-cert.pem`). `PTC_INSECURE_TLS=1` is a lab-only escape.
- MCP-over-HTTPS: `initialize` → `Mcp-Session-Id` → `notifications/initialized` →
  `tools/call`. Multi-block results (payload + `case_context` envelope) are parsed; full
  payload saved under `scripts/ptc/out/<tool>_<ts>_<seq>.json`.
- The gateway stays the policy boundary — PTC does NOT bypass auth, the evidence gate, or
  re-auth. Mutations (record_finding etc.) go through the same gateway checks.

## Usage
```bash
# one call (saves full result, prints summary)
python3 scripts/ptc/ptc.py call opensearch_search '{"query":"event.code:4625","limit":200}'
python3 scripts/ptc/ptc.py tools            # list tool names
```
```python
import sys; sys.path.insert(0, "scripts/ptc")
from ptc import MCP
m = MCP()
r = m.call("opensearch_search", {"query": "event.code:4624", "limit": 200})  # full hits → disk
# r["_ptc_saved"] is the local path; jq/python it locally, print only the slim result
```

## Proven patterns (recipe seeds)
1. **Big query → save → `jq` filter.** Pull up to 200 hits (even `compact=false` full docs,
   since bulk lands on disk), then `jq` group/aggregate locally. e.g. logon-type x outcome.
2. **Multi-query correlation.** Several `opensearch_search`/`aggregate` calls → join on disk.
   e.g. pivot N IOCs across the case → cross-artifact footprint (`set(A.indices) & set(B.indices)`).

## Next: recipe library + how-to skill
Turn the patterns into a few parametrized recipes (`recipes/*.py`) — IOC pivot, logon
correlation, timeline-to-events drill, aggregate-then-fetch — and wrap them in a how-to
skill so any agent session invokes them via Bash. See `docs/optimization/tool-audit-2026-06-14.md`
for the parallel response-efficiency/schema fixes that further slim the on-wire responses.
