# Open-Items Register — Forks (F#) & Backlog (B#)

The single home for open decisions and deferred work, per `OPERATING_MODEL.md` §5.
Append-only; mark status, do not delete. Forks (F#) await an operator call; Backlog
(B#) are accepted-but-deferred work with a do-by phase. Resolved forks point to the
Decision (D#) or Backlog (B#) they became.

Format (LOAD-BEARING — parsed by tooling; see `OPERATING_MODEL.md` §8). Both
registers are GitHub-flavored **markdown tables** with a fixed column order.
Fork rows begin `| F-<n> |` and have exactly 7 columns; backlog rows begin
`| B-<n> |` and have exactly 5. Append new columns only at the end — never
reorder or rename existing ones. Allowed `Status` values: forks `OPEN` |
`RESOLVED`; backlog `OPEN` | `DONE` (bold `**…**` is fine; the validator strips it).

```
| ID  | Question        | Raised          | Status   | Decision (date) | Becomes      | Affects |
| F-n | <question>      | Run <r>, <doc §>| OPEN|RESOLVED | <call + date>  | D-n / B-n / rejected | <D#/doc/snapshot> |

| ID  | Deferred work   | Source          | Status   | Do-by phase |
| B-n | <deferred work> | F-n / Run <r>   | OPEN|DONE | <phase/date> |
```

Run `python3 scripts/validate_migration_docs.py` after editing this file.

---

## Forks (F#)

| ID | Question | Raised | Status | Decision (date) | Becomes | Affects |
| --- | --- | --- | --- | --- | --- | --- |
| F-1 | Model the read-only status/catalog "tools" as MCP **resources**? | Run 18, doc 16 §2/§7 | **RESOLVED** | APPROVED additively (2026-06-07): 4 strong → resources + deprecated tool alias; 2 query-shaped (`opensearch_list_detections`, `opensearch_case_summary`) stay tools + optional resource view | B-1 (alias removal horizon) | D27b `ResourcesAsTools`, golden snapshot |
| F-2 | Legacy wintriage dispatch aliases — formalize or drop? | Run 18, doc 16 §6/§7 | **RESOLVED** | KEEP as deprecated aliases one cycle (2026-06-07); grep found `analyze_filename` referenced in a `forensic-knowledge` playbook + `tool_metadata.py`, so drop would break a skill | B-2 (removal + playbook update) | wintriage surface, golden snapshot |
| F-3 | Must the gateway response-guard scan `structured_content`, not just text? | Run 18, doc 16 §1.1/§7 | **RESOLVED** | REQUIRED — security (2026-06-07); text-only scanning of typed output is a redaction bypass | B-3 (D27b gate + `/security-review`) | D27b, response_guard |
| F-4 | `opensearch_timeline` bucket ceiling value + truncate vs warn? | Run 18, doc 16 §3.5/§7 | **RESOLVED** | ADD cap ~2000, configurable; **warn, never silently truncate** (2026-06-07) | (implemented in D27a) | opensearch_timeline contract |
| F-5 | `opensearch_ingest.password` redaction? | Run 18, doc 16 §3.11/§7 | **RESOLVED** | REDACT in audit/logs/`ToolResult` (2026-06-07, mandatory) | B-4 (credential-as-arg redesign) | response_guard, audit, ingest contract |
| F-6 | Does FastMCP `Middleware.on_call_tool` wrap proxied (ProxyProvider) add-on tools so evidence gate + response guard + audit cover them identically to in-process tools? | Run 22, doc 17 §9 | **RESOLVED** | YES (2026-06-07, grounded vs fastmcp 3.4.2 docs): "parent middleware runs for all requests, including those routed to mounted servers"; `create_proxy()` is a mount; per-session visibility/auth/transforms applied by the server layer after the proxy cache; parent sees+mutates the proxy's `ToolResult`. 2 caveats carried: **(a)** middleware/session state does NOT cross the mount boundary (active-case propagation must use the args/result path or a shared `session_state_store`, not parent `ctx.set_state`) → **B-11**; **(b)** byte-exact `structured_content`/`meta` pass-through through the proxy has no verbatim doc guarantee → assert in an in-memory proxy test at Build. | (design confirmed) / B-11 | D27b policy_middleware, parity suite |
| F-7 | Drop the per-backend `/mcp/{name}` MCP routes at D27b? | Run 22, doc 17 §1/§9 | **RESOLVED** | DROP completely (2026-06-07, operator): they run no evidence gate + no response guard = live policy bypass; no client uses a per-backend path. Reflected in **D3** (firmed). | D3 (firmed) / D27b cutover | D3, server.py, mcp_endpoint.py |
| F-8 | Adopt FastAPI now for D27b, or keep Starlette until the D26 identity phase? | Run 22, doc 17 §9 | **RESOLVED** | ADOPT FastAPI now (2026-06-07, operator): one FastAPI app is also the entry point for the React operator portal/dashboard (REST + MCP under one ASGI app) — bring it in now for efficiency (honors D24). Sub F-8b: keep the raw-ASGI `MCPAuthASGIApp` hash-only token auth around the MCP mount (SSE-safe). | D24 (confirmed) / D27b | D24, D26, server.py, portal |
| F-9 | Are per-case/per-phase/per-role `Visibility` + `ToolSearch` in the D27b parity PR or a deferred additive follow-up? | Run 22, doc 17 §9 | **RESOLVED** | DROP per-case/per-phase/per-role tool exposure entirely (2026-06-07, operator) — not pursued. The one capability worth having is **per-agent-token tool authorization** (restrict which tools a generated AI-agent MCP token may call, for benchmarking/testing tool updates) → **B-10**. | B-10 (per-token tool-scope authz) | D24, token_registry, transforms |
| F-10 | `forensic-mcp` fate at the cutover — proxied backend, LocalProvider, or retired? | Run 22, doc 17 §9 | **RESOLVED** | RETIRED (2026-06-07, operator): `forensic-mcp` stays in `_RETIRED_CORE_BACKENDS`; its tools/capabilities are **core** (in-process `LocalProvider`), no proxy entry. | (folded into core) | server.py, doc 14 §7 |
| F-11 | D27b reads add-ons from `gateway.yaml` (the D22 `mcp_backends` table is unbuilt) — confirm that is in scope, not a silent dependency? | Run 22, doc 17 §9 | OPEN | (operator: tackle on a separate run — keep `gateway.yaml` for now; re-point to `mcp_backends` when that phase lands) | D27b scope | D22, backends config |
| F-12 | REST `/api/v1/tools` response-guard asymmetry — preserve (humans get un-redacted output) or extend B-3 redaction to REST? | Run 22, doc 17 §9 | **RESOLVED** | KEEP AS IS (2026-06-07, operator): no redaction for human/examiner output; freeze the asymmetry in a parity test. The response guard remains an agent-facing leak/bloat control only. | D27b parity (frozen) | response_guard, rest.py |

## Backlog (B#)

| ID | Deferred work | Source | Status | Do-by phase |
| --- | --- | --- | --- | --- |
| B-1 | Remove the tool-form aliases of the reclassified resources (`opensearch_status`, `opensearch_shard_status`, `cti_get_health`, `wintriage_server_status`) once skills/RAG are updated to the resource URIs. | F-1 | OPEN | at/after D27b |
| B-2 | Remove the 10 legacy wintriage dispatch aliases after one cutover cycle; first update the `forensic-knowledge` playbook (`suspicious_execution.yaml`) and `tool_metadata.py` reference to `analyze_filename` → `wintriage_check_artifact(type='filename')`. | F-2 | OPEN | one cycle after D27a |
| B-3 | Gateway response-guard must scan `ToolResult.structured_content` (size cap + secret redaction), not only text. Hard acceptance-gate + `/security-review` at the gateway cutover. **Design: doc 17 §5** (single `guard_tool_result`; redact both `content` and `structured_content` — they are coupled in FastMCP ToolResult). | F-3 | OPEN | D27b |
| B-4 | Replace `opensearch_ingest.password` (and any credential-as-tool-arg) with a reference to a named control-plane credential, so secrets never transit the tool-call/audit path. | F-5 | OPEN | auth/jobs phase |
| B-5 | `opensearch_case_detections_resource` ignores its `case_id` path param (returns active-case detections regardless; D4 single-active-case masks the gap). Scope the query by `case_id` or drop the path parameter so the URI does not promise scoping it cannot deliver. | Run 21 (D27a review, S2) | OPEN | D27b |
| B-6 | Consolidate the per-registry duplicate `ToolResult` envelope builders (opensearch `_success_tool_result`/`_success_result`; wintriage's four builders) into one, so the B-3 `structured_content` redaction and any `ResultMeta` change apply at a single point instead of 2–4 drift-prone copies. **At the gateway: doc 17 §5 folds this into one `guard_tool_result` redaction point.** | Run 21 (D27a review) | OPEN | D27b |
| B-7 | OpenSearch `ResultMeta` only populates `audit_id`; bring it to parity with opencti/wintriage (`examiner`, `caveats`, `interpretation_constraint`, `audit_warning`) or document the divergence — clients relying on those fields get nulls from every OpenSearch tool today. | Run 21 (D27a review) | OPEN | D27b |
| B-8 | Dedupe the two byte-identical opensearch resources under different URIs (`opensearch://cluster/status` vs `opensearch://catalog/indices`); each is a full cluster-health + cat.indices round-trip, so they double I/O and will drift. | Run 21 (D27a review) | OPEN | at/after D27b |
| B-9 | D27a robustness nits: `opensearch_get_event`/`shard_status` error-code substring heuristic (`'not' in type(exc).__name__`); wintriage generic `except` returns an unaudited `ResultMeta()`; `_redact_secret_fields` exact-key-match misses `SIFT_ARCHIVE_PASSWORD`-style names (no live leak — legacy audit curates params and never logs the password); per-call `inspect.signature` recomputation on the tool/resource hot path. | Run 21 (D27a review) | OPEN | D27b/hardening |
| B-10 | Per-agent-token **tool authorization**: let a generated AI-agent MCP token restrict *which tools* it may list/call (for benchmarking and testing tool updates against a controlled subset). Infra partly exists — `app.mcp_token_scopes` + `Identity.tool_scopes` are populated but agent tokens default to `mcp:*` and per-tool scope is **not enforced** at the call boundary today. Decide the scope grammar (e.g. `tool:<name>`, `namespace:<ns>`) and enforce **SIFT-side** in the gateway `on_call_tool` middleware (reject before `call_next`) AND filter `on_list_tools` (list/exec consistency) — keep it SIFT-owned per D24, do not delegate to FastMCP `require_scopes`. Grounding (Run 22) confirms FastMCP natively supports this; we mirror it in SIFT policy. | F-9 / Run 22 | OPEN | auth/jobs phase (after D27b) |
| B-11 | Active-case propagation across the mount boundary: FastMCP parent middleware/session state does **not** cross into mounted/proxied servers (grounded Run 22, F-6). The evidence-gate/case-context middleware must pass active-case to proxied backends via the call arguments/result path or a shared `session_state_store`/env, not parent `ctx.set_state`. Verify proxied backends receive the active case correctly. | F-6 / Run 22 | OPEN | D27b |

---

## Notes
- Earlier project-level findings (e.g. the Rocba/run_command hardening items) live in
  their own session logs and memory; this register tracks the **migration** forks/backlog.
- When a B# is completed, mark **DONE** with the commit/Run that closed it; do not delete.
