# 15 — Backend Tooling Revamp (opensearch / opencti / windows-triage → FastMCP 3.0 + tool quality)

Status: **design locked** (decisions D27a/D27b/D28 in `00_migration_charter.md`).
This document is the single source of truth and the drift-control contract for the
dedicated worktree that revamps the three backend MCP servers. The charter stays
canonical; this doc governs the revamp. Runtime code changes happen only in the
worktree, scoped per §8.

This work runs **in parallel with PR02 (Phase ID-2)** and merges **before** the
gateway cutover (D27b). It is decoupled from PR02 because it touches only the
three backend packages (§8) and from the gateway because the gateway↔backend
boundary is the MCP wire protocol, not a Python API.

---

## 1. Why this exists (grounded)

Audit of the current `server.py` in each backend:

| | opensearch | opencti | windows-triage |
| --- | ---: | ---: | ---: |
| tools | 16 | 8 | 6 |
| framework today | in-SDK FastMCP 1.x | low-level `Server` | low-level `Server` |
| **structured/output schemas** | **0** | **0** | **0** |
| **prompts** | **0** | **0** | **0** |
| **resources** | **0** | **0** | **0** |
| **Pydantic input models** | **0** | **0** | **0** |
| **arg-level `Field` descriptions** | **0** | **0** | **0** |
| annotations / hints | 12 | 9 | 7 |
| input schemas | inferred from type hints | hand-written dicts | hand-written dicts |

Diagnosis: the mediocre tool-use performance is **not** a framework-version
problem. Every tool returns untyped blobs, no tool has argument-level
descriptions, and there are zero prompts and zero resources across all three
servers. The 3.0 upgrade is the enabler; the **tool-quality redesign is the
payoff**. A version bump alone fixes almost none of the pain.

Current tool inventory (to be carried forward, possibly renamed per §6):

- **opensearch (16):** `opensearch_search`, `opensearch_count`,
  `opensearch_aggregate`, `opensearch_get_event`, `opensearch_timeline`,
  `opensearch_field_values`, `opensearch_status`, `opensearch_shard_status`,
  `opensearch_case_summary`, `opensearch_inspect_container`, `opensearch_ingest`,
  `opensearch_ingest_status`, `opensearch_enrich_intel`, `opensearch_enrich_triage`,
  `opensearch_list_detections`, `opensearch_host_fix`.
- **opencti (8):** `cti_get_entity`, `cti_get_health`, `cti_get_recent_indicators`,
  `cti_get_relationships`, `cti_lookup_ioc`, `cti_search_entity`,
  `cti_search_reports`, `cti_search_threat_intel`.
- **windows-triage (6):** `wintriage_check_artifact`, `wintriage_check_pipe`,
  `wintriage_check_process_tree`, `wintriage_check_registry`,
  `wintriage_check_system`, `wintriage_server_status`.

---

## 2. Decisions locked by this doc

See `00_migration_charter.md`:
- **D27a** — backend tooling revamp is a standalone, parallel-safe stage (this
  doc), running alongside PR02 and merging before the gateway cutover.
- **D27b** — the gateway cutover is the later stage; it owes **policy parity**
  only (evidence gate / response guard / audit / active-case), and **consumes the
  already-revamped backend tool surface** rather than freezing it.
- **D28** — the tool-quality contract (§5), exposure-agnostic authoring (§7), and
  the rename/change-map mechanism (§6) are mandatory for every revamped tool.

Operator forks resolved for this stage:
- Method: **combined per-tool** (port + redesign in one pass), with the
  reviewability guardrail in §4.
- Names: **renames allowed**, recorded in a change map with aliases (§6).
- Scope: **all three backends**, with opensearch authored exposure-agnostic (§7).

---

## 3. The two parity layers (reconciling D27)

The original D27 parity gate ("tool names/namespaces/schemas byte-stable") is
**split**, because this revamp deliberately changes the tool surface:

| Layer | Owner | Rule |
| --- | --- | --- |
| **Policy parity** | gateway cutover (D27b) | evidence gate, response guard, audit envelope, active-case propagation must be byte-stable across the gateway swap. **Not affected by this revamp.** |
| **Tool surface** | this revamp (D27a) | names/namespaces/schemas/outputs change deliberately. Produces a **new golden snapshot** + a **change map** (§6). The gateway cutover consumes this; it does not re-freeze it. |

---

## 4. Method: combined per-tool, with a reviewability guardrail

The operator chose to port + redesign each tool in one pass (not a two-phase
mechanical-then-semantic split). To keep that reviewable and bisectable:

- **One commit per tool.** Each commit fully revamps a single tool (port +
  schema + output + annotations + description + result shaping) and updates the
  golden snapshot for that tool only. Commit message names the tool and lists
  schema/output/annotation/description/rename changes.
- **Snapshot diff is part of every commit.** The regenerated MCP-surface snapshot
  diff (names, namespaces, input schema, output schema, annotations) must be in
  the commit and reviewed.
- **Prompts/resources land as their own commits** per backend, after that
  backend's tools are done.
- **Tests stay green per commit.** A red commit is not pushed.

This recovers most of the bisectability that a two-phase split would have given,
without the double-touch.

---

## 5. The tool-quality contract (definition of "done" per tool) — D28

Every revamped tool MUST have all of the following. This is the anti-drift
backbone: a tool that does not meet the contract is not "done," and the
acceptance gate (§9) checks it.

1. **Typed Pydantic input model** with `Field(description=…)` on every argument,
   plus constraints (enums, ranges, regex, defaults). Replaces hand-written
   `inputSchema` dicts and type-hint-only inference.
2. **Structured output**: a Pydantic output model returned via `ToolResult`
   (`structured_content`), not a free-text blob. Human-readable `content` may
   accompany it, but the structured payload is authoritative.
3. **Complete annotations**: `readOnlyHint`, `destructiveHint`, `idempotentHint`,
   `openWorldHint`, and a human `title`. (All three backends are read/query-only;
   `readOnlyHint=true`, `destructiveHint=false` unless a tool truly writes.)
4. **Task-oriented description**: what it does, **when to use it** (and when not),
   and one concrete example invocation. This is the single biggest tool-selection
   lever.
5. **Result shaping**: default field projection, pagination/limit params with safe
   caps, and a size ceiling. Especially `opensearch_search`/`_timeline`/
   `_aggregate`, which currently return large untyped payloads.
6. **Error model**: typed, structured errors (code + message + remediation), never
   raw stack traces in tool output.

Per-backend additions (D28):
- At least one **prompt** per backend (reusable investigation template).
- At least one **resource** per backend (reference data exposed read-only).

---

## 6. Renames + change map (operator chose "renames allowed")

Renames are permitted to fix unclear names, but must not silently break existing
agent skills/configs or the gateway snapshot. Mechanism:

- A **change map** file in the worktree: `old_name → new_name` per tool, with a
  one-line reason, kept in sync with the golden snapshot.
- **Aliases + deprecation**: where a tool is renamed, the backend registers the
  old name as a deprecated alias for one cutover cycle (annotation marks it
  deprecated), so existing skills keep working until updated.
- Namespaces (`opensearch_`, `cti_`, `wintriage_`) stay as the per-backend prefix
  (Namespace transform, D24); renames happen within the namespace.
- The change map is an input to the gateway cutover (D27b) and to any RAG/skills
  that reference tool names.

---

## 7. Exposure-agnostic authoring (so opensearch's core move wastes nothing) — D28

Because `opensearch-mcp` becomes core/in-process later (D19) while `opencti`/
`wintriage` stay external (ProxyProvider, D22), author **every** tool so its
exposure is a thin adapter:

```
tool logic           = pure async function(params: InModel) -> OutModel
tool definition      = InModel/OutModel (Pydantic) + annotations + description
registration table   = [ (name, fn, InModel, OutModel, annotations, ...), ... ]
exposure adapter      ├─ standalone:  FastMCP 3.0 server registers the table
                       └─ in-process:  gateway LocalProvider registers the table
```

- The **registration table** is the durable artifact. For opensearch, the
  standalone server shell is throwaway at the core cutover; the table + models +
  logic are reused verbatim by the in-process LocalProvider.
- opencti/wintriage keep the standalone FastMCP 3.0 server (fronted by
  `ProxyProvider`), but use the same table pattern for consistency.

---

## 8. Worktree governance (drift control)

- **Branch:** create the worktree off the **same base commit as PR02** (the
  current integration line) so merges are clean:
  `git worktree add ../sift-mcps-backends revamp/backends-mcp3`.
- **Scope fence (hard):** edits limited to
  `packages/opensearch-mcp/**`, `packages/opencti-mcp/**`,
  `packages/windows-triage-mcp/**`, plus this doc and the change map. **No** edits
  to `sift-gateway`, `supabase/**`, or shared `sift-core`/`sift-common` (additive
  only, and only if unavoidable — flag in MIGRATION_STATE if so). This guarantees
  zero file overlap with PR02.
- **Dependencies:** add `fastmcp>=3` to each backend's `pyproject.toml`; keep
  `mcp` only if still needed transitively. Pin the exact `fastmcp` version and
  record it in MIGRATION_STATE.
- **Merge order:** this worktree merges into the integration line **before** the
  gateway cutover PR (D27b) opens.
- **Canonical references:** charter wins on any conflict; this doc governs the
  revamp; the change map + golden snapshot are the surface of record.

---

## 9. Acceptance gates

**Per tool:** contract §5 fully met (input model, structured output, annotations,
description+example, result shaping, error model); golden snapshot regenerated and
diff reviewed; tests green.

**Per backend:** all tools meet the contract; ≥1 prompt and ≥1 resource added;
the change map covers every rename with an alias; the server starts and a
`list_tools`/`list_prompts`/`list_resources` smoke test passes; the existing
gateway client can still call the backend over the wire (protocol-compat check).

**Per worktree merge:** all three backends pass; full package test suites green;
the consolidated golden snapshot + change map are committed; no out-of-scope files
touched (§8).

---

## 10. Per-backend redesign notes

- **opensearch (16 tools).** Highest leverage. Priorities: structured outputs +
  result shaping on `opensearch_search`/`_timeline`/`_aggregate`/`_field_values`
  (untyped blobs today); typed inputs with `Field` descriptions on query params;
  clear read-vs-write annotations (`_ingest`/`_enrich_*`/`_host_fix` are the
  write/job-enqueuing ones — annotate `readOnlyHint=false` and align with the D5
  job model). Prompts: e.g. `triage_host`, `build_timeline`, `ioc_sweep`.
  Resources: index catalog (`case-*` indices + doc counts), field/mapping
  dictionary, detection-rule catalog. Author exposure-agnostic (§7).
- **opencti (8 tools).** Query-only API client (D20). Structured outputs for
  entities/indicators/relationships; typed IOC inputs with validation
  (hash/ip/domain enums). Prompt: e.g. `enrich_ioc` (lookup + relationships +
  reports). Resource: connector/feed catalog (MITRE, CVE) and entity-type
  reference.
- **windows-triage (6 tools).** Minimal baseline-DB add-on (D23). Structured
  outputs for artifact/registry/process-tree checks; typed inputs. Prompt: e.g.
  `triage_process_tree` / `baseline_compare`. Resource: baseline-DB catalog +
  summaries (known-good services/pipes/registry).

---

## 11. Risks / open items

- **Wire-protocol compatibility** with the current gateway client must be
  verified per backend (stdio + streamable-HTTP), since the gateway is still on
  the low-level SDK until D27b.
- **Structured output + the gateway response guard:** confirm the response
  guard's secret-redaction and size-cap still apply correctly to
  `structured_content` (not just text) at the gateway. Flag for the D27b cutover.
- **Alias lifetime:** decide how long deprecated old names live (one cutover cycle
  proposed); RAG/skills referencing tool names must be updated from the change map.
- **opensearch write tools vs job model:** `_ingest`/`_enrich_*`/`_host_fix`
  intersect the D5 durable-job model; keep their revamp behavior-compatible now
  and let the jobs phase reshape execution later.

---

## 12. Ready-to-copy worktree coding prompt

> You are implementing the backend tooling revamp in a dedicated worktree. Read
> `docs/migration/15_backend_tooling_revamp.md` (this doc) and
> `00_migration_charter.md` "Confirmed Decisions" (D19, D22, D24, D27a/b, D28)
> first. Scope is strictly `packages/{opensearch,opencti,windows-triage}-mcp/**`
> plus the change map — never touch `sift-gateway`, `supabase/**`, or shared
> packages (§8). Migrate each backend to FastMCP 3.0 and revamp each tool to meet
> the tool-quality contract (§5): typed Pydantic input model with `Field`
> descriptions, structured `ToolResult` output model, complete annotations,
> task-oriented description with a when-to-use note and example, result shaping
> (projection/pagination/caps), and a typed error model. Author tools
> exposure-agnostic (§7: pure function + models + registration table + thin
> adapter). One commit per tool, regenerating and reviewing the golden MCP-surface
> snapshot each time (§4); renames go in the change map with a deprecated alias
> (§6). Add ≥1 prompt and ≥1 resource per backend (§10). Keep tests green per
> commit; verify wire-protocol compatibility with the current gateway client.
> Stop and summarize at each backend's acceptance gate (§9).

---

## Sources

FastMCP 3.0 capabilities used here are documented in
`14_fastmcp3_supabase_integration.md` (providers/transforms/result objects/
concurrency) and its Sources list.
