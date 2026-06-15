# MCP Tool Surface Audit — response efficiency + schema accuracy (2026-06-14)

Live brute-force on active case `case-rocba-case-06132304` (2.08M docs indexed, 37 artifact
families, 9 draft findings). Goal: per tool, measure (A) response efficiency = signal vs spam,
(B) schema/definition accuracy + agent-helpfulness. Companion static code audit by qa-expert.

Autosave-to-disk pattern CONFIRMED present on: `run_command` (`full_output_path` + `agent/run_commands/outputN/`),
`list_existing_findings` (`full_findings_path: agent/findings_list.json`), `opensearch_case_summary`
(`filesystem_meta_path`). To verify: does `opensearch_search` / `opensearch_aggregate` autosave large hits?

## Axis A — response efficiency findings (live)

| Tool | Payload | Spam / redundancy | Signal:spam | Sev |
|---|---|---|---|---|
| capability_guide | ~8KB | 3 `groups` blocks (by_provides/by_category/by_recommended_phase) just RE-LIST tool names already in `available_backends`; by_provides sub-lists (search/ingest/enrichment) are ~identical 15-tool dumps. Full 64-tool core catalog inline. `case_context` envelope appended. | ~40% spam | HIGH |
| opensearch_status | 41 indices | 4 empty `case-seed-*-init` (docs:0) pure noise; index names carry double `case-case-` prefix + repeat full case_id every row; deprecated tool still live. | med spam | MED |
| opensearch_case_summary | large | `artifacts.<fam>.indices:[full-name]` redundant w/ family key; `artifacts` + `coverage_state.disk_artifacts` both enumerate families. Otherwise high-signal (gaps + fill commands + hints). | mostly signal | LOW-MED |
| kb_get_knowledge_stats | tiny | clean (status + 6 nums). | ~all signal | — |
| list_existing_findings | 9 items | `created_by` == `examiner` (dup); good `full_findings_path` autosave. | mostly signal | LOW |
| manage_todo(list) | 1 todo | `_version` internal leaked; echoes input `action`/`status`/`assignee` back. | mostly signal | LOW |

### Cross-cutting spam patterns (all tools)
- **`case_context` envelope** appended to capability_guide / case_info / evidence_info every call —
  duplicate of case_info; agent already knows the case. Candidate: drop or gate behind a flag.
- **Input echo**: several tools echo back the params just sent (manage_todo action/status/assignee).
- **Internal fields leak**: `_version` (todo), `_sift_context`, double `audit_id`+`job_id`+`rc-*` on run_command.
- **Per-line `[untrusted forensic-tool output…]` label** prepended to EVERY run_command stdout block
  (and opensearch?) — 70+ chars of boilerplate per call; could be one top-level flag instead of inline.

## Axis B — schema / definition accuracy + helpfulness (live)
- capability_guide description is accurate (add-on scope) but the payload contradicts "compact" intent.
- opensearch_status self-declares DEPRECATED in description AND output → should be hidden from the
  default tool list (still returned by tools/list = wastes the agent's attention budget).
- opensearch_* descriptions are EXCELLENT (when_to_use / avoid_when / cross-refs). Strong prior art to
  copy to the core tools (run_command/case/findings have thinner guidance).
- record_finding schema is very rich (good example payload) — verify required-field rejection live.
- (todo create-vs-add mismatch from memory: schema enum here is create/list/update/complete — `add`
  alias is handler-only, correctly NOT in enum. OK.)

## Batch 2 — query surface (live on 2M-doc index)

| Tool | Result | Finding | Sev |
|---|---|---|---|
| opensearch_count | `{count:3}` | perfect — pure signal. The model to copy. | — |
| opensearch_aggregate | buckets ok | **`total_docs:10000` is misleading** — it's the OpenSearch track_total_hits cap, not the real corpus (2.08M). Reads as "only 10k docs." Aggregation buckets ARE exact. Fix: label as `sampled_total`/`>=10000`, or set track_total_hits. | MED |
| opensearch_timeline | `total_docs:0` | empty result for event.code:4688 (genuinely absent; Sysmon uses code:1). No guidance that 0 may mean wrong field/value → add a "verify field via field_values" hint on empty. | LOW |
| opensearch_search (compact) | 2 hits | **(1) NO autosave/`full_path` for large result sets** — at limit=200 with full docs this is a context bomb (run_command/findings autosave; this doesn't). (2) per-hit constants repeated: `vhir.provenance_id`,`vhir.case_id`,`host.id`(==host.name),`winlog.provider_name`. (3) `winlog.event_data` is a single-quoted **Python-repr string, not JSON** → not parseable. | **HIGH** |
| opensearch_list_detections | empty+suggestion | excellent fallback (exact Hayabusa query when Sigma absent). Model design. | — |
| kb_search_knowledge | 3 results | per-result spam: 3 provenance UUIDs (chunk_id+provenance_id+document_provenance_id) + 2 always-null fields (case_id, evidence_object_id) + constant `kind:"knowledge"`. Signal = content+title+distance+source_ref. | MED |

### Highest-leverage so far
1. **opensearch_search large-result autosave** — biggest context win: save full hits to `agent/…/search_*.json`, return summary + path + top-N, mirroring run_command. Enables the PTC "query→save→grep" loop.
2. **capability_guide groups-block bloat** + **case_context envelope** on every call.
3. **Hoist per-hit/per-result constants** (vhir.*, host.id, kind, null fields) out of each item into one header.
4. **event_data as real JSON** not Python-repr.
5. **aggregate total_docs mislabel.**

## Batch 3 — mutation surface (live)

| Tool | Result | Finding |
|---|---|---|
| record_finding (all req fields, no provenance) | `status:REJECTED` "no evidence trail" | GOOD message (3 options). Confirms `audit_ids`/`supporting_commands` are EFFECTIVELY REQUIRED though schema labels them OPTIONAL (= static B9). |
| record_finding (missing confidence_justification) | `status:VALIDATION_FAILED` FD-005 | clean, but DIFFERENT status vocab than the provenance reject (`REJECTED` vs `VALIDATION_FAILED`) — inconsistent. |
| manage_todo(create) | `{status:created, todo_id}` | ideal minimal shape. |
| record_timeline_event | `{status:STAGED, event_id}` | ideal minimal shape. |
| manage_todo(complete) | `{status:completed, todo_id}` | ideal. |

NB: probe artifacts left on case — timeline event `T-claude-007` (no delete tool; labeled QA-TEST-AUDIT);
todo `TODO-claude-008` created+completed. No test finding persisted (both rejected). Cleanup = operator.

## Consolidated priority backlog (live-verified ✓ + static code-grounded)

Two axes, ranked by leverage. File:line from the qa-expert static pass.

### A — RESPONSE EFFICIENCY (cut the 90% spam)
1. **run_command quadruple provenance receipt** ✓ — `audit_id` + root `job_id`(=`rc-{audit_id}`) + `provenance.job_id` + `provenance.audit_id`, plus `full_output_path`==`full_output_ref`, plus constant `tool`/`examiner` every call. `agent_tools.py:904-948`, `execute/response.py:129-134`. Est. 15-25% off the most-called tool. **HIGH**
2. **`opensearch_search` no large-result autosave** ✓ — add `agent/…/search_<id>.json` + summary + path (mirror run_command). Unlocks the PTC query→save→grep loop. `opensearch-mcp server.py` search path. **HIGH**
3. **`case_info` always dumps full `case_brief`** (multi-paragraph) — gate behind `include_brief=False`; drop `case_dir` (==case_id). `agent_tools.py:416-453`. **HIGH**
4. **`case_context` envelope** appended to case_info/evidence_info/capability_guide every call ✓ — `case_id`==`case_key`, `evidence_dir`/`agent_dir`/`source`/`tool` constant. Collapse. `policy_middleware.py:134-146`. **MED**
5. **`capability_guide` 3 `groups` blocks + empty-add-on full dump** ✓ — re-list tool names already present; return-early when no add-on. `mcp_endpoint.py:692-713`. **MED**
6. **Hoist per-hit/per-result constants** ✓ — opensearch_search `vhir.*`/`host.id`(==host.name)/provider; kb_search 3 UUIDs + 2 always-null (`case_id`,`evidence_object_id`) + `kind`. One header, not per item. **MED**
7. **`opensearch_field_values` `count`==`doc_count` dup** — drop one. `server.py:1258`. **MED**
8. **compact `event_data` = `str(dict)[:500]` Python-repr** ✓ — truncates nested JSON into single-quoted unparseable string; keep JSON or summarize keys. **MED**
9. **`aggregate.total_docs:10000`** ✓ misleading track-total cap (real 2M) — relabel/`track_total_hits`. **MED**
10. Per-call boilerplate: `[untrusted…]` label on every output line; `opensearch_search` compact `note` every call; FK `caveats`/`field_notes` repeat per binary — deliver once/session then decay. **MED/LOW**

### B — SCHEMA / DEFINITION ACCURACY
1. **Zero `outputSchema` on ANY tool** (16 core + ~22 opensearch) — define at least for case_info/evidence_info/list_existing_findings/opensearch_case_summary; enables structured access + regression catch. **HIGH**
2. **Ingest polling dead-end (DB-active)** — `opensearch_ingest`→`run_id`; `opensearch_ingest_status` says use `job_status(job_id)`; `running_commands_status` wants a Postgres UUID that ingest never emits. No working poll path. Fix descriptions + (deferred) inject DB job row. `job_tools.py:78`, `opensearch server.py:2543-2556`. **HIGH**
3. **`record_finding` audit_ids labeled OPTIONAL but rejection-required** ✓ — move to required-for-acceptance in description/schema; unify `REJECTED`/`VALIDATION_FAILED` status vocab. **MED**
4. **`run_command.input_files` deprecated but unmarked** + failure-warning still steers agents to it. Mark `deprecated`, drop the warning. `agent_tools.py:263-286`. **HIGH**
5. **`opensearch_host_fix` name mismatch** — decorator `opensearch_host_fix` vs response/audit `opensearch_fix_host_mapping`. Unify. **HIGH**
6. **opensearch_status/shard_status self-declare DEPRECATED** ✓ but still in tools/list (wastes attention) — hide or alias to resource. **MED**
7. `evidence_info` description omits chain_status/requires_examiner_action semantics (what blocks tools). `manage_todo` `add` alias undocumented + audits as `add_todo`. `get_tool_help` doesn't mention `'inventory'` or post-output drill-in. **MED/LOW**

### SECURITY (from static pass — verify + fold into hardening)
- **opensearch-mcp leaks absolute host paths** that bypass the gateway redactor: `log_file` (ingest_status, `server.py:2586`), `resolved_path` (inspect_container/ingest errors, `1700/2766/2809/2937/3523`), `dict_path` (host_fix error paths `4095/4150`). F-MVP-2 invariant violations — agent can't use them anyway; delete/relativize. **Verify live, then patch.**
- `list_existing_findings.full_findings_path` not passed through `sanitize_path_value` (run_command is). `agent_tools.py:1222`. **MED**

### Phase 2 (PTC) — LANDED 2026-06-14
PTC runs host-side (this terminal), not in the run_command jail. Bridge + recipes + how-to skill:
`scripts/ptc/ptc.py` (CA-pinned MCP-over-HTTPS, live token from `~/.claude.json`),
`scripts/ptc/recipes/{ioc_pivot,aggregate_then_fetch,timeline_drill}.py`, `scripts/ptc/README.md`,
`.claude/skills/ptc/SKILL.md`. Live-proven: 200-hit search = ~256 KB on disk / ~10 lines in context;
2-IOC pivot over 2M docs correlates both external RDP IPs into vol-netscan+vol-netstat. The on-wire
fixes below remain complementary (they slim the summaries that DO return).

### Top wins for Phase 2 (PTC) enablement
The single highest-leverage change for the PTC/context goal: **#A2 opensearch_search autosave-and-return-path** + **#A1 run_command receipt slimming** + **#A6 constant-hoisting**. Together they make the "query → save → grep/transform/correlate on disk" loop cheap and keep raw bulk out of context.

