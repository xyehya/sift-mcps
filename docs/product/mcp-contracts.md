# MCP Contracts

Status: filled by BATCH-PDOC2 (verified inventory). Validation owner: BATCH-PDOC2 and BATCH-AUT1.
Last updated: 2026-06-09.

## Scope

The AI-agent-facing MCP surface served by the Gateway at `/mcp`, written from the
agent's point of view: what the agent sees, what each tool is for, its input/output
shape, how much context it consumes, and what to do after success/failure.

Every contract cites a source symbol and/or a BATCH-V1 live block. Each tool is tagged
**live-proven** (exercised on the SIFT VM in a Session-Notes BATCH-V1 block) or
**source-derived** (verified from source/schemas only — needs a live block to promote).
No raw secrets, tokens, DSNs, or passwords appear here.

## How the catalog is assembled (ground truth)

The aggregate FastMCP server is built by `mcp_server.py` `create_gateway_mcp_server`.
Tools come from three places:

1. **Core in-process tools** — `sift_core/agent_tools.py` `CORE_TOOL_SPECS` (8 specs),
   registered by `_register_core_tools` as `GatewayLocalTool`s.
2. **Gateway-local tools** — `capability_guide` (registered inline in
   `_register_core_tools`); the durable job tools `ingest_job` / `run_command_job` /
   `job_status` (`job_tools.py` `gateway_job_tool_specs`, registered only when
   `gateway.job_service` is wired); `rag_search_case` (`rag_bridge.py`, registered only
   when `gateway.rag_query_service` is wired).
3. **Add-on proxy tools** — mounted from registered backends' manifests
   (`_mount_addon_proxies`), namespaced and renamed per manifest. These are
   demo-optional and out of scope for the demo-critical contracts below.

Each tool carries `meta.category` and `meta.recommended_for_phase`
(`_CORE_TOOL_CATEGORIES` / `_CORE_TOOL_PHASES`, mcp_server.py:41-71) so the agent can
order its workflow (ORIENT → TRIAGE/INGEST → CORRELATE → FINDINGS).

### Catalog-printing evidence (no full VM stack)

From the pdoc2 worktree, `gateway_job_tool_specs()` and `rag_search_case_schema()`
import and print cleanly:

```
ingest_job      (read_only=False) required=['evidence_ref']        cat=ingest    phase=INGEST
run_command_job (read_only=False) required=['command','purpose']   cat=detection phase=TRIAGE
job_status      (read_only=True)  required=['job_id']              cat=ingest    phase=INGEST
rag_search_case props=['query','query_embedding','top_k','include_knowledge','include_derived'] anyOf=[query | query_embedding]
```

`CORE_TOOL_SPECS` could not be imported in this worktree (transitive
`forensic_knowledge` import), so the 8 core names were extracted directly from source:
`case_info, evidence_info, record_finding, record_timeline_event,
list_existing_findings, manage_todo, get_tool_help, run_command`. These are
source-derived from `agent_tools.py:91-272`; the listed ones below are additionally
live-proven where a BATCH-V1 block names them.

## Verified live MCP tool inventory

| Tool | Class | read_only | Required scope (example) | Status |
| --- | --- | --- | --- | --- |
| `case_info` | session-start / ORIENT | yes | `tool:case_info` or `mcp:*` | live-proven (BATCH-V1: redacts `case_dir`) |
| `evidence_info` | evidence-survey / ORIENT | yes | `tool:evidence_info` | source-derived |
| `capability_guide` | session-start / ORIENT | yes | `tool:capability_guide` | source-derived |
| `get_tool_help` | detection / TRIAGE | yes | `tool:get_tool_help` | source-derived |
| `run_command` | detection / TRIAGE | **no** | `tool:run_command` | live-proven (deny floor blocks `bash`, redacts paths) |
| `run_command_job` | detection / TRIAGE | **no** | `tool:run_command_job` | live-proven (job `884c3641…` post-seal) |
| `ingest_job` | ingest / INGEST | **no** | `tool:ingest_job` | live-proven (job `e6572af3…`, indexed 1) |
| `job_status` | ingest / INGEST | yes | `tool:job_status` | live-proven (V1 catalog) |
| `rag_search_case` | knowledge-rag / CORRELATE | yes | `tool:rag_search_case` | live-proven (`status=ok, count=3`) |
| `record_finding` | findings / FINDINGS | **no** | `tool:record_finding` | live-proven (`F-hermes-v1-gate-001`) |
| `record_timeline_event` | findings / FINDINGS | **no** | `tool:record_timeline_event` | live-proven |
| `manage_todo` | findings / FINDINGS | **no** | `tool:manage_todo` | live-proven |
| `list_existing_findings` | findings / FINDINGS | yes | `tool:list_existing_findings` | source-derived |
| add-on proxy tools (e.g. opensearch/cti/wintools) | per-manifest | per-manifest | manifest `required_scopes` | source-derived (demo-optional) |

`evidence_register` is **filtered out of the agent catalog** (`_AGENT_FILTERED_TOOLS`,
mcp_server.py:37) and any manifest tool with `hidden_from_agent` is hidden
(`GatewayToolCatalogMiddleware`). Registration/sealing is an operator portal action,
not an agent tool.

## Scopes and authorization (what gates each tool)

Tool authorization is SIFT-owned in `policy_middleware.py`
`ToolAuthorizationMiddleware` using `is_tool_allowed` (`supabase_auth.py:1435`) for
BOTH `on_list_tools` (filter) and `on_call_tool` (reject before dispatch), so list and
call are always consistent. Scope grammar (DB `app.principal_tool_scopes`, global rows
only for MVP):

- `mcp:*` → all tools
- `tool:<name>` → exactly that tool
- `namespace:<pfx>` → tools named `<pfx>_*`
- any other string grants nothing; a principal with no matching scope lists/calls
  nothing (fail-closed when auth is enabled — B6).

Add-on tools may additionally declare manifest `required_scopes` enforced by
`AddonAuthorityMiddleware` via `is_scope_satisfied` (`supabase_auth.py:1466`), plus
`prohibited_operations` / `non_authoritative` so a query-only add-on can never perform
an authority operation (seal/approve/bypass). The Gateway, not the add-on, remains the
authority boundary.

### Policy middleware order (every call passes through this)

`gateway_policy_middlewares` (policy_middleware.py:935):
`ToolAuthorization → AddonAuthority → CaseContext → AuditEnvelope → ProxyActiveCase →
EvidenceGate → ResponseGuard`. Consequences the agent feels:
- **Tool authz** first — denied tools 403-equivalent (`tool_not_authorized`) and are
  absent from the catalog.
- **Case context** — resolves the DB active case for the principal; case-scoped tools
  with no active case are denied (`active_case_denied`).
- **Evidence gate** — blocks ALL tool calls when the active evidence chain is not OK
  (unsealed/violated). Block payload below.
- **Audit envelope** — DB-first; a mutating tool whose required pre-dispatch audit
  write fails **fails closed** (`audit_unavailable`) and never runs.
- **Response guard** — last; redacts secrets + absolute paths and caps output.

## Cross-cutting agent-visible behavior

### Evidence gate block (pre-seal, fail-closed)
`EvidenceGateMiddleware` + `build_block_response` (evidence_gate.py:211). When the chain
is not OK the agent gets:
```json
{"blocked": true, "reason": "evidence_chain_unsealed", "tool": "<name>",
 "status": "UNSEALED", "issues": [...], "manifest_version": 0,
 "detail": "No sealed evidence manifest. This tool requires evidence to be registered
 and sealed before it can be used.",
 "remediation": "Open the Examiner Portal and use the Evidence tab to review and seal
 the evidence chain before proceeding with agent analysis."}
```
DB authority is preferred (`check_evidence_gate_db` → `app.evidence_gate_status`),
fail-closed on any DB error. **Recovery: the agent cannot self-remediate** — it must
ask the operator to seal in the portal, then retry. Live-proven: BATCH-V1 pre-seal
calls failed closed with `evidence_chain_unsealed`; post-seal calls allowed.

### Path / secret redaction and opaque IDs (response guard)
`ResponseGuardMiddleware` + `response_guard.py`:
- **Secret patterns** (`_PATTERNS`): critical/high matches (AWS/GitHub/OpenAI/
  Anthropic/Stripe/Slack/Google/JWT/Bearer/private keys/connection strings/passwords)
  are replaced inline with `[REDACTED:<pattern_name>]`; medium patterns are flagged
  only. A `_sift_context.secret_warning` list is appended.
- **Absolute paths**: in-case absolutes collapse to relative display paths; any other
  case/evidence/mount/`/home`/`/etc` path becomes `[REDACTED:absolute_path]`. The bare
  case dir itself is redacted (the agent gets opaque case IDs, never the artifact path).
- **Opaque IDs**: the agent sees `case_id` (UUID) + `case_key` and relative dirs
  (`evidence`, `agent`) via the appended `case_context` block (`_case_text`,
  policy_middleware.py:124), never the host `/cases/...` path.
- **Override**: an operator may enable a time-boxed redaction override per case; when
  active, `_sift_context.redact_override_active=true`. This is operator-controlled, not
  agent-controlled.
- Live-proven: BATCH-V1 `case_info` redacted `case_dir`; `run_command_job` "redacted
  absolute-path output"; report export leak scan clean.

### Output cap / context budget (response guard)
`output_cap_bytes()` default **262144 bytes (256 KiB)** per response
(`SIFT_OUTPUT_CAP` env, settable via `trust.output_cap_bytes`). Oversized responses are
truncated to a preview with a `[OUTPUT CAPPED BY GATEWAY: returned preview of N
serialized bytes …]` marker and a `_sift_context.output_capped` entry carrying
`{original_bytes, returned_bytes, cap_bytes, output_file (relative ref)}`. Structured
content also has a depth limit (`Structured Content Depth Limit`). Tools further self-
limit at the source (see per-tool budgets).

### Provenance the agent can cite
`run_command` returns a `provenance` block: `{job_id ("rc-<audit_id>"), audit_id,
input_sha256s, input_count, evidence_refs, output_sha256?, output_ref?}` and a
`job_id`. Findings/timeline carry `audit_ids` linking claims to tool responses; the
agent is told to pass `audit_id` from each tool response into `record_finding`.

## Per-tool contracts (demo-critical)

### `case_info` — ORIENT, read-only (live-proven)
- Purpose / agent-visible description: "Essential case overview: status, finding/
  timeline/todo counts, evidence chain status, file structure summary, platform
  capabilities. Call at session start."
- Input: `{}` (no args). Output (`_case_info`, agent_tools.py:353): `{case_id, name,
  status, examiner, case_dir, case_brief, findings{total,draft,approved},
  timeline_events, todos{open,total}, evidence_chain{status,ok,issues,
  manifest_version}, file_structure{top_level_dirs,total_files,total_dirs,
  subtree_counts}, platform_capabilities}` — plus the appended `case_context`.
- Parallel-safety: **safe-read** (read-parallel). Context budget: bounded — full file
  tree is written to `agent/case_file_structure.json` and only a slim summary returned
  (`_case_file_structure`, returns `full_tree_path`); avoids dumping the whole tree.
- Saved-artifact: `agent/case_file_structure.json` (full tree, path-free ref).
- Provenance: case_id/manifest_version. Recovery: if `evidence_chain.ok=false`, expect
  the evidence gate to block mutating tools — ask operator to seal.
- Security: `case_dir` is redacted by the response guard before the agent sees it
  (BATCH-V1). Tests/live proof: BATCH-V1 "case_info redacts case_dir".

### `evidence_info` — ORIENT, read-only (source-derived)
- Description: "Evidence listing with registration, sealing, chain integrity, and
  manifest verification in a single call. Returns sealed evidence and unregistered
  files with required actions."
- Input `{}`. Output (`_evidence_info`): `{chain_status, ok_count, issues,
  manifest_version, evidence_files:[...], total_evidence_files, unregistered_files:[...],
  requires_examiner_action}`. Parallel-safety: safe-read. Budget: list-bounded.
  Provenance: manifest_version + per-file ids/hashes. Recovery: surfaces
  `requires_examiner_action` → defer to operator.

### `capability_guide` — ORIENT, read-only (source-derived)
- Description (verbatim): "ADD-ON backends only: manifest-derived guide to currently
  usable add-on tools, grouped by backend, provides[], category, and recommended phase.
  Returns empty when no add-on backend is registered — that is expected, NOT an error."
- Input `{}`. Parallel-safety: safe-read. Note: empty result is normal in the
  core-only demo. **AUT1 flag (minor):** description is accurate but the agent may
  misread an empty list as a failure; the "not an error" caveat mitigates this.

### `get_tool_help` — TRIAGE, read-only (source-derived)
- Description: "Get usage information, common flags, caveats, and field meanings for a
  cataloged forensic tool." Input `{tool_name}` (required). Parallel-safety: safe-read.

### `run_command` — TRIAGE, mutating (live-proven)
- Description: "Execute a validated command on this SIFT VM. Pass a single command
  string; pipes (|), sequencing (&&/||/;), and redirects (>,>>,<,2>&1) are supported.
  Set preview_lines to cap inline stdout and save_output for large output. Case path
  jails, audit logging, and provenance hashing are enforced."
- Input (agent_tools.py:256): required `command, purpose`; optional `timeout,
  save_output, evidence_refs[], output_ref, input_files[] (deprecated), working_dir,
  preview_lines, skip_enrichment`.
- Output: `build_response` envelope — `{success, tool, data, audit_id, output_format,
  elapsed_seconds, exit_code, command, job_id, provenance{...}}`, plus optional
  `warnings/agent_action/privilege_escalation/stages`, `full_output_ref/_sha256/_bytes`
  (relative ref), and `input_files_warning` when inputs weren't detected.
- Parallel-safety: **serialized-mutation** (writes to `agent/run_commands/`, runs in
  the case jail). Treat as case-serialized; prefer `run_command_job` for long work.
- Context budget: `preview_lines` capped at 200 (`min(..., 200)`); large stdout is
  saved and only a preview returned; response guard then applies the 256 KiB cap.
- Saved-artifact: `save_output`/`output_ref` persist full stdout/stderr under
  `agent/run_commands/`, returned as a **relative** `full_output_ref` — never an
  absolute path. `evidence_refs` resolve opaque ids/relative paths to local paths
  internally; the agent never supplies or sees absolute paths.
- Provenance: `provenance{job_id="rc-<audit_id>", audit_id, input_sha256s, evidence_
  refs, output_sha256?}`. Recovery: on `purpose is required`/`command must be a
  string…` fix args; the deny floor returns a `SiftError` with a redacted message.
- Security: command-array form is literal argv (no shell operators); a final
  `sanitize_paths_deep` scrubs every path-like value. Live-proven: BATCH-V1 deny floor
  blocked `bash` and redacted error paths.
- **AUT1 watch (from MEMORY/Sess 31):** flex features (pipe/redirect/stderr) may not be
  reachable through the gateway when the command is passed as an argv array → literal
  argv → context bloat; and `cp`/`rm` reaching `evidence/` is an open write-gap (S-1).
  Flag for BATCH-AUT1/SEC1, not a doc defect.

### `run_command_job` — TRIAGE, mutating (live-proven)
- Description: "Enqueue a sandboxed run_command request through the Postgres job state
  machine. Returns a job_id only."
- Input (job_tools.py:69): required `command, purpose`; optional `timeout, save_output,
  evidence_refs[], output_ref, working_dir, preview_lines, skip_enrichment, priority
  (100), max_attempts (1)`.
- Output: `{job_id, status:"queued", job_type:"run_command", ...public_dict}` —
  **job_id only**, no inline output (poll `job_status`). Parallel-safety:
  **job-parallel** (independent durable jobs). Context budget: tiny (queue receipt).
  Saved-artifact: the worker writes outputs path-free; results surface via `job_status`.
- Provenance: opaque `case_id`/`evidence_id` only; absolute paths live in
  `spec_internal` for the worker, never returned. Recovery: `active_case_required` (403)
  → ensure active case; `command_and_purpose_required` → fill args; `job_service_not_
  wired` (503). Live-proven: BATCH-V1 job `884c3641-7bfa-4801-a3de-7eb7b69f0d2e`.

### `ingest_job` — INGEST, mutating (live-proven)
- Description: "Enqueue sealed evidence ingest into the derived search plane through the
  Postgres job state machine. Returns a job_id only."
- Input (job_tools.py:35): required `evidence_ref` (sealed evidence id or relative
  display path); optional `hostname, include[], exclude[], full (false), priority (100),
  max_attempts (3)`. Output: `{job_id, status:"queued", job_type:"ingest", ...}`.
- Parallel-safety: **job-parallel**. Context budget: tiny. Saved-artifact: results land
  in the derived OpenSearch plane + DB provenance, not the agent response.
- Provenance/security: `_resolve_evidence` fails closed (`evidence_file_unavailable` /
  `invalid_relative_evidence_ref`) and never echoes absolute paths; only the relative
  display path and opaque ids are enqueued publicly. Live-proven: BATCH-V1 job
  `e6572af3…`, provenance `3f90b65a…`, indexed `1`, bulk failures `0`, index
  `case-<uuid>-json-v1-ingest-host01`.

### `job_status` — INGEST, read-only (live-proven)
- Description: "Read sanitized status for a durable Postgres job." Input `{job_id}`
  (required). Output: `job_status_public(job_id, identity)` — sanitized status/logs,
  path-free. Parallel-safety: **safe-read** (job-poll). Recovery: `job_id_required`,
  `active_case_required`. Live-proven: present in V1 scoped catalog; the agent's token
  `case_id`/`default_case_id` is accepted for the job case (BATCH-V1 fix).

### `rag_search_case` — CORRELATE, read-only (live-proven)
- Description: "Search the case-scoped pgvector RAG plane and shared forensic knowledge.
  Returns path-free, provenance-linked snippets."
- Input (rag_bridge.py:97): `anyOf [query | query_embedding]`; optional `top_k (5),
  include_knowledge (true), include_derived (true)`. `query_embedding` must be a numeric
  array of exactly **768** dims or it's rejected (`query_embedding_must_be_768_
  dimensional`).
- Output: store `public_dict()` — path-free, provenance-linked snippets with `kinds`
  and titles. Parallel-safety: **safe-read**. Context budget: `top_k`-bounded.
- Recovery: `active_case_required`, `rag_pgvector_not_wired`,
  `rag_pgvector_store_unavailable`, `rag_embedding_model_unavailable`. Security: the
  agent never queries Postgres directly; the Gateway brokers; shared knowledge rows keep
  `case_id NULL`. Live-proven: BATCH-V1 `status=ok, count=3, kinds=["knowledge"],
  has_abs_path=false`; titles `Intelligence Requirements Definition`, `SIFT Workstation`,
  `oledump.py Overview`.

### `record_finding` — FINDINGS, mutating (live-proven)
- Purpose: "Stage a finding as DRAFT for examiner approval. Findings missing required
  fields or provenance (audit_ids) are REJECTED." Input (agent_tools.py:106): `finding`
  (required: title, type∈{finding,attribution,conclusion,exclusion}, host, observation,
  interpretation, confidence∈{HIGH,MEDIUM,LOW,SPECULATIVE}, confidence_justification;
  optional audit_ids, mitre_ids, iocs, event_type, event_timestamp, artifact_ref,
  related_findings, affected_account); optional `supporting_commands[]`, `artifacts[]`
  (each with `audit_id` for provenance).
- Output: on success `{status:"STAGED", finding_status:"DRAFT — requires human approval
  via the examiner portal", considerations, grounding?, provenance?, provenance_
  guidance?}`; on failure `{status:"VALIDATION_FAILED", errors, guidance (FD-001/003/
  005)}`. Parallel-safety: **serialized-mutation** (case-serialized).
- Saved-artifact: staged DRAFT row (DB/case authority); becomes reportable only after
  operator approval (POST `/api/commit`, HMAC). Provenance: requires `audit_ids` from
  real tool calls; SHELL-only provenance gets `provenance_guidance` to re-run via MCP.
- Recovery: read the `guidance` codes and add the missing audit_id/justification.
  Live-proven: BATCH-V1 `F-hermes-v1-gate-001` staged → portal-approved.

### `record_timeline_event` — FINDINGS, mutating (live-proven)
- Input (agent_tools.py:184): `event` required (title, timestamp ISO-8601, description,
  host, source; optional event_type∈{execution,persistence,lateral,auth,network,other},
  related_findings, audit_ids, mitre_ids). Parallel-safety: serialized-mutation. Staged
  as DRAFT pending approval.

### `manage_todo` — FINDINGS, mutating (live-proven)
- Input: `action`∈{create,list,update,complete} (required) + action-specific fields
  (create→description; update/complete→todo_id). `add` is a back-compat alias for
  `create`. `list` is effectively read; create/update/complete mutate. Parallel-safety:
  serialized-mutation (treat list as safe-read). Recovery: structured errors
  `missing_description` / `missing_todo_id` / `unsupported_todo_action`.

### `list_existing_findings` — FINDINGS, read-only (source-derived)
- Input: optional `status`∈{DRAFT,COMMITTED,REJECTED,SUPERSEDED}, `limit (20)`,
  `offset (0)`. Output: paginated summaries (`_SUMMARY_KEYS` only) + `total/limit/offset`
  + `full_findings_path` (full set written to `agent/findings_list.json`).
  Parallel-safety: safe-read. Context budget: **paginated** + slim summary keys; full
  list spilled to a saved artifact rather than inlined.

## Parallel-safety summary

| Class | Tools |
| --- | --- |
| Safe-read (read-parallel) | `case_info`, `evidence_info`, `capability_guide`, `get_tool_help`, `list_existing_findings`, `rag_search_case`, `job_status`, `manage_todo` (list) |
| Job-parallel (durable) | `ingest_job`, `run_command_job` |
| Serialized-mutation (case-serialized) | `run_command`, `record_finding`, `record_timeline_event`, `manage_todo` (create/update/complete) |
| Operator-only / denied to agent | `evidence_register` (filtered), portal seal/ignore/retire/approve (REST, not MCP) |

## Context management rules (enforced + advisory)

- Enforced: 256 KiB response cap + structured-content depth limit (response guard);
  `run_command` `preview_lines` ≤ 200; large/full payloads spilled to saved artifacts
  (`case_file_structure.json`, `findings_list.json`, `agent/run_commands/*`) returned as
  relative refs; `list_existing_findings` pagination.
- Advisory: prefer concise summaries; cite opaque ids; don't request exhaustive trees.
- Any bloated response BATCH-AUT1 finds should become a contract fix, a pagination
  requirement, or a known limitation.

## Flags for BATCH-AUT1 (missing / misleading schema or description)

1. **No `required_scopes`/`authority_contract` on core tools.** Core tools rely on the
   `tool:<name>`/`mcp:*` gateway scope grammar only; the manifest `required_scopes` /
   `prohibited_operations` machinery exists solely for add-on tools
   (`AddonAuthorityMiddleware`). Not a defect, but AUT1 should confirm the demo agent's
   issued `tool_scopes` actually cover every demo-critical tool, or the catalog silently
   shrinks (fail-closed list filtering).
2. **`run_command` vs `run_command_job` overlap.** Both exist with near-identical
   schemas; the description does not tell the agent when to pick the synchronous vs the
   durable variant. AUT1 should add disambiguation guidance (sync = quick/preview;
   job = long-running/parallel).
3. **`run_command` flex reachability (Sess 31 friction).** Pipes/redirects/stderr are
   advertised but may be unreachable when the command arrives as an argv array (literal
   argv), causing context bloat; and `cp`/`rm` reaching `evidence/` is an open write-gap
   (S-1, HIGH). Schema is fine; behavior needs AUT1/SEC1 verification.
4. **`capability_guide` empty-result ambiguity.** Description says empty is expected,
   but an autonomous agent may still treat empty as failure. AUT1 should score
   discoverability here.
5. **`job_status` poll loop.** No advertised backoff/terminal-state contract in the
   description; AUT1 should verify the agent can tell `queued`/`running`/`done`/`failed`
   apart and knows when to stop polling.

## Suggested interaction-model.md additions (owned by PDOC1 — for the conductor)

1. The agent tool loop ordered by `meta.recommended_for_phase`
   (ORIENT → TRIAGE/INGEST → CORRELATE → FINDINGS), and the enqueue→`job_status`-poll
   loop for `ingest_job`/`run_command_job`.
2. The evidence-gate handoff: pre-seal, every tool fails closed with
   `evidence_chain_unsealed` and the agent must hand back to the operator to seal in the
   portal (it cannot self-remediate).
3. The DRAFT→approval handoff: `record_finding` stages DRAFT → operator approves via
   portal commit (HMAC) → finding becomes reportable. This is the core agent↔operator
   recovery/handoff edge.
