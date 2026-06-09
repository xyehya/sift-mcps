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
| `case_info` | session-start / ORIENT | yes | `tool:case_info` or `mcp:*` | live-proven (BATCH-V1 + AUT1: redacts `case_dir`; **AUT1-B1**: `evidence_chain` is file-backed, can disagree with DB gate) |
| `evidence_info` | evidence-survey / ORIENT | yes | `tool:evidence_info` | **live-proven (AUT1)**; **AUT1-B1**: `chain_status`/`requires_examiner_action` file-backed, can disagree with DB gate |
| `capability_guide` | session-start / ORIENT | yes | `tool:capability_guide` | **live-proven (AUT1)**: empty add-on list with explicit "not an error" note |
| `get_tool_help` | detection / TRIAGE | yes | `tool:get_tool_help` | **live-proven (AUT1)** for `run_command`; **AUT1-B6**: a static abs-path example is self-redacted in the guidance |
| `run_command` | detection / TRIAGE | **no** | `tool:run_command` | live-proven (AUT1: deny floor blocks `bash`; evidence `rm` blocked; paths redacted). Returns a **non-pollable** `rc-<audit_id>` job_id |
| `run_command_job` | detection / TRIAGE | **no** | `tool:run_command_job` | live-proven (BATCH-V1 `884c3641…`; **AUT1** `b58fb7a2…` → pollable UUID) |
| `ingest_job` | ingest / INGEST | **no** | `tool:ingest_job` | live-proven (job `e6572af3…`, indexed 1) |
| `job_status` | ingest / INGEST | yes | `tool:job_status` | **live-proven (AUT1)**: `b58fb7a2…` → `succeeded`; `job_not_found` for missing UUID; malformed id → typed `invalid_job_id` (AUT1 fix) |
| `rag_search_case` | knowledge-rag / CORRELATE | yes | `tool:rag_search_case` | live-proven BATCH-V1 (`status=ok`), but **AUT1-B2: ABSENT from the live agent catalog** — only registered when `gateway.rag_query_service` is wired |
| `record_finding` | findings / FINDINGS | **no** | `tool:record_finding` | live-proven (`F-hermes-v1-gate-001`; AUT1: incomplete finding REJECTED with provenance guidance) |
| `record_timeline_event` | findings / FINDINGS | **no** | `tool:record_timeline_event` | live-proven |
| `manage_todo` | findings / FINDINGS | **no** | `tool:manage_todo` | live-proven (AUT1: create→list→complete) |
| `list_existing_findings` | findings / FINDINGS | yes | `tool:list_existing_findings` | **live-proven (AUT1)**: returns `F-hermes-v1-gate-001` + `full_findings_path` saved ref |
| add-on proxy tools (e.g. opensearch/cti/wintools) | per-manifest | per-manifest | manifest `required_scopes` | source-derived (demo-optional; **absent in the assessed core-only deployment**) |

`evidence_register` is **filtered out of the agent catalog** (`_AGENT_FILTERED_TOOLS`,
mcp_server.py:37) and any manifest tool with `hidden_from_agent` is hidden
(`GatewayToolCatalogMiddleware`). Registration/sealing is an operator portal action,
not an agent tool.

### AUT1 live-catalog observation (2026-06-09)

The agent's **live catalog in the assessed deployment held 12 tools**:
`case_info, capability_guide, evidence_info, get_tool_help, ingest_job,
job_status, list_existing_findings, manage_todo, record_finding,
record_timeline_event, run_command, run_command_job`. **`rag_search_case` was
absent** (AUT1-B2) — it is registered only when `gateway.rag_query_service` is
wired (`mcp_server.py:261`). The agent's JWT carried **no scope/case claims**
(`role=authenticated` only); tool scopes and the active case are resolved
server-side from DB principal rows (`app.principal_tool_scopes`,
`app.active_case_state`), so the agent **cannot self-inspect its scopes** and a
silently-shrunk catalog (fail-closed filtering) is invisible to it — the operator
must confirm the issued scope set covers every demo-critical tool.

**AUT1-B1 (file vs DB evidence-chain split-brain).** `case_info.evidence_chain`
and `evidence_info.chain_status` are computed from the **file manifest**
(`agent_tools.py:360` `chain_status(case_dir)`; `:397` file verify), while the
evidence **gate** that actually governs execution reads **DB authority**
(`evidence_gate.check_evidence_gate_db` → `app.evidence_gate_status`, preferred at
`policy_middleware.py:456`). On the live case these disagreed: orientation
reported `unsealed / ok=false / manifest_version=0 / requires_examiner_action=true`
yet `run_command` (a gated mutating tool) executed successfully, proving the DB
gate was OK. An agent obeying the documented "hand back on `ok=false`" loop would
stall. Until fixed, prepare demo cases so the file manifest and DB gate agree.

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
- Description: quick, synchronous validated command execution on the SIFT VM.
  Returns inline preview/receipt output. The returned `rc-*` receipt id is **not**
  a durable job id; use `run_command_job` for long-running or parallel work that
  should be polled with `job_status`. Pass a single command string; pipes (`|`),
  sequencing (`&&`/`||`/`;`), and redirects (`>`,`>>`,`<`,`2>&1`) are supported.
  Set `preview_lines` to cap inline stdout and `save_output` for large output.
  Case path jails, audit logging, and provenance hashing are enforced.
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
- Description: enqueue a sandboxed `run_command` request through the Postgres job
  state machine for long-running or parallel work. Returns a pollable UUID
  `job_id` only; use `job_status` to retrieve terminal status and sanitized
  output refs.
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

### `job_status` — INGEST, read-only (live-proven AUT1)
- Description: "Read sanitized status for a durable Postgres job." Input `{job_id}`
  (required, **must be a durable job UUID**). Output: `job_status_public(job_id,
  identity)` — sanitized status/logs, path-free. Parallel-safety: **safe-read**
  (job-poll).
- **Poll / terminal-state contract (AUT1-verified live).** `status` advances
  `queued → running → succeeded` (terminal set also includes `failed`,
  `cancelled`, `expired`). A terminal record carries `created_at`, `started_at`,
  `finished_at`, `step_count`, `steps_succeeded`, and the full `result_public`.
  **Stop polling on any terminal status.** Live: `b58fb7a2-…` returned
  `status=succeeded` with a 1-step success and full result.
- **Recovery (AUT1-updated).** `job_id_required` (empty); `active_case_required`;
  `job_not_found` (well-formed UUID, no such job — verified live); **`invalid_job_id`**
  (non-UUID id — AUT1 fix; previously this leaked a raw psycopg
  `invalid input syntax for type uuid … unnamed portal parameter $1`). Note the
  `rc-<audit_id>` id returned by synchronous `run_command` is **not** a durable
  job id and now yields `invalid_job_id` rather than a raw leak.
- **Context caveat (AUT1).** A terminal `job_status` **re-emits the entire
  `result_public`** (including job stdout, receipt, provenance) on every poll, so
  repeated polling of a large-output job re-consumes context. Poll sparingly and
  stop at the first terminal state.

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

## Flags for BATCH-AUT1 — RESOLVED (2026-06-09 live assessment)

Outcomes recorded in `agent-autonomy-assessment.md` (AUT1-B1…B6).

1. **Core-tool scopes / catalog shrinkage.** Confirmed live: 12/13 demo-critical
   tools present; only `rag_search_case` absent (AUT1-B2). The agent JWT has no
   scope claims (resolved server-side), so the agent cannot self-detect a shrunk
   catalog — operator must verify the issued scope set. See AUT1 live-catalog note
   above.
2. **`run_command` vs `run_command_job` overlap.** Confirmed and fixed in the
   conductor pass (AUT1-B4). Sync
   `run_command` returns inline output + a **non-pollable** `rc-<audit_id>` id;
   durable `run_command_job` returns a **pollable UUID**. Disambiguation is now
   in this contract and in the live tool descriptions after redeploy.
3. **`run_command` flex reachability + S-1 write-gap.** Deny floor solid live
   (`bash` blocked). **S-1 (evidence write-gap) closed for delete**: `rm evidence/…`
   blocked with a forensic-integrity message (K5 `assert_no_authority_write_target`
   + protected-dir guard). Single-command-string pipes are honored; AUT2 to stress
   multi-stage pipelines. The bad `rm` denial wording that told the agent to
   leave the harness is fixed in the conductor pass (AUT1-B5).
4. **`capability_guide` empty-result ambiguity.** Resolved: live empty result
   carries an explicit "expected default, not an error" note. Scored well.
5. **`job_status` poll loop.** Resolved: terminal-state contract verified and now
   documented (see the `job_status` contract above). The malformed-id raw leak
   (AUT1-B3) is **fixed** (typed `invalid_job_id`).
6. **AUT1-B5/B6 (LOW).** Evidence-delete handback wording and the
   self-redacting `get_tool_help` stderr example are fixed in the conductor pass;
   live re-verification awaits redeploy.
7. **AUT1-B1 (new, HIGH).** `case_info`/`evidence_info` evidence-chain is
   file-backed and can contradict the DB-authority gate — see the AUT1 live-catalog
   note. Highest-impact autonomy defect; fix recommended, not yet applied.

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
