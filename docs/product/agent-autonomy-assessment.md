# Agent Autonomy Assessment

Status: filled (BATCH-AUT1, live-exercised). Validation owners: BATCH-AUT1 (this
file) and BATCH-AUT2 (demo-case benchmark).
Last updated: 2026-06-09.

## Assessment Question

Can an AI agent complete a realistic DFIR investigation through Gateway MCP
alone, with enough context, provenance, safety, and recovery behavior to feel
autonomous rather than manually driven?

**AUT1 verdict:** Mostly yes. The MCP surface is sufficient for an end-to-end
MCP-only investigation, the security/redaction posture holds from the agent's
eyes, and the FINDINGS/INGEST/TRIAGE loops are strong. Three issues must be
resolved or accepted before the AUT2 demo benchmark can be trusted:

1. **AUT1-B1 (HIGH, autonomy):** `case_info` / `evidence_info` report a
   **file-backed** evidence-chain status that can contradict the **DB-authority**
   evidence gate that actually governs execution. On the live case the agent was
   told `evidence_chain: unsealed, ok=false, requires_examiner_action=true` while
   the gate was in fact OK and mutating tools executed. An agent following the
   documented loop ("on `ok=false`, hand back to operator") would stall
   needlessly. **Not fixed in AUT1** (cross-boundary authority plumbing; needs
   security review) — see Recommended Fixes.
2. **AUT1-B2 (MEDIUM, sufficiency):** `rag_search_case` is **absent from this
   agent's live catalog** — the CORRELATE/grounding plane is unavailable to the
   agent in the assessed deployment. Demo must verify the RAG service is wired
   (and scoped) before AUT2, or grounding is MCP-unreachable.
3. **AUT1-B3 (MEDIUM, error/security) — FIXED in AUT1:** `job_status` leaked a
   raw Postgres error (`invalid input syntax for type uuid … unnamed portal
   parameter $1`) for any malformed `job_id`, including the non-UUID `job_id`
   that `run_command` itself returns. Fixed: typed `invalid_job_id` + generic
   `internal_error` (no raw exception text) for all durable-job tools.

## How this assessment was produced (agent-only, with labeled diagnostics)

All autonomy/capability claims below come from **live MCP calls through the
configured Gateway `/mcp`** (server `Siftmcp`, `https://192.168.122.81:4508/mcp`,
Bearer agent token), exactly the surface the agent gets in a live environment.
17 live MCP calls were made against active case `case-v1gate-06081857`
(`57a06521-c9b8-4654-92ac-42b4f2bb0915`).

Non-MCP actions were used **only as diagnostics** and are explicitly labeled as
such; they never count as agent capability:

- decoding the presented agent JWT (own credential) to confirm scopes/case are
  resolved server-side, not from token claims;
- reading Gateway/core source to ground each behavior in a symbol;
- running `uv run pytest` for the AUT1 code fix.

## Scorecard

Score each category from 0 to 3.

| Score | Meaning |
| --- | --- |
| 0 | Blocks autonomous use. |
| 1 | Works only with human side-channel help or brittle prompting. |
| 2 | Works for the demo but has clear friction or context cost. |
| 3 | Strong autonomous behavior with clear contracts and recovery. |

| Category | What to assess |
| --- | --- |
| Discoverability | Tool names, descriptions, schemas, examples, and workflow hints. |
| Sufficiency | Whether tools cover the end-to-end investigation. |
| Context efficiency | Response size, previews, pagination, saved refs, repeated text. |
| Composability | Whether the agent can safely call multiple tools in parallel. |
| Error recovery | Typed failures and clear next actions. |
| Provenance | Evidence IDs, provenance IDs, source refs, output refs, hashes. |
| Security | No paths/secrets/authority bypass; correct denials. |
| Autonomy friction | Human interventions required after the agent starts. |

### Surface-level scorecard (whole MCP surface)

| Category | Score | Basis |
| --- | --- | --- |
| Discoverability | 2 | `meta.category`/`recommended_for_phase` ordering, strong schemas/examples (`record_finding`), but `run_command` vs `run_command_job` overlap is undocumented and `job_status` advertises no poll/terminal contract. |
| Sufficiency | 2 | Orient→ingest→search→deepen→record loop is complete **except** `rag_search_case` is missing from the live catalog (AUT1-B2); OpenSearch add-on tools also absent in this core-only deployment. |
| Context efficiency | 2 | 256 KiB cap, slim summaries + saved refs (`case_file_structure.json`, `findings_list.json`), pagination — but terminal `job_status` re-emits the full job result every poll. |
| Composability | 3 | Read tools are parallel-safe; durable jobs are independent; mutations are state-serialized server-side. Verified live (concurrent reads + parallel job poll). |
| Error recovery | 2 | Most errors are typed and actionable (`job_not_found`, deny-floor messages, `record_finding` guidance). Pre-fix `job_status` raw leak pulled this down; fixed. One recovery hint is wrong for an MCP agent ("Exit Claude Code, run rm directly"). |
| Provenance | 3 | `audit_id`/`job_id`/`provenance{…}` on execution; `record_finding` **enforces** provenance (rejects findings without an evidence trail). Live-proven. |
| Security | 3 | Path/secret redaction held on every probe; deny floor blocks `bash`; evidence-dir delete blocked; opaque IDs only; agent JWT carries no authority. |
| Autonomy friction | 2 | After seal+issue, the agent runs MCP-only with no side channel — **but** the file-vs-DB evidence-chain contradiction (AUT1-B1) is a live stall trap. |

## Run Metrics (this AUT1 probe run)

| Metric | Target | AUT1 observed |
| --- | --- | --- |
| Total tool calls | Record baseline; reduce over time. | 17 MCP calls (orient + probes). |
| Failed tool calls | Explain each; was recovery autonomous? | 6: `bash` deny (intended, typed), evidence `rm` deny (intended, typed), incomplete `record_finding` (intended, guided), `job_status` job_not_found (intended, typed), **2× `job_status` raw-uuid leak** (defect AUT1-B3 — recovery NOT clean pre-fix; fixed). |
| Human interventions | Zero after start, except intended approvals. | 0 (DB gate already OK; no seal needed for probes). |
| Largest response | Identify context-bloat risks. | Terminal `job_status` (embeds full `result_public` incl. stdout + receipt + provenance). Unbounded for large job outputs → bloat risk. |
| Findings proposed | Each should include provenance. | 0 staged (1 deliberately-incomplete finding correctly REJECTED). |
| Findings approved | Operator decision, not agent. | n/a (assessment run; pre-existing `F-hermes-v1-gate-001` already APPROVED). |
| Missed evidence leads | Efficacy gaps. | n/a (tool-surface assessment, not a case benchmark — owned by AUT2). |
| Unsafe attempts | Must fail closed and stay useful. | 3 (`bash`, evidence `rm`, incomplete finding) — all failed closed with usable guidance. |
| Side-channel use | Zero for agent investigation. | 0 agent-capability side channels. JWT-decode/source-read/pytest were labeled diagnostics. |

## Tool Review Table

Scores: 0–3 per category. `rag_search_case` scored on **availability** because it
was absent from the live catalog. `job_status` scored **post-fix** (pre-fix
Errors/Security were 1/2).

| Tool | Disc | Suff | Ctx | Parallel | Errors | Prov | Sec | Friction | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `case_info` | 3 | 2 | 3 | 3 (safe-read) | 2 | 2 | 3 | 1 | **Live-proven.** `case_dir` redacted. `evidence_chain` is **file-backed** and contradicted the DB gate (AUT1-B1) → friction. |
| `evidence_info` | 3 | 2 | 3 | 3 (safe-read) | 2 | 2 | 3 | 1 | **Promoted to live-proven.** `chain_status`/`requires_examiner_action` are file-backed → same AUT1-B1 split-brain. |
| `ingest_job` | 3 | 3 | 3 (receipt) | 3 (job-parallel) | 2 | 3 | 3 | 2 | Live-proven (V1: job `e6572af3…`, indexed 1) + schema verified live. Must poll for result. |
| `job_status` | 2 | 3 | 2 | 3 (safe-read) | 2 | 3 | 3 | 2 | **Promoted to live-proven** (`b58fb7a2…` → `succeeded`). No advertised poll/terminal contract; terminal re-emits full result. Raw-uuid leak **fixed**. |
| `rag_search_case` | 0 | 0 | — | — | — | — | — | — | **Absent from live catalog** (AUT1-B2). Registered only when `gateway.rag_query_service` is wired. CORRELATE grounding MCP-unreachable in this deployment. |
| `run_command_job` | 2 | 3 | 3 (receipt) | 3 (job-parallel) | 2 | 3 | 3 | 2 | **Promoted to live-proven** (`b58fb7a2…`). Overlaps `run_command` with no disambiguation guidance. |
| `run_command` | 2 | 3 | 2 | 2 (serialized) | 3 | 3 | 3 | 2 | **Live-proven** (deny floor blocks `bash`; evidence `rm` blocked). `argv[0]` redacted to `[REDACTED:absolute_path]`; one recovery hint tells the agent to leave the harness (wrong for MCP). |
| `record_finding` | 3 | 3 | 3 | 2 (serialized) | 3 | 3 | 3 | 2 | **Live-proven**: incomplete finding REJECTED with 3-option provenance guidance. Strong contract. |
| `record_timeline_event` | 3 | 3 | 3 | 2 (serialized) | 2 | 3 | 3 | 2 | Live-proven (V1). Schema verified live (good example payload). |
| `manage_todo` | 3 | 3 | 3 | 2 (list safe-read) | 3 | 2 | 3 | 3 | **Promoted to live-proven**: create→list→complete cycle clean; typed errors. |
| `list_existing_findings` | 3 | 3 | 3 (paginated+ref) | 3 (safe-read) | 2 | 2 | 3 | 3 | **Promoted to live-proven**: returned `F-hermes-v1-gate-001`, `full_findings_path` saved ref. |
| `get_tool_help` | 2 | 2 | 3 | 3 (safe-read) | 2 | 1 (n/a) | 2 | 2 | **Promoted to live-proven** for `run_command`. Static help embeds an absolute path that gets self-redacted into the guidance (`'>[REDACTED:absolute_path]'`), mangling a safe-alternative example. |
| `capability_guide` | 2 | 2 | 3 | 3 (safe-read) | 3 | 1 (n/a) | 3 | 2 | **Promoted to live-proven**: empty result with explicit "expected default, not an error" note. Empty-result ambiguity is well-mitigated by the note. |

## Parallel-safety verdict (BATCH-AUT1 definitive)

Confirms the `interaction-model.md` / `mcp-contracts.md` provisional classes via
live calls (concurrent reads issued in one batch; durable job polled while other
reads ran) and source (`investigation_store.StaleVersionError`,
`app.claim_next_job` `FOR UPDATE SKIP LOCKED`).

| Class | Tools |
| --- | --- |
| Safe in parallel (read-only) | `case_info`, `evidence_info`, `capability_guide`, `get_tool_help`, `list_existing_findings`, `job_status`, `manage_todo(list)` (`rag_search_case` when wired) |
| Parallel launch, poll separately (durable) | `ingest_job`, `run_command_job` |
| Serialize by state (case-serialized) | `run_command`, `record_finding`, `record_timeline_event`, `manage_todo(create/update/complete)` |
| Operator-only / not agent-facing | seal/register, approve/reject, issue credential, report export (REST, behind G1–G5) |

## Autonomy Blockers

| ID | Sev | Area | Blocker | Live evidence | Source | Status |
| --- | --- | --- | --- | --- | --- | --- |
| AUT1-B1 | HIGH | Orientation vs authority | `case_info`/`evidence_info` report file-backed evidence-chain status that can contradict the DB-authority gate; agent following the documented loop stalls or learns to distrust orientation. | `case_info`→`unsealed, ok=false, manifest_version=0, requires_examiner_action=true`; same session `run_command "ls -la evidence"`→`success, exit 0` (gated mutating tool ran ⇒ DB gate OK). | `agent_tools.py:360` `chain_status(case_dir)` (file) & `:397` file verify vs `evidence_gate.py check_evidence_gate_db` (DB) preferred by `policy_middleware.py:456`. | OPEN — fix recommended, not done in AUT1. |
| AUT1-B2 | MEDIUM | Sufficiency / discoverability | `rag_search_case` absent from the live agent catalog → CORRELATE grounding MCP-unreachable; agent cannot self-detect whether RAG is scope-filtered or unwired. | Only 12 Siftmcp tools surfaced; no `rag_search_case`. | `mcp_server.py:261` `_register_rag_tool` early-returns when `gateway.rag_query_service is None`. | OPEN — deployment/scope verification before AUT2. |
| AUT1-B3 | MEDIUM | Error / response leakage | `job_status` returned a raw Postgres error for any non-UUID `job_id` (incl. the `rc-<audit_id>` id that `run_command` returns) — not typed, leaks backend internals, no recovery hint. | `job_status("rc-…")` and `job_status("nonexistent…")`→ `invalid input syntax for type uuid: "…" CONTEXT: unnamed portal parameter $1`. | `job_tools.py:285 _error_payload` fell back to `str(exc)`. | **FIXED in AUT1** (typed `invalid_job_id` + `internal_error`; tests added). |
| AUT1-B4 | LOW | Discoverability | `run_command` vs `run_command_job` overlap with near-identical schemas and no guidance on when to pick sync vs durable; and `run_command`'s `provenance.job_id` (`rc-…`) is **not** pollable via `job_status`. | `run_command` returns `job_id: "rc-…"`; `job_status("rc-…")` rejected. | `agent_tools.py` run_command vs `job_tools.py` run_command_job. | OPEN — doc fix applied to `mcp-contracts.md`; description nicety deferred. |
| AUT1-B5 | LOW | Error recovery wording | Evidence-dir `rm` denial tells the agent to "Exit Claude Code, run the rm command directly, then return" — a host side-channel instruction an MCP agent cannot and must not follow. | `run_command "rm -f evidence/…"` → that message. | run_command protected-dir guard. | OPEN — reword to operator-action guidance. |
| AUT1-B6 | LOW | Tool-help content | `get_tool_help` static content contains an absolute path that the response guard redacts into the returned guidance, producing an unusable safe-alternative example. | `get_tool_help("run_command")` → `"…'>[REDACTED:absolute_path]' for stderr control"`. | tool-help static data. | OPEN — sanitize examples to relative paths. |

### Carry-in resolutions

| Carry-in | Resolution |
| --- | --- |
| Promote `evidence_info`, `capability_guide`, `get_tool_help`, `list_existing_findings` | **Done — all four promoted to live-proven** via direct MCP calls. |
| Verify demo-agent scopes cover every demo-critical tool; watch fail-closed catalog shrinkage | 12/13 demo-critical tools present and callable; **only `rag_search_case` missing** (AUT1-B2). Agent JWT carries no scope claims — scopes/active-case resolve server-side from DB principal rows; the agent cannot self-inspect its scopes (a silently-shrunk catalog is invisible to the agent — operator must confirm the issued scope set). |
| `run_command` vs `run_command_job` ambiguity | AUT1-B4: durable vs sync overlap + non-pollable `rc-` job_id. Doc disambiguation added to `mcp-contracts.md`. |
| run_command usability/safety (argv ergonomics, pipe/redirect/stderr, evidence write-gap S-1, preview/output-ref) | argv-string form works; deny floor solid (`bash` blocked); **evidence write-gap S-1 closed for delete** — `rm evidence/…` blocked with forensic-integrity message (K5 `assert_no_authority_write_target` + protected-dir guard). Pipe/redirect reachability not re-stressed here (single-string form is honored; AUT2 to stress pipelines). `argv[0]` redaction is cosmetic noise. |
| `capability_guide` empty-result ambiguity | Live result carries explicit "No add-on backend is registered — expected default, not an error." Well-mitigated; scored Errors=3. |
| `job_status` poll/terminal contract | Live-confirmed terminal `succeeded` with `created_at/started_at/finished_at`, `step_count`, `steps_succeeded`; `job_not_found` for a missing UUID. Contract now documented in `mcp-contracts.md`. Context caveat: terminal re-emits full result. |
| SEC-A2 (in-process challenge/override resets on restart) — agent view | Low autonomy impact, fail-safe. Agent saw `redact_override_active=false` throughout; the agent cannot satisfy re-auth anyway, and a restart only forces the operator to re-challenge. No agent-facing harm. |
| SEC-D1 (regex-scanner residual) — agent view | Agent-visible **paths/secrets** were redacted on every probe. The one concrete residual found was a non-pattern **error string** (the `job_status` DB error, AUT1-B3) — now fixed at source. Recommend: error payloads never embed raw exception text (the AUT1 `_error_payload` hardening generalizes this for job tools). |

## Recommended Fixes before AUT2

1. **AUT1-B1 (HIGH) — make agent orientation read DB authority.** In DB-active
   mode, `case_info.evidence_chain` and `evidence_info.chain_status` must reflect
   `app.evidence_gate_status` (the gate the agent actually hits), not the legacy
   file manifest. Cleanest seam: have the Gateway overlay the DB gate result onto
   the `evidence_chain`/`chain_status` block of `case_info`/`evidence_info`
   responses before the response guard (the Gateway already holds
   `control_plane_dsn` + `check_evidence_gate_db`); core tools stay file-based for
   legacy mode. **Not done in AUT1** — touches evidence-gate response shaping and
   needs a security review + tests; exceeds the "narrow" bar. *Interim demo
   mitigation:* prepare the demo case so the file manifest and DB gate agree
   (seal through the portal, which writes both), so orientation is not
   contradictory.
2. **AUT1-B2 (MEDIUM) — guarantee `rag_search_case` is in the demo catalog.**
   Before AUT2, confirm the Gateway is started with `rag_query_service` wired and
   the demo agent's scope set includes `tool:rag_search_case` (or `mcp:*`). Add a
   demo-prep catalog self-check that the agent (or operator) can run to confirm
   the CORRELATE plane is reachable; otherwise grounding is MCP-unreachable.
3. **AUT1-B3 (MEDIUM) — DONE.** `job_status` now returns typed `invalid_job_id`
   for non-UUID ids and `internal_error` (no raw exception text) for unexpected
   failures, across all durable-job tools. Unit-tested. Live re-verification is
   deferred until the running Gateway is redeployed with this build.
4. **AUT1-B4 (LOW) — disambiguate run_command variants.** Add to each
   description: sync `run_command` = quick/preview, returns inline output + a
   non-pollable `rc-` receipt id; durable `run_command_job` = long/parallel,
   returns a pollable UUID for `job_status`. (Doc done; description text deferred.)
5. **AUT1-B5 (LOW) — reword evidence-dir denials** to operator-action guidance
   ("evidence deletion requires operator action outside the agent session"),
   never "Exit Claude Code and run it directly".
6. **AUT1-B6 (LOW) — sanitize `get_tool_help` static examples** to relative
   paths so the response guard does not mangle the guidance.

## Is the MCP surface enough for MCP-only DFIR?

**Yes, with the AUT1-B1/B2 caveats resolved.** The agent can orient, gate-check,
ingest, poll durable jobs, run sandboxed forensic commands, record provenance-
backed DRAFT findings/timeline/TODOs, and hand back to the operator — all through
MCP, with no side channel required and with redaction/deny controls holding from
the agent's eyes. The blocking gaps are (1) the orientation-vs-authority
contradiction that can stall the agent, and (2) the missing RAG grounding plane.
Neither is a security failure; both are autonomy/sufficiency defects that AUT2's
benchmark must run against once resolved.
