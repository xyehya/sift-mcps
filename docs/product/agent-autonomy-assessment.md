# Agent Autonomy Assessment

Status: filled (BATCH-AUT1/AUT2, live-exercised). Validation owners:
BATCH-AUT1 (tool-surface assessment) and BATCH-AUT2 (demo-case benchmark).
Last updated: 2026-06-10.

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
   needlessly. **FIXED in BATCH-INST1** (2026-06-09): the Gateway now overlays the
   DB-authority gate onto `case_info`/`evidence_info` orientation; live-proven
   (`status=ok, ok=true, manifest_version=2, authority=db`). See
   `docs/migration/Session-Notes.md` (BATCH-INST1).
2. **AUT1-B2 (MEDIUM, sufficiency):** `rag_search_case` is **absent from this
   agent's live catalog** — the CORRELATE/grounding plane is unavailable to the
   agent in the assessed AUT1 deployment. **CLOSED LIVE FOR AUT2:** a fresh
   portal-issued `mcp:*` agent saw a 13-tool catalog including
   `rag_search_case`, and RAG returned scoped, redacted results.
3. **AUT1-B3 (MEDIUM, error/security) — FIXED in AUT1:** `job_status` leaked a
   raw Postgres error (`invalid input syntax for type uuid … unnamed portal
   parameter $1`) for any malformed `job_id`, including the non-UUID `job_id`
   that `run_command` itself returns. Fixed: typed `invalid_job_id` + generic
   `internal_error` (no raw exception text) for all durable-job tools.

**AUT2 verdict:** Partial. The live system is ready for a controlled
smoke/custody demo in which an MCP-only agent orients, discovers evidence,
searches RAG, records a limited finding/timeline/TODO, and hands back for portal
approval/reporting. It is **not** ready to claim a full autonomous Rocba
disk+memory investigation. Original benchmark score: **14/24**. After the
2026-06-10 autonomy remediation pass, the current score is **17/24**.

## BATCH-AUT2 Demo-Case Benchmark (2026-06-09)

### Readiness Verified

- Active case: `case-v1gate-06081857`
  (`57a06521-c9b8-4654-92ac-42b4f2bb0915`), status open.
- Evidence gate: DB authority, `status=ok`, `manifest_version=3`, no gate
  issues. Portal/DB evidence contained four active sealed objects:
  `rocba-cdrive.e01`, `Rocba-Memory.raw`, `v1-gate.log`, and
  `v1-ingest.jsonl`.
- Fresh portal-issued `mcp:*` agent catalog: 13 tools, including
  `rag_search_case`. RAG corpus baseline remained `app.rag_chunks=26586`.
- Live service health was checked on the active VM tree
  `/home/sansforensics/sift-mcps-test`; Gateway and worker were active and
  health returned OK.

### Run Metrics

| Metric | AUT2 observed |
| --- | --- |
| Fresh-client MCP calls | 30 calls across two fresh portal-issued agents, plus supplemental conductor MCP calls to stage records and reproduce failures. |
| Failed calls | Fresh pass: 6 failed calls; deep pass: 2 parser-counted failed calls. Supplemental probes added policy/tool failures for Volatility cache, `grep -E`, `env`, and cache-directory creation. |
| Human interventions | 0 after agent start except intended operator approval/report generation through the portal. Portal credentials were used only for operator actions and fresh agent issuance. |
| Largest responses | RAG largest fresh response: 5,254 bytes. Binary memory `grep` previews reached 42-72 KB stdout totals despite caps/truncation, creating context-bloat risk. |
| Findings/timeline/TODOs | Finding `F-codex-1-001`, timeline event `T-codex-1-002`, and TODO `TODO-codex-1-001` were staged through MCP. |
| Operator approval/report | Portal commit approved 1 finding with DB authority; report eligibility flipped to eligible; findings-profile report `1ff91996-5666-4b36-9568-c701f5204c24` generated, saved, downloaded, and passed the AUT2 quick secret-shape scan. |
| Unsafe attempts | `rm -f evidence/v1-gate.log` failed closed with the forensic-integrity operator-workflow message. No side-channel delete succeeded. |
| Missed leads | Primary disk and memory image corroboration was blocked by tooling, so memory-string hits such as PowerShell/HTTP/certutil-like strings remain speculative and were not promoted to findings. |

### AUT2 Scorecard

| Category | Score | Basis |
| --- | --- | --- |
| Discoverability | 2 | The 13-tool catalog is visible and RAG is present for fresh `mcp:*` agents. Residuals remain: `evidence_info.evidence_files` is empty under DB authority, and summary counters can disagree with DB-backed lists. |
| Sufficiency | 1 | The smoke loop works, but `.e01`/`.raw` single-file ingest fails and deeper disk/memory analysis is not usable enough for a full Rocba investigation. |
| Context efficiency | 1 | RAG responses are bounded, but binary `grep` previews produced tens of KB of noisy output and `job_status` terminal payloads remain verbose. Response-guard false positives redacted URL schemes and benign headings. |
| Composability | 2 | Durable jobs, reads, RAG, and record/list calls compose, but pipelines can mask upstream forensic-tool failures (`fls | head` returned wrapper success while `fls` errored). |
| Error recovery | 2 | Unsupported ingest and protected delete failures were clear. Some failures are still weak: `mmls` returned exit 1 with no stderr, Volatility surfaced a raw Python traceback, and `evidence_refs` says "no sealed evidence" on a DB-sealed case. |
| Provenance | 1 | `run_command` returns audit/provenance receipts and hashes, but `record_finding` rejected a fresh returned `audit_id` because artifact validation still scans the local JSONL audit trail rather than DB audit authority. The finding could only be staged with PARTIAL/NONE supporting-command provenance. |
| Security | 3 | Path/secret redaction held from the agent view, deletion of sealed evidence failed closed, raw tokens/secrets were not exposed, and report download secret-shape scan was clean. |
| Autonomy friction | 2 | The controlled smoke required no side-channel after start except intended portal approval/reporting, but the primary-image blockers force a handback before full investigation completion. |

Total: **14/24**.

### AUT2 Remediation Scorecard (2026-06-10)

| Category | Score | Remediation basis |
| --- | --- | --- |
| Discoverability | 3 | `evidence_info` now lists all four sealed DB evidence objects with evidence IDs, hashes, sizes, and relative display paths. Fresh `mcp:*` agents still see the 13-tool catalog including RAG. |
| Sufficiency | 1 | Primary-image ingest and deeper disk/memory analysis remain blocked, so full Rocba investigation is still out of scope. |
| Context efficiency | 2 | Repeated active-case context is now limited to orientation tools, and saved outputs return reusable `agent/run_commands/...` refs. Large binary search previews still need stronger defaults. |
| Composability | 2 | `run_command` and `run_command_job` now compose with DB evidence refs and reusable saved-output refs. Pipeline masking and some forensic-tool behavior still need work. |
| Error recovery | 2 | DB evidence-ref failures are resolved; `rg` now fails clearly because the binary is absent. Volatility and EWF/TSK failures remain weak. |
| Provenance | 2 | `run_command` and durable job receipts now record DB evidence IDs and input hashes for sealed evidence refs. `record_finding` still cannot validate those receipts through DB audit authority. |
| Security | 3 | Path/secret redaction still holds; sealed evidence reads resolve internally; client-supplied private evidence resolver fields are stripped/rejected. |
| Autonomy friction | 2 | Fresh agent TTL is now about 48 hours and core smoke no longer needs evidence-listing or `input_files` workarounds, but primary-image blockers still force handback. |

Total after remediation: **17/24**.

### AUT2 Blockers and Caveats

| ID | Sev | Area | Live evidence | Status for BATCH-FRZ1 |
| --- | --- | --- | --- | --- |
| AUT2-B1 | HIGH | Large-evidence ingest | `ingest_job evidence/rocba-cdrive.e01` and `ingest_job evidence/Rocba-Memory.raw` queued then failed with `unsupported single-file evidence format for ingest job`. Positive control `v1-ingest.jsonl` succeeded. | Must be fixed or demo must avoid claiming primary-image ingest. |
| AUT2-B2 | HIGH | DB authority/provenance | Original AUT2: `run_command` with `evidence_refs` for DB-sealed evidence failed before execution: "the case has no sealed evidence." 2026-06-10 remediation: `run_command` and `run_command_job` with `evidence_refs=["evidence/v1-gate.log"]` succeeded and returned DB evidence ID/hash provenance. `grep` also read `Rocba-Memory.raw` through DB evidence refs. | **FIXED for Gateway/worker run_command paths.** Keep regression coverage; next provenance blocker is `record_finding` DB-audit validation. |
| AUT2-B3 | HIGH | Finding provenance | `record_finding` rejected immediately returned audit id `siftgateway-codex-1-20260609-212` as "not found in audit trail." The strong artifact-audit path still checks the local JSONL audit trail while Gateway audit authority is DB-first. | Fix before claiming provenance-grade findings from live `run_command` receipts. |
| AUT2-B4 | HIGH | Memory analysis | `vol` cannot start under `run_command`; it raises a cache-path `PermissionError`. Attempts to set `VOLATILITY_CACHE_PATH` or create cache dirs through MCP were blocked by policy/output-path validation. | Required before using the memory image as a real demo lead source. |
| AUT2-B5 | MEDIUM | Disk analysis | `mmls` against the EWF image returned exit 1 with no stderr; `fls -o 2048 ... | head` masked the upstream failure because the final pipeline stage succeeded. | Provide an EWF-aware approved extraction/mount workflow or improve forensic-tool error surfacing. |
| AUT2-B6 | MEDIUM | Orientation/listing | Original AUT2: `evidence_info` reported DB gate OK but `evidence_files=[]`. 2026-06-10 remediation: `evidence_info` returned all four sealed DB evidence objects with `listing_authority=db`. `case_info.findings` counters still lag behind `list_existing_findings`. | **PARTIAL.** Evidence listing fixed; summary counters still need DB-authority cleanup or mirror labeling. |
| AUT2-B7 | MEDIUM | Context/redaction | Original AUT2: repeated context and binary previews created bloat risk. 2026-06-10 remediation: non-orientation tools no longer append `case_context`; saved outputs return reusable relative refs. Binary memory search still needs safer default preview/file-first ergonomics. | **PARTIAL.** Context repetition and saved refs fixed; preview/redaction tuning remains. |
| AUT2-B8 | MEDIUM | Tool availability / inventory | 2026-06-10 live smoke: `rg` is not installed on the VM, while installed `grep` works against DB-sealed memory evidence. The agent has no first-class MCP tool inventory of available DFIR binaries. | Add an agent-facing installed-tool inventory and improve guidance for SIFT/DFIR tools before a polished autonomy demo. |

### Approved Demo Boundary

For BATCH-FRZ1, the safe demo claim is:

- The platform can run a sealed-case, MCP-only smoke investigation with scoped
  agent tools, RAG grounding, redaction, protected command execution, DRAFT
  proposal, operator approval, and approved-only report generation.

The unsafe claim is:

- A fully autonomous agent has completed substantive analysis of the Rocba disk
  and memory images. AUT2 did not establish that.

## BATCH-AUT1 Tool-Surface Probe (historical)

The sections below preserve the AUT1 tool-surface evidence. AUT2 supersedes the
live readiness status where noted above.

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
| Discoverability | 2 | `meta.category`/`recommended_for_phase` ordering, strong schemas/examples (`record_finding`). AUT1 found unclear `run_command`/`run_command_job` descriptions and missing `job_status` poll/terminal guidance; docs and live schema descriptions were updated, but live re-verification awaits redeploy. |
| Sufficiency | 2 | AUT1 showed the orient→ingest→search→deepen→record loop was complete **except** `rag_search_case` was missing from that live catalog (AUT1-B2). AUT2 closed this for fresh `mcp:*` agents. OpenSearch add-on tools remain absent in this core-only deployment. |
| Context efficiency | 2 | 256 KiB cap, slim summaries + saved refs (`case_file_structure.json`, `findings_list.json`), pagination — but terminal `job_status` re-emits the full job result every poll. |
| Composability | 3 | Read tools are parallel-safe; durable jobs are independent; mutations are state-serialized server-side. Verified live (concurrent reads + parallel job poll). |
| Error recovery | 2 | Most errors are typed and actionable (`job_not_found`, deny-floor messages, `record_finding` guidance). Pre-fix `job_status` raw leak and side-channel `rm` denial wording pulled this down; both are fixed in code/docs pending live redeploy. |
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
| `job_status` | 2 | 3 | 2 | 3 (safe-read) | 2 | 3 | 3 | 2 | **Promoted to live-proven** (`b58fb7a2…` → `succeeded`). Terminal re-emits full result. Raw-uuid leak **fixed**; poll/terminal contract documented. |
| `rag_search_case` | 0 | 0 | — | — | — | — | — | — | **AUT1 historical score:** absent from that live catalog (AUT1-B2). **AUT2 live status:** present and callable for fresh `mcp:*` agents. |
| `run_command_job` | 2 | 3 | 3 (receipt) | 3 (job-parallel) | 2 | 3 | 3 | 2 | **Promoted to live-proven** (`b58fb7a2…`). Description now says durable/pollable UUID path; live re-verification awaits redeploy. |
| `run_command` | 2 | 3 | 2 | 2 (serialized) | 3 | 3 | 3 | 2 | **Live-proven** (deny floor blocks `bash`; evidence `rm` blocked). `argv[0]` redacted to `[REDACTED:absolute_path]`; description now calls out non-pollable `rc-*` receipts and durable alternative. |
| `record_finding` | 3 | 3 | 3 | 2 (serialized) | 3 | 3 | 3 | 2 | **Live-proven**: incomplete finding REJECTED with 3-option provenance guidance. Strong contract. |
| `record_timeline_event` | 3 | 3 | 3 | 2 (serialized) | 2 | 3 | 3 | 2 | Live-proven (V1). Schema verified live (good example payload). |
| `manage_todo` | 3 | 3 | 3 | 2 (list safe-read) | 3 | 2 | 3 | 3 | **Promoted to live-proven**: create→list→complete cycle clean; typed errors. |
| `list_existing_findings` | 3 | 3 | 3 (paginated+ref) | 3 (safe-read) | 2 | 2 | 3 | 3 | **Promoted to live-proven**: returned `F-hermes-v1-gate-001`, `full_findings_path` saved ref. |
| `get_tool_help` | 2 | 2 | 3 | 3 (safe-read) | 2 | 1 (n/a) | 2 | 2 | **Promoted to live-proven** for `run_command`. Static self-redacting stderr example fixed in source; live re-verification awaits redeploy. |
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
| AUT1-B1 | HIGH | Orientation vs authority | `case_info`/`evidence_info` report file-backed evidence-chain status that can contradict the DB-authority gate; agent following the documented loop stalls or learns to distrust orientation. | `case_info`→`unsealed, ok=false, manifest_version=0, requires_examiner_action=true`; same session `run_command "ls -la evidence"`→`success, exit 0` (gated mutating tool ran ⇒ DB gate OK). | `agent_tools.py:360` `chain_status(case_dir)` (file) & `:397` file verify vs `evidence_gate.py check_evidence_gate_db` (DB) preferred by `policy_middleware.py:456`. | **FIXED in BATCH-INST1** — `mcp_server._overlay_db_evidence_gate` overlays the DB gate onto orientation in DB-active mode; live-proven `status=ok, authority=db`. |
| AUT1-B2 | MEDIUM | Sufficiency / discoverability | `rag_search_case` absent from the AUT1 live agent catalog → CORRELATE grounding MCP-unreachable; agent cannot self-detect whether RAG is scope-filtered or unwired. | AUT1: only 12 Siftmcp tools surfaced; no `rag_search_case`. AUT2: fresh `mcp:*` agents surfaced 13 tools including `rag_search_case`. | `mcp_server.py:261` `_register_rag_tool` early-returns when `gateway.rag_query_service is None`. | **CLOSED LIVE FOR AUT2** — deployment/scope verified with fresh agent issuance. |
| AUT1-B3 | MEDIUM | Error / response leakage | `job_status` returned a raw Postgres error for any non-UUID `job_id` (incl. the `rc-<audit_id>` id that `run_command` returns) — not typed, leaks backend internals, no recovery hint. | `job_status("rc-…")` and `job_status("nonexistent…")`→ `invalid input syntax for type uuid: "…" CONTEXT: unnamed portal parameter $1`. | `job_tools.py:285 _error_payload` fell back to `str(exc)`. | **FIXED in AUT1** (typed `invalid_job_id` + `internal_error`; tests added). |
| AUT1-B4 | LOW | Discoverability | `run_command` vs `run_command_job` overlap with near-identical schemas and no guidance on when to pick sync vs durable; and `run_command`'s `provenance.job_id` (`rc-…`) is **not** pollable via `job_status`. | `run_command` returns `job_id: "rc-…"`; `job_status("rc-…")` rejected. | `agent_tools.py` run_command vs `job_tools.py` run_command_job. | **FIXED in AUT1 conductor pass** — descriptions now distinguish sync `run_command` from durable `run_command_job`; tests added. |
| AUT1-B5 | LOW | Error recovery wording | Evidence-dir `rm` denial tells the agent to "Exit Claude Code, run the rm command directly, then return" — a host side-channel instruction an MCP agent cannot and must not follow. | `run_command "rm -f evidence/…"` → that message. | run_command protected-dir guard. | **FIXED in AUT1 conductor pass** — denial now tells the agent to hand back to the operator/approved evidence workflow; test added. |
| AUT1-B6 | LOW | Tool-help content | `get_tool_help` static content contains an absolute path that the response guard redacts into the returned guidance, producing an unusable safe-alternative example. | `get_tool_help("run_command")` → `"…'>[REDACTED:absolute_path]' for stderr control"`. | tool-help static data. | **FIXED in AUT1 conductor pass** — static example now avoids absolute-path text; test added. |

### Carry-in resolutions

| Carry-in | Resolution |
| --- | --- |
| Promote `evidence_info`, `capability_guide`, `get_tool_help`, `list_existing_findings` | **Done — all four promoted to live-proven** via direct MCP calls. |
| Verify demo-agent scopes cover every demo-critical tool; watch fail-closed catalog shrinkage | AUT1: 12/13 demo-critical tools present, with `rag_search_case` missing. AUT2: fresh portal-issued `mcp:*` agents surfaced all 13 tools including `rag_search_case`. Agent JWT carries no scope claims — scopes/active-case resolve server-side from DB principal rows; the agent cannot self-inspect its scopes, so operator/fresh-client catalog verification remains required. |
| `run_command` vs `run_command_job` ambiguity | AUT1-B4 fixed in conductor pass: docs and tool descriptions now distinguish sync `run_command` (`rc-*` receipt, not pollable) from durable `run_command_job` (pollable UUID). |
| run_command usability/safety (argv ergonomics, pipe/redirect/stderr, evidence write-gap S-1, preview/output-ref) | argv-string form works; deny floor solid (`bash` blocked); **evidence write-gap S-1 closed for delete** — `rm evidence/…` blocked with forensic-integrity message (K5 `assert_no_authority_write_target` + protected-dir guard). Pipe/redirect reachability not re-stressed here (single-string form is honored; AUT2 to stress pipelines). `argv[0]` redaction is cosmetic noise. |
| `capability_guide` empty-result ambiguity | Live result carries explicit "No add-on backend is registered — expected default, not an error." Well-mitigated; scored Errors=3. |
| `job_status` poll/terminal contract | Live-confirmed terminal `succeeded` with `created_at/started_at/finished_at`, `step_count`, `steps_succeeded`; `job_not_found` for a missing UUID. Contract now documented in `mcp-contracts.md`. Context caveat: terminal re-emits full result. |
| SEC-A2 (in-process challenge/override resets on restart) — agent view | Low autonomy impact, fail-safe. Agent saw `redact_override_active=false` throughout; the agent cannot satisfy re-auth anyway, and a restart only forces the operator to re-challenge. No agent-facing harm. |
| SEC-D1 (regex-scanner residual) — agent view | Agent-visible **paths/secrets** were redacted on every probe. The one concrete residual found was a non-pattern **error string** (the `job_status` DB error, AUT1-B3) — now fixed at source. Recommend: error payloads never embed raw exception text (the AUT1 `_error_payload` hardening generalizes this for job tools). |

## AUT1 Recommended Fixes before AUT2

1. **AUT1-B1 (HIGH) — make agent orientation read DB authority.** In DB-active
   mode, `case_info.evidence_chain` and `evidence_info.chain_status` must reflect
   `app.evidence_gate_status` (the gate the agent actually hits), not the legacy
   file manifest. Cleanest seam: have the Gateway overlay the DB gate result onto
   the `evidence_chain`/`chain_status` block of `case_info`/`evidence_info`
   responses before the response guard (the Gateway already holds
   `control_plane_dsn` + `check_evidence_gate_db`); core tools stay file-based for
   legacy mode. **DONE in BATCH-INST1** — implemented as
   `mcp_server._overlay_db_evidence_gate` (fail-safe, DB-active only, adds an
   `authority: "db"` marker), unit-tested and live-proven on the demo case.
   *Residual:* `evidence_info`'s evidence *listing* is still file-backed (a
   DB-sealed case with an absent local manifest shows `chain_status=ok` with an
   empty `evidence_files`), tracked in `known-limitations-and-improvements.md`.
2. **AUT1-B2 (MEDIUM) — DONE FOR AUT2.** Fresh portal-issued `mcp:*` agents saw
   the 13-tool catalog including `rag_search_case`, and the tool returned
   redacted RAG/knowledge results. Keep the fresh-client catalog self-check in
   the final runbook because stale clients can cache older catalogs.
3. **AUT1-B3 (MEDIUM) — DONE.** `job_status` now returns typed `invalid_job_id`
   for non-UUID ids and `internal_error` (no raw exception text) for unexpected
   failures, across all durable-job tools. Unit-tested. Live re-verification is
   deferred until the running Gateway is redeployed with this build.
4. **AUT1-B4 (LOW) — DONE in conductor pass.** Descriptions now state:
   synchronous `run_command` returns inline output plus a non-pollable `rc-*`
   receipt id; durable `run_command_job` returns a pollable UUID for
   `job_status`.
5. **AUT1-B5 (LOW) — DONE in conductor pass.** Evidence-dir deletion denials now
   instruct the agent to hand back to the operator/approved evidence workflow,
   never to leave the MCP harness.
6. **AUT1-B6 (LOW) — DONE in conductor pass.** `get_tool_help` static examples
   avoid absolute-path text that self-redacts in returned guidance.

## Is the MCP surface enough for MCP-only DFIR?

**For a controlled smoke/custody demo: yes, with caveats. For a full primary
disk+memory investigation: not yet.** AUT2 proved the agent can orient against a
DB-sealed case, enumerate evidence with `run_command`, use RAG, stage a limited
finding/timeline/TODO, and hand back to the operator for approval/reporting
without side-channel investigation work. AUT2 also proved the current surface
cannot yet complete substantive Rocba disk+memory analysis through MCP alone:
large single-file ingest, DB-backed `evidence_refs`, strong finding provenance,
Volatility, and EWF triage all need follow-up before BATCH-FRZ1 can claim more
than the smoke/custody story.
