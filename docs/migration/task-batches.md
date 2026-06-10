# Task Batches

Status: MVP sprint execution tracker plus OpenSearch restoration track.
Last updated: 2026-06-10.

Rules:

- Use one worktree per batch when running parallel sessions.
- Checkboxes are grep targets. Mark only the leading batch checkbox when the
  batch acceptance checks pass.
- Do not start dependent work until dependencies are checked complete or the
  blocking decision is resolved in `Session-Notes.md`.
- Resolve blockers on spot for dependent work. Independent batches may proceed.
- Keep new planning in this file. Do not create more migration docs.
- `docs/migration` is intentionally trimmed to this tracker plus
  `Session-Notes.md`; do not restore `Migration-Spec.md`.
- Parallel worker branches must not all edit `docs/migration`. A worker returns
  a landing log block; the integration/conductor session updates this tracker
  and `Session-Notes.md` after merge.

## Batch Index

- [x] BATCH-A0 - Freeze simplified migration operating model
- [x] BATCH-A1 - Final installer, Supabase bootstrap, forced reset, and health contract
- [x] BATCH-B1 - Gateway policy parity and agent response redaction
- [x] BATCH-C1 - DB evidence authority, custody ledger, and seal broker
- [x] BATCH-D1 - Durable Postgres jobs and local worker claim loop
- [x] BATCH-D2 - Gateway job adapter and add-on authority enforcement
- [x] BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports
- [x] BATCH-F1 - OpenSearch secure core integration and ingest job adapter
- [x] BATCH-G1 - RAG pgvector target with provenance filters
- [x] BATCH-H1 - Add-on contract hardening for OpenCTI, Windows triage, and forensic knowledge
- [x] BATCH-I1 - Sandboxed run_command uplift
- [x] BATCH-J1 - Approved-only report generation and export
- [x] BATCH-L1 - Live service binding, worker bootstrap, and Gateway tool bridge
- [x] BATCH-K0 - Authority cutover impact model and batch freeze
- [x] BATCH-K1 - Authority context and DB audit cutover
- [x] BATCH-K2 - Core investigation DB authority cutover
- [x] BATCH-K3 - Evidence gate, proof export, and Solana anchor cutover
- [x] BATCH-K4 - OpenSearch derived-state and host identity cutover
- [x] BATCH-K5 - run_command authority-isolation hardening
- [x] BATCH-K6 - Portal/report tamper regression and file-authority removal
- [x] BATCH-V1 - End-to-end validation and cutover
- [x] BATCH-PQA0 - Post-MVP QA and product documentation operating model
- [x] BATCH-PDOC1 - Product architecture, journeys, lifecycles, and code map
- [x] BATCH-PDOC2 - API, MCP, and interaction contract documentation
- [x] BATCH-SEC1 - Security architecture and assessment baseline
- [x] BATCH-INST1 - Installer and component hardening QA
- [x] BATCH-AUT1 - AI agent autonomy and MCP tool-surface assessment
- [x] BATCH-AUT2 - Demo-case autonomous investigation benchmark
- [ ] BATCH-FRZ1 - Final freeze rehearsal, limitations, and demo runbook
- [x] BATCH-OS0 - OpenSearch disappearance baseline and restoration order
- [x] BATCH-OS1 - DB backend seed and aggregate catalog visibility
- [x] BATCH-OS2 - Active-case proxy compatibility for OpenSearch tools
- [x] BATCH-OS3 - Read-only OpenSearch investigation surface
- [x] BATCH-OS4 - Job-backed ingest using standalone OpenSearch code
- [x] BATCH-OS5 - Host identity, enrichment, and mutating-tool policy
- [ ] BATCH-OS6 - Live VM OpenSearch proof
- [x] BATCH-PMI0 - Installer hardening + Supabase CLI bring-up (one-session bare-SIFT)
- [x] BATCH-PMI1 - OpenSearch 3.5 cutover + Sigma-disable/Security-Analytics cleanup
- [x] BATCH-PMI2 - RAG single-home: remove standalone Chroma kb_search_* path (decision SUPERSEDED by BATCH-OSX-RAG; see Session-Notes 2026-06-10 OSX plan)
- [ ] BATCH-PMI3 - FK enrichment actually fires (wire FK_DATA_DIR)
- [ ] BATCH-PMI4 - VM proof: bare-SIFT -> live stack -> Rocba case run
- [ ] BATCH-OSX1 - OpenSearch backend mounting fix (P1: seed-before-start race + dedupe double stdio spawn)
- [ ] BATCH-OSX2 - OpenSearch FastMCP surface optimization (tool defs/schemas/examples/prompts; advanced-tool-use)
- [ ] BATCH-OSX-RAG - Port forensic-rag-mcp tools to pgvector at full parity + remove rag_search_case shim
- [ ] BATCH-OSX3 - Programmatic tool-calling / code-execution-with-MCP feasibility spike (doc-first)
- [ ] BATCH-OSX-PURGE - Purge stale/unused (forensic-mcp, dead Chroma index modules, broken win-triage scripts)

## OpenSearch Restoration Operating Model

Decision:

- OpenSearch stays standalone in `packages/opensearch-mcp/**`.
- Gateway stays the only agent-facing policy boundary in
  `packages/sift-gateway/**`.
- Supabase/Postgres remains authority for cases, evidence, jobs, audit, host
  identity receipts, and ingest provenance.
- OpenSearch is a derived, secured, rebuildable search plane. It never
  authorizes cases, evidence, findings, approvals, or reports.

Current baseline to verify before implementation:

- Live aggregate MCP catalog was last recorded with 13 Gateway tools and no
  `opensearch_*` tools.
- Standalone manifest already declares `opensearch-mcp` with search, ingest,
  enrichment, host-fix, status, shard, and detection tools:
  `packages/opensearch-mcp/sift-backend.json`.
- Standalone registry/golden still shows the rich surface:
  `packages/opensearch-mcp/src/opensearch_mcp/registry.py`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py`,
  `packages/opensearch-mcp/tests/fixtures/mcp_surface_golden.json`.
- Gateway add-on visibility is controlled by DB registry + requirement gates:
  `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`,
  `packages/sift-gateway/src/sift_gateway/server.py`,
  `packages/sift-gateway/src/sift_gateway/mcp_server.py`.

Parallel order:

- OS0 is this conductor planning/baseline batch.
- OS1 and OS2 can run in parallel after OS0; integrate OS1 first if both touch
  backend catalog tests.
- OS3 starts after OS1 proves OpenSearch tools can appear in the aggregate
  catalog and OS2 proves active-case injection.
- OS4 and OS5 can run in parallel after OS2; both must treat mutating work as
  DB/job/audit backed or deny/redirect it.
- OS6 is last and must run only after local tests for OS1-OS5 pass.

Questions resolved before coding:

- Standalone versus core: standalone. Do not move parser/search code into
  sift-core.
- `gateway.yaml` versus DB registry: DB registry only. Do not re-enable YAML as
  authority.
- Agent ingest path: prefer `ingest_job` for real writes. Direct
  `opensearch_ingest(dry_run=False)` must be hidden, denied, or typed-redirected
  in DB-active mode unless Gateway can provide the same evidence/job/provenance
  envelope.

## BATCH-OS0 - OpenSearch disappearance baseline and restoration order

Dependencies: none.

Scope:

- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`
- Read-only inspection of:
  `packages/opensearch-mcp/sift-backend.json`,
  `packages/opensearch-mcp/src/opensearch_mcp/registry.py`,
  `packages/opensearch-mcp/src/opensearch_mcp/server.py`,
  `packages/sift-gateway/src/sift_gateway/mcp_server.py`,
  `packages/sift-gateway/src/sift_gateway/server.py`,
  `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`,
  `packages/sift-gateway/src/sift_gateway/policy_middleware.py`.

Exact work:

- Record why the OpenSearch track is reopened: agent autonomy needs indexed
  search, count, aggregate, timeline, event fetch, ingest, enrichment, and
  status tools through aggregate MCP.
- Add OS1-OS6 as the executable restoration track with code references,
  parallel order, and acceptance checks.
- Keep the docs trimmed to this tracker plus `Session-Notes.md`.

Acceptance:

- `python3 scripts/validate_docs.py`
- `python3 scripts/validate_migration_docs.py`
- `git diff --check`

## BATCH-OS1 - DB backend seed and aggregate catalog visibility

Dependencies: BATCH-OS0.

Scope:

- `install.sh`
- `scripts/setup-addon.sh`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py`
- `packages/sift-gateway/tests/test_d22a_mcp_backends_registry.py`

Exact work:

- Ensure bootstrap/setup registers `opensearch-mcp` in `app.mcp_backends` when
  OpenSearch config/dependencies are present.
- Store non-secret connection metadata only; use env refs for URLs,
  credentials, TLS, and runtime config.
- Prove requirement gating: unavailable OpenSearch hides the backend; available
  OpenSearch exposes `opensearch_*` in aggregate `/mcp tools/list`.
- Keep `gateway.yaml` ignored as add-on authority.

Acceptance:

- Gateway registry tests cover OpenSearch enabled, disabled, missing
  requirement, and no raw-secret storage.
- Aggregate tool-list smoke shows OpenSearch namespace present without leaking
  credentials.

## BATCH-OS2 - Active-case proxy compatibility for OpenSearch tools

Dependencies: BATCH-OS0. Can run parallel with OS1, but lands after catalog
tests are reconciled.

Scope:

- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/opensearch-mcp/sift-backend.json`
- Gateway proxy/policy tests near:
  `packages/sift-gateway/tests/test_pr03b_active_case_policy.py`,
  `packages/sift-gateway/tests/test_tool_refactor_2026.py`,
  `packages/sift-gateway/tests/test_pr03_tool_authorization.py`

Exact work:

- Fix mounted FastMCP proxy calls so case-scoped OpenSearch tools receive the
  DB active `case_id` safely.
- Stop relying on placeholder schemas for `safe_case_argument_names`; use
  manifest metadata or concrete Gateway logic for OpenSearch case arguments.
- Allow safe active-case injection for `opensearch_search`,
  `opensearch_count`, `opensearch_aggregate`, `opensearch_get_event`,
  `opensearch_timeline`, `opensearch_field_values`,
  `opensearch_case_summary`, `opensearch_status`,
  `opensearch_shard_status`, and `opensearch_list_detections`.
- Preserve denial when a client supplies a mismatched case.

Acceptance:

- Tests prove proxied OpenSearch tools get DB active case by default.
- Tests prove wrong explicit case IDs fail with typed denial.
- Evidence gate, audit envelope, response guard, and scope checks still wrap
  backend dispatch.

## BATCH-OS3 - Read-only OpenSearch investigation surface

Dependencies: BATCH-OS1; BATCH-OS2.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/registry.py`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/opensearch-mcp/tests/test_opensearch_mcp_surface_snapshot.py`
- `packages/opensearch-mcp/tests/test_server_tools.py`
- `packages/opensearch-mcp/tests/fixtures/mcp_surface_golden.json`
- Gateway aggregate tool-list snapshot/tests.

Exact work:

- Reconcile manifest, registry, golden, and aggregate Gateway catalog.
- Restore read-only investigator tools first: search, count, aggregate, get
  event, timeline, field values, case summary, status, shard status, and
  detections.
- Keep schemas as client-compatible JSON objects with concise descriptions.
- Keep outputs capped/redacted through Gateway response guard.

Acceptance:

- OpenSearch surface snapshot passes.
- Aggregate `/mcp tools/list` advertises the read-only OpenSearch tools.
- Targeted aggregate calls cover at least `opensearch_status`,
  `opensearch_count`, and `opensearch_search`.

## BATCH-OS4 - Job-backed ingest using standalone OpenSearch code

Dependencies: BATCH-OS2. Can run parallel with OS5.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/job_ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- Worker bootstrap/job registration paths.
- `packages/opensearch-mcp/tests/test_job_ingest.py`
- `packages/sift-gateway/tests/test_mvp_binding_job_tools.py`

Exact work:

- Keep parser, mount, discovery, mapping, bulk indexing, and client behavior in
  `opensearch-mcp`.
- Keep real agent-facing writes job-backed: Gateway resolves evidence refs,
  worker resolves paths internally, and OpenSearch provenance is recorded in
  Postgres.
- Return only job IDs, status, counts, index names, provenance IDs, and bounded
  summaries to agents.
- Hide, deny, or typed-redirect direct `opensearch_ingest(dry_run=False)` in
  DB-active mode unless it goes through the same Gateway evidence/job/provenance
  envelope.
- Allow dry-run/survey only if it uses opaque evidence refs and sealed-evidence
  checks; no absolute path bypass.

Acceptance:

- Sealed-evidence ingest job indexes documents and writes DB provenance.
- Agent responses contain no absolute evidence paths, mount paths, OpenSearch
  credentials, DB DSNs, or worker file paths.
- `ingest_job` + `job_status` integration tests pass.

## BATCH-OS5 - Host identity, enrichment, and mutating-tool policy

Dependencies: BATCH-OS2. Can run parallel with OS4.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/host_identity_db.py`
- `packages/opensearch-mcp/src/opensearch_mcp/host_dictionary.py`
- `packages/opensearch-mcp/src/opensearch_mcp/threat_intel.py`
- `packages/opensearch-mcp/src/opensearch_mcp/triage_remote.py`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/opensearch-mcp/tests/test_k4_host_identity_authority.py`
- Gateway add-on authority middleware tests.

Exact work:

- Keep `opensearch_fix_host_mapping` canonical; keep
  `opensearch_host_fix` only as a deprecated alias if needed for one cutover.
- In DB-active mode, host corrections must write DB host-identity receipts or
  be denied/redirected with typed guidance.
- Treat enrichment as derived-state mutation requiring explicit scopes, audit,
  and status tracking. Enrichment cannot approve findings, alter evidence, or
  decide reports.
- Mark required scopes and prohibited operations in the manifest.

Acceptance:

- Mutating OpenSearch tools are job/DB/audit backed or fail closed with typed
  guidance.
- Host correction records source/canonical/actor/tool/affected IDs/audit ID and
  leaks no `host-dictionary.yaml` absolute path.
- Enrichment status is pollable and does not expose OpenCTI/OpenSearch secrets.

## BATCH-OS6 - Live VM OpenSearch proof

Dependencies: BATCH-OS1; BATCH-OS2; BATCH-OS3; BATCH-OS4; BATCH-OS5.

Scope:

- Deployment/smoke only.
- `docs/migration/Session-Notes.md` closeout after proof passes.

Exact work:

- Sync to the active VM tree recorded in `Session-Notes.md`.
- Restart `sift-gateway.service` and `sift-job-worker.service`.
- Verify Gateway health, Supabase, evidence root, worker, and OpenSearch.
- Issue a fresh portal agent principal and prove aggregate `/mcp tools/list`
  includes restored `opensearch_*`.
- Run one read-only OpenSearch path, then one sealed-evidence ingest job if the
  demo case is ready.

Acceptance:

- Live aggregate MCP shows OpenSearch tools present and callable.
- Search/ingest uses DB active case and sealed evidence only.
- No path, DSN, service-role key, token, or OpenSearch credential leakage.
- `Session-Notes.md` records command-level proof after checks pass.

## OpenSearch Worker Prompts

Use these from clean parallel worktrees. Worker branches do not edit
`docs/migration`; they return a landing log for the conductor.

### PROMPT-OS1 - DB backend seed and aggregate catalog visibility

```text
ROLE & MODE
You are the BATCH-OS1 coding agent for the SIFT MVP sprint. Restore
opensearch-mcp visibility through the Gateway aggregate MCP catalog by fixing
DB-backed add-on registration/bootstrap. Do not move OpenSearch into sift-core.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/task-batches.md OpenSearch
Restoration Operating Model + BATCH-OS1; latest entry in
docs/migration/Session-Notes.md.

SCOPE
Own OS1 only. Inspect/edit only:
- install.sh
- scripts/setup-addon.sh
- packages/opensearch-mcp/sift-backend.json
- packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py
- packages/sift-gateway/src/sift_gateway/server.py
- packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py
- packages/sift-gateway/tests/test_d22a_mcp_backends_registry.py

GROUNDING FACTS
The live aggregate catalog was last recorded with 13 Gateway tools and no
opensearch_* tools. The standalone manifest already declares opensearch-mcp and
the rich tool surface. Gateway add-on authority is app.mcp_backends, not
gateway.yaml.

DELIVERABLE
Ensure a bootstrap/setup path registers opensearch-mcp in app.mcp_backends when
OpenSearch config/dependencies are present. Store only non-secret connection
metadata; use env refs for OpenSearch URL/credentials/TLS/runtime config. Prove
requirement gating: unavailable OpenSearch hides the backend; available
OpenSearch exposes opensearch_* in aggregate /mcp tools/list.

HARD CONSTRAINTS
Do not re-enable gateway.yaml as authority. Do not store raw OpenSearch
credentials, DB DSNs, service-role keys, MCP tokens, or VM secrets in repo
files. Do not change active-case proxy logic; that is OS2.

TESTS
Run targeted registry/bootstrap tests, at minimum:
- pytest packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py -q
- pytest packages/sift-gateway/tests/test_d22a_mcp_backends_registry.py -q
Also run any new/changed aggregate catalog tests.

OUTPUT DISCIPLINE
Do not edit docs/migration. End with a LANDING LOG block:
- changed files
- tests run and results
- how OpenSearch is registered
- proof no raw secrets are stored/emitted
- whether aggregate tools/list can include opensearch_* when requirements pass
- follow-up needed for OS2/OS3
```

### PROMPT-OS2 - Active-case proxy compatibility for OpenSearch tools

```text
ROLE & MODE
You are the BATCH-OS2 coding agent for the SIFT MVP sprint. Fix Gateway
active-case injection/denial for proxied OpenSearch MCP tools. Do not work on
backend registration/bootstrap; that is OS1.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/task-batches.md OpenSearch
Restoration Operating Model + BATCH-OS2; latest entry in
docs/migration/Session-Notes.md.

SCOPE
Own OS2 only. Inspect/edit only:
- packages/sift-gateway/src/sift_gateway/policy_middleware.py
- packages/sift-gateway/src/sift_gateway/server.py
- packages/sift-gateway/src/sift_gateway/mcp_server.py
- packages/opensearch-mcp/sift-backend.json
- directly related tests near:
  packages/sift-gateway/tests/test_pr03b_active_case_policy.py
  packages/sift-gateway/tests/test_tool_refactor_2026.py
  packages/sift-gateway/tests/test_pr03_tool_authorization.py

GROUNDING FACTS
OpenSearch tools are case-scoped and must receive the DB active case safely
through Gateway. Empty/placeholder schemas must not cause
active_case_proxy_denied for safe OpenSearch tools. Explicit wrong case IDs must
still be denied.

DELIVERABLE
Make Gateway safely inject the DB active case for proxied OpenSearch tools:
opensearch_search, opensearch_count, opensearch_aggregate,
opensearch_get_event, opensearch_timeline, opensearch_field_values,
opensearch_case_summary, opensearch_status, opensearch_shard_status, and
opensearch_list_detections. Use manifest metadata or concrete Gateway logic for
safe case argument names; do not rely on placeholder schemas.

HARD CONSTRAINTS
Gateway remains the policy boundary. Preserve evidence gate, audit envelope,
response guard, and scope checks before/around backend dispatch. Preserve
fail-closed mismatch denial when a client supplies another case. Do not expose
absolute evidence paths, case paths, mount paths, OpenSearch credentials, DB
credentials, service-role keys, or shell access.

TESTS
Run targeted proxy/policy tests you add or touch, plus the narrow existing
authorization/policy tests needed to prove:
- DB active case is injected by default for safe OpenSearch tools.
- explicit mismatched case_id is denied before backend dispatch.
- non-OpenSearch backend tools are not accidentally widened.

OUTPUT DISCIPLINE
Do not edit docs/migration. End with a LANDING LOG block:
- changed files
- tests run and results
- exact OpenSearch tools made case-injectable
- mismatch-denial proof
- response/audit/evidence-gate implications
- follow-up needed for OS1/OS3
```

### PROMPT-OSX - Template for OS3 through OS6

```text
ROLE & MODE
You are the BATCH-OS<N> coding agent for the SIFT MVP sprint. Complete only
BATCH-OS<N> from docs/migration/task-batches.md. Do not redesign the
architecture and do not move OpenSearch into sift-core.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/task-batches.md OpenSearch
Restoration Operating Model + BATCH-OS<N>; latest entry in
docs/migration/Session-Notes.md; LANDING LOGs from completed OS dependencies.

SCOPE
Use only the BATCH-OS<N> scope paths listed in task-batches.md unless a failing
test proves one minimal adjacent change is required. If a needed fix belongs to
another OS batch, return it as a follow-up instead of expanding scope.

SECURITY INVARIANTS
Gateway is the only agent-facing policy boundary. Supabase/Postgres is
authority for cases, evidence, jobs, audit, host identity receipts, and ingest
provenance. OpenSearch is derived/rebuildable and never authorizes cases,
evidence, findings, approvals, or reports. Agents never receive absolute paths,
DB/OpenSearch credentials, service-role keys, MCP tokens, or shell access.

DELIVERABLE
Implement the Exact work for BATCH-OS<N>. Keep responses capped/redacted and
schemas client-compatible plain objects. For mutating work, use Gateway/DB/job
authority or fail closed with typed guidance.

TESTS
Run the targeted tests named in BATCH-OS<N> plus any tests for changed files.
For OS6, run live VM smoke only after OS1-OS5 local tests pass.

OUTPUT DISCIPLINE
Do not edit docs/migration from worker branches. End with a LANDING LOG block:
- batch ID and status
- changed files
- tests/smoke run and results
- acceptance evidence
- security/leakage notes
- unresolved blockers or next OS follow-up
```

## BATCH-A0 - Freeze simplified migration operating model

Dependencies: none.

Scope:

- `docs/migration/**`
- `AGENTS.md`
- `CLAUDE.md`
- `scripts/validate_docs.py`
- `scripts/validate_migration_docs.py`

Exact work:

- Purge the previous migration document forest.
- Replace it with `Migration-Spec.md`, `task-batches.md`, and
  `Session-Notes.md`.
- Simplify root agent instructions to point at the three active docs only.
- Make `scripts/validate_docs.py` enforce the new three-file model.

Acceptance:

- `rg --files docs/migration` lists only the three active docs.
- `python3 scripts/validate_docs.py` passes.
- `python3 scripts/validate_migration_docs.py` passes.

## BATCH-A1 - Final installer, Supabase bootstrap, forced reset, and health contract

Dependencies: BATCH-A0.

Scope:

- `install.sh`
- `configs/gateway.yaml.template`
- `configs/systemd/sift-gateway.service`
- `configs/audit/99-sift-evidence.rules`
- `configs/apparmor/sift-gateway.template`
- `scripts/setup-agent-runtime.sh`
- `packages/sift-gateway/src/sift_gateway/config.py`
- `packages/sift-gateway/src/sift_gateway/health.py`
- `packages/sift-gateway/src/sift_gateway/supabase_auth.py`
- `packages/case-dashboard/src/case_dashboard/auth.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`

Exact work:

- Update the final installer so it performs installation, configuration,
  hardening, health check, and operator handoff in one idempotent flow.
- Make the operator bootstrap Supabase-first. The installer must produce a
  one-time credential or reset challenge that forces reset on first login.
- Preserve the SIFT VM constraints: `/usr/bin/python3.12`,
  `UV_NO_MANAGED_PYTHON=1`, and `UV_PYTHON_DOWNLOADS=never`.
- Add explicit evidence mount validation and case root validation.
- Freeze the case path implementation to `/cases/case-<slug>-<MMDDHHSS>`, with
  a filesystem-safe lowercase slug and `-NN` collision suffix if needed.
- Health output must prove Gateway, portal, Supabase connectivity, OpenSearch
  reachability if configured, evidence root permissions, and worker readiness
  if enabled.

Acceptance:

- Fresh SIFT VM install completes without manual patching.
- Operator can log in with one-time credential and is forced to reset.
- Operator can create and activate a case with re-auth.
- Active case is sourced from Postgres, not local env/pointer files.
- Installer health check shows the evidence root/mount status.

## BATCH-B1 - Gateway policy parity and agent response redaction

Dependencies: BATCH-A0.

Scope:

- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- `packages/sift-gateway/src/sift_gateway/response_guard.py`
- `packages/sift-gateway/src/sift_gateway/rate_limit.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- Gateway and core tests touching auth, active case, evidence gate, response guard, and REST tools

Exact work:

- Make protected portal REST and MCP tool paths policy-equivalent for equivalent
  actions.
- For the MVP, make REST tool execution operator-only. Agents use Gateway MCP
  only.
- Ensure every agent-facing tool response uses opaque IDs and redacted/capped
  previews.
- Remove absolute case paths, evidence paths, mount paths, local config paths,
  and secret-bearing values from agent-visible responses.
- Allow agent-visible evidence IDs, display names, relative display paths, size,
  hash, seal status, and provenance IDs. Deny absolute paths.
- Verify pre-seal evidence denial and post-seal allow behavior.

Acceptance:

- Tests prove agent tokens cannot use REST to bypass MCP policy.
- Tests prove `case_info`, `evidence_info`, existing-finding views, and
  run-command results expose no absolute paths.
- Evidence gate failures are fail-closed and audited.
- Rate limit and response guard still apply on agent paths.

## BATCH-C1 - DB evidence authority, custody ledger, and seal broker

Dependencies: BATCH-A0; BATCH-A1 for final case path details.

Scope:

- `supabase/migrations/*.sql`
- `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- `packages/sift-gateway/src/sift_gateway/audit_helpers.py`
- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/case_io.py`
- Evidence API/route tests only if they do not overlap a concurrently running
  portal batch; otherwise return the route patch as follow-up for BATCH-E1

Exact work:

- Add Postgres evidence tables for detected files, registered evidence,
  evidence versions, custody events, hash chain heads, seal status, and proof
  export metadata.
- Add service-only transition RPCs for detect, register, seal, verify, ignore,
  retire, and violation marking.
- Keep file manifests and proof files as exported artifacts, not as the
  authoritative state machine.
- Broker must resolve evidence IDs to mounted paths internally. The agent never
  receives the path.
- Hash-chain/custody arrow is mounted evidence focused: proof links to the
  evidence mount and custody ledger, not RAG.

Acceptance:

- Portal detects unregistered evidence and shows it from DB state.
- Operator registers evidence with name and description.
- Seal requires re-auth and writes a custody event/hash-chain entry.
- Agent analysis is blocked until sealed OK.
- Proof export can verify sealed mounted evidence.

## BATCH-D1 - Durable Postgres jobs and local worker claim loop

Dependencies: BATCH-A0; can run in parallel with BATCH-C1 after table contracts are agreed.

Scope:

- `supabase/migrations/*.sql`
- `packages/sift-gateway/src/sift_gateway/**`
- `packages/sift-core/src/sift_core/execute/worker.py`
- New worker module if needed under `packages/sift-core/src/sift_core/**`
- Tests for job enqueue, claim, lease, status, logs, cancellation, and retry

Exact work:

- Add minimal job tables: jobs, job_steps, job_logs, worker_heartbeats, and
  typed status enums.
- Add enqueue RPC/API for ingest, enrich, report, and run-command jobs.
- Add worker claim loop using Postgres row locking or equivalent lease
  semantics.
- Jobs return `job_id` to portal/agent and write status/logs to Postgres.
- Worker receives case/evidence/job IDs, resolves paths internally, and writes
  provenance IDs on outputs.

Acceptance:

- Concurrent workers do not claim the same job.
- Lease expiry and retry behavior are tested.
- Portal and agent can poll job status without reading worker files.
- Failed jobs preserve audit/provenance and sanitized logs.

## BATCH-D2 - Gateway job adapter and add-on authority enforcement

Dependencies: BATCH-B1; BATCH-D1; BATCH-H1. BATCH-C1 context is available for
case/evidence IDs, but D2 must not implement evidence UI.

Scope:

- `packages/sift-gateway/src/sift_gateway/rest.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`
- `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
- `packages/sift-gateway/src/sift_gateway/backends/**`
- `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
- Gateway tests for jobs, backend registry, scope enforcement, and add-on
  authority contracts
- Optional narrow SQL migration only if required for grants/wrappers around
  existing D1 job RPCs

Exact work:

- Add the Gateway adapter over D1's `app.enqueue_job`,
  `app.job_status_public`, and `app.expire_stale_jobs` surfaces.
- Job enqueue returns only `job_id` to portal/agent callers and attaches the
  Gateway audit event ID as `enqueue_audit_event_id`.
- Job status reads are sanitized and expose no worker files or local paths.
- Add a safe Gateway-owned reaper trigger or service hook for
  `expire_stale_jobs`.
- Enforce add-on `authority_contract` at runtime: `non_authoritative`,
  `prohibited_operations`, and tool-level `required_scopes`.
- Keep `transport: library` manifests non-routable.

Acceptance:

- Tests prove enqueue/status uses D1 RPC/view shape and returns sanitized
  `job_id`/status only.
- Tests prove a missing required add-on scope is denied before backend dispatch.
- Tests prove prohibited add-on authority operations are denied before backend
  dispatch.
- Tests prove library manifests remain accepted but non-routable.
- Existing Gateway manifest and backend registry tests remain green.

## BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports

Dependencies: BATCH-B1; BATCH-C1 for evidence; BATCH-D1 for job-backed actions; BATCH-D2 for Gateway job/status adapter.

Scope:

- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/App.jsx`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `packages/case-dashboard/frontend/src/components/findings/FindingsTab.jsx`
- `packages/case-dashboard/frontend/src/components/timeline/TimelineTab.jsx`
- `packages/case-dashboard/frontend/src/components/todos/TodosTab.jsx`
- `packages/case-dashboard/frontend/src/components/reports/ReportsTab.jsx`
- `packages/case-dashboard/frontend/src/components/settings/SettingsTab.jsx`
- Portal tests

Exact work:

- Wire evidence screens to DB evidence state and custody transitions.
- Wire findings, timeline, TODOs, and report metadata to Postgres.
- Preserve human review power: approve, reject, edit, manage TODOs, and approve
  report inclusion from portal only.
- Sensitive actions require password/HMAC re-auth.
- Portal must show job status, evidence seal status, custody status, add-on
  status, and report eligibility clearly.

Acceptance:

- Operator can complete the full portal journey without relying on old file
  authority.
- Agent proposals appear as proposed/draft records until human action.
- Approved-only report eligibility is visible and testable.
- Portal tests cover auth, re-auth, and rejected unauthorized mutations.

## BATCH-F1 - OpenSearch secure core integration and ingest job adapter

Dependencies: BATCH-D1; BATCH-C1 for evidence IDs; BATCH-D2 for Gateway job/status adapter and add-on contract enforcement.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/**`
- `packages/opensearch-mcp/docker/**`
- `packages/opensearch-mcp/scripts/setup-opensearch.sh`
- `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
- Gateway backend registry integration tests

Exact work:

- Keep the working parser/ingestor stack. Add the minimal adapter needed for
  DB job execution and evidence/provenance IDs.
- Ensure OpenSearch security remains enabled and credentials are never exposed
  to the AI agent.
- Write case/provenance IDs into indexed documents.
- Register index/job/provenance metadata in Postgres.
- Keep OpenSearch derived and rebuildable.

Acceptance:

- Ingest job indexes parser documents with case/evidence/provenance metadata.
- Search tools are case-scoped through Gateway.
- OpenSearch direct credentials are not present in agent-visible output.
- Existing parser tests remain green.

## BATCH-G1 - RAG pgvector target with provenance filters

Dependencies: BATCH-D1; BATCH-C1 for evidence provenance; BATCH-B1 for Gateway policy; BATCH-D2 for job/status adapter.

Scope:

- `supabase/migrations/*.sql`
- `packages/forensic-rag-mcp/src/rag_mcp/**`
- `packages/forensic-rag-mcp/knowledge/**`
- Gateway RAG tool bridge tests

Exact work:

- Add Supabase pgvector schema for RAG collections, documents, chunks,
  embeddings, and provenance IDs.
- Store derived text and forensic knowledge chunks with case/provenance filters.
- Query RAG only through Gateway.
- Return grounded context with provenance IDs, not evidence paths.
- Keep knowledge data as reference data, not evidence.

Acceptance:

- RAG queries return case-scoped, provenance-linked context.
- Agent cannot query another case's RAG data.
- RAG has no authority over evidence seal, approvals, or reports.

## BATCH-H1 - Add-on contract hardening for OpenCTI, Windows triage, and forensic knowledge

Dependencies: BATCH-B1; can run in parallel with DB-heavy batches.

Scope:

- `packages/opencti-mcp/src/opencti_mcp/**`
- `packages/windows-triage-mcp/src/windows_triage_mcp/**`
- `packages/forensic-knowledge/src/**`
- `packages/*/sift-backend.json`
- Gateway backend registry tests

Exact work:

- Align add-ons with the final contract: query-only, audited, scoped, and
  non-authoritative.
- Ensure add-ons cannot create cases, seal evidence, approve findings, approve
  reports, or bypass Gateway.
- Preserve Windows triage suspicious file/service/process/hash baseline value.
- Preserve forensic knowledge snippets as discipline guidance only.

Acceptance:

- Add-on metadata clearly marks capabilities and required scopes.
- Gateway registry can enable/disable/gate add-ons.
- Tool surface snapshots remain deterministic.

## BATCH-I1 - Sandboxed run_command uplift

Dependencies: BATCH-B1; BATCH-C1 for evidence refs; BATCH-D1 for job backing; BATCH-D2 for Gateway job/status adapter.

Scope:

- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/security_policy.py`
- `scripts/setup-agent-runtime.sh`
- Execution tests

Exact work:

- Make `run_command` accept evidence refs and output refs, not arbitrary paths.
- Keep `shell=False`, deny-by-default parsing, and runtime user isolation.
- Add a tight MVP allowlist for necessary forensic tools.
- Run as a job where practical and return `job_id`, stdout preview, output refs,
  output hashes, and provenance receipts.
- Sanitize all returned path-like values for the agent.

Acceptance:

- Allowed forensic commands work against sealed evidence refs.
- Denied commands fail closed and are audited.
- Outputs are hash-linked and reportable without exposing local paths.

## BATCH-J1 - Approved-only report generation and export

Dependencies: BATCH-E1; BATCH-D1; BATCH-C1; BATCH-D2.

Scope:

- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/report_profiles.py`
- Portal report routes and `ReportsTab.jsx`
- Report tests

Exact work:

- Store report metadata and report state in Postgres.
- Generate reports from approved findings and approved supporting data only.
- Require operator re-auth for report inclusion/export.
- Include custody/evidence seal status, provenance IDs, and hash-chain proof
  references.
- Keep report files as exported artifacts, not authority.

Acceptance:

- Unapproved findings cannot appear in generated reports.
- Approved findings include provenance and supporting custody references.
- Exported report bundle includes verification material.

## BATCH-L1 - Live service binding, worker bootstrap, and Gateway tool bridge

Dependencies: BATCH-C1; BATCH-D1; BATCH-D2; BATCH-E1; BATCH-F1; BATCH-G1; BATCH-I1; BATCH-J1.

Scope:

- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/mcp_server.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/jobs.py`
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `packages/sift-gateway/src/sift_gateway/rag_bridge.py`
- `packages/sift-core/src/sift_core/execute/job_worker.py`
- `packages/sift-core/src/sift_core/execute/job_worker_cli.py`
- `packages/sift-core/src/sift_core/execute/run_command_job.py`
- `supabase/migrations/202606081500_report_metadata.sql`
- `configs/systemd/sift-job-worker.service`
- Binding tests and DB structural tests

Exact work:

- Bind `create_dashboard_v2_app` service slots to live Gateway-owned DB
  adapters for evidence/custody, findings/timeline/IOCs/TODOs, report metadata,
  and D2 job status.
- Add the report/investigation metadata migration required by J1's
  `report_service.record_report` seam.
- Prefer the C1 DB evidence gate for DB active cases; keep the legacy file gate
  only as bridge fallback.
- Add a worker CLI/service that registers D1 `JobWorker` handlers for `ingest`
  and `run_command`, and filters claims to job types this worker can handle.
- Add Gateway-owned MCP tools for durable `ingest_job`, durable
  `run_command_job`, and sanitized `job_status`; public job specs stay
  path-free and worker-only `spec_internal` carries resolved local paths.
- Add the case-scoped pgvector `rag_search_case` Gateway tool over G1's
  `PgVectorRagStore`, routed through normal Gateway policy and response guard.

Acceptance:

- Portal DB service slots are wired by Gateway startup when a control-plane DSN
  exists.
- Agent-facing durable job tools return `job_id` and status only; absolute
  paths appear only in worker-only `spec_internal`.
- Worker claim loop does not claim unsupported job types.
- DB active cases use DB evidence-gate status before tool dispatch.
- RAG query tool validates case scope and embedding shape and returns
  provenance-linked, path-free results.
- Gateway, core, portal, RAG/DB, and OpenSearch job-ingest tests pass.

## BATCH-K0 - Authority cutover impact model and batch freeze

Dependencies: BATCH-L1 live binding context; BATCH-V1 partial validation
findings.

Scope:

- `docs/migration/Migration-Spec.md`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`
- `scripts/validate_docs.py` only if the three-file governance model itself
  needs an intentional rule change

Exact work:

- Document the authority cutover impact model: Postgres is authority for
  critical mutable state; Supabase Storage/case files are immutable exports,
  workspace/debug artifacts, parser compatibility artifacts, or legacy fallback
  only.
- Map critical file touchpoints with code references so implementation sessions
  do not rediscover the same split-brain paths:
  - active case: `packages/sift-common/src/sift_common/__init__.py`,
    `packages/sift-core/src/sift_core/case_manager.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`;
  - audit: `packages/sift-common/src/sift_common/audit.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`;
  - evidence/custody: `packages/sift-core/src/sift_core/evidence_chain.py`,
    `packages/sift-core/src/sift_core/verification.py`,
    `packages/case-dashboard/src/case_dashboard/routes.py`;
  - investigation records: `packages/sift-core/src/sift_core/case_manager.py`,
    `packages/sift-core/src/sift_core/case_io.py`,
    `packages/sift-gateway/src/sift_gateway/portal_services.py`,
    `packages/case-dashboard/src/case_dashboard/routes.py`;
  - OpenSearch status/provenance/host identity:
    `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/host_discovery.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/host_dictionary.py`,
    `packages/opensearch-mcp/src/opensearch_mcp/server.py`;
  - run-command: `packages/sift-core/src/sift_core/execute/**`,
    `packages/sift-core/src/sift_core/agent_tools.py`,
    `scripts/setup-agent-runtime.sh`.
- Preserve the hostname carve-out: host detection/index naming is derived
  parser metadata, not case/evidence authority. `opensearch_fix_host_mapping`
  is the canonical correction tool; `opensearch_host_fix` is a deprecated alias.
- Preserve the Solana carve-out: optional SPL Memo anchoring strengthens
  external proof but never decides evidence gate state. DB custody chain heads
  remain authority.
- Split the blocking authority cutover into K1-K6 implementation batches and
  make BATCH-V1 depend on them.

Acceptance:

- `Migration-Spec.md` includes the authority cutover model, host identity
  carve-out, Solana anchor carve-out, and DB-active constraints.
- `task-batches.md` contains grep-friendly K-series checkboxes and executable
  batch sections.
- `Session-Notes.md` records the authority decision and next execution order.
- `python3 scripts/validate_docs.py` passes.
- `python3 scripts/validate_migration_docs.py` passes.

## BATCH-K1 - Authority context and DB audit cutover

Dependencies: BATCH-K0. This is the dependency root for K2-K6.

Status (2026-06-08): DONE - landed as `0e9577a`. K1 introduced
`AuthorityContext`, DB-active active-case fail-closed behavior, worker
`SIFT_DB_ACTIVE=1`, DB-first `app.audit_events` envelope writes, and mutating
fail-closed audit behavior. Conductor security review found and fixed one
pre-merge gap: the DB audit envelope now wraps proxy/evidence-gate denials after
case-context setup, and evidence-gate block results are MCP errors so DB result
receipts record `failure`.

Scope:

- `packages/sift-common/src/sift_common/__init__.py`
- `packages/sift-common/src/sift_common/audit.py`
- `packages/sift-core/src/sift_core/active_case_context.py`
- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/case_ops.py`
- `packages/sift-gateway/src/sift_gateway/active_case.py`
- `packages/sift-gateway/src/sift_gateway/audit_helpers.py`
- `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
- `packages/sift-gateway/src/sift_gateway/server.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `packages/sift-core/src/sift_core/execute/job_worker.py`
- `packages/sift-core/src/sift_core/execute/job_worker_cli.py`
- Existing DB migrations only if a narrow audit/helper RPC is missing; otherwise
  add a new timestamped migration.
- Gateway/common/core tests for active case, audit, and response redaction.

Exact work:

- Introduce or harden a single `AuthorityContext`/request context contract that
  carries case UUID, case key, artifact path for worker-only use, principal,
  membership role, tool scopes, evidence gate version/status, request ID, and
  audit event IDs.
- In DB-active mode, Gateway/core/worker must use this context for
  authoritative work. `SIFT_CASE_DIR`, `~/.sift/active_case`, and `CASE.yaml`
  remain legacy fallback only when DB authority is disabled.
- Replace JSONL-first audit on Gateway/core DB-active paths with DB-first
  audit writes to `app.audit_events`. The file writer may remain as an export
  or legacy fallback, but a required DB audit failure must fail a mutating
  call.
- For MCP/API calls, write a pre-dispatch audit envelope and a result/failure
  audit receipt. Mutating handlers must be able to attach those IDs to DB
  transitions.
- Ensure audit output and errors are path/secret redacted for agent callers.

Acceptance:

- Tests prove DB-active Gateway/tool calls do not read active case from
  `~/.sift/active_case`.
- Tests prove file pointer tampering cannot change the active case used by
  MCP/API calls.
- Tests prove mutating DB-active calls fail closed when required DB audit write
  fails.
- Tests prove audit rows carry request/tool/principal/case/provenance fields
  needed by K2-K6.
- Existing legacy CLI/file-mode tests still pass or are explicitly scoped as
  legacy fallback.

## BATCH-K2 - Core investigation DB authority cutover

Dependencies: BATCH-K1.

Scope:

- `packages/sift-core/src/sift_core/case_manager.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `supabase/migrations/202606081500_report_metadata.sql` for contract
  reference; add a new timestamped migration only if schema/RPC gaps remain.
- Core, Gateway, portal, and DB tests for findings, timeline, TODOs, IOCs, and
  approvals.

Exact work:

- Add a typed investigation authority port/store used by core mutating tools:
  findings, timeline events, TODOs, IOCs, approvals/rejections, and content
  hashes.
- In DB-active mode, `record_finding`, `record_timeline_event`, and
  `manage_todo` write to `app.investigation_*` first and return DB-backed IDs.
  File writes are disabled or mirror-only.
- Approval/rejection/edit transitions must update the DB row, status, actor,
  re-auth audit ID, content hash, and approval metadata atomically.
- Portal reads and report generation must use DB rows only for DB-active cases.
- Prevent agent downgrades or overwrites of human-approved/rejected records:
  agents may create/update draft/proposed rows only.

Acceptance:

- Agent-created findings, timeline events, TODOs, and IOCs appear in portal
  from Postgres without reading case JSON.
- Portal approval/rejection updates Postgres and is visible to report
  generation.
- Tampering with `findings.json`, `timeline.json`, `todos.json`, `iocs.json`,
  or `approvals.jsonl` cannot alter portal state or report eligibility in
  DB-active mode.
- Race tests cover stale content hash/version on approval/edit.
- Approved-only report tests still pass using DB authority.

## BATCH-K3 - Evidence gate, proof export, and Solana anchor cutover

Dependencies: BATCH-K1. Can run in parallel with K2 and K4 after K1 lands.

Scope:

- `packages/sift-core/src/sift_core/evidence_chain.py`
- `packages/sift-core/src/sift_core/verification.py`
- `packages/sift-core/src/sift_core/case_io.py`
- `packages/sift-gateway/src/sift_gateway/evidence_gate.py`
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/components/evidence/EvidenceTab.jsx`
- `supabase/migrations/202606081000_evidence_custody.sql` for contract
  reference; add a new timestamped migration only if proof export/anchor
  metadata is missing.
- Evidence/custody/proof-export tests.

Exact work:

- Ensure DB-active evidence gate reads only `app.evidence_gate_status` /
  `app.evidence_chain_heads` and never treats `evidence-manifest.json` or
  `evidence-ledger.jsonl` as gate authority.
- Make evidence detect/register/seal/ignore/retire/violation transitions write
  DB custody rows and chain heads first. File manifest/ledger writes become
  immutable proof exports or legacy fallback.
- Add or complete proof export generation from DB-derived evidence state:
  manifest snapshot, ledger/custody event snapshot, chain head, verification
  result, and optional storage/file object metadata.
- Preserve optional Solana anchoring as export proof only. Anchor payload must
  derive from DB custody proof material and record result in
  `app.evidence_proof_exports`; lack of Solana must not block sealing.
- New/changed file detection after seal must mark the case evidence gate non-OK
  until the operator resolves and seals again.

Acceptance:

- Tampering with `evidence-manifest.json`, `evidence-ledger.jsonl`, or
  `evidence-anchor-v*.json` cannot change evidence gate state in DB-active mode.
- Evidence gate fails closed when DB chain head is missing, violated, unsealed,
  or stale.
- Proof export verifies mounted evidence and records export metadata/hash in
  Postgres.
- Optional Solana anchor writes proof metadata when configured and degrades
  cleanly when not configured.

## BATCH-K4 - OpenSearch derived-state and host identity cutover

Dependencies: BATCH-K1; BATCH-F1/L1 OpenSearch job adapter. Can run in
parallel with K2, K3, and K5 after K1 lands.

Scope:

- `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py`
- `packages/opensearch-mcp/src/opensearch_mcp/ingest_status.py`
- `packages/opensearch-mcp/src/opensearch_mcp/host_discovery.py`
- `packages/opensearch-mcp/src/opensearch_mcp/host_dictionary.py`
- `packages/opensearch-mcp/src/opensearch_mcp/server.py`
- `packages/opensearch-mcp/src/opensearch_mcp/registry.py`
- `packages/opensearch-mcp/sift-backend.json`
- `packages/sift-core/src/sift_core/execute/job_worker.py`
- `supabase/migrations/202606081300_opensearch_provenance.sql` for contract
  reference; add a new timestamped migration only if host identity/job-status
  tables/RPCs are missing.
- OpenSearch ingest/job/host identity tests and Gateway tool-surface snapshots.

Exact work:

- Keep hostname extraction/detection because parsers and index naming need it.
  Host identity is derived indexing metadata, not case/evidence authority.
- Move DB-active ingest status, per-artifact provenance manifests, host
  discovery decisions, host dictionary mutations, and host-fix receipts into
  Postgres-backed provenance/host-identity records.
- Treat local `host-dictionary.yaml`, ingest manifests, discovery reports, and
  ingest status JSON as legacy/parser-compatibility/debug artifacts only.
- Preserve `opensearch_fix_host_mapping` as the canonical correction tool and
  `opensearch_host_fix` as the deprecated alias. Both may mutate OpenSearch
  derived docs and host metadata only, with DB audit/provenance receipts.
- Ensure OpenSearch credentials and local paths never appear in agent-visible
  responses.

Acceptance:

- Ingest/job status visible to portal/agent comes from Postgres durable job and
  provenance state, not case status JSON.
- Host identity decisions/corrections are recorded in DB with source,
  canonical value, actor/tool, affected index/provenance IDs, and audit ID.
- Tampering with `host-dictionary.yaml` cannot change portal/Gateway authority
  in DB-active mode; at most it can affect a legacy parser compatibility file
  that is regenerated from DB.
- Existing parser/index-name behavior remains compatible.

## BATCH-K5 - run_command authority-isolation hardening

Dependencies: BATCH-K1; BATCH-I1/L1 run-command job path. Can run in parallel
with K2-K4 after K1 lands.

Scope:

- `packages/sift-core/src/sift_core/execute/tools/generic.py`
- `packages/sift-core/src/sift_core/execute/executor.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/security_policy.py`
- `packages/sift-core/src/sift_core/execute/run_command_job.py`
- `packages/sift-core/src/sift_core/execute/runtime_acl.py`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `scripts/setup-agent-runtime.sh`
- `configs/systemd/sift-job-worker.service`
- Execution, ACL, redaction, and job tests.

Exact work:

- Ensure `run_command` receives opaque evidence refs/input refs and controlled
  output refs only. Worker-only path resolution must happen after DB job claim,
  evidence gate check, and audit pre-event.
- Strip DB DSNs, Supabase keys, service-role secrets, OpenSearch credentials,
  local VM secrets, and unrelated environment variables from the run-command
  subprocess environment.
- Ensure runtime user ACLs cannot read/write authority files. In the final
  model, critical authority files should not exist in the case dir; remaining
  proof/export files are read-only unless an operator/export process writes
  them.
- Persist output receipt metadata in Postgres: command plan hash, evidence refs,
  stdout/stderr preview hash, output refs, output file hash, audit IDs, job ID,
  and provenance ID.
- Keep `shell=False`, deny floor, allowlist profiles, path redaction, and
  bounded output previews.

Acceptance:

- Allowed commands work against sealed evidence refs and return job/status plus
  redacted previews only.
- Denied commands fail closed and are audited.
- A command cannot read DB secrets from env, cannot write authority state, and
  cannot cause portal/report/evidence gate state changes except through
  approved DB authority APIs.
- Output receipts are DB-backed and reportable without local paths.

## BATCH-K6 - Portal/report tamper regression and file-authority removal

Dependencies: BATCH-K2; BATCH-K3; BATCH-K4 for OpenSearch status views if
included; BATCH-K5 for run-command receipts.

Scope:

- `packages/case-dashboard/src/case_dashboard/routes.py`
- `packages/case-dashboard/frontend/src/**` only for surfaced authority labels
  or removed file fallback flows
- `packages/sift-gateway/src/sift_gateway/portal_services.py`
- `packages/sift-core/src/sift_core/reporting.py`
- `packages/sift-core/src/sift_core/audit_ops.py`
- `packages/sift-core/src/sift_core/backup_ops.py`
- End-to-end portal/Gateway/core/security regression tests.

Exact work:

- Remove or gate DB-active file fallbacks from portal views, approvals, report
  generation, audit views, backup/export views, and status endpoints.
- Add tamper regression tests that modify or delete legacy files and prove DB
  portal state, MCP state, evidence gate, approvals, report eligibility, and
  report output do not change.
- Keep legacy file mode explicitly available for old tests/CLI only when DB
  authority is not configured.
- Update visible portal labels only where needed so the operator can see DB
  authority versus export/debug artifacts.
- Confirm no duplicate state write path remains where file success can mask DB
  failure for critical mutable state.

Acceptance:

- Portal and report generation remain functional after legacy JSON/JSONL files
  are absent, stale, corrupt, or tampered in DB-active mode.
- Tests prove file tampering cannot approve findings, alter todos/timeline,
  change evidence seal state, change report inclusion, or spoof audit/custody.
- Any remaining file fallback is protected by an explicit legacy-mode guard.
- BATCH-V1 can resume with the authority cutover no longer blocking approval,
  report, ingest status, RAG verification, or run-command proof.

## BATCH-V1 - End-to-end validation and cutover

Dependencies: BATCH-A1; BATCH-B1; BATCH-C1; BATCH-D1; BATCH-D2; BATCH-E1; BATCH-F1; BATCH-G1; BATCH-H1; BATCH-I1; BATCH-J1; BATCH-L1; BATCH-K1; BATCH-K2; BATCH-K3; BATCH-K4; BATCH-K5; BATCH-K6.

Status (2026-06-08): DONE - live VM cutover/smoke completed from integrated
root `revamp/spg-v1`. The run applied the integrated migrations plus additive
IOC content-hash fixup `202606081602_investigation_iocs_content_hash.sql`,
restarted Gateway/job worker with `~/.sift/control-plane.env`, seeded the
shared pgvector forensic-knowledge corpus (`case_id NULL`), created/activated
`case-v1gate-06081857`, registered/sealed
evidence, issued an agent with default case binding, proved pre-seal denial and
post-seal `run_command`, completed `ingest_job`/OpenSearch and
`rag_search_case`, exported an approved-finding report, and exported DB custody
proof. Validation evidence is recorded at the top of `Session-Notes.md`.

Post-cutover freeze follow-up (2026-06-08): B-MVP-18 is DONE. The live VM
downloaded Chroma release `rag-index-v2026.03.01` through the SSH-tunneled
proxy, imported `22268` Chroma records into Supabase pgvector with
`rag-mcp-import-chroma-pgvector`, and proved `app.rag_chunks=26586`, all
`kind='knowledge'`, all `case_id NULL`, with live `rag_search_case` returning
Chroma-backed knowledge hits and no local path/secret leakage.

Scope:

- End-to-end tests and smoke scripts.
- VM deployment/test instructions if needed.
- `docs/migration/Session-Notes.md`
- `docs/migration/task-batches.md`

Exact work:

- Run the Phase 3 smoke journey from `Migration-Spec.md`.
- Run package tests for changed areas.
- Run document validators.
- Confirm no agent-visible absolute paths or secrets.
- Confirm old file-backed authority paths are not needed for the demo journey.
- Mark all completed batches and record final validation evidence at the top of
  `Session-Notes.md`.

Acceptance:

- SIFT VM demo flow works end to end.
- Security checks cover auth, authorization, access control, evidence gate,
  response guard, audit, custody, jobs, and report approval.
- The MVP is ready to freeze for the hackathon demo.

## Post-MVP QA Operating Model

Status (2026-06-09): ACTIVE - BATCH-PQA0 created the product documentation
workspace under `docs/product/**`, opened the post-MVP QA/product-documentation
batch wave, and made AI-agent autonomy a first-class acceptance axis.

Purpose:

- Move from MVP cutover proof to repeatable product QA, security assessment,
  documentation, and demo freeze.
- Keep `docs/migration` as the tracker/log only. Product documentation lives in
  `docs/product/**`.
- Judge the product from the AI agent's point of view, not only from service
  liveness. The core question is whether a scoped agent can complete a realistic
  DFIR investigation through MCP alone, with useful context, provenance, error
  recovery, and bounded response sizes.

Parallelization:

- Wave 0, sequential: BATCH-PQA0. Land the structure before parallel work so all
  workers use the same documents and acceptance language.
- Wave 1, parallel after PQA0: BATCH-PDOC1, BATCH-PDOC2, BATCH-SEC1, and
  BATCH-INST1. If running only three workers, run PDOC1/PDOC2/SEC1 first;
  INST1 is independent and can start as a fourth worker or immediately after.
- Wave 2, serial autonomy gate: BATCH-AUT1 after PDOC2 has captured the live MCP
  inventory and PDOC1 has the product journey draft. AUT1 may produce code/doc
  fixes before the demo-case benchmark.
- Wave 3, parallel after AUT1: BATCH-AUT2 and any SEC1/INST1 remediation that
  AUT1 exposes. BATCH-FRZ1 remains last.

Landing rules:

- Parallel workers use clean worktrees from `revamp/spg-v1`.
- Product-doc workers may edit only their owned `docs/product/**` files plus
  directly related source/tests if their batch explicitly calls for proof or
  fixes.
- Parallel workers do not edit shared migration docs. They return a landing log;
  the conductor updates `task-batches.md` and `Session-Notes.md` after merge.
- Any implementation change still requires targeted tests, `git diff --check`,
  and security-boundary notes.
- Any product-doc claim about live behavior needs either a test reference, a
  live evidence block in `Session-Notes.md`, or an explicit `needs live proof`
  label.

Autonomy assessment:

- BATCH-AUT1 uses `docs/product/agent-autonomy-assessment.md` as the scorecard.
- Each MCP tool is scored for discoverability, sufficiency, context efficiency,
  composability, error recovery, provenance, security, and autonomy friction.
- Context bloat, unclear errors, missing provenance, tool gaps, and side-channel
  requirements are product defects, not just documentation issues.

## BATCH-PQA0 - Post-MVP QA and product documentation operating model

Dependencies: BATCH-V1; B-MVP-18.

Status (2026-06-09): DONE - created the `docs/product/**` documentation
workspace, added post-MVP batches, and established the parallel execution model
plus the serial AI-agent autonomy gate.

Scope:

- `docs/product/**`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`

Exact work:

- Create the product documentation workspace for architecture, flows,
  contracts, journeys, security, code structure, limitations, assessment, and
  demo runbook material.
- Define how post-MVP QA is tracked without adding more files under
  `docs/migration`.
- Define batch dependencies and parallelization.
- Make AI-agent autonomy a first-class scorecard and acceptance axis.

Acceptance:

- `docs/product/**` contains jump-in-ready skeleton documents with owning
  batches.
- `task-batches.md` contains grep-friendly post-MVP batch checkboxes and
  executable batch sections.
- `Session-Notes.md` records the new phase and next execution order.
- `python3 scripts/validate_docs.py` passes.
- `git diff --check` is clean.

## BATCH-PDOC1 - Product architecture, journeys, lifecycles, and code map

Dependencies: BATCH-PQA0.

Status (2026-06-09): DONE - merged `revamp/postmvp-pdoc1` as `eca5b10`
through integration merge `Merge BATCH-PDOC1 product architecture docs`.
Filled product architecture, data/process lifecycles, operator and AI-agent
journeys, interaction model, and code-structure map. Validation: worker
`python3 scripts/validate_docs.py` OK; worker `git diff --check` clean; root
integration validation recorded in `Session-Notes.md`.

Scope:

- `docs/product/architecture.md`
- `docs/product/data-flows-and-lifecycles.md`
- `docs/product/operator-journey.md`
- `docs/product/ai-agent-journey.md`
- `docs/product/interaction-model.md`
- `docs/product/code-structure.md`
- Existing diagrams/docs only if referenced directly from these files

Exact work:

- Revamp the product architecture diagrams for the hackathon narrative:
  authority plane, data plane, trust boundaries, portal journey, MCP journey,
  worker/job journey, and report/custody proof journey.
- Document process and data lifecycles: install, operator session, case,
  evidence, agent credential, MCP call, durable job, RAG import/query,
  investigation record, approval, report export, and custody proof export.
- Document the operator journey and AI-agent journey as product workflows.
- Produce a high/mid-level code map for future development and extension.

Acceptance:

- A future session can understand the product architecture and main flows from
  `docs/product/**` without rereading implementation history.
- Diagrams match the current Gateway/Postgres/worker/OpenSearch/RAG authority
  model.
- Operator and AI-agent journeys explicitly distinguish human authority from
  MCP-only autonomy.
- Code structure points future developers to the right packages and boundaries.

## BATCH-PDOC2 - API, MCP, and interaction contract documentation

Dependencies: BATCH-PQA0.

Status (2026-06-09): DONE - merged `revamp/postmvp-pdoc2` as `d0fcc31`
through integration merge `Merge BATCH-PDOC2 API and MCP contracts`. Filled
REST contract groups and MCP contract inventory for demo-critical tools,
including live-proven/source-derived labels, context budgets, provenance fields,
parallel-safety notes, and AUT1 flags. Validation: worker
`python3 scripts/validate_docs.py` OK; worker `git diff --check` clean; root
integration validation recorded in `Session-Notes.md`.

Scope:

- `docs/product/api-contracts.md`
- `docs/product/mcp-contracts.md`
- `docs/product/interaction-model.md`
- Gateway/portal source reads needed to inventory live contracts
- Optional narrowly scoped tests or scripts that print contract/catalog data

Exact work:

- Inventory Portal/Gateway REST contracts by route group, actor, auth, state
  transition, request/response shape, re-auth need, audit behavior, failure
  modes, and security notes.
- Inventory the live Gateway MCP catalog exactly as the agent sees it: tool
  names, descriptions, schemas, required scopes, inputs, outputs, errors, and
  examples.
- Classify each MCP tool for parallel safety, context budget, saved artifact
  behavior, provenance fields, and recovery guidance.
- Identify missing or misleading tool descriptions/schemas before AUT1.

Acceptance:

- `mcp-contracts.md` contains the verified live MCP inventory and tool contract
  template filled for the demo-critical tools.
- `api-contracts.md` contains the operator REST contract groups and lifecycle
  transitions needed for portal testing.
- Agent-visible contracts explicitly cover context management, path/secret
  redaction, provenance, and failure recovery.

## BATCH-SEC1 - Security architecture and assessment baseline

Dependencies: BATCH-PQA0.

Status (2026-06-09): DONE - merged `revamp/postmvp-sec1` as `73f5d38`
through integration merge `Merge BATCH-SEC1 security assessment docs`. Filled
security architecture and security assessment baseline; no open validated
critical/high freeze blockers were reported by the worker. Validation: worker
`python3 scripts/validate_docs.py` OK; worker `git diff --check` clean; root
integration validation recorded in `Session-Notes.md`.

Scope:

- `docs/product/security-architecture.md`
- `docs/product/security-assessment.md`
- Security-critical source/test reads for Gateway auth/policy, response guard,
  evidence gate, jobs, run_command, reports, Supabase migrations/RPCs, and
  portal auth/re-auth
- Narrow fixes only for validated high-impact security defects

Exact work:

- Produce the product security architecture: trust boundaries, control
  objectives, threat areas, accepted MVP caveats, and assessment method.
- Run a security assessment over auth/session, authorization, evidence gate,
  response leakage, job/worker boundary, run_command, RAG/OpenSearch/add-ons,
  and report integrity.
- Record findings with severity, evidence, remediation, and residual risk.
- Feed any agent-facing security observations into BATCH-AUT1.

Acceptance:

- Security assessment report is filled with tested findings or explicit "no
  finding" notes per area.
- Any critical/high validated issue is fixed or listed as a freeze blocker.
- Accepted caveats are bounded and reflected in
  `known-limitations-and-improvements.md`.

## BATCH-INST1 - Installer and component hardening QA

Dependencies: BATCH-PQA0.

Status (2026-06-09): DONE - conductor remediation pass on live VM service tree
`/home/sansforensics/sift-mcps-test`. AUT1-B1 fixed in code (Gateway overlays the
DB-authority evidence gate onto `case_info`/`evidence_info` orientation; legacy
file mode untouched) and live-proven through the agent MCP channel
(`evidence_chain` now `status=ok, ok=true, manifest_version=2, authority=db` on
the demo case, matching `app.evidence_gate_status`). `rag_search_case` confirmed
present in the live 13-tool catalog and callable (knowledge hits, `case_id=null`,
no path/secret leak). pgvector corpus matches the B-MVP-18 baseline
(`app.rag_chunks=26586`, all `kind='knowledge'`, `case_id NULL`,
`chroma_release_pgvector=22268`). `~/.sift/control-plane.env` is `600`;
`agent_runtime` ACLs verified on the demo case (evidence `r-x`,
`agent/extractions/tmp` `rwx`, authority files + `/var/lib/sift` denied);
worker heartbeating; OpenSearch container healthy; VM Python `3.12.3`. Caveat: a
full destructive `./install.sh` re-run was intentionally not executed on the live
demo VM to preserve prepared demo state and large corpora; installer idempotency
was checked structurally (`bash -n` + idempotency/Python-constraint guards) and
remains covered end-to-end by the BATCH-V1 install. Landed as a single conductor
commit on `revamp/spg-v1`; see `Session-Notes.md`.

Scope:

- `install.sh`
- `configs/**`
- `scripts/setup-agent-runtime.sh`
- Gateway/worker systemd templates
- Health checks and setup scripts
- `docs/product/known-limitations-and-improvements.md`
- Tests or live VM commands needed for reproducibility proof

Exact work:

- 2026-06-09 live repair note: portal re-auth/MCP-token issuance blockers were
  fixed and live-proven from the active VM service tree
  `/home/sansforensics/sift-mcps-test`. Future rsync/restart checks must target
  that tree unless the systemd unit is intentionally moved.
- Re-run or simulate install/refresh paths for idempotency, environment
  rendering, service restart, Supabase connectivity, evidence root validation,
  OpenSearch reachability, pgvector corpus import, and worker readiness.
- Use `Conductor.md` as the live operations runbook for host-to-VM rsync,
  VM dependency refresh, Gateway/worker restart, installer replay, env-file
  permission checks, `agent_runtime` ACL checks, OpenSearch checks, RAG
  download/import repair, and pgvector count proof.
- Close the AUT1 live-readiness gates before AUT2:
  - redeploy and live-prove AUT1-B3/B4/B5/B6 Gateway/core fixes;
  - make `rag_search_case` visible in the live MCP catalog and callable through
    the configured MCP client;
  - verify full forensic RAG corpus counts in Supabase pgvector against the
    B-MVP-18 baseline;
  - resolve AUT1-B1 by fixing DB-active `case_info`/`evidence_info`
    orientation, or prove the prepared demo case has file-backed orientation and
    DB evidence gate in agreement.
- Harden setup scripts for clear failures, no secret persistence, and VM Python
  constraints.
- Document exact operational caveats and recovery commands in product docs
  without storing raw secrets.

Acceptance:

- Installer/setup path can be repeated without manual patching.
- Gateway and worker restart/health checks are documented and reproducible.
- RAG download/import and OpenSearch setup behavior are covered.
- `~/.sift/*.env` permissions are verified as `600`, and raw secret values stay
  in VM-local files or local shell variables only.
- `agent_runtime` ACLs are verified for at least one prepared case: read/traverse
  sealed evidence, write only to approved output directories, no read/write to
  authority files or `/var/lib/sift`.
- Live Gateway MCP catalog includes `rag_search_case`, and a direct MCP
  `rag_search_case` call returns pgvector-backed knowledge results without path
  or secret leakage.
- Live pgvector proof records total chunk count, `kind`, `case_id`, and
  Chroma-import `seed_source` counts; any drift from the full-corpus baseline is
  explained.
- AUT1-B1 is fixed or operationally neutralized with live evidence before
  BATCH-AUT2 starts.
- No raw secrets are written to repo docs or generated tracked files.

## BATCH-AUT1 - AI agent autonomy and MCP tool-surface assessment

Dependencies: BATCH-PDOC2; BATCH-PDOC1 draft architecture/journeys.

Status (2026-06-09): DONE - merged `revamp/postmvp-aut1` through
`Merge BATCH-AUT1 agent autonomy assessment`. Worker commit `3813033` filled the
live MCP autonomy scorecard and fixed `job_status` malformed-id/raw-error
leakage. Conductor commit `0d27706` closed low-friction AUT1 findings by
disambiguating `run_command`/`run_command_job` descriptions, rewording
evidence-delete denial guidance away from side-channel instructions, and
sanitizing `get_tool_help` static examples. AUT1-B1 and AUT1-B2 remain explicit
pre-AUT2 gates, not hidden blockers.

Scope:

- `docs/product/agent-autonomy-assessment.md`
- `docs/product/mcp-contracts.md`
- `docs/product/ai-agent-journey.md`
- Gateway MCP/tool source and tests
- Narrow code/doc fixes for MCP descriptions, schemas, response shaping,
  pagination/previews, typed errors, provenance, or context bloat

Exact work:

- Assess the live MCP surface from the AI agent's point of view.
- Score each demo-critical tool for discoverability, sufficiency, context
  efficiency, composability, error recovery, provenance, security, and autonomy
  friction.
- Verify whether multiple read/job tools can be called in parallel safely and
  document serialized mutation points.
- Identify response bloat, missing context management, vague errors, missing
  fallbacks, and missing provenance.
- Produce concrete fixes or backlog entries before the demo-case benchmark.

Acceptance:

- Agent autonomy scorecard is filled with evidence.
- Demo-critical MCP tools have verified schemas, examples, error behavior,
  context budgets, and parallel-safety class.
- The assessment answers whether the existing tools are enough for an end-to-end
  forensic investigation through MCP only.
- High-impact autonomy blockers are fixed or explicitly block BATCH-AUT2.

## BATCH-AUT2 - Demo-case autonomous investigation benchmark

Dependencies: BATCH-AUT1; sealed demo case prepared by operator.

Scope:

- `docs/product/agent-autonomy-assessment.md`
- `docs/product/ai-agent-journey.md`
- `docs/product/demo-runbook.md`
- Demo-case evidence and live VM validation notes in `Session-Notes.md`
- Narrow MCP/tool fixes only for benchmark blockers

Exact work:

- Run the selected demo case with the agent restricted to MCP only after portal
  case activation, evidence register/seal, and agent issuance.
- Capture tool calls, failed calls, human interventions, largest responses,
  context-bloat events, findings with/without provenance, missed leads, unsafe
  attempts, and recovery behavior.
- Verify the agent can propose findings/timeline/TODOs and the operator can
  approve/report through the portal.
- Turn benchmark findings into fixes, limitations, or demo caveats.

Acceptance:

- The agent completes the demo investigation through MCP only, or blockers are
  documented with severity.
- Findings have provenance suitable for operator approval and report inclusion.
- Human intervention after agent start is limited to intended operator review
  and approval.
- The final autonomy score and caveats are ready for BATCH-FRZ1.

Result (2026-06-09):

- Status: **DONE with limitations**. The demo case was live-ready and the agent
  completed the controlled MCP-only smoke investigation through Gateway MCP. The
  run does **not** prove full autonomous analysis of the Rocba disk and memory
  images because primary-image ingest and deeper triage paths blocked.
- Final autonomy score: **14/24**. The surface is safe and usable for a
  smoke/custody demo, but insufficient for a full disk+memory DFIR demo without
  caveats.
- Fresh portal-issued `mcp:*` agents saw the 13-tool catalog including
  `rag_search_case`; DB gate was OK at `manifest_version=3`; four active sealed
  evidence objects were present.
- Agent records: `F-codex-1-001`, `T-codex-1-002`, and `TODO-codex-1-001`.
  The operator approval/report path was verified through the portal: approval
  committed with DB authority, report eligibility flipped to eligible, a
  findings-profile report was generated/saved/downloaded, and the downloaded
  report passed the AUT2 quick secret-shape scan.
- Required BATCH-FRZ1 caveats: `.e01`/`.raw` single-file `ingest_job` fails,
  `run_command.evidence_refs` still depends on file-manifest resolution,
  `record_finding` strong audit-id validation still scans the local JSONL audit
  trail instead of DB audit authority, Volatility cannot start due cache-path
  permissions, EWF/TSK probing is not yet usable for this image, and summary
  counters/listing fields still have file-mirror residuals.

Remediation result (2026-06-10):

- Status: **DONE as AUT2 remediation; FRZ1 still not complete**.
- Fresh agent credential TTL was corrected to about 48 hours by setting the
  live self-hosted Supabase Auth expiry to `172800` seconds.
- `evidence_info` now lists DB-authoritative sealed evidence objects instead of
  the stale file manifest list.
- `run_command` and `run_command_job` now resolve `evidence_refs` through DB
  evidence authority in Gateway/worker paths, while still rejecting
  client-supplied private resolver fields outside a DB-active context.
- `run_command` saved outputs and durable job receipts now return reusable
  relative `agent/run_commands/...` refs, including caller-provided logical
  `output_ref` names.
- Non-orientation MCP tool responses no longer repeat the active-case context
  block; `case_info`, `evidence_info`, and `capability_guide` retain it for
  orientation.
- AUT2 remediation score: **17/24**.
- Carried to BATCH-FRZ1 / next implementation pass: `.e01`/`.raw` ingest,
  DB-audit-backed `record_finding` artifact provenance, Volatility cache
  execution, reliable EWF triage, stale `case_info` counters, and an
  agent-facing installed-DFIR-tool inventory.

## BATCH-FRZ1 - Final freeze rehearsal, limitations, and demo runbook

Dependencies: BATCH-PDOC1; BATCH-PDOC2; BATCH-SEC1; BATCH-INST1; BATCH-AUT2.

Current status (2026-06-10):

- MCP-only freeze rehearsal proof is live-clean on the prepared demo case:
  services healthy, 13-tool catalog present, DB-backed `case_info` /
  `evidence_info` aligned to `manifest_version=4`, RAG corpus available, and
  bounded Volatility/E01 checks work through `run_command` with sealed
  `evidence_refs`.
- Portal login, HMAC re-auth, and fresh portal-issued agent TTL are live-proven:
  the new token TTL is 172800 seconds / 48 hours and the fresh token sees the
  13-tool catalog. Do not check BATCH-FRZ1 complete until re-acquisition click
  proof on a throwaway file, approval/report export if still required for the
  final demo, docs validation, and `git diff --check` all pass.
- Portal principal/session UX and MCP schema compatibility are source-fixed and
  live-deployed: the Settings table shows Supabase JWT token type, display name,
  active/expired/revoked status, TTL remaining, scopes, and a revoke button that
  disables/dims after success; the normal legacy PR02 token management surface
  was removed. `rag_search_case` now advertises a plain object schema (no
  top-level `anyOf`) and live `tools/list` shows 13 tools with
  `rag_search_case` callable.
- Installer hardening source changes are landed for `rg`, post-`uv sync` `pyewf`
  relink, worker unit install/restart, and sudoers helper wiring, but destructive
  throwaway-VM idempotency and dedicated non-admin service-user cutover proof
  remain open.
- Operator-requested next-session focus: leave offline Volatility symbol
  packaging/pre-warm and progress-stderr filtering for a fresh session; decide
  and implement or explicitly defer those two without reopening broad FRZ1 scope.

Scope:

- `docs/product/demo-runbook.md`
- `docs/product/known-limitations-and-improvements.md`
- `docs/product/README.md`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`

Exact work:

- Run the final demo rehearsal from installer/service readiness through portal
  operator flow, MCP-only agent investigation, report export, and custody proof.
- Freeze accepted limitations and improvement backlog.
- Produce the exact demo prompt and operator run sequence.
- Record final readiness evidence and commit hashes.

Acceptance:

- Demo runbook is executable without hidden side-channel steps.
- Known limitations are explicit, bounded, and non-fatal to the security and
  autonomy thesis.
- Product docs, migration tracker, and session notes agree on readiness.
- `python3 scripts/validate_docs.py`, relevant tests, and `git diff --check`
  pass.

## Parallel Prompt Pack

Use these prompts after the governance/doc-freeze commit is available on
`revamp/spg-v1`. Suggested worktree names are examples; adjust only the branch
suffix if needed.

### PROMPT-A1 - Installer and bootstrap

Suggested worktree:

```bash
git worktree add ../sift-mcps-a1 -b revamp/mvp-a1-installer-bootstrap revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-A1 coding agent for the SIFT MVP sprint. Build the installer/bootstrap slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 1, 2, 3 Phase 1, 4, and 5; docs/migration/task-batches.md BATCH-A1; docs/migration/Session-Notes.md latest entry and resolved F-MVP decisions.

GROUND IN SOURCE
Inspect only the BATCH-A1 scope paths before editing: install.sh; configs/gateway.yaml.template; configs/systemd/sift-gateway.service; configs/audit/99-sift-evidence.rules; configs/apparmor/sift-gateway.template; scripts/setup-agent-runtime.sh; packages/sift-gateway/src/sift_gateway/config.py; packages/sift-gateway/src/sift_gateway/health.py; packages/sift-gateway/src/sift_gateway/supabase_auth.py; packages/case-dashboard/src/case_dashboard/auth.py; packages/case-dashboard/src/case_dashboard/routes.py; directly related tests.

DELIVERABLE
Implement the final installer/bootstrap path: installation, config rendering, hardening, health check, Supabase-first operator bootstrap/forced reset, evidence root validation, and case path creation using /cases/case-<slug>-<MMDDHHSS> with -NN collision suffix.

HARD CONSTRAINTS
Do not add evidence DB schema, durable jobs, OpenSearch adapters, RAG changes, add-on changes, or report changes. Do not store secrets in repo files. Preserve /usr/bin/python3.12, UV_NO_MANAGED_PYTHON=1, and UV_PYTHON_DOWNLOADS=never for the SIFT VM.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, and any follow-up needed.

ACCEPTANCE
Operator can receive a one-time forced-reset handoff, login/reset through portal, create and activate a case with re-auth, and health output covers Gateway, portal, Supabase, evidence root, and configured services.
```

### PROMPT-B1 - Gateway policy and redaction

Suggested worktree:

```bash
git worktree add ../sift-mcps-b1 -b revamp/mvp-b1-gateway-policy-redaction revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-B1 coding agent for the SIFT MVP sprint. Build the Gateway policy/redaction slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md architecture invariants, trust boundaries, Phase 2 journey, and technical constraints; docs/migration/task-batches.md BATCH-B1; docs/migration/Session-Notes.md resolved F-MVP-2 and F-MVP-3.

GROUND IN SOURCE
Inspect only the BATCH-B1 scope paths before editing: packages/sift-gateway/src/sift_gateway/server.py; rest.py; mcp_server.py; mcp_endpoint.py; policy_middleware.py; evidence_gate.py; response_guard.py; rate_limit.py; packages/sift-core/src/sift_core/agent_tools.py; directly related Gateway/core tests.

DELIVERABLE
Make agent access MCP-only for the MVP, make REST tool execution operator-only, and sanitize agent-visible results. Agent-visible evidence data may include evidence_id, display name, relative display path, size, hash, seal status, and provenance ID. It must not include absolute case/evidence/mount paths or secrets.

HARD CONSTRAINTS
Do not implement installer changes, DB evidence authority, durable jobs, portal feature rewrites, OpenSearch adapters, RAG, add-ons, or reports. Keep evidence gate fail-closed.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, path-redaction evidence, and any follow-up needed.

ACCEPTANCE
Tests prove agent tokens cannot use REST to bypass MCP policy; case_info/evidence_info/finding views/run-command previews expose no absolute paths; evidence-gate denial is fail-closed and audited; response guard and rate limits still apply.
```

### PROMPT-C1 - Evidence authority and custody ledger

Suggested worktree:

```bash
git worktree add ../sift-mcps-c1 -b revamp/mvp-c1-evidence-custody revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-C1 coding agent for the SIFT MVP sprint. Build the DB evidence authority and custody ledger slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md component mapping, trust boundaries, Phase 2 journey, and DoD; docs/migration/task-batches.md BATCH-C1; docs/migration/Session-Notes.md resolved F-MVP-1 and F-MVP-2.

GROUND IN SOURCE
Inspect only the BATCH-C1 scope paths before editing: supabase/migrations/*.sql; packages/sift-gateway/src/sift_gateway/evidence_gate.py; packages/sift-gateway/src/sift_gateway/audit_helpers.py; packages/sift-core/src/sift_core/evidence_chain.py; verification.py; case_io.py; directly related evidence/custody tests.

DELIVERABLE
Add Postgres evidence metadata, evidence versions, custody events, hash-chain heads, seal status, and proof-export metadata. Add service-only transition RPCs for detect/register/seal/verify/ignore/retire/violation. Keep file manifests/proofs as exports, not authority.

HARD CONSTRAINTS
The AI agent never receives local paths. Evidence IDs resolve to mounted paths only inside broker/worker code. Do not wire portal UI broadly in this branch if it overlaps another worker; return route/UI follow-up for BATCH-E1. Do not add durable job worker logic.

OUTPUT DISCIPLINE
Use a new timestamped SQL migration file; do not edit prior migrations unless unavoidable and explained. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, and any route/UI follow-up.

ACCEPTANCE
DB state can represent detected, registered, sealed, ignored, retired, and violated evidence. Seal requires re-auth transition support. Custody events are append-only/hash-linked. Proof export can verify mounted evidence without making file manifests authoritative.
```

### PROMPT-D1 - Durable jobs and worker loop

Suggested worktree:

```bash
git worktree add ../sift-mcps-d1 -b revamp/mvp-d1-durable-jobs revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-D1 coding agent for the SIFT MVP sprint. Build the durable Postgres job and local worker slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md durable job state machine, worker, run-command, and Phase 2 journey; docs/migration/task-batches.md BATCH-D1; docs/migration/Session-Notes.md latest entry.

GROUND IN SOURCE
Inspect only the BATCH-D1 scope paths before editing: supabase/migrations/*.sql; packages/sift-core/src/sift_core/execute/worker.py; existing execute modules and tests; only Gateway files needed for a minimal enqueue/status adapter if BATCH-B1 has already landed in your branch.

DELIVERABLE
Add minimal Postgres job tables/RPCs and a local worker claim loop: jobs, job_steps, job_logs, worker heartbeats, typed statuses, claim lease, status update, failure logging, and retry/expiry behavior.

HARD CONSTRAINTS
Do not introduce Redis/RQ/Celery/Temporal. Do not take arbitrary client paths. Worker receives case_id/evidence_id/job_id and resolves local paths internally after policy. Avoid Gateway edits if they overlap BATCH-B1; return the enqueue/status adapter as follow-up if needed.

OUTPUT DISCIPLINE
Use a new timestamped SQL migration file separate from BATCH-C1. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, lease/race behavior evidence, and any follow-up.

ACCEPTANCE
Concurrent workers cannot claim the same job; lease expiry/retry is tested; portal/agent callers can poll sanitized status when the adapter is present; failed jobs preserve audit/provenance and sanitized logs.
```

### PROMPT-D2 - Gateway job adapter and authority enforcement

Suggested worktree:

```bash
git worktree add ../sift-mcps-d2 -b revamp/mvp-d2-gateway-job-contract-seam revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-D2 coding agent for the SIFT MVP sprint. Build the Gateway integration seam for jobs and add-on authority contracts. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md Gateway, Durable Job State Machine, Postgres Control Plane, derived/reference planes, and technical constraints; docs/migration/task-batches.md BATCH-D2; docs/migration/Session-Notes.md latest entry and B-MVP-3/B-MVP-4 rows.

GROUND IN SOURCE
Inspect only the BATCH-D2 scope paths before editing: packages/sift-gateway/src/sift_gateway/rest.py; server.py; mcp_server.py; mcp_endpoint.py; mcp_backends_registry.py; backends/**; sift-backend.schema.json; packages/sift-gateway/tests relevant to jobs/backend registry/scopes/manifests; supabase/migrations/202606081200_durable_jobs.sql only to confirm RPC/view names.

DELIVERABLE
Add the Gateway adapter over D1 job surfaces: enqueue_job, job_status_public, and expire_stale_jobs. Enqueue returns only job_id and stores the Gateway audit event id as enqueue_audit_event_id. Status responses are sanitized. Also enforce H1 authority_contract at runtime: non_authoritative, prohibited_operations, and tool required_scopes before backend dispatch. Keep transport: library manifests accepted but non-routable.

HARD CONSTRAINTS
Do not implement portal UI, OpenSearch ingest handlers, RAG, run_command handlers, report generation, or evidence UI. Do not expose DB errors, local paths, worker files, or credentials. Add SQL only if a minimal grant/wrapper is unavoidable and explain it.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests run, acceptance status, and whether E1/F1/G1/I1 can launch without more Gateway glue.

ACCEPTANCE
Tests prove job enqueue/status returns sanitized job_id/status only; missing required add-on scopes deny before backend dispatch; prohibited authority operations deny before backend dispatch; library manifests remain non-routable; existing Gateway backend registry tests stay green.
```

### PROMPT-H1 - Add-on contract hardening

Suggested worktree:

```bash
git worktree add ../sift-mcps-h1 -b revamp/mvp-h1-addon-contracts revamp/spg-v1
```

Prompt:

```text
ROLE & MODE
You are the BATCH-H1 coding agent for the SIFT MVP sprint. Build the add-on contract hardening slice. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md architecture invariants and derived/reference planes; docs/migration/task-batches.md BATCH-H1; docs/migration/Session-Notes.md latest entry.

GROUND IN SOURCE
Inspect only the BATCH-H1 scope paths before editing: packages/opencti-mcp/src/opencti_mcp/**; packages/windows-triage-mcp/src/windows_triage_mcp/**; packages/forensic-knowledge/src/**; packages/*/sift-backend.json; directly related add-on tests and surface snapshots.

DELIVERABLE
Align OpenCTI, Windows triage, and forensic knowledge add-ons with the final contract: query-only, audited, scoped, deterministic tool metadata, and non-authoritative. Preserve Windows triage baseline value and forensic knowledge discipline snippets.

HARD CONSTRAINTS
Add-ons must not create cases, seal evidence, approve findings, approve reports, expose secrets, bypass Gateway, or become case authority. Avoid Gateway registry edits if they overlap another worker; return integration follow-up if needed.

OUTPUT DISCIPLINE
Keep the scope fence. Do not edit docs/migration in this worker branch. End with a LANDING LOG block containing changed files, tests/snapshots run, acceptance status, and any registry follow-up.

ACCEPTANCE
Add-on metadata clearly marks capabilities and required scopes; query-only behavior is tested or snapshotted; tool surface snapshots remain deterministic; no add-on gains authority over cases, evidence, approvals, or reports.
```

## Next Prompt

Launch BATCH-K2, BATCH-K3, BATCH-K4, and BATCH-K5 in parallel worktrees.
BATCH-K6 waits until K2-K5 land. BATCH-V1 remains blocked until K1-K6 close the
DB-active authority cutover.

Suggested worktrees:

```bash
git worktree add ../sift-mcps-k2 -b revamp/mvp-k2-investigation-db-authority revamp/spg-v1
git worktree add ../sift-mcps-k3 -b revamp/mvp-k3-evidence-proof-cutover revamp/spg-v1
git worktree add ../sift-mcps-k4 -b revamp/mvp-k4-opensearch-host-authority revamp/spg-v1
git worktree add ../sift-mcps-k5 -b revamp/mvp-k5-run-command-authority-isolation revamp/spg-v1
```

### PROMPT-K2 - Core investigation DB authority

```text
ROLE & MODE
You are the BATCH-K2 coding agent for the SIFT MVP sprint. Cut over core
investigation state to Postgres authority in DB-active mode. Do not redesign the
architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially "Authority cutover impact model"; docs/migration/task-batches.md
BATCH-K2; the latest entry in docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K2 only. Inspect and edit only the K2 scope paths unless a test proves
a minimal adjacent change is required: sift_core case_manager/case_io/agent_tools/
reporting; sift_gateway portal_services; case-dashboard routes; the existing
202606081500 report/investigation migration for contract reference; direct core,
Gateway, portal, and DB tests.

SECURITY INVARIANTS
In DB-active mode, findings, timeline, TODOs, IOCs, approvals, report
eligibility, and content hashes are Postgres authority. JSON/JSONL files are
legacy fallback or mirror/export only. Agents cannot overwrite human-approved or
rejected records. Mutations must carry AuthorityContext audit event IDs.

DELIVERABLE
Implement the typed investigation authority store/port and wire agent tools,
portal approval/rejection/edit flows, and report reads to DB authority for
DB-active cases.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, schema/RPC gaps, and any K6
tamper-regression follow-up.

ACCEPTANCE
Agent-created findings/timeline/TODO/IOC records appear in portal from Postgres
without case JSON; portal approval/rejection updates DB and report eligibility;
tampering with findings/timeline/todos/iocs JSON or approvals.jsonl cannot alter
DB-active portal/report state; stale content-hash/version races are tested.
```

### PROMPT-K3 - Evidence proof and gate cutover

```text
ROLE & MODE
You are the BATCH-K3 coding agent for the SIFT MVP sprint. Cut over evidence
gate/proof export/Solana anchor behavior to DB authority. Do not redesign the
architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially the evidence, proof-export, and Solana carve-out parts;
docs/migration/task-batches.md BATCH-K3; the latest entry in
docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K3 only. Inspect and edit only the K3 scope paths unless a test proves
a minimal adjacent change is required: sift_core evidence_chain/verification/
case_io; sift_gateway evidence_gate/portal_services; case-dashboard evidence
routes/UI; the existing 202606081000 evidence custody migration for contract
reference; direct evidence/custody/proof-export tests.

SECURITY INVARIANTS
In DB-active mode, evidence gate state comes only from Postgres chain heads and
custody events. File manifests, ledgers, and anchor JSON are proof exports or
legacy fallback only. Optional Solana anchoring is external proof, not authority.

DELIVERABLE
Ensure evidence detect/register/seal/ignore/retire/violation transitions are
DB-first, proof exports derive from DB custody material, and new/changed files
after seal make the DB evidence gate non-OK until resolved and resealed.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, Solana/export behavior, and any
K6 tamper-regression follow-up.

ACCEPTANCE
Tampering with evidence-manifest.json, evidence-ledger.jsonl, or anchor JSON
cannot change DB-active gate state; missing/violated/unsealed/stale DB chain head
fails closed; proof export verifies mounted evidence and records metadata/hash in
Postgres; Solana configured/unconfigured paths degrade correctly.
```

### PROMPT-K4 - OpenSearch and host identity authority

```text
ROLE & MODE
You are the BATCH-K4 coding agent for the SIFT MVP sprint. Cut over OpenSearch
ingest status/provenance and host identity decisions to Postgres-backed derived
state. Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially the OpenSearch/host identity carve-out; docs/migration/task-batches.md
BATCH-K4; the latest entry in docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K4 only. Inspect and edit only the K4 scope paths unless a test proves
a minimal adjacent change is required: opensearch_mcp ingest/ingest_cli/
ingest_status/host_discovery/host_dictionary/server/registry/sift-backend.json;
sift_core job_worker; the existing 202606081300 OpenSearch provenance migration
for contract reference; direct OpenSearch/job/host tests and Gateway snapshots.

SECURITY INVARIANTS
Hostname detection/index naming remains required derived parser metadata.
Host identity and ingest status do not authorize cases, evidence, approvals, or
reports. Local host-dictionary/status/manifest files are parser compatibility,
debug, or legacy only in DB-active mode.

DELIVERABLE
Move DB-active ingest status, provenance manifests, host discovery decisions,
host dictionary mutations, and host-fix receipts into Postgres-backed records.
Preserve `opensearch_fix_host_mapping` canonical behavior and deprecated
`opensearch_host_fix` alias without leaking paths/credentials.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, schema/RPC gaps, and any K6
tamper-regression follow-up.

ACCEPTANCE
Portal/agent ingest status comes from Postgres job/provenance state; host
identity decisions/corrections are DB-recorded with source/canonical/actor/tool/
affected IDs/audit ID; tampering with host-dictionary.yaml cannot change
DB-active authority; parser/index behavior remains compatible.
```

### PROMPT-K5 - run_command authority isolation

```text
ROLE & MODE
You are the BATCH-K5 coding agent for the SIFT MVP sprint. Harden run_command so
it cannot read/write authority state and persists command receipts in Postgres.
Do not redesign the architecture.

REQUIRED READING
Read, in order: AGENTS.md; docs/migration/Migration-Spec.md sections 2, 3, 4,
and 5, especially the run_command and authority cutover constraints;
docs/migration/task-batches.md BATCH-K5; the latest entry in
docs/migration/Session-Notes.md.

SCOPE
Own BATCH-K5 only. Inspect and edit only the K5 scope paths unless a test proves
a minimal adjacent change is required: sift_core execute generic/executor/
security/security_policy/run_command_job/runtime_acl/agent_tools; Gateway
job_tools; setup-agent-runtime.sh; sift-job-worker systemd unit; direct execution,
ACL, redaction, and job tests.

SECURITY INVARIANTS
run_command receives opaque evidence/input refs and controlled output refs only.
It must not inherit DB DSNs, Supabase keys, service-role secrets, OpenSearch
credentials, VM secrets, or unrelated env. It must not read/write authority files
or change portal/report/evidence state except through approved DB authority APIs.

DELIVERABLE
Harden job-backed run_command path resolution/env/ACLs, persist command receipt
metadata in Postgres, keep shell=False/deny floor/allowlist profiles/path
redaction/bounded previews, and prove allowed and denied paths.

OUTPUT DISCIPLINE
Do not edit docs/migration in this worker branch. End with a LANDING LOG block:
changed files, tests run, acceptance evidence, ACL/env proof, and any K6
tamper-regression follow-up.

ACCEPTANCE
Allowed commands work against sealed evidence refs and return job/status plus
redacted previews; denied commands fail closed and are audited; commands cannot
read DB/service secrets or write authority state; output receipts are DB-backed
and reportable without local paths.
```

## Post-Migration Install & Cleanup (PMI) Track

Goal: a single `./install.sh --no-windows-triage --no-opencti` on a BARE SIFT VM
brings up everything live (Supabase via CLI, migrations, OpenSearch 3.5 + Hayabusa,
RAG pgvector, gateway+worker+portal), then the operator runs the Rocba case.

### PMI operating model (LEAN — read this first)
- One worktree per batch off `revamp/spg-v1`; one commit per batch; scope-fenced.
- Tests: run ONLY the targeted tests for the package(s) you touched, plus `bash -n`
  for any shell script. DO NOT run full suites every session. The single full
  integration check is BATCH-PMI4 (live VM) — that is where end-to-end is proven.
- Log: one line per batch in `Session-Notes.md`. No new runbooks.
- PMI1 and PMI2 are DISJOINT -> run in PARALLEL. PMI3 is small, touches install.sh
  env-writing -> run after PMI1 (or solo). PMI4 is last, after PMI1/PMI2/PMI3.

### Locked decisions (context for all PMI batches)
- OpenSearch = 3.5 (Hayabusa-compatible; Sigma percolator broken on 3.5 -> Sigma
  detectors stay DISABLED, detection is Hayabusa-during-evtx-ingest). 2.18 was a
  stopgap; cut over to 3.5.
- RAG has ONE home = Supabase Postgres pgvector (`app.rag_chunks`, served by core
  `rag_search_case`). The standalone Chroma `kb_search_*` tools are a redundant
  duplicate to delete; keep the Chroma->pgvector importer only as the load step.
- `forensic-knowledge` (FK enrichment / anti-drift reminders) is CORE context-
  injection, NOT a RAG — KEEP it; it just never fires because FK_DATA_DIR is unset.
- Add-ons (opencti, windows-triage) are read-only, zero authority to mutate state/
  config, behind the Backend Contract — unchanged here.
- BATCH-PMI0 landed: commit `1742172` (installer hardening + Supabase CLI v2.105
  lean stack jwt_expiry=172800 + --network-id loopback isolation + apply_db_migrations
  + opensearch env/restart fixes + linger + hardened poll). install.sh + setup-supabase.sh
  are `bash -n` clean; live-VM validation is PMI4.

## BATCH-PMI0 - Installer hardening + Supabase CLI bring-up

Landed (commit `1742172`); see "Locked decisions" above. Acceptance: `bash -n` clean on
install.sh + setup-supabase.sh; config.toml parses; :9200 loopback. Live-VM acceptance
is BATCH-PMI4.

## BATCH-PMI1 - OpenSearch 3.5 cutover + Sigma-disable/Security-Analytics cleanup

LANDED 2026-06-10 (security-disabled/loopback posture; see Session-Notes). Fork
F-MVP-OS35-SEC resolved -> `DISABLE_SECURITY_PLUGIN=true` + loopback `:9200`; "enable
security" deferred to backlog B-MVP-OS35-SEC. Root + package composes on `3.5.0`/4g heap;
`install.sh` gained `configure_opensearch_detections()` (http/no-auth detector+monitor
cleanup + Sigma aliases, Sigma detectors stay disabled); package `setup-opensearch.sh`
reconciled to http/no-auth. Tests: opensearch-mcp `1025 passed, 73 skipped`.

Prompt (paste as the agent task). Scope: `docker-compose.yml`, `install.sh` (start_opensearch + opensearch config
funcs only), `packages/opensearch-mcp/**` (client/security/config + the Security
Analytics setup), `packages/opensearch-mcp/docker/docker-compose.yml`. Reference the
OLD working script `/home/yk/AI/SIFTHACK/opensearch-mcp/scripts/setup-opensearch.sh`
(VHIR) for the 3.5 Security-Analytics cleanup pattern. Do: switch the OpenSearch image
to 3.5 (the packages/opensearch-mcp/docker compose already pins 3.5.0 with
OPENSEARCH_INITIAL_ADMIN_PASSWORD); wire the admin password into opensearch.yaml/client
(or keep DISABLE_SECURITY_PLUGIN if that is the chosen 3.5 posture — pick one and make
it consistent across compose + client); keep :9200 bound to 127.0.0.1; port the
Sigma-disable + non-functional-detector/orphaned-monitor cleanup + alias setup from the
VHIR script so install doesn't create dead detectors; confirm Hayabusa detection +
`opensearch_list_detections`/`opensearch_aggregate` still work. Tests: opensearch-mcp
targeted tests only + `bash -n install.sh`. Do NOT touch RAG/forensic-rag or gateway core.

## BATCH-PMI2 - RAG single-home: remove standalone Chroma kb_search_* path

LANDED 2026-06-10 (see Session-Notes). Removed the three Chroma `kb_search_*` agent tools
from `forensic-rag-mcp` (manifest now `provides:[]`/`tools:[]` v2.0.0; server is a zero-tool
harness; `pgvector_store` + importers kept); dropped `setup_rag` from `setup-addon.sh`.
pgvector `rag_search_case` (gateway core, untouched) is the only agent-facing RAG. Tests:
forensic-rag-mcp `27 passed`.

Prompt (paste as the agent task). Scope: `packages/forensic-rag-mcp/**` (remove the Chroma kb_search backend serving +
the `kb_search_knowledge`/`kb_list_knowledge_sources`/`kb_get_knowledge_stats` tools +
its sift-backend.json manifest), `scripts/setup-addon.sh` (remove the RAG/`setup_rag`
option). KEEP `rag_mcp.pgvector_store`, the Chroma->pgvector importers
(`pgvector_chroma_import`, `pgvector_seed`), and the gateway core `rag_search_case`
(do NOT touch `packages/sift-gateway/**`). Net result: pgvector is the only agent-facing
RAG; Chroma remains only as an internal import source. Tests: forensic-rag-mcp targeted
tests only. Do NOT touch OpenSearch or gateway core.

## BATCH-PMI3 - FK enrichment actually fires (wire FK_DATA_DIR)

Prompt (paste as the agent task). Scope: `install.sh` (env writing region) + `configs/systemd/sift-gateway.service` +
`configs/systemd/sift-job-worker.service`; verify-only in
`packages/forensic-knowledge/src/forensic_knowledge/loader.py` and
`packages/sift-core/src/sift_core/execute/response.py`. Problem: FK enrichment
(`build_response`, run_command path) never injects because FK_DATA_DIR is unset in the
service env and the loader can't resolve the data dir under the service user. Do: resolve
the installed `forensic-knowledge` data dir, write `FK_DATA_DIR=<that path>` into a
gateway/worker env file (or Environment= line), and confirm the loader finds it. Keep the
existing run_command scope + decay budget. Tests: forensic-knowledge/sift-core targeted
tests + `bash -n install.sh`. Live confirmation is in PMI4.

## BATCH-PMI4 - VM proof: bare-SIFT -> live stack -> Rocba case run

Operator-run, last. On the bare SIFT VM: `./install.sh --no-windows-triage --no-opencti`; confirm
`status:ok` (not degraded), job-worker not crash-looping, aggregate /mcp lists
`opensearch_*` + the forensic-rag-mcp knowledge tools (`kb_search_knowledge` etc., per
BATCH-OSX-RAG; `rag_search_case` is removed) after the post-seed restart, `app.rag_chunks`
populated, Hayabusa detections queryable. Then portal: create case -> issue agent token
-> register+seal Rocba disk+RAM evidence -> run the agent end-to-end. Record command-level
proof in `Session-Notes.md`. This is the ONLY full end-to-end gate.

# OpenSearch Excellence + RAG-Port + Purge (OSX) Track

Goal: make OpenSearch a reliable, well-defined, context-efficient first-party surface; finish
the forensic-rag-mcp -> pgvector port the way it was actually specced (parity, not a thinner
duplicate); and purge the consolidation debt discovered in the code-discovery pass. Planned
2026-06-10. Same LEAN operating model as the PMI track (targeted tests per batch; the one full
end-to-end gate stays BATCH-PMI4 / OS6 on the VM).

## OSX operating model + tooling

- One worktree per batch off `revamp/spg-v1`; one commit per batch; scope-fenced. **Do NOT use
  the Agent `isolation: worktree` feature in this repo** — it branches off `origin/HEAD`
  (`origin/main`, weeks stale, pre-sift-branding) and corrupts the work (this caused the
  2026-06-10 crashed-team incident). Create worktrees manually: `git worktree add ../sift-mcps-<b> revamp/spg-v1`, or run inline in the main worktree when batches are file-disjoint.
- Targeted tests only per batch (the touched package) + `bash -n` for shell + a doc-validator run.
- Optional orientation aid: **understand-anything** (`/understand` regenerates the graph,
  `/understand-chat "q"` queries it, `/understand-dashboard` opens the HTML). It is a good
  LEAD generator for architecture orientation and stale-code candidates, but it has a HIGH
  false-positive rate on this repo (its static `calls`/`imports` edges miss shell-function
  calls, FastAPI/FastMCP decorators, dynamic dispatch, data-glob loaders, and entry-points — it
  will flag live MCP tools and install.sh functions as "dead"). ALWAYS verify a candidate against
  real `grep`/usage before acting. The `.understand-anything/` artifacts are gitignored (local only).

## Discovered architecture (grounding for this track — verified 2026-06-10)

- **OpenSearch runtime today = stdio add-on branded core (NOT worker-run).** `install.sh
  seed_addon_backends()` (~L620-696) writes a `transport="stdio"` row into `app.mcp_backends`
  (`uv run … opensearch-mcp`, env-refs `OPENSEARCH_CONFIG`/`OPENSEARCH_HOST`, `tier="addon"`).
  The **gateway** (not the worker) reads it in `Gateway.__init__` -> `create_backend_instances()`
  -> `StdioMCPBackend.start()` spawns the subprocess; `mcp_server._mount_addon_proxies()` mounts
  a FastMCP stdio proxy. The job worker only imports `opensearch_mcp.job_ingest` as a LIBRARY for
  durable `ingest` jobs — it never supervises the MCP subprocess.
- **"No tools until restart" root cause:** backend instances are built ONCE at `Gateway.__init__`;
  if `seed_addon_backends` writes the row AFTER the gateway started, the registry read already
  returned zero rows. `_late_start_checker` (server.py ~L606-633) retries only ALREADY-instantiated
  backends — it never re-reads the DB. Only a restart re-reads `app.mcp_backends`. Also a likely
  double-spawn smell: the backend instance and the proxy each open a stdio subprocess.
- **`rag_search_case` is a migration-era duplicate, not the spec.** Pre-migration
  (`/home/yk/AI/SIFTHACK/sift-mcp/packages/forensic-rag/src/rag_mcp/server.py`) forensic-rag
  registered its OWN tools (`search_knowledge` + `list_knowledge_sources` + `get_stats`, with
  `source/source_ids/technique/platform` filters); `rag_search_case` did not exist. BATCH-G1
  added a thinner gateway-core pgvector tool (`rag_bridge.py:PgVectorRagQueryService` +
  `mcp_server._register_rag_tool`) instead of porting the real tools; BATCH-PMI2 then deleted the
  forensic-rag-mcp tools. Net: the agent lost the richer DFIR-knowledge query. **Vector parity is
  intact** — `pgvector_chroma_import.py` copies the original BGE 768-d vectors 1:1 from the big
  Chroma release bundle (model-mismatch-guarded); runtime query is embedded with the same BGE model
  (`rag_bridge._embed_query`); `deterministic_embedding()` is smoke-data only. So keep pgvector;
  restore the tool surface on top of it. (Decision: SUPERSEDES PMI2.)
- **Dependency note:** `sentence-transformers` (BGE) is REQUIRED at runtime to embed the query —
  it stays. Only `chromadb` is import-only -> can become optional.

## OSX forks / decisions (resolved this planning session)

- **F-MVP-OS-WIRING:** OpenSearch mounting fix approach. RESOLVED -> **P1** (keep stdio add-on;
  fix the seed-before-start race + dedupe double-spawn). P2 (static first-party backend) and P3
  (true in-process core like rag_search_case) recorded as future options, NOT chosen now. P3 would
  trade away process isolation; revisit post-MVP.
- **F-MVP-RAG-PORT:** RAG home. RESOLVED -> port forensic-rag-mcp's ORIGINAL tools to pgvector at
  full parity (filters + list-sources + stats), register forensic-rag-mcp as the knowledge backend,
  REMOVE `rag_search_case`. Keep pgvector (vectors are the original big corpus). Supersedes the
  PMI2 "single-home = rag_search_case" decision.
- **F-MVP-RAG-DERIVED (OPEN):** `rag_search_case` adds case-scoped *derived*-chunk retrieval that
  the original tool never had ("more than spec"). Before removing it, OSX-RAG must check whether
  anything writes/reads case-derived rag chunks; if unused, drop with the shim; if used, decide
  whether derived-RAG is a separate keep. Resolve in OSX-RAG.

## Orchestration / wave order

- Gateway+install seed are a shared fence -> **OSX1 then OSX-RAG run serially** (both touch
  `sift-gateway` server.py/mcp_server.py + `install.sh` seed).
- **OSX2 (opensearch-mcp) ∥ OSX3 (doc spike) ∥ PMI3 (install env+systemd)** are file-disjoint from
  the gateway chain and from each other -> run in parallel.
- **OSX-PURGE** runs AFTER OSX-RAG (forensic-rag-mcp file overlap) and after OSX2 (opensearch-mcp).
- **PMI4 / OS6** (VM proof) is LAST and validates the whole stack end to end.

## BATCH-OSX1 - OpenSearch backend mounting fix (P1) + dedupe double-spawn

Prompt (paste). Scope: `packages/sift-gateway/src/sift_gateway/{server.py,mcp_server.py}` and
`install.sh` (the `main()` ordering around `seed_addon_backends` + the gateway start/poll).
Problem + landmarks are in "Discovered architecture" above. Do: (1) ensure the opensearch backend
row exists in `app.mcp_backends` BEFORE the gateway starts (reorder install.sh so seeding +
gateway start are ordered correctly), AND/OR make the gateway pick up newly-seeded backends without
a full restart — extend `_late_start_checker` (server.py ~L606-633) to re-read `app.mcp_backends`
and instantiate rows that appeared after `__init__`, or add an explicit reload path. (2) Dedupe the
double stdio spawn: confirm whether `StdioMCPBackend.start()` and `_mount_addon_proxies()`
(`mcp_server.py` ~L495-568) each launch a subprocess; if so, make the proxy reuse the started
backend's transport/session instead of opening a second one. Keep process isolation + env-ref
secrets. Tests: sift-gateway targeted tests (backend registry / mount / late-start) + `bash -n
install.sh`. Do NOT change opensearch-mcp internals or RAG. Live confirmation is PMI4.

## BATCH-OSX2 - OpenSearch FastMCP surface optimization

Prompt (paste). Scope: `packages/opensearch-mcp/sift-backend.json` (manifest tool metadata) +
`packages/opensearch-mcp/src/opensearch_mcp/{server.py,tools.py,registry.py}` (FastMCP tool
decorators/docstrings) + any tool_metadata. Reference (read first): the two Anthropic articles
in Session-Notes (advanced-tool-use; code-execution-with-MCP). Do: raise every OpenSearch tool to
the advanced-tool-use bar — descriptive names; descriptions that enumerate capabilities; explicit
OUTPUT schema/field docs; `when_to_use`/`avoid_when`; 1-5 realistic usage examples (minimal/partial/
full) per non-trivial tool; enums + sensible defaults; response shaping for context efficiency (lean
into the existing `save_output`+path "reference, not raw bytes" pattern, `preview_lines`, filter/
pagination params); and tighten the per-tool prompts/recommended_phase. Add `defer_loading: true`
(Tool Search) candidacy notes for the lower-frequency tools given the large OS tool set. Keep tool
BEHAVIOR identical — this is definition/schema/prompt quality only. Tests: opensearch-mcp targeted
tests (surface snapshot / manifest / tools) — update the golden surface snapshot if tool metadata
changes, and say so. Do NOT touch gateway/RAG/install.

## BATCH-OSX-RAG - Port forensic-rag-mcp tools to pgvector at full parity; remove rag_search_case

Prompt (paste). Scope: `packages/forensic-rag-mcp/**` (restore the tools, backed by pgvector),
`packages/sift-gateway/src/sift_gateway/{rag_bridge.py,server.py,mcp_server.py}` (REMOVE the
rag_search_case shim + its registration), a NEW `supabase/migrations/*.sql` (extend the
`app.rag_search` SQL function with `source/technique/platform/source_ids` filters — append-only, do
NOT edit existing migrations), `install.sh seed_addon_backends` + `scripts/setup-addon.sh` (register
forensic-rag-mcp as a backend again). Grounding is in "Discovered architecture" above. Do: (1)
Re-add forensic-rag-mcp's ORIGINAL tool surface — `kb_search_knowledge` (with
`query, top_k, source, source_ids, technique, platform`), `kb_list_knowledge_sources`,
`kb_get_knowledge_stats` — but backed by `PgVectorRagStore` (the filter metadata is already in the
chunk `metadata` jsonb from the importer; surface it). Reuse the BGE query embedding currently in
`rag_bridge._embed_query` (move it into forensic-rag-mcp). (2) Extend `app.rag_search` + `PgVectorRagStore.search`
to accept the metadata filters (shared-knowledge scope = original behavior). (3) Remove
`rag_search_case`, `rag_bridge.py`, the `_register_rag_tool` call, `PgVectorRagQueryService`, and the
`_gateway_local_tools`/`_CORE_TOOL_CATEGORIES` entries. (4) Resolve F-MVP-RAG-DERIVED: grep for
writers/readers of case-derived rag chunks; if none, drop derived-RAG with the shim; else record a
follow-up. Keep `forensic-rag-mcp` the package (dense corpus). `chromadb` -> optional dep;
`sentence-transformers` STAYS (runtime query embedding). Tests: forensic-rag-mcp targeted tests
(new pgvector-backed tool tests incl. each filter) + a DB schema test for the new migration +
sift-gateway tests (rag tool gone). Acceptance (defer live to PMI4): pre-migration tool parity
(same tool names + params); VM cross-check that `app.rag_chunks` count == the big Chroma bundle
record count (memory baseline 26,586), not the small seed. Mark PMI2 superseded in Session-Notes.

## BATCH-OSX3 - Programmatic tool-calling / code-execution-with-MCP feasibility spike (doc-first)

Prompt (paste). Scope: a short feasibility+design write-up appended to `Session-Notes.md` (no new
runbook) + a minimal read-only probe; no production code. Reference (read first): the two Anthropic
articles in Session-Notes. Goal: let the agent WRITE CODE that calls OpenSearch tools and filters/
transforms/pipes results locally so a huge OS query result never floods context. Assess: (a) does
the agent runtime support API-level Programmatic Tool Calling (`allowed_callers:
["code_execution_20250825"]`) + Tool Search (`defer_loading`)? (b) Could we instead expose OS tools
as a code-API module set inside the EXISTING sift-core execute sandbox (run_command security stack:
`execute/security.py`, `security_policy.py`, `executor.py`) — i.e., the "MCP-as-code-APIs in a
sandbox" pattern — reusing our isolation rather than building a new one? Note current run_command is
shell-less argv, not a Python sandbox, so spell out the gap. Deliver: a feasibility verdict
(supported now / needs harness work / out of scope), a recommended implementation path with the
smallest secure footprint, the security model (sandboxing model-written code, network isolation to
only OS, resource limits, audit), and a follow-on impl batch outline (OSX4) if green. This is the
"winning feature" spike — be concrete, cite the articles' patterns.

## BATCH-OSX-PURGE - Purge stale/unused (verified 2026-06-10)

Prompt (paste). Runs AFTER OSX-RAG + OSX2. Scope: delete only VERIFIED-dead targets, with `grep`
proof in the commit. HIGH-confidence: `packages/forensic-mcp/` (whole package — in
`_RETIRED_CORE_BACKENDS`, zero external imports, not in install.sh; also drop it from root pyproject
`[core]`); the dead Chroma INDEX modules in forensic-rag-mcp that OSX-RAG leaves unused
(`index.py, build.py, refresh.py, status.py, sources.py, analyze_queries.py, tuning_config.py,
fs_safety.py, scripts/build_release.py`) — confirm none are imported by the pgvector path after
OSX-RAG; empty `tool_metadata.py` if still empty. MEDIUM (review first, don't bulk-delete):
`windows-triage-mcp/scripts/*` (import a non-existent `windows_triage_mcp_mcp` module — but that
token also appears in live src files, so investigate before touching; add-on, non-MVP);
`compute_content_hash` consolidation (`case_io.py` vs `investigation_store.py` vs the
`case-dashboard/routes.py` shadow — diverging `_HASH_EXCLUDE_KEYS`; consolidate to the
`investigation_store` DB-authority copy, careful key reconciliation). Already done in the OSX plan
commit: `scripts/test_mcp.py` (committed token) removed + `.understand-anything/` gitignored — the
token still needs ROTATION. Tests: targeted tests for each touched package + the full gateway
manifest/`test_phase6` suite if any backend list changes. `chromadb` -> optional dep (coordinate
with OSX-RAG). Be conservative; `log` anything dropped.
