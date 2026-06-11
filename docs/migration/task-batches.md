# Task Batches

Status: MVP sprint execution tracker.
Last updated: 2026-06-12.

Rules:

- Use one worktree per batch when running parallel sessions off `main`.
- Checkboxes are grep targets. Mark only the leading batch checkbox when the
  batch acceptance checks pass.
- Do not start dependent work until dependencies are checked complete.
- Keep new planning in this file. Do not create more migration docs.
- Parallel worker branches must not edit `docs/migration`. A worker returns
  a landing log block; the conductor updates this tracker and `Session-Notes.md`
  after merge.

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
- [x] BATCH-PMI3 - FK enrichment actually fires (wire FK_DATA_DIR)
- [ ] BATCH-PMI4 - VM proof: bare-SIFT -> live stack -> Rocba case run
- [x] BATCH-OSX1 - OpenSearch backend mounting fix (P1: seed-before-start race + dedupe double stdio spawn)
- [x] BATCH-OSX2 - OpenSearch FastMCP surface optimization (tool defs/schemas/examples/prompts; advanced-tool-use)
- [x] BATCH-OSX-RAG - Port forensic-rag-mcp tools to pgvector at full parity + remove rag_search_case shim
- [x] BATCH-OSX3 - Programmatic tool-calling / code-execution-with-MCP feasibility spike (doc-first)
- [x] BATCH-OSX-PURGE - Purge stale/unused (forensic-mcp, dead Chroma index modules, broken win-triage scripts)
- [x] BATCH-NW1 - compute_content_hash consolidation (operator priority #1; test on fresh install)
- [x] BATCH-NW2 - Remove windows-triage-mcp entirely + decouple opensearch enrich-triage
- [x] BATCH-NW3 - Add-on Backend Contract documentation (hackathon modularity story)
- [x] BATCH-NW4 - RAG knowledge-only hardening (drop per-case derived RAG; privacy)
- [x] BATCH-NW5 - opensearch run_command duplicate check (RESOLVED: none exists, no action)
- [ ] BATCH-NW6 - Programmatic Tool Calling: enable + native-harness validation (reframed OSX3)
- [ ] BATCH-HARD1 - Non-admin service-user cutover + shared vol3 symbol cache

## OpenSearch Restoration (OS Track) — Locked Decisions

OS1-OS5 all landed. Only OS6 (live VM smoke) remains.

- OpenSearch stays standalone in `packages/opensearch-mcp/**`.
- Gateway is the only agent-facing policy boundary.
- Supabase/Postgres is authority; OpenSearch is derived/rebuildable.
- OS6 runs as part of PMI4 (the bare-SIFT VM install).

## BATCH-OS0 - OpenSearch disappearance baseline and restoration order

DONE. Baseline recorded; OS1-OS6 restoration track opened.

## BATCH-OS1 - DB backend seed and aggregate catalog visibility

DONE (commit `ce3748e`). `install.sh seed_addon_backends()` registers opensearch-mcp in
`app.mcp_backends`; gateway backend registry tests: 107 passed.

## BATCH-OS2 - Active-case proxy compatibility for OpenSearch tools

DONE (commit `ce3748e`). Manifest-declared `safe_case_argument_names` per tool; tri-state
fail-closed injection; gateway suite: 439 passed.

## BATCH-OS3 - Read-only OpenSearch investigation surface

DONE. No code change required; manifest/registry/golden/catalog already agreed.
opensearch-mcp suite: 1015 passed, 71 skipped.

## BATCH-OS4 - Job-backed ingest using standalone OpenSearch code

DONE (commit `cff7378` + `aae168b`). Gateway-local `opensearch_ingest` shadow registered; 27
new tests; gateway suite: 447 passed.

## BATCH-OS5 - Host identity, enrichment, and mutating-tool policy

DONE (commit `ba781c5` + `ade8442`). Fail-closed receipt gate; scope/prohibited_operations in
manifest; gateway suite: 447 passed.

## BATCH-OS6 - Live VM OpenSearch proof

Dependencies: BATCH-OS1; BATCH-OS2; BATCH-OS3; BATCH-OS4; BATCH-OS5. Runs during PMI4.

Scope:

- Deployment/smoke only on the active VM tree.
- `docs/migration/Session-Notes.md` closeout after proof passes.

Exact work:

- Sync to VM; restart `sift-gateway.service` and `sift-job-worker.service`.
- Verify Gateway health, Supabase, evidence root, worker, and OpenSearch.
- Issue a fresh portal agent principal and prove aggregate `/mcp tools/list`
  includes `opensearch_*` and `kb_*` WITHOUT a restart (OSX1 race fix).
- Confirm `app.rag_chunks` is populated by the direct model-backed pgvector seed and Hayabusa
  detections are queryable.
- Run one read-only OpenSearch path, then one sealed-evidence ingest job.

Acceptance:

- Live aggregate MCP shows OpenSearch tools present and callable.
- Search/ingest uses DB active case and sealed evidence only.
- No path, DSN, service-role key, token, or OpenSearch credential leakage.
- `Session-Notes.md` records command-level proof after checks pass.

## BATCH-A0 - Freeze simplified migration operating model

DONE.

## BATCH-A1 - Final installer, Supabase bootstrap, forced reset, and health contract

DONE.

## BATCH-B1 - Gateway policy parity and agent response redaction

DONE.

## BATCH-C1 - DB evidence authority, custody ledger, and seal broker

DONE.

## BATCH-D1 - Durable Postgres jobs and local worker claim loop

DONE.

## BATCH-D2 - Gateway job adapter and add-on authority enforcement

DONE.

## BATCH-E1 - Portal authority migration for evidence, findings, timeline, TODOs, and reports

DONE.

## BATCH-F1 - OpenSearch secure core integration and ingest job adapter

DONE.

## BATCH-G1 - RAG pgvector target with provenance filters

DONE.

## BATCH-H1 - Add-on contract hardening for OpenCTI, Windows triage, and forensic knowledge

DONE.

## BATCH-I1 - Sandboxed run_command uplift

DONE.

## BATCH-J1 - Approved-only report generation and export

DONE.

## BATCH-L1 - Live service binding, worker bootstrap, and Gateway tool bridge

DONE.

## BATCH-K0 - Authority cutover impact model and batch freeze

DONE.

## BATCH-K1 - Authority context and DB audit cutover

DONE (commit `0e9577a`). `AuthorityContext` introduced; DB-active fail-closed behavior; DB-first
`app.audit_events` envelope writes.

## BATCH-K2 - Core investigation DB authority cutover

DONE.

## BATCH-K3 - Evidence gate, proof export, and Solana anchor cutover

DONE.

## BATCH-K4 - OpenSearch derived-state and host identity cutover

DONE.

## BATCH-K5 - run_command authority-isolation hardening

DONE.

## BATCH-K6 - Portal/report tamper regression and file-authority removal

DONE.

## BATCH-V1 - End-to-end validation and cutover

DONE (2026-06-08). Live VM cutover/smoke completed from `revamp/spg-v1`. Post-cutover:
B-MVP-18 done (26,586 Chroma->pgvector chunks, all `kind='knowledge'`, `case_id NULL`).

## Post-MVP QA Batches — all done except FRZ1

BATCH-PQA0, PDOC1, PDOC2, SEC1, INST1, AUT1, AUT2 all DONE.
Final autonomy score after AUT2 remediation: **22/24**.
See `docs/product/agent-autonomy-assessment.md` for per-category basis.

## BATCH-PQA0 - Post-MVP QA and product documentation operating model

DONE (2026-06-09). Created `docs/product/**` workspace; parallel execution model established.

## BATCH-PDOC1 - Product architecture, journeys, lifecycles, and code map

DONE (commit `eca5b10`). Merged `revamp/postmvp-pdoc1`.

## BATCH-PDOC2 - API, MCP, and interaction contract documentation

DONE (commit `d0fcc31`). Merged `revamp/postmvp-pdoc2`.

## BATCH-SEC1 - Security architecture and assessment baseline

DONE (commit `73f5d38`). Merged `revamp/postmvp-sec1`. No critical/high freeze blockers.

## BATCH-INST1 - Installer and component hardening QA

DONE. AUT1-B1 fixed (DB-authority evidence gate overlay); `rag_search_case`/`kb_*` confirmed
in live catalog; pgvector corpus verified (26,586 chunks). Installer idempotency structurally
checked; destructive throwaway-VM replay deferred to PMI4.

## BATCH-AUT1 - AI agent autonomy and MCP tool-surface assessment

DONE (merged via `Merge BATCH-AUT1`). Scorecard filled; `job_status` malformed-id/raw-error
leak fixed; AUT1-B1 and AUT1-B2 closed before AUT2.

## BATCH-AUT2 - Demo-case autonomous investigation benchmark

DONE with limitations. Final autonomy score: **22/24** (after remediation pass).
See `docs/product/agent-autonomy-assessment.md`.

## BATCH-FRZ1 - Final freeze rehearsal, limitations, and demo runbook

Dependencies: BATCH-PDOC1; BATCH-PDOC2; BATCH-SEC1; BATCH-INST1; BATCH-AUT2.

Current status (2026-06-10): IN_PROGRESS. See `docs/status.md` for the exhaustive list of
remaining open items. Summary:
- MCP-only freeze rehearsal proof is live-clean (services healthy, 13-tool catalog, DB-backed
  `case_info`/`evidence_info`, manifest_version=4, RAG available, Volatility/E01 via run_command).
- Portal login, HMAC re-auth, fresh portal-issued agent TTL (172800 s) live-proven.
- Settings UX source-fixed and live-deployed.
- **Still open:** offline Volatility symbol pre-warm, progress-stderr filtering,
  throwaway-VM install proof, non-admin service-user cutover, re-acquisition click proof.

Scope:

- `docs/product/demo-runbook.md`
- `docs/product/known-limitations-and-improvements.md`
- `docs/product/README.md`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`

Exact work:

- Complete remaining open items (see `docs/status.md`).
- Run the final demo rehearsal from installer/service readiness through portal operator flow,
  MCP-only agent investigation, report export, and custody proof.
- Freeze accepted limitations and improvement backlog.
- Produce the exact demo prompt and operator run sequence.
- Record final readiness evidence and commit hashes.

Acceptance:

- Demo runbook is executable without hidden side-channel steps.
- Known limitations are explicit, bounded, and non-fatal to the security and autonomy thesis.
- Product docs, migration tracker, and session notes agree on readiness.
- `python3 scripts/validate_docs.py`, relevant tests, and `git diff --check` pass.

## Post-Migration Install & Cleanup (PMI) Track

Goal: a single zero-argument `./install.sh` on a BARE SIFT VM brings up the native stack
(Supabase via CLI, migrations, OpenSearch 3.5 + Hayabusa, direct RAG pgvector seed,
gateway+worker+portal). OpenCTI and other external add-ons are installed separately through
`scripts/setup-addon.sh` + Portal -> Backends. Then the operator runs the Rocba case.

PMI operating model (LEAN):
- One worktree per batch off `main`; one commit per batch; scope-fenced.
- Targeted tests only per batch. The single full integration check is PMI4 (live VM).
- PMI0-PMI3 all landed. PMI4 is the final operator-run gate.

Locked decisions:
- OpenSearch = 3.5 (security-disabled + loopback `:9200`; Sigma detectors disabled, detection
  is Hayabusa-during-evtx-ingest).
- RAG = Supabase Postgres pgvector (`kb_*` tools from forensic-rag-mcp backend). `rag_search_case`
  shim removed (BATCH-OSX-RAG supersedes BATCH-PMI2).
- `forensic-knowledge` FK enrichment is CORE; `FK_DATA_DIR` is wired via PMI3.
- Add-ons (opencti, windows-triage) are external; windows-triage removed in NW2.

## BATCH-PMI0 - Installer hardening + Supabase CLI bring-up

DONE (commit `1742172`). Installer hardening; Supabase CLI v2.105 lean stack; `jwt_expiry=172800`;
`--network-id` loopback isolation; `apply_db_migrations`; opensearch env/restart fixes; linger;
hardened `poll_gateway`. `bash -n` clean.

## BATCH-PMI1 - OpenSearch 3.5 cutover + Sigma-disable/Security-Analytics cleanup

DONE (2026-06-10). `DISABLE_SECURITY_PLUGIN=true` + loopback `:9200`; root + package composes on
`3.5.0`/4g heap; `configure_opensearch_detections()` added to install.sh; package
`setup-opensearch.sh` reconciled to http/no-auth. Tests: 1025 passed, 73 skipped.

## BATCH-PMI2 - RAG single-home: remove standalone Chroma kb_search_* path

DONE (2026-06-10; SUPERSEDED by BATCH-OSX-RAG). Removed Chroma `kb_search_*` agent tools from
forensic-rag-mcp. OSX-RAG later restored the full tool surface backed by pgvector — this is
the current authoritative RAG.

## BATCH-PMI3 - FK enrichment actually fires (wire FK_DATA_DIR)

DONE (commit `ef6e229`). `FK_DATA_DIR=$SIFT_ENRICHMENT_DIR/forensic-knowledge` wired via
`write_fk_env()` + `EnvironmentFile=` in both systemd units. Tests: 34 FK loader.

## BATCH-PMI4 - VM proof: bare-SIFT -> live stack -> Rocba case run

Dependencies: NW1; NW2; NW3; NW4 (cleanup wave must land first). Operator-run. Last gate.

Scope:

- Deployment/smoke only.
- `docs/migration/Session-Notes.md` closeout after proof passes.

Exact work:

- On the bare SIFT VM: `./install.sh` (zero-argument native install; OpenCTI external,
  windows-triage removed)
- Confirm `status:ok` (not degraded), job-worker not crash-looping
- Confirm aggregate `/mcp` lists `opensearch_*` + `kb_*` tools after post-seed (no restart
  needed — OSX1 race fix)
- Confirm `app.rag_chunks` populated from the direct model-backed pgvector seed and Hayabusa
  detections queryable
- Portal: create case → issue agent token → register+seal Rocba disk+RAM evidence → run agent
  end-to-end
- Record command-level proof in `Session-Notes.md`

Acceptance:

- `status:ok` from fresh bare-SIFT install.
- Aggregate `/mcp tools/list` advertises `opensearch_*` + `kb_*` without restart.
- `app.rag_chunks` is nonzero and matches the direct bundled-knowledge seed count recorded in
  `Session-Notes.md`.
- Rocba case agent run completes or blockers documented with severity.
- `Session-Notes.md` records command-level proof.

## OpenSearch Excellence + RAG-Port + Purge (OSX) Track — all done

OSX1 through OSX-PURGE all landed. Architecture verified, tools restored, dead code purged.
Only OS6 (live VM smoke) remains and is tracked in the OS section above.

Key outcomes: seed-before-start race fixed (OSX1); `kb_*` tools restored on pgvector at parity
(OSX-RAG); `rag_search_case` shim removed; forensic-mcp dead package purged; advanced-tool-use
bar raised on all 16 OpenSearch tools (OSX2); PTC feasibility assessed (OSX3 → became NW6).

## BATCH-OSX1 - OpenSearch backend mounting fix (P1: seed-before-start race + dedupe double stdio spawn)

DONE (commit `e3d7414`). Race fixed two ways: install.sh reordered + `Gateway.reload_backend_registry()`
called by `_late_start_checker`. Double-spawn deduped. Tests: 25 targeted; gateway 450 passed.

## BATCH-OSX2 - OpenSearch FastMCP surface optimization (tool defs/schemas/examples/prompts; advanced-tool-use)

DONE (commit `38e1f65`). All 16 OpenSearch tools raised to advanced-tool-use bar in registry +
`sift-backend.json`. Tests: 108 opensearch-mcp.

## BATCH-OSX-RAG - Port forensic-rag-mcp tools to pgvector at full parity + remove rag_search_case shim

DONE (commit `8940a32`). `kb_search_knowledge`, `kb_list_knowledge_sources`, `kb_get_knowledge_stats`
backed by `PgVectorRagStore`; `rag_bridge.py` + `_register_rag_tool` + `PgVectorRagQueryService`
deleted; new migration `202606101100_rag_search_filters.sql`. Tests: 55 forensic-rag + gateway 450.

## BATCH-OSX3 - Programmatic tool-calling / code-execution-with-MCP feasibility spike (doc-first)

DONE (no code commit). Verdict: needs harness work. PTC is client-side in agent harness (not
on-VM). Feasibility write-up in Session-Notes. Became NW6.

## BATCH-OSX-PURGE - Purge stale/unused (forensic-mcp, dead Chroma index modules, broken win-triage scripts)

DONE (commit `978bdb8`). Deleted `packages/forensic-mcp/`; deleted 7 dead Chroma index modules in
forensic-rag-mcp. `compute_content_hash` divergence and win-triage scripts deferred to NW1/NW2
(MEDIUM risk; conservative). Tests: 55 + 450 green.

# Next Conductor Wave (NW) Track — post-OSX cleanup + fresh-install + PTC

Goal: land a small cleanup wave so the FRESH bare-SIFT install tests it, prove the whole stack on
the VM (PMI4/OS6), then enable + validate Programmatic Tool Calling (NW6).

## NW operating model

- One worktree per batch off **`main`** — `main` is the SOLE working trunk (OSX wave fast-forwarded
  in and pushed; `revamp/spg-v1` deleted). Create worktrees manually: `git worktree add ../sift-mcps-<b> main`.
- Targeted tests only per batch (touched package) + `bash -n` for shell + doc validators. Validate
  on the root `.venv`.
- Workers do NOT edit `docs/migration/**`; conductor logs after merge. One commit per batch.
- CONDUCTOR runs an INTEGRATED test sweep on the merged tree before landing (the OSX wave proved
  per-batch greens can still fail combined — OSX2 manifest vs gateway schema).

## NW decisions resolved (operator, 2026-06-10)

- **B-MVP-RAG-DERIVED → REJECTED.** No per-case RAG — case-sensitive derived text must not enter
  the vector store. Becomes **NW4** (harden to knowledge-only).
- **B-MVP-HASH-CONSOLIDATION → NW1** (fix it now; fresh install is the test bed).
- **B-MVP-WINTRIAGE-SCRIPTS → NW2** (remove ALL of windows-triage-mcp; future need via Backend
  Contract, which **NW3** documents as the hackathon modularity story).
- **OSX3 reframed → NW6.** PTC runs CLIENT-SIDE in the agent harness. The "evidence leaves the VM"
  objection is moot — Gateway sanitizes every result (live-proven: `case_dir: "[REDACTED:absolute_path]"`).
  NW6 = enable PTC on heavy read-only tools + validate live.

## NW wave order / parallelization

1. **NW1 ∥ NW2 ∥ NW3 ∥ NW4** (file-disjoint → run in parallel worktrees). Conductor integrated
   sweep, then land all into `main`.
2. **PMI4 / OS6** — full end-to-end gate; now exercises NW1/NW2/NW4. Operator-run.
3. **NW6 (PTC)** — enable + validate AFTER install (needs live `opensearch_*` tools).

## BATCH-NW1 - compute_content_hash consolidation (operator priority #1)

DONE (commit `a9602f0`; landed on `main` in NW Wave 1, 2026-06-11). Every call site now imports the
`investigation_store` authority (19-key WIDE set; strips `_`-prefixed keys); the narrow 15-key copies
in `case_io`/`reporting`/`case-dashboard routes` removed. New test asserts all call sites hash an item
identically. Existing-deployment re-hash need documented in code (no migration written). Tests: 23
hash + 84 adjacent pass.

Dependencies: none. Run BEFORE fresh install.

Scope:

- `packages/sift-core/src/sift_core/{case_io.py,reporting.py,investigation_store.py,case_manager.py}`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- Their targeted tests

Exact work:

- Consolidate every `compute_content_hash` call site to import the `investigation_store` authority
  (19-key wide set; strips `_`-prefixed keys). Remove re-declared exclude-key sets.
- Add a test asserting all call sites hash an item identically.
- Document (do not implement) that existing deployments would need a re-hash migration pass.

Acceptance:

- Single shared hash implementation; no diverging exclude-key sets remain.
- Test proves all call sites produce an identical content_hash for the same item.
- sift-core + case-dashboard targeted hash tests pass.

Worktree: `git worktree add ../sift-mcps-nw1 main`

Prompt:
```text
Scope: packages/sift-core/src/sift_core/{case_io.py,reporting.py,investigation_store.py,
case_manager.py}, packages/case-dashboard/src/case_dashboard/routes.py and their targeted tests.
Problem: compute_content_hash has TWO diverging shapes — authority =
investigation_store.compute_content_hash (19-key WIDE set incl provenance_detail/chain/grade/gaps
AND strips k.startswith("_")); narrow copies (case_io.HASH_EXCLUDE_KEYS,
reporting._HASH_EXCLUDE_KEYS, case-dashboard/routes._HASH_EXCLUDE_KEYS, 15-key, no _-strip)
produce a DIFFERENT content_hash for the same item. Do: consolidate every site to a SINGLE shared
implementation = the investigation_store authority (import it; do not re-declare exclude-key sets).
Add a test asserting all call sites hash an item identically. Behavior-touching: a fresh DB has no
pre-existing hashes, so no re-hash migration is needed for the fresh install — but DOCUMENT that
existing deployments would need a re-hash pass (note it; do not write that migration). Tests:
sift-core + case-dashboard targeted hash tests. Do not edit docs/migration. End with a LANDING LOG:
changed files, tests run, acceptance status.
```

## BATCH-NW2 - Remove windows-triage-mcp entirely + decouple opensearch enrich-triage

DONE (commit `77dfb58`; landed on `main` in NW Wave 1, 2026-06-11). Whole `windows-triage-mcp` package
deleted (32 files); refs removed from root `pyproject.toml`/`uv.lock`, `install.sh`,
`scripts/setup-addon.sh`, `sift-common/instructions.py`, and gateway tests. OpenSearch coupling severed:
`triage_remote.py` + `opensearch_enrich_triage` removed from server/registry/`sift-backend.json`;
`mcp_surface_golden.json` regenerated. Grep-proven no live importers. Conductor follow-up `c32a291`
dropped the stale `wintriage_check_artifact` hint from sift-core `_RELATED_TOOLS` (outside both NW1/NW2
fences). Tests: opensearch surface 40 + gateway phase6/f1 29 pass; `bash -n` clean; `uv lock --check` OK.

Dependencies: none. Run BEFORE fresh install.

Scope:

- `packages/windows-triage-mcp/` — delete whole package
- Root `pyproject.toml` — remove workspace member + `[core]`/optional entries
- `install.sh`, `scripts/setup-addon.sh` — remove win-triage references
- `packages/sift-common/src/sift_common/instructions.py` — remove win-triage references
- `packages/sift-gateway/tests/test_windows_triage_backend.py` — delete
- Win-triage rows in `test_f1_opensearch_backend_registry.py`
- `packages/opensearch-mcp/src/opensearch_mcp/triage_remote.py` — delete
- `opensearch_enrich_triage` tool from `server.py`, `registry.py`, `sift-backend.json`
- `test_triage_remote.py` — delete
- `tests/fixtures/mcp_surface_golden.json` — regenerate

Exact work:

- Delete windows-triage-mcp entirely; grep-prove no live importer remains.
- Decouple the opensearch coupling: remove `triage_remote.py` + `opensearch_enrich_triage`.
- Regenerate the mcp_surface golden snapshot.
- Keep a `_RETIRED_CORE_BACKENDS`-style guard if warranted.

Acceptance:

- `packages/windows-triage-mcp/` is gone; no live importers.
- `opensearch_enrich_triage` is absent from opensearch-mcp surface.
- opensearch-mcp surface snapshot (golden regen) passes.
- Full gateway manifest/`test_phase6` passes.
- `bash -n install.sh setup-addon.sh` clean.

Worktree: `git worktree add ../sift-mcps-nw2 main`

Prompt:
```text
Scope: delete packages/windows-triage-mcp/ (whole package); remove its refs in root pyproject.toml
(workspace member + [core]/optional list), install.sh, scripts/setup-addon.sh,
packages/sift-common/src/sift_common/instructions.py, and the gateway tests
(test_windows_triage_backend.py + any win-triage rows in test_f1_opensearch_backend_registry.py);
keep a _RETIRED_CORE_BACKENDS-style guard if warranted. Decouple the opensearch coupling: remove
packages/opensearch-mcp/src/opensearch_mcp/triage_remote.py + the opensearch_enrich_triage tool
from server.py/registry.py/sift-backend.json + test_triage_remote.py, and regenerate
tests/fixtures/mcp_surface_golden.json (say so). Grep-PROVE each removal (no live importer remains).
Tests: opensearch-mcp surface (golden regen) + full gateway manifest/test_phase6 (backend-list
change) + bash -n install.sh setup-addon.sh. Do not edit docs/migration. End with a LANDING LOG.
```

## BATCH-NW3 - Add-on Backend Contract documentation (hackathon modularity story)

DONE (commit `a200f66`; landed on `main` in NW Wave 1, 2026-06-11). New `docs/backend-contract.md`
(361 lines) documents the `sift-backend.json` manifest schema (incl OSX2 advanced-tool-use fields +
authority_contract), the seed/mount/requirement-gate/late-seed lifecycle (OSX1 reload), and a worked
end-to-end add-on example citing opensearch-mcp + forensic-rag-mcp. Grounded with source citations.
`validate_docs.py` OK (docs/migration untouched); `git diff --check` clean.

Dependencies: none. Docs-only; no code.

Scope:

- ONE new reference doc: `docs/backend-contract.md` (NOT under `docs/migration/`)

Exact work:

- Document the `sift-backend.json` manifest schema from `sift-backend.schema.json`: spec_version,
  name, version, tier, transport, namespace, `capabilities.requires`, per-tool advanced-tool-use
  fields (OSX2: when_to_use, avoid_when, output_shape, response_shaping, usage_examples,
  defer_loading, recommended_phase, category), authority_contract (non_authoritative,
  prohibited_operations, tool required_scopes, scope_enforcement).
- Document the lifecycle: `install.sh seed_addon_backends` + `scripts/setup-addon.sh` → DB row in
  `app.mcp_backends` → Gateway mounts, requirement-gates, enforces authority contract, picks up
  late-seeded rows without restart (OSX1).
- Worked example: adding a brand-new query-only add-on end to end (manifest → seed → mount →
  `tools/list`), citing `opensearch-mcp` and `forensic-rag-mcp` manifests as exemplars.

Acceptance:

- `docs/backend-contract.md` exists and is concise, demo-ready.
- `python3 scripts/validate_docs.py` still passes (docs/migration/ untouched).
- `git diff --check` clean.

Worktree: `git worktree add ../sift-mcps-nw3 main`

Prompt:
```text
Scope: ONE new reference doc — docs/backend-contract.md (product/reference, NOT under
docs/migration/; do not trip the migration two-file validator). Document the CURRENT contract
(OSX2 added tool fields; schema updated in aaa244b): (1) the sift-backend.json manifest schema
from packages/sift-gateway/src/sift_gateway/sift-backend.schema.json — spec_version/name/version/
tier/transport/namespace, capabilities.requires (requirement gating), per-tool metadata incl the
advanced-tool-use fields (when_to_use/avoid_when/output_shape/response_shaping/usage_examples/
defer_loading/recommended_phase/category), and the authority_contract (non_authoritative/
prohibited_operations, tool required_scopes/scope_enforcement). (2) The lifecycle: how
install.sh seed_addon_backends + scripts/setup-addon.sh register a backend row (env_refs only, no
raw secrets) into app.mcp_backends, and how the Gateway mounts it (create_backend_instances ->
mount_single_addon_proxy), requirement-gates it, enforces the authority contract, and picks up
late-seeded rows without a restart (OSX1 fix). (3) A WORKED EXAMPLE: adding a brand-new query-only
add-on end to end (manifest -> seed -> mount -> tools/list), citing the opensearch-mcp and
forensic-rag-mcp manifests as exemplars. Keep it concise and demo-ready. No code changes.
Do not edit docs/migration. End with a LANDING LOG.
```

## BATCH-NW4 - RAG knowledge-only hardening (drop per-case derived RAG; privacy)

DONE (commit `068e5c6`; landed on `main` in NW Wave 1, 2026-06-11). New append-only migration
`202606111200_rag_knowledge_only.sql` makes `app.rag_search` knowledge-only (6-arg overload; revokes
the old 9-arg from service_role) and adds BEFORE-INSERT triggers blocking `kind='derived'` at the DB
layer. `pgvector_store.search` + kb tools drop `case_id`/`include_derived`/`include_knowledge`; a Python
guard rejects derived. Tests: 56 pass (incl SQL static-analysis schema assertions; no live DB needed).
Note: the old 9-arg `app.rag_search` overload is revoked but not dropped (append-only) — a future
cleanup migration may DROP it once callers are confirmed migrated.

Dependencies: BATCH-OSX-RAG (landed; `202606101100_rag_search_filters.sql` exists).

Scope:

- NEW append-only `supabase/migrations/*.sql` (neutralize the `derived` branch of `app.rag_search`)
- `packages/forensic-rag-mcp/src/rag_mcp/{pgvector_store.py,server.py}` (remove `include_derived`/
  case-scoped params)
- Their targeted tests

Exact work:

- New migration: make `app.rag_search` knowledge-only; ensure no code path can insert/select
  `kind='derived'`. Builds on `202606101100_rag_search_filters.sql` (append-only; do NOT edit).
- Remove `include_derived`/case-scoped params from `pgvector_store.search` and the kb tools.
- Assert knowledge-only behavior in tests.

Acceptance:

- No code path can store or retrieve `kind='derived'` chunks.
- forensic-rag-mcp targeted tests (knowledge-only search; no derived) pass.
- Schema test for the new migration passes.

Worktree: `git worktree add ../sift-mcps-nw4 main`

Prompt:
```text
Scope: a NEW append-only supabase/migrations/*.sql (neutralize the derived branch of app.rag_search
— knowledge-only; do NOT edit existing migrations; builds on 202606101100_rag_search_filters.sql),
packages/forensic-rag-mcp/src/rag_mcp/{pgvector_store.py,server.py} (remove the include_derived/
case-scoped params from search + the kb tool; kb tools stay shared-knowledge only) + tests.
Operator decision (B-MVP-RAG-DERIVED REJECTED): no per-case RAG — case-sensitive derived text must
NEVER enter the vector store. Ensure no code path can insert/select kind='derived'; optionally keep
the columns but make the search path knowledge-only and assert it. Tests: forensic-rag-mcp targeted
(knowledge-only search; no derived) + a schema test for the new migration. Coordinate: builds on
OSX-RAG's 202606101100_rag_search_filters.sql. Do not edit docs/migration. End with a LANDING LOG.
```

## BATCH-NW5 - opensearch run_command duplicate check

RESOLVED (no action). opensearch-mcp exposes NO run_command/execute/shell tool; the only forensic
exec path is the sift-core run_command worker. No duplicate to remove.

## BATCH-NW6 - Programmatic Tool Calling: enable + native-harness validation (reframed OSX3)

Dependencies: PMI4/OS6 (needs live `opensearch_*` tools). Run AFTER fresh install.

Scope:

- Agent harness configuration (Messages-API side — NOT this repo's server side)
- Live validation with the native harness (the conductor)
- `docs/migration/Session-Notes.md` to record live validation note

Exact work:

- Decide how the SIFT agent-runtime converts Gateway/MCP tool defs into Messages-API tool defs
  with the `code_execution` tool + `allowed_callers:["code_execution_20250825"]` on the heavy
  read-only tools: `opensearch_search`, `opensearch_aggregate`, `opensearch_timeline`,
  `opensearch_count`, `opensearch_field_values`, `kb_*`.
- Use OSX2's per-tool `defer_loading`/advanced metadata as the eligibility signal.
- Confirm security: Gateway response-guard sanitizes every result (proven live).
- VALIDATE live: write code calling two OpenSearch tools + filter/join locally; measure context
  savings vs naive tool calls.
- Deliver: enablement steps + live validation note appended in `Session-Notes.md`.

Acceptance:

- Agent can write code that calls opt-in tools and receives only the code's final stdout.
- Context savings measured and recorded vs naive tool calls.
- No new server-side code required (posture confirmed: client-side only).
- If client-side PTC is rejected for posture reasons, the on-VM Python sandbox (former OSX4)
  becomes the fallback path.

Prompt:
```text
Goal: let the SIFT agent WRITE CODE that orchestrates OpenSearch tools and filters results
CLIENT-SIDE (in the agent harness's code sandbox), so a huge opensearch_search result never floods
context. Reference: anthropic.com/engineering/advanced-tool-use (PTC allowed_callers:
["code_execution_20250825"]) + code-execution-with-MCP. Do: (1) Decide how the SIFT agent-runtime
(the Messages-API/Agent-SDK harness) converts Gateway/MCP tool defs into Messages-API tool defs
with the code_execution tool + allowed_callers opt-in on the heavy read-only tools
(opensearch_search/aggregate/timeline/count/field_values, kb_*). Use OSX2's per-tool defer_loading/
advanced metadata as the eligibility signal. (2) Confirm the security posture is already satisfied:
Gateway response-guard sanitizes every result (proven live — [REDACTED:absolute_path]), so
client-side execution leaks nothing. (3) VALIDATE live with the native harness once the fresh
install exposes opensearch_*: write code that calls two OpenSearch tools and filters/joins locally,
measure context savings vs naive tool calls. Deliver: enablement steps + a live validation note
appended by the conductor in Session-Notes.md. The on-VM Python sandbox (former OSX4) is a FALLBACK
only if client-side PTC is rejected for posture reasons. End with a LANDING LOG.
```

# Hardening (HARD) Track — non-admin service user + shared symbol cache

Goal: stop running the gateway/worker/backends as the `sansforensics` operator with a blanket
`NOPASSWD: ALL`. Cut over to a dedicated non-admin system user, relocate the deploy tree to
`/opt/sift-mcps`, and warm the Volatility symbol cache from a shared writable location instead of
chmod-hacking the read-only `/opt/volatility3` tree. Resolves FRZ1 item 4 (Host-Only #4) and the
offline-symbol slice of FRZ1 item 1 (Host-Only #3).

## HARD operating model (LEAN)

- One worktree per group off `main`; scope-fenced; targeted tests only per group.
- Host code/docs landed in commit `30596a7`; live enforcement proof (run-as-user, warm cache,
  no-restart catalog) folds into PMI4/OS6 on the fresh VM.
- `/security-review` completed before land: the diff touches the service user, sudoers grants,
  secret/env-file relocation, and systemd unit ownership.

## BATCH-HARD1 - Non-admin service-user cutover + shared vol3 symbol cache

Dependencies: BATCH-PMI0 (installer/systemd hardening baseline). Live proof folds into PMI4/OS6.

Current status (2026-06-11): HOST CODE DONE — commit `30596a7` landed the host installer/systemd/cache
work; live proof is pending a fresh VM. See `docs/status.md` and `Session-Notes.md` (2026-06-11 host
build note) for the frozen contract constants.

Frozen contract (the agreed end-state):

- Dedicated non-admin service user `sift-service` (system user, `nologin`, home `/var/lib/sift`) runs
  the gateway + worker + all stdio backends. It holds ONLY two narrow sudoers grants:
  `sift-ingest-mount` (mount helpers) and `sift-agent-runtime` (the `agent_runtime` sandbox).
  `sansforensics` keeps its own operator login/sudo; `agent_runtime` stays the run_command sandbox user.
- Services become **system** services at `/etc/systemd/system/`, `User=sift-service`, managed via
  `sudo systemctl` (NOT `systemctl --user`).
- Deploy tree relocates to `/opt/sift-mcps`; operators can use the normal
  `git clone ... && cd sift-mcps && ./install.sh` flow because the installer stages the checkout
  into `/opt/sift-mcps` and re-execs from there before provisioning services.
- Shared writable vol3 symbol cache at `/var/cache/sift/volatility-symbols` (group `sift`), env override
  `SIFT_VOL_SYMBOLS`; first run warms it online — no pre-seeding.
- `install.sh` is ZERO-ARGUMENT (single native `--extra full`; OpenCTI external via
  `scripts/setup-addon.sh`; windows-triage removed in NW2). `--no-opencti` is accepted only as a
  no-op compatibility flag.

Scope (three parallel groups):

- **Group A — shared vol3 symbol cache:** point `parse_memory` + the worker at
  `/var/cache/sift/volatility-symbols` via `SIFT_VOL_SYMBOLS`; drop the `/opt/volatility3` chmod hack.
  Touched code + targeted sift-core/worker tests.
- **Group B — sift-service system-service cutover (installer/systemd, lead-owned):** create the
  `sift-service` system user; stage ordinary cloned checkouts into `/opt/sift-mcps`; narrow sudoers to
  the two grants; relocate secret env files to `sift-service`-readable `0600`; convert the units to
  system services (`User=sift-service`, `/etc/systemd/system/`, `sudo systemctl`).
- **Group C — this doc work:** `docs/status.md`, `docs/migration/task-batches.md`,
  `docs/migration/Session-Notes.md` (install command de-staled; VM quick reference + batch tracker
  + session log updated).

Acceptance:

- Fresh-install proof shows `status:ok`.
- `ps -o user= -C` (or `systemctl show`) confirms gateway/worker run as `sift-service`, NOT
  `sansforensics`.
- A vol3 ingest warms `/var/cache/sift/volatility-symbols` on first run (no pre-seeding).
- OS6 `tools/list` shows `opensearch_*` without a restart.
- `/security-review` clean (secret/env relocation + sudoers + service user); `validate_docs.py` +
  `validate_migration_docs.py` OK; `git diff --check` clean.
