# Session Notes

Status: sprint log and decision register.
Last updated: 2026-06-08.

Format rules:

- Latest change entry stays at the top of `Current Change Log`.
- Use `Status: DONE`, `Status: IN_PROGRESS`, or `Status: BLOCKED`.
- Keep forks, blockers, and needs-input in the single table below.
- Use IDs beginning with `F-MVP-` for forks and `B-MVP-` for backlog.
- Do not create more migration runbooks.

## Current Change Log

### 2026-06-08 - BATCH-V1 live cutover completed

Status: DONE

Ran the live BATCH-V1 cutover/smoke on the SIFT VM from integrated root
`revamp/spg-v1`. The VM was synced to `~/sift-mcps-test`, Gateway and the durable
job worker were restarted with `~/.sift/control-plane.env`, and the demo journey
completed through portal + Gateway MCP without exposing service secrets or
absolute evidence paths to the agent surface.

Live VM readiness:

- Root disk was expanded after the run hit space pressure: `/` now has a 200G
  logical volume with roughly 94G free. Docker uses the VM reverse SOCKS proxy
  for image pulls.
- Gateway health on `https://127.0.0.1:4508/api/v1/health`: `status=ok`,
  Supabase `status=ok`, evidence root `status=ok`.
- OpenSearch was started through Docker after proxy configuration; cluster
  health is `yellow` on the single-node VM and indexing/search works.
- Supabase migration fixup applied live through `psycopg` because the VM image
  lacks `psql`: new additive migration
  `202606081602_investigation_iocs_content_hash.sql` adds
  `app.investigation_iocs.content_hash`. This aligns IOC authority rows with the
  K2 store's hash-guarded approve/report contract. The self-hosted DB has no
  `supabase_migrations.schema_migrations` table to stamp.

Live journey evidence:

- Active case: `case-v1gate-06081857`, UUID
  `57a06521-c9b8-4654-92ac-42b4f2bb0915`, active case authority from Postgres.
- Evidence seal: `evidence/v1-gate.log` was registered/sealed with DB proof
  export `d93bc9db-f283-4b23-ad81-0c2c3a3b7cb1`; `evidence/v1-ingest.jsonl`
  registered/sealed as evidence `f8c0c7bf-1838-4ca6-b2c1-38c436ff25b0`,
  `manifest_version=2`, proof export `d3736f53-4242-43ec-9416-76d326388c19`,
  proof hash
  `sha256:e7d20083ce0b15ae975f37ccb51693f8f721098841432935dd28f5cce1e473bc`.
- Agent issuance: live agent token was issued with default case binding to
  `57a06521-c9b8-4654-92ac-42b4f2bb0915`. Token material stayed VM-local.
- Evidence gate: pre-seal agent execution failed closed with the unsealed
  evidence gate; post-seal `run_command_job`
  `884c3641-7bfa-4801-a3de-7eb7b69f0d2e` succeeded and redacted absolute-path
  output.
- OpenSearch ingest: `ingest_job`
  `e6572af3-e894-4b06-ab8a-37db87c7246d` succeeded for
  `evidence/v1-ingest.jsonl`; provenance
  `3f90b65a-b829-4ef8-ac2b-419b8f3c65e6`, indexed `1`, bulk failures `0`,
  index `case-57a06521-c9b8-4654-92ac-42b4f2bb0915-json-v1-ingest-host01`.
  DB provenance, `app.opensearch_indices`, and
  `app.host_identity_decisions` all recorded the same job/provenance/index.
- RAG: `rag_search_case` returned `status=ok`, `count=3`, `kinds=["knowledge"]`,
  `has_abs_path=false` from Supabase pgvector. Top titles were
  `Intelligence Requirements Definition`, `SIFT Workstation`, and
  `oledump.py Overview`; shared knowledge rows retain `case_id NULL`.
- Report approval/export: agent staged finding `F-hermes-v1-gate-001`; portal
  HMAC re-auth approved it (`authority=db`, `approved=1`). Report
  `41e0a5ff-4e43-4a38-8e9c-5ce128160a16` was generated/saved/downloaded with
  the approved finding, IOC/MITRE sections, and DB sealed custody appendix.
  Export size was 5570 bytes; a leak scan found no `/cases`, `/home`,
  `127.0.0.1`, Supabase/service-role/password, Postgres, or OpenSearch strings.
- Custody proof export: DB proof export
  `f06b6bb7-ae55-4d44-85be-d34d8c198668`, `manifest_version=2`, proof hash
  `sha256:e7d20083ce0b15ae975f37ccb51693f8f721098841432935dd28f5cce1e473bc`.

Live defects found and fixed in this cutover:

- DB audit actor FK: Supabase JWT agent principals no longer populate
  `actor_token_id` with a non-token principal UUID.
- Gateway local MCP handlers now pass the gateway instance to job/RAG handlers.
- Agent `job_status` accepts the token's `case_id`/`default_case_id` for the job
  case.
- OpenSearch ingest now handles sealed single JSON/JSONL/NDJSON evidence files
  without leaking paths or requiring directory discovery.
- Report generation now uses DB custody for the visible evidence-chain block
  when the portal supplies custody, avoiding stale legacy-manifest warnings.
- Added `202606081602_investigation_iocs_content_hash.sql` so IOC rows can use
  the same content-hash authority contract as findings/timeline.

Validation:

- Local focused tests after fixes: core report/K2 store `25 passed`; gateway
  audit/local-binding/job authorization `30 passed`; OpenSearch ingest
  `10 passed`.
- Live report export leak scan: clean for local paths and service-secret terms.
- `bash -n install.sh`: OK.
- `uv lock --check`: OK.
- `python3 scripts/validate_docs.py`: OK.
- `python3 scripts/validate_migration_docs.py`: OK.
- `git diff --check`: clean.

### 2026-06-08 - V1 enablers integrated before live cutover

Status: DONE

Integrated the remaining V1 enabler tracks into root `revamp/spg-v1` from clean
worktrees based on `49fb044`. BATCH-V1 is still not complete; the next session
should run the live VM cutover/smoke journey against the integrated root.

Integration:

- Auth/installer/agent: worker commit `58c669b`, merge `84404ba`. Closes
  B-MVP-8 and B-MVP-9 by writing `~/.sift/control-plane.env`, keeping DSN/pepper
  out of gateway YAML, creating/repairing Supabase Auth users with matching
  `app.operator_profiles`, and issuing MVP agents with global tool scopes plus
  `default_case_id` bound to the active DB case.
- RAG: worker commit `db47c71`, merge `2c34520`. Closes B-MVP-11 and B-MVP-15 by
  exempting Gateway-local `rag_search_case` from proxy case-arg rewriting/denial
  and adding `rag-mcp-seed-pgvector` plus pgvector collection/document/chunk
  upserts. Knowledge RAG is treated as a shared forensic case-study/reference
  corpus (`kind='knowledge'`, `case_id NULL`); the active case remains only the
  Gateway policy/audit boundary and the filter for future `kind='derived'` rows.
- Runtime/evidence journey: worker commit `0acd60f`, merge `09a0023`. Closes
  B-MVP-12, B-MVP-13, and B-MVP-14 by applying per-case ACLs for
  `agent_runtime`, making the local password/HMAC re-auth bridge explicit as MVP
  behavior (`reauth_method=local_hmac_mvp_bridge`), and making register+seal the
  MVP evidence journey (`registration_mode=atomic_register_and_seal`). The DB
  seal path already calls `app.evidence_register` before `app.evidence_seal`.

Branch validation before integration:

- Auth/installer/agent: `bash -n install.sh`; `git diff --check`; dashboard
  token/auth/bootstrap tests `58 passed`; gateway Supabase/JWT auth tests
  `57 passed`.
- RAG: Gateway RAG/proxy/local-tool tests `14 passed`; forensic pgvector store
  and seed tests `15 passed`; `uv lock --check`; seed CLI dry run; Ruff targeted
  check; `git diff --check`.
- Runtime/evidence: portal case/evidence DB/intake tests `87 passed`; Ruff
  targeted check; `git diff --check`.

Post-integration validation on root `revamp/spg-v1`:

- `python3 scripts/validate_docs.py`: OK.
- `bash -n install.sh`: OK.
- `uv lock --check`: OK.
- `uv run --extra full rag-mcp-seed-pgvector --dry-run --max-files 1
  --max-records-per-file 2`: OK (`store=supabase_pgvector`, 1 collection,
  1 document, 2 chunks).
- Pytest: dashboard auth/bootstrap/token suites `58 passed`; gateway
  Supabase/JWT + active-case/RAG/local binding suites `71 passed`; forensic
  pgvector store/seed suites `15 passed`; portal case/evidence DB/intake suites
  `87 passed`.
- `git diff --check`: clean.

Next:

- Run BATCH-V1 live on the SIFT VM from root `revamp/spg-v1`: apply migrations,
  restart gateway/job worker with the new control-plane env, seed pgvector
  knowledge, create/activate a case, register+seal evidence, issue an agent,
  prove denied and allowed `run_command`, drive `ingest_job`/OpenSearch,
  `rag_search_case`, report export, and custody proof export.

### 2026-06-08 - K2-K5 integrated, K6 landed, authority cutover closed

Status: DONE

Integrated the four parallel authority-cutover branches into `revamp/spg-v1`,
ran BATCH-K6 as the tamper-regression gate, and closed the DB-active file-authority
cutover (B-MVP-16). BATCH-V1 is now unblocked.

Integration:

- Cherry-picked the four single-commit worker branches onto `revamp/spg-v1` for
  linear history: K4 `89abafe`, K5 `bcba5db`, K2 `5b1cf9c`, K3 `9048da6`
  (K3 last to absorb the K2/K3 `portal_services.py` + `routes.py` overlap; git
  auto-merged cleanly because K2 = `InvestigationService` and K3 =
  `EvidenceAuthorityService` touch disjoint regions).
- `59e0267`: deduped the colliding `202606081600_*` migration version. K2
  (`investigation_authority`) and K4 (`host_identity`) both landed at
  `202606081600` on parallel branches; bumped host_identity to `202606081601`
  (no SQL change; neither depends on the other) so each has a unique Supabase
  migration version. Updated its structural test path.
- Post-integration full suites green: sift-core 424, sift-gateway 388,
  case-dashboard 354, opensearch-mcp 995 (+71 skip), tests/db 58.

BATCH-K6 (`b76eba9`) - portal/report tamper regression + DB-active file-authority
removal:

- `reporting.py`: in DB-active mode report verification reconciles against the
  per-row DB `content_hash` (K2) via new `reconcile_verification_db` and never
  reads the local verification JSONL ledger; the file-ledger path is retained
  only for legacy non-DB mode. Adds a `verification_authority` label.
- `portal_services.py`: `InvestigationService.audit_events` reads the audit trail
  from `app.audit_events` scoped to the case.
- `routes.py`: `GET /api/audit/{finding_id}` sources the finding's audit_ids from
  the DB investigation record and entries from `app.audit_events` in DB-active
  mode; `findings.json` / `audit/*.jsonl` are consulted only in legacy mode.
- `audit_ops.py`: the file-mirror summary is explicitly labelled
  `legacy-file-mirror` (non-authoritative) in DB-active mode and can derive from
  an injected DB reader.
- `backup_ops.py`: backup manifest marks `authority: db-postgres` +
  `snapshot_only` in DB-active mode so a backup cannot masquerade as authority.
- B-MVP-17 decided (see register): pre-context denials stay on the local audit
  mirror for the MVP; hardened DB projector deferred to V1. Locked by test.

Validation:

- Full suites green after K6: sift-core 435 (+11 K6), sift-gateway 392 (+4 K6),
  case-dashboard 356 (+2 K6), opensearch-mcp 995, tests/db 58. `git diff --check`
  clean on each commit.
- `python3 scripts/validate_docs.py`: OK.
- Resolved this run: B-MVP-10 (DONE, K2), B-MVP-16 (DONE, K1-K6), B-MVP-17
  (DONE/decided, K6).
- Not run: live-VM apply of the integrated migrations and the live end-to-end
  journey (BATCH-V1).

Next:

- **Resume BATCH-V1** end-to-end validation and cutover on the live SIFT VM. The
  authority cutover (K1-K6) no longer blocks approval, report, ingest status, RAG
  verification, or run-command proof. V1 carry-ins to exercise live: the
  K2 `PostgresInvestigationStore.apply_review` `WHERE version=%s` atomic guard
  under READ COMMITTED concurrency; live apply ordering of the two
  `202606081600/...1601` migrations; the K4 Gateway-side host-fix receipt for the
  pure agent→proxy path; and the still-open V1 enablers B-MVP-8 (installer
  operator-profile insert + control-plane env), B-MVP-9 (case-bound agent
  issuance), B-MVP-11 (`rag_search_case` proxy denial), B-MVP-12 (agent_runtime
  case-dir ACL), and B-MVP-15 (pgvector population path).

### 2026-06-08 - BATCH-K2/K3/K4/K5 landed on worker branches

Status: DONE

Ran the four parallel authority-cutover batches in dedicated worktrees off
`revamp/spg-v1`. Each is one commit on its own branch (not yet integrated into
`revamp/spg-v1`); all reuse the K1 `AuthorityContext`/DB-audit contracts and none
edited `docs/migration`.

Landed (per-branch):

- BATCH-K2 `5a9fe4b` on `revamp/mvp-k2-investigation-db-authority` - typed
  `InvestigationAuthorityStore` port + `PostgresInvestigationStore`; `case_manager`
  findings/timeline/IOC/TODO write DB-first and fail closed; portal JSON->DB sync
  gated off by default; portal approve/reject/edit + report reads route to DB
  authority with optimistic `version` locking and `reauth_audit_event_id`. New
  migration `202606081600_investigation_authority.sql`. Tests: sift-core 398,
  gateway 377, dashboard 354, db 52.
- BATCH-K3 `662c6aa` on `revamp/mvp-k3-evidence-proof-cutover` - evidence gate
  reads only `app.evidence_gate_status`; added seal-tamper detection
  (`_detect_seal_tamper` -> `evidence_mark_violation`), DB-derived proof export
  (re-hash mounted bytes -> `evidence_record_proof_export`), and `anchor_db_proof()`
  Solana-as-external-proof-only. Tests: sift-core 386, gateway 382, dashboard 350,
  db 49.
- BATCH-K4 `717a548` on `revamp/mvp-k4-opensearch-host-authority` - new migration
  `202606081600_host_identity.sql` (`app.host_identity_decisions` ledger +
  `record_host_identity_decision` + `opensearch_ingest_status` RPC); DB-active
  ingest status from durable jobs/provenance; `host-dictionary.yaml` is parser-compat
  only and `dict_path` no longer leaked to agents in DB-active mode; canonical
  `opensearch_fix_host_mapping` + deprecated `opensearch_host_fix` alias preserved;
  MCP surface golden regenerated. No Gateway registry edits. Tests: opensearch-mcp
  995, sift-core 384, gateway 371, db 55.
- BATCH-K5 `63b5f48` on `revamp/mvp-k5-run-command-authority-isolation` - closed the
  root env-leak defect (sandbox subprocess inherited the full worker env incl.
  `~/.sift/supabase.env` secrets). New `runtime_acl.py` (`build_sandbox_env()`
  allowlist + post-allowlist secret deny; authority-path write/redirect refusal);
  scrubbed env on every `Popen`; path-free DB receipts; fixed a latent non-UUID
  `provenance_id` bug in the `complete_job` path. Tests: sift-core 408, gateway 371,
  db 49, +24 new K5 tests.

Two known shared-file overlaps to reconcile at integration (each batch on its own
branch, so only a merge concern): K2 and K3 both touch
`sift_gateway/portal_services.py` and `case-dashboard routes.py` (changes are
service-scoped and additive - K2 only added a `legacy_sync=False` kwarg to the base
service and edited `InvestigationService`; K3 only added `EvidenceAuthorityService`
methods + evidence routes); K4 and K5 are disjoint and neither touched
`job_worker.py`.

Both K2 and K4 introduce a `202606081600_*` migration; the two filenames differ
(`_investigation_authority` vs `_host_identity`) so they coexist, but confirm
timestamp ordering at integration.

Validation:

- All four worker suites green as listed above; `git diff --check` clean on each.
- Per-batch `python3 scripts/validate_docs.py` reported OK where run.
- Not run: cross-branch integration build and live-VM apply of the two new
  `202606081600_*` migrations (deferred to integration + BATCH-V1, consistent with
  prior K-series).

Next:

- Integrate K2-K5 into `revamp/spg-v1` (resolve the K2/K3 `portal_services.py` +
  `routes.py` overlap additively; confirm `202606081600_*` migration ordering), then
  run BATCH-K6 as the tamper-regression gate. K6 must cover: end-to-end portal/report
  tamper regression for findings/timeline/todos/iocs + approvals (K2), the seal-tamper
  / proof-export verify path (K3), DB-active ingest/host authority vs local-file
  tampering (K4), the run_command authority-write deny path (K5), and the B-MVP-17
  pre-context denial DB-audit decision. BATCH-V1 stays blocked until K1-K6 close the
  cutover.

### 2026-06-08 - BATCH-K1 landed with security-review correction

Status: DONE

Changed:

- Landed BATCH-K1 as `0e9577a` on `revamp/spg-v1`.
- Added the `AuthorityContext` contract in `sift_core.active_case_context`
  with principal, principal type, tool scopes, evidence-gate snapshot fields,
  request ID, DB-active flag, and audit event IDs.
- Hardened `CaseManager._require_active_case()` so DB-active mode uses the
  request/worker authority context only and fails closed instead of reading
  `SIFT_CASE_DIR` or `~/.sift/active_case`.
- Set the durable job worker CLI to `SIFT_DB_ACTIVE=1` after requiring a
  control-plane DSN.
- Added `DbAuditWriter` for DB-first `app.audit_events` writes and wired the
  Gateway MCP audit envelope to reserve `requested` rows and write
  result/failure receipts. Mutating calls fail closed when the required
  pre-dispatch DB audit write cannot persist.
- Conductor security review found one pre-merge audit gap: the new DB audit
  envelope initially ran after proxy/evidence-gate denials. Fixed it by moving
  `AuditEnvelopeMiddleware` after case-context setup but before proxy active
  case and evidence gate middleware, and by marking evidence-gate block results
  as MCP errors so DB result receipts record `failure`.
- Root pre-existing candidate patches were stashed before integration as
  `stash@{0}: pre-k1-root-candidate-patches-20260608` so K1 could land cleanly
  without mixing unreviewed work.

Validation:

- Passed: `uv run pytest` in `packages/sift-core` - 384 tests.
- Passed: `uv run pytest` in `packages/sift-gateway` - 371 tests.
- Passed: `uv run pytest tests/db` - 49 tests.
- Passed: `git diff --check` before K1 commit.
- Security report generated and validated:
  `/tmp/codex-security-scans/sift-mcps/ef52331_20260608T141952Z/report.md`
  and `report.html`. Result: no remaining reportable findings; K1-001 fixed
  before merge.

Next:

- Launch BATCH-K2, BATCH-K3, BATCH-K4, and BATCH-K5 in parallel worktrees from
  `revamp/spg-v1`.
- BATCH-K6 follows after K2-K5 and must include tamper regressions plus the
  pre-context denial DB-audit decision tracked as B-MVP-17.

### 2026-06-08 - Authority cutover model frozen

Status: DONE

Changed:

- Added the authority cutover impact model to `Migration-Spec.md`. DB-active
  mode now has an explicit invariant: critical mutable DFIR state cannot be
  decided from case-local files, env pointers, or legacy JSON/JSONL artifacts.
- Classified remaining files into authority, append-only ledger, evidence
  bytes, derived/rebuildable state, immutable proof/export artifacts, and
  legacy compatibility. Postgres is authority for mutable state; Supabase
  Storage/case files are export/workspace/debug/parser-compatibility only.
- Mapped the discovered split-brain touchpoints to implementation files:
  active case resolution, audit writer, evidence manifest/ledger, findings,
  timeline, TODOs, IOCs, approvals, reports, OpenSearch ingest status/manifests,
  host identity, and `run_command`.
- Locked the hostname carve-out: parser/indexer hostname detection is required
  derived metadata for OpenSearch index naming and `host.name`/`host.id`.
  `opensearch_fix_host_mapping` is canonical; `opensearch_host_fix` remains a
  deprecated alias. Host corrections may mutate derived OpenSearch/host
  metadata only, not case/evidence/report authority.
- Locked the Solana carve-out: optional SPL Memo anchoring remains proof export
  only. DB custody chain heads and custody events are authority; anchor proof is
  recorded/exported through `app.evidence_proof_exports` when configured.
- Split the blocking authority cutover into K-series batches:
  K1 authority context + DB audit, K2 core investigation DB authority, K3
  evidence/proof/Solana export, K4 OpenSearch/host identity derived-state
  cutover, K5 `run_command` authority isolation, and K6 portal/report tamper
  regression. BATCH-V1 now depends on K1-K6.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch BATCH-K1 first. After K1 lands, K2-K5 can run in parallel worktrees;
  K6 follows as the tamper/regression gate before BATCH-V1 resumes.

### 2026-06-08 - BATCH-V1 live VM validation partial

Status: IN_PROGRESS

First real end-to-end run on the live SIFT VM. Prior waves were unit/structural;
this run deployed the integrated MVP to `~/sift-mcps-test`, applied all
migrations to live Supabase, re-pointed Gateway to the control plane, and drove
the Phase 3 journey through portal + MCP.

Validated live:

- Migrations: all `supabase/migrations/*.sql` apply clean in timestamp order to
  fresh Supabase. Schema, RPCs, and pgvector are present.
- Health: Gateway reports `status: ok`; Supabase and control-plane DB are
  connected; evidence root is OK after F-MVP-5.
- Operator bootstrap and forced reset: invited operator can log in, receives
  `must_reset`, completes forced reset, and transitions `invited -> active`
  after F-MVP-6.
- Case create/activate: persisted to `app.cases`; active case is DB authority
  (`deployment_active_case`, `authority: postgres`), not a file pointer. Frozen
  case naming confirmed with `case-v1smoke-06081250`.
- Evidence detect/register/seal: DB evidence detect path works; seal with HMAC
  re-auth writes custody events; `app.evidence_gate_status` returns `sealed`
  after F-MVP-7.
- Custody hash chain: `EVIDENCE_DETECTED -> EVIDENCE_REGISTERED ->
  MANIFEST_SEALED`, append-only and prev/event-hash linked.
- Agent credential + MCP: one-time agent credential issued; MCP connects through
  `/mcp`; scoped catalog exposes the expected tools including `ingest_job`,
  `run_command_job`, `job_status`, and `rag_search_case`.
- Path redaction and evidence gate: `case_info` redacts `case_dir`; pre-seal
  agent calls fail closed with `evidence_chain_unsealed`; post-seal calls allow.
- Agent writes and command controls: `manage_todo`, `record_timeline_event`, and
  provenance-enforced `record_finding` work at the agent surface; `run_command`
  deny floor blocks `bash` and redacts error paths.
- RAG status: new pgvector schema and `rag_search_case` tool surface exist, but
  live Supabase row counts are `app.rag_collections=0`, `app.rag_documents=0`,
  and `app.rag_chunks=0`. Any successful VM knowledge/RAG-looking answers came
  from legacy `kb_*` forensic-rag/Chroma or core forensic-knowledge guidance,
  not from the new Supabase pgvector path.

Defects fixed on this branch:

- F-MVP-5: `health.py` Supabase health probe omitted the `apikey` header, so
  Kong returned 401. The probe now sends the configured anon key as `apikey`.
- F-MVP-6: `supabase_auth.py` rejected `invited` operators before a session
  cookie existed, making `/api/auth/forced-reset` unreachable. Login now allows
  `active` and `invited`; resolver/protected actions remain active-only.
- F-MVP-7: `202606081000_evidence_custody.sql` used pgcrypto `digest()`, which
  was unresolved under Supabase's extension schema and the function search path.
  Custody hashing now uses built-in `sha256(v_payload::bytea)`.

Validation:

- Passed live/unit after fixes: sift-gateway 361, sift-core 376,
  case-dashboard 350, forensic-rag 18, tests/db 48, opensearch job-ingest 8.
- Passed: `python3 scripts/validate_docs.py`,
  `python3 scripts/validate_migration_docs.py`.

Remaining before BATCH-V1 can be checked:

- Resolve B-MVP-8/9/10 first. B-MVP-10, the agent file-to-DB investigation
  bridge, is the blocker for portal approval and approved-only report.
- Then drive `ingest_job`/`job_status` with the worker, populate/verify
  pgvector RAG, drive `rag_search_case`, allowed `run_command`, approved-only
  report export, and custody proof export.

Live VM replay notes for the next session:

- VM host/user: `192.168.122.81` / `sansforensics`. Use local `SSHPASS` or SSH
  agent configuration; do not commit the test VM password.
- Gateway/portal: `https://192.168.122.81:4508`,
  `https://192.168.122.81:4508/portal/`.
- VM runtime: Ubuntu 24.04, `/usr/bin/python3.12`, uv at
  `/home/sansforensics/.local/bin/uv`.
- Supabase project: `/home/sansforensics/supabase-project`; sparse source clone:
  `/home/sansforensics/supabase-src-v1.26.05`; pinned Supabase tag `v1.26.05`,
  commit `23b55d63485e51919d1b4c05b03d33a9edc1f06d`. Supabase secrets stay in
  VM-local `.env` / `~/.sift/control-plane.env` files only.
- Deployed V1 copy: `~/sift-mcps-test`; all migrations applied; Gateway
  re-pointed to the control plane; old Gateway unit/config backed up on the VM
  as `*.bak.<ts>`.
- Current live state: operator `examiner@operators.sift.local` active owner;
  active sealed case `case-v1smoke-06081250` with UUID
  `31831057-0de9-4781-b6fd-c38043f0aa23`; global `mcp:*` test agent
  `hermes-v1-global` with token stored VM-local in `~/.sift/agent-token.txt`.

Replay command patterns:

- Sync host to VM:
  `rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/`
- VM command wrapper:
  `sshpass -e ssh -o StrictHostKeyChecking=no sansforensics@192.168.122.81 '<command>'`
- VM dependency sync:
  `cd ~/sift-mcps-test && UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12`
- Start/check Supabase:
  `cd ~/supabase-project && docker compose up -d --wait && docker compose ps`
- Apply migrations from a fresh DB:
  `for m in $(ls ~/sift-mcps-test/supabase/migrations/*.sql | sort); do cat "$m" | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1; done`
- Restart/check Gateway:
  `systemctl --user restart sift-gateway && curl -s -k https://localhost:4508/api/v1/health | python3 -m json.tool`

### 2026-06-08 - BATCH-L1 landed (live service binding before V1)

Status: DONE

Changed:

- Resolved B-MVP-5: Gateway startup now wires portal service slots to live
  Postgres-backed adapters for evidence/custody, investigation records, report
  metadata, and D2 job status. Added migration
  `202606081500_report_metadata.sql` for findings/timeline/IOCs/TODOs/report
  metadata used by the portal/report seams.
- Resolved B-MVP-6: added `sift-job-worker` bootstrap and systemd unit, registered
  `ingest` and `run_command` handlers, and filtered worker claims to supported
  job types. Added Gateway-owned durable MCP tools: `ingest_job`,
  `run_command_job`, and `job_status`. Public job specs stay path-free;
  worker-only `spec_internal` carries resolved local paths.
- Resolved B-MVP-7: added Gateway `rag_search_case` over G1 pgvector RAG with
  case scope, embedding validation, and normal Gateway policy/response guard.
- Switched MCP evidence gating for DB active cases to prefer C1
  `app.evidence_gate_status`; legacy file gate remains only as bridge fallback.
- Kept Gateway source add-on-name-neutral by exposing a generic `ingest_job`
  tool rather than hardcoding a derived-plane backend name.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 361, sift-core 376, case-dashboard 350,
  forensic-rag/tests + `tests/db` 66, opensearch job-ingest 8.
- Not run here: live `supabase db` migration apply, live OpenSearch indexing,
  or SIFT VM end-to-end journey.

Next:

- Run BATCH-V1 on the SIFT VM: apply migrations in timestamp order, start
  Gateway + `sift-job-worker`, and execute the Phase 3 smoke journey from
  `Migration-Spec.md`.

### 2026-06-08 - BATCH-J1 landed and integrated (approved-only reports)

Status: DONE

Changed (merged into `revamp/spg-v1`, `--no-ff`):

- BATCH-J1 (`e12a990`): Approved-only report generation/export to the locked
  F-MVP-4 shape. `reporting.py` hard-filters to `status == "APPROVED"` (draft/
  rejected finding IDs and text proven absent from output and API response) and
  adds `build_custody_appendix()` (seal status + manifest/chain-head/ledger-tip
  hashes + provenance refs). Portal `generate_report_route` now re-auths
  (`/api/reports/challenge`), folds in custody, persists metadata via E1's
  `report_service.record_report` seam, and renders the appendix into the
  downloadable markdown. ReportsTab gains a re-auth modal. E1's approved-only 409
  eligibility gate preserved and re-verified. API JSON sanitized (no absolute
  paths). J1 deliberately did not add a report-metadata migration — deferred to
  the binding batch (B-MVP-5).
- Conductor (`<this entry's commit>` precursor): rebuilt the portal v2 bundle
  (`vite build`) so the committed `static/v2/` includes both E1 and J1 frontend
  changes (the worker worktrees lacked node_modules); closes J1 frontend-bundle
  follow-up.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed (integrated): sift-core 374, case-dashboard 350, sift-gateway 355.
  `vite build` succeeded. No regressions.
- Not run here: live `supabase`/VM report journey (depends on the B-MVP-5 binding).

Status: all implementation batches (A1, B1, C1, D1, D2, E1, F1, G1, H1, I1, J1)
are landed and integrated on `revamp/spg-v1`. Remaining before BATCH-V1 is the
live-service binding (B-MVP-5/6/7), which is the only thing standing between the
built code paths and a working SIFT VM end-to-end journey.

Next:

- Resolve the binding work (B-MVP-5 portal service adapters, B-MVP-6 worker
  handler bootstrap + enqueue call sites, B-MVP-7 pgvector RAG query tool) as one
  focused batch — it spans portal + worker + gateway tool surface and should not
  be parallelized.
- Then BATCH-V1 end-to-end validation and cutover.

### 2026-06-08 - Dependent wave landed and integrated (E1/F1/G1/I1)

Status: DONE

Changed (merged into `revamp/spg-v1`, one `--no-ff` merge per batch; branch
filesets verified fully disjoint, no conflicts):

- BATCH-E1 (`0390a9c`): Portal authority migration. `routes.py` gains four
  Gateway-injected service slots (`evidence_service`, `investigation_service`,
  `report_service`, `job_service`) following the established DI seam
  (`_ACTIVE_CASES`/`_SUPABASE_AUTH`); each route prefers DB authority when wired
  and falls back to the file path when `None`. Evidence seal/ignore/retire refuse
  403 without a `reauth_audit_event_id` (C1 contract); reports gate 409 on no
  approved findings; new `GET /api/portal/state` and `GET /api/jobs/{job_id}`
  (D2 `JobService`). Report generation internals left to J1. Frontend evidence/
  reports tabs + polling + rebuilt v2 bundle.
- BATCH-F1 (`4a27aba`): OpenSearch ingest job adapter. `job_ingest.py` concrete
  `ingest` handler for the D1 `JobWorker` (resolves path from worker-only
  `spec_internal`, never echoed); central provenance stamping at the `flush_bulk`
  choke point (no parser-module edits); migration
  `202606081300_opensearch_provenance.sql` (index + ingest-provenance tables,
  service-only RPCs, sanitized coverage view, case-member RLS); registry surfaces
  `default_case_scoped`/`data_plane`. Owned `mcp_backends_registry.py` this wave.
- BATCH-G1 (`cc8c7a8`): RAG pgvector. Migration `202606081400_rag_pgvector.sql`
  (collections/documents/chunks, `vector(768)`, IVFFlat cosine, knowledge-vs-derived
  CHECK, RLS); `pgvector_store.py` case-scoped path-free adapter; `rag_search`
  returns shared knowledge UNION only the querying case's derived chunks. No
  gateway source touched (one new bridge test only).
- BATCH-I1 (`3fd86bd`): run_command uplift. `evidence_refs`/`output_ref` instead
  of arbitrary paths; `MVP_FORENSIC_ALLOWLIST` + `@mvp_forensic` alias; deep
  agent-response path sanitization (audit keeps absolutes); hash-linked provenance
  receipt. Deny-floor preserved (`bash` denied even when requested; dd/mount/losetup
  excluded). Updated 2 existing gateway tests that asserted the old absolute-path
  contract.

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed (integrated, main worktree): sift-gateway 355, sift-core 364,
  case-dashboard 344, forensic-rag 18, opensearch-mcp 987 (+71 skipped),
  tests/db 45. No regressions.
- Not run in this environment: live `supabase db` apply of migrations
  `202606081300`/`202606081400`, live OpenSearch ingest, and live VM portal journey.
  Validation was structural + unit-level, consistent with prior waves.

Last-mile binding gap (every consuming batch deferred this; no defined batch owns
it yet): the DB-authority code paths are built but not yet bound to live services.
Captured as B-MVP-5/6/7. These block BATCH-V1's live end-to-end journey but not the
individual batch acceptances (each passes with fallbacks/units).

Next:

- Launch BATCH-J1 (approved-only report generation/export; depends on E1, now landed).
- Resolve the binding batch (B-MVP-5/6/7) before BATCH-V1.

### 2026-06-08 - BATCH-D2 landed and integrated (Gateway job/authority seam)

Status: DONE

Changed (merged into `revamp/spg-v1`, `--no-ff`):

- BATCH-D2 (`e80ad41`): Gateway integration seam.
  - `jobs.py` (new) `JobService` over D1's `app.enqueue_job` /
    `app.job_status_public` / `app.expire_stale_jobs`. Enqueue writes the Gateway
    enqueue audit event first and passes its id as `p_enqueue_audit_event_id`,
    returning only `{job_id}`. Status reads go through an explicit agent-safe
    allow-list with case-membership enforcement (no `spec_internal`, `worker_id`,
    lease internals, local paths, or DB errors). `expire_stale_jobs` runs from a
    Gateway-owned periodic reaper wired into the FastAPI lifespan (mirrors the
    existing idle-reaper pattern). No grant/wrapper migration needed — same
    service DSN path as `ActiveCaseService`.
  - `AddonAuthorityMiddleware` (in `policy_middleware.py`) runs before the
    evidence gate/audit/dispatch: denies `addon_scope_missing` when the caller
    lacks a tool's `required_scopes`, denies `addon_prohibited_operation` when a
    backend's `prohibited_operations` is invoked; `non_authoritative` surfaced as
    advisory. `transport: library` manifests stay accepted but non-routable.
  - `server.py` indexes `required_scopes`/`authority_contract` into tool meta and
    exposes `Gateway.job_service` + `addon_authority_for_tool()`;
    `supabase_auth.is_scope_satisfied()` helper added.

Resolved B-MVP-3 and B-MVP-4 (both implemented by D2).

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 348 (335 baseline + 13 new); existing manifest/registry/policy
  tests green. D2 touched only the gateway package.
- Not run in this environment: live `supabase`/Postgres execution of the job RPCs
  (D2 pins to D1's frozen RPC/view names; D1 verified them on a Postgres 16 container).

Launch readiness: E1/F1/G1/I1 need no further Gateway glue — they wire their own
call sites onto `gateway.job_service` and inherit the authority enforcement. D2
deliberately did not add REST/MCP route handlers surfacing `JobService` (out of its
fence); the consuming batches own those call sites.

Next:

- Launch BATCH-E1, BATCH-F1, BATCH-G1, BATCH-I1 in parallel worktrees. BATCH-J1
  follows E1. BATCH-V1 follows all implementation batches.

### 2026-06-08 - Next-wave seams assigned to BATCH-D2

Status: DONE

Changed:

- Checked `revamp/spg-v1` after the first parallel wave: branch is clean,
  integration commits are present, and both doc validators pass.
- Solved the two open cross-batch seams by adding BATCH-D2 as a Gateway-only
  integration batch before the dependent wave.
- Assigned B-MVP-3 to BATCH-D2: Gateway adapter over D1 job enqueue/status/reaper
  surfaces.
- Assigned B-MVP-4 to BATCH-D2: runtime enforcement of add-on
  `authority_contract` and tool `required_scopes`.
- Updated dependent batch dependencies so E1/F1/G1/I1/J1/V1 consume D2 instead
  of each implementing Gateway glue independently.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch BATCH-D2 first. After D2 lands cleanly, launch E1/F1/G1/I1 in parallel;
  J1 follows E1, and V1 follows all implementation batches.

### 2026-06-08 - First parallel wave landed and integrated (A1/B1/C1/D1/H1)

Status: DONE

Changed (merged into `revamp/spg-v1`, one `--no-ff` merge per batch + one integration commit):

- BATCH-A1 (`4effda6`): Supabase-first installer/bootstrap. `~/.sift/supabase.env`
  (chmod 600) secrets via systemd `EnvironmentFile`; Admin-API invite + one-time
  temp password; `invited->active` forced-reset transition (`POST /api/auth/forced-reset`,
  `must_reset` login flag); frozen case path `case-<slug>-<MMDDHHSS>` + `-NN` with
  slug traversal guard; rewritten `/health` (Gateway, Supabase, evidence root,
  tools_count).
- BATCH-B1 (`55e6933`): Gateway policy parity + agent redaction. Agent/service
  tokens 403 on `POST /api/v1/tools/{tool}` before dispatch (F-MVP-3, closes the
  REST bypass the prior R4 block missed); path-redaction at the MCP choke point
  (in-case absolute -> relative, all other host paths -> `[REDACTED:absolute_path]`,
  audit retains absolute) (F-MVP-2). Made no edits to `evidence_gate.py`.
- BATCH-C1 (`67d0dbb`): DB evidence authority + custody ledger. Migration
  `202606081000_evidence_custody.sql` (evidence_objects/versions, append-only
  hash-linked custody events, chain heads as fail-closed read model, proof exports);
  service-only transition RPCs (seal/ignore/retire require a re-auth audit event id);
  added `check_evidence_gate_db()` alongside the untouched file-backed gate.
- BATCH-D1 (`df93104`): Durable Postgres jobs + worker. Migration
  `202606081200_durable_jobs.sql` (jobs/job_steps/job_logs/worker_heartbeats);
  `FOR UPDATE SKIP LOCKED` claim/lease RPCs; `job_status_public` sanitized view;
  `JobWorker` claim loop with path-scrubbed logs/results. Lease/race verified on a
  live Postgres 16 container.
- BATCH-H1 (`ed5f27a`): Add-on contract hardening. `authority_contract` +
  tool `required_scopes` on OpenCTI/Windows-triage; new library manifest for
  forensic-knowledge.
- Integration (`be4d7f4`, conductor): reconciled H1 into the Gateway manifest layer
  (the gateway-side glue H1 deferred) — backend schema now permits optional
  `authority_contract` + tool `required_scopes`; `load_and_validate_manifest` skips
  `transport: library` / `standalone_server: false` manifests as non-routable;
  `test_phase6` enumerates routable backends only.

Branch fileset was fully disjoint across the five batches; merges were
conflict-free. The B1/C1 `evidence_gate.py` overlap I pre-split did not
materialize (B1 worked in `policy_middleware`/`response_guard` instead).

Validation:

- Passed: `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`.
- Passed: sift-gateway 335, sift-core 346, case-dashboard 322, tests/db 45,
  opencti 11, windows-triage 24, forensic-knowledge 31. No regressions.
- Not run in this environment: live SIFT VM smoke (installer bootstrap, Supabase
  Admin API) and live `supabase db` apply of the two new migrations. C1 used the
  repo's text-based migration tests; D1 applied on a Postgres 16 container.

Carried-forward integration follow-ups (feed the dependent wave):

- Gateway enqueue/status adapter over D1's `enqueue_job` / `job_status_public`
  (returns only `job_id`; set `enqueue_audit_event_id`; schedule `expire_stale_jobs`
  reaper). New B-MVP-3.
- Switch the MCP evidence gate to prefer `check_evidence_gate_db()` once cases
  carry DB evidence state (B1/C1 seam) — consumed by BATCH-E1.
- Runtime enforcement of `authority_contract` (`non_authoritative`,
  `prohibited_operations`, `required_scopes`) in the Gateway backend registry;
  schema acceptance is done, routing-time enforcement is not. New B-MVP-4.
- Concrete job handlers (ingest/enrich/report/run_command) for `JobWorker` belong
  to BATCH-F1 and BATCH-I1.

Next:

- Launch the dependent wave: BATCH-E1 (portal DB authority), BATCH-F1 (OpenSearch
  ingest adapter), BATCH-G1 (RAG pgvector), BATCH-I1 (job-backed run_command),
  BATCH-J1 (approved-only reports), then BATCH-V1.

### 2026-06-08 - MVP forks closed for parallel sprint

Status: DONE

Changed:

- Resolved F-MVP-1: case directories use
  `/cases/case-<slug>-<MMDDHHSS>` with a lowercase filesystem-safe slug and
  `-NN` collision suffix if needed.
- Resolved F-MVP-2: agents may see evidence IDs, display names, relative
  display paths, size, hash, seal status, and provenance IDs. Absolute case,
  evidence, and mount paths remain forbidden.
- Resolved F-MVP-3: agents use MCP only for the MVP. REST tool execution is
  operator-only.
- Resolved F-MVP-4: hackathon report export keeps the current profile output
  and adds DB metadata, approved-only filtering, custody/provenance appendix,
  and downloadable artifact.
- Deferred B-MVP-1 and B-MVP-2 as post-MVP presentation/backlog items.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Launch parallel worktrees using the prompts generated from
  `task-batches.md`.

### 2026-06-08 - Migration docs collapsed to MVP operating model

Status: DONE

Changed:

- Purged the previous `docs/migration` document forest.
- Added `Migration-Spec.md` as the architecture, journey, constraints, and DoD
  source of truth.
- Added `task-batches.md` as the parallel-execution tracker with grep-friendly
  checkboxes.
- Added `Session-Notes.md` as the top-loaded change log and fork/backlog table.
- Recreated root `AGENTS.md` and `CLAUDE.md` as compact sprint instructions.
- Updated the Python document validator to enforce the new three-file model.

Validation:

- Passed: `python3 scripts/validate_docs.py`.
- Passed: `python3 scripts/validate_migration_docs.py`.

Next:

- Start BATCH-A1, BATCH-B1, and contract prep for BATCH-C1/BATCH-D1 in separate
  worktrees after the operator confirms or resolves the open forks below.

## Forks / Backlog / Needs Input

| ID | Type | Status | Decision or work needed | Recommendation | Blocks |
| --- | --- | --- | --- | --- | --- |
| F-MVP-1 | Fork | RESOLVED | Case directory format is `/cases/case-<slug>-<MMDDHHSS>`, with lowercase filesystem-safe slug and `-NN` collision suffix if needed. | Locked for BATCH-A1 and BATCH-C1. | none |
| F-MVP-2 | Fork | RESOLVED | Agents may see `evidence_id`, display name, relative display path, size, hash, seal status, and provenance ID. Absolute case/evidence/mount paths are forbidden. | Locked for BATCH-B1 and BATCH-C1. | none |
| F-MVP-3 | Fork | RESOLVED | Agents use MCP only for the MVP. REST tool execution is operator-only. | Locked for BATCH-B1. | none |
| F-MVP-4 | Fork | RESOLVED | Hackathon report export keeps current profile output and adds DB metadata, approved-only filtering, custody/provenance appendix, and downloadable artifact. | Locked for BATCH-J1. | none |
| F-MVP-5 | Fork | RESOLVED | Gateway Supabase health probe omitted `apikey`; Kong returned 401 and health read degraded. | Fixed in `health.py`: send configured anon key as `apikey`. | none |
| F-MVP-6 | Fork | RESOLVED | First-login deadlock: login rejected `invited` operators, but forced reset requires a session cookie. | Fixed in `supabase_auth.py`: login admits `active` and `invited`; protected resolution stays active-only. | none |
| F-MVP-7 | Fork | RESOLVED | Custody append used pgcrypto `digest()`, unresolved on Supabase under the function search path. | Fixed in `202606081000_evidence_custody.sql`: use built-in `sha256(v_payload::bytea)`. | none |
| F-MVP-8 | Fork | RESOLVED | Critical mutable DFIR state authority is Postgres. Supabase Storage and case files are immutable exports, workspace/debug artifacts, parser compatibility artifacts, or legacy fallback only. | Locked in `Migration-Spec.md` authority cutover model and K-series batches. | none |
| F-MVP-9 | Fork | RESOLVED | Hostname detection/correction is required for parser/indexer metadata and OpenSearch index naming, but it is derived state only. | Keep `opensearch_fix_host_mapping` canonical and `opensearch_host_fix` as deprecated alias; record corrections in DB provenance/host identity. | K4 |
| F-MVP-10 | Fork | RESOLVED | Solana anchoring is optional external proof, not local authority. DB custody chain heads decide evidence gate state. | Record DB-derived anchor proof in `app.evidence_proof_exports`; export to file/storage when configured. | K3 |
| B-MVP-1 | Backlog | DEFERRED | Enterprise object-lock/WORM evidence vault option. | Post-MVP architecture appendix only. | none |
| B-MVP-2 | Backlog | DEFERRED | ContextForge/Envoy-style external gateway integration. | Post-MVP presentation/backlog only; Gateway policy remains in SIFT Gateway for MVP. | none |
| B-MVP-3 | Backlog | DONE | Gateway enqueue/status adapter over D1's `enqueue_job`/`job_status_public` (job_id only, sets `enqueue_audit_event_id`, schedules `expire_stale_jobs` reaper). | Landed in BATCH-D2 (`e80ad41`) as `JobService` + lifespan reaper. | E1, F1, G1, I1, J1 |
| B-MVP-4 | Backlog | DONE | Runtime enforcement of add-on `authority_contract` (non_authoritative, prohibited_operations, required_scopes) in the Gateway backend registry; schema acceptance landed in this wave. | Landed in BATCH-D2 (`e80ad41`) as `AddonAuthorityMiddleware`. | F1 |
| B-MVP-5 | Backlog | DONE | Bind `create_dashboard_v2_app` service slots (`evidence_service`/`investigation_service`/`report_service`/`job_service`) to live Postgres/C1 RPCs/D2 `JobService`. | Landed in BATCH-L1 with Gateway-owned `portal_services.py` and migration `202606081500_report_metadata.sql`. | none |
| B-MVP-6 | Backlog | DONE | Worker bootstrap + enqueue call sites: register D1 `JobWorker` handlers (`ingest`, `run_command`) and enqueue call sites that place resolved local paths in worker-only `spec_internal`. | Landed in BATCH-L1 with `sift-job-worker`, generic `ingest_job`, `run_command_job`, and `job_status`. | none |
| B-MVP-7 | Backlog | DONE | Wire a case-scoped pgvector RAG query tool (G1 `app.rag_search`/`PgVectorRagStore`) into the Gateway tool surface with a worker service DSN. | Landed in BATCH-L1 as `rag_search_case`, routed through existing Gateway policy/response guard. | none |
| B-MVP-8 | Backlog | DONE | Installer bootstrap created Supabase `auth.users` without matching `app.operator_profiles` and lacked full control-plane DSN/env wiring. | Landed in V1 enabler integration (`58c669b`, merge `84404ba`): installer writes `~/.sift/control-plane.env`, keeps DSN/pepper out of YAML, and creates/repairs Auth + `app.operator_profiles` together. | verified in BATCH-V1 |
| B-MVP-9 | Backlog | DONE | Case-bound agent issuance was inconsistent: case-scoped scopes did not load, while global scopes lacked an active-case default. | Landed in V1 enabler integration (`58c669b`, merge `84404ba`): MVP agents use global tool scopes plus `agents.default_case_id`/token `case_id` bound to the active DB case. | verified in BATCH-V1 |
| B-MVP-10 | Backlog | DONE | Agent `record_finding`/`record_timeline_event` stage to case files, not `app.investigation_*`; portal approval and approved-only report DB authority do not see them. | Landed in BATCH-K2 (`5b1cf9c`): `case_manager` writes findings/timeline/IOC/TODO DB-first via `PostgresInvestigationStore`; portal review + approved-only report read DB authority. | verified in BATCH-V1 |
| B-MVP-11 | Backlog | DONE | `rag_search_case` denied live with `active_case_proxy_denied`; case-scoped Gateway-local tool was treated like a proxied tool without safe case args. | Landed in V1 enabler integration (`db47c71`, merge `2c34520`): `ProxyActiveCaseMiddleware` skips Gateway-local tools; RAG still resolves active case internally and remains response-guarded. | verified in BATCH-V1 |
| B-MVP-12 | Backlog | DONE | `run_command` deny floor worked, but allowed execution failed because `agent_runtime` lacked read ACL on new case dirs. | Landed in V1 enabler integration (`0acd60f`, merge `09a0023`): portal case creation applies per-case `setfacl` for `agent_runtime` read/write areas and denies legacy authority artifacts. | verified in BATCH-V1 |
| B-MVP-13 | Backlog | DONE | Evidence seal/ignore/retire re-auth still uses legacy local-password PBKDF2 HMAC, not Supabase password re-auth. | MVP decision landed in V1 enabler integration (`0acd60f`, merge `09a0023`): local password/HMAC remains the MVP re-auth bridge and endpoints surface `reauth_method=local_hmac_mvp_bridge`; Supabase password re-auth is deferred. | none |
| B-MVP-14 | Backlog | DONE | No standalone register-evidence endpoint exists. Operator journey said detect -> register -> seal, but implementation folded registration into seal `file_specs` while emitting `EVIDENCE_REGISTERED`. | MVP decision landed in V1 enabler integration (`0acd60f`, merge `09a0023`): register+seal is one atomic operator action (`registration_mode=atomic_register_and_seal`); DB seal calls `app.evidence_register` before `app.evidence_seal`. | verified in BATCH-V1 |
| B-MVP-15 | Backlog | DONE | Supabase pgvector RAG was schema/query-surface only; live VM tables were empty and any knowledge answers came from legacy `kb_*`/forensic-knowledge. | Landed in V1 enabler integration (`db47c71`, merge `2c34520`): `rag-mcp-seed-pgvector` seeds shared knowledge collections/documents/chunks (`kind='knowledge'`, `case_id NULL`) with 768-d embeddings through pgvector, not Chroma. | verified in BATCH-V1 |
| B-MVP-16 | Backlog | DONE | DB-active mode still has split-brain file authority touchpoints: active-case pointer/env fallbacks, JSONL audit, evidence manifest/ledger, findings/timeline/TODO/IOC JSON, approval JSONL, OpenSearch ingest status/manifests, host dictionary, and run-command access to case-local authority artifacts. | Closed by K1-K6 (landed/integrated on `revamp/spg-v1`): active-case + audit (K1), investigation (K2), evidence/proof (K3), OpenSearch/host (K4), run_command env/ACL (K5), and report/audit/backup file-authority removal + tamper regressions (K6). Remaining file paths are explicit legacy fallback, parser compatibility, workspace/debug, or immutable export only. | verified in BATCH-V1 |
| B-MVP-17 | Backlog | DONE | K1 DB audit envelope covers case-context-established tool attempts and now wraps proxy/evidence-gate denials, but tool-scope authorization denials and active-case lookup denials still use pre-existing denial audit paths before an authority context can attach. | Decided in K6 (`b76eba9`) and accepted for MVP live cutover: pre-context denials stay on the local audit mirror (`status=denied`) for security telemetry and are NOT projected into `app.audit_events` (projecting unresolved principals/null case_id would write unattributable rows and expose a DB write path to unauthenticated callers). The K1 envelope remains the sole DB-audit write path for allowed calls + post-context denials. Locked by `test_k6_precontext_denial_audit.py`. | none |
