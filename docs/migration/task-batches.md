# Task Batches

Status: operator-readiness, hardening, add-on, and documentation regeneration tracker.
Last updated: 2026-06-13.

This file is the executable batch list. `docs/migration/Session-Notes.md` is the
decision log. Older completed migration batches remain in git history; do not
re-expand them here unless a current batch needs exact historical evidence.

## Rules

- Read `AGENTS.md`, this file, and `docs/migration/Session-Notes.md` before work.
- Use one worktree per parallel batch when practical.
- Check the leading batch checkbox only after the batch acceptance checks pass.
- Keep batch planning in this file. Do not create extra migration runbooks.
- Worker branches should avoid editing `docs/migration/**`; return a landing log
  and let the conductor update this tracker after merge.
- `docs/regenerate/**` is seed/reference material from the first migration phase.
  Treat it as stale until a batch revalidates it against code and the live VM.
- For library, SDK, API, CLI, framework, or cloud-service docs, use the Context7
  CLI workflow from `AGENTS.md` and record exact source/version/date in the
  resulting doc.

## Current Baseline

Core now means: Gateway, sift-core, operator portal, Supabase/Postgres control
plane, OpenSearch, forensic-rag-mcp on Supabase pgvector, forensic-knowledge,
Hayabusa, installer/system services, and the local worker.

External add-ons mean: OpenCTI and future Windows triage style integrations. They
must not be installed by the core installer. They join through the backend
contract, manifest, registry, requirement gates, and portal/operator workflow.

Live installer baseline from 2026-06-12: clone-entry `./install.sh` stages to
`/opt/sift-mcps`, services run as `sift-service`, `/health` is `status=ok`,
OpenSearch/RAG backend rows mount as idle stdio proxies, RAG pgvector is populated,
and portal operator login works. Remaining live proof: issue an agent/service
credential from the portal and run aggregate MCP `initialize`/`tools/list` plus
OpenSearch/RAG tool smoke.

## Wave Order

1. Discovery and operator docs: OR1, OR2, OR4 can run in parallel after OR0.
2. Operator manual: OR3 consumes OR1, OR2, and OR4.
3. Hardening research/audit: HR1 can run in parallel with OR1/OR2; HR2 consumes
   HR1 plus OR1/OR2; HR3 implements agreed changes.
4. Add-ons and cleanup: AD1, CL1 can run after OR2/HR1; AD2 consumes AD1.
5. Portal/TLS/product gaps: PT1, PT2, TLS1 consume operator docs and hardening
   decisions.
6. Regenerate docs and live validation: RG1 and LV1 close the program.

## Batch Index

- [x] BATCH-OR0 - Rebase docs operating model around operator-hardening track
- [x] BATCH-OR1 - Live VM inventory and SIFT tool path map
- [x] BATCH-OR2 - File-state versus database-authority discovery map
- [x] BATCH-OR3 - Full operator maintenance manual and variable dictionary
- [x] BATCH-OR4 - RAG, forensic knowledge, and Hayabusa provenance manual
- [x] BATCH-HR1 - Official hardening research matrix
- [x] BATCH-HR2 - Component hardening audit guides
- [x] BATCH-HR3 - Installer and runtime hardening implementation wave
- [x] BATCH-AD1 - Add-on specification and author guide
- [x] BATCH-AD2 - Add-on conformance tests and OpenCTI/Windows-triage proof
- [x] BATCH-CL1 - Legacy, pre-migration, and dead-reference cleanup
- [ ] BATCH-CL2 - ProtocolSiftGateway rename and add_ons repository layout
- [x] BATCH-PT1 - Portal operator workflow and health features
- [ ] BATCH-PT2 - Portal RAG document management flow
- [x] BATCH-TLS1 - Installer certificate and trust strategy
- [ ] BATCH-SB1 - Self-managed Supabase compose with generated secrets (DEFERRED to after LV1 per operator 2026-06-13)
- [ ] BATCH-CL3 - Retire legacy file-HMAC re-auth plane (BLOCKED 2026-06-13: premise false, needs operator re-scope - see B-MVP-017 + CL3 section)
- [x] BATCH-DB1 - Adopt FORCE ROW LEVEL SECURITY on app.* tables (B-MVP-013)
- [x] BATCH-UN1 - Component uninstaller, remove all or selected components (B-MVP-007)
- [x] BATCH-RG1 - Regenerate documentation modernization pass
- [ ] BATCH-LV1 - End-to-end live VM validation and Rocba proof

## BATCH-OR0 - Rebase docs operating model around operator-hardening track

Dependencies: none.

Scope:

- `AGENTS.md`
- `docs/migration/task-batches.md`
- `docs/migration/Session-Notes.md`

Exact work:

- Replace the completed migration tracker with this second-phase batch plan.
- Preserve the important settled decisions: Supabase/Postgres authority,
  Gateway-only policy, OpenSearch/RAG/FK/Hayabusa as core, OpenCTI and Windows
  triage as external add-on candidates, clone-entry installer flow, and
  live-VM validation discipline.
- Point future sessions at `docs/regenerate/**` as stale source material to be
  refreshed, not blindly trusted.

Hints and references:

- `docs/regenerate/backend-contract.md` contains useful manifest/add-on material
  but still reflects older paths and should be verified during AD1.
- `docs/regenerate/mcp-contracts.md` and `data-flows-and-lifecycles.md` contain
  stale `rag_search_case` and Chroma language; fix under RG1/OR4.
- `docs/regenerate/security-architecture.md` and
  `dfir-hardening-guide-pre-migration.md` are good hardening seeds for HR2.

Acceptance:

- `AGENTS.md` points to this two-file migration model.
- Batch list captures all operator requests in actionable, parallelizable work.
- `python3 scripts/validate_docs.py`, `python3 scripts/validate_migration_docs.py`,
  and `git diff --check` pass.

## BATCH-OR1 - Live VM inventory and SIFT tool path map

Dependencies: BATCH-OR0.

Scope:

- New doc: `docs/inventory/sift-tool-inventory.md`
- Optional helper: `scripts/inventory-sift-tools.sh`
- Installer injection notes in `install.sh` only if a missing-tool fix is tiny
  and fully validated; otherwise leave as explicit backlog rows.

Exact work:

- SSH to the live VM and collect a complete post-install inventory of forensic
  and platform tools, including symlinks and real paths.
- Record package/source ownership where discoverable: apt/dpkg, pip/uv venv,
  GitHub release download, bundled repo data, Docker image, or manual operator
  install.
- Include key paths and modes for services, venv entrypoints, config files,
  TLS/CA material, Supabase project files, OpenSearch config, RAG knowledge
  corpus, Hayabusa binary/rules, and Volatility symbol cache.
- Identify key missing SIFT/DFIR tools and whether the installer should install
  them by default, leave them operator-managed, or expose them only through
  `run_command`.

Hints and references:

- VM: `sansforensics@192.168.122.81`; use `sshpass` only from the host.
- Confirm service paths with:
  `sudo systemctl show sift-gateway.service -p WorkingDirectory -p User -p EnvironmentFiles`.
- Check real paths with `command -v`, `readlink -f`, `ls -l`, `dpkg -S`,
  `python3 -m pip show`, and `/opt/sift-mcps/.venv/bin/* --help` where safe.
- Include at minimum: `python3.12`, `uv`, `supabase`, `supabase-go`, `docker`,
  `docker compose`, `rg`, `hayabusa`, `vol3`, `fls`, `mmls`, `ewfmount`,
  `tsk_*`, `yara`, `log2timeline.py`, `psort.py`, `bulk_extractor`,
  `strings`, `jq`, `curl`, `openssl`, `opensearch-mcp`, and `rag-mcp`.
- Capture Docker inventory: images, containers, volumes, networks, and bound
  ports for Supabase and OpenSearch. Do not paste raw secrets.

Acceptance:

- `docs/inventory/sift-tool-inventory.md` gives the operator a checked,
  command-backed inventory with symlink targets and maintenance notes.
- Missing-tool recommendations are grouped as required/default, optional, or
  out-of-scope.
- No secret values, JWTs, DSNs, or private tokens are committed.
- Relevant shell/docs checks pass.

## BATCH-OR2 - File-state versus database-authority discovery map

Dependencies: BATCH-OR0.

Scope:

- New doc: `docs/operator/state-authority-map.md`
- Updates to `docs/regenerate/**` only if directly tied to verified authority
  facts; broad cleanup belongs to BATCH-RG1.

Exact work:

- Produce a full inventory of mutable system state and classify each item as
  database-authoritative, file-authoritative, derived/rebuildable, export/proof,
  secret/config, cache, or obsolete legacy fallback.
- Map all remaining file-backed JSON/YAML/ledger/audit/log/reference paths to
  the DB tables/RPCs that own truth, or document why the file remains authority.
- Call out old migration debt explicitly: hashes, ledgers, audit, custody,
  active case, findings, timeline, reports, jobs, RAG rows, OpenSearch indices,
  backend registry, portal sessions, and add-on registration.

Hints and references:

- DB authority starts in `supabase/migrations/**`; search for `create table app.`,
  `create or replace function app.`, `security definer`, and `grant execute`.
- Core code landmarks: `packages/sift-core/src/sift_core/evidence_chain.py`,
  `investigation_store.py`, `case_io.py`, `reporting.py`,
  `execute/worker.py`, and `execute/job_store.py`.
- Gateway landmarks: `active_case.py`, `evidence_gate.py`,
  `policy_middleware.py`, `mcp_backends.py`, `audit.py`, `response_guard.py`,
  `health.py`, and `server.py`.
- Portal landmarks: `packages/case-dashboard/src/case_dashboard/routes.py` and
  frontend state panels under `packages/case-dashboard/frontend/src/**`.
- Useful scans:
  `rg --files | rg '(json|yaml|yml|env|ledger|manifest|audit|sqlite|db)$'`,
  `rg -n 'file-backed|fallback|legacy|manifest|ledger|active_case|rag_chunks|app\\.' packages supabase install.sh`.

Acceptance:

- The doc has a table with: state/fact, authority, DB object, file mirror or
  cache, writer, reader, maintenance command, backup/restore note, and migration
  status.
- Any remaining file-authoritative state is justified and has a follow-up batch
  or accepted reason.
- Stale claims in `docs/regenerate/**` are listed for RG1.

## BATCH-OR3 - Full operator maintenance manual and variable dictionary

Dependencies: BATCH-OR1; BATCH-OR2; BATCH-OR4.

Scope:

- New doc: `docs/operator/maintenance-guide.md`
- Optional doc split if it grows too large:
  `docs/operator/config-and-secrets.md`,
  `docs/operator/rag-and-search-maintenance.md`

Exact work:

- Write the operator manual for a real installed VM: login, password discovery,
  forced reset, password rotation, service status, restarts, health checks,
  backup/restore, evidence mount/seal, RAG maintenance, OpenSearch index checks,
  add-on registration, logs, audit checks, and failure recovery.
- Produce a variable dictionary covering environment files, installer variables,
  Supabase project exports, Gateway env refs, DB-backed settings, OpenSearch
  config, RAG/FK/Hayabusa settings, Docker compose variables, and systemd unit
  environment files.
- Explain where the current password is and is not recoverable:
  installer handoff stores the temporary operator password before first reset;
  after reset, the password is not recoverable and must be rotated/reset.
- Include "what not to edit manually" for generated files such as
  `~/.sift/supabase-project/sift-supabase.env`.

Hints and references:

- Handoff file: `/var/lib/sift/tokens/installer-handoff.txt`.
- Expected portal email: `examiner@operators.sift.local`.
- Important generated/config paths to verify:
  `/var/lib/sift/.sift/control-plane.env`,
  `/var/lib/sift/.sift/gateway.yaml`,
  `/var/lib/sift/.sift/opensearch.yaml`,
  `/var/lib/sift/.sift/forensic-knowledge.env`,
  `/home/sansforensics/.sift/supabase-project/sift-supabase.env`,
  `/opt/sift-mcps`, `/cases`, and `/var/cache/sift`.
- Useful DB checks should be written with redaction, for example row counts and
  key names only for `app.mcp_backends`, `app.rag_chunks`, jobs, audit, cases,
  and evidence tables.
- OpenSearch checks: `_cluster/health`, `_cat/indices`, index templates, ingest
  pipeline presence, and case index prefixes.

Acceptance:

- A new operator can maintain the installed system without reading source code.
- No committed manual includes raw keys, DSNs, passwords, JWTs, tokens, or private
  certificates.
- All commands are safe by default and label destructive/reset operations.
- Docs validators and whitespace checks pass.

## BATCH-OR4 - RAG, forensic knowledge, and Hayabusa provenance manual

Dependencies: BATCH-OR0.

Scope:

- New doc: `docs/operator/reference-data-provenance.md`
- Update notes for `docs/regenerate/data-flows-and-lifecycles.md`,
  `mcp-contracts.md`, `matrix-comparison.md`, and `known-limitations-and-improvements.md`
  to be applied in RG1.

Exact work:

- Trace exactly what RAG seeds, what model embeds it, where the model/cache comes
  from, what the installer downloads by default, and what remains optional.
- Trace forensic-knowledge data: repo location, installed/symlinked location,
  `FK_DATA_DIR`, loader call sites, and how context injection is used after tool
  calls.
- Trace Hayabusa: binary source, rules source, install location, rules location,
  event-log ingest path, generated CSV/output paths, OpenSearch index pattern,
  and how agents query results.
- Produce an external-download ledger for installer hardening: URL/source,
  version pin, checksum/signature status, cache path, offline alternative, and
  whether the download is allowed in a hardened/offline profile.

Hints and references:

- RAG installer functions: `download_rag_index`, `import_rag_pgvector`,
  `seed_rag_pgvector`, `seed_rag_assets`.
- RAG package landmarks:
  `packages/forensic-rag-mcp/src/rag_mcp/pgvector_seed.py`,
  `pgvector_store.py`, `server.py`, `query_embedding.py`, `knowledge/**`.
- Forensic knowledge landmarks:
  `packages/forensic-knowledge/src/forensic_knowledge/**`,
  `packages/forensic-knowledge/data/**`, and `FK_DATA_DIR` wiring in `install.sh`.
- Hayabusa landmarks:
  `install.sh install_hayabusa`,
  `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`,
  `ingest_cli.py`, `mappings/hayabusa_template.json`, and registry entries that
  mention Hayabusa fallback searches.
- Current policy: RAG is knowledge-only in pgvector. Case evidence must not be
  silently embedded into shared RAG without an explicit future design.

Acceptance:

- The doc answers: what was downloaded, from where, why, where stored, how to
  refresh, how to disable, and how to run offline.
- It distinguishes forensic knowledge/reference from case evidence.
- It identifies any unpinned or unauthenticated download as a hardening backlog.

## BATCH-HR1 - Official hardening research matrix

Dependencies: BATCH-OR0.

Scope:

- New doc: `docs/hardening/research-matrix.md`

Exact work:

- Build a vendor/source-backed hardening research matrix for every component:
  Ubuntu/SIFT host, systemd services, Docker/Compose, Supabase CLI/Auth/Postgres,
  Postgres/RLS/pgvector, OpenSearch, FastAPI/FastMCP, React/Vite portal, Python/uv,
  AppArmor, auditd, TLS/certificates, Hugging Face/sentence-transformers,
  Hayabusa, and MCP/add-on manifests.
- For each component, record current repo/runtime posture, official best-practice
  reference, gap, severity, implementation owner, and validation method.

Hints and references:

- Use Context7 first for library/framework/API/CLI/cloud-service docs according
  to `AGENTS.md`.
- For OS/security components where Context7 is not appropriate or insufficient,
  use official vendor/project docs only and cite the exact URL/version/date.
- Do not rely on generic blog posts when official docs exist.
- Keep this batch research-only unless a small docs correction is required.

Acceptance:

- Matrix has source links and retrieval dates for each component.
- Every hardening recommendation maps to either HR2/HR3/PT/TLS/AD/CL follow-up
  or an accepted "not applicable" rationale.
- No implementation change is merged from this batch unless separately tested.

## BATCH-HR2 - Component hardening audit guides

Dependencies: BATCH-HR1; BATCH-OR1; BATCH-OR2.

Scope:

- New doc: `docs/hardening/component-audit.md`
- Optional per-component docs under `docs/hardening/components/`

Exact work:

- Convert the research matrix into an actionable audit guide for each repo
  component, from smallest to most important.
- Include exact check commands, expected output shape, config paths, service
  names, DB queries, logs, tests, and risk ratings.
- Cover at minimum: database/Supabase, OpenSearch, RAG, Hayabusa, Docker,
  systemd, AppArmor, auditd, Gateway APIs/MCP, portal React/API routes, add-ons,
  installer, secrets/env files, evidence custody, reports/exports, and worker
  sandbox.

Hints and references:

- Start from `docs/regenerate/security-architecture.md` and
  `dfir-hardening-guide-pre-migration.md`, but rewrite current facts from code.
- Pull variable/source facts from OR1/OR2/OR3 rather than duplicating guesses.
- Each component section should have: purpose, current posture, threats,
  checks, remediation plan, residual risk, and owner batch.

Acceptance:

- The audit guide is executable by an operator or reviewer on the VM.
- Each finding has severity, evidence, and a concrete next step.
- The guide avoids secret disclosure and labels destructive commands clearly.

## BATCH-HR3 - Installer and runtime hardening implementation wave

Dependencies: BATCH-HR2.

Scope:

- `install.sh`
- `scripts/setup-supabase.sh`
- `scripts/setup-addon.sh`
- `configs/**`
- `docker-compose*.yml`
- service docs/tests touched by hardening fixes

Exact work:

- Implement approved hardening deltas from HR2 that are safe for the core install.
- Likely areas: secret file modes and ownership, generated env file clarity,
  offline/download controls, checksums for downloaded binaries, OpenSearch bind
  posture, Supabase project isolation, Docker profiles, systemd hardening
  directives, AppArmor/auditd coverage, log redaction, backup/restore checks,
  and explicit destructive reset safeguards.
- Keep changes incremental and test each risk boundary.

Hints and references:

- Use the live VM only after local targeted tests pass.
- Preserve zero-argument clone-entry install flow.
- Preserve SIFT VM Python constraints: `/usr/bin/python3.12`,
  `UV_NO_MANAGED_PYTHON=1`, `UV_PYTHON_DOWNLOADS=never`.
- Avoid reintroducing native OpenCTI or bundled Windows triage into the core path.

Acceptance:

- Targeted shell/unit tests pass.
- Fresh or cleaned VM installer run exits 0.
- `/health` remains `status=ok`.
- Services run under intended service identity and no secret is readable by the
  operator/agent users beyond the designed handoff.
- Session notes include sanitized live proof.

## BATCH-AD1 - Add-on specification and author guide

Dependencies: BATCH-OR2; BATCH-HR1.

Scope:

- New doc: `docs/add-ons/spec.md`
- New doc: `docs/add-ons/author-guide.md`
- Update or replace `docs/regenerate/backend-contract.md` during RG1, not here,
  unless the doc is promoted directly.

Exact work:

- Document the current add-on contract in a way a third-party MCP author can
  implement: manifest schema, transport, namespace, capabilities/requires,
  env_refs, authority_contract, scopes, prohibited operations, setup flow,
  validation, portal registration, hot reload, health, and tests.
- Make the core/add-on boundary explicit: OpenSearch, RAG, forensic-knowledge,
  and Hayabusa are core; OpenCTI is external; Windows triage is a future external
  candidate to rebuild or reintroduce only through the add-on path.
- Include a worked query-only add-on example and a conformance checklist.

Hints and references:

- Verify against `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`,
  `mcp_backends.py`, `server.py`, `mcp_server.py`, `policy_middleware.py`,
  `install.sh seed_addon_backends`, and `scripts/setup-addon.sh`.
- Use `packages/opencti-mcp/sift-backend.json` as the first external add-on
  example after confirming it is not in the core installer path.
- Confirm current package paths before writing examples. Windows triage was
  removed from core; do not cite old paths as current functionality.

Acceptance:

- An author can create a new add-on without changing Gateway code.
- The guide explains failure modes: unmet requirements, missing env refs, denied
  scopes, duplicate tool names, and non-authoritative restrictions.
- Manifest validation and at least one golden/example manifest are covered by
  tests or documented check commands.

## BATCH-AD2 - Add-on conformance tests and OpenCTI/Windows-triage proof

Dependencies: BATCH-AD1; BATCH-OR1.

Scope:

- `scripts/setup-addon.sh`
- `packages/opencti-mcp/**`
- Optional future `add_ons/windows-triage-mcp/**` only after CL2 or a scoped
  reintroduction decision.
- Gateway add-on registry/tests and portal backend controls as needed.

Exact work:

- Prove OpenCTI installs and registers only as an external add-on, never as part
  of the core installer.
- Add conformance tests that exercise manifest validation, requirement gating,
  env_refs, hot reload, query-only authority enforcement, duplicate/shadowed
  tool handling, and clean uninstall/disable.
- Decide whether Windows triage should be recreated as a decoupled add-on now or
  left as an author-guide example/backlog. Do not reintroduce it to core.

Hints and references:

- Use Portal -> Backends or the current registry API path, not direct DB edits,
  for operator-facing registration proof.
- Confirm add-on OpenSearch/Docker resources cannot contaminate the native
  forensic OpenSearch cluster.
- Test negative cases: missing Docker, missing env var, insufficient scopes,
  and attempt to perform an authority operation.

Acceptance:

- OpenCTI add-on proof is documented and repeatable.
- Core install remains OpenCTI-free and Windows-triage-free.
- Add-on tools appear/disappear from aggregate MCP without gateway restart when
  expected.
- Query-only policy is enforced fail-closed.

## BATCH-CL1 - Legacy, pre-migration, and dead-reference cleanup

Dependencies: BATCH-OR2.

Scope:

- Code comments and docs across `packages/**`, `scripts/**`, `install.sh`,
  `docs/regenerate/**`, `pyproject.toml`, and tests.

Exact work:

- Scan for stale names, pre-migration assumptions, dead packages, obsolete
  comments, old file-authority claims, removed tool names, old service paths,
  native OpenCTI references, Windows triage core references, Chroma-as-default
  language, `rag_search_case`, `systemctl --user`, stale `~/.sift` service
  paths, and old product docs that were moved to `docs/regenerate`.
- Remove dead code where proven unreachable; update comments/docs where code is
  current but wording is stale.
- Keep behavior-preserving cleanup separate from behavior changes.

Hints and references:

- Useful searches: `rg -n 'agentir|pre-migration|premigration|legacy|Chroma|chromadb|rag_search_case|windows-triage|wintriage|OpenCTI|systemctl --user|sift-mcps-test|~/.sift|docs/product|docs/status'`.
- Compare every removal against tests and import graph; do not delete a fallback
  just because a comment says it is old.
- Regenerate or update golden snapshots if tool metadata changes.

Acceptance:

- No live code points at removed packages or obsolete native install behavior.
- Remaining legacy references are intentional and labelled.
- Targeted tests and docs validators pass.

## BATCH-CL2 - ProtocolSiftGateway rename and add_ons repository layout

Dependencies: BATCH-AD1; BATCH-CL1.

Scope:

- Repository metadata and docs naming.
- Move external add-on packages under a dedicated `add_ons/` tree if approved.
- Root workspace config, install/setup scripts, tests, docs, and CI references.

Exact work:

- Plan and implement the repo rename from `sift-mcps` to `ProtocolSiftGateway`
  without breaking the clone-entry installer.
- Move add-on candidates into a clear `add_ons/` folder while preserving Python
  package import names unless a deliberate package rename is approved.
- Update root `pyproject.toml`, `uv.lock`, setup scripts, manifests, docs, and
  tests to use the new paths.
- Keep core packages in their current ownership boundary: Gateway, core, portal,
  OpenSearch, RAG, forensic-knowledge, and installer.

Hints and references:

- Needs operator decision before changing the GitHub remote/repo name.
- The installer currently stages to `/opt/sift-mcps`; decide whether to preserve
  that runtime path for compatibility or migrate to `/opt/ProtocolSiftGateway`.
- Keep external add-ons out of the default `full` extra and native install path.
- Run an import/path audit after moves: `rg`, `uv lock --check`, targeted tests,
  and a clone-entry installer smoke.

Acceptance:

- A fresh clone using the new repo name can run `./install.sh`.
- Add-ons are visibly separate from core without breaking setup-addon.
- All path changes are documented for operators and future agents.

## BATCH-PT1 - Portal operator workflow and health features

Dependencies: BATCH-OR3.

Scope:

- `packages/case-dashboard/frontend/src/**`
- `packages/case-dashboard/src/case_dashboard/routes.py`
- Gateway health/backend APIs as needed.

Exact work:

- Fix operator portal workflow gaps:
  create-new-case after first login, root URL redirect to `/portal/`, backend
  health panel, service/backend status visibility, add-on backend controls, and
  clearer handoff/reset UX.
- Keep portal REST human/operator-only. Agents continue to use MCP only.
- Add useful operational panels without exposing secrets.

Hints and references:

- Current main portal URL: `https://192.168.122.81:4508/portal/`.
- Root `/` should redirect or link cleanly to `/portal/`, not fail with a raw
  error.
- Health data should normalize mounted idle stdio backends as ready, matching
  `packages/sift-gateway/src/sift_gateway/health.py`.
- Frontend design should be dense and operator-focused, not a marketing page.

Acceptance:

- Operator can create additional cases from the portal after first login.
- `/` and `/portal` resolve ergonomically.
- Health/backend panels show Supabase, Gateway, worker, OpenSearch, RAG, add-ons,
  and evidence root without leaking secrets.
- Frontend build and targeted route/API tests pass; live portal smoke recorded.

## BATCH-PT2 - Portal RAG document management flow

Dependencies: BATCH-OR4; BATCH-PT1.

Scope:

- Portal frontend/backend upload and management routes.
- `packages/forensic-rag-mcp/**`
- Supabase RAG tables/functions if schema changes are required.

Exact work:

- Add an operator workflow to add, list, refresh, and retire documents in the RAG
  knowledge plane.
- Preserve the current policy: shared knowledge/reference is not case evidence.
  If case-derived RAG is proposed, it must be a separate design decision with
  evidence provenance, approval, and privacy controls.
- Expose status and provenance: source document, hash, embedding model, chunk
  count, last indexed, and query smoke.

Hints and references:

- Start from `rag-mcp-seed-pgvector` and `PgVectorRagStore`.
- Reuse existing Supabase pgvector schema where possible.
- Consider offline model cache and no-external-download mode from OR4/HR2.

Acceptance:

- Operator can add a knowledge document and query it through `kb_*` tools.
- Document provenance and embedding metadata are visible to the operator.
- No case evidence is embedded into shared knowledge by accident.

## BATCH-TLS1 - Installer certificate and trust strategy

Dependencies: BATCH-HR1; BATCH-OR3.

Scope:

- `install.sh`
- TLS generation/config files
- Gateway/portal serving config
- Operator docs and handoff output

Exact work:

- Decide and implement the certificate profile:
  Let's Encrypt for a real DNS name with reachable HTTP/DNS challenge, or an
  internal/local CA profile for lab IP-only VMs.
- Make installer handoff explicit about CA certificate location, client trust
  steps, MCP endpoint trust requirements, and renewal/rotation.
- Avoid manual hidden browser workarounds by giving the operator a documented
  trust bundle or domain-based certificate path.

Hints and references:

- Let's Encrypt generally requires a domain and an ACME challenge path; an
  IP-only libvirt VM is usually better served by an internal CA or operator
  supplied certificate.
- Existing handoff already records `ca_cert`; verify path, permissions, SANs,
  and client import steps.
- Research certbot/ACME and local CA best practices in HR1 before implementation.

Acceptance:

- Fresh install produces a trusted or clearly trustable HTTPS portal/MCP profile
  for the chosen environment.
- Renewal/replacement is documented.
- No private key material is printed to handoff or logs.

## BATCH-SB1 - Self-managed Supabase compose with generated secrets

Status: DEFERRED to after BATCH-LV1 (operator 2026-06-13). LV1 runs the
end-to-end proof first on the current Supabase CLI loopback stack with the
demo secrets accepted as documented lab posture; SB1 then replaces the CLI
stack before any non-lab deployment. SB1 no longer gates LV1.

Dependencies: BATCH-HR3. Decided in B-MVP-012 (2026-06-12); deferred 2026-06-13.

Scope:

- `scripts/setup-supabase.sh`, new compose file(s), `install.sh` Supabase
  bootstrap path, generated env files, operator docs sections 5/5.1.

Exact work:

- Replace the Supabase CLI-managed local stack with a repo-owned
  docker-compose that generates GOTRUE_JWT_SECRET, anon/service-role JWTs,
  and a random non-default Postgres password at install time.
- Preserve idempotent rerun, existing operator mapping, loopback-only binds,
  and the clone-entry installer flow.
- Provide a migration path for an existing CLI-stack VM (export/import or
  documented clean re-init) and a rotation procedure.

Acceptance:

- Fresh install runs with non-demo secrets (`iss` != supabase-demo, non-default
  DB password); `/health` ok; portal + MCP auth work end to end.
- Rerun is idempotent; rotation procedure proven once live.
- No secret values in repo, logs, or handoff beyond the designed handoff.

## BATCH-CL3 - Retire legacy file-HMAC re-auth plane

Status: BLOCKED 2026-06-13 - premise false, needs operator re-scope (B-MVP-017).
The CL3 build agent (opus) refused all three deletions with code-cited proof
(conductor independently confirmed two load-bearing facts):
- `app.audit_events` re-auth via `portal_services.record_reauth_event` is
  AUDIT-ONLY: it inserts an unconditional `status='success'` row with no
  password parameter and no verification.
- The ONLY operator-password re-auth verifier is the file-HMAC challenge
  (`_load_pw_entry`/HMAC compare) gating evidence seal/ignore/retire, commit,
  report inclusion, and case-activate; `_sync_local_reauth_password` bridges it
  to the live Supabase password on login/forced-reset.
- The legacy plane ships ENABLED: `configs/gateway.yaml.template:134`
  `portal_session_enabled: true` (defaults True in `supabase_auth.py`).
Deleting the plane removes the only password re-verify with NO replacement -> a
security regression. CL3 is therefore a build-replacement-then-delete batch, not
a delete-only cleanup. Recommended re-scope (operator decision in B-MVP-017):
  - CL3a: build a fail-closed Supabase/DB operator-password re-verification for
    the sensitive actions; flip `portal_session_enabled` to false; migrate the
    legacy-plane tests to the Supabase-envelope harness.
  - CL3b: then delete the now-dead `sift_session` middleware,
    `_sync_local_reauth_password`, the file-HMAC challenges, and the
    `verification.py`/`backup_ops.py` writers together.
Provably-dead-in-isolation (0 src callers, could land under CL3b only):
`verification.py` `rehmac_entries`/`copy_ledger_to_case`/`derive_hmac_key`,
`backup_ops.py` ledger-copy block.

Dependencies: BATCH-PT1; BATCH-HR3. Decided in B-MVP-017 (2026-06-12);
BLOCKED/re-scope pending 2026-06-13.

Scope:

- `packages/case-dashboard/**` (local re-auth bridge, sift_session middleware),
  `packages/sift-core/**` (`verification.py` writer funcs, `backup_ops.py`
  ledger copy), tests.

Exact work:

- Remove `_sync_local_reauth_password` and file-authority HMAC challenges for
  commit/evidence/report/case-activate; DB/Supabase authority becomes the only
  re-auth path with fail-closed errors.
- Remove the orphaned `sift_session` cookie verification middleware (nothing
  mints it) after confirming the test/agent harness has a replacement.
- Delete `verification.py` writer functions and the ledger copy in
  `backup_ops.py` once the last consumer is gone; drop their tests.

Acceptance:

- No file-HMAC write path remains; targeted suites green; portal sensitive
  actions still re-auth correctly under DB authority (live smoke).

## BATCH-DB1 - Adopt FORCE ROW LEVEL SECURITY on app.* tables

Status: LANDED 2026-06-13 (916f0e6): migration authored, 31/31 RLS-enabled
app.* tables FORCEd; applies at next install/LV1 (not yet live-applied).

Dependencies: none (schema-only). Decided in B-MVP-013 (2026-06-13).

Scope:

- `supabase/migrations/**` (new migration adding `FORCE ROW LEVEL SECURITY`).
- Targeted DB/policy tests; operator docs RLS note in
  `docs/operator/maintenance-guide.md` and `docs/hardening/component-audit.md`.

Exact work:

- Add a migration that runs `ALTER TABLE app.<t> FORCE ROW LEVEL SECURITY` for
  the 31 `app.*` tables that already have RLS ENABLED (HR2 verdict 2026-06-12).
- Confirm the migration is idempotent/re-runnable and ordered after the table
  and policy definitions.
- Verify the gateway path is unaffected: Supabase `service_role` carries
  `BYPASSRLS`, so FORCE changes nothing for the gateway's own queries. FORCE is
  defense-in-depth: it makes RLS apply to the table OWNER role too, so the
  several default-deny (0-policy) tables also deny owner-role direct access.

Hints and references:

- HR2 verdict source: B-MVP-013; `docs/hardening/component-audit.md` RLS section.
- Find tables: `rg -n 'enable row level security|create table app\.' supabase/migrations`.
- Do NOT add BYPASSRLS to any application role; the point is to keep the owner
  honest, not to widen access.

Acceptance:

- Every `app.*` table that has RLS ENABLED also has FORCE set (verify with a
  `pg_class.relforcerowsecurity` query, redacted output).
- Portal + MCP auth and a sensitive re-auth action still work end to end (live
  smoke under BATCH-LV1 or a scoped DB1 live check).
- Targeted suites green; both doc validators and `git diff --check` pass.

## BATCH-UN1 - Component uninstaller, remove all or selected components

Status: LANDED 2026-06-13 (c98ec90): scripts/uninstall.sh + maintenance-guide
section authored; bash -n clean, dry-run default, evidence triple-gated. Live
teardown/reinstall proof folded into the LV1 fresh-install sequence.

Dependencies: BATCH-AD2; BATCH-OR1; BATCH-OR2. Decided in B-MVP-007 (2026-06-13).

Scope:

- New script: `scripts/uninstall.sh` (or `scripts/teardown.sh`).
- Operator docs section in `docs/operator/maintenance-guide.md`.

Exact work:

- Give the operator one script that can remove ALL or a SELECTED subset of
  installed/provisioned components: add-on Docker stacks/images/volumes (OpenCTI
  ~4.4 GB, OpenSearch), the Supabase CLI stack, the staged runtime tree
  `/opt/sift-mcps`, systemd units, the service user, state under
  `/var/lib/sift`, caches under `/var/cache/sift`, auditd ruleset, AppArmor
  profile, and TLS/CA material — each behind an explicit, named flag.
- Default to an interactive menu plus non-interactive flags (e.g.
  `--components opencti,opensearch` / `--all`). Dry-run by default; require an
  explicit `--yes`/`--i-understand` to actually delete.
- NEVER delete evidence under `/cases` unless an explicit, separately-named and
  double-confirmed flag is given; treat evidence as the highest blast radius.
- Keep core and add-on teardown separable: removing OpenCTI must not disturb the
  SPG core; `--all` is the only path that tears core down.

Hints and references:

- Provisioning sources to mirror in reverse: `install.sh` (staging, units,
  service user, auditd, AppArmor, TLS), `scripts/setup-supabase.sh`,
  `scripts/setup-addon.sh`, OpenCTI/OpenSearch compose under `configs/**`.
- Add-on image lifecycle is the B-MVP-007 driver: ~4.4 GB of OpenCTI images sit
  unused on the core VM; this is the supported way to reclaim them.
- Mark every destructive branch clearly; print exactly what will be removed in
  the dry-run before any deletion.

Acceptance:

- `--components` removes only the named add-on resources; core stays `/health`
  ok and both services active afterward.
- `--all` cleanly removes the install; a fresh `./install.sh` then succeeds.
- Dry-run lists targets without deleting; deletion requires explicit
  confirmation; evidence under `/cases` is never removed without its own flag.
- `bash -n` clean; live teardown/reinstall proof recorded in Session-Notes.

## BATCH-RG1 - Regenerate documentation modernization pass

Status: LANDED 2026-06-13 (245322a): 15 docs/regenerate files modernized vs
current code + the new operator/hardening/add-on docs; new
docs/regenerate/README.md fact-ownership index. Promotion recommendations
(interaction-model, api-contracts, mcp-contracts kb_* surface, matrix-comparison)
captured in that index for a later operator/docs pass.

Dependencies: BATCH-OR2; BATCH-OR3; BATCH-OR4; BATCH-AD1; BATCH-HR2.

Scope:

- `docs/regenerate/**`
- Optional promotion into `docs/operator/**`, `docs/hardening/**`,
  `docs/add-ons/**`, and `docs/inventory/**`.

Exact work:

- Revalidate every obsolete first-phase document under `docs/regenerate/**`
  against current code, live VM facts, and the new operator docs.
- Delete, replace, or mark stale sections about removed tools, old authority,
  Chroma-default RAG, `rag_search_case`, native OpenCTI, Windows triage as core,
  old service paths, and pre-migration file-state ownership.
- Produce a concise docs index that tells future agents which document owns each
  fact and which docs are archival only.

Hints and references:

- Current docs with known stale content:
  `mcp-contracts.md`, `data-flows-and-lifecycles.md`,
  `known-limitations-and-improvements.md`, `matrix-comparison.md`,
  `backend-contract.md`, `security-architecture.md`, and
  `code-structure.md`.
- Do not duplicate the same fact in five places. Prefer one authoritative doc
  plus links from overview docs.

Acceptance:

- `docs/regenerate/**` no longer contradicts the current core/add-on split,
  Supabase authority, RAG pgvector path, or live installer behavior.
- New docs index explains active vs archival status.
- Validators and `git diff --check` pass.

## BATCH-LV1 - End-to-end live VM validation and Rocba proof

Dependencies: BATCH-OR3; BATCH-HR3; BATCH-AD2; BATCH-PT1; BATCH-TLS1; BATCH-DB1.
(BATCH-SB1 deferred to after LV1 per operator 2026-06-13: the end-to-end proof
runs on the current Supabase CLI loopback stack with demo secrets accepted as
documented lab posture. BATCH-CL3 is BLOCKED/re-scope pending 2026-06-13: the
file-HMAC re-auth plane currently WORKS, so LV1 can proceed on it; whether LV1
waits for the CL3 re-scope is an open operator decision in B-MVP-017.)

Scope:

- Live VM only plus `docs/migration/Session-Notes.md` closeout.
- Any tiny source fix discovered during the proof gets its own scoped patch and
  targeted tests before rerun.

Exact work:

- Fresh or cleaned VM install from clone-entry `./install.sh`.
- Portal: sign in, forced reset if required, create/activate case, issue
  agent/service credential with expected scopes.
- MCP: run initialize/tools/list and prove `opensearch_*` and `kb_*` tools are
  present and callable through Gateway.
- Evidence: register and seal Rocba disk and memory evidence, then run the
  intended agent investigation path through MCP only.
- Search/reference: prove OpenSearch health, Hayabusa index/query path, RAG
  `kb_*` query path, and report/export custody controls.
- B-MVP-019 (folded in, operator 2026-06-13): when the first real add-on
  launches under the hardened gateway, derive setup-addon.sh
  `command`/`--project`/`manifest_path` from the staged `/opt/sift-mcps` tree
  (operator-home paths are invisible under ProtectHome=tmpfs). Scoped patch +
  targeted test before rerun.

Hints and references:

- Use the portal-generated agent/service credential; an operator Supabase login
  token should not authenticate to MCP.
- Current live proof gap from 2026-06-12 is exactly the agent credential step.
- Record sanitized command-level evidence: no raw tokens, DSNs, JWTs, passwords,
  private keys, or full case paths.

Acceptance:

- Fresh install is `status=ok`.
- Services remain active after reboot/restart.
- Aggregate MCP lists and executes OpenSearch/RAG tools.
- Rocba run either completes or records precise blockers with severity and owner
  batch.
- `Session-Notes.md` contains command-level proof and next actions.
