# State Authority Map: File-State vs Database-Authority

Status: BATCH-OR2 discovery map. Ground truth as of the code in this checkout.
Scope: classify every mutable system fact, name the object that owns truth, and
map every remaining file-backed JSON/YAML/ledger/audit/log/reference path either
to the DB object that owns it or to a justification for why the file remains
authority. Every claim cites code (`path:line`). No VM access was used.

## How To Read This Map

Authority classes used in the tables:

- **db** - Supabase/Postgres `app.*` table/RPC is the single source of truth.
- **file** - a file on disk is still the source of truth (each one is justified
  below with a follow-up batch or an accepted reason).
- **file-mirror** - the DB is authority; a file copy is written for export,
  proof, or legacy-parser compatibility and is explicitly labelled so a stale
  mirror cannot masquerade as truth.
- **derived** - rebuildable from authoritative state (search index, embeddings).
- **export/proof** - non-authoritative artifact produced for offline custody
  verification.
- **secret/config** - credentials, keys, or deployment config.
- **cache** - performance-only; safe to drop and recompute.
- **legacy/obsolete** - retained only for cleanup, export, or pre-migration
  parser/test compatibility; never an active non-DB authority fallback.

The deployment runs **DB-active** (Supabase is the control plane). The driving
flag is `db_authority_active()` in
`packages/sift-core/src/sift_core/active_case_context.py:96`; in DB-active mode
the core resolvers fail closed to the request/worker `AuthorityContext` instead
of reading env or pointer files
(`packages/sift-core/src/sift_core/active_case_context.py:29-50,96-111`). A
legacy file path may still exist for cleanup, export, or compatibility, but it
does not become authority when Postgres is unavailable; active workflows fail
closed.

## Master Authority Table

| State / fact | Authority | DB object | File mirror or cache | Writer | Reader | Maintenance command | Backup/restore note | Migration status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Case lifecycle + metadata | db | `app.cases` (`status`, `case_key`, `legacy_case_dir`, `metadata`) `supabase/migrations/202606070101_identity_foundation.sql:24` | `CASE.yaml` legacy mirror only (`case_io.py`); `compat_export_status='stale'` flags it | Gateway `ActiveCaseService.create_case/update_case_metadata` `active_case.py:236,336` | Portal/agents via Gateway; `ActiveCaseService.get_case_metadata` `active_case.py:166` | reset via Supabase; cases edited through portal REST | Postgres dump (Supabase). `CASE.yaml` not authoritative | migrated; `CASE.yaml` legacy/file-mirror |
| Active case pointer | db | `app.active_case_state` (scope=`deployment`) `202606070101_identity_foundation.sql:67`; read view `app.deployment_active_case` `202606070400_active_case_authority.sql:13` | legacy `~/.sift/active_case` may remain for compatibility but is never an authority fallback | `ActiveCaseService._set_active_case_cur` `active_case.py:455` (upsert on `scope`) | `ActiveCaseService.get_active_case` `active_case.py:147` | set via operator Portal activation (re-auth gated) | Postgres dump | migrated; pointer file obsolete |
| Case membership + roles | db | `app.case_members` `202606070101_identity_foundation.sql:50` | none | Gateway (case create / member mgmt) | RLS-scoped reads `active_case.py:202-213,431-444` | portal operator admin | Postgres dump | migrated |
| Operator identity + system role | db | `app.operator_profiles` (`status`, `system_role`, `auth_user_id`) `202606070101_identity_foundation.sql:9`; role col `202606070300_unified_jwt_principals.sql:28` | none; credentials live in Supabase Auth, not `app.*` | Supabase Auth + installer mapping | Gateway `supabase_auth.py` principal resolve | reset password via Supabase Auth path | Supabase Auth dump | migrated |
| Operator password + re-auth credential | db (Supabase Auth/GoTrue) | Supabase `auth.users`; `app.operator_profiles.auth_user_id` binds the operator principal | retired `/var/lib/sift/passwords/examiner.json` may remain after upgrade but is never read as a fallback | Supabase Auth/admin bootstrap | Gateway resolves the signed-in identity and calls GoTrue password re-verification | rotate/reset only through Supabase Auth | Supabase Auth dump; do not back up the retired password file as credential authority | migrated; Supabase-only, fail closed |
| Agent + service identities | db | `app.agents`, `app.service_identities` `202606070101_identity_foundation.sql:83,97` | none | Gateway credential issuance (re-auth gated) | Gateway principal resolve | issue/revoke via portal/MCP | Postgres dump | migrated |
| MCP/service credential + scope authority | db (Supabase JWT + `app.*`) | `app.agents`, `app.service_identities`, `app.principal_tool_scopes`; Supabase-issued JWT subject binds the principal | none; raw credentials are not stored, and `gateway.yaml` static tokens/PR02 tokens are not authentication fallbacks | Gateway/Supabase credential issuance (re-auth gated) | Gateway JWT verification + DB principal/scope resolution | issue/revoke via operator Portal workflow | Postgres/Supabase dump; deployment secrets remain outside repo | migrated under SEC-6; scoped DB authority, fail closed |
| Per-principal MCP tool scopes | db | `app.principal_tool_scopes` `202606070300_unified_jwt_principals.sql:46`; legacy `app.mcp_token_scopes` `202606070101_identity_foundation.sql:162` | none | Gateway credential issuance | Gateway policy middleware | manage via credential issuance | Postgres dump | migrated (unified JWT) |
| Portal / agent auth session | db (Supabase Auth) | Supabase Auth `auth.users` + issued JWT; principal mapped via `app.operator_profiles.auth_user_id` | none server-side; token material is in-memory only `supabase_auth.py:307` | Supabase Auth `password_grant` `supabase_auth.py:1043` | Gateway JWT validation | logout = Supabase session revoke / user delete `supabase_auth.py:331,488` | Supabase Auth dump | migrated; no file-backed session store |
| Audit log (tool calls, identity, custody) | db | `app.audit_events` `202606070101_identity_foundation.sql:136` | per-case `audit/*.jsonl` is **file-mirror**, labelled `legacy-file-mirror` vs `db-audit-events` `audit_ops.py:70-117` | Gateway `DbAuditWriter` `audit_helpers.py:81`; required-write raises `AuditPersistError` | portal/agents via Gateway summaries | n/a (append-only) | Postgres dump; JSONL mirror is local proof copy | migrated (BATCH-K1/K6); JSONL = file-mirror |
| Examiner approval decisions | db | reflected in `app.investigation_*` approval cols + `app.audit_events` | `approvals.jsonl` per-case append-only `case_io.py:354-415`, `audit_ops.py` | core `case_io`/`audit_ops` | reporting verification | n/a | Postgres dump; JSONL = local proof | migrated; JSONL = export/proof |
| Evidence registry + seal status | db | `app.evidence_objects` (`status`, `seal_status`, `current_sha256`); `app.evidence_chain_heads` (`seal_status`, `head_hash`) | current compatibility manifest export is unsigned and non-authoritative | durable `app.custody_operations` begin/resume + verified commit RPCs; historical one-shot `app.evidence_seal` remains migration ancestry only | `app.evidence_gate_status` + Gateway read-only reconciliation | Add/Seal and recovery via re-auth-gated Portal operations | Postgres dump; compatibility manifest is not independent proof | migrated to durable custody operations |
| Evidence custody ledger (hash chain) | db | `app.evidence_custody_events` append-only, per-case `prev_hash`/`event_hash`; mutation/TRUNCATE blocked | current JSONL compatibility export is unsigned and non-authoritative; retired HMAC JSONL is historical | current verified custody-operation commit RPCs append canonical events atomically; direct `app.evidence_append_custody_event` is a historical low-level predecessor, not an operator workflow | Gateway custody/history services | n/a (append-only) | Postgres dump is current authority | migrated; current chain is Postgres-only |
| Evidence per-version snapshots | db | `app.evidence_versions` append-only and linked to `custody_operation_id` | unsigned compatibility manifest version export | verified custody-operation commit RPCs | gate/reporting/history | n/a | Postgres dump | migrated to durable custody operations |
| Evidence proof exports | current compatibility export; future signed proof | `app.evidence_proof_exports` currently stores non-authoritative export metadata | current manifest/ledger/anchor compatibility bundles are unsigned and must not be represented as court-verifiable signed proof | current compatibility export path only | current bundle consumers; **P4.23.6** adds detached signatures plus the supported offline verifier | export via operator Portal workflow | preserve Postgres authority; archive future detached signed proof with its verification material | P4.23.6 signed proof/offline verifier not yet represented by the legacy bundle |
| Investigation findings | db | `app.investigation_findings` (`status`, `content_hash`) `202606081500_report_metadata.sql:12` | `findings.json` = file-mirror/export in DB-active `case_io.py`, `investigation_store.py:7` | `PostgresInvestigationStore.upsert_finding/apply_review` `investigation_store.py:321,463` | `report_inputs()` approved-only `:614` | manage via portal/MCP (approve = re-auth) | Postgres dump | migrated (BATCH-K2); JSON = mirror |
| Investigation timeline events | db | `app.investigation_timeline_events` `202606081500_report_metadata.sql:31` | `timeline.json` = file-mirror/export | `PostgresInvestigationStore` `investigation_store.py` | reporting (approved only) | portal/MCP | Postgres dump | migrated; JSON = mirror |
| Investigation IOCs | db | `app.investigation_iocs` (`content_hash` added `202606081602`) `202606081500_report_metadata.sql:50` | `iocs.json` = file-mirror/export | `PostgresInvestigationStore` | reporting | portal/MCP | Postgres dump | migrated; JSON = mirror |
| Investigation TODOs | db | `app.investigation_todos` `202606081500_report_metadata.sql:70` | `todos.json` = file-mirror | `PostgresInvestigationStore` | portal | portal/MCP | Postgres dump | migrated; JSON = mirror |
| Content-hash (approval guard) | db | `content_hash` columns on `app.investigation_*` | none (single impl) | `compute_content_hash` `investigation_store.py:186` (BATCH-NW1 single authority) | reporting reconcile (DB) `reporting.py:696-723` | n/a | Postgres dump | migrated (NW1 consolidation) |
| Report metadata + export provenance | db | `app.report_metadata` (`status`, `seal_status`, `manifest_hash`, `chain_head_hash`, `exported`) `202606081500_report_metadata.sql:89` | generated report files (PDF/MD) = export artifacts | core `reporting.py` + portal | portal Reports tab | generate/export via portal (re-auth gated) | Postgres dump; report files are exports | migrated |
| Investigation content verification | db | `content_hash` in `app.investigation_*`, reconciled by `reconcile_verification_db` `reporting.py:696-723` | `/var/lib/sift/verification/{case_id}.jsonl` is a retired legacy format, not a runtime fallback | DB investigation writes + `reconcile_verification_db` | DB reconciliation only | n/a | Postgres dump | migrated; legacy file path may be removed during cleanup |
| Durable jobs (ingest/enrich/report/run_command) | db | `app.jobs` (+`job_steps`,`job_logs`,`worker_heartbeats`) `202606081200_durable_jobs.sql:38`; sanitized read `app.job_status_public` `:535` | none (no external queue, no job file/sqlite) | `app.enqueue_job` `:170`; `app.claim_next_job` FOR UPDATE SKIP LOCKED `:215`; `JobWorker` `execute/job_worker.py:211` | portal/agents via `job_status_public` | restart `sift-job-worker.service`; `app.expire_stale_jobs()` reclaims leases `:415` | Postgres dump | migrated (BATCH-D1); fully DB |
| Worker liveness | db | `app.worker_heartbeats` `202606081200_durable_jobs.sql:146` | none | `app.worker_heartbeat` `:507` | `app.expire_stale_jobs` | restart worker service | Postgres dump | migrated |
| OpenSearch indices (search plane) | derived | registry `app.opensearch_indices` `202606081300_opensearch_provenance.sql:27`; provenance `app.opensearch_ingest_provenance` `:80` | OpenSearch index data in Docker volume | `app.register_opensearch_index` `:114`; ingest job adapter | portal/agent via `app.opensearch_index_coverage` `:205` | rebuild by re-running ingest; reindex | Docker volume snapshot OR rebuild from sealed evidence | derived/rebuildable; registry+provenance are DB |
| Ingest/enrich status | db (DB-active) | `app.opensearch_ingest_status` `202606081601_host_identity.sql:156` + `app.job_status_public` | `~/.sift/ingest-status/*.json` is parser-compat/debug only `opensearch-mcp/host_identity_db.py:1-4` | ingest adapters write provenance to DB | portal/agent poll `opensearch_ingest_status` | poll status tools | Postgres dump | migrated (BATCH-K4); JSON = debug-only |
| Host-identity decisions/corrections | db | `app.host_identity_decisions` append-only ledger `202606081601_host_identity.sql:38`; `app.record_host_identity_decision` `:103` | `<case>/host-dictionary.yaml` = parser-compat/debug only `opensearch-mcp/server.py:4008`, `ingest_cli.py:49`, backend manifest note `opensearch-mcp/sift-backend.json:13` | ingest adapter / operator correction | OpenSearch ingest naming | n/a | Postgres dump | migrated (BATCH-K4); YAML = debug-only |
| RAG knowledge chunks/embeddings | db | `app.rag_chunks`/`rag_documents`/`rag_collections` (knowledge-only) `202606081400_rag_pgvector.sql:155,97,56`; ANN ivfflat index | none (embeddings in Postgres pgvector) | `app.rag_upsert_chunk` (service-only) `:264`; embedder job | `app.rag_search` (6-arg, kind='knowledge' hard-coded) `202606111200_rag_knowledge_only.sql:41`; `app.rag_chunk_public` view | re-embed via RAG ingest; reindex pgvector | Postgres dump (vectors included) | migrated; knowledge-only enforced by trigger `_block_derived_rag_insert` `202606111200:147`; derived RAG **rejected** (B-MVP-RAG-DERIVED) |
| MCP backend registry (incl. add-on registration) | db | `app.mcp_backends` (`name`,`namespace`,`transport`,`enabled`,`connection` non-secret, `manifest_sha256`,`health_status`) `202606070500_mcp_backends_registry.sql:9` | per-add-on `sift-backend.json` manifest in repo (source manifest, validated then hashed into DB) | `mcp_backends_registry.py`; `scripts/setup-addon.sh` writes register payloads `$SIFT_HOME/addon-register/*.json` | Gateway backend mounting + `/health` | register add-on via `scripts/setup-addon.sh`; `systemctl restart sift-gateway` | Postgres dump; manifests in repo/checkout | migrated (D22A); raw secrets rejected by CHECK + validators `202606080100_mcp_backends_registry_hardening.sql:8-83` |
| Backend health status | db | `app.mcp_backends.health_status` | none | Gateway health probe `health.py` | `/health` endpoint | `curl -sk https://127.0.0.1:4508/health` | n/a (recomputed) | migrated |
| Tool catalog / artifact knowledge | file (reference) | none (static reference data) | `packages/sift-core/data/catalog/*.yaml`, `packages/forensic-knowledge/data/**` (artifacts, tools) | shipped in repo | core tool dispatch / forensic-knowledge MCP | update via repo, reinstall | in git; reference symlinked to `/var/lib/sift/enrichment/forensic-knowledge` `install.sh:636` | **accepted file authority** - static reference data, versioned in repo (FORK-3) |
| OpenSearch index mappings/templates | file (reference) | none | `packages/opensearch-mcp/src/opensearch_mcp/mappings/*.json`, `reduced_*.yaml` | shipped in repo | opensearch-mcp ingest | update via repo | in git | accepted file authority - static reference |
| Backend manifest schema | file (reference) | none | `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json` | shipped in repo | manifest validation | update via repo | in git | accepted file authority - schema contract |
| Gateway runtime config | secret/config | none | `/var/lib/sift/.sift/gateway.yaml` (0600) `install.sh:1685` | installer `write_gateway_config` | Gateway startup `config.py` | edit + restart gateway service | back up `/var/lib/sift/.sift/` (0700) | deployment config only; static-token/PBKDF2 entries do not authenticate under SEC-6 |
| Supabase credentials | secret/config | none | `/var/lib/sift/.sift/supabase.env` (0600) `install.sh:1405`; `~/.sift/supabase-project/sift-supabase.env` `setup-supabase.sh:296` | installer | Gateway/worker env | rotate via Supabase, rewrite env | back up `.sift/` securely | secret env; never commit values |
| Control-plane DSN + token pepper | secret/config | none | `/var/lib/sift/.sift/control-plane.env` (0600) `install.sh:1521` | installer `write_control_plane_env` | Gateway/worker DB connect, token hashing | rotate DSN/pepper, rewrite env | back up `.sift/` securely | secret env |
| TLS CA + gateway cert/key | secret/config | none | `/var/lib/sift/.sift/tls/{ca,gateway}-{key,cert}.pem` `install.sh:862-865` (keys 0600) | installer `generate_tls` | Gateway TLS listener | regenerate via installer / BATCH-TLS1 | back up keys securely | self-signed lab CA; profile open in B-MVP-001/BATCH-TLS1 |
| OpenSearch client credentials | secret/config | none | `/var/lib/sift/.sift/opensearch.yaml` (0600) `install.sh:1813`; `opensearch.env` `:1839` | installer | opensearch-mcp client | rotate OS creds, rewrite | back up `.sift/` | default admin/admin lab posture (B-MVP-005) |
| OpenCTI secrets (add-on, optional) | secret/config | none | `/var/lib/sift/.sift/opencti-{stack,shared,connectors}.env` (root `0600`) plus `opencti-query.env` (sift-service `0600`) | `provision-opencti-shared-target.sh` + identity provisioners | OpenCTI stack and query-only gateway child | regenerate via `setup-addon.sh opencti --provision` | back up `.sift/` if add-on used | external add-on; raw secrets never enter the registry payload |
| Installer handoff (temp creds) | secret/config | none | `/var/lib/sift/tokens/installer-handoff.txt` (0600) `install.sh:2425` | installer `write_handoff` | operator first-login | reset password; file becomes stale post-reset | back up `tokens/` (0700) | temporary; password not recoverable from docs after reset |
| Add-on register payloads | file (transient) | DB target = `app.mcp_backends` after registration | `$SIFT_HOME/addon-register/*.json` `setup-addon.sh:88,190` | `scripts/setup-addon.sh` | registration step | re-run `setup-addon.sh` | regenerated by installer | transient payload; authority lands in DB |
| Hayabusa binary + rules | file (reference/tool) | none | `/var/lib/sift/.sift/bin/hayabusa`, `hayabusa-rules/` `install.sh:791,796` | installer `install_hayabusa` | detection runs | reinstall / update rules | re-fetched by installer | accepted file authority - tool + rules (B-MVP-004 download policy) |
| Volatility symbol cache | cache | none | `/var/cache/sift/volatility-symbols` (2775, group `sift`) `install.sh:502` | vol3 runtime | vol3 runtime | safe to delete; recomputed | not backed up (cache) | cache only |
| Evidence bytes / case tree | file (operator-managed) | `app.evidence_objects` holds metadata + hash, not bytes | `/cases/*` evidence files `install.sh:487` | operator mounts/copies on VM | analysis tools (read-only after seal) | operator-managed; immutable `+i` on seal is the write-protection boundary (`evidence_posture.py`) | **bytes backed up by operator out-of-band**; DB holds sealed hashes | by design: evidence bytes are file, DB owns custody/hash (FORK-4) |
| Forensic snapshots | file (operator) | none | `/var/lib/sift/snapshots` (owner 1000:1000) `install.sh:485` | operator/tools | analysis | operator-managed | operator backup | accepted file authority - operator artifacts |
| Python venv + runtime checkout | derived | none | `$REPO/.venv`, `/opt/sift-mcps` `install.sh:74,397` | installer `uv sync` | services | rebuild via `uv sync` / reinstall | rebuildable from repo | derived; not backed up |
| Supabase CLI project state (Docker) | secret/config + data | Postgres itself | `$REPO/supabase/.supabase` (Docker volumes) `setup-supabase.sh:241` | `supabase start` | Supabase stack | manage via Supabase CLI | **Postgres volume is the primary backup target** | the DB data plane |

## File Authority and Retired Lookalikes

These are the only items where a file (not the DB) is still authoritative in the
live deployment, or where a file holds truth that the DB intentionally does not.
The first two legacy paths below may still exist on upgraded installs, but they
are explicitly **not** file-authoritative and are listed only to prevent them
being mistaken for a fallback.

1. **Retired examiner password file** - `/var/lib/sift/passwords/examiner.json`
   (PBKDF2) may remain for cleanup compatibility. Active Portal login and
   sensitive-action re-auth both require Supabase; there is no local fallback.

2. **Retired post-approval HMAC verification ledger** -
   `/var/lib/sift/verification/{case_id}.jsonl` `verification.py:18`. In DB-active
   mode the authoritative reconciliation is `content_hash` in
   `app.investigation_*` via `reconcile_verification_db`
   `reporting.py:696-723`; the JSONL path (`reconcile_verification`
   `reporting.py:726-801`) is legacy compatibility code, not an active runtime
   fallback. It may be removed during legacy cleanup; Postgres remains the sole
   investigation verification authority.

3. **Static reference data** - tool catalogs
   (`packages/sift-core/data/catalog/*.yaml`), forensic-knowledge artifact/tool
   YAML (`packages/forensic-knowledge/data/**`), OpenSearch mappings/templates
   (`packages/opensearch-mcp/.../mappings/*.json`), and the backend manifest
   schema (`sift-backend.schema.json`). **Justification (accepted):** these are
   immutable, versioned reference data shipped in the repo and updated via
   git/reinstall, not mutable runtime state. They correctly remain file
   authority; no DB migration is warranted. FORK-3 only if the conductor wants
   them formally declared out-of-scope for DB authority.

4. **Evidence bytes and the `/cases/*` tree** `install.sh:487`. **Justification
   (accepted, by architecture):** evidence bytes are operator-mounted/copied on
   the SIFT VM (per the architecture invariants); the DB owns custody metadata
   and sealed hashes (`app.evidence_objects.current_sha256`,
   `app.evidence_chain_heads.head_hash`) but never the bytes. Forensic snapshots
   (`/var/lib/sift/snapshots`) are similarly operator-managed file artifacts.
   FORK-4 only if the conductor wants the backup/restore contract for evidence
   bytes documented explicitly (it is currently out-of-band/operator
   responsibility).

5. **Secrets/config files** under `/var/lib/sift/.sift/**`, `~/.sift/**`, and
   `/var/lib/sift/{tokens,passwords}/**`. **Justification (accepted):** secrets
   and deployment config must live as protected files (0600/0700) outside the
   DB; the DB stores only references/hashes, never raw secret material
   (`app.mcp_backends` no-raw-secret CHECK
   `202606070500_mcp_backends_registry.sql`). Certificate posture is open in
   B-MVP-001 / BATCH-TLS1; download policy in B-MVP-004.

6. **Tooling/cache/derived files** - Hayabusa binary+rules, Volatility symbol
   cache, `.venv`, `/opt/sift-mcps` checkout, Docker volumes. **Justification
   (accepted):** tools and caches are rebuildable/reinstallable and are not
   mutable system-of-record state.

7. **File mirrors / compatibility exports** - `CASE.yaml`,
   `findings/timeline/iocs/todos.json`, `approvals.jsonl`,
   per-case `audit/*.jsonl`. **Justification (accepted, not authority):** these
   are written from DB authority for legacy-parser/export compatibility and are
   explicitly labelled (`legacy-file-mirror` vs `db-audit-events` in
   `audit_ops.py:112-116`). They are unsigned and non-authoritative; they are not
   the detached signed proof/offline-verifier contract added by P4.23.6.

8. **Parser-compatibility/debug files** - `<case>/host-dictionary.yaml` and
   `~/.sift/ingest-status/*.json`. **Justification (accepted, not authority):**
   `opensearch-mcp/sift-backend.json:13` and `server.py:4008` state these are
   "parser-compatibility/debug artifacts only and cannot change DB authority";
   DB authority is `app.host_identity_decisions` and
   `app.opensearch_ingest_status` (BATCH-K4).

## Documentation Reconciliation Status

The former `docs/regenerate/**` cleanup queue is complete. Current operational
documents live under `docs/drafts/**`, `docs/latest/**`, and `docs/architecture/**`
and consistently identify Postgres as authority. Retained pre-migration evidence
and hardening documents are explicitly historical; their HMAC/file-ledger model
must not be used as current runtime guidance. Compatibility filenames and the
retired file-custody endpoints do not confer authority.

## Historical Authority Questions and Current Resolutions

- **FORK-1 (resolved):** Supabase Auth is mandatory. The local PBKDF2
  `examiner.json` path is not a Portal login or re-auth fallback.
- **FORK-2 (resolved):** The file-mode HMAC verification ledger is retired as
  runtime authority. DB `content_hash` reconciliation is authoritative; any
  retained file format is cleanup/export compatibility only.
- **FORK-3 (reference data):** Formally declare static reference data (catalogs,
  forensic-knowledge YAML, OS mappings, manifest schema) as intentionally file-
  authoritative and out of DB-authority scope?
- **FORK-4 (evidence-byte backup):** Document an explicit backup/restore contract
  for operator-managed evidence bytes (`/cases/*`) and snapshots, since the DB
  holds only hashes/metadata.

## Requires Live Deployment Readback

- The exact contents of the live AppArmor profile and auditd rules vs the
  pre-migration regenerate docs - the installer generates them
  (`install.sh:2464,2487`) but the rendered files live on the VM.
