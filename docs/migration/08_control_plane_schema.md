# Control Plane Schema Design

Last updated: 2026-06-07.

Scope: planning only. This document translates the agreed migration
architecture into a practical initial Supabase/Postgres control-plane schema
design. It does not create SQL migrations, modify application code, refactor
REST APIs, MCP tools, frontend views, OpenSearch, evidence, or worker code, and
it does not introduce Redis, RQ, Celery, Temporal, or any external queue.

Several schema choices below were initial recommendations and have now been
**locked** by `00_migration_charter.md` "Confirmed Decisions (Locked)". The
relevant locks for this document:

- D10: UUID primary keys plus explicit legacy text keys (`case_key`,
  `legacy_case_id`). Locked.
- D11: tables live in an `app` schema (RLS) plus an `internal`/`svc` schema for
  service-only helpers. Locked. The "place everything in `public`" alternative
  is rejected.
- D12: privileged writes go through Gateway/worker service-role paths; RLS
  protects human reads and a small set of explicitly safe human writes; the
  browser never writes authoritative state directly and never talks to a backend
  or OpenSearch directly.
- D13: lean job core (`jobs`, `job_steps`, `job_logs`, `workers`).
  `job_attempts`, `job_cancellations`, `worker_heartbeats` are deferred.
- D6: OpenSearch 3.5.0 with security enabled is the canonical profile for the
  index registry and indexing-status tables.
- D14/D15: TODOs, IOCs, evidence anchoring, RAG collections, and agent skills are
  first-class tables, not deferred or hand-waved.
- D30: Supabase-issued JWTs are the final credential for humans, AI agents, MCP
  clients, workers, and services. Existing `mcp_tokens`/`mcp_token_scopes`
  schema from PR01/PR02 remains a transitional compatibility bridge and/or
  non-secret issuance/provenance surface until ID-6.

Where a row below still says "needs approval", it is now superseded by the
charter lock; the charter wins.

## 1. Executive Summary

The schema purpose is to make Supabase/Postgres the authoritative control plane
for SIFT while preserving the current evidence vault and file-backed migration
compatibility during the transition.

Target responsibilities:

- Supabase/Postgres is authoritative for case lifecycle, memberships,
  operator/agent/service identity records, token registry state, evidence
  metadata, integrity status, audit, approvals, findings review state, reports,
  durable jobs, job steps/logs, workers, parser lineage, and OpenSearch indexing
  status.
- OpenSearch remains the core search/data plane for derived searchable forensic
  data, including parsed artifacts, timeline records, IOCs, full-text records,
  aggregations, and future vector search. It is not authority for jobs,
  evidence, audit, approvals, case lifecycle, or token validity.
- The Evidence Vault remains immutable evidence storage. Postgres stores
  metadata, hashes, provenance, integrity status, and references, not mutable
  raw evidence blobs.
- The Gateway enforces policy and writes authoritative state through service
  paths. In the final target it validates Supabase JWTs for human, agent, MCP,
  worker, and service principals before mutating privileged state.
- Frontend human access uses Supabase Auth and RLS where appropriate, plus
  Gateway REST APIs for privileged or policy-heavy actions.
- MCP/service clients use Supabase JWTs in the final target; PR02
  Gateway-issued token registry records are a cutover bridge.
- Workers claim durable jobs from Postgres and write execution state, parser
  lineage, indexing status, logs, and audit events back to Postgres.
- The initial schema should be additive and migration-friendly. Current files,
  manifests, ledgers, ingest status, and saved artifacts should remain
  compatible until DB-backed equivalents are tested.

## 2. Schema Design Principles

- Additive before destructive.
- Preserve existing file and evidence behavior during transition.
- Store no plaintext MCP/service tokens while the PR02 bridge exists; target
  credentials are Supabase JWT sessions, with app principal/scope metadata in
  Postgres.
- Keep frontend UI state out of forensic authority.
- Keep OpenSearch out of case, job, evidence, approval, and audit authority.
- Put `case_id` on every case-scoped table.
- Use `created_at` and `updated_at` where they help with ordering,
  synchronization, or compatibility exports.
- Keep audit append-only where possible.
- Treat raw evidence as immutable. Evidence metadata can change status, but the
  raw vault object cannot become mutable.
- Use explicit status values through enums or check constraints.
- Use idempotency keys for durable jobs, parser runs, ingest batches, indexing
  attempts, and repeatable evidence operations.
- Use service-role writes for privileged paths such as token issuance,
  evidence integrity mutation, audit append, job lifecycle transitions, worker
  claims, and indexing metadata.
- Use RLS for human/operator-facing reads and safe writes.
- Keep MCP/agent access indirect through Gateway. Agents do not receive direct
  Postgres write access.
- Store compatibility metadata for current JSON/file-backed sources, including
  legacy case IDs, paths, manifest references, ledger references, ingest status
  files, audit JSONL files, and exported report artifacts.
- Prefer one authoritative write plus generated compatibility export over
  uncontrolled dual-write.

## 3. Proposed Schemas And Namespaces

Initial recommendation, pending user approval:

| Schema or namespace | Purpose | Visibility |
| --- | --- | --- |
| `auth` | Supabase Auth users and sessions. | Managed by Supabase. Human frontend identity only. |
| `app` | Core control-plane tables: cases, memberships, evidence metadata, findings, reports, jobs, parser lineage, OpenSearch registry, and audit. | RLS-enabled. Gateway and worker service roles can write through service paths. Human frontend users can read safe rows through RLS and write only explicitly safe records. |
| `internal` or `svc` | Service-only helper tables/functions if needed, such as token validation helpers, worker claim functions, compatibility export bookkeeping, and policy helpers. | Not directly exposed to frontend clients. Gateway and worker service roles only. |
| `public` | Optional frontend-safe views if the project prefers keeping Supabase exposed schemas simple. | Read-only or narrowly writable views, never raw privileged tables. |

Locked (D11): use `app` (RLS) plus `internal`/`svc` (service-only). The
"everything in `public`" alternative is rejected. Supabase-managed `auth`
remains the human identity source.

Access model:

- Human frontend users: authenticate through Supabase Auth. They may read
  case-scoped safe views/tables through RLS based on `case_members`. They should
  call Gateway for privileged actions such as evidence state changes, token
  issuance, job creation/cancel/retry, approvals, exports, archive, and any
  operation requiring audit policy.
- Gateway service role: can write authoritative state after enforcing auth,
  case scope, token scope, approval gates, and audit policy.
- Worker service role: can claim jobs, heartbeat, write job steps/logs,
  parser runs, parser outputs, ingest batches, OpenSearch indexing status, and
  execution audit events for claimed jobs.
- MCP/agent clients: no direct Postgres access. They interact through Gateway
  MCP tools and receive case-scoped, tool-scoped responses.

## 4. Core Identity And Authorization Tables

Key convention (locked, D10): use UUID primary keys for new DB records and keep
legacy string IDs in explicit columns such as `case_key` or `legacy_case_id`.
This avoids making current directory names the permanent DB primary key while
preserving compatibility.

### `operator_profiles`

| Detail | Design |
| --- | --- |
| Purpose | Human operator profile linked to Supabase Auth. Stores display and local migration metadata, not credentials. |
| Key columns | `id uuid`, `auth_user_id uuid`, `display_name text`, `email text`, `status text`, `default_case_id uuid null`, `created_at`, `updated_at`, `legacy_examiner_id text null`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `auth_user_id` references `auth.users(id)`. `default_case_id` references `cases(id)` when used. |
| Indexes | Unique `auth_user_id`; optional unique lower-case email where policy allows; `status`; `default_case_id`. |
| Uniqueness constraints | One profile per Supabase Auth user. |
| Status values | `active`, `disabled`, `invited`, `archived`. |
| RLS/security notes | Users can read their own profile. Case leads/admins can read case member profiles through joins or safe views. Service role writes profile lifecycle. |
| Who can read | The operator, authorized case members through safe views, Gateway service role. |
| Who can write | Gateway/admin service path; limited self-profile fields may be safe for human writes if approved. |
| Migration source | Current portal examiner/session model and any local user metadata. |
| Notes/open questions | Exact mapping from current examiner identity to Supabase Auth user remains unconfirmed. |

### `cases`

| Detail | Design |
| --- | --- |
| Purpose | Authoritative case lifecycle and compatibility anchor. |
| Key columns | `id uuid`, `case_key text`, `title text`, `description text`, `status text`, `created_by_user_id uuid null`, `opened_at`, `closed_at`, `created_at`, `updated_at`, `legacy_case_dir text null`, `legacy_case_yaml_path text null`, `compat_export_status text`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `created_by_user_id` references `operator_profiles(id)`. |
| Indexes | Unique `case_key`; `status`; `created_at`; `created_by_user_id`. |
| Uniqueness constraints | `case_key` unique. If legacy case IDs are reused across roots, add a separate uniqueness policy before migration. |
| Status values | `draft`, `active`, `paused`, `closed`, `archived`. |
| RLS/security notes | Human reads require membership. Creation/update should normally go through Gateway. |
| Who can read | Case members through RLS; Gateway and worker service roles as needed. |
| Who can write | Gateway service role. Human direct writes should be limited to safe metadata only if approved. |
| Migration source | `CASE.yaml`, case directories, active case config/pointers. |
| Notes/open questions | Locked (D10): UUID `id` plus text `case_key`/`legacy_case_id`. |

### `case_members`

| Detail | Design |
| --- | --- |
| Purpose | Human case authorization and role membership. |
| Key columns | `id uuid`, `case_id uuid`, `operator_profile_id uuid`, `role text`, `status text`, `added_by_user_id uuid null`, `created_at`, `updated_at`, `expires_at null`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id` references `cases(id)`; `operator_profile_id` references `operator_profiles(id)`; `added_by_user_id` references `operator_profiles(id)`. |
| Indexes | `(case_id, status)`, `(operator_profile_id, status)`, `(case_id, role)`. |
| Uniqueness constraints | Unique active membership per `(case_id, operator_profile_id)`. |
| Status values | `active`, `suspended`, `removed`, `expired`. |
| RLS/security notes | Core RLS join table for case-scoped human reads. Direct writes should be Gateway/admin only. |
| Who can read | Case members can read members according to role policy; Gateway service role. |
| Who can write | Gateway/admin service path. |
| Migration source | Current examiner role/session model. |
| Notes/open questions | Locked: roles `owner`, `lead`, `operator`, `readonly`, `admin`; permission matrix in `09_identity_auth_cutover.md` §5. |

### `active_case_state`

| Detail | Design |
| --- | --- |
| Purpose | Authoritative current active case for the SIFT VM deployment (charter D4/D32). Replaces `SIFT_CASE_DIR` / `~/.sift/active_case` / `gateway.yaml case.dir` as authority. Operator sets it via the portal; the Gateway reads it and propagates it to backends/APIs/tool calls. D32 supersedes the earlier env/pointer compatibility-export plan: PR03B does not generate active-case exports. |
| Key columns | `id uuid`, `scope text`, `active_case_id uuid null`, `set_by_user_id uuid null`, `set_at`, `compat_export_status text`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `active_case_id` references `cases(id)`; `set_by_user_id` references `operator_profiles(id)`. |
| Indexes | Unique `scope`; `active_case_id`. |
| Uniqueness constraints | One row per `scope`. v1 uses a single `scope = 'deployment'` row (one active case per SIFT VM, matching current behavior). The `scope` column leaves room for per-operator active case later without a schema change. |
| Status values | `compat_export_status`: `pending`, `exported`, `stale`. |
| RLS/security notes | Human reads through membership; writes through Gateway portal-activation service path only. Agents/MCP clients never set it. |
| Who can read | Authorized case members; Gateway/worker service roles. |
| Who can write | Gateway service path on portal case activation. |
| Migration source | `SIFT_CASE_DIR`, `gateway.yaml case.dir`, `~/.sift/active_case`, portal case activation (`packages/case-dashboard/src/case_dashboard/routes.py:3598-3717`). |
| Notes/open questions | None. Locked to one active case per deployment in v1 (D4). |

### `agents`

| Detail | Design |
| --- | --- |
| Purpose | AI agent or automation identity independent from Supabase Auth users. |
| Key columns | `id uuid`, `display_name text`, `agent_type text`, `status text`, `owner_user_id uuid null`, `default_case_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `owner_user_id` references `operator_profiles(id)`; `default_case_id` references `cases(id)`. |
| Indexes | `status`, `agent_type`, `owner_user_id`, `default_case_id`. |
| Uniqueness constraints | Optional unique display/slug if approved; not required for security. |
| Status values | `active`, `disabled`, `revoked`, `archived`. |
| RLS/security notes | Agents are not Auth users. Human visibility is through case membership and Gateway policy. |
| Who can read | Gateway service role; authorized operators through safe views. |
| Who can write | Gateway/admin service path. |
| Migration source | `gateway.yaml api_keys` records with `role=agent` and `agent_id`. |
| Notes/open questions | Need exact agent metadata model and whether every token must reference an agent. |

### `service_identities`

| Detail | Design |
| --- | --- |
| Purpose | Non-human service principals such as Gateway instances, workers, maintenance tasks, or integration services. |
| Key columns | `id uuid`, `name text`, `service_type text`, `status text`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | None by default. |
| Indexes | Unique `name` where stable; `service_type`; `status`. |
| Uniqueness constraints | Unique active service name if names are stable. |
| Status values | `active`, `disabled`, `revoked`, `archived`. |
| RLS/security notes | Service-only table. Do not expose broadly to frontend. |
| Who can read | Gateway/admin service role; limited admin views. |
| Who can write | Gateway/admin service path. |
| Migration source | Current Gateway/backend service configuration and future worker registration. |
| Notes/open questions | Workers may use `workers` only, but service identities are useful for non-worker automation and audit actors. |

### `mcp_tokens`

| Detail | Design |
| --- | --- |
| Purpose | Hash-only MCP/service token registry used by Gateway validation. |
| Key columns | `id uuid`, `token_hash text`, `token_fingerprint text`, `status text`, `agent_id uuid null`, `service_identity_id uuid null`, `created_by_user_id uuid null`, `case_id uuid null`, `label text`, `expires_at`, `revoked_at null`, `revoked_by_user_id uuid null`, `last_used_at null`, `last_used_audit_event_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `agent_id` references `agents(id)`; `service_identity_id` references `service_identities(id)`; `created_by_user_id` and `revoked_by_user_id` reference `operator_profiles(id)`; `case_id` references `cases(id)`; `last_used_audit_event_id` references `audit_events(id)` after audit table exists. |
| Indexes | Unique `token_hash`; `token_fingerprint`; `(case_id, status)`; `(agent_id, status)`; `(service_identity_id, status)`; `expires_at`; `last_used_at`. |
| Uniqueness constraints | Unique `token_hash`. Token fingerprints can be non-secret and unique if derived safely. |
| Status values | `active`, `expired`, `revoked`, `disabled`. |
| RLS/security notes | No frontend direct access to `token_hash`. Token creation/rotation/revocation through Gateway only. Human views should use safe views that expose label, fingerprint, status, scope, expiry, and last use, never hash material. |
| Who can read | Gateway service role. Authorized operators through redacted safe views only. |
| Who can write | Gateway service path. |
| Migration source | `~/.sift/gateway.yaml` `api_keys` raw-token registry. |
| Notes/open questions | Locked (D8): SHA-256 + server pepper hash, 16-hex fingerprint, default expiries (agent 90d / service 30d), one-time raw display, dual-validate then sunset legacy; KMS deferred. See `09_identity_auth_cutover.md` §4. |

### `mcp_token_scopes`

| Detail | Design |
| --- | --- |
| Purpose | Normalized tool/action scopes for MCP/service tokens. |
| Key columns | `id uuid`, `token_id uuid`, `scope text`, `case_id uuid null`, `constraints jsonb`, `created_at`. |
| Primary key | `id`. |
| Foreign keys | `token_id` references `mcp_tokens(id)`; `case_id` references `cases(id)`. |
| Indexes | `(token_id, scope)`, `(case_id, scope)`. |
| Uniqueness constraints | Unique `(token_id, scope, case_id)` where `case_id` is not null; separate uniqueness policy for global scopes if approved. |
| Status fields | Scope status usually inherited from token; add `disabled_at` only if per-scope revocation is needed. |
| RLS/security notes | Service-only raw table; safe view can expose scope names to case leads/admins. |
| Who can read | Gateway service role; redacted operator views. |
| Who can write | Gateway service path. |
| Migration source | Current role/capability metadata in gateway config and backend manifests. |
| Notes/open questions | Scope naming must align with future MCP tools, for example `jobs.enqueue`, `parsers.run`, `opensearch.health.read`. |

### `mcp_backends`

| Detail | Design |
| --- | --- |
| Purpose | Control-plane registry of MCP add-on backends (D22). Replaces `gateway.yaml`-based backend config as authority. The Gateway reads registration/enabled/health state from here; the portal manages enable/disable and monitors health. Core tools (OpenSearch, RAG, case/evidence/job tools) are NOT add-ons and are not listed here. |
| Key columns | `id uuid`, `name text`, `namespace text`, `tier text`, `transport text`, `status text`, `enabled boolean`, `manifest jsonb`, `spec_version text`, `data_plane jsonb`, `default_case_scoped boolean`, `health_status text`, `last_health_at null`, `registered_by_user_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `registered_by_user_id` references `operator_profiles(id)`. |
| Indexes | Unique `name`; unique `namespace`; `(status, enabled)`; `health_status`. |
| Uniqueness constraints | Unique `name` and `namespace` (no tool/namespace collisions). |
| Status values | `registered`, `enabled`, `disabled`, `degraded`, `unavailable`, `retired`. |
| `data_plane` shape | Declares what the backend reads/writes, e.g. `{"type":"external_platform","opensearch_role":"opencti","index_prefix":"opencti_*"}`, `{"type":"local_package"}` (wintriage), or `{"type":"none"}`. See `10_addon_backend_spec.md`. |
| RLS/security notes | Read for authorized operators; registration/enable/disable through Gateway/admin service paths only. |
| Who can read | Operators (portal) and Gateway service role. |
| Who can write | Gateway/admin service path (manifest validation + registration). |
| Migration source | `gateway.yaml` backend config and `sift-backend.json` manifests. |
| Notes/open questions | `manifest` stores the validated add-on manifest; `default_case_scoped` is the backend default, overridable per tool in the manifest (`case_scoped`). Full contract in `10_addon_backend_spec.md`. |

## 5. Evidence And Integrity Tables

### `evidence_sources`

| Detail | Design |
| --- | --- |
| Purpose | Acquisition/source metadata for evidence before or during vault registration. |
| Key columns | `id uuid`, `case_id uuid`, `source_type text`, `source_ref text`, `source_display text`, `acquired_by_user_id uuid null`, `acquired_at null`, `metadata jsonb`, `created_at`, `updated_at`. |
| Primary key | `id`. |
| Foreign keys | `case_id` references `cases(id)`; `acquired_by_user_id` references `operator_profiles(id)`. |
| Indexes | `case_id`, `(case_id, source_type)`, `acquired_at`. |
| Uniqueness constraints | None by default; duplicate sources are resolved by evidence hashes and policy. |
| Status fields | Optional `status`: `observed`, `registered`, `rejected`, `archived`. |
| RLS/security notes | Source refs may include sensitive paths. Frontend exposure should be redacted or role-gated. |
| Who can read | Authorized case members according to evidence visibility; Gateway/worker service roles. |
| Who can write | Gateway/evidence service path. |
| Migration source | Case evidence directories, evidence registration flows, current source path metadata. |
| Notes/open questions | Decide how much original path/source detail is safe for normal operators and agents. |

### `evidence_objects`

| Detail | Design |
| --- | --- |
| Purpose | Authoritative metadata and vault reference for immutable evidence. |
| Key columns | `id uuid`, `case_id uuid`, `evidence_source_id uuid null`, `display_name text`, `evidence_type text`, `status text`, `integrity_status text`, `vault_uri text`, `legacy_path text null`, `size_bytes bigint null`, `mtime timestamptz null`, `sha256 text null`, `hashes jsonb`, `immutable_status text`, `registered_by_user_id uuid null`, `registered_by_job_id uuid null`, `registered_audit_event_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id` references `cases(id)`; `evidence_source_id` references `evidence_sources(id)`; `registered_by_user_id` references `operator_profiles(id)`; `registered_by_job_id` references `jobs(id)` when jobs exist; `registered_audit_event_id` references `audit_events(id)`. |
| Indexes | `(case_id, status)`, `(case_id, integrity_status)`, `(case_id, sha256)`, `registered_by_job_id`, `created_at`. |
| Uniqueness constraints | Locked (D16): preserve by default. Do NOT enforce unique active `(case_id, sha256)` as the default, because duplicate acquisitions are often forensically meaningful. Any such uniqueness is an explicit, opt-in per-deployment policy and must never silently drop evidence. |
| Status values | `registered`, `sealed`, `ignored`, `retired`, `missing`, `quarantined`, `archived`. |
| RLS/security notes | Read through case membership and evidence visibility. Writes through Gateway/evidence service only. |
| Who can read | Authorized case members; Gateway/worker service roles; MCP agents through Gateway only. |
| Who can write | Gateway/evidence service and authorized worker jobs. |
| Migration source | `evidence-manifest.json`, legacy `evidence.json`, case evidence paths, evidence-chain operations. |
| Notes/open questions | Locked: dedupe preserves by default (D16). Default: `legacy_path`/raw source paths are not exposed to normal operators/agents; reads are redacted or role-gated to `lead`/`owner`/`admin`. |

### `evidence_manifests`

| Detail | Design |
| --- | --- |
| Purpose | Register preserved manifest and ledger proof/export artifacts for a case. |
| Key columns | `id uuid`, `case_id uuid`, `manifest_path text`, `ledger_path text`, `manifest_hash text null`, `ledger_head_hash text null`, `status text`, `last_verified_at null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id` references `cases(id)`. |
| Indexes | `(case_id, status)`, `last_verified_at`. |
| Uniqueness constraints | One active manifest registration per case unless historical versions are intentionally retained. |
| Status values | `active`, `mirrored`, `exported`, `stale`, `invalid`, `archived`. |
| RLS/security notes | Case-scoped read. Writes through evidence service. |
| Who can read | Authorized case members; Gateway/worker service roles. |
| Who can write | Gateway/evidence service path. |
| Migration source | `/var/lib/sift/<case>/evidence-manifest.json` and `evidence-ledger.jsonl`. |
| Notes/open questions | Locked: manifest/ledger files are preserved indefinitely as proof/export artifacts after DB authority (charter). Whether they are additionally treated as the canonical legal artifact is a deployment/legal-retention policy, not a schema blocker. |

### `evidence_integrity_events`

| Detail | Design |
| --- | --- |
| Purpose | Append-only integrity, seal, verify, ignore, retire, anchor, and ledger-mirror events. |
| Key columns | `id uuid`, `case_id uuid`, `evidence_id uuid null`, `event_type text`, `status text`, `actor_user_id uuid null`, `actor_agent_id uuid null`, `actor_service_identity_id uuid null`, `job_id uuid null`, `audit_event_id uuid null`, `ledger_event_ref text null`, `manifest_hash text null`, `source_hash text null`, `details jsonb`, `created_at`. |
| Primary key | `id`. |
| Foreign keys | `case_id` references `cases(id)`; `evidence_id` references `evidence_objects(id)`; actor refs to identity tables; `job_id` references `jobs(id)`; `audit_event_id` references `audit_events(id)`. |
| Indexes | `(case_id, created_at)`, `(evidence_id, created_at)`, `(case_id, event_type)`, `job_id`, `audit_event_id`. |
| Uniqueness constraints | Optional idempotency key for repeatable full verification events if needed. |
| Status values | `recorded`, `verified`, `failed`, `warning`, `superseded`. |
| RLS/security notes | Append-only. Normal users can read case-scoped integrity history if role permits. Writes through service paths only. |
| Who can read | Authorized case members according to role; Gateway/worker service roles. |
| Who can write | Gateway/evidence service and authorized worker jobs. |
| Migration source | Evidence ledger events and evidence-chain operation results. |
| Notes/open questions | Decide which ledger events are mirrored verbatim versus summarized. |

### `evidence_access_events`

| Detail | Design |
| --- | --- |
| Purpose | Optional evidence-specific access log for queries that need fast evidence access history. It should also link to `audit_events`. |
| Key columns | `id uuid`, `case_id uuid`, `evidence_id uuid`, `access_type text`, `actor_user_id uuid null`, `actor_agent_id uuid null`, `actor_service_identity_id uuid null`, `job_id uuid null`, `audit_event_id uuid`, `created_at`, `details jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `evidence_id`, actor refs, `job_id`, `audit_event_id`. |
| Indexes | `(case_id, created_at)`, `(evidence_id, created_at)`, `audit_event_id`, `job_id`. |
| Uniqueness constraints | None by default. |
| Status fields | Access records are append-only events; no status needed beyond event type. |
| RLS/security notes | May reveal sensitive activity. Prefer admin/lead reads or safe summaries. |
| Who can read | Gateway service role; elevated case roles through safe views. |
| Who can write | Gateway/evidence service and authorized worker jobs. |
| Migration source | Audit JSONL evidence-related entries and future evidence job access events. |
| Notes/open questions | This table can be deferred if `audit_events` is sufficient initially. |

## 6. Audit And Approval Tables

### `audit_events`

| Detail | Design |
| --- | --- |
| Purpose | Append-only accountability record for privileged actions, policy decisions, job lifecycle, evidence access/checks, parser/indexing events, approvals, token activity, and denials. |
| Key columns | `id uuid`, `case_id uuid null`, `event_type text`, `actor_type text`, `actor_user_id uuid null`, `actor_agent_id uuid null`, `actor_token_id uuid null`, `actor_service_identity_id uuid null`, `job_id uuid null`, `request_id text null`, `source text`, `status text`, `summary text`, `details jsonb`, `created_at`. |
| Primary key | `id`. |
| Foreign keys | Optional refs to `cases`, identity tables, `mcp_tokens`, and `jobs`. |
| Indexes | `(case_id, created_at)`, `(event_type, created_at)`, `actor_user_id`, `actor_agent_id`, `actor_token_id`, `job_id`, `request_id`. |
| Uniqueness constraints | Optional unique request/event idempotency key for retry-safe writes. |
| Status values | `success`, `failure`, `denied`, `warning`, `degraded`, `requested`. |
| RLS/security notes | Append-only. Direct frontend writes are forbidden. Reads are role-gated and may be summarized through views. |
| Who can read | Gateway service role; elevated case members and admins through safe views. |
| Who can write | Gateway service role and worker service role for claimed jobs. |
| Migration source | `/var/lib/sift/<case>/audit/*.jsonl`, Gateway MCP audit, core tool audit, OpenSearch ingest audit. |
| Notes/open questions | Decide which privileged actions fail closed when DB audit write is unavailable. |

### `approval_requests`

| Detail | Design |
| --- | --- |
| Purpose | Explicit approval gates for final, destructive, high-risk, or human-review actions. |
| Key columns | `id uuid`, `case_id uuid`, `target_type text`, `target_id uuid null`, `job_id uuid null`, `requested_by_user_id uuid null`, `requested_by_agent_id uuid null`, `requested_by_token_id uuid null`, `status text`, `reason text`, `content_hash text null`, `created_at`, `updated_at`, `expires_at null`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`; requester refs; `job_id`; target FK is polymorphic by `target_type` and should be validated in service code or typed join tables if needed. |
| Indexes | `(case_id, status)`, `job_id`, `(target_type, target_id)`, `created_at`. |
| Uniqueness constraints | Optional unique active `(case_id, target_type, target_id, content_hash)` to avoid duplicate approval gates. |
| Status values | `pending`, `approved`, `rejected`, `cancelled`, `expired`, `superseded`. |
| RLS/security notes | Case members can read pending approvals based on role. Creation and state transitions through Gateway. |
| Who can read | Authorized case members; Gateway service role. |
| Who can write | Gateway service path; workers can create requests only through job service paths. |
| Migration source | `pending-reviews.json`, `approvals.jsonl`, approval commit flow. |
| Notes/open questions | Locked: approval/destructive actions require `lead`/`owner`/`admin` per the role matrix (`09_identity_auth_cutover.md` §5); agents never approve their own findings. |

### `approval_decisions`

| Detail | Design |
| --- | --- |
| Purpose | Append-only human decisions on approval requests. |
| Key columns | `id uuid`, `approval_request_id uuid`, `case_id uuid`, `decision text`, `decided_by_user_id uuid`, `reason text null`, `content_hash text null`, `audit_event_id uuid null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `approval_request_id` references `approval_requests(id)`; `case_id`; `decided_by_user_id`; `audit_event_id`. |
| Indexes | `(case_id, created_at)`, `approval_request_id`, `decided_by_user_id`. |
| Uniqueness constraints | Usually one final decision per request. If multiple decisions are allowed, request status determines finality. |
| Status fields | `decision`: `approved`, `rejected`, `cancelled`, `returned_for_changes`. |
| RLS/security notes | Agent/service identities cannot approve. Direct frontend mutation should be via Gateway to ensure audit and policy. |
| Who can read | Authorized case members according to role. |
| Who can write | Gateway approval service path after human auth. |
| Migration source | Approval logs and pending review commit records. |
| Notes/open questions | Whether direct Supabase human insert is allowed for simple decisions remains a policy decision; Gateway path is safer initially. |

Event classification:

| Event kind | Audit only | Job log only | Both audit and job log |
| --- | --- | --- | --- |
| Policy denial, token validation, approval decision, human membership change | Yes | No | No |
| Fine-grained parser progress line, stdout/stderr tail, UI progress note | No | Yes | No |
| Job created/claimed/succeeded/failed/cancelled, parser run start/end, evidence access/hash/check, OpenSearch indexing batch, report export | No | No | Yes |

## 7. Findings, Timeline References, And Report Tables

### `findings`

| Detail | Design |
| --- | --- |
| Purpose | Case-scoped findings, including agent/worker proposed findings and human-approved findings. |
| Key columns | `id uuid`, `case_id uuid`, `title text`, `description text`, `severity text`, `status text`, `source_type text`, `created_by_user_id uuid null`, `created_by_agent_id uuid null`, `created_by_job_id uuid null`, `approved_by_user_id uuid null`, `approved_at null`, `content_hash text`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`; creator refs; `created_by_job_id`; `approved_by_user_id`. |
| Indexes | `(case_id, status)`, `(case_id, severity)`, `created_by_job_id`, `created_at`, `content_hash`. |
| Uniqueness constraints | Optional uniqueness on `(case_id, content_hash)` for duplicate proposal detection. |
| Status values | `proposed`, `pending_review`, `approved`, `rejected`, `superseded`, `archived`. |
| RLS/security notes | Case members can read according to role. Writes that change status should go through Gateway approval/review paths. |
| Who can read | Authorized case members; Gateway service role; MCP agents through Gateway only. |
| Who can write | Gateway/service paths; workers may create proposed findings through jobs. |
| Migration source | `findings.json`, `CaseManager.record_finding()`, forensic MCP finding tools. |
| Notes/open questions | Exact mapping from current DRAFT/review statuses to target statuses needs confirmation. |

### `finding_reviews`

| Detail | Design |
| --- | --- |
| Purpose | Review lifecycle entries for findings. |
| Key columns | `id uuid`, `case_id uuid`, `finding_id uuid`, `review_status text`, `reviewed_by_user_id uuid null`, `approval_request_id uuid null`, `comment text null`, `content_hash text null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `finding_id`, `reviewed_by_user_id`, `approval_request_id`. |
| Indexes | `(case_id, finding_id)`, `(case_id, review_status)`, `approval_request_id`, `created_at`. |
| Uniqueness constraints | Optional one active review row per finding. |
| Status values | `pending`, `approved`, `rejected`, `needs_changes`, `superseded`. |
| RLS/security notes | Review writes through Gateway or approved human RLS path. |
| Who can read | Authorized case members. |
| Who can write | Gateway review/approval service path. |
| Migration source | `pending-reviews.json`, approval commit logic. |
| Notes/open questions | Decide whether finding review and approval requests remain separate or are merged for simple cases. |

### `finding_evidence_refs`

| Detail | Design |
| --- | --- |
| Purpose | Link findings to evidence, parser outputs, OpenSearch document IDs, jobs, and audit refs. |
| Key columns | `id uuid`, `case_id uuid`, `finding_id uuid`, `evidence_id uuid null`, `parser_run_id uuid null`, `parser_output_id uuid null`, `opensearch_doc_id text null`, `opensearch_index_id uuid null`, `job_id uuid null`, `source_hash text null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `finding_id`, optional evidence/parser/job/index refs. |
| Indexes | `(case_id, finding_id)`, `evidence_id`, `parser_run_id`, `job_id`, `(opensearch_index_id, opensearch_doc_id)`. |
| Uniqueness constraints | Optional unique tuple for duplicate refs. |
| Status fields | Optional `status`: `active`, `removed`, `superseded`. |
| RLS/security notes | Same visibility as finding plus evidence visibility. |
| Who can read | Authorized case members. |
| Who can write | Gateway/finding/report services and worker proposal jobs. |
| Migration source | Finding evidence links in current JSON and future parser/OpenSearch lineage. |
| Notes/open questions | Not every current finding may have evidence refs; missing provenance should be explicit. |

### `timeline_event_refs`

| Detail | Design |
| --- | --- |
| Purpose | Postgres review/reference metadata for timeline items while searchable timeline documents live in OpenSearch. |
| Key columns | `id uuid`, `case_id uuid`, `status text`, `event_time timestamptz null`, `title text`, `summary text null`, `opensearch_doc_id text null`, `opensearch_index_id uuid null`, `evidence_id uuid null`, `finding_id uuid null`, `parser_run_id uuid null`, `created_by_user_id uuid null`, `created_by_agent_id uuid null`, `created_by_job_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | Case, evidence, finding, parser, job, and index refs. |
| Indexes | `(case_id, status)`, `(case_id, event_time)`, `finding_id`, `evidence_id`, `(opensearch_index_id, opensearch_doc_id)`. |
| Uniqueness constraints | Optional unique `(case_id, opensearch_index_id, opensearch_doc_id)` for reviewed references. |
| Status values | `proposed`, `approved`, `rejected`, `superseded`, `archived`. |
| RLS/security notes | Case-scoped. Human approval required for final timeline promotion. |
| Who can read | Authorized case members. |
| Who can write | Gateway/review service and worker proposal jobs. |
| Migration source | `timeline.json`, OpenSearch timeline docs, CaseManager timeline tools. |
| Notes/open questions | Decide how much timeline data is duplicated into Postgres versus kept only in OpenSearch. |

### `case_todos`

| Detail | Design |
| --- | --- |
| Purpose | Investigation TODOs (retained capability, D14). Replaces `todos.json`. |
| Key columns | `id uuid`, `case_id uuid`, `title text`, `description text null`, `status text`, `priority text null`, `assigned_to_user_id uuid null`, `created_by_user_id uuid null`, `created_by_agent_id uuid null`, `created_by_job_id uuid null`, `due_at null`, `completed_at null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`; creator/assignee refs; `created_by_job_id`. |
| Indexes | `(case_id, status)`, `(case_id, assigned_to_user_id)`, `created_at`. |
| Uniqueness constraints | None by default. |
| Status values | `open`, `in_progress`, `blocked`, `done`, `cancelled`. |
| RLS/security notes | Case-scoped reads. Agents may create/update TODOs through Gateway tools; humans manage them through portal/Gateway. |
| Who can read | Authorized case members; MCP agents through Gateway. |
| Who can write | Gateway/portal service and worker/agent tool paths. |
| Migration source | `todos.json`, `CaseManager` TODO tools, forensic-mcp TODO tools. |
| Notes/open questions | None. First-class, not deferred (D14). |

### `iocs`

| Detail | Design |
| --- | --- |
| Purpose | Indicators of compromise (retained capability, D14). Replaces `iocs.json`. Postgres holds authoritative IOC records and review state; OpenSearch holds searchable IOC documents/views. |
| Key columns | `id uuid`, `case_id uuid`, `ioc_type text`, `value text`, `status text`, `confidence text null`, `severity text null`, `source_type text`, `finding_id uuid null`, `evidence_id uuid null`, `parser_run_id uuid null`, `opensearch_doc_id text null`, `opensearch_index_id uuid null`, `created_by_user_id uuid null`, `created_by_agent_id uuid null`, `created_by_job_id uuid null`, `approved_by_user_id uuid null`, `approved_at null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`; `finding_id`; `evidence_id`; `parser_run_id`; `opensearch_index_id`; creator/approver refs; `created_by_job_id`. |
| Indexes | `(case_id, status)`, `(case_id, ioc_type)`, `(case_id, value)`, `finding_id`, `evidence_id`, `(opensearch_index_id, opensearch_doc_id)`. |
| Uniqueness constraints | Optional unique active `(case_id, ioc_type, value)` to dedupe within a case; must not silently drop forensically distinct observations (D16) - prefer status/merge over delete. |
| Status values | `proposed`, `approved`, `rejected`, `superseded`, `archived`. |
| IOC types | `ip`, `domain`, `url`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`, `filename`, `filepath`, `registry_key`, `mutex`, `user_account`, `host`, `other`. |
| RLS/security notes | Case-scoped reads. Agent-proposed IOCs remain `proposed` until human approval, mirroring findings. |
| Who can read | Authorized case members; MCP agents through Gateway. |
| Who can write | Gateway/service paths; workers/agents create proposed IOCs through jobs/tools. |
| Migration source | `iocs.json`, IOC extraction in `CaseManager`/`record_finding`, OpenSearch IOC views. |
| Notes/open questions | None. First-class, not deferred (D14). |

### `reports`

| Detail | Design |
| --- | --- |
| Purpose | Report metadata and generation lifecycle. |
| Key columns | `id uuid`, `case_id uuid`, `title text`, `report_type text`, `status text`, `profile text`, `created_by_user_id uuid null`, `created_by_agent_id uuid null`, `generation_job_id uuid null`, `approval_request_id uuid null`, `source_snapshot_hash text null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, creator refs, `generation_job_id`, `approval_request_id`. |
| Indexes | `(case_id, status)`, `(case_id, report_type)`, `generation_job_id`, `created_at`. |
| Uniqueness constraints | Optional idempotency over `(case_id, report_type, profile, source_snapshot_hash)`. |
| Status values | `draft`, `generating`, `pending_approval`, `approved`, `exported`, `failed`, `archived`. |
| RLS/security notes | Reads by case role. Final/export status changes through Gateway approval path. |
| Who can read | Authorized case members according to report visibility. |
| Who can write | Gateway/report service and report jobs. |
| Migration source | In-memory report drafts and `case/reports/{uuid}.json`. |
| Notes/open questions | Need mapping for current saved report JSON shape and downstream consumers. |

### `report_artifacts`

| Detail | Design |
| --- | --- |
| Purpose | Generated/exported report artifact registrations. |
| Key columns | `id uuid`, `case_id uuid`, `report_id uuid`, `artifact_type text`, `status text`, `artifact_uri text`, `legacy_path text null`, `sha256 text null`, `size_bytes bigint null`, `export_job_id uuid null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `report_id`, `export_job_id`. |
| Indexes | `(case_id, report_id)`, `(case_id, status)`, `export_job_id`, `sha256`. |
| Uniqueness constraints | Optional unique `(report_id, artifact_type, sha256)`. |
| Status values | `created`, `ready`, `failed`, `retired`, `archived`. |
| RLS/security notes | Export artifacts may be sensitive. Downloads should go through Gateway. |
| Who can read | Authorized case members; direct artifact content access through Gateway policy. |
| Who can write | Gateway/report service and worker jobs. |
| Migration source | Saved report JSON and generated report downloads. |
| Notes/open questions | Decide artifact storage location and retention policy. |

## 8. Durable Execution And Job Tables

**v1 lean core (locked, D13).** Implement only `jobs`, `job_steps`, `job_logs`,
and `workers` first. `attempt_count`, `cancellation_requested_at`,
`cancellation_requested_by`, and `heartbeat_at` live directly on the `jobs` /
`workers` rows. The separate `job_attempts`, `job_cancellations`, and
`worker_heartbeats` tables below are **deferred** until a concrete need exists
(multi-worker fairness, attempt forensics, or heartbeat history); their history
is initially captured by `jobs` fields plus `audit_events`. `SKIP LOCKED`
cross-case fairness is added only when a second worker exists (D9). All job
types and step types in §12 are enumerated now, but only `health_check` plus the
first converted workflow (e.g. `evidence_hash`/`parser_run`) are implemented
initially.

### `jobs`

| Detail | Design |
| --- | --- |
| Purpose | Durable requested work and lifecycle authority. |
| Key columns | `id uuid`, `case_id uuid`, `job_type text`, `status text`, `priority int`, `idempotency_key text null`, `spec jsonb`, `requested_by_user_id uuid null`, `requested_by_agent_id uuid null`, `requested_by_token_id uuid null`, `created_by_type text`, `queued_at null`, `started_at null`, `finished_at null`, `claimed_by_worker_id uuid null`, `lease_expires_at null`, `heartbeat_at null`, `attempt_count int`, `max_attempts int`, `retry_after null`, `cancellation_requested_at null`, `cancellation_requested_by text null`, `failure_summary text null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`; requester refs; `claimed_by_worker_id` references `workers(id)`. |
| Indexes | `(case_id, status)`, `(case_id, job_type, created_at)`, `(status, priority, queued_at)`, `(status, lease_expires_at)`, `claimed_by_worker_id`, requester refs. |
| Uniqueness constraints | Unique active or completed idempotency per `(case_id, job_type, idempotency_key)` where key is not null, with force-rerun creating linked lineage if approved. |
| Status values | `pending`, `queued`, `running`, `waiting_human`, `succeeded`, `failed`, `retrying`, `cancelled`, `stale`, `paused`. |
| RLS/security notes | Human users can read case-visible job summaries. Job mutation through Gateway/worker service paths only. |
| Who can read | Authorized case members through RLS or Gateway; MCP agents through Gateway. |
| Who can write | Gateway job service and worker service for claimed jobs. |
| Migration source | OpenSearch ingest status files, in-memory report generation state, current synchronous evidence/report/parser workflows. |
| Notes/open questions | Default (non-blocking): integer `priority` (higher = sooner), small range e.g. 0-9; retry granularity is whole-job in v1, finer parser-run/indexing-batch retry later (JOB-8/JOB-9). |

### `job_attempts` (DEFERRED in v1 - D13)

This table is deferred. In v1, `jobs.attempt_count` plus `job_steps` and
`audit_events` capture attempt history. Add this table only when attempt-level
forensics are actually needed.

| Detail | Design |
| --- | --- |
| Purpose | Preserve attempt history across retries, stale recovery, and force reruns. |
| Key columns | `id uuid`, `case_id uuid`, `job_id uuid`, `attempt_number int`, `worker_id uuid null`, `status text`, `started_at`, `finished_at null`, `failure_summary text null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `job_id`, `worker_id`. |
| Indexes | `(job_id, attempt_number)`, `(case_id, created_at)`, `worker_id`. |
| Uniqueness constraints | Unique `(job_id, attempt_number)`. |
| Status values | `running`, `succeeded`, `failed`, `cancelled`, `stale`, `superseded`. |
| RLS/security notes | Read with job visibility. Writes by worker/job service. |
| Who can read | Authorized case members. |
| Who can write | Gateway/worker service. |
| Migration source | Current status/logs do not preserve structured attempts; this is new DB authority. |
| Notes/open questions | Could be deferred if `attempt_count` plus steps is enough initially, but preserving retries argues for keeping it. |

### `job_steps`

| Detail | Design |
| --- | --- |
| Purpose | Ordered structured progress within a job. |
| Key columns | `id uuid`, `case_id uuid`, `job_id uuid`, `job_attempt_id uuid null`, `step_name text`, `step_type text`, `status text`, `sequence int`, `started_at null`, `finished_at null`, `duration_ms int null`, `progress jsonb`, `metrics jsonb`, `output_refs jsonb`, `error_summary text null`, `created_at`, `updated_at`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `job_id`, `job_attempt_id`. |
| Indexes | `(job_id, sequence)`, `(case_id, status)`, `job_attempt_id`. |
| Uniqueness constraints | Unique `(job_id, sequence)` or `(job_id, job_attempt_id, sequence)`. |
| Status values | `pending`, `running`, `succeeded`, `failed`, `skipped`, `cancelled`, `stale`, `waiting_human`. |
| RLS/security notes | Read with job visibility. Writes by worker/job service. |
| Who can read | Authorized case members. |
| Who can write | Gateway/worker service. |
| Migration source | Implicit parser phases, ingest status records, report/evidence route progress. |
| Notes/open questions | Need step type list aligned to worker adapters. |

### `job_logs`

| Detail | Design |
| --- | --- |
| Purpose | Append-only operational logs for jobs and steps. |
| Key columns | `id uuid`, `case_id uuid`, `job_id uuid`, `job_step_id uuid null`, `job_attempt_id uuid null`, `level text`, `source text`, `message text`, `structured_data jsonb`, `redaction_applied boolean`, `created_at`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `job_id`, `job_step_id`, `job_attempt_id`. |
| Indexes | `(job_id, created_at)`, `(case_id, created_at)`, `(job_step_id, created_at)`, `level`. |
| Uniqueness constraints | None by default. |
| Status fields | Log level: `debug`, `info`, `warning`, `error`. |
| RLS/security notes | Logs may expose paths or stderr. Use role-gated reads and redaction. Do not store secrets or raw evidence content. |
| Who can read | Authorized case members with log permission; Gateway/worker service roles. |
| Who can write | Gateway/worker service. |
| Migration source | `~/.sift/ingest-logs`, command stdout/stderr summaries, status messages. |
| Notes/open questions | Decide DB log retention versus file/object log references. |

### `workers`

| Detail | Design |
| --- | --- |
| Purpose | Worker registration, capabilities, current heartbeat, and health state. |
| Key columns | `id uuid`, `service_identity_id uuid null`, `worker_name text`, `host text`, `pid int null`, `version text`, `status text`, `capabilities jsonb`, `parser_allowlist jsonb`, `active_job_id uuid null`, `registered_at`, `last_seen_at`, `degraded_reason text null`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `service_identity_id` references `service_identities(id)`; `active_job_id` references `jobs(id)`. |
| Indexes | `status`, `last_seen_at`, `active_job_id`, `host`. |
| Uniqueness constraints | Optional unique `(host, pid, registered_at)` or stable worker name depending on topology. |
| Status values | `online`, `degraded`, `offline`, `stale`, `draining`, `disabled`. |
| RLS/security notes | Human views should expose summary only unless admin/lead. Writes by worker service. |
| Who can read | Gateway/worker service; authorized operators through safe views. |
| Who can write | Worker service registration/heartbeat paths. |
| Migration source | Current process-local OpenSearch ingest pids and future worker runtime. |
| Notes/open questions | Exact worker topology remains unapproved. |

### `worker_heartbeats` (DEFERRED in v1 - D13)

This table is deferred. Current heartbeat lives on `workers.last_seen_at`. Add
history only if operations require it.

| Detail | Design |
| --- | --- |
| Purpose | Optional historical heartbeat samples for diagnostics. Current heartbeat lives on `workers`. |
| Key columns | `id uuid`, `worker_id uuid`, `status text`, `active_job_id uuid null`, `observed_at`, `metrics jsonb`, `degraded_reason text null`. |
| Primary key | `id`. |
| Foreign keys | `worker_id` references `workers(id)`; `active_job_id` references `jobs(id)`. |
| Indexes | `(worker_id, observed_at)`, `observed_at`, `active_job_id`. |
| Uniqueness constraints | None. |
| Status values | Same as `workers`. |
| RLS/security notes | Service/admin diagnostics. Can be deferred to avoid high-volume writes. |
| Who can read | Gateway/admin service; safe summaries for operators. |
| Who can write | Worker service. |
| Migration source | No current durable heartbeat history. |
| Notes/open questions | Defer unless heartbeat history is required for operations. |

### `job_cancellations` (DEFERRED in v1 - D13)

This table is deferred. In v1, `jobs.cancellation_requested_at` /
`jobs.cancellation_requested_by` plus `audit_events` record cancellation. Add
this table only if richer cancellation lineage is needed.

| Detail | Design |
| --- | --- |
| Purpose | Preserve cancellation request and finalization history. |
| Key columns | `id uuid`, `case_id uuid`, `job_id uuid`, `requested_by_user_id uuid null`, `requested_by_agent_id uuid null`, `requested_by_token_id uuid null`, `reason text`, `force_after_seconds int null`, `status text`, `requested_at`, `finalized_at null`, `audit_event_id uuid null`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `job_id`, requester refs, `audit_event_id`. |
| Indexes | `(case_id, requested_at)`, `job_id`, `status`. |
| Uniqueness constraints | Optional one active cancellation request per nonterminal job. |
| Status values | `requested`, `observed`, `completed`, `failed`, `superseded`. |
| RLS/security notes | Reads with job visibility. Writes through Gateway and worker finalization. |
| Who can read | Authorized case members. |
| Who can write | Gateway cancellation path and worker service finalization. |
| Migration source | No current durable cancellation model. |
| Notes/open questions | Default (non-blocking): cooperative stop first, then bounded force-kill of the subprocess group when policy allows; partial outputs marked `partial`, never reported as complete. Table itself is deferred in v1 (D13). |

## 9. Parser, Ingest, And OpenSearch Lineage Tables

### `parser_runs`

| Detail | Design |
| --- | --- |
| Purpose | One parser execution attempt against evidence/source. |
| Key columns | `id uuid`, `case_id uuid`, `job_id uuid`, `job_step_id uuid null`, `job_attempt_id uuid null`, `evidence_id uuid null`, `parser_name text`, `parser_version text`, `status text`, `source_ref text`, `source_hash text null`, `started_at`, `finished_at null`, `output_count int`, `error_summary text null`, `worker_id uuid null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `job_id`, `job_step_id`, `job_attempt_id`, `evidence_id`, `worker_id`. |
| Indexes | `(case_id, parser_name, status)`, `job_id`, `evidence_id`, `source_hash`, `worker_id`, `started_at`. |
| Uniqueness constraints | Recommended idempotency over `(case_id, evidence_id, parser_name, parser_version, source_hash, spec_hash)` where applicable. |
| Status values | `pending`, `running`, `succeeded`, `failed`, `cancelled`, `stale`, `partial`. |
| RLS/security notes | Case-scoped reads. Writes by worker/job service. |
| Who can read | Authorized case members. |
| Who can write | Worker service for claimed jobs. |
| Migration source | OpenSearch ingest `run_id`, parser audit IDs, status files. |
| Notes/open questions | Need exact parser version source and spec hash strategy. |

### `parser_outputs`

| Detail | Design |
| --- | --- |
| Purpose | Registered derived parser output, whether file, object, normalized batch, or stream summary. |
| Key columns | `id uuid`, `case_id uuid`, `parser_run_id uuid`, `job_id uuid`, `job_step_id uuid null`, `evidence_id uuid null`, `output_type text`, `output_uri text null`, `legacy_path text null`, `output_hash text null`, `source_hash text null`, `schema_version text`, `record_count int null`, `status text`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `parser_run_id`, `job_id`, `job_step_id`, `evidence_id`. |
| Indexes | `(case_id, status)`, `parser_run_id`, `job_id`, `evidence_id`, `output_hash`, `source_hash`. |
| Uniqueness constraints | Optional unique `(parser_run_id, output_type, output_hash)` where hash exists. |
| Status values | `created`, `ready`, `failed`, `partial`, `indexed`, `retired`. |
| RLS/security notes | Case-scoped and evidence visibility aware. |
| Who can read | Authorized case members through Gateway/views. |
| Who can write | Worker/parser service. |
| Migration source | Current `agent/`, `extractions/`, `tmp/`, ingest manifests, parser-generated outputs. |
| Notes/open questions | Some parser modules write directly to OpenSearch today; adapters may need to synthesize output records. |

### `ingest_batches`

| Detail | Design |
| --- | --- |
| Purpose | Group parser outputs or normalized records into indexable batches. |
| Key columns | `id uuid`, `case_id uuid`, `parser_run_id uuid null`, `parser_output_id uuid null`, `job_id uuid`, `job_step_id uuid null`, `batch_key text`, `source_hash text null`, `schema_version text`, `record_count int null`, `status text`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `parser_run_id`, `parser_output_id`, `job_id`, `job_step_id`. |
| Indexes | `(case_id, status)`, `parser_run_id`, `parser_output_id`, `job_id`, `batch_key`. |
| Uniqueness constraints | Unique `(case_id, batch_key, schema_version)` where batch keys are deterministic. |
| Status values | `planned`, `ready`, `indexing`, `indexed`, `failed`, `partial`, `cancelled`, `retired`. |
| RLS/security notes | Case-scoped reads; worker writes. |
| Who can read | Authorized case members through status views. |
| Who can write | Worker/parser/indexing service. |
| Migration source | OpenSearch ingest run/artifact batches and sidecar manifests. |
| Notes/open questions | Default (non-blocking): per-source-file plus parser run in v1; finer bulk-chunk batching when converting parser paths (JOB-8/JOB-9). |

### `opensearch_indexes`

| Detail | Design |
| --- | --- |
| Purpose | Postgres registry of case-scoped OpenSearch logical indexes, aliases, schema versions, and health. |
| Key columns | `id uuid`, `case_id uuid`, `logical_kind text`, `index_name text`, `read_alias text`, `write_alias text`, `schema_version text`, `mapping_template text`, `status text`, `created_by_job_id uuid null`, `active_parser_run_id uuid null`, `last_indexed_at null`, `doc_count bigint null`, `last_health_status text null`, `created_at`, `updated_at`, `retired_at null`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `created_by_job_id`, `active_parser_run_id`. |
| Indexes | `(case_id, logical_kind, status)`, unique aliases, `index_name`, `schema_version`, `last_health_status`. |
| Uniqueness constraints | Unique `index_name`; unique active `(case_id, logical_kind, schema_version)` where status active/ready; unique read/write aliases. |
| Status values | `planned`, `creating`, `ready`, `degraded`, `reindexing`, `retired`, `failed`. |
| RLS/security notes | Case-scoped read. Writes through OpenSearch/Gateway/worker service paths. |
| Who can read | Authorized case members; MCP agents through Gateway. |
| Who can write | Gateway/OpenSearch service and worker indexing jobs. |
| Migration source | Existing `case-*` indexes and future logical aliases. |
| Notes/open questions | Locked (D18): v1 **registers the existing** `case-{case_id}-{artifact_type}-{hostname}` indices (discovery/registration, not renaming); `logical_kind` classifies them (`evtx`, `hayabusa`, `csv`, `timeline`, `iocs`, etc.); `read_alias`/`write_alias` are nullable in v1. The logical-family rename (`dfir-case-*-vN` + aliases) is a deferred, optional evolution. OpenSearch 3.5.0 security-on (D6). The write contract for all writers (core + addon + enrichment) is `03` §7A. |

### `opensearch_indexing_status`

| Detail | Design |
| --- | --- |
| Purpose | Durable status for indexing attempts and batches. |
| Key columns | `id uuid`, `case_id uuid`, `opensearch_index_id uuid`, `ingest_batch_id uuid null`, `parser_run_id uuid null`, `parser_output_id uuid null`, `job_id uuid`, `job_step_id uuid null`, `status text`, `target_alias text`, `target_index text null`, `schema_version text`, `indexed_document_count int`, `failed_document_count int`, `last_error text null`, `started_at null`, `finished_at null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `opensearch_index_id`, `ingest_batch_id`, `parser_run_id`, `parser_output_id`, `job_id`, `job_step_id`. |
| Indexes | `(case_id, status)`, `opensearch_index_id`, `ingest_batch_id`, `parser_run_id`, `job_id`, `(target_alias, status)`, `updated_at`. |
| Uniqueness constraints | Recommended unique `(ingest_batch_id, opensearch_index_id, schema_version)` for non-force runs. |
| Status values | `pending`, `indexing`, `succeeded`, `failed`, `partial`, `retrying`, `cancelled`, `degraded`, `stale`. |
| RLS/security notes | Read through case membership. Writes by indexing workers. |
| Who can read | Authorized case members and Gateway health/status APIs. |
| Who can write | Worker/OpenSearch indexing service. |
| Migration source | `~/.sift/ingest-status`, ingest logs, OpenSearch index state. |
| Notes/open questions | Decide how to reconcile DB success with OpenSearch bulk success/failure ordering. |

### `opensearch_document_refs`

| Detail | Design |
| --- | --- |
| Purpose | Optional table for important or referenced OpenSearch documents. Not recommended for every indexed document in the first schema because volume can be high. |
| Key columns | `id uuid`, `case_id uuid`, `opensearch_index_id uuid`, `document_id text`, `evidence_id uuid null`, `parser_run_id uuid null`, `parser_output_id uuid null`, `ingest_batch_id uuid null`, `job_id uuid null`, `source_hash text null`, `status text`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | Case, index, evidence, parser, batch, and job refs. |
| Indexes | `(case_id, opensearch_index_id, document_id)`, `evidence_id`, `parser_run_id`, `ingest_batch_id`, `source_hash`. |
| Uniqueness constraints | Unique `(opensearch_index_id, document_id)`. |
| Status values | `referenced`, `pinned`, `linked_to_finding`, `linked_to_report`, `retired`. |
| RLS/security notes | Same as OpenSearch document visibility. |
| Who can read | Authorized case members through Gateway/safe views. |
| Who can write | Gateway/search/report/finding service and worker indexing service. |
| Migration source | Future finding/report evidence lookups and selected indexed document refs. |
| Notes/open questions | Defer full document-ref population unless required. Every OpenSearch document should still carry provenance fields in its body. |

## 9A. Evidence Anchoring, RAG, And Agent Skill Tables

These tables retain an existing capability (evidence anchoring, D14) and realize
the locked control-plane scope additions (RAG centralization and retrievable
agent skills, D15). RAG and skills are net-new capabilities specified concretely
here; they are post-foundation work but are not vague "future" items.

### `evidence_anchors`

| Detail | Design |
| --- | --- |
| Purpose | Durable record of external anchoring (e.g. Solana) of evidence integrity proofs. Retains the current anchoring capability whose proof state is file-based today (`evidence-verify-state.json` / Solana proof state, `packages/case-dashboard/src/case_dashboard/routes.py:1034-1074`). |
| Key columns | `id uuid`, `case_id uuid`, `evidence_id uuid null`, `manifest_hash text null`, `anchor_provider text`, `anchor_ref text`, `tx_signature text null`, `anchor_payload_hash text`, `status text`, `anchored_by_user_id uuid null`, `job_id uuid null`, `audit_event_id uuid null`, `anchored_at null`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id`, `evidence_id`, `job_id`, `audit_event_id`, `anchored_by_user_id`. |
| Indexes | `(case_id, created_at)`, `evidence_id`, `status`, `anchor_provider`. |
| Uniqueness constraints | Optional unique `(anchor_provider, tx_signature)` where a signature exists. |
| Status values | `pending`, `submitted`, `confirmed`, `failed`, `superseded`. |
| Anchor providers | `solana`, `none`/`local` for non-chain proof export, extensible. |
| RLS/security notes | Case-scoped reads. Anchoring is a high-risk/approval-gated action; writes through Gateway/worker service paths. |
| Who can read | Authorized case members; Gateway/worker service roles. |
| Who can write | Gateway/evidence service and anchoring worker jobs (`evidence_anchor` job type). |
| Migration source | Solana proof state files and evidence verify-state. |
| Notes/open questions | None. Capability retained (D14); anchoring runs as an approval-gated job. |

### `rag_collections`

| Detail | Design |
| --- | --- |
| Purpose | Registry of RAG knowledge collections centralized into the control plane (D15). Replaces the in-memory Chroma index in `forensic-rag-mcp`. RAG **folds into core** (D23): retrieval is a core, control-plane-backed tool over Supabase `pgvector`, not a standalone add-on backend. |
| Key columns | `id uuid`, `scope text`, `case_id uuid null`, `name text`, `description text null`, `embedding_model text null`, `status text`, `document_count int`, `created_by_user_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id` (null for global/shared collections); `created_by_user_id`. |
| Indexes | `(scope, status)`, `case_id`, unique `(scope, name)`. |
| Uniqueness constraints | Unique `(scope, name)`. |
| Scope values | `global` (shared knowledge), `case` (case-specific). |
| Status values | `active`, `building`, `degraded`, `disabled`, `archived`. |
| RLS/security notes | Global collections readable to authorized operators/agents; case collections case-scoped. Access mediated by Gateway. |
| Who can read | Authorized operators/agents through Gateway. |
| Who can write | Gateway/RAG service path. |
| Migration source | `forensic-rag-mcp` Chroma index and SANS/knowledge corpora. |
| Notes/open questions | Vector storage approach: Postgres `pgvector` is the v1 target for centralization; OpenSearch vector remains available for case artifact search. Confirm pgvector availability in the Supabase Local image at implementation time. |

### `rag_documents`

| Detail | Design |
| --- | --- |
| Purpose | Documents/chunks within a RAG collection, with optional embeddings for retrieval. |
| Key columns | `id uuid`, `collection_id uuid`, `case_id uuid null`, `title text null`, `source_ref text null`, `chunk_index int null`, `content text`, `content_hash text`, `embedding vector null`, `token_count int null`, `status text`, `created_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `collection_id` references `rag_collections(id)`; `case_id` references `cases(id)`. |
| Indexes | `(collection_id, status)`, `content_hash`, vector index on `embedding` (e.g. ivfflat/hnsw via pgvector) when embeddings are used. |
| Uniqueness constraints | Optional unique `(collection_id, content_hash)` to dedupe chunks. |
| Status values | `active`, `superseded`, `retired`. |
| RLS/security notes | Inherits collection scope/visibility. Retrieval is Gateway-mediated. |
| Who can read | Authorized operators/agents through Gateway. |
| Who can write | Gateway/RAG ingestion service. |
| Migration source | RAG corpus files and embeddings. |
| Notes/open questions | `embedding vector` type requires `pgvector`; if unavailable, store embeddings externally and keep a reference. Decide at implementation. |

### `agent_skills`

| Detail | Design |
| --- | --- |
| Purpose | Retrievable agent/operator skill documents (`skills.md`-style playbooks) the agent can fetch on demand (D15). |
| Key columns | `id uuid`, `scope text`, `case_id uuid null`, `name text`, `description text null`, `content text null`, `content_uri text null`, `content_hash text`, `version text`, `tags text[]`, `status text`, `created_by_user_id uuid null`, `created_at`, `updated_at`, `metadata jsonb`. |
| Primary key | `id`. |
| Foreign keys | `case_id` (null for global skills); `created_by_user_id`. |
| Indexes | `(scope, status)`, unique `(scope, name, version)`, `tags` (GIN). |
| Uniqueness constraints | Unique `(scope, name, version)`. |
| Scope values | `global`, `case`. |
| Status values | `active`, `draft`, `deprecated`, `archived`. |
| RLS/security notes | Skills are operator-curated; agents read through Gateway tools, do not self-author final skills without policy. Content may live inline (`content`) or in Supabase Storage (`content_uri`). |
| Who can read | Authorized operators/agents through Gateway. |
| Who can write | Gateway/skill service path; operator-curated. |
| Migration source | New capability; seed from existing operator playbooks/docs. |
| Notes/open questions | None at schema level. Whether agents may propose new skill drafts (status `draft`) is a policy choice, defaulted off. |

## 10. Compatibility And Migration Mapping

| Current source/path/domain | Current authority role | Future table(s) | Bridge strategy | Cutover phase | Deprecation condition | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| Flat case JSON/YAML: `CASE.yaml`, `findings.json`, `timeline.json`, `todos.json`, `iocs.json`, `evidence.json` | Case metadata and investigation records | `cases`, `findings`, `finding_reviews`, `timeline_event_refs`, future TODO/IOC tables, `evidence_objects` | Mirror files into DB, then write DB and export compatibility JSON | After foundational schema and baseline tests | All portal/MCP readers use DB or generated exports | File/DB drift |
| `/var/lib/sift/<case>/evidence-manifest.json` and `evidence-ledger.jsonl` | Evidence integrity proof/authority today | `evidence_objects`, `evidence_manifests`, `evidence_integrity_events` | Preserve artifacts, mirror metadata/events, later DB operational authority with proof export | Evidence job phases | Manifest/ledger preserved as proof/export, not primary workflow authority | Evidence provenance loss |
| `/var/lib/sift/<case>/audit/*.jsonl` | Audit logs today | `audit_events`, optional exports | DB audit first when available, JSONL export during bridge | Audit service phase | JSONL consumers migrated and export verified | Audit gaps or duplicates |
| `/var/lib/sift/<case>/approvals.jsonl` and pending review files | Approval and review state | `approval_requests`, `approval_decisions`, `finding_reviews` | Import/mirror, then DB transactional review/approval | Approval/review phase | Portal review commit uses DB | Approval mismatch |
| `~/.sift/gateway.yaml api_keys` | Raw-token-keyed token registry | `agents`, `service_identities`, `mcp_tokens`, `mcp_token_scopes` | DB hash registry first, legacy fallback read-only/limited during cutover | Auth/token phase | No active legacy raw tokens | Raw token leakage |
| `gateway.yaml case.dir`, `SIFT_CASE_DIR`, `SIFT_CASES_ROOT`, `~/.sift/active_case` | Active case selection | `active_case_state` (+ `cases`, `case_members`) | Control-plane active case set via portal; Gateway propagates DB context. Per D32, no active-case env/pointer/config export bridge. | PR03B / Batch B, see `21` | Stale env/config/pointer values cannot override DB active case | Cross-case confusion |
| `case/agent` Solana proof / evidence verify-state files | Evidence anchoring proof | `evidence_anchors` | Mirror anchor proofs to DB, run anchoring as approval-gated `evidence_anchor` job | Evidence phase | Anchoring proof recorded in DB + proof export | Lost anchor provenance |
| `forensic-rag-mcp` Chroma index / knowledge corpora | RAG knowledge (in-memory/add-on) | `rag_collections`, `rag_documents` | Centralize into control plane (pgvector), Gateway-mediated retrieval | Post-foundation (D15) | RAG served from control plane | Stale/duplicate knowledge |
| Operator playbooks / skill docs (new) | Agent skill retrieval (new) | `agent_skills` | Curate operator skills into control plane; agents retrieve via Gateway tools | Post-foundation (D15) | Skills served from control plane | n/a (net-new) |
| `~/.sift/ingest-status/*.json` | Background ingest progress and PID status | `jobs`, `job_steps`, `parser_runs`, `ingest_batches`, `opensearch_indexing_status` | Mirror/read current status, then DB job status first and export files | JOB-8/JOB-9 | CLI/status tools use DB or generated files | Status drift |
| `~/.sift/ingest-logs/*.log` | Ingest diagnostics | `job_logs` plus retained log artifact refs | Register log metadata and optionally ingest redacted summaries | JOB-8/JOB-9 | Retention/export policy exists | Secret/path leakage |
| `case/agent/run_commands`, `case/extractions`, `case/tmp` | Native/parser output spill | `parser_outputs`, `job_logs`, evidence-derived artifact refs | Register outputs with hashes while preserving files | Parser/native job phases | Output-producing tools create DB lineage | Orphan outputs |
| OpenSearch `case-*` indexes | Derived searchable data | `opensearch_indexes`, `opensearch_indexing_status`, `opensearch_document_refs` where useful | Discover/register legacy indexes, then use case-scoped aliases and DB indexing status | OpenSearch integration phases | All query paths Gateway-mediated and registered | Cross-case search or stale index state |
| Frontend Zustand/cache and polling assumptions | UI cache only, but currently mirrors file-shaped APIs | Safe views and Gateway APIs | Keep frontend cache only, move authority behind DB/Gateway | Frontend job monitoring and later case views | UI no longer encodes file authority | Stale UI state |
| Report drafts and `case/reports/{uuid}.json` | Report draft/saved report state | `reports`, `report_artifacts`, `jobs` | Mirror saved metadata, job-back generation, keep JSON as artifact/export | Report job phase | DB report list/export is authoritative | Lost in-memory drafts |

## 11. RLS And Service-Role Policy Model

Initial RLS/security strategy:

- Enable RLS on human-readable `app` tables.
- Use `case_members` as the primary case membership predicate for human reads.
- Prefer safe read views for frontend dashboards where raw rows include
  sensitive paths, hashes, token metadata, worker details, or log data.
- Allow direct human writes only for low-risk, explicitly approved fields.
  Examples might include personal profile display metadata or non-privileged
  annotations after policy approval.
- Route privileged writes through Gateway service paths: case lifecycle,
  memberships, token issuance/revocation, evidence registration/integrity,
  audit append, approvals, job creation/cancel/retry, report export, archive,
  and destructive actions.
- Worker service role writes are limited by service code to claimed jobs.
  Workers do not decide case authorization; they inherit `case_id` from the
  claimed job.
- MCP/agent access is through Gateway only. In the final target, MCP/agent JWTs
  resolve to app principal/scope rows; `mcp_tokens` and `mcp_token_scopes` are
  compatibility bridge tables while enabled.

Protection notes:

- `audit_events`: append-only; no direct frontend writes; reads role-gated.
  Updates/deletes should be disallowed except for tightly controlled retention
  or correction workflows, if any.
- `mcp_tokens`: raw table service-only. Frontend sees redacted safe views
  without `token_hash`. Token hash lookup is Gateway-only.
- `jobs`: human users can read case-scoped job state. Mutations go through
  Gateway or worker service paths. Frontend never directly sets status.
- `job_logs`: case-scoped but role-gated and redacted. Sensitive logs may need
  elevated role.
- `evidence_objects`: case-scoped metadata, but raw vault access remains
  Gateway/evidence-service mediated. Metadata does not grant raw file access.
- `evidence_integrity_events`: service writes only. Human reads according to
  evidence visibility.
- `opensearch_indexes` and indexing status: case-scoped reads. Writes by
  Gateway/OpenSearch/worker services.

RLS pseudocode examples:

- A human can read a case row if an active `case_members` row exists for
  `auth.uid()` mapped through `operator_profiles`.
- A human can read a job row if the job's `case_id` is in the user's active case
  memberships.
- A human cannot update `jobs.status`; retry/cancel calls go through Gateway.
- A token row is not selected directly by frontend clients. Gateway validates
  token hashes with service credentials and emits audit.

## 12. Initial Enums And Status Values

Use Postgres enums or text with check constraints. Text plus check constraints
can be easier during early migration; enums are stricter but require migration
care when values change.

| Domain | Proposed values |
| --- | --- |
| Case status | `draft`, `active`, `paused`, `closed`, `archived` |
| Operator status | `active`, `disabled`, `invited`, `archived` |
| Case member role | Locked: `owner`, `lead`, `operator`, `readonly`, `admin` (permission matrix in `09_identity_auth_cutover.md` §5) |
| Case member status | `active`, `suspended`, `removed`, `expired` |
| Agent type | `assistant`, `automation`, `service_agent`, `external_client` |
| Agent status | `active`, `disabled`, `revoked`, `archived` |
| Service identity type | `gateway`, `worker`, `maintenance`, `integration` |
| Token status | `active`, `expired`, `revoked`, `disabled` |
| Evidence type | `disk_image`, `memory_image`, `file`, `directory`, `archive`, `log`, `triage_package`, `other` |
| Evidence status | `registered`, `sealed`, `ignored`, `retired`, `missing`, `quarantined`, `archived` |
| Evidence integrity status | `unknown`, `verified`, `changed`, `missing`, `failed`, `warning`, `not_applicable` |
| Evidence integrity event type | `registered`, `sealed`, `hash_computed`, `verified`, `ignored`, `retired`, `anchored`, `manifest_mirrored`, `ledger_mirrored`, `failed` |
| Approval status | `pending`, `approved`, `rejected`, `cancelled`, `expired`, `superseded` |
| Finding status | `proposed`, `pending_review`, `approved`, `rejected`, `superseded`, `archived` |
| Finding severity | `informational`, `low`, `medium`, `high`, `critical` |
| Report status | `draft`, `generating`, `pending_approval`, `approved`, `exported`, `failed`, `archived` |
| Report type | `case_summary`, `finding_report`, `timeline_report`, `evidence_report`, `export_package` |
| Job status | `pending`, `queued`, `running`, `waiting_human`, `succeeded`, `failed`, `retrying`, `cancelled`, `stale`, `paused` |
| Job type | `evidence_register`, `evidence_hash`, `evidence_verify_integrity`, `evidence_anchor`, `evidence_ingest`, `parser_run`, `opensearch_index`, `timeline_build`, `ioc_extract`, `finding_generate`, `report_generate`, `report_export`, `case_archive`, `maintenance_reindex`, `health_check` |
| Job step status | `pending`, `running`, `succeeded`, `failed`, `skipped`, `cancelled`, `stale`, `waiting_human` |
| Job step type | `validate_request`, `resolve_evidence`, `hash_evidence`, `verify_integrity`, `anchor_evidence`, `run_parser`, `register_output`, `bulk_index_opensearch`, `extract_iocs`, `write_report_artifact`, `generate_findings`, `approval_gate`, `cleanup_partial_outputs` |
| TODO status | `open`, `in_progress`, `blocked`, `done`, `cancelled` |
| IOC status | `proposed`, `approved`, `rejected`, `superseded`, `archived` |
| IOC type | `ip`, `domain`, `url`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`, `filename`, `filepath`, `registry_key`, `mutex`, `user_account`, `host`, `other` |
| Evidence anchor status | `pending`, `submitted`, `confirmed`, `failed`, `superseded` |
| Anchor provider | `solana`, `local`, `none` |
| RAG collection scope/status | scope: `global`, `case`; status: `active`, `building`, `degraded`, `disabled`, `archived` |
| Agent skill scope/status | scope: `global`, `case`; status: `active`, `draft`, `deprecated`, `archived` |
| Worker status | `online`, `degraded`, `offline`, `stale`, `draining`, `disabled` |
| Parser run status | `pending`, `running`, `succeeded`, `failed`, `cancelled`, `stale`, `partial` |
| Parser output status | `created`, `ready`, `failed`, `partial`, `indexed`, `retired` |
| Ingest batch status | `planned`, `ready`, `indexing`, `indexed`, `failed`, `partial`, `cancelled`, `retired` |
| OpenSearch index status | `planned`, `creating`, `ready`, `degraded`, `reindexing`, `retired`, `failed` |
| Indexing status | `pending`, `indexing`, `succeeded`, `failed`, `partial`, `retrying`, `cancelled`, `degraded`, `stale` |

## 13. Indexing And Performance Notes

Recommended Postgres indexes before broad rollout:

- Case-scoped tables: index `case_id` on every case-scoped table.
- Time-ordered reads: `(case_id, created_at desc)` for audit, jobs, findings,
  timeline refs, reports, parser runs, and indexing status.
- Status filters: `(case_id, status)` for cases' child tables and `(status,
  created_at)` where system views need cross-case health.
- Token validation: unique index on `mcp_tokens.token_hash`; secondary indexes
  on `token_fingerprint`, `status`, `expires_at`, and `last_used_at`.
- Membership enforcement: unique active membership on `(case_id,
  operator_profile_id)` and lookup on `(operator_profile_id, status)`.
- Idempotency: unique or partial unique indexes for `(case_id, job_type,
  idempotency_key)`, parser run idempotency, ingest batch key, and indexing
  batch uniqueness.
- Job claiming: partial index for queued jobs by status, retry eligibility,
  priority, and age. The claim query should be able to filter `status='queued'`,
  `retry_after is null or retry_after <= now()`, capability/job type, and order
  by priority and `queued_at` before `for update skip locked`.
- Stale detection: index `(status, lease_expires_at)` where status is
  `running`.
- Worker health: index `workers.last_seen_at`, `workers.status`, and active job.
- Job observability: indexes on `(job_id, sequence)` for steps and `(job_id,
  created_at)` for logs.
- Parser lineage: indexes on `parser_runs.evidence_id`,
  `parser_runs.source_hash`, `parser_runs.parser_name`, `parser_outputs.output_hash`,
  and `ingest_batches.batch_key`.
- OpenSearch registry/status: unique `opensearch_indexes.index_name`, alias
  indexes, `(case_id, logical_kind, status)`, and indexing status by
  `ingest_batch_id`, `parser_run_id`, `job_id`, and target alias.
- Audit: `(case_id, created_at desc)`, `(event_type, created_at desc)`,
  actor indexes, `job_id`, and `request_id`.

SKIP LOCKED-style job claiming needs a small, selective runnable-job index.
Exact SQL should wait for implementation, but the design target is a query that
locks eligible queued rows and updates claim fields inside one transaction.

## 14. First Schema PR Recommendation

Historical note: JOB-0 and the first schema-focused PR (PR01 / Phase ID-1) are
complete. This section is retained to explain the original sequencing logic, not
to define the current next run.

Recommended first schema-focused PR after schema approval:

Add Supabase/Postgres migration infrastructure and schema verification harness
if it is missing. Do not add all domain tables in the same PR.

Reasoning:

- Current migration docs still list the exact Supabase Local deployment shape
  and migration layout as open questions.
- Adding table migrations before the migration infrastructure and test command
  are confirmed risks churn.
- A migration-infrastructure PR can be completed in one Codex coding session
  without touching runtime application code.

Exact scope:

- Inspect only the repo's database/Supabase migration layout and test
  conventions.
- Add or document the migration directory, local schema verification command,
  and rollback/reset command if missing and approved.
- Add a placeholder or baseline schema test harness only if the repo convention
  supports it.
- Do not create domain table migrations unless the migration infrastructure is
  already confirmed and the user explicitly approves the table slice.

Likely files to add/change:

- Supabase configuration/migration directory if missing and approved.
- Schema test harness or migration README.
- Migration documentation note.

Tests to add:

- A local migration verification command that proves migrations can be applied
  to an empty local database.
- If no migrations exist yet, a smoke check that the migration toolchain is
  discoverable and documented.

Commands to run:

```bash
git diff --check
```

Plus the repo-approved Supabase/Postgres migration verification command once it
is confirmed.

Acceptance criteria:

- Migration infrastructure is present or clearly documented.
- No application runtime behavior changes.
- No REST, MCP, frontend, OpenSearch, evidence, parser, report, finding, or
  worker code changes.
- No Redis/RQ/Celery/Temporal dependency.
- Future schema table PRs have a known place to put migrations and a known
  verification command.

Rollback strategy:

- Revert the migration infrastructure/docs files. No data rollback is needed if
  no domain migrations are created.

What remains intentionally unchanged:

- All application code and all current file-backed authority.
- All domain table migrations until the schema slice is approved.

Follow-up schema table PR candidate, after infrastructure is approved:

- Add foundational identity tables only (cutover step 1, see
  `09_identity_auth_cutover.md`): `operator_profiles`, `cases`, `case_members`,
  `active_case_state`, `agents`, `service_identities`, `mcp_tokens`,
  `mcp_token_scopes`, and `audit_events`.
- Keep jobs, evidence, parser, OpenSearch, findings, TODOs, IOCs, reports,
  approvals, anchoring, RAG, and skills for later focused PRs, in cutover order.

## 15. Decisions And Open Questions

### Confirmed decisions

- Supabase/Postgres is the control-plane authority.
- OpenSearch is a core search/data plane, not authority.
- No Redis/RQ.
- No Celery, Temporal, or external queue.
- MCP/service tokens are hash-only registry records.
- MCP/service tokens are not normal Supabase Auth user sessions.
- Gateway validates tokens and enforces case scope, tool scope, expiry,
  revocation, and policy.
- Frontend is not forensic state authority.
- Evidence vault behavior is preserved.
- Raw evidence remains immutable.
- Workers claim jobs from Postgres.
- Long-running REST/MCP actions enqueue jobs and return job IDs in the target
  design.
- OpenSearch indexing status is recorded in Postgres.
- Agent findings are not auto-approved.
- Migration remains additive first.

### Decisions now locked (previously "needs approval")

- Keys: UUID PKs plus legacy text keys (D10).
- Namespaces: `app` (RLS) plus `internal`/`svc`; not `public` (D11).
- Human roles: `readonly`, `operator`, `lead`, `owner`, `admin` with the
  permission matrix in `09_identity_auth_cutover.md` §5.
- Token hashing: SHA-256 + server pepper, 16-hex fingerprint, default expiries,
  one-time raw display, dual-validate then sunset legacy; KMS deferred
  (`09_identity_auth_cutover.md` §4, D8).
- `service_identities`: included in the first foundational slice.
- Evidence dedup: preserve by default; `(case_id, sha256)` uniqueness is an
  explicit opt-in policy, never a silent drop (D16).
- OpenSearch indexing: reuse the existing working model (D18). v1 registers the
  current `case-{case_id}-{artifact_type}-{hostname}` indices in
  `opensearch_indexes`; the `dfir-case-*-vN` logical-family rename is deferred/
  optional. OpenSearch 3.5.0 security-on (D6). All writers (core + addon +
  enrichment) follow the write contract in `03` §7A.
- Active case: `active_case_state`, one row per deployment in v1 (D4).
- Retained capabilities: `case_todos`, `iocs`, `evidence_anchors` are first-class
  (D14); `rag_collections`/`rag_documents`/`agent_skills` are first-class
  control-plane scope additions (D15).
- Lean job core: `job_attempts`, `job_cancellations`, `worker_heartbeats`
  deferred (D13).

### Decisions still genuinely open (non-blocking, decide at implementation)

- Exact Supabase Local deployment/migration directory layout (resolved during the
  first schema-infrastructure PR by inspecting the repo).
- Batch granularity for parser/indexing idempotency (source file vs host/artifact
  vs parser run vs bulk chunk) - pick when converting the first parser path
  (JOB-8), default to per-source-file + parser run.
- Which audit events must fail closed if the DB audit write is unavailable -
  default fail-closed set: token issuance, evidence integrity/seal/anchor,
  approvals, and destructive/export/archive actions; confirm during JOB-7.
- pgvector availability in the chosen Supabase Local image (for `rag_documents.embedding`).
- How long compatibility exports remain after DB authority - default 1 release
  cycle past parity for non-active-case surfaces; D32 removes active-case
  env/config/pointer exports from the target.
- `evidence_access_events` and `opensearch_document_refs` remain optional/deferred
  (defer unless a query need appears); `audit_events` covers access initially.

### Code facts still needing confirmation

- Existing Supabase/Postgres migration infrastructure and commands.
- Existing package-specific test layout for schema/migration verification.
- Complete current role/session model that maps to Supabase Auth/RLS.
- Complete list of direct file readers/writers for case JSON, evidence
  manifests, audit JSONL, approvals, report JSON, ingest status/log files, and
  active-case pointers.
- Exact parser metadata emitted by every parser family.
- Which parser outputs are files rather than direct OpenSearch documents.
- External consumers of `~/.sift/ingest-status`, `~/.sift/ingest-logs`,
  active-case pointers, ingest manifests, and legacy `case-*` indexes.
- Current saved report JSON shape and downstream consumers.
- Canonical OpenSearch version/profile for local SIFT VM deployments.

## 16. Next Recommended Run

PR01 / Phase ID-1 implemented the identity foundation schema from this document,
and PR02 / Phase ID-2 implemented DB-first hash-only token validation with
legacy fallback as a bridge. The next schema/runtime planning target is PR03A /
Batch A: unified Supabase JWT authentication for REST and MCP plus
operator/agent/service principal and membership resolution behind the
legacy-auth flag. Jobs, evidence metadata, OpenSearch index registration, RAG,
skills, and remaining control-plane tables stay behind the foundation track
unless explicitly scoped.
