# Environment profile: Protocol SIFT Gateway (sift-mcps)

Concrete architecture of THIS repo. Use it to ground every assessment in real
component names, file paths, and trust boundaries instead of a generic template.
When a fact here disagrees with the code, the code wins — update this file (it is
a living document; see `repo-security-baseline.md`).

Host repo path: `/home/yk/AI/SIFTHACK/sift-mcps`. VM staged runtime: `/opt/sift-mcps`.
State/secrets root: `/var/lib/sift` (SIFT_HOME = `/var/lib/sift/.sift`). Cases +
evidence: `/cases`.

## The one architectural invariant

**The Gateway is the SOLE policy boundary for portal and AI-agent operations.**
Agents use MCP only; the operator portal uses REST. Supabase/Postgres is the
authoritative control plane. Everything else (add-on MCP backends, the worker,
OpenSearch) sits behind the Gateway and is subject to its policy. A consequence
that shapes the whole threat model: a misbehaving or untrusted *client* (including
agent-written code that speaks MCP) cannot escape policy, because enforcement is
server-side at the Gateway, not client-side.

## Packages (workspace members)

- `sift-gateway` — the policy boundary. FastMCP 3.x aggregator + Starlette/FastAPI
  REST + auth. Aggregates in-process core tools plus mounted add-on backend
  proxies onto one `/mcp` surface.
- `sift-core` — in-process core tools (run_command, record_finding,
  record_timeline_event, case/evidence IO) + the run_command executor + the
  evidence chain + investigation store. NOT an MCP server itself; called in-process
  by the gateway.
- `sift-common` — shared lib (audit writer, redaction helpers). Layer below core;
  must not import sift-core.
- `case-dashboard` — operator portal backend (REST routes, review/approval path).
- `opensearch-mcp` — add-on backend: ingest (disk/memory/logs via Hayabusa,
  Volatility, etc.) + search/aggregate/timeline. The ONLY ingest+query driver.
  SPLIT execution (2026-06-14): the privileged ingest/enrich pipeline does NOT run
  as a stdio child of the gateway — it would inherit the gateway's private/slave
  mount namespace and FUSE E01 mounts fail. The gateway enqueues a durable
  ingest/enrich job; a dedicated least-privilege `sift-opensearch-worker@` systemd
  unit (`MountFlags=shared` is its only relaxation vs `sift-job-worker`) claims and
  runs it (`opensearch_mcp/ingest_job.py`, console script `sift-opensearch-worker`,
  N instances via `FOR UPDATE SKIP LOCKED`). Query tools (search/aggregate/timeline
  /count/field_values/list_detections) need no FUSE and stay on the thin in-gateway
  proxy.
- `forensic-rag-mcp` (namespace `kb`) — add-on backend: global IR/DFIR knowledge
  corpus in Supabase pgvector. Non-authoritative reference plane; `query_only`.
- `forensic-knowledge` — FK enrichment data loader (tool guidance bundled with
  responses).
- `opencti-mcp`, `windows-triage-mcp` — external add-ons (NOT in the native core
  installer; bound by the Backend Contract / add-on schema). Not deployed live yet.

## Gateway security-relevant files (`packages/sift-gateway/src/sift_gateway/`)

- `mcp_server.py` — FastMCP aggregate server; mounts add-on proxies
  (`mount_single_addon_proxy`), `GatewayToolCatalogMiddleware` (tool catalog +
  `_normalize_output_schema`), tool filtering.
- `policy_middleware.py` — the enforcement stack: `AuditEnvelopeMiddleware`
  (writes mcp.tool.call/result to `app.audit_events`, fail-closed for mutating
  tools), `ProxyActiveCaseMiddleware` / active-case injection,
  `AddonAuthorityMiddleware` (add-on authority contract), evidence-gate checks.
- `audit_helpers.py` — `DbAuditWriter.record()`, `redact_for_audit()`
  (secret+path redaction then bounding), run_command detail extraction.
- `response_guard.py` — `redact_structured` / `redact_paths_structured` (the
  trusted redaction primitives reused everywhere agent-facing data is emitted).
- `evidence_gate.py` — DB evidence-gate: blocks every agent tool unless evidence
  is registered + sealed + chain_status OK.
- `auth.py` / `supabase_auth.py` / `token_registry.py` / `token_gen.py` —
  credential verification; Supabase is the re-auth authority.
- `mcp_backends_registry.py` — `app.mcp_backends` DB registry (manifest,
  `default_case_scoped`, data_plane, authority_contract).
- `server.py` — `Gateway` orchestration, `is_case_scoped_tool`,
  `safe_case_argument_names`, lifespan (backend reconcile + pre-serve warm-up).

## run_command executor (`packages/sift-core/src/sift_core/execute/`)

- `security.py` / `security_policy.py` — the single parser+policy. shell=False,
  parsed argv, deny-floor (interpreters sh/bash/python/perl/ruby/node blocked;
  awk system()/getline blocked; pager/editor/media-destroyers blocked), redirect
  sentinel handling, path-shadow defense (execute resolved binary, not argv[0]).
- `executor.py` / `worker.py` — runs staged argv via `subprocess.Popen(shell=False)`
  as `agent_runtime` via `sudo -n -u`; cgroup/rlimit containment (systemd-run),
  NOT a real sandbox.
- `runtime_acl.py` — agent_runtime user isolation / ACLs.

## Data planes (DB tables, schema `app`)

Authoritative control plane (Supabase/Postgres). Key tables:
- Cases: `app.cases`, `app.active_case_state`, `app.case_members`,
  `app.operator_profiles`, `app.service_identities`.
- Investigation (DB-authoritative, content-hashed): `app.investigation_findings`,
  `app.investigation_timeline_events`, `app.investigation_iocs`,
  `app.investigation_todos`.
- Audit (authoritative): `app.audit_events` (envelope + run_command detail in
  `details` jsonb).
- Evidence custody (append-only hash chain): `app.evidence_objects`,
  `app.evidence_versions`, `app.evidence_custody_events`,
  `app.evidence_chain_heads`, `app.evidence_proof_exports`.
- Approval ledger (append-only hash chain, FORK-2): `app.approval_commit_events`,
  `app.approval_commit_heads`.
- Backends: `app.mcp_backends`. Search index registry: `app.opensearch_indices`.

Non-authoritative file mirrors live under `/cases/<case>/` (CASE.yaml,
findings/timeline/iocs/todos/evidence.json, audit/*.jsonl). DB wins; files are
export/proof/legacy-mirror. See `docs/operator/case-directory-layout.md` and
`docs/operator/state-authority-map.md`.

## Trust boundaries (assess each)

1. Operator browser/portal → REST (Supabase-auth, re-auth gated).
2. AI agent → `/mcp` (agent JWT; gateway policy stack).
3. Gateway → add-on backend proxies (stdio/http subprocesses; Backend Contract).
4. Gateway/core → run_command → `agent_runtime` user on the host (deny-floor +
   privilege drop). Highest-risk boundary.
5. Gateway/worker → Supabase service-role DSN (BYPASSRLS; backend-only).
6. Gateway → OpenSearch (loopback, security plugin disabled = lab posture).
7. Evidence vault `/cases/<case>/evidence/` — sealed + chattr +i immutable.

## Known pain points / residual risk (verify current state before asserting)

- OS-level run_command sandbox is cgroup/rlimit only (same fs/net as agent_runtime
  user); no bwrap/nsjail. Deployment-phase item.
- OpenSearch security plugin disabled; loopback-only lab posture (not for non-lab).
- Supabase local stack uses CLI demo secrets (BATCH-SB1 self-managed compose is the
  non-lab fix; deferred).
- AppArmor profile COMPLAIN-only (enforce post-LV1).
- Docker can carry a stale `HTTP_PROXY` drop-in (`/etc/systemd/system/
  docker.service.d/http-proxy.conf`) that silently breaks image pulls.
