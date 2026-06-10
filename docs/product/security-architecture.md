# Security Architecture

Status: validated baseline. Validation owner: BATCH-SEC1.
Last updated: 2026-06-09.

This document is the control baseline for the SIFT MCP DFIR platform. It maps the
`AGENTS.md` "Security invariants" to the code that enforces each one, defines the
trust boundaries and threat areas, records the accepted MVP caveats, and states
the assessment method. Findings live in `security-assessment.md`; accepted demo
caveats also appear in `known-limitations-and-improvements.md`. Every control
claim here is grounded to a file+symbol, a test, or a `Session-Notes.md` block —
nothing is asserted from memory.

## Security Thesis

SIFT enables AI-agent autonomy by narrowing, mediating, and auditing the agent's
capabilities. The agent gets MCP tools, not raw evidence paths, shell access,
database credentials, OpenSearch credentials, service-role keys, or report
approval authority. Two planes carry truth — the Gateway (the single policy
boundary) and Postgres/Supabase (the authoritative control plane) — and every
other surface (OpenSearch, RAG, OpenCTI, Windows triage, forensic knowledge,
local case files, file manifests) is derived, reference, or export only and can
never authorize a case, seal evidence, approve a finding, or admit data to a
report.

## Trust Boundaries

| Z | Principal / plane | Trust | Inputs | Outputs | Enforcement point |
| --- | --- | --- | --- | --- | --- |
| Z1 | Human operator (browser) | Authority for human decisions | credentials, case/evidence decisions, approvals | case create/activate, evidence seal, agent key, finding/report approvals | Portal session + per-action re-auth (`case_dashboard/auth.py`, `routes.py`) |
| Z1 | AI agent / MCP client | Lower-trust automation | operator brief, MCP results, opaque IDs | MCP tool calls only | Gateway MCP policy middleware (`policy_middleware.py`) |
| Z2 | SIFT Gateway | Single policy boundary | portal REST, MCP JSON-RPC, health/admin | DB RPCs, job enqueue, guarded tool results | JWT/scope validation, evidence gate, response guard, rate limit, audit envelope |
| Z3 | Postgres/Supabase control plane | Authority plane | service-mediated transition RPCs | authoritative IDs, statuses, read models | RLS + service-only RPCs + append-only hash-chained ledgers (`supabase/migrations/*.sql`) |
| Z4 | Durable job worker | Path-resolving executor | path-free public job specs + worker-only `spec_internal` | DB job rows, path-scrubbed receipts | scrubbed env, authority-write refusal (`execute/worker.py`, `runtime_acl.py`) |
| Z4 | Evidence mount | Operator-managed bytes | sealed evidence files | read bytes under ACL/audit | per-case host ACLs, broker/worker-only path resolution |
| Z5 | Derived/reference planes (OpenSearch, RAG, OpenCTI, Windows triage, forensic knowledge) | Non-authoritative | provenance-stamped docs, query-only lookups | search/intel/context | add-on `authority_contract` enforced by `AddonAuthorityMiddleware` |

The agent (Z1) and the Gateway (Z2) are the same host process boundary for the
MVP; the agent reaches tools only through the FastMCP `/mcp` surface. The Gateway
(Z2) is the only thing that talks to Postgres (Z3) with the service-role DSN; the
browser never holds `service_role` and reaches the DB only through the Gateway.

## Control Objectives

1. The agent never crosses the MCP policy boundary — no REST tool path, no direct
   DB, no service-role key, no shell, no absolute host path.
2. Authority decisions (active case, evidence seal, approvals, report inclusion)
   are made only in Postgres through service-mediated, re-auth-gated transitions.
3. The evidence gate fails closed: nothing agent-facing runs against unsealed or
   violated evidence.
4. No secret and no absolute host path reaches the agent or a report.
5. Derived/reference planes cannot make or alter an authority decision.
6. Every post-context tool call is auditable; mutating calls fail closed if their
   required audit cannot persist.

## Invariant → enforcement map

Each row is an `AGENTS.md` "Security invariants" line and where it is enforced.

| Invariant | Enforced in | Mechanism |
| --- | --- | --- |
| Gateway is the only policy boundary for portal and agent ops | `policy_middleware.gateway_policy_middlewares`; `rest.call_tool` | All MCP calls pass the SIFT middleware chain; REST tool calls by agent/service tokens are 403'd (`is_agent_principal`) so they cannot bypass MCP policy. |
| Supabase/Postgres is the authoritative control plane | `supabase/migrations/202606081000_evidence_custody.sql`, `202606081600_investigation_authority.sql`, `202606081200_durable_jobs.sql`; `active_case_context.AuthorityContext` | Mutable DFIR state lives in DB tables/RPCs; core `CaseManager._require_active_case()` fails closed to the request/worker `AuthorityContext` in DB-active mode instead of reading env/pointer files. |
| Agents use MCP only; portal REST is for operators | `auth.is_agent_principal`; `rest.call_tool` (BATCH-B1 / F-MVP-3) | Typed agent/service principals are rejected from `POST /api/v1/tools/{tool}` before dispatch; operator types are an allowlist so an unknown principal_type is treated as non-operator (fail-closed). |
| Agent never receives absolute evidence/case/mount paths, DB/OpenSearch creds, service-role keys, or shell | `response_guard.guard_tool_result` (secret + absolute-path redaction); `_case_text` (relative display dirs); `jobs._PUBLIC_STATUS_FIELDS` | At the MCP choke point, critical/high secrets are redacted and every absolute path is collapsed to a case-relative display path or `[REDACTED:absolute_path]`; agent-visible job status is an explicit allowlist. |
| Evidence bytes mounted/copied only by the operator on the VM | broker/worker path resolution; `spec_internal` (`job_tools.py`) | The agent passes an opaque `evidence_ref`/`evidence_id`; the Gateway resolves the absolute path server-side into worker-only `spec_internal`. |
| Privileged forensic ops are a narrow, audited allowlist — gateway never root | run_command runs as restricted `agent_runtime` (`worker.py` writable HOME/XDG jail, no root); disk-image ingest mounting via `scripts/setup-ingest-mount-sudoers.sh` → `/etc/sudoers.d/sift-ingest-mount` | Agent tool exec needs no root (writable jail for caches/symbols). Ingest mounting (xmount/ewfmount/mount/losetup/qemu-nbd/modprobe nbd/partprobe/umount/fusermount) is a full-path, no-wildcard sudoers allowlist (modprobe pinned to nbd; `tee` excluded; `visudo`-validated). Enforced once the service runs as a dedicated non-admin user without a blanket NOPASSWD grant. |
| Evidence must be registered and sealed before analysis | `evidence_gate.check_evidence_gate_db` / `check_evidence_gate`; `EvidenceGateMiddleware` | DB-authority gate reads `app.evidence_gate_status`; fail-closed on any error/missing head; middleware blocks all tool calls when not OK and audits the block. |
| Sensitive human actions require password/HMAC re-auth | `routes._verify_evidence_hmac`, `_record_reauth_event`; evidence RPCs `evidence_seal/ignore/retire/reacquire` | Constant-time HMAC challenge (TTL + IP-bound + examiner-bound + one-time), producing a `reauth_audit_event_id` that the service-only seal/ignore/retire/reacquire RPCs require (`raise insufficient_privilege` if null). Re-acquisition (re-seal of a legitimately changed item) is held to the same re-auth bar and additionally requires a non-empty operator reason; it supersedes the prior sealed hash in an append-only custody event rather than overwriting history. |
| Derived/reference planes do not authorize cases or evidence | `policy_middleware.AddonAuthorityMiddleware`; `*/sift-backend.json` `authority_contract` | `required_scopes` and `prohibited_operations` (seal/approve/bypass/...) are enforced fail-closed before backend dispatch; knowledge RAG is case-neutral (`case_id NULL`). |
| Reports include approved findings and approved supporting data only | `reporting.generate_report_data` (line ~500) | Single gate filters items to exactly `status == "APPROVED"`; in DB-active mode report verification reconciles against the per-row DB `content_hash` (K6) so post-approval tampering is detected. |
| No raw MCP/service tokens, Supabase secrets, OpenSearch passwords, or VM secrets in repo files | `runtime_acl.build_sandbox_env`; control-plane env handling (`~/.sift/*.env`, chmod 600, systemd `EnvironmentFile`) | Secrets live in VM-local env files, never repo files; the sandbox subprocess env is scrubbed to a tiny allowlist with a post-allowlist secret deny floor. |

## Middleware execution order (defense-in-depth chain)

`gateway_policy_middlewares` returns the FastMCP chain in this order; ordering is
itself a control (the K1 security-review correction moved the audit envelope to
sit after case-context but before proxy/evidence-gate so denials are recorded —
`Session-Notes.md` 2026-06-08 "BATCH-K1 landed with security-review correction"):

1. `ToolAuthorizationMiddleware` — per-principal tool scope for list AND call;
   fail-closed when auth is configured but no SIFT identity resolves (B6).
2. `AddonAuthorityMiddleware` — add-on `required_scopes` / `prohibited_operations`.
3. `CaseContextMiddleware` — resolves the Postgres active case into the core
   `AuthorityContext`; denies case-scoped tools with no active case.
4. `AuditEnvelopeMiddleware` — DB-first `requested` envelope before dispatch;
   mutating tools fail closed if the required pre-dispatch audit write fails.
5. `ProxyActiveCaseMiddleware` — injects DB case args for safe proxied tools or
   denies implicit-env tools and client/DB case mismatches.
6. `EvidenceGateMiddleware` — blocks every tool call when the chain is not OK.
7. `ResponseGuardMiddleware` — redact (secret then absolute-path) then cap,
   redact-then-cap so a secret can never straddle a truncation boundary.

## Authority cutover model (DB-active invariant)

The blocking migration was an authority migration, not a file migration
(`Migration-Spec.md` "Authority cutover impact model"). In DB-active mode:

- Critical mutable state (active case, evidence seal state, custody chain head,
  findings/timeline/TODOs/IOCs, approvals, report metadata, jobs, agent
  tokens/scopes) is decided only in Postgres; case-local files, env pointers, and
  legacy JSON/JSONL are export/workspace/debug/parser-compat only.
- Evidence proof export re-hashes the mounted bytes and records the proof in DB
  (`evidence_record_proof_export`); the file manifest is an export.
- Report verification reconciles against DB `content_hash`, never the local
  verification JSONL ledger (K6).

## run_command isolation model

`run_command` is the deepest agent capability and has the tightest controls:

- `shell=False` on every spawn (`execute/worker.py`, `executor.py`); no nested
  shell is ever invoked.
- Hardcoded `DENY_FLOOR` (`security_policy.py`) blocks shells, interpreters,
  pagers/editors, network tools (`nc`/`ncat`/`socat`), device-destruction tools,
  and `env`/`printenv`; the deny floor wins even under an operator allowlist.
- `MVP_FORENSIC_ALLOWLIST` is a read-only/inspection forensic set (TSK, registry,
  evtx, etc.); imaging/acquisition tooling is excluded.
- Env scrub (`runtime_acl.build_sandbox_env`): a tiny safe allowlist (PATH,
  locale, HOME/TMPDIR, `SIFT_EXECUTE_*` knobs) survives; a post-allowlist secret
  deny floor (DSN, supabase, service_role, opensearch, jwt, ssh, ...) drops
  anything secret-named even if a future allowlist entry matched. Applied at both
  the isolated-worker spawn and the final tool `Popen`.
- Authority-file write refusal (`assert_no_authority_write_target`): redirect
  targets that resolve onto a known authority/proof artifact name are refused
  with `PermissionError`, even inside the agent/extractions/tmp write-jail.
- Output flows back through the Gateway response guard (redact + 256 KiB cap with
  case-relative spill pointer); the agent gets relative display paths and hashes.

## Accepted MVP caveats (bounded)

These are explicit, bounded, and do not break the security thesis. They are
mirrored in `known-limitations-and-improvements.md`.

| Caveat | Why bounded | Improvement path |
| --- | --- | --- |
| Re-auth uses a local password/HMAC bridge (`reauth_method=local_hmac_mvp_bridge`) for sensitive actions. | Constant-time, TTL+IP+examiner-bound, one-time challenge; still produces the DB `reauth_audit_event_id` the service-only RPCs require. | Move to Supabase password re-auth / session verification. |
| Some pre-context denials are Gateway local security telemetry, not `app.audit_events`. | These are denials before any case context exists; post-context calls and all mutations are DB-audited and fail closed. | Hardened DB projector for attributable pre-context denials (B-MVP-17 follow-up). |
| Anonymous single-user mode treats no-identity/no-role as operator. | Only reachable when no verifier/keys/registry are configured; any configured-auth deployment fails closed (B6) and rejects untyped agents. | Keep auth configured in any multi-principal deployment. |
| OS-level sandbox (namespaces/seccomp) for `run_command` is not yet in place. | Process-level controls (shell=False, deny floor, env scrub, write-jail, authority-write refusal, resource limits) are layered; a denied binary cannot be re-enabled. | Add a kernel-level sandbox profile for the worker. |
| OpenSearch single-node VM reports yellow cluster health. | Indexing/search work; OpenSearch is derived/rebuildable, not authority. | Multi-node / replica-adjusted production profile. |

## Assessment Method

1. Static review of every security-critical path listed in the BATCH-SEC1 scope
   (Gateway auth/policy, response guard, evidence gate, jobs/`spec_internal`,
   `run_command` isolation, Supabase migrations/RPCs, portal re-auth, add-on
   contracts).
2. Targeted test execution grounding each control claim (see
   `security-assessment.md` "Tests run").
3. Reuse of the BATCH-V1 live VM cutover evidence and leak scans recorded in
   `Session-Notes.md` (agent-visible responses and report export proven clean of
   `/cases`, `/home`, loopback, DSN, service-role/password, OpenSearch strings).
4. For each of the eight assessment areas, record a tested finding or an explicit
   "no finding" note with evidence; any validated critical/high is fixed-with-test
   or listed as a freeze blocker.
