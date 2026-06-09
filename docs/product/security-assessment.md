# Security Assessment Report

Status: validated baseline. Validation owner: BATCH-SEC1.
Last updated: 2026-06-09.

## Scope

Post-MVP SIFT Gateway, Portal, MCP tools, Supabase/Postgres authority plane,
worker/job execution path, OpenSearch/RAG/add-on derived planes, evidence custody
flow, and report export path. Assessed across eight areas: auth/session,
authorization, evidence gate, response leakage, job/worker boundary,
`run_command`, RAG/OpenSearch/add-ons, and report integrity.

## Methodology

- Static review of the BATCH-SEC1 security-critical paths.
- Targeted test execution grounding each control claim (see "Tests run").
- Reuse of BATCH-V1 live VM cutover + leak-scan evidence in `Session-Notes.md`.
- Secret/path leak inspection of agent-visible and report-visible outputs.
- Each finding cites a file+symbol, a test, or a `Session-Notes.md` block. No
  claim is from memory; unverified items are marked "needs live proof".

## Severity Rubric

| Severity | Meaning |
| --- | --- |
| Critical | Agent or remote user can bypass evidence/approval authority, access secrets, or tamper with custody/report truth. |
| High | Auth, authorization, path isolation, or report integrity failure with realistic exploit path. |
| Medium | Defense-in-depth gap, degraded auditability, or limited information leak. |
| Low | Hardening or clarity issue with low exploitability. |
| Informational | Documentation, test coverage, or operational improvement. |

## Result summary

No critical or high validated defect was found; the controls for all eight areas
hold under static review and targeted tests, and match the BATCH-V1 live leak
scans. **No freeze blockers.** Findings below are Informational/Low/Medium
defense-in-depth observations plus the accepted, bounded MVP caveats. The K5
env-leak defect (sandbox subprocess inherited the full worker env including
`~/.sift/supabase.env`) was a genuine High that was already found and fixed in
BATCH-K5 (`Session-Notes.md` 2026-06-08) before this assessment; SEC1 re-verified
the fix rather than re-fixing it.

## Finding Register

| ID | Severity | Status | Area | Component | Finding | Evidence | Remediation | Residual risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-A1 | Informational | NO FINDING | Auth/session | `rest.call_tool`, `auth.is_agent_principal` | Agent/service token cannot bypass MCP policy via REST: `POST /api/v1/tools/{tool}` returns 403 before dispatch for typed agent/service principals; operator types are an allowlist (unknown type → non-operator → fail-closed). | `auth.py:272 is_agent_principal`, `_REST_TOOL_OPERATOR_TYPES`; tests `test_mvp_b1_policy_redaction.py::test_agent_token_blocked_from_rest_tool_execution`, `::test_service_token_blocked...`, `::test_agent_rest_block_does_not_invoke_tool`; `Session-Notes.md` BATCH-B1 (F-MVP-3). | None required. | Anonymous single-user mode treats no-identity as operator (accepted caveat); fails closed when auth is configured. |
| SEC-A2 | Low | OPEN | Auth/session | `policy_middleware.ToolAuthorizationMiddleware` | Per-principal MCP rate limit and tool-scope filter are SIFT-owned and applied for both `list_tools` and `call_tool`; auth-configured-but-no-identity fails closed (B6). Re-auth challenge stores are in-process dicts (single-process uvicorn), so they reset on Gateway restart. | `policy_middleware.py:213-250`; `routes.py:231-254` in-memory challenge stores; `rate_limit.py` sliding window. | Acceptable for single-process MVP; move challenge/override state to a shared store if the Gateway is ever multi-worker. | A Gateway restart cancels in-flight challenges and redaction overrides (fail-safe direction: re-auth required again). |
| SEC-B1 | Informational | NO FINDING | Authorization | `gateway_policy_middlewares`; `ProxyActiveCaseMiddleware` | Portal REST and MCP are intentionally NOT equivalent for agents (REST tools are operator-only); MCP enforces tool scope, active-case binding, and rejects client/DB case mismatch. Proxied case-scoped tools without a safe case arg are denied. | `policy_middleware.py:699-737` (`client_case_mismatch`, `proxy_requires_implicit_case`); tests `test_policy_parity_d27b.py`, `test_pr03b_active_case_policy.py` (12 passed). | None required. | None material. |
| SEC-C1 | Informational | NO FINDING | Evidence gate | `evidence_gate.check_evidence_gate_db`, `EvidenceGateMiddleware` | Evidence gate fails closed pre-seal: missing case_id/DSN, missing chain head, or any DB error → `blocked=True` (UNSEALED/LEDGER_ERROR); middleware blocks every tool call when not OK and audits the block. Seal-tamper is detected (`_detect_seal_tamper` → `evidence_mark_violation`, K3). | `evidence_gate.py:137-208` (`_DB_STATUS_MAP`, fail-closed branches); `policy_middleware.py:443-508`; test `test_mvp_b1_policy_redaction.py::test_mcp_evidence_gate_fail_closed_and_audited`; `Session-Notes.md` BATCH-V1 "pre-seal agent execution failed closed". | None required. | 30s TTL cache on the file-backed path is a freshness hint only, never an integrity assertion; DB path is authority. |
| SEC-D1 | Informational | NO FINDING | Response leakage | `response_guard.guard_tool_result` | No absolute paths or secrets in agent-visible responses: secret redaction (critical/high) then absolute-path redaction (in-case → relative, all other → `[REDACTED:absolute_path]`) then cap; path redaction always runs even under the secret override; the audit retains absolutes. | `response_guard.py:607-676`; tests `test_response_guard.py` + `test_mvp_b1_policy_redaction.py` (37 passed); `Session-Notes.md` BATCH-V1 report-export + `rag_search_case` leak scans (clean for `/cases`,`/home`,loopback,DSN,service-role,OpenSearch). | None required. | Regex-based scanner; a novel secret shape outside `_PATTERNS` could pass — mitigated by env scrub upstream so secrets rarely reach output. |
| SEC-D2 | Low | OPEN | Response leakage | `response_guard._cap_guarded_result`, `policy_middleware.ResponseGuardMiddleware` | Agent-visible `_sift_context` / `_sift_output_capped` (both `result.content` and `result.meta`) carry only the case-relative display path; the absolute spill path is kept only in the local audit `meta` dict, not attached to the agent result. | `response_guard.py:564-604` (`display_file` in structured/meta), `policy_middleware.py:592-613` (`_display_spill_path`). | None required; preserve the relative-only invariant if the cap marker schema changes. | Secret scanner severity rubric ("Generic Password" needs `>=8` chars) could miss very short secrets; low exploitability. |
| SEC-E1 | Informational | NO FINDING | Job/worker boundary | `job_tools.py`, `jobs.py` | Public job spec never carries an absolute path and `spec_internal` is never agent-visible: agent supplies an opaque `evidence_ref`; the Gateway resolves the absolute `evidence_path`/`case_dir` into worker-only `spec_internal`; enqueue returns only `job_id`; `job_status_public` returns an explicit allowlist (no `spec_internal`/`worker_id`/lease/local paths). | `job_tools.py:131-142, 175-185`; `jobs.py:37-56 _PUBLIC_STATUS_FIELDS`, `:140-144 public_dict`; `app.job_status_public` sanitized view; `Session-Notes.md` BATCH-L1/G1 "Public job specs stay path-free; worker-only spec_internal". | None required. | run_command `command` text rides in `spec_public` but is re-validated by the worker security pipeline before execution. |
| SEC-F1 | Informational | NO FINDING | run_command | `security_policy.DENY_FLOOR`, `runtime_acl.build_sandbox_env`, `worker.py` | Deny floor blocks shells/interpreters/network/device tools and wins over any allowlist; env is scrubbed to a tiny allowlist with a post-allowlist secret deny floor at both worker and tool `Popen`; `shell=False` everywhere. | `security_policy.py:14-84 DENY_FLOOR`; `runtime_acl.py:90-172 build_sandbox_env`/`_SECRET_ENV_PATTERNS`; `worker.py:96,164-173`; tests `test_mvp_k5_run_command_isolation.py` (subset of 35 passed). | None required. | OS-level sandbox not yet present (accepted caveat); process-level controls layered. |
| SEC-F2 | Informational | NO FINDING | run_command | `runtime_acl.assert_no_authority_write_target` | run_command refuses to write/redirect onto an authority/proof artifact even inside the write-jail (`PermissionError`), defense-in-depth over host ACLs. | `runtime_acl.py:188-238 AUTHORITY_FILE_BASENAMES`/`_AUTHORITY_PATH_MARKERS`; `worker.py:120-122`; `Session-Notes.md` BATCH-K5 "authority-write deny path". | None required. | DB-active mode keeps authority out of the case dir entirely; this is the bridge backstop. |
| SEC-G1 | Informational | NO FINDING | RLS / service-only RPC | `supabase/migrations/202606081000_evidence_custody.sql` | RLS enabled on every authority table; transition RPCs (seal/ignore/retire/verify/mark_violation/proof_export) granted only to `service_role`, never anon/authenticated; seal/ignore/retire require a non-null `reauth_audit_event_id` or raise `insufficient_privilege`; custody events are append-only (UPDATE/DELETE blocked by trigger) and hash-chained (`prev_hash`/`event_hash`). | `202606081000_evidence_custody.sql:827-889` (RLS + service-only grants), `:266-325` (hash chain), `:240` (append-only trigger), `:515/633/679` (reauth-required). | None required. | Service-role DSN bypasses RLS by design (D12); browser reaches DB only via Gateway. |
| SEC-H1 | Informational | NO FINDING | RAG/OpenSearch/add-ons | `AddonAuthorityMiddleware`, `*/sift-backend.json` | Add-ons cannot seal/approve/bypass: `prohibited_operations` (create/activate_case, seal/register_evidence, approve/reject_finding, approve_report, include_in_report, issue_agent_credential, bypass_gateway) and `required_scopes` are enforced fail-closed before backend dispatch; knowledge RAG is case-neutral (`case_id NULL`). | `policy_middleware.py:306-440`; `opencti-mcp/sift-backend.json` `authority_contract` (`non_authoritative:true`, full prohibited list); `Session-Notes.md` BATCH-H1 + RAG import (`case_bound_chunks=0`). | None required. | Knowledge RAG case-neutrality is correct for reference grounding, not case evidence (accepted limitation). |
| SEC-I1 | Informational | NO FINDING | Report integrity | `reporting.generate_report_data`, `reconcile_verification_db` | Approved-only: a single gate filters to exactly `status == "APPROVED"`; draft/rejected/proposed items are dropped and never re-introduced. DB-active verification reconciles each approved item against its Postgres `content_hash` (K6), detecting post-approval tampering regardless of the legacy JSONL ledger. | `reporting.py:495-501` (approved filter), `:644-654, 710-737` (`reconcile_verification_db`); tests `test_k6_file_authority_removal.py` (subset of 35 passed); `Session-Notes.md` BATCH-K6 + BATCH-V1 report export (approved finding only, leak-scan clean). | None required. | `APPROVED_NO_DB_HASH` items (no recorded hash) are surfaced rather than silently trusted. |
| SEC-AUDIT1 | Informational | NO FINDING | Auth/session (audit) | `AuditEnvelopeMiddleware` | Mutating MCP tools fail closed if the required pre-dispatch DB audit write cannot persist (`audit_unavailable`); read-only tools proceed; unknown tools are treated as mutating (`_tool_read_only` fail-safe). | `policy_middleware.py:768-933`; `Session-Notes.md` BATCH-K1 security-review correction (envelope moved before evidence gate; block results marked as failures). | None required. | Pre-context denials (no case yet) remain local telemetry — accepted caveat. |

## Tests run (this assessment)

- `test_mvp_b1_policy_redaction.py` + `test_response_guard.py` — 37 passed
  (REST agent/service block, in-case→relative + foreign-path redaction, MCP path
  redaction, evidence-gate fail-closed-and-audited, secret redaction under
  override).
- `test_mvp_k5_run_command_isolation.py` + `test_k6_file_authority_removal.py` —
  35 passed (env scrub/secret deny, authority-write refusal, DB content-hash
  reconciliation / file-authority removal).
- `test_policy_parity_d27b.py` + `test_pr03b_active_case_policy.py` — 12 passed
  (policy parity, active-case binding/mismatch).

Run with `uv run --extra full pytest <paths>` in the sec1 worktree.

## Live checks reused (BATCH-V1, `Session-Notes.md` 2026-06-08)

- Pre-seal agent execution failed closed on the unsealed evidence gate; post-seal
  `run_command_job` succeeded with redacted absolute-path output.
- Agent `rag_search_case` and report export leak scans: clean for `/cases`,
  `/home`, loopback, Supabase/service-role/password, Postgres, OpenSearch.
- Report export contained only the approved finding; HMAC re-auth gated approval
  (`authority=db`). Knowledge RAG rows retained `case_id NULL`.

## Accepted residual risks (bounded)

See `security-architecture.md` "Accepted MVP caveats" and
`known-limitations-and-improvements.md`: local HMAC re-auth bridge; pre-context
denials as local telemetry; anonymous single-user mode = operator; no kernel-level
sandbox for `run_command`; OpenSearch single-node yellow health.

## Blockers before demo freeze

None. No critical/high validated defect remains open; the one historical High
(K5 env leak) is fixed and re-verified.

## Follow-ups for other batches

- BATCH-AUT1: SEC-A2 (in-process challenge/override state resets on restart) and
  SEC-D1 regex-scanner residual are agent-facing security observations to weigh in
  the autonomy scorecard.
- BATCH-INST1: confirm `~/.sift/*.env` permissions (chmod 600) and per-case
  `agent_runtime` ACLs on the live VM; confirm no secret persists in generated
  tracked files.
