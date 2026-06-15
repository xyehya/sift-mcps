# API Contracts

Status: archival — REST contracts and auth model remain accurate.
No stale facts requiring correction were found by BATCH-RG1 (2026-06-13).
See `docs/operator/maintenance-guide.md` for the current operator login and
credential flow.
Last updated: 2026-06-13 (RG1 review — no corrections needed).

## Scope

Operator-facing Portal/Gateway REST contracts. The AI agent does NOT use REST for
the MVP — agent/service tokens are rejected on REST tool execution (see
"Operator-only REST" below). MCP tool contracts live in `mcp-contracts.md`.

Every contract below cites a source symbol. Items not yet exercised by a test or a
live BATCH-V1 block are marked `Status: needs live proof`. No raw secrets, tokens,
DSNs, or passwords appear here.

## Source map (single home per fact)

| Concern | Source of truth |
| --- | --- |
| Portal route table | `case_dashboard/routes.py` `create_dashboard_v2_app()` `Route(...)` list (≈ lines 5983-6061) |
| Portal session auth / principal resolution | `case_dashboard/auth.py` `PortalSessionMiddleware.dispatch` |
| Portal RBAC (examiner vs readonly) | `routes.py` `_require_examiner_role` / `_require_portal_role` / `_require_owner_or_admin` |
| Re-auth (password/HMAC) | `routes.py` `_verify_evidence_hmac`, `get_*_challenge`, `_record_reauth_event` |
| Gateway REST v1 route table | `sift_gateway/rest.py` `rest_routes()` |
| Operator-only REST enforcement | `rest.py` `call_tool` + `sift_gateway/auth.py` `is_agent_principal` |
| Health | `sift_gateway/health.py` `health_endpoint` / `health_routes` |

## Actors and auth methods

- **operator** — a human examiner/owner/admin. Authenticated by a Supabase session
  envelope cookie (`PortalSessionMiddleware._resolve_supabase`, `auth.py`), or, only
  when `legacy_portal_session_enabled` is true, by a legacy `sift_session` JWT cookie
  or `Authorization: Bearer` examiner api-key (`auth.py` dispatch steps 2-3). Only
  `principal_type == "operator"` is mapped to an `examiner` identity and a portal
  role (`auth.py` `_examiner_role_from_principal`). Agent/service principals are
  deliberately left with no `(examiner, role)`, so every portal handler that calls
  `_resolve_examiner` / `_require_examiner_role` returns 401/403 for them.
- **agent / service** — non-human MCP principals. On the Gateway REST `/api/v1/tools/*`
  surface they are detected by `is_agent_principal` and returned **403** (operator-only
  REST, MVP — see F-MVP-3 note in `rest.py` `call_tool`). They use `/mcp` instead.
- **service (gateway internal)** — health/join/setup endpoints; join is its own
  bearer/one-time-code boundary (`rest.py` `join_gateway`).

### Portal RBAC roles

`examiner` (read+mutate), `readonly` (read only). Mapped from the principal's
`system_role`: `readonly` stays readonly; everything else (operator/lead/owner/admin)
becomes `examiner` (`auth.py` `_examiner_role_from_principal`). Owner/admin-only
endpoints (principal issuance/revoke) use `_require_owner_or_admin`.

### Re-auth (password/HMAC) gate

Sensitive operator actions require a fresh password proof on top of the session. The
pattern is a challenge/response HMAC: GET a `*/challenge` endpoint to obtain
`{challenge_id, nonce, salt, iterations=600000, hash_algorithm="SHA-256",
reauth_method="local_hmac_mvp_bridge"}`, then POST the action with
`{challenge_id, response}` where `response = HMAC_SHA256(stored_pw_hash, nonce)`
(`routes.py` `get_evidence_chain_challenge` / `_verify_evidence_hmac`). Challenges are
single-use, TTL ≈ 30s, and IP-bound (`bound_ip`). In DB-active mode the re-auth also
writes an audit event whose id (`_record_reauth_event` →
`request.state.reauth_audit_event_id`) is **required** by the C1 seal/ignore/retire
RPCs; absence ⇒ 403. Re-auth-gated actions: case activation, evidence
seal/ignore/retire, ledger HMAC verify, finding approval (commit), and report
generation/inclusion.

## Operator-only REST (MVP, ground truth)

`rest.py` `call_tool` (POST `/api/v1/tools/{tool_name}`): before any body parsing, if
`is_agent_principal(request)` it logs and returns **403**
`{"error": "REST tool execution is operator-only; agents must use the Gateway MCP
surface", "tool": ...}`. Rationale in-code (F-MVP-3): only `/mcp` runs the SIFT policy
middleware (tool authz + add-on authority + evidence gate + response guard +
per-principal rate limit), so REST tool execution would bypass that boundary. The
agent journey therefore never calls REST. `is_agent_principal` resolves from the
`Identity.principal_type` first, falling back to `request.state.role in
{"agent","service"}`; anonymous single-user mode is treated as operator
(`auth.py:272`).

## Contract template

```text
Endpoint / Method / Actor / Auth / Required role/scope / Request / Response /
State transition / Re-auth required / Audit behavior / Failure modes /
Security notes / Tests-or-live-proof
```

---

## Group: Auth / session

Authority: Supabase Auth + operator profile status. Routes: `routes.py` ≈6025-6034.

### POST `/api/auth/login`
- Actor: operator. Auth: establishes session (challenge/response over local PBKDF2 in
  legacy mode; Supabase login when `_SUPABASE_AUTH` wired). Source: `post_auth_login`
  (routes.py:3717).
- Response: sets the session envelope (or legacy `sift_session`) cookie; body carries
  operator identity + `must_reset` flag.
- State transition: anonymous → authenticated operator session. An `invited` operator
  may log in but is forced into reset (F-MVP-6 fix: login allows `active`+`invited`).
- Failure modes: 401 bad credentials; 429 login lockout (`_check_login_lockout`,
  5 attempts / 900s, separate `login:` namespace).
- Live proof: BATCH-V1 (2026-06-08) — "invited operator can log in, receives
  `must_reset`, completes forced reset, `invited -> active`."

### GET `/api/auth/challenge`
- Issues a login challenge nonce + salt/iterations for legacy password proof.
  Disabled when `_legacy_password_auth_disabled()` (Supabase mode) → 403. Source:
  `get_auth_challenge`.

### POST `/api/auth/forced-reset`  (`post_supabase_forced_reset`, 3668)
- Actor: operator with `must_reset_password`. Transitions profile `invited → active`
  and clears the reset flag. Re-auth: current/temp password. Status: live-proven
  (BATCH-V1 forced reset).

### POST `/api/auth/reset-password` (`post_auth_reset_password`)
- Legacy password rotation; clears `must_reset`. Disabled in Supabase mode.

### POST `/api/auth/refresh` (`post_supabase_refresh`, 3612)
- Rotates the Supabase session envelope from the refresh token. Only `operator`
  principals are refreshable through the portal cookie (agent/service JWTs belong on
  `/mcp`, never the portal cookie — `auth.py:188-204`).

### POST `/api/auth/logout` (`post_auth_logout`, 3899)
- Clears the session cookie / revokes the JTI (`revoke_jti`). State: authenticated →
  anonymous.

### GET `/api/auth/me` (`get_auth_me`, 3948)
- Returns the current operator identity/role. 401 when unauthenticated.

### GET `/api/auth/setup-required`, POST `/api/auth/setup`
- First-run local operator bootstrap (legacy). Disabled when Supabase auth is wired.

Security notes (group): cookies are `HttpOnly; Secure; SameSite` (`auth.py`
`_set_envelope_cookie`). Failed-auth lockout files are mode-0600. No password or token
material is ever returned except one-time principal issuance (below).

## Group: Agent principals (owner/admin only, re-auth context)

Authority: Supabase principals + `app.principal_tool_scopes`. Routes ≈6036-6042.

### GET `/api/auth/principals` (`list_principals`, 4485) — owner/admin only.
### POST `/api/auth/principals` (`create_principal`, 4526)
- Actor: operator, `_require_owner_or_admin`. Issues an `agent` or `service` Supabase
  principal with `tool_scopes` and (for agents) a default `case_id`.
- Request: `{kind: "agent"|"service", display_name, system_role?, tool_scopes:[...],
  case_id?}`. Agent issuance requires an active DB case (409
  `An active DB case is required...` if none).
- Response (201): `{principal_type, principal_id, auth_user_id, display_name,
  default_case_id, access_token, refresh_token, expires_at, token_fingerprint,
  warning}` — **token material is returned exactly once and stored nowhere**
  (routes.py:4605, "cannot be recovered").
- Failure modes: 403 non-owner/admin; 503 Supabase not configured; 400 invalid
  kind/display_name/system_role/tool_scopes; 409 no active case (agent).
- Audit: `Principal created: type/id/by` logged (no token material).
- Security note: `tool_scopes` map onto the MCP grammar consumed by
  `is_tool_allowed` (`mcp:*` / `tool:<name>` / `namespace:<pfx>`) — see
  `mcp-contracts.md` scopes section. **Do not paste issued tokens into any doc.**
- Live proof: BATCH-V1 — "live agent token was issued with default case binding...
  Token material stayed VM-local."

### DELETE `/api/auth/principals/{principal_type}/{principal_id}` (`revoke_principal`, 4624)
- Owner/admin only; disables + revokes the principal and its scopes. 400 invalid
  type/id; 503 if Supabase unwired.

## Group: Cases

Authority: Postgres `app.cases` / `deployment_active_case` (DB active-case authority,
not a file pointer). Routes ≈6049-6052.

### POST `/api/case/create` (`post_case_create`, 4993)
- Actor: operator/examiner. Creates a case (frozen naming e.g. `case-v1gate-06081857`)
  and may activate it; per-case agent-runtime ACL configured
  (`_configure_agent_runtime_case_acl`). Live-proven (BATCH-V1 case create/activate).
### GET `/api/cases` (`get_cases`) — list cases.
### GET `/api/case/activate/challenge` (`get_case_activate_challenge`, 4832)
- Issues the activation re-auth challenge (legacy HMAC path).
### POST `/api/case/activate` (`post_case_activate`, 4891)
- Re-auth required: yes (password/HMAC). In DB mode (`_ACTIVE_CASES` wired) it calls
  `set_active_case(case_id, principal)` and returns the active case dict; legacy mode
  validates the HMAC challenge (`activate:` lockout namespace).
- State transition: selected case → DB active case (`authority: postgres`).
- Failure: 401 no examiner; 403 IP mismatch / non-examiner; 404 unknown case; 429
  lockout. Live-proven BATCH-V1.
### GET `/api/case` (`get_case`), POST `/api/case/metadata` — read/update case metadata.

## Group: Evidence chain (custody, re-auth gated)

Authority: DB custody chain (C1 RPCs) with file-backed fallback; evidence gate
authority. Routes ≈6011-6019. All mutations require examiner role + `must_reset=false`
+ HMAC re-auth; DB-active mutations additionally require a `reauth_audit_event_id`.

### GET `/api/evidence/chain/status` (`get_evidence_chain_status`, 993)
- Read-only. Prefers DB authority (`_db_evidence_chain_status` → `app.evidence_gate_
  status`); returns `{authority: "db"|"file", status/seal_status, manifest_version,
  active_count, issues, head_hash, hmac_last_verified_at, anchor{...}, proof_export?}`.
  Role: examiner or readonly.
### POST `/api/evidence/chain/rescan` (`post_evidence_chain_rescan`, 1014)
- Examiner; drops the evidence gate cache and returns fresh status.
### GET `/api/evidence/chain/challenge` (`get_evidence_chain_challenge`, 1034)
- Issues the seal/ignore re-auth challenge `{challenge_id, nonce, salt,
  iterations=600000, hash_algorithm, reauth_method}`. 403 if must-reset/no password;
  429 lockout (`evidence:` namespace).
### POST `/api/evidence/chain/seal` (`post_evidence_chain_seal`, 1081)
- Request: `{challenge_id, response, file_specs:[{path, source?, description?}]}`.
- State transition: registers + seals a new manifest version (atomic
  `register_and_seal`, MVP), bumping `manifest_version`; flips the evidence gate to
  `sealed`/OK so MCP tools unblock. DB path then derives a proof export (and optional
  Solana anchor, non-blocking).
- Response: `{sealed:true, authority, registration_mode, reauth_method,
  manifest_version, seal_status, files_added:[...], proof_export?, anchor?}`.
- Re-auth: HMAC required; DB path requires a `reauth_audit_event_id` (403 if absent).
- Failure: 401 bad HMAC / no examiner; 400 bad file_specs / FileNotFound; 500 seal
  error.
- Audit: custody events `EVIDENCE_DETECTED → EVIDENCE_REGISTERED → MANIFEST_SEALED`,
  append-only, prev/event-hash linked (BATCH-V1).
- Live proof: BATCH-V1 — sealed `evidence/v1-gate.log` + `evidence/v1-ingest.jsonl`,
  `manifest_version=2`, proof export ids + proof hash recorded.
### POST `/api/evidence/chain/ignore` (`post_evidence_chain_ignore`, 1215)
- Marks an unregistered file intentionally ignored. Request `{challenge_id, response,
  path, reason}`; HMAC + (DB) reauth event required. Response `{ignored:true,...}`.
### POST `/api/evidence/chain/retire` (`post_evidence_chain_retire`, 1310)
- Retires an ACTIVE file (records `FILE_RETIRED`, clears immutable flag, deletes from
  disk in file mode). Request `{challenge_id, response, path, reason}`; HMAC + reauth
  event required.
### POST `/api/evidence/chain/verify-hmac` (`post_evidence_chain_verify_hmac`, 1426)
- Full ledger HMAC re-verification; records `last_hmac_verified_at`. HMAC required.
  Returns `{ok, verified, failed, failed_indices, verified_at, verified_by}`.
### POST `/api/evidence/chain/anchor`, `/proof-export`
- Solana anchor / DB proof export of the sealed manifest (operator examiner; proof is
  external/optional and never blocks the seal).
- Security note (group): only relative display paths and seal/custody summary fields
  are surfaced — never absolute mount paths (`_db_evidence_chain_status` docstring,
  routes.py:879).

## Group: Investigation records (findings / timeline / IOCs / todos / commit)

Authority: DB-backed records + content hashes; agent-authored rows stay proposed/draft
until human approval. Routes ≈5991-6006.

### GET `/api/findings`, `/api/findings/{id}`, `/api/timeline`, `/api/iocs`, `/api/audit/{finding_id}`, `/api/summary`
- Read endpoints (examiner or readonly). `_verify_items` annotates each record with a
  `verification` state (draft / confirmed / tampered / unverified / no approval record)
  by recomputing the content hash.
### TODOs: GET/POST `/api/todos`, PATCH/DELETE `/api/todos/{todo_id}`
- Examiner mutations of investigation TODOs (DB todo authority when wired).
### GET `/api/delta`, POST `/api/delta`, DELETE `/api/delta/{id}`
- The finding-review delta set (proposed approvals/modifications/rejections) staged
  before commit. `_VALID_DELTA_KEYS` / `_DELTA_EDITABLE_FIELDS` bound what an examiner
  may edit.
### GET `/api/commit/challenge` (`get_commit_challenge`, 3206) + POST `/api/commit` (`post_commit`, 3259)
- The human approval action. Re-auth: HMAC required (`commit` lockout namespace,
  3 attempts / 900s). Applies the staged delta — approves/rejects findings/timeline/
  IOCs and writes approval records with `content_hash_at_review`, transitioning rows
  DRAFT → COMMITTED/REJECTED.
- Security note: this is the operator gate that turns an agent's DRAFT finding into an
  approved, reportable finding. Live-proven: BATCH-V1 — `F-hermes-v1-gate-001`
  approved via portal HMAC re-auth (`authority=db, approved=1`).

## Group: Reports (approved-only, re-auth gated)

Authority: DB report metadata + approved-only eligibility. Routes ≈5985-5990.

### GET `/api/reports` (`get_reports`, 5567) — list report metadata (DB authority).
### GET `/api/reports/challenge` (`get_report_challenge`, 5558) — report re-auth challenge.
### POST `/api/reports/generate` (`generate_report_route`, 5613)
- Actor: operator examiner. **Approved-only gate**: 409 `No approved findings...` when
  `_report_eligibility()` says ineligible (routes.py:5625). Re-auth: `_report_reauth`
  yields a `reauth_audit_event_id` stamped into the custody appendix (F-MVP-4).
- Request: `{profile (default "full"), finding_ids?, start_date?, end_date?}`. Invalid
  profile → 400; concurrent generation for the same case → 429.
- Response: `{id, profile, report_data, sections, guidance, evidence_chain,
  custody_appendix, integrity_warning?, verification_alerts?}`. Reports include
  approved findings + approved supporting data only; in DB mode inputs are read from
  Postgres authority, never tamperable case JSON (BATCH-K2).
### POST `/api/reports/{id}/save` (`save_report_route`, 5747), GET `/api/reports/{id}` , GET `/api/reports/{id}/download` (`download_report`, 5823)
- Persist/fetch/export the generated report (UUID id; 404 on expired draft).
- Security note: export is leak-scanned in practice — BATCH-V1 export (5570 bytes) had
  no `/cases`, `/home`, `127.0.0.1`, Supabase/service-role/password, Postgres, or
  OpenSearch strings.

## Group: Jobs (operator poll surface)

### GET `/api/jobs/{job_id}` (`get_job_status`, 5889)
- Actor: operator. Sanitized durable-job status via the D2 `_JOB_SERVICE`
  (`job_status_public`); path-free. (Agents poll the same job state via the MCP
  `job_status` tool — see `mcp-contracts.md`.)

## Group: Portal aggregate state

### GET `/api/portal/state` (`get_portal_state`, 5915)
- Actor: operator. Aggregate dashboard bootstrap (case + evidence + counts). Read-only.

## Group: Response guard controls (operator override)

Routes ≈6021-6023. `routes.py` `get_response_guard_status` / `post_response_guard_
override` / `post_response_guard_override_cancel`.
- Operator-only knobs that enable a time-boxed (default 600s) redaction override per
  case so the operator can see secret-pattern matches the agent surface redacts.
  Override is in-memory, per-process, expiring (`response_guard.enable_override`).
  This is an operator escape hatch; it does NOT affect what the agent sees.

## Group: Backends / services (operator admin)

Portal routes ≈6054-6061 (`get_backends_route` etc.) and Gateway REST `rest.py`
`rest_routes()`:
- `GET/POST /api/v1/backends`, `DELETE /api/v1/backends/{name}`,
  `POST /api/v1/backends/validate`, `POST /api/v1/backends/reload` — MCP add-on backend
  registry. D34 is **restart-to-apply**: register/unregister write the DB registry and
  return `restart_required: true`; the served `/mcp` catalog only changes after Gateway
  restart. Secret refs (`bearer_token`, `tls_cert`, env) are sanitized out of error
  reasons (`_sanitize_reasons`).
- `GET /api/v1/services`, `POST /api/v1/services/{name}/{start|stop|restart}` — control
  running backends and rebuild the tool map.

## Group: Setup / join

`rest.py`: `POST /api/v1/setup/join-code` (authenticated examiner; one-time code),
`POST /api/v1/setup/join` (**unauthenticated** — the join code IS the auth; rate-limited;
returns a gateway bearer token once for non-wintools joins), `GET /api/v1/setup/join-
status`. Security: D22A forbids persisting a received wintools bearer token to
`gateway.yaml`/Postgres; it lives only as a process env ref and needs a restart to
expose the backend.

## Group: Gateway REST tools (operator-only, MVP)

`rest.py` `rest_routes()`:
- `GET /api/v1/tools` (`list_tools`) — lists aggregated tool name/backend/description/
  input_schema. (Catalog view; the agent's scoped catalog is served over `/mcp`.)
- `POST /api/v1/tools/{tool_name}` (`call_tool`) — **operator-only**: agent/service
  tokens → 403 (see "Operator-only REST"). Rate-limited per IP; body ≤ 10 MB; 404 on
  unknown tool; case-mismatch/implicit-env proxy errors → 403; `ActiveCaseError`
  surfaces its `http_status`.

## Group: Health / admin

`health.py` `health_routes()`: `GET /health` and `GET /api/v1/health`
(`health_endpoint`).
- Response: `{status: "ok"|"degraded", backends:{...}, tools_count, supabase:{status,
  url}, evidence_root:{status, path, readable, ...}}`. Degraded if any backend
  unhealthy or evidence root missing.
- Security note: must not expose secrets; `supabase.url` is a host URL, not a key. The
  Supabase probe sends only the configured anon key as the `apikey` header (F-MVP-5).
- Live proof: BATCH-V1 — `status=ok`, Supabase `status=ok`, evidence root `status=ok`.

## Cross-cutting security notes

- The Gateway is the only policy boundary; the portal session middleware never returns
  401/403 itself — handlers do (`auth.py` docstring; `_require_*` helpers).
- Agent/service principals are structurally barred from operator portal routes (no
  `examiner`/`role`) and from REST tool execution (403). Their only path is `/mcp`.
- All re-auth challenges are single-use, TTL-bound (~30s), and IP-bound.
- DB authority is preferred for evidence/investigation/reports; file-backed paths are
  legacy fallbacks. Absolute case/mount paths are never returned to any caller; only
  relative display paths and opaque ids.

## Suggested interaction-model.md additions (owned by PDOC1 — for the conductor)

These interaction-contract facts surfaced here but belong in `interaction-model.md`:
1. The challenge→action re-auth handshake (GET `*/challenge` then POST with
   `response=HMAC(stored_hash, nonce)`) as the canonical human re-auth loop, with the
   gated action list (activate, seal/ignore/retire, verify-hmac, commit, report
   generate).
2. The human-in-the-loop transition: agent stages a DRAFT finding via MCP →
   operator approves via POST `/api/commit` (HMAC) → finding becomes reportable. This
   is the agent↔operator handoff edge.
3. The operator redaction-override escape hatch (`/api/response-guard/override`) as the
   operator-side counterpart to the agent-facing response guard.
