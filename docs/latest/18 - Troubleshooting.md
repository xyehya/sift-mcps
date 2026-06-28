# Troubleshooting

## Where to find logs

- **Gateway + workers:** `journalctl -u sift-gateway` (systemd journal, JSON to stderr)
- **OpenSearch worker:** `journalctl -u sift-opensearch-worker@1`
- **Job worker:** `journalctl -u sift-job-worker`
- **File logs:** `~/.sift/logs/sift-gateway.jsonl` (if `SIFT_LOG_FILE=true`; controlled by `packages/sift-common/src/sift_common/oplog.py:91-97`)
- **Audit trail:** `~/.sift/<case-id>/audit/<mcp-name>.jsonl` (file mode) or `app.audit_events` (DB mode)
- **Log format:** Structured JSON to stderr (default `SIFT_LOG_FORMAT="json"`)

---

## 1. No tools appear in MCP surface

**Symptom:** Agent sees empty `tools/list` or only 8-11 core tools, no add-on tools.

**Error message:** No explicit error — tools just missing from discovery.

**Diagnosis:**

1. Check if `SIFT_CONTROL_PLANE_DSN` is set and Postgres is reachable — `ControlPlaneRequiredMiddleware` blocks all tools when no DSN config is present (`packages/sift-gateway/src/sift_gateway/policy_middleware.py:530-564`).
2. Query the backends endpoint: `GET /api/v1/backends` — are add-on backends registered and enabled?
3. Query Postgres directly: `SELECT name, enabled, health_status FROM app.mcp_backends;`
4. Check backend health: each backend's `health_status` should be `"healthy"` — if `"error"`, the backend subprocess may have crashed.

**Fix:**

- Verify `~/.sift/control-plane.env` contains a valid `SIFT_CONTROL_PLANE_DSN`.
- If backend registered but not enabled: `POST /api/v1/backends/{name}/enabled` with `{"enabled": true}`.
- Restart sift-gateway: `sudo systemctl restart sift-gateway`.
- Check journalctl for stdio subprocess crash details: `journalctl -u sift-gateway -n 100`.

---

## 2. All MCP tool calls blocked — "control_plane_unavailable"

**Symptom:** Every tool call returns `{"error": "control_plane_unavailable"}`.

**Error message (exact):**

```
{"error": "control_plane_unavailable", "detail": "Gateway has no control-plane DSN"}
```

From `packages/sift-gateway/src/sift_gateway/policy_middleware.py:551` (`ControlPlaneRequiredMiddleware`).

**Diagnosis:** The gateway's `control_plane_dsn` is `None` — either Postgres is unreachable or the env var is missing.

**Fix:**

1. Verify `SIFT_CONTROL_PLANE_DSN` is exported in the gateway process env:
   ```
   sudo cat /proc/$(pgrep -f sift-gateway)/environ | tr '\0' '\n' | grep DSN
   ```
2. Check the env file: `cat ~/.sift/control-plane.env`
3. Verify Postgres is running: `psql "$SIFT_CONTROL_PLANE_DSN" -c "SELECT 1"`
4. Restart gateway: `sudo systemctl restart sift-gateway`

---

## 3. Evidence gate blocks all MCP tool calls

**Symptom:** All tool calls return `{"error": "evidence_chain_unsealed"}` or `{"error": "evidence_chain_violation"}`.

**Error message (exact):**

```
"reason": "evidence_chain_unsealed"
```

```
"reason": "evidence_chain_violation"
```

From `packages/sift-gateway/src/sift_gateway/evidence_gate.py:136` (`build_block_response`).

**Diagnosis:** The active case's evidence chain is not in OK status. The `check_evidence_gate_db()` function (`evidence_gate.py:62`) queries the DB and returns `{blocked, status, issues, manifest_version}`. Evidence gate applies fail-closed logic:
- Missing `case_id` → `blocked=True`
- Missing DSN → `blocked=True`
- DB error → `blocked=True`
- Custody event issues → `blocked=True`

Check in the portal: `GET /portal/api/evidence/chain/status`.

**Fix:**

1. Register evidence files via the portal Evidence panel.
2. Seal the evidence chain: `POST /portal/api/evidence/chain/seal` (requires password re-verification).
3. This writes to `app.evidence_objects` + `app.evidence_custody_events`. Note: `app.evidence_custody_events` is append-only — no UPDATE/DELETE allowed (trigger `evidence_block_mutation()` from Supabase migration `202606131000`).
4. After seal, the gate passes → MCP tools work.

**Note:** If no active case is set, the evidence gate passes through (nothing to seal yet). The block only applies when a case is active and evidence is unsealed.

---

## 4. Authentication errors — 401 / 403 / 503

All auth errors originate from `packages/sift-gateway/src/sift_gateway/supabase_auth.py` and the `MCPAuthASGIApp` ASGI guard in `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py`.

### 4a. 401 — `"invalid_token"` or `"token_expired"`

**Error message (exact):**

- `{"error": "invalid_token"}` — `supabase_auth.py:87-96` (`InvalidTokenError`)
- `{"error": "token_expired"}` — `supabase_auth.py:98-107` (`TokenExpiredError`)

**Symptom:** REST returns 401, MCP denies all tools.

**Diagnosis:** Supabase JWT is expired or malformed. Check token validity:
```
curl -H "Authorization: Bearer <token>" <supabase_url>/auth/v1/user
```

**Fix:**

- Generate a new token: re-login via the portal, or issue a new agent token via `POST /portal/api/auth/principals`.
- Agent tokens: default TTL is the Supabase Auth JWT expiry (should be 48h). Ensure `GOTRUE_JWT_EXP=172800` is set in the Supabase project environment.
- For the ASGI guard layer: `MCPAuthASGIApp` (`mcp_endpoint.py`) rejects requests with no bearer token as 401 (`SiftTokenVerifier`), and treats readonly tokens as 403.

### 4b. 403 — `"principal_not_mapped"` or `"principal_disabled"`

**Error message (exact):**

- `{"error": "principal_not_mapped"}` — `supabase_auth.py:109-118` (`PrincipalNotMappedError`)
- `{"error": "principal_disabled"}` — `supabase_auth.py:120-129` (`PrincipalDisabledError`)

**Symptom:** Valid JWT but no corresponding app principal, or principal is disabled.

**Diagnosis:**

- `"principal_not_mapped"`: The `auth.users.id` from the JWT doesn't have a row in `app.principal_identities`. This happens when a Supabase user was created but the app principal insert failed.
- `"principal_disabled"`: The principal row has `status != 'active'`.

**Fix:**

- Check: `SELECT * FROM app.principal_identities WHERE auth_user_id = '<uuid>';`
- If missing, re-create the principal via the portal.
- If disabled, re-enable: set `status = 'active'` in `app.principal_identities`.

### 4c. 403 — `"ambiguous_principal"`

**Error message (exact):**

```
{"error": "ambiguous_principal"}
```

From `supabase_auth.py:131-140` (`AmbiguousPrincipalError`).

**Symptom:** One Supabase auth user maps to multiple app principals.

**Diagnosis:** `lookup_by_auth_user_id()` found >1 row. This is a fail-closed privilege-confusion guard.

**Fix:** Clean up duplicate principal rows. There should be exactly one principal per auth user.

### 4d. 503 — `"supabase_unavailable"`

**Error message (exact):**

```
{"error": "supabase_unavailable"}
```

From `supabase_auth.py:165-172` (`SupabaseUnavailableError`).

**Symptom:** Gateway cannot reach Supabase Auth (GoTrue). All auth fails closed.

**Diagnosis:** Check if Supabase containers are running: `docker ps | grep supabase`.

**Fix:**

1. Start Supabase: `cd ~/supabase-project && docker compose up -d`
2. Wait for auth service health: `curl <supabase_url>/auth/v1/health`
3. No gateway restart needed — the resolver will recover on next auth attempt.

### 4e. 503 — `"agent_token_ttl_below_minimum"`

**Error message (exact):**

```
{"error": "agent_token_ttl_below_minimum"}
```

From `supabase_auth.py:174-182` (`AgentTokenTtlError`).

**Symptom:** Agent token TTL is below the minimum configured threshold.

**Diagnosis:** The Supabase project JWT expiry (`GOTRUE_JWT_EXP`) is set too low. The gateway enforces a minimum TTL on agent tokens.

**Fix:** Increase `GOTRUE_JWT_EXP` in the Supabase project environment to at least the gateway minimum (default 48h: `172800`).

### 4f. ASGI guard errors (pre-auth)

**Error messages and codes:**

| HTTP Status | Cause | Source |
|---|---|---|
| 411 | No `Content-Length` header | `mcp_endpoint.py` (`MCPAuthASGIApp`) |
| 413 | Body exceeds 10 MB | `mcp_endpoint.py` (`MCPAuthASGIApp`) |
| 403 | Origin not allowed | `mcp_endpoint.py` (`MCPAuthASGIApp`) |
| 429 | Rate limit exceeded (pre-auth IP) | `mcp_endpoint.py` (`MCPAuthASGIApp`) |
| 401 | No bearer token | `mcp_endpoint.py` (`SiftTokenVerifier`) |
| 403 | Readonly token used for write | `mcp_endpoint.py` (`SiftTokenVerifier`) |

`SiftTokenVerifier` enforces SEC-6: Supabase outage = deny, readonly = deny.

**Fix:** These are configuration and client-side issues. Check the client's headers, body size, origin, and token.

---

## 5. OpenSearch connection refused

**Symptom:** Opensearch-mcp tools return `ErrorCode.upstream_unavailable`. Confirmed by `curl localhost:9200/_cluster/health` failing.

**Error message (exact):**

```
{"error": "upstream_unavailable"}
```

From `ErrorCode.upstream_unavailable` in `packages/sift-common/src/sift_common/contracts.py`.

**Diagnosis:**

1. Check if OpenSearch container is running: `docker ps | grep opensearch`
2. Check container health: `docker inspect sift-opensearch --format '{{.State.Health.Status}}'`
3. Check config: verify `~/.sift/opensearch.yaml` exists with correct URL.

**Fix:**

1. Start OpenSearch: `docker compose up -d` (from sift-mcps root).
2. Wait for healthy: `curl -s localhost:9200/_cluster/health | grep status`.
3. If OpenSearch container exits immediately: check `docker logs sift-opensearch` for `vm.max_map_count` error. Run:
   ```
   sudo sysctl -w vm.max_map_count=262144
   ```
4. Check disk space: `df -h /var/lib/docker`.

---

## 6. Ingest never completes

**Symptom:** `opensearch_ingest` returns `status: "queued"` or `status: "running"` indefinitely. Job never reaches `"complete"`.

**Error message (exact):** No single error — diagnosis through job status inspection.

**Diagnosis:**

1. Check job status: `curl /portal/api/jobs/<job_id>` or:
   ```sql
   SELECT status, worker_label, attempts, last_error
   FROM app.job_status_public
   WHERE id = '<job_id>';
   ```
2. Check if workers are running: `sudo systemctl status sift-opensearch-worker@1`
3. Check worker logs: `journalctl -u sift-opensearch-worker@1`
4. Circuit breaker may have tripped in `bulk.py` — check worker logs for `ShardCapacityExhausted`.

**Fix:**

- Start workers: `sudo systemctl enable --now sift-opensearch-worker@1 sift-opensearch-worker@2`.
- If circuit breaker tripped: check OpenSearch shard capacity (`opensearch_shard_status`). Increase nodes/shards or clean old indices.
- If stale job (lease expired): gateway reaper (`_job_reaper`) re-queues every 60s (default). Wait or restart gateway.
- If FUSE mount failed: the worker requires `CAP_SYS_ADMIN` in its bounding set (`sift-opensearch-worker@.service:97`). FUSE requires host mount namespace — the worker's systemd unit explicitly trades off `ProtectSystem` for this.
- Check `sudo journalctl -u sift-opensearch-worker@1 -n 100` for the actual error.

---

## 7. Rate limit exceeded (429)

**Symptom:** Tool calls or MCP requests return `429` with `"Rate limit exceeded"`.

**Error message (exact):**

```
"Rate limit exceeded"
```

From `packages/sift-gateway/src/sift_gateway/rate_limit.py:117-125` (IP limiter) and `policy_middleware.py:326` (examiner limiter).

**Diagnosis:**

- **IP rate limit:** 60 requests/60s default, applied pre-auth (`rate_limit.py`). Localhost bypasses this limiter.
- **Examiner rate limit:** 120 requests/60s default per identity, applied post-auth (`policy_middleware.py:326`, `ToolAuthorizationMiddleware`).

The denial pattern returned is `"rate_limit_exceeded"` (`policy_middleware.py:342`).

**Fix:**

1. Configure rate limits in `gateway.yaml`:
   - `gateway.rate_limit.ip_calls_per_minute` (default: 60)
   - `gateway.rate_limit.examiner_calls_per_minute` (default: 120)
2. Set to `0` to disable (no rate limiting).
3. Restart gateway: `sudo systemctl restart sift-gateway`.

---

## 8. Tool denied — "tool_not_authorized"

**Symptom:** A specific tool call is rejected even though other tools work.

**Error message (exact):**

```
{"error": "tool_not_authorized"}
```

From `packages/sift-gateway/src/sift_gateway/policy_middleware.py:380` (`ToolAuthorizationMiddleware`).

**Diagnosis:** The authenticated principal does not have the required policy grant for this tool. `ToolAuthorizationMiddleware` checks principal grants against tool-level policy.

**Fix:**

1. Check principal grants: `SELECT * FROM app.principal_grants WHERE principal_id = '<id>';`
2. Grant the required tool to the principal via the portal or API: `POST /api/v1/principals/{id}/grants`.

---

## 9. Add-on tool denied — "addon_scope_missing" or "addon_prohibited_operation"

**Symptom:** Add-on MCP tools are denied with scope or operation errors.

**Error message (exact):**

- `{"error": "addon_scope_missing"}` — `policy_middleware.py:465`
- `{"error": "addon_prohibited_operation"}` — `policy_middleware.py:465`

From `AddonAuthorityMiddleware` in `policy_middleware.py:465`.

**Diagnosis:** The add-on principal lacks the required scope declaration, or the requested operation is not permitted by the add-on's registered scope. This is the add-on sandbox gate — add-ons can only call tools within their declared scope boundary.

**Fix:**

1. Check the add-on's registered scope: `SELECT name, scope FROM app.mcp_backends WHERE backend_type = 'addon';`
2. Ensure the add-on's `mcp_backend_entrypoint` declares a scope that covers the operation.
3. Update the add-on's scope via `PATCH /api/v1/backends/{name}`.

---

## 10. Active case denied — "active_case_denied"

**Symptom:** Tool calls blocked because no active case is set.

**Error message (exact):**

```
{"error": "active_case_denied"}
```

From `packages/sift-gateway/src/sift_gateway/policy_middleware.py:775` (`CaseContextMiddleware`).

**Diagnosis:** `CaseContextMiddleware` requires an active case context but none is set. This applies to tools that mandate case context.

**Fix:**

1. Set an active case via the portal or API.
2. If the tool should not require a case, check the tool's policy configuration — update `requires_case` to `false`.

---

## 11. Proxy case errors — "client_case_mismatch" or "proxy_requires_implicit_case"

**Symptom:** Proxy-mode tool calls are denied due to case context mismatch.

**Error message (exact):**

- `{"error": "client_case_mismatch"}` — `policy_middleware.py:880`
- `{"error": "proxy_requires_implicit_case"}` — `policy_middleware.py:900`

From `ProxyActiveCaseMiddleware` in `policy_middleware.py:880,900`.

**Diagnosis:**

- `"client_case_mismatch"`: The client-claimed case doesn't match the proxy's implicit case binding.
- `"proxy_requires_implicit_case"`: Proxy mode requires an implicit case, but the client didn't provide one.

**Fix:**

1. Ensure the client includes the correct case context in the request.
2. Check the proxy's implicit case binding configuration.

---

## 12. Audit unavailable — "audit_unavailable"

**Symptom:** Tool calls are blocked because the audit system is unreachable.

**Error message (exact):**

```
{"error": "audit_unavailable"}
```

From `packages/sift-gateway/src/sift_gateway/policy_middleware.py:500` (`AuditEnvelopeMiddleware`).

**Diagnosis:** `AuditEnvelopeMiddleware` could not write to the audit system. The audit writer role (`sift_audit_writer`) has no `BYPASSRLS` (per Supabase migration `202606242300`) — all writes go through RLS policies. If the audit table is unreachable (DB down, RLS misconfiguration, permission denied), the gate fails closed.

**Fix:**

1. Check Postgres connectivity: `psql "$SIFT_CONTROL_PLANE_DSN" -c "SELECT 1 FROM app.audit_events LIMIT 1;"`
2. Verify `sift_audit_writer` role can insert into `app.audit_events`:
   ```sql
   SET ROLE sift_audit_writer;
   SELECT has_table_privilege('app.audit_events', 'INSERT');
   ```
3. Check RLS policies on `app.audit_events`. All 31 `app.*` tables have `FORCE RLS` (migration `202606131000`).
4. In file mode: check `~/.sift/<case-id>/audit/` exists and is writeable.

---

## 13. Ingest capacity refused — "capacity_refused"

**Symptom:** Ingest jobs or tool calls are rejected due to system capacity.

**Error message (exact):**

```
{"error": "capacity_refused"}
```

From `ErrorCode.capacity_refused` in `packages/sift-common/src/sift_common/contracts.py`.

**Diagnosis:** The gateway's capacity guard has rejected the request — possible causes include OpenSearch shard saturation, worker pool exhaustion, or disk watermark thresholds.

**Fix:**

1. Check OpenSearch disk watermarks: `curl localhost:9200/_cluster/settings?include_defaults=true | grep watermark`
2. Check worker pool size: `SELECT count(*) FROM app.workers WHERE status = 'active';`
3. Free disk space on the OpenSearch data volume.
4. Scale workers: increase worker instances in systemd or adjust pool configuration.

---

## 14. Internal error — 500

**Symptom:** Generic 500 response with no structured tool error.

**Error message (exact):**

```
{"error": "internal"}
```

From `ErrorCode.internal` in `packages/sift-common/src/sift_common/contracts.py`.

**Diagnosis:** An unhandled exception occurred in gateway middleware or tool execution. Check the gateway logs for the full traceback.

**Fix:**

1. Check gateway logs: `journalctl -u sift-gateway -n 200 --no-pager`
2. Look for Python tracebacks in the output.
3. Common causes: DB query failure, subprocess crash, unhandled edge case in tool implementation.
4. If reproducible, enable debug logging: set `SIFT_LOG_LEVEL=DEBUG` and restart gateway.

---

## 15. Portal session keeps expiring

**Symptom:** Portal logs you out frequently, even when actively using it.

**Diagnosis:**

- The `sift_portal_session` cookie has a 12-hour **absolute** ceiling (`ABSOLUTE_ENVELOPE_LIFETIME_SECONDS = 43200`; `packages/case-dashboard/src/case_dashboard/session_jwt.py:38`). The `eiat` (original issued-at) is preserved across refreshes — after 12h from first login, you must re-login.
- The sliding `max_age` is 8h (28800s), configurable via `portal.session_max_age` in `gateway.yaml:188`. If the cookie's `max_age` expires but a valid `refresh_token` exists, the middleware transparently rotates it.
- If neither works: check that `SIFT_PORTAL_SESSION_SECRET` is the same value across gateway restarts. A changed secret invalidates all existing cookies.

**Fix:**

- Re-login. After 12h of active use, this is expected behavior.
- To extend: increase `ABSOLUTE_ENVELOPE_LIFETIME_SECONDS` (requires code change in `session_jwt.py`).
- Verify `SIFT_PORTAL_SESSION_SECRET` is stable: check `~/.sift/control-plane.env`.

---

## 16. DB-authority context conflict — `SIFT_DB_ACTIVE`

**Symptom:** Core tools read from wrong case directory (stale file-mode path) even though DB-authority mode is active.

**Diagnosis:** When `db_authority_active()` returns `True` (context says `db_active=True` OR `SIFT_DB_ACTIVE` env var is set), core resolvers must NOT use `SIFT_CASE_DIR` or `~/.sift/active_case`. They must use `AuthorityContext` only. If resolvers fall back to file-mode paths, they will read stale or wrong data. Reference: `packages/sift-core/src/sift_core/active_case_context.py`.

**Fix:**

- Ensure `SIFT_DB_ACTIVE` is consistently set (or unset) across all gateway + worker processes.
- Check that core resolvers are not hardcoding file paths when `db_authority_active()` is true.
- If migrating from file-mode to DB-authority: clear `~/.sift/active_case` and set `SIFT_DB_ACTIVE=true` in `control-plane.env`.

---

## 17. Retired core backends referenced

**Symptom:** Gateway startup logs reference old backend names but they are not wired.

**Diagnosis:** `_RETIRED_CORE_BACKENDS` is a frozenset of retired backend names hardcoded in `packages/sift-gateway/src/sift_gateway/server.py:143-144`. These names are known to the registry but deliberately unwired — any tool call to them will return `not_found`. This is expected behavior; they exist to prevent stale client configurations from crashing.

**Fix:** No action needed. These are informational. If you need a retired backend back, add it to the active registry instead of the retired set.

---

## 18. Supabase RLS blocks legitimate queries

**Symptom:** Direct Postgres queries return empty results even though rows exist.

**Diagnosis:** All 31 `app.*` tables have `FORCE RLS` (Supabase migration `202606131000`). When connecting directly to Postgres (not through the gateway's service role), row-level security filters results based on the authenticated role. The `sift_audit_writer` role has no `BYPASSRLS` (migration `202606242300`). If you're using a different role or a direct connection, you may not see rows that the gateway service role can access.

**Fix:**

- For debugging, use the same role the gateway uses (typically `authenticator` or the service role).
- Query via the gateway API rather than directly to Postgres, to ensure consistent RLS behavior.
- If adding new tables, ensure they include `FORCE RLS` and appropriate policies.
