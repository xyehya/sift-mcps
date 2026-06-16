# Data Flow Analysis (数据流分析)

> Covers: packages/sift-gateway/src/, packages/sift-core/src/, packages/case-dashboard/src/, packages/forensic-rag-mcp/src/, packages/opensearch-mcp/src/, supabase/migrations/
> Class: live-reference
> Last validated: 35e0d33 (2026-06-16)

## sift-mcps: Data Flow Through the Platform

All flows verified from actual source code with [VERIFY:] citations.

---

## 0. Active Case Metadata Parity

During the Axis B transition, CASE.yaml remains the reader authority for case
metadata. Gateway still mirrors every currently consumed CASE.yaml field into
`app.cases` before DB-native readers are enabled: `case_id`/`name`/`title`/
`description`/lifecycle status map to `app.cases` columns when compatible, and
examiner, created/closed dates, close summary, lead examiner, incident details,
TLP/severity, timestamps, affected systems/accounts, tags, and related cases
are preserved in `app.cases.metadata`. Backfill fills missing DB values only;
conflicting DB values are left untouched and logged for operator review.

---

## 1. Agent Tool Call Flow (Complete End-to-End)

```
AI Agent (Claude)
    │
    │ HTTP POST /mcp/
    │ Body: {"method": "tools/call", "params": {"name": "run_command", "arguments": {...}}}
    │
    ▼
MCPAuthASGIApp (ASGI-level guard)
    │ ├── Origin header check (allowed_origins set)
    │ ├── Body size guard (DoS protection)
    │ ├── IP rate limit check
    │ └── Token verification (SiftTokenVerifier → FastMCP auth)
    │
    ▼
FastMCP Router
    │
    ▼
Policy Middleware Stack (executed in declaration order)
    │
    ├── [1] ToolAuthorizationMiddleware
    │       ├── Resolve identity from context var
    │       ├── Per-principal rate limit (check_examiner_rate_limit)
    │       └── is_tool_allowed(identity, tool_name) → allow or deny
    │
    ├── [2] AddonAuthorityMiddleware
    │       ├── Fetch addon_authority_for_tool(tool_name)
    │       ├── Check required_scopes ⊆ identity.tool_scopes
    │       └── Check prohibited_operations not attempted
    │
    ├── [3] CaseContextMiddleware
    │       ├── active_case_service.require_active_case_for_principal(identity)
    │       │       → ActiveCase{case_id, case_key, artifact_path, role}
    │       ├── Build ActiveCaseContext (with request_id UUID)
    │       ├── Set _CURRENT_ACTIVE_CASE context var
    │       └── Set use_active_case_context(ctx) context var
    │
    ├── [4] AuditEnvelopeMiddleware
    │       ├── DB-first PRE-DISPATCH: db_audit.record("mcp.tool.call", status="requested")
    │       │       ↳ If mutating tool and DB write fails → fail closed (deny)
    │       ├── [DISPATCH: call_next(context)]
    │       └── DB-first POST-DISPATCH: db_audit.record("mcp.tool.result", status=ok/failure)
    │           + JSONL mirror: gateway._audit.log(...)
    │
    ├── [5] ProxyActiveCaseMiddleware  (for proxied/add-on tools only)
    │       ├── For case-scoped tool: get safe_case_argument_names
    │       ├── Inject case_id/case_key/case_dir into arguments
    │       └── Reject if client supplied mismatching case value
    │
    ├── [6] EvidenceGateMiddleware
    │       ├── check_evidence_gate_db(case.case_id, dsn)  [DB mode]
    │       │   OR check_evidence_gate(case_dir)            [file mode]
    │       └── If gate["blocked"]: return block_response, audit, stop
    │
    ├── [7] ResponseGuardMiddleware
    │       ├── guard_tool_result(result, override_active, case_dir, cap_bytes)
    │       │       → Pattern scan: secrets, absolute paths, PII
    │       │       → Cap output if > cap_bytes
    │       └── Append _sift_context{secret_warning, output_capped} if triggered
    │
    └── [8] OpenSearchJobDispatchMiddleware  (for opensearch_ingest/enrich_intel)
            ├── If dry_run: pass through
            └── job_service.enqueue_job(job_type, case_id, spec_public, spec_internal)
                    → Return {job_id, status:"queued"} immediately (non-blocking)

    ▼
GatewayLocalTool.run()  [for core tools]
    │   or
FastMCP Proxy dispatch [for add-on tools]
    │
    ▼ (core tool path)
asyncio.to_thread(call_core_tool, name, arguments, examiner, audit)
    │
    ├── case_info → _case_info() → case_status_data() + chain_status() + build_platform_capabilities()
    ├── evidence_info → _evidence_info() → list_evidence_status_data() + chain_status()
    ├── run_command → _run_command() → [see Section 2 below]
    ├── record_finding → manager.record_finding()
    ├── record_timeline_event → manager.record_timeline_event()
    ├── list_existing_findings → manager.get_findings(status or None)   # no PostgresInvestigationStore fallback in this dispatch
    ├── manage_todo → manager.add_todo/list_todos/update_todo/complete_todo
    └── get_tool_help → _get_tool_help(tool_name)
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:1158-1184]  
[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:286-308]

---

## 2. run_command Data Flow (Detailed)

```
call_core_tool("run_command", args)
    │
    ▼
_run_command(args, examiner, audit)
    │
    ├── audit._next_audit_id(examiner) → "siftgateway-analyst-20260615-001"
    │
    ├── _coerce_run_command(args["command"])
    │       ├── str → use as-is
    │       └── list → shlex.join (if no shell operators)
    │
    ├── Resolve working_dir:
    │       ├── args["working_dir"] → resolve_case_path(working_dir)
    │       └── None → active_case_context.case_dir
    │
    ├── Evidence refs resolution (BATCH-I1):
    │       ├── If args["_resolved_evidence_refs"] present (Gateway-injected DB path):
    │       │       → _trusted_internal_evidence_refs() → absolute paths
    │       └── Else → resolve_evidence_ref(ref, case_dir) → local sealed manifest lookup
    │
    ├── Output ref resolution:
    │       └── resolve_output_ref(output_ref, case_dir) → absolute save_dir
    │
    ├── Command parsing & input detection:
    │       ├── split_command_by_operators(command) → subcmds list
    │       ├── For each subcmd: parse_subcommand_argv_and_redirects()
    │       ├── Detect input files: redirects (<) + tool catalog input_flag
    │       └── SHA-256 hash each detected input file
    │
    ├── _execute_command(command, purpose, timeout, save_output, cwd)
    │       [→ see Section 3: Command Execution Flow]
    │
    ├── Post-processing:
    │       ├── Detect failed pipeline stages (AUT2-B5)
    │       ├── sanitize_path_value(output_file) → relative output_ref
    │       ├── Build provenance receipt (job_id, input/output SHA-256s)
    │       └── audit.log("run_command", params, result_summary, ...)
    │
    └── sanitize_paths_deep(response, case_dir)
            → Scrub ALL absolute paths from the complete response dict
```

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:687-1108]

---

## 3. Command Execution Flow (Subprocess Isolation)

```
_execute_command(command, purpose, timeout, save_output, cwd)
    [packages/sift-core/src/sift_core/execute/tools/generic.py]
    │
    ▼
execute(cmd_list, timeout, cwd, save_output, save_dir)
    [packages/sift-core/src/sift_core/execute/executor.py:324]
    │
    ├── config = get_config()      # Reads SIFT_EXECUTE_* env vars
    ├── _native_runtime_identity() # → (runtime_user, sudo_path) or ("", "")
    │
    ▼
_run_isolated_worker(cmd_list, timeout, cwd, max_output_bytes, memory_limit_bytes,
                     runtime_user, sudo_path, cache_dir)
    │
    ├── Build payload JSON:
    │       {cmd, timeout, cwd, case_dir, max_output_bytes, memory_limit_bytes,
    │        runtime_user, launcher_enabled, require_landlock, seccomp_mode, ...}
    │
    ├── _systemd_scope_command([sys.executable, "-m", "sift_core.execute.worker"])
    │       ├── mode="off" → [python, -m, worker]           (dev mode)
    │       ├── mode="auto" → systemd-run --scope -p MemoryMax=4G ... [python -m worker]
    │       └── mode="required" + helper → sudo sift-run-command-systemd-scope ...
    │
    ├── worker_env = build_sandbox_env()
    │       # Keeps ONLY an explicit allowlist (runtime_acl.py:40-82):
    │       #   _SAFE_ENV_NAMES = PATH, HOME, USER, LOGNAME, SHELL, TMPDIR, TMP, TEMP,
    │       #     LANG, LANGUAGE, LC_ALL, LC_CTYPE, LC_NUMERIC, LC_TIME, LC_COLLATE,
    │       #     LC_MESSAGES, TZ, PWD   (a FIXED LC_* subset — not "all LC_*")
    │       #   _SAFE_SIFT_ENV_NAMES = SIFT_CASE_DIR, SIFT_EXAMINER, SIFT_TOOL_PATHS,
    │       #     SIFT_TIMEOUT, SIFT_HAYABUSA_DIR, SIFT_RESPONSE_BUDGET, SIFT_MAX_OUTPUT,
    │       #     SIFT_EXECUTE_MEMORY_LIMIT, SIFT_EXECUTE_AS_USER, SIFT_SHARE_ROOT,
    │       #     SIFT_STATE_DIR, SECURITY_POLICY_ENV
    │       # then forces TERM=dumb and a default LC_ALL.
    │       # NOTE: SIFT_DB_ACTIVE is NOT kept (not in either allowlist).
    │       # Deny floor (_is_secret_env_name) drops anything matching secret/auth
    │       # patterns (dsn, supabase, password, token, ld_*, python, node_options, …)
    │       # even if allowlisted — so DSNs/API keys/Supabase/OpenSearch creds never pass.
    │
    ├── subprocess.run(worker_cmd, input=json.dumps(payload), capture_output=True,
    │                 text=True, timeout=timeout+3, shell=False, env=worker_env)
    │       │
    │       ▼
    │   sift_core.execute.worker (subprocess)
    │       ├── Receive JSON payload on stdin
    │       ├── Apply Landlock filesystem restrictions (if enabled)
    │       ├── Apply seccomp filter (log/kill mode)
    │       ├── Drop to runtime_user (if configured)
    │       ├── Run the actual forensic tool subprocess (shell=False)
    │       └── Return JSON result on stdout
    │
    └── Parse JSON result from stdout:
            ├── error_type=="timeout" → ExecutionTimeoutError
            ├── error_type=="not_found" → FileNotFoundError
            ├── error_type=="permission" → PermissionError
            └── Success → raw result dict

    ▼ (back in execute())
    ├── _strip_cr_progress(stdout) → collapse vol3/tqdm progress meters
    ├── _looks_binary(stdout) → detect binary output
    ├── If exceeds budget OR binary OR save_output: _save_output(...) → files
    └── Build final response dict
```

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:191-275]  
[VERIFY: packages/sift-core/src/sift_core/execute/runtime_acl.py]

---

## 4. Backend Tool Call Flow (Proxied Add-on)

```
Gateway receives call for "opensearch_search" (add-on tool)
    │
    ▼ [after passing middleware stack]
FastMCP aggregate server routes to opensearch proxy provider
    │
    ▼
StdioTransport (keep_alive=True) → opensearch-mcp subprocess
    │ (spawned on first call; kept warm between calls)
    │
    ├── opensearch-mcp server receives the tool call
    ├── Executes opensearch query against 127.0.0.1:9200
    └── Returns MCP ToolResult
    │
    ▼ (result flows back through)
ResponseGuardMiddleware → redact secrets, cap output
    │
    ▼
AuditEnvelopeMiddleware → write "mcp.tool.result" to app.audit_events
    │
    ▼
Agent receives response
```

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:570-604]

---

## 5. OpenSearch Ingest Job Flow (Durable Worker)

```
Agent calls opensearch_ingest(path="evidence/disk.e01", format="e01")
    │
    ▼ [middleware stack: auth → addon-authority → case-context → audit-envelope
       → proxy-case-injection → evidence-gate → response-guard]
    │
    ▼
OpenSearchJobDispatchMiddleware.on_call_tool()
    ├── dry_run=True → pass through to stdio proxy (fast planning preview)
    └── dry_run=False → ENQUEUE (non-blocking):
            job_service.enqueue_job(
                job_type="ingest",
                case_id=case.case_id,
                spec_public={path, format, hostname, ...},    # No case_dir
                spec_internal={case_dir, case_key, examiner}  # Never to agent
            )
            → Return {job_id, status:"queued"}
    │
    ▼ (async, in background)
sift-opensearch-worker@ systemd unit
    ├── Claims job from app.jobs (via lease mechanism)
    ├── FUSE-mounts evidence E01 image
    ├── Runs Hayabusa (Windows event analysis)
    ├── Runs Volatility 3 (memory analysis, if applicable)
    ├── Bulk-indexes results into OpenSearch
    ├── Updates job status: running → completed
    └── Writes result_public to app.jobs

Agent polls: running_commands_status(job_id)
    │
    ▼
job_service.get_job_status(job_id)
    └── Returns {job_id, status, worker_label, current_step, result_public}
        (spec_internal is NEVER included)
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:1037-1155]  
[VERIFY: packages/sift-gateway/src/sift_gateway/jobs.py]

---

## 6. Evidence Chain Verification Flow

```
EvidenceGateMiddleware intercepts every tool call
    │
    ├── Get current active case from _CURRENT_ACTIVE_CASE context var
    │
    ├── DB mode (dsn present):
    │       check_evidence_gate_db(case.case_id, dsn)
    │           → cur.execute("select seal_status, manifest_version, issues "
    │                         "from app.evidence_gate_status(%s)", (case_id,))
    │             (app.evidence_gate_status is a FUNCTION, not a table)
    │           → maps seal_status {sealed→OK, unsealed→UNSEALED, violated→LEDGER_ERROR}
    │           → Returns {blocked: status != OK, status, issues, manifest_version}
    │
    └── File mode (no dsn):
            check_evidence_gate(case_dir)
                → chain_status(case_dir)
                    → load_manifest()  (NO file rehashing — stat-check only)
                    → verify manifest_hash + ledger hash-chain (structural)
                    → diff_manifest(): missing / modified (byte size) / unregistered
                    → Return {status: ChainStatus, issues, manifest_version, ok_count}
    │
    ├── gate["blocked"] == False (status == OK) → proceed
    └── gate["blocked"] == True (status != OK):
            ├── Audit (source="gateway_evidence_gate"): "blocked: evidence_chain_{status}"
            └── Return ToolResult(is_error=True) with build_block_response(name, gate):
                    {blocked: True, reason: "evidence_chain_unsealed"|"evidence_chain_violation",
                     tool, status, issues, manifest_version, detail, remediation}
```

> The block response keys are `blocked / reason / tool / status / issues / manifest_version / detail / remediation` — there is no `error: "evidence_gate"` or `chain_status` key. `chain_status()` does **not** SHA-256-rehash files; it does a stat-check plus structural hash-chain verification.

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:463-528]  
[VERIFY: packages/sift-gateway/src/sift_gateway/evidence_gate.py:137-232]  
[VERIFY: packages/sift-core/src/sift_core/evidence_chain.py:289-338]

---

## 7. Gateway Boot-up Flow

```
python -m sift_gateway
    │
    ▼
Gateway.__init__(config)
    ├── apply_case_env(config)          # Set env vars from config
    ├── apply_execute_security_env(config)
    ├── registry_config(config)         # Read control_plane_dsn
    │
    └── If dsn:
            McpBackendRegistry(dsn).create_backend_instances()
                → SELECT name, config, manifest FROM app.mcp_backends WHERE enabled=true
                → Instantiate StdioMCPBackend or HttpMCPBackend for each row
    │
    ▼
Gateway.create_app()
    ├── load_auth_config(config) → AuthConfig
    ├── create_token_registry(config) → TokenRegistry | None
    ├── ActiveCaseService(dsn) + DbAuditWriter(dsn) + JobService(dsn)
    ├── EvidenceAuthorityService + InvestigationService + ReportService
    ├── SupabaseAuthClient + SupabaseIdentityResolver (if Supabase configured)
    │
    ├── create_gateway_mcp_server(gateway, ...)
    │       ├── SiftTokenVerifier (FastMCP auth verifier)
    │       ├── GatewayToolCatalogMiddleware
    │       ├── gateway_policy_middlewares(gateway)
    │       ├── FastMCP("sift-gateway", auth=verifier, middleware=[...])
    │       ├── _register_core_tools(mcp, gateway)  → 9 GatewayLocalTool instances
    │       └── _mount_addon_proxies(mcp, gateway)  → FastMCP proxy per backend
    │
    └── Build FastAPI app with routes:
            /health routes
            REST routes (/api/v1/...)
            /portal → case-dashboard app
            /mcp → MCPAuthASGIApp
    │
    ▼ App lifespan:
    ├── gateway.start() → _build_tool_map()
    ├── gateway.reload_backend_registry() → mount late-seeded backends
    ├── Validate: expected_mounted_tool_names() == actual tool catalog
    ├── Pre-warm: gateway_mcp.list_tools() with 90s timeout (LV1)
    ├── asyncio.create_task(gateway._late_start_checker())
    ├── asyncio.create_task(gateway._idle_reaper()) [if idle_timeout > 0]
    └── asyncio.create_task(gateway._job_reaper()) [if job_service present]
```

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:1084-1408]  
[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:228-270]

---

## 8. Audit Flow (Dual-Channel)

In DB-active mode, every tool call produces TWO audit records:

```
Tool call received
    │
    ├── Channel 1: DB-first (AuditEnvelopeMiddleware)
    │       ├── Pre-dispatch: INSERT INTO app.audit_events (status="requested")
    │       │       → envelope_event_id
    │       ├── Post-dispatch: INSERT INTO app.audit_events (status="success"|"failure")
    │       │       → includes backend_audit_id, elapsed_ms, result_detail
    │       └── Failure: If pre-dispatch INSERT fails AND tool is mutating → DENY
    │
    └── Channel 2: JSONL mirror (best-effort)
            └── gateway._audit.log(...) → /var/lib/sift/{case_id}/audit/sift-gateway.jsonl
                    (fsync for durability; failure logged but not blocking)

    (Per-tool audit: each core/add-on tool also calls audit.log() internally)
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:808-986]

---

## 9. DB-Native Orientation Flow (case_info / evidence_info) — BU1

In DB-active mode (a control-plane DSN is configured) orientation is
DB-authoritative and **fails closed**: there is no file base layer and a DB error
returns blocked/error rather than file-derived values. The pre-BU1 file-overlay
(`_overlay_db_*`) is gone.

```
case_info or evidence_info called
    │
    ▼
GatewayLocalTool.run() → call_core_tool("case_info", ...)
    → _case_info() → case_status_data()
        → DB mode: resolve_case_metadata() (app.cases) + investigation store
          counters; CASE.yaml NOT read; raises (fail closed) on DB error
        → file mode: CASE.yaml + *.json mirror (unchanged)
    │
    ▼ (still in GatewayLocalTool.run(), DB mode only)
if tool_name in _DB_ORIENTED_TOOLS and gateway.control_plane_dsn:
    _db_orientation_authority(gateway, tool_name, text)   # evidence authority only
        │  (raises _OrientationAuthorityError on any DB failure → tool blocked)
        ├── check_evidence_gate_db(case.case_id, dsn)
        │       → {status, blocked, issues, manifest_version}, authority: "db"
        ├── case_info:     set evidence_chain.{status, ok, issues, manifest_version}
        └── evidence_info: set chain_status/issues/requires_examiner_action +
                           _apply_db_evidence_listing() → DB evidence objects
```

Finding counters are now DB-authoritative in core (`case_status_data`), not at the
gateway. The gateway layer owns only the evidence gate + listing.

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py (_db_orientation_authority);
packages/sift-core/src/sift_core/case_ops.py (case_status_data);
packages/sift-core/src/sift_core/investigation_store.py (resolve_case_metadata)]

---

## 10. Tool Map Build Flow

```
Gateway._build_tool_map()
    │
    ├── For each backend in self.backends:
    │       ├── Evaluate requirements: evaluate_requirement(req) for each req
    │       │       - "docker" → shutil.which("docker")
    │       │       - "ram:8gb" → os.sysconf SC_PHYS_PAGES comparison
    │       │       - "env:VARNAME" → os.environ check
    │       │       - "host:port" → socket.create_connection test
    │       │
    │       ├── If requirements not met → skip (not in _available_backends)
    │       │
    │       ├── If backend.started:
    │       │       → backend.list_tools() → actual tool objects
    │       │       → Validate namespace prefix + manifest declaration
    │       └── Else:
    │               → Synthesize Tool objects from manifest declarations
    │
    ├── Check for name collisions (tool_name → multiple backends → ValueError)
    ├── Check for core tool name collisions → ValueError
    │
    ├── Atomic swap:
    │       self._tool_map = new_map
    │       self._tool_cache = new_cache
    │       self._tool_manifest_meta = {t: manifest_meta[t] for t in new_map}
    │
    └── Log: "Tool map built: N add-on tools across M backends; K core tools in-process"
```

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:378-566]
