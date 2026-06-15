# Key Questions (关键问题解答)

## sift-mcps: Design Decisions Explained

All answers verified from actual source code with [VERIFY:] citations.

---

## Architecture Questions

### Q1: Why does the gateway use FastMCP proxy rather than direct subprocess management?

**Answer**: The D27b decision to use FastMCP's proxy architecture (`mcp.mount(proxy, ...)`) gives three advantages over the earlier direct stdio subprocess approach:

1. **Protocol encapsulation**: FastMCP proxy handles MCP framing, schema translation, and error wrapping. The gateway doesn't need to speak raw MCP JSON-RPC to each backend.
2. **Tool namespace remapping**: `mcp.mount(proxy, namespace=ns, tool_names=rename_map)` lets the gateway rewrite tool names (`opensearch_search` → the backend's own name) transparently.
3. **Keep-alive with lazy start**: `StdioTransport(keep_alive=True)` keeps the subprocess warm between calls without the gateway needing to manage the process lifecycle.

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:499-604]

The tradeoff: the gateway can't do low-level process control (e.g., per-call timeout via SIGKILL). The 300s `asyncio.wait_for(backend.call_tool(...), timeout=300.0)` in `call_tool()` is the per-call dispatch timeout (distinct from `backend.start()` 60s and `list_tools()` 15s).

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:1037-1039]

---

### Q2: Why does the middleware stack execute in the specific order it does?

**Order**: ToolAuth → AddonAuthority → CaseContext → AuditEnvelope → ProxyActiveCase → EvidenceGate → ResponseGuard → OpenSearchJobDispatch

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:1162-1185]

**Reasoning for each position**:

| Position | Middleware | Why here |
|----------|-----------|----------|
| 1st | ToolAuthorization | Short-circuit unauthorized calls before any state is touched. Cheapest check (in-memory scope comparison). |
| 2nd | AddonAuthority | Validate the backend's authority contract before case context is loaded. Prevents authority escalation by new backends. |
| 3rd | CaseContext | Must run before anything that needs case state. Resolves principal → active case from DB. |
| 4th | AuditEnvelope | Opens audit record BEFORE the tool executes. This guarantees an audit trail even if the tool crashes. |
| 5th | ProxyActiveCase | Injects case args into `arguments` after case is resolved (step 3) but before forwarding to backend. |
| 6th | EvidenceGate | Checks chain integrity AFTER case is resolved (so we know which case to check). Blocks ALL tools if BROKEN. |
| 7th | ResponseGuard | Runs AFTER the tool produces output — must see the actual result to redact it. |
| 8th | OpenSearchJobDispatch | Optionally replaces a blocking result with a queued job reference. Last so it can observe the unguarded result. |

---

### Q3: Why does `run_command` accept a string command but also parse it into pipeline stages internally?

The agent sends a single command string (potentially a pipe like `vol3 -f disk.img windows.pslist | grep explorer`). The executor needs to:
1. Detect which stage failed (SIGPIPE vs real failure) — not possible with a single process
2. Capture per-stage stderr separately
3. Report the "binary" that failed for forensic provenance

So `_run_command()` uses `split_command_by_operators()` to split the command into sub-commands (including on `|`, respecting quotes) and `parse_subcommand_argv_and_redirects()` to parse each sub-command into argv + redirects (both from `sift_core.execute.security`); the worker then runs each stage as a separate process with piped stdout/stdin. (There is no function named `_parse_pipeline_stages` — that was an invented name in the earlier draft.)

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:832,859 (split_command_by_operators / parse_subcommand_argv_and_redirects)]
[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:316-382]

**Why not shell exec?** Shell exec (via `shell=True`) would give a single process and a single exit code. The gateway would be unable to distinguish a SIGPIPE in `grep` from a genuine `vol3` failure.

---

### Q4: Why is the environment scrubbed before the worker subprocess?

Two layers of scrubbing:

1. **Gateway layer (K5)**: `build_sandbox_env()` strips all `SIFT_CONTROL_PLANE_DSN`, `SIFT_DB_*`, `SUPABASE_*`, `ANTHROPIC_API_KEY`, `OPENAI_*`, etc. from the environment before `subprocess.Popen()`.

   [VERIFY: packages/sift-core/src/sift_core/execute/runtime_acl.py]
   [VERIFY: packages/sift-core/src/sift_core/execute/executor.py:241-250]

2. **Worker layer**: The worker process scrubs again before it exec's the forensic tool binary.

**Why double-scrub?** Defense-in-depth. If a forensic tool binary has a code injection vulnerability (e.g., a malicious plugin in Volatility 3), it cannot exfiltrate secrets that aren't in its environment. The worker itself can't connect to Supabase even if compromised.

**Why not just empty env?** Some tools require `PATH`, `HOME`, `TMPDIR`, `LANG`. `build_sandbox_env()` constructs a minimal allowlist rather than an empty env.

---

### Q5: Why does the audit trail use dual-channel (DB + JSONL file)?

[VERIFY: packages/sift-common/src/sift_common/audit.py:263-361]
[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:808-1006 (AuditEnvelopeMiddleware)]

**DB-first in production**: `app.audit_events` in Postgres provides ACID durability, queryability, and tamper-evidence (Postgres WAL). This is authoritative.

**JSONL mirror**: The JSONL trail serves as:
- **Independent backup**: Survives DB outage or Supabase upgrade
- **Portability**: Human-readable, importable into SIEM tools
- **Chain of custody in file-mode**: When SIFT_CONTROL_PLANE_DSN is not set, JSONL IS the audit trail

**The `AuditEnvelopeMiddleware`** writes the audit start record to DB before calling next, then updates with the result after. If the gateway crashes between start and end, there's an orphaned "start" record in DB — a DFIR examiner reviewing audit logs would see a tool call that started but never completed, which is forensically correct.

---

### Q6: Why is the evidence chain global — blocking ALL tools rather than just evidence-touching tools?

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:463-528]  
[VERIFY: packages/sift-gateway/src/sift_gateway/evidence_gate.py:118,204]

When `EvidenceGateMiddleware` sees a gate result where **`status != ChainStatus.OK`** (the gate computes `blocked = status != OK`), it returns an error to the caller and does **not** call `next()`. Note there is no single `BROKEN` state — *any* non-OK status blocks: `UNSEALED`, `MODIFIED`, `MISSING`, `UNREGISTERED`, or `LEDGER_ERROR`. This blocks:
- `run_command` (forensic tool execution)
- `opensearch_search` (indexed data search)
- `record_finding` (documentation)
- Even read-only tools like `case_info`

**Why this strict?** A non-OK chain means one of:
1. No sealed manifest yet (`UNSEALED`) — nothing has been put under chain of custody
2. A registered file changed size (`MODIFIED`) or vanished (`MISSING`)
3. An unknown file appeared in `evidence/` (`UNREGISTERED`)
4. The manifest hash or ledger hash-chain failed structural verification (`LEDGER_ERROR`)

In every case, **any analysis result derived from this case is potentially invalid or unprovable**. Allowing agents to continue running commands on un-sealed or tainted evidence would produce findings that cannot be defended in court. The "nuclear option" of blocking everything is the correct DFIR response.

**The examiner must seal or repair the chain via the Examiner Portal** before analysis can continue (the block response's `remediation` field points there). This is intentional friction.

---

### Q7: How does the gateway achieve per-principal active case isolation in a multi-examiner scenario?

**File-mode**: Active case is a pointer file at `~/.sift/active_case`. All processes on the same user share the same case — no per-principal isolation possible.

**DB-mode**: `ActiveCaseService.require_active_case_for_principal(principal)` resolves the per-principal assignment by joining the assignment table to the case row (there is no `app.active_cases` table):
```sql
select c.id::text, c.case_key, c.title, c.description, c.status,
       c.artifact_path, c.metadata
from app.active_case_state s
join app.cases c on c.id = s.case_id
where s.principal = %s
```

[VERIFY: packages/sift-gateway/src/sift_gateway/active_case.py:148-174,449-470]

Each `Identity.principal` is a unique slug per examiner. Multiple examiners can have different active cases simultaneously. The case context is set per-request (not per-connection) via `AuthorityContext` (aliased `ActiveCaseContext`) as a Python contextvar.

[VERIFY: packages/sift-core/src/sift_core/active_case_context.py]

This means: examiner `alice` calling `run_command` gets her case injected; examiner `bob` calling simultaneously gets his case. The contextvar propagates through `asyncio.to_thread` correctly because Python 3.7+ copies contextvars into new threads.

---

### Q8: Why does the tool map use an atomic swap rather than locking?

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:378-566]

`_build_tool_map()` builds `new_tool_map`, `new_tool_cache`, `new_tool_manifest_meta` as local dicts, then does three assignments:
```python
self._tool_map = new_tool_map
self._tool_cache = new_tool_cache
self._tool_manifest_meta = new_tool_manifest_meta
```

**Why no lock?** In CPython, dict assignment is atomic at the C level (single bytecode `STORE_ATTR` instruction under the GIL). A concurrent reader either sees the old dict or the new dict — never a partially-built one.

**Tradeoff**: The three assignments are not atomically consistent with each other. A reader could see `_tool_map` updated to new but `_tool_manifest_meta` still old. In practice this is safe because:
1. `_build_tool_map` runs at boot and during `reload_backend_registry`
2. In-flight requests use their locally-captured `backend_name` string before the swap completes

A future improvement would be to wrap all three in a single tuple assignment or use a named tuple, making the snapshot truly atomic.

---

### Q9: How does `keep_alive=True` in StdioTransport affect the subprocess lifecycle?

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:556-604]

Without `keep_alive=True`: each tool call to a stdio backend would spawn a new subprocess, wait for it to initialize (load VOL3 plugins, connect to OpenSearch, etc.), execute, and exit. For opensearch-mcp, this initialization is expensive (~2s).

With `keep_alive=True`: FastMCP's `StdioTransport` keeps the subprocess running after the first call. Subsequent calls reuse the warm subprocess via stdin/stdout pipes.

**The pre-warm call in lifespan**:
```python
await gateway_mcp.list_tools()
```
[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:1283-1285]

This forces all backends to spawn their subprocesses at boot, so the first agent tool call doesn't pay the startup latency.

**Lifecycle**: The subprocess lives until the gateway shuts down (lifespan exit) or the backend is restarted via `ensure_backend_started()` after an error.

---

### Q10: Why does `_looks_binary()` use a heuristic rather than file magic (libmagic)?

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:521-534]

`_looks_binary()` inspects the first **8192 characters** of the already-decoded stdout (the worker decodes with `errors="replace"`). It returns `True` if either: (1) a **NUL byte** (`\x00`) is present, or (2) `len(head) >= 64` **and** the density of U+FFFD replacement characters (`�`) exceeds **5%** (`> 0.05`). It is a decoded-string heuristic — it does **not** count "non-printable bytes" and does not use a fixed 1% threshold. (See Algorithm Flows §7 for the canonical description; an earlier draft of this answer misstated the window as 8000 bytes and the threshold as 1% non-printable.)

**Why not libmagic / `file` command?**
1. **Output is in memory**: The executor already has the output as bytes. Running `file -` would require piping to a subprocess, adding latency.
2. **Context matters**: A forensic tool might emit mostly text with some embedded hex. Libmagic would classify the whole thing as binary; the heuristic would pass it through if the hex ratio is below threshold.
3. **No dependency**: `libmagic` Python bindings are not universally available on SIFT; avoiding it removes an install requirement.

**What happens when binary is detected**: The agent response includes `"binary_output": true` and a message explaining the output was saved to a file reference instead of inlined. The agent should use `get_tool_help` to discover appropriate decoders.

---

### Q11: How does the OpenSearch job dispatch middleware avoid blocking the agent on long ingests?

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:1037-1155]  
[VERIFY: packages/sift-gateway/src/sift_gateway/jobs.py:31-37]  
[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:744-760]

`OpenSearchJobDispatchMiddleware` intercepts exactly the tools in `_OPENSEARCH_JOB_DISPATCH_TOOLS = {opensearch_ingest, opensearch_enrich_intel}`. Instead of letting the call proceed to the opensearch-mcp backend (which would block for minutes on large EVTX files), it:

1. Passes through `opensearch_ingest` when `dry_run` is truthy (default `True`) — fast planning preview.
2. Otherwise builds a path-free `spec_public` + worker-only `spec_internal` and calls `job_service.enqueue_job(...)` → durable row in `app.jobs`.
3. Returns immediately with `{job_id, status: "queued", ...}`.

**Execution is decoupled from the gateway.** The actual ingest pipeline (FUSE-mount E01 + Hayabusa + vol3 → index) runs in dedicated, least-privilege **`sift-opensearch-worker@` systemd units** — the only place with the shared mount namespace FUSE needs. Those workers claim jobs via a Postgres lease and publish progress through the `worker_label` / `current_step` realtime fields.

The gateway's own `_job_reaper()` does **not** run jobs — it is a periodic sweep that calls the `app.expire_stale_jobs` RPC so leases whose worker stopped heartbeating get re-queued or marked expired (`server.py:744-760`).

The agent polls `running_commands_status(job_id)` → `job_service.get_job_status(job_id)` (which returns only the `app.job_status_public` allow-listed fields; `spec_internal` is never included).

**The key insight**: The job record is written in the `on_call_tool` pre-phase (before `next()`), so even if the gateway crashes immediately after returning to the agent, the job is durably queued and a worker unit will claim it.

---

### Q12: Why does the gateway validate `expected_mounted_tool_names()` against the actual catalog at startup?

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:1236-1243]

The manifests in `app.mcp_backends` declare what tools each backend promises to provide. The validation:
```python
expected = gateway.expected_mounted_tool_names()
actual = {t.name for t in await gateway_mcp.list_tools()}
if expected != actual:
    raise ValueError(f"Tool catalog mismatch: expected {expected - actual} missing")
```

**Why strict?** Without this check:
- A backend could register in the manifest but silently fail to start
- The gateway would advertise tools to agents that don't exist
- Agents would get confusing "unknown tool" errors mid-investigation

The startup validation ensures the system is fully consistent before serving the first request. The operator sees a clear error with exactly which tools are missing.

**Tradeoff**: Strict validation prevents partial backend failures from being masked. The downside is that a single bad backend prevents the whole gateway from starting. This is mitigated by `evaluate_requirement()` filtering — backends whose requirements aren't met are excluded from `_available_backends` BEFORE the validation check, so a missing OpenSearch doesn't block the rest.

---

## Security Questions

### Q13: What prevents an agent from accessing evidence outside its active case?

Three overlapping controls:

1. **EvidenceGateMiddleware** checks the gate (`status != OK → blocked`) for the principal's active case only.
   [VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:463-528]

2. **ProxyActiveCaseMiddleware** overwrites any agent-supplied `case_id`/`case_key`/`case_dir` arguments with the DB-authoritative values, and denies (`client_case_mismatch`) if the client supplied a conflicting value. Even if the agent sends `case_id="OTHER-CASE"`, it is rejected/replaced.
   [VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:719-805]

3. **`_trusted_internal_evidence_refs()`** enforces that resolved paths are under `case_root`:
   ```python
   if not path.is_relative_to(case_resolved):
       raise ValueError("internal evidence ref is unavailable")
   ```
   [VERIFY: packages/sift-core/src/sift_core/agent_tools.py:434-479]

Additionally, **`sanitize_paths_deep()`** ensures that even if an absolute path slips into the response, it gets redacted before the agent sees it.
[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:1107]

---

### Q14: What prevents an add-on backend from performing unauthorized case modifications?

`AddonAuthorityMiddleware` (H1) enforces the backend's declared `authority_contract` **before the backend is ever invoked** (fail-closed), using two checks:

```python
{
    "non_authoritative": true,    # advisory; tightens prohibited-op matching
    "required_scopes": ["dfir:opensearch"],
    "prohibited_operations": ["seal_evidence", "approve_finding", "bypass_gateway"]
}
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:326-460]

1. **`required_scopes`**: every manifest-declared scope on the tool must be satisfied by the caller's identity scopes, or the call is denied (`addon_scope_missing`).
2. **`prohibited_operations`**: if the tool name itself, or an `operation`/`action`/`op`/`command`/`mode` argument value, names a prohibited operation, the call is denied (`addon_prohibited_operation`).

`non_authoritative` is **advisory state**, not an injected flag: it is surfaced in the audit trail and, when `true`, tightens prohibited-operation matching so a query-only add-on fails closed. (The earlier draft's claim that the middleware injects `__gateway_non_authoritative=true` into the tool arguments is incorrect — no such injection happens.) The Gateway — not the add-on — remains the authority boundary.

**Deeper enforcement**: The backend runs in an isolated subprocess. It receives `case_id`/`case_dir` arguments from the gateway (never absolute paths directly). It can only write to locations where it has filesystem permission. The gateway scrubs the worker environment, so the backend can't use hidden credentials to bypass the contract.

---

### Q15: How does the response guard avoid false positives on legitimate forensic output?

`ResponseGuardMiddleware` uses pattern matching with context sensitivity:

1. **Path redaction**: Only absolute paths that don't start with the case dir are redacted. Paths WITHIN the case dir are allowed through (the case is the forensic workspace).

2. **Secret detection**: Patterns match only when the value looks like an actual credential (length, entropy, specific format). High-specificity patterns prevent accidental redaction of log lines that contain words like "password:" in a forensic event.

3. **Bypass for admin scopes**: Principals with `dfir:admin` scope can set `override_active=True` for specific tool calls (operator maintenance use cases).

[VERIFY: packages/sift-gateway/src/sift_gateway/response_guard.py]

**Limitation acknowledged in design**: There's no 100% reliable way to distinguish "forensic artifact that contains a leaked API key" from "response accidentally exposing a live credential". The guard errs on the side of redaction, with the examiner advised to check the saved output file for full content when investigating credential-related artifacts.
