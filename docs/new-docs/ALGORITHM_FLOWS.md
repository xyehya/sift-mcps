# Algorithm Flows (算法流程详解)

## sift-mcps: Core Algorithm Analysis

All algorithms verified from actual source code with [VERIFY:] citations.

---

## 1. Policy Middleware Pipeline

### 1.1 Overview

The gateway's policy middleware stack is the most complex algorithm in the system. It implements a **defense-in-depth security model** where each layer has a specific responsibility and the ordering is load-bearing.

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:1158-1184]

```
Middleware execution order (FastMCP calls in list order):
┌─────────────────────────────────────────────────────────┐
│  1. ToolAuthorizationMiddleware   (outermost)           │
│  2. AddonAuthorityMiddleware                            │
│  3. CaseContextMiddleware                               │
│  4. AuditEnvelopeMiddleware                             │
│  5. ProxyActiveCaseMiddleware                           │
│  6. EvidenceGateMiddleware                              │
│  7. ResponseGuardMiddleware                             │
│  8. OpenSearchJobDispatchMiddleware  (innermost)        │
│     ↓                                                   │
│     Tool dispatch (core in-process OR proxy)            │
└─────────────────────────────────────────────────────────┘
```

**Why this order?**

- Auth before evidence gate: no point checking evidence integrity if caller is unauthorized
- Audit envelope before gate: the pre-dispatch audit write captures the "requested" event even for gate-blocked calls
- Response guard after dispatch: scrubs the actual result
- Job dispatch innermost: only after the full policy has been satisfied

### 1.2 `ToolAuthorizationMiddleware`

**Step-by-step**:

```
on_call_tool(context, call_next):
│
├── identity = current_mcp_identity()
│
├── If identity is None:
│       ├── auth_enabled=False → pass through (anonymous mode)
│       └── auth_enabled=True → return _deny(reason="no_identity")
│               (B6: auth configured but no identity → fail closed)
│
├── check_examiner_rate_limit(identity.principal)
│       ├── Uses token bucket or sliding window per examiner
│       └── If exceeded → return _rate_limited() + log_rate_limit_violation()
│
├── is_tool_allowed(identity, tool_name)
│       ├── Checks identity.tool_scopes against tool's required_scopes
│       └── → True/False
│
├── Allowed → await call_next(context)
└── Denied → await _deny(name, identity, reason="tool_scope")
                + audit.log(tool=name, result_summary="denied: tool_scope")
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:212-320]

### 1.3 `AddonAuthorityMiddleware` (H1)

**Purpose**: Enforce add-on backend's own authority contract BEFORE dispatch. Prevents a query-only backend from performing authority operations.

```
on_call_tool(context, call_next):
│
├── profile = gateway.addon_authority_for_tool(tool_name)
│       → None for core tools (skip entirely)
│
├── Check required_scopes:
│       missing = [s for s in profile["required_scopes"]
│                  if not is_scope_satisfied(identity, s)]
│       └── If missing → deny("addon_scope_missing")
│
└── Check prohibited_operations:
        attempted = set()
        ├── If tool_name itself is prohibited → hits.add(tool_name)
        └── For key in ("operation", "action", "op", "command", "mode"):
                value = args.get(key)
                if value in prohibited → hits.add(value)
        └── If hits → deny("addon_prohibited_operation")
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:326-460]

### 1.4 `CaseContextMiddleware`

**Purpose**: Resolve DB active case and set context variables so all downstream middleware and tools see the authoritative case state.

```
on_call_tool(context, call_next):
│
├── identity = current_mcp_identity()
├── service = _active_case_service(gateway)   # None in file-mode
│
├── If service:
│       case = service.require_active_case_for_principal(identity)
│           → select c.* from app.active_case_state s
│                join app.cases c on c.id = s.case_id where s.principal=%s
│           → ActiveCase{case_id, case_key, title, status, artifact_path, ...}
│           → If not found AND is_case_scoped_tool → ActiveCaseError
│               → audit + return _error_result("active_case_denied")
│
├── Build ActiveCaseContext(case_id, case_key, artifact_path, ..., db_active=True)
│       with request_id = uuid.uuid4().hex
│
├── with _use_gateway_active_case(case):     # Sets _CURRENT_ACTIVE_CASE
│   with use_active_case_context(core_ctx): # Sets sift_core contextvar
│       result = await call_next(context)
│
└── If case and tool in {case_info, evidence_info, capability_guide}:
        result.content.append(_case_text(case, tool_name))
            → Append JSON{case_context:{id, case_id, case_key, evidence_dir, agent_dir}}
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:638-716]

### 1.5 `AuditEnvelopeMiddleware` (K1: DB-first)

**Purpose**: DB-first authoritative audit trail. Fail closed for mutating tools when DB write fails.

```
on_call_tool(context, call_next):
│
├── Gather: identity, examiner, case, backend_name, request_id
├── redacted_args = redact_for_audit(_tool_args(context), case_dir)
│
├── PRE-DISPATCH (if db_audit):
│       Try: envelope_event_id = db_audit.record(
│                event_type="mcp.tool.call", status="requested",
│                summary=f"requested {name}",
│                details={tool, backend, arguments:redacted_args, ...}
│           )
│       Except:
│           ├── Mutating tool → fail closed (return "audit_unavailable" error)
│           └── Read-only tool → log warning, proceed
│
├── start = time.monotonic()
│
├── DISPATCH: result = await call_next(context)
│
└── POST-DISPATCH (finally block):
        elapsed_ms = (time.monotonic() - start) * 1000
        
        ├── Extract result_detail:
        │       summary = _summarize_audit_result(result_content)
        │       rc_detail = _extract_run_command_detail(result_content)
        │
        ├── DB result receipt (best-effort):
        │       db_audit.record(event_type="mcp.tool.result",
        │           status="success"|"failure", elapsed_ms=elapsed_ms,
        │           details={..., backend_audit_id, envelope_event_id, result_detail})
        │
        └── JSONL legacy mirror (best-effort):
                gateway._audit.log(tool=name, ..., source="gateway_mcp_envelope")
```

**_tool_is_mutating(name)**:
- Returns `not _tool_read_only(gateway, name)`
- `_tool_read_only`: checks CoreToolSpec.read_only, then manifest read_only flag
- Fail-safe: unknown tools are treated as mutating

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:808-1006]

### 1.6 `ProxyActiveCaseMiddleware` (B-11 / OS2)

**Purpose**: Inject DB-authoritative case_id/case_key/case_dir into proxied add-on tool arguments. Prevents add-on backends from resolving case from environment/files.

```
on_call_tool(context, call_next):
│
├── Skip if: core tool, gateway-local tool, or not case-scoped
│
├── case = _current_gateway_active_case()  # Set by CaseContextMiddleware
│       If None → pass through
│
├── safe_args = _safe_case_args(gateway, tool_name)
│       → gateway.safe_case_argument_names(tool_name)
│           ├── From manifest: tool["safe_case_argument_names"] (explicit list)
│           └── Fallback: schema properties {case_id, case_key, case_dir}
│       → None: unknown → DENY ("proxy_requires_implicit_case")
│       → set() (empty): declared no injection → pass through
│
└── For key in (case_id, case_key, case_dir):
        if key not in safe_args: skip
        supplied = args.get(key)
        if supplied and str(supplied) != expected:
            → DENY ("client_case_mismatch")
        args[key] = expected  # Overwrite with DB-authoritative value
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:719-805]

### 1.7 `EvidenceGateMiddleware`

**Purpose**: Block ALL tool calls (not just evidence-touching ones) when the evidence chain is compromised. Prevents analysis on tampered evidence.

```
on_call_tool(context, call_next):
│
├── case = _current_gateway_active_case()
├── case_dir_str = case.artifact_path OR env SIFT_CASE_DIR
│
├── Check gate:
│       If dsn and case:
│           gate = check_evidence_gate_db(case.case_id, dsn)
│               → SELECT seal_status, manifest_version, issues
│                 FROM app.evidence_gate_status(case_id)   # a FUNCTION, not a table
│       Else:
│           gate = check_evidence_gate(case_dir_str)
│               → chain_status(case_dir) → stat-check + structural hash-chain
│                 verify (NO per-file SHA-256 rehashing)
│
├── If NOT gate["blocked"] (i.e. status == ChainStatus.OK): await call_next(context)
│
└── If gate["blocked"] (status != OK — UNSEALED/MODIFIED/MISSING/UNREGISTERED/LEDGER_ERROR):
        ├── audit.log(source="gateway_evidence_gate", "blocked: evidence_chain_{status}")
        └── Return ToolResult(is_error=True, content=[
                build_block_response(name, gate),
                _case_text(case, name)
            ])
```

**Build block response** (`evidence_gate.py:211-232`) — actual keys:
```json
{
    "blocked": true,
    "reason": "evidence_chain_unsealed",   // or "evidence_chain_violation"
    "tool": "run_command",
    "status": "unsealed",                  // a ChainStatus value (no "broken")
    "issues": ["No sealed evidence manifest"],
    "manifest_version": 0,
    "detail": "No sealed evidence manifest. This tool requires evidence ...",
    "remediation": "<PORTAL_REMEDIATION>"
}
```

> The earlier draft invented `error: "evidence_gate_blocked"`, `chain_status: "broken"`, `blocked_tool`, and `required_action`; none of these keys exist, and `ChainStatus` has no `broken` member.

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:463-528]  
[VERIFY: packages/sift-gateway/src/sift_gateway/evidence_gate.py:211-232]

### 1.8 `ResponseGuardMiddleware`

**Purpose**: Redact secrets and cap output size in ALL tool results before they reach the agent.

```
on_call_tool(context, call_next):
│
├── result = await call_next(context)
│
├── case = _current_gateway_active_case()
├── override = is_override_active(case.case_id)  # Examiner can unlock
├── cap = output_cap_bytes()                       # From config
│
├── result, findings, cap_events = guard_tool_result(result,
│       override_active=override, case_dir=case_dir_str,
│       tool_name=name, cap_bytes=cap)
│       │
│       ├── For each TextContent in result.content:
│       │       ├── Pattern scan for secrets (API keys, tokens, etc.)
│       │       ├── Absolute path detection + redaction
│       │       ├── PII detection (if configured)
│       │       └── If override=False: replace with "[REDACTED:...]"
│       │
│       └── Cap enforcement: if content > cap_bytes:
│               → Truncate content
│               → Save overflow to spill file in case/tmp/
│               → Append "output_capped" notice
│
├── If findings → audit.log(source="gateway_response_guard", findings=[...])
├── If cap_events → audit.log(source="gateway_output_cap", cap_events=[...])
│
└── If sift_context:
        result.content.append(TextContent(_sift_context={...}))
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:531-636]

### 1.9 `OpenSearchJobDispatchMiddleware`

**Purpose**: Redirect heavy, privilege-requiring tools (FUSE mount, vol3) to dedicated worker units instead of running them in the gateway process.

```
on_call_tool(context, call_next):
│
├── If tool NOT in {opensearch_ingest, opensearch_enrich_intel}: pass through
├── If no job_service or no active case: pass through (graceful degradation)
│
├── For opensearch_ingest with dry_run=True: pass through (fast, read-only)
│
└── asyncio.to_thread(_enqueue, name, args, case):
        ├── identity = current_mcp_identity()
        ├── job_type = "ingest" | "enrich"
        ├── spec_public = _spec_public(name, args)   # Path-free public args
        ├── spec_internal = {case_dir, case_key, examiner}  # Never to agent
        ├── job = gateway.job_service.enqueue_job(
        │       job_type, case.case_id, spec_public, spec_internal,
        │       priority, max_attempts, actor=identity)
        └── Return ToolResult({job_id, status:"queued", next_step:...})
```

**_spec_public for ingest** (path-free):
```python
{
    "path": args["path"],          # Case-relative evidence ref (e.g. "evidence/x.e01")
    "format": args["format"],      # "e01", "raw", "auto", etc.
    "hostname": args["hostname"],  # Optional hostname override
    # All other tool args except case_id/case_key/case_dir
}
```

[VERIFY: packages/sift-gateway/src/sift_gateway/policy_middleware.py:1037-1155]

---

## 2. Command Execution Security Pipeline

### 2.1 Environment Scrubbing

[VERIFY: packages/sift-core/src/sift_core/execute/runtime_acl.py:40-205]

`build_sandbox_env()` constructs a minimal environment for the worker from **two fixed allowlists**, then applies a **secret deny floor** that wins even over the allowlist:

```python
_SAFE_ENV_NAMES = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL",
    "TMPDIR", "TMP", "TEMP",
    "LANG", "LANGUAGE",
    "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MESSAGES",  # FIXED subset, not "all LC_*"
    "TZ", "PWD",
}
_SAFE_SIFT_ENV_NAMES = {
    "SIFT_CASE_DIR", "SIFT_EXAMINER", "SIFT_TOOL_PATHS", "SIFT_TIMEOUT",
    "SIFT_HAYABUSA_DIR", "SIFT_RESPONSE_BUDGET", "SIFT_MAX_OUTPUT",
    "SIFT_EXECUTE_MEMORY_LIMIT", "SIFT_EXECUTE_AS_USER", "SIFT_SHARE_ROOT",
    "SIFT_STATE_DIR", SECURITY_POLICY_ENV,
}
# allow = _SAFE_ENV_NAMES | _SAFE_SIFT_ENV_NAMES ; then drop any name where
# _is_secret_env_name(name) is True (deny floor, checked AFTER the allowlist).
# Finally: scrubbed.setdefault("TERM", "dumb"); scrubbed.setdefault("LC_ALL", LANG or "C.UTF-8").

# NOTE: SIFT_DB_ACTIVE is NOT in either allowlist — it is dropped.
# Deny-floor substrings include: secret, password, token, dsn, supabase,
# postgres, opensearch, service_role, jwt, hmac, auth, session, cookie, ssh,
# and code-injection vectors ld_*, python, node_options, gconv_path, ifs, ...
```

So the scrubbed env is intentionally tiny (a locale, a search path, a writable temp/home, and the non-secret SIFT_* runtime knobs). Authority/secret-bearing vars — `SIFT_CONTROL_PLANE_DSN`, `SUPABASE_SERVICE_ROLE_KEY`, `OPENSEARCH_PASSWORD`, any `*_API_KEY` — are excluded by the allowlist and, redundantly, by the deny floor.

**Why**: Defense in depth. Even if the gateway is compromised, a forensic tool cannot exfiltrate secrets (or be hijacked via `LD_PRELOAD`/`PYTHON*` injection) because the environment is scrubbed before the subprocess fork.

### 2.2 Systemd Scope Isolation

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:90-177]

The `_systemd_scope_command()` function wraps the worker in a transient systemd scope unit:

```
systemd-run --scope --quiet --collect
    --unit=sift-run-command-{pid}-{monotonic_ns}.scope
    -p MemoryHigh={75% of limit}
    -p MemoryMax={limit}  (default: 4G)
    -p CPUQuota={200%}    (2 cores)
    -p TasksMax={64}
    -p RuntimeMaxSec={timeout + 5}
    -p OOMPolicy=kill
    -p IPAddressDeny=any  # No network from forensic tool process
    -p IOAccounting=yes
    -p IPAccounting=yes
    [--uid {runtime_user}]
    --
    python -m sift_core.execute.worker
```

**Three modes**:
- `off`: direct subprocess (development)
- `auto`: use systemd-run if available, else direct
- `required`: fail if systemd-run not available

### 2.3 Path Sanitization

These are **two distinct mechanisms** that the earlier draft conflated:

**(a) Output redaction — `sanitize_paths_deep()`** (`security.py:1256-1354`). Runs after tool execution, recursing through `str`/`dict`/`list`/`tuple`. Redaction is keyed on `_SENSITIVE_PATH_PREFIXES`, **not** on `is_authority_path`:

```
For each absolute-path token (single value, or embedded in stdout/stderr free text):
    ├── If token is inside case_dir (resolve + is_relative_to, with a textual
    │     fallback for not-yet-existing planned output paths):
    │       → rewrite to a case-relative display path
    │         e.g. "/cases/IR-2026-001/evidence/disk.E01" → "evidence/disk.E01"
    │
    ├── Else if token starts with a sensitive prefix
    │     {/cases, /evidence, /mnt, /media, /var/lib/sift, /dev,
    │      resolved cases_root(), $SIFT_STATE_DIR}:
    │       → "[REDACTED:absolute_path]"
    │
    └── Else (benign system path like /usr/bin/vol3): LEFT INTACT
```

So not every absolute path is redacted — benign tool-binary paths survive so command echoes stay readable.

**(b) Authority write-jail — `is_authority_path()`** (`runtime_acl.py:232-241`, used by `assert_no_authority_write_target`). This is unrelated to response redaction; it refuses `run_command` **write/redirect targets** that land on a proof artifact. It returns True when the path's basename is in `AUTHORITY_FILE_BASENAMES` (e.g. `case.yaml`, `evidence-manifest.json`, `evidence-ledger.jsonl`) **or** the path contains a marker in `_AUTHORITY_PATH_MARKERS`:
- `"/audit/"`  (the substring with slashes — not just "audit")
- `"evidence-anchor"`
- `"/.sift/"`
- `"/var/lib/sift"`

(There is no `/cases/` marker, and `evidence-ledger` is matched as a basename, not an arbitrary substring.)

[VERIFY: packages/sift-core/src/sift_core/execute/security.py:1256-1354]  
[VERIFY: packages/sift-core/src/sift_core/execute/runtime_acl.py:207-256]

---

## 3. Audit ID Generation Algorithm

[VERIFY: packages/sift-common/src/sift_common/audit.py:163-231]

```python
def _next_audit_id(examiner: str) -> str:
    today = datetime.now(UTC).strftime("%Y%m%d")
    
    with self._lock:  # Thread-safe
        if today != self._date_str:
            # New day: resume sequence from sidecar file or JSONL scan
            self._date_str = today
            self._sequence = _resume_sequence(today)
            # O(1) sidecar read → O(n) JSONL scan fallback
        
        self._sequence += 1
        seq = self._sequence
    
    prefix = mcp_name.replace("-mcp", "").replace("-", "")
    return f"{prefix}-{examiner}-{today}-{seq:03d}"
```

**Sequence resume on restart**:
1. Try sidecar file: `{mcp_name}.seq` → `{"date": "20260615", "seq": 42}`
2. Fallback: scan entire JSONL with regex `r"-{date_str}-(\d+)$"`, take max
3. Resume from max (prevents duplicates across restarts)

**Format**: `{prefix}-{examiner}-{YYYYMMDD}-{seq:03d}`
- `prefix`: `mcp_name.replace("-mcp", "").replace("-", "")` — strip `-mcp` first, then remove remaining dashes. So `sift-gateway → siftgateway`, `opensearch-mcp → opensearch`, and **`windows-triage-mcp → windowstriage`** (not `windowstriagemcp`).
- The prefix derives from the **`mcp_name`**, never the tool name. (CLAUDE.md's `run_command-analyst-...` example is misleading: `run_command` is the *tool* and lives in the separate `tool` field; the prefix would be `siftgateway`/`siftcore`/etc.)
- `examiner`: validated slug `^[a-z0-9][a-z0-9-]{0,19}$` (`_EXAMINER_RE`, `audit.py:21`)
- Sequence: zero-padded 3 digits (resets daily)

---

## 4. Tool Map Build Algorithm

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:378-566]

```python
async def _build_tool_map() -> None:
    raw_map: dict[str, list[str]] = {}  # tool → [backends]
    tool_objects: dict[str, Tool] = {}
    manifest_meta: dict[str, dict] = {}
    self._available_backends.clear()
    
    for name, backend in self.backends.items():
        # 1. Requirement evaluation
        is_available = True
        for req in manifest.get("capabilities", {}).get("requires", []):
            if not self.evaluate_requirement(req):
                is_available = False; break
        if not is_available: continue
        self._available_backends.add(name)
        
        # 2. Index manifest UX metadata per tool
        for tool_decl in manifest.get("tools", []):
            manifest_meta[tool_decl["name"]] = {
                "backend": name,
                "read_only": ..., "category": ..., "recommended_phase": ...,
                "safe_case_argument_names": ...,  # OS2
                "authority_contract": ...,         # H1
                ...
            }
        
        # 3. Collect tools
        if backend.started:
            tools = await backend.list_tools()
            # Validate namespace prefix + manifest declaration
            for tool in tools:
                raw_map.setdefault(tool.name, []).append(name)
                tool_objects[tool.name] = tool
        else:
            # Synthesize from manifest (lazy-start mode)
            for tool_decl in manifest["tools"]:
                raw_map.setdefault(tool_decl["name"], []).append(name)
    
    # 4. Collision detection
    new_map: dict[str, str] = {}
    for tool_name, backend_names in raw_map.items():
        if len(backend_names) > 1:
            raise ValueError(f"Tool name collision: {tool_name}")
        if tool_name in core_tool_names():
            raise ValueError(f"Core tool name collision: {tool_name}")
        new_map[tool_name] = backend_names[0]
    
    # 5. Atomic reference swap
    self._tool_map = new_map
    self._tool_cache = {name: Tool(...) for name in new_map}
    self._tool_manifest_meta = {t: manifest_meta[t] for t in new_map if t in manifest_meta}
```

**Complexity**: O(B × T) where B = backends, T = tools per backend  
**Invariant**: The swap is atomic (Python dict assignment) — concurrent readers see either the old or new map, never a partial state.

---

## 5. Requirement Evaluation Algorithm

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:272-343]

```python
def evaluate_requirement(req: str) -> bool:
    req = req.strip()
    if not req: return True
    
    # "docker" → check PATH
    if req.lower() == "docker":
        return shutil.which("docker") is not None
    
    # "ram:8gb" → check total physical memory
    if req.lower().startswith("ram:"):
        total_gb = (sysconf(SC_PAGE_SIZE) * sysconf(SC_PHYS_PAGES)) / (1024**3)
        match = re.match(r"ram:(\d+(?:\.\d+)?)\s*(gb|g|mb|m)?", req, re.IGNORECASE)
        required_gb = float(val) if "g" in unit else float(val) / 1024
        return total_gb >= required_gb
    
    # "env:VAR_NAME" → check env var exists (and path exists if it's a path)
    if req.lower().startswith("env:"):
        var_name = req[4:].strip()
        if var_name not in os.environ: return False
        val = os.environ[var_name]
        if val.startswith("/"):
            return os.path.exists(val)
        return True
    
    # "host:port" or "http://host:port" → TCP connect test
    if host and port:
        try:
            socket.create_connection((host, port), timeout=2.0)
            return True
        except Exception:
            return False
    
    # Unknown format → fail closed (warn loudly)
    logger.warning("Unknown requirement format: %r — treating as UNMET", req)
    return False
```

**Fail-closed principle**: Unrecognized requirement format returns False, gating the backend. This ensures a typo in a requirement string surfaces immediately rather than silently passing.

---

## 6. Evidence Reference Resolution Algorithm

[VERIFY: packages/sift-core/src/sift_core/execute/security.py]  
[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:434-479]

```
resolve_evidence_ref(ref, case_dir):    [security.py:1166-1223]
    │
    ├── Reject empty ref or ref containing a NUL byte
    │
    ├── Load ACTIVE entries of the sealed manifest
    │       (evidence-manifest.json; evidence-ledger.jsonl is the legacy append-log)
    │       → only entries with status == "ACTIVE" are considered
    │
    ├── If no active entries → EvidenceRefError("...the case has no sealed evidence...")
    │
    ├── Match ref against each entry, in order, by:
    │       1. exact evidence_id  (entry["evidence_id"] or entry["id"])
    │       2. exact relative display path  (e.g. "evidence/disk.E01")
    │       3. basename of the relative path  (e.g. "disk.E01")
    │       (NOTE: there is NO match-by-sha256)
    │
    ├── If no match → EvidenceRefError("... does not match any sealed evidence ...")
    │
    └── Resolve through the input-path jail (must stay inside case_dir)
        → Return the absolute path the worker may read
```

**DB path** (when _INTERNAL_RESOLVED_EVIDENCE_REFS injected by Gateway):

```python
_trusted_internal_evidence_refs(refs, case_root):
    # Requires DB-active context (db_active=True in ActiveCaseContext)
    for item in refs:
        path = Path(item["path"]).resolve()
        if not path.is_relative_to(case_root) or not path.is_file():
            raise ValueError("internal evidence ref is unavailable")
        paths.append(str(path))
        public_refs.append(item.get("evidence_id") or item.get("display_path"))
    return paths, public_refs
```

**Security invariant**: The absolute path from `_INTERNAL_RESOLVED_EVIDENCE_REFS` must be:
1. Inside `case_root` (containment check)
2. An existing file (not a symlink attack)
3. In a DB-active context (prevents downgrade attack)

---

## 7. Binary Output Detection Algorithm

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:521-534]

```python
def _looks_binary(stdout: str) -> bool:
    if not stdout: return False
    head = stdout[:8192]  # Only scan the first 8KB
    
    # NUL byte is a definitive binary indicator
    if "\x00" in head: return True
    
    # High density of replacement characters (U+FFFD) from errors="replace" decode
    if len(head) >= 64 and head.count("") / len(head) > 0.05:
        return True
    
    return False
```

**Why**: The worker decodes tool stdout with `errors="replace"`. Binary files (PE, ELF, SQLite, etc.) produce a high density of `U+FFFD` replacement characters (>5% threshold). This prevents bloating the agent context with useless binary blobs; instead they're saved to file.

---

## 8. Progress Frame Stripping Algorithm

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:495-518]

```python
def _strip_cr_progress(text: str) -> tuple[str, int]:
    """Collapse \\r progress frames and drop vol3/tqdm progress lines."""
    if "\r" not in text and "Progress:" not in text:
        return text, 0  # Fast path
    
    removed = 0
    out_lines = []
    
    for line in text.split("\n"):
        # Handle \\r within a line (tqdm style: "Progress:  10%\\rProgress:  20%\\r...")
        if "\r" in line:
            frames = line.split("\r")
            removed += sum(1 for f in frames[:-1] if f.strip())
            line = frames[-1]  # Keep only the LAST frame (final terminal state)
        
        # Drop Volatility 3 "Progress:  NN.NN ..." lines
        if _CR_PROGRESS_RE.match(line):  # r"^\s*Progress:\s"
            removed += 1
            continue
        
        out_lines.append(line)
    
    return "\n".join(out_lines), removed
```

**Motivation**: A single `vol3 windows.info` produces ~139,000 lines / 9.4 MB of pure progress output. Without stripping, this would:
1. Exceed the response byte budget → trigger auto-save
2. Blow the agent context window
3. Bloat the saved output file

The algorithm keeps only the final progress frame (terminal visible state) and drops all intermediate `Progress:` lines.

---

## 9. Late Backend Discovery Algorithm (OSX1)

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:626-685]

```python
async def reload_backend_registry() -> bool:
    # Re-reads app.mcp_backends for new rows
    instances, loaded_at = await asyncio.to_thread(
        registry.create_backend_instances
    )
    
    new_names = [name for name in instances if name not in self.backends]
    if not new_names:
        self._mcp_catalog_loaded_at = loaded_at  # Keep timestamp fresh
        return False
    
    # Mount new backends onto the live FastMCP server
    for name in new_names:
        backend = instances[name]
        self.backends[name] = backend
        
        # mount_single_addon_proxy: idempotent, checks _mounted_proxy_backends
        if self._fastmcp_server:
            mount_single_addon_proxy(self._fastmcp_server, self, name, backend)
    
    await self._build_tool_map()  # Rebuild tool catalog
    return True
```

**Called from**:
1. `_late_start_checker()` — every 30 seconds background task
2. `app_lifespan` — pre-serve reload before first request (closes startup race)

**Idempotency**: `_mounted_proxy_backends` set prevents double-mounting a backend that was already registered.

---

## 10. Audit Sequence Resume Algorithm

[VERIFY: packages/sift-common/src/sift_common/audit.py:183-231]

```python
def _resume_sequence(date_str: str) -> int:
    """Resume sequence from last known position to prevent duplicate audit IDs."""
    
    # Fast path: O(1) sidecar file read
    seq_file = audit_dir / f"{mcp_name}.seq"
    if seq_file.exists():
        data = json.loads(seq_file.read_text())
        if data["date"] == date_str:
            return data["seq"]  # Resume from where we left off
    
    # Slow path: O(n) JSONL scan (only on first startup or date rollover)
    log_file = audit_dir / f"{mcp_name}.jsonl"
    suffix_re = re.compile(rf"-{re.escape(date_str)}-(\d+)$")
    max_seq = 0
    
    with open(log_file) as f:
        for line in f:
            if date_str not in line: continue  # Fast skip
            entry = json.loads(line)
            audit_id = entry.get("audit_id", "")
            m = suffix_re.search(audit_id)
            if m:
                max_seq = max(max_seq, int(m.group(1)))
    
    return max_seq
```

**Why**: On server restart, the sequence counter resets to 0. Without resume, the next call would produce audit_id `...-001` which may already exist in the JSONL file, creating non-unique IDs. The sidecar file provides O(1) resume; JSONL scan is the fallback for corrupted sidecars.
