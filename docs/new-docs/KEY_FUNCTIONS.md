# Key Functions Analysis (关键函数分析)

## sift-mcps: Deep Dive into Critical Functions

All functions verified from actual source code with [VERIFY:] citations.

---

## 1. `Gateway.create_app()` — FastAPI Application Builder

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:1084-1408]

**Purpose**: Builds the complete FastAPI application with all services, routes, and middleware.

**Internal structure**:

```
create_app(self) -> FastAPI:

Step 1: Initialize control-plane services (lines 1096-1128)
    ├── DbAuditWriter(dsn)           → DB-first audit sink
    ├── ActiveCaseService(dsn)       → Per-principal case resolution
    ├── JobService(dsn)              → Durable job queue
    ├── EvidenceAuthorityService(dsn)
    ├── InvestigationService(dsn)
    └── ReportService(dsn)

Step 2: Initialize Supabase auth (lines 1138-1173)
    ├── SupabaseAuthClient(auth_config)
    ├── SupabasePrincipalRepository(dsn)
    ├── SupabaseIdentityResolver(auth_config, client, repository)
    ├── AgentServiceIssuance(auth_config, client, dsn)
    └── SupabaseAuthCallbacks(auth_config, client, repo, resolver, ...)

Step 3: Create aggregate MCP server (lines 1192-1216)
    ├── create_gateway_mcp_server(gateway, api_keys, token_registry, resolver, ...)
    │       → FastMCP with policy middleware + proxy backends
    ├── mcp_app = gateway_mcp.http_app(path="/")
    └── MCPAuthASGIApp(mcp_app, ...)
            → ASGI guard: Origin, body size, IP rate limit, token verify

Step 4: App lifespan (lines 1218-1290)
    ├── gateway.start()                      → _build_tool_map()
    ├── gateway.reload_backend_registry()    → mount late-seeded backends
    ├── Validate expected vs actual tools    → raise ValueError if mismatch
    ├── Pre-warm: gateway_mcp.list_tools()   → spawn add-on subprocesses (LV1)
    └── Background tasks:
            _late_start_checker() (always)
            _idle_reaper() (if idle_timeout > 0)
            _job_reaper() (if job_service present)

Step 5: Routes (lines 1292-1408)
    ├── health_routes()     → /health, /api/v1/health
    ├── rest_routes()       → /api/v1/...
    ├── case-dashboard      → /portal/* (if installed)
    └── MCPAuthASGIApp      → /mcp

Step 6: Middleware (added in reverse — outermost added last)
    ├── AuthMiddleware           (REST auth)
    ├── CORSMiddleware           (restricted to gateway origin)
    ├── _NormalizeMCPPath        (adds trailing slash)
    ├── _PortalHTTPSGuard        (enforces HTTPS for portal)
    └── SecureHeadersMiddleware  (HSTS, X-Content-Type-Options, CSP)
```

**Key invariant**: The lifespan validates that `expected_mounted_tool_names()` (from manifests) equals the actual FastMCP catalog. A manifest-registered tool missing from the catalog causes a ValueError at startup, preventing silent capability gaps.

---

## 2. `Gateway._build_tool_map()` — Tool Catalog Construction

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:378-566]

**Purpose**: Constructs the authoritative tool-name → backend-name mapping.

**Inputs**: `self.backends` (dict[str, MCPBackend]), manifest data

**Outputs**: Atomically swapped `_tool_map`, `_tool_cache`, `_tool_manifest_meta`

**Critical path**:
```
1. Evaluate requirements for each backend → filter to _available_backends

2. For each available backend:
   a. Index manifest UX metadata (category, phase, safe_case_argument_names, authority_contract)
   b. If backend.started: list_tools() with 15s timeout
      - Validate: every tool starts with namespace prefix
      - Validate: every tool is declared in manifest["tools"]
   c. If not started: synthesize Tool objects from manifest declarations

3. Collision detection:
   - Same tool name across backends → ValueError
   - Add-on tool name == core tool name → ValueError

4. Atomic swap of all three dicts
```

**Complexity**: O(B × T) where B = number of backends, T = max tools per backend  
**Thread safety**: The swap is GIL-protected in CPython (dict assignment is atomic).

---

## 3. `call_core_tool()` — Core Tool Dispatcher

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:1263-1348]

**Purpose**: Single dispatch point for all 9 in-process core tools.

```python
def call_core_tool(name, arguments, *, examiner, manager, audit) -> str:
    
    if name not in _SPECS_BY_NAME:
        raise KeyError(name)  # Unknown tool — must be a routing error
    
    effective_examiner = (examiner or resolve_examiner()).strip().lower()
    manager = manager or CaseManager()
    audit = audit or AuditWriter(mcp_name="sift-core")
    
    try:
        if name == "case_info":
            result = _case_info(manager)
        elif name == "evidence_info":
            result = _evidence_info()
        elif name == "record_finding":
            result = _record_finding(args, effective_examiner, manager, audit)
        elif name == "record_timeline_event":
            ...
        elif name == "run_command":
            result = _run_command(args, effective_examiner, audit)
        # ... etc.
    except Exception as exc:
        # ALL exceptions from tool execution are caught here and converted
        # to a structured envelope so the gateway never misreports them
        # as "unknown tool {name}".
        result = {"success": False, "tool": name, "data": None,
                  "error": f"{type(exc).__name__}: {exc}"}
    
    return _json_result(result)  # json.dumps(result, indent=2, default=str)
```

**Key design**: The `KeyError` for unknown tools is raised BEFORE the `try` block. Any error DURING execution of a known tool is caught and wrapped. This means the gateway correctly distinguishes "tool not found" from "tool execution failure".

---

## 4. `_run_command()` — Forensic Command Executor

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:687-1152]

The most complex core tool (the function body runs to ~1152 — the main path returns `sanitize_paths_deep(...)` at line 1107, followed by three exception handlers). Full analysis:

**Phase 1: Input Validation and Setup** (lines 687-735)
```python
audit_id = audit._next_audit_id(examiner)

command, command_error = _coerce_run_command(args["command"])
# Rejects: command arrays with shell operators (|, &&, >, etc.)
# Accepts: single string (pipes allowed), clean array → shlex.join

purpose = str(args.get("purpose", ""))
# Required: empty purpose → error (prevents undocumented tool use)

cwd = resolve_working_dir(args["working_dir"], active_case_ctx)
case_root = get_case_dir()
```

**Phase 2: Evidence Reference Resolution** (lines 759-813)
```python
evidence_refs = args.get("evidence_refs")
if "_evidence_ref_error" in args:
    # Gateway failed to resolve refs from DB → error (not silently proceed)
    return build_response(error=evidence_ref_error)

if "_resolved_evidence_refs" in args:
    # DB-active path: Gateway resolved refs to absolute paths
    resolved_paths, public_refs = _trusted_internal_evidence_refs(
        args["_resolved_evidence_refs"], case_root=case_root
    )
else:
    # File-mode path: resolve from sealed manifest
    for ref in evidence_refs:
        resolved_paths.append(resolve_evidence_ref(ref, case_dir=case_root))
```

**Phase 3: Input Detection and Provenance Hashing** (lines 832-907)
```python
for subcmd_str, _ in subcmds:
    argv, redirects = parse_subcommand_argv_and_redirects(subcmd_str)
    # Detect: < redirects, tool catalog input_flag, positional path args
    
for fpath in detected_inputs:
    p = Path(fpath).resolve()
    if p.is_file() and p.stat().st_size <= 1_000_000_000:  # Skip >1GB
        h = hashlib.sha256()
        with open(p, "rb") as hf:
            for chunk in iter(lambda: hf.read(65536), b""):
                h.update(chunk)
        input_hashes[str(p)] = h.hexdigest()
```

**Phase 4: Execution** (lines 909-918)
```python
exec_result = _execute_command(
    command, purpose=purpose, timeout=timeout or None,
    save_output=bool(args.get("save_output")) or bool(save_dir),
    save_dir=save_dir, cwd=cwd,
    preview_lines=min(int(args.get("preview_lines") or 0), 200),
)
```

**Phase 5: Pipeline Failure Detection (AUT2-B5)** (lines 946-965)
```python
failed_stages = []
for idx, stage in enumerate(raw_stages):
    rc = stage["exit_code"]
    # SIGPIPE (141/-13) in non-final stages is NORMAL (head, grep closing pipe)
    if rc in (141, -13) and idx < len(raw_stages) - 1:
        continue
    if rc not in (0, None):
        failed_stages.append({
            "binary": stage["binary"],
            "exit_code": rc,
            "stderr_tail": stage.get("stderr_tail") or hint
        })
```

**Phase 6: Response Construction and Provenance** (lines 975-1047)
```python
response = build_response(
    tool_name="run_command", success=pipeline_ok, data=exec_result,
    audit_id=audit_id, output_format=output_format,
    fk_tool_name=fk_name, output_files=[output_file_ref], ...
)

response["provenance"] = {
    "job_id": f"rc-{audit_id}",        # Stable handle for findings
    "input_sha256s": sorted(set(input_hashes.values())),
    "input_count": len(input_hashes),
    "evidence_refs": public_evidence_refs,   # Opaque refs (no absolute paths)
    "output_sha256": output_sha256,
    "output_ref": output_file_ref,
}
```

**Phase 7: Final Path Sanitization** (line 1107)
```python
return sanitize_paths_deep(response, case_dir=case_root)
# Scrubs EVERY string value recursively:
# - In-case absolute paths → relative display path
# - Other absolute paths → "[REDACTED:absolute_path]"
```

---

## 5. `Gateway.call_tool()` — Tool Routing

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:924-1082]

**Purpose**: Routes a tool call to the correct backend (core or proxied).

```python
async def call_tool(name, arguments, examiner, identity) -> list:

# Step 1: Active case resolution (for case-scoped tools)
if active_case_service and is_case_scoped_tool(name):
    active_case = active_case_service.require_active_case_for_principal(identity)

# Step 2: Route to core tools (in-process)
if name in core_tool_names():
    context = ActiveCaseContext(case_id, case_key, artifact_path, db_active=True)
    
    def _run_core():
        with use_active_case_context(context):
            return call_core_tool(name, arguments, examiner=examiner, audit=self._audit)
    
    text = await asyncio.to_thread(_run_core)
    return [TextContent(type="text", text=text)]

# Step 3: Route to backend (proxy)
if name not in self._tool_map:
    raise KeyError(f"Unknown tool: {name}")

backend_name = self._tool_map[name]
backend = self.backends[backend_name]

# Step 4: Inject active case arguments
if active_case and is_case_scoped_tool(name):
    safe_args = self.safe_case_argument_names(name)
    if safe_args is None:
        raise RuntimeError("proxied case-scoped tool does not expose a safe case arg")
    for key, expected in (("case_id", ...), ("case_key", ...), ("case_dir", ...)):
        if key in safe_args:
            if arguments.get(key) and str(arguments[key]) != expected:
                raise RuntimeError(f"client-supplied {key} does not match DB active case")
            arguments[key] = expected

# Step 5: Lazy restart
if not backend.started:
    await self.ensure_backend_started(backend_name)

# Step 6: Dispatch with 300s timeout
result = await asyncio.wait_for(backend.call_tool(name, arguments), timeout=300.0)

# Step 7: Centralized audit for HTTP backends
if isinstance(backend, HttpMCPBackend):
    await asyncio.to_thread(
        self._audit.log, tool=name, params=_truncate_params(arguments),
        result_summary=_summarize_result(result), source="gateway_proxy",
        elapsed_ms=elapsed_ms, extra={"backend": backend_name, ...}
    )

return result
```

Note: In the FastMCP architecture (D27b), this function is called via the REST API path, NOT the MCP path. The MCP path goes through FastMCP's own proxy dispatch. Both paths have different audit mechanisms.

---

## 6. `AuditWriter.log()` — Forensic Audit Writer

[VERIFY: packages/sift-common/src/sift_common/audit.py:263-330]

**Purpose**: Write an immutable, fsync'd audit entry to the JSONL trail.

```python
def log(tool, params, result_summary, source, audit_id, elapsed_ms, ...) -> str | None:

# Step 1: Get audit directory
audit_dir = self._get_audit_dir()
# Priority: explicit_dir → SIFT_AUDIT_DIR → SIFT_CASE_DIR/CASE.yaml resolved
if not audit_dir:
    if _db_authority_env_active():
        # DB-active mode: Postgres is the authority. JSONL absence is expected.
        return audit_id or self._next_audit_id(examiner)
    return None  # No active case — caller should handle

# Step 2: Generate audit ID if not provided
if audit_id is None:
    audit_id = self._next_audit_id(examiner_override)

# Step 3: Build entry
entry = {
    "ts": datetime.now(UTC).isoformat(),
    "mcp": self.mcp_name,
    "tool": tool,
    "audit_id": audit_id,
    "examiner": examiner_override or self.examiner,
    "case_id": case_id or env["SIFT_ACTIVE_CASE"] or pointer_file.read(),
    "source": source,
    "params": params,
    "result_summary": _summarize(result_summary),
    # Optional: elapsed_ms, input_files, input_sha256s, input_detection_method
}
if extra: entry.update(extra)

# Step 4: Write with fsync (durability)
success = self._write_entry(entry)

# Step 5: Update sidecar (O(1) sequence resume on next restart)
self._write_seq_sidecar()

return audit_id if success else None
```

**_write_entry with fsync**:
```python
def _write_entry(entry: dict) -> bool:
    log_file = audit_dir / f"{self.mcp_name}.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())  # Force to disk
    return True
```

**Thread safety**: The sequence counter is protected by `self._lock` (threading.Lock). File writes are not locked (each write is a single `append` + `fsync`; POSIX guarantees atomicity of writes below PIPE_BUF for local filesystems).

---

## 7. `create_gateway_mcp_server()` — MCP Server Assembly

[VERIFY: packages/sift-gateway/src/sift_gateway/mcp_server.py:385-423]

```python
def create_gateway_mcp_server(gateway, *, api_keys, token_registry,
                               base_url, resolver, legacy_fallback_enabled) -> FastMCP:

# Step 1: Create verifier (authentication)
verifier = None
if resolver or api_keys or token_registry:
    verifier = SiftTokenVerifier(
        api_keys=api_keys,
        token_registry=token_registry,
        base_url=base_url,
        resolver=resolver,
        legacy_fallback_enabled=legacy_fallback_enabled,
    )

# Step 2: Assemble middleware stack
middlewares = [
    GatewayToolCatalogMiddleware(gateway),  # Category/phase metadata + filtering
    *gateway_policy_middlewares(gateway, auth_enabled=bool(verifier)),
    # ToolAuthorization, AddonAuthority, CaseContext, AuditEnvelope,
    # ProxyActiveCase, EvidenceGate, ResponseGuard, OpenSearchJobDispatch
]

# Step 3: Create FastMCP server
mcp = FastMCP(
    "sift-gateway",
    instructions=_build_gateway_instructions(gateway),  # Dynamic system prompt
    auth=verifier,
    middleware=middlewares,
)
gateway._fastmcp_server = mcp  # Store ref for OSX1 late-mount

# Step 4: Register in-process core tools
_register_core_tools(mcp, gateway)
# → 9 GatewayLocalTool instances (case_info, evidence_info, run_command, etc.)
# → 1 capability_guide tool (dynamic, no handler)
# → N gateway job tools (if job_service wired)

# Step 5: Mount add-on proxies
_mount_addon_proxies(mcp, gateway)
# → For each backend with manifest:
#       mount_single_addon_proxy(mcp, gateway, backend_name, backend)
#           → _create_backend_proxy() → StdioTransport(keep_alive=True) or FastMCPProxy
#           → mcp.mount(proxy, namespace=ns, tool_names=rename_map)

return mcp
```

**GatewayToolCatalogMiddleware.on_list_tools()**: Filters `_AGENT_FILTERED_TOOLS` and `hidden_from_agent` tools from the advertised catalog, and injects `meta.category` and `meta.recommended_for_phase` onto each tool.

---

## 8. `_trusted_internal_evidence_refs()` — DB Evidence Path Resolution

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:434-479]

**Purpose**: Resolve Gateway-injected evidence paths (from DB manifest) into absolute paths, with strict security checks.

```python
def _trusted_internal_evidence_refs(refs, *, case_root) -> tuple[list[str], list[str]]:
    
    # MUST be in DB-active context (prevent downgrade attack)
    ctx = current_active_case()
    if ctx is None or not ctx.db_active:
        raise ValueError("internal evidence refs require DB authority context")
    
    # refs must be a list (injected by Gateway, not from agent)
    if not isinstance(refs, list):
        raise ValueError("internal evidence refs must be an array")
    
    case_resolved = Path(case_root).resolve()
    paths, public_refs = [], []
    
    for item in refs:
        if not isinstance(item, dict):
            raise ValueError("internal evidence ref entries must be objects")
        
        path_text = str(item.get("path") or "")
        if not path_text:
            raise ValueError("internal evidence ref missing path")
        
        path = Path(path_text).resolve()
        
        # Containment check: MUST be inside case directory
        if not path.is_relative_to(case_resolved):
            raise ValueError("internal evidence ref is unavailable")
        
        # Existence check: MUST be an existing file
        if not path.is_file():
            raise ValueError("internal evidence ref is unavailable")
        
        paths.append(str(path))
        public_refs.append(str(item.get("evidence_id") or item.get("display_path") or ""))
    
    return paths, [ref for ref in public_refs if ref]
```

**Security invariants**:
1. DB-active context required (prevents bypassing via direct sift-core calls)
2. Containment: symlink-resistant `is_relative_to()` check
3. Existence: prevents forged paths to non-existent evidence
4. Returns ONLY paths; public_refs strip the absolute path from agent output

---

## 9. `guard_tool_result()` — Response Guard

[VERIFY: packages/sift-gateway/src/sift_gateway/response_guard.py]

**Purpose**: Scan tool results for secrets/paths and cap size.

```python
def guard_tool_result(result, *, override_active, case_dir, tool_name, cap_bytes):
    findings = []      # Detected patterns (for audit)
    cap_events = []    # Output capping events (for audit)
    
    new_contents = []
    for content in result.content:
        if isinstance(content, TextContent):
            text = content.text
            
            # Secret/path scanning
            if not override_active:
                text, detected = _scan_and_redact(text, case_dir=case_dir)
                findings.extend(detected)
            
            # Output capping
            if cap_bytes > 0 and len(text.encode()) > cap_bytes:
                overflow = text.encode()[cap_bytes:]
                text = text[:cap_bytes].decode(errors="replace") + "...[CAPPED]"
                cap_events.append({
                    "original_bytes": len(text.encode()) + len(overflow),
                    "returned_bytes": cap_bytes,
                    "cap_bytes": cap_bytes,
                    "output_file": _save_overflow(overflow, case_dir, tool_name),
                })
            
            new_contents.append(TextContent(type="text", text=text))
        else:
            new_contents.append(content)
    
    result.content = new_contents
    return result, findings, cap_events
```

**Pattern scanning** (`_scan_and_redact`):
- Compiled regex patterns for API keys, tokens, credentials
- Path detection: absolute paths matching sensitive patterns
- Case-dir-relative paths are allowed (case analysis is the purpose)
- Redaction: `[REDACTED:{pattern_name}]` replaces matched text

---

## 10. `evaluate_requirement()` — Backend Capability Check

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:272-343]

**Purpose**: Evaluate a backend's runtime requirement before including it in the tool catalog.

| Requirement type | Example | Check method |
|-----------------|---------|-------------|
| Docker available | `"docker"` | `shutil.which("docker") is not None` |
| RAM minimum | `"ram:8gb"` | `sysconf(SC_PHYS_PAGES) * sysconf(SC_PAGE_SIZE) / 1024**3 >= 8` |
| Env variable | `"env:OPENCTI_URL"` | `os.environ.get("OPENCTI_URL")` + optional path existence |
| Network endpoint | `"127.0.0.1:9200"` | `socket.create_connection(("127.0.0.1", 9200), timeout=2.0)` |
| HTTP endpoint | `"http://localhost:9200"` | Same via urlparse |
| Unknown | anything else | Fail closed (log warning, return False) |

**Fail-closed principle**: An unrecognized requirement string gates the backend rather than passing it through. This surfaces typos immediately (operator sees the warning in logs and fixes the manifest).

**Design trade-off**: The TCP connect test (2s timeout) runs synchronously during `_build_tool_map()`. For N backends with network requirements, this adds up to N×2s worst case at boot. This is acceptable for a server that boots rarely.
