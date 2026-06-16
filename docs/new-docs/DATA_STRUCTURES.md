# Data Structures (数据结构详解)

> Covers: packages/**/src/, supabase/migrations/
> Class: live-reference
> Last validated: a7ddaaa (2026-06-16)

## sift-mcps Key Data Structures

All structures verified from actual source code with [VERIFY:] citations.

---

## 1. Gateway Layer

### 1.1 `Gateway` class

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:126-165]

```python
class Gateway:
    config: dict                          # Loaded from gateway.yaml
    backends: dict[str, MCPBackend]       # name → MCPBackend instance
    _mounted_proxy_backends: set[str]     # Backend names with FastMCP proxies
    _fastmcp_server: FastMCP | None       # The aggregate FastMCP server
    _tool_map: dict[str, str]             # tool_name → backend_name (atomic swap)
    _tool_cache: dict[str, Tool]          # tool_name → MCP Tool object
    _start_locks: dict[str, asyncio.Lock] # Per-backend start lock (lazy mode)
    _audit: AuditWriter                   # mcp_name="sift-gateway"
    _available_backends: set[str]         # Backends passing requirements check
    mcp_backend_registry: McpBackendRegistry | None
    _mcp_catalog_loaded_at: datetime | None
    _tool_manifest_meta: dict[str, dict]  # tool_name → manifest UX metadata
    active_case_service: ActiveCaseService | None
    control_plane_dsn: str | None         # Postgres DSN
    evidence_service: EvidenceAuthorityService | None
    investigation_service: InvestigationService | None
    report_service: ReportService | None
    job_service: JobService | None        # Durable job service
    db_audit: DbAuditWriter | None        # DB-first audit sink
    _gateway_local_tools: set[str]        # Gateway-owned tool names (not proxied)
```

**Critical invariant**: `_tool_map` is atomically swapped in `_build_tool_map()` — never partially updated. Race-free read of the current catalog.

### 1.2 `CoreToolSpec` dataclass

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:41-47]

```python
@dataclass(frozen=True)
class CoreToolSpec:
    name: str                           # Tool name (e.g. "run_command")
    description: str                    # Agent-facing description
    input_schema: dict[str, Any]        # JSON Schema for arguments
    read_only: bool = False             # Whether tool is read-only
    output_schema: dict[str, Any] | None = None  # Structured output schema
```

**Instantiation**: **8** specs in the `CORE_TOOL_SPECS` tuple (not 9), in this order with their `read_only` flag:

| # | Tool | `read_only` |
|---|------|-------------|
| 1 | `case_info` | `True` |
| 2 | `evidence_info` | `True` |
| 3 | `record_finding` | `False` |
| 4 | `record_timeline_event` | `False` |
| 5 | `list_existing_findings` | `True` |
| 6 | `manage_todo` | `False` |
| 7 | `get_tool_help` | `True` |
| 8 | `run_command` | `False` |

`capability_guide`, `run_command_job`, and `running_commands_status` are **gateway-local** tools registered by `sift-gateway` (`mcp_server.py`), not members of `CORE_TOOL_SPECS`.

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:186-380]

### 1.3 Tool Manifest Metadata (per tool)

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:445-467]

```python
manifest_meta[tool_name] = {
    "backend": str,                     # Backend name that owns this tool
    "read_only": bool,                  # From manifest readOnlyHint
    "category": str,                    # UX category (e.g. "detection")
    "recommended_phase": str,           # Investigation phase (e.g. "TRIAGE")
    "health": bool,                     # Whether it's a health-check tool
    "health_args": dict,                # Args to pass for health check
    "hidden_from_agent": bool,          # Filtered from tools/list
    "when_to_use": str,                 # Usage guidance
    "avoid_when": str,                  # Avoidance guidance
    "output_notes": str,                # Output format notes
    "case_scoped": bool | None,         # Whether tool requires active case
    "required_scopes": list[str],       # Required identity scopes
    "authority_contract": dict | None,  # H1: add-on authority contract
    "safe_case_argument_names": list[str] | None,  # OS2: injectable case args
}
```

---

## 2. Identity & Authentication

### 2.1 `Identity` (principal record)

The class is named **`Identity`** (there is no `SiftIdentity`). It is a `@dataclass(frozen=True)` constructed by `resolve_identity()` and by the Supabase resolver:

```python
@dataclass(frozen=True)
class Identity:
    principal: str                 # Examiner/agent slug (validated ^[a-z0-9][a-z0-9-]{0,19}$)
    principal_type: str            # "user" | "agent" | "service"
    token_id: str | None
    agent_id: str | None
    created_by: str | None
    role: str                      # "examiner", "agent", "admin", ...
    source_ip: str | None
    auth_surface: str              # "mcp" | "portal" | "rest"
    case_id: str | None = None
    tool_scopes: frozenset[str] = frozenset()   # e.g. {"dfir:core", "dfir:opensearch"}
    token_fingerprint: str | None = None
    # PR03A unified Supabase JWT identity (all additive, defaulted):
    auth_user_id: str | None = None
    principal_id: str | None = None
    system_role: str | None = None
    case_memberships: tuple[CaseMembership, ...] = ()   # CaseMembership(case_id, role)
```

The slug pattern `^[a-z0-9][a-z0-9-]{0,19}$` is `_EXAMINER_RE` (defined in `identity.py:16`, `audit.py:21`, and 5 other files).

[VERIFY: packages/sift-gateway/src/sift_gateway/identity.py:14-32]  
[VERIFY: packages/sift-gateway/src/sift_gateway/identity.py:40-104 (resolve_identity)]

### 2.2 `SupabaseAuthConfig` (parsed from `auth.supabase` + `auth.legacy`)

The class is named **`SupabaseAuthConfig`** and lives in `supabase_auth.py` (not an `AuthConfig` in `config.py`). `configured` is a computed `@property`, not a field:

```python
@dataclass(frozen=True)
class SupabaseAuthConfig:
    enabled: bool = False
    url: str | None = None                  # read from env by name; never logged
    anon_key: str | None = None
    service_role_key: str | None = None
    validation: str = "user_api"
    principal_cache_ttl_seconds: int = _DEFAULT_CACHE_TTL
    min_agent_token_ttl_seconds: int = _DEFAULT_MIN_AGENT_TOKEN_TTL  # AUT2-B0
    legacy_token_fallback_enabled: bool = True
    legacy_portal_session_enabled: bool = True
    legacy_anonymous_examiner_enabled: bool = False

    @property
    def configured(self) -> bool:           # True when enabled AND url AND anon_key present
        return bool(self.enabled and self.url and self.anon_key)
```

[VERIFY: packages/sift-gateway/src/sift_gateway/supabase_auth.py:184-213]

---

## 3. Active Case Context

### 3.1 `ActiveCase` (gateway-resolved DB record)

[VERIFY: packages/sift-gateway/src/sift_gateway/active_case.py:25-50]

```python
@dataclass(frozen=True)
class ActiveCase:
    case_id: str                  # DB UUID of the case
    case_key: str                 # Human-readable case key (e.g. "IR-2026-001")
    title: str
    description: str | None
    status: str
    artifact_path: str | None     # Worker-only filesystem path to case directory
    metadata: dict[str, Any]
    membership_role: str | None = None   # Role of this principal in this case
```

(The earlier draft omitted `title`, `description`, `status`, and `metadata`, and over-typed `artifact_path` as a required `str`.)

### 3.2 `AuthorityContext` (in-process context variable; aliased `ActiveCaseContext`)

The canonical class is **`AuthorityContext`**; `ActiveCaseContext = AuthorityContext` is a backward-compat alias (`active_case_context.py:70`). It is `frozen=True`; `audit_event_ids` is a **public** mutable list (not `_audit_event_ids`), kept mutable so a later middleware can append the reserved id without rebuilding the frozen object:

```python
@dataclass(frozen=True)
class AuthorityContext:
    case_id: str
    case_key: str
    artifact_path: str | None = None        # case_dir comes from here (a property)
    membership_role: str | None = None
    principal: str | None = None
    principal_type: str | None = None
    tool_scopes: frozenset[str] = frozenset()
    evidence_gate_status: str | None = None  # gate snapshot observed at request time
    evidence_gate_version: int | None = None
    request_id: str | None = None
    db_active: bool = False                  # True when Postgres is the authority
    audit_event_ids: list[str] = field(default_factory=list)

    @property
    def case_dir(self) -> Path | None: ...   # Path(artifact_path) or None
```

(The earlier draft used the wrong class name, marked `audit_event_ids` private, and omitted the `evidence_gate_status`/`evidence_gate_version` snapshot fields.)

**Usage**: Set via `use_active_case_context(ctx)` context manager; read via `current_active_case()`. The DB-authority predicate is `db_authority_active()` (context `db_active=True` OR `SIFT_DB_ACTIVE` env).

[VERIFY: packages/sift-core/src/sift_core/active_case_context.py:29-124]

The context var propagates through the asyncio task to the thread (via `asyncio.to_thread`), so in-process core tools see the same context as the gateway middleware.

---

## 4. Audit System

### 4.1 `AuditWriter`

[VERIFY: packages/sift-common/src/sift_common/audit.py:102-165]

```python
class AuditWriter:
    mcp_name: str           # MCP identifier (e.g. "sift-gateway", "opensearch-mcp")
    _explicit_audit_dir: str | None
    _sequence: int          # Monotonic sequence counter (per-day, protected by lock)
    _date_str: str          # Current date in YYYYMMDD format
    _lock: threading.Lock   # Protects sequence counter
```

### 4.2 Audit Entry (JSONL record)

[VERIFY: packages/sift-common/src/sift_common/audit.py:296-330]

```json
{
    "ts": "2026-06-15T10:30:00.123456+00:00",
    "mcp": "sift-gateway",
    "tool": "run_command",
    "audit_id": "siftgateway-analyst-20260615-001",
    "examiner": "analyst",
    "case_id": "IR-2026-001",
    "source": "gateway_mcp_envelope",
    "params": {"command": "...", "purpose": "..."},
    "result_summary": {"exit_code": 0, "stdout_bytes": 1024},
    "elapsed_ms": 250.5,
    "input_files": ["/cases/IR-2026-001/evidence/disk.e01"],
    "input_sha256s": ["abc123..."],
    "input_detection_method": "evidence_ref"
}
```

**Audit ID format**: `{mcp_prefix}-{examiner}-{YYYYMMDD}-{seq:03d}`  
- `mcp_prefix`: `mcp_name` with `-mcp` stripped and `-` removed  
- e.g. `siftgateway-analyst-20260615-001`

---

## 5. Evidence Chain

### 5.1 `ChainStatus` enum

There are **six** members (there is no `BROKEN`):

```python
class ChainStatus(str, Enum):
    OK = "ok"                      # all registered files verified
    UNSEALED = "unsealed"          # no sealed manifest (version=0, no files)
    MODIFIED = "modified"          # a registered file's byte size differs
    MISSING = "missing"            # a registered file is not found on disk
    UNREGISTERED = "unregistered"  # an unknown file appeared in evidence/
    LEDGER_ERROR = "ledger_error"  # hash-chain broken or manifest hash mismatch
```

[VERIFY: packages/sift-core/src/sift_core/evidence_chain.py:35-41]

### 5.2 `chain_status(case_dir)` return value

```python
{
    "status": ChainStatus,    # OK / UNSEALED / MODIFIED / MISSING / UNREGISTERED / LEDGER_ERROR
    "issues": list[str],      # e.g. ["Missing: evidence/disk.E01", "Modified: ..."]
    "manifest_version": int,  # 0 when unsealed
    "ok_count": int,          # number of verified files
}
```

The gateway gate (`check_evidence_gate*`) derives **`blocked = (status != ChainStatus.OK)`** — so UNSEALED, MODIFIED, MISSING, UNREGISTERED, **and** LEDGER_ERROR all block (not only a single "broken" state). The DB path maps Postgres `seal_status` → `{sealed→OK, unsealed→UNSEALED, violated→LEDGER_ERROR}`.

[VERIFY: packages/sift-core/src/sift_core/evidence_chain.py:289-338]  
[VERIFY: packages/sift-gateway/src/sift_gateway/evidence_gate.py:118,130-134,204]

---

## 6. Execute / Run Command

### 6.1 Executor result dict

[VERIFY: packages/sift-core/src/sift_core/execute/executor.py:384-442]

The dict is built incrementally — **7 base keys** are always present; the rest are added only under the noted condition (so a simple text command returns just the base 7):

```python
# Always present (executor.py:384-394):
{
    "exit_code": int,
    "stdout": str,              # Cleaned stdout (CR progress stripped)
    "stderr": str,              # Truncated stderr (min(max_output//10, 4000) chars inline)
    "elapsed_seconds": float,   # round(elapsed, 2)
    "command": list,
    "stdout_total_bytes": int,  # Post-cleaning UTF-8 byte count
    "executor": str,            # "native_user_worker" if runtime_user else "direct_worker"
}
# Conditional:
    "runtime_user": str,        # only when a restricted runtime_user was used
    "progress_frames_removed": int,  # only when >0 progress frames stripped
    "truncated": True,          # only when worker truncated output
    "stages": list[dict],       # only for multi-stage pipelines
    "binary_output": True,      # only when _looks_binary(stdout)
    "stdout_note": str,         # only with binary_output (explains inline suppression)
# Added by _save_output() when output is persisted (executor.py:646-664):
    "output_file": str,  "output_sha256": str,
    "stderr_file": str,  "stderr_sha256": str,
}
```

### 6.2 Run Command response (agent-visible)

The response is `build_response(...)` (`response.py:95-188`) plus run-command-specific additions (`agent_tools.py:975-1047`). **`stdout`/`stderr`/`exit_code`/`elapsed_seconds` live inside the `data` payload — they are NOT top-level keys.** The canonical output handle is `full_output_ref` (there is no top-level `output_ref`):

[VERIFY: packages/sift-core/src/sift_core/execute/response.py:95-188]  
[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:975-1047]

```python
{
    # build_response root (always):
    "success": bool,
    "tool": "run_command",
    "data": dict,               # the executor result dict from §6.1 (stdout/stderr/exit_code/... live here)
    "audit_id": str,            # e.g. "siftgateway-analyst-20260615-001"
    "examiner": str,
    # build_response conditional: error, output_files, extractions,
    #   caveats, field_meanings, field_notes, advisories, corroboration, cross_mcp_checks
    # run_command additions (conditional):
    "warnings": list | None,
    "stages": list[dict] | None,        # multi-stage pipes: [{binary, exit_code}, ...]
    "failed_stages": list[dict] | None,
    "full_output_ref": str | None,      # case-relative path (e.g. "agent/run_commands/output1/...")
    "full_output_sha256": str | None,
    "full_output_bytes": int | None,
    "provenance": {
        "job_id": str,                  # "rc-<audit_id>"
        "input_sha256s": list[str],     # sorted(set(...)) hashes of evidence files read
        "input_count": int,
        "evidence_refs": list[str],     # public refs (no absolute paths)
        "output_sha256": str | None,    # present only when output saved
        "output_ref": str | None,       # present only when output saved
    },
}
```

**Security invariant**: `sanitize_paths_deep(response, case_dir=case_root)` runs on the entire response before return. In-case absolute paths become case-relative display paths; absolute paths under sensitive prefixes (`/cases`, `/evidence`, `/mnt`, `/media`, `/var/lib/sift`, `/dev`, configured roots) become `[REDACTED:absolute_path]`. Benign system paths (e.g. resolved `/usr/bin` tool binaries) are left intact so command echoes stay readable.

[VERIFY: packages/sift-core/src/sift_core/agent_tools.py:1107]  
[VERIFY: packages/sift-core/src/sift_core/execute/security.py:1256-1354]

---

## 7. Backend Backend Manifest (sift-backend.json)

Each add-on backend ships a manifest file that the gateway reads from `app.mcp_backends`:

[VERIFY: packages/sift-gateway/src/sift_gateway/server.py:415-467]

```json
{
    "namespace": "opensearch",
    "default_case_scoped": true,
    "authority_contract": {
        "non_authoritative": false,
        "prohibited_operations": []
    },
    "capabilities": {
        "provides": ["search", "ingest", "timeline"],
        "requires": ["127.0.0.1:9200"]
    },
    "tools": [
        {
            "name": "opensearch_search",
            "description": "...",
            "category": "detection",
            "recommended_phase": "TRIAGE",
            "read_only": true,
            "case_scoped": true,
            "safe_case_argument_names": ["case_id", "case_key", "case_dir"],
            "required_scopes": ["dfir:opensearch"],
            "hidden_from_agent": false,
            "when_to_use": "...",
            "avoid_when": "..."
        }
    ]
}
```

---

## 8. Durable Job

### 8.1 Durable jobs (`app.jobs` + `EnqueuedJob`)

There is **no `Job` dataclass** in `jobs.py`. `enqueue_job(...)` returns a tiny `EnqueuedJob(job_id)`; the full record lives in the `app.jobs` table and is read back through the `app.job_status_public` view (`get_job_status`).

```python
@dataclass(frozen=True)
class EnqueuedJob:
    job_id: str
```

Relevant `app.jobs` columns (DB is authoritative):

```text
id              uuid    -- the job_id (column is "id", not "job_id")
job_type        text    -- CHECK in {ingest, enrich, report, run_command}
status          text    -- CHECK in {queued, claimed, running, succeeded,
                        --            failed, cancelled, expired}
case_id         uuid
evidence_id     uuid | null
priority        int
spec_public     jsonb   -- path-free public spec (returned to agent)
spec_internal   jsonb   -- case_dir/case_key/examiner (worker only, never agent-visible)
result_public   jsonb | null
attempts        int     -- (not "attempt_count")
max_attempts    int
worker_id / lease_expires_at  -- lease internals (never exposed)
```

Agent/portal-safe fields (the `_PUBLIC_STATUS_FIELDS` allow-list, `jobs.py:53+`): `job_id, job_type, status, case_id, evidence_id, priority, attempts, max_attempts, spec_public, result_public, error_summary, provenance_id, created_at, started_at, …` plus the two realtime worker fields `worker_label` and `current_step`. The earlier draft's `Job` dataclass, the `completed`/`running` status names (real terminal success is **`succeeded`**), and the `ingest|enrich`-only job_type list were all inaccurate.

[VERIFY: packages/sift-gateway/src/sift_gateway/jobs.py:31-67,154]  
[VERIFY: supabase/migrations/*_durable_jobs.sql (app.jobs table + status/type CHECKs)]

---

## 9. Response Guard Patterns

The `ResponseGuardMiddleware` scans text content against a fixed list of compiled, **named, severity-tagged** secret signatures (`_PATTERNS`), plus an absolute-path detector. There is **no generic PII (email/phone) category** and no base64/binary category.

| Severity | Action | Example patterns (`_PATTERNS`) |
|----------|--------|--------------------------------|
| `critical` | **redacted** | AWS Access/Secret Key, GitHub Token/PAT, OpenAI/Anthropic/Stripe key, RSA/EC/OpenSSH private key, DB connection string, `api_key=…`, hex private key |
| `high` | **redacted** | Slack/Google/Telegram token, `password=…`, Bearer token, JWT, `"auth": "<blob>"` |
| `medium` | **flagged only, never redacted** | `KEY=value` env-file lines, `"skillsSnapshot": {` |

- Redaction applies to severities in `_REDACT_SEVERITIES = {critical, high}`; matched spans are replaced with `[REDACTED:{pattern_name}]`.
- Absolute paths are handled separately (`_ABS_PATH_RE`): in-case paths are left/relativized, sensitive absolute paths become `[REDACTED:absolute_path]`.
- Terminal control sequences are stripped via `sanitize_untrusted_output_text()`.

[VERIFY: packages/sift-gateway/src/sift_gateway/response_guard.py:50-90 (_PATTERNS, _REDACT_SEVERITIES)]  
[VERIFY: packages/sift-gateway/src/sift_gateway/response_guard.py:263 (redaction token)]

---

## 10. OpenSearch Index Mapping

The opensearch-mcp creates per-case indices with mappings for forensic events:

[VERIFY: packages/opensearch-mcp/src/opensearch_mcp/mappings/__init__.py]

Key fields in the forensic event mapping:
- `@timestamp`: ISO 8601 event timestamp (keyword + date)
- `hostname`: Source hostname (keyword)
- `event_id`: Windows Event ID (keyword)  
- `event_source`: Log source (keyword)
- `message`: Event message (text)
- `_sift.*`: SIFT-specific metadata namespace
- Plugin-specific fields (Sysmon, Defender, etc.)
