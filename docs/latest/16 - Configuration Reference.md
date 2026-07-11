# Configuration Reference

## A. Gateway YAML (`~/.sift/gateway.yaml`)

The gateway reads its configuration from `gateway.yaml` at the path passed to
`--config` (default `gateway.yaml` in the working directory; the systemd unit
sets this to `~/.sift/gateway.yaml`). Environment variable interpolation
(`${VAR}`) is applied at load time by `config.py:_interpolate_env`. Secrets are
**never** stored in the YAML — only env-var name references.

### gateway

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `gateway.host` | string | `"0.0.0.0"` | Bind address for all listeners (REST, MCP) | `gateway.yaml.template:2` |
| `gateway.port` | integer | `4508` | Listen port | `gateway.yaml.template:3` |
| `gateway.tls.certfile` | path | `$SIFT_TLS_DIR/gateway-cert.pem` | TLS certificate file for HTTPS/WS | `gateway.yaml.template:5` |
| `gateway.tls.keyfile` | path | `$SIFT_TLS_DIR/gateway-key.pem` | TLS private key file | `gateway.yaml.template:6` |
| `gateway.rate_limit.ip_calls_per_minute` | integer | `120` | Per-IP pre-auth rate limit (localhost bypassed) | `rate_limit.py:129` |
| `gateway.rate_limit.examiner_calls_per_minute` | integer | `120` | Per-principal post-auth rate limit | `mcp_endpoint.py:320` |
| `gateway.rate_limit.burst` | integer | `20` | Burst allowance above the per-minute rate | `rate_limit.py` `RateLimiter` |
| `gateway.lazy_start` | boolean | `false` | Defer backend process launch to first tool request | `server.py:284-287` |
| `gateway.idle_timeout_seconds` | integer | `0` | Idle backend subprocess timeout; `0` = never kill | `server.py:290-293` |

### case

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `case.root` | path | `$SIFT_CASES_ROOT` | Root directory for evidence/case files. The gateway exports this as `SIFT_CASES_ROOT` in the process env at startup via `config.py:apply_case_env`. | `gateway.yaml.template:15` |

### execute

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `execute.runtime_user` | string | `$SIFT_EXECUTE_AS_USER` | Linux user for `run_command` sandboxing. `"__current__"` only for local dev (never production). | `gateway.yaml.template:24` |
| `execute.security.mode` | string | `"allowlist"` | Executor policy mode: `allowlist` (default) or `denylist` | `gateway.yaml.template:30` |
| `execute.security.allowed_binaries` | list | `["@mvp_forensic"]` | Whitelist binary groups/tools; `@mvp_forensic` resolves to the bundled SIFT forensic toolset | `gateway.yaml.template:31-32` |
| `execute.security.unlisted_policy` | string | `"contained"` | Policy for non-denied binaries absent from the allowlist: `contained` (kernel-jailed, never blocked) | `gateway.yaml.template:33` |
| `execute.security.dangerous_flags` | list | `["-e","--exec","--command","-enc","-encodedcommand","--script","--invoke"]` | Globally prohibited command flags (shell/code execution escapes) — enforced before per-tool rules | `gateway.yaml.template:34-41` |
| `execute.security.tool_allowed_flags` | map | `run_bulk_extractor: ["-e","-x"]` | Per-tool flag exemptions that override the global dangerous_flags block for that specific tool | `gateway.yaml.template:42-45` |
| `execute.security.tool_blocked_flags` | map | `find: [-exec,-execdir,-delete,-fls,-fprint,-fprint0,-fprintf]`; `sed: [-i,--in-place]`; `tar: [-x,--extract,--get,-c,--create,--delete,--append,--checkpoint-action,--use-compress-program,--to-command]`; `unzip: [-o,-n]` | Per-tool additional blocked flags (blocked even if not in dangerous_flags). The built-in deny floor always applies. | `gateway.yaml.template:46-71` |
| `execute.security.output_flags` | list | `["--csv","--csvf","-o","--output","--json","--jsonl"]` | Flags that direct tool output to a file — the gateway resolves the output path into the sandboxed case directory to prevent overwriting arbitrary filesystem paths | `gateway.yaml.template:72-78` |
| `execute.security.denied_binaries` | list | 19 entries (see below) | Operator-supplied denial list; the gateway unions this with a **non-weakenable built-in deny floor** | `gateway.yaml.template:79-102` |

**Built-in deny floor** (always active, operator cannot weaken): `mkfs`, `mkfs.ext4`, `mkfs.xfs`, `mkfs.btrfs`, `mkfs.ntfs`, `shutdown`, `reboot`, `poweroff`, `halt`, `init`, `kill`, `killall`, `pkill`, `env`, `printenv`, `nc`, `ncat`, `socat`. Categories: filesystem destruction, system state mutation, process termination, environment/token leakage, raw sockets.

### trust

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `trust.output_cap_bytes` | integer | `262144` (256 KiB) | Central output cap on all tool responses forwarded to the agent. The gateway translates this to `SIFT_OUTPUT_CAP` env at startup (`config.py:apply_trust_env` → `response_guard.py:output_cap_bytes`). Oversized responses are truncated; the full redacted output is spilled to `<case>/agent/tool_outputs/` and a pointer + SHA-256 returned. | `gateway.yaml.template:112`, `response_guard.py:526-527` |

### auth

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `auth.supabase.enabled` | boolean | `true` | Enable Supabase JWT identity (PR03A/D30). When `true`, the gateway validates Supabase-issued JWTs and rejects all other credential types. | `gateway.yaml.template:124` |
| `auth.supabase.url_env` | string | `SUPABASE_URL` | Name of the env var holding the Supabase API URL | `gateway.yaml.template:125` |
| `auth.supabase.anon_key_env` | string | `SUPABASE_ANON_KEY` | Name of the env var holding the public anon key | `gateway.yaml.template:126` |
| `auth.supabase.service_role_key_env` | string | `SUPABASE_SERVICE_ROLE_KEY` | Name of the env var holding the admin service-role key | `gateway.yaml.template:127` |
| `auth.supabase.validation` | string | `"user_api"` | JWT validation mode: `user_api` validates against Supabase's `/auth/v1/user` endpoint | `gateway.yaml.template:128` |
| `auth.supabase.principal_cache_ttl_seconds` | integer | `30` | In-memory cache TTL for principal lookups | `gateway.yaml.template:129` |
| `auth.supabase.min_agent_token_ttl_seconds` | integer | `172800` (48h) | **AUT2-B0** — minimum JWT lifetime for agent principal issuance. If Supabase Auth returns a session shorter than this, the gateway rejects the issue with `agent_token_ttl_below_minimum`. `0` disables the check. Deploy must set `GOTRUE_JWT_EXP` / `JWT_EXPIRY` ≥ this value on the Supabase Auth service. | `gateway.yaml.template:134`, `supabase_auth.py:200,1482-1504` |
| `auth.legacy.anonymous_examiner_enabled` | boolean | `false` | **Pre-PR03 only** — enable the anonymous single-examiner legacy mode (no Supabase). Must remain `false` in production. | `gateway.yaml.template:144` |

**Removed keys (SEC-6):** `auth.legacy.token_fallback_enabled` and `auth.legacy.portal_session_enabled` have been **deleted**. Legacy PR02 `mcp_tokens` registry tokens and examiner HMAC cookies no longer authenticate. A stale key in an existing install is silently ignored.

### control\_plane

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `control_plane.postgres_dsn_env` | string | `SIFT_CONTROL_PLANE_DSN` | Name of the env var holding the Postgres control-plane DSN | `gateway.yaml.template:148` |

### token\_registry

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `token_registry.pepper_env` | string | `SIFT_TOKEN_PEPPER` | Name of the env var holding the pepper for token hashing | `gateway.yaml.template:152` |

### portal

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `portal.session_secret_env` | string | `SIFT_PORTAL_SESSION_SECRET` | B-MVP-010 env-indirection — only the env var **name** is stored here; the secret value lives in `~/.sift/control-plane.env` (0600), resolved at startup by `config.py:resolve_portal_session_secret`. Backward-compatible: a literal `session_secret` in an older config is accepted. | `gateway.yaml.template:187`, `config.py:184-210` |
| `portal.session_max_age` | integer | `28800` (8h) | Sliding session lifetime for the portal cookie (seconds). Absolute ceiling is **12h** enforced by `session_jwt.py:38` (`ABSOLUTE_ENVELOPE_LIFETIME_SECONDS`) — a stolen HttpOnly cookie cannot be refreshed indefinitely even if the gateway refresh callback is lax. | `gateway.yaml.template:188`, `session_jwt.py:33-38` |
| `portal.default_examiner` | string | `$SIFT_EXAMINER` | Default examiner slug for legacy surfaces | `gateway.yaml.template:189` |
| `portal.require_password_reset` | boolean | `true` | Require first-login password reset for operator accounts | `gateway.yaml.template:190` |

### api\_keys (legacy bootstrap)

The `api_keys` block in the template (`gateway.yaml.template:154-179`) provides
**installer-created bootstrap tokens** for the initial examiner and Hermes agent
service. On a PR03A Supabase deployment these are superseded by the portal's
principal-issuance flow; they exist for the installation handoff and legacy
compatibility.

### opensearch

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `opensearch.url` | string | `"http://127.0.0.1:9200"` | OpenSearch cluster HTTP endpoint | `gateway.yaml.template:193` |
| `opensearch.verify_certs` | boolean | `true` | Verify TLS certificates on OpenSearch connections | `gateway.yaml.template:194` |
| `opensearch.ca_cert_path` | path | `$SIFT_TLS_DIR/ca-cert.pem` | CA certificate for OpenSearch TLS verification | `gateway.yaml.template:195` |

### enrichment

| Key | Type | Default | Effect | Source |
|-----|------|---------|--------|--------|
| `enrichment.enabled` | boolean | `true` | Global enrichment toggle | `gateway.yaml.template:198` |
| `enrichment.forensic_knowledge` | boolean | `true` | Enable Forensic Knowledge (FK) enrichment. FK is a **core runtime dependency (D4)**, not an add-on. | `gateway.yaml.template:200` |
| `enrichment.root` | path | `"/var/lib/sift/enrichment"` | Root directory for enrichment data | `gateway.yaml.template:201` |

Add-on enrichment (e.g. RAG grounding) is derived at runtime from the
capabilities a registered backend advertises in its manifest
(`capabilities.provides: reference/enrichment`) — no static core flag controls it.

### backends

| Key | Default | Effect |
|-----|---------|--------|
| `backends` | `{}` | **Intentionally empty (D22A).** Add-on backend registration is authoritative in Postgres `app.mcp_backends` via the portal. This YAML block is ignored by the gateway loader. Backend credentials are represented by DB-stored env-var references (`bearer_token_env`, `tls_cert_env`, `env_refs`); usable secret values live only in the gateway process environment. | `gateway.yaml.template:213` |

---

## B. Environment Variables

Gateway and worker processes read their secrets and runtime knobs from the
environment. The systemd unit (`configs/systemd/sift-gateway.service`) sets
mandatory isolation variables and loads env files from `~/.sift/`.

### Secrets & control plane

| Var name | Read by | Effect | Default |
|----------|---------|--------|---------|
| `SIFT_CASES_ROOT` | `case_io.py:cases_root()` | Evidence root directory. Set by the gateway from `case.root` at startup. | `~/cases` |
| `SIFT_CONTROL_PLANE_DSN` | `token_registry.py:registry_config` | Postgres connection DSN for the control plane (app schema, principal store, audit log) | (required) |
| `SIFT_AUDIT_WRITER_DSN` | `investigation_store.py`, `policy_middleware.py` | Scoped Postgres DSN for the least-privilege audit writer role. Provisioned by `install.sh:provision_audit_writer`. Falls back to `SIFT_CONTROL_PLANE_DSN` if unset. | (from `SIFT_CONTROL_PLANE_DSN`) |
| `SIFT_TOKEN_PEPPER` | `token_generation.py:token_hash` | Pepper for legacy token hashing (PR02 tokens) | (required) |
| `SIFT_PORTAL_SESSION_SECRET` | `session_jwt.py` | HMAC key for the portal session cookie JWT | (required) |
| `SUPABASE_URL` | `supabase_auth.py:SupabaseAuthConfig` | Supabase API URL | (required when `auth.supabase.enabled`) |
| `SUPABASE_ANON_KEY` | `supabase_auth.py:SupabaseAuthConfig` | Public anon key for client-side auth | (required when `auth.supabase.enabled`) |
| `SUPABASE_SERVICE_ROLE_KEY` | `supabase_auth.py:SupabaseAuthConfig` | Admin service-role key for user management and agent issuance | (required when `auth.supabase.enabled`) |

### Runtime identity & resource

| Var name | Read by | Effect | Default |
|----------|---------|--------|---------|
| `SIFT_EXAMINER` | `sift_core/identity.py:54` | Default examiner slug used when no principal context is available (legacy surfaces, audit fallback) | OS username |
| `HF_HOME` | RAG / Hayabusa | HuggingFace cache directory for embedding models | `$SIFT_HF_HOME` (sift-service home) |
| `RAG_MODEL_NAME` | `forensic-rag-mcp/constants.py` | BGE embedding model name for knowledge-base search | `BAAI/bge-base-en-v1.5` |
| `RAG_MODEL_REVISION` | `forensic-rag-mcp/constants.py` | Pinned git revision of the embedding model for reproducible weights | `a5beb1e...` |
| `OPENSEARCH_CONFIG` | `opensearch-mcp/client.py:get_client()` | Path to the OpenSearch YAML config (host, credentials). Set by the gateway from `app.mcp_backends` `env_refs`. | `~/.sift/opensearch.yaml` |

### Sandboxing & isolation (run\_command)

| Var name | Read by | Effect | Default |
|----------|---------|--------|---------|
| `SIFT_EXECUTE_AS_USER` | `executor.py:execute` | Linux user for `run_command` sandbox execution. Set by the gateway from `execute.runtime_user` at startup (`config.py:93`). | `agent_runtime` |
| `SIFT_EXECUTE_REQUIRE_RUNTIME_USER` | `executor.py:301` | Fail closed if the executing process is not running as the `runtime_user` (UID check). Set by systemd unit. | `1` |
| `SIFT_EXECUTE_REQUIRE_LANDLOCK` | `dfir_exec_launcher.py:491` | Require Landlock LSM sandboxing. Set by systemd unit. | `1` |
| `SIFT_EXECUTE_SYSTEMD_SCOPE` | `executor.py:_systemd_scope_mode` | Wrap `run_command` execution in a transient systemd scope with cgroup isolation (IPAddressDeny=any, MemoryHigh/Max, CPUQuota). `0` to disable (local dev only). SEC-11: the legacy `auto` mode is removed — any non-off value requires systemd-run; a missing systemd-run fails closed. | `1` |
| `SIFT_EXECUTE_SYSTEMD_SCOPE_HELPER` | `executor.py:_systemd_scope_helper_path` | Path to the privileged helper binary for creating transient systemd scopes. Defaults to `/usr/local/sbin/sift-run-command-systemd-scope`. | (none — falls back to direct `systemd-run` if helper absent) |
| `SIFT_EXECUTE_SECCOMP_MODE` | `dfir_exec_launcher.py:491` | Seccomp filter mode for the forensic-tool process: `kill` (SECCOMP_RET_KILL the violating process) or `log` (audit only). Socket syscalls are always `log`-only so `curl`/`wget` read-only fetches and AF_UNIX IPC survive. | `kill` |
| `SIFT_EXECUTE_SYSTEMD_MEMORY_MAX` | `executor.py:_systemd_memory_props` | systemd scope `MemoryMax` (hard limit). Overrides the per-tool memory budget. | `4G` |
| `SIFT_EXECUTE_SYSTEMD_MEMORY_HIGH` | `executor.py:_systemd_memory_props` | systemd scope `MemoryHigh` (soft throttle). | `3G` |
| `SIFT_EXECUTE_SYSTEMD_CPU_QUOTA` | `executor.py:_systemd_scope_command` | systemd scope `CPUQuota`. | `200%` |
| `SIFT_EXECUTE_SYSTEMD_TASKS_MAX` | `executor.py:_systemd_scope_command` | systemd scope `TasksMax`. | `64` |

### Observability

| Var name | Read by | Effect | Default |
|----------|---------|--------|---------|
| `SIFT_LOG_FORMAT` | `sift_common/oplog.py:setup_logging` | Log output format: `json` or `text` | `json` |
| `SIFT_LOG_FILE` | `sift_common/oplog.py:setup_logging` | Write structured logs to `~/.sift/logs/{service}.jsonl` | `true` |

### Output guard

| Var name | Read by | Effect | Default |
|----------|---------|--------|---------|
| `SIFT_OUTPUT_CAP` | `response_guard.py:output_cap_bytes` | Override `trust.output_cap_bytes` at runtime. Set by the gateway config loader at startup. | From `trust.output_cap_bytes` (256 KiB) |

### Installer-mode knobs

| Var name | Read by | Effect | Default |
|----------|---------|--------|---------|
| `SIFT_EXTERNAL_SUPABASE` | `install.sh:75` | Skip Supabase auto-provisioning. Requires `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, and `SIFT_CONTROL_PLANE_DSN` already exported. | `0` |
| `SIFT_OFFLINE` | `install.sh:88` | Air-gapped install mode: attempt zero network downloads; each missing artifact fails loudly with the expected staged path | `0` |
| `SIFT_GEOIP_ENABLED` | `install.sh:89` | Enable the OpenSearch ip2geo pipeline (fetches from a live endpoint) | `0` |
| `SIFT_WITH_RAG` | `install.sh` | Install the first-party RAG pack (`true` or `false`) | `false` |
| `SIFT_WITH_WINDOWS_TRIAGE` | `install.sh` | Install the Windows-triage pack (`true` or `false`) | `false` |
| `SIFT_WITH_WINDOWS_TRIAGE_REGISTRY` | `install.sh` | Install the separate large registry baseline (`true` or `false`) | `false` |
| `SIFT_APPARMOR_ENFORCE` | `install.sh` | Internal resolved posture; secure installs enforce AppArmor by default. Use `--apparmor-complain` only for local profile development. | `1` |

---

## C. Backend Manifest (`sift-backend.json`) Schema

Every add-on backend ships a `sift-backend.json` manifest. At registration time
the manifest is validated by `McpBackendRegistry` and stored in Postgres
`app.mcp_backends`. The gateway reads the registry at startup (and periodically
thereafter via `_late_start_checker`) to discover tools.

### Top-level fields

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `spec_version` | string | yes | Manifest format version | `"1.0"` |
| `name` | string | yes | Unique backend identifier | `"opensearch-mcp"` |
| `version` | string | yes | Semantic version | `"1.0.0"` |
| `tier` | enum | yes | Backend tier: `addon` | `"addon"` |
| `transport` | enum | yes | Communication protocol: `stdio` or `http` | `"stdio"` |
| `namespace` | string | yes | Tool name prefix, e.g. `"opensearch_"` → tool becomes `opensearch_search` | `"opensearch_"` |
| `instructions` | string | no | Agent-facing usage instructions surfaced in the tool list | `"OpenSearch queries require..."` |
| `default_case_scoped` | boolean | no | Whether all tools default to requiring a case context (default: `false`) | `true` |
| `hidden_from_agent` | boolean | no | Hide the backend from agent tool listings (default: `false`) | `false` |

### data\_plane

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dependencies` | list[string] | yes | Data-plane services this backend depends on. E.g. `["opensearch"]`. |
| `writes` | boolean | yes | Whether the backend writes to the data plane |
| `notes` | string | yes | Human-readable operational notes |

### capabilities

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provides` | list[string] | yes | Capabilities the backend offers. E.g. `["search", "ingest", "enrichment"]`. |
| `requires` | list[string] | yes | Resources the backend needs. E.g. `["http://localhost:9200"]`. |
| `enriches_responses` | boolean | no | Whether this backend enriches tool responses from other backends (default: `false`) |

### authority\_contract

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `non_authoritative` | boolean | yes | Backend output is derived, never authoritative. |
| `prohibited_operations` | list[string] | yes | Operations the backend guarantees it will never perform. E.g. `["approve_findings", "alter_evidence", "decide_reports"]`. |

### tools[] entries

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Tool name (without namespace prefix) |
| `description` | string | yes | What the tool does |
| `when_to_use` | string | no | Guidance for when agents should invoke this tool |
| `avoid_when` | string | no | Guidance for when agents should avoid it |
| `output_notes` | string | no | Notes on output format and content |
| `output_shape` | dict | no | JSON schema describing the tool's structured output shape |
| `read_only` | boolean | no | Tool is read-only (default: `true`) |
| `readOnlyHint` | boolean | no | Hint for SDK compatibility (default: matches `read_only`) |
| `evidence_class` | string | no | Evidence classification for the tool output |
| `category` | string | no | Functional category |
| `recommended_phase` | enum | no | Investigation phase: `SURVEY`, `INGEST`, `ANALYZE`, `CORRELATE`, `REPORT` |
| `safe_case_argument_names` | list[string] | no | Arguments safe to resolve to case paths. E.g. `["case_id", "case_dir"]`. |
| `case_bound_argument_names` | list[string] | no | Arguments bound to a specific case context. E.g. `["index"]`. |
| `required_scopes` | list[string] | no | Scopes required to invoke this tool |
| `scope_enforcement` | string | no | How scopes are enforced |
| `enrichment_policy` | string | no | Enrichment behavior for this tool |
| `receipt_policy` | string | no | Receipt/provenance behavior |
| `prohibited_operations` | list[string] | no | Per-tool prohibited operations |
| `secret_leak_guarantee` | string | no | Guarantee that tool output contains no secrets |
| `defer_loading` | boolean | no | Defer loading this tool until first use (default: `false`) |
| `usage_examples` | array | no | Array of `{description, arguments}` usage examples |
| `response_shaping` | dict | no | Configuration for response shaping/truncation |

### health

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `health` | string | no | Name of a tool to use as a health probe |
| `health_args` | dict | no | Default arguments for the health probe call |

### Other fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resources[]` | array | no | Agent-facing resources this backend exposes |
| `prompts[]` | array | no | Agent-facing prompt templates this backend provides |

### Registration note

The manifest is stored in Postgres `app.mcp_backends` — **not** in
`gateway.yaml`. Backend registration is performed via the portal UI or the
`scripts/setup-addon.sh` script. The gateway reads the registry at startup and
re-reads it periodically for late-seeded backends (`_late_start_checker`). The
`backends: {}` key in `gateway.yaml` is intentionally ignored.

---

## D. Supabase Auth Configuration

The self-hosted Supabase `auth` (GoTrue) service must be configured with the
following settings. These are applied in the Supabase project's Docker Compose
`.env` file (typically `~/supabase-project/.env`) or Supabase dashboard.

### Required GoTrue environment variables

| Setting | Value | Source | Effect |
|---------|-------|--------|--------|
| `GOTRUE_JWT_EXP` | `172800` (48h) | `auth-jwt.env.template:22` | Agent access-token expiry in seconds. Must be ≥ `auth.supabase.min_agent_token_ttl_seconds` in gateway.yaml. |
| `JWT_EXPIRY` | `172800` (48h) | `auth-jwt.env.template:23` | Alternative name for the same setting. Both are listed because self-hosted compose files have historically used either; setting both is harmless. |
| `GOTRUE_SITE_URL` | `http://localhost:4508` | `config.toml` | Auth redirect URL — must point to the gateway's listen address. |
| `GOTRUE_DISABLE_SIGNUP` | `true` | `config.toml` | Disable public signup. Account creation is portal-only. |
| `GOTRUE_MAILER_AUTOCONFIRM` | `true` | `config.toml` | No email verification in lab deployments. |
| `GOTRUE_JWT_DEFAULT_GROUP_NAME` | `authenticated` | `config.toml` | Default Postgres role for authenticated users. |
| `GOTRUE_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED` | `true` | `config.toml` | Rotate refresh tokens on each use (mitigates refresh-token replay). |

**AUT2-B0 enforcement:** The gateway checks every agent principal issuance at
`supabase_auth.py:1482` — if the Supabase Auth session TTL is below
`auth.supabase.min_agent_token_ttl_seconds` (default 172800s / 48h), issuance
fails with `agent_token_ttl_below_minimum`. The error tells the operator to set
`GOTRUE_JWT_EXP` / `JWT_EXPIRY` on the Supabase Auth service and restart it.
A short TTL would cause agent sessions to expire mid-investigation.

After changing these values, restart the Supabase `auth` container:
```bash
cd ~/supabase-project
docker compose up -d auth
```
