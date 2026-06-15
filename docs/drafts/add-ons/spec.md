# SIFT MCP Backend Contract — Normative Specification

**Audience:** external MCP backend authors and operators integrating add-on
backends into the SIFT Protocol Gateway (SPG).

**Status:** grounded against code at commit d47f7ed (2026-06-12).

**Authoritative sources (read before writing a manifest):**
- Schema: `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
  (JSON Schema draft-07)
- Cross-field contract rules: `packages/sift-gateway/src/sift_gateway/backends/__init__.py`
  (`validate_manifest_contract`)
- Connection config rules: `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py`
  (`normalize_connection_config`, `resolve_runtime_config`)
- Gateway mounting and tool-map construction: `packages/sift-gateway/src/sift_gateway/server.py`
  (`Gateway._build_tool_map`, `Gateway.evaluate_requirement`)
- Policy and authority enforcement: `packages/sift-gateway/src/sift_gateway/policy_middleware.py`
  (`AddonAuthorityMiddleware`, `ToolAuthorizationMiddleware`)

---

## 1. The Core/Add-on Boundary

The SIFT Protocol Gateway distinguishes two kinds of backends:

**Core** backends are installed and seeded by the native installer (`install.sh`).
They form the complete forensic analysis stack on their own. Core today means:
`sift-gateway` (in-process), `sift-core` (in-process), the operator portal,
Supabase/Postgres, `opensearch-mcp`, `forensic-rag-mcp`, `forensic-knowledge`
(in-process library), Hayabusa (installed binary), the local worker, and
installer/system services.

**External add-ons** are installed and registered separately through this
contract. OpenCTI (`packages/opencti-mcp`) is the first shipped external add-on.
Windows-triage-style integrations are future external candidates. They must not
appear in the core install path.

Evidence from `install.sh`:
- Line 16: "OpenCTI is an external add-on; prepare/register it via
  `scripts/setup-addon.sh`."
- Lines 391-392: "External add-ons such as OpenCTI are never pulled by the
  native installer; `scripts/setup-addon.sh` requests their extras."
- Lines 2811-2834: The `--no-opencti` flag is documented as a no-op
  compatibility stub with the explicit note "OpenCTI native install disabled:
  external add-on only."
- `seed_addon_backends` (lines 998-1040) seeds only `opensearch-mcp` (when
  `SIFT_OPENSEARCH_ENABLED=true`) and `forensic-rag-mcp` (when
  `SIFT_RAG_ENABLED=true`). It never references `opencti-mcp` or any
  windows-triage package.

There is exactly one integration path for all external add-ons: the
`sift-backend.json` manifest validated through Portal -> Backends or the
REST registration API. The gateway is add-on-agnostic — it does not hardcode
any add-on name in its policy or routing code.

---

## 2. The Manifest (`sift-backend.json`)

Every add-on backend ships a single JSON file named `sift-backend.json`
placed in its package root (for example `packages/opencti-mcp/sift-backend.json`).
The gateway reads this file at registration time and stores it in
`app.mcp_backends`. It is the sole integration door.

### 2.1 Top-level required fields

The following fields are required by the JSON schema (field `required` array at
schema root: `spec_version`, `name`, `version`, `tier`, `transport`,
`namespace`, `capabilities`, `tools`, `health`).

| Field | Type | Description |
|---|---|---|
| `spec_version` | string `"1.x"` | Must match `^1\.[0-9]+$`. Current value: `"1.0"`. The gateway rejects manifests with a major version other than 1 (`backends/__init__.py` line 270). |
| `name` | string | Unique backend identifier (e.g. `"opencti-mcp"`). Used as the registry key in `app.mcp_backends`. |
| `version` | string | Backend software version (semver). |
| `tier` | enum | Only `"addon"` is accepted. Core tools live in-process in the gateway. |
| `transport` | enum | `"stdio"` or `"http"`. Determines how the gateway spawns or connects to the backend. |
| `namespace` | string | Tool name prefix the gateway enforces. All tools in `tools[]` must be named `<namespace>_<suffix>`. Must not be empty; empty namespace makes contract validation fail. Example: `"cti"` in `opencti-mcp/sift-backend.json`. |
| `capabilities` | object | See §2.2. **Required sub-fields:** `provides`, `requires`, `enriches_responses`. |
| `tools` | array | Minimum one entry. Each entry must meet the per-tool requirements in §2.3. |
| `health` | string | Name of the health-probe tool. Must match exactly one tool in `tools[]` that also has `"health": true` at the tool level. Exactly one tool in the array may set `health: true`. |

### 2.2 Top-level optional fields

| Field | Type | Description |
|---|---|---|
| `instructions` | string | System-prompt fragment the gateway injects when this backend is active. Mutually exclusive with `instructions_path`. |
| `instructions_path` | string | Relative path (from the manifest file) to a text file containing the instructions. Must stay inside the package root. |
| `default_case_scoped` | boolean | When `true`, the gateway treats all tools as needing an active case unless a tool explicitly overrides with `"case_scoped": false`. |
| `data_plane` | object | Declares runtime dependencies (`dependencies` array), whether the backend writes (`writes` boolean), and documentation notes (`notes` string). Gateway stores and surfaces this field in the public registry dict; see `mcp_backends_registry.py BackendRegistryRecord.public_dict`. |
| `authority_contract` | object | Declares the add-on as non-authoritative. See §2.5. |

### 2.3 `capabilities` object

All three sub-fields are required by the JSON schema (`"required": ["provides",
"requires", "enriches_responses"]`, `additionalProperties: false`).

| Key | Type | Values / Description |
|---|---|---|
| `provides` | array of enum | One or more of: `"reference"`, `"search"`, `"ingest"`, `"enrichment"`, `"baseline"`, `"threat-intel"`. The gateway uses `provides` to discover reference backends (`server.py Gateway.get_reference_backends`) and to build the platform capabilities summary (`get_available_backend_capabilities`). `"reference"` backends may have their outputs injected into core tool context. |
| `requires` | array of strings | Runtime requirements the gateway evaluates before mounting the backend. An unmet requirement silently gates the backend from `tools/list`; the core stays up. See §3 for the supported requirement formats and evaluation logic. |
| `enriches_responses` | boolean | Whether the backend output may be injected into core tool responses. Currently advisory metadata. |

### 2.4 Per-tool metadata (`tools[]`)

Required fields for every tool entry (from the JSON schema `items.required`
array: `name`, `description`, `read_only`, `readOnlyHint`, `evidence_class`,
`category`, `recommended_phase`). `additionalProperties: false` — unknown keys
are rejected by schema validation.

**Required fields:**

| Field | Type | Constraint |
|---|---|---|
| `name` | string | Must start with `<namespace>_`. Validated by `validate_manifest_contract` and again by `Gateway._build_tool_map`. |
| `description` | string | Shown to the agent in `tools/list`. |
| `read_only` | boolean | Must equal `readOnlyHint`. An inconsistency raises a `ValueError` in `validate_manifest_contract`. |
| `readOnlyHint` | boolean | Must equal `read_only`. |
| `evidence_class` | enum | `"read_only"`, `"analysis"`, or `"mutating"`. `read_only` requires `read_only: true`; `mutating` requires `read_only: false`. The gateway uses this to decide whether a pre-dispatch audit failure should fail closed (mutating tools) or proceed (read-only tools). |
| `category` | enum | One of: `"evidence-survey"`, `"ingest"`, `"search-analysis"`, `"enrichment"`, `"baseline-check"`, `"threat-intel"`, `"admin"`. |
| `recommended_phase` | enum | One of: `"SURVEY"`, `"INGEST"`, `"ANALYZE"`, `"CORRELATE"`, `"FINDING"`. |

**Optional fields (advisory / UX metadata):**

| Field | Type | Description |
|---|---|---|
| `health` | boolean | Marks the single health-probe tool (`true` on exactly one tool). |
| `health_args` | object | Fixed arguments the gateway passes when calling the health probe. |
| `case_scoped` | boolean | Whether this specific tool requires an active case. Overrides `default_case_scoped` at the tool level. |
| `hidden_from_agent` | boolean | When `true`, the tool is filtered out of `tools/list` returned to agents (but remains callable). |
| `when_to_use` | string | Agent guidance: when this tool is the right choice. |
| `avoid_when` | string | Agent guidance: when NOT to call this tool. |
| `output_notes` | string | Agent guidance: what the output contains and how to interpret it. |
| `output_shape` | string | Human-readable description of the response shape. |
| `response_shaping` | string | How the gateway shapes or truncates the response. |
| `defer_loading` | boolean | Whether to defer this tool from the initial `tools/list` (lazy capability). |
| `defer_loading_rationale` | string | Why the tool is deferred. |
| `usage_examples` | array | Realistic example calls for agent guidance. Each entry: `{ "description": "...", "arguments": {...} }`. Metadata only; does not change dispatch. |
| `required_scopes` | array of strings | Token scopes the caller must hold for this tool. Enforced by `AddonAuthorityMiddleware` before dispatch. |
| `safe_case_argument_names` | array | Argument names the gateway may inject the DB active `case_id` into: subset of `["case_id", "case_key"]`. Empty list = case-scoped but no injection argument needed. Absent = unknown; gateway falls back to schema property detection and denies fail-closed if nothing is found. |
| `scope_enforcement` | string | How `required_scopes` are enforced for a mutating tool. |
| `enrichment_policy` | object | For enrichment tools: declares audited, scope-gated, pollable derived-state mutation. |
| `prohibited_operations` | array | Operations this specific tool must never perform. See §2.5 for the backend-level field. |
| `secret_leak_guarantee` | string | Statement that the agent-facing response carries no credentials, DSNs, or paths. |
| `receipt_policy` | object | DB-active host-correction receipt contract for mutating tools. |

### 2.5 `authority_contract` object

The `authority_contract` is optional but **required for any add-on that is
query-only or non-authoritative** (which is all current add-ons). The schema
allows: `non_authoritative`, `plane`, `query_only`, `authority_disclaimer`,
`prohibited_operations`. `additionalProperties: false`.

The contract is **advisory metadata** — the gateway is the enforcement boundary.
`AddonAuthorityMiddleware` reads the indexed contract from `_tool_manifest_meta`
and enforces it before backend dispatch.

| Field | Type | Description |
|---|---|---|
| `non_authoritative` | boolean | Declares this add-on is a reference/derived plane only. |
| `plane` | string | Label for the plane type (e.g. `"reference"`). |
| `query_only` | boolean | Declares that all tools are read-only queries. Tightens prohibited-operation matching. |
| `authority_disclaimer` | string | Human-readable statement shown in the portal and capability guide. Should be at least 20 characters (enforced by `test_opencti_contract.py`). |
| `prohibited_operations` | array of strings | Operations the add-on must never perform. The gateway checks whether the tool name or an `operation`/`action`/`op`/`command`/`mode` argument value matches any entry; a match denies the call with `addon_prohibited_operation`. |

Standard prohibited operations for a non-authoritative add-on (from
`packages/opencti-mcp/sift-backend.json`): `create_case`, `activate_case`,
`seal_evidence`, `register_evidence`, `approve_finding`, `reject_finding`,
`approve_report`, `include_in_report`, `issue_agent_credential`,
`bypass_gateway`.

---

## 3. Requirement Evaluation (`capabilities.requires`)

The gateway evaluates every entry in `requires[]` before mounting a backend.
Implemented in `server.py Gateway.evaluate_requirement`. An unmet requirement
gates the backend (it is excluded from `tools/list`); the core gateway stays up.

| Format | Evaluates |
|---|---|
| `"docker"` | `shutil.which("docker") is not None` |
| `"ram:Ngb"` or `"ram:Nmb"` | Total system RAM (`os.sysconf`) >= N |
| `"env:VAR_NAME"` | `VAR_NAME` is set in the gateway's environment; if the value starts with `/`, `./`, or `../`, the path must also exist |
| `"http://host:port"` or `"https://host:port"` | TCP reachability to the resolved host/port with a 2-second timeout |
| `"host:port"` | Same TCP check |
| Any other string | Treated as **unmet** (fail-closed); a warning is logged. This prevents silent pass of a typo'd requirement. |

A backend with `"requires": []` (no requirements) is always mounted if enabled.
Example: `packages/forensic-rag-mcp/sift-backend.json` has `"requires": []`.

---

## 4. Transport and Connection Configuration

### 4.1 stdio transport

The gateway spawns the backend as a subprocess. Required connection field:
`command` (string path or executable on PATH).

Connection config accepted fields (from `normalize_connection_config` in
`mcp_backends_registry.py`, `_CONNECTION_KEYS` set): `type`, `manifest_path`,
`command`, `args`, `cwd`, `url`, `enabled`, `bearer_token_env`,
`tls_cert_env`, `env_refs`.

Raw secrets (`bearer_token`, `tls_cert`, `env`, `headers`, `password`,
`secret`, `api_key`, `token`, `raw_token`, `plaintext_token`) are **rejected**
at registration. Secrets must be referenced only by environment variable name.

The gateway passes a minimal process environment to stdio subprocesses
(`mcp_server.py _stdio_base_env`): `PATH`, `HOME`, `USER`, `LOGNAME`,
`SHELL`, `LANG`, `TMPDIR`, `TEMP`, `TMP`, and any `LC_*` vars. Additional
environment is supplied only via `env_refs`.

### 4.2 http transport

The gateway connects to an already-running HTTP server. Required connection
field: `url` (https URL). The URL must resolve to a public address — the
gateway rejects private, loopback, link-local, multicast, reserved, and
unspecified addresses (`mcp_server.py _validate_egress_url`).

Optional: `bearer_token_env` (gateway env var name whose value is used as the
`Authorization: Bearer <token>` header) and `tls_cert_env` (gateway env var
name whose value is a path to a CA cert file).

### 4.3 `env_refs` — secret indirection for stdio backends

`env_refs` is a JSON object mapping backend child process environment variable
names to gateway process environment variable names:

```json
"env_refs": {
  "OPENCTI_TOKEN": "SIFT_OPENCTI_TOKEN",
  "OPENCTI_URL":   "SIFT_OPENCTI_URL"
}
```

The gateway resolves the values from its own environment at backend startup
(`resolve_runtime_config`). If a referenced gateway environment variable is
absent or empty, startup fails with `BackendRegistryError`. No secret values
are stored in `app.mcp_backends`.

---

## 5. Namespace Enforcement

The gateway enforces namespace consistency in two places:

1. **`validate_manifest_contract`** (static): every tool name in `tools[]`
   must start with `<namespace>_`. Duplicate tool declarations within a single
   manifest are rejected.

2. **`Gateway._build_tool_map`** (runtime): when a started backend's live
   `tools/list` response includes a tool name that either does not start with
   the declared namespace prefix or is not declared in `tools[]`, a
   `ValueError` is raised and startup halts.

Tool names must also not collide with core in-process tool names; the gateway
raises `ValueError` on any collision. Tool names must be globally unique across
all registered add-on backends; a duplicate across two backends raises
`ValueError` with the tool name and both backend names.

---

## 6. Policy and Authority Enforcement

The gateway applies a fixed middleware stack to every MCP tool call
(`policy_middleware.py gateway_policy_middlewares`). The order is:

1. `GatewayToolCatalogMiddleware` — filters `hidden_from_agent` tools from
   `tools/list` and enriches tool metadata.
2. `ToolAuthorizationMiddleware` — enforces per-principal tool scopes (token
   `tool_scopes`). Denied calls are audited and return a structured error
   without invoking the tool. In auth-configured mode, a missing identity
   fails closed (no tools listed, all calls denied).
3. `AddonAuthorityMiddleware` — enforces add-on manifest-declared
   `required_scopes` and `prohibited_operations` BEFORE backend dispatch.
   See §6.1 and §6.2.
4. `CaseContextMiddleware` — resolves the DB active case for the principal.
5. `AuditEnvelopeMiddleware` — writes pre-dispatch and result audit rows to
   `app.audit_events`. For mutating tools, a pre-dispatch audit write failure
   causes the call to fail closed (backend not invoked).
6. `ProxyActiveCaseMiddleware` — injects the DB active `case_id` into
   `safe_case_argument_names` for proxied tools; denies fail-closed when the
   tool's case-argument contract is unknown.
7. `EvidenceGateMiddleware` — blocks all tool calls when the active evidence
   chain is not OK.
8. `ResponseGuardMiddleware` — redacts sensitive patterns and caps output size.

### 6.1 Scope enforcement

`AddonAuthorityMiddleware` collects `required_scopes` from the tool's manifest
entry (indexed in `_tool_manifest_meta`). Every scope in the list must be
satisfied by the caller's token scopes (`is_scope_satisfied`). Missing scopes
produce a denial with `reason: "addon_scope_missing"` and a
`missing_scopes` field listing each absent scope.

Scope strings are arbitrary labels matching what the operator configured when
issuing the agent/service credential (e.g. `"cti:read"` for OpenCTI tools).

### 6.2 Prohibited-operation enforcement

`AddonAuthorityMiddleware._attempted_prohibited_operations` checks:
- Whether the tool name itself is in the `prohibited_operations` set.
- Whether any argument whose key is `"operation"`, `"action"`, `"op"`,
  `"command"`, or `"mode"` has a value that appears in the prohibited set.

A match produces a denial with `reason: "addon_prohibited_operation"`,
`non_authoritative` flag, and the list of matched prohibited operations. The
backend is never invoked.

---

## 7. Registration and Hot Reload

### 7.1 DB registry (`app.mcp_backends`)

The gateway's authoritative add-on registry is the `app.mcp_backends`
Postgres table (`mcp_backends_registry.py McpBackendRegistry`). Every
enabled row is instantiated as a backend at gateway startup and re-read
periodically. There is no authoritative `gateway.yaml` backend block; a
stale YAML block is silently ignored when a control-plane DSN is configured.

### 7.2 Registration flow

Registration is an upsert: re-registering the same `name` updates the row.
The manifest SHA-256 digest (`manifest_sha256` function) is stored with the
row; a changed manifest produces a new digest. Registration is audited to
`app.audit_events` with event type `mcp_backend.registered`.

The REST path (`POST /api/v1/backends`) calls
`load_and_validate_manifest` before inserting. Validation steps:
1. Load `sift-backend.json` from `manifest_path` (local file) or the HTTP
   backend's `/manifest` endpoint.
2. Check `spec_version` starts with `"1."`.
3. Validate against the JSON schema.
4. Run `validate_manifest_contract` for cross-field invariants.

A manifest that fails any step is rejected with a `ValueError`. There is no
"soft" validation that produces warnings but accepts the manifest.

### 7.3 Hot reload (OSX1)

The gateway discovers backends seeded after startup without a full restart:

- `Gateway._late_start_checker` polls `app.mcp_backends` every 30 seconds
  (`reload_backend_registry`).
- When a new enabled row appears, `mount_single_addon_proxy` mounts a new
  FastMCP proxy onto the live aggregate server.
- The tool map is rebuilt atomically (`_build_tool_map`).
- New tools appear in the aggregate `tools/list` without a gateway restart.
- Hot reload is additive only — a running backend is never dropped by a reload.

### 7.4 Enable/disable

A backend can be disabled via `McpBackendRegistry.set_enabled(name, False)`.
Disabling sets `health_status = "disabled"` and is audited. Disabled backends
are excluded from `enabled_backends()` and from `tools/list`.

---

## 8. Health Semantics

Every manifest must declare exactly one health-probe tool (top-level `health`
field naming the tool, with `"health": true` on the tool entry).

The gateway calls the health-probe tool with the `health_args` (or no
arguments if absent) to determine backend health status. Health status values:
`"unknown"` (not yet checked), `"ok"` (probe succeeded), `"error"` (probe
failed), `"disabled"` (backend disabled).

Health results are written to `app.mcp_backends.health_status` and
`health_checked_at` via `McpBackendRegistry.update_health`. The portal surfaces
backend health status to operators.

A backend whose `requires[]` entry is unmet is never started and is not
health-checked; it is silently absent from `tools/list`.

---

## 9. Manifest Validation — Current Test Coverage

The following tests exercise manifest validation. An author can run them with:
```bash
uv run --extra dev pytest packages/sift-gateway/tests/test_phase6.py \
    packages/opencti-mcp/tests/test_opencti_contract.py \
    packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py \
    packages/sift-gateway/tests/test_d22a_mcp_backends_registry.py -v
```

| Test file | What is covered |
|---|---|
| `packages/sift-gateway/tests/test_phase6.py` | `load_and_validate_manifest` loads and validates a manifest; requirement gating gates a backend when `requires` is unmet; hidden tools are filtered from `tools/list`; namespace violations and tool-map collisions raise `ValueError`. |
| `packages/opencti-mcp/tests/test_opencti_contract.py` | OpenCTI `sift-backend.json` declares `non_authoritative`, `query_only`, prohibited operations; all tools are `read_only`; all tools have `required_scopes`; Python registry matches the manifest. |
| `packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py` | `normalize_connection_config` rejects raw secrets; `env_refs` round-trips; `manifest_sha256` stability; requirement gating in `Gateway._build_tool_map`. |
| `packages/sift-gateway/tests/test_d22a_mcp_backends_registry.py` | `normalize_connection_config` stores only credential references; `resolve_runtime_config` expands `env_refs` and `bearer_token_env`/`tls_cert_env` from the gateway environment; missing env var raises `BackendRegistryError`. |

**Coverage gaps for AD2 to address:**
- No test exercises `AddonAuthorityMiddleware` with a manifest that has
  `prohibited_operations` and verifies the denial response.
- No test exercises scope enforcement (`required_scopes` in `AddonAuthorityMiddleware`).
- No end-to-end registration smoke for `opencti-mcp` (install, register via
  REST API, verify tools appear in aggregate `tools/list`).
- No clean-uninstall/disable test (verify tools disappear after disable).
- No duplicate-tool-name test across two simultaneously registered backends.
- No hot-reload test that seeds a row after gateway startup and confirms the
  tool appears without restart.

---

## 10. Summary Checklist for Conformant Manifests

A manifest is accepted when:

- [ ] `spec_version` matches `^1\.[0-9]+$` (currently `"1.0"`)
- [ ] `tier` is `"addon"`
- [ ] `transport` is `"stdio"` or `"http"`
- [ ] `namespace` is non-empty
- [ ] `capabilities.provides`, `.requires`, `.enriches_responses` are all present
- [ ] `tools[]` has at least one entry
- [ ] Every tool name starts with `<namespace>_`
- [ ] No duplicate tool names within the manifest
- [ ] Every tool has `read_only == readOnlyHint` (both `true` or both `false`)
- [ ] `evidence_class` is consistent with `read_only` (see §2.4 table)
- [ ] `recommended_phase` is one of the five valid values
- [ ] Top-level `health` names exactly one tool that has `"health": true`
- [ ] If `instructions_path` is used, it is relative and inside the package root
- [ ] If the add-on is non-authoritative, `authority_contract` declares it
- [ ] No raw secrets appear in the connection config; secrets use `env_refs` or
  `bearer_token_env`/`tls_cert_env`
