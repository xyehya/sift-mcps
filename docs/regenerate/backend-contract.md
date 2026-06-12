# SIFT MCP Backend Contract

> **Audience:** add-on authors and operators integrating external MCP backends into
> the SIFT Protocol Gateway (SPG).
> **Status:** current as of OSX2 (commit aaa244b — advanced-tool-use per-tool fields).
> **Schema source:** `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
> (JSON Schema draft-07, validates every manifest before registration).

---

## 1. The Manifest (`sift-backend.json`)

Every add-on backend is described by a single JSON file named `sift-backend.json`
placed in its package root. The gateway and installer read this file — it is the
sole integration door. All fields below are grounded in the authoritative schema.

### 1.1 Top-level identity fields

| Field | Type | Required | Description |
|---|---|---|---|
| `spec_version` | string `"1.x"` | yes | Contract version; must match `^1\.[0-9]+$`. Current value: `"1.0"`. |
| `name` | string | yes | Unique backend identifier (e.g. `"opensearch-mcp"`, `"forensic-rag-mcp"`). |
| `version` | string | yes | Backend software version (semver). |
| `tier` | enum `"addon"` | yes | Only `"addon"` is valid; core tools live in the gateway itself. |
| `transport` | enum `"stdio"` or `"http"` | yes | How the gateway spawns or connects to the backend process. |
| `namespace` | string | yes | Tool name prefix applied by the gateway (e.g. `"opensearch"` → tools `opensearch_*`). Must not be empty. |
| `health` | string | yes | Tool name the gateway calls to probe backend readiness (e.g. `"opensearch_status"`). |
| `instructions` | string | no | System-prompt fragment injected by the gateway when this backend is active. Use `instructions_path` to load from a file instead. |
| `default_case_scoped` | boolean | no | When `true`, the gateway injects the active `case_id` into case-aware tools automatically. |
| `data_plane` | object | no | Declares runtime dependencies, whether the backend writes, and notes. Fields: `dependencies` (array of strings), `writes` (boolean), `notes` (string). Example from `opensearch-mcp/sift-backend.json`: dependencies include `"opensearch"` and `"postgres-opensearch-provenance"`. |

### 1.2 `capabilities` object

Declares what the backend provides and requires. **All three keys are required.**

```json
"capabilities": {
  "provides": ["search", "ingest", "enrichment"],
  "requires": ["http://localhost:9200"],
  "enriches_responses": false
}
```

| Key | Type | Description |
|---|---|---|
| `provides` | array of enum | Capability labels: `"reference"`, `"search"`, `"ingest"`, `"enrichment"`, `"baseline"`, `"threat-intel"`. Controls gateway routing decisions (e.g. reference-backend injection). |
| `requires` | array of strings | Requirement strings the gateway evaluates before mounting the backend. An unmet requirement silently gates the backend from `tools/list`; the core gateway stays up. Supported formats (from `server.py Gateway.evaluate_requirement`): `"http://host:port"` / `"host:port"` (TCP reachability), `"env:VAR_NAME"` (env var present, path value must exist), `"docker"` (binary on PATH), `"ram:16gb"` (system RAM). Unknown format = fail-closed (treated unmet). |
| `enriches_responses` | boolean | Whether the backend's output can be injected into core tool responses. |

**Example — forensic-rag-mcp** (`packages/forensic-rag-mcp/sift-backend.json`):
`"requires": []` — no runtime prerequisite; always mountable if enabled.

**Example — opensearch-mcp** (`packages/opensearch-mcp/sift-backend.json`):
`"requires": ["http://localhost:9200"]` — the gateway probes TCP reachability before
mounting; the backend is silently absent if OpenSearch is down.

### 1.3 Per-tool metadata (`tools` array)

Every tool in the array is validated against the schema. Required fields: `name`,
`description`, `read_only`, `readOnlyHint`, `evidence_class`, `category`,
`recommended_phase`.

#### Core classification fields

| Field | Values | Description |
|---|---|---|
| `read_only` / `readOnlyHint` | boolean | Both must be set consistently. |
| `evidence_class` | `"read_only"`, `"analysis"`, `"mutating"` | Gateway evidence-classification hint. |
| `category` | `"evidence-survey"`, `"ingest"`, `"search-analysis"`, `"enrichment"`, `"baseline-check"`, `"threat-intel"`, `"admin"` | Tool category surfaced in `tools/list`. |
| `recommended_phase` | `"SURVEY"`, `"INGEST"`, `"ANALYZE"`, `"CORRELATE"`, `"FINDING"` | Investigation phase hint for the agent. |
| `health` | boolean | Mark `true` on the tool used as backend health probe (matches top-level `health`). |
| `case_scoped` | boolean | Per-tool override of `default_case_scoped`. |
| `hidden_from_agent` | boolean | Exclude from agent-facing `tools/list`. |
| `safe_case_argument_names` | array (`"case_id"`, `"case_key"`) | Argument names the gateway may safely inject the DB active `case_id` into. Empty list = tool is case-scoped but resolves it internally. Absent = gateway falls back to schema detection, denies fail-closed if ambiguous. (Added OS2.) |

#### Advanced-tool-use fields (OSX2, commit aaa244b)

These are **metadata only** — they do not change dispatch or tool behaviour. They
appear in `tools/list` responses so the agent can make informed calling decisions.

| Field | Type | Description |
|---|---|---|
| `when_to_use` | string | Guidance on appropriate usage context. |
| `avoid_when` | string | Conditions under which the tool should be skipped. |
| `output_notes` | string | Plain-language description of what the tool returns. |
| `output_shape` | string | Structured output schema description (field names and types). |
| `response_shaping` | string | Tips for efficient calling (pagination, compact mode, etc.). |
| `usage_examples` | array of `{description, arguments}` | Realistic call examples: minimal / partial / full. The schema requires `arguments`; `description` is optional. Used for agent grounding. |
| `defer_loading` | boolean | Hint: this tool is low-frequency enough to be excluded from the default tool budget and loaded on demand via Tool-Search. |
| `defer_loading_rationale` | string | Human-readable justification for the `defer_loading` value. |

**Example from opensearch-mcp — `opensearch_search`:**
```json
"when_to_use": "Use for targeted searches across already indexed case evidence...",
"output_shape": "SearchOut: total, total_capped, returned, offset, compact, results[], advisories[].",
"usage_examples": [
  {"description": "Minimal: find a process by name", "arguments": {"query": "process.name:*powershell*"}},
  {"description": "Full document view, second page", "arguments": {"query": "source.ip:\"::1\"", "compact": false}}
]
```

#### Authority / scope enforcement fields (OS5)

Apply to mutating or enrichment tools.

| Field | Type | Description |
|---|---|---|
| `required_scopes` | array of strings | Agent JWT scopes required to call this tool. |
| `scope_enforcement` | string | How scopes are enforced (e.g. `"gateway_primary_env_fallback"`). |
| `prohibited_operations` | array of strings | Operations this tool must never perform (e.g. `"approve_findings"`, `"alter_evidence"`, `"decide_reports"`). |
| `secret_leak_guarantee` | string | Statement that no credentials, DSNs, or tokens appear in responses. |
| `enrichment_policy` | object | For async enrichment tools: `derived_state_only`, `audit_required`, `status_pollable`, `poll_via`, `poll_discriminator`. |
| `receipt_policy` | object | DB-active host-correction receipt contract: `db_active_mode`, `receipt_fields`, `fail_closed`, `no_path_leak`. |

### 1.4 `authority_contract` object

Declares the add-on as a non-authoritative plane. Advisory metadata — the gateway
remains the enforcement boundary.

```json
"authority_contract": {
  "non_authoritative": true,
  "plane": "reference",
  "query_only": true,
  "authority_disclaimer": "...",
  "prohibited_operations": ["create_case", "seal_evidence", "approve_finding", ...]
}
```

From `forensic-rag-mcp/sift-backend.json`: the KB backend declares `"plane": "reference"`,
`"query_only": true`, and lists ten prohibited operations including `"bypass_gateway"`.

---

## 2. Lifecycle: Seed → Mount → Hot-Reload

### 2.1 Install-time seeding (`install.sh seed_addon_backends`)

Source: `install.sh` lines 614–731 (`_seed_one_addon_backend`, `seed_addon_backends`).

```
install.sh main()
  └─ seed_addon_backends()          # gated on SIFT_CONTROL_PLANE_DSN present
       ├─ if SIFT_OPENSEARCH_ENABLED=true
       │    └─ _seed_one_addon_backend("opensearch-mcp", ...,
       │         env_refs='{"OPENSEARCH_CONFIG":"OPENSEARCH_CONFIG","OPENSEARCH_HOST":"OPENSEARCH_HOST"}')
       └─ if SIFT_RAG_ENABLED=true (default true)
            └─ _seed_one_addon_backend("forensic-rag-mcp", ...,
                 env_refs='{"SIFT_CONTROL_PLANE_DSN":"SIFT_CONTROL_PLANE_DSN","RAG_MODEL_NAME":"RAG_MODEL_NAME"}')
```

Key invariant (from the code comment at line 617–618):
> Raw OpenSearch credentials, DSNs, and MCP tokens are **NEVER** stored — only
> `env_ref` metadata (names of gateway process env vars). The gateway resolves
> actual values from its own process environment at load time.

`_seed_one_addon_backend` (line 625) reads the manifest file, builds a `connection`
object with `type: "stdio"`, `command: uv`, `args`, `manifest_path`, and
`env_refs`, then calls `McpBackendRegistry.register()` which performs an idempotent
`INSERT ... ON CONFLICT (name) DO UPDATE` into `app.mcp_backends`.

The row stored in `app.mcp_backends` carries: `name`, `namespace`, `transport`,
`tier`, `enabled`, `connection` (JSONB — env_refs only, no raw secrets), `data_plane`,
`default_case_scoped`, `manifest` (full JSONB), `manifest_source`, `manifest_sha256`,
`health_status`, `registered_by`, `updated_at`.

### 2.2 Post-install operator path (`scripts/setup-addon.sh`)

For backends NOT bundled with the installer, `scripts/setup-addon.sh` (lines 1–50)
is a helper that provisions prerequisites, prompts for config, and writes a
ready-to-submit register payload to `~/.sift/addon-register/<name>.json`. The
operator then submits via Portal → Backends. This is the same `register` door a
third-party backend uses — `setup-addon.sh` never edits `gateway.yaml` and never
seeds the DB directly.

### 2.3 Gateway mount (`create_backend_instances` → `mount_single_addon_proxy`)

Source: `packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py` line 285;
`mcp_server.py` line 466; `server.py` line 187.

On `Gateway.__init__` (when a control-plane DSN is present):

```
McpBackendRegistry.create_backend_instances()
  ├─ list_backends() → reads app.mcp_backends, filters enabled=true
  ├─ for each record: resolve_runtime_config(record.connection)
  │     (injects gateway env values for env_refs)
  └─ create_backend(name, config, manifest=record.manifest) → MCPBackend object

_mount_addon_proxies(mcp, gateway)
  └─ for each backend: mount_single_addon_proxy(mcp, gateway, name, backend)
       ├─ check _mounted_proxy_backends set (idempotent)
       ├─ evaluate capabilities.requires[] via gateway.evaluate_requirement()
       │    unmet → backend silently skipped (not in tools/list; core stays up)
       ├─ _create_backend_proxy(name, config, manifest)
       └─ mcp.mount(proxy, namespace=manifest["namespace"],
                    tool_names=_tool_rename_map(manifest))
```

The `namespace` field is applied as a mount-time prefix so all tool names in
`tools/list` become `<namespace>_<tool_name>` (e.g. `opensearch_search`).

### 2.4 Late-seeded backends — no restart required (OSX1 race fix)

Source: `server.py` lines 611–695 (`reload_backend_registry`, `_late_start_checker`).

The OSX1 release fixed the case where `seed_addon_backends` ran after the gateway
was already serving traffic — the new backend row was invisible until restart.

The gateway spawns `_late_start_checker()` as a background asyncio task on startup
(`server.py` line 1204). Every 30 seconds it calls `reload_backend_registry()`:

```
reload_backend_registry()
  ├─ McpBackendRegistry.create_backend_instances()   # re-reads app.mcp_backends
  ├─ diff: new_names = names in result NOT already in self.backends
  └─ for each new name:
       ├─ self.backends[name] = backend
       └─ mount_single_addon_proxy(mcp, gateway, name, backend)
            (idempotent — _mounted_proxy_backends prevents double-mount)
  └─ _build_tool_map()   # rebuilds the unified tool map
```

Result: a backend seeded after the gateway starts appears in `tools/list` within
30 seconds with no restart.

---

## 3. Worked Example: Adding a New Query-Only Add-on

This example traces a hypothetical `cti-lookup-mcp` through the full lifecycle,
using `forensic-rag-mcp` (pure reference, no requirements) and `opensearch-mcp`
(requires + advanced-tool-use) as exemplars.

### Step 1 — Author the manifest

```json
{
  "spec_version": "1.0",
  "name": "cti-lookup-mcp",
  "version": "1.0.0",
  "tier": "addon",
  "transport": "stdio",
  "namespace": "cti",
  "health": "cti_health",
  "instructions": "Query-only CTI enrichment. Outputs are supporting context; not case authority.",
  "authority_contract": {
    "non_authoritative": true,
    "plane": "reference",
    "query_only": true,
    "authority_disclaimer": "No authority over cases, evidence, findings, or reports.",
    "prohibited_operations": ["seal_evidence", "approve_finding", "approve_report"]
  },
  "capabilities": {
    "provides": ["threat-intel"],
    "requires": ["http://localhost:8080"],
    "enriches_responses": false
  },
  "tools": [
    {
      "name": "cti_lookup_ip",
      "description": "Look up threat intel for an IP address.",
      "when_to_use": "Use to check whether a pivot IP has known malicious reputation.",
      "avoid_when": "Avoid treating a hit as attribution; it is corroborating context only.",
      "output_notes": "Returns enrichment context; not case evidence.",
      "output_shape": "LookupOut: ip, verdict, confidence, sources[].",
      "usage_examples": [
        {"description": "Single IP lookup", "arguments": {"ip": "198.51.100.42"}}
      ],
      "defer_loading": false,
      "read_only": true,
      "readOnlyHint": true,
      "evidence_class": "read_only",
      "category": "threat-intel",
      "recommended_phase": "CORRELATE"
    },
    {
      "name": "cti_health",
      "description": "Check CTI backend connectivity.",
      "read_only": true,
      "readOnlyHint": true,
      "evidence_class": "read_only",
      "category": "admin",
      "recommended_phase": "SURVEY",
      "health": true,
      "usage_examples": [{"arguments": {}}]
    }
  ]
}
```

Modelled on `forensic-rag-mcp/sift-backend.json` for the authority contract and
`opensearch-mcp/sift-backend.json` for the advanced-tool-use fields.

### Step 2 — Seed or register

**Installer path** (bundled backend): add a block in `install.sh seed_addon_backends`:

```bash
if [[ "${SIFT_CTI_ENABLED:-}" == "true" ]]; then
  _seed_one_addon_backend \
    "cti-lookup-mcp" \
    "$REPO_DIR/packages/cti-lookup-mcp/sift-backend.json" \
    "cti-lookup-mcp" \
    '{"CTI_API_KEY": "CTI_API_KEY"}'
fi
```

The `env_refs` object maps gateway process env var names to child process env var
names. The raw `CTI_API_KEY` value is **never** stored in `app.mcp_backends` — only
the name `"CTI_API_KEY"` is. The gateway resolves the actual value at mount time.

**Operator path** (external / post-install): run `scripts/setup-addon.sh`, which
writes `~/.sift/addon-register/cti-lookup-mcp.json`, then submit via
Portal → Backends → Register. The portal validates the manifest against
`sift-backend.schema.json` before calling `McpBackendRegistry.register()`.

Either path performs an idempotent upsert into `app.mcp_backends` (ON CONFLICT on
`name`), so re-running is safe.

### Step 3 — Gateway mount

On next startup (or within 30 s via `_late_start_checker` → `reload_backend_registry`
if already running):

1. `McpBackendRegistry.create_backend_instances()` reads `app.mcp_backends`,
   resolves env_refs from the gateway process env, and builds an `MCPBackend` for
   `cti-lookup-mcp`.
2. `mount_single_addon_proxy` evaluates `capabilities.requires`:
   `["http://localhost:8080"]` → TCP probe on port 8080. If the CTI service is
   reachable, the proxy mounts with namespace `"cti"`.
   If unreachable, the backend is silently absent; core tools continue serving.
3. The gateway rebuilds its tool map. `cti_lookup_ip` and `cti_health` now appear
   in `tools/list` as `cti_lookup_ip` and `cti_health` (namespace applied at mount
   time by `_tool_rename_map`).

### Step 4 — Verify

```
# tools/list (agent call) should include:
cti_lookup_ip   category=threat-intel   recommended_phase=CORRELATE
cti_health      category=admin          health=true
```

The agent sees `when_to_use`, `avoid_when`, `output_shape`, and `usage_examples`
metadata from the manifest — no hardcoded add-on names in the gateway are required.

---

## Quick-reference: required fields checklist

For every new `sift-backend.json`:

- [ ] `spec_version`, `name`, `version`, `tier`, `transport`, `namespace`, `health`
- [ ] `capabilities.provides`, `capabilities.requires`, `capabilities.enriches_responses`
- [ ] At least one tool with: `name`, `description`, `read_only`, `readOnlyHint`,
      `evidence_class`, `category`, `recommended_phase`
- [ ] `authority_contract` with `non_authoritative`, `prohibited_operations` (for query-only backends)
- [ ] `when_to_use` / `avoid_when` / `usage_examples` on every tool (OSX2 best practice)
- [ ] `env_refs` uses variable **names**, never raw secrets
- [ ] Validate: schema at `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`
