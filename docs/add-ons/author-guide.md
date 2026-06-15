# SIFT MCP Backend — Add-on Author Guide

**Audience:** third-party or community developers writing a new MCP backend
that integrates with the SIFT Protocol Gateway (SPG).

**Goal:** walk from an empty repository to a registered, conformant add-on
without changing a single line of Gateway code.

**Read first:**
- `docs/add-ons/spec.md` — the normative contract that this guide implements.
- `packages/opencti-mcp/sift-backend.json` — the first shipped external add-on
  manifest; used as the reference example throughout.

---

## 1. What an Add-on Is (and Is Not)

The Gateway is complete on its own. It ships with in-process core tools
(`sift-core`, `sift-gateway`) and seeds `opensearch-mcp` and
`forensic-rag-mcp` during installation. An add-on is an **optional external
MCP server** that the operator chooses to attach. The Gateway discovers
add-ons from the `app.mcp_backends` Postgres table; it does not care what
language, framework, or process model the add-on uses, as long as the add-on
speaks the MCP wire protocol and ships a conformant `sift-backend.json`
manifest.

**The Gateway never changes to accommodate a new add-on.** If you need the
Gateway to change, stop and discuss the design first.

### The core/add-on boundary

Core backends (installed by `./install.sh`): `sift-gateway`, `sift-core`,
portal, Supabase/Postgres, OpenSearch, `forensic-rag-mcp`,
`forensic-knowledge`, Hayabusa, the local worker.

External add-ons (installed separately): OpenCTI (`packages/opencti-mcp`) is
the first shipped external add-on. It is never in the core install path (see
`docs/add-ons/spec.md §1` for the `install.sh` evidence).

Windows-triage-style integrations are future external candidates. They would
follow the same contract as OpenCTI; AD2 will prove the contract with OpenCTI
alone. The section below uses a **hypothetical** windows-triage-style add-on
as a tutorial example — it is illustrative only and is not a shipped package.

---

## 2. Prerequisites

Before you start, you need:

- A working SPG installation (`./install.sh` completed, `/health` returns
  `status=ok`).
- An operator portal account with permission to register backends (Portal ->
  Backends).
- A text editor or your preferred language/framework for writing an MCP server.
- (Optional) `scripts/setup-addon.sh` — the interactive helper that prepares
  prerequisites and writes a ready-to-submit registration payload.

---

## 3. Tutorial: Building a Query-only Add-on

This section walks through a **hypothetical** Windows-artifact-triage-style
read-only MCP backend. This example is **illustrative only** — no such package
exists in this repository. The same steps apply to any query-only add-on.

### 3.1 Decide what the add-on provides

Your add-on should have a clear capability label from the manifest schema:
`reference`, `search`, `ingest`, `enrichment`, `baseline`, or `threat-intel`.

Our hypothetical `wintriage-mcp` provides Windows event-log triage results: a
read-only search into a Windows-artifact analysis engine. It provides
`"reference"` (contextual artifact lookups) and `"search"` (event-log queries).
It has no authority and must not touch cases, evidence, or findings.

### 3.2 Choose a namespace

Pick a short, lowercase namespace that uniquely identifies your add-on. All
tool names must start with `<namespace>_`. The namespace becomes the DB
registry key separator — no two registered add-ons may share a namespace or
have overlapping tool names.

Our example uses namespace `"wt"` → all tools are `wt_*`.

### 3.3 Write your MCP server

Your server just needs to implement the MCP protocol. Any language works. A
Python/FastMCP example tool:

```python
from fastmcp import FastMCP

mcp = FastMCP("wintriage-mcp")

@mcp.tool(
    description="Check wintriage service connectivity.",
    annotations={"readOnlyHint": True},
)
def wt_get_health() -> dict:
    return {"status": "ok", "version": "1.0.0"}

@mcp.tool(
    description="Search Windows event logs for a keyword or event ID.",
    annotations={"readOnlyHint": True},
)
def wt_search_events(query: str, limit: int = 20) -> list:
    # ... query your artifact analysis engine ...
    return []
```

The tool names must match exactly what you declare in `sift-backend.json`.

### 3.4 Write `sift-backend.json`

Place this file in the root of your add-on package. Below is a complete,
valid manifest for our hypothetical add-on. Every claim is grounded in the
schema at `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`.

```json
{
  "spec_version": "1.0",
  "name": "wintriage-mcp",
  "version": "1.0.0",
  "tier": "addon",
  "transport": "stdio",
  "namespace": "wt",
  "instructions": "Use this backend to search Windows artifact analysis results. Treat outputs as supporting context; correlate with case evidence before drawing conclusions.",
  "authority_contract": {
    "non_authoritative": true,
    "plane": "reference",
    "query_only": true,
    "authority_disclaimer": "This add-on is a read-only reference plane. It does not authorize cases, seal evidence, approve findings, or bypass the Gateway. All outputs are supporting context only.",
    "prohibited_operations": [
      "create_case",
      "activate_case",
      "seal_evidence",
      "register_evidence",
      "approve_finding",
      "reject_finding",
      "approve_report",
      "include_in_report",
      "issue_agent_credential",
      "bypass_gateway"
    ]
  },
  "capabilities": {
    "provides": ["reference", "search"],
    "requires": ["env:WINTRIAGE_URL"],
    "enriches_responses": false
  },
  "tools": [
    {
      "name": "wt_get_health",
      "description": "Check wintriage service connectivity and readiness.",
      "when_to_use": "Use to confirm the wintriage API is reachable before relying on search results.",
      "output_notes": "Health/status output only; not case evidence.",
      "read_only": true,
      "readOnlyHint": true,
      "evidence_class": "read_only",
      "required_scopes": ["wt:read"],
      "category": "evidence-survey",
      "recommended_phase": "SURVEY",
      "health": true
    },
    {
      "name": "wt_search_events",
      "description": "Search Windows event logs for a keyword or event ID.",
      "when_to_use": "Use after extracting an event ID or keyword from case evidence.",
      "avoid_when": "Avoid broad queries that produce hundreds of results without a case-specific hypothesis.",
      "output_notes": "Returns matching event log entries; correlate with observed case artifacts.",
      "read_only": true,
      "readOnlyHint": true,
      "evidence_class": "read_only",
      "required_scopes": ["wt:read"],
      "category": "search-analysis",
      "recommended_phase": "ANALYZE"
    },
    {
      "name": "wt_get_process_tree",
      "description": "Retrieve the process tree for a given PID from artifact analysis.",
      "when_to_use": "Use after finding a suspicious PID in case evidence to understand the process context.",
      "avoid_when": "Avoid without a specific PID from case artifacts.",
      "read_only": true,
      "readOnlyHint": true,
      "evidence_class": "read_only",
      "required_scopes": ["wt:read"],
      "category": "search-analysis",
      "recommended_phase": "ANALYZE"
    }
  ],
  "health": "wt_get_health"
}
```

**Key decisions made in this manifest:**

- `authority_contract.non_authoritative: true` and `query_only: true` because
  this add-on is a read-only reference plane. The `authority_disclaimer` must
  be at least 20 characters (enforced by `test_opencti_contract.py`).
- `prohibited_operations` lists every authority operation the add-on must never
  perform. The Gateway enforces this list before dispatch.
- `requires: ["env:WINTRIAGE_URL"]` means the backend is gated if
  `WINTRIAGE_URL` is not in the gateway's process environment. If the
  environment variable is set but its value begins with `/`, the path must
  also exist. An unmet requirement silently excludes the backend from
  `tools/list`; the core gateway stays up.
- `required_scopes: ["wt:read"]` on every tool means the operator must grant
  this scope when issuing an agent/service credential. Without the scope, all
  calls are denied by `AddonAuthorityMiddleware` before the backend is ever
  invoked.
- `health` names `wt_get_health`, which has `"health": true` at the tool level.
  Exactly one tool may have `"health": true`.
- All tools have `read_only: true`, `readOnlyHint: true`, and
  `evidence_class: "read_only"`. The three must be consistent.

### 3.5 Validate the manifest locally

Before registering, validate the manifest against the JSON schema and the
cross-field contract rules:

```python
import json
from pathlib import Path
import jsonschema

from sift_gateway.backends import validate_manifest_contract

schema_path = Path("packages/sift-gateway/src/sift_gateway/sift-backend.schema.json")
manifest_path = Path("packages/wintriage-mcp/sift-backend.json")

schema = json.loads(schema_path.read_text())
manifest = json.loads(manifest_path.read_text())

# Step 1: JSON schema validation
jsonschema.validate(instance=manifest, schema=schema)
print("Schema OK")

# Step 2: Cross-field contract rules
validate_manifest_contract(manifest, manifest_path)
print("Contract OK")
```

Or invoke it through the REST validation endpoint (read-only, no side effects):

```bash
curl -sk -X POST https://192.168.122.81:4508/api/v1/backends/validate \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"name": "wintriage-mcp", "config": {"type":"stdio","command":"uv","args":["run","wintriage-mcp"],"manifest_path":"/opt/wintriage-mcp/sift-backend.json","enabled":true}}'
```

### 3.6 Prepare the registration payload

`scripts/setup-addon.sh` option 4 (custom backend) prompts for all required
fields and writes a JSON payload to `~/.sift/addon-register/<name>.json`:

```bash
./scripts/setup-addon.sh
# Select: 4
# Backend name: wintriage-mcp
# Transport: stdio
# Command: uv
# Args: run wintriage-mcp
# Manifest path: /opt/wintriage-mcp/sift-backend.json
# env KEY=VALUE: WINTRIAGE_URL=http://127.0.0.1:9999
```

The script echoes every value (nothing hidden) and writes the payload. It does
NOT register anything or modify the gateway.

### 3.7 Register through the portal or REST API

There is exactly one integration door. The payload from step 3.6 is the
input. Drive it yourself:

**Portal (recommended):** Portal -> Backends -> Add backend -> point at the
manifest path -> Validate -> Register.

**REST API:**
```bash
# Validate first (read-only, no side effects)
curl -sk -X POST https://192.168.122.81:4508/api/v1/backends/validate \
     -H "Authorization: Bearer <operator-token>" \
     -H "Content-Type: application/json" \
     -d @~/.sift/addon-register/wintriage-mcp.json

# Register (upsert; re-registering an existing name updates it)
curl -sk -X POST https://192.168.122.81:4508/api/v1/backends \
     -H "Authorization: Bearer <operator-token>" \
     -H "Content-Type: application/json" \
     -d @~/.sift/addon-register/wintriage-mcp.json
```

### 3.8 Verify the add-on is live

After registration, the gateway's `_late_start_checker` picks up the new row
within 30 seconds (OSX1 hot reload). Verify:

```bash
# Aggregate MCP tools/list (via operator portal or agent credential)
# wt_search_events and wt_get_process_tree should appear
curl -sk https://192.168.122.81:4508/api/v1/backends \
     -H "Authorization: Bearer <operator-token>"
# Look for "wintriage-mcp" with health_status "ok"

# Portal -> Backends: wintriage-mcp appears with status ok
```

Issue an agent/service credential from Portal -> Credentials with scope
`wt:read`, then run a smoke call:

```bash
curl -sk -X POST https://192.168.122.81:4508/mcp/ \
     -H "Authorization: Bearer <agent-token>" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wt_get_health","arguments":{}}}'
```

---

## 4. Real-World Reference: `opencti-mcp`

`packages/opencti-mcp/sift-backend.json` is the first shipped external add-on
manifest. It demonstrates the full contract for a query-only, non-authoritative
threat-intelligence add-on:

- Namespace `"cti"` — all tools prefixed `cti_`.
- `authority_contract` with `non_authoritative: true`, `query_only: true`,
  `plane: "reference"`, and the full list of prohibited operations.
- `capabilities.provides: ["reference", "threat-intel"]` with no requirements
  (`"requires": []`).
- Eight tools, all with `read_only: true`, `readOnlyHint: true`,
  `evidence_class: "read_only"`, and `required_scopes: ["cti:read"]`.
- Health tool: `cti_get_health` (with `"health": true`).

The conformance tests for OpenCTI are in
`packages/opencti-mcp/tests/test_opencti_contract.py`. An author should write
equivalent tests for their add-on.

**OpenCTI is not in the core install path.** The native installer
(`install.sh`) never seeds or references `opencti-mcp`. It is set up
exclusively through `scripts/setup-addon.sh` option 2 or the portal/REST door.
Windows-triage-style backends follow the same external path.

---

## 5. Conformance Checklist

Before submitting a manifest for registration, confirm every item:

**Identity and structure:**
- [ ] `spec_version` is `"1.0"` (or a later 1.x value).
- [ ] `tier` is `"addon"`.
- [ ] `transport` is `"stdio"` or `"http"`.
- [ ] `namespace` is non-empty, lowercase, and unique across all registered backends.
- [ ] `name` is unique across all registered backends (used as the DB key).

**Capabilities:**
- [ ] `capabilities.provides` contains at least one valid label.
- [ ] `capabilities.requires` entries use only supported formats (§3 of spec.md).
- [ ] Unknown format strings in `requires` are treated as unmet (fail-closed).
- [ ] `capabilities.enriches_responses` is set.

**Tools:**
- [ ] Every tool name starts with `<namespace>_`.
- [ ] No duplicate tool names within the manifest.
- [ ] Every tool has `read_only == readOnlyHint` (both values identical).
- [ ] `evidence_class` is consistent: `"read_only"` ↔ `read_only: true`;
  `"mutating"` ↔ `read_only: false`.
- [ ] `recommended_phase` is one of `SURVEY`, `INGEST`, `ANALYZE`, `CORRELATE`,
  `FINDING`.
- [ ] `category` is one of the seven valid values.
- [ ] Every tool has `required_scopes` listing the scope(s) an agent must hold.

**Health:**
- [ ] Top-level `health` names exactly one tool.
- [ ] That tool has `"health": true`.
- [ ] No other tool has `"health": true`.

**Authority contract:**
- [ ] `authority_contract` is present and `non_authoritative: true`.
- [ ] `query_only: true` for query-only add-ons.
- [ ] `prohibited_operations` includes all standard authority operations
  (see spec.md §2.5).
- [ ] `authority_disclaimer` is at least 20 characters.

**Secrets and connection:**
- [ ] No raw secrets in the connection config.
- [ ] All secrets referenced via `env_refs` (stdio) or `bearer_token_env`/
  `tls_cert_env` (http).
- [ ] HTTP backend `url` resolves to a public (non-private, non-loopback) address.

**Tests:**
- [ ] Schema + contract validation passes locally (see §3.5).
- [ ] The add-on has conformance tests matching the pattern in
  `packages/opencti-mcp/tests/test_opencti_contract.py`.

---

## 6. Failure Modes and What Happens

### 6.1 Unmet `requires[]` entry

The gateway evaluates `requires` during `_build_tool_map` and
`mount_single_addon_proxy`. If a requirement is unmet:
- The backend is excluded from `_available_backends`.
- Its tools do not appear in `tools/list`.
- A `WARNING` is logged: `"Backend <name> requires <req> which is not met. Gating this backend."`.
- The core gateway stays up. Other backends are unaffected.
- The operator can check backend health via Portal -> Backends.

An unknown requirement format (anything that does not match `docker`, `ram:*`,
`env:*`, or a host:port/URL pattern) is also treated as unmet and logs a
warning. Fix the requirement string in the manifest and re-register.

### 6.2 Missing or wrong `env_refs` / `bearer_token_env`

When the gateway tries to start a backend and a referenced environment
variable is absent or empty, `resolve_runtime_config` raises
`BackendRegistryError("env_refs.<target> references missing environment variable")`.
The gateway logs the error and marks the backend health as `"error"`. The
backend is not started; its tools are absent from `tools/list`.

Fix: ensure the gateway process environment contains the referenced variable
(via the gateway's environment file, typically `/var/lib/sift/.sift/control-plane.env`
or the relevant systemd `EnvironmentFile`), then restart the gateway or wait
for the 30-second hot-reload cycle.

### 6.3 Denied scope (`required_scopes` not satisfied)

When an agent calls a tool and the token does not carry all `required_scopes`
declared for that tool, `AddonAuthorityMiddleware` denies the call before the
backend is ever invoked. The agent receives:

```json
{
  "error": "addon_scope_missing",
  "tool": "wt_search_events",
  "detail": "principal is missing add-on tool scope(s) required by this backend tool",
  "missing_scopes": ["wt:read"]
}
```

The denial is audited to `app.audit_events`. Fix: the operator must issue or
update the agent credential to include the required scope.

### 6.4 Duplicate or shadowed tool name

If a tool name from an add-on collides with a core tool name, the gateway
raises `ValueError` during `_build_tool_map` and refuses to start or reload
the tool map. If two simultaneously registered add-ons expose the same tool
name, the same `ValueError` is raised.

```
ValueError: Tool name collision for 'wt_search_events' across backends: ['wintriage-mcp', 'other-addon']
ValueError: Tool name 'case_info' from backend wintriage-mcp collides with in-process core tool
```

Fix: rename the tool in your manifest (and in your Python server) to a unique
name under your namespace.

There is one exception: gateway-local tools (`_gateway_local_tools` set, e.g.
`opensearch_ingest` in DB-active mode) intentionally shadow add-on tools when
the gateway owns the policy boundary. An add-on must not declare a tool name
that the gateway owns.

### 6.5 Prohibited-operation attempt

When an agent calls an add-on tool and either the tool name or an
`operation`/`action`/`op`/`command`/`mode` argument value matches a
`prohibited_operations` entry, `AddonAuthorityMiddleware` denies the call:

```json
{
  "error": "addon_prohibited_operation",
  "tool": "wt_search_events",
  "detail": "add-on backend is non-authoritative and may not perform this authority operation",
  "prohibited_operations": ["seal_evidence"],
  "non_authoritative": true
}
```

The denial is audited. The backend is never invoked. Fix: the add-on must not
attempt authority operations. If the add-on genuinely needs to perform a
write, it must be redesigned as a different tier of integration (not an
external add-on).

### 6.6 Manifest validation failure at registration time

If the manifest fails JSON schema validation or `validate_manifest_contract`,
the registration API returns a 400 error with the validation message. Common
causes:
- `read_only` and `readOnlyHint` disagree on a tool entry.
- `evidence_class` is inconsistent with `read_only`.
- Top-level `health` does not match any tool in `tools[]`.
- More than one tool has `"health": true`.
- A tool name does not start with the declared namespace.
- `spec_version` does not start with `"1."`.
- An extra unknown field at the manifest or tool level (schema uses
  `additionalProperties: false`).

The REST validation endpoint (`POST /api/v1/backends/validate`) accepts the
same payload but is read-only (no DB write). Run it first to catch errors
before the actual registration.

### 6.7 Served-but-undeclared tool (served ⊆ manifest)

Every tool your backend actually serves on its live `tools/list` MUST be
declared in the manifest `tools[]` block. For a **started** backend the gateway
`_build_tool_map` compares the backend's real served tools against
`{t["name"] for t in manifest["tools"]}` and raises

```
ValueError: Tool '<name>' from backend '<backend>' is not declared in the manifest 'tools' block
```

which surfaces as an HTTP 500 on the next portal Start/Restart of the backend.
Note the asymmetry: a *not-started* backend builds its tool map from the
manifest alone, so an undeclared served tool passes every static and boot-time
check and only detonates on the first live Start. `validate_manifest_contract`
is manifest-only and cannot catch it either. The pin is `manifest_sha256`: the
operator-registered manifest bounds your served surface, so do not serve any
tool you have not declared.

**Renaming a tool (the safe path).** There is no alias mechanism — the add-on
contract does not let you keep serving an old tool name after a rename (the
former `deprecated_aliases` field was removed under B-MVP-052 because a served
alias is undeclared by construction and trips the guard above). To rename a
tool:

1. Add the **new** tool name to the manifest `tools[]` block and serve it under
   that name in your Python server.
2. Bump `manifest_sha256` to match the new manifest and re-register (via
   `POST /api/v1/backends` or Portal -> Backends).
3. The gateway now legally serves the new name; remove the old name from both
   the manifest and your server in the same or the next cutover cycle. Do not
   serve both names simultaneously unless **both** are declared in `tools[]`.

---

## 7. Development Workflow Summary

1. Write your MCP server. Name every tool `<namespace>_*`.
2. Write `sift-backend.json` following the template in §3.4 and the spec in
   `docs/add-ons/spec.md`.
3. Validate locally against the schema and `validate_manifest_contract`.
4. Run `scripts/setup-addon.sh` option 4 to generate a registration payload.
5. Validate via `POST /api/v1/backends/validate` (no side effects).
6. Register via `POST /api/v1/backends` or Portal -> Backends.
7. Within 30 seconds, tools appear in `tools/list` (or check Portal ->
   Backends for health status).
8. Issue an agent/service credential with the required scope(s) and run a
   smoke call.
9. Write conformance tests (see `packages/opencti-mcp/tests/test_opencti_contract.py`
   as the model).
10. To disable: Portal -> Backends -> toggle disabled. Tools disappear from
    `tools/list` immediately. The core gateway is unaffected.
