# Development Guide

## 1. Dev Environment Setup

```bash
# From repo root:
uv sync --extra dev

# Frontend (optional):
npm --prefix packages/case-dashboard/frontend install
```

The workspace covers all packages under `packages/*` (`pyproject.toml:2`).
Dev extras from `pyproject.toml:71-76` pull in `pytest>=9.0`, `pytest-asyncio>=0.23`,
`pytest-cov>=4.0`, `pyright>=1.1`, and `ruff>=0.15`.

## 2. Running Tests and Linting

```bash
# All tests (from repo root):
uv run --extra dev pytest

# Single package tests:
uv run --extra dev pytest packages/sift-core/tests/

# Lint (from repo root):
uv run --extra dev ruff check packages/<pkg>/src/

# Type-check — sift-gateway is the Pyright baseline (0 new diagnostics):
uv run --extra dev pyright packages/sift-gateway/src/sift_gateway/<file>.py

# Type-check other packages (may have pre-existing debt — fix only NEW diagnostics):
uv run --extra dev pyright packages/opensearch-mcp/src/opensearch_mcp/<file>.py
```

Test config (`pyproject.toml:117-120`): `testpaths = ["tests", "packages"]`,
`asyncio_mode = "auto"`, `asyncio_default_fixture_loop_scope = "function"`.
Ruff config (`pyproject.toml:88-91`): `target-version = "py310"`, `line-length = 88`,
selects `E, F, I, UP, B, SIM`.

## 3. Adding a Core Tool

Core tools live in `sift-core` and run in-process in the Gateway. They appear on the
aggregate `/mcp` surface alongside add-on tools.

**Step 1:** Add a `CoreToolSpec` to `CORE_TOOL_SPECS` in `agent_tools.py`:

```python
# packages/sift-core/src/sift_core/agent_tools.py:186
CoreToolSpec(
    name="my_new_tool",
    description="What this tool does.",
    input_schema={"type": "object", "properties": {}},
    read_only=True,  # or False for mutating tools
)
```

`CoreToolSpec` is a frozen dataclass (`agent_tools.py:41-47`): `name`, `description`,
`input_schema`, `read_only`, and optional `output_schema`.

**Step 2:** Add a handler branch in `call_core_tool()` (`agent_tools.py`):

```python
# In call_core_tool() — dispatch via if/elif chain
elif name == "my_new_tool":
    return _my_handler(arguments, examiner, manager, audit)
```

**Step 3:** Write a test in `packages/sift-core/tests/`.

**Step 4:** Run lint and type-check on changed files:

```bash
uv run --extra dev ruff check packages/sift-core/src/sift_core/agent_tools.py
uv run --extra dev pyright packages/sift-core/src/sift_core/agent_tools.py
uv run --extra dev pytest packages/sift-core/tests/
```

The Gateway auto-discovers core tools via `core_tool_specs()` at
`mcp_server.py:404-418`. No restart needed for testing — gateway rebuilds on
restart.

## 4. Adding an Add-on Backend

Add-on backends run as stdio subprocesses spawned by the Gateway. Each has its own
package, manifest, and typed tool registry. Existing examples:
`packages/opensearch-mcp/`, `packages/opencti-mcp/`, `packages/windows-triage-mcp/`,
`packages/rag-mcp/`.

### 4.1 Package Skeleton

```
packages/my-addon/
  pyproject.toml
  sift-backend.json
  src/my_addon/
    __init__.py
    registry.py     # ToolDef REGISTRY + Pydantic models
    server.py       # Implementation functions (return plain dicts)
  tests/
    test_surface_meta.py    # Surface conformance (SURFACE_OPTIONAL_KEYS)
```

### 4.2 pyproject.toml

```toml
[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[project]
name = "my-addon"
requires-python = ">=3.10"
dependencies = ["sift-common", "fastmcp>=3"]
```

Depend on `sift-common` — it provides `ToolDef`, `success_result`, `error_result`,
and the surface conformance harness. The workspace root `pyproject.toml:2` already
covers `packages/*`.

### 4.3 Manifest (`sift-backend.json`)

Spec version `"1.0"`, namespace prefix (e.g., `"myaddon_"`), tier `"addon"`,
transport `"stdio"`. Declare `capabilities`, `authority_contract`
(`non-authoritative: true`), and a `tools[]` array with per-tool metadata. Key
fields per tool entry:

- `name` — tool name shown to agents
- `when_to_use` / `avoid_when` — agent guidance
- `output_shape` — brief output structure description
- `safe_case_argument_names` — list of arg names the Gateway may safely inject
  (e.g., `["case_id", "case_dir"]`)
- `read_only` / `readOnlyHint` — bool
- `evidence_class` — `"read_only"` or `"mutating"`
- `category` — e.g., `"search-analysis"`, `"ingest"`, `"admin"`
- `recommended_phase` — `"SURVEY"`, `"INGEST"`, `"ANALYZE"`, `"CORRELATE"`

See `packages/opensearch-mcp/sift-backend.json` for a complete example.

### 4.4 Registry (`registry.py`)

The typed contract layer — the only module that knows about FastMCP/MCP protocol.
Declares Pydantic `*In` / `*Out` models and `run_*` wrappers that call into
`server.py` and reshape raw dicts into typed results.

```python
# packages/my-addon/src/my_addon/registry.py

from pydantic import BaseModel, Field
from fastmcp.tools import ToolResult
from mcp.types import ToolAnnotations
from sift_common.contracts import ToolDef, ToolError, ErrorCode, ResultMeta
from sift_common.registry_helpers import (
    success_result, error_result, register_all,
)
from sift_common.registry_helpers import tool_output_schema

class MyToolIn(BaseModel):
    query: str = Field(..., description="Search query.")

class MyToolOut(BaseModel):
    results: list[str]
    total: int

async def run_my_tool(params: MyToolIn) -> ToolResult:
    raw = _impl_server().my_tool(**params.model_dump())
    if "error" in raw:
        return error_result(
            ErrorCode.internal,
            str(raw["error"]),
            "Check backend logs, then retry."
        )
    out = MyToolOut(results=raw["results"], total=raw["total"])
    return success_result(out, MyToolOut)

def _impl_server():
    from my_addon import server as impl
    return impl

REGISTRY: list[ToolDef] = [
    ToolDef(
        name="myaddon_search",
        fn=run_my_tool,
        in_model=MyToolIn,
        out_model=MyToolOut,
        annotations=ToolAnnotations(readOnlyHint=True),
        title="Search via My Addon",
        description="Search...",
    ),
]
```

`ToolDef` is defined in `sift_common/contracts.py:44-51`. `success_result` wraps a
Pydantic model into a `ToolResult` with `structured_content` set
(`registry_helpers.py:88-105`). `error_result` builds a typed `ToolError` result
(`registry_helpers.py:108-130`).

### 4.5 Server (`server.py`)

Implementation engine — returns **plain dicts**, no Pydantic, no FastMCP types:

```python
# packages/my-addon/src/my_addon/server.py

def my_tool(query: str) -> dict:
    # Real I/O here
    return {"results": ["a", "b"], "total": 2}
```

This layering (`registry.py` = typed contract, `server.py` = plain dict engine) is
the canonical SIFT add-on pattern (`opensearch-mcp/server.py:1-8`).

### 4.6 Register the Backend

Backend registration is stored in Postgres (`app.mcp_backends`). Register via the
Portal (Backends → Register) or programmatically:

```python
McpBackendRegistry.register(name="my-addon", config=config, manifest=manifest, actor=operator)
```

`McpBackendRegistry` is at `sift_gateway/mcp_backends_registry.py:487-656`. The
method upserts into `app.mcp_backends`, validates the command is an absolute
allowlisted path (`assert_stdio_command_allowlisted` at line 445), normalizes
connection config (rejects raw secrets — env var references only,
`normalize_connection_config` at line 314), and creates an audit record.

At startup, `create_backend_instances()` (line 514) builds runtime backend objects
from enabled DB rows. Backends seeded after startup are auto-discovered by
`_late_start_checker → reload_backend_registry` (`server.py:803-848`).

### 4.7 Surface Conformance Tests

Every add-on backend with typed output models needs a `tests/test_surface_meta.py`
with a `SURFACE_OPTIONAL_KEYS` manifest dict. This catches the #1 recurring bug
class: a fix lands in the implementation layer but fails to reach the MCP surface.

```python
# packages/my-addon/tests/test_surface_meta.py

import pytest
from sift_common.testing.surface import assert_surfaces

SURFACE_OPTIONAL_KEYS = {
    "myaddon_search": {
        "in_args": {"query": "test"},
        "raw": {"results": ["a", "b"], "total": 2},
        "expected": {"results": ["a", "b"], "total": 2},
    }
}

@pytest.mark.parametrize("tool_name", sorted(SURFACE_OPTIONAL_KEYS.keys()))
def test_optional_keys_surface_via_run(tool_name, monkeypatch):
    spec = SURFACE_OPTIONAL_KEYS[tool_name]
    run_fn, in_model_cls, _out_model = _registry_entry(tool_name)
    in_model = in_model_cls(**spec.get("in_args", {}))
    assert_surfaces(run_fn, in_model, spec["raw"], spec["expected"],
                    monkeypatch_impl=monkeypatch)
```

See `packages/opensearch-mcp/tests/test_surface_meta.py:51-317` for the full harness
with parametrized coverage guards.

## 5. Adding a REST Endpoint

**Gateway routes** (`packages/sift-gateway/src/sift_gateway/rest.py:1-1385`):
Add a handler function returning `JSONResponse`, then add a `Route` instance to the
`rest_routes` list at the bottom of the file. Most mutation handlers call
`require_control_plane_operator` (`rest.py:22`, from `sift_gateway/auth`).

**Portal routes** (`packages/case-dashboard/src/case_dashboard/routes.py`):
Add a Starlette `Route`, include role checks — `_require_examiner_role` for
mutations, `_supabase_reverify` for sensitive actions.

## 6. Surface Conformance Testing

The surface conformance harness (`sift_common/testing/surface.py:1-314`) catches
regressions across three seams:

| Seam | What it protects | Assertion | Loc |
|------|-----------------|-----------|-----|
| **A** | `run_*` wrapper drops key before Pydantic | `assert_surfaces()` | line 125 |
| **B** | SDK `outputSchema` rejects `structured_content=None` | `assert_passes_output_schema()` | line 170 |
| **C** | Worker `_aggregate` conditional guard drift | Manual direct assert | line 43 |

Seam B also has two SDK-level tests:
- `assert_sdk_output_schema_enforced()` (line 213) — full `CallToolRequest` dispatch
- `assert_model_matches_output_schema()` (line 284) — model schema round-trip

When adding or editing a tool's output, always update `SURFACE_OPTIONAL_KEYS`.

## 7. Code Conventions

- **Python 3.10+** syntax. Line length target 88 (ruff: `pyproject.toml:90`).
- **`sift-common`** is the shared dependency leaf — add shared types there.
- **Add-on backends:** `registry.py` is the only module that knows about
  FastMCP/MCP protocol. `server.py` returns plain dicts — no Pydantic, no FastMCP.
- **Every add-on tool** must have a `safe_case_argument_names` declaration in its
  manifest (`sift-backend.json`).
- **Gateway namespace prefix enforcement and name collision detection** runs in
  `_build_tool_map()` (`server.py:462-682`).
- **Non-baseline packages** (`opensearch-mcp`, `opencti-mcp`, `case-dashboard`
  backend) carry legacy type debt — report NEW diagnostics from your edits
  separately, fix only what you introduced, do not expand `pyrightconfig.json`.
- **Read `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`** before touching
  auth, policy, backends, evidence, or execution.
- **Use codebase-memory MCP graph tools** (`search_graph`, `trace_path`) over grep
  for code discovery.
- **`ruff check` + `pyright` before committing.** `sift-gateway` must have 0 new
  pyright diagnostics.
