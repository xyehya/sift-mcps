---
title: Shared Contracts — Common Audit, Schema, and Contracts
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 5
status: draft
---

## Overview
`sift-common` (packages/sift-common/src/sift_common/) is the shared layer preventing copy-paste drift across all sibling packages. It provides audit trail (AuditWriter with cross-process flock), MCP schema construction (output_schema preventing B-MVP-038 class bugs), shared contracts (ToolDef, ToolError, ErrorCode, ResultMeta), registry wiring (register_all, build_function_tool), identifier validation (examiner slug), output parsers (text/JSON/CSV with byte-budget truncation), LLM instruction strings, and the surface conformance test harness. Only runtime dependency: `pyyaml`. The `testing/` subpackage is never shipped in production wheels.

## How it works
Dependency graph: `sift-common` is a leaf — `pyproject.toml` declares only `pyyaml>=6.0` as a direct runtime dependency. Types from `pydantic`, `fastmcp`, and `jsonschema` are used but arrive transitively via sibling packages. All 7 sibling packages depend on it. Every backend uses the same `AuditWriter`, `output_schema()`, `register_all()`, and `ErrorCode`/`ToolError` contracts.

## Reference sections

### __init__.py
- `resolve_case_dir()`: Resolves from SIFT_CASE_DIR; returns "" if not set or invalid
- `resolve_share_path(relative_path)`: Joins SIFT_SHARE_ROOT with share-relative path

### audit.py — AuditWriter
**class AuditWriter**: Writes audit entries to per-MCP JSONL in case audit directory.
- `__init__(mcp_name, audit_dir)`: `mcp_name` used for filenames (`{mcp_name}.jsonl`, `.seq`, `.lock`)
- `log(tool, params, result_summary, ...)` -> `audit_id | None`: Writes entry. Returns audit_id, or None when no active case. DB-authority mode (SIFT_DB_ACTIVE) returns audit_id even with no local ledger. Concurrency-safe: cross-process `fcntl.flock` + in-process `threading.Lock`.
- `get_entries(since, case_id)` -> list[dict]: Read back entries.
- `close()`: Release lock fd.

Audit entry shape: `{ts, mcp, tool, audit_id, examiner, case_id, source, params, result_summary, elapsed_ms, input_files, input_sha256s, ...}`

Audit ID format: `{mcp_name_without_suffix}-{examiner_slug}-{YYYYMMDD}-{seq:03d}`

Concurrency model: Cross-process `fcntl.flock(LOCK_EX)` on `.lock` file (outermost). In-process `threading.Lock` for seq counter (inside flock). Crash safety: JSONL append first, then atomic sidecar write.

### contracts.py — Shared Contracts/Models
- **class ResultMeta** `BaseModel`: `audit_id`, `examiner`, `caveats` (list[str]), `interpretation_constraint`, `audit_warning`
- **class ErrorCode** `str, Enum`: `invalid_input`, `not_found`, `upstream_unavailable`, `upstream_degraded`, `rate_limited`, `not_configured`, `no_active_case`, `capacity_refused`, `internal`
- **class ToolError** `BaseModel`: `error` (ErrorCode), `message` (str), `remediation` (str), `retryable` (bool), `details` (dict)
- **class ToolDef** `BaseModel`: `name`, `fn` (Callable), `in_model` (type[BaseModel]), `out_model` (type[BaseModel]), `annotations` (ToolAnnotations), `title`, `description`

### env.py — Environment Loading
- `parse_int_env(name, default)` -> int
- `parse_float_env(name, default)` -> float
- `parse_set_env(name)` -> frozenset[str]: comma-separated
- `parse_bool_env(name, default=False)` -> bool: truthy = "true","1","yes","on" (case-insensitive)
- **class SecretStr**: Wrapper hiding value in `repr`/`__str__` ("***"). Supports `get_secret_value()`, `__eq__`, `__hash__`, `__bool__`, `__len__`.

### identifiers.py — Identifier Types
- `EXAMINER_SLUG_PATTERN`: `^[a-z0-9][a-z0-9-]{0,19}\Z`
- `is_valid_examiner_slug(value)` -> bool: Rejects empty, path separators, dots, whitespace, uppercase, NUL, trailing newlines. This is the single source of truth — previously copy-pasted across 6 modules.

### instructions.py — MCP Server Instructions
Module-level string constants:
- `FORENSIC_MCP` ~42 lines: Rule Zero, evidence presentation, HITL checkpoints, confidence levels, anti-patterns
- `GATEWAY` ~34 lines: Aggregated surface, run_command sandbox, output cap, evidence sovereignty
- `WINDOWS_TRIAGE`: SUSPICIOUS/EXPECTED_LOLBIN/EXPECTED/UNKNOWN verdict guide
- `FORENSIC_RAG`: Semantic search caveats
- `OPENCTI`: CTI as supporting evidence
- `OPENSEARCH`: Full workflow (summary→aggregate→search→timeline→enrich)

### mcp_schema.py — MCP Schema Helpers
- **class SchemaCollisionError** ValueError: Raised when success and error models clash in `$defs`
- `output_schema(success_model, error_model)` -> dict: Builds spec-compliant `outputSchema` with root `type: "object"` and `anyOf` over both models. Hoists all `$defs` to document root. Every SIFT backend uses this.

### oplog.py — Operational Logging
- **class _StructuredFormatter**: JSON log formatter with `ts`, `level`, `logger`, `message`, `service`. WARNING+ adds `location`. Exception adds `exception`.
- `setup_logging(service_name, *, level, json_format, log_to_file)`: JSON to stderr. Controlled by SIFT_LOG_FORMAT (json/text) and SIFT_LOG_FILE (true/false).

### parsers/ — Output Parsers
**text_parser.py**: `parse_text(stdout, max_lines=50000, byte_budget=0)` -> `{lines, total_lines, preview_lines, ...}`
**json_parser.py**: `parse_json(text, max_entries=100000, byte_budget=0)` -> `{data, total_entries, truncated, ...}`. Also `parse_jsonl()`.
**csv_parser.py**: `parse_csv(text, max_rows=10000, byte_budget=0)` -> `{rows, total_rows, truncated, columns, ...}`. Also `parse_csv_file()` with 50MB size guard.

### registry_helpers.py — Registry Helpers
- **class PromptDef** BaseModel: `name`, `fn`, `title`, `description`
- **class ResourceDef** BaseModel: `uri`, `fn`, `name`, `title`, `description`, `mime_type`
- `register_all(mcp, tools, prompts, resources)`: Registers all on FastMCP server
- `tool_output_schema(out_model)` -> dict: Wrapper over `output_schema(out_model, ToolError)`
- `success_result(result, out_model, meta)` -> ToolResult
- `error_result(code, message, remediation, ...)` -> ToolResult
- `call_with_optional_context(fn, params, context)`: Passes (params, context) if fn accepts 2 args
- `build_function_tool(tool_def, name, ...)` -> FunctionTool: Standard validation, error handling, auto output_schema

### testing/surface.py — Surface Conformance Testing
Three identified seams:
- Seam A: `run_*` wrapper drops key before Pydantic
- Seam B: SDK `outputSchema` catches `structured_content=None`
- Seam C: Worker `_aggregate` plain-dict conditional guard drift

Key exports:
- `call_through_registry(run_fn, in_model, raw_dict, *, monkeypatch_impl)` -> ToolResult
- `assert_surfaces(run_fn, in_model, raw, expected, *, monkeypatch_impl)` -> ToolResult: Seam A assertion
- `assert_passes_output_schema(out_schema, result)`: Seam B assertion
- `assert_sdk_output_schema_enforced(mcp_server, tool_name, ...)`: Full SDK dispatch Seam B test
- `assert_model_matches_output_schema(out_model, instance=None)`: Seam B meta-test

`SURFACE_OPTIONAL_KEYS` pattern: Consuming package declares manifest dict keyed by tool name. Parametrized meta-test calls `assert_surfaces()` for each entry.

## Invariants
- **Single source of truth for examiner slug**: All callers import from `identifiers.py`. Previously copy-pasted across 6 modules. (`identifiers.py`)
- **Output schema root type must be "object"**: `output_schema()` always produces root `type: "object"`, preventing B-MVP-038 class rejections by strict MCP clients. (`mcp_schema.py`)
- **Cross-process audit concurrency**: `fcntl.flock` on `.lock` file + in-process `threading.Lock`. Lock ordering: flock outermost, thread lock inside. Crash safety: append first, atomic sidecar second. (`audit.py:AuditWriter.log`)
- **SecretStr never logs secrets**: `__repr__` and `__str__` return "***". `get_secret_value()` is the only extraction path. (`env.py:SecretStr`)
- **Testing/ subpackage never ships**: Not included in production wheels. (`testing/__init__.py`)

## Gotchas & Edge Cases
> [!warning] `result_summary` audit field handles dicts as-is, lists as `{count, type}`, everything else as `{value}`. Large results are truncated by the caller before calling `log()`. (`audit.py`)

> [!important] `SchemaCollisionError` is raised at server build time if success and error models share `$defs` names. Use unique model names per backend. (`mcp_schema.py`)

> [!note] `parse_set_env` does NOT lowercase values. Callers must normalize if case-insensitive comparison is intended. (`env.py`)

## Related
- All 7 sibling packages depend on sift-common
- Gateway doc (AuditWriter used for MCP audit trail)
- Core Tools doc (AuditWriter used for all core tool logging)
- All add-on docs (each uses register_all, output_schema, ToolDef, ErrorCode)

## Key files
- `audit.py` — AuditWriter (cross-process safe)
- `contracts.py` — ToolDef, ToolError, ErrorCode, ResultMeta
- `env.py` — Environment parsers, SecretStr wrapper
- `identifiers.py` — Single source of truth for examiner slug validation
- `instructions.py` — LLM discipline strings for all MCP servers
- `mcp_schema.py` — output_schema builder preventing B-MVP-038
- `oplog.py` — JSON structured logging setup
- `parsers/text_parser.py` — Text output parser with byte budget
- `parsers/json_parser.py` — JSON/JSONL output parser
- `parsers/csv_parser.py` — CSV output parser
- `registry_helpers.py` — register_all, build_function_tool, success/error_result
- `testing/surface.py` — Surface conformance test harness (Seam A/B/C)

## Reconciliation log
None — independently confirmed against code.
