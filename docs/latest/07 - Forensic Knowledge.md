---
title: Forensic Knowledge — YAML Knowledge Loader
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 3
status: draft
---

## Overview

`forensic-knowledge` (`packages/forensic-knowledge/src/forensic_knowledge/`) provides a YAML knowledge loader with in-memory caching for forensic knowledge data. Pure data dependency — no network calls, no external system connections. Used by `sift-core` for finding validation rules, confidence definitions, anti-patterns, evidence standards, artifact/tool catalogs, investigation playbooks, and collection checklists. Runs offline with data bundled via `hatch build` `force-include` (`pyproject.toml:53-54`).

## How it works

`loader.py:_find_data_dir()` (line 24) resolves the data directory in three strategies, in order:

1. **`FK_DATA_DIR` env override** — for testing/PMI3 installer (test: `test_fk_data_dir_env_override_resolves`)
2. **Source tree**: `Path(__file__).resolve().parent.parent.parent / "data"` — resolves to `packages/forensic-knowledge/data/`
3. **`importlib.resources.files("forensic_knowledge") / "data"`** — installed package path via `force-include` in wheel

Data is loaded on first request and cached in a module-level `_cache: dict[str, Any]` (line 64). `clear_cache()` (line 104) resets both cache and data dir resolution. The cache is **not** `@lru_cache` — it is a manual dict with a `__dir__` prefix convention for directory loads.

## Reference sections

### `loader.py` — Knowledge Loader

All public functions use `_load_yaml()` (line 67) or `_load_all_in_dir()` (line 83). YAML paths are relative to `_data_dir`. 23 public functions total.

**Artifact knowledge**:
- `get_artifact(name)` (line 130) — Loads artifact by name, searches `artifacts/{windows,linux,macos}/{name}.yaml`. First match wins. Returns `None` if not found.
- `list_artifacts(platform=None)` (line 141) — Lists artifacts, filtered by platform if given. Returns `{name, description, platform}` dicts.
- `artifact_catalog(platform=None)` (line 157) — Catalog with `id` (file stem, feedable to `get_artifact`), `name`, `aliases`, `platform`. Test `test_artifact_catalog_id_roundtrip` proves round-trip.
- `get_artifacts_for_tool(tool_name)` (line 186) — Finds artifacts where `related_tools` contains the tool name.

**Tool knowledge**:
- `get_tool(name)` (line 201) — Case-insensitive lookup; normalizes via `.lower()`. Iterates all category directories.
- `list_tools(category=None, platform=None)` (line 211) — Lists tools, optionally filtered. Returns `{name, category, description, platform}`.
- `_iter_tool_categories()` (line 231) — Returns sorted subdirectory names under `tools/`. 17 categories exist: browser, carving, file_analysis, hashing, imaging, logs, malware, mcp, memory, network, persistence, registry, sleuthkit, timeline, triage, volatility, zimmerman.

**Discipline knowledge**:
- `get_rules()` (line 244) — Loads `discipline/rules.yaml`, returns `data["rules"]`.
- `get_confidence_definitions()` (line 276) — Loads `discipline/confidence.yaml`, returns `data["levels"]`. Levels: HIGH (min_audit_ids: 2), MEDIUM (min_audit_ids: 1), LOW (min_audit_ids: 0), SPECULATIVE (min_audit_ids: 0).
- `get_anti_patterns()` (line 282) — Loads `discipline/anti_patterns.yaml`, returns `data["anti_patterns"]`.
- `get_evidence_standards()` (line 288) — Loads `discipline/evidence_standards.yaml`, returns `data["standards"]`. Standards: CONFIRMED (level 1, min_sources: 2), INDICATED (level 2, min_sources: 1), INFERRED (level 3, min_sources: 1), UNKNOWN (level 4, min_sources: 0), CONTRADICTED (level 5, min_sources: 1).
- `get_evidence_template()` (line 294) — Loads `discipline/evidence_template.yaml`, returns `data["template"]`.

**Checkpoints and guidance**:
- `get_checkpoint(action_type)` (line 300) — Loads `discipline/checkpoints.yaml`, scans for matching `action_type`. Known types: attribution, root_cause, exclusion, clean_declaration. All require `human_approval: true`.
- `list_checkpoints()` (line 311) — Returns `{action_type, description}` for all checkpoints.
- `get_corroboration(finding_type)` (line 325) — Loads `discipline/guidance/corroboration.yaml`, returns findings for a type.
- `get_false_positive_context(tool, finding_type)` (line 333) — Loads `discipline/guidance/false_positives.yaml`, keys by `"{tool}/{finding_type}"`.
- `get_tool_interpretation(tool)` (line 342) — Loads `discipline/guidance/tool_interpretation.yaml`, returns tool guidance if present.

**Investigation playbooks**:
- `get_playbook(name)` (line 250) — Loads `discipline/playbooks/{name}.yaml`. `_sanitize_name` applied. Known: `credential_access` (test: `test_get_playbook_known`).
- `list_playbooks()` (line 256) — Returns `{name, description, phases}` for each.
- `list_playbook_slugs()` (line 270) — Returns sorted filename stems from `discipline/playbooks/`.

**Collection checklists**:
- `get_collection_checklist(artifact)` (line 350) — Loads `discipline/checklists/{artifact}.yaml`. `_sanitize_name` applied.
- `list_collection_checklists()` (line 356) — Lists available checklist slugs from `discipline/checklists/`.

**Operational**:
- `get_investigation_framework()` (line 364) — Loads `discipline/framework/investigation_framework.yaml`.
- `clear_cache()` (line 104) — Clears `_cache` and resets `_DATA_DIR` to `None`.

### `_sanitize_name()` — Path Traversal Protection

In `loader.py:116-122` (not a separate `security.py`). Rejects: empty name, `..`, `/`, `\\`, null bytes (`\x00`). Applied in `get_artifact`, `get_playbook`, `get_collection_checklist`. Tests: `test_get_artifact_path_traversal_rejected`, `test_get_playbook_path_traversal_rejected`, `test_get_collection_checklist_path_traversal_rejected`.

### `data/` — YAML Files

Bundled at `packages/forensic-knowledge/data/`. Structure:

```
data/
├── artifacts/
│   ├── linux/        (no macos dir in this repo)
│   └── windows/
├── discipline/
│   ├── anti_patterns.yaml
│   ├── checklists/
│   ├── checkpoints.yaml
│   ├── confidence.yaml
│   ├── evidence_standards.yaml
│   ├── evidence_template.yaml
│   ├── framework/
│   │   └── investigation_framework.yaml
│   ├── guidance/
│   │   ├── corroboration.yaml
│   │   ├── false_positives.yaml
│   │   └── tool_interpretation.yaml
│   ├── playbooks/
│   └── rules.yaml
└── tools/            (17 category subdirectories)
```

Built into the wheel via `[tool.hatch.build.targets.wheel.force-include]` → `"data" = "forensic_knowledge/data"` (`pyproject.toml:53-54`).

### `__init__.py`

Exports `__version__` from `importlib.metadata.version("forensic-knowledge")` with `PackageNotFoundError` fallback to `"0.0.0.dev0"` (lines 5-8). Source of truth: `hatch-vcs` from git release tags matching `^v(?P<version>...)` (`pyproject.toml:42-45`).

## Invariants

- **Offline-only**: No network calls, no external system connections. Only dependency: `pyyaml>=6.0` (`pyproject.toml:26`). All data is bundled YAML. (`loader.py`)
- **Path traversal protection**: `_sanitize_name()` rejects `..`, `/`, `\\`, null bytes before any file access. Located in `loader.py`, not a separate `security.py`. (`loader.py:116-122`)
- **In-memory caching**: Manual `_cache` dict on all public functions, not `@lru_cache`. Cache cleared via `clear_cache()` or process restart. (`loader.py:64`)
- **No mutation APIs**: Test `test_loader_has_no_mutation_apis` asserts no `create_case`, `seal_evidence`, `approve_finding`, etc. exists in the module.
- **Non-authoritative reference data**: `sift-backend.json` declares `non_authoritative: true`, `plane: reference`, `query_only: true` (test: `test_sift_backend_json_non_authoritative`).

## Gotchas & Edge Cases

> [!note] The data directory resolves at runtime through three fallback strategies. `FK_DATA_DIR` env var takes priority for testing. When the env var points to a non-existent directory, it is silently skipped and fallback strategies apply (test: `test_fk_data_dir_env_ignored_when_not_a_dir`).

> [!warning] Case-insensitive tool name lookup: `get_tool()` normalizes via `.lower()`, but the YAML files store tool names with arbitrary casing. No normalization on artifact names — `get_artifact("Amcache")` will miss `amcache.yaml`.

> [!note] `macos` artifacts directory does not exist in this repo. The `get_artifact()` loop includes `"macos"` but the directory is absent, so macOS artifacts return `None`.

> [!note] The cache is a manual `dict`, not `@lru_cache`. No TTL, no eviction. `clear_cache()` is the only way to reset.

## Related

- Core Tools doc (finding validation uses `get_confidence_definitions()`, `get_rules()`, `get_corroboration()`)
- Add-on Ecosystem doc: `forensic-rag-mcp` uses separate knowledge corpus (not this package)

## Key files

| File | Purpose |
|------|---------|
| `loader.py` | All 23 public knowledge loader functions + `_sanitize_name` |
| `data/` | YAML artifact definitions, tool catalogs, discipline rules, confidence defs, anti-patterns, evidence standards, playbooks, checklists |
| `__init__.py` | Version export via `importlib.metadata` |
| `pyproject.toml` | Build config, `force-include` for data bundling, hatch-vcs versioning |
| `sift-backend.json` | Authority contract: non-authoritative reference data |
| `tests/test_loader_contract.py` | 22 tests covering load, path traversal, env override, contract |

## Reconciliation log

- **`@lru_cache` claim corrected**: actual implementation uses a manual `_cache` dict in `_load_yaml()` / `_load_all_in_dir()`, not `@lru_cache` decorators. (`loader.py:64-80`)
- **`security.py` claim corrected**: `_sanitize_name()` lives in `loader.py:116-122`, not a separate module. No `security.py` exists in the package.
- **macOS directory**: `data/artifacts/macos/` does not exist in this checkout; `get_artifact()` and `list_artifacts()` loop over it but find zero artifacts.
