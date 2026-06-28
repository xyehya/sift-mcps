---
title: Add-on Ecosystem — Forensic RAG, OpenCTI, Windows Triage
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 10
status: draft
---

## Overview

Three add-on MCP backends share the reference/add-on pattern: stdio transport, namespace-prefixed tools, all `read_only`, non-authoritative, not case-scoped. They are launched as stdio subprocesses by the Gateway and provide reference data (forensic knowledge corpus, threat intelligence baselines, Windows OS baselines) without modifying case evidence.

## How it works

All three follow the same pattern:

1. Gateway loads the manifest from `app.mcp_backends` (Postgres)
2. Gateway spawns each as stdio subprocess
3. FastMCP proxy mounts the backend's tools into the aggregate `/mcp` surface
4. Each backend opens its own connection to its external system (pgvector, OpenCTI API, local SQLite)
5. Every tool is read-only, non-authoritative, and not case-scoped

## Reference sections

### 1. forensic-rag-mcp (`packages/forensic-rag-mcp/src/rag_mcp/`)

Manifest: `sift-backend.json` (tier: `addon`, namespace: `kb`, `default_case_scoped: false`, provides: `["reference"]`)

**3 tools (all `read_only: true`):**

| Tool | Purpose |
|------|---------|
| `kb_search_knowledge` | Semantic search over IR/DFIR knowledge corpus (Sigma, MITRE ATT&CK, Atomic Red Team, Splunk, KAPE, Velociraptor, LOLBAS, GTFOBins). Supports source/source_ids/technique/platform filters. Returns ranked provenance-linked snippets. |
| `kb_list_knowledge_sources` | List distinct knowledge source labels. |
| `kb_get_knowledge_stats` | Corpus statistics (chunk/doc/collection/source counts, embedding model). Also serves as health probe. |

**External system:** Supabase pgvector (Postgres + pgvector extension). DSN resolution: `SIFT_CONTROL_PLANE_DSN` > `DATABASE_URL` > `POSTGRES_DSN`. Embedding model: `BAAI/bge-base-en-v1.5` (768-dim, allowlist-pinned, revision-pinned `a5beb1e3e68b9ab74eb54cfd186867f64f240e1a`). Schema: `app.rag_collections`, `app.rag_documents`, `app.rag_chunks` tables; `app.rag_search`, `app.rag_upsert_chunk` RPCs.

**Security:**

- Model allowlist (`ALLOWED_MODELS` in `utils.py:35`): Only 5 SentenceTransformer models
- Forbidden paths (`constants.py:66`): `/`, `/home`, `/root`, `/tmp`, `/var`, `/etc`, `/usr`, `$HOME`
- SSRF protection: URL hostname allowlist, IP-literal blocking, DNS-rebinding countermeasure, redirect validation
- Path sanitization: `_sanitize_hit()` (`pgvector_store.py:102`) drops embedding/spec_internal/dsn keys; `_scrub_text()` (`pgvector_store.py:70`) redacts absolute paths
- `_validate_kind_case` (`pgvector_store.py:514`): Both Python-layer and DB-trigger enforce `kind='knowledge'`; `kind='derived'` raises

**Config env vars:** `RAG_MODEL_NAME`, `RAG_MAX_TOP_K` (50), `RAG_MAX_QUERY_LENGTH` (1000), `RAG_ALLOW_HTTP`, `RAG_UNSAFE_PATHS`, `RAG_MAX_DOWNLOAD_BYTES` (60MB), `RAG_MODEL_REVISION`.

### 2. opencti-mcp (`packages/opencti-mcp/src/opencti_mcp/`)

Manifest: `sift-backend.json` (tier: `addon`, namespace: `cti`, provides: `["reference", "threat-intel"]`)

**8 tools (all `read_only: true`, namespaced `cti_`):**

| Tool | Purpose |
|------|---------|
| `cti_get_health` | Check OpenCTI connectivity and API health |
| `cti_search_threat_intel` | Broad search across all entity types (indicators, actors, malware, techniques, CVEs, reports). Max 20 per type. |
| `cti_search_entity` | Search one specific entity type. 16 valid types. |
| `cti_lookup_ioc` | IOC lookup (IP, hash, domain, URL, CVE, MITRE id). Returns full context. |
| `cti_get_recent_indicators` | Recent IOCs from last N days (default 7, max 90) |
| `cti_get_entity` | Full details by OpenCTI UUID |
| `cti_get_relationships` | Relationships filtered by direction and relationship_types |
| `cti_search_reports` | Threat intelligence reports by keyword |

**External system:** OpenCTI GraphQL API via `pycti.OpenCTIApiClient(url, token)`. Rate limiting: 600 queries/min, 100 enrichment/min (`config.py:72-73`). Circuit breaker: 5 failure threshold, 60s recovery (`config.py:80-81`). Caching: search TTL=60s, entity TTL=300s, IOC TTL=60s. Token: `OPENCTI_TOKEN` env > `~/.config/opencti-mcp/token` (600 perms) > `.env`.

**Security (`config.py`):**

- `SecretStr` token prevents logging; `frozen=True` prevents mutation; file perms 600
- URL validation: http/https only; non-local http warns
- Input length checks (`validation.py:25-26`): `MAX_QUERY_LENGTH=1000`, `MAX_IOC_LENGTH=2048`, all validated before regex (anti-ReDoS)
- Null byte rejection, UUID validation (36 chars, 8-4-4-4-12), domain validation (ASCII-only, length limits), label validation (10 max, ASCII-only)
- STIX pattern validation: balanced brackets, observable type prefix
- Response truncation: `MAX_RESPONSE_SIZE=1MB` (`validation.py:30`), description 500 chars, pattern 200 chars
- Log sanitization: `sanitize_for_log()` redacts sensitive fields

**Config env vars:** `OPENCTI_URL` (default `http://localhost:8080`), `OPENCTI_TIMEOUT` (60s, range 1-300), `OPENCTI_SSL_VERIFY` (default true), `OPENCTI_CIRCUIT_THRESHOLD`/`TIMEOUT`, `FF_*` feature flags.

### 3. windows-triage-mcp (`packages/windows-triage-mcp/src/windows_triage_mcp/`)

Manifest: `sift-backend.json` (tier: `addon`, namespace: `wintriage`, provides: `["reference", "baseline"]`)

**6 tools (all `read_only: true`, namespaced `wintriage_`):**

| Tool | Purpose |
|------|---------|
| `wintriage_check_artifact` | Validate artifact against offline baselines. 5 subtypes: file (path+optional hash), hash (LOLDrivers lookup), filename (deception heuristics), lolbin (LOLBin context), dll (hijackability). |
| `wintriage_check_process_tree` | Validate parent-child process relationship against baseline. Triple approach: never-spawns rules, suspicious-parent blacklist, valid-parent allowlist. |
| `wintriage_check_system` | Validate persistence/system config. 3 subtypes: service, scheduled_task, autorun. |
| `wintriage_check_registry` | Check registry key/value against full baseline (requires optional ~12GB `known_good_registry.db`). |
| `wintriage_check_pipe` | Check named pipe against known Windows/C2 pipes. |
| `wintriage_server_status` | Backend readiness: health, db_stats, or all. |

**External system:** Fully offline — three local SQLite databases:

- `known_good.db` — Process/registry/service/task/pipe baselines from Windows clean installs
- `context.db` — Risk enrichment (LOLBins, vulnerable drivers, C2 pipes, DLL hijackability)
- `known_good_registry.db` — Optional, ~12GB
- Data shipped as pre-built files, downloaded via `scripts/download_databases.py`

**Analysis modules (`analysis/`):**

- `filename.py` — Executable extension detection, entropy, known tool filenames
- `hashes.py` — Hash algorithm detection, normalization, validation
- `paths.py` — Path normalization, system directory recognition
- `unicode.py` — RLO/BIDI override detection, homoglyph normalization, leet-speak, typosquatting via Levenshtein
- `verdicts.py` — `SUSPICIOUS > EXPECTED_LOLBIN > EXPECTED > UNKNOWN` priority (`verdicts.py:37`)

**Security:**

- Input length limits: paths 4096, hashes 128, pipe names 256
- Null byte rejection on all string inputs
- Read-only databases in production
- Parameterized queries against SQL injection
- Fully offline — no SSRF or network exposure
- Unicode evasion detection (RLO, homoglyphs, zero-width, typosquatting against 100+ protected process names)

## Invariants

| # | Invariant | Evidence |
|---|-----------|----------|
| 1 | **All three are read-only** | Every tool has `readOnlyHint: true` and `read_only: true` in manifest. None mutates case evidence. (each package's `sift-backend.json`) |
| 2 | **Non-authoritative** | All three have `authority_contract.non_authoritative: true` with identical prohibited operations. (each package's `sift-backend.json`) |
| 3 | **Not case-scoped** | `default_case_scoped: false` across all three. No Gateway active-case injection. (each package's `sift-backend.json`) |
| 4 | **Namespace prefix enforcement** | Every tool name starts with the declared namespace (`kb_`, `cti_`, `wintriage_`). Gateway rejects tools not matching. (`server.py:_build_tool_map()`) |
| 5 | **Forensic RAG enforces knowledge-only** | Both Python-layer and DB-trigger enforce `kind='knowledge'`. `kind='derived'` raises. (`pgvector_store.py:514-526`) |
| 6 | **OpenCTI token never logged** | `SecretStr` type with frozen, pickle-blocking, file perms 600. (`config.py:4-8, 61`) |
| 7 | **Windows triage is fully offline** | No external API calls. Databases shipped as pre-built files. (`README.md`, `scripts/download_databases.py`) |
| 8 | **SUSPICIOUS > EXPECTED_LOLBIN > EXPECTED > UNKNOWN verdict priority** | Designed to avoid false positives. UNKNOWN is explicitly neutral. (`analysis/verdicts.py:37`) |
| 9 | **Embedding model allowlist-pinned** | Only 5 SentenceTransformer models in `ALLOWED_MODELS`. RAG_MODEL_NAME must be in it. (`utils.py:35-43`) |
| 10 | **OpenCTI version enforcement** | pycti and OpenCTI server major versions must match. Caught at connect time with actionable error. (`errors.py:133-164`, `client.py:1036`) |

## Gotchas & Edge Cases

> **forensic-rag-mcp embedding model is allowlist-pinned to 5 models.** `RAG_MODEL_NAME` override must be in `ALLOWED_MODELS` (`utils.py:35`).

> **opencti-mcp has two server implementations:** legacy `mcp.server.Server` path (`server.py`) and newer FastMCP 3 registry (`registry.py`). The FastMCP path uses Pydantic-validated in/out models with structured ToolResult.

> **Windows-triage `known_good_registry.db` is ~12GB and optional.** Tools degrade gracefully when absent. (`sift-backend.json` tool description, registry check logic)

> **OpenCTI version enforcement:** pycti and OpenCTI server major versions must match. Caught at connect time with actionable error (`errors.py:133`).

> **Windows-triage also has a FastMCP 3 registry** (`registry.py:1`) alongside the server module (`server.py:1689`).

## Related

- Gateway doc (how add-on manifests are loaded, how ProxyActiveCase handles non-case-scoped backends)
- OpenSearch Data Plane doc (shared add-on architecture pattern)
- Control Plane doc (`app.mcp_backends` for backend registration)

## Key files

| Package | Files |
|---------|-------|
| forensic-rag-mcp | `server.py`, `pgvector_store.py`, `sources.py`, `constants.py`, `config.py`, `utils.py`, `sift-backend.json` |
| opencti-mcp | `server.py`, `registry.py`, `client.py`, `config.py`, `validation.py`, `contracts.py`, `errors.py`, `sift-backend.json` |
| windows-triage-mcp | `server.py`, `registry.py`, `analysis/` (verdicts, paths, unicode, hashes, filename), `db/`, `sift-backend.json` |

### Full paths

- `packages/forensic-rag-mcp/src/rag_mcp/server.py`
- `packages/forensic-rag-mcp/src/rag_mcp/pgvector_store.py`
- `packages/forensic-rag-mcp/src/rag_mcp/sources.py`
- `packages/forensic-rag-mcp/src/rag_mcp/constants.py`
- `packages/forensic-rag-mcp/src/rag_mcp/config.py`
- `packages/forensic-rag-mcp/src/rag_mcp/utils.py`
- `packages/forensic-rag-mcp/sift-backend.json`
- `packages/opencti-mcp/src/opencti_mcp/server.py`
- `packages/opencti-mcp/src/opencti_mcp/registry.py`
- `packages/opencti-mcp/src/opencti_mcp/client.py`
- `packages/opencti-mcp/src/opencti_mcp/config.py`
- `packages/opencti-mcp/src/opencti_mcp/validation.py`
- `packages/opencti-mcp/src/opencti_mcp/contracts.py`
- `packages/opencti-mcp/src/opencti_mcp/errors.py`
- `packages/opencti-mcp/sift-backend.json`
- `packages/windows-triage-mcp/src/windows_triage_mcp/server.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/registry.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/analysis/verdicts.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/analysis/paths.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/analysis/unicode.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/analysis/hashes.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/analysis/filename.py`
- `packages/windows-triage-mcp/src/windows_triage_mcp/db/`
- `packages/windows-triage-mcp/sift-backend.json`

## Reconciliation log

None — independently confirmed against code.
