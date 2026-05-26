# sift-mcps Tool Audit — 2026-05-25

78 tools across 8 MCP backends, aggregated behind sift-gateway at `/mcp`.
Live snapshot from SIFT VM (192.168.122.81:4508), case `test-rocba-2026`.

---

## 1. case-mcp (14 tools) — Case lifecycle, evidence registry, audit

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `case_list` | yes | — | List all cases with status (open/closed) and active flag |
| 2 | `case_status` | yes | `case_id` (opt) | Detailed case status: finding counts, timeline, TODOs, platform capabilities |
| 3 | `case_file_structure` | yes | — | Recursive tree of all files/dirs in the active case directory |
| 4 | `evidence_register` | no | `path`*, `description` | PORTAL-ONLY. Returns portal-remediation block when called by agent |
| 5 | `evidence_list` | yes | — | List registered evidence files with SHA-256, registration dates; shows unregistered files |
| 6 | `evidence_verify` | yes | — | Stat-check integrity of all registered evidence against manifest (ok/unsealed/modified/missing/unregistered/ledger_error) |
| 7 | `export_bundle` | no | `since` (opt) | Export findings+timeline as JSON bundle (may be large, 30K+ tokens) |
| 8 | `import_bundle` | no | `bundle_path`* | Import bundle, merging findings+timeline (last-write-wins) |
| 9 | `audit_summary` | yes | — | Audit trail stats: total entries, evidence IDs, breakdown by MCP and tool |
| 10 | `record_action` | no | `description`*, `tool`, `command`, `analyst_override` | Log supplemental action note (auto-committed, no approval) |
| 11 | `log_reasoning` | no | `text`*, `analyst_override` | Record analytical reasoning to audit trail (survives context compaction) |
| 12 | `log_external_action` | no | `command`*, `output_summary`*, `purpose`*, `analyst_override`, `hook_audit_id`, `input_files`, `output_files` | Record tool execution done outside MCP; returns audit_id for findings |
| 13 | `backup_case` | no | `destination`*, `purpose` | Backup case metadata/findings/timeline/audit/reports (not evidence files) |
| 14 | `open_case_dashboard` | yes | — | Return portal URL with auth token (clickable link for examiner) |

**Key issues:**
- `evidence_register` (tool 4) is visible to the agent but always returns a portal-remediation block. Should be FILTERED from agent view (B4).
- `case_init` and `case_activate` are defined as inner functions but NOT decorated — dead code in `create_server()`, removable.
- `export_bundle` returns 30K+ tokens — dangerous for context. Should have a `compact=True` default.

---

## 2. forensic-mcp (10 tools) — Findings, timeline, TODOs, workflow

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `record_finding` | no | `finding`*, `analyst_override`, `supporting_commands`, `artifacts` | Stage finding as DRAFT for human review. Rich docstring with field requirements |
| 2 | `record_timeline_event` | no | `event`*, `analyst_override` | Stage timeline event as DRAFT |
| 3 | `get_findings` | no | `status`, `limit`(20), `offset`(0) | Return findings filtered by DRAFT/APPROVED/REJECTED |
| 4 | `get_timeline` | no | `status`, `source`, `examiner`, `start_date`, `end_date`, `event_type`, `limit`(50), `offset`(0) | Return timeline events with 6 optional filters |
| 5 | `get_actions` | no | `limit`(50) | Recent actions from the case actions log |
| 6 | `workflow_status` | **yes** | — | **NEW (B1)**. Single entry point — detects phase, returns next steps. Replaces 7+ discovery calls |
| 7 | `add_todo` | no | `description`*, `assignee`, `priority`(medium), `related_findings`, `analyst_override` | Create investigation TODO |
| 8 | `list_todos` | no | `status`(open), `assignee` | List TODOs by status |
| 9 | `update_todo` | no | `todo_id`*, `status`, `note`, `assignee`, `priority`, `analyst_override` | Update TODO fields |
| 10 | `complete_todo` | no | `todo_id`*, `analyst_override` | Mark TODO completed |

**Not visible to agent (registered as MCP Resources, not tools):**
- 14 discipline reference resources (investigation-framework, rules, checkpoints, validation-schema, evidence-standards, confidence-definitions, anti-patterns, evidence-template, tool-guidance/{tool}, false-positive-context/{tool}/{type}, corroboration/{type}, playbooks, playbook/{name}, collection-checklist/{type})

**Key issues:**
- `get_findings`, `get_timeline`, `get_actions`, `list_todos` are all READ-ONLY but not annotated `readOnlyHint` → would be blocked on UNSEALED evidence gate unnecessarily.
- 14 discipline tools available in `reference_mode="tools"` but default is `"resources"` — these never appear. Good design, but verify gateway is using resources mode.

---

## 3. sift-mcp (5 tools) — Forensic tool execution

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `list_available_tools` | no | `category` (opt) | List forensic tools on SIFT workstation with availability status |
| 2 | `get_tool_help` | no | `tool_name`* | Usage info, flags, and caveats for a specific forensic tool |
| 3 | `check_tools` | no | `tool_names` (opt, list) | Check which tools are installed and available |
| 4 | `suggest_tools` | no | `artifact_type`*, `question` (opt) | Suggest tools for analyzing a specific artifact type (uses forensic-knowledge) |
| 5 | `run_command` | no | `command`*(list), `purpose`*, `timeout`(0), `save_output`(False), `input_files`, `working_dir`, `preview_lines`(0), `skip_enrichment`(False) | Execute forensic tool on SIFT workstation. **Core tool** — the primary workhorse |

**Automatic enrichment for `run_command`:**
- FK (forensic-knowledge) context injected on first call: caveats, corroboration suggestions, advisories
- `skip_enrichment=True` suppresses FK on repeat calls (saves tokens)
- Artifact context auto-detected from command args for FK advisory filtering
- Output saved with SHA-256 hashes when `save_output=True`
- Input files tracked for provenance chain

**Key issues:**
- `list_available_tools`, `get_tool_help`, `check_tools`, `suggest_tools` are all read-only but not annotated — should be `readOnlyHint=True`.
- `run_command` is the catch-all — it can do almost anything. The agent needs guidance on when to use it vs. structured tools.

---

## 4. opensearch-mcp (20 tools) — Evidence ingest, search, enrichment

### Query tools (all readOnlyHint=True)

| # | Tool | Params | Description |
|---|------|--------|-------------|
| 1 | `idx_search` | `query`*, `index`, `case_id`, `limit`(50,max200), `offset`(0), `sort`(@timestamp:desc), `time_from`, `time_to`, `compact`(True) | Search indexed evidence with query_string syntax |
| 2 | `idx_count` | `query`(*), `index`, `case_id` | Count matching documents |
| 3 | `idx_aggregate` | `field`*, `query`(*), `index`, `case_id`, `limit`(50,max500) | Group by field with optional query filter |
| 4 | `idx_get_event` | `event_id`*, `index`* | Retrieve single document by _id |
| 5 | `idx_timeline` | `query`(*), `index`, `case_id`, `interval`(1h), `time_field`(@timestamp), `time_from`, `time_to` | Event count over time as date histogram |
| 6 | `idx_field_values` | `field`*, `query`(*), `index`, `case_id`, `limit`(50,max500) | Unique values for a field (terms aggregation) |
| 7 | `idx_status` | — | OpenSearch cluster + case index status |
| 8 | `idx_shard_status` | — | Shard usage and capacity headroom |
| 9 | `idx_case_summary` | `case_id`, `include_fields`(False) | Complete overview of indexed evidence — FIRST call in any indexed investigation |
| 10 | `idx_list_detections` | `severity`, `detector_type`, `limit`(50), `offset`(0) | Security Analytics (Sigma) detections; suggests Hayabusa alternatives |

### Ingest tools (no readOnlyHint)

| # | Tool | Params | Description |
|---|------|--------|-------------|
| 11 | `idx_ingest` | `path`*, `hostname`, `include`, `exclude`, `source_timezone`, `all_logs`(False), `reduced_ids`(False), `full`(False), `dry_run`(True), `vss`(False), `password`, `no_hayabusa`(False) | Discover and ingest forensic artifacts. **dry_run=True by default** — agent must explicitly set False |
| 12 | `idx_ingest_status` | `case_id` (opt) | Check running/recent ingest operations. `"*"` for all cases |
| 13 | `idx_ingest_json` | `path`*, `hostname`*, `index_suffix`, `time_field`, `dry_run`(True) | Ingest JSON/JSONL files |
| 14 | `idx_ingest_delimited` | `path`*, `hostname`, `index_suffix`, `time_field`, `delimiter`, `recursive`(False), `dry_run`(True) | Ingest CSV/TSV/Zeek/bodyfile |
| 15 | `idx_ingest_accesslog` | `path`*, `hostname`*, `index_suffix`, `dry_run`(True) | Ingest Apache/Nginx access logs |
| 16 | `idx_ingest_memory` | `path`*, `hostname`*, `tier`(1), `plugins`, `dry_run`(True) | Parse memory image with Volatility 3 |

### Enrichment/Admin tools (no readOnlyHint)

| # | Tool | Params | Description |
|---|------|--------|-------------|
| 17 | `idx_enrich_intel` | `case_id`, `dry_run`(True), `force`(False) | Enrich indexed evidence with OpenCTI threat intel. Async — returns immediately with run_id |
| 18 | `idx_enrich_triage` | `case_id` | Run Windows baseline enrichment on indexed data |
| 19 | `idx_install_pipelines` | — | Install/verify OpenSearch ingest pipelines and index templates (admin) |
| 20 | `case_host_fix` | `raw`*, `new_canonical`* | Correct wrong host.id mapping; reindexes affected documents |

**Key issues:**
- **4 separate ingest tools** (`idx_ingest`, `idx_ingest_json`, `idx_ingest_delimited`, `idx_ingest_accesslog`) with overlapping functionality — consolidation candidate.
- `idx_ingest` has 11 parameters, many with confusing defaults (`dry_run=True`, `full=False`). Agent must understand the tier system.
- `idx_ingest_status` is readOnlyHint but rest of ingest tools are not — inconsistent.
- `idx_install_pipelines` and `case_host_fix` are admin tools that should maybe not clutter agent view.

---

## 5. forensic-rag-mcp (3 tools) — Semantic knowledge search

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `search_knowledge` | yes | `query`*, `top_k`(5), `source`, `source_ids`, `technique`, `platform` | Semantic search over 23K+ IR knowledge records. Scores 0-1 |
| 2 | `list_knowledge_sources` | yes | — | List all available knowledge sources in the RAG index |
| 3 | `get_knowledge_stats` | yes | — | RAG index statistics: doc count, sources, model info |

**Clean. Well-designed. No issues.** All 3 annotated `readOnlyHint=True`.

---

## 6. opencti-mcp (8 tools) — Threat intelligence enrichment

All tools prefixed `opencti-mcp__` in aggregate gateway.

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `get_health` | no* | — | Check OpenCTI server connectivity and API health |
| 2 | `search_threat_intel` | no* | `query`*, `limit`(5,max20), `offset`(0,max500), `labels`, `confidence_min`(0-100), `created_after`, `created_before` | Broad search across ALL entity types |
| 3 | `search_entity` | no* | `type`*(enum16), `query`*, `limit`(10,max50), `offset`, `labels`, `confidence_min`, `created_after`, `created_before` | Type-specific search (more results, more precise) |
| 4 | `lookup_ioc` | no* | `ioc`* | Look up specific IOC (IP/hash/domain/URL) with full context |
| 5 | `get_recent_indicators` | no* | `days`(7,max90), `limit`(20,max100) | Recently added IOCs |
| 6 | `get_entity` | no* | `entity_id`*(UUID) | Full details for a specific entity by UUID |
| 7 | `get_relationships` | no* | `entity_id`*, `direction`(both), `relationship_types`, `limit`(50) | Entity relationships (uses/indicates/targets) |
| 8 | `search_reports` | no* | `query`*, `limit`(10,max50), `offset`(0,max500), `labels`, `confidence_min`, `created_after`, `created_before` | Search threat intel reports |

*No `readOnlyHint` annotations at all — ALL are read-only. Should be annotated.
*These tools use plain `Tool(...)` objects, not decorators — annotations would need to be added to the `Tool(...)` constructor.

**Key issues:**
- All 8 tools are read-only but NONE carry `readOnlyHint` → all blocked on UNSEALED evidence gate.
- `search_threat_intel` and `search_entity` overlap significantly — the agent must understand when to use each.
- No caching hints in descriptions (the underlying client has a cache, but the agent doesn't know).

---

## 7. windows-triage-mcp (13 tools) — Baseline validation

All tools prefixed `windows-triage-mcp__` in aggregate gateway.

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `get_health` | no* | — | Server health: uptime, DB connectivity, cache, memory |
| 2 | `check_file` | no* | `path`*, `hash`, `os_version` | Check file path against Windows baseline → EXPECTED/LOLBIN/SUSPICIOUS/UNKNOWN |
| 3 | `check_process_tree` | no* | `process_name`*, `parent_name`*, `path`, `user` | Validate parent-child relationship |
| 4 | `check_service` | no* | `service_name`*, `binary_path`, `os_version`* | Check service against OS-version baseline |
| 5 | `check_scheduled_task` | no* | `task_path`*, `os_version`* | Check scheduled task against baseline |
| 6 | `check_autorun` | no* | `key_path`*, `value_name`, `os_version`* | Check registry autorun/persistence entry |
| 7 | `check_registry` | no* | `key_path`*, `value_name`, `hive`, `os_version` | Check registry key/value against full baseline (needs 12GB DB) |
| 8 | `check_hash` | no* | `hash`* | Check hash against LOLDrivers vulnerable driver DB |
| 9 | `analyze_filename` | no* | `filename`* | Deception analysis: homoglyphs, typosquatting, double extensions |
| 10 | `check_lolbin` | no* | `filename`* | Check if binary is a known LOLBin with abuse techniques + MITRE |
| 11 | `check_hijackable_dll` | no* | `dll_name`* | Check if DLL is vulnerable to search-order hijacking |
| 12 | `check_pipe` | no* | `pipe_name`* | Check named pipe against known Windows pipes + C2 pipes |
| 13 | `get_db_stats` | no* | — | Baseline DB statistics: record counts, OS versions, update timestamps |

*No `readOnlyHint` annotations at all — ALL are read-only. Should be annotated.

**Key issues:**
- 13 tools is a lot of surface area for what is essentially "look up X in baseline DB". 
- `check_file`, `check_hash`, `check_lolbin`, `analyze_filename` — 4 tools for checking a filename/hash. Could be unified.
- `check_service`, `check_scheduled_task`, `check_autorun`, `check_registry` — 4 tools for Windows artifact checking. Similar pattern.
- All tools are read-only but no `readOnlyHint` annotation — would be blocked on UNSEALED.

---

## 8. report-mcp (6 tools) — Report generation

| # | Tool | readOnly | Params | Description |
|---|------|----------|--------|-------------|
| 1 | `generate_report` | no | `profile`(full), `case_id`, `finding_ids`, `start_date`, `end_date` | Generate structured report. 6 profiles: full, executive, timeline, ioc, findings, status |
| 2 | `set_case_metadata` | no | `field`*, `value` | Set metadata field in CASE.yaml (validated enum/date/list) |
| 3 | `get_case_metadata` | no | `field` (opt) | Retrieve metadata from CASE.yaml |
| 4 | `list_profiles` | no | — | List available report profiles with Zeltser tool mappings |
| 5 | `save_report` | no | `filename`*, `content`*, `profile` | Persist rendered report to case reports/ directory |
| 6 | `list_reports` | no | — | List saved reports |

**Key issues:**
- `get_case_metadata` and `list_profiles` and `list_reports` are read-only but not annotated.
- `set_case_metadata` writes to CASE.yaml — needs to be clearly marked as write tool.

---

## Context Injection (Automatic, Per-Tool-Call)

The gateway injects context into every tool response:

1. **Evidence gate context** (`mcp_endpoint.py:528-538`):
   - On UNSEALED: `_agentir_context` with `evidence_gate_warning: True`, status, manifest_version, remediation string
   - On VIOLATION: full block response with `blocked: True`, reason, issues[], remediation

2. **Response guard context** (`mcp_endpoint.py:526-534`):
   - When secrets detected: `_agentir_context` with `secret_warning: [pattern_names]`, `redact_override_active: bool`

3. **FK enrichment** (`sift_mcp/response.py:113-173`):
   - For `run_command` only — injects caveats, corroboration, advisories from forensic-knowledge
   - First call per tool: full enrichment. Subsequent calls: `skip_enrichment=True` suppresses.
   - Token budget decay counters limit how often FK content is delivered

4. **Case context** (`mcp_endpoint.py:540`):
   - Every response gets `_case: {case_id, dir, evidence_dir}` appended

5. **Audit ID envelope** (`mcp_endpoint.py:543-569`):
   - Every call_tool writes a gateway transport audit entry

---

## Summary Statistics

| Backend | Tool Count | readOnlyHint | Missing Annotation |
|---------|-----------|-------------|-------------------|
| case-mcp | 14 | 7 of 14 | `record_action`, `log_reasoning`, `log_external_action`, `backup_case`, `export_bundle`, `import_bundle` (6 are genuinely write tools — correct) |
| forensic-mcp | 10 | 1 of 10 | `get_findings`, `get_timeline`, `get_actions`, `list_todos` (4 read-only tools missing annotation) |
| sift-mcp | 5 | 0 of 5 | `list_available_tools`, `get_tool_help`, `check_tools`, `suggest_tools` (4 read-only missing) |
| opensearch-mcp | 20 | 11 of 20 | `idx_ingest_status` has it; ingest tools correctly don't. 2 admin tools debatable |
| forensic-rag-mcp | 3 | 3 of 3 | PERFECT |
| opencti-mcp | 8 | 0 of 8 | ALL 8 are read-only, none annotated |
| windows-triage-mcp | 13 | 0 of 13 | ALL 13 are read-only, none annotated |
| report-mcp | 6 | 0 of 6 | `get_case_metadata`, `list_profiles`, `list_reports` read-only missing |
| **TOTAL** | **78** | **22 of 78** | **~35 tools are read-only but only 22 are annotated** |

---

## Interaction Map

```
workflow_status ──first call──▶ Agent
    │
    ├─ ORIENT ──▶ case_status, evidence_list
    ├─ SEALED ──▶ idx_ingest (opensearch-mcp)
    ├─ INGESTING ──▶ idx_ingest_status (opensearch-mcp)  
    ├─ TRIAGE ──▶ idx_case_summary → idx_search → idx_aggregate → idx_timeline
    │              ├─ search_knowledge (forensic-rag)
    │              ├─ lookup_ioc / search_threat_intel (opencti)
    │              ├─ check_file / check_process_tree (windows-triage)
    │              └─ run_command (sift-mcp) for custom analysis
    ├─ FINDINGS ──▶ record_finding → get_findings (forensic-mcp)
    │                └─ record_timeline_event (forensic-mcp)
    └─ REPORTING ──▶ generate_report → save_report (report-mcp)

Automatic enrichment:
    run_command ──▶ FK caveats/corroboration (sift-mcp response.py)
    idx_enrich_intel ──▶ OpenCTI IOC lookup (async, 15-60 min)
    idx_enrich_triage ──▶ Windows baseline cross-check
    All tools ──▶ Evidence gate check (mcp_endpoint.py)
    All tools ──▶ Response guard redaction (mcp_endpoint.py)
    All tools ──▶ Gateway audit envelope (mcp_endpoint.py)
```

---

## Critical Issues Blocking Autonomous DFIR

1. **No tool categorization** — 78 tools in a flat alphabetical list. The agent cannot distinguish session-start tools from deep-analysis tools from admin tools.

2. **Missing readOnlyHint on 35 truly read-only tools** — On UNSEALED evidence state, these tools would be incorrectly blocked by the evidence gate, preventing the agent from even orienting itself.

3. **Portal-only tools visible to agent** — `evidence_register` always returns a portal-remediation block. The agent should never see it.

4. **Ingest tool sprawl** — 4 separate ingest tools (`idx_ingest`, `idx_ingest_json`, `idx_ingest_delimited`, `idx_ingest_accesslog`) could be unified under `idx_ingest` with a `format` parameter.

5. **Windows triage fragmentation** — 13 tools for "look up X in baseline DB". Could be unified into fewer tools with a `check_type` parameter, or at minimum grouped under a clear prefix.

6. **OpenCTI tool overlap** — `search_threat_intel` and `search_entity` have nearly identical signatures. The distinction is confusing.

7. **No `annotations` propagation** — `get_tools_list()` in server.py:474-479 drops annotations. The `workflow_status` readOnlyHint I added in B1 won't reach the agent until this is fixed.

8. **No evidence chain state in workflow_status** — B1 doesn't check the evidence gate at all. If evidence is tampered, `workflow_status` won't detect it, and the agent won't get the HITL signal from the workflow entry point.
