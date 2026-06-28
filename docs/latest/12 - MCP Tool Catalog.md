---
title: MCP Tool Catalog — All 42 Tools with Schemas
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 3
status: draft
---

# MCP Tool Catalog

## 1. Tool Overview Table

| Backend | Count | Read-Only | Mutating | Namespace | Protocol |
|---|---|---|---|---|---|
| sift-core | 8 | 5 | 3 | (none) | In-process |
| sift-gateway | 3 | 2 | 1 | (none) | In-process |
| opensearch-mcp | 14 | 11 | 3 | `opensearch_` | stdio proxy |
| forensic-rag-mcp | 3 | 3 | 0 | `kb_` | stdio proxy |
| opencti-mcp | 8 | 8 | 0 | `cti_` | stdio proxy |
| windows-triage-mcp | 6 | 6 | 0 | `wintriage_` | stdio proxy |
| **Total** | **42** | **35** | **7** | — | — |

## 2. Interaction Matrix

| Backend | Interacts With |
|---|---|
| sift-core | Local case directory, Postgres investigation store, forensic tool binaries |
| sift-gateway | Postgres (durable jobs, active case, evidence refs) |
| opensearch-mcp | OpenSearch (primary), Postgres (provenance, host identity, job status), OpenCTI (enrichment callback through gateway) |
| forensic-rag-mcp | Supabase pgvector (knowledge corpus) |
| opencti-mcp | OpenCTI GraphQL API |
| windows-triage-mcp | Local SQLite databases (known_good.db, context.db, known_good_registry.db) |

# 3. sift-core (8 tools — In-process)

**Package:** `packages/sift-core/src/sift_core/`
**Namespace:** (none — registered directly on the aggregate gateway surface)
**Transport:** In-process (same Python process as the gateway)
**Source:** `packages/sift-core/src/sift_core/agent_tools.py`

### case_info

**Description:** Essential case overview: status, finding/timeline/todo counts, evidence chain status, file structure summary, platform capabilities. Call at session start.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| *(none)* | | | | No input parameters. |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| case_id | string | Case identifier |
| name | string | Case name |
| status | string | Case status |
| examiner | string | Examiner identity |
| case_brief | string | Case brief text |
| findings | object | `{total, draft, approved}` — finding counts |
| timeline_events | integer | Count of timeline events |
| todos | object | `{open, total}` — todo counts |
| evidence_chain | object | `{status, ok, issues[], manifest_version}` |
| file_structure | object | `{top_level_dirs[], total_files, total_dirs, subtree_counts, full_tree_path?}` |
| platform_capabilities | object | Available platform capabilities |

**Interacts With:** Local case directory, Postgres investigation store, evidence chain manifest

**Security Annotations:** No special scope — available to all authenticated agents. DB-authority mode overrides evidence chain fields from Postgres.

---

### evidence_info

**Description:** Evidence listing with registration, sealing, chain integrity, and manifest verification in a single call. Returns sealed evidence and unregistered files with required actions.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| *(none)* | | | | No input parameters. |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| chain_status | string | Evidence chain integrity status |
| ok_count | integer | Count of OK entries |
| issues | string[] | Chain integrity issues |
| manifest_version | integer | Manifest version |
| evidence_files | object[] | `{evidence_id, display_path, sealed, chain_ok}` |
| total_evidence_files | integer | Total evidence file count |
| unregistered_files | string[] | Unregistered file paths |
| requires_examiner_action | boolean | Whether examiner action is needed |

**Interacts With:** Local case directory, evidence manifest, Postgres (DB-authority mode)

**Security Annotations:** DB-authority mode overrides evidence listing from Postgres. No special scope.

---

### record_finding

**Description:** Stage a finding as DRAFT for examiner approval. Findings missing required fields or provenance (audit_ids) are REJECTED.

**read_only:** No (mutating — writes finding to case store)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| finding | object | **Yes** | — | Finding payload (see below) |
| finding.title | string | Yes (in finding) | — | Concise finding title |
| finding.type | string (enum) | Yes (in finding) | — | One of: `finding`, `attribution`, `conclusion`, `exclusion` |
| finding.host | string | Yes (in finding) | — | Affected hostname |
| finding.observation | string | Yes (in finding) | — | Raw evidence observed |
| finding.interpretation | string | Yes (in finding) | — | Analytical interpretation |
| finding.confidence | string (enum) | Yes (in finding) | — | `HIGH`, `MEDIUM`, `LOW`, or `SPECULATIVE`. Auto-clamped down to a provenance ceiling (W3) |
| finding.confidence_justification | string | Yes (in finding) | — | Why this confidence level is justified |
| finding.audit_ids | string[] | No | — | Audit IDs from tool responses — critical for provenance |
| finding.mitre_ids | string[] | No | — | MITRE ATT&CK technique IDs |
| finding.iocs | string[] | No | — | Indicators of compromise |
| finding.event_type | string | No | — | Event type classification |
| finding.event_timestamp | string | No | — | ISO 8601 timestamp of the incident event |
| finding.artifact_ref | string | No | — | Artifact reference |
| finding.related_findings | string[] | No | — | Related finding IDs |
| finding.supersedes | string[] | No | — | Finding IDs this finding corrects/replaces (self-correction chain) |
| finding.affected_account | string | No | — | Affected account name |
| supporting_commands | object[] | No | — | `{command, output_excerpt, purpose, audit_id}` |
| artifacts | object[] | No | — | `{source, extraction, content, content_type?, purpose?, audit_id?}` — must include audit_id from tool response |

**Output Shape:** Standard tool response with `{success, data, audit_id, command?}` plus provenance metadata.

**Interacts With:** Postgres investigation store (findings table)

**Security Annotations:** Findings are staged as DRAFT — not final. Confidence is auto-clamped to provenance ceiling. Only `artifacts[]` with audit_id chains to sealed evidence raise the provenance grade above LOW.

---

### record_timeline_event

**Description:** Stage a timeline event as DRAFT for examiner approval.

**read_only:** No (mutating — writes timeline event)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| event | object | **Yes** | — | Event payload (see below) |
| event.title | string | Yes (in event) | — | Concise event title |
| event.timestamp | string | Yes (in event) | — | ISO 8601 timestamp of the event |
| event.description | string | Yes (in event) | — | What occurred |
| event.host | string | Yes (in event) | — | Host where the event occurred |
| event.source | string | Yes (in event) | — | Evidence source file or log type |
| event.event_type | string (enum) | No | — | One of: `execution`, `persistence`, `lateral`, `auth`, `network`, `other` |
| event.related_findings | string[] | No | — | Related finding IDs |
| event.audit_ids | string[] | No | — | Audit IDs from tool responses |
| event.mitre_ids | string[] | No | — | MITRE ATT&CK technique IDs |

**Output Shape:** Standard tool response with success/error and audit_id.

**Interacts With:** Postgres investigation store (timeline_events table)

**Security Annotations:** Timeline events are staged as DRAFT — not final.

---

### list_existing_findings

**Description:** List staged findings already recorded in the active case.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| status | string (enum) | No | — | Filter by status: `DRAFT`, `COMMITTED`, `REJECTED`, `SUPERSEDED` |
| limit | integer | No | 20 | Max results to return |
| offset | integer | No | 0 | Pagination offset |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| findings | object[] | `{id, title, status, confidence, host, type, staged, examiner}` |
| total | integer | Total findings matching filter |
| limit | integer | Echoed limit |
| offset | integer | Echoed offset |
| full_findings_path | string | Full path to the findings JSON file |

**Interacts With:** Postgres investigation store (findings table)

**Security Annotations:** No special scope.

---

### manage_todo

**Description:** Manage investigation TODOs. Supports create, list, update, and complete actions.

**read_only:** No (mutating — creates/updates TODOs)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| action | string (enum) | **Yes** | — | One of: `create`, `list`, `update`, `complete` |
| todo_id | string | conditional | — | Required for `update` and `complete` actions |
| description | string | conditional | — | Required for `create` action |
| assignee | string | No | — | Assignee name |
| priority | string (enum) | No | — | One of: `low`, `medium`, `high` |
| status | string (enum) | No | — | One of: `open`, `in_progress`, `completed`, `blocked` |
| note | string | No | — | Note text |
| related_findings | string[] | No | — | Related finding IDs |

**Output Shape:** Varies by action — returns created/updated todo or listing.

**Interacts With:** Postgres investigation store (todos table)

**Security Annotations:** No special scope.

---

### get_tool_help

**Description:** Get usage information, common flags, caveats, and field meanings for a cataloged forensic tool.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| tool_name | string | **Yes** | — | Name of the forensic tool to look up |

**Output Shape:** Returns tool documentation as structured text — usage, common flags, caveats, field meanings.

**Interacts With:** Local forensic tool catalog (execute/tools catalog)

**Security Annotations:** Read-only reference — no case scope needed.

---

### run_command

**Description:** Execute a quick, synchronous validated command on the SIFT VM and return inline preview/receipt output. Supports pipes (`|`), sequencing (`&&`/`||`/`;`), and redirects (`>`/`>>`/`<`/`2>&1`). Case path jails, audit logging, and provenance hashing are enforced.

**read_only:** No (mutating — executes commands on the VM)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| command | string | **Yes** | — | Command to execute. May include pipes, `&&`/`||`/`;`, and redirects. |
| purpose | string | **Yes** | — | Short reason for this command, recorded in the audit trail |
| timeout | integer | No | 0 | Per-command timeout in seconds (0 = platform default) |
| save_output | boolean | No | false | Persist full stdout/stderr to `agent/run_commands/` |
| evidence_refs | string[] | No | — | Sealed evidence references (evidence_id or relative display path) the command reads |
| output_ref | string | No | — | Logical name for saved output. Resolved to `agent/run_commands/` |
| input_files | string[] | No | — | Deprecated: prefer evidence_refs |
| working_dir | string | No | — | Working directory, relative to the case directory |
| preview_lines | integer | No | 0 | Cap inline stdout to this many lines (0 = no inline cap) |
| skip_enrichment | boolean | No | false | Skip forensic-knowledge enrichment after the first call |

**Output Shape:** Tool response with `{success, data, audit_id, exit_code, command[], provenance{job_id, input_sha256s[], input_count, evidence_refs[], output_sha256?, output_ref?}, full_output_ref?, full_output_sha256?, full_output_bytes?, isolation?, warnings?, agent_action?, privilege_escalation?, stages[], failed_stages?, partial_failure?, input_files_warning?}`

**Interacts With:** SIFT VM shell, forensic tool binaries, case directory (jailed), Postgres audit

**Security Annotations:** Case path jailing enforced — commands cannot escape the case directory. Audit logging is mandatory. Provenance hashing tracks all inputs and outputs. Evidence refs are resolved internally; the agent never supplies absolute paths. Command arrays with shell operators are rejected. Isolation posture (cgroup, seccomp, Landlock) is reported on the response. The returned `rc-{audit_id}` receipt ID is _not_ a durable job ID — use `run_command_job` for long-running work.

---

# 4. sift-gateway (3 tools — In-process)

**Package:** `packages/sift-gateway/src/sift_gateway/`
**Namespace:** (none — registered directly on the aggregate gateway surface)
**Transport:** In-process (same Python process as the gateway)
**Source:** `packages/sift-gateway/src/sift_gateway/mcp_server.py`, `job_tools.py`

### capability_guide

**Description:** ADD-ON backends only: manifest-derived guide to currently usable add-on tools, grouped by backend, provides[], category, and recommended phase. Returns empty when no add-on backend is registered — that is expected, NOT an error.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| *(none)* | | | | No input parameters. |

**Output Shape:** List of capability records — each with backend name, tool listing, category, recommended phase, and provides array.

**Interacts With:** Gateway backend registry (read-only manifest inspection)

**Security Annotations:** No special scope. Returns only manifest metadata — no secrets, credentials, or case data.

---

### run_command_job

**Description:** Enqueue a sandboxed run_command request through the Postgres job state machine for long-running or parallel work. Returns a pollable UUID job_id only; use `running_commands_status` to retrieve terminal status and sanitized output refs.

**read_only:** No (mutating — enqueues a durable job)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| command | string | **Yes** | — | Command to execute |
| purpose | string | **Yes** | — | Short reason for this command |
| timeout | integer | No | 0 | Per-command timeout in seconds |
| save_output | boolean | No | false | Persist full stdout/stderr |
| evidence_refs | string[] | No | — | Sealed evidence references |
| output_ref | string | No | — | Logical name for saved output |
| working_dir | string | No | — | Working directory relative to case dir |
| preview_lines | integer | No | 0 | Cap inline stdout lines |
| skip_enrichment | boolean | No | false | Skip forensic-knowledge enrichment |
| priority | integer | No | 100 | Job priority |
| max_attempts | integer | No | 1 | Maximum retry attempts |

**Output Shape:** `{job_id (UUID), status: "queued", job_type: "run_command", spec_public{command, purpose, ...}}`

**Interacts With:** Postgres (durable job queue), SIFT VM shell

**Security Annotations:** Returns only opaque UUID job_id + spec_public. Absolute evidence/case paths are resolved by the gateway and written only into `spec_internal` for the local worker. Evidence refs are resolved via the evidence service — the client never supplies absolute paths.

---

### running_commands_status

**Description:** Read sanitized status for a durable Postgres job. Pass the UUID job_id from `run_command_job`, or from `opensearch_ingest` only when it returned status='queued' (worker-dispatched).

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| job_id | string | **Yes** | — | UUID job_id from `run_command_job` or a worker-dispatched `opensearch_ingest` |

**Output Shape:** Sanitized job status — `{job_id, status, job_type, worker_label?, current_step?, result_public?, error?, ...}`

**Interacts With:** Postgres (durable job status — `app.job_status_public`)

**Security Annotations:** Only returns sanitized public fields (no absolute paths, no internal spec). Rejects non-UUID job_ids. Validates caller identity against the job's ownership.

---

# 5. opensearch-mcp (14 tools — stdio proxy)

**Package:** `packages/opensearch-mcp/src/opensearch_mcp/`
**Namespace:** `opensearch_`
**Transport:** stdio proxy (keep_alive subprocess)
**Source:** `packages/opensearch-mcp/src/opensearch_mcp/registry.py`

### opensearch_search

**Description:** Search indexed evidence with query_string syntax. Use for targeted lookups by indicator, user, IP, hash, or field value.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| query | string | **Yes** | — | OpenSearch query_string. Include file extensions; quote special chars |
| limit | integer | No | 50 | Max hits. Min 1, max 200 |
| offset | integer | No | 0 | Pagination offset. Min 0, max 10000 |
| sort | string | No | `@timestamp:desc` | Sort as `field:asc\|desc` |
| time_from | string | No | "" | ISO-8601 lower bound on @timestamp (inclusive) |
| time_to | string | No | "" | ISO-8601 upper bound on @timestamp (inclusive) |
| compact | boolean | No | true | True excludes bloat fields and truncates values to 500 chars |
| index | string | No | "" | Index pattern to narrow WITHIN the active case |
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| total | integer | Total matching docs |
| total_capped | boolean | True when total is a lower bound (relation gte) |
| returned | integer | Number of hits in results |
| offset | integer | Echoed pagination offset |
| compact | boolean | Whether compact projection was applied |
| results | SearchHit[] | `{id, index, fields{}, truncated[]}` |
| common_fields | object | Fields identical across every hit |
| full_path | string? | Path to full hit set when results exceeded inline cap |
| advisories | Advisory[] | Field-mapping/empty-result/pagination hints |

**Interacts With:** OpenSearch (read), Postgres (provenance)

**Security Annotations:** Index patterns are scoped to the active case. Cross-case patterns are rejected. Gateway-injected `case_dir` overrides any client-supplied value. Compact mode prevents bloat fields from reaching the agent.

---

### opensearch_count

**Description:** Return an exact match count without documents.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| query | string | No | `*` | query_string filter; default `*` counts all docs in scope |
| index | string | No | "" | Index pattern to narrow within the active case |
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| count | integer | Exact document count for the query in scope |

**Interacts With:** OpenSearch (read)

**Security Annotations:** Index scoped to active case. Cheapest possible probe — one integer, no documents returned.

---

### opensearch_aggregate

**Description:** Group by a field for top-N frequency analysis such as event codes, users, hosts, or process names.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| field | string | **Yes** | — | Field to group by (terms aggregation). CSV/text fields need `.keyword` |
| query | string | No | `*` | query_string filter applied before aggregation |
| limit | integer | No | 50 | Max buckets. Min 1, max 500 |
| index | string | No | "" | Index pattern to narrow within the active case |
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| field | string | Field grouped by this aggregation |
| total_docs | integer | Docs matching query before bucketing |
| buckets | Bucket[] | `{key, count}` — top-N buckets |
| truncated | boolean | True when bucket count hit the limit |
| full_path | string? | Path to full bucket set when it exceeded inline limits |

**Interacts With:** OpenSearch (read)

**Security Annotations:** Index scoped to active case. Returns only bucket counts, never raw documents.

---

### opensearch_get_event

**Description:** Fetch one complete document by _id with every field and no truncation.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| event_id | string | **Yes** | — | Document _id from a search hit |
| index | string | **Yes** | — | Exact case-* index name from the search hit; patterns rejected |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| id | string | Document _id |
| index | string | Concrete index the hit came from |
| fields | object | Full _source fields — no truncation |
| truncated | string[] | Empty array (no truncation on this tool) |
| note | string | Full document fetch confirmation |

**Interacts With:** OpenSearch (read)

**Security Annotations:** Index must be an exact name (not a pattern) starting with `case-`. Single-document lookup only.

---

### opensearch_timeline

**Description:** Build a date histogram of event counts to find activity bursts before drilling in.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| query | string | No | `*` | query_string filter |
| interval | string | No | `1h` | Bucket size: Ns/Nm/Nh/Nd (e.g. 30m, 1h, 1d) |
| time_field | string | No | `@timestamp` | Date field to bucket on |
| time_from | string | No | "" | ISO-8601 lower bound |
| time_to | string | No | "" | ISO-8601 upper bound |
| index | string | No | "" | Index pattern to narrow within the active case |
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| total_docs | integer | Docs matching query before bucketing |
| interval | string | Histogram interval used |
| buckets | TimeBucket[] | `{time (ISO-8601), count}` — sparse date histogram |
| advisories | Advisory[] | Narrowing advisory for very large histograms |

**Interacts With:** OpenSearch (read)

**Security Annotations:** Returns bucket counts only. Buckets are never silently truncated — warned at configured ceiling. Index scoped to active case.

---

### opensearch_field_values

**Description:** Enumerate distinct values of a field with counts before writing targeted queries.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| field | string | **Yes** | — | Field to enumerate. CSV/text fields need `.keyword` |
| query | string | No | `*` | query_string filter to narrow the value set |
| limit | integer | No | 50 | Max distinct values. Min 1, max 500 |
| index | string | No | "" | Index pattern to narrow within the active case |
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| field | string | Field enumerated |
| values | FieldValue[] | `{value, count}` — distinct values with counts |
| truncated | boolean | True when more distinct values exist than returned |
| advisory | string? | Set when field is absent from the index mapping |

**Interacts With:** OpenSearch (read)

**Security Annotations:** Index scoped to active case. Returns value inventory only — no documents.

---

### opensearch_status (DEPRECATED)

**Description:** DEPRECATED tool form; prefer resource `opensearch://cluster/status`. Shows cluster health and per-case-index document counts.

**read_only:** Yes

**Deprecated:** Yes — removal horizon at/after D27b. Resource `opensearch://cluster/status` replaces this tool.

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| cluster_status | string | Cluster health status |
| indices | IndexInfo[] | `{index, docs, size, status}` — active case only |
| total_indices | integer | Number of active-case indices |
| hayabusa | HayabusaHealth? | `{binary?, rules_dir?, rules_count}` — binary=null ⇒ Sigma detection unavailable |

**Interacts With:** OpenSearch (read — cluster health + cat indices)

**Security Annotations:** Index catalog is scoped to the active case (SEC-7). Cluster-wide enumeration is never exposed to the agent. Hayabusa binary path is returned only as a resolved (authorized) path or null.

---

### opensearch_shard_status (DEPRECATED)

**Description:** DEPRECATED tool form; prefer resource `opensearch://cluster/shards`. Reports shard usage and capacity headroom.

**read_only:** Yes

**Deprecated:** Yes — removal horizon at/after D27b. Resource `opensearch://cluster/shards` replaces this tool.

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| case_id | string | No | "" | Case id; empty resolves to active portal case |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| current_shards | integer | Current shard count |
| max_shards_per_node | integer | Configured max shards per data node |
| data_nodes | integer | Number of data nodes |
| max_total | integer | Maximum total shards across data nodes |
| headroom_pct | float | Remaining shard capacity percentage |
| status | string (enum) | `ok` (>=10%), `warning` (>=2%), `critical` (<2%) |
| top_indices_by_shard_count | TopIndexShards[] | Active case only — `{index, primary_shards, replica_shards, doc_count, size?}` |

**Interacts With:** OpenSearch (read — cluster shard stats)

**Security Annotations:** Top indices by shard count are scoped to active case (SEC-7). Cluster capacity fields are cluster-wide.

---

### opensearch_case_summary

**Description:** Complete coverage overview for a case. Call this first in every indexed session.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| case_id | string | No | "" | Case id; empty resolves to active case |
| include_fields | boolean | No | false | Include per-artifact field-type mappings (large output) |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| case_id | string | Resolved case id |
| hosts | string[] | Indexed hosts |
| artifacts | object | Artifact coverage keyed by family — `{family: {docs, hosts[], indices[]}}` |
| total_docs | integer | Total case document count |
| time_range | object | `{earliest, latest}` ISO-8601 |
| enrichment | object | `{triage:{checked,suspicious}, threat_intel:{checked,malicious}}` |
| coverage_state | CoverageState | `{disk_artifacts, memory, enrichment, gaps[], filesystem_meta_path?}` |
| fields_per_type | object? | Optional capped field mappings per artifact type |
| investigation_hints | string[] | Compact investigation hints |
| warnings | string[] | Non-fatal sub-query failures |

**Interacts With:** OpenSearch (read — multiple aggregations across case indices)

**Security Annotations:** Returns only case-scoped metadata. `include_fields=False` by default to keep output compact.

---

### opensearch_inspect_container

**Description:** Survey a forensic container (E01/raw/zip) without mounting it: integrity, size, partitions, acquisition metadata.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| path | string | **Yes** | — | Container path under the active case; bare names resolve to `evidence/` |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| path | string | Original path argument |
| resolved_path | string | Resolved filesystem path |
| container_type | string (enum) | `e01`, `raw`, `file`, or `unknown` |
| tool_available | boolean | False when no inspection tool is available on the SIFT VM |
| size_bytes | integer? | Container size in bytes if known |
| size_human | string? | Human-readable container size |
| hashes | object | Reported hashes |
| partitions | object[] | Detected partitions when available |
| acquiry_info | object? | E01 acquisition metadata from ewfinfo |
| raw_info | string? | Truncated fdisk/img_stat output |
| partition_note | string? | Guidance when no partition table |

**Interacts With:** SIFT VM forensic tools (ewfinfo, fdisk, img_stat)

**Security Annotations:** Read-only — never modifies evidence. Paths are resolved relative to the active case directory. `raw_info` is truncated text output.

---

### opensearch_ingest

**Description:** Preview or run evidence ingest into OpenSearch. `dry_run=True` (default) previews the plan; set `dry_run=False` to write.

**read_only:** No (mutating — indexes evidence into OpenSearch)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| path | string | **Yes** | — | Evidence path under active case; bare names resolve to `evidence/` |
| format | string (enum) | No | `auto` | `auto`, `json`, `delimited`, `accesslog`, `memory` |
| hostname | string | No | "" | Only for formats with no derivable host (json, accesslog). IGNORED for auto/memory/e01 |
| index_suffix | string | No | "" | Optional index suffix |
| time_field | string | No | "" | Optional timestamp field |
| delimiter | string | No | "" | Optional delimiter for delimited input |
| recursive | boolean | No | false | Delimited dirs: treat immediate subdirs as hostnames |
| include | string[] | No | — | Only these artifact types |
| exclude | string[] | No | — | Skip these artifact types |
| source_timezone | string | No | "" | Evidence system local timezone, e.g. `Eastern Standard Time` |
| all_logs | boolean | No | false | Parse all evtx, not only forensic logs |
| reduced_ids | boolean | No | false | Filter to high-value Event IDs |
| full | boolean | No | false | Include all ingest tiers |
| tier | integer | No | 1 | Memory analysis depth: 1 fast, 3 deep |
| plugins | string[] | No | — | Memory: run only these plugins |
| dry_run | boolean | No | true | Preview without indexing by default |
| force | boolean | No | false | Allow intentional re-ingest when case already has docs |
| vss | boolean | No | false | Process Volume Shadow Copies |
| password | string | No | "" | **SECRET** — redacted from audit/logs/results |
| no_hayabusa | boolean | No | false | Skip Hayabusa Sigma scan |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string (enum) | `preview`, `started`, `containers_detected`, `multi_started`, `already_indexed`, `failed`, `queued` |
| case_id | string? | Resolved active case id |
| job_id | string? | Durable job id for worker-dispatched ingest |
| job_type | string? | Dispatched job type (`ingest`/`enrich`) when queued |
| dispatched_to | string? | Worker lane when queued |
| next_step | string? | Operator guidance for queued dispatch |
| plan | object | Preview plan/details |
| container | object? | Detected container details |
| already_indexed | object? | Existing index warning |
| suggested_hostname | string? | Suggested source hostname |
| warning | string? | Non-fatal warning |
| pid | integer? | Background process id (started runs) |
| run_id | string? | Background ingest run id |
| log_file | string? | Background run log file |
| note | string? | Polling or operator note |

**Interacts With:** OpenSearch (write — bulk index), SIFT VM (forensic tool binaries), Postgres (provenance)

**Security Annotations:** Mutating operation scoped to OpenSearch index layer. `password` is a SECRET field — redacted from audit, logs, and results. Host is auto-derived from evidence (registry ComputerName, vol3) — not client-supplied (for disk/memory formats). Disk/E01 ingest returns `status=queued` + `job_id` (dispatched to `sift-opensearch-worker@`); poll `running_commands_status(job_id)` for realtime status.

---

### opensearch_ingest_status

**Description:** Return status for running or recent ingest and enrichment runs.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| case_id | string | No | "" | Filter to this case; default active. `*` for all cases |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| ingests | IngestRun[] | `{case_id?, status, pid?, elapsed, total_indexed, bulk_failed, hosts_complete, hosts_total, artifacts_complete, artifacts_total, log_file, checklist[], message, halt_reason?, errors[], next_steps[], warnings[], details{}}` |
| message | string? | Summary message when no runs present |
| authority | string? | Status authority plane (`postgres-durable-jobs` in DB-active mode) |
| last_completed | object? | OpenSearch-derived summary of last finished ingest |
| job_id | string? | Echoed durable job_id when one was supplied |
| next_step | string? | Suggested next polling step |

**Interacts With:** Postgres (durable job status in DB-active mode), local filesystem (legacy JSON status files)

**Security Annotations:** Returns structured progress summary plus `log_file` reference, never the raw run log. In DB-active mode, ingests are served from Postgres `app.job_status_public`.

---

### opensearch_enrich_intel

**Description:** Extract unique IOCs from indexed docs, optionally look them up in OpenCTI, and stamp matching docs with threat_intel fields.

**read_only:** No (mutating — stamps indexed documents with enrichment results)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| case_id | string | No | "" | Case to enrich; default active |
| dry_run | boolean | No | true | Extract and count IOCs without lookup |
| force | boolean | No | false | Re-enrich already-enriched docs |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string (enum) | `preview`, `started`, `queued` |
| case_id | string? | Resolved case id |
| ips | integer? | Unique IP indicators in preview |
| hashes | integer? | Unique hash indicators in preview |
| domains | integer? | Unique domain indicators in preview |
| total_iocs | integer? | Total unique IOCs in preview |
| job_id | string? | Durable job id for worker-dispatched enrich |
| job_type | string? | Dispatched job type (`enrich`) when queued |
| dispatched_to | string? | Worker lane when queued |
| next_step | string? | Operator guidance for queued dispatch |
| pid | integer? | Background process id |
| run_id | string? | Background run id |
| log_file | string? | Background run log file |
| note | string? | Polling note |

**Interacts With:** OpenSearch (read IOCs + write threat_intel fields), OpenCTI (through gateway callback), Postgres (provenance)

**Security Annotations:** Requires `enrichment:intel` scope (gateway-authoritative). No OpenCTI credentials, OpenSearch passwords, DB DSNs, or service tokens are returned in any response (secret_leak_guarantee). Prohibited operations: approve findings, alter evidence, decide reports. Progress is pollable via `opensearch_ingest_status` with `artifact_name == 'intel'`.

---

### opensearch_fix_host_mapping

**Description:** Correct a wrong host.id mapping in the active case by updating the case host dictionary and reindexing docs where host.name equals raw.

**read_only:** No (mutating — reindexes OpenSearch documents)

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| raw | string | **Yes** | — | The raw host.name value with the wrong mapping |
| new_canonical | string | **Yes** | — | The correct canonical host.id to assign |
| case_dir | string | No | "" | Gateway-injected authoritative case directory |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string (enum) | Always `complete` on success |
| raw | string | Raw host.name value corrected |
| new_canonical | string | Canonical host.id assigned |
| docs_updated | integer? | Documents updated by reindex |
| dict_path | string? | Legacy host dictionary path (non-DB-active mode only) |
| dict_saved | boolean | Whether the host dictionary was saved |
| host_identity_authority | string? | Authority plane (`postgres` in DB-active mode) |
| host_identity_decision_id | string? | DB host-identity correction receipt id |
| audit_id | string? | Audit event id for the correction |
| details | object | Additional behavior-compatible fields |

**Interacts With:** OpenSearch (reindex), Postgres (host identity decisions), local host dictionary

**Security Annotations:** Mutating — updates indexed documents and host-identity derived metadata. Does NOT alter original evidence, cases, findings, or reports. In DB-active mode, the correction is recorded as an authoritative Postgres host-identity receipt; in DB-active mode WITHOUT a receipt recorder, the correction is DENIED (fail closed). Returns no local filesystem paths in DB-active mode. Prohibited operations: approve findings, alter evidence, decide reports.

---

# 6. forensic-rag-mcp (3 tools — stdio proxy)

**Package:** `packages/forensic-rag-mcp/src/rag_mcp/`
**Namespace:** `kb_`
**Transport:** stdio proxy (keep_alive subprocess)
**Source:** `packages/forensic-rag-mcp/src/rag_mcp/server.py`

### kb_search_knowledge

**Description:** Semantic search across the shared IR/DFIR knowledge corpus (Sigma, MITRE ATT&CK, Atomic Red Team, Splunk, KAPE, Velociraptor, LOLBAS, GTFOBins, and more). Returns ranked, provenance-linked results.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| query | string | **Yes** | — | Natural language search query (max 1000 chars). E.g. 'credential dumping detection' |
| top_k | integer | No | 5 | Number of results (max 50; clamped) |
| source | string | No | "" | Filter by source (partial/substring match, e.g. 'sigma', 'mitre') |
| source_ids | string[] | No | — | Filter by exact source IDs (max 20 items). Takes precedence over `source` |
| technique | string | No | "" | Filter by MITRE technique ID (e.g. 'T1003'). Auto-relaxes when corpus not technique-tagged |
| platform | string | No | "" | Filter by platform: `windows`, `linux`, or `macos` |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string | `"ok"` or error |
| query | string | Echoed search query |
| results | object[] | `{distance, content, source, source_id, technique, platform}` — ranked by distance (lower = closer) |
| technique_filter | string? | Present when technique filter auto-relaxed (corpus not technique-tagged) |
| warning | string? | Present when source filter matched nothing |

**Interacts With:** Supabase pgvector (knowledge corpus — `app.rag_search`, kind='knowledge')

**Security Annotations:** Knowledge-only store — no case evidence enters or exits the vector store. No `case_id`, no `include_derived` parameter — derived content is unreachable at SQL level (BATCH-NW4). Output is provenance-linked and PATH-FREE. Input length/size limits prevent DoS.

---

### kb_list_knowledge_sources

**Description:** List all available knowledge sources in the corpus.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| *(none)* | | | | No input parameters. |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string | `"ok"` or error |
| sources | string[] | Distinct knowledge source labels |
| count | integer | Number of sources |

**Interacts With:** Supabase pgvector (knowledge corpus source enumeration)

**Security Annotations:** Returns source labels only — no content, no case data.

---

### kb_get_knowledge_stats

**Description:** Get knowledge corpus statistics and backend health.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| *(none)* | | | | No input parameters. |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string | `"ok"` or error |
| chunk_count | integer | Number of embedded chunks |
| document_count | integer | Number of documents |
| collection_count | integer | Number of collections |
| source_count | integer | Number of distinct sources |
| embedding_dim | integer | Embedding vector dimension |
| embedding_model | string | Embedding model name |

**Interacts With:** Supabase pgvector (knowledge corpus statistics)

**Security Annotations:** Statistics and model contract only — no content, no case data. Also serves as the backend health probe.

---

# 7. opencti-mcp (8 tools — stdio proxy)

**Package:** `packages/opencti-mcp/src/opencti_mcp/`
**Namespace:** `cti_`
**Transport:** stdio proxy (keep_alive subprocess)
**Source:** `packages/opencti-mcp/src/opencti_mcp/registry.py`

### cti_get_health (LEGACY/DEPRECATED)

**Description:** Check OpenCTI connectivity and API health before relying on CTI lookups. Deprecated tool-form alias for the `cti://health` resource for one cutover cycle.

**read_only:** Yes

**Deprecated:** Yes — resource `cti://health` replaces this tool form for one cutover cycle.

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| *(none)* | | | | No input parameters. |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| status | string (enum) | `healthy` or `unavailable` |
| opencti_available | boolean | True when the OpenCTI API answered the health probe |

**Interacts With:** OpenCTI GraphQL API (read-only health probe)

**Security Annotations:** Requires `cti:read` scope. Health probe only — no data retrieved.

---

### cti_search_threat_intel

**Description:** Broad search across all OpenCTI entity types: indicators, actors, malware, techniques, CVEs, reports, and related CTI records.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| query | string | **Yes** | — | Search term (1-1000 chars): IOC, actor, malware, CVE, campaign, or other CTI keyword |
| limit | integer | No | 5 | Max results per entity type. Min 1, max 20 |
| offset | integer | No | 0 | Pagination offset. Min 0, max 500 |
| labels | string[] | No | — | Filter by labels, e.g. `['tlp:amber', 'malicious']` |
| confidence_min | integer | No | — | Minimum confidence threshold (0-100) |
| created_after | string | No | — | ISO-8601 lower bound for entity creation date |
| created_before | string | No | — | ISO-8601 upper bound for entity creation date |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| query | string | Echoed search term |
| results_by_type | object | Entities grouped by entity type — `{entity_type: CtiEntity[]}` |
| total | integer | Total returned entities across all groups |
| offset | integer | Echoed pagination offset |

**Interacts With:** OpenCTI GraphQL API (read — `unified_search`)

**Security Annotations:** Requires `cti:read` scope. Broad discovery — do not use as attribution without corroborating case artifacts.

---

### cti_search_entity

**Description:** Search one OpenCTI entity type with a higher per-type cap than broad search.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| type | string (enum) | **Yes** | — | One of 16 entity types: `threat_actor`, `malware`, `attack_pattern`, `vulnerability`, `campaign`, `tool`, `infrastructure`, `incident`, `observable`, `sighting`, `organization`, `sector`, `location`, `course_of_action`, `grouping`, `note` |
| query | string | **Yes** | — | Search term (1-1000 chars) |
| limit | integer | No | 10 | Max results. Min 1, max 50 |
| offset | integer | No | 0 | Pagination offset. Min 0, max 500 |
| labels | string[] | No | — | Filter by labels |
| confidence_min | integer | No | — | Minimum confidence threshold (0-100) — only for types that support it |
| created_after | string | No | — | ISO-8601 lower bound |
| created_before | string | No | — | ISO-8601 upper bound |
| observable_types | string[] | No | — | Only for `type='observable'`: restrict to OpenCTI observable subtypes |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| type | string (enum) | Entity type searched |
| results | CtiEntity[] | Matching OpenCTI entities |
| total | integer | Number of returned entities |
| offset | integer | Echoed pagination offset |

**Interacts With:** OpenCTI GraphQL API (read — type-specific search methods)

**Security Annotations:** Requires `cti:read` scope. Focused single-type search — not all types support all filters (offset unsupported for sighting/organization/sector/location/course_of_action/grouping/note).

---

### cti_lookup_ioc

**Description:** Look up one observed IOC and return OpenCTI context: matched indicator or observable plus related actors, malware, techniques, and campaigns.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| ioc | string | **Yes** | — | IOC value (1-1000 chars): IP, MD5/SHA1/SHA256 hash, domain, URL, CVE, or MITRE ATT&CK id |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| ioc | string | Echoed IOC value |
| ioc_type | string? | Detected IOC type: `ipv4`, `ipv6`, hash type, `domain`, `url`, `cve`, `mitre`, or `unknown` |
| found | boolean | True when OpenCTI returned indicator or observable context |
| indicator | CtiEntity? | Matched indicator or observable |
| related_threat_actors | CtiEntity[] | Related actors |
| related_malware | CtiEntity[] | Related malware |
| related_techniques | CtiEntity[] | Related MITRE techniques/attack patterns |
| related_campaigns | CtiEntity[] | Related campaigns |

**Interacts With:** OpenCTI GraphQL API (read — `get_indicator_context`)

**Security Annotations:** Requires `cti:read` scope. Use only for IOCs extracted from case evidence — not for speculative indicators not observed in evidence.

---

### cti_get_recent_indicators

**Description:** Return recently added OpenCTI indicators from a bounded look-back window.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| days | integer | No | 7 | Look-back window in days. Min 1, max 90 |
| limit | integer | No | 20 | Maximum recent indicators. Min 1, max 100 |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| days | integer | Echoed look-back window |
| results | CtiEntity[] | Recently created OpenCTI indicators |
| total | integer | Number of indicators returned |

**Interacts With:** OpenCTI GraphQL API (read — `get_recent_indicators`)

**Security Annotations:** Requires `cti:read` scope. Do not bulk-pivot on recent indicators without a case-specific hypothesis.

---

### cti_get_entity

**Description:** Return full details for one OpenCTI entity UUID, including projected common fields and type-specific extras.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| entity_id | string | **Yes** | — | OpenCTI entity UUID from a search result; validated before dispatch |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| found | boolean | True when the entity id exists in OpenCTI |
| entity_id | string | Echoed entity UUID |
| entity | CtiEntity? | Projected entity details, or null when not found |

**Interacts With:** OpenCTI GraphQL API (read — `get_entity`)

**Security Annotations:** Requires `cti:read` scope. Entity_id is validated as UUID before dispatch.

---

### cti_get_relationships

**Description:** Return relationships for an OpenCTI entity: who uses it, what it indicates, what it targets, and adjacent context.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| entity_id | string | **Yes** | — | OpenCTI entity UUID to expand |
| direction | string (enum) | No | `both` | Relationship direction: `from` (outgoing), `to` (incoming), `both` |
| relationship_types | string[] | No | — | Optional filter, e.g. `['indicates', 'uses', 'targets']` |
| limit | integer | No | 50 | Maximum relationships. Min 1, max 50 |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| entity_id | string | Echoed entity UUID |
| relationships | CtiRelationship[] | `{id?, relationship_type?, source?, target?, direction?}` |
| total | integer | Number of relationships returned |

**Interacts With:** OpenCTI GraphQL API (read — `get_relationships`)

**Security Annotations:** Requires `cti:read` scope. Entity_id validated as UUID. Relationship types validated against known types.

---

### cti_search_reports

**Description:** Search threat-intel reports by keyword.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| query | string | **Yes** | — | Report search term (1-1000 chars): campaign, actor, malware, CVE, or technique |
| limit | integer | No | 10 | Maximum reports. Min 1, max 50 |
| offset | integer | No | 0 | Pagination offset. Min 0, max 500 |
| labels | string[] | No | — | Filter by labels |
| confidence_min | integer | No | — | Minimum confidence threshold (0-100) |
| created_after | string | No | — | ISO-8601 lower bound |
| created_before | string | No | — | ISO-8601 upper bound |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| results | CtiReport[] | `{id?, name?, published?, description?, labels[], confidence?, object_refs[]}` |
| total | integer | Number of reports returned |
| offset | integer | Echoed pagination offset |

**Interacts With:** OpenCTI GraphQL API (read — `search_reports`)

**Security Annotations:** Requires `cti:read` scope. Report content is analytical narrative — treat as context only and tie conclusions back to case artifacts.

---

# 8. windows-triage-mcp (6 tools — stdio proxy)

**Package:** `packages/windows-triage-mcp/src/windows_triage_mcp/`
**Namespace:** `wintriage_`
**Transport:** stdio proxy (keep_alive subprocess)
**Source:** `packages/windows-triage-mcp/src/windows_triage_mcp/registry.py`

### wintriage_check_artifact

**Description:** Validate one Windows artifact against local offline baselines. Supports five artifact types: file, hash, filename, lolbin, dll.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| type | string (enum) | **Yes** | — | Artifact type: `file` (path + optional hash), `hash` (vulnerable-driver lookup), `filename` (deception heuristics), `lolbin` (LOLBin context), `dll` (hijackability) |
| value | string | **Yes** | — | `file`=Windows path; `hash`=MD5/SHA1/SHA256; `filename`=filename; `lolbin`=exe WITH extension (e.g. `certutil.exe`); `dll`=DLL name. Max 4096 chars |
| hash | string | No | — | Optional file hash when `type='file'` (baseline mismatch check). Max 128 chars |
| os_version | string | No | — | Optional OS filter for `type='file'` (e.g. `Win10_21H2_Pro`). Max 256 chars |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| verdict | string (enum) | `EXPECTED`, `EXPECTED_LOLBIN`, `SUSPICIOUS`, `UNKNOWN`, `ERROR` |
| reasons | string[] | Why this verdict was assigned |
| confidence | string (enum) | `high`, `medium`, `low` |
| findings | Finding[] | `{type, severity (critical/high/medium/low), description, extra{}}` |
| artifact_type | string (enum) | Artifact subtype checked |
| path_in_baseline | boolean? | For `type='file'`: exact path exists in baseline |
| filename_in_baseline | boolean? | For `type='file'`: filename exists anywhere in baseline |
| is_system_path | boolean? | For `type='file'`: path is under Windows system directory |
| is_lolbin | boolean | True when filename is a known LOLBin |
| lolbin_functions | string[] | LOLBAS abuse functions when known |
| subtype_data | object | Type-specific fields (vulnerable_driver, algorithm, hash, etc.) |

**Interacts With:** Local SQLite databases (known_good.db, context.db — offline baselines)

**Security Annotations:** Read-only offline baseline comparison. Null bytes rejected in all string inputs. UNKNOWN is neutral — not in local DB, not evidence of malice. For hash/IOC reputation use `cti_lookup_ioc` instead.

---

### wintriage_check_process_tree

**Description:** Validate a parent-to-child Windows process relationship against the local process-tree baseline.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| process_name | string | **Yes** | — | Child process name (e.g. `cmd.exe`). Max 4096 chars |
| parent_name | string | **Yes** | — | Parent process name (e.g. `winword.exe`). Max 4096 chars |
| path | string | No | — | Optional executable path for tighter matching. Max 4096 chars |
| user | string | No | — | Optional user context (SYSTEM vs user). Max 256 chars |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| verdict | string (enum) | `EXPECTED`, `SUSPICIOUS`, `UNKNOWN`, `ERROR` |
| reasons | string[] | Why this verdict was assigned |
| confidence | string (enum) | `high`, `medium`, `low` |
| findings | Finding[] | Suspicious or contextual findings |
| in_expectations_db | boolean | True when child process exists in local expectations DB |
| expected_parents | string[] | Known-good parent process names for this child |
| suspicious_parents | string[] | Known suspicious parent names for this child |
| user_context | object? | User-context validation details when user was provided |

**Interacts With:** Local SQLite database (known_good.db — process tree baseline)

**Security Annotations:** Read-only offline baseline comparison. Null bytes rejected. UNKNOWN is neutral — not in local expectations DB.

---

### wintriage_check_system

**Description:** Validate Windows persistence and system configuration against OS-version baselines: services, scheduled tasks, or autoruns.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| type | string (enum) | **Yes** | — | System check type: `service`, `scheduled_task`, or `autorun` |
| name | string | **Yes** | — | Service name, scheduled-task path, or autorun registry key path. Max 1024 chars |
| binary_path | string | No | — | Optional service binary path (`type='service'`). Max 4096 chars |
| value_name | string | No | — | Optional registry value name (`type='autorun'`). Max 256 chars |
| os_version | string | **Yes** | — | Target OS (e.g. `Win10_21H2_Pro`, `W11_22H2`, `Server2022`). REQUIRED because baselines vary by release. Max 256 chars |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| verdict | string (enum) | `EXPECTED`, `SUSPICIOUS`, `UNKNOWN`, `ERROR` |
| reasons | string[] | Why this verdict was assigned |
| confidence | string (enum) | `high`, `medium`, `low` |
| findings | Finding[] | Suspicious or contextual findings |
| system_type | string (enum) | System artifact subtype checked |
| in_baseline | boolean? | True when the service/task/autorun is present in baseline |
| baseline_info | object? | Baseline service metadata when available |
| os_versions | string[] | OS versions associated with the match |
| hive | string? | Autorun hive for matching entries |
| task_name | string? | Scheduled task display name |
| lookup_performed | boolean | False only when validation prevented a baseline lookup |

**Interacts With:** Local SQLite database (known_good.db — system/scheduled tasks/autorun baselines)

**Security Annotations:** Read-only offline baseline comparison. `os_version` is REQUIRED. Null bytes rejected. UNKNOWN is neutral unless concrete suspicious findings are present.

---

### wintriage_check_registry

**Description:** Check a registry key or value against the full Windows registry baseline. Requires the optional large `known_good_registry.db`.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| key_path | string | **Yes** | — | Registry key path (e.g. `SOFTWARE\Microsoft\Windows\CurrentVersion`). Max 1024 chars |
| value_name | string | No | — | Optional specific value name. Max 256 chars |
| hive | string (enum) | No | — | Optional registry hive: `SYSTEM`, `SOFTWARE`, `NTUSER`, `DEFAULT` |
| os_version | string | No | — | Optional OS-version filter. Max 256 chars |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| verdict | string (enum) | `EXPECTED`, `SUSPICIOUS`, `UNKNOWN`, `ERROR` |
| reasons | string[] | Why this verdict was assigned |
| confidence | string (enum) | `high`, `medium`, `low` |
| findings | Finding[] | Suspicious or contextual findings |
| in_baseline | boolean | True when the key/value exists in the registry baseline |
| os_versions | string[] | Up to 10 OS versions associated with matching entries |
| os_version_count | integer? | Total OS-version count before capping |
| match_count | integer? | Total matching registry rows before capping |
| values | RegistryValueSummary[] | Up to 10 matching values as `{name?, type?, hive?}` |
| value_count | integer? | Total value count before capping |

**Interacts With:** Local SQLite database (known_good_registry.db — optional, ~12GB)

**Security Annotations:** Read-only offline baseline comparison. Requires optional `known_good_registry.db` — returns `upstream_degraded` with guidance when unavailable. Null bytes rejected. UNKNOWN is neutral — for autorun persistence checks, prefer `wintriage_check_system(type='autorun')`.

---

### wintriage_check_pipe

**Description:** Check a named pipe against known Windows pipes and known C2 pipe patterns such as Cobalt Strike or Metasploit.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| pipe_name | string | **Yes** | — | Named pipe (with or without `\\.\pipe\` prefix; normalized before lookup). Max 256 chars |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| verdict | string (enum) | `EXPECTED`, `SUSPICIOUS`, `UNKNOWN`, `ERROR` |
| is_suspicious | boolean | True when the pipe matches a known C2 pipe pattern |
| is_windows_pipe | boolean | True when the pipe is a known standard Windows pipe |
| tool_name | string? | C2 tool or framework name for suspicious matches |
| malware_family | string? | Malware family associated with suspicious matches |
| description | string? | Pipe context from the local baseline database |
| protocol | string? | Windows protocol associated with expected pipe matches |
| service_name | string? | Windows service associated with expected pipe matches |

**Interacts With:** Local SQLite databases (known_good.db + context.db — pipe baselines + C2 patterns)

**Security Annotations:** Read-only offline baseline comparison. Null bytes rejected. SUSPICIOUS = known C2-pattern match; EXPECTED = standard Windows pipe; UNKNOWN = neither catalog matches.

---

### wintriage_server_status

**Description:** Report Windows triage backend readiness.

**read_only:** Yes

**Input Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| resource | string (enum) | No | `health` | `health`=connectivity/cache; `db_stats`=baseline coverage counts; `all`=both |

**Output Shape:**

| Field | Type | Description |
|---|---|---|
| resource | string (enum) | Status resource returned |
| health | WintriageHealth? | `{status (healthy/degraded), uptime_seconds, databases{}, cache{}, config{}}` |
| db_stats | WintriageDbStats? | `{known_good_db{}, context_db{}, registry_db{}}` coverage counts |

**Interacts With:** Local SQLite databases (health check), in-memory cache

**Security Annotations:** Read-only backend status. No case data returned. No secrets in config summary.
