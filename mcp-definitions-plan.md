# MCP Context & Tool Definition Optimization Plan

## Purpose

The current MCP instruction set was carried over from the old Valhuntir repo. It
references removed components, dead external services, and contains redundancy across
the three layers where context is injected. This document inventories every context
injection point, identifies what is stale or contradictory, and defines the
optimization work needed to make the system structured, resilient, and guiding
rather than non-deterministic.

---

## Part 1 — Context Injection Map (All Paths)

There are **four layers** where context reaches the AI agent.

### Layer 1 — Gateway aggregate instructions

Injected at MCP `Initialize` response. Seen by every client connecting to `/mcp`.

| File | Constant | Registration site |
|------|----------|-------------------|
| `packages/sift-common/src/sift_common/instructions.py` | `GATEWAY` | `packages/sift-gateway/src/sift_gateway/mcp_endpoint.py:378` → `Server("sift-gateway", instructions=_GATEWAY_INSTRUCTIONS)` |

### Layer 2 — Per-backend instructions (gateway override map)

Injected when the gateway serves a per-backend diagnostic endpoint or initializes
the backend sub-server. The gateway overrides backend self-declared instructions
with this map so the gateway controls the canonical text.

| Constant | Backend key | Override site |
|----------|-------------|---------------|
| `FORENSIC_MCP` | `forensic-mcp` | `mcp_endpoint.py:57` `_BACKEND_INSTRUCTIONS` dict |
| `SIFT_MCP` | `sift-mcp` | same map |
| `CASE_MCP` | `case-mcp` | same map |
| `REPORT_MCP` | `report-mcp` | same map |
| `FORENSIC_RAG` | `forensic-rag-mcp` | same map |
| `WINDOWS_TRIAGE` | `windows-triage-mcp` | same map |
| `OPENCTI` | `opencti-mcp` | same map |
| `OPENSEARCH` | `opensearch-mcp` | same map |

All constants live in `packages/sift-common/src/sift_common/instructions.py`.

### Layer 3 — Backend self-declared instructions (FastMCP / Server init)

Each backend also passes its own instructions when it creates its server object.
Under the aggregate gateway these are **overridden** by Layer 2. They only matter
when a backend is run standalone for diagnostics.

| Backend | File | Registration |
|---------|------|--------------|
| forensic-mcp | `packages/forensic-mcp/src/forensic_mcp/server.py:117` | `FastMCP("forensic-mcp", instructions=FORENSIC_MCP)` |
| case-mcp | `packages/case-mcp/src/case_mcp/server.py:153` | `FastMCP("case-mcp", instructions=CASE_MCP)` |
| sift-mcp | `packages/sift-mcp/src/sift_mcp/server.py:66` | `FastMCP("sift-mcp", instructions=SIFT_MCP)` |
| report-mcp | `packages/report-mcp/src/report_mcp/server.py:756` | `FastMCP("report-mcp", instructions=REPORT_MCP)` |
| forensic-rag-mcp | `packages/forensic-rag-mcp/src/rag_mcp/server.py:68` | `FastMCP("forensic-rag-mcp", instructions=FORENSIC_RAG)` |
| opencti-mcp | `packages/opencti-mcp/src/opencti_mcp/server.py:142` | `Server("opencti-mcp", instructions=OPENCTI)` |
| windows-triage-mcp | `packages/windows-triage-mcp/src/windows_triage_mcp/server.py:153` | `Server("windows-triage", instructions=WINDOWS_TRIAGE)` |
| **opensearch-mcp** | `packages/opensearch-mcp/src/opensearch_mcp/server.py:47` | `FastMCP("opensearch-mcp")` — **NO instructions= parameter** |

> opensearch-mcp is the only backend with no self-declared instructions. It gets
> context exclusively from the gateway Layer 2 map. If ever run standalone it presents
> with no instructions.

### Layer 4 — Tool-level descriptions (docstrings / MCP tool schema)

Each tool's first docstring line becomes the `description` field in `tools/list`.
This is what the agent reads when deciding which tool to call. Longer docstrings
become the `inputSchema.description`.

| Backend | Tool registration pattern | Where docstrings live |
|---------|---------------------------|-----------------------|
| opensearch-mcp | `@server.tool()` decorator on module-level functions | `server.py` function docstrings |
| forensic-mcp | `@server.tool()` inside `create_server()` closure | `server.py` nested function docstrings |
| case-mcp | `@server.tool()` inside `create_server()` closure | `server.py` nested function docstrings |
| sift-mcp | `@server.tool()` on methods of `SiftMCPServer` | `server.py` method docstrings |
| report-mcp | `@server.tool()` inside `create_server()` closure | `server.py` nested function docstrings |
| forensic-rag-mcp | `@mcp.tool()` inside `RAGServer` class | `server.py` method docstrings |
| opencti-mcp | Low-level `Server`, tools registered via `list_tools()` + `call_tool()` | Inline `description=` strings in `list_tools` handler |
| windows-triage-mcp | Low-level `Server`, same pattern | Inline `description=` strings in `list_tools` handler |

---

## Part 2 — Tool Inventory

### Live tool availability (verified via list_available_tools 2026-05-29)

**Available on VM:**
grep, awk, sed, cut, sort, uniq, wc, head, tail, tr, diff, jq, zcat, zgrep, tar, unzip,
file, stat, find, ls, md5sum, sha1sum, sha256sum, xxd, hexdump, readelf, objdump,
bulk_extractor, strings, ssdeep, exiftool, regripper (rip.pl), hashdeep, 7z, dc3dd,
ewfacquire, ewfmount, vshadowinfo, vshadowmount, fls, icat, mmls, blkls, hayabusa,
log2timeline.py, mactime, psort.py, vol, AmcacheParser, AppCompatCacheParser, RECmd,
MFTECmd, EvtxECmd, JLECmd, LECmd, SBECmd, RBCmd, SQLECmd, bstrings, zeek

**NOT available (not installed):**
- `PECmd` 
- `SrumECmd` 


**TODO — install.sh: add missing tool installation**
The hardened installer (`install.sh`) must provision these tools so fresh SIFT VM
deployments are complete. Add an idempotent block (check binary exists before installing):

| Tool | Install method | Priority |
|------|---------------|----------|
| `yara` | `sudo apt install -y yara` | High — referenced in coverage gaps |
| `tshark` | `sudo apt install -y tshark` | Medium — PCAP analysis |
| `binwalk` | `sudo apt install -y binwalk` | Low — firmware only |
| `PECmd` | Zimmerman via dotnet + GitHub release | Medium — Prefetch primary parser |
| `SrumECmd` | Zimmerman via dotnet + GitHub release | Medium — SRUM primary parser |
| `zeek` | PPA: `zeek/zeek` on Ubuntu — complex | Low — only if PCAP workflow added |

Pattern for install.sh (idempotent):
```bash
if ! command -v yara &>/dev/null; then
    echo "[install] Installing yara..."
    sudo apt install -y yara
else
    echo "[install] yara already installed: $(yara --version)"
fi
```
Zimmerman tools (PECmd, SrumECmd) follow the existing pattern in install.sh where
other Zimmerman binaries are downloaded from GitHub releases and placed in
`/usr/local/bin/`. Check if that pattern exists for these two and add if missing.

**Notable confirmed-available:**
- `SQLECmd` — browser artifact parsing via SQLite IS viable. Update browser coverage note.
- `bulk_extractor` — carving IS available.
- `vol` (Volatility 3) — memory analysis confirmed.

### Complete tool list per backend (as of 2026-05-29)

**forensic-mcp** — 6 tools exposed
```
record_finding, record_timeline_event, list_existing_findings,
query_case, workflow_status, manage_todo
```
Also registers 14 MCP **resources** (not tools): `investigation-framework`, `rules`,
`checkpoint/{action_type}`, `validation-schema`, `evidence-standards`,
`confidence-definitions`, `anti-patterns`, `evidence-template`,
`tool-guidance/{tool_name}`, `false-positive-context/{tool_name}/{finding_type}`,
`corroboration/{finding_type}`, `playbooks`, `playbook/{name}`,
`collection-checklist/{artifact_type}`

**case-mcp** — 10 tools exposed
```
case_status, case_file_structure, evidence_register (portal-blocked),
evidence_list, evidence_verify, export_bundle, import_bundle,
record_action, log_reasoning, log_external_action
```

**sift-mcp** — 5 tools exposed
```
list_available_tools, get_tool_help, check_tools, suggest_tools, run_command
```

**report-mcp** — 6 tools exposed
```
generate_report, set_case_metadata, get_case_metadata,
list_profiles, save_report, list_reports
```

**opensearch-mcp** — 16 tools exposed
```
idx_search, idx_count, idx_aggregate, idx_get_event, idx_timeline,
idx_field_values, idx_status, idx_shard_status, idx_case_summary,
idx_inspect_container, idx_ingest, idx_ingest_status,
idx_enrich_intel, idx_enrich_triage, idx_list_detections, case_host_fix
```

**forensic-rag-mcp** — 3 tools exposed
```
search_knowledge, list_knowledge_sources, get_knowledge_stats
```

**opencti-mcp** — 8 tools exposed
```
get_health, search_threat_intel, search_entity, lookup_ioc,
get_recent_indicators, get_entity, get_relationships, search_reports
```

**windows-triage-mcp** — 6 tools exposed via gateway
```
check_artifact, check_process_tree, check_system,
check_registry, check_pipe, server_status
```
`check_artifact` accepts `type` field: `file | hash | filename | lolbin | dll` — all
former separate tools (check_file, check_hash, check_lolbin, check_hijackable_dll) are
consolidated here. `check_system` accepts `type`: `service | scheduled_task | autorun`.
No unexposed tools — the schema is the interface.

**Total: 60 tools**

---

## Part 3 — Stale / Incorrect / Missing Context

### 3.1 Wrong product name
`FORENSIC_MCP`, `SIFT_MCP`, `WINTOOLS_MCP`, `GATEWAY`, `CASE_MCP`, `REPORT_MCP`,
and `report-mcp/server.py:1` all say "Valhuntir". The product is now **agentir / sift-mcps**.

### 3.2 Dead constant — `WINTOOLS_MCP`
`WINTOOLS_MCP` is defined in `instructions.py` but the `wintools-mcp` package was
removed. The constant is not referenced anywhere in the gateway or any active backend.
Delete it.

### 3.3 Dead external reference — Zeltser HTTP MCP
`REPORT_MCP` says: *"Use Zeltser IR Writing MCP tools as guided by the zeltser_guidance
section in generate_report output."*
The Zeltser MCP HTTP server is **not configured** in this runtime. The `generate_report`
tool does emit a `zeltser_guidance` key in its response, but that points to an HTTP
service that does not exist. The instruction is misleading.

### 3.4 Dead external reference — REMnux MCP
`FORENSIC_MCP` investigation startup step 4b says:
*"upload_from_host on REMnux (remnux-mcp connects directly to the client...)"*
REMnux is not part of this stack. Remove.

### 3.5 `list_playbooks` instruction present and tool exists — but poorly routed
`FORENSIC_MCP` startup step 6 says *"Use list_playbooks for investigation procedures."*
`list_playbooks` **is** a real tool in forensic-mcp. But it is a resource-style tool that
returns YAML playbook content. The instruction should specify when to call it and that
playbooks are on-demand reference, not a required startup step.

### 3.6 `forensic-mcp` resources — on-demand, agent must be told they exist
14 MCP resources registered. They are **not auto-injected** — the agent must explicitly
fetch them by URI. They are valuable discipline reference content (playbooks, corroboration
guides, false-positive context, confidence definitions). The agent has no way to know
they exist unless `FORENSIC_MCP` instructions mention them.

Resources worth surfacing to agent (add to FORENSIC_MCP):
- `forensic-mcp://playbooks` + `forensic-mcp://playbook/{name}` — step-by-step investigation procedures
- `forensic-mcp://corroboration/{finding_type}` — what artifacts to cross-reference for a given finding
- `forensic-mcp://false-positive-context/{tool_name}/{finding_type}` — before recording a finding, check this
- `forensic-mcp://tool-guidance/{tool_name}` — result interpretation per tool

Resources that duplicate FORENSIC_MCP instruction string content (do NOT re-add to instructions):
- `forensic-mcp://anti-patterns` — already covered in FORENSIC_MCP ANTI-PATTERNS section
- `forensic-mcp://evidence-standards` — already covered in EVIDENCE STANDARDS section
- `forensic-mcp://confidence-definitions` — already covered in CONFIDENCE LEVELS section

Candidate for promotion to a real tool: `corroboration/{finding_type}` — agents frequently
need "what else should I check?" guidance mid-investigation and the resource URI is awkward
to call. A `get_corroboration_suggestions(finding_type)` tool would be more natural.

### 3.7 `opensearch-mcp` has no self-declared instructions
If ever run standalone (debugging, testing), it presents with zero instructions. Add
`instructions=OPENSEARCH` to `FastMCP("opensearch-mcp")` at `server.py:47`.

### 3.8 `OPENSEARCH` instruction — investigation workflow is incomplete
Current text mentions the 5-step query workflow but does not cover:
- New `coverage_state` field in `idx_case_summary` (added 2026-05-27)
- `filesystem_meta_path` in ingest response (added 2026-05-29)
- `idx_ingest_memory` and its `tier` parameter
- `idx_list_detections` (Sigma hits)
- `case_host_fix` tool (what it does and when)

### 3.9 `SIFT_MCP` — YARA now installed, add proper usage guidance
**YARA 4.5.0 installed 2026-05-29** (`/usr/bin/yara`, `available: true`).
Write real YARA usage guidance in SIFT_MCP (see Phase B6 below). Key constraints:
- Only run after `idx_enrich_intel` confirms hits or a specific malware family is known
- Never run community rules automatically — noisy hits corrupt findings
- Output always to `agent/yara/` — never inline
- Hits recorded as SPECULATIVE pending corroboration

### 3.10 `GATEWAY` — no output cap / auto-save convention, idx detail misplaced
No instruction tells the agent that large tool outputs are auto-saved to `agent/` and
that it should grep/search rather than consume raw output. Each tool currently handles
this ad-hoc. A gateway-level convention would make it consistent.

Additionally, `GATEWAY` currently lists idx tools inline:
`"Evidence indexing — idx_ingest, idx_search, idx_aggregate, idx_timeline, idx_case_summary, idx_enrich_triage, idx_enrich_intel (via opensearch-mcp)."`
This is redundant with the full `OPENSEARCH` workflow block. Decision: **GATEWAY stays
as a routing map only** (which backend owns which tool group). The full idx investigation
workflow belongs exclusively in `OPENSEARCH`. No duplication.

### 3.11 Tool docstrings — quality varies widely
- `idx_ingest`: no examples, parameter list but no format guidance
- `idx_search`: minimal, no example query syntax
- `run_command`: good parameter docs but no output limit guidance
- `record_finding`: good
- `generate_report`: good
- `idx_case_summary`: good (was improved recently)
- Many tools: no "when to call this vs that" disambiguation

---

## Part 4 — Optimization Plan

### Phase A — Cleanup (no behavior change, high signal/noise improvement)

**A1. Rename all "Valhuntir" → "agentir" in instructions.py**
File: `sift_common/instructions.py`
All `FORENSIC_MCP`, `SIFT_MCP`, `GATEWAY`, `CASE_MCP`, `REPORT_MCP` strings.
Also `report-mcp/server.py:1` module docstring.

**A2. Delete `WINTOOLS_MCP` constant**
File: `sift_common/instructions.py`
It is unreferenced. Delete the block.

**A3. Remove REMnux reference from `FORENSIC_MCP`**
File: `sift_common/instructions.py` — step 4b of INVESTIGATION STARTUP.
Replace with: tool inventory is via `suggest_tools` on sift-mcp for each artifact type.

**A4. Fix Zeltser reference in `REPORT_MCP`**
Change to: *"generate_report returns a zeltser_guidance key with IR writing prompts.
Use these to structure narrative sections. No external Zeltser MCP is required."*

**A5. Add `instructions=OPENSEARCH` to opensearch-mcp FastMCP init**
File: `packages/opensearch-mcp/src/opensearch_mcp/server.py:47`
`server = FastMCP("opensearch-mcp")` → `server = FastMCP("opensearch-mcp", instructions=OPENSEARCH)`

### Phase B — Update `OPENSEARCH` and `GATEWAY` for new capabilities

**B1. Add `coverage_state` and `filesystem_meta_path` to `OPENSEARCH`**
```
idx_case_summary returns coverage_state with: disk_artifacts (indexed/not_run/not_available
per artifact type), memory (tier_run, plugins_run, plugins_not_run), enrichment state, gaps
(structured run_command recipes for missing coverage), and filesystem_meta_path (path to
partition/filesystem sidecar written at ingest time, null if not collected).
Call idx_case_summary first in every indexed session — it tells you exactly what ran and
what gaps remain.
```

**B2. Add `idx_ingest_memory` tier guidance to `OPENSEARCH`**
```
idx_ingest_memory(path, hostname, tier=1) indexes Volatility 3 memory plugins.
Tier 1 (default): pslist, psscan, pstree, cmdline, netstat, netscan, svcscan, modules,
registry.hivelist, windows.info — always run first.
Tier 2: dlllist, envars, getsids, handles, filescan — run after suspicious PIDs identified.
Tier 3: malfind, vadinfo, dumpfiles — targeted, high cost, high noise.
```

**B3. Add `case_host_fix` to `OPENSEARCH`**
```
case_host_fix(case_id, old_hostname, new_hostname): renames the host label across all
indexed documents for a case. Use when evidence was ingested with the wrong hostname.
Run before any analysis that cross-references host.name.
```

**B4. Add `idx_list_detections` to `OPENSEARCH`**
```
idx_list_detections(case_id): returns Hayabusa sigma rule hits grouped by severity and
rule name. Call after idx_enrich_triage to see what Hayabusa flagged. High/critical
hits become investigation pivot points — look for matching process names in vol-pslist
and vol-psscan via the hayabusa_corroboration field.
```

**B5. Add output cap + auto-save convention to `GATEWAY`**
```
OUTPUT CAP: Large tool outputs (run_command, idx_search with many hits, Volatility results)
are automatically saved to agent/ under the active case directory. Tool responses return
a file path, a summary, and key counts — not raw content. Use run_command with
save_output=true to write to agent/commands/<filename>. Then use run_command(['grep', ...])
or idx_search to target specific content. Never paste full tool output into reasoning.
```

**B6. Add YARA usage guidance to `SIFT_MCP`**
```
YARA SWEEPS: yara 4.5.0 is installed (/usr/bin/yara). Run YARA only after
idx_enrich_intel has confirmed threat intel hits, or when a specific malware
family/hash is known. Never run community rule sets automatically — noisy false
positives corrupt findings.
Step 1: run_command(['yara', '-r', '-s', 'rules.yar', 'evidence/'],
  save_output=True, output_path='agent/yara/ioc_sweep.txt')
Step 2: report only matching rule name, hit file path, and byte offset — never
  paste full yara output inline.
Step 3: record hits as SPECULATIVE findings pending corroboration from a second
  independent artifact.
Output always goes to agent/yara/ — never rendered inline.
```

**B7. Add forensic-mcp resource awareness to `FORENSIC_MCP`**
```
REFERENCE RESOURCES: forensic-mcp exposes discipline reference content as fetchable
resources. Before recording a finding, fetch:
  forensic-mcp://corroboration/{finding_type} — what artifacts to cross-reference.
  forensic-mcp://false-positive-context/{tool_name}/{finding_type} — common false positives.
  forensic-mcp://playbooks — list available investigation playbooks by name.
  forensic-mcp://playbook/{name} — step-by-step procedure for that investigation type.
  forensic-mcp://tool-guidance/{tool_name} — how to interpret results from a specific tool.
These are on-demand only — the agent must explicitly request them by URI.
```

**B8. Trim `GATEWAY` idx routing to one line, remove detail**
Replace the current idx list with:
```
Evidence indexing and search — use idx_* tools (opensearch-mcp); start every indexed
session with idx_case_summary for scope.
```
Full idx workflow lives in OPENSEARCH instruction only.

### Phase C — Tool-level docstring improvements (most important)

**Design rule**: the tool description IS the primary interface. The agent reads it before
calling. It must answer in order: (1) what this does, (2) when to call this vs the
alternative, (3) what comes back, (4) a concrete example call with realistic args.
No walls of prose. Bullet points and examples over paragraphs.

**Output cap rule** (applies to every tool description):
- If the tool can return large output, the description must state the cap and what
  happens to overflow: "Returns first N results inline; full output saved to
  agent/<subdir>/ when result exceeds cap."
- This sets agent expectations at tool-selection time, before the call is made.

**Standard template:**
```
"""<One line: what this does. When to use this vs [alternative tool].>

Returns: <key response fields and what they mean, one line>.
Output cap: <N results inline; remainder saved to agent/... or: no cap, always compact>.

Example:
  <tool_name>(<realistic args>) → <what the response contains>
  <tool_name>(<second realistic case>) → <what changes>

Notes:
  - <Caveat 1 — one line, most common mistake>
  - <Caveat 2>
"""
```

**check_artifact and check_system are the gold standard** — their descriptions are already
correct (type-parameterized, examples inline, UNKNOWN explained). Use these as the reference
when rewriting other tools.

**Priority order (highest agent confusion / context-bloat risk first):**

**idx_ingest** — most-called, most confusion
```
"""Index evidence into OpenSearch for searching. Call dry_run=True first to preview
what will be parsed, then dry_run=False to commit. Format 'auto' detects most KAPE/EZ
artifacts; use explicit format when auto fails.

Formats: auto | evtx | delimited | json | accesslog | memory | autorunsc
Returns: {run_id, status, estimated_docs, filesystem_meta_path} — filesystem_meta_path
is the sidecar JSON written at ingest with partition/filesystem metadata.
Output cap: response is always compact (status + counts, not document content).

Example:
  idx_ingest(path='evidence/C/', hostname='DESKTOP-ABC', format='auto', dry_run=True)
    → preview: detects evtx, amcache, shimcache, mft under evidence/C/
  idx_ingest(path='evidence/Rocba-Memory.raw', format='memory', hostname='ROCBA', tier=1)
    → launches Volatility Tier 1 (10 plugins); returns run_id for idx_ingest_status

Notes:
  - dry_run=True is the default — always confirm with False when ready to commit.
  - For memory images, tier=1 always first; tier=2/3 only after suspicious PIDs identified.
  - path is relative to evidence/ under the active case dir.
"""
```

**idx_case_summary** — call first, currently under-described
```
"""Single call to scope an indexed case. Call this FIRST every session before any search.

Returns: {hosts[], artifact_types with doc counts, enrichment_status, coverage_state,
filesystem_meta_path}. coverage_state shows what SIFT skill areas ran vs gaps with
exact run_command recipes to fill them.
Output cap: always compact — one summary object, no document content.

Example:
  idx_case_summary(case_id='rocba-drive-20260526-1417')
    → hosts: ['ROCBA'], disk_artifacts: {evtx: indexed, mft: indexed, amcache: indexed},
       memory: {tier_run: 1, plugins_run: [pslist, psscan, ...]},
       gaps: [{coverage_gap: 'YARA not run', command: '...'}]

Notes:
  - include_fields=True adds available field names per index — use when building queries.
  - coverage_state.filesystem_meta_path points to the partition sidecar if collected at ingest.
"""
```

**idx_search** — most-used, syntax often wrong
```
"""Search indexed evidence with OpenSearch query_string syntax.

Use for specific IOC lookups, event code filters, user/host pivots.
Use idx_aggregate instead when you need counts per value (e.g., top 10 source IPs).
Returns: {hits[], total, next_offset} — hits contain _source fields of each document.
Output cap: limit default=50, max=200. Use offset for pagination.

Examples:
  idx_search(query='event.code:4624 AND source.ip:192.168.*', case_id='rocba-...')
  idx_search(query='Path.keyword:"C:\\Windows\\Temp\\*.exe"', index='case-rocba-shimcache')
  idx_search(query='winlog.event_data.ServiceName:svchost', time_from='2026-05-01T00:00:00')

Notes:
  - Quote special chars: source.ip:"::1", Path.keyword:"C:\\path"
  - CSV/shimcache fields need .keyword suffix; evtx fields (event.code) do not.
  - Add NOT winlog.channel:"Microsoft-Windows-WinRM/Operational" to cut noise.
  - Fetch case_id from case_status first — never guess it.
"""
```

**idx_aggregate vs idx_field_values** — constant confusion
```
# idx_aggregate:
"""Count documents grouped by a field value. Use when you need 'top N X' answers.

Use idx_search to read actual document content. Use idx_field_values to list unique
values without counts.
Returns: {buckets: [{key, doc_count}]} sorted by count descending.
Output cap: top_n default=20, max=100 — always compact.

Example:
  idx_aggregate(field='user.name.keyword', case_id='rocba-...', top_n=10)
    → top 10 usernames by event count
  idx_aggregate(field='event.code', query='host.name:ROCBA', case_id='rocba-...')
    → event code distribution for one host
"""

# idx_field_values:
"""List unique values for a field without counts. Use when you need the value set,
not frequency. Use idx_aggregate when counts matter.
Returns: {values: [str]} — flat list, no counts.
Output cap: limit default=50. Always compact.

Example:
  idx_field_values(field='host.name.keyword', case_id='rocba-...')
    → ['DESKTOP-ABC', 'ROCBA', 'DC01']
"""
```

**run_command** — output cap critical
```
"""Execute a forensic tool on the SIFT VM. shell=False enforced; no pipes or redirects.

Output cap: save_output=true required for any command that produces >50 lines.
Response returns {summary, line_count, saved_to: 'agent/commands/<filename>'}
not full stdout. Then use run_command(['grep', ...]) against the saved path.

Example:
  run_command(['fls', '-r', '-m', '/', 'evidence/disk.e01'], save_output=True,
    purpose='Generate bodyfile for timeline')
    → saved_to: 'agent/commands/fls_20260529_143201.txt', line_count: 284921

  run_command(['grep', '-i', 'temp', 'agent/commands/fls_20260529_143201.txt'],
    save_output=False)
    → inline: matching lines only

Notes:
  - No shell metacharacters — each arg is a list item: ['grep', '-i', 'pattern', 'file'].
  - For tools with large output (vol, fls, bulk_extractor) always save_output=True.
  - Output path is relative to the active case dir.
"""
```

**workflow_status** — description currently doesn't explain return shape
```
"""Single entry point: detect current investigation phase and next steps.
Call this FIRST every session — replaces 7 separate discovery calls.

Returns: {phase, case_id, evidence_summary, indexing_status, findings_summary,
  timeline_events, available_capabilities, next_steps[]}.

Phases: ORIENT→SEALED→INGESTING→INGESTED→TRIAGE→FINDINGS→REPORTING.
Output cap: always compact — one status object.

Example:
  workflow_status() → phase: TRIAGE, 3 sealed files, indexing complete, 0 findings yet
  workflow_status() → phase: REPORTING, 26 findings (1 approved, 25 draft)
"""
```

**manage_todo** — no action enumeration currently
```
"""Manage investigation task list. Tracks planned steps; examiner sees list in real time.

Actions: add | complete | cancel | list | update
Output cap: always compact — todo list items only.

Example:
  manage_todo(action='add', text='Check svchost.exe parent processes in vol-psscan')
  manage_todo(action='list') → [{id, text, status, created_at}]
  manage_todo(action='complete', id='todo-abc123')
"""
```

**evidence_register** — always blocked, misleading description
```
"""Portal-managed only — this tool always returns blocked. Do not call it.
Evidence registration is done by the examiner in the portal UI at /portal/.
Use evidence_list() to see what is already registered and sealed.
"""
```

**idx_list_detections** — no severity guidance
```
"""Return Hayabusa sigma rule hits grouped by severity. Call after idx_enrich_triage.

Returns: {detections: [{rule_name, severity, count, sample_event_ids}]}.
Output cap: top 50 rules inline; full list saved to agent/detections/.

Severity levels: critical → immediate pivot required; high → investigate before
medium; medium → context-dependent; informational → rarely actionable alone.

Example:
  idx_list_detections(case_id='rocba-...')
    → critical: ['Mimikatz Command Line', 'LSASS Memory Access'],
       high: ['PsExec Lateral Movement'], ...

Notes:
  - Cross-reference critical/high process names against vol-pslist via
    idx_search(query='process.name:mimikatz', index='case-rocba-vol-pslist')
  - Check hayabusa_corroboration.flagged field on vol-psscan/netscan docs.
"""
```

### Phase D — Output cap enforcement (new capability)

Define and enforce a standard output size convention across all tools.

**Convention:**
- Tool responses rendered inline in the MCP session: max ~2,000 tokens of content.
- Anything larger: write to `agent/<subdir>/<filename>`, return `{"saved_to": "agent/...", "summary": "...", "line_count": N}`.
- Agent uses `run_command(['grep', ...])` or `idx_search` against the saved path.

**Enforcement points:**
- `run_command` in sift-mcp: already has `save_output=true`. Add default cap of 200 lines in response; remainder in file.
- `idx_search`: already has `limit` param. Enforce max limit=200 and add response note when truncated.
- `idx_enrich_triage` / `idx_enrich_intel`: return summary counts + first 10 hits inline, full detail saved to `agent/enrichment/<run_id>.json`.
- `generate_report`: already saves to file, returns path.
- `idx_inspect_container`: already returns compact metadata.

### Phase E — forensic-mcp resources audit

The 14 registered resources cost nothing unless fetched, but:
1. Some clients auto-discover resources and display them, adding noise.
2. The most useful content (evidence template, anti-patterns, corroboration) is already
   partially duplicated in `FORENSIC_MCP` instructions string.

**Decision needed:**
- Keep resources as on-demand reference (add note to `FORENSIC_MCP` instructions: "forensic-mcp://playbooks lists available investigation playbooks; fetch forensic-mcp://playbook/{name} for step-by-step guidance").
- Remove resources whose content is fully covered by instructions.
- Do NOT duplicate resource content into instructions — pick one authoritative location.

---

## Part 5 — Implementation Order

All changes in Steps 1-5 are text-only in `instructions.py`. No logic, no tests needed.
Steps 6-8 touch function docstrings. Step 9 is the only behavioral change.

| Step | Task | File(s) | Size |
|------|------|---------|------|
| 1 | A1-A4: name/dead-ref cleanup | `instructions.py`, `report-mcp/server.py:1` | Small |
| 2 | A5: opensearch-mcp instructions= | `opensearch-mcp/server.py:47` | 1 line |
| 3 | B1-B4: OPENSEARCH update (coverage_state, memory tiers, detections, case_host_fix) | `instructions.py` OPENSEARCH block | Medium |
| 4 | B5+B8: GATEWAY — output cap + trim idx detail to routing-only | `instructions.py` GATEWAY block | Small |
| 5 | B6-B7: SIFT_MCP YARA reality + FORENSIC_MCP resource awareness | `instructions.py` SIFT_MCP + FORENSIC_MCP | Small |
| 6 | C (high priority): idx_ingest, idx_case_summary, idx_search docstrings | `opensearch-mcp/server.py` | Medium |
| 7 | C (medium): idx_aggregate, idx_field_values, idx_list_detections, case_host_fix | `opensearch-mcp/server.py` | Medium |
| 8 | C (other backends): workflow_status, manage_todo, evidence_register, run_command | `forensic-mcp/server.py`, `case-mcp/server.py`, `sift-mcp/server.py` | Medium |
| 9 | D: Output cap enforcement in run_command (truncate + auto-save) | `sift-mcp/server.py` | Small behavior change |
| 10 | E: Evaluate corroboration resource → promote to tool | `forensic-mcp/server.py` | Optional |

Steps 1-5 are pure text changes with no logic. Steps 6-8 touch behavior.
Deploy after each step (rsync + gateway restart) and validate with a live `tools/list`
call to confirm description changes propagate.

---

## Part 6 — What NOT to do (decisions locked)

- **Do not** add GATEWAY-level idx workflow detail — it belongs in OPENSEARCH only.
- **Do not** duplicate anti-patterns / evidence-standards / confidence-definitions from
  FORENSIC_MCP instructions into resource content or vice versa. Pick one location.
- **Do not** create new tools for check_file, check_service, check_autorun, check_hash,
  check_lolbin — they are already inside check_artifact and check_system via `type` param.
- **Do not** run community YARA rule sets automatically — noisy false positives corrupt findings.
- **Do not** reference REMnux, wintools-mcp, or Zeltser HTTP MCP — none are in this stack.
- **Do not** remove the forensic-mcp resources — they are discipline content. Just make
  FORENSIC_MCP instructions tell the agent they exist and when to fetch them.

## Part 7 — Validation Checklist

After each phase, verify via live MCP tool calls (not code reading):
- [ ] `get_health` — all 8 backends ok, 60 tools unchanged
- [ ] `workflow_status()` — returns phase and next_steps correctly
- [ ] `check_tools(['yara','tshark','binwalk'])` — all show available=true; zeek shows available=false
- [ ] `check_artifact(type='lolbin', value='certutil.exe')` — returns verdict correctly
- [ ] `server_status(resource='all')` — windows-triage baseline counts unchanged
- [ ] `idx_case_summary()` — coverage_state and filesystem_meta_path present in response
- [ ] No stale "Valhuntir" / "wintools" / "REMnux" in any MCP instructions text
- [ ] `run_command` with large output returns saved_to path not full content (Step 9)
- [ ] All tests pass: `bash scripts/remediation-gate.sh`
