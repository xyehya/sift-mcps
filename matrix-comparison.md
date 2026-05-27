# SIFT Skill Coverage Matrix

## Scope

This compares the SIFT skill workflows against the current `sift-mcps` runtime surface.
The goal is to identify what the AI agent can use through MCP directly, what is only
available as a controlled `run_command` fallback, and where the easiest automation wins are.

Assumptions:

- "Automated" means available through an MCP workflow that resolves case paths, writes indexed
  structured output, and can be queried later without re-reading large command output.
- "Fallback" means the host tool exists or can be run through `sift-mcp/run_command`, but the
  output is not yet captured as first-class case context.
- The desired direction is: enrich the pipeline once, index or summarize durable facts, and only
  instruct the agent to run manual commands for narrow gaps.
- Examiner-controlled evidence intake remains authoritative. The human operator copies files
  into `evidence/`, seals them in the portal, and verifies the evidence ledger. Agent-run
  commands produce analysis outputs, not evidence registrations.
- Agent-visible fallback outputs should live under `AGENTIR_CASE_DIR/agent/`, with
  `agent/commands/` as the default command capture location. Do not add new top-level
  case directories such as `analysis/` or `exports/` unless the portal and case I/O
  explicitly adopt them.

## Grounding Notes

The matrix is a coverage map, not an implementation contract. The safest expansion path is:

1. Improve response hints and coverage state before adding new tools.
2. Prefer existing MCP boundaries: `idx_*` for indexed/searchable artifacts, `run_command`
   for controlled manual fallback, `case_status`/`case_file_structure` for orientation.
3. Save bulky or manual outputs under `agent/`, return paths and hashes, then let findings
   cite those paths plus audit IDs as provenance.
4. Keep evidence verification and sealing as examiner actions. Agent tools may report
   ledger status and container metadata, but must not blur analysis output with sealed
   evidence.

## Coverage Matrix

| SIFT skill area | Current MCP coverage | Current status | Main gaps | Agent risk today |
|---|---|---:|---|---|
| Windows Artifacts / EZ Tools | `idx_ingest(format="auto")`, `idx_search`, `idx_timeline`, `idx_aggregate`, `idx_case_summary`, Hayabusa, triage enrichment | Strong | Autorunsc, SQLECmd/browser, bstrings, some EZ tools depend on fallback paths | Low to medium. Most high-value host artifacts are indexed, but browser and ASEP coverage is not explicit. |
| Memory Forensics / Volatility 3 | `idx_ingest(format="memory", tier=1/2/3)`, `vol-*` indices, triage enrichment for services | Partial | Default is Tier 1; no Memory Baseliner; no dump workflows; no YARA-in-memory; no VAD/manual strings workflow | Medium. Agent may assume memory coverage is complete when only Tier 1 ran. |
| Timeline / Plaso | Plaso fallback parsers for selected artifacts; OpenSearch timeline/query tools | Partial | No first-class `.plaso` build/export, `pinfo`, `psort` slice/filter, or merged super-timeline workflow | Medium. Agent can query indexed timelines, but not generate examiner-friendly Plaso exports through MCP. |
| File System / Carving / TSK | Container inspect, read-only mount/ingest, artifact discovery, safe traversal | Partial | `mmls/fsstat/fls/icat/ils/tsk_recover`, `bulk_extractor`, `photorec`, bodyfile/mactime are not indexed workflows | Medium. Deep filesystem recovery requires manual commands and can bloat context. |
| Threat Hunting / IOC Sweeps | OpenCTI enrichment, Hayabusa detections, windows-triage baselines, OpenSearch IOC search | Low to partial | YARA/yarac not currently integrated; no generated IOC sweep artifacts; Velociraptor is out-of-band | Medium to high for malware-hunt workflows. Agent lacks a one-call sweep path. |
| Case/report chain of custody | Portal case lifecycle, evidence manifest, HMAC ledger, approvals, reports | Strong | Command-output artifacts from manual fallbacks need standard capture, hashes, and audit/provenance linking | Low for normal workflow; medium when manual commands produce sidecar outputs. |

## Detailed Skill Mapping

### Memory Forensics

| Skill item | Current automated coverage | Gap / note | Recommended MCP direction |
|---|---|---|---|
| `windows.info` | Yes, Tier 1 | Indexed as `vol-info` | Keep default. |
| `windows.pslist` | Yes, Tier 1 | Indexed as `vol-pslist` | Keep default. |
| `windows.pstree` | Yes, Tier 1 | Indexed as `vol-pstree` | Add process-tree enrichment hints in `idx_case_summary`. |
| `windows.cmdline` | Yes, Tier 1 | Indexed as `vol-cmdline` | Add suspicious command-line rollup. |
| `windows.netstat` | Yes, Tier 1 | Indexed as `vol-netstat` | Add external-IP summary and OpenCTI pivot candidates. |
| `windows.svcscan` | Yes, Tier 1 | Indexed as `vol-svcscan`; triage currently checks service names | Add binary path checks where available. |
| `windows.modules` | Yes, Tier 1 | Indexed as `vol-modules` | Add unsigned/unknown driver summary if fields support it. |
| `windows.registry.hivelist` | Yes, Tier 1 | Indexed as `vol-hivelist` | Keep default. |
| `windows.netscan` | Yes, Tier 2 | Not default | Promote to Tier 1 or add "memory coverage incomplete" hint until Tier 2 runs. |
| `windows.psscan` | Yes, Tier 2 | Not default; important hidden/exited process coverage | Promote to Tier 1. |
| `windows.dlllist`, `envars`, `getsids` | Yes, Tier 2 | Useful pivots, moderate cost | Keep Tier 2; add targeted follow-up prompt. |
| `windows.handles`, `filescan`, `malfind` | Yes, Tier 3 | Useful but heavier | Add an MCP "deep memory scan" preset rather than agent hand-selecting plugins. |
| `windows.vadinfo`, `vadyarascan`, dumpfiles, memmap dumps | No | Manual only | Return precise `run_command` recipes only when a suspicious PID/path exists. |
| Memory Baseliner | No | Not currently a case-aware MCP workflow | Add as a dedicated optional enrichment if baseline JSON exists. |

### Timeline / Plaso

| Skill item | Current automated coverage | Gap / note | Recommended MCP direction |
|---|---|---|---|
| Full `log2timeline.py` super-timeline | No | OpenSearch timeline is not a `.plaso` substitute for examiner export | Add `idx_generate_plaso_timeline(dry_run=True)` or case artifact bundle job. |
| `pinfo.py` parser stats | No | Would be useful quality gate | Auto-run after Plaso jobs and store summary. |
| `psort.py` CSV/JSON export | No | Manual only | Add output files under case `agent/timelines/` and return paths, not full CSV. |
| `psort --slice` | No | Very useful for event pivot | Add a narrow MCP tool that takes timestamp/window and writes a small export. |
| `image_export.py` | No | Overlaps targeted artifact extraction | Keep as fallback unless frequent need appears. |

### File System / Carving

| Skill item | Current automated coverage | Gap / note | Recommended MCP direction |
|---|---|---|---|
| `ewfinfo` | Yes via `idx_inspect_container` | Metadata only | Add optional hash fields to case evidence view if missing. |
| `ewfverify` | No | Examiner-owned evidence validation step. Evidence manifest hashes and HMAC ledger are authoritative for this runtime. | Do not prioritize as agent automation now. If needed later, expose as examiner/portal metadata, not as an agent substitute for sealing and HMAC verification. |
| E01 mount | Yes | Uses xmount/ntfs-3g with ewfmount fallback | Keep. |
| `mmls`, `fsstat` | Not exposed | Useful for partition/filesystem context | Capture partition/filesystem summary during ingest. |
| `fls` bodyfile + `mactime` | No | Useful filesystem timeline | Add optional filesystem timeline job; index or save bodyfile summary. |
| `icat`, `tsk_recover` | No | Targeted recovery/manual extraction | Add response recipes for suspicious inode/path only. |
| `bulk_extractor`, `photorec` | No | Heavy/noisy | Keep manual/deep-dive, but provide case-safe output paths and command templates. |

### Windows Artifacts / EZ Tools

| Skill item | Current automated coverage | Gap / note | Recommended MCP direction |
|---|---|---|---|
| Amcache | Yes | Strong | Keep. |
| Shimcache | Yes | Strong | Keep caveat messaging: presence, not execution. |
| Registry / RECmd | Yes | Strong | Add ASEP-specific rollups for Run keys, services, USB, UserAssist. |
| Shellbags | Yes | Strong | Add user/path summaries. |
| Jump Lists / LNK | Yes | Strong | Add network share/recent-target summaries. |
| Recycle Bin | Yes | Strong | Keep. |
| MFT / USN | Yes when full/tier includes them | Not always default | Add "not run" hint in summary when absent. |
| Prefetch | Yes via PECmd if available, Plaso fallback otherwise | VM currently falls back successfully | Keep, but surface parse method. |
| SRUM | Yes via SrumECmd if available, Plaso fallback otherwise | VM currently falls back successfully | Keep, but surface parse method. |
| EVTX | Yes | Some corrupt logs can produce recoverable parser errors | Keep. Improve error detail in status. |
| Hayabusa | Yes | Strong | Keep. |
| Autorunsc | No | Requires Windows collection or pre-collected CSV | Add delimited ingest classifier + ASEP summary for Autorunsc CSV. |
| Browser / SQLECmd | Low/no | Browser artifacts not first-class | Add browser parser or delimited/SQLECmd ingestion path. |
| bstrings | No | Deep-dive only | Keep fallback tied to suspicious binary extraction. |

### Threat Hunting / IOC Sweeps

| Skill item | Current automated coverage | Gap / note | Recommended MCP direction |
|---|---|---|---|
| OpenCTI IOC enrichment | Yes | Strong for indexed IOCs | Keep. |
| Hayabusa | Yes | Strong for event detections | Keep. |
| windows-triage baselines | Yes | Strong for paths/services/process context | Keep; expand summary rollups. |
| YARA file sweep | No | `yara` was not found in current VM PATH during check | Install/verify YARA, then add a case-aware sweep job. |
| YARA memory scan | No | Needs rules + memory image path | Add only after file sweep framework exists. |
| Velociraptor | No | External web console; not local SIFT binary | Treat as out-of-band collection, ingest exported results. |

## Biggest And Easiest Wins

### 1. Add Coverage State To `idx_case_summary`

Impact: very high. Effort: low.

`idx_case_summary()` should explicitly report expected coverage by evidence type:

- Disk container coverage: EVTX, Hayabusa, registry, Amcache, Shimcache, Prefetch, SRUM,
  LNK, Jumplists, Shellbags, Recycle Bin, tasks, MFT/USN if requested.
- Memory coverage: tier run, plugins completed, plugins not run.
- Enrichment coverage: triage baseline, OpenCTI, Hayabusa.
- Gaps: "not run", "fallback parser used", "manual-only".

This prevents the agent from assuming "case indexed" means every SIFT skill has been covered.

### 2. Promote `windows.psscan` And `windows.netscan` Into Default Memory Tier

Impact: high. Effort: low to medium.

Current Tier 1 misses two skill-recommended high-value plugins:

- `windows.psscan`: hidden/exited processes.
- `windows.netscan`: historical/closed network connections.

These are core memory-baseline signals. Adding them to default memory ingest gives better
coverage without asking the agent to remember a Tier 2 rerun.

### 3. Standardize Agent Output Capture Under `agent/`

Impact: high. Effort: medium.

For manual fallbacks, the agent should not paste huge command output into chat. Instead:

- MCP response gives a precise command.
- Command writes to `agent/commands/` or another purpose-specific subdirectory under
  `AGENTIR_CASE_DIR/agent/`.
- A follow-up MCP tool indexes or summarizes the output.
- Tool response returns file paths and short summaries only.

Current primitive:

`run_command(command=[...], purpose="...", save_output=True, input_files=[...])`

The next increment should add structured response recipes in relevant tools and, only if
needed, an explicit `output_dir`/`output_path` parameter constrained to `agent/`.

### 4. Improve Fallback Response Hints

Impact: high. Effort: low to medium.

Fallback-only workflows should return compact, structured guidance with:

- `coverage_gap`
- `when_to_run`
- `command`
- `output_path` under `agent/`
- `next_mcp_step`
- `warning`

### 5. Add Autorunsc CSV Ingest And ASEP Summary

Impact: high. Effort: medium.

Autorunsc is not collected by SIFT from an offline image, but if the examiner supplies CSV,
we can classify and index it. Add:

- CSV classifier for Autorunsc.
- `autoruns` index suffix.
- Summary: enabled unsigned entries, suspicious paths, services/drivers/tasks/logon items.
- Triage baseline checks against file paths and hashes where available.

### 6. Add Filesystem Metadata Summary During Disk Ingest

Impact: medium-high. Effort: low.

During container mount, capture:

- partition table equivalent,
- selected filesystem metadata,
- mounted volume paths,
- VSS availability if detected.

This covers the `mmls/fsstat` skill intent without requiring manual command output.

### 7. Add Plaso Export As An Optional Background Job

Impact: medium-high. Effort: medium.

Do not run full Plaso by default; it is expensive. Add a background job:

- `idx_generate_timeline(profile="win10", scope="full|evtx|registry|filesystem", output="csv|json")`
- Writes `.plaso` and exports under `agent/timelines/`.
- Runs `pinfo.py` and returns parser hit stats.
- Adds a "timeline export available" entry in `idx_case_summary`.

### 8. Add YARA Sweep Framework After Installer Verifies YARA

Impact: medium-high. Effort: medium.

First add installer/prereq verification for `yara` and `yarac`. Then add:

- `idx_yara_sweep(path="evidence|mounted|agent", rules_path=..., dry_run=True)`
- Background scan.
- Output file under `agent/yara/`.
- Optional hit indexing into OpenSearch.

Default should not run community rules automatically because noisy hits can confuse findings.

### 9. Add Browser Artifact Coverage

Impact: medium. Effort: medium.

Browser artifacts are common intrusion evidence and currently not first-class. Options:

- Use Plaso targeted parsers.
- Add SQLECmd if available.
- Add native SQLite parsers for Chrome/Edge History and Downloads.

The easiest first step is a targeted Plaso/SQLECmd path that writes browser rows into a
`browser` index suffix.

### 10. Improve Ingest Status Error Specificity

Impact: medium. Effort: low.

Current status can collapse recoverable parser issues into `unknown error`, while the log has
the useful detail. Add compact parser error details to `idx_ingest_status()` for:

- corrupt EVTX names,
- fallback parser used,
- skipped files count,
- manual next step if output is incomplete.

## Recommended Prioritization

| Rank | Work item | Why first |
|---:|---|---|
| 1 | Coverage state in `idx_case_summary` | Stops agent overclaiming coverage immediately. |
| 2 | Promote memory `psscan` + `netscan` to default | Big memory-forensics upgrade with small code change. |
| 3 | Standardize `agent/` command-output capture | Reduces context bloat and keeps agent-generated provenance visible to the operator. |
| 4 | Manual fallback response hints with `agent/` output paths | Gives the agent safe next steps without adding premature tools. |
| 5 | Autorunsc CSV ingest + ASEP summary | High-value persistence coverage from common collection output. |
| 6 | Filesystem metadata summary | Captures TSK context without heavy recovery workflows. |
| 7 | Optional Plaso timeline job | Useful examiner deliverable, but expensive. |
| 8 | YARA sweep framework | Valuable, but needs rules/noise controls and VM dependency verification. |
| 9 | Browser artifact ingestion | Important, but parser choice needs design. |
| 10 | Heavy carving/recovery workflows | Keep manual until a specific investigation need appears. |

## MCP Response Guidance For Fallback-Only Areas

When a workflow is not automated, MCP tools should return small, structured guidance instead of
leaving the agent to improvise. Each response should include:

- `coverage_gap`: what has not been covered.
- `when_to_run`: concrete trigger condition.
- `command`: shell-safe command list or exact command string for `run_command`.
- `output_path`: case-relative path where output must be written.
- `next_mcp_step`: how to summarize, ingest, or attach the output.
- `warning`: expected runtime/noise/destructive-risk caveats.

Example for YARA:

```json
{
  "coverage_gap": "No YARA sweep has been run for this case.",
  "when_to_run": "Run only after specific IOC strings, hashes, or malware family rules are available.",
  "command": "yara -r -s /path/to/rules.yar \"$AGENTIR_CASE_DIR/evidence\" > \"$AGENTIR_CASE_DIR/agent/yara/ioc_sweep.txt\"",
  "output_path": "agent/yara/ioc_sweep.txt",
  "next_mcp_step": "Index or summarize only matching rule names, paths, and offsets; do not paste full output into findings.",
  "warning": "Community rules can be noisy. Treat hits as leads, not findings."
}
```

Example for Volatility deep dive:

```json
{
  "coverage_gap": "Default memory ingest did not run malfind or VAD analysis.",
  "when_to_run": "Run only for suspicious PIDs from pslist/psscan/pstree/cmdline/netstat.",
  "command": "vol -f \"$AGENTIR_CASE_DIR/evidence/Rocba-Memory.raw\" --renderer json windows.malfind --pid <PID> > \"$AGENTIR_CASE_DIR/agent/memory/malfind_<PID>.json\"",
  "output_path": "agent/memory/malfind_<PID>.json",
  "next_mcp_step": "Summarize PID, process name, VAD address, protection, and PE/header indicators.",
  "warning": "malfind has false positives; require corroboration before recording a finding."
}
```

## Target End State

The agent should be able to ask `idx_case_summary()` and see:

- what evidence exists,
- what was ingested,
- what enrichment ran,
- which SIFT skill areas are covered,
- which skill areas are intentionally not covered,
- exact low-context next steps for the gaps.

That makes the MCP workflow evidence-first and prevents large manual command transcripts from
becoming confused case facts.
