# SIFT Skill Coverage Matrix

> **RG1 (2026-06-13):** This document is **archival**. The coverage matrix and skill
> mapping remain useful context for understanding forensic tool coverage, but several
> terms and tool references are stale:
>
> - `AGENTIR_CASE_DIR` — old environment variable name. Current code uses the case path
>   resolved server-side via `AuthorityContext`; agents never see the absolute path.
>   The agent output dir is `agent/` (relative). `run_command` saves outputs under
>   `agent/run_commands/` (source: `packages/sift-core/src/sift_core/execute/worker.py`).
> - `windows-triage baselines` — the `windows-triage-mcp` package has been removed from
>   this repo. Windows-triage integrations are a future external add-on candidate only
>   (see `docs/add-ons/author-guide.md`). References below are historical.
> - `idx_*` tool names — these were pre-migration MCP tool names. Current tool names
>   are in `docs/add-ons/spec.md` and `packages/opensearch-mcp/sift-backend.json`.
>   `opensearch_search`, `opensearch_ingest_status`, etc. are the current names.
> - `sift-mcp/run_command` — the tool name is now simply `run_command` through Gateway `/mcp`.
>
> See `docs/inventory/sift-tool-inventory.md` for the current live tool inventory.

## Scope

This compares the SIFT skill workflows against the current `sift-mcps` runtime surface.
The goal is to identify what the AI agent can use through MCP directly, what is only
available as a controlled `run_command` fallback, and where the easiest automation wins are.

Assumptions (original — see RG1 note above for current corrections):

- "Automated" means available through an MCP workflow that resolves case paths, writes indexed
  structured output, and can be queried later without re-reading large command output.
- "Fallback" means the host tool exists or can be run through `run_command`, but the
  output is not yet captured as first-class case context.
- The desired direction is: enrich the pipeline once, index or summarize durable facts, and only
  instruct the agent to run manual commands for narrow gaps.
- Examiner-controlled evidence intake remains authoritative. The human operator copies files
  into `evidence/`, seals them in the portal, and verifies the evidence ledger. Agent-run
  commands produce analysis outputs, not evidence registrations.
- Agent-visible fallback outputs should live under `agent/` (relative path within the case),
  with `agent/run_commands/` as the default command capture location. **RG1: `AGENTIR_CASE_DIR`
  is a stale pre-migration env var name; the case dir is never passed to the agent.** Do not add
  new top-level case directories such as `analysis/` or `exports/` unless the portal and case
  I/O explicitly adopt them.

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
| Memory Forensics / Volatility 3 | `idx_ingest(format="memory", tier=1/2/3)`, `vol-*` indices, triage enrichment for services, Hayabusa↔memory correlation, `coverage_state` in `idx_case_summary` | **Strong (Tier 1)** | No Memory Baseliner; no dump workflows; no YARA-in-memory; no VAD/manual strings workflow | Low to medium. psscan (2,212 docs) and netscan (430 docs) now default Tier 1. Agent can query `hayabusa_corroboration.flagged:true` to surface cross-referenced processes. `coverage_state` shows exactly what ran and what's missing. |
| Timeline / Plaso | Plaso fallback parsers for selected artifacts; OpenSearch timeline/query tools | Partial | No first-class `.plaso` build/export, `pinfo`, `psort` slice/filter, or merged super-timeline workflow | Medium. Agent can query indexed timelines, but not generate examiner-friendly Plaso exports through MCP. |
| File System / Carving / TSK | Container inspect, read-only mount/ingest, artifact discovery, safe traversal | Partial | `mmls/fsstat/fls/icat/ils/tsk_recover`, `bulk_extractor`, `photorec`, bodyfile/mactime are not indexed workflows | Medium. Deep filesystem recovery requires manual commands and can bloat context. |
| Threat Hunting / IOC Sweeps | OpenCTI enrichment (external add-on), Hayabusa detections, OpenSearch IOC search | Low to partial | YARA/yarac not currently integrated; no generated IOC sweep artifacts; Velociraptor is out-of-band. **RG1: `windows-triage baselines` removed** — package is no longer in repo (external add-on candidate only). | Medium to high for malware-hunt workflows. Agent lacks a one-call sweep path. |
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
| `windows.netscan` | **Yes, Tier 1** ✓ | **Promoted 2026-05-27.** Live: 430 docs on rocba case (vs 162 netstat — 268 additional historical/closed connections). `ForeignAddr.keyword` swept by `idx_enrich_intel`. `Owner` field corroborated by Hayabusa memory correlation. | Done. |
| `windows.psscan` | **Yes, Tier 1** ✓ | **Promoted 2026-05-27.** Live: 2,212 docs on rocba case (vs 2,186 pslist — 26 hidden/exited processes). `ImageFileName` 14-char truncated — excluded from `check_file` by design. Hayabusa corroboration stamps applied. | Done. |
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
| windows-triage baselines | **RG1: removed** | `windows-triage-mcp` package no longer in repo. Future external add-on candidate (see `docs/add-ons/author-guide.md`). | Rebuild as an external add-on if needed. |
| YARA file sweep | No | `yara` was not found in current VM PATH during check | Install/verify YARA, then add a case-aware sweep job. |
| YARA memory scan | No | Needs rules + memory image path | Add only after file sweep framework exists. |
| Velociraptor | No | External web console; not local SIFT binary | Treat as out-of-band collection, ingest exported results. |

## Biggest And Easiest Wins

### ~~1. Add Coverage State To `idx_case_summary`~~ — **DONE 2026-05-27**

`_build_coverage_state(artifacts, enrichment)` in `server.py`. Returns `disk_artifacts`
(indexed/not_run/not_available per SIFT skill area), `memory` (tier_run, plugins_run,
plugins_not_run), `enrichment` state, and `gaps` (structured fallback recipes). Verified
live on rocba case: coverage_state correctly reported tier_run=1, psscan/netscan in
plugins_not_run before re-ingest, then correctly updated after. 25 unit tests.

### ~~2. Promote `windows.psscan` And `windows.netscan` Into Default Memory Tier~~ — **DONE 2026-05-27**

`parse_memory.py` TIER_1 updated. TIER_2 extension deduped. Verified live on rocba case:
psscan → 2,212 docs (26 hidden/exited vs pslist); netscan → 430 docs (268 more than netstat).
4 regression tests added.

### 3. Standardize Agent Output Capture Under `agent/`

Impact: high. Effort: medium.

For manual fallbacks, the agent should not paste huge command output into chat. Instead:

- MCP response gives a precise command.
- Command writes to `agent/run_commands/` or another purpose-specific subdirectory under
  `agent/` (the case-relative output dir; **RG1: `AGENTIR_CASE_DIR` is a stale pre-migration
  env var** — the case dir is resolved server-side and is never exposed to the agent).
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
| ~~1~~ | ~~Coverage state in `idx_case_summary`~~ | **Done 2026-05-27** |
| ~~2~~ | ~~Promote memory `psscan` + `netscan` to default~~ | **Done 2026-05-27** |
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
  "command": "yara -r -s /path/to/rules.yar evidence > agent/yara/ioc_sweep.txt",
  "_rg1_note": "RG1: $AGENTIR_CASE_DIR is a stale pre-migration env var. Pass evidence_refs to run_command; the gateway resolves paths internally.",
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
  "command": "vol --renderer json windows.malfind --pid <PID>",
  "_rg1_note": "RG1: $AGENTIR_CASE_DIR is stale. Pass evidence_ref for the memory image via run_command evidence_refs; the gateway resolves the absolute path internally.",
  "output_path": "agent/memory/malfind_<PID>.json",
  "next_mcp_step": "Summarize PID, process name, VAD address, protection, and PE/header indicators.",
  "warning": "malfind has false positives; require corroboration before recording a finding."
}
```

## Confirmed Enrichment Pipeline State

Verified against live case `rocba-drive-20260526-1417` (2026-05-27). This is the actual
enrichment chain — not aspirational. Do not add a new enrichment layer if the signal is
already flowing through one of these paths.

| Signal | Source field | Destination | Mechanism |
|---|---|---|---|
| External IPs from network connections | `ForeignAddr.keyword` (vol-netscan, vol-netstat) | `threat_intel.verdict` on each doc | `idx_enrich_intel` → `extract_unique_iocs` → OpenCTI |
| External IPs from event logs | `source.ip` (evtx, accesslog, w3c) | `threat_intel.verdict` | same sweep (`case-{id}-*` pattern) |
| Hashes from CSV artifacts | `SHA1/SHA256/MD5.keyword` | `threat_intel.verdict` | same sweep |
| Service names from memory | `Name.keyword` (vol-svcscan) | `triage.verdict` | `_enrich_service_artifact` → `check_system` |
| Service names from EVTX 7045 | `winlog.event_data.ServiceName` | `triage.verdict` | `_enrich_evtx_services` → `check_system` |
| DLL paths from memory | `Path.keyword` (vol-dlllist) | `triage.verdict` | `_enrich_file_artifact` → `check_artifact` |
| File paths (shimcache, amcache, tasks) | `Path/FullPath/task.command.keyword` | `triage.verdict` | `_enrich_file_artifact` → `check_artifact` |
| Registry persistence mechanisms | KeyPath + ValueName patterns (R1–R17) | `triage.verdict` | `_enrich_registry_persistence` (gateway-independent) |
| **Hayabusa high/critical process names** | `Details` field `Proc:/Img:/TgtImg:` aliases | `hayabusa_corroboration.*` on vol-pslist/psscan/netscan | `_enrich_hayabusa_memory_correlation` (2026-05-27, gateway-independent) |

### Confirmed non-overlaps (do not re-add)

- **vol-pslist/psscan excluded from `check_file`**: `ImageFileName` is truncated to 14 chars
  by the Windows kernel. `check_file` would call every system process SUSPICIOUS. This is
  intentional. The Hayabusa correlation stamps these docs instead when a name-level match exists.

- **Hayabusa `SrcIP:` → netscan correlation not added**: Logon-event source IPs (EID 4624
  `SrcIP:` alias) are already swept by threat intel enrichment via `source.ip` from evtx.
  Adding a second path through Hayabusa Details would produce duplicate stamps.

- **Hayabusa `Path:` (7045 service alerts) → vol-svcscan not added**: Service binary paths
  from service-install alerts are already handled via `_enrich_service_artifact` on vol-svcscan
  service names. The check_service call covers the same ground.

### Hayabusa Details field format reference

Hayabusa verbose profile separator: ` ¦ ` (U+00A6 BROKEN BAR). Each segment: `Alias: Value`.

| Event type | EID | Process-bearing aliases | Non-process aliases |
|---|---|---|---|
| Process creation | 4688 | `Proc:` (new process), `PProc:` (parent) | `User:`, `Cmd:` |
| Sysmon process | 1 | `Img:` (full path), `PImg:` (parent full path) | `Cmd:`, `User:` |
| Sysmon process access | 10 | `TgtImg:` | `SrcImg:`, `Access:` |
| Service install | 7045 | — | `Svc:`, `Path:`, `Acct:`, `StartType:` |
| BITS transfer | 16403 | — | `LocalName:`, `RemoteName:`, `User:`, `processId:` |
| Network logon | 4624 | — | `Type:`, `TgtUser:`, `SrcComp:`, `SrcIP:`, `LID:` |

The correlation regex targets `Proc:`, `Img:`, `TgtImg:` only (forward process, not parent).
`PProc:` and `PImg:` are deliberately excluded to avoid over-flagging processes that are
merely parents of suspicious children.

## Next Work Queue

Ordered by the priority framework established 2026-05-27 (Group 1 → response enrichment,
Group 2 → small targeted extensions, Group 3 → new capability modules):

### Group 1 — Complete

**1. psscan + netscan → Tier 1** — Done 2026-05-27
**2. `coverage_state` in `idx_case_summary`** — Done 2026-05-27

### Group 2 — Small targeted extensions (one file each)

**3. Filesystem metadata sidecar during ingest** (`containers.py` + `server.py`)

**Decisions locked 2026-05-29** — see Design Decisions section below.

Use TSK stack (`img_stat` + `mmls` + `fsstat`), NOT `fdisk`/`ewfinfo`. Schema differs by
image type: volume image vs partitioned disk vs memory. Add `source_path` to
`ingest_status.py:write_status()`. Reference sidecar path in `coverage_state`; N/A if not
present. Return path in ingest response.

Still needs: live test of `mmls` → `fsstat -o <offset>` path on a **partitioned disk image**.
No such image on VM. Create a synthetic 200 MB test image at session start (see kickoff
prompt) before implementing the partitioned-disk code path. Unit test covers the rest.

**4. Autorunsc CSV ingest** (`idx_ingest(format="autorunsc")`)
New `parse_autorunsc.py` (~100 lines, same pattern as `parse_csv.py`). New index suffix
`autoruns`. Triage enrichment already handles file paths via `check_artifact`. Examiner
drops Autorunsc CSV into `evidence/`; agent calls `idx_ingest(format="autorunsc")`.
`coverage_state` already has `"autoruns": (set(), "not_available")` as a placeholder.

### Group 3 — Reclassified: run_command + guidance only (no new MCP tools)

**Decision locked 2026-05-29**: Plaso and YARA are NOT MCP tools. Reasons:
- Plaso is expensive, examiner-deliverable, not a query target. Agent runs
  `log2timeline.py` via `run_command`, saves to `agent/timelines/`. Dashboard
  integration (timeline viewer) is a future portal task.
- YARA requires examiner-chosen rules, is noisy, and must be agent-initiated only when
  specific IOCs exist. Keep as `run_command` with structured guidance. The missing piece:
  `_build_coverage_state` does not currently emit a YARA gap hint. Add one that fires when
  `threat_intel` enrichment found hits but no YARA output file exists under `agent/yara/`.

- Browser artifact ingestion (Plaso targeted or native SQLite) — still Group 3 MCP work.

## Design Decisions (2026-05-29)

### Filesystem Sidecar — Tool Stack

**Decision**: Use Sleuth Kit (`img_stat`, `mmls`, `fsstat`), not `fdisk` + `ewfinfo`.

**Why**: Tested live on rocba E01 (22 GB, Windows C: drive, NTFS volume image):
- `fdisk` on the EWF-mounted raw file produces **garbage partition entries** with start
  sectors (1,920,221,984) exceeding total disk sectors (170,764,280). Do not save this.
- `mmls` on the E01 directly returns **empty** — correct, because this is a volume image
  with no partition table. Empty mmls = volume image; populated mmls = partitioned disk.
- `fsstat` on the E01 directly returns real filesystem metadata: `NTFS`, volume name
  `Windows`, cluster size 4096, sector size 512, MFT range, volume serial number.
- `img_stat` on the E01 returns image-level metadata: `ewf`, size 87,431,311,360 bytes,
  sector size 512, MD5. Subset of `ewfinfo` output, already in TSK.
- TSK tools understand EWF natively — no `ewfmount` step required.

**Three distinct sidecar schemas by image type:**

| Image type | Detection | Tools run | Sidecar key fields |
|---|---|---|---|
| EWF/raw NTFS volume | `mmls` returns empty | `img_stat` + `fsstat` at offset 0 | `image_type: ntfs_volume`, fs_type, volume_name, cluster_size, md5 |
| Partitioned disk | `mmls` returns partition table | `img_stat` + `mmls` + `fsstat -o <offset>` per NTFS/ext partition | `image_type: partitioned_disk`, partition list with offsets, per-partition fs metadata |
| Memory image | `format="memory"` at ingest call | none (not mountable) | `image_type: memory_image`, size, detected magic (LiME/HIBR/PAGEDU64/raw) |

**RAM test result**: `Rocba-Memory.raw` (18 GB) — all-zero header, no LiME/HIBR/PAGEDU64
magic. Plain raw acquisition.

**Partitioned disk path not yet live-tested** — no full disk image with MBR/GPT on VM.
Must create synthetic test image before implementing that code path.

### Evidence Cross-Reference — Minimal Change

**Decision**: Add `source_path` to `ingest_status.py:write_status()`. One field. No new
tool. `coverage_state` in `idx_case_summary` then cross-references manifest (sealed
files) against ingest status records (by path) and emits a compact per-evidence table:
path / sealed (T/F) / ingested (T/F) / index_suffixes.

**Why not a new `idx_evidence_status()` tool**: The cross-reference is derivable from
existing data once `source_path` is stored. Adding a tool before the data exists adds
complexity without payoff.

**What `load_manifest` does and does not do** (verified in code):
- Pure JSON reader. Reads `evidence-manifest.json` fresh on every call. No caching, no
  startup state, no file-type classification.
- Per-file fields: `path`, `sha256`, `bytes`, `mtime_ns`, `registered_at`,
  `registered_by`, `source` (examiner free text), `description` (examiner free text),
  `status` (ACTIVE/IGNORED/RETIRED).
- Does NOT store: file type, whether ingested, index suffixes, partition metadata.
- Called from: `case-mcp` (`evidence_list`), `case-dashboard` (portal routes), `report-mcp`
  (report generation), `evidence_chain.py` (seal/ignore/retire/chain_status).
- **Do not add ingest state to the manifest** — it is chain-of-custody data only.
  Keep the systems separate.

### YARA and Plaso — run_command Only

**Decision**: No MCP wrappers for either.

YARA gap hint to add to `_build_coverage_state` (`server.py`):
```python
# Fire when threat_intel found hits but no agent/yara/ output exists
if enrichment_state["threat_intel"] == "done" and not _yara_output_exists(case_dir):
    gaps.append({
        "coverage_gap": "YARA sweep not run — IOCs enriched but no file sweep performed.",
        "when_to_run": "When specific IOC strings, hashes, or malware family rules are available.",
        "command": "run_command(['yara', '-r', '-s', '/path/to/rules.yar', 'evidence/'], ...)",
        "output_path": "agent/yara/ioc_sweep.txt",
        "next_mcp_step": "Summarize matching rule names, paths, offsets only. Do not paste full output.",
        "warning": "Community rules are noisy. Treat hits as leads, not findings.",
    })
```

## Implementation Log

| Date | Item | Status | Notes |
|---|---|---|---|
| 2026-05-27 | Hayabusa↔memory correlation | **Done** | `_enrich_hayabusa_memory_correlation` in `triage_remote.py`; 9 tests; 928/928 pass; deployed to VM; runs as gateway-independent enrichment pass inside `idx_enrich_triage` |
| 2026-05-27 | psscan + netscan → Tier 1 | **Done** | `parse_memory.py` TIER_1 promoted; TIER_2 deduped; 4 new regression tests; 953/953 pass |
| 2026-05-27 | `coverage_state` in `idx_case_summary` | **Done** | `_build_coverage_state(artifacts, enrichment)` added to `server.py`; injected as `coverage_state` field; 25 unit tests; disk/memory/enrichment/gaps; reuses `_plugin_to_index_suffix` from `parse_memory.py` |
| 2026-05-27 | Live validation — psscan/netscan + coverage_state | **Verified** | Force re-ingest of `Rocba-Memory.raw` on rocba-drive-20260526-1417: 10-plugin Tier 1 run (pid 1664039, 1m). psscan: 2,212 docs; netscan: 430 docs. coverage_state returned correct state before and after. EVTX `unknown error` on disk ingest is pre-existing across all historical runs — not a regression. |
| 2026-05-29 | Filesystem sidecar design | **Decided, not implemented** | TSK stack chosen (img_stat+mmls+fsstat). fdisk discarded. Live-tested on rocba E01. Partitioned disk path untested (no full disk image on VM). See Design Decisions section. |
| 2026-05-29 | Evidence cross-reference design | **Decided, not implemented** | Add `source_path` to `ingest_status.py:write_status()`. No new tool. |
| 2026-05-29 | YARA/Plaso as run_command only | **Decided** | No MCP wrappers. YARA gap hint to be added to `_build_coverage_state`. |

## Next Work Queue

Ordered by the priority framework established 2026-05-27 (Group 1 → response enrichment,
Group 2 → small targeted extensions, Group 3 → new capability modules):

### Group 1 — Complete

**1. psscan + netscan → Tier 1** — Done 2026-05-27
**2. `coverage_state` in `idx_case_summary`** — Done 2026-05-27

### Group 2 — Next up

**3a. Synthetic partitioned disk test** — prerequisite for 3b
Create a ~200 MB test image on the VM: `dd` + `fdisk` (MBR, one NTFS partition) + `mkfs.ntfs`.
Verify: `mmls` returns partition table → `fsstat -o <offset>` returns NTFS metadata.
This confirms the partitioned-disk code path before writing it.

**3b. Filesystem metadata sidecar** (`containers.py` + `server.py` + `ingest_status.py`)
- `containers.py`: add `_collect_filesystem_meta(image_path, container_format)` → runs
  `img_stat`, `mmls`, `fsstat` (per volume if partitioned, at offset 0 if volume image).
  Returns structured dict. Handles empty mmls (volume image) and populated mmls
  (partitioned disk) as separate branches. Graceful fallback if any TSK tool missing.
- `server.py`: write sidecar to `agent/ingest/<run_id>-filesystem-meta.json` after mount,
  for both disk and memory ingest paths. Return `filesystem_meta_path` in ingest response
  (N/A string if collection failed). Add path reference to `coverage_state`.
- `ingest_status.py`: add `source_path` field to `write_status()` calls in ingest flow.
  Enables evidence cross-reference in `coverage_state`.

**4. Autorunsc CSV ingest** (`idx_ingest(format="autorunsc")`)
New `parse_autorunsc.py` (~100 lines). New index suffix `autoruns`. Placeholder already
in `coverage_state`. Examiner drops CSV into `evidence/`; agent calls
`idx_ingest(format="autorunsc")`.

### Group 3 — run_command + guidance only

- YARA: add gap hint to `_build_coverage_state` (see Design Decisions above)
- Plaso: agent uses `run_command` → `agent/timelines/`. Dashboard integration is a future portal task.
- Browser artifact ingestion (Plaso targeted or native SQLite)

## Target End State

The agent should be able to ask `idx_case_summary()` and see:

- what evidence exists (per-file: path, sealed, ingested, index suffixes),
- what was ingested and from which source file,
- what enrichment ran,
- which SIFT skill areas are covered,
- which skill areas are intentionally not covered,
- exact low-context next steps for the gaps.

That makes the MCP workflow evidence-first and prevents large manual command transcripts from
becoming confused case facts.
