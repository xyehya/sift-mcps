# MCP Tool Assessment — Autonomous DFIR Run

Source: autonomous opus 4.8 agent ("Hermes"), MCP-only run on case
`case-rocba-case-06132304` (Rocba Exfiltration), 124 tool calls, ~19 min.
Grounded in what actually happened during the run. All findings staged as DRAFT
in the live system (F-claude-001…009 + 6 timeline events).

Top-line: the investigation answered all 5 case questions at high confidence, but
the **prescribed OpenSearch ingest workflow was non-functional** and a cluster of
`run_command` write/isolation constraints forced a fallback to direct TSK/vol3
forensics off the sealed evidence. The issues below are the reason the run was
harder and slower than it needed to be.

---

## 0. Resolution status (2026-06-14) — append-only update

The friction report below is the historical record of the run; it is NOT rewritten.
This section tracks which of its defects have since been fixed in code. Anchors point
at the merged/landed fix.

Resolved on `fix/mcp-assessment-p0` (merged to main; live-proven):
- **RESOLVED — `no_active_case` ingest defect (the highest-impact defect, §1
  opensearch_ingest / opensearch_inspect_container / opensearch_case_summary).** The
  gateway now injects the DB-authoritative `case_dir` into each filesystem-touching
  backend tool call; the opensearch backend resolves the active case from it. Memory
  ingest live-proven: 23 indices / ~180,892 docs. Anchor: commit 1e660ea +
  03f5753; `opensearch_mcp/server.py:active_case_dir()`.
- **RESOLVED — UUID-vs-human-id trap (§1 opensearch_ingest_status, §2(b)).** case_dir
  injection makes ingest resolve the same active case the tolerant siblings do.
- **RESOLVED — `extractions/`/`agent/` write-jail + 0600 handoff (§2(b/c), §3 P0
  extract→parse handoff).** run_command may now read/write anywhere under the active
  case dir (evidence/ + integrity records + secrets stay hard-denied); worker umask
  0027 makes extracted files group-readable. Anchor: 445bb1e, 349bb23.
- **RESOLVED — `grep -e`/`-E` over-aggressive flag block (§2(c)).** Anchor: ef41e85.
- **RESOLVED — record_finding IOC `hashlib` bug (§3 P2) + KB/audit_id grounding
  credit + native `supersedes` field (§2(d), §3 P1 supersedes).** Anchor: 1863fe2,
  aaa885d.
- **RESOLVED — vol3/tqdm CR `Progress:` flood (§2(a)).** Collapsed at the executor.
  Anchor: 6bcbb0f.

Resolved by the OpenSearch-worker decoupling (this branch `feat/opensearch-workers`;
deployed to TEST, first live smoke per Session-Notes):
- **RESOLVED — FUSE E01 disk-image mount (`fusermount: Operation not permitted`),
  the residual half of the §1 opensearch_ingest defect.** Root cause: the opensearch
  backend ran as a stdio child of the hardened gateway and inherited its private/slave
  mount namespace, so the kernel refused new FUSE mounts. Fixed by moving the
  privileged ingest/enrich pipeline into a dedicated least-privilege
  `sift-opensearch-worker@` systemd unit (`MountFlags=shared` its only relaxation vs
  `sift-job-worker`); the gateway dispatches a durable job and stays hardened. Anchor:
  `policy_middleware.py:OpenSearchJobDispatchMiddleware`, `opensearch_mcp/ingest_job.py`,
  `configs/systemd/sift-opensearch-worker@.service`, migration
  `202606150900_opensearch_worker_status.sql`.
- **RESOLVED — Hayabusa/detections never reachable (§2(d), §3 P1 event-log
  timeliner).** Hayabusa runs in the DISK ingest, which was blocked by the FUSE mount;
  with the worker the disk pipeline mounts and Hayabusa indices land + become
  queryable via `opensearch_list_detections`/`search`/`timeline`. (Live verify of the
  Hayabusa indices is the remaining joint-test step — see Session-Notes.)
- **RESOLVED — single-threaded / blocking ingest.** Dispatch is now NON-BLOCKING
  (gateway returns an opaque job_id immediately) and N `sift-opensearch-worker@`
  instances claim distinct jobs via `FOR UPDATE SKIP LOCKED`, so ingest scales and
  never blocks further MCP calls. Realtime per-worker progress via
  `app.job_status_public`.

Still OPEN (not addressed by these fixes):
- **OPEN — P0 WOF/NTFS-compressed file extractor (§3).** TSK can't read WOF-compressed
  EVTX; independent of ingest decoupling. (Ingest's own Hayabusa/EVTX path may sidestep
  this for the in-pipeline parse, but the standalone run_command extractor gap remains.)
- **OPEN — P1 programmatic callMCPTool bridge / sandboxed code runner (§2(c), §3).**
- **OPEN — catalog↔binary name mismatch (`regripper`/`vol3` vs `rip.pl`/`vol`) (§1
  get_tool_help).**
- **OPEN — OS-level run_command sandbox (cgroup/rlimit only, not bwrap/nsjail).**

---

## 1. Frictions — per tool

### case_info
- Tried: orientation, active-case truth, case brief + 5 questions.
- Friction: none. Complete and accurate. The single reliable source of
  active-case identity (`674425ae-…` / `case-rocba-case-06132304`).
- Impact: positive — anchored the whole run.

### evidence_info
- Tried: confirm sealed evidence + chain status.
- Friction: none. Correctly reported the two sealed images, chain OK.
- Impact: positive.

### capability_guide
- Tried: discover add-on tools/backends.
- Friction: minor — does not flag that the listed ingest tools are
  non-functional in the current active-case state; gives no hint of the
  UUID-vs-human-id requirement downstream.
- Workaround: relied on `get_tool_help` per tool.

### get_tool_help
- Tried: exact policy for `run_command`; usage for forensic binaries.
- Friction: very good overall. Surfaced the exact run_command policy. BUT it
  exposed a **catalog↔binary name mismatch**: help/catalog reference
  `regripper` and `vol3`, while the invocable binaries are `rip.pl` and `vol`.
- Impact: cost discovery cycles guessing the real binary name.
- Workaround: trial-and-error to map `regripper`→`rip.pl`, `vol3`→`vol`.

### opensearch_ingest  — **highest-impact defect**
- Tried: ingest the disk image (auto) and memory image (deep tier), per the
  prescribed "ingest first" workflow.
- Friction: returned **`no_active_case`** even though `case_info`/`evidence_info`
  show a valid DB active case and `opensearch_ingest_status('674425ae-…')`
  resolves it. There is **no `case_id` parameter** to override the resolution.
- Impact: **hard-blocked the entire intended ingest → index → search workflow.**
  No OpenSearch case index was ever created; all of OpenSearch search/aggregate/
  timeline became unavailable for this case.
- Workaround: abandoned ingest; pivoted to direct forensic analysis off the
  sealed evidence (TSK reading the E01 natively with `-i ewf`; vol3 reading the
  raw memory file in place).

### opensearch_inspect_container
- Tried: inspect/confirm container state before ingest.
- Friction: same **`no_active_case`** failure as opensearch_ingest.
- Impact: could not introspect the ingest target.
- Workaround: none needed after abandoning the ingest path.

### opensearch_ingest_status
- Tried: resolve/monitor ingest by case.
- Friction: **accepts the UUID `674425ae-…` but REJECTS the human id
  `case-rocba-case-06132304` with `active_case_mismatch`.** The schema examples
  (e.g. `rocba-drive-2026…`) imply the human id is expected — misleading. So one
  backend tool is tolerant of identity and its sibling (`ingest`) is strict, and
  neither agrees with the schema examples.
- Impact: exposed the identity inconsistency that underlies the ingest failure.

### opensearch_case_summary / opensearch_status
- Tried: cluster health + per-case coverage.
- Friction: work, but inherit the same UUID-vs-human-id tolerance inconsistency.
  With no case index (ingest failed) there was nothing to summarize for the case.
- Impact: confirmed cluster green but no case data.

### opensearch_search / opensearch_aggregate / opensearch_timeline / opensearch_field_values / opensearch_list_detections / opensearch_enrich_intel  — **CROWN JEWEL, NEVER EXERCISED (blocked upstream)**
- These are the whole point of the platform: full-text/structured search,
  aggregation, timeline, field discovery, and Hayabusa detection/enrichment query
  over ALL the parsed artifacts the ingest produces (filesystem, EVTX, registry,
  memory, browser, cloud-sync, IOCs).
- Tried: nothing usable. There was **no case index to query** because
  `opensearch_ingest` failed with `no_active_case`, so the entire query surface
  had zero data for this case.
- Friction: **not the tools' fault — they were starved by the broken ingest.**
  The single `no_active_case` ingest defect cascades into total loss of the
  primary investigative capability: instead of querying indexed, normalized,
  Hayabusa-tagged artifacts, the agent had to hand-parse raw images with
  TSK/vol3/strings/grep — far slower, lower coverage (event logs entirely lost to
  WOF compression), and far more context-hungry.
- Impact: **this is the most important finding of the run.** The crown-jewel
  search/aggregate/timeline/detections workflow was completely unavailable and
  therefore UNASSESSED. Everything the agent achieved was the manual fallback;
  the intended high-signal path (e.g. "query Hayabusa RDP detections, pivot to
  the 4624/4778 logon events, aggregate source IPs, build the timeline") never
  ran.
- Workaround: none possible for search itself — substituted raw-image forensics.

### Programmatic tool calling (R5) — blocked; pipelines as substitute
- Tried: scripting >1 MCP tool call. `python3`/`node` hard-blocked ("cannot be
  overridden"); `bash/sh/perl/ruby` per policy; no code→MCP bridge or token in the
  agent env (pure MCP client). So a script orchestrating multiple MCP tools is
  impossible.
- Substitute achieved: in-policy multi-binary `run_command` pipelines that
  correlate/aggregate in one audited call and return summaries not dumps, e.g.
  `vol3 … netscan | grep -o <ip-regex> | sort | uniq -c | sort -rn` to rank
  intruder IPs, and `icat … | strings -n N | grep -o … | sort -u | head` to pull
  only distilled tokens. Practical equivalent of programmatic correlation within
  the sandbox — but single-tool only (can't join MCP tool outputs).
- Required next step: fix the ingest active-case resolver (see Optimization (b) /
  Missing Feature P0), run a real ingest, THEN do a proper assessment of
  opensearch_search/aggregate/timeline/detections. Until then this surface has
  zero real-world evaluation despite being the platform's core value.

### kb_search_knowledge (RAG)
- Tried: ground methodology (RDP event-source map; OneDrive/Dropbox artifact
  locations; cloud-exfil patterns).
- Friction: **very useful and accurate** for precise, artifact-named queries.
  Weak on vague queries — a broad "cloud exfil" query returned SQLite/macOS noise
  instead of Windows cloud-sync artifacts.
- Impact: positive when queried precisely; wasted one query when vague.
- Workaround: tightened queries to name specific artifacts/tools.

### kb_get_knowledge_stats
- Tried: backend health.
- Friction: none. Healthy (4318 chunks).

### run_command  — powerful but heavily constrained
- Tried: TSK (`fls`/`icat`/`istat` with `-i ewf`), vol3 plugins, registry via
  `rip.pl`, `strings`/`grep` pipelines, netscan correlation.
- Frictions (multiple, compounding):
  1. **Write-jail "no active case":** writes to `tmp/`, `extractions/`, or cwd
     are denied; **only `/tmp` is writable.** Blocks the normal
     "extract artifact → write → parse" flow. (Same active-case-resolution smell
     as the OpenSearch ingest failure.)
  2. **Per-stage / per-call uid isolation + 0600 umask:** a file written by one
     binary (e.g. `icat > /tmp/x`) is **unreadable by the next stage or call**
     (`rip.pl: Permission denied`). `/dev/stdin` piping is path-blocked. Net:
     **file-based parsers (rip.pl, EvtxECmd, RECmd, vol-to-file) cannot consume
     extracted artifacts.**
  3. **NTFS/WOF-compressed EVTX unreadable:** all Windows event logs are
     WOF-compressed; TSK `icat`/`istat` fail with
     `ntfs_uncompress_compunit: Phrase token offset is too large`. **Event-log
     analysis was impossible** — cost precise Nov-13 RDP source-IP correlation.
  4. **vol3 progress flood:** `windows.info` emitted **138,904 lines / 9.4 MB**
     of CR-based `Progress: …` to stdout (even with `2>&1`); `head` useless.
  5. **`strings | grep` long-line bloat:** matching whole binary string lines
     produced 300–600 KB responses that auto-saved and risked context blowout.
  6. **`grep -e`/`-E` flags blocked** as "dangerous" though harmless.
- Impact: forced everything into **single-command pipelines reading directly off
  the image** (no intermediate files). Lost file→file parsing entirely.
- Workarounds: pipelines like `icat … | strings -n N | grep -o … | sort -u | head`
  (distilled tokens only); `2>/dev/null` + grep-filter saved output to drop
  `Progress`; `grep -o` to emit only matched tokens; BRE `\|` alternation instead
  of `-e/-E`. Good provenance throughout (evidence_refs → sha256, audit_id).

### forensic-knowledge (FK) enrichment
- Tried: normal run_command / registry calls (enrichment is auto-bundled).
- Friction: the first run_command/registry call returned ~3 KB of advisory
  enrichment text appended to the response — useful once, bloat thereafter.
- Impact: per-call context bloat if left on.
- Workaround: set `skip_enrichment:true` on subsequent calls (had to repeat it).

### record_finding
- Tried: stage 9 DRAFT findings with grounding/audit_ids.
- Frictions:
  1. **`name 'hashlib' is not defined`** raised on every IOC-bearing finding
     (finding still staged, but noisy/alarming).
  2. Always reports grounding **WEAK / `forensic-rag-mcp missing`** even after KB
     searches were run — it does not credit the KB/audit_id grounding actually
     performed.
  3. **No `supersedes` field** for self-correction chains — had to overload
     `related_findings` to express "F-006 supersedes F-003".
  4. Nags that IPs are "in text but not in iocs list."
- Impact: cosmetic noise + can't cleanly express the supersession chain.

### record_timeline_event
- Tried: 6 timeline events.
- Friction: none material; good schema + provenance grading.

### manage_todo
- Tried: 7 TODOs to checkpoint state across the long run.
- Friction: none. Clean and reliable — the main defense against losing the thread
  across context growth.

### job_status / misc
- Tried: discovery of `env`/`printenv`/`regripper` availability.
- Friction: name/availability mismatches (`regripper` vs `rip.pl`; `vol3` vs
  `vol`) cost discovery cycles.

---

## 2. Optimizations wanted

### (a) Context efficiency
- **Tame noisy tool output at the gateway.** Auto-route vol3 progress to stderr
  or strip CR-based `Progress:` lines server-side; today a single `windows.info`
  produced 138k lines / 9.4 MB. Why: one noisy tool can blow the whole context.
- **Output projection / field selection.** A `fields=` / `max_line_length=`
  projection on search and on `strings`/`grep` results so the agent can't be
  forced to pull 300–600 KB lines. Why: keeps large forensic output bounded
  without an extra round-trip.
- **Server-side `grep`/`jq` on saved outputs.** The default "save large output +
  return summary + path" is good; add first-class tools to grep/jq the SAVED file
  so the agent targets content without re-running the producing tool. Why: turns
  a multi-call drill-down into one call.

### (b) Autonomy
- **Fix the active-case resolver for the OpenSearch backend AND the run_command
  write-jail** so they read the same DB active case `case_info` uses. This single
  fix restores the entire intended ingest/index/search workflow and lets the
  agent write under `agent/`/`extractions/`. Why: these two `no_active_case`
  failures were the biggest blockers of the run.
- **Accept either UUID or human `case_id` everywhere; align schema examples.**
  Why: the tolerant/strict split between `ingest_status` and `ingest` is a trap.
- **Solve the artifact-handoff problem** (see Missing Features) so the agent never
  has to juggle `/tmp` and never loses an extracted artifact between calls.

### (c) Flexibility
- **Make `extractions/`/`agent/` writable** under the case (group-readable, not
  0600 per-uid) so extracted artifacts survive across stages/calls. Why: enables
  the standard extract→parse forensic loop.
- **Relax the over-aggressive flag validator** — allow safe `grep -e/-E`; clearly
  enumerate blocked flags up front. Why: removes wasted cycles on harmless flags.
- **A real programmatic bridge** (see Missing Features) — even a scoped pipeline/
  code runner. Why: multi-tool correlation in one step cuts round-trips + context.

### (d) Enrichment
- **Credit KB/audit_id grounding in record_finding** so "WEAK / forensic-rag
  missing" reflects reality after KB searches were actually run. Why: the grounding
  signal is currently always wrong, which trains the agent to ignore it.
- **Hayabusa/detections surfaced as a first-class, queryable artifact** post-ingest
  (was never reachable here because ingest failed). Why: highest-signal starting
  point for intrusion timelining.
- **KB precision aids** — return source/platform facets so the agent can filter out
  macOS/SQLite noise on broad queries. Why: improves grounding on vague questions.
- **Make FK enrichment opt-in by default / skippable globally** (the first call
  returned ~3 KB advisory text). Why: avoids per-call enrichment bloat; `skip_
  enrichment:true` worked but had to be set repeatedly.

---

## 3. Missing features

Priority: P0 = blocked core workflow this run; P1 = major efficiency/accuracy;
P2 = quality-of-life.

- **P0 — WOF/NTFS-compressed file extractor.** TSK can't read WOF-compressed
  files; **all Windows event logs were unrecoverable** (`ntfs_uncompress_compunit:
  Phrase token offset is too large`). Ship a WOF-aware extractor (or `7z` /
  `dissect.target`). Would have unblocked: Security.evtx/RDP (EID 4624/4778/1149)
  source-IP + exact-time correlation for the 2020-11-13 break-in — the one thing
  this run could not pin precisely.

- **P0 — extract-inode→parse handoff.** A first-class "extract inode/MFT entry →
  parse with tool X" capability (or group-readable writes under `extractions/`) so
  file-based parsers (EvtxECmd, RECmd, rip.pl, vol-to-file) can consume extracted
  artifacts. Would have unblocked: registry hive + EVTX + prefetch parsing, which
  were impossible because per-stage 0600 isolation made every extracted file
  unreadable by the next tool.

- **P1 — programmatic callMCPTool bridge / sandboxed code runner.** `python3` and
  `node` are hard-blocked and there is no code→MCP bridge or token in the agent
  environment, so a script calling >1 MCP tool is impossible. A sandboxed runner
  (or a scoped `callMCPTool` shim) would let the agent correlate/filter multi-tool
  output in one step instead of approximating it with shell pipelines. Would have
  unblocked: cross-source correlation (memory IPs × browser history × registry
  MRU) in one audited call instead of many.

- **P1 — event-log timeliner tool.** A purpose-built EVTX→timeline tool (Hayabusa
  output surfaced, or EvtxECmd-as-a-tool) so the agent doesn't hand-assemble
  timelines from raw artifacts. Would have unblocked: the intrusion timeline that
  had to be inferred from memory + browser bursts instead of authoritative logs.

- **P1 — `supersedes` field on record_finding.** Native support for self-correction
  chains (F-006 supersedes F-003) instead of overloading `related_findings`. Would
  have improved: clean, auditable representation of the two self-corrections
  (Minecraft decoy; intrusion-timing refinement).

- **P2 — server-side grep/jq + field projection on saved outputs** (also listed
  under Context). A standalone "search the saved file" tool. Would have improved:
  every large-output drill-down (strings dumps, vol3 output).

- **P2 — fix record_finding IOC `hashlib` bug.** Tiny code fix; removes alarming
  noise on every IOC-bearing finding.

---

## Appendix — what worked well (keep)

- `case_info` / `evidence_info` — authoritative, accurate, the backbone.
- `manage_todo` — reliable checkpointing; the main defense against context loss.
- `run_command` provenance — evidence_refs → sha256 + audit_id on every call.
- `kb_search_knowledge` — accurate methodology grounding on precise queries.
- Default save-large-output + summary + path — right pattern; just needs the
  server-side grep/jq companion and projection to be complete.
- TSK-over-E01 (`-i ewf`) and vol3-in-place — solid once the agent gave up on the
  broken ingest path; carried the entire investigation to high-confidence answers.
