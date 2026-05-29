# MCP QA / Friction Log — Rocba Case as Agent Probe

Method: run the investigation forward as the autonomous DFIR agent would. Every friction
point, missing artifact, wrong turn, token blowup, or missing guardrail is a deliverable.
Each entry: ID · Severity · What happened · Where (tool/file) · Proposed fix.

---

## F-001 · MEDIUM · `list_existing_findings(limit=0)` exceeds token cap
- **What:** Listing all 26 findings returned 83,332 chars → blew the MCP output token cap;
  forced a dump-to-file + jq workaround. There is no compact/summary projection.
- **Impact:** An agent orienting on an active case cannot read its own prior findings in one
  call. Wastes a full turn on a workaround. On a real case this is a hard wall.
- **Proposed fix:** Add a `fields=` / `compact=True` projection to `list_existing_findings`
  (id, title, status, confidence, type, mitre_ids only). Mirror the `compact` pattern already
  in `idx_search`. Default the full payload only when a single `id=` is requested.

## F-002 · MEDIUM · No investigation plan/state is persisted (`manage_todo` empty)
- **What:** 26 findings + 22 timeline events produced, but `manage_todo(list, all)` is empty.
  The prior agent never scaffolded a goal-driven plan; nothing maps actions → case questions.
- **Impact:** This is the "out of context with no results" failure mode the user named. No
  durable spine an agent can resume from; HITL examiner can't see investigative intent.
- **Proposed fix:** workflow_status / case_status should nudge or seed a TODO skeleton from the
  5 case questions on first session. Consider a soft gate: record_finding suggests linking to
  an open TODO. Make the goal→action→verify loop a first-class scaffold.

---

## Investigation theory tracking (don't anchor — discriminators required)

The 5 surface questions are largely answered by F-claude-001..018 / F-lms-001..008.
"More than the surface" = a different axis. Three unanchored threads:

- **T-A · shieldbase.lan pivot (F-lms-002):** only proves Default.rdp was *present/configured*.
  DISCRIMINATOR: was the pivot to base-rd-08.shieldbase.lan actually USED? Search evtx/hayabusa/
  SRUM/netscan for outbound conn to that host/subnet + EID 4648 explicit-cred events.
- **T-B · attribution (threat_intel NOT run):** idx_enrich_intel() never executed. Cheap, live
  OpenCTI/MITRE/KEV. Link Azure 52.249.198.56 / WIIT-AG DE / Verizon 174.196.200.9 to a named actor.
- **T-C · insider complicity (Fred):** exfil lands in Fred's OWN personal accounts; BitLocker keys
  uploaded to Fred's OWN Google Drive. DISCRIMINATOR: were personal accounts the destination
  (Fred benefits) or compromised conduits (attacker throwaway)? Any activity conflicting with
  "Fred at Disney, uninvolved"?

## Findings to AUDIT (possible confidently-wrong inherited claims)
- **MRC.exe (F-003/F-004):** Magnet RAM Capture is a legit IR tool; briefing says Fred was told to
  leave laptop ON for SRL remote IR team. Nov 16 02:31 MRC run may be RESPONDERS, not attacker.
- **EDT/UTC normalization:** Nov 13 ~22:42 EDT = Nov 14 03:42 UTC. Reconciles, but every timing
  claim must be explicit about TZ or it drifts.

## F-003 · HIGH · Canonical ECS field `event.code` is EMPTY for Hayabusa-sourced events
- **What:** `idx_search(event.code:4648)` returned **0**. The 4648 explicit-logon events DO exist —
  but under Hayabusa's string field `EventID:4648` in the hayabusa index. The native evtx index
  uses `event.code` (integer); hayabusa uses `EventID` (string). No unified field.
- **Impact:** SEVERE finding-quality risk. An agent querying the documented canonical field
  (`event.code`, which idx_case_summary's own investigation_hints recommend) gets a false negative
  and can wrongly conclude "no explicit-credential logons / no lateral movement exist." This is
  exactly how a confidently-wrong finding gets made. I nearly missed the entire shieldbase pivot.
- **Proposed fix:** (a) Normalize at ingest: map Hayabusa `EventID`→`event.code` (int) and
  `Channel`→`winlog.channel` so one query spans both. (b) Until then, idx_case_summary hints and
  the opensearch instructions MUST warn that event.code only covers native-evtx docs and that
  Hayabusa detections require `EventID:` (string). (c) Best: a cross-source field alias.

## F-004 · MEDIUM · Naive keyword search over all indices is dominated by tokenizer noise
- **What:** `idx_search("shieldbase OR base-rd-08")` (unscoped) returned 2,428 hits topped by amcache
  driver binaries / WER / tasks — the analyzer matched "base" inside "Base System Device" etc.
  The signal (RDP-Cli events) was buried. Scoping to an index + quoting phrases fixed it.
- **Impact:** An agent doing a first-pass keyword sweep gets a wall of false positives and may give
  up or anchor on noise. High token cost for low signal.
- **Proposed fix:** idx_search could expose a `match_phrase`/exact mode, or auto-quote multi-token
  values, or surface a hint when result count is high + relevance is flat ("results look like
  tokenizer noise — try quoting the phrase or scoping with index="). Document phrase-quoting in the
  tool description prominently (currently only a terse note).

## F-005 · LOW · IOC-completeness validator false-positive on a provided IOC
- **What:** record_finding warned: "1 value(s) in text but not in iocs list: 172.16.6.18" — but
  172.16.6.18 WAS passed explicitly as {"value":"172.16.6.18","type":"ipv4-addr"}. iocs_extracted=4.
- **Impact:** Erodes trust in the validator; agent may waste a turn "fixing" a non-issue or, worse,
  learn to ignore the warning (then miss real omissions).
- **Proposed fix:** The completeness check should dedupe against the structured iocs list (by value)
  before warning. Likely the regex scan of `text` runs independent of the structured-IOC parse.
  Also: confirm the accepted type token — "ipv4-addr" (STIX) vs "ip"/"ipv4" may not be recognized.

## F-006 · LOW · `provenance_grade: PARTIAL` with no actionable guidance on reaching FULL
- **What:** Finding graded PARTIAL because audit_ids were given but no `artifacts` raw-evidence blocks.
  The response lists generic "considerations" but doesn't say "attach artifacts[] to reach FULL."
- **Proposed fix:** Make the grade rubric explicit in the response (what FULL requires vs PARTIAL),
  so the agent knows the concrete lever. Ties into UX ux-bug-fix CLR-005 (grade badge legend).

## F-007 · CRITICAL · [RESOLVED 2026-05-29] forensic-rag reported HEALTHY but was non-functional
- **RESOLUTION:** Ran `.venv/bin/python -m rag_mcp.scripts.download_index` on the VM — downloaded
  rag-index-v2026.03.01 (chroma.sqlite3 ~138MB), HNSW test query OK, restarted gateway, verified
  search_knowledge returns status:ok. The underlying capability/health-mismatch bug REMAINS open
  (see proposed fix b/c below) — health still reports forensic_rag:true even when index absent.
- **What:** All `search_knowledge` calls return `internal_error: "RAG knowledge index not found.
  The installer may have been run with --skip-rag, or the download step failed."` — yet
  `workflow_status.available_capabilities.forensic_rag = true` and AGENTS.md claims 22,268 records.
- **Impact:** The single worst failure class: a capability the agent is TOLD it has, that silently
  doesn't work. An autonomous agent would route knowledge questions to RAG, get errors, and have no
  fallback. The whole "ride a solid DFIR path" premise leans on RAG being there.
- **Proposed fix:** (a) Health/capability check must actually probe the index (load test), not just
  "backend process up". workflow_status should report forensic_rag:false or :degraded when the index
  is missing. (b) Installer: make `download_index` non-skippable or verify post-install. (c) On VM
  now: `python -m rag_mcp.scripts.download_index`. **Blocks the user's RAG queries this session.**

## F-008 · MEDIUM · suggest_tools advertises artifact tokens it cannot answer
- **What:** suggest_tools returns the canonical `available_artifacts` list, but querying two of those
  exact tokens — `Memory Analysis (Volatility)` and `USN Journal` — returns "No tools found". `MFT`
  returns a rich, excellent response (tools + corroboration map + cross-MCP checks + discipline).
- **Impact:** The knowledge map has holes precisely at MEMORY (the key artifact in this case — we
  have Rocba-Memory.raw) and USN. An agent asking the documented way gets nothing and may assume no
  tooling exists for memory, when vol3 + bulk_extractor are installed and available.
- **Proposed fix:** Either populate suggestions for every advertised artifact token, or have the
  list only expose tokens the resolver can answer. Add memory→{vol3 plugins, bulk_extractor, strings}
  and usn_journal→{MFTECmd -f $J, fls}.

## F-009 · LOW-MED · list_available_tools(category=) silently returns empty for wrong category
- **What:** `list_available_tools(category="memory")` → `{tools:[], count:0}`. The real category is
  `volatility`. No error, no "valid categories are…", no fuzzy match. Bare call returns all 65.
- **Proposed fix:** On unknown category, return the valid category set (analysis, file_analysis,
  malware, misc, network, sleuthkit, timeline, volatility, zimmerman) instead of an empty list.

## F-010 · INFO · Positive: the MFT suggest_tools response is the gold standard
- The MFT response (tools + availability + what_it_reveals/does_not_reveal + corroboration map +
  cross_mcp_checks + discipline_reminder) is exactly the scaffolding the agent needs. The fix for
  F-008 is to bring memory/USN up to THIS quality bar, not to lower this one.

## F-011 · CRITICAL · Lucene date-range on hayabusa `Timestamp` silently returns 0 (false negative)
- **What:** `idx_count(query='EventID:4624 AND Timestamp:[2020-11-16T00:00:00 TO 2020-11-16T03:30:00]')`
  returned 0. So did a bare `Timestamp:[... TO ...]` for all events, AND a 4778 range that I had just
  proven contains an event at 02:29:36. Meanwhile `EventID:4624` (no range) = 93. The hayabusa
  `Timestamp` field is stored as text ("2020-11-16 02:29:36.951 +00:00"), not a `date` type, so range
  queries match nothing and return **0 with no error**.
- **Impact:** SAME class as F-003 — the documented/obvious way to time-bound a query yields a silent
  false-negative. I nearly concluded "no logons in the window" from a broken filter. On a real case
  this manufactures confidently-wrong "absence of evidence" findings.
- **Proposed fix:** (a) Map `Timestamp` (and all event-time fields) as OpenSearch `date` at ingest, or
  add a normalized `@timestamp` date field across ALL indices (evtx already has one; hayabusa should
  too). (b) Until then, idx_search/idx_count must reject/down-rank range syntax on non-date fields
  with a warning, OR expose explicit `start=`/`end=` params that the gateway translates to a proper
  range on a known date field. (c) Workaround that works: pull with `fields=` + small set and filter
  dates client-side, or use idx_timeline.

## F-012 · MEDIUM · `idx_search(index=)` rejects the artifact tokens `idx_case_summary` advertises
- **What:** `idx_case_summary` lists artifacts by short token (`vol-pstree`, `registry`, ...). Passing
  `index='vol-pstree'` to idx_search errors: "Index segment 'vol-pstree' must start with 'case-'".
  You must pass the full `case-rocba-drive-20260526-1417-vol-pstree-srl-forge`. Cost a wasted turn.
- **Proposed fix:** Accept the short artifact token and expand it internally (case_id + host are known
  from the active case), or have idx_case_summary surface the full index name alongside the token.

## F-013 · MEDIUM · `idx_search(size=)` ignored; `compact` insufficient on broad queries → token-cap blowups
- **What:** Several idx_search calls blew the MCP output token cap even with `compact=true`
  (60k–120k chars saved to file). Also `size=30` returned 50 docs (the param appears ignored / capped
  at a default 50). Broad queries (e.g. unscoped MRC search, an IP that turns out to be a brute-force
  source with 10k+ hits) dump huge verbose payloads before the agent can tell the query was too broad.
- **Impact:** Repeated context-killing dumps; the agent must defensively route every search through a
  file + jq/python. Directly the "log output fills the context window" failure the user flagged.
- **Proposed fix:** (a) Honor `size`. (b) Make `fields=` projection the default-encouraged path (it
  WORKS great — see F-014) and/or auto-truncate verbose source fields harder in compact mode.
  (c) When `total` is very large or relevance is flat, return a short summary + counts instead of docs
  and hint "narrow with index=/fields=/idx_count" (mirror the existing tokenizer-noise idea in F-004).

## F-014 · INFO · Positive: `idx_search(fields=...)` is the clean fix for token blowups
- Passing `fields='Timestamp,EventID,Details,RuleTitle'` returned all 12 Type-10 logons in one tidy
  response with zero file-dump. This projection should be documented prominently and suggested by the
  tool whenever a result would otherwise exceed the cap.

## F-015 · LOW · No way to amend/reject/supersede an existing finding via MCP
- **What:** `record_finding` is append-only (DRAFT). When an audit refutes prior findings
  (F-claude-004/012/013), there is no MCP path to mark them superseded/rejected — only `related_findings`
  linkage on a NEW finding. Correction relies on a human running `agentir approve`/reject out-of-band.
- **Impact:** The case record accumulates contradictory DRAFTs; an agent generating a report could pull
  the wrong (un-rejected) ones. The corrected narrative depends entirely on the human reading the audit
  finding's `related_findings` and acting.
- **Proposed fix:** Add `supersede`/`status_override` (with justification + audit_ids) to record_finding,
  or a `manage_finding(action=reject/supersede)` tool, so an agent can stage a status change for human
  approval — same HITL gate, but the link is explicit and machine-actionable.

---

## Hard rule
- Do NOT generate_report() until the deeper layer resolves. Premature report = the failure the
  committee is hinting at.
