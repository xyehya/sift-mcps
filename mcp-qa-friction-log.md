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

## F-016 · CRITICAL · `_case` envelope duplicated on EVERY tool response — systemic token bleed

- **What:** Every single MCP tool response (all 68 tools, all 11 backends) includes a redundant
  `_case` wrapper:
  ```json
  "_case": {
    "id": "rocba-drive-20260526-1417",
    "dir": "/cases/rocba-drive-20260526-1417",
    "evidence_dir": "/cases/rocba-drive-20260526-1417/evidence",
    "agent_dir": "/cases/rocba-drive-20260526-1417/agent"
  }
  ```
  This is ~300 bytes (4 lines) of identical, never-changing data per response. An agent making
  50 tool calls per session wastes 15,000 bytes of context tokens on this alone. With case_id,
  evidence_dir, and agent_dir already available from `workflow_status` (the mandatory first
  call), this repetition has zero information value after the initial orientation.

- **Impact:** Over a multi-hour investigation producing 100–300 tool calls, the `_case` envelope
  alone burns 30,000–90,000 characters — about 7,500–22,500 tokens. This is context that could
  hold 5–10 additional search results, or a complete finding with evidence artifacts. It directly
  accelerates context compaction (the #1 failure mode the user named: "out of context with no
  results").

- **Where:** Injected by the gateway's MCP response normalization — appears in every backend
  tool response (`mcp_endpoint.py` or `server.py` response wrapper).

- **Proposed fix:**
  **(a) Immediate:** Remove `_case` from all individual tool responses. Keep it ONLY on the
  orientation tools where it matters: `workflow_status`, `case_status`, `environment_summary`.
  The agent already has `case_id` from the first call; paths are derivable.

  **(b) Elite approach — "Case Spine" pattern:** Instead of injecting a static envelope,
  produce a *case-header* only when the gateway detects a case boundary change (first tool call
  in a session, or when the portal switches cases). Otherwise, inject nothing. This is the MCP
  equivalent of HTTP `Connection: keep-alive` headers — stateful context, not per-message noise.

  **(c) Alternatively:** If removal is architecturally hard, compress to a single opaque
  reference: `"_case_ref": "rocba-drive-20260526-1417"` and have `case_status` resolve it.
  Every byte counts when context windows are the limiting reagent for autonomous investigation.

  **Token savings:** At 300 bytes/response × 200 calls = 60KB saved = the difference between
  the agent keeping 3 prior search results vs. losing them to compaction.

## F-017 · HIGH · `idx_search` error on malformed query is opaque — no self-correction path

- **What:** `idx_search(query='INVALID:SYNTAX:::test')` returns:
  `"Error executing tool idx_search: Query error: all shards failed"`
  That's the entire error. No hint about what was wrong, no suggestion for correction,
  no example of valid syntax. The agent has no lever to fix the query.

- **Why it matters for autonomy:** When an agent encounters a query error, the autonomy loop
  looks like:
  1. Try query → error
  2. Try with quotes → error
  3. Try with different field name → error
  4. Give up, miss the evidence → produce confidently-wrong finding

  The difference between a competent DFIR agent and a broken one is **how many self-correction
  attempts succeed before the agent gives up**. An opaque error puts the agent's error-recovery
  budget at $0.

- **Proposed fix:**
  **(a) Structured error envelope:**
  ```json
  {
    "error": "query_parse_failure",
    "detail": "Unexpected ':::' at position 8. Colon (:) is a field separator — use quotes for literal colons.",
    "invalid_query": "INVALID:SYNTAX:::test",
    "hint": "Try: query='user.name:admin' for exact field match, or wrap values with special chars in quotes: source.ip:\"::1\"",
    "examples": [
      "event.code:4624 AND user.name:admin",
      "process.name:*powershell*",
      "source.ip:\"192.168.1.1\""
    ]
  }
  ```

  **(b) Auto-correction heuristics:** Common failure patterns the gateway can detect and fix:
  - Triple colons `:::` → suggest quoting
  - Missing field colon `4624` → suggest `event.code:4624`
  - Unbalanced quotes → point to the break
  - Regex characters in literal strings `[2020` → suggest escaping or quoting

  **(c) Query preview mode:** `idx_search(dry_run=true)` that validates syntax and returns
  estimated hit count without fetching docs — the agent can iterate fast without paying
  the full token cost of a bad search.

## F-018 · HIGH · `idx_field_values` returns empty `[]` silently — agent cannot distinguish failure modes

- **What:** `idx_field_values(field='process.name', query='event.code:7045')` returned:
  ```json
  {"field": "process.name", "values": [], "truncated": false}
  ```
  Meanwhile `idx_count(query='event.code:7045')` confirms 41 matching docs exist. The values
  are NOT empty — the field `process.name` simply doesn't exist in the hayabusa index where
  those 7045 events live (hayabusa uses different field names). But the response gives zero
  indication of *why* it's empty.

- **Impact:** Agent sees `values: []` and concludes "no processes associated with 7045 events."
  This is a silent false-negative of the same class as F-003 and F-011. The agent has no way
  to know that `process.name` exists in other indices but not in the one that matched the query.

- **Proposed fix:**
  **(a) Diagnostic annotation on empty results:**
  ```json
  {
    "field": "process.name",
    "values": [],
    "truncated": false,
    "diagnostic": {
      "matching_docs": 41,
      "field_exists_in_matched_docs": false,
      "hint": "Field 'process.name' not found in documents matching 'event.code:7045'. Hayabusa-detected events use different field names. Try: field='Details' or check idx_case_summary(include_fields=true) for per-artifact field mappings."
    }
  }
  ```

  **(b) Cross-index field awareness:** `idx_case_summary(include_fields=true)` should be the
  canonical field-discovery mechanism, and `idx_field_values` should reference it when results
  are empty. Better yet: `idx_field_values` should auto-expand across all indices and return
  per-index field availability, so the agent can discover which indices actually have the field.

  **(c) Elite approach — "field intent resolution":** The gateway knows the case's index set
  and field mappings. When an agent queries `field='process.name'` on a query that only matches
  hayabusa indices (where the field is called something else), the gateway could auto-translate
  or at minimum warn: "process.name not in matched indices; did you mean hayabusa's
  'Details' field?"

## F-019 · MEDIUM · `idx_aggregate` returns opaque integer keys for event codes — requires external knowledge

- **What:** `idx_aggregate(field='event.code')` returns:
  ```json
  {"key": 5857, "count": 525},
  {"key": 4625, "count": 469},
  {"key": 4776, "count": 466},
  {"key": 5858, "count": 461}
  ```
  An LLM seeing `5857` has no idea this is "WinRM Operational" and that a count of 525 means
  heavy WinRM activity. Similarly, `4625` → "failed logon", `4776` → "credential validation",
  etc. The agent must either (a) already know these mappings from training data (unreliable for
  obscure codes) or (b) waste turns asking external knowledge.

- **Impact:** Distribution analysis is the #1 pattern an autonomous agent uses to orient:
  "what are the most common events?" → "what is unusual?" The tool gives numbers but not meaning.
  Without meaning, the agent can't prioritise. "Code 5857 has 525 occurrences" is inert data;
  "WinRM Operational has 525 occurrences, WinRM often dominates, consider excluding" is
  actionable intelligence.

- **Proposed fix:**
  **(a) Inline event code descriptions for common Windows events:**
  ```json
  {"key": 4625, "count": 469, "label": "Failed logon (4625)", "significance": "auth_failure"},
  {"key": 4624, "count": 312, "label": "Successful logon (4624)", "significance": "auth_success"},
  {"key": 4688, "count": 204, "label": "Process creation (4688)", "significance": "execution"},
  {"key": 7045, "count": 41,  "label": "Service installed (7045)", "significance": "persistence"}
  ```

  **(b) Maintain a static lookup of the top ~200 Windows Security event IDs + common
  Hayabusa rule titles (the `event.code` field in the hayabusa index uses Hayabusa
  internal codes, not Windows EIDs — this is the same F-003 normalization problem).**

  **(c) Elite approach:** Include `significance_category` tags (auth, execution, persistence,
  lateral_movement, defense_evasion, noise) to let the agent auto-filter:
  `"exclude noise, focus on persistence + lateral_movement events"` becomes a one-liner
  instead of "look up 15 event codes one by one."

## F-020 · MEDIUM · `check_system` / `check_artifact` baseline gaps return UNKNOWN on core Windows components

- **What:** `check_system(type='service', name='EventLog', os_version='Win10_21H2_Pro')` returns
  `"verdict": "UNKNOWN", "reasons": ["Service not in baseline"]`. But EventLog is a core
  Windows service present in every single Windows installation since NT 4.0. This is NOT
  unknown — it is definitively expected. The baseline database simply lacks an entry.

- **Impact:** An autonomous agent doing triage validation sees `UNKNOWN` on EventLog, svchost,
  or other core system components and can go down a rabbit hole investigating false positives.
  The current `interpretation_constraint` says "UNKNOWN requires context and does not confirm
  malicious persistence" — but this puts the classification burden on the LLM, which may not
  have the OS-specific knowledge to correctly classify a gap vs. genuine unknown.

  Worse: the agent is being trained to trust these tools. When they say UNKNOWN on definitively
  known entities, the agent learns "these tools are unreliable" and may stop using them entirely.

- **Proposed fix:**
  **(a) Tiered verdicts for gaps:**
  - `EXPECTED` — in baseline, confirmed expected
  - `EXPECTED_IMPLIED` — not in baseline, but matches a known pattern (core OS path, Microsoft-signed,
    standard Windows service name, system32 directory)
  - `UNKNOWN` — genuinely unknown, no heuristics apply
  - `SUSPICIOUS` — matches known-bad or anomalous patterns

  For `EventLog`, the tool should return `EXPECTED_IMPLIED` with reason:
  `"Core Windows service (present in all Windows installations); baseline entry not needed for
  confirmation."`

  **(b) Heuristic tier for path-based checks:** Any binary under `C:\Windows\System32\` that is
  Microsoft-signed and matches a known Windows component naming pattern should get
  `EXPECTED_IMPLIED`, not `UNKNOWN`.

  **(c) Minimum:** Add a `known_core_component` boolean to the response so the agent can see
  the system's internal classification vs. the baseline result.

## F-021 · HIGH · No index-to-artifact-type mapping tool — agent must guess where data lives

- **What:** The agent needs to answer "I want to query 4624 logon events → which indices?"
  The answer is: `case-rocba-drive-20260526-1417-hayabusa-srl-forge` AND
  `case-rocba-drive-20260526-1417-evtx-srl-forge` (with DIFFERENT field names in each).
  Currently the agent must:
  1. Call `idx_case_summary` to get artifact list (short tokens only: `hayabusa`, `evtx`)
  2. Manually derive full index names from the artifact-to-index mapping buried in
     `artifacts.{type}.indices[]`
  3. Know from DFIR training data that 4624 events live in both hayabusa and evtx
  4. Know that hayabusa uses `EventID` (string) while evtx uses `event.code` (integer)

  This is too many degrees of separation for reliable autonomous operation.

- **Impact:** F-012 already documented that short artifact tokens are rejected by `idx_search`.
  Even with that fixed, the agent has no way to discover "for query X, search indices A, B, C"
  without deep Windows event log knowledge that most LLMs have unreliably.

- **Proposed fix:**
  **(a) `idx_resolve_indices` tool:**
  ```json
  // Input: {"query_type": "logon_events", "event_ids": [4624, 4625]}
  // Output: {
  //   "indices": ["case-...-hayabusa-srl-forge", "case-...-evtx-srl-forge"],
  //   "field_mapping": {
  //     "hayabusa": {"event_id_field": "EventID", "timestamp_field": "Timestamp", "is_date_typed": false},
  //     "evtx": {"event_id_field": "event.code", "timestamp_field": "@timestamp", "is_date_typed": true}
  //   },
  //   "preferred_index": "case-...-evtx-srl-forge",
  //   "preferred_reason": "Native EVTX has date-typed @timestamp; Hayabusa Timestamp is text (see F-011)"
  // }
  ```

  **(b) Least-effort fix:** `idx_case_summary` should return index names directly alongside
  artifact tokens, and include field-type mappings by default (not behind `include_fields=true`).
  The current `include_fields` parameter is a discoverability trap — most agents won't know
  to pass it.

  **(c) Elite approach — "intent-based query routing":** `idx_search(query='event.code:4624')`
  should internally expand to search both evtx AND hayabusa indices, translating field names
  as needed. The agent writes one query; the gateway resolves to the right indices. This is
  how GraphQL resolvers work and it's the right pattern for multi-source data federation.

## F-022 · MEDIUM · `generate_report` output is massive even for `executive` profile — no compact mode

- **What:** `generate_report(profile='executive')` returned 200+ lines containing:
  - 5 full finding documents with observation/interpretation/justification (some 500+ words each)
  - 50+ verification_alerts entries
  - Full writing_guidance block
  - 5 human_review_required sections with prompts
  - Full zeltser_guidance tool list

  The agent asked for a 1-2 page executive summary and got raw data + metadata at ~15KB.

- **Impact:** Report generation is the culmination of an investigation. An agent needs to
  iterate: generate → review structure → identify gaps → regenerate. If every iteration
  costs 15KB of context, the agent can iterate 3-4 times before context exhaustion. This is
  incompatible with the autonomous workflow the user wants.

- **Proposed fix:**
  **(a) Two-phase report generation:**
  - Phase 1 — `generate_report(profile='executive', preview=true)`: returns ONLY the section
    structure, summary counts, and writing guidance. No raw finding text. ~500 bytes.
  - Phase 2 — `generate_report(profile='executive', sections=['findings'])`: returns only
    the requested sections. Agent pulls sections one at a time as needed.

  **(b) Smart projection:** The executive profile should include finding titles + 1-line
  summaries, not the full observation/interpretation. The agent can request full detail
  for specific findings via `finding_ids=[...]`.

  **(c) Remove verification_alerts from the default report response.** These are integrity
  metadata, not report content. Provide a separate `report_integrity` endpoint or a
  `include_verification=false` default.

## F-023 · MEDIUM · `search_threat_intel` truncates MITRE descriptions mid-sentence

- **What:** `search_threat_intel(query='APT28')` returns threat actor descriptions that are
  cut off mid-word:
  `"...GRU 85th Main Special Service Center (GTsSS) military unit 26165.(Citat"`
  The MITRE description text is truncated, losing the reference and potentially critical
  details about the threat actor's TTPs.

- **Impact:** The agent sees a truncated description and cannot determine whether the missing
  portion contains relevant indicators. For attribution work (which the user specifically asked
  for in T-B), this is a hard block.

- **Proposed fix:** Increase the text field length limit in the OpenCTI MCP backend. The
  descriptions are pulled from the OpenCTI API and likely truncated by a `text[:N]` or
  `str[:max_length]` in the response serialization. MITRE descriptions can exceed 500 chars —
  budget at least 2,000.

## F-024 · LOW · `environment_summary` output is enormous — defeats its purpose as an "overview"

- **What:** `environment_summary` returns all 6 backend health checks with full tool output
  inline — `evidence_list` result, `idx_status` with all 25 indices, `get_knowledge_stats`
  with 67 sources, `server_status` with all cache statistics, and `list_available_tools`
  with all 65 tools. The response is ~15KB.

  An agent wanting a quick "are we ready?" check gets a firehose of data it didn't ask for.

- **Impact:** The tool's own description says: "Single-call environment overview. Call this
  after workflow_status for a complete picture of platform readiness." But calling it means
  burning 15KB of context on data the agent already has or doesn't need yet. Agents will
  stop calling it, making the "single-call overview" pattern useless.

- **Proposed fix:**
  **(a) Default to health-only:** Return `{backends: {name: {status, degraded_since?}}}` on
  default call. The agent just wants to know "everything green?"

  **(b) Add `detail` parameter:** `environment_summary(detail='full'|'health'|'stats')`.
  Default to `health`. Agent escalates detail only when something is degraded.

  **(c) The elite inversion:** Instead of a giant aggregate response, make it a push-based
  health dashboard: the gateway emits a `health_summary` event at session start and on state
  change. The agent never needs to poll for health — it's reported proactively.

## F-025 · MEDIUM · `idx_field_values` and `idx_aggregate` need `.keyword` suffix for CSV/registry fields — undiscoverable

- **What:** The tool description for `idx_aggregate` notes:
  `"CSV/registry fields (Path, KeyPath, ValueData) require .keyword suffix: field='Path.keyword'"`
  This is buried in the description text. An agent scanning quickly may miss it.
  If it queries `field='Path'` (no suffix), it gets the text-analyzed version which returns
  tokenized garbage instead of the actual path — or worse, an error.

- **Impact:** Middle of the discoverability spectrum — the info IS present, but an agent
  making 50+ tool calls may not re-read descriptions on each call. The first time it hits
  this, it wastes a turn debugging "why are my Path results showing 'users' and 'windows'
  instead of 'C:\Users\...'"

- **Proposed fix:**
  **(a) Auto-suffix when needed:** If the field is known to be a text/analyzed type and the
  `.keyword` sub-field exists, the gateway should auto-append `.keyword` and return a note:
  `"field 'Path' auto-resolved to 'Path.keyword' (text field, using keyword sub-field for
  exact matching)."`

  **(b) Minimum:** When an aggregation returns obviously tokenized results (single-word
  values for a path-like field), the response should include a hint: "Results appear
  tokenized. If querying file paths, use field='Path.keyword' for exact values."

  **(c) `idx_case_summary` field metadata should be surfaced by default**, not behind
  `include_fields=true`. The agent needs to know field types to write correct queries.

## F-026 · LOW · `set_case_metadata` accepts potentially invalid enum values

- **What:** `set_case_metadata(field='severity', value='critical')` returned `"status": "set"`.
  The tool silently accepted the value without confirming it's a recognized severity level.
  The SIFT/CASE spec may define a specific severity enum — if "critical" isn't valid, the
  error will surface later (e.g., during report generation), far from the set point.

- **Proposed fix:** Return valid options alongside accepted values, or reject unknown enum
  values with a list of valid options (mirrors the pattern already used for protected/unknown
  fields).

## F-027 · INFO · Positive: `record_finding` validation is excellent — gold standard for input guarding

- `record_finding` with a deliberately incomplete payload returned:
  ```json
  {
    "status": "VALIDATION_FAILED",
    "errors": [
      "Missing required field: observation",
      "Missing required field: interpretation",
      "Missing required field: confidence",
      "Missing required field: type",
      "Missing required field: host",
      "Missing confidence_justification (FD-005: confidence must be justified)"
    ],
    "guidance": ["FD-005: Confidence must be justified — cite specific evidence for your confidence level"]
  }
  ```
  This is exactly what an autonomous agent needs: clear, field-level, actionable errors with
  rule references. The agent can fix all 6 issues in one shot and retry. This pattern should
  be replicated across ALL mutation tools (`record_timeline_event`, `manage_todo`, etc.).

## F-028 · INFO · Positive: `get_tool_help` response is the blueprint for tool discoverability

- `get_tool_help(tool_name='vol3')` returns:
  ```json
  {
    "investigation_sequence": ["Start with windows.info...", "Run windows.pslist...", ...],
    "field_meanings": {"PID": "Process identifier", "PPID": "Parent process identifier", ...},
    "advisories": ["Always run pslist AND psscan — comparing results reveals HIDDEN PROCESSES..."],
    "caveats": ["Requires a full physical memory dump...", "Anti-forensics techniques..."],
    "quick_start": "vol -f memory_dump.raw windows.info",
    "cross_mcp_checks": [...]
  }
  ```
  This is the platonic ideal of a tool-help response. It provides: workflow sequence (HOW to use
  the tool in an investigation), field meanings (WHAT the output columns mean), advisories
  (WHAT to watch for), and cross-MCP integration hooks (WHERE to go next). Every tool in the
  catalog should aspire to this depth. The `investigation_sequence` field in particular is the
  missing piece that would make `list_available_tools` + `get_tool_help` a self-contained
  onboarding path for an agent encountering an unfamiliar forensic tool.

## F-029 · MEDIUM · No `case_id` / session affinity is visible in the tool contract — agent cannot self-confirm context

- **What:** The active case is set by the portal and propagated via `AGENTIR_CASE_DIR`.
  The agent gets `case_id` from `workflow_status` and then passes it to Opensearch tools.
  But many tools (evidence_list, case_status, etc.) auto-resolve the case from the environment
  with no `case_id` parameter. The agent has no way to know: "am I still operating on the
  right case?"

- **Why it matters:** In a multi-case investigation, if the portal switches the active case
  mid-session, the agent's tool calls silently start operating on the wrong case. Context
  compaction could drop the `case_id` knowledge entirely. The agent needs a cheap way to
  re-confirm "I'm still on case X" without re-calling `workflow_status` (which is heavy).

- **Proposed fix:**
  **(a) `case_identity` tool:** A zero-parameter, sub-100-byte response:
  ```json
  {"case_id": "rocba-drive-20260526-1417", "context_confirmed": true}
  ```
  The agent calls this before every mutation (record_finding, manage_todo, idx_ingest) to
  confirm context. Cost: 1 token in, ~10 tokens out.

  **(b) Include `case_id` in the tool response header (not the full `_case` envelope — just
  the ID). This adds ~20 bytes per response, a 10× improvement over the full `_case` block.**

## F-030 · LOW · `idx_inspect_container` returns `aquairy_info` (typo for `acquiry_info`)

- **What:** The description says `acquiry_info` but the actual response key is `acquiry`.
  Small, but an agent that extracts fields by key name will miss it. The agent description
  promises one key; the response delivers a differently-named key.

- **Proposed fix:** Standardize to `acquiry_info` (or fix the description to match `acquiry`).

## F-031 · HIGH · `run_command` policy is opaque — blocked commands lack safe equivalents

- **What:** During live core-only ROCBA workflow, the agent hit several policy blocks that were
  understandable individually but hard to predict: multi-command `sh -c` with semicolons,
  awk regex alternation interpreted as a pipe operator, Python snippets blocked for shell
  metacharacters, and relative output directories rejected where absolute paths worked.

- **Impact:** The agent burns turns discovering the execution policy by trial and error. This is
  particularly expensive under context compaction because every failed attempt adds noisy
  state but does not advance the investigation.

- **Proposed fix:** Add a small `run_command_policy` / `executor_policy` tool or include a
  compact policy block in `get_tool_help('run_command')`: allowed shells, redirects, relative
  output path rules, blocked metacharacters, allowed safe filter patterns, and 5-10 approved
  DFIR examples. Block responses should include the exact rejected token and a safe equivalent.

## F-032 · HIGH · No safe batch/workflow primitive for common DFIR command sequences

- **What:** Security correctly blocks arbitrary shell chaining, but DFIR work naturally requires
  short sequences: extract artifact → parse artifact → filter result → summarize. Without a
  first-class safe batch primitive, the agent spends 3-5 MCP calls per obvious workflow.

- **Impact:** This slows investigation and multiplies boilerplate responses, `_case` envelopes,
  audit wrappers, and compaction pressure. The agent is pushed toward unsafe shell idioms
  because the platform lacks a safer equivalent.

- **Proposed fix:** Add a declarative `run_workflow` / `run_pipeline` primitive where each step is
  still individually validated, audited, and path-jailed:
  ```json
  [
    {"tool": "icat", "args": ["agent/mounts/ewf/ewf1", "279894"], "output": "agent/exports/evtx/foo.evtx"},
    {"tool": "EvtxECmd", "args": ["-f", "agent/exports/evtx/foo.evtx", "--csv", "agent/analysis/evtx"]},
    {"tool": "grep", "args": ["52.249.198.56", "agent/analysis/evtx/foo.csv"]}
  ]
  ```
  Return a compact execution graph with step status, audit IDs, output paths, warnings, and
  final selected output only.

## F-033 · HIGH · `run_command.success` can hide parser partial failure

- **What:** Forensic tools can return process exit 0 while printing argument errors, skipped
  files, invalid signatures, or partial parse failures. In the live run, EvtxECmd returned
  success while printing `Unrecognized command or argument`, `is not an evtx file`, and
  Security.evtx parse errors.

- **Impact:** An agent can treat `success:true` as "artifact parsed cleanly" and then make a
  false-negative finding from missing events. This is the same autonomy-killer class as
  silent 0-hit index queries.

- **Proposed fix:** Add tool-specific warning classifiers for common parser output. At minimum,
  scan stdout/stderr for patterns like `Unrecognized command`, `Error processing`, `Skipping`,
  `Invalid signature`, and `is not an evtx file`, then return:
  ```json
  {"success": true, "warnings": ["parser_partial_failure"], "agent_action": "Inspect parser stdout before relying on absence of events"}
  ```

## F-034 · MEDIUM · `run_command` previews can still be too noisy for autonomous loops

- **What:** Save-to-file behavior is good, but some commands still preview verbose help,
  parser metrics, or broad grep output into the active context.

- **Impact:** The agent needs progressive disclosure. Repeated verbose previews consume the
  same scarce context budget needed for evidence, hypotheses, and open questions.

- **Proposed fix:** For known high-volume tools, default to compact summaries: line count,
  stdout/stderr bytes, output path, hash, warnings, and at most the top relevant lines.
  Let the agent explicitly request slices via `grep_file`, `head`, `tail`, or `preview_lines`.

## F-035 · HIGH · Derivative provenance is not first-class

- **What:** The agent extracted EVTX from sealed E01, parsed CSV, grepped rows, and then tried
  to record a finding. The evidence chain was conceptually sound, but `record_finding`
  rejected artifact sources and later staged with partial provenance.

- **Impact:** This breaks the normal DFIR chain: original evidence → extracted artifact →
  parsed derivative → selected evidence row → finding. If the platform cannot model that
  chain cleanly, autonomous findings are either blocked or downgraded despite correct work.

- **Proposed fix:** `run_command` should emit derivative provenance when `input_files` and
  output paths are present. `record_finding` should accept derivative paths and resolve them
  back to sealed evidence via audit IDs. `supporting_commands` should expose an explicit
  `audit_id` field rather than forcing audit IDs into free-text excerpts.

## F-036 · MEDIUM · Missing safe convenience wrappers force shell-shaped workarounds

- **What:** The agent needed common operations: extract inode to file, grep saved output, parse
  EVTX, summarize CSV fields, run strings with filters, inspect file metadata. Several require
  redirects, shell snippets, awk, or Python when no wrapper exists.

- **Impact:** The platform's security model is strongest when agents do not need shell syntax.
  Without wrappers, useful DFIR actions look suspicious and get blocked, or agents waste turns
  finding allowed approximations.

- **Proposed fix:** Add small forensic file-operation tools: `extract_inode`, `grep_file`,
  `parse_evtx`, `summarize_csv`, `strings_search`, and `safe_pipeline`. These should be
  provenance-aware, path-jailed, compact by default, and auditable.

## F-037 · MEDIUM · Tool catalog gaps undermine live skill reliability

- **What:** Useful SIFT support tools (`ewfinfo`, `img_stat`, `fsstat`, `pinfo.py`, `ewfverify`)
  were present and executable but missing from the catalog/FK enrichment, while downloaded
  skills pointed at stale paths.

- **Impact:** Agents are forced into live trial-and-error and may distrust the tool discovery
  surface. Skills become brittle if they use static filesystem paths instead of the live catalog.

- **Proposed fix:** Catalog common SIFT support tools, not only headline analyzers. Skills should
  resolve tools through `check_tools`/catalog metadata before running commands.

## F-038 · HIGH · `run_command` should optimize for forensic workflow execution, not raw command execution

- **What:** The current executor is useful but still exposes the agent to low-level command
  mechanics: blocked metacharacters, output path quirks, parser stdout interpretation, and
  manual derivative provenance.

- **Impact:** The autonomy failure is not "the agent cannot run arbitrary shell." The failure is
  "the agent cannot see the safe forensic equivalent, cannot trust success semantics, and loses
  context to repeated low-level ceremony."

- **Proposed fix:** Treat `run_command` as the substrate, but expose higher-level audited
  forensic workflows above it. Restrictions should be predictable, explained, paired with safe
  alternatives, compact in output, and provenance-preserving.

---

## Design Principles for Autonomous Agent DFIR (from these findings)

1. **Every byte in a tool response is a byte the agent CANNOT use for evidence in context.**
   The `_case` envelope, verbose `environment_summary`, and full-finding `generate_report`
   responses all violate this principle. Treat tool response payloads as a zero-sum budget
   against the context window.

2. **Silent false-negatives are worse than errors.** F-003 (empty event.code on hayabusa),
   F-011 (date range silently 0), and F-018 (empty field values with no diagnostic) are the
   same failure class: the tool says "nothing here" when there IS something. An error the
   agent can see and fix is recoverable. A silent empty set is an investigation-killer.

3. **The agent's "field discovery loop" must be O(1), not O(n).** Currently, to answer
   "what field holds the event ID in index X?" the agent must: call idx_case_summary,
   re-call with include_fields=true, parse the field mappings, cross-reference with the
   artifact type. That's 3 calls and ~5KB of tokens. A unified `idx_resolve_indices` tool
   collapses this to 1 call / ~200 bytes.

4. **Mutation tools need `record_finding`-quality validation.** F-027 shows the gold
   standard: field-level errors, rule references, fixable in one shot. `manage_todo`,
   `record_timeline_event`, and `set_case_metadata` should match this.

5. **Tool discovery should be knowledge-driven, not search-driven.** `get_tool_help` (F-028)
   is excellent because it organizes information the way a DFIR investigator THINKS:
   "first do X, then Y, watch out for Z." The `investigation_sequence`, `field_meanings`,
   and `cross_mcp_checks` fields should be standard on every tool-help response. The agent
   should be able to `get_tool_help('evtx')` and receive a complete mini-playbook, not just
   flags and caveats.

6. **Date/time must work universally or fail loudly.** F-011 showed that date ranges on
   hayabusa's `Timestamp` field silently return 0. The fix isn't just hayabusa-specific —
   every tool that accepts `time_from`/`time_to` should validate that the target index's
   timestamp field is `date`-typed, and warn if it's not.

---

## Hard rule
- Do NOT generate_report() until the deeper layer resolves. Premature report = the failure the
  committee is hinting at.
