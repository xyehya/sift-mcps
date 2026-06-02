# Phase 6 GATE — live e2e QA log

> Structured ledger for the MVP-completion run (full add-on install + ROCBA e2e on the
> live VM, 192.168.122.81). Append as you go; triage at the end of each stage; fix every
> **blocker/major** before advancing and re-run the affected stage.

## Framing (do not drift)

The **SIFT Protocol Gateway (SPG)** *is* the product: core + gateway + portal + the agent's
in-process MCP server. It is complete on its own (`install.sh --core-only`). OpenCTI,
OpenSearch, windows-triage, and forensic-rag are **external, independent, optional** add-on
backends — *reference implementations* of the SIFT MCP Backend Contract. An operator runs
any subset (including none) or brings their own conformant backend. There is exactly **one**
integration door for all of them: point the portal at a `sift-backend.json` manifest →
validate against the spec → register → hot-reload. The core never special-cases a backend.

## Run metadata

| | |
|---|---|
| VM | 192.168.122.81 (sansforensics / forensics) |
| Branch / commit | revamp/spg-v1 @ _(fill at close)_ |
| Evidence set | ROCBA (23 GB `.e01` + 19 GB RAM) |
| Service token | _(record `sift_svc_*`, redacted, at close)_ |
| Case path | _(fill)_ |

## Severity scale

`blocker` = stops the gate · `major` = wrong behavior, must fix before MVP · `minor` =
works but rough · `cosmetic` = wording/UX nit.

## Optimization baseline

Baseline backlog: [`mcp-qa-friction-log.md`](../../mcp-qa-friction-log.md).

Use that older ROCBA agent-probe assessment as the standing optimization baseline for
autonomous DFIR ergonomics: token economy, silent false-negative prevention, field
discovery, mutation validation, persisted investigation state, and report/query compactness.
This Phase 6 log remains the live gate ledger. When a live issue repeats or confirms a
baseline friction pattern, log the concrete Phase 6 defect here and cross-reference the
baseline `F-*` item rather than duplicating the full older writeup.

Scope note: many baseline items are add-on/indexed-backend scoped (`idx_*`, threat intel,
Hayabusa/OpenSearch/RAG). They are not blockers for the current core-only SPG gate unless
they appear on the live core/gateway/portal surface, but they become Stage 3+ optimization
criteria when optional backends are registered through manifests.

---

## Table 1 — Tool inventory & definition review

One row per advertised tool. "Description verdict" = is the tool's description/schema clear
and correct *for an autonomous DFIR agent* (OK / vague / misleading). "Call test" = result
of invoking it once on a sealed case via Claude Code.

| Tool | Backend / namespace | Description verdict | inputSchema sanity | Call test | Notes |
|------|---------------------|---------------------|--------------------|-----------|-------|
| `workflow_status` | sift-core (in-proc) | OK — states purpose (detect phase + next steps) | empty obj, OK | PASS post-seal | first-call tool per MCP instructions; reported ROCBA phase TRIAGE, chain OK, 2 sealed files |
| `environment_summary` | **sift-gateway (synthetic)** | OK — explains aggregation + call ordering | empty obj, OK | PASS post-seal | appended in `_list_tools()`; core healthy, no add-ons |
| `capability_guide` | **sift-gateway (synthetic)** | OK — declaration-driven framing, points to tools/list for schemas | empty obj, OK | PASS post-seal | **20th tool — absent from plan's "19"; see count note** |
| `case_status` | sift-core (in-proc) | OK | empty obj, OK | PASS post-seal | D-008 live-verified: `case_brief` reaches agent; TODO counters 5/5 |
| `case_file_structure` | sift-core (in-proc) | OK — notes it excludes integrity/transient files | empty obj, OK | PASS post-seal | listed case workspace; integrity dirs excluded |
| `evidence_list` | sift-core (in-proc) | OK | empty obj, OK | PASS post-seal | 2 registered/sealed files; chain OK |
| `evidence_verify` | sift-core (in-proc) | OK | empty obj, OK | PASS post-seal | manifest v1, ok_count=2 |
| `list_available_tools` | sift-core (in-proc) | OK | `category` free-string optional, OK | PASS post-seal | overlaps `check_tools`/`get_tool_help`/`suggest_tools` → D-005 |
| `get_tool_help` | sift-core (in-proc) | OK | `tool_name` required, OK | PASS post-seal | `mmls` help returned caveats/advisories/field meanings |
| `check_tools` | sift-core (in-proc) | vague — doesn't state behavior when `tool_names` omitted (check-all?) | `tool_names` optional array, OK | PASS post-seal | discovery-tool overlap → D-005 |
| `suggest_tools` | sift-core (in-proc) | OK — grounds in forensic-knowledge | `artifact_type` required, OK | PASS (empty result) post-seal | literal `E01 disk image` returned no suggestions but valid artifact catalogue; consider ergonomic expansion |
| `run_command` | sift-core (in-proc) | OK — names denylist/jail/audit/FK pipeline | rich + sensible defaults, OK | PASS post-seal | `/usr/bin/true`, audit `siftgateway-codex-20260602-032`; output-cap behavior only in server instructions, not schema (minor) |
| `record_finding` | sift-core (in-proc) | OK desc (validation/provenance/grounding) | **vague — `finding` is opaque `type:object`, no sub-schema** | PASS validation post-seal | returned `VALIDATION_FAILED` with required fields; no draft finding created |
| `record_timeline_event` | sift-core (in-proc) | OK desc | **vague — `event` opaque `type:object`** | FAIL validation post-seal | accepted minimal non-evidentiary probe as DRAFT `T-codex-001`; probe removed; see D-009 |
| `record_action` | sift-core (in-proc) | OK | `description`/`reasoning` required, OK | PASS post-seal | audit-only call test recorded |
| `log_reasoning` | sift-core (in-proc) | OK | `text` required, OK | PASS post-seal | audit-only call test logged |
| `log_external_action` | sift-core (in-proc) | OK — provenance/audit_id framing is good | required fields sensible, OK | PASS post-seal | audit `siftgateway-codex-20260602-038`; source marked orchestrator voluntary |
| `list_existing_findings` | sift-core (in-proc) | OK | `status` free-string, allowed values not enumerated (minor) | PASS post-seal | returned zero findings; enumerate DRAFT/COMMITTED → D-004 |
| `query_case` | sift-core (in-proc) | vague — `record_type` required but allowed values undocumented | other filters free strings | PASS post-seal | `actions` and `timeline` queries returned valid empty/current sets; agent must guess record_type values → D-004 |
| `manage_todo` | sift-core (in-proc) | vague — `action` required but allowed verbs not enumerated | `action`/`status`/`priority` free strings, no enums | PASS post-seal | seeded 5 ROCBA investigation objectives `TODO-codex-001`…`005`; enum action/status/priority → D-004 |

**Inventory result (Stage 2 step 1):** **20** advertised agent tools, **0** add-on tools (no `opensearch_*`/`wintriage_*`/`kb_*`/`cti_*` prefixes) → core-only out-of-box **confirmed**. 18 in-process core + 2 synthetic gateway (`environment_summary`, `capability_guide`). Note the gateway's `_CORE_TOOL_CATEGORIES`/`_PHASES` hint maps also list `audit_summary`, `backup_case`, `open_case_dashboard`, `case_list` — these are **not** on the advertised agent surface (filtered/not in-process); they are hint entries only, not a discrepancy.

---

## Table 2 — Defect ledger

| ID | Area | Severity | Repro | Expected vs actual | Root-cause hypothesis | Remediation status | Retest |
|----|------|----------|-------|--------------------|-----------------------|--------------------|--------|
| D-001 | install / core | major (off-message; runtime-inert) | `install.sh --core-only` → inspect `~/.sift/gateway.yaml` | Expected: a standalone-core config names **no** add-on backends. Actual: `backends:` block enumerated all four reference add-ons with `enabled: false`. | `configs/gateway.yaml.template` hardcoded the four reference backends, each `enabled: ${SIFT_*_ENABLED}`; core-only set the flags false but the entries still rendered. Contradicts "SPG core is self-contained; add-ons external/optional/bring-your-own" and is redundant with the portal register flow that writes entries on registration. | **FIXED (all paths)** — template now ships `backends: {}` (with a comment forbidding pre-seeding); `_migrate_gateway_config` no longer auto-enables rag/wintriage/opensearch/opencti (only normalizes args for portal-written entries); install summary directs operators to register add-ons via Portal → Backends / `setup-addon.sh`. Template renders to `backends: {}`, valid YAML. | Pending live re-gen on VM (`rm ~/.sift/gateway.yaml && ./install.sh --core-only`) |
| D-001-note | install / core | minor | inspect `enrichment:` block | `enrichment.forensic_rag` / `opensearch_context` carried add-on names in core config. | Vestigial flags — **nothing reads them**; grounding/enrichment is already declaration-driven via `set_reference_backend_provider`. | **FIXED** — removed both keys from the template; `enrichment` now holds only core `enabled`/`forensic_knowledge`/`root` with a comment that add-on enrichment is derived from registered-backend manifests. | Pending live re-gen |
| D-002 | core / agent-tool | major | call `case_status` (and the findings considerations path) | `platform_capabilities` advertised add-ons via `importlib.util.find_spec("<pkg>")` — "is the package installed," NOT "is a backend registered + advertising." Full install → all four advertised even when none registered; an external/HTTP/third-party backend would never be detected. Violated R-no-hardcoded-names / declaration-driven model. | `_build_platform_capabilities()` (agent_tools.py) + duplicate find_spec block in `case_manager.py` Layer-4. Predates the manifest-driven `capability_guide`/`environment_summary` (6.4c). | **FIXED (declaration-driven, field kept)** — gateway exposes `get_available_backend_capabilities()` (registered+available backends + advertised `provides`), injected into sift_core via `set_backend_capability_provider`. New `case_manager.build_platform_capabilities()` builds the field name-agnostically (capability `provides` union + per-backend `{name,namespace,provides}` + generated guidance); `case_status` and the case-manager path both use it; both find_spec blocks removed. No provider/gateway ⇒ core-only (correct). Tests: `test_platform_capabilities.py` (4). sift-core 305 / gateway 134 green. | Pending live verify in Stage 2/4 |
| D-002-note | core / methodology | minor | grep `forensic-mcp/server.py:534` | `forensic-mcp` still has a `find_spec` capability block. | It is the Phase-7 methodology backend — not served in-process and not on the live agent surface (backends are `{}`; forensic-mcp not started). | OPEN (Phase-7-scoped) — fix when methodology → /skills lands | — |

| D-003 | agent-tool | minor | inspect `tools/list` inputSchema for `record_finding` / `record_timeline_event` | Expected: an autonomous agent can determine required authoring fields from the schema. Actual: `finding` and `event` are bare `{"type":"object"}` with no sub-properties — the two most important authoring tools expose opaque payloads. | Core registers these with a generic object param; the real shape is enforced at runtime via validation + FK enrichment, not advertised in the schema. Workable for an agent that reads error/enrichment feedback, but rough on cold start. | OPEN — recommend documenting expected keys in the description (or a nested JSON schema). Non-blocking; runtime validation still enforces correctness. | Pending |
| D-004 | agent-tool | minor | inspect inputSchema for `manage_todo.action`, `query_case.record_type`, `list_existing_findings.status` | Required/filter string params have no `enum` of allowed values; an autonomous agent must guess valid verbs (`create`/`list`/…?) and record types (`timeline`/`action`?). | Params declared as free `type:string`. | OPEN — add `enum` (or list allowed values in description) for `action`, `status`, `priority`, `record_type`. Non-blocking. | Pending |
| D-005 | agent-tool | cosmetic | compare descriptions of `check_tools` vs `list_available_tools` vs `get_tool_help` vs `suggest_tools`; and `log_reasoning` vs `record_action` vs `log_external_action` | Overlapping tool families with no "use X when…" disambiguation; an agent may mis-select among near-synonyms. | Tools grew organically; descriptions describe each in isolation. | OPEN — add a one-line disambiguation to each. Non-blocking. | Pending |
| C-001 (count note, not a defect) | core | n/a | `tools/list` on core-only gateway | Plan/gate text says **19 core tools**; live advertises **20**. | `capability_guide` is a synthetic gateway tool appended in `_list_tools()` (`mcp_endpoint.py:687`) after the gate text was written; it is the legitimate 20th. | **Reconciled** — update the gate's expected count 19 → 20 at close (Stage 7). Product is correct. | n/a |

| D-006 | portal | **blocker** | Fresh core-only install → log into portal → no way to create the first case. Header case selector shows "No cases found"; every tab errors `{"error":"No active case. Set SIFT_CASE_DIR in gateway.yaml case.dir."}` (routes.py:200). | Expected: operator creates a case from the portal (case lifecycle is portal-managed per the framing). Actual: **no create-case UI exists anywhere in the React portal.** | Backend `POST /api/case/create` + client wrapper `postCaseCreate` exist, but **no component calls them**. `Header.jsx` implements only the *activate/switch* flow (`postCaseActivate` + challenge); the case dropdown lists existing cases and an empty "No cases found" state with no "create" affordance. So the very first case can never be made via the portal. | **FIXED (frontend-only)** — `Header.jsx`: added a "New case" action (examiner-only) to the case-selector dropdown + a create modal (casename→lowercased, title) → `postCaseCreate` → reset case-scoped state; backend auto-activates and polling picks it up. Extracts `{error}` from failed responses for a clean message. Added `plus` icon to `Icon.jsx`. Frontend build clean (411 modules); vitest 83/83 green. Built `static/v2` + changed source rsynced to VM (editable install serves from repo); asset hashes verified to match `index.html`. **No gateway restart needed — hard-refresh the portal.** | Pending operator retest on VM (create a case from the Header selector) |

| D-006-note | portal | minor (by design, partial) | Create case via Header → only casename + title prompted; no path choice. | Path/case_id are intentionally computed by the portal (`post_case_create` rejects `dir/directory/case_dir/case_id`, routes.py:3752) — **confirmed by design** (consistency + R5 escape guard). But the create form also captures **no synopsis/description**, so the initial case brief has nowhere to go at creation (`description` is a PROTECTED field set only at creation). | **FIXED** — create modal now has an optional **Synopsis** textarea → `description` (backend `post_case_create` accepts optional `description`, ≤10k, stored in CASE.yaml). Path/case_id remain portal-computed (by design). Tests: 2 new in `test_case_create.py`. Deployed + gateway restarted. | Pending operator retest (create a case with a synopsis) |
| D-007 | portal | major | After case create, examiner has no way to record structured case facts (incident_type, severity, occurred_at, affected_systems/accounts, client, PoC, impact_summary, tags). | Expected: portal is the owner of case metadata (F-E) and exposes an editor. Actual: `set_case_metadata` supports a full typed schema (`case_metadata.py`) and `POST /api/case/metadata` + `postCaseMetadata` exist, but **no component calls them** — there is no metadata-editing UI. | Same omission pattern as D-006 — backend + client wrapper present, UI never built. | **FIXED** — new `CaseBriefCard` on the Overview tab: read-only brief for all roles + examiner **"Edit brief"** modal covering every settable field (incident_type/severity/tlp enums, client/PoC/lead_examiner, 6 date fields, affected_systems/accounts as line-lists, tags/related_cases/distribution_list as comma-lists, impact_summary). Saves per-field via `postCaseMetadata`, surfaces field-level validation errors, refreshes `activeCase`. `description` shown read-only (creation-only/protected). Frontend build clean (412 modules), vitest 83/83. Deployed. | PASS browser retest — Overview shows populated brief; Edit brief modal fields are populated (`unauthorized_access`, `high`, `AMBER`, Stark Research Labs, occurred datetime, affected systems/accounts, tags, impact summary). |
| D-008 | core / agent-tool | major | Agent calls `case_status` on a case with rich CASE.yaml metadata. | Expected: an autonomous DFIR agent receives the case brief/scope/objectives so it knows what it is investigating. Actual: `case_status_data` (case_ops.py:30) surfaces only `case_id/name/status/examiner` + paths + counts; it **omits** `description`, `incident_type`, `severity`, date fields, `affected_systems/accounts`, `impact_summary`. The agent is blind to the case brief. | `case_status_data` was written for lifecycle/counts, predates structured intake. The one scope channel that *does* reach the agent is **TODOs** (`manage_todo`). | **FIXED** — added `build_case_brief(meta)` (case_ops.py) surfacing the curated intake fields (description, incident_type, severity, tlp, client, point_of_contact, impact_summary, the 6 date fields, affected_systems/accounts, tags, related_cases); empties dropped, lifecycle fields excluded. Injected as `case_brief` into both `case_status_data` (agent `case_status`) and `case_manager.get_case_status`. Tests: 2 new in `test_case_ops.py`; sift-core 307 / gateway 134 green. Deployed + gateway restarted (log confirms 18 core in-proc). | PASS live post-seal — `case_status` returned curated ROCBA `case_brief` and TODO counters 5/5. |
| D-009 | agent-tool | major | Post-seal call `record_timeline_event(event={title,timestamp,description})` as a validation probe with no evidence/provenance fields. | Expected: timeline authoring rejects or returns validation guidance for a non-evidentiary/minimal event. Actual: tool staged DRAFT `T-codex-001` successfully. | Timeline event schema/runtime validation is too permissive compared with finding provenance enforcement; opaque `event` schema hides required evidentiary expectations, if any. | OPEN — add required fields/provenance validation or explicit schema/guidance. Test artifact `T-codex-001` was removed from `timeline.json`; case counters returned to 0. | Pending |
| D-010 | agent-tool / core | minor | `check_tools(["ewfinfo","img_stat","pinfo.py"])` then call each through `run_command`. | Expected: commonly used SIFT gate tools from the filesystem/timeline skills are cataloged for availability/FK enrichment. Actual: `ewfinfo`, `img_stat`, and `pinfo.py` execute successfully through `run_command` but are reported as "not in catalog — can execute but without FK enrichment." | FK tool catalog covers many SIFT binaries but misses some libewf/TSK/Plaso support commands that are first-step DFIR workflow tools. | OPEN — add catalog entries/help metadata for `ewfinfo`, `img_stat`, and `pinfo.py` so autonomous agents can discover them cleanly. | Pending |
| D-011 | agent-tool / methodology | minor | Apply downloaded skills from `/home/yk/Downloads/SKILL*.md` to live VM. Memory skill points to `/opt/volatility3-2.20.0/vol.py`; Windows artifact skill points to `/opt/zimmermantools/PECmd.dll`. | Expected: skill command paths match live SIFT VM. Actual: those paths do not exist; live Volatility is `/usr/local/bin/vol -> /opt/volatility3/bin/vol`; `PECmd` is absent, while other Zimmerman wrappers such as `/usr/local/bin/EvtxECmd` and `/usr/local/bin/MFTECmd` exist. | Downloaded skill docs target a different SIFT image/tool layout than this VM; the gateway catalog is more reliable than static paths for live execution. | OPEN — when formalizing skills, generate or validate paths from `check_tools`/catalog on the target VM, or include fallback path guidance. | Pending |
| D-012 | agent-tool / findings | major | Stage RDP finding with `artifacts=[{source:"evidence/rocba-cdrive.e01", audit_id:"siftgateway-codex-..."}]` after `evidence_list` shows that exact path sealed/ACTIVE. | Expected: registered evidence path is accepted as artifact source, or validation guidance clearly states the required artifact shape. Actual: `record_finding` rejects the artifact as "source not in evidence registry"; omitting `artifacts` stages the finding but downgrades provenance to PARTIAL and reports `source_evidence:""`. | Finding artifact validator likely compares against a different source namespace/object shape than `evidence_list.path`, and the schema is opaque (D-003). | OPEN — align `record_finding` artifact `source` validation with `evidence_list.path` or document/advertise the exact accepted schema. RDP finding staged as `F-codex-002` without artifacts to avoid blocking the workflow. | Pending |
| D-013 | agent-tool / provenance | major | Stage finding with supporting commands whose excerpts include real `siftgateway-codex-*` audit IDs. | Expected: provenance extraction/counting recognizes supplied MCP audit IDs, especially for HIGH confidence checks. Actual: finding staged with synthetic `shell-codex-*` provenance and warns "Confidence HIGH typically requires 2+ audit_id(s) (got 0)" even though supporting commands cite multiple audit IDs. | `record_finding` provenance extractor may only count a hidden command audit model, not audit IDs in `supporting_commands.output_excerpt`; schema gives no explicit `audit_id` field for supporting commands. | OPEN — add an `audit_id` field to `supporting_commands` schema and count it, or parse/carry audit IDs from tool calls deterministically. | Pending |
| D-014 | agent-tool / run_command | minor | `EvtxECmd ... --sd "2020-11-01 00:00:00.0000000" --ed "2020-11-16 23:59:59.9999999"` and later parse focused EVTX directory. | Expected: command failures are reflected by non-zero exit or `run_command.success=false` when the tool prints argument/parse errors. Actual: EvtxECmd returned exit 0 while printing help + "Unrecognized command or argument"; later directory parse returned exit 0 while skipping invalid EVTX extractions and erroring on partial Security.evtx. | Some forensic tools report partial failure on stdout/stderr while preserving exit 0; `run_command` currently treats process exit only as success. | OPEN — consider optional stderr/error-pattern surfacing or tool-specific health summaries so autonomous agents do not mistake partial parser output for a clean parse. | Pending |
| D-015 | agent-tool / run_command | minor | `awk -F, '$3 ~ /^2020-11-(13|14|15|16)/ {print ...}' ...` through `run_command`. | Expected: awk guardrail blocks dangerous `system()`, `getline`, and shell pipes, but allows regex alternation inside awk programs. Actual: guardrail rejected the program as "pipe operators are not allowed" because of `|` in the regex. | Static safety check overmatches awk regex alternation as a pipe operator. | OPEN — refine awk guardrail parsing or document that agents should avoid alternation and use simpler grep stages. | Pending |

### Baseline friction crosswalk

`mcp-qa-friction-log.md` is the optimization baseline. Current Phase 6 live defects map as:

- D-003/D-004/D-009/D-012/D-013 → baseline F-006/F-027 principle: mutation tools need explicit schemas, actionable validation, provenance-grade guidance, and machine-readable audit/artifact fields.
- D-014/D-015 → baseline F-017/F-018/F-011 principle: fail loudly and diagnostically; avoid opaque errors and silent false negatives in query/parser/filter tooling.
- D-014/D-015 plus the live `run_command` workflow friction → baseline F-031/F-032/F-033/F-034/F-035/F-036/F-037/F-038: document executor policy, provide safe batch/workflow primitives, classify parser partial failures, compact previews, preserve derivative provenance, add safe wrappers, close catalog gaps, and optimize for forensic workflow execution rather than raw shell execution.
- Stage 2 TODO seeding and the five ROCBA questions → baseline F-002: investigation plan/state must persist as the resume spine.
- Environment/tool payload bloat observed in live `environment_summary` and `_case` envelopes → baseline F-016/F-024: optimize response bytes aggressively; keep orientation data on orientation tools, not every call.
- Add-on/indexed-backend acceptance in Stage 3 should use F-003/F-004/F-011/F-012/F-013/F-018/F-021/F-025 as explicit query/index ergonomics checks.

Area ∈ { install · core · add-on · portal · agent-tool · security }.

---

## Pre-run notes (Stage 0, local — recorded before touching the VM)

- **Scripts:** added source-guard to `install.sh` (reusable as a function library); hardened
  `scripts/reset-vm-test.sh` to restart via `systemctl --user` (was stale `nohup uv run`);
  added `scripts/setup-addon.sh` (optional add-on provisioning + env echo + generic
  register-payload emitter; registers nothing, edits no config).
- **OpenSearch `requires` string** (`https://localhost:9200`) vs runtime `http://127.0.0.1:9200`:
  **verified benign** — `Gateway.evaluate_requirement` (server.py:247) does a plain TCP
  connect to host:port (explicit `:9200`), so scheme and `localhost`↔`127.0.0.1` don't
  matter. No change made.
- **Offline manifest probe:** `probe_backends.py --manifest-dir packages --skip-mcp` →
  all 4 backends conform.
- **setup-addon.sh payload smoke:** emits valid `{name, config{type,command,args,
  manifest_path,enabled}}` with explicit `manifest_path` — the same shape an external backend
  submits.

## Stage 2 progress (live, core-only out-of-box — 2026-06-02)

- **Step 1 — inventory:** `tools/list` = **20 agent tools, 0 add-on** → core-only confirmed (see Table 1 result line). Count reconciled in C-001 (19→20, `capability_guide`).
- **Step 2 — tool-definition review:** all 20 reviewed in Table 1. Descriptions mostly OK; schema gaps captured as D-003 (opaque finding/event objects), D-004 (missing enums), D-005 (overlapping tool families). All **minor/cosmetic — no blockers**.
- **Step 3 — F-A pre-seal block:** ✓ confirmed. With **no active case**, 5 tools across session-start + discovery categories (`workflow_status`, `environment_summary`, `capability_guide`, `case_status`, `list_available_tools`) all return `blocked / evidence_chain_unsealed`. Fail-closed gate covers the entire agent surface incl. the synthetic gateway tools.
- **Pending (needs operator):** portal first-run (forced password reset → login); **create + seal a case** so I can re-run the Table 1 "Call test" column for real (currently all `blocked pre-seal`); then `scripts/phase2_gate_test.py` → expect 14/14.
- **2026-06-02 continuation:** ROCBA case is active and sealed. `evidence_list`/`evidence_verify` show 2 sealed files (`Rocba-Memory.raw`, `rocba-cdrive.e01`) and `chain.status == ok`.
- **Brief/TODO verification:** corrected structured ROCBA brief to `incident_type=unauthorized_access`, `severity=high`, `tlp=AMBER`, `client=Stark Research Labs`, `occurred_at=2020-11-13T19:00:00-05:00`, affected systems/accounts, and tags. `case_status` confirms D-008 live: the curated `case_brief` reaches the agent. Seeded five open high-priority TODOs as the agent-readable objectives channel: key projects, what was stolen, transfer destination/staging, how it was stolen, and when activity occurred.
- **Browser portal verification:** Chrome DevTools MCP headless login as `examiner` succeeded. Overview shows the active ROCBA case, populated Case Brief, `Edit brief` control, sealed status, and the corrected structured fields. The Edit brief modal is populated with the same values. TODOs tab shows **5 of 5** open high-priority objectives (`TODO-codex-001`…`005`) with the five investigation questions.
- **Table 1 call tests:** reran all 20 core/synthetic tools post-seal. 19/20 passed or returned expected validation; `record_timeline_event` exposed D-009 by staging a minimal non-evidentiary event. The probe event was removed; `timeline_count` returned to 0.
- **`run_command` skill probes:** Applied the four downloaded skills where safe without starting long ingest jobs. File System & Carving: `ewfinfo evidence/rocba-cdrive.e01` PASS (`siftgateway-codex-20260602-049`) and `img_stat evidence/rocba-cdrive.e01` PASS (`...-052`), confirming EWF type, 512-byte sectors, 81 GiB media size, and embedded MD5/SHA1; `mmls evidence/rocba-cdrive.e01` returned exit 1 (`...-061`), consistent with needing EWF mount/raw device workflow before TSK partition listing. Memory Forensics: downloaded skill path `/opt/volatility3-2.20.0/vol.py` absent (`...-054`); live `/usr/local/bin/vol` runs but `windows.info --offline` cannot satisfy kernel/symbol requirements on the current RAM image (`...-063`). Windows Artifacts: downloaded `PECmd` path absent (`...-056`, `...-065`), but live `/usr/local/bin/EvtxECmd -h` PASS (`...-071`). Timeline: `log2timeline.py --parsers list` PASS (`...-058`) and `pinfo.py --help` PASS (`...-067`). Gaps logged as D-010/D-011.
- **Scripted Stage 2 gate:** `scripts/phase2_gate_test.py` on the VM passed **13/14**. The only failure is stale C-001 logic: it still treats synthetic `capability_guide` as an unexpected add-on tool (`unexpected: capability_guide`) while live inventory is the accepted 20-tool core/synthetic surface. The script temporarily switched `gateway.yaml case.dir` to `/cases/phase2-gate-smoke`; restored to `/cases/rocba-exfiltration-20260602-1245` and restarted `sift-gateway.service`.
- **Local pre-VM check:** `uv run python scripts/probe_backends.py --manifest-dir packages --skip-mcp` passed all four manifests.
- **Autonomous DFIR workflow iteration (core-only tools):** mounted `rocba-cdrive.e01` via `ewfmount` (`siftgateway-codex-20260602-085`) and confirmed `ewf1` is a direct NTFS volume, not a partitioned disk (`file`/`fsstat` audits `...-092`/`...-094`; `mmls` on the mounted raw device fails). Enumerated Fred's profile and cloud folders with `fls`; OneDrive contains SRL project material (`Project P.E.G.A.S.U.S`, `Tesseract`, `Vibrainium`, `Adamantium`, `Shield`) and ROCBA Dropbox contains `Fred Rocba/Data Testing Results` (`fls`/`grep` audits `...-112`, `...-114`, `...-118`, `...-120`). Staged access-scope finding `F-codex-001` as DRAFT.
- **RDP finding:** Extracted and parsed focused EVTX logs. `EvtxECmd` parsed `TerminalServices_LocalSessionManager_Operational.evtx` cleanly (94 records, zero errors; `siftgateway-codex-20260602-218`). `grep -n 52.249.198.56 agent/analysis/evtx_csv/rocba_focused_evtx.csv` (`...-242`) shows `SRL-FORGE\fredr` session 1 reconnecting from `52.249.198.56` at `2020-11-14 03:42:50.2241580 UTC` and disconnecting at `2020-11-14 05:15:54.1965320 UTC`, with later reconnect/disconnect rows at `12:31/12:51` and `12:52/14:17` UTC. Prefetch listing includes `MSTSC.EXE-2A83B7D7.pf` (`...-246`). Staged narrow RDP finding `F-codex-002` as DRAFT; no attribution/exfiltration conclusion yet.
- **Skill improvements from live workflow:** File System & Carving skill should branch after EWF mount: if `mmls` fails/empty, treat the mounted `ewf1` as a direct filesystem and run `file`/`fsstat`/`fls` directly. Avoid full `ewfverify` inside an interactive agent loop on 23 GB E01s; use the sealed chain manifest or run long verification out-of-band. Windows Artifacts skill should prefer `check_tools`/catalog-discovered wrappers (`EvtxECmd`, `MFTECmd`, `RECmd`, etc.) and handle missing `PECmd`. OneDrive sparse/offline files can have metadata and non-zero logical sizes but no readable local body; do not overinterpret placeholder transcript files. For EVTX, parse logs individually or validate parser stdout because tool exit 0 can still include skipped/errored files.

## Stage checklist (tick as completed live)

- [ ] **Stage 1** — `install.sh --uninstall --purge-data -y` → `install.sh --core-only`; healthy, 19 core tools, 0 add-on tools.
- [~] **Stage 2** — portal first-run; F-A blocks pre-seal; tool-definition review (Table 1); `phase2_gate_test.py` 14/14. Live behavior passed except stale script expectation C-001 (`capability_guide`).
- [ ] **Stage 3** — `setup-addon.sh` per backend → portal validate→register→hot-reload; `tools/list` namespaced; `environment_summary` health; `requires[]` gating; live `probe_backends.py`; non-conformant manifest → 422, no write.
- [ ] **Stage 4** — Claude Code MCP wired to `https://192.168.122.81:4508/mcp/`; call each tool once (Table 1).
- [ ] **Stage 5** — ROCBA: create case → copy evidence → seal → full agent loop → examiner commit → signed report.
- [ ] **Stage 6** — invariants: F-A corrupt-evidence; R-B jail; executor deny-floor/traversal/output-cap; R-core-survives (disable add-on); R-roles (portal rejects agent token).
- [ ] **Stage 7** — all blocker/major fixed + retested; gate ticked in `revamp-tasks.md`; Session Log appended.
