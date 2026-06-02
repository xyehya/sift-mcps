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

---

## Table 1 — Tool inventory & definition review

One row per advertised tool. "Description verdict" = is the tool's description/schema clear
and correct *for an autonomous DFIR agent* (OK / vague / misleading). "Call test" = result
of invoking it once on a sealed case via Claude Code.

| Tool | Backend / namespace | Description verdict | inputSchema sanity | Call test | Notes |
|------|---------------------|---------------------|--------------------|-----------|-------|
| `workflow_status` | sift-core (in-proc) | OK — states purpose (detect phase + next steps) | empty obj, OK | blocked pre-seal (F-A) ✓expected | first-call tool per MCP instructions |
| `environment_summary` | **sift-gateway (synthetic)** | OK — explains aggregation + call ordering | empty obj, OK | blocked pre-seal (F-A) ✓expected | appended in `_list_tools()`; F-A blocks it too (good) |
| `capability_guide` | **sift-gateway (synthetic)** | OK — declaration-driven framing, points to tools/list for schemas | empty obj, OK | blocked pre-seal (F-A) ✓expected | **20th tool — absent from plan's "19"; see count note** |
| `case_status` | sift-core (in-proc) | OK | empty obj, OK | blocked pre-seal (F-A) ✓expected | |
| `case_file_structure` | sift-core (in-proc) | OK — notes it excludes integrity/transient files | empty obj, OK | blocked pre-seal (F-A) | re-test post-seal |
| `evidence_list` | sift-core (in-proc) | OK | empty obj, OK | blocked pre-seal (F-A) | re-test post-seal |
| `evidence_verify` | sift-core (in-proc) | OK | empty obj, OK | blocked pre-seal (F-A) | re-test post-seal |
| `list_available_tools` | sift-core (in-proc) | OK | `category` free-string optional, OK | blocked pre-seal (F-A) ✓expected | overlaps `check_tools`/`get_tool_help`/`suggest_tools` → D-005 |
| `get_tool_help` | sift-core (in-proc) | OK | `tool_name` required, OK | blocked pre-seal (F-A) | re-test post-seal |
| `check_tools` | sift-core (in-proc) | vague — doesn't state behavior when `tool_names` omitted (check-all?) | `tool_names` optional array, OK | blocked pre-seal (F-A) | discovery-tool overlap → D-005 |
| `suggest_tools` | sift-core (in-proc) | OK — grounds in forensic-knowledge | `artifact_type` required, OK | blocked pre-seal (F-A) | |
| `run_command` | sift-core (in-proc) | OK — names denylist/jail/audit/FK pipeline | rich + sensible defaults, OK | blocked pre-seal (F-A) | output-cap behavior only in server instructions, not schema (minor) |
| `record_finding` | sift-core (in-proc) | OK desc (validation/provenance/grounding) | **vague — `finding` is opaque `type:object`, no sub-schema** | blocked pre-seal (F-A) | agent can't author required keys from schema alone → D-003 |
| `record_timeline_event` | sift-core (in-proc) | OK desc | **vague — `event` opaque `type:object`** | blocked pre-seal (F-A) | same as record_finding → D-003 |
| `record_action` | sift-core (in-proc) | OK | `description`/`reasoning` required, OK | blocked pre-seal (F-A) | overlaps `log_reasoning`/`log_external_action` → D-005 |
| `log_reasoning` | sift-core (in-proc) | OK | `text` required, OK | blocked pre-seal (F-A) | overlap w/ `record_action.reasoning` → D-005 |
| `log_external_action` | sift-core (in-proc) | OK — provenance/audit_id framing is good | required fields sensible, OK | blocked pre-seal (F-A) | |
| `list_existing_findings` | sift-core (in-proc) | OK | `status` free-string, allowed values not enumerated (minor) | blocked pre-seal (F-A) | enumerate DRAFT/COMMITTED → D-004 |
| `query_case` | sift-core (in-proc) | vague — `record_type` required but allowed values undocumented | other filters free strings | blocked pre-seal (F-A) | agent must guess record_type values → D-004 |
| `manage_todo` | sift-core (in-proc) | vague — `action` required but allowed verbs not enumerated | `action`/`status`/`priority` free strings, no enums | blocked pre-seal (F-A) | enum action/status/priority → D-004 |

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
| D-007 | portal | major | After case create, examiner has no way to record structured case facts (incident_type, severity, occurred_at, affected_systems/accounts, client, PoC, impact_summary, tags). | Expected: portal is the owner of case metadata (F-E) and exposes an editor. Actual: `set_case_metadata` supports a full typed schema (`case_metadata.py`) and `POST /api/case/metadata` + `postCaseMetadata` exist, but **no component calls them** — there is no metadata-editing UI. | Same omission pattern as D-006 — backend + client wrapper present, UI never built. | **FIXED** — new `CaseBriefCard` on the Overview tab: read-only brief for all roles + examiner **"Edit brief"** modal covering every settable field (incident_type/severity/tlp enums, client/PoC/lead_examiner, 6 date fields, affected_systems/accounts as line-lists, tags/related_cases/distribution_list as comma-lists, impact_summary). Saves per-field via `postCaseMetadata`, surfaces field-level validation errors, refreshes `activeCase`. `description` shown read-only (creation-only/protected). Frontend build clean (412 modules), vitest 83/83. Deployed. | Pending operator retest (Overview → Edit brief) |
| D-008 | core / agent-tool | major | Agent calls `case_status` on a case with rich CASE.yaml metadata. | Expected: an autonomous DFIR agent receives the case brief/scope/objectives so it knows what it is investigating. Actual: `case_status_data` (case_ops.py:30) surfaces only `case_id/name/status/examiner` + paths + counts; it **omits** `description`, `incident_type`, `severity`, date fields, `affected_systems/accounts`, `impact_summary`. The agent is blind to the case brief. | `case_status_data` was written for lifecycle/counts, predates structured intake. The one scope channel that *does* reach the agent is **TODOs** (`manage_todo`). | **FIXED** — added `build_case_brief(meta)` (case_ops.py) surfacing the curated intake fields (description, incident_type, severity, tlp, client, point_of_contact, impact_summary, the 6 date fields, affected_systems/accounts, tags, related_cases); empties dropped, lifecycle fields excluded. Injected as `case_brief` into both `case_status_data` (agent `case_status`) and `case_manager.get_case_status`. Tests: 2 new in `test_case_ops.py`; sift-core 307 / gateway 134 green. Deployed + gateway restarted (log confirms 18 core in-proc). | Pending **live agent verify post-seal** (case_status is F-A-gated; verify at Stage 4/5 that the agent receives the brief) |

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

## Stage checklist (tick as completed live)

- [ ] **Stage 1** — `install.sh --uninstall --purge-data -y` → `install.sh --core-only`; healthy, 19 core tools, 0 add-on tools.
- [ ] **Stage 2** — portal first-run; F-A blocks pre-seal; tool-definition review (Table 1); `phase2_gate_test.py` 14/14.
- [ ] **Stage 3** — `setup-addon.sh` per backend → portal validate→register→hot-reload; `tools/list` namespaced; `environment_summary` health; `requires[]` gating; live `probe_backends.py`; non-conformant manifest → 422, no write.
- [ ] **Stage 4** — Claude Code MCP wired to `https://192.168.122.81:4508/mcp/`; call each tool once (Table 1).
- [ ] **Stage 5** — ROCBA: create case → copy evidence → seal → full agent loop → examiner commit → signed report.
- [ ] **Stage 6** — invariants: F-A corrupt-evidence; R-B jail; executor deny-floor/traversal/output-cap; R-core-survives (disable add-on); R-roles (portal rejects agent token).
- [ ] **Stage 7** — all blocker/major fixed + retested; gate ticked in `revamp-tasks.md`; Session Log appended.
