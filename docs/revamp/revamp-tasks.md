# SIFT Protocol Gateway — Revamp Task Tracker

> **Spec:** `revamp-plan.html` (v2.1) + `docs/revamp/target-architecture.mmd`
> **This file:** the working tracker. The HTML is *why/what at the design level*; this is *what to do, in what order, how to verify, and where we left off*.
> **Read this file at the start of every revamp session.** Update the Session Log at the bottom before you stop.

---

## What we're doing

We are **re-architecting the existing repo into the SIFT Protocol Gateway (SPG)** — and defining the **unified add-on method/spec** that lets the wider SANS/SIFT community extend it safely.

Today the platform has every capability it needs but the wrong *topology*: the things that should be "core" (execute, case, evidence & chain-of-custody, audit, findings, reporting) run as independent stdio subprocesses the gateway merely routes to, and case logic is duplicated across `forensic-mcp` / `case-mcp` / `report-mcp`. A core capability can silently vanish if a subprocess fails to boot, and a third party has no contract to build against.

The revamp delivers two things:

1. **A solid, self-contained core** (backed by the renamed `sift-core`) that owns the minimal-but-complete requirements for an autonomous DFIR agent: sandboxed execution, case management, evidence/chain-of-custody, audit, findings, reporting, the portal, and the trust layer (auth, evidence gate, response guard). Governance, oversight, security, and audit are defined **once**, centrally.
2. **A versioned SIFT MCP Backend Contract** (spec + JSON Schema + conformance probe) — a simple, plug-and-play pathway for *any* add-on backend (OpenSearch, OpenCTI, RAG, Windows-triage, or a community tool) to natively integrate with the core: declared namespace, `evidence_class`, `requires[]`, identity rules, and capability declarations, with **zero hardcoded backend names** anywhere in core logic.

**Outcome:** a standardized, secure, extensible baseline the community can build on — where the hard DFIR guarantees live in the core, and capabilities are added by dropping in a conformant backend. **MVP = Phases 0–6.** `/skills` + SDK (Phase 7) is the post-MVP ecosystem layer.

---

## 0 · How to use this document

- Every task has **What / How / Why / Test** and a checkbox. Don't tick a box until its **Test** passes.
- Phases are ordered by dependency. Don't start a phase until the prior phase's gate (the `🔒 PHASE GATE` line) is green.
- **MVP = Phases 0–6.** Phase 7 (`/skills` + SDK) is post-MVP, done last.
- When a task reveals the spec is wrong, fix the spec (HTML/mmd) in the same commit and note it in the Session Log — the spec must never drift from reality again (that drift is what this whole revamp is correcting).

---

## 1 · Locked decisions (do not re-litigate)

From the v2.1 spec plus the four forks settled 2026-06-01:

| # | Decision | Source |
|---|----------|--------|
| D1 | Rename `agentir_core` → `sift_core`; env/path surface `AGENTIR_*` → `SIFT_*`, `/var/lib/agentir` → `/var/lib/sift`; service-token prefix to `sift_svc_*`. **No back-compat** — fresh VM + fresh case, so do a clean cutover (no shim, no symlink, no dual-name config). | spec §6 + fork 2026-06-01 |
| D2 | `run_command` stays **denylist-default** (already externalized to `security.yaml`). Work = relocate to operator-editable `gateway.yaml` + add non-weakenable **deny floor** + optional **allowlist mode**. | spec §5 |
| D3 | Privileged exec (vol/dd/mount) = **capabilities-first**, sudoers-allowlist fallback (full-path NOPASSWD, never shell/wildcard). Every escalation audited; gateway never root. | spec §5 |
| D4 | 14 forensic methodology `get_*` tools → `/skills` packs (downloadable zip, Anthropic skills standard). **FK *data package* stays a core runtime dependency.** Post-MVP, last. | spec §7 |
| **F-A** | **Evidence gate = strict binary, block everything.** No agent `/mcp` tool runs until evidence is registered **and sealed** and `chain_status == OK`. Any `MODIFIED/MISSING/UNREGISTERED/UNSEALED/LEDGER_ERROR` → block **all** agent tools until the operator fixes it in the portal. **Drops** the `readOnlyHint` carve-out and the 3-class O2 target. | fork @473 |
| **F-B** | **Relocate integrity records out of the agent jail** (`audit/`, `approvals.jsonl`, `evidence-ledger.jsonl`, manifest) to `/var/lib/sift/<case_id>/`, done during core consolidation (Phase 1). Evidence/extractions/reports/agent stay under `case_root`. | fork @622 |
| **F-C** | **Drop `export_bundle` / `import_bundle` from the agent MCP surface** for MVP. Keep the `sift_core` functions for a future portal export feature. | fork @277 |
| **F-D** | `case_host_fix` **stays in `opensearch-mcp`** (mutates OpenSearch index/alias state, not global case state). Rename to `opensearch_*` namespace. **Not** pulled into core. | fork @168/@328 |
| **F-E** | `set_case_metadata` + report generation become **portal-owned** (examiner-triggered), removed from the agent MCP surface. | fork @292 |
| **F-F** | **Universal identity is core-native and transparent.** Identity (`principal`/`principal_type`/`agent_id`/`created_by`/`token_id`/`source_ip`/`auth_surface`) is resolved **once** at the auth boundary and stamped into every audit entry. It is **invisible** to the agent's tool schemas *and* to add-on backends — it never travels as a tool argument. **Retires `analyst_override` / `analyst_identity` / `ANALYST_TOOLS` / `accepts_analyst_override` entirely** (does **not** move them into the manifest — this reverses the earlier "manifest `identity.accepts_analyst_override`" plan). Done in Phase 4.1–4.2. | session 2026-06-02 |

### Grounded facts the build starts from (verified in code 2026-06-01)
- **Evidence gate today** = `blocked = chain_status != OK` (`sift_gateway/evidence_gate.py:117`) + a read-only carve-out in `mcp_endpoint.py`. F-A removes the carve-out.
- **Integrity records today live inside `case_dir`**: `audit/` (`audit_ops.py:15`), `approvals.jsonl` (`case_io.py:286`), `evidence-ledger.jsonl` (`evidence_chain.py:45`). `run_command` cwd/jail defaults to `AGENTIR_CASE_DIR` (`sift-mcp/tools/generic.py:71`) → records are inside the agent's reach. F-B fixes this.
- **`analyst_override`** = today's identity trust boundary: gateway injects the authenticated examiner into `arguments` for the 6 `ANALYST_TOOLS` at **three** sites (`server.py:539-540,575-577`; `mcp_endpoint.py:827-828`); core schemas don't expose it, and `call_core_tool` already takes `examiner=` as a kwarg (`agent_tools.py:918-932`, passed at `server.py:550`). → **F-F retires it entirely**: identity flows only as the out-of-band kwarg/contextvar, never as an arg, and is stamped into audit (`principal`/`agent_id`/`created_by`). *(Supersedes the earlier "becomes manifest `identity.accepts_analyst_override`" note.)*
- **Grounding does NOT break core-only.** `_grounding_result` returns `{}` when no reference backends are deployed (`manager.py:1648`); it only flags *deployed* ones. The real defect is the hardcoded `_GROUNDING_MCPS` tuple (`manager.py:1604`) → make declaration-driven via manifest `capabilities.provides: ["reference"]`.
- **Provenance enforced** (not advisory): `_classify_provenance` MCP>HOOK>SHELL>NONE (`manager.py:1691`); finding with `NONE` + no validated commands is rejected (`manager.py:1217`).
- **14 methodology tools are reference lookups, not control flow.** `considerations` (`server.py:31,237`), grounding suggestions (`manager.py:1661`), and `validate_finding` enforcement (inside `record_finding`) all run server-side regardless. Removing the *tools* loses nothing operational.
- Counts to respect: `AGENTIR_CASE_DIR` appears ~141×; bare `/cases` literals ~55×; response guard = 30 patterns; forensic-mcp = 20 tools + 14 resources.

**SIFT VM:** 192.168.122.81
- User/pass: `sansforensics` / `forensics`
- Python: `/usr/bin/python3.12` (SIFT native, 3.12.3)
- Ubuntu 24.04.4 LTS (Noble Numbat)
---

## 2 · Repo & environment setup (do this once, before Phase 0)

**Repo strategy: long-lived branch + worktree (chosen).**

- [x] Commit the working-tree changes (branched first per best practice, then committed on the branch so `main` stays a clean baseline) — commit `b1593a2`.
- [x] Tag the pre-revamp baseline at `main`'s HEAD: `pre-revamp-v0` @ `0c260ff`. *(push tags when a remote is configured)*
- [x] Create the revamp branch: `revamp/spg-v1`.
- [x] Add a worktree for side-by-side live testing: `../sift-mcps-main` on `main`.
- [x] `revamp-tasks.md`, `revamp-plan.html`, and `docs/revamp/*` live on `revamp/spg-v1`.

**Baseline to preserve:** ~1146 tests green + evidence gate passing on `pre-revamp-v0`. Re-run after every phase; a phase is not done if the baseline regressed without a logged, intentional reason.

**VM strategy: build a fully fresh VM (chosen).**

- [x] Provision a fresh SIFT VM (Ubuntu 24.04, Python 3.12, Docker).
- [x] Run the (renamed) `install.sh` from scratch on it — `./install.sh --core-only` succeeded (Session 13); gateway running with 19 core tools. Full-addon install deferred to Phase 6 gate.
- [ ] Re-index an evidence set for live regression. **Cost note:** the ROCBA set is 23GB `.e01` + 19GB RAM = expensive re-indexing. Consider a smaller evidence sample for fast iteration and reserve a full ROCBA re-index for end-of-MVP regression.
- [ ] Record the fresh VM's IP, service token, and case path in the Session Log so live tests are reproducible.

---

## 3 · Session handover format

At the **end** of every session, append an entry to the **Session Log** (§8). Keep it short and mechanical:

```
### Session N — YYYY-MM-DD — <focus>
- Branch/commit: revamp/spg-v1 @ <sha>
- Phase: <Px> — tasks touched: <Px.y, Px.z>
- DONE (boxes ticked this session): <ids>
- Tests: <count> pass / <count> fail — <command used>
- Live test on VM: <what was run, result, or "none">
- Spec changed?: <yes: which file/section | no>
- BLOCKERS / open questions for next session: <…>
- NEXT: <single most important next task id>
```

Rules:
- One source of truth for "what's done" = the checkboxes in this file. The Session Log explains *how* and *why*, not *what*.
- If you change a locked decision, you may **not** just edit §1 — add a dated note in the Session Log explaining the reversal and get it confirmed.

---

## 4 · Live testing approach

Three layers, fastest → slowest. Run the cheap ones constantly; the expensive one at phase gates.

1. **Unit/integration (per-package `pytest`)** — run on every task. Fast, no VM. This is the 1146-test baseline.
   - ⚠️ **Run tests PER-PACKAGE** (`uv run python -m pytest packages/<pkg>/ -q`). A whole-suite `pytest` from the repo root fails collection on duplicate test basenames across packages — that's pre-existing, not a regression.
   - 🛑 **NEVER run bare `uv sync`.** It prunes the venv to dev-only deps and **deletes every workspace editable install** (the workspace packages live in the `full` extra, not the default deps). **Always `uv sync --extra full`** (matches `install.sh:176`). Symptom of having done the wrong one: `ModuleNotFoundError: No module named 'sift_core'` / `'sift_gateway'`. Fix = re-run `uv sync --extra full`. (Hit & recovered in Session 3.)
2. **Gateway contract probe (no evidence needed)** — hit the live gateway over HTTPS and assert tool inventory + gate behaviour:
   - `initialize` → capture `Mcp-Session-Id` → `notifications/initialized` → `tools/list` (note: `/mcp/` **with trailing slash**; bearer token required).
   - Assert: every advertised tool is namespaced; core tools present even with all add-ons disabled; calling any agent tool on an **unsealed** case returns the F-A block response.
   - This is the conformance surface (the per-backend `/mcp/{name}` mounts) the spec wants to formalize — wire a script for it in Phase 4.
3. **End-to-end on the fresh VM** — full workflow: `install.sh` → portal first-run registration → evidence copy → **seal** → agent runs a real DFIR loop (`run_command` → `record_finding` → grounding/provenance) → examiner reviews in portal. Run at each `🔒 PHASE GATE`. Use the smaller evidence sample for iteration; full ROCBA for the MVP gate.

**The single most important live assertion (regression guard for F-A):** on a case with no sealed manifest, *every* agent `/mcp` tool call is blocked; after the examiner seals and `chain_status==OK`, the same calls succeed; corrupt the evidence → calls block again until re-sealed.

---

## 5 · Add-on migration playbook — reconfigure existing MCPs to the spec

The four bundled backends (`opensearch-mcp`, `opencti-mcp`, `windows-triage-mcp`, `forensic-rag-mcp`) become the **reference implementations** of the contract. This is the repeatable recipe to bring an existing MCP into conformance so it can be dropped on the live VM and aggregated with no special-casing. It's the concrete fill-in for **Phase 6** (and what a third party copies for their own backend). Don't start it until the contract exists (Phase 4); use it then to migrate one backend at a time.

**Migration order:** do `forensic-rag-mcp` first (smallest, 3 tools, read-only reference) to shake out the recipe, then `windows-triage-mcp`, `opencti-mcp`, and `opensearch-mcp` last (largest, has the `case_host_fix`→`opensearch_host_fix` rename and the most tools).

### Per-backend steps (repeat for each)
1. **Author `sift-backend.json`** at the backend's well-known path. Fill: identity (`name`, namespace `prefix`), `spec_version`, `tier: addon`, per-tool `read_only` + `readOnlyHint` + `evidence_class` (`read_only` / `analysis` / `mutating`) + **standardized** per-tool `category` / `recommended_phase` / `health` / `hidden_from_agent` (the UX metadata moved out of core in 6.1 — this is what feeds `tools/list` meta and `environment_summary`), `capabilities.provides` (enum: `reference`, `search`, `ingest`, `enrichment`, `baseline`, `threat-intel`; set `reference` only when the backend supplies independent grounding/corroboration), `enriches_responses` (true only if the backend enriches its own tool output), and `requires[]` (services, RAM, docker, offline DBs). **No `identity.*` field** — F-F retired `accepts_analyst_override`; identity is core-native and never in a manifest or schema.
2. **Namespace every tool** to `prefix_tool` — `opensearch_*`, `cti_*`, `wintriage_*`, `kb_*`. This is what removes the reactive collision-prefixing and the `get_health`/`server_status` clashes. Update the tool registration names in the backend's `server.py`.
3. **Strip core-owned tools** the backend no longer provides. For `opensearch-mcp`: rename `case_host_fix` → `opensearch_host_fix` (it stays — F-D, scoped to index/alias state), and make sure it does **not** touch global case state. No add-on should ship case/findings/evidence tools (those are core now).
4. **Drop identity-injection params from the agent-facing schema.** Add-ons don't accept `analyst_override`; if any tool has it, remove it from the signature so it never appears in the advertised schema (R-identity).
5. **Validate + probe:** the gateway must (a) schema-validate the manifest, (b) run the conformance probe against the backend's `/mcp/{name}` mount, (c) only then advertise its tools. A failing manifest/probe must reject the backend with an actionable reason — never silently degrade.
6. **Wire `requires[]` gating:** if a backend's prerequisite is absent (e.g. OpenSearch service down, insufficient RAM), the gateway advertises it as unavailable rather than crashing — core stays up.

### Live-environment integration test (per backend, on the fresh VM)
- Enable only core + the one migrated backend. `tools/list` shows core tools + the backend's `prefix_*` tools, nothing un-namespaced.
- Confirm the **evidence gate (F-A) still governs** the backend's tools: unsealed case → the add-on's tools are blocked too; sealed+OK → they run.
- For a `provides:["reference"]` backend: record a finding after calling one of its tools and confirm the **declaration-driven grounding** counts it (no hardcoded names) — and that with the backend disabled, grounding goes inert (doesn't break).
- Disable/kill the backend mid-session → core tools and the gateway stay healthy (R-core-survives).
- Run the backend's own pre-existing test suite against the renamed namespace; fix fallout.

### Done-condition (feeds the Phase 6 gate)
All four backends pass the conformance probe, advertise only namespaced tools, are governed by the F-A gate, and the three reference backends light up grounding purely from their manifest `provides`. Their manifests also carry the category/phase/health metadata that used to be hardcoded in core (6.1), so **migrating them requires no `mcp_endpoint.py` edit**. A from-scratch backend built from the spec + one of these as a template should aggregate on the first try **with zero core changes**, and an operator can register it from the portal (6.3).

---

## 6 · Phases (MVP = 0–6)

Legend: `[ ]` todo · `[~]` partially done (see inline notes) · `[x]` done & Test passes · per task: **What / How / Why / Test**.

### Phase 0 — Rename + foundations (D1)
Kills nothing yet; unblocks everything. Mechanical but wide (~141 `AGENTIR_CASE_DIR`, ~55 `/cases` literals). **Clean cutover — no back-compat** (fresh VM + fresh case): remove `agentir`/`AGENTIR_*`/legacy service-token prefixes entirely, don't dual-name anything.

- [x] **0.1 Rename Python package `agentir_core` → `sift_core`** ✅ Session 3
  - *How:* rename dir + `pyproject` name; update all imports. **Delete** the old name — no shim module.
  - *Why:* single core identity; the package is already the de-facto core.
  - *Test:* full suite imports clean under `sift_core`; `grep -r agentir_core` returns nothing in source.
  - *Done:* `git mv packages/agentir-core → packages/sift-core`, `src/agentir_core → src/sift_core`; dist name `agentir-core`→`sift-core` (own pyproject + 4 dependents + root workspace source/extra); all `.py` + `install.sh` swept (0 `agentir_core` in source); `uv sync --extra full` regenerated editable installs; per-package suites match baseline exactly (sift-core 225, case-dashboard 274, sift-gateway 104, case-mcp 23, opensearch 973+71skip, sift-mcp 4, report 31, forensic 20, win-triage 11). AGENTS.md code refs updated; docs module refs updated (paths `/var/lib/agentir` + `agentir_core_write` audit key + `configs/audit/99-agentir-evidence.rules` left for 0.2/0.3). `agentir.plugins` entry-point group + `opensearch_mcp.agentir_plugin` left for 0.3 (not `agentir_core`).
- [x] **0.2 Rename env/path surface `AGENTIR_*`→`SIFT_*`, `/var/lib/agentir`→`/var/lib/sift`** — RENAME DONE (Session 3); `/cases` single-resolver consolidation DONE (Session 4)
  - *How:* central config reader uses **only** the `SIFT_*` names (no fallback, no symlink). Audit the ~55 bare `/cases` literals — route them all through one path-resolution function.
  - *Why:* one config source that path-resolution, the gate, `run_command` cwd, and the portal all read (prereq for F-B and customizable paths).
  - *Test:* boot with `SIFT_*` set; `grep -r 'AGENTIR_\|/var/lib/agentir'` returns nothing in source; no bare `/cases` literal escapes the resolver (grep returns only the resolver).
  - *DONE this session:* all 41 `AGENTIR_*` env vars → `SIFT_*` (442 occ.), `/var/lib/agentir` → `/var/lib/sift`, and config home `~/.agentir` → `~/.sift` — across **all** `.py`/tests, `install.sh`, `configs/*` (incl. the two `.template` files `gateway.yaml.template` + `apparmor/sift-gateway.template`, easy to miss — they're rendered with `${SIFT_*}` so leaving `${AGENTIR_*}` would break first-run), docs, AGENTS.md, and `frontend/src`. `grep -rE 'AGENTIR_|/var/lib/agentir'` over source/config = **0**. install.sh `bash -n` clean; `SIFT_HOME=$HOME/.sift` / `SIFT_STATE_DIR=/var/lib/sift` consistent with code. All per-package suites unchanged (same counts as Phase 0.1).
  - *`/cases` resolver — DONE (Session 4):* added the single resolver `sift_core.case_io.cases_root()` (precedence `SIFT_CASES_ROOT`→`SIFT_CASES_DIR`→`~/cases`, matching what most sites already did) and routed **all 13** scattered cases-root reads through it: `sift_core` (`get_case_dir`, `case_ops` list/init/activate), `case-mcp`, `report-mcp` (×2), `opensearch-mcp` (`ingest_cli` ×2, `server.py` ×2, `containers.py`), `sift-mcp/security.py`, and — after **adding a `sift-core` dep** — `case-dashboard/routes.py` (`_load_cases_root` fallback; its `/cases` default replaced by the resolver's `~/cases`) + `forensic-mcp/case/manager.py` (`CaseManager.cases_dir`). Removed now-orphaned `_DEFAULT_CASES_DIR`/`CASES_DIR_ENV`/`DEFAULT_CASES_DIR` constants. **Intentional belts kept** (documented in-code): the static `/cases` + `/evidence` literals in `sift-mcp/security.py` and the allow-root list in `opensearch/server.py` — the latter now *also* includes `cases_root().resolve()` so a custom `SIFT_CASES_ROOT` is honored. Forensic `server.py:607/614` `/cases/{case}/evidence/` are illustrative docstrings, left. **Single writer→reader path:** the only env *writers* are the gateway (`config.py apply_case_env`, yaml→env) and the portal (`routes.py` first-run registration); the only env *reader* is `cases_root()`. `grep /cases` over non-generated source now returns only the resolver + the two intentional belts + docstrings. (`grep AGENTIR_` over source/config = 0; the one hit is the generated frontend bundle, still pending the VM rebuild noted in Session 3.)
  - *NOTE:* `_agentir_context` warning key → **Phase 4** (removed with the readOnlyHint carve-out).
- [x] **0.3 Rename `agentir-opensearch`→`sift-opensearch` and any other `agentir-*` service/identifier surface.** ✅ Session 5
  - *Test:* service starts; role names resolve; no `agentir-` identifier remains.
  - *Done:* completed the under-counted remaining surface from the Session 5 audit: HMAC domains `agentir-auth-v1`/`agentir-signing-v1`→`sift-auth-v1`/`sift-signing-v1` (backend + portal frontend + tests), evidence anchor schema/payload `agentir.evidence-anchor.v1`/`AGENTIR|...`→`sift.evidence-anchor.v1`/`SIFT|...`, portal cookie `agentir_session`→`sift_session`, audit rule file `99-agentir-evidence.rules`→`99-sift-evidence.rules`, audit keys `agentir_evidence_write`/`agentir_core_write`→`sift_evidence_write`/`sift_core_write`, OpenSearch CLI plugin module/group `opensearch_mcp.agentir_plugin` + `agentir.plugins`→`opensearch_mcp.sift_plugin` + `sift.plugins`, and remaining package docstrings/comments/product strings that belonged to 0.3. Verified no `agentir-*`, `agentir_plugin`, `agentir.plugins`, old HMAC domains, old cookie name, old audit keys, or old evidence-anchor schema remain in source/config outside historical tracker/spec/docs and the deferred 0.4/Phase 4 names.
- [x] **0.4 Rename service-token prefix to `sift_svc_*`** ✅ Session 6
  - *How:* update `generate_service_token()` and the portal token-mgmt UI/labels. Tokens are minted fresh on the new VM, so **no back-compat for existing tokens** — old tokens simply won't exist.
  - *Why:* consistent `sift` identity on the one artifact that crosses from operator (portal) to agent.
  - *Test:* portal mints a `sift_svc_*` token; agent authenticates with it; legacy token prefixes return nothing in source.
  - *Done:* `generate_gateway_token()` now emits `sift_gw_*`, `generate_service_token()` emits `sift_svc_*`, installer first-run config writes the new prefixes, portal token creation inherits the new service token format, and gateway/dashboard auth tests plus docs/config examples were updated. Legacy token prefixes have no hits in tracked source/config/docs outside the untracked `old-repo-AGENTS.md`.

🔒 **PHASE 0 GATE:** full suite green on `revamp/spg-v1`; gateway boots on the fresh VM via renamed `install.sh`; **zero `agentir`/`AGENTIR_` references remain in source** (`grep -ri agentir packages/` is clean except historical changelog/docs).

### Phase 1 — Consolidate core library (kills P2) + relocate integrity records (F-B)
Move duplicated case logic out of `forensic-mcp`/`case-mcp`/`report-mcp` into `sift_core`, and move integrity records outside the agent jail while the code is already being touched.

- [x] **1.1 Move findings/timeline/TODO/evidence-listing logic into `sift_core`** ✅ Session 7
  - *How:* `sift_core` becomes the single owner of `record_finding`, `record_timeline_event`, `manage_todo`, `list_existing_findings`, evidence listing. The backends call into it; no parallel implementations remain.
  - *Why:* P2 duplication is the interoperability hazard the revamp exists to kill.
  - *Test:* one implementation per operation (grep); existing finding/timeline tests pass against the consolidated path.
  - *Done:* moved `CaseManager` from `forensic_mcp.case.manager` to `sift_core.case_manager`; `forensic-mcp` now imports the core manager and keeps only MCP tool wrappers. Moved finding validation to `sift_core.finding_validation` with a compatibility re-export from `forensic_mcp.discipline.validation`. Centralized manifest-backed evidence listing in `sift_core.evidence_ops.list_evidence_status_data`; `case-mcp` delegates `evidence_list` to it, and report/evidence reads use the core evidence layer.
- [x] **1.2 Move finding-time CORE-LOGIC into `sift_core`: validation, provenance classification, grounding, considerations** ✅ Session 8
  - *How:* relocate `_classify_provenance`, `_score_grounding`/`_grounding_result`, `_build_finding_considerations`, and the `VALIDATION_FAILED` enforcement. Keep FK data package as a dependency.
  - *Why:* this logic must live in core so every backend (and the agent) gets identical enforcement; it's not an add-on concern.
  - *Test:* finding rejected on `provenance==NONE`; considerations attached; grounding returns `{}` with no reference backends.
  - *Done:* `sift_core.case_manager` owns validation enforcement, provenance classification, grounding score/result, and `build_finding_considerations`; `forensic-mcp` only enriches the tool response with the core result.
- [x] **1.3 Make grounding declaration-driven (remove hardcoded `_GROUNDING_MCPS`)** ✅ Session 8
  - *How:* replace the `(forensic-rag-mcp, windows-triage-mcp, opencti-mcp)` tuple with "backends whose manifest declares `capabilities.provides: ["reference"]`." (Manifest schema lands in Phase 4; here, stub the lookup behind an interface so Phase 4 just fills it.)
  - *Why:* zero hardcoded backend names — community reference backends must count automatically.
  - *Test:* with a fake manifest declaring `provides:["reference"]`, grounding counts it; with none, grounding is inert.
  - *Done:* added `set_reference_backend_provider()` plus `SIFT_REFERENCE_BACKENDS` fallback. With no declared reference backends, grounding returns `{}`; no hardcoded reference-backend names remain in `sift_core`/`forensic-mcp`.
- [x] **1.4 Relocate integrity records to `/var/lib/sift/<case_id>/` (F-B)** ✅ Session 8
  - *How:* `audit/`, `approvals.jsonl`, `evidence-ledger.jsonl`, manifest move outside `case_root`; update `audit_ops`, `evidence_chain`, `case_io._CASE_SUBDIRS`, `_classify_provenance`, `_score_grounding`, and the gate to read the new location. `evidence/extractions/reports/agent` stay under `case_root`. Confirm `run_command`'s jail cannot reach the new path.
  - *Why:* tamper-resistance — the agent must not be able to delete/alter its own audit trail or the custody ledger. This is the core security pitch.
  - *Test:* `run_command` with `cwd` traversal cannot read/write the records dir; provenance/grounding still resolve audit_ids from the new path; chain status still computes.
  - *Done:* added `sift_core.case_io.case_records_dir()` / `case_audit_dir()` / `case_approvals_path()` backed by `SIFT_STATE_DIR` or `/var/lib/sift`; moved manifest, ledger, anchors, approvals, and audit reads/writes through those helpers. Removed `audit` from core case subdirs. Local `/tmp` tests keep compatibility shadows only for unit-test isolation; production/default paths are outside `case_root`.
- [x] **1.5 Confirm `case_host_fix` stays in `opensearch-mcp` (F-D) — no core move.** ✅ Session 8
  - *Test:* no `case_host_fix` reference in `sift_core`/gateway core tools.
  - *Done:* removed the stale gateway workflow map mention; `case_host_fix` remains only in `opensearch-mcp` code/tests.

🔒 **PHASE 1 GATE:** single implementation of each case operation; integrity records under `/var/lib/sift`; agent jail proven unable to reach them; suite green.

### Phase 2 — In-process core tools (kills P1)
Register the ~25 core tools *in-process* in the gateway instead of as stdio subprocesses.

- [x] **2.1 Register core tools in-process** (execute, case mgmt, evidence/CoC, findings/timeline/TODO, audit/reasoning/external-action). ✅ Session 11
  - *How:* gateway exposes `sift_core` operations directly; retire `forensic-mcp`/`case-mcp`/`report-mcp` as separate subprocesses for the core slice.
  - *Why:* P1 — a core capability must not silently vanish because a subprocess failed to boot.
  - *Test:* with **all** add-on backends disabled, `tools/list` still shows the full core tool set; killing any add-on doesn't remove a core tool.
  - *Done:* 18 in-process core tools registered via `sift_core.agent_tools` (case/evidence/findings/timeline/TODO/audit/reasoning/external-action + execute), proven by the gateway regression that missing core subprocess commands don't remove them and `run_command(["date"])` runs through `sift-core` (Sessions 9–10). Reporting migration finished Session 11: report-generation logic moved into `sift_core.reporting` + `sift_core.report_profiles` and case-metadata into `sift_core.case_metadata` (real move, no adapter). Reporting is **not** an agent tool — it's portal-owned (see 2.3). `report-mcp` slimmed to a dormant thin delegator over core. **Live VM e2e confirmed Session 13** (14/14 gate checks passed on siftworkstation). Note: actual tool count is **19** — 18 from `sift_core.agent_tools` plus `environment_summary` registered directly in `mcp_endpoint.py`.
- [x] **2.2 Remove `export_bundle`/`import_bundle` from the agent surface (F-C); keep `sift_core` functions.** ✅ Session 11
  - *Test:* tools not in `tools/list`; `sift_core.export_bundle` still unit-tested.
  - *Done:* neither tool is in the in-process agent registry (`core_tool_names()` excludes both) and `report-mcp`/`case-mcp` subprocesses are not started, so they never reach `tools/list`; pruned the dead `export_bundle`/`import_bundle` entries from the gateway `_TOOL_CATEGORIES` map. `sift_core.case_io.export_bundle`/`import_bundle` remain present (kept for a future portal export feature) and still unit-tested in `test_case_io.py`.
- [x] **2.3 Make `set_case_metadata` + report generation portal-owned (F-E); remove from agent surface.** ✅ Session 11
  - *How:* move metadata-set + `generate_report` triggers to the portal; agent no longer calls them.
  - *Test:* tools absent from agent `tools/list`; portal can set metadata and generate a signed report.
  - *Done:* core logic lives in `sift_core.reporting.generate_report_data` + `sift_core.case_metadata.set_case_metadata`/`get_case_metadata`. Portal `generate_report_route` now imports `sift_core` (the `report_mcp.server._generate`/`report_mcp.profiles.PROFILES` import shortcut is gone), and a new examiner-guarded `POST /api/case/metadata` route (`post_case_metadata`) + `postCaseMetadata` frontend helper own metadata-set. Neither tool is on the agent surface (registry excludes them; `report-mcp` not started); pruned their dead entries from the gateway category/phase maps. New tests: `case-dashboard/tests/test_case_metadata_endpoint.py` (7) prove the portal can set metadata with role/auth guards; the existing report flow (generate→save→download/commit) remains green against the core-backed route.

🔒 **PHASE 2 GATE:** ✅ **GREEN (Session 13)** — 19 core tools present (18 sift_core + gateway-native `environment_summary`), zero add-on tools; F-A gate blocks on no-case and on corrupted evidence, passes on sealed case; `run_command` executes via in-process executor; `record_action`/`record_finding` reach the tool layer; portal correctly rejects agent token. Script: `scripts/phase2_gate_test.py` (14/14 checks on siftworkstation).

### Phase 3 — Sandbox + privilege executor (D2 + D3)
- [x] **3.1 Relocate denylist `security.yaml` → operator-editable `gateway.yaml` + non-weakenable deny floor** ✅ Session 16
  - *How:* load order = hardcoded deny floor ∪ operator denylist; refuse to start on empty policy (preserve current behaviour); deny floor cannot be removed by config.
  - *Why:* D2 — operator can tighten, never weaken below the floor (mkfs*, shutdown/reboot/halt/init, kill*, env/printenv token-leak, raw sockets).
  - *Test:* operator config can't delete a floor entry; empty policy refuses boot; denied command blocked end-to-end.
  - *Done:* moved executor policy out of package-data `security.yaml` and into `execute.security` in operator-owned `gateway.yaml`; `sift_core.execute.security_policy` now builds the effective policy as **hardcoded deny floor ∪ default denylist ∪ operator additions**. Gateway config load/start refuses missing or empty `execute.security`, exports the merged policy to the in-process executor, and clears the policy cache on reload. Removed the old `packages/sift-core/data/catalog/security.yaml`. Added tests for non-weakenable floor entries, empty policy rejection, gateway config export, and `run_command(["env"])` being blocked through `Gateway.call_tool`.
- [x] **3.2 Optional allowlist mode** — config flag flips denylist→allowlist. ✅ Session 17
  - *Test:* in allowlist mode, only listed commands run; everything else blocked.
  - *Done:* added `execute.security.mode` (`denylist` default, optional `allowlist`) and `execute.security.allowed_binaries` to `gateway.yaml`; the effective policy is exported through the existing `SIFT_EXECUTE_SECURITY_POLICY` path. `run_command` still applies the deny floor first, so floor entries remain blocked even when listed in `allowed_binaries`. Added local policy/config/gateway tests for default denylist behaviour, allowlist permit, unlisted-command block, deny-floor precedence, and end-to-end blocked command responses.
- [x] **3.3 Hardened isolated executor** (separate process · cgroup · AppArmor · `shell=False` · path jail). ✅ Session 19
  - *Why:* P6 — contain blast radius distinct from other backends.
  - *Test:* executor runs unprivileged; cannot escape the case jail; resource limits enforced.
  - *Done:* 
    - `run_command` executes through a short-lived isolated Python worker process, which then launches the requested forensic binary with `shell=False`/argv-only execution. Denylist/allowlist and argument/path validation still happen before the worker is invoked.
    - Worker starts tools in a new process session, kills the process group on timeout, enforces output capture limits, applies `RLIMIT_CPU` where available, and supports optional `SIFT_EXECUTE_MEMORY_LIMIT` address-space limiting.
    - Large stdout over the response budget is auto-written under `case/agent/run_commands/outputN` and the MCP response carries the full output path/hash/byte count. Case cwd jail behaviour is preserved at the agent-facing wrapper.
    - **cgroup & AppArmor Confinement:** Wrapped the worker command with `systemd-run --user --scope` to run inside its own cgroup scope, applying `MemoryMax` and `MemoryHigh` resource limits when `SIFT_EXECUTE_MEMORY_LIMIT` is specified.
    - Implemented automatic user session bus configuration (`DBUS_SESSION_BUS_ADDRESS` / `XDG_RUNTIME_DIR`) with a robust fallback to direct execution (plus `systemctl --user reset-failed` cleanup) if systemd-run fails to boot.
    - Hardened the gateway AppArmor template to permit executing `/usr/bin/systemd-run` and `/usr/bin/systemctl` with `rix` inheritance.
    - **Sudo Target Validation:** Added validation for target commands executed via `sudo` wrappers. The executor skips sudo options to extract the target binary (e.g. `reboot` or `fdisk`), applies denylist/allowlist/flag sanitization to it, and resolves both `sudo` and the target binary to absolute paths. Interactive sudo shells (`sudo -i`, `sudo -s`) or running sudo without a target command are strictly blocked.
    - Added unit and integration tests verifying cgroup scopes, memory limit mapping, D-Bus environment, fallback, and sudo validation rules.
- [x] **3.4 Privileged path: capabilities-first → sudoers-allowlist fallback (D3)**
  - *How:* vol/dd/mount escalate via Linux caps; fallback to NOPASSWD full-path sudoers entries (no shell, no wildcard); every escalation audited.
  - *Why:* P6 — some artifacts can't be extracted today; gateway must never run as root.
  - *Test:* a privileged tool succeeds via caps; with caps removed, succeeds via the exact sudoers entry; a wildcard/shell escalation is rejected; audit records every escalation.

🔒 **PHASE 3 GATE:** executor isolation verified; privilege escalation audited and narrow; suite + live `run_command` tests green.

### Phase 4 — Universal identity + contract enforcement + declaration-driven gate (kills P3/P4)

This phase does two coupled things. **(a)** It makes **identity a core-native, transparent property (F-F)**: resolved **once** at the auth boundary, threaded out-of-band to core tools, stamped into every audit entry — and **fully invisible** to the agent's tool schemas *and* to add-on backends. `analyst_override` / `analyst_identity` / `ANALYST_TOOLS` / `accepts_analyst_override` are **retired entirely** — not relocated into the manifest. **(b)** It lands the versioned **Backend Contract v1** (manifest + JSON Schema + probe), the binary F-A gate, declaration-driven grounding, and the namespace rule.

**Ordering is load-bearing.** Do the identity spine (4.1 → 4.2) first, then the F-A gate (4.3, isolated deletion), then the contract (4.4–4.9), then the probe (4.10) which exercises code 4.2 deletes. Don't reorder.

**Grounded starting state (verified in code 2026-06-02):**
- Identity is resolved in **two** places: `MCPAuthASGIApp` for the agent `/mcp` surface (`mcp_endpoint.py:156-206`) and `AuthMiddleware` for everything else (`auth.py:83-161`). `/mcp` is **deliberately exempt** from `AuthMiddleware` because `BaseHTTPMiddleware` buffers responses and breaks SSE (`auth.py:14-15,124-130`). **Do not merge them** — share a resolver, keep the two ASGI layers.
- Today only `examiner`+`role`+`token_id`+`source_ip` reach `scope["state"]` (`mcp_endpoint.py:195-198`); `created_by`/`agent_id` exist in the token store (`routes.py:3047-3162`, `"examiner": agent_id` for agent tokens) but are **dropped** by the gateway.
- Core tool input-schemas **already do not expose** `analyst_override` — it's injected into the `arguments` dict server-side at **three** sites: `server.py:539-540` (in-process core), `server.py:575-577` (add-on path), `mcp_endpoint.py:827-828` (per-backend `/mcp/{name}` path). `call_core_tool` already takes `examiner=` as a kwarg (`agent_tools.py:918-932`) and `Gateway.call_tool` already passes it (`server.py:550`) — the out-of-band path **exists** and is merely shadowed by the redundant arg injection.
- The evidence-gate function is **already binary** (`blocked = status != OK`, `evidence_gate.py:113-120`); the read-only carve-out lives only in the *enforcement branch* (`mcp_endpoint.py:582-633`) + helpers `VIOLATION_STATUSES`/`is_violation`/`build_unsealed_warning` (`evidence_gate.py:37-42,123-145`).
- `create_backend` (`backends/__init__.py:14-62`) does **zero** manifest loading today. `_build_tool_map` (`server.py:242-298`) does **reactive** `backend__tool` collision-prefixing.

---

- [x] **4.1 Universal identity context (F-F) — resolve once, stamp everywhere** ✅ Session 21
  - *Done:* new `sift_gateway/identity.py` with frozen `Identity` dataclass + `resolve_identity(...)` called by both auth layers; `created_by`/`agent_id` now survive into `scope["state"]`/`request.state` (stopped dropping them); full identity stamped into the audit envelope on success/error/blocked, and a throttled audit line on 429 (`test_log_rate_limit_violation`). SSE on `/mcp` unaffected.
  - *How:*
    - Add a single `resolve_identity(token, api_keys) -> Identity | None` helper (new `sift_gateway/identity.py`) that both auth layers call, returning a frozen dataclass: `principal`, `principal_type` (`"user"`/`"agent"`/`"service"`, derived from `role`), `token_id` (existing `_hash_token`, `mcp_endpoint.py:209-211`), `agent_id`, `created_by`, `role`, `source_ip`, `auth_surface` (`"mcp"`/`"portal"`/`"rest"`). For agent tokens `principal = agent_id`; dev/no-keys mode → `principal="anonymous"`, `principal_type="user"`.
    - Plumb the new fields through `verify_api_key`'s `key_info` consumers so `created_by`/`agent_id` survive into `scope["state"]`/`request.state` (they're in the token store already — stop dropping them). Store the whole object at `request.state.identity` and keep the flat `examiner`/`role`/`token_id`/`source_ip` attrs as thin reads off it for back-compat with existing call sites.
    - Extend `_extract_request_context` (`mcp_endpoint.py:214-228`) to surface the full identity.
    - **Audit envelope:** pass `principal`, `principal_type`, `agent_id`, `created_by`, `auth_surface` via the existing `extra=` dict (`sift_common/audit.py:248,278-279`) on the gateway envelope (`mcp_endpoint.py:765-787`) **and** the per-backend HTTP path (`mcp_endpoint.py:877-888`). Stamp them on **success, error, blocked, and rate-limited** outcomes.
    - **Rate-limited audit (new):** today 429s `return` before any audit (`mcp_endpoint.py:121-126,162-165,201-204`). Emit one audit line on rejection, **throttled/sampled** (don't write one per 429 — that's an audit-flood vector).
  - *Why:* F-F — one trust boundary owns identity; human accountability (`created_by`) and machine attribution (`agent_id`/`principal`) are always linkable in audit, per **R-roles**. Backends and the LLM never see it.
  - *Test:* agent-token call → audit entry carries `principal=agent_id`, `principal_type="agent"`, `created_by=<examiner>`, `token_id`, `source_ip`, `auth_surface="mcp"`; no-keys mode → `principal="anonymous"`; a 429 emits exactly one (throttled) audit line; SSE streaming on `/mcp` still works (no `BaseHTTPMiddleware` regression).

- [x] **4.2 Retire `analyst_override` end-to-end — identity becomes invisible & out-of-band** ✅ Session 21
  - *Done:* deleted all three arg-injection sites + `ANALYST_TOOLS` frozenset + `accepts_analyst_override` from `CoreToolSpec`; identity flows only via the `examiner=` kwarg with per-call principal override on the audit entry (`test_per_call_examiner_stamping`). Legacy `analyst_override` params removed from `forensic-mcp/server.py`. Grep-gate `analyst_override|ANALYST_TOOLS|accepts_analyst_override|analyst_identity` over non-test source = **CLEAN**.
  - *How:*
    - **Gateway:** delete the three arg-injection sites — `server.py:538-540`, `server.py:571-577`, `mcp_endpoint.py:826-828` — and the `ANALYST_TOOLS` frozenset (`mcp_endpoint.py:62-72`) + the `core_accepts_analyst_override`/`ANALYST_TOOLS` imports (`server.py:13,105`). Identity flows **only** as the existing `examiner=` kwarg on `Gateway.call_tool` / `call_core_tool`.
    - **Core:** drop `accepts_analyst_override` from `CoreToolSpec` (`agent_tools.py:42,127,133,149,162,168,223,286-288`). In `call_core_tool` (`agent_tools.py:929-932`) compute `effective_examiner = (examiner or resolve_examiner())` — **remove** the `args.get("analyst_override")` fallback. Make the handlers read the threaded principal, not `args["analyst_override"]`: `_log_reasoning` (`:636,642`), `_log_external_action` (`:658,663,698`). For `record_action`/`record_finding`/`record_timeline_event`/`manage_todo`, pass the principal to `audit.log(...)`/`examiner_override=` so the **audit entry is stamped per-call** (today `AuditWriter.examiner` is process-level from env — the per-call principal must override it; use an explicit arg or a contextvar set by `call_core_tool`).
    - **Backends stay identity-transparent:** add-on `/mcp` calls receive **no** identity argument at all. Attribution for add-on calls comes solely from the 4.1 audit envelope (`principal`/`agent_id`/`token_id`), never from a tool arg.
    - **Legacy backend cleanup:** remove the now-dead `analyst_override` params from `forensic-mcp/server.py:71,199,659,699,724,748` (forensic core was retired in-process in Phase 2 — confirm the path is dead before deleting, then delete).
    - Grep-gate: `grep -rn "analyst_override\|analyst_identity\|ANALYST_TOOLS\|accepts_analyst_override" packages --include="*.py"` returns **only** test files asserting absence (or nothing).
  - *Why:* F-F + **R-identity** — the gateway is the *only* authority that sets examiner identity; making it a Python param (not a tool arg) means it can't appear in a schema, can't be spoofed by a backend, and can't be hallucinated by the agent.
  - *Test:* `tools/list` for every core write tool shows **no** `analyst_override` property (already true — assert it stays); a `record_finding` call with `analyst_override` in `arguments` **ignores** it and stamps the authenticated principal; an add-on tool call passes through with the identity arg **absent**; full per-package suites green.

- [x] **4.3 Strict binary evidence gate — F-A block-all (isolated deletion)** ✅ Session 21
  - *Done:* enforcement branch now always returns `build_block_response` when `gate["blocked"]`; the read-only carve-out and helpers `VIOLATION_STATUSES`/`is_violation`/`build_unsealed_warning` are deleted from `evidence_gate.py`; `environment_summary` blocks when unsealed/violation and is allowed only on OK (`test_gate_*`). The `_agentir_context` payload key was renamed to `_sift_context` (`mcp_endpoint.py:763-766`) — last runtime `agentir` string gone; the obsolete `test_two_tier_gate.py` was removed and replaced by `test_phase4.py`. (Note: `_VIOLATION_STATUSES` in `sift_core/reporting.py` is an unrelated report-time constant, intentionally kept.)
  - *How:* in the enforcement branch (`mcp_endpoint.py:556-633`) delete the `is_violation`/read-only `else` split and **always** return `build_block_response(name, gate)` whenever `gate["blocked"]`. Remove the now-dead helpers `VIOLATION_STATUSES`, `is_violation()`, `build_unsealed_warning()` (`evidence_gate.py:37-42,123-145`) and the `_is_read_only`/`readOnlyHint` inspection. `check_evidence_gate` is already binary — don't touch it. UNSEALED and every non-OK status block **all** agent tools (including `environment_summary`). Block response points to the portal. **Rename** the lingering `_agentir_context` payload key → `_sift_context` at the normal-response injection (`mcp_endpoint.py:746-749`) — closes the Phase 0.2 deferral and the last `agentir` runtime string.
  - *Why:* F-A — nothing runs against unsealed or compromised evidence; simplest defensible custody invariant. Health/lifecycle/portal/rest are **not** agent tools and stay ungated (**R-A**).
  - *Test:* the §4 regression guard — unsealed → **all** blocked (incl. read-only + `environment_summary`); sealed+OK → all allowed; corrupt → all blocked until re-seal. `grep -rn "_agentir_context\|build_unsealed_warning\|VIOLATION_STATUSES" packages` is clean.

- [x] **4.4 Backend manifest schema (`sift-backend.json`) + JSON Schema (Contract v1)** ✅ Session 21
  - *Done:* `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json` authored (major-version `spec_version` compat, `namespace`, `capabilities.{provides,requires,enriches_responses}`, `tools[]`, `health`; no identity field); `jsonschema>=4.18` added as a direct dep. Schema self-validates and rejects bad `spec_version`/missing `namespace` (`test_manifest_validation`).
  - *How:* author `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`. One flat schema (your note @338) — fillable in 10 min. Fields:
    - `spec_version` (string) — **major-version compat**: gateway accepts `1.x`, rejects `2.x`. (Do **not** require exact `"1.0"` — it breaks on the first minor bump.)
    - `name`, `version`, `tier` (`"addon"` only in real files; `"core"` is implicit/in-process and ships no manifest), `transport` (`"stdio"`/`"http"`), `namespace` (the tool prefix).
    - `capabilities`: `provides` (e.g. `["reference"]`), `requires` (services/RAM/docker/offline-DB prereqs), `enriches_responses` (bool — **must** have a consumer wired in 4.x or be dropped; ties to the `_sift_context` response injection).
    - `tools[]`: `name`, `description`, `read_only`, `readOnlyHint`, `evidence_class` (`read_only`/`analysis`/`mutating`), `category`, `recommended_phase`. **No `identity.*` / `accepts_analyst_override` field** — identity is core-native (F-F), backends are transparent.
    - `health`: endpoint path or sub-command.
    - **`output_cap` is NOT a per-tool manifest field** — the single cap lives in the trust layer (Phase 5). If a per-tool hint is ever wanted it may only *tighten*, never loosen, the central cap; for v1, omit it to avoid the Phase 5 conflict (resolves review C1).
  - *Dependency:* add `jsonschema` as a direct dep in `packages/sift-gateway/pyproject.toml`.
  - *Test:* schema self-validates; a hand-written minimal addon manifest validates; an invalid one (bad `spec_version`, missing `namespace`) is rejected with a field-level error.

- [x] **4.5 Manifest discovery + validation in `create_backend` (warn-now, enforce-in-P6)** ✅ Session 21
  - *Done:* `load_and_validate_manifest(name, config)` in `backends/__init__.py` resolves an explicit `manifest_path` or the well-known `packages/<name>/sift-backend.json`, validates against the schema. Phase 4 = warn + degrade (missing/invalid manifest logs a clear warning and still boots core); the P6 hard-reject flip is left as the documented Phase 6 change.
  - *How:* resolve the manifest per transport — **stdio:** `sift-backend.json` at the backend package's well-known path (config may override with `manifest_path`); **http:** a configured `manifest_path` or a `/manifest` fetch. Validate in `create_backend` (`backends/__init__.py:14`). **Phase 4 = warn + degrade** (log a clear warning, still start) so the four un-migrated add-ons don't break the gateway during the 4→6 window; **Phase 6 flips to hard-reject** (resolves review C3). A failing manifest must produce an actionable reason, never a silent partial.
  - *Test:* a backend with a valid manifest loads; a missing/invalid manifest in P4 logs a warning and still boots core; the same in P6 mode rejects with reason.

- [x] **4.6 Tier enforcement: core mandatory, add-ons optional** ✅ Session 21
  - *Done:* `_RETIRED_CORE_BACKENDS = {forensic-mcp, case-mcp, sift-mcp, report-mcp}` (plus `sift-core`) — a `gateway.yaml` that lists any of these as a backend raises `ValueError` on startup; add-ons toggle freely.
  - *How:* core tools are in-process (no backend entry). Reject a `gateway.yaml` that **lists** any retired/core name as a backend — `sift-core`, `forensic-mcp`, `case-mcp`, `sift-mcp`, `report-mcp` — with a `ValueError` on startup (they're core/in-process now, not subprocesses). Add-ons toggle freely.
  - *Why:* P4 — an operator must never be able to disable a core capability.
  - *Test:* config listing `forensic-mcp` as a backend refuses boot with an actionable error; disabling/enabling an add-on works.

- [x] **4.7 Declared-namespace rule (structural collision fix)** ✅ Session 21
  - *Done:* `_build_tool_map` asserts every add-on tool is `<namespace>_`-prefixed and declared in the manifest `tools[]`, rejecting mis-prefixed/undeclared tools and core-name shadows with a fatal startup error; in-process core tools + `environment_summary` exempt; the reactive `backend__tool` prefixing is removed (`test_namespace_enforcement`). Backends without a manifest gracefully degrade enforcement (warn) per the 4→6 window.
  - *How:* in `_build_tool_map` (`server.py:242-298`): assert every add-on tool starts with `<namespace>_` (from its manifest) and is **declared** in the manifest `tools[]`; reject undeclared or mis-prefixed tools with a **fatal startup error**. Reject an add-on tool whose name **collides with a core tool name** (the dangerous shadowing case) and add-on↔add-on duplicates. **Exempt** in-process core tools and the gateway-native `environment_summary` (both legitimately unprefixed). **Remove** the reactive `backend__tool` prefixing (`server.py:264-277`) and its strip logic (`server.py:282-285,566-569`).
  - *Why:* P3 — kills `get_health`/`server_status` collisions structurally instead of reactively.
  - *Test:* two backends declaring the same tool name → fatal startup error; an add-on declaring `record_finding` → rejected (core shadow); core tools + `environment_summary` still advertised unprefixed; no `__` prefixing path remains.

- [x] **4.8 `requires[]` availability gating (R-core-survives)** ✅ Session 21
  - *Done:* before advertising an add-on's tools the gateway evaluates `capabilities.requires` (ram:/env:/path/http reachability); unmet → backend marked unavailable and its tools omitted from `tools/list` while core stays up (`test_requirements_gating`). An unrecognized requirement fails closed (gates the backend loudly rather than silently passing) — `test_unknown_requirement_fails_closed`.
  - *How:* before advertising an add-on's tools, evaluate its manifest `capabilities.requires` (service reachable, RAM, docker, offline DB present). If unmet, mark the backend **unavailable** and **omit its tools** from `tools/list` — the gateway and all core tools stay up. Never crash core on an add-on prereq.
  - *Why:* declaring `requires[]` (4.4) without enforcing it is a no-op; **R-core-survives** demands graceful degradation.
  - *Test:* with a reference backend's service down, the gateway boots, core tools present, that add-on's tools absent and reported unavailable; bringing the service up re-advertises on rebuild.

- [x] **4.9 Declaration-driven grounding (fill the 1.3 provider interface)** ✅ Session 21
  - *Done:* gateway registers `set_reference_backend_provider(self.get_reference_backends)`; `get_reference_backends()` returns started+available backends whose manifest declares `capabilities.provides: ["reference"]` — zero hardcoded backend names (`test_reference_provider`).
  - *How:* register a provider with `sift_core.case_manager.set_reference_backend_provider(...)` (stub already exists, `case_manager.py:31-46`) that queries the gateway registry and returns the names of **started + available** (4.8) backends whose manifest declares `capabilities.provides: ["reference"]`. Remove the `SIFT_REFERENCE_BACKENDS` env fallback once the provider is wired (or keep only for tests). Zero hardcoded backend names anywhere.
  - *Why:* **R-no-hardcoded-names** — community reference backends count automatically by declaration.
  - *Test:* an add-on manifest with `provides:["reference"]` makes grounding count it; toggling the declaration (or downing the backend per 4.8) makes grounding go inert without breaking.

- [x] **4.10 Conformance checklist + probe script (`scripts/probe_backends.py`)** ✅ Session 21
  - *Done:* `scripts/probe_backends.py` schema-validates each manifest, hits the per-backend `/mcp/{name}` mount (`initialize`→`tools/list`), asserts namespace-prefix + declaration + `health`, and confirms no identity argument is required by any tool schema (F-F conformance). Offline self-check covered by `test_probe_backends_script_offline`. **Live VM run still pending** — see Phase 4 gate note below.
  - *How:* the probe (service identity, `sift_svc_*` token from Phase 0.4): (a) schema-validates each `sift-backend.json`; (b) hits the per-backend `/mcp/{name}` mount (`create_backend_mcp_server`, `mcp_endpoint.py:794`) — `initialize` → `tools/list`; (c) asserts every advertised tool is `<namespace>_`-prefixed and declared; (d) checks `health`; (e) confirms **no identity argument** is required by any tool schema (F-F conformance). Must run **after** 4.2 (the per-backend path still injects `ANALYST_TOOLS` at `mcp_endpoint.py:824-828` until 4.2 deletes it).
  - *Test:* probe passes for a conformant add-on; fails with actionable output for a broken one (bad prefix, undeclared tool, identity arg present, schema-invalid manifest).

🔒 **PHASE 4 GATE:** ✅ **GREEN (code-complete, unit-verified — Session 21)** — identity is core-native and invisible (no `analyst_override`/`ANALYST_TOOLS` in source, no identity field in any tool schema, audit stamps `principal`/`agent_id`/`created_by` on every outcome incl. throttled 429); gate is declaration-driven and binary (F-A: unsealed → all blocked incl. `environment_summary`); namespace + tier + `requires[]` enforced; declaration-driven grounding live; conformance probe authored + offline-green. **Live-VM caveat:** unlike Phases 2–3, Phase 4 was *not* re-run on the fresh VM this session — `scripts/probe_backends.py` against real mounts and the `phase2_gate_test.py` e2e should be replayed on the VM before the Phase 6 gate (folds naturally into the §5 add-on migration, where the first conformant manifest exists to probe). A third party could implement an add-on from the spec + schema alone.

### Phase 5 — Central output cap
- [x] **5.1 Single output-cap + redaction point in the trust layer** (response guard already = 30 patterns; centralize the size cap). ✅ Session 22
  - *Why:* consistent token/secret control regardless of backend.
  - *Test:* oversized response capped centrally; secrets redacted; per-backend ad-hoc caps removed.
  - *Done:* added the central output cap to the trust-layer module `response_guard.py` (`output_cap_bytes()` + `cap_tool_result()`), applied at the **same gateway choke point as redaction** (`mcp_endpoint.py` aggregated `/mcp` loop) in **redact-then-cap** order — a secret can never straddle the truncation boundary and leak half. **Disk-spill-for-all (chosen model):** any backend's oversized (already-redacted) response is truncated on a UTF-8-safe boundary, the full redacted text is persisted under `<case>/agent/tool_outputs/<ts>_<tool>.txt` (parallels run_command's `agent/run_commands/`, stays under `case_root/agent`), and the response carries a `[OUTPUT CAPPED BY GATEWAY …]` marker + path + sha256 + byte counts. Cap events are audited (`source="gateway_output_cap"`) and surfaced to the agent via the unified `_sift_context` note (alongside `secret_warning`). **Single knob:** `gateway.yaml` `trust.output_cap_bytes` (default **262144 = 256 KiB**) → `SIFT_OUTPUT_CAP` env via new `apply_trust_env()` in `config.py`; `response_guard.output_cap_bytes()` is the single read path (env, safe default). This is a **backstop ceiling** — run_command keeps its own tighter 10 KB `response_byte_budget` + disk-spill as a sub-limit (a feature, not an ad-hoc cap). **Scope:** aggregated agent `/mcp` surface only (the per-backend `/mcp/{name}` mounts are the service-token conformance surface, not agent-facing). New tests: `tests/test_phase5.py` (17) — resolver default/override/invalid-fallback, under/over-cap, disk-spill path + sha, no-case-dir truncation, UTF-8 boundary, the redact-then-cap no-partial-leak invariant, and `trust.output_cap_bytes`→env plumbing through `load_config`. **NOTE on "per-backend ad-hoc caps removed":** the four add-ons aren't migrated until Phase 6, so their ad-hoc response caps get stripped per-backend during the §5 migration; the sift-common parser limits (`max_rows`/`max_entries`) are legitimate structured-parse bounds used by run_command and stay.

🔒 **PHASE 5 GATE:** ✅ **GREEN (code-complete, unit-verified — Session 22)** — one cap+redaction path in the trust layer (redact-then-cap), single `trust.output_cap_bytes` knob, guard tests green (gateway 121 / core 301). **Live-VM caveat (same as Phase 4):** not re-run on the fresh VM (VM was wiped — needs `install.sh --core-only` fresh); the oversized-response cap + spill should be exercised live during the Phase 6 add-on migration (first real large-output add-on to probe).

### Phase 6 — Manifest-driven core + migrate add-ons + portal integration (MVP DONE)

**Why this phase grew.** The original 6.1 ("namespace the four add-ons + give each a manifest") was correct but incomplete, and it hid a contradiction with **R-no-hardcoded-names**. Verified in code 2026-06-02:

- The Phase 4 contract machinery is already **zero-hardcoded-names / core-change-free**: `load_and_validate_manifest`, `_build_tool_map` namespace enforcement, `requires[]` gating (`evaluate_requirement`), and grounding (`get_reference_backends` keyed on `capabilities.provides`). Adding a new backend through these needs **no** core edit. ✅
- **But three UX maps in `mcp_endpoint.py` hardcode add-on *tool names*** — `_TOOL_CATEGORIES` (lines 445–511), `_PHASE_RECOMMENDED` (lines 514–573), `_ENV_SUMMARY_TOOLS` (lines 363–371). The manifest schema has no field for category/phase/health-tool, so the data was hardcoded in core. This is the *only* reason migrating the four backends would force gateway edits — and the reason a future community add-on would have to patch core just to be categorized. **Avoidable shortcut, not inherent coupling.**
- **No operator self-service path exists.** A backend is added only by hand-editing `~/.sift/gateway.yaml` + `POST /api/v1/backends/reload`; conformance is checked by running `scripts/probe_backends.py` from the CLI. There is **no portal UI** and **no validate-then-register REST endpoint**. The "operator points the portal at a compliant backend → portal checks compliance → integrates it" flow is not built.

**Decision (operator-confirmed 2026-06-02):** (1) make the maps **manifest-driven before** migrating backends so migration — and every future add-on — touches only its own package; (2) **build the portal self-service add-backend flow now** (plug-and-play is the MVP pitch). Order is load-bearing: **6.1 → 6.2 → 6.3 → 6.4**.

- [x] **6.1 Make the core maps manifest-driven (remove all add-on tool names from core)** ✅
  - *Done:* schema (`sift-backend.schema.json`) gained per-tool `category`/`recommended_phase`/`health`/`health_args`/`hidden_from_agent` (additive, `1.x`-compat; self-validates + sample exercises them). `server.py` builds a per-tool `_tool_manifest_meta` index (category/phase/health/health_args/hidden_from_agent/backend) from each **available** backend's manifest inside `_build_tool_map`, atomic-swapped alongside `_tool_map`/`_tool_cache` and pruned to surviving tools. `mcp_endpoint.py`: `_TOOL_CATEGORIES`/`_PHASE_RECOMMENDED` reduced to **core+synthetic only** (`_CORE_TOOL_CATEGORIES`/`_CORE_TOOL_PHASES`); `_list_tools` overlays add-on category/phase from the manifest and filters add-on tools flagged `hidden_from_agent`; `_AGENT_FILTERED_TOOLS` trimmed to core-only `evidence_register` (the add-on `idx_install_pipelines` note was later superseded by Session 25 removal). `environment_summary` rebuilt: core status tools + every available backend's manifest-declared `health` tool — no hardcoded backend/tool names. **Verify:** grep of `mcp_endpoint.py` for add-on tool names = CLEAN; gateway suite 121/121 green. (Dedicated `test_phase6.py` lands in 6.5.)
  - *What:* `mcp_endpoint.py` must contain zero add-on tool names. Category / recommended-phase / which-tool-is-health move into each backend's manifest.
  - *How:*
    - Extend `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`: add optional per-tool `category` (string), `recommended_phase` (string), `health` (bool — the tool `environment_summary` calls), `hidden_from_agent` (bool), plus optional `health_args` (object, for the windows `{"resource":"health"}` case). Additive only — `1.x` major-compat permits it.
    - `mcp_endpoint.py` `_list_tools` (575–598): build a `tool_name → {category, recommended_phase, hidden_from_agent}` index from `gateway.backends[*].manifest["tools"]` (each backend already carries `.manifest`, cf. `get_reference_backends` `server.py:316–325`); annotate from it. Keep a **core-only** hint map for in-process core tools (first-party, not "backend names").
    - `_handle_environment_summary` (363–409): replace the hardcoded `_ENV_SUMMARY_TOOLS` list with the core status tools (`case_status`/`evidence_list`/`list_available_tools`) **plus**, for every backend in `gateway._available_backends`, the tool its manifest marks `health: true` (+ `health_args`). Down/unavailable backends are skipped — no name list.
    - `_AGENT_FILTERED_TOOLS`: union the core-policy set (`evidence_register`) with backend tools manifest-flagged `hidden_from_agent` (replaces the hardcoded `idx_install_pipelines`).
  - *Why:* **R-no-hardcoded-names** — extended beyond grounding/gate to tool categorization, phase hints, and env-summary. Closes the disconnect: the core never learns add-on tool names again.
  - *Test:* `grep -nE 'idx_|check_artifact|server_status|get_health|search_knowledge|lookup_ioc' packages/sift-gateway/src/sift_gateway/mcp_endpoint.py` → zero add-on names. A fake backend whose manifest declares category/phase/health flows through to `tools/list` meta + `environment_summary` with **no** core edit.

- [x] **6.2 Namespace + migrate the four add-ons** following the **§5 migration playbook** (order: rag → windows-triage → opencti → opensearch): `kb_*`, `wintriage_*`, `cti_*`, `opensearch_*`. Give each a `sift-backend.json` manifest **now also declaring** the `category`/`recommended_phase`/`health` metadata moved out of core in 6.1. Rename `case_host_fix`→`opensearch_host_fix` (stays in opensearch, F-D). **ALL 4 DONE: rag/windows-triage/opencti (Session 24), opensearch (Session 25).**
  - *How:* per backend — namespace every tool registration/dispatch in `server.py`, re-key `tool_metadata.py`. **Atomic cross-backend edit:** `opensearch-mcp/src/opensearch_mcp/triage_remote.py` gateway `call_tool` refs `check_artifact`/`check_system` → `wintriage_check_artifact`/`wintriage_check_system` migrated *with* the windows-triage step. Strip any residual `analyst_override`/identity params from add-on schemas (R-identity).
  - *Test:* each add-on passes the conformance probe (§5 done-condition); `tools/list` shows only namespaced add-on tools; no `mcp_endpoint.py` edit was needed (proves 6.1).
  - *DONE — rag (`kb_*`), Session 24:* manifest `packages/forensic-rag-mcp/sift-backend.json` (ns `kb`, `provides:["reference"]`, 3 tools, `kb_get_knowledge_stats` = health). Renamed `search_knowledge`/`list_knowledge_sources`/`get_knowledge_stats` → `kb_*` in `server.py` (FastMCP fn names) + `tool_metadata.py` keys + in-package docstrings/agent strings. External agent-facing refs updated: `sift_core/case_manager.py` guidance.
  - *DONE — windows-triage (`wintriage_*`), Session 24:* manifest (ns `wintriage`, `provides:["reference"]`, 6 advertised tools, `wintriage_server_status` = health w/ `health_args={"resource":"health"}`). Word-boundary rename of the **6 advertised** tools (`check_artifact`/`check_process_tree`/`check_system`/`check_registry`/`check_pipe`/`server_status`) in `server.py` (`list_tools` + dispatch) + `tool_metadata.py` + `tests/test_windows_triage.py`. **Left the granular internal branches** (`check_file`/`check_service`/`check_hash`/etc.) un-namespaced — they're not advertised, so they don't trip namespace enforcement. **Cross-backend:** `opensearch-mcp/triage_remote.py` `check_artifact`/`check_system` → `wintriage_*`; its test `test_triage_remote.py` updated. Rewrote gateway `tests/test_windows_triage_backend.py` to load the real manifest + assert namespaced. Agent instructions (`sift_common/instructions.py`) + core guidance (`execute/response.py`) updated.
  - *DONE — opencti (`cti_*`), Session 24:* manifest (ns `cti`, `provides:["reference"]`, 8 tools, `cti_get_health` = health). **Surgical** rename (blanket was unsafe — `self.client.get_entity`/`get_relationships`/`search_reports`/`get_recent_indicators` are real client methods): renamed only `name="X"` / `name == "X"` / `tool_name == "search_entity"` contexts in `server.py` + the 8 advertised `tool_metadata.py` keys (**left** the per-type `search_threat_actor`/`search_malware`/… meta keys used by the `_type_to_meta_key` map). **Cross-backend:** `opensearch-mcp/threat_intel.py` `lookup_ioc` → `cti_lookup_ioc`. Agent instructions + core guidance (`case_manager.py`, `execute/response.py`) updated.
  - *requires[] choice (rag/wintriage/cti):* declared `requires: []` — each backend self-reports availability via its health tool and degrades gracefully (no hard prereq to gate on; fail-closed `evaluate_requirement` makes a wrong `env:`/`host:port` entry worse than none). **opensearch differs** — see below.
  - *DONE — opensearch (`opensearch_*`), Session 25:* **Naming decision (operator-confirmed): rename `idx_*`→`opensearch_*`** (not prefix to `opensearch_idx_*`) — consistent single-prefix with the 3 siblings, no stutter; edit cost/test-fallout identical either way (word-boundary per-name edits required regardless, since `idx_name`/`idx_err`/`idx_lower`/`idx_j/d/a` are local vars). Word-boundary rename of the **16 advertised** `@server.tool` fns in `server.py` (`opensearch_search/count/aggregate/get_event/timeline/field_values/status/shard_status/case_summary/inspect_container/ingest/ingest_status/enrich_intel/enrich_triage/list_detections` + `case_host_fix`→`opensearch_host_fix`, F-D). **`idx_install_pipelines` REMOVED ENTIRELY** (operator-confirmed "remove it totally") — it was never a `@server.tool` (docstring: "not exposed as an agent tool") so the old hardcoded `_AGENT_FILTERED_TOOLS` entry was dead; pipeline/template setup already runs via `ensure_winlog_pipeline` at server first-connection (`server.py:432`). So **no `hidden_from_agent` is used by opensearch**. **Left internal non-advertised helpers** un-namespaced (`idx_ingest_json`/`idx_ingest_delimited`/`idx_ingest_accesslog`/`idx_ingest_memory` + their `idx_ingest_{subcommand}`/`idx_ingest_csv_*` audit labels) — same precedent as wintriage's internal branches. **No `tool_metadata.py` in opensearch** (it has none — N/A). **Manifest** `packages/opensearch-mcp/sift-backend.json` (ns `opensearch`, 16 tools, `provides:["search","ingest","enrichment"]` — **not** `reference`, so no grounding; per-tool `evidence_class`/`readOnlyHint`/`category`/`recommended_phase`; `health:"opensearch_status"`; **`requires:["https://localhost:9200"]`** — genuine hard dep, TCP-checked by `evaluate_requirement`'s `http(s)://host:port` branch against the co-located service, gated loudly if down). `shard_status` and `host_fix` are now explicitly categorized as `admin` to satisfy the hardened contract. **External agent-facing refs swept:** `sift_common/instructions.py` (incl. `idx_*`→`opensearch_*` glob phrases), `sift_core/case_manager.py` (incl. the `startswith("opensearch_ingest")` provenance check), `execute/response.py`, `forensic-mcp/server.py` next_steps (+ fixed a pre-existing dangling `idx_artifact_browse()`→`opensearch_search()`), `forensic-knowledge` yaml follow-ups, `scripts/reset-vm-test.sh`. **Tests:** updated `test_detections.py` count guard (now counts `opensearch_`-prefixed == 16) + `test_server_tools.py` admin-install guard (asserts neither old nor namespaced install_pipelines exists). `.understand-anything/*` (generated) and `docs/tool-audit-2026-05-25.md` (dated historical) intentionally left.

- [x] **6.3 Portal self-service add-backend flow (plug-and-play integration)** — REST validate/register and portal Backends tab UI fully done. ✅ Session 29
  - *What:* an operator integrates a compliant backend end-to-end from the portal: point at a manifest → conformance probe → on pass, register + hot-reload.
  - *How:*
    - **Probe as library:** refactor `scripts/probe_backends.py` into importable `probe_manifest(manifest)->result` (schema + spec_version + namespace-prefix + declared-tools + forbidden-identity-arg) and `probe_live(gateway_url, token, name)->result` (MCP handshake + tool list + health), reusing the schema path from `backends/__init__.py`. CLI becomes a thin wrapper (existing usage unchanged).
    - **Gateway REST** (`rest.py`, add to `rest_routes()` line 693, examiner-guarded): `POST /api/v1/backends/validate` (body = inline manifest / file path / backend URL; runs `probe_manifest` + optional `probe_live`; **read-only**); `POST /api/v1/backends` (body = backend config entry; re-validates, on pass writes the `backends:` entry into `~/.sift/gateway.yaml` and triggers the existing reload path — `gateway._pending_backends[name]=conf` + `gateway._reload_event.set()`, mirroring `reload_backends` 657–690; on fail 422 w/ reasons, never writes a non-conformant backend). Reuse existing `list_backends`/`start|stop|restart_service` for lifecycle.
    - **Portal Backends tab** (`packages/case-dashboard/src/case_dashboard/routes.py` + `frontend/src/`, examiner-only, dashboard reaches the gateway via `request.app.state.gateway`): list backends (name/tier/started/health/unmet `requires[]`); "Add backend" form (manifest path/URL/upload → `/validate` shows namespace + declared tools + requirements + verdict → "Register" → hot-reload, row appears); enable/disable + start/stop/restart wired to the service endpoints.
  - *Why:* delivers the MVP "plug-and-play" pitch; the building blocks existed but were never wired into an operator experience.
  - *Test:* from the portal, add a backend by manifest path/URL → probe runs → register → its tools appear in `tools/list`; a non-conformant manifest is rejected with field-level reasons and writes nothing; disable it → its tools vanish, core stays up.
  - *DONE (Session 29):* gateway REST now exposes examiner-guarded `POST /api/v1/backends/validate` and `POST /api/v1/backends`. Validate accepts inline manifests or backend config/manifest path, returns namespace/provides/requires/tool guidance plus field-level `reasons`, and is read-only. Register re-validates before any write, rejects non-conformant manifests/config with 422, writes only conformant entries to `gateway.yaml`, updates in-memory config, and schedules hot-load only when enabled and `requires[]` are satisfied. Disabled/gated add-ons are not exposed as available. Added portal Backends tab UI, including configured backends grid panel, dynamic stdio/http input fields switcher, key-value environment variables editor, and password challenge overlays for mutating admin actions (register, start, stop, restart, reload). Added frontend vitest unit test suite covering logic, states, and payload compile helpers. All tests green and built successfully.

- [x] **6.4 Contract graduation — permanent hard-reject** ✅ Session 24
  - *How:* remove the `SIFT_PHASE == "6"` conditionals in `backends/__init__.py` (~92, ~115) and any gateway-path guard so a missing/invalid **add-on** manifest is **always** rejected with an actionable reason (one-time, legitimate core change — the contract graduating, not a per-add-on cost). Drop `monkeypatch.setenv("SIFT_PHASE","6")` from `test_phase4.py`.
  - *Test:* a backend with no/invalid manifest refuses to load with a reason, no env needed; conformant backends unaffected.
  - *Done:* both `load_and_validate_manifest` guards now **always** raise `ValueError` (missing manifest → message includes the searched `manifest_source`; invalid → wraps the validation error). Dropped the `SIFT_PHASE` monkeypatch from `test_phase4.py::test_manifest_validation`. `grep SIFT_PHASE packages/` = clean. Gateway suite 121/121 green. **Note:** `_build_tool_map`'s no-manifest *warn-degrade* branch still exists for backends injected directly in tests (bypassing `create_backend`); real backends now can't reach it because `create_backend` hard-rejects first.

- [x] **6.4a Contract hardening — schema/probe enforce the add-on standard** ✅ Session 26
  - *Decision:* plug-and-play add-ons are accepted by a strong, executable contract, not per-backend workarounds. The gateway/core/portal remain core-owned; every other backend is an add-on that ships a manifest the gateway can validate, start, gate by `requires[]`, aggregate into the single `/mcp`, and annotate without hardcoded backend/tool names.
  - *Phase taxonomy:* add-on `recommended_phase` is now standardized and schema-enforced as exactly `SURVEY`, `INGEST`, `ANALYZE`, `CORRELATE`, `FINDING`. `SEALED` is not a phase; it is an evidence-chain/custody state. Core/synthetic tool phases can keep their own internal map, but add-on manifests must use this enum.
  - *Capabilities:* `capabilities.provides[]` is now schema-enforced as `reference`, `search`, `ingest`, `enrichment`, `baseline`, or `threat-intel`. `reference` remains the **only** grounding switch and is backend-level: it means independent corroboration/reference context. OpenSearch remains **not** `reference`; marking it reference would let case-evidence search satisfy grounding by itself.
  - *Tool contract:* every manifest tool must declare `name`, `description`, `read_only`, `readOnlyHint`, `evidence_class`, `category`, and `recommended_phase`. `category` is schema-enforced (`evidence-survey`, `ingest`, `search-analysis`, `enrichment`, `baseline-check`, `threat-intel`, `admin`). `evidence_class` stays required (`read_only`/`analysis`/`mutating`) for audit/risk/UX/future approvals; it does **not** reintroduce the old read-only evidence-gate carve-out (F-A still blocks every agent tool unless sealed+OK).
  - *Health contract:* top-level `health` is required; conformance additionally requires it to point at exactly one declared tool with `health:true`. `environment_summary` continues to discover health tools from manifest metadata.
  - *Enforcement:* `sift-backend.schema.json` now rejects weak manifests; `load_and_validate_manifest()` also enforces cross-field invariants (namespace prefix, unique tool names, `read_only == readOnlyHint`, `evidence_class` consistency, valid phase, exactly one health tool). `scripts/probe_backends.py` enforces the same invariants offline/live, so portal self-service can reuse it as the manifest validator.
  - *Manifest sync:* all four bundled add-ons updated to conform. RAG=`reference`; Windows triage=`reference,baseline`; OpenCTI=`reference,threat-intel`; OpenSearch=`search,ingest,enrichment` and still **not** grounding. Old `ORIENT`/`TRIAGE`/`SEALED` add-on phases were replaced with the new taxonomy.
  - *Verify:* `uv run python scripts/probe_backends.py --manifest-dir packages --skip-mcp` passes all four manifests; `uv run pytest packages/sift-gateway/tests/test_phase4.py -q` passes (15).

- [x] **6.4b Aggregate gateway instructions are manifest-aware, not add-on hardcoded** ✅ Session 26
  - *Problem:* the active aggregate `/mcp` Initialize instructions had been ported from the old static gateway prose. It named bundled add-ons/tools directly (`windows-triage`, `forensic-rag`, `opensearch_*`, `cti_*`) even though the actual tool surface depends on enabled add-ons, `requires[]` gating, and future community backends.
  - *Decision:* keep core forensic discipline static, but generate the aggregate add-on summary from loaded `sift-backend.json` manifests. Initialize instructions are not live status; they now explicitly tell the agent to call `workflow_status`, `environment_summary`, and `tools/list` for live health and exact tool availability.
  - *Done:* `GATEWAY` in `sift_common/instructions.py` is add-on-neutral. `create_mcp_server()` now calls `_build_gateway_instructions(gateway)`, which summarizes each configured add-on from manifest data (`provides`, categories, phases, health tool, and unmet `requires[]`) without hardcoded add-on names. If no add-on is configured/requirement-satisfied, the instruction says to use core tools unless `tools/list` shows add-ons.
  - *Remaining design note:* per-backend `/mcp/{name}` instructions still use bundled backend constants for known local backends before subprocess startup, then fall back to backend initialize instructions. The stricter final form should move static backend guidance into manifest `instructions` (or an adjacent manifest-declared file) so community backends can provide first-class per-backend initialize text without gateway code changes.

- [x] **6.4c Manifest-driven guidance + live capability guide** ✅ Session 27
  - *Goal:* make backend/tool guidance plug-and-play without bloating `/mcp` initialize instructions. Every add-on should ship enough manifest-declared guidance for the gateway to explain what is available, when to use it, and how to call it, while the exact call contract still comes from MCP `tools/list` schemas.
  - *Manifest extension:* add optional backend-level `instructions` (short inline guidance) and `instructions_path` (repo-relative markdown for longer guidance; use one or the other). Add optional per-tool fields: `when_to_use`, `avoid_when`, and `output_notes`. These complement, not replace, the MCP tool `description`, `inputSchema`, and `outputSchema`.
  - *Aggregation rule:* aggregate `/mcp` initialize instructions stay concise: core discipline, evidence gate, “call `workflow_status`, `environment_summary`, and `tools/list` for live state,” plus a short generated add-on summary from manifests. Do **not** dump all input/output schemas into initialize text.
  - *Live guide surface:* add a synthetic gateway tool, likely `capability_guide` or an `environment_summary` expansion, that groups currently available tools by backend, `provides[]`, `category`, and `recommended_phase`; includes health/unmet `requires[]`; includes per-tool `when_to_use`/`avoid_when`/`output_notes`; and points the model to `tools/list` for exact input schemas. This is the agent's “what should I use now?” view.
  - *Expected flow:* agent initializes → reads short core + generated add-on summary → calls `workflow_status` → calls `environment_summary`/`capability_guide` → calls `tools/list` for exact schemas → chooses tools based on live metadata. If an add-on is disabled or gated by `requires[]`, it does not appear as available and its guidance is not presented as usable.
  - *Contract/probe updates:* schema validates the new optional guidance fields; probe verifies `instructions_path` stays inside the backend package and is readable; portal validate/register displays backend instructions summary and tool guidance before registration.
  - *Spec sync note:* update the task plan markdown/spec docs later to reflect this guidance model. For now this tracker item is the source of truth so the next session does not forget the design.
  - *Done:* schema accepts backend-level `instructions`/`instructions_path` and per-tool `when_to_use`/`avoid_when`/`output_notes`; backend validation enforces only one backend instruction source and validates local `instructions_path` containment/readability under the backend package; `scripts/probe_backends.py` mirrors the same checks. Per-backend `/mcp/{name}` initialize instructions now come from manifest guidance instead of a gateway hardcoded add-on map. Aggregate `/mcp` instructions remain concise and point agents to `workflow_status`, `environment_summary`, `capability_guide`, and `tools/list`; no tool schemas are dumped into initialize text.
  - *Live guide:* added gated synthetic `capability_guide`, generated from currently available manifest metadata. It groups tools by backend, `provides[]`, `category`, and `recommended_phase`; includes health tool and `requires[]`/unmet requirement status; includes per-tool `when_to_use`/`avoid_when`/`output_notes`; omits disabled/gated tools from available guidance and points to `tools/list` for exact schemas.
  - *Manifest sync:* all four bundled add-ons gained concise backend instructions and per-tool guidance. OpenSearch remains `provides:["search","ingest","enrichment"]` and is still **not** `reference`; grounding remains backend-level via `provides:["reference"]`.
  - *Verify:* `uv run python scripts/probe_backends.py --skip-mcp` passes all four manifests; `uv run python -m pytest packages/sift-gateway/tests/test_phase6.py -q` passes (4); `uv run python -m pytest packages/sift-gateway/tests -q` passes (125); static scan for add-on names in `mcp_endpoint.py` + `server.py` is clean.

- [x] **6.5 Tests + tracker + spec sync** ✅ Session 28
  - *Already covered by 6.4c:* `packages/sift-gateway/tests/test_phase6.py` now exercises manifest guidance fields, namespace/availability behavior through a fake backend, hidden-tool omission, `instructions_path` containment/readability, and a no-hardcoded-add-on-name scan over `mcp_endpoint.py` + `server.py`.
  - *Still needed:* broaden `test_phase6.py`/gateway tests for all four shipped manifests validating with the new fields, `tools/list` annotations, `environment_summary` health derivation, `capability_guide` exact output shape, `provides:["reference"]` grounding, manifest-missing hard-reject, `/backends/validate` pass+fail, and `POST /backends` refusal of non-conformant registrations. If `/backends/validate` / `POST /backends` do not exist yet, implement them or move the remaining portal self-service work back to 6.3 explicitly — do not mark 6.5 done while that flow is missing.
  - *Verification:* update `opensearch-mcp/tests/test_server_tools.py` + per-package suites if any namespaced-name drift remains. Run **per-package** (`uv run python -m pytest packages/<pkg>/ -q`); never bare `uv sync` (always `--extra full`). Re-run manifest probe live/offline, static no-hardcoded-name scans, and the full gateway suite. Update HTML/mmd if behaviour drifts (R-spec-truth); Session Log per §3.
  - *Done:* `test_phase6.py` broadened to cover all shipped manifests, real MCP `tools/list` manifest-derived annotations, manifest-driven `environment_summary` health calls, exact `capability_guide` shape and gated/hidden omission, reference-backend grounding via `provides:["reference"]` with OpenSearch excluded, manifest-missing hard-reject, REST validate pass/fail, REST register rejection without writes/tool exposure, gated registration staying unavailable, and a static scan over all gateway core Python. Added REST validate/register flow because it was missing. `revamp-plan.html` contract section now includes guidance fields and the validate/register REST flow. OpenSearch namespaced tool drift check stayed green; no per-package edits were needed.

🔒 **PHASE 6 GATE = MVP COMPLETE:** core is **provably add-on-agnostic** (zero add-on tool names in `mcp_endpoint.py`; the only one-time core change is the hard-reject flip); contract enforced; four add-ons conformant and namespaced; **an operator can integrate a compliant backend from the portal** (validate → register → hot-reload, core survives disable); F-A/F-B verified live. **Live VM** (192.168.122.81, wiped → re-run `install.sh`): this is the **full-addon** install + e2e (discharges the deferred Phase 4 probe + Phase 5 output-cap live caveats); full ROCBA workflow reproduced end-to-end.

---

### Post-Phase-6 refactor — `run_command` hardening + flexibility (code-complete, Session 32 supersedes Session 30)

Not a numbered MVP phase — a **refactor of the `run_command` exec path** in `packages/sift-core/src/sift_core/execute/`, captured here so it can be reflected back into the architecture spec (HTML/mmd) under R-B / Phase 3 (sandbox + privilege executor). Motivation: the previous `run_command` was slow, context-bloating, and incoherent for the autonomous DFIR agent; this makes it **one hardened, flexible, low-bloat tool**. Replaces the older "run command assessment/hardening" commits with a sound model.

**Invariants now enforced in code (do not regress — see `[[project-run-command-security]]`):**
- **No shell, one parser.** `worker.py` executes parsed `argv` via `subprocess.Popen(shell=False)`; there is **no `/bin/bash -c` anywhere** in the exec path. `validate_shell_command` (`security.py`) is the single parser and its output is exactly what runs — the validate-then-`bash -c` **parser differential is eliminated**. Remediation gate enforces `shell=False`.
- **Native Linux user isolation.** The executor no longer wraps the worker in `systemd-run`; each validated stage runs as the configured low-privilege local user (`execute.runtime_user`, default `agent_runtime`) via `sudo -n -u <runtime_user> -- <resolved-binary> ...`. Host ACLs are the kernel boundary: read-only evidence, no access to state records, write only under `agent/`, `extractions/`, and `tmp/`. Setup helper: `scripts/setup-agent-runtime.sh`.
- **Execute the *resolved* binary, never the literal path.** Every `argv[0]` is rewritten to the `find_binary`-resolved path before it reaches the worker. Closes a **path-shadow RCE**: a file named after an allowed tool (e.g. a copy of `python3` at `<case>/tmp/ls`, run as `./ls -c …`) would otherwise pass basename validation yet execute the attacker file. Also fixes the latent "tool in `/opt/zimmerman` not on `PATH`" exec failure.
- **Redirect operators use the unforgeable `\x01` sentinel.** Operators are tagged during the char-walk so a **quoted literal** (`grep ">" f`, `grep "2>&1" log`) stays an argument instead of being mis-read as a redirect (pre-existing bug for `>`/`<`/`>>`, fixed at root). `\x01` can't appear in user input (banned by the control-char check + a direct guard in the parser).
- **stderr ergonomics (kills retry friction for the agent).** Supported: `2>&1` (merge into the pipe), `2>`/`2>>` (stderr→file), `&>`/`&>>` (both→file), and **`/dev/null` allowed as a sink** (`>/dev/null`, `2>/dev/null` just work). stderr is always captured/returned regardless. Exotic fd-dup (`>&N`, `1>&2`, `3>`) and heredocs (`<<`) are **rejected with clear, actionable messages**, not cryptic `FileNotFound`.
- **DENY_FLOOR right-sized for DFIR** (`security_policy.py`): nested interpreters + shell-escape/pager/editor binaries (`sh/bash/python*/perl/ruby/node/php/lua/gdb/vi/vim/less/man/watch/script/screen/tmux/…`) and media destroyers (`shred/wipefs/blkdiscard/…`); dev-centric git/k8s/terraform patterns dropped in favour of DB-destruction rules. Per-tool privileged jails (mount/dd/losetup/fdisk read-only) and narrow, logged sudo wrapping of the **resolved binary only** (never `bash -c`) remain for explicitly privileged fallback paths.
- **Evidence/state sovereignty enforced before exec.** Relative path validation is against the command cwd. `cp`/`mv`/`rm`/`mkdir`/`touch`/`chmod`/`setfacl`/similar positional mutators cannot write, delete, move, or metadata-change `evidence/` or integrity records. This closes the Session 31 `cp /usr/bin/python3 evidence/qa-decoy-REMOVEME` gap at the policy layer, with ACLs as the host backstop.
- **Context-bloat control retained:** output byte-budget + auto-save to `<case>/agent/outputs/` with SHA-256, parsed/summarized large output, per-stage audit provenance.

**Containment caveat (deployment-level):** this is native local-user isolation, **not** a container/namespace/seccomp sandbox. It is practical for SIFT and FUSE persistence, but it requires host ACL/sudoers setup and a gateway service user distinct from the restricted runtime user. Integrity records must remain outside the case tree under `SIFT_STATE_DIR` and unreadable by `agent_runtime`.

**Tests:** `packages/sift-core/tests/test_execute_executor.py` red-team + feature cases (path-shadow→resolved, quoted-redirect-literal, nested-interpreter reject, `2>&1` merge, `2>`/`&>`/`/dev/null`, exotic-fd reject, heredoc reject, worker stderr routing, native runtime user prefix, missing runtime/sudo fail-closed, evidence write/delete/move blocked). Gateway config/in-process tests cover `execute.runtime_user` export and end-to-end core `run_command`. Live-VM exercise still required after host ACL setup.

**Spec follow-up (R-spec-truth):** reflect the "no `bash -c`, execute-resolved-binary, redirect-sentinel, stderr-to-file/`/dev/null`, native `agent_runtime` + ACL host boundary (not a container)" model into `revamp-plan.html` / mmd at the Phase 3 executor + R-B sections in the commit that lands this.

### Pre-Phase 7 — Tool-registration ergonomics pass (agent-facing) (POST-MVP, before /skills)
- [ ] **Optimize everything the AI agent sees when it loads each tool**: descriptions, **input and output formats**, worked **examples**, and **common use cases**, across the agent-facing tool registrations (core in-process tools + the four namespaced add-ons via their manifests). Goal: make the tool surface self-explanatory and low-friction for an autonomous agent (fewer malformed calls / retries, less wasted context), building on the manifest guidance fields shipped in 6.4c (`instructions`, `when_to_use`, `avoid_when`, `output_notes`).
  - *Scope:* every `@tool` schema/docstring the agent loads (e.g. `run_command` now supports pipes/`&&`/`||`/`;`, redirects incl. `2>&1`/`2>file`/`/dev/null`, save-to-file, partial-failure warnings — its description/examples should advertise exactly that and the supported-vs-rejected redirect set); and each add-on manifest's per-tool `description`/examples/`output_notes`.
  - *Why pre-Phase-7:* this is the registration-quality counterpart to moving methodology into `/skills`; do it while the tool surface is stable and before the SDK/scaffold (7.3) so third-party authors copy a good example.
  - *Done-condition:* descriptions/examples/IO/use-cases reviewed and tightened for all agent-visible tools; a short "tool authoring style" note added to the §5 add-on playbook so new backends inherit the standard; no behavioural code change required (registration metadata only).

### Phase 7 — Methodology → /skills + SDK (POST-MVP, last)
- [ ] **7.1 Build `/skills` endpoint** serving versioned, signed markdown packs as a **downloadable zip following Anthropic's skills standard** (your note @595).
- [ ] **7.2 Move the 14 methodology `get_*` tools' content into skills packs; remove the tools.** Keep the FK **data package** as a core runtime dependency (considerations + grounding still read it). `validate_finding` tool dropped; enforcement stays in `record_finding`.
  - *Test:* methodology no longer costs per-session context as tools; considerations/grounding/validation unchanged; pack downloads + verifies signature.
- [ ] **7.3 Backend SDK / scaffold** so a dev can generate a conformant add-on skeleton.

---

## 7 · Cross-cutting invariants to preserve (check at every gate)
- **R-A (F-A):** no agent `/mcp` tool executes unless `chain_status == OK`. Health/lifecycle/portal are not agent tools and are exempt — by design.
- **R-B (F-B):** the agent (via `run_command` jail) can never read or write `audit/`, the ledger, approvals, or the manifest.
- **R-identity (F-F):** the gateway is the only authority that sets identity, and it does so **out-of-band** — identity is resolved once at the auth boundary and never appears as a tool argument or in any tool schema. Add-on backends are identity-transparent (attribution rides the audit envelope, not a tool arg). No `analyst_override`/`ANALYST_TOOLS` anywhere.
- **R-roles (operator-drives-portal-only):** strict two-way role separation, enforced in code and required of the standard:
  - Agent tokens are minted **only** by a logged-in examiner in the portal (`routes.py:3029`). The token's audit identity = its **`agent_id`** (machine attribution); the authorizing human is recorded as **`created_by`**.
  - Audit entries the agent writes are stamped with the `agent_id`; **human accountability attaches at portal approval/commit** (DRAFT → examiner HMAC commit), not at agent-write time.
  - The portal **rejects agent tokens** (`case-dashboard/auth.py`); `/mcp` is the **agent-only** surface. The operator never calls `/mcp`; the agent never reaches the portal.
  - The operator's only out-of-portal actions are the one-time `install.sh` and pasting the portal-issued token into the agent config. Everything case/evidence/findings/token-related is portal-only.
- **R-provenance:** a finding with no evidence trail is rejected, not warned.
- **R-no-hardcoded-names:** the core never hardcodes add-on backend *or tool* names. Grounding and the gate decide by *declaration*; **tool categorization, phase hints, and `environment_summary` health-tool selection are also manifest-driven** (Phase 6.1) — `mcp_endpoint.py` contains zero add-on tool names. Adding a conformant backend requires no core edit.
- **R-core-survives:** disabling/killing any add-on never removes a core capability.
- **R-spec-truth:** the HTML/mmd spec matches the code; fix the spec in the same commit that changes behaviour.

---

## 8 · Session Log

> Append newest at the top. Use the §3 template.

### Session 32 — 2026-06-02 — `run_command` native user isolation baseline
- Branch/commit: `revamp/spg-v1` @ working tree (not committed).
- Phase: Post-Phase-6 refactor follow-up — supersedes the Session 30 executor model after Session 31 black-box QA found the MCP surface mismatch and evidence write gap.
- DONE: adopted Option 3 **Native Linux User Isolation** without reintroducing `bash -c`: `execute.runtime_user` (default `agent_runtime`) is exported from `gateway.yaml`; `executor.py` starts the worker directly (no `systemd-run`); `worker.py` prefixes each validated stage with `sudo -n -u <runtime_user> -- <resolved-binary> ...` and still uses `subprocess.Popen(shell=False)`.
- DONE: added host setup helper `scripts/setup-agent-runtime.sh` to create the restricted user, add FUSE group membership where available, apply case ACLs (read-only `evidence/`, writable `agent/`/`extractions/`/`tmp/`, deny state records), and write a target-user-scoped sudoers rule for the gateway user to drop to `agent_runtime`.
- DONE: hardened policy around the Session 31 security gaps: all stages now execute the resolved binary path; relative paths validate against command cwd; reads from integrity records are blocked; `cp`/`mv`/`rm`/`mkdir`/`touch`/`chmod`/`setfacl`/similar mutators cannot write/delete/move/metadata-change `evidence/` or state records. Legacy command arrays with operators now fail loudly and tell the agent to use a command string.
- Tests: green focused — `packages/sift-core/tests/test_execute_executor.py` **31 passed**; `packages/sift-gateway/tests/test_execute_security_config.py` + `test_inprocess_core_tools.py` **11 passed**.
- Live test on VM: pending — run `sudo scripts/setup-agent-runtime.sh --service-user sansforensics --runtime-user agent_runtime --cases-root /cases --state-root /var/lib/sift`, restart gateway, then replay Session 31 MCP matrix (pipes/redirects, evidence write/delete block, FUSE mount persistence, path-shadow).
- Spec changed?: tracker + `docs/revamp/run_command_updated.md` only. **R-spec-truth follow-up:** update `revamp-plan.html` / mmd to describe native user isolation and remove cgroup/container wording.
- BLOCKERS / open questions: host ACL/sudoers setup is required before production use; privileged root fallbacks still require separate narrow sudoers rules and live verification.
- NEXT: live VM ACL setup + black-box MCP retest; then full Phase 6 gate.

### Session 31 — 2026-06-02 — Live black-box QA of hardened `run_command` (MCP surface only)
- Branch/commit: `revamp/spg-v1` @ working tree. No code edits (black-box pass, per owner).
- Phase: Stage-6 invariant probing — the live-VM test Session 30 deferred. Full log appended to `docs/revamp/phase6-e2e-qa-log.md` (Stage 6 section); audit IDs `…-266 … -338`.
- DONE: ran the A/B/C matrix through the SIFT `/mcp` tools only (no Bash/curl/ssh) against `192.168.122.81:4508`, case `rocba-exfiltration-20260602-1245`.
- **Security PASS:** DENY_FLOOR solid — `sh`/`bash`/`python3`/`less`/`xargs`/`gdb`/`shred`/`wipefs` all blocked with one clear message. `dd of=` jail and the system-dir arg-jail (`/etc`) fire with specific, actionable messages. Operator-injection class is eliminated **because** operators are inert (upside of U-1). Integrity gate **detects** an evidence-dir plant and fails closed.
- **Security GAPS:** **S-1 (HIGH)** `evidence/` is not write/delete-protected by policy — `cp /usr/bin/python3 evidence/qa-decoy-REMOVEME` **succeeded** (audit 338); `rm evidence/<x>` reaches exec (328). Only `dd` is evidence-aware. **S-2 (HIGH)** the resulting chain-violation fail-closed lock blocks `run_command` itself → agent cannot self-remediate → one landed evidence write = DoS until portal re-seal. **S-3** `rm`/`cp`/`mv` allowed, only system-dir-jailed. **S-4** containment still same-user, jail is an argv scan not a kernel boundary.
- **Usability (owner's concern, confirmed):** `command[]` is **literal argv, zero shell parsing**. Pipes/redirects/append/`<`/`2>&1`/`&&`/`||`/`;` are all inert (multi-element) or become a nonsense binary name (single string). **The Session-30 "flex" claims — `\x01` redirect sentinel, `2>&1`/`2>file`/`/dev/null`, exotic-fd/heredoc *rejection* — do NOT reproduce on the MCP surface.** No single-call data reduction beyond `preview_lines` → drill-downs need a 2nd `run_command(['grep',…])` on the saved file → context bloat. Worst part is **silent** mis-composition (U-2): no error when operators are swallowed.
- **UNVERIFIED:** path-shadow exec (decoy `tmp/ls`=python3 staged at 334) not completed — chmod hit a transient harness classifier outage, then the chain lock halted runs. Basename-resolution is active but the live decoy-vs-real-ls exec was not observed. Redo.
- Tests: n/a (black-box, no code change).
- Live test on VM: **this session** — exercised the Session-30 `run_command` end to end via MCP.
- Spec changed?: no. **R-spec-truth follow-up:** Session-30 plan/mmd edits must NOT claim redirect/stderr/heredoc handling as agent-facing until it's actually wired to the gateway array surface (or document it as a non-MCP code path).
- ⚠️ STATE LEFT ON VM: `evidence/qa-decoy-REMOVEME` planted; chain in violation; agent surface fail-closed. Clean via portal re-seal or VM `rm /cases/rocba-exfiltration-20260602-1245/evidence/qa-decoy-REMOVEME` + `evidence_verify`. (Also harmless in jail: `tmp/ls`, `tmp/`.)
- BLOCKERS: case agent surface is locked until the planted file is removed + re-sealed (owner action).
- NEXT: (1) operator cleans up VM state; (2) decide `run_command` contract — recommend **structured `pipe_to`/`stdout_to`/`stdin_file` params** over a shell parser (keeps the no-injection win, restores compose+reduce); (3) close S-1 by making `<case>/evidence/` read-only to the worker for ALL binaries + RO mount/`0444` at seal; (4) finish the path-shadow exec test.

### Session 30 — 2026-06-02 — Post-Phase-6 refactor: `run_command` hardening + flexibility
- Branch/commit: `revamp/spg-v1` @ working tree (committed this session)
- Phase: post-Phase-6 refactor (not a numbered MVP task) — tasks touched: **`run_command` exec path** in `packages/sift-core/src/sift_core/execute/`; added the **Pre-Phase-7 tool-registration ergonomics** task.
- DONE: code-complete + unit-green refactor of `run_command`; doc captured under "Post-Phase-6 refactor"; new Pre-Phase-7 task box added.
- What: closed the validate-then-`bash -c` **parser differential** (worker now runs parsed `argv`, `shell=False`, no `/bin/bash -c`); **execute-resolved-binary** fix closes a path-shadow RCE; **`\x01` redirect sentinel** so quoted operator literals stay arguments (also fixed pre-existing `>`/`<` misparse); **stderr ergonomics** — `2>&1`/`2>`/`2>>`/`&>`/`&>>` + `/dev/null` sink supported, exotic fd-dup + heredocs rejected with clear messages; **DENY_FLOOR** expanded (interpreters/shell-escape/media-destroyers) and DFIR-right-sized; narrow logged sudo of the resolved binary only. Reviewed via `/code-review` (high) — the 3 real findings it surfaced (path-shadow, quoted-redirect misparse, `2>/dev/null` friction) were all fixed in-pass + tested.
- Tests: green — `sift-core` **321 passed**, `sift-gateway` **134 passed**, `./scripts/remediation-gate.sh` **PASSED** (shell=False, no legacy strings, no untagged reads). New/updated red-team + feature cases in `tests/test_execute_executor.py`.
- Live test on VM: pending — commit + rsync to 192.168.122.81 + gateway restart this session so the operator can wire their own MCP in Claude Code config and test the tools; folds into the Phase 6 full-addon live e2e.
- Spec changed?: tracker only this session. **R-spec-truth follow-up:** reflect "no `bash -c` / execute-resolved-binary / redirect-sentinel / stderr-to-file+`/dev/null` / fail-closed cgroup (not a sandbox)" into `revamp-plan.html` + mmd at the Phase 3 executor + R-B sections.
- BLOCKERS / open questions: containment is still same-user cgroup + rlimits + passwordless `sudo -n` — OS-level P1 (low-priv user, RO evidence mounts, no passwordless sudo, append-only audit log, real bwrap/nsjail sandbox fail-closed) remains a live-VM deployment task; do it at the Phase 6 gate hardening.
- NEXT: Phase 6 gate live e2e on the VM (now also exercises the new `run_command`); then the Pre-Phase-7 tool-registration ergonomics pass.

### Session 29 — 2026-06-02 — Phase 6.3 portal Backends tab UI + frontend tests
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 6 — tasks touched: **6.3**. Box **6.3 ticked**.
- DONE (boxes ticked this session): **6.3**.
- What: completed the portal self-service add-backend flow by implementing the frontend Backends tab UI. Designed a dense admin interface featuring configured backends status/requirements grid, dynamic stdio/http form switcher, and inline key-value environment variables editor. Integrated secure timing-safe password challenges via HMACS and strict origin gating for mutating actions. Exposed new endpoints in `endpoints.js`, mapped SVG `IconServer` in `NavRail.jsx`, and integrated `<BackendsTab />` in `App.jsx`. Authored frontend vitest suite covering logic, states, and payload compilers.
- Tests: green — `npm run test` (**83 passed**), `npm run build` (successful compilation), and python tests (`test_phase6.py` and `test_backends_portal.py` **22 passed**). Conformance probe and static scan both passed.
- Live test on VM: none.
- Spec changed?: no.
- BLOCKERS / open questions for next session: none.
- NEXT: Phase 6 gate live e2e verification.

### Session 28 — 2026-06-02 — Phase 6.5 tests + REST validate/register + spec sync
- Branch/commit: `revamp/spg-v1` @ `2c084e1` (working tree not committed)
- Phase: 6 — tasks touched: **6.3 partial**, **6.5**. Box **6.5 ticked**; 6.3 marked `[~]`.
- DONE (boxes ticked this session): **6.5**.
- What: added REST `POST /api/v1/backends/validate` and `POST /api/v1/backends` with field-level reasons, pre-write validation, config persistence, hot-load scheduling only for enabled + requirement-satisfied backends, and no exposure for disabled/gated add-ons. Broadened Phase 6 regression coverage for all shipped manifests, `tools/list` metadata, manifest-driven `environment_summary`, exact `capability_guide` shape, reference grounding via `provides:["reference"]` (OpenSearch excluded), manifest-missing hard-reject, REST validate/register pass/fail behavior, and static no-hardcoded-add-on-name scans over gateway core.
- Tests: green — `uv run python -m pytest packages/sift-gateway/tests/test_phase6.py -q` (**13 passed**); `uv run python -m pytest packages/sift-gateway/tests -q` (**134 passed**); `uv run python scripts/probe_backends.py --manifest-dir packages --skip-mcp` (**4 manifests pass**); `uv run python -m pytest packages/opensearch-mcp/tests/test_server_tools.py -q` (**49 passed**); static scan over `packages/sift-gateway/src/sift_gateway` found no hardcoded shipped add-on backend/tool names.
- Live test on VM: none.
- Spec changed?: yes — `revamp-plan.html` contract section now documents guidance fields plus validate/register REST behavior.
- BLOCKERS / open questions for next session: portal Backends tab UI and optional live probe wiring remain in 6.3; Phase 6 gate still needs full-addon install + live e2e on 192.168.122.81.
- NEXT: **6.3 portal Backends tab** (or Phase 6 gate if REST-only self-service is accepted for MVP).

### Session 27 — 2026-06-02 — Phase 6.4c manifest guidance + live capability guide
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 6 — tasks touched: **6.4c**. Box **ticked**.
- DONE (boxes ticked this session): **6.4c**.
- What: added manifest guidance fields (`instructions`, `instructions_path`, `when_to_use`, `avoid_when`, `output_notes`), path containment/readability validation in gateway + probe, manifest-driven per-backend instructions, and gated synthetic `capability_guide` generated from available manifests/tools. Updated all four bundled add-on manifests with concise guidance; OpenSearch remains non-reference.
- Tests: green — offline manifest probe all four manifests; `packages/sift-gateway/tests/test_phase6.py` **4 passed**; full gateway suite **125 passed**; static scan found no hardcoded add-on names in aggregate instruction/capability-guide logic.
- Live test on VM: none.
- Spec changed?: tracker only. `revamp-plan.html` deliberately not updated this session; keep the 6.4c spec-sync note for later.
- BLOCKERS / open questions for next session: none for 6.4c. Phase 6.5 still owns broader spec sync, portal validate/register coverage, and any remaining per-package add-on suites.
- NEXT: **6.5 Tests + tracker + spec sync**.

### Session 25 — 2026-06-02 — Phase 6.2 COMPLETE (opensearch → `opensearch_*`, the 4th/largest backend)
- Branch/commit: revamp/spg-v1 @ <commit after this session>
- Phase: 6 — tasks touched: **6.2 opensearch DONE → 6.2 box now `[x]` (all 4 add-ons migrated)**
- Naming decision (operator-confirmed): **rename `idx_*`→`opensearch_*`** (not `opensearch_idx_*`). Rationale: single-prefix consistency with kb_/cti_/wintriage_, no stutter; edit cost & test fallout identical either way (word-boundary per-name edits required regardless — `idx_name`/`idx_err`/`idx_lower`/`idx_j/d/a` are local vars, blanket sed unsafe). Done via a Python word-boundary regex driver (the `Bash` tool runs zsh, where unquoted `$var` does **not** word-split — a naive `for f in $files` sed loop silently no-ops; use Python or `${=var}`).
- install_pipelines decision (operator-confirmed): **removed entirely** ("remove it totally"). It was never a `@server.tool` (docstring said so), so the old hardcoded `_AGENT_FILTERED_TOOLS` filter was dead; `ensure_winlog_pipeline` already runs at server first-connection (`server.py:432`). **Net: opensearch uses no `hidden_from_agent`.** (If 6.5's `test_phase6.py` wants to exercise the `hidden_from_agent` path, use a synthetic/fake backend.)
- What shipped:
  - **16 advertised tools** renamed in `server.py` (15 `idx_*` + `case_host_fix`→`opensearch_host_fix`, F-D — stays in opensearch). 379 replacements across 26 files (server + other opensearch src + tests + external callers + knowledge yaml + vm script).
  - `idx_install_pipelines` function deleted; `mappings/__init__.py` docstring + 2 tests adjusted.
  - **Manifest** `packages/opensearch-mcp/sift-backend.json`: ns `opensearch`, 16 tools, `provides:["search","ingest"]` (**not** `reference` — no grounding), per-tool `evidence_class`/`readOnlyHint`/`category`/`recommended_phase` recovered from `git show fa9f482^:…/mcp_endpoint.py`, `health:"opensearch_status"`, **`requires:["https://localhost:9200"]`** (real hard dep; TCP-checked by `evaluate_requirement`).
  - Internal non-advertised helpers (`idx_ingest_json/delimited/accesslog/memory` + `idx_ingest_{subcommand}`/`idx_ingest_csv_*` audit labels) left un-namespaced (wintriage precedent). No `tool_metadata.py` in opensearch (N/A).
  - External sweep: `sift_common/instructions.py` (+ `idx_*` globs), `sift_core/case_manager.py` (+ `startswith("opensearch_ingest")`), `execute/response.py`, `forensic-mcp/server.py` (+ fixed dangling `idx_artifact_browse()`), `forensic-knowledge` yaml, `scripts/reset-vm-test.sh`.
- Tests (per-package, all green, baselines preserved): **opensearch-mcp 973 (+71 skip)**, sift-core 301, sift-gateway 121, forensic-mcp 20, windows-triage-mcp 11. Manifest schema-valid via the gateway loader path; all 16 tools namespaced.
- Live test on VM: NO (code+unit only; VM core-only per Session 23). opensearch live bring-up + `scripts/probe_backends.py` folds into the Phase 6 GATE.
- Spec changed?: tracker only (6.2 box + opensearch bullet + this log). HTML/mmd unchanged.
- BLOCKERS / open questions: none for 6.2. (Generated `.understand-anything/*` and dated `docs/tool-audit-2026-05-25.md` left as-is.)
- NEXT: **6.3** (portal Backends tab + REST `/api/v1/backends/validate`+`register`; refactor `scripts/probe_backends.py` into importable `probe_manifest`/`probe_live`), then **6.5** (`test_phase6.py` + spec sync), then the **Phase 6 GATE** = full-addon `install.sh` + live e2e on 192.168.122.81 (currently core-only).

### Session 24 — 2026-06-02 — Phase 6.4 + 6.2 (3 of 4 add-ons migrated: kb_/wintriage_/cti_)
- Branch/commit: revamp/spg-v1 @ <commit after this session>
- Phase: 6 — tasks touched: **6.4 DONE**, **6.2 rag/windows-triage/opencti DONE** (opensearch pending)
- DONE (boxes ticked): **6.4** (permanent hard-reject — both `SIFT_PHASE==6` guards removed in `backends/__init__.py`, monkeypatch dropped from `test_phase4.py`); **6.2** for 3 of 4 backends → marked `[~]`.
- What shipped:
  - **6.4:** missing/invalid add-on manifest is now *always* a `ValueError` (no env needed). `grep SIFT_PHASE packages/` clean.
  - **rag → `kb_*`** (3 tools): manifest + `server.py` fn renames + `tool_metadata.py` + docstrings; `kb_get_knowledge_stats` = health.
  - **windows-triage → `wintriage_*`** (6 advertised tools): manifest + word-boundary rename in `server.py`/`tool_metadata.py`/`test_windows_triage.py`; granular internal branches left un-namespaced (not advertised); `wintriage_server_status` = health (`health_args={"resource":"health"}`). Cross-backend `triage_remote.py` + its test updated; gateway `test_windows_triage_backend.py` rewritten to the real manifest.
  - **opencti → `cti_*`** (8 tools): manifest + **surgical** rename (avoided breaking real `self.client.*` methods of the same name) in `server.py`/`tool_metadata.py` (per-type meta keys kept); `cti_get_health` = health. Cross-backend `threat_intel.py` `lookup_ioc`→`cti_lookup_ioc`.
  - Agent-facing strings retargeted to namespaced names where the migrated tool was referenced: `sift_common/instructions.py`, `sift_core/case_manager.py`, `sift_core/execute/response.py`.
- Tests (per-package, all green): sift-gateway 121, sift-core 301, opensearch-mcp 973 (+71 skip), windows-triage-mcp 11, forensic-mcp 20. opencti-mcp & sift-common have no test suite. All 3 new manifests validate against the schema; all 3 backends import clean.
- Live test on VM: NO (code+unit only; VM is core-only per Session 23). Each migrated backend still needs the live incremental bring-up (enable just that backend → `scripts/probe_backends.py` → F-A gate check) — folds into the opensearch step + Phase 6 gate.
- Spec changed?: tracker only (6.2/6.4 boxes + this log). HTML/mmd unchanged.
- BLOCKERS / open questions: **opensearch naming decision** — keep `idx_*` and prefix to `opensearch_idx_*`, or rename `idx_*`→`opensearch_*`? The manifest `namespace` must equal the literal advertised-tool prefix (gateway enforces `<namespace>_`). 973 tests reference `idx_*` → large test fallout either way.
- NEXT: **6.2 opensearch** (`opensearch_*` + `case_host_fix`→`opensearch_host_fix` + `idx_install_pipelines` `hidden_from_agent` via manifest), then **6.3** (portal Backends tab + REST validate/register), then **6.5** (test_phase6.py + per-package test sweep + spec sync), then the **Phase 6 GATE** full-addon install + live e2e on 192.168.122.81.

### Session 23 — 2026-06-02 — Phase 6 re-scope + 6.1 (manifest-driven core)
- Branch/commit: revamp/spg-v1 @ <commit after this session>
- Phase: 6 — tasks touched: Phase 6 rewrite (6.1–6.5 + gate), §5 playbook align, **6.1 DONE**
- Trigger: operator flagged a real disconnect — "core should never change to accept an add-on, and the portal should let an operator add a compliant backend after a compliance check." Verified in code: Phase 4 contract machinery is already zero-hardcoded-names; the **only** leak was three UX maps in `mcp_endpoint.py` (`_TOOL_CATEGORIES`/`_PHASE_RECOMMENDED`/`_ENV_SUMMARY_TOOLS`) hardcoding add-on **tool names**, and there is **no portal self-service add-backend flow** (only hand-edit gateway.yaml + `POST /backends/reload` + CLI probe).
- Decisions (operator-confirmed): (1) make those maps **manifest-driven** before migrating backends; (2) **build the portal add-backend flow** (validate→register→hot-reload) as part of Phase 6. Rewrote Phase 6 into ordered 6.1→6.5 and fixed §5 (added per-tool category/phase/health to the manifest authoring step; removed the retired `accepts_analyst_override`); extended `R-no-hardcoded-names` to tool categorization/phase/env-summary.
- DONE (boxes ticked): **6.1** — schema `+category/recommended_phase/health/health_args/hidden_from_agent`; gateway builds `_tool_manifest_meta` in `_build_tool_map`; `mcp_endpoint.py` category/phase maps reduced to core+synthetic (`_CORE_TOOL_*`), add-on category/phase/hide + `environment_summary` health tools now read from manifests. Zero add-on tool names left in `mcp_endpoint.py`.
- Tests: 121 passed / 0 failed — `uv run python -m pytest packages/sift-gateway/ -q`. Schema self-validates + sample manifest with new fields validates. Grep gate (add-on tool names in `mcp_endpoint.py`) = CLEAN.
- Live test on VM: NO (code+unit only). VM (192.168.122.81) was wiped; repo synced this session. **Reinstall as `./install.sh --core-only -y`** — NOT full-addon yet: the four add-ons still have no `sift-backend.json` and are un-migrated (6.2), so a full-addon install would boot them in legacy/un-namespaced warn-degrade mode (no manifest → namespace enforcement off, no add-on health in `environment_summary`, no add-on category/phase meta, and `idx_install_pipelines` becomes agent-visible since its hide now depends on the manifest `hidden_from_agent` flag). **Full-addon is the Phase 6 GATE**, reached after 6.2. Bring add-ons online incrementally during 6.2 (migrate one → drop its manifest → enable just that backend → `scripts/probe_backends.py`); that is also how 6.1 gets its live proof (first real manifest advertising category/phase/health).
- Spec changed?: tracker only (Phase 6 + §5 + invariant + this log). HTML/mmd unchanged — sync if 6.2/6.3 behaviour drifts (R-spec-truth).
- BLOCKERS / open questions: none.
- NEXT: **6.4** (flip `SIFT_PHASE==6` guards → permanent hard-reject; tiny) then **6.2** rag-first migration (kb_*) verified live on the VM, one backend at a time. 6.3 (portal Backends tab + REST validate/register) is its own focused session.

### Session 22 — 2026-06-02 — Phase 5.1: central output cap (trust layer)
- Branch/commit: revamp/spg-v1 @ <commit after this session> (Phase 4 now committed `a73dbec`; tree was clean at session start)
- Phase: 5 — tasks touched: 5.1 (all of Phase 5)
- DONE (boxes ticked this session): 5.1 + Phase 5 gate marked GREEN (code-complete/unit-verified)
- Tests: 121 passed / 0 failed — `uv run python -m pytest packages/sift-gateway/ -q` (104 prior + 17 new `test_phase5.py`); 301 passed / 0 failed — `packages/sift-core/` (unchanged baseline).
- Design decisions (confirmed with user via AskUserQuestion): **(1) cap model = backstop + disk-spill-for-all** — central ceiling AND extend run_command-style disk persistence to every backend's overflow; **(2) scope = aggregated agent `/mcp` surface only** (per-backend mounts left as-is, they're the service-token conformance surface).
- New/changed files: `response_guard.py` (+`output_cap_bytes`/`cap_tool_result`/`_spill_full_output`), `mcp_endpoint.py` (redact→cap loop, cap audit, unified `_sift_context`), `config.py` (+`apply_trust_env`, wired into `load_config`), `configs/gateway.yaml.template` (+`trust.output_cap_bytes: 262144`), `tests/test_phase5.py` (17).
- Key invariant landed: **redact-then-cap** (secret can't straddle the cut and leak half) — proven by `test_redact_then_cap_never_leaks_partial_secret`. Full spilled output is the *redacted* text (secrets never hit disk).
- Live test on VM: NO — VM was wiped clean last session; needs `install.sh --core-only` fresh. Phase 5 live exercise folds into the Phase 6 add-on migration (same caveat as Phase 4; first real large-output add-on to probe).
- Spec changed?: no (HTML/mmd unchanged; tracker checkboxes + gate + this log only).
- BLOCKERS / open questions for next session: none. Consider committing Phase 5 before starting Phase 6.
- NEXT: Phase 6 — migrate the four add-ons to namespaces (§5 playbook, order rag → windows-triage → opencti → opensearch); this also discharges the deferred Phase 4 + Phase 5 live-VM probes.

### Session 21 — 2026-06-02 — Phase 4 (4.1–4.10): universal identity + Backend Contract v1 + binary gate
- Branch/commit: revamp/spg-v1 @ working tree (not committed)
- Phase: 4 — tasks touched: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10 (all)
- DONE (boxes ticked this session): 4.1–4.10 + Phase 4 gate marked GREEN (code-complete/unit-verified)
- Tests: 104 passed / 0 failed — `uv run python -m pytest packages/sift-gateway/ -q`; 301 passed / 0 failed — `packages/sift-core/`; 20 passed / 0 failed — `packages/forensic-mcp/`. New `tests/test_phase4.py` = 15/15. (Gateway count moved 115→104: removed obsolete `test_two_tier_gate.py`, added `test_phase4.py`.)
  - Pre-existing unrelated failures: 2 in `case-dashboard/tests/test_auth_endpoints.py::TestSetupRequired` (response shape `setup_required` vs `required`) — confirmed by stashing this session's changes; not touched by Phase 4.
- New files: `sift_gateway/identity.py`, `sift_gateway/sift-backend.schema.json`, `tests/test_phase4.py`, `scripts/probe_backends.py`.
- Grep-gates CLEAN (non-test source): `analyst_override|ANALYST_TOOLS|accepts_analyst_override|analyst_identity`; `_agentir_context|build_unsealed_warning|VIOLATION_STATUSES|is_violation` (only the unrelated `sift_core/reporting.py:_VIOLATION_STATUSES` remains, intentionally). Last runtime `agentir` string gone (`_agentir_context`→`_sift_context`).
- Live test on VM: NO — code-complete + unit-green only. Phase 4 conformance probe + `phase2_gate_test.py` e2e on the fresh VM deferred to the Phase 6 add-on migration (first real manifest to probe lands there). Recorded as the live-VM caveat on the Phase 4 gate.
- Spec changed?: yes — `revamp-plan.html` updated last session ("new phase 4 definition", commit cdf099c) to add `identity.py` (F-F) and the binary-gate (F-A) to the architecture; this session updated `revamp-tasks.md` only (checkboxes + gate + this log). No `.mmd` change.
- DOCS NOTE: the prior session implemented all of Phase 4 and ran the suites green but the API connection dropped before the tracker was updated — this session re-verified the tree (tests + grep-gates + artifact presence) and brought `revamp-tasks.md` in sync. No code changed this session.
- BLOCKERS / open questions for next session: none. Working tree is uncommitted — consider committing Phase 4 before Phase 5.
- NEXT: Phase 5 (central output cap), then Phase 6 add-on migration (which also discharges the Phase 4 live-VM probe caveat).

### Session 20 — 2026-06-02 — Phase 3.4 Privileged Path implementation & verification
- Branch/commit: revamp/spg-v1 @ working tree (not committed)
- Phase: 3 — tasks touched: 3.4
- DONE (boxes ticked this session): 3.4
- Tests: 302 passed / 0 failed — `uv run python -m pytest packages/sift-core/ -q` and 115 passed / 0 failed — `uv run python -m pytest packages/sift-gateway/ -q`
- Live test on VM: YES. Synced changed source files and tests to VM 192.168.122.81, ran `./install.sh --core-only`, and verified:
  - All 302 sift-core unit tests and 115 sift-gateway integration tests pass.
  - End-to-end `phase2_gate_test.py` passes 14/14 checks successfully.
  - Manual execution of `run_command(["mount", "/dev/loop0", "/cases/phase2-gate-smoke/tmp"])` triggers direct unprivileged permission failure, falls back to `/usr/bin/sudo -n --`, and executes successfully, generating expected `privilege_escalation` audit logs.
  - Manual execution of `run_command(["umount", "/cases/phase2-gate-smoke/tmp"])` also falls back and succeeds.
- Spec changed?: no
- BLOCKERS / open questions for next session: none
- NEXT: Phase 4.

### Session 19 — 2026-06-02 — Phase 3.3 cgroup and AppArmor confinement
- Branch/commit: revamp/spg-v1 @ working tree (not committed)
- Phase: 3 — tasks touched: 3.3
- DONE (boxes ticked this session): 3.3
- Tests: 297 passed / 0 failed — `uv run python -m pytest packages/sift-core/ -q` and 114 passed / 0 failed — `uv run python -m pytest packages/sift-gateway/ -q`
- Live test on VM: YES. Synced changed source files and test file to VM 192.168.122.81, ran `./install.sh --core-only`, and verified:
  - 10 unit tests in `test_execute_executor.py` passed successfully on the VM.
  - Manual execution of `run_command(["date"])` succeeded via `systemd-run --user --scope`.
  - Manual execution of `run_command(["sudo", "fdisk", "-l"])` successfully resolved target paths and executed fdisk.
  - Denied commands wrapped in sudo (like `sudo reboot`) and interactive flags (like `sudo -i`) were correctly blocked.
- Spec changed?: no
- BLOCKERS / open questions for next session: none
- NEXT: Phase 3.4 privileged path (capabilities-first → sudoers-allowlist fallback).

### Session 18 — 2026-06-02 — Phase 3.3 isolated run_command worker
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 3 — tasks touched: **3.3** partial.
- DONE (boxes ticked this session): none; **3.3 marked `[~]`** because cgroup/AppArmor confinement is still pending.
- What:
  - Added `sift_core.execute.worker`, a short-lived isolated executor process. Parent executor launches it with argv-only `subprocess.run(..., shell=False)`; worker launches the forensic command with `subprocess.Popen(..., shell=False)`.
  - Kept policy enforcement order intact: deny floor, operator denylist, allowlist mode, argument sanitization, and path validation all happen before the worker is invoked.
  - Preserved case cwd jail through the agent-facing `working_dir` resolver and added a gateway regression for inside-case cwd plus traversal rejection.
  - Added practical resource controls: timeout kills the worker child process group, output capture limit still prevents runaway capture, worker applies POSIX `RLIMIT_CPU`, and optional `SIFT_EXECUTE_MEMORY_LIMIT` maps to `RLIMIT_AS` where available.
  - Changed automatic large-output persistence to `case/agent/run_commands/outputN`; responses include `full_output_path`, hash, and byte count through the existing run_command envelope.
- Tests:
  - Local focused: `uv run python -m pytest packages/sift-core/tests/test_execute_executor.py -q` → **6 passed**.
  - Local focused: `uv run python -m pytest packages/sift-gateway/tests/test_inprocess_core_tools.py -q` → **6 passed**.
  - Local package: `uv run python -m pytest packages/sift-core/ -q` → **293 passed**.
  - Local package: `uv run python -m pytest packages/sift-gateway/ -q` → **114 passed**.
- Live test on VM: YES — synced runtime executor files to `192.168.122.81`, restarted user gateway, active case `/cases/phase2-gate`; MCP smoke passed: `date` succeeded through `isolated_worker`, `env` blocked by deny floor, cwd inside case preserved, cwd escape blocked, large output auto-wrote under `/cases/phase2-gate/agent/run_commands/outputN`, and `sleep 5` with `timeout=1` timed out. Gateway health OK after smoke.
- Spec changed?: no.
- BLOCKERS / open questions for next session:
  - Finish 3.3 with cgroup/AppArmor confinement if still in MVP scope before the Phase 3 gate.
  - Phase 3.4 privileged executor design remains untouched.
  - `scripts/phase2_gate_test.py` remains intentionally untracked Phase 2 artifact unless already committed.
- NEXT: continue **Phase 3.3** cgroup/AppArmor hardening, then **3.4** privileged path.

### Session 17 — 2026-06-02 — Phase 3.2 run_command allowlist mode
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 3 — tasks touched: **3.2**.
- DONE (boxes ticked this session): **3.2**.
- What:
  - Added `execute.security.mode` with default `denylist` and optional `allowlist`.
  - Added `execute.security.allowed_binaries` to `configs/gateway.yaml.template`.
  - Preserved denylist-default behaviour and kept the hard deny floor ahead of allowlist checks, so floor binaries cannot be re-enabled by allowlisting.
  - Wired allowlist enforcement through the existing in-process executor policy cache used by gateway `run_command`.
- Tests:
  - Local targeted: `uv run python -m pytest packages/sift-core/tests/test_execute_security_policy.py -q` → **7 passed**.
  - Local targeted: `uv run python -m pytest packages/sift-gateway/tests/test_execute_security_config.py packages/sift-gateway/tests/test_inprocess_core_tools.py -q` → **9 passed**.
  - Local: `uv run python -m pytest packages/sift-core/ -q` → **287 passed**.
  - Local: `uv run python -m pytest packages/sift-gateway/ -q` → **113 passed**.
- Live test on VM:
  - Synced scoped runtime files to `192.168.122.81`, temporarily changed live `~/.sift/gateway.yaml` to `execute.security.mode: allowlist` with `allowed_binaries: ["date", "env"]`, and restarted `sift-gateway.service`.
  - Real `/mcp/` agent calls on active sealed case `/cases/phase2-gate`: `run_command(["date"])` succeeded; `run_command(["cat", "--version"])` returned `Binary 'cat' is not allowed by execute.security allowlist mode`; `run_command(["env"])` remained blocked by the deny floor.
  - Restored the original live `~/.sift/gateway.yaml` and restarted gateway; `/health` returned OK.
- Spec changed?: no.
- BLOCKERS / open questions for next session:
  - Phase 3.3 hardened isolated executor is still todo.
  - Phase 3.4 privileged executor design is still todo; the earlier immutable capability installer cleanup does not count as 3.4.
- NEXT: **Phase 3.3** — hardened isolated executor.

### Session 16 — 2026-06-02 — Phase 3.1 executor policy relocation + installer warning cleanup
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 3 — tasks touched: **3.1** plus installer cleanup for finished-phase warnings.
- DONE (boxes ticked this session): **3.1**.
- What:
  - Replaced package-data executor `security.yaml` with `execute.security` in operator-editable `gateway.yaml`.
  - Added `sift_core.execute.security_policy` with a non-weakenable deny floor covering `mkfs*`, shutdown/reboot/halt/init/poweroff, kill tools, env/printenv, and raw-socket tools (`nc`, `ncat`, `socat`).
  - Gateway startup now rejects missing/empty `execute.security`; operator config can add denied binaries but cannot remove the deny floor.
  - Root cause of the old gateway health warning: service startup used `uv run`, which made restarts/package resolution slow enough for health polling to false-alarm. Confirmed VM service now uses `.venv/bin/sift-gateway` directly and health comes up in ~2 seconds.
  - Root cause of immutable warnings: installer ran `setcap` against `.venv/bin/python`, which is a symlink on the VM, and did not verify the capability. Installer now resolves the real executable and verifies `getcap`; VM capability applied to `/usr/bin/python3.12`.
  - Synced scoped source/config/test changes to the VM, added `execute.security` to live `~/.sift/gateway.yaml` (backup: `~/.sift/gateway.yaml.bak-20260601T215947Z`), removed the old remote `security.yaml`, and restarted gateway.
- Tests:
  - Local: `uv run python -m pytest packages/sift-core/ -q` → **283 passed**.
  - Local: `uv run python -m pytest packages/sift-gateway/ -q` → **109 passed**.
  - Local: targeted Phase 3.1 tests included in the above (`test_execute_security_policy.py`, `test_execute_security_config.py`, `test_inprocess_core_tools.py`).
  - Local: `bash -n install.sh` and `py_compile` for touched policy/config modules → OK.
- Live test on VM:
  - `systemctl --user restart sift-gateway.service`; `/health` OK on poll 2.
  - Real `/mcp/` agent call `run_command(["env"])` on active sealed case `/cases/phase2-gate` returned `success:false` with `Binary 'env' is blocked by security policy`.
  - Immutable capability smoke test on `/tmp/sift-immutable-smoke.txt`: set `+i`, observed flag, cleared `+i` → all true.
- Spec changed?: no.
- BLOCKERS / open questions for next session:
  - Phase 3.2 allowlist mode is still todo.
  - Phase 3.3/3.4 executor isolation and privileged-path design are still todo; this session only fixed the installer/runtime root cause of the existing immutable warning.
- NEXT: **Phase 3.2** — optional allowlist mode.

### Session 15 — 2026-06-02 — Reset test ledger, isolate Phase 2 gate, fix slow gateway restarts
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: post-Phase-2 gate stabilization — tasks touched: live VM evidence-chain cleanup, `scripts/phase2_gate_test.py`, gateway systemd service generation.
- DONE:
  - Reset `/cases/phase2-gate` evidence chain records after the Phase 2 gate test polluted the real test case with old `gate-tester` HMAC events.
  - Fixed `scripts/phase2_gate_test.py` so it no longer uses `/cases/phase2-gate` or a hardcoded test signing key.
  - Fixed the slow gateway restart path by removing `uv run --project ... sift-gateway` from the systemd service.
- What:
  - Backed up old `/var/lib/sift/phase2-gate/evidence-manifest.json` and `evidence-ledger.jsonl` under `/var/lib/sift/phase2-gate/backups/20260601T214639Z-reset-ledger`.
  - Rebuilt `/cases/phase2-gate` chain from the current evidence directory using the configured examiner ledger key. Result: manifest v1 with `evidence/Rocba-Memory.raw` and `evidence/rocba-cdrive.e01`; HMAC verify `ok=True`, `verified=1`, `failed=0`; structural integrity `ok=True`, `events=1`.
  - Patched `scripts/phase2_gate_test.py`:
    - default case is now `/cases/phase2-gate-smoke` (`SIFT_PHASE2_GATE_CASE_ID` override available);
    - agent/examiner tokens are loaded from `~/.sift/gateway.yaml` unless env overrides are provided;
    - seal/reseal uses the configured portal examiner's current ledger key instead of `TEST_KEY`;
    - existing smoke records are backed up before setup;
    - after the intentional F-A corruption check, evidence is immediately restored and re-sealed so the smoke case is left clean.
  - Ran the fixed Phase 2 gate on the VM: **14/14 checks passed** against `/cases/phase2-gate-smoke`.
  - Restored live `~/.sift/gateway.yaml` `case.dir` back to `/cases/phase2-gate` after the smoke test and restarted gateway.
  - Fixed restart performance:
    - `configs/systemd/sift-gateway.service` now uses `${SIFT_MCPS_ROOT}/.venv/bin/sift-gateway --config ${SIFT_CONFIG}` directly.
    - `install.sh` now fails fast if `.venv/bin/sift-gateway` is missing and polls health for 30s.
    - Patched the live VM user service to match.
    - Measured VM restarts: **2472 ms** and **1189 ms**. No `uv run` remains in the gateway service path.
- Tests:
  - Local: `uv run python -m py_compile scripts/phase2_gate_test.py` → OK.
  - Local: `bash -n install.sh` → OK.
  - VM: `/cases/phase2-gate` HMAC verify `ok=True`, `failed=0`; structural integrity `ok=True`.
  - VM: fixed `scripts/phase2_gate_test.py` full run → **14/14 passed**.
  - VM: gateway direct service restart measured at ~1–2.5 seconds.
- Live test on VM: YES — `siftworkstation` (`192.168.122.81`) running direct venv service; active case restored to `/cases/phase2-gate`.
- Spec changed?: no.
- BLOCKERS / open questions:
  - `seal_manifest` still logs `could not set +i` because `cap_linux_immutable` is not applied to the venv Python. This belongs to **Phase 3.4**.
  - `scripts/phase2_gate_test.py` is still untracked in local git status; add it intentionally with the rest of the Phase 2 artifacts before committing.
- NEXT: **Phase 3.1** — relocate denylist `security.yaml` → operator-editable `gateway.yaml` + non-weakenable deny floor.

### Session 14 — 2026-06-02 — Portal login loop fix on fresh VM
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: post-Phase-2 gate stabilization — tasks touched: portal auth/runtime; no phase boxes changed.
- DONE: fixed the portal login loop on `siftworkstation` (`192.168.122.81`) and reflected the rebuilt portal bundle into the running VM.
- What:
  - Root cause 1: `POST /portal/api/auth/login` returned `401`, `apiFetch()` converted that to `null`, and `LoginCard` treated `null` as a successful login. The app entered the authenticated shell, polling immediately received `401`, and the UI bounced back to login.
  - Root cause 2: first-run detection was split: backend returned `{"required": ...}` while React checked `setup_required`.
  - Root cause 3: installer-created account has `must_reset_password: true`, but the React portal had no forced-reset screen. Added a reset-password phase that reuses the current-password challenge flow, calls `/api/auth/reset-password`, then refreshes `/api/auth/me`.
  - Deployed changed `routes.py`, `LoginCard.jsx`, and rebuilt `static/v2` assets to `~/sift-mcps` on the VM via `rsync`; restarted the user service.
  - Killed a stale VM `uv sync --extra full` process that had been running for ~2 hours and was blocking `uv run` service startup. Gateway recovered after that.
- Tests:
  - Local: `uv run python -m pytest packages/case-dashboard/tests/test_session_middleware.py packages/case-dashboard/tests/test_session_jwt.py packages/case-dashboard/tests/test_token_lifecycle.py -q` → **61 passed**.
  - Local frontend: `npm run build` → OK; `npm run test` → **80 passed / 2 files**. One invalid attempt with Jest-only `--runInBand` failed and was rerun correctly.
  - VM: `/health` OK; `/portal/api/auth/setup-required` returns `{"required":false,"setup_required":false}`; `/portal/` serves rebuilt `index-CpRxQxN9.js`; challenge/login with the installer examiner returns **200**, sets cookie, and returns `must_reset:true`.
- Live test on VM: YES — portal bundle and backend patched in place; `systemctl --user is-active sift-gateway.service` → active.
- Spec changed?: no.
- BLOCKERS / open questions:
  - `install.sh` still creates a user service that launches through `uv run`; a stale `uv sync` can block service startup. This matches the Session 13 startup-time observation and should be fixed by switching the service to the venv binary or making install locking explicit.
  - The portal still needs a browser/manual pass for the reset-password UI, but the API path and bundle are deployed and verified.
- NEXT: **Phase 3.1** — relocate denylist `security.yaml` → operator-editable `gateway.yaml` + non-weakenable deny floor.

### Session 13 — 2026-06-02 — Phase 2 GATE live e2e on fresh VM
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 2 — gate verification. No task boxes changed (all already ticked); gate line updated to ✅ GREEN.
- DONE: **Phase 2 GATE passed** — 14/14 checks on siftworkstation (`192.168.122.81`). Created `scripts/phase2_gate_test.py` as the permanent gate test artifact.
- What:
  - Ran `./install.sh --core-only` on the fresh VM; gateway came up after ~5 min (uv run package-resolution overhead — see notes).
  - Verified via `scripts/phase2_gate_test.py --checks-only` (after pre-sealing a test case with `sift_core` direct):
    - **tools/list**: 19 tools (18 `sift_core.agent_tools` + `environment_summary` gateway-native in `mcp_endpoint.py`), zero add-on tools — confirmed R-core-survives.
    - **F-A gate**: `run_command` blocked with no active case ("No active case"); passes on sealed case (`chain_status==OK`); immediately blocks when evidence file is modified (`evidence_chain_violation`, `status: modified`) — confirmed F-A binary gate.
    - **Executor**: `run_command(["echo","phase2-gate-live"])` returned expected stdout via in-process `sift_core.execute` pipeline.
    - **Audit**: `record_action` accepted and written.
    - **Findings**: `record_finding` reached the validation layer (gate passed; content validation correctly caught missing `observation`/`interpretation`/`confidence` fields — not a regression, correct enforced schema).
    - **Portal role separation**: `/portal/api/cases` returns 403 for the agent token — R-roles confirmed.
- Observations / known gaps surfaced:
  - `seal_manifest` warns `could not set +i` (immutable bit) — `cap_linux_immutable` not applied to venv Python on this VM. Non-blocking for Phase 2; Phase 3.4 (privileged path) is the correct fix.
  - `install.sh` health-check timeout (120 s) < gateway startup time (~5 min) → "Gateway not reachable" warning in install output is a **false alarm**; gateway is fine. Fix: increase the health-check loop timeout in `install.sh` or switch the service to call venv Python directly instead of `uv run --project`.
  - `record_finding` schema requires `observation`, `interpretation`, `confidence` inside the `finding` dict — tighter than what a naive agent might send. The test script uses a simplified finding object. Document the full required schema somewhere reachable to the agent (open item for Phase 4 instruction re-homing).
  - Open from Session 12: `run_command` discipline text (YARA sweeps, large-output, "treat evidence as untrusted") has no delivery home since `sift-mcp` was deleted. Still unresolved — Phase 4.
- Tests: `scripts/phase2_gate_test.py` on VM: **14/14 passed**. No per-package unit runs this session (no source changes).
- Live test on VM: YES — full e2e on `siftworkstation` (`192.168.122.81`, sansforensics/forensics). Case `/cases/phase2-gate` created and sealed with `sift_core` direct; gateway configured with `case.dir`.
- Spec changed?: no.
- BLOCKERS / open questions: install.sh health-check timeout (cosmetic — see above). No blocking issues.
- NEXT: **Phase 3.1** — relocate denylist `security.yaml` → operator-editable `gateway.yaml` + non-weakenable deny floor.

### Session 12 — 2026-06-01 — Remove dormant migrated packages (case-mcp / report-mcp / sift-mcp)
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 2 (cleanup) — no task boxes; repo-hygiene pass on the now-consolidated core.
- DONE: deleted **3** fully-migrated dormant packages whose logic now lives in core/portal: `case-mcp` (→ `sift_core` case/evidence), `report-mcp` (→ `sift_core.reporting`/`report_profiles` + portal), `sift-mcp` (→ `sift_core.execute`). **Kept `forensic-mcp`** (owner decision 2026-06-01): it still nominally hosts the 14 methodology `get_*` tools + discipline resources earmarked for Phase 7 `/skills`; its content source is the `forensic-knowledge` data package. None of the 3 removed packages were started by the gateway (absent from `gateway.yaml.template`) and nothing imported them at runtime.
- Cleanup wiring touched:
  - `pyproject.toml`: dropped the 3 from `[tool.uv.sources]` + `[project.optional-dependencies].core`. `uv lock` removed `case-mcp`/`report-mcp`/`sift-mcp`; `uv sync --extra full` uninstalled them.
  - `sift-gateway/mcp_endpoint.py`: removed `CASE_MCP`/`REPORT_MCP`/`SIFT_MCP` imports + their `_BACKEND_INSTRUCTIONS` entries; relabeled `_ENV_SUMMARY_TOOLS` (`case_status`/`evidence_list`/`list_available_tools` now labeled `sift-core` — they already resolve in-process via `gateway.call_tool`).
  - `sift-common/instructions.py`: removed the now-orphaned `SIFT_MCP`/`CASE_MCP`/`REPORT_MCP` constants; fixed stale `GATEWAY` prose (dropped the `sift-mcp` backend line → "core forensic tools (… tool execution)", and removed the agent-facing `"Reports — generate_report"` line since report-gen is portal-owned per F-E). Fixed the `suggest_tools on sift-mcp` bootstrap line.
  - Stale references swept: `opensearch-mcp/parse_memory.py` docstring + `server.py:2603` suggest_tools hint; `sift_core` module docstrings that named the deleted packages as owners; `scripts/remediation-gate.sh` `shell=True` rule (was scoped to the deleted `packages/sift-mcp` → now "shell=False everywhere", which the no-shell executor already satisfies).
  - **Kept intentionally:** `Gateway._RETIRED_CORE_BACKENDS` (still lists all 4 — graceful skip-guard if a stale config names them) and `test_inprocess_core_tools.py` (regression proving retired-backend names don't strip core tools). `forensic-knowledge` knowledge corpus still says "(via sift-mcp …)" in playbook/tool YAML — left as Phase 7 content, not package wiring.
- Tests: green, all match Session 11 baseline — `sift-gateway` **105**, `sift-core` **280**, `forensic-mcp` **20**, `opensearch-mcp` **973** (+71 skip), `case-dashboard` **281**, `sift-common` (no tests). `bash scripts/remediation-gate.sh` → **Gate PASSED**.
- Live test on VM: none yet — **but the fresh VM is now live**: `siftworkstation` @ `192.168.122.81` (sansforensics/forensics), Ubuntu 24.04 (kernel 6.8), Python 3.12.3. **Repo is NOT deployed there yet** (no repo / no `install.sh` in `~`), so the Phase 2 gate e2e still needs: copy repo → run renamed `install.sh` → portal first-run → evidence seal → in-process core finding loop. (Note: VM host key changed vs. the old box — cleared the stale `known_hosts` entry.)
- Spec changed?: no — repo-hygiene only; behaviour unchanged (the removed packages were already dormant/not-served).
- BLOCKERS / open questions for next session:
  - **Follow-up (pre-existing gap, surfaced by this cleanup):** the deleted `SIFT_MCP` instruction block carried the detailed `run_command` discipline (YARA sweeps, large-output pattern, "treat evidence as untrusted", correlation≠causation). Since Session 10 moved `execute` to in-process core (no `sift-mcp` backend endpoint), that per-backend instruction was already orphaned. The condensed essentials live in the `GATEWAY` umbrella instruction (delivered on the main `/mcp`), but the deeper discipline now has no delivery home. **Re-home** it onto the in-process core tool surface (likely Phase 4 when the gate/instructions get finalized). Full text recoverable from git history (`instructions.py` pre-Session-12).
- NEXT: deploy repo to the live VM + run the renamed `install.sh` → **Phase 2 GATE live e2e** (seal → in-process core finding loop). Then **Phase 3.1**.

### Session 11 — 2026-06-01 — Phase 2 close: reporting+metadata → core/portal (2.1/2.2/2.3)
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 2 — tasks touched: **2.1, 2.2, 2.3**. Boxes **ticked**.
- DONE (boxes ticked this session): **2.1, 2.2, 2.3**. Phase 2 task list complete (live VM e2e gate still pending).
- What: finished the reporting migration that was blocking 2.1. Moved report generation into `sift_core.reporting` (`generate_report_data` + IOC/MITRE/summary/Zeltser helpers, guidance constants, `reconcile_verification` using `sift_core.verification.VERIFICATION_DIR`) and profiles into `sift_core.report_profiles`; moved case-metadata validation/persistence into `sift_core.case_metadata` (`set_case_metadata`/`get_case_metadata` + validation tables). Repointed the portal `generate_report_route` off `report_mcp` onto `sift_core` (killed the import shortcut), and added an examiner-guarded `POST /api/case/metadata` route (`post_case_metadata`) + `postCaseMetadata` frontend helper for F-E metadata ownership. Slimmed `report-mcp/server.py` to a dormant thin delegator over core (`profiles.py` re-exports core). Pruned the dead reporting + `export_bundle`/`import_bundle` entries from the gateway `_TOOL_CATEGORIES`/`_PHASE_RECOMMENDED` maps. Migrated the 30 report-mcp evidence-chain tests into `sift-core/tests/test_reporting_evidence_chain.py` (patching `sift_core.reporting.*`), kept 1 delegation smoke test in report-mcp, and added `sift-core/tests/test_case_metadata.py` (22) + `case-dashboard/tests/test_case_metadata_endpoint.py` (7).
- Tests: green — `sift-core` **280** (228 + 52 new), `report-mcp` **1** (logic+30 tests moved to core), `sift-gateway` **105**, `case-dashboard` **281** (274 + 7), `sift-mcp` **4**, `forensic-mcp` **20**, `case-mcp` **23**. Also `py_compile` over all touched modules and an agent-surface assert proving `core_tool_names()` excludes `export_bundle`/`import_bundle`/`generate_report`/`set_case_metadata`/`get_case_metadata`/`save_report`/`list_reports`/`list_profiles` while `sift_core.case_io.export_bundle`/`import_bundle` still exist. Per-package runs (whole-suite from root still fails on duplicate basenames — pre-existing).
- Live test on VM: none (fresh VM still not provisioned).
- Spec changed?: no — behaviour matches F-E/F-C already documented in `revamp-plan.html`; code/tracker only.
- BLOCKERS / open questions for next session: Phase 2 GATE still needs the fresh-VM e2e (seal → in-process core finding loop). Open decision deferred: whether to fully remove the now-dormant `report-mcp`/`sift-mcp`/`case-mcp` packages after Phase 3, or keep them as thin compat shims.
- NEXT: Phase 2 gate live e2e on the fresh VM, then **Phase 3.1** (relocate denylist `security.yaml` → operator-editable `gateway.yaml` + non-weakenable deny floor).

### Session 10 — 2026-06-01 — Phase 2.1 execute + discovery/FK enrichment into core
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 2 — tasks touched: **2.1**. Box remains **partial** (`[~]`), not ticked.
- DONE (boxes ticked this session): none.
- What: migrated the execute slice out of `sift-mcp` into `sift_core.execute`: catalog/security policy, config/env helpers, executor, exceptions, discovery helpers, generic command runner, and FK response enrichment/decay. Registered `run_command`, `list_available_tools`, `get_tool_help`, `check_tools`, and `suggest_tools` as direct `sift-core` tools in `sift_core.agent_tools`; updated the in-process-core regression to prove `run_command(["date"])` works with missing retired core subprocesses. Added `sift-core` package-data inclusion for the execute catalog.
- Tests: green — `packages/sift-core/` **228 passed**, `packages/sift-gateway/` **105 passed**, `packages/sift-mcp/` **4 passed**, focused in-process core regression **1 passed**, and `py_compile` over core execute/gateway modules. The `py_compile` command needed escalated execution because the sandbox could not create files in the `uv` cache.
- Live test on VM: none.
- Spec changed?: no.
- BLOCKERS / open questions for next session: 2.1 still needs reporting ownership finished (`generate_report`/`set_case_metadata` portal-owned per F-E, agent surface adjusted; keep core functions where appropriate). Need decide whether to fully remove or leave legacy `sift-mcp` package after Phase 2/3 once sandbox executor lands.
- NEXT: continue **2.1/2.3** with reporting and metadata portal ownership; keep `export_bundle`/`import_bundle` absent from agent surface for **2.2**.

### Session 9 — 2026-06-01 — Phase 2.1 direct in-process core tools (partial)
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 2 — tasks touched: **2.1**. Box marked **partial** (`[~]`), not ticked.
- DONE (boxes ticked this session): none.
- What: read `revamp-plan.html` and corrected course away from a backend-adapter approach. Added direct `sift_core.agent_tools` registration/dispatch for 13 gateway-owned core tools (case/evidence/audit/findings/timeline/TODO/workflow), wired `sift_gateway.server.Gateway` to expose/call them in-process, skipped retired core backend config entries (`forensic-mcp`, `case-mcp`, `sift-mcp`, `report-mcp`), removed those four subprocess entries from `configs/gateway.yaml.template`, and added a regression proving core tools remain available when the old subprocess commands are missing.
- Tests: green — `packages/sift-gateway/` **105 passed**, `packages/sift-core/` **228 passed**, `bash -n install.sh`, plus focused `py_compile`. A combined `pytest packages/sift-gateway/ packages/sift-core/` hit the repo's known duplicate `tests.*` collection issue; per-package runs are the valid gate.
- Live test on VM: none.
- Spec changed?: no.
- BLOCKERS / open questions for next session: 2.1 is not complete until execute (`run_command`, discovery helpers, FK enrichment/decay) is migrated into `sift_core` properly and reporting is moved to its intended portal/core ownership. Do not shortcut through old MCP package imports or adapters.
- NEXT: continue **2.1** by migrating execute support into `sift_core` and registering `run_command`, `list_available_tools`, `get_tool_help`, `check_tools`, `suggest_tools` directly from core.

### Session 8 — 2026-06-01 — Finish Phase 1 core consolidation + F-B records relocation
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 1 — tasks touched: **1.2, 1.3, 1.4, 1.5**. Boxes **ticked**.
- DONE (boxes ticked this session): **1.2, 1.3, 1.4, 1.5**. Phase 1 task list is now complete.
- What: moved finding-time considerations into `sift_core.case_manager`, made grounding use a declaration/provider interface instead of hardcoded backend names, relocated integrity records via `case_records_dir()` (`SIFT_STATE_DIR` or `/var/lib/sift/<case_id>/`), routed audit/approvals/manifest/ledger/anchor/gate reads through the new helpers, removed `audit` from normal case subdirs, and confirmed `case_host_fix` remains out of core/gateway-owned code.
- Tests: green — `packages/sift-core/` **228 passed**, `packages/case-mcp/` **23 passed**, `packages/forensic-mcp/` **20 passed**, `packages/report-mcp/` **31 passed**, `packages/sift-gateway/` **104 passed**, `packages/case-dashboard/` **274 passed** (42 warnings). Also ran `py_compile` over the touched modules and grep checks for hardcoded grounding names / core `case_host_fix` references.
- Live test on VM: none.
- Spec changed?: no.
- BLOCKERS / open questions for next session: Phase 1 live gate still needs fresh VM verification that `/var/lib/sift/<case_id>/` permissions are correct and `run_command` cannot read/write records. Unit tests use `/tmp` compatibility shadows only to avoid `/var/lib` writes.
- NEXT: Phase 1 gate live check, then Phase 2.1 in-process core tools.

### Session 7 — 2026-06-01 — Phase 1.1 core case-record consolidation
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 1 — tasks touched: **1.1**. Box **ticked**.
- DONE (boxes ticked this session): **1.1**.
- What: moved the case-record manager implementation into `sift_core.case_manager`, moved finding validation into `sift_core.finding_validation`, left compatibility re-exports in `forensic_mcp.case.manager` and `forensic_mcp.discipline.validation`, and routed `case-mcp` evidence listing through `sift_core.evidence_ops.list_evidence_status_data`.
- Tests: green — full affected package suites: `packages/sift-core/` (**228 passed**), `packages/forensic-mcp/` (**20 passed**), `packages/case-mcp/` (**23 passed**), `packages/report-mcp/` (**31 passed**). Also re-ran the combined targeted evidence/consolidation check (**58 passed**).
- Live test on VM: none.
- Spec changed?: no.
- BLOCKERS / open questions for next session: none for 1.1. F-B relocation remains task 1.4; grounding/considerations remain 1.2/1.3.
- NEXT: **1.2** or **1.4** depending on whether to finish finding-time core logic before moving integrity records.

### Session 6 — 2026-06-01 — Phase 0.4 token prefix cutover
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 0 — tasks touched: **0.4**. Box **ticked**.
- DONE (boxes ticked this session): **0.4**.
- What: changed gateway/examiner tokens to `sift_gw_*` and service/agent tokens to `sift_svc_*` in `sift_gateway.token_gen`, installer first-run token generation, portal token tests, gateway auth/audit tests, docs/config examples, and local MCP sample config/scripts. Portal token creation already uses `generate_service_token()`, so it now mints `sift_svc_*` without a separate code path.
- Tests: green — targeted token suites: `packages/sift-gateway/tests/test_phase13_auth.py packages/sift-gateway/tests/test_audit_envelope.py packages/sift-gateway/tests/test_portal_agent_block.py` (**29 passed**), `packages/case-dashboard/tests/test_token_lifecycle.py packages/case-dashboard/tests/test_session_middleware.py` (**42 passed**); local package gate: sift-core **228**, case-dashboard **274** (42 warnings), sift-gateway **104**, case-mcp **23**, opensearch-mcp **973** (+71 skipped), sift-mcp **4**, report-mcp **31**, forensic-mcp **20**, windows-triage-mcp **11**. `bash -n install.sh`; `bash scripts/remediation-gate.sh` (**PASSED**). Legacy token-prefix grep is clean in tracked source/config/docs; only untracked `old-repo-AGENTS.md` still contains the old live-token notes.
- Live test on VM: none (fresh VM still provisioned).
- Spec changed?: yes — `revamp-plan.html` token-prefix prose now names only the new `sift_svc_*` prefix.
- BLOCKERS / open questions for next session: Phase 0 gate still needs a fresh VM install/live boot. `_agentir_context` remains intentionally deferred to Phase 4.
- NEXT: Phase 0 gate work — provision/install on fresh VM or, if staying local, run any remaining per-package suites and decide whether to rebuild the generated portal bundle.

### Session 5 — 2026-06-01 — Phase 0.3 remaining `agentir` surface
- Branch/commit: `revamp/spg-v1` @ working tree (not committed)
- Phase: 0 — tasks touched: **0.3**. Box **ticked**.
- DONE (boxes ticked this session): **0.3**.
- What: completed the audited 0.3 backlog beyond the original tracker count. Renamed security/identity constants (`sift-auth-v1`, `sift-signing-v1`, `sift.evidence-anchor.v1`, `SIFT|...`, `sift_session`), audit rule filename/keys (`99-sift-evidence.rules`, `sift_evidence_write`, `sift_core_write`), OpenSearch plugin module and entry-point group (`sift_plugin`, `sift.plugins`), and 0.3-owned docstrings/comments/product strings. Confirmed the previously flagged AppArmor `~/.sift/bin` and remediation-gate `packages/sift-core/` latent bugs were already fixed in this tree.
- Tests: green — `uv run python -m pytest packages/sift-core/ --tb=short -q` (**228 passed**), `packages/case-dashboard/` (**274 passed, 42 warnings**), `packages/opensearch-mcp/` (**973 passed, 71 skipped**), `packages/sift-gateway/` (**104 passed**), `packages/case-mcp/` (**23 passed**), `packages/report-mcp/` (**31 passed**), `packages/forensic-mcp/` (**20 passed**), `bash -n install.sh`, `bash -n scripts/remediation-gate.sh`, and `bash scripts/remediation-gate.sh` (**PASSED**). `packages/opencti-mcp/` has no collected tests (pytest exit 5).
- Live test on VM: none (fresh VM still not provisioned — open §2 item).
- Spec changed?: no — code/docs/tracker only; revamp spec still contains historical rename context.
- BLOCKERS / open questions for next session: 0.4 still owns token prefixes; Phase 4 still owns `_agentir_context` removal with the readOnlyHint carve-out.
- NEXT: **0.4** — rename generated gateway/service token prefixes and update portal/token tests.

### Session 4 — 2026-06-01 — Phase 0.2 finish (`/cases` single-resolver)
- Branch/commit: `revamp/spg-v1` @ `a6cd48d`
- Phase: 0 — tasks touched: **0.2** (the `/cases` single-resolver clause — the last open piece). Box **ticked**.
- DONE (boxes ticked this session): **0.2** (now fully `[x]`).
- What: added `sift_core.case_io.cases_root()` — the one cases-root resolver (precedence `SIFT_CASES_ROOT`→`SIFT_CASES_DIR`→`~/cases`) — and routed all 13 scattered cases-root env reads through it across `sift-core`, `case-mcp`, `report-mcp`, `opensearch-mcp` (server/ingest_cli/containers), `sift-mcp/security.py`, plus `case-dashboard` + `forensic-mcp` (both gained an explicit `sift-core` dep; no dep cycle — sift-core only needs pyyaml). Removed orphaned `_DEFAULT_CASES_DIR`/`CASES_DIR_ENV`/`DEFAULT_CASES_DIR` constants. Intentional defense-in-depth belts (`sift-mcp/security.py` static `/cases`+`/evidence`; `opensearch/server.py` allow-root list) kept + documented in-code; the opensearch allow-list now also includes `cases_root().resolve()` so a custom root is honored. Net effect: env *writers* = gateway `config.py` (yaml→env) + portal `routes.py` (registration); env *reader* = `cases_root()` only.
- Tests: per-package, **all green, baseline preserved** — sift-core **228** (225 baseline + 3 new `TestCasesRoot` precedence tests), case-dashboard 274, sift-gateway 104, case-mcp 23, opensearch 973 (+71 skip), sift-mcp 4, report 31, forensic 20, win-triage 11. Command: `uv run python -m pytest packages/<pkg>/ -q`. Ran `uv sync --extra full` after the two pyproject dep additions.
- Live test on VM: none (fresh VM still not provisioned — open §2 item).
- Spec changed?: no — `revamp-plan.html` already describes sift-core as the single source of truth for `case_root` (architecture diagram + §6.3); the resolver realizes that intent. (Note: §6.3's pre-fork text still mentions an `AGENTIR_*` fallback + `/var/lib/agentir` symlink; that's superseded by D1 clean-cutover and was already not implemented — left as historical spec prose.)
- Gotchas: (1) `DEFAULT_CASES_DIR` is frozen at import (`str(Path.home()/"cases")`), so monkeypatching `Path.home()` after import does NOT change the resolver's default — test the default against the constant, not a patched home. (2) Two call-sites had a local var literally named `cases_root` shadowing the import — replaced the inline `Path(...)` construction with direct `cases_root()` calls. (3) The lone remaining `AGENTIR_` hit is the generated portal bundle `static/v2/assets/index-*.js` — still needs the VM frontend rebuild flagged in Session 3.
- BLOCKERS: none.
- NEXT: **0.3** (service/identifier surface: `agentir-opensearch`→`sift-opensearch`, opensearch identifiers `agentir-geoip`/`agentir-evtx-ecs`, `agentir_plugin` module + `agentir.plugins` entry-point group, `agentir_home()` fn, config filenames `99-agentir-evidence.rules`/`agentir-cases.conf`, `agentir_core_write` audit key, product-name strings). Then **0.4** (token prefix to `sift_svc_*`). NOTE: 0.3 touches live OpenSearch index/role identifiers — best validated on the (still-unprovisioned) fresh VM.

### Session 3 — 2026-06-01 — Phase 0.1 (package rename) + 0.2 env/path rename
- Branch/commit: `revamp/spg-v1` @ `d292df9` — chain: `cc9765e` (stale-doc cleanup) → `4890f75` (0.1 rename) → `48ab494` (tracker SHA) → `d292df9`.
- Phase: 0 — tasks touched: **0.1** (done, ticked), **0.2** (env/path rename done; `/cases` resolver deferred — box marked `[~]`).
- DONE (boxes ticked): **0.1**. **0.2 rename portion** complete but box left `[~]` (not fully ticked — `/cases` single-resolver clause outstanding).
- 0.1: `git mv` package `agentir-core`→`sift-core`, `agentir_core`→`sift_core`; dist name + 4 dependents + root workspace; swept all `.py` + install.sh; docs/AGENTS module refs.
- 0.2: `AGENTIR_*`→`SIFT_*` (41 vars/442 occ), `/var/lib/agentir`→`/var/lib/sift`, `~/.agentir`→`~/.sift` across all py/tests/install.sh/configs (incl. 2 `.template` files)/docs/frontend src. `grep -rE 'AGENTIR_|/var/lib/agentir'` over source/config = 0. **`/cases` single-resolver consolidation deferred** (scattered cases-root logic — details under task 0.2 "STILL TODO").
- Tests: per-package, re-run after each rename — **identical counts, all green** every time: sift-core 225 · case-dashboard 274 · sift-gateway 104 · case-mcp 23 · opensearch 973 (+71 skip) · sift-mcp 4 · report 31 · forensic 20 · win-triage 11. Command: `uv run python -m pytest packages/<pkg>/ -q` (whole-suite from root fails on duplicate test basenames — pre-existing; run per-package).
- Live test on VM: none (fresh VM still not provisioned — open §2 item).
- Spec changed?: `revamp-plan.html` NOT touched (it documents the rename intentionally — `ux-tasks.md` also still has one `AGENTIR_CASE_DIR` ref, left as a different project's historical doc). Docs/AGENTS updated for both renames.
- Gotchas (now also in §4): (1) `uv sync` **without** `--extra full` prunes the venv to dev-only and deletes all workspace editable installs → always `uv sync --extra full`. (2) The two `configs/*.template` files are NOT matched by `--include='*.yaml'` etc. — must rename env vars in them explicitly or first-run rendering breaks. (3) The portal **built bundle** `packages/case-dashboard/src/case_dashboard/static/v2/assets/index-*.js` is a generated artifact that still contains old `AGENTIR_*` strings — needs a **frontend rebuild** on the VM (source `frontend/src` is already fixed).
- Deferred (tracked under tasks 0.2 NOTE / 0.3 / 0.4 / Phase 4 so nothing is lost): token prefixes → 0.4; `_agentir_context` → Phase 4; opensearch identifiers + `agentir_plugin` module + `agentir_home()` fn + config filenames + `agentir_core_write` audit key + product-name strings → 0.3.
- BLOCKERS: none.
- NEXT: finish **0.2** — build the single `sift_core` cases-root resolver and route the scattered call-sites through it (see task 0.2 "STILL TODO"), then tick 0.2. Then **0.3** (service/identifier surface) and **0.4** (token prefix).

### Session 2 — 2026-06-01 — Repo setup + spec cleanup + tracker expansion
- Branch/commit: `revamp/spg-v1` @ `b1593a2` (planning artifacts committed; `pre-revamp-v0` tagged at `main` 0c260ff; worktree at `../sift-mcps-main`).
- Phase: pre-0 (repo setup done; Phase 0 deferred to next session per owner).
- DONE: §2 repo setup boxes (commit, tag, branch, worktree). Locked forks **F-E** (set_case_metadata + reporting → portal-owned) and **no-back-compat** (clean cutover, fresh VM/case) + token-prefix rename to `sift_svc_*`. Cleaned `revamp-plan.html`: stripped all 29 `##NOTE##` markers (42 verified edits) and fixed deviations to match F-A..F-E (binary evidence gate §4.2, case_host_fix stays opensearch, grounding graceful-degradation note, audit relocation §8, R9 revised + R12/R13 added). Added tracker "What we're doing" mission + §5 add-on migration playbook; renumbered Phases/Invariants/Log → §6/§7/§8.
- Tests: not run (docs + git only, no source change).
- Live test on VM: none (fresh VM not yet provisioned).
- Spec changed?: yes — `revamp-plan.html` fully reconciled with locked decisions; `revamp-tasks.md` expanded.
- BLOCKERS: none.
- NEXT: provision the fresh SIFT VM (§2) - done - test access, then **Phase 0** (rename, clean cutover) — owner said Phase 0 starts next session.

### Session 1 — 2026-06-01 — Spec grounding + tracker creation
- Branch/commit: `main` (revamp branch not yet created — see §2)
- Phase: pre-0 — created this tracker from grounded code reading
- DONE: investigated all `##NOTE##` items in `revamp-plan.html`; answered the code questions (analyst_override, audit tools, bundles, methodology tools, provenance, grounding); locked forks F-A…F-D.
- Tests: not run this session (no code change).
- Live test on VM: none.
- Spec changed?: no (HTML notes still pending cleanup — do that as §1 decisions get applied).
- BLOCKERS: none.
- NEXT: **Task 2 (repo setup)** — tag `pre-revamp-v0`, branch `revamp/spg-v1`, add worktree; then provision the fresh VM.
