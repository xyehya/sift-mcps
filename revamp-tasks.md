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

### Grounded facts the build starts from (verified in code 2026-06-01)
- **Evidence gate today** = `blocked = chain_status != OK` (`sift_gateway/evidence_gate.py:117`) + a read-only carve-out in `mcp_endpoint.py`. F-A removes the carve-out.
- **Integrity records today live inside `case_dir`**: `audit/` (`audit_ops.py:15`), `approvals.jsonl` (`case_io.py:286`), `evidence-ledger.jsonl` (`evidence_chain.py:45`). `run_command` cwd/jail defaults to `AGENTIR_CASE_DIR` (`sift-mcp/tools/generic.py:71`) → records are inside the agent's reach. F-B fixes this.
- **`analyst_override`** = identity trust boundary: gateway overwrites it with the authenticated examiner for the 6 `ANALYST_TOOLS` (`mcp_endpoint.py:846`); backends can't spoof identity. → becomes manifest `identity.accepts_analyst_override` per tool.
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
1. **Author `sift-backend.json`** at the backend's well-known path. Fill: identity (`name`, namespace `prefix`), `spec_version`, `tier: addon`, per-tool `evidence_class` (`read_only` / `analysis` / `mutating`) + `readOnlyHint`, `identity.accepts_analyst_override` (almost always false for add-ons — they don't write core audit), `capabilities.provides` (set `["reference"]` for the three grounding backends: rag, windows-triage, opencti), `enriches_responses` (true only if the backend enriches its own tool output), and `requires[]` (services, RAM, docker, offline DBs).
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
All four backends pass the conformance probe, advertise only namespaced tools, are governed by the F-A gate, and the three reference backends light up grounding purely from their manifest `provides`. A from-scratch backend built from the spec + one of these as a template should aggregate on the first try.

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

### Phase 4 — Contract enforcement + declaration-driven gate (kills P3/P4)
- [ ] **4.1 Backend manifest schema (`sift-backend.json`) + JSON Schema**
  - *How:* fields: identity (name, namespace prefix), `capabilities.provides` (e.g. `["reference"]`), per-tool `evidence_class` + `readOnlyHint` + `identity.accepts_analyst_override`, `enriches_responses` flag, `requires[]`, health/identity endpoints. **Keep it simple** (your note @338) — one flat schema a dev can fill in 10 minutes.
  - *Test:* schema validates the four existing add-ons after they're given manifests; an invalid manifest is rejected with a clear error.
- [ ] **4.2 Tier in config: core (mandatory, can't disable) vs add-on (optional)**
  - *Why:* P4 — an operator must not be able to disable a core capability.
  - *Test:* attempting to disable a core capability is refused; add-ons toggle freely.
- [ ] **4.3 Namespace rule (structural collision fix)** — every add-on tool is `prefix_tool`; fixes `get_health`/`server_status` collisions.
  - *Test:* no two backends advertise the same tool name; reactive prefixing path removed.
- [ ] **4.4 Declaration-driven evidence gate — F-A binary block-all**
  - *How:* gate = `chain_status == OK` ? allow : block **all** agent `/mcp` tools (no `readOnlyHint` carve-out). UNSEALED is a block (not a warning). Block response points the agent to the portal. Health/lifecycle/portal endpoints are **not** agent tools and stay ungated — document this invariant.
  - *Why:* F-A — nothing runs against unsealed or compromised evidence; simplest defensible custody invariant.
  - *Test:* the §4 regression guard — unsealed → all blocked; sealed+OK → all allowed; corrupt → all blocked until re-seal.
- [ ] **4.5 Wire declaration-driven grounding (fill the 1.3 interface)** — count backends with `provides:["reference"]`.
  - *Test:* add-on manifest toggles whether it counts as a grounding source.
- [ ] **4.6 Replace hardcoded `ANALYST_TOOLS` with manifest `identity.accepts_analyst_override`**
  - *Test:* identity injection driven by manifest; a backend not declaring it gets no injection.
- [ ] **4.7 Conformance checklist + probe script** (uses per-backend `/mcp/{name}` mounts — P8 surface).
  - *Test:* probe passes for conformant add-on, fails with actionable output for a broken one.

🔒 **PHASE 4 GATE:** a third party could implement an add-on from the spec + schema alone; gate is declaration-driven and binary; conformance probe green for all four add-ons.

### Phase 5 — Central output cap
- [ ] **5.1 Single output-cap + redaction point in the trust layer** (response guard already = 30 patterns; centralize the size cap).
  - *Why:* consistent token/secret control regardless of backend.
  - *Test:* oversized response capped centrally; secrets redacted; per-backend ad-hoc caps removed.

🔒 **PHASE 5 GATE:** one cap/redaction path; guard tests green.

### Phase 6 — Migrate add-ons to namespaces (MVP DONE)
- [ ] **6.1 Namespace + migrate the four add-ons** following the **§5 migration playbook** (order: rag → windows-triage → opencti → opensearch): `opensearch_*`, `cti_*`, `kb_*`, `wintriage_*`. Give each a `sift-backend.json` manifest. Rename `case_host_fix`→`opensearch_host_fix` (stays in opensearch, F-D).
  - *Test:* each add-on passes the conformance probe (§5 done-condition); full e2e on fresh VM with all four add-ons enabled; full ROCBA regression case.

🔒 **PHASE 6 GATE = MVP COMPLETE:** core self-contained; contract enforced; four add-ons conformant; F-A/F-B verified live; full ROCBA workflow reproduced end-to-end.

### Phase 7 — Methodology → /skills + SDK (POST-MVP, last)
- [ ] **7.1 Build `/skills` endpoint** serving versioned, signed markdown packs as a **downloadable zip following Anthropic's skills standard** (your note @595).
- [ ] **7.2 Move the 14 methodology `get_*` tools' content into skills packs; remove the tools.** Keep the FK **data package** as a core runtime dependency (considerations + grounding still read it). `validate_finding` tool dropped; enforcement stays in `record_finding`.
  - *Test:* methodology no longer costs per-session context as tools; considerations/grounding/validation unchanged; pack downloads + verifies signature.
- [ ] **7.3 Backend SDK / scaffold** so a dev can generate a conformant add-on skeleton.

---

## 7 · Cross-cutting invariants to preserve (check at every gate)
- **R-A (F-A):** no agent `/mcp` tool executes unless `chain_status == OK`. Health/lifecycle/portal are not agent tools and are exempt — by design.
- **R-B (F-B):** the agent (via `run_command` jail) can never read or write `audit/`, the ledger, approvals, or the manifest.
- **R-identity:** the gateway is the only authority that sets examiner identity for write tools.
- **R-roles (operator-drives-portal-only):** strict two-way role separation, enforced in code and required of the standard:
  - Agent tokens are minted **only** by a logged-in examiner in the portal (`routes.py:3029`). The token's audit identity = its **`agent_id`** (machine attribution); the authorizing human is recorded as **`created_by`**.
  - Audit entries the agent writes are stamped with the `agent_id`; **human accountability attaches at portal approval/commit** (DRAFT → examiner HMAC commit), not at agent-write time.
  - The portal **rejects agent tokens** (`case-dashboard/auth.py`); `/mcp` is the **agent-only** surface. The operator never calls `/mcp`; the agent never reaches the portal.
  - The operator's only out-of-portal actions are the one-time `install.sh` and pasting the portal-issued token into the agent config. Everything case/evidence/findings/token-related is portal-only.
- **R-provenance:** a finding with no evidence trail is rejected, not warned.
- **R-no-hardcoded-names:** grounding and the gate decide by *declaration*, never by a hardcoded backend list.
- **R-core-survives:** disabling/killing any add-on never removes a core capability.
- **R-spec-truth:** the HTML/mmd spec matches the code; fix the spec in the same commit that changes behaviour.

---

## 8 · Session Log

> Append newest at the top. Use the §3 template.

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
