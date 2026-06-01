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
| D1 | Rename `agentir_core` → `sift_core`; env/path surface `AGENTIR_*` → `SIFT_*`, `/var/lib/agentir` → `/var/lib/sift`; service-token prefix `agentir_svc_*` → `sift_svc_*`. **No back-compat** — fresh VM + fresh case, so do a clean cutover (no shim, no symlink, no dual-name config). | spec §6 + fork 2026-06-01 |
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

- [ ] Provision a fresh SIFT VM (Ubuntu 24.04, Python 3.12, Docker).
- [ ] Run the (renamed) `install.sh` from scratch on it — this is the *only* environment that validates the `agentir→sift` path migration + first-run registration cleanly.
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
Kills nothing yet; unblocks everything. Mechanical but wide (~141 `AGENTIR_CASE_DIR`, ~55 `/cases` literals). **Clean cutover — no back-compat** (fresh VM + fresh case): remove `agentir`/`AGENTIR_*`/`agentir_svc_*` entirely, don't dual-name anything.

- [x] **0.1 Rename Python package `agentir_core` → `sift_core`** ✅ Session 3
  - *How:* rename dir + `pyproject` name; update all imports. **Delete** the old name — no shim module.
  - *Why:* single core identity; the package is already the de-facto core.
  - *Test:* full suite imports clean under `sift_core`; `grep -r agentir_core` returns nothing in source.
  - *Done:* `git mv packages/agentir-core → packages/sift-core`, `src/agentir_core → src/sift_core`; dist name `agentir-core`→`sift-core` (own pyproject + 4 dependents + root workspace source/extra); all `.py` + `install.sh` swept (0 `agentir_core` in source); `uv sync --extra full` regenerated editable installs; per-package suites match baseline exactly (sift-core 225, case-dashboard 274, sift-gateway 104, case-mcp 23, opensearch 973+71skip, sift-mcp 4, report 31, forensic 20, win-triage 11). AGENTS.md code refs updated; docs module refs updated (paths `/var/lib/agentir` + `agentir_core_write` audit key + `configs/audit/99-agentir-evidence.rules` left for 0.2/0.3). `agentir.plugins` entry-point group + `opensearch_mcp.agentir_plugin` left for 0.3 (not `agentir_core`).
- [~] **0.2 Rename env/path surface `AGENTIR_*`→`SIFT_*`, `/var/lib/agentir`→`/var/lib/sift`** — RENAME DONE (Session 3); `/cases` single-resolver consolidation **deferred** (see below)
  - *How:* central config reader uses **only** the `SIFT_*` names (no fallback, no symlink). Audit the ~55 bare `/cases` literals — route them all through one path-resolution function.
  - *Why:* one config source that path-resolution, the gate, `run_command` cwd, and the portal all read (prereq for F-B and customizable paths).
  - *Test:* boot with `SIFT_*` set; `grep -r 'AGENTIR_\|/var/lib/agentir'` returns nothing in source; no bare `/cases` literal escapes the resolver (grep returns only the resolver).
  - *DONE this session:* all 41 `AGENTIR_*` env vars → `SIFT_*` (442 occ.), `/var/lib/agentir` → `/var/lib/sift`, and config home `~/.agentir` → `~/.sift` — across **all** `.py`/tests, `install.sh`, `configs/*` (incl. the two `.template` files `gateway.yaml.template` + `apparmor/sift-gateway.template`, easy to miss — they're rendered with `${SIFT_*}` so leaving `${AGENTIR_*}` would break first-run), docs, AGENTS.md, and `frontend/src`. `grep -rE 'AGENTIR_|/var/lib/agentir'` over source/config = **0**. install.sh `bash -n` clean; `SIFT_HOME=$HOME/.sift` / `SIFT_STATE_DIR=/var/lib/sift` consistent with code. All per-package suites unchanged (same counts as Phase 0.1).
  - *STILL TODO (the `/cases` resolver — the box's 3rd test clause):* cases-root resolution is **scattered & inconsistent** — `sift_core/case_io.get_case_dir` uses `SIFT_CASES_DIR`→`~/cases`; `sift_core/case_ops.case_list_data` uses `SIFT_CASES_ROOT`→`SIFT_CASES_DIR`→`~/cases`; `opensearch_mcp/ingest_cli` uses `SIFT_CASES_DIR`→`~/cases`; `case_dashboard/routes.py:3460` uses `SIFT_CASES_ROOT`→`"/cases"`. Need **one** `sift_core` resolver (e.g. `cases_root()`) with a single env precedence that all of these call. Separately, hardcoded `/cases` allow-roots in `sift-mcp/security.py:98` + `opensearch_mcp/server.py:686` are **defense-in-depth allow-lists** (alongside `/mnt`,`/media`,`/evidence`,`/tmp`,`~/`) — decide whether to source their cases-root from the resolver or leave them as intentional per-package belts. Docstring `/cases/{case}/evidence/` examples (forensic server.py:607/614) are illustrative text, not paths. **Not ticked** until the resolver lands and `grep /cases` over source returns only the resolver + intentional allow-lists.
  - *NOTE:* `agentir_svc_*`/`agentir_gw_*` token prefixes → **0.4**; `_agentir_context` warning key → **Phase 4** (removed with the readOnlyHint carve-out); product-name strings in `instructions.py`/docstrings, opensearch identifiers (`agentir-geoip`, `agentir-evtx-ecs`, `agentir-opensearch`), `agentir_plugin` module, `agentir_home()` fn, config filenames (`99-agentir-evidence.rules`, `agentir-cases.conf`), and the `agentir_core_write` audit key → **0.3**.
- [ ] **0.3 Rename `agentir-opensearch`→`sift-opensearch` and any other `agentir-*` service/identifier surface.**
  - *Test:* service starts; role names resolve; no `agentir-` identifier remains.
- [ ] **0.4 Rename service-token prefix `agentir_svc_*` → `sift_svc_*`**
  - *How:* update `generate_service_token()` and the portal token-mgmt UI/labels. Tokens are minted fresh on the new VM, so **no back-compat for existing tokens** — old tokens simply won't exist.
  - *Why:* consistent `sift` identity on the one artifact that crosses from operator (portal) to agent.
  - *Test:* portal mints a `sift_svc_*` token; agent authenticates with it; `grep -r agentir_svc` returns nothing in source.

🔒 **PHASE 0 GATE:** full suite green on `revamp/spg-v1`; gateway boots on the fresh VM via renamed `install.sh`; **zero `agentir`/`AGENTIR_` references remain in source** (`grep -ri agentir packages/` is clean except historical changelog/docs).

### Phase 1 — Consolidate core library (kills P2) + relocate integrity records (F-B)
Move duplicated case logic out of `forensic-mcp`/`case-mcp`/`report-mcp` into `sift_core`, and move integrity records outside the agent jail while the code is already being touched.

- [ ] **1.1 Move findings/timeline/TODO/evidence-listing logic into `sift_core`**
  - *How:* `sift_core` becomes the single owner of `record_finding`, `record_timeline_event`, `manage_todo`, `list_existing_findings`, evidence listing. The backends call into it; no parallel implementations remain.
  - *Why:* P2 duplication is the interoperability hazard the revamp exists to kill.
  - *Test:* one implementation per operation (grep); existing finding/timeline tests pass against the consolidated path.
- [ ] **1.2 Move finding-time CORE-LOGIC into `sift_core`: validation, provenance classification, grounding, considerations**
  - *How:* relocate `_classify_provenance`, `_score_grounding`/`_grounding_result`, `_build_finding_considerations`, and the `VALIDATION_FAILED` enforcement. Keep FK data package as a dependency.
  - *Why:* this logic must live in core so every backend (and the agent) gets identical enforcement; it's not an add-on concern.
  - *Test:* finding rejected on `provenance==NONE`; considerations attached; grounding returns `{}` with no reference backends.
- [ ] **1.3 Make grounding declaration-driven (remove hardcoded `_GROUNDING_MCPS`)**
  - *How:* replace the `(forensic-rag-mcp, windows-triage-mcp, opencti-mcp)` tuple with "backends whose manifest declares `capabilities.provides: ["reference"]`." (Manifest schema lands in Phase 4; here, stub the lookup behind an interface so Phase 4 just fills it.)
  - *Why:* zero hardcoded backend names — community reference backends must count automatically.
  - *Test:* with a fake manifest declaring `provides:["reference"]`, grounding counts it; with none, grounding is inert.
- [ ] **1.4 Relocate integrity records to `/var/lib/sift/<case_id>/` (F-B)**
  - *How:* `audit/`, `approvals.jsonl`, `evidence-ledger.jsonl`, manifest move outside `case_root`; update `audit_ops`, `evidence_chain`, `case_io._CASE_SUBDIRS`, `_classify_provenance`, `_score_grounding`, and the gate to read the new location. `evidence/extractions/reports/agent` stay under `case_root`. Confirm `run_command`'s jail cannot reach the new path.
  - *Why:* tamper-resistance — the agent must not be able to delete/alter its own audit trail or the custody ledger. This is the core security pitch.
  - *Test:* `run_command` with `cwd` traversal cannot read/write the records dir; provenance/grounding still resolve audit_ids from the new path; chain status still computes.
- [ ] **1.5 Confirm `case_host_fix` stays in `opensearch-mcp` (F-D) — no core move.**
  - *Test:* no `case_host_fix` reference in `sift_core`/gateway core tools.

🔒 **PHASE 1 GATE:** single implementation of each case operation; integrity records under `/var/lib/sift`; agent jail proven unable to reach them; suite green.

### Phase 2 — In-process core tools (kills P1)
Register the ~25 core tools *in-process* in the gateway instead of as stdio subprocesses.

- [ ] **2.1 Register core tools in-process** (execute, case mgmt, evidence/CoC, findings/timeline/TODO, audit/reasoning/external-action).
  - *How:* gateway exposes `sift_core` operations directly; retire `forensic-mcp`/`case-mcp`/`report-mcp` as separate subprocesses for the core slice.
  - *Why:* P1 — a core capability must not silently vanish because a subprocess failed to boot.
  - *Test:* with **all** add-on backends disabled, `tools/list` still shows the full core tool set; killing any add-on doesn't remove a core tool.
- [ ] **2.2 Remove `export_bundle`/`import_bundle` from the agent surface (F-C); keep `sift_core` functions.**
  - *Test:* tools not in `tools/list`; `sift_core.export_bundle` still unit-tested.
- [ ] **2.3 Make `set_case_metadata` + report generation portal-owned (F-E); remove from agent surface.**
  - *How:* move metadata-set + `generate_report` triggers to the portal; agent no longer calls them.
  - *Test:* tools absent from agent `tools/list`; portal can set metadata and generate a signed report.

🔒 **PHASE 2 GATE:** core tools present with zero add-ons; live VM e2e (seal → agent finding loop) works against in-process core.

### Phase 3 — Sandbox + privilege executor (D2 + D3)
- [ ] **3.1 Relocate denylist `security.yaml` → operator-editable `gateway.yaml` + non-weakenable deny floor**
  - *How:* load order = hardcoded deny floor ∪ operator denylist; refuse to start on empty policy (preserve current behaviour); deny floor cannot be removed by config.
  - *Why:* D2 — operator can tighten, never weaken below the floor (mkfs*, shutdown/reboot/halt/init, kill*, env/printenv token-leak, raw sockets).
  - *Test:* operator config can't delete a floor entry; empty policy refuses boot; denied command blocked end-to-end.
- [ ] **3.2 Optional allowlist mode** — config flag flips denylist→allowlist.
  - *Test:* in allowlist mode, only listed commands run; everything else blocked.
- [ ] **3.3 Hardened isolated executor** (separate process · cgroup · AppArmor · `shell=False` · path jail).
  - *Why:* P6 — contain blast radius distinct from other backends.
  - *Test:* executor runs unprivileged; cannot escape the case jail; resource limits enforced.
- [ ] **3.4 Privileged path: capabilities-first → sudoers-allowlist fallback (D3)**
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

### Session 3 — 2026-06-01 — Phase 0.1 (package rename) + 0.2 env/path rename
- Branch/commit: `revamp/spg-v1` @ `cf69e97` — chain: `cc9765e` (stale-doc cleanup) → `4890f75` (0.1 rename) → `48ab494` (tracker SHA) → `cf69e97`.
- Phase: 0 — tasks touched: **0.1** (done, ticked), **0.2** (env/path rename done; `/cases` resolver deferred — box marked `[~]`).
- DONE (boxes ticked): **0.1**. **0.2 rename portion** complete but box left `[~]` (not fully ticked — `/cases` single-resolver clause outstanding).
- 0.1: `git mv` package `agentir-core`→`sift-core`, `agentir_core`→`sift_core`; dist name + 4 dependents + root workspace; swept all `.py` + install.sh; docs/AGENTS module refs.
- 0.2: `AGENTIR_*`→`SIFT_*` (41 vars/442 occ), `/var/lib/agentir`→`/var/lib/sift`, `~/.agentir`→`~/.sift` across all py/tests/install.sh/configs (incl. 2 `.template` files)/docs/frontend src. `grep -rE 'AGENTIR_|/var/lib/agentir'` over source/config = 0. **`/cases` single-resolver consolidation deferred** (scattered cases-root logic — details under task 0.2 "STILL TODO").
- Tests: per-package, re-run after each rename — **identical counts, all green** every time: sift-core 225 · case-dashboard 274 · sift-gateway 104 · case-mcp 23 · opensearch 973 (+71 skip) · sift-mcp 4 · report 31 · forensic 20 · win-triage 11. Command: `uv run python -m pytest packages/<pkg>/ -q` (whole-suite from root fails on duplicate test basenames — pre-existing; run per-package).
- Live test on VM: none (fresh VM still not provisioned — open §2 item).
- Spec changed?: `revamp-plan.html` NOT touched (it documents the rename intentionally — `ux-tasks.md` also still has one `AGENTIR_CASE_DIR` ref, left as a different project's historical doc). Docs/AGENTS updated for both renames.
- Gotchas (now also in §4): (1) `uv sync` **without** `--extra full` prunes the venv to dev-only and deletes all workspace editable installs → always `uv sync --extra full`. (2) The two `configs/*.template` files are NOT matched by `--include='*.yaml'` etc. — must rename env vars in them explicitly or first-run rendering breaks. (3) The portal **built bundle** `packages/case-dashboard/src/case_dashboard/static/v2/assets/index-*.js` is a generated artifact that still contains old `AGENTIR_*` strings — needs a **frontend rebuild** on the VM (source `frontend/src` is already fixed).
- Deferred (tracked under tasks 0.2 NOTE / 0.3 / 0.4 / Phase 4 so nothing is lost): token prefixes `agentir_svc_*`/`agentir_gw_*` → 0.4; `_agentir_context` → Phase 4; opensearch identifiers + `agentir_plugin` module + `agentir_home()` fn + config filenames + `agentir_core_write` audit key + product-name strings → 0.3.
- BLOCKERS: none.
- NEXT: finish **0.2** — build the single `sift_core` cases-root resolver and route the scattered call-sites through it (see task 0.2 "STILL TODO"), then tick 0.2. Then **0.3** (service/identifier surface) and **0.4** (token prefix).

### Session 2 — 2026-06-01 — Repo setup + spec cleanup + tracker expansion
- Branch/commit: `revamp/spg-v1` @ `b1593a2` (planning artifacts committed; `pre-revamp-v0` tagged at `main` 0c260ff; worktree at `../sift-mcps-main`).
- Phase: pre-0 (repo setup done; Phase 0 deferred to next session per owner).
- DONE: §2 repo setup boxes (commit, tag, branch, worktree). Locked forks **F-E** (set_case_metadata + reporting → portal-owned) and **no-back-compat** (clean cutover, fresh VM/case) + token-prefix rename `agentir_svc_*`→`sift_svc_*`. Cleaned `revamp-plan.html`: stripped all 29 `##NOTE##` markers (42 verified edits) and fixed deviations to match F-A..F-E (binary evidence gate §4.2, case_host_fix stays opensearch, grounding graceful-degradation note, audit relocation §8, R9 revised + R12/R13 added). Added tracker "What we're doing" mission + §5 add-on migration playbook; renumbered Phases/Invariants/Log → §6/§7/§8.
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
