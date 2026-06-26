# ORCHESTRATOR — Final Reconciliation Assessment

> **Exercise:** You + 3-agent architecture/docs/code reconciliation.
> **Base commit:** `a7ea369` (local `main`, clean). **Date:** 2026-06-19.
> **Index:** codebase-memory `Users-yk-AI-SIFTHACK-sift-mcps` (15,968 nodes /
> 61,764 edges, `ready`, zero drift since `HEAD~8`).
> **Constraint honored:** documentation/reconciliation/planning only — no product
> code changed, **no Linear issues created or mutated** (all Linear items below are
> *recommendations* for the operator to apply).

---

## 0. Verdict

**Architecture documentation: CLEARED WITH CAVEATS.**

The system's intended architecture (the SPEC) is **structurally accurate** — all
ten load-bearing planes/boundaries were traced into current code and *confirmed in
substance*. There is **no code-blocking contradiction** and **no case where the
code does something the SPEC forbids** (the one apparent exception — OpenCTI
indices — resolved to a *labeling* error, not a behavioral one). What remains is:

- **8 SPEC drift items (M1–M8)** — all *documentation-only* edits (stale labels,
  counts, paths, a removed mount, a missing migration), caused by the SPEC being
  pinned to `156e810` (06-14) while `HEAD` moved to `a7ea369` (06-19).
- **3 install-blueprint target-vs-current mislabels (C1–C3)** — the
  `FINAL-INSTALL-BLUEPRINT` narrates the *target* state as if current; one (C1) is
  **security-relevant**.
- **4 human decisions (H1–H4)** — architect/operator rulings that code cannot settle.

None of these block the package. They are enumerated, evidenced, and actionable
below. The SPEC may be published once the M1–M8 edits land and H1/H2 are ruled.

---

## 0b. Close-out (operator-ratified, 2026-06-19)

- **SPEC M1–M8 edits APPLIED** to `docs/drafts/architecture/sift-architecture-SPEC.md`
  this session (header bumped `156e810`→`a7ea369`; OpenCTI arrow relabeled to the
  isolated add-on cluster; policy chain noted as 11 stages; seccomp/AppArmor posture
  annotated; `/dashboard` removed; `backends/` paths fixed; `evidence_unseal` migration
  appended; `chattr`→`ioctl` reworded; `opensearch_*` list annotated).
- **H2 ACCEPTED** — make blueprint D5 true: I-PS2 removes the `install.sh`
  `$SIFT_CASE_ROOT` purge branch; the **G-9 evidence-preserving-uninstall regression
  lands first** (before any installer refactor).
- **H3 / XYE-85 approach ACCEPTED** — installer modernization proceeds as harden+extend
  (Phases 1–5 first, registry cutover behind the gate checklist); meta-package name
  coordinated with the XYE-7 repo rename.
- **H1** (OpenCTI mirror-vs-isolated intent) remains an architect note; the SPEC now
  reflects current code (isolated by design).
- Reconciliation package + SPEC edits committed and pushed to origin; per-agent
  worktrees/branches removed after consolidation.

---

## 1. Agent outputs received

| Agent | Worktree / branch | Deliverable(s) (now consolidated on `main` under `docs/new-docs/reconciliation/`) |
|---|---|---|
| **Agent 1** — SPEC↔code architecture auditor | `recon-wt/agent1-spec-code` / `recon/agent1-spec-code` | `AGENT1_SPEC_CODE_TRACE.md` (10 planes + 4 extra SPEC sections; 6 confirmed / 4 partial / 3 stale / 1 contradicted-resolved) |
| **Agent 2** — recent-docs/install/CI/packaging/roadmap | `recon-wt/agent2-newdocs-install-ci` / `recon/agent2-newdocs-install-ci` | `AGENT2_RECENT_DOCS_CODE_TRACE.md` + `AGENT2_TESTING_CI_PACKAGING_EXPANSION.md` (15-gate pre-cutover checklist) |
| **Agent 3** — independent contradiction reviewer / signoff gate | `recon-wt/agent3-review-signoff` / `recon/agent3-review-signoff` | `AGENT3_SIGNOFF_REVIEW.md` (16 independent spot-checks; **SIGNED OFF**) |

**Iteration protocol outcome:** Round 1 (A1 ∥ A2) → Round 2 (A3 review) →
**signoff at Round 2, zero contradiction rounds.** A3 raised **0 blocking
revisions** (1 optional sharpening, R-A1.1, applied by A1: the OpenCTI arrow
resolution made definite). Every agent verified each load-bearing claim with a
direct `Read`/`grep` against its worktree, not graph citations alone.

---

## 2. Contradictions found — and how they resolved

A3 independently re-verified 16 highest-risk claims: **14 CONFIRMED, 2 NUANCED, 0
REFUTED.** Both peer reports applied source precedence correctly (code = now, SPEC
= intent, new-docs = roadmap). The full matrices are in the agent files; the
consolidated set:

### 2.1 SPEC ↔ code drift (all *doc-only* fixes, classification = code vs SPEC)

| ID | Drift | Status | Evidence (file:line) |
|---|---|---|---|
| **M1** | SPEC §1/§2/§6/§7 show `CTIMCP → SIFT-OpenSearch` writing `opencti_*` indices. **Resolved:** opencti-mcp is GraphQL-only (8 query `cti_*` tools); `opencti_*` indices are **real but in the add-on's OWN isolated OpenSearch cluster**, which is explicitly forbidden from writing into the SIFT forensic cluster. The arrow is **mislabeled, not fabricated.** | stale/mislabeled (High doc-trust) | `opencti-mcp/.../registry.py:198-212`; `docker-compose.opencti.yml:13-41,110-115` (`sift-opencti-net`, `INDEX_PREFIX=opencti`, "must not write into the native SIFT cluster") |
| **M2** | SPEC "9-stage" policy chain → actually **10 policy middlewares + prepended Catalog = 11**, led by `ControlPlaneRequiredMiddleware` (BU3, absent from §3) | stale (order correct) | `policy_middleware.py:1262-1280`; `mcp_server.py:387-390` |
| **M3** | SPEC §4/§9 state `seccomp=KILL` / `AppArmor=ENFORCE` as flat facts → **code default = seccomp `log` + AppArmor COMPLAIN**; kill/enforce is the install-gated *hardened* posture | partial (posture, not default) | `dfir_exec_launcher.py:475-477`; `harden.sh:6-12,32`; `install.sh:3406-3407` |
| **M4** | SPEC §3 lists `/dashboard` v1 mount "slated removal" → no such mount exists | stale | `server.py` (no `Mount("/dashboard"`) |
| **M5** | SPEC §6 puts `http_backend.py`/`stdio_backend.py` at package root → they live in `backends/` | stale (path) | `sift_gateway/backends/{http,stdio}_backend.py` |
| **M6** | SPEC §8 ends at 20 migrations → disk has **21** (`evidence_unseal`) | stale (tail) | `supabase/migrations/202606160100_evidence_unseal.sql` |
| **M7** | SPEC §4/§9 literal `chattr +i` → code uses in-process `ioctl(FS_IOC_SETFLAGS)` | partial (equivalent) | `evidence_chain.py:726-746` |
| **M8** | SPEC §7 `opensearch_*` list is a 16-name subset → contract exposes more (`*_catalog`, `*_cluster_*`, `_resource`) | stale | `opensearch-mcp/.../registry.py`; regen via `test_opensearch_mcp_surface_snapshot.py` |

**Every other SPEC plane confirmed against code**, notably the strongest-verified
one — **Plane 4 (Postgres-authoritative, no file-mode fallback)**: startup DSN exit
(`__main__.py:112-126`), pre-file-read raise (`case_manager.py:620-665`), and the
in-process `ControlPlaneRequiredMiddleware` backstop (`policy_middleware.py:496-543`)
all re-read verbatim and accurate to the line.

### 2.2 Install-blueprint ↔ code (target narrated as current)

| ID | Contradiction | Classification | Severity | Resolution |
|---|---|---|---|---|
| **C1** | Blueprint **D5** "installer NEVER deletes evidence … not a code path, ever" vs `install.sh --uninstall --purge-data` which DOES (`_purge_tree` `chattr -i` unlock + `rm -rf $SIFT_CASE_ROOT`) | code vs recent docs **+** roadmap mismatch | **High (security)** | D5 is the *target* (= I-PS2 work). **Framing nuance (A3 §3):** reachable only via opt-in `--purge-data` + typed `_confirm_destructive` prompt — **not silent/default**; default `--uninstall` preserves `/cases`. This is design-debt, not a live P1. See **H2**. |
| **C2** | Blueprint **D4** "bump the THREE 0.1.0 packages via hatch-vcs" vs reality: only `sift-core` + `windows-triage` (+ root meta) at `0.1.0`; 7/9 already `0.6.1` **as literals**; **no hatch-vcs anywhere** | packaging/release mismatch | Med | Update D4 to current counts; hatch-vcs single-source + `v0.6.2` tag still TODO (I-PS1) |
| **C3** | Blueprint §2 "thin bootstrap installing published hash-pinned wheels from PyPI" vs current installer = staged checkout + un-pinned `uv sync` (no `--locked`/`--require-hashes`/registry) | packaging/release mismatch | Med | Label §2 TARGET; cutover = Phase 8 / I-PS8 |
| **C4** | `.gitignore:8` still ignores the now-committed `uv.lock` | code vs recent docs | Low | Delete the dead line (I-LOCK chore) |
| **C5** | Doc-promised CI gates absent: `bash -n`/shellcheck, greenfield smoke, npm portal-bundle provenance | missing test/CI proof | Med | → XYE-53 (shell+smoke), XYE-85/I-PS6 (npm provenance) |
| **C6** | No CI assertion of the ENFORCE posture (live-VM-proven only) | missing test/CI proof | Med | Post-install smoke asserting profiles ENFORCE + `SECCOMP_MODE=kill` (XYE-9) |

### 2.3 The single most important *correction to our own brief*

The exercise brief hypothesized "check whether ANY CI exists." **CI exists and is
substantial** — `.github/workflows/ci.yml` gates `uv sync --locked`, Ruff
`F821/F822/F823` + clean-source(3 pkgs), Pyright(gateway), docs-freshness, `pytest`,
and **per-package coverage floors** (`scripts/check_package_coverage.py:28-136`).
**XYE-85 is therefore "harden + extend CI for publish," not greenfield.** This
reframes the entire installer-modernization effort and is the most consequential
single finding for roadmap planning.

---

## 3. Remaining human decisions (cannot be settled from code/docs)

| ID | Decision | Evidence says | Why it's a human call |
|---|---|---|---|
| **H1** | **OpenCTI `opencti_*` arrow intent.** Relabel the SPEC arrow to the isolated add-on datastore, *or* is a future mirror into the SIFT forensic cluster an intended (unbuilt) roadmap item? | "separate by design" (`docker-compose.opencti.yml:4-5,110`) | Architect owns the intended end-state; code only proves *current* isolation |
| **H2** | **C1 evidence-purge: fix vs document.** Remove the `$SIFT_CASE_ROOT` purge branch from `install.sh` (make D5 true — I-PS2), *or* keep an opt-in operator wipe and amend D5 to "never *by default*; `--purge-data` + typed confirm required"? | Path is opt-in + typed-confirm gated, not silent | Security-posture / product ruling. **Recommendation: remove the branch** (a hardened-forensics installer should not carry an evidence-`rm -rf`); operator confirms |
| **H3** | **Meta-package public name vs repo rename.** Published PyPI dist name `sift-mcps` vs a `protocol-sift-*` family, coupled to repo-rename **XYE-7** (`ProtocolSiftGateway`) | Root dist is `sift-mcps` (`pyproject.toml:23`) today | Naming gates I-PS5/I-PS8; must land coherently with XYE-7 so neither strands the other |
| **H4** | **Linear binding for XYE-83 / XYE-84 / XYE-64.** A2 could not bind these to an install/CI/packaging artifact and left them "needs-grooming" | No packaging code artifact binds them at `a7ea369` | Coordinator scope confirmation; XYE-84/64 are OpenSearch-ingest correctness (OT3), outside this exercise's deep coverage |

---

## 4. Recommended next documentation edits

**A. SPEC (`docs/drafts/architecture/sift-architecture-SPEC.md`) — apply M1–M8 (doc-only):**
1. **M1 (do first, High):** Redraw §2 so the `opencti_*` arrow points at the OpenCTI
   add-on's **separate/isolated** OpenSearch (label "external connector /
   `docker-compose.opencti.yml`"); remove `opencti_*` from the §1 *SIFT* data-plane
   indices and the §6/§7 "writes opencti_* to OpenSearch" wording. **Pending H1.**
2. **M2:** §2 `MCPMW` node + §3 sequence — add `ControlPlaneRequired` outermost
   backstop; "9-stage" → "Catalog + 10".
3. **M3:** §4/§9 — annotate seccomp=kill / AppArmor=enforce as the *hardened*
   posture (`--apparmor-enforce` / `harden.sh` / `SIFT_EXECUTE_SECCOMP_MODE=kill`);
   default is log/complain.
4. **M4:** drop the `/dashboard` mount + `legacy_portal_session_enabled` line from §3.
5. **M5:** fix §6 transport paths to `backends/…`.
6. **M6:** append `evidence_unseal` (21st migration) to §8.
7. **M7:** reword `chattr +i` → "FS immutable flag (ioctl FS_IOC_SETFLAGS, ≡ `chattr +i`)".
8. **M8:** regenerate §7 `opensearch_*` list from the golden snapshot.
9. Bump the SPEC header's "code-grounded as of `156e810`" → `a7ea369`.

**B. `FINAL-INSTALL-BLUEPRINT.md` — correct target-vs-current (C1–C4):**
- D4: fix the "three 0.1.0 packages" count (now two + root meta) and note bumps were
  *literals*, hatch-vcs still TODO.
- D5: add an honesty line — *today* `install.sh --purge-data` CAN destroy evidence
  (opt-in + typed-confirm); D5 is the post-I-PS2 target.
- §2: label "published hash-pinned wheels from PyPI" explicitly as TARGET.
- §5 / I-LOCK: re-scope to "delete the dead `.gitignore:8` `uv.lock` line."

**C. Operational note:** these new `docs/new-docs/reconciliation/*.md` files will be
seen by the CI docs-freshness gate (`check_newdocs_refs.py`, `ci.yml:70-71`) if
committed — add the required references (or verify the gate's scope) before commit.

---

## 5. Recommended next Linear work grouping

**Do not create the blueprint's `I-PS1…I-PS8` as new issues.** They are a *phase
breakdown*, and existing OT2 (`XYE-45`) children already cover most of them. Map,
don't duplicate (honoring the no-new-issues + no-duplicates constraints):

- **`XYE-85` = the installer-modernization umbrella** (keep `queue:run-alone`).
  In-capsule: I-PS1 (version coherence/hatch-vcs), I-PS3 (uv pin), I-PS4
  (modularize → `lib/`), I-PS2 (evidence-safe uninstall — **security, see H2**),
  I-PS5 (dist rename, coordinate with **XYE-7**).
- **Bind, don't fork:** asset-pinning (I-PS6 pinning pieces) → **`XYE-49`** (its
  confirmed home for G2/G3/G8/G10); greenfield smoke + shell CI → **`XYE-53`**;
  add-on lifecycle regression (post I-PS7 decouple) → **`XYE-55`**.
- **Sequencing:** Blueprint **Phases 1–5 ship zero distribution change** — land them
  first behind gates G-3/G-4/G-6/G-7/G-9. **Phases 6–8 (registry cutover)** come
  after, gated by G-1/G-2/G-11/G-12/G-15.
- **Coordinator note (`XYE-45`):** record that `XYE-85` (run-alone) sequences ahead
  of its `queue:combine` siblings `XYE-49/53/55/83`; they execute as bound
  sub-streams, not in parallel with the capsule.

---

## 6. Recommended test / CI / packaging expansion path

From `AGENT2_TESTING_CI_PACKAGING_EXPANSION.md` — the **15-gate pre-cutover
checklist** (G-1…G-15). Current standing:

- **Already green (keep):** G-5 (pytest + per-pkg coverage floors), G-6 (ruff +
  pyright).
- **Partial (finish):** G-4 (delete `.gitignore:8`), G-10 (pin RAG/WT `latest`→tag,
  hash the `uv` arch-fallback).
- **To-build, ordered:**
  1. **G-3** single-source version (hatch-vcs) + `v0.6.2` tag.
  2. **G-9** *(security, do before any installer refactor)* regression: `--uninstall`
     **without** `--purge-data` provably preserves `/cases` + immutability; then I-PS2
     removes the purge branch.
  3. **G-7** `bash -n` + shellcheck on `install.sh`/`scripts/*` in CI.
  4. **G-8** greenfield install→`/health`→add-on→uninstall→reinstall smoke
     (`scripts/smoke-install.sh`, fed into the `live-vm.yml` attestation).
  5. **G-14** decouple `setup-addon.sh` from sourcing all of `install.sh`
     (`setup-addon.sh:54`) + lifecycle regression.
  6. **G-13** portal Vite bundle built in CI (`npm ci && npm run build`) + provenance.
  7. **G-1/G-2** buildable meta + all-9-wheel build job.
  8. **G-12** install-time Python hash-pinning (`--require-hashes`/`--locked`).
  9. **G-11** install-from-published-wheel job (clean venv, import each entrypoint).
  10. **G-15** PyPI trusted-publishing (OIDC) release workflow on tag.
- **Test matrix:** add Python **3.10 + 3.12** (VM target is 3.12) to the current
  single 3.11 job.

---

## 7. Linear action table (recommendations only — nothing was mutated)

| Issue | Current status | Recommendation | Proof needed | Action |
|---|---|---|---|---|
| **XYE-85** Modernize installer → public PyPI | Backlog, p2, parent OT2/XYE-45, `agent-ready` `queue:run-alone` | **Keep as umbrella; reframe greenfield→harden+extend.** Bind blueprint phases to existing XYE-49/53/55; don't create I-PS* issues | 15-gate checklist; esp. G-3, G-9 (security), G-7, G-8, G-11, G-12 | **Comment** the 3 corrections (CI-exists; D5 false today; version-state) + sequencing note; **move Backlog→Todo** when scheduled. **Do not close** (capsule unbuilt) |
| **XYE-70** Code-hygiene sweep (D2+D3) | Backlog, p3, parent OT4/XYE-47, `component:core` `queue:run-alone` | **Keep; consider splitting D2 from D3.** Census: **444** broad-except handlers / **81** files; **324** ticket-code refs (test-heavy). ADR target = codebase-memory `manage_adr` | Audited subset of broad-excepts narrowed/justified; ticket-codes migrated to ADR prose; tests green | **Comment** the census + ADR-tool pointer; keep run-alone. **Do not close** (real, sizable work) |
| **XYE-83** Installer + tool-catalog hygiene | Backlog, p2, parent XYE-45, `agent-ready` `queue:combine` | **Keep; clarify it is NOT absorbed by XYE-85 packaging.** Distinct scope = tool-catalog/allowlist accuracy (follow-up to XYE-80/81), not wheels | Live-VM catalog-vs-allowlist proof | **Comment** the non-overlap clarification; keep agent-ready |
| **XYE-49** F2: install + download integrity manifest | Backlog, p2, parent XYE-45, `agent-ready` `queue:combine` | **Keep — confirmed home for asset-pinning.** Reconciliation confirms G2/G3/G8/G10 with file:line; manifest must cover the **runtime** RAG-feed surface (G10), not just install-time | Manifest of every artifact (url/version/hash/failure); `latest`→tag; `uv` fallback hashed | **Comment** the confirmed G-gap evidence; sequence under XYE-85 |
| **XYE-53** I2: greenfield install/uninstall smoke harness | Backlog, p3, parent XYE-45, `agent-ready` `queue:combine` | **Keep — confirmed no automated smoke exists** (`live-vm.yml` = manual attestation). Home for G-7/G-8/G-9 | `scripts/smoke-install.sh` + `bash -n`/shellcheck CI green; G-9 evidence-preserving uninstall test | **Comment**; sequence under XYE-85 |
| **XYE-55** I4: service/add-on lifecycle regression | Backlog, p3, parent XYE-45, `agent-ready` `queue:combine` | **Keep — confirmed no lifecycle suite.** Home for G-14 after I-PS7 decouple | Regression exercising `setup-addon.sh` against `lib/` in isolation | **Comment**; sequence under XYE-85 |
| **XYE-84** parse_srum/parse_prefetch `_id` collision | Backlog, p3, parent OT3/XYE-46, `agent-ready` `queue:combine` | **Keep as-is — out of this exercise's deep scope** (OpenSearch ingest correctness). Already groomed w/ file:line in body | `table_name`-disambiguated `_id` dedup test | **No change**; H4 note (coordinator confirms binding) |
| **XYE-64** G4: force re-ingest idempotency tests | Backlog, p3, parent OT3/XYE-46, `agent-ready` | **Keep as-is — out of deep scope.** Groomed | Mixed pre/post-`vhir`→`sift` re-ingest regression | **No change**; H4 note |
| **XYE-45 / XYE-47** OT2 / OT4 coordinators | Backlog | **Keep.** OT2: record XYE-85 sequences ahead of its combine-children | n/a | **Comment** sequencing on XYE-45 |
| **XYE-7** (ref) repo rename | Backlog | **Keep — gates H3.** Naming must land coherently with I-PS5/I-PS8 | n/a | Note coupling in XYE-85 |
| **XYE-48** (ref) network-fetch inventory | — | **Keep.** `FINAL-ASSET-INVENTORY` IS this inventory; ready to attach | n/a | Note in XYE-49 |

**Nothing is recommended for `Done`** — every primary/secondary issue is unbuilt or
partially-built; the reconciliation produces evidence and scoping, not completion
proof.

---

## 8. Package status

**CLEARED WITH CAVEATS.** The reconciliation package is internally consistent
(Agent 3 signed off, 0 blocking revisions) and implementation-grounded (every claim
file:line-cited at `a7ea369`). To move from "cleared with caveats" to "cleared":
apply the M1–M8 SPEC edits (§4), correct the blueprint target-vs-current language
(C1–C4), and obtain the H1/H2 rulings. No code change is required to make the
*documentation* truthful; the H2 (evidence-purge) and C6 (enforce-posture) items are
the only ones that imply *code/CI* follow-up, both already tracked
(XYE-85/I-PS2, XYE-9).

### Package contents (`docs/new-docs/reconciliation/`)
- `AGENT1_SPEC_CODE_TRACE.md` — SPEC↔code, 10 planes + 4 sections, ledger M1–M8.
- `AGENT2_RECENT_DOCS_CODE_TRACE.md` — recent-docs↔code, ledger C1–C4.
- `AGENT2_TESTING_CI_PACKAGING_EXPANSION.md` — current+target CI/packaging, G-1…G-15.
- `AGENT3_SIGNOFF_REVIEW.md` — 16 independent spot-checks, matrix, signoff.
- `ORCHESTRATOR_FINAL_ASSESSMENT.md` — this file.
