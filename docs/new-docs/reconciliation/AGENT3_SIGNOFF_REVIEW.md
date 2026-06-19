# AGENT 3 — Independent Signoff Review

**Role.** Independent contradiction reviewer and signoff gate for the 3-agent
documentation-reconciliation team. I do not re-author the peer reports; I
independently re-verify their highest-risk claims against current source,
classify each contradiction, and either pass correct findings through
(VALID-FINDING) or bounce wrong/overclaimed ones back (NEEDS-REVISION).

**Base commit.** `a7ea369` (worktree `/Users/yk/AI/SIFTHACK/recon-wt/agent3-review-signoff`,
same commit as the indexed main repo and both peer worktrees).

**Inputs reviewed (read-only).**
- Agent 1: `…/agent1-spec-code/docs/new-docs/reconciliation/AGENT1_SPEC_CODE_TRACE.md`
- Agent 2a: `…/agent2-newdocs-install-ci/docs/new-docs/reconciliation/AGENT2_RECENT_DOCS_CODE_TRACE.md`
- Agent 2b: `…/agent2-newdocs-install-ci/docs/new-docs/reconciliation/AGENT2_TESTING_CI_PACKAGING_EXPANSION.md`

**Method.** codebase-memory MCP index `Users-yk-AI-SIFTHACK-sift-mcps`
(15,968 nodes / 61,764 edges, status `ready`) for routing; **every** verdict
below is backed by my OWN `Read`/`grep` in this worktree — I did not trust peer
citations blindly. Citations are relative paths against the worktree (= same
commit as indexed main). All file:line references were opened directly.

**Claims I independently re-verified (with my own file:line):**
OpenCTI tool surface + the out-of-repo connector question (the caveat A1 left
open); the 10-middleware policy chain + catalog prepend; seccomp default + the
AppArmor COMPLAIN→ENFORCE flip; `install.sh` evidence-purge path; Blueprint D5
language; all 9 package versions + hatch-vcs absence; the install `uv sync`
flow; the full `ci.yml` gate set + per-package coverage floors; `/dashboard`
mount absence; the 21st migration; the `.gitignore` uv.lock residual; the
evidence-immutability `ioctl` vs `chattr` mechanism; the `backends/` path drift;
root `package=false` build config.

---

## 1. Spot-Check Results

| # | Claim (peer) | Peer | My verdict | My evidence (file:line, this worktree) | Label |
|---|---|---|---|---|---|
| S1 | opencti-mcp exposes ONLY 8 query-only `cti_*` tools (no `opencti_*` tools) | A1 #1 | **CONFIRMED** | `packages/opencti-mcp/src/opencti_mcp/registry.py:198-212` — `TOOL_CATALOG_META` = exactly `cti_get_health, cti_search_threat_intel, cti_search_entity, cti_lookup_ioc, cti_get_recent_indicators, cti_get_entity, cti_get_relationships, cti_search_reports` | VALID-FINDING |
| S2 | No repo code writes `opencti_*` indices into the SIFT forensic OpenSearch | A1 #1 | **NUANCED** (true for the SIFT cluster; an out-of-repo connector DOES write `opencti_*` — to a *separate* datastore) | `docker-compose.opencti.yml:13-41,110-115` — the add-on runs its OWN `opencti-opensearch` service on isolated net `sift-opencti-net`, `ELASTICSEARCH__INDEX_PREFIX=opencti`; comment `:4-5` + `:110` "must not write OpenCTI platform indices into the native SIFT forensic OpenSearch cluster / isolated datastore, not the SIFT evidence cluster"; connectors `docker-compose.opencti-connectors.yml:9-41` feed the OpenCTI platform, not OpenSearch directly | VALID-FINDING (resolves A1's open caveat — see §4 R-A1.1) |
| S3 | Policy chain = 10 policy middlewares led by `ControlPlaneRequiredMiddleware`; +Catalog = 11 served stages | A1 #2 | **CONFIRMED** | `policy_middleware.py:1262-1280` returns exactly `[ControlPlaneRequired, ToolAuthorization, AddonAuthority, CaseContext, AuditEnvelope, ProxyActiveCase, EvidenceGate, ResponseGuard, OpenSearchJobDispatch]` (10); `mcp_server.py:387-390` prepends `GatewayToolCatalogMiddleware` ⇒ 11 | VALID-FINDING |
| S4 | seccomp default = `log` (KILL only when mode=="kill"); AppArmor installs COMPLAIN, flips ENFORCE via harden.sh | A1 #3 | **CONFIRMED** | `dfir_exec_launcher.py:475-477` `_seccomp_action` → `SECCOMP_RET_KILL_PROCESS` iff `seccomp_mode`/`SIFT_EXECUTE_SECCOMP_MODE=="kill"` else `SECCOMP_RET_LOG`; `harden.sh:6-12,32` "install.sh provisions … in COMPLAIN mode by default … flips the two SIFT profiles to enforce"; `install.sh:3406-3407` `SIFT_APPARMOR_ENFORCE` defaults 0 | VALID-FINDING |
| S5 | `/dashboard` v1 mount removed (SPEC §3 stale) | A1 #4 | **CONFIRMED** | `grep -n 'Mount("/dashboard"\|create_dashboard_v1\|/dashboard' packages/sift-gateway/src/sift_gateway/server.py` → no matches (exit 1) | VALID-FINDING |
| S6 | `http_backend.py`/`stdio_backend.py` live in `backends/`, not package root (SPEC §6 path drift) | A1 §6 | **CONFIRMED** | `packages/sift-gateway/src/sift_gateway/backends/http_backend.py`, `…/backends/stdio_backend.py` (root has neither) | VALID-FINDING |
| S7 | 21st migration `evidence_unseal` added after SPEC's 20 | A1 §8 / #7 | **CONFIRMED** | `supabase/migrations/` has 21 `.sql`; tail = `202606160100_evidence_unseal.sql` (preceded by `…_opensearch_worker_status.sql`) | VALID-FINDING |
| S8 | Evidence immutability uses in-process `ioctl(FS_IOC_SETFLAGS)`, not the `chattr` binary | A1 #8 | **CONFIRMED** | `evidence_chain.py:726-746` `_FS_IMMUTABLE_FL=0x10`, `_set_immutable` via `fcntl.ioctl(..., _FS_IOC_SETFLAGS, …)`; docstring `:826` "set FS_IMMUTABLE_FL via the in-process ioctl helper" | VALID-FINDING |
| S9 | CI EXISTS and is substantial — `ci.yml` gates Ruff F821/F822/F823, clean-source(3 pkgs), pyright(gateway), docs-freshness, pytest, per-pkg coverage floors; reframes XYE-85 from greenfield to harden+extend | A2 §0 | **CONFIRMED** | `.github/workflows/ci.yml:47-51` `uv sync --locked …`; `:53-58` Ruff `F821,F822,F823`; `:60-65` Ruff clean-source case-dashboard/forensic-knowledge/sift-common; `:67-68` `pyright -p pyrightconfig.json`; `:70-71` `check_newdocs_refs.py`; `:73-81` `pytest tests` + `check_package_coverage.py` | VALID-FINDING |
| S10 | Per-package coverage gate with floors, fails CI on miss | A2b §1.4 | **CONFIRMED** | `scripts/check_package_coverage.py` `PACKAGE_GATES` — forensic-knowledge 72/70, sift-common 4/3, sift-core 62/60, sift-gateway 59/57, opensearch 52/50, case-dashboard 45/43, forensic-rag-mcp 21/19 | VALID-FINDING |
| S11 | **C1 (SECURITY):** `install.sh --uninstall --purge-data` actively unlocks immutability + `rm -rf $SIFT_CASE_ROOT` (deletes evidence) | A2 C1 | **CONFIRMED** | `install.sh:3341-3355` `_purge_tree` → `chattr -R -f -i`/`-a` then `rm -rf`; `:3357-3368` `purge_data` calls it on `$SIFT_CASE_ROOT`, logs "EVIDENCE deleted (immutable flags cleared first)"; gated by `_confirm_destructive` `:3359` + opt-in `--purge-data` `:3415` | VALID-FINDING (framing nuanced — see §3 C1) |
| S12 | Blueprint D5 = "Installer NEVER deletes case evidence — by design … not an installer code path, ever" | A2 C1 | **CONFIRMED** | `docs/new-docs/install-nextgen/FINAL-INSTALL-BLUEPRINT.md:19` verbatim; `:74` PS2 "installer can never delete evidence; do not forward evidence-unlock flags"; `:101` I-PS2 (security) | VALID-FINDING |
| S13 | **C2:** root meta + sift-core + windows-triage still `0.1.0`; other 6 at `0.6.1`; no hatch-vcs | A2 C2 | **CONFIRMED** | root `pyproject.toml:24` `0.1.0`; `packages/sift-core/pyproject.toml`=`0.1.0`; `packages/windows-triage-mcp/pyproject.toml`=`0.1.0`; case-dashboard/forensic-knowledge/rag/opencti/opensearch/sift-common/sift-gateway = `0.6.1` (7 pkgs); grep `hatch-vcs\|dynamic` across all pyproject → none | VALID-FINDING |
| S14 | **C3:** installer stages checkout + `uv sync --extra full` with NO `--locked`, NO `--require-hashes`, no registry | A2 C3 | **CONFIRMED** | `install.sh:197-228` `stage_repo_to_install_root` rsync; `:508-513` `uv sync --extra "$sync_extra" --project "$REPO_DIR" --no-managed-python --no-python-downloads` (no `--locked`/`--require-hashes`) | VALID-FINDING |
| S15 | `uv.lock` is committed/tracked, but `.gitignore:8` still lists it (latent foot-gun) | A2 §1.3 / §5 | **CONFIRMED** | `git ls-files uv.lock` → `uv.lock` (tracked); `.gitignore:8` = `uv.lock` | VALID-FINDING |
| S16 | Root `package=false`, empty wheel target (meta builds no wheel today) | A2 D2 / §1.1 | **CONFIRMED** | `pyproject.toml:5` `package = false`; `:70-71` `[tool.hatch.build.targets.wheel] packages = []`; extras `core/standard/full` present `:31-52`; MIT `:27`, requires-python `>=3.10` `:26` | VALID-FINDING |

**Tally: 16 spot-checks — 14 CONFIRMED, 0 REFUTED, 2 NUANCED** (S2 OpenCTI
out-of-repo connector resolution; S11 C1 security-framing precision). Both
NUANCED items remain VALID-FINDINGs — the nuance sharpens the recommended
resolution, it does not invalidate the peer's core claim.

---

## 2. Contradiction Matrix

Each contradiction classified as exactly one of: {code vs SPEC | code vs recent
docs | SPEC vs recent docs | roadmap/Linear mismatch | missing test/CI proof |
packaging/release mismatch}.

| ID | Contradiction | Classification | Severity | Recommended resolution |
|---|---|---|---|---|
| **M1** | SPEC draws `CTIMCP → SIFT-OpenSearch` writing `opencti_*` indices; reality: opencti-mcp is GraphQL-only (8 `cti_*` query tools), and `opencti_*` indices exist ONLY in the add-on's **own isolated** `opencti-opensearch` cluster | **code vs SPEC** | High (doc-trust; an AI/diagram consumer will model a data flow that does not exist) | Redraw SPEC §2: the `opencti_*` arrow does NOT point at the SIFT forensic cluster. Relabel as the OpenCTI add-on's **separate datastore** (external connector / `docker-compose.opencti.yml`), and remove `opencti_*` from the §1 *SIFT* data-plane indices and the §6/§7 "writes opencti_* to OpenSearch" / tool-naming. **Do NOT simply delete** — the indices are real, just out-of-cluster. Doc fix only; no code change. |
| **M2** | SPEC "9-stage" policy chain vs 10 policy middlewares (led by `ControlPlaneRequiredMiddleware`) + prepended Catalog = 11 served stages | **code vs SPEC** | Low (order correct; count + BU3 backstop stale) | Update SPEC §2 `MCPMW` node + §3 sequence diagram: add `ControlPlaneRequired` as the outermost backstop; correct "9" → "Catalog + 10". |
| **M3** | SPEC §4/§9 state "seccomp = KILL" / "AppArmor=ENFORCE" as flat facts; code default = seccomp `log` + AppArmor COMPLAIN (kill/enforce are the install-gated hardened posture) | **code vs SPEC** | Low–Med (mechanisms present; posture is opt-in) | Annotate SPEC §4 that kill/enforce is the *hardened/deployed* posture (live-proven RUN-3), selected by `./install.sh --apparmor-enforce` / `harden.sh` / `SIFT_EXECUTE_SECCOMP_MODE=kill`; code default is log/complain. |
| **M4** | SPEC §3 lists a `/dashboard` v1 mount "slated removal"; no such mount exists | **code vs SPEC** | Low | Delete the `/dashboard` mount line + `legacy_portal_session_enabled` plane reference from SPEC §3. |
| **M5** | SPEC §6 paths `http_backend.py`/`stdio_backend.py` at package root; actually in `backends/` | **code vs SPEC** | Low | Fix SPEC §6 paths to `backends/…`. |
| **M6** | SPEC §8 ends at 20 migrations (`opensearch_worker_status`); disk has 21 (`evidence_unseal`) | **code vs SPEC** | Low | Append `evidence_unseal` to SPEC §8. |
| **M7** | SPEC §4/§9 literal `chattr +i`; code uses in-process `ioctl(FS_IOC_SETFLAGS)` | **code vs SPEC** | Low (semantically equivalent) | Reword to "FS immutable flag (ioctl FS_IOC_SETFLAGS, equivalent to `chattr +i`)". |
| **M8** | SPEC §7 `opensearch_*` tool list is a 16-name subset; typed contract exposes more (`*_catalog`, `*_cluster_*`, `_resource` variants) | **code vs SPEC** | Low | Regenerate SPEC §7 from the golden surface snapshot (`test_opensearch_mcp_surface_snapshot.py`). |
| **C1** | Blueprint D5 "installer NEVER deletes evidence … not a code path, ever" vs `install.sh --purge-data` which DOES (`_purge_tree`+`$SIFT_CASE_ROOT`) | **code vs recent docs** (primary) + **roadmap/Linear mismatch** (D5/I-PS2 is the unbuilt target) | **High** (security-relevant — stated design invariant is violated by current code) | D5 is the TARGET (I-PS2/XYE-85), not current reality. Resolve in BOTH directions: (a) docs must state plainly that today `install.sh --uninstall --purge-data` CAN destroy evidence; (b) I-PS2 must remove the `$SIFT_CASE_ROOT` purge branch + chattr-unlock from `install.sh` to make D5 true. **Add a regression test asserting `--uninstall` WITHOUT `--purge-data` leaves `/cases` + immutability intact** *before* any installer refactor. (See §3 framing nuance.) |
| **C2** | Blueprint D4 "bump the THREE 0.1.0 packages via hatch-vcs" vs reality: only sift-core + windows-triage remain 0.1.0 (root meta also 0.1.0); 7/9 already `0.6.1` as literals; no hatch-vcs | **packaging/release mismatch** + **SPEC vs recent docs** (doc count stale) | Med | Update D4 to current counts: "literal bump to 0.6.1 done for 7/9; root meta + sift-core + windows-triage still 0.1.0; hatch-vcs single-source + `v0.6.2` tag still TODO." |
| **C3** | Blueprint §2 narrates "thin bootstrap installing published hash-pinned wheels" vs current installer = staged checkout + un-pinned `uv sync` (no `--locked`/`--require-hashes`/registry) | **packaging/release mismatch** (target-vs-current) | Med (supply-chain asymmetry: CI is `--locked`, live install is not) | Label Blueprint §2 as TARGET; current = source-tree `uv sync`. Cutover = Phase 8 / I-PS8. |
| **C4** | `.gitignore:8` still ignores the now-committed `uv.lock` | **code vs recent docs** (Blueprint §5 "lock ignored while CI uses --locked" now stale) | Low (latent foot-gun) | Delete the dead `.gitignore:8` line; re-scope I-LOCK to that chore. |
| **C5** | Doc-promised CI gates absent: `bash -n`/shellcheck on `install.sh`, greenfield install/uninstall smoke (AXIS_I I1/I2), npm portal-bundle build provenance (G1-residual) | **missing test/CI proof** | Med | Track as XYE-53 (shell static + smoke harness) and XYE-85/I-PS6 (npm build provenance). The most-changed surface (3658-line `install.sh`) has the least automated proof. |
| **C6** | No CI assertion of the ENFORCE posture (seccomp=kill / AppArmor=enforce live-VM-proven only) | **missing test/CI proof** | Med (a regression leaving log/complain would pass CI) | Add a post-install/deploy smoke asserting the SIFT profiles are ENFORCE and `SIFT_EXECUTE_SECCOMP_MODE=kill` on the served unit (XYE-9 / project_postmvp_run1). |

---

## 3. C1 Security-Framing Nuance (the one item worth precision)

A2 labels C1 "**contradicted**" and "**Security-relevant**." Both are correct and
I confirm the code path (S11). One nuance for the final assessment so the
severity is not over- or under-stated:

- **The contradiction is with Blueprint D5's *absolute* wording** ("NEVER … not a
  code path, ever"), which the code violates. That absolute claim is false today.
  VALID-FINDING — keep it.
- **But the live path is not silent or default.** It requires BOTH the explicit
  opt-in `--purge-data` flag (`install.sh:3415`) AND an interactive
  `_confirm_destructive` prompt that names evidence loss (`install.sh:3359`,
  message at `:3359` enumerates "EVIDENCE, incl. immutable-flagged files … cannot
  be undone"). The default `--uninstall` explicitly preserves `/cases`
  (`:3375,3384-3390`). This matches **CLAUDE.md**, which already documents
  `install.sh --uninstall/--purge-data` as a "lighter built-in" and names
  `scripts/uninstall.sh` as the canonical teardown that preserves `/cases`.
- **Net:** the security finding is genuine (a hardened-forensics product SHOULD
  not carry an evidence-`rm -rf` path in its installer, per its own stated
  design), but the framing in the final assessment should read "**reachable only
  via an opt-in flag + typed destructive confirmation**," not "installer silently
  deletes evidence." That precision is the difference between a P1 and a
  design-debt item. I am NOT bouncing this to A2 as a revision — A2's report text
  already says "gated only by `_confirm_destructive` … and opt-in `--purge-data`,"
  so A2 captured the gating. The nuance is a note for the *final assessment*
  wording, not a peer error.

---

## 4. Revision Requests

**To Agent 1:** NONE that block signoff. One non-blocking sharpening:

- **R-A1.1 (sharpen, not a defect).** Report §"§7 / §6 — OpenCTI writes
  `opencti_*` indices" + Ledger #1 + Assumption A2 correctly scoped the claim to
  "*opencti-mcp does not write `opencti_*`, and no repo Python writes them*" and
  explicitly left the out-of-repo connector OPEN. I **resolved that open caveat**:
  `docker-compose.opencti.yml:13-41,110-115` shows the OpenCTI add-on runs its OWN
  isolated `opencti-opensearch` cluster on `sift-opencti-net` with
  `ELASTICSEARCH__INDEX_PREFIX=opencti`, and the file comment (`:4-5,110`)
  explicitly forbids writing those indices into the SIFT forensic cluster. So the
  `opencti_*` indices DO exist — in a separate datastore the gateway never reads
  as authority. **Required correction to the *recommended resolution* (not the
  finding):** change "remove the arrow / drop `opencti_*` … unless a separate
  connector populates those indices; if so, name it" to the **definite**: "relabel
  the SPEC arrow as the OpenCTI add-on's **separate/isolated** OpenSearch
  datastore (`docker-compose.opencti.yml`), not the SIFT forensic cluster." A1's
  finding and classification (code vs SPEC, stale) stand; only the conditional
  phrasing should become definite. This is OPTIONAL — A1's report is correct as
  written; I am supplying the missing evidence rather than asking A1 to re-verify.

**To Agent 2:** NONE. Both A2 reports are accurate to the line on every
load-bearing claim I re-verified (C1/C2/C3, CI gate set, coverage floors,
versions, install flow, lock/gitignore, build config). The C1 framing nuance in
§3 is a note for the *final assessment*, not an A2 error — A2 already documented
the opt-in + confirmation gating.

**Net: 0 blocking revisions for A1, 0 for A2.** (1 optional sharpening for A1.)

---

## 5. Human-Decision List

These cannot be resolved from code/docs alone; they need an operator/architect
ruling:

- **H1 — OpenCTI `opencti_*` arrow intent.** Code proves the indices live in the
  add-on's *isolated* OpenSearch (M1/R-A1.1). The SPEC author must confirm the
  intended end-state: is the OpenCTI datastore meant to stay a fully separate
  sidecar (relabel the arrow), or was there ever a design to mirror/ingest CTI
  into the SIFT forensic cluster (then it's an unbuilt roadmap item, not just a
  doc fix)? Evidence points to "separate by design" (`docker-compose.opencti.yml:4-5,110`),
  but intent is the architect's call.
- **H2 — C1 evidence-purge: fix vs document.** Decision: does I-PS2/XYE-85 REMOVE
  the `$SIFT_CASE_ROOT` purge branch from `install.sh` (making D5 true), or does
  the project KEEP an opt-in operator wipe and amend D5 to "never deletes evidence
  *by default*; explicit `--purge-data` + typed confirmation required"? This is a
  security-posture / product-design ruling, not a code-vs-docs fact.
- **H3 — meta-package public name vs repo rename.** Root dist is `sift-mcps`
  (`pyproject.toml:23`); the install-nextgen blueprint couples the `sift-` dist
  prefix + public name to repo-rename **XYE-7** (`ProtocolSiftGateway`). The
  eventual published meta-package name on PyPI (`sift-mcps` vs a `protocol-sift-*`
  family) is an operator/architect call that gates I-PS5/I-PS8.
- **H4 — Linear ticket binding for XYE-83 / XYE-84 / XYE-64.** A2 could not bind
  these to a specific install/CI/packaging code artifact and left them
  "needs-grooming." Confirming their scope against the coordinator issue is an
  operator action (I did not run linear-cli, per hard rule; IDs referenced
  textually only).

---

## 6. Signoff Verdict

**SIGNED OFF — no blocking revisions.**

All 16 independently re-verified claims hold (14 CONFIRMED, 2 NUANCED, 0
REFUTED). Both peer reports correctly applied source precedence (code = now,
SPEC = intent, new-docs = roadmap) and correctly classified their contradictions
as code-vs-SPEC / code-vs-recent-docs / packaging-vs-target / missing-CI-proof.
No correct finding is bounced back. The two NUANCED items (OpenCTI out-of-repo
connector resolution; C1 security framing) are sharpenings that strengthen the
peers' recommended resolutions — they flow into the final assessment, they do not
require peer revision.

Outstanding items are all **human-decision** (H1–H4), chiefly: (a) the OpenCTI
datastore-scope intent behind the SPEC arrow, and (b) whether C1's evidence-purge
path is removed (fix D5) or documented (amend D5). The contradiction matrix
(M1–M8, C1–C6) is ready for the final reconciliation assessment.

---

## 7. Assumptions Made

- **A1.** codebase-memory is keyed to the main repo path
  (`Users-yk-AI-SIFTHACK-sift-mcps`); this worktree is the same commit
  (`a7ea369`). I used the graph only for routing and verified every cited
  file:line with a direct `Read`/`grep` in THIS worktree.
- **A2.** I did not run git/linear-cli/product-code edits (hard rule). Linear IDs
  (XYE-85/53/55/49/9/7) are referenced textually by topical fit, inherited from
  the peer reports; I did not re-derive ticket mappings.
- **A3.** For M1/H1 I treat `docker-compose.opencti.yml` (committed at repo root)
  as in-scope repo evidence — it is, even though A1 scoped its grep to
  `packages/`. That file definitively resolves the "out-of-repo connector"
  caveat: the connector is in-repo (a compose stack) and targets a *separate*
  OpenSearch, so the SPEC arrow is mislabeled, not fabricated.
- **A4.** "Severity" in §2 reflects doc-trust / security / supply-chain impact at
  this commit, not Linear priority. C1 (security) and M1 (doc-trust for an AI
  diagram consumer) are the two High items.
