# Agent 2 — Recent-Docs ↔ Code Trace (install / CI / packaging / roadmap)

> **Scope:** reconcile `docs/new-docs` + `docs/new-docs/install-nextgen` (recent operational truth)
> against CURRENT code at commit `a7ea369`.
> **Author:** Agent 2 (recent-docs/install/CI/packaging/roadmap auditor).
> **Date:** 2026-06-19. **Index:** codebase-memory `Users-yk-AI-SIFTHACK-sift-mcps`, status `ready`
> (15968 nodes / 61764 edges); file:line citations are against this worktree (same commit).
> **Source precedence applied:** (1) current code/tests/CI decide what is implemented NOW;
> (2) `docs/drafts/architecture/sift-architecture-SPEC.md` anchors intent; (3) new-docs/install-nextgen
> capture recent roadmap; (4) conflicts are recorded, never silently resolved.

---

## 0. Headline correction to the mission brief

The team brief hypothesized *"check whether ANY CI exists"*. **CI exists and is substantial.**
`.github/workflows/` contains three workflows:

- `ci.yml` — real gate on push/PR to `main`: `uv sync --locked` (full+opencti+windows-triage+dev),
  Ruff undefined-name guard (`F821,F822,F823`), Ruff clean-source gate on 3 packages, Pyright on the
  gateway policy layer, docs-freshness (`check_newdocs_refs.py`), `pytest tests`, and
  `check_package_coverage.py` (`.github/workflows/ci.yml:21-82`).
- `live-vm.yml` — manual (`workflow_dispatch`) attestation checklist for live-VM proof; it records
  operator-confirmed booleans and fails if any are not `true` (`.github/workflows/live-vm.yml:48-116`).
  It does NOT actually drive the VM — it is a proof-recording gate.
- `claude.yml` — `@claude` mention bot (`.github/workflows/claude.yml:13-37`).

So the modernization track is NOT greenfield-CI; it is "CI exists, harden + extend it for publish."

---

## 1. Recent-doc decision/gap trace table

Legend — Status: **confirmed** | **partial** | **stale** | **contradicted** | **not-found**.

### 1.1 FINAL-INSTALL-BLUEPRINT.md (the decision-locked roadmap)

| # | Documented decision / claim (doc §) | Code / CI / package evidence (file:line) | Status | Recommended doc update | Linear lane |
|---|---|---|---|---|---|
| D2 | Meta-package = buildable root `sift-mcps` carrying core/standard/full extras (§1, §2) | Root `pyproject.toml:4-5` `[tool.uv] package = false`; `:70-71` `[tool.hatch.build.targets.wheel] packages = []`; extras `core/standard/full` already declared `:31-52` | **partial** | Extras already exist; the *buildable* flip (`package=true` + non-empty wheel target / `bypass-selection`) is NOT done. Mark D2 "extras present, build target empty — Phase 6 work" | XYE-85 (I-PS6) |
| D3 | Public PyPI, MIT; `sift-` dist prefix; rename to `ProtocolSiftGateway` (§1, §3) | Root `pyproject.toml:27` `license = { text = "MIT" }`, `:23` `name = "sift-mcps"`; package dist names still un-prefixed: `case-dashboard` (`packages/case-dashboard/pyproject.toml:6`), `rag-mcp` (`packages/forensic-rag-mcp/pyproject.toml:6`), `opensearch-mcp` (`packages/opensearch-mcp/pyproject.toml:6`) | **partial** | MIT confirmed. `sift-` prefix rename NOT applied to any package. Keep coupling note to repo-rename XYE-7 | XYE-85 (I-PS5) + XYE-7 |
| D4 | Versioning = hatch-vcs + git tag, line `0.6.2`; bump the three `0.1.0` pkgs; drop `__init__` literals (§1, §4) | **No hatch-vcs anywhere** (grep `hatch-vcs\|dynamic\|version` across `packages/*/pyproject.toml` → none); versions are hardcoded literals. **7 of 9 already at `0.6.1`** (case-dashboard/forensic-knowledge/rag/opencti/opensearch/sift-common/sift-gateway `pyproject.toml:7`); only `sift-core` (`packages/sift-core/pyproject.toml:7`) and `windows-triage-mcp` (`packages/windows-triage-mcp/pyproject.toml:7`) remain `0.1.0`; **root meta still `0.1.0`** (root `pyproject.toml:24`) | **stale / partial** | Doc says "three 0.1.0 packages" — **two** remain (+ root meta). Versions were bumped as *literals*, not via hatch-vcs. Update D4 to: "literal bump to 0.6.1 partially done (7/9); hatch-vcs + single-source + `0.6.2` tag still TODO" | XYE-85 (I-PS1) |
| D5 | **Installer NEVER deletes case evidence — by design**; never forward evidence-unlock flags (§1, §4) | **CONTRADICTED by current code.** `install.sh --uninstall --purge-data` actively strips immutability and deletes `/cases`: `_purge_tree` does `sudo chattr -R -f -i/-a "$target"` then `rm -rf` (`install.sh:3349-3354`); `purge_data` calls it on `$SIFT_CASE_ROOT` and logs "EVIDENCE deleted (immutable flags cleared first)" (`install.sh:3364-3366`). Gated only by `_confirm_destructive` prompt (`install.sh:3359`) and opt-in `--purge-data` (`install.sh:3415`) | **contradicted** | D5 is the TARGET, not current state. Document explicitly: today `install.sh` CAN destroy evidence via `--purge-data`; PS2/I-PS2 must remove the `_purge_tree` chattr-unlock + `$SIFT_CASE_ROOT` branch from the installer | XYE-85 (I-PS2, security) |
| D6 | G10 RAG feeds deferred, hosted as-is (§1, §5) | `rag_mcp/sources.py:130,145` live gov JSON (d3fend, cisa) un-pinned; host allowlist `:593-595`; 60MB cap `MAX_DOWNLOAD_BYTES` `:600-601`; `refresh.py:73` `skip_online: bool = False` | **confirmed** | Accurate; keep as deferred fork. | XYE-49 (deferred fork) |
| §2 | Current install = thin bootstrap installing **published hash-pinned wheels** | **NOT current.** Current installer stages the *checkout* to `/opt/sift-mcps` (`stage_repo_to_install_root`, `install.sh:197-230`, rsync `:215-228`) then `uv sync --extra full --project "$REPO_DIR"` from the local workspace (`sync_workspace`, `install.sh:508-513`) — **not `--locked`, not from a registry** | **contradicted** (as current) / target accurate | Clarify §2 is the TARGET. Current = source-tree + `uv sync` (no `--locked`). Phase 8/M19 cutover replaces both | XYE-85 (I-PS8) |
| §2 | Integrity bar: every fetch SHA/hash-gated; existing hayabusa/uv/BGE pins retained | Confirmed for non-Python assets: `verify_sha256` helper (`install.sh:57-64`); uv tarball pin `SIFT_UV_TARBALL_SHA256` (`install.sh:167`, enforced `:329-340`); hayabusa tag+SHA `SIFT_HAYABUSA_TAG=v3.9.0` / `SIFT_HAYABUSA_SHA256` (`install.sh:170-171`, enforced `:995-996`); BGE revision pin `SIFT_RAG_MODEL_NAME` (`install.sh:175`) | **confirmed** (assets) / **partial** (Python graph) | Asset pins real. But the **Python dependency graph is NOT hash-pinned at install** (`uv sync` without `--require-hashes`/`--locked`). `constraints.txt --require-hashes` is target-only | XYE-49 / XYE-85 (I-PS6) |
| §2 | Modularize → thin entrypoint + `lib/*.sh`; setup-addon sources `lib/` | **No `lib/` dir exists.** `install.sh` is a 3658-line monolith (`wc -l install.sh`). `setup-addon.sh:54` `source "$REPO_ROOT/install.sh"` — sources the WHOLE installer | **not-found / contradicted** | Modularization not started. setup-addon couples to full install.sh today | XYE-85 (I-PS4, I-PS7) |
| §2 | `--offline` via `scripts/bundle-offline.sh` | `scripts/bundle-offline.sh` **does not exist** (`ls scripts/` → absent). install.sh has `SIFT_OFFLINE=1` skip branches (e.g. hayabusa `install.sh:976`) but no bundle builder | **not-found** | Offline secondary mode is partial (skip-flags only, no pre-staged wheel bundle builder) | XYE-85 (I-PS8 / offline fork) |
| §3 | Import/module names do NOT change on dist rename | Module dirs already match (`rag_mcp`, `case_dashboard`, `opensearch_mcp`, `sift_gateway` under each `packages/*/src/`) | **confirmed** | Accurate | XYE-85 (I-PS5) |
| §5 | Bonus: `.gitignore` ignores `uv.lock` while CI runs `uv sync --locked` | **PARTIALLY STALE.** `uv.lock` **IS now committed/tracked** (`git ls-files uv.lock` → tracked; file present 1.1M) — so CI `--locked` (`ci.yml:47`) works. BUT `.gitignore:8` STILL lists `uv.lock` (latent foot-gun: a future re-add could drop it) | **partial / stale** | Lock-vs-CI conflict resolved (lock committed). Residual: remove the stale `.gitignore:8` entry. Re-scope I-LOCK to "delete dead gitignore line" | XYE-85 (I-LOCK chore) |

### 1.2 FINAL-ASSET-INVENTORY.md (download/supply-chain gaps G1–G11)

| Gap | Documented gap | Code evidence (file:line) | Status | Linear lane |
|---|---|---|---|---|
| G2 | windows-triage downloader has NO offline guard (inconsistent w/ install.sh) | `download_databases.py` has no `SIFT_OFFLINE`/offline branch (grep → none); always hits `api.github.com` (`:86,104`) | **confirmed** | XYE-49 |
| G3 | `latest`-tag resolution for first-party data assets (RAG + triage DBs) | RAG `download_index.py:60` `tag="latest"`, resolves newest `rag-index-*` (`:68-76`); WT `download_databases.py:74` `tag="latest"`, newest `triage-db-*` (`:82`). NOTE: both still SHA-verify a checksum asset *inside* the chosen release (RAG `:127-145`) — integrity yes, release-pin no | **confirmed** | XYE-49 |
| G8 | uv arch-fallback path is unhashed | `install.sh:349` `curl -LsSf "https://astral.sh/uv/${SIFT_UV_VERSION}/install.sh" \| sh` — version-pinned URL but the piped script body is unhashed. Reached only when the SHA-pinned tarball path can't resolve a binary (`install.sh:345-350`) | **confirmed** | XYE-49 |
| G10 | RAG online-source subsystem no content/commit pinning (headline surface) | `sources.py:130,145` live JSON; git-clone HEAD feeds (per inventory `sources.py:642` uncapped clone); `skip_online=False` default (`refresh.py:73`); NOT run by install.sh (`download_index.py:379` passes `skip_online=True`) | **confirmed** | XYE-49 (deferred) |
| G1-residual | No provenance link from committed Vite bundle → reproducible build | Blueprint §2 states CI should run `npm ci && npm run build` before wheel build; no such CI step exists in `ci.yml` (no npm step) | **confirmed** | XYE-85 / XYE-53 |

### 1.3 AXIS_I_BUILD_PLAN.md (installer verification track)

| Item | Documented plan | Code evidence | Status | Linear lane |
|---|---|---|---|---|
| I1 | Installer static + helper test harness (`bash -n`, helper extraction) | No shell unit tests; `bash -n install.sh` is the only static check, run manually per CLAUDE.md, NOT in `ci.yml`. CI has zero shellcheck/`bash -n` step | **not-found** (as CI gate) | XYE-53 |
| I2 | Greenfield install/uninstall smoke harness, repeatable | `live-vm.yml` is a manual attestation checklist (`:48-116`), not an automated smoke runner. No `scripts/smoke-*.sh` | **partial** | XYE-53 |
| I3 | Installer replacement/wrapper decision (Bash vs Python vs Ansible) | Open decision; blueprint chose "thin bootstrap + published wheels" (FINAL-INSTALL-BLUEPRINT §2) — partially answers I3 | **partial** | XYE-85 |
| I4 | Service/add-on lifecycle regression suite | `setup-addon.sh` exists (34k); no lifecycle regression test suite found | **not-found** | XYE-55 |

### 1.4 OPTIMIZATION_TRACK.md / CODEBASE_ASSESSMENT.md (CI-relevant claims)

| Claim | Evidence | Status |
|---|---|---|
| CI gates F821/F822/F823 undefined-name + pyright on gateway | `ci.yml:53-68` exactly that | **confirmed** |
| `check_package_coverage.py` enforces every package is test-covered | `scripts/check_package_coverage.py` exists; invoked `ci.yml:76-81` | **confirmed** |
| Docs-freshness gate | `scripts/check_newdocs_refs.py` exists; invoked `ci.yml:70-71` | **confirmed** |

---

## 2. Contradiction Ledger

| # | Contradiction | Doc side | Code side | Recommended resolution |
|---|---|---|---|---|
| **C1** | Installer + evidence destruction | FINAL-INSTALL-BLUEPRINT D5: "installer NEVER deletes case evidence, by design" | `install.sh:3349-3354` (`_purge_tree` chattr-unlock+`rm -rf`) + `:3364-3366` (`purge_data` on `$SIFT_CASE_ROOT`); reachable via `--uninstall --purge-data` (`:3415`) | D5 is TARGET. Code is reality. PS2/I-PS2 must DELETE the evidence-purge branch from `install.sh`; until then docs must say the installer CAN destroy evidence. **Security-relevant.** |
| **C2** | "0.1.0 packages" count + versioning mechanism | D4: "bump the three 0.1.0 packages via hatch-vcs" | Only `sift-core` + `windows-triage-mcp` remain `0.1.0` (`packages/*/pyproject.toml:7`); 7/9 already `0.6.1` as **literals**; root meta `0.1.0` (root `pyproject.toml:24`); **no hatch-vcs** | Update D4 to current counts; hatch-vcs single-source + `0.6.2` tag is still the unbuilt step. |
| **C3** | Current install mechanism | Blueprint §2 narrates published hash-pinned wheels from PyPI | `install.sh` stages the checkout (`:197-230`) + `uv sync --extra full --project` (no `--locked`, `:508-513`) from local workspace | §2 must be labeled TARGET; current = source-tree `uv sync`. Cutover = Phase 8 / I-PS8. |

Secondary (sub-contradiction): blueprint §5 "uv.lock ignored while CI uses --locked" is now **stale** — `uv.lock` is committed and CI `--locked` works (`ci.yml:47`); only the dead `.gitignore:8` line remains.

---

## 3. Top Risks / Missing Tests

1. **Evidence-destruction path lives in the installer (C1).** Highest-severity gap vs stated design.
   No test asserts `install.sh --uninstall` (without `--purge-data`) leaves `/cases` + immutability
   intact. **Add a regression test before any installer refactor.** (XYE-85/I-PS2.)
2. **Installer resolves dependencies un-pinned.** `sync_workspace` omits `--locked`/`--require-hashes`
   (`install.sh:508-513`) — CI is reproducible (`--locked`) but a live install is not. Supply-chain
   asymmetry. (XYE-49 + XYE-85/I-PS6.)
3. **No shell static-analysis or installer smoke in CI.** `bash -n`/shellcheck and a greenfield
   install/uninstall harness are doc-promised (AXIS_I I1/I2) but absent from `ci.yml`. The riskiest,
   most-changed surface (3658-line `install.sh`) has the least automated proof. (XYE-53.)
4. **`setup-addon.sh` sources the entire `install.sh`** (`:54`) — any installer change can break add-on
   provisioning with no isolating test. (XYE-85/I-PS7 + XYE-55.)
5. **First-party data assets resolve `latest`** (G3) — a fresh install pulls whichever RAG/triage
   release is newest; reproducibility depends on release immutability, not a pin. (XYE-49.)
6. **No reproducible-build provenance for the committed portal Vite bundle** (G1-residual); blueprint
   wants `npm ci && npm run build` in CI before the wheel build — not present. (XYE-85/I-PS6, XYE-53.)

## 4. Assumptions Made

- **A1:** The mission brief's "check whether ANY CI exists" predates commit `a7ea369`; I treat current
  `.github/workflows/*` as ground truth and flag the brief as outdated (§0).
- **A2:** Linear IDs (XYE-85/83/49/53/55/84/64) are mapped by topical fit per the brief; I did NOT run
  linear-cli (per hard rule) and reference them textually only. Mapping: XYE-85 = installer
  modernization → PyPI (I-PS* phases); XYE-49 = network-fetch inventory / asset pinning (the G-gaps);
  XYE-53 = install/uninstall smoke harness (AXIS_I I1/I2); XYE-55 = add-on lifecycle regression
  (AXIS_I I4); XYE-83/84/64 = adjacent modernization/packaging work I could not bind to a specific
  code artifact and therefore left as "needs-grooming" in the gap→ticket table of Deliverable 2.
- **A3:** "Three 0.1.0 packages" in D4 was true at authoring time; the bump to 0.6.1 landed for 7/9
  between blueprint authoring and commit `a7ea369`. I report current state.
- **A4:** `docs/drafts/architecture/sift-architecture-SPEC.md` (precedence tier 2) was not deeply read
  by this agent for install/CI specifics; the install/packaging intent precedence I used is the
  install-nextgen blueprint (tier 3), which is the most specific source for this surface. No
  architecture-intent conflict surfaced in the install/CI/packaging slice.
