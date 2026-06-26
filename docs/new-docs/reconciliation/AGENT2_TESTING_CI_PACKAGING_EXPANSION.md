# Agent 2 — Testing / CI / Packaging / Publish Expansion (install → public PyPI)

> **Purpose:** expand install-nextgen rounds 01–02 into a concrete testing/CI/packaging/publish
> approach for the install → public-PyPI modernization (XYE-85).
> **Author:** Agent 2. **Date:** 2026-06-19. **Commit:** `a7ea369`.
> Every current-state claim is file-cited; every target item is marked **to-build**.
> Companion: `AGENT2_RECENT_DOCS_CODE_TRACE.md`.

---

## 1. CURRENT STATE (file-cited)

### 1.1 Packaging layout
- **uv workspace**, root is a NON-buildable aggregator: `pyproject.toml:1-2` `[tool.uv.workspace]
  members = ["packages/*"]`; `:4-5` `[tool.uv] package = false`; `:70-71`
  `[tool.hatch.build.targets.wheel] packages = []` → **root builds no wheel today.**
- **9 workspace packages** (`packages/*/pyproject.toml`): sift-gateway, sift-core, sift-common,
  case-dashboard, forensic-knowledge, opensearch-mcp (`rag-mcp` = forensic-rag-mcp dir), opencti-mcp,
  windows-triage-mcp. Sources wired via `[tool.uv.sources]` `pyproject.toml:7-16`.
- **Extras** on the root meta: `core` / `standard` (=core+opensearch) / `full` (=standard+rag) /
  `opencti` / `windows-triage` / `chroma-import` / `dev` (`pyproject.toml:31-62`).
- **Build backend:** hatchling (`pyproject.toml:18-20`).

### 1.2 Version pinning
- All versions are **hardcoded literals**, NOT dynamic/hatch-vcs (grep for `dynamic`/`hatch-vcs` →
  none). Root meta `0.1.0` (`pyproject.toml:24`). Packages: 7 at `0.6.1`
  (case-dashboard/forensic-knowledge/rag/opencti/opensearch/sift-common/sift-gateway, each
  `pyproject.toml:7`); `sift-core` + `windows-triage-mcp` still `0.1.0`
  (`packages/sift-core/pyproject.toml:7`, `packages/windows-triage-mcp/pyproject.toml:7`).
- `requires-python = ">=3.10"` (root `pyproject.toml:26`; packages `:9`); CI/runtime pin is
  **3.11** (`.python-version`); VM target is **3.12** (CLAUDE.md).

### 1.3 Lockfile
- `uv.lock` (1.1M) is **committed/tracked** (`git ls-files uv.lock`). CI consumes it via
  `uv sync --locked` (`.github/workflows/ci.yml:47`).
- **Residual defect:** `.gitignore:8` STILL lists `uv.lock` (stale — a future `git rm --cached`/re-add
  could silently drop the committed lock). The install-nextgen "lock-vs-CI" finding is otherwise
  resolved.

### 1.4 Tests + how invoked
- `[tool.pytest.ini_options] testpaths = ["tests", "packages"]`, `asyncio_mode = "auto"`
  (`pyproject.toml:97-100`).
- **~185 test files**: root `tests/` (newdocs-refs, TLS cert profile, db) + per-package — opensearch 53,
  gateway 47, sift-core 40, case-dashboard 25, rag 9, sift-common 4, windows-triage 4, opencti 2,
  forensic-knowledge 1.
- **Per-package coverage gate with floors** — `scripts/check_package_coverage.py:28-95` defines a
  `PackageCoverageGate` per package (observed vs floor, e.g. gateway 59/57, core 62/60, opensearch
  52/50 with `-m "not integration"` `:65`, rag 21/19, sift-common 4/3). Runs `pytest --cov ...
  --cov-fail-under=<floor>` per package (`:98-110`) and fails CI on any miss (`:131-136`).
- **Invocation gotchas** (CLAUDE.md + `conftest.py`): opensearch tests need
  `PYTHONPATH=packages/opensearch-mcp/tests`; windows-triage needs `--extra windows-triage` (NOT in
  `full`); golden MCP-surface regen via `UPDATE_MCP_GOLDENS=1`.

### 1.5 CI (exists — 3 workflows)
- **`ci.yml`** (push/PR to main, `:21-82`): checkout → setup-python from `.python-version` →
  setup-uv v8.2.0 w/ cache → `uv sync --locked --extra full --extra opencti --extra windows-triage
  --extra dev` → Ruff `F821,F822,F823` undefined-name guard (`:53-58`) → Ruff clean-source on
  case-dashboard/forensic-knowledge/sift-common (`:60-65`) → Pyright on gateway policy layer via
  `pyrightconfig.json` (`:67-68`) → docs-freshness `check_newdocs_refs.py` (`:70-71`) → `pytest tests`
  + `check_package_coverage.py` (`:73-81`).
- **`live-vm.yml`** — manual `workflow_dispatch` proof-recording checklist; fails unless operator
  booleans are all `true` (`:48-116`). **Not** an automated VM driver.
- **`claude.yml`** — `@claude` mention bot (`:13-37`).

### 1.6 Install / uninstall / smoke
- **Install** = `./install.sh` (3658 lines, monolith, no `lib/`): stages the checkout to
  `/opt/sift-mcps` (`stage_repo_to_install_root`, `install.sh:197-230`) then `uv sync --extra full
  --project "$REPO_DIR"` (`sync_workspace`, `install.sh:508-513`). **Not `--locked`, not from a
  registry** — resolves fresh from the local workspace.
- **Uninstall** = `install.sh --uninstall [--purge-data]` (`:3370-3393`) AND the canonical
  `scripts/uninstall.sh` (44k). `--purge-data` strips immutability and deletes `/cases`
  (`_purge_tree` `:3349-3354`, `purge_data` `:3357-3368`) — see C1 in the trace doc.
- **Smoke** = manual only (CLAUDE.md live-VM discipline; `live-vm.yml` attestation). No automated
  smoke harness script.

### 1.7 Asset download + integrity (current)
- **SHA-pinned (good):** uv tarball `SIFT_UV_TARBALL_SHA256` (`install.sh:167`, enforced `:329-340`);
  hayabusa tag+SHA `v3.9.0` (`install.sh:170-171`, enforced `:995-996`); BGE model revision pin
  (`install.sh:175`). Helper `verify_sha256` (`install.sh:57-64`).
- **Un-pinned (gaps):** uv arch-fallback `curl|sh` (`install.sh:349`, version-pinned URL, unhashed
  body — G8); RAG/WT data assets resolve `latest` (`download_index.py:60,68`,
  `download_databases.py:74,82` — G3, but each release's own `*.sha256` IS verified, RAG
  `download_index.py:127-145`); WT downloader has no offline guard (G2); RAG online feeds un-pinned
  (`sources.py:130,145,593-595`, cap `:600-601` — G10).
- **Python dependency graph is NOT hash-pinned at install** — `sync_workspace` omits
  `--require-hashes` and `--locked` (`install.sh:508-513`).

---

## 2. TARGET STATE — public-PyPI cutover

### 2.1 Package build + publish flow (ties XYE-85)
1. **Flip root to buildable meta** — `[tool.uv] package = true`, populate
   `[tool.hatch.build.targets.wheel]` (currently empty `pyproject.toml:70-71`) or use
   hatch `bypass-selection`; keep `core/standard/full` extras as the public install surface.
   **(to-build — Phase 6 / I-PS6.)**
2. **Build all 9 wheels + sdists** in CI (`uv build` per workspace member). **(to-build.)**
3. **Portal bundle in CI before wheel build** — `npm ci && npm run build` so the Vite bundle ships
   inside the `sift-case-dashboard` wheel (no npm on the VM); record build provenance to close
   G1-residual. **(to-build — no npm step in `ci.yml` today.)**
4. **Two-phase release**: (a) publish wheels to PyPI on tag; (b) THEN compile
   `constraints-<ver>.txt --require-hashes` *from the published index* and commit/attach it.
   **(to-build.)**
5. **Trusted publishing (OIDC) to PyPI** via `pypa/gh-action-pypi-publish` (no long-lived token);
   `id-token: write` (pattern already used in `claude.yml:25`). **(to-build.)**

### 2.2 Version strategy (ties XYE-85 / I-PS1)
- Adopt **hatch-vcs single-source** driven by git tag `v0.6.2`; drop literal `version =` in all 9
  `pyproject.toml` and any `__init__.py` literals; bump root meta + `sift-core` +
  `windows-triage-mcp` off `0.1.0`. **(to-build.)**
- Keep import/module names unchanged on the `sift-` dist rename (modules already match,
  `packages/*/src/<module>`); coordinate the dist rename with repo-rename **XYE-7**.

### 2.3 Asset pinning + integrity manifest (ties XYE-49)
- Replace `latest` with **explicit release tags** for RAG + triage data assets
  (`download_index.py:60`, `download_databases.py:74`) and assert the release tag + the per-asset
  SHA from a checked-in manifest. **(to-build.)**
- **Hash the uv arch-fallback** or remove the `curl|sh` branch (`install.sh:349`) — pin per-arch uv
  binaries with SHA like the x86_64 tarball already is. **(to-build — I-PS3.)**
- **Add an offline guard to the WT downloader** to match install.sh `SIFT_OFFLINE` semantics
  (G2). **(to-build.)**
- **`constraints-<ver>.txt --require-hashes`** becomes the install-time Python pin; the installer
  switches to `uv pip install "sift-mcps[full]==<ver>" -c constraints --require-hashes`. **(to-build.)**

### 2.4 Supply-chain posture
- **Hashes:** committed `uv.lock` (done) + post-publish `--require-hashes` constraints (to-build) +
  asset SHAs (partly done). Remove the stale `.gitignore:8` `uv.lock` line. **(mostly to-build.)**
- **Provenance:** PyPI attestations / Sigstore via the publish action; record portal-bundle build
  provenance. **(to-build.)**
- **Signing:** none today; OIDC trusted publishing gives provenance without manual signing. **(to-build.)**

### 2.5 Test matrix
- **Current:** single job, ubuntu-latest, python from `.python-version` (3.11) (`ci.yml:24-34`).
- **Target:** add **python 3.10 + 3.12** (VM target is 3.12; `requires-python>=3.10`) and an
  **install-from-built-wheel** job that `uv pip install`s the freshly built `sift-mcps[full]` into a
  clean venv and imports each entrypoint. **(to-build.)**

### 2.6 Greenfield install/uninstall smoke harness (ties XYE-53)
- A `scripts/smoke-install.sh` (**to-build**) the manual `live-vm.yml` checklist
  (`:64-73`) can call: fresh `./install.sh` → `/health` (CLAUDE.md health URL) → seeded backends
  (opensearch+RAG only per AXIS_I I4) → `setup-addon.sh` add-on → restart-to-apply → `--uninstall`
  (assert `/cases` + immutability untouched) → reinstall. Output compact for Linear proof.
- **Containerized installer smoke in CI** (ubuntu + system python) for the non-VM-specific paths
  (helper unit behavior, `bash -n`, shellcheck). **(to-build.)**

### 2.7 Service / add-on lifecycle regression (ties XYE-55)
- Pin the XYE-44 semantics (AXIS_I I4): default install seeds **only** opensearch + RAG;
  `setup-addon.sh` payload generation; Portal Register; restart-to-apply; proxy-mount on-demand
  status; no misleading Start/Stop for proxy mounts. After I-PS7 decouples `setup-addon.sh` from
  sourcing all of `install.sh` (`setup-addon.sh:54`), add a regression that exercises add-on
  provisioning against `lib/` in isolation. **(to-build.)**

### 2.8 Smoke / live-proof gates
- Keep the manual `live-vm.yml` attestation as the operator gate (`:84-116`); add the automated
  `smoke-install.sh` output as its evidence input so proof is reproducible, not ad hoc.

---

## 3. PACKAGING / TEST GATE CHECKLIST — MUST pass BEFORE install-nextgen cutover

| # | Gate | Current evidence / status |
|---|---|---|
| G-1 | Root meta builds a wheel (`package=true`, non-empty wheel target) | **to-build** — `pyproject.toml:4-5,70-71` currently `package=false`, `packages=[]` |
| G-2 | All 9 packages build wheel+sdist in CI (`uv build`) | **to-build** — no build/publish job in `ci.yml` |
| G-3 | Single-source version (hatch-vcs) + `v0.6.2` tag; no `0.1.0` stragglers | **to-build** — literals only; root/sift-core/windows-triage still `0.1.0` |
| G-4 | Committed `uv.lock` + `.gitignore` no longer ignores it | **partial** — lock committed (`git ls-files uv.lock`); `.gitignore:8` still lists it (**fix**) |
| G-5 | `pytest tests` + per-package coverage floors green | **done** — `check_package_coverage.py:28-136`, wired `ci.yml:73-81` |
| G-6 | Ruff undefined-name + clean-source + pyright gates green | **done** — `ci.yml:53-68` |
| G-7 | `bash -n` + shellcheck on `install.sh`/`scripts/*.sh` in CI | **to-build** — manual only per CLAUDE.md, absent from `ci.yml` |
| G-8 | Greenfield install→/health→add-on→uninstall→reinstall smoke (automated/scripted) | **to-build** — only manual `live-vm.yml` attestation |
| G-9 | Uninstall WITHOUT `--purge-data` provably preserves `/cases` + immutability (D5) | **to-build** — and `install.sh:3349-3366` must lose the evidence-purge branch first (security) |
| G-10 | Asset SHA + release-tag pins (RAG/WT pinned, uv arch-fallback hashed) | **partial** — uv tarball/hayabusa/BGE pinned (`install.sh:167,170-171,175`); RAG/WT `latest` (`download_index.py:60`) + uv fallback (`install.sh:349`) **to-build** |
| G-11 | Install-from-published-wheel job (clean venv, import each entrypoint) | **to-build** |
| G-12 | Python dependency graph hash-pinned at install (`--require-hashes`/`--locked`) | **to-build** — `sync_workspace` omits both (`install.sh:508-513`) |
| G-13 | Portal Vite bundle built in CI (`npm ci && npm run build`) before wheel build + provenance | **to-build** — G1-residual; no npm step in `ci.yml` |
| G-14 | `setup-addon.sh` decoupled from sourcing all of `install.sh`; add-on lifecycle regression | **to-build** — `setup-addon.sh:54` sources full `install.sh` |
| G-15 | PyPI trusted-publishing (OIDC) release workflow on tag | **to-build** — `id-token: write` pattern exists in `claude.yml:25` |

**Cutover rule:** Phases 1–5 of the blueprint (version coherence, uninstall delegation, uv pin,
modularize, dist rename) ship zero distribution change and must land + stay green (G-3,4,6,7,9)
BEFORE Phases 6–8 (buildable meta, two-phase release, registry-install cutover: G-1,2,11,12,15).

---

## 4. Gap → ticket mapping

| Gap | Description | Evidence | Suggested ticket |
|---|---|---|---|
| Evidence-purge in installer (C1) | `install.sh --purge-data` deletes `/cases` + unlocks immutability vs D5 | `install.sh:3349-3366` | **XYE-85** (I-PS2, security) |
| No buildable meta-package | root `package=false`, empty wheel target | `pyproject.toml:4-5,70-71` | **XYE-85** (I-PS6) |
| Literal versions / no hatch-vcs / `0.1.0` stragglers | bump + single-source | `pyproject.toml:24`, `sift-core`/`windows-triage` `:7` | **XYE-85** (I-PS1) |
| Installer not registry/wheel-based, no `--locked` | `uv sync` from staged source | `install.sh:197-230,508-513` | **XYE-85** (I-PS8) |
| Monolith install.sh / no `lib/` / setup-addon sources it | modularize + decouple | `install.sh` 3658 lines; `setup-addon.sh:54` | **XYE-85** (I-PS4, I-PS7) |
| No shell static-analysis / install smoke in CI | add `bash -n`/shellcheck + smoke | absent from `ci.yml` | **XYE-53** |
| Add-on lifecycle regression suite | pin XYE-44 semantics | AXIS_I I4; `setup-addon.sh` | **XYE-55** |
| RAG/WT `latest` (G3), uv-fallback unhashed (G8), WT no offline (G2), RAG feeds un-pinned (G10) | asset pinning + integrity manifest | `download_index.py:60`, `install.sh:349`, `download_databases.py`, `sources.py:130,145` | **XYE-49** |
| `.gitignore` still ignores committed `uv.lock` | delete dead line | `.gitignore:8` | **XYE-85** (I-LOCK chore) |
| Portal bundle reproducible-build provenance (G1-residual) | npm build in CI + provenance | no npm step in `ci.yml` | **XYE-85** (I-PS6) / **XYE-53** |
| **XYE-83 / XYE-84 / XYE-64** | Could not bind to a specific install/CI/packaging code artifact from new-docs alone | — | **needs-grooming** — confirm scope with the coordinator issue before mapping |

---

## 5. Assumptions
- **A1:** XYE topical mapping per the brief; linear-cli NOT run (hard rule) — IDs referenced textually.
- **A2:** XYE-83/84/64 left as needs-grooming rather than force-fit; no code artifact in the install/CI
  slice cleanly binds to them at commit `a7ea369`.
- **A3:** "Two-phase release" (publish, then compile `--require-hashes` constraints from the published
  index) is taken from FINAL-INSTALL-BLUEPRINT §2/§4 as the intended target; not yet in code.
- **A4:** `npm`/portal-frontend build wiring assumed from blueprint §2 ("CI runs `npm ci && npm run
  build`"); the case-dashboard frontend build config itself was not deep-read by this agent.
