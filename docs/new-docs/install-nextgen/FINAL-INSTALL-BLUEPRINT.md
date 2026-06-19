# FINAL — Installation Modernization Blueprint (decisions ratified)

**Track A capstone · Lead synthesis · Date: 2026-06-19**

This is the actionable plan after operator ratification. It supersedes the open questions in
[`01-INSTALL-EXPLORATION.md`](01-INSTALL-EXPLORATION.md) (primary, structure/skeletons) and
[`01b-INSTALL-EXPLORATION-ALT.md`](01b-INSTALL-EXPLORATION-ALT.md) (second opinion), and resolves
the REVISION-REQUIRED findings in [`02-INSTALL-REVIEW.md`](02-INSTALL-REVIEW.md). Detail/patches
live in those files; this is the decision-locked roadmap. Asset context:
[`FINAL-ASSET-INVENTORY.md`](FINAL-ASSET-INVENTORY.md).

## 1. Ratified decisions

| # | Decision | Ruling |
|---|----------|--------|
| D2 | Meta-package mechanism | **A — buildable root `sift-mcps` meta-distribution** carrying `core/standard/full` extras |
| D3 | Registry + license | **Public PyPI, MIT.** Public hackathon repo (rename → `ProtocolSiftGateway`). `sift-`-prefixed public dist names adopted (rename was happening anyway) |
| D4 | Versioning | **hatch-vcs + git tag, line `0.6.2`.** One source of truth; bump the three 0.1.0 packages up; drop `__init__.py` literals |
| D5 | Uninstall vs evidence | **Installer NEVER deletes case evidence — by design.** Evidence destruction is an operator-manual action (remove `chattr +i`, then keep/delete `/cases` deliberately). Not an installer code path, ever |
| D6 | RAG feeds (G10) | **Deferred, documented as-is.** Host the ~22 upstream feeds as-is for now; published-feed release pipeline comes later. Track as future fork issue |

## 2. Target design (locked)

- **Distribution:** thin `./install.sh` bootstrap (~150 lines) that `uv pip install`s published,
  hash-pinned wheels from **public PyPI** into a system-`python3.12` venv at `/opt/sift-mcps`.
  Install command: `uv pip install "sift-mcps[full]==0.6.2" -c constraints-0.6.2.txt --require-hashes`.
- **Tiering:** Tier A core (`sift-gateway`, `sift-core`, `sift-common`, `sift-case-dashboard`,
  `sift-forensic-knowledge`) · Tier B first-party core-addons (`sift-opensearch-mcp`, `sift-rag-mcp`) ·
  Tier C external add-ons (`sift-opencti-mcp`, `sift-windows-triage-mcp`, via `setup-addon.sh`).
- **Portal frontend:** ships pre-built inside the `sift-case-dashboard` wheel (no npm on the VM) —
  CI runs `npm ci && npm run build` before the wheel build.
- **Modularization:** monolith → thin entrypoint + `lib/*.sh` sourced modules; `setup-addon.sh`
  sources `lib/` (not all of `install.sh`).
- **`--offline`:** secondary mode (pre-staged wheel bundle via `scripts/bundle-offline.sh`).
- **Integrity bar:** every fetch SHA/hash-gated — `constraints.txt --require-hashes` for the Python
  graph (compiled **from the published index, post-publish**), per-arch SHA for `uv`, existing
  hayabusa/BGE pins retained.

## 3. Naming scheme (public PyPI, `sift-` prefix)

Distribution names rename; **import/module names do NOT change** (`rag_mcp`, `case_dashboard` stay).

| Current dist | New public dist | Module (unchanged) |
|---|---|---|
| `sift-mcps` (meta) | `sift-mcps` *(keep — or `protocol-sift-gateway`; see open item)* | — |
| `sift-gateway` | `sift-gateway` | `sift_gateway` |
| `sift-core` | `sift-core` | `sift_core` |
| `sift-common` | `sift-common` | `sift_common` |
| `case-dashboard` | `sift-case-dashboard` | `case_dashboard` |
| `forensic-knowledge` | `sift-forensic-knowledge` | (n/a) |
| `opensearch-mcp` | `sift-opensearch-mcp` | `opensearch_mcp` |
| `rag-mcp` | `sift-rag-mcp` | `rag_mcp` |
| `opencti-mcp` | `sift-opencti-mcp` | `opencti_mcp` |
| `windows-triage-mcp` | `sift-windows-triage-mcp` | `windows_triage_mcp` |

> **Meta/dist naming is coupled to the repo rename — do not pre-decide here.** The
> `ProtocolSiftGateway` rename is its own open backlog item: **XYE-7** *("[B-MVP-002] Rename repo to
> ProtocolSiftGateway and normalize add_ons layout", Backlog)*. The final meta name (`sift-mcps`
> vs `protocol-sift-gateway`) and the `sift-` dist prefixes should be settled **with/under XYE-7** so
> the package rename and repo rename land coherently in one pass. Interim default: keep `sift-mcps`.
> **Relationship:** the publish phase (Phase 6, I-PS6) is *related to / should coordinate with* XYE-7
> — whichever lands first must not strand the other. Whatever names are chosen must be applied
> consistently across `[project] name`, meta extras, `[tool.uv.sources]` keys,
> `importlib.metadata.version("…")` calls, `constraints.txt`, and `setup-addon.sh`.

## 4. Remediation roadmap (dependency-correct, reversible-first)

Patch-set detail is in `02-INSTALL-REVIEW.md` Part B. Decisions are now baked in (no gates left
except the trivial meta-name item).

| Phase | Work | Patch set | Risk | Reversible |
|------|------|-----------|------|------------|
| **1** | Version coherence: hatch-vcs across 9 pkgs, drop literals, tag `v0.6.2` | PS1 | low | yes |
| **2** | Uninstall delegation: `install.sh` can never delete evidence; do not forward evidence-unlock flags (per **D5**) | PS2 | low | yes |
| **3** | Per-arch SHA-pinned `uv`; delete the `curl \| sh` fallback | PS4a | low | yes |
| **4** | Modularize → `lib/*.sh`; shellcheck/`bash -n` CI; remove dead Phase-9 OpenCTI + `fix_volatility_permissions` no-op | M0–M2/M4 | low | yes |
| **5** | Dist rename to `sift-` prefix (per **D3**) across all 5 locations | PS5a | low | yes |
| **6** | Buildable meta-package (root `package=true`, `bypass-selection`) + two-phase release CI + post-publish hash-pinned constraints | PS3 + Major#3 | med | mostly |
| **7** | `setup-addon.sh` sources `lib/` not `install.sh` | PS4b | med | yes |
| **8** | Cutover: `./install.sh` installs published wheels (replace `uv sync`/`stage_repo_to_install_root`) | M19 | high | gated by clean-VM smoke |

**Phases 1–5 ship zero distribution change** (pure hardening, all reversible) and can land
immediately. Phases 6–8 are the registry cutover.

## 5. Deferred / out of scope (tracked separately)

- **D6 / G10 — RAG online-source feeds (~22 unpinned `git clone HEAD` + live MITRE/CISA JSON).**
  Registry publishing pins *package code only*; the knowledge corpus stays HEAD-at-refresh-time.
  Plan: host feeds as-is now; build a published-feed release pipeline later (pin to commit SHAs via a
  checked-in manifest; snapshot gov JSON into the release; make live fetch opt-in). Blueprint honesty
  note added. → future fork issue.
- **Bonus — committed-lock gap.** `.gitignore` ignores `uv.lock` while CI runs `uv sync --locked`.
  Either commit `uv.lock` or drop `--locked`. → quick Linear note.

## 6. Proposed Linear breakdown (Axis I — Installer)

Suggested parent + children (names map to the phases above):

- **Parent (coordinator):** *Install modernization → registry-published, modular installer*
- I-PS1 — Version coherence via hatch-vcs + tag v0.6.2 *(agent-ready, low)*
- I-PS2 — Uninstall delegation; installer can never delete evidence *(agent-ready, low, security)*
- I-PS3 — Per-arch SHA-pinned uv; remove curl|sh fallback *(agent-ready, low, security)*
- I-PS4 — Modularize install.sh → lib/*.sh + shellcheck CI + dead-code removal *(low)*
- I-PS5 — Public dist rename to `sift-` prefix *(low; after PS4; **related to XYE-7** repo rename — coordinate naming)*
- I-PS6 — Buildable meta-package + two-phase release CI + post-publish constraints *(med; after PS1/PS5)*
- I-PS7 — setup-addon.sh decouple to lib/ *(med; after PS4)*
- I-PS8 — Registry-install cutover + clean-VM smoke *(high; after PS6)*
- I-G10 (fork) — Pin RAG online-source feeds / published-feed pipeline *(deferred)*
- I-LOCK (chore) — Resolve uv.lock vs `--locked` CI *(quick)*
