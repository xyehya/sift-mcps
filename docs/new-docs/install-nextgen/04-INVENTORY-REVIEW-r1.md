# 04 — Download / Network-Fetch Asset Inventory: Review (round 1)

**Verdict:** `CHANGES REQUIRED`

**Reviews:** `03-DOWNLOAD-ASSET-INVENTORY.md` (DRAFT v1)
**Date:** 2026-06-19
**Reviewer:** Auditor agent (independent static code audit)
**Findings:** 0 blocker · 3 major · 6 minor

---

## 1. Methodology

This was an independent re-audit, not a re-read of the draft. I:

1. **Re-derived a representative subset of the 24 rows from source**, prioritizing
   the riskiest. Independently opened and read end-to-end:
   - `install.sh` (uv install/pins, hayabusa install, apt host prereqs, GeoIP
     block, frontend rsync staging).
   - `packages/windows-triage-mcp/src/windows_triage_mcp/scripts/download_databases.py` (full).
   - `packages/forensic-rag-mcp/src/rag_mcp/scripts/download_index.py` (full).
   - `packages/forensic-rag-mcp/src/rag_mcp/utils.py` (BGE model load/pin path).
   - `packages/forensic-rag-mcp/src/rag_mcp/sources.py` (online-source subsystem).
   - `packages/windows-triage-mcp/scripts/update_sources.py` (triage feeds).
   - `docker-compose.yml`, `docker-compose.opencti.yml`,
     `docker-compose.opencti-connectors.yml`.
   - `scripts/setup-supabase.sh` (CLI pin), `scripts/setup-addon.sh` (triage
     trigger), `.github/workflows/{ci,claude,live-vm}.yml`,
     `packages/case-dashboard/frontend/package.json`.
2. **Hunted misses** with tree-wide greps (excluding `.venv`, `node_modules`,
   tests) for `curl|wget|urllib|requests|httpx|hf_hub|snapshot_download|git clone|
   pip install|apt-get|dnf|index-url|extra-index|registry|docker|image:|npm|vite|
   gh auth token|GITHUB_TOKEN`, and inspected each non-test hit.
3. **Verified committed build artifacts** for the portal via `git ls-files`.

No live network fetches were performed. No secrets/tokens/paths recorded.

---

## 2. Confirmed-accurate (independently verified)

These draft claims I re-derived from source and confirm:

- **uv SHA-256 hard-pin** — `SIFT_UV_TARBALL_SHA256` set at `install.sh:167`;
  tarball verified at `install.sh:329`, hard `die` on mismatch `install.sh:340`.
  Offline guard present `install.sh:310-313`. ✔
- **uv arch fallback unhashed (G8)** — `curl -LsSf https://astral.sh/uv/<ver>/install.sh | sh`
  at `install.sh:349`; version-pinned, not hash-verified. ✔
- **Hayabusa** — tag+SHA pinned `install.sh:170-171`; URL `install.sh:972`; SHA
  hard gate `install.sh:996-1002`; ZIP-magic check `install.sh:1003`; offline
  guard `install.sh:976-983`. ✔
- **Supabase CLI** — version `2.105.0` + `SUPABASE_CLI_SHA256` at
  `scripts/setup-supabase.sh:29-31`. ✔
- **OpenSearch core image digest-pinned** —
  `opensearchproject/opensearch@sha256:dbb01641…a31dec` at `docker-compose.yml:7`. ✔
- **OpenCTI image pinning split** — `opensearch:3.5.0` (`:14`), `redis:7.4`
  (`:44`), `rabbitmq:4.0-management` (`:58`) pinned; `minio/minio:latest` (`:75`),
  `opencti/platform:latest` (`:93`), `opencti/worker:latest` (`:151`),
  connectors `:latest` (`opencti-connectors.yml:10,25`) unpinned. ✔
- **BGE model** — name `BAAI/bge-base-en-v1.5`, revision
  `a5beb1e3…240e1a` (`utils.py:54-55`); allowlist-enforced load, revision applied,
  `local_files_only` under offline (`utils.py:81-107`). No content hash of weights. ✔
- **windows-triage downloader has NO offline guard (G2)** — confirmed: no
  `SIFT_OFFLINE`/`is_offline` reference anywhere in `download_databases.py`. ✔
- **Triage source feeds (#22)** — exactly the five repos listed, in
  `update_sources.py:61,71,81,91,99,107` (`VanillaWindowsRegistryHives` appears
  twice as two source keys). ✔
- **GeoIP** — opt-in (`SIFT_GEOIP_ENABLED`, default 0) `install.sh:2480-2483`;
  offline-skipped `install.sh:2484-2487`; endpoint
  `geoip.maps.opensearch.org/v1/geolite2-city/manifest.json` `install.sh:2493`. ✔
- **Zimmerman/EZ tools NOT downloaded** — assumed pre-present at
  `/opt/zimmermantools`, symlinked only `install.sh:1057-1075`. ✔ (draft's anchor
  note is correct.)

---

## 3. Findings requiring change

### [major] M1 — Missing asset: the forensic-rag-mcp online-source subsystem (23 upstream feeds)

The draft's `forensic-rag-mcp` section asserts the RAG tier fetches only the BGE
model (#4) and the optional Chroma bundle (#5), and that the default `direct`
path has "no bundle download." It entirely omits a second, parallel network-fetch
subsystem in the same package.

- **Evidence:** `packages/forensic-rag-mcp/src/rag_mcp/sources.py` defines a
  registry of **23 authoritative upstream sources** (`sources.py:4-11,86-89`) and
  fetches them at runtime via:
  - `git clone --depth 1 https://github.com/{repo}.git` —
    `sources.py:639-642` (SigmaHQ/sigma, redcanaryco/atomic-red-team,
    mitre-attack/{attack-stix-data,car}, DataDog/stratus-red-team, LOLBAS,
    GTFOBins, HijackLibs, LOLDrivers, KAPE, Velociraptor, etc.).
  - `https://api.github.com/repos/{repo}/commits|releases/latest` —
    `sources.py:531,544`.
  - JSON feeds: `https://d3fend.mitre.org/ontologies/d3fend.json`
    (`sources.py:130`), `https://www.cisa.gov/.../known_exploited_vulnerabilities.json`
    (`sources.py:145`).
  - It carries its own `GITHUB_TOKEN` auth path (`sources.py:302`) — the same
    auth-helper the draft tracks only for #5/#6 (#23).
- **Trigger:** `rag_mcp.refresh.refresh(skip_online=False)` — and `skip_online`
  **defaults to `False`** (`refresh.py:73`, used by the `refresh` CLI at
  `refresh.py:449`). It is NOT run by `install.sh` (the only install-path caller,
  `download_index.py:379`, passes `skip_online=True`), so this is a
  **maintenance/runtime** fetch surface — directly analogous to the windows-triage
  `update_sources.py` feeds the draft *did* include as #22.
- **Why it matters:** This is the single largest unpinned external-fetch surface
  in the repo (raw `git clone` HEAD of ~15+ third-party repos + live gov/MITRE
  feeds) and it materially changes the "endpoint traceability" and "private
  GitHub Releases is the highest-trust dependency" conclusions in §3 — these are
  public, mutable, unpinned origins feeding detection/IR knowledge.
- **Required fix:** Add one or more rows for the RAG online-source subsystem
  (mirror #22's treatment): category `data feed`, origins = the GitHub repos +
  `api.github.com` + `d3fend.mitre.org` + `cisa.gov`, pin = unpinned (clone HEAD /
  live feed), trigger = `rag-mcp refresh` (maintenance, `skip_online` default
  False), integrity = host-allowlist validation only (`_validate_url_host`,
  `sources.py:329-348`; HTTPS-only + redirect re-validation), offline = honored
  via `skip_online`. Add `sources.py` origins to the §3 traceability table and to
  the §5 forensic-integrity discussion. Update the `forensic-rag-mcp`
  per-component section so it no longer implies the package is download-free in
  the default path.

### [major] M2 — Asset #24 (CI actions) is materially incomplete; "enumerated all `.github/workflows/*`" is not borne out

The draft (Methodology step 1; row #24; Source Anchors) claims it enumerated all
workflows but only captures `claude.yml` (`actions/checkout@v4`,
`anthropics/claude-code-action@v1`). Two of three workflows are unaccounted for.

- **Evidence:** `.github/workflows/` contains `ci.yml`, `claude.yml`,
  `live-vm.yml`. `ci.yml` additionally pulls:
  `actions/checkout@v6` (`ci.yml:29`), `actions/setup-python@v6` (`ci.yml:32`,
  downloads a Python runtime), `astral-sh/setup-uv@v8.2.0` (`ci.yml:37`,
  downloads uv). `live-vm.yml` also exists and was not inspected by the draft.
- **Why it matters:** Lower severity than M1 (CI-only, no prod-install impact),
  but the draft asserts completeness, and the pinning posture differs (`@v6`/`@v8.2.0`
  vs the `@v4`/`@v1` cited). An auditor relying on the table would miss the uv and
  Python-runtime fetches in CI.
- **Required fix:** Expand #24 (or add rows) to cover `ci.yml`
  (`actions/checkout@v6`, `actions/setup-python@v6`, `astral-sh/setup-uv@v8.2.0`)
  and acknowledge `live-vm.yml`. Correct the Source Anchors line (currently only
  `claude.yml:29,35`).

### [major] M3 — G1 is presented as "undetermined" but is resolvable from the repo (and the determination changes the npm risk story)

G1 states it is "unknown whether `/portal` assets are pre-built/committed or built
out-of-band" and leaves "where the portal's npm deps are actually fetched"
undetermined. The repo answers this definitively.

- **Evidence:** The built Vite bundle is **committed to git**:
  `git ls-files` returns
  `packages/case-dashboard/src/case_dashboard/static/v2/assets/index-Bijo8Grb.js`,
  `…/index-8t46IkMY.css`, `…/index.html`, plus `favicon.svg`/`icons.svg`. The
  installer's rsync excludes `node_modules` (`install.sh:222,234`) but **not**
  `static/v2`, so the prebuilt bundle is staged to the VM. The frontend is
  therefore served from committed assets; **npm deps (#14/#15) are fetched only at
  dev/CI build-time and never on the VM install host.**
- **Why it matters:** This downgrades #14/#15 from an open install-time unknown to
  a build-host-only concern, and it should be stated as a resolved finding, not a
  gap. Leaving it as "needs confirmation" overstates the VM-install attack
  surface.
- **Required fix:** Resolve G1: state that `/portal` is served from committed
  prebuilt assets under `static/v2/` (cite the `git ls-files` paths), staged via
  rsync; npm fetch is build-host-only. Reframe #14/#15 accordingly. (Keep a
  residual note that the committed bundle is opaque — there is no in-repo
  provenance linking the committed `index-*.js` back to a pinned lockfile build,
  which is itself worth a minor flag; see m9.)

---

### [minor] m4 — `latest`-tag semantics mischaracterized for #5/#6 and G3

Both downloaders' `tag="latest"` does **not** resolve GitHub's literal "latest
release." It lists `?per_page=100` and filters for a **tag prefix** —
`rag-index-` (`download_index.py:33,73-78`) / `triage-db-`
(`download_databases.py:82-97`) — returning the newest *matching* release. The
table (#5/#6) and G3 say "tag `latest`" without this nuance, which overstates the
blast radius (an unrelated newest repo release won't be selected).
**Fix:** Note the prefix-filtered resolution in #5/#6 and G3; the residual risk
(newest matching release is still mutable/unpinned for triage) stands and is
correctly flagged.

### [minor] m5 — #6 missing the RAG-style tag-pin asymmetry callout in the row itself

G3 correctly observes install.sh pins the RAG tag (`SIFT_RAG_INDEX_TAG=rag-index-v1`,
`install.sh:179`, passed at `install.sh:837`) but does NOT pin the triage tag
(`setup-addon.sh:509` calls `download_databases` with no `--tag`, so it defaults
to prefix-`latest`). The #6 row's "Version/pin: tag `latest` (default)" is right
but should cross-reference that no install-path override exists (unlike RAG).
**Fix:** add the cross-reference in #6.

### [minor] m6 — `gh`/`GITHUB_TOKEN` auth helper (#23) under-scoped

#23 lists the token helper as gating #5/#6 only. It also gates the M1 RAG
online-source subsystem (`sources.py:302`) and the triage `update_sources.py`
(`update_sources.py:122`). **Fix:** broaden #23's "Assets sourced" to include
#22 and the new M1 rows.

### [minor] m7 — BGE allowlist permits two additional, revision-unpinned models

`utils.py` `ALLOWED_MODELS` also permits `sentence-transformers/all-MiniLM-L6-v2`
and `all-mpnet-base-v2` (`utils.py:40-42`); `resolve_model_revision` returns
`None` (unpinned) for anything but the canonical default unless
`RAG_MODEL_REVISION` is set (`utils.py:67-71`). #4 implies a single pinned model.
**Fix:** add a note that operator-selected alternate models are unpinned.

### [minor] m8 — `setup-python` / `packageManager` corepack fetches unlisted

`package.json` declares `"packageManager": "npm@11.8.0"` and `engines.npm
>=11.8.0` — under corepack this is an auto-downloaded package-manager spec
(build-host fetch). Combined with M2's `actions/setup-python@v6`, these are minor
build/CI fetches absent from the inventory. **Fix:** mention under the frontend /
CI rows as build-host-only.

### [minor] m9 — No provenance link from committed portal bundle to a reproducible build

Following M3: the committed `static/v2/assets/index-*.js` has no in-repo manifest
tying it to a `package-lock.json`-pinned build (no build-info/SRI). For a forensic
product this is a supply-chain-integrity gap worth a §5 line (the served portal JS
is trusted on commit, not on a verifiable build). **Fix:** add a one-line §5 flag.

---

## 4. Missing assets (rows the draft lacks)

| # | Asset | Category | Source / endpoint | Pin | Trigger | Integrity today | Evidence |
|---|-------|----------|-------------------|-----|---------|-----------------|----------|
| 25 | RAG online detection/IR sources (23) | data feed | `git clone HEAD` of SigmaHQ/sigma, redcanaryco/atomic-red-team, mitre-attack/{attack-stix-data,car}, DataDog/stratus-red-team, LOLBAS, GTFOBins, HijackLibs, LOLDrivers, KAPE, Velociraptor, …; `api.github.com/repos/*/commits|releases/latest`; `d3fend.mitre.org/ontologies/d3fend.json`; `cisa.gov/.../known_exploited_vulnerabilities.json` | unpinned (clone HEAD / live feed) | `rag-mcp refresh` (maintenance; `skip_online` default False) | host-allowlist + HTTPS-only + redirect re-validate (`sources.py:329-348`); no content pin | `sources.py:86-145,329-348,531-545,630-642` |
| 26 | CI: `astral-sh/setup-uv@v8.2.0`, `actions/setup-python@v6`, `actions/checkout@v6` | CI only | GitHub Actions marketplace (downloads uv + Python runtime) | tag-pinned | CI (`ci.yml`) | GitHub-managed | `ci.yml:29,32,37` |
| 27 (note, not a row) | corepack `npm@11.8.0` | js tooling | npm registry (corepack) | exact | build-host | n/a | `package.json packageManager` |

(#25 may be split into two rows — git-clone feeds vs JSON/API feeds — at the
author's discretion; the load-bearing requirement is that the subsystem appears.)

---

## 5. False positives / over-flags

- **G2 is correct, not a false positive** — independently confirmed there is no
  offline guard in `download_databases.py`. Keep.
- **No over-flags found** in G1–G9. G1 is not *wrong*, but is resolvable (M3) and
  should move from "gap" to "resolved with residual minor (m9)." G3 is correct in
  substance; only its `latest` wording needs the m4 refinement.
- The draft's exclusion of the many `pip install …` strings (opencti/volatility
  error hints) is **correct** — verified these are user-facing messages, not
  install vectors. Good call.

---

## 6. Signoff readiness — punch list

Not cleared. To reach CLEARED, Inventory must:

1. **M1** — add the forensic-rag online-source subsystem as asset row(s) (#25),
   wire it into §3 traceability and §5 forensic-integrity, and fix the
   `forensic-rag-mcp` section's "no download" claim.
2. **M2** — complete #24 with `ci.yml` actions (checkout@v6, setup-python@v6,
   setup-uv@v8.2.0) and acknowledge `live-vm.yml`; fix the Source Anchors line.
3. **M3** — resolve G1 using the committed `static/v2/` bundle evidence; reframe
   #14/#15 as build-host-only; convert G1 to resolved + residual m9.
4. **m4–m9** — apply the minor refinements (latest-tag prefix semantics, #6
   tag-pin asymmetry, #23 auth-helper scope, BGE alternate-model unpinning,
   corepack/setup-python build fetches, portal-bundle provenance §5 line).

The core of the table (24 rows, pins, hard-pin tiers, OpenCTI/minio/GeoIP
findings) is solid and largely verified; the gaps are completeness (M1/M2/M3),
not correctness of what is present.
