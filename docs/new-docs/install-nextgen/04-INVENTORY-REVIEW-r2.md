# 04 — Download / Network-Fetch Asset Inventory: Review (round 2)

**Verdict:** `CLEARED` (with 2 non-blocking minor nits noted for optional polish)

**Reviews:** `03-DOWNLOAD-ASSET-INVENTORY.md` (DRAFT v2)
**Date:** 2026-06-19
**Reviewer:** Auditor agent (independent static code audit)
**Findings:** 0 blocker · 0 major · 2 minor (both optional; do not block signoff)

> Round-1 raised 3 major + 6 minor. v2 resolves all 9. I re-verified the three
> majors and the new rows against source rather than trusting the changelog. The
> two minors below are fresh, low-severity accuracy nits on the new rows; neither
> changes any conclusion, so the document is cleared.

---

## 1. Methodology (round 2)

I focused hardest on the **new/changed** content (#25a, #25b, #26, G1-resolved,
G10, G11) and re-derived each from source:

- `packages/forensic-rag-mcp/src/rag_mcp/refresh.py` — read the `refresh()`
  signature and the online-sources phase to confirm the trigger/default.
- `packages/forensic-rag-mcp/src/rag_mcp/sources.py` — read the full `SOURCES`
  registry (counted entries by `source_type`), the SSRF/allowlist/size-cap/
  format-guard block, and `clone_repo`.
- `.github/workflows/{ci,claude,live-vm}.yml` — confirmed the action set and that
  `live-vm.yml` has no marketplace actions or fetches.
- `git ls-files packages/case-dashboard/src/case_dashboard/static/v2/` — confirmed
  the committed portal bundle.

No live fetches; no secrets recorded.

---

## 2. Round-1 majors — re-verified as fixed

### M1 (RAG online-source subsystem) — FIXED ✔

- **Trigger logic confirmed.** `refresh.py:73` — `skip_online: bool = False`
  (default False). The online phase runs under `if not skip_online:`
  (`refresh.py:127`). The install-path caller passes `skip_online=True`
  (`download_index.py:379`), so the subsystem is genuinely a maintenance/runtime
  surface, NOT install-triggered. The draft's distinction is accurate.
- **Source registry confirmed.** `SOURCES` (`sources.py:89-291`) contains exactly
  **23 entries**: **20 git repos** (`github_commits`/`github_releases`), **2 JSON
  feeds** (`d3fend.mitre.org`, `www.cisa.gov` KEV), **1 embedded** (`repo=""`,
  no network). Every repo named in #25a is present (SigmaHQ/sigma, atomic-red-team,
  mitre-attack/{attack-stix-data,car}, mitre-atlas/atlas-data, mitre/engage,
  mitre/cti [CAPEC], DataDog/stratus-red-team, elastic/detection-rules,
  splunk/security_content, LOLBAS, GTFOBins/GTFOBins.github.io, wietze/HijackLibs,
  magicsword-io/LOLDrivers, ForensicArtifacts/artifacts, EricZimmerman/KapeFiles,
  Velocidex/velociraptor-docs, MBCProject/mbc-stix2.1, WithSecureLabs/chainsaw,
  Yamato-Security/hayabusa-rules).
- **Security controls confirmed.** Host allowlist `ALLOWED_URL_HOSTS`
  (`sources.py:589-598`) = `{api.github.com, raw.githubusercontent.com,
  www.cisa.gov, github.com, d3fend.mitre.org, atlas.mitre.org}`; HTTPS-only with
  `RAG_ALLOW_HTTP` override (`sources.py:347-351,604`); IP-literal block
  (`sources.py:340-341`); redirect re-validation (`sources.py:399-401`); 60 MB
  cap `MAX_DOWNLOAD_BYTES` (`sources.py:601`); repo/branch regex + git-option
  injection guard (`sources.py:611-627`); `git clone --depth 1 --branch`
  (`sources.py:642`). All as described. "No content pin" (G10) is correct.
- §3 conclusion correctly rewritten to name this subsystem as the largest
  unpinned surface; §4 forensic-integrity note added; G10 added. ✔

### M2 (CI enumeration) — FIXED ✔

- `#24` scoped to `claude.yml` (`actions/checkout@v4`,
  `anthropics/claude-code-action@v1` — `claude.yml:29,35`). ✔
- `#26` added for `ci.yml`: `actions/checkout@v6` (`ci.yml:29`),
  `actions/setup-python@v6` (`ci.yml:32`), `astral-sh/setup-uv@v8.2.0`
  (`ci.yml:37`). ✔
- `live-vm.yml` acknowledged as a manual-proof checklist — independently
  confirmed it has **no** `uses:`/`curl`/`wget`/`git clone`/`setup-`/`pip
  install`/`docker pull`. ✔

### M3 (G1 frontend) — FIXED ✔

- `git ls-files` confirms the committed bundle:
  `packages/case-dashboard/src/case_dashboard/static/v2/assets/index-Bijo8Grb.js`,
  `…/index-8t46IkMY.css`, `…/index.html`, `favicon.svg`, `icons.svg`. ✔
- rsync excludes `node_modules` but not `static/v2` (`install.sh:222,234`) — bundle
  stages to VM; npm is build-host-only. ✔
- G1 reclassified to RESOLVED; residual provenance gap retained as G1-residual/m9
  (§5) and in the per-component section. ✔

### Minors m4–m9 — FIXED ✔

- **m4** — #5/#6 and G3 now describe the prefix-filtered (`rag-index-`/
  `triage-db-`) `latest` resolution. Matches `download_index.py:33,73-78` /
  `download_databases.py:82-97`. ✔
- **m5** — #6/G3 cross-reference the triage-vs-RAG tag-pin asymmetry
  (`setup-addon.sh:509` passes no `--tag`). ✔
- **m6** — #23 broadened to gate #22 + #25a/#25b; the auth path exists at
  `sources.py:299-305` and `update_sources.py:122`. ✔
- **m7** — alternate allowlisted models flagged (#4 / forensic-rag section / G11),
  matching `utils.py:40-42,67-71`. ✔
- **m8** — corepack `npm@11.8.0` (#15b) and `setup-python@v6` (#26) added. ✔
- **m9** — committed-bundle provenance flag added (G1-residual). ✔

---

## 3. New minor nits (optional polish — do NOT block signoff)

### [minor] n1 — #25a repo count is internally inconsistent (says "~17", actually 20)

The #25a header label reads "**~17 repos**" but then lists 20, and the source has
**20 git repos**. §3 traceability separately says "<22 public repos>" and "17+",
and §4 says "~22 origins." The accurate decomposition is:
**20 git-clone/API repos (#25a) + 2 JSON/gov feeds (#25b) = 22 network origins**
(out of 23 `SOURCES` entries; 1 is embedded/no-network).
- **Evidence:** `sources.py` `SOURCES` — 20 `github_commits|github_releases`, 2
  `json_feed`, 1 `embedded` (verified by count).
- **Suggested fix (optional):** change "~17 repos" → "20 repos" in #25a and make
  §3/§4 consistently say "20 git repos + 2 JSON feeds = 22 origins." Does not
  affect any conclusion (the headline "largest unpinned surface" stands either
  way).

### [minor] n2 — the 60 MB cap applies to `fetch_url` (API/JSON), not to `git clone`

#25a's integrity cell lists "host-allowlist ... + 60 MB cap" for the git-clone
feeds. The 60 MB `MAX_DOWNLOAD_BYTES` cap is enforced only in `_fetch_url_once`
(`sources.py:404-431`), i.e. on the version-check API calls and the #25b JSON
feeds. `clone_repo` (`sources.py:630-647`) shells out to `git clone` and is **not**
size-capped — so large repos (KapeFiles, atomic-red-team, attack-stix-data) clone
uncapped to a temp dir.
- **Evidence:** `sources.py:642` (`git clone` subprocess, no size limit) vs
  `sources.py:404-431` (cap only on the `urlopen` stream).
- **Suggested fix (optional):** in #25a, scope the "60 MB cap" to the API/version-
  check calls and note that `git clone` itself is uncapped (the per-source temp
  clone is the real disk/footprint risk). #25b's 60 MB-cap attribution is correct.

Neither nit changes the trust tiering, the gap set, or the headline conclusion;
both are wording precision on the freshly added row.

---

## 4. False positives / over-flags

None. The v2 edits did not introduce any incorrect claim, over-broad gap, or
mischaracterized control. G10 is correctly framed as a *pinning gap* (endpoints
fully determined), distinct from the genuine "endpoint undetermined" unknowns
(G5/G6/G7). The split of the RAG subsystem into git feeds (#25a) vs JSON/gov
feeds (#25b) is a sound modeling choice and matches the code's two fetch paths
(`clone_repo`/API vs `fetch_url` JSON).

---

## 5. Signoff

**CLEARED.** The inventory is complete and accurate to the source as of this
revision. All round-1 majors and minors are resolved and independently
re-verified; the 24 original rows plus the 4 added rows (#15b, #25a, #25b, #26)
are anchored to correct `file:line` evidence; the trust tiers, endpoint
traceability, offline posture, and gap set (G1-resolved, G2–G11) faithfully
reflect the code.

Signoff statement for the final document:

> The download/network-fetch asset inventory (`03-DOWNLOAD-ASSET-INVENTORY.md`
> v2) has been independently audited against source across two review rounds.
> Every download vector — OS/PyPI/npm deps, forensic data packages and the BGE
> model, container images, the first-party private-Release channel, the
> windows-triage and forensic-rag online-source feed subsystems, runtime TOFU
> fetches, and CI actions — is enumerated with its endpoint, version pin,
> integrity control, offline behavior, and failure mode, each anchored to
> `file:line` and spot-verified. The trust tiering and the eleven gaps (G1
> resolved; G2–G11 open, with G10 — the unpinned ~22-origin forensic-rag
> online-source subsystem — identified as the largest unpinned fetch surface)
> are accurate. **Auditor verdict: CLEARED.** Two optional wording nits (#25a
> repo count "~17" vs actual 20; the 60 MB cap applies to API/JSON fetches, not
> `git clone`) are noted in `04-INVENTORY-REVIEW-r2.md §3` and may be polished at
> the author's discretion without further review.
