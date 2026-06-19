# 03 — Download / Network-Fetch Asset Inventory

**Status:** DRAFT v2
**Date:** 2026-06-19
**Feeds:** Linear issue **XYE-48** (F0 network-fetch inventory)
**Author:** Inventory agent (static code audit)

> v2 incorporates the round-1 Auditor punch-list (`04-INVENTORY-REVIEW-r1.md`):
> M1 (RAG online-source subsystem added as #25a/#25b), M2 (all 3 CI workflows
> enumerated, #26), M3 (G1 resolved — committed portal bundle), plus minors
> m4–m9. See the **Changelog (v1 → v2)** at the end.

## Scope

Every asset Protocol SIFT Gateway downloads or fetches from a network source
during install, add-on setup, or runtime — traced to its final endpoint, with
version pin, integrity verification, offline behavior, and failure mode. Covers:
OS/system packages, Python deps (uv/PyPI), JS/frontend deps (npm), forensic data
packages and ML models, container images, runtime/TOFU fetches, and add-on
(OpenCTI, windows-triage) feeds.

**Out of scope by policy:** no secrets/tokens/DSNs are recorded; no live network
fetch was performed. This is a pure static read of code, scripts, and manifests.

## Methodology

1. Enumerated all manifests: root `pyproject.toml`, 9 `packages/*/pyproject.toml`,
   `uv.lock`, `package.json` + `package-lock.json`, `supabase/config.toml`, the 3
   `docker-compose*.yml`, and all three `.github/workflows/*` files
   (`ci.yml`, `claude.yml`, `live-vm.yml` — the last is a manual-proof checklist
   with no marketplace actions or fetches).
2. Grepped the whole tree (excluding `.venv`, `node_modules`, test fixtures) for:
   `https?://`, `curl`, `wget`, `git clone`, `pip install`, `uv add`,
   `apt-get install`/`dnf`/`yum`, `download`, `huggingface`/`hf_hub`/
   `snapshot_download`, `github.com/.../releases`, `index-url`, `registry`,
   `npmjs`, `urllib`/`requests`/`httpx`.
3. Read each download helper end-to-end: `install.sh` (3659 lines),
   `scripts/setup-supabase.sh`, `scripts/setup-addon.sh`,
   `packages/forensic-rag-mcp/.../download_index.py`,
   `packages/windows-triage-mcp/.../download_databases.py` +
   `scripts/update_sources.py`, `packages/forensic-rag-mcp/.../utils.py`.
4. Every claim is anchored to `file:line`.

**Pin tiers observed (trust model):**
- **Tier 1 (version + SHA-256 pinned in-repo):** uv, Hayabusa, Supabase CLI. Hard
  fail on mismatch.
- **Tier 2 (TOFU checksum + mutable `latest` tag):** RAG index bundle,
  windows-triage DBs — verify a `*.sha256` file shipped *with* the asset, but the
  release tag defaults to `latest` (mutable).
- **Tier 3 (revision-pinned, live hub):** BGE embedding model from Hugging Face.
- **Tier 4 (unpinned `latest` / mutable):** OpenCTI add-on Docker images, GeoIP
  datasource, windows-triage source-feed git repos, **and the forensic-rag
  online-source subsystem (~22 live `git clone` HEAD / API / gov-JSON feeds —
  the single largest unpinned fetch surface; see #25a/#25b)**.

---

## 1. Master Inventory Table

| # | Asset | Category | Source URL / registry (final endpoint) | Version/pin | Trigger | Destination path | Integrity today | Offline behavior | Approx size | Failure mode |
|---|-------|----------|------------------------------------------|-------------|---------|------------------|-----------------|------------------|-------------|--------------|
| 1 | uv (Python pkg mgr) | binary | `github.com/astral-sh/uv/releases/download/<ver>/uv-x86_64-unknown-linux-gnu.tar.gz`; fallback `astral.sh/uv/<ver>/install.sh` | `0.11.21` + SHA-256 pinned | install-time | `~/.local/bin/uv` | **SHA-256 hard-pin** (`SIFT_UV_TARBALL_SHA256`); arch fallback pipes version-pinned script to `sh` (no hash) | `offline_die` w/ message | ~15 MB | Hard `die` on hash mismatch; fatal if absent and offline |
| 2 | Python workspace deps (`--extra full`) | python | PyPI `https://pypi.org/simple` | per `uv.lock` (228 locked pkgs) | install-time | repo `.venv/` | uv.lock hashes (uv verifies) | sync fails (network) → retry `--reinstall` | tens–hundreds MB | Import smoke-test warns; degraded venv |
| 3 | Hayabusa detection engine + Sigma rules | binary+data-pkg | `github.com/Yamato-Security/hayabusa/releases/download/<tag>/hayabusa-<ver>-lin-x64-gnu.zip` | `v3.9.0` + SHA-256 pinned | install-time | bin → `$SIFT_HOME/bin/hayabusa`; rules → `$SIFT_HOME/hayabusa-rules`; symlink `/usr/local/bin/hayabusa` | **SHA-256 hard-pin** (`SIFT_HAYABUSA_SHA256`) + ZIP magic check | skip w/ warn; stage manually | ~30–50 MB zip; rules ~thousands of `.yml` | Refuse-to-install on mismatch; evtx ingest skips Sigma detection |
| 4 | BGE embedding model | model | Hugging Face Hub `huggingface.co/BAAI/bge-base-en-v1.5` | name + **revision** `a5beb1e3…240e1a` | setup-time (RAG seed) **and** runtime (query/verify) | `$SIFT_HF_HOME` = `/var/lib/sift/.cache/huggingface` | revision pin; verified after load; **no SHA of weights** | `HF_HUB_OFFLINE=1`/`TRANSFORMERS_OFFLINE=1` → local cache only | ~440 MB | Seed warns; pgvector RAG stays on existing rows |
| 5 | RAG knowledge index (ChromaDB bundle) | data-pkg | GitHub Releases API `api.github.com/repos/AppliedIR/sift-mcp/releases` → asset `rag-index.tar.zst` | tag `rag-index-v1` pinned by install.sh; downloader default `latest` = **newest release whose tag begins `rag-index-`** (prefix-filtered, not GitHub's literal "latest") | install-time (**only** if `SIFT_RAG_IMPORT_SOURCE=chroma`; default is `direct`, no download) | `packages/forensic-rag-mcp/data/` | TOFU: verifies `rag-checksums.sha256` shipped with asset | warn + skip | ~1–3 GB | warn; forensic-rag degraded |
| 6 | windows-triage baseline DBs (`known_good.db`, `context.db`) | data-pkg | GitHub Releases API `api.github.com/repos/AppliedIR/sift-mcp/...` → `*.db.zst` + `checksums.sha256` | tag `latest` = **newest release whose tag begins `triage-db-`** (prefix-filtered). **No install-path pin** (`setup-addon.sh` passes no `--tag`) — asymmetric to #5, which install.sh pins | operator-triggered (`setup-addon.sh`) | `$SIFT_WINDOWS_TRIAGE_DB_DIR` → `/var/lib/sift/windows-triage` | TOFU: `checksums.sha256` shipped w/ assets; row-count verify | (no offline guard in downloader — see G2) | known_good ~? + context; baseline (sizes not stated in-repo, G4) | warn; backend starts degraded (UNKNOWN-only) |
| 7 | windows-triage **full registry baseline** (`known_good_registry.db`) | data-pkg | same GitHub Releases API → `known_good_registry.db.zst` | tag `latest` | operator-triggered, **opt-in** (`--with-registry`, disk + confirm gate) | same as #6 | TOFU checksum; ≥15 GB disk gate; row-count verify | n/a | ~500 MB compressed / **~12 GB decompressed** | aborts if <15 GB free / not confirmed |
| 8 | Supabase CLI | binary | `github.com/supabase/cli/releases/download/v<ver>/supabase_<ver>_linux_amd64.tar.gz` | `2.105.0` + SHA-256 pinned | install-time (unless external Supabase / core-only) | `$SIFT_BIN_DIR/supabase` (+ `supabase-go`) | **SHA-256 hard-pin** (`SUPABASE_CLI_SHA256`) | `die` w/ stage instructions | ~? tens MB | Hard `die` on mismatch / no sha256sum |
| 9 | Supabase stack images (`supabase start`) | container | Docker registries via Supabase CLI; Postgres `supabase/postgres:15.8.1.085` (+ gotrue, kong, postgrest, realtime, storage, studio, etc.) | CLI-bundled for v2.105.0; pg pinned `15.8.1.085` | install-time | Docker | image digests resolved by CLI (not pinned in this repo) | requires Docker; no in-repo offline path for images | multi-GB total | `die` if Docker not ready; stack fails |
| 10 | OpenSearch (core) | container | `opensearchproject/opensearch@sha256:dbb01641…a31dec` | **digest-pinned** | install-time (`docker compose up opensearch`) | Docker | **digest pin** (immutable) | Docker pull required; warn+skip if Docker absent | ~1 GB+ | OpenSearch not seeded; backend RED |
| 11 | OS host pkgs: `ripgrep`, `acl` | OS | distro apt repos (Ubuntu/SIFT) | unpinned (apt latest) | install-time | system | apt/distro signing | n/a (apt) | small | `acl` missing → `die`; ripgrep → warn only |
| 12 | OS host pkgs: `yara`, `tshark`, `binwalk` | OS | distro apt repos | unpinned | install-time (best-effort) | system | apt signing | n/a | small | warn-only; agent runs without them |
| 13 | Docker engine + compose plugin | OS | NOT auto-installed; operator action | n/a | pre-req | system | n/a | n/a | n/a | `die`/warn with install hint |
| 14 | Frontend npm deps (runtime: react, recharts, zustand, cmdk, clsx, date-fns) | js | npm registry `registry.npmjs.org` (default) | ranged (`^`) in `package.json`; exact in `package-lock.json` | **dev/CI build-time ONLY** (the built bundle is committed to git; **never fetched on the VM install host** — see resolved G1) | `node_modules/` on build host; built bundle → committed `static/v2/assets/` | npm lockfile integrity hashes | n/a (build host) | tens MB | build fails (no VM-install impact) |
| 15 | Frontend npm devDeps (vite, eslint, vitest, tailwind, postcss, types) | js | `registry.npmjs.org` | ranged + locked | **dev/CI build-time ONLY** | `node_modules/` on build host | lockfile hashes | n/a | hundreds MB | build/lint/test fail (no VM-install impact) |
| 15b | corepack package-manager spec `npm@11.8.0` | js tooling | npm registry (via corepack) | exact (`packageManager` field) | dev/CI build-host only | corepack cache | corepack integrity | n/a | small | build host falls back to system npm |
| 16 | Node.js runtime (engines `>=24.13.1 <25`) | runtime | NOT fetched by repo; operator/CI provides | constraint only | build-time | host | n/a | n/a | n/a | npm refuses on engine mismatch |
| 17 | Volatility3 ISF symbols | runtime | upstream Volatility symbol server (live, first-use) | unpinned | runtime (first memory analysis) | `/var/cache/sift/volatility-symbols` (shared 2775 grp `sift`) | none in-repo | warm-cache trick; otherwise fails offline | varies | vol plugins fail / hang offline |
| 18 | OpenSearch GeoIP datasource (ip2geo / GeoLite2) | data-pkg | `https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json` | unpinned, live unauth endpoint | install-time **opt-in** (`SIFT_GEOIP_ENABLED=1`, default OFF) | OpenSearch ip2geo datasource | none | always skipped offline | ~tens MB | warn; no geo enrichment |
| 19 | OpenCTI platform + worker | container | `opencti/platform:latest`, `opencti/worker:latest` | **`:latest` (unpinned)** | operator-triggered add-on (`SIFT_OPENCTI_ENABLED=true`) | Docker | none (mutable tag) | Docker pull required | multi-GB | add-on not healthy in 5 min → warn |
| 20 | OpenCTI deps: opensearch 3.5.0, redis 7.4, rabbitmq 4.0-management, minio:latest | container | Docker Hub | pinned except `minio/minio:latest` | operator-triggered add-on | Docker | mixed (minio unpinned) | Docker pull required | multi-GB | stack unhealthy |
| 21 | OpenCTI connectors: MITRE, CISA-KEV | container + data feed | `opencti/connector-mitre:latest`, `opencti/connector-cisa-known-exploited-vulnerabilities:latest`; connectors then pull MITRE ATT&CK / CISA-KEV feeds at runtime | `:latest` images; feeds unpinned | operator-triggered add-on | Docker | none | Docker + live feeds | varies | connectors degraded |
| 22 | windows-triage source feeds (LOLBAS, LOLDrivers, HijackLibs, VanillaWindowsReference, VanillaWindowsRegistryHives) | data feed | `git clone` of `github.com/LOLBAS-Project/LOLBAS`, `magicsword-io/LOLDrivers`, `wietze/HijackLibs`, `AndrewRathbun/VanillaWindows*`; + `api.github.com` commit metadata | unpinned (shallow clone HEAD) | operator-triggered (`update_sources.py`, maintenance/refresh) | clone dir → imported into `context.db`/registry DB | none (raw clone HEAD) | requires network | varies (Vanilla* large) | update fails; DB stale |
| 23 | `gh` CLI / `GITHUB_TOKEN` auth helper | (auth helper) | `gh auth token` / `GITHUB_TOKEN` env | n/a | install/setup/maintenance helper | in-memory header | n/a | n/a | n/a | falls back to anon GitHub API (rate-limited). **Gates #5, #6/#7, #22 (`update_sources.py:122`), AND #25a/#25b (`sources.py:302`)** |
| 24 | CI (`claude.yml`): `actions/checkout@v4`, `anthropics/claude-code-action@v1` | (CI only) | GitHub Actions marketplace | tag-pinned (`@v4`,`@v1`) | CI (not install) | runner | GitHub-managed | n/a | n/a | CI workflow fails (no prod impact) |
| 25a | RAG online detection/IR **git feeds** (20 repos: SigmaHQ/sigma, redcanaryco/atomic-red-team, mitre-attack/{attack-stix-data,car}, mitre-atlas/atlas-data, mitre/{engage,cti}, DataDog/stratus-red-team, elastic/detection-rules, splunk/security_content, LOLBAS-Project/LOLBAS, GTFOBins/GTFOBins.github.io, wietze/HijackLibs, magicsword-io/LOLDrivers, ForensicArtifacts/artifacts, EricZimmerman/KapeFiles, Velocidex/velociraptor-docs, MBCProject/mbc-stix2.1, WithSecureLabs/chainsaw, Yamato-Security/hayabusa-rules) | data feed | `git clone --depth 1 --branch <b> https://github.com/<repo>.git` + `api.github.com/repos/<repo>/commits|releases/latest` (version check) | **unpinned (clone HEAD of branch; live API)** | **maintenance/runtime** — `rag-mcp refresh` (`skip_online` **defaults False**); NOT run by install.sh (`download_index.py:379` passes `skip_online=True`) | clone temp → parsed → embedded into pgvector/index | host-allowlist (`api.github.com`,`github.com`,`raw.githubusercontent.com`) + HTTPS-only + IP-literal block + 60 MB cap on the API/JSON fetch path only (`git clone` itself is **uncapped**, `sources.py:642`); **no content pin** | honored via `skip_online=True` | varies (ATT&CK STIX ~50 MB; KapeFiles/atomic large) | refresh of that source fails; KB stale |
| 25b | RAG online **JSON/gov feeds** (MITRE D3FEND, CISA KEV) | data feed | `https://d3fend.mitre.org/ontologies/d3fend.json`, `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | **unpinned, live** | maintenance/runtime — `rag-mcp refresh` (`skip_online` default False) | fetched → parsed → embedded | host-allowlist (`d3fend.mitre.org`,`www.cisa.gov`,`atlas.mitre.org`) + HTTPS-only + 60 MB cap; **no content pin** | honored via `skip_online=True` | a few–tens MB | that feed's records stale |
| 26 | CI (`ci.yml`): `actions/checkout@v6`, `actions/setup-python@v6` (downloads a Python runtime), `astral-sh/setup-uv@v8.2.0` (downloads uv) | CI only | GitHub Actions marketplace | tag-pinned (`@v6`/`@v6`/`@v8.2.0`) | CI (not install) | runner | GitHub-managed | n/a | runtime/uv | CI fails (no prod-install impact) |

---

## 2. Per-Component Breakdown

### Gateway / sift-core / sift-common / case-dashboard (portal backend)
- **Python deps** (#2) from PyPI via `uv.lock`. Gateway pulls `fastapi`,
  `fastmcp>=3`, `uvicorn`, `starlette`, `httpx`, `bcrypt`, `jsonschema`,
  `psycopg[binary]` (`packages/sift-gateway/pyproject.toml:10`). sift-core/common
  are pure-Python + `pyyaml`. Installed as the single `--extra full` sync
  (`install.sh:505`).
- **uv** itself (#1) — `install.sh:296-354`.
- No direct external data downloads for the gateway tier.

### Portal frontend (case-dashboard/frontend, Vite+React)
- **The built bundle is committed to git** and served from there — there is **no
  npm fetch on the VM install host** (G1 resolved). `git ls-files` shows the
  prebuilt Vite output at
  `packages/case-dashboard/src/case_dashboard/static/v2/assets/index-Bijo8Grb.js`,
  `…/index-8t46IkMY.css`, `…/index.html` (+ `favicon.svg`, `icons.svg`). The
  installer's rsync excludes `node_modules` (`install.sh:222,234`) but **not**
  `static/v2`, so the committed assets are staged to the VM.
- **npm runtime deps** (#14) and **devDeps** (#15) from `registry.npmjs.org`
  (`packages/case-dashboard/frontend/package.json`, `package-lock.json`; React 19,
  recharts, zustand, cmdk, Vite 8) are therefore **build-host-only** (dev/CI),
  never fetched during VM install. Corepack `npm@11.8.0` (#15b) is likewise a
  build-host fetch.
- **Node** engine constraint `>=24.13.1 <25` (#16) — not fetched by the repo.
- **Residual flag (m9):** the committed `index-*.js`/`.css` have no in-repo
  provenance manifest (no build-info / SRI) tying them back to a
  `package-lock.json`-pinned build → the served portal JS is trusted on commit,
  not on a verifiable build. See §5.

### OpenSearch (core, first-party)
- **Container image** (#10): digest-pinned `opensearchproject/opensearch@sha256:dbb01641…`
  (`docker-compose.yml:7`). Brought up by `start_opensearch`
  (`install.sh:2406-2451`).
- **Python deps**: `opensearch-py`, `evtx`, `regipy`, `defusedxml`, `fastmcp`
  (`packages/opensearch-mcp/pyproject.toml:7-17`) via PyPI.
- **GeoIP datasource** (#18): opt-in live fetch
  (`install.sh:2476-2518`; also `setup-opensearch.sh:186`).
- Templates/pipelines/detector hygiene are **API calls to local loopback :9200**,
  not external downloads (`install.sh:2453-2662`).

### forensic-rag-mcp / pgvector (RAG, core knowledge)
This package has **two independent network-fetch subsystems** — it is NOT
download-free even on the default install path.

- **Embedding model** (#4): BGE from HF Hub, revision-pinned
  (`packages/forensic-rag-mcp/src/rag_mcp/utils.py:46-107`; install seed
  `install.sh:875-931`). The default *install* path is **`direct`** (embeds bundled
  JSONL knowledge corpus into pgvector) — no *bundle* download, **but the BGE model
  is still fetched** for embedding unless pre-staged. The model allowlist
  (`ALLOWED_MODELS`, `utils.py:40-42`) also permits
  `sentence-transformers/all-MiniLM-L6-v2` and `all-mpnet-base-v2`; for any model
  other than the canonical default, `resolve_model_revision` returns `None`
  (**unpinned**) unless `RAG_MODEL_REVISION` is set (`utils.py:67-71`) — see m7.
- **RAG ChromaDB bundle** (#5): only on `SIFT_RAG_IMPORT_SOURCE=chroma`
  (`install.sh:819-844`, `download_index.py`). Needs `chroma-import` extra
  (`forensic-rag-mcp/pyproject.toml:33-36`).
- **Online-source subsystem (#25a/#25b) — largest unpinned fetch surface in the
  repo.** `sources.py` defines a registry of **23 authoritative upstream sources**
  (`sources.py:4-11,86-291`; one is `embedded`, ~22 are network) covering
  detection rules (Sigma, Elastic, Splunk, Chainsaw, Hayabusa-rules), attack
  frameworks (MITRE ATT&CK/CAR/D3FEND/ATLAS/Engage/CAPEC/MBC), red-team (Atomic,
  Stratus), forensic artifacts (ForensicArtifacts, KAPE, Velociraptor), LOLBins
  (LOLBAS/GTFOBins/HijackLibs/LOLDrivers), and threat intel (CISA KEV). Fetched
  via `git clone --depth 1 --branch <b>` (`sources.py:639-642`), GitHub commit/
  release API (`sources.py:531,544`), and direct gov/MITRE JSON
  (`sources.py:130,145`), all behind a host-allowlist + HTTPS-only + IP-literal
  block + 60 MB cap (`sources.py:329-353,589-604`) and a `GITHUB_TOKEN` auth path
  (`sources.py:299-305`). **Triggered by `rag-mcp refresh`** with `skip_online`
  defaulting to **False** (`refresh.py:70-73,449`). It is **not** invoked by
  `install.sh` (the only install-path caller, `download_index.py:379`, passes
  `skip_online=True`), so it is a maintenance/runtime surface analogous to the
  windows-triage feeds (#22).
- pgvector data is materialized into Supabase Postgres (migration
  `supabase/migrations/202606081400_rag_pgvector.sql`), not downloaded.

### forensic-knowledge
- **No network fetch.** Ships its YAML corpus as package data
  (`packages/forensic-knowledge/data/...`, `pyproject.toml:39`). Install just
  symlinks it (`install.sh:806-817`). The `https://` strings inside the data
  YAMLs are documentation references, not fetch targets.

### Hayabusa / Sigma
- **Binary + bundled rules** (#3): pinned GitHub release
  (`install.sh:952-1031`, pins at `install.sh:170-171`).

### windows-triage-mcp (add-on)
- **Baseline DBs** (#6) and **opt-in 12 GB registry baseline** (#7) from GitHub
  Releases (`download_databases.py`; orchestrated by `setup-addon.sh:499-510`).
- **Source feeds** (#22) via `git clone` for maintenance refresh
  (`scripts/update_sources.py:55-153,217-253`; `importers/lolbas.py:43`).
- **Python deps**: `python-registry`, `zstandard`, `fastmcp`
  (`packages/windows-triage-mcp/pyproject.toml:8-14`); NOT in `full` extra
  (needs `--extra windows-triage`).

### OpenCTI (add-on, external)
- **Container stack** (#19, #20, #21): `docker-compose.opencti.yml` +
  `docker-compose.opencti-connectors.yml`. Mostly `:latest` tags.
- Deployed via `install_opencti` only when `SIFT_OPENCTI_ENABLED=true`
  (`install.sh:2707-2724`); normally via `setup-addon.sh`.
- **Python dep**: `pycti>=6.0` (`packages/opencti-mcp/pyproject.toml:31`),
  `opencti` extra only.

### Supabase / Postgres (control plane)
- **CLI** (#8) pinned (`scripts/setup-supabase.sh:28-31`).
- **Stack images** (#9) pulled by `supabase start`
  (`setup-supabase.sh:261-284`); Postgres pinned `15.8.1.085`
  (`supabase/config.toml:29`).
- Schema from in-repo SQL migrations (`supabase/migrations/`), not downloaded.

---

## 3. Endpoint Traceability (trust-per-origin)

| Endpoint / registry | Assets sourced | Trust posture |
|---------------------|----------------|---------------|
| `pypi.org/simple` | #2 all Python deps (228 locked) | uv.lock hash-verified |
| `registry.npmjs.org` | #14, #15, #15b frontend deps + corepack | lockfile-hash-verified; **build-host-only (never on VM install)** |
| `github.com/astral-sh/uv/releases` + `astral.sh` | #1 uv | SHA-256 hard-pin (fallback script unhashed) |
| `github.com/Yamato-Security/hayabusa/releases` | #3 Hayabusa + rules | SHA-256 hard-pin |
| `github.com/supabase/cli/releases` | #8 Supabase CLI | SHA-256 hard-pin |
| `api.github.com/repos/AppliedIR/sift-mcp/releases` | #5 RAG bundle, #6/#7 triage DBs | TOFU checksum file; **prefix-filtered mutable tag** (`rag-index-`/`triage-db-`); **private repo** (needs `gh`/token) |
| `huggingface.co/BAAI/bge-base-en-v1.5` (+ alt allowlisted models) | #4 embedding model | revision pin (canonical only); alternates unpinned (m7); live hub |
| `github.com/<20 public repos>` (SigmaHQ, redcanaryco, mitre-attack, mitre-atlas, mitre, DataDog, elastic, splunk, LOLBAS-Project, GTFOBins, wietze, magicsword-io, ForensicArtifacts, EricZimmerman, Velocidex, MBCProject, WithSecureLabs, Yamato-Security) | **#25a RAG git feeds** | **raw `git clone` HEAD, no pin**; host-allowlist only |
| `api.github.com` | #5/#6/#7 release metadata, #22, #25a version checks | host-allowlisted; auth via #23 |
| `d3fend.mitre.org`, `www.cisa.gov`, `atlas.mitre.org` | **#25b RAG JSON/gov feeds** | live unpinned; host-allowlist + HTTPS-only |
| Docker Hub / registries (via `docker compose` & supabase CLI) | #9, #10, #19, #20, #21 | #10 digest-pinned; OpenCTI/minio `:latest` unpinned |
| `geoip.maps.opensearch.org` | #18 GeoLite2 | unauth, unpinned, opt-in only |
| `github.com/{LOLBAS-Project,magicsword-io,wietze,AndrewRathbun}` | #22 triage source feeds | raw `git clone` HEAD, no pin |
| distro apt repos | #11, #12 OS pkgs | distro signing |
| GitHub Actions marketplace | #24 (claude.yml), #26 (ci.yml) CI actions | CI-only; tag-pinned |

**Highest-trust install-path dependency:** the **private** `AppliedIR/sift-mcp`
GitHub Releases — RAG bundle (#5) and windows-triage DBs (#6/#7) originate here,
gated on a `gh`/`GITHUB_TOKEN` credential and a prefix-filtered mutable tag.

**Largest unpinned fetch surface overall:** the forensic-rag online-source
subsystem (#25a/#25b) — 22 *public, mutable* origins (20 third-party repos cloned at
HEAD + 2 live MITRE/CISA JSON feeds) feeding detection/IR knowledge.
This materially shifts the per-origin trust story: the riskiest network surface is
not the private release channel but the public, version-unpinned upstreams pulled
by `rag-mcp refresh`. Their only integrity control today is a host-allowlist +
HTTPS-only + size cap — no content/commit pinning.

---

## 4. Verification & Offline Posture Summary

- **Hard-pinned (SHA-256, fatal on mismatch):** uv (#1), Hayabusa (#3), Supabase
  CLI (#8). Digest-pinned: core OpenSearch image (#10).
- **TOFU (checksum file shipped with asset, mutable tag):** RAG bundle (#5),
  triage DBs (#6/#7).
- **Revision-pinned, no content hash:** BGE canonical model (#4); alternate
  allowlisted models are **unpinned** (m7).
- **Unpinned / mutable:** GeoIP (#18), OpenCTI `:latest` images (#19–#21), triage
  source feeds (#22), **RAG online-source subsystem (#25a/#25b — host-allowlist +
  HTTPS-only + 60 MB cap, but no content/commit pin)**, Volatility ISF symbols
  (#17), apt packages (#11–#12).
- **Offline / skip-online honored by:** uv, Hayabusa, Supabase CLI, RAG chroma
  path, RAG model seed (`HF_HUB_OFFLINE`), GeoIP (`SIFT_OFFLINE`); and the RAG
  online-source subsystem via `skip_online=True` (#25a/#25b — install.sh already
  passes this). **NOT honored by:** `download_databases.py` (#6/#7 — no
  `is_offline` guard, G2), `update_sources.py` (#22), Volatility symbol fetch
  (#17), Docker image pulls (#9/#10/OpenCTI).
- **Forensic-integrity note:** the detection/IR knowledge that drives findings is
  seeded/refreshed from version-unpinned public upstreams (#25a/#25b, #22). For a
  forensic product, the lack of commit/content pinning on these feeds means the
  knowledge base is reproducible only to "whatever HEAD was at refresh time" —
  worth a pinning/lockfile follow-up in the install blueprint.

---

## 5. Gaps & Unknowns (flagged findings for XYE-48)

- **G1 — RESOLVED (was: frontend build not in installer).** The portal is served
  from a **prebuilt Vite bundle committed to git** under
  `packages/case-dashboard/src/case_dashboard/static/v2/`
  (`assets/index-Bijo8Grb.js`, `assets/index-8t46IkMY.css`, `index.html`,
  `favicon.svg`, `icons.svg`; confirmed via `git ls-files`). The installer rsync
  excludes `node_modules` but **not** `static/v2` (`install.sh:222,234`), so the
  committed assets stage to the VM. **npm (#14/#15/#15b) is therefore fetched only
  at dev/CI build-time and never on the VM install host.** Residual minor below.
- **G1-residual (m9) — No provenance from committed bundle to a reproducible
  build.** The committed `static/v2/assets/index-*.js`/`.css` carry no in-repo
  build-info or SRI tying them to a `package-lock.json`-pinned build, so the served
  portal JS is trusted on commit, not on a verifiable build. Supply-chain-integrity
  gap worth a blueprint follow-up (e.g. checked-in build manifest / SRI / CI
  attestation).
- **G2 — windows-triage downloader has no offline guard.**
  `download_databases.py` (#6/#7) never checks `SIFT_OFFLINE`/`is_offline`, unlike
  the install.sh binary downloads (`download_databases.py:227-361`). Will attempt
  network even in a hardened/air-gapped install.
- **G3 — `latest`-tag resolution for first-party data assets.** RAG bundle and
  triage DBs default to `tag="latest"`, which is **not** GitHub's literal latest
  release: each downloader lists `?per_page=100` and selects the newest release
  whose tag begins with a fixed prefix — `rag-index-` (`download_index.py:33,73-78`)
  / `triage-db-` (`download_databases.py:82-97`). So an unrelated newest repo
  release is not selected; the residual risk is that the newest *matching* release
  is still mutable. install.sh pins the RAG tag (`rag-index-v1`,
  `install.sh:179,837`) but `setup-addon.sh:509` passes **no `--tag`** for triage
  DBs → triage DBs remain prefix-`latest` (effectively unpinned), asymmetric to
  RAG (m4/m5).
- **G4 — Exact sizes/digests of #6 baseline DBs unknown.** Only the registry
  baseline size (~500 MB/~12 GB) is documented (`download_databases.py:39-45`);
  `known_good.db`/`context.db` sizes are not stated in-repo. → size column
  partially unknown.
- **G5 — Supabase stack image set not enumerated in-repo.** `supabase start`
  pulls gotrue/kong/postgrest/realtime/storage/studio/etc.; only Postgres
  (`15.8.1.085`) is named (`config.toml:29`). Full image list + digests are
  CLI-internal → not auditable from this repo alone.
- **G6 — Volatility ISF symbol endpoint not pinned/asserted in repo.** Referenced
  only as a runtime cache dir (`install.sh:127-135`). The actual symbol-server
  URL lives in the `volatility3` PyPI package, not this repo → endpoint
  undetermined here.
- **G7 — OpenCTI connectors pull external threat feeds at runtime** (MITRE ATT&CK,
  CISA-KEV) inside the connector containers; those feed URLs are not in this repo
  (`docker-compose.opencti-connectors.yml:10,25`). → endpoints undetermined here.
- **G8 — `uv` arch-fallback path is unhashed.** Non-x86_64 hosts fall back to
  `curl … astral.sh/uv/<ver>/install.sh | sh` (`install.sh:349`) — version-pinned
  but the piped script and its payload are **not** SHA-verified.
- **G9 — minio image `:latest`** in the OpenCTI stack (`docker-compose.opencti.yml:75`)
  is unpinned within an otherwise mostly-pinned dep set.
- **G10 — RAG online-source subsystem (#25a/#25b) has no content/commit pinning.**
  ~22 public upstreams are pulled at `git clone` HEAD / live-feed with only a
  host-allowlist + HTTPS-only + 60 MB cap (`sources.py:329-353,589-604`); no
  per-source commit/tag/hash pin and no offline-staging path beyond
  `skip_online`. Largest unpinned surface; reproducibility of the IR knowledge
  base is HEAD-at-refresh-time. (Endpoints are fully determined here — this is a
  pinning *gap*, not an unknown.)
- **G11 — RAG alternate embedding models unpinned (m7).** `ALLOWED_MODELS`
  permits `all-MiniLM-L6-v2` / `all-mpnet-base-v2` with `resolve_model_revision`
  returning `None` unless `RAG_MODEL_REVISION` is set (`utils.py:40-42,67-71`);
  only the canonical `bge-base-en-v1.5` is revision-pinned.

---

## 6. Source Anchors (primary)

- Pins & offline helpers: `install.sh:41-70,155-188`
- uv: `install.sh:296-354`
- apt host pkgs: `install.sh:356-404,1116-1160`
- Hayabusa: `install.sh:170-171,952-1055`
- Zimmerman/EZ symlinks (assumes `/opt/zimmermantools` present, not downloaded):
  `install.sh:1057-1110`
- RAG model seed / HF cache: `install.sh:187,651-657,875-931`;
  model name/revision `forensic-rag-mcp/src/rag_mcp/utils.py:46-107`
- RAG chroma bundle: `install.sh:819-844`; `forensic-rag-mcp/src/rag_mcp/scripts/download_index.py:29-90`
- RAG online-source subsystem (#25a/#25b): registry
  `forensic-rag-mcp/src/rag_mcp/sources.py:89-291`; clone
  `sources.py:639-642`; API `sources.py:531,544`; JSON feeds `sources.py:130,145`;
  allowlist/SSRF/cap `sources.py:329-353,589-604`; auth `sources.py:299-305`;
  trigger/skip_online `forensic-rag-mcp/src/rag_mcp/refresh.py:70-73,127,449`;
  install passes skip_online=True `download_index.py:379`
- BGE alternate models (m7): `forensic-rag-mcp/src/rag_mcp/utils.py:40-42,67-71`
- OpenSearch image/up/templates/geoip: `docker-compose.yml:7`;
  `install.sh:2406-2662`; `packages/opensearch-mcp/scripts/setup-opensearch.sh:106,186`
- OpenCTI: `install.sh:2668-2724`; `docker-compose.opencti.yml:14,44,58,75,93,151`;
  `docker-compose.opencti-connectors.yml:10,25`
- Supabase CLI + stack: `scripts/setup-supabase.sh:28-31,261-284`;
  `supabase/config.toml:29`
- windows-triage DBs: `packages/windows-triage-mcp/src/windows_triage_mcp/scripts/download_databases.py:37-45,74-107,227-361`;
  `scripts/setup-addon.sh:499-510`
- windows-triage source feeds: `packages/windows-triage-mcp/scripts/update_sources.py:55-153,217-253`;
  `packages/windows-triage-mcp/src/windows_triage_mcp/importers/lolbas.py:43,115`
- Frontend deps: `packages/case-dashboard/frontend/package.json`
- PyPI registry: `uv.lock` (`source = { registry = "https://pypi.org/simple" }`)
- CI actions: `.github/workflows/claude.yml:29,35`;
  `.github/workflows/ci.yml:29,32,37`; `.github/workflows/live-vm.yml` (manual
  proof checklist — no marketplace actions / fetches)
- Committed portal bundle (G1 resolved): `git ls-files
  packages/case-dashboard/src/case_dashboard/static/v2/`; rsync staging
  `install.sh:222,234`
- corepack packageManager (#15b): `packages/case-dashboard/frontend/package.json`
  (`"packageManager": "npm@11.8.0"`)

---

## 7. Changelog (v1 → v2)

Addresses every item in `04-INVENTORY-REVIEW-r1.md`:

- **M1 (major) — RAG online-source subsystem added.** New rows **#25a** (20 git
  `clone` HEAD feeds + GitHub API) and **#25b** (MITRE D3FEND / CISA KEV JSON).
  Rewrote the `forensic-rag-mcp` per-component section (no longer claims the
  default path is download-free), added the origins to §3 traceability, changed
  the "highest-trust dependency" conclusion to call out this subsystem as the
  largest unpinned surface, and added a §4 forensic-integrity note + new gap
  **G10**. Anchored to `sources.py` / `refresh.py`.
- **M2 (major) — CI fully enumerated.** Row **#24** scoped to `claude.yml`; new
  row **#26** for `ci.yml` (`actions/checkout@v6`, `actions/setup-python@v6`,
  `astral-sh/setup-uv@v8.2.0`); `live-vm.yml` acknowledged (manual checklist, no
  fetches). Methodology + Source Anchors corrected.
- **M3 (major) — G1 resolved.** G1 reclassified from "undetermined" to RESOLVED:
  portal served from committed `static/v2/` bundle (cited `git ls-files` paths),
  staged via rsync; #14/#15 reframed as build-host-only. Residual supply-chain
  provenance flag retained as **G1-residual / m9**.
- **m4** — #5/#6 and G3 now state the prefix-filtered (`rag-index-`/`triage-db-`)
  `latest` resolution rather than literal "latest."
- **m5** — #6 + G3 now cross-reference the triage-vs-RAG tag-pin asymmetry
  (`setup-addon.sh:509` passes no `--tag`).
- **m6** — #23 broadened: the `gh`/`GITHUB_TOKEN` helper also gates #22 and
  #25a/#25b.
- **m7** — #4 / forensic-rag section / §4 note the two unpinned alternate
  allowlisted models; new gap **G11**.
- **m8** — corepack `npm@11.8.0` (#15b) and `actions/setup-python@v6` (#26) added
  as build-host/CI fetches.
- **m9** — committed-portal-bundle provenance flag added to §5 (G1-residual) and
  the frontend per-component section.

No correctness changes to the original 24 rows (the Auditor confirmed them
accurate); v2 is purely completeness + the requested refinements. Still: no
secrets recorded, no live fetches performed, every new row anchored to
`file:line`.
