# Reference Data Provenance Manual

**BATCH-OR4** — RAG, forensic knowledge, and Hayabusa provenance.
Last updated: 2026-06-12.

This document answers, for each reference-data plane: what was downloaded,
from where, why, where it is stored, how to refresh it, how to disable it, and
how to run offline. It also contains an external-download ledger for installer
hardening and a list of stale claims in `docs/regenerate/**` for BATCH-RG1.

---

## Policy statement

**RAG is knowledge/reference-only in Supabase pgvector.** Case evidence must
not be silently embedded into shared RAG without an explicit future design.

The `app.rag_chunks` / `app.rag_documents` / `app.rag_collections` tables store
shared forensic reference knowledge (`kind='knowledge'`, `case_id NULL`).
Per-case derived content (`kind='derived'`) is **blocked** by both the Python
ingest layer (`pgvector_seed.py`, `pgvector_store.py`) and a DB BEFORE INSERT
trigger. Agents never receive DB credentials or case-level paths through the RAG
plane. All output from `kb_search_knowledge` is sanitised before it leaves the
process (path fields redacted, embedding fields stripped).

---

## 1. RAG Plane (forensic-rag-mcp / Supabase pgvector)

### 1.1 What seeds it

The knowledge corpus is seeded from two sources, controlled by the
`SIFT_RAG_IMPORT_SOURCE` environment variable:

| Source | Env value | Description |
|---|---|---|
| Bundled JSONL knowledge corpus (default) | `direct` (or unset) | `packages/forensic-rag-mcp/knowledge/**/*.jsonl` |
| Legacy pre-built Chroma release bundle | `chroma` | Downloaded from GitHub releases (`AppliedIR/sift-mcp`, tag prefix `rag-index-`) |

The default path (`direct`) is preferred. The `chroma` path is a compatibility
option for existing large pre-built snapshots or for operators who need the
full 22 000+ record corpus before on-VM embedding is feasible.

#### Bundled JSONL corpus

Location: `packages/forensic-rag-mcp/knowledge/` in the repo checkout, staged
at `/opt/sift-mcps/packages/forensic-rag-mcp/knowledge/` after install.

Two top-level subcorpora (both shipped in the repo):

| Subcorpus | Path | Approximate records |
|---|---|---|
| AppliedIR analyst references | `knowledge/AppliedIR/*.jsonl` | 570 |
| SANS cheat sheets and posters | `knowledge/SANS/*.jsonl` | 3 748 |

Markers: files containing a `.bundled` sentinel (e.g.
`knowledge/AppliedIR/.bundled`, `knowledge/SANS/.bundled`) identify
subcorpora that ship in the repo under permissive or licensed terms.

Full 22 000+ record corpus sources are listed in
`packages/forensic-rag-mcp/ATTRIBUTION.md` (23 authoritative public
sources including MITRE ATT&CK, Sigma, Elastic Detection Rules, Atomic Red
Team, CAPEC, etc.). Those sources are **not** all downloaded at install time
— they originate from the pre-built Chroma bundle (legacy path) or from a
separate corpus-build step outside this installer.

#### Why

The RAG plane provides semantic search over shared forensic reference
knowledge for agents. Agents call `kb_search_knowledge` to ground their
analysis in authoritative IR/DFIR guidance without touching case evidence.

### 1.2 Embedding model

Default model: `BAAI/bge-base-en-v1.5` (768-dimensional BGE embeddings).

Allowlisted models (`packages/forensic-rag-mcp/src/rag_mcp/utils.py`,
line 29–37):

```
BAAI/bge-base-en-v1.5   (default)
BAAI/bge-small-en-v1.5
BAAI/bge-large-en-v1.5
sentence-transformers/all-MiniLM-L6-v2
sentence-transformers/all-mpnet-base-v2
```

Override at runtime with `RAG_MODEL_NAME` env var. The allowlist prevents
arbitrary model loading.

#### Where the model comes from

The `sentence-transformers` library is installed as a Python dependency via
uv/pip from PyPI. The model weights themselves are downloaded on first use
from Hugging Face Hub (`https://huggingface.co/BAAI/bge-base-en-v1.5`).
Subsequent loads use the Hugging Face local cache (default:
`~/.cache/huggingface/hub/` for the service user, typically
`/var/lib/sift/.cache/huggingface/hub/`).

This download happens the first time either:
- `seed_rag_pgvector_direct` runs (installer seeding, `embedding_mode=model`)
- `kb_search_knowledge` is called and the model is not yet cached

**There is no explicit model cache path configured in the installer.** The
model cache location is controlled by Hugging Face's default
`HF_HOME`/`TRANSFORMERS_CACHE` resolution. On the SIFT VM the service user
is `sift-service` (home `/var/lib/sift`), so the cache typically resolves to
`/var/lib/sift/.cache/huggingface/`.

**Hardening note:** the model download is **unpinned and unauthenticated**
(no SHA-256 or signature check in the installer). See the external-download
ledger in section 4.

#### Seeding flow (default `direct` path)

```
install.sh: seed_rag_pgvector_direct()
  -> uv run rag-mcp-seed-pgvector
     -> pgvector_seed.py: plan_knowledge_seed(knowledge_dir)
        -> scans knowledge/**/*.jsonl
        -> for each record: SentenceTransformer(model).encode(text)
        -> PgVectorRagStore.upsert_chunk(..., kind='knowledge', case_id=None)
           -> Supabase pgvector: app.rag_chunks
```

Source references:
- `install.sh`: lines 692–736 (`seed_rag_pgvector_direct`, `load_rag_pgvector`)
- `packages/forensic-rag-mcp/src/rag_mcp/pgvector_seed.py`: full seeding logic
- `packages/forensic-rag-mcp/src/rag_mcp/pgvector_store.py`: storage layer
- `packages/forensic-rag-mcp/src/rag_mcp/utils.py`: model allowlist

#### Seeding flow (legacy `chroma` path)

```
install.sh: download_rag_index()
  -> python -m rag_mcp.scripts.download_index --dest <data_dir>
     -> GitHub API: https://api.github.com/repos/AppliedIR/sift-mcp/releases
     -> downloads: rag-index.tar.zst + rag-checksums.sha256
     -> SHA-256 verified against bundled checksum file
     -> extracts to packages/forensic-rag-mcp/data/chroma/

install.sh: import_rag_pgvector()
  -> uv run rag-mcp-import-chroma-pgvector --chroma-dir <chroma_dir>
     -> pgvector_chroma_import.py: reads Chroma collection
        -> embeds records with SentenceTransformer
        -> PgVectorRagStore.upsert_chunk(..., kind='knowledge', case_id=None)
```

Source references:
- `install.sh`: lines 643–690 (`download_rag_index`, `import_rag_pgvector`)
- `packages/forensic-rag-mcp/src/rag_mcp/scripts/download_index.py`
- `packages/forensic-rag-mcp/src/rag_mcp/pgvector_chroma_import.py`

### 1.3 Where stored

| Artefact | Path | Authority |
|---|---|---|
| Knowledge embeddings and metadata | Supabase pgvector: `app.rag_chunks`, `app.rag_documents`, `app.rag_collections` | Supabase/Postgres (authoritative) |
| Bundled JSONL source corpus | `/opt/sift-mcps/packages/forensic-rag-mcp/knowledge/` | Repo checkout (read-only reference) |
| Chroma bundle (legacy path only) | `/opt/sift-mcps/packages/forensic-rag-mcp/data/chroma/` | Derived/rebuildable from GitHub release |
| Hugging Face model cache | `~/.cache/huggingface/hub/` (sift-service home: `/var/lib/sift/.cache/huggingface/`) | Derived/rebuildable from Hugging Face |
| Enrichment dir symlink | `/var/lib/sift/enrichment/forensic-rag/` | Pointer; managed by installer |

### 1.4 Runtime query path

```
Agent -> Gateway: kb_search_knowledge(query)
  -> forensic-rag-mcp server.py: RAGServer._get_embedder()
     -> QueryEmbedder.embed(query) -> SentenceTransformer.encode(query) -> [float * 768]
  -> PgVectorRagStore -> app.rag_search(embedding, top_k, kind='knowledge')
     -> returns hits with provenance_id, content (sanitised, path-free)
```

The DB function `app.rag_search` enforces `kind='knowledge'` unconditionally
at SQL level. Derived content is unreachable at the query layer.

Source references:
- `packages/forensic-rag-mcp/src/rag_mcp/server.py`: `kb_search_knowledge` tool
- `packages/forensic-rag-mcp/src/rag_mcp/query_embedding.py`: `QueryEmbedder`
- `packages/forensic-rag-mcp/src/rag_mcp/pgvector_store.py`: `PgVectorRagStore`

### 1.5 How to refresh

**Re-seed from bundled corpus:**

```bash
cd /opt/sift-mcps
SIFT_CONTROL_PLANE_DSN='<dsn>' .venv/bin/rag-mcp-seed-pgvector \
  --knowledge-dir packages/forensic-rag-mcp/knowledge \
  --embedding-mode model
```

This is idempotent: it uses `ON CONFLICT DO UPDATE` semantics via stable UUIDs
derived from content paths.

**Re-import from Chroma bundle (legacy path):**

```bash
SIFT_CONTROL_PLANE_DSN='<dsn>' .venv/bin/rag-mcp-import-chroma-pgvector \
  --chroma-dir packages/forensic-rag-mcp/data/chroma
```

**Dry-run to check corpus plan without writing:**

```bash
.venv/bin/rag-mcp-seed-pgvector --knowledge-dir packages/forensic-rag-mcp/knowledge \
  --embedding-mode deterministic --dry-run
```

### 1.6 How to disable

Set `SIFT_RAG_ENABLED=false` before running the installer to skip seeding the
`forensic-rag-mcp` backend row in `app.mcp_backends`. The backend will not
be registered and agents will not see the `kb_*` tools.

To disable at runtime without reinstalling: mark the backend row as disabled
in `app.mcp_backends` or remove it. The service must be restarted for the
change to take effect.

### 1.7 How to run offline

The Supabase pgvector store is on-VM and works without internet after seeding.
The only network-dependent steps are:

1. **Model download** (first seed or first query if cache is cold): requires
   Hugging Face Hub access. Pre-warm the cache before going offline:
   ```bash
   python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-base-en-v1.5')"
   ```
2. **Chroma bundle download** (legacy path only): requires GitHub access.
   Pre-download the `rag-index.tar.zst` bundle and place it at the expected
   path, or skip and use the `direct` path instead.

For fully air-gapped installs:
- Use `SIFT_RAG_IMPORT_SOURCE=direct` (default).
- Pre-populate the Hugging Face cache (`~/.cache/huggingface/`) from an
  internet-connected system and transfer it to the VM.
- The bundled JSONL corpus ships in the repo and requires no download.
- Operator decision required: see B-MVP-004 in `docs/migration/Session-Notes.md`.

---

## 2. Forensic Knowledge (forensic-knowledge package)

### 2.1 What it is

The `forensic-knowledge` package (`packages/forensic-knowledge/`) is a
**static, bundled reference library** shipped entirely in the repo. It
requires **no external downloads**. There is no MCP server or stdio transport
for this package — it is a library that other packages import directly.

Source (`packages/forensic-knowledge/sift-backend.json`, line 8):
> "forensic-knowledge is a reference data library consumed by forensic-mcp
> and sift-core. It provides YAML-backed discipline snippets, artifact
> definitions, tool references, playbooks, and investigation frameworks for
> structured DFIR guidance."

### 2.2 Data layout

```
packages/forensic-knowledge/
  data/
    artifacts/
      windows/   (53 YAML files: amcache, prefetch, event_logs_*, shellbags, etc.)
      linux/     (8 YAML files: auth_log, bash_history, syslog, etc.)
    discipline/
      rules.yaml
      anti_patterns.yaml
      confidence.yaml
      evidence_standards.yaml
      evidence_template.yaml
      checkpoints.yaml
      checklists/  (event_logs, filesystem, memory, registry)
      guidance/    (corroboration, false_positives, tool_interpretation)
      playbooks/   (14 YAML files: credential_access, remote_access, etc.)
      framework/   investigation_framework.yaml
    tools/
      browser/ carving/ file_analysis/ hashing/ imaging/ logs/ malware/
      mcp/ memory/ network/ persistence/ registry/ sleuthkit/ timeline/
      triage/ volatility/ zimmerman/  (100+ YAML tool reference files)
```

### 2.3 Repo location and installed location

Repo location: `packages/forensic-knowledge/data/` (checked into the repo,
world-readable under `/opt/sift-mcps/packages/forensic-knowledge/data/`).

Installed location: the installer creates a symlink at install time:

```
/var/lib/sift/enrichment/forensic-knowledge
  -> /opt/sift-mcps/packages/forensic-knowledge/data
```

Source: `install.sh`, `prepare_enrichment_assets()`, lines 630–641.

### 2.4 FK_DATA_DIR wiring

The `FK_DATA_DIR` environment variable points the loader to the data directory
when the package is not importable via `importlib.resources` (e.g. when running
as a system service that does not see the source tree).

The installer writes:

```
/var/lib/sift/.sift/forensic-knowledge.env
```

containing:

```
FK_DATA_DIR=/var/lib/sift/enrichment/forensic-knowledge
```

Both systemd units (`sift-gateway.service`, `sift-job-worker.service`) load
this file via their `EnvironmentFile` directive.

Source: `install.sh`, `write_fk_env()`, lines 1852–1871.

Loader resolution order (`packages/forensic-knowledge/src/forensic_knowledge/loader.py`, lines 24–57):

1. `FK_DATA_DIR` env var (explicit override, used in production)
2. Relative to `__file__` in source tree (`src/forensic_knowledge/loader.py` -> `../../data/`)
3. `importlib.resources` (installed package data)
4. Raises `FileNotFoundError`

### 2.5 Loader call sites

The `forensic_knowledge.loader` module is imported by:

| Package | File | Purpose |
|---|---|---|
| sift-core | `execute/response.py` | Enriches tool-call responses with caveats, advisories, field meanings, corroboration hints |
| sift-core | `case_manager.py` (lines 543, 1939) | Case and finding context injection |
| sift-core | `execute/tools/discovery.py` (line 9) | Tool help cards with FK notes |
| sift-core | `finding_validation.py` (line 13) | Validates findings against FK confidence definitions |

### 2.6 How context injection works

After every tool call (e.g. `run_amcacheparser`, `run_command`, ingest tools),
`sift_core.execute.response.build_response()` calls `_build_knowledge_context()`
which loads artifact caveats, field meanings, corroboration suggestions, and
advisories from the FK YAML files. These are injected as structured fields in
the MCP tool-call response envelope:

```python
response["caveats"]        # accuracy guidance — never truncated
response["field_meanings"] # per-field interpretation notes
response["field_notes"]    # additional field guidance
response["corroboration"]  # suggested corroborating evidence
response["advisories"]     # proactive investigative direction
```

The enrichment is delivered with a decay counter: full enrichment for the
first 3 calls per tool, then every 10th call, to avoid context bloat
(`execute/response.py`, line 178).

### 2.7 How to refresh

The FK corpus is static YAML checked into the repo. To update it:

1. Edit/add YAML files under `packages/forensic-knowledge/data/`.
2. Re-run `./install.sh` to refresh the symlink (if the data dir path
   changed) and the FK env file.
3. Restart services: `sudo systemctl restart sift-gateway.service sift-job-worker.service`

The in-memory YAML cache is populated per-process on first access and cleared
only on restart (`loader.clear_cache()`).

### 2.8 How to disable

FK enrichment is part of `sift-core` and not separately gatable by an env var.
To disable it, either:
- Set an invalid `FK_DATA_DIR` path so `_find_data_dir()` raises (the response
  builder catches the error and returns an empty enrichment silently).
- The enrichment is always attempted but non-fatal; failure logs a warning and
  the tool response is still returned.

### 2.9 How to run offline

No downloads required. The entire FK corpus is bundled in the repo. Fully
offline-capable after install.

---

## 3. Hayabusa

### 3.1 Binary source and install location

**Source:** GitHub releases — `Yamato-Security/hayabusa`

The installer queries the GitHub API for the latest release tag at install time:

```
https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest
```

It then downloads the Linux x64 GNU build:

```
https://github.com/Yamato-Security/hayabusa/releases/download/<tag>/hayabusa-<tag>-lin-x64-gnu.zip
```

**Install location:** `$SIFT_HOME/bin/hayabusa` (`/var/lib/sift/.sift/bin/hayabusa`)
Owned by `sift-service:sift-service`, mode `0755`.

**System symlink:** `/usr/local/bin/hayabusa -> /var/lib/sift/.sift/bin/hayabusa`
Created by `install_hayabusa_system_links()`.

Source: `install.sh`, `install_hayabusa()`, lines 738–803;
`install_hayabusa_system_links()`, lines 805–809.

**Hardening note:** the binary download is **unpinned (latest tag)** and
**has no checksum verification**. The installer validates only that the
downloaded file is a valid ZIP (`file ... | grep -q 'Zip archive'`). See
the download ledger in section 4.

### 3.2 Rules source and install location

Hayabusa rules are **bundled inside the release archive** — the same ZIP
that contains the binary also contains a `rules/` directory.

**Rules location:** `$SIFT_HOME/hayabusa-rules/` (`/var/lib/sift/.sift/hayabusa-rules/`)
Owned by `sift-service:sift-service`.

At runtime the ingest code also searches the following fallback paths
(`ingest.py`, `_HAYABUSA_RULES_CANDIDATES`, lines 308–315):

```
/usr/local/share/hayabusa-rules
/usr/share/hayabusa-rules
/opt/hayabusa/rules
/opt/hayabusa-rules
$HOME/.sift/hayabusa-rules       (service user default)
```

The rules directory must contain a `config/` subdirectory for Hayabusa to
function (`_resolve_hayabusa_rules_dir()`, line 318).

Override: set `HAYABUSA_RULES_DIR` env var to any directory containing the
rules + `config/` subdirectory.

Source: `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`, lines 308–351.

### 3.3 Event-log ingest path

Hayabusa runs as a post-ingest detection phase after EVTX files have been
indexed. Flow:

```
opensearch_mcp.ingest.run_hayabusa_batch(hosts, client, case_id)
  -> shutil.which("hayabusa")  (resolves /usr/local/bin/hayabusa)
  -> _resolve_hayabusa_rules_dir()
  -> subprocess.run([hayabusa, "csv-timeline",
       "-r", <rules_dir>,
       "-c", <rules_dir>/config,
       "-d", <host.evtx_dir>,
       "-o", <csv_output>,
       "-p", "verbose",
       "--no-wizard"])
```

Input: EVTX files under `host.evtx_dir` (a directory in the registered case
evidence tree).

Source: `packages/opensearch-mcp/src/opensearch_mcp/ingest.py`, lines 354–508.

### 3.4 Generated CSV/output paths

CSV output files are written to:

```
$HOME/.sift/hayabusa-output/hayabusa-<case_id>-<hostname>.csv
```

(`sift_dir()` resolves to the service user's `~/.sift/`; on the installed VM
this is `/var/lib/sift/.sift/hayabusa-output/`.)

The path is constructed from sanitised case and hostname components:

```python
output_dir = sift_dir() / "hayabusa-output"
csv_output = output_dir / f"hayabusa-{_cid}-{_hn}.csv"
```

Source: `ingest.py`, lines 375, 413–414.

### 3.5 OpenSearch index pattern

After CSV generation, the results are ingested into OpenSearch under the
index pattern:

```
case-<case_id>-hayabusa-<hostname>
```

Index template: `packages/opensearch-mcp/src/opensearch_mcp/mappings/hayabusa_template.json`
Template index pattern: `case-*-hayabusa-*` (priority 18).

Key mapped fields: `@timestamp`, `Timestamp`, `host.name`, `host.id`,
`Channel`, `EventID`, `Level`, `MitreTactics`, `MitreTags`, `OtherTags`,
`RuleTitle`, `Details`, `ExtraFieldInfo`, `RuleFile`, `EvtxFile`, `RecordID`.

Source: `mappings/hayabusa_template.json`.

### 3.6 How agents query Hayabusa results

Agents use the `opensearch_search` tool from `opensearch-mcp`. The canonical
query pattern for Hayabusa detections is:

```
opensearch_search(query='Level:critical OR Level:high', index='case-*-hayabusa-*')
```

The `opensearch_list_detections` tool checks for OpenSearch Security Analytics
(Sigma) first; if unavailable, it falls back to suggesting the Hayabusa index
pattern (`server.py`, lines 3562–3621).

After `opensearch_ingest` completes, the ingest response includes a
suggested follow-up query when Hayabusa data is present (`server.py`,
lines 2553–2558):

```
Query Hayabusa alerts: opensearch_search(query='Level:critical OR Level:high',
index='case-*-hayabusa-*')
```

Source: `packages/opensearch-mcp/src/opensearch_mcp/server.py`.

### 3.7 Halt condition

If Hayabusa rules are not found for any host in a batch, the ingest writes
a halt-status file so the portal and `opensearch_ingest_status` surface the
reason (`HALT_HAYABUSA_NO_RULES`). This replaces the previous silent-skip
behaviour.

Source: `ingest.py`, lines 482–506.

### 3.8 How to refresh / update rules

Rules ship inside the Hayabusa binary release archive. To update rules:

1. Remove the installed binary to trigger re-install on next `./install.sh`
   run: `sudo rm /var/lib/sift/.sift/bin/hayabusa`
2. Re-run `./install.sh` (the installer checks for binary presence and skips
   if already installed).

Or, to update rules independently of the binary:

```bash
# Download and extract the latest rules from the release archive
cd /tmp && curl -LO https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-<tag>-lin-x64-gnu.zip
unzip hayabusa-<tag>-lin-x64-gnu.zip -d extracted
sudo cp -r extracted/rules /var/lib/sift/.sift/hayabusa-rules
sudo chown -R sift-service:sift-service /var/lib/sift/.sift/hayabusa-rules
```

Or point `HAYABUSA_RULES_DIR` to a separately maintained rules directory.

### 3.9 How to disable

Hayabusa is skipped automatically if not installed (`shutil.which("hayabusa")`
returns `None`). It is also skipped if no EVTX directory is present for a
host.

To disable without uninstalling: remove or rename the binary at
`/var/lib/sift/.sift/bin/hayabusa` and the symlink at
`/usr/local/bin/hayabusa`.

To prevent the installer from installing Hayabusa: set
`SIFT_CORE_ONLY=1` (skips OpenSearch, Docker, and forensic-tool downloads).

Source: `install.sh`, line 2915.

### 3.10 How to run offline

Once installed, Hayabusa runs entirely on-VM with no network requirement.
The binary and rules are local files. No internet access is needed during
case analysis.

---

## 4. External-Download Ledger (installer hardening)

This ledger covers every external network download made by `install.sh` and
`scripts/setup-supabase.sh`. Each entry is graded for installer hardening.

| # | What | Source URL | Version pin | Checksum / Signature | Cache path | Offline alternative | Hardened-profile verdict |
|---|---|---|---|---|---|---|---|
| D1 | uv (Python package manager) | `https://astral.sh/uv/install.sh` (shell pipe) | **None — latest** | **None** | `~/.local/bin/uv` | Pre-install uv via OS package or supply the binary | **FAIL — unpinned, unauthenticated pipe-to-shell** |
| D2 | Hayabusa binary + rules | `https://github.com/Yamato-Security/hayabusa/releases/latest` (dynamic tag) | **None — latest** | ZIP format check only (no hash) | `/var/lib/sift/.sift/bin/hayabusa` | Pre-place binary at install path; installer skips if already present | **FAIL — unpinned, no hash** |
| D3 | Hugging Face BGE model weights | `https://huggingface.co/BAAI/bge-base-en-v1.5` (via `sentence-transformers`) | Model name pinned by allowlist; weights not versioned in installer | **None — no hash in installer** | `~/.cache/huggingface/hub/` (service user) | Pre-warm cache offline or transfer from internet-connected host | **FAIL — unpinned weights, no hash** |
| D4 | RAG Chroma bundle (legacy `chroma` path only) | `https://api.github.com/repos/AppliedIR/sift-mcp/releases` (latest `rag-index-*` tag) | **None — latest matching release** | SHA-256 checksum file (`rag-checksums.sha256`) **included in the bundle** — verified by `download_index.py` | `packages/forensic-rag-mcp/data/chroma/` | Use `SIFT_RAG_IMPORT_SOURCE=direct` instead | **PARTIAL — checksum present but release tag is unpinned** |
| D5 | Supabase CLI binary | `https://github.com/supabase/cli/releases/download/v2.105.0/supabase_2.105.0_linux_amd64.tar.gz` | **Pinned: 2.105.0** | SHA-256 in script (`11ac4410...`) — advisory check, non-blocking on mismatch | `~/.sift/bin/supabase` or `/usr/local/bin/supabase` | Supply binary at `SIFT_BIN_DIR` | **PARTIAL — pinned version, SHA advisory only (non-blocking)** |
| D6 | GeoIP datasource (OpenSearch ip2geo) | `https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json` | **None — live endpoint** | **None** | OpenSearch internal datasource | Set `update_interval_in_days` to 0 or skip `configure_geoip_pipeline()` | **FAIL — unpinned, unauthenticated, live endpoint** |
| D7 | Python packages (PyPI) | `https://pypi.org` (via uv sync) | Pinned via `uv.lock` in the workspace | Hash verification by uv (lockfile-based) | `/opt/sift-mcps/.venv/` | Supply a local PyPI mirror or pre-built venv | **PASS — uv lockfile pins all packages with hashes** |
| D8 | Supabase Docker images | Docker Hub / registry (via `supabase start`) | Pinned by Supabase CLI version (`supabase/...` compose manifest) | Docker layer digests (registry-side) | Docker image cache | Pre-pull images; use a local registry mirror | **PARTIAL — Supabase CLI pins its own images; no explicit installer-level hash** |

### Hardening backlog items

The following downloads are flagged as hardening backlog items (open,
linked to B-MVP-004):

| Ledger # | Item | Required action |
|---|---|---|
| D1 | uv install via pipe-to-shell — no version pin, no hash | Pin to a specific uv version URL with SHA-256 checksum; or require pre-installed uv |
| D2 | Hayabusa binary — latest tag, no hash | Pin to a specific release tag; add SHA-256 or cosign signature check after download |
| D3 | BGE model weights — no hash | Specify expected model SHA in the installer; pre-stage cache for air-gapped installs; document HF_HOME path for the service user |
| D4 | RAG Chroma bundle — release tag unpinned | Pin to a specific `rag-index-*` tag; the internal checksum file is good but the tag must also be pinned |
| D5 | Supabase CLI SHA check is advisory only | Change from `warn` to `die` on SHA mismatch for production profiles |
| D6 | GeoIP datasource — unauthenticated live endpoint | Gate behind `SIFT_GEOIP_ENABLED` flag defaulting to off; use local GeoLite2 file for offline installs |

Operator decision B-MVP-004 (open, `docs/migration/Session-Notes.md`):
choose between live Hugging Face/GitHub downloads, pre-bundle/cache
artifacts, or require operator-provided artifacts before BATCH-HR3 can
close these items.

---

## 5. Update Notes for BATCH-RG1

The following stale claims in `docs/regenerate/**` should be corrected in
BATCH-RG1. Do not edit those files before RG1 lands.

### 5.1 `docs/regenerate/data-flows-and-lifecycles.md`

- **Line 28–40** — The install flow diagram shows `download_rag_index ->
  import_rag_pgvector` as the primary path. This is now the **legacy `chroma`
  path** only. The default primary path since BATCH-OSX-RAG is `direct`
  (seed from bundled JSONL corpus via `seed_rag_pgvector_direct`).
- **Line 38–40** — Claims "RAG corpus import calls
  `rag-mcp-import-chroma-pgvector`" as the main flow. Correct to: default
  uses `rag-mcp-seed-pgvector`, which reads the bundled JSONL corpus; the
  Chroma import is `SIFT_RAG_IMPORT_SOURCE=chroma` only.
- **Line 264–279** — The RAG import/query lifecycle section shows
  `Chroma release bundle -> rag-mcp-import-chroma-pgvector` as the seeding
  mechanism. This should be updated to describe the `direct` path as primary
  and `chroma` as the legacy/compat option.
- **Line 271** — References `agent rag_search_case(query)`. The tool has been
  renamed to `kb_search_knowledge` in the current codebase. `rag_search_case`
  does not exist in the live agent tool catalog.

### 5.2 `docs/regenerate/mcp-contracts.md`

- **Lines 27–28, 46, 68, 85–86, 320–331, 379, 399** — Throughout this file,
  `rag_search_case` is named as the RAG tool exposed to agents. This tool
  does not exist in the current codebase. The live tools are:
  `kb_search_knowledge`, `kb_list_knowledge_sources`, `kb_get_knowledge_stats`
  (defined in `packages/forensic-rag-mcp/src/rag_mcp/server.py`).
- **Line 46** — The schema shown for `rag_search_case` (with
  `include_derived`, `query_embedding` parameters) reflects a superseded
  design. The current `kb_search_knowledge` has `query`, `top_k`, `source`,
  `source_ids`, `technique`, `platform` parameters. There is no
  `include_derived` — derived content is permanently blocked by design.

### 5.3 `docs/regenerate/matrix-comparison.md`

- **Line 42** — References `Hayabusa` and `idx_ingest` tools. These are
  opensearch-mcp tools (`opensearch_ingest`, `opensearch_search`), not
  `idx_*` tools. The latter naming predates the current tool surface.
- The RAG-related section should be updated to name `kb_search_knowledge`
  rather than `rag_search_case` for consistency.

### 5.4 `docs/regenerate/known-limitations-and-improvements.md`

- **Line 17** — References `rag_search_case` as the RAG tool. Replace with
  `kb_search_knowledge`.
- **Line 18** — "Shared forensic knowledge rows are case-neutral" — this is
  correct and matches current design. Keep.
- **Line 35 (IMP-FRZ1-08)** — "Add case-derived RAG chunks with evidence
  provenance." This should be marked as explicitly deferred/rejected per
  BATCH-NW4 (B-MVP-RAG-DERIVED REJECTED). The current design permanently
  blocks `kind='derived'` at both the Python layer and via DB trigger.
  If case-derived RAG is reconsidered in future it requires an explicit new
  design tracked separately.
