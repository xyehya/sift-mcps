# RAG and Search Maintenance

**BATCH-OR3** — operator procedures for the RAG knowledge plane, OpenSearch
search plane, and Hayabusa detection on an installed SIFT VM.
Last updated: 2026-06-12.

Companion to `docs/operator/maintenance-guide.md`. Provenance (what was
downloaded, from where, why) is in `docs/operator/reference-data-provenance.md`;
this doc is the **operate/maintain** view. Commands are read-only unless marked
`DANGER`. Replace `<VM_IP>` with the VM address.

---

## 1. RAG knowledge plane (forensic-rag-mcp / Supabase pgvector)

**Policy:** RAG is **knowledge/reference-only**. `kind='knowledge'`,
`case_id NULL`. Per-case derived content (`kind='derived'`) is **blocked** at
both the Python ingest layer and a DB BEFORE INSERT trigger. Do not attempt to
embed case evidence into shared RAG — it is rejected by design (B-MVP-RAG-DERIVED
rejected). Adding case-derived RAG would require an explicit new design with
provenance, approval, and privacy controls.

### 1.1 Check that RAG is populated (read-only)

```bash
docker exec supabase_db_sift-mcps psql -U postgres -d postgres -tA -c \
  "select count(*) from app.rag_chunks;"
```

Baseline on the reference VM: ~26,586 chunks. A count of 0 means RAG was never
seeded (or `SIFT_RAG_ENABLED=false` at install). The `forensic-rag-mcp` backend
should also appear `status:"ok"` in `/health`.

### 1.2 Embedding model

- Default: `BAAI/bge-base-en-v1.5` (768-dim). Override with `RAG_MODEL_NAME`.
- Allowlisted models only (`bge-base/small/large-en-v1.5`,
  `all-MiniLM-L6-v2`, `all-mpnet-base-v2`) — arbitrary models are refused.
- Weights download from Hugging Face on first use into the service user's HF
  cache (`/var/lib/sift/.cache/huggingface/hub/`). The download is **unpinned /
  unauthenticated** (hardening ledger D3 / B-MVP-004).

### 1.3 Re-seed from the bundled corpus (idempotent)

Use this after editing the bundled corpus or to repair a partial seed. It is
idempotent (stable UUIDs, `ON CONFLICT DO UPDATE`).

```bash
# Reads the DSN from the env file into a shell var WITHOUT echoing it,
# then re-seeds from the repo's bundled JSONL knowledge corpus.
cd /opt/sift-mcps
DSN="$(sudo awk -F= '$1=="SIFT_CONTROL_PLANE_DSN"{sub(/^[^=]*=/,"");print;exit}' \
  /var/lib/sift/.sift/control-plane.env)"
SIFT_CONTROL_PLANE_DSN="$DSN" .venv/bin/rag-mcp-seed-pgvector \
  --knowledge-dir packages/forensic-rag-mcp/knowledge \
  --embedding-mode model
unset DSN
```

Dry-run the plan without writing (no model download with `deterministic`):

```bash
cd /opt/sift-mcps
.venv/bin/rag-mcp-seed-pgvector \
  --knowledge-dir packages/forensic-rag-mcp/knowledge \
  --embedding-mode deterministic --dry-run
```

> Run these as a user that can read `control-plane.env` (i.e. with `sudo` to read
> the DSN). Never put the DSN on a bare command line or in shell history.

### 1.4 Legacy Chroma import path (compatibility only)

Only if you installed with `SIFT_RAG_IMPORT_SOURCE=chroma` and have the bundle at
`packages/forensic-rag-mcp/data/chroma/`:

```bash
cd /opt/sift-mcps
SIFT_CONTROL_PLANE_DSN="$DSN" .venv/bin/rag-mcp-import-chroma-pgvector \
  --chroma-dir packages/forensic-rag-mcp/data/chroma
```

Prefer the `direct` path (§1.3) for new installs.

### 1.5 Query smoke (through the gateway, not direct DB)

Agents query via the `kb_search_knowledge` MCP tool through the gateway with a
portal-issued agent/service credential. Output is sanitized (paths redacted,
embedding fields stripped) and the DB function `app.rag_search` hard-codes
`kind='knowledge'`. There is no `rag_search_case` tool — that name is stale.

### 1.6 Disable RAG

- **At install:** `SIFT_RAG_ENABLED=false` (backend not registered; no `kb_*`
  tools).
- **At runtime:** set the `forensic-rag-mcp` row in `app.mcp_backends` to
  `enabled=false` (or remove it), then restart the gateway.

### 1.7 Offline operation

The pgvector store is on-VM and needs no internet after seeding. The only
network steps are the embedding-model download (pre-warm the HF cache from an
online host and copy it to `/var/lib/sift/.cache/huggingface/`) and the optional
legacy Chroma bundle. The bundled JSONL corpus ships in the repo. Air-gap policy
is open as B-MVP-004.

---

## 2. OpenSearch search plane

Container `sift-opensearch` (`opensearchproject/opensearch:3.5.0`), published on
`127.0.0.1:9200`. The index **data** is derived/rebuildable; the DB authority is
`app.opensearch_indices` (registry) and `app.opensearch_ingest_provenance`.

### 2.1 Health and indices (read-only)

```bash
# Single-node clusters report "yellow" (replicas unassigned) — that is normal.
curl -s 'http://127.0.0.1:9200/_cluster/health?pretty'

# All indices with doc counts and sizes.
curl -s 'http://127.0.0.1:9200/_cat/indices?v&s=index'

# Per-case index families.
curl -s 'http://127.0.0.1:9200/_cat/indices/case-*?v'
```

Verified live 2026-06-12: `status=yellow`, 1 node, 15 active primaries, 2
unassigned replicas, 9 indices (system indices, query-insights, and
`case-seed-*-init` template scaffolding at 0 docs).

### 2.2 Templates and pipelines (read-only)

```bash
# Index templates (expect the hayabusa template, case-*-hayabusa-* pattern).
curl -s 'http://127.0.0.1:9200/_index_template?pretty' | less

# Ingest pipelines present (e.g. geoip enrichment, if configured).
curl -s 'http://127.0.0.1:9200/_ingest/pipeline?pretty' | less
```

The Hayabusa index template (`mappings/hayabusa_template.json`) matches
`case-*-hayabusa-*` (priority 18). Mappings/templates are static repo reference
data (file-authoritative by design).

### 2.3 Ingest status and registry (DB-authoritative)

```bash
# Ingest provenance / status by case (counts only).
docker exec supabase_db_sift-mcps psql -U postgres -d postgres -tA -c \
  "select count(*) as registered_indices from app.opensearch_indices;"
```

`~/.sift/ingest-status/*.json` and `<case>/host-dictionary.yaml` are
parser-compat/debug artifacts only — they cannot change DB authority
(`app.opensearch_ingest_status`, `app.host_identity_decisions`).

### 2.4 Rebuild indices

OpenSearch data is rebuildable: re-run ingest against sealed evidence. There is
no need to back up the index volume if the evidence bytes and DB are backed up.

```bash
# DANGER: deleting an index permanently removes its documents. Only do this for
# a case index you intend to re-ingest. Confirm the exact name first.
# curl -s -XDELETE 'http://127.0.0.1:9200/case-<id>-<...>'
```

### 2.5 Credentials / posture

OpenSearch currently runs with a default `admin`-class credential and the
security plugin in a lab posture (B-MVP-005 / HR1 gap). The client config is
`/var/lib/sift/.sift/opensearch.yaml` (`user`, `password=<redacted>`,
`verify_certs`). Rotate via the installer path, not by hand-editing (see
`config-and-secrets.md` §10).

---

## 3. Hayabusa (EVTX detection)

Binary `/var/lib/sift/.sift/bin/hayabusa` (symlink `/usr/local/bin/hayabusa`),
owned `sift-service`, mode `0755`. Rules under
`/var/lib/sift/.sift/hayabusa-rules/` (must contain a `config/` subdir).

> **Verify as `sift-service`/root, not as the login user.** To the
> `sansforensics` login the symlink can *look* broken because
> `/var/lib/sift/.sift/bin` is not world-traversable. The target resolves fine
> for the service user. Do not "fix" a non-existent missing binary.

### 3.1 How it runs

Hayabusa runs as a post-ingest detection phase after EVTX files are indexed:
`hayabusa csv-timeline -r <rules> -c <rules>/config -d <evtx_dir> -o <csv> -p
verbose --no-wizard`. CSV output goes to
`/var/lib/sift/.sift/hayabusa-output/hayabusa-<case_id>-<host>.csv`, then ingests
to OpenSearch under `case-<case_id>-hayabusa-<host>`.

### 3.2 Query detections

```bash
# Through the agent path (opensearch-mcp), the canonical query is:
#   opensearch_search(query='Level:critical OR Level:high', index='case-*-hayabusa-*')
# Operator read-only equivalent against OpenSearch directly:
curl -s 'http://127.0.0.1:9200/case-*-hayabusa-*/_count?q=Level:critical%20OR%20Level:high'
```

### 3.3 Halt condition

If rules are missing for any host in a batch, ingest writes a halt status
(`HALT_HAYABUSA_NO_RULES`) surfaced via `opensearch_ingest_status` and the
portal — it no longer silently skips. If you see this, check the rules dir or set
`HAYABUSA_RULES_DIR`.

### 3.4 Refresh / update rules

```bash
# Trigger a clean re-install on the next installer run:
# DANGER: removes the installed binary; re-run ./install.sh to reinstall.
# sudo rm /var/lib/sift/.sift/bin/hayabusa
# Then from the repo checkout:
# ./install.sh
```

Or update rules independently by extracting `rules/` from the release ZIP into
`/var/lib/sift/.sift/hayabusa-rules` and
`chown -R sift-service:sift-service` it, or point `HAYABUSA_RULES_DIR` at a
maintained rules tree. The binary download is **unpinned, no checksum**
(ledger D2 / B-MVP-004).

### 3.5 Disable / offline

- Disable: rename/remove the binary + symlink, or install with `SIFT_CORE_ONLY=1`
  (skips Hayabusa with OpenSearch/Docker/forensic-tool downloads).
- Offline: once installed, Hayabusa runs entirely on-VM; binary and rules are
  local files, no internet needed during analysis.

---

## 4. Forensic knowledge (FK) enrichment — operator notes

FK is a **static, bundled reference library** (no downloads, no MCP server). Data
at `/opt/sift-mcps/packages/forensic-knowledge/data/`, symlinked to
`/var/lib/sift/enrichment/forensic-knowledge`, pointed to by
`FK_DATA_DIR` in `/var/lib/sift/.sift/forensic-knowledge.env` (loaded by both
units). It enriches tool responses with caveats/field meanings/corroboration,
decaying after the first few calls per tool to avoid context bloat.

To refresh: edit YAML under the data dir, re-run `./install.sh` (refreshes the
symlink + FK env), then restart services. The in-memory cache clears on restart.
FK is offline-capable and requires no maintenance beyond keeping the repo current.

---

## 5. Cross-references

- Provenance / download ledger / refresh-offline detail:
  `docs/operator/reference-data-provenance.md`.
- Variable names, file modes, and "do not hand-edit":
  `docs/operator/config-and-secrets.md`.
- Service status, health, backup/restore, evidence, logs, audit, recovery:
  `docs/operator/maintenance-guide.md`.
- Authority of each fact (DB vs file): `docs/operator/state-authority-map.md`.
- Live paths/services/Docker inventory: `docs/inventory/sift-tool-inventory.md`.
