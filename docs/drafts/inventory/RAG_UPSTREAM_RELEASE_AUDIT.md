# Upstream RAG Release Audit and pgvector Migration Recommendation

_Audit date: 2026-07-11. Scope: `forensic-rag` / `forensic-rag-mcp` only.
`forensic-knowledge` is an independent AI-agent context-injection component and
is deliberately excluded._

## Executive conclusion

The original AppliedIR RAG release provides **both** the ready-to-query Chroma
index **and** the parsed source documents needed to rebuild the corpus:

| Artifact | Records | Source labels | Purpose |
| --- | ---: | ---: | --- |
| Upstream checkout's bundled JSONL | 4,318 | 44 | AppliedIR and SANS reference material; checked into source control. |
| Release `sources/*.jsonl` | 17,950 | 23 | Parsed records for every external source plus embedded forensic clarifications. |
| Release Chroma `ir_knowledge` collection | 22,268 | 67 | Precomputed BGE vectors and the transformed text used by the original server. |

`17,950 + 4,318 = 22,268`, exactly matching the release metadata and Chroma
row count. This proves the release is not index-only: the raw parsed records
are present alongside the index.

## Verified upstream snapshot

- Repository: `https://github.com/AppliedIR/sift-mcp`
- Cloned audit checkout: `/Users/yk/AI/sift-mcp-upstream-audit-20260711`
- Audited `main` commit: `c67a860ea70c38dc3c5243193a76f0bcbd6db18f`
- Index-release tag: `rag-index-v2026.03.01` at
  `c09d1b1109ff46182cb806bdf477832037de677c`
- Release asset: `rag-index.tar.zst` (134,358,099 bytes)
- Verified SHA-256:
  `ab18c4f353a613edcbddbffafa6806454dc4efa7f7c6a39e7f718d145087a8b6`

The archive contains `chroma/`, `sources/`, `metadata.json`, and
`user_state.json`. Its `metadata.json` records the BGE model name, ChromaDB
version, 22,268 records, and 67 source labels. The package's checked-in
`knowledge/` directory has not changed since the index-release tag.

## What matches our repository, and what does not

### Confirmed matches

1. Our `packages/forensic-rag-mcp/knowledge/` is byte-for-byte identical to
   the original project's bundled `knowledge/` directory (44 documents,
   4,318 records).
2. Our `ATTRIBUTION.md` is byte-for-byte identical to upstream's copy.
3. The release's Chroma metadata rows have exactly 570 AppliedIR and 3,748 SANS
   records—the same counts as our bundled direct seed.
4. Our existing `rag-mcp-import-chroma-pgvector --dry-run` successfully opened
   the audited artifact without a database connection and reported:

   ```json
   {
     "chroma_records": 22268,
     "collections": 67,
     "documents": 22268,
     "chunks": 22268,
     "skipped": 0
   }
   ```

### Documented-count drift

The historical `~26,586` count in several local operational documents is not
the count of the available upstream release. It is exactly:

```text
22,268  full Chroma release
 4,318  direct AppliedIR/SANS seed
------
26,586  combined result
```

That arithmetic strongly indicates a historical target that imported the full
release and then seeded the bundled direct corpus, duplicating the 4,318
AppliedIR/SANS records. This is an inference from independently verified
counts, not a claim about the current VM. The current installer default is the
clean 4,318-record direct path; confirm a deployed target with
`kb_get_knowledge_stats` before changing it.

## Important retrieval-compatibility distinction

The existing Chroma importer copies the release's stored 768-dimensional
vectors verbatim. It is the fastest path to preserve the source set and the
old vector corpus, but it is not a full behavioral clone of the upstream
server:

- Upstream Chroma uses cosine distance and augments both documents and queries
  with MITRE technique names before embedding.
- The upstream server also applies source and keyword boosts after retrieval.
- Our gateway uses pgvector cosine distance, but currently embeds the supplied
  query directly and does not implement the upstream query augmentation or
  boost/rerank layer.
- The release records only the model name (`BAAI/bge-base-en-v1.5`), not the
  exact Hugging Face revision used when it was built. Re-embedding its raw
  files today cannot reproduce its vectors bit-for-bit.

The direct JSONL seeder is therefore a good small corpus seed, but it neither
imports the remaining 17,950 source records nor duplicates the upstream
MITRE-text transform.

## Recommended migration: one canonical corpus, re-embedded under our pin

Use the audited release as a **source snapshot**, then transform and embed it
under our own pinned model. This is the durable route because it gives SIFT a
single reproducible corpus, known provenance, and query/index compatibility.

1. Stage the exact release archive, verify its SHA-256, and safely extract it.
   Refuse a missing/incorrect manifest, count, dimension, or source-label set.
2. Build a canonical input manifest from the 23 release `sources/*.jsonl`
   files plus the 44 same-tag bundled JSONL files. Record per-file SHA-256,
   upstream release tag, archive hash, source label, and record count.
3. Apply one documented, versioned text transform. To preserve the original
   corpus semantics, start with the upstream MITRE-name augmentation; store the
   transform version and the hash of the exact embedding input in metadata.
4. Re-embed all 22,268 records with SIFT's pinned
   `BAAI/bge-base-en-v1.5` revision, not an unpinned Hugging Face default.
   Store source snapshot/model/transform provenance on collections, documents,
   and chunks.
5. Activate the new corpus only after its counts, per-source distribution,
   provenance, and a fixed relevance suite pass. Keep the old corpus untouched
   until the cutover is accepted, then retire it as one explicitly named
   snapshot.

This should result in **22,268** chunks, not 26,586. Do not run the direct
seed in addition to this full-corpus load.

## Safe implementation shape

Add a dedicated, gateway/installer-authority-only release importer rather than
expanding the agent-facing `kb_*` tool surface. It should:

- accept a local archive/staged directory only; agents never receive a DB DSN;
- reject archive path traversal and unexpected file types;
- validate the archive hash, `metadata.json`, 768 dimensions, 22,268 records,
  and the expected 67 source labels before writing;
- use stable IDs based on the upstream record IDs plus the release tag, making
  re-runs idempotent;
- make the source snapshot explicit in pgvector metadata;
- refuse to mix `direct` and `release` seed modes in the same active corpus;
- emit a dry-run manifest first and require an explicit operator action for the
  write/cutover.

The current Chroma importer remains useful as a temporary, exact-vector bridge,
but it must capture the archive/release provenance before being used for a
production import.

## Acceptance checks before a live cutover

1. Dry run: 22,268 input records, 67 source labels, no unsupported rows.
2. Database: 22,268 knowledge chunks, no duplicate AppliedIR/SANS rows, and
   no derived/case content.
3. Provenance: every row traces to a release tag, archive hash, source file,
   record ID, transform version, and embedding model revision.
4. Retrieval: compare a fixed set of DFIR, Sigma, ATT&CK, platform, and source
   filtered queries against the upstream release; evaluate result quality rather
   than expecting identical ranks after a deliberate re-embed.
5. Gateway: `kb_get_knowledge_stats`, `kb_list_knowledge_sources`, and
   `kb_search_knowledge` pass through the normal policy/audit/ResponseGuard
   surface on the VM.
