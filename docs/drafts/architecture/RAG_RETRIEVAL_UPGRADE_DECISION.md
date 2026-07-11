# RAG Retrieval Upgrade — Architecture Decision and Benchmark Charter

**Status:** accepted for test/dev and manually proven on the SIFT VM on
2026-07-11. Installer integration remains in progress on
`codex/rag-retrieval-upgrade`.

**Scope:** forensic-rag-mcp only. forensic-knowledge is a separate AI-agent guidance/context-injection component and is not a vector corpus, RAG tool, or migration input.

## Decision in one page

1. Keep the shared forensic-reference corpus in **Postgres + pgvector** for this upgrade. It is already inside the authoritative control plane and is more than capable of the intended 22,268-record corpus and moderate future growth.
2. Adopt **Qwen3-Embedding-0.6B at 1024 dimensions** as the primary candidate, not as an automatic replacement. It must win a fixed retrieval evaluation on the SIFT VM before activation.
3. Evaluate **Qwen3-Reranker-0.6B** only as a gated top-N reranker. It is not permitted on the unconditional request path until CPU latency and memory are measured on the 8-core, CPU-only VM.
4. Build one canonical, release-pinned 22,268-record corpus from the upstream source snapshot and re-embed it under our own pinned model revision. Do not layer the 4,318-record direct seed onto it.
5. Do **not** introduce Qdrant, Chroma, or OpenSearch for this corpus now. Reconsider Qdrant only when a benchmark or workload change demonstrates that pgvector cannot meet the agreed service objective.

This is intentionally conservative: quality comes from a better corpus, embedding model, query instruction, and reranker—not from adding a second database at a 22k-document scale.

## Workload facts

| Fact | Evidence / implication |
| --- | --- |
| Full upstream release corpus | 22,268 records across 67 source labels. The release bundles both parsed JSONL source records and a Chroma index. |
| Existing direct corpus | 4,318 AppliedIR/SANS records. It is a subset of the full release. |
| Historical 26,586 count | 22,268 + 4,318; it indicates that the subset was layered over the full release, duplicating bundled sources. It is not the desired target. |
| Current vector contract | vector(768), BGE base, pgvector cosine retrieval, gateway-held control-plane authority. A Qwen 1024-d model is a schema/version migration, not an environment-variable flip. |
| Test VM | 8 CPU cores, 31 GiB RAM, no GPU. The gateway currently has no systemd memory limit. |
| Data sensitivity | RAG is shared reference knowledge only. Case evidence must never be embedded into this corpus or delegated to another backend. |

At 22,268 rows, raw 1024-dimensional float32 vectors occupy roughly 87 MiB before index and database overhead. That is not a vector-store-scale problem; model inference and operational correctness dominate the design.

## Embedding and ranking recommendation

### Qwen3-Embedding-0.6B: strong candidate, not a blind default

Qwen3-Embedding-0.6B is Apache-2.0, supports 100+ languages, 32k context, instruction-aware queries, and Matryoshka output dimensions from 32 to 1024. Its model card reports stronger MTEB retrieval results than the older BGE class of small models, including an English-v2 retrieval score of 61.83 and a multilingual retrieval score of 64.64. It is a credible fit for mixed DFIR, detection-rule, ATT&CK, command-line, and non-English reference material.

Sources: [official embedding model card](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B), [published MTEB table](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B#evaluation).

Why 1024 dimensions first:

- the corpus is too small for vector storage to be the primary cost;
- it avoids voluntarily discarding representation capacity before measuring relevance; and
- a parallel 1024-d snapshot is needed anyway because BGE and Qwen vectors cannot share a similarity space.

Qwen's Matryoshka support makes 768 or 512 dimensions worth benchmarking as a secondary storage/latency profile, but only after 1024 establishes the quality ceiling. Do not select a smaller dimension simply to preserve the existing vector(768) column; that would entangle a model migration with a legacy table and prevent a clean blue/green comparison.

Operational caveat: 0.6B is compact by modern embedding standards, but it is substantially heavier than BGE base. On our CPU-only VM it must be loaded once by the gateway service, revision-pinned, cached under the service account, and measured under concurrent load. It must never download model files at query time.

### Qwen3-Reranker-0.6B: high-value second stage, feature-gated

The companion reranker supports the same 0.6B/32k/instruction-aware shape. Its official evaluation reports an MTEB retrieval score of 65.80 after reranking the top 100 dense candidates, versus 61.82 for the embedding model. That makes it attractive for quality, especially for precise forensic queries, but a cross-encoder has to read every query/passage pair and will cost far more CPU than one dense query embedding.

Source: [official reranker model card](https://huggingface.co/Qwen/Qwen3-Reranker-0.6B).

Use it only after dense retrieval:

    query -> instructed Qwen embedding -> pgvector top 20 -> optional Qwen rerank top 10 -> response

Initial implementation constraints:

- cap candidate passage size and rerank at most 20 candidates;
- enforce a request deadline and return the dense ordering if reranking times out or is unavailable;
- make it explicit and observable (rerank_applied, model/version, latency), but do not broaden the agent-facing authority of the RAG tools;
- default it off until VM P95 latency and resident memory are acceptable.

## Vector-store decision

### Retain pgvector now — recommended

This is the lowest-risk, most coherent option. The database already provides the control-plane authority, audit model, backup process, RLS posture, and the gateway already owns the credential. pgvector supports HNSW, configurable search candidates, iterative scans for filtered ANN queries, and half-precision indexes if they ever become necessary. For the current corpus, exact search may also be competitive; benchmark both exact and HNSW before committing to ANN.

Source: [pgvector HNSW, filtering, iterative scans, and halfvec documentation](https://github.com/pgvector/pgvector).

Important engineering requirements:

- for the current disposable test/dev environment, replace the 768-d BGE RAG
  storage with a clean 1024-d Qwen rebuild after artifact validation; do not
  keep both active or mix their vector spaces;
- retain a rollback dump/receipt only when comparison is useful; production
  environments should use a versioned cutover instead;
- benchmark exact cosine search and HNSW with the real 22,268-row corpus;
- if source/platform filters remain selective, configure pgvector iterative scans and ordinary metadata indexes, then prove recall under filters.

The possible future retirement of Supabase is **not** a reason to leave pgvector. pgvector is a PostgreSQL extension; a later move from Supabase to self-managed Postgres can retain this RAG schema and migration path. Replacing Supabase is a broader identity, control-plane, and operational change—not a RAG retrieval optimization.

### Qdrant — best future challenger, not justified yet

Qdrant is the strongest alternative once the reference corpus grows materially or dedicated vector-service operation becomes worthwhile. It offers filter-aware payload indexing, HNSW, on-disk vectors/indexes, quantization, and collection-scoped API access. Its own guidance recommends one collection per embedding model with payload partitioning rather than many collections, which fits a future corpus-snapshot design.

Sources: [Qdrant multitenancy/collection guidance](https://qdrant.tech/documentation/manage-data/multitenancy/), [resource and on-disk/quantization guidance](https://qdrant.tech/documentation/faq/database-optimization/), [security controls](https://qdrant.tech/documentation/operations/security/).

It would add a new database service, TLS/API-key lifecycle, snapshot/restore process, availability dependency, monitoring, and a new gateway-to-store trust boundary. Qdrant must never be exposed directly to agents and must receive only reference-corpus data through the gateway. For 22k rows, those costs buy very little. Put Qdrant behind a RagStore interface and evaluate it later at approximately 100k+ records, tight P95 latency requirements, or clear evidence that pgvector filtering/recall is failing the benchmark.

### OpenSearch — do not use for RAG now

OpenSearch can serve vector and hybrid lexical search with on-disk modes and compression, so it is technically capable. It already runs in SIFT, but that is the reason to avoid it here: its current plane is derived case search. A shared RAG corpus in the same cluster creates another route for security-role, index-prefix, mapping, and operational mistakes to expose reference or case data across a boundary that must remain strict.

Sources: [OpenSearch vector mapping and storage options](https://docs.opensearch.org/latest/mappings/supported-field-types/knn-vector/), [filter-aware k-NN behavior](https://docs.opensearch.org/latest/vector-search/filter-search-knn/).

If OpenSearch is ever reconsidered, it must be a separately prefixed RAG namespace, a dedicated least-privilege service role, no case-search alias, no agent credential, and a gateway-only adapter with cross-plane negative tests. It is operationally disproportionate for this corpus today.

### Chroma — retain only as an import format

Chroma is useful because the upstream source distributes a verified Chroma artifact, but it is not the production target. Its local-persistent layout is convenient for a single-node index, while its server authentication/RBAC documentation is still marked alpha. It does not improve SIFT's existing control-plane/audit model.

Source: [Chroma server authentication and RBAC documentation](https://github.com/chroma-core/docs/blob/main/docs/usage-guide.md).

## Secure full-corpus migration design

1. Fetch the selected upstream release by immutable tag; verify the release archive SHA-256 before extraction. Preserve the archive and a generated per-file manifest as source evidence.
2. Transform the 23 release sources JSONL files plus the 44 bundled JSONL documents into one canonical 22,268-record source snapshot. Reject extra, missing, path-traversing, oversized, or malformed members.
3. Version the transform. Start by reproducing the upstream MITRE-name text augmentation for both document and query embedding inputs, but preserve the source text and its hash separately for provenance.
4. Rebuild the test/dev Qwen snapshot with stable source-record identifiers, collection/document/chunk provenance, model repository revision, model file hashes, embedding dimension, prompt instruction, and transform version.
5. Query only through the gateway. The gateway owns the database connection; RAG subprocesses and agent clients receive neither pgvector nor future Qdrant credentials.
6. Activate only after the benchmark succeeds. In this test/dev environment,
   failure permits restoring a lightweight dump/receipt or rerunning the
   provisioning path; a production deployment should retain a versioned
   rollback snapshot.

## Benchmark charter: the decision gate

Build a reproducible local/VM benchmark before choosing the production model or store. It must compare at least:

| Candidate | Retrieval | Ranking |
| --- | --- | --- |
| Current BGE base | 768-d pgvector, exact + HNSW | none |
| Qwen3 Embedding 0.6B | 1024-d pgvector, exact + HNSW | none |
| Qwen3 Embedding 0.6B | same | Qwen3 Reranker 0.6B top 20 |
| Optional Qwen MRL profile | 768-d and/or 512-d pgvector | best viable rerank profile |

Measure on the actual VM with a versioned query/relevance set covering ATT&CK IDs, Sigma rule logic, Windows/Linux/macOS, IOC/command-line, forensic methodology, source filters, and ambiguous natural-language requests.

Required evidence:

- Recall@10, nDCG@10, MRR@10, and qualitative relevance review;
- embedding, dense retrieval, reranking, and end-to-end P50/P95 latency under 1 and 4 concurrent queries;
- cold-load and steady-state RSS/CPU plus complete-seed duration;
- exact/HNSW recall comparison under source/platform filters;
- source count, per-source count, and document-hash reconciliation;
- gateway surface, audit, ResponseGuard, offline-cache, and forged-provenance negative tests.

**Go/no-go:** Qwen is adopted only if it improves relevance materially without violating the agreed CPU-only latency/memory budget. Qdrant is adopted only if the same benchmark demonstrates a measurable pgvector limitation worth the additional trust boundary. No vendor benchmark substitutes for this gate.
