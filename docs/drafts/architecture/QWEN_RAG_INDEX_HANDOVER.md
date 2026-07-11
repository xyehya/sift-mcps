# Qwen RAG Index Handover

## Artifact

Use this verified local artifact:

- [qwen3-embedding-0.6b-1024-sift-rag-v1.tar.zst](/Users/yk/AI/sift-mcps-rag-retrieval-upgrade/artifacts/qwen3-embedding-0.6b-1024-sift-rag-v1.tar.zst)
- SHA-256: \`1030d3901d116c1c4fe7e82148da2eb07857afaebb0702a01aa2532273b870b4\`
- Archive layout: \`qwen3-embedding-0.6b-1024/\` containing:
  - \`manifest.json\`
  - \`records.jsonl\`
  - \`embeddings.f32.npy\`

## What was built

- **22,268** source records, with no case evidence.
- **67** source files: 23 upstream release sources (17,950 records) plus 44
  bundled AppliedIR/SANS JSONL documents (4,318 records).
- Model: \`Qwen/Qwen3-Embedding-0.6B\`
- Pinned revision: \`97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3\`
- Shape: **(22,268, 1,024)**, \`float32\`, all values finite.
- Metric: cosine. Query instruction is recorded in \`manifest.json\`; documents
  were embedded from raw source text truncated at 2,048 tokens.
- Builder: [build_qwen_rag_index.py](/Users/yk/AI/sift-mcps-rag-retrieval-upgrade/scripts/build_qwen_rag_index.py:1).

The build ran on Fedora 44 using an RTX 5080 and its existing CUDA 13.0 PyTorch
environment. It did not contact Postgres, Supabase, the SIFT VM, OpenSearch, or
any case/evidence data.

## Required migration shape

This is an approved **test/dev replacement**, not a parallel snapshot. The
existing BGE corpus is removed only after the Qwen artifact has passed every
pre-write validation below. Keep a compact database dump or exported count/hash
receipt only if comparison is useful; the environment is otherwise disposable.

1. Verify the archive SHA-256 before extraction.
2. Safely extract into a fresh staging directory; reject archive traversal and
   require exactly the expected three files.
3. Verify \`manifest.json\`, input-file hashes, 22,268 records, and the
   \`(22268, 1024)\` NPY shape before database writes.
4. Replace the current 768-dimension RAG storage/query contract with the Qwen
   1024-dimension contract in one migration. Delete the old BGE knowledge rows
   and HNSW index in the same controlled operation; never compare BGE and Qwen
   vectors in one similarity query.
5. Insert only \`kind='knowledge'\`, \`case_id=NULL\` rows. Preserve source
   file, upstream ID, per-record stable ID, manifest hash, model revision,
   query instruction, and transform version as provenance.
6. Query Qwen with the exact manifest instruction, normalize vectors, and use
   cosine distance. The model must be service-cached/offline-pinned; no runtime
   model download.
7. Bring the gateway back only after the Qwen migration, gateway surface tests,
   retrieval evaluation, and VM proof pass. A failed validation restores the
   pre-migration dump or reruns the test/dev provisioning path.

Do **not** run the existing 4,318-record direct seed against this full snapshot;
the artifact already includes that subset and doing so recreates the historical
26,586-row duplication.

## Required tests before cutover

- Archive/hash/shape/record-count rejection tests.
- A fail-on-revert provenance test: every imported row must remain
  knowledge-only and source-traceable.
- Qwen retrieval suite: ATT&CK, Sigma, Windows/Linux/macOS, source-filter,
  command-line, and natural-language queries. Compare with BGE only when a
  retained pre-replacement receipt is available.
- Exact cosine vs HNSW recall/latency tests with source/platform filters.
- Gateway surface tests for \`kb_search_knowledge\`,
  \`kb_list_knowledge_sources\`, and \`kb_get_knowledge_stats\`; update output
  models and the surface optional-key contract if the snapshot metadata becomes
  public.
- VM deploy/proof through the gateway only, including no-case-content and
  response-redaction negative tests.

## Deferred, explicit decision

Qwen3-Reranker-0.6B is not part of this artifact. Evaluate it as an optional
top-20 reranker after the dense Qwen snapshot has passed the CPU-only SIFT VM
latency benchmark.

## Manual SIFT VM proof (2026-07-11)

The disposable SIFT VM was migrated in place after a RAG-only rollback dump was
written under `/var/lib/sift/rag-rollbacks/`.

- Gateway stopped cleanly during the replacement and returned active afterward.
- PostgreSQL changed from `vector(768)` + IVFFlat to `vector(1024)` + HNSW
  (`m=16`, `ef_construction=128`).
- The two obsolete derived-capable `rag_search` overloads were removed. Only the
  six-argument knowledge-only search and the upsert function remain.
- Import completed atomically in about 35 seconds with 81.3 MiB peak importer
  memory: 22,268 chunks, 22,268 documents, 67 collections, 67 source labels.
- All source references passed the relative/path-free database check.
- The database trigger continued to reject a synthetic `kind='derived'` insert.
- The pinned model loaded from the `sift-service` cache with offline mode and
  emitted a normalized 1,024-dimensional query vector.
- Query `LSASS credential dumping detection` ranked the exact Splunk and Sigma
  LSASS detections first and second (cosine distances 0.1269 and 0.1426).
- Source-filtered query `PowerShell archive data before exfiltration` ranked
  Atomic Red Team's `Compress Data for Exfiltration With PowerShell` first.

The Codex host did not have a configured gateway bearer token, so the authenticated
HTTP `tools/call` was not fabricated. The exact gateway-owned `RAGServer` handler
was exercised under `sift-service` with the live control-plane DSN, and gateway
startup proved the registered `forensic-rag-mcp` backend. A final authenticated
MCP call remains an explicit acceptance item.

## Installer and fresh-schema integration

The branch now implements the repeatable fresh-install path:

1. The 58 MiB archive ships under `artifacts/` and is pinned by full SHA-256.
   The installer exact-allowlists its four tar members before extraction.
2. `scripts/core-addons/setup-rag.sh` has one active corpus path: service-owned
   Qwen model smoke test plus `rag_mcp.pgvector_snapshot_import`. Legacy direct
   and Chroma installer paths and console entrypoints were removed.
3. The installed importer validates format/model/revision/instruction, artifact
   hashes, NPY shape/finiteness, record order/count, and relative paths before
   connecting. It uses parameterized SQL and one transaction, records stable
   source provenance and snapshot fingerprints, skips only an exact current
   database, and rejects any non-empty mismatch.
4. Fresh schema migrations now create `vector(1024)` and HNSW directly. The
   knowledge-only migration drops historical derived-capable overloads. There
   is no upgrade-only compatibility migration.
5. The gateway service is configured offline after installation. The installer
   loads the pinned model as `sift-service` and proves a finite normalized
   1,024-dimensional query vector before importing.
6. Supabase bootstrap was also hardened: JWT secret state is outside the
   replaceable checkout; CLI credentials are reconciled every local install;
   gateway env is atomically refreshed; operator existence is checked against
   Auth/DB instead of the handoff; and a real password grant must pass before
   installer success.

## Final live acceptance (2026-07-11)

- The canonical installer imported the snapshot from an empty RAG plane and an
  immediate rerun returned `current: true` without writes or duplicates.
- All repository migrations applied successfully to an isolated scratch
  database. Final schema was `vector(1024)`, HNSW, and exactly one
  knowledge-only `app.rag_search` overload.
- Supabase setup reconciled the running Auth JWT secret into mode-600 operator
  state, removed the obsolete checkout-local secret, emitted no key material,
  and completed idempotently.
- A disposable operator bootstrap created the Auth user, mapped its owner
  profile, passed a real password grant, and was deleted afterward.
- The examiner forced-reset flow completed through the portal API. The permanent
  password was copied directly to the operator clipboard and is not stored by
  SIFT; the protected handoff now records `already-reset`.
- An authenticated temporary service principal scoped only to `namespace:kb`
  advertised and called all three KB tools. `case_info` was denied and the
  principal was revoked in `finally`; the database has zero active verifier
  principals.
- Warm LSASS semantic search completed in 101.3 ms. Atomic-source-filtered
  exfiltration search completed in 105.2 ms and ranked the expected PowerShell
  procedure first.
- Final data checks: 22,268 chunks/documents, 67 collections/sources, one
  snapshot fingerprint, zero missing provenance, zero non-knowledge rows, zero
  unsafe source references. The derived-insert negative test remained blocked.
- Gateway health and all four services were active. The loaded CPU model left
  gateway memory at approximately 668 MiB current / 670 MiB peak. Runtime model
  access is offline (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`).
