# Demo Runbook

Status: freeze candidate. MCP rehearsal proof, portal login/HMAC, and fresh
agent TTL are current; approval/export and optional re-acquisition click proof
remain final checklist actions. Validation owner: BATCH-FRZ1.
Last updated: 2026-06-10.

## Purpose

This is the final hackathon demo script for the prepared live case. It stays
product-facing and must not include raw passwords, tokens, DSNs, service-role
keys, OpenSearch credentials, or local VM secrets.

## Demo Narrative

1. Operator controls cases, evidence, credentials, approvals, and report export
   in the portal.
2. AI agent receives only scoped MCP access.
3. Gateway enforces case binding, tool scopes, evidence gate, audit, response
   shaping, and saved-output refs.
4. Agent investigates autonomously with orientation, RAG, search, jobs, and
   controlled command execution.
5. Operator approves findings and report inclusion.
6. Report export includes approved findings and custody/provenance proof only.

## Live Readiness

Use the prepared demo case; do not recreate it for the final rehearsal:

- Case: `case-v1gate-06081857`
  (`57a06521-c9b8-4654-92ac-42b4f2bb0915`).
- Active service tree: `/home/sansforensics/sift-mcps-test`.
- Gateway health: OK; Supabase health: OK; evidence root `/cases`: OK.
- Gateway/worker services: active.
- DB evidence gate: `sealed`, `manifest_version=4`, `active_count=4`, no
  issues.
- Active sealed evidence:
  `rocba-cdrive.e01` (logical EWF image; use `fls` directly, not `mmls`),
  `Rocba-Memory2.raw` (valid Windows 10 memory image), `v1-gate.log`, and
  `v1-ingest.jsonl`.
- Retired evidence: `Rocba-Memory.raw` is the corrupted original and is no
  longer active.
- MCP catalog: 13 tools, including `rag_search_case`, `run_command`,
  `run_command_job`, `job_status`, `record_finding`, `manage_todo`,
  `list_existing_findings`, `case_info`, and `evidence_info`.
- RAG baseline: `app.rag_chunks=26586`, all `kind='knowledge'`, all
  `case_id NULL`; `22268` rows came from `chroma_release_pgvector`.
- MCP proof from 2026-06-10: `case_info` returned chain `ok`,
  `manifest_version=4`, and DB-authoritative finding counters;
  `evidence_info` listed exactly the four sealed evidence objects with
  `listing_authority=db`; `rag_search_case` returned `status=ok`.
- Forensic-tool proof from 2026-06-10: `vol -f evidence/Rocba-Memory2.raw
  windows.info` exited 0 and identified Windows 10 build 19041; `fls
  evidence/rocba-cdrive.e01 | head -20` exited 0 and listed the logical E01
  filesystem root.
- Current investigation records: `F-codex3-001` is DRAFT,
  `F-codex-1-001` is APPROVED, `F-hermes-v1-gate-001` is REJECTED, and
  `TODO-codex-1-001` remains open.
- Portal proof from 2026-06-10: operator login with
  `examiner@operators.sift.local` succeeded, `must_reset=false`, HMAC challenge
  and verify succeeded, and a fresh portal-issued agent principal saw the
  13-tool MCP catalog. The fresh agent JWT TTL is `172800` seconds / 48 hours.
- Portal Settings now shows the post-migration principal/session table only for
  normal operation: Supabase JWT token type, display name, status,
  TTL remaining, scopes, and disabled/dimmed revoke after success.
- MCP schema proof from 2026-06-10: `rag_search_case` is in the 13-tool catalog
  with a plain object input schema and no top-level `anyOf`/`oneOf`/`allOf`;
  a direct RAG call returned `status=ok` with two result rows.

## Demo Boundary

Approved demo claim:

- The platform supports a sealed-case, MCP-only agent loop: orient, gate-check,
  enumerate DB-backed evidence, query RAG, run controlled commands against
  sealed evidence refs, stage DRAFT investigation records, then hand back to
  the operator for approval and approved-only reporting.
- The prepared Rocba evidence is triage-readable through controlled tools:
  Memory2 supports Volatility `windows.info`, and the logical E01 supports
  direct `fls` listing.
- Re-acquisition is a real custody transition: a violated object can be
  superseded under operator re-auth, preserving the prior hash/version in the
  custody ledger; the corrupted original memory image was retired in favor of
  `Rocba-Memory2.raw`.

Do not claim:

- The agent has completed full autonomous disk and memory analysis of the Rocba
  images.
- The E01 has a partition table. It is a logical image; use filesystem tools
  directly.
- The RAG corpus is case evidence. It is shared forensic knowledge unless a row
  carries case/provenance binding.

## Operator Sequence

1. Log in to the portal with the current operator password.
2. Confirm the active case is `case-v1gate-06081857`.
3. Show evidence gate `sealed`, manifest version 4, and four active sealed
   objects.
4. Issue a fresh agent principal with `mcp:*` scope. Confirm token TTL is about
   48 hours and store token material only in local/VM secret storage.
5. Give the agent the prompt in the next section.
6. Review the staged finding, timeline, and TODO. Approve only claims supported
   by MCP audit IDs and sealed evidence refs.
7. Generate, save, and download the report. Run the leak scan before showing
   the output.
8. For the custody story, show the retired `Rocba-Memory.raw` row and the
   re-acquisition event details for `Rocba-Memory2.raw`. If a live re-acquire
   click demo is needed, perform it on a throwaway case/file, not the prepared
   Rocba evidence.

## Agent Demo Prompt

```text
You are the SIFT demo agent. Use Gateway MCP tools only. Do not ask for local
paths, DB credentials, service tokens, OpenSearch credentials, or shell access
outside the MCP tools.

1. Orient with case_info and evidence_info. Confirm the evidence chain is OK,
   manifest_version is 4, listing_authority is db, and the four active sealed
   objects are rocba-cdrive.e01, Rocba-Memory2.raw, v1-gate.log, and
   v1-ingest.jsonl.
2. Use rag_search_case for PowerShell investigation guidance and explain that
   RAG hits are shared knowledge unless case-bound provenance is present.
3. Read v1-gate.log and v1-ingest.jsonl through run_command using evidence_refs,
   save_output=true, and small preview_lines.
4. Optionally run these bounded tool checks through run_command with
   evidence_refs and saved output:
   - vol -f evidence/Rocba-Memory2.raw windows.info
   - fls evidence/rocba-cdrive.e01 | head -20
5. Stage one concise finding, one timeline event, and one TODO only if each
   references MCP audit IDs from the tool responses. Keep the claim bounded to
   the smoke evidence and do not claim full autonomous Rocba analysis.
6. Stop after staging. Tell the operator which IDs need review and approval.
```

## Final Rehearsal Checklist

- Clean git state except local `.mcp.json`.
- Migrations applied.
- Gateway and worker active.
- Supabase health OK.
- Evidence root OK.
- OpenSearch reachable and indexing.
- pgvector full forensic RAG corpus loaded.
- Portal login works with the current operator password.
- HMAC re-auth challenge succeeds.
- Fresh portal-issued `mcp:*` agent sees the 13-tool catalog.
- MCP agent journey completes without side channels.
- Re-acquisition click proof is run on a throwaway case/file if shown live.
- Report export leak scan is clean.
- Security caveats are documented.
