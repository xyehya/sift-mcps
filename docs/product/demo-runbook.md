# Demo Runbook

Status: rehearsal draft with AUT2 caveats. Validation owner: BATCH-FRZ1.
Last updated: 2026-06-09.

## Purpose

This document will become the final hackathon demo script. It should stay
product-facing and must not include raw passwords, tokens, DSNs, service-role
keys, OpenSearch credentials, or local VM secrets.

## Demo Narrative

1. Operator controls evidence and approvals in the portal.
2. AI agent receives only scoped MCP access.
3. Gateway enforces case, scope, evidence, audit, and response controls.
4. Agent investigates autonomously with search, RAG, jobs, and controlled
   command execution.
5. Operator approves findings.
6. Report export includes approved findings and custody/provenance proof.

AUT2 proved this narrative for the controlled smoke/custody path, not for full
Rocba disk+memory analysis. The final demo should say that boundary plainly.

## AUT2 Live Readiness

Use the prepared demo case; do not recreate it for the final rehearsal:

- Case: `case-v1gate-06081857`
  (`57a06521-c9b8-4654-92ac-42b4f2bb0915`).
- DB evidence gate: OK, `manifest_version=3`.
- Active sealed evidence: `rocba-cdrive.e01`, `Rocba-Memory.raw`,
  `v1-gate.log`, and `v1-ingest.jsonl`.
- Fresh portal-issued `mcp:*` agents see the 13-tool catalog including
  `rag_search_case`.
- RAG baseline: `app.rag_chunks=26586`.
- AUT2 agent artifacts: `F-codex-1-001`, `T-codex-1-002`,
  `TODO-codex-1-001`.
- Portal approval/report smoke: one finding approved with DB authority; report
  `1ff91996-5666-4b36-9568-c701f5204c24` generated, saved, downloaded, and
  quick secret-shape scan clean.

## Demo Script Boundary

Approved demo claim:

- The platform supports a sealed-case, MCP-only agent loop: orient, gate-check,
  enumerate evidence, search/RAG, run controlled commands, stage DRAFT
  investigation records, then hand back to the operator for approval and
  approved-only reporting.

Do not claim:

- The agent has completed full autonomous analysis of the Rocba disk and memory
  images. AUT2 found blockers in the primary-image paths.

Demo-safe investigative path:

1. Operator shows the prepared sealed case and DB gate OK.
2. Operator issues a fresh scoped agent principal through the portal.
3. Agent calls `case_info`, `evidence_info`, and `capability_guide`.
4. Agent confirms evidence by `run_command "ls evidence"` because
   `evidence_info.evidence_files` can still be empty under DB authority.
5. Agent runs the smoke ingest/search/RAG path and reads `v1-gate.log` /
   `v1-ingest.jsonl` through MCP.
6. Agent stages the limited suspicious PowerShell finding/timeline/TODO.
7. Operator reviews and approves in the portal.
8. Operator generates/saves/downloads the findings report and runs the leak
   scan.

## Final Rehearsal Checklist

- Clean git state.
- Migrations applied.
- Gateway and worker active.
- Supabase health OK.
- Evidence root OK.
- OpenSearch reachable and indexing.
- pgvector full forensic RAG corpus loaded.
- Portal login works.
- Case create/activate works.
- Evidence register/seal works.
- Agent credential issuance works through portal.
- MCP agent journey completes without side channels.
- Report export leak scan is clean.
- Security caveats are documented.
- AUT2 caveats are presented before any primary-image investigation claim.

## AUT2 Caveats for BATCH-FRZ1

- `ingest_job` does not ingest `.e01` or `.raw` single evidence files; it failed
  cleanly on both Rocba primary images.
- `run_command.evidence_refs` still reports no sealed evidence on the DB-sealed
  case; `input_files` worked only as a degraded smoke workaround.
- `record_finding` rejected a fresh `run_command` audit id for artifacts because
  its validation still checks the local JSONL audit trail, not DB audit
  authority. The AUT2 finding was approved for report smoke, but provenance was
  only PARTIAL/NONE.
- Volatility fails before analysis due cache-path permission errors, and MCP
  policy currently blocks the attempted env/cache-directory workarounds.
- EWF disk triage is not demo-ready: `mmls` returned exit 1 without useful
  stderr, and a piped `fls | head` masked the upstream failure.
- Summary/listing residuals remain: `evidence_info.evidence_files` can be empty
  even when DB gate is OK, and `case_info` counters can lag behind DB-backed
  finding/report state.
- Large binary grep previews can create context bloat, and response redaction
  produced benign false positives on URL-like strings/headings.

## Final Prompt Slot

BATCH-FRZ1 should replace this section with the exact demo run prompt after the
autonomy benchmark and final freeze rehearsal pass.
