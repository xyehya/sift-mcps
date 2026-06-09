# Demo Runbook

Status: skeleton. Validation owner: BATCH-FRZ1.
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

## Final Prompt Slot

BATCH-FRZ1 should replace this section with the exact demo run prompt after the
autonomy benchmark and final freeze rehearsal pass.

