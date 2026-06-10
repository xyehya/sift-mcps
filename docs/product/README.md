# SIFT Product Documentation

Status: post-MVP QA and demo-freeze workspace.
Last updated: 2026-06-10.

This directory holds product-facing documentation for the SIFT MCP DFIR
platform after the MVP cutover. It is separate from `docs/migration`, which
remains the three-file execution tracker for migration state, batch tracking,
and session notes.

## Purpose

The hackathon theme to prove is AI-agent autonomy for DFIR without weakening
evidence custody, operator control, or policy boundaries. These documents must
therefore explain both sides of the product:

- what the operator controls through the portal;
- what the AI agent can do through MCP;
- how Gateway, Supabase/Postgres, local workers, OpenSearch, pgvector RAG, and
  reports cooperate without exposing secrets or raw evidence paths;
- where the product is strong today, where it is limited, and how to improve it.

## Documentation Map

| Document | Owned by | Purpose |
| --- | --- | --- |
| `architecture.md` | BATCH-PDOC1 | Product architecture diagrams and component responsibilities. |
| `data-flows-and-lifecycles.md` | BATCH-PDOC1 | Case, evidence, agent, MCP call, job, RAG, finding, and report lifecycles. |
| `operator-journey.md` | BATCH-PDOC1 | Portal-first human workflow from install to report export. |
| `ai-agent-journey.md` | BATCH-AUT1 / BATCH-AUT2 | MCP-only autonomous investigation journey and evaluation script. |
| `interaction-model.md` | BATCH-PDOC1 / BATCH-AUT1 | Human-agent handoff, re-auth gates, tool loops, and failure recovery. |
| `api-contracts.md` | BATCH-PDOC2 | Portal/Gateway REST contracts, lifecycle states, errors, and security notes. |
| `mcp-contracts.md` | BATCH-PDOC2 / BATCH-AUT1 | MCP tool inventory, schemas, response budgets, examples, and parallel-safety. |
| `agent-autonomy-assessment.md` | BATCH-AUT1 | Scorecard for judging whether the MCP surface supports real autonomy. |
| `security-architecture.md` | BATCH-SEC1 | Trust boundaries, control objectives, threat model, and baseline controls. |
| `security-assessment.md` | BATCH-SEC1 | Security assessment report template and finding register. |
| `code-structure.md` | BATCH-PDOC1 | High/mid-level codebase map for future development. |
| `known-limitations-and-improvements.md` | BATCH-FRZ1 | Accepted limitations, improvement backlog, and demo caveats. |
| `demo-runbook.md` | BATCH-FRZ1 | Freeze rehearsal script and demo prompt structure. |

## Operating Rules

- Do not store raw passwords, tokens, service-role keys, DSNs, OpenSearch
  credentials, or local VM secrets in these files.
- Prefer diagrams, tables, contracts, and concrete examples over broad claims.
- Mark unverified claims as `Status: TODO` or `Status: needs live proof`.
- When a QA run proves a behavior, record the evidence in
  `docs/migration/Session-Notes.md` and update the relevant product doc.
- Product docs may describe current limitations frankly. Limitations that affect
  the demo must also appear in `known-limitations-and-improvements.md`.
- MCP documentation must be written from the AI agent's point of view: what the
  agent sees, what it can infer, what it can safely call next, and how much
  context the response consumes.
