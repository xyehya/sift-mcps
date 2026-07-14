# Interaction Model

Status: archival — interaction model and re-auth gates remain accurate.
Updated by BATCH-RG1 (2026-06-13): `rag_search_case` references updated to reflect
removal; current RAG tools are `kb_search_knowledge` etc. via `forensic-rag-mcp`.
Last updated: 2026-06-13 (RG1 corrections applied on top of original 2026-06-09 entry).

This document defines how the human operator and the AI agent interact across the
Gateway policy boundary: the handoff, the re-auth gates, the tool loops, and
failure recovery. The operator journey detail lives in `operator-journey.md`, the
agent journey in `ai-agent-journey.md`, and the lifecycles in
`data-flows-and-lifecycles.md`. This file is the connective tissue between them.

## Actors and Interfaces

| Actor | Primary interface | Authority | Cannot do |
| --- | --- | --- | --- |
| Operator | Portal REST UI (through Gateway) | Case activation, evidence decisions, credentials, approvals, report export. | Investigate at machine scale. |
| AI agent | Gateway `/mcp` (MCP only) | Investigation actions scoped to active case + allowed tools. | Seal evidence, approve findings, issue credentials, see raw paths/secrets. |
| Gateway | Internal policy + orchestration | Auth, authorization, redaction, audit, evidence gate, job enqueue. | Hold mutable case authority (that is Postgres). |
| Worker | Postgres job claim loop | Local processing after policy approval. | Accept an agent-to-worker channel (there is none). |

The two human-visible interfaces (portal REST, MCP) never share a second
authorization path: the Gateway is the **sole policy boundary**
(`architecture.md` section 4; `AGENTS.md` security invariants).

## Human <-> Agent Handoff

```mermaid
sequenceDiagram
  participant OP as Operator (portal)
  participant GW as Gateway
  participant AG as AI agent (MCP)
  OP->>GW: activate case (G1 re-auth)
  OP->>GW: register + seal evidence (G2 re-auth)
  Note over GW: Evidence gate now OK
  OP->>GW: issue one-time agent credential (G3 re-auth)
  OP-->>AG: hand off credential + case brief + objective
  AG->>GW: investigate (orient -> ingest -> search -> record DRAFT)
  AG-->>OP: proposals appear as DRAFT in the portal
  OP->>GW: approve / reject / edit (G4 re-auth)
  OP->>GW: generate + export report (G5 re-auth)
```

Handoff rules:

1. The operator prepares and **seals** the case before any agent work is allowed.
2. The operator **issues** the scoped, case-bound credential and hands it off.
3. The agent **proposes** (`DRAFT`); it never finalizes.
4. The operator **reviews and approves**; approval human-locks the row.
5. The operator **exports** the report and custody proof.

The handoff is asynchronous: the agent works while the operator monitors, and the
operator's approvals gate what can ever reach a report.

Pre-seal handback is intentional. If the agent receives an
`evidence_gate_denied` result, the correct autonomous behavior is to stop
analysis for that case, summarize what is blocked, and hand control back to the
operator for evidence registration/seal. The agent should not try alternate
tools to route around the gate.

Draft-to-portal commit is the core collaboration boundary. Agent calls such as
`record_finding`, `record_timeline_event`, and `manage_todo` create or update
proposed records with provenance. They do not make reportable truth. The portal
review action is the commit point that turns a proposal into approved,
human-owned report input.

## Re-Auth Gate Model

Five sensitive transitions require fresh Supabase password re-authentication.
These are operator-only — the agent can never satisfy them.

| Gate | Action | Mechanism (MVP) | Authority recorded |
| --- | --- | --- | --- |
| G1 | Case activation | Supabase password re-auth + scoped audit receipt | `app.active_case_state` |
| G2 | Add/Seal, Replace/Reacquire, exact Restore, Ignore/Delete/Retire, Full Verify Evidence | Supabase password re-auth + operation/object-bound audit receipt | durable custody operation + `app.evidence_custody_events` + chain head |
| G3 | Agent credential issuance | Supabase password re-auth + scoped audit receipt | Supabase principal + scope rows |
| G4 | Finding approval | Supabase password re-auth + scoped audit receipt | `app.investigation_*` (human-locked) |
| G5 | Report inclusion / export | Supabase password re-auth + scoped audit receipt | `app.report_metadata` + proof refs |

The verifier uses the authenticated session identity, discards password-grant
tokens, and fails closed without Supabase or DB audit authority. Historical
BATCH-V1 proof used the then-current re-auth mechanism; it is not the active
credential contract.

Current re-auth loop:

1. The signed-in operator submits the sensitive action with their password and
   exact action inputs.
2. The Gateway re-verifies that password with Supabase for the authenticated
   session identity; it never accepts a client-supplied identity.
3. The Gateway records an action/object/operation-scoped DB audit receipt and
   discards any returned password-grant token.
4. The service-only transition RPC validates and consumes the receipt, then
   atomically records the authorized state change. Missing, reused, cross-case,
   cross-action, or wrong-actor receipts fail closed.

There is no process-local challenge state and no local HMAC/password proof in
the active contract. Gateway restart therefore cannot erase authorization state
for an already-started durable custody operation.

## Agent Tool Loops

The agent's interaction is a set of bounded loops, all mediated by the Gateway
middleware chain (`policy_middleware.py`):

| Loop | Tools | Termination |
| --- | --- | --- |
| Orientation | `case_info`, `evidence_info`, `get_tool_help` | once oriented |
| Ingest | `ingest_job` -> `job_status` | job `succeeded`/`failed` |
| Search/ground | OpenSearch search (`opensearch_search`), `kb_search_knowledge` (via forensic-rag-mcp add-on) | enough context gathered | (`rag_search_case` removed — RG1) |
| Deeper analysis | `run_command_job`, `run_command` | output captured + hashed |
| Record | `record_finding`, `record_timeline_event`, `manage_todo`, `list_existing_findings` | proposals staged as `DRAFT` |

Every loop returns opaque IDs and redacted, size-capped output so the agent can
chain to the next call without context bloat. The agent polls jobs rather than
blocking, and de-duplicates findings via `list_existing_findings` before
recording new ones.

Phase-ordered agent loop for the demo case:

1. Orient: call `case_info`, `evidence_info`, and tool-help/capability guidance.
2. Gate check: if evidence is unsealed or stale, hand back to the operator.
3. Prepare derived data: enqueue `ingest_job` when needed.
4. Poll: use `job_status` until a terminal state (`succeeded`, `failed`,
   `cancelled`, or `expired`) appears; do not enqueue duplicate jobs only
   because a job is pending.
5. Ground: use OpenSearch (`opensearch_search`) and `kb_search_knowledge` (via
   forensic-rag-mcp add-on) to collect evidence and forensic knowledge context.
   **RG1: `rag_search_case` removed; use `kb_*` tools through the add-on.**
6. Deepen: use `run_command_job` only when the allowed command adds specific
   forensic value and can cite controlled output refs.
7. Propose: record findings/timeline/TODOs with provenance.
8. Hand back: let the operator review, approve, and export.

Redaction recovery is not a bypass. If a useful value is redacted, the agent
should continue with opaque IDs, provenance IDs, hashes, display paths, and saved
artifact refs. If an operator or developer needs to inspect a redacted local
value for troubleshooting, that belongs in an operator/debug path outside the
agent-facing MCP contract and must not expose raw paths or secrets to the agent.

## Error and Recovery Model

Agent-facing errors are structured around the **next safe action**, not raw
stack traces:

| Error class | Meaning | Agent action |
| --- | --- | --- |
| `auth_denied` | Credential/scope invalid or revoked. | Stop. Do not retry or seek a side channel. |
| `active_case_denied` | No bound active case. | Stop or ask operator to activate/bind. |
| `evidence_gate_denied` | Evidence not sealed (or post-seal drift). | Wait; ask operator to register/seal; re-orient. |
| `job_pending` | Durable job not finished. | Poll `job_status` after a delay; do not relaunch. |
| `tool_policy_denied` | Tool not in scope / operator-only. | Choose a different allowed tool. |
| `input_validation_error` | Bad arguments. | Correct arguments and retry once. |
| `backend_unavailable` | Derived plane (OpenSearch/RAG/add-on) down. | Report degraded plane; continue with available tools if safe. |

Recovery principle: the agent should always be able to choose a productive next
tool or cleanly hand back to the operator. It must never need a filesystem, DB,
OpenSearch, or shell side channel. (Mapping of these classes to concrete Gateway
responses is owned by BATCH-PDOC2/AUT1; the classes above are the product
contract.) Live proof of fail-closed recovery: pre-seal denial then post-seal
success in BATCH-V1.

## Parallel Tool-Call Safety

Parallel safety is an autonomy feature: it lets the agent search, retrieve RAG
context, and poll jobs concurrently without waiting, while preventing state races
around evidence, findings, and job execution.

Product-level classification (BATCH-AUT1 produces the per-tool verdict in
`agent-autonomy-assessment.md`):

| Class | Tools | Rationale |
| --- | --- | --- |
| Safe in parallel (read-only) | `case_info`, `evidence_info`, `list_existing_findings`, `opensearch_search`, `kb_search_knowledge` (via add-on), `job_status` | No mutation; idempotent reads. (`rag_search_case` removed — RG1) |
| Parallel-safe launch, poll separately | `ingest_job`, `run_command_job` | Durable jobs are independent; the worker serializes via `claim_next_job` (`FOR UPDATE SKIP LOCKED`). |
| Serialize by state | `record_finding`, `record_timeline_event`, `manage_todo` | Content-hash/version guards reject stale concurrent writes (`investigation_store.StaleVersionError`). |
| Operator-only / not agent-facing | seal, approve, issue credential, report export | Behind re-auth gates G1–G5. |

Grounding: worker atomic claim is `app.claim_next_job` with `FOR UPDATE SKIP
LOCKED` (`202606081200_durable_jobs.sql`; `execute/job_worker.py`); investigation
write guards are in `202606081600_investigation_authority.sql` and
`investigation_store.py`. The definitive per-tool parallel-safety table is
BATCH-AUT1's deliverable. Status here: product-level guidance, AUT1 to verify.
