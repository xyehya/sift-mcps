# Interaction Model

Status: skeleton. Validation owner: BATCH-PDOC1 and BATCH-AUT1.
Last updated: 2026-06-09.

## Actors

| Actor | Primary interface | Authority |
| --- | --- | --- |
| Operator | Portal REST UI | Case activation, evidence decisions, credentials, approvals, report export. |
| AI agent | Gateway MCP | Investigation actions only, scoped to active case and allowed tools. |
| Gateway | Internal policy and orchestration | Auth, authorization, redaction, audit, evidence gate, job enqueue. |
| Worker | Postgres job claim loop | Local processing after policy approval. |

## Human-Agent Handoff

1. Operator prepares and seals the case.
2. Operator issues an agent credential.
3. Agent investigates through MCP.
4. Agent records proposals, not final approvals.
5. Operator reviews and approves.
6. Operator exports report and custody proof.

## Re-Auth Model

Sensitive human actions require re-auth. Current MVP behavior uses the local
HMAC bridge where implemented. Product docs should name this honestly and track
Supabase password re-auth as an improvement area if it remains deferred.

## Error and Recovery Model

Agent-facing errors should be structured around the next safe action:

| Error class | Agent action |
| --- | --- |
| `auth_denied` | Stop; credential or scope is invalid. |
| `active_case_denied` | Stop or ask operator to activate/bind case. |
| `evidence_gate_denied` | Ask operator to register/seal evidence. |
| `job_pending` | Poll `job_status` after delay. |
| `tool_policy_denied` | Choose a different allowed tool. |
| `input_validation_error` | Correct arguments and retry once. |
| `backend_unavailable` | Report degraded plane and continue with available tools if safe. |

## Parallel Tool Calls

BATCH-AUT1 must classify each MCP tool:

- safe to call in parallel;
- safe in parallel only for read-only calls;
- serialized by case/evidence/job state;
- operator-only or not agent-facing.

Parallel safety is an autonomy feature. It allows agents to search, retrieve
RAG context, and poll jobs without waiting unnecessarily, while preventing
state races around evidence, findings, and job execution.

