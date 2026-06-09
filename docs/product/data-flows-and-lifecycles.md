# Data Flows and Lifecycles

Status: skeleton. Validation owner: BATCH-PDOC1.
Last updated: 2026-06-09.

## Case Lifecycle

```mermaid
stateDiagram-v2
  [*] --> Created
  Created --> Active: operator activates with re-auth
  Active --> EvidencePending: files detected or added
  EvidencePending --> Sealed: operator registers and seals
  Sealed --> Investigation: agent tools allowed
  Investigation --> Review: findings/timeline/TODOs proposed
  Review --> Reportable: operator approves findings/supporting data
  Reportable --> Exported: operator re-auths and exports report
```

Authority: Supabase/Postgres. Case-local files may exist as workspace, debug,
legacy fallback, or immutable exports only.

## Evidence Lifecycle

```mermaid
sequenceDiagram
  participant O as Operator
  participant P as Portal
  participant G as Gateway
  participant DB as Postgres
  participant W as Worker/Broker
  participant E as Evidence Mount

  O->>E: copy or mount evidence
  P->>G: detect evidence
  G->>W: scan mounted evidence
  W->>DB: record detected evidence
  O->>P: name, describe, seal with re-auth
  P->>G: register and seal
  G->>DB: custody event and chain head
  G-->>P: sealed status and proof metadata
```

Post-seal file drift must move the evidence gate out of OK until the operator
resolves and seals again.

## Agent Credential Lifecycle

1. Operator issues a one-time AI credential from the portal.
2. Gateway binds the agent principal to allowed MCP scopes and default case
   context.
3. The agent calls MCP only.
4. Revocation or expiry prevents future tool use.
5. Token material is never written to product docs or repo files.

## MCP Tool Call Lifecycle

```mermaid
sequenceDiagram
  participant A as AI Agent
  participant M as Gateway MCP
  participant P as Policy Middleware
  participant DB as Postgres
  participant T as Tool Handler

  A->>M: tool call
  M->>P: authenticate, load active case, scopes
  P->>DB: audit envelope and policy reads
  P->>T: allowed call with AuthorityContext
  T->>DB: authoritative reads/writes or job enqueue
  T-->>P: tool result
  P-->>A: redacted, capped, provenance-linked response
```

Failures must be typed and actionable enough for the agent to select the next
safe tool call.

## Durable Job Lifecycle

1. Gateway validates caller, case, evidence gate, and scope.
2. Gateway enqueues a path-free public job spec plus worker-only internal spec.
3. Worker claims a job lease from Postgres.
4. Worker resolves paths internally and executes parser/command/report work.
5. Worker writes job steps, logs, provenance, output refs, and final status.
6. Agent/operator poll sanitized job status through Gateway.

## RAG Lifecycle

Shared forensic knowledge is stored as `kind='knowledge'` with `case_id NULL`.
It is not evidence and is not case-authoritative. The active case is still used
as the Gateway policy and audit context for `rag_search_case`.

Future case-derived RAG rows should use `kind='derived'`, case/provenance IDs,
and the same path/secret redaction rules as other agent-visible results.

## Finding and Report Lifecycle

1. Agent records proposed findings with evidence/provenance support.
2. Portal shows proposals as draft/proposed records.
3. Operator approves, rejects, or edits with re-auth where required.
4. Reports include approved findings and approved supporting data only.
5. Report export records metadata and custody proof references in Postgres.

