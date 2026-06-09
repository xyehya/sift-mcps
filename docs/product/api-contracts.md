# API Contracts

Status: skeleton. Validation owner: BATCH-PDOC2.
Last updated: 2026-06-09.

## Scope

This document will describe operator-facing Portal/Gateway REST contracts. MCP
contracts live in `mcp-contracts.md`.

## Contract Template

Each REST contract should use this shape:

```text
Endpoint:
Method:
Actor:
Auth:
Required role/scope:
Request:
Response:
State transition:
Re-auth required:
Audit behavior:
Failure modes:
Security notes:
Tests:
```

## Contract Groups

| Group | Purpose | Authority notes |
| --- | --- | --- |
| Auth/session | Login, forced reset, logout, current operator. | Supabase Auth plus operator profile status. |
| Cases | Create, list, activate, active case status. | Postgres active case authority. |
| Evidence | Detect, register/seal, ignore/retire, proof export. | DB custody chain and evidence gate authority. |
| Agent principals | Issue/revoke scoped AI agent credentials. | Operator-only, re-auth gated. |
| Jobs | Enqueue/poll long-running work for operator flows. | Durable Postgres jobs; path-free responses. |
| Investigation records | Findings, timeline, IOCs, TODOs, review actions. | DB-backed records and content hashes. |
| Reports | Eligibility, generate, export/download metadata. | Approved-only and re-auth gated. |
| Health/admin | Service health and readiness. | Must not expose secrets. |

## Required BATCH-PDOC2 Work

- Inventory live route paths from code.
- Document request and response shapes.
- Document state transitions and re-auth requirements.
- Confirm which REST actions are operator-only.
- Add example success and error payloads without secrets.
- Link each contract to tests or live proof in `Session-Notes.md`.

