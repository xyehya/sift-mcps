# Security Architecture

Status: skeleton. Validation owner: BATCH-SEC1.
Last updated: 2026-06-09.

## Security Thesis

SIFT enables AI-agent autonomy by narrowing, mediating, and auditing the agent's
capabilities. The agent gets MCP tools, not raw evidence paths, shell access,
database credentials, OpenSearch credentials, service-role keys, or report
approval authority.

## Trust Boundaries

| Boundary | Control objective |
| --- | --- |
| Browser to Gateway | Authenticate operator, protect sessions, require re-auth for sensitive actions. |
| Agent to Gateway MCP | Validate JWT/token, scopes, active case, evidence gate, and rate limits. |
| Gateway to Postgres | Use service-only transitions and avoid exposing service credentials to clients. |
| Gateway to worker | Enqueue path-free jobs; worker resolves local paths internally. |
| Worker to evidence mount | Read mounted evidence under ACL/audit controls; no agent-visible paths. |
| Derived planes | OpenSearch/RAG/add-ons cannot authorize cases, evidence, approvals, or reports. |

## Baseline Controls

- Supabase/Postgres authority for mutable state.
- Gateway-only policy boundary.
- MCP-only agent operation for the MVP.
- Operator-only portal REST mutations for human approvals and credentials.
- Evidence registered and sealed before analysis.
- Password/HMAC re-auth for sensitive human actions.
- DB audit envelope for post-context tool calls and local telemetry for
  accepted pre-context denials.
- Response guard for paths and secrets.
- Durable jobs for long-running work.
- `run_command` with `shell=False`, deny floor, allowlisted profiles, env scrub,
  ACLs, and hashed output refs.

## Threat Areas for BATCH-SEC1

| Area | Questions |
| --- | --- |
| Auth/session | Can stale, revoked, or wrong-case principals still act? |
| Authorization | Are portal REST and MCP equivalent where they should be? |
| Evidence gate | Can unsealed or tampered evidence be analyzed? |
| Response leakage | Do tools leak paths, DSNs, service keys, OpenSearch creds, or VM secrets? |
| Job/worker boundary | Can public job specs smuggle paths or commands? |
| `run_command` | Can allowed commands read authority files or inherited secrets? |
| RAG/OpenSearch/add-ons | Can derived planes affect authority decisions? |
| Reports | Can unapproved data enter a report? |

