# Agentic security assessment methodology

## Inputs to collect

- Architecture diagrams, README files, deployment docs, MCP config, `.env.example`, Docker Compose, Supabase migrations, OpenSearch config, worker job code, tool descriptors, and audit/logging code.
- Current security assumptions: local only vs remote, single user vs multi-user, demo vs production, case tenancy model, evidence mutability model.
- Code paths that translate natural language, model output, evidence content, or retrieval results into tool calls, SQL, OpenSearch DSL, shell commands, filesystem paths, or worker jobs.

## Phase 1: inventory

Create a table with these columns:

| Component | Trust zone | Data handled | Identity used | Tools/actions | Stores touched | ASI risks |
|---|---|---|---|---|---|---|

Minimum components to include:

- Agent client and MCP client configuration.
- MCP gateway/server and every tool.
- FastAPI routes and auth dependencies.
- Supabase tables, policies, storage buckets, realtime channels.
- OpenSearch indexes, aliases, pipelines, and query builders.
- Worker runtime, job claim logic, parser invocations, report generation.
- Evidence vault and derived artifact storage.
- Audit trail, traces, logs, and alerting.

## Phase 2: static triage

Run the bundled scanner if code access exists:

```bash
python3 .agents/skills/agentic-security/scripts/agentic_security_scan.py --root . --out .agentic-security
```

Use the result as leads only. Confirm every important issue manually.

## Phase 3: control review

Review these controls in order:

1. Authentication and authorization.
2. Case and tenant isolation.
3. Tool policy enforcement.
4. Prompt injection and output handling.
5. Host command execution safety.
6. Evidence immutability and chain of custody.
7. Worker queue safety and idempotency.
8. OpenSearch retrieval safety.
9. Memory/context poisoning controls.
10. Audit, alerting, kill switch, and incident response.

## Phase 4: safe adversarial testing

Use synthetic fixtures only:

- Prompt-injection strings embedded in text evidence.
- Filenames with shell metacharacters.
- Cross-case fake IDs.
- Low-trust RAG documents that claim policy authority.
- Replayed or stale worker events.
- Oversized output fixtures.

Never use real secrets or destructive commands.

## Phase 5: reporting

Prioritize fixes by blast radius and exploitability, not by how easy the patch is. A good report contains:

- One-paragraph summary.
- Findings mapped to ASI IDs and stack layers.
- Concrete patches or design changes.
- Tests that would fail before the fix and pass after.
- Residual risk and follow-up work.
