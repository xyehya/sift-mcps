# MCP Contracts

Status: skeleton. Validation owner: BATCH-PDOC2 and BATCH-AUT1.
Last updated: 2026-06-09.

## Scope

This document describes the AI-agent-facing MCP surface. It must be written from
the agent's point of view: what the agent sees, what the tool is for, what input
shape it needs, what output shape it returns, how much context it consumes, and
what the agent should do after success or failure.

## Tool Contract Template

```text
Tool:
Status:
Purpose:
Agent-visible description:
Required scope:
Required case/evidence state:
Input schema:
Output schema:
Context budget:
Pagination/preview behavior:
Saved artifact behavior:
Parallel safety:
Success example:
Error examples:
Recovery guidance:
Provenance fields:
Security checks:
Tests/live proof:
Autonomy notes:
```

## Initial Tool Inventory to Verify

BATCH-PDOC2 must verify the live Gateway catalog before treating this list as
final.

| Tool | Expected role |
| --- | --- |
| `case_info` | Orient the agent to the active case without local paths. |
| `evidence_info` | Show sealed evidence IDs, names, status, hashes, and display paths. |
| `ingest_job` | Start derived ingestion through durable jobs. |
| `job_status` | Poll sanitized job status and logs. |
| `rag_search_case` | Retrieve shared forensic knowledge and future case-derived context through pgvector. |
| `run_command_job` | Run allowed deeper-analysis commands through the worker sandbox. |
| `record_finding` | Propose a finding with provenance support. |
| `record_timeline_event` | Propose timeline entries. |
| `manage_todo` | Track investigation tasks. |
| `list_existing_findings` | Inspect current proposed/approved finding state. |
| `get_tool_help` / `capability_guide` | Help the agent choose the next tool if present in the live catalog. |

## Context Management Rules

- Prefer concise summaries over full payloads.
- Return bounded previews for command/search output.
- Use opaque output refs for large payloads.
- Include enough metadata for the agent to retrieve or cite later.
- Avoid returning exhaustive directory trees or repeated boilerplate.
- Every bloated response found in BATCH-AUT1 should become either a contract
  fix, a pagination requirement, or a known limitation.

## Parallel Safety Classes

| Class | Meaning |
| --- | --- |
| Read-parallel | Safe to call concurrently with other read-only tools. |
| Job-parallel | Safe to enqueue or poll as independent durable jobs. |
| Case-serialized | Should be serialized because it mutates case/investigation state. |
| Operator-only | Not callable by the AI agent. |
| Denied | Must fail closed for the AI agent. |

## Required BATCH-AUT1 Work

- Capture actual tool schemas and descriptions from the live Gateway.
- Score each tool for discoverability, sufficiency, context efficiency,
  composability, errors, provenance, security, and autonomy friction.
- Identify missing tools or description/schema gaps that block an MCP-only
  investigation.
- Produce concrete fixes or backlog rows for high-impact autonomy defects.

