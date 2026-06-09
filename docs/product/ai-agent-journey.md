# AI Agent Journey

Status: skeleton. Validation owner: BATCH-AUT1 and BATCH-AUT2.
Last updated: 2026-06-09.

## Goal

The AI agent should be able to conduct a realistic DFIR investigation through
MCP alone after the operator has activated a sealed case and issued a scoped
credential. The agent should not need raw filesystem access, direct OpenSearch
access, database access, service credentials, or shell access.

## Baseline Agent Loop

1. Orient to the active case and evidence state.
2. Discover available tools and expected workflow.
3. Query case/evidence summaries.
4. Launch or inspect ingest jobs.
5. Search derived OpenSearch content.
6. Ask RAG for forensic grounding and enrichment context.
7. Use controlled `run_command_job` only when deeper analysis is justified.
8. Record proposed findings, timeline events, IOCs, and TODOs.
9. Poll job status and recover from failures.
10. Avoid report approval/export; those are operator actions.

## Autonomy Requirements

- Tool names and descriptions must make the next action obvious.
- Tool schemas must be strict enough to prevent unsafe guesses but ergonomic
  enough for common DFIR tasks.
- Responses must fit context budgets through summaries, previews, pagination,
  and saved output refs.
- Errors must explain whether the agent should retry, wait, ask the operator,
  or choose a different tool.
- Every substantive finding should be supportable by evidence IDs, provenance
  IDs, search hits, RAG source refs, command output refs, or custody proof refs.
- The agent must not see absolute case paths, evidence paths, mount paths, DB
  secrets, OpenSearch credentials, service-role keys, or local VM secrets.

## Autonomy Failure Modes

| Failure mode | Product impact | Tracked by |
| --- | --- | --- |
| Tool catalog is unclear | Agent stalls or calls wrong tools. | BATCH-AUT1 |
| Response bloat fills context | Agent loses investigation state. | BATCH-AUT1 |
| Errors lack recovery hints | Agent loops or needs human intervention. | BATCH-AUT1 |
| Missing provenance | Findings are weak or unreportable. | BATCH-AUT2 |
| Tool gaps in the forensic workflow | Agent cannot complete investigation MCP-only. | BATCH-AUT2 |
| Unsafe side-channel needed | Autonomy/security thesis fails. | BATCH-AUT2 |

## Demo Prompt Shape

The final demo prompt should give the agent only:

- the Gateway MCP endpoint configuration;
- the one-time/scoped agent credential from the portal;
- the case brief;
- the investigation objective;
- constraints that all work must happen through MCP.

No local paths, direct database instructions, OpenSearch credentials, or shell
commands should be included.

