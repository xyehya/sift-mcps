# Agent Autonomy Assessment

Status: skeleton. Validation owner: BATCH-AUT1.
Last updated: 2026-06-09.

## Assessment Question

Can an AI agent complete a realistic DFIR investigation through Gateway MCP
alone, with enough context, provenance, safety, and recovery behavior to feel
autonomous rather than manually driven?

## Scorecard

Score each category from 0 to 3.

| Score | Meaning |
| --- | --- |
| 0 | Blocks autonomous use. |
| 1 | Works only with human side-channel help or brittle prompting. |
| 2 | Works for the demo but has clear friction or context cost. |
| 3 | Strong autonomous behavior with clear contracts and recovery. |

| Category | What to assess |
| --- | --- |
| Discoverability | Tool names, descriptions, schemas, examples, and workflow hints. |
| Sufficiency | Whether tools cover the end-to-end investigation. |
| Context efficiency | Response size, previews, pagination, saved refs, repeated text. |
| Composability | Whether the agent can safely call multiple tools in parallel. |
| Error recovery | Typed failures and clear next actions. |
| Provenance | Evidence IDs, provenance IDs, source refs, output refs, hashes. |
| Security | No paths/secrets/authority bypass; correct denials. |
| Autonomy friction | Human interventions required after the agent starts. |

## Run Metrics

| Metric | Target |
| --- | --- |
| Total tool calls | Record baseline; reduce unnecessary calls over time. |
| Failed tool calls | Explain each failure and whether recovery was autonomous. |
| Human interventions | Zero after agent start, except intended operator approvals. |
| Largest response | Identify context-bloat risks. |
| Findings proposed | Each should include provenance. |
| Findings approved | Operator decision, not agent authority. |
| Missed evidence leads | Record as efficacy gaps. |
| Unsafe attempts | Must fail closed and remain useful to the agent. |
| Side-channel use | Should be zero for agent investigation. |

## Tool Review Table

| Tool | Discoverability | Sufficiency | Context | Parallel safety | Errors | Provenance | Security | Friction | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `case_info` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `evidence_info` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `ingest_job` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `job_status` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `rag_search_case` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `run_command_job` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `record_finding` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `record_timeline_event` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `manage_todo` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |
| `list_existing_findings` | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | Verify in BATCH-AUT1. |

## Assessment Output

BATCH-AUT1 should produce:

- a filled scorecard;
- exact tool descriptions/schemas as seen by the agent;
- context-size and response-bloat findings;
- parallel-safety classification;
- a list of autonomy blockers;
- a prioritized fix list before BATCH-AUT2 runs the demo-case benchmark.

