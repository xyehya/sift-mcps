# Open-Items Register — Forks (F#) & Backlog (B#)

The single home for open decisions and deferred work, per `OPERATING_MODEL.md` §5.
Append-only; mark status, do not delete. Forks (F#) await an operator call; Backlog
(B#) are accepted-but-deferred work with a do-by phase. Resolved forks point to the
Decision (D#) or Backlog (B#) they became.

Format:
```
F-<n> | <question> | raised | status | decision | becomes | affects
B-<n> | <deferred work> | source | status | do-by
```

---

## Forks (F#)

| ID | Question | Raised | Status | Decision (date) | Becomes | Affects |
| --- | --- | --- | --- | --- | --- | --- |
| F-1 | Model the read-only status/catalog "tools" as MCP **resources**? | Run 18, doc 16 §2/§7 | **RESOLVED** | APPROVED additively (2026-06-07): 4 strong → resources + deprecated tool alias; 2 query-shaped (`opensearch_list_detections`, `opensearch_case_summary`) stay tools + optional resource view | B-1 (alias removal horizon) | D27b `ResourcesAsTools`, golden snapshot |
| F-2 | Legacy wintriage dispatch aliases — formalize or drop? | Run 18, doc 16 §6/§7 | **RESOLVED** | KEEP as deprecated aliases one cycle (2026-06-07); grep found `analyze_filename` referenced in a `forensic-knowledge` playbook + `tool_metadata.py`, so drop would break a skill | B-2 (removal + playbook update) | wintriage surface, golden snapshot |
| F-3 | Must the gateway response-guard scan `structured_content`, not just text? | Run 18, doc 16 §1.1/§7 | **RESOLVED** | REQUIRED — security (2026-06-07); text-only scanning of typed output is a redaction bypass | B-3 (D27b gate + `/security-review`) | D27b, response_guard |
| F-4 | `opensearch_timeline` bucket ceiling value + truncate vs warn? | Run 18, doc 16 §3.5/§7 | **RESOLVED** | ADD cap ~2000, configurable; **warn, never silently truncate** (2026-06-07) | (implemented in D27a) | opensearch_timeline contract |
| F-5 | `opensearch_ingest.password` redaction? | Run 18, doc 16 §3.11/§7 | **RESOLVED** | REDACT in audit/logs/`ToolResult` (2026-06-07, mandatory) | B-4 (credential-as-arg redesign) | response_guard, audit, ingest contract |

## Backlog (B#)

| ID | Deferred work | Source | Status | Do-by phase |
| --- | --- | --- | --- | --- |
| B-1 | Remove the tool-form aliases of the reclassified resources (`opensearch_status`, `opensearch_shard_status`, `cti_get_health`, `wintriage_server_status`) once skills/RAG are updated to the resource URIs. | F-1 | OPEN | at/after D27b |
| B-2 | Remove the 10 legacy wintriage dispatch aliases after one cutover cycle; first update the `forensic-knowledge` playbook (`suspicious_execution.yaml`) and `tool_metadata.py` reference to `analyze_filename` → `wintriage_check_artifact(type='filename')`. | F-2 | OPEN | one cycle after D27a |
| B-3 | Gateway response-guard must scan `ToolResult.structured_content` (size cap + secret redaction), not only text. Hard acceptance-gate + `/security-review` at the gateway cutover. | F-3 | OPEN | D27b |
| B-4 | Replace `opensearch_ingest.password` (and any credential-as-tool-arg) with a reference to a named control-plane credential, so secrets never transit the tool-call/audit path. | F-5 | OPEN | auth/jobs phase |

---

## Notes
- Earlier project-level findings (e.g. the Rocba/run_command hardening items) live in
  their own session logs and memory; this register tracks the **migration** forks/backlog.
- When a B# is completed, mark **DONE** with the commit/Run that closed it; do not delete.
