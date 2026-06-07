# Open-Items Register — Forks (F#) & Backlog (B#)

The single home for open decisions and deferred work, per `OPERATING_MODEL.md` §5.
Append-only; mark status, do not delete. Forks (F#) await an operator call; Backlog
(B#) are accepted-but-deferred work with a do-by phase. Resolved forks point to the
Decision (D#) or Backlog (B#) they became.

Format (LOAD-BEARING — parsed by tooling; see `OPERATING_MODEL.md` §8). Both
registers are GitHub-flavored **markdown tables** with a fixed column order.
Fork rows begin `| F-<n> |` and have exactly 7 columns; backlog rows begin
`| B-<n> |` and have exactly 5. Append new columns only at the end — never
reorder or rename existing ones. Allowed `Status` values: forks `OPEN` |
`RESOLVED`; backlog `OPEN` | `DONE` (bold `**…**` is fine; the validator strips it).

```
| ID  | Question        | Raised          | Status   | Decision (date) | Becomes      | Affects |
| F-n | <question>      | Run <r>, <doc §>| OPEN|RESOLVED | <call + date>  | D-n / B-n / rejected | <D#/doc/snapshot> |

| ID  | Deferred work   | Source          | Status   | Do-by phase |
| B-n | <deferred work> | F-n / Run <r>   | OPEN|DONE | <phase/date> |
```

Run `python3 scripts/validate_migration_docs.py` after editing this file.

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
| B-5 | `opensearch_case_detections_resource` ignores its `case_id` path param (returns active-case detections regardless; D4 single-active-case masks the gap). Scope the query by `case_id` or drop the path parameter so the URI does not promise scoping it cannot deliver. | Run 21 (D27a review, S2) | OPEN | D27b |
| B-6 | Consolidate the per-registry duplicate `ToolResult` envelope builders (opensearch `_success_tool_result`/`_success_result`; wintriage's four builders) into one, so the B-3 `structured_content` redaction and any `ResultMeta` change apply at a single point instead of 2–4 drift-prone copies. | Run 21 (D27a review) | OPEN | D27b |
| B-7 | OpenSearch `ResultMeta` only populates `audit_id`; bring it to parity with opencti/wintriage (`examiner`, `caveats`, `interpretation_constraint`, `audit_warning`) or document the divergence — clients relying on those fields get nulls from every OpenSearch tool today. | Run 21 (D27a review) | OPEN | D27b |
| B-8 | Dedupe the two byte-identical opensearch resources under different URIs (`opensearch://cluster/status` vs `opensearch://catalog/indices`); each is a full cluster-health + cat.indices round-trip, so they double I/O and will drift. | Run 21 (D27a review) | OPEN | at/after D27b |
| B-9 | D27a robustness nits: `opensearch_get_event`/`shard_status` error-code substring heuristic (`'not' in type(exc).__name__`); wintriage generic `except` returns an unaudited `ResultMeta()`; `_redact_secret_fields` exact-key-match misses `SIFT_ARCHIVE_PASSWORD`-style names (no live leak — legacy audit curates params and never logs the password); per-call `inspect.signature` recomputation on the tool/resource hot path. | Run 21 (D27a review) | OPEN | D27b/hardening |

---

## Notes
- Earlier project-level findings (e.g. the Rocba/run_command hardening items) live in
  their own session logs and memory; this register tracks the **migration** forks/backlog.
- When a B# is completed, mark **DONE** with the commit/Run that closed it; do not delete.
