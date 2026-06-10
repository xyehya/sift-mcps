# Known Limitations and Areas of Improvement

Status: skeleton. Validation owner: BATCH-FRZ1.
Last updated: 2026-06-09.

## Current Known Limitations

| Area | Limitation | Demo impact | Improvement path |
| --- | --- | --- | --- |
| Re-auth | MVP uses a local HMAC/password bridge for some sensitive actions. | Acceptable if explained clearly. | Move to Supabase password re-auth/session verification. |
| OpenSearch | Single-node VM can report yellow cluster health. | Acceptable if indexing/search works. | Multi-node or replica-adjusted production profile. |
| Pre-context denials | Some pre-context denials remain Gateway local security telemetry, not `app.audit_events`. | Accepted MVP behavior. | Hardened DB projector for attributable denials. |
| RAG | Shared forensic knowledge is case-neutral (`case_id NULL`). | Correct for reference grounding; not case evidence. | Add case-derived chunks with provenance after ingest. |
| Evidence listing | `evidence_info` lists evidence files from the local file manifest, so a DB-sealed case whose local manifest is absent shows `chain_status=ok` but `evidence_files=[]`. | Low: AUT1-B1 stall-trap fields (`chain_status`, `requires_examiner_action`) are DB-correct after the BATCH-INST1 overlay; only the file *listing* lags. | DB-derived evidence listing in `evidence_info` (read `app.evidence_*` instead of the file manifest). |
| Installer re-run | A full destructive `./install.sh` re-run is not exercised on the live demo VM. | None for the demo; idempotency is checked structurally and via BATCH-V1's install. | Idempotency harness on a throwaway VM in CI. |
| Agent RAG scope | `rag_search_case` is reachable only when the issued agent carries `mcp:*` or `tool:rag_search_case`; the agent cannot self-inspect its scopes. | Operator must issue the demo agent with the RAG scope. | Surface the issued scope set / a catalog self-check to the agent. |
| Memory analysis symbols | Volatility positively identifies the kernel PDB for the re-acquired `Rocba-Memory2.raw` (GUID `15B12C74F0E177581B6B27DD4C5022C2`) but cannot write the generated/downloaded symbol JSON to its read-only install `symbols/windows/` dir under `agent_runtime`, so `windows.*` plugins fail `plugins.Info.kernel.symbol_table_name`. | Memory-depth plugins blocked until fixed; disk/strings planes unaffected. The corrupted-image root cause is resolved (the old image yielded no banner). | Point vol's symbol dir at a case-writable path (`VOLATILITY3_SYMBOL_DIRS` / `--symbol-dirs`) beside the existing `XDG_CACHE_HOME` cache_dir (B4-family executor change), then download/provision the PDB once. |
| Product docs | This directory starts as a structured skeleton. | Must be filled before final presentation. | Run PDOC/AUT/SEC batches. |

## Improvement Backlog Template

| ID | Priority | Area | Improvement | Owner batch | Status |
| --- | --- | --- | --- | --- | --- |
| IMP-TODO-1 | TODO | TODO | Populate during post-MVP QA. | TODO | TODO |

## Demo Caveat Rules

- Caveats are acceptable only when they are explicit, bounded, and do not break
  the security thesis.
- Any caveat that weakens MCP-only autonomy, custody, report eligibility, or
  secret isolation must be fixed or called out as a blocker before freeze.

